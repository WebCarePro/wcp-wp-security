<?php
/**
 * Site Behavioral Intelligence & AST Analyzer
 *
 * Stateful chunked scanner that analyzes all installed plugins, themes, mu-plugins,
 * and custom functions.php hooks using token-level AST parsing (token_get_all()).
 *
 * Inspects:
 * - Unprotected guest AJAX hooks (wp_ajax_nopriv_*) lacking nonces or capability checks
 * - Permissive REST routes ('permission_callback' => '__return_true')
 * - Direct-access standalone PHP files missing defined('ABSPATH') guards
 * - Untrusted inputs flowing into SQL, file-upload, command, and SSRF sinks
 * - Outdated / abandoned plugins with known CVE vulnerabilities
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Modular
 */

namespace WebCareProScanner\Firewall\Modular;

if (!defined('ABSPATH')) {
    exit;
}

class SiteBehavioralAnalyzer {

    const OPTION_STATE = 'webcareproscan_modular_scan_state';
    const MAX_FILE_SIZE = 2097152; // 2MB
    const BATCH_TIME_LIMIT = 3.5;  // 3.5 seconds per batch to avoid HTTP/proxy timeouts

    private const AUTH_NONCE_FUNCTIONS = [
        'check_ajax_referer',
        'check_admin_referer',
        'wp_verify_nonce',
        'verify_nonce',
        'check_nonce',
        'validate_nonce',
        'wc_verify_nonce',
        'acf_verify_ajax',
        'acf_verify_nonce',
        'gf_verify_nonce',
        'wpforms_verify_nonce',
    ];

    /**
     * Start or initialize a full behavioral intelligence scan session.
     *
     * @param array $options Scan options (force_rescan, components_filter)
     * @return array Scan initialization summary
     */
    public static function start_scan(array $options = []): array {
        // Build Component & File Inventory with live official origin, vendor & checksum verification
        $components = self::discover_all_components(true);
        $file_queue = self::build_file_queue($components);

        $session_id = 'scan_' . time() . '_' . wp_generate_password(6, false, false);

        $initial_cve_count      = 0;
        $initial_outdated_count = 0;
        foreach ($components as $comp_item) {
            if (!empty($comp_item['cve_count'])) {
                $initial_cve_count += (int) $comp_item['cve_count'];
            }
            if (!empty($comp_item['update_available'])) {
                $initial_outdated_count++;
            }
        }

        $initial_state = [
            'session_id'         => $session_id,
            'status'             => 'running',
            'started_at'         => time(),
            'started_at_micro'   => microtime(true),
            'updated_at'         => time(),
            'current_phase'      => 1, // 1: Census, 2: Hooks/AST, 3: REST, 4: Taint/Sinks, 5: Direct-Access, 6: Synthesis
            'total_components'   => count($components),
            'visited_components' => [],
            'total_files'        => count($file_queue),
            'processed_files'    => 0,
            'current_index'      => 0,
            'current_component'  => '',
            'current_file'       => '',
            'last_batch_files'   => 0,
            'last_batch_ms'      => 0,
            'last_batch_rate'    => 0.0,
            'counters'           => [
                'files_tokenized'        => 0,
                'ajax_hooks_found'       => 0,
                'unprotected_ajax_hooks' => 0,
                'rest_routes_found'      => 0,
                'permissive_rest_routes' => 0,
                'missing_abspath_files'  => 0,
                'tampered_files_found'   => 0,
                'taint_sinks_found'      => 0,
                'cve_vulnerabilities'    => $initial_cve_count,
                'outdated_components'    => $initial_outdated_count,
                'abandoned_components'   => 0,
                'rules_synthesized'      => 0,
            ],
            'inventory'          => $components,
            'endpoint_map'       => [],
            'findings'           => [],
            'file_queue'         => $file_queue,
            'options'            => $options,
        ];

        update_option(self::OPTION_STATE, $initial_state, false);

        // Pre-save component census to Vault
        BehavioralVaultManager::write_shard(BehavioralVaultManager::SHARD_INVENTORY, $components);

        // Update vault meta
        $meta = BehavioralVaultManager::read_meta();
        $meta['last_scan'] = time();
        $meta['scan_session'] = $session_id;
        $meta['total_components'] = count($components);
        $meta['total_files'] = count($file_queue);
        BehavioralVaultManager::write_meta($meta);

        $progress = self::format_progress_response($initial_state);
        $progress['message'] = sprintf(
            /* translators: %1$d: components count, %2$d: files count */
            __('Behavioral scan session initialized: %1$d components and %2$d PHP files queued.', 'webcare-pro-security'),
            count($components),
            count($file_queue)
        );
        return $progress;
    }

    /**
     * Process the next batch of queued files.
     *
     * @param int $batch_size Maximum files to process in this chunk
     * @return array Live progress telemetry
     */
    public static function process_batch(int $batch_size = 50): array {
        $state = get_option(self::OPTION_STATE, null);
        if (!$state || !is_array($state) || empty($state['status'])) {
            return [
                'success' => false,
                'status'  => 'idle',
                'message' => __('No active behavioral scan session found.', 'webcare-pro-security'),
            ];
        }

        if ($state['status'] === 'completed') {
            return self::format_progress_response($state);
        }

        $start_time = microtime(true);
        $file_queue = $state['file_queue'] ?? [];
        $total_files = count($file_queue);
        $current_index = intval($state['current_index'] ?? 0);

        $processed_in_this_batch = 0;
        $endpoint_map = $state['endpoint_map'] ?? [];
        $findings = $state['findings'] ?? [];
        $counters = $state['counters'] ?? [];
        $visited_components = is_array($state['visited_components'] ?? null) ? $state['visited_components'] : [];

        while ($current_index < $total_files && $processed_in_this_batch < $batch_size) {
            // Check time envelope
            if ((microtime(true) - $start_time) >= self::BATCH_TIME_LIMIT) {
                break;
            }

            $file_info = $file_queue[$current_index] ?? null;
            $current_index++;
            $processed_in_this_batch++;

            if (!$file_info || empty($file_info['path'])) {
                continue;
            }

            $comp_name = (string) ($file_info['component'] ?? '');
            $comp_key  = (string) ($file_info['slug'] ?? $comp_name);
            if ($comp_key !== '') {
                $visited_components[$comp_key] = true;
            }

            $state['current_component'] = $comp_name;
            $state['current_file']      = (string) ($file_info['rel_path'] ?? basename((string) $file_info['path']));

            // Analyze individual PHP file
            self::analyze_php_file($file_info, $endpoint_map, $findings, $counters);
        }

        $batch_elapsed_sec          = max(0.001, microtime(true) - $start_time);
        $state['current_index']      = $current_index;
        $state['processed_files']    = $current_index;
        $state['visited_components'] = $visited_components;
        $state['last_batch_files']   = $processed_in_this_batch;
        $state['last_batch_ms']      = (int) round($batch_elapsed_sec * 1000);
        $state['last_batch_rate']    = round($processed_in_this_batch / $batch_elapsed_sec, 1);
        $state['endpoint_map']       = $endpoint_map;
        $state['findings']           = $findings;
        $state['counters']           = $counters;
        $state['updated_at']         = time();

        // Calculate phase based on progress percentage
        $pct = $total_files > 0 ? round(($current_index / $total_files) * 100, 1) : 100;
        if ($pct < 15) {
            $state['current_phase'] = 2; // Hooks & functions.php AST
        } elseif ($pct < 45) {
            $state['current_phase'] = 3; // REST API Attack Surface
        } elseif ($pct < 75) {
            $state['current_phase'] = 4; // Taint & Vulnerability Hunter
        } elseif ($pct < 95) {
            $state['current_phase'] = 5; // Direct-Access Script Discovery
        } else {
            $state['current_phase'] = 6; // Modular Firewall Synthesis
        }

        // Check if queue completed
        if ($current_index >= $total_files) {
            $now_micro                    = microtime(true);
            $started_micro                = floatval($state['started_at_micro'] ?? ($state['started_at'] ?? $now_micro));
            $total_duration               = max(0.1, round($now_micro - $started_micro, 1));
            $state['status']              = 'completed';
            $state['completed_at']        = time();
            $state['completed_at_micro']  = $now_micro;
            $state['current_phase']       = 6;
            $state['current_file']        = '';

            // Commit Shards to Vault
            BehavioralVaultManager::write_shard(BehavioralVaultManager::SHARD_ENDPOINTS, $endpoint_map);
            BehavioralVaultManager::write_shard(BehavioralVaultManager::SHARD_FINDINGS, $findings);

            // Synthesize Modular Firewall Rules from Vault Shards
            $synthesized = ModularFirewallSynthesizer::synthesize_rules($state['inventory'], $endpoint_map, $findings);
            $state['counters']['rules_synthesized'] = count($synthesized);

            // Write synthesized rules to Vault Shard
            BehavioralVaultManager::write_shard(BehavioralVaultManager::SHARD_RULES, $synthesized);

            // Update Vault Meta
            $meta = BehavioralVaultManager::read_meta();
            $meta['last_scan'] = time();
            $meta['scan_status'] = 'completed';
            $meta['total_rules'] = count($synthesized);
            $meta['counters'] = $state['counters'];
            $meta['last_duration_seconds'] = $total_duration;
            $meta['last_files_per_sec']    = $total_files > 0 ? round($total_files / $total_duration, 1) : 0.0;
            BehavioralVaultManager::write_meta($meta);

            // Log activity event
            if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                \WebCareProScanner\System\WebCareActivityLogger::log(
                    'behavioral_intel_scan_completed',
                    sprintf(
                        /* translators: %1$d: components, %2$d: rules count */
                        __('Deep Behavioral Intelligence scan completed across %1$d components. Synthesized %2$d tailored Modular Firewall rules.', 'webcare-pro-security'),
                        count($state['inventory']),
                        count($synthesized)
                    ),
                    'info',
                    [
                        'components' => count($state['inventory']),
                        'rules'      => count($synthesized),
                        'duration'   => time() - ($state['started_at'] ?? time()),
                    ]
                );
            }
        }

        update_option(self::OPTION_STATE, $state, false);

        return self::format_progress_response($state);
    }

    /**
     * Get live scan progress status.
     *
     * @return array
     */
    public static function get_scan_progress(): array {
        $state = get_option(self::OPTION_STATE, null);
        if (!$state || !is_array($state)) {
            $summary    = BehavioralVaultManager::get_vault_summary();
            $has_scan   = !empty($summary['last_scan']);
            $meta_files = intval($summary['total_files'] ?? 0);
            $meta_comps = intval($summary['total_components'] ?? 0);
            return [
                'success'                     => true,
                'status'                      => $has_scan ? 'idle_with_results' : 'not_started',
                'progress_pct'                => $has_scan ? 100 : 0,
                'current_phase'               => $has_scan ? 6 : 1,
                'phase_label'                 => $has_scan ? __('Modular Firewall Rule Synthesis & Simulation', 'webcare-pro-security') : __('Extension & Version Census', 'webcare-pro-security'),
                'phase_labels'                => self::get_phase_labels(),
                'total_files'                 => $meta_files,
                'processed_files'             => $has_scan ? $meta_files : 0,
                'remaining_files'             => 0,
                'total_components'            => $meta_comps,
                'components_scanned'          => $has_scan ? $meta_comps : 0,
                'current_component'           => '',
                'current_file'                => '',
                'files_per_sec'               => floatval($summary['last_files_per_sec'] ?? 0),
                'batch_files_per_sec'         => 0.0,
                'last_batch_files'            => 0,
                'last_batch_ms'               => 0,
                'elapsed_seconds'             => floatval($summary['last_duration_seconds'] ?? 0),
                'estimated_remaining_seconds' => $has_scan ? 0 : null,
                'is_completed'                => $has_scan,
                'vault_summary'               => $summary,
                'counters'                    => $summary['counters'] ?? [],
            ];
        }

        return self::format_progress_response($state);
    }

    /**
     * Standardized 6-stage behavioral scan phase labels.
     *
     * @return array<int, string>
     */
    private static function get_phase_labels(): array {
        return [
            1 => __('Extension & Version Census', 'webcare-pro-security'),
            2 => __('Hook Registrations & functions.php AST', 'webcare-pro-security'),
            3 => __('REST API & Public Route Attack-Surface', 'webcare-pro-security'),
            4 => __('Source-to-Sink Taint & Vulnerability Hunter', 'webcare-pro-security'),
            5 => __('Direct-Access Script & Missing ABSPATH Discovery', 'webcare-pro-security'),
            6 => __('Modular Firewall Rule Synthesis & Simulation', 'webcare-pro-security'),
        ];
    }

    /**
     * Format standardized progress response for React UI.
     *
     * @param array $state
     * @return array
     */
    private static function format_progress_response(array $state): array {
        $raw_total       = max(0, intval($state['total_files'] ?? 0));
        $processed       = min($raw_total, max(0, intval($state['processed_files'] ?? 0)));
        $remaining_files = max(0, $raw_total - $processed);
        $status          = (string) ($state['status'] ?? 'idle');
        $is_completed    = ($status === 'completed');

        $pct = $raw_total > 0
            ? min(100, round(($processed / $raw_total) * 100, 1))
            : ($is_completed ? 100 : 0);

        $started_micro = floatval($state['started_at_micro'] ?? ($state['started_at'] ?? time()));
        $end_micro     = $is_completed
            ? floatval($state['completed_at_micro'] ?? ($state['completed_at'] ?? microtime(true)))
            : microtime(true);
        $elapsed_sec   = max(0.0, round($end_micro - $started_micro, 1));

        $last_batch_rate = floatval($state['last_batch_rate'] ?? 0.0);
        $files_per_sec   = ($processed > 0 && $elapsed_sec >= 0.2)
            ? round($processed / $elapsed_sec, 1)
            : $last_batch_rate;

        $eta_seconds = null;
        if ($is_completed) {
            $eta_seconds = 0;
        } elseif ($processed >= 5 && $files_per_sec > 0) {
            $eta_seconds = (int) ceil($remaining_files / $files_per_sec);
        }

        $total_components   = max(0, intval($state['total_components'] ?? count((array) ($state['inventory'] ?? []))));
        $components_scanned = $is_completed
            ? $total_components
            : count((array) ($state['visited_components'] ?? []));

        $phase_labels  = self::get_phase_labels();
        $current_phase = max(1, min(6, intval($state['current_phase'] ?? 1)));

        return [
            'success'                     => true,
            'session_id'                  => $state['session_id'] ?? '',
            'status'                      => $status,
            'progress_pct'                => $pct,
            'current_phase'               => $current_phase,
            'phase_label'                 => $phase_labels[$current_phase] ?? '',
            'phase_labels'                => $phase_labels,
            'total_files'                 => $raw_total,
            'processed_files'             => $processed,
            'remaining_files'             => $remaining_files,
            'total_components'            => $total_components,
            'components_scanned'          => $components_scanned,
            'current_component'           => (string) ($state['current_component'] ?? ''),
            'current_file'                => (string) ($state['current_file'] ?? ''),
            'files_per_sec'               => $files_per_sec,
            'batch_files_per_sec'         => $last_batch_rate,
            'last_batch_files'            => intval($state['last_batch_files'] ?? 0),
            'last_batch_ms'               => intval($state['last_batch_ms'] ?? 0),
            'started_at'                  => intval($state['started_at'] ?? 0),
            'completed_at'                => $is_completed ? intval($state['completed_at'] ?? 0) : null,
            'elapsed_seconds'             => $elapsed_sec,
            'estimated_remaining_seconds' => $eta_seconds,
            'counters'                    => $state['counters'] ?? [],
            'is_completed'                => $is_completed,
        ];
    }

    /**
     * Analyze a single PHP file using AST tokens.
     *
     * @param array $file_info
     * @param array &$endpoint_map
     * @param array &$findings
     * @param array &$counters
     */
    private static function analyze_php_file(array $file_info, array &$endpoint_map, array &$findings, array &$counters): void {
        $path = $file_info['path'] ?? '';
        if (!file_exists($path) || !is_readable($path)) {
            return;
        }

        $size = filesize($path);
        if ($size > self::MAX_FILE_SIZE || $size === 0) {
            return;
        }

        $content = @file_get_contents($path);
        if ($content === false || strlen($content) === 0) {
            return;
        }

        $counters['files_tokenized']++;

        $tokens = @token_get_all($content);
        if (!is_array($tokens)) {
            return;
        }

        $token_count    = count($tokens);
        $component_name = $file_info['component'] ?? 'WordPress Core/Custom';
        $component_type = $file_info['type'] ?? 'unknown';
        $rel_path       = $file_info['rel_path'] ?? basename($path);

        // Compute file cryptographic hashes & official checksum / vendor match status
        $file_forensics = ComponentIntegrityVerifier::verify_file_forensics($path, $file_info);
        $start_idx      = count($findings);

        // 0. Check official WordPress.org / Self-Defense checksum tampering or unknown injected PHP scripts
        $chk_status = $file_forensics['checksum_status'] ?? 'unmanaged_custom';
        if (in_array($chk_status, ['modified', 'unknown_in_official', 'self_modified', 'self_untracked'], true)) {
            $counters['tampered_files_found'] = ($counters['tampered_files_found'] ?? 0) + 1;
            $is_unknown = ($chk_status === 'unknown_in_official' || $chk_status === 'self_untracked');
            $findings[] = [
                'type'        => 'integrity_tamper_mismatch',
                'component'   => $component_name,
                'type_label'  => $component_type,
                'file'        => $rel_path,
                'full_path'   => $path,
                'line'        => 1,
                'evidence'    => $is_unknown
                    ? __('PHP file exists inside an official checksum-verified component directory but is NOT present in the official release manifest.', 'webcare-pro-security')
                    : sprintf(
                        /* translators: %1$s: expected hash, %2$s: actual hash */
                        __('File checksum mismatch against official release manifest (Expected: %1$s, Actual: %2$s).', 'webcare-pro-security'),
                        substr((string) ($file_forensics['expected_checksum'] ?? ''), 0, 12),
                        substr((string) ($file_forensics['file_md5'] ?? $file_forensics['file_sha256'] ?? ''), 0, 12)
                    ),
                'severity'    => 'critical',
            ];
        }

        // 1. Check for missing defined('ABSPATH') in standalone procedural plugins/themes/uploads scripts
        $is_tampered_file   = in_array($chk_status, ['modified', 'unknown_in_official', 'self_modified', 'self_untracked'], true);
        $is_trusted_origin  = !$is_tampered_file && (!empty($file_info['is_official_wporg']) || !empty($file_info['is_known_vendor']) || !empty($file_forensics['is_official_verified']));
        $has_abspath_guard  = self::check_abspath_guard($tokens);
        $has_superglobals   = self::check_superglobals($tokens);
        $is_pure_decl       = self::is_pure_declaration_file($tokens);
        $is_safe_partial    = $is_trusted_origin && self::is_safe_wp_template_partial($tokens);

        if (!$has_abspath_guard && $has_superglobals && !$is_pure_decl && !$is_safe_partial && empty($file_forensics['known_vendor_lib']) && in_array($component_type, ['plugin', 'theme', 'upload'], true)) {
            $counters['missing_abspath_files']++;
            $findings[] = [
                'type'        => 'missing_abspath_script',
                'component'   => $component_name,
                'type_label'  => $component_type,
                'file'        => $rel_path,
                'full_path'   => $path,
                'line'        => 1,
                'evidence'    => __('Direct-access PHP script executes top-level code reading superglobals without defined("ABSPATH") guard.', 'webcare-pro-security'),
                'severity'    => ($file_forensics['is_official_verified'] ?? false) ? 'medium' : 'high',
            ];
        }

        // 2. Token AST Traversal for Hook Registrations, REST Routes, and Sinks
        for ($i = 0; $i < $token_count; $i++) {
            $token = $tokens[$i];

            // Match function calls
            if (is_array($token) && $token[0] === T_STRING) {
                $fn_name = strtolower($token[1]);
                $line = $token[2];

                // Hook inspection: add_action(...)
                if ($fn_name === 'add_action') {
                    self::inspect_hook_call($tokens, $i, $file_info, $endpoint_map, $findings, $counters);
                }

                // REST Route inspection: register_rest_route(...)
                if ($fn_name === 'register_rest_route') {
                    self::inspect_rest_route_call($tokens, $i, $file_info, $endpoint_map, $findings, $counters);
                }

                // Direct File Upload Sink inspection
                if (in_array($fn_name, ['move_uploaded_file'], true)) {
                    $counters['taint_sinks_found']++;
                    $findings[] = [
                        'type'        => 'raw_file_upload_sink',
                        'component'   => $component_name,
                        'file'        => $rel_path,
                        'full_path'   => $path,
                        'line'        => $line,
                        'sink'        => $fn_name,
                        'evidence'    => sprintf(
                            /* translators: %s: function name */
                            __('Direct file upload sink "%s" invoked outside standard wp_handle_upload().', 'webcare-pro-security'),
                            $fn_name
                        ),
                        'severity'    => 'high',
                    ];
                }

                // SSRF Sink inspection (wp_remote_get/post/request with unvalidated dynamic URL in arg #1)
                if (in_array($fn_name, ['wp_remote_get', 'wp_remote_post', 'wp_remote_request'], true)) {
                    if (self::has_unvalidated_ssrf_url_arg($tokens, $i)) {
                        $counters['taint_sinks_found']++;
                        $findings[] = [
                            'type'        => 'ssrf_egress_sink',
                            'component'   => $component_name,
                            'file'        => $rel_path,
                            'full_path'   => $path,
                            'line'        => $line,
                            'sink'        => $fn_name,
                            'evidence'    => sprintf(
                                /* translators: %s: function name */
                                __('Outbound HTTP request "%s" parameterized with unvalidated request input (Potential SSRF).', 'webcare-pro-security'),
                                $fn_name
                            ),
                            'severity'    => 'high',
                        ];
                    }
                }
            }

            // Unprepared SQL Sink inspection ($wpdb->query)
            if (is_array($token) && $token[0] === T_VARIABLE && $token[1] === '$wpdb') {
                self::inspect_wpdb_sink($tokens, $i, $file_info, $findings, $counters);
            }
        }

        // Attach cryptographic file hashes, checksum status & component origin provenance to every finding discovered in this file
        $end_idx = count($findings);
        for ($f_idx = $start_idx; $f_idx < $end_idx; $f_idx++) {
            $findings[$f_idx]['full_path']            = $path;
            $findings[$f_idx]['file_sha256']          = $file_forensics['file_sha256'];
            $findings[$f_idx]['file_md5']             = $file_forensics['file_md5'];
            $findings[$f_idx]['file_size']            = $file_forensics['file_size'];
            $findings[$f_idx]['file_mtime']           = $file_forensics['file_mtime'];
            $findings[$f_idx]['checksum_status']      = $file_forensics['checksum_status'];
            $findings[$f_idx]['expected_checksum']    = $file_forensics['expected_checksum'];
            $findings[$f_idx]['known_vendor_lib']     = $file_forensics['known_vendor_lib'];
            $findings[$f_idx]['is_official_verified'] = $file_forensics['is_official_verified'];
            $findings[$f_idx]['origin_type']          = $file_info['origin_type'] ?? 'custom_unmanaged';
            $findings[$f_idx]['is_official_wporg']    = !empty($file_info['is_official_wporg']);
            $findings[$f_idx]['is_known_vendor']      = !empty($file_info['is_known_vendor']);
            $findings[$f_idx]['vendor_name']          = $file_info['vendor_name'] ?? null;
        }
    }

    /**
     * Inspect an add_action(...) invocation.
     */
    private static function inspect_hook_call(array $tokens, int $pos, array $file_info, array &$endpoint_map, array &$findings, array &$counters): void {
        $arg1 = self::extract_string_arg($tokens, $pos, 1);
        $arg2 = self::extract_string_arg($tokens, $pos, 2);

        if (!$arg1 || self::is_dynamic_hook_arg($tokens, $pos, 1)) {
            return;
        }

        $line = is_array($tokens[$pos]) ? $tokens[$pos][2] : 1;
        $component_name = $file_info['component'] ?? 'Custom';
        $rel_path = $file_info['rel_path'] ?? '';

        // Match AJAX Hooks
        if (str_starts_with($arg1, 'wp_ajax_nopriv_') || str_starts_with($arg1, 'wp_ajax_') || str_starts_with($arg1, 'admin_post_nopriv_')) {
            $action_slug = str_replace(['wp_ajax_nopriv_', 'wp_ajax_', 'admin_post_nopriv_'], '', $arg1);
            if ($action_slug === '') {
                return;
            }
            $counters['ajax_hooks_found']++;
            $is_guest = str_starts_with($arg1, 'wp_ajax_nopriv_') || str_starts_with($arg1, 'admin_post_nopriv_');
            $cb_name  = $arg2 ?: self::extract_callback_name($tokens, $pos);

            // Inspect strictly inside the callback / closure scope rather than across the entire file
            $scope     = self::inspect_callback_scope($tokens, $cb_name, $pos);
            $has_nonce = $scope['has_nonce'];
            $has_cap   = $scope['has_cap'];
            $has_sink  = $scope['has_dangerous_sink'];

            // Background async loopback processors inherit WP_Async_Request::maybe_handle(), which verifies check_ajax_referer($this->identifier, 'nonce') in parent class
            $cb_short = strtolower((string) $cb_name);
            if ($is_guest && !$has_nonce && !$scope['scope_found'] && in_array($cb_short, ['maybe_handle', 'handle_cron_healthcheck'], true)) {
                $has_nonce = true;
            }

            $endpoint_info = [
                'hook'               => $arg1,
                'action'             => $action_slug,
                'callback'           => $cb_name ?: 'closure/variable',
                'component'          => $component_name,
                'file'               => $rel_path,
                'line'               => $line,
                'is_guest'           => $is_guest,
                'has_nonce'          => $has_nonce,
                'has_capability'     => $has_cap,
                'has_dangerous_sink' => $has_sink,
                'scope_found'        => $scope['scope_found'],
            ];

            $endpoint_map[] = $endpoint_info;

            // Flag unprotected guest AJAX hooks
            if ($is_guest && !$has_nonce && !$has_cap) {
                $is_trusted_source = !empty($file_info['is_official_wporg'])
                    || !empty($file_info['is_known_vendor'])
                    || (($file_info['origin_type'] ?? '') === 'self_official');
                $is_verified_read_only = !$has_sink && ($scope['scope_found'] || $is_trusted_source);
                $counters['unprotected_ajax_hooks']++;
                $findings[] = [
                    'type'               => 'unprotected_guest_ajax',
                    'component'          => $component_name,
                    'file'               => $rel_path,
                    'line'               => $line,
                    'action'             => $action_slug,
                    'hook'               => $arg1,
                    'callback'           => $cb_name ?: 'closure/variable',
                    'has_dangerous_sink' => $has_sink,
                    'scope_found'        => $scope['scope_found'],
                    'evidence'           => sprintf(
                        /* translators: %1$s: action slug, %2$s: callback */
                        __('Unprotected guest AJAX hook "%1$s" (callback: %2$s) lacks nonce verification or capability authorization.', 'webcare-pro-security'),
                        $action_slug,
                        $cb_name ?: 'inline closure'
                    ),
                    'severity'           => $is_verified_read_only ? 'medium' : ($has_sink ? 'critical' : 'high'),
                ];
            }
        }
    }

    /**
     * Determine if a literal REST namespace/route is intentionally public by architecture
     * (batch dispatchers, storefront carts/checkout using internal nonces, or HMAC connection handshakes).
     */
    public static function is_intentional_public_rest_route(string $full_route, string $namespace = ''): bool {
        $norm_route = '/' . ltrim(strtolower($full_route), '/');
        $norm_ns    = trim(strtolower($namespace), '/');

        if ($norm_route === '/batch/v1' || $norm_ns === 'batch/v1') {
            return true;
        }
        if ($norm_ns === 'wc/store' || str_starts_with($norm_ns, 'wc/store/') || str_starts_with($norm_route, '/wc/store/')) {
            return true;
        }
        if (str_starts_with($norm_route, '/jetpack/v4/verify_') || str_starts_with($norm_route, '/jetpack/v4/remote_authorize')) {
            return true;
        }
        if (str_starts_with($norm_route, '/wc-admin/mobile-app/qr-login-')) {
            return true;
        }
        if ($norm_route === '/wordfence/v1/authenticate' || $norm_route === '/litespeed/v3/wp_rest_echo') {
            return true;
        }
        if (str_starts_with($norm_route, '/webcare-pro-security/v1/webauthn/')) {
            return true;
        }

        return false;
    }

    /**
     * Inspect a register_rest_route(...) invocation per endpoint sub-array block.
     */
    private static function inspect_rest_route_call(array $tokens, int $pos, array $file_info, array &$endpoint_map, array &$findings, array &$counters): void {
        $raw_namespace = self::extract_string_arg($tokens, $pos, 1);
        $raw_route     = self::extract_string_arg($tokens, $pos, 2);
        $namespace     = $raw_namespace ?: '[dynamic]';
        $route         = $raw_route ?: '[dynamic]';
        $line          = is_array($tokens[$pos]) ? $tokens[$pos][2] : 1;
        $component     = $file_info['component'] ?? 'Custom';
        $rel_path      = $file_info['rel_path'] ?? '';

        $counters['rest_routes_found']++;

        $full_route      = '/' . ltrim($namespace, '/') . '/' . ltrim($route, '/');
        $call_end        = self::find_call_end_pos($tokens, $pos, 240);
        $blocks          = self::extract_rest_endpoint_blocks($tokens, $pos, $call_end);
        $is_permissive      = false;
        $has_post_method    = false;
        $has_internal_guard = false;
        $is_write_unauth    = false;
        $write_scope_all    = true;
        $write_has_sink     = false;

        foreach ($blocks as [$b_start, $b_end]) {
            $b_len       = max(1, $b_end - $b_start + 1);
            $b_perm_true = self::has_token_string_within($tokens, $b_start, $b_len, '__return_true');
            $b_has_write = self::has_token_string_within($tokens, $b_start, $b_len, 'POST') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'PUT') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'PATCH') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'DELETE') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'CREATABLE') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'EDITABLE') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'DELETABLE') ||
                           self::has_token_string_within($tokens, $b_start, $b_len, 'ALLMETHODS');

            if ($b_perm_true) {
                $is_permissive = true;
            }
            if ($b_has_write) {
                $has_post_method = true;
            }

            if ($b_perm_true && $b_has_write) {
                // Check if the REST endpoint callback enforces nonce/cap/HMAC checks or performs strictly read-only queries
                $cb_scope = self::inspect_rest_block_callback_scope($tokens, $b_start, $b_end);
                if (!empty($cb_scope['has_nonce']) || !empty($cb_scope['has_cap'])) {
                    $has_internal_guard = true;
                    continue;
                }
                $is_write_unauth = true;
                if (empty($cb_scope['scope_found'])) {
                    $write_scope_all = false;
                    $write_has_sink  = true;
                } elseif (!empty($cb_scope['has_dangerous_sink'])) {
                    $write_has_sink = true;
                }
            }
        }

        $is_intentional = ($raw_namespace && $raw_route && self::is_intentional_public_rest_route($full_route, $namespace));

        $endpoint_map[] = [
            'type'               => 'rest_route',
            'namespace'          => $namespace,
            'route'              => $route,
            'full_route'         => $full_route,
            'component'          => $component,
            'file'               => $rel_path,
            'line'               => $line,
            'is_permissive'      => $is_permissive,
            'is_creatable'       => $has_post_method,
            'has_internal_guard' => $has_internal_guard,
        ];

        // Only synthesize permissive REST route guards for non-intentional write endpoints resolved with literal routes
        if ($raw_namespace && $raw_route && $is_write_unauth && !$is_intentional) {
            $is_read_only_rest = $write_scope_all && !$write_has_sink;
            $counters['permissive_rest_routes']++;
            $findings[] = [
                'type'               => 'permissive_rest_route',
                'component'          => $component,
                'file'               => $rel_path,
                'line'               => $line,
                'route'              => $full_route,
                'has_internal_guard' => $has_internal_guard,
                'has_dangerous_sink' => $write_has_sink,
                'scope_found'        => $write_scope_all,
                'evidence'           => sprintf(
                    /* translators: %s: REST route */
                    __('REST API endpoint "%s" permits unauthenticated write access via "permission_callback => __return_true".', 'webcare-pro-security'),
                    $full_route
                ),
                'severity'           => $is_read_only_rest ? 'medium' : 'high',
            ];
        }
    }

    /**
     * Inspect $wpdb->query / $wpdb->get_results for missing prepare().
     */
    private static function inspect_wpdb_sink(array $tokens, int $pos, array $file_info, array &$findings, array &$counters): void {
        $count = count($tokens);
        if ($pos + 2 >= $count) {
            return;
        }

        // Must be ->query or ->get_results or ->get_row
        if ($tokens[$pos + 1][0] !== T_OBJECT_OPERATOR) {
            return;
        }

        $method_token = $tokens[$pos + 2];
        if (!is_array($method_token) || $method_token[0] !== T_STRING) {
            return;
        }

        $method_name = strtolower($method_token[1]);
        if (!in_array($method_name, ['query', 'get_results', 'get_row', 'get_col', 'get_var'], true)) {
            return;
        }

        $line      = $method_token[2];
        $component = $file_info['component'] ?? 'Custom';
        $rel_path  = $file_info['rel_path'] ?? '';

        // Skip calls that invoke $wpdb->prepare(...) inside their argument window
        if (self::has_token_string_within($tokens, $pos + 2, 35, 'prepare')) {
            return;
        }

        // Check if adjacent arguments contain string concatenation (.) without prepare()
        if (self::has_string_concat_within($tokens, $pos + 2, 25)) {
            $counters['taint_sinks_found']++;
            $findings[] = [
                'type'        => 'unprepared_sql_query',
                'component'   => $component,
                'file'        => $rel_path,
                'line'        => $line,
                'method'      => '$wpdb->' . $method_name,
                'evidence'    => sprintf(
                    /* translators: %s: method name */
                    __('Raw SQL query constructed via string concatenation with $wpdb->%s() without $wpdb->prepare().', 'webcare-pro-security'),
                    $method_name
                ),
                'severity'    => 'critical',
            ];
        }
    }

    /**
     * Check if tokens contain defined('ABSPATH') or WPINC guard (skipping comments/whitespace).
     */
    private static function check_abspath_guard(array $tokens): bool {
        $non_trivial = 0;
        $count       = count($tokens);
        $depth       = 0;

        for ($i = 0; $i < $count; $i++) {
            $t = $tokens[$i];
            if ($t === '{' || (is_array($t) && in_array($t[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
                $depth++;
                continue;
            }
            if ($t === '}') {
                $depth = max(0, $depth - 1);
                continue;
            }
            if ($t === '!' && $depth === 0) {
                // Detect early abort pattern: !defined(...)/!class_exists(...)/!function_exists(...) followed closely by exit/die/return/wp_die
                $saw_env_check = false;
                $look_limit    = min($i + 35, $count);
                for ($j = $i + 1; $j < $look_limit; $j++) {
                    $lt = $tokens[$j];
                    if (!is_array($lt)) {
                        continue;
                    }
                    if (in_array($lt[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                        continue;
                    }
                    if (in_array($lt[0], [T_FUNCTION, T_CLASS, T_INTERFACE, T_TRAIT], true)) {
                        break;
                    }
                    $lval = strtolower($lt[1]);
                    if (!$saw_env_check && $lt[0] === T_STRING && in_array($lval, ['defined', 'class_exists', 'function_exists'], true)) {
                        $saw_env_check = true;
                        continue;
                    }
                    if ($saw_env_check && ($lt[0] === T_EXIT || $lt[0] === T_RETURN || ($lt[0] === T_STRING && $lval === 'wp_die'))) {
                        return true;
                    }
                }
            }
            if (!is_array($t)) {
                continue;
            }
            if (in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG], true)) {
                continue;
            }
            $non_trivial++;
            $val = strtolower(trim($t[1], "'\""));
            if ($val === 'abspath' || $val === 'wpinc') {
                return true;
            }
            if ($non_trivial >= 250) {
                break;
            }
        }
        return false;
    }

    /**
     * Determine whether a PHP file only contains namespace/use/class/interface/trait/enum/function declarations
     * (i.e. zero top-level procedural code that executes superglobals when invoked directly via HTTP).
     */
    private static function is_pure_declaration_file(array $tokens): bool {
        $depth               = 0;
        $count               = count($tokens);
        $has_oop_declaration = false;

        for ($i = 0; $i < $count; $i++) {
            $t = $tokens[$i];
            if ($t === '{' || (is_array($t) && in_array($t[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
                $depth++;
                continue;
            }
            if ($t === '}') {
                $depth = max(0, $depth - 1);
                continue;
            }
            if (!is_array($t) || $depth > 0) {
                continue;
            }
            if (in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_CLOSE_TAG], true)) {
                continue;
            }
            if (in_array($t[0], [T_CLASS, T_INTERFACE, T_TRAIT, T_FUNCTION], true) || (defined('T_ENUM') && $t[0] === T_ENUM)) {
                $has_oop_declaration = true;
                continue;
            }
            if ($t[0] === T_VARIABLE && in_array($t[1], ['$_GET', '$_POST', '$_REQUEST', '$_FILES'], true)) {
                // Top-level superglobal read at depth 0 means procedural HTTP entry script!
                return false;
            }
        }

        return $has_oop_declaration;
    }

    /**
     * Detect read-only WordPress admin views or theme partial templates coupled to WP core APIs with zero dangerous sinks.
     */
    private static function is_safe_wp_template_partial(array $tokens): bool {
        if (self::tokens_have_dangerous_sink($tokens)) {
            return false;
        }

        $wp_partial_apis = [
            'check_admin_referer', 'wp_nonce_field', 'settings_fields', 'submit_button',
            'esc_html_e', 'esc_attr_e', 'esc_html__', 'esc_attr__', '__', '_e', '_x',
            'get_header', 'get_footer', 'get_template_part', 'wp_kses_post', 'selected', 'checked',
        ];
        $has_inline_html = false;
        $has_wp_api      = false;

        foreach ($tokens as $t) {
            if (!is_array($t)) {
                continue;
            }
            if ($t[0] === T_INLINE_HTML && trim($t[1]) !== '') {
                $has_inline_html = true;
            } elseif ($t[0] === T_STRING && in_array(strtolower($t[1]), $wp_partial_apis, true)) {
                $has_wp_api = true;
            }
            if ($has_inline_html && $has_wp_api) {
                return true;
            }
        }

        return $has_wp_api;
    }

    /**
     * Check if tokens read any PHP superglobals ($_GET, $_POST, $_REQUEST, $_FILES).
     */
    private static function check_superglobals(array $tokens): bool {
        foreach ($tokens as $t) {
            if (is_array($t) && $t[0] === T_VARIABLE && in_array($t[1], ['$_GET', '$_POST', '$_REQUEST', '$_FILES'], true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract callback string or array method name (arg #2) from an add_action(...) call.
     */
    private static function extract_callback_name(array $tokens, int $pos): ?string {
        $count         = count($tokens);
        $current_arg   = 1;
        $paren_depth   = 0;
        $bracket_depth = 0;
        $strings       = [];

        for ($i = $pos; $i < min($pos + 80, $count); $i++) {
            $t = $tokens[$i];
            if ($t === '(') {
                $paren_depth++;
                continue;
            }
            if ($t === ')') {
                $paren_depth--;
                if ($paren_depth <= 0) {
                    break;
                }
                continue;
            }
            if ($t === '[') {
                $bracket_depth++;
                continue;
            }
            if ($t === ']') {
                $bracket_depth = max(0, $bracket_depth - 1);
                continue;
            }
            if ($t === ',' && $paren_depth === 1 && $bracket_depth === 0) {
                $current_arg++;
                if ($current_arg > 2) {
                    break;
                }
                continue;
            }
            if ($current_arg === 2 && is_array($t) && ($t[0] === T_FUNCTION || (defined('T_FN') && $t[0] === T_FN))) {
                return null;
            }
            if ($current_arg === 2 && is_array($t) && $t[0] === T_CONSTANT_ENCAPSED_STRING) {
                $strings[] = trim($t[1], "'\"");
            }
        }

        if (empty($strings)) {
            return null;
        }
        $last = end($strings);
        if (is_string($last) && str_contains($last, '::')) {
            $parts = explode('::', $last);
            $last  = end($parts);
        }
        return is_string($last) && $last !== '' ? $last : null;
    }

    /**
     * Inspect nonces, capabilities, and dangerous mutation sinks strictly inside the target callback scope
     * (either an inline Closure at add_action() or the named function/method body in the same file).
     */
    private static function inspect_callback_scope(array $tokens, ?string $callback_name, int $hook_pos): array {
        $result = [
            'has_nonce'          => false,
            'has_cap'            => false,
            'has_dangerous_sink' => true, // Conservative default when callback implementation lives outside this file
            'scope_found'        => false,
        ];

        $count       = count($tokens);
        $body_tokens = [];

        // 1. Check for inline closure / arrow function in argument #2 of add_action(...)
        $paren_depth   = 0;
        $bracket_depth = 0;
        $current_arg   = 1;
        for ($i = $hook_pos; $i < min($hook_pos + 200, $count); $i++) {
            $t = $tokens[$i];
            if ($t === '(') {
                $paren_depth++;
                continue;
            }
            if ($t === ')') {
                $paren_depth--;
                if ($paren_depth <= 0) {
                    break;
                }
                continue;
            }
            if ($t === '[') {
                $bracket_depth++;
                continue;
            }
            if ($t === ']') {
                $bracket_depth = max(0, $bracket_depth - 1);
                continue;
            }
            if ($t === ',' && $paren_depth === 1 && $bracket_depth === 0) {
                $current_arg++;
                if ($current_arg > 2) {
                    break;
                }
                continue;
            }
            if ($current_arg === 2 && is_array($t) && $t[0] === T_FUNCTION) {
                $body_tokens = self::extract_braced_function_body($tokens, $i);
                break;
            }
            if ($current_arg === 2 && defined('T_FN') && is_array($t) && $t[0] === T_FN) {
                for ($j = $i; $j < min($i + 150, $count); $j++) {
                    if ($tokens[$j] === ',' || $tokens[$j] === ')' || $tokens[$j] === ';') {
                        break;
                    }
                    $body_tokens[] = $tokens[$j];
                }
                break;
            }
        }

        // 2. Otherwise search for named function / method definition inside this file
        if (empty($body_tokens) && !empty($callback_name)) {
            $target_fn = strtolower($callback_name);
            if (str_contains($target_fn, '::')) {
                $parts     = explode('::', $target_fn);
                $target_fn = end($parts);
            }
            for ($i = 0; $i < $count; $i++) {
                $t = $tokens[$i];
                if (!is_array($t) || $t[0] !== T_FUNCTION) {
                    continue;
                }
                // Find the identifier token immediately following 'function'
                for ($j = $i + 1; $j < min($i + 6, $count); $j++) {
                    if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                        continue;
                    }
                    if ($tokens[$j] === '&') {
                        continue;
                    }
                    if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING && strtolower($tokens[$j][1]) === $target_fn) {
                        $body_tokens = self::extract_braced_function_body($tokens, $i);
                    }
                    break;
                }
                if (!empty($body_tokens)) {
                    break;
                }
            }
        }

        if (empty($body_tokens)) {
            return $result;
        }

        return self::evaluate_scope_tokens($body_tokens);
    }

    /**
     * Evaluate security posture tokens within a scoped callback body (closure or named function).
     */
    private static function evaluate_scope_tokens(array $body_tokens): array {
        return [
            'has_nonce'          => self::file_has_nonce_verification($body_tokens),
            'has_cap'            => self::file_has_capability_check($body_tokens),
            'has_dangerous_sink' => self::scope_has_dangerous_sink($body_tokens),
            'scope_found'        => true,
        ];
    }

    /**
     * Inspect either an inline closure or a named callback assigned to 'callback' inside a register_rest_route block.
     */
    private static function inspect_rest_block_callback_scope(array $tokens, int $b_start, int $b_end): array {
        for ($i = $b_start; $i <= $b_end; $i++) {
            $t = $tokens[$i];
            if (!is_array($t) || $t[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }
            if (strtolower(trim($t[1], "'\"")) !== 'callback') {
                continue;
            }
            $j = $i + 1;
            while ($j <= $b_end && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if ($j <= $b_end && is_array($tokens[$j]) && $tokens[$j][0] === T_DOUBLE_ARROW) {
                for ($k = $j + 1; $k <= min($j + 10, $b_end); $k++) {
                    if ($tokens[$k] === ',' || $tokens[$k] === ')') {
                        break;
                    }
                    if (is_array($tokens[$k]) && $tokens[$k][0] === T_FUNCTION) {
                        $body = self::extract_braced_function_body($tokens, $k);
                        if (!empty($body)) {
                            return self::evaluate_scope_tokens($body);
                        }
                        break;
                    }
                    if (is_array($tokens[$k]) && defined('T_FN') && $tokens[$k][0] === T_FN) {
                        $body = [];
                        for ($m = $k; $m <= min($k + 150, $b_end); $m++) {
                            if ($tokens[$m] === ',' || $tokens[$m] === ']' || $tokens[$m] === ')') {
                                break;
                            }
                            $body[] = $tokens[$m];
                        }
                        if (!empty($body)) {
                            return self::evaluate_scope_tokens($body);
                        }
                        break;
                    }
                }
            }
            break;
        }

        $cb_name = self::extract_keyed_callback_name($tokens, $b_start, $b_end, 'callback');
        if ($cb_name) {
            return self::inspect_callback_scope($tokens, $cb_name, $b_start);
        }

        return [
            'has_nonce'          => false,
            'has_cap'            => false,
            'has_dangerous_sink' => true,
            'scope_found'        => false,
        ];
    }

    /**
     * Extract tokens enclosed in the { ... } body of a function/closure starting near $fn_pos.
     */
    private static function extract_braced_function_body(array $tokens, int $fn_pos): array {
        $count      = count($tokens);
        $brace_depth = 0;
        $started    = false;
        $body       = [];

        for ($i = $fn_pos; $i < min($fn_pos + 3000, $count); $i++) {
            $t = $tokens[$i];
            if ($t === '{' || (is_array($t) && in_array($t[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
                $brace_depth++;
                $started = true;
                $body[]  = $t;
                continue;
            }
            if (!$started && $t === ';') {
                // Abstract or interface method declaration without body
                return [];
            }
            if ($started) {
                $body[] = $t;
                if ($t === '}') {
                    $brace_depth--;
                    if ($brace_depth <= 0) {
                        break;
                    }
                }
            }
        }

        return $body;
    }

    /**
     * Split a register_rest_route(..., ..., $args) invocation into individual endpoint configuration blocks.
     * Prevents public GET '__return_true' in block #1 from false-flagging authenticated POST/PUT/DELETE in block #2.
     *
     * @return array<int, array{0:int,1:int}>
     */
    private static function extract_rest_endpoint_blocks(array $tokens, int $pos, int $call_end): array {
        $arg3_start  = -1;
        $paren_depth = 0;
        $bracket_d   = 0;
        $arg_num     = 1;

        for ($i = $pos; $i <= $call_end; $i++) {
            $t = $tokens[$i];
            if ($t === '(') {
                $paren_depth++;
            } elseif ($t === ')') {
                $paren_depth--;
            } elseif ($t === '[') {
                $bracket_d++;
            } elseif ($t === ']') {
                $bracket_d = max(0, $bracket_d - 1);
            } elseif ($t === ',' && $paren_depth === 1 && $bracket_d === 0) {
                $arg_num++;
                if ($arg_num === 3) {
                    $arg3_start = $i + 1;
                    break;
                }
            }
        }

        if ($arg3_start < 0 || $arg3_start >= $call_end) {
            return [[$pos, $call_end]];
        }

        // Check if arg 3 is a list of endpoint arrays `[ [ ... ], [ ... ] ]` or single associative array `[ ... ]`
        $outer_open = -1;
        for ($i = $arg3_start; $i <= $call_end; $i++) {
            $t = $tokens[$i];
            if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            if ($t === '[') {
                $outer_open = $i;
            } elseif (is_array($t) && $t[0] === T_ARRAY) {
                // Find '(' of array(...)
                for ($j = $i + 1; $j <= $call_end; $j++) {
                    if ($tokens[$j] === '(') {
                        $outer_open = $j;
                        break;
                    }
                }
            }
            break;
        }

        if ($outer_open < 0) {
            return [[$arg3_start, $call_end]];
        }

        // Scan depth 1 inside outer array for child array blocks
        $sub_blocks = [];
        $cur_depth  = 0;
        $in_assoc   = false;
        $child_start = -1;
        $p_d = 0;
        $b_d = 0;

        for ($i = $outer_open; $i <= $call_end; $i++) {
            $t = $tokens[$i];
            if ($t === '[' || $t === '(') {
                if ($i > $outer_open && $p_d + $b_d === 1 && $child_start < 0) {
                    $prev_tok = $tokens[$i - 1] ?? null;
                    if ($t === '[' || (is_array($prev_tok) && $prev_tok[0] === T_ARRAY)) {
                        $child_start = $i;
                    }
                }
                if ($t === '[') {
                    $b_d++;
                } else {
                    $p_d++;
                }
            } elseif ($t === ']' || $t === ')') {
                if ($t === ']') {
                    $b_d = max(0, $b_d - 1);
                } else {
                    $p_d = max(0, $p_d - 1);
                }
                if ($child_start >= 0 && $p_d + $b_d === 1) {
                    $sub_blocks[] = [$child_start, $i];
                    $child_start  = -1;
                }
                if ($i > $outer_open && $p_d + $b_d === 0) {
                    break;
                }
            } elseif ($p_d + $b_d === 1 && is_array($t) && $t[0] === T_DOUBLE_ARROW) {
                $in_assoc = true;
            }
        }

        if (!$in_assoc && !empty($sub_blocks)) {
            return $sub_blocks;
        }

        return [[$outer_open, $call_end]];
    }

    /**
     * Extract method/function name assigned to a specific array key (e.g. 'callback' => [$this, 'save']).
     */
    private static function extract_keyed_callback_name(array $tokens, int $start, int $end, string $key): ?string {
        $target_key = strtolower($key);
        for ($i = $start; $i <= $end; $i++) {
            $t = $tokens[$i];
            if (!is_array($t) || $t[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }
            if (strtolower(trim($t[1], "'\"")) !== $target_key) {
                continue;
            }
            $j = $i + 1;
            while ($j <= $end && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if ($j <= $end && is_array($tokens[$j]) && $tokens[$j][0] === T_DOUBLE_ARROW) {
                $strings = [];
                for ($k = $j + 1; $k <= min($j + 12, $end); $k++) {
                    if ($tokens[$k] === ',' || $tokens[$k] === ')') {
                        break;
                    }
                    if (is_array($tokens[$k]) && ($tokens[$k][0] === T_FUNCTION || (defined('T_FN') && $tokens[$k][0] === T_FN))) {
                        return null;
                    }
                    if (is_array($tokens[$k]) && $tokens[$k][0] === T_CONSTANT_ENCAPSED_STRING) {
                        $strings[] = trim($tokens[$k][1], "'\"");
                    }
                }
                if (!empty($strings)) {
                    $last = end($strings);
                    if (is_string($last) && str_contains($last, '::')) {
                        $parts = explode('::', $last);
                        $last  = end($parts);
                    }
                    return is_string($last) && $last !== '' ? $last : null;
                }
            }
        }
        return null;
    }

    /**
     * Shared AST check: determine whether PHP tokens contain internal nonce, capability, or cryptographic verification.
     *
     * Scans the full token slice so capability checks are never shadowed by earlier nonce/signature calls.
     *
     * @return string '' if none detected, or 'capability' / 'nonce' / 'signature'.
     */
    public static function tokens_have_auth_guard(array $tokens): string {
        $cap_targets   = ['current_user_can', 'is_user_logged_in', 'user_can', 'auth_redirect', 'current_user_can_for_blog'];
        $sig_targets   = ['hash_hmac', 'hash_equals', 'openssl_verify', 'sodium_crypto_sign_verify_detached'];

        $found_cap   = false;
        $found_nonce = false;
        $found_sig   = false;

        foreach ($tokens as $t) {
            if (!is_array($t) || $t[0] !== T_STRING) {
                continue;
            }
            $fn = strtolower($t[1]);
            if (in_array($fn, $cap_targets, true)) {
                $found_cap = true;
            } elseif (in_array($fn, self::AUTH_NONCE_FUNCTIONS, true)) {
                $found_nonce = true;
            } elseif (in_array($fn, $sig_targets, true)) {
                $found_sig = true;
            }
        }

        if ($found_cap) {
            return 'capability';
        }
        if ($found_nonce) {
            return 'nonce';
        }
        return $found_sig ? 'signature' : '';
    }

    /**
     * Shared AST sink detector: detect mutating database, filesystem, option, user, mail, or OS execution sinks.
     */
    public static function tokens_have_dangerous_sink(array $tokens): bool {
        $dangerous_functions = [
            'update_option', 'add_option', 'delete_option', 'update_site_option', 'add_site_option',
            'update_user_meta', 'add_user_meta', 'delete_user_meta', 'update_post_meta', 'wp_insert_post',
            'wp_update_post', 'wp_delete_post', 'wp_insert_user', 'wp_update_user', 'wp_create_user',
            'wp_delete_user', 'wp_set_auth_cookie', 'wp_set_current_user', 'wp_set_password',
            'move_uploaded_file', 'file_put_contents', 'fwrite', 'fputs', 'unlink', 'wp_delete_file',
            'rmdir', 'wp_handle_upload', 'media_handle_upload', 'wp_mail', 'mail',
            'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'eval',
            'curl_exec', 'wp_remote_post', 'wp_remote_request', 'unserialize', 'maybe_unserialize',
        ];
        $wpdb_mutators = ['query', 'insert', 'update', 'delete', 'replace'];
        $count         = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $t = $tokens[$i];
            if (!is_array($t)) {
                continue;
            }
            if ($t[0] === T_EVAL || ($t[0] === T_STRING && in_array(strtolower($t[1]), $dangerous_functions, true))) {
                return true;
            }
            if ($t[0] === T_VARIABLE && $t[1] === '$wpdb') {
                for ($j = $i + 1; $j < min($i + 6, $count); $j++) {
                    if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING && in_array(strtolower($tokens[$j][1]), $wpdb_mutators, true)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Detect mutating database, filesystem, option, user, mail, or OS execution sinks within callback tokens.
     */
    private static function scope_has_dangerous_sink(array $tokens): bool {
        return self::tokens_have_dangerous_sink($tokens);
    }

    /**
     * Check if tokens contain standard WordPress nonce or cryptographic signature verification.
     */
    private static function file_has_nonce_verification(array $tokens): bool {
        $guard = self::tokens_have_auth_guard($tokens);
        if ($guard === 'nonce' || $guard === 'signature') {
            return true;
        }
        // Fallback when capability check also present alongside nonce in the same scope
        $combined = array_merge(self::AUTH_NONCE_FUNCTIONS, ['hash_hmac', 'hash_equals']);
        foreach ($tokens as $t) {
            if (is_array($t) && $t[0] === T_STRING && in_array(strtolower($t[1]), $combined, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if tokens contain standard WordPress capability checks.
     */
    private static function file_has_capability_check(array $tokens): bool {
        return self::tokens_have_auth_guard($tokens) === 'capability';
    }

    /**
     * Helper to extract a string argument from function call tokens.
     */
    private static function extract_string_arg(array $tokens, int $pos, int $arg_number): ?string {
        $count         = count($tokens);
        $current_arg   = 1;
        $in_parens     = false;
        $paren_depth   = 0;
        $bracket_depth = 0;

        for ($i = $pos; $i < min($pos + 80, $count); $i++) {
            $t = $tokens[$i];

            if ($t === '(') {
                $paren_depth++;
                $in_parens = true;
                continue;
            }

            if ($t === ')') {
                $paren_depth--;
                if ($paren_depth <= 0) {
                    break;
                }
                continue;
            }

            if ($t === '[') {
                $bracket_depth++;
                continue;
            }

            if ($t === ']') {
                $bracket_depth = max(0, $bracket_depth - 1);
                continue;
            }

            if ($t === ',' && $paren_depth === 1 && $bracket_depth === 0) {
                $current_arg++;
                continue;
            }

            if ($in_parens && $paren_depth === 1 && $bracket_depth === 0 && $current_arg === $arg_number && is_array($t) && $t[0] === T_CONSTANT_ENCAPSED_STRING) {
                return trim($t[1], "'\"");
            }
        }

        return null;
    }

    /**
     * Find the closing parenthesis token index of a function invocation starting at $pos.
     */
    private static function find_call_end_pos(array $tokens, int $pos, int $max_lookahead = 180): int {
        $count       = count($tokens);
        $limit       = min($pos + $max_lookahead, $count);
        $paren_depth = 0;
        $started     = false;

        for ($i = $pos; $i < $limit; $i++) {
            if ($tokens[$i] === '(') {
                $paren_depth++;
                $started = true;
            } elseif ($tokens[$i] === ')') {
                $paren_depth--;
                if ($started && $paren_depth <= 0) {
                    return $i;
                }
            }
        }

        return $limit - 1;
    }

    /**
     * Helper to check for a specific string value within a lookahead window.
     */
    private static function has_token_string_within(array $tokens, int $pos, int $window, string $needle): bool {
        $limit = min($pos + $window, count($tokens));
        $needle = strtolower($needle);
        for ($i = $pos; $i < $limit; $i++) {
            $t = $tokens[$i];
            if (is_array($t) && strtolower(trim($t[1], "'\"")) === $needle) {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper to check for string concatenation '.' operator within a window.
     */
    private static function has_string_concat_within(array $tokens, int $pos, int $window): bool {
        $limit = min($pos + $window, count($tokens));
        for ($i = $pos; $i < $limit; $i++) {
            if ($tokens[$i] === '.') {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper to check for adjacent superglobals within a window.
     */
    private static function has_adjacent_superglobal(array $tokens, int $pos, int $window): bool {
        $limit = min($pos + $window, count($tokens));
        for ($i = $pos; $i < $limit; $i++) {
            $t = $tokens[$i];
            if (is_array($t) && $t[0] === T_VARIABLE && in_array($t[1], ['$_GET', '$_POST', '$_REQUEST'], true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether a specific function call argument contains dynamic concatenation (e.g. 'wp_ajax_' . $var).
     */
    private static function is_dynamic_hook_arg(array $tokens, int $pos, int $arg_number): bool {
        $count         = count($tokens);
        $current_arg   = 1;
        $in_parens     = false;
        $paren_depth   = 0;
        $bracket_depth = 0;

        for ($i = $pos; $i < min($pos + 80, $count); $i++) {
            $t = $tokens[$i];
            if ($t === '(') {
                $paren_depth++;
                $in_parens = true;
                continue;
            }
            if ($t === ')') {
                $paren_depth--;
                if ($paren_depth <= 0) {
                    break;
                }
                continue;
            }
            if ($t === '[') {
                $bracket_depth++;
                continue;
            }
            if ($t === ']') {
                $bracket_depth = max(0, $bracket_depth - 1);
                continue;
            }
            if ($t === ',' && $paren_depth === 1 && $bracket_depth === 0) {
                $current_arg++;
                if ($current_arg > $arg_number) {
                    break;
                }
                continue;
            }
            if ($in_parens && $paren_depth === 1 && $bracket_depth === 0 && $current_arg === $arg_number && $t === '.') {
                return true;
            }
        }

        return false;
    }

    /**
     * Inspect argument #1 of wp_remote_get/post/request() for genuine SSRF risk.
     * Ignores superglobals appearing only in arg #2 ($args) or query parameters appended to a hardcoded scheme+host URL.
     */
    private static function has_unvalidated_ssrf_url_arg(array $tokens, int $pos): bool {
        $count         = count($tokens);
        $in_parens     = false;
        $paren_depth   = 0;
        $bracket_depth = 0;
        $first_token   = null;
        $has_super     = false;

        for ($i = $pos; $i < min($pos + 120, $count); $i++) {
            $t = $tokens[$i];
            if ($t === '(') {
                $paren_depth++;
                $in_parens = true;
                continue;
            }
            if ($t === ')') {
                $paren_depth--;
                if ($paren_depth <= 0) {
                    break;
                }
                continue;
            }
            if ($t === '[') {
                $bracket_depth++;
                continue;
            }
            if ($t === ']') {
                $bracket_depth = max(0, $bracket_depth - 1);
                continue;
            }
            if ($t === ',' && $paren_depth === 1 && $bracket_depth === 0) {
                // End of URL argument #1
                break;
            }
            if (!$in_parens) {
                continue;
            }
            if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            if ($first_token === null) {
                $first_token = $t;
            }
            if (is_array($t) && $t[0] === T_VARIABLE && in_array($t[1], ['$_GET', '$_POST', '$_REQUEST'], true)) {
                $has_super = true;
            }
        }

        if (!$has_super) {
            return false;
        }

        // Fixed scheme + hardcoded domain followed by '/' or '?' guarantees outbound host cannot be pivoted by input
        if (is_array($first_token) && $first_token[0] === T_CONSTANT_ENCAPSED_STRING) {
            $literal = trim($first_token[1], "'\"");
            if (preg_match('#^https?://[a-z0-9.-]+(?::\d+)?[/?]#i', $literal)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Discover all installed plugins, active themes, mu-plugins, and drop-ins,
     * enriched with official WordPress.org origin, checksums, and known vendor attestation.
     *
     * @param bool $deep_verify True during scans/exports to verify release checksums on disk.
     * @return array
     */
    public static function discover_all_components(bool $deep_verify = false): array {
        $components = [];

        // 1. Plugins (Active & Inactive)
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins    = function_exists('get_plugins') ? get_plugins() : [];
        $active_plugins = get_option('active_plugins', []);
        $update_plugins = get_site_transient('update_plugins');

        foreach ($all_plugins as $plugin_file => $data) {
            $slug = dirname($plugin_file);
            if ($slug === '.') {
                $slug = basename($plugin_file, '.php');
            }

            $is_active        = in_array($plugin_file, $active_plugins, true);
            $cur_version      = $data['Version'] ?? '0.0.0';
            $update_available = !empty($update_plugins->response[$plugin_file]);
            $latest_version   = $update_available ? ($update_plugins->response[$plugin_file]->new_version ?? null) : null;
            $cves             = class_exists('\\WebCareProScanner\\WordPress\\UpdateScanner')
                ? \WebCareProScanner\WordPress\UpdateScanner::get_plugin_cves($slug, $cur_version, $data['Name'] ?? $slug)
                : [];

            $comp = [
                'type'             => 'plugin',
                'slug'             => $slug,
                'file'             => $plugin_file,
                'name'             => $data['Name'] ?? $slug,
                'version'          => $cur_version,
                'author'           => $data['Author'] ?? '',
                'is_active'        => $is_active,
                'path'             => WP_PLUGIN_DIR . '/' . $slug,
                'update_available' => $update_available,
                'latest_version'   => $latest_version,
                'cves'             => $cves,
                'cve_count'        => count($cves),
                'has_cve'          => !empty($cves),
            ];
            $components['plugin:' . $slug] = array_merge($comp, ComponentIntegrityVerifier::verify_component($comp, $deep_verify));
        }

        // 2. Active Theme & Child Theme
        $update_themes = get_site_transient('update_themes');
        $theme = wp_get_theme();
        if ($theme->exists()) {
            $t_slug    = $theme->get_stylesheet();
            $t_ver     = $theme->get('Version') ?: '1.0.0';
            $t_name    = $theme->get('Name') ?: $t_slug;
            $t_upd     = !empty($update_themes->response[$t_slug]);
            $t_latest  = $t_upd ? ($update_themes->response[$t_slug]['new_version'] ?? null) : null;
            $t_cves    = class_exists('\\WebCareProScanner\\WordPress\\UpdateScanner')
                ? \WebCareProScanner\WordPress\UpdateScanner::get_theme_cves($t_slug, $t_ver, $t_name)
                : [];

            $comp = [
                'type'             => 'theme',
                'slug'             => $t_slug,
                'name'             => $t_name,
                'version'          => $t_ver,
                'author'           => $theme->get('Author') ?: '',
                'is_active'        => true,
                'is_child'         => is_child_theme(),
                'path'             => $theme->get_stylesheet_directory(),
                'update_available' => $t_upd,
                'latest_version'   => $t_latest,
                'cves'             => $t_cves,
                'cve_count'        => count($t_cves),
                'has_cve'          => !empty($t_cves),
            ];
            $components['theme:' . $t_slug] = array_merge($comp, ComponentIntegrityVerifier::verify_component($comp, $deep_verify));

            // Parent theme if child active
            if (is_child_theme()) {
                $parent = $theme->parent();
                if ($parent && $parent->exists()) {
                    $p_slug   = $parent->get_template();
                    $p_ver    = $parent->get('Version') ?: '1.0.0';
                    $p_name   = $parent->get('Name') ?: $p_slug;
                    $p_upd    = !empty($update_themes->response[$p_slug]);
                    $p_latest = $p_upd ? ($update_themes->response[$p_slug]['new_version'] ?? null) : null;
                    $p_cves   = class_exists('\\WebCareProScanner\\WordPress\\UpdateScanner')
                        ? \WebCareProScanner\WordPress\UpdateScanner::get_theme_cves($p_slug, $p_ver, $p_name)
                        : [];

                    $pcomp = [
                        'type'             => 'theme',
                        'slug'             => $p_slug,
                        'name'             => $p_name,
                        'version'          => $p_ver,
                        'author'           => $parent->get('Author') ?: '',
                        'is_active'        => true,
                        'is_child'         => false,
                        'path'             => $parent->get_template_directory(),
                        'update_available' => $p_upd,
                        'latest_version'   => $p_latest,
                        'cves'             => $p_cves,
                        'cve_count'        => count($p_cves),
                        'has_cve'          => !empty($p_cves),
                    ];
                    $components['theme:' . $p_slug] = array_merge($pcomp, ComponentIntegrityVerifier::verify_component($pcomp, $deep_verify));
                }
            }
        }

        // 3. MU-Plugins
        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            $mu_comp = [
                'type'      => 'mu_plugin',
                'slug'      => 'mu-plugins',
                'name'      => 'Must-Use Plugins',
                'version'   => '1.0',
                'is_active' => true,
                'path'      => WPMU_PLUGIN_DIR,
            ];
            $components['mu_plugins'] = array_merge($mu_comp, ComponentIntegrityVerifier::verify_component($mu_comp, $deep_verify));
        }

        return $components;
    }

    /**
     * Build flat array of PHP files to inspect from components.
     *
     * @param array $components
     * @return array
     */
    private static function build_file_queue(array $components): array {
        $queue = [];

        foreach ($components as $comp) {
            // Skip self-plugin AST scanning when verified clean against plugin-manifest.json
            if (($comp['slug'] ?? '') === 'webcare-pro-security' && !empty($comp['checksum_verified'])) {
                continue;
            }

            $meta = [
                'component'         => $comp['name'],
                'slug'              => $comp['slug'] ?? '',
                'version'           => $comp['version'] ?? '',
                'type'              => $comp['type'],
                'origin_type'       => $comp['origin_type'] ?? 'custom_unmanaged',
                'is_official_wporg' => !empty($comp['is_official_wporg']),
                'is_known_vendor'   => !empty($comp['is_known_vendor']),
                'vendor_name'       => $comp['vendor_name'] ?? null,
            ];

            $path = $comp['path'] ?? '';
            if (!is_dir($path)) {
                // Single file plugin
                if (file_exists($path . '.php')) {
                    $queue[] = array_merge($meta, [
                        'path'     => $path . '.php',
                        'rel_path' => basename($path . '.php'),
                    ]);
                }
                continue;
            }

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($iterator as $item) {
                    if (!$item->isFile() || $item->getExtension() !== 'php') {
                        continue;
                    }

                    $filePath = wp_normalize_path($item->getPathname());

                    // Skip third-party vendor bundles, test suites, build artifacts & bundled SDKs
                    if (preg_match('#/(?:node_modules|vendor|vendor_prefixed|freemius|\.git|\.github|cache|dist|tests|languages)/#i', $filePath)) {
                        continue;
                    }

                    $queue[] = array_merge($meta, [
                        'path'     => $filePath,
                        'rel_path' => ltrim(str_replace(wp_normalize_path(WP_CONTENT_DIR), '', $filePath), '/\\'),
                    ]);
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        return $queue;
    }
}
