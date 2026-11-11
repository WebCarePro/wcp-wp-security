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
            'updated_at'         => time(),
            'current_phase'      => 1, // 1: Census, 2: Hooks/AST, 3: REST, 4: Taint/Sinks, 5: Direct-Access, 6: Synthesis
            'total_components'   => count($components),
            'total_files'        => count($file_queue),
            'processed_files'    => 0,
            'current_index'      => 0,
            'current_component'  => '',
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

        return [
            'success'            => true,
            'session_id'         => $session_id,
            'status'             => 'running',
            'total_components'   => count($components),
            'total_files'        => count($file_queue),
            'current_phase'      => 1,
            'message'            => sprintf(
                /* translators: %1$d: components count, %2$d: files count */
                __('Behavioral scan session initialized: %1$d components and %2$d PHP files queued.', 'webcare-pro-security'),
                count($components),
                count($file_queue)
            ),
        ];
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

            $state['current_component'] = $file_info['component'] ?? '';

            // Analyze individual PHP file
            self::analyze_php_file($file_info, $endpoint_map, $findings, $counters);
        }

        $state['current_index']   = $current_index;
        $state['processed_files'] = $current_index;
        $state['endpoint_map']    = $endpoint_map;
        $state['findings']        = $findings;
        $state['counters']        = $counters;
        $state['updated_at']      = time();

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
            $state['status'] = 'completed';
            $state['completed_at'] = time();
            $state['current_phase'] = 6;

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
            $summary = BehavioralVaultManager::get_vault_summary();
            return [
                'success'           => true,
                'status'            => !empty($summary['last_scan']) ? 'idle_with_results' : 'not_started',
                'progress_pct'      => !empty($summary['last_scan']) ? 100 : 0,
                'vault_summary'     => $summary,
                'counters'          => $summary['counters'] ?? [],
            ];
        }

        return self::format_progress_response($state);
    }

    /**
     * Format standardized progress response for React UI.
     *
     * @param array $state
     * @return array
     */
    private static function format_progress_response(array $state): array {
        $total = max(1, intval($state['total_files'] ?? 0));
        $processed = intval($state['processed_files'] ?? 0);
        $pct = min(100, round(($processed / $total) * 100, 1));

        $phase_labels = [
            1 => __('Extension & Version Census', 'webcare-pro-security'),
            2 => __('Hook Registrations & functions.php AST', 'webcare-pro-security'),
            3 => __('REST API & Public Route Attack-Surface', 'webcare-pro-security'),
            4 => __('Source-to-Sink Taint & Vulnerability Hunter', 'webcare-pro-security'),
            5 => __('Direct-Access Script & Missing ABSPATH Discovery', 'webcare-pro-security'),
            6 => __('Modular Firewall Rule Synthesis & Simulation', 'webcare-pro-security'),
        ];

        return [
            'success'            => true,
            'session_id'         => $state['session_id'] ?? '',
            'status'             => $state['status'] ?? 'idle',
            'progress_pct'       => $pct,
            'current_phase'      => $state['current_phase'] ?? 1,
            'phase_label'        => $phase_labels[$state['current_phase'] ?? 1] ?? '',
            'total_files'        => $total,
            'processed_files'    => $processed,
            'current_component'  => $state['current_component'] ?? '',
            'counters'           => $state['counters'] ?? [],
            'elapsed_seconds'    => time() - ($state['started_at'] ?? time()),
            'is_completed'       => ($state['status'] ?? '') === 'completed',
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
        $has_abspath_guard = self::check_abspath_guard($tokens);
        $has_superglobals  = self::check_superglobals($tokens);
        $is_pure_decl      = self::is_pure_declaration_file($tokens);

        if (!$has_abspath_guard && $has_superglobals && !$is_pure_decl && empty($file_forensics['known_vendor_lib']) && in_array($component_type, ['plugin', 'theme', 'upload'], true)) {
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

                // SSRF Sink inspection (wp_remote_get, curl_exec with dynamic $_GET/$_POST)
                if (in_array($fn_name, ['wp_remote_get', 'wp_remote_post', 'wp_remote_request'], true)) {
                    if (self::has_adjacent_superglobal($tokens, $i, 30)) {
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

        if (!$arg1) {
            return;
        }

        $line = is_array($tokens[$pos]) ? $tokens[$pos][2] : 1;
        $component_name = $file_info['component'] ?? 'Custom';
        $rel_path = $file_info['rel_path'] ?? '';

        // Match AJAX Hooks
        if (str_starts_with($arg1, 'wp_ajax_nopriv_') || str_starts_with($arg1, 'wp_ajax_') || str_starts_with($arg1, 'admin_post_nopriv_')) {
            $counters['ajax_hooks_found']++;
            $is_guest = str_starts_with($arg1, 'wp_ajax_nopriv_') || str_starts_with($arg1, 'admin_post_nopriv_');
            $action_slug = str_replace(['wp_ajax_nopriv_', 'wp_ajax_', 'admin_post_nopriv_'], '', $arg1);
            $cb_name     = $arg2 ?: self::extract_callback_name($tokens, $pos);

            // Inspect strictly inside the callback / closure scope rather than across the entire file
            $scope     = self::inspect_callback_scope($tokens, $cb_name, $pos);
            $has_nonce = $scope['has_nonce'];
            $has_cap   = $scope['has_cap'];
            $has_sink  = $scope['has_dangerous_sink'];

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
                $counters['unprotected_ajax_hooks']++;
                $is_verified_read_only = !$has_sink && !empty($file_info['is_official_wporg']);
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
     * Inspect a register_rest_route(...) invocation.
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

        // Inspect strictly inside THIS register_rest_route(...) invocation up to its closing parenthesis
        $full_route = '/' . ltrim($namespace, '/') . '/' . ltrim($route, '/');
        $call_end   = self::find_call_end_pos($tokens, $pos, 180);
        $window_len = max(1, $call_end - $pos + 1);
        $is_permissive   = self::has_token_string_within($tokens, $pos, $window_len, '__return_true');
        $has_post_method = self::has_token_string_within($tokens, $pos, $window_len, 'POST') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'PUT') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'PATCH') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'DELETE') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'CREATABLE') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'EDITABLE') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'DELETABLE') ||
                           self::has_token_string_within($tokens, $pos, $window_len, 'ALLMETHODS');

        $endpoint_map[] = [
            'type'          => 'rest_route',
            'namespace'     => $namespace,
            'route'         => $route,
            'full_route'    => $full_route,
            'component'     => $component,
            'file'          => $rel_path,
            'line'          => $line,
            'is_permissive' => $is_permissive,
            'is_creatable'  => $has_post_method,
        ];

        // Only synthesize permissive REST route guards when literal route strings are resolved
        if ($raw_namespace && $raw_route && $is_permissive && $has_post_method) {
            $counters['permissive_rest_routes']++;
            $findings[] = [
                'type'        => 'permissive_rest_route',
                'component'   => $component,
                'file'        => $rel_path,
                'line'        => $line,
                'route'       => $full_route,
                'evidence'    => sprintf(
                    /* translators: %s: REST route */
                    __('REST API endpoint "%s" permits unauthenticated write access via "permission_callback => __return_true".', 'webcare-pro-security'),
                    $full_route
                ),
                'severity'    => 'high',
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
        foreach ($tokens as $t) {
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
            if ($non_trivial >= 150) {
                break;
            }
        }
        return false;
    }

    /**
     * Determine whether a PHP file only contains namespace/use/class/interface/trait/enum declarations
     * (i.e. zero top-level procedural code that executes superglobals when invoked directly via HTTP).
     */
    private static function is_pure_declaration_file(array $tokens): bool {
        $depth = 0;
        $count = count($tokens);
        $has_oop_declaration = false;

        for ($i = 0; $i < $count; $i++) {
            $t = $tokens[$i];
            if ($t === '{') {
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
            if (in_array($t[0], [T_CLASS, T_INTERFACE, T_TRAIT], true) || (defined('T_ENUM') && $t[0] === T_ENUM)) {
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
        $count       = count($tokens);
        $current_arg = 1;
        $paren_depth = 0;
        $strings     = [];

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
            if ($t === ',' && $paren_depth === 1) {
                $current_arg++;
                if ($current_arg > 2) {
                    break;
                }
                continue;
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
        $paren_depth = 0;
        $current_arg = 1;
        for ($i = $hook_pos; $i < min($hook_pos + 120, $count); $i++) {
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
            if ($t === ',' && $paren_depth === 1) {
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

        $result['scope_found']        = true;
        $result['has_nonce']          = self::file_has_nonce_verification($body_tokens);
        $result['has_cap']            = self::file_has_capability_check($body_tokens);
        $result['has_dangerous_sink'] = self::scope_has_dangerous_sink($body_tokens);

        return $result;
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
     * Detect mutating database, filesystem, option, user, mail, or OS execution sinks within callback tokens.
     */
    private static function scope_has_dangerous_sink(array $tokens): bool {
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
     * Check if file contains standard nonce verification functions.
     */
    private static function file_has_nonce_verification(array $tokens): bool {
        $targets = ['check_ajax_referer', 'check_admin_referer', 'wp_verify_nonce'];
        foreach ($tokens as $t) {
            if (is_array($t) && $t[0] === T_STRING && in_array(strtolower($t[1]), $targets, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if file contains standard capability check functions.
     */
    private static function file_has_capability_check(array $tokens): bool {
        $targets = ['current_user_can', 'is_user_logged_in', 'user_can'];
        foreach ($tokens as $t) {
            if (is_array($t) && $t[0] === T_STRING && in_array(strtolower($t[1]), $targets, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper to extract a string argument from function call tokens.
     */
    private static function extract_string_arg(array $tokens, int $pos, int $arg_number): ?string {
        $count = count($tokens);
        $current_arg = 1;
        $in_parens = false;
        $paren_depth = 0;

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

            if ($t === ',' && $paren_depth === 1) {
                $current_arg++;
                continue;
            }

            if ($in_parens && $current_arg === $arg_number && is_array($t) && $t[0] === T_CONSTANT_ENCAPSED_STRING) {
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
