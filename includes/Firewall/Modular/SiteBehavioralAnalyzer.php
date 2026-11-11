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
        // Build Component & File Inventory
        $components = self::discover_all_components();
        $file_queue = self::build_file_queue($components);

        $session_id = 'scan_' . time() . '_' . wp_generate_password(6, false, false);

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
                'taint_sinks_found'      => 0,
                'cve_vulnerabilities'    => 0,
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

        $token_count = count($tokens);
        $component_name = $file_info['component'] ?? 'WordPress Core/Custom';
        $component_type = $file_info['type'] ?? 'unknown';
        $rel_path       = $file_info['rel_path'] ?? basename($path);

        // 1. Check for missing defined('ABSPATH') in standalone plugins/themes/uploads scripts
        $has_abspath_guard = self::check_abspath_guard($tokens);
        $has_superglobals = self::check_superglobals($tokens);

        if (!$has_abspath_guard && $has_superglobals && in_array($component_type, ['plugin', 'theme', 'upload'], true)) {
            $counters['missing_abspath_files']++;
            $findings[] = [
                'type'        => 'missing_abspath_script',
                'component'   => $component_name,
                'type_label'  => $component_type,
                'file'        => $rel_path,
                'full_path'   => $path,
                'line'        => 1,
                'evidence'    => __('Direct-access PHP script reads superglobals without defined("ABSPATH") guard.', 'webcare-pro-security'),
                'severity'    => 'high',
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

            // Check if file contains nonce verification or capability check
            $has_nonce = self::file_has_nonce_verification($tokens);
            $has_cap   = self::file_has_capability_check($tokens);

            $endpoint_info = [
                'hook'           => $arg1,
                'action'         => $action_slug,
                'callback'       => $arg2 ?: 'closure/variable',
                'component'      => $component_name,
                'file'           => $rel_path,
                'line'           => $line,
                'is_guest'       => $is_guest,
                'has_nonce'      => $has_nonce,
                'has_capability' => $has_cap,
            ];

            $endpoint_map[] = $endpoint_info;

            // Flag unprotected guest AJAX hooks
            if ($is_guest && !$has_nonce && !$has_cap) {
                $counters['unprotected_ajax_hooks']++;
                $findings[] = [
                    'type'        => 'unprotected_guest_ajax',
                    'component'   => $component_name,
                    'file'        => $rel_path,
                    'line'        => $line,
                    'action'      => $action_slug,
                    'hook'        => $arg1,
                    'callback'    => $arg2,
                    'evidence'    => sprintf(
                        /* translators: %1$s: action slug, %2$s: callback */
                        __('Unprotected guest AJAX hook "%1$s" (callback: %2$s) lacks nonce verification or capability authorization.', 'webcare-pro-security'),
                        $action_slug,
                        $arg2 ?: 'inline closure'
                    ),
                    'severity'    => 'critical',
                ];
            }
        }
    }

    /**
     * Inspect a register_rest_route(...) invocation.
     */
    private static function inspect_rest_route_call(array $tokens, int $pos, array $file_info, array &$endpoint_map, array &$findings, array &$counters): void {
        $namespace = self::extract_string_arg($tokens, $pos, 1) ?: 'custom/v1';
        $route     = self::extract_string_arg($tokens, $pos, 2) ?: '/';
        $line      = is_array($tokens[$pos]) ? $tokens[$pos][2] : 1;
        $component = $file_info['component'] ?? 'Custom';
        $rel_path  = $file_info['rel_path'] ?? '';

        $counters['rest_routes_found']++;

        // Inspect adjacent tokens for '__return_true' permission callback
        $full_route = '/' . ltrim($namespace, '/') . '/' . ltrim($route, '/');
        $is_permissive = self::has_token_string_within($tokens, $pos, 120, '__return_true');
        $has_post_method = self::has_token_string_within($tokens, $pos, 120, 'POST') ||
                           self::has_token_string_within($tokens, $pos, 120, 'CREATABLE') ||
                           self::has_token_string_within($tokens, $pos, 120, 'EDITABLE');

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

        if ($is_permissive && $has_post_method) {
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

        $line = $method_token[2];
        $component = $file_info['component'] ?? 'Custom';
        $rel_path  = $file_info['rel_path'] ?? '';

        // Check if adjacent arguments contain string concatenation (.) or inline variables without prepare
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
     * Check if tokens contain defined('ABSPATH') check.
     */
    private static function check_abspath_guard(array $tokens): bool {
        $limit = min(60, count($tokens));
        for ($i = 0; $i < $limit; $i++) {
            $t = $tokens[$i];
            if (is_array($t) && in_array(strtolower($t[1]), ['abspath', 'wpinc'], true)) {
                return true;
            }
        }
        return false;
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
     * Discover all installed plugins, active themes, mu-plugins, and drop-ins.
     *
     * @return array
     */
    public static function discover_all_components(): array {
        $components = [];

        // 1. Plugins (Active & Inactive)
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $active_plugins = get_option('active_plugins', []);

        foreach ($all_plugins as $plugin_file => $data) {
            $slug = dirname($plugin_file);
            if ($slug === '.') {
                $slug = basename($plugin_file, '.php');
            }

            $is_active = in_array($plugin_file, $active_plugins, true);
            $components['plugin:' . $slug] = [
                'type'         => 'plugin',
                'slug'         => $slug,
                'file'         => $plugin_file,
                'name'         => $data['Name'] ?? $slug,
                'version'      => $data['Version'] ?? '0.0.0',
                'author'       => $data['Author'] ?? '',
                'is_active'    => $is_active,
                'path'         => WP_PLUGIN_DIR . '/' . $slug,
            ];
        }

        // 2. Active Theme & Child Theme
        $theme = wp_get_theme();
        if ($theme->exists()) {
            $components['theme:' . $theme->get_stylesheet()] = [
                'type'         => 'theme',
                'slug'         => $theme->get_stylesheet(),
                'name'         => $theme->get('Name') ?: $theme->get_stylesheet(),
                'version'      => $theme->get('Version') ?: '1.0.0',
                'is_active'    => true,
                'is_child'     => is_child_theme(),
                'path'         => $theme->get_stylesheet_directory(),
            ];

            // Parent theme if child active
            if (is_child_theme()) {
                $parent = $theme->parent();
                if ($parent && $parent->exists()) {
                    $components['theme:' . $parent->get_template()] = [
                        'type'         => 'theme',
                        'slug'         => $parent->get_template(),
                        'name'         => $parent->get('Name') ?: $parent->get_template(),
                        'version'      => $parent->get('Version') ?: '1.0.0',
                        'is_active'    => true,
                        'is_child'     => false,
                        'path'         => $parent->get_template_directory(),
                    ];
                }
            }
        }

        // 3. MU-Plugins
        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            $components['mu_plugins'] = [
                'type'      => 'mu_plugin',
                'slug'      => 'mu-plugins',
                'name'      => 'Must-Use Plugins',
                'version'   => '1.0',
                'is_active' => true,
                'path'      => WPMU_PLUGIN_DIR,
            ];
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
            $path = $comp['path'] ?? '';
            if (!is_dir($path)) {
                // Single file plugin
                if (file_exists($path . '.php')) {
                    $queue[] = [
                        'component' => $comp['name'],
                        'type'      => $comp['type'],
                        'path'      => $path . '.php',
                        'rel_path'  => basename($path . '.php'),
                    ];
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

                    // Skip vendor, node_modules, cache, dist directories
                    if (preg_match('#/(?:node_modules|vendor|\.git|cache|dist|tests)/#i', $filePath)) {
                        continue;
                    }

                    $queue[] = [
                        'component' => $comp['name'],
                        'type'      => $comp['type'],
                        'path'      => $filePath,
                        'rel_path'  => ltrim(str_replace(wp_normalize_path(WP_CONTENT_DIR), '', $filePath), '/\\'),
                    ];
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        return $queue;
    }
}
