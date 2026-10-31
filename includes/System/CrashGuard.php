<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CrashGuard
 *
 * Enterprise-grade circuit breaker and self-preservation engine for WCP Security Scanner.
 * Ensures that unexpected PHP exceptions, TypeErrors, or fatal errors originating inside
 * the plugin do not cause persistent website crashes or recurring WSOD downtime.
 *
 * Architectural Principles:
 * 1. Safe Mode Isolation: Disables active WAF, FIM, scans, and auth hooks; loads only minimal admin UI.
 * 2. Scoped Shutdown Interception: Listens strictly for fatal errors occurring inside our plugin directory.
 * 3. Multi-Strike Threshold: Requires 3 fatals within 300 seconds (5 mins) before auto-deactivation.
 * 4. Ultra-Lean Shutdown Path: Single fast update_option, zero remote HTTP or heavy DB calls on fatal path.
 * 5. Accurate, Honest Copy: Avoids misleading "100% online" absolutes; frames as self-preservation.
 * 6. Privacy First: Diagnostics remain 100% local with safe copy/download capability, zero auto phone-home.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CrashGuard {

    public const OPTION_SAFE_MODE        = 'wcpscan_circuit_breaker_safe_mode';
    public const OPTION_LAST_INCIDENT    = 'wcpscan_circuit_breaker_last_incident';
    public const OPTION_INCIDENT_ARCHIVE = 'wcpscan_circuit_breaker_archive';
    public const OPTION_CRASH_HISTORY    = 'wcpscan_circuit_breaker_history';
    public const ACTION_RESET            = 'wcpscan_reset_circuit_breaker';
    public const ACTION_DEACTIVATE       = 'wcpscan_circuit_breaker_deactivate';
    public const ACTION_TEST_SYNTAX      = 'wcpscan_test_circuit_syntax';

    /**
     * Maximum historical incidents to retain in archive.
     */
    private const MAX_ARCHIVE_ENTRIES    = 15;

    /**
     * Multi-strike deactivation limits.
     */
    private const STRIKE_LIMIT           = 3;   // Number of fatal strikes to trigger deactivation
    private const STRIKE_WINDOW_SECONDS  = 300; // 5 minutes window

    /**
     * Whether the circuit breaker has isolated the plugin on this execution thread.
     */
    private static bool $isolated = false;

    /**
     * Register early real-time error interceptors and shutdown hooks.
     */
    public static function register_protection(): void {
        // Register shutdown handler as early as possible
        register_shutdown_function([__CLASS__, 'handle_fatal_shutdown']);

        // Admin recovery notices & manual escape routes
        if (is_admin()) {
            add_action('admin_notices', [__CLASS__, 'render_admin_notice']);
            add_action('admin_post_' . self::ACTION_RESET, [__CLASS__, 'handle_reset_action']);
            add_action('admin_post_' . self::ACTION_DEACTIVATE, [__CLASS__, 'handle_self_deactivation']);
            add_action('admin_post_' . self::ACTION_TEST_SYNTAX, [__CLASS__, 'handle_test_syntax_action']);
        }
    }

    /**
     * Check if the plugin is currently isolated in Safe Mode.
     *
     * @return bool
     */
    public static function is_safe_mode_active(): bool {
        if (self::$isolated) {
            return true;
        }

        return (bool) get_option(self::OPTION_SAFE_MODE, false);
    }

    /**
     * Execute a callable safely under the CrashGuard shield.
     *
     * @param callable $callback
     * @return mixed
     */
    public static function run_guarded(callable $callback) {
        if (self::is_safe_mode_active()) {
            return null;
        }

        try {
            return $callback();
        } catch (\Throwable $e) {
            self::engage_safe_mode_from_throwable($e);
            return null;
        }
    }

    /**
     * Engage Safe Mode isolation from a caught \Throwable.
     *
     * @param \Throwable $e
     */
    public static function engage_safe_mode_from_throwable(\Throwable $e): void {
        self::$isolated = true;

        $fingerprint = md5($e->getFile() . ':' . $e->getLine() . ':' . $e->getCode());
        $now = time();

        $incident = self::build_forensic_incident_payload([
            'type'        => get_class($e),
            'message'     => $e->getMessage(),
            'file'        => wp_normalize_path($e->getFile()),
            'line'        => $e->getLine(),
            'fingerprint' => $fingerprint,
            'trace'       => $e->getTraceAsString(),
            'timestamp'   => $now,
            'datetime'    => gmdate('Y-m-d H:i:s') . ' GMT',
        ]);

        update_option(self::OPTION_LAST_INCIDENT, $incident, false);
        update_option(self::OPTION_SAFE_MODE, true, false);
        self::archive_incident($incident);

        // Record in server error log for sysadmin visibility
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log(sprintf(
            '[WCP CrashGuard] Intercepted %s in %s:%d - %s. Safe Mode engaged to protect host website. Endpoint: %s %s',
            $incident['type'],
            $incident['file'],
            $incident['line'],
            $incident['message'],
            $incident['request_method'] ?? 'UNKNOWN',
            $incident['request_uri'] ?? '/'
        ));
    }

    /**
     * Ultra-lean shutdown handler: Catches unhandled fatal errors before next request loads.
     * Keeps execution strictly lightweight: no heavy DB reads/writes, no remote HTTP, no scanning.
     */
    public static function handle_fatal_shutdown(): void {
        $error = error_get_last();
        if (!$error) {
            return;
        }

        $fatal_types = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
        if (!in_array($error['type'], $fatal_types, true)) {
            return;
        }

        $error_file = wp_normalize_path($error['file']);
        $plugin_dir = wp_normalize_path(defined('WCPSCAN_PATH') ? WCPSCAN_PATH : dirname(__DIR__, 2) . '/');

        // Verify if error originated inside WCP Security Scanner
        if (strpos($error_file, $plugin_dir) === false) {
            return; // Not our plugin, do not touch
        }

        $fingerprint = md5($error_file . ':' . $error['line']);
        $now = time();

        $incident = self::build_forensic_incident_payload([
            'type'        => 'PHP Fatal Error (E_' . $error['type'] . ')',
            'message'     => $error['message'],
            'file'        => $error_file,
            'line'        => $error['line'],
            'fingerprint' => $fingerprint,
            'trace'       => 'Fatal error caught at PHP shutdown lifecycle.',
            'timestamp'   => $now,
            'datetime'    => gmdate('Y-m-d H:i:s') . ' GMT',
        ]);

        // 1. Immediately flag Safe Mode for NEXT requests and record in archive
        update_option(self::OPTION_LAST_INCIDENT, $incident, false);
        update_option(self::OPTION_SAFE_MODE, true, false);
        self::archive_incident($incident);

        // 2. Check multi-strike threshold (3 crashes in 5 minutes)
        $history = get_option(self::OPTION_CRASH_HISTORY, []);
        if (!is_array($history)) {
            $history = [];
        }

        // Clean out timestamps older than our 5-minute sliding window
        $window_start = $now - self::STRIKE_WINDOW_SECONDS;
        $history = array_values(array_filter($history, function ($ts) use ($window_start) {
            return $ts >= $window_start;
        }));

        $history[] = $now;
        update_option(self::OPTION_CRASH_HISTORY, $history, false);

        // Stage 2: Automatic Deactivation if crash loop persists
        if (count($history) >= self::STRIKE_LIMIT) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            if (defined('WCPSCAN_FILE') && function_exists('deactivate_plugins')) {
                deactivate_plugins(WCPSCAN_FILE, true);
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log(sprintf(
                    '[WCP CrashGuard] %d consecutive fatal crashes detected within 5 minutes. WCP Security Scanner automatically self-deactivated to preserve host stability.',
                    count($history)
                ));
            }
        }
    }

    /**
     * Build rich diagnostic forensic payload detailing request environment, user context, and code snapshot.
     *
     * @param array $base Base error data (type, message, file, line, timestamp, etc.)
     * @return array Enriched forensic incident dossier
     */
    private static function build_forensic_incident_payload(array $base): array {
        $file = $base['file'] ?? '';
        $line = (int) ($base['line'] ?? 0);

        // 1. Extract 20-line surrounding code snippet around the error
        $code_snippet = self::extract_code_context($file, $line);

        // 2. Categorize root cause
        $root_cause = self::categorize_root_cause($base['type'] ?? '', $base['message'] ?? '');

        // 3. User Identity context
        $user_info = 'Unauthenticated Visitor / Background Task';
        if (function_exists('wp_get_current_user')) {
            $curr = wp_get_current_user();
            if ($curr && $curr->exists()) {
                $user_info = sprintf('%s (ID: %d, Roles: %s)', $curr->user_login, $curr->ID, implode(', ', $curr->roles));
            }
        }

        // 4. Request Endpoint & Context
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'CLI';
        $http_referer = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : 'Direct / None';

        $endpoint_type = 'Front-end Request';
        if (defined('DOING_CRON') && DOING_CRON) {
            $endpoint_type = 'WP-Cron Background Scheduler';
        } elseif (defined('WP_CLI') && WP_CLI) {
            $endpoint_type = 'WP-CLI Command Runner';
        } elseif (strpos($request_uri, '/wp-json/') !== false) {
            $endpoint_type = 'WordPress REST API (' . strtok($request_uri, '?') . ')';
        } elseif (strpos($request_uri, 'admin-ajax.php') !== false) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $action = isset($_REQUEST['action']) ? sanitize_text_field(wp_unslash($_REQUEST['action'])) : 'unknown';
            $endpoint_type = 'AJAX Handler (action: ' . $action . ')';
        } elseif (is_admin()) {
            $endpoint_type = 'WordPress Admin Dashboard';
        }

        // 5. Sanitize request parameters (mask passwords, tokens, keys)
        $sanitized_params = [];
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $raw_params = !empty($_POST) ? wp_unslash($_POST) : (!empty($_GET) ? wp_unslash($_GET) : []);
        if (is_array($raw_params)) {
            foreach ($raw_params as $pk => $pv) {
                if (preg_match('/(pass|token|secret|key|auth|cookie|nonce)/i', (string) $pk)) {
                    $sanitized_params[$pk] = '******** (REDACTED)';
                } else {
                    $sanitized_params[$pk] = is_scalar($pv) ? substr((string) $pv, 0, 150) : '[Array/Object]';
                }
            }
        }

        // 6. Memory & Performance State
        $mem_bytes = memory_get_usage(true);
        $mem_peak  = memory_get_peak_usage(true);
        $mem_limit = ini_get('memory_limit') ?: 'N/A';

        return array_merge($base, [
            'root_cause'          => $root_cause,
            'code_snippet'        => $code_snippet,
            'request_uri'         => $request_uri,
            'request_method'      => $request_method,
            'http_referer'        => $http_referer,
            'endpoint_type'       => $endpoint_type,
            'request_params'      => $sanitized_params,
            'triggered_by'        => $user_info,
            'client_ip'           => self::get_sanitized_ip(),
            'php_version'         => PHP_VERSION,
            'php_sapi'            => php_sapi_name(),
            'memory_used'         => size_format($mem_bytes, 2),
            'memory_peak'         => size_format($mem_peak, 2),
            'memory_limit'        => $mem_limit,
            'wp_version'          => function_exists('get_bloginfo') ? get_bloginfo('version') : 'unknown',
            'server_software'     => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
        ]);
    }

    /**
     * Extract 20-line surrounding code context around the failure line.
     *
     * @param string $file Absolute file path
     * @param int $target_line Target line number
     * @return array Formatted array of lines with line numbers and error marker
     */
    private static function extract_code_context(string $file, int $target_line): array {
        if (empty($file) || !file_exists($file) || $target_line <= 0) {
            return [];
        }

        $lines = @file($file);
        if (!$lines || !is_array($lines)) {
            return [];
        }

        $total_lines = count($lines);
        $start_line = max(1, $target_line - 10);
        $end_line   = min($total_lines, $target_line + 10);

        $snippet = [];
        for ($i = $start_line; $i <= $end_line; $i++) {
            $raw_line = rtrim($lines[$i - 1], "\r\n");
            $is_error = ($i === $target_line);
            $snippet[] = [
                'line_num' => $i,
                'content'  => $raw_line,
                'is_error' => $is_error,
            ];
        }

        return $snippet;
    }

    /**
     * Categorize root cause of fatal crash.
     *
     * @param string $type Error type
     * @param string $message Error message
     * @return string Human-friendly classification
     */
    private static function categorize_root_cause(string $type, string $message): string {
        $msg_lower = strtolower($message);
        if (strpos($msg_lower, 'syntax error') !== false || strpos($type, 'E_PARSE') !== false) {
            return 'PHP Syntax / Parse Error';
        }
        if (strpos($msg_lower, 'allowed memory size of') !== false) {
            return 'PHP Memory Limit Exhaustion';
        }
        if (strpos($msg_lower, 'maximum execution time of') !== false) {
            return 'PHP Execution Timeout';
        }
        if (strpos($msg_lower, 'call to undefined function') !== false) {
            return 'Undefined Function Call';
        }
        if (strpos($msg_lower, 'call to undefined method') !== false) {
            return 'Undefined Method Call';
        }
        if (strpos($msg_lower, 'class') !== false && strpos($msg_lower, 'not found') !== false) {
            return 'Missing Class / Autoloading Mismatch';
        }
        if (strpos($type, 'TypeError') !== false || strpos($msg_lower, 'must be of type') !== false) {
            return 'Type Strictness Violation (TypeError)';
        }
        return 'Unhandled Execution Abort';
    }

    /**
     * Safe client IP detection.
     */
    private static function get_sanitized_ip(): string {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
        foreach ($headers as $h) {
            if (!empty($_SERVER[$h])) {
                $raw = sanitize_text_field(wp_unslash($_SERVER[$h]));
                $parts = explode(',', $raw);
                $ip = trim($parts[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '127.0.0.1';
    }

    /**
     * Persist incident into historical rolling archive.
     *
     * @param array $incident
     */
    private static function archive_incident(array $incident): void {
        $archive = get_option(self::OPTION_INCIDENT_ARCHIVE, []);
        if (!is_array($archive)) {
            $archive = [];
        }

        // Prepend new incident and cap at maximum entries
        array_unshift($archive, $incident);
        if (count($archive) > self::MAX_ARCHIVE_ENTRIES) {
            $archive = array_slice($archive, 0, self::MAX_ARCHIVE_ENTRIES);
        }

        update_option(self::OPTION_INCIDENT_ARCHIVE, $archive, false);
    }

    /**
     * Render high-visibility warning and self-healing recovery actions in wp-admin.
     */
    public static function render_admin_notice(): void {
        if (!current_user_can('activate_plugins')) {
            return;
        }

        $is_safe = get_option(self::OPTION_SAFE_MODE, false);
        if (!$is_safe) {
            return;
        }

        $incident = get_option(self::OPTION_LAST_INCIDENT, []);
        $err_type = !empty($incident['type']) ? esc_html($incident['type']) : 'Unhandled Exception';
        $err_msg  = !empty($incident['message']) ? esc_html($incident['message']) : 'An unexpected condition occurred.';
        $err_file = !empty($incident['file']) ? esc_html(basename($incident['file'])) : 'unknown';
        $full_file = !empty($incident['file']) ? esc_html($incident['file']) : 'unknown';
        $err_line = !empty($incident['line']) ? (int) $incident['line'] : 0;
        $err_time = !empty($incident['datetime']) ? esc_html($incident['datetime']) : 'Recently';

        $root_cause   = !empty($incident['root_cause']) ? esc_html($incident['root_cause']) : 'Execution Anomaly';
        $endpoint     = !empty($incident['endpoint_type']) ? esc_html($incident['endpoint_type']) : 'Web Request';
        $method       = !empty($incident['request_method']) ? esc_html($incident['request_method']) : 'GET';
        $uri          = !empty($incident['request_uri']) ? esc_html($incident['request_uri']) : '/';
        $user_trigger = !empty($incident['triggered_by']) ? esc_html($incident['triggered_by']) : 'Visitor';
        $client_ip    = !empty($incident['client_ip']) ? esc_html($incident['client_ip']) : '127.0.0.1';
        $php_ver      = !empty($incident['php_version']) ? esc_html($incident['php_version']) : PHP_VERSION;
        $mem_used     = !empty($incident['memory_used']) ? esc_html($incident['memory_used']) : 'N/A';
        $mem_limit    = !empty($incident['memory_limit']) ? esc_html($incident['memory_limit']) : 'N/A';
        $code_snippet = !empty($incident['code_snippet']) && is_array($incident['code_snippet']) ? $incident['code_snippet'] : [];

        $reset_url      = wp_nonce_url(admin_url('admin-post.php?action=' . self::ACTION_RESET), 'wcpscan_circuit_breaker_nonce');
        $deactivate_url = wp_nonce_url(admin_url('admin-post.php?action=' . self::ACTION_DEACTIVATE), 'wcpscan_circuit_breaker_nonce');
        $test_url       = wp_nonce_url(admin_url('admin-post.php?action=' . self::ACTION_TEST_SYNTAX), 'wcpscan_circuit_breaker_nonce');

        // Check if admin notice flash message is present
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $flash_msg = isset($_GET['wcpscan_msg']) ? sanitize_key(wp_unslash($_GET['wcpscan_msg'])) : '';
        ?>
        <div class="notice notice-error is-dismissible" style="border-left-color: #ef4444; padding: 20px 24px; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 14px rgba(0,0,0,0.06); margin: 20px 0;">
            <div style="display: flex; align-items: flex-start; gap: 14px;">
                <div style="width: 42px; height: 42px; border-radius: 8px; background: #fee2e2; display: flex; align-items: center; justify-content: center; flex-shrink: 0; color: #dc2626; font-size: 22px;">
                    🛡️
                </div>
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap;">
                        <strong style="font-size: 16px; color: #0f172a;">WCP Security Scanner &bull; Safe Mode Self-Preservation Engaged</strong>
                        <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: #fef2f2; color: #dc2626; border: 1px solid #fecaca;">
                            Interception Paused
                        </span>
                        <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd;">
                            <?php echo esc_html($root_cause); ?>
                        </span>
                    </div>

                    <?php if ('syntax_valid' === $flash_msg) : ?>
                        <div style="background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin: 10px 0;">
                            <strong><?php esc_html_e('Syntax Verification Passed:', 'wcp-security-scanner'); ?></strong> <?php esc_html_e('The offending file has clean syntax and no compile errors detected. You may now safely clear the incident.', 'wcp-security-scanner'); ?>
                        </div>
                    <?php elseif ('syntax_error' === $flash_msg) : ?>
                        <div style="background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin: 10px 0;">
                            <strong><?php esc_html_e('Syntax Verification Failed:', 'wcp-security-scanner'); ?></strong> <?php esc_html_e('The file still contains syntax errors or invalid PHP tokens. Please repair the file before re-enabling protection.', 'wcp-security-scanner'); ?>
                        </div>
                    <?php endif; ?>

                    <p style="margin: 0 0 10px 0; font-size: 13px; color: #475569; line-height: 1.5;">
                        WCP Security Scanner entered <strong>Safe Mode</strong> after catching an internal error (<code style="background: #f1f5f9; color: #b91c1c; font-weight: 600;"><?php echo esc_html($err_type); ?></code> in <code style="background: #f1f5f9; color: #0284c7;"><?php echo esc_html($err_file) . ':' . esc_html((string) $err_line); ?></code>). Safe Mode automatically paused high-privilege hooks so the rest of your website, WordPress admin, and visitor traffic continue running smoothly without blank screens (WSOD).
                    </p>

                    <div style="background: #0f172a; color: #f8fafc; padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; max-width: 960px; overflow-x: auto;">
                        <span style="color: #ef4444; font-weight: bold;">[CrashGuard Incident <?php echo esc_html($err_time); ?>]</span> <?php echo esc_html($err_msg); ?>
                    </div>

                    <!-- Expandable Forensic Incident Dossier -->
                    <details style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; max-width: 960px;">
                        <summary style="font-size: 13px; font-weight: 600; color: #1e293b; cursor: pointer; user-select: none;">
                            🔍 <?php esc_html_e('Inspect Full Forensic Incident Dossier & Code Snapshot', 'wcp-security-scanner'); ?>
                        </summary>

                        <div style="margin-top: 12px; font-size: 12px; color: #334155; display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px;">
                            <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0;">
                                <strong><?php esc_html_e('Triggering Endpoint:', 'wcp-security-scanner'); ?></strong><br>
                                <code><?php echo esc_html($endpoint); ?></code><br>
                                <span style="color: #64748b;"><?php echo esc_html($method . ' ' . $uri); ?></span>
                            </div>

                            <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0;">
                                <strong><?php esc_html_e('Executing Identity & IP:', 'wcp-security-scanner'); ?></strong><br>
                                <span><?php echo esc_html($user_trigger); ?></span><br>
                                <span style="color: #64748b;"><?php esc_html_e('Client IP:', 'wcp-security-scanner'); ?> <?php echo esc_html($client_ip); ?></span>
                            </div>

                            <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0;">
                                <strong><?php esc_html_e('System & Memory State:', 'wcp-security-scanner'); ?></strong><br>
                                <span>PHP <?php echo esc_html($php_ver); ?> &bull; Memory: <?php echo esc_html($mem_used); ?> / <?php echo esc_html($mem_limit); ?></span><br>
                                <span style="color: #64748b;"><?php esc_html_e('File:', 'wcp-security-scanner'); ?> <?php echo esc_html($full_file); ?></span>
                            </div>
                        </div>

                        <?php if (!empty($code_snippet)) : ?>
                            <div style="margin-top: 12px;">
                                <div style="font-weight: 600; margin-bottom: 4px; color: #475569; font-size: 11px; text-transform: uppercase;">
                                    <?php esc_html_e('Surrounding Code Snapshot (Line', 'wcp-security-scanner'); ?> <?php echo esc_html((string) $err_line); ?> <?php esc_html_e('Highlighted):', 'wcp-security-scanner'); ?>
                                </div>
                                <div style="background: #090d16; color: #cbd5e1; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 11px; max-height: 220px; overflow-y: auto;">
                                    <?php foreach ($code_snippet as $s_line) : ?>
                                        <div style="display: flex; gap: 8px; <?php echo !empty($s_line['is_error']) ? 'background: rgba(239, 68, 68, 0.25); color: #fca5a5; font-weight: bold; border-left: 3px solid #ef4444; padding-left: 4px;' : ''; ?>">
                                            <span style="color: #64748b; min-width: 34px; text-align: right; user-select: none;"><?php echo esc_html((string) $s_line['line_num']); ?></span>
                                            <span style="white-space: pre-wrap; word-break: break-all;"><?php echo esc_html($s_line['content']); ?></span>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div style="margin-top: 12px; display: flex; align-items: center; justify-content: flex-end;">
                            <button type="button" class="button button-small" onclick="navigator.clipboard.writeText(document.getElementById('wcp-crashguard-json-dossier').textContent).then(function(){alert('Incident dossier copied to clipboard!');});">
                                📋 <?php esc_html_e('Copy Full Forensic JSON Dossier', 'wcp-security-scanner'); ?>
                            </button>
                            <script type="application/json" id="wcp-crashguard-json-dossier"><?php echo wp_json_encode($incident, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES); ?></script>
                        </div>
                    </details>

                    <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                        <a href="<?php echo esc_url($reset_url); ?>" class="button button-primary" style="background: #4f46e5; border-color: #4338ca;">
                            <?php esc_html_e('Clear Incident & Re-Enable Full Protection', 'wcp-security-scanner'); ?>
                        </a>
                        <a href="<?php echo esc_url($test_url); ?>" class="button button-secondary" style="border-color: #cbd5e1;">
                            <?php esc_html_e('Verify Code Syntax', 'wcp-security-scanner'); ?>
                        </a>
                        <a href="<?php echo esc_url($deactivate_url); ?>" class="button button-secondary" style="color: #b91c1c;">
                            <?php esc_html_e('Deactivate Plugin Safely', 'wcp-security-scanner'); ?>
                        </a>
                        <span style="font-size: 12px; color: #64748b; margin-left: 6px;">
                            Connect directly with <strong style="color: #0f172a;">Mir Alamin (WebCare Pro)</strong> for assistance.
                        </span>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Handle manual 1-click reset action from wp-admin banner.
     */
    public static function handle_reset_action(): void {
        check_admin_referer('wcpscan_circuit_breaker_nonce');

        if (!current_user_can('activate_plugins')) {
            wp_die(esc_html__('Unauthorized capability.', 'wcp-security-scanner'), 403);
        }

        delete_option(self::OPTION_SAFE_MODE);
        delete_option(self::OPTION_LAST_INCIDENT);
        delete_option(self::OPTION_CRASH_HISTORY);

        wp_safe_redirect(admin_url('admin.php?page=wcp-security-scanner&wcpscan_msg=circuit_reset'));
        exit;
    }

    /**
     * Handle graceful user-requested self-deactivation.
     */
    public static function handle_self_deactivation(): void {
        check_admin_referer('wcpscan_circuit_breaker_nonce');

        if (!current_user_can('activate_plugins')) {
            wp_die(esc_html__('Unauthorized capability.', 'wcp-security-scanner'), 403);
        }

        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        if (defined('WCPSCAN_FILE')) {
            deactivate_plugins(WCPSCAN_FILE);
        }

        delete_option(self::OPTION_SAFE_MODE);
        wp_safe_redirect(admin_url('plugins.php?deactivate=true'));
        exit;
    }

    /**
     * Handle non-destructive syntax verification of the offending file.
     */
    public static function handle_test_syntax_action(): void {
        check_admin_referer('wcpscan_circuit_breaker_nonce');

        if (!current_user_can('activate_plugins')) {
            wp_die(esc_html__('Unauthorized capability.', 'wcp-security-scanner'), 403);
        }

        $incident = get_option(self::OPTION_LAST_INCIDENT, []);
        $file = $incident['file'] ?? '';

        $is_valid = false;
        if (!empty($file) && file_exists($file)) {
            $code = @file_get_contents($file);
            if (false !== $code) {
                try {
                    // Use token_get_all to detect syntax/lexical compile failures safely
                    token_get_all($code, TOKEN_PARSE);
                    $is_valid = true;
                } catch (\ParseError $e) {
                    $is_valid = false;
                } catch (\Throwable $e) {
                    $is_valid = false;
                }
            }
        }

        $redirect_msg = $is_valid ? 'syntax_valid' : 'syntax_error';
        $referer = wp_get_referer();
        $target_url = $referer ? add_query_arg('wcpscan_msg', $redirect_msg, $referer) : admin_url('index.php?wcpscan_msg=' . $redirect_msg);

        wp_safe_redirect($target_url);
        exit;
    }
}
