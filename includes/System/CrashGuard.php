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
    public const OPTION_CRASH_HISTORY    = 'wcpscan_circuit_breaker_history';
    public const ACTION_RESET            = 'wcpscan_reset_circuit_breaker';
    public const ACTION_DEACTIVATE       = 'wcpscan_circuit_breaker_deactivate';

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
        $incident = [
            'type'        => get_class($e),
            'message'     => $e->getMessage(),
            'file'        => wp_normalize_path($e->getFile()),
            'line'        => $e->getLine(),
            'fingerprint' => $fingerprint,
            'trace'       => $e->getTraceAsString(),
            'timestamp'   => time(),
            'datetime'    => gmdate('Y-m-d H:i:s') . ' GMT',
            'php_version' => PHP_VERSION,
            'wp_version'  => get_bloginfo('version'),
        ];

        update_option(self::OPTION_LAST_INCIDENT, $incident, false);
        update_option(self::OPTION_SAFE_MODE, true, false);

        // Record in server error log for sysadmin visibility
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log(sprintf(
            '[WCP CrashGuard] Intercepted %s in %s:%d - %s. Safe Mode engaged to protect host website.',
            $incident['type'],
            $incident['file'],
            $incident['line'],
            $incident['message']
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

        $incident = [
            'type'        => 'PHP Fatal Error (E_' . $error['type'] . ')',
            'message'     => $error['message'],
            'file'        => $error_file,
            'line'        => $error['line'],
            'fingerprint' => $fingerprint,
            'trace'       => 'Fatal error caught at PHP shutdown lifecycle.',
            'timestamp'   => $now,
            'datetime'    => gmdate('Y-m-d H:i:s') . ' GMT',
            'php_version' => PHP_VERSION,
            'wp_version'  => function_exists('get_bloginfo') ? get_bloginfo('version') : 'unknown',
        ];

        // 1. Immediately flag Safe Mode for NEXT requests
        update_option(self::OPTION_LAST_INCIDENT, $incident, false);
        update_option(self::OPTION_SAFE_MODE, true, false);

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
        $err_line = !empty($incident['line']) ? (int) $incident['line'] : 0;
        $err_time = !empty($incident['datetime']) ? esc_html($incident['datetime']) : 'Recently';

        $reset_url = wp_nonce_url(admin_url('admin-post.php?action=' . self::ACTION_RESET), 'wcpscan_circuit_breaker_nonce');
        $deactivate_url = wp_nonce_url(admin_url('admin-post.php?action=' . self::ACTION_DEACTIVATE), 'wcpscan_circuit_breaker_nonce');
        ?>
        <div class="notice notice-error is-dismissible" style="border-left-color: #ef4444; padding: 18px 22px; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 14px rgba(0,0,0,0.06); margin: 20px 0;">
            <div style="display: flex; align-items: flex-start; gap: 14px;">
                <div style="width: 40px; height: 40px; border-radius: 8px; background: #fee2e2; display: flex; align-items: center; justify-content: center; flex-shrink: 0; color: #dc2626; font-size: 20px;">
                    🛡️
                </div>
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                        <strong style="font-size: 15px; color: #0f172a;">WCP Security Scanner &bull; Safe Mode Self-Preservation Engaged</strong>
                        <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: #fef2f2; color: #dc2626; border: 1px solid #fecaca;">
                            Interception Paused
                        </span>
                    </div>

                    <p style="margin: 0 0 10px 0; font-size: 13px; color: #475569; line-height: 1.5;">
                        WCP Security Scanner entered <strong>Safe Mode</strong> after an internal error (<code style="background: #f1f5f9; color: #b91c1c; font-weight: 600;"><?php echo esc_html($err_type); ?></code> in <code style="background: #f1f5f9; color: #0284c7;"><?php echo esc_html($err_file) . ':' . esc_html((string) $err_line); ?></code>) so the rest of your site and admin dashboard could keep loading safely.
                    </p>

                    <div style="background: #0f172a; color: #f8fafc; padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 14px; max-width: 900px; overflow-x: auto;">
                        <span style="color: #ef4444; font-weight: bold;">[CrashGuard Incident <?php echo esc_html($err_time); ?>]</span> <?php echo esc_html($err_msg); ?>
                    </div>

                    <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                        <a href="<?php echo esc_url($reset_url); ?>" class="button button-primary" style="background: #4f46e5; border-color: #4338ca;">
                            <?php esc_html_e('Clear Incident & Re-Enable Full Protection', 'wcp-security-scanner'); ?>
                        </a>
                        <a href="<?php echo esc_url($deactivate_url); ?>" class="button button-secondary" style="color: #b91c1c;">
                            <?php esc_html_e('Deactivate Plugin Safely', 'wcp-security-scanner'); ?>
                        </a>
                        <span style="font-size: 12px; color: #64748b;">
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
}
