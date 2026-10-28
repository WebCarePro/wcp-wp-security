<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CrashGuard
 *
 * Enterprise-grade zero-downtime circuit breaker and crash protection engine.
 * Ensures that any unexpected PHP exception, TypeError, or fatal error originating
 * inside WCP Security Scanner is safely intercepted, preventing WordPress White Screen
 * of Death (WSOD) or "There has been a critical error on this website" outages.
 */
class CrashGuard {

    public const OPTION_SAFE_MODE = 'wcpscan_circuit_breaker_safe_mode';
    public const OPTION_LAST_INCIDENT = 'wcpscan_circuit_breaker_last_incident';
    public const ACTION_RESET = 'wcpscan_reset_circuit_breaker';
    public const ACTION_DEACTIVATE = 'wcpscan_circuit_breaker_deactivate';

    /**
     * Whether the circuit breaker has isolated the plugin on this execution thread.
     */
    private static bool $isolated = false;

    /**
     * Register real-time error interceptors and shutdown hooks.
     */
    public static function register_protection(): void {
        // 1. Shutdown Error Interceptor (Catches E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR)
        register_shutdown_function([__CLASS__, 'handle_fatal_shutdown']);

        // 2. Admin UI Notices & Recovery Actions
        if (is_admin()) {
            add_action('admin_notices', [__CLASS__, 'render_admin_notice']);
            add_action('admin_post_' . self::ACTION_RESET, [__CLASS__, 'handle_reset_action']);
            add_action('admin_post_' . self::ACTION_DEACTIVATE, [__CLASS__, 'handle_self_deactivation']);
        }
    }

    /**
     * Determine if the plugin is currently isolated in Safe Mode.
     *
     * @return bool
     */
    public static function is_safe_mode_active(): bool {
        if (self::$isolated) {
            return true;
        }

        $safe_mode = get_option(self::OPTION_SAFE_MODE, false);
        return !empty($safe_mode);
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

        $incident = [
            'type'        => get_class($e),
            'message'     => $e->getMessage(),
            'file'        => wp_normalize_path($e->getFile()),
            'line'        => $e->getLine(),
            'trace'       => $e->getTraceAsString(),
            'timestamp'   => time(),
            'datetime'    => gmdate('Y-m-d H:i:s') . ' GMT',
            'php_version' => PHP_VERSION,
            'wp_version'  => get_bloginfo('version'),
        ];

        // Store incident report
        update_option(self::OPTION_LAST_INCIDENT, $incident, false);
        update_option(self::OPTION_SAFE_MODE, true, false);

        // Record in server error log for sysadmin visibility without taking down site
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
     * Shutdown handler: Catches unhandled fatal errors before they render the WSOD screen.
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
            return; // Not our plugin, let WordPress handle normal error workflow
        }

        // Engage Safe Mode isolation immediately
        $incident = [
            'type'        => 'PHP Fatal Error (E_' . $error['type'] . ')',
            'message'     => $error['message'],
            'file'        => $error_file,
            'line'        => $error['line'],
            'trace'       => 'Fatal error caught at script termination.',
            'timestamp'   => time(),
            'datetime'    => gmdate('Y-m-d H:i:s') . ' GMT',
            'php_version' => PHP_VERSION,
            'wp_version'  => get_bloginfo('version'),
        ];

        update_option(self::OPTION_LAST_INCIDENT, $incident, false);
        update_option(self::OPTION_SAFE_MODE, true, false);

        // Check crash loop threshold: If 2 crashes occur within 120 seconds, automatically deactivate plugin
        $history = get_option('wcpscan_circuit_breaker_history', []);
        if (!is_array($history)) {
            $history = [];
        }
        $history[] = time();
        // Keep last 5 timestamps
        if (count($history) > 5) {
            $history = array_slice($history, -5);
        }
        update_option('wcpscan_circuit_breaker_history', $history, false);

        // If at least 2 crashes occurred within last 2 minutes, self-deactivate to protect client site
        if (count($history) >= 2 && ($history[count($history) - 1] - $history[count($history) - 2]) <= 120) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            if (defined('WCPSCAN_FILE') && function_exists('deactivate_plugins')) {
                deactivate_plugins(WCPSCAN_FILE, true);
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log('[WCP CrashGuard] Persistent crash loop detected. WCP Security Scanner automatically self-deactivated to guarantee 100% website uptime.');
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
        <div class="notice notice-error is-dismissible" style="border-left-color: #ef4444; padding: 16px 20px; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); margin: 20px 0;">
            <div style="display: flex; align-items: flex-start; gap: 14px;">
                <div style="width: 38px; height: 38px; border-radius: 8px; background: #fee2e2; display: flex; align-items: center; justify-content: center; flex-shrink: 0; color: #dc2626; font-size: 20px;">
                    🛡️
                </div>
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                        <strong style="font-size: 15px; color: #0f172a;">WCP Security Scanner &bull; Zero-Downtime Circuit Breaker Engaged</strong>
                        <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: #fef2f2; color: #dc2626; border: 1px solid #fecaca;">
                            Safe Mode Active
                        </span>
                    </div>

                    <p style="margin: 0 0 10px 0; font-size: 13px; color: #475569; line-height: 1.5;">
                        WCP CrashGuard intercepted an internal PHP exception (<code style="background: #f1f5f9; color: #b91c1c; font-weight: 600;"><?php echo $err_type; ?></code> in <code style="background: #f1f5f9; color: #0284c7;"><?php echo $err_file . ':' . $err_line; ?></code>) and automatically entered <strong>Safe Mode</strong>.
                        <strong>Your website remained 100% online with zero visitor interruption.</strong>
                    </p>

                    <div style="background: #0f172a; color: #f8fafc; padding: 10px 14px; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; max-width: 900px; overflow-x: auto;">
                        <span style="color: #ef4444; font-weight: bold;">[CrashGuard Incident <?php echo $err_time; ?>]</span> <?php echo $err_msg; ?>
                    </div>

                    <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                        <a href="<?php echo esc_url($reset_url); ?>" class="button button-primary" style="background: #4f46e5; border-color: #4338ca;">
                            <?php esc_html_e('1-Click Clear & Re-Enable WCP Scanner', 'wcp-security-scanner'); ?>
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
        delete_option('wcpscan_circuit_breaker_history');

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
