<?php
/**
 * Plugin Name:       WebCare Pro Security & Firewall
 * Description:       Advanced security & malware scanner with core file integrity checks, heuristic threat analysis, and modern React dashboard.
 * Version:           2.12.0
 * Requires at least: 7.0
 * Requires PHP:      8.3
 * Author:            Mir Alamin
 * Author URI:        https://webcarespro.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       webcare-pro-security
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

define('WEBCAREPROSCAN_VERSION', '2.12.0');
define('WEBCAREPROSCAN_FILE', __FILE__);
define('WEBCAREPROSCAN_PATH', plugin_dir_path(__FILE__));
define('WEBCAREPROSCAN_URL', plugin_dir_url(__FILE__));

// Custom Autoloader for WebCareProScanner
spl_autoload_register(function ($class) {
    $base_dir = WEBCAREPROSCAN_PATH . 'includes/';

    if (strncmp('WebCareProScanner\\', $class, 18) !== 0) {
        return;
    }

    $relative_class = substr($class, 18);
    $rel_path = str_replace('\\', '/', $relative_class);
    $file = $base_dir . $rel_path . '.php';

    if (file_exists($file)) {
        require_once $file;
        return;
    }

    // Fallback 1: lowercase directory name (e.g. includes/cloudflare/CloudflareService.php)
    $dir = dirname($rel_path);
    $base = basename($rel_path);
    if ($dir !== '.' && $dir !== '') {
        $lower_dir_file = $base_dir . strtolower($dir) . '/' . $base . '.php';
        if (file_exists($lower_dir_file)) {
            require_once $lower_dir_file;
            return;
        }
    }

    // Fallback 2: completely lowercase path
    $all_lower_file = $base_dir . strtolower($rel_path) . '.php';
    if (file_exists($all_lower_file)) {
        require_once $all_lower_file;
        return;
    }
});

// Composer Autoloader (if present)
if (file_exists(WEBCAREPROSCAN_PATH . 'vendor/autoload.php')) {
    require_once WEBCAREPROSCAN_PATH . 'vendor/autoload.php';
}

// Activation & Deactivation hooks
register_activation_hook(__FILE__, function () {
    // 1. Run Pre-Flight Environment & Cryptographic Requirements Gate
    \WebCareProScanner\System\SystemReadinessChecker::run_activation_check();

    // 2. Install Database Schema
    \WebCareProScanner\Database\Migration::install();

    // 3. Queue First-Time Onboarding Wizard Redirect
    if (!get_option('webcareproscan_wizard_completed', false)) {
        add_option('webcareproscan_activation_redirect_wizard', true);
    }
});

register_deactivation_hook(__FILE__, function () {
    // Notify via NotificationDispatcher before cleaning up crons (defensively caught so broken mailer plugins cannot block deactivation)
    if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
        try {
            $user = wp_get_current_user();
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('plugin_deactivate_attempt', [
                'severity' => 'high',
                'message'  => sprintf(
                    /* translators: %s: WordPress user login name */
                    __('WebCare Pro Security & Firewall was deactivated by user "%s".', 'webcare-pro-security'),
                    $user->user_login ?: 'system/cron'
                ),
                'details'  => [
                    'user_login' => $user->user_login ?: 'unknown',
                    'user_email' => $user->user_email ?: 'unknown',
                    'ip_address' => !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1',
                ],
            ]);
        } catch (\Throwable $e) {
            // Silently swallow or log to error_log to ensure plugin deactivation is NEVER blocked
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WebCare Pro deactivation notice failed: ' . $e->getMessage());
        }
    }

    if (class_exists('\\WebCareProScanner\\System\\Cron\\CronRegistry')) {
        foreach (\WebCareProScanner\System\Cron\CronRegistry::get_all_hook_names() as $wcps_cron_hook) {
            wp_clear_scheduled_hook($wcps_cron_hook);
        }
    } else {
        wp_clear_scheduled_hook('webcareproscan_scheduled_scan_cron');
        wp_clear_scheduled_hook('webcareproscan_scheduled_scan_event');
        wp_clear_scheduled_hook('webcareproscan_threat_intel_cron_sync');
        wp_clear_scheduled_hook('webcareproscan_backup_step_worker');
        wp_clear_scheduled_hook('webcareproscan_redirect_canary_event');
        wp_clear_scheduled_hook('webcareproscan_modular_ast_step');
        wp_clear_scheduled_hook('webcareproscan_weekly_digest_event');
        wp_clear_scheduled_hook('webcareproscan_waf_log_retention_prune');
        wp_clear_scheduled_hook('webcareproscan_domain_reputation_daily_check');
        wp_clear_scheduled_hook('webcareproscan_reinfection_hourly_check');
        wp_clear_scheduled_hook('webcareproscan_self_defense_watchdog_event');
        wp_clear_scheduled_hook('webcareproscan_modular_autopilot_cron');
        wp_clear_scheduled_hook('webcareproscan_auto_rearm_waf');
        wp_clear_scheduled_hook('webcare_cloudflare_ip_sync_cron');
        wp_clear_scheduled_hook('webcare_cf_auto_sync_edge_cron');
    }

    // Emergency fail-safe: Instantly revoke any active JIT elevations so no user is left with permanent administrator privileges
    $ephem_admins = get_option('webcareproscan_ephemeral_admins', []);
    if (is_array($ephem_admins) && !empty($ephem_admins)) {
        $history = get_option('webcareproscan_ephemeral_admin_history', []);
        if (!is_array($history)) {
            $history = [];
        }
        foreach ($ephem_admins as $uid => $entry) {
            $baseline_role = !empty($entry['baseline_role']) ? $entry['baseline_role'] : 'subscriber';
            $u = get_userdata((int) $uid);
            if ($u) {
                $u->set_role($baseline_role);
            }
            wp_clear_scheduled_hook('webcareproscan_ephemeral_admin_expire', [(int) $uid]);
            $entry['status'] = 'revoked';
            $entry['revoked_at'] = time();
            $entry['revoke_reason'] = 'Plugin deactivation triggered';
            array_unshift($history, $entry);
        }
        if (count($history) > 100) {
            $history = array_slice($history, 0, 100);
        }
        update_option('webcareproscan_ephemeral_admin_history', $history);
        delete_option('webcareproscan_ephemeral_admins');
    }

    // Emergency fail-safe: Terminate all active temporary support sessions
    $support_users = get_option('webcareproscan_support_active_users', []);
    if (is_array($support_users) && !empty($support_users)) {
        foreach ($support_users as $uid => $conf) {
            delete_user_meta((int) $uid, 'webcareproscan_is_temporary_support');
            if (class_exists('\\WP_Session_Tokens')) {
                $manager = \WP_Session_Tokens::get_instance((int) $uid);
                $manager->destroy_all();
            }
        }
        delete_option('webcareproscan_support_active_users');
    }

    // Clean up Micro-WAF preloads and server security rules on deactivation to prevent site breakage
    if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
        try {
            \WebCareProScanner\Firewall\MicroWafCompiler::uninstall_preload();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }
    if (class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
        try {
            \WebCareProScanner\Firewall\ServerSecurityEngine::remove_rules();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }

    // Clean up MU Guardian if deployed
    $mu_guardian = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR . '/webcare-jit-guardian.php' : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/mu-plugins/webcare-jit-guardian.php' : '');
    if (!empty($mu_guardian) && file_exists($mu_guardian)) {
        wp_delete_file($mu_guardian);
    }
});

// =========================================================================
// CRASHGUARD ZERO-DOWNTIME CIRCUIT BREAKER BOOTSTRAP
// =========================================================================
// Protects WordPress from internal crashes, White Screens of Death (WSOD),
// or fatal execution aborts. If any unhandled exception strikes inside the
// plugin, CrashGuard intercepts it, isolates execution in Safe Mode, and
// ensures the client website remains 100% online without interruption.
// =========================================================================

\WebCareProScanner\System\CrashGuard::register_protection();

\WebCareProScanner\System\CrashGuard::run_guarded(function () {
    // Initialize the plugin early so WAF inspection hooks into plugins_loaded priority 0
    \WebCareProScanner\Plugin::get_instance();
});

