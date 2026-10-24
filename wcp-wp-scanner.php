<?php
/**
 * Plugin Name:       WCP Security Scanner
 * Description:       Advanced security & malware scanner with core file integrity checks, heuristic threat analysis, and modern React dashboard.
 * Version:           1.25.0
 * Requires at least: 7.0
 * Requires PHP:      8.3
 * Author:            Mir Alamin
 * Author URI:        https://webcarespro.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wcp-security-scanner
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

define('WCPSCAN_VERSION', '1.25.0');
define('WCPSCAN_FILE', __FILE__);
define('WCPSCAN_PATH', plugin_dir_path(__FILE__));
define('WCPSCAN_URL', plugin_dir_url(__FILE__));

// Custom Autoloader for WcpScanner namespace
spl_autoload_register(function ($class) {
    $prefix = 'WcpScanner\\';
    $base_dir = WCPSCAN_PATH . 'includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
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
if (file_exists(WCPSCAN_PATH . 'vendor/autoload.php')) {
    require_once WCPSCAN_PATH . 'vendor/autoload.php';
}

// Activation & Deactivation hooks
register_activation_hook(__FILE__, function () {
    // 1. Run Pre-Flight Environment & Cryptographic Requirements Gate
    \WcpScanner\System\SystemReadinessChecker::run_activation_check();

    // 2. Install Database Schema
    \WcpScanner\Database\Migration::install();
});

register_deactivation_hook(__FILE__, function () {
    // Notify via NotificationDispatcher before cleaning up crons (defensively caught so broken mailer plugins cannot block deactivation)
    if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
        try {
            $user = wp_get_current_user();
            \WcpScanner\Notifications\NotificationDispatcher::trigger('plugin_deactivate_attempt', [
                'severity' => 'high',
                'message'  => sprintf(
                    /* translators: %s: WordPress user login name */
                    __('WCP Security Scanner was deactivated by user "%s".', 'wcp-security-scanner'),
                    $user->user_login ?: 'system/cron'
                ),
                'details'  => [
                    'user_login' => $user->user_login ?: 'unknown',
                    'user_email' => $user->user_email ?: 'unknown',
                    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
                ],
            ]);
        } catch (\Throwable $e) {
            // Silently swallow or log to error_log to ensure plugin deactivation is NEVER blocked
            error_log('WCP Scanner deactivation notice failed: ' . $e->getMessage());
        }
    }

    wp_clear_scheduled_hook('wcpscan_scheduled_scan_cron');
    wp_clear_scheduled_hook('wcpscan_threat_intel_cron_sync');
});

// Initialize the plugin early so WAF inspection hooks into plugins_loaded priority 0
\WcpScanner\Plugin::get_instance();

