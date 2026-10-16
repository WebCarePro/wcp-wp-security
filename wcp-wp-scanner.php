<?php
/**
 * Plugin Name:       WCP Security Scanner
 * Description:       Advanced security & malware scanner with core file integrity checks, heuristic threat analysis, and modern React dashboard.
 * Version:           1.17.0
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

define('WCPSCAN_VERSION', '1.17.0');
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
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

// Composer Autoloader (if present)
if (file_exists(WCPSCAN_PATH . 'vendor/autoload.php')) {
    require_once WCPSCAN_PATH . 'vendor/autoload.php';
}

// Activation & Deactivation hooks
register_activation_hook(__FILE__, function () {
    \WcpScanner\Database\Migration::install();
});

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('wcpscan_scheduled_scan_cron');
    wp_clear_scheduled_hook('wcpscan_threat_intel_cron_sync');
});

// Initialize the plugin
add_action('plugins_loaded', function () {
    \WcpScanner\Plugin::get_instance();
});
