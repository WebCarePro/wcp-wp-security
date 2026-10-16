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

// Backward compatibility aliases
if (!defined('WCP_SCANNER_VERSION')) {
    define('WCP_SCANNER_VERSION', WCPSCAN_VERSION);
}
if (!defined('WCP_SCANNER_FILE')) {
    define('WCP_SCANNER_FILE', WCPSCAN_FILE);
}
if (!defined('WCP_SCANNER_PATH')) {
    define('WCP_SCANNER_PATH', WCPSCAN_PATH);
}
if (!defined('WCP_SCANNER_URL')) {
    define('WCP_SCANNER_URL', WCPSCAN_URL);
}

// Composer or Custom Autoloader
if (file_exists(WCP_SCANNER_PATH . 'vendor/autoload.php')) {
    require_once WCP_SCANNER_PATH . 'vendor/autoload.php';
} else {
    spl_autoload_register(function ($class) {
        $prefix = 'WcpScanner\\';
        $base_dir = WCP_SCANNER_PATH . 'includes/';

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
