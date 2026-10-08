<?php
/**
 * Plugin Name:       WCP WP Security Scanner
 * Plugin URI:        https://webcarespro.com
 * Description:       Advanced WordPress Security & Malware Scanner with Core File Integrity, Heuristic Threat Analysis, and Modern React Dashboard.
 * Version:           1.4.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Mir Alamin
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wcp-wp-scanner
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

define('WCP_SCANNER_VERSION', '1.4.0');
define('WCP_SCANNER_FILE', __FILE__);
define('WCP_SCANNER_PATH', plugin_dir_path(__FILE__));
define('WCP_SCANNER_URL', plugin_dir_url(__FILE__));

// Composer or Custom Autoloader
if (file_exists(WCP_SCANNER_PATH . 'vendor/autoload.php')) {
    require_once WCP_SCANNER_PATH . 'vendor/autoload.php';
} else {
    spl_autoload_register(function ($class) {
        $prefix = 'WCP\\Scanner\\';
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
    \WCP\Scanner\Database\Migration::install();
});

register_deactivation_hook(__FILE__, function () {
    // Optional cleanup or cron unschedule
});

// Initialize the plugin
add_action('plugins_loaded', function () {
    \WCP\Scanner\Plugin::get_instance();
});
