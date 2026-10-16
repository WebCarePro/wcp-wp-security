<?php
namespace WcpScanner;

use WcpScanner\Admin\AdminMenu;
use WcpScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

class Plugin {
    private static $instance = null;

    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init();
    }

    private function init() {
        global $wpdb;
        $core_table = $wpdb->prefix . 'wcpscan_scans';
        $history_table = $wpdb->prefix . 'wcpscan_login_history';
        $has_tables = ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $core_table)) === $core_table)
            && ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $history_table)) === $history_table);

        if (get_option('wcpscan_db_version') !== '1.8.0' || !$has_tables) {
            \WcpScanner\Database\Migration::install();
        }

        AdminMenu::register();
        \WcpScanner\System\Scheduler::register();
        
        $audit_logger = new \WcpScanner\System\AuditLogger();
        $audit_logger->init();

        \WcpScanner\Firewall\FirewallEngine::init();
        \WcpScanner\Hardening\SecurityHeadersEngine::init();
        \WcpScanner\Auth\TwoFactorAuth::init();
        \WcpScanner\Auth\LoginHardening::init();
        \WcpScanner\Auth\SessionSentinel::init();
        \WcpScanner\Auth\LoginHistoryManager::init();

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }
}
