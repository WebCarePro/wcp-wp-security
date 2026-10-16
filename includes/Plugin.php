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
        if (get_option('wcpscan_db_version') !== '1.8.0') {
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
