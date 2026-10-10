<?php
namespace WCP\Scanner;

use WCP\Scanner\Admin\AdminMenu;
use WCP\Scanner\Api\ScannerRoutes;

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
        AdminMenu::register();
        \WCP\Scanner\System\Scheduler::register();
        
        $audit_logger = new \WCP\Scanner\System\AuditLogger();
        $audit_logger->init();

        \WCP\Scanner\Firewall\FirewallEngine::init();
        \WCP\Scanner\Hardening\SecurityHeadersEngine::init();
        \WCP\Scanner\Auth\TwoFactorAuth::init();
        \WCP\Scanner\Auth\LoginHardening::init();
        \WCP\Scanner\Auth\SessionSentinel::init();

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }
}
