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
        $firewall_table = $wpdb->prefix . 'wcpscan_firewall_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $has_tables = ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $core_table)) === $core_table)
            && ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $history_table)) === $history_table)
            && ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $firewall_table)) === $firewall_table);

        if (get_option('wcpscan_db_version') !== '1.12.0' || !$has_tables) {
            \WcpScanner\Database\Migration::install();
        }

        AdminMenu::register();
        \WcpScanner\System\Scheduler::register();
        
        $audit_logger = new \WcpScanner\System\AuditLogger();
        $audit_logger->init();

        // Firewall & Edge Security Services
        if (class_exists('\\WcpScanner\\Firewall\\WafFileLogger')) {
            \WcpScanner\Firewall\WafFileLogger::init();
        }
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            \WcpScanner\Firewall\FirewallEngine::init();
        }

        if (class_exists('\\WcpScanner\\Security\\EmergencyContainmentManager')) {
            \WcpScanner\Security\EmergencyContainmentManager::init();
        }

        if (class_exists('\\WcpScanner\\Hardening\\SecurityHeadersEngine')) {
            \WcpScanner\Hardening\SecurityHeadersEngine::init();
        }
        if (class_exists('\\WcpScanner\\Auth\\TwoFactorAuth')) {
            \WcpScanner\Auth\TwoFactorAuth::init();
        }
        if (class_exists('\\WcpScanner\\Auth\\LoginHardening')) {
            \WcpScanner\Auth\LoginHardening::init();
        }
        if (class_exists('\\WcpScanner\\Auth\\SessionSentinel')) {
            \WcpScanner\Auth\SessionSentinel::init();
        }
        if (class_exists('\\WcpScanner\\Auth\\LoginHistoryManager')) {
            \WcpScanner\Auth\LoginHistoryManager::init();
        }
        if (class_exists('\\WcpScanner\\Security\\PluginSelfDefense')) {
            \WcpScanner\Security\PluginSelfDefense::init();
        }
        if (class_exists('\\WcpScanner\\SupplyChain\\UpdateGatekeeperEngine')) {
            \WcpScanner\SupplyChain\UpdateGatekeeperEngine::init();
        }
        if (class_exists('\\WcpScanner\\Content\\ScriptInventoryMonitor')) {
            \WcpScanner\Content\ScriptInventoryMonitor::init();
        }
        if (class_exists('\\WcpScanner\\Identity\\SessionForensicsEngine')) {
            \WcpScanner\Identity\SessionForensicsEngine::init();
        }
        if (class_exists('\\WcpScanner\\Identity\\EphemeralAdminEngine')) {
            \WcpScanner\Identity\EphemeralAdminEngine::init();
        }
        if (class_exists('\\WcpScanner\\Firewall\\GhostRouteTrap')) {
            \WcpScanner\Firewall\GhostRouteTrap::init();
        }
        if (class_exists('\\WcpScanner\\Firewall\\OutboundEgressFirewall')) {
            \WcpScanner\Firewall\OutboundEgressFirewall::init();
        }
        if (class_exists('\\WcpScanner\\Security\\PromptInjectionGuard')) {
            \WcpScanner\Security\PromptInjectionGuard::init();
        }
        if (class_exists('\\WcpScanner\\WordPress\\RestApiInventory')) {
            \WcpScanner\WordPress\RestApiInventory::init();
        }
        if (class_exists('\\WcpScanner\\System\\PluginUpdater')) {
            \WcpScanner\System\PluginUpdater::init();
        }

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }
}
