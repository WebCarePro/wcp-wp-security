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
        // Performance optimization: check cached in-memory alloptions db version first (0 queries)
        $db_version = get_option('wcpscan_db_version');
        if ($db_version !== '1.12.0') {
            global $wpdb;
            $core_table = $wpdb->prefix . 'wcpscan_scans';
            $history_table = $wpdb->prefix . 'wcpscan_login_history';
            $firewall_table = $wpdb->prefix . 'wcpscan_firewall_logs';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $has_tables = ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $core_table)) === $core_table)
                && ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $history_table)) === $history_table)
                && ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $firewall_table)) === $firewall_table);

            if (!$has_tables) {
                \WcpScanner\Database\Migration::install();
            }
        }

        // Ensure root uploads/wcp-security-scanner storage directory has an index.php directory silence guard
        self::ensure_uploads_storage_protected();

        AdminMenu::register();
        \WcpScanner\System\Scheduler::register();
        
        if (class_exists('\\WcpScanner\\WordPress\\UserRemediationManager')) {
            \WcpScanner\WordPress\UserRemediationManager::init();
        }

        if (class_exists('\\WcpScanner\\System\\WcpActivityLogger')) {
            \WcpScanner\System\WcpActivityLogger::init();
        }

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
        if (class_exists('\\WcpScanner\\Firewall\\FormSpamProtectionEngine')) {
            \WcpScanner\Firewall\FormSpamProtectionEngine::init();
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
        if (class_exists('\\WcpScanner\\Quarantine\\ReinfectionWatchdog')) {
            \WcpScanner\Quarantine\ReinfectionWatchdog::init();
        }
        if (class_exists('\\WcpScanner\\Firewall\\DomainReputationMonitor')) {
            \WcpScanner\Firewall\DomainReputationMonitor::init();
        }
        if (class_exists('\\WcpScanner\\Auth\\WebAuthnManager')) {
            \WcpScanner\Auth\WebAuthnManager::init();
        }
        if (class_exists('\\WcpScanner\\Identity\\WcpJitMuGuardian')) {
            \WcpScanner\Identity\WcpJitMuGuardian::ensure_installed();
        }

        // Context-Adaptive Firewall (CAF) Lifecycle Observers & Edge Cron
        if (class_exists('\\WcpScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            \WcpScanner\Firewall\CAF\AdaptiveFirewallAdvisor::register_lifecycle_hooks();
        }
        if (class_exists('\\WcpScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            \WcpScanner\Firewall\CAF\CloudflareIpListSynchronizer::register_cron();
        }

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }

    /**
     * Ensure root uploads/wcp-security-scanner storage directory has an index.php directory silence guard.
     */
    public static function ensure_uploads_storage_protected(): void {
        $upload_dir = wp_upload_dir();
        $dir = $upload_dir['basedir'] . '/wcp-security-scanner';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }
        $index_file = $dir . '/index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\nhttp_response_code(403);\nexit;\n");
        }
    }
}
