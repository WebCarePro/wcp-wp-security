<?php
namespace WebCareProScanner;

use WebCareProScanner\Admin\AdminMenu;
use WebCareProScanner\Api\ScannerRoutes;

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
        if (get_option('webcareproscan_db_version') !== '1.12.0') {
            \WebCareProScanner\Database\Migration::install();
        }

        // Ensure root uploads/webcare-pro-security storage directory has an index.php directory silence guard
        self::ensure_uploads_storage_protected();

        AdminMenu::register();
        \WebCareProScanner\System\Scheduler::register();
        
        if (class_exists('\\WebCareProScanner\\Backup\\DatabaseBackup')) {
            \WebCareProScanner\Backup\DatabaseBackup::init();
        }

        if (class_exists('\\WebCareProScanner\\WordPress\\UserRemediationManager')) {
            \WebCareProScanner\WordPress\UserRemediationManager::init();
        }

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::init();
        }

        $audit_logger = new \WebCareProScanner\System\AuditLogger();
        $audit_logger->init();

        // Firewall & Edge Security Services
        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            \WebCareProScanner\Firewall\WafFileLogger::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            \WebCareProScanner\Firewall\FirewallEngine::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\HtaccessShield')) {
            \WebCareProScanner\Firewall\HtaccessShield::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            \WebCareProScanner\Firewall\HtaccessVaultManager::register_cli();
        }
        if (class_exists('\\WebCareProScanner\\Integrity\\ObjectCacheIntegritySentinel')) {
            \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::init();
        }

        if (class_exists('\\WebCareProScanner\\Security\\EmergencyContainmentManager')) {
            \WebCareProScanner\Security\EmergencyContainmentManager::init();
        }

        if (class_exists('\\WebCareProScanner\\Hardening\\SecurityHeadersEngine')) {
            \WebCareProScanner\Hardening\SecurityHeadersEngine::init();
        }
        if (class_exists('\\WebCareProScanner\\Auth\\TwoFactorAuth')) {
            \WebCareProScanner\Auth\TwoFactorAuth::init();
        }
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
            \WebCareProScanner\Auth\LoginHardening::init();
        }
        if (class_exists('\\WebCareProScanner\\Auth\\SessionSentinel')) {
            \WebCareProScanner\Auth\SessionSentinel::init();
        }
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHistoryManager')) {
            \WebCareProScanner\Auth\LoginHistoryManager::init();
        }
        if (class_exists('\\WebCareProScanner\\Auth\\ApplicationPasswordSentinel')) {
            \WebCareProScanner\Auth\ApplicationPasswordSentinel::init();
        }
        if (class_exists('\\WebCareProScanner\\Security\\PluginSelfDefense')) {
            \WebCareProScanner\Security\PluginSelfDefense::init();
        }
        if (class_exists('\\WebCareProScanner\\SupplyChain\\UpdateGatekeeperEngine')) {
            \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::init();
        }
        if (class_exists('\\WebCareProScanner\\Content\\ScriptInventoryMonitor')) {
            \WebCareProScanner\Content\ScriptInventoryMonitor::init();
        }
        if (class_exists('\\WebCareProScanner\\Identity\\SessionForensicsEngine')) {
            \WebCareProScanner\Identity\SessionForensicsEngine::init();
        }
        if (class_exists('\\WebCareProScanner\\Identity\\EphemeralAdminEngine')) {
            \WebCareProScanner\Identity\EphemeralAdminEngine::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\GhostRouteTrap')) {
            \WebCareProScanner\Firewall\GhostRouteTrap::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\FormSpamProtectionEngine')) {
            \WebCareProScanner\Firewall\FormSpamProtectionEngine::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\OutboundEgressFirewall')) {
            \WebCareProScanner\Firewall\OutboundEgressFirewall::init();
        }
        if (class_exists('\\WebCareProScanner\\Security\\PromptInjectionGuard')) {
            \WebCareProScanner\Security\PromptInjectionGuard::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\DistributedVelocityShield')) {
            \WebCareProScanner\Firewall\DistributedVelocityShield::init();
        }
        if (class_exists('\\WebCareProScanner\\Content\\BlockDirectiveSanitizer')) {
            \WebCareProScanner\Content\BlockDirectiveSanitizer::init();
        }
        if (class_exists('\\WebCareProScanner\\WordPress\\RestApiInventory')) {
            \WebCareProScanner\WordPress\RestApiInventory::init();
        }
        if (class_exists('\\WebCareProScanner\\Quarantine\\ReinfectionWatchdog')) {
            \WebCareProScanner\Quarantine\ReinfectionWatchdog::init();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\DomainReputationMonitor')) {
            \WebCareProScanner\Firewall\DomainReputationMonitor::init();
        }
        if (class_exists('\\WebCareProScanner\\Auth\\WebAuthnManager')) {
            \WebCareProScanner\Auth\WebAuthnManager::init();
        }
        if (class_exists('\\WebCareProScanner\\Identity\\WebCareJitMuGuardian')) {
            \WebCareProScanner\Identity\WebCareJitMuGuardian::ensure_installed();
        }

        // Context-Adaptive Firewall (CAF) Lifecycle Observers & Edge Cron
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::register_lifecycle_hooks();
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::register_cron();
        }

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }

    /**
     * Ensure root uploads/webcare-pro-security storage directory has an index.php directory silence guard.
     */
    public static function ensure_uploads_storage_protected(): void {
        $upload_dir = wp_upload_dir();
        $dir = $upload_dir['basedir'] . '/webcare-pro-security';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }
        $index_file = $dir . '/index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\nhttp_response_code(403);\nexit;\n");
        }
    }
}
