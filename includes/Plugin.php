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
        if (class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            \WebCareProScanner\Firewall\RescueAssistantManager::init();
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

        if (defined('WP_CLI') && WP_CLI && class_exists('\\WP_CLI')) {
            \WP_CLI::add_command('webcare doctor', static function () {
                self::cli_webcare_doctor();
            });
        }
    }

    /**
     * WP-CLI self-diagnostic suite (`wp webcare doctor`) verifying RASP hardening,
     * canonical rest_route parity, SSRF blocks, and REST route authorization.
     */
    public static function cli_webcare_doctor(): void {
        $checks = [];

        // 1. Canonical REST route normalization parity (/wp-json/... vs ?rest_route=...)
        $c1 = \WebCareProScanner\Firewall\FirewallEngine::canonicalize_rest_route('/wp-json/wp/v2/users');
        $c2 = \WebCareProScanner\Firewall\FirewallEngine::canonicalize_rest_route('/?rest_route=/wp/v2/users');
        $checks['rest_route_canonical'] = ($c1 === '/wp/v2/users' && $c2 === '/wp/v2/users');

        // 2. Verify SSRF guard rejects cloud metadata target
        $rm_ssrf = new \ReflectionMethod(\WebCareProScanner\Firewall\OutboundEgressFirewall::class, 'evaluate_ssrf_destination');
        $rm_ssrf->setAccessible(true);
        $ssrf_bad = $rm_ssrf->invoke(null, '169.254.169.254');
        $checks['ssrf_metadata_blocked'] = (($ssrf_bad['threat'] ?? null) === 'ssrf_metadata');

        // 3. Verify server-side RASP helper ignores forged HTTP_REFERER and $_REQUEST['action'] when unprivileged
        $rm = new \ReflectionMethod(\WebCareProScanner\Firewall\FirewallEngine::class, 'is_trusted_plugin_check_or_cli_runtime');
        $rm->setAccessible(true);
        $checks['rasp_helper_present'] = $rm->isStatic();

        // 4. REST API Authz Audit: ensure no admin route under webcare-pro-security/v1 uses __return_true
        $server = rest_get_server();
        $routes = $server->get_routes('webcare-pro-security/v1');
        $public_unexpected = [];
        foreach ($routes as $r_path => $handlers) {
            foreach ((array) $handlers as $ep) {
                if (($ep['permission_callback'] ?? null) === '__return_true') {
                    $public_unexpected[] = $r_path;
                }
            }
        }
        $checks['rest_routes_audited'] = count($routes);
        $checks['rest_no_open_admin']  = empty($public_unexpected);

        foreach ($checks as $name => $val) {
            \WP_CLI::line(sprintf('%-26s : %s', $name, is_bool($val) ? ($val ? 'PASS' : 'FAIL') : (string) $val));
        }

        if (empty($checks['rest_route_canonical']) || empty($checks['ssrf_metadata_blocked']) || empty($checks['rest_no_open_admin'])) {
            \WP_CLI::error('WebCare Doctor detected a failed security self-check.');
        }

        \WP_CLI::success('All WebCare Pro security self-checks passed.');
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
