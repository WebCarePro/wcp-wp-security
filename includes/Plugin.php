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

        if (get_option('wcpscan_db_version') !== '1.10.0' || !$has_tables) {
            \WcpScanner\Database\Migration::install();
        }

        AdminMenu::register();
        \WcpScanner\System\Scheduler::register();
        
        $audit_logger = new \WcpScanner\System\AuditLogger();
        $audit_logger->init();

        // Ensure unified storage directory under wp-content/uploads/wcp-security-scanner
        self::consolidate_uploads_storage();

        // Firewall & Edge Security Services
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
        if (class_exists('\\WcpScanner\\Identity\\SessionForensicsEngine')) {
            \WcpScanner\Identity\SessionForensicsEngine::init();
        }
        if (class_exists('\\WcpScanner\\Identity\\EphemeralAdminEngine')) {
            \WcpScanner\Identity\EphemeralAdminEngine::init();
        }
        if (class_exists('\\WcpScanner\\System\\PluginUpdater')) {
            \WcpScanner\System\PluginUpdater::init();
        }

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }

    /**
     * Consolidate all historical scattered plugin storage directories inside wp-content/uploads
     * into a single unified root directory: wp-content/uploads/wcp-security-scanner/
     */
    public static function consolidate_uploads_storage(): void {
        $upload_dir = wp_upload_dir();
        if (empty($upload_dir['basedir'])) {
            return;
        }

        $uploads_root = untrailingslashit($upload_dir['basedir']);
        $main_dir     = $uploads_root . '/wcp-security-scanner';

        // Check if any legacy folder actually exists before running
        $legacy_folders = [
            'wcp-vault'              => $main_dir . '/fim-vault',
            'wcp-waf'                => $main_dir . '/waf',
            'wcp-scanner-quarantine' => $main_dir,
            'wcp-quarantine'         => $main_dir,
        ];

        $has_legacy = false;
        foreach ($legacy_folders as $legacy_name => $target_dest) {
            if (is_dir($uploads_root . '/' . $legacy_name)) {
                $has_legacy = true;
                break;
            }
        }

        if (!$has_legacy) {
            return;
        }

        if (!is_dir($main_dir)) {
            wp_mkdir_p($main_dir);
        }

        // 1. Migrate wcp-vault -> wcp-security-scanner/fim-vault
        $vault_src = $uploads_root . '/wcp-vault';
        if (is_dir($vault_src)) {
            $fim_dest = $main_dir . '/fim-vault';
            if (!is_dir($fim_dest)) {
                wp_mkdir_p($fim_dest);
            }
            self::move_directory_contents($vault_src, $fim_dest);
            @rmdir($vault_src);
        }

        // 2. Migrate wcp-waf -> wcp-security-scanner/waf
        $waf_src = $uploads_root . '/wcp-waf';
        if (is_dir($waf_src)) {
            $waf_dest = $main_dir . '/waf';
            if (!is_dir($waf_dest)) {
                wp_mkdir_p($waf_dest);
            }
            self::move_directory_contents($waf_src, $waf_dest);
            @rmdir($waf_src);
        }

        // 3. Migrate wcp-scanner-quarantine:
        //    gatekeeper_snapshots -> wcp-security-scanner/gatekeeper
        //    transactions         -> wcp-security-scanner/transactions
        $sq_src = $uploads_root . '/wcp-scanner-quarantine';
        if (is_dir($sq_src)) {
            $gk_src = $sq_src . '/gatekeeper_snapshots';
            if (is_dir($gk_src)) {
                $gk_dest = $main_dir . '/gatekeeper';
                if (!is_dir($gk_dest)) {
                    wp_mkdir_p($gk_dest);
                }
                self::move_directory_contents($gk_src, $gk_dest);
                @rmdir($gk_src);
            }

            $tx_src = $sq_src . '/transactions';
            if (is_dir($tx_src)) {
                $tx_dest = $main_dir . '/transactions';
                if (!is_dir($tx_dest)) {
                    wp_mkdir_p($tx_dest);
                }
                self::move_directory_contents($tx_src, $tx_dest);
                @rmdir($tx_src);
            }

            // Move any remaining files or clean up
            self::move_directory_contents($sq_src, $main_dir);
            @rmdir($sq_src);
        }

        // 4. Migrate wcp-quarantine:
        //    backups -> wcp-security-scanner/backups/plugin-updates/
        $q_src = $uploads_root . '/wcp-quarantine';
        if (is_dir($q_src)) {
            $bak_src = $q_src . '/backups';
            if (is_dir($bak_src)) {
                $bak_dest = $main_dir . '/backups/plugin-updates';
                if (!is_dir($bak_dest)) {
                    wp_mkdir_p($bak_dest);
                }
                self::move_directory_contents($bak_src, $bak_dest);
                @rmdir($bak_src);
            }

            self::move_directory_contents($q_src, $main_dir);
            @rmdir($q_src);
        }
    }

    /**
     * Recursively move contents of source directory into destination directory
     */
    private static function move_directory_contents(string $src, string $dst): void {
        if (!is_dir($src)) {
            return;
        }
        if (!is_dir($dst)) {
            wp_mkdir_p($dst);
        }

        $items = @scandir($src) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $src_path = $src . '/' . $item;
            $dst_path = $dst . '/' . $item;

            if (is_dir($src_path)) {
                if (!is_dir($dst_path)) {
                    if (!@rename($src_path, $dst_path)) {
                        self::move_directory_contents($src_path, $dst_path);
                        @rmdir($src_path);
                    }
                } else {
                    self::move_directory_contents($src_path, $dst_path);
                    @rmdir($src_path);
                }
            } else {
                if (!file_exists($dst_path)) {
                    @rename($src_path, $dst_path);
                } else {
                    @unlink($src_path);
                }
            }
        }
    }
}
