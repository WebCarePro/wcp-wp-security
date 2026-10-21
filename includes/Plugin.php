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

        // Firewall Engine with file_exists fallback
        if (!class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            $fw_file = WCPSCAN_PATH . 'includes/Firewall/FirewallEngine.php';
            if (file_exists($fw_file)) {
                require_once $fw_file;
            }
        }
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            \WcpScanner\Firewall\FirewallEngine::init();
        }

        // Cloudflare Service with fallback
        if (!class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
            $cf_candidates = [
                WCPSCAN_PATH . 'includes/Cloudflare/CloudflareService.php',
                WCPSCAN_PATH . 'includes/cloudflare/CloudflareService.php',
                WCPSCAN_PATH . 'includes/Firewall/CloudflareService.php',
            ];
            foreach ($cf_candidates as $cf_file) {
                if (file_exists($cf_file)) {
                    require_once $cf_file;
                    break;
                }
            }
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

        // Real-time Rogue Admin & Elevated Privilege Monitor
        add_action('user_register', function ($user_id) {
            $user = get_userdata($user_id);
            if ($user && in_array('administrator', (array) $user->roles, true)) {
                if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                    \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_rogue_admin_created', [
                        'severity' => 'critical',
                        'message'  => sprintf(__('A new user account with Administrator privileges was registered: "%s" (%s).', 'wcp-security-scanner'), $user->user_login, $user->user_email),
                        'details'  => [
                            'user_id'    => $user_id,
                            'user_login' => $user->user_login,
                            'user_email' => $user->user_email,
                            'created_at' => current_time('mysql'),
                            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                        ],
                    ]);
                }
            }
        });

        add_action('set_user_role', function ($user_id, $role, $old_roles) {
            if ($role === 'administrator' && !in_array('administrator', (array) $old_roles, true)) {
                if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                    $user = get_userdata($user_id);
                    \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_rogue_admin_created', [
                        'severity' => 'critical',
                        'message'  => sprintf(__('Existing user "%s" was promoted to Administrator role.', 'wcp-security-scanner'), $user ? $user->user_login : 'user #' . $user_id),
                        'details'  => [
                            'user_id'    => $user_id,
                            'user_login' => $user ? $user->user_login : 'unknown',
                            'old_roles'  => implode(', ', (array) $old_roles),
                            'new_role'   => 'administrator',
                            'promoted_by'=> wp_get_current_user()->user_login ?: 'unknown',
                        ],
                    ]);
                }
            }
        }, 10, 3);

        add_action('rest_api_init', function () {
            ScannerRoutes::register();
        });
    }
}
