<?php
namespace WcpScanner\Admin;

if (!defined('ABSPATH')) {
    exit;
}

class AdminMenu {
    public static function register() {
        add_action('admin_menu', [__CLASS__, 'add_menu_page']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_assets']);
        add_filter('plugin_action_links_' . plugin_basename(WCPSCAN_FILE), [__CLASS__, 'add_plugin_action_links']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_brand_styles']);
        add_action('admin_notices', [__CLASS__, 'render_user_recovery_notice']);
        add_action('admin_init', [__CLASS__, 'handle_user_recovery_action']);
    }

    public static function add_menu_page() {
        $menu_icon = plugins_url('assets/icon.svg', WCPSCAN_FILE);

        // Main Menu: Dashboard
        add_menu_page(
            __('WCP Security Scanner', 'wcp-security-scanner'),
            __('WCP Security Scanner', 'wcp-security-scanner'),
            'manage_options',
            'wcp-security-scanner',
            [__CLASS__, 'render_app_container'],
            $menu_icon,
            80
        );

        // =========================================================================
        // 1. SCANNER & AUDIT LOGS
        // =========================================================================

        // Submenu: Dashboard
        add_submenu_page(
            'wcp-security-scanner',
            __('Scanner Dashboard', 'wcp-security-scanner'),
            __('Dashboard', 'wcp-security-scanner'),
            'manage_options',
            'wcp-security-scanner',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Targeted Scans
        add_submenu_page(
            'wcp-security-scanner',
            __('Targeted Security Audits', 'wcp-security-scanner'),
            __('Targeted Scans', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-tools',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Scan Logs & History
        add_submenu_page(
            'wcp-security-scanner',
            __('Scan Logs & Audit History', 'wcp-security-scanner'),
            __('Scan Logs', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-logs',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: WCP Vault (Unified Vault Suite)
        add_submenu_page(
            'wcp-security-scanner',
            __('WCP Vault & Safety Recoveries', 'wcp-security-scanner'),
            __('WCP Vault', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-vault',
            [__CLASS__, 'render_app_container']
        );

        // =========================================================================
        // 2. ACTIVE DEFENSES & PROTECTION
        // =========================================================================

        // Submenu: Firewall (WAF Lite)
        add_submenu_page(
            'wcp-security-scanner',
            __('Web Application Firewall (WAF Lite)', 'wcp-security-scanner'),
            __('Firewall (WAF)', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-firewall',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Login Security & 2FA
        add_submenu_page(
            'wcp-security-scanner',
            __('Multi-Factor Authentication (2FA) & Login Security', 'wcp-security-scanner'),
            __('Login Security & 2FA', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-auth',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: File Integrity Monitoring (FIM) & Code Diff
        add_submenu_page(
            'wcp-security-scanner',
            __('File Integrity Monitoring (FIM) & Code Diff', 'wcp-security-scanner'),
            __('File Integrity (FIM)', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-fim',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Vulnerabilities & Updates (Outdated Themes/Plugins/Core with CVEs)
        add_submenu_page(
            'wcp-security-scanner',
            __('Vulnerabilities & Updates', 'wcp-security-scanner'),
            __('Vulnerabilities', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-vulnerabilities',
            [__CLASS__, 'render_app_container']
        );

        // =========================================================================
        // 3. TOOLS & SYSTEM ADMINISTRATION
        // =========================================================================

        // Submenu: Database Backup
        add_submenu_page(
            'wcp-security-scanner',
            __('Database Backup Vault', 'wcp-security-scanner'),
            __('Database Backup', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-backup',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Server Info
        add_submenu_page(
            'wcp-security-scanner',
            __('Server & PHP Environment Info', 'wcp-security-scanner'),
            __('Server Info', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-server',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Settings
        add_submenu_page(
            'wcp-security-scanner',
            __('Scanner Settings & AI Configuration', 'wcp-security-scanner'),
            __('Settings', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-settings',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: About & Services
        add_submenu_page(
            'wcp-security-scanner',
            __('About WebCare Pro & Services', 'wcp-security-scanner'),
            __('About & Services', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-about',
            [__CLASS__, 'render_app_container']
        );
    }

    public static function render_app_container() {
        echo '<div class="wrap"><div id="wcp-scanner-root"></div></div>';
    }

    public static function enqueue_assets($hook) {
        $valid_hooks = [
            'toplevel_page_wcp-security-scanner',
            'wcp-security-scanner_page_wcp-scanner-vault',
            'wcp-security-scanner_page_wcp-scanner-tools',
            'wcp-security-scanner_page_wcp-scanner-logs',
            'wcp-security-scanner_page_wcp-scanner-quarantine',
            'wcp-security-scanner_page_wcp-scanner-backup',
            'wcp-security-scanner_page_wcp-scanner-server',
            'wcp-security-scanner_page_wcp-scanner-vulnerabilities',
            'wcp-security-scanner_page_wcp-scanner-firewall',
            'wcp-security-scanner_page_wcp-scanner-fim',
            'wcp-security-scanner_page_wcp-scanner-auth',
            'wcp-security-scanner_page_wcp-scanner-settings',
            'wcp-security-scanner_page_wcp-scanner-about',
            'security-scanner_page_wcp-scanner-vault',
            'security-scanner_page_wcp-scanner-tools',
            'security-scanner_page_wcp-scanner-logs',
            'security-scanner_page_wcp-scanner-quarantine',
            'security-scanner_page_wcp-scanner-backup',
            'security-scanner_page_wcp-scanner-server',
            'security-scanner_page_wcp-scanner-vulnerabilities',
            'security-scanner_page_wcp-scanner-firewall',
            'security-scanner_page_wcp-scanner-fim',
            'security-scanner_page_wcp-scanner-auth',
            'security-scanner_page_wcp-scanner-settings',
            'security-scanner_page_wcp-scanner-about',
        ];

        // Also check query param fallback
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        $is_wcp_page = in_array($hook, $valid_hooks, true) || strpos($current_page, 'wcp-scanner') !== false || $current_page === 'wcp-security-scanner';

        if (!$is_wcp_page) {
            return;
        }

        $active_tab = 'dashboard';
        if ($current_page === 'wcp-scanner-vault') $active_tab = 'vault';
        elseif ($current_page === 'wcp-scanner-tools') $active_tab = 'targeted';
        elseif ($current_page === 'wcp-scanner-logs') $active_tab = 'logs';
        elseif ($current_page === 'wcp-scanner-quarantine') $active_tab = 'quarantine';
        elseif ($current_page === 'wcp-scanner-backup') $active_tab = 'backup';
        elseif ($current_page === 'wcp-scanner-server') $active_tab = 'server';
        elseif ($current_page === 'wcp-scanner-vulnerabilities') $active_tab = 'vulnerabilities';
        elseif ($current_page === 'wcp-scanner-firewall') $active_tab = 'firewall';
        elseif ($current_page === 'wcp-scanner-fim') $active_tab = 'fim';
        elseif ($current_page === 'wcp-scanner-auth') $active_tab = 'auth';
        elseif ($current_page === 'wcp-scanner-settings') $active_tab = 'settings';
        elseif ($current_page === 'wcp-scanner-about') $active_tab = 'about';

        $asset_file = WCPSCAN_PATH . 'build/index.asset.php';
        $deps = ['wp-element', 'wp-components', 'wp-api-fetch', 'wp-i18n'];
        $version = WCPSCAN_VERSION;

        if (file_exists($asset_file)) {
            $asset = include $asset_file;
            $deps = $asset['dependencies'] ?? $deps;
            $version = $asset['version'] ?? $version;
        }

        $js_url = WCPSCAN_URL . 'build/index.js';
        $css_url = WCPSCAN_URL . 'build/index.css';

        if (file_exists(WCPSCAN_PATH . 'build/index.js')) {
            $server_info = [];
            try {
                $server_info = \WcpScanner\System\ServerInfo::get_info(false);
            } catch (\Throwable $e) {
                $server_info = [
                    'php' => ['version' => PHP_VERSION],
                    'wordpress' => ['version' => $GLOBALS['wp_version'] ?? ''],
                ];
            }

            wp_enqueue_script('wcp-scanner-app', $js_url, $deps, $version, true);
            wp_localize_script('wcp-scanner-app', 'wcpScannerSettings', [
                'root'       => esc_url_raw(rest_url('wcp-scanner/v1')),
                'nonce'      => wp_create_nonce('wp_rest'),
                'siteUrl'    => get_site_url(),
                'siteName'   => wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES),
                'initialTab'    => $active_tab,
                'version'       => WCPSCAN_VERSION,
                'currentUserId' => get_current_user_id(),
                'serverInfo'    => $server_info,
                'assetsUrl'     => esc_url_raw(WCPSCAN_URL . 'assets/'),
                'logo3dUrl'     => esc_url_raw(WCPSCAN_URL . 'assets/webcare-original-logo-3d.jpg'),
                'emblem3dUrl'   => esc_url_raw(WCPSCAN_URL . 'assets/webcare-3d-emblem.png'),
            ]);
        }

        if (file_exists(WCPSCAN_PATH . 'build/index.css')) {
            wp_enqueue_style('wcp-scanner-style', $css_url, ['wp-components'], $version);
        }
    }

    /**
     * Add "Settings" action link beside "Deactivate" on wp-admin/plugins.php
     *
     * @param array $actions
     * @return array
     */
    public static function add_plugin_action_links(array $actions): array {
        $settings_url = admin_url('admin.php?page=wcp-scanner-settings');
        $settings_link = '<a href="' . esc_url($settings_url) . '">' . esc_html__('Settings', 'wcp-security-scanner') . '</a>';

        $new_actions = [];
        $placed = false;

        foreach ($actions as $key => $action) {
            $new_actions[$key] = $action;
            if ($key === 'deactivate' || $key === 'activate') {
                $new_actions['settings'] = $settings_link;
                $placed = true;
            }
        }

        if (!$placed) {
            $new_actions['settings'] = $settings_link;
        }

        return $new_actions;
    }

    /**
     * Enqueue custom admin CSS for official branding logo in sidebar and plugins page
     */
    public static function enqueue_brand_styles(): void {
        $logo_url = plugins_url('assets/icon.svg', WCPSCAN_FILE);
        $custom_css = "
            /* WCP Security Scanner - Sidebar Menu Icon */
            #adminmenu #toplevel_page_wcp-security-scanner .wp-menu-image img {
                width: 20px;
                height: 20px;
                padding: 7px 0 0;
                object-fit: contain;
                transition: transform 0.15s ease-in-out;
            }
            #adminmenu #toplevel_page_wcp-security-scanner:hover .wp-menu-image img,
            #adminmenu #toplevel_page_wcp-security-scanner.wp-has-current-submenu .wp-menu-image img {
                transform: scale(1.1);
            }
            /* WCP Security Scanner - Plugins List Page Brand Logo */
            .plugins tr[data-plugin*=\"wcp-wp-scanner.php\"] .plugin-title strong::before,
            .plugins tr[data-plugin*=\"wcp-security-scanner.php\"] .plugin-title strong::before {
                content: \"\";
                display: inline-block;
                vertical-align: -4px;
                width: 20px;
                height: 20px;
                margin-right: 8px;
                background: url(\"" . esc_url($logo_url) . "\") no-repeat center center;
                background-size: contain;
                border-radius: 4px;
            }
        ";

        wp_register_style('wcpscan-admin-brand', false);
        wp_enqueue_style('wcpscan-admin-brand');
        wp_add_inline_style('wcpscan-admin-brand', $custom_css);
    }

    /**
     * Render an emergency 1-click restore notice across wp-admin (including users.php)
     * if any backed-up administrator accounts are missing from the WordPress database.
     */
    public static function render_user_recovery_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Show confirmation notice if redirected after restoration
        if (!empty($_GET['wcpscan_restored'])) {
            $count = (int) $_GET['wcpscan_restored'];
            echo '<div class="notice notice-success is-dismissible" style="padding: 12px 18px; border-left: 4px solid #16a34a; background: #f0fdf4;">';
            echo '<p style="margin: 0; font-size: 13px; color: #14532d;">';
            echo '<strong>' . esc_html__('WCP Security Scanner:', 'wcp-security-scanner') . '</strong> ';
            echo esc_html(sprintf(__('Successfully restored %d administrator account(s) to the WordPress database with full original capabilities and passwords.', 'wcp-security-scanner'), $count));
            echo '</p></div>';
            return;
        }

        $mgr = new \WcpScanner\WordPress\UserRemediationManager();
        $missing_users = $mgr->get_missing_user_backups();

        if (empty($missing_users)) {
            return;
        }

        $nonce = wp_create_nonce('wcpscan_restore_users_action');
        $restore_url = add_query_arg([
            'wcpscan_action' => 'restore_all_users',
            '_wpnonce'       => $nonce,
        ], admin_url('users.php'));

        $names = array_map(fn($u) => '<code style="background: #e2e8f0; font-weight: 700;">' . esc_html($u['user_login']) . '</code>', $missing_users);
        $names_str = implode(', ', $names);

        echo '<div class="notice notice-warning is-dismissible" style="padding: 14px 18px; border-left: 4px solid #22c55e; background: #f0fdf4; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">';
        echo '<div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">';
        echo '<div style="font-size: 13px; color: #14532d;">';
        echo '<strong>' . esc_html__('WCP Security Scanner:', 'wcp-security-scanner') . '</strong> ';
        echo sprintf(
            /* translators: %1$d: count, %2$s: usernames */
            esc_html__('Found %1$d quarantined administrator account(s) (%2$s) available in safety backups.', 'wcp-security-scanner'),
            count($missing_users),
            $names_str
        );
        echo '</div>';
        echo '<a href="' . esc_url($restore_url) . '" class="button button-primary" style="background: #16a34a; border-color: #15803d; font-weight: 700; padding: 2px 14px; box-shadow: 0 2px 4px rgba(22,163,74,0.2);">';
        echo esc_html__('1-Click Restore All Admin Accounts', 'wcp-security-scanner');
        echo '</a>';
        echo '</div>';
        echo '</div>';
    }

    /**
     * Process 1-click restore request initiated from the WordPress admin notice.
     */
    public static function handle_user_recovery_action() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_GET['wcpscan_action']) && $_GET['wcpscan_action'] === 'restore_all_users') {
            check_admin_referer('wcpscan_restore_users_action');

            $mgr = new \WcpScanner\WordPress\UserRemediationManager();
            $res = $mgr->restore_all_user_backups();
            $count = count($res['restored'] ?? []);

            wp_safe_redirect(add_query_arg(['wcpscan_restored' => $count], admin_url('users.php')));
            exit;
        }
    }
}

