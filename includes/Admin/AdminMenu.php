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
        add_action('admin_header', [__CLASS__, 'ensure_admin_screen_title'], 0);
        add_action('admin_footer', [__CLASS__, 'render_plugins_uninstall_modal']);
        add_action('wp_ajax_wcpscan_set_uninstall_purge', [__CLASS__, 'ajax_set_uninstall_purge']);
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
        // PRIMARY VISIBLE MENU PILLARS (Clean SOC Organization)
        // =========================================================================

        // 1. Submenu: Dashboard
        add_submenu_page(
            'wcp-security-scanner',
            __('Scanner Dashboard', 'wcp-security-scanner'),
            __('Dashboard', 'wcp-security-scanner'),
            'manage_options',
            'wcp-security-scanner',
            [__CLASS__, 'render_app_container']
        );

        // 2. Submenu: Scanner & Findings
        add_submenu_page(
            'wcp-security-scanner',
            __('Security Scan & Findings', 'wcp-security-scanner'),
            __('Security Scanner', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-scan',
            [__CLASS__, 'render_app_container']
        );

        // 3. Submenu: Firewall & WAF
        add_submenu_page(
            'wcp-security-scanner',
            __('Web Application Firewall (WAF Lite)', 'wcp-security-scanner'),
            __('Firewall & WAF', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-firewall',
            [__CLASS__, 'render_app_container']
        );

        // 3b. Submenu: Virtual Patching & 0-Day Defense Studio
        add_submenu_page(
            'wcp-security-scanner',
            __('Virtual Patching & 0-Day Exploit Studio', 'wcp-security-scanner'),
            __('Virtual Patching', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-vpatch',
            [__CLASS__, 'render_app_container']
        );

        // 4. Submenu: Login Security & 2FA
        add_submenu_page(
            'wcp-security-scanner',
            __('Multi-Factor Authentication (2FA) & Login Security', 'wcp-security-scanner'),
            __('Identity & 2FA', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-auth',
            [__CLASS__, 'render_app_container']
        );

        // 5. Submenu: WCP Vault & Diagnostics
        add_submenu_page(
            'wcp-security-scanner',
            __('WCP Vault & Safety Recoveries', 'wcp-security-scanner'),
            __('Vault & Tools', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-vault',
            [__CLASS__, 'render_app_container']
        );

        // 6. Submenu: Settings & AI
        add_submenu_page(
            'wcp-security-scanner',
            __('Scanner Settings & AI Configuration', 'wcp-security-scanner'),
            __('Settings & AI', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-settings',
            [__CLASS__, 'render_app_container']
        );

        // 7. Submenu: About & Services
        add_submenu_page(
            'wcp-security-scanner',
            __('About WebCare Pro & Services', 'wcp-security-scanner'),
            __('About & Support', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-about',
            [__CLASS__, 'render_app_container']
        );

        // =========================================================================
        // COMPANION SUB-PAGES (Accessible via Top Header & Contextual Sub-Nav Hub)
        // =========================================================================

        // Sub-Page: Targeted Scans
        add_submenu_page(
            null,
            __('Targeted Security Audits', 'wcp-security-scanner'),
            __('Targeted Scans', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-tools',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: Scan Logs & History
        add_submenu_page(
            null,
            __('Scan Logs & Audit History', 'wcp-security-scanner'),
            __('Scan Logs', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-logs',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: System Forensics & Deep Diagnostics
        add_submenu_page(
            null,
            __('System Forensics & Deep Diagnostics', 'wcp-security-scanner'),
            __('System Forensics', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-forensics',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: File Integrity Monitoring (FIM) & Code Diff
        add_submenu_page(
            null,
            __('File Integrity Monitoring (FIM) & Code Diff', 'wcp-security-scanner'),
            __('File Integrity (FIM)', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-fim',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: Vulnerabilities & Updates (Outdated Themes/Plugins/Core with CVEs)
        add_submenu_page(
            null,
            __('Vulnerabilities & Updates', 'wcp-security-scanner'),
            __('Vulnerabilities', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-vulnerabilities',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: Database Backup Vault
        add_submenu_page(
            null,
            __('Database Backup Vault', 'wcp-security-scanner'),
            __('Database Backup', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-backup',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: Server & Host Infrastructure Telemetry
        add_submenu_page(
            null,
            __('Server & Host Infrastructure Telemetry', 'wcp-security-scanner'),
            __('Host Telemetry', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-server',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: WAF Incident Logs & Telemetry
        add_submenu_page(
            null,
            __('WAF Incident Logs & Attack Forensics', 'wcp-security-scanner'),
            __('WAF Logs', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-waf-logs',
            [__CLASS__, 'render_app_container']
        );

        // Sub-Page: Notifications & Alerts
        add_submenu_page(
            null,
            __('Notifications & Security Alerts', 'wcp-security-scanner'),
            __('Notifications', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-notifications',
            [__CLASS__, 'render_app_container']
        );
    }

    /**
     * Ensure global $title is a valid string for all WCP admin screens before WordPress core admin-header.php runs.
     * Prevents PHP 8.4 deprecation: strip_tags(): Passing null to parameter #1 ($string) is deprecated.
     */
    public static function ensure_admin_screen_title(): void {
        global $title;
        if (empty($title)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
            $title_map = [
                'wcp-security-scanner'       => __('WCP Security Scanner', 'wcp-security-scanner'),
                'wcp-scanner-scan'           => __('Security Scan & Findings', 'wcp-security-scanner'),
                'wcp-scanner-firewall'       => __('Web Application Firewall (WAF Lite)', 'wcp-security-scanner'),
                'wcp-scanner-vpatch'         => __('Virtual Patching & 0-Day Exploit Studio', 'wcp-security-scanner'),
                'wcp-scanner-auth'           => __('Multi-Factor Authentication (2FA) & Login Security', 'wcp-security-scanner'),
                'wcp-scanner-vault'          => __('WCP Vault & Safety Recoveries', 'wcp-security-scanner'),
                'wcp-scanner-settings'       => __('Scanner Settings & AI Configuration', 'wcp-security-scanner'),
                'wcp-scanner-about'          => __('About WebCare Pro & Services', 'wcp-security-scanner'),
                'wcp-scanner-tools'          => __('Targeted Security Audits', 'wcp-security-scanner'),
                'wcp-scanner-logs'           => __('Scan Logs & Audit History', 'wcp-security-scanner'),
                'wcp-scanner-forensics'      => __('System Forensics & Deep Diagnostics', 'wcp-security-scanner'),
                'wcp-scanner-fim'            => __('File Integrity Monitoring (FIM) & Code Diff', 'wcp-security-scanner'),
                'wcp-scanner-vulnerabilities'=> __('Vulnerabilities & Updates', 'wcp-security-scanner'),
                'wcp-scanner-backup'         => __('Database Backup Vault', 'wcp-security-scanner'),
                'wcp-scanner-server'         => __('Server & Host Infrastructure Telemetry', 'wcp-security-scanner'),
                'wcp-scanner-waf-logs'       => __('WAF Incident Logs & Attack Forensics', 'wcp-security-scanner'),
                'wcp-scanner-notifications'  => __('Notifications & Security Alerts', 'wcp-security-scanner'),
            ];

            if (isset($title_map[$page])) {
                $title = $title_map[$page];
            } elseif (strpos($page, 'wcp-') !== false) {
                $title = __('WCP Security Scanner', 'wcp-security-scanner');
            }
        }
    }

    public static function render_app_container() {
        echo '<div class="wrap"><div id="wcp-scanner-root"></div></div>';
    }

    public static function enqueue_assets($hook) {
        $valid_hooks = [
            'toplevel_page_wcp-security-scanner',
            'wcp-security-scanner_page_wcp-scanner-scan',
            'wcp-security-scanner_page_wcp-scanner-vault',
            'wcp-security-scanner_page_wcp-scanner-tools',
            'wcp-security-scanner_page_wcp-scanner-logs',
            'wcp-security-scanner_page_wcp-scanner-forensics',
            'wcp-security-scanner_page_wcp-scanner-quarantine',
            'wcp-security-scanner_page_wcp-scanner-backup',
            'wcp-security-scanner_page_wcp-scanner-server',
            'wcp-security-scanner_page_wcp-scanner-vulnerabilities',
            'wcp-security-scanner_page_wcp-scanner-firewall',
            'wcp-security-scanner_page_wcp-scanner-vpatch',
            'wcp-security-scanner_page_wcp-scanner-waf-logs',
            'wcp-security-scanner_page_wcp-scanner-fim',
            'wcp-security-scanner_page_wcp-scanner-auth',
            'wcp-security-scanner_page_wcp-scanner-notifications',
            'wcp-security-scanner_page_wcp-scanner-settings',
            'wcp-security-scanner_page_wcp-scanner-about',
            'security-scanner_page_wcp-scanner-scan',
            'security-scanner_page_wcp-scanner-vault',
            'security-scanner_page_wcp-scanner-tools',
            'security-scanner_page_wcp-scanner-logs',
            'security-scanner_page_wcp-scanner-forensics',
            'security-scanner_page_wcp-scanner-quarantine',
            'security-scanner_page_wcp-scanner-backup',
            'security-scanner_page_wcp-scanner-server',
            'security-scanner_page_wcp-scanner-vulnerabilities',
            'security-scanner_page_wcp-scanner-firewall',
            'security-scanner_page_wcp-scanner-vpatch',
            'security-scanner_page_wcp-scanner-waf-logs',
            'security-scanner_page_wcp-scanner-fim',
            'security-scanner_page_wcp-scanner-auth',
            'security-scanner_page_wcp-scanner-notifications',
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
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tab_param = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : '';
        if ($current_page === 'wcp-scanner-scan' || ($current_page === 'wcp-security-scanner' && $tab_param === 'scan')) $active_tab = 'scan';
        elseif ($current_page === 'wcp-scanner-vault' || ($current_page === 'wcp-security-scanner' && in_array($tab_param, ['vault', 'quarantine'], true))) $active_tab = 'vault';
        elseif ($current_page === 'wcp-scanner-tools' || ($current_page === 'wcp-security-scanner' && $tab_param === 'targeted')) $active_tab = 'targeted';
        elseif ($current_page === 'wcp-scanner-logs' || ($current_page === 'wcp-security-scanner' && $tab_param === 'logs')) $active_tab = 'logs';
        elseif ($current_page === 'wcp-scanner-forensics' || ($current_page === 'wcp-security-scanner' && $tab_param === 'forensics')) $active_tab = 'forensics';
        elseif ($current_page === 'wcp-scanner-quarantine') $active_tab = 'quarantine';
        elseif ($current_page === 'wcp-scanner-backup' || ($current_page === 'wcp-security-scanner' && $tab_param === 'backup')) $active_tab = 'backup';
        elseif ($current_page === 'wcp-scanner-server' || ($current_page === 'wcp-security-scanner' && $tab_param === 'server')) $active_tab = 'server';
        elseif ($current_page === 'wcp-scanner-vulnerabilities' || ($current_page === 'wcp-security-scanner' && $tab_param === 'vulnerabilities')) $active_tab = 'vulnerabilities';
        elseif ($current_page === 'wcp-scanner-firewall' || ($current_page === 'wcp-security-scanner' && $tab_param === 'firewall')) $active_tab = 'firewall';
        elseif ($current_page === 'wcp-scanner-vpatch' || ($current_page === 'wcp-security-scanner' && $tab_param === 'vpatch') || ($current_page === 'wcp-scanner-firewall' && $tab_param === 'vpatch')) $active_tab = 'vpatch';
        elseif ($current_page === 'wcp-scanner-waf-logs' || ($current_page === 'wcp-security-scanner' && $tab_param === 'waf_logs')) $active_tab = 'waf_logs';
        elseif ($current_page === 'wcp-scanner-fim' || ($current_page === 'wcp-security-scanner' && $tab_param === 'fim')) $active_tab = 'fim';
        elseif ($current_page === 'wcp-scanner-auth' || ($current_page === 'wcp-security-scanner' && $tab_param === 'auth')) $active_tab = 'auth';
        elseif ($current_page === 'wcp-scanner-notifications' || ($current_page === 'wcp-security-scanner' && $tab_param === 'notifications')) $active_tab = 'notifications';
        elseif ($current_page === 'wcp-scanner-settings' || ($current_page === 'wcp-security-scanner' && $tab_param === 'settings')) $active_tab = 'settings';
        elseif ($current_page === 'wcp-scanner-about' || ($current_page === 'wcp-security-scanner' && $tab_param === 'about')) $active_tab = 'about';

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

            $wp_tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone(get_option('timezone_string') ?: 'UTC');
            $wp_tz_offset = $wp_tz->getOffset(new \DateTime('now', new \DateTimeZone('UTC')));

            // Fetch active administrators for reassignment selection
            $admin_users_raw = get_users([
                'role'    => 'administrator',
                'orderby' => 'display_name',
                'order'   => 'ASC',
                'fields'  => ['ID', 'user_login', 'display_name', 'user_email'],
            ]);
            $admin_users_list = [];
            foreach ($admin_users_raw as $admin_obj) {
                $admin_users_list[] = [
                    'id'           => (int) $admin_obj->ID,
                    'user_login'   => $admin_obj->user_login,
                    'display_name' => $admin_obj->display_name ?: $admin_obj->user_login,
                    'user_email'   => $admin_obj->user_email,
                ];
            }

            wp_enqueue_script('wcp-scanner-app', $js_url, $deps, $version, true);
            wp_localize_script('wcp-scanner-app', 'wcpScannerSettings', [
                'root'            => esc_url_raw(rest_url('wcp-scanner/v1')),
                'nonce'           => wp_create_nonce('wp_rest'),
                'siteUrl'         => get_site_url(),
                'siteName'        => wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES),
                'initialTab'      => $active_tab,
                'version'         => WCPSCAN_VERSION,
                'currentUserId'   => get_current_user_id(),
                'adminUsers'      => $admin_users_list,
                'serverInfo'      => $server_info,
                'timezoneString'  => wp_timezone_string(),
                'timezoneOffset'  => $wp_tz_offset, // in seconds from UTC
                'gmtOffset'       => (float) get_option('gmt_offset', 0),
                'siteTime'        => current_time('mysql'),
                'assetsUrl'       => esc_url_raw(WCPSCAN_URL . 'assets/'),
                'logo3dUrl'       => esc_url_raw(WCPSCAN_URL . 'assets/webcare-original-logo-3d.jpg'),
                'emblem3dUrl'     => esc_url_raw(WCPSCAN_URL . 'assets/webcare-3d-emblem.png'),
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

        wp_register_style('wcpscan-admin-brand', false, [], defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.0.0');
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
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['wcpscan_restored'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $count = (int) sanitize_text_field(wp_unslash($_GET['wcpscan_restored']));
            echo '<div class="notice notice-success is-dismissible" style="padding: 12px 18px; border-left: 4px solid #16a34a; background: #f0fdf4;">';
            echo '<p style="margin: 0; font-size: 13px; color: #14532d;">';
            echo '<strong>' . esc_html__('WCP Security Scanner:', 'wcp-security-scanner') . '</strong> ';
            /* translators: %d: count of restored administrator accounts */
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
        echo wp_kses(
            sprintf(
                /* translators: %1$d: count, %2$s: usernames */
                esc_html__('Found %1$d quarantined administrator account(s) (%2$s) available in safety backups.', 'wcp-security-scanner'),
                count($missing_users),
                $names_str
            ),
            ['code' => ['style' => []]]
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

    /**
     * Handle AJAX update for uninstall purge preference when user confirms in modal.
     */
    public static function ajax_set_uninstall_purge() {
        check_ajax_referer('wcpscan_uninstall_prompt_nonce', 'nonce');

        if (!current_user_can('delete_plugins')) {
            wp_send_json_error(['message' => __('Unauthorized permission.', 'wcp-security-scanner')], 403);
        }

        $purge = !empty($_POST['purge']);
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $settings['delete_data_on_uninstall'] = $purge;
        \WcpScanner\System\SettingsManager::save_settings($settings);

        wp_send_json_success(['purge' => $purge]);
    }

    /**
     * Render the interactive modal on wp-admin/plugins.php when deleting WCP Security Scanner.
     * Reminds administrators about quarantined malware, firewall rules, and scan logs,
     * defaulting to KEEP ALL DATA.
     */
    public static function render_plugins_uninstall_modal() {
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        if (!$screen || $screen->id !== 'plugins' || !current_user_can('delete_plugins')) {
            return;
        }

        $nonce = wp_create_nonce('wcpscan_uninstall_prompt_nonce');
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $is_purge_checked = !empty($settings['delete_data_on_uninstall']);
        ?>
        <!-- WCP Security Scanner Uninstall Confirmation Modal -->
        <div id="wcpscan-uninstall-modal-overlay" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.6); z-index: 100050; backdrop-filter: blur(3px); align-items: center; justify-content: center;">
            <div id="wcpscan-uninstall-modal" style="background: #ffffff; border-radius: 12px; width: 100%; max-width: 520px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.25), 0 8px 10px -6px rgba(0, 0, 0, 0.2); overflow: hidden; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, sans-serif; border: 1px solid #e2e8f0; animation: wcpscanFadeIn 0.2s ease-out;">
                
                {/* Header */}
                <div style="padding: 20px 24px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 12px;">
                    <div style="width: 38px; height: 38px; border-radius: 8px; background: #fee2e2; color: #dc2626; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <line x1="12" y1="8" x2="12" y2="12"/>
                            <line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                    </div>
                    <div>
                        <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: #0f172a; line-height: 1.3;">
                            <?php echo esc_html__('Uninstalling WCP Security Scanner', 'wcp-security-scanner'); ?>
                        </h3>
                        <p style="margin: 2px 0 0 0; font-size: 12px; color: #64748b;">
                            <?php echo esc_html__('Please choose your data retention preference before deletion.', 'wcp-security-scanner'); ?>
                        </p>
                    </div>
                </div>

                {/* Body Content */}
                <div style="padding: 22px 24px; color: #334155; font-size: 13.5px; line-height: 1.55;">
                    <p style="margin: 0 0 16px 0;">
                        <?php echo esc_html__('You are deleting WCP Security Scanner. If you reinstall the plugin later, keeping your data ensures your quarantined files and configurations remain intact.', 'wcp-security-scanner'); ?>
                    </p>

                    {/* Option 1: Retain Data (Recommended Default) */}
                    <label style="display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px; border-radius: 8px; border: 2px solid #10b981; background: #f0fdf4; cursor: pointer; margin-bottom: 12px;">
                        <input type="radio" name="wcpscan_uninstall_choice" value="retain" <?php checked(!$is_purge_checked); ?> style="margin-top: 3px; accent-color: #059669;">
                        <div>
                            <div style="font-weight: 700; color: #065f46; font-size: 13.5px; display: flex; align-items: center; gap: 6px;">
                                <span><?php echo esc_html__('Keep All Data & Quarantine Vault', 'wcp-security-scanner'); ?></span>
                                <span style="background: #10b981; color: #ffffff; font-size: 10px; font-weight: 800; text-transform: uppercase; padding: 1px 6px; border-radius: 4px;"><?php echo esc_html__('Recommended', 'wcp-security-scanner'); ?></span>
                            </div>
                            <div style="font-size: 12px; color: #047857; margin-top: 2px;">
                                <?php echo esc_html__('Preserves quarantined malware files, firewall bypass rules, scan history, and custom settings across reinstalls.', 'wcp-security-scanner'); ?>
                            </div>
                        </div>
                    </label>

                    {/* Option 2: Full Purge */}
                    <label style="display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px; border-radius: 8px; border: 1px solid #e2e8f0; background: #ffffff; cursor: pointer;">
                        <input type="radio" name="wcpscan_uninstall_choice" value="purge" <?php checked($is_purge_checked); ?> style="margin-top: 3px; accent-color: #dc2626;">
                        <div>
                            <div style="font-weight: 700; color: #0f172a; font-size: 13.5px;">
                                <?php echo esc_html__('Completely Purge All Data & Tables', 'wcp-security-scanner'); ?>
                            </div>
                            <div style="font-size: 12px; color: #dc2626; margin-top: 2px;">
                                <?php echo esc_html__('Permanently drops all database tables and deletes quarantined files, virtual patches, and backups.', 'wcp-security-scanner'); ?>
                            </div>
                        </div>
                    </label>
                </div>

                {/* Footer Buttons */}
                <div style="padding: 16px 24px; background: #f8fafc; border-top: 1px solid #e2e8f0; display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" id="wcpscan-uninstall-cancel-btn" class="button" style="padding: 4px 14px; font-size: 13px; font-weight: 600;">
                        <?php echo esc_html__('Cancel', 'wcp-security-scanner'); ?>
                    </button>
                    <button type="button" id="wcpscan-uninstall-confirm-btn" class="button button-primary" style="background: #dc2626; border-color: #b91c1c; padding: 4px 18px; font-size: 13px; font-weight: 700; box-shadow: 0 2px 4px rgba(220, 38, 38, 0.25);">
                        <?php echo esc_html__('Proceed with Deletion', 'wcp-security-scanner'); ?>
                    </button>
                </div>
            </div>
        </div>

        <script>
        (function() {
            var targetDeleteLink = null;
            var overlay = document.getElementById('wcpscan-uninstall-modal-overlay');
            var cancelBtn = document.getElementById('wcpscan-uninstall-cancel-btn');
            var confirmBtn = document.getElementById('wcpscan-uninstall-confirm-btn');

            if (!overlay || !cancelBtn || !confirmBtn) return;

            // Intercept click on the "Delete" action link for this plugin
            document.addEventListener('click', function(e) {
                var link = e.target.closest('a');
                if (!link) return;

                var href = link.getAttribute('href') || '';
                var isDelete = href.indexOf('action=delete-selected') !== -1 || (link.classList.contains('delete') && href.indexOf('plugins.php') !== -1);
                var isWcpPlugin = href.indexOf('wcp-wp-scanner') !== -1 || href.indexOf('wcp-security-scanner') !== -1;

                if (!isWcpPlugin) {
                    var row = link.closest('tr[data-plugin*="wcp-"]');
                    if (row) isWcpPlugin = true;
                }

                if (isDelete && isWcpPlugin) {
                    e.preventDefault();
                    e.stopImmediatePropagation();
                    targetDeleteLink = href;
                    overlay.style.display = 'flex';
                }
            }, true);

            // Cancel button
            cancelBtn.addEventListener('click', function() {
                overlay.style.display = 'none';
                targetDeleteLink = null;
            });

            // Close on backdrop click
            overlay.addEventListener('click', function(e) {
                if (e.target === overlay) {
                    overlay.style.display = 'none';
                    targetDeleteLink = null;
                }
            });

            // Confirm & Save preference via AJAX before proceeding
            confirmBtn.addEventListener('click', function() {
                var selected = document.querySelector('input[name="wcpscan_uninstall_choice"]:checked');
                var shouldPurge = selected ? selected.value === 'purge' : false;

                confirmBtn.disabled = true;
                confirmBtn.innerText = '<?php echo esc_js(__('Saving preference...', 'wcp-security-scanner')); ?>';

                var data = new URLSearchParams();
                data.append('action', 'wcpscan_set_uninstall_purge');
                data.append('nonce', '<?php echo esc_js($nonce); ?>');
                data.append('purge', shouldPurge ? '1' : '0');

                fetch(ajaxurl, {
                    method: 'POST',
                    body: data,
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }).then(function() {
                    // Navigate to WordPress native delete confirmation
                    if (targetDeleteLink) {
                        window.location.href = targetDeleteLink;
                    } else {
                        overlay.style.display = 'none';
                    }
                }).catch(function() {
                    if (targetDeleteLink) {
                        window.location.href = targetDeleteLink;
                    }
                });
            });
        })();
        </script>
        <?php
    }
}

