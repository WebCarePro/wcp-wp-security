<?php
namespace WCP\Scanner\Admin;

if (!defined('ABSPATH')) {
    exit;
}

class AdminMenu {
    public static function register() {
        add_action('admin_menu', [__CLASS__, 'add_menu_page']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_assets']);
    }

    public static function add_menu_page() {
        // Main Menu: Dashboard
        add_menu_page(
            __('Security Scanner', 'wcp-security-scanner'),
            __('Security Scanner', 'wcp-security-scanner'),
            'manage_options',
            'wcp-security-scanner',
            [__CLASS__, 'render_app_container'],
            'dashicons-shield',
            80
        );

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

        // Submenu: Vulnerabilities & Updates (Outdated Themes/Plugins/Core with CVEs)
        add_submenu_page(
            'wcp-security-scanner',
            __('Vulnerabilities & Updates', 'wcp-security-scanner'),
            __('Vulnerabilities', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-vulnerabilities',
            [__CLASS__, 'render_app_container']
        );

        // Submenu: Firewall (WAF Lite)
        add_submenu_page(
            'wcp-security-scanner',
            __('Web Application Firewall (WAF Lite)', 'wcp-security-scanner'),
            __('Firewall (WAF)', 'wcp-security-scanner'),
            'manage_options',
            'wcp-scanner-firewall',
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
            'security-scanner_page_wcp-scanner-tools',
            'security-scanner_page_wcp-scanner-logs',
            'security-scanner_page_wcp-scanner-backup',
            'security-scanner_page_wcp-scanner-server',
            'security-scanner_page_wcp-scanner-vulnerabilities',
            'security-scanner_page_wcp-scanner-firewall',
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
        if ($current_page === 'wcp-scanner-tools') $active_tab = 'targeted';
        elseif ($current_page === 'wcp-scanner-logs') $active_tab = 'logs';
        elseif ($current_page === 'wcp-scanner-backup') $active_tab = 'backup';
        elseif ($current_page === 'wcp-scanner-server') $active_tab = 'server';
        elseif ($current_page === 'wcp-scanner-vulnerabilities') $active_tab = 'vulnerabilities';
        elseif ($current_page === 'wcp-scanner-firewall') $active_tab = 'firewall';
        elseif ($current_page === 'wcp-scanner-settings') $active_tab = 'settings';
        elseif ($current_page === 'wcp-scanner-about') $active_tab = 'about';

        $asset_file = WCP_SCANNER_PATH . 'build/index.asset.php';
        $deps = ['wp-element', 'wp-components', 'wp-api-fetch', 'wp-i18n'];
        $version = WCP_SCANNER_VERSION;

        if (file_exists($asset_file)) {
            $asset = include $asset_file;
            $deps = $asset['dependencies'] ?? $deps;
            $version = $asset['version'] ?? $version;
        }

        $js_url = WCP_SCANNER_URL . 'build/index.js';
        $css_url = WCP_SCANNER_URL . 'build/index.css';

        if (file_exists(WCP_SCANNER_PATH . 'build/index.js')) {
            wp_enqueue_script('wcp-scanner-app', $js_url, $deps, $version, true);
            wp_localize_script('wcp-scanner-app', 'wcpScannerSettings', [
                'root'       => esc_url_raw(rest_url('wcp-scanner/v1')),
                'nonce'      => wp_create_nonce('wp_rest'),
                'siteUrl'    => get_site_url(),
                'siteName'   => wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES),
                'initialTab' => $active_tab,
                'version'    => WCP_SCANNER_VERSION,
            ]);
        }

        if (file_exists(WCP_SCANNER_PATH . 'build/index.css')) {
            wp_enqueue_style('wcp-scanner-style', $css_url, ['wp-components'], $version);
        }
    }
}
