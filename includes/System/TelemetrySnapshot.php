<?php
namespace WebCareProScanner\System;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Diagnostic & Environmental Telemetry Snapshot Provider.
 *
 * Provides a sanitized, safe snapshot of the WordPress environment,
 * server infrastructure, Cloudflare/proxy routing, and active/installed
 * plugins and themes for forensic log analysis and support audits.
 *
 * Excludes any credentials, API tokens, salts, or confidential keys.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
class TelemetrySnapshot {

    /**
     * Build comprehensive environment snapshot.
     *
     * @return array
     */
    public static function get_snapshot(): array {
        global $wp_version;

        // 1. Site info
        $site_url  = function_exists('get_site_url') ? get_site_url() : '';
        $home_url  = function_exists('get_home_url') ? get_home_url() : '';
        $site_name = function_exists('get_bloginfo') ? get_bloginfo('name') : '';
        $domain    = !empty($site_url) ? (wp_parse_url($site_url, PHP_URL_HOST) ?: '') : '';
        if (empty($domain) && !empty($_SERVER['HTTP_HOST'])) {
            $domain = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST']));
        }

        // 2. Server IP & Infrastructure
        $server_ip = class_exists('\\WebCareProScanner\\System\\ServerInfo')
            ? ServerInfo::get_server_ip()
            : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown');

        $all_ips = class_exists('\\WebCareProScanner\\System\\ServerInfo')
            ? ServerInfo::get_all_server_ips()
            : [$server_ip];

        $server_software = isset($_SERVER['SERVER_SOFTWARE'])
            ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))
            : 'Unknown';

        // 3. Cloudflare & Edge Proxy Detection
        $has_cf_ip_header   = !empty($_SERVER['HTTP_CF_CONNECTING_IP']);
        $has_cf_ray         = !empty($_SERVER['HTTP_CF_RAY']);
        $remote_ip          = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $is_cf_ip           = class_exists(FirewallEngine::class) && FirewallEngine::is_cloudflare_ip($remote_ip);
        $is_cf_configured   = false;
        if (class_exists(CloudflareService::class) && method_exists(CloudflareService::class, 'is_configured')) {
            $is_cf_configured = CloudflareService::is_configured();
        } elseif (class_exists(SettingsManager::class)) {
            $cf_settings = SettingsManager::get_settings();
            $is_cf_configured = !empty($cf_settings['cloudflare_api_token']) && !empty($cf_settings['cloudflare_zone_id']);
        }

        $powered_by_cf = $has_cf_ip_header || $has_cf_ray || $is_cf_ip || $is_cf_configured;
        $cf_mode_desc  = 'Direct Origin (No Cloudflare Detected)';
        if ($powered_by_cf) {
            $cf_mode_desc = 'Cloudflare Edge Proxy Active';
            if ($is_cf_configured) {
                $cf_mode_desc .= ' & Synchronized with WCP Firewall';
            }
        }

        // 4. Themes Inventory
        $theme_data = self::get_themes_data();

        // 5. Plugins Inventory
        $plugin_data = self::get_plugins_data();

        // 6. Database & PHP
        global $wpdb;
        $db_version = method_exists($wpdb, 'db_version') ? $wpdb->db_version() : 'Unknown';

        return [
            'schema_version'          => '1.0.0',
            'exported_at_utc'         => gmdate('Y-m-d\TH:i:s\Z'),
            'exported_at_local'       => current_time('mysql'),
            'site' => [
                'name'                => $site_name,
                'domain'              => $domain,
                'site_url'            => $site_url,
                'home_url'            => $home_url,
                'is_multisite'        => is_multisite(),
                'ssl_active'          => class_exists('\\WebCareProScanner\\System\\ServerInfo') ? ServerInfo::is_ssl_active() : is_ssl(),
            ],
            'server' => [
                'real_ip'             => $server_ip,
                'all_host_ips'        => $all_ips,
                'software'            => $server_software,
                'os'                  => php_uname('s') . ' ' . php_uname('r') . ' (' . php_uname('m') . ')',
                'php_version'         => PHP_VERSION,
                'php_sapi'            => php_sapi_name(),
                'memory_limit'        => ini_get('memory_limit') ?: '256M',
                'max_execution_time'  => (int) (ini_get('max_execution_time') ?: 30),
                'database_version'    => $db_version,
                'database_prefix'     => $wpdb->prefix ?? 'wp_',
            ],
            'edge_network' => [
                'powered_by_cloudflare' => $powered_by_cf,
                'cloudflare_status'     => $cf_mode_desc,
                'cf_ray_detected'       => $has_cf_ray,
                'cf_sync_enabled'       => $is_cf_configured,
            ],
            'wordpress' => [
                'core_version'        => $wp_version ?? 'Unknown',
                'debug_mode'          => defined('WP_DEBUG') && WP_DEBUG,
                'debug_log'           => defined('WP_DEBUG_LOG') && WP_DEBUG_LOG,
            ],
            'theme'                   => $theme_data,
            'plugins'                 => $plugin_data,
        ];
    }

    /**
     * Collect active and installed themes.
     *
     * @return array
     */
    private static function get_themes_data(): array {
        $active_theme = function_exists('wp_get_theme') ? wp_get_theme() : null;
        $active_info = null;
        $parent_info = null;

        if ($active_theme && $active_theme->exists()) {
            $active_info = [
                'name'        => $active_theme->get('Name'),
                'slug'        => $active_theme->get_stylesheet(),
                'version'     => $active_theme->get('Version') ?: 'Unknown',
                'author'      => $active_theme->get('Author') ?: '',
                'is_child'    => is_child_theme(),
            ];

            if (is_child_theme() && $active_theme->parent()) {
                $parent = $active_theme->parent();
                $parent_info = [
                    'name'    => $parent->get('Name'),
                    'slug'    => $parent->get_template(),
                    'version' => $parent->get('Version') ?: 'Unknown',
                    'author'  => $parent->get('Author') ?: '',
                ];
            }
        }

        $installed = [];
        if (function_exists('wp_get_themes')) {
            $all_themes = wp_get_themes();
            foreach ($all_themes as $slug => $t) {
                $is_current = $active_theme && ($slug === $active_theme->get_stylesheet());
                $installed[] = [
                    'name'    => $t->get('Name'),
                    'slug'    => $slug,
                    'version' => $t->get('Version') ?: 'Unknown',
                    'status'  => $is_current ? 'active' : 'inactive',
                ];
            }
        }

        return [
            'active_theme'     => $active_info,
            'parent_theme'     => $parent_info,
            'total_installed'  => count($installed),
            'installed_themes' => $installed,
        ];
    }

    /**
     * Collect active and installed plugins.
     *
     * @return array
     */
    private static function get_plugins_data(): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $active_plugins_list = function_exists('get_option') ? (array) get_option('active_plugins', []) : [];

        $active = [];
        $inactive = [];

        foreach ($all_plugins as $file => $info) {
            $is_active = in_array($file, $active_plugins_list, true) || (is_multisite() && function_exists('is_plugin_active_for_network') && is_plugin_active_for_network($file));
            $item = [
                'name'    => $info['Name'] ?? $file,
                'version' => $info['Version'] ?? 'Unknown',
                'file'    => $file,
                'author'  => !empty($info['Author']) ? wp_strip_all_tags($info['Author']) : '',
                'status'  => $is_active ? 'active' : 'inactive',
            ];

            if ($is_active) {
                $active[] = $item;
            } else {
                $inactive[] = $item;
            }
        }

        return [
            'total_installed'  => count($all_plugins),
            'active_count'     => count($active),
            'inactive_count'   => count($inactive),
            'active_plugins'   => $active,
            'inactive_plugins' => $inactive,
        ];
    }
}
