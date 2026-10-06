<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class UpdateScanner {

    /**
     * Check for outdated WordPress core, plugins, and themes.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];

        // 1. Check WordPress Core Updates
        if (!function_exists('get_core_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        wp_version_check();
        $core_updates = get_core_updates();

        if (!empty($core_updates) && is_array($core_updates)) {
            $latest = $core_updates[0];
            if (isset($latest->response) && $latest->response === 'upgrade') {
                global $wp_version;
                $findings[] = new Finding([
                    'engine'      => 'wordpress-updates',
                    'type'        => 'outdated_core',
                    'severity'    => 'high',
                    'confidence'  => 100,
                    'file_path'   => ABSPATH . 'wp-includes/version.php',
                    'description' => "WordPress core is outdated (current: {$wp_version}, latest: {$latest->current}). Outdated core installations are vulnerable to known security exploits.",
                    'evidence'    => "Current: {$wp_version}, Available: {$latest->current}"
                ]);
            }
        }

        // 2. Check Plugin Updates
        wp_update_plugins();
        $update_plugins = get_site_transient('update_plugins');

        if (!empty($update_plugins->response) && is_array($update_plugins->response)) {
            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $all_plugins = get_plugins();

            foreach ($update_plugins->response as $plugin_file => $update_info) {
                $plugin_name = $all_plugins[$plugin_file]['Name'] ?? dirname($plugin_file);
                $cur_version = $all_plugins[$plugin_file]['Version'] ?? 'Unknown';
                $new_version = $update_info->new_version ?? 'Latest';

                $findings[] = new Finding([
                    'engine'      => 'wordpress-updates',
                    'type'        => 'outdated_plugin',
                    'severity'    => 'medium',
                    'confidence'  => 100,
                    'file_path'   => WP_PLUGIN_DIR . '/' . $plugin_file,
                    'description' => "Plugin '{$plugin_name}' is outdated (installed: v{$cur_version}, available: v{$new_version}).",
                    'evidence'    => "Plugin: {$plugin_name}, Installed: v{$cur_version}, Update: v{$new_version}"
                ]);
            }
        }

        // 3. Check Theme Updates
        wp_update_themes();
        $update_themes = get_site_transient('update_themes');

        if (!empty($update_themes->response) && is_array($update_themes->response)) {
            if (!function_exists('wp_get_themes')) {
                require_once ABSPATH . 'wp-includes/theme.php';
            }
            $all_themes = wp_get_themes();

            foreach ($update_themes->response as $theme_slug => $update_info) {
                $theme_obj = $all_themes[$theme_slug] ?? null;
                $theme_name = $theme_obj ? $theme_obj->get('Name') : $theme_slug;
                $cur_version = $theme_obj ? $theme_obj->get('Version') : 'Unknown';
                $new_version = $update_info['new_version'] ?? 'Latest';

                $findings[] = new Finding([
                    'engine'      => 'wordpress-updates',
                    'type'        => 'outdated_theme',
                    'severity'    => 'medium',
                    'confidence'  => 100,
                    'file_path'   => WP_CONTENT_DIR . "/themes/{$theme_slug}",
                    'description' => "Theme '{$theme_name}' is outdated (installed: v{$cur_version}, available: v{$new_version}).",
                    'evidence'    => "Theme: {$theme_name}, Installed: v{$cur_version}, Update: v{$new_version}"
                ]);
            }
        }

        return $findings;
    }
}
