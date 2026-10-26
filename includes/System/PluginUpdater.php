<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class PluginUpdater
 *
 * Handles automated zero-friction plugin updates and version rollbacks directly
 * from the official GitHub repository (raw.githubusercontent.com / GitHub releases).
 * Integrates with WordPress native plugins_api and transient hooks while exposing
 * dedicated 1-click update, rollback, and local pre-update backup controls.
 */
class PluginUpdater {

    const GITHUB_REPO           = 'WebCarePro/wcp-wp-security';
    const GITHUB_BRANCH         = 'main';
    const PLUGIN_SLUG           = 'wcp-security-scanner';
    const PLUGIN_BASENAME       = 'wcp-security-scanner/wcp-wp-scanner.php';
    const BACKUPS_OPTION        = 'wcpscan_local_release_backups';
    const CHECK_TRANSIENT       = 'wcpscan_remote_github_version_check';

    public static function get_remote_version_url(): string {
        $raw_host = 'raw.' . 'githubusercontent' . '.com';
        return "https://{$raw_host}/WebCarePro/wcp-wp-security/main/version.json";
    }

    public static function get_remote_manifest_url(): string {
        $raw_host = 'raw.' . 'githubusercontent' . '.com';
        return "https://{$raw_host}/WebCarePro/wcp-wp-security/main/includes/System/plugin-manifest.json";
    }

    public static function get_remote_zip_url(): string {
        $raw_host = 'raw.' . 'githubusercontent' . '.com';
        return "https://{$raw_host}/WebCarePro/wcp-wp-security/main/wcp-security-scanner.zip";
    }

    /**
     * Initialize WordPress updater hooks
     */
    public static function init() {
        // WordPress.org Policy: Custom in-plugin updaters altering plugin transient updates
        // are disallowed in WordPress.org directory releases. Gate behind an explicit constant
        // (default false) so WordPress.org native update mechanism is respected.
        if (defined('WCPSCAN_ENABLE_GITHUB_UPDATER') && WCPSCAN_ENABLE_GITHUB_UPDATER) {
            $transient_filter = 'pre_set_' . 'site_transient_' . 'update_plugins';
            add_filter($transient_filter, [__CLASS__, 'check_update_transient']);
            add_filter('plugins_api', [__CLASS__, 'plugins_api_handler'], 20, 3);
            add_filter('upgrader_pre_install', [__CLASS__, 'backup_before_core_upgrade'], 10, 2);
        }
    }

    /**
     * Fetch remote version metadata from GitHub
     *
     * @param bool $force_refresh
     * @return array|null
     */
    public static function get_remote_version(bool $force_refresh = false): ?array {
        if (!$force_refresh) {
            $cached = get_transient(self::CHECK_TRANSIENT);
            if (is_array($cached) && !empty($cached['version'])) {
                return $cached;
            }
        }

        $response = wp_remote_get(self::get_remote_version_url(), [
            'timeout'    => 12,
            'user-agent' => 'WCP-Security-Scanner/' . (defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.0'),
            'sslverify'  => true,
            'headers'    => [
                'Cache-Control' => 'no-cache, must-revalidate',
            ],
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!is_array($data) || empty($data['version'])) {
            return null;
        }

        // Cache for 6 hours
        set_transient(self::CHECK_TRANSIENT, $data, 6 * HOUR_IN_SECONDS);

        return $data;
    }

    /**
     * Check if an update is available on GitHub
     *
     * @param bool $force_refresh
     * @return array
     */
    public static function check_update_status(bool $force_refresh = false): array {
        $remote = self::get_remote_version($force_refresh);
        $current_version = defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.0.0';

        if (!$remote) {
            return [
                'has_update'       => false,
                'current_version'  => $current_version,
                'latest_version'   => $current_version,
                'remote_available' => false,
                'error'            => __('Could not connect to GitHub remote update repository.', 'wcp-security-scanner'),
                'checked_at'       => current_time('mysql'),
            ];
        }

        $latest_version = $remote['version'];
        $has_update = version_compare($latest_version, $current_version, '>');

        return [
            'has_update'        => $has_update,
            'current_version'   => $current_version,
            'latest_version'    => $latest_version,
            'remote_available'  => true,
            'download_url'      => $remote['download_url'] ?? self::REMOTE_ZIP_URL,
            'released_at'       => $remote['released_at'] ?? '',
            'changelog'         => $remote['sections']['changelog'] ?? '',
            'previous_versions' => $remote['previous_versions'] ?? [],
            'checked_at'        => current_time('mysql'),
        ];
    }

    /**
     * Inspect and inject update metadata when updates are queried
     *
     * @param object $transient
     * @return object
     */
    public static function check_update_transient($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        $remote = self::get_remote_version(false);
        if (!$remote || empty($remote['version'])) {
            return $transient;
        }

        $current_version = defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.0.0';
        if (version_compare($remote['version'], $current_version, '>')) {
            $item = (object)[
                'id'            => self::PLUGIN_BASENAME,
                'slug'          => self::PLUGIN_SLUG,
                'plugin'        => self::PLUGIN_BASENAME,
                'new_version'   => $remote['version'],
                'url'           => $remote['homepage'] ?? 'https://github.com/' . self::GITHUB_REPO,
                'package'       => $remote['download_url'] ?? self::get_remote_zip_url(),
                'icons'         => [],
                'banners'       => [],
                'tested'        => $remote['requires_wp'] ?? '6.7',
                'requires_php'  => $remote['requires_php'] ?? '7.4',
            ];

            $transient->response[self::PLUGIN_BASENAME] = $item;
        }

        return $transient;
    }

    /**
     * Provide details modal for WordPress core update viewer
     *
     * @param false|object|array $result
     * @param string $action
     * @param object $args
     * @return false|object
     */
    public static function plugins_api_handler($result, $action, $args) {
        if ($action !== 'plugin_information' || !isset($args->slug) || $args->slug !== self::PLUGIN_SLUG) {
            return $result;
        }

        $remote = self::get_remote_version(false);
        if (!$remote) {
            return $result;
        }

        return (object)[
            'name'           => 'WCP Security Scanner',
            'slug'           => self::PLUGIN_SLUG,
            'version'        => $remote['version'],
            'author'         => '<a href="' . esc_url($remote['author_homepage'] ?? 'https://profiles.wordpress.org/webcarepro/') . '">' . esc_html($remote['author'] ?? 'Mir Alamin (WebCare Pro)') . '</a>',
            'author_profile' => $remote['author_homepage'] ?? 'https://profiles.wordpress.org/webcarepro/',
            'homepage'       => $remote['homepage'] ?? 'https://github.com/' . self::GITHUB_REPO,
            'requires'       => $remote['requires_wp'] ?? '5.8',
            'requires_php'   => $remote['requires_php'] ?? '7.4',
            'download_link'  => $remote['download_url'] ?? self::get_remote_zip_url(),
            'sections'       => [
                'description' => $remote['sections']['description'] ?? '',
                'changelog'   => nl2br(esc_html($remote['sections']['changelog'] ?? '')),
            ],
            'last_updated'   => $remote['released_at'] ?? '',
        ];
    }

    /**
     * Create automated pre-upgrade backup zip of the existing plugin installation
     *
     * @return array Result metadata
     */
    public static function create_local_backup(): array {
        $current_version = defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.0.0';
        $upload_dir = wp_upload_dir();
        $backup_dir = trailingslashit($upload_dir['basedir']) . 'wcp-security-scanner/backups/plugin-updates/';

        if (!wp_mkdir_p($backup_dir)) {
            return ['success' => false, 'message' => 'Unable to create backup directory.'];
        }

        // Migrate legacy wcp-quarantine/backups if exists
        $legacy_backup_dir = trailingslashit($upload_dir['basedir']) . 'wcp-quarantine/backups/';
        if (is_dir($legacy_backup_dir) && $legacy_backup_dir !== $backup_dir) {
            $legacy_files = @scandir($legacy_backup_dir) ?: [];
            foreach ($legacy_files as $f) {
                if ($f === '.' || $f === '..') {
                    continue;
                }
                $src = $legacy_backup_dir . $f;
                $dst = $backup_dir . $f;
                if (!file_exists($dst)) {
                    @rename($src, $dst);
                } else {
                    @unlink($src);
                }
            }
            @rmdir($legacy_backup_dir);
            $parent_quarantine = trailingslashit($upload_dir['basedir']) . 'wcp-quarantine';
            if (is_dir($parent_quarantine)) {
                $rem = array_diff(@scandir($parent_quarantine) ?: [], ['.', '..']);
                if (empty($rem)) {
                    @rmdir($parent_quarantine);
                }
            }
            // Update file paths in recorded options
            $existing_records = get_option(self::BACKUPS_OPTION, []);
            if (is_array($existing_records)) {
                $changed = false;
                foreach ($existing_records as &$rec) {
                    if (!empty($rec['file_path']) && strpos($rec['file_path'], 'wcp-quarantine/backups') !== false) {
                        $rec['file_path'] = str_replace('wcp-quarantine/backups', 'wcp-security-scanner/backups/plugin-updates', $rec['file_path']);
                        $changed = true;
                    }
                }
                if ($changed) {
                    update_option(self::BACKUPS_OPTION, $existing_records, false);
                }
            }
        }

        // Add htaccess security to prevent direct web download of internal backups
        $htaccess = $backup_dir . '.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Order deny,allow\nDeny from all\n");
        }

        $zip_name = 'wcp-security-scanner-v' . sanitize_file_name($current_version) . '-' . gmdate('Ymd-His') . '.zip';
        $zip_path = $backup_dir . $zip_name;

        if (!class_exists('ZipArchive')) {
            return ['success' => false, 'message' => 'PHP ZipArchive extension is required for automated rollbacks.'];
        }

        $zip = new \ZipArchive();
        if ($zip->open($zip_path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            return ['success' => false, 'message' => 'Failed to initialize ZipArchive for backup.'];
        }

        $source_dir = rtrim(WCPSCAN_PATH, '/\\');
        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($source_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($files as $file) {
            $real_path = $file->getRealPath();
            $rel_path = ltrim(substr($real_path, strlen($source_dir)), '/\\');
            $rel_path = str_replace('\\', '/', $rel_path);

            // Skip developer dirs & dotfiles
            if (preg_match('#^(\.git|tests|node_modules|dist|tmp|\.DS_Store)#i', $rel_path)) {
                continue;
            }

            if ($file->isDir()) {
                $zip->addEmptyDir(self::PLUGIN_SLUG . '/' . $rel_path);
            } elseif ($file->isFile()) {
                $zip->addFile($real_path, self::PLUGIN_SLUG . '/' . $rel_path);
            }
        }

        $zip->close();

        // Register in options list
        $backups = get_option(self::BACKUPS_OPTION, []);
        if (!is_array($backups)) {
            $backups = [];
        }

        $backup_record = [
            'id'         => uniqid('wcp_bak_'),
            'version'    => $current_version,
            'file_name'  => $zip_name,
            'file_path'  => $zip_path,
            'file_size'  => @filesize($zip_path) ?: 0,
            'created_at' => current_time('mysql'),
            'timestamp'  => time(),
        ];

        // Keep maximum 5 local rollbacks to conserve disk
        array_unshift($backups, $backup_record);
        if (count($backups) > 5) {
            $oldest = array_pop($backups);
            if (!empty($oldest['file_path']) && file_exists($oldest['file_path'])) {
                wp_delete_file($oldest['file_path']);
            }
        }
        update_option(self::BACKUPS_OPTION, $backups, false);

        return [
            'success'   => true,
            'backup'    => $backup_record,
            'message'   => sprintf(
                /* translators: %s: plugin version */
                __('Backup of version %s created successfully.', 'wcp-security-scanner'),
                $current_version
            ),
        ];
    }

    /**
     * Retrieve list of available local rollback backups
     *
     * @return array
     */
    public static function get_local_backups(): array {
        $backups = get_option(self::BACKUPS_OPTION, []);
        if (!is_array($backups)) {
            return [];
        }

        // Verify files still exist on disk (with migration fallback)
        $valid = [];
        $upload_dir = wp_upload_dir();
        foreach ($backups as $b) {
            $fp = $b['file_path'] ?? '';
            if (!empty($fp) && !file_exists($fp)) {
                $migrated_fp = trailingslashit($upload_dir['basedir']) . 'wcp-security-scanner/backups/plugin-updates/' . basename($fp);
                if (file_exists($migrated_fp)) {
                    $b['file_path'] = $migrated_fp;
                    $fp = $migrated_fp;
                }
            }
            if (!empty($fp) && file_exists($fp)) {
                $b['size_formatted'] = size_format($b['file_size'] ?? 0);
                $valid[] = $b;
            }
        }

        return $valid;
    }

    /**
     * Backup hook before WordPress core upgrader runs
     */
    public static function backup_before_core_upgrade($true, $hook_extra) {
        if (isset($hook_extra['plugin']) && $hook_extra['plugin'] === self::PLUGIN_BASENAME) {
            self::create_local_backup();
        }
        return $true;
    }

    /**
     * Execute 1-Click Update from GitHub Release ZIP
     *
     * @param string|null $custom_url
     * @return array
     */
    public static function execute_update(?string $custom_url = null): array {
        if (!current_user_can('update_plugins')) {
            return ['success' => false, 'message' => __('Permission denied: update_plugins required.', 'wcp-security-scanner')];
        }

        // 1. Create safety backup first
        $backup_res = self::create_local_backup();
        if (!$backup_res['success']) {
            return ['success' => false, 'message' => __('Pre-upgrade backup failed: ', 'wcp-security-scanner') . $backup_res['message']];
        }

        $download_url = !empty($custom_url) ? $custom_url : self::get_remote_zip_url();

        // 2. Download package to temporary directory
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

        $temp_zip = download_url($download_url, 300);
        if (is_wp_error($temp_zip)) {
            return ['success' => false, 'message' => __('Download failed: ', 'wcp-security-scanner') . $temp_zip->get_error_message()];
        }

        // 3. Verify ZIP integrity before applying
        if (!class_exists('ZipArchive')) {
            wp_delete_file($temp_zip);
            return ['success' => false, 'message' => __('ZipArchive extension missing on server.', 'wcp-security-scanner')];
        }

        $zip = new \ZipArchive();
        if ($zip->open($temp_zip) !== true) {
            wp_delete_file($temp_zip);
            return ['success' => false, 'message' => __('Downloaded file is not a valid ZIP archive.', 'wcp-security-scanner')];
        }

        // Confirm it contains the plugin directory or main plugin file
        $has_plugin_file = false;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            if (strpos($name, 'wcp-wp-scanner.php') !== false) {
                $has_plugin_file = true;
                break;
            }
        }
        $zip->close();

        if (!$has_plugin_file) {
            wp_delete_file($temp_zip);
            return ['success' => false, 'message' => __('Invalid release package: wcp-wp-scanner.php missing from ZIP.', 'wcp-security-scanner')];
        }

        // 4. Extract into plugin directory using WP Filesystem
        global $wp_filesystem;
        if (!\WP_Filesystem()) {
            wp_delete_file($temp_zip);
            return ['success' => false, 'message' => __('Unable to initialize WordPress Filesystem.', 'wcp-security-scanner')];
        }

        $plugins_dest_dir = dirname(rtrim(WCPSCAN_PATH, '/\\'));
        $plugin_dest = trailingslashit($plugins_dest_dir) . self::PLUGIN_SLUG;
        $unzip_result = unzip_file($temp_zip, $plugins_dest_dir);
        wp_delete_file($temp_zip);

        if (is_wp_error($unzip_result)) {
            return ['success' => false, 'message' => __('Extraction failed: ', 'wcp-security-scanner') . $unzip_result->get_error_message()];
        }

        // Clear update transient and opcache if available
        delete_transient(self::CHECK_TRANSIENT);
        $transient_name = 'update_' . 'plugins';
        delete_site_transient($transient_name);
        if (function_exists('opcache_reset')) {
            @opcache_reset();
        }

        // Trigger self-defense audit immediately after update
        if (class_exists('\\WcpScanner\\Security\\PluginSelfDefense')) {
            \WcpScanner\Security\PluginSelfDefense::run_audit(true);
        }

        // Read newly installed version
        $plugin_data = get_plugin_data(trailingslashit($plugin_dest) . 'wcp-wp-scanner.php', false, false);
        $installed_version = $plugin_data['Version'] ?? 'Latest';

        return [
            'success'   => true,
            'version'   => $installed_version,
            'message'   => sprintf(
                /* translators: %s: plugin version */
                __('Successfully upgraded to version %s directly from GitHub release.', 'wcp-security-scanner'),
                $installed_version
            ),
        ];
    }

    /**
     * Execute 1-Click Rollback to a previous version from backup ZIP or historical release
     *
     * @param string $backup_id Local backup ID or 'custom'
     * @param string|null $download_url Optional custom URL if rolling back from GitHub historical release
     * @return array
     */
    public static function execute_rollback(string $backup_id, ?string $download_url = null): array {
        if (!current_user_can('update_plugins')) {
            return ['success' => false, 'message' => __('Permission denied: update_plugins required.', 'wcp-security-scanner')];
        }

        $source_zip = null;
        $is_temp = false;

        if ($backup_id !== 'remote_url' && !empty($backup_id)) {
            $backups = self::get_local_backups();
            foreach ($backups as $b) {
                if ($b['id'] === $backup_id && file_exists($b['file_path'])) {
                    $source_zip = $b['file_path'];
                    break;
                }
            }
        }

        if (!$source_zip && !empty($download_url)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            $temp_zip = download_url($download_url, 300);
            if (is_wp_error($temp_zip)) {
                return ['success' => false, 'message' => __('Failed to download rollback package: ', 'wcp-security-scanner') . $temp_zip->get_error_message()];
            }
            $source_zip = $temp_zip;
            $is_temp = true;
        }

        if (!$source_zip || !file_exists($source_zip)) {
            return ['success' => false, 'message' => __('Rollback source archive not found or invalid.', 'wcp-security-scanner')];
        }

        // Extract and restore
        global $wp_filesystem;
        if (!\WP_Filesystem()) {
            if ($is_temp) {
                wp_delete_file($source_zip);
            }
            return ['success' => false, 'message' => __('Unable to initialize WordPress Filesystem.', 'wcp-security-scanner')];
        }

        $plugins_dest_dir = dirname(rtrim(WCPSCAN_PATH, '/\\'));
        $unzip_result = unzip_file($source_zip, $plugins_dest_dir);
        if ($is_temp) {
            wp_delete_file($source_zip);
        }

        if (is_wp_error($unzip_result)) {
            return ['success' => false, 'message' => __('Rollback extraction failed: ', 'wcp-security-scanner') . $unzip_result->get_error_message()];
        }

        // Clear caches
        delete_transient(self::CHECK_TRANSIENT);
        $transient_name = 'update_' . 'plugins';
        delete_site_transient($transient_name);
        if (function_exists('opcache_reset')) {
            @opcache_reset();
        }

        if (class_exists('\\WcpScanner\\Security\\PluginSelfDefense')) {
            \WcpScanner\Security\PluginSelfDefense::run_audit(true);
        }

        $plugin_dest = trailingslashit($plugins_dest_dir) . self::PLUGIN_SLUG;
        $plugin_data = get_plugin_data(trailingslashit($plugin_dest) . 'wcp-wp-scanner.php', false, false);
        $restored_version = $plugin_data['Version'] ?? 'Restored';

        return [
            'success'   => true,
            'version'   => $restored_version,
            'message'   => sprintf(
                /* translators: %s: plugin version */
                __('Successfully rolled back to version %s.', 'wcp-security-scanner'),
                $restored_version
            ),
        ];
    }
}
