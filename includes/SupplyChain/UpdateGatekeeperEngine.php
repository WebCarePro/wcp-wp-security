<?php
namespace WcpScanner\SupplyChain;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * UpdateGatekeeperEngine
 *
 * Supply-Chain Defense & Pre-Install Delta Gatekeeper.
 * Intercepts incoming unzipped plugin updates before production directories are overwritten,
 * conducting differential integrity analysis, detecting obfuscated PHP and rogue socket endpoints,
 * creating automated pre-update rollback snapshots, and blocking contaminated releases.
 */
class UpdateGatekeeperEngine {

    const OPTION_LOGS      = 'wcpscan_gatekeeper_logs';
    const OPTION_SNAPSHOTS = 'wcpscan_gatekeeper_snapshots';
    const OPTION_SETTINGS  = 'wcpscan_gatekeeper_settings';

    /**
     * Initialize Gatekeeper hooks.
     */
    public static function init() {
        add_filter('upgrader_source_selection', [__CLASS__, 'inspect_unpacked_source'], 20, 4);
    }

    /**
     * Get Gatekeeper configuration settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'                => true,
            'block_critical_threats' => true,
            'auto_snapshot_updates'  => true,
            'max_snapshots'          => 10,
        ];
        $settings = get_option(self::OPTION_SETTINGS, []);
        return array_merge($defaults, is_array($settings) ? $settings : []);
    }

    /**
     * Update Gatekeeper settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();
        $updated = [
            'enabled'                => !empty($new_settings['enabled']),
            'block_critical_threats' => !empty($new_settings['block_critical_threats']),
            'auto_snapshot_updates'  => !empty($new_settings['auto_snapshot_updates']),
            'max_snapshots'          => max(3, min(30, intval($new_settings['max_snapshots'] ?? 10))),
        ];
        update_option(self::OPTION_SETTINGS, $updated);
        return $updated;
    }

    /**
     * Inspect unpacked source before WordPress copies files to destination.
     *
     * @param string|\WP_Error $source Source directory of extracted files.
     * @param string           $remote_source Remote source directory.
     * @param object           $upgrader Upgrader instance.
     * @param array            $hook_extra Hook context.
     * @return string|\WP_Error
     */
    public static function inspect_unpacked_source($source, $remote_source, $upgrader, array $hook_extra = []) {
        if (is_wp_error($source)) {
            return $source;
        }

        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return $source;
        }

        $folder_name = basename(untrailingslashit($source));

        // Self-Exclusion: Never intercept or flag WCP Security Scanner itself
        // (Internal attack simulation test suites, virtual patch synthesizers, and quarantine engines contain controlled exploit strings)
        if ($folder_name === 'wcp-security-scanner') {
            return $source;
        }

        $installed_plugin_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $folder_name);
        $is_update = is_dir($installed_plugin_dir);

        if ($is_update) {
            // =========================================================================
            // UPDATE DELTA ANALYSIS
            // =========================================================================
            $delta = self::calculate_delta($installed_plugin_dir, $source);

            // Stash pre-update rollback snapshot
            $snapshot_id = null;
            if (!empty($settings['auto_snapshot_updates'])) {
                $snapshot_id = self::create_rollback_snapshot($folder_name, $installed_plugin_dir);
            }

            // Perform static risk analysis on the incoming directory
            $analysis = InstallRiskAdvisor::analyze_directory($source, $folder_name);

            $log_entry = [
                'id'            => 'gk_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
                'timestamp'     => time(),
                'datetime'      => current_time('mysql'),
                'action_type'   => 'update',
                'plugin_slug'   => $folder_name,
                'status'        => 'allowed',
                'risk_score'    => $analysis['score'],
                'risk_level'    => $analysis['level'],
                'delta'         => [
                    'added_count'    => count($delta['added']),
                    'modified_count' => count($delta['modified']),
                    'deleted_count'  => count($delta['deleted']),
                    'added_sample'   => array_slice($delta['added'], 0, 8),
                    'modified_sample'=> array_slice($delta['modified'], 0, 8),
                ],
                'snapshot_id'   => $snapshot_id,
                'findings_count'=> count($analysis['findings']),
                'findings'      => array_slice($analysis['findings'], 0, 5),
            ];

            // If critical supply chain contamination found and blocking enabled
            if ($analysis['level'] === 'critical' && !empty($settings['block_critical_threats'])) {
                $log_entry['status'] = 'blocked';
                self::record_log($log_entry);

                AuditLogger::log(
                    'gatekeeper_update_blocked',
                    sprintf('WCP Gatekeeper BLOCKED supply-chain update for "%s" (Risk Score: %d/100).', $folder_name, $analysis['score'])
                );

                NotificationDispatcher::trigger('supply_chain_gatekeeper_blocked', [
                    'title'   => __('Hostile Plugin Update Intercepted by Gatekeeper', 'wcp-security-scanner'),
                    'message' => sprintf(__('Hostile update intercepted for "%s" (Risk Score: %d/100). Production files protected.', 'wcp-security-scanner'), $folder_name, $analysis['score']),
                    'details' => [
                        'plugin_slug'     => $folder_name,
                        'risk_score'      => $analysis['score'] . '/100',
                        'findings_sample' => !empty($analysis['findings'][0]['title']) ? $analysis['findings'][0]['title'] : 'Critical anomalies detected',
                    ],
                ]);

                $reason = !empty($analysis['findings'][0]['title'])
                    ? $analysis['findings'][0]['title'] . ' (' . ($analysis['findings'][0]['file'] ?? '') . ')'
                    : 'Critical supply-chain security anomaly detected.';

                return new \WP_Error(
                    'wcp_gatekeeper_update_blocked',
                    sprintf(
                        /* translators: 1: plugin folder name, 2: block reason */
                        __('WCP Update Gatekeeper Security Intercept: The incoming update for "%1$s" was BLOCKED because critical supply-chain risks were detected: %2$s. Your production files were protected.', 'wcp-security-scanner'),
                        esc_html($folder_name),
                        esc_html($reason)
                    )
                );
            }

            // Allowed update
            self::record_log($log_entry);
            AuditLogger::log(
                'gatekeeper_update_audited',
                sprintf('WCP Gatekeeper audited update for "%s" (+%d files, %d modified, Risk: %s).', $folder_name, count($delta['added']), count($delta['modified']), strtoupper($analysis['level']))
            );

        } else {
            // =========================================================================
            // FRESH INSTALL RISK AUDIT
            // =========================================================================
            $analysis = InstallRiskAdvisor::analyze_directory($source, $folder_name);

            $log_entry = [
                'id'            => 'gk_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
                'timestamp'     => time(),
                'datetime'      => current_time('mysql'),
                'action_type'   => 'install',
                'plugin_slug'   => $folder_name,
                'status'        => 'allowed',
                'risk_score'    => $analysis['score'],
                'risk_level'    => $analysis['level'],
                'delta'         => null,
                'snapshot_id'   => null,
                'findings_count'=> count($analysis['findings']),
                'findings'      => array_slice($analysis['findings'], 0, 5),
            ];

            if ($analysis['level'] === 'critical' && !empty($settings['block_critical_threats'])) {
                $log_entry['status'] = 'blocked';
                self::record_log($log_entry);

                AuditLogger::log(
                    'gatekeeper_install_blocked',
                    sprintf('WCP Gatekeeper BLOCKED fresh install of "%s" (Risk Score: %d/100).', $folder_name, $analysis['score'])
                );

                return new \WP_Error(
                    'wcp_gatekeeper_install_blocked',
                    sprintf(
                        /* translators: %s: plugin folder name */
                        __('WCP Update Gatekeeper Security Intercept: Installation of "%s" was BLOCKED due to critical security risk patterns detected in package.', 'wcp-security-scanner'),
                        esc_html($folder_name)
                    )
                );
            }

            self::record_log($log_entry);
        }

        return $source;
    }

    /**
     * Compute delta file diff between installed plugin and incoming update folder.
     *
     * @param string $installed_dir
     * @param string $source_dir
     * @return array
     */
    public static function calculate_delta(string $installed_dir, string $source_dir): array {
        $old_files = self::map_directory_hashes($installed_dir);
        $new_files = self::map_directory_hashes($source_dir);

        $added = [];
        $modified = [];
        $deleted = [];

        foreach ($new_files as $rel => $hash) {
            if (!isset($old_files[$rel])) {
                $added[] = $rel;
            } elseif ($old_files[$rel] !== $hash) {
                $modified[] = $rel;
            }
        }

        foreach ($old_files as $rel => $hash) {
            if (!isset($new_files[$rel])) {
                $deleted[] = $rel;
            }
        }

        return [
            'added'    => $added,
            'modified' => $modified,
            'deleted'  => $deleted,
        ];
    }

    /**
     * Hash all files in directory relative to base.
     *
     * @param string $dir
     * @return array [rel_path => sha256]
     */
    private static function map_directory_hashes(string $dir): array {
        $hashes = [];
        $dir = wp_normalize_path(realpath($dir) ?: $dir);

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS)
            );

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $full_path = wp_normalize_path($item->getPathname());
                    $rel_path = ltrim(str_replace($dir, '', $full_path), '/');
                    $hashes[$rel_path] = hash_file('sha256', $full_path);
                }
            }
        } catch (\Exception $e) {
            // Ignore traversal failures
        }

        return $hashes;
    }

    /**
     * Create an isolated pre-update rollback snapshot of an existing plugin.
     *
     * @param string $slug
     * @param string $source_dir
     * @return string|null Snapshot ID
     */
    public static function create_rollback_snapshot(string $slug, string $source_dir): ?string {
        $uploads = wp_upload_dir();
        $base_snapshots = wp_normalize_path($uploads['basedir'] . '/wcp-security-scanner/gatekeeper');

        if (!is_dir($base_snapshots)) {
            wp_mkdir_p($base_snapshots);
            @file_put_contents($base_snapshots . '/.htaccess', "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>");
            @file_put_contents($base_snapshots . '/index.php', "<?php\nexit;\n");
        }

        $snapshot_id = 'snap_' . $slug . '_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3));
        $target_dir = $base_snapshots . '/' . $snapshot_id;

        if (!wp_mkdir_p($target_dir)) {
            return null;
        }

        // Copy existing directory recursively
        self::copy_dir_recursive($source_dir, $target_dir);

        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (!is_array($snapshots)) {
            $snapshots = [];
        }

        $snapshots[$snapshot_id] = [
            'id'          => $snapshot_id,
            'slug'        => $slug,
            'created_at'  => current_time('mysql'),
            'timestamp'   => time(),
            'path'        => $target_dir,
            'source_dir'  => $source_dir,
            'status'      => 'ready',
        ];

        // Maintain snapshot limit
        $settings = self::get_settings();
        $max = $settings['max_snapshots'] ?? 10;
        if (count($snapshots) > $max) {
            $oldest_id = array_key_first($snapshots);
            $oldest = $snapshots[$oldest_id];
            if (!empty($oldest['path']) && is_dir($oldest['path'])) {
                self::delete_dir_recursive($oldest['path']);
            }
            unset($snapshots[$oldest_id]);
        }

        update_option(self::OPTION_SNAPSHOTS, $snapshots);
        return $snapshot_id;
    }

    /**
     * Restore an installed plugin from a pre-update snapshot.
     *
     * @param string $snapshot_id
     * @return array
     */
    public static function rollback_snapshot(string $snapshot_id): array {
        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (empty($snapshots[$snapshot_id])) {
            return [
                'success' => false,
                'message' => 'Requested snapshot ID not found in Gatekeeper records.',
            ];
        }

        $snap = $snapshots[$snapshot_id];
        $snap_path = $snap['path'] ?? '';
        $slug = $snap['slug'] ?? '';
        $destination = WP_PLUGIN_DIR . '/' . $slug;

        if (!is_dir($snap_path)) {
            // Check migrated location
            $uploads = wp_upload_dir();
            $migrated = wp_normalize_path($uploads['basedir'] . '/wcp-security-scanner/gatekeeper/' . basename($snap_path));
            if (is_dir($migrated)) {
                $snap_path = $migrated;
            }
        }

        if (!is_dir($snap_path)) {
            return [
                'success' => false,
                'message' => 'Snapshot directory on disk has been purged or is inaccessible.',
            ];
        }

        // Overwrite installed plugin with snapshot files
        if (is_dir($destination)) {
            self::delete_dir_recursive($destination);
        }
        wp_mkdir_p($destination);
        self::copy_dir_recursive($snap_path, $destination);

        AuditLogger::log(
            'gatekeeper_rollback_executed',
            sprintf('WCP Gatekeeper successfully rolled back plugin "%s" to pre-update snapshot "%s".', $slug, $snapshot_id)
        );

        NotificationDispatcher::trigger('supply_chain_gatekeeper_rollback', [
            'title'   => __('Pre-Install Gatekeeper Rollback Executed', 'wcp-security-scanner'),
            'message' => sprintf(__('Plugin "%s" was successfully rolled back to pre-update snapshot "%s".', 'slug', $snapshot_id), $slug, $snapshot_id),
            'details' => [
                'plugin_slug' => $slug,
                'snapshot_id' => $snapshot_id,
                'action'      => 'Reverted to Verified Snapshot',
            ],
        ]);

        return [
            'success'     => true,
            'message'     => sprintf('Successfully rolled back "%s" to pre-update state from %s.', $slug, $snap['created_at']),
            'snapshot_id' => $snapshot_id,
            'slug'        => $slug,
        ];
    }

    /**
     * Get recorded Gatekeeper audit logs.
     *
     * @param int $limit
     * @return array
     */
    public static function get_logs(int $limit = 30): array {
        $logs = get_option(self::OPTION_LOGS, []);
        if (!is_array($logs)) {
            return [];
        }
        return array_slice($logs, 0, $limit);
    }

    /**
     * Clear recorded Gatekeeper audit logs.
     *
     * @return bool
     */
    public static function clear_logs(): bool {
        return update_option(self::OPTION_LOGS, []);
    }

    /**
     * Get stored rollback snapshots.
     *
     * @return array
     */
    public static function get_snapshots(): array {
        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (!is_array($snapshots)) {
            return [];
        }
        return array_values($snapshots);
    }

    /**
     * Record a gatekeeper log event.
     *
     * @param array $entry
     */
    private static function record_log(array $entry) {
        $logs = get_option(self::OPTION_LOGS, []);
        if (!is_array($logs)) {
            $logs = [];
        }
        array_unshift($logs, $entry);
        if (count($logs) > 60) {
            $logs = array_slice($logs, 0, 60);
        }
        update_option(self::OPTION_LOGS, $logs);
    }

    /**
     * Copy directory recursively.
     */
    private static function copy_dir_recursive(string $src, string $dst) {
        $dir = @opendir($src);
        if (!$dir) return;
        wp_mkdir_p($dst);

        while (false !== ($file = readdir($dir))) {
            if ($file !== '.' && $file !== '..') {
                if (is_dir($src . '/' . $file)) {
                    self::copy_dir_recursive($src . '/' . $file, $dst . '/' . $file);
                } else {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_copy -- Internal pre-update rollback snapshot
                    @copy($src . '/' . $file, $dst . '/' . $file);
                }
            }
        }
        closedir($dir);
    }

    /**
     * Delete directory recursively.
     */
    private static function delete_dir_recursive(string $dir) {
        if (!is_dir($dir)) return;
        $files = array_diff(scandir($dir) ?: [], ['.', '..']);
        foreach ($files as $file) {
            if (is_dir("$dir/$file")) {
                self::delete_dir_recursive("$dir/$file");
            } else {
                wp_delete_file("$dir/$file");
            }
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Fallback directory cleanup for internal rollback snapshot
        @rmdir($dir);
    }
}
