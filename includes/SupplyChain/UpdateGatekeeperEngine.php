<?php
namespace WcpScanner\SupplyChain;

use WcpScanner\System\AuditLogger;
use WcpScanner\Notifications\NotificationDispatcher;

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
    const LOCK_OPTION_KEY  = 'wcp_atomic_upgrade_lock';
    const LOCK_TTL         = 180;

    /**
     * Initialize Gatekeeper hooks.
     */
    public static function init() {
        add_filter('upgrader_pre_install', [__CLASS__, 'acquire_upgrade_lock'], 10, 2);
        add_filter('upgrader_source_selection', [__CLASS__, 'inspect_unpacked_source'], 20, 4);
        add_action('upgrader_process_complete', [__CLASS__, 'release_lock_and_rebaseline'], 10, 2);
    }

    /**
     * Acquire atomic upgrade lock before package installation begins.
     *
     * @param bool|\WP_Error $returnStatus Current status.
     * @param array         $hook_extra   Upgrade context.
     * @return bool|\WP_Error
     */
    public static function acquire_upgrade_lock($returnStatus, array $hook_extra = []) {
        if (is_wp_error($returnStatus)) {
            return $returnStatus;
        }

        $target = (string) ($hook_extra['plugin'] ?? ($hook_extra['theme'] ?? 'core'));
        $client_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        $lock_payload = [
            'target'     => $target,
            'started_at' => time(),
            'expires_at' => time() + self::LOCK_TTL,
            'user_id'    => function_exists('get_current_user_id') ? get_current_user_id() : 0,
            'ip'         => $client_ip,
        ];

        update_option(self::LOCK_OPTION_KEY, $lock_payload, false);

        return $returnStatus;
    }

    /**
     * Release lock and trigger FIM re-baselining once upgrade finishes.
     *
     * @param object $upgrader   Upgrader instance.
     * @param array  $hook_extra Upgrade details.
     */
    public static function release_lock_and_rebaseline($upgrader, array $hook_extra = []): void {
        self::release_upgrade_lock();

        if (class_exists('\\WcpScanner\\Integrity\\FileIntegrityMonitor') && method_exists('\\WcpScanner\\Integrity\\FileIntegrityMonitor', 'schedule_immediate_baseline_sync')) {
            \WcpScanner\Integrity\FileIntegrityMonitor::schedule_immediate_baseline_sync($hook_extra);
        }
    }

    /**
     * Release atomic upgrade lock.
     */
    public static function release_upgrade_lock(): void {
        delete_option(self::LOCK_OPTION_KEY);
    }

    /**
     * Check if an atomic upgrade window is currently active.
     *
     * @return array|null
     */
    public static function get_active_lock(): ?array {
        $lock = get_option(self::LOCK_OPTION_KEY);
        if (!is_array($lock) || empty($lock['expires_at'])) {
            return null;
        }

        if (time() > (int) $lock['expires_at']) {
            delete_option(self::LOCK_OPTION_KEY);
            return null;
        }

        return $lock;
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

        // Audit Trail: Log Update Gatekeeper settings change
        $diff = \WcpScanner\System\SettingsManager::compute_settings_diff($current, $updated);
        if (!empty($diff) && class_exists('\WcpScanner\System\WcpActivityLogger')) {
            \WcpScanner\System\WcpActivityLogger::notice(
                'gatekeeper_settings_updated',
                'settings',
                [
                    'changed_count' => count($diff),
                    'description'   => sprintf('Supply-Chain Gatekeeper policy updated (%d parameter(s)).', count($diff)),
                    'module'        => 'update_gatekeeper',
                    'diff'          => $diff,
                ]
            );
        }

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

        // Pre-Move Path Traversal, Null Byte, Symlink & Webshell Security Audit
        $real_source = realpath($source);
        if (false !== $real_source && is_dir($real_source)) {
            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($real_source, \FilesystemIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($iterator as $item) {
                    $item_path = $item->getPathname();

                    // 1. Block Zip-Slip / Path Traversal & Null Bytes
                    if (str_contains($item_path, "\0") || str_contains($item_path, '..')) {
                        self::release_upgrade_lock();
                        return new \WP_Error('wcp_upgrade_zip_slip', __('Blocked package containing path traversal sequences or null bytes.', 'wcp-security-scanner'));
                    }

                    // 2. Block External Symlinks inside packages
                    if ($item->isLink()) {
                        $link_target = @readlink($item_path);
                        $real_target = $link_target ? realpath(dirname($item_path) . DIRECTORY_SEPARATOR . $link_target) : false;

                        if (false === $real_target || !str_starts_with($real_target, $real_source)) {
                            self::release_upgrade_lock();
                            return new \WP_Error(
                                'wcp_upgrade_malicious_symlink',
                                sprintf(
                                    /* translators: %s: symlink name */
                                    __('Blocked package containing external symlink: %s', 'wcp-security-scanner'),
                                    esc_html(basename($item_path))
                                )
                            );
                        }
                    }

                    // 3. Audit extracted PHP files for high-confidence webshell markers
                    if ($item->isFile() && preg_match('/\.(?:php[0-9]?|phtml|phar)$/i', $item->getFilename())) {
                        $head = (string) @file_get_contents($item_path, false, null, 0, 65536);
                        if (preg_match('/(?:eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|\$_POST|\$_REQUEST|\$_GET)|FilesMan|WSO\s+[0-9.]+)/i', $head)) {
                            self::release_upgrade_lock();
                            return new \WP_Error(
                                'wcp_upgrade_backdoor_detected',
                                sprintf(
                                    /* translators: %s: file name */
                                    __('Blocked package containing backdoor signature in %s.', 'wcp-security-scanner'),
                                    esc_html(basename($item_path))
                                )
                            );
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Proceed with delta analysis if directory iteration encountered read permission issues
            }
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
                    /* translators: 1%$s: plugin slug, 2%$d: risk score out of 100 */
                    'message' => sprintf(__('Hostile update intercepted for "%1$s" (Risk Score: %2$d/100). Production files protected.', 'wcp-security-scanner'), $folder_name, $analysis['score']),
                    'details' => [
                        'plugin_slug'     => $folder_name,
                        'risk_score'      => $analysis['score'] . '/100',
                        'findings_sample' => !empty($analysis['findings'][0]['title']) ? $analysis['findings'][0]['title'] : 'Critical anomalies detected',
                    ],
                ]);

                $reason = !empty($analysis['findings'][0]['title'])
                    ? $analysis['findings'][0]['title'] . ' (' . ($analysis['findings'][0]['file'] ?? '') . ')'
                    : 'Critical supply-chain security anomaly detected.';

                // Log incident to centralized WAF Incident Stream
                if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
                    \WcpScanner\Firewall\FirewallEngine::log_incident([
                        'id'          => 'WAF-SUPPLY-CHAIN-GATEKEEPER',
                        'name'        => 'Supply-Chain Update Gatekeeper Intercept',
                        'category'    => 'Supply-Chain Defense',
                        'description' => sprintf('Update of plugin "%s" blocked due to critical supply-chain security risk: %s', esc_html($folder_name), esc_html($reason)),
                        'match_type'  => 'Supply-Chain Risk',
                        'match_value' => $folder_name,
                        'payload'     => sprintf('Plugin: %s | Risk: %d/100 | Finding: %s', $folder_name, $analysis['score'], substr($reason, 0, 150)),
                    ], 'blocked');
                }

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

                $reason = !empty($analysis['findings'][0]['title'])
                    ? $analysis['findings'][0]['title'] . ' (' . ($analysis['findings'][0]['file'] ?? '') . ')'
                    : 'Critical security risk patterns detected';

                // Log incident to centralized WAF Incident Stream
                if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
                    \WcpScanner\Firewall\FirewallEngine::log_incident([
                        'id'          => 'WAF-SUPPLY-CHAIN-GATEKEEPER',
                        'name'        => 'Supply-Chain Update Gatekeeper Intercept',
                        'category'    => 'Supply-Chain Defense',
                        'description' => sprintf('Installation of plugin "%s" blocked due to critical security risk patterns: %s', esc_html($folder_name), esc_html($reason)),
                        'match_type'  => 'Supply-Chain Risk',
                        'match_value' => $folder_name,
                        'payload'     => sprintf('Plugin: %s | Risk: %d/100 | Finding: %s', $folder_name, $analysis['score'], substr($reason, 0, 150)),
                    ], 'blocked');
                }

                NotificationDispatcher::trigger('supply_chain_gatekeeper_blocked', [
                    'title'   => __('Hostile Plugin Installation Intercepted by Gatekeeper', 'wcp-security-scanner'),
                    /* translators: 1%$s: plugin slug, 2%$d: risk score out of 100 */
                    'message' => sprintf(__('Hostile installation intercepted for "%1$s" (Risk Score: %2$d/100). System protected.', 'wcp-security-scanner'), $folder_name, $analysis['score']),
                    'details' => [
                        'plugin_slug'     => $folder_name,
                        'risk_score'      => $analysis['score'] . '/100',
                        'findings_sample' => !empty($analysis['findings'][0]['title']) ? $analysis['findings'][0]['title'] : 'Critical anomalies detected',
                    ],
                ]);

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
            @file_put_contents($base_snapshots . '/index.php', "<?php\n// Silence is golden.\n");
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
            /* translators: 1%$s: plugin slug, 2%$s: snapshot identifier */
            'message' => sprintf(__('Plugin "%1$s" was successfully rolled back to pre-update snapshot "%2$s".', 'wcp-security-scanner'), $slug, $snapshot_id),
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
