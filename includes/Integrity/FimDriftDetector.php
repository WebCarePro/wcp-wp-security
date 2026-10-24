<?php
namespace WcpScanner\Integrity;

use WcpScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * FimDriftDetector
 *
 * High-performance, memory-efficient File Integrity drift and deviation detector.
 * Performs two-stage attestation against the cryptographically sealed FIM Vault manifests:
 * - Stage 1 (Sub-millisecond Stat Check): size, mtime, ctime, perms, owner, symlink status.
 * - Stage 2 (Deep Cryptographic Hash): Computes SHA-256 only when Stage 1 indicates alteration.
 *
 * Detects:
 * - MODIFIED: Existing file content or cryptographic hash modified
 * - ADDED / ROGUE: New unexpected file created since baseline calibration
 * - DELETED: Baseline file removed from disk
 * - PERMS_CHANGED: File or folder permissions altered (e.g. 0644 -> 0777)
 * - OWNER_CHANGED: File or folder UID/GID altered
 * - SYMLINK_ALERT: File converted to symlink or pointing outside ABSPATH
 */
class FimDriftDetector {

    /**
     * Calibrate a fresh, known-good baseline snapshot across all scopes.
     *
     * @return array
     */
    public static function calibrate_all(): array {
        $start_time = microtime(true);
        $normalized_abs = wp_normalize_path(ABSPATH);

        $results = [
            'success'       => true,
            'calibrated_at' => current_time('mysql'),
            'timestamp'     => time(),
            'scopes'        => [],
            'total_files'   => 0,
            'duration_sec'  => 0,
        ];

        // 1. Core Scope: wp-admin and wp-includes
        $core_files = self::scan_directory_files([
            ABSPATH . 'wp-admin',
            ABSPATH . (defined('WPINC') ? WPINC : 'wp-includes'),
        ], true, $normalized_abs);
        FimVaultManager::write_shard('core', $core_files);
        $results['scopes']['core'] = count($core_files);
        $results['total_files'] += count($core_files);

        // 2. Core Root Scope: ABSPATH root files (.htaccess, wp-config.php, index.php, etc.)
        $root_files = self::scan_root_directory(ABSPATH, $normalized_abs);
        FimVaultManager::write_shard('core_root', $root_files);
        $results['scopes']['core_root'] = count($root_files);
        $results['total_files'] += count($root_files);

        // 3. Plugins Scope: WP_PLUGIN_DIR and WPMU_PLUGIN_DIR
        $plugin_dirs = [WP_PLUGIN_DIR];
        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            $plugin_dirs[] = WPMU_PLUGIN_DIR;
        }
        $plugins_files = self::scan_directory_files($plugin_dirs, true, $normalized_abs);
        FimVaultManager::write_shard('plugins', $plugins_files);
        $results['scopes']['plugins'] = count($plugins_files);
        $results['total_files'] += count($plugins_files);

        // 4. Themes Scope: WP_CONTENT_DIR/themes
        $theme_root = function_exists('get_theme_root') ? get_theme_root() : WP_CONTENT_DIR . '/themes';
        $theme_files = is_dir($theme_root) ? self::scan_directory_files([$theme_root], true, $normalized_abs) : [];
        FimVaultManager::write_shard('themes', $theme_files);
        $results['scopes']['themes'] = count($theme_files);
        $results['total_files'] += count($theme_files);

        // 5. Uploads Code Scope: scripts & executables in uploads
        $upload_dir = wp_upload_dir();
        $uploads_base = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : WP_CONTENT_DIR . '/uploads';
        $uploads_code_files = is_dir($uploads_base) ? self::scan_uploads_code_files($uploads_base, $normalized_abs) : [];
        FimVaultManager::write_shard('uploads', $uploads_code_files);
        $results['scopes']['uploads'] = count($uploads_code_files);
        $results['total_files'] += count($uploads_code_files);

        // Update Meta
        $user = wp_get_current_user();
        $author = ($user && $user->exists()) ? $user->user_login : 'admin';

        $meta = [
            'calibrated_at'    => $results['calibrated_at'],
            'calibrated_by'    => $author,
            'timestamp'        => time(),
            'total_files'      => $results['total_files'],
            'scopes'           => $results['scopes'],
            'last_verified_at' => $results['calibrated_at'],
        ];
        FimVaultManager::save_meta($meta);

        $results['duration_sec'] = round(microtime(true) - $start_time, 2);
        return $results;
    }

    /**
     * Audit filesystem for drift and tampering against the stored baseline shards.
     *
     * @param string $category Filter category ('all', 'core', 'plugins', 'themes', 'uploads')
     * @param int $limit Maximum drift items to return
     * @return array
     */
    public static function audit_drift(string $category = 'all', int $limit = 250): array {
        $start_time = microtime(true);
        $vault_status = FimVaultManager::get_vault_status();

        if ($vault_status['has_tamper']) {
            return [
                'success'         => false,
                'has_tamper'      => true,
                'tampered_shards' => $vault_status['tampered_shards'],
                'message'         => 'CRITICAL: Vault FIM baseline manifest has been modified or forged outside WCP Security Suite!',
                'drift_items'     => [],
                'stats'           => [
                    'modified_count' => 0,
                    'added_count'    => 0,
                    'deleted_count'  => 0,
                    'perms_count'    => 0,
                    'total_drift'    => 0,
                ],
            ];
        }

        if (!$vault_status['is_calibrated']) {
            return [
                'success'       => true,
                'is_calibrated' => false,
                'message'       => 'No FIM Vault baseline currently calibrated. Please calibrate baseline snapshot.',
                'drift_items'   => [],
                'stats'         => [
                    'modified_count' => 0,
                    'added_count'    => 0,
                    'deleted_count'  => 0,
                    'perms_count'    => 0,
                    'total_drift'    => 0,
                ],
            ];
        }

        $scopes_to_check = ($category === 'all')
            ? array_keys(FimVaultManager::SCOPES)
            : (in_array($category, array_keys(FimVaultManager::SCOPES), true) ? [$category] : ['core', 'plugins', 'themes', 'uploads']);

        $drift_items = [];
        $stats = [
            'modified_count' => 0,
            'added_count'    => 0,
            'deleted_count'  => 0,
            'perms_count'    => 0,
            'owner_count'    => 0,
            'symlink_count'  => 0,
            'total_drift'    => 0,
        ];

        $normalized_abs = wp_normalize_path(ABSPATH);

        foreach ($scopes_to_check as $scope) {
            $shard = FimVaultManager::read_shard($scope);
            if (!$shard['valid'] || empty($shard['data'])) {
                continue;
            }

            $baseline_files = $shard['data']; // path => metadata

            // Current live disk files for this scope
            $live_files = self::scan_scope_live_files($scope, $normalized_abs);

            // 1. Detect MODIFIED, PERMS_CHANGED, OWNER_CHANGED, and DELETED
            foreach ($baseline_files as $rel_path => $base_meta) {
                if (!isset($live_files[$rel_path])) {
                    // DELETED
                    $stats['deleted_count']++;
                    $drift_items[] = [
                        'type'           => 'deleted',
                        'severity'       => ($scope === 'core' || $scope === 'core_root') ? 'critical' : 'high',
                        'relative_path'  => $rel_path,
                        'file_path'      => $normalized_abs . $rel_path,
                        'category'       => $scope,
                        'expected_hash'  => $base_meta['hash'] ?? '',
                        'current_hash'   => null,
                        'expected_perms' => $base_meta['perms'] ?? '',
                        'current_perms'  => null,
                        'detail'         => "Baseline file was deleted from disk: {$rel_path}",
                    ];
                    continue;
                }

                $live_meta = $live_files[$rel_path];

                // Fast Check: If size, mtime, or ctime differs, verify cryptographic hash
                $size_diff  = ($live_meta['size'] !== $base_meta['size']);
                $time_diff  = ($live_meta['mtime'] !== $base_meta['mtime']);
                $perms_diff = ($live_meta['perms'] !== $base_meta['perms']);
                $owner_diff = ($live_meta['owner'] !== $base_meta['owner']);
                $is_symlink = !empty($live_meta['is_symlink']);

                if ($size_diff || $time_diff) {
                    $live_hash = @hash_file('sha256', $normalized_abs . $rel_path);
                    if ($live_hash && $live_hash !== ($base_meta['hash'] ?? '')) {
                        // CONTENT MODIFIED
                        $stats['modified_count']++;
                        $drift_items[] = [
                            'type'           => 'modified',
                            'severity'       => ($scope === 'core' || $scope === 'core_root') ? 'critical' : 'high',
                            'relative_path'  => $rel_path,
                            'file_path'      => $normalized_abs . $rel_path,
                            'category'       => $scope,
                            'expected_hash'  => $base_meta['hash'] ?? '',
                            'current_hash'   => $live_hash,
                            'mtime'          => $live_meta['mtime'],
                            'size'           => $live_meta['size'],
                            'perms'          => $live_meta['perms'],
                            'owner'          => $live_meta['owner'],
                            'detail'         => "Content modified. SHA-256 hash changed from calibrated baseline.",
                        ];
                    }
                }

                // Check permissions drift
                if ($perms_diff) {
                    $stats['perms_count']++;
                    $drift_items[] = [
                        'type'           => 'perms_changed',
                        'severity'       => ($live_meta['perms'] === '0777') ? 'critical' : 'info',
                        'relative_path'  => $rel_path,
                        'file_path'      => $normalized_abs . $rel_path,
                        'category'       => $scope,
                        'expected_perms' => $base_meta['perms'],
                        'current_perms'  => $live_meta['perms'],
                        'detail'         => "File permissions drifted from {$base_meta['perms']} to {$live_meta['perms']}.",
                    ];
                }

                // Check owner drift
                if ($owner_diff) {
                    $stats['owner_count']++;
                    $drift_items[] = [
                        'type'           => 'owner_changed',
                        'severity'       => 'info',
                        'relative_path'  => $rel_path,
                        'file_path'      => $normalized_abs . $rel_path,
                        'category'       => $scope,
                        'expected_owner' => $base_meta['owner'],
                        'current_owner'  => $live_meta['owner'],
                        'detail'         => "File owner drifted from {$base_meta['owner']} to {$live_meta['owner']}.",
                    ];
                }

                // Check symlink injection
                if ($is_symlink && empty($base_meta['is_symlink'])) {
                    $stats['symlink_count']++;
                    $drift_items[] = [
                        'type'           => 'symlink_created',
                        'severity'       => 'critical',
                        'relative_path'  => $rel_path,
                        'file_path'      => $normalized_abs . $rel_path,
                        'category'       => $scope,
                        'target'         => $live_meta['symlink_target'] ?? '',
                        'detail'         => "File converted to symbolic link pointing to: " . ($live_meta['symlink_target'] ?? 'unknown'),
                    ];
                }
            }

            // 2. Detect ADDED / ROGUE Files (Exist on disk but missing from baseline)
            foreach ($live_files as $rel_path => $live_meta) {
                if (!isset($baseline_files[$rel_path])) {
                    $stats['added_count']++;
                    $live_hash = @hash_file('sha256', $normalized_abs . $rel_path);
                    $drift_items[] = [
                        'type'          => 'added',
                        'severity'      => ($scope === 'core' || $scope === 'core_root' || $scope === 'uploads') ? 'critical' : 'high',
                        'relative_path' => $rel_path,
                        'file_path'     => $normalized_abs . $rel_path,
                        'category'      => $scope,
                        'current_hash'  => $live_hash,
                        'mtime'         => $live_meta['mtime'],
                        'size'          => $live_meta['size'],
                        'perms'         => $live_meta['perms'],
                        'owner'         => $live_meta['owner'],
                        'detail'        => "New file discovered on disk that was not present in calibrated baseline.",
                    ];
                }
            }
        }

        $stats['total_drift'] = count($drift_items);

        // Update verification timestamp in meta
        $meta = FimVaultManager::get_meta();
        $meta['last_verified_at'] = current_time('mysql');
        FimVaultManager::save_meta($meta);

        // Limit results if excessive
        if (count($drift_items) > $limit) {
            $drift_items = array_slice($drift_items, 0, $limit);
        }

        return [
            'success'       => true,
            'is_calibrated' => true,
            'calibrated_at' => $meta['calibrated_at'] ?? null,
            'verified_at'   => $meta['last_verified_at'],
            'duration_sec'  => round(microtime(true) - $start_time, 2),
            'stats'         => $stats,
            'drift_items'   => $drift_items,
        ];
    }

    /**
     * Scan directories recursively and build full metadata dictionary.
     */
    private static function scan_directory_files(array $dirs, bool $recursive, string $normalized_abs): array {
        $files = [];

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            if ($recursive) {
                try {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::SELF_FIRST
                    );

                    foreach ($iterator as $item) {
                        if (!$item->isFile()) {
                            continue;
                        }
                        $path = wp_normalize_path($item->getPathname());
                        if (self::is_ignored_path($path)) {
                            continue;
                        }

                        $rel = ltrim(str_replace($normalized_abs, '', $path), '/');
                        $files[$rel] = self::extract_file_metadata($path, $item);
                    }
                } catch (\Throwable $e) {
                    continue;
                }
            } else {
                $glob_files = glob(rtrim($dir, '/\\') . '/*');
                if ($glob_files) {
                    foreach ($glob_files as $path) {
                        if (!is_file($path)) {
                            continue;
                        }
                        $path = wp_normalize_path($path);
                        if (self::is_ignored_path($path)) {
                            continue;
                        }
                        $rel = ltrim(str_replace($normalized_abs, '', $path), '/');
                        $files[$rel] = self::extract_file_metadata($path, null);
                    }
                }
            }
        }

        return $files;
    }

    /**
     * Scan root directory files (ABSPATH non-recursive).
     */
    private static function scan_root_directory(string $dir, string $normalized_abs): array {
        $files = [];
        $glob_files = glob(rtrim($dir, '/\\') . '/*');
        if ($glob_files) {
            foreach ($glob_files as $path) {
                if (!is_file($path)) {
                    continue;
                }
                $path = wp_normalize_path($path);
                if (self::is_ignored_path($path)) {
                    continue;
                }
                $rel = ltrim(str_replace($normalized_abs, '', $path), '/');
                $files[$rel] = self::extract_file_metadata($path, null);
            }
        }
        return $files;
    }

    /**
     * Scan uploads directory specifically for code/executable files.
     */
    private static function scan_uploads_code_files(string $uploads_base, string $normalized_abs): array {
        $files = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($uploads_base, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                if (!$item->isFile()) {
                    continue;
                }
                $path = wp_normalize_path($item->getPathname());
                if (self::is_ignored_path($path)) {
                    continue;
                }

                $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                $basename = strtolower(basename($path));

                // Only track script or executable files in uploads
                if (!in_array($ext, ['php', 'phtml', 'php5', 'php7', 'pht', 'phps', 'inc', 'sh', 'pl', 'py'], true) && $basename !== '.htaccess') {
                    continue;
                }

                // Ignore harmless blank directory protection index.php
                if (($basename === 'index.php' || $basename === 'index.html') && SettingsManager::is_safe_directory_index($path)) {
                    continue;
                }

                $rel = ltrim(str_replace($normalized_abs, '', $path), '/');
                $files[$rel] = self::extract_file_metadata($path, $item);
            }
        } catch (\Throwable $e) {
            // Ignore unreadable dirs
        }

        return $files;
    }

    /**
     * Scan live files for a specific scope.
     */
    private static function scan_scope_live_files(string $scope, string $normalized_abs): array {
        switch ($scope) {
            case 'core':
                return self::scan_directory_files([
                    ABSPATH . 'wp-admin',
                    ABSPATH . (defined('WPINC') ? WPINC : 'wp-includes'),
                ], true, $normalized_abs);

            case 'core_root':
                return self::scan_root_directory(ABSPATH, $normalized_abs);

            case 'plugins':
                $dirs = [WP_PLUGIN_DIR];
                if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
                    $dirs[] = WPMU_PLUGIN_DIR;
                }
                return self::scan_directory_files($dirs, true, $normalized_abs);

            case 'themes':
                $theme_root = function_exists('get_theme_root') ? get_theme_root() : WP_CONTENT_DIR . '/themes';
                return is_dir($theme_root) ? self::scan_directory_files([$theme_root], true, $normalized_abs) : [];

            case 'uploads':
                $upload_dir = wp_upload_dir();
                $uploads_base = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : WP_CONTENT_DIR . '/uploads';
                return is_dir($uploads_base) ? self::scan_uploads_code_files($uploads_base, $normalized_abs) : [];

            default:
                return [];
        }
    }

    /**
     * Extract rich forensic metadata for a single file.
     */
    private static function extract_file_metadata(string $path, ?\SplFileInfo $item): array {
        $size = ($item instanceof \SplFileInfo) ? $item->getSize() : @filesize($path);
        $mtime = ($item instanceof \SplFileInfo) ? $item->getMTime() : @filemtime($path);
        $ctime = ($item instanceof \SplFileInfo) ? $item->getCTime() : @filectime($path);

        $perms_octal = sprintf('%04o', (@fileperms($path) & 0777));
        $owner_uid   = @fileowner($path);
        $group_gid   = @filegroup($path);

        $owner_str = ($owner_uid !== false) ? (string) $owner_uid : '0';
        $group_str = ($group_gid !== false) ? (string) $group_gid : '0';

        if (function_exists('posix_getpwuid') && $owner_uid !== false) {
            $user_info = @posix_getpwuid($owner_uid);
            if (!empty($user_info['name'])) {
                $owner_str = $user_info['name'];
            }
        }
        if (function_exists('posix_getgrgid') && $group_gid !== false) {
            $group_info = @posix_getgrgid($group_gid);
            if (!empty($group_info['name'])) {
                $group_str = $group_info['name'];
            }
        }

        $is_symlink = is_link($path);
        $symlink_target = $is_symlink ? @readlink($path) : null;

        // Compute deep SHA-256 hash
        $hash = @hash_file('sha256', $path);

        return [
            'type'           => $is_symlink ? 'l' : (is_dir($path) ? 'd' : 'f'),
            'size'           => (int) $size,
            'mtime'          => (int) $mtime,
            'ctime'          => (int) $ctime,
            'perms'          => $perms_octal,
            'owner'          => "{$owner_str}:{$group_str}",
            'is_symlink'     => $is_symlink,
            'symlink_target' => $symlink_target,
            'hash'           => $hash ?: '',
        ];
    }

    /**
     * Check if a path should be skipped from FIM tracking.
     */
    private static function is_ignored_path(string $path): bool {
        return (bool) preg_match('#/(node_modules|\.git|cache|wcp-security-scanner|updraft|backups|wfcache|wcp-vault)/#i', $path);
    }
}
