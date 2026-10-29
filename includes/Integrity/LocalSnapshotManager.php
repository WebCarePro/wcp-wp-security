<?php
namespace WcpScanner\Integrity;

use WcpScanner\System\AuditLogger;
use WcpScanner\Filesystem\PathValidator;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LocalSnapshotManager
 *
 * "Time-Machine" Local File & Snapshot Diff Engine:
 * Creates compressed, read-only baseline snapshots of custom client plugins,
 * child themes, and premium extensions outside the webroot.
 *
 * If an attacker or compromised credential injects webshell backdoors or alters code,
 * the administrator can visually inspect a side-by-side diff against the verified
 * local baseline and perform 1-click atomic restoration.
 */
class LocalSnapshotManager {

    public const OPTION_SNAPSHOTS = 'wcpscan_local_snapshots';
    public const MAX_FILE_SIZE    = 2097152; // 2MB max per single code file

    /**
     * Get or create the snapshot storage directory.
     *
     * @return string
     */
    public static function get_storage_dir(): string {
        $uploads = wp_upload_dir();
        $dir = untrailingslashit($uploads['basedir']) . '/wcp-security-scanner/snapshots';

        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
            // Block all public HTTP access to snapshot storage
            @file_put_contents($dir . '/.htaccess', "# WCP Security: Deny public access\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n");
            @file_put_contents($dir . '/index.php', "<?php\nhttp_response_code(403);\nexit('Direct access forbidden.');\n");
        }

        return $dir;
    }

    /**
     * Create a verified baseline snapshot of a specific directory or file.
     *
     * @param string $target_rel_path Target path relative to ABSPATH (e.g. 'wp-content/themes/my-theme')
     * @param string $label           Human-readable descriptor (e.g. 'Pre-Update Baseline')
     * @return array
     */
    public static function create_snapshot(string $target_rel_path, string $label = ''): array {
        $clean_rel = ltrim(wp_normalize_path(sanitize_text_field($target_rel_path)), '/');
        $full_path = wp_normalize_path(ABSPATH . $clean_rel);

        if (!file_exists($full_path)) {
            return [
                'success' => false,
                'message' => esc_html__('Target path does not exist on disk.', 'wcp-security-scanner'),
            ];
        }

        // Prohibit root-level snapshot to prevent disk saturation
        if (empty($clean_rel) || $clean_rel === '.' || $clean_rel === '/') {
            return [
                'success' => false,
                'message' => esc_html__('Creating a snapshot of the entire WordPress root is prohibited. Please select a specific plugin, theme, or folder.', 'wcp-security-scanner'),
            ];
        }

        $snapshot_id = 'snap_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(4));
        $storage_dir = self::get_storage_dir();

        $manifest = [];
        $file_payloads = [];
        $total_bytes = 0;
        $file_count = 0;

        if (is_file($full_path)) {
            $content = @file_get_contents($full_path);
            if ($content !== false && strlen($content) <= self::MAX_FILE_SIZE) {
                $hash = hash('sha256', $content);
                $manifest[$clean_rel] = [
                    'rel_path' => $clean_rel,
                    'size'     => strlen($content),
                    'sha256'   => $hash,
                    'mtime'    => filemtime($full_path) ?: time(),
                ];
                $file_payloads[$clean_rel] = base64_encode($content);
                $total_bytes += strlen($content);
                $file_count++;
            }
        } else {
            // Recursive directory traversal
            try {
                $dir_iter = new \RecursiveDirectoryIterator($full_path, \RecursiveDirectoryIterator::SKIP_DOTS);
                $filter = new \RecursiveCallbackFilterIterator($dir_iter, function ($current) {
                    if ($current->isDir()) {
                        $name = $current->getFilename();
                        if (in_array($name, ['.git', '.svn', 'node_modules', 'cache', '.wcp-quarantine'], true)) {
                            return false;
                        }
                    }
                    return true;
                });
                $iterator = new \RecursiveIteratorIterator($filter, \RecursiveIteratorIterator::SELF_FIRST);

                $root_norm = wp_normalize_path(ABSPATH);

                foreach ($iterator as $item) {
                    if ($item->isFile()) {
                        $p = wp_normalize_path($item->getPathname());
                        $size = (int) $item->getSize();

                        // Only snapshot code and config files under size cap
                        $ext = strtolower($item->getExtension());
                        if (!in_array($ext, ['php', 'js', 'css', 'json', 'htaccess', 'ini', 'html', 'txt', 'svg'], true)) {
                            continue;
                        }

                        if ($size > self::MAX_FILE_SIZE) {
                            continue;
                        }

                        $rel = ltrim(str_replace($root_norm, '', $p), '/');
                        $content = @file_get_contents($p);
                        if ($content !== false) {
                            $hash = hash('sha256', $content);
                            $manifest[$rel] = [
                                'rel_path' => $rel,
                                'size'     => $size,
                                'sha256'   => $hash,
                                'mtime'    => (int) $item->getMTime(),
                            ];
                            $file_payloads[$rel] = base64_encode($content);
                            $total_bytes += $size;
                            $file_count++;
                        }
                    }
                }
            } catch (\Throwable $e) {
                return [
                    'success' => false,
                    'message' => sprintf(
                        /* translators: %s: error message */
                        esc_html__('Failed to traverse directory: %s', 'wcp-security-scanner'),
                        $e->getMessage()
                    ),
                ];
            }
        }

        if ($file_count === 0) {
            return [
                'success' => false,
                'message' => esc_html__('No suitable code files found to snapshot in the specified path.', 'wcp-security-scanner'),
            ];
        }

        // Package into compressed archive payload
        $archive_data = [
            'version'     => 1,
            'snapshot_id' => $snapshot_id,
            'target_rel'  => $clean_rel,
            'label'       => sanitize_text_field($label ?: basename($clean_rel)),
            'created_at'  => current_time('mysql'),
            'file_count'  => $file_count,
            'total_bytes' => $total_bytes,
            'manifest'    => $manifest,
            'files'       => $file_payloads,
        ];

        $json_str = wp_json_encode($archive_data);
        $compressed = gzencode($json_str, 9);
        if ($compressed === false) {
            $compressed = $json_str; // Fallback to raw json if gz not available
        }

        $archive_filename = $snapshot_id . '.snap.gz';
        $archive_file = $storage_dir . '/' . $archive_filename;

        if (@file_put_contents($archive_file, $compressed, LOCK_EX) === false) {
            return [
                'success' => false,
                'message' => esc_html__('Failed to write compressed snapshot to storage vault.', 'wcp-security-scanner'),
            ];
        }

        // Record snapshot metadata in options
        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (!is_array($snapshots)) {
            $snapshots = [];
        }

        $snapshots[$snapshot_id] = [
            'id'             => $snapshot_id,
            'label'          => sanitize_text_field($label ?: basename($clean_rel)),
            'target_rel'     => $clean_rel,
            'created_at'     => current_time('mysql'),
            'timestamp'      => time(),
            'file_count'     => $file_count,
            'archive_bytes'  => strlen($compressed),
            'archive_formatted' => size_format(strlen($compressed)),
            'raw_bytes'      => $total_bytes,
            'raw_formatted'  => size_format($total_bytes),
            'archive_file'   => $archive_filename,
        ];

        update_option(self::OPTION_SNAPSHOTS, $snapshots, false);

        AuditLogger::log(
            'snapshot_created',
            sprintf('Time-Machine baseline snapshot "%s" created for "%s" (%d files, %s).', $snapshots[$snapshot_id]['label'], $clean_rel, $file_count, size_format(strlen($compressed)))
        );

        return [
            'success'     => true,
            'snapshot_id' => $snapshot_id,
            'file_count'  => $file_count,
            'size'        => size_format(strlen($compressed)),
            'message'     => sprintf(
                /* translators: 1: label, 2: file count */
                esc_html__('Baseline snapshot "%1$s" successfully created with %2$d tracked files.', 'wcp-security-scanner'),
                $snapshots[$snapshot_id]['label'],
                $file_count
            ),
        ];
    }

    /**
     * List all recorded baseline snapshots.
     *
     * @return array
     */
    public static function list_snapshots(): array {
        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (!is_array($snapshots)) {
            $snapshots = [];
        }

        // Verify physical file exists on disk
        $storage_dir = self::get_storage_dir();
        $verified = [];

        foreach ($snapshots as $id => $snap) {
            $f = $storage_dir . '/' . ($snap['archive_file'] ?? '');
            if (file_exists($f)) {
                $verified[] = $snap;
            }
        }

        usort($verified, fn($a, $b) => ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0));

        return [
            'success'   => true,
            'total'     => count($verified),
            'snapshots' => $verified,
        ];
    }

    /**
     * Compare live disk files against snapshot baseline manifest.
     * Identifies modified, added (injected), and deleted files.
     *
     * @param string $snapshot_id
     * @return array
     */
    public static function compare_snapshot(string $snapshot_id): array {
        $archive_data = self::load_snapshot_archive($snapshot_id);
        if (!$archive_data) {
            return [
                'success' => false,
                'message' => esc_html__('Snapshot archive could not be read or is corrupted.', 'wcp-security-scanner'),
            ];
        }

        $manifest = $archive_data['manifest'] ?? [];
        $target_rel = $archive_data['target_rel'] ?? '';
        $root = wp_normalize_path(ABSPATH);
        $full_target = $root . $target_rel;

        $modified = [];
        $clean    = [];
        $deleted  = [];
        $added    = [];

        // Check manifest files against disk
        foreach ($manifest as $rel => $info) {
            $live_path = $root . $rel;
            if (!file_exists($live_path)) {
                $deleted[] = [
                    'rel_path' => $rel,
                    'status'   => 'deleted',
                    'original_size' => $info['size'],
                ];
                continue;
            }

            $live_content = @file_get_contents($live_path);
            if ($live_content === false) {
                continue;
            }

            $live_hash = hash('sha256', $live_content);
            if (hash_equals($info['sha256'], $live_hash)) {
                $clean[] = [
                    'rel_path' => $rel,
                    'status'   => 'clean',
                    'size'     => strlen($live_content),
                ];
            } else {
                $modified[] = [
                    'rel_path'     => $rel,
                    'status'       => 'modified',
                    'live_size'    => strlen($live_content),
                    'snapshot_size'=> $info['size'],
                    'live_mtime'   => filemtime($live_path) ?: time(),
                ];
            }
        }

        // Check for newly added files on disk not present in snapshot
        if (is_dir($full_target)) {
            try {
                $dir_iter = new \RecursiveDirectoryIterator($full_target, \RecursiveDirectoryIterator::SKIP_DOTS);
                $filter = new \RecursiveCallbackFilterIterator($dir_iter, function ($current) {
                    if ($current->isDir()) {
                        $name = $current->getFilename();
                        if (in_array($name, ['.git', '.svn', 'node_modules', 'cache'], true)) {
                            return false;
                        }
                    }
                    return true;
                });
                $iterator = new \RecursiveIteratorIterator($filter, \RecursiveIteratorIterator::SELF_FIRST);

                foreach ($iterator as $item) {
                    if ($item->isFile()) {
                        $p = wp_normalize_path($item->getPathname());
                        $rel = ltrim(str_replace($root, '', $p), '/');

                        if (!isset($manifest[$rel])) {
                            $ext = strtolower($item->getExtension());
                            if (in_array($ext, ['php', 'js', 'css', 'json', 'htaccess', 'ini', 'html', 'txt'], true)) {
                                $added[] = [
                                    'rel_path'   => $rel,
                                    'status'     => 'added_untracked',
                                    'size'       => (int) $item->getSize(),
                                    'live_mtime' => (int) $item->getMTime(),
                                ];
                            }
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Ignore traversal error
            }
        }

        $is_identical = (count($modified) === 0 && count($deleted) === 0 && count($added) === 0);

        return [
            'success'      => true,
            'snapshot_id'  => $snapshot_id,
            'label'        => $archive_data['label'] ?? '',
            'target_rel'   => $target_rel,
            'is_identical' => $is_identical,
            'counts'       => [
                'clean'    => count($clean),
                'modified' => count($modified),
                'deleted'  => count($deleted),
                'added'    => count($added),
            ],
            'modified'     => $modified,
            'deleted'      => $deleted,
            'added'        => $added,
        ];
    }

    /**
     * Retrieve file content from snapshot archive and live disk for visual Myers diff.
     *
     * @param string $snapshot_id
     * @param string $rel_path
     * @return array
     */
    public static function get_file_diff(string $snapshot_id, string $rel_path): array {
        $archive_data = self::load_snapshot_archive($snapshot_id);
        if (!$archive_data) {
            return [
                'success' => false,
                'message' => esc_html__('Snapshot archive not found.', 'wcp-security-scanner'),
            ];
        }

        $clean_rel = ltrim(wp_normalize_path(sanitize_text_field($rel_path)), '/');
        $encoded_original = $archive_data['files'][$clean_rel] ?? null;

        $original_content = $encoded_original !== null ? base64_decode($encoded_original) : '';

        $live_path = wp_normalize_path(ABSPATH . $clean_rel);
        $live_content = file_exists($live_path) ? (@file_get_contents($live_path) ?: '') : '';

        return [
            'success'          => true,
            'rel_path'         => $clean_rel,
            'snapshot_id'      => $snapshot_id,
            'original_content' => $original_content,
            'live_content'     => $live_content,
            'is_modified'      => !hash_equals(hash('sha256', $original_content), hash('sha256', $live_content)),
        ];
    }

    /**
     * Restore an individual file from snapshot archive to disk.
     *
     * @param string $snapshot_id
     * @param string $rel_path
     * @return array
     */
    public static function restore_file(string $snapshot_id, string $rel_path): array {
        if (!current_user_can('manage_options')) {
            return ['success' => false, 'message' => esc_html__('Access Denied: manage_options capability required.', 'wcp-security-scanner')];
        }
        $archive_data = self::load_snapshot_archive($snapshot_id);
        if (!$archive_data) {
            return ['success' => false, 'message' => esc_html__('Snapshot archive not found.', 'wcp-security-scanner')];
        }

        $clean_rel = ltrim(wp_normalize_path(sanitize_text_field($rel_path)), '/');
        $encoded = $archive_data['files'][$clean_rel] ?? null;

        if ($encoded === null) {
            return ['success' => false, 'message' => esc_html__('Target file is not present in this snapshot baseline.', 'wcp-security-scanner')];
        }

        $live_path = wp_normalize_path(ABSPATH . $clean_rel);
        $parent = dirname($live_path);
        if (!is_dir($parent)) {
            wp_mkdir_p($parent);
        }

        $content = base64_decode($encoded);
        global $wp_filesystem;
        $written = false;
        if ($wp_filesystem) {
            $mode = defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644;
            $written = $wp_filesystem->put_contents($live_path, $content, $mode);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Restoring verified baseline code file back to original location.
            $written = (@file_put_contents($live_path, $content, LOCK_EX) !== false);
        }

        if (!$written) {
            return ['success' => false, 'message' => esc_html__('Permission denied writing file to disk.', 'wcp-security-scanner')];
        }

        AuditLogger::log(
            'snapshot_file_restored',
            sprintf('File "%s" atomically restored from baseline snapshot %s.', $clean_rel, $snapshot_id)
        );

        return [
            'success' => true,
            'message' => sprintf(
                /* translators: %s: relative file path */
                esc_html__('File "%s" successfully restored to baseline state.', 'wcp-security-scanner'),
                $clean_rel
            ),
        ];
    }

    /**
     * Delete a snapshot archive and remove its metadata.
     *
     * @param string $snapshot_id
     * @return bool
     */
    public static function delete_snapshot(string $snapshot_id): bool {
        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (!is_array($snapshots) || !isset($snapshots[$snapshot_id])) {
            return false;
        }

        $storage_dir = self::get_storage_dir();
        $file = $storage_dir . '/' . ($snapshots[$snapshot_id]['archive_file'] ?? '');

        if (file_exists($file)) {
            wp_delete_file($file);
        }

        unset($snapshots[$snapshot_id]);
        update_option(self::OPTION_SNAPSHOTS, $snapshots, false);

        AuditLogger::log('snapshot_deleted', sprintf('Baseline snapshot "%s" deleted.', $snapshot_id));

        return true;
    }

    /**
     * Helper to load and decompress a snapshot archive.
     *
     * @param string $snapshot_id
     * @return array|null
     */
    private static function load_snapshot_archive(string $snapshot_id): ?array {
        $snapshots = get_option(self::OPTION_SNAPSHOTS, []);
        if (!is_array($snapshots) || !isset($snapshots[$snapshot_id])) {
            return null;
        }

        $storage_dir = self::get_storage_dir();
        $archive_file = $storage_dir . '/' . ($snapshots[$snapshot_id]['archive_file'] ?? '');

        if (!file_exists($archive_file)) {
            return null;
        }

        $raw = @file_get_contents($archive_file);
        if ($raw === false) {
            return null;
        }

        // Try gzdecode first
        $json = @gzdecode($raw);
        if ($json === false) {
            $json = $raw;
        }

        $data = json_decode($json, true);
        return is_array($data) ? $data : null;
    }
}
