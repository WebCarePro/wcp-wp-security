<?php
namespace WebCareProScanner\Quarantine;

if (!defined('ABSPATH')) {
    exit;
}

class QuarantineManager {

    private $quarantine_dir;

    public function __construct() {
        $this->quarantine_dir = self::get_quarantine_dir();
        $this->ensure_quarantine_directory();
    }

    public static function get_quarantine_dir(): string {
        $uploads = wp_upload_dir();
        $base = untrailingslashit($uploads['basedir']);
        return $base . '/webcare-pro-security/.vault';
    }

    /**
     * Ensure the quarantine directory exists and is heavily locked down against public web execution.
     */
    private function ensure_quarantine_directory() {
        if (!is_dir($this->quarantine_dir)) {
            wp_mkdir_p($this->quarantine_dir);
        }

        // Lock with .htaccess (Apache / LiteSpeed defense)
        $htaccess = $this->quarantine_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# Block all public web access to quarantine vault\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n<FilesMatch \".*\">\n    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n    <IfModule !mod_authz_core.c>\n        Order deny,allow\n        Deny from all\n    </IfModule>\n</FilesMatch>\n";
            @file_put_contents($htaccess, $rules);
        }

        // Lock with index.php
        $index = $this->quarantine_dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WebCare Pro Security: Direct access forbidden.');\n");
        }
    }

    /**
     * Safely quarantine a suspicious file.
     *
     * @param string $file_path
     * @param int|null $scan_id
     * @param int|null $issue_id
     * @return array ['success' => bool, 'message' => string, 'id' => int|null]
     */
    public function quarantine_file($file_path, $scan_id = null, $issue_id = null) {
        global $wpdb;

        // Ensure path is normalized, exists, and is not a symlink
        if (is_link($file_path)) {
            return ['success' => false, 'message' => 'Security violation: Symlinks cannot be quarantined.'];
        }
        $real_path = realpath($file_path);
        if (!$real_path || !file_exists($real_path) || is_dir($real_path) || is_link($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist, is a directory, or is a symbolic link.'];
        }

        // Security check: Must reside within WordPress installation root with directory boundary check
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($file_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security violation: File resides outside ABSPATH.'];
        }
        $real_root = rtrim(wp_normalize_path(realpath(ABSPATH) ?: ABSPATH), '/') . '/';
        $normalized_real = wp_normalize_path($real_path);

        // Prohibit quarantining genuine core files inside core directories (wp-admin, wp-includes).
        // Unknown, extraneous, or rogue files injected by attackers CAN and should be quarantined.
        $wp_includes_dir = wp_normalize_path(untrailingslashit(ABSPATH . WPINC)) . '/';
        $wp_admin_dir = wp_normalize_path(untrailingslashit(ABSPATH . 'wp-admin')) . '/';
        if (strpos($normalized_real, $wp_includes_dir) === 0 || strpos($normalized_real, $wp_admin_dir) === 0) {
            $provider = new \WebCareProScanner\Integrity\ChecksumProvider();
            $core_checksums = $provider->get_core_checksums();
            $rel_file = ltrim(str_replace($real_root, '', $normalized_real), '/');

            // If the file is part of the official WordPress core manifest, do not allow direct quarantine
            if (!empty($core_checksums) && isset($core_checksums[$rel_file])) {
                return [
                    'success' => false,
                    'message' => "Action Blocked: '{$rel_file}' is an official WordPress core system file. To safely restore legitimate core files, navigate to Dashboard -> Updates -> Re-install Core or use WP-CLI."
                ];
            }
        }

        // Critical system protection: Never allow quarantining essential bootstrap or config files
        $protected_basenames = [
            'wp-config.php',
            '.htaccess',
            'index.php',
            'wp-settings.php',
            'wp-load.php',
            'wp-blog-header.php',
            'wp-login.php',
            'xmlrpc.php'
        ];

        $basename = strtolower(basename($real_path));

        if (in_array($basename, $protected_basenames, true)) {
            return [
                'success' => false,
                'message' => "Action Blocked: '{$basename}' is a critical WordPress core bootstrap file and cannot be quarantined to prevent fatal website outages."
            ];
        }

        // Prohibit quarantining modified official files (which must be repaired/restored, not isolated)
        if ($issue_id) {
            $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
            $issue_sql = "SELECT type FROM {$table_issues} WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $issue = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($issue_sql, (int) $issue_id)
            );
            if ($issue && (strpos($issue->type, 'modified_') === 0 || strpos($issue->type, 'wp_config_') === 0 || $issue->type === 'injected_wp_config')) {
                return [
                    'success' => false,
                    'message' => __('Action Blocked: This is an official component file that was modified. Please use Auto-Cure or code restoration rather than quarantine to avoid breaking website functionality.', 'webcare-pro-security')
                ];
            }
        }

        if (strpos($normalized_real, '/plugins/webcare-pro-security/') !== false) {
            return [
                'success' => false,
                'message' => "Action Blocked: Cannot quarantine security scanner plugin files."
            ];
        }

        $src_stat = @lstat($real_path);
        if (!$src_stat || !is_array($src_stat)) {
            return ['success' => false, 'message' => 'Failed to obtain filesystem stat for target file.'];
        }

        $file_size = (int) ($src_stat['size'] ?? @filesize($real_path));
        $file_perms = substr(sprintf('%o', fileperms($real_path)), -4);
        $sha256 = hash_file('sha256', $real_path) ?: '';

        // Generate quarantined file destination with .quarantine.php extension
        $safe_filename = bin2hex(random_bytes(16)) . '_' . time() . '.quarantine.php';
        $dest_path = $this->quarantine_dir . '/' . $safe_filename;

        // Unified 1 MB Chunked Streaming AEAD Encryption (Q-02, Q-03):
        // 100% of files from 1 byte to 500 MB+ are authenticated and encrypted via AES-256-GCM.
        $vault_res = \WebCareProScanner\Security\SecretVault::encrypt_file_to_vault($real_path, $dest_path);
        if (empty($vault_res['success'])) {
            return [
                'success' => false,
                'message' => 'Quarantine encryption failed: ' . ($vault_res['error'] ?? 'Unknown vault error'),
            ];
        }

        // Lock down permissions on vault file
        global $wp_filesystem;
        if ($wp_filesystem) {
            $wp_filesystem->chmod($dest_path, 0600);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($dest_path, 0600);
        }

        // Record in database BEFORE unlinking original file (WCP-01, Q-01)
        // We preserve any older quarantine rows until the new file deletion commits!
        $table = $wpdb->prefix . 'webcareproscan_quarantine';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $inserted = $wpdb->insert($table, [
            'scan_id'             => $scan_id,
            'issue_id'            => $issue_id,
            'original_path'       => $real_path,
            'quarantine_filename' => $safe_filename,
            'sha256'              => $sha256,
            'file_size'           => $file_size,
            'file_perms'          => $file_perms,
            'status'              => 'quarantined',
            'quarantined_at'      => current_time('mysql'),
            'quarantined_at_gmt'  => gmdate('Y-m-d H:i:s'),
        ]);

        $quarantine_id = (int) $wpdb->insert_id;
        if ($inserted === false || $quarantine_id <= 0) {
            wp_delete_file($dest_path);
            return [
                'success' => false,
                'message' => 'Database error: Could not record quarantine entry. Original file was left untouched.',
            ];
        }

        // TOCTOU Symlink Replacement & Inode Attribute Verification (Q-01):
        // Re-stat target immediately before deletion and verify dev, ino, size, and mtime remain identical.
        clearstatcache(true, $real_path);
        $pre_del_stat = @lstat($real_path);

        if (
            is_link($real_path) || is_link($file_path)
            || !$pre_del_stat || !is_array($pre_del_stat)
            || ($pre_del_stat['dev'] ?? null) !== ($src_stat['dev'] ?? null)
            || ($pre_del_stat['ino'] ?? null) !== ($src_stat['ino'] ?? null)
            || ($pre_del_stat['size'] ?? null) !== ($src_stat['size'] ?? null)
            || ($pre_del_stat['mtime'] ?? null) !== ($src_stat['mtime'] ?? null)
        ) {
            // Roll back the new database record and remove newly created vault copy
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table, ['id' => $quarantine_id], ['%d']);
            wp_delete_file($dest_path);
            return [
                'success' => false,
                'message' => 'Security violation: File attributes or inode changed between encryption and deletion (possible TOCTOU race); operation safely aborted.',
            ];
        }

        // Unlink original infected/suspicious file and verify removal
        wp_delete_file($real_path);
        clearstatcache(true, $real_path);
        if (file_exists($real_path)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table, ['id' => $quarantine_id], ['%d']);
            wp_delete_file($dest_path);
            return [
                'success' => false,
                'message' => 'Failed to remove original file from filesystem; quarantine record rolled back.',
            ];
        }

        // Now that deletion is 100% committed, prune any superseded older quarantine rows for this path (Q-01)
        $exist_sql = "SELECT id, quarantine_filename FROM `{$table}` WHERE original_path = %s AND id != %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $existing = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($exist_sql, $real_path, $quarantine_id),
            ARRAY_A
        );

        if (!empty($existing)) {
            foreach ($existing as $old_rec) {
                if (!empty($old_rec['quarantine_filename'])) {
                    $old_file = $this->quarantine_dir . '/' . $old_rec['quarantine_filename'];
                    if (file_exists($old_file)) {
                        wp_delete_file($old_file);
                    }
                }
            }
            $del_sql = "DELETE FROM `{$table}` WHERE original_path = %s AND id != %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($del_sql, $real_path, $quarantine_id)
            );
        }

        // Flush bytecode caches ONLY after original file is confirmed deleted
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($real_path, true);
        }
        if (function_exists('apc_delete_file')) {
            @apc_delete_file($real_path);
        }

        // Update issue status
        $issues_table = $wpdb->prefix . 'webcareproscan_scan_issues';
        if ($issue_id) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($issues_table, ['status' => 'quarantined'], ['id' => $issue_id]);
        }
        if (!empty($real_path)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($issues_table, ['status' => 'quarantined'], ['file_path' => $real_path]);
        }

        // Trigger 72-Hour Reinfection Watchdog post-remediation surveillance
        do_action('webcareproscan_file_quarantined', $real_path, $sha256);

        // Dispatch scan_auto_quarantine notification event
        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_auto_quarantine', [
                'severity' => 'high',
                /* translators: 1: original file basename */
                'message'  => sprintf(__('Malicious file "%1$s" was neutralized and quarantined into the encrypted WebCare Vault.', 'webcare-pro-security'), basename($real_path)),
                'details'  => [
                    'File Path'      => $real_path,
                    'SHA-256'        => $sha256,
                    'File Size'      => size_format($file_size),
                    'Quarantine ID'  => $quarantine_id,
                ],
            ]);
        }

        return [
            'success'       => true,
            'message'       => 'File successfully quarantined and encrypted in vault.',
            'quarantine_id' => $quarantine_id,
            'sha256'        => $sha256
        ];
    }

    /**
     * Restore a quarantined file back to its original location.
     * Decrypts AES-256-GCM ciphertext safely in memory before writing to disk.
     *
     * @param int $quarantine_id
     * @return array ['success' => bool, 'message' => string]
     */
    /**
     * Restore a quarantined file back to its original location.
     * Decrypts authenticated vault ciphertext safely (Q-02, Q-03) and enforces no-clobber guarantees (Q-04).
     *
     * @param int $quarantine_id
     * @param bool $overwrite Whether to overwrite existing destination files
     * @param bool $allow_legacy_unverified Whether to allow restoring unencrypted legacy files
     * @return array ['success' => bool, 'message' => string, 'conflict' => bool]
     */
    public function restore_file($quarantine_id, bool $overwrite = false, bool $allow_legacy_unverified = false) {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_quarantine';

        $rec_sql = "SELECT * FROM {$table} WHERE id = %d AND status = 'quarantined'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $record = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($rec_sql, $quarantine_id),
            ARRAY_A
        );

        if (!$record) {
            return ['success' => false, 'message' => 'Quarantine record not found or already restored.'];
        }

        $source_path = $this->quarantine_dir . '/' . $record['quarantine_filename'];
        if (!file_exists($source_path)) {
            if (substr($record['quarantine_filename'], -4) === '.php') {
                $alt_name = substr($record['quarantine_filename'], 0, -4);
                if (file_exists($this->quarantine_dir . '/' . $alt_name)) {
                    $source_path = $this->quarantine_dir . '/' . $alt_name;
                }
            } else {
                $alt_name = $record['quarantine_filename'] . '.php';
                if (file_exists($this->quarantine_dir . '/' . $alt_name)) {
                    $source_path = $this->quarantine_dir . '/' . $alt_name;
                }
            }
        }

        if (!file_exists($source_path)) {
            return ['success' => false, 'message' => 'Quarantined backup file is missing from archive storage.'];
        }

        $dest_path = $record['original_path'];

        // Enforce No-Clobber (Q-04): If file already exists at destination and not $overwrite, refuse to overwrite
        if ((file_exists($dest_path) || is_link($dest_path)) && !$overwrite) {
            return [
                'success'  => false,
                'conflict' => true,
                'message'  => __('Restore aborted: A file already exists at the destination path.', 'webcare-pro-security'),
            ];
        }

        // Security check: Destination must reside within ABSPATH boundary and be safe to write
        if (!\WebCareProScanner\Filesystem\PathValidator::is_safe_write_target($dest_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security violation: Restore destination resides outside ABSPATH.'];
        }
        $real_root = rtrim(wp_normalize_path(realpath(ABSPATH) ?: ABSPATH), '/') . '/';
        $normalized_dest = wp_normalize_path($dest_path);

        // Prohibit overwriting official WordPress core files inside wp-admin / wp-includes,
        // while allowing restoration of false-positive custom/unknown files that are not part of core checksums (WCP-10).
        $wp_includes_dir = wp_normalize_path(untrailingslashit(ABSPATH . WPINC)) . '/';
        $wp_admin_dir    = wp_normalize_path(untrailingslashit(ABSPATH . 'wp-admin')) . '/';
        if (strpos($normalized_dest, $wp_includes_dir) === 0 || strpos($normalized_dest, $wp_admin_dir) === 0) {
            $provider       = new \WebCareProScanner\Integrity\ChecksumProvider();
            $core_checksums = $provider->get_core_checksums();
            $rel_file       = ltrim(str_replace($real_root, '', $normalized_dest), '/');
            if ((!empty($core_checksums) && isset($core_checksums[$rel_file])) || file_exists($dest_path)) {
                return [
                    'success' => false,
                    'message' => 'Action Blocked: Cannot overwrite an existing or official WordPress core file in wp-admin/wp-includes.',
                ];
            }
        }

        // Ensure destination directory exists
        $dest_dir = dirname($dest_path);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }

        $expected_hash = (string) ($record['sha256'] ?? $record['file_hash'] ?? '');
        $raw_perms     = $record['file_permissions'] ?? $record['file_perms'] ?? '';
        $perms         = !empty($raw_perms) ? octdec((string) $raw_perms) : 0644;

        // Hash verification check: Require valid 64-character SHA-256 hex unless legacy unverified is explicitly allowed
        if (!$allow_legacy_unverified && !preg_match('/^[a-f0-9]{64}$/i', $expected_hash)) {
            return [
                'success' => false,
                'message' => 'Integrity verification failed: Missing or invalid SHA-256 fingerprint in quarantine record.',
            ];
        }

        // Decrypt authenticated vault archive to an isolated staging file in the target directory (Finding 2.1)
        $staging_path = $dest_path . '.webcare_rst_stage_' . bin2hex(random_bytes(6));
        $dec_res = \WebCareProScanner\Security\SecretVault::decrypt_vault_to_file(
            $source_path,
            $staging_path,
            null,
            $allow_legacy_unverified
        );

        if (empty($dec_res['success'])) {
            if (file_exists($staging_path)) {
                wp_delete_file($staging_path);
            }
            return [
                'success' => false,
                'message' => 'Cryptographic decryption failed: ' . ($dec_res['error'] ?? 'Corrupted or unauthenticated vault archive.'),
            ];
        }

        // Verify restored file hash against recorded SHA-256 on STAGING file BEFORE touching target destination (Finding 2.1)
        if ($expected_hash !== '') {
            $restored_hash = @hash_file('sha256', $staging_path);
            if ($restored_hash === false || !hash_equals($expected_hash, $restored_hash)) {
                wp_delete_file($staging_path);
                return [
                    'success' => false,
                    'message' => 'Integrity check failed: Restored file SHA-256 does not match quarantine record.',
                ];
            }
        }

        // Apply genuinely atomic no-clobber commit (Finding 1.3)
        $committed = false;
        if (!$overwrite) {
            if (file_exists($dest_path)) {
                wp_delete_file($staging_path);
                return [
                    'success'  => false,
                    'conflict' => true,
                    'message'  => __('Restore aborted: A file already exists at the destination path.', 'webcare-pro-security'),
                ];
            }

            // Atomic commit via link(): fails with EEXIST if destination exists, preventing race-condition overwrite
            if (function_exists('link') && @link($staging_path, $dest_path)) {
                wp_delete_file($staging_path);
                $committed = true;
            } else {
                // Secondary check if destination appeared before rename
                if (file_exists($dest_path)) {
                    wp_delete_file($staging_path);
                    return [
                        'success'  => false,
                        'conflict' => true,
                        'message'  => __('Restore aborted: A file already exists at the destination path.', 'webcare-pro-security'),
                    ];
                }
                // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic swap of restored staging file
                if (@rename($staging_path, $dest_path)) {
                    $committed = true;
                }
            }
        } else {
            // Overwrite allowed: atomic rename with safe copy fallback
            // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
            if (@rename($staging_path, $dest_path)) {
                $committed = true;
            } elseif (@copy($staging_path, $dest_path)) {
                wp_delete_file($staging_path);
                $committed = true;
            }
        }

        if (!$committed) {
            wp_delete_file($staging_path);
            return [
                'success' => false,
                'message' => __('Failed to commit restored file into destination path. Check filesystem permissions.', 'webcare-pro-security'),
            ];
        }

        // Restore file permissions
        global $wp_filesystem;
        if ($wp_filesystem && method_exists($wp_filesystem, 'chmod')) {
            $wp_filesystem->chmod($dest_path, $perms);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($dest_path, $perms);
        }

        // Update database record FIRST to preserve recoverability until DB state commits (Finding 1.3)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $db_updated = $wpdb->update($table, [
            'status'          => 'restored',
            'restored_at'     => current_time('mysql'),
            'restored_at_gmt' => gmdate('Y-m-d H:i:s'),
        ], ['id' => $quarantine_id]);

        if ($db_updated === false) {
            // Roll back restored file so the system state remains consistent
            wp_delete_file($dest_path);
            return [
                'success' => false,
                'message' => __('Database update failed during restore. Restored file reverted and quarantine vault preserved.', 'webcare-pro-security'),
            ];
        }

        // Only once database commit is confirmed, safely unlink vault storage file
        wp_delete_file($source_path);

        // If issue exists, set status back to open
        $issues_table = $wpdb->prefix . 'webcareproscan_scan_issues';
        if (!empty($record['issue_id'])) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($issues_table, ['status' => 'open'], ['id' => (int) $record['issue_id']]);
        }
        if (!empty($record['original_path'])) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($issues_table, ['status' => 'open'], ['file_path' => $record['original_path']]);
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('vault_quarantine_restored', [
                'severity' => 'warning',
                'message'  => sprintf(
                    /* translators: %s: file path */
                    __('A file in security quarantine was restored back to the active filesystem: "%s".', 'webcare-pro-security'),
                    $dest_path
                ),
                'details'  => [
                    'original_path' => $dest_path,
                    'restored_by'   => wp_get_current_user()->user_login ?: 'admin',
                    'quarantine_id' => $quarantine_id,
                ],
            ]);
        }

        return ['success' => true, 'message' => 'File successfully restored to original location.'];
    }

    /**
     * Retrieve all quarantine records with automatic deduplication per file path.
     * Prunes obsolete duplicate history rows so each file path has one authoritative record.
     *
     * @return array
     */
    public function list_records() {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_quarantine';
        $list_sql = "SELECT * FROM `{$table}` ORDER BY id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results($list_sql, ARRAY_A);
        if (!is_array($results)) {
            return [];
        }

        $seen = [];
        $unique_records = [];
        $duplicate_ids = [];

        foreach ($results as $r) {
            $path = $r['original_path'];
            if (!isset($seen[$path])) {
                $seen[$path] = true;
                $unique_records[] = $r;
            } else {
                // Older duplicate row for the same file path; mark for automatic database cleanup
                $duplicate_ids[] = (int) $r['id'];
                // If there's an orphaned vault file for the duplicate row, remove it
                if (!empty($r['quarantine_filename'])) {
                    $cand = $this->quarantine_dir . '/' . $r['quarantine_filename'];
                    if (file_exists($cand)) {
                        wp_delete_file($cand);
                    }
                }
            }
        }

        if (!empty($duplicate_ids)) {
            $ids_sql = implode(',', array_map('intval', $duplicate_ids));
            $del_dups = "DELETE FROM `{$table}` WHERE id IN ({$ids_sql})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_dups);
        }

        foreach ($unique_records as &$ur) {
            if (!empty($ur['quarantined_at_gmt'])) {
                $ur['quarantined_at_gmt'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($ur['quarantined_at_gmt']));
            } elseif (!empty($ur['quarantined_at'])) {
                $ur['quarantined_at_gmt'] = get_gmt_from_date($ur['quarantined_at'], 'Y-m-d\TH:i:s\Z');
            }
            if (!empty($ur['restored_at_gmt'])) {
                $ur['restored_at_gmt'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($ur['restored_at_gmt']));
            } elseif (!empty($ur['restored_at'])) {
                $ur['restored_at_gmt'] = get_gmt_from_date($ur['restored_at'], 'Y-m-d\TH:i:s\Z');
            }
        }
        unset($ur);

        return $unique_records;
    }

    /**
     * Static alias for list_records()
     *
     * @return array
     */
    public static function get_all(): array {
        $instance = new self();
        return $instance->list_records();
    }

    /**
     * Clear all restored records from the quarantine history.
     * Restored files on the live website remain completely untouched.
     *
     * @return array
     */
    public function clear_restored_records() {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_quarantine';
        $restored_sql = "SELECT id, quarantine_filename FROM `{$table}` WHERE status = 'restored'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $restored = $wpdb->get_results($restored_sql, ARRAY_A);
        if (!empty($restored)) {
            foreach ($restored as $r) {
                if (!empty($r['quarantine_filename'])) {
                    $cand = $this->quarantine_dir . '/' . $r['quarantine_filename'];
                    if (file_exists($cand)) {
                        wp_delete_file($cand);
                    }
                }
            }
            $clear_sql = "DELETE FROM `{$table}` WHERE status = 'restored'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($clear_sql);
            return [
                'success' => true,
                'message' => sprintf(
                    /* translators: %d: count of cleared log entries */
                    __('Cleared %d restored history log entries. (Live website files remain untouched).', 'webcare-pro-security'),
                    count($restored)
                )
            ];
        }
        return [
            'success' => true,
            'message' => __('No restored records to clear.', 'webcare-pro-security')
        ];
    }

    /**
     * Delete a quarantine record.
     * For quarantined threats: Permanently purges isolated file from vault storage and marks issue repaired.
     * For restored files: Removes log record from history without touching live site file.
     *
     * @param int $quarantine_id
     * @return array
     */
    public function delete_record($quarantine_id) {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_quarantine';
        $find_sql = "SELECT * FROM `{$table}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $record = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($find_sql, (int) $quarantine_id),
            ARRAY_A
        );
        if (!$record) {
            return ['success' => false, 'message' => 'Quarantine record not found.'];
        }

        $was_restored = ($record['status'] === 'restored');

        $candidates = [
            $this->quarantine_dir . '/' . $record['quarantine_filename'],
            $this->quarantine_dir . '/' . $record['quarantine_filename'] . '.php',
        ];
        if (substr($record['quarantine_filename'], -4) === '.php') {
            $stripped = substr($record['quarantine_filename'], 0, -4);
            $candidates[] = $this->quarantine_dir . '/' . $stripped;
        }

        foreach ($candidates as $cand) {
            if (file_exists($cand)) {
                wp_delete_file($cand);
            }
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->delete($table, ['id' => (int) $quarantine_id]);

        // When permanently deleting an active quarantined threat, mark matching scan issues as repaired
        if (!$was_restored) {
            $issues_table = $wpdb->prefix . 'webcareproscan_scan_issues';
            if (!empty($record['issue_id'])) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update($issues_table, ['status' => 'repaired'], ['id' => (int) $record['issue_id']]);
            }
            if (!empty($record['original_path'])) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update($issues_table, ['status' => 'repaired'], ['file_path' => $record['original_path']]);
            }

            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('vault_quarantine_deleted', [
                    'severity' => 'info',
                    /* translators: %s: file path */
                    'message'  => sprintf(__('Quarantined file was permanently purged from vault storage: "%s".', 'webcare-pro-security'), $record['original_path'] ?? 'unknown'),
                    'details'  => [
                        'file_path'     => $record['original_path'] ?? 'unknown',
                        'purged_by'     => wp_get_current_user()->user_login ?: 'admin',
                        'quarantine_id' => $quarantine_id,
                    ],
                ]);
            }

            return ['success' => true, 'message' => 'Quarantined threat permanently purged from vault storage.'];
        }

        return ['success' => true, 'message' => 'Restored log entry removed from vault history. (Live website file remains untouched).'];
    }
}
