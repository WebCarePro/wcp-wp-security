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

        // Ensure path is normalized and exists
        $real_path = realpath($file_path);
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist or is a directory.'];
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

        $file_size = (int) @filesize($real_path);
        $file_perms = substr(sprintf('%o', fileperms($real_path)), -4);
        $sha256 = hash_file('sha256', $real_path) ?: '';

        // Generate quarantined file destination with .quarantine.php extension
        $safe_filename = bin2hex(random_bytes(16)) . '_' . time() . '.quarantine.php';
        $dest_path = $this->quarantine_dir . '/' . $safe_filename;
        $guard_header = "<?php http_response_code(403); exit('WebCare Pro Security: Direct access forbidden.'); __halt_compiler(); ?>\n";

        // For large files (>20MB), stream directly with guard header to prevent PHP memory exhaustion (OOM)
        if ($file_size > 20971520) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $src_fp = @fopen($real_path, 'rb');
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $dst_fp = @fopen($dest_path, 'wb');
            if (!$src_fp || !$dst_fp) {
                if ($src_fp) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                    fclose($src_fp);
                }
                if ($dst_fp) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                    fclose($dst_fp);
                }
                return ['success' => false, 'message' => 'Failed to isolate large file to vault storage. Permission denied.'];
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Stream write required for chunked processing of large files (>20MB) to prevent memory exhaustion
            fwrite($dst_fp, $guard_header);
            stream_copy_to_stream($src_fp, $dst_fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($src_fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($dst_fp);
        } else {
            // Read file contents before isolation
            $file_content = @file_get_contents($real_path);
            if ($file_content === false) {
                return ['success' => false, 'message' => 'Failed to read target file. Permission denied.'];
            }

            // Encrypt file contents using SecretVault (AES-256-GCM authenticated AEAD encryption)
            $encrypted_payload = \WebCareProScanner\Security\SecretVault::encrypt($file_content);
            $vault_payload = $guard_header . $encrypted_payload;

            // Write encrypted payload to protected vault
            if (@file_put_contents($dest_path, $vault_payload, LOCK_EX) === false) {
                return ['success' => false, 'message' => 'Failed to isolate file to encrypted vault storage. Permission denied.'];
            }
        }

        // Lock down permissions on vault file
        global $wp_filesystem;
        if ($wp_filesystem) {
            $wp_filesystem->chmod($dest_path, 0600);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($dest_path, 0600);
        }

        // Unlink original infected/suspicious file
        wp_delete_file($real_path);

        // Record in database - ensure single authoritative record per original_path
        $table = $wpdb->prefix . 'webcareproscan_quarantine';

        // Check if previous records exist for this exact file path to avoid duplicates
        $exist_sql = "SELECT id, quarantine_filename FROM `{$table}` WHERE original_path = %s";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $existing = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($exist_sql, $real_path),
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
            $del_sql = "DELETE FROM `{$table}` WHERE original_path = %s";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($del_sql, $real_path)
            );
        }

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

        $quarantine_id = $wpdb->insert_id;

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
    public function restore_file($quarantine_id) {
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

        // Security check: Destination must reside within ABSPATH boundary and be safe to write
        if (!\WebCareProScanner\Filesystem\PathValidator::is_safe_write_target($dest_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security violation: Restore destination resides outside ABSPATH.'];
        }
        $real_root = rtrim(wp_normalize_path(realpath(ABSPATH) ?: ABSPATH), '/') . '/';
        $normalized_dest = wp_normalize_path($dest_path);

        // Prohibit restoring directly into WordPress core directories
        $wp_includes_dir = wp_normalize_path(untrailingslashit(ABSPATH . WPINC)) . '/';
        $wp_admin_dir = wp_normalize_path(untrailingslashit(ABSPATH . 'wp-admin')) . '/';
        if (strpos($normalized_dest, $wp_includes_dir) === 0 || strpos($normalized_dest, $wp_admin_dir) === 0) {
            return ['success' => false, 'message' => 'Action Blocked: Cannot restore files directly into WordPress core system directories.'];
        }

        // Ensure destination directory exists
        $dest_dir = dirname($dest_path);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }

        $source_size = (int) @filesize($source_path);
        if ($source_size > 20971520) {
            // Large file stream restore: avoid loading entire file into memory (OOM prevention)
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $src_fp = @fopen($source_path, 'rb');
            if (!$src_fp) {
                return ['success' => false, 'message' => 'Failed to open large vault file for restoration.'];
            }

            // Seek past guard header
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Stream read required to inspect halt marker on large files (>20MB) without loading into memory
            $header_buffer = fread($src_fp, 2048);
            $halt_marker = '__halt_compiler(); ' . '?>';
            $pos = strpos($header_buffer, $halt_marker);
            if ($pos !== false) {
                $payload_offset = $pos + strlen($halt_marker);
                while ($payload_offset < strlen($header_buffer) && ($header_buffer[$payload_offset] === "\r" || $header_buffer[$payload_offset] === "\n")) {
                    $payload_offset++;
                }
                fseek($src_fp, $payload_offset, SEEK_SET);
            } else {
                fseek($src_fp, 0, SEEK_SET);
            }

            $temp_dest = $dest_path . '.webcare_rst_' . bin2hex(random_bytes(6));
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $dst_fp = @fopen($temp_dest, 'wb');
            if (!$dst_fp) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($src_fp);
                return ['success' => false, 'message' => 'Failed to create destination stream for large file restoration.'];
            }

            stream_copy_to_stream($src_fp, $dst_fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($src_fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($dst_fp);

            global $wp_filesystem;
            if (empty($wp_filesystem)) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
            }

            $perms = !empty($record['file_perms']) ? octdec($record['file_perms']) : 0644;
            if (!empty($wp_filesystem) && method_exists($wp_filesystem, 'chmod')) {
                $wp_filesystem->chmod($temp_dest, $perms);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                @chmod($temp_dest, $perms);
            }

            $moved = false;
            if (!empty($wp_filesystem) && method_exists($wp_filesystem, 'move')) {
                $moved = $wp_filesystem->move($temp_dest, $dest_path, true);
            }
            if (!$moved) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic filesystem rename fallback when WP_Filesystem::move is unavailable
                $moved = @rename($temp_dest, $dest_path);
            }

            if (!$moved) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'message' => 'Failed to safely move restored large file to destination.'];
            }
        } else {
            // Read vault file and extract payload
            $vault_raw = @file_get_contents($source_path);
            if ($vault_raw === false) {
                return ['success' => false, 'message' => 'Failed to read vault file for restoration.'];
            }

            $payload = $vault_raw;
            $halt_marker = '__halt_compiler(); ' . '?>';
            $pos = strpos($vault_raw, $halt_marker);
            if ($pos !== false) {
                $payload = ltrim(substr($vault_raw, $pos + strlen($halt_marker)), "\r\n");
            }

            // Decrypt ciphertext if encrypted
            if (\WebCareProScanner\Security\SecretVault::is_encrypted($payload)) {
                $decrypted = \WebCareProScanner\Security\SecretVault::decrypt($payload);
                if ($decrypted === false) {
                    return ['success' => false, 'message' => 'Cryptographic decryption failed: Invalid vault key or corrupted vault ciphertext.'];
                }
                $clean_data = $decrypted;
            } else {
                // Legacy unencrypted plaintext fallback
                $clean_data = $payload;
            }

            // Atomically write restored plaintext to original destination, preventing symlink follower races
            $perms = !empty($record['file_perms']) ? octdec($record['file_perms']) : 0644;
            if (!\WebCareProScanner\Filesystem\PathValidator::safe_atomic_write($dest_path, $clean_data, ABSPATH, $perms)) {
                return ['success' => false, 'message' => 'Failed to safely restore file to original location. Check directory permissions.'];
            }
        }

        // Unlink vault storage file
        wp_delete_file($source_path);

        // Update database record
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table, [
            'status'          => 'restored',
            'restored_at'     => current_time('mysql'),
            'restored_at_gmt' => gmdate('Y-m-d H:i:s'),
        ], ['id' => $quarantine_id]);

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
