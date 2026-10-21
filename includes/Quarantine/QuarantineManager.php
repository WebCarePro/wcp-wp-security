<?php
namespace WcpScanner\Quarantine;

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
        return $base . '/wcp-security-scanner/.vault';
    }

    /**
     * Ensure the quarantine directory exists and is heavily locked down against public web execution.
     * Migrates legacy unencrypted quarantine files to the encrypted dot-vault if present.
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
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WCP Security: Direct access forbidden.');\n");
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
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($file_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security violation: File resides outside ABSPATH.'];
        }
        $real_root = rtrim(wp_normalize_path(realpath(ABSPATH) ?: ABSPATH), '/') . '/';
        $normalized_real = wp_normalize_path($real_path);

        // Prohibit quarantining genuine core files inside core directories (wp-admin, wp-includes).
        // Unknown, extraneous, or rogue files injected by attackers CAN and should be quarantined.
        $wp_includes_dir = wp_normalize_path(untrailingslashit(ABSPATH . WPINC)) . '/';
        $wp_admin_dir = wp_normalize_path(untrailingslashit(ABSPATH . 'wp-admin')) . '/';
        if (strpos($normalized_real, $wp_includes_dir) === 0 || strpos($normalized_real, $wp_admin_dir) === 0) {
            $provider = new \WcpScanner\Integrity\ChecksumProvider();
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
            $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $issue = $wpdb->get_row($wpdb->prepare("SELECT type FROM {$table_issues} WHERE id = %d", (int) $issue_id));
            if ($issue && (strpos($issue->type, 'modified_') === 0 || strpos($issue->type, 'wp_config_') === 0 || $issue->type === 'injected_wp_config')) {
                return [
                    'success' => false,
                    'message' => __('Action Blocked: This is an official component file that was modified. Please use Auto-Cure or code restoration rather than quarantine to avoid breaking website functionality.', 'wcp-security-scanner')
                ];
            }
        }

        if (strpos($normalized_real, '/plugins/wcp-wp-scanner/') !== false || strpos($normalized_real, '/plugins/wcp-security-scanner/') !== false) {
            return [
                'success' => false,
                'message' => "Action Blocked: Cannot quarantine security scanner plugin files."
            ];
        }

        // Read file contents before isolation
        $file_content = @file_get_contents($real_path);
        if ($file_content === false) {
            return ['success' => false, 'message' => 'Failed to read target file. Permission denied.'];
        }

        // Compute metadata from raw plaintext
        $sha256 = hash('sha256', $file_content);
        $file_size = strlen($file_content);
        $file_perms = substr(sprintf('%o', fileperms($real_path)), -4);

        // Encrypt file contents using SecretVault (AES-256-GCM authenticated AEAD encryption)
        $encrypted_payload = \WcpScanner\Security\SecretVault::encrypt($file_content);

        // Prepend defanged PHP execution prevention header and __halt_compiler()
        $guard_header = "<?php http_response_code(403); exit('WCP Security: Direct access forbidden.'); __halt_compiler(); ?>\n";
        $vault_payload = $guard_header . $encrypted_payload;

        // Generate quarantined file destination with .quarantine.php extension
        $safe_filename = bin2hex(random_bytes(16)) . '_' . time() . '.quarantine.php';
        $dest_path = $this->quarantine_dir . '/' . $safe_filename;

        // Write encrypted payload to protected vault
        if (@file_put_contents($dest_path, $vault_payload, LOCK_EX) === false) {
            return ['success' => false, 'message' => 'Failed to isolate file to encrypted vault storage. Permission denied.'];
        }

        // Lock down permissions on vault file
        @chmod($dest_path, 0600);

        // Unlink original infected/suspicious file
        @unlink($real_path);

        // Record in database - ensure single authoritative record per original_path
        $table = $wpdb->prefix . 'wcpscan_quarantine';

        // Check if previous records exist for this exact file path to avoid duplicates
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $existing = $wpdb->get_results($wpdb->prepare(
            "SELECT id, quarantine_filename FROM `{$table}` WHERE original_path = %s",
            $real_path
        ), ARRAY_A);

        if (!empty($existing)) {
            foreach ($existing as $old_rec) {
                if (!empty($old_rec['quarantine_filename'])) {
                    $old_file = $this->quarantine_dir . '/' . $old_rec['quarantine_filename'];
                    if (file_exists($old_file)) {
                        @unlink($old_file);
                    }
                }
            }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query($wpdb->prepare("DELETE FROM `{$table}` WHERE original_path = %s", $real_path));
        }

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
        ]);

        $quarantine_id = $wpdb->insert_id;

        // Update issue status
        $issues_table = $wpdb->prefix . 'wcpscan_scan_issues';
        if ($issue_id) {
            $wpdb->update($issues_table, ['status' => 'quarantined'], ['id' => $issue_id]);
        }
        if (!empty($real_path)) {
            $wpdb->update($issues_table, ['status' => 'quarantined'], ['file_path' => $real_path]);
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
        $table = $wpdb->prefix . 'wcpscan_quarantine';

        $record = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE id = %d AND status = 'quarantined'",
            $quarantine_id
        ), ARRAY_A);

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
        if (!\WcpScanner\Filesystem\PathValidator::is_safe_write_target($dest_path, ABSPATH)) {
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

        // Read vault file and extract payload
        $vault_raw = @file_get_contents($source_path);
        if ($vault_raw === false) {
            return ['success' => false, 'message' => 'Failed to read vault file for restoration.'];
        }

        $payload = $vault_raw;
        $halt_marker = '__halt_compiler(); ?>';
        $pos = strpos($vault_raw, $halt_marker);
        if ($pos !== false) {
            $payload = ltrim(substr($vault_raw, $pos + strlen($halt_marker)), "\r\n");
        }

        // Decrypt ciphertext if encrypted
        if (\WcpScanner\Security\SecretVault::is_encrypted($payload)) {
            $decrypted = \WcpScanner\Security\SecretVault::decrypt($payload);
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
        if (!\WcpScanner\Filesystem\PathValidator::safe_atomic_write($dest_path, $clean_data, ABSPATH, $perms)) {
            return ['success' => false, 'message' => 'Failed to safely restore file to original location. Check directory permissions.'];
        }

        // Unlink vault storage file
        @unlink($source_path);

        // Update database record
        $wpdb->update($table, [
            'status'      => 'restored',
            'restored_at' => current_time('mysql')
        ], ['id' => $quarantine_id]);

        // If issue exists, set status back to open
        $issues_table = $wpdb->prefix . 'wcpscan_scan_issues';
        if (!empty($record['issue_id'])) {
            $wpdb->update($issues_table, ['status' => 'open'], ['id' => (int) $record['issue_id']]);
        }
        if (!empty($record['original_path'])) {
            $wpdb->update($issues_table, ['status' => 'open'], ['file_path' => $record['original_path']]);
        }

        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('vault_quarantine_restored', [
                'severity' => 'warning',
                'message'  => sprintf(__('A file in security quarantine was restored back to the active filesystem: "%s".', 'wcp-security-scanner'), $dest_path),
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
        $table = $wpdb->prefix . 'wcpscan_quarantine';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $wpdb->get_results("SELECT * FROM `{$table}` ORDER BY id DESC", ARRAY_A);
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
                        @unlink($cand);
                    }
                }
            }
        }

        if (!empty($duplicate_ids)) {
            $ids_sql = implode(',', $duplicate_ids);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("DELETE FROM `{$table}` WHERE id IN ({$ids_sql})");
        }

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
        $table = $wpdb->prefix . 'wcpscan_quarantine';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $restored = $wpdb->get_results("SELECT id, quarantine_filename FROM `{$table}` WHERE status = 'restored'", ARRAY_A);
        if (!empty($restored)) {
            foreach ($restored as $r) {
                if (!empty($r['quarantine_filename'])) {
                    $cand = $this->quarantine_dir . '/' . $r['quarantine_filename'];
                    if (file_exists($cand)) {
                        @unlink($cand);
                    }
                }
            }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("DELETE FROM `{$table}` WHERE status = 'restored'");
            return [
                'success' => true,
                'message' => sprintf(__('Cleared %d restored history log entries. (Live website files remain untouched).', 'wcp-security-scanner'), count($restored))
            ];
        }
        return [
            'success' => true,
            'message' => __('No restored records to clear.', 'wcp-security-scanner')
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
        $table = $wpdb->prefix . 'wcpscan_quarantine';
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table}` WHERE id = %d", (int) $quarantine_id), ARRAY_A);
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
                @unlink($cand);
            }
        }

        $wpdb->delete($table, ['id' => (int) $quarantine_id]);

        // When permanently deleting an active quarantined threat, mark matching scan issues as repaired
        if (!$was_restored) {
            $issues_table = $wpdb->prefix . 'wcpscan_scan_issues';
            if (!empty($record['issue_id'])) {
                $wpdb->update($issues_table, ['status' => 'repaired'], ['id' => (int) $record['issue_id']]);
            }
            if (!empty($record['original_path'])) {
                $wpdb->update($issues_table, ['status' => 'repaired'], ['file_path' => $record['original_path']]);
            }

            if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('vault_quarantine_deleted', [
                    'severity' => 'info',
                    'message'  => sprintf(__('Quarantined file was permanently purged from vault storage: "%s".', 'wcp-security-scanner'), $record['original_path'] ?? 'unknown'),
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
