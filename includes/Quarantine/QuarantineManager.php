<?php
namespace WCP\Scanner\Quarantine;

if (!defined('ABSPATH')) {
    exit;
}

class QuarantineManager {

    private $quarantine_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = !empty($uploads['basedir']) ? untrailingslashit($uploads['basedir']) : WP_CONTENT_DIR . '/uploads';
        $this->quarantine_dir = $base . '/wcp-security-scanner/quarantine';
        $this->ensure_quarantine_directory();
    }

    /**
     * Ensure the quarantine directory exists and is heavily locked down against public web execution.
     */
    private function ensure_quarantine_directory() {
        if (!is_dir($this->quarantine_dir)) {
            wp_mkdir_p($this->quarantine_dir);
        }

        // Lock with .htaccess
        $htaccess = $this->quarantine_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# Block all public web access to quarantine\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
            @file_put_contents($htaccess, $rules);
        }

        // Lock with index.php
        $index = $this->quarantine_dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\nexit;\n");
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
        $real_root = wp_normalize_path(untrailingslashit(ABSPATH)) . '/';
        $normalized_real = wp_normalize_path($real_path);
        if (strpos($normalized_real, $real_root) !== 0) {
            return ['success' => false, 'message' => 'Security violation: File resides outside ABSPATH.'];
        }

        // Prohibit quarantining files inside core directories (wp-admin, wp-includes)
        $wp_includes_dir = wp_normalize_path(untrailingslashit(ABSPATH . WPINC)) . '/';
        $wp_admin_dir = wp_normalize_path(untrailingslashit(ABSPATH . 'wp-admin')) . '/';
        if (strpos($normalized_real, $wp_includes_dir) === 0 || strpos($normalized_real, $wp_admin_dir) === 0) {
            return [
                'success' => false,
                'message' => "Action Blocked: Core WordPress directory files cannot be quarantined directly."
            ];
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

        if (strpos($normalized_real, '/plugins/wcp-wp-scanner/') !== false || strpos($normalized_real, '/plugins/wcp-security-scanner/') !== false) {
            return [
                'success' => false,
                'message' => "Action Blocked: Cannot quarantine security scanner plugin files."
            ];
        }

        // Compute metadata before moving
        $sha256 = hash_file('sha256', $real_path);
        $file_size = filesize($real_path);
        $file_perms = substr(sprintf('%o', fileperms($real_path)), -4);

        // Generate quarantined file destination
        $safe_filename = bin2hex(random_bytes(16)) . '_' . time() . '.quarantine';
        $dest_path = $this->quarantine_dir . '/' . $safe_filename;

        // Move file into protected quarantine
        if (!@rename($real_path, $dest_path)) {
            // Fallback to copy and unlink
            if (!@copy($real_path, $dest_path)) {
                return ['success' => false, 'message' => 'Failed to move file to quarantine directory. Permission denied.'];
            }
            @unlink($real_path);
        }

        // Record in database
        $table = $wpdb->prefix . 'wcp_quarantine';
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

        // Update issue status if issue_id provided
        if ($issue_id) {
            $issues_table = $wpdb->prefix . 'wcp_scan_issues';
            $wpdb->update($issues_table, ['status' => 'quarantined'], ['id' => $issue_id]);
        }

        return [
            'success'       => true,
            'message'       => 'File successfully quarantined.',
            'quarantine_id' => $quarantine_id,
            'sha256'        => $sha256
        ];
    }

    /**
     * Restore a quarantined file back to its original location.
     *
     * @param int $quarantine_id
     * @return array ['success' => bool, 'message' => string]
     */
    public function restore_file($quarantine_id) {
        global $wpdb;
        $table = $wpdb->prefix . 'wcp_quarantine';

        $record = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE id = %d AND status = 'quarantined'",
            $quarantine_id
        ), ARRAY_A);

        if (!$record) {
            return ['success' => false, 'message' => 'Quarantine record not found or already restored.'];
        }

        $source_path = $this->quarantine_dir . '/' . $record['quarantine_filename'];
        if (!file_exists($source_path)) {
            return ['success' => false, 'message' => 'Quarantined backup file is missing from archive storage.'];
        }

        $dest_path = $record['original_path'];

        // Security check: Destination must reside within ABSPATH boundary
        $real_root = wp_normalize_path(untrailingslashit(ABSPATH)) . '/';
        $normalized_dest = wp_normalize_path($dest_path);
        if (strpos($normalized_dest, $real_root) !== 0) {
            return ['success' => false, 'message' => 'Security violation: Restore destination resides outside ABSPATH.'];
        }

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

        // Move back
        if (!@rename($source_path, $dest_path)) {
            if (!@copy($source_path, $dest_path)) {
                return ['success' => false, 'message' => 'Failed to restore file to original location.'];
            }
            @unlink($source_path);
        }

        // Restore permissions
        if ($record['file_perms']) {
            @chmod($dest_path, octdec($record['file_perms']));
        }

        // Update database record
        $wpdb->update($table, [
            'status'      => 'restored',
            'restored_at' => current_time('mysql')
        ], ['id' => $quarantine_id]);

        // If issue_id exists, set status back to open
        if ($record['issue_id']) {
            $issues_table = $wpdb->prefix . 'wcp_scan_issues';
            $wpdb->update($issues_table, ['status' => 'open'], ['id' => $record['issue_id']]);
        }

        return ['success' => true, 'message' => 'File successfully restored to original location.'];
    }

    /**
     * Retrieve all quarantine records.
     *
     * @return array
     */
    public function list_records() {
        global $wpdb;
        $table = $wpdb->prefix . 'wcp_quarantine';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $wpdb->get_results("SELECT * FROM `{$table}` ORDER BY id DESC", ARRAY_A);
        return is_array($results) ? $results : [];
    }
}
