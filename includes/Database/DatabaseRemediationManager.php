<?php
namespace WcpScanner\Database;

if (!defined('ABSPATH')) {
    exit;
}

class DatabaseRemediationManager {

    private $backup_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = untrailingslashit($uploads['basedir']);
        $this->backup_dir = $base . '/wcp-security-scanner/.backups/remediation';
        $this->ensure_backup_directory();
    }

    /**
     * Ensure backup directory exists and is heavily locked down.
     */
    private function ensure_backup_directory() {
        if (!is_dir($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
        }

        $htaccess = $this->backup_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# Block all public access\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n<FilesMatch \".*\">\n    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n    <IfModule !mod_authz_core.c>\n        Order deny,allow\n        Deny from all\n    </IfModule>\n</FilesMatch>\n";
            @file_put_contents($htaccess, $rules);
        }

        $index = $this->backup_dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WCP Security: Direct access forbidden.');\n");
        }
    }

    /**
     * Validate table and column names to prevent SQL injection.
     */
    private function validate_identifier($name) {
        return (bool) preg_match('/^[a-zA-Z0-9_]+$/', $name);
    }

    /**
     * Retrieve primary key and column metadata for a database table.
     */
    public function get_primary_key($table) {
        global $wpdb;
        if (!$this->validate_identifier($table)) {
            return null;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $cols = $wpdb->get_results("SHOW COLUMNS FROM `{$table}`");
        if (empty($cols)) {
            return null;
        }

        foreach ($cols as $col) {
            if ($col->Key === 'PRI') {
                return $col->Field;
            }
        }

        // Fallback: check for standard id column names
        foreach ($cols as $col) {
            if (in_array(strtolower($col->Field), ['id', 'comment_id', 'post_id', 'user_id', 'option_id'], true)) {
                return $col->Field;
            }
        }

        return null;
    }

    /**
     * Fetch a single database row by primary key or ID.
     */
    public function get_row($table, $row_id) {
        global $wpdb;
        if (!$this->validate_identifier($table)) {
            return null;
        }

        $pk = $this->get_primary_key($table);
        if (!$pk) {
            return null;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table}` WHERE `{$pk}` = %s", $row_id), ARRAY_A);
    }

    /**
     * Create an auto-backup snapshot of a database row before remediation.
     */
    public function create_row_backup($table, $pk, $row_id, $column = '', $action = 'delete_row', $issue_id = null) {
        $row_data = $this->get_row($table, $row_id);
        if (!$row_data) {
            return false;
        }

        $rand = function_exists('wp_generate_password') ? wp_generate_password(6, false) : bin2hex(random_bytes(3));
        $backup_id = 'db_' . $table . '_' . $row_id . '_' . gmdate('Ymd_His') . '_' . $rand;
        $backup_file = $this->backup_dir . '/' . $backup_id . '.json';

        $payload = [
            'backup_id'    => $backup_id,
            'type'         => 'database_row',
            'action'       => $action,
            'table'        => $table,
            'primary_key'  => $pk,
            'row_id'       => $row_id,
            'column'       => $column,
            'issue_id'     => $issue_id,
            'created_at'   => function_exists('current_time') ? current_time('mysql') : gmdate('Y-m-d H:i:s'),
            'user_id'      => function_exists('get_current_user_id') ? get_current_user_id() : 0,
            'data'         => $row_data,
        ];

        $encoded = function_exists('wp_json_encode') ? wp_json_encode($payload, JSON_PRETTY_PRINT) : json_encode($payload, JSON_PRETTY_PRINT);
        $written = @file_put_contents($backup_file, $encoded);
        if ($written === false) {
            return false;
        }

        return [
            'backup_id'   => $backup_id,
            'backup_file' => $backup_file,
            'data'        => $row_data,
        ];
    }

    /**
     * Safely delete a database row with pre-action auto-backup.
     */
    public function delete_row_with_backup($table, $row_id, $column = '', $issue_id = null) {
        global $wpdb;

        if (!$this->validate_identifier($table)) {
            return ['success' => false, 'message' => 'Invalid table identifier.'];
        }

        $pk = $this->get_primary_key($table);
        if (!$pk) {
            return ['success' => false, 'message' => "Cannot determine primary key for table '{$table}'."];
        }

        // 1. Create instant snapshot auto-backup
        $backup = $this->create_row_backup($table, $pk, $row_id, $column, 'delete_row', $issue_id);
        if (!$backup) {
            return ['success' => false, 'message' => 'Failed to create pre-deletion auto-backup snapshot. Deletion aborted for safety.'];
        }

        // 2. Perform deletion
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $deleted = $wpdb->delete($table, [$pk => $row_id]);
        if ($deleted === false) {
            return ['success' => false, 'message' => "Database query failed: {$wpdb->last_error}"];
        }

        // 3. Mark scan issue as repaired if provided
        if ($issue_id) {
            $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        // Also resolve any open finding matching this exact table/row
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $update_sql = "UPDATE `{$table_issues}` SET status = 'repaired' WHERE (file_path LIKE %s OR file_path LIKE %s) AND status = 'open'";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $update_sql,
            "{$table}.%[ID: {$row_id}]%",
            "{$table}.%{$row_id}%"
        ));

        return [
            'success'     => true,
            'message'     => "Row #{$row_id} deleted successfully from '{$table}'. An auto-backup snapshot was saved to the Quarantine Vault.",
            'backup_id'   => $backup['backup_id'],
            'backup_file' => $backup['backup_file'],
            'table'       => $table,
            'row_id'      => $row_id,
        ];
    }

    /**
     * Safely cleanse / sanitize an infected column in a row with pre-action auto-backup.
     */
    public function cleanse_field_with_backup($table, $column, $row_id, $issue_id = null) {
        global $wpdb;

        if (!$this->validate_identifier($table) || !$this->validate_identifier($column)) {
            return ['success' => false, 'message' => 'Invalid table or column identifier.'];
        }

        $pk = $this->get_primary_key($table);
        if (!$pk) {
            return ['success' => false, 'message' => "Cannot determine primary key for table '{$table}'."];
        }

        // 1. Create instant snapshot auto-backup
        $backup = $this->create_row_backup($table, $pk, $row_id, $column, 'cleanse_field', $issue_id);
        if (!$backup) {
            return ['success' => false, 'message' => 'Failed to create pre-cleanse auto-backup snapshot. Operation aborted for safety.'];
        }

        // 2. Set field to empty string / safe default
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $updated = $wpdb->update($table, [$column => ''], [$pk => $row_id]);
        if ($updated === false) {
            return ['success' => false, 'message' => "Database update failed: {$wpdb->last_error}"];
        }

        // 3. Mark scan issue as repaired
        if ($issue_id) {
            $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return [
            'success'     => true,
            'message'     => "Column '{$column}' in row #{$row_id} has been sanitized. An auto-backup snapshot was saved to the Quarantine Vault.",
            'backup_id'   => $backup['backup_id'],
            'backup_file' => $backup['backup_file'],
            'table'       => $table,
            'column'      => $column,
            'row_id'      => $row_id,
        ];
    }

    /**
     * Restore a deleted database row or cleansed field from an auto-backup snapshot.
     */
    public function restore_backup($backup_id) {
        global $wpdb;

        $safe_id = function_exists('sanitize_file_name') ? sanitize_file_name($backup_id) : preg_replace('/[^a-zA-Z0-9_\-]/', '', $backup_id);
        $file = $this->backup_dir . '/' . $safe_id . '.json';
        if (!file_exists($file)) {
            return ['success' => false, 'message' => 'Backup snapshot file not found in Quarantine Vault.'];
        }

        $raw = @file_get_contents($file);
        $data = json_decode($raw, true);
        if (empty($data) || empty($data['table']) || empty($data['data'])) {
            return ['success' => false, 'message' => 'Invalid or corrupt backup snapshot payload.'];
        }

        $table = $data['table'];
        $pk = $data['primary_key'] ?? $this->get_primary_key($table);
        $row_id = $data['row_id'];
        $row_data = $data['data'];

        if (!$this->validate_identifier($table)) {
            return ['success' => false, 'message' => 'Invalid table identifier in backup.'];
        }

        // Check if row already exists
        $existing = $this->get_row($table, $row_id);
        if ($existing) {
            // Update existing row
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $res = $wpdb->update($table, $row_data, [$pk => $row_id]);
        } else {
            // Re-insert row
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $res = $wpdb->insert($table, $row_data);
        }

        if ($res === false) {
            return ['success' => false, 'message' => "Failed to restore database row: {$wpdb->last_error}"];
        }

        return [
            'success' => true,
            'message' => "Successfully restored row #{$row_id} in table '{$table}' from auto-backup snapshot.",
            'table'   => $table,
            'row_id'  => $row_id,
        ];
    }
}
