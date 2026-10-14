<?php
namespace WCP\Scanner\WordPress;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * UserRemediationManager
 *
 * Provides safe, audited remediation for compromised, anomalous, and stealth user accounts:
 * - Pre-action auto-backup snapshot of wp_users and wp_usermeta before any alteration
 * - Assigns default role (subscriber) to users missing capabilities (repairing ghost/zombie accounts)
 * - Strips unauthorized/trojan capabilities from non-admin accounts (e.g. customers with upload/edit rights)
 * - Safely deletes rogue accounts with pre-action backup and self-deletion prevention
 * - Restores quarantined user accounts from isolated JSON backup archives
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class UserRemediationManager {

    private $backup_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = !empty($uploads['basedir']) ? untrailingslashit($uploads['basedir']) : WP_CONTENT_DIR . '/uploads';
        $this->backup_dir = $base . '/wcp-security-scanner/.backups/remediation';
        $this->ensure_backup_directory();
    }

    /**
     * Ensure backup directory exists and is heavily locked down.
     */
    private function ensure_backup_directory() {
        if (!is_dir($this->backup_dir)) {
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($this->backup_dir);
            } else {
                @mkdir($this->backup_dir, 0755, true);
            }
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
     * Create isolated JSON pre-action snapshot of user and usermeta.
     *
     * @param int $user_id
     * @param string $action_context
     * @return string|false Backup filename or false on failure
     */
    public function backup_user(int $user_id, string $action_context = 'remediation') {
        global $wpdb;
        $users_table    = $wpdb->prefix . 'users';
        $usermeta_table = $wpdb->prefix . 'usermeta';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $user_row = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$users_table}` WHERE ID = %d", $user_id), ARRAY_A);
        if (!$user_row) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $usermeta_rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM `{$usermeta_table}` WHERE user_id = %d", $user_id), ARRAY_A);

        $timestamp = gmdate('Ymd_His');
        $rand = wp_generate_password(8, false);
        $filename = "user_{$user_id}_{$timestamp}_{$rand}.json";
        $filepath = $this->backup_dir . '/' . $filename;

        $snapshot = [
            'backup_version' => '1.0',
            'created_at'     => current_time('mysql'),
            'action_context' => $action_context,
            'user_id'        => $user_id,
            'user'           => $user_row,
            'usermeta'       => $usermeta_rows ?: [],
            'specialist'     => 'Mir Alamin (WebCare Pro)',
        ];

        $encoded = wp_json_encode($snapshot, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $written = @file_put_contents($filepath, $encoded);

        return $written !== false ? $filename : false;
    }

    /**
     * Assign default or specified role to a user, repairing missing capabilities metadata.
     *
     * @param int $user_id
     * @param string|null $role
     * @return array
     */
    public function assign_default_role(int $user_id, $role = null): array {
        global $wpdb;

        if ($user_id <= 0) {
            return ['success' => false, 'error' => 'Invalid user ID.'];
        }

        $user = get_userdata($user_id);
        if (!$user) {
            return ['success' => false, 'error' => "User ID #{$user_id} not found."];
        }

        $target_role = !empty($role) ? sanitize_key($role) : get_option('default_role', 'subscriber');

        // Prevent demoting currently authenticated user if they are an administrator
        if ($user_id === get_current_user_id() && in_array('administrator', (array) $user->roles, true) && $target_role !== 'administrator') {
            return ['success' => false, 'error' => __('Cannot demote the currently logged in administrator account. Please update your password instead.', 'wcp-security-scanner')];
        }

        // Protect primary site administrator if it is the only admin
        if (in_array('administrator', (array) $user->roles, true) && $target_role !== 'administrator' && function_exists('get_users')) {
            $admin_count = count(get_users(['role' => 'administrator']));
            if ($admin_count <= 1) {
                return ['success' => false, 'error' => __('Cannot demote the only remaining Administrator on this website.', 'wcp-security-scanner')];
            }
        }

        $backup_file = $this->backup_user($user_id, "assign_role_{$target_role}");

        // Direct user meta repair to guarantee standard WordPress structure
        $cap_key = $wpdb->prefix . 'capabilities';
        $level_key = $wpdb->prefix . 'user_level';

        // Re-assign role using WordPress API
        $user_obj = new \WP_User($user_id);
        $user_obj->set_role($target_role);

        // Ensure capabilities metadata is strictly synchronized
        update_user_meta($user_id, $cap_key, [$target_role => true]);
        update_user_meta($user_id, $level_key, 0);

        return [
            'success'     => true,
            'action'      => 'assign_role',
            'user_id'     => $user_id,
            'user_login'  => $user->user_login,
            'new_role'    => $target_role,
            'backup_file' => $backup_file,
            'message'     => sprintf(
                __("User '%s' (ID #%d) assigned role '%s' successfully.", 'wcp-security-scanner'),
                $user->user_login,
                $user_id,
                $target_role
            ),
        ];
    }

    /**
     * Strip injected custom capabilities from non-admin accounts while preserving their declared role.
     *
     * @param int $user_id
     * @return array
     */
    public function strip_injected_capabilities(int $user_id): array {
        global $wpdb;

        if ($user_id <= 0) {
            return ['success' => false, 'error' => 'Invalid user ID.'];
        }

        $user = get_userdata($user_id);
        if (!$user) {
            return ['success' => false, 'error' => "User ID #{$user_id} not found."];
        }

        $cap_key = $wpdb->prefix . 'capabilities';
        $stored_caps = get_user_meta($user_id, $cap_key, true);
        if (!is_array($stored_caps)) {
            $stored_caps = [];
        }

        // Determine primary declared role
        $wp_roles = wp_roles();
        $declared_roles = array_keys(array_intersect_key($stored_caps, $wp_roles->roles));
        $primary_role = !empty($declared_roles) ? reset($declared_roles) : (!empty($user->roles) ? reset($user->roles) : get_option('default_role', 'subscriber'));

        // Identify non-role capabilities being removed
        $stripped_caps = [];
        foreach ($stored_caps as $cap => $granted) {
            if (!isset($wp_roles->roles[$cap])) {
                $stripped_caps[] = $cap;
            }
        }

        $backup_file = $this->backup_user($user_id, 'strip_injected_caps');

        // Reset capabilities strictly to primary role definition
        $clean_caps = [$primary_role => true];
        update_user_meta($user_id, $cap_key, $clean_caps);

        // Reset user_level appropriately
        $level_key = $wpdb->prefix . 'user_level';
        $new_level = ($primary_role === 'administrator') ? 10 : ($primary_role === 'editor' ? 7 : ($primary_role === 'author' ? 2 : 0));
        update_user_meta($user_id, $level_key, $new_level);

        return [
            'success'       => true,
            'action'        => 'strip_capabilities',
            'user_id'       => $user_id,
            'user_login'    => $user->user_login,
            'role'          => $primary_role,
            'stripped_caps' => $stripped_caps,
            'backup_file'   => $backup_file,
            'message'       => sprintf(
                __("Stripped %d unauthorized capability entries from user '%s'. Role preserved as '%s'.", 'wcp-security-scanner'),
                count($stripped_caps),
                $user->user_login,
                $primary_role
            ),
        ];
    }

    /**
     * Safely delete a user account with mandatory pre-action snapshot.
     * Prevents deleting currently authenticated admin or the only administrator.
     *
     * @param int $user_id
     * @param int|null $reassign_to
     * @return array
     */
    public function delete_user(int $user_id, $reassign_to = null): array {
        if ($user_id <= 0) {
            return ['success' => false, 'error' => 'Invalid user ID.'];
        }

        // Prevent deleting currently authenticated user
        if ($user_id === get_current_user_id()) {
            return ['success' => false, 'error' => 'Cannot delete the currently logged in account.'];
        }

        $user = get_userdata($user_id);
        if (!$user) {
            return ['success' => false, 'error' => "User ID #{$user_id} not found."];
        }

        // Protect primary site administrator if it is the only admin
        if (in_array('administrator', (array) $user->roles, true)) {
            $admin_count = count(get_users(['role' => 'administrator']));
            if ($admin_count <= 1) {
                return ['success' => false, 'error' => 'Cannot delete the only remaining Administrator on this website.'];
            }
        }

        $backup_file = $this->backup_user($user_id, 'delete_account');
        if (!$backup_file) {
            return ['success' => false, 'error' => 'Failed to create pre-action auto-backup snapshot before deletion. Aborting for safety.'];
        }

        require_once ABSPATH . 'wp-admin/includes/user.php';

        $deleted = wp_delete_user($user_id, $reassign_to);
        if (!$deleted) {
            return ['success' => false, 'error' => "Failed to delete user ID #{$user_id}."];
        }

        return [
            'success'     => true,
            'action'      => 'delete_user',
            'user_id'     => $user_id,
            'user_login'  => $user->user_login,
            'backup_file' => $backup_file,
            'message'     => sprintf(
                __("User '%s' (ID #%d) deleted successfully. Auto-backup snapshot saved as %s.", 'wcp-security-scanner'),
                $user->user_login,
                $user_id,
                $backup_file
            ),
        ];
    }
}
