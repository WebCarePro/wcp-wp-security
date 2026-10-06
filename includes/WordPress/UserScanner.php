<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class UserScanner {

    /**
     * Inspect users, administrator accounts, capabilities, password strength, and detect orphaned authors.
     *
     * @param string $scan_id
     * @param bool $admins_only
     * @return Finding[]
     */
    public function scan($scan_id, $admins_only = false) {
        global $wpdb;
        $findings = [];
        $users_table = $wpdb->prefix . 'users';
        $posts_table = $wpdb->prefix . 'posts';

        // Common weak passwords to audit against hashes
        $common_passwords = [
            'password', '123456', '12345678', '123456789', 'admin', 'admin123', 
            'root', 'welcome', 'qwerty', 'login', 'pass123', 'wordpress', 'master'
        ];

        // 1. Scan administrator accounts
        $admins = get_users(['role' => 'administrator']);
        
        foreach ($admins as $admin) {
            $login = strtolower($admin->user_login);
            // Flag weak or generic admin usernames common in automated attacks
            $generic_logins = ['admin', 'administrator', 'root', 'support', 'test', 'temp', 'backup', 'system', 'wp_admin', 'webmaster'];
            if (in_array($login, $generic_logins)) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'generic_admin_username',
                    'severity'    => 'low',
                    'confidence'  => 90,
                    'file_path'   => "user:{$admin->ID} ({$admin->user_login})",
                    'description' => "Administrator account uses a generic/predictable username '{$admin->user_login}'. High target for brute-force attacks.",
                    'evidence'    => "User ID: {$admin->ID}, Login: {$admin->user_login}, Email: {$admin->user_email}"
                ]);
            }
        }

        // 2. Audit Password Strength & Credentials
        $users_to_audit = $admins_only ? $admins : get_users(['number' => 200]);
        foreach ($users_to_audit as $user) {
            $test_passwords = array_merge($common_passwords, [
                $user->user_login,
                strtolower($user->user_login),
                $user->user_email,
                explode('@', $user->user_email)[0]
            ]);

            foreach ($test_passwords as $weak_pwd) {
                if (empty($weak_pwd) || strlen($weak_pwd) < 3) continue;

                if (wp_check_password($weak_pwd, $user->user_pass, $user->ID)) {
                    $is_admin = in_array('administrator', (array) $user->roles);
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-users',
                        'type'        => 'weak_password_detected',
                        'severity'    => $is_admin ? 'critical' : 'high',
                        'confidence'  => 100,
                        'file_path'   => "user:{$user->ID} ({$user->user_login})",
                        'description' => ($is_admin ? "CRITICAL: Administrator account" : "User account") . " '{$user->user_login}' has a dangerously weak/predictable password.",
                        'evidence'    => "Password matched common dictionary term or username. Immediate password reset required."
                    ]);
                    break;
                }
            }

            // Display Name matches User Login (Username enumeration leak)
            if ($user->display_name === $user->user_login) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'username_enumeration_risk',
                    'severity'    => 'low',
                    'confidence'  => 85,
                    'file_path'   => "user:{$user->ID} ({$user->user_login})",
                    'description' => "Public display name is identical to login username '{$user->user_login}'. Reveals account username to site visitors.",
                    'evidence'    => "Display name equals login: {$user->user_login}"
                ]);
            }
        }

        // 3. Detect users with administrative capabilities without standard administrator role (Privilege Escalation)
        $all_users = get_users(['number' => 200]);
        foreach ($all_users as $user) {
            $roles = (array) $user->roles;
            if (!in_array('administrator', $roles) && $user->has_cap('manage_options')) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'privilege_escalation_risk',
                    'severity'    => 'high',
                    'confidence'  => 95,
                    'file_path'   => "user:{$user->ID} ({$user->user_login})",
                    'description' => "User has administrative capability ('manage_options') without holding the standard Administrator role.",
                    'evidence'    => "User: {$user->user_login}, Roles: " . implode(', ', $roles)
                ]);
            }
        }

        // 3. Orphaned Post Author Detection
        // Find posts authored by IDs that don't exist in wp_users
        $orphaned = $wpdb->get_results(
            "SELECT p.ID, p.post_title, p.post_type, p.post_author 
             FROM {$posts_table} p 
             LEFT JOIN {$users_table} u ON p.post_author = u.ID 
             WHERE u.ID IS NULL AND p.post_status IN ('publish', 'future', 'draft') 
             LIMIT 50"
        );

        if (!empty($orphaned)) {
            foreach ($orphaned as $post) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'orphaned_post_author',
                    'severity'    => 'medium',
                    'confidence'  => 95,
                    'file_path'   => "post:{$post->ID} ({$post->post_type})",
                    'description' => "Post references non-existent author user ID ({$post->post_author}). May indicate deleted accounts or unauthorized database manipulation.",
                    'evidence'    => "Post ID: {$post->ID}, Missing Author ID: {$post->post_author}"
                ]);
            }
        }

        return $findings;
    }
}
