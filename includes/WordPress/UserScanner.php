<?php
namespace WcpScanner\WordPress;

use WcpScanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * UserScanner
 *
 * Comprehensive WordPress User Accounts, Roles & Capability Auditor:
 * 1. Audits administrator accounts for generic/predictable usernames.
 * 2. Checks password strength against high-frequency attack dictionaries.
 * 3. Detects username enumeration vulnerabilities on privileged accounts.
 * 4. Uncovers "Trojan Customer" attacks & Stealth Privilege Escalation:
 *    - Users displaying as Customer / Subscriber but holding upload_files, edit_files, or admin capabilities.
 *    - Injected per-user custom capabilities exceeding declared role permissions (e.g. via Role Editor plugins or raw SQL).
 * 5. Identifies "user_missing_capabilities" (users in wp_users lacking wp_capabilities in wp_usermeta).
 * 6. Audits global role definitions in wp_user_roles for poisoned/tampered low-privilege roles.
 * 7. Detects orphaned post authors referencing non-existent user IDs.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class UserScanner {

    /**
     * Dangerous administrative capabilities that should NEVER belong to non-administrators.
     */
    private const ADMIN_LEVEL_CAPS = [
        'manage_options'     => 'Manage Site Options & Configuration',
        'activate_plugins'   => 'Activate Plugins',
        'edit_plugins'       => 'Directly Edit Plugin PHP Files',
        'install_plugins'    => 'Install Plugins from Repository or ZIP',
        'update_plugins'     => 'Update Plugin Files',
        'delete_plugins'     => 'Delete Plugin Files',
        'edit_themes'        => 'Directly Edit Theme PHP Templates',
        'install_themes'     => 'Install Themes',
        'update_themes'      => 'Update Theme Files',
        'delete_themes'      => 'Delete Themes',
        'switch_themes'      => 'Switch Active Theme',
        'edit_files'         => 'Direct Filesystem Edit Rights',
        'unfiltered_html'    => 'Inject Raw Unsanitized HTML/JavaScript (Stored XSS)',
        'unfiltered_upload'  => 'Upload Executable Files Bypassing MIME Checks',
        'edit_users'         => 'Edit Other User Accounts & Passwords',
        'delete_users'       => 'Delete User Accounts',
        'create_users'       => 'Create New User Accounts',
        'promote_users'      => 'Promote Users to Administrator',
        'remove_users'       => 'Remove Users from Site',
        'export'             => 'Export Complete Site Database & Content',
        'import'             => 'Import Site Content & Media',
        'update_core'        => 'Execute WordPress Core System Updates',
    ];

    /**
     * Upload & publishing capabilities that should NEVER belong to subscriber/customer accounts.
     */
    private const ELEVATED_CONTENT_CAPS = [
        'upload_files'        => 'Upload Media & Files (Webshell Injection Vector)',
        'edit_posts'          => 'Create and Edit Posts',
        'publish_posts'       => 'Publish Live Posts',
        'edit_others_posts'   => 'Tamper With Other Authors\' Posts',
        'delete_others_posts' => 'Delete Other Authors\' Posts',
        'delete_posts'        => 'Delete Posts',
        'edit_pages'          => 'Create and Edit Pages',
        'publish_pages'       => 'Publish Live Pages',
        'delete_pages'        => 'Delete Pages',
    ];

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
        $users_table    = $wpdb->prefix . 'users';
        $usermeta_table = $wpdb->prefix . 'usermeta';
        $posts_table    = $wpdb->prefix . 'posts';
        $cap_key        = $wpdb->prefix . 'capabilities';

        // Common weak passwords to audit against hashes
        $common_passwords = [
            'password', '123456', '12345678', '123456789', 'admin', 'admin123', 
            'root', 'welcome', 'qwerty', 'login', 'pass123', 'wordpress', 'master'
        ];

        // 1. Scan administrator accounts for predictable usernames
        $admins = get_users(['role' => 'administrator']);
        
        foreach ($admins as $admin) {
            $login = strtolower($admin->user_login);
            $generic_logins = ['admin', 'administrator', 'root', 'support', 'test', 'temp', 'backup', 'system', 'wp_admin', 'webmaster'];
            if (in_array($login, $generic_logins, true)) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'generic_admin_username',
                    'severity'    => 'low',
                    'confidence'  => 90,
                    'file_path'   => "user:{$admin->ID} ({$admin->user_login})",
                    'description' => "Administrator account uses a generic/predictable username '{$admin->user_login}'. High target for automated credential stuffing and brute-force attacks.",
                    'evidence'    => "User ID: {$admin->ID}, Login: {$admin->user_login}, Email: {$admin->user_email}"
                ]);
            }
        }

        // 2. Audit Password Strength & Credentials
        $users_to_audit = $admins_only ? $admins : get_users(['number' => 300]);
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
                    $is_admin = in_array('administrator', (array) $user->roles, true);
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

            // Display Name matches User Login (Username enumeration leak) - restrict to elevated/privileged accounts
            $roles = (array) $user->roles;
            $privileged_roles = ['administrator', 'editor', 'author', 'shop_manager'];
            $has_privileged_role = !empty(array_intersect($roles, $privileged_roles)) || $user->has_cap('edit_posts');

            if ($has_privileged_role && $user->display_name === $user->user_login) {
                $role_label = implode(', ', $roles) ?: 'privileged';
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'username_enumeration_risk',
                    'severity'    => 'low',
                    'confidence'  => 85,
                    'file_path'   => "user:{$user->ID} ({$user->user_login})",
                    'description' => "Privileged account ({$role_label}) has public display name identical to login username '{$user->user_login}'. Exposes username to enumeration and brute-force attacks.",
                    'evidence'    => "Display name equals login: {$user->user_login} (Roles: {$role_label})"
                ]);
            }
        }

        // 3. Detect "user_missing_capabilities" (Users in wp_users lacking wp_capabilities in wp_usermeta)
        $hidden_sql = "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM `{$users_table}` u LEFT JOIN `{$usermeta_table}` m ON (u.ID = m.user_id AND m.meta_key = '{$cap_key}') WHERE m.meta_value IS NULL LIMIT 100";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $hidden_users = $wpdb->get_results($hidden_sql);

        if (!empty($hidden_users)) {
            foreach ($hidden_users as $u) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'user_missing_capabilities',
                    'severity'    => 'medium',
                    'confidence'  => 95,
                    'file_path'   => "user:{$u->ID} ({$u->user_login})",
                    'description' => "User '{$u->user_login}' exists in database ({$users_table}) but lacks standard '{$cap_key}' metadata in {$usermeta_table}. Ghost account without declared role; often injected by raw SQL backdoors.",
                    'evidence'    => "User ID: {$u->ID}, Email: {$u->user_email}, Registered: {$u->user_registered}"
                ]);
            }
        }

        // 4. Detect "Trojan Customer" & Injected Capabilities on Non-Administrators
        // Audits users who display as a normal role (customer, subscriber, contributor, etc.)
        // but have been given file upload, file editing, or administrative powers
        $wp_roles = wp_roles();
        $all_users = get_users(['number' => 500]);

        foreach ($all_users as $user) {
            $roles = (array) $user->roles;
            $is_admin = in_array('administrator', $roles, true);

            // Fetch raw stored capabilities directly from database to catch per-user custom injections
            $raw_meta = get_user_meta($user->ID, $cap_key, true);
            $stored_caps = is_array($raw_meta) ? $raw_meta : [];

            // A. Check for Administrative Powers on Non-Admin Users (CRITICAL)
            if (!$is_admin) {
                $found_admin_caps = [];
                foreach (self::ADMIN_LEVEL_CAPS as $cap => $label) {
                    if ($user->has_cap($cap) || !empty($stored_caps[$cap])) {
                        $found_admin_caps[$cap] = $label;
                    }
                }

                if (!empty($found_admin_caps)) {
                    $cap_names = implode(', ', array_keys($found_admin_caps));
                    $display_role = !empty($roles) ? implode(', ', $roles) : 'none';

                    $findings[] = new Finding([
                        'engine'      => 'wordpress-users',
                        'type'        => 'suspicious_user_capabilities',
                        'severity'    => 'critical',
                        'confidence'  => 98,
                        'file_path'   => "user:{$user->ID} ({$user->user_login})",
                        'description' => sprintf(
                            /* translators: 1: username, 2: display role, 3: count of admin capabilities, 4: list of capability names, 5: display role */
                            __('CRITICAL: User \'%1$s\' has display role \'%2$s\' but holds %3$d administrative capability(ies): [%4$s]. In the WordPress Users list this account appears as an ordinary %5$s, but secretly possesses administrative powers.', 'wcp-security-scanner'),
                            $user->user_login,
                            $display_role,
                            count($found_admin_caps),
                            $cap_names,
                            $display_role
                        ),
                        'evidence'    => "User ID: {$user->ID}, Display Role: {$display_role}, Injected Admin Caps: [{$cap_names}], Email: {$user->user_email}, Registered: {$user->user_registered}"
                    ]);
                    continue; // Already flagged as critical
                }
            }

            // B. Check for Upload & Content Rights on Low-Privilege Roles (Subscriber, Customer, Contributor)
            $low_privilege_roles = ['subscriber', 'customer', 'contributor'];
            $is_low_privilege = !empty(array_intersect($roles, $low_privilege_roles)) || empty($roles);

            if ($is_low_privilege && !$is_admin) {
                $found_content_caps = [];
                foreach (self::ELEVATED_CONTENT_CAPS as $cap => $label) {
                    if ($user->has_cap($cap) || !empty($stored_caps[$cap])) {
                        // Allow contributor to edit_posts / delete_posts as standard
                        if (in_array('contributor', $roles, true) && in_array($cap, ['edit_posts', 'delete_posts'], true)) {
                            continue;
                        }
                        $found_content_caps[$cap] = $label;
                    }
                }

                if (!empty($found_content_caps)) {
                    $cap_names = implode(', ', array_keys($found_content_caps));
                    $display_role = !empty($roles) ? implode(', ', $roles) : 'none';
                    $has_upload = isset($found_content_caps['upload_files']);

                    $findings[] = new Finding([
                        'engine'      => 'wordpress-users',
                        'type'        => 'suspicious_user_capabilities',
                        'severity'    => $has_upload ? 'critical' : 'high',
                        'confidence'  => 95,
                        'file_path'   => "user:{$user->ID} ({$user->user_login})",
                        'description' => sprintf(
                            /* translators: 1: username, 2: role, 3: list of capabilities, 4: permission name */
                            __('HIGH RISK: User \'%1$s\' has role \'%2$s\' but possesses elevated privileges: [%3$s]. Subscribers and Customers should NEVER have \'%4$s\' permission.', 'wcp-security-scanner'),
                            $user->user_login,
                            $display_role,
                            $cap_names,
                            $has_upload ? 'upload_files' : $cap_names
                        ),
                        'evidence'    => "User ID: {$user->ID}, Role: {$display_role}, Injected Capabilities: [{$cap_names}], Email: {$user->user_email}, Registered: {$user->user_registered}"
                    ]);
                    continue;
                }
            }

            // C. Detect Injected Custom Capabilities Exceeding Declared Role Definition
            if (!$is_admin && !empty($roles)) {
                $primary_role = reset($roles);
                $role_def = $wp_roles->get_role($primary_role);
                $role_standard_caps = $role_def ? (array) $role_def->capabilities : [];

                $extra_caps = [];
                foreach ($stored_caps as $c => $granted) {
                    if ($granted && !isset($wp_roles->roles[$c]) && empty($role_standard_caps[$c])) {
                        $extra_caps[] = $c;
                    }
                }

                if (!empty($extra_caps)) {
                    $extra_list = implode(', ', array_slice($extra_caps, 0, 8));
                    if (count($extra_caps) > 8) {
                        /* translators: %d: count of remaining capabilities */
                        $extra_list .= sprintf(__(' (+%d more)', 'wcp-security-scanner'), count($extra_caps) - 8);
                    }

                    $findings[] = new Finding([
                        'engine'      => 'wordpress-users',
                        'type'        => 'injected_user_capabilities',
                        'severity'    => 'medium',
                        'confidence'  => 90,
                        'file_path'   => "user:{$user->ID} ({$user->user_login})",
                        'description' => sprintf(
                            /* translators: 1: username, 2: role, 3: count of capabilities, 4: list of custom capabilities */
                            __('User \'%1$s\' (role: %2$s) has %3$d custom capability entry(ies) explicitly assigned: [%4$s]. May indicate role editor customization or stealth capability injection.', 'wcp-security-scanner'),
                            $user->user_login,
                            $primary_role,
                            count($extra_caps),
                            $extra_list
                        ),
                        'evidence'    => "User ID: {$user->ID}, Role: {$primary_role}, Custom Caps: [{$extra_list}]"
                    ]);
                }
            }
        }

        // 5. Audit Global Role Definitions in wp_user_roles (wp_options)
        // Detect if subscriber or customer role definition itself was tampered with globally
        $global_roles = get_option($wpdb->prefix . 'user_roles');
        if (is_array($global_roles)) {
            $check_roles = ['subscriber', 'customer'];
            $forbidden_global_caps = [
                'upload_files', 'edit_plugins', 'edit_themes', 'edit_files', 
                'manage_options', 'unfiltered_html', 'activate_plugins', 'edit_users'
            ];

            foreach ($check_roles as $r_name) {
                if (isset($global_roles[$r_name]['capabilities']) && is_array($global_roles[$r_name]['capabilities'])) {
                    $r_caps = $global_roles[$r_name]['capabilities'];
                    $poisoned = [];
                    foreach ($forbidden_global_caps as $f_cap) {
                        if (!empty($r_caps[$f_cap])) {
                            $poisoned[] = $f_cap;
                        }
                    }

                    if (!empty($poisoned)) {
                        $p_list = implode(', ', $poisoned);
                        $findings[] = new Finding([
                            'engine'      => 'wordpress-users',
                            'type'        => 'tampered_role_definition',
                            'severity'    => 'critical',
                            'confidence'  => 99,
                            'file_path'   => "wp_options:{$wpdb->prefix}user_roles [Role: {$r_name}]",
                            'description' => sprintf(
                                /* translators: 1: role name, 2: list of capabilities, 3: role name */
                                __('CRITICAL: Global role definition for \'%1$s\' in wp_user_roles has been compromised to grant dangerous capability(ies): [%2$s]. Every single user with role \'%3$s\' automatically receives this permission.', 'wcp-security-scanner'),
                                $r_name,
                                $p_list,
                                $r_name
                            ),
                            'evidence'    => "Role: {$r_name}, Compromised Capabilities: [{$p_list}], Stored in option: {$wpdb->prefix}user_roles"
                        ]);
                    }
                }
            }
        }

        // 6. Orphaned Post Author Detection
        $excluded_post_types = [
            'wp_navigation', 'wp_template', 'wp_template_part', 'wp_global_styles', 
            'nav_menu_item', 'revision', 'attachment', 'custom_css', 'oembed_cache',
            'wplconsentlogs', 'custom-css-js', 'action_log'
        ];
        $orphaned_sql = "SELECT p.ID, p.post_title, p.post_name, p.post_type, p.post_status, p.post_date, p.post_author FROM `{$posts_table}` p LEFT JOIN `{$users_table}` u ON p.post_author = u.ID WHERE u.ID IS NULL AND p.post_author > 0 AND p.post_type NOT IN ('{$post_type_placeholders}') AND p.post_status IN ('publish', 'future', 'draft') LIMIT 500";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $orphaned = $wpdb->get_results($orphaned_sql);

        if (!empty($orphaned)) {
            $grouped_orphans = [];
            foreach ($orphaned as $post) {
                $author_id = (int) $post->post_author;
                if (!isset($grouped_orphans[$author_id])) {
                    $grouped_orphans[$author_id] = [
                        'count'         => 0,
                        'types'         => [],
                        'sample_id'     => (int) $post->ID,
                        'sample_title'  => !empty($post->post_title) ? $post->post_title : __('(Untitled Post)', 'wcp-security-scanner'),
                        'sample_slug'   => !empty($post->post_name) ? $post->post_name : '',
                        'sample_type'   => $post->post_type,
                        'sample_status' => $post->post_status,
                        'sample_date'   => $post->post_date,
                        'posts'         => [],
                    ];
                }
                $grouped_orphans[$author_id]['count']++;
                if (!in_array($post->post_type, $grouped_orphans[$author_id]['types'], true)) {
                    $grouped_orphans[$author_id]['types'][] = $post->post_type;
                }
                if (count($grouped_orphans[$author_id]['posts']) < 5) {
                    $grouped_orphans[$author_id]['posts'][] = [
                        'id'     => (int) $post->ID,
                        'title'  => !empty($post->post_title) ? $post->post_title : __('(Untitled Post)', 'wcp-security-scanner'),
                        'slug'   => !empty($post->post_name) ? $post->post_name : '',
                        'type'   => $post->post_type,
                        'status' => $post->post_status,
                    ];
                }
            }

            foreach ($grouped_orphans as $author_id => $data) {
                $types_str = implode(', ', $data['types']);
                $meta_json = wp_json_encode([
                    'author_id'     => $author_id,
                    'count'         => $data['count'],
                    'types'         => $data['types'],
                    'sample_id'     => $data['sample_id'],
                    'sample_title'  => $data['sample_title'],
                    'sample_slug'   => $data['sample_slug'],
                    'sample_type'   => $data['sample_type'],
                    'sample_status' => $data['sample_status'],
                    'posts'         => $data['posts'],
                ]);
                $findings[] = new Finding([
                    'engine'      => 'wordpress-users',
                    'type'        => 'orphaned_post_author',
                    'severity'    => 'medium',
                    'confidence'  => 95,
                    'file_path'   => "author:{$author_id}",
                    'description' => "{$data['count']} post(s) [type(s): {$types_str}] reference non-existent author user ID ({$author_id}). Sample: Post #{$data['sample_id']} ('{$data['sample_title']}'). May indicate deleted accounts or database integrity issues.",
                    'evidence'    => "Author ID: {$author_id}, Affected Posts: {$data['count']}, Types: {$types_str} | Meta: {$meta_json}"
                ]);
            }
        }

        return $findings;
    }
}
