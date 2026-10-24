<?php
namespace WcpScanner\Hardening;

if (!defined('ABSPATH')) {
    exit;
}

class PermissionHardeningManager {

    /**
     * Get active PHP web server user and group info.
     *
     * @return array
     */
    public static function get_server_user_info(): array {
        $user = 'unknown';
        $uid = 0;
        $group = 'unknown';
        $gid = 0;

        if (function_exists('posix_geteuid')) {
            $uid = posix_geteuid();
            $pw = posix_getpwuid($uid);
            if (is_array($pw) && !empty($pw['name'])) {
                $user = $pw['name'];
            } else {
                $user = (string) $uid;
            }

            if (function_exists('posix_getegid')) {
                $gid = posix_getegid();
                $gr = posix_getgrgid($gid);
                if (is_array($gr) && !empty($gr['name'])) {
                    $group = $gr['name'];
                } else {
                    $group = (string) $gid;
                }
            }
        } elseif (function_exists('get_current_user')) {
            $user = get_current_user();
            $group = $user;
        }

        // Fallback: Check owner of index.php in root
        if ($user === 'unknown' && file_exists(ABSPATH . 'index.php')) {
            $owner_id = @fileowner(ABSPATH . 'index.php');
            if ($owner_id !== false) {
                $uid = $owner_id;
                $user = 'uid_' . $owner_id;
            }
        }

        return [
            'user'  => $user,
            'uid'   => $uid,
            'group' => $group,
            'gid'   => $gid,
        ];
    }

    /**
     * Get ownership and permissions for a file/folder.
     *
     * @param string $path
     * @return array
     */
    public static function get_path_ownership(string $path): array {
        if (!file_exists($path)) {
            return [
                'exists'      => false,
                'owner_name'  => 'unknown',
                'owner_uid'   => 0,
                'group_name'  => 'unknown',
                'group_gid'   => 0,
                'is_writable' => false,
                'perms_octal' => '0000',
            ];
        }

        $owner_uid = @fileowner($path);
        $group_gid = @filegroup($path);
        $perms = @fileperms($path);

        $owner_name = (string) $owner_uid;
        $group_name = (string) $group_gid;

        if (function_exists('posix_getpwuid') && $owner_uid !== false) {
            $pw = posix_getpwuid($owner_uid);
            if (is_array($pw) && !empty($pw['name'])) {
                $owner_name = $pw['name'];
            }
        }

        if (function_exists('posix_getgrgid') && $group_gid !== false) {
            $gr = posix_getgrgid($group_gid);
            if (is_array($gr) && !empty($gr['name'])) {
                $group_name = $gr['name'];
            }
        }

        $perms_octal = $perms !== false ? substr(sprintf('%o', $perms), -4) : '0000';

        return [
            'exists'      => true,
            'owner_name'  => $owner_name,
            'owner_uid'   => $owner_uid !== false ? $owner_uid : 0,
            'group_name'  => $group_name,
            'group_gid'   => $group_gid !== false ? $group_gid : 0,
            'is_writable' => wp_is_writable($path),
            'perms_octal' => $perms_octal,
        ];
    }

    /**
     * Audit filesystem permissions and detect ownership conflicts across WordPress installation.
     *
     * @param string|null $scope_dir Target directory (defaults to ABSPATH)
     * @param int $limit Maximum items to return in detail lists
     * @return array
     */
    public function audit(?string $scope_dir = null, int $limit = 500): array {
        // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
        @set_time_limit(180);

        $root = $scope_dir ? wp_normalize_path(untrailingslashit($scope_dir)) : wp_normalize_path(untrailingslashit(ABSPATH));
        $server_info = self::get_server_user_info();
        $server_uid = $server_info['uid'];
        $has_posix = function_exists('posix_geteuid');

        $total_dirs = 0;
        $total_files = 0;
        $insecure_dirs = [];
        $insecure_files = [];
        $conflicts = [];

        // Excluded folders from deep recursion
        $excluded_dirs = [
            '.git',
            'node_modules',
            'cache',
            'wfcache',
            '.backups',
            'wcp-backups',
            'wcp-quarantine',
        ];

        // Evaluate root directory itself.
        // In cPanel, Plesk, and Apache suEXEC/mod_ruid2/PHP-FPM setups (e.g. user:nobody),
        // the document root (ABSPATH / public_html) is standardly and securely set to 0750 or 0755.
        $root_ownership = self::get_path_ownership($root);
        $root_raw_perms = @fileperms($root);
        $root_octal = $root_ownership['perms_octal'];
        $root_world_writable = ($root_raw_perms !== false) ? (($root_raw_perms & 0002) !== 0) : false;

        $is_root_insecure = ($root_octal === '0777') || $root_world_writable;
        // 0755 and 0750 are standard, secure directory permissions (never world-writable)
        if ($is_root_insecure && !in_array($root_octal, ['0755', '0750'], true)) {
            $insecure_dirs[] = [
                'path'          => $root,
                'relative_path' => '/',
                'current_perm'  => $root_octal,
                'target_perm'   => '0755',
                'owner'         => $root_ownership['owner_name'],
                'group'         => $root_ownership['group_name'],
            ];
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                $sub_path = $iterator->getSubPathname();
                $normalized_sub = wp_normalize_path($sub_path);

                // Skip excluded directories
                $skip = false;
                foreach ($excluded_dirs as $excluded) {
                    if (strpos($normalized_sub, $excluded . '/') !== false || $normalized_sub === $excluded) {
                        $skip = true;
                        break;
                    }
                }
                if ($skip) {
                    continue;
                }

                $full_path = wp_normalize_path($item->getPathname());
                $is_dir = $item->isDir();

                if ($is_dir) {
                    $total_dirs++;
                    $perms = $item->getPerms();
                    $octal = substr(sprintf('%o', $perms), -4);

                    // Flag if 0777 or world-writable (last digit has write bit 2)
                    $is_insecure = ($octal === '0777') || (($perms & 0002) !== 0);
                    $is_safe_dir = in_array($octal, ['0755', '0750'], true) && !$is_insecure;

                    if (!$is_safe_dir) {
                        $owner_uid = $item->getOwner();
                        $group_gid = $item->getGroup();
                        $owner_name = $owner_uid;
                        $group_name = $group_gid;

                        if (function_exists('posix_getpwuid')) {
                            $pw = posix_getpwuid($owner_uid);
                            if (is_array($pw) && !empty($pw['name'])) {
                                $owner_name = $pw['name'];
                            }
                        }
                        if (function_exists('posix_getgrgid')) {
                            $gr = posix_getgrgid($group_gid);
                            if (is_array($gr) && !empty($gr['name'])) {
                                $group_name = $gr['name'];
                            }
                        }

                        // Check if PHP can modify
                        $can_modify = true;
                        $reason = '';
                        if ($has_posix && $server_uid !== 0 && $owner_uid !== $server_uid) {
                            $can_modify = false;
                            $reason = sprintf(
                                /* translators: 1: directory owner name, 2: directory owner UID, 3: server user name, 4: server UID */
                                __('Directory is owned by %1$s (UID %2$d), but PHP web server runs as %3$s (UID %4$d). Non-root PHP cannot modify directory permissions owned by another user.', 'wcp-security-scanner'),
                                $owner_name,
                                $owner_uid,
                                $server_info['user'],
                                $server_uid
                            );
                        }

                        if (!$can_modify) {
                            if (count($conflicts) < $limit) {
                                $conflicts[] = [
                                    'path'           => $full_path,
                                    'relative_path'  => $normalized_sub,
                                    'type'           => 'directory',
                                    'current_perm'   => $octal,
                                    'target_perm'    => '0755',
                                    'owner_name'     => (string) $owner_name,
                                    'owner_uid'      => $owner_uid,
                                    'group_name'     => (string) $group_name,
                                    'group_gid'      => $group_gid,
                                    'expected_owner' => $server_info['user'],
                                    'expected_group' => $server_info['group'],
                                    'reason'         => $reason,
                                ];
                            }
                        }

                        if ($is_insecure) {
                            if (count($insecure_dirs) < $limit) {
                                $insecure_dirs[] = [
                                    'path'          => $full_path,
                                    'relative_path' => $normalized_sub,
                                    'current_perm'  => $octal,
                                    'target_perm'   => '0755',
                                    'owner'         => (string) $owner_name,
                                    'group'         => (string) $group_name,
                                    'unfixable'     => !$can_modify,
                                ];
                            }
                        }
                    }
                } else {
                    $total_files++;
                    $perms = $item->getPerms();
                    $octal = substr(sprintf('%o', $perms), -4);
                    $filename = $item->getFilename();

                    $target_perm = '0644';
                    if ($filename === 'wp-config.php') {
                        $target_perm = '0600';
                    }

                    // Flag if 0777, 0666, executable or world-writable
                    $is_insecure = ($octal === '0777') || ($octal === '0666') || (($perms & 0002) !== 0);

                    // Also flag wp-config.php if looser than 0640/0600
                    if ($filename === 'wp-config.php' && $octal !== '0600' && $octal !== '0640') {
                        $is_insecure = true;
                    }

                    if ($is_insecure || ($octal !== $target_perm && ($perms & 0002))) {
                        $owner_uid = $item->getOwner();
                        $group_gid = $item->getGroup();
                        $owner_name = $owner_uid;
                        $group_name = $group_gid;

                        if (function_exists('posix_getpwuid')) {
                            $pw = posix_getpwuid($owner_uid);
                            if (is_array($pw) && !empty($pw['name'])) {
                                $owner_name = $pw['name'];
                            }
                        }
                        if (function_exists('posix_getgrgid')) {
                            $gr = posix_getgrgid($group_gid);
                            if (is_array($gr) && !empty($gr['name'])) {
                                $group_name = $gr['name'];
                            }
                        }

                        // Check if PHP can modify
                        $can_modify = true;
                        $reason = '';
                        if ($has_posix && $server_uid !== 0 && $owner_uid !== $server_uid) {
                            $can_modify = false;
                            $reason = sprintf(
                                /* translators: 1: file owner name, 2: file owner UID, 3: server user name, 4: server UID */
                                __('File is owned by %1$s (UID %2$d), but PHP web server runs as %3$s (UID %4$d). Non-root PHP cannot modify file permissions owned by another user.', 'wcp-security-scanner'),
                                $owner_name,
                                $owner_uid,
                                $server_info['user'],
                                $server_uid
                            );
                        }

                        if (!$can_modify) {
                            if (count($conflicts) < $limit) {
                                $conflicts[] = [
                                    'path'           => $full_path,
                                    'relative_path'  => $normalized_sub,
                                    'type'           => 'file',
                                    'current_perm'   => $octal,
                                    'target_perm'    => $target_perm,
                                    'owner_name'     => (string) $owner_name,
                                    'owner_uid'      => $owner_uid,
                                    'group_name'     => (string) $group_name,
                                    'group_gid'      => $group_gid,
                                    'expected_owner' => $server_info['user'],
                                    'expected_group' => $server_info['group'],
                                    'reason'         => $reason,
                                ];
                            }
                        }

                        if ($is_insecure) {
                            if (count($insecure_files) < $limit) {
                                $insecure_files[] = [
                                    'path'          => $full_path,
                                    'relative_path' => $normalized_sub,
                                    'current_perm'  => $octal,
                                    'target_perm'   => $target_perm,
                                    'owner'         => (string) $owner_name,
                                    'group'         => (string) $group_name,
                                    'unfixable'     => !$can_modify,
                                ];
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WCP Permission Hardening Audit Error: ' . $e->getMessage());
        }

        $cli_commands = self::generate_cli_commands($root, $server_info['user'], $server_info['group']);

        return [
            'success'                    => true,
            'root_path'                  => $root,
            'server_info'                => $server_info,
            'total_directories_scanned'  => $total_dirs,
            'total_files_scanned'        => $total_files,
            'insecure_directories_count' => count($insecure_dirs),
            'insecure_files_count'       => count($insecure_files),
            'conflicts_count'            => count($conflicts),
            'is_healthy'                 => (count($insecure_dirs) === 0 && count($insecure_files) === 0 && count($conflicts) === 0),
            'insecure_directories'       => $insecure_dirs,
            'insecure_files'             => $insecure_files,
            'conflicts'                  => $conflicts,
            'cli_commands'               => $cli_commands,
        ];
    }

    /**
     * Fix all filesystem permissions across WordPress installation to secure defaults:
     * - Folders: 0755
     * - Files: 0644
     * - wp-config.php: 0600 or 0640
     *
     * @param string|null $scope_dir Target directory (defaults to ABSPATH)
     * @return array Result metadata
     */
    public function fix_all(?string $scope_dir = null): array {
        // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
        @set_time_limit(300);

        $root = $scope_dir ? wp_normalize_path(untrailingslashit($scope_dir)) : wp_normalize_path(untrailingslashit(ABSPATH));
        $server_info = self::get_server_user_info();

        $dirs_fixed = 0;
        $files_fixed = 0;
        $unfixable_items = [];
        $fixed_paths = [];

        // Excluded folders
        $excluded_dirs = [
            '.git',
            'node_modules',
            'cache',
            'wfcache',
            '.backups',
            'wcp-backups',
            'wcp-quarantine',
        ];

        // 1. Fix root directory itself if needed.
        // In cPanel and secure setups, 0750 and 0755 are both fully compliant and secure.
        global $wp_filesystem;
        $root_perm = substr(sprintf('%o', @fileperms($root)), -4);
        if ($root_perm !== '0755' && $root_perm !== '0750') {
            if ($wp_filesystem) {
                $changed = $wp_filesystem->chmod($root, 0755);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                $changed = @chmod($root, 0755);
            }
            clearstatcache(true, $root);
            $new_perm = substr(sprintf('%o', @fileperms($root)), -4);
            if ($new_perm === '0755' || $new_perm === '0750') {
                $dirs_fixed++;
                $fixed_paths[] = $root;
            } else {
                $unfixable_items[] = self::build_unfixable_item($root, 'directory', $root_perm, '0755', $server_info);
            }
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                $sub_path = $iterator->getSubPathname();
                $normalized_sub = wp_normalize_path($sub_path);

                // Skip excluded folders
                $skip = false;
                foreach ($excluded_dirs as $excluded) {
                    if (strpos($normalized_sub, $excluded . '/') !== false || $normalized_sub === $excluded) {
                        $skip = true;
                        break;
                    }
                }
                if ($skip) {
                    continue;
                }

                $full_path = wp_normalize_path($item->getPathname());
                $is_dir = $item->isDir();
                $current_octal = substr(sprintf('%o', $item->getPerms()), -4);

                if ($is_dir) {
                    // Standardize directory to 0755 (allow 0750 as already secure)
                    if ($current_octal !== '0755' && $current_octal !== '0750') {
                        if ($wp_filesystem) {
                            $changed = $wp_filesystem->chmod($full_path, 0755);
                        } else {
                            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                            $changed = @chmod($full_path, 0755);
                        }
                        clearstatcache(true, $full_path);
                        $after_octal = substr(sprintf('%o', @fileperms($full_path)), -4);

                        if ($after_octal === '0755' || $after_octal === '0750') {
                            $dirs_fixed++;
                            $fixed_paths[] = $full_path;
                        } else {
                            $unfixable_items[] = self::build_unfixable_item($full_path, 'directory', $current_octal, '0755', $server_info);
                        }
                    }
                } else {
                    $filename = $item->getFilename();
                    $target_mode = 0644;
                    $target_octal = '0644';

                    if ($filename === 'wp-config.php') {
                        $target_mode = 0600;
                        $target_octal = '0600';
                    }

                    if ($current_octal !== $target_octal) {
                        // For wp-config.php, try 0600, fallback to 0640 or 0644 if 0600 breaks read
                        if ($wp_filesystem) {
                            $changed = $wp_filesystem->chmod($full_path, $target_mode);
                        } else {
                            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                            $changed = @chmod($full_path, $target_mode);
                        }
                        clearstatcache(true, $full_path);
                        $after_octal = substr(sprintf('%o', @fileperms($full_path)), -4);

                        if ($after_octal === $target_octal || ($filename === 'wp-config.php' && ($after_octal === '0640' || $after_octal === '0644'))) {
                            $files_fixed++;
                            $fixed_paths[] = $full_path;
                        } else {
                            $unfixable_items[] = self::build_unfixable_item($full_path, 'file', $current_octal, $target_octal, $server_info);
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WCP Permission Hardening Fix Error: ' . $e->getMessage());
        }

        // 2. Auto-reconcile active scan issues in wp_wcp_scan_issues
        $reconciled_issues_count = self::reconcile_scan_issues($fixed_paths);

        // 3. Record in Audit Log
        if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
            $log_message = sprintf(
                '1-Click Filesystem Permission Hardening: Restored %d directories to 0755, %d files to 0644. %d unfixable items encountered.',
                $dirs_fixed,
                $files_fixed,
                count($unfixable_items)
            );
            \WcpScanner\System\AuditLogger::log_event('PERMISSION_HARDENING', $log_message);
        }

        $cli_commands = self::generate_cli_commands($root, $server_info['user'], $server_info['group']);

        return [
            'success'                 => true,
            'message'                 => sprintf(
                /* translators: 1: count of fixed directories, 2: count of fixed files, 3: count of reconciled scan issues */
                __('Hardening complete: %1$d directories restored to 0755, %2$d files secured to 0644. %3$d active scan issues resolved.', 'wcp-security-scanner'),
                $dirs_fixed,
                $files_fixed,
                $reconciled_issues_count
            ),
            'directories_fixed'       => $dirs_fixed,
            'files_fixed'             => $files_fixed,
            'reconciled_issues_count' => $reconciled_issues_count,
            'unfixable_count'         => count($unfixable_items),
            'unfixable_items'         => $unfixable_items,
            'cli_commands'            => $cli_commands,
        ];
    }

    /**
     * Build metadata for unfixable item.
     */
    private static function build_unfixable_item(string $path, string $type, string $current_octal, string $target_octal, array $server_info): array {
        $ownership = self::get_path_ownership($path);
        $reason = sprintf(
            /* translators: 1: path owner name, 2: path owner UID, 3: server user name, 4: server UID */
            __('Path is owned by %1$s (UID %2$d), but PHP web server runs as %3$s (UID %4$d). Modify ownership via terminal or SSH.', 'wcp-security-scanner'),
            $ownership['owner_name'],
            $ownership['owner_uid'],
            $server_info['user'],
            $server_info['uid']
        );

        return [
            'path'           => $path,
            'relative_path'  => ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($path)), '/'),
            'type'           => $type,
            'current_perm'   => $current_octal,
            'target_perm'    => $target_octal,
            'owner_name'     => $ownership['owner_name'],
            'owner_uid'      => $ownership['owner_uid'],
            'group_name'     => $ownership['group_name'],
            'group_gid'      => $ownership['group_gid'],
            'expected_owner' => $server_info['user'],
            'expected_group' => $server_info['group'],
            'reason'         => $reason,
        ];
    }

    /**
     * Reconcile any scan issues in database that were hardened by this action.
     *
     * @param array $fixed_paths
     * @return int
     */
    private static function reconcile_scan_issues(array $fixed_paths): int {
        global $wpdb;
        if (empty($wpdb) || !isset($wpdb->prefix)) {
            return 0;
        }
        $table = $wpdb->prefix . 'wcpscan_scan_issues';
        $check_sql = "SHOW TABLES LIKE '{$table}'";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        if ($wpdb->get_var($check_sql) !== $table) {
            return 0;
        }

        $open_sql = "SELECT id, file_path, type FROM {$table} WHERE (type = 'unsafe_permissions' OR engine = 'filesystem') AND status = 'open'";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $open_issues = $wpdb->get_results($open_sql);

        if (empty($open_issues)) {
            return 0;
        }

        $reconciled = 0;
        foreach ($open_issues as $iss) {
            $real_path = realpath($iss->file_path);
            if (!$real_path) {
                $candidate = ABSPATH . ltrim($iss->file_path, '/\\');
                if (file_exists($candidate)) {
                    $real_path = realpath($candidate);
                }
            }
            if ($real_path && file_exists($real_path)) {
                $current_octal = substr(sprintf('%o', @fileperms($real_path)), -4);
                $is_safe = is_dir($real_path) ? in_array($current_octal, ['0755', '0750'], true) : in_array($current_octal, ['0644', '0640', '0600'], true);
                if ($is_safe) {
                    // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->update($table, ['status' => 'repaired'], ['id' => $iss->id]);
                    $reconciled++;
                }
            }
        }

        return $reconciled;
    }

    /**
     * Generate safe, copy-pasteable terminal commands for SysAdmins to fix ownership and permissions.
     */
    public static function generate_cli_commands(string $root, string $user, string $group): string {
        $clean_root = rtrim($root, '/\\') . '/';
        $config_path = $clean_root . 'wp-config.php';
        $htaccess_path = $clean_root . '.htaccess';

        return "# =========================================================================\n" .
               "# WebCare Pro - WordPress Filesystem Permissions & Ownership Reset Script\n" .
               "# Run via SSH or Terminal as root / with sudo privileges\n" .
               "# =========================================================================\n\n" .
               "# 1. Standardize ownership across the WordPress document root\n" .
               "sudo chown -R {$user}:{$group} \"{$clean_root}\"\n\n" .
               "# 2. Reset all directories to standard 755 (drwxr-xr-x)\n" .
               "find \"{$clean_root}\" -type d -exec chmod 755 {} +\n\n" .
               "# 3. Reset all files to standard 644 (-rw-r--r--)\n" .
               "find \"{$clean_root}\" -type f -exec chmod 644 {} +\n\n" .
               "# 4. Harden sensitive configuration files\n" .
               "if [ -f \"{$config_path}\" ]; then\n" .
               "    chmod 600 \"{$config_path}\"\n" .
               "fi\n" .
               "if [ -f \"{$htaccess_path}\" ]; then\n" .
               "    chmod 644 \"{$htaccess_path}\"\n" .
               "fi\n\n" .
               "# 5. Verify no world-writable files remain\n" .
               "find \"{$clean_root}\" -perm -0002 -ls\n";
    }
}
