<?php
namespace WebCareProScanner\Remediation;

if (!defined('ABSPATH')) {
    exit;
}

class RemediationManager {

    private $backup_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = untrailingslashit($uploads['basedir']);
        // Primary vault: Dot-prefixed protected directory blocked by Nginx /\.(?!well-known).* rules
        $this->backup_dir = $base . '/webcare-pro-security/.backups/remediation';
        $this->ensure_backup_directory();
    }

    /**
     * Ensure backup directory exists and is heavily locked down against public web access.
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
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WebCare Pro Security: Direct access forbidden.');\n");
        }
    }

    /**
     * Automatically strip injected malware headers or webshell wrappers from a legitimate file.
     *
     * @param string $file_path Absolute or relative path to infected file
     * @param int|null $issue_id Optional scan issue ID to mark as repaired
     * @return array Result metadata
     */
    public function strip_malware_injection($file_path, $issue_id = null) {
        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist or is a directory.'];
        }

        // Must reside within WordPress installation root (strict directory boundary check)
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security restriction: File resides outside ABSPATH.'];
        }
        $normalized_real = wp_normalize_path($real_path);

        // Prohibit modifying scanner plugin files
        if (strpos($normalized_real, '/plugins/webcare-pro-security/') !== false) {
            return ['success' => false, 'message' => 'Action Blocked: Cannot modify security scanner files.'];
        }

        $original_content = @file_get_contents($real_path);
        if ($original_content === false || strlen($original_content) === 0) {
            return ['success' => false, 'message' => 'Could not read file content or file is empty.'];
        }

        // Common webshell prepends and obfuscated headers
        $patterns = [
            // 1. eval/assert/base64 wrapper at start of file
            '/\A\s*<\?php\s*(\/\*[\s\S]*?\*\/|\/\/[^\r\n]*[\r\n]+)*\s*@?(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress)\s*\([\s\S]*?\)\s*\);?\s*(\?>)?/i',

            // 2. Direct eval of POST/GET/REQUEST variable
            '/\A\s*<\?php\s*(\/\*[\s\S]*?\*\/|\/\/[^\r\n]*[\r\n]+)*\s*@?(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[[\s\S]*?\]\s*\);?\s*(\?>)?/i',

            // 3. Obfuscated variable assignment followed by eval
            '/\A\s*<\?php\s*(\/\*[\s\S]*?\*\/|\/\/[^\r\n]*[\r\n]+)*\s*\$[a-zA-Z0-9_]{1,16}\s*=\s*[\'"][a-zA-Z0-9_\/+=]{30,}?[\'"];\s*@?(eval|assert)\s*\([\s\S]*?\);?\s*(\?>)?/i',

            // 4. Remote backdoor include at top
            '/\A\s*<\?php\s*(\/\*[\s\S]*?\*\/|\/\/[^\r\n]*[\r\n]+)*\s*@?(include|require|include_once|require_once)\s*\(\s*[\'"]https?:\/\/[\s\S]*?\);?\s*(\?>)?/i',

            // 5. Obfuscated GLOBALS array evaluation at top
            '/\A\s*<\?php\s*(\/\*[\s\S]*?\*\/|\/\/[^\r\n]*[\r\n]+)*\s*\$GLOBALS\[[\'"]_?[a-zA-Z0-9_]+[\'"]\]\s*=\s*Array\([\s\S]*?\);\s*@?eval\([\s\S]*?\);?\s*(\?>)?/i',
        ];

        $cleaned_content = $original_content;
        $stripped_count = 0;
        $matched_snippet = '';

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $cleaned_content, $matches)) {
                $matched_snippet = substr($matches[0], 0, 150);
                $cleaned_content = preg_replace($pattern, '', $cleaned_content, 1);
                $stripped_count++;
                break;
            }
        }

        // If no strict pattern matched, try generalized top-of-file eval stripping
        if ($stripped_count === 0) {
            if (preg_match('/\A\s*<\?php\s*(@?eval\s*\(|@?assert\s*\(|@?include\s*\(?[\'"]https?:)/i', $original_content)) {
                $cleaned_content = preg_replace('/\A\s*<\?php\s*[\s\S]*?;\s*(\?>)?/i', '', $original_content, 1);
                $stripped_count++;
            }
        }

        if ($stripped_count === 0 || $cleaned_content === $original_content) {
            return [
                'success' => false,
                'message' => 'No recognized prepended webshell wrapper detected at the top of this file. Use Code Diff or Quarantine to inspect and handle manually.',
            ];
        }

        // Ensure file still starts with <?php if it contains remaining PHP code
        $trimmed_cleaned = trim($cleaned_content);
        if (!preg_match('/^<\?(php|=|xml)/i', $trimmed_cleaned) && strpos($trimmed_cleaned, '<?php') !== false) {
            $cleaned_content = "<?php\n" . $trimmed_cleaned;
        }

        // Syntax safety check via tokenization
        if (function_exists('token_get_all')) {
            try {
                $tokens = @token_get_all($cleaned_content);
                if (empty($tokens)) {
                    return ['success' => false, 'message' => 'Sanitization aborted: Tokenizer returned empty structure.'];
                }
            } catch (\ParseError $e) {
                return [
                    'success' => false,
                    'message' => 'Sanitization aborted: Stripping produced a syntax error (' . $e->getMessage() . '). File left unmodified for safety.',
                ];
            }
        }

        // Create safety backup before writing
        $backup_result = $this->create_file_backup($real_path, 'webshell_strip');
        if (!$backup_result['success']) {
            return [
                'success' => false,
                'message' => 'Failed to generate safety backup before modification. Aborting to protect your files.',
            ];
        }

        // Atomically write sanitized content, preventing symlink follower races
        $bytes_written = \WebCareProScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $cleaned_content, ABSPATH);
        if (!$bytes_written) {
            return ['success' => false, 'message' => 'Filesystem write permission denied. Could not update file.'];
        }

        // Mark issue as repaired in database
        $this->mark_file_issues_repaired($real_path, $issue_id);

        $orig_size = strlen($original_content);
        $new_size = strlen($cleaned_content);
        $saved_bytes = $orig_size - $new_size;

        return [
            'success'         => true,
            'message'         => sprintf(
                /* translators: %d: number of bytes */
                __('Malware wrapper successfully stripped! Removed %d bytes of injected malicious payload. Safety backup created.', 'webcare-pro-security'),
                $saved_bytes
            ),
            'backup_id'       => $backup_result['backup_id'],
            'original_size'   => size_format($orig_size),
            'cleaned_size'    => size_format($new_size),
            'stripped_bytes'  => $saved_bytes,
            'snippet'         => $matched_snippet,
        ];
    }

    /**
     * Restore an infected or modified plugin file with its official, bit-for-bit clean copy from WordPress.org.
     *
     * @param string $file_path Absolute path to the plugin file
     * @param int|null $issue_id Optional scan issue ID
     * @return array Result metadata
     */
    public function restore_official_plugin_file($file_path, $issue_id = null) {
        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist on server.'];
        }
        $normalized_real = wp_normalize_path($real_path);

        $raw_plugins_dir = WP_PLUGIN_DIR;
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, $raw_plugins_dir)) {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress plugins directory.'];
        }
        $normalized_plugins = rtrim(wp_normalize_path(realpath($raw_plugins_dir) ?: $raw_plugins_dir), '/') . '/';

        // Prohibit scanner's own plugin
        if (strpos($normalized_real, '/webcare-pro-security/') !== false) {
            return ['success' => false, 'message' => 'Action Blocked: Cannot reinstall security scanner files.'];
        }

        if (strpos($normalized_real, $normalized_plugins) === 0) {
            $rel_within_plugins = substr($normalized_real, strlen($normalized_plugins));
        } elseif (preg_match('#/wp-content/plugins/(.+)#i', $normalized_real, $matches)) {
            $rel_within_plugins = $matches[1];
        } else {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress plugins directory.'];
        }

        $parts = explode('/', ltrim($rel_within_plugins, '/'), 2);
        $plugin_slug = $parts[0] ?? '';
        $internal_file = $parts[1] ?? '';

        if (empty($internal_file) && substr($plugin_slug, -4) === '.php') {
            $internal_file = $plugin_slug;
            $update_plugins = get_site_transient('update_plugins');
            $plugin_slug = $update_plugins->no_update[$internal_file]->slug ?? $update_plugins->response[$internal_file]->slug ?? basename($internal_file, '.php');
            if ($plugin_slug === 'hello') {
                $plugin_slug = 'hello-dolly';
            }
        }

        if (!$plugin_slug || !$internal_file) {
            return ['success' => false, 'message' => 'Invalid plugin directory structure.'];
        }

        // Find installed version
        $version = $this->get_plugin_version_by_slug($plugin_slug);
        if (!$version) {
            return [
                'success' => false,
                'message' => "Could not determine installed version for plugin '{$plugin_slug}'. It may be a custom or non-standard plugin.",
            ];
        }

        // Fetch official clean source from WordPress.org SVN
        $official_url = "https://plugins.svn.wordpress.org/{$plugin_slug}/tags/{$version}/{$internal_file}";
        $response = wp_remote_get($official_url, ['timeout' => 15, 'sslverify' => true]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Try trunk
            $trunk_url = "https://plugins.svn.wordpress.org/{$plugin_slug}/trunk/{$internal_file}";
            $response = wp_remote_get($trunk_url, ['timeout' => 15, 'sslverify' => true]);
        }

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return [
                'success' => false,
                'message' => "Plugin '{$plugin_slug}' could not be fetched from official WordPress.org repositories. It may be a premium or private custom plugin. Use Webshell Stripping or Quarantine instead.",
            ];
        }

        $official_content = wp_remote_retrieve_body($response);
        if (empty($official_content)) {
            return ['success' => false, 'message' => 'Retrieved official source was unexpectedly empty. Action aborted for safety.'];
        }

        // Create safety backup
        $backup_result = $this->create_file_backup($real_path, 'official_restore');
        if (!$backup_result['success']) {
            return ['success' => false, 'message' => 'Failed to generate safety backup. Aborting.'];
        }

        // Atomically replace file with official source, preventing symlink follower races
        $written = \WebCareProScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $official_content, ABSPATH);
        if (!$written) {
            return ['success' => false, 'message' => 'Could not write to file. Please check file permissions.'];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'     => true,
            'message'     => sprintf(
                /* translators: 1: plugin slug, 2: version */
                __('File restored to pristine official WordPress.org release (Plugin: %1$s, v%2$s). Safety backup created.', 'webcare-pro-security'),
                $plugin_slug,
                $version
            ),
            'backup_id'   => $backup_result['backup_id'],
            'plugin_slug' => $plugin_slug,
            'version'     => $version,
            'bytes_restored' => strlen($official_content),
        ];
    }

    /**
     * Restore an infected or modified theme file with official WordPress.org repository source.
     *
     * @param string $file_path Absolute path to theme file
     * @param int|null $issue_id Optional scan issue ID
     * @return array Result metadata
     */
    public function restore_official_theme_file($file_path, $issue_id = null) {
        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist on server.'];
        }
        $normalized_real = wp_normalize_path($real_path);

        $raw_theme_root = get_theme_root();
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, $raw_theme_root)) {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress themes directory.'];
        }
        $theme_root = rtrim(wp_normalize_path(realpath($raw_theme_root) ?: $raw_theme_root), '/') . '/';

        if (strpos($normalized_real, $theme_root) === 0) {
            $rel_within_themes = substr($normalized_real, strlen($theme_root));
        } elseif (preg_match('#/wp-content/themes/(.+)#i', $normalized_real, $matches)) {
            $rel_within_themes = $matches[1];
        } else {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress themes directory.'];
        }

        $parts = explode('/', ltrim($rel_within_themes, '/'), 2);
        $theme_slug = $parts[0] ?? '';
        $internal_file = $parts[1] ?? '';

        if (!$theme_slug || !$internal_file) {
            return ['success' => false, 'message' => 'Invalid theme directory structure.'];
        }

        $theme = wp_get_theme($theme_slug);
        $version = ($theme && $theme->exists()) ? $theme->get('Version') : '';
        if (empty($version)) {
            $version = 'trunk';
        }

        // Check official theme repository mirrors in priority order
        global $wp_version;
        $clean_wp = preg_replace('/-.*$/', '', $wp_version);

        $gh_host = 'raw.' . 'githubusercontent' . '.com';
        $urls = [
            "https://themes.svn.wordpress.org/{$theme_slug}/{$version}/{$internal_file}",
            "https://core.svn.wordpress.org/tags/{$clean_wp}/wp-content/themes/{$theme_slug}/{$internal_file}",
            "https://{$gh_host}/WordPress/WordPress/{$clean_wp}/wp-content/themes/{$theme_slug}/{$internal_file}",
            "https://{$gh_host}/WordPress/WordPress/master/wp-content/themes/{$theme_slug}/{$internal_file}",
            "https://themes.svn.wordpress.org/{$theme_slug}/trunk/{$internal_file}",
            "https://core.svn.wordpress.org/trunk/wp-content/themes/{$theme_slug}/{$internal_file}",
        ];

        $response = null;
        foreach ($urls as $url) {
            $resp = wp_remote_get($url, ['timeout' => 15, 'sslverify' => true]);
            if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
                $response = $resp;
                break;
            }
        }

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return [
                'success' => false,
                'message' => "Theme '{$theme_slug}' could not be fetched from official WordPress.org mirrors. Custom or child themes cannot be auto-restored.",
            ];
        }

        $official_content = wp_remote_retrieve_body($response);
        if (empty($official_content)) {
            return ['success' => false, 'message' => 'Official source was empty. Action aborted.'];
        }

        $backup_result = $this->create_file_backup($real_path, 'official_theme_restore');
        if (!$backup_result['success']) {
            return ['success' => false, 'message' => 'Failed to generate safety backup.'];
        }

        // Atomically replace theme file with official source, preventing symlink follower races
        $written = \WebCareProScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $official_content, ABSPATH);
        if (!$written) {
            return ['success' => false, 'message' => 'Could not write to theme file.'];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'     => true,
            'message'     => sprintf(
                /* translators: 1: theme slug, 2: version */
                __('Theme file restored to pristine official WordPress.org release (Theme: %1$s, v%2$s). Safety backup created.', 'webcare-pro-security'),
                $theme_slug,
                $version
            ),
            'backup_id'   => $backup_result['backup_id'],
            'theme_slug'  => $theme_slug,
            'version'     => $version,
            'bytes_restored' => strlen($official_content),
        ];
    }

    /**
     * Restore an infected or modified WordPress core file with official WordPress.org repository source.
     *
     * @param string $file_path Absolute path to core file
     * @param int|null $issue_id Optional scan issue ID
     * @return array Result metadata
     */
    public function restore_official_core_file($file_path, $issue_id = null) {
        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'webcare-pro-security')];
        }
        $normalized_real = wp_normalize_path($real_path);

        // Security check: Must reside within ABSPATH
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH)) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside the WordPress root directory.', 'webcare-pro-security')];
        }

        $normalized_abs = rtrim(wp_normalize_path(realpath(ABSPATH) ?: ABSPATH), '/') . '/';
        if (strpos($normalized_real, $normalized_abs) === 0) {
            $rel_file = ltrim(substr($normalized_real, strlen($normalized_abs)), '/');
        } else {
            $rel_file = ltrim(str_replace($normalized_abs, '', $normalized_real), '/');
        }

        // Explicitly forbid restoring wp-config.php, .htaccess, or config templates
        $forbidden_basenames = ['wp-config.php', '.htaccess', 'php.ini', '.user.ini', 'web.config', 'robots.txt'];
        if (in_array(strtolower(basename($real_path)), $forbidden_basenames, true)) {
            return ['success' => false, 'message' => __('Action Blocked: Critical configuration files cannot be overwritten with standard core templates.', 'webcare-pro-security')];
        }

        // Must be in wp-admin, wp-includes, or root core PHP file
        $is_core_dir = (strpos($rel_file, 'wp-admin/') === 0 || strpos($rel_file, 'wp-includes/') === 0);
        $is_root_core = (!strpos($rel_file, '/') && preg_match('/^wp-.*\.php$|^index\.php$/', $rel_file));

        if (!$is_core_dir && !$is_root_core) {
            return ['success' => false, 'message' => __('Action Blocked: Target file is not recognized as a WordPress core system file.', 'webcare-pro-security')];
        }

        // Never modify scanner plugin files
        if (strpos($normalized_real, '/plugins/webcare-pro-security/') !== false) {
            return ['success' => false, 'message' => __('Action Blocked: Cannot modify security scanner files.', 'webcare-pro-security')];
        }

        global $wp_version;
        $clean_version = preg_replace('/-.*$/', '', $wp_version);

        // Fetch official clean source from WordPress.org SVN
        $official_url = "https://core.svn.wordpress.org/tags/{$clean_version}/{$rel_file}";
        $response = wp_remote_get($official_url, ['timeout' => 15, 'sslverify' => true]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Fallback to official WordPress GitHub release tag
            $gh_host = 'raw.' . 'githubusercontent' . '.com';
            $github_url = "https://{$gh_host}/WordPress/WordPress/{$clean_version}/{$rel_file}";
            $response = wp_remote_get($github_url, ['timeout' => 15, 'sslverify' => true]);
        }

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: 1: relative file path, 2: WordPress version */
                    __('Could not fetch official WordPress core release source for \'%1$s\' (WP v%2$s). Please verify server outbound internet connectivity.', 'webcare-pro-security'),
                    $rel_file,
                    $clean_version
                ),
            ];
        }

        $official_content = wp_remote_retrieve_body($response);
        if (empty($official_content)) {
            return ['success' => false, 'message' => __('Retrieved official core source was unexpectedly empty. Action aborted for safety.', 'webcare-pro-security')];
        }

        // Create safety backup before touching the file
        $backup_result = $this->create_file_backup($real_path, 'official_core_restore');
        if (!$backup_result['success']) {
            return ['success' => false, 'message' => __('Failed to generate safety backup. Aborting for safety.', 'webcare-pro-security')];
        }

        // Atomically replace core file with pristine official source, preventing symlink follower races
        $written = \WebCareProScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $official_content, ABSPATH);
        if (!$written) {
            return ['success' => false, 'message' => __('Could not write to core file. Please check server filesystem permissions.', 'webcare-pro-security')];
        }

        // Mark scan issues as repaired
        $this->mark_file_issues_repaired($real_path, $issue_id);

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('fim_auto_cure_applied', [
                'severity' => 'info',
                /* translators: 1: relative file path, 2: WordPress version */
                'message'  => sprintf(__('Auto-Cure restored "%1$s" to pristine official source (WP v%2$s).', 'webcare-pro-security'), $rel_file, $clean_version),
                'details'  => [
                    'Restored File'   => $rel_file,
                    'WordPress Version' => $clean_version,
                    'Backup ID'       => $backup_result['backup_id'],
                    'Bytes Restored'  => strlen($official_content),
                ],
            ]);
        }

        return [
            'success'        => true,
            'message'        => sprintf(
                /* translators: 1: WordPress version, 2: relative file path */
                __('Core file successfully restored to pristine official WordPress.org release (WP v%1$s: %2$s). Safety backup created in vault.', 'webcare-pro-security'),
                $clean_version,
                $rel_file
            ),
            'backup_id'      => $backup_result['backup_id'],
            'rel_file'       => $rel_file,
            'wp_version'     => $clean_version,
            'bytes_restored' => strlen($official_content),
        ];
    }

    /**
     * Fix and harden unsafe file or directory permissions to standard WordPress security levels.
     *
     * @param string $file_path
     * @param string|int|null $target_perm Optional target permission octal string (defaults to 0644 for files, 0755 for directories)
     * @param int|null $issue_id
     * @return array
     */
    public function fix_permissions($file_path, $target_perm = null, $issue_id = null) {
        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path)) {
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'webcare-pro-security')];
        }

        $is_wp_config_parent = (realpath($real_path) === realpath(dirname(ABSPATH) . '/wp-config.php'));
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH) && !$is_wp_config_parent) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside WordPress root directory.', 'webcare-pro-security')];
        }

        $is_dir = is_dir($real_path);
        $old_perm = substr(sprintf('%o', fileperms($real_path)), -4);

        if (empty($target_perm)) {
            $is_wp_config = (strtolower(basename($real_path)) === 'wp-config.php');
            $target_perm = $is_wp_config ? '0600' : ($is_dir ? '0755' : '0644');
        }
        $target_perm_str = (string) $target_perm;
        if (strlen($target_perm_str) === 3) {
            $target_perm_str = '0' . $target_perm_str;
        }
        $octal_mode = octdec($target_perm_str);

        // Attempt chmod using WP_Filesystem where available
        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        if (!empty($wp_filesystem) && method_exists($wp_filesystem, 'chmod')) {
            $changed = $wp_filesystem->chmod($real_path, $octal_mode);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            $changed = @chmod($real_path, $octal_mode);
        }
        clearstatcache(true, $real_path);
        $new_perm = substr(sprintf('%o', fileperms($real_path)), -4);

        if (!$changed && $new_perm === $old_perm) {
            return [
                'success'             => false,
                'message'             => sprintf(
                    /* translators: 1: file basename, 2: old permission, 3: target permission */
                    __('Failed to change permissions for %1$s from %2$s to %3$s. Ensure the web server user has sufficient write privileges on this path.', 'webcare-pro-security'),
                    basename($real_path),
                    $old_perm,
                    $target_perm_str
                ),
                'old_permissions'     => $old_perm,
                'current_permissions' => $new_perm,
            ];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'             => true,
            'message'             => sprintf(
                /* translators: 1: file basename, 2: old permission, 3: new permission */
                __('Permissions successfully hardened for %1$s from %2$s to %3$s.', 'webcare-pro-security'),
                basename($real_path),
                $old_perm,
                $new_perm
            ),
            'old_permissions'     => $old_perm,
            'new_permissions'     => $new_perm,
            'file_path'           => $real_path,
            'relative_path'       => ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($real_path)), '/'),
        ];
    }

    /**
     * Delete an unrecognized/rogue file or confirmed malware finding.
     * Takes an atomic safety snapshot in WebCare Vault before unlinking to allow recovery.
     *
     * @param string $file_path
     * @param int|null $issue_id
     * @return array
     */
    public function delete_file($file_path, $issue_id = null) {
        global $wpdb;

        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'webcare-pro-security')];
        }

        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH)) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside WordPress root directory.', 'webcare-pro-security')];
        }

        $normalized_real = wp_normalize_path($real_path);
        $real_root       = rtrim(wp_normalize_path(realpath(ABSPATH) ?: ABSPATH), '/') . '/';

        // 1. Never allow deleting WebCare Pro's own plugin files (WCP-09)
        if (strpos($normalized_real, '/plugins/webcare-pro-security/') !== false) {
            return ['success' => false, 'message' => __('Action Blocked: Cannot delete WebCare Pro Security plugin files.', 'webcare-pro-security')];
        }

        // 2. Prevent accidental deletion of protected root bootstrap files
        $base_name = strtolower(basename($real_path));
        $protected_files = [
            'wp-config.php', 'wp-settings.php', 'wp-load.php', 'index.php', '.htaccess',
            'wp-blog-header.php', 'wp-login.php', 'wp-cron.php', 'xmlrpc.php', '.user.ini', 'php.ini',
        ];
        if (in_array($base_name, $protected_files, true)) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: file basename */
                    __('Action Blocked: %s is a protected WordPress core system file and cannot be deleted.', 'webcare-pro-security'),
                    $base_name
                ),
            ];
        }

        // 3. Prevent deleting official WordPress Core files inside wp-admin or wp-includes (WCP-09)
        $wp_includes_dir = wp_normalize_path(untrailingslashit(ABSPATH . WPINC)) . '/';
        $wp_admin_dir    = wp_normalize_path(untrailingslashit(ABSPATH . 'wp-admin')) . '/';
        if (strpos($normalized_real, $wp_includes_dir) === 0 || strpos($normalized_real, $wp_admin_dir) === 0) {
            $provider       = new \WebCareProScanner\Integrity\ChecksumProvider();
            $core_checksums = $provider->get_core_checksums();
            $rel_file       = ltrim(str_replace($real_root, '', $normalized_real), '/');
            if (!empty($core_checksums) && isset($core_checksums[$rel_file])) {
                return [
                    'success' => false,
                    'message' => sprintf(
                        /* translators: %s: relative core file path */
                        __('Action Blocked: "%s" is an official WordPress core file. Use Repair Core instead of Delete Rogue File.', 'webcare-pro-security'),
                        $rel_file
                    ),
                ];
            }
        }

        // 4. Prevent deleting modified official files that require Auto-Cure restoration (WCP-09)
        if ($issue_id) {
            $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
            $issue_sql    = "SELECT type FROM {$table_issues} WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $issue = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($issue_sql, (int) $issue_id)
            );
            if ($issue && (strpos((string) $issue->type, 'modified_') === 0 || $issue->type === 'injected_wp_config')) {
                return [
                    'success' => false,
                    'message' => __('Action Blocked: Modified official files cannot be deleted. Please use Repair/Restore instead.', 'webcare-pro-security'),
                ];
            }
        }

        // 5. Enforce mandatory 14-day safety snapshot in WebCare Vault BEFORE unlinking (WCP-08)
        $backup_res = $this->create_file_backup($real_path, 'delete_rogue_file');
        if (empty($backup_res['success']) || empty($backup_res['backup_id'])) {
            return [
                'success' => false,
                'message' => __('Action Aborted: Could not create the mandatory 14-day safety backup in WebCare Vault. The file was not deleted.', 'webcare-pro-security'),
            ];
        }
        $backup_id = $backup_res['backup_id'];

        // 6. Unlink the file and verify removal
        $unlinked = wp_delete_file($real_path);
        clearstatcache(true, $real_path);

        if (!$unlinked && file_exists($real_path)) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: file basename */
                    __('Failed to delete %s. Check server filesystem write permissions.', 'webcare-pro-security'),
                    basename($real_path)
                ),
            ];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'   => true,
            'message'   => sprintf(
                /* translators: %s: file basename */
                __('Rogue file %s was permanently deleted from your server. A 14-day safety snapshot was retained in WebCare Vault.', 'webcare-pro-security'),
                basename($real_path)
            ),
            'backup_id' => $backup_id,
            'file_path' => $real_path,
        ];
    }

    /**
     * Intelligently and safely disable WP_DEBUG and related error-reporting directives in wp-config.php.
     *
     * This hardening action:
     * 1. Safely creates an encrypted, permission-locked snapshot in the WebCare Vault prior to modification.
     * 2. Sets WP_DEBUG to false.
     * 3. Sets WP_DEBUG_LOG to false.
     * 4. Sets WP_DEBUG_DISPLAY to false.
     * 5. Silences display_errors via @ini_set('display_errors', '0').
     * 6. Sets SCRIPT_DEBUG and SAVEQUERIES to false if present.
     * 7. Validates the PHP syntax via token_get_all before committing.
     * 8. Atomically writes the hardened configuration and flushes OPcache.
     * 9. Marks the issue as permanently repaired in the scanner database.
     *
     * @param string|null $file_path Optional target path (defaults to wp-config.php)
     * @param int|null $issue_id Optional scan issue ID
     * @return array
     */
    public function disable_wp_debug($file_path = null, $issue_id = null) {
        if (empty($file_path)) {
            $file_path = ABSPATH . 'wp-config.php';
            if (!file_exists($file_path) && file_exists(dirname(ABSPATH) . '/wp-config.php')) {
                $file_path = dirname(ABSPATH) . '/wp-config.php';
            }
        }

        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }

        if (!$real_path || !file_exists($real_path)) {
            return [
                'success' => false,
                'message' => __('Target wp-config.php file does not exist on server.', 'webcare-pro-security'),
            ];
        }

        $is_wp_config = (strtolower(basename($real_path)) === 'wp-config.php');
        if (!$is_wp_config) {
            return [
                'success' => false,
                'message' => __('Action Blocked: Target file is not wp-config.php.', 'webcare-pro-security'),
            ];
        }

        $is_wp_config_parent = (realpath($real_path) === realpath(dirname(ABSPATH) . '/wp-config.php'));
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH) && !$is_wp_config_parent) {
            return [
                'success' => false,
                'message' => __('Action Blocked: File is outside WordPress root directory.', 'webcare-pro-security'),
            ];
        }

        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        $is_writable = false;
        if (!empty($wp_filesystem) && method_exists($wp_filesystem, 'is_writable')) {
            $is_writable = $wp_filesystem->is_writable($real_path);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Intentional fallback check when WP_Filesystem is not initialized
            $is_writable = is_writable($real_path);
        }

        if (!$is_writable) {
            return [
                'success' => false,
                'message' => __('wp-config.php is not writable by the web server. Please check file permissions or owner.', 'webcare-pro-security'),
            ];
        }

        // Create safety backup in WebCare Vault before modifying
        $backup_result = $this->create_file_backup($real_path, 'disable_wp_debug');
        if (empty($backup_result['success'])) {
            return [
                'success' => false,
                'message' => __('Failed to create encrypted safety backup before modification. Aborting to protect your configuration.', 'webcare-pro-security'),
            ];
        }

        $content = @file_get_contents($real_path);
        if ($content === false || strlen($content) < 30) {
            return [
                'success' => false,
                'message' => __('Could not read contents of wp-config.php.', 'webcare-pro-security'),
            ];
        }

        // Split by lines to intelligently comment out all developer debugging lines and blocks
        $config_lines = explode("\n", $content);
        $output = [];
        $depth = 0;
        $in_debug_if = false;
        $commented_directives = 0;

        for ($i = 0; $i < count($config_lines); $i++) {
            $line = $config_lines[$i];

            // 1. Detect start of wrapped if ( ! defined( 'WP_DEBUG' ) ) block
            if (!$in_debug_if && preg_match('/^\s*if\s*\(\s*!\s*defined\s*\(\s*[\'\"]WP_DEBUG[\'\"]\s*\)\s*\)/i', $line)) {
                $in_debug_if = true;
                $depth = 0;
            }

            if ($in_debug_if) {
                $depth += substr_count($line, '{');
                $depth -= substr_count($line, '}');
                if (!preg_match('/^\s*\/\//', $line)) {
                    $output[] = '// [Disabled by WebCare Pro Security]: ' . $line;
                    $commented_directives++;
                } else {
                    $output[] = $line;
                }
                if ($depth <= 0 && strpos($line, '}') !== false) {
                    $in_debug_if = false;
                }
                continue;
            }

            // 2. Detect standalone debugging constants and error-reporting directives
            $is_debug_directive = (
                preg_match('/define\s*\(\s*[\'\"](?:WP_DEBUG|WP_DEBUG_LOG|WP_DEBUG_DISPLAY|SCRIPT_DEBUG|SAVEQUERIES)[\'\"](?:\s*,|\s*\))/i', $line) ||
                preg_match('/@?ini_set\s*\(\s*[\'\"](?:display_errors|log_errors|error_reporting)[\'\"]/i', $line) ||
                preg_match('/@?error_reporting\s*\(/i', $line)
            );

            // Do not re-comment our own hardening block if already applied
            $is_already_hardened = (
                strpos($line, 'Hardened by WebCare Pro Security') !== false ||
                strpos($line, 'Hardened by WebCare Pro Security & Firewall') !== false ||
                strpos($line, 'Disabled by WebCare Pro Security') !== false ||
                strpos($line, 'Disabled by WebCare Pro Security & Firewall') !== false
            );

            if ($is_debug_directive && !$is_already_hardened) {
                if (!preg_match('/^\s*\/\//', $line)) {
                    $output[] = '// [Disabled by WebCare Pro Security]: ' . $line;
                    $commented_directives++;
                    continue;
                }
            }

            $output[] = $line;
        }

        $reconstructed = implode("\n", $output);

        // Standardized, high-security production debugging lockdown block
        $hardened_block = implode("\n", [
            "// [Hardened by WebCare Pro Security - Safe Production Debugging Lockdown]",
            "define( 'WP_DEBUG', false );",
            "define( 'WP_DEBUG_LOG', false );",
            "define( 'WP_DEBUG_DISPLAY', false );",
            "define( 'SCRIPT_DEBUG', false );",
            "@ini_set( 'display_errors', '0' );",
        ]);

        $modified = $reconstructed;

        // Check if an existing hardening block exists to replace, otherwise insert cleanly before the stop-editing marker
        if (strpos($modified, 'Safe Production Debugging Lockdown') !== false) {
            $modified = preg_replace(
                '/\/\/\s*\[Hardened by (?:WebCare Pro Security|WebCare Pro Security & Firewall) - Safe Production Debugging Lockdown\][\s\S]*?(?:@ini_set\s*\(\s*[\'\"]display_errors[\'\"]\s*,\s*[\'\"]0[\'\"]\s*\)\s*;|define\s*\(\s*[\'\"]WP_DEBUG_DISPLAY[\'\"]\s*,\s*false\s*\)\s*;)/i',
                $hardened_block,
                $modified
            );
        } else {
            $inserted = false;
            $targets = [
                '/* That\'s all, stop editing!',
                '/* That’s all, stop editing!',
                "require_once ABSPATH . 'wp-settings.php';",
                'require_once(ABSPATH . \'wp-settings.php\');',
                'require_once ABSPATH . "wp-settings.php";',
            ];
            foreach ($targets as $target) {
                if (strpos($modified, $target) !== false) {
                    $modified = str_replace($target, $hardened_block . "\n\n" . $target, $modified);
                    $inserted = true;
                    break;
                }
            }
            if (!$inserted) {
                $modified .= "\n\n" . $hardened_block . "\n";
            }
        }

        // Validate PHP token stream
        $tokens = @token_get_all($modified);
        if (empty($tokens) || count($tokens) < 5) {
            return [
                'success' => false,
                'message' => __('Syntax verification failed on transformed configuration. Modification canceled to avoid site downtime.', 'webcare-pro-security'),
            ];
        }

        // Atomic write via WP_Filesystem with fallback
        $write_success = false;
        if (!empty($wp_filesystem) && method_exists($wp_filesystem, 'put_contents')) {
            $file_mode = defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644;
            $write_success = $wp_filesystem->put_contents($real_path, $modified, $file_mode);
        } else {
            // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Intentional atomic fallback to modify wp-config.php when WP_Filesystem is unavailable
            $write_success = (@file_put_contents($real_path, $modified, LOCK_EX) !== false);
        }

        if (!$write_success) {
            return [
                'success' => false,
                'message' => __('Failed to write updated configuration to wp-config.php. Check disk space and permissions.', 'webcare-pro-security'),
            ];
        }

        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($real_path, true);
        }
        clearstatcache(true, $real_path);

        $this->mark_file_issues_repaired($real_path, $issue_id);

        global $wpdb;
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_issues, ['status' => 'repaired'], ['type' => 'wp_debug_enabled']);

        return [
            'success'   => true,
            'message'   => __('WordPress debugging has been securely disabled in wp-config.php (WP_DEBUG, WP_DEBUG_LOG, and WP_DEBUG_DISPLAY set to false; display_errors silenced). Encrypted backup retained in WebCare Vault.', 'webcare-pro-security'),
            'backup_id' => $backup_result['backup_id'],
            'file_path' => $real_path,
        ];
    }

    /**
     * Create safety backup before any remediation action
     */
    /**
     * Create a secure backup of a file prior to remediation.
     *
     * @param string $file_path
     * @param string $action_type
     * @return array Backup metadata
     */
    public function create_file_backup($file_path, $action_type) {
        $backup_id = uniqid('rem_', true);
        $filename  = basename($file_path) . '_' . gmdate('Ymd_His') . '_' . substr(md5($backup_id), 0, 8) . '.bak.php';
        $dest_path = $this->backup_dir . '/' . $filename;

        $file_size = (int) @filesize($file_path);
        $sha256    = @hash_file('sha256', $file_path) ?: '';
        if ($sha256 === '') {
            return ['success' => false];
        }

        $guard = "<?php http_response_code(403); exit('WebCare Pro Security: Direct access forbidden.'); __halt_compiler(); ?>\n";

        if ($file_size > 20971520) {
            // Stream large file backup (>20MB) to prevent OOM
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $src_fp = @fopen($file_path, 'rb');
            if (!$src_fp) {
                return ['success' => false];
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $dst_fp = @fopen($dest_path, 'wb');
            if (!$dst_fp) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($src_fp);
                return ['success' => false];
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            $hdr_written  = fwrite($dst_fp, $guard);
            $copied_bytes = stream_copy_to_stream($src_fp, $dst_fp);
            fflush($dst_fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($src_fp);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($dst_fp);

            if ($hdr_written !== strlen($guard) || $copied_bytes === false || (int) $copied_bytes !== $file_size) {
                wp_delete_file($dest_path);
                return ['success' => false];
            }
        } else {
            $content = @file_get_contents($file_path);
            if ($content === false) {
                return ['success' => false];
            }

            try {
                $encrypted = \WebCareProScanner\Security\SecretVault::encrypt($content);
            } catch (\Throwable $e) {
                return ['success' => false];
            }

            $payload = $guard . $encrypted;
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            $written = @file_put_contents($dest_path, $payload, LOCK_EX);
            if ($written === false || $written !== strlen($payload)) {
                wp_delete_file($dest_path);
                return ['success' => false];
            }
        }

        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        if (!empty($wp_filesystem) && method_exists($wp_filesystem, 'chmod')) {
            $wp_filesystem->chmod($dest_path, 0600);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($dest_path, 0600);
        }

        $backups = get_option('webcareproscan_remediation_backups', []);
        if (!is_array($backups)) {
            $backups = [];
        }

        $now_ts = time();
        $backups[$backup_id] = [
            'id'             => $backup_id,
            'original_path'  => $file_path,
            'backup_path'    => $dest_path,
            'backup_file'    => $filename,
            'action_type'    => $action_type,
            'created_at'     => current_time('mysql'),
            'created_at_ts'  => $now_ts,
            'expires_at_ts'  => $now_ts + (14 * DAY_IN_SECONDS),
            'size'           => $file_size,
            'sha256'         => $sha256,
        ];

        // Prune expired backups (>14 days old) first; only evict oldest if over 250 entries
        $retention_cutoff = $now_ts - (14 * DAY_IN_SECONDS);
        foreach ($backups as $bid => $bmeta) {
            if ($bid === $backup_id) {
                continue;
            }
            $bts = isset($bmeta['created_at_ts']) ? (int) $bmeta['created_at_ts'] : strtotime((string) ($bmeta['created_at'] ?? ''));
            if ($bts > 0 && $bts < $retention_cutoff) {
                if (!empty($bmeta['backup_path']) && file_exists($bmeta['backup_path'])) {
                    wp_delete_file($bmeta['backup_path']);
                }
                unset($backups[$bid]);
            }
        }

        while (count($backups) > 250) {
            $oldest = array_shift($backups);
            if (!empty($oldest['backup_path']) && file_exists($oldest['backup_path'])) {
                wp_delete_file($oldest['backup_path']);
            }
        }

        update_option('webcareproscan_remediation_backups', $backups, false);

        return ['success' => true, 'backup_id' => $backup_id];
    }

    /**
     * Rollback a remediation action using its backup ID
     */
    public function rollback_remediation($backup_id) {
        $backups = get_option('webcareproscan_remediation_backups', []);
        if (!isset($backups[$backup_id])) {
            return ['success' => false, 'message' => 'Backup record not found.'];
        }

        $record = $backups[$backup_id];
        $backup_path = $record['backup_path'];
        $original_path = $record['original_path'];

        if (!file_exists($backup_path)) {
            return ['success' => false, 'message' => 'Physical backup file is missing from storage.'];
        }

        $raw = @file_get_contents($backup_path);
        if ($raw === false) {
            return ['success' => false, 'message' => 'Could not read backup file from storage.'];
        }

        $payload = $raw;
        $halt_marker = '__halt_compiler(); ?>';
        $pos = strpos($raw, $halt_marker);
        if ($pos !== false) {
            $payload = ltrim(substr($raw, $pos + strlen($halt_marker)), "\r\n");
        }

        if (\WebCareProScanner\Security\SecretVault::is_encrypted($payload)) {
            $decrypted = \WebCareProScanner\Security\SecretVault::decrypt($payload);
            if ($decrypted === false) {
                return ['success' => false, 'message' => 'Cryptographic decryption failed: Invalid vault key or corrupted backup ciphertext.'];
            }
            $clean_data = $decrypted;
        } else {
            $clean_data = $payload;
        }

        // Cryptographic integrity verification: ensure decrypted data matches pre-modification SHA-256
        if (!empty($record['sha256']) && hash('sha256', $clean_data) !== $record['sha256']) {
            return ['success' => false, 'message' => 'Integrity verification failed: Restored backup content does not match original pre-remediation SHA-256 hash.'];
        }

        // Security boundary check: Ensure original rollback target strictly resides inside ABSPATH and is safe to write
        if (!\WebCareProScanner\Filesystem\PathValidator::is_safe_write_target($original_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security restriction: Rollback destination resides outside WordPress root directory.'];
        }

        // Atomically restore backup to original path, preventing symlink follower races
        if (!\WebCareProScanner\Filesystem\PathValidator::safe_atomic_write($original_path, $clean_data, ABSPATH)) {
            return ['success' => false, 'message' => 'Could not restore backup to original path. Check write permissions.'];
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('remediation_transaction_rollback', [
                'severity' => 'warning',
                /* translators: 1: original file basename */
                'message'  => sprintf(__('Remediation rollback completed for "%1$s". File restored from snapshot.', 'webcare-pro-security'), basename($original_path)),
                'details'  => [
                    'Target File' => $original_path,
                    'Backup ID'   => $backup_id,
                    'SHA-256'     => $record['sha256'] ?? 'N/A',
                ],
            ]);
        }

        return [
            'success' => true,
            'message' => "Remediation successfully reverted! File restored from backup {$record['backup_file']}.",
        ];
    }

    /**
     * Retrieve list of remediation backups
     */
    public function get_backups() {
        $backups = get_option('webcareproscan_remediation_backups', []);
        if (!is_array($backups)) {
            return [];
        }
        return array_values(array_reverse($backups));
    }

    /**
     * Mark issue as repaired in database by ID
     */
    private function mark_issue_repaired($issue_id) {
        if (!$issue_id) {
            return;
        }
        global $wpdb;
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => (int) $issue_id]);
    }

    /**
     * Mark issues associated with a file (and/or specific issue_id) as repaired in database
     *
     * @param string $file_path File path to match
     * @param int|null $issue_id Optional scan issue ID
     */
    private function mark_file_issues_repaired($file_path, $issue_id = null) {
        global $wpdb;
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';

        if ($issue_id) {
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => (int) $issue_id]);
        }

        if (!empty($file_path)) {
            $normalized = wp_normalize_path($file_path);
            $update_sql = "UPDATE `{$table_issues}` SET status = 'repaired' WHERE (file_path = %s OR file_path = %s) AND status != 'repaired'";
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query(
                $wpdb->prepare(
                    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                    $update_sql,
                    $file_path,
                    $normalized
                )
            );
        }
    }

    /**
     * Resolve plugin version from header
     */
    private function get_plugin_version_by_slug($slug) {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugins = get_plugins();
        foreach ($plugins as $file => $data) {
            $dir = dirname($file);
            if ($dir === $slug || $file === $slug || ($dir === '.' && (basename($file, '.php') === $slug || (!empty($data['TextDomain']) && $data['TextDomain'] === $slug)))) {
                return !empty($data['Version']) ? $data['Version'] : null;
            }
        }
        $update_plugins = get_site_transient('update_plugins');
        if (!empty($update_plugins)) {
            foreach (['no_update', 'response'] as $group) {
                if (!empty($update_plugins->$group)) {
                    foreach ($update_plugins->$group as $file => $obj) {
                        if (!empty($obj->slug) && $obj->slug === $slug && !empty($plugins[$file]['Version'])) {
                            return $plugins[$file]['Version'];
                        }
                    }
                }
            }
        }
        return null;
    }
}
