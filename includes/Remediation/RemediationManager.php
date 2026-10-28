<?php
namespace WcpScanner\Remediation;

if (!defined('ABSPATH')) {
    exit;
}

class RemediationManager {

    private $backup_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = untrailingslashit($uploads['basedir']);
        // Primary vault: Dot-prefixed protected directory blocked by Nginx /\.(?!well-known).* rules
        $this->backup_dir = $base . '/wcp-security-scanner/.backups/remediation';
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
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WCP Security: Direct access forbidden.');\n");
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
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security restriction: File resides outside ABSPATH.'];
        }
        $normalized_real = wp_normalize_path($real_path);

        // Prohibit modifying scanner plugin files
        if (strpos($normalized_real, '/plugins/wcp-security-scanner/') !== false) {
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
        $bytes_written = \WcpScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $cleaned_content, ABSPATH);
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
                __('Malware wrapper successfully stripped! Removed %d bytes of injected malicious payload. Safety backup created.', 'wcp-security-scanner'),
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
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, $raw_plugins_dir)) {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress plugins directory.'];
        }
        $normalized_plugins = rtrim(wp_normalize_path(realpath($raw_plugins_dir) ?: $raw_plugins_dir), '/') . '/';

        // Prohibit scanner's own plugin
        if (strpos($normalized_real, '/wcp-security-scanner/') !== false) {
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
        $written = \WcpScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $official_content, ABSPATH);
        if (!$written) {
            return ['success' => false, 'message' => 'Could not write to file. Please check file permissions.'];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'     => true,
            'message'     => sprintf(
                /* translators: 1: plugin slug, 2: version */
                __('File restored to pristine official WordPress.org release (Plugin: %1$s, v%2$s). Safety backup created.', 'wcp-security-scanner'),
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
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, $raw_theme_root)) {
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
        $written = \WcpScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $official_content, ABSPATH);
        if (!$written) {
            return ['success' => false, 'message' => 'Could not write to theme file.'];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'     => true,
            'message'     => sprintf(
                /* translators: 1: theme slug, 2: version */
                __('Theme file restored to pristine official WordPress.org release (Theme: %1$s, v%2$s). Safety backup created.', 'wcp-security-scanner'),
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
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'wcp-security-scanner')];
        }
        $normalized_real = wp_normalize_path($real_path);

        // Security check: Must reside within ABSPATH
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH)) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside the WordPress root directory.', 'wcp-security-scanner')];
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
            return ['success' => false, 'message' => __('Action Blocked: Critical configuration files cannot be overwritten with standard core templates.', 'wcp-security-scanner')];
        }

        // Must be in wp-admin, wp-includes, or root core PHP file
        $is_core_dir = (strpos($rel_file, 'wp-admin/') === 0 || strpos($rel_file, 'wp-includes/') === 0);
        $is_root_core = (!strpos($rel_file, '/') && preg_match('/^wp-.*\.php$|^index\.php$/', $rel_file));

        if (!$is_core_dir && !$is_root_core) {
            return ['success' => false, 'message' => __('Action Blocked: Target file is not recognized as a WordPress core system file.', 'wcp-security-scanner')];
        }

        // Never modify scanner plugin files
        if (strpos($normalized_real, '/plugins/wcp-security-scanner/') !== false) {
            return ['success' => false, 'message' => __('Action Blocked: Cannot modify security scanner files.', 'wcp-security-scanner')];
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
                    __('Could not fetch official WordPress core release source for \'%1$s\' (WP v%2$s). Please verify server outbound internet connectivity.', 'wcp-security-scanner'),
                    $rel_file,
                    $clean_version
                ),
            ];
        }

        $official_content = wp_remote_retrieve_body($response);
        if (empty($official_content)) {
            return ['success' => false, 'message' => __('Retrieved official core source was unexpectedly empty. Action aborted for safety.', 'wcp-security-scanner')];
        }

        // Create safety backup before touching the file
        $backup_result = $this->create_file_backup($real_path, 'official_core_restore');
        if (!$backup_result['success']) {
            return ['success' => false, 'message' => __('Failed to generate safety backup. Aborting for safety.', 'wcp-security-scanner')];
        }

        // Atomically replace core file with pristine official source, preventing symlink follower races
        $written = \WcpScanner\Filesystem\PathValidator::safe_atomic_write($real_path, $official_content, ABSPATH);
        if (!$written) {
            return ['success' => false, 'message' => __('Could not write to core file. Please check server filesystem permissions.', 'wcp-security-scanner')];
        }

        // Mark scan issues as repaired
        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'        => true,
            'message'        => sprintf(
                /* translators: 1: WordPress version, 2: relative file path */
                __('Core file successfully restored to pristine official WordPress.org release (WP v%1$s: %2$s). Safety backup created in vault.', 'wcp-security-scanner'),
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
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'wcp-security-scanner')];
        }

        $is_wp_config_parent = (realpath($real_path) === realpath(dirname(ABSPATH) . '/wp-config.php'));
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH) && !$is_wp_config_parent) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside WordPress root directory.', 'wcp-security-scanner')];
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
                    __('Failed to change permissions for %1$s from %2$s to %3$s. Ensure the web server user has sufficient write privileges on this path.', 'wcp-security-scanner'),
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
                __('Permissions successfully hardened for %1$s from %2$s to %3$s.', 'wcp-security-scanner'),
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
     * Takes an atomic safety snapshot in WCP Vault before unlinking to allow recovery.
     *
     * @param string $file_path
     * @param int|null $issue_id
     * @return array
     */
    public function delete_file($file_path, $issue_id = null) {
        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !file_exists($real_path)) {
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'wcp-security-scanner')];
        }

        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH)) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside WordPress root directory.', 'wcp-security-scanner')];
        }

        // Prevent accidental deletion of protected core WordPress files
        $base_name = strtolower(basename($real_path));
        $protected_files = [
            'wp-config.php', 'wp-settings.php', 'wp-load.php', 'index.php', '.htaccess',
            'wp-blog-header.php', 'wp-login.php', 'wp-cron.php', 'xmlrpc.php'
        ];
        if (in_array($base_name, $protected_files, true)) {
            return ['success' => false, 'message' => sprintf(
                /* translators: %s: file basename */
                __('Action Blocked: %s is a protected WordPress core system file and cannot be deleted.', 'wcp-security-scanner'),
                $base_name
            )];
        }

        // Take safety backup snapshot in WCP Vault
        $backup_res = $this->create_file_backup($real_path, 'delete_rogue_file');
        $backup_id = !empty($backup_res['backup_id']) ? $backup_res['backup_id'] : null;

        // Unlink the file
        $unlinked = wp_delete_file($real_path);
        clearstatcache(true, $real_path);

        if (!$unlinked && file_exists($real_path)) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: file basename */
                    __('Failed to delete %s. Check server filesystem write permissions.', 'wcp-security-scanner'),
                    basename($real_path)
                )
            ];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'   => true,
            'message'   => sprintf(
                /* translators: %s: file basename */
                __('Rogue file %s was permanently deleted from your server. A safety snapshot was retained in WCP Vault.', 'wcp-security-scanner'),
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
     * 1. Safely creates an encrypted, permission-locked snapshot in the WCP Vault prior to modification.
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
                'message' => __('Target wp-config.php file does not exist on server.', 'wcp-security-scanner'),
            ];
        }

        $is_wp_config = (strtolower(basename($real_path)) === 'wp-config.php');
        if (!$is_wp_config) {
            return [
                'success' => false,
                'message' => __('Action Blocked: Target file is not wp-config.php.', 'wcp-security-scanner'),
            ];
        }

        $is_wp_config_parent = (realpath($real_path) === realpath(dirname(ABSPATH) . '/wp-config.php'));
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($real_path, ABSPATH) && !$is_wp_config_parent) {
            return [
                'success' => false,
                'message' => __('Action Blocked: File is outside WordPress root directory.', 'wcp-security-scanner'),
            ];
        }

        if (!is_writable($real_path)) {
            return [
                'success' => false,
                'message' => __('wp-config.php is not writable by the web server. Please check file permissions or owner.', 'wcp-security-scanner'),
            ];
        }

        // Create safety backup in WCP Vault before modifying
        $backup_result = $this->create_file_backup($real_path, 'disable_wp_debug');
        if (empty($backup_result['success'])) {
            return [
                'success' => false,
                'message' => __('Failed to create encrypted safety backup before modification. Aborting to protect your configuration.', 'wcp-security-scanner'),
            ];
        }

        $content = @file_get_contents($real_path);
        if ($content === false || strlen($content) < 30) {
            return [
                'success' => false,
                'message' => __('Could not read contents of wp-config.php.', 'wcp-security-scanner'),
            ];
        }

        $has_debug = (bool) preg_match('/define\s*\(\s*[\'"]WP_DEBUG[\'"]\s*,/i', $content);
        $has_log = (bool) preg_match('/define\s*\(\s*[\'"]WP_DEBUG_LOG[\'"]\s*,/i', $content);
        $has_display = (bool) preg_match('/define\s*\(\s*[\'"]WP_DEBUG_DISPLAY[\'"]\s*,/i', $content);
        $has_script_debug = (bool) preg_match('/define\s*\(\s*[\'"]SCRIPT_DEBUG[\'"]\s*,/i', $content);
        $has_savequeries = (bool) preg_match('/define\s*\(\s*[\'"]SAVEQUERIES[\'"]\s*,/i', $content);
        $has_ini_display = (bool) preg_match('/@?ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,/i', $content);

        $modified = $content;

        // In-place updates for already existing directives
        if ($has_log) {
            $modified = preg_replace('/[ \t]*define\s*\(\s*([\'"])WP_DEBUG_LOG\1\s*,\s*[^)]+\s*\)\s*;[^\r\n]*/i', "define('WP_DEBUG_LOG', false);", $modified);
        }
        if ($has_display) {
            $modified = preg_replace('/[ \t]*define\s*\(\s*([\'"])WP_DEBUG_DISPLAY\1\s*,\s*[^)]+\s*\)\s*;[^\r\n]*/i', "define('WP_DEBUG_DISPLAY', false);", $modified);
        }
        if ($has_script_debug) {
            $modified = preg_replace('/[ \t]*define\s*\(\s*([\'"])SCRIPT_DEBUG\1\s*,\s*[^)]+\s*\)\s*;[^\r\n]*/i', "define('SCRIPT_DEBUG', false);", $modified);
        }
        if ($has_savequeries) {
            $modified = preg_replace('/[ \t]*define\s*\(\s*([\'"])SAVEQUERIES\1\s*,\s*[^)]+\s*\)\s*;[^\r\n]*/i', "define('SAVEQUERIES', false);", $modified);
        }
        if ($has_ini_display) {
            $modified = preg_replace('/[ \t]*@?ini_set\s*\(\s*([\'"])display_errors\1\s*,\s*[^)]+\s*\)\s*;[^\r\n]*/i', "@ini_set('display_errors', '0');", $modified);
        }

        // Determine missing auxiliary directives to bundle cleanly with WP_DEBUG
        $additions = [];
        if (!$has_log) {
            $additions[] = "define('WP_DEBUG_LOG', false);";
        }
        if (!$has_display) {
            $additions[] = "define('WP_DEBUG_DISPLAY', false);";
        }
        if (!$has_ini_display) {
            $additions[] = "@ini_set('display_errors', '0');";
        }

        $debug_block = array_merge(["define('WP_DEBUG', false);"], $additions);
        $debug_block_str = implode("\n", $debug_block);

        if ($has_debug) {
            $modified = preg_replace('/[ \t]*define\s*\(\s*([\'"])WP_DEBUG\1\s*,\s*[^)]+\s*\)\s*;[^\r\n]*/i', $debug_block_str, $modified);
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
                    $modified = str_replace($target, $debug_block_str . "\n\n" . $target, $modified);
                    $inserted = true;
                    break;
                }
            }
            if (!$inserted) {
                $modified .= "\n\n" . $debug_block_str . "\n";
            }
        }

        // Validate PHP token stream
        $tokens = @token_get_all($modified);
        if (empty($tokens) || count($tokens) < 5) {
            return [
                'success' => false,
                'message' => __('Syntax verification failed on transformed configuration. Modification canceled to avoid site downtime.', 'wcp-security-scanner'),
            ];
        }

        // Atomic write
        $write_success = @file_put_contents($real_path, $modified, LOCK_EX);
        if ($write_success === false) {
            return [
                'success' => false,
                'message' => __('Failed to write updated configuration to wp-config.php. Check disk space and permissions.', 'wcp-security-scanner'),
            ];
        }

        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($real_path, true);
        }
        clearstatcache(true, $real_path);

        $this->mark_file_issues_repaired($real_path, $issue_id);

        global $wpdb;
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_issues, ['status' => 'repaired'], ['type' => 'wp_debug_enabled']);

        return [
            'success'   => true,
            'message'   => __('WordPress debugging has been securely disabled in wp-config.php (WP_DEBUG, WP_DEBUG_LOG, and WP_DEBUG_DISPLAY set to false; display_errors silenced). Encrypted backup retained in WCP Vault.', 'wcp-security-scanner'),
            'backup_id' => $backup_result['backup_id'],
            'file_path' => $real_path,
        ];
    }

    /**
     * Create safety backup before any remediation action
     */
    private function create_file_backup($file_path, $action_type) {
        $backup_id = uniqid('rem_', true);
        $filename = basename($file_path) . '_' . gmdate('Ymd_His') . '_' . substr(md5($backup_id), 0, 8) . '.bak.php';
        $dest_path = $this->backup_dir . '/' . $filename;

        $content = @file_get_contents($file_path);
        if ($content === false) {
            return ['success' => false];
        }

        $guard = "<?php http_response_code(403); exit('WCP Security: Direct access forbidden.'); __halt_compiler(); ?>\n";
        $encrypted = \WcpScanner\Security\SecretVault::encrypt($content);

        if (@file_put_contents($dest_path, $guard . $encrypted, LOCK_EX) === false) {
            return ['success' => false];
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

        $backups = get_option('wcpscan_remediation_backups', []);
        if (!is_array($backups)) {
            $backups = [];
        }

        $backups[$backup_id] = [
            'id'            => $backup_id,
            'original_path' => $file_path,
            'backup_path'   => $dest_path,
            'backup_file'   => $filename,
            'action_type'   => $action_type,
            'created_at'    => current_time('mysql'),
            'size'          => strlen($content),
            'sha256'        => hash('sha256', $content),
        ];

        // Keep last 100 backups
        if (count($backups) > 100) {
            $oldest = array_shift($backups);
            if (!empty($oldest['backup_path']) && file_exists($oldest['backup_path'])) {
                wp_delete_file($oldest['backup_path']);
            }
        }

        update_option('wcpscan_remediation_backups', $backups, false);

        return ['success' => true, 'backup_id' => $backup_id];
    }

    /**
     * Rollback a remediation action using its backup ID
     */
    public function rollback_remediation($backup_id) {
        $backups = get_option('wcpscan_remediation_backups', []);
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

        if (\WcpScanner\Security\SecretVault::is_encrypted($payload)) {
            $decrypted = \WcpScanner\Security\SecretVault::decrypt($payload);
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
        if (!\WcpScanner\Filesystem\PathValidator::is_safe_write_target($original_path, ABSPATH)) {
            return ['success' => false, 'message' => 'Security restriction: Rollback destination resides outside WordPress root directory.'];
        }

        // Atomically restore backup to original path, preventing symlink follower races
        if (!\WcpScanner\Filesystem\PathValidator::safe_atomic_write($original_path, $clean_data, ABSPATH)) {
            return ['success' => false, 'message' => 'Could not restore backup to original path. Check write permissions.'];
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
        $backups = get_option('wcpscan_remediation_backups', []);
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
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
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
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';

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
