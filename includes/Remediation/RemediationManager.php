<?php
namespace WCP\Scanner\Remediation;

if (!defined('ABSPATH')) {
    exit;
}

class RemediationManager {

    private $backup_dir;
    private $legacy_backup_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = !empty($uploads['basedir']) ? untrailingslashit($uploads['basedir']) : WP_CONTENT_DIR . '/uploads';
        // Primary vault: Dot-prefixed protected directory blocked by Nginx /\.(?!well-known).* rules
        $this->backup_dir = $base . '/wcp-security-scanner/.backups/remediation';
        $this->legacy_backup_dir = $base . '/wcp-security-scanner/backups/remediation';
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
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist or is a directory.'];
        }

        // Must reside within WordPress installation root
        $real_root = wp_normalize_path(untrailingslashit(ABSPATH)) . '/';
        $normalized_real = wp_normalize_path($real_path);
        if (strpos($normalized_real, $real_root) !== 0) {
            return ['success' => false, 'message' => 'Security restriction: File resides outside ABSPATH.'];
        }

        // Prohibit modifying scanner plugin files
        if (strpos($normalized_real, '/plugins/wcp-wp-scanner/') !== false || strpos($normalized_real, '/plugins/wcp-security-scanner/') !== false) {
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

        // Write sanitized content
        $bytes_written = @file_put_contents($real_path, $cleaned_content, LOCK_EX);
        if ($bytes_written === false) {
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
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist on server.'];
        }

        $normalized_real = wp_normalize_path($real_path);
        $normalized_plugins = wp_normalize_path(WP_PLUGIN_DIR) . '/';

        if (strpos($normalized_real, $normalized_plugins) !== 0) {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress plugins directory.'];
        }

        // Prohibit scanner's own plugin
        if (strpos($normalized_real, '/wcp-wp-scanner/') !== false || strpos($normalized_real, '/wcp-security-scanner/') !== false) {
            return ['success' => false, 'message' => 'Action Blocked: Cannot reinstall security scanner files.'];
        }

        $rel_within_plugins = substr($normalized_real, strlen($normalized_plugins));
        $parts = explode('/', $rel_within_plugins, 2);
        $plugin_slug = $parts[0];
        $internal_file = isset($parts[1]) ? $parts[1] : '';

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

        // Replace file with official source
        $written = @file_put_contents($real_path, $official_content, LOCK_EX);
        if ($written === false) {
            return ['success' => false, 'message' => 'Could not write to file. Please check file permissions.'];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'     => true,
            'message'     => sprintf(
                __("File restored to pristine official WordPress.org release (Plugin: %s, v%s). Safety backup created.", 'wcp-security-scanner'),
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
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => 'Target file does not exist on server.'];
        }

        $normalized_real = wp_normalize_path($real_path);
        $theme_root = function_exists('get_theme_root') ? wp_normalize_path(get_theme_root()) . '/' : wp_normalize_path(WP_CONTENT_DIR . '/themes') . '/';

        if (strpos($normalized_real, $theme_root) !== 0) {
            return ['success' => false, 'message' => 'Action Blocked: File is not inside the WordPress themes directory.'];
        }

        $rel_within_themes = substr($normalized_real, strlen($theme_root));
        $parts = explode('/', $rel_within_themes, 2);
        $theme_slug = $parts[0];
        $internal_file = isset($parts[1]) ? $parts[1] : '';

        if (!$theme_slug || !$internal_file) {
            return ['success' => false, 'message' => 'Invalid theme directory structure.'];
        }

        $theme = wp_get_theme($theme_slug);
        if (!$theme->exists()) {
            return ['success' => false, 'message' => "Theme '{$theme_slug}' not found."];
        }

        $version = $theme->get('Version');

        // Check if bundled default theme (in core) or from WordPress.org theme repository
        global $wp_version;
        $clean_wp = preg_replace('/-.*$/', '', $wp_version);
        $core_theme_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$clean_wp}/wp-content/themes/{$theme_slug}/{$internal_file}";
        $response = wp_remote_get($core_theme_url, ['timeout' => 15, 'sslverify' => true]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Try themes SVN
            $theme_svn_url = "https://themes.svn.wordpress.org/{$theme_slug}/{$version}/{$internal_file}";
            $response = wp_remote_get($theme_svn_url, ['timeout' => 15, 'sslverify' => true]);
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

        $written = @file_put_contents($real_path, $official_content, LOCK_EX);
        if ($written === false) {
            return ['success' => false, 'message' => 'Could not write to theme file.'];
        }

        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'     => true,
            'message'     => sprintf(
                __("Theme file restored to pristine official WordPress.org release (Theme: %s, v%s). Safety backup created.", 'wcp-security-scanner'),
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
        if (!$real_path || !file_exists($real_path) || is_dir($real_path)) {
            return ['success' => false, 'message' => __('Target file does not exist on server.', 'wcp-security-scanner')];
        }

        $normalized_real = wp_normalize_path($real_path);
        $normalized_abs = wp_normalize_path(ABSPATH);

        // Security check: Must reside within ABSPATH
        if (strpos($normalized_real, $normalized_abs) !== 0) {
            return ['success' => false, 'message' => __('Action Blocked: File is outside the WordPress root directory.', 'wcp-security-scanner')];
        }

        $rel_file = ltrim(substr($normalized_real, strlen($normalized_abs)), '/');

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
        if (strpos($normalized_real, '/plugins/wcp-wp-scanner/') !== false || strpos($normalized_real, '/plugins/wcp-security-scanner/') !== false) {
            return ['success' => false, 'message' => __('Action Blocked: Cannot modify security scanner files.', 'wcp-security-scanner')];
        }

        global $wp_version;
        $clean_version = preg_replace('/-.*$/', '', $wp_version);

        // Fetch official clean source from WordPress.org SVN
        $official_url = "https://core.svn.wordpress.org/tags/{$clean_version}/{$rel_file}";
        $response = wp_remote_get($official_url, ['timeout' => 15, 'sslverify' => true]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Fallback to official WordPress GitHub release tag
            $github_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$clean_version}/{$rel_file}";
            $response = wp_remote_get($github_url, ['timeout' => 15, 'sslverify' => true]);
        }

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return [
                'success' => false,
                'message' => sprintf(
                    __("Could not fetch official WordPress core release source for '%s' (WP v%s). Please verify server outbound internet connectivity.", 'wcp-security-scanner'),
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

        // Replace file with pristine official WordPress source
        $written = @file_put_contents($real_path, $official_content, LOCK_EX);
        if ($written === false) {
            return ['success' => false, 'message' => __('Could not write to core file. Please check server filesystem permissions.', 'wcp-security-scanner')];
        }

        // Mark scan issues as repaired
        $this->mark_file_issues_repaired($real_path, $issue_id);

        return [
            'success'        => true,
            'message'        => sprintf(
                __("Core file successfully restored to pristine official WordPress.org release (WP v%s: %s). Safety backup created in vault.", 'wcp-security-scanner'),
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
     * Create safety backup before any remediation action
     */
    private function create_file_backup($file_path, $action_type) {
        $backup_id = uniqid('rem_', true);
        $filename = basename($file_path) . '_' . date('Ymd_His') . '_' . substr(md5($backup_id), 0, 8) . '.bak.php';
        $dest_path = $this->backup_dir . '/' . $filename;

        $content = @file_get_contents($file_path);
        if ($content === false) {
            return ['success' => false];
        }

        $guard = "<?php http_response_code(403); exit('WCP Security: Direct access forbidden.'); __halt_compiler(); ?>\n";
        $encrypted = \WCP\Scanner\Security\SecretVault::encrypt($content);

        if (@file_put_contents($dest_path, $guard . $encrypted, LOCK_EX) === false) {
            return ['success' => false];
        }
        @chmod($dest_path, 0600);

        $backups = get_option('wcp_remediation_backups', []);
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
        ];

        // Keep last 100 backups
        if (count($backups) > 100) {
            $oldest = array_shift($backups);
            if (!empty($oldest['backup_path']) && file_exists($oldest['backup_path'])) {
                @unlink($oldest['backup_path']);
            }
        }

        update_option('wcp_remediation_backups', $backups, false);

        return ['success' => true, 'backup_id' => $backup_id];
    }

    /**
     * Rollback a remediation action using its backup ID
     */
    public function rollback_remediation($backup_id) {
        $backups = get_option('wcp_remediation_backups', []);
        if (!isset($backups[$backup_id])) {
            return ['success' => false, 'message' => 'Backup record not found.'];
        }

        $record = $backups[$backup_id];
        $backup_path = $record['backup_path'];
        $original_path = $record['original_path'];

        if (!file_exists($backup_path) && isset($this->legacy_backup_dir)) {
            $legacy_alt = $this->legacy_backup_dir . '/' . $record['backup_file'];
            if (file_exists($legacy_alt)) {
                $backup_path = $legacy_alt;
            }
        }

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

        if (\WCP\Scanner\Security\SecretVault::is_encrypted($payload)) {
            $decrypted = \WCP\Scanner\Security\SecretVault::decrypt($payload);
            if ($decrypted === false) {
                return ['success' => false, 'message' => 'Cryptographic decryption failed: Invalid vault key or corrupted backup ciphertext.'];
            }
            $clean_data = $decrypted;
        } else {
            $clean_data = $payload;
        }

        if (@file_put_contents($original_path, $clean_data, LOCK_EX) === false) {
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
        $backups = get_option('wcp_remediation_backups', []);
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
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';

        if ($issue_id) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => (int) $issue_id]);
        }

        if (!empty($file_path)) {
            $normalized = wp_normalize_path($file_path);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$table_issues} SET status = 'repaired' WHERE (file_path = %s OR file_path = %s) AND status != 'repaired'",
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
