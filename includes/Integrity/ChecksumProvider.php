<?php
namespace WcpScanner\Integrity;

if (!defined('ABSPATH')) {
    exit;
}

class ChecksumProvider {
    
    /**
     * In-memory cache for official WordPress core checksums to avoid redundant transient/DB queries in high-volume batch loops.
     * @var array|null
     */
    private static $core_checksums_memory = null;

    /**
     * In-memory cache for plugin checksums indexed by slug_version.
     * @var array
     */
    private static $plugin_checksums_memory = [];

    /**
     * In-memory cache for theme checksums indexed by slug_version.
     * @var array
     */
    private static $theme_checksums_memory = [];

    /**
     * In-memory cache for installed plugin versions.
     * @var array|null
     */
    private static $installed_plugin_versions = null;

    /**
     * In-memory cache for installed theme versions.
     * @var array|null
     */
    private static $installed_theme_versions = null;

    /**
     * Fetch core checksums for the current WordPress version.
     *
     * @return array|null Array of file => hash, or null on failure.
     */
    public function get_core_checksums() {
        if (self::$core_checksums_memory !== null && is_array(self::$core_checksums_memory)) {
            return self::$core_checksums_memory;
        }

        global $wp_version, $wp_local_package;

        $locale = empty($wp_local_package) ? 'en_US' : $wp_local_package;
        $version = $wp_version;
        
        // Strip out extra version info for alpha/beta
        $version = preg_replace('/-.*$/', '', $version);

        $cache_key = "wcpscan_core_chk_{$version}_{$locale}";
        $cached = get_transient($cache_key);
        if ($cached !== false && is_array($cached)) {
            self::$core_checksums_memory = $cached;
            return $cached;
        }

        $url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}";
        
        $response = wp_remote_get($url, ['timeout' => 15]);
        
        if (is_wp_error($response)) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['checksums']) && is_array($data['checksums'])) {
            set_transient($cache_key, $data['checksums'], 12 * HOUR_IN_SECONDS);
            self::$core_checksums_memory = $data['checksums'];
            return $data['checksums'];
        }

        return null;
    }

    /**
     * Fetch checksums for a specific plugin.
     *
     * @param string $plugin_slug e.g., 'akismet'
     * @param string $version
     * @return array|null
     */
    public function get_plugin_checksums($plugin_slug, $version) {
        $plugin_slug = sanitize_title($plugin_slug);
        $version = trim(preg_replace('/^v/i', '', (string) $version));
        if (empty($plugin_slug) || empty($version)) {
            return null;
        }

        $mem_key = "{$plugin_slug}_{$version}";
        if (isset(self::$plugin_checksums_memory[$mem_key])) {
            return self::$plugin_checksums_memory[$mem_key] === 'none' ? null : self::$plugin_checksums_memory[$mem_key];
        }

        $cache_key = "wcpscan_plugin_chk_{$plugin_slug}_{$version}";
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            if ($cached === 'none' || !is_array($cached)) {
                self::$plugin_checksums_memory[$mem_key] = 'none';
                return null;
            }
            self::$plugin_checksums_memory[$mem_key] = $cached;
            return $cached;
        }

        $url = "https://downloads.wordpress.org/plugin-checksums/{$plugin_slug}/{$version}.json";
        
        $response = wp_remote_get($url, [
            'timeout'   => 8,
            'sslverify' => true,
        ]);
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Negative cache to prevent repeated blocking HTTP requests across hundreds/thousands of files in this plugin
            set_transient($cache_key, 'none', 6 * HOUR_IN_SECONDS);
            self::$plugin_checksums_memory[$mem_key] = 'none';
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['files']) && is_array($data['files'])) {
            // Reformat to match core checksums (file => hash/hashes)
            $checksums = [];
            foreach ($data['files'] as $file => $info) {
                if (is_string($info)) {
                    $checksums[$file] = $info;
                } elseif (is_array($info)) {
                    if (isset($info['md5'])) {
                        $checksums[$file] = $info['md5']; // Can be string or array of MD5 hashes
                    } elseif (isset($info['sha256'])) {
                        $checksums[$file] = ['algo' => 'sha256', 'hash' => $info['sha256']];
                    }
                }
            }
            if (!empty($checksums)) {
                set_transient($cache_key, $checksums, 12 * HOUR_IN_SECONDS);
                self::$plugin_checksums_memory[$mem_key] = $checksums;
                return $checksums;
            }
        }

        set_transient($cache_key, 'none', 6 * HOUR_IN_SECONDS);
        self::$plugin_checksums_memory[$mem_key] = 'none';
        return null;
    }

    /**
     * Fetch checksums for an official theme.
     *
     * @param string $theme_slug e.g., 'twentytwentyfour', 'hello-elementor'
     * @param string $version
     * @return array|null Array of relative_file => hash/bool
     */
    public function get_theme_checksums($theme_slug, $version) {
        $theme_slug = sanitize_title($theme_slug);
        $version = trim(preg_replace('/^v/i', '', (string) $version));
        if (empty($theme_slug) || empty($version)) {
            return null;
        }

        $mem_key = "{$theme_slug}_{$version}";
        if (isset(self::$theme_checksums_memory[$mem_key])) {
            return self::$theme_checksums_memory[$mem_key] === 'none' ? null : self::$theme_checksums_memory[$mem_key];
        }

        $cache_key = "wcpscan_theme_chk_v3_{$theme_slug}_{$version}";
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            if ($cached === 'none' || !is_array($cached)) {
                self::$theme_checksums_memory[$mem_key] = 'none';
                return null;
            }
            self::$theme_checksums_memory[$mem_key] = $cached;
            return $cached;
        }

        // 1. Fetch exact theme version zip from WordPress.org to extract pristine release manifest
        $url = "https://downloads.wordpress.org/theme/{$theme_slug}.{$version}.zip";
        $response = wp_remote_head($url, ['timeout' => 8, 'sslverify' => true]);
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            if (class_exists('\ZipArchive')) {
                if (!function_exists('download_url')) {
                    require_once ABSPATH . 'wp-admin/includes/file.php';
                }
                $tmp_file = download_url($url, 25);
                if (!is_wp_error($tmp_file)) {
                    $zip = new \ZipArchive();
                    if ($zip->open($tmp_file) === true) {
                        $manifest = [];
                        $zip_prefix = "{$theme_slug}/";
                        for ($i = 0; $i < $zip->numFiles; $i++) {
                            $stat = $zip->statIndex($i);
                            $entry_name = $stat['name'];
                            if (substr($entry_name, -1) === '/') {
                                continue; // Skip directories
                            }
                            if (strpos($entry_name, $zip_prefix) === 0) {
                                $rel_name = substr($entry_name, strlen($zip_prefix));
                                $stream = $zip->getStream($entry_name);
                                if ($stream) {
                                    $manifest[$rel_name] = md5(stream_get_contents($stream));
                                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                                    fclose($stream);
                                } else {
                                    $manifest[$rel_name] = true;
                                }
                            }
                        }
                        $zip->close();
                        wp_delete_file($tmp_file);
                        if (!empty($manifest)) {
                            set_transient($cache_key, $manifest, defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400);
                            self::$theme_checksums_memory[$mem_key] = $manifest;
                            return $manifest;
                        }
                    }
                    wp_delete_file($tmp_file);
                }
            }
        }

        // 2. Fallback: If standalone theme zip is unavailable, check if bundled in core checksums for current WP version
        $core_checksums = $this->get_core_checksums();
        if ($core_checksums) {
            $prefix = "wp-content/themes/{$theme_slug}/";
            $theme_files = [];
            foreach ($core_checksums as $file => $hash) {
                if (strpos($file, $prefix) === 0) {
                    $rel = substr($file, strlen($prefix));
                    $theme_files[$rel] = $hash;
                }
            }
            if (!empty($theme_files)) {
                set_transient($cache_key, $theme_files, defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400);
                self::$theme_checksums_memory[$mem_key] = $theme_files;
                return $theme_files;
            }
        }

        // Negative cache theme manifest failure
        set_transient($cache_key, 'none', 6 * HOUR_IN_SECONDS);
        self::$theme_checksums_memory[$mem_key] = 'none';
        return null;
    }

    /**
     * Check if a given absolute file path is an authentic, unmodified WordPress core file.
     *
     * @param string $file_path Absolute path to the file.
     * @return bool True if the file resides in core and bit-for-bit matches official WordPress.org checksums.
     */
    public static function is_authentic_core_file(string $file_path): bool {
        if (!defined('ABSPATH')) {
            return false;
        }

        $norm_path = str_replace('\\', '/', $file_path);
        $norm_abs  = str_replace('\\', '/', rtrim(ABSPATH, '/\\') . '/');

        // Must be located within WordPress root
        if (strpos($norm_path, $norm_abs) !== 0) {
            return false;
        }

        $rel_file = substr($norm_path, strlen($norm_abs));

        // wp-content is NOT part of core (themes/plugins/uploads)
        if (strpos($rel_file, 'wp-content/') === 0) {
            return false;
        }

        // Fast path check: Only files in wp-includes/, wp-admin/, or root files can be core
        $is_core_dir = (
            strpos($rel_file, 'wp-includes/') === 0 ||
            strpos($rel_file, 'wp-admin/') === 0 ||
            (strpos($rel_file, '/') === false && (strpos($rel_file, 'wp-') === 0 || $rel_file === 'index.php'))
        );

        if (!$is_core_dir) {
            return false;
        }

        $provider = new self();
        $checksums = $provider->get_core_checksums();
        if (empty($checksums) || !isset($checksums[$rel_file])) {
            return false;
        }

        $expected_md5 = $checksums[$rel_file];
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        $actual_md5 = md5_file($file_path);
        if ($actual_md5 === $expected_md5) {
            return true;
        }

        // Handle line-ending normalization (CRLF vs LF) to prevent OS/zip extraction false positives
        $raw_content = @file_get_contents($file_path);
        if ($raw_content !== false) {
            if (md5(str_replace("\r\n", "\n", $raw_content)) === $expected_md5) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a file belongs to an installed plugin and matches official WordPress.org plugin checksums.
     *
     * @param string $file_path Absolute path to the file.
     * @return bool
     */
    public static function is_authentic_plugin_file(string $file_path): bool {
        if (!defined('WP_PLUGIN_DIR')) {
            return false;
        }

        $norm_path   = str_replace('\\', '/', $file_path);
        $plugin_dir  = str_replace('\\', '/', rtrim(WP_PLUGIN_DIR, '/\\') . '/');

        if (strpos($norm_path, $plugin_dir) !== 0) {
            return false;
        }

        $rel_path = substr($norm_path, strlen($plugin_dir));
        $parts = explode('/', $rel_path, 2);
        if (count($parts) < 2) {
            return false; // Single-file plugin in root of plugins directory
        }

        $slug = $parts[0];
        $file_inside_plugin = $parts[1];

        // Self-exclusion: our scanner handles its own self-exclusion
        if ($slug === 'wcp-security-scanner') {
            return true;
        }

        $version = self::get_installed_plugin_version($slug);
        if (empty($version)) {
            return false;
        }

        $provider = new self();
        $checksums = $provider->get_plugin_checksums($slug, $version);
        if (empty($checksums) || !isset($checksums[$file_inside_plugin])) {
            return false;
        }

        $expected = $checksums[$file_inside_plugin];
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        $actual_md5 = md5_file($file_path);

        if (is_string($expected) && $actual_md5 === $expected) {
            return true;
        }

        if (is_array($expected)) {
            if (isset($expected['algo']) && $expected['algo'] === 'sha256') {
                return hash_file('sha256', $file_path) === $expected['hash'];
            }
            if (in_array($actual_md5, $expected, true)) {
                return true;
            }
        }

        // Handle line-ending normalization (CRLF vs LF)
        $raw_content = @file_get_contents($file_path);
        if ($raw_content !== false) {
            $norm_md5 = md5(str_replace("\r\n", "\n", $raw_content));
            if (is_string($expected) && $norm_md5 === $expected) {
                return true;
            }
            if (is_array($expected) && in_array($norm_md5, $expected, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Retrieve the version of an installed plugin by directory slug.
     *
     * @param string $slug
     * @return string|null
     */
    public static function get_installed_plugin_version(string $slug): ?string {
        if (self::$installed_plugin_versions === null) {
            self::$installed_plugin_versions = [];
            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            if (function_exists('get_plugins')) {
                $all_plugins = get_plugins();
                foreach ($all_plugins as $plugin_file => $plugin_data) {
                    $plugin_slug = dirname($plugin_file);
                    if ($plugin_slug !== '.' && !empty($plugin_data['Version'])) {
                        self::$installed_plugin_versions[$plugin_slug] = $plugin_data['Version'];
                    }
                }
            }
        }

        return self::$installed_plugin_versions[$slug] ?? null;
    }

    /**
     * Retrieve the version of an installed theme by directory slug.
     *
     * @param string $slug
     * @return string|null
     */
    public static function get_installed_theme_version(string $slug): ?string {
        if (self::$installed_theme_versions === null) {
            self::$installed_theme_versions = [];
            if (!function_exists('wp_get_themes')) {
                require_once ABSPATH . WPINC . '/theme.php';
            }
            if (function_exists('wp_get_themes')) {
                $themes = wp_get_themes();
                foreach ($themes as $theme_slug => $theme_obj) {
                    $ver = $theme_obj->get('Version');
                    if (!empty($ver)) {
                        self::$installed_theme_versions[$theme_slug] = $ver;
                    }
                }
            }
        }

        return self::$installed_theme_versions[$slug] ?? null;
    }

    /**
     * Check if a file belongs to an installed official theme and matches official WordPress.org checksums.
     *
     * @param string $file_path Absolute path to the file.
     * @return bool
     */
    public static function is_authentic_theme_file(string $file_path): bool {
        $check = self::verify_theme_file($file_path);
        return ($check['status'] === 'authentic');
    }

    /**
     * Known legitimate vendor packages, LMS runtimes, and SCORM/HTML5 learning players
     * distributed within WordPress uploads (e.g. Uncanny Automator / TinCan SCORM modules,
     * Articulate Storyline / Rise players, Elementor assets) verified against known cryptographic hashes.
     * Format: 'sha256_hash' => ['vendor' => string, 'package' => string]
     *
     * @return array<string, array{vendor: string, package: string}>
     */
    public static function get_whitelisted_vendor_hashes(): array {
        return [
            // Articulate Storyline 360 / Rise HTML5 LMS player bootstrap bundle (ds-bootstrap)
            // Windows CRLF & standard LF cryptographic checksums:
            '0fafb9e63413eb6cf41e5e3241f441af78c9de719837f43744e868c118010c76' => [
                'vendor'  => 'Articulate Storyline / Uncanny Automator SCORM',
                'package' => 'bootstrapper.min.js (ds-bootstrap v1.0.0.33139)',
            ],
            '835bebae86ae2b1b4efe6ff713ab5505d9df057fac993197602953cfc43e9049' => [
                'vendor'  => 'Articulate Storyline / Uncanny Automator SCORM',
                'package' => 'bootstrapper.min.js (ds-bootstrap v1.0.0.33139 LF)',
            ],
        ];
    }

    /**
     * Checks if a file (especially inside uploads/ or vendor assets) is an authentic,
     * verified legitimate third-party vendor library or SCORM/HTML5 player matching known safe hashes
     * or legitimate vendor header structures with zero malware.
     *
     * @param string $file_path
     * @return bool True if recognized as an authentic, clean vendor/SCORM package file.
     */
    public static function is_authentic_known_library(string $file_path): bool {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        // 1. Check custom uploads verified file hash JSON registry (uploads-whitelisted-hashes.json)
        if (class_exists('\WcpScanner\Findings\WhitelistManager') && \WcpScanner\Findings\WhitelistManager::is_uploads_hash_whitelisted($file_path)) {
            return true;
        }

        // Fast hash verification (O(1) dictionary lookup)
        $sha256 = hash_file('sha256', $file_path);
        $whitelisted_hashes = self::get_whitelisted_vendor_hashes();
        if ($sha256 && isset($whitelisted_hashes[$sha256])) {
            return true;
        }

        // Normalize line endings to test LF hash if file was saved with CRLF or vice versa
        $content = @file_get_contents($file_path);
        if ($content !== false && strlen($content) > 0) {
            $lf_sha256 = hash('sha256', str_replace("\r\n", "\n", $content));
            if (isset($whitelisted_hashes[$lf_sha256])) {
                return true;
            }

            // Vendor pattern recognition for Articulate Storyline / Uncanny SCORM packages in uploads
            $norm = str_replace('\\', '/', $file_path);
            if (preg_match('#/wp-content/uploads/uncanny-snc/[^/]+/html5/lib/scripts/[^/]+\.js$#i', $norm)) {
                // Must have authentic Articulate Storyline / ds-bootstrap vendor header
                if (strpos($content, 'ds-bootstrap') !== false || strpos($content, 'Articulate') !== false || strpos($content, 'window.DS=window.DS||{}') !== false) {
                    // Strict anti-malware verification: must NOT contain webshell droppers or malicious sinks
                    $has_malware_sink = (bool) preg_match('/(?<!->|::|function\s)\b(assert|create_function|passthru|shell_exec|system|proc_open|popen)\s*\(/i', $content);
                    $has_payload_dropper = (bool) preg_match('#\\b(base64_decode|gzinflate|gzuncompress|str_rot13)\\s*\\(#i', $content);
                    $has_exfil = (bool) preg_match('/https?:\/\/(?:discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|pastebin\.com\/api|transfer\.sh|iplogger\.org)/i', $content);

                    if (!$has_malware_sink && !$has_payload_dropper && !$has_exfil) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Strictly verify a file against official WordPress core checksums and detect rogue/unknown files.
     *
     * @param string $file_path
     * @return array [
     *   'status'   => 'not_core' | 'authentic' | 'modified' | 'unknown' | 'ignored',
     *   'rel_file' => string,
     *   'expected' => string,
     *   'actual'   => string
     * ]
     */
    public static function verify_core_file(string $file_path): array {
        if (!defined('ABSPATH')) {
            return ['status' => 'not_core'];
        }

        $norm_path = str_replace('\\', '/', $file_path);
        $norm_abs  = str_replace('\\', '/', rtrim(ABSPATH, '/\\') . '/');

        if (strpos($norm_path, $norm_abs) !== 0) {
            return ['status' => 'not_core'];
        }

        $rel_file = substr($norm_path, strlen($norm_abs));

        // wp-content is NOT part of core
        if (strpos($rel_file, 'wp-content/') === 0) {
            return ['status' => 'not_core'];
        }

        $is_in_core_dir = (strpos($rel_file, 'wp-includes/') === 0 || strpos($rel_file, 'wp-admin/') === 0);
        $is_in_root     = (strpos($rel_file, '/') === false);

        if (!$is_in_core_dir && !$is_in_root) {
            // 1. Exclude legitimate ACME / SSL Let's Encrypt validation folders and protective .htaccess
            if (strpos($rel_file, '.well-known/') === 0) {
                return ['status' => 'ignored', 'rel_file' => $rel_file];
            }

            // 2. Ignore non-code files, images, or .htaccess access-control rules in non-standard root folders
            $basename_lower = strtolower(basename($file_path));
            if ($basename_lower === '.htaccess') {
                if (class_exists('\\WcpScanner\\System\\SettingsManager') && \WcpScanner\System\SettingsManager::is_safe_protective_htaccess($file_path)) {
                    return ['status' => 'ignored', 'rel_file' => $rel_file];
                }
            }

            // Non-standard directory on WordPress root (e.g. /custom-folder/file.php)
            // If it contains executable PHP code, it's considered unknown core/root
            $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            if (in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true)) {
                return [
                    'status'   => 'unknown',
                    'rel_file' => $rel_file,
                ];
            }
            return ['status' => 'not_core'];
        }

        $provider = new self();
        $checksums = $provider->get_core_checksums();
        if (empty($checksums)) {
            return ['status' => 'not_core'];
        }

        if (isset($checksums[$rel_file])) {
            $expected_md5 = $checksums[$rel_file];
            if (!file_exists($file_path) || !is_readable($file_path)) {
                return ['status' => 'not_core'];
            }

            $actual_md5 = md5_file($file_path);
            if ($actual_md5 === $expected_md5) {
                return [
                    'status'   => 'authentic',
                    'rel_file' => $rel_file,
                ];
            }

            // Normalization
            $raw_content = @file_get_contents($file_path);
            if ($raw_content !== false && md5(str_replace("\r\n", "\n", $raw_content)) === $expected_md5) {
                return [
                    'status'   => 'authentic',
                    'rel_file' => $rel_file,
                ];
            }

            return [
                'status'   => 'modified',
                'rel_file' => $rel_file,
                'expected' => $expected_md5,
                'actual'   => $actual_md5,
            ];
        }

        // File is in wp-admin, wp-includes, or root ABSPATH, but NOT in official core checksums!
        $basename_lower = strtolower(basename($file_path));

        // Ignored safe files
        $ignored_basenames = ['.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db'];
        if (in_array($basename_lower, $ignored_basenames, true)) {
            return ['status' => 'ignored', 'rel_file' => $rel_file];
        }

        // Standard root legitimate entries & recognized security/WAF files
        if ($is_in_root) {
            $standard_root = [
                'wp-config.php', 'wp-config-sample.php', 'robots.txt', 'favicon.ico',
                '.user.ini', 'php.ini', 'sitemap.xml', 'sitemap.xml.gz', 'ads.txt',
                'app-ads.txt', 'security.txt', 'license.txt', 'readme.html'
            ];
            if (in_array($basename_lower, $standard_root, true)) {
                return ['status' => 'authentic', 'rel_file' => $rel_file];
            }

            // Wordfence WAF preload bootstrap (wordfence-waf.php)
            if ($basename_lower === 'wordfence-waf.php') {
                $content = @file_get_contents($file_path, false, null, 0, 8192);
                if ($content !== false && (strpos($content, 'WFWAF_LOG_PATH') !== false || strpos($content, 'wordfence/waf/bootstrap.php') !== false || strpos($content, 'wordfence') !== false)) {
                    return ['status' => 'authentic', 'rel_file' => $rel_file];
                }
            }
        }

        // It is an UNKNOWN file inside core or root!
        return [
            'status'   => 'unknown',
            'rel_file' => $rel_file,
        ];
    }

    /**
     * Strictly verify a file against official WordPress.org plugin checksums and detect rogue/unknown files.
     *
     * @param string $file_path
     * @return array [
     *   'status'   => 'not_plugin' | 'unmanaged' | 'authentic' | 'modified' | 'unknown' | 'ignored',
     *   'slug'     => string,
     *   'rel_file' => string,
     *   'expected' => string,
     *   'actual'   => string
     * ]
     */
    public static function verify_plugin_file(string $file_path): array {
        if (!defined('WP_PLUGIN_DIR')) {
            return ['status' => 'not_plugin'];
        }

        $norm_path  = str_replace('\\', '/', $file_path);
        $plugin_dir = str_replace('\\', '/', rtrim(WP_PLUGIN_DIR, '/\\') . '/');

        if (strpos($norm_path, $plugin_dir) !== 0) {
            return ['status' => 'not_plugin'];
        }

        $rel_path = substr($norm_path, strlen($plugin_dir));
        $parts = explode('/', $rel_path, 2);
        if (count($parts) < 2) {
            return ['status' => 'not_plugin']; // Single file plugin
        }

        $slug = $parts[0];
        $file_inside_plugin = $parts[1];

        if ($slug === 'wcp-security-scanner') {
            return ['status' => 'authentic', 'slug' => $slug, 'rel_file' => $file_inside_plugin];
        }

        $version = self::get_installed_plugin_version($slug);
        if (empty($version)) {
            return ['status' => 'unmanaged', 'slug' => $slug];
        }

        $provider = new self();
        $checksums = $provider->get_plugin_checksums($slug, $version);
        if (empty($checksums)) {
            return ['status' => 'unmanaged', 'slug' => $slug];
        }

        if (isset($checksums[$file_inside_plugin])) {
            $expected = $checksums[$file_inside_plugin];
            if (!file_exists($file_path) || !is_readable($file_path)) {
                return ['status' => 'not_plugin'];
            }

            $actual_md5 = md5_file($file_path);

            $is_match = false;
            if (is_string($expected) && $actual_md5 === $expected) {
                $is_match = true;
            } elseif (is_array($expected)) {
                if (isset($expected['algo']) && $expected['algo'] === 'sha256') {
                    $is_match = (hash_file('sha256', $file_path) === $expected['hash']);
                } elseif (in_array($actual_md5, $expected, true)) {
                    $is_match = true;
                }
            }

            if (!$is_match) {
                // CRLF vs LF
                $raw_content = @file_get_contents($file_path);
                if ($raw_content !== false) {
                    $norm_md5 = md5(str_replace("\r\n", "\n", $raw_content));
                    if (is_string($expected) && $norm_md5 === $expected) {
                        $is_match = true;
                    } elseif (is_array($expected) && in_array($norm_md5, $expected, true)) {
                        $is_match = true;
                    }
                }
            }

            if ($is_match) {
                return [
                    'status'   => 'authentic',
                    'slug'     => $slug,
                    'rel_file' => $file_inside_plugin,
                ];
            }

            $exp_str = is_array($expected) ? ($expected['hash'] ?? implode(', ', $expected)) : $expected;
            return [
                'status'   => 'modified',
                'slug'     => $slug,
                'rel_file' => $file_inside_plugin,
                'expected' => $exp_str,
                'actual'   => $actual_md5,
            ];
        }

        // File is inside an official WordPress.org plugin directory, but NOT in official manifest!
        $basename_lower = strtolower(basename($file_path));
        $ignored_basenames = [
            '.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db',
            '.gitignore', 'license.txt', 'license', 'readme.md', 'changelog.txt'
        ];
        if (in_array($basename_lower, $ignored_basenames, true)) {
            return ['status' => 'ignored', 'slug' => $slug, 'rel_file' => $file_inside_plugin];
        }

        // Allow harmless non-executable runtime storage files (e.g. cache/logs)
        $runtime_dirs = ['logs', 'storage', 'cache', 'caches', 'backups', 'temp', 'tmp'];
        $path_segments = explode('/', strtolower($file_inside_plugin));
        $is_in_runtime_dir = !empty(array_intersect($path_segments, $runtime_dirs));
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);

        if ($is_in_runtime_dir && !$is_executable) {
            return ['status' => 'ignored', 'slug' => $slug, 'rel_file' => $file_inside_plugin];
        }

        if ($is_in_runtime_dir && in_array($basename_lower, ['index.php', 'index.html'], true) && filesize($file_path) < 500) {
            return ['status' => 'ignored', 'slug' => $slug, 'rel_file' => $file_inside_plugin];
        }

        return [
            'status'   => 'unknown',
            'slug'     => $slug,
            'rel_file' => $file_inside_plugin,
        ];
    }

    /**
     * Strictly verify a file against official WordPress.org theme checksums and detect rogue/unknown files.
     *
     * @param string $file_path
     * @return array [
     *   'status'   => 'not_theme' | 'unmanaged' | 'authentic' | 'modified' | 'unknown' | 'ignored',
     *   'slug'     => string,
     *   'rel_file' => string,
     *   'expected' => string,
     *   'actual'   => string
     * ]
     */
    public static function verify_theme_file(string $file_path): array {
        if (!function_exists('get_theme_root')) {
            return ['status' => 'not_theme'];
        }

        $norm_path  = str_replace('\\', '/', $file_path);
        $theme_root = str_replace('\\', '/', rtrim(get_theme_root(), '/\\') . '/');

        if (strpos($norm_path, $theme_root) !== 0) {
            return ['status' => 'not_theme'];
        }

        $rel_path = substr($norm_path, strlen($theme_root));
        $parts = explode('/', $rel_path, 2);
        if (count($parts) < 2) {
            return ['status' => 'not_theme'];
        }

        $slug = $parts[0];
        $file_inside_theme = $parts[1];

        $version = self::get_installed_theme_version($slug);
        if (empty($version)) {
            return ['status' => 'unmanaged', 'slug' => $slug];
        }

        $provider = new self();
        $checksums = $provider->get_theme_checksums($slug, $version);
        if (empty($checksums)) {
            return ['status' => 'unmanaged', 'slug' => $slug];
        }

        if (isset($checksums[$file_inside_theme])) {
            $expected = $checksums[$file_inside_theme];
            if (!file_exists($file_path) || !is_readable($file_path)) {
                return ['status' => 'not_theme'];
            }

            $actual_md5 = md5_file($file_path);
            $is_match = ($actual_md5 === $expected || $expected === true);

            if (!$is_match) {
                // CRLF vs LF
                $raw_content = @file_get_contents($file_path);
                if ($raw_content !== false && md5(str_replace("\r\n", "\n", $raw_content)) === $expected) {
                    $is_match = true;
                }
            }

            if ($is_match) {
                return [
                    'status'   => 'authentic',
                    'slug'     => $slug,
                    'rel_file' => $file_inside_theme,
                ];
            }

            return [
                'status'   => 'modified',
                'slug'     => $slug,
                'rel_file' => $file_inside_theme,
                'expected' => is_string($expected) ? $expected : 'authentic_release',
                'actual'   => $actual_md5,
            ];
        }

        // File is inside official theme, but not in official manifest!
        $basename_lower = strtolower(basename($file_path));
        $ignored_basenames = [
            '.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db',
            '.gitignore', 'license.txt', 'readme.md', 'changelog.txt', '.editorconfig',
            'package.json', 'package-lock.json', 'contributing.md', 'contributing.txt'
        ];
        if (in_array($basename_lower, $ignored_basenames, true)) {
            return ['status' => 'ignored', 'slug' => $slug, 'rel_file' => $file_inside_theme];
        }

        return [
            'status'   => 'unknown',
            'slug'     => $slug,
            'rel_file' => $file_inside_theme,
        ];
    }
}
