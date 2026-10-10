<?php
namespace WCP\Scanner\Integrity;

if (!defined('ABSPATH')) {
    exit;
}

class FileIntegrityMonitor {

    private $provider;

    public function __construct() {
        $this->provider = new ChecksumProvider();
    }

    /**
     * Get files modified within the last $hours hours across core, plugins, themes, and sensitive areas.
     *
     * @param int $hours Hours timeframe (default 48)
     * @param string $category Filter category ('all', 'core', 'plugins', 'themes', 'uploads')
     * @param int $limit Maximum results to return
     * @return array
     */
    public function get_recent_changes($hours = 48, $category = 'all', $limit = 150) {
        $hours = max(1, min(720, intval($hours))); // 1 hour to 30 days
        $threshold_time = time() - ($hours * HOUR_IN_SECONDS);

        $changes = [];
        $stats = [
            'total_modified'   => 0,
            'core_modified'    => 0,
            'plugins_modified' => 0,
            'themes_modified'  => 0,
            'uploads_modified' => 0,
            'high_risk_count'  => 0,
            'timeframe_hours'  => $hours,
        ];

        // Identify custom or commercial/premium components to skip from official WP.org baseline
        $custom_components = $this->get_custom_and_premium_components();
        $custom_plugin_slugs = $custom_components['plugins'];
        $custom_theme_slugs = $custom_components['themes'];

        // Pre-fetch official core checksums to verify authentic installation files
        $core_checksums = $this->provider->get_core_checksums();

        $dirs_to_check = [];

        // 1. Core directories and root
        $dirs_to_check[] = [
            'path'      => ABSPATH . 'wp-admin',
            'category'  => 'core',
            'recursive' => true,
        ];
        $dirs_to_check[] = [
            'path'      => ABSPATH . 'wp-includes',
            'category'  => 'core',
            'recursive' => true,
        ];
        $dirs_to_check[] = [
            'path'      => ABSPATH,
            'category'  => 'core_root',
            'recursive' => false,
        ];

        // 2. Plugins
        $dirs_to_check[] = [
            'path'      => WP_PLUGIN_DIR,
            'category'  => 'plugins',
            'recursive' => true,
        ];
        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            $dirs_to_check[] = [
                'path'      => WPMU_PLUGIN_DIR,
                'category'  => 'plugins',
                'recursive' => true,
            ];
        }

        // 3. Themes
        $theme_root = function_exists('get_theme_root') ? get_theme_root() : WP_CONTENT_DIR . '/themes';
        if (is_dir($theme_root)) {
            $dirs_to_check[] = [
                'path'      => $theme_root,
                'category'  => 'themes',
                'recursive' => true,
            ];
        }

        // 4. Uploads (check for suspicious code files)
        $upload_dir = wp_upload_dir();
        if (!empty($upload_dir['basedir']) && is_dir($upload_dir['basedir'])) {
            $dirs_to_check[] = [
                'path'      => $upload_dir['basedir'],
                'category'  => 'uploads',
                'recursive' => true,
            ];
        }

        $normalized_abs = wp_normalize_path(ABSPATH);

        foreach ($dirs_to_check as $target) {
            $dir_path = $target['path'];
            if (!is_dir($dir_path)) {
                continue;
            }

            $cat = $target['category'];
            $is_recursive = $target['recursive'];

            if ($is_recursive) {
                try {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($dir_path, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::SELF_FIRST
                    );

                    foreach ($iterator as $item) {
                        if (!$item->isFile()) {
                            continue;
                        }

                        $file_path = wp_normalize_path($item->getPathname());

                        // Exclude common noise directories
                        if (preg_match('#/(node_modules|\.git|cache|wcp-security-scanner|updraft|backups|wfcache)/#i', $file_path)) {
                            continue;
                        }

                        // Skip files inside custom or premium plugins (no official WP.org baseline)
                        if ($cat === 'plugins') {
                            $rel_to_plugins = ltrim(str_replace(wp_normalize_path(WP_PLUGIN_DIR), '', $file_path), '/');
                            $plugin_parts = explode('/', $rel_to_plugins, 2);
                            $p_slug = $plugin_parts[0];
                            if (isset($custom_plugin_slugs[$p_slug])) {
                                continue;
                            }
                        }

                        // Skip files inside custom or premium themes (no official WP.org baseline)
                        if ($cat === 'themes') {
                            $theme_root_norm = wp_normalize_path(function_exists('get_theme_root') ? get_theme_root() : WP_CONTENT_DIR . '/themes');
                            $rel_to_themes = ltrim(str_replace($theme_root_norm, '', $file_path), '/');
                            $theme_parts = explode('/', $rel_to_themes, 2);
                            $t_slug = $theme_parts[0];
                            if (isset($custom_theme_slugs[$t_slug])) {
                                continue;
                            }
                        }

                        // For uploads directory: only flag PHP, script files, or .htaccess
                        if ($cat === 'uploads') {
                            $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                            $basename = strtolower(basename($file_path));
                            if (!in_array($ext, ['php', 'phtml', 'php5', 'php7', 'pht', 'phps', 'inc'], true) && $basename !== '.htaccess') {
                                continue;
                            }
                            // Ignore harmless directory index.php protection placeholders
                            if (($basename === 'index.php' || $basename === 'index.html') && \WCP\Scanner\System\SettingsManager::is_safe_directory_index($file_path)) {
                                continue;
                            }
                        }

                        $mtime = $item->getMTime();
                        if ($mtime >= $threshold_time) {
                            $change_item = $this->format_change_item($file_path, $mtime, $item->getSize(), $cat, $normalized_abs, $core_checksums);
                            $this->tally_stats($stats, $change_item);
                            if ($category === 'all' || $change_item['category'] === $category) {
                                $changes[] = $change_item;
                            }
                        }
                    }
                } catch (\Exception $e) {
                    continue;
                }
            } else {
                // Non-recursive root directory check
                $root_files = glob(rtrim($dir_path, '/\\') . '/*');
                if ($root_files) {
                    foreach ($root_files as $file_path) {
                        if (!is_file($file_path)) {
                            continue;
                        }
                        $file_path = wp_normalize_path($file_path);
                        $mtime = @filemtime($file_path);
                        if ($mtime && $mtime >= $threshold_time) {
                            $change_item = $this->format_change_item($file_path, $mtime, @filesize($file_path), 'core_root', $normalized_abs, $core_checksums);
                            $this->tally_stats($stats, $change_item);
                            if ($category === 'all' || $change_item['category'] === $category) {
                                $changes[] = $change_item;
                            }
                        }
                    }
                }
            }
        }

        // Sort by newest modified first
        usort($changes, function ($a, $b) {
            return $b['mtime'] - $a['mtime'];
        });

        // Limit results
        $total_found = count($changes);
        if ($total_found > $limit) {
            $changes = array_slice($changes, 0, $limit);
        }

        return [
            'stats'          => $stats,
            'total'          => $total_found,
            'changes'        => $changes,
            'skipped_custom' => [
                'plugins' => array_values($custom_components['plugins']),
                'themes'  => array_values($custom_components['themes']),
                'count'   => count($custom_components['plugins']) + count($custom_components['themes']),
            ],
        ];
    }

    /**
     * Tally statistics counters
     */
    private function tally_stats(&$stats, $item) {
        $stats['total_modified']++;
        if ($item['category'] === 'core') {
            // Only count genuine core modifications (not verified authentic files)
            if ($item['severity'] === 'critical' || $item['severity'] === 'high') {
                $stats['core_modified']++;
            }
        } elseif ($item['category'] === 'plugins') {
            $stats['plugins_modified']++;
        } elseif ($item['category'] === 'themes') {
            $stats['themes_modified']++;
        } elseif ($item['category'] === 'uploads') {
            $stats['uploads_modified']++;
        }

        if ($item['severity'] === 'critical' || $item['severity'] === 'high') {
            $stats['high_risk_count']++;
        }
    }

    /**
     * Format a change record with risk evaluation and checksum verification
     */
    private function format_change_item($file_path, $mtime, $size, $category, $normalized_abs, $core_checksums = null) {
        $rel_path = ltrim(str_replace($normalized_abs, '', $file_path), '/');
        $basename = strtolower(basename($file_path));
        $severity = 'info';
        $risk_reason = 'Standard recent file modification';
        $is_suspicious = false;
        $is_verified_clean = false;

        // 1. Check if it's a configuration or server environment file
        $config_files = ['wp-config.php', 'wp-config-sample.php', 'php.ini', '.user.ini', '.htaccess', 'web.config', 'nginx.conf'];
        if (in_array($basename, $config_files, true)) {
            $category = 'config';
            if ($basename === 'wp-config.php') {
                $severity = 'info';
                $risk_reason = 'WordPress database & secret keys configuration file (Normal for installation)';
            } elseif ($basename === 'php.ini' || $basename === '.user.ini') {
                $severity = 'info';
                $risk_reason = 'Server PHP runtime configuration file';
            } elseif ($basename === '.htaccess') {
                $severity = 'info';
                $risk_reason = 'Web server permalink & rewrite configuration file';
            } else {
                $severity = 'info';
                $risk_reason = 'Server configuration file';
            }
        } elseif ($category === 'uploads') {
            $severity = 'critical';
            $is_suspicious = true;
            $risk_reason = 'Executable script file modified or created inside uploads directory!';
        } elseif ($category === 'core' || $category === 'core_root') {
            $category = 'core';
            
            // Check if file is in official core checksums and matches MD5
            if (!empty($core_checksums) && isset($core_checksums[$rel_path])) {
                $local_hash = @md5_file($file_path);
                if ($local_hash && hash_equals($core_checksums[$rel_path], $local_hash)) {
                    $is_verified_clean = true;
                    $severity = 'clean';
                    $risk_reason = 'Authentic official core file (Checksum bit-for-bit verified with WordPress.org)';
                } else {
                    $severity = 'high';
                    $is_suspicious = true;
                    $risk_reason = 'WordPress core file altered from official WordPress.org release!';
                }
            } else {
                // If it's a standard core root file like index.php, wp-login.php, wp-blog-header.php
                if (!empty($core_checksums)) {
                    $severity = 'info';
                    $risk_reason = 'WordPress core installation file (Recent timestamp)';
                } else {
                    $severity = 'high';
                    $risk_reason = 'WordPress core file was modified.';
                }
            }
        } elseif ($category === 'themes') {
            // Check if default bundled theme (twenty*) matches core checksums
            if (!empty($core_checksums) && isset($core_checksums[$rel_path])) {
                $local_hash = @md5_file($file_path);
                if ($local_hash && hash_equals($core_checksums[$rel_path], $local_hash)) {
                    $is_verified_clean = true;
                    $severity = 'clean';
                    $risk_reason = 'Authentic official theme file (Checksum bit-for-bit verified with WordPress.org)';
                }
            }
        }

        // Content heuristic check on small/medium files for active web shells
        if ($size > 0 && $size < 1048576 && !$is_verified_clean) { // under 1MB and not clean official file
            $content_sample = @file_get_contents($file_path, false, null, 0, 8192);
            if ($content_sample) {
                if (preg_match('/(eval\s*\(|base64_decode\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|gzuncompress\s*\()/i', $content_sample)) {
                    $severity = 'critical';
                    $is_suspicious = true;
                    $risk_reason = 'Dangerous execution signature (eval/base64/exec) detected in modified file!';
                }
            }
        }

        return [
            'file_path'         => $file_path,
            'relative_path'     => $rel_path,
            'filename'          => basename($file_path),
            'category'          => $category,
            'mtime'             => $mtime,
            'modified_human'    => human_time_diff($mtime, time()) . ' ago',
            'modified_iso'      => gmdate('Y-m-d H:i:s', $mtime),
            'size'              => $size,
            'size_formatted'    => size_format($size),
            'severity'          => $severity,
            'is_suspicious'     => $is_suspicious,
            'is_verified_clean' => $is_verified_clean,
            'risk_reason'       => $risk_reason,
        ];
    }

    /**
     * Compute Git-style visual code diff between official WordPress/Plugin source and local file.
     *
     * @param string $file_path Absolute or relative file path
     * @return array Diff result with lines, stats, and metadata
     */
    public function get_file_diff($file_path) {
        $normalized_abs = wp_normalize_path(ABSPATH);

        // Path validation and normalization
        $file_path = wp_normalize_path($file_path);
        if (strpos($file_path, $normalized_abs) !== 0) {
            $file_path = wp_normalize_path($normalized_abs . ltrim($file_path, '/\\'));
        }

        // Prevent path traversal
        $real_path = realpath($file_path);
        if (!$real_path || !file_exists($real_path)) {
            return [
                'success' => false,
                'message' => 'Target file does not exist on local filesystem.',
            ];
        }

        $real_path = wp_normalize_path($real_path);
        if (strpos($real_path, $normalized_abs) !== 0) {
            return [
                'success' => false,
                'message' => 'Path traversal denied: File is outside WordPress root directory.',
            ];
        }

        $rel_path = ltrim(str_replace($normalized_abs, '', $real_path), '/');
        $local_content = @file_get_contents($real_path);

        if ($local_content === false) {
            return [
                'success' => false,
                'message' => 'Could not read local file content.',
            ];
        }

        // Determine context: Core, Plugin, Theme, Config
        $category = 'custom';
        $official_content = null;
        $official_source_url = null;
        $is_official_compared = false;
        $diff_message = '';

        global $wp_version;
        $clean_wp_version = preg_replace('/-.*$/', '', $wp_version);

        // Check if configuration file (wp-config.php, .htaccess, php.ini, etc.)
        $file_name = basename($real_path);
        if ($file_name === 'wp-config.php') {
            $category = 'config';
            // Securely mask database credentials and secret authentication salts
            $sensitive_patterns = [
                "/(define\s*\(\s*['\"](?:DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\"]\s*,\s*['\"])(?:[^'\"]*)(['\"]\s*\);)/i" => '$1********$2',
                "/(\\\$table_prefix\s*=\s*['\"])(?:[^'\"]*)(['\"]\s*;)/i" => '$1********$2',
            ];
            foreach ($sensitive_patterns as $pattern => $replacement) {
                $local_content = preg_replace($pattern, $replacement, $local_content);
            }

            // Compare against official WordPress wp-config-sample.php baseline
            $official_source_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$clean_wp_version}/wp-config-sample.php";
            $official_content = $this->fetch_remote_source($official_source_url);
            if ($official_content !== null) {
                $is_official_compared = true;
                $diff_message = "Comparing local wp-config.php against official WordPress {$clean_wp_version} wp-config-sample.php baseline (sensitive credentials masked for security).";
            } else {
                $diff_message = 'Official wp-config-sample.php baseline could not be fetched. Displaying sanitized local inspection view.';
            }
        } elseif (in_array(strtolower($file_name), ['.htaccess', 'php.ini', '.user.ini', 'web.config', 'robots.txt'], true)) {
            $category = 'config';
            $diff_message = "Server configuration file ({$file_name}): No remote repository baseline exists. Displaying local inspection view.";
        } elseif (strpos($rel_path, 'wp-admin/') === 0 || strpos($rel_path, 'wp-includes/') === 0 || (!strpos($rel_path, '/') && preg_match('/^wp-.*\.php$|^index\.php$/', $rel_path))) {
            // 1. Check if WordPress core file
            $category = 'core';
            // Fetch clean WordPress core version from official GitHub/SVN
            $official_source_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$clean_wp_version}/{$rel_path}";
            $official_content = $this->fetch_remote_source($official_source_url);
            if ($official_content !== null) {
                $is_official_compared = true;
            }
        } elseif (strpos($rel_path, 'wp-content/plugins/') === 0) {
            $category = 'plugin';
            $plugin_rel = substr($rel_path, strlen('wp-content/plugins/'));
            $parts = explode('/', $plugin_rel, 2);
            $plugin_slug = $parts[0];
            $internal_file = isset($parts[1]) ? $parts[1] : '';

            $custom_components = $this->get_custom_and_premium_components();
            if (isset($custom_components['plugins'][$plugin_slug])) {
                $comp = $custom_components['plugins'][$plugin_slug];
                $diff_message = "Custom/Premium Plugin ({$comp['name']}): Excluded from official repository baselines. Displaying local inspection view.";
            } elseif ($plugin_slug && $internal_file) {
                // Find plugin version
                $version = $this->get_plugin_version_by_slug($plugin_slug);
                if ($version) {
                    $official_source_url = "https://plugins.svn.wordpress.org/{$plugin_slug}/tags/{$version}/{$internal_file}";
                    $official_content = $this->fetch_remote_source($official_source_url);
                    if ($official_content === null) {
                        // Try trunk
                        $official_source_url = "https://plugins.svn.wordpress.org/{$plugin_slug}/trunk/{$internal_file}";
                        $official_content = $this->fetch_remote_source($official_source_url);
                    }
                    if ($official_content !== null) {
                        $is_official_compared = true;
                    }
                }
            }
        } elseif (strpos($rel_path, 'wp-content/themes/') === 0) {
            $category = 'theme';
            $theme_rel = substr($rel_path, strlen('wp-content/themes/'));
            $parts = explode('/', $theme_rel, 2);
            $theme_slug = $parts[0];
            $internal_file = isset($parts[1]) ? $parts[1] : '';

            $custom_components = $this->get_custom_and_premium_components();
            if (isset($custom_components['themes'][$theme_slug])) {
                $comp = $custom_components['themes'][$theme_slug];
                $diff_message = "Custom/Premium Theme ({$comp['name']}): Excluded from official repository baselines. Displaying local inspection view.";
            }
        }

        // If official content not found, compare with empty or analyze local
        if ($official_content === null) {
            $official_content = '';
            if (empty($diff_message)) {
                $diff_message = 'Official repository baseline is unavailable for this custom file. Displaying local inspection view.';
            }
        } elseif (empty($diff_message)) {
            $diff_message = 'Comparing against official bit-for-bit repository source.';
        }

        // Compute Line-by-Line Diff
        $diff_result = $this->compute_diff($official_content, $local_content);

        return [
            'success'              => true,
            'file_path'            => $real_path,
            'relative_path'        => $rel_path,
            'filename'             => basename($real_path),
            'category'             => $category,
            'is_official_compared' => $is_official_compared,
            'official_source_url'  => $official_source_url,
            'message'              => $diff_message,
            'stats'                => [
                'additions'     => $diff_result['additions'],
                'deletions'     => $diff_result['deletions'],
                'total_changes' => $diff_result['additions'] + $diff_result['deletions'],
                'local_lines'   => count(explode("\n", $local_content)),
            ],
            'diff_lines'           => $diff_result['lines'],
        ];
    }

    /**
     * Fetch remote clean source with caching transient
     */
    private function fetch_remote_source($url) {
        $cache_key = 'wcp_fim_diff_' . md5($url);
        $cached = get_transient($cache_key);
        if ($cached !== false && is_string($cached)) {
            return $cached;
        }

        $response = wp_remote_get($url, [
            'timeout'   => 12,
            'sslverify' => true,
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        if (!empty($body)) {
            set_transient($cache_key, $body, 12 * HOUR_IN_SECONDS);
            return $body;
        }

        return null;
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
            if (dirname($file) === $slug) {
                return !empty($data['Version']) ? $data['Version'] : null;
            }
        }
        return null;
    }

    /**
     * Pure PHP Line-by-Line Unified Diff Algorithm (Myers / LCS style)
     */
    private function compute_diff($old_text, $new_text) {
        $old_lines = $old_text !== '' ? explode("\n", str_replace(["\r\n", "\r"], "\n", $old_text)) : [];
        $new_lines = $new_text !== '' ? explode("\n", str_replace(["\r\n", "\r"], "\n", $new_text)) : [];

        // Trim single trailing empty line from split
        if (count($old_lines) > 0 && end($old_lines) === '') {
            array_pop($old_lines);
        }
        if (count($new_lines) > 0 && end($new_lines) === '') {
            array_pop($new_lines);
        }

        $n = count($old_lines);
        $m = count($new_lines);

        $additions = 0;
        $deletions = 0;
        $diff_lines = [];

        // Fast path 1: Both empty
        if ($n === 0 && $m === 0) {
            return [
                'lines'     => [],
                'additions' => 0,
                'deletions' => 0,
            ];
        }

        // Fast path 2: Old empty, all lines are added
        if ($n === 0) {
            foreach ($new_lines as $idx => $line) {
                $diff_lines[] = [
                    'type'     => 'added',
                    'old_line' => null,
                    'new_line' => $idx + 1,
                    'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($line),
                ];
            }
            return [
                'lines'     => $diff_lines,
                'additions' => $m,
                'deletions' => 0,
            ];
        }

        // Fast path 3: New empty, all lines are removed
        if ($m === 0) {
            foreach ($old_lines as $idx => $line) {
                $diff_lines[] = [
                    'type'     => 'removed',
                    'old_line' => $idx + 1,
                    'new_line' => null,
                    'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($line),
                ];
            }
            return [
                'lines'     => $diff_lines,
                'additions' => 0,
                'deletions' => $n,
            ];
        }

        // Simple optimized LCS table for files under 2,000 lines
        if ($n < 2500 && $m < 2500) {
            $lcs = [];
            for ($i = 0; $i <= $n; $i++) {
                $lcs[$i][0] = 0;
            }
            for ($j = 0; $j <= $m; $j++) {
                $lcs[0][$j] = 0;
            }

            for ($i = 1; $i <= $n; $i++) {
                for ($j = 1; $j <= $m; $j++) {
                    if ($old_lines[$i - 1] === $new_lines[$j - 1]) {
                        $lcs[$i][$j] = $lcs[$i - 1][$j - 1] + 1;
                    } else {
                        $lcs[$i][$j] = max($lcs[$i - 1][$j], $lcs[$i][$j - 1]);
                    }
                }
            }

            // Backtrack
            $i = $n;
            $j = $m;
            $reversed_diff = [];

            while ($i > 0 || $j > 0) {
                if ($i > 0 && $j > 0 && $old_lines[$i - 1] === $new_lines[$j - 1]) {
                    $reversed_diff[] = [
                        'type'     => 'unchanged',
                        'old_line' => $i,
                        'new_line' => $j,
                        'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($old_lines[$i - 1]),
                    ];
                    $i--;
                    $j--;
                } elseif ($j > 0 && ($i === 0 || ($lcs[$i][$j - 1] >= ($i > 0 ? $lcs[$i - 1][$j] : 0)))) {
                    $reversed_diff[] = [
                        'type'     => 'added',
                        'old_line' => null,
                        'new_line' => $j,
                        'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($new_lines[$j - 1]),
                    ];
                    $additions++;
                    $j--;
                } elseif ($i > 0) {
                    $reversed_diff[] = [
                        'type'     => 'removed',
                        'old_line' => $i,
                        'new_line' => null,
                        'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($old_lines[$i - 1]),
                    ];
                    $deletions++;
                    $i--;
                }
            }

            $diff_lines = array_reverse($reversed_diff);
        } else {
            // Fallback line scan for large files
            $max_lines = max($n, $m);
            for ($k = 0; $k < $max_lines; $k++) {
                $old_val = isset($old_lines[$k]) ? $old_lines[$k] : null;
                $new_val = isset($new_lines[$k]) ? $new_lines[$k] : null;

                if ($old_val === $new_val) {
                    $diff_lines[] = [
                        'type'     => 'unchanged',
                        'old_line' => $k + 1,
                        'new_line' => $k + 1,
                        'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($old_val),
                    ];
                } else {
                    if ($old_val !== null) {
                        $diff_lines[] = [
                            'type'     => 'removed',
                            'old_line' => $k + 1,
                            'new_line' => null,
                            'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($old_val),
                        ];
                        $deletions++;
                    }
                    if ($new_val !== null) {
                        $diff_lines[] = [
                            'type'     => 'added',
                            'old_line' => null,
                            'new_line' => $k + 1,
                            'content'  => \WCP\Scanner\Filesystem\UploadsScanner::sanitize_utf8($new_val),
                        ];
                        $additions++;
                    }
                }
            }
        }

        return [
            'lines'     => $diff_lines,
            'additions' => $additions,
            'deletions' => $deletions,
        ];
    }

    /**
     * Identify custom or commercial/premium plugins and themes that are not hosted
     * on the official public WordPress.org repository.
     *
     * @return array ['plugins' => [...], 'themes' => [...]]
     */
    public function get_custom_and_premium_components() {
        $cache_key = 'wcp_fim_custom_components_v1';
        $cached = get_transient($cache_key);
        if ($cached !== false && is_array($cached)) {
            return $cached;
        }

        $custom_plugins = [];
        $custom_themes = [];

        // 1. Detect Custom & Premium Plugins
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $update_plugins = get_site_transient('update_plugins');

        $checked_plugins = (!empty($update_plugins) && is_object($update_plugins) && !empty($update_plugins->checked)) ? $update_plugins->checked : [];
        $response_plugins = (!empty($update_plugins) && is_object($update_plugins) && !empty($update_plugins->response)) ? $update_plugins->response : [];
        $no_update_plugins = (!empty($update_plugins) && is_object($update_plugins) && !empty($update_plugins->no_update)) ? $update_plugins->no_update : [];

        $commercial_domains = [
            'woocommerce.com', 'codecanyon.net', 'themeforest.net', 'envato.com',
            'elegantthemes.com', 'gravityforms.com', 'wpengine.com', 'yoast.com/premium',
            'elementor.com/pro', 'crocoblock.com', 'wpml.org', 'advancedcustomfields.com/pro',
            'wpmudev.com', 'ithemes.com', 'solidwp.com', 'stellarwp.com'
        ];

        foreach ($all_plugins as $plugin_file => $plugin_data) {
            $slug = dirname($plugin_file);
            if ($slug === '.' || empty($slug)) {
                $slug = sanitize_title(pathinfo($plugin_file, PATHINFO_FILENAME));
            }

            $name = !empty($plugin_data['Name']) ? $plugin_data['Name'] : $slug;
            $version = !empty($plugin_data['Version']) ? $plugin_data['Version'] : '';
            $author = !empty($plugin_data['Author']) ? wp_strip_all_tags($plugin_data['Author']) : '';
            $plugin_uri = strtolower($plugin_data['PluginURI'] ?? '');
            $author_uri = strtolower($plugin_data['AuthorURI'] ?? '');

            $is_wporg = false;
            $type = 'custom';
            $reason = 'Not hosted on WordPress.org repository baseline';

            // Check if known commercial store
            foreach ($commercial_domains as $domain) {
                if (strpos($plugin_uri, $domain) !== false || strpos($author_uri, $domain) !== false) {
                    $type = 'premium';
                    $reason = "Commercial extension ({$domain})";
                    break;
                }
            }

            // If found in WordPress.org update response or no_update
            if (isset($response_plugins[$plugin_file]) || isset($no_update_plugins[$plugin_file])) {
                $is_wporg = true;
            } elseif (!empty($checked_plugins) && isset($checked_plugins[$plugin_file])) {
                // WordPress core checked it on api.wordpress.org, and it was not found
                $is_wporg = false;
            } else {
                // Check transient or quick checksum head
                $chk_cache = get_transient("wcp_is_wporg_plugin_{$slug}");
                if ($chk_cache === 'yes') {
                    $is_wporg = true;
                } elseif ($chk_cache === 'no') {
                    $is_wporg = false;
                } else {
                    // Fast remote check
                    $test_url = "https://downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json";
                    $res = wp_remote_head($test_url, ['timeout' => 3]);
                    if (!is_wp_error($res) && wp_remote_retrieve_response_code($res) === 200) {
                        $is_wporg = true;
                        set_transient("wcp_is_wporg_plugin_{$slug}", 'yes', 7 * DAY_IN_SECONDS);
                    } else {
                        $is_wporg = false;
                        set_transient("wcp_is_wporg_plugin_{$slug}", 'no', 7 * DAY_IN_SECONDS);
                    }
                }
            }

            if (!$is_wporg) {
                $custom_plugins[$slug] = [
                    'slug'    => $slug,
                    'name'    => $name,
                    'version' => $version,
                    'author'  => $author,
                    'type'    => $type,
                    'reason'  => $reason,
                ];
            }
        }

        // 2. Detect Custom & Premium Themes
        $all_themes = function_exists('wp_get_themes') ? wp_get_themes() : [];
        $update_themes = get_site_transient('update_themes');

        $checked_themes = (!empty($update_themes) && is_object($update_themes) && !empty($update_themes->checked)) ? $update_themes->checked : [];
        $response_themes = (!empty($update_themes) && is_object($update_themes) && !empty($update_themes->response)) ? $update_themes->response : [];
        $no_update_themes = (!empty($update_themes) && is_object($update_themes) && !empty($update_themes->no_update)) ? $update_themes->no_update : [];

        $bundled_themes = [
            'twentytwentyfive', 'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
            'twentytwentyone', 'twentytwenty', 'twentynineteen', 'twentyseventeen',
            'twentysixteen', 'twentyfifteen', 'twentyfourteen', 'twentythirteen',
            'twentytwelve', 'twentyeleven', 'twentyten'
        ];

        foreach ($all_themes as $theme_slug => $theme_obj) {
            $is_wporg = false;
            $type = 'custom';
            $name = $theme_obj->get('Name') ?: $theme_slug;
            $version = $theme_obj->get('Version') ?: '';
            $author = wp_strip_all_tags($theme_obj->get('Author') ?: '');
            $theme_uri = strtolower($theme_obj->get('ThemeURI') ?: '');
            $author_uri = strtolower($theme_obj->get('AuthorURI') ?: '');

            // Core default themes are always official
            if (in_array(strtolower($theme_slug), $bundled_themes, true) || strpos(strtolower($theme_slug), 'twenty') === 0) {
                $is_wporg = true;
            } elseif ($theme_obj->parent()) {
                // Child theme is custom
                $is_wporg = false;
                $type = 'child_theme';
                $reason = 'Custom Child Theme';
            } elseif (isset($response_themes[$theme_slug]) || isset($theme_no_update[$theme_slug])) {
                $is_wporg = true;
            } elseif (!empty($checked_themes) && isset($checked_themes[$theme_slug])) {
                $is_wporg = false;
                $reason = 'Not hosted on WordPress.org repository baseline';
            } else {
                // Check if commercial domains
                foreach ($commercial_domains as $domain) {
                    if (strpos($theme_uri, $domain) !== false || strpos($author_uri, $domain) !== false) {
                        $type = 'premium';
                        $reason = "Commercial Theme ({$domain})";
                        break;
                    }
                }
                if ($type !== 'premium') {
                    $is_wporg = false;
                    $reason = 'Custom or Third-Party Theme';
                }
            }

            if (!$is_wporg) {
                $custom_themes[$theme_slug] = [
                    'slug'    => $theme_slug,
                    'name'    => $name,
                    'version' => $version,
                    'author'  => $author,
                    'type'    => $type,
                    'reason'  => $reason,
                ];
            }
        }

        $result = [
            'plugins' => $custom_plugins,
            'themes'  => $custom_themes,
        ];

        set_transient($cache_key, $result, 6 * HOUR_IN_SECONDS);
        return $result;
    }
}
