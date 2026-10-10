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

                        // For uploads directory: only flag PHP, script files, or .htaccess
                        if ($cat === 'uploads') {
                            $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                            $basename = basename($file_path);
                            if (!in_array($ext, ['php', 'phtml', 'php5', 'php7', 'pht', 'phps', 'inc'], true) && $basename !== '.htaccess') {
                                continue;
                            }
                        }

                        $mtime = $item->getMTime();
                        if ($mtime >= $threshold_time) {
                            $change_item = $this->format_change_item($file_path, $mtime, $item->getSize(), $cat, $normalized_abs);
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
                            $change_item = $this->format_change_item($file_path, $mtime, @filesize($file_path), 'core', $normalized_abs);
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
            'stats'   => $stats,
            'total'   => $total_found,
            'changes' => $changes,
        ];
    }

    /**
     * Tally statistics counters
     */
    private function tally_stats(&$stats, $item) {
        $stats['total_modified']++;
        if ($item['category'] === 'core') {
            $stats['core_modified']++;
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
     * Format a change record with risk evaluation
     */
    private function format_change_item($file_path, $mtime, $size, $category, $normalized_abs) {
        $rel_path = str_replace($normalized_abs, '', $file_path);
        $severity = 'info';
        $risk_reason = 'Standard recent file modification';
        $is_suspicious = false;

        // Threat heuristics on modified file
        if ($category === 'uploads') {
            $severity = 'critical';
            $is_suspicious = true;
            $risk_reason = 'Executable script file modified or created inside uploads directory!';
        } elseif ($category === 'core' || $category === 'core_root') {
            $category = 'core';
            $severity = 'high';
            $risk_reason = 'WordPress core file was modified.';
        }

        // Content heuristic check on small/medium files
        if ($size > 0 && $size < 1048576) { // under 1MB
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
            'file_path'      => $file_path,
            'relative_path'  => $rel_path,
            'filename'       => basename($file_path),
            'category'       => $category,
            'mtime'          => $mtime,
            'modified_human' => human_time_diff($mtime, time()) . ' ago',
            'modified_iso'   => gmdate('Y-m-d H:i:s', $mtime),
            'size'           => $size,
            'size_formatted' => size_format($size),
            'severity'       => $severity,
            'is_suspicious'  => $is_suspicious,
            'risk_reason'    => $risk_reason,
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

        // Determine context: Core, Plugin, Theme
        $category = 'custom';
        $official_content = null;
        $official_source_url = null;
        $is_official_compared = false;

        global $wp_version;
        $clean_wp_version = preg_replace('/-.*$/', '', $wp_version);

        // 1. Check if WordPress core file
        if (strpos($rel_path, 'wp-admin/') === 0 || strpos($rel_path, 'wp-includes/') === 0 || (!strpos($rel_path, '/') && preg_match('/^wp-.*\.php$|^index\.php$/', $rel_path))) {
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

            if ($plugin_slug && $internal_file) {
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
        }

        // If official content not found, compare with empty or analyze local
        if ($official_content === null) {
            $official_content = '';
            $diff_message = 'Official repository baseline is unavailable for this custom file. Displaying local inspection view.';
        } else {
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
        $old_lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $old_text));
        $new_lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $new_text));

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
                        'content'  => $old_lines[$i - 1],
                    ];
                    $i--;
                    $j--;
                } elseif ($j > 0 && ($i === 0 || $lcs[$i][$j - 1] >= $lcs[$i - 1][$j])) {
                    $reversed_diff[] = [
                        'type'     => 'added',
                        'old_line' => null,
                        'new_line' => $j,
                        'content'  => $new_lines[$j - 1],
                    ];
                    $additions++;
                    $j--;
                } elseif ($i > 0 && ($j === 0 || $lcs[$i][$j - 1] < $lcs[$i - 1][$j])) {
                    $reversed_diff[] = [
                        'type'     => 'removed',
                        'old_line' => $i,
                        'new_line' => null,
                        'content'  => $old_lines[$i - 1],
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
                        'content'  => $old_val,
                    ];
                } else {
                    if ($old_val !== null) {
                        $diff_lines[] = [
                            'type'     => 'removed',
                            'old_line' => $k + 1,
                            'new_line' => null,
                            'content'  => $old_val,
                        ];
                        $deletions++;
                    }
                    if ($new_val !== null) {
                        $diff_lines[] = [
                            'type'     => 'added',
                            'old_line' => null,
                            'new_line' => $k + 1,
                            'content'  => $new_val,
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
}
