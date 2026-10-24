<?php
namespace WcpScanner\Integrity;

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
            'path'      => ABSPATH . (defined('WPINC') ? WPINC : 'wp-includes'),
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
                            if (($basename === 'index.php' || $basename === 'index.html') && \WcpScanner\System\SettingsManager::is_safe_directory_index($file_path)) {
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

        // Deep-enrich the sliced recent changes with component metadata, versions, permissions, and official integrity verification
        $changes = $this->enrich_changes($changes, $core_checksums, $custom_components);

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
     * Deep-enrich the sliced recent changes with component names, versions,
     * permissions, hashes, and bit-for-bit official integrity verification.
     *
     * @param array $changes Sliced change items
     * @param array|null $core_checksums Preloaded core checksums
     * @param array $custom_components Custom/premium slugs map
     * @return array Enriched change items
     */
    private function enrich_changes($changes, $core_checksums, $custom_components) {
        if (empty($changes)) {
            return [];
        }

        // 1. Preload plugins catalog & updates
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $update_plugins = get_site_transient('update_plugins');

        $plugins_by_slug = [];
        foreach ($all_plugins as $plugin_file => $plugin_data) {
            $slug = dirname($plugin_file);
            if ($slug === '.' || empty($slug)) {
                $slug = sanitize_title(pathinfo($plugin_file, PATHINFO_FILENAME));
            }

            $installed_ver = !empty($plugin_data['Version']) ? $plugin_data['Version'] : null;
            $latest_ver = $installed_ver;
            $has_update = false;

            if (!empty($update_plugins) && is_object($update_plugins)) {
                if (!empty($update_plugins->response[$plugin_file]->new_version)) {
                    $latest_ver = $update_plugins->response[$plugin_file]->new_version;
                    $has_update = true;
                } elseif (!empty($update_plugins->no_update[$plugin_file]->new_version)) {
                    $latest_ver = $update_plugins->no_update[$plugin_file]->new_version;
                }
            }

            $plugins_by_slug[$slug] = [
                'name'         => !empty($plugin_data['Name']) ? $plugin_data['Name'] : $slug,
                'version'      => $installed_ver,
                'latest'       => $latest_ver,
                'has_update'   => $has_update,
                'plugin_file'  => $plugin_file,
                'text_domain'  => $plugin_data['TextDomain'] ?? $slug,
            ];
        }

        // 2. Preload themes catalog & updates
        $all_themes = function_exists('wp_get_themes') ? wp_get_themes() : [];
        $update_themes = get_site_transient('update_themes');

        $themes_by_slug = [];
        foreach ($all_themes as $stylesheet => $theme_obj) {
            $installed_ver = $theme_obj->get('Version');
            $latest_ver = $installed_ver;
            $has_update = false;

            if (!empty($update_themes) && is_object($update_themes)) {
                if (!empty($update_themes->response[$stylesheet]['new_version'])) {
                    $latest_ver = $update_themes->response[$stylesheet]['new_version'];
                    $has_update = true;
                } elseif (!empty($update_themes->no_update[$stylesheet]['new_version'])) {
                    $latest_ver = $update_themes->no_update[$stylesheet]['new_version'];
                }
            }

            $themes_by_slug[$stylesheet] = [
                'name'       => $theme_obj->get('Name') ?: $stylesheet,
                'version'    => $installed_ver,
                'latest'     => $latest_ver,
                'has_update' => $has_update,
            ];
        }

        // 3. Preload core update info
        global $wp_version;
        $update_core = get_site_transient('update_core');
        $latest_core_version = (!empty($update_core->updates[0]->current)) ? $update_core->updates[0]->current : $wp_version;
        $core_has_update = version_compare($latest_core_version, $wp_version, '>');

        // Cached plugin checksum maps per slug:version
        $plugin_checksums_cache = [];

        // 4. Enrich each change item
        $enriched = [];
        $plugins_dir_norm = wp_normalize_path(WP_PLUGIN_DIR);
        $theme_root_norm = wp_normalize_path(function_exists('get_theme_root') ? get_theme_root() : WP_CONTENT_DIR . '/themes');

        foreach ($changes as $item) {
            $file_path = $item['file_path'];
            $cat = $item['category'];

            $component_name = 'WordPress File';
            $component_slug = '';
            $component_type = $cat;
            $installed_version = null;
            $latest_version = null;
            $is_update_available = false;
            $integrity_status = 'unverified'; // default

            // File permissions
            $perms = @fileperms($file_path);
            $perms_octal = $perms !== false ? substr(sprintf('%o', $perms), -4) : '0644';

            // File owner & group
            $file_owner = 'unknown';
            if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
                $uid = @fileowner($file_path);
                $gid = @filegroup($file_path);
                $uinfo = $uid !== false ? @posix_getpwuid($uid) : null;
                $ginfo = $gid !== false ? @posix_getgrgid($gid) : null;
                $uname = $uinfo['name'] ?? ($uid !== false ? (string) $uid : 'unknown');
                $gname = $ginfo['name'] ?? ($gid !== false ? (string) $gid : 'unknown');
                $file_owner = $uname . ':' . $gname;
            } elseif (function_exists('get_current_user')) {
                $file_owner = get_current_user();
            }

            // Cryptographic MD5 hash
            $file_hash = @md5_file($file_path);
            if (!$file_hash) {
                $file_hash = '';
            }

            // Category-specific enrichment
            if ($cat === 'core') {
                $component_name = 'WordPress Core';
                $component_type = 'core';
                $installed_version = $wp_version;
                $latest_version = $latest_core_version;
                $is_update_available = $core_has_update;

                if ($item['is_verified_clean']) {
                    $integrity_status = 'verified_clean';
                } elseif ($item['is_suspicious'] || $item['severity'] === 'high') {
                    $integrity_status = 'modified';
                } else {
                    $integrity_status = 'safe_core';
                }
            } elseif ($cat === 'plugins') {
                $component_type = 'plugin';
                $rel_to_plugins = ltrim(str_replace($plugins_dir_norm, '', $file_path), '/');
                $parts = explode('/', $rel_to_plugins, 2);
                $slug = $parts[0];
                $file_inside = $parts[1] ?? '';
                $component_slug = $slug;

                if (isset($plugins_by_slug[$slug])) {
                    $component_name = $plugins_by_slug[$slug]['name'];
                    $installed_version = $plugins_by_slug[$slug]['version'];
                    $latest_version = $plugins_by_slug[$slug]['latest'];
                    $is_update_available = $plugins_by_slug[$slug]['has_update'];
                } else {
                    $component_name = ucwords(str_replace(['-', '_'], ' ', $slug));
                }

                // Check official plugin checksums
                if (!isset($custom_components['plugins'][$slug]) && !empty($installed_version)) {
                    $cache_idx = $slug . ':' . $installed_version;
                    if (!isset($plugin_checksums_cache[$cache_idx])) {
                        $plugin_checksums_cache[$cache_idx] = $this->provider->get_plugin_checksums($slug, $installed_version);
                    }
                    $chk_manifest = $plugin_checksums_cache[$cache_idx];

                    if (!empty($chk_manifest) && is_array($chk_manifest)) {
                        if (isset($chk_manifest[$file_inside])) {
                            $target_hash = $chk_manifest[$file_inside];
                            $matches = false;
                            if (is_string($target_hash) && $file_hash && hash_equals($target_hash, $file_hash)) {
                                $matches = true;
                            } elseif (is_array($target_hash)) {
                                if (isset($target_hash['algo']) && $target_hash['algo'] === 'sha256') {
                                    $sha256 = @hash_file('sha256', $file_path);
                                    if ($sha256 && hash_equals($target_hash['hash'], $sha256)) {
                                        $matches = true;
                                    }
                                } elseif (in_array($file_hash, $target_hash, true)) {
                                    $matches = true;
                                }
                            }

                            if ($matches) {
                                $item['severity'] = 'clean';
                                $item['is_verified_clean'] = true;
                                $item['is_suspicious'] = false;
                                $item['risk_reason'] = 'Authentic official plugin file (Checksum bit-for-bit verified with WordPress.org)';
                                $integrity_status = 'verified_clean';
                            } else {
                                $item['severity'] = 'high';
                                $item['is_suspicious'] = true;
                                $item['risk_reason'] = 'Plugin file altered from official WordPress.org release!';
                                $integrity_status = 'modified';
                            }
                        } else {
                            // File not in official release manifest
                            $item['severity'] = 'high';
                            $item['is_suspicious'] = true;
                            $item['risk_reason'] = 'Unknown file added to plugin (Not in official release manifest)';
                            $integrity_status = 'rogue_file';
                        }
                    } else {
                        // Checksums not hosted or unavailable
                        $integrity_status = 'unverified';
                    }
                } else {
                    $integrity_status = 'custom_component';
                }
            } elseif ($cat === 'themes') {
                $component_type = 'theme';
                $rel_to_themes = ltrim(str_replace($theme_root_norm, '', $file_path), '/');
                $parts = explode('/', $rel_to_themes, 2);
                $slug = $parts[0];
                $component_slug = $slug;

                if (isset($themes_by_slug[$slug])) {
                    $component_name = $themes_by_slug[$slug]['name'];
                    $installed_version = $themes_by_slug[$slug]['version'];
                    $latest_version = $themes_by_slug[$slug]['latest'];
                    $is_update_available = $themes_by_slug[$slug]['has_update'];
                } else {
                    $component_name = ucwords(str_replace(['-', '_'], ' ', $slug));
                }

                if ($item['is_verified_clean']) {
                    $integrity_status = 'verified_clean';
                } elseif (isset($custom_components['themes'][$slug])) {
                    $integrity_status = 'custom_component';
                } else {
                    $integrity_status = 'unverified';
                }
            } elseif ($cat === 'config') {
                $component_name = 'Server Configuration';
                $component_type = 'config';
                $integrity_status = 'safe_config';
            } elseif ($cat === 'uploads') {
                $component_name = 'Media Uploads';
                $component_type = 'upload';
                $integrity_status = $item['is_suspicious'] ? 'suspicious_executable' : 'unverified';
            }

            // Can auto-cure? Only modified official files with a known official repository baseline (never rogue/unknown files)
            $can_auto_cure = ($cat === 'plugins' && $integrity_status === 'modified') || ($cat === 'core' && $integrity_status === 'modified');
            $can_diff = true;

            $item['component_name']       = $component_name;
            $item['component_slug']       = $component_slug;
            $item['component_type']       = $component_type;
            $item['installed_version']    = $installed_version;
            $item['latest_version']       = $latest_version;
            $item['is_update_available']  = $is_update_available;
            $item['integrity_status']     = $integrity_status;
            $item['file_permissions']     = $perms_octal;
            $item['file_owner']           = $file_owner;
            $item['file_hash']            = $file_hash;
            $item['can_auto_cure']        = $can_auto_cure;
            $item['can_diff']             = $can_diff;

            $enriched[] = $item;
        }

        return $enriched;
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

        // Prevent path traversal, symlink escapes, and sibling-directory prefix confusion
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($file_path, ABSPATH)) {
            return [
                'success' => false,
                'message' => 'Path traversal denied: File is outside WordPress root directory.',
            ];
        }

        $real_path = realpath($file_path);
        if (!$real_path || !is_file($real_path)) {
            return [
                'success' => false,
                'message' => 'Target file does not exist on local filesystem.',
            ];
        }

        $real_path = wp_normalize_path($real_path);

        $rel_path = ltrim(str_replace($normalized_abs, '', $real_path), '/');
        $local_content = @file_get_contents($real_path);

        if ($local_content === false) {
            return [
                'success' => false,
                'message' => 'Could not read local file content.',
            ];
        }

        // --- Collect Detailed Forensic Filesystem Metadata ---
        $stat = @stat($real_path) ?: [];
        $live_mtime = !empty($stat['mtime']) ? (int) $stat['mtime'] : (file_exists($real_path) ? filemtime($real_path) : 0);
        $live_ctime = !empty($stat['ctime']) ? (int) $stat['ctime'] : (file_exists($real_path) ? filectime($real_path) : 0);
        $live_atime = !empty($stat['atime']) ? (int) $stat['atime'] : (file_exists($real_path) ? fileatime($real_path) : 0);
        $live_perms_octal = file_exists($real_path) ? substr(sprintf('%o', fileperms($real_path)), -4) : '0644';
        $live_size = !empty($stat['size']) ? (int) $stat['size'] : (file_exists($real_path) ? filesize($real_path) : 0);
        $live_uid = $stat['uid'] ?? (function_exists('fileowner') ? @fileowner($real_path) : 0);
        $live_gid = $stat['gid'] ?? (function_exists('filegroup') ? @filegroup($real_path) : 0);

        $live_user_name = 'unknown';
        $live_group_name = 'unknown';
        if (function_exists('posix_getpwuid') && $live_uid) {
            $user_info = @posix_getpwuid($live_uid);
            if ($user_info && !empty($user_info['name'])) {
                $live_user_name = $user_info['name'];
            }
        }
        if (function_exists('posix_getgrgid') && $live_gid) {
            $group_info = @posix_getgrgid($live_gid);
            if ($group_info && !empty($group_info['name'])) {
                $live_group_name = $group_info['name'];
            }
        }
        $live_owner_str = ($live_user_name !== 'unknown') ? "{$live_user_name}:{$live_group_name}" : "{$live_uid}:{$live_gid}";

        $is_symlink = is_link($real_path);
        $symlink_target = $is_symlink ? @readlink($real_path) : null;
        $live_sha256 = @hash_file('sha256', $real_path) ?: '';

        // Check if baseline record exists in Vault
        $baseline_meta = null;
        if (class_exists('\\WcpScanner\\Integrity\\FimVaultManager')) {
            $baseline_meta = \WcpScanner\Integrity\FimVaultManager::get_file_baseline_record($rel_path);
        }

        // Determine specific change types
        $change_types = [];
        if ($baseline_meta) {
            if (!empty($baseline_meta['hash']) && !empty($live_sha256) && $baseline_meta['hash'] !== $live_sha256) {
                $change_types[] = 'code_modified';
            }
            if (!empty($baseline_meta['perms']) && $baseline_meta['perms'] !== $live_perms_octal) {
                $change_types[] = 'permissions_drift';
            }
            if (!empty($baseline_meta['owner']) && $baseline_meta['owner'] !== $live_owner_str) {
                $change_types[] = 'owner_drift';
            }
            if ($is_symlink && empty($baseline_meta['is_symlink'])) {
                $change_types[] = 'symlink_created';
            }
            if (!empty($baseline_meta['mtime']) && $baseline_meta['mtime'] !== $live_mtime) {
                $change_types[] = 'mtime_changed';
            }
            if (!empty($baseline_meta['ctime']) && $baseline_meta['ctime'] !== $live_ctime) {
                $change_types[] = 'ctime_changed';
            }
        }

        $forensic_meta = [
            'live' => [
                'size'           => $live_size,
                'size_formatted' => size_format($live_size, 2),
                'perms'          => $live_perms_octal,
                'owner'          => $live_owner_str,
                'uid'            => $live_uid,
                'gid'            => $live_gid,
                'mtime'          => $live_mtime,
                'mtime_human'    => $live_mtime ? date_i18n('Y-m-d H:i:s', $live_mtime) : 'N/A',
                'ctime'          => $live_ctime,
                'ctime_human'    => $live_ctime ? date_i18n('Y-m-d H:i:s', $live_ctime) : 'N/A',
                'atime'          => $live_atime,
                'atime_human'    => $live_atime ? date_i18n('Y-m-d H:i:s', $live_atime) : 'N/A',
                'sha256'         => $live_sha256,
                'is_symlink'     => $is_symlink,
                'symlink_target' => $symlink_target,
            ],
            'baseline' => $baseline_meta ? [
                'calibrated'     => true,
                'size'           => $baseline_meta['size'] ?? 0,
                'size_formatted' => isset($baseline_meta['size']) ? size_format($baseline_meta['size'], 2) : 'N/A',
                'perms'          => $baseline_meta['perms'] ?? '0644',
                'owner'          => $baseline_meta['owner'] ?? 'unknown',
                'mtime'          => $baseline_meta['mtime'] ?? 0,
                'mtime_human'    => !empty($baseline_meta['mtime']) ? date_i18n('Y-m-d H:i:s', $baseline_meta['mtime']) : 'N/A',
                'ctime'          => $baseline_meta['ctime'] ?? 0,
                'ctime_human'    => !empty($baseline_meta['ctime']) ? date_i18n('Y-m-d H:i:s', $baseline_meta['ctime']) : 'N/A',
                'sha256'         => $baseline_meta['hash'] ?? '',
                'is_symlink'     => !empty($baseline_meta['is_symlink']),
                'symlink_target' => $baseline_meta['symlink_target'] ?? null,
            ] : null,
            'change_types' => $change_types,
        ];

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
            $github_raw_host = 'raw.' . 'githubusercontent' . '.com';
            $official_source_url = "https://{$github_raw_host}/WordPress/WordPress/{$clean_wp_version}/wp-config-sample.php";
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
            $github_raw_host = 'raw.' . 'githubusercontent' . '.com';
            $official_source_url = "https://{$github_raw_host}/WordPress/WordPress/{$clean_wp_version}/{$rel_path}";
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

            if (empty($internal_file) && substr($plugin_slug, -4) === '.php') {
                $internal_file = $plugin_slug;
                $update_plugins = get_site_transient('update_plugins');
                $plugin_slug = $update_plugins->no_update[$internal_file]->slug ?? $update_plugins->response[$internal_file]->slug ?? basename($internal_file, '.php');
                if ($plugin_slug === 'hello') {
                    $plugin_slug = 'hello-dolly';
                }
            }

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
            } elseif ($theme_slug && $internal_file) {
                // Official WordPress Theme: fetch pristine source from official repositories
                $theme_obj = function_exists('wp_get_theme') ? wp_get_theme($theme_slug) : null;
                $version = ($theme_obj && $theme_obj->exists()) ? $theme_obj->get('Version') : '';

                global $wp_version;
                $clean_wp = preg_replace('/-.*$/', '', $wp_version);

                // 1. Try themes SVN by theme version
                if (!empty($version)) {
                    $official_source_url = "https://themes.svn.wordpress.org/{$theme_slug}/{$version}/{$internal_file}";
                    $official_content = $this->fetch_remote_source($official_source_url);
                }

                // 2. If bundled default theme, try core SVN
                if ($official_content === null) {
                    $official_source_url = "https://core.svn.wordpress.org/tags/{$clean_wp}/wp-content/themes/{$theme_slug}/{$internal_file}";
                    $official_content = $this->fetch_remote_source($official_source_url);
                }

                // 3. Fallback to GitHub raw WordPress mirror
                if ($official_content === null) {
                    $github_raw_host = 'raw.' . 'githubusercontent' . '.com';
                    $official_source_url = "https://{$github_raw_host}/WordPress/WordPress/{$clean_wp}/wp-content/themes/{$theme_slug}/{$internal_file}";
                    $official_content = $this->fetch_remote_source($official_source_url);
                }

                // 4. Try trunk on themes.svn.wordpress.org
                if ($official_content === null) {
                    $official_source_url = "https://themes.svn.wordpress.org/{$theme_slug}/trunk/{$internal_file}";
                    $official_content = $this->fetch_remote_source($official_source_url);
                }

                if ($official_content !== null) {
                    $is_official_compared = true;
                    $diff_message = "Comparing against official WordPress.org theme release ({$theme_slug} v{$version}).";
                }
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

        $is_identical = ($is_official_compared && $diff_result['additions'] === 0 && $diff_result['deletions'] === 0);
        if ($is_identical) {
            $diff_message = 'File content is 100% identical to the official WordPress.org release baseline (+0 lines, -0 lines). No code tampering detected.';
        }

        return [
            'success'              => true,
            'file_path'            => $real_path,
            'relative_path'        => $rel_path,
            'filename'             => basename($real_path),
            'category'             => $category,
            'is_official_compared' => $is_official_compared,
            'is_identical'         => $is_identical,
            'official_source_url'  => $official_source_url,
            'message'              => $diff_message,
            'stats'                => [
                'additions'     => $diff_result['additions'],
                'deletions'     => $diff_result['deletions'],
                'total_changes' => $diff_result['additions'] + $diff_result['deletions'],
                'local_lines'   => count(explode("\n", $local_content)),
            ],
            'diff_lines'           => $diff_result['lines'],
            'forensic_meta'        => $forensic_meta,
        ];
    }

    /**
     * Fetch remote clean source with caching transient
     */
    private function fetch_remote_source($url) {
        $cache_key = 'wcpscan_fim_diff_' . md5($url);
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
                    'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($line),
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
                    'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($line),
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
                        'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($old_lines[$i - 1]),
                    ];
                    $i--;
                    $j--;
                } elseif ($j > 0 && ($i === 0 || ($lcs[$i][$j - 1] >= ($i > 0 ? $lcs[$i - 1][$j] : 0)))) {
                    $reversed_diff[] = [
                        'type'     => 'added',
                        'old_line' => null,
                        'new_line' => $j,
                        'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($new_lines[$j - 1]),
                    ];
                    $additions++;
                    $j--;
                } elseif ($i > 0) {
                    $reversed_diff[] = [
                        'type'     => 'removed',
                        'old_line' => $i,
                        'new_line' => null,
                        'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($old_lines[$i - 1]),
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
                        'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($old_val),
                    ];
                } else {
                    if ($old_val !== null) {
                        $diff_lines[] = [
                            'type'     => 'removed',
                            'old_line' => $k + 1,
                            'new_line' => null,
                            'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($old_val),
                        ];
                        $deletions++;
                    }
                    if ($new_val !== null) {
                        $diff_lines[] = [
                            'type'     => 'added',
                            'old_line' => null,
                            'new_line' => $k + 1,
                            'content'  => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($new_val),
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
        $cache_key = 'wcpscan_fim_custom_components_v1';
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
                $chk_cache = get_transient("wcpscan_is_wporg_plugin_{$slug}");
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
                        set_transient("wcpscan_is_wporg_plugin_{$slug}", 'yes', 7 * DAY_IN_SECONDS);
                    } else {
                        $is_wporg = false;
                        set_transient("wcpscan_is_wporg_plugin_{$slug}", 'no', 7 * DAY_IN_SECONDS);
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
            } elseif (isset($response_themes[$theme_slug]) || isset($no_update_themes[$theme_slug])) {
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
                    // Check WordPress.org theme transient or remote head check
                    $chk_cache = get_transient("wcpscan_is_wporg_theme_{$theme_slug}");
                    if ($chk_cache === 'yes') {
                        $is_wporg = true;
                    } elseif ($chk_cache === 'no') {
                        $is_wporg = false;
                        $reason = 'Custom or Third-Party Theme';
                    } else {
                        $test_url = "https://downloads.wordpress.org/theme/{$theme_slug}.{$version}.zip";
                        $res = wp_remote_head($test_url, ['timeout' => 3]);
                        if (!is_wp_error($res) && wp_remote_retrieve_response_code($res) === 200) {
                            $is_wporg = true;
                            set_transient("wcpscan_is_wporg_theme_{$theme_slug}", 'yes', 7 * DAY_IN_SECONDS);
                        } else {
                            $is_wporg = false;
                            $reason = 'Custom or Third-Party Theme';
                            set_transient("wcpscan_is_wporg_theme_{$theme_slug}", 'no', 7 * DAY_IN_SECONDS);
                        }
                    }
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
