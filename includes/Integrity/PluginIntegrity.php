<?php
namespace WCP\Scanner\Integrity;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class PluginIntegrity {
    
    private $provider;

    public function __construct() {
        $this->provider = new ChecksumProvider();
    }

    /**
     * Verify active plugins against official checksums.
     *
     * @param string $scan_id
     * @return Finding[] Array of findings
     */
    public function verify($scan_id) {
        $findings = [];
        
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins = get_plugins();

        $processed_slugs = [];
        $scanner_basename = plugin_basename(WCP_SCANNER_FILE);
        $scanner_slug = dirname($scanner_basename);

        // Fetch WordPress official update transient to resolve canonical slugs
        $update_plugins = get_site_transient('update_plugins');

        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_dir_name = dirname($plugin_file);
            $is_single_file = ($plugin_dir_name === '.' || empty($plugin_dir_name));

            // Exclude scanner's own code
            if (
                $plugin_dir_name === $scanner_slug ||
                $plugin_dir_name === 'wcp-security-scanner' ||
                $plugin_dir_name === 'wcp-wp-scanner' ||
                strpos($plugin_file, 'wcp-') === 0
            ) {
                continue;
            }

            // Determine canonical plugin slug
            $canonical_slug = null;
            if (!empty($update_plugins->no_update[$plugin_file]->slug)) {
                $canonical_slug = $update_plugins->no_update[$plugin_file]->slug;
            } elseif (!empty($update_plugins->response[$plugin_file]->slug)) {
                $canonical_slug = $update_plugins->response[$plugin_file]->slug;
            }

            if ($is_single_file) {
                $effective_slug = $canonical_slug ?: (!empty($plugin_data['TextDomain']) ? $plugin_data['TextDomain'] : basename($plugin_file, '.php'));
            } else {
                $effective_slug = $canonical_slug ?: $plugin_dir_name;
            }

            if (isset($processed_slugs[$effective_slug])) {
                continue;
            }
            $processed_slugs[$effective_slug] = true;

            $version = trim(preg_replace('/^v/i', '', (string) ($plugin_data['Version'] ?? '')));
            if (empty($version)) {
                continue;
            }

            // Detect commercial / premium / custom branches in folder naming or plugin title
            $is_premium_or_custom_dir = (bool) preg_match('/(?:^|[-_])(premium|pro|addon|addons|unlimited|disabled|disableds|master|main|dev|backup|old)(?:[-_]|$)/i', $plugin_dir_name);
            $has_premium_title = (bool) preg_match('/\b(premium|pro|unlimited|commercial)\b/i', $plugin_data['Name'] ?? '');
            $is_commercial_or_custom = ($is_premium_or_custom_dir || $has_premium_title);

            $checksums = null;

            // Only attempt official WordPress.org checksum retrieval if this is NOT a commercial/premium/custom plugin
            if (!$is_commercial_or_custom) {
                // 1. Attempt checksum retrieval by effective slug
                $checksums = $this->provider->get_plugin_checksums($effective_slug, $version);

                // 2. Fallback to folder name if effective slug differed
                if (!$checksums && !$is_single_file && $effective_slug !== $plugin_dir_name) {
                    $checksums = $this->provider->get_plugin_checksums($plugin_dir_name, $version);
                }

                // 3. Fallback to TextDomain ONLY for single-file plugins (e.g. hello.php) or when folder matches TextDomain.
                if (!$checksums && !empty($plugin_data['TextDomain'])) {
                    if ($is_single_file || $plugin_data['TextDomain'] === $plugin_dir_name) {
                        $checksums = $this->provider->get_plugin_checksums($plugin_data['TextDomain'], $version);
                    }
                }
            }

            $component_dir = $is_single_file ? WP_PLUGIN_DIR : (WP_PLUGIN_DIR . '/' . $plugin_dir_name);

            if (!$checksums) {
                // Not from WP.org or checksums unavailable
                $findings[] = new Finding([
                    'engine'      => 'integrity-plugin',
                    'type'        => 'plugin_checksums_unavailable',
                    'severity'    => 'info',
                    'confidence'  => 100,
                    'file_path'   => wp_normalize_path($component_dir),
                    'description' => "Integrity verification unavailable for plugin: {$plugin_data['Name']} (custom/premium plugin)."
                ]);
                continue;
            }

            // 1. Forward verification: check missing & modified files
            foreach ($checksums as $file => $expected_hash) {
                $absolute_path = $is_single_file ? (WP_PLUGIN_DIR . '/' . $file) : ($component_dir . '/' . $file);
                
                if (!file_exists($absolute_path)) {
                    // For single-file plugins, auxiliary files like readme.txt are not placed in WP_PLUGIN_DIR
                    if ($is_single_file && $file !== basename($plugin_file)) {
                        continue;
                    }
                    $findings[] = new Finding([
                        'engine'      => 'integrity-plugin',
                        'type'        => 'missing_plugin_file',
                        'severity'    => 'high',
                        'confidence'  => 100,
                        'file_path'   => wp_normalize_path($absolute_path),
                        'description' => "A plugin file is missing: {$plugin_data['Name']}",
                        'evidence'    => "File: $file"
                    ]);
                    continue;
                }

                // Extract valid hashes and algorithm
                $algo = 'md5';
                $valid_hashes = [];
                if (is_array($expected_hash)) {
                    if (isset($expected_hash['algo']) && $expected_hash['algo'] === 'sha256') {
                        $algo = 'sha256';
                        $valid_hashes = (array) ($expected_hash['hash'] ?? []);
                    } elseif (isset($expected_hash['md5'])) {
                        $valid_hashes = (array) $expected_hash['md5'];
                    } elseif (isset($expected_hash['hash'])) {
                        $valid_hashes = (array) $expected_hash['hash'];
                    } else {
                        $valid_hashes = $expected_hash;
                    }
                } elseif (is_string($expected_hash)) {
                    $valid_hashes = [$expected_hash];
                }

                $valid_hashes = array_filter(array_map('strval', $valid_hashes));
                if (empty($valid_hashes)) {
                    continue;
                }

                $actual_hash = ($algo === 'sha256') ? hash_file('sha256', $absolute_path) : md5_file($absolute_path);
                $is_modified = !in_array($actual_hash, $valid_hashes, true);

                // If modified, also normalize line endings (CRLF vs LF) to prevent OS false positives
                if ($is_modified && $algo === 'md5') {
                    $raw_content = @file_get_contents($absolute_path);
                    if ($raw_content !== false) {
                        $normalized_hash = md5(str_replace("\r\n", "\n", $raw_content));
                        if (in_array($normalized_hash, $valid_hashes, true)) {
                            $is_modified = false;
                        }
                    }
                }

                if ($is_modified) {
                    $expected_hash_str = implode(', ', $valid_hashes);
                    $findings[] = new Finding([
                        'engine'      => 'integrity-plugin',
                        'type'        => 'modified_plugin_file',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => wp_normalize_path($absolute_path),
                        'description' => "Plugin file differs from the official checksum: {$plugin_data['Name']}",
                        'evidence'    => "Expected: {$expected_hash_str}, Actual: {$actual_hash}"
                    ]);
                }
            }

            // 2. Reverse reconciliation: detect ANY unknown/unlisted files inside official plugin directory
            if (!$is_single_file && is_dir($component_dir)) {
                $ignored_basenames = [
                    '.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db',
                    '.gitignore', 'license', 'license.txt', 'readme.md', 'changelog.txt'
                ];
                $runtime_dirs = ['logs', 'storage', 'cache', 'caches', 'backups', 'temp', 'tmp'];

                try {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($component_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::SELF_FIRST
                    );

                    $normalized_plugin_dir = str_replace('\\', '/', rtrim($component_dir, '/\\') . '/');

                    foreach ($iterator as $item) {
                        if (!$item->isFile()) {
                            continue;
                        }

                        $real_path = $item->getPathname();
                        $normalized_path = str_replace('\\', '/', $real_path);
                        $rel_file = ltrim(str_replace($normalized_plugin_dir, '', $normalized_path), '/');
                        $filename = strtolower($item->getBasename());

                        if (in_array($filename, $ignored_basenames, true)) {
                            continue;
                        }

                        // Check if file is located inside common runtime/storage directories (e.g. storage/, logs/, cache/)
                        $path_segments = explode('/', strtolower($rel_file));
                        $is_in_runtime_dir = !empty(array_intersect($path_segments, $runtime_dirs));

                        // Flag any file not present in official release manifest
                        if (!isset($checksums[$rel_file])) {
                            $ext = strtolower($item->getExtension());
                            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);

                            // Skip non-executable runtime files (e.g. storage/index.html, logs/debug.log)
                            if ($is_in_runtime_dir && !$is_executable) {
                                continue;
                            }

                            // If it's a directory silence guard in runtime folders (e.g. index.php with silent exit), skip
                            if ($is_in_runtime_dir && in_array($filename, ['index.php', 'index.html'], true) && $item->getSize() < 500) {
                                continue;
                            }

                            $findings[] = new Finding([
                                'engine'      => 'integrity-plugin',
                                'type'        => 'unknown_plugin_file',
                                'severity'    => $is_executable ? 'high' : 'medium',
                                'confidence'  => 95,
                                'file_path'   => wp_normalize_path($real_path),
                                'description' => "Unrecognized/unknown file found inside official plugin {$plugin_data['Name']}: {$rel_file}",
                                'evidence'    => "File '{$rel_file}' is not part of the official WordPress.org release manifest for {$effective_slug} v{$version}."
                            ]);
                        }
                    }
                } catch (\Exception $e) {
                    // Suppress plugin checksum exceptions silently
                }
            }
        }

        return $findings;
    }
}
