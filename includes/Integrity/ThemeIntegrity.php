<?php
namespace WCP\Scanner\Integrity;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class ThemeIntegrity {
    
    private $provider;

    public function __construct() {
        $this->provider = new ChecksumProvider();
    }

    /**
     * Verify installed themes against official checksums.
     * Note: WP.org doesn't officially expose a theme checksum endpoint identical to plugins, 
     * but we simulate the interface here for when they do or if we hook into a 3rd party API.
     * For now, we will flag them as unavailable.
     *
     * @param string $scan_id
     * @return Finding[] Array of findings
     */
    public function verify($scan_id) {
        $findings = [];
        
        if (!function_exists('wp_get_themes')) {
            require_once ABSPATH . 'wp-includes/theme.php';
        }

        $themes = wp_get_themes();

        foreach ($themes as $theme_slug => $theme_data) {
            $version = $theme_data->get('Version');
            $theme_dir = $theme_data->get_stylesheet_directory();

            $checksums = $this->provider->get_theme_checksums($theme_slug, $version);

            if (!$checksums) {
                // Not from WP.org or theme manifest unavailable (Custom, Child, or Premium Theme)
                $is_child = (bool) $theme_data->parent() || (bool) preg_match('/(?:^|[-_])child(?:[-_]|$)/i', $theme_slug);
                $theme_name = $theme_data->get('Name') ?: $theme_slug;
                $theme_uri = (string) $theme_data->get('ThemeURI');
                $author_uri = (string) $theme_data->get('AuthorURI');
                $parent_name = ($is_child && $theme_data->parent()) ? $theme_data->parent()->get('Name') : null;

                $is_premium = (bool) preg_match(
                    '/\b(premium|pro|commercial|license|themeforest|envato|elegantthemes|studiopress|woocommerce|flavor)\b/i',
                    $theme_slug . ' ' . $theme_name . ' ' . $theme_uri . ' ' . $author_uri
                );

                if ($is_child) {
                    $classification = 'custom_child_theme';
                    $display_title = 'Custom Child Theme';
                    $desc_type = $parent_name ? "child theme (parent: {$parent_name})" : "child theme";
                } elseif ($is_premium) {
                    $classification = 'premium_theme';
                    $display_title = 'Premium Theme';
                    $desc_type = 'premium theme';
                } else {
                    $classification = 'custom_theme';
                    $display_title = 'Custom or Premium Theme';
                    $desc_type = 'custom or premium theme';
                }

                $findings[] = new Finding([
                    'engine'      => 'integrity-theme',
                    'type'        => 'theme_checksums_unavailable',
                    'severity'    => 'info',
                    'confidence'  => 100,
                    'file_path'   => wp_normalize_path($theme_dir),
                    'evidence'    => wp_json_encode([
                        'component_type' => 'theme',
                        'is_dir'         => true,
                        'is_child'       => $is_child,
                        'is_premium'     => $is_premium,
                        'classification' => $classification,
                        'display_title'  => $display_title,
                        'theme_slug'     => $theme_slug,
                        'theme_name'     => $theme_name,
                        'parent_theme'   => $parent_name,
                        'version'        => $version,
                    ]),
                    'description' => "Integrity checksums unavailable for {$desc_type}: {$theme_name} (unmanaged/non-WordPress.org theme)."
                ]);
                continue;
            }

            // 1. Forward verification: check missing & modified files
            foreach ($checksums as $file => $expected_hash) {
                $absolute_path = $theme_dir . '/' . $file;
                
                if (!file_exists($absolute_path)) {
                    // Ignore development/build artifacts present in SVN/GitHub repos but intentionally stripped in production core theme bundles
                    $ignored_dev_files = [
                        'package.json', 'package-lock.json', 'contributing.txt', 'contributing.md',
                        'readme.md', 'changelog.md', 'changelog.txt', '.editorconfig', '.prettierrc',
                        'composer.json', 'composer.lock', 'gruntfile.js', 'webpack.config.js',
                        'style.min.css'
                    ];
                    if (in_array(strtolower(basename($file)), $ignored_dev_files, true)) {
                        continue;
                    }

                    $findings[] = new Finding([
                        'engine'      => 'integrity-theme',
                        'type'        => 'missing_theme_file',
                        'severity'    => 'medium',
                        'confidence'  => 100,
                        'file_path'   => $absolute_path,
                        'description' => "A theme file is missing: {$theme_data->get('Name')}",
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
                        'engine'      => 'integrity-theme',
                        'type'        => 'modified_theme_file',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => wp_normalize_path($absolute_path),
                        'description' => "Theme file differs from the official checksum: {$theme_data->get('Name')}",
                        'evidence'    => "Expected: {$expected_hash_str}, Actual: {$actual_hash}"
                    ]);
                }
            }

            // 2. Reverse reconciliation: detect ANY unknown/unlisted files inside official theme directory (whatever the extension)
            $ignored_basenames = ['.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db'];

            if (is_dir($theme_dir)) {
                try {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($theme_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::SELF_FIRST
                    );

                    $normalized_theme_dir = str_replace('\\', '/', rtrim($theme_dir, '/\\') . '/');

                    foreach ($iterator as $item) {
                        if (!$item->isFile()) {
                            continue;
                        }

                        $real_path = $item->getPathname();
                        $normalized_path = str_replace('\\', '/', $real_path);
                        $rel_file = str_replace($normalized_theme_dir, '', $normalized_path);
                        $filename = strtolower($item->getBasename());

                        if (in_array($filename, $ignored_basenames, true)) {
                            continue;
                        }

                        // Flag any file not present in official release manifest (regardless of extension)
                        if (!isset($checksums[$rel_file])) {
                            $ext = strtolower($item->getExtension());
                            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);

                            $findings[] = new Finding([
                                'engine'      => 'integrity-theme',
                                'type'        => 'unknown_theme_file',
                                'severity'    => $is_executable ? 'high' : 'medium',
                                'confidence'  => 95,
                                'file_path'   => $real_path,
                                'description' => "Unrecognized/unknown file found inside official theme {$theme_data->get('Name')}: {$rel_file}",
                                'evidence'    => "File '{$rel_file}' is not part of the official WordPress release manifest for theme {$theme_slug} v{$version}."
                            ]);
                        }
                    }
                } catch (\Exception $e) {
                    // Suppress theme checksum exceptions silently
                }
            }
        }

        return $findings;
    }
}
