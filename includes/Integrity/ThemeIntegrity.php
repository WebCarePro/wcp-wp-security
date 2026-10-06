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
                // Not from WP.org or theme manifest unavailable
                $findings[] = new Finding([
                    'engine'      => 'integrity-theme',
                    'type'        => 'theme_checksums_unavailable',
                    'severity'    => 'info',
                    'confidence'  => 100,
                    'file_path'   => $theme_dir,
                    'description' => "Integrity verification unavailable for theme: {$theme_data->get('Name')} (custom/premium theme)."
                ]);
                continue;
            }

            // 1. Forward verification: check missing & modified files
            foreach ($checksums as $file => $expected_hash) {
                $absolute_path = $theme_dir . '/' . $file;
                
                if (!file_exists($absolute_path)) {
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

                if (is_string($expected_hash) && strlen($expected_hash) === 32) {
                    $actual_hash = md5_file($absolute_path);
                    if ($actual_hash !== $expected_hash) {
                        $findings[] = new Finding([
                            'engine'      => 'integrity-theme',
                            'type'        => 'modified_theme_file',
                            'severity'    => 'medium',
                            'confidence'  => 90,
                            'file_path'   => $absolute_path,
                            'description' => "Theme file differs from the official checksum: {$theme_data->get('Name')}",
                            'evidence'    => "Expected: $expected_hash, Actual: $actual_hash"
                        ]);
                    }
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
                    error_log("WCP ThemeIntegrity reverse check error: " . $e->getMessage());
                }
            }
        }

        return $findings;
    }
}
