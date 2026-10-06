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

        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_slug = dirname($plugin_file);
            if ($plugin_slug === '.') {
                continue; // Single file plugin, skip checksums usually
            }

            $version = $plugin_data['Version'];
            $checksums = $this->provider->get_plugin_checksums($plugin_slug, $version);

            if (!$checksums) {
                // Not from WP.org or checksums unavailable
                $findings[] = new Finding([
                    'engine'      => 'integrity-plugin',
                    'type'        => 'plugin_checksums_unavailable',
                    'severity'    => 'info',
                    'confidence'  => 100,
                    'file_path'   => WP_PLUGIN_DIR . '/' . $plugin_slug,
                    'description' => "Integrity verification unavailable for plugin: {$plugin_data['Name']} (custom/premium plugin)."
                ]);
                continue;
            }

            foreach ($checksums as $file => $expected_hash) {
                $absolute_path = WP_PLUGIN_DIR . '/' . $plugin_slug . '/' . $file;
                
                if (!file_exists($absolute_path)) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-plugin',
                        'type'        => 'missing_plugin_file',
                        'severity'    => 'medium',
                        'confidence'  => 100,
                        'file_path'   => $absolute_path,
                        'description' => "A plugin file is missing: {$plugin_data['Name']}",
                        'evidence'    => "File: $file"
                    ]);
                    continue;
                }

                $actual_hash = md5_file($absolute_path);
                $expected_hash_str = is_array($expected_hash) ? ($expected_hash['hash'] ?? json_encode($expected_hash)) : (string) $expected_hash;
                
                if (!empty($expected_hash_str) && is_string($expected_hash) && $actual_hash !== $expected_hash) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-plugin',
                        'type'        => 'modified_plugin_file',
                        'severity'    => 'medium',
                        'confidence'  => 90, // Modified != malicious
                        'file_path'   => $absolute_path,
                        'description' => "Plugin file differs from the official checksum: {$plugin_data['Name']}",
                        'evidence'    => "Expected: {$expected_hash_str}, Actual: {$actual_hash}"
                    ]);
                }
            }

            // 2. Reverse reconciliation: detect ANY unknown/unlisted files inside official plugin directory (regardless of extension)
            $plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;
            $ignored_basenames = ['.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db'];

            if (is_dir($plugin_dir)) {
                try {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($plugin_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::SELF_FIRST
                    );

                    $normalized_plugin_dir = str_replace('\\', '/', rtrim($plugin_dir, '/\\') . '/');

                    foreach ($iterator as $item) {
                        if (!$item->isFile()) {
                            continue;
                        }

                        $real_path = $item->getPathname();
                        $normalized_path = str_replace('\\', '/', $real_path);
                        $rel_file = str_replace($normalized_plugin_dir, '', $normalized_path);
                        $filename = strtolower($item->getBasename());

                        if (in_array($filename, $ignored_basenames, true)) {
                            continue;
                        }

                        // Flag any file not present in official release manifest
                        if (!isset($checksums[$rel_file])) {
                            $ext = strtolower($item->getExtension());
                            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);

                            $findings[] = new Finding([
                                'engine'      => 'integrity-plugin',
                                'type'        => 'unknown_plugin_file',
                                'severity'    => $is_executable ? 'high' : 'medium',
                                'confidence'  => 95,
                                'file_path'   => $real_path,
                                'description' => "Unrecognized/unknown file found inside official plugin {$plugin_data['Name']}: {$rel_file}",
                                'evidence'    => "File '{$rel_file}' is not part of the official WordPress.org release manifest for {$plugin_slug} v{$version}."
                            ]);
                        }
                    }
                } catch (\Exception $e) {
                    error_log("WCP PluginIntegrity reverse check error: " . $e->getMessage());
                }
            }
        }

        return $findings;
    }
}
