<?php
namespace WCP\Scanner\Integrity;

use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Filesystem\FileHasher;

if (!defined('ABSPATH')) {
    exit;
}

class CoreIntegrity {
    
    private $provider;

    public function __construct() {
        $this->provider = new ChecksumProvider();
    }

    /**
     * Verify WordPress core files against official checksums.
     *
     * @param string $scan_id
     * @return Finding[] Array of findings
     */
    public function verify($scan_id) {
        $findings = [];
        $checksums = $this->provider->get_core_checksums();

        if (!$checksums) {
            $findings[] = new Finding([
                'engine'      => 'integrity-core',
                'type'        => 'core_checksums_unavailable',
                'severity'    => 'info',
                'confidence'  => 100,
                'description' => "Could not retrieve official WordPress core checksums from api.wordpress.org."
            ]);
            return $findings;
        }

        // We use MD5 here because api.wordpress.org/core/checksums currently returns MD5
        foreach ($checksums as $file => $expected_hash) {
            $absolute_path = ABSPATH . $file;
            
            // Skip wp-content as it's not core, though checksums might include some default themes/plugins
            if (strpos($file, 'wp-content/') === 0) {
                continue;
            }

            if (!file_exists($absolute_path)) {
                $findings[] = new Finding([
                    'engine'      => 'integrity-core',
                    'type'        => 'missing_core_file',
                    'severity'    => 'high',
                    'confidence'  => 100,
                    'file_path'   => $absolute_path,
                    'description' => "A WordPress core file is missing.",
                    'evidence'    => "File: $file"
                ]);
                continue;
            }

            $actual_hash = md5_file($absolute_path);
            
            if ($actual_hash !== $expected_hash) {
                $findings[] = new Finding([
                    'engine'      => 'integrity-core',
                    'type'        => 'modified_core_file',
                    'severity'    => 'high',
                    'confidence'  => 99,
                    'file_path'   => $absolute_path,
                    'description' => "WordPress core file differs from the official checksum.",
                    'evidence'    => "Expected: $expected_hash, Actual: $actual_hash"
                ]);
            }
        }

        // 2. Reverse Reconciliation: Scan wp-admin and wp-includes for unknown/rogue files
        $core_dirs = [
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes'
        ];

        $ignored_basenames = ['.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db'];
        $normalized_abs = str_replace('\\', '/', rtrim(ABSPATH, '/\\') . '/');

        foreach ($core_dirs as $core_dir) {
            if (!is_dir($core_dir)) {
                continue;
            }

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($core_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($iterator as $item) {
                    if (!$item->isFile()) {
                        continue;
                    }

                    $real_file_path = $item->getPathname();
                    $normalized_item = str_replace('\\', '/', $real_file_path);
                    $rel_file = str_replace($normalized_abs, '', $normalized_item);
                    $filename = strtolower($item->getBasename());

                    if (in_array($filename, $ignored_basenames, true)) {
                        continue;
                    }

                    // Check if file is present in official manifest
                    if (!isset($checksums[$rel_file])) {
                        $ext = strtolower($item->getExtension());
                        $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);

                        $findings[] = new Finding([
                            'engine'      => 'integrity-core',
                            'type'        => 'unknown_core_file',
                            'severity'    => $is_executable ? 'high' : 'medium',
                            'confidence'  => 95,
                            'file_path'   => $real_file_path,
                            'description' => "Unrecognized/unknown file found inside WordPress core directory: {$rel_file}",
                            'evidence'    => "File '{$rel_file}' is not part of the official WordPress release manifest."
                        ]);
                    }
                }
            } catch (\Exception $e) {
                error_log("WCP CoreIntegrity reverse check error: " . $e->getMessage());
            }
        }

        return $findings;
    }
}
