<?php
namespace WCP\Scanner\Integrity;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class ImportantFileFIM {
    
    /**
     * Checks highly sensitive WordPress root files for unexpected modifications.
     * This acts as a basic File Integrity Monitor (FIM) for files that are not strictly 
     * checked by core checksums since they are unique per installation.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function verify($scan_id) {
        $findings = [];

        $critical_files = [
            'wp-config.php' => ABSPATH . 'wp-config.php',
            'index.php'     => ABSPATH . 'index.php',
            '.htaccess'     => ABSPATH . '.htaccess'
        ];

        foreach ($critical_files as $name => $path) {
            if (!file_exists($path)) {
                // Not all sites use .htaccess (e.g., Nginx)
                if ($name === 'wp-config.php' || $name === 'index.php') {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'missing_critical_file',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => $path,
                        'description' => "Critical WordPress file ($name) is missing from the root directory."
                    ]);
                }
                continue;
            }

            // Read the file to check for obvious injected payloads at the top
            // (Often, malware injects a small include/eval at the very beginning of index.php or wp-config.php)
            $content = file_get_contents($path);
            
            if ($name === 'index.php') {
                // The default index.php for WordPress is very simple. 
                // If it contains complex eval() or base64_decode() outside of comments, it's highly suspicious.
                if (preg_match('/^\s*<\?php\s+(eval|assert|base64_decode|gzinflate|str_rot13)\s*\(/i', $content)) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'injected_critical_file',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => $path,
                        'description' => "Suspicious function call detected at the very beginning of $name. This is a common backdoor injection technique.",
                        'code_snippet'=> substr($content, 0, 200)
                    ]);
                }
            }

            if ($name === 'wp-config.php') {
                // wp-config.php should not typically download code or eval
                if (preg_match('/(file_get_contents\s*\(\s*[\'"]https?:\/\/)|(eval\s*\()|(base64_decode\s*\()/', $content)) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'injected_wp_config',
                        'severity'    => 'critical',
                        'confidence'  => 90,
                        'file_path'   => $path,
                        'description' => "Suspicious executable code or remote file inclusion detected in wp-config.php.",
                    ]);
                }
            }
        }

        return $findings;
    }
}
