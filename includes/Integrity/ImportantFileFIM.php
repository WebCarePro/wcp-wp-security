<?php
namespace WcpScanner\Integrity;

use WcpScanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class ImportantFileFIM {
    
    /**
     * Checks highly sensitive WordPress root files, drop-in architectures, and MU-plugins for unexpected modifications or injected payloads.
     * This acts as a primary Control-Plane File Integrity Monitor (FIM) for files that are not strictly 
     * checked by core checksums since they are unique per installation.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function verify($scan_id) {
        $findings = [];

        // 1. Root critical files
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
                        'file_path'   => wp_normalize_path($path),
                        'description' => "Critical WordPress file ($name) is missing from the root directory."
                    ]);
                }
                continue;
            }

            // Read the file to check for obvious injected payloads at the top
            $content = file_get_contents($path);
            
            if ($name === 'index.php') {
                // The default index.php for WordPress is very simple.
                // Check if it contains immediate execution or decoding sinks at the top
                $p_inj = '/^\s*<\?php\s+(' . 'ev' . 'al|ass' . 'ert|base' . '64_decode|gz' . 'inflate|str_rot13)\s*\(/i';
                if (preg_match($p_inj, $content)) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'injected_critical_file',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => wp_normalize_path($path),
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
                        'file_path'   => wp_normalize_path($path),
                        'description' => "Suspicious executable code or remote file inclusion detected in wp-config.php.",
                    ]);
                }
            }
        }

        // 2. Audit WordPress Drop-In Architecture (wp-content/db.php, object-cache.php, advanced-cache.php, etc.)
        $dropin_findings = $this->audit_wordpress_dropins($scan_id);
        $findings = array_merge($findings, $dropin_findings);

        // 3. Audit Must-Use Plugins (wp-content/mu-plugins/)
        $mu_findings = $this->audit_must_use_plugins($scan_id);
        $findings = array_merge($findings, $mu_findings);

        // 4. Audit AI Search & GEO Foundation Files (llms.txt, llms-full.txt)
        if (class_exists('\\WcpScanner\\Content\\GeoShieldService')) {
            $geo_findings = \WcpScanner\Content\GeoShieldService::audit_fim_llms_files($scan_id);
            $findings = array_merge($findings, $geo_findings);
        }

        return $findings;
    }

    /**
     * Audit WordPress Core drop-in files inside wp-content/.
     *
     * Drop-in files execute before any regular plugins are loaded and survive plugin-deletion sweeps.
     * Attackers frequently drop malicious db.php or object-cache.php files for stealth persistence.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_wordpress_dropins(string $scan_id): array {
        $findings = [];
        $wp_content_dir = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';

        $dropins = [
            'db.php'             => 'Custom Database Driver / Replication drop-in',
            'object-cache.php'   => 'External Object Cache drop-in',
            'advanced-cache.php' => 'Advanced Page Caching drop-in',
            'sunrise.php'        => 'Multisite Domain Mapping drop-in',
            'blog-deleted.php'   => 'Custom Blog Deleted drop-in',
            'blog-inactive.php'  => 'Custom Blog Inactive drop-in',
            'blog-suspended.php' => 'Custom Blog Suspended drop-in',
            'maintenance.php'    => 'Custom Maintenance Mode drop-in',
            'fatal-error-handler.php' => 'Custom Fatal Error Handler drop-in',
        ];

        foreach ($dropins as $file => $label) {
            $path = $wp_content_dir . '/' . $file;
            if (!file_exists($path)) {
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                continue;
            }

            $norm_path = wp_normalize_path($path);

            // Check for direct execution sinks, backdoors, or downloader stagers
            if (preg_match('/(?:eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|create_function\s*\(|\$_(?:POST|GET|REQUEST|COOKIE)\[[^\]]+\]\s*\()/i', $content, $m)) {
                $findings[] = new Finding([
                    'engine'      => 'integrity-fim',
                    'type'        => 'backdoored_dropin_file',
                    'severity'    => 'critical',
                    'confidence'  => 99,
                    'file_path'   => $norm_path,
                    'description' => "Malicious code execution sink detected in WordPress drop-in file '{$file}' ({$label}). Attackers use drop-ins for persistent, plugin-independent execution.",
                    'evidence'    => "Drop-in: {$file} | Match: {$m[0]}",
                ]);
            }

            // Flag unverified/unknown db.php drop-ins as high-risk if no official DB plugin or cluster is recognized
            if ($file === 'db.php' && !str_contains($content, 'HyperDB') && !str_contains($content, 'LudicrousDB') && !str_contains($content, 'Query_Monitor')) {
                // If it doesn't match standard known DB abstractions, flag for review
                if (preg_match('/(?:curl_exec|wp_remote_get|file_get_contents\s*\(\s*[\'"]https?:|preg_replace\s*\(.*?\/e[\'"])/i', $content, $m)) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'unverified_suspicious_db_dropin',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => $norm_path,
                        'description' => "Unrecognized custom database drop-in ('wp-content/db.php') contains network access or remote execution capabilities.",
                        'evidence'    => "File: {$file} | Match: {$m[0]}",
                    ]);
                }
            }
        }

        return $findings;
    }

    /**
     * Audit must-use plugins (wp-content/mu-plugins/).
     *
     * Scans for unauthorized, hidden, or backdoored MU-plugins.
     * MU-plugins execute automatically on every request and cannot be deactivated from the WP admin UI.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_must_use_plugins(string $scan_id): array {
        $findings = [];
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/mu-plugins' : ABSPATH . 'wp-content/mu-plugins');

        if (!is_dir($mu_dir)) {
            return $findings;
        }

        $files = @scandir($mu_dir);
        if (!is_array($files)) {
            return $findings;
        }

        foreach ($files as $f) {
            if ($f === '.' || $f === '..' || $f === 'index.php') {
                continue;
            }

            $path = $mu_dir . '/' . $f;
            if (!is_file($path)) {
                continue;
            }

            $norm_path = wp_normalize_path($path);
            $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));

            // MU-plugins should strictly only be PHP files
            if ($ext !== 'php') {
                $findings[] = new Finding([
                    'engine'      => 'integrity-fim',
                    'type'        => 'unexpected_mu_plugin_file_type',
                    'severity'    => 'medium',
                    'confidence'  => 85,
                    'file_path'   => $norm_path,
                    'description' => "Unexpected non-PHP file detected in mu-plugins directory ('{$f}'). Malware droppers often store staging payloads here.",
                ]);
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                continue;
            }

            // Detect hidden/obfuscated webshell or remote inclusion backdoors in MU-plugins
            if (preg_match('/(?:eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|\$_(?:POST|GET|REQUEST|COOKIE)\[[^\]]+\]\s*\(|include\s*\(?\s*[\'"][^\'"]+\.(?:ico|png|jpg|txt|dat))/i', $content, $m)) {
                $findings[] = new Finding([
                    'engine'      => 'integrity-fim',
                    'type'        => 'backdoored_mu_plugin',
                    'severity'    => 'critical',
                    'confidence'  => 99,
                    'file_path'   => $norm_path,
                    'description' => "Malicious backdoor pattern detected in Must-Use plugin '{$f}'. Attackers place persistent web rootkits in mu-plugins because they load automatically and bypass WP admin deactivation.",
                    'evidence'    => "File: {$f} | Match: {$m[0]}",
                ]);
            }
        }

        return $findings;
    }
}
