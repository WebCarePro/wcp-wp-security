<?php
namespace WcpScanner\SupplyChain;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * InstallRiskAdvisor
 *
 * Shift-Left Static Risk Analyzer for WordPress Plugins & Themes.
 * Inspects unpacked installation folders and installed extensions prior to execution,
 * scoring risk vectors (obfuscation, network C2, command execution, privilege escalation,
 * and persistence injection) to prevent supply-chain compromise.
 */
class InstallRiskAdvisor {

    const MAX_FILE_SIZE = 524288; // 512 KB per file limit for deep AST / regex evaluation
    const MAX_FILES_TO_SCAN = 400; // Cap scan depth for responsive UI & fast hook execution

    /**
     * Analyze an unpacked or installed directory.
     *
     * @param string $dir_path
     * @param string $slug
     * @return array
     */
    public static function analyze_directory(string $dir_path, string $slug = ''): array {
        $real_dir = realpath($dir_path);
        if (!$real_dir || !is_dir($real_dir)) {
            return [
                'success' => false,
                'slug'    => $slug ?: basename($dir_path),
                'score'   => 0,
                'level'   => 'clean',
                'message' => 'Specified directory does not exist or is not readable.',
                'findings'=> [],
                'stats'   => [],
            ];
        }

        $files = self::get_scannable_files($real_dir);
        $findings = [];
        $capabilities = [
            'has_network'      => false,
            'has_exec'         => false,
            'has_obfuscation'  => false,
            'has_persistence'   => false,
            'has_priv_escalation' => false,
            'contacted_domains'=> [],
            'contacted_ips'    => [],
        ];

        $files_scanned = 0;
        foreach ($files as $file) {
            if ($files_scanned >= self::MAX_FILES_TO_SCAN) {
                break;
            }
            $files_scanned++;

            $rel_file = str_replace(wp_normalize_path($real_dir), '', wp_normalize_path($file));
            $rel_file = ltrim($rel_file, '/');

            $file_findings = self::scan_file($file, $rel_file, $capabilities);
            if (!empty($file_findings)) {
                $findings = array_merge($findings, $file_findings);
            }
        }

        // Deduplicate contacted domains and IPs
        $capabilities['contacted_domains'] = array_values(array_unique($capabilities['contacted_domains']));
        $capabilities['contacted_ips'] = array_values(array_unique($capabilities['contacted_ips']));

        // Calculate aggregate score
        $score = 0;
        foreach ($findings as $f) {
            $score += $f['weight'];
        }
        $score = min(100, $score);

        // Determine Risk Level
        if ($score >= 80) {
            $level = 'critical';
        } elseif ($score >= 60) {
            $level = 'high';
        } elseif ($score >= 35) {
            $level = 'medium';
        } elseif ($score >= 15) {
            $level = 'low';
        } else {
            $level = 'clean';
        }

        return [
            'success'      => true,
            'slug'         => $slug ?: basename($real_dir),
            'dir_path'     => $real_dir,
            'score'        => $score,
            'level'        => $level,
            'findings'     => $findings,
            'capabilities' => $capabilities,
            'stats'        => [
                'total_files_found'   => count($files),
                'files_scanned'       => $files_scanned,
                'findings_count'      => count($findings),
                'scanned_at'          => current_time('mysql'),
            ],
        ];
    }

    /**
     * Analyze an installed plugin by its slug.
     *
     * @param string $plugin_slug (e.g. 'contact-form-7' or 'elementor')
     * @return array
     */
    public static function analyze_installed_plugin(string $plugin_slug): array {
        $plugin_slug = sanitize_file_name($plugin_slug);
        $plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;

        if (!is_dir($plugin_dir)) {
            // Check if slug is single-file plugin
            $single_file = WP_PLUGIN_DIR . '/' . $plugin_slug . '.php';
            if (file_exists($single_file)) {
                $temp_dir = dirname($single_file);
                return self::analyze_directory($temp_dir, $plugin_slug);
            }

            return [
                'success' => false,
                'slug'    => $plugin_slug,
                'score'   => 0,
                'level'   => 'clean',
                'message' => 'Plugin folder not found in WP_PLUGIN_DIR.',
                'findings'=> [],
                'stats'   => [],
            ];
        }

        return self::analyze_directory($plugin_dir, $plugin_slug);
    }

    /**
     * Collect scannable files (.php, .phtml, .js) recursively from directory.
     *
     * @param string $dir
     * @return array
     */
    private static function get_scannable_files(string $dir): array {
        $files = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS)
            );

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $ext = strtolower($item->getExtension());
                    if (in_array($ext, ['php', 'phtml', 'phar', 'inc'], true)) {
                        $files[] = $item->getPathname();
                    }
                }
            }
        } catch (\Exception $e) {
            // Fallback to glob
            $files = @glob($dir . '/*.php') ?: [];
        }

        return $files;
    }

    /**
     * Scan an individual file for risk signatures.
     *
     * @param string $path
     * @param string $rel_path
     * @param array &$capabilities
     * @return array
     */
    private static function scan_file(string $path, string $rel_path, array &$capabilities): array {
        if (@filesize($path) > self::MAX_FILE_SIZE) {
            return [];
        }

        $content = @file_get_contents($path);
        if ($content === false || empty($content)) {
            return [];
        }

        $findings = [];

        // 1. Obfuscation Patterns
        if (preg_match('/eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_obfuscation'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Obfuscation',
                'severity'    => 'critical',
                'weight'      => 45,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Nested Obfuscated Execution Primitive',
                'description' => 'Detected eval(base64_decode/gzinflate) construct commonly used to conceal backdoors.',
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 20), 80)),
            ];
        } elseif (preg_match('/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_obfuscation'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Obfuscation',
                'severity'    => 'high',
                'weight'      => 25,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Chr() ASCII Concatenation Chain',
                'description' => 'String obfuscation using sequential character encoding to bypass static keyword checks.',
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 60)),
            ];
        }

        // 2. Command Execution Primitives
        if (preg_match('/\b(system|shell_exec|exec|passthru|proc_open|popen)\s*\(\s*(?:\$_|\$[a-zA-Z0-9_]+)/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_exec'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Command Execution',
                'severity'    => 'critical',
                'weight'      => 35,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Dynamic OS Command Execution',
                'description' => sprintf('Invokes system shell primitive `%s()` with dynamic variable input.', $m[1][0]),
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 70)),
            ];
        }

        // 3. Raw IP Network Sockets & cURL to External IPs
        if (preg_match_all('/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/i', $content, $ip_matches)) {
            foreach ($ip_matches[1] as $ip) {
                if ($ip !== '127.0.0.1' && $ip !== '0.0.0.0') {
                    $capabilities['has_network'] = true;
                    $capabilities['contacted_ips'][] = $ip;
                    $findings[] = [
                        'category'    => 'Network Telemetry',
                        'severity'    => 'high',
                        'weight'      => 20,
                        'file'        => $rel_path,
                        'title'       => 'Hardcoded Public IP Network Request',
                        'description' => sprintf('Plugin establishes outbound HTTP connection directly to raw IP address "%s" instead of a verified domain name.', $ip),
                        'snippet'     => "IP: {$ip}",
                    ];
                }
            }
        }

        // 4. Persistence Injection (Writing to drop-ins or mu-plugins)
        if (preg_match('/(?:file_put_contents|copy|rename)\s*\([^)]*(?:mu-plugins|db\.php|object-cache\.php|auto_prepend_file|\.user\.ini)/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_persistence'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Persistence Injection',
                'severity'    => 'critical',
                'weight'      => 40,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Stealth Drop-In / Mu-Plugin File Injection',
                'description' => 'Logic attempts to programmatically write into mu-plugins, drop-ins, or INI prepend files.',
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 80)),
            ];
        }

        // 5. Rogue Admin Creation
        if (preg_match('/wp_create_user\s*\([^)]*\)/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            if (stripos($content, 'administrator') !== false) {
                $capabilities['has_priv_escalation'] = true;
                $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
                $findings[] = [
                    'category'    => 'Privilege Escalation',
                    'severity'    => 'critical',
                    'weight'      => 35,
                    'file'        => $rel_path,
                    'line'        => $line,
                    'title'       => 'Programmatic Administrator Account Creation',
                    'description' => 'Plugin creates a new WordPress user account with administrative privileges.',
                    'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 80)),
                ];
            }
        }

        // Extract contacted external domains
        if (preg_match_all('/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\/\'"]/i', $content, $domain_matches)) {
            foreach ($domain_matches[1] as $dom) {
                $dom = strtolower($dom);
                if (
                    $dom !== 'wordpress.org' &&
                    $dom !== 'api.wordpress.org' &&
                    $dom !== 'github.com' &&
                    $dom !== 'w.org' &&
                    $dom !== 'schema.org' &&
                    $dom !== 'www.w3.org' &&
                    $dom !== 'localhost'
                ) {
                    $capabilities['contacted_domains'][] = $dom;
                }
            }
        }

        return $findings;
    }
}
