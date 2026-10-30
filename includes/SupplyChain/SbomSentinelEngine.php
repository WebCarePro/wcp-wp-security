<?php
namespace WcpScanner\SupplyChain;

use WcpScanner\Quarantine\QuarantineManager;
use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SbomSentinelEngine
 *
 * Software Bill of Materials (SBOM) Sentinel & Runtime Anchor Monitor.
 * Cryptographically tracks standard and custom drop-in PHP files, must-use plugins,
 * autoloaders, and PHP INI directives (auto_prepend_file / auto_append_file) to detect
 * zero-day stealth persistence and supply-chain contamination.
 */
class SbomSentinelEngine {

    const OPTION_BASELINE = 'wcpscan_sbom_baseline';
    const OPTION_LOGS     = 'wcpscan_sbom_drift_logs';

    /**
     * Recognized standard WordPress drop-ins in WP_CONTENT_DIR.
     */
    const STANDARD_DROPINS = [
        'advanced-cache.php'      => 'Advanced caching engine (Drop-in)',
        'object-cache.php'        => 'External object cache backend (Drop-in)',
        'db.php'                  => 'Custom database class replacement (Drop-in)',
        'db-error.php'            => 'Custom database connection error template',
        'install.php'             => 'Custom installation routine override',
        'maintenance.php'         => 'Custom maintenance mode display',
        'sunrise.php'             => 'Multisite domain mapping and routing loader',
        'blog-deleted.php'        => 'Multisite blog deleted notice template',
        'blog-inactive.php'       => 'Multisite blog inactive notice template',
        'blog-suspended.php'      => 'Multisite blog suspended notice template',
        'php-error.php'           => 'Custom PHP error display handler',
        'fatal-error-handler.php' => 'Fatal error handler drop-in'
    ];

    /**
     * Get complete real-time SBOM inventory of all runtime anchors.
     *
     * @return array
     */
    public static function get_inventory(): array {
        $inventory = [
            'dropins'        => self::scan_dropins(),
            'mu_plugins'     => self::scan_mu_plugins(),
            'ini_directives' => self::scan_ini_directives(),
            'autoloaders'    => self::scan_autoloaders(),
            'generated_at'   => current_time('mysql'),
            'timestamp'      => time(),
        ];

        // Calculate summary counts
        $total_items = count($inventory['dropins']) + count($inventory['mu_plugins']) + count($inventory['ini_directives']) + count($inventory['autoloaders']);
        $anomalies = 0;

        foreach ($inventory['dropins'] as $item) {
            if ($item['risk_level'] === 'high' || $item['risk_level'] === 'critical' || $item['is_custom']) {
                $anomalies++;
            }
        }
        foreach ($inventory['mu_plugins'] as $item) {
            if ($item['risk_level'] === 'high' || $item['risk_level'] === 'critical') {
                $anomalies++;
            }
        }
        foreach ($inventory['ini_directives'] as $item) {
            if ($item['risk_level'] === 'high' || $item['risk_level'] === 'critical') {
                $anomalies++;
            }
        }

        $inventory['summary'] = [
            'total_anchors' => $total_items,
            'active_dropins' => count(array_filter($inventory['dropins'], fn($d) => $d['exists'])),
            'mu_plugins_count' => count($inventory['mu_plugins']),
            'ini_injections_count' => count(array_filter($inventory['ini_directives'], fn($i) => $i['has_prepend'] || $i['has_append'])),
            'anomalies_count' => $anomalies,
        ];

        return $inventory;
    }

    /**
     * Scan standard and rogue drop-in files in WP_CONTENT_DIR.
     *
     * @return array
     */
    public static function scan_dropins(): array {
        $content_dir = wp_normalize_path(WP_CONTENT_DIR);
        $items = [];

        // 1. Check all standard drop-ins
        foreach (self::STANDARD_DROPINS as $file => $description) {
            $path = $content_dir . '/' . $file;
            $exists = file_exists($path);

            $entry = [
                'id'          => 'dropin:' . $file,
                'name'        => $file,
                'type'        => 'dropin',
                'description' => $description,
                'is_standard' => true,
                'is_custom'   => false,
                'path'        => $path,
                'rel_path'    => 'wp-content/' . $file,
                'exists'      => $exists,
                'sha256'      => $exists ? hash_file('sha256', $path) : null,
                'size'        => $exists ? filesize($path) : 0,
                'size_human'  => $exists ? size_format(filesize($path), 2) : '0 B',
                'modified_at' => $exists ? filemtime($path) : null,
                'perms'       => $exists ? substr(sprintf('%o', fileperms($path)), -4) : null,
                'risk_level'  => 'none',
                'reasons'     => [],
            ];

            if ($exists) {
                // Static heuristic check on drop-in content
                $content = @file_get_contents($path, false, null, 0, 65536);
                if ($content !== false) {
                    if (preg_match('/(eval\s*\(|base64_decode|gzinflate|str_rot13|system\s*\(|shell_exec|assert\s*\()/i', $content)) {
                        $entry['risk_level'] = 'critical';
                        $entry['reasons'][] = 'Obfuscation or execution primitives detected inside drop-in';
                    } elseif (stripos($content, 'curl_exec') !== false || stripos($content, 'fsockopen') !== false) {
                        $entry['risk_level'] = 'medium';
                        $entry['reasons'][] = 'Network socket capabilities found in drop-in file';
                    }
                }
            }

            $items[] = $entry;
        }

        // 2. Discover non-standard rogue PHP files directly in WP_CONTENT_DIR
        $php_files = @glob($content_dir . '/*.php');
        if (is_array($php_files)) {
            foreach ($php_files as $php_file) {
                $filename = basename($php_file);
                if (isset(self::STANDARD_DROPINS[$filename]) || $filename === 'index.php') {
                    continue;
                }

                $sha = hash_file('sha256', $php_file);
                $content = @file_get_contents($php_file, false, null, 0, 65536);
                $risk = 'high';
                $reasons = ['Non-standard rogue PHP file situated directly in wp-content/'];

                if ($content !== false && preg_match('/(eval\s*\(|base64_decode|gzinflate|system\s*\(|shell_exec|assert\s*\()/i', $content)) {
                    $risk = 'critical';
                    $reasons[] = 'Confirmed obfuscated execution payload inside rogue file';
                }

                $items[] = [
                    'id'          => 'custom_dropin:' . $filename,
                    'name'        => $filename,
                    'type'        => 'custom_dropin',
                    'description' => 'Unrecognized arbitrary PHP file in wp-content/',
                    'is_standard' => false,
                    'is_custom'   => true,
                    'path'        => wp_normalize_path($php_file),
                    'rel_path'    => 'wp-content/' . $filename,
                    'exists'      => true,
                    'sha256'      => $sha,
                    'size'        => filesize($php_file),
                    'size_human'  => size_format(filesize($php_file), 2),
                    'modified_at' => filemtime($php_file),
                    'perms'       => substr(sprintf('%o', fileperms($php_file)), -4),
                    'risk_level'  => $risk,
                    'reasons'     => $reasons,
                ];
            }
        }

        return $items;
    }

    /**
     * Scan must-use plugins in WPMU_PLUGIN_DIR.
     *
     * @return array
     */
    public static function scan_mu_plugins(): array {
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? wp_normalize_path(WPMU_PLUGIN_DIR) : wp_normalize_path(WP_CONTENT_DIR . '/mu-plugins');
        if (!is_dir($mu_dir)) {
            return [];
        }

        $items = [];
        $files = @glob($mu_dir . '/*.php');

        if (is_array($files)) {
            foreach ($files as $file) {
                $filename = basename($file);
                $sha = hash_file('sha256', $file);
                $content = @file_get_contents($file, false, null, 0, 65536);
                $risk = 'none';
                $reasons = [];

                if ($content !== false) {
                    if (preg_match('/(eval\s*\(|base64_decode|gzinflate|str_rot13|system\s*\(|shell_exec)/i', $content)) {
                        $risk = 'critical';
                        $reasons[] = 'Obfuscated execution functions identified in must-use plugin';
                    } elseif (stripos($content, 'curl_exec') !== false || stripos($content, 'fsockopen') !== false) {
                        $risk = 'low';
                        $reasons[] = 'Network requests found in must-use plugin';
                    }
                }

                $items[] = [
                    'id'          => 'mu:' . $filename,
                    'name'        => $filename,
                    'type'        => 'mu-plugin',
                    'description' => 'Must-Use Plugin (Executes before all standard plugins)',
                    'path'        => wp_normalize_path($file),
                    'rel_path'    => 'wp-content/mu-plugins/' . $filename,
                    'exists'      => true,
                    'sha256'      => $sha,
                    'size'        => filesize($file),
                    'size_human'  => size_format(filesize($file), 2),
                    'modified_at' => filemtime($file),
                    'perms'       => substr(sprintf('%o', fileperms($file)), -4),
                    'risk_level'  => $risk,
                    'reasons'     => $reasons,
                ];
            }
        }

        return $items;
    }

    /**
     * Verify whether an auto_prepend_file target is an authentic, recognized security tool
     * (e.g. Wordfence WAF, WCP Micro-WAF, NinjaFirewall) or matches the calibrated baseline.
     *
     * @param string $target_path Absolute or relative path to preloaded file
     * @return array Verification payload
     */
    public static function verify_prepend_target(string $target_path): array {
        $target_path = trim($target_path, "'\" \t\n\r\0\x0B");
        if (empty($target_path)) {
            return [
                'is_recognized' => false,
                'is_trusted'    => false,
                'provider'      => '',
                'label'         => '',
                'risk_level'    => 'none',
                'description'   => '',
            ];
        }

        $norm = wp_normalize_path($target_path);
        $basename = basename($norm);
        $exists = file_exists($target_path);
        $sha256 = $exists ? hash_file('sha256', $target_path) : null;

        // 1. Check calibrated baseline
        $baseline = get_option(self::OPTION_BASELINE, null);
        if (!empty($baseline['ini_prepend'])) {
            $base_prepend = trim($baseline['ini_prepend'], "'\" \t\n\r\0\x0B");
            if (wp_normalize_path($base_prepend) === $norm) {
                $base_hashes = $baseline['hashes'] ?? [];
                $hash_match = true;
                if ($sha256 && !empty($base_hashes['ini_prepend:' . $basename]['sha256'])) {
                    $hash_match = ($base_hashes['ini_prepend:' . $basename]['sha256'] === $sha256);
                }

                if ($hash_match) {
                    return [
                        'is_recognized' => true,
                        'is_trusted'    => true,
                        'provider'      => 'Calibrated Baseline',
                        'label'         => 'Calibrated Trusted Preload',
                        'risk_level'    => 'none',
                        'description'   => sprintf(
                            /* translators: %s: target file name */
                            __('Preload file "%s" matches verified cryptographic administrator baseline.', 'wcp-security-scanner'),
                            $basename
                        ),
                        'sha256'        => $sha256,
                    ];
                }
            }
        }

        // 2. WCP Micro-WAF Preload
        if ($basename === 'micro-waf-compiled.php' || str_contains($norm, 'wcp-security-scanner') || str_contains($norm, 'wcp-micro-waf.php')) {
            return [
                'is_recognized' => true,
                'is_trusted'    => true,
                'provider'      => 'WCP Security Scanner',
                'label'         => 'Verified WCP Micro-WAF Preload',
                'risk_level'    => 'none',
                'description'   => __('Official WebCare Pro Micro-WAF pre-boot firewall engine.', 'wcp-security-scanner'),
                'sha256'        => $sha256,
            ];
        }

        // 3. Wordfence Web Application Firewall (wordfence-waf.php)
        if ($basename === 'wordfence-waf.php' || str_contains($norm, 'wordfence-waf.php')) {
            $is_authentic_wf = false;
            $detail = '';

            if ($exists) {
                $content = @file_get_contents($target_path, false, null, 0, 16384);
                if ($content !== false && (strpos($content, 'WFWAF_LOG_PATH') !== false || strpos($content, 'wordfence/waf/bootstrap.php') !== false)) {
                    $is_authentic_wf = true;
                    $detail = __('Authentic Wordfence WAF bootstrap directives verified.', 'wcp-security-scanner');
                }
            }

            // Also check if wordfence plugin is installed/active
            $active_plugins = (array) get_option('active_plugins', []);
            $active_str = strtolower(implode(' ', $active_plugins));
            $is_wf_active = strpos($active_str, 'wordfence.php') !== false;

            if ($is_authentic_wf || $is_wf_active) {
                return [
                    'is_recognized' => true,
                    'is_trusted'    => true,
                    'provider'      => 'Wordfence WAF',
                    'label'         => 'Verified Security WAF (Wordfence)',
                    'risk_level'    => 'none',
                    'description'   => $detail ?: __('Official Wordfence Web Application Firewall preload active.', 'wcp-security-scanner'),
                    'sha256'        => $sha256,
                ];
            }

            return [
                'is_recognized' => true,
                'is_trusted'    => false,
                'provider'      => 'Wordfence WAF',
                'label'         => 'Unverified Wordfence Script',
                'risk_level'    => 'medium',
                'description'   => __('Target is named wordfence-waf.php but Wordfence plugin was not detected or contents differed from official bootstrap.', 'wcp-security-scanner'),
                'sha256'        => $sha256,
            ];
        }

        // 4. NinjaFirewall
        if ($basename === 'ninjafirewall.php' || str_contains($norm, 'ninjafirewall')) {
            return [
                'is_recognized' => true,
                'is_trusted'    => true,
                'provider'      => 'NinjaFirewall',
                'label'         => 'Verified Security WAF (NinjaFirewall)',
                'risk_level'    => 'none',
                'description'   => __('Official NinjaFirewall PHP pre-boot engine active.', 'wcp-security-scanner'),
                'sha256'        => $sha256,
            ];
        }

        // 5. Unknown target file
        return [
            'is_recognized' => false,
            'is_trusted'    => false,
            'provider'      => '',
            'label'         => '',
            'risk_level'    => $exists ? 'critical' : 'high',
            'description'   => $exists
                ? sprintf(
                    /* translators: %s: target file path */
                    __('Unrecognized PHP preload file active: "%s". Runs before any WordPress core code boots.', 'wcp-security-scanner'),
                    $target_path
                )
                : sprintf(
                    /* translators: %s: target file path */
                    __('Preload file is configured in INI directives but target file does not exist on disk: "%s".', 'wcp-security-scanner'),
                    $target_path
                ),
            'sha256'        => $sha256,
        ];
    }

    /**
     * Scan PHP INI directives and configuration files for auto_prepend_file or auto_append_file.
     *
     * @return array
     */
    public static function scan_ini_directives(): array {
        $items = [];

        // 1. Runtime INI directives
        $prepend = ini_get('auto_prepend_file');
        $append  = ini_get('auto_append_file');

        $runtime_entry = [
            'id'            => 'ini:runtime',
            'name'          => 'PHP Runtime Directives',
            'type'          => 'ini_directive',
            'description'   => 'Live PHP interpreter directives active for the current request process',
            'has_prepend'   => !empty($prepend),
            'prepend_val'   => $prepend ?: 'None',
            'has_append'    => !empty($append),
            'append_val'    => $append ?: 'None',
            'risk_level'    => 'none',
            'is_recognized' => false,
            'is_trusted'    => false,
            'provider'      => '',
            'label'         => '',
            'reasons'       => [],
        ];

        if (!empty($prepend)) {
            $verification = self::verify_prepend_target($prepend);
            $runtime_entry['is_recognized'] = $verification['is_recognized'];
            $runtime_entry['is_trusted']    = $verification['is_trusted'];
            $runtime_entry['provider']      = $verification['provider'];
            $runtime_entry['label']         = $verification['label'] ?? '';

            if (file_exists($prepend)) {
                $runtime_entry['prepend_sha'] = hash_file('sha256', $prepend);
            }

            if ($verification['is_trusted']) {
                $runtime_entry['risk_level'] = 'none';
                $runtime_entry['reasons'][] = $verification['description'];
            } else {
                $runtime_entry['risk_level'] = $verification['risk_level'] ?: 'high';
                $runtime_entry['reasons'][] = $verification['description'] ?: ('Runtime auto_prepend_file active: ' . esc_html($prepend));
            }
        }

        if (!empty($append)) {
            $runtime_entry['risk_level'] = 'critical';
            $runtime_entry['reasons'][] = 'Runtime auto_append_file active: ' . esc_html($append);
        }

        $items[] = $runtime_entry;

        // 2. Check local configuration files (.user.ini, php.ini, .htaccess)
        $root = wp_normalize_path(ABSPATH);
        $config_files = [
            '.user.ini' => $root . '.user.ini',
            'php.ini'   => $root . 'php.ini',
            '.htaccess' => $root . '.htaccess',
        ];

        foreach ($config_files as $cfg_name => $cfg_path) {
            if (!file_exists($cfg_path)) {
                continue;
            }

            $content = @file_get_contents($cfg_path, false, null, 0, 32768);
            if ($content === false) {
                continue;
            }

            $has_prepend = (bool) preg_match('/(?:auto_prepend_file|php_value\s+auto_prepend_file)\s*=\s*["\']?([^"\';\r\n]+)/i', $content, $m_prep);
            $has_append  = (bool) preg_match('/(?:auto_append_file|php_value\s+auto_append_file)\s*=\s*["\']?([^"\';\r\n]+)/i', $content, $m_app);

            if ($has_prepend || $has_append) {
                $reasons = [];
                $prepend_val = $has_prepend ? trim($m_prep[1] ?? '') : 'None';
                $append_val  = $has_append ? trim($m_app[1] ?? '') : 'None';
                $is_recognized = false;
                $is_trusted    = false;
                $provider      = '';
                $label         = '';
                $file_risk     = 'critical';

                if ($has_prepend && $prepend_val !== 'None') {
                    $verification = self::verify_prepend_target($prepend_val);
                    $is_recognized = $verification['is_recognized'];
                    $is_trusted    = $verification['is_trusted'];
                    $provider      = $verification['provider'];
                    $label         = $verification['label'] ?? '';

                    if ($is_trusted && !$has_append) {
                        $file_risk = 'none';
                        $reasons[] = sprintf('Official auto_prepend_file configuration verified: "%s" (%s)', $prepend_val, $verification['provider']);
                    } else {
                        $file_risk = $verification['risk_level'] ?: 'critical';
                        $reasons[] = sprintf('Found auto_prepend_file configuration pointing to "%s"', $prepend_val);
                    }
                }

                if ($has_append) {
                    $file_risk = 'critical';
                    $reasons[] = sprintf('Found auto_append_file configuration pointing to "%s"', $append_val);
                }

                $items[] = [
                    'id'            => 'ini_file:' . $cfg_name,
                    'name'          => $cfg_name . ' Directive',
                    'type'          => 'ini_file',
                    'description'   => 'Server configuration file containing PHP file inclusion overrides',
                    'path'          => $cfg_path,
                    'rel_path'      => $cfg_name,
                    'has_prepend'   => $has_prepend,
                    'prepend_val'   => $prepend_val,
                    'has_append'    => $has_append,
                    'append_val'    => $append_val,
                    'risk_level'    => $file_risk,
                    'is_recognized' => $is_recognized,
                    'is_trusted'    => $is_trusted,
                    'provider'      => $provider,
                    'label'         => $label,
                    'reasons'       => $reasons,
                ];
            }
        }

        return $items;
    }

    /**
     * Scan composer and runtime autoloaders.
     *
     * @return array
     */
    public static function scan_autoloaders(): array {
        $items = [];
        $candidates = [
            'root_vendor' => wp_normalize_path(ABSPATH . 'vendor/autoload.php'),
            'content_vendor' => wp_normalize_path(WP_CONTENT_DIR . '/vendor/autoload.php'),
        ];

        foreach ($candidates as $key => $path) {
            $exists = file_exists($path);
            if ($exists) {
                $items[] = [
                    'id'          => 'autoloader:' . $key,
                    'name'        => basename(dirname($path)) . '/' . basename($path),
                    'type'        => 'autoloader',
                    'description' => 'Composer dependency autoloader',
                    'path'        => $path,
                    'rel_path'    => str_replace(wp_normalize_path(ABSPATH), '', $path),
                    'exists'      => true,
                    'sha256'      => hash_file('sha256', $path),
                    'size'        => filesize($path),
                    'size_human'  => size_format(filesize($path), 2),
                    'modified_at' => filemtime($path),
                    'risk_level'  => 'low',
                    'reasons'     => ['Global composer autoloader present outside plugins'],
                ];
            }
        }

        return $items;
    }

    /**
     * Calibrate clean cryptographic baseline of current SBOM inventory.
     *
     * @return array
     */
    public static function calibrate_baseline(): array {
        $inventory = self::get_inventory();
        $user = wp_get_current_user();
        $calibrated_by = ($user && $user->exists()) ? $user->user_login : 'admin';

        $hashes = [];
        foreach ($inventory['dropins'] as $item) {
            if ($item['exists'] && !empty($item['sha256'])) {
                $hashes[$item['id']] = [
                    'sha256'      => $item['sha256'],
                    'size'        => $item['size'],
                    'modified_at' => $item['modified_at'],
                    'rel_path'    => $item['rel_path'],
                    'type'        => $item['type']
                ];
            }
        }
        foreach ($inventory['mu_plugins'] as $item) {
            if ($item['exists'] && !empty($item['sha256'])) {
                $hashes[$item['id']] = [
                    'sha256'      => $item['sha256'],
                    'size'        => $item['size'],
                    'modified_at' => $item['modified_at'],
                    'rel_path'    => $item['rel_path'],
                    'type'        => $item['type']
                ];
            }
        }

        $ini_prepend = ini_get('auto_prepend_file');
        if (!empty($ini_prepend) && file_exists($ini_prepend)) {
            $base_name = basename($ini_prepend);
            $hashes['ini_prepend:' . $base_name] = [
                'sha256'      => hash_file('sha256', $ini_prepend),
                'size'        => filesize($ini_prepend),
                'modified_at' => filemtime($ini_prepend),
                'rel_path'    => $ini_prepend,
                'type'        => 'ini_directive',
            ];
        }

        $baseline = [
            'calibrated_at'   => current_time('mysql'),
            'timestamp'       => time(),
            'calibrated_by'   => $calibrated_by,
            'total_anchors'   => count($hashes),
            'hashes'          => $hashes,
            'ini_prepend'     => $ini_prepend,
            'ini_append'      => ini_get('auto_append_file'),
        ];

        update_option(self::OPTION_BASELINE, $baseline);

        AuditLogger::log(
            'sbom_baseline_calibrated',
            sprintf('Cryptographic SBOM baseline calibrated with %d runtime anchors by %s.', count($hashes), $calibrated_by)
        );

        return [
            'success'       => true,
            'message'       => 'SBOM baseline calibrated successfully.',
            'calibrated_at' => $baseline['calibrated_at'],
            'anchors_count' => count($hashes),
        ];
    }

    /**
     * Compare current SBOM inventory against stored baseline to identify drift.
     *
     * @return array
     */
    public static function check_drift(): array {
        $baseline = get_option(self::OPTION_BASELINE, null);
        $inventory = self::get_inventory();

        if (empty($baseline) || !isset($baseline['hashes'])) {
            return [
                'has_baseline' => false,
                'is_drifted'   => false,
                'drift_count'  => 0,
                'added'        => [],
                'modified'     => [],
                'removed'      => [],
                'message'      => 'No baseline calibrated yet. Click "Calibrate Baseline" to create your cryptographic anchor profile.',
                'inventory'    => $inventory,
            ];
        }

        $stored_hashes = $baseline['hashes'];
        $added = [];
        $modified = [];
        $removed = [];

        // Check active dropins and mu-plugins against baseline
        $all_current = array_merge($inventory['dropins'], $inventory['mu_plugins']);
        $seen_ids = [];

        foreach ($all_current as $item) {
            if (!$item['exists']) {
                continue;
            }
            $id = $item['id'];
            $seen_ids[$id] = true;

            if (!isset($stored_hashes[$id])) {
                // Newly added drop-in or mu-plugin!
                $added[] = [
                    'id'          => $item['id'],
                    'name'        => $item['name'],
                    'type'        => $item['type'],
                    'rel_path'    => $item['rel_path'],
                    'sha256'      => $item['sha256'],
                    'risk_level'  => $item['risk_level'] === 'none' ? 'high' : $item['risk_level'],
                    'message'     => 'New runtime anchor detected that was not present when baseline was calibrated.',
                ];
            } elseif ($stored_hashes[$id]['sha256'] !== $item['sha256']) {
                // File modified!
                $modified[] = [
                    'id'          => $item['id'],
                    'name'        => $item['name'],
                    'type'        => $item['type'],
                    'rel_path'    => $item['rel_path'],
                    'current_sha' => $item['sha256'],
                    'baseline_sha'=> $stored_hashes[$id]['sha256'],
                    'risk_level'  => 'critical',
                    'message'     => 'Cryptographic hash mismatch. Runtime anchor file was modified after baseline calibration.',
                ];
            }
        }

        // Check for items that were in baseline but deleted
        foreach ($stored_hashes as $id => $data) {
            if (!isset($seen_ids[$id])) {
                $removed[] = [
                    'id'       => $id,
                    'rel_path' => $data['rel_path'],
                    'type'     => $data['type'],
                    'message'  => 'Runtime anchor file was removed from disk.',
                ];
            }
        }

        $drift_count = count($added) + count($modified) + count($removed);

        if ($drift_count > 0 && class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            $critical_drifts = array_merge($modified, array_filter($added, fn($a) => $a['risk_level'] === 'critical' || $a['type'] === 'dropin'));
            if (!empty($critical_drifts)) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('supply_chain_anchor_tampered', [
                    'severity' => 'critical',
                    /* translators: %d: count of tampered runtime anchors */
                    'message'  => sprintf(__('Supply-Chain Alert: %d runtime drop-in anchor(s) (object-cache, db.php, or mu-plugins) have been tampered or added.', 'wcp-security-scanner'), count($critical_drifts)),
                    'details'  => [
                        'Drift Count'   => $drift_count,
                        'Tampered Items'=> implode(', ', array_slice(array_column($critical_drifts, 'rel_path'), 0, 3)),
                    ],
                ]);
            }
        }

        return [
            'has_baseline'  => true,
            'calibrated_at' => $baseline['calibrated_at'],
            'calibrated_by' => $baseline['calibrated_by'] ?? 'admin',
            'is_drifted'    => $drift_count > 0,
            'drift_count'   => $drift_count,
            'added'         => $added,
            'modified'      => $modified,
            'removed'       => $removed,
            'inventory'     => $inventory,
        ];
    }

    /**
     * Quarantine a rogue drop-in or must-use plugin to the WCP Vault.
     *
     * @param string $item_id (e.g. "dropin:db.php" or "custom_dropin:shell.php")
     * @return array
     */
    public static function isolate_anchor(string $item_id): array {
        $inventory = self::get_inventory();
        $target = null;

        $all_items = array_merge($inventory['dropins'], $inventory['mu_plugins']);
        foreach ($all_items as $item) {
            if ($item['id'] === $item_id) {
                $target = $item;
                break;
            }
        }

        if (!$target || empty($target['path']) || !file_exists($target['path'])) {
            return [
                'success' => false,
                'message' => 'Target anchor file does not exist or cannot be identified.',
            ];
        }

        $path = $target['path'];

        // Safety check: Don't isolate index.php
        if (basename($path) === 'index.php') {
            return [
                'success' => false,
                'message' => 'Safety restriction: Cannot quarantine core placeholder index.php.',
            ];
        }

        $quarantine_mgr = new QuarantineManager();
        $result = $quarantine_mgr->quarantine_file($path);

        if ($result['success']) {
            AuditLogger::log(
                'sbom_anchor_quarantined',
                sprintf('Quarantined runtime anchor "%s" (%s) to WCP Vault.', basename($path), $target['rel_path'])
            );
        }

        return $result;
    }
}
