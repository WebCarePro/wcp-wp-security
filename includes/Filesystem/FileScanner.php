<?php
namespace WcpScanner\Filesystem;

use WcpScanner\Findings\Finding;
use WcpScanner\Malware\HeuristicEngine;

if (!defined('ABSPATH')) {
    exit;
}

class FileScanner {
    
    private $symlink_scanner;
    private $permission_scanner;
    private $hasher;
    private $heuristic_engine;
    private $js_scanner;

    public function __construct() {
        $this->symlink_scanner = new SymlinkScanner();
        $this->permission_scanner = new PermissionScanner();
        $this->hasher = new FileHasher();
        $this->heuristic_engine = new HeuristicEngine();
        $this->js_scanner = new \WcpScanner\Malware\JavaScriptSecurityScanner();
    }

    /**
     * Scan a single file for anomalies and metadata.
     *
     * @param string $file_path
     * @param string $scan_id
     * @return Finding[] Array of findings
     */
    public function scan_file($file_path, $scan_id) {
        $findings = [];
        
        if (!file_exists($file_path)) {
            return $findings; // Might have been deleted mid-scan
        }

        // Self-Exclusion: Do not scan the scanner's own plugin files or tests
        $norm_path = str_replace('\\', '/', $file_path);
        if (strpos($norm_path, '/plugins/wcp-security-scanner/') !== false || strpos($norm_path, '/tests/') !== false) {
            return $findings;
        }

        // Respect user-defined excluded paths / patterns
        if (class_exists('\\WcpScanner\\System\\SettingsManager') && \WcpScanner\System\SettingsManager::is_path_excluded($norm_path)) {
            return $findings;
        }

        // Uploads Cryptographic Hash Whitelist Check (0 database queries via local JSON registry):
        // If file resides in wp-content/uploads/ and matches an authentic verified file hash, skip heuristics and threat scans.
        if (strpos($norm_path, '/wp-content/uploads/') !== false) {
            if (class_exists('\\WcpScanner\\Findings\\WhitelistManager') && \WcpScanner\Findings\WhitelistManager::is_uploads_hash_whitelisted($file_path)) {
                return $findings;
            }
        }

        $metadata = new FileMetadata($file_path);

        // 1. Permission check
        $perm_finding = $this->permission_scanner->scan($file_path, $metadata, $scan_id);
        if ($perm_finding) {
            $findings[] = $perm_finding;
        }

        // 2. Symlink check
        $symlink_finding = $this->symlink_scanner->scan($file_path, $scan_id);
        if ($symlink_finding) {
            $findings[] = $symlink_finding;
        }

        // 3. Executable in uploads check
        $norm_path = str_replace('\\', '/', $file_path);
        if (strpos($norm_path, '/wp-content/uploads/') !== false) {
            // Exclude plugin's internal secure storage (quarantine, logs, backups, fim-vault, etc.) and user exclusions
            if (!preg_match('#/(wcp-security-scanner|wcp-scanner-quarantine|wcp-vault|wcp-waf|wcp-quarantine|node_modules|\.git|updraft|wfcache)/#i', $norm_path) && !\WcpScanner\System\SettingsManager::is_path_excluded($norm_path)) {
                $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                $basename = strtolower(basename($file_path));
                if (in_array($ext, ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar'], true)) {
                    // Check if harmless WordPress directory listing prevention placeholder
                    if (($basename === 'index.php' || $basename === 'index.html' || $basename === 'index.htm') && \WcpScanner\System\SettingsManager::is_safe_directory_index($file_path)) {
                        // Harmless directory silence placeholder, ignore
                    } elseif (\WcpScanner\System\SettingsManager::is_legitimate_uploads_cache_file($file_path)) {
                        // Legitimate verified plugin cache file (e.g. MailPoet Twig template cache) with 0 malware
                    } else {
                        $findings[] = new Finding([
                            'engine'      => 'filesystem',
                            'type'        => 'executable_in_uploads',
                            'severity'    => 'high',
                            'confidence'  => 80,
                            'file_path'   => $file_path,
                            'description' => "Executable PHP file found in uploads directory.",
                            'evidence'    => "Extension: $ext in /uploads/"
                        ]);
                    }
                }
            }
        }

        // 4. PHP Heuristic Malware Scan
        try {
            $malware_findings = $this->heuristic_engine->scan_file($file_path, $scan_id);
            if (!empty($malware_findings)) {
                $findings = array_merge($findings, $malware_findings);
            }
        } catch (\Throwable $e) {
            // Guard against individual file heuristic failure
        }

        // 5. Client-Side JavaScript Threat Scan (Magecart, Form Skimmers, Miners)
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        if ($ext === 'js') {
            $js_findings = $this->js_scanner->scan_file($file_path, $scan_id);
            if (!empty($js_findings)) {
                $findings = array_merge($findings, $js_findings);
            }
        }

        // 6. Strict Official Integrity & Rogue/Unknown File Detection
        // Strictly verify every official core, plugin, and theme file against official WordPress.org checksums,
        // and strictly detect modified files or unknown rogue files injected into core, root, or official components.
        try {
            $integrity_findings = $this->verify_official_integrity($file_path, $scan_id);
            if (!empty($integrity_findings)) {
                $findings = array_merge($findings, $integrity_findings);
            }
        } catch (\Throwable $e) {
            // Guard against individual file integrity verification error
        }

        return $findings;
    }

    /**
     * Strictly verify files against official WordPress.org release manifests (Core, Plugins, Themes)
     * and strictly detect modified files or unknown rogue files inside core, root, or official components.
     *
     * @param string $file_path
     * @param string $scan_id
     * @return Finding[]
     */
    private function verify_official_integrity($file_path, $scan_id) {
        $findings = [];

        // 1. Core & Root Integrity Verification
        $core_check = \WcpScanner\Integrity\ChecksumProvider::verify_core_file($file_path);
        if ($core_check['status'] === 'modified') {
            $findings[] = new Finding([
                'engine'      => 'integrity-core',
                'type'        => 'modified_core_file',
                'severity'    => 'high',
                'confidence'  => 99,
                'file_path'   => wp_normalize_path($file_path),
                'description' => "WordPress core file differs from the official checksum: {$core_check['rel_file']}",
                'evidence'    => "Expected: {$core_check['expected']}, Actual: {$core_check['actual']}"
            ]);
        } elseif ($core_check['status'] === 'unknown') {
            $basename_lower = strtolower(basename($file_path));
            $norm_path = str_replace('\\', '/', $file_path);

            // Exclude benign ACME / SSL Let's Encrypt validation files & protective .htaccess files
            if (strpos($norm_path, '/.well-known/') !== false) {
                return $findings;
            }
            if ($basename_lower === '.htaccess') {
                if (class_exists('\\WcpScanner\\System\\SettingsManager') && \WcpScanner\System\SettingsManager::is_safe_protective_htaccess($file_path)) {
                    return $findings;
                }
            }

            // Exclude verified Wordfence WAF preload bootstrap (wordfence-waf.php)
            if ($basename_lower === 'wordfence-waf.php') {
                $content = @file_get_contents($file_path, false, null, 0, 8192);
                if ($content !== false && (strpos($content, 'WFWAF_LOG_PATH') !== false || strpos($content, 'wordfence/waf/bootstrap.php') !== false || strpos($content, 'wordfence') !== false)) {
                    return $findings;
                }
            }

            $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);
            $findings[] = new Finding([
                'engine'      => 'integrity-core',
                'type'        => 'unknown_core_file',
                'severity'    => $is_executable ? 'high' : 'medium',
                'confidence'  => 95,
                'file_path'   => wp_normalize_path($file_path),
                'description' => "Unrecognized/unknown file found inside WordPress core/root: {$core_check['rel_file']}",
                'evidence'    => "File '{$core_check['rel_file']}' is not part of the official WordPress release manifest."
            ]);
        }

        // 2. Official Plugins Integrity Verification
        $plugin_check = \WcpScanner\Integrity\ChecksumProvider::verify_plugin_file($file_path);
        if ($plugin_check['status'] === 'modified') {
            $findings[] = new Finding([
                'engine'      => 'integrity-plugin',
                'type'        => 'modified_plugin_file',
                'severity'    => 'high',
                'confidence'  => 95,
                'file_path'   => wp_normalize_path($file_path),
                'description' => "Plugin file differs from official WordPress.org checksum: {$plugin_check['slug']}/{$plugin_check['rel_file']}",
                'evidence'    => "Expected: {$plugin_check['expected']}, Actual: {$plugin_check['actual']}"
            ]);
        } elseif ($plugin_check['status'] === 'unknown') {
            $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);
            $findings[] = new Finding([
                'engine'      => 'integrity-plugin',
                'type'        => 'unknown_plugin_file',
                'severity'    => $is_executable ? 'high' : 'medium',
                'confidence'  => 95,
                'file_path'   => wp_normalize_path($file_path),
                'description' => "Unrecognized/unknown file found inside official plugin {$plugin_check['slug']}: {$plugin_check['rel_file']}",
                'evidence'    => "File '{$plugin_check['rel_file']}' is not part of the official WordPress.org release manifest for plugin {$plugin_check['slug']}."
            ]);
        }

        // 3. Official Themes Integrity Verification
        $theme_check = \WcpScanner\Integrity\ChecksumProvider::verify_theme_file($file_path);
        if ($theme_check['status'] === 'modified') {
            $findings[] = new Finding([
                'engine'      => 'integrity-theme',
                'type'        => 'modified_theme_file',
                'severity'    => 'high',
                'confidence'  => 95,
                'file_path'   => wp_normalize_path($file_path),
                'description' => "Theme file differs from official WordPress.org checksum: {$theme_check['slug']}/{$theme_check['rel_file']}",
                'evidence'    => "Expected: {$theme_check['expected']}, Actual: {$theme_check['actual']}"
            ]);
        } elseif ($theme_check['status'] === 'unknown') {
            $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);
            $findings[] = new Finding([
                'engine'      => 'integrity-theme',
                'type'        => 'unknown_theme_file',
                'severity'    => $is_executable ? 'high' : 'medium',
                'confidence'  => 95,
                'file_path'   => wp_normalize_path($file_path),
                'description' => "Unrecognized/unknown file found inside official theme {$theme_check['slug']}: {$theme_check['rel_file']}",
                'evidence'    => "File '{$theme_check['rel_file']}' is not part of the official WordPress.org release manifest for theme {$theme_check['slug']}."
            ]);
        }

        return $findings;
    }
}
