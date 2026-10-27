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
        if (strpos($norm_path, '/plugins/wcp-wp-scanner/') !== false || strpos($norm_path, '/plugins/wcp-security-scanner/') !== false || strpos($norm_path, '/tests/') !== false) {
            return $findings;
        }

        // Respect user-defined excluded paths / patterns
        if (class_exists('\\WcpScanner\\System\\SettingsManager') && \WcpScanner\System\SettingsManager::is_path_excluded($norm_path)) {
            return $findings;
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
        $malware_findings = $this->heuristic_engine->scan_file($file_path, $scan_id);
        $findings = array_merge($findings, $malware_findings);

        // 5. Client-Side JavaScript Threat Scan (Magecart, Form Skimmers, Miners)
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        if ($ext === 'js') {
            $js_findings = $this->js_scanner->scan_file($file_path, $scan_id);
            if (!empty($js_findings)) {
                $findings = array_merge($findings, $js_findings);
            }
        }

        // Future: Core Integrity verification will hook here or run in a separate engine pass using $this->hasher

        return $findings;
    }
}
