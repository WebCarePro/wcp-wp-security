<?php
namespace WcpScanner\Integrity;

use WcpScanner\Findings\Finding;
use WcpScanner\Filesystem\FileHasher;

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

            // Optional / Security-Hardened Files:
            // Security plugins (Wordfence, iThemes/Solid Security, Defender, Sucuri) and security-conscious
            // administrators frequently delete or rename informational files (like readme.html, license.txt)
            // to prevent version enumeration and info disclosure. Do NOT flag these as high-severity missing core files.
            $informational_core_files = [
                'readme.html',
                'license.txt',
                'licencia.txt',
                'license-es_ES.txt',
            ];
            if (in_array(strtolower($file), $informational_core_files, true)) {
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
            $is_modified = ($actual_hash !== $expected_hash);

            // If modified, normalize line endings (CRLF vs LF) to prevent OS/zip extraction false positives
            if ($is_modified) {
                $raw_content = @file_get_contents($absolute_path);
                if ($raw_content !== false) {
                    $normalized_hash = md5(str_replace("\r\n", "\n", $raw_content));
                    if ($normalized_hash === $expected_hash) {
                        $is_modified = false;
                    }
                }
            }
            
            if ($is_modified) {
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

        // 2. Reverse Reconciliation: Scan core directories AND root folder for unknown/rogue files
        $core_dirs = [
            ABSPATH . 'wp-admin',
            ABSPATH . (defined('WPINC') ? WPINC : 'wp-includes')
        ];

        $ignored_basenames = ['.htaccess', 'web.config', 'error_log', '.ds_store', 'thumbs.db'];
        $normalized_abs = str_replace('\\', '/', rtrim(ABSPATH, '/\\') . '/');

        // Check if user has excluded paths configured
        $has_settings_manager = class_exists('\\WcpScanner\\System\\SettingsManager');

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

                    if ($has_settings_manager && \WcpScanner\System\SettingsManager::is_path_excluded($normalized_item)) {
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
                // Suppress core checksum exceptions silently
            }
        }

        // 3. Root Folder & Hidden Directory Inspection: Scan ABSPATH root level files & unknown directories
        try {
            $root_items = @scandir(ABSPATH);
            if (is_array($root_items)) {
                $known_root_standard_entries = [
                    '.', '..', 'wp-admin', 'wp-includes', 'wp-content',
                    'wp-config.php', 'wp-config-sample.php', 'wp-load.php', 'wp-blog-header.php',
                    'wp-login.php', 'wp-settings.php', 'wp-cron.php', 'wp-comments-post.php',
                    'wp-trackback.php', 'wp-activate.php', 'wp-signup.php', 'wp-mail.php',
                    'xmlrpc.php', 'index.php', 'license.txt', 'readme.html',
                    '.htaccess', 'web.config', 'robots.txt', 'favicon.ico', '.user.ini', 'php.ini',
                    'error_log', '.ds_store', 'thumbs.db', 'sitemap.xml', 'sitemap.xml.gz',
                ];

                foreach ($root_items as $item_name) {
                    if ($item_name === '.' || $item_name === '..') {
                        continue;
                    }

                    $full_item_path = rtrim(ABSPATH, '/\\') . DIRECTORY_SEPARATOR . $item_name;
                    $normalized_item_path = str_replace('\\', '/', $full_item_path);
                    $item_name_lower = strtolower($item_name);

                    // Skip scanner self-quarantine / internal storage
                    if (preg_match('#/(wcp-security-scanner|wcp-scanner-quarantine|wcp-vault|wcp-waf|wcp-quarantine|node_modules|\.git|\.svn)/#i', '/' . $item_name . '/')) {
                        continue;
                    }

                    // Respect user-defined excluded paths / patterns
                    if ($has_settings_manager && \WcpScanner\System\SettingsManager::is_path_excluded($normalized_item_path)) {
                        continue;
                    }

                    if (is_file($full_item_path)) {
                        // Check if file is recognized in official root checksums or standard legitimate root list
                        $rel_file = $item_name;
                        if (!isset($checksums[$rel_file]) && !in_array($item_name_lower, $known_root_standard_entries, true)) {
                            $ext = strtolower(pathinfo($item_name, PATHINFO_EXTENSION));
                            $is_hidden_file = str_starts_with($item_name, '.');
                            $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl', 'py', 'rb'], true);

                            $findings[] = new Finding([
                                'engine'      => 'integrity-core',
                                'type'        => 'unknown_core_file',
                                'severity'    => ($is_executable || $is_hidden_file) ? 'high' : 'medium',
                                'confidence'  => 95,
                                'file_path'   => $full_item_path,
                                'description' => $is_hidden_file 
                                    ? "Unrecognized hidden file found in WordPress root directory: {$item_name}" 
                                    : "Unrecognized file found in WordPress root directory: {$item_name}",
                                'evidence'    => "File '{$item_name}' is not part of official WordPress release manifest or standard root configuration."
                            ]);
                        }
                    } elseif (is_dir($full_item_path)) {
                        // Unknown directory or hidden .dot directory on WordPress root
                        if (!in_array($item_name_lower, ['wp-admin', 'wp-includes', 'wp-content'], true)) {
                            $is_dot_dir = str_starts_with($item_name, '.');

                            // Crawl unexpected directory to flag dropped backdoors / rogue scripts
                            try {
                                $dir_iterator = new \RecursiveIteratorIterator(
                                    new \RecursiveDirectoryIterator($full_item_path, \RecursiveDirectoryIterator::SKIP_DOTS),
                                    \RecursiveIteratorIterator::SELF_FIRST
                                );

                                foreach ($dir_iterator as $child_item) {
                                    if (!$child_item->isFile()) {
                                        continue;
                                    }

                                    $child_full_path = $child_item->getPathname();
                                    $normalized_child = str_replace('\\', '/', $child_full_path);

                                    if ($has_settings_manager && \WcpScanner\System\SettingsManager::is_path_excluded($normalized_child)) {
                                        continue;
                                    }

                                    $child_rel = str_replace($normalized_abs, '', $normalized_child);
                                    $child_ext = strtolower($child_item->getExtension());
                                    $child_executable = in_array($child_ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);

                                    $findings[] = new Finding([
                                        'engine'      => 'integrity-core',
                                        'type'        => 'unknown_core_file',
                                        'severity'    => ($child_executable || $is_dot_dir) ? 'high' : 'medium',
                                        'confidence'  => 95,
                                        'file_path'   => $child_full_path,
                                        'description' => $is_dot_dir
                                            ? "Rogue file found inside hidden directory on WordPress root: {$child_rel}"
                                            : "Unrecognized file found inside non-standard root directory: {$child_rel}",
                                        'evidence'    => "Directory '{$item_name}' is not a standard WordPress directory. File: {$child_rel}"
                                    ]);
                                }
                            } catch (\Throwable $e) {
                                // Suppress sub-directory permission or traversal error
                            }
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Suppress root scan errors
        }

        return $findings;
    }
}
