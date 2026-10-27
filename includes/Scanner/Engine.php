<?php
namespace WcpScanner\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class Engine {
    /**
     * Scan a single file against malware rules.
     *
     * @param string $filepath
     * @return array
     */
    public static function scan_file($filepath) {
        $issues = [];

        if (!file_exists($filepath) || !is_readable($filepath)) {
            return $issues;
        }

        // Avoid false positives on scanner's own rule definitions
        $norm_filepath = str_replace('\\', '/', $filepath);
        if (strpos($norm_filepath, '/includes/Scanner/Rules.php') !== false) {
            return $issues;
        }

        // Limit scanning files larger than 5MB to avoid memory exhausted errors
        if (filesize($filepath) > 5 * 1024 * 1024) {
            return $issues;
        }

        $content = @file_get_contents($filepath);
        if ($content === false || empty($content)) {
            return $issues;
        }

        $patterns = Rules::get_patterns();
        $lines = explode("\n", $content);

        foreach ($patterns as $rule) {
            if (preg_match($rule['pattern'], $content)) {
                // Find line number and excerpt
                $line_number = 1;
                $snippet = '';

                foreach ($lines as $idx => $line) {
                    if (preg_match($rule['pattern'], $line)) {
                        $line_number = $idx + 1;
                        $snippet = trim($line);
                        if (strlen($snippet) > 200) {
                            $snippet = substr($snippet, 0, 197) . '...';
                        }
                        break;
                    }
                }

                $issues[] = [
                    'type'         => 'malware_heuristic',
                    'severity'     => $rule['severity'],
                    'file_path'    => str_replace(untrailingslashit(ABSPATH) . '/', '', str_replace('\\', '/', $filepath)),
                    'line_number'  => $line_number,
                    'code_snippet' => $snippet,
                    'description'  => $rule['description'],
                ];
            }
        }

        return $issues;
    }

    /**
     * Stream PHP, JS, and scannable code files in target directory via callback.
     * Prevents giant in-memory array allocations during large filesystem scans.
     *
     * @param string $dir Target directory
     * @param callable $callback Callback receiving each string filepath
     * @param int $limit 0 for unlimited (default)
     * @return int Number of files processed
     */
    public static function stream_scannable_files(string $dir, callable $callback, int $limit = 0): int {
        if (!is_dir($dir)) {
            return 0;
        }

        $count = 0;

        try {
            $dir_iterator = new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS);

            // Skip heavy non-code and runtime directories
            $filter_iterator = new \RecursiveCallbackFilterIterator($dir_iterator, function ($current) {
                $pathname = str_replace('\\', '/', $current->getPathname());
                if ($current->isDir()) {
                    $name = $current->getFilename();
                    // System VCS and internal plugin storage exclusions
                    if (in_array($name, ['.git', '.svn', '.hg', 'node_modules', 'cache', 'wfcache', '.vault', '.backups', 'wcp-backups', 'wcp-security-scanner', 'wcp-quarantine', 'wcp-scanner-quarantine', 'wcp-vault', 'wcp-waf'], true)) {
                        return false;
                    }
                    if (class_exists('\\WcpScanner\\System\\SettingsManager') && \WcpScanner\System\SettingsManager::is_path_excluded($pathname)) {
                        return false;
                    }
                }
                return true;
            });

            $iterator = new \RecursiveIteratorIterator($filter_iterator, \RecursiveIteratorIterator::SELF_FIRST);
            $allowed_exts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'inc', 'suspected', 'js', 'txt', 'sh', 'pl', 'cgi'];
            $has_settings_manager = class_exists('\\WcpScanner\\System\\SettingsManager');

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $pathname = str_replace('\\', '/', $item->getPathname());
                    if (strpos($pathname, '/plugins/wcp-wp-scanner/') !== false || strpos($pathname, '/plugins/wcp-security-scanner/') !== false) {
                        continue; // Do not enqueue scanner's own files
                    }

                    // Respect user-defined excluded paths / patterns
                    if ($has_settings_manager && \WcpScanner\System\SettingsManager::is_path_excluded($pathname)) {
                        continue;
                    }

                    $filename = $item->getFilename();
                    $ext = strtolower($item->getExtension());
                    $is_dotfile = str_starts_with($filename, '.');

                    // Check if file is executable code, recognized script extension, dotfile, or double-extension
                    if (in_array($ext, $allowed_exts, true) || $is_dotfile || substr_count($filename, '.') > 1) {
                        $callback($item->getPathname());
                        $count++;
                        if ($limit > 0 && $count >= $limit) {
                            break;
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WCP Scanner: File discovery error in ' . $dir . ': ' . $e->getMessage());
        }

        return $count;
    }

    /**
     * Recursively list PHP, JS, and scannable code files in target directory.
     *
     * @param string $dir
     * @param int $limit 0 for unlimited (default)
     * @return array
     */
    public static function get_scannable_files($dir, $limit = 0) {
        $files = [];
        self::stream_scannable_files((string) $dir, function ($path) use (&$files) {
            $files[] = $path;
        }, (int) $limit);
        return $files;
    }
}

