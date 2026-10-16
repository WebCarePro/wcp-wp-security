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
     * Recursively list PHP, JS, and scannable code files in target directory.
     *
     * @param string $dir
     * @param int $limit 0 for unlimited (default)
     * @return array
     */
    public static function get_scannable_files($dir, $limit = 0) {
        $files = [];
        if (!is_dir($dir)) {
            return $files;
        }

        try {
            $dir_iterator = new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS);

            // Skip heavy non-code and runtime directories
            $filter_iterator = new \RecursiveCallbackFilterIterator($dir_iterator, function ($current) {
                if ($current->isDir()) {
                    $name = $current->getFilename();
                    if (in_array($name, ['.git', '.svn', 'node_modules', 'cache', 'wfcache', '.vault', '.backups', 'wcp-backups', 'wcp-quarantine'], true)) {
                        return false;
                    }
                }
                return true;
            });

            $iterator = new \RecursiveIteratorIterator($filter_iterator, \RecursiveIteratorIterator::SELF_FIRST);
            $allowed_exts = ['php', 'phtml', 'php5', 'php7', 'suspected', 'js', 'txt'];

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $pathname = str_replace('\\', '/', $item->getPathname());
                    if (strpos($pathname, '/plugins/wcp-wp-scanner/') !== false || strpos($pathname, '/plugins/wcp-security-scanner/') !== false) {
                        continue; // Do not enqueue scanner's own files
                    }
                    $ext = strtolower($item->getExtension());
                    if (in_array($ext, $allowed_exts, true)) {
                        $files[] = $item->getPathname();
                        if ($limit > 0 && count($files) >= $limit) {
                            break;
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            error_log('WCP Scanner: File discovery error in ' . $dir . ': ' . $e->getMessage());
        }

        return $files;
    }
}
