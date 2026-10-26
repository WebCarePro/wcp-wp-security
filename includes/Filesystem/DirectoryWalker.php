<?php
namespace WcpScanner\Filesystem;

if (!defined('ABSPATH')) {
    exit;
}

class DirectoryWalker {

    /** Directories we never enter */
    private array $exclude_dirs = [
        '.git',
        '.svn',
        '.hg',
        'node_modules',
        'vendor',
        'cache',
        'caches',
        'wfcache',
        'updraft',
        'wcp-security-scanner',
        'wcp-wp-scanner',
        'wcp-scanner-quarantine',
        'wcp-vault',
        'wcp-waf',
        'wcp-quarantine',
        '.vault',
        '.backups',
        '.logs',
        'object-cache-pro',
        'wp-content/cache',
        'wp-content/upgrade',
        'wp-content/uploads/wcp-security-scanner',
        'wp-content/uploads/wcp-scanner-quarantine',
        'wp-content/uploads/wcp-vault',
        'wp-content/uploads/wcp-waf',
        'wp-content/uploads/wcp-quarantine',
    ];

    /** Safe media/document extensions we skip early during deep code inspection */
    private array $skip_extensions = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico',
        'mp4', 'mov', 'avi', 'webm', 'mp3', 'wav',
        'zip', 'gz', 'tar', 'rar', '7z',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'woff', 'woff2', 'ttf', 'eot',
    ];

    /**
     * Get a batch of files from the filesystem using an opaque hierarchical cursor.
     *
     * @param string $root Root directory path
     * @param array $cursor Hierarchical state cursor
     * @param int $batch_size Maximum files per batch
     * @return array
     */
    public function get_batch(string $root, array $cursor = [], int $batch_size = 25): array {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        $dir_stack = $cursor['dir_stack'] ?? [];
        $last_file = $cursor['last_file'] ?? null;
        $phase = $cursor['phase'] ?? 'filesystem';

        $files = [];
        $new_cursor = $cursor;
        $exhausted = false;

        $current_dir = $this->build_path($root, $dir_stack);
        if (!is_dir($current_dir)) {
            return [
                'files'     => [],
                'cursor'    => $cursor,
                'exhausted' => true,
            ];
        }

        $found_resume_point = ($last_file === null || $last_file === '');

        try {
            $iterator = $this->create_iterator($current_dir);

            foreach ($iterator as $fileinfo) {
                /** @var \SplFileInfo $fileinfo */
                $pathname = str_replace('\\', '/', $fileinfo->getPathname());
                $basename = $fileinfo->getFilename();

                if ($fileinfo->isDir()) {
                    continue;
                }

                if (!$fileinfo->isFile()) {
                    continue;
                }

                if ($this->is_in_excluded_dir($pathname, $root)) {
                    continue;
                }

                // Skip until resume point is found
                if (!$found_resume_point) {
                    if ($basename === $last_file) {
                        $found_resume_point = true;
                    }
                    continue;
                }

                // Fast path for harmless static media (unless double extension e.g. photo.jpg.php)
                if ($this->should_skip_file($basename)) {
                    $new_cursor = $this->make_cursor($phase, $root, $pathname);
                    continue;
                }

                $files[] = $pathname;
                $new_cursor = $this->make_cursor($phase, $root, $pathname);

                if (count($files) >= $batch_size) {
                    break;
                }
            }
        } catch (\Throwable $e) {
            // Suppress iterator access errors gracefully
        }

        if (count($files) < $batch_size) {
            $exhausted = true;
        }

        return [
            'files'     => $files,
            'cursor'    => $new_cursor,
            'exhausted' => $exhausted,
        ];
    }

    private function create_iterator(string $dir): \RecursiveIteratorIterator {
        $flags = \FilesystemIterator::SKIP_DOTS
               | \FilesystemIterator::CURRENT_AS_FILEINFO
               | \FilesystemIterator::UNIX_PATHS;

        $inner = new \RecursiveDirectoryIterator($dir, $flags);

        // LEAVES_ONLY + CATCH_GET_CHILD; strictly do NOT follow symlinks to prevent circular loops
        return new \RecursiveIteratorIterator(
            $inner,
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
    }

    private function is_in_excluded_dir(string $pathname, string $root): bool {
        $relative = substr($pathname, strlen($root));
        $relative = strtolower(trim($relative, '/'));

        foreach ($this->exclude_dirs as $excluded) {
            $excluded = strtolower(trim($excluded, '/'));
            if ($relative === $excluded || str_starts_with($relative, $excluded . '/') || str_contains($relative, '/' . $excluded . '/')) {
                return true;
            }
        }

        // Check user-configured excluded paths and patterns
        if (class_exists('\\WcpScanner\\System\\SettingsManager') && \WcpScanner\System\SettingsManager::is_path_excluded($pathname)) {
            return true;
        }

        return false;
    }

    private function should_exclude_dir(string $basename, string $pathname, string $root): bool {
        $basename_lower = strtolower($basename);

        if (in_array($basename_lower, array_map('strtolower', $this->exclude_dirs), true)) {
            return true;
        }

        $relative = substr($pathname, strlen($root));
        $relative = strtolower(trim($relative, '/'));

        foreach ($this->exclude_dirs as $excluded) {
            $excluded = strtolower(trim($excluded, '/'));
            if ($relative === $excluded || str_starts_with($relative, $excluded . '/')) {
                return true;
            }
        }

        return false;
    }

    private function should_skip_file(string $basename): bool {
        $ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        if (in_array($ext, $this->skip_extensions, true)) {
            // Guard against hidden PHP extensions like shell.jpg.php
            if (substr_count($basename, '.') > 1) {
                return false;
            }
            return true;
        }
        return false;
    }

    private function build_path(string $root, array $stack): string {
        if (empty($stack)) {
            return $root;
        }
        return $root . '/' . implode('/', $stack);
    }

    private function make_cursor(string $phase, string $root, string $filepath): array {
        $dir = dirname($filepath);
        $relative = substr($dir, strlen($root));
        $relative = trim(str_replace('\\', '/', $relative), '/');

        $dir_stack = $relative === '' ? [] : explode('/', $relative);

        return [
            'phase'     => $phase,
            'dir_stack' => $dir_stack,
            'last_file' => basename($filepath),
        ];
    }
}
