<?php
namespace WCP\Scanner\Filesystem;

if (!defined('ABSPATH')) {
    exit;
}

class DirectoryWalker {
    /**
     * Get a batch of files from the filesystem.
     *
     * @param string $root_dir The root directory to scan (e.g., ABSPATH)
     * @param int $batch_size Maximum number of files to return in this batch
     * @param int $offset The number of files to skip (simulating pagination)
     * @return array Array of file paths
     */
    public function get_batch($root_dir, $batch_size, $offset = 0) {
        $files = [];
        $current_index = 0;

        // Ensure we handle recursive directories safely without loading all into memory
        // Using RecursiveDirectoryIterator
        
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root_dir, \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS),
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );

            foreach ($iterator as $file) {
                // We only process files, not directories themselves for the scan list
                if ($file->isFile()) {
                    if ($current_index >= $offset) {
                        $files[] = $file->getPathname();
                        if (count($files) >= $batch_size) {
                            break;
                        }
                    }
                    $current_index++;
                }
            }
        } catch (\Exception $e) {
            // Suppress filesystem traversal exceptions silently
        }

        return $files;
    }
}
