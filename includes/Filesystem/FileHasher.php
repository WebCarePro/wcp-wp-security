<?php
namespace WCP\Scanner\Filesystem;

if (!defined('ABSPATH')) {
    exit;
}

class FileHasher {
    /**
     * Safely calculate SHA-256 hash of a file.
     *
     * @param string $file_path
     * @return string|null The SHA-256 hash, or null on failure
     */
    public function hash($file_path) {
        if (!is_readable($file_path)) {
            return null;
        }
        
        try {
            return hash_file('sha256', $file_path);
        } catch (\Exception $e) {
            return null;
        }
    }
}
