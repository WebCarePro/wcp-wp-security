<?php
namespace WCP\Scanner\Filesystem;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PathValidator
 *
 * Provides cryptographic-grade canonical path boundary validation to prevent
 * directory traversal, symlink escapes, and sibling-directory prefix confusion attacks.
 */
class PathValidator {

    /**
     * Check if a given file or directory path strictly resides within an approved root directory.
     *
     * Prevents sibling-directory attacks (e.g., /var/www/html-backup matching prefix /var/www/html)
     * by enforcing a trailing directory separator on the canonicalized root path.
     *
     * @param string $path Target path to test
     * @param string|null $root Approved root directory (defaults to ABSPATH)
     * @return bool True if $path is canonically inside $root
     */
    public static function is_inside_root(string $path, ?string $root = null): bool {
        if (empty($path)) {
            return false;
        }

        $root = $root ?: ABSPATH;
        $real_root = realpath($root);
        $real_path = realpath($path);

        // If either path cannot be resolved by the OS filesystem, access is denied
        if ($real_root === false || $real_path === false) {
            return false;
        }

        // Canonicalize and normalize directory separators
        $norm_root = function_exists('wp_normalize_path') ? wp_normalize_path($real_root) : str_replace('\\', '/', $real_root);
        $norm_path = function_exists('wp_normalize_path') ? wp_normalize_path($real_path) : str_replace('\\', '/', $real_path);

        // Enforce trailing slash on root directory to ensure boundary isolation
        $norm_root_dir = rtrim($norm_root, '/') . '/';

        // Valid if exact root directory OR starts with root directory + separator
        return ($norm_path === rtrim($norm_root_dir, '/') || strpos($norm_path, $norm_root_dir) === 0);
    }

    /**
     * Check if a given path is an existing, readable regular file strictly within an approved root directory.
     *
     * @param string $path Target file path
     * @param string|null $root Approved root directory (defaults to ABSPATH)
     * @return bool True if path is a regular readable file within root
     */
    public static function is_safe_readable_file(string $path, ?string $root = null): bool {
        if (!self::is_inside_root($path, $root)) {
            return false;
        }

        $real_path = realpath($path);
        return ($real_path !== false && is_file($real_path) && is_readable($real_path));
    }

    /**
     * Check if a given path resides inside any of the provided approved root directories.
     *
     * Useful for installations where WP_CONTENT_DIR resides outside of ABSPATH.
     *
     * @param string $path Target path
     * @param array $roots Array of approved root directories
     * @return bool
     */
    public static function is_inside_any_root(string $path, array $roots): bool {
        foreach ($roots as $root) {
            if (!empty($root) && self::is_inside_root($path, $root)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get safe relative path within the approved root directory.
     *
     * @param string $path Target path
     * @param string|null $root Approved root directory (defaults to ABSPATH)
     * @return string Relative path or empty string if outside root
     */
    public static function get_relative_path(string $path, ?string $root = null): string {
        if (!self::is_inside_root($path, $root)) {
            return '';
        }

        $root = $root ?: ABSPATH;
        $real_root = realpath($root);
        $real_path = realpath($path);

        $norm_root = function_exists('wp_normalize_path') ? wp_normalize_path($real_root) : str_replace('\\', '/', $real_root);
        $norm_path = function_exists('wp_normalize_path') ? wp_normalize_path($real_path) : str_replace('\\', '/', $real_path);

        $norm_root_dir = rtrim($norm_root, '/') . '/';

        if ($norm_path === rtrim($norm_root_dir, '/')) {
            return '';
        }

        return ltrim(substr($norm_path, strlen($norm_root_dir)), '/');
    }
}
