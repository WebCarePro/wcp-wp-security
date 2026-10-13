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
     * @param bool $must_exist If true, the target path itself must currently exist on disk
     * @return bool True if $path is canonically inside $root
     */
    public static function is_inside_root(string $path, ?string $root = null, bool $must_exist = false): bool {
        if (empty($path)) {
            return false;
        }

        $root = $root ?: ABSPATH;
        $real_root = realpath($root);
        if ($real_root === false) {
            return false;
        }

        // Canonicalize and normalize directory separators for root
        $norm_root = function_exists('wp_normalize_path') ? wp_normalize_path($real_root) : str_replace('\\', '/', $real_root);
        $norm_root_dir = rtrim($norm_root, '/') . '/';

        $real_path = realpath($path);
        if ($real_path !== false) {
            $norm_path = function_exists('wp_normalize_path') ? wp_normalize_path($real_path) : str_replace('\\', '/', $real_path);
            return ($norm_path === rtrim($norm_root_dir, '/') || strpos($norm_path, $norm_root_dir) === 0);
        }

        // Target does not exist on disk
        if ($must_exist) {
            return false;
        }

        // For non-existent targets (e.g. restoration or rollback destinations),
        // resolve the nearest existing ancestor canonical path and verify boundary containment.
        $canonical = self::resolve_nonexistent_path($path);
        if ($canonical === false) {
            return false;
        }

        return (strpos($canonical, $norm_root_dir) === 0 || $canonical === rtrim($norm_root_dir, '/'));
    }

    /**
     * Resolve the canonical path for a target that may not yet exist on disk
     * by resolving its nearest existing ancestor and evaluating traversal segments.
     *
     * @param string $path
     * @return string|false
     */
    public static function resolve_nonexistent_path(string $path): string|false {
        if (strpos($path, "\0") !== false) {
            return false;
        }

        $norm = function_exists('wp_normalize_path') ? wp_normalize_path($path) : str_replace('\\', '/', $path);
        $current = $norm;
        $sub_paths = [];

        while (!empty($current) && $current !== '.' && $current !== '/' && !@file_exists($current)) {
            $base = basename($current);
            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }
            array_unshift($sub_paths, $base);
            $current = $parent;
        }

        $real_existing = realpath($current);
        if ($real_existing === false) {
            return false;
        }

        $canonical_existing = function_exists('wp_normalize_path') ? wp_normalize_path($real_existing) : str_replace('\\', '/', $real_existing);
        $segments = explode('/', $canonical_existing);

        foreach ($sub_paths as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                if (count($segments) > 1) {
                    array_pop($segments);
                } else {
                    return false;
                }
            } else {
                $segments[] = $part;
            }
        }

        return implode('/', $segments);
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
