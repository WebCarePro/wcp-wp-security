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
        if (empty($path) || strpos($path, "\0") !== false) {
            return false;
        }

        // Disallow PHP stream wrappers (e.g. phar://, file://, php://, zip://)
        if (preg_match('/^[a-zA-Z0-9+.-]+:\/\//', $path)) {
            return false;
        }

        $root = $root ?: ABSPATH;

        // Disallow UNC network paths (e.g. \\server\share) unless root itself is a UNC share
        if (str_starts_with($path, '\\\\') || str_starts_with($path, '//')) {
            if (!str_starts_with($root, '\\\\') && !str_starts_with($root, '//')) {
                return false;
            }
        }

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
     * Check if a path is absolute across POSIX and Windows systems.
     *
     * @param string $path
     * @return bool
     */
    public static function is_absolute_path(string $path): bool {
        if ($path === '') {
            return false;
        }
        if ($path[0] === '/') {
            return true;
        }
        return (preg_match('/^[a-zA-Z]:[\\\\\/]/', $path) === 1 || str_starts_with($path, '\\\\'));
    }

    /**
     * Check if a destination path is safe to create or write to.
     * Enforces root boundary containment, disallows stream wrappers / UNC paths,
     * resolves relative symlink targets against the enclosing directory,
     * and strictly prohibits writing through unverified symlinks (preventing TOCTOU symlink attacks).
     *
     * @param string $path Target write path
     * @param string|null $root Approved root directory (defaults to ABSPATH)
     * @return bool True if destination is safe to write
     */
    public static function is_safe_write_target(string $path, ?string $root = null): bool {
        if (!self::is_inside_root($path, $root, false)) {
            return false;
        }

        // If target already exists as a symlink, resolve its target relative to dirname($path)
        if (is_link($path)) {
            $raw_target = readlink($path);
            if ($raw_target === false) {
                return false;
            }

            // Relative symlinks must be evaluated relative to dirname($path), not getcwd()
            $resolved_target = self::is_absolute_path($raw_target)
                ? $raw_target
                : dirname($path) . '/' . $raw_target;

            if (!self::is_inside_root($resolved_target, $root, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Safely write content to disk atomically while preventing symlink follower / TOCTOU attacks.
     * Writes to a cryptographically unique temporary file in the destination's directory
     * and executes an atomic replace via rename(). If the destination is an existing symlink,
     * it unlinks the symlink node directly rather than following it to write to an external target.
     *
     * @param string $path Destination file path
     * @param string $content File contents to write
     * @param string|null $root Approved root boundary
     * @param int $perms Optional filesystem permissions (e.g. 0644)
     * @return bool True on success
     */
    public static function safe_atomic_write(string $path, string $content, ?string $root = null, int $perms = 0644): bool {
        if (!self::is_safe_write_target($path, $root)) {
            return false;
        }

        $dir = dirname($path);
        if (!is_dir($dir)) {
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($dir);
            } else {
                @mkdir($dir, 0755, true);
            }
        }

        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }

        // Exclusive creation of cryptographically unique temporary file in the destination's directory
        $tmp_file = null;
        $handle = false;
        for ($i = 0; $i < 5; $i++) {
            $candidate = $dir . '/.wcp_tmp_' . bin2hex(random_bytes(8)) . '.tmp';
            $handle = @fopen($candidate, 'x+b'); // O_CREAT | O_EXCL
            if ($handle !== false) {
                $tmp_file = $candidate;
                break;
            }
        }

        if ($handle === false || $tmp_file === null) {
            return false;
        }

        // Write content and verify full byte write
        $bytes_to_write = strlen($content);
        $written_total = 0;
        while ($written_total < $bytes_to_write) {
            $chunk = substr($content, $written_total);
            $bytes = @fwrite($handle, $chunk);
            if ($bytes === false || $bytes <= 0) {
                @fclose($handle);
                @unlink($tmp_file);
                return false;
            }
            $written_total += $bytes;
        }

        // Ensure data is completely flushed to disk with fsync durability where supported
        $flushed = @fflush($handle);
        if (function_exists('fsync')) {
            @fsync($handle);
        }
        $closed = @fclose($handle);

        if (!$flushed || !$closed) {
            @unlink($tmp_file);
            return false;
        }

        @chmod($tmp_file, $perms);

        // Security: If destination is an existing symlink, unlink the symlink node itself
        // so rename() cannot follow or replace a symlink pointer
        if (is_link($path)) {
            @unlink($path);
        }

        // Attempt direct atomic replace via rename
        $renamed = @rename($tmp_file, $path);
        if ($renamed) {
            return true;
        }

        // Failure-aware fallback for platforms where destination locking prevents direct rename (e.g. Windows)
        if (file_exists($path)) {
            $dest_backup = $dir . '/.wcp_bak_' . bin2hex(random_bytes(8)) . '.tmp';
            $displaced = @rename($path, $dest_backup);

            if ($displaced) {
                $renamed = @rename($tmp_file, $path);
                if ($renamed) {
                    // Safe replacement succeeded: clean up backup
                    @unlink($dest_backup);
                    return true;
                }

                // Replacement failed: attempt to rollback original file from backup
                $rolled_back = @rename($dest_backup, $path);
                if (!$rolled_back) {
                    // Critical failure: both replacement and rollback failed.
                    // Preserve $dest_backup so the file remains recoverable by the administrator.
                    if (function_exists('error_log')) {
                        error_log(sprintf(
                            '[WCP Security Scanner CRITICAL] Atomic write rollback failure for "%s". Original file preserved in backup "%s".',
                            $path,
                            $dest_backup
                        ));
                    }
                }
            }
        }

        @unlink($tmp_file);
        return false;
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
