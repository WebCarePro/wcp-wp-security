<?php
namespace WebCareProScanner\Filesystem;

use WebCareProScanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class SymlinkScanner {
    
    /**
     * Standard WordPress Drop-ins that plugins legitimately create via symlinks.
     * e.g. wp-content/db.php (Query Monitor, LudicrousDB)
     *      wp-content/object-cache.php (Redis Object Cache, Memcached)
     *      wp-content/advanced-cache.php (WP Rocket, WP Super Cache, Batcache)
     */
    private const KNOWN_SAFE_DROPINS = [
        'db.php',
        'object-cache.php',
        'advanced-cache.php',
        'sunrise.php',
        'blog-deleted.php',
        'blog-inactive.php',
        'blog-suspended.php',
        'maintenance.php',
        'fatal-error-handler.php',
    ];

    public function scan($file_path, $scan_id) {
        if (!is_link($file_path)) {
            return null;
        }

        $target = readlink($file_path);
        $norm_target = wp_normalize_path($target);
        $norm_file = wp_normalize_path($file_path);
        $basename = strtolower(basename($norm_file));

        // 1. Legitimate WordPress Drop-in symlink:
        // If file is in WP_CONTENT_DIR root and points inside WP_PLUGIN_DIR or active plugins, it is a legitimate drop-in
        $wp_content_root = wp_normalize_path(defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : (ABSPATH . 'wp-content'));
        $wp_plugin_root = wp_normalize_path(defined('WP_PLUGIN_DIR') ? WP_PLUGIN_DIR : ($wp_content_root . '/plugins'));

        if (dirname($norm_file) === $wp_content_root && in_array($basename, self::KNOWN_SAFE_DROPINS, true)) {
            // Check if the symlink target resolves inside the legitimate plugins or mu-plugins directory
            if (strpos($norm_target, $wp_plugin_root) === 0 || strpos($norm_target, wp_normalize_path(WPMU_PLUGIN_DIR)) === 0) {
                // Benign standard WordPress drop-in symlink created by reputable plugins (Query Monitor, Redis, etc.)
                return null;
            }
        }

        return new Finding([
            'engine'      => 'filesystem',
            'type'        => 'symlink_detected',
            'severity'    => 'low',
            'confidence'  => 100,
            'file_path'   => $file_path,
            'description' => "Symbolic link detected pointing to: $target",
            'evidence'    => "Target: $target"
        ]);
    }
}
