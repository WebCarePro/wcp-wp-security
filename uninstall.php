<?php
/**
 * Fired when the plugin is deleted via the WordPress Admin Plugins screen.
 *
 * @package WCP_Security_Scanner
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$settings = get_option('wcp_scanner_settings', []);
$delete_data = true; // Enabled by default

if (is_array($settings) && array_key_exists('delete_data_on_uninstall', $settings)) {
    $delete_data = (bool) $settings['delete_data_on_uninstall'];
}

if ($delete_data) {
    global $wpdb;

    // 1. Drop all custom plugin tables
    $tables = [
        $wpdb->prefix . 'wcp_scans',
        $wpdb->prefix . 'wcp_scan_issues',
        $wpdb->prefix . 'wcp_scan_files',
        $wpdb->prefix . 'wcp_quarantine',
    ];

    foreach ($tables as $table) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS `{$table}`");
    }

    // 2. Delete plugin options and transients
    delete_option('wcp_scanner_settings');
    delete_option('wcp_scanner_db_version');
    delete_transient('wcp_scanner_ai_models_catalog');

    // 3. Clear scheduled cron jobs
    wp_clear_scheduled_hook('wcp_scanner_scheduled_scan_cron');

    // 4. Remove all plugin-created files in uploads (logs, quarantine, backups)
    $upload_dir = wp_upload_dir();
    if (!empty($upload_dir['basedir'])) {
        $storage_dir = untrailingslashit($upload_dir['basedir']) . '/wcp-security-scanner';
        if (is_dir($storage_dir)) {
            $items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($storage_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($items as $item) {
                if ($item->isDir()) {
                    @rmdir($item->getRealPath());
                } else {
                    @unlink($item->getRealPath());
                }
            }
            @rmdir($storage_dir);
        }
    }
}
