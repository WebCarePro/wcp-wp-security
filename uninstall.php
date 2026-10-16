<?php
/**
 * Fired when the plugin is deleted via the WordPress Admin Plugins screen.
 *
 * @package WCP_Security_Scanner
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$settings = get_option('wcpscan_settings', []);
$delete_data = true; // Enabled by default

if (is_array($settings) && array_key_exists('delete_data_on_uninstall', $settings)) {
    $delete_data = (bool) $settings['delete_data_on_uninstall'];
}

if ($delete_data) {
    global $wpdb;

    // 1. Drop all custom plugin tables
    $tables = [
        $wpdb->prefix . 'wcpscan_scans',
        $wpdb->prefix . 'wcpscan_scan_issues',
        $wpdb->prefix . 'wcpscan_scan_files',
        $wpdb->prefix . 'wcpscan_quarantine',
        $wpdb->prefix . 'wcpscan_firewall_logs',
    ];

    foreach ($tables as $table) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS `{$table}`");
    }

    // 2. Delete plugin options and transients
    delete_option('wcpscan_settings');
    delete_option('wcpscan_db_version');
    delete_option('wcpscan_remediation_backups');
    delete_option('wcpscan_threat_intel_ips');
    delete_option('wcpscan_threat_intel_meta');
    delete_option('wcpscan_threat_intel_cves');
    delete_option('wcpscan_login_lockouts');
    delete_transient('wcpscan_ai_models_catalog');

    // 3. Clear scheduled cron jobs
    wp_clear_scheduled_hook('wcpscan_scheduled_scan_cron');
    wp_clear_scheduled_hook('wcpscan_threat_intel_cron_sync');

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
