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

    // 1. Drop all custom plugin tables (current wcpscan_ prefix and legacy wcp_ tables)
    $tables = [
        $wpdb->prefix . 'wcpscan_scans',
        $wpdb->prefix . 'wcpscan_scan_issues',
        $wpdb->prefix . 'wcpscan_scan_files',
        $wpdb->prefix . 'wcpscan_quarantine',
        $wpdb->prefix . 'wcpscan_firewall_logs',
        $wpdb->prefix . 'wcpscan_login_history',
        $wpdb->prefix . 'wcp_scans',
        $wpdb->prefix . 'wcp_scan_issues',
        $wpdb->prefix . 'wcp_scan_files',
        $wpdb->prefix . 'wcp_quarantine',
        $wpdb->prefix . 'wcp_firewall_logs',
        $wpdb->prefix . 'wcp_login_history',
    ];

    foreach ($tables as $table) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS `{$table}`");
    }

    // 2. Delete all plugin options
    $plugin_options = [
        'wcpscan_settings',
        'wcpscan_db_version',
        'wcpscan_remediation_backups',
        'wcpscan_threat_intel_ips',
        'wcpscan_threat_intel_meta',
        'wcpscan_threat_intel_cves',
        'wcpscan_login_lockouts',
        'wcpscan_mcp_audit_log',
        'wcpscan_active_patches',
        'wcpscan_whitelist_rules',
        'wcpscan_behavioral_baseline',
        'wcpscan_firewall_blacklist_ips',
        'wcpscan_vault_rotation_state',
        'wcpscan_scan_lock',
    ];
    foreach ($plugin_options as $opt) {
        delete_option($opt);
    }

    // 3. Purge all plugin transients and temporary caches
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wcpscan_%' OR option_name LIKE '_transient_timeout_wcpscan_%'");

    // 4. Purge plugin user meta (encrypted 2FA secrets and trusted devices)
    $wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '_wcpscan_%'");

    // 5. Clear scheduled cron jobs
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
