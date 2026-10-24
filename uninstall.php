<?php
/**
 * Fired when the plugin is deleted via the WordPress Admin Plugins screen.
 *
 * @package WCP_Security_Scanner
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$wcpscan_settings = get_option('wcpscan_settings', []);
$wcpscan_delete_data = true; // Enabled by default

if (is_array($wcpscan_settings) && array_key_exists('delete_data_on_uninstall', $wcpscan_settings)) {
    $wcpscan_delete_data = (bool) $wcpscan_settings['delete_data_on_uninstall'];
}

if ($wcpscan_delete_data) {
    global $wpdb;

    // 1. Drop all custom plugin tables
    $wcpscan_tables = [
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

    foreach ($wcpscan_tables as $wcpscan_table) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS `{$wcpscan_table}`");
    }

    // 2. Delete all plugin options (both exact keys and wildcard prefixes)
    $wcpscan_plugin_options = [
        'wcpscan_settings',
        'wcpscan_db_version',
        'wcpscan_welcome_dismissed',
        'wcpscan_server_security_options',
        'wcpscan_self_defense_hashes',
        'wcpscan_self_defense_last_audit',
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
        'wcpscan_vault_salt',
        'wcpscan_vault_old_key_blob',
        'wcpscan_vault_new_key_blob',
        'wcpscan_scan_lock',
        'wcpscan_cloudflare_rate_limit_config',
    ];
    foreach ($wcpscan_plugin_options as $wcpscan_opt) {
        delete_option($wcpscan_opt);
        delete_site_option($wcpscan_opt);
    }

    // Comprehensive cleanup for dynamic/wildcard options (e.g. wcpscan_vault_backup_*, wcpscan_vault_ephem_*, wcpscan_*)
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'wcpscan_%' OR option_name LIKE 'wcp_%'");
    if (is_multisite()) {
        $wpdb->query("DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE 'wcpscan_%' OR meta_key LIKE 'wcp_%'");
    }

    // 3. Purge all plugin transients and temporary caches
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wcpscan_%' OR option_name LIKE '_transient_timeout_wcpscan_%' OR option_name LIKE '_transient_wcp_%' OR option_name LIKE '_transient_timeout_wcp_%'");

    // 4. Purge plugin user meta (2FA tokens, backup codes, trusted devices, session meta)
    $wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '_wcpscan_%' OR meta_key LIKE 'wcpscan_%'");

    // 5. Clear scheduled cron jobs
    wp_clear_scheduled_hook('wcpscan_scheduled_scan_cron');
    wp_clear_scheduled_hook('wcpscan_scheduled_scan_event');
    wp_clear_scheduled_hook('wcpscan_threat_intel_cron_sync');
    wp_clear_scheduled_hook('wcpscan_self_defense_watchdog_event');

    // 6. Remove all plugin-created files in uploads (logs, quarantine, backups)
    $wcpscan_upload_dir = wp_upload_dir();
    if (!empty($wcpscan_upload_dir['basedir'])) {
        $wcpscan_storage_dir = untrailingslashit($wcpscan_upload_dir['basedir']) . '/wcp-security-scanner';
        if (is_dir($wcpscan_storage_dir)) {
            $wcpscan_items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($wcpscan_storage_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($wcpscan_items as $wcpscan_item) {
                if ($wcpscan_item->isDir()) {
                    @rmdir($wcpscan_item->getRealPath());
                } else {
                    @unlink($wcpscan_item->getRealPath());
                }
            }
            @rmdir($wcpscan_storage_dir);
        }
    }
}
