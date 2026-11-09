<?php
/**
 * Fired when the plugin is deleted via the WordPress Admin Plugins screen.
 *
 * @package WCP_Security_Scanner
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Register autoloader for WebCareProScanner namespace during uninstallation
spl_autoload_register(function ($class) {
    $prefix = 'WebCareProScanner\\';
    $base_dir = dirname(__FILE__) . '/includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $rel_path = str_replace('\\', '/', $relative_class);
    $file = $base_dir . $rel_path . '.php';

    if (file_exists($file)) {
        require_once $file;
        return;
    }

    $dir = dirname($rel_path);
    $base = basename($rel_path);
    if ($dir !== '.' && $dir !== '') {
        $lower_dir_file = $base_dir . strtolower($dir) . '/' . $base . '.php';
        if (file_exists($lower_dir_file)) {
            require_once $lower_dir_file;
            return;
        }
    }

    $all_lower_file = $base_dir . strtolower($rel_path) . '.php';
    if (file_exists($all_lower_file)) {
        require_once $all_lower_file;
        return;
    }
});

// Dispatch plugin uninstallation security event notification before purging configuration
$webcareproscan_dispatcher_file = dirname(__FILE__) . '/includes/Notifications/NotificationDispatcher.php';
$webcareproscan_settings_mgr_file = dirname(__FILE__) . '/includes/System/SettingsManager.php';
if (file_exists($webcareproscan_dispatcher_file) && file_exists($webcareproscan_settings_mgr_file)) {
    require_once $webcareproscan_settings_mgr_file;
    require_once $webcareproscan_dispatcher_file;
    if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
        try {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('plugin_uninstall', [
                'severity' => 'high',
                'message'  => __('WCP Security Scanner is being uninstalled and deleted from WordPress plugins manager.', 'webcare-pro-security'),
                'details'  => [
                    'Event'        => 'Plugin Uninstallation',
                    'Triggered By' => function_exists('wp_get_current_user') && wp_get_current_user()->exists() ? wp_get_current_user()->user_login : 'admin',
                    'Timestamp'    => current_time('mysql'),
                ],
            ]);
        } catch (\Throwable $e) {
            // Fail safely during uninstall without blocking deletion
        }
    }
}

// Always clean up Micro-WAF preloads and server security rules regardless of delete_data_on_uninstall
$webcareproscan_microwaf_file = dirname(__FILE__) . '/includes/Firewall/MicroWafCompiler.php';
if (file_exists($webcareproscan_microwaf_file)) {
    require_once $webcareproscan_microwaf_file;
    if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
        try {
            \WebCareProScanner\Firewall\MicroWafCompiler::uninstall_preload();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }
}
$webcareproscan_server_sec_file = dirname(__FILE__) . '/includes/Firewall/ServerSecurityEngine.php';
if (file_exists($webcareproscan_server_sec_file)) {
    require_once $webcareproscan_server_sec_file;
    if (class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
        try {
            \WebCareProScanner\Firewall\ServerSecurityEngine::remove_rules();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }
}

// Remove Must-Use (MU) plugin watchdog unconditionally upon uninstall
$webcareproscan_mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
$webcareproscan_mu_file = $webcareproscan_mu_dir . '/wcp-jit-guardian.php';
if (file_exists($webcareproscan_mu_file)) {
    wp_delete_file($webcareproscan_mu_file);
}

$webcareproscan_settings = get_option('webcareproscan_settings', []);
$webcareproscan_delete_data = false; // Disabled by default to prevent loss of quarantine vault & settings on reinstallation

if (is_array($webcareproscan_settings) && array_key_exists('delete_data_on_uninstall', $webcareproscan_settings)) {
    $webcareproscan_delete_data = (bool) $webcareproscan_settings['delete_data_on_uninstall'];
}

if ($webcareproscan_delete_data) {
    global $wpdb;

    $webcareproscan_drop_tables    = !isset($webcareproscan_settings['uninstall_drop_tables']) || !empty($webcareproscan_settings['uninstall_drop_tables']);
    $webcareproscan_delete_options = !isset($webcareproscan_settings['uninstall_delete_options']) || !empty($webcareproscan_settings['uninstall_delete_options']);
    $webcareproscan_delete_crons   = !isset($webcareproscan_settings['uninstall_delete_crons']) || !empty($webcareproscan_settings['uninstall_delete_crons']);
    $webcareproscan_delete_uploads = !isset($webcareproscan_settings['uninstall_delete_uploads']) || !empty($webcareproscan_settings['uninstall_delete_uploads']);

    // 1. Drop all custom plugin tables
    if ($webcareproscan_drop_tables) {
        $webcareproscan_tables = [
            $wpdb->prefix . 'webcareproscan_scans',
            $wpdb->prefix . 'webcareproscan_scan_issues',
            $wpdb->prefix . 'webcareproscan_scan_files',
            $wpdb->prefix . 'webcareproscan_quarantine',
            $wpdb->prefix . 'webcareproscan_firewall_logs',
            $wpdb->prefix . 'webcareproscan_login_history',
            $wpdb->prefix . 'wcp_scans',
            $wpdb->prefix . 'wcp_scan_issues',
            $wpdb->prefix . 'wcp_scan_files',
            $wpdb->prefix . 'wcp_quarantine',
            $wpdb->prefix . 'wcp_firewall_logs',
            $wpdb->prefix . 'wcp_login_history',
        ];

        foreach ($webcareproscan_tables as $webcareproscan_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query("DROP TABLE IF EXISTS `{$webcareproscan_table}`");
        }
    }

    // 2. Delete all plugin options (both exact keys and wildcard prefixes)
    if ($webcareproscan_delete_options) {
        $webcareproscan_plugin_options = [
            'webcareproscan_settings',
            'webcareproscan_db_version',
            'webcareproscan_welcome_dismissed',
            'webcareproscan_server_security_options',
            'webcareproscan_self_defense_hashes',
            'webcareproscan_self_defense_last_audit',
            'webcareproscan_remediation_backups',
            'webcareproscan_threat_intel_ips',
            'webcareproscan_threat_intel_meta',
            'webcareproscan_threat_intel_cves',
            'webcareproscan_login_lockouts',
            'webcareproscan_mcp_audit_log',
            'webcareproscan_active_patches',
            'webcareproscan_whitelist_rules',
            'webcareproscan_behavioral_baseline',
            'webcareproscan_firewall_blacklist_ips',
            'webcareproscan_vault_rotation_state',
            'webcareproscan_vault_salt',
            'webcareproscan_vault_old_key_blob',
            'webcareproscan_vault_new_key_blob',
            'webcareproscan_scan_lock',
            'webcareproscan_circuit_breaker_safe_mode',
            'webcareproscan_circuit_breaker_last_incident',
            'webcareproscan_circuit_breaker_archive',
            'webcareproscan_circuit_breaker_history',
            'webcareproscan_cloudflare_rate_limit_config',
        ];
        foreach ($webcareproscan_plugin_options as $webcareproscan_opt) {
            delete_option($webcareproscan_opt);
            delete_site_option($webcareproscan_opt);
        }

        // Comprehensive cleanup for dynamic/wildcard options (e.g. webcareproscan_vault_backup_*, webcareproscan_vault_ephem_*, webcareproscan_*)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'webcareproscan_%'");
        if (is_multisite()) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE 'webcareproscan_%'");
        }

        // 3. Purge all plugin transients and temporary caches
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_webcareproscan_%' OR option_name LIKE '_transient_timeout_webcareproscan_%'");

        // 4. Purge plugin user meta (2FA tokens, backup codes, trusted devices, session meta)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '_webcareproscan_%' OR meta_key LIKE 'webcareproscan_%'");
    }

    // 5. Clear scheduled cron jobs
    if ($webcareproscan_delete_crons) {
        wp_clear_scheduled_hook('webcareproscan_scheduled_scan_cron');
        wp_clear_scheduled_hook('webcareproscan_scheduled_scan_event');
        wp_clear_scheduled_hook('webcareproscan_threat_intel_cron_sync');
        wp_clear_scheduled_hook('webcareproscan_self_defense_watchdog_event');
        wp_clear_scheduled_hook('webcareproscan_ephemeral_admin_expire');
        wp_clear_scheduled_hook('webcareproscan_waf_log_retention_prune');
    }

    // 6. Remove all plugin-created files in uploads (logs, quarantine, backups)
    if ($webcareproscan_delete_uploads) {
        $webcareproscan_upload_dir = wp_upload_dir();
        if (!empty($webcareproscan_upload_dir['basedir'])) {
            $webcareproscan_storage_dir = untrailingslashit($webcareproscan_upload_dir['basedir']) . '/wcp-security-scanner';
            if (is_dir($webcareproscan_storage_dir)) {
                global $wp_filesystem;
                if (!$wp_filesystem) {
                    require_once ABSPATH . 'wp-admin/includes/file.php';
                    WP_Filesystem();
                }
                if ($wp_filesystem && is_object($wp_filesystem) && method_exists($wp_filesystem, 'delete')) {
                    try {
                        $wp_filesystem->delete($webcareproscan_storage_dir, true);
                    } catch (\Throwable $e) {
                        // Fail safely
                    }
                }
            }
        }
    }
}
