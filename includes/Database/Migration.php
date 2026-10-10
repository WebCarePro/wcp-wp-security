<?php
namespace WCP\Scanner\Database;

if (!defined('ABSPATH')) {
    exit;
}

class Migration {
    public static function install() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();
        $scans_table = $wpdb->prefix . 'wcp_scans';
        $issues_table = $wpdb->prefix . 'wcp_scan_issues';
        $files_log_table = $wpdb->prefix . 'wcp_scan_files';
        $quarantine_table = $wpdb->prefix . 'wcp_quarantine';

        // 1. Scans Table
        $sql1 = "CREATE TABLE $scans_table (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            status varchar(50) NOT NULL DEFAULT 'pending',
            scan_target varchar(50) NOT NULL DEFAULT 'plugins_themes',
            scanned_files int(11) NOT NULL DEFAULT 0,
            total_files int(11) NOT NULL DEFAULT 0,
            issues_found int(11) NOT NULL DEFAULT 0,
            risk_score int(11) NOT NULL DEFAULT 0,
            duration int(11) NOT NULL DEFAULT 0,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at datetime NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        // 2. Scan Issues Table
        $sql2 = "CREATE TABLE $issues_table (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            scan_id bigint(20) unsigned NOT NULL,
            engine varchar(50) NOT NULL DEFAULT 'filesystem',
            type varchar(50) NOT NULL,
            severity varchar(20) NOT NULL DEFAULT 'medium',
            confidence int(11) NOT NULL DEFAULT 100,
            file_path text NOT NULL,
            line_number int(11) DEFAULT NULL,
            code_snippet text DEFAULT NULL,
            evidence text DEFAULT NULL,
            description text NOT NULL,
            status varchar(30) NOT NULL DEFAULT 'open',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY scan_id (scan_id),
            KEY severity (severity),
            KEY status (status)
        ) $charset_collate;";

        // 3. Scan Files Log Table
        $sql3 = "CREATE TABLE $files_log_table (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            scan_id bigint(20) unsigned NOT NULL,
            file_path text NOT NULL,
            file_size int(11) NOT NULL DEFAULT 0,
            status varchar(20) NOT NULL DEFAULT 'clean',
            scanned_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY scan_id (scan_id),
            KEY status (status)
        ) $charset_collate;";

        // 4. Quarantine Table
        $sql4 = "CREATE TABLE $quarantine_table (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            scan_id bigint(20) unsigned DEFAULT NULL,
            issue_id bigint(20) unsigned DEFAULT NULL,
            original_path text NOT NULL,
            quarantine_filename varchar(255) NOT NULL,
            sha256 varchar(64) NOT NULL,
            file_size bigint(20) NOT NULL DEFAULT 0,
            file_perms varchar(10) DEFAULT NULL,
            status varchar(30) NOT NULL DEFAULT 'quarantined',
            quarantined_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            restored_at datetime DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY scan_id (scan_id),
            KEY status (status)
        ) $charset_collate;";

        // 5. Firewall Blocked Requests Table
        $firewall_logs_table = $wpdb->prefix . 'wcp_firewall_logs';
        $sql5 = "CREATE TABLE $firewall_logs_table (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            request_uri text NOT NULL,
            request_method varchar(10) NOT NULL DEFAULT 'GET',
            rule_category varchar(50) NOT NULL,
            rule_description text NOT NULL,
            payload_sample text DEFAULT NULL,
            user_agent text DEFAULT NULL,
            action_taken varchar(20) NOT NULL DEFAULT 'blocked',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY ip_address (ip_address(50)),
            KEY rule_category (rule_category),
            KEY created_at (created_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql1);
        dbDelta($sql2);
        dbDelta($sql3);
        dbDelta($sql4);
        dbDelta($sql5);

        // Ensure scan_target column exists if upgraded
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $col_check = $wpdb->get_results("SHOW COLUMNS FROM `{$scans_table}` LIKE 'scan_target'");
        if (empty($col_check)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
            $wpdb->query("ALTER TABLE `{$scans_table}` ADD COLUMN scan_target varchar(50) NOT NULL DEFAULT 'plugins_themes' AFTER status");
        }

        update_option('wcp_scanner_db_version', '1.5.0');
    }
}
