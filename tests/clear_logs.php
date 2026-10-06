<?php
require '/var/www/html/wp-load.php';
global $wpdb;

$table_scans = $wpdb->prefix . 'wcp_scans';
$table_issues = $wpdb->prefix . 'wcp_scan_issues';
$table_files = $wpdb->prefix . 'wcp_scan_files';

$wpdb->query("TRUNCATE TABLE $table_scans");
$wpdb->query("TRUNCATE TABLE $table_issues");
$wpdb->query("TRUNCATE TABLE $table_files");

WCP\Scanner\Scan\ScanLock::release(WCP\Scanner\Scan\ScanLock::get_locked_scan_id() ?: 0);

$count = (int) $wpdb->get_var("SELECT COUNT(id) FROM $table_scans");
echo "All old scan logs and records cleared. Remaining scans in database: {$count}\n";
