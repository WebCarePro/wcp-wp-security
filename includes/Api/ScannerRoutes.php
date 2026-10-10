<?php
namespace WCP\Scanner\Api;

use WCP\Scanner\Scanner\Engine;
use WCP\Scanner\Filesystem\FileScanner;
use WCP\Scanner\Integrity\CoreIntegrity;
use WCP\Scanner\Integrity\ImportantFileFIM;
use WCP\Scanner\Integrity\PluginIntegrity;
use WCP\Scanner\Database\DatabaseScanner;
use WCP\Scanner\Content\ContentScanner;
use WCP\Scanner\WordPress\WordPressSecurityScanner;
use WCP\Scanner\WordPress\UserScanner;
use WCP\Scanner\WordPress\UpdateScanner;
use WCP\Scanner\System\ServerInfo;
use WCP\Scanner\Backup\DatabaseBackup;
use WCP\Scanner\Findings\CorrelationEngine;
use WCP\Scanner\Findings\RiskScorer;
use WCP\Scanner\Quarantine\QuarantineManager;
use WCP\Scanner\Quarantine\CoreRepairManager;
use WCP\Scanner\Scan\ScanLock;
use WCP\Scanner\Filesystem\UploadsScanner;
use WCP\Scanner\WordPress\CronScanner;
use WCP\Scanner\WordPress\PersistenceScanner;

if (!defined('ABSPATH')) {
    exit;
}

class ScannerRoutes {
    const NAMESPACE = 'wcp-scanner/v1';

    public static function register() {
        $permission = function () {
            return current_user_can('manage_options');
        };

        // Start scan
        register_rest_route(self::NAMESPACE, '/scan/start', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'start_scan'],
            'permission_callback' => $permission,
        ]);

        // Process file batch
        register_rest_route(self::NAMESPACE, '/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'process_batch'],
            'permission_callback' => $permission,
        ]);

        // Run deep engines (DB, Content, WP Security, Integrity)
        register_rest_route(self::NAMESPACE, '/scan/deep-audit', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'run_deep_audit'],
            'permission_callback' => $permission,
        ]);

        // Get latest summary & findings
        register_rest_route(self::NAMESPACE, '/scan/latest', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_latest_scan'],
            'permission_callback' => $permission,
        ]);

        // Get currently active running scan
        register_rest_route(self::NAMESPACE, '/scan/active', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_active_scan'],
            'permission_callback' => $permission,
        ]);

        // Abort running scan
        register_rest_route(self::NAMESPACE, '/scan/abort', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'abort_scan'],
            'permission_callback' => $permission,
        ]);

        // Scan History & Logs
        register_rest_route(self::NAMESPACE, '/scan/history', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/scan/history/clear', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/scan/history/(?P<id>\d+)', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_scan_log_detail'],
            'permission_callback' => $permission,
        ]);

        // Server Information
        register_rest_route(self::NAMESPACE, '/server-info', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_server_info'],
            'permission_callback' => $permission,
        ]);

        // Vulnerabilities & Outdated Software Report
        register_rest_route(self::NAMESPACE, '/vulnerabilities/report', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_vulnerabilities_report'],
            'permission_callback' => $permission,
        ]);

        // Database Backup
        register_rest_route(self::NAMESPACE, '/backup/create', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'create_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'list_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/delete', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/download', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'download_backup'],
            'permission_callback' => $permission,
        ]);

        // Secure File Content Viewer
        register_rest_route(self::NAMESPACE, '/file/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'view_file_content'],
            'permission_callback' => $permission,
        ]);

        // Secure Post/Page Content Viewer
        register_rest_route(self::NAMESPACE, '/post/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'view_post_content'],
            'permission_callback' => $permission,
        ]);

        // Update issue status (ignore, safe, etc.)
        register_rest_route(self::NAMESPACE, '/issues/(?P<id>\d+)', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_issue'],
            'permission_callback' => $permission,
        ]);

        // Quarantine endpoints
        register_rest_route(self::NAMESPACE, '/quarantine', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'quarantine_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/(?P<id>\d+)/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/repair', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'repair_core_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'list_quarantine'],
            'permission_callback' => $permission,
        ]);

        // Settings Endpoints
        register_rest_route(self::NAMESPACE, '/settings', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/export', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'export_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/import', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'import_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/reset', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'reset_settings'],
            'permission_callback' => $permission,
        ]);

        // HTTP Security Headers & Hardening Endpoints
        register_rest_route(self::NAMESPACE, '/hardening/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_hardening_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/hardening/apply-preset', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'apply_hardening_preset'],
            'permission_callback' => $permission,
        ]);

        // AI Threat Analysis & Connection Test Endpoints
        register_rest_route(self::NAMESPACE, '/ai/test', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_ai_connection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/ai/analyze', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'analyze_code_with_ai'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/ai/models', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_ai_models'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/ai/models/update', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_ai_models'],
            'permission_callback' => $permission,
        ]);

        // Firewall (WAF Lite) Endpoints
        register_rest_route(self::NAMESPACE, '/firewall/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/clear-logs', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/toggle', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_firewall'],
            'permission_callback' => $permission,
        ]);

        // File Integrity Monitoring (FIM) & Code Diff Endpoints
        register_rest_route(self::NAMESPACE, '/integrity/recent-changes', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_integrity_recent_changes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/diff', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_integrity_file_diff'],
            'permission_callback' => $permission,
        ]);

        // One-Click Remediation & Auto-Cure Endpoints
        register_rest_route(self::NAMESPACE, '/remediation/strip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_strip_webshell'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/restore-plugin', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_restore_plugin'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/restore-theme', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_restore_theme'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/backups', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_remediation_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rollback_remediation'],
            'permission_callback' => $permission,
        ]);

        // Cloud Threat Intelligence & Community Blacklist Endpoints
        register_rest_route(self::NAMESPACE, '/threat-intel/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_threat_intel_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'sync_threat_intel'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/threat-intel/cves', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_threat_intel_cves'],
            'permission_callback' => $permission,
        ]);

        // Multi-Factor Authentication (2FA) & Login Security Endpoints
        register_rest_route(self::NAMESPACE, '/auth/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_auth_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/setup', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'setup_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/verify-setup', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'verify_and_enable_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'disable_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/unlock-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'unlock_locked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/clear-lockouts', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_all_lockouts'],
            'permission_callback' => $permission,
        ]);

        // Session Sentinel Endpoints
        register_rest_route(self::NAMESPACE, '/auth/sessions/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_active_sessions_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/sessions/revoke', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_active_session'],
            'permission_callback' => $permission,
        ]);

        // Rogue Administrator & Database Anomaly Audit
        register_rest_route(self::NAMESPACE, '/database/rogue-admin-audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_rogue_admin_audit'],
            'permission_callback' => $permission,
        ]);

        // Living-off-the-Land (LotL) Hook Infiltration Audit
        register_rest_route(self::NAMESPACE, '/hooks/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_hook_sentinel_audit'],
            'permission_callback' => $permission,
        ]);

        // DevSecOps Webhook Testing
        register_rest_route(self::NAMESPACE, '/notifications/test-webhook', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_chat_webhook'],
            'permission_callback' => $permission,
        ]);

        // Cloudflare Edge Defense Endpoints
        register_rest_route(self::NAMESPACE, '/cloudflare/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/verify', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'verify_cloudflare_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/deploy-rules', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'deploy_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/rate-limiting', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_cloudflare_rate_limiting'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/sync-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'block_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/purge-cache', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'purge_cloudflare_cache'],
            'permission_callback' => $permission,
        ]);
    }

    public static function start_scan(\WP_REST_Request $request) {
        global $wpdb;

        // Check for concurrent active scan lock
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            $table_scans = $wpdb->prefix . 'wcp_scans';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $existing_scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $locked_id), ARRAY_A);
            if (!$existing_scan || $existing_scan['status'] !== 'running') {
                ScanLock::release($locked_id);
            } else {
                $queue = get_transient("wcp_scan_queue_{$locked_id}");
                $remaining = is_array($queue) ? count($queue) : 0;
                return rest_ensure_response([
                    'success'       => true,
                    'scan_id'       => $locked_id,
                    'scan_target'   => $existing_scan['scan_target'],
                    'total_files'   => (int) $existing_scan['total_files'],
                    'scanned_files' => (int) $existing_scan['scanned_files'],
                    'remaining'     => $remaining,
                    'status'        => 'running',
                    'resumed'       => true,
                ]);
            }
        }

        $target = sanitize_text_field($request->get_param('target') ?: 'plugins_themes');
        
        $paths = [];
        $all_files = [];

        // Determine scannable filesystem files based on scan profile
        if (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity', 'rogue_admin', 'hook_sentinel'], true)) {
            // Targeted deep engines do not queue filesystem files
            $all_files = [];
        } elseif ($target === 'filesystem_only' || $target === 'full') {
            $paths[] = untrailingslashit(ABSPATH);
            foreach ($paths as $path) {
                $all_files = array_merge($all_files, Engine::get_scannable_files($path, 3000));
            }
        } else { // default plugins_themes
            $paths[] = WP_PLUGIN_DIR;
            $paths[] = get_theme_root();
            foreach ($paths as $path) {
                $all_files = array_merge($all_files, Engine::get_scannable_files($path, 2500));
            }
        }

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $wpdb->insert($table_scans, [
            'status'        => 'running',
            'scan_target'   => $target,
            'scanned_files' => 0,
            'total_files'   => count($all_files),
            'issues_found'  => 0,
            'risk_score'    => 0,
            'duration'      => 0,
            'created_at'    => current_time('mysql'),
        ]);
        $scan_id = $wpdb->insert_id;

        // Acquire lock
        ScanLock::acquire($scan_id);

        set_transient("wcp_scan_queue_{$scan_id}", $all_files, HOUR_IN_SECONDS);

        return rest_ensure_response([
            'success'     => true,
            'scan_id'     => $scan_id,
            'total_files' => count($all_files),
            'status'      => 'running',
        ]);
    }

    public static function process_batch(\WP_REST_Request $request) {
        global $wpdb;

        $scan_id = (int) $request->get_param('scan_id');
        $batch_size = (int) ($request->get_param('batch_size') ?: 25);

        // Update lock heartbeat
        ScanLock::heartbeat($scan_id);

        $queue = get_transient("wcp_scan_queue_{$scan_id}");
        if ($queue === false || !is_array($queue)) {
            // Check if scan exists in DB to prevent hard 404 failure
            $scan_exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}wcp_scans WHERE id = %d", $scan_id));
            if ($scan_exists) {
                return rest_ensure_response([
                    'success'     => true,
                    'is_finished' => true,
                    'remaining'   => 0,
                    'processed'   => 0,
                    'last_file'   => '',
                ]);
            }
            return new \WP_Error('scan_not_found', 'Scan queue expired or not found', ['status' => 404]);
        }

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_files = $wpdb->prefix . 'wcp_scan_files';

        $total_files = count($queue);
        $files_to_process = array_splice($queue, 0, $batch_size);

        $file_scanner = new FileScanner();

        foreach ($files_to_process as $filepath) {
            $findings = $file_scanner->scan_file($filepath, (string) $scan_id);
            $rel_path = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($filepath)), '/');
            $file_size = @filesize($filepath) ?: 0;
            $file_status = !empty($findings) ? 'threat' : 'clean';

            $wpdb->insert($table_files, [
                'scan_id'    => $scan_id,
                'file_path'  => $rel_path,
                'file_size'  => $file_size,
                'status'     => $file_status,
                'scanned_at' => current_time('mysql'),
            ]);

            foreach ($findings as $f) {
                $item = $f->to_array();
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $item['engine'],
                    'type'         => $item['type'],
                    'severity'     => $item['severity'],
                    'confidence'   => $item['confidence'],
                    'file_path'    => $item['file_path'],
                    'line_number'  => $item['line_number'] ?? null,
                    'code_snippet' => $item['code_snippet'] ?? null,
                    'evidence'     => $item['evidence'] ?? null,
                    'description'  => $item['description'],
                    'status'       => 'open',
                    'created_at'   => current_time('mysql'),
                ]);
            }
        }

        $remaining = count($queue);
        $is_finished = ($remaining === 0);

        if ($is_finished) {
            delete_transient("wcp_scan_queue_{$scan_id}");
        } else {
            set_transient("wcp_scan_queue_{$scan_id}", $queue, HOUR_IN_SECONDS);
        }

        $scanned_so_far = $total_files - $remaining;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $current_issues_total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d", $scan_id
        ));

        $wpdb->update($table_scans, [
            'scanned_files' => $scanned_so_far,
            'issues_found'  => $current_issues_total,
        ], ['id' => $scan_id]);

        return rest_ensure_response([
            'success'        => true,
            'is_finished'    => $is_finished,
            'remaining'      => $remaining,
            'processed'      => count($files_to_process),
            'last_file'      => !empty($files_to_process) ? basename(end($files_to_process)) : '',
        ]);
    }

    public static function run_deep_audit(\WP_REST_Request $request) {
        global $wpdb;

        $scan_id = (int) $request->get_param('scan_id');
        $target = sanitize_text_field($request->get_param('target') ?: '');
        $admins_only = (bool) $request->get_param('admins_only');

        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_scans = $wpdb->prefix . 'wcp_scans';

        // Keep lock alive
        ScanLock::heartbeat($scan_id);

        // If scan is already completed, return results directly (idempotent for reconnects)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $scan_row = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
        if ($scan_row && $scan_row['status'] === 'completed') {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $all_scan_issues = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM `{$table_issues}` WHERE scan_id = %d", $scan_id
            ), ARRAY_A);
            $scorer = new RiskScorer();
            $summary = $scorer->calculate($all_scan_issues);
            return rest_ensure_response([
                'success' => true,
                'summary' => $summary,
                'issues'  => self::enrich_issues($all_scan_issues),
                'status'  => 'completed'
            ]);
        }

        if (empty($target)) {
            $target = $scan_row ? ($scan_row['scan_target'] ?? 'plugins_themes') : 'plugins_themes';
        }

        $all_deep_findings = [];

        try {
            if ($target === 'unknown_files') {
                // Find only unknown files (core & plugins & themes)
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                // Filter strictly for unknown/unrecognized files
                $all_deep_findings = array_filter($all_deep_findings, function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'], ['unknown_core_file', 'unknown_plugin_file'], true);
                });
            } elseif ($target === 'spam_content') {
                // Scan for spam posts/pages only
                $content_scanner = new ContentScanner();
                $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 300));
            } elseif ($target === 'user_security') {
                // Password strength and privilege checks
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, $admins_only));
            } elseif ($target === 'outdated_software') {
                // Check outdated WP core, plugins, themes
                $update_scanner = new UpdateScanner();
                $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
            } elseif ($target === 'suspicious_uploads') {
                // Detect .php, .sh, or suspicious file extensions inside wp-content/uploads
                $uploads_scanner = new UploadsScanner();
                $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
            } elseif ($target === 'crontab_audit') {
                // Crontab & WP-Cron scheduled tasks audit
                $cron_scanner = new CronScanner();
                $all_deep_findings = array_merge($all_deep_findings, $cron_scanner->scan((string) $scan_id));
            } elseif ($target === 'core_integrity') {
                // WordPress Core files integrity check against official checksums
                $core_integrity = new CoreIntegrity();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
            } elseif ($target === 'rogue_admin') {
                // Rogue Administrator & Database Micro-Anomaly Audit
                $rogue_detector = new \WCP\Scanner\Database\RogueAdminAnomalyDetector();
                $all_deep_findings = array_merge($all_deep_findings, $rogue_detector->scan((string) $scan_id));
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true));
            } elseif ($target === 'hook_sentinel') {
                // Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
                $hook_sentinel = new \WCP\Scanner\WordPress\HookInfiltrationSentinel();
                $all_deep_findings = array_merge($all_deep_findings, $hook_sentinel->scan((string) $scan_id));
                $persistence_scanner = new PersistenceScanner();
                $all_deep_findings = array_merge($all_deep_findings, $persistence_scanner->scan((string) $scan_id));
            } elseif ($target === 'filesystem_only') {
                // Filesystem-only scan: no additional deep audit engines needed
            } else {
                // Full or plugins_themes: run all engines
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $important_fim = new ImportantFileFIM();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));

                $db_scanner = new DatabaseScanner();
                $all_deep_findings = array_merge($all_deep_findings, $db_scanner->scan((string) $scan_id, 100));

                $content_scanner = new ContentScanner();
                $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 100));

                $wp_security = new WordPressSecurityScanner();
                $all_deep_findings = array_merge($all_deep_findings, $wp_security->scan((string) $scan_id));

                $update_scanner = new UpdateScanner();
                $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));

                $uploads_scanner = new UploadsScanner();
                $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
            }

            // Cross-engine Correlation
            $correlation = new CorrelationEngine();
            $correlated = $correlation->correlate($all_deep_findings);

            foreach ($correlated as $f) {
                $item = $f->to_array();
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $item['engine'],
                    'type'         => $item['type'],
                    'severity'     => $item['severity'],
                    'confidence'   => $item['confidence'],
                    'file_path'    => $item['file_path'],
                    'line_number'  => $item['line_number'] ?? null,
                    'code_snippet' => UploadsScanner::sanitize_utf8($item['code_snippet'] ?? null),
                    'evidence'     => UploadsScanner::sanitize_utf8($item['evidence'] ?? null),
                    'description'  => $item['description'],
                    'status'       => 'open',
                    'created_at'   => current_time('mysql'),
                ]);
            }

            // Calculate final risk score across all findings
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $all_scan_issues = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM `{$table_issues}` WHERE scan_id = %d", $scan_id
            ), ARRAY_A);

            $scorer = new RiskScorer();
            $summary = $scorer->calculate($all_scan_issues);

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $scan_row = $wpdb->get_row($wpdb->prepare("SELECT created_at FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
            $duration = 1;
            if ($scan_row && !empty($scan_row['created_at'])) {
                $duration = max(1, time() - strtotime($scan_row['created_at']));
            }

            $wpdb->update($table_scans, [
                'status'        => 'completed',
                'issues_found'  => count($all_scan_issues),
                'risk_score'    => $summary['score'],
                'duration'      => $duration,
                'completed_at'  => current_time('mysql'),
            ], ['id' => $scan_id]);

            // Release the scan lock upon completion
            ScanLock::release($scan_id);

            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => self::enrich_issues($all_scan_issues),
                'status'      => 'completed'
            ]);
        } catch (\Throwable $e) {
            ScanLock::release($scan_id);
            error_log('[WCP Scanner] Error during deep audit: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());

            return new \WP_Error(
                'audit_error',
                sprintf(__('Audit failed: %s', 'wcp-security-scanner'), $e->getMessage()),
                ['status' => 500]
            );
        }
    }

    public static function get_latest_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_files = $wpdb->prefix . 'wcp_scan_files';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $latest_scan = $wpdb->get_row("SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1", ARRAY_A);
        if (!$latest_scan) {
            return rest_ensure_response([
                'has_scan' => false,
                'scan'     => null,
                'summary'  => null,
                'issues'   => [],
                'files'    => [],
            ]);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC",
            $latest_scan['id']
        ), ARRAY_A);
        $issues = self::enrich_issues($issues);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $scanned_files = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table_files}` WHERE scan_id = %d ORDER BY id ASC",
            $latest_scan['id']
        ), ARRAY_A);

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);

        return rest_ensure_response([
            'has_scan' => true,
            'scan'     => $latest_scan,
            'summary'  => $summary,
            'issues'   => $issues,
            'files'    => $scanned_files,
        ]);
    }

    public static function update_issue(\WP_REST_Request $request) {
        global $wpdb;

        $issue_id = (int) $request->get_param('id');
        $status = sanitize_text_field($request->get_param('status') ?: 'ignored');

        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $updated = $wpdb->update($table_issues, ['status' => $status], ['id' => $issue_id]);

        return rest_ensure_response([
            'success' => $updated !== false,
            'id'      => $issue_id,
            'status'  => $status,
        ]);
    }

    public static function quarantine_file(\WP_REST_Request $request) {
        $file_path = sanitize_text_field($request->get_param('file_path'));
        $issue_id = $request->get_param('issue_id') ? (int) $request->get_param('issue_id') : null;
        $scan_id = $request->get_param('scan_id') ? (int) $request->get_param('scan_id') : null;

        $qm = new QuarantineManager();
        $result = $qm->quarantine_file($file_path, $scan_id, $issue_id);

        return rest_ensure_response($result);
    }

    public static function restore_quarantine(\WP_REST_Request $request) {
        $quarantine_id = (int) $request->get_param('id');

        $qm = new QuarantineManager();
        $result = $qm->restore_file($quarantine_id);

        return rest_ensure_response($result);
    }

    public static function list_quarantine(\WP_REST_Request $request) {
        $qm = new QuarantineManager();
        $records = $qm->list_records();

        return rest_ensure_response([
            'success' => true,
            'records' => $records,
        ]);
    }

    public static function get_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'wcp_scans';
        $limit = (int) ($request->get_param('limit') ?: 50);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $history = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT %d", $limit),
            ARRAY_A
        );
        return rest_ensure_response([
            'success' => true,
            'scans'   => $history ?: [],
        ]);
    }

    public static function clear_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_files = $wpdb->prefix . 'wcp_scan_files';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE `{$table_scans}`");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE `{$table_issues}`");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE `{$table_files}`");

        ScanLock::release(ScanLock::get_locked_scan_id() ?: 0);

        return rest_ensure_response([
            'success' => true,
            'message' => 'All old scan logs and history records cleared successfully.',
        ]);
    }

    public static function get_scan_log_detail(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('id');
        $table_scans = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_files = $wpdb->prefix . 'wcp_scan_files';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
        if (!$scan) {
            return new \WP_Error('scan_not_found', 'Scan log not found', ['status' => 404]);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC",
            $scan_id
        ), ARRAY_A);
        $issues = self::enrich_issues($issues);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $files_count = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$table_files}` WHERE scan_id = %d", $scan_id));

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);

        return rest_ensure_response([
            'success'     => true,
            'scan'        => $scan,
            'summary'     => $summary,
            'issues'      => $issues,
            'files_count' => $files_count,
        ]);
    }

    public static function get_server_info(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success' => true,
            'info'    => ServerInfo::get_info(),
        ]);
    }

    public static function get_vulnerabilities_report(\WP_REST_Request $request) {
        $report = UpdateScanner::get_detailed_report();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function create_backup(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $res = $db_backup->create_backup();
        return rest_ensure_response($res);
    }

    public static function list_backups(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        return rest_ensure_response([
            'success' => true,
            'backups' => $db_backup->list_backups(),
        ]);
    }

    public static function delete_backup(\WP_REST_Request $request) {
        $filename = sanitize_text_field($request->get_param('filename'));
        $db_backup = new DatabaseBackup();
        $deleted = $db_backup->delete_backup($filename);
        return rest_ensure_response([
            'success' => $deleted,
            'message' => $deleted ? 'Backup deleted successfully.' : 'Could not delete backup.',
        ]);
    }

    public static function download_backup(\WP_REST_Request $request) {
        $filename = sanitize_text_field($request->get_param('filename'));
        $db_backup = new DatabaseBackup();
        $path = $db_backup->get_backup_path($filename);

        if (!$path || !file_exists($path)) {
            return new \WP_Error('not_found', 'Backup file not found.', ['status' => 404]);
        }

        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($path) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($path));
        readfile($path);
        exit;
    }

    public static function get_active_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $locked_id = ScanLock::get_locked_scan_id();

        if (!$locked_id) {
            // Clean up any stray scans marked 'running' whose locks have expired or died
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("UPDATE `{$table_scans}` SET status = 'interrupted', completed_at = NOW() WHERE status = 'running'");
            return rest_ensure_response([
                'is_running' => false,
            ]);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $running_scan = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM `{$table_scans}` WHERE id = %d",
            $locked_id
        ), ARRAY_A);

        if (!$running_scan || $running_scan['status'] !== 'running') {
            ScanLock::release($locked_id);
            return rest_ensure_response([
                'is_running' => false,
            ]);
        }

        // Lock heartbeat
        ScanLock::heartbeat($locked_id);

        $queue = get_transient("wcp_scan_queue_{$locked_id}");
        $remaining = is_array($queue) ? count($queue) : 0;
        $total = (int) $running_scan['total_files'];
        $scanned = (int) $running_scan['scanned_files'];

        return rest_ensure_response([
            'is_running'     => true,
            'scan_id'        => $locked_id,
            'scan_target'    => $running_scan['scan_target'],
            'status'         => 'running',
            'scanned_files'  => $scanned,
            'total_files'    => $total,
            'remaining'      => $remaining,
            'issues_found'   => (int) $running_scan['issues_found'],
            'phase'          => ($remaining > 0) ? 'batch' : 'deep_audit',
            'created_at'     => $running_scan['created_at'],
            'elapsed'        => max(1, time() - strtotime($running_scan['created_at'])),
        ]);
    }

    public static function abort_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $scan_id = (int) $request->get_param('scan_id');
        if (!$scan_id) {
            $scan_id = ScanLock::get_locked_scan_id();
        }

        if ($scan_id) {
            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'completed_at' => current_time('mysql'),
            ], ['id' => $scan_id]);
            delete_transient("wcp_scan_queue_{$scan_id}");
            ScanLock::release($scan_id);
        }

        // Also release any active scan lock and ensure any hanging scans are aborted
        ScanLock::release();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("UPDATE `{$table_scans}` SET status = 'aborted', completed_at = NOW() WHERE status = 'running'");

        return rest_ensure_response([
            'success' => true,
            'message' => 'Scan successfully aborted and lock released.',
        ]);
    }

    /**
     * Enrich findings with real-time WordPress post/page URLs, edit links, and file metadata.
     *
     * @param array $issues
     * @return array
     */
    public static function enrich_issues(array $issues) {
        $norm_abspath = wp_normalize_path(ABSPATH);

        foreach ($issues as &$item) {
            $filePath = $item['file_path'] ?? '';
            $engine = $item['engine'] ?? '';
            $type = $item['type'] ?? '';

            // 0. Check if finding is WordPress Updates / CVE Advisory
            if ($engine === 'wordpress-updates' || in_array($type, ['outdated_core', 'vulnerable_core', 'outdated_plugin', 'vulnerable_plugin', 'outdated_theme', 'vulnerable_theme'])) {
                $item['is_software_update'] = true;
                $evidence = $item['evidence'] ?? '';
                if (!empty($evidence) && is_string($evidence)) {
                    $decoded = json_decode($evidence, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $item['cves'] = $decoded['cves'] ?? [];
                        $item['has_cve'] = !empty($decoded['has_cve']);
                        $item['is_outdated'] = !empty($decoded['is_outdated']);
                        $item['installed_version'] = $decoded['installed'] ?? '';
                        $item['latest_version'] = $decoded['latest'] ?? '';
                        $item['component_name'] = $decoded['name'] ?? '';
                        $item['component_type'] = $decoded['type'] ?? '';
                        $item['update_url'] = $decoded['update_url'] ?? '';
                    }
                }
            }

            // 1. Check if finding is a WordPress Post or Page
            if (preg_match('/^post:(\d+)/i', $filePath, $matches)) {
                $postId = (int) $matches[1];
                $post = get_post($postId);
                if ($post) {
                    $item['is_post'] = true;
                    $item['post_id'] = $postId;
                    $item['post_title'] = $post->post_title ?: __('(Untitled)', 'wcp-security-scanner');
                    $item['post_type'] = $post->post_type;
                    $item['view_url'] = get_permalink($postId) ?: '';
                    $item['edit_url'] = get_edit_post_link($postId, 'raw') ?: admin_url("post.php?post={$postId}&action=edit");
                }
            } 
            // 2. Check if finding is a WordPress Comment
            elseif (preg_match('/^comment:(\d+)/i', $filePath, $matches)) {
                $commentId = (int) $matches[1];
                $comment = get_comment($commentId);
                if ($comment) {
                    $item['is_comment'] = true;
                    $item['comment_id'] = $commentId;
                    $item['view_url'] = get_comment_link($comment) ?: '';
                    $item['edit_url'] = admin_url("comment.php?action=editcomment&c={$commentId}");
                }
            } 
            // 3. Check if finding is a WordPress User Account
            elseif (preg_match('/^user:(\d+)/i', $filePath, $matches)) {
                $userId = (int) $matches[1];
                $user = get_userdata($userId);
                if ($user) {
                    $item['is_user'] = true;
                    $item['user_id'] = $userId;
                    $item['user_login'] = $user->user_login;
                    $item['edit_url'] = admin_url("user-edit.php?user_id={$userId}");
                }
            } 
            // 3. Otherwise treat as a Filesystem finding
            else {
                $cleanPath = ltrim(str_replace(['../', '..\\'], '', $filePath), '/\\');
                $fullPath = wp_normalize_path(ABSPATH . $cleanPath);

                if (!file_exists($fullPath) && file_exists($filePath)) {
                    $fullPath = wp_normalize_path($filePath);
                }

                $realPath = realpath($fullPath);
                $isInsideRoot = $realPath && (strpos(wp_normalize_path($realPath), $norm_abspath) === 0);

                $item['file_exists'] = $isInsideRoot && file_exists($realPath);
                $item['is_dir'] = $item['file_exists'] && is_dir($realPath);
                $item['is_file'] = $item['file_exists'] && is_file($realPath);
                // Only allow viewing if it is a regular readable file (not a folder/directory)
                $item['can_view'] = $item['is_file'] && is_readable($realPath);
            }
        }
        unset($item);

        return $issues;
    }

    /**
     * Safely read and return file content for code inspection popup modal.
     */
    public static function view_file_content(\WP_REST_Request $request) {
        $raw_path = sanitize_text_field($request->get_param('file_path') ?: ($request->get_param('path') ?: ''));
        if (empty($raw_path)) {
            return new \WP_Error('missing_path', __('File path parameter is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        // Clean path and ensure inside ABSPATH
        $raw_path = str_replace(['../', '..\\'], '', $raw_path);
        $norm_abspath = wp_normalize_path(ABSPATH);

        $target_full = '';
        if (file_exists($raw_path)) {
            $target_full = wp_normalize_path($raw_path);
        } else {
            $candidate = wp_normalize_path(ABSPATH . ltrim($raw_path, '/\\'));
            if (file_exists($candidate)) {
                $target_full = $candidate;
            }
        }

        if (empty($target_full) || !file_exists($target_full)) {
            return new \WP_Error('file_not_found', __('File does not exist or has been removed from server.', 'wcp-security-scanner'), ['status' => 404]);
        }

        $real_path = realpath($target_full);
        $real_abs = realpath(ABSPATH);

        if (!$real_path || !$real_abs || strpos(wp_normalize_path($real_path), wp_normalize_path($real_abs)) !== 0) {
            return new \WP_Error('forbidden_path', __('Access to this file path is restricted outside WordPress root.', 'wcp-security-scanner'), ['status' => 403]);
        }

        if (!is_readable($real_path)) {
            return new \WP_Error('unreadable_file', __('File is not readable due to server permissions.', 'wcp-security-scanner'), ['status' => 403]);
        }

        $file_size = (int) filesize($real_path);
        $max_read = 750 * 1024; // 750KB limit to protect memory
        $is_truncated = $file_size > $max_read;

        $content = file_get_contents($real_path, false, null, 0, $max_read);
        if ($content === false) {
            return new \WP_Error('read_error', __('Failed to read file content.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $perms = substr(sprintf('%o', fileperms($real_path)), -4);
        $lines = explode("\n", $content);
        $line_count = count($lines);

        $rel_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($real_path));
        $rel_path = ltrim($rel_path, '/\\');

        return rest_ensure_response([
            'success'        => true,
            'filename'       => basename($real_path),
            'file_path'      => $rel_path,
            'full_path'      => $real_path,
            'size_bytes'     => $file_size,
            'size_formatted' => size_format($file_size, 2),
            'permissions'    => $perms,
            'is_writable'    => is_writable($real_path),
            'line_count'     => $line_count,
            'content'        => $content,
            'is_truncated'   => $is_truncated,
        ]);
    }

    /**
     * Safely read and return post/page content for inspection popup modal.
     */
    public static function view_post_content(\WP_REST_Request $request) {
        $post_id = (int) $request->get_param('post_id');
        if (!$post_id) {
            $path = sanitize_text_field($request->get_param('path') ?: '');
            if (preg_match('/^post:(\d+)/i', $path, $matches)) {
                $post_id = (int) $matches[1];
            }
        }

        if (!$post_id) {
            return new \WP_Error('missing_post_id', __('Valid post ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $post = get_post($post_id);
        if (!$post) {
            return new \WP_Error('post_not_found', __('The requested post or page was not found.', 'wcp-security-scanner'), ['status' => 404]);
        }

        return rest_ensure_response([
            'success'      => true,
            'post_id'      => $post_id,
            'title'        => $post->post_title ?: __('(Untitled)', 'wcp-security-scanner'),
            'post_type'    => $post->post_type,
            'post_status'  => $post->post_status,
            'author'       => get_the_author_meta('display_name', $post->post_author),
            'content'      => $post->post_content,
            'view_url'     => get_permalink($post_id) ?: '',
            'edit_url'     => get_edit_post_link($post_id, 'raw') ?: admin_url("post.php?post={$post_id}&action=edit"),
            'date'         => $post->post_date,
            'modified'     => $post->post_modified,
        ]);
    }

    /**
     * Get plugin settings
     */
    public static function get_settings(\WP_REST_Request $request) {
        $settings = \WCP\Scanner\System\SettingsManager::get_settings();
        $next_run = wp_next_scheduled(\WCP\Scanner\System\SettingsManager::CRON_HOOK);
        return rest_ensure_response([
            'success'        => true,
            'settings'       => $settings,
            'next_scheduled' => $next_run ? date_i18n('Y-m-d H:i:s', $next_run) : null,
            'current_time'   => current_time('mysql'),
        ]);
    }

    /**
     * Save plugin settings
     */
    public static function save_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params();
        if (!is_array($params)) {
            $params = $request->get_body_params();
        }

        $saved = \WCP\Scanner\System\SettingsManager::save_settings((array) $params);
        $next_run = wp_next_scheduled(\WCP\Scanner\System\SettingsManager::CRON_HOOK);

        return rest_ensure_response([
            'success'        => true,
            'message'        => __('Settings successfully saved.', 'wcp-security-scanner'),
            'settings'       => $saved,
            'next_scheduled' => $next_run ? date_i18n('Y-m-d H:i:s', $next_run) : null,
        ]);
    }

    /**
     * Export settings as downloadable JSON payload
     */
    public static function export_settings(\WP_REST_Request $request) {
        $data = \WCP\Scanner\System\SettingsManager::export_settings();
        return rest_ensure_response([
            'success' => true,
            'export'  => $data,
        ]);
    }

    /**
     * Import settings from uploaded JSON payload
     */
    public static function import_settings(\WP_REST_Request $request) {
        $payload = $request->get_json_params();
        if (empty($payload)) {
            $raw = $request->get_body();
            if (!empty($raw)) {
                $payload = json_decode($raw, true);
            }
            if (empty($payload)) {
                $payload = $request->get_body_params();
            }
        }
        if (empty($payload) || !is_array($payload)) {
            return new \WP_Error('invalid_import', __('Invalid JSON data.', 'wcp-security-scanner'), ['status' => 400]);
        }

        try {
            $imported = \WCP\Scanner\System\SettingsManager::import_settings($payload);
            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Settings successfully imported and applied.', 'wcp-security-scanner'),
                'settings' => $imported,
            ]);
        } catch (\Exception $e) {
            return new \WP_Error('import_failed', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Reset settings to factory defaults
     */
    public static function reset_settings(\WP_REST_Request $request) {
        $defaults = \WCP\Scanner\System\SettingsManager::reset_defaults();
        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Settings have been reset to factory defaults.', 'wcp-security-scanner'),
            'settings' => $defaults,
        ]);
    }

    /**
     * Audit HTTP security headers & site hardening status
     */
    public static function get_hardening_audit(\WP_REST_Request $request) {
        $audit = \WCP\Scanner\Hardening\SecurityHeadersEngine::audit_hardening_status();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Apply recommended A+ hardening preset
     */
    public static function apply_hardening_preset(\WP_REST_Request $request) {
        $current = \WCP\Scanner\System\SettingsManager::get_settings();
        
        $preset = [
            'header_hsts'                      => true,
            'header_hsts_preload'              => false,
            'header_x_frame_options'           => true,
            'header_x_frame_options_mode'      => 'SAMEORIGIN',
            'header_nosniff'                   => true,
            'header_referrer_policy'           => true,
            'header_referrer_policy_value'     => 'strict-origin-when-cross-origin',
            'header_permissions_policy'        => true,
            'header_permissions_policy_value'  => 'geolocation=(), camera=(), microphone=(), payment=()',
            'header_xss_protection'            => true,
            'disable_file_editing'             => true,
            'block_user_enumeration'           => true,
            'hide_wp_version'                  => true,
            'block_sensitive_files'            => true,
            'waf_disable_xmlrpc'               => true,
        ];

        $updated = array_merge($current, $preset);
        $saved = \WCP\Scanner\System\SettingsManager::save_settings($updated);
        $audit = \WCP\Scanner\Hardening\SecurityHeadersEngine::audit_hardening_status();

        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Recommended A+ Security Hardening preset applied successfully.', 'wcp-security-scanner'),
            'settings' => $saved,
            'audit'    => $audit,
        ]);
    }

    /**
     * Test AI connection
     */
    public static function test_ai_connection(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $provider = sanitize_text_field($params['provider'] ?? 'openai');
        $api_key  = trim($params['api_key'] ?? '');
        $model    = sanitize_text_field($params['model'] ?? '');

        // If key is masked or empty, fall back to stored key
        if ($api_key === '' || $api_key === '••••••••') {
            $settings = \WCP\Scanner\System\SettingsManager::get_settings();
            if ($provider === 'gemini') {
                $api_key = $settings['gemini_api_key'] ?? '';
                if (!$model) $model = $settings['gemini_model'] ?? 'gemini-3.8-flash';
            } elseif ($provider === 'claude') {
                $api_key = $settings['claude_api_key'] ?? '';
                if (!$model) $model = $settings['claude_model'] ?? 'claude-sonnet-5-5';
            } else {
                $api_key = $settings['openai_api_key'] ?? '';
                if (!$model) $model = $settings['openai_model'] ?? 'gpt-6.1-sol';
            }
        }

        $result = \WCP\Scanner\System\AIService::test_connection($provider, $api_key, $model);
        if (empty($result['success'])) {
            return new \WP_Error('ai_test_failed', $result['error'] ?? 'AI Test Connection Failed', ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Run AI forensic analysis on code or suspicious finding
     */
    public static function analyze_code_with_ai(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        try {
            $analysis = \WCP\Scanner\System\AIService::analyze_code($params);
            return rest_ensure_response($analysis);
        } catch (\Exception $e) {
            return new \WP_Error('ai_analysis_error', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Get available AI model catalog
     */
    public static function get_ai_models(\WP_REST_Request $request) {
        $catalog = \WCP\Scanner\System\AIService::get_available_models();
        return rest_ensure_response([
            'success' => true,
            'catalog' => $catalog,
        ]);
    }

    /**
     * Check provider APIs for new agent releases and update catalog & settings
     */
    public static function update_ai_models(\WP_REST_Request $request) {
        try {
            $params = $request->get_json_params() ?: [];
            $auto_upgrade = !isset($params['auto_upgrade']) || !empty($params['auto_upgrade']);
            $result = \WCP\Scanner\System\AIService::check_and_update_models($auto_upgrade);
            $settings = \WCP\Scanner\System\SettingsManager::get_settings();
            $result['settings'] = $settings;
            return rest_ensure_response($result);
        } catch (\Exception $e) {
            return new \WP_Error('ai_models_update_error', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Safely repair an infected core file by pulling the pristine version from WP.org.
     */
    public static function repair_core_file(\WP_REST_Request $request) {
        $file_path = sanitize_text_field($request->get_param('file_path'));
        $issue_id = (int) $request->get_param('issue_id');

        if (empty($file_path)) {
            return new \WP_Error('missing_params', 'File path is required.', ['status' => 400]);
        }

        $repair_manager = new CoreRepairManager();
        $result = $repair_manager->repair_core_file($file_path);

        if ($result['success'] && $issue_id) {
            global $wpdb;
            $table_issues = $wpdb->prefix . 'wcp_scan_issues';
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response($result);
    }

    public static function get_firewall_status() {
        return rest_ensure_response(\WCP\Scanner\Firewall\FirewallEngine::get_status());
    }

    public static function get_firewall_logs(\WP_REST_Request $request) {
        $limit = (int) ($request->get_param('limit') ?: 50);
        return rest_ensure_response([
            'logs' => \WCP\Scanner\Firewall\FirewallEngine::get_logs($limit),
        ]);
    }

    public static function clear_firewall_logs() {
        $cleared = \WCP\Scanner\Firewall\FirewallEngine::clear_logs();
        return rest_ensure_response([
            'success' => $cleared,
            'message' => 'Firewall incident logs cleared successfully.',
        ]);
    }

    public static function toggle_firewall(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enabled = !empty($params['enabled']);
        $settings = \WCP\Scanner\System\SettingsManager::get_settings();
        $settings['waf_enabled'] = $enabled;
        \WCP\Scanner\System\SettingsManager::save_settings($settings);

        return rest_ensure_response([
            'success' => true,
            'enabled' => $enabled,
            'status'  => \WCP\Scanner\Firewall\FirewallEngine::get_status(),
        ]);
    }

    public static function get_integrity_recent_changes(\WP_REST_Request $request) {
        $hours = (int) ($request->get_param('hours') ?: 48);
        $category = sanitize_key($request->get_param('category') ?: 'all');
        $limit = (int) ($request->get_param('limit') ?: 150);

        $fim = new \WCP\Scanner\Integrity\FileIntegrityMonitor();
        $data = $fim->get_recent_changes($hours, $category, $limit);

        return rest_ensure_response($data);
    }

    public static function get_integrity_file_diff(\WP_REST_Request $request) {
        $file_path = $request->get_param('file_path');
        if (empty($file_path)) {
            return new \WP_Error('missing_file_path', __('Missing required file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $file_path = sanitize_text_field(wp_unslash($file_path));
        $fim = new \WCP\Scanner\Integrity\FileIntegrityMonitor();
        $diff_data = $fim->get_file_diff($file_path);

        return rest_ensure_response($diff_data);
    }

    public static function remediate_strip_webshell(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WCP\Scanner\Remediation\RemediationManager();
        $result = $manager->strip_malware_injection($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_plugin(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WCP\Scanner\Remediation\RemediationManager();
        $result = $manager->restore_official_plugin_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_theme(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WCP\Scanner\Remediation\RemediationManager();
        $result = $manager->restore_official_theme_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function get_remediation_backups() {
        $manager = new \WCP\Scanner\Remediation\RemediationManager();
        return rest_ensure_response([
            'backups' => $manager->get_backups(),
        ]);
    }

    public static function rollback_remediation(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field(wp_unslash($params['backup_id'])) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_param', __('Missing backup_id parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WCP\Scanner\Remediation\RemediationManager();
        $result = $manager->rollback_remediation($backup_id);

        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get Status
     */
    public static function get_threat_intel_status() {
        return rest_ensure_response(\WCP\Scanner\Firewall\ThreatIntelService::get_status());
    }

    /**
     * Threat Intelligence: Sync live data
     */
    public static function sync_threat_intel() {
        $result = \WCP\Scanner\Firewall\ThreatIntelService::sync_threat_data();
        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get CVE catalog
     */
    public static function get_threat_intel_cves() {
        return rest_ensure_response([
            'cves' => \WCP\Scanner\Firewall\ThreatIntelService::get_cve_catalog(),
        ]);
    }

    /**
     * Auth Security: Get Status & Lockouts
     */
    public static function get_auth_security_status() {
        $settings = \WCP\Scanner\System\SettingsManager::get_settings();
        $user_id  = get_current_user_id();
        $user     = wp_get_current_user();

        return rest_ensure_response([
            'auth_2fa_enabled'         => !empty($settings['auth_2fa_enabled']),
            'login_hardening_enabled'  => !empty($settings['login_hardening_enabled']),
            'login_max_retries'        => (int) ($settings['login_max_retries'] ?? 5),
            'login_lockout_duration'   => (int) ($settings['login_lockout_duration'] ?? 15),
            'session_sentinel_enabled' => !empty($settings['session_sentinel_enabled']),
            'session_block_concurrent' => !empty($settings['session_block_concurrent']),
            'session_lock_ip'          => !empty($settings['session_lock_ip']),
            'session_idle_timeout'     => (int) ($settings['session_idle_timeout'] ?? 120),
            'user_2fa_enabled'         => \WCP\Scanner\Auth\TwoFactorAuth::is_user_enabled($user_id),
            'user_login'               => $user ? $user->user_login : '',
            'user_email'               => $user ? $user->user_email : '',
            'lockouts'                 => array_values(\WCP\Scanner\Auth\LoginHardening::get_locked_ips()),
            'stats'                    => \WCP\Scanner\Auth\LoginHardening::get_stats(),
            'active_sessions'          => \WCP\Scanner\Auth\SessionSentinel::get_active_sessions(),
        ]);
    }

    /**
     * Auth Security: Generate 2FA Setup Package
     */
    public static function setup_2fa_for_user() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        $secret           = \WCP\Scanner\Auth\TwoFactorAuth::generate_secret(16);
        $provisioning_uri = \WCP\Scanner\Auth\TwoFactorAuth::get_provisioning_uri($secret, $user->user_login);
        $qr_data_uri      = \WCP\Scanner\Auth\TwoFactorAuth::get_qr_data_uri($provisioning_uri);
        $backup_bundle    = \WCP\Scanner\Auth\TwoFactorAuth::generate_backup_codes(8);

        // Store setup state in transient for 10 minutes
        set_transient('wcp_2fa_setup_' . $user_id, [
            'secret'       => $secret,
            'hashed_codes' => $backup_bundle['hashed'],
        ], 600);

        return rest_ensure_response([
            'secret'           => $secret,
            'provisioning_uri' => $provisioning_uri,
            'qr_code_url'      => $qr_data_uri,
            'backup_codes'     => $backup_bundle['plain'],
        ]);
    }

    /**
     * Auth Security: Verify and Enable 2FA
     */
    public static function verify_and_enable_2fa(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        $params  = $request->get_json_params() ?: [];
        $code    = sanitize_text_field($params['code'] ?? '');
        $secret  = sanitize_text_field($params['secret'] ?? '');

        $setup_state = get_transient('wcp_2fa_setup_' . $user_id);
        if (!$setup_state || empty($setup_state['secret'])) {
            return new \WP_Error('session_expired', __('2FA setup session expired. Please click "Setup 2FA" again.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $active_secret = $secret ?: $setup_state['secret'];

        if (!\WCP\Scanner\Auth\TwoFactorAuth::verify_code($active_secret, $code)) {
            return new \WP_Error('invalid_code', __('The 6-digit verification code you entered is invalid. Please check your authenticator clock and try again.', 'wcp-security-scanner'), ['status' => 400]);
        }

        \WCP\Scanner\Auth\TwoFactorAuth::enable_user($user_id, $active_secret, $setup_state['hashed_codes']);
        delete_transient('wcp_2fa_setup_' . $user_id);

        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) is now active on your account!', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Auth Security: Disable 2FA
     */
    public static function disable_2fa_for_user() {
        $user_id = get_current_user_id();
        \WCP\Scanner\Auth\TwoFactorAuth::disable_user($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) has been disabled.', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Auth Security: Unlock IP
     */
    public static function unlock_locked_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field($params['ip'] ?? '');
        if (empty($ip)) {
            return new \WP_Error('missing_ip', __('Missing IP parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }
        \WCP\Scanner\Auth\LoginHardening::unlock_ip($ip);
        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(__('IP %s has been unlocked.', 'wcp-security-scanner'), $ip),
        ]);
    }

    /**
     * Auth Security: Clear all lockouts
     */
    public static function clear_all_lockouts() {
        \WCP\Scanner\Auth\LoginHardening::clear_all_lockouts();
        return rest_ensure_response([
            'success' => true,
            'message' => __('All temporary IP lockouts have been cleared.', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Session Sentinel: Get active sessions list
     */
    public static function get_active_sessions_list() {
        return rest_ensure_response([
            'success'  => true,
            'sessions' => \WCP\Scanner\Auth\SessionSentinel::get_active_sessions(),
        ]);
    }

    /**
     * Session Sentinel: Revoke session
     */
    public static function revoke_active_session(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $token   = sanitize_text_field($params['token'] ?? '');
        $user_id = (int) ($params['user_id'] ?? 0);
        $revoke_others = !empty($params['revoke_others']);

        if ($revoke_others) {
            $target_user_id = $user_id ?: get_current_user_id();
            \WCP\Scanner\Auth\SessionSentinel::terminate_all_other_sessions($target_user_id);
            return rest_ensure_response([
                'success' => true,
                'message' => __('All other active sessions have been terminated.', 'wcp-security-scanner'),
                'sessions' => \WCP\Scanner\Auth\SessionSentinel::get_active_sessions(),
            ]);
        }

        if (empty($token) || empty($user_id)) {
            return new \WP_Error('missing_params', __('Session token and user ID are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        \WCP\Scanner\Auth\SessionSentinel::terminate_session($user_id, $token, 'Revoked by administrator via Session Sentinel.');

        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Session successfully revoked.', 'wcp-security-scanner'),
            'sessions' => \WCP\Scanner\Auth\SessionSentinel::get_active_sessions(),
        ]);
    }

    /**
     * Database: Get Rogue Administrator & Micro-Anomaly Audit
     */
    public static function get_rogue_admin_audit(\WP_REST_Request $request) {
        $audit = \WCP\Scanner\Database\RogueAdminAnomalyDetector::audit_users_and_anomalies();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Living-off-the-Land (LotL) Hook Infiltration Audit
     */
    public static function get_hook_sentinel_audit(\WP_REST_Request $request) {
        $sentinel = new \WCP\Scanner\WordPress\HookInfiltrationSentinel();
        $findings = $sentinel->scan('manual_api_' . time());
        $results = [];
        foreach ($findings as $f) {
            $results[] = $f->to_array();
        }
        return rest_ensure_response([
            'success'  => true,
            'count'    => count($results),
            'findings' => $results,
        ]);
    }

    /**
     * Webhook Testing Endpoint
     */
    public static function test_chat_webhook(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $platform = sanitize_text_field($params['platform'] ?? 'slack');
        $url      = !empty($params['webhook_url']) ? esc_url_raw(trim($params['webhook_url'])) : null;

        $result = \WCP\Scanner\Notifications\WebhookService::send_test($platform, $url);
        return rest_ensure_response($result);
    }

    /**
     * Cloudflare Edge Defense Handlers
     */
    public static function get_cloudflare_status(\WP_REST_Request $request) {
        $status = \WCP\Scanner\Cloudflare\CloudflareService::get_status();
        $definitions = \WCP\Scanner\Cloudflare\CloudflareService::get_rule_definitions();
        return rest_ensure_response([
            'success'     => true,
            'status'      => $status,
            'definitions' => $definitions,
        ]);
    }

    public static function verify_cloudflare_credentials(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $token   = !empty($params['token']) ? trim(sanitize_text_field($params['token'])) : null;
        $zone_id = !empty($params['zone_id']) ? trim(sanitize_text_field($params['zone_id'])) : null;

        $result = \WCP\Scanner\Cloudflare\CloudflareService::verify_zone($zone_id, $token);
        return rest_ensure_response($result);
    }

    public static function deploy_cloudflare_rules(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $rules  = is_array($params['rules'] ?? null) ? $params['rules'] : [];

        $result = \WCP\Scanner\Cloudflare\CloudflareService::deploy_custom_rules($rules);
        return rest_ensure_response($result);
    }

    public static function toggle_cloudflare_rate_limiting(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enable = !empty($params['enabled']);

        $result = \WCP\Scanner\Cloudflare\CloudflareService::toggle_rate_limiting($enable);
        return rest_ensure_response($result);
    }

    public static function block_cloudflare_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Manual block via Security Scanner');

        $result = \WCP\Scanner\Cloudflare\CloudflareService::block_ip($ip, $reason);
        return rest_ensure_response($result);
    }

    public static function purge_cloudflare_cache(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $files  = !empty($params['files']) && is_array($params['files']) ? array_map('esc_url_raw', $params['files']) : null;

        $result = \WCP\Scanner\Cloudflare\CloudflareService::purge_cache($files);
        return rest_ensure_response($result);
    }
}
