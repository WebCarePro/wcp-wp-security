<?php
namespace WCP\Scanner\Api;

use WCP\Scanner\Scanner\Engine;
use WCP\Scanner\Filesystem\FileScanner;
use WCP\Scanner\Integrity\CoreIntegrity;
use WCP\Scanner\Integrity\ImportantFileFIM;
use WCP\Scanner\Integrity\PluginIntegrity;
use WCP\Scanner\Integrity\ThemeIntegrity;
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
use WCP\Scanner\Filesystem\PathValidator;

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

        // Scan Findings Export Endpoint (JSON, CSV)
        register_rest_route(self::NAMESPACE, '/scan/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'export_scan_results'],
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

        // Component Changelog Viewer (Plugins & Themes)
        register_rest_route(self::NAMESPACE, '/component/changelog', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'get_component_changelog'],
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

        register_rest_route(self::NAMESPACE, '/quarantine/restored', [
            'methods'             => 'DELETE',
            'callback'            => [__CLASS__, 'clear_restored_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/(?P<id>\d+)', [
            'methods'             => 'DELETE',
            'callback'            => [__CLASS__, 'delete_quarantine'],
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

        register_rest_route(self::NAMESPACE, '/settings/trigger-cron', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'trigger_cron_now'],
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
            'methods'             => ['GET', 'POST'],
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

        register_rest_route(self::NAMESPACE, '/remediation/restore-core', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_restore_core'],
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

        register_rest_route(self::NAMESPACE, '/remediation/delete-cron-hook', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_delete_cron_hook'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/comment/moderate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'moderate_comment'],
            'permission_callback' => $permission,
        ]);

        // Database Table & Record Remediation Endpoints (Auto-Backup & Quarantine)
        register_rest_route(self::NAMESPACE, '/database/remediate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/database/row', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/database/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_database_row'],
            'permission_callback' => $permission,
        ]);

        // User Account & Role Remediation Endpoint (Auto-Backup Snapshot & Repair)
        register_rest_route(self::NAMESPACE, '/user/remediate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_user'],
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

        register_rest_route(self::NAMESPACE, '/auth/2fa/revoke-trusted-devices', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_2fa_trusted_devices'],
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

        register_rest_route(self::NAMESPACE, '/cloudflare/disconnect', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'disconnect_cloudflare'],
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
        if (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity', 'rogue_admin', 'hook_sentinel', 'modified_files'], true)) {
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
        $now_exact = self::now_fractional_mysql();
        $start_micro = microtime(true);

        $wpdb->insert($table_scans, [
            'status'        => 'running',
            'scan_target'   => $target,
            'trigger_type'  => 'manual',
            'scanned_files' => 0,
            'total_files'   => count($all_files),
            'issues_found'  => 0,
            'risk_score'    => 0,
            'duration'      => 0,
            'duration_ms'   => 0,
            'created_at'    => current_time('mysql'),
            'started_at'    => $now_exact,
        ]);
        $scan_id = (int) $wpdb->insert_id;

        // Acquire lock
        ScanLock::acquire($scan_id);

        set_transient("wcp_scan_start_micro_{$scan_id}", $start_micro, HOUR_IN_SECONDS);
        set_transient("wcp_scan_queue_{$scan_id}", $all_files, HOUR_IN_SECONDS);

        $init_telemetry = self::get_realtime_resource_stats(null, null, 0, count($all_files), 0, 0.0);
        set_transient("wcp_scan_live_telemetry_{$scan_id}", $init_telemetry, 600);

        return rest_ensure_response([
            'success'     => true,
            'scan_id'     => $scan_id,
            'total_files' => count($all_files),
            'status'      => 'running',
            'started_at'  => $now_exact,
            'telemetry'   => $init_telemetry,
        ]);
    }

    public static function process_batch(\WP_REST_Request $request) {
        global $wpdb;

        $scan_id = (int) $request->get_param('scan_id');
        $batch_size = (int) ($request->get_param('batch_size') ?: 25);
        $batch_start = microtime(true);
        $batch_ru_start = function_exists('getrusage') ? @getrusage() : null;

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

        $scan_row = $wpdb->get_row($wpdb->prepare("SELECT total_files FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
        if (!$scan_row) {
            // Self-healing: recreate running scan row if missing
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->insert($table_scans, [
                'id'            => $scan_id,
                'status'        => 'running',
                'scan_type'     => 'full',
                'scanned_files' => 0,
                'total_files'   => max(1, $remaining),
                'issues_found'  => 0,
                'risk_score'    => 0,
                'created_at'    => current_time('mysql'),
            ]);
            $scan_row = ['total_files' => max(1, $remaining)];
        }
        $scan_total = (int) ($scan_row['total_files'] ?? 0);
        $scanned_so_far = max(0, $scan_total - $remaining);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $current_issues_total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d", $scan_id
        ));

        $wpdb->update($table_scans, [
            'scanned_files' => $scanned_so_far,
            'issues_found'  => $current_issues_total,
        ], ['id' => $scan_id]);

        $start_micro = get_transient("wcp_scan_start_micro_{$scan_id}");
        $elapsed_sec = ($start_micro && is_numeric($start_micro)) ? max(0.1, microtime(true) - (float) $start_micro) : 0.0;
        $telemetry = self::get_realtime_resource_stats(
            $batch_start,
            $batch_ru_start,
            $scanned_so_far,
            $scan_total,
            $current_issues_total,
            $elapsed_sec
        );
        set_transient("wcp_scan_live_telemetry_{$scan_id}", $telemetry, 600);

        return rest_ensure_response([
            'success'        => true,
            'is_finished'    => $is_finished,
            'remaining'      => $remaining,
            'processed'      => count($files_to_process),
            'scanned_files'  => $scanned_so_far,
            'total_files'    => $scan_total,
            'issues_found'   => $current_issues_total,
            'last_file'      => !empty($files_to_process) ? basename(end($files_to_process)) : '',
            'telemetry'      => $telemetry,
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
            $diagnostics = self::build_scan_diagnostics($scan_row);
            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => self::enrich_issues($all_scan_issues),
                'diagnostics' => $diagnostics,
                'status'      => 'completed'
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
                // Password strength, privilege escalation, and Trojan capability injection audit across all accounts
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, false));
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
            } elseif ($target === 'modified_files') {
                // Modified Core, Plugins, and Themes Audit against official WordPress.org checksums
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $theme_integrity = new ThemeIntegrity();
                $important_fim = new ImportantFileFIM();

                $integrity_findings = array_merge(
                    $core_integrity->verify((string) $scan_id),
                    $plugin_integrity->verify((string) $scan_id),
                    $theme_integrity->verify((string) $scan_id),
                    $important_fim->verify((string) $scan_id)
                );

                // Filter strictly for modified or tampered files (excluding informational notes)
                $modified_items = array_filter($integrity_findings, function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'], [
                        'modified_core_file',
                        'modified_plugin_file',
                        'modified_theme_file',
                        'missing_core_file',
                        'missing_plugin_file',
                        'missing_theme_file',
                        'important_file_modified',
                    ], true);
                });

                $all_deep_findings = array_merge($all_deep_findings, $modified_items);

                // Additionally run AST malware inspection on any modified files to identify injected backdoors
                $file_scanner = new FileScanner();
                foreach ($modified_items as $mf) {
                    $item = is_array($mf) ? $mf : $mf->to_array();
                    $file_path = $item['file_path'] ?? '';
                    if ($file_path) {
                        $abs_path = (strpos($file_path, ABSPATH) === 0) ? $file_path : (rtrim(ABSPATH, '/\\') . '/' . ltrim($file_path, '/\\'));
                        if (file_exists($abs_path) && is_file($abs_path)) {
                            $code_findings = $file_scanner->scan_file($abs_path, (string) $scan_id);
                            if (!empty($code_findings)) {
                                $all_deep_findings = array_merge($all_deep_findings, $code_findings);
                            }
                        }
                    }
                }
            } elseif ($target === 'filesystem_only') {
                // Filesystem-only scan: no additional deep audit engines needed
            } else {
                // Full or plugins_themes: run all engines
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $theme_integrity = new ThemeIntegrity();
                $important_fim = new ImportantFileFIM();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));

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

            // Pre-load all existing findings already saved for this scan to prevent any duplicate insertions
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $existing_issues = $wpdb->get_results($wpdb->prepare(
                "SELECT engine, type, file_path, line_number, description FROM `{$table_issues}` WHERE scan_id = %d",
                $scan_id
            ), ARRAY_A) ?: [];

            $inserted_signatures = [];
            foreach ($existing_issues as $ex) {
                $sig = md5(($ex['engine'] ?? '') . '|' . ($ex['type'] ?? '') . '|' . ($ex['file_path'] ?? '') . '|' . ($ex['line_number'] ?? '') . '|' . ($ex['description'] ?? ''));
                $inserted_signatures[$sig] = true;
            }

            foreach ($correlated as $f) {
                $item = $f->to_array();
                $sig = md5(($item['engine'] ?? '') . '|' . ($item['type'] ?? '') . '|' . ($item['file_path'] ?? '') . '|' . ($item['line_number'] ?? '') . '|' . ($item['description'] ?? ''));
                if (isset($inserted_signatures[$sig])) {
                    continue; // Skip exact duplicate finding for this scan
                }
                $inserted_signatures[$sig] = true;

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

            // Calculate duration accurately with millisecond precision
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $scan_row = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
            $client_duration_ms = (int) $request->get_param('client_duration_ms');
            $client_duration = (int) $request->get_param('client_duration');
            $start_micro = get_transient("wcp_scan_start_micro_{$scan_id}");
            $completed_at_exact = self::now_fractional_mysql();

            $duration_ms = 0;
            $duration_sec = 0;

            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }

            if ($duration_ms <= 0 && $client_duration_ms > 0) {
                $duration_ms = $client_duration_ms;
                $duration_sec = max(1, (int) round($client_duration_ms / 1000));
            } elseif ($duration_ms <= 0 && $client_duration > 0) {
                $duration_sec = $client_duration;
                $duration_ms = $client_duration * 1000;
            } elseif ($duration_ms <= 0 && $scan_row) {
                if (!empty($scan_row['started_at'])) {
                    $start_dt = date_create($scan_row['started_at'], wp_timezone());
                    $end_dt = date_create($completed_at_exact, wp_timezone());
                    if ($start_dt && $end_dt) {
                        $diff_sec = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                        if ($diff_sec > 0) {
                            $duration_ms = (int) round($diff_sec * 1000);
                            $duration_sec = max(1, (int) round($diff_sec));
                        }
                    }
                }

                if ($duration_ms <= 0 && !empty($scan_row['created_at'])) {
                    $created_dt = date_create($scan_row['created_at'], wp_timezone());
                    if ($created_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        $diff_sec = max(0.1, $now_dt->getTimestamp() - $created_dt->getTimestamp());
                        $duration_ms = (int) round($diff_sec * 1000);
                        $duration_sec = max(1, (int) round($diff_sec));
                    }
                }
            }

            if ($duration_ms <= 0) {
                $duration_ms = 100;
                $duration_sec = 1;
            }

            delete_transient("wcp_scan_start_micro_{$scan_id}");

            $started_at_db = !empty($scan_row['started_at']) ? $scan_row['started_at'] : ($scan_row['created_at'] ?? $completed_at_exact);

            if (!$scan_row) {
                // Self-healing: recreate missing scan record so results are guaranteed to persist
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_scans, [
                    'id'            => $scan_id,
                    'status'        => 'completed',
                    'scan_target'   => $target ?: 'full',
                    'trigger_type'  => 'manual',
                    'scanned_files' => count($all_scan_issues),
                    'total_files'   => count($all_scan_issues),
                    'issues_found'  => count($all_scan_issues),
                    'risk_score'    => $summary['score'],
                    'duration'      => $duration_sec,
                    'duration_ms'   => $duration_ms,
                    'created_at'    => current_time('mysql'),
                    'started_at'    => $started_at_db,
                    'completed_at'  => $completed_at_exact,
                ]);
            } else {
                $wpdb->update($table_scans, [
                    'status'        => 'completed',
                    'issues_found'  => count($all_scan_issues),
                    'risk_score'    => $summary['score'],
                    'duration'      => $duration_sec,
                    'duration_ms'   => $duration_ms,
                    'started_at'    => $started_at_db,
                    'completed_at'  => $completed_at_exact,
                ], ['id' => $scan_id]);
            }

            $completed_scan_row = [
                'id'            => $scan_id,
                'status'        => 'completed',
                'issues_found'  => count($all_scan_issues),
                'risk_score'    => $summary['score'],
                'duration'      => $duration_sec,
                'duration_ms'   => $duration_ms,
                'scanned_files' => (int) ($scan_row['scanned_files'] ?? ($scan_row['total_files'] ?? 0)),
                'total_files'   => (int) ($scan_row['total_files'] ?? 0),
                'created_at'    => $scan_row['created_at'] ?? current_time('mysql'),
                'started_at'    => $started_at_db,
                'completed_at'  => $completed_at_exact,
            ];
            $diagnostics = self::build_scan_diagnostics($completed_scan_row);

            // Release the scan lock upon completion
            ScanLock::release($scan_id);

            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => self::enrich_issues($all_scan_issues),
                'diagnostics' => $diagnostics,
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

        // Prune any duplicate issue rows for this scan to keep database clean
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $duplicates = $wpdb->get_results($wpdb->prepare(
            "SELECT MIN(id) as keep_id, scan_id, engine, type, file_path, line_number, description, COUNT(*) as cnt 
             FROM `{$table_issues}` 
             WHERE scan_id = %d 
             GROUP BY scan_id, engine, type, file_path, line_number, description 
             HAVING cnt > 1",
            $latest_scan['id']
        ), ARRAY_A);

        if (!empty($duplicates)) {
            foreach ($duplicates as $dup) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->query($wpdb->prepare(
                    "DELETE FROM `{$table_issues}` 
                     WHERE scan_id = %d AND engine = %s AND type = %s AND file_path = %s AND description = %s AND id != %d",
                    $dup['scan_id'],
                    $dup['engine'],
                    $dup['type'],
                    $dup['file_path'],
                    $dup['description'],
                    $dup['keep_id']
                ));
            }
            // Update issues_found count on scan record
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $fixed_count = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d", $latest_scan['id']));
            $wpdb->update($table_scans, ['issues_found' => $fixed_count], ['id' => $latest_scan['id']]);
            $latest_scan['issues_found'] = $fixed_count;
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
        if ((int) $latest_scan['risk_score'] !== (int) $summary['score']) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['risk_score' => (int) $summary['score']], ['id' => $latest_scan['id']]);
            $latest_scan['risk_score'] = (int) $summary['score'];
        }
        $diagnostics = self::build_scan_diagnostics($latest_scan);

        return rest_ensure_response([
            'has_scan'    => true,
            'scan'        => $latest_scan,
            'summary'     => $summary,
            'issues'      => $issues,
            'files'       => $scanned_files,
            'diagnostics' => $diagnostics,
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

    public static function delete_quarantine(\WP_REST_Request $request) {
        $quarantine_id = (int) $request->get_param('id');
        $qm = new QuarantineManager();
        $result = $qm->delete_record($quarantine_id);

        return rest_ensure_response($result);
    }

    public static function clear_restored_quarantine(\WP_REST_Request $request) {
        $qm = new QuarantineManager();
        $result = $qm->clear_restored_records();

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

        $scans = [];
        if (!empty($history)) {
            foreach ($history as $row) {
                $diag = self::build_scan_diagnostics($row);
                $row['diagnostics'] = $diag;
                $row['duration_formatted'] = $diag['duration_formatted'] ?? ($row['duration'] . 's');
                if (empty($row['trigger_type'])) {
                    $row['trigger_type'] = 'manual';
                }
                $scans[] = $row;
            }
        }

        return rest_ensure_response([
            'success' => true,
            'scans'   => $scans,
        ]);
    }


    public static function clear_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_files = $wpdb->prefix . 'wcp_scan_files';

        // 1. Identify any scans that are actively running or in progress
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $running_scans = $wpdb->get_results(
            "SELECT id FROM `{$table_scans}` WHERE status = 'running'",
            ARRAY_A
        );
        $running_ids = !empty($running_scans) ? array_map('intval', wp_list_pluck($running_scans, 'id')) : [];

        // Check if there is an active lock for an additional running scan
        $locked_id = (int) ScanLock::get_locked_scan_id();
        if ($locked_id > 0 && !in_array($locked_id, $running_ids, true)) {
            $running_ids[] = $locked_id;
        }

        if (!empty($running_ids)) {
            // There IS an active scan in progress!
            // Preserve the active running scan(s) and their issues/files. Delete only historical records.
            $placeholders = implode(',', array_fill(0, count($running_ids), '%d'));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query($wpdb->prepare(
                "DELETE FROM `{$table_issues}` WHERE scan_id NOT IN ($placeholders)",
                ...$running_ids
            ));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query($wpdb->prepare(
                "DELETE FROM `{$table_files}` WHERE scan_id NOT IN ($placeholders)",
                ...$running_ids
            ));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query($wpdb->prepare(
                "DELETE FROM `{$table_scans}` WHERE id NOT IN ($placeholders)",
                ...$running_ids
            ));

            // Do NOT release lock because the scan is actively running!
            return rest_ensure_response([
                'success'        => true,
                'has_active'     => true,
                'active_scan_id' => reset($running_ids),
                'message'        => sprintf(
                    __('Past scan logs cleared successfully. Actively running scan (#%s) was preserved and continues executing uninterrupted.', 'wcp-security-scanner'),
                    implode(', #', $running_ids)
                ),
            ]);
        }

        // 2. No scan is currently running: safe to truncate all tables cleanly
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE `{$table_scans}`");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE `{$table_issues}`");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE `{$table_files}`");

        ScanLock::release(ScanLock::get_locked_scan_id() ?: 0);

        return rest_ensure_response([
            'success'    => true,
            'has_active' => false,
            'message'    => __('All old scan logs and history records cleared successfully.', 'wcp-security-scanner'),
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

        if (empty($scan['trigger_type'])) {
            $scan['trigger_type'] = 'manual';
        }

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);
        $diagnostics = self::build_scan_diagnostics($scan);

        return rest_ensure_response([
            'success'     => true,
            'scan'        => $scan,
            'summary'     => $summary,
            'issues'      => $issues,
            'files_count' => $files_count,
            'diagnostics' => $diagnostics,
        ]);
    }

    public static function export_scan_results(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('scan_id');
        $format  = sanitize_key($request->get_param('format') ?: 'json');

        $table_scans  = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';

        if ($scan_id > 0) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $scan = $wpdb->get_row("SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1", ARRAY_A);
        }

        if (!$scan) {
            return new \WP_Error('scan_not_found', 'No scan record found to export.', ['status' => 404]);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC",
            (int) $scan['id']
        ), ARRAY_A);
        $issues = self::enrich_issues($issues);

        $scorer  = new RiskScorer();
        $summary = $scorer->calculate($issues);
        $diagnostics = self::build_scan_diagnostics($scan);

        if ($format === 'csv') {
            $output  = fopen('php://temp', 'r+');
            // Sysadmin Telemetry & Environment comments header
            $site_url = get_site_url();
            $site_name = get_bloginfo('name');
            $peak_ram = $diagnostics['peak_memory_fmt'] . ' / ' . $diagnostics['memory_limit_raw'] . ' (' . $diagnostics['memory_percent'] . '%)';
            $throughput = $diagnostics['files_per_second'] . ' files/sec';
            $cpu_str = !empty($diagnostics['cpu_load'])
                ? '1m: ' . ($diagnostics['cpu_load']['1m'] ?? '-') . ', 5m: ' . ($diagnostics['cpu_load']['5m'] ?? '-') . ', 15m: ' . ($diagnostics['cpu_load']['15m'] ?? '-')
                : 'N/A';
            if (!empty($diagnostics['cpu_cores'])) {
                $cpu_str .= ' (' . $diagnostics['cpu_cores'] . ' Cores)';
            }
            $server_soft = $diagnostics['server_software'] ?? 'Unknown';
            $server_os = $diagnostics['server_os'] . ' (' . ($diagnostics['server_arch'] ?? 'x86_64') . ')';
            $php_info = 'PHP ' . $diagnostics['php_version'] . ' (' . $diagnostics['php_sapi'] . ') | Max Execution: ' . ($diagnostics['php_max_execution_time'] ?? '30') . 's';
            $db_info = 'MySQL ' . ($diagnostics['database_version'] ?? 'N/A');

            fwrite($output, "# ====================================================================\r\n");
            fwrite($output, "# WCP Security Scanner Pro - Audit Findings Report\r\n");
            fwrite($output, "# Auditor: Mir Alamin (WebCare Pro) - Senior Linux SysAdmin & WordPress Security Engineer\r\n");
            fwrite($output, "# Target: {$site_name} ({$site_url})\r\n");
            fwrite($output, "# Peak RAM: {$peak_ram}\r\n");
            fwrite($output, "# Throughput: {$throughput}\r\n");
            fwrite($output, "# CPU Load: {$cpu_str}\r\n");
            fwrite($output, "# Server Software: {$server_soft}\r\n");
            fwrite($output, "# Platform & OS: {$server_os}\r\n");
            fwrite($output, "# PHP Environment: {$php_info}\r\n");
            fwrite($output, "# Database: {$db_info}\r\n");
            fwrite($output, "# Active Engines: " . ($diagnostics['engines_active'] ?? 10) . " Core Security Engines\r\n");
            fwrite($output, "# Exported: " . current_time('mysql') . "\r\n");
            fwrite($output, "# ====================================================================\r\n");

            $headers = ['ID', 'Severity', 'Engine', 'Threat Type', 'File / Target', 'Line Number', 'Status', 'Description'];
            fputcsv($output, $headers);

            foreach ($issues as $issue) {
                fputcsv($output, [
                    $issue['id'] ?? '',
                    strtoupper($issue['severity'] ?? 'low'),
                    $issue['engine'] ?? '',
                    $issue['type'] ?? '',
                    $issue['file_path'] ?? '',
                    $issue['line_number'] ?? '',
                    $issue['status'] ?? 'open',
                    $issue['description'] ?? '',
                ]);
            }

            rewind($output);
            $csv_data = stream_get_contents($output);
            fclose($output);

            return rest_ensure_response([
                'success'     => true,
                'format'      => 'csv',
                'filename'    => 'wcp-scan-' . $scan['id'] . '-' . gmdate('Ymd-His') . '.csv',
                'csv_data'    => $csv_data,
                'diagnostics' => $diagnostics,
            ]);
        }

        return rest_ensure_response([
            'success'            => true,
            'format'             => 'json',
            'filename'           => 'wcp-scan-' . $scan['id'] . '-' . gmdate('Ymd-His') . '.json',
            'report_generator'   => 'WCP Security Scanner Pro',
            'specialist'         => 'Mir Alamin (WebCare Pro)',
            'specialist_role'    => 'Senior Linux SysAdmin & WordPress Security Engineer',
            'site_url'           => get_site_url(),
            'site_name'          => get_bloginfo('name'),
            'exported_at'        => current_time('mysql'),
            'scan'               => $scan,
            'summary'            => $summary,
            'diagnostics'        => $diagnostics,
            'server_diagnostics' => [
                'peak_ram'               => $diagnostics['peak_memory_fmt'],
                'peak_ram_mb'            => $diagnostics['peak_memory_mb'],
                'memory_limit'           => $diagnostics['memory_limit_raw'],
                'memory_usage_percent'   => $diagnostics['memory_percent'] . '%',
                'throughput'             => $diagnostics['files_per_second'] . ' files/sec',
                'files_per_second'       => $diagnostics['files_per_second'],
                'cpu_load'               => $diagnostics['cpu_load'],
                'cpu_cores'              => $diagnostics['cpu_cores'] ?? null,
                'server_software'        => $diagnostics['server_software'] ?? 'Unknown',
                'server_os'              => $diagnostics['server_os'],
                'server_architecture'    => $diagnostics['server_arch'] ?? 'x86_64',
                'php_version'            => $diagnostics['php_version'],
                'php_sapi'               => $diagnostics['php_sapi'],
                'php_max_execution_time' => ($diagnostics['php_max_execution_time'] ?? 30) . 's',
                'database_version'       => $diagnostics['database_version'] ?? 'N/A',
                'database_name'          => $diagnostics['database_name'] ?? 'N/A',
                'wordpress_version'      => $diagnostics['wordpress_version'] ?? 'N/A',
                'ssl_active'             => !empty($diagnostics['ssl_active']) ? 'Active (HTTPS)' : 'Inactive (HTTP)',
                'opcache'                => $diagnostics['opcache_status'] ?? 'Disabled',
                'active_engines'         => $diagnostics['engines_active'] ?? 10,
            ],
            'findings_count'     => count($issues),
            'findings'           => $issues,
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

        // If no lock option exists, check if there is an active scan record in the DB created recently
        if (!$locked_id) {
            // Clean up any stale scans marked 'running' older than 10 minutes
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("UPDATE `{$table_scans}` SET status = 'interrupted', completed_at = NOW() WHERE status = 'running' AND created_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)");

            // Fallback: check if any recent scan (< 5 mins) is legitimately running in database
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $recent_active = $wpdb->get_row(
                "SELECT * FROM `{$table_scans}` WHERE status = 'running' AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) ORDER BY id DESC LIMIT 1",
                ARRAY_A
            );

            if ($recent_active) {
                $locked_id = (int) $recent_active['id'];
                ScanLock::acquire($locked_id);
            } else {
                return rest_ensure_response([
                    'is_running' => false,
                ]);
            }
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
        $total = (int) $running_scan['total_files'];
        $scanned = (int) $running_scan['scanned_files'];
        $trigger_type = !empty($running_scan['trigger_type']) ? $running_scan['trigger_type'] : 'manual';
        $remaining = is_array($queue) ? count($queue) : max(0, $total - $scanned);
        $last_file = get_transient("wcp_active_scan_file_{$locked_id}") ?: '';

        $live_telemetry = get_transient("wcp_scan_live_telemetry_{$locked_id}");
        if (!$live_telemetry || !is_array($live_telemetry)) {
            $live_telemetry = self::get_realtime_resource_stats(null, null, $scanned, $total, (int) $running_scan['issues_found'], 0.0);
        }

        return rest_ensure_response([
            'is_running'     => true,
            'scan_id'        => $locked_id,
            'scan_target'    => $running_scan['scan_target'],
            'trigger_type'   => $trigger_type,
            'status'         => 'running',
            'scanned_files'  => $scanned,
            'total_files'    => $total,
            'remaining'      => $remaining,
            'last_file'      => $last_file,
            'issues_found'   => (int) $running_scan['issues_found'],
            'telemetry'      => $live_telemetry,
            'phase'          => ($trigger_type === 'scheduled') 
                ? (($scanned >= $total && $total > 0) ? 'deep_audit' : 'batch')
                : (($remaining > 0) ? 'batch' : 'deep_audit'),
            'created_at'     => $running_scan['created_at'],
            'started_at'     => $running_scan['started_at'] ?? $running_scan['created_at'],
            'elapsed'        => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("wcp_scan_start_micro_{$locked_id}");
                if ($start_micro && is_numeric($start_micro)) {
                    $diff = microtime(true) - (float) $start_micro;
                    if ($diff > 0) return max(1, (int) round($diff));
                }
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], wp_timezone());
                    if ($start_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        return max(1, $now_dt->getTimestamp() - $start_dt->getTimestamp());
                    }
                }
                if (empty($running_scan['created_at'])) return 1;
                $created_dt = date_create($running_scan['created_at'], wp_timezone());
                if ($created_dt) {
                    $now_dt = date_create('now', wp_timezone());
                    return max(1, $now_dt->getTimestamp() - $created_dt->getTimestamp());
                }
                return 1;
            })(),
            'elapsed_ms'     => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("wcp_scan_start_micro_{$locked_id}");
                if ($start_micro && is_numeric($start_micro)) {
                    $diff = microtime(true) - (float) $start_micro;
                    if ($diff > 0) return (int) round($diff * 1000);
                }
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], wp_timezone());
                    if ($start_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        $diff = $now_dt->getTimestamp() - $start_dt->getTimestamp() + (($now_dt->format('u') - $start_dt->format('u')) / 1000000);
                        return max(100, (int) round($diff * 1000));
                    }
                }
                return 1000;
            })(),
        ]);
    }

    public static function abort_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $scan_id = (int) $request->get_param('scan_id');
        if (!$scan_id) {
            $scan_id = ScanLock::get_locked_scan_id();
        }

        $now_exact = self::now_fractional_mysql();

        if ($scan_id) {
            $start_micro = get_transient("wcp_scan_start_micro_{$scan_id}");
            $duration_ms = 0;
            $duration_sec = 0;
            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }
            delete_transient("wcp_scan_start_micro_{$scan_id}");

            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'duration'     => $duration_sec,
                'duration_ms'  => $duration_ms,
                'completed_at' => $now_exact,
            ], ['id' => $scan_id]);
            delete_transient("wcp_scan_queue_{$scan_id}");
            ScanLock::release($scan_id);
        }

        // Also release any active scan lock and ensure any hanging scans are aborted
        ScanLock::release();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query($wpdb->prepare("UPDATE `{$table_scans}` SET status = 'aborted', completed_at = %s WHERE status = 'running'", $now_exact));

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
                    }
                }
            }

            // 0b. Check if finding is Theme Checksums Unavailable (Custom / Child / Premium Theme)
            if ($type === 'theme_checksums_unavailable' || ($engine === 'integrity-theme' && (strpos($filePath, '/themes/') !== false || strpos($filePath, '\\themes\\') !== false) && !preg_match('/\.[a-zA-Z0-9]{2,5}$/', $filePath))) {
                $item['is_dir'] = true;
                $item['is_file'] = false;
                $item['can_view'] = false;
                $item['component_type'] = 'theme';

                $evidence_data = !empty($item['evidence']) && is_string($item['evidence']) ? json_decode($item['evidence'], true) : [];
                $path_lower = strtolower($filePath);
                $desc_lower = strtolower($item['description'] ?? '');

                $is_child = !empty($evidence_data['is_child']) || strpos($path_lower, '-child') !== false || strpos($desc_lower, 'child') !== false;
                $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/\b(premium|pro|commercial|license|themeforest|envato)\b/i', $filePath . ' ' . $desc_lower);

                if (!empty($evidence_data['display_title'])) {
                    $item['display_title'] = $evidence_data['display_title'];
                } elseif ($is_child) {
                    $item['display_title'] = __('Custom Child Theme', 'wcp-security-scanner');
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Theme', 'wcp-security-scanner');
                } else {
                    $item['display_title'] = __('Custom or Premium Theme', 'wcp-security-scanner');
                }

                $meta = self::get_theme_forensics_meta($filePath, is_array($evidence_data) ? $evidence_data : []);
                $item['component_meta'] = $meta;
                $item['component_name'] = $meta['name'];
                $item['installed_version'] = $meta['version'];
                $item['latest_version'] = $meta['latest_version'];
                $item['has_update'] = $meta['has_update'];
                $item['author_name'] = $meta['author'];
                $item['author_url'] = $meta['author_uri'];
                $item['component_status'] = $meta['status_label'];
                $item['last_updated'] = $meta['last_modified'];
                $item['has_changelog'] = $meta['has_changelog'];
            }
            // 0c. Check if finding is Plugin Checksums Unavailable (Custom or Premium Plugin)
            elseif ($type === 'plugin_checksums_unavailable' || ($engine === 'integrity-plugin' && (strpos($filePath, '/plugins/') !== false || strpos($filePath, '\\plugins\\') !== false) && !preg_match('/\.[a-zA-Z0-9]{2,5}$/', $filePath))) {
                $item['is_dir'] = true;
                $item['is_file'] = false;
                $item['can_view'] = false;
                $item['component_type'] = 'plugin';

                $evidence_data = !empty($item['evidence']) && is_string($item['evidence']) ? json_decode($item['evidence'], true) : [];
                $path_lower = strtolower($filePath);
                $desc_lower = strtolower($item['description'] ?? '');

                $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/(?:^|[-_])(premium|pro|addon|addons|unlimited|commercial)(?:[-_]|$)/i', $filePath) || (bool) preg_match('/\b(premium|pro|yith|woocommerce)\b/i', $desc_lower);

                if (!empty($evidence_data['display_title'])) {
                    $item['display_title'] = $evidence_data['display_title'];
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Plugin', 'wcp-security-scanner');
                } else {
                    $item['display_title'] = __('Custom or Premium Plugin', 'wcp-security-scanner');
                }

                $meta = self::get_plugin_forensics_meta($filePath, is_array($evidence_data) ? $evidence_data : []);
                $item['component_meta'] = $meta;
                $item['component_name'] = $meta['name'];
                $item['installed_version'] = $meta['version'];
                $item['latest_version'] = $meta['latest_version'];
                $item['has_update'] = $meta['has_update'];
                $item['author_name'] = $meta['author'];
                $item['author_url'] = $meta['author_uri'];
                $item['component_status'] = $meta['status_label'];
                $item['last_updated'] = $meta['last_modified'];
                $item['has_changelog'] = $meta['has_changelog'];
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
            elseif (preg_match('/comment[:_#]?\s*(\d+)/i', $filePath, $matches) || $engine === 'content-comments' || strpos($filePath, 'comment:') === 0) {
                $commentId = !empty($matches[1]) ? (int) $matches[1] : 0;
                $comment = $commentId > 0 ? get_comment($commentId) : null;
                $item['is_comment'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['comment_id'] = $commentId;

                if ($comment) {
                    $item['author_id'] = (int) $comment->user_id;
                    $item['author_name'] = $comment->comment_author ?: __('(Anonymous)', 'wcp-security-scanner');
                    $item['author_email'] = $comment->comment_author_email ?: '';
                    $item['author_url'] = $comment->comment_author_url ?: '';
                    $item['author_ip'] = $comment->comment_author_IP ?: '';
                    $item['comment_date'] = $comment->comment_date ?: '';
                    $item['comment_content'] = $comment->comment_content ?: '';
                    if (empty($item['code_snippet'])) {
                        $item['code_snippet'] = $comment->comment_content ?: '';
                    }
                    $postId = (int) $comment->comment_post_ID;
                    $item['post_id'] = $postId;
                    $item['post_title'] = $postId > 0 ? (get_the_title($postId) ?: __('(Untitled Post)', 'wcp-security-scanner')) : '';
                    $item['post_url'] = $postId > 0 ? (get_permalink($postId) ?: '') : '';
                    $item['view_url'] = get_comment_link($comment) ?: '';
                    $item['edit_url'] = admin_url("comment.php?action=editcomment&c={$commentId}");
                } else {
                    $item['author_id'] = 0;
                    $item['author_name'] = preg_match('/by\s+(.+)$/i', $filePath, $am) ? trim($am[1]) : __('Unknown Author', 'wcp-security-scanner');
                    $item['author_email'] = '';
                    $item['author_url'] = '';
                    $item['author_ip'] = '';
                    $item['comment_date'] = '';
                    $item['comment_content'] = $item['code_snippet'] ?? '';
                    $item['post_id'] = 0;
                    $item['post_title'] = '';
                    $item['post_url'] = '';
                    $item['view_url'] = '';
                    $item['edit_url'] = $commentId > 0 ? admin_url("comment.php?action=editcomment&c={$commentId}") : '';
                }
            } 
            // 3. Check if finding is a WordPress User Account
            elseif (
                preg_match('/(?:^user:|_users:user_id_|users\.ID\s*=\s*)(\d+)/i', $filePath, $userMatches) ||
                preg_match('/User ID:\s*(\d+)/i', $item['evidence'] ?? '', $userMatches) ||
                $engine === 'wordpress-users' ||
                strpos($filePath, 'user:') === 0 ||
                strpos($filePath, '_users:user_id_') !== false ||
                strpos($type, 'user_') === 0 ||
                in_array($type, ['rogue_admin_user', 'hidden_admin_user', 'elevated_privilege_user', 'suspicious_user_capabilities', 'tampered_role_definition', 'generic_admin_username', 'weak_password_detected', 'username_enumeration_risk', 'user_missing_capabilities'], true)
            ) {
                $userId = 0;
                if (!empty($userMatches[1])) {
                    $userId = (int) $userMatches[1];
                } elseif (preg_match('/(?:^user:|_users:user_id_|users\.ID\s*=\s*)(\d+)/i', $filePath, $m)) {
                    $userId = (int) $m[1];
                } elseif (preg_match('/User ID:\s*(\d+)/i', $item['evidence'] ?? '', $m)) {
                    $userId = (int) $m[1];
                }

                $user = $userId > 0 ? get_userdata($userId) : null;
                $item['is_user'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['user_id'] = $userId;
                $item['user_login'] = $user ? $user->user_login : (preg_match('/\(([^)]+)\)/', $filePath, $m) ? $m[1] : (preg_match('/User\s*\'([^\']+)\'/i', $item['description'] ?? '', $m) ? $m[1] : 'user'));
                $item['user_email'] = $user ? $user->user_email : (preg_match('/Email:\s*([^,\s]+)/i', $item['evidence'] ?? '', $m) ? $m[1] : '');
                $item['user_registered'] = $user ? $user->user_registered : (preg_match('/Registered:\s*([^,\n]+)/i', $item['evidence'] ?? '', $m) ? trim($m[1]) : '');
                $item['user_display_name'] = $user ? $user->display_name : $item['user_login'];
                $current_user_id = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                $is_current_user = ($userId > 0 && $userId === $current_user_id);
                $is_admin = ($user && in_array('administrator', (array) $user->roles, true));

                $item['is_current_user'] = $is_current_user;
                $item['is_admin'] = $is_admin;
                $item['profile_url'] = $is_current_user ? admin_url('profile.php') : ($userId > 0 ? admin_url("user-edit.php?user_id={$userId}") : admin_url('users.php'));
                $item['password_url'] = $is_current_user ? admin_url('profile.php#password') : ($userId > 0 ? admin_url("user-edit.php?user_id={$userId}#password") : admin_url('users.php'));
                $item['edit_url'] = $userId > 0 ? admin_url("user-edit.php?user_id={$userId}") : admin_url("users.php");

                // Injected custom capabilities inspection
                if ($userId > 0) {
                    global $wpdb;
                    $cap_key = $wpdb->prefix . 'capabilities';
                    $stored_caps = get_user_meta($userId, $cap_key, true);
                    $wp_roles = wp_roles();
                    $injected_caps = [];
                    if (is_array($stored_caps)) {
                        foreach ($stored_caps as $cap_name => $granted) {
                            if (!isset($wp_roles->roles[$cap_name])) {
                                $injected_caps[] = $cap_name;
                            }
                        }
                    }
                    $item['injected_caps'] = $injected_caps;
                }
            } 
            // 4. Check if finding is a Database Table Row
            elseif ($engine === 'database-table' || preg_match('/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i', $filePath)) {
                $tableName = '';
                $columnName = '';
                $rowId = null;

                if (preg_match('/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i', $filePath, $dbMatches)) {
                    $tableName = !empty($dbMatches[1]) ? $dbMatches[1] : '';
                    $columnName = !empty($dbMatches[2]) ? $dbMatches[2] : '';
                    $rowId = !empty($dbMatches[3]) ? (int) $dbMatches[3] : null;
                }
                if (!$rowId && preg_match('/\[ID:\s*(\d+)\]/i', $filePath, $idM)) {
                    $rowId = (int) $idM[1];
                }
                if (!$tableName && strpos($filePath, '.') !== false) {
                    $tableName = explode('.', $filePath)[0];
                }
                if (!$columnName && strpos($filePath, '.') !== false) {
                    $parts = explode('.', $filePath);
                    $columnName = explode(' ', $parts[1])[0];
                }

                $item['is_db_table'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['table_name'] = $tableName;
                $item['column_name'] = $columnName;
                $item['row_id'] = $rowId;
                $item['is_log_table'] = (bool) preg_match('/(log|logs|redirection|audit|history|stat|stats|traffic|404)/i', $tableName);

                // Pre-load full row data if available
                if ($tableName && $rowId) {
                    $mgr = new \WCP\Scanner\Database\DatabaseRemediationManager();
                    $dbRow = $mgr->get_row($tableName, $rowId);
                    if ($dbRow) {
                        $item['db_row'] = $dbRow;
                        $item['db_primary_key'] = $mgr->get_primary_key($tableName);
                        if (empty($item['code_snippet']) && isset($dbRow[$columnName])) {
                            $item['code_snippet'] = (string) $dbRow[$columnName];
                        }
                    }
                }
            }
            // 5. Otherwise treat as a Filesystem finding
            else {
                $cleanPath = ltrim(str_replace(['../', '..\\'], '', $filePath), '/\\');
                $fullPath = wp_normalize_path(ABSPATH . $cleanPath);

                if (!file_exists($fullPath) && file_exists($filePath)) {
                    $fullPath = wp_normalize_path($filePath);
                }

                $realPath = realpath($fullPath);
                $isInsideRoot = $realPath && \WCP\Scanner\Filesystem\PathValidator::is_inside_root($realPath, ABSPATH);

                $item['file_exists'] = $isInsideRoot && file_exists($realPath);
                if (!isset($item['is_dir'])) {
                    $item['is_dir'] = $item['file_exists'] && is_dir($realPath);
                }
                if (!isset($item['is_file'])) {
                    $item['is_file'] = $item['file_exists'] && is_file($realPath);
                }
                // Only allow viewing if it is a regular readable file (not a folder/directory)
                if (!isset($item['can_view'])) {
                    $item['can_view'] = !empty($item['is_file']) && is_readable($realPath);
                }
            }

            // Attach component forensics for any theme or plugin finding if not already populated
            if (empty($item['component_meta']) && !empty($filePath)) {
                if (strpos($filePath, '/themes/') !== false || strpos($filePath, '\\themes\\') !== false) {
                    if (preg_match('#[\\\\/]wp-content[\\\\/]themes[\\\\/]([^\\\\/]+)#i', $filePath, $tm)) {
                        $theme_root = function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes');
                        $theme_dir = wp_normalize_path($theme_root . '/' . $tm[1]);
                        if (is_dir($theme_dir)) {
                            $item['component_meta'] = self::get_theme_forensics_meta($theme_dir, ['theme_slug' => $tm[1]]);
                        }
                    }
                } elseif (strpos($filePath, '/plugins/') !== false || strpos($filePath, '\\plugins\\') !== false) {
                    if (preg_match('#[\\\\/]wp-content[\\\\/]plugins[\\\\/]([^\\\\/]+)#i', $filePath, $pm)) {
                        $plugin_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $pm[1]);
                        if (is_dir($plugin_dir)) {
                            $item['component_meta'] = self::get_plugin_forensics_meta($plugin_dir, ['plugin_dir' => $pm[1]]);
                        }
                    }
                }
            }
        }
        unset($item);

        // Deduplicate identical issues by unique signature
        $deduped = [];
        $seen_signatures = [];
        foreach ($issues as $entry) {
            $sig = ($entry['engine'] ?? '') . '|' . ($entry['type'] ?? '') . '|' . ($entry['file_path'] ?? '') . '|' . ($entry['line_number'] ?? '') . '|' . ($entry['description'] ?? '');
            if (isset($seen_signatures[$sig])) {
                continue;
            }
            $seen_signatures[$sig] = true;
            $deduped[] = $entry;
        }

        return $deduped;
    }

    /**
     * Extract deep forensic metadata for a WordPress theme directory.
     *
     * @param string $filePath
     * @param array $evidence_data
     * @return array
     */
    public static function get_theme_forensics_meta(string $filePath, array $evidence_data = []): array {
        if (!function_exists('wp_get_theme')) {
            require_once ABSPATH . 'wp-includes/theme.php';
        }

        $norm_path = wp_normalize_path($filePath);
        $theme_slug = !empty($evidence_data['theme_slug']) ? $evidence_data['theme_slug'] : basename($norm_path);
        $theme = wp_get_theme($theme_slug);

        // Fallback: check if directory exists even if slug slightly differed
        if (!$theme->exists() && file_exists($norm_path . '/style.css')) {
            $all_themes = function_exists('wp_get_themes') ? wp_get_themes() : [];
            foreach ($all_themes as $s => $t) {
                if (wp_normalize_path($t->get_stylesheet_directory()) === $norm_path) {
                    $theme = $t;
                    $theme_slug = $s;
                    break;
                }
            }
        }

        $name = $theme->exists() ? $theme->get('Name') : (!empty($evidence_data['theme_name']) ? $evidence_data['theme_name'] : $theme_slug);
        $version = $theme->exists() ? (string) $theme->get('Version') : (!empty($evidence_data['version']) ? (string) $evidence_data['version'] : '');
        $author = $theme->exists() ? wp_strip_all_tags($theme->get('Author')) : '';
        $author_uri = $theme->exists() ? (string) $theme->get('AuthorURI') : '';
        $theme_uri = $theme->exists() ? (string) $theme->get('ThemeURI') : '';
        $description = $theme->exists() ? wp_strip_all_tags($theme->get('Description')) : '';
        $requires_wp = $theme->exists() ? (string) $theme->get('RequiresWP') : '';
        $requires_php = $theme->exists() ? (string) $theme->get('RequiresPHP') : '';
        $text_domain = $theme->exists() ? (string) $theme->get('TextDomain') : '';

        // Active state detection
        $current_stylesheet = function_exists('get_stylesheet') ? get_stylesheet() : '';
        $current_template = function_exists('get_template') ? get_template() : '';
        $is_active_child = ($theme_slug === $current_stylesheet && $theme_slug !== $current_template);
        $is_active_parent = ($theme_slug === $current_template);
        $is_active = ($theme_slug === $current_stylesheet || $theme_slug === $current_template);

        $parent_obj = $theme->exists() ? $theme->parent() : null;
        $is_child = (bool) $parent_obj || !empty($evidence_data['is_child']) || strpos(strtolower($norm_path), '-child') !== false;
        $parent_name = $parent_obj ? $parent_obj->get('Name') : (!empty($evidence_data['parent_theme']) ? $evidence_data['parent_theme'] : null);
        $parent_version = $parent_obj ? (string) $parent_obj->get('Version') : null;

        if ($is_active_child) {
            $status_label = 'Active Child Theme';
        } elseif ($is_active_parent && $current_stylesheet !== $current_template) {
            $status_label = 'Active Parent Template';
        } elseif ($is_active) {
            $status_label = 'Active Theme';
        } else {
            $status_label = 'Inactive';
        }

        // Check latest version in update_themes transient
        $latest_version = null;
        $has_update = false;
        $update_package = '';
        $update_themes = get_site_transient('update_themes');
        if (!empty($update_themes->response[$theme_slug])) {
            $theme_update = (array) $update_themes->response[$theme_slug];
            $latest_version = $theme_update['new_version'] ?? null;
            $has_update = !empty($latest_version) && (!empty($version) ? version_compare($latest_version, $version, '>') : true);
            $update_package = $theme_update['package'] ?? '';
        } elseif (!empty($update_themes->checked[$theme_slug])) {
            $latest_version = $update_themes->checked[$theme_slug];
        }

        // File stats and timestamps
        $mtime = file_exists($norm_path) ? filemtime($norm_path) : (file_exists($norm_path . '/style.css') ? filemtime($norm_path . '/style.css') : 0);
        $last_updated = $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : 'Unknown';
        $last_updated_human = $mtime ? human_time_diff($mtime, current_time('timestamp', 1)) . ' ago' : 'Unknown';

        // Permissions
        $folder_perms = file_exists($norm_path) ? substr(sprintf('%o', fileperms($norm_path)), -4) : '0755';
        $style_css_path = $norm_path . '/style.css';
        $file_perms = file_exists($style_css_path) ? substr(sprintf('%o', fileperms($style_css_path)), -4) : '0644';

        // Check for changelog or readme file
        $changelog_info = self::detect_component_changelog($norm_path);

        return [
            'type'                => 'theme',
            'slug'                => $theme_slug,
            'name'                => $name,
            'version'             => $version,
            'latest_version'      => $latest_version,
            'has_update'          => $has_update,
            'update_package'      => !empty($update_package),
            'author'              => $author,
            'author_uri'          => $author_uri,
            'theme_uri'           => $theme_uri,
            'description'         => $description,
            'is_active'           => $is_active,
            'is_child'            => $is_child,
            'parent_name'         => $parent_name,
            'parent_version'      => $parent_version,
            'status_label'        => $status_label,
            'requires_wp'         => $requires_wp,
            'requires_php'        => $requires_php,
            'text_domain'         => $text_domain,
            'path'                => $norm_path,
            'last_modified'       => $last_updated,
            'last_modified_human' => $last_updated_human,
            'folder_perms'        => $folder_perms,
            'main_file_perms'     => $file_perms,
            'main_file'           => file_exists($style_css_path) ? 'style.css' : '',
            'has_changelog'       => $changelog_info['has_changelog'],
            'changelog_file'      => $changelog_info['filename'],
            'admin_url'           => admin_url('themes.php'),
        ];
    }

    /**
     * Extract deep forensic metadata for a WordPress plugin directory or file.
     *
     * @param string $filePath
     * @param array $evidence_data
     * @return array
     */
    public static function get_plugin_forensics_meta(string $filePath, array $evidence_data = []): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $norm_path = wp_normalize_path($filePath);

        $matched_file = '';
        $matched_data = [];

        // Check direct plugin_file from evidence_data first
        if (!empty($evidence_data['plugin_file']) && isset($all_plugins[$evidence_data['plugin_file']])) {
            $matched_file = $evidence_data['plugin_file'];
            $matched_data = $all_plugins[$matched_file];
        }

        if (empty($matched_file)) {
            $folder_name = !empty($evidence_data['plugin_dir']) ? $evidence_data['plugin_dir'] : basename($norm_path);
            foreach ($all_plugins as $plugin_file => $data) {
                $dir_name = dirname($plugin_file);
                if ($dir_name === $folder_name || $plugin_file === $folder_name) {
                    $matched_file = $plugin_file;
                    $matched_data = $data;
                    break;
                }
                $full_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $dir_name);
                if ($full_dir === $norm_path) {
                    $matched_file = $plugin_file;
                    $matched_data = $data;
                    break;
                }
            }
        }

        $name = !empty($matched_data['Name']) ? $matched_data['Name'] : (!empty($evidence_data['plugin_name']) ? $evidence_data['plugin_name'] : basename($norm_path));
        $version = !empty($matched_data['Version']) ? (string) $matched_data['Version'] : (!empty($evidence_data['version']) ? (string) $evidence_data['version'] : '');
        $author = !empty($matched_data['Author']) ? wp_strip_all_tags($matched_data['Author']) : '';
        $author_uri = (string) ($matched_data['AuthorURI'] ?? '');
        $plugin_uri = (string) ($matched_data['PluginURI'] ?? '');
        $description = !empty($matched_data['Description']) ? wp_strip_all_tags($matched_data['Description']) : '';
        $requires_wp = (string) ($matched_data['RequiresWP'] ?? '');
        $requires_php = (string) ($matched_data['RequiresPHP'] ?? '');
        $text_domain = (string) ($matched_data['TextDomain'] ?? '');

        // Active state detection
        $is_active = false;
        $network_active = false;
        if (!empty($matched_file) && function_exists('is_plugin_active')) {
            $is_active = is_plugin_active($matched_file);
            if (is_multisite() && function_exists('is_plugin_active_for_network')) {
                $network_active = is_plugin_active_for_network($matched_file);
                if ($network_active) {
                    $is_active = true;
                }
            }
        }

        if ($network_active) {
            $status_label = 'Network Active';
        } elseif ($is_active) {
            $status_label = 'Active';
        } else {
            $status_label = 'Inactive';
        }

        // Check latest version in update_plugins transient
        $latest_version = null;
        $has_update = false;
        $update_package = '';
        $update_plugins = get_site_transient('update_plugins');
        if (!empty($matched_file) && !empty($update_plugins->response[$matched_file])) {
            $plugin_update = $update_plugins->response[$matched_file];
            $latest_version = $plugin_update->new_version ?? null;
            $has_update = !empty($latest_version) && (!empty($version) ? version_compare($latest_version, $version, '>') : true);
            $update_package = $plugin_update->package ?? '';
        } elseif (!empty($matched_file) && !empty($update_plugins->no_update[$matched_file])) {
            $latest_version = $update_plugins->no_update[$matched_file]->new_version ?? $version;
        }

        // Timestamps
        $main_file_full = (!empty($matched_file) && file_exists(WP_PLUGIN_DIR . '/' . $matched_file)) ? wp_normalize_path(WP_PLUGIN_DIR . '/' . $matched_file) : '';
        $mtime = $main_file_full ? filemtime($main_file_full) : (file_exists($norm_path) ? filemtime($norm_path) : 0);
        $last_updated = $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : 'Unknown';
        $last_updated_human = $mtime ? human_time_diff($mtime, current_time('timestamp', 1)) . ' ago' : 'Unknown';

        // Permissions
        $folder_perms = file_exists($norm_path) ? substr(sprintf('%o', fileperms($norm_path)), -4) : '0755';
        $main_file_perms = $main_file_full ? substr(sprintf('%o', fileperms($main_file_full)), -4) : '0644';

        // Changelog detection
        $changelog_info = self::detect_component_changelog($norm_path);

        return [
            'type'                => 'plugin',
            'slug'                => !empty($matched_file) ? dirname($matched_file) : basename($norm_path),
            'plugin_file'         => $matched_file,
            'name'                => $name,
            'version'             => $version,
            'latest_version'      => $latest_version,
            'has_update'          => $has_update,
            'update_package'      => !empty($update_package),
            'author'              => $author,
            'author_uri'          => $author_uri,
            'plugin_uri'          => $plugin_uri,
            'description'         => $description,
            'is_active'           => $is_active,
            'network_active'      => $network_active,
            'status_label'        => $status_label,
            'requires_wp'         => $requires_wp,
            'requires_php'        => $requires_php,
            'text_domain'         => $text_domain,
            'path'                => $norm_path,
            'last_modified'       => $last_updated,
            'last_modified_human' => $last_updated_human,
            'folder_perms'        => $folder_perms,
            'main_file_perms'     => $main_file_perms,
            'main_file'           => $matched_file ? basename($matched_file) : '',
            'has_changelog'       => $changelog_info['has_changelog'],
            'changelog_file'      => $changelog_info['filename'],
            'admin_url'           => admin_url('plugins.php'),
        ];
    }

    /**
     * Inspect component folder for changelog or release history files.
     *
     * @param string $component_path
     * @return array
     */
    public static function detect_component_changelog(string $component_path): array {
        $candidates = [
            'changelog.txt', 'CHANGELOG.txt',
            'changelog.md', 'CHANGELOG.md',
            'readme.txt', 'README.txt',
            'readme.md', 'README.md',
            'history.md', 'HISTORY.md',
            'releases.md', 'RELEASES.md',
            'docs/changelog.txt', 'docs/CHANGELOG.md'
        ];

        foreach ($candidates as $cand) {
            $target = $component_path . '/' . $cand;
            if (file_exists($target) && is_readable($target) && is_file($target)) {
                return [
                    'has_changelog' => true,
                    'filename'      => basename($cand),
                    'full_path'     => wp_normalize_path($target)
                ];
            }
        }

        return [
            'has_changelog' => false,
            'filename'      => '',
            'full_path'     => ''
        ];
    }

    /**
     * Retrieve changelog content for a specific theme or plugin component.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response|\WP_Error
     */
    public static function get_component_changelog(\WP_REST_Request $request) {
        $raw_path = sanitize_text_field($request->get_param('path') ?: ($request->get_param('file_path') ?: ''));
        $slug = sanitize_text_field($request->get_param('slug') ?: '');
        $type = sanitize_key($request->get_param('type') ?: 'plugin'); // 'plugin' or 'theme'

        $target_dir = '';
        if (!empty($raw_path)) {
            $raw_path = str_replace(['../', '..\\'], '', $raw_path);
            if (file_exists($raw_path) && is_dir($raw_path)) {
                $target_dir = wp_normalize_path($raw_path);
            }
        }

        if (empty($target_dir) && !empty($slug)) {
            if ($type === 'theme') {
                $theme_root = function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes');
                $candidate = wp_normalize_path($theme_root . '/' . $slug);
                if (file_exists($candidate) && is_dir($candidate)) {
                    $target_dir = $candidate;
                }
            } else {
                $candidate = wp_normalize_path(WP_PLUGIN_DIR . '/' . $slug);
                if (file_exists($candidate) && is_dir($candidate)) {
                    $target_dir = $candidate;
                }
            }
        }

        if (empty($target_dir)) {
            return new \WP_Error('invalid_target', __('Theme or plugin directory could not be located.', 'wcp-security-scanner'), ['status' => 404]);
        }

        // Verify inside ABSPATH
        if (!PathValidator::is_inside_root($target_dir, ABSPATH)) {
            return new \WP_Error('forbidden_path', __('Access to this path is restricted.', 'wcp-security-scanner'), ['status' => 403]);
        }

        $changelog = self::detect_component_changelog($target_dir);
        if (!$changelog['has_changelog']) {
            return rest_ensure_response([
                'success'       => true,
                'has_changelog' => false,
                'message'       => __('No local changelog file (changelog.txt, readme.txt, or changelog.md) was found in this component directory.', 'wcp-security-scanner'),
                'content'       => '',
                'filename'      => '',
            ]);
        }

        $file_path = $changelog['full_path'];
        if (!PathValidator::is_inside_root($file_path, $target_dir)) {
            return new \WP_Error('forbidden_file', __('Access to changelog file is restricted.', 'wcp-security-scanner'), ['status' => 403]);
        }

        $max_bytes = 250 * 1024; // 250KB limit
        $content = file_get_contents($file_path, false, null, 0, $max_bytes);
        if ($content === false) {
            return new \WP_Error('read_failed', __('Failed to read changelog file.', 'wcp-security-scanner'), ['status' => 500]);
        }

        // Clean UTF-8
        if (function_exists('mb_check_encoding') && !mb_check_encoding($content, 'UTF-8')) {
            $content = mb_convert_encoding($content, 'UTF-8', 'ISO-8859-1');
        }

        return rest_ensure_response([
            'success'       => true,
            'has_changelog' => true,
            'filename'      => $changelog['filename'],
            'file_size'     => (int) filesize($file_path),
            'last_modified' => gmdate('Y-m-d H:i:s', filemtime($file_path)) . ' UTC',
            'content'       => $content,
        ]);
    }

    /**
     * Get high-precision current timestamp in WordPress local time.
     *
     * @return string e.g. "2026-10-12 01:10:12.345"
     */
    public static function now_fractional_mysql() {
        $micro = microtime(true);
        $seconds = (int) $micro;
        $millis = (int) round(($micro - $seconds) * 1000);
        if ($millis >= 1000) {
            $seconds++;
            $millis = 0;
        }
        $date_str = wp_date('Y-m-d H:i:s', $seconds);
        return sprintf('%s.%03d', $date_str, $millis);
    }

    /**
     * Formats duration in seconds or fractional seconds into human-readable representation.
     *
     * @param float $duration_secs Duration in seconds (e.g. 0.42, 1.85, 65.2)
     * @param int $duration_ms Duration in milliseconds (e.g. 420)
     * @return string e.g. "420ms", "1.85s", "1m 5s"
     */
    public static function format_duration_precise($duration_secs, $duration_ms = 0) {
        $ms = (int) $duration_ms;
        if ($ms <= 0 && $duration_secs > 0) {
            $ms = (int) round($duration_secs * 1000);
        }

        if ($ms < 1000 && $ms > 0) {
            return "{$ms}ms";
        }

        $secs = $duration_secs > 0 ? $duration_secs : round($ms / 1000, 2);
        if ($secs < 10) {
            return sprintf('%.2fs', $secs);
        } elseif ($secs < 60) {
            return sprintf('%.1fs', $secs);
        }

        $total_sec = (int) round($secs);
        $mins = floor($total_sec / 60);
        $rem_sec = $total_sec % 60;
        return "{$mins}m {$rem_sec}s";
    }

    /**
     * Build rich performance and system diagnostic telemetry for a scan.
     *
     * @param array $scan
     * @return array
     */
    public static function build_scan_diagnostics(array $scan) {
        $scan_id = (int) ($scan['id'] ?? 0);
        $cached_diag = $scan_id > 0 ? get_transient("wcp_scan_diag_{$scan_id}") : null;

        // Peak Memory
        $peak_bytes = memory_get_peak_usage(true);
        if ($cached_diag && !empty($cached_diag['peak_memory_bytes'])) {
            $peak_bytes = max($peak_bytes, (int) $cached_diag['peak_memory_bytes']);
        }
        $peak_mb = round($peak_bytes / (1024 * 1024), 2);

        // Memory Limit
        $memory_limit_raw = ini_get('memory_limit') ?: '256M';
        $limit_bytes = 256 * 1024 * 1024;
        if (preg_match('/^(\d+)(.)$/i', $memory_limit_raw, $m)) {
            $val = (int) $m[1];
            $unit = strtoupper($m[2]);
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }
        $memory_pct = $limit_bytes > 0 ? round(($peak_bytes / $limit_bytes) * 100, 1) : 0;

        // Accurate Duration & Throughput
        $duration_ms = (int) ($scan['duration_ms'] ?? 0);
        $duration_sec = isset($scan['duration']) ? (float) $scan['duration'] : 0.0;

        if ($duration_ms > 0) {
            $duration_sec = round($duration_ms / 1000, 3);
        } elseif ($duration_sec <= 0 && !empty($scan['started_at']) && !empty($scan['completed_at'])) {
            $start_dt = date_create_from_format('Y-m-d H:i:s.u', $scan['started_at']) ?: date_create($scan['started_at']);
            $end_dt = date_create_from_format('Y-m-d H:i:s.u', $scan['completed_at']) ?: date_create($scan['completed_at']);
            if ($start_dt && $end_dt) {
                $diff = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                if ($diff > 0) {
                    $duration_sec = round($diff, 3);
                    $duration_ms = (int) round($diff * 1000);
                }
            }
        } elseif ($duration_sec <= 0 && !empty($scan['created_at'])) {
            $created_dt = date_create($scan['created_at'], wp_timezone());
            if ($created_dt) {
                $now_dt = date_create('now', wp_timezone());
                $diff = $now_dt->getTimestamp() - $created_dt->getTimestamp();
                $duration_sec = max(0.1, (float) $diff);
                $duration_ms = (int) round($duration_sec * 1000);
            }
        }

        $duration_fmt = self::format_duration_precise($duration_sec, $duration_ms);
        $scanned_files = (int) ($scan['scanned_files'] ?? ($scan['total_files'] ?? 0));
        $effective_sec = max(0.1, $duration_sec);
        $files_per_sec = round($scanned_files / $effective_sec, 1);

        // CPU Load Average
        $cpu_load = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $cpu_load = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2)
                ];
            }
        }

        // Server & System Environment details
        $php_version = PHP_VERSION;
        $php_sapi = php_sapi_name();
        $server_os = php_uname('s') . ' ' . php_uname('r');
        $server_arch = php_uname('m');
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
        $max_execution_time = (int) ini_get('max_execution_time');
        $opcache_status = (extension_loaded('Zend OPcache') && ini_get('opcache.enable')) ? 'Enabled' : 'Disabled';

        // CPU Cores Detection
        $cpu_cores = null;
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            $cpu_cores = (int) $win_cores;
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                $cpu_cores = substr_count($cpuinfo, 'processor');
            }
        }

        global $wpdb;
        $db_version = $wpdb ? $wpdb->db_version() : null;
        $db_name = defined('DB_NAME') ? DB_NAME : null;

        return [
            'duration_seconds'       => round($duration_sec, 2),
            'duration_ms'            => $duration_ms,
            'duration_formatted'     => $duration_fmt,
            'peak_memory_mb'         => $peak_mb,
            'peak_memory_fmt'        => "{$peak_mb} MB",
            'memory_limit_raw'       => $memory_limit_raw,
            'memory_percent'         => $memory_pct,
            'scanned_files'          => $scanned_files,
            'total_files'            => (int) ($scan['total_files'] ?? 0),
            'files_per_second'       => $files_per_sec,
            'cpu_load'               => $cpu_load,
            'cpu_cores'              => $cpu_cores,
            'server_software'        => $server_software,
            'server_os'              => $server_os,
            'server_arch'            => $server_arch,
            'php_version'            => $php_version,
            'php_sapi'               => $php_sapi,
            'php_max_execution_time' => $max_execution_time,
            'database_version'       => $db_version,
            'database_name'          => $db_name,
            'wordpress_version'      => get_bloginfo('version'),
            'ssl_active'             => is_ssl(),
            'opcache_status'         => $opcache_status,
            'engines_active'         => 10,
        ];
    }

    /**
     * Compute real-time telemetry metrics (memory, CPU, speed, progress, system context)
     * during active scan execution for administrator visibility.
     *
     * @param float|null $batch_start_time
     * @param array|null $batch_ru_start
     * @param int $scanned_files
     * @param int $total_files
     * @param int $issues_found
     * @param float $elapsed_sec
     * @return array
     */
    public static function get_realtime_resource_stats($batch_start_time = null, $batch_ru_start = null, $scanned_files = 0, $total_files = 0, $issues_found = 0, $elapsed_sec = 0.0) {
        // 1. Memory Metrics
        $mem_bytes = memory_get_usage(true);
        $mem_peak_bytes = memory_get_peak_usage(true);
        $mem_mb = round($mem_bytes / (1024 * 1024), 1);
        $mem_peak_mb = round($mem_peak_bytes / (1024 * 1024), 1);

        $memory_limit_raw = ini_get('memory_limit') ?: '256M';
        $limit_bytes = 256 * 1024 * 1024;
        if ($memory_limit_raw === '-1') {
            $limit_bytes = 0; // unlimited
        } elseif (preg_match('/^(\d+)(.)$/i', $memory_limit_raw, $m)) {
            $val = (int) $m[1];
            $unit = strtoupper($m[2]);
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }

        $mem_percent = $limit_bytes > 0 ? round(($mem_bytes / $limit_bytes) * 100, 1) : 0.0;
        $mem_peak_percent = $limit_bytes > 0 ? round(($mem_peak_bytes / $limit_bytes) * 100, 1) : 0.0;
        $mem_free_mb = $limit_bytes > 0 ? max(0, round(($limit_bytes - $mem_bytes) / (1024 * 1024), 1)) : 9999.0;

        // 2. CPU / Load Metrics
        $cpu_percent = null;
        if ($batch_start_time && $batch_ru_start && function_exists('getrusage')) {
            $batch_wall_time = max(0.001, microtime(true) - $batch_start_time);
            $ru_end = @getrusage();
            if (is_array($ru_end) && is_array($batch_ru_start)) {
                $user_start = ($batch_ru_start['ru_utime.tv_sec'] ?? 0) + (($batch_ru_start['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_start  = ($batch_ru_start['ru_stime.tv_sec'] ?? 0) + (($batch_ru_start['ru_stime.tv_usec'] ?? 0) / 1000000);
                $user_end   = ($ru_end['ru_utime.tv_sec'] ?? 0) + (($ru_end['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_end    = ($ru_end['ru_stime.tv_sec'] ?? 0) + (($ru_end['ru_stime.tv_usec'] ?? 0) / 1000000);
                $cpu_time_used = max(0, ($user_end + $sys_end) - ($user_start + $sys_start));
                $cpu_percent = min(100.0, round(($cpu_time_used / $batch_wall_time) * 100, 1));
            }
        }

        $cpu_load = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $cpu_load = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2),
                ];
            }
        }

        $cpu_cores = null;
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            $cpu_cores = (int) $win_cores;
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                $cpu_cores = substr_count($cpuinfo, 'processor');
            }
        }

        // 3. Scan Throughput & ETA
        $files_per_sec = ($elapsed_sec > 0 && $scanned_files > 0) ? round($scanned_files / $elapsed_sec, 1) : 0.0;
        $remaining_files = max(0, $total_files - $scanned_files);
        $eta_seconds = ($files_per_sec > 0 && $remaining_files > 0) ? (int) round($remaining_files / $files_per_sec) : null;

        // 4. Server environment details
        $php_version = PHP_VERSION;
        $server_os = php_uname('s');
        $max_exec = (int) ini_get('max_execution_time');

        return [
            'memory_mb'           => $mem_mb,
            'memory_peak_mb'      => $mem_peak_mb,
            'memory_limit_raw'    => $memory_limit_raw,
            'memory_percent'      => $mem_percent,
            'memory_peak_percent' => $mem_peak_percent,
            'memory_free_mb'      => $mem_free_mb,
            'cpu_percent'         => $cpu_percent,
            'cpu_load'            => $cpu_load,
            'cpu_cores'           => $cpu_cores,
            'scanned_files'       => $scanned_files,
            'total_files'         => $total_files,
            'files_per_sec'       => $files_per_sec,
            'eta_seconds'         => $eta_seconds,
            'issues_found'        => $issues_found,
            'php_version'         => $php_version,
            'server_os'           => $server_os,
            'max_execution_time'  => $max_exec,
        ];
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

        // Canonical directory boundary check: Enforce trailing slash on root to eliminate sibling directory escapes
        if (!\WCP\Scanner\Filesystem\PathValidator::is_inside_root($target_full, ABSPATH)) {
            return new \WP_Error('forbidden_path', __('Access to this file path is restricted outside WordPress root.', 'wcp-security-scanner'), ['status' => 403]);
        }

        $real_path = realpath($target_full);
        if (!$real_path || !is_file($real_path)) {
            return new \WP_Error('not_a_file', __('The requested path is a directory or special file, not a viewable file.', 'wcp-security-scanner'), ['status' => 400]);
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
     * Helper to build schedule time info payload
     */
    public static function build_schedule_time_info() {
        $next_run_timestamp = wp_next_scheduled(\WCP\Scanner\System\SettingsManager::CRON_HOOK);
        $now_utc = time();
        $diff_seconds = $next_run_timestamp ? max(0, $next_run_timestamp - $now_utc) : 0;

        $tz_string = get_option('timezone_string');
        $gmt_offset = get_option('gmt_offset');
        if (empty($tz_string)) {
            $offset_sign = $gmt_offset >= 0 ? '+' : '-';
            $offset_hours = abs((int) $gmt_offset);
            $offset_mins = abs((int) (($gmt_offset - (int) $gmt_offset) * 60));
            $tz_string = sprintf('UTC%s%02d:%02d', $offset_sign, $offset_hours, $offset_mins);
        }

        $is_cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;

        return [
            'next_run_timestamp' => $next_run_timestamp ?: null,
            'next_scheduled_wp'  => $next_run_timestamp ? (function_exists('wp_date') ? wp_date('Y-m-d H:i:s', $next_run_timestamp) : date_i18n('Y-m-d H:i:s', $next_run_timestamp + (int) ($gmt_offset * 3600))) : null,
            'next_scheduled_gmt' => $next_run_timestamp ? gmdate('Y-m-d H:i:s', $next_run_timestamp) . ' GMT' : null,
            'diff_seconds'       => $diff_seconds,
            'current_wp_time'    => current_time('Y-m-d H:i:s'),
            'current_gmt_time'   => gmdate('Y-m-d H:i:s') . ' GMT',
            'timezone'           => $tz_string,
            'gmt_offset'         => (float) $gmt_offset,
            'cron_disabled'      => $is_cron_disabled,
        ];
    }

    /**
     * Get plugin settings
     */
    public static function get_settings(\WP_REST_Request $request) {
        $settings = \WCP\Scanner\System\SettingsManager::get_settings();
        $time_info = self::build_schedule_time_info();

        return rest_ensure_response([
            'success'        => true,
            'settings'       => $settings,
            'next_scheduled' => $time_info['next_scheduled_wp'],
            'schedule_time'  => $time_info,
            'current_time'   => $time_info['current_wp_time'],
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
        $time_info = self::build_schedule_time_info();

        return rest_ensure_response([
            'success'        => true,
            'message'        => __('Settings successfully saved.', 'wcp-security-scanner'),
            'settings'       => $saved,
            'next_scheduled' => $time_info['next_scheduled_wp'],
            'schedule_time'  => $time_info,
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
     * Manually trigger the scheduled cron scan immediately (for test / on-demand cron execution)
     */
    public static function trigger_cron_now(\WP_REST_Request $request) {
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            return new \WP_Error(
                'scan_locked',
                sprintf(
                    /* translators: %d: active scan ID */
                    __('A scan is already actively running (ID: %d).', 'wcp-security-scanner'),
                    $locked_id
                ),
                ['status' => 409]
            );
        }

        // Run scheduled scan synchronously or trigger the hook
        try {
            \WCP\Scanner\System\Scheduler::run_scheduled_scan();
            return rest_ensure_response([
                'success' => true,
                'message' => __('Scheduled security scan was triggered and executed successfully.', 'wcp-security-scanner'),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('cron_trigger_failed', $e->getMessage(), ['status' => 500]);
        }
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
        $file_path = $request->get_param('file_path') ?: $request->get_param('path');
        if (empty($file_path)) {
            $json_params = $request->get_json_params();
            if (!empty($json_params['file_path'])) {
                $file_path = $json_params['file_path'];
            } elseif (!empty($json_params['path'])) {
                $file_path = $json_params['path'];
            }
        }

        if (empty($file_path)) {
            return new \WP_Error('missing_file_path', __('Missing required file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $file_path = sanitize_text_field(wp_unslash($file_path));

        // Support base64 encoded path to avoid WAF false positives on sensitive filenames in URL
        if (strpos($file_path, 'b64:') === 0) {
            $decoded = base64_decode(substr($file_path, 4), true);
            if ($decoded !== false && is_string($decoded)) {
                $file_path = $decoded;
            }
        } elseif (preg_match('/^[a-zA-Z0-9+\/]+=*$/', $file_path) && strlen($file_path) >= 8) {
            $decoded = base64_decode($file_path, true);
            if ($decoded !== false && is_string($decoded) && (strpos($decoded, '/') !== false || strpos($decoded, '\\') !== false || strpos($decoded, '.php') !== false)) {
                $file_path = $decoded;
            }
        }

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

    public static function remediate_restore_core(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WCP\Scanner\Remediation\RemediationManager();
        $result = $manager->restore_official_core_file($file_path, $issue_id);

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

    public static function remediate_delete_cron_hook(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $hook_name = !empty($params['hook_name']) ? sanitize_text_field(wp_unslash($params['hook_name'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($hook_name) && !empty($params['file_path'])) {
            $path = sanitize_text_field(wp_unslash($params['file_path']));
            if (strpos($path, 'cron:hook:') === 0) {
                $hook_name = substr($path, strlen('cron:hook:'));
            } else {
                $hook_name = $path;
            }
        }

        if (empty($hook_name)) {
            return new \WP_Error('missing_param', __('Missing hook_name parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        // Safety check: protect essential WordPress core cron hooks from being cleared
        $protected_core_crons = [
            'wp_version_check',
            'wp_update_plugins',
            'wp_update_themes',
            'recovery_mode_clean_expired_keys',
            'wp_scheduled_delete',
            'delete_expired_transients',
            'wp_privacy_delete_old_export_files',
        ];

        if (in_array($hook_name, $protected_core_crons, true)) {
            return new \WP_Error('protected_core_hook', __('Cannot delete essential WordPress core system cron hooks.', 'wcp-security-scanner'), ['status' => 403]);
        }

        // Clear all scheduled instances of this cron hook
        $cleared = wp_clear_scheduled_hook($hook_name);

        if ($issue_id) {
            global $wpdb;
            $table = $wpdb->prefix . 'wcp_scan_issues';
            $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(__('Scheduled cron hook "%s" was successfully removed from the WordPress database.', 'wcp-security-scanner'), $hook_name),
            'cleared' => $cleared,
            'hook'    => $hook_name,
        ]);
    }

    /**
     * Moderate or delete a spam/malicious WordPress comment.
     */
    public static function moderate_comment(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $comment_id = !empty($params['comment_id']) ? (int) $params['comment_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (!$comment_id) {
            return new \WP_Error('missing_comment_id', __('Valid comment ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $comment = get_comment($comment_id);
        if (!$comment && $action !== 'delete') {
            return new \WP_Error('comment_not_found', __('Comment not found or already deleted.', 'wcp-security-scanner'), ['status' => 404]);
        }

        $success = false;
        $message = '';

        switch ($action) {
            case 'trash':
                $success = (bool) wp_trash_comment($comment_id);
                $message = sprintf(__('Comment #%d has been moved to Trash (quarantined from public view).', 'wcp-security-scanner'), $comment_id);
                break;

            case 'spam':
                $success = (bool) wp_spam_comment($comment_id);
                $message = sprintf(__('Comment #%d has been marked as Spam and delisted.', 'wcp-security-scanner'), $comment_id);
                break;

            case 'delete':
                $success = (bool) wp_delete_comment($comment_id, true);
                $message = sprintf(__('Comment #%d has been permanently deleted from the database.', 'wcp-security-scanner'), $comment_id);
                break;

            case 'approve':
                $success = (bool) wp_set_comment_status($comment_id, 'approve');
                $message = sprintf(__('Comment #%d status updated to approved.', 'wcp-security-scanner'), $comment_id);
                break;

            default:
                return new \WP_Error('invalid_action', __('Invalid moderation action. Supported: trash, spam, delete.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if ($success) {
            global $wpdb;
            $table = $wpdb->prefix . 'wcp_scan_issues';
            if ($issue_id) {
                $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
            }
            // Mark all open findings associated with this comment as solved/repaired
            $wpdb->query($wpdb->prepare(
                "UPDATE {$table} SET status = 'repaired' WHERE (file_path LIKE %s OR file_path = %s) AND status = 'open'",
                "comment:{$comment_id}%",
                "comment:{$comment_id}"
            ));
        }

        return rest_ensure_response([
            'success'    => $success,
            'message'    => $message,
            'action'     => $action,
            'comment_id' => $comment_id,
        ]);
    }

    /**
     * Database Row Remediation (Delete row or cleanse field with auto-backup snapshot)
     */
    public static function remediate_database_row(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $table = !empty($params['table']) ? sanitize_text_field($params['table']) : '';
        $column = !empty($params['column']) ? sanitize_text_field($params['column']) : '';
        $row_id = !empty($params['row_id']) ? sanitize_text_field($params['row_id']) : '';
        $action = !empty($params['action']) ? sanitize_key($params['action']) : 'delete_row';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table name and Row ID are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WCP\Scanner\Database\DatabaseRemediationManager();

        if ($action === 'delete_row') {
            $result = $mgr->delete_row_with_backup($table, $row_id, $column, $issue_id);
        } elseif ($action === 'cleanse_field') {
            if (empty($column)) {
                return new \WP_Error('missing_column', __('Column name is required for field cleansing.', 'wcp-security-scanner'), ['status' => 400]);
            }
            $result = $mgr->cleanse_field_with_backup($table, $column, $row_id, $issue_id);
        } else {
            return new \WP_Error('invalid_action', __('Invalid database remediation action.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!$result['success']) {
            return new \WP_Error('db_remediation_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Get Database Row Data for Live Forensic Inspection
     */
    public static function get_database_row(\WP_REST_Request $request) {
        $table = sanitize_text_field($request->get_param('table') ?: '');
        $row_id = sanitize_text_field($request->get_param('row_id') ?: '');

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table and Row ID are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WCP\Scanner\Database\DatabaseRemediationManager();
        $pk = $mgr->get_primary_key($table);
        $row = $mgr->get_row($table, $row_id);

        if (!$row) {
            return new \WP_Error('row_not_found', __('Database record not found or already deleted.', 'wcp-security-scanner'), ['status' => 404]);
        }

        $is_log_table = (bool) preg_match('/(log|logs|redirection|audit|history|stat|stats|traffic|404)/i', $table);

        return rest_ensure_response([
            'success'      => true,
            'table'        => $table,
            'row_id'       => $row_id,
            'primary_key'  => $pk,
            'is_log_table' => $is_log_table,
            'row'          => $row,
            'data'         => [
                'table'        => $table,
                'row_id'       => $row_id,
                'primary_key'  => $pk,
                'is_log_table' => $is_log_table,
                'row'          => $row,
            ],
        ]);
    }

    /**
     * Restore Database Row from Auto-Backup Snapshot
     */
    public static function restore_database_row(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field($params['backup_id']) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_backup_id', __('Backup ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WCP\Scanner\Database\DatabaseRemediationManager();
        $result = $mgr->restore_backup($backup_id);

        if (!$result['success']) {
            return new \WP_Error('db_restore_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Remediate User Account / Capabilities Anomaly
     *
     * Actions:
     * - 'assign_default_role': Assigns default role (subscriber) to user missing capabilities.
     * - 'strip_capabilities': Strips unauthorized/trojan capabilities from non-admin accounts.
     * - 'delete_user': Safely deletes anomalous/ghost account with mandatory pre-action snapshot.
     */
    public static function remediate_user(\WP_REST_Request $request) {
        global $wpdb;

        $params = $request->get_json_params() ?: [];
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $role = !empty($params['role']) ? sanitize_key($params['role']) : null;
        $reassign_to = !empty($params['reassign_to']) ? (int) $params['reassign_to'] : null;
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if ($user_id <= 0) {
            return new \WP_Error('invalid_user_id', __('Valid User ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WCP\Scanner\WordPress\UserRemediationManager();

        if ($action === 'assign_default_role') {
            $result = $mgr->assign_default_role($user_id, $role);
        } elseif ($action === 'strip_capabilities') {
            $result = $mgr->strip_injected_capabilities($user_id);
        } elseif ($action === 'delete_user') {
            $result = $mgr->delete_user($user_id, $reassign_to);
        } else {
            return new \WP_Error('invalid_action', __('Invalid user remediation action.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            return new \WP_Error('remediation_failed', $result['error'] ?? __('User remediation failed.', 'wcp-security-scanner'), ['status' => 500]);
        }

        // Mark associated scan issue as repaired if issue_id is provided
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        if ($issue_id > 0) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        // Also mark open issues for this user account as repaired
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query($wpdb->prepare(
            "UPDATE `{$table_issues}` SET status = 'repaired' WHERE (file_path LIKE %s OR file_path LIKE %s OR file_path LIKE %s) AND status = 'open'",
            "user:{$user_id}%",
            "%_users:user_id_{$user_id}%",
            "%users.ID = {$user_id}%"
        ));

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
            'auth_2fa_enabled'          => !empty($settings['auth_2fa_enabled']),
            'auth_2fa_remember_device'  => !empty($settings['auth_2fa_remember_device']),
            'auth_2fa_remember_days'    => (int) ($settings['auth_2fa_remember_days'] ?? 7),
            'login_hardening_enabled'   => !empty($settings['login_hardening_enabled']),
            'login_max_retries'         => (int) ($settings['login_max_retries'] ?? 5),
            'login_lockout_duration'    => (int) ($settings['login_lockout_duration'] ?? 15),
            'session_sentinel_enabled'  => !empty($settings['session_sentinel_enabled']),
            'session_block_concurrent'  => !empty($settings['session_block_concurrent']),
            'session_lock_ip'           => !empty($settings['session_lock_ip']),
            'session_idle_timeout'      => (int) ($settings['session_idle_timeout'] ?? 120),
            'user_2fa_enabled'          => \WCP\Scanner\Auth\TwoFactorAuth::is_user_enabled($user_id),
            'user_login'                => $user ? $user->user_login : '',
            'user_email'                => $user ? $user->user_email : '',
            'trusted_devices_count'     => count(\WCP\Scanner\Auth\TwoFactorAuth::get_trusted_devices($user_id)),
            'trusted_devices'           => \WCP\Scanner\Auth\TwoFactorAuth::get_trusted_devices($user_id),
            'lockouts'                  => array_values(\WCP\Scanner\Auth\LoginHardening::get_locked_ips()),
            'stats'                     => \WCP\Scanner\Auth\LoginHardening::get_stats(),
            'active_sessions'           => \WCP\Scanner\Auth\SessionSentinel::get_active_sessions(),
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
     * Auth Security: Revoke All Trusted Devices
     */
    public static function revoke_2fa_trusted_devices() {
        $user_id = get_current_user_id();
        \WCP\Scanner\Auth\TwoFactorAuth::revoke_all_trusted_devices($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('All remembered/trusted devices have been revoked. 2FA verification will be required on all browsers.', 'wcp-security-scanner'),
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
     * Helper to load CloudflareService reliably
     */
    private static function ensure_cloudflare_service(): bool {
        if (!class_exists('\WCP\Scanner\Cloudflare\CloudflareService')) {
            $candidates = [
                WCP_SCANNER_PATH . 'includes/Cloudflare/CloudflareService.php',
                WCP_SCANNER_PATH . 'includes/cloudflare/CloudflareService.php',
                WCP_SCANNER_PATH . 'includes/Firewall/CloudflareService.php',
            ];
            foreach ($candidates as $file) {
                if (file_exists($file)) {
                    require_once $file;
                    break;
                }
            }
        }
        return class_exists('\WCP\Scanner\Cloudflare\CloudflareService');
    }

    /**
     * Cloudflare Edge Defense Handlers
     */
    public static function get_cloudflare_status(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $status = \WCP\Scanner\Cloudflare\CloudflareService::get_status();
        $definitions = \WCP\Scanner\Cloudflare\CloudflareService::get_rule_definitions();
        return rest_ensure_response([
            'success'     => true,
            'status'      => $status,
            'definitions' => $definitions,
        ]);
    }

    public static function verify_cloudflare_credentials(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation. Please reinstall or update the plugin zip.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $token   = !empty($params['token']) ? trim(sanitize_text_field($params['token'])) : null;
        $zone_id = !empty($params['zone_id']) ? trim(sanitize_text_field($params['zone_id'])) : null;

        $result = \WCP\Scanner\Cloudflare\CloudflareService::verify_zone($zone_id, $token);
        return rest_ensure_response($result);
    }

    public static function deploy_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $rules  = is_array($params['rules'] ?? null) ? $params['rules'] : [];

        $result = \WCP\Scanner\Cloudflare\CloudflareService::deploy_custom_rules($rules);
        return rest_ensure_response($result);
    }

    public static function toggle_cloudflare_rate_limiting(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $enable = !empty($params['enabled']);

        $result = \WCP\Scanner\Cloudflare\CloudflareService::toggle_rate_limiting($enable);
        return rest_ensure_response($result);
    }

    public static function block_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Manual block via Security Scanner');

        $result = \WCP\Scanner\Cloudflare\CloudflareService::block_ip($ip, $reason);
        return rest_ensure_response($result);
    }

    public static function purge_cloudflare_cache(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $files  = !empty($params['files']) && is_array($params['files']) ? array_map('esc_url_raw', $params['files']) : null;

        $result = \WCP\Scanner\Cloudflare\CloudflareService::purge_cache($files);
        return rest_ensure_response($result);
    }

    public static function disconnect_cloudflare(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $result = \WCP\Scanner\Cloudflare\CloudflareService::disconnect();
        return rest_ensure_response($result);
    }
}
