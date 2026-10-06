<?php
namespace WCP\Scanner\Api;

use WCP\Scanner\Scanner\Engine;
use WCP\Scanner\Filesystem\FileScanner;
use WCP\Scanner\Integrity\CoreIntegrity;
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
use WCP\Scanner\Scan\ScanLock;
use WCP\Scanner\Filesystem\UploadsScanner;
use WCP\Scanner\WordPress\CronScanner;

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

        register_rest_route(self::NAMESPACE, '/quarantine', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'list_quarantine'],
            'permission_callback' => $permission,
        ]);
    }

    public static function start_scan(\WP_REST_Request $request) {
        global $wpdb;

        // Check for concurrent active scan lock
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            $table_scans = $wpdb->prefix . 'wcp_scans';
            $existing_scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_scans} WHERE id = %d", $locked_id), ARRAY_A);
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
        if (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity'], true)) {
            // Targeted deep engines do not queue filesystem files
            $all_files = [];
        } elseif ($target === 'filesystem_only' || $target === 'full') {
            $paths[] = untrailingslashit(ABSPATH);
            foreach ($paths as $path) {
                $all_files = array_merge($all_files, Engine::get_scannable_files($path, 3000));
            }
        } else { // default plugins_themes
            $paths[] = WP_CONTENT_DIR . '/plugins';
            $paths[] = WP_CONTENT_DIR . '/themes';
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
            $rel_path = str_replace(untrailingslashit(ABSPATH) . '/', '', str_replace('\\', '/', $filepath));
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
        $current_issues_total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table_issues WHERE scan_id = %d", $scan_id
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
        $scan_row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_scans} WHERE id = %d", $scan_id), ARRAY_A);
        if ($scan_row && $scan_row['status'] === 'completed') {
            $all_scan_issues = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$table_issues} WHERE scan_id = %d", $scan_id
            ), ARRAY_A);
            $scorer = new RiskScorer();
            $summary = $scorer->calculate($all_scan_issues);
            return rest_ensure_response([
                'success' => true,
                'summary' => $summary,
                'status'  => 'completed'
            ]);
        }

        if (empty($target)) {
            $target = $scan_row ? ($scan_row['scan_target'] ?? 'plugins_themes') : 'plugins_themes';
        }

        $all_deep_findings = [];

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
        } elseif ($target === 'filesystem_only') {
            // Filesystem-only scan: no additional deep audit engines needed
        } else {
            // Full or plugins_themes: run all engines
            $core_integrity = new CoreIntegrity();
            $plugin_integrity = new PluginIntegrity();
            $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
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
                'code_snippet' => $item['code_snippet'] ?? null,
                'evidence'     => $item['evidence'] ?? null,
                'description'  => $item['description'],
                'status'       => 'open',
                'created_at'   => current_time('mysql'),
            ]);
        }

        // Calculate final risk score across all findings
        $all_scan_issues = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_issues} WHERE scan_id = %d", $scan_id
        ), ARRAY_A);

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($all_scan_issues);

        $scan_row = $wpdb->get_row($wpdb->prepare("SELECT created_at FROM {$table_scans} WHERE id = %d", $scan_id), ARRAY_A);
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
            'status'      => 'completed'
        ]);
    }

    public static function get_latest_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        $table_files = $wpdb->prefix . 'wcp_scan_files';

        $latest_scan = $wpdb->get_row("SELECT * FROM $table_scans ORDER BY id DESC LIMIT 1", ARRAY_A);
        if (!$latest_scan) {
            return rest_ensure_response([
                'has_scan' => false,
                'scan'     => null,
                'summary'  => null,
                'issues'   => [],
                'files'    => [],
            ]);
        }

        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table_issues WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC",
            $latest_scan['id']
        ), ARRAY_A);

        $scanned_files = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table_files WHERE scan_id = %d ORDER BY id ASC",
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
        $history = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM $table_scans ORDER BY id DESC LIMIT %d", $limit),
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

        $wpdb->query("TRUNCATE TABLE $table_scans");
        $wpdb->query("TRUNCATE TABLE $table_issues");
        $wpdb->query("TRUNCATE TABLE $table_files");

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

        $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_scans WHERE id = %d", $scan_id), ARRAY_A);
        if (!$scan) {
            return new \WP_Error('scan_not_found', 'Scan log not found', ['status' => 404]);
        }

        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table_issues WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC",
            $scan_id
        ), ARRAY_A);

        $files_count = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table_files WHERE scan_id = %d", $scan_id));

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
            $wpdb->query("UPDATE {$table_scans} SET status = 'interrupted', completed_at = NOW() WHERE status = 'running'");
            return rest_ensure_response([
                'is_running' => false,
            ]);
        }

        $running_scan = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_scans} WHERE id = %d",
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
        $wpdb->query("UPDATE {$table_scans} SET status = 'aborted', completed_at = NOW() WHERE status = 'running'");

        return rest_ensure_response([
            'success' => true,
            'message' => 'Scan successfully aborted and lock released.',
        ]);
    }
}
