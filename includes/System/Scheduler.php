<?php
namespace WcpScanner\System;

use WcpScanner\Scanner\Engine;
use WcpScanner\Findings\CorrelationEngine;
use WcpScanner\Findings\RiskScorer;
use WcpScanner\Scan\ScanLock;

if (!defined('ABSPATH')) {
    exit;
}

class Scheduler {
    const CRON_HOOK = 'wcpscan_scheduled_scan_event';

    public static function register() {
        add_action(self::CRON_HOOK, [__CLASS__, 'run_scheduled_scan']);

        // Custom cron intervals (e.g., weekly)
        add_filter('cron_schedules', function ($schedules) {
            if (!isset($schedules['weekly'])) {
                $schedules['weekly'] = [
                    'interval' => 7 * DAY_IN_SECONDS,
                    'display'  => __('Once Weekly', 'wcp-security-scanner'),
                ];
            }
            return $schedules;
        });
    }

    /**
     * Executes background scheduled scan
     */
     public static function run_scheduled_scan() {
         global $wpdb;

         $settings = SettingsManager::get_settings();
         if (empty($settings['schedule_enabled'])) {
             return;
         }

         // Prevent execution timeouts and memory exhaustion during cron execution
         if (function_exists('set_time_limit')) {
             @set_time_limit(0);
         }
         $mem_limit = !empty($settings['memory_limit_override']) ? $settings['memory_limit_override'] : '512M';
         @ini_set('memory_limit', $mem_limit);

         $target = $settings['schedule_scan_type'] ?? 'plugins_themes';
         $table_scans = $wpdb->prefix . 'wcpscan_scans';
         $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
         $table_files = $wpdb->prefix . 'wcpscan_scan_files';

         // 1. Discover filesystem files (0 = unlimited)
         $files = [];
         $file_limit = (int) apply_filters('wcpscan_file_limit', 0, $target);

         if (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity', 'rogue_admin', 'hook_sentinel'], true)) {
             $files = [];
         } elseif ($target === 'filesystem_only' || $target === 'full') {
             $paths = [untrailingslashit(ABSPATH)];
             foreach ($paths as $p) {
                 $files = array_merge($files, Engine::get_scannable_files($p, $file_limit));
             }
         } else {
             // plugins_themes
             $paths = [WP_PLUGIN_DIR, get_theme_root()];
             foreach ($paths as $p) {
                 $files = array_merge($files, Engine::get_scannable_files($p, $file_limit));
             }
         }

         $now_exact = \WcpScanner\Api\ScannerRoutes::now_fractional_mysql();
         $start_time = microtime(true);

         // Insert scan record
         $wpdb->insert($table_scans, [
             'status'        => 'running',
             'scan_target'   => $target,
             'trigger_type'  => 'scheduled',
             'scanned_files' => 0,
             'total_files'   => count($files),
             'issues_found'  => 0,
             'risk_score'    => 0,
             'duration'      => 0,
             'duration_ms'   => 0,
             'created_at'    => current_time('mysql'),
             'started_at'    => $now_exact,
         ]);
         $scan_id = (int) $wpdb->insert_id;

         // Acquire exclusive scan lock so dashboard doesn't mark it interrupted
         ScanLock::acquire($scan_id);
         set_transient("wcpscan_scan_start_micro_{$scan_id}", $start_time, HOUR_IN_SECONDS);

         try {
             $scanned_count = 0;
             $file_scanner = new \WcpScanner\Filesystem\FileScanner();

             // 2. Scan discovered filesystem files
             foreach ($files as $idx => $filepath) {
                 // Refresh lock heartbeat and persist progress count every 15 files
                 if ($idx > 0 && $idx % 15 === 0) {
                     \WcpScanner\Scan\ScanLock::heartbeat($scan_id);
                     $wpdb->update($table_scans, [
                         'scanned_files' => $scanned_count,
                     ], ['id' => $scan_id]);
                     set_transient("wcpscan_active_scan_file_{$scan_id}", $filepath, 120);
                 }

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
                     $item = is_array($f) ? $f : (method_exists($f, 'to_array') ? $f->to_array() : (array) $f);
                     $wpdb->insert($table_issues, [
                         'scan_id'      => $scan_id,
                         'engine'       => $item['engine'] ?? 'filesystem',
                         'type'         => $item['type'] ?? 'malware_heuristic',
                         'severity'     => $item['severity'] ?? 'medium',
                         'confidence'   => $item['confidence'] ?? 100,
                         'file_path'    => $item['file_path'] ?? $rel_path,
                         'line_number'  => $item['line_number'] ?? null,
                         'code_snippet' => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($item['code_snippet'] ?? null),
                         'evidence'     => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($item['evidence'] ?? null),
                         'description'  => $item['description'] ?? '',
                         'status'       => 'open',
                         'created_at'   => current_time('mysql'),
                     ]);
                 }

                 $scanned_count++;
             }

             // 3. Run target-specific deep audit engines
             \WcpScanner\Scan\ScanLock::heartbeat($scan_id);
             $all_deep_findings = [];

             if ($target === 'unknown_files') {
                 $core_integrity = new \WcpScanner\Integrity\CoreIntegrity();
                 $plugin_integrity = new \WcpScanner\Integrity\PluginIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                 $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                 $all_deep_findings = array_filter($all_deep_findings, function ($f) {
                     $arr = is_array($f) ? $f : (method_exists($f, 'to_array') ? $f->to_array() : (array) $f);
                     return in_array($arr['type'] ?? '', ['unknown_core_file', 'unknown_plugin_file'], true);
                 });
             } elseif ($target === 'spam_content') {
                 $content = new \WcpScanner\Content\ContentScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $content->scan((string) $scan_id, 300));
             } elseif ($target === 'user_security') {
                 $user_scanner = new \WcpScanner\WordPress\UserScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, false));
             } elseif ($target === 'outdated_software') {
                 $update_scanner = new \WcpScanner\WordPress\UpdateScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
             } elseif ($target === 'suspicious_uploads') {
                 $uploads = new \WcpScanner\Filesystem\UploadsScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $uploads->scan((string) $scan_id));
             } elseif ($target === 'crontab_audit') {
                 $cron_scanner = new \WcpScanner\WordPress\CronScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $cron_scanner->scan((string) $scan_id));
             } elseif ($target === 'core_integrity') {
                 $core = new \WcpScanner\Integrity\CoreIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $core->verify((string) $scan_id));
             } elseif ($target === 'rogue_admin') {
                 $rogue = new \WcpScanner\Database\RogueAdminAnomalyDetector();
                 $all_deep_findings = array_merge($all_deep_findings, $rogue->scan((string) $scan_id));
                 $user_scanner = new \WcpScanner\WordPress\UserScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true));
             } elseif ($target === 'hook_sentinel') {
                 $hook_sentinel = new \WcpScanner\WordPress\HookInfiltrationSentinel();
                 $all_deep_findings = array_merge($all_deep_findings, $hook_sentinel->scan((string) $scan_id));
                 $persistence_scanner = new \WcpScanner\WordPress\PersistenceScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $persistence_scanner->scan((string) $scan_id));
             } elseif ($target === 'filesystem_only') {
                 // Filesystem-only scan: no additional deep audit engines needed
             } else {
                 // Full or plugins_themes: execute all comprehensive engines
                 $core = new \WcpScanner\Integrity\CoreIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $core->verify((string) $scan_id));

                 $fim = new \WcpScanner\Integrity\ImportantFileFIM();
                 $all_deep_findings = array_merge($all_deep_findings, $fim->verify((string) $scan_id));

                 $plugin_integrity = new \WcpScanner\Integrity\PluginIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));

                 $theme_integrity = new \WcpScanner\Integrity\ThemeIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));

                 $db_scanner = new \WcpScanner\Database\DatabaseScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $db_scanner->scan((string) $scan_id, 100));

                 $content_scanner = new \WcpScanner\Content\ContentScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 100));

                 $wp_security = new \WcpScanner\WordPress\WordPressSecurityScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $wp_security->scan((string) $scan_id));

                 $update_scanner = new \WcpScanner\WordPress\UpdateScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));

                 $uploads = new \WcpScanner\Filesystem\UploadsScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $uploads->scan((string) $scan_id));
             }

             // Cross-engine Correlation
             $correlation = new \WcpScanner\Findings\CorrelationEngine();
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

             foreach ($correlated as $finding) {
                 $f = is_array($finding) ? $finding : (method_exists($finding, 'to_array') ? $finding->to_array() : (array) $finding);
                 $sig = md5(($f['engine'] ?? '') . '|' . ($f['type'] ?? '') . '|' . ($f['file_path'] ?? ($f['target'] ?? '')) . '|' . ($f['line_number'] ?? '') . '|' . ($f['description'] ?? ''));
                 if (isset($inserted_signatures[$sig])) {
                     continue; // Skip exact duplicate finding for this scan
                 }
                 $inserted_signatures[$sig] = true;

                 $wpdb->insert($table_issues, [
                     'scan_id'      => $scan_id,
                     'engine'       => $f['engine'] ?? 'system',
                     'type'         => $f['type'] ?? 'anomaly',
                     'severity'     => $f['severity'] ?? 'medium',
                     'confidence'   => $f['confidence'] ?? 100,
                     'file_path'    => $f['file_path'] ?? ($f['target'] ?? 'N/A'),
                     'line_number'  => $f['line_number'] ?? null,
                     'code_snippet' => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($f['code_snippet'] ?? null),
                     'evidence'     => \WcpScanner\Filesystem\UploadsScanner::sanitize_utf8($f['evidence'] ?? null),
                     'description'  => $f['description'] ?? '',
                     'status'       => 'open',
                     'created_at'   => current_time('mysql'),
                 ]);
             }

             // 4. Calculate final risk score across all findings
             $calc_sec = microtime(true) - $start_time;
             $duration_ms = (int) round($calc_sec * 1000);
             $duration = max(1, (int) round($calc_sec));
             $completed_at_exact = \WcpScanner\Api\ScannerRoutes::now_fractional_mysql();
             // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
             $all_scan_issues = $wpdb->get_results($wpdb->prepare(
                 "SELECT * FROM `{$table_issues}` WHERE scan_id = %d",
                 $scan_id
             ), ARRAY_A) ?: [];

             $scorer = new \WcpScanner\Findings\RiskScorer();
             $risk_summary = $scorer->calculate($all_scan_issues);
             $risk_score = (int) ($risk_summary['score'] ?? 0);
             $total_issues = count($all_scan_issues);

             $wpdb->update($table_scans, [
                 'status'        => 'completed',
                 'scanned_files' => $scanned_count,
                 'issues_found'  => $total_issues,
                 'risk_score'    => $risk_score,
                 'duration'      => $duration,
                 'duration_ms'   => $duration_ms,
                 'completed_at'  => $completed_at_exact,
             ], ['id' => $scan_id]);

             // Release exclusive lock
             \WcpScanner\Scan\ScanLock::release($scan_id);
             delete_transient("wcpscan_active_scan_file_{$scan_id}");
             delete_transient("wcpscan_scan_start_micro_{$scan_id}");

             // 5. Send Alerts & Notifications
             self::send_scan_notification($scan_id, $total_issues, $risk_score, $target);

         } catch (\Throwable $e) {
             \WcpScanner\Scan\ScanLock::release($scan_id);
             delete_transient("wcpscan_active_scan_file_{$scan_id}");
             delete_transient("wcpscan_scan_start_micro_{$scan_id}");
             $calc_sec = microtime(true) - $start_time;
             $duration_ms = (int) round($calc_sec * 1000);
             $duration = max(1, (int) round($calc_sec));
             $wpdb->update($table_scans, [
                 'status'       => 'interrupted',
                 'duration'     => $duration,
                 'duration_ms'  => $duration_ms,
                 'completed_at' => \WcpScanner\Api\ScannerRoutes::now_fractional_mysql(),
             ], ['id' => $scan_id]);
             error_log('[WCP Scanner] Scheduled scan failed: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
         }
    }

    /**
     * Send email notifications based on settings
     */
    public static function send_scan_notification(int $scan_id, int $total_issues, int $risk_score, string $target) {
        $settings = SettingsManager::get_settings();

        global $wpdb;
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, type, file_path, description FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')",
            $scan_id
        ), ARRAY_A) ?: [];

        // Dispatch DevSecOps Webhooks (Slack & Discord)
        if (class_exists('\\WcpScanner\\Notifications\\WebhookService')) {
            \WcpScanner\Notifications\WebhookService::send_scan_alert($scan_id, $total_issues, $risk_score, $target, $issues);
        }

        if (empty($settings['email_alerts_enabled'])) {
            return;
        }

        $recipients_str = $settings['alert_emails'] ?: get_option('admin_email');
        $recipients = array_filter(array_map('trim', preg_split('/[\r\n,]+/', $recipients_str)));
        if (empty($recipients)) {
            return;
        }

        $critical_count = 0;
        $high_count = 0;
        $medium_count = 0;
        foreach ($issues as $iss) {
            if ($iss['severity'] === 'critical') $critical_count++;
            elseif ($iss['severity'] === 'high') $high_count++;
            elseif ($iss['severity'] === 'medium') $medium_count++;
        }

        $min_severity = $settings['alert_min_severity'] ?? 'high';
        $should_notify = false;

        if ($settings['email_on_scan_completed']) {
            $should_notify = true;
        } elseif ($min_severity === 'critical' && $critical_count > 0) {
            $should_notify = true;
        } elseif ($min_severity === 'high' && ($critical_count > 0 || $high_count > 0)) {
            $should_notify = true;
        } elseif ($min_severity === 'medium' && ($critical_count > 0 || $high_count > 0 || $medium_count > 0)) {
            $should_notify = true;
        } elseif ($min_severity === 'all' && $total_issues > 0) {
            $should_notify = true;
        }

        if (!$should_notify) {
            return;
        }

        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $site_url = get_site_url();
        $admin_url = admin_url('admin.php?page=wcp-security-scanner');

        $status_label = ($critical_count > 0 || $high_count > 0) ? '🔴 SECURITY ALERT' : '🛡️ Security Scan Report';
        $subject = "[$status_label] {$site_name} - Scan #{$scan_id} Completed ({$total_issues} findings)";

        $headers = ['Content-Type: text/html; charset=UTF-8'];

        $body = "<div style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;max-width:620px;margin:0 auto;padding:24px;background:#f8fafc;border-radius:12px;border:1px solid #e2e8f0;color:#1e293b;'>";
        $body .= "<div style='background:#0f172a;padding:20px;border-radius:8px;color:#fff;margin-bottom:20px;'>";
        $body .= "<h2 style='margin:0 0 6px 0;font-size:20px;color:#38bdf8;'>WCP Security Scanner</h2>";
        $body .= "<p style='margin:0;font-size:13px;color:#94a3b8;'>Automated Security Audit Report for <strong>{$site_name}</strong> ({$site_url})</p>";
        $body .= "</div>";

        $body .= "<div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px;'>";
        $body .= "<div style='background:#fff;padding:12px;border-radius:8px;border:1px solid #e2e8f0;text-align:center;'>";
        $body .= "<div style='font-size:11px;color:#64748b;text-transform:uppercase;'>Risk Score</div>";
        $body .= "<div style='font-size:22px;font-weight:700;color:" . ($risk_score > 60 ? '#ef4444' : ($risk_score > 25 ? '#f59e0b' : '#10b981')) . ";'>{$risk_score}/100</div>";
        $body .= "</div>";

        $body .= "<div style='background:#fff;padding:12px;border-radius:8px;border:1px solid #e2e8f0;text-align:center;'>";
        $body .= "<div style='font-size:11px;color:#64748b;text-transform:uppercase;'>Critical Threats</div>";
        $body .= "<div style='font-size:22px;font-weight:700;color:#ef4444;'>{$critical_count}</div>";
        $body .= "</div>";

        $body .= "<div style='background:#fff;padding:12px;border-radius:8px;border:1px solid #e2e8f0;text-align:center;'>";
        $body .= "<div style='font-size:11px;color:#64748b;text-transform:uppercase;'>Total Findings</div>";
        $body .= "<div style='font-size:22px;font-weight:700;color:#0f172a;'>{$total_issues}</div>";
        $body .= "</div>";
        $body .= "</div>";

        if (!empty($issues)) {
            $body .= "<h3 style='font-size:15px;color:#0f172a;margin:20px 0 10px 0;'>Top Detected Issues:</h3>";
            $body .= "<table style='width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;font-size:13px;'>";
            $body .= "<tr style='background:#f1f5f9;color:#475569;text-align:left;'>";
            $body .= "<th style='padding:8px 12px;'>Severity</th><th style='padding:8px 12px;'>Type</th><th style='padding:8px 12px;'>Target / File</th>";
            $body .= "</tr>";
            $limit = 10;
            $count = 0;
            foreach ($issues as $iss) {
                if ($count++ >= $limit) break;
                $sev_color = $iss['severity'] === 'critical' ? '#dc2626' : ($iss['severity'] === 'high' ? '#ea580c' : '#ca8a04');
                $body .= "<tr style='border-top:1px solid #e2e8f0;'>";
                $body .= "<td style='padding:8px 12px;'><span style='background:{$sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;font-size:11px;'>".strtoupper($iss['severity'])."</span></td>";
                $body .= "<td style='padding:8px 12px;color:#334155;'>".esc_html($iss['type'])."</td>";
                $body .= "<td style='padding:8px 12px;color:#64748b;word-break:break-all;'><code>".esc_html($iss['file_path'])."</code></td>";
                $body .= "</tr>";
            }
            $body .= "</table>";
            if (count($issues) > 10) {
                $rem = count($issues) - 10;
                $body .= "<p style='font-size:12px;color:#64748b;margin-top:8px;'>...and {$rem} more findings. View full forensic report in WordPress Admin.</p>";
            }
        }

        $body .= "<div style='margin-top:24px;text-align:center;'>";
        $body .= "<a href='{$admin_url}' style='display:inline-block;padding:12px 24px;background:#0284c7;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;font-size:14px;'>Open Security Scanner Dashboard</a>";
        $body .= "</div>";

        $body .= "<p style='font-size:11px;color:#94a3b8;margin-top:24px;text-align:center;border-top:1px solid #e2e8f0;padding-top:12px;'>Generated by WCP Security Scanner by WebCare Pro &bull; {$site_url}</p>";
        $body .= "</div>";

        foreach ($recipients as $email) {
            if (is_email($email)) {
                wp_mail($email, $subject, $body, $headers);
            }
        }
    }
}
