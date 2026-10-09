<?php
namespace WCP\Scanner\System;

use WCP\Scanner\Scanner\Engine;
use WCP\Scanner\Findings\CorrelationEngine;
use WCP\Scanner\Findings\RiskScorer;

if (!defined('ABSPATH')) {
    exit;
}

class Scheduler {
    const CRON_HOOK = 'wcp_scanner_scheduled_scan_event';

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

        $target = $settings['schedule_scan_type'] ?? 'plugins_themes';
        $table_scans = $wpdb->prefix . 'wcp_scans';

        // 1. Queue scan
        $paths = [];
        $files = [];
        if ($target === 'full') {
            $paths[] = untrailingslashit(ABSPATH);
            foreach ($paths as $p) {
                $files = array_merge($files, Engine::get_scannable_files($p, 3000));
            }
        } elseif ($target === 'core_integrity' || $target === 'suspicious_uploads' || $target === 'spam_content') {
            $files = [];
        } else {
            $paths[] = WP_PLUGIN_DIR;
            $paths[] = get_theme_root();
            foreach ($paths as $p) {
                $files = array_merge($files, Engine::get_scannable_files($p, 2000));
            }
        }

        $wpdb->insert($table_scans, [
            'status'        => 'running',
            'scan_target'   => $target,
            'scanned_files' => 0,
            'total_files'   => count($files),
            'issues_found'  => 0,
            'risk_score'    => 0,
            'created_at'    => current_time('mysql'),
        ]);
        $scan_id = (int) $wpdb->insert_id;

        $start_time = microtime(true);

        // 2. Scan files if any
        $engine = new Engine($scan_id);
        $scanned_count = 0;
        foreach ($files as $file) {
            $engine->scan_file($file);
            $scanned_count++;
        }

        // 3. Run target-specific deep audits
        $deep_findings = [];
        if ($target === 'core_integrity') {
            $core = new \WCP\Scanner\Integrity\CoreIntegrity();
            $deep_findings = array_merge($deep_findings, $core->scan());
        } elseif ($target === 'suspicious_uploads') {
            $uploads = new \WCP\Scanner\Filesystem\UploadsScanner();
            $deep_findings = array_merge($deep_findings, $uploads->scan());
        } elseif ($target === 'spam_content') {
            $content = new \WCP\Scanner\Content\ContentScanner();
            $deep_findings = array_merge($deep_findings, $content->scan());
        } else {
            // General deep audit
            $db_scanner = new \WCP\Scanner\Database\DatabaseScanner();
            $deep_findings = array_merge($deep_findings, $db_scanner->scan());
            $content_scanner = new \WCP\Scanner\Content\ContentScanner();
            $deep_findings = array_merge($deep_findings, $content_scanner->scan());
        }

        if (!empty($deep_findings)) {
            $table_issues = $wpdb->prefix . 'wcp_scan_issues';
            foreach ($deep_findings as $finding) {
                $f = is_array($finding) ? $finding : (method_exists($finding, 'to_array') ? $finding->to_array() : (array) $finding);
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $f['engine'] ?? 'system',
                    'type'         => $f['type'] ?? 'anomaly',
                    'severity'     => $f['severity'] ?? 'medium',
                    'confidence'   => $f['confidence'] ?? 100,
                    'file_path'    => $f['file_path'] ?? ($f['target'] ?? 'N/A'),
                    'line_number'  => $f['line_number'] ?? null,
                    'code_snippet' => $f['code_snippet'] ?? null,
                    'evidence'     => $f['evidence'] ?? null,
                    'description'  => $f['description'] ?? '',
                    'status'       => 'open',
                    'created_at'   => current_time('mysql'),
                ]);
            }
        }

        // 4. Correlate and calculate risk score
        $duration = (int) round(microtime(true) - $start_time);
        $total_issues = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}wcp_scan_issues WHERE scan_id = %d", $scan_id));

        $scorer = new RiskScorer();
        $risk_score = $scorer->calculate_for_scan($scan_id);

        $wpdb->update($table_scans, [
            'status'        => 'completed',
            'scanned_files' => $scanned_count,
            'issues_found'  => $total_issues,
            'risk_score'    => $risk_score,
            'duration'      => $duration,
            'completed_at'  => current_time('mysql'),
        ], ['id' => $scan_id]);

        // 5. Send Email Alerts if configured
        self::send_scan_notification($scan_id, $total_issues, $risk_score, $target);
    }

    /**
     * Send email notifications based on settings
     */
    public static function send_scan_notification(int $scan_id, int $total_issues, int $risk_score, string $target) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['email_alerts_enabled'])) {
            return;
        }

        $recipients_str = $settings['alert_emails'] ?: get_option('admin_email');
        $recipients = array_filter(array_map('trim', preg_split('/[\r\n,]+/', $recipients_str)));
        if (empty($recipients)) {
            return;
        }

        global $wpdb;
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, type, file_path, description FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')",
            $scan_id
        ), ARRAY_A);

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
