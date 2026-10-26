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
             // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
             @set_time_limit(0);
         }
         $mem_limit = !empty($settings['memory_limit_override']) ? $settings['memory_limit_override'] : '512M';
         // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
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
         // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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
             'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
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
                     // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                     $wpdb->update($table_scans, [
                         'scanned_files' => $scanned_count,
                     ], ['id' => $scan_id]);
                     set_transient("wcpscan_active_scan_file_{$scan_id}", $filepath, 120);
                 }

                 $findings = $file_scanner->scan_file($filepath, (string) $scan_id);
                 $rel_path = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($filepath)), '/');
                 $file_size = @filesize($filepath) ?: 0;
                 $file_status = !empty($findings) ? 'threat' : 'clean';

                 // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                 $wpdb->insert($table_files, [
                     'scan_id'    => $scan_id,
                     'file_path'  => $rel_path,
                     'file_size'  => $file_size,
                     'status'     => $file_status,
                     'scanned_at'     => current_time('mysql'),
                     'scanned_at_gmt' => gmdate('Y-m-d H:i:s'),
                 ]);

                 foreach ($findings as $f) {
                     $item = is_array($f) ? $f : (method_exists($f, 'to_array') ? $f->to_array() : (array) $f);
                     // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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
                         'status'         => 'open',
                         'created_at'     => current_time('mysql'),
                         'created_at_gmt' => gmdate('Y-m-d H:i:s'),
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
             $issues_query = "SELECT engine, type, file_path, line_number, description FROM `{$table_issues}` WHERE scan_id = %d";
              // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
              $existing_issues = $wpdb->get_results(
                  // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                  $wpdb->prepare($issues_query, $scan_id),
                  ARRAY_A
              ) ?: [];

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

                 // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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
                     'status'       => (class_exists('\\WcpScanner\\Findings\\WhitelistManager') && \WcpScanner\Findings\WhitelistManager::match_finding($f) !== null) ? 'ignored' : 'open',
                     'created_at'   => current_time('mysql'),
                     'created_at_gmt' => gmdate('Y-m-d H:i:s'),
                 ]);
             }

             // 4. Calculate final risk score across all findings
             $calc_sec = microtime(true) - $start_time;
             $duration_ms = (int) round($calc_sec * 1000);
             $duration = max(1, (int) round($calc_sec));
             $completed_at_exact = \WcpScanner\Api\ScannerRoutes::now_fractional_mysql();
             $all_query = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d";
              // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
              $all_scan_issues = $wpdb->get_results(
                  // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                  $wpdb->prepare($all_query, $scan_id),
                  ARRAY_A
              ) ?: [];

             $open_issues = array_filter($all_scan_issues, function($issue) {
                 return ($issue['status'] ?? 'open') === 'open';
             });

             $scorer = new \WcpScanner\Findings\RiskScorer();
             $risk_summary = $scorer->calculate($open_issues);
             $risk_score = (int) ($risk_summary['score'] ?? 0);
             $open_issues_count = count($open_issues);

             // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
             $wpdb->update($table_scans, [
                 'status'        => 'completed',
                 'scanned_files' => $scanned_count,
                 'issues_found'  => $open_issues_count,
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
             self::send_scan_notification($scan_id, $open_issues_count, $risk_score, $target);

         } catch (\Throwable $e) {
             \WcpScanner\Scan\ScanLock::release($scan_id);
             delete_transient("wcpscan_active_scan_file_{$scan_id}");
             delete_transient("wcpscan_scan_start_micro_{$scan_id}");
             $calc_sec = microtime(true) - $start_time;
             $duration_ms = (int) round($calc_sec * 1000);
             $duration = max(1, (int) round($calc_sec));
             // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
             $wpdb->update($table_scans, [
                 'status'       => 'interrupted',
                 'duration'     => $duration,
                 'duration_ms'  => $duration_ms,
                 'completed_at' => \WcpScanner\Api\ScannerRoutes::now_fractional_mysql(),
             ], ['id' => $scan_id]);
             // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
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
        $notif_query = "SELECT severity, type, file_path, description FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($notif_query, $scan_id),
            ARRAY_A
        ) ?: [];

        // Dispatch granular event notifications via NotificationDispatcher
        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            // 1. Scheduled scan complete event
            \WcpScanner\Notifications\NotificationDispatcher::trigger('scan_scheduled_complete', [
                'severity' => ($total_issues > 0) ? 'high' : 'info',
                'message'  => sprintf(
                    /* translators: 1: scan ID, 2: scan target, 3: count of issues, 4: risk score */
                    __('Scheduled background scan #%1$d finished for target "%2$s". %3$d issue(s) identified (Risk Score: %4$d/100).', 'wcp-security-scanner'),
                    $scan_id,
                    $target,
                    $total_issues,
                    $risk_score
                ),
                'details'  => [
                    'scan_id'      => $scan_id,
                    'target'       => $target,
                    'issues_found' => $total_issues,
                    'risk_score'   => $risk_score,
                ],
            ]);

            // 2. Critical / High threats found event
            $critical_or_high = array_filter($issues, function($i) {
                return in_array($i['severity'] ?? '', ['critical', 'high'], true);
            });
            if (!empty($critical_or_high)) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('scan_threats_found', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: scan ID, 2: count of threats */
                        __('Critical or high-priority security threats were detected during scan #%1$d (%2$d threats).', 'wcp-security-scanner'),
                        $scan_id,
                        count($critical_or_high)
                    ),
                    'details'  => [
                        'scan_id'        => $scan_id,
                        'critical_count' => count($critical_or_high),
                        'sample'         => array_column(array_slice($critical_or_high, 0, 3), 'description'),
                    ],
                ]);
            }
        }

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
        $host = wp_parse_url($site_url, PHP_URL_HOST) ?: $site_url;
        $subject = "[$status_label] {$site_name} - Scan #{$scan_id} Completed for {$host} ({$total_issues} findings)";

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        $logo_url = defined('WCPSCAN_URL') ? WCPSCAN_URL . 'assets/logo.png' : plugins_url('assets/logo.png', dirname(__DIR__));
        $sev_badge_color = ($critical_count > 0 || $high_count > 0) ? '#dc2626' : '#10b981';

        // Generate Gemini AI Overview preheader text (single-line executive brief)
        $ai_summary_line = sprintf(
            'WebCare Pro completed security scan #%d for %s with a risk score of %d/100 (%d critical threats, %d total findings).',
            $scan_id,
            $host,
            $risk_score,
            $critical_count,
            $total_issues
        );

        // Schema.org / JSON-LD security audit report
        $json_ld = [
            '@context'         => 'https://schema.org',
            '@type'            => 'SecurityAssessment',
            'name'             => "WCP Security Scan #{$scan_id}",
            'description'      => $ai_summary_line,
            'datePublished'    => gmdate('Y-m-d H:i:s') . ' GMT',
            'about'            => [
                '@type' => 'WebSite',
                'name'  => $site_name,
                'url'   => $site_url,
            ],
            'publisher'        => [
                '@type' => 'Organization',
                'name'  => 'WebCare Pro',
                'url'   => 'https://webcarespro.com',
            ],
            'assessmentResult' => [
                'riskScore'       => $risk_score,
                'criticalThreats' => $critical_count,
                'highThreats'     => $high_count,
                'totalFindings'   => $total_issues,
            ],
            'potentialAction'  => [
                '@type'  => 'ViewAction',
                'name'   => 'View Scan Forensic Report',
                'target' => $admin_url,
            ],
        ];
        $json_ld_string = wp_json_encode($json_ld, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

        $body = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
        $body .= "<meta name='description' content='" . esc_attr($ai_summary_line) . "'>";
        $body .= "<meta name='wcp-risk-score' content='" . esc_attr((string)$risk_score) . "'>";
        $body .= "<meta name='wcp-critical-threats' content='" . esc_attr((string)$critical_count) . "'>";
        $body .= "<script type='application/ld+json'>{$json_ld_string}</script>";
        $body .= "</head><body style='font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;background-color:#f1f5f9;margin:0;padding:28px 12px;color:#0f172a;'>";

        // Hidden AI & Email Client Preheader
        $body .= "<div style='display:none;font-size:1px;color:#f1f5f9;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;mso-hide:all;'>";
        $body .= esc_html($ai_summary_line);
        $body .= " &#847; &zwnj; &nbsp; &#8199; &shy; &#847; &zwnj; &nbsp; &#8199; &shy; &#847; &zwnj; &nbsp; &#8199; &shy;";
        $body .= "</div>";

        $body .= "<div style='max-width:620px;margin:0 auto;background:#ffffff;border-radius:16px;border:1px solid #e2e8f0;overflow:hidden;box-shadow:0 10px 25px -5px rgba(15,23,42,0.08);'>";
        
        // Header matching brand
        $body .= "<div style='background:#0b1120;padding:36px 32px 30px 32px;text-align:center;border-top:4px solid #3b82f6;border-bottom:3px solid {$sev_badge_color};'>";
        $body .= "<div style='display:inline-block;padding:6px 16px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;background:rgba(59,130,246,0.12);color:#60a5fa;border:1px solid rgba(96,165,250,0.3);margin-bottom:20px;'>";
        $body .= "🛡️ " . esc_html($status_label);
        $body .= "</div>";
        $body .= "<div style='margin-bottom:14px;'><img src='" . esc_url($logo_url) . "' alt='WebCare Pro Logo' style='max-height:48px;width:auto;display:inline-block;'></div>";
        $body .= "<div style='color:#94a3b8;font-size:13.5px;font-weight:500;margin-bottom:18px;'>High-Performance WordPress Security & Autonomous Defense</div>";
        $body .= "<div style='background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:12px 18px;'>";
        $body .= "<h1 style='color:#ffffff;font-size:18px;margin:0;font-weight:700;'>Scan #{$scan_id} Completed</h1>";
        $body .= "<p style='color:#64748b;font-size:12.5px;margin:6px 0 0 0;'>Site: <strong style='color:#cbd5e1;'>{$site_name}</strong> (<a href='{$site_url}' style='color:#38bdf8;text-decoration:none;'>{$site_url}</a>)</p>";
        $body .= "</div>";
        $body .= "</div>";

        // Body Metrics
        $body .= "<div style='padding:32px 32px 28px 32px;background:#ffffff;'>";

        // AI Summary Quick-Glance Callout
        $body .= "<div style='background:linear-gradient(135deg, rgba(79, 70, 229, 0.06) 0%, rgba(99, 102, 241, 0.03) 100%);border:1px solid rgba(79, 70, 229, 0.2);border-radius:10px;padding:14px 18px;margin-bottom:24px;'>";
        $body .= "<div style='display:flex;align-items:center;gap:8px;font-size:11.5px;font-weight:800;color:#4338ca;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:4px;'>";
        $body .= "⚡ AI Executive Incident Brief";
        $body .= "</div>";
        $body .= "<div style='font-size:13.5px;color:#1e293b;line-height:1.5;font-weight:500;'>";
        $body .= esc_html($ai_summary_line);
        $body .= "</div>";
        $body .= "</div>";
        $body .= "<div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:24px;'>";
        $body .= "<div style='background:#f8fafc;padding:14px;border-radius:10px;border:1px solid #e2e8f0;text-align:center;'>";
        $body .= "<div style='font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;'>Risk Score</div>";
        $body .= "<div style='font-size:24px;font-weight:800;margin-top:4px;color:" . ($risk_score > 60 ? '#ef4444' : ($risk_score > 25 ? '#f59e0b' : '#10b981')) . ";'>{$risk_score}/100</div>";
        $body .= "</div>";

        $body .= "<div style='background:#f8fafc;padding:14px;border-radius:10px;border:1px solid #e2e8f0;text-align:center;'>";
        $body .= "<div style='font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;'>Critical Threats</div>";
        $body .= "<div style='font-size:24px;font-weight:800;margin-top:4px;color:#ef4444;'>{$critical_count}</div>";
        $body .= "</div>";

        $body .= "<div style='background:#f8fafc;padding:14px;border-radius:10px;border:1px solid #e2e8f0;text-align:center;'>";
        $body .= "<div style='font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;'>Total Findings</div>";
        $body .= "<div style='font-size:24px;font-weight:800;margin-top:4px;color:#0f172a;'>{$total_issues}</div>";
        $body .= "</div>";
        $body .= "</div>";

        if (!empty($issues)) {
            $body .= "<h3 style='font-size:14px;font-weight:700;color:#0f172a;margin:20px 0 10px 0;text-transform:uppercase;letter-spacing:0.5px;'>Top Detected Issues:</h3>";
            $body .= "<table style='width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;font-size:13px;border:1px solid #e2e8f0;'>";
            $body .= "<tr style='background:#f1f5f9;color:#475569;text-align:left;'>";
            $body .= "<th style='padding:10px 12px;font-size:11px;text-transform:uppercase;'>Severity</th><th style='padding:10px 12px;font-size:11px;text-transform:uppercase;'>Type</th><th style='padding:10px 12px;font-size:11px;text-transform:uppercase;'>Target / File</th>";
            $body .= "</tr>";
            $limit = 10;
            $count = 0;
            foreach ($issues as $iss) {
                if ($count++ >= $limit) break;
                $sev_color = $iss['severity'] === 'critical' ? '#dc2626' : ($iss['severity'] === 'high' ? '#ea580c' : '#ca8a04');
                $body .= "<tr style='border-top:1px solid #e2e8f0;'>";
                $body .= "<td style='padding:8px 12px;'><span style='background:{$sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;font-size:11px;'>".strtoupper($iss['severity'])."</span></td>";
                $body .= "<td style='padding:8px 12px;color:#334155;font-weight:500;'>".esc_html($iss['type'])."</td>";
                $body .= "<td style='padding:8px 12px;color:#64748b;word-break:break-all;font-family:monospace;font-size:12px;'>".esc_html($iss['file_path'])."</td>";
                $body .= "</tr>";
            }
            $body .= "</table>";
            if (count($issues) > 10) {
                $rem = count($issues) - 10;
                $body .= "<p style='font-size:12px;color:#64748b;margin-top:8px;'>...and {$rem} more findings. View full forensic report in WordPress Admin.</p>";
            }
        }

        $body .= "<div style='margin-top:32px;text-align:center;'>";
        $body .= "<a href='{$admin_url}' style='display:inline-block;padding:13px 30px;background:#4f46e5;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;box-shadow:0 4px 14px rgba(79,70,229,0.35);'>Open Security Scanner Dashboard &rarr;</a>";
        $body .= "</div>";
        $body .= "</div>";

        // About Us & Company Footer
        $body .= "<div style='background:#0f172a;padding:28px 32px;border-top:1px solid #1e293b;color:#94a3b8;font-size:12.5px;line-height:1.6;'>";
        $body .= "<div style='display:flex;align-items:center;margin-bottom:12px;'>";
        $body .= "<strong style='color:#ffffff;font-size:14px;letter-spacing:0.2px;'>About WebCare Pro</strong>";
        $body .= "<span style='color:#475569;margin:0 8px;'>•</span>";
        $body .= "<a href='https://webcarespro.com' target='_blank' style='color:#38bdf8;text-decoration:none;font-weight:600;'>https://webcarespro.com</a>";
        $body .= "</div>";
        $body .= "<p style='margin:0 0 16px 0;color:#cbd5e1;font-size:12.5px;line-height:1.6;'>";
        $body .= "WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux &amp; cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—we keep your online presence fast, secure, and always available.";
        $body .= "</p>";
        $notif_url = admin_url('admin.php?page=wcp-scanner-notifications');
        $body .= "<div style='border-top:1px solid #1e293b;padding-top:14px;font-size:12px;color:#94a3b8;text-align:center;line-height:1.6;'>";
        $body .= "Automated Security Audit Report generated on <span style='color:#e2e8f0;font-weight:600;'>" . gmdate('Y-m-d H:i:s') . " GMT</span>. You can manage granular notification preferences anytime under <strong>WCP Scanner &gt; <a href='{$notif_url}' style='color:#38bdf8;text-decoration:underline;font-weight:600;'>Notifications</a></strong>.";
        $body .= "</div>";
        $body .= "</div>";

        $body .= "</div></body></html>";

        foreach ($recipients as $email) {
            if (is_email($email)) {
                wp_mail($email, $subject, $body, $headers);
            }
        }
    }
}
