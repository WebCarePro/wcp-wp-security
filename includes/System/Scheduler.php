<?php
namespace WebCareProScanner\System;

use WebCareProScanner\Scanner\Engine;
use WebCareProScanner\Findings\CorrelationEngine;
use WebCareProScanner\Findings\RiskScorer;
use WebCareProScanner\Scan\ScanLock;

if (!defined('ABSPATH')) {
    exit;
}

class Scheduler {
    const CRON_HOOK   = 'webcareproscan_scheduled_scan_event';
    const DIGEST_HOOK = 'webcareproscan_weekly_digest_event';
    const CANARY_HOOK = 'webcareproscan_redirect_canary_event';

    public static function register() {
        add_action(self::CRON_HOOK, [__CLASS__, 'run_scheduled_scan']);
        add_action(self::DIGEST_HOOK, [__CLASS__, 'run_weekly_digest']);
        add_action(self::CANARY_HOOK, ['\\WebCareProScanner\\Firewall\\RedirectCanaryEngine', 'run_scheduled_canary']);

        // Schedule recurring Monday morning digest cron if not yet registered
        if (!wp_next_scheduled(self::DIGEST_HOOK)) {
            // Find next Monday 08:00 AM local site time
            $next_monday = strtotime('next monday 08:00:00');
            if ($next_monday !== false) {
                wp_schedule_event($next_monday, 'weekly', self::DIGEST_HOOK);
            }
        }

        // Schedule 15-minute synthetic redirect canary watchdog
        if (!wp_next_scheduled(self::CANARY_HOOK)) {
            wp_schedule_event(time() + 60, 'webcare_15min', self::CANARY_HOOK);
        }

        // Custom cron intervals (e.g., weekly, 5-minutes, 15-minutes)
        add_filter('cron_schedules', function ($schedules) {
            if (!isset($schedules['weekly'])) {
                $schedules['weekly'] = [
                    'interval' => 7 * DAY_IN_SECONDS,
                    'display'  => __('Once Weekly', 'webcare-pro-security'),
                ];
            }
            if (!isset($schedules['webcare_every_five_minutes'])) {
                $schedules['webcare_every_five_minutes'] = [
                    'interval' => 300,
                    'display'  => __('Every 5 Minutes (WebCare Pro Security)', 'webcare-pro-security'),
                ];
            }
            if (!isset($schedules['webcare_15min'])) {
                $schedules['webcare_15min'] = [
                    'interval' => 900,
                    'display'  => __('Every 15 Minutes (WebCare Redirect Canary)', 'webcare-pro-security'),
                ];
            }
            return $schedules;
        });
    }

    /**
     * Executes the Monday Morning Peace-of-Mind security digest
     */
    public static function run_weekly_digest() {
        if (!class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher') || !class_exists('\\WebCareProScanner\\Reports\\WeeklyDigestEngine')) {
            return;
        }

        // Strict Policy: Only proceed if administrator explicitly enabled the event in Notification Center
        $is_email_on = \WebCareProScanner\Notifications\NotificationDispatcher::is_event_enabled('weekly_peace_of_mind_digest', 'email');
        $is_webhook_on = \WebCareProScanner\Notifications\NotificationDispatcher::is_event_enabled('weekly_peace_of_mind_digest', 'webhook');

        if (!$is_email_on && !$is_webhook_on) {
            // Silently abort if disabled by user (the default state)
            return;
        }

        $telemetry = \WebCareProScanner\Reports\WeeklyDigestEngine::compile_weekly_telemetry();
        $email_html = \WebCareProScanner\Reports\WeeklyDigestEngine::render_email_html($telemetry);

        \WebCareProScanner\Notifications\NotificationDispatcher::trigger('weekly_peace_of_mind_digest', [
            /* translators: %s: site name */
            'title'     => sprintf(__('Your Site Had a Safe Week • %s', 'webcare-pro-security'), $telemetry['site_name']),
            /* translators: 1: total blocked threats, 2: bot logins stopped, 3: verified files count */
            'message'   => sprintf(__('WebCare Pro blocked %1$s automated threats, stopped %2$s bot logins, and verified %3$s files intact this week. No action needed.', 'webcare-pro-security'), number_format($telemetry['total_blocked']), number_format($telemetry['login_blocks']), number_format($telemetry['verified_files'])),
            'severity'  => 'info',
            'html_body' => $email_html,
            'details'   => $telemetry,
        ]);
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
         $table_scans = $wpdb->prefix . 'webcareproscan_scans';
         $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
         $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

         // 1. Discover filesystem files (0 = unlimited)
         $files = [];
         $file_limit = (int) apply_filters('webcareproscan_file_limit', 0, $target);

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

         $now_exact = \WebCareProScanner\Api\ScannerRoutes::now_fractional_mysql();
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
         set_transient("webcareproscan_scan_start_micro_{$scan_id}", $start_time, HOUR_IN_SECONDS);

         // Audit Trail: Log scheduled scan started (Attributed to System WP-Cron)
         \WebCareProScanner\System\WebCareActivityLogger::info(
             'scheduled_scan_started',
             'scan',
             [
                 'description' => sprintf('Automated scheduled scan #%d started.', $scan_id),
                 'scan_id'     => (int) $scan_id,
                 'target'      => (string) $target,
                 'total_files' => count($files),
             ],
             [
                 'display_name' => 'System (WP-Cron)',
                 'id'           => 0,
                 'ip'           => '127.0.0.1',
                 'role'         => 'system',
                 'type'         => 'system',
                 'user_agent'   => 'WordPress/' . get_bloginfo('version') . '; Cron',
                 'user_login'   => 'System',
             ]
         );

         try {
             $scanned_count = 0;
             $file_scanner = new \WebCareProScanner\Filesystem\FileScanner();

             // 2. Scan discovered filesystem files
             foreach ($files as $idx => $filepath) {
                 // Refresh lock heartbeat and persist progress count every 15 files
                 if ($idx > 0 && $idx % 15 === 0) {
                     \WebCareProScanner\Scan\ScanLock::heartbeat($scan_id);
                     // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                     $wpdb->update($table_scans, [
                         'scanned_files' => $scanned_count,
                     ], ['id' => $scan_id]);
                     set_transient("webcareproscan_active_scan_file_{$scan_id}", $filepath, 120);
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
                         'code_snippet' => \WebCareProScanner\Filesystem\UploadsScanner::sanitize_utf8($item['code_snippet'] ?? null),
                         'evidence'     => \WebCareProScanner\Filesystem\UploadsScanner::sanitize_utf8($item['evidence'] ?? null),
                         'description'  => $item['description'] ?? '',
                         'status'         => 'open',
                         'created_at'     => current_time('mysql'),
                         'created_at_gmt' => gmdate('Y-m-d H:i:s'),
                     ]);
                 }

                 $scanned_count++;
             }

             // 3. Run target-specific deep audit engines
             \WebCareProScanner\Scan\ScanLock::heartbeat($scan_id);
             $all_deep_findings = [];

             if ($target === 'unknown_files') {
                 $core_integrity = new \WebCareProScanner\Integrity\CoreIntegrity();
                 $plugin_integrity = new \WebCareProScanner\Integrity\PluginIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                 $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                 $all_deep_findings = array_filter($all_deep_findings, function ($f) {
                     $arr = is_array($f) ? $f : (method_exists($f, 'to_array') ? $f->to_array() : (array) $f);
                     return in_array($arr['type'] ?? '', ['unknown_core_file', 'unknown_plugin_file'], true);
                 });
             } elseif ($target === 'spam_content') {
                 $content = new \WebCareProScanner\Content\ContentScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $content->scan((string) $scan_id, 300));
             } elseif ($target === 'user_security') {
                 $user_scanner = new \WebCareProScanner\WordPress\UserScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, false));
             } elseif ($target === 'outdated_software') {
                 $update_scanner = new \WebCareProScanner\WordPress\UpdateScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
             } elseif ($target === 'suspicious_uploads') {
                 $uploads = new \WebCareProScanner\Filesystem\UploadsScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $uploads->scan((string) $scan_id));
             } elseif ($target === 'crontab_audit') {
                 $cron_scanner = new \WebCareProScanner\WordPress\CronScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $cron_scanner->scan((string) $scan_id));
             } elseif ($target === 'core_integrity') {
                 $core = new \WebCareProScanner\Integrity\CoreIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $core->verify((string) $scan_id));
             } elseif ($target === 'rogue_admin') {
                 $rogue = new \WebCareProScanner\Database\RogueAdminAnomalyDetector();
                 $all_deep_findings = array_merge($all_deep_findings, $rogue->scan((string) $scan_id));
                 $user_scanner = new \WebCareProScanner\WordPress\UserScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true));
             } elseif ($target === 'hook_sentinel') {
                 $hook_sentinel = new \WebCareProScanner\WordPress\HookInfiltrationSentinel();
                 $all_deep_findings = array_merge($all_deep_findings, $hook_sentinel->scan((string) $scan_id));
                 $persistence_scanner = new \WebCareProScanner\WordPress\PersistenceScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $persistence_scanner->scan((string) $scan_id));
             } elseif ($target === 'filesystem_only') {
                 // Filesystem-only scan: no additional deep audit engines needed
             } else {
                 // Full or plugins_themes: execute all comprehensive engines
                 $core = new \WebCareProScanner\Integrity\CoreIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $core->verify((string) $scan_id));

                 $fim = new \WebCareProScanner\Integrity\ImportantFileFIM();
                 $all_deep_findings = array_merge($all_deep_findings, $fim->verify((string) $scan_id));

                 $plugin_integrity = new \WebCareProScanner\Integrity\PluginIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));

                 $theme_integrity = new \WebCareProScanner\Integrity\ThemeIntegrity();
                 $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));

                 $db_scanner = new \WebCareProScanner\Database\DatabaseScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $db_scanner->scan((string) $scan_id, 100));

                 $content_scanner = new \WebCareProScanner\Content\ContentScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 100));

                 $wp_security = new \WebCareProScanner\WordPress\WordPressSecurityScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $wp_security->scan((string) $scan_id));

                 $update_scanner = new \WebCareProScanner\WordPress\UpdateScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));

                 $uploads = new \WebCareProScanner\Filesystem\UploadsScanner();
                 $all_deep_findings = array_merge($all_deep_findings, $uploads->scan((string) $scan_id));
             }

             // Cross-engine Correlation
             $correlation = new \WebCareProScanner\Findings\CorrelationEngine();
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
                     'code_snippet' => \WebCareProScanner\Filesystem\UploadsScanner::sanitize_utf8($f['code_snippet'] ?? null),
                     'evidence'     => \WebCareProScanner\Filesystem\UploadsScanner::sanitize_utf8($f['evidence'] ?? null),
                     'description'  => $f['description'] ?? '',
                     'status'       => (class_exists('\\WebCareProScanner\\Findings\\WhitelistManager') && \WebCareProScanner\Findings\WhitelistManager::match_finding($f) !== null) ? 'ignored' : 'open',
                     'created_at'   => current_time('mysql'),
                     'created_at_gmt' => gmdate('Y-m-d H:i:s'),
                 ]);
             }

             // 4. Calculate final risk score across all findings
             $calc_sec = microtime(true) - $start_time;
             $duration_ms = (int) round($calc_sec * 1000);
             $duration = max(1, (int) round($calc_sec));
             $completed_at_exact = \WebCareProScanner\Api\ScannerRoutes::now_fractional_mysql();
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

             $scorer = new \WebCareProScanner\Findings\RiskScorer();
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
             \WebCareProScanner\Scan\ScanLock::release($scan_id);
             delete_transient("webcareproscan_active_scan_file_{$scan_id}");
             delete_transient("webcareproscan_scan_start_micro_{$scan_id}");

             // 5. Send Alerts & Notifications
             self::send_scan_notification($scan_id, $open_issues_count, $risk_score, $target);

             // Audit Trail: Log scheduled scan completed
             \WebCareProScanner\System\WebCareActivityLogger::info(
                 'scheduled_scan_completed',
                 'scan',
                 [
                     'description'   => sprintf('Scheduled scan #%d completed in %d ms with %d finding(s).', $scan_id, $duration_ms, $open_issues_count),
                     'duration_ms'   => (int) $duration_ms,
                     'issues_found'  => (int) $open_issues_count,
                     'risk_score'    => (int) $risk_score,
                     'scan_id'       => (int) $scan_id,
                     'scanned_files' => (int) $scanned_count,
                     'target'        => (string) $target,
                 ],
                 [
                     'display_name' => 'System (WP-Cron)',
                     'id'           => 0,
                     'ip'           => '127.0.0.1',
                     'role'         => 'system',
                     'type'         => 'system',
                     'user_agent'   => 'WordPress/' . get_bloginfo('version') . '; Cron',
                     'user_login'   => 'System',
                 ]
             );

         } catch (\Throwable $e) {
             \WebCareProScanner\Scan\ScanLock::release($scan_id);
             $last_file = get_transient("webcareproscan_active_scan_file_{$scan_id}") ?: '';
             delete_transient("webcareproscan_active_scan_file_{$scan_id}");
             delete_transient("webcareproscan_scan_start_micro_{$scan_id}");
             $calc_sec = microtime(true) - $start_time;
             $duration_ms = (int) round($calc_sec * 1000);
             $duration = max(1, (int) round($calc_sec));

             // Record deep forensic interruption dossier
             \WebCareProScanner\Scan\ScanInterruptionForensics::record($scan_id, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_EXCEPTION_CAUGHT, [
                 'exception' => $e,
                 'last_file' => $last_file,
             ]);

             // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
             $wpdb->update($table_scans, [
                 'status'       => 'interrupted',
                 'duration'     => $duration,
                 'duration_ms'  => $duration_ms,
                 'completed_at' => \WebCareProScanner\Api\ScannerRoutes::now_fractional_mysql(),
             ], ['id' => $scan_id]);
             // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
             error_log('[WebCare Pro] Scheduled scan failed: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
         }
    }

    /**
     * Send email notifications based on settings
     */
    public static function send_scan_notification(int $scan_id, int $total_issues, int $risk_score, string $target) {
        $settings = SettingsManager::get_settings();

        global $wpdb;
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $notif_query = "SELECT severity, type, file_path, description FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($notif_query, $scan_id),
            ARRAY_A
        ) ?: [];

        // Dispatch granular event notifications via NotificationDispatcher
        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            // 1. Scheduled scan complete event
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_scheduled_complete', [
                'severity' => ($total_issues > 0) ? 'high' : 'info',
                'message'  => sprintf(
                    /* translators: 1: scan ID, 2: scan target, 3: count of issues, 4: risk score */
                    __('Scheduled background scan #%1$d finished for target "%2$s". %3$d issue(s) identified (Risk Score: %4$d/100).', 'webcare-pro-security'),
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
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_threats_found', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: scan ID, 2: count of threats */
                        __('Critical or high-priority security threats were detected during scan #%1$d (%2$d threats).', 'webcare-pro-security'),
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
        if (class_exists('\\WebCareProScanner\\Notifications\\WebhookService')) {
            \WebCareProScanner\Notifications\WebhookService::send_scan_alert($scan_id, $total_issues, $risk_score, $target, $issues);
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
        $admin_url = admin_url('admin.php?page=webcare-pro-security');

        $status_label = ($critical_count > 0 || $high_count > 0) ? '🔴 SECURITY ALERT' : '🛡️ Security Scan Report';
        $host = wp_parse_url($site_url, PHP_URL_HOST) ?: $site_url;
        $subject = "[$status_label] {$site_name} - Scan #{$scan_id} Completed for {$host} ({$total_issues} findings)";

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        $logo_url = defined('WEBCAREPROSCAN_URL') ? WEBCAREPROSCAN_URL . 'assets/logo.png' : plugins_url('assets/logo.png', dirname(__DIR__));
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
            'name'             => "WebCare Pro Security Scan #{$scan_id}",
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
        $body .= "<meta name='webcare-risk-score' content='" . esc_attr((string)$risk_score) . "'>";
        $body .= "<meta name='webcare-critical-threats' content='" . esc_attr((string)$critical_count) . "'>";
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
            // Priority-based sorting so high-risk items (critical/high) always appear first in emails
            $severity_ranks = [
                'critical' => 4,
                'high'     => 3,
                'medium'   => 2,
                'low'      => 1,
                'info'     => 0,
            ];
            usort($issues, function($a, $b) use ($severity_ranks) {
                $rank_a = $severity_ranks[$a['severity'] ?? 'info'] ?? 0;
                $rank_b = $severity_ranks[$b['severity'] ?? 'info'] ?? 0;
                if ($rank_a !== $rank_b) {
                    return $rank_b <=> $rank_a; // Descending priority
                }
                return strcmp($a['file_path'] ?? '', $b['file_path'] ?? '');
            });

            $limit = max(1, min(25, (int) ($settings['email_report_items_limit'] ?? 20)));
            $display_issues = array_slice($issues, 0, $limit);
            $total_count = count($issues);

            $body .= "<h3 style='font-size:14px;font-weight:700;color:#0f172a;margin:20px 0 10px 0;text-transform:uppercase;letter-spacing:0.5px;'>Top Detected Issues (Priority Ranked):</h3>";
            $body .= "<table style='width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;font-size:13px;border:1px solid #e2e8f0;'>";
            $body .= "<tr style='background:#f1f5f9;color:#475569;text-align:left;'>";
            $body .= "<th style='padding:10px 12px;font-size:11px;text-transform:uppercase;'>Severity</th><th style='padding:10px 12px;font-size:11px;text-transform:uppercase;'>Type</th><th style='padding:10px 12px;font-size:11px;text-transform:uppercase;'>Target / File</th>";
            $body .= "</tr>";
            foreach ($display_issues as $iss) {
                $sev = strtolower($iss['severity'] ?? 'medium');
                $sev_color = $sev === 'critical' ? '#dc2626' : ($sev === 'high' ? '#ea580c' : ($sev === 'medium' ? '#ca8a04' : '#64748b'));
                $body .= "<tr style='border-top:1px solid #e2e8f0;'>";
                $body .= "<td style='padding:8px 12px;'><span style='background:{$sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;font-size:11px;'>".strtoupper($sev)."</span></td>";
                $body .= "<td style='padding:8px 12px;color:#334155;font-weight:500;'>".esc_html($iss['type'] ?? 'Threat')."</td>";
                $body .= "<td style='padding:8px 12px;color:#64748b;word-break:break-all;font-family:monospace;font-size:12px;'>".esc_html($iss['file_path'] ?? 'Unknown target')."</td>";
                $body .= "</tr>";
            }
            $body .= "</table>";
            if ($total_count > $limit) {
                $rem = $total_count - $limit;
                $body .= "<div style='margin-top:12px;padding:10px 14px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;font-size:12.5px;color:#475569;'>";
                $body .= "...and <strong>{$rem}</strong> more findings detected. View complete forensic details and 1-click remediation in WordPress Admin.";
                $body .= "</div>";
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
        $notif_url = admin_url('admin.php?page=webcare-pro-notifications');
        $body .= "<div style='border-top:1px solid #1e293b;padding-top:14px;font-size:12px;color:#94a3b8;text-align:center;line-height:1.6;'>";
        $body .= "Automated Security Audit Report generated on <span style='color:#e2e8f0;font-weight:600;'>" . gmdate('Y-m-d H:i:s') . " GMT</span>. You can manage granular notification preferences anytime under <strong>WebCare Pro &gt; <a href='{$notif_url}' style='color:#38bdf8;text-decoration:underline;font-weight:600;'>Notifications</a></strong>.";
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
