<?php
namespace WcpScanner\Quarantine;

use WcpScanner\System\AuditLogger;
use WcpScanner\Firewall\WafFileLogger;
use WcpScanner\Filesystem\PathValidator;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ReinfectionWatchdog
 *
 * 72-Hour Post-Remediation Reinfection Watchdog:
 * Tracks files that were quarantined, disinfected, or repaired to detect
 * self-healing malware resurrecting via background cron loops, stealth pre-loaders,
 * or persistent webhooks.
 *
 * Runs an hourly WP-Cron inspection for 72 hours following remediation.
 */
class ReinfectionWatchdog {

    public const OPTION_WATCHES   = 'wcpscan_reinfection_watches';
    public const OPTION_ALERTS    = 'wcpscan_reinfection_alerts';
    public const CRON_HOOK        = 'wcpscan_reinfection_hourly_check';
    public const WATCH_DURATION   = 259200; // 72 hours in seconds (72 * 3600)

    /**
     * Initialize the watchdog hooks and cron listener.
     */
    public static function init() {
        add_action(self::CRON_HOOK, [__CLASS__, 'run_scheduled_inspection']);

        // Schedule hourly cron if not already scheduled
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK);
        }

        // Automatic registration hooks when quarantine or auto-cure occurs
        add_action('wcpscan_file_quarantined', [__CLASS__, 'on_file_quarantined'], 10, 2);
    }

    /**
     * Listener when a file is quarantined by QuarantineManager.
     *
     * @param string $file_path
     * @param string $sha256
     */
    public static function on_file_quarantined(string $file_path, string $sha256) {
        self::register_watch($file_path, 'deleted', $sha256, 'File quarantined to encrypted vault');
    }

    /**
     * Register a file path for 72-hour reinfection surveillance.
     *
     * @param string      $file_path       Real physical path on disk
     * @param string      $expected_status 'deleted' | 'cleaned'
     * @param string|null $clean_hash      Expected SHA-256 hash if status is 'cleaned'
     * @param string      $reason          Contextual reason for watch
     * @return array
     */
    public static function register_watch(string $file_path, string $expected_status = 'deleted', ?string $clean_hash = null, string $reason = ''): array {
        $real_path = wp_normalize_path(realpath($file_path) ?: $file_path);
        $watches = get_option(self::OPTION_WATCHES, []);
        if (!is_array($watches)) {
            $watches = [];
        }

        $now = time();
        $id  = 'rw_' . substr(md5($real_path), 0, 12);

        $root = defined('ABSPATH') ? wp_normalize_path(ABSPATH) : '';
        $rel_path = ltrim(str_replace($root, '', $real_path), '/');

        $watches[$id] = [
            'id'              => $id,
            'file_path'       => $real_path,
            'rel_path'        => $rel_path,
            'filename'        => basename($real_path),
            'parent_dir'      => dirname($real_path),
            'expected_status' => in_array($expected_status, ['deleted', 'cleaned'], true) ? $expected_status : 'deleted',
            'clean_hash'      => $clean_hash,
            'reason'          => sanitize_text_field($reason ?: 'Post-remediation surveillance'),
            'remediated_at'   => $now,
            'remediated_human'=> current_time('mysql'),
            'expires_at'      => $now + self::WATCH_DURATION,
            'last_checked'    => $now,
            'check_count'     => 1,
            'is_reinfected'   => false,
            'reinfected_at'   => null,
            'reinfection_desc'=> '',
        ];

        update_option(self::OPTION_WATCHES, $watches, false);

        AuditLogger::log(
            'reinfection_watch_registered',
            sprintf('File registered for 72-hour reinfection surveillance: "%s" (Expected: %s).', $rel_path, $expected_status)
        );

        return [
            'success' => true,
            'watch_id'=> $id,
            'message' => sprintf(
                /* translators: %s: relative file path */
                __('Surveillance activated: "%s" will be monitored for reinfection over the next 72 hours.', 'wcp-security-scanner'),
                $rel_path
            ),
        ];
    }

    /**
     * Scheduled hourly cron runner.
     */
    public static function run_scheduled_inspection() {
        self::inspect_all_monitors();
    }

    /**
     * Inspect all active surveillance monitors.
     *
     * @return array
     */
    public static function inspect_all_monitors(): array {
        $watches = get_option(self::OPTION_WATCHES, []);
        if (!is_array($watches)) {
            $watches = [];
        }

        $alerts = get_option(self::OPTION_ALERTS, []);
        if (!is_array($alerts)) {
            $alerts = [];
        }

        $now = time();
        $active_count    = 0;
        $expired_count   = 0;
        $reinfected_count= 0;
        $results         = [];

        foreach ($watches as $id => &$watch) {
            // Check for expiration (> 72 hours)
            if ($now >= $watch['expires_at']) {
                $expired_count++;
                continue;
            }

            $active_count++;
            $watch['last_checked'] = $now;
            $watch['check_count']  = ($watch['check_count'] ?? 0) + 1;

            $path = $watch['file_path'];
            $expected = $watch['expected_status'];
            $reinfection_triggered = false;
            $trigger_reason = '';

            if ($expected === 'deleted') {
                if (file_exists($path)) {
                    $reinfection_triggered = true;
                    $size = @filesize($path) ?: 0;
                    $mtime = @filemtime($path) ?: $now;
                    $trigger_reason = sprintf(
                        /* translators: 1: file size in bytes, 2: formatted time */
                        __('Deleted malware file resurrected on disk! Current size: %1$d bytes, modified at %2$s.', 'wcp-security-scanner'),
                        $size,
                        gmdate('Y-m-d H:i:s', $mtime)
                    );
                }
            } elseif ($expected === 'cleaned') {
                if (file_exists($path)) {
                    $content = @file_get_contents($path);
                    if ($content !== false) {
                        $current_hash = hash('sha256', $content);
                        if (!empty($watch['clean_hash']) && !hash_equals($watch['clean_hash'], $current_hash)) {
                            $reinfection_triggered = true;
                            $trigger_reason = sprintf(
                                /* translators: 1: clean hash, 2: current hash */
                                __('Cleaned file was re-modified or injected! Expected hash %1$s, found %2$s.', 'wcp-security-scanner'),
                                substr($watch['clean_hash'], 0, 12),
                                substr($current_hash, 0, 12)
                            );
                        }
                    }
                } else {
                    // Unexpected deletion of cleaned legitimate file
                    $reinfection_triggered = true;
                    $trigger_reason = __('Cleaned file was unexpectedly removed or altered by external script.', 'wcp-security-scanner');
                }
            }

            if ($reinfection_triggered) {
                $reinfected_count++;
                $watch['is_reinfected']    = true;
                $watch['reinfected_at']    = $now;
                $watch['reinfection_desc'] = $trigger_reason;

                $alert_id = 'alert_' . substr(md5($id . $now), 0, 10);
                $alert_item = [
                    'alert_id'     => $alert_id,
                    'watch_id'     => $id,
                    'file_path'    => $path,
                    'rel_path'     => $watch['rel_path'],
                    'filename'     => $watch['filename'],
                    'detected_at'  => $now,
                    'detected_iso' => gmdate('Y-m-d H:i:s', $now),
                    'reason'       => $trigger_reason,
                    'dismissed'    => false,
                ];

                array_unshift($alerts, $alert_item);
                if (count($alerts) > 50) {
                    $alerts = array_slice($alerts, 0, 50);
                }

                // Log Critical Incident in Audit and Forensic WAF logs
                AuditLogger::log(
                    'malware_reinfection_detected',
                    sprintf('CRITICAL: 72-Hour Watchdog detected malware resurrection: %s (%s)', $watch['rel_path'], $trigger_reason)
                );

                if (class_exists('\\WcpScanner\\Firewall\\WafFileLogger')) {
                    WafFileLogger::log_incident([
                        'category'    => 'malware_reinfection_loop',
                        'rule_id'     => 'wcp_watchdog_resurrection',
                        'description' => sprintf('Malware resurrection loop detected on monitored path: %s. %s', $watch['rel_path'], $trigger_reason),
                        'payload'     => $watch['rel_path'],
                    ], 'blocked');
                }

                // Safely re-quarantine the resurrected/re-injected file to neutralize persistence loops
                if (file_exists($path) && class_exists('\\WcpScanner\\Quarantine\\QuarantineManager')) {
                    try {
                        $qm = new \WcpScanner\Quarantine\QuarantineManager();
                        $quarantine_res = $qm->quarantine_file($path);
                        if (!empty($quarantine_res['success'])) {
                            AuditLogger::log(
                                'malware_reinfection_quarantined',
                                sprintf('72-Hour Watchdog neutralized resurrected file by placing into quarantine vault: %s', $watch['rel_path'])
                            );
                        }
                    } catch (\Throwable $e) {
                        // Prevent unhandled filesystem exceptions from interrupting the batch inspection loop
                    }
                }

                if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                    \WcpScanner\Notifications\NotificationDispatcher::trigger('scan_threats_found', [
                        'threat_count' => 1,
                        'message'      => sprintf('CRITICAL: 72-Hour Watchdog detected malware resurrection on %s: %s', $watch['rel_path'], $trigger_reason),
                    ]);
                }
            }

            $results[] = [
                'id'            => $id,
                'rel_path'      => $watch['rel_path'],
                'is_reinfected' => $watch['is_reinfected'],
                'reason'        => $watch['reinfection_desc'],
            ];
        }
        unset($watch);

        // Clean up expired entries older than 7 days
        $pruned_watches = [];
        foreach ($watches as $k => $w) {
            if ($now < ($w['expires_at'] + (4 * DAY_IN_SECONDS))) {
                $pruned_watches[$k] = $w;
            }
        }

        update_option(self::OPTION_WATCHES, $pruned_watches, false);
        update_option(self::OPTION_ALERTS, $alerts, false);

        return [
            'success'          => true,
            'inspected_at'     => current_time('mysql'),
            'active_monitors'  => $active_count,
            'expired_monitors' => $expired_count,
            'reinfected_alerts'=> $reinfected_count,
            'results'          => $results,
        ];
    }

    /**
     * Retrieve status telemetry and active watches for the dashboard.
     *
     * @return array
     */
    public static function get_status(): array {
        $watches = get_option(self::OPTION_WATCHES, []);
        if (!is_array($watches)) {
            $watches = [];
        }

        $alerts = get_option(self::OPTION_ALERTS, []);
        if (!is_array($alerts)) {
            $alerts = [];
        }

        $now = time();
        $active_items = [];
        $expired_items = [];
        $reinfected_count = 0;

        foreach ($watches as $w) {
            $time_left = max(0, $w['expires_at'] - $now);
            $hours_left = round($time_left / 3600, 1);

            $item = array_merge($w, [
                'time_left_seconds' => $time_left,
                'hours_left'        => $hours_left,
                'is_expired'        => ($now >= $w['expires_at']),
            ]);

            if ($w['is_reinfected']) {
                $reinfected_count++;
            }

            if ($item['is_expired']) {
                $expired_items[] = $item;
            } else {
                $active_items[] = $item;
            }
        }

        // Sort active items: reinfected first, then newest
        usort($active_items, function ($a, $b) {
            if ($a['is_reinfected'] !== $b['is_reinfected']) {
                return $a['is_reinfected'] ? -1 : 1;
            }
            return $b['remediated_at'] <=> $a['remediated_at'];
        });

        return [
            'success'           => true,
            'active_count'      => count($active_items),
            'expired_count'     => count($expired_items),
            'reinfected_count'  => $reinfected_count,
            'total_alerts'      => count($alerts),
            'next_cron_run'     => wp_next_scheduled(self::CRON_HOOK) ? gmdate('Y-m-d H:i:s', wp_next_scheduled(self::CRON_HOOK)) : null,
            'active_watches'    => $active_items,
            'recent_alerts'     => array_slice($alerts, 0, 20),
        ];
    }

    /**
     * Dismiss an alert or cancel a watch.
     *
     * @param string $watch_id
     * @return bool
     */
    public static function dismiss_watch(string $watch_id): bool {
        $watches = get_option(self::OPTION_WATCHES, []);
        if (!is_array($watches) || !isset($watches[$watch_id])) {
            return false;
        }

        unset($watches[$watch_id]);
        update_option(self::OPTION_WATCHES, $watches, false);

        // Also mark related alert as dismissed
        $alerts = get_option(self::OPTION_ALERTS, []);
        if (is_array($alerts)) {
            foreach ($alerts as &$alt) {
                if (($alt['watch_id'] ?? '') === $watch_id) {
                    $alt['dismissed'] = true;
                }
            }
            update_option(self::OPTION_ALERTS, $alerts, false);
        }

        return true;
    }
}
