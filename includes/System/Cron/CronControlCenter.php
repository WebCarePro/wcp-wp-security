<?php
namespace WebCareProScanner\System\Cron;

use WebCareProScanner\Backup\DatabaseBackup;
use WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor;
use WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer;
use WebCareProScanner\Firewall\DomainReputationMonitor;
use WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer;
use WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer;
use WebCareProScanner\Firewall\RedirectCanaryEngine;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\Firewall\ThreatIntelService;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Identity\EphemeralAdminEngine;
use WebCareProScanner\Notifications\NotificationDispatcher;
use WebCareProScanner\Quarantine\ReinfectionWatchdog;
use WebCareProScanner\Security\PluginSelfDefense;
use WebCareProScanner\System\Scheduler;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\WebCareActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Centralized WP-Cron & Scheduled Tasks Control Center.
 *
 * Provides:
 * - Single source of truth for enable/disable status and recurrence synchronized
 *   bidirectionally with SettingsManager, NotificationDispatcher, Options, and Setup Studio.
 * - Re-scheduling guardrails so disabled tasks never quietly re-register on init.
 * - Monitored execution wrapper capturing duration, metrics, skips, and exceptions
 *   in wp_webcareproscan_cron_logs.
 */
class CronControlCenter {

    /**
     * Re-entrancy guard preventing SettingsManager -> CronControlCenter -> SettingsManager loops.
     */
    public static bool $syncing_from_cron_center = false;

    /**
     * Track whether custom cron_schedules filter was registered.
     */
    private static bool $filters_registered = false;

    /**
     * Register custom WordPress cron intervals cleanly once.
     */
    public static function register_filters(): void {
        if (self::$filters_registered) {
            return;
        }
        self::$filters_registered = true;

        add_filter('cron_schedules', static function ($schedules) {
            if (!is_array($schedules)) {
                $schedules = [];
            }
            foreach (CronRegistry::get_custom_intervals() as $slug => $def) {
                if (!isset($schedules[$slug])) {
                    $schedules[$slug] = $def;
                }
            }
            return $schedules;
        });
    }

    /**
     * Evaluate whether a registered cron hook is enabled and whether runtime dependencies are met.
     *
     * @param string     $hook
     * @param array|null $settings
     * @return bool
     */
    public static function is_task_enabled(string $hook, ?array $settings = null): bool {
        $task = CronRegistry::get_task($hook);
        if (!$task) {
            return false;
        }

        if (empty($task['can_disable'])) {
            return true;
        }

        $settings = $settings ?? SettingsManager::get_settings();
        $defaults = SettingsManager::get_defaults();
        $setting_type = $task['setting_type'] ?? 'settings_manager';
        $setting_key  = $task['setting_key'] ?? '';

        if ($setting_type === 'wp_option' && $setting_key !== '') {
            return (bool) get_option($setting_key, true);
        }

        if ($setting_type === 'settings_digest') {
            $digest_setting = !empty($settings['email_digest_enabled']);
            $notif_events   = is_array($settings['notification_events'] ?? null) ? $settings['notification_events'] : [];
            $digest_ev      = is_array($notif_events['weekly_peace_of_mind_digest'] ?? null) ? $notif_events['weekly_peace_of_mind_digest'] : [];
            return $digest_setting || !empty($digest_ev['email']) || !empty($digest_ev['webhook']);
        }

        if ($setting_key !== '') {
            if (array_key_exists($setting_key, $settings)) {
                return !empty($settings[$setting_key]);
            }
            return !empty($defaults[$setting_key]);
        }

        return true;
    }

    /**
     * Evaluate task dependency readiness (e.g. Cloudflare credentials or log retention days > 0).
     *
     * @param string     $hook
     * @param array|null $settings
     * @return array{met: bool, note: string}
     */
    public static function get_dependency_status(string $hook, ?array $settings = null): array {
        $settings = $settings ?? SettingsManager::get_settings();

        if ($hook === 'webcare_cloudflare_ip_sync_cron' || $hook === 'webcare_cf_auto_sync_edge_cron') {
            if (empty($settings['cloudflare_enabled'])) {
                return [
                    'met'  => false,
                    'note' => __('Cloudflare Edge Defense is currently disabled in Settings -> Cloudflare.', 'webcare-pro-security'),
                ];
            }
            if (empty($settings['cloudflare_api_token']) || empty($settings['cloudflare_zone_id'])) {
                return [
                    'met'  => false,
                    'note' => __('Cloudflare API Token and Zone ID are required before automated sync can execute.', 'webcare-pro-security'),
                ];
            }
        }

        if ($hook === 'webcareproscan_waf_log_retention_prune') {
            $days = WafFileLogger::get_retention_days();
            if ($days <= 0) {
                return [
                    'met'  => false,
                    'note' => __('WAF log retention is set to keep forever (0 days).', 'webcare-pro-security'),
                ];
            }
        }

        return ['met' => true, 'note' => ''];
    }

    /**
     * Resolve configured recurrence slug for a task.
     *
     * @param string     $hook
     * @param array|null $settings
     * @return string
     */
    public static function get_configured_recurrence(string $hook, ?array $settings = null): string {
        $task = CronRegistry::get_task($hook);
        if (!$task) {
            return 'daily';
        }

        $settings = $settings ?? SettingsManager::get_settings();
        if ($hook === SettingsManager::CRON_HOOK) {
            $freq = (string) ($settings['schedule_frequency'] ?? 'daily');
            return in_array($freq, $task['allowed_recurrences'], true) ? $freq : 'daily';
        }

        $overrides = is_array($settings['cron_task_schedules'] ?? null) ? $settings['cron_task_schedules'] : [];
        if (!empty($overrides[$hook]) && in_array($overrides[$hook], $task['allowed_recurrences'], true)) {
            return (string) $overrides[$hook];
        }

        return (string) ($task['default_recurrence'] ?? 'daily');
    }

    /**
     * Ensure a recurring WP-Cron hook matches its central enable/schedule state.
     * Replaces direct init/register calls so disabled tasks are never silently re-scheduled.
     *
     * @param string      $hook
     * @param int|null    $first_delay
     * @param string|null $fallback_recurrence
     */
    public static function ensure_scheduled(string $hook, ?int $first_delay = null, ?string $fallback_recurrence = null): void {
        self::register_filters();

        $task = CronRegistry::get_task($hook);
        if (!$task || ($task['kind'] ?? '') !== 'recurring') {
            return;
        }

        $settings = SettingsManager::get_settings();
        $enabled  = self::is_task_enabled($hook, $settings);
        $dep      = self::get_dependency_status($hook, $settings);

        if (!$enabled || ($hook === 'webcare_cloudflare_ip_sync_cron' && !$dep['met'])) {
            if (wp_next_scheduled($hook)) {
                wp_clear_scheduled_hook($hook);
            }
            return;
        }

        if ($hook === SettingsManager::CRON_HOOK) {
            if (!wp_next_scheduled($hook)) {
                SettingsManager::sync_cron_schedule($settings);
            }
            return;
        }

        $desired_recurrence = self::get_configured_recurrence($hook, $settings);
        if ($desired_recurrence === 'on_demand' && $fallback_recurrence) {
            $desired_recurrence = $fallback_recurrence;
        }

        $next_ts       = wp_next_scheduled($hook);
        $current_sched = $next_ts ? wp_get_schedule($hook) : false;

        if ($next_ts && $current_sched === $desired_recurrence) {
            return;
        }

        if ($next_ts) {
            wp_clear_scheduled_hook($hook);
        }

        $delay = $first_delay ?? (int) ($task['default_delay'] ?? 300);
        if ($hook === Scheduler::DIGEST_HOOK) {
            $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone('UTC');
            $dt_target = $desired_recurrence === 'weekly' ? 'next monday 08:00:00' : 'tomorrow 08:00:00';
            try {
                $dt = new \DateTime($dt_target, $tz);
                $first_run = $dt->getTimestamp();
            } catch (\Exception $e) {
                $first_run = time() + 3600;
            }
        } else {
            $first_run = time() + max(15, $delay);
        }

        wp_schedule_event($first_run, $desired_recurrence, $hook);
    }

    /**
     * Synchronize all recurring WP-Cron schedules when plugin settings are saved.
     *
     * @param array|null $settings
     */
    public static function sync_all_from_settings(?array $settings = null): void {
        $settings = $settings ?? SettingsManager::get_settings();

        foreach (CronRegistry::get_tasks() as $hook => $task) {
            if (($task['kind'] ?? '') === 'recurring') {
                self::ensure_scheduled($hook, (int) ($task['default_delay'] ?? 300), (string) ($task['default_recurrence'] ?? 'daily'));
            } elseif ($hook === 'webcare_cf_auto_sync_edge_cron' && (!get_option('webcare_cf_auto_sync_edge', true) || empty($settings['cloudflare_enabled']))) {
                wp_clear_scheduled_hook($hook);
            } elseif ($hook === 'webcareproscan_modular_ast_step' && empty($settings['cron_modular_ast_bg_enabled'] ?? true)) {
                wp_clear_scheduled_hook($hook);
            } elseif ($hook === 'webcareproscan_backup_step_worker' && empty($settings['cron_backup_bg_enabled'] ?? true)) {
                wp_clear_scheduled_hook($hook);
            }
        }
    }

    /**
     * Wrap a cron callback with enabled guardrails, mutex locking, exception capture, and SQL execution logging.
     *
     * @param string   $hook
     * @param callable $callback
     * @param string   $trigger_source
     * @param array    $args
     * @param bool     $bypass_enabled_guard
     * @return array<string, mixed>
     */
    public static function execute_monitored(
        string $hook,
        callable $callback,
        string $trigger_source = 'wp_cron',
        array $args = [],
        bool $bypass_enabled_guard = false
    ): array {
        $task    = CronRegistry::get_task($hook);
        $task_id = $task['id'] ?? sanitize_key($hook);

        if (defined('WP_CLI') && WP_CLI && $trigger_source === 'wp_cron') {
            $trigger_source = 'wp_cli';
        }

        $actor_id = ($trigger_source === 'manual_admin') ? (int) get_current_user_id() : 0;

        if (!$bypass_enabled_guard && !self::is_task_enabled($hook)) {
            if ($task && ($task['kind'] ?? '') === 'recurring') {
                wp_clear_scheduled_hook($hook);
            }
            $log_id = CronExecutionLogger::start_run($task_id, $hook, $trigger_source, $actor_id);
            CronExecutionLogger::finish_run(
                $log_id,
                $task_id,
                $hook,
                $trigger_source,
                'disabled',
                microtime(true),
                __('Execution skipped because this scheduled task is disabled in Cron Control Center.', 'webcare-pro-security')
            );
            return [
                'success' => false,
                'status'  => 'disabled',
                'summary' => __('Task is disabled.', 'webcare-pro-security'),
            ];
        }

        $lock_suffix = empty($args) ? '' : '_' . md5((string) wp_json_encode($args));
        $lock_key    = 'webcareproscan_cron_lock_' . md5($hook) . $lock_suffix;
        if (get_transient($lock_key)) {
            $log_id = CronExecutionLogger::start_run($task_id, $hook, $trigger_source, $actor_id);
            CronExecutionLogger::finish_run(
                $log_id,
                $task_id,
                $hook,
                $trigger_source,
                'skipped',
                microtime(true),
                __('Skipped overlapping execution because another run is already in progress.', 'webcare-pro-security')
            );
            return [
                'success' => true,
                'status'  => 'skipped',
                'summary' => __('Another instance of this task is currently running.', 'webcare-pro-security'),
            ];
        }

        set_transient($lock_key, time(), 180);
        $started_micro = microtime(true);
        $log_id        = CronExecutionLogger::start_run($task_id, $hook, $trigger_source, $actor_id);

        try {
            $raw = call_user_func_array($callback, $args);

            $status  = 'success';
            $summary = __('Task executed cleanly.', 'webcare-pro-security');
            $metrics = [];

            if (is_array($raw)) {
                if (isset($raw['status']) && in_array($raw['status'], ['success', 'skipped', 'disabled', 'failed'], true)) {
                    $status = (string) $raw['status'];
                }
                if (!empty($raw['summary'])) {
                    $summary = (string) $raw['summary'];
                }
                if (!empty($raw['metrics']) && is_array($raw['metrics'])) {
                    $metrics = $raw['metrics'];
                }
            }

            if ($bypass_enabled_guard && !self::is_task_enabled($hook) && $trigger_source === 'manual_admin') {
                $summary .= ' ' . __('(Manual admin trigger while schedule paused)', 'webcare-pro-security');
            }

            CronExecutionLogger::finish_run(
                $log_id,
                $task_id,
                $hook,
                $trigger_source,
                $status,
                $started_micro,
                $summary,
                $metrics
            );

            delete_transient($lock_key);

            return [
                'success'     => ($status !== 'failed'),
                'status'      => $status,
                'summary'     => $summary,
                'metrics'     => $metrics,
                'duration_ms' => max(1, (int) round((microtime(true) - $started_micro) * 1000)),
                'log_id'      => $log_id,
            ];
        } catch (\Throwable $e) {
            $err = $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')';
            CronExecutionLogger::finish_run(
                $log_id,
                $task_id,
                $hook,
                $trigger_source,
                'failed',
                $started_micro,
                __('Task aborted with an unhandled exception.', 'webcare-pro-security'),
                [],
                $err
            );
            delete_transient($lock_key);

            return [
                'success'       => false,
                'status'        => 'failed',
                'summary'       => $err,
                'error_message' => $err,
                'duration_ms'   => max(1, (int) round((microtime(true) - $started_micro) * 1000)),
                'log_id'        => $log_id,
            ];
        }
    }

    /**
     * Toggle a task enabled or disabled and synchronize all linked settings & schedules.
     *
     * @param string $hook
     * @param bool   $enabled
     * @return array<string, mixed>|\WP_Error
     */
    public static function toggle_task(string $hook, bool $enabled) {
        $task = CronRegistry::get_task($hook);
        if (!$task) {
            return new \WP_Error('unknown_cron_hook', __('Unknown scheduled task hook.', 'webcare-pro-security'), ['status' => 404]);
        }

        if (empty($task['can_disable']) && !$enabled) {
            return new \WP_Error('security_safeguard_locked', __('Security-enforced safeguard timers cannot be disabled.', 'webcare-pro-security'), ['status' => 403]);
        }

        self::$syncing_from_cron_center = true;
        try {
            $setting_type = $task['setting_type'] ?? 'settings_manager';
            $setting_key  = $task['setting_key'] ?? '';

            if ($setting_type === 'wp_option' && $setting_key !== '') {
                update_option($setting_key, (bool) $enabled, false);
                if (!$enabled) {
                    wp_clear_scheduled_hook($hook);
                }
            } elseif ($setting_type === 'settings_digest') {
                $settings = SettingsManager::get_settings();
                $events   = is_array($settings['notification_events'] ?? null) ? $settings['notification_events'] : SettingsManager::get_default_notification_events();
                $cur_ev   = is_array($events['weekly_peace_of_mind_digest'] ?? null) ? $events['weekly_peace_of_mind_digest'] : ['email' => false, 'webhook' => false];

                if ($enabled) {
                    $events['weekly_peace_of_mind_digest'] = [
                        'email'   => true,
                        'webhook' => !empty($cur_ev['webhook']),
                    ];
                } else {
                    $events['weekly_peace_of_mind_digest'] = [
                        'email'   => false,
                        'webhook' => false,
                    ];
                }

                SettingsManager::save_settings([
                    'email_digest_enabled' => $enabled,
                    'notification_events'  => $events,
                ]);
            } elseif ($setting_key !== '') {
                SettingsManager::save_settings([
                    $setting_key => $enabled,
                ]);
            }

            if ($enabled) {
                self::ensure_scheduled($hook, (int) ($task['default_delay'] ?? 300), (string) ($task['default_recurrence'] ?? 'daily'));
            } else {
                wp_clear_scheduled_hook($hook);
            }
        } finally {
            self::$syncing_from_cron_center = false;
        }

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::notice(
                'cron_task_toggled',
                'settings',
                [
                    /* translators: 1: task title, 2: enabled or disabled state */
                    'description' => sprintf(__('Scheduled task "%1$s" %2$s via Cron Control Center.', 'webcare-pro-security'), $task['title'], $enabled ? 'enabled' : 'disabled'),
                    'hook'        => $hook,
                    'enabled'     => $enabled,
                ]
            );
        }

        return [
            'success' => true,
            'task'    => self::format_task_state($hook),
            /* translators: 1: task title, 2: enabled or disabled state */
            'message' => sprintf(__('%1$s has been %2$s and synchronized with plugin settings.', 'webcare-pro-security'), $task['title'], $enabled ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
        ];
    }

    /**
     * Update a task's recurrence frequency (plus optional scan_time / scan_type for main scheduled scan).
     *
     * @param string               $hook
     * @param string               $frequency
     * @param array<string, mixed> $extra
     * @return array<string, mixed>|\WP_Error
     */
    public static function update_task_schedule(string $hook, string $frequency, array $extra = []) {
        $task = CronRegistry::get_task($hook);
        if (!$task) {
            return new \WP_Error('unknown_cron_hook', __('Unknown scheduled task hook.', 'webcare-pro-security'), ['status' => 404]);
        }

        if (($task['kind'] ?? '') !== 'recurring') {
            return new \WP_Error('not_recurring_task', __('On-demand background workers do not use a fixed recurrence schedule.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!in_array($frequency, $task['allowed_recurrences'], true)) {
            return new \WP_Error('invalid_frequency', __('Selected interval is not supported for this task.', 'webcare-pro-security'), ['status' => 400]);
        }

        self::$syncing_from_cron_center = true;
        try {
            $settings  = SettingsManager::get_settings();
            $schedules = is_array($settings['cron_task_schedules'] ?? null) ? $settings['cron_task_schedules'] : [];
            $schedules[$hook] = $frequency;

            $payload = ['cron_task_schedules' => $schedules];

            if ($hook === SettingsManager::CRON_HOOK) {
                $payload['schedule_frequency'] = $frequency;
                if (!empty($extra['schedule_time']) && preg_match('/^\d{2}:\d{2}$/', (string) $extra['schedule_time'])) {
                    $payload['schedule_time'] = sanitize_text_field((string) $extra['schedule_time']);
                }
                if (!empty($extra['schedule_scan_type'])) {
                    $payload['schedule_scan_type'] = sanitize_key((string) $extra['schedule_scan_type']);
                }
                $updated = SettingsManager::save_settings($payload);
                if (self::is_task_enabled($hook, $updated)) {
                    SettingsManager::sync_cron_schedule($updated);
                }
            } else {
                SettingsManager::save_settings($payload);
                wp_clear_scheduled_hook($hook);
                self::ensure_scheduled($hook, (int) ($task['default_delay'] ?? 300), $frequency);
            }
        } finally {
            self::$syncing_from_cron_center = false;
        }

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::notice(
                'cron_task_rescheduled',
                'settings',
                [
                    /* translators: 1: task title, 2: recurrence slug */
                    'description' => sprintf(__('Scheduled task "%1$s" interval changed to %2$s.', 'webcare-pro-security'), $task['title'], $frequency),
                    'hook'        => $hook,
                    'frequency'   => $frequency,
                ]
            );
        }

        return [
            'success' => true,
            'task'    => self::format_task_state($hook),
            /* translators: 1: task title, 2: frequency slug */
            'message' => sprintf(__('Updated schedule for %1$s (%2$s).', 'webcare-pro-security'), $task['title'], $frequency),
        ];
    }

    /**
     * Trigger immediate execution of any registered task with full logging and audit attribution.
     *
     * @param string $hook
     * @return array<string, mixed>|\WP_Error
     */
    public static function run_task_now(string $hook) {
        $task = CronRegistry::get_task($hook);
        if (!$task) {
            return new \WP_Error('unknown_cron_hook', __('Unknown scheduled task hook.', 'webcare-pro-security'), ['status' => 404]);
        }

        $result = self::invoke_task_handler($hook, 'manual_admin', [], true);

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::info(
                'cron_task_manual_run',
                'system',
                [
                    /* translators: 1: task title, 2: status string */
                    'description' => sprintf(__('Administrator manually executed task "%1$s" (status: %2$s).', 'webcare-pro-security'), $task['title'], $result['status'] ?? 'success'),
                    'hook'        => $hook,
                    'status'      => $result['status'] ?? 'success',
                    'duration_ms' => $result['duration_ms'] ?? 0,
                ]
            );
        }

        $result['task'] = self::format_task_state($hook);
        return $result;
    }

    /**
     * Dispatch the real subsystem logic under execute_monitored() telemetry.
     *
     * @param string $hook
     * @param string $trigger_source
     * @param array  $args
     * @param bool   $bypass_enabled_guard
     * @return array<string, mixed>
     */
    public static function invoke_task_handler(
        string $hook,
        string $trigger_source = 'wp_cron',
        array $args = [],
        bool $bypass_enabled_guard = false
    ): array {
        return self::execute_monitored(
            $hook,
            static function (...$cb_args) use ($hook, $trigger_source) {
                switch ($hook) {
                    case 'webcareproscan_scheduled_scan_event':
                        $before_ts = time();
                        Scheduler::run_scheduled_scan(true);
                        global $wpdb;
                        $scans_table = $wpdb->prefix . 'webcareproscan_scans';
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                        $latest = $wpdb->get_row(
                            $wpdb->prepare(
                                'SELECT id, status, scanned_files, issues_found, risk_score, scan_target FROM %i WHERE trigger_type = %s ORDER BY id DESC LIMIT 1',
                                $scans_table,
                                'scheduled'
                            ),
                            ARRAY_A
                        );
                        if (is_array($latest)) {
                            return [
                                'status'  => ($latest['status'] ?? '') === 'interrupted' ? 'failed' : 'success',
                                /* translators: 1: scan ID, 2: file count, 3: findings count */
                                'summary' => sprintf(__('Scan #%1$d (%2$d files inspected, %3$d open finding(s)).', 'webcare-pro-security'), (int) $latest['id'], (int) $latest['scanned_files'], (int) $latest['issues_found']),
                                'metrics' => $latest,
                            ];
                        }
                        return ['status' => 'success', 'summary' => __('Scheduled malware audit executed.', 'webcare-pro-security')];

                    case 'webcareproscan_modular_ast_step':
                        $state = get_option('webcareproscan_modular_scan_state', []);
                        if (!is_array($state) || ($state['status'] ?? '') !== 'running') {
                            return [
                                'status'  => 'skipped',
                                'summary' => __('No active Modular WAF AST scan session waiting in queue.', 'webcare-pro-security'),
                            ];
                        }
                        $before = (int) ($state['processed_files'] ?? 0);
                        $prog   = ($trigger_source === 'manual_admin')
                            ? SiteBehavioralAnalyzer::process_batch(400)
                            : SiteBehavioralAnalyzer::get_scan_progress();
                        if ($trigger_source !== 'manual_admin') {
                            SiteBehavioralAnalyzer::run_background_cron_step(true);
                            $prog = SiteBehavioralAnalyzer::get_scan_progress();
                        }
                        $after = (int) ($prog['processed_files'] ?? $before);
                        $delta = max(0, $after - $before);
                        return [
                            'status'  => 'success',
                            /* translators: 1: batch files processed, 2: processed count, 3: total count */
                            'summary' => sprintf(__('Advanced AST scan by %1$d file(s) (%2$d / %3$d total).', 'webcare-pro-security'), $delta, $after, (int) ($prog['total_files'] ?? $after)),
                            'metrics' => ['delta_files' => $delta, 'processed_files' => $after, 'total_files' => (int) ($prog['total_files'] ?? 0)],
                        ];

                    case 'webcareproscan_threat_intel_cron_sync':
                        $res = ThreatIntelService::sync_threat_intelligence();
                        return [
                            'status'  => !empty($res['success']) ? 'success' : 'failed',
                            /* translators: 1: total IPs, 2: CVE count, 3: newly fetched IPs */
                            'summary' => sprintf(__('Synced %1$d threat IPs and %2$d CVEs (%3$d fetched from live feeds).', 'webcare-pro-security'), (int) ($res['total_ips'] ?? 0), (int) ($res['total_cves'] ?? 0), (int) ($res['downloaded_ips'] ?? 0)),
                            'metrics' => $res,
                        ];

                    case 'webcareproscan_redirect_canary_event':
                        $rep      = RedirectCanaryEngine::run_scheduled_canary();
                        $findings = is_array($rep['findings'] ?? null) ? count($rep['findings']) : 0;
                        return [
                            'status'  => 'success',
                            'summary' => !empty($rep['is_hostile'])
                                /* translators: %d: findings count */
                                ? sprintf(__('Detected %d redirect/cloaking anomaly indicator(s).', 'webcare-pro-security'), $findings)
                                : __('All synthetic cloaking and database URL probes verified clean.', 'webcare-pro-security'),
                            'metrics' => ['severity' => $rep['severity'] ?? 'clean', 'findings_count' => $findings, 'auto_healed' => !empty($rep['auto_healed'])],
                        ];

                    case 'webcareproscan_modular_autopilot_cron':
                        $promoted = ModularFirewallSynthesizer::evaluate_autopilot_promotions();
                        return [
                            'status'  => 'success',
                            'summary' => $promoted > 0
                                /* translators: %d: promoted rules count */
                                ? sprintf(__('Promoted %d Modular WAF rule(s) to Enforce after 48h observation.', 'webcare-pro-security'), $promoted)
                                : __('48h Auto-Pilot queue evaluated cleanly; no rules eligible for promotion yet.', 'webcare-pro-security'),
                            'metrics' => ['promoted_rules' => $promoted],
                        ];

                    case 'webcare_cloudflare_ip_sync_cron':
                        $dep = self::get_dependency_status($hook);
                        if (!$dep['met']) {
                            return ['status' => 'skipped', 'summary' => $dep['note']];
                        }
                        $sync    = new CloudflareIpListSynchronizer();
                        $flushed = $sync->process_sync_queue();
                        return [
                            'status'  => $flushed > 0 ? 'success' : 'skipped',
                            'summary' => $flushed > 0
                                /* translators: %d: synced IP count */
                                ? sprintf(__('Synchronized %d queued origin block IP(s) with Cloudflare Edge.', 'webcare-pro-security'), $flushed)
                                : __('Cloudflare IP sync queue is empty; zero pending blocks.', 'webcare-pro-security'),
                            'metrics' => ['flushed_count' => $flushed],
                        ];

                    case 'webcare_cf_auto_sync_edge_cron':
                        $dep = self::get_dependency_status($hook);
                        if (!$dep['met']) {
                            return ['status' => 'skipped', 'summary' => $dep['note']];
                        }
                        AdaptiveFirewallAdvisor::execute_edge_auto_sync();
                        return [
                            'status'  => 'success',
                            'summary' => __('Cloudflare Edge firewall slot optimization rules synchronized.', 'webcare-pro-security'),
                        ];

                    case 'webcareproscan_self_defense_watchdog_event':
                        PluginSelfDefense::run_scheduled_watchdog(true);
                        $audit    = get_option(PluginSelfDefense::DB_LAST_AUDIT_OPTION, []);
                        $modified = (int) ($audit['modified_count'] ?? 0);
                        $missing  = (int) ($audit['missing_count'] ?? 0);
                        return [
                            'status'  => 'success',
                            'summary' => ($modified > 0 || $missing > 0)
                                /* translators: 1: modified file count, 2: missing file count */
                                ? sprintf(__('Integrity anomaly: %1$d modified and %2$d missing plugin file(s).', 'webcare-pro-security'), $modified, $missing)
                                : __('Plugin self-defense manifest verified intact with 0 file anomalies.', 'webcare-pro-security'),
                            'metrics' => ['modified_count' => $modified, 'missing_count' => $missing, 'status' => $audit['status'] ?? 'clean'],
                        ];

                    case 'webcareproscan_reinfection_hourly_check':
                        $res = ReinfectionWatchdog::inspect_all_monitors();
                        return [
                            'status'  => 'success',
                            /* translators: 1: active watch count, 2: reinfection alert count */
                            'summary' => sprintf(__('Inspected %1$d 72h file watch(es); %2$d reinfection alert(s) triggered.', 'webcare-pro-security'), (int) ($res['active_monitors'] ?? 0), (int) ($res['reinfected_alerts'] ?? 0)),
                            'metrics' => [
                                'active_monitors'   => (int) ($res['active_monitors'] ?? 0),
                                'expired_monitors'  => (int) ($res['expired_monitors'] ?? 0),
                                'reinfected_alerts' => (int) ($res['reinfected_alerts'] ?? 0),
                            ],
                        ];

                    case 'webcareproscan_domain_reputation_daily_check':
                        $force = ($trigger_source === 'manual_admin');
                        $res   = DomainReputationMonitor::run_reputation_audit($force);
                        $issues = is_array($res['issues'] ?? null) ? count($res['issues']) : 0;
                        return [
                            'status'  => 'success',
                            /* translators: 1: reputation score, 2: issues count */
                            'summary' => sprintf(__('Domain reputation score: %1$d/100 (%2$d SSL/DNSBL/email advisory flag(s)).', 'webcare-pro-security'), (int) ($res['score'] ?? 100), $issues),
                            'metrics' => ['score' => (int) ($res['score'] ?? 100), 'issues_count' => $issues],
                        ];

                    case 'webcareproscan_waf_log_retention_prune':
                        $days = WafFileLogger::get_retention_days();
                        if ($days <= 0) {
                            return ['status' => 'skipped', 'summary' => __('Retention set to forever (0 days); no logs pruned.', 'webcare-pro-security')];
                        }
                        $pruned = WafFileLogger::prune_expired_logs();
                        return [
                            'status'  => 'success',
                            /* translators: 1: pruned file count, 2: retention days */
                            'summary' => sprintf(__('Pruned %1$d expired WAF log shard(s) older than %2$d days.', 'webcare-pro-security'), $pruned, $days),
                            'metrics' => ['pruned_files' => $pruned, 'retention_days' => $days],
                        ];

                    case 'webcareproscan_weekly_digest_event':
                        $force = ($trigger_source === 'manual_admin');
                        $sent  = Scheduler::run_weekly_digest($force);
                        if (!$sent) {
                            return [
                                'status'  => 'skipped',
                                'summary' => __('Skipped digest dispatch because both email and webhook weekly digest channels are disabled.', 'webcare-pro-security'),
                            ];
                        }
                        return [
                            'status'  => 'success',
                            'summary' => __('Weekly peace-of-mind security telemetry digest compiled and dispatched.', 'webcare-pro-security'),
                        ];

                    case 'webcareproscan_backup_step_worker':
                        $sess_id = get_option(DatabaseBackup::OPTION_ACTIVE_SESSION, '');
                        if (empty($sess_id)) {
                            return [
                                'status'  => 'skipped',
                                'summary' => __('No active database backup export session queued.', 'webcare-pro-security'),
                            ];
                        }
                        DatabaseBackup::run_background_step();
                        return [
                            'status'  => 'success',
                            'summary' => __('Executed one incremental Database Backup Vault export chunk.', 'webcare-pro-security'),
                        ];

                    case 'webcareproscan_auto_rearm_waf':
                        $paused_until = (int) get_option(RescueAssistantManager::OPTION_PAUSED_UNTIL, 0);
                        if ($paused_until <= 0) {
                            return [
                                'status'  => 'skipped',
                                'summary' => __('Strict WAF is already armed (no active Rescue Test Pause).', 'webcare-pro-security'),
                            ];
                        }
                        RescueAssistantManager::resume_strict_firewall();
                        return [
                            'status'  => 'success',
                            'summary' => __('Strict WAF blocking re-armed cleanly.', 'webcare-pro-security'),
                        ];

                    case 'webcareproscan_ephemeral_admin_expire':
                        $uid = isset($cb_args[0]) ? (int) $cb_args[0] : 0;
                        if ($uid > 0) {
                            EphemeralAdminEngine::on_cron_expire_elevation($uid);
                            return [
                                'status'  => 'success',
                                /* translators: %d: WordPress user ID */
                                'summary' => sprintf(__('Reverted expired JIT temporary administrator access for user #%d.', 'webcare-pro-security'), $uid),
                            ];
                        }
                        $before_map = get_option(EphemeralAdminEngine::OPTION_EPHEMERAL_ADMINS, []);
                        $before_cnt = is_array($before_map) ? count($before_map) : 0;
                        EphemeralAdminEngine::check_and_expire_elevations();
                        $after_map  = get_option(EphemeralAdminEngine::OPTION_EPHEMERAL_ADMINS, []);
                        $after_cnt  = is_array($after_map) ? count($after_map) : 0;
                        $revoked    = max(0, $before_cnt - $after_cnt);
                        return [
                            'status'  => $revoked > 0 ? 'success' : 'skipped',
                            'summary' => $revoked > 0
                                /* translators: %d: revoked count */
                                ? sprintf(__('Revoked %d overdue JIT administrator elevation(s).', 'webcare-pro-security'), $revoked)
                                : __('Verified active JIT grants; zero overdue elevations pending expiration.', 'webcare-pro-security'),
                            'metrics' => ['revoked_count' => $revoked, 'remaining_active' => $after_cnt],
                        ];
                }

                return ['status' => 'skipped', 'summary' => __('No handler mapped for hook.', 'webcare-pro-security')];
            },
            $trigger_source,
            $args,
            $bypass_enabled_guard
        );
    }

    /**
     * Re-schedule all enabled tasks missing from wp_options['cron'].
     *
     * @return array<string, mixed>
     */
    public static function repair_missing_schedules(): array {
        $repaired = [];
        $settings = SettingsManager::get_settings();

        foreach (CronRegistry::get_tasks() as $hook => $task) {
            if (($task['kind'] ?? '') !== 'recurring') {
                continue;
            }
            $enabled = self::is_task_enabled($hook, $settings);
            $dep     = self::get_dependency_status($hook, $settings);
            if ($enabled && $dep['met'] && !wp_next_scheduled($hook)) {
                self::ensure_scheduled($hook, (int) ($task['default_delay'] ?? 300), (string) ($task['default_recurrence'] ?? 'daily'));
                $repaired[] = $hook;
            }
        }

        if (class_exists(WebCareActivityLogger::class) && !empty($repaired)) {
            WebCareActivityLogger::info(
                'cron_schedules_repaired',
                'system',
                [
                    /* translators: %d: repaired hook count */
                    'description' => sprintf(__('Repaired %d missing WP-Cron schedule(s) via Cron Control Center.', 'webcare-pro-security'), count($repaired)),
                    'hooks'       => $repaired,
                ]
            );
        }

        return [
            'success'        => true,
            'repaired_hooks' => $repaired,
            'repaired_count' => count($repaired),
        ];
    }

    /**
     * Execute bulk control action (`enable_recommended`, `disable_optional`, `repair_schedules`).
     *
     * @param string $action
     * @return array<string, mixed>|\WP_Error
     */
    public static function bulk_action(string $action) {
        if ($action === 'repair_schedules') {
            $res = self::repair_missing_schedules();
            return array_merge($res, self::get_overview());
        }

        if ($action === 'enable_recommended') {
            foreach (CronRegistry::get_tasks() as $hook => $task) {
                if (($task['kind'] ?? '') === 'recurring') {
                    self::toggle_task($hook, true);
                }
            }
            return array_merge([
                'success' => true,
                'message' => __('All recurring security tasks enabled and synchronized.', 'webcare-pro-security'),
            ], self::get_overview());
        }

        if ($action === 'disable_optional') {
            foreach (CronRegistry::get_tasks() as $hook => $task) {
                if (!empty($task['can_disable']) && ($task['kind'] ?? '') === 'recurring') {
                    self::toggle_task($hook, false);
                }
            }
            return array_merge([
                'success' => true,
                'message' => __('All optional recurring tasks paused. Security safeguards remain protected.', 'webcare-pro-security'),
            ], self::get_overview());
        }

        return new \WP_Error('invalid_bulk_action', __('Unsupported bulk action.', 'webcare-pro-security'), ['status' => 400]);
    }

    /**
     * Build complete formatted state object for one registered task.
     *
     * @param string     $hook
     * @param array|null $settings
     * @param array|null $last_runs
     * @return array<string, mixed>
     */
    public static function format_task_state(string $hook, ?array $settings = null, ?array $last_runs = null): array {
        $task      = CronRegistry::get_task($hook);
        $settings  = $settings ?? SettingsManager::get_settings();
        $last_runs = $last_runs ?? CronExecutionLogger::get_last_runs_map();
        $intervals = CronRegistry::get_recurrence_catalog();

        $enabled      = self::is_task_enabled($hook, $settings);
        $dep          = self::get_dependency_status($hook, $settings);
        $recurrence   = self::get_configured_recurrence($hook, $settings);
        $next_ts      = self::resolve_next_timestamp($hook);
        $live_sched   = $next_ts ? (wp_get_schedule($hook) ?: $recurrence) : null;
        $now          = time();
        $is_overdue   = ($next_ts !== null && $next_ts < ($now - 300));
        $last_run     = $last_runs[$hook] ?? null;

        $allowed_formatted = [];
        foreach (($task['allowed_recurrences'] ?? []) as $slug) {
            $allowed_formatted[] = [
                'value' => $slug,
                'label' => $intervals[$slug]['label'] ?? ucfirst($slug),
            ];
        }

        $extra = [];
        if ($hook === SettingsManager::CRON_HOOK) {
            $extra = [
                'schedule_time'      => (string) ($settings['schedule_time'] ?? '02:00'),
                'schedule_scan_type' => (string) ($settings['schedule_scan_type'] ?? 'plugins_themes'),
            ];
        }

        return [
            'id'                   => $task['id'] ?? $hook,
            'hook'                 => $hook,
            'title'                => $task['title'] ?? $hook,
            'description'          => $task['description'] ?? '',
            'category'             => $task['category'] ?? 'system',
            'kind'                 => $task['kind'] ?? 'recurring',
            'can_disable'          => !empty($task['can_disable']),
            'enabled'              => $enabled,
            'dependency_met'       => $dep['met'],
            'dependency_note'      => $dep['note'],
            'setting_key'          => $task['setting_key'] ?? null,
            'setting_location'     => $task['setting_location'] ?? '',
            'deep_link'            => $task['deep_link'] ?? '',
            'recurrence'           => $recurrence,
            'recurrence_label'     => $recurrence === 'on_demand'
                ? __('On-Demand Trigger', 'webcare-pro-security')
                : ($intervals[$recurrence]['label'] ?? ucfirst($recurrence)),
            'live_schedule'        => $live_sched,
            'allowed_recurrences'  => $allowed_formatted,
            'is_scheduled'         => ($next_ts !== null),
            'next_run_timestamp'   => $next_ts,
            'next_run_local'       => $next_ts ? wp_date('Y-m-d H:i:s', $next_ts) : null,
            'next_run_relative'    => $next_ts
                ? ($next_ts >= $now
                    /* translators: %s: human-readable time difference */
                    ? sprintf(__('In %s', 'webcare-pro-security'), human_time_diff($now, $next_ts))
                    /* translators: %s: human-readable overdue duration */
                    : sprintf(__('%s overdue', 'webcare-pro-security'), human_time_diff($next_ts, $now)))
                : null,
            'is_overdue'           => $is_overdue,
            'extra'                => $extra,
            'last_run'             => $last_run,
        ];
    }

    /**
     * Resolve next scheduled UTC timestamp, including parameterized hooks like ephemeral_admin_expire.
     *
     * @param string $hook
     * @return int|null
     */
    private static function resolve_next_timestamp(string $hook): ?int {
        $ts = wp_next_scheduled($hook);
        if ($ts) {
            return (int) $ts;
        }

        if ($hook === EphemeralAdminEngine::CRON_HOOK) {
            $cron_array = _get_cron_array();
            if (is_array($cron_array)) {
                $earliest = null;
                foreach ($cron_array as $timestamp => $hooks) {
                    if (isset($hooks[$hook]) && is_numeric($timestamp)) {
                        $t = (int) $timestamp;
                        if ($earliest === null || $t < $earliest) {
                            $earliest = $t;
                        }
                    }
                }
                return $earliest;
            }
        }

        return null;
    }

    /**
     * Build complete Overview payload for the Cron & Task Control REST API.
     *
     * @return array<string, mixed>
     */
    public static function get_overview(): array {
        $settings  = SettingsManager::get_settings();
        $last_runs = CronExecutionLogger::get_last_runs_map();
        $stats_24h = CronExecutionLogger::get_24h_stats();
        $tasks     = [];

        $enabled_count       = 0;
        $disabled_count      = 0;
        $overdue_count       = 0;
        $missing_sched_count = 0;

        foreach (CronRegistry::get_tasks() as $hook => $meta) {
            $item = self::format_task_state($hook, $settings, $last_runs);
            $tasks[] = $item;

            if ($item['enabled']) {
                $enabled_count++;
            } else {
                $disabled_count++;
            }
            if ($item['is_overdue']) {
                $overdue_count++;
            }
            if ($item['kind'] === 'recurring' && $item['enabled'] && $item['dependency_met'] && !$item['is_scheduled']) {
                $missing_sched_count++;
            }
        }

        $cron_array       = function_exists('_get_cron_array') ? (_get_cron_array() ?: []) : [];
        $all_hooks_seen   = [];
        $our_hooks        = array_fill_keys(CronRegistry::get_all_hook_names(), true);
        foreach ($cron_array as $ts => $hooks) {
            if (!is_array($hooks)) {
                continue;
            }
            foreach (array_keys($hooks) as $hk) {
                if (!isset($our_hooks[$hk])) {
                    $all_hooks_seen[$hk] = true;
                }
            }
        }

        return [
            'health' => [
                'disable_wp_cron'          => defined('DISABLE_WP_CRON') && DISABLE_WP_CRON,
                'alternate_wp_cron'        => defined('ALTERNATE_WP_CRON') && ALTERNATE_WP_CRON,
                'site_time'                => current_time('mysql'),
                'timezone'                 => function_exists('wp_timezone_string') ? wp_timezone_string() : 'UTC',
                'total_tasks'              => count($tasks),
                'enabled_count'            => $enabled_count,
                'disabled_count'           => $disabled_count,
                'overdue_count'            => $overdue_count,
                'missing_schedule_count'   => $missing_sched_count,
                'third_party_hooks_count'  => count($all_hooks_seen),
                'retention_days'           => (int) ($settings['cron_log_retention_days'] ?? 30),
                'runs_24h'                 => $stats_24h['runs_24h'],
                'success_24h'              => $stats_24h['success_24h'],
                'skipped_24h'              => $stats_24h['skipped_24h'],
                'failed_24h'               => $stats_24h['failed_24h'],
            ],
            'categories' => CronRegistry::get_categories(),
            'tasks'      => $tasks,
        ];
    }
}
