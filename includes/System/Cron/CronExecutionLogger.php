<?php
namespace WebCareProScanner\System\Cron;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\WebCareActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Persists structured WP-Cron execution records into wp_webcareproscan_cron_logs,
 * maintains O(1) last-run snapshots, enforces retention, and bridges critical events
 * into the cryptographic WebCareActivityLogger.
 */
class CronExecutionLogger {

    public const OPTION_LAST_RUNS = 'webcareproscan_cron_last_runs';
    public const MAX_RETAINED_ROWS = 2000;

    /**
     * Get the qualified execution logs table name.
     *
     * @return string
     */
    public static function get_table_name(): string {
        global $wpdb;
        return $wpdb->prefix . 'webcareproscan_cron_logs';
    }

    /**
     * Ensure table exists cleanly when upgrade runs inline before activation hook.
     */
    private static function ensure_table_exists(): void {
        if (get_option('webcareproscan_db_version') !== '1.13.0' && class_exists('\\WebCareProScanner\\Database\\Migration')) {
            \WebCareProScanner\Database\Migration::install();
        }
    }

    /**
     * Insert initial running record and return row ID.
     *
     * @param string $task_id
     * @param string $hook
     * @param string $trigger_source
     * @param int    $actor_id
     * @return int
     */
    public static function start_run(string $task_id, string $hook, string $trigger_source = 'wp_cron', int $actor_id = 0): int {
        global $wpdb;
        self::ensure_table_exists();

        $table = self::get_table_name();
        $now_local = current_time('mysql');
        $now_gmt   = gmdate('Y-m-d H:i:s');

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $inserted = $wpdb->insert(
            $table,
            [
                'task_id'        => sanitize_key($task_id),
                'hook_name'      => sanitize_text_field($hook),
                'trigger_source' => sanitize_key($trigger_source),
                'status'         => 'running',
                'started_at'     => $now_local,
                'completed_at'   => null,
                'duration_ms'    => 0,
                'summary'        => '',
                'metrics_json'   => null,
                'error_message'  => null,
                'actor_id'       => max(0, $actor_id),
                'created_at_gmt' => $now_gmt,
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s']
        );

        return $inserted ? (int) $wpdb->insert_id : 0;
    }

    /**
     * Finalize execution row, refresh cached snapshot, bridge errors to Activity Log,
     * and run lightweight retention pruning.
     *
     * @param int                  $log_id
     * @param string               $task_id
     * @param string               $hook
     * @param string               $trigger_source
     * @param string               $status        'success'|'skipped'|'disabled'|'failed'
     * @param float                $started_micro
     * @param string               $summary
     * @param array<string, mixed> $metrics
     * @param string               $error_message
     */
    public static function finish_run(
        int $log_id,
        string $task_id,
        string $hook,
        string $trigger_source,
        string $status,
        float $started_micro,
        string $summary = '',
        array $metrics = [],
        string $error_message = ''
    ): void {
        global $wpdb;

        $valid_statuses = ['success', 'skipped', 'disabled', 'failed'];
        if (!in_array($status, $valid_statuses, true)) {
            $status = 'success';
        }

        $duration_ms   = max(1, (int) round((microtime(true) - $started_micro) * 1000));
        $completed_at  = current_time('mysql');
        $completed_gmt = gmdate('Y-m-d H:i:s');
        $metrics_json  = !empty($metrics) ? wp_json_encode($metrics) : null;
        $table         = self::get_table_name();

        if ($log_id > 0) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update(
                $table,
                [
                    'status'        => $status,
                    'completed_at'  => $completed_at,
                    'duration_ms'   => $duration_ms,
                    'summary'       => sanitize_text_field(substr($summary, 0, 500)),
                    'metrics_json'  => $metrics_json,
                    'error_message' => $error_message !== '' ? sanitize_textarea_field(substr($error_message, 0, 4000)) : null,
                ],
                ['id' => $log_id],
                ['%s', '%s', '%d', '%s', '%s', '%s'],
                ['%d']
            );
        }

        // Cache O(1) last-run summary per hook (for instant overview rendering)
        $last_runs = get_option(self::OPTION_LAST_RUNS, []);
        if (!is_array($last_runs)) {
            $last_runs = [];
        }
        $last_runs[$hook] = [
            'log_id'            => $log_id,
            'task_id'           => $task_id,
            'status'            => $status,
            'trigger_source'    => $trigger_source,
            'duration_ms'       => $duration_ms,
            'summary'           => substr($summary, 0, 240),
            'error_message'     => substr($error_message, 0, 500),
            'completed_at'      => $completed_at,
            'completed_at_gmt'  => $completed_gmt,
            'timestamp'         => time(),
        ];
        update_option(self::OPTION_LAST_RUNS, $last_runs, false);

        // Record critical cron failures in tamper-evident WebCareActivityLogger
        if ($status === 'failed' && class_exists(WebCareActivityLogger::class)) {
            $task = CronRegistry::get_task($hook);
            $label = $task['title'] ?? $hook;
            WebCareActivityLogger::error(
                'cron_task_failed',
                'system',
                [
                    /* translators: 1: task title, 2: error message */
                    'description' => sprintf(__('Scheduled task "%1$s" failed: %2$s', 'webcare-pro-security'), $label, $error_message ?: 'Unknown error'),
                    'hook'        => $hook,
                    'trigger'     => $trigger_source,
                    'duration_ms' => $duration_ms,
                ]
            );
        }

        // Occasional automatic pruning (1 in 25 writes) to prevent unbounded growth
        if (wp_rand(1, 25) === 1) {
            self::prune_old_logs();
        }
    }

    /**
     * Retrieve O(1) cached last-run map keyed by hook name.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_last_runs_map(): array {
        $raw = get_option(self::OPTION_LAST_RUNS, []);
        return is_array($raw) ? $raw : [];
    }

    /**
     * Get 24-hour execution statistics from SQL table.
     *
     * @return array{runs_24h: int, success_24h: int, skipped_24h: int, failed_24h: int}
     */
    public static function get_24h_stats(): array {
        global $wpdb;
        self::ensure_table_exists();

        $table  = self::get_table_name();
        $cutoff = gmdate('Y-m-d H:i:s', time() - DAY_IN_SECONDS);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT status, COUNT(*) AS cnt FROM %i WHERE created_at_gmt >= %s GROUP BY status',
                $table,
                $cutoff
            ),
            ARRAY_A
        ) ?: [];

        $counts = [
            'runs_24h'    => 0,
            'success_24h' => 0,
            'skipped_24h' => 0,
            'failed_24h'  => 0,
        ];

        foreach ($rows as $row) {
            $cnt = (int) ($row['cnt'] ?? 0);
            $st  = (string) ($row['status'] ?? '');
            $counts['runs_24h'] += $cnt;
            if ($st === 'success') {
                $counts['success_24h'] += $cnt;
            } elseif ($st === 'skipped' || $st === 'disabled') {
                $counts['skipped_24h'] += $cnt;
            } elseif ($st === 'failed') {
                $counts['failed_24h'] += $cnt;
            }
        }

        return $counts;
    }

    /**
     * Query paginated execution logs with filters.
     *
     * @param array<string, mixed> $filters
     * @return array{items: array<int, array<string, mixed>>, total: int, page: int, per_page: int, total_pages: int}
     */
    public static function query_logs(array $filters = []): array {
        global $wpdb;
        self::ensure_table_exists();

        $table    = self::get_table_name();
        $hook     = sanitize_text_field((string) ($filters['hook'] ?? ''));
        $status   = sanitize_key((string) ($filters['status'] ?? ''));
        $trigger  = sanitize_key((string) ($filters['trigger'] ?? ''));
        $search   = sanitize_text_field((string) ($filters['search'] ?? ''));
        $days     = max(0, min(365, (int) ($filters['days'] ?? 30)));
        $page     = max(1, (int) ($filters['page'] ?? 1));
        $per_page = max(10, min(100, (int) ($filters['per_page'] ?? 25)));
        $offset   = ($page - 1) * $per_page;

        $hook_all    = ($hook === '' || $hook === 'all') ? 1 : 0;
        $status_all  = ($status === '' || $status === 'all') ? 1 : 0;
        $trigger_all = ($trigger === '' || $trigger === 'all') ? 1 : 0;
        $cutoff_gmt  = ($days > 0) ? gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS)) : '1970-01-01 00:00:00';
        $has_search  = ($search !== '') ? 1 : 0;
        $like_term   = ($search !== '') ? '%' . $wpdb->esc_like($search) . '%' : '%';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $total = (int) $wpdb->get_var(
            $wpdb->prepare(
                'SELECT COUNT(*) FROM %i
                 WHERE (%d = 1 OR hook_name = %s)
                   AND (%d = 1 OR status = %s)
                   AND (%d = 1 OR trigger_source = %s)
                   AND created_at_gmt >= %s
                   AND (%d = 0 OR hook_name LIKE %s OR summary LIKE %s OR error_message LIKE %s)',
                $table,
                $hook_all,
                $hook,
                $status_all,
                $status,
                $trigger_all,
                $trigger,
                $cutoff_gmt,
                $has_search,
                $like_term,
                $like_term,
                $like_term
            )
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT id, task_id, hook_name, trigger_source, status, started_at, completed_at, duration_ms, summary, metrics_json, error_message, actor_id, created_at_gmt
                 FROM %i
                 WHERE (%d = 1 OR hook_name = %s)
                   AND (%d = 1 OR status = %s)
                   AND (%d = 1 OR trigger_source = %s)
                   AND created_at_gmt >= %s
                   AND (%d = 0 OR hook_name LIKE %s OR summary LIKE %s OR error_message LIKE %s)
                 ORDER BY id DESC LIMIT %d OFFSET %d',
                $table,
                $hook_all,
                $hook,
                $status_all,
                $status,
                $trigger_all,
                $trigger,
                $cutoff_gmt,
                $has_search,
                $like_term,
                $like_term,
                $like_term,
                $per_page,
                $offset
            ),
            ARRAY_A
        ) ?: [];

        $tasks = CronRegistry::get_tasks();
        foreach ($rows as &$row) {
            $h = (string) ($row['hook_name'] ?? '');
            $row['id']          = (int) $row['id'];
            $row['duration_ms'] = (int) $row['duration_ms'];
            $row['actor_id']    = (int) $row['actor_id'];
            $row['task_title']  = $tasks[$h]['title'] ?? $h;
            $row['category']    = $tasks[$h]['category'] ?? 'system';
            $row['metrics']     = !empty($row['metrics_json']) ? (json_decode((string) $row['metrics_json'], true) ?: []) : [];
            unset($row['metrics_json']);

            if ($row['actor_id'] > 0) {
                $user = get_userdata($row['actor_id']);
                $row['actor_label'] = $user ? $user->user_login : "Admin #{$row['actor_id']}";
            } else {
                $row['actor_label'] = ($row['trigger_source'] === 'wp_cli') ? 'WP-CLI' : 'System (WP-Cron)';
            }
        }
        unset($row);

        return [
            'items'       => $rows,
            'total'       => $total,
            'page'        => $page,
            'per_page'    => $per_page,
            'total_pages' => max(1, (int) ceil($total / $per_page)),
        ];
    }

    /**
     * Prune expired logs per configured retention days and maximum row cap.
     *
     * @return int Rows deleted
     */
    public static function prune_old_logs(): int {
        global $wpdb;
        self::ensure_table_exists();

        $settings = SettingsManager::get_settings();
        $days = max(7, min(365, (int) ($settings['cron_log_retention_days'] ?? 30)));
        $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));
        $table = self::get_table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $deleted_age = (int) $wpdb->query(
            $wpdb->prepare('DELETE FROM %i WHERE created_at_gmt < %s', $table, $cutoff)
        );

        // Cap total stored rows so table remains compact on high-frequency sites
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $total = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i', $table));
        $deleted_cap = 0;
        if ($total > self::MAX_RETAINED_ROWS) {
            $overflow = $total - self::MAX_RETAINED_ROWS;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $deleted_cap = (int) $wpdb->query(
                $wpdb->prepare('DELETE FROM %i ORDER BY id ASC LIMIT %d', $table, $overflow)
            );
        }

        return $deleted_age + $deleted_cap;
    }

    /**
     * Clear all stored execution logs (or only for a specific hook).
     *
     * @param string $hook Optional hook filter
     * @return int Rows deleted
     */
    public static function clear_logs(string $hook = ''): int {
        global $wpdb;
        self::ensure_table_exists();
        $table = self::get_table_name();

        if ($hook !== '' && $hook !== 'all') {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $deleted = (int) $wpdb->query(
                $wpdb->prepare('DELETE FROM %i WHERE hook_name = %s', $table, $hook)
            );
            $last = self::get_last_runs_map();
            unset($last[$hook]);
            update_option(self::OPTION_LAST_RUNS, $last, false);
            return $deleted;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $deleted = (int) $wpdb->query($wpdb->prepare('DELETE FROM %i', $table));
        update_option(self::OPTION_LAST_RUNS, [], false);
        return $deleted;
    }
}
