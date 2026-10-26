<?php
namespace WcpScanner\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WafFileLogger
 *
 * High-performance, filesystem-partitioned WAF incident logging engine.
 * Writes zero-SQL, append-only daily JSON files under /uploads/wcp-security-scanner/waf-logs/
 * to eliminate MySQL lockups and database connection exhaustion during brute-force attacks.
 */
class WafFileLogger {

    const SUBDIR = 'wcp-security-scanner/waf-logs';
    const RETENTION_OPTION = 'wcpscan_waf_log_retention_days';
    const DEFAULT_RETENTION_DAYS = 60;
    const CRON_HOOK = 'wcpscan_waf_log_retention_prune';

    /**
     * Bootstrap WAF File Logger hooks and daily cron maintenance
     */
    public static function init() {
        add_action(self::CRON_HOOK, [__CLASS__, 'prune_expired_logs']);

        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
        }
    }

    /**
     * Get the absolute path to the WAF logs storage directory.
     *
     * @return string
     */
    public static function get_storage_dir(): string {
        $upload_dir = wp_upload_dir();
        $base_dir   = $upload_dir['basedir'];
        return rtrim($base_dir, '/\\') . '/' . self::SUBDIR;
    }

    /**
     * Ensure the storage directory exists and is secured against direct HTTP access.
     *
     * @return bool
     */
    public static function ensure_directory_secured(): bool {
        $dir = self::get_storage_dir();

        if (!is_dir($dir)) {
            // phpcs:ignore WordPress.WP.AlternativeFileSystem.mkdir_mkdir
            wp_mkdir_p($dir);
        }

        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }

        // Hardening 1: Apache/LiteSpeed .htaccess deny rules
        $htaccess_file = $dir . '/.htaccess';
        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# WCP Security Scanner - Protect WAF Forensic Logs\n"
                . "<IfModule mod_authz_core.c>\n"
                . "    Require all denied\n"
                . "</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n"
                . "    Deny from all\n"
                . "</IfModule>\n";
            // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_put_contents_file_put_contents
            @file_put_contents($htaccess_file, $htaccess_content);
        }

        // Hardening 2: Nginx / IIS silence index file
        $index_file = $dir . '/index.php';
        if (!file_exists($index_file)) {
            // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_put_contents_file_put_contents
            @file_put_contents($index_file, "<?php\n// Silence is golden.\n");
        }

        return true;
    }

    /**
     * Format a timestamp into the daily log filename.
     * Example: october-27-2026-waf-logs.json
     *
     * @param int|null $timestamp Optional UNIX timestamp. Defaults to current time.
     * @return string
     */
    public static function get_daily_filename(?int $timestamp = null): string {
        $ts = $timestamp ?? time();
        // Lowercase formatted date: e.g. "october-27-2026-waf-logs.json"
        return strtolower(gmdate('F-j-Y', $ts)) . '-waf-logs.json';
    }

    /**
     * Parse date from a filename like "october-27-2026-waf-logs.json".
     *
     * @param string $filename
     * @return string|null Returns ISO date YYYY-MM-DD or null if invalid format.
     */
    public static function parse_date_from_filename(string $filename): ?string {
        if (!preg_match('/^([a-z]+)-(\d{1,2})-(\d{4})-waf-logs\.json$/i', $filename, $matches)) {
            return null;
        }

        $month_str = ucfirst(strtolower($matches[1]));
        $day       = (int) $matches[2];
        $year      = (int) $matches[3];

        $ts = strtotime("{$month_str} {$day}, {$year}");
        if ($ts === false) {
            return null;
        }

        return gmdate('Y-m-d', $ts);
    }

    /**
     * Log a firewall incident into today's JSON log file.
     *
     * @param array  $rule
     * @param string $action
     * @param string|null $incident_id
     * @return string|null Incident ID or null if skipped
     */
    public static function log_incident(array $rule, string $action, ?string $incident_id = null): ?string {
        $ip = class_exists('\\WcpScanner\\Firewall\\FirewallEngine')
            ? \WcpScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

        // Red Team Synthetic Attack Drill probe suppression
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['wcp_drill_token']) ? sanitize_text_field(wp_unslash($_GET['wcp_drill_token'])) : (isset($_SERVER['HTTP_X_WCP_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WCP_DRILL_TOKEN'])) : '');
        if (!empty($drill_token)) {
            return null;
        }

        // Server Origin IP Safety: Never log server's own outbound IP
        $server_ip = class_exists('\\WcpScanner\\System\\ServerInfo')
            ? \WcpScanner\System\ServerInfo::get_server_ip()
            : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '');
        if (!empty($server_ip) && $ip === $server_ip) {
            return null;
        }

        $category = sanitize_key($rule['category'] ?? 'general_defense');

        // Zero-SQL Deduplication Cache: prevent logging identical IP + Category within 60 seconds
        $cache_key = 'wcp_dedup_' . md5($ip . '_' . $category);
        if (get_transient($cache_key)) {
            return $incident_id;
        }
        set_transient($cache_key, 1, 60);

        if (empty($incident_id)) {
            $incident_id = 'WCP-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
        }

        // Determine HTTP Status Code
        $status_code = 403;
        if ($action === 'detected') {
            $status_code = 200;
        } elseif (isset($rule['category']) && $rule['category'] === '404 Scanner Rate Limit') {
            $status_code = 404;
        } elseif (isset($rule['category']) && (stripos($rule['category'], 'method') !== false || stripos($rule['description'] ?? '', 'method') !== false)) {
            $status_code = 405;
        }

        $raw_uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $uri        = substr($raw_uri, 0, 500);
        $raw_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $method     = substr($raw_method, 0, 10);
        $raw_ua     = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $user_agent = substr($raw_ua, 0, 300);
        $raw_ref    = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '';
        $referer    = substr($raw_ref, 0, 500);

        // Rich User Identity Detection
        $user_id          = 0;
        $username         = '';
        $user_role        = '';
        $is_authenticated = false;

        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            $current_user     = wp_get_current_user();
            $user_id          = (int) $current_user->ID;
            $username         = sanitize_user($current_user->user_login);
            $roles            = (array) $current_user->roles;
            $user_role        = !empty($roles) ? sanitize_key(reset($roles)) : 'subscriber';
            $is_authenticated = true;
        } else {
            // Check for unauthenticated login attempt usernames
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            if (!empty($_POST['log'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                $username = sanitize_user(wp_unslash($_POST['log']));
            }
        }

        $payload = substr((string) ($rule['payload'] ?? $rule['match_value'] ?? ''), 0, 255);

        // Sanitize sensitive credentials from payload
        $payload = preg_replace('/(pwd|password|pass|secret|token)=([^&]+)/i', '$1=********', $payload);

        $incident_record = [
            'id'               => 'wcp_' . substr(md5(uniqid((string) wp_rand(), true)), 0, 12),
            'incident_id'      => sanitize_text_field($incident_id),
            'timestamp'        => time(),
            'created_at'       => current_time('mysql'),
            'created_at_gmt'   => gmdate('Y-m-d H:i:s'),
            'ip_address'       => sanitize_text_field($ip),
            'request_uri'      => $uri,
            'request_method'   => $method,
            'http_status_code' => (int) $status_code,
            'http_referer'     => !empty($referer) ? $referer : null,
            'rule_category'    => $category,
            'rule_description' => sanitize_text_field($rule['description'] ?? $rule['name'] ?? 'Threat payload intercepted by WCP firewall.'),
            'payload_sample'   => $payload,
            'user_agent'       => $user_agent,
            'action_taken'     => sanitize_key($action),
            'user_id'          => $user_id,
            'username'         => $username,
            'user_role'        => $user_role,
            'is_authenticated' => $is_authenticated,
            'hostname'         => isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '',
        ];

        self::append_record_to_file($incident_record);

        return $incident_id;
    }

    /**
     * Atomically append a record to today's daily JSON file.
     *
     * @param array $record
     * @return bool
     */
    private static function append_record_to_file(array $record): bool {
        self::ensure_directory_secured();
        $dir = self::get_storage_dir();

        $filename = self::get_daily_filename();
        $filepath = $dir . '/' . $filename;

        $json_line = wp_json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json_line === false) {
            return false;
        }

        // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_put_contents_file_put_contents
        $bytes = @file_put_contents($filepath, $json_line . "\n", FILE_APPEND | LOCK_EX);
        return $bytes !== false;
    }

    /**
     * Get a list of all available daily log files with metadata.
     *
     * @return array
     */
    public static function get_available_files(): array {
        $dir = self::get_storage_dir();
        if (!is_dir($dir)) {
            return [];
        }

        $files   = scandir($dir);
        $results = [];

        foreach ($files as $file) {
            if ($file === '.' || $file === '..' || !preg_match('/-waf-logs\.json$/', $file)) {
                continue;
            }

            $filepath = $dir . '/' . $file;
            if (!is_file($filepath)) {
                continue;
            }

            $date_str = self::parse_date_from_filename($file);
            $size     = filesize($filepath) ?: 0;
            $mtime    = filemtime($filepath) ?: time();

            $results[] = [
                'filename'    => $file,
                'date'        => $date_str ?? gmdate('Y-m-d', $mtime),
                'size_bytes'  => $size,
                'size_human'  => size_format($size),
                'modified_at' => gmdate('Y-m-d H:i:s', $mtime),
            ];
        }

        // Sort descending by date (newest days first)
        usort($results, function ($a, $b) {
            return strcmp($b['date'], $a['date']);
        });

        return $results;
    }

    /**
     * Query WAF logs across daily files with time-window filtering, text search, sorting, and pagination.
     *
     * @param array $filters [
     *    'range'       => 'today'|'daily'|'7days'|'30days'|'6months'|'all',
     *    'date'        => 'YYYY-MM-DD' or filename (for 'daily' range),
     *    'search'      => string,
     *    'category'    => string,
     *    'action'      => string,
     *    'method'      => string,
     *    'ip'          => string,
     *    'status_code' => int|string,
     *    'sort_by'     => 'created_at'|'ip_address'|'username'|'rule_category'|'action_taken'|'http_status_code'|'request_method',
     *    'sort_order'  => 'asc'|'desc'
     * ]
     * @param int   $limit
     * @param int   $offset
     * @return array
     */
    public static function query_logs(array $filters = [], int $limit = 50, int $offset = 0): array {
        $files_to_read = self::resolve_target_files($filters);
        if (empty($files_to_read)) {
            return [
                'logs'            => [],
                'total'           => 0,
                'page'            => 1,
                'total_pages'     => 1,
                'limit'           => $limit,
                'offset'          => $offset,
                'available_files' => self::get_available_files(),
            ];
        }

        $all_matched = [];

        foreach ($files_to_read as $filepath) {
            if (!file_exists($filepath) || !is_readable($filepath)) {
                continue;
            }

            $handle = @fopen($filepath, 'r');
            if (!$handle) {
                continue;
            }

            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if ($line === '' || $line[0] !== '{') {
                    continue;
                }

                $record = json_decode($line, true);
                if (!is_array($record)) {
                    continue;
                }

                // Apply in-memory stream filtering
                if (!self::record_matches_filters($record, $filters)) {
                    continue;
                }

                $all_matched[] = $record;
            }

            fclose($handle);
        }

        $total = count($all_matched);

        // Sorting
        $sort_by    = sanitize_key($filters['sort_by'] ?? 'created_at');
        $sort_order = strtolower(sanitize_key($filters['sort_order'] ?? 'desc')) === 'asc' ? 'asc' : 'desc';

        usort($all_matched, function ($a, $b) use ($sort_by, $sort_order) {
            $val_a = $a[$sort_by] ?? '';
            $val_b = $b[$sort_by] ?? '';

            if ($sort_by === 'created_at' || $sort_by === 'timestamp') {
                $ts_a = isset($a['timestamp']) ? (int) $a['timestamp'] : strtotime((string) $val_a);
                $ts_b = isset($b['timestamp']) ? (int) $b['timestamp'] : strtotime((string) $val_b);
                $cmp  = ($ts_a <=> $ts_b);
            } elseif ($sort_by === 'http_status_code') {
                $cmp = ((int) $val_a <=> (int) $val_b);
            } elseif ($sort_by === 'ip_address') {
                // Natural/IP sorting
                $cmp = ip2long($val_a) && ip2long($val_b)
                    ? (ip2long($val_a) <=> ip2long($val_b))
                    : strnatcasecmp((string) $val_a, (string) $val_b);
            } else {
                $cmp = strcasecmp((string) $val_a, (string) $val_b);
            }

            return $sort_order === 'asc' ? $cmp : -$cmp;
        });

        // Pagination
        $limit       = max(1, min(500, $limit));
        $offset      = max(0, $offset);
        $sliced_logs = array_slice($all_matched, $offset, $limit);
        $total_pages = max(1, (int) ceil($total / $limit));
        $page        = (int) floor($offset / $limit) + 1;

        return [
            'logs'            => $sliced_logs,
            'total'           => $total,
            'page'            => $page,
            'total_pages'     => $total_pages,
            'limit'           => $limit,
            'offset'          => $offset,
            'available_files' => self::get_available_files(),
        ];
    }

    /**
     * Check if a log record satisfies the search and facet filters.
     *
     * @param array $record
     * @param array $filters
     * @return bool
     */
    private static function record_matches_filters(array $record, array $filters): bool {
        // Keyword Search
        if (!empty($filters['search'])) {
            $needle = strtolower(trim($filters['search']));
            $haystack = strtolower(
                ($record['incident_id'] ?? '') . ' ' .
                ($record['ip_address'] ?? '') . ' ' .
                ($record['request_uri'] ?? '') . ' ' .
                ($record['rule_description'] ?? '') . ' ' .
                ($record['payload_sample'] ?? '') . ' ' .
                ($record['user_agent'] ?? '') . ' ' .
                ($record['username'] ?? '') . ' ' .
                ($record['http_referer'] ?? '')
            );
            if (strpos($haystack, $needle) === false) {
                return false;
            }
        }

        // Status code filter
        if (!empty($filters['status_code']) && $filters['status_code'] !== 'all') {
            if ((int) ($record['http_status_code'] ?? 0) !== (int) $filters['status_code']) {
                return false;
            }
        }

        // Category filter
        if (!empty($filters['category']) && $filters['category'] !== 'all') {
            $cat = sanitize_key($filters['category']);
            if (sanitize_key($record['rule_category'] ?? '') !== $cat) {
                return false;
            }
        }

        // Action filter (blocked vs detected)
        if (!empty($filters['action']) && $filters['action'] !== 'all') {
            if (($record['action_taken'] ?? '') !== $filters['action']) {
                return false;
            }
        }

        // Method filter
        if (!empty($filters['method']) && $filters['method'] !== 'all') {
            if (strcasecmp((string) ($record['request_method'] ?? ''), (string) $filters['method']) !== 0) {
                return false;
            }
        }

        // IP filter
        if (!empty($filters['ip'])) {
            if (stripos((string) ($record['ip_address'] ?? ''), trim($filters['ip'])) === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Resolve target filepaths based on range and date filter.
     *
     * @param array $filters
     * @return array
     */
    private static function resolve_target_files(array $filters): array {
        $dir   = self::get_storage_dir();
        $range = $filters['range'] ?? 'today';

        if ($range === 'today' || $range === 'recent') {
            $today_file = $dir . '/' . self::get_daily_filename();
            return file_exists($today_file) ? [$today_file] : [];
        }

        if ($range === 'daily') {
            $date_input = trim($filters['date'] ?? '');
            if (!empty($date_input)) {
                // Check if user passed full filename or ISO date
                if (preg_match('/-waf-logs\.json$/', $date_input)) {
                    $target = $dir . '/' . basename($date_input);
                    return file_exists($target) ? [$target] : [];
                }
                $ts = strtotime($date_input);
                if ($ts !== false) {
                    $target = $dir . '/' . self::get_daily_filename($ts);
                    return file_exists($target) ? [$target] : [];
                }
            }
            // Fallback to today if no date provided
            $today_file = $dir . '/' . self::get_daily_filename();
            return file_exists($today_file) ? [$today_file] : [];
        }

        // Multi-day ranges
        $days_cutoff = 0;
        if ($range === '7days') {
            $days_cutoff = 7;
        } elseif ($range === '30days' || $range === '1month') {
            $days_cutoff = 30;
        } elseif ($range === '6months' || $range === '180days') {
            $days_cutoff = 180;
        }

        $available = self::get_available_files();
        $matched   = [];
        $cutoff_ts = $days_cutoff > 0 ? (time() - ($days_cutoff * 86400)) : 0;

        foreach ($available as $finfo) {
            $file_ts = strtotime($finfo['date']);
            if ($days_cutoff === 0 || ($file_ts !== false && $file_ts >= $cutoff_ts)) {
                $matched[] = $dir . '/' . $finfo['filename'];
            }
        }

        return $matched;
    }

    /**
     * Compute aggregate metrics and statistics from daily JSON files.
     *
     * @param string $range 'today'|'7days'|'30days'|'6months'|'all'
     * @return array
     */
    public static function get_log_stats(string $range = 'today'): array {
        $files = self::resolve_target_files(['range' => $range]);

        $total_intercepted = 0;
        $blocked_count     = 0;
        $detected_count    = 0;
        $unique_ips        = [];
        $categories        = [];
        $top_ips           = [];
        $targets           = [];
        $methods           = [];
        $hourly_buckets    = [];

        $one_day_ago = time() - 86400;

        foreach ($files as $filepath) {
            if (!file_exists($filepath) || !is_readable($filepath)) {
                continue;
            }

            $handle = @fopen($filepath, 'r');
            if (!$handle) {
                continue;
            }

            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if ($line === '' || $line[0] !== '{') {
                    continue;
                }

                $rec = json_decode($line, true);
                if (!is_array($rec)) {
                    continue;
                }

                $total_intercepted++;
                $action = $rec['action_taken'] ?? 'blocked';
                $ip     = $rec['ip_address'] ?? 'unknown';
                $cat    = $rec['rule_category'] ?? 'general';
                $uri    = $rec['request_uri'] ?? '/';
                $method = $rec['request_method'] ?? 'GET';
                $ts     = (int) ($rec['timestamp'] ?? (isset($rec['created_at']) ? strtotime($rec['created_at']) : 0));

                if ($action === 'blocked') {
                    $blocked_count++;
                } else {
                    $detected_count++;
                }

                $unique_ips[$ip] = true;

                $categories[$cat]  = ($categories[$cat] ?? 0) + 1;
                $targets[$uri]     = ($targets[$uri] ?? 0) + 1;
                $methods[$method]  = ($methods[$method] ?? 0) + 1;

                if (!isset($top_ips[$ip])) {
                    $top_ips[$ip] = [
                        'count'          => 0,
                        'last_seen'      => $rec['created_at'] ?? '',
                        'primary_reason' => $cat,
                    ];
                }
                $top_ips[$ip]['count']++;

                if ($ts >= $one_day_ago) {
                    $slot = gmdate('Y-m-d H:00', $ts);
                    $hourly_buckets[$slot] = ($hourly_buckets[$slot] ?? 0) + 1;
                }
            }

            fclose($handle);
        }

        // Sort Top Categories
        arsort($categories);
        $top_categories = [];
        foreach (array_slice($categories, 0, 8, true) as $k => $v) {
            $top_categories[] = ['rule_category' => $k, 'count' => $v];
        }

        // Sort Top IPs
        uasort($top_ips, function ($a, $b) {
            return $b['count'] <=> $a['count'];
        });
        $formatted_top_ips = [];
        foreach (array_slice($top_ips, 0, 10, true) as $ip_str => $data) {
            $formatted_top_ips[] = [
                'ip_address'     => $ip_str,
                'count'          => $data['count'],
                'last_seen'      => $data['last_seen'],
                'primary_reason' => $data['primary_reason'],
            ];
        }

        // Sort Top Targets
        arsort($targets);
        $top_targets = [];
        foreach (array_slice($targets, 0, 8, true) as $k => $v) {
            $top_targets[] = ['request_uri' => $k, 'count' => $v];
        }

        // Sort Methods
        arsort($methods);
        $methods_breakdown = [];
        foreach ($methods as $k => $v) {
            $methods_breakdown[] = ['request_method' => $k, 'count' => $v];
        }

        // Format Hourly Trend
        ksort($hourly_buckets);
        $hourly_trend = [];
        foreach ($hourly_buckets as $slot => $count) {
            $hourly_trend[] = ['hour_slot' => $slot, 'count' => $count];
        }

        return [
            'total_intercepted' => $total_intercepted,
            'blocked_24h'       => $blocked_count,
            'detected_learning' => $detected_count,
            'unique_attack_ips' => count($unique_ips),
            'top_categories'    => $top_categories,
            'top_ips'           => $formatted_top_ips,
            'top_targets'       => $top_targets,
            'methods_breakdown' => $methods_breakdown,
            'hourly_trend'      => $hourly_trend,
        ];
    }

    /**
     * Get the configured log retention period in days.
     *
     * @return int
     */
    public static function get_retention_days(): int {
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        if (isset($settings['waf_log_retention_days'])) {
            return (int) $settings['waf_log_retention_days'];
        }
        return (int) get_option(self::RETENTION_OPTION, self::DEFAULT_RETENTION_DAYS);
    }

    /**
     * Set the log retention period in days.
     *
     * @param int $days
     * @return bool
     */
    public static function set_retention_days(int $days): bool {
        $valid_options = [7, 14, 30, 60, 90, 180, 365, 0]; // 0 = keep forever
        if (!in_array($days, $valid_options, true)) {
            $days = self::DEFAULT_RETENTION_DAYS;
        }
        $updated = update_option(self::RETENTION_OPTION, $days);
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $settings['waf_log_retention_days'] = $days;
        \WcpScanner\System\SettingsManager::save_settings($settings);
        return $updated || true;
    }

    /**
     * Prune expired daily WAF JSON files older than retention policy.
     * Can be invoked via WP-Cron or manually by an administrator.
     *
     * @return int Number of pruned files.
     */
    public static function prune_expired_logs(): int {
        $retention_days = self::get_retention_days();
        if ($retention_days <= 0) {
            return 0; // Keep forever
        }

        $dir = self::get_storage_dir();
        if (!is_dir($dir)) {
            return 0;
        }

        $cutoff_time = time() - ($retention_days * 86400);
        $files       = scandir($dir);
        $pruned      = 0;

        foreach ($files as $file) {
            if (!preg_match('/-waf-logs\.json$/', $file)) {
                continue;
            }

            $date_str = self::parse_date_from_filename($file);
            $filepath = $dir . '/' . $file;

            if ($date_str) {
                $file_time = strtotime($date_str);
            } else {
                $file_time = filemtime($filepath);
            }

            if ($file_time !== false && $file_time < $cutoff_time) {
                if (function_exists('wp_delete_file')) {
                    wp_delete_file($filepath);
                } else {
                    // phpcs:ignore WordPress.WP.AlternativeFileSystem.unlink_unlink
                    @unlink($filepath);
                }
                $pruned++;
            }
        }

        return $pruned;
    }

    /**
     * Delete a single incident from log files by its ID or incident_id.
     *
     * @param string|int $id
     * @return bool
     */
    public static function delete_log($id): bool {
        $id_str = trim((string) $id);
        if ($id_str === '') {
            return false;
        }

        $dir = self::get_storage_dir();
        if (!is_dir($dir)) {
            return false;
        }

        $files = scandir($dir);
        $deleted = false;

        foreach ($files as $file) {
            if (!preg_match('/-waf-logs\.json$/', $file)) {
                continue;
            }

            $filepath = $dir . '/' . $file;
            $lines = @file($filepath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!is_array($lines)) {
                continue;
            }

            $remaining = [];
            $modified = false;

            foreach ($lines as $line) {
                $rec = json_decode($line, true);
                if (is_array($rec)) {
                    $match_id = (string) ($rec['id'] ?? '');
                    $match_inc = (string) ($rec['incident_id'] ?? '');
                    if ($match_id === $id_str || $match_inc === $id_str) {
                        $modified = true;
                        $deleted = true;
                        continue;
                    }
                }
                $remaining[] = $line;
            }

            if ($modified) {
                // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_put_contents_file_put_contents
                @file_put_contents($filepath, implode("\n", $remaining) . (empty($remaining) ? '' : "\n"), LOCK_EX);
            }
        }

        return $deleted;
    }

    /**
     * Clear all filesystem WAF logs (removes all daily JSON files).
     *
     * @return bool
     */
    public static function clear_all_logs(): bool {
        $dir = self::get_storage_dir();
        if (!is_dir($dir)) {
            return true;
        }

        $files = scandir($dir);
        foreach ($files as $file) {
            if (preg_match('/-waf-logs\.json$/', $file)) {
                $filepath = $dir . '/' . $file;
                if (function_exists('wp_delete_file')) {
                    wp_delete_file($filepath);
                } else {
                    // phpcs:ignore WordPress.WP.AlternativeFileSystem.unlink_unlink
                    @unlink($filepath);
                }
            }
        }

        return true;
    }
}
