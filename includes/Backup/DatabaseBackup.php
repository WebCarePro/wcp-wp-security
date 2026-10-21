<?php
namespace WcpScanner\Backup;

if (!defined('ABSPATH')) {
    exit;
}

class DatabaseBackup {

    private $backup_dir;

    public function __construct() {
        $uploads = wp_upload_dir();
        $base = untrailingslashit($uploads['basedir']);
        $this->backup_dir = $base . '/wcp-security-scanner/backups';
        $this->ensure_directory();
    }

    /**
     * Get the active backup directory.
     *
     * @return string
     */
    public function get_backup_dir(): string {
        return $this->backup_dir;
    }

    /**
     * Ensure the backup directory exists and is strictly blocked from public web access.
     */
    private function ensure_directory() {
        if (!is_dir($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
            @chmod($this->backup_dir, 0775);
        }

        if (is_dir($this->backup_dir) && !is_writable($this->backup_dir)) {
            @chmod($this->backup_dir, 0775);
        }

        // Lock with .htaccess
        $htaccess = $this->backup_dir . '/.htaccess';
        if (!file_exists($htaccess) && is_writable($this->backup_dir)) {
            $rules = "# Block all public access to database backups\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
            @file_put_contents($htaccess, $rules);
        }

        // Lock with index.php
        $index = $this->backup_dir . '/index.php';
        if (!file_exists($index) && is_writable($this->backup_dir)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\nexit;\n");
        }
    }

    /**
     * Compute system-wide RAM metrics (Total, Free, Used RAM, Usage %).
     *
     * @return array
     */
    public static function get_system_ram_metrics(): array {
        $res = [
            'total_ram_mb'     => null,
            'free_ram_mb'      => null,
            'used_ram_mb'      => null,
            'ram_used_percent' => null,
            'source'           => 'php_fallback',
        ];

        // 1. Linux /proc/meminfo
        if (is_readable('/proc/meminfo')) {
            $meminfo = @file_get_contents('/proc/meminfo');
            if ($meminfo) {
                preg_match('/MemTotal:\s+(\d+)\s+kB/i', $meminfo, $tot_m);
                preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $meminfo, $avail_m);
                if (empty($avail_m)) {
                    preg_match('/MemFree:\s+(\d+)\s+kB/i', $meminfo, $avail_m);
                }
                if (!empty($tot_m[1])) {
                    $total_kb = (float) $tot_m[1];
                    $avail_kb = !empty($avail_m[1]) ? (float) $avail_m[1] : 0;
                    $used_kb = max(0, $total_kb - $avail_kb);
                    $res['total_ram_mb']     = round($total_kb / 1024, 1);
                    $res['free_ram_mb']      = round($avail_kb / 1024, 1);
                    $res['used_mb']          = round($used_kb / 1024, 1);
                    $res['used_ram_mb']      = round($used_kb / 1024, 1);
                    $res['ram_used_percent'] = round(($used_kb / $total_kb) * 100, 1);
                    $res['source']           = '/proc/meminfo';
                    return $res;
                }
            }
        }

        // 2. Windows PowerShell / CIM fallback
        if (stripos(PHP_OS, 'WIN') === 0 && function_exists('shell_exec')) {
            $ps = @shell_exec('powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | ForEach-Object { $_.TotalVisibleMemorySize, $_.FreePhysicalMemory }" 2>nul');
            if ($ps) {
                $lines = array_values(array_filter(array_map('trim', explode("\n", $ps))));
                if (count($lines) >= 2 && is_numeric($lines[0]) && is_numeric($lines[1])) {
                    $total_kb = (float) $lines[0];
                    $free_kb  = (float) $lines[1];
                    $used_kb  = max(0, $total_kb - $free_kb);
                    $res['total_ram_mb']     = round($total_kb / 1024, 1);
                    $res['free_ram_mb']      = round($free_kb / 1024, 1);
                    $res['used_ram_mb']      = round($used_kb / 1024, 1);
                    $res['ram_used_percent'] = round(($used_kb / $total_kb) * 100, 1);
                    $res['source']           = 'win32_cim';
                    return $res;
                }
            }
        }

        // 3. Fallback based on PHP memory limit
        $limit_raw = ini_get('memory_limit') ?: '256M';
        $bytes = 256 * 1024 * 1024;
        if (preg_match('/^(\d+)(.)/i', $limit_raw, $m)) {
            $val = (int) $m[1];
            $u = strtoupper($m[2]);
            if ($u === 'G') $bytes = $val * 1024 * 1024 * 1024;
            elseif ($u === 'M') $bytes = $val * 1024 * 1024;
            elseif ($u === 'K') $bytes = $val * 1024;
        }
        $php_used = memory_get_usage(true);
        $res['total_ram_mb']     = round($bytes / (1024 * 1024), 1);
        $res['used_ram_mb']      = round($php_used / (1024 * 1024), 1);
        $res['free_ram_mb']      = max(0, round(($bytes - $php_used) / (1024 * 1024), 1));
        $res['ram_used_percent'] = $bytes > 0 ? round(($php_used / $bytes) * 100, 1) : 0;
        return $res;
    }

    /**
     * Compute CPU utilization metrics.
     *
     * @param float|null $step_start
     * @param array|null $step_ru_start
     * @return array
     */
    public static function get_cpu_metrics($step_start = null, $step_ru_start = null): array {
        $cpu_percent = null;
        if ($step_start && $step_ru_start && function_exists('getrusage')) {
            $wall_time = max(0.001, microtime(true) - $step_start);
            $ru_end = @getrusage();
            if (is_array($ru_end) && is_array($step_ru_start)) {
                $user_start = ($step_ru_start['ru_utime.tv_sec'] ?? 0) + (($step_ru_start['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_start  = ($step_ru_start['ru_stime.tv_sec'] ?? 0) + (($step_ru_start['ru_stime.tv_usec'] ?? 0) / 1000000);
                $user_end   = ($ru_end['ru_utime.tv_sec'] ?? 0) + (($ru_end['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_end    = ($ru_end['ru_stime.tv_sec'] ?? 0) + (($ru_end['ru_stime.tv_usec'] ?? 0) / 1000000);
                $cpu_time_used = max(0, ($user_end + $sys_end) - ($user_start + $sys_start));
                $cpu_percent = min(100.0, round(($cpu_time_used / $wall_time) * 100, 1));
            }
        }

        $load_avg = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $load_avg = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2),
                ];
            }
        }

        return [
            'process_cpu_percent' => $cpu_percent,
            'load_average'        => $load_avg,
        ];
    }

    /**
     * Inspect database size, table count, estimated rows, and disk safety before backup.
     *
     * @return array
     */
    public function get_preflight_info(): array {
        global $wpdb;

        $db_name = DB_NAME;
        $tables_raw = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT TABLE_NAME, ENGINE, TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH, (DATA_LENGTH + INDEX_LENGTH) AS TOTAL_BYTES 
                 FROM information_schema.TABLES 
                 WHERE TABLE_SCHEMA = %s 
                 ORDER BY TOTAL_BYTES DESC",
                $db_name
            ),
            ARRAY_A
        );

        $total_size_bytes = 0;
        $total_rows = 0;
        $tables_breakdown = [];

        if (is_array($tables_raw)) {
            foreach ($tables_raw as $t) {
                $size = (int) ($t['TOTAL_BYTES'] ?? 0);
                $rows = (int) ($t['TABLE_ROWS'] ?? 0);
                $total_size_bytes += $size;
                $total_rows += $rows;

                $tables_breakdown[] = [
                    'name'          => $t['TABLE_NAME'],
                    'engine'        => $t['ENGINE'] ?? 'InnoDB',
                    'rows'          => $rows,
                    'size_bytes'    => $size,
                    'size_mb'       => round($size / (1024 * 1024), 2),
                    'data_size_mb'  => round(((int) ($t['DATA_LENGTH'] ?? 0)) / (1024 * 1024), 2),
                    'index_size_mb' => round(((int) ($t['INDEX_LENGTH'] ?? 0)) / (1024 * 1024), 2),
                ];
            }
        }

        $total_size_mb = round($total_size_bytes / (1024 * 1024), 2);
        $total_size_gb = round($total_size_bytes / (1024 * 1024 * 1024), 3);
        $total_tables = count($tables_breakdown);

        // Scale tier
        $scale_tier = 'normal';
        if ($total_size_bytes >= 5 * 1024 * 1024 * 1024) {
            $scale_tier = 'massive'; // > 5GB
        } elseif ($total_size_bytes >= 1024 * 1024 * 1024) {
            $scale_tier = 'large';   // 1GB - 5GB
        } elseif ($total_size_bytes >= 500 * 1024 * 1024) {
            $scale_tier = 'moderate'; // 500MB - 1GB
        }

        // Free disk space check
        $free_disk_bytes = @disk_free_space($this->backup_dir);
        $free_disk_mb = $free_disk_bytes !== false ? round($free_disk_bytes / (1024 * 1024), 1) : null;
        $free_disk_gb = $free_disk_bytes !== false ? round($free_disk_bytes / (1024 * 1024 * 1024), 2) : null;

        $disk_safety = 'safe';
        $disk_safety_message = 'Vault storage capacity is optimal for backup generation.';

        if ($free_disk_bytes !== false) {
            $required_est_bytes = max(50 * 1024 * 1024, $total_size_bytes * 0.4); // compressed est ~40% of uncompressed
            if ($free_disk_bytes < $total_size_bytes) {
                $disk_safety = 'critical';
                $disk_safety_message = sprintf(
                    'Critical: Vault partition free disk space (%s GB) is smaller than total database size (%s GB). Please clear disk space before starting.',
                    $free_disk_gb,
                    $total_size_gb
                );
            } elseif ($free_disk_bytes < ($total_size_bytes * 2)) {
                $disk_safety = 'warning';
                $disk_safety_message = sprintf(
                    'Warning: Free disk space (%s GB) is tight. Ensure at least 2x database size (%s GB) is free for safe temporary spooling.',
                    $free_disk_gb,
                    $total_size_gb * 2
                );
            }
        }

        // Recommended server pacing based on database size
        $recommended_throttle_ms = 40;
        if ($scale_tier === 'massive') {
            $recommended_throttle_ms = 60; // 60ms pause per chunk to protect server CPU
        } elseif ($scale_tier === 'large') {
            $recommended_throttle_ms = 45;
        }

        $system_ram = self::get_system_ram_metrics();
        $cpu_metrics = self::get_cpu_metrics();

        $php_mem = memory_get_usage(true);
        $php_peak = memory_get_peak_usage(true);
        $php_limit = ini_get('memory_limit') ?: '256M';

        return [
            'database' => [
                'name'               => DB_NAME,
                'host'               => DB_HOST,
                'mysql_version'      => $wpdb->db_version(),
                'charset'            => $wpdb->charset ?: 'utf8mb4',
                'collate'            => $wpdb->collate ?: 'utf8mb4_unicode_ci',
                'total_size_bytes'   => $total_size_bytes,
                'total_size_mb'      => $total_size_mb,
                'total_size_gb'      => $total_size_gb,
                'total_tables'       => $total_tables,
                'total_rows'         => $total_rows,
                'scale_tier'         => $scale_tier,
                'is_large'           => $scale_tier === 'large' || $scale_tier === 'massive',
                'is_massive'         => $scale_tier === 'massive',
                'top_tables'         => array_slice($tables_breakdown, 0, 15),
                'all_tables_count'   => $total_tables,
            ],
            'storage' => [
                'backup_dir'          => $this->backup_dir,
                'is_writable'         => is_writable($this->backup_dir),
                'free_disk_bytes'     => $free_disk_bytes,
                'free_disk_mb'        => $free_disk_mb,
                'free_disk_gb'        => $free_disk_gb,
                'disk_safety'         => $disk_safety,
                'disk_safety_message' => $disk_safety_message,
            ],
            'server_environment' => [
                'php_version'             => PHP_VERSION,
                'php_sapi'                => php_sapi_name(),
                'php_memory_limit'        => $php_limit,
                'php_memory_usage_mb'     => round($php_mem / (1024 * 1024), 2),
                'php_peak_memory_mb'      => round($php_peak / (1024 * 1024), 2),
                'max_execution_time'      => (int) ini_get('max_execution_time'),
                'gzip_compression'        => function_exists('gzopen'),
                'system_ram'              => $system_ram,
                'cpu_load'                => $cpu_metrics['load_average'],
                'server_time'             => current_time('mysql'),
                'recommended_throttle_ms' => $recommended_throttle_ms,
            ],
        ];
    }

    /**
     * Start a progressive, chunked database backup session.
     *
     * @param array $options
     * @return array
     */
    public function start_session(array $options = []): array {
        global $wpdb;

        if (!is_writable($this->backup_dir)) {
            return [
                'success' => false,
                'message' => 'Backup vault directory is not writable. Check folder permissions: ' . $this->backup_dir,
                'error'   => 'permission_denied',
            ];
        }

        $preflight = $this->get_preflight_info();
        if ($preflight['storage']['disk_safety'] === 'critical') {
            return [
                'success' => false,
                'message' => $preflight['storage']['disk_safety_message'],
                'error'   => 'disk_space_critical',
            ];
        }

        $throttle_ms = isset($options['throttle_ms']) ? max(5, min(300, (int) $options['throttle_ms'])) : (int) $preflight['server_environment']['recommended_throttle_ms'];
        $batch_size = isset($options['batch_size']) ? max(100, min(2500, (int) $options['batch_size'])) : 1000;

        $tables = $wpdb->get_col("SHOW TABLES");
        if (empty($tables)) {
            return [
                'success' => false,
                'message' => 'No database tables found to back up.',
                'error'   => 'no_tables_found',
            ];
        }

        $session_id = 'wcpscan_bak_' . wp_generate_password(12, false, false);
        $date_str = gmdate('Y-m-d_H-i-s');
        $use_gzip = function_exists('gzopen');
        $ext = $use_gzip ? 'sql.gz' : 'sql';
        $filename = "db_backup_{$date_str}_" . wp_generate_password(8, false) . ".{$ext}";
        $filepath = $this->backup_dir . '/' . $filename;

        // Inspect each table's row count and primary key for optimized cursor pagination
        $table_metadata = [];
        $total_est_rows = 0;
        foreach ($tables as $t) {
            $pk_col = null;
            $keys = $wpdb->get_results("SHOW KEYS FROM `{$t}` WHERE Key_name = 'PRIMARY'", ARRAY_A);
            if (!empty($keys) && count($keys) === 1 && !empty($keys[0]['Column_name'])) {
                // Verify column is numeric
                $col_name = $keys[0]['Column_name'];
                $col_type = $wpdb->get_var($wpdb->prepare("SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s", DB_NAME, $t, $col_name));
                if (in_array(strtolower((string) $col_type), ['int', 'bigint', 'mediumint', 'smallint', 'tinyint'], true)) {
                    $pk_col = $col_name;
                }
            }

            $count = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$t}`");
            $total_est_rows += $count;

            $table_metadata[] = [
                'name'        => $t,
                'total_rows'  => $count,
                'pk_column'   => $pk_col,
            ];
        }

        // Initialize file and write SQL header
        $fp = $use_gzip ? @gzopen($filepath, 'w9') : @fopen($filepath, 'w');
        if (!$fp) {
            return [
                'success' => false,
                'message' => 'Failed to initialize database backup file: ' . $filename,
                'error'   => 'file_init_failed',
            ];
        }

        $header = "-- ============================================================\n"
                . "-- WCP Security Scanner - Progressive Database Backup Vault\n"
                . "-- Generated By: Mir Alamin (WebCare Pro) Solo Security Engine\n"
                . "-- Date: " . current_time('mysql') . "\n"
                . "-- Session ID: {$session_id}\n"
                . "-- WordPress Version: " . get_bloginfo('version') . "\n"
                . "-- MySQL Host: " . DB_HOST . " | Database: " . DB_NAME . "\n"
                . "-- Character Set: utf8mb4 | Compression: " . ($use_gzip ? 'Gzip (.sql.gz)' : 'Plaintext (.sql)') . "\n"
                . "-- Server Pacing: Enabled ({$throttle_ms}ms throttle pause per chunk)\n"
                . "-- ============================================================\n\n"
                . "SET FOREIGN_KEY_CHECKS = 0;\n"
                . "SET NAMES utf8mb4;\n"
                . "SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n\n";

        if ($use_gzip) {
            gzwrite($fp, $header);
            gzclose($fp);
        } else {
            fwrite($fp, $header);
            fclose($fp);
        }

        $now_time = current_time('mysql');
        $start_micro = microtime(true);

        $state = [
            'session_id'            => $session_id,
            'filename'              => $filename,
            'filepath'              => $filepath,
            'use_gzip'              => $use_gzip,
            'status'                => 'running', // running | completed | failed | cancelled
            'throttle_ms'           => $throttle_ms,
            'batch_size'            => $batch_size,
            'tables'                => $table_metadata,
            'current_table_index'   => 0,
            'current_table_name'    => $table_metadata[0]['name'] ?? '',
            'current_row_offset'    => 0,
            'last_primary_id'       => 0,
            'table_rows_processed'  => 0,
            'total_rows_processed'  => 0,
            'total_estimated_rows'  => max(1, $total_est_rows),
            'total_tables'          => count($table_metadata),
            'tables_completed'      => 0,
            'table_logs'            => [],
            'start_time'            => $now_time,
            'start_micro'           => $start_micro,
            'stop_time'             => null,
            'total_time_seconds'    => 0.0,
            'peak_memory_bytes'     => memory_get_peak_usage(true),
            'error_details'         => null,
        ];

        $this->save_session_state($session_id, $state);

        $telemetry = $this->collect_telemetry($state, null, null);

        return [
            'success'    => true,
            'session_id' => $session_id,
            'filename'   => $filename,
            'status'     => 'running',
            'state'      => $state,
            'telemetry'  => $telemetry,
        ];
    }

    /**
     * Execute the next chunked step in an active backup session.
     *
     * @param string $session_id
     * @param int|null $custom_throttle_ms
     * @return array
     */
    public function step_session(string $session_id, ?int $custom_throttle_ms = null): array {
        global $wpdb;

        $state = $this->get_session_state($session_id);
        if (!$state) {
            return [
                'success' => false,
                'message' => 'Backup session not found or expired: ' . $session_id,
                'error'   => 'session_not_found',
            ];
        }

        if ($state['status'] !== 'running') {
            return [
                'success'   => true,
                'status'    => $state['status'],
                'state'     => $state,
                'telemetry' => $this->collect_telemetry($state),
            ];
        }

        if ($custom_throttle_ms !== null) {
            $state['throttle_ms'] = max(5, min(300, $custom_throttle_ms));
        }

        $step_start = microtime(true);
        $step_ru_start = function_exists('getrusage') ? @getrusage() : null;

        $filepath = $state['filepath'];
        $use_gzip = (bool) $state['use_gzip'];
        $throttle_ms = (int) $state['throttle_ms'];
        $batch_size = (int) $state['batch_size'];

        // Open in append mode
        $fp = $use_gzip ? @gzopen($filepath, 'a9') : @fopen($filepath, 'a');
        if (!$fp) {
            $error_details = [
                'title'                    => 'Vault Write Failure',
                'technical_message'        => 'Could not append to backup archive in vault. Check storage permissions and disk space.',
                'file_and_line'            => __FILE__ . ':' . __LINE__,
                'failed_at_table'          => $state['current_table_name'],
                'failed_at_row_offset'     => $state['current_row_offset'],
                'resource_state_at_failure' => [
                    'php_memory_mb'  => round(memory_get_usage(true) / (1024 * 1024), 2),
                    'free_disk_mb'   => round(@disk_free_space($this->backup_dir) / (1024 * 1024), 1),
                ],
                'recommended_action'       => 'Ensure the web server user has write permissions to ' . $this->backup_dir . ' and free disk space is available.',
            ];

            $state['status'] = 'failed';
            $state['stop_time'] = current_time('mysql');
            $state['total_time_seconds'] = round(microtime(true) - $state['start_micro'], 2);
            $state['error_details'] = $error_details;
            $this->save_session_state($session_id, $state);

            return [
                'success'   => false,
                'status'    => 'failed',
                'state'     => $state,
                'telemetry' => $this->collect_telemetry($state, $step_start, $step_ru_start),
                'error'     => $error_details,
            ];
        }

        $write_fn = function ($str) use ($fp, $use_gzip) {
            if ($use_gzip) {
                gzwrite($fp, $str);
            } else {
                fwrite($fp, $str);
            }
        };

        try {
            $max_step_seconds = 1.9; // Bounded time per step for high-frequency live UI feedback and zero web timeouts
            $tables = $state['tables'];
            $total_tables = count($tables);

            while ((microtime(true) - $step_start) < $max_step_seconds && $state['current_table_index'] < $total_tables) {
                $t_idx = $state['current_table_index'];
                $table_meta = $tables[$t_idx];
                $table_name = $table_meta['name'];
                $state['current_table_name'] = $table_name;
                $pk_col = $table_meta['pk_column'];

                // 1. If starting this table: write DROP TABLE IF EXISTS and CREATE TABLE schema
                if ($state['current_row_offset'] === 0 && $state['last_primary_id'] === 0) {
                    $write_fn("-- --------------------------------------------------------\n");
                    $write_fn("-- Structure for table `{$table_name}`\n");
                    $write_fn("DROP TABLE IF EXISTS `{$table_name}`;\n");
                    $create_res = $wpdb->get_row("SHOW CREATE TABLE `{$table_name}`", ARRAY_A);
                    if (isset($create_res['Create Table'])) {
                        $write_fn($create_res['Create Table'] . ";\n\n");
                    }
                    $write_fn("-- Dumping data for `{$table_name}`\n");
                }

                // If table has 0 rows, mark it done immediately
                if ($table_meta['total_rows'] === 0) {
                    $state['table_logs'][] = [
                        'table' => $table_name,
                        'rows'  => 0,
                    ];
                    $state['current_table_index']++;
                    $state['current_row_offset'] = 0;
                    $state['last_primary_id'] = 0;
                    $state['table_rows_processed'] = 0;
                    $state['tables_completed']++;
                    continue;
                }

                // 2. Fetch rows in chunks
                if ($pk_col) {
                    // Cursor pagination via primary key for maximum query performance on massive tables
                    $query = $wpdb->prepare(
                        "SELECT * FROM `{$table_name}` WHERE `{$pk_col}` > %d ORDER BY `{$pk_col}` ASC LIMIT %d",
                        $state['last_primary_id'],
                        $batch_size
                    );
                } else {
                    $query = $wpdb->prepare(
                        "SELECT * FROM `{$table_name}` LIMIT %d OFFSET %d",
                        $batch_size,
                        $state['current_row_offset']
                    );
                }

                $rows = $wpdb->get_results($query, ARRAY_A);

                if (!empty($rows)) {
                    $batch_count = count($rows);

                    // Build efficient multi-row INSERT statement chunks (e.g. 50 rows per INSERT)
                    $sub_batches = array_chunk($rows, 50);
                    foreach ($sub_batches as $chunk) {
                        $first_row = $chunk[0];
                        $cols = array_map(function ($c) { return "`{$c}`"; }, array_keys($first_row));
                        $cols_str = implode(', ', $cols);

                        $val_lines = [];
                        foreach ($chunk as $row) {
                            $vals = array_map(function ($val) use ($wpdb) {
                                if ($val === null) return 'NULL';
                                return "'" . esc_sql($val) . "'";
                            }, array_values($row));
                            $val_lines[] = "(" . implode(', ', $vals) . ")";

                            if ($pk_col && isset($row[$pk_col])) {
                                $state['last_primary_id'] = max($state['last_primary_id'], (int) $row[$pk_col]);
                            }
                        }

                        $sql = "INSERT INTO `{$table_name}` ({$cols_str}) VALUES \n" . implode(",\n", $val_lines) . ";\n";
                        $write_fn($sql);
                    }

                    $state['current_row_offset'] += $batch_count;
                    $state['table_rows_processed'] += $batch_count;
                    $state['total_rows_processed'] += $batch_count;

                    // Pacing sleep: keep CPU cool and prevent server pressure
                    if ($throttle_ms > 0) {
                        usleep($throttle_ms * 1000);
                    }
                }

                // 3. Check if table finished
                if (empty($rows) || $state['current_row_offset'] >= $table_meta['total_rows']) {
                    $write_fn("\n");
                    $state['table_logs'][] = [
                        'table' => $table_name,
                        'rows'  => $state['table_rows_processed'],
                    ];

                    $state['current_table_index']++;
                    $state['current_row_offset'] = 0;
                    $state['last_primary_id'] = 0;
                    $state['table_rows_processed'] = 0;
                    $state['tables_completed']++;

                    if ($state['current_table_index'] >= $total_tables) {
                        break; // Completed all tables!
                    }
                }
            }

            // Check if all tables finished
            if ($state['current_table_index'] >= $total_tables) {
                $write_fn("SET FOREIGN_KEY_CHECKS = 1;\n");
                $write_fn("-- Dump fully completed on " . current_time('mysql') . "\n");

                if ($use_gzip) {
                    gzclose($fp);
                } else {
                    fclose($fp);
                }

                $state['status'] = 'completed';
                $state['stop_time'] = current_time('mysql');
                $state['total_time_seconds'] = round(microtime(true) - $state['start_micro'], 2);
                $final_size = @filesize($filepath) ?: 0;
                $state['final_size_mb'] = round($final_size / (1024 * 1024), 2);

                if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                    \WcpScanner\Notifications\NotificationDispatcher::trigger('backup_db_completed', [
                        'severity' => 'info',
                        'message'  => sprintf(__('Database backup completed successfully (%s MB, %d tables in %s seconds).', 'wcp-security-scanner'), $state['final_size_mb'], $state['tables_completed'], $state['total_time_seconds']),
                        'details'  => [
                            'filename'      => basename($filepath),
                            'size_mb'       => $state['final_size_mb'],
                            'tables'        => $state['tables_completed'],
                            'duration_sec'  => $state['total_time_seconds'],
                        ],
                    ]);
                }
            } else {
                if ($use_gzip) {
                    gzclose($fp);
                } else {
                    fclose($fp);
                }
            }

        } catch (\Throwable $e) {
            if ($use_gzip && is_resource($fp)) {
                @gzclose($fp);
            } elseif (is_resource($fp)) {
                @fclose($fp);
            }

            $error_details = [
                'title'                    => 'Database Backup Interrupted',
                'technical_message'        => $e->getMessage(),
                'file_and_line'            => $e->getFile() . ':' . $e->getLine(),
                'failed_at_table'          => $state['current_table_name'],
                'failed_at_row_offset'     => $state['current_row_offset'],
                'resource_state_at_failure' => [
                    'php_memory_mb'      => round(memory_get_usage(true) / (1024 * 1024), 2),
                    'php_peak_memory_mb' => round(memory_get_peak_usage(true) / (1024 * 1024), 2),
                    'memory_limit'       => ini_get('memory_limit'),
                    'free_disk_mb'       => round(@disk_free_space($this->backup_dir) / (1024 * 1024), 1),
                ],
                'recommended_action'       => 'Check MySQL connection timeouts (`wait_timeout`, `max_allowed_packet`), database permissions, or free disk space.',
            ];

            $state['status'] = 'failed';
            $state['stop_time'] = current_time('mysql');
            $state['total_time_seconds'] = round(microtime(true) - $state['start_micro'], 2);
            $state['error_details'] = $error_details;

            if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('backup_db_failed', [
                    'severity' => 'high',
                    'message'  => sprintf(__('Database backup failed while exporting table "%s": %s', 'wcp-security-scanner'), $state['current_table_name'] ?? 'unknown', $e->getMessage()),
                    'details'  => [
                        'table'             => $state['current_table_name'] ?? 'unknown',
                        'technical_message' => $e->getMessage(),
                    ],
                ]);
            }

            $this->save_session_state($session_id, $state);

            return [
                'success'   => false,
                'status'    => 'failed',
                'state'     => $state,
                'telemetry' => $this->collect_telemetry($state, $step_start, $step_ru_start),
                'error'     => $error_details,
            ];
        }

        $this->save_session_state($session_id, $state);
        $telemetry = $this->collect_telemetry($state, $step_start, $step_ru_start);

        return [
            'success'   => true,
            'status'    => $state['status'],
            'state'     => $state,
            'telemetry' => $telemetry,
        ];
    }

    /**
     * Cancel an ongoing backup session and clean up its partial file.
     *
     * @param string $session_id
     * @return array
     */
    public function cancel_session(string $session_id): array {
        $state = $this->get_session_state($session_id);
        if ($state) {
            $state['status'] = 'cancelled';
            $state['stop_time'] = current_time('mysql');
            $state['total_time_seconds'] = round(microtime(true) - $state['start_micro'], 2);
            $this->save_session_state($session_id, $state);

            // Remove partial file
            if (!empty($state['filepath']) && file_exists($state['filepath'])) {
                @unlink($state['filepath']);
            }
        }

        return [
            'success' => true,
            'status'  => 'cancelled',
            'message' => 'Backup session cancelled and partial archive removed.',
        ];
    }

    /**
     * Collect live diagnostic telemetry for an active session.
     *
     * @param array $state
     * @param float|null $step_start
     * @param array|null $step_ru_start
     * @return array
     */
    private function collect_telemetry(array $state, $step_start = null, $step_ru_start = null): array {
        $php_mem = memory_get_usage(true);
        $php_peak = memory_get_peak_usage(true);
        $php_limit_raw = ini_get('memory_limit') ?: '256M';

        $limit_bytes = 256 * 1024 * 1024;
        if (preg_match('/^(\d+)(.)/i', $php_limit_raw, $m)) {
            $val = (int) $m[1];
            $u = strtoupper($m[2]);
            if ($u === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($u === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($u === 'K') $limit_bytes = $val * 1024;
        }

        $php_mem_percent = $limit_bytes > 0 ? min(100.0, round(($php_mem / $limit_bytes) * 100, 1)) : 0.0;
        $php_peak_percent = $limit_bytes > 0 ? min(100.0, round(($php_peak / $limit_bytes) * 100, 1)) : 0.0;

        $system_ram = self::get_system_ram_metrics();
        $cpu_metrics = self::get_cpu_metrics($step_start, $step_ru_start);

        $now_micro = microtime(true);
        $elapsed_seconds = max(0.1, round($now_micro - (float) $state['start_micro'], 1));

        $total_rows_processed = (int) $state['total_rows_processed'];
        $total_est_rows = max(1, (int) $state['total_estimated_rows']);
        $overall_percent = min(100.0, round(($total_rows_processed / $total_est_rows) * 100, 1));

        $rows_per_sec = $elapsed_seconds > 0 ? round($total_rows_processed / $elapsed_seconds, 1) : 0.0;
        $remaining_rows = max(0, $total_est_rows - $total_rows_processed);
        $eta_seconds = $rows_per_sec > 0 && $remaining_rows > 0 ? (int) round($remaining_rows / $rows_per_sec) : null;

        $archive_size = 0;
        if (!empty($state['filepath']) && file_exists($state['filepath'])) {
            $archive_size = @filesize($state['filepath']) ?: 0;
        }
        $archive_size_mb = round($archive_size / (1024 * 1024), 2);

        // Current table progress
        $current_table_meta = $state['tables'][$state['current_table_index']] ?? null;
        $curr_total_rows = $current_table_meta['total_rows'] ?? 0;
        $curr_rows_done = $state['table_rows_processed'] ?? 0;
        $curr_table_percent = $curr_total_rows > 0 ? min(100.0, round(($curr_rows_done / $curr_total_rows) * 100, 1)) : 100.0;

        return [
            'php_memory_mb'           => round($php_mem / (1024 * 1024), 2),
            'php_peak_memory_mb'      => round($php_peak / (1024 * 1024), 2),
            'php_memory_limit'        => $php_limit_raw,
            'php_memory_percent'      => $php_mem_percent,
            'php_peak_memory_percent' => $php_peak_percent,
            'system_ram'              => $system_ram,
            'cpu_usage_percent'       => $cpu_metrics['process_cpu_percent'],
            'cpu_load_average'        => $cpu_metrics['load_average'],
            'elapsed_seconds'         => $elapsed_seconds,
            'eta_seconds'             => $eta_seconds,
            'rows_per_second'         => $rows_per_sec,
            'overall_percent'         => $overall_percent,
            'total_rows_processed'    => $total_rows_processed,
            'total_estimated_rows'    => $total_est_rows,
            'tables_completed'        => (int) $state['tables_completed'],
            'total_tables'            => (int) $state['total_tables'],
            'current_table_name'      => $state['current_table_name'],
            'current_table_rows_done' => $curr_rows_done,
            'current_table_rows_total'=> $curr_total_rows,
            'current_table_percent'   => $curr_table_percent,
            'archive_size_mb'         => $archive_size_mb,
            'throttle_ms'             => (int) $state['throttle_ms'],
            'start_time'              => $state['start_time'],
            'stop_time'               => $state['stop_time'],
        ];
    }

    /**
     * Get session state from transient or disk state file.
     *
     * @param string $session_id
     * @return array|null
     */
    public function get_session_state(string $session_id): ?array {
        $transient_key = "wcpscan_bak_sess_{$session_id}";
        $state = get_transient($transient_key);
        if (is_array($state)) {
            return $state;
        }

        $state_file = $this->backup_dir . "/.state_{$session_id}.json";
        if (file_exists($state_file)) {
            $json = @file_get_contents($state_file);
            if ($json) {
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    return $decoded;
                }
            }
        }

        return null;
    }

    /**
     * Save session state to transient and disk state file.
     *
     * @param string $session_id
     * @param array $state
     */
    private function save_session_state(string $session_id, array $state) {
        $transient_key = "wcpscan_bak_sess_{$session_id}";
        set_transient($transient_key, $state, 6 * HOUR_IN_SECONDS);

        $state_file = $this->backup_dir . "/.state_{$session_id}.json";
        @file_put_contents($state_file, wp_json_encode($state));
    }

    /**
     * Generate a one-shot synchronous database backup dump.
     *
     * @return array ['success' => bool, 'filename' => string, 'size_mb' => float, 'message' => string]
     */
    public function create_backup() {
        @set_time_limit(600);
        $res = $this->start_session(['throttle_ms' => 15]);
        if (!$res['success']) {
            return $res;
        }

        $session_id = $res['session_id'];
        while (true) {
            $step = $this->step_session($session_id, 15);
            if (!$step['success']) {
                return [
                    'success' => false,
                    'message' => $step['error']['technical_message'] ?? 'Backup failed during execution.',
                ];
            }
            if ($step['status'] === 'completed') {
                return [
                    'success'  => true,
                    'filename' => $step['state']['filename'],
                    'size_mb'  => $step['state']['final_size_mb'] ?? 0,
                    'created'  => $step['state']['stop_time'],
                    'message'  => "Database backup created successfully (" . ($step['state']['final_size_mb'] ?? 0) . " MB).",
                ];
            }
            if ($step['status'] !== 'running') {
                return [
                    'success' => false,
                    'message' => 'Backup session stopped unexpectedly.',
                ];
            }
        }
    }

    /**
     * List all database backups stored in the secure vault.
     *
     * @return array
     */
    public function list_backups(): array {
        $backups = [];
        $dirs = [$this->backup_dir];

        $seen = [];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $files = @scandir($dir, SCANDIR_SORT_DESCENDING);
            if (!$files) {
                continue;
            }

            foreach ($files as $file) {
                if ($file === '.' || $file === '..' || $file === '.htaccess' || $file === 'index.php' || strpos($file, '.state_') === 0) {
                    continue;
                }
                if (isset($seen[$file])) {
                    continue;
                }

                $path = $dir . '/' . $file;
                if (is_file($path)) {
                    $seen[$file] = true;
                    $size = @filesize($path) ?: 0;
                    $mtime = @filemtime($path) ?: time();
                    $backups[] = [
                        'filename'   => $file,
                        'size_mb'    => round($size / (1024 * 1024), 2),
                        'size_bytes' => $size,
                        'created'    => gmdate('Y-m-d H:i:s', $mtime),
                        'timestamp'  => $mtime,
                    ];
                }
            }
        }

        usort($backups, function ($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });

        return $backups;
    }

    /**
     * Delete a backup file.
     *
     * @param string $filename
     * @return bool
     */
    public function delete_backup(string $filename): bool {
        $path = $this->get_backup_path($filename);
        if ($path && file_exists($path) && is_file($path)) {
            return @unlink($path);
        }
        return false;
    }

    /**
     * Get path for downloading a backup.
     *
     * @param string $filename
     * @return string|null
     */
    public function get_backup_path(string $filename): ?string {
        $basename = basename($filename);
        $path = $this->backup_dir . '/' . $basename;
        if (file_exists($path) && is_file($path)) {
            return $path;
        }
        return null;
    }
}
