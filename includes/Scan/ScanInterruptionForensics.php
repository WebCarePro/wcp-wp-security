<?php
namespace WcpScanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ScanInterruptionForensics
 *
 * Captures, analyzes, and formats deep forensic diagnostics whenever
 * a security scan is interrupted (timeout, memory exhaustion, fatal error,
 * process abandonment, or manual abort).
 */
class ScanInterruptionForensics {

    const OPTION_PREFIX = 'wcpscan_interruption_';

    /**
     * Standardized reason codes
     */
    const REASON_PHP_TIMEOUT        = 'php_timeout';
    const REASON_MEMORY_EXHAUSTION  = 'memory_exhaustion';
    const REASON_FATAL_ERROR        = 'fatal_error';
    const REASON_STALE_HEARTBEAT    = 'stale_heartbeat';
    const REASON_MANUAL_ABORT       = 'manual_abort';
    const REASON_EXCEPTION_CAUGHT   = 'exception_caught';
    const REASON_UNKNOWN            = 'unknown';

    /**
     * Record a comprehensive interruption event for a scan.
     *
     * @param int $scan_id
     * @param string $reason_code
     * @param array $extra_context
     * @return array The recorded forensic telemetry payload
     */
    public static function record(int $scan_id, string $reason_code = self::REASON_UNKNOWN, array $extra_context = []): array {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);

        $last_file = $extra_context['last_file'] ?? get_transient("wcpscan_active_scan_file_{$scan_id}") ?: '';
        $live_telemetry = get_transient("wcpscan_scan_live_telemetry_{$scan_id}");

        $mem_peak_bytes = memory_get_peak_usage(true);
        $mem_limit_str = ini_get('memory_limit') ?: '256M';
        $mem_limit_bytes = self::parse_size_to_bytes($mem_limit_str);
        $mem_percent = $mem_limit_bytes > 0 ? round(($mem_peak_bytes / $mem_limit_bytes) * 100, 1) : 0;

        $max_exec_time = (int) ini_get('max_execution_time');
        $start_micro = get_transient("wcpscan_scan_start_micro_{$scan_id}");
        $elapsed_sec = ($start_micro && is_numeric($start_micro)) ? max(0.1, round(microtime(true) - (float) $start_micro, 2)) : (float) ($scan['duration'] ?? 0);

        // Check if PHP captured a shutdown error
        $php_error = error_get_last();
        $is_fatal_php = false;
        if (!empty($php_error) && in_array($php_error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
            $is_fatal_php = true;
            // Auto-detect OOM or timeout from message
            $msg_lower = strtolower($php_error['message']);
            if (str_contains($msg_lower, 'allowed memory size of') || str_contains($msg_lower, 'out of memory')) {
                $reason_code = self::REASON_MEMORY_EXHAUSTION;
            } elseif (str_contains($msg_lower, 'maximum execution time of') || str_contains($msg_lower, 'execution time exceeded')) {
                $reason_code = self::REASON_PHP_TIMEOUT;
            } else {
                $reason_code = self::REASON_FATAL_ERROR;
            }
        }

        // Derive Human-friendly diagnostics
        $reason_meta = self::get_reason_metadata($reason_code, [
            'elapsed_sec'   => $elapsed_sec,
            'max_exec_time' => $max_exec_time,
            'mem_peak'      => round($mem_peak_bytes / 1024 / 1024, 2) . ' MB',
            'mem_limit'     => $mem_limit_str,
            'mem_percent'   => $mem_percent,
            'last_file'     => $last_file,
            'php_error'     => $php_error,
            'exception'     => $extra_context['exception'] ?? null,
        ]);

        $payload = [
            'scan_id'               => $scan_id,
            'interrupted_at'        => gmdate('c'),
            'interrupted_at_human'  => gmdate('F j, Y g:i:s A \U\T\C'),
            'reason_code'           => $reason_code,
            'title'                 => $reason_meta['title'],
            'severity'              => $reason_meta['severity'],
            'summary'               => $reason_meta['summary'],
            'technical_details'     => $reason_meta['technical_details'],
            'remediation'           => $reason_meta['remediation'],
            'last_active_file'      => $last_file,
            'elapsed_seconds'       => $elapsed_sec,
            'scanned_files'         => (int) ($scan['scanned_files'] ?? 0),
            'total_files'           => (int) ($scan['total_files'] ?? 0),
            'progress_percent'      => (!empty($scan['total_files']) && (int) $scan['total_files'] > 0) ? round(((int) $scan['scanned_files'] / (int) $scan['total_files']) * 100, 1) : 0,
            'peak_memory_mb'        => round($mem_peak_bytes / 1024 / 1024, 2),
            'peak_memory_formatted' => round($mem_peak_bytes / 1024 / 1024, 2) . ' MB',
            'memory_limit'          => $mem_limit_str,
            'memory_usage_percent'  => $mem_percent,
            'max_execution_time'    => $max_exec_time,
            'php_sapi'              => php_sapi_name(),
            'php_version'           => phpversion(),
            'server_os'             => php_uname('s') . ' ' . php_uname('r'),
            'last_php_error'        => $php_error ?: null,
            'caught_exception'      => !empty($extra_context['exception']) ? [
                'message' => $extra_context['exception']->getMessage(),
                'file'    => $extra_context['exception']->getFile(),
                'line'    => $extra_context['exception']->getLine(),
                'trace'   => substr($extra_context['exception']->getTraceAsString(), 0, 1500),
            ] : null,
        ];

        // Store persistent record in WordPress options
        update_option(self::OPTION_PREFIX . $scan_id, $payload, false);

        // Dispatch scan_aborted_timeout notification
        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('scan_aborted_timeout', [
                'severity' => 'warning',
                /* translators: 1: scan ID, 2: interruption title */
                'message'  => sprintf(__('Scan #%1$d was aborted or interrupted: %2$s', 'wcp-security-scanner'), $scan_id, $payload['title']),
                'details'  => [
                    'Scan ID'        => $scan_id,
                    'Reason Code'    => $reason_code,
                    'Last File'      => $last_file ?: __('N/A', 'wcp-security-scanner'),
                    'Files Scanned'  => number_format($scanned_files) . ' / ' . number_format($total_files),
                    'Elapsed'        => round($elapsed_sec, 1) . 's',
                ],
            ]);
        }

        // Update database scan record with interrupted status if still marked running
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_scans, [
            'status'       => 'interrupted',
            'duration'     => max(1, (int) round($elapsed_sec)),
            'completed_at' => \WcpScanner\Api\ScannerRoutes::now_fractional_mysql(),
        ], ['id' => $scan_id]);

        return $payload;
    }

    /**
     * Retrieve the recorded interruption details for a scan.
     *
     * @param int $scan_id
     * @return array|null
     */
    public static function get(int $scan_id): ?array {
        $details = get_option(self::OPTION_PREFIX . $scan_id, null);
        if ($details && is_array($details)) {
            return $details;
        }

        // If not stored explicitly, synthesize a dynamic forensic deduction based on database scan state
        global $wpdb;
        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $scan_id), ARRAY_A);
        if (!$scan || $scan['status'] !== 'interrupted') {
            return null;
        }

        $last_file = get_transient("wcpscan_active_scan_file_{$scan_id}") ?: '';
        $scanned = (int) ($scan['scanned_files'] ?? 0);
        $total = (int) ($scan['total_files'] ?? 0);
        $dur = (int) ($scan['duration'] ?? 0);

        return [
            'scan_id'               => $scan_id,
            'interrupted_at'        => $scan['completed_at'] ?? $scan['created_at'],
            'interrupted_at_human'  => !empty($scan['completed_at']) ? gmdate('F j, Y g:i:s A \U\T\C', strtotime($scan['completed_at'])) : 'Unknown',
            'reason_code'           => self::REASON_STALE_HEARTBEAT,
            'title'                 => __('Scan Execution Interrupted / Abandoned Heartbeat', 'wcp-security-scanner'),
            'severity'              => 'high',
            /* translators: 1: scan ID, 2: scanned files count, 3: total files count, 4: percentage completed */
            'summary'               => sprintf(__('Scan #%1$d stopped prematurely after processing %2$s of %3$s files (%4$s%% completed).', 'wcp-security-scanner'), $scan_id, number_format($scanned), number_format($total), $total > 0 ? round(($scanned / $total) * 100, 1) : 0),
            'technical_details'     => __('The scanner worker stopped receiving heartbeats. This commonly occurs if the browser window was closed, the WP-Cron execution thread was killed by the host web server, or a reverse proxy timed out the HTTP worker request.', 'wcp-security-scanner'),
            'remediation'           => __('Keep the scan tab active during manual audits, or run the scan via WP-CLI ("wp wcp scan start") for unlimited background execution.', 'wcp-security-scanner'),
            'last_active_file'      => $last_file,
            'elapsed_seconds'       => $dur,
            'scanned_files'         => $scanned,
            'total_files'           => $total,
            'progress_percent'      => $total > 0 ? round(($scanned / $total) * 100, 1) : 0,
            'peak_memory_formatted' => 'N/A',
            'memory_limit'          => ini_get('memory_limit') ?: '256M',
            'max_execution_time'    => (int) ini_get('max_execution_time'),
            'php_sapi'              => php_sapi_name(),
            'php_version'           => phpversion(),
            'server_os'             => php_uname('s') . ' ' . php_uname('r'),
        ];
    }

    /**
     * Delete interruption records for a scan (when scan is deleted or pruned).
     */
    public static function delete(int $scan_id): void {
        delete_option(self::OPTION_PREFIX . $scan_id);
    }

    /**
     * Map reason codes to detailed human & sysadmin metadata.
     */
    private static function get_reason_metadata(string $code, array $ctx): array {
        switch ($code) {
            case self::REASON_PHP_TIMEOUT:
                return [
                    'title'             => __('PHP Maximum Execution Timeout Exceeded', 'wcp-security-scanner'),
                    'severity'          => 'high',
                    /* translators: %d: maximum execution time in seconds */
                    'summary'           => sprintf(__('The scanner worker batch exceeded the PHP time limit of %ds while inspecting files.', 'wcp-security-scanner'), $ctx['max_exec_time']),
                    /* translators: 1: elapsed execution time in seconds, 2: last file path */
                    'technical_details' => sprintf(__('Process execution was halted by the server after %1$.2fs. The last active file inspected was: "%2$s".', 'wcp-security-scanner'), $ctx['elapsed_sec'], $ctx['last_file'] ?: 'unknown'),
                    'remediation'       => __('Increase "max_execution_time = 300" in your php.ini or wp-config.php ("set_time_limit(300)"), or reduce batch size in WCP Scanner Settings.', 'wcp-security-scanner'),
                ];

            case self::REASON_MEMORY_EXHAUSTION:
                return [
                    'title'             => __('PHP Memory Allocation Limit Exhausted (OOM)', 'wcp-security-scanner'),
                    'severity'          => 'critical',
                    /* translators: 1: memory limit, 2: peak memory consumed, 3: memory consumption percentage */
                    'summary'           => sprintf(__('The scan exceeded the allowed memory limit of %1$s (consumed %2$s, %3$s%%).', 'wcp-security-scanner'), $ctx['mem_limit'], $ctx['mem_peak'], $ctx['mem_percent']),
                    /* translators: %s: last active file path */
                    'technical_details' => sprintf(__('PHP ran out of memory while allocating buffers for file inspection. Last file loaded: "%s".', 'wcp-security-scanner'), $ctx['last_file'] ?: 'unknown'),
                    'remediation'       => __('Increase the WordPress memory limit in wp-config.php: define(\'WP_MEMORY_LIMIT\', \'512M\'); define(\'WP_MAX_MEMORY_LIMIT\', \'512M\');', 'wcp-security-scanner'),
                ];

            case self::REASON_FATAL_ERROR:
                $err_msg = !empty($ctx['php_error']['message']) ? $ctx['php_error']['message'] : __('Fatal engine failure', 'wcp-security-scanner');
                return [
                    'title'             => __('Fatal PHP Execution Error', 'wcp-security-scanner'),
                    'severity'          => 'critical',
                    /* translators: %s: fatal error message */
                    'summary'           => sprintf(__('A fatal PHP engine error terminated the scanner: %s', 'wcp-security-scanner'), $err_msg),
                    /* translators: 1: source file name, 2: line number, 3: last target file audited */
                    'technical_details' => sprintf(__('Error in file: %1$s on line %2$d. Last audited target file: "%3$s".', 'wcp-security-scanner'), $ctx['php_error']['file'] ?? 'unknown', $ctx['php_error']['line'] ?? 0, $ctx['last_file'] ?: 'unknown'),
                    'remediation'       => __('Inspect server error logs or run PHP syntax validation. Ensure file system read permissions allow access to all directories.', 'wcp-security-scanner'),
                ];

            case self::REASON_MANUAL_ABORT:
                return [
                    'title'             => __('Scan Manually Aborted by Administrator', 'wcp-security-scanner'),
                    'severity'          => 'medium',
                    'summary'           => __('The active security audit was deliberately stopped by an authorized administrator.', 'wcp-security-scanner'),
                    /* translators: 1: elapsed seconds, 2: last file processed */
                    'technical_details' => sprintf(__('Scan was aborted after %1$.2fs elapsed with %2$s as the last processed file.', 'wcp-security-scanner'), $ctx['elapsed_sec'], $ctx['last_file'] ?: 'none'),
                    'remediation'       => __('You can initiate a new scan anytime from the Dashboard or Scan Logs page.', 'wcp-security-scanner'),
                ];

            case self::REASON_EXCEPTION_CAUGHT:
                $ex_msg = !empty($ctx['exception']) ? $ctx['exception']->getMessage() : 'Exception thrown';
                return [
                    'title'             => __('Unhandled Engine Exception', 'wcp-security-scanner'),
                    'severity'          => 'high',
                    /* translators: %s: exception message */
                    'summary'           => sprintf(__('A subsystem exception halted the scan worker: %s', 'wcp-security-scanner'), $ex_msg),
                    /* translators: 1: source file, 2: line number, 3: last target file */
                    'technical_details' => sprintf(__('Exception in %1$s:%2$d while scanning "%3$s".', 'wcp-security-scanner'), !empty($ctx['exception']) ? $ctx['exception']->getFile() : 'unknown', !empty($ctx['exception']) ? $ctx['exception']->getLine() : 0, $ctx['last_file'] ?: 'unknown'),
                    'remediation'       => __('Review the exception stack trace. If inspecting a corrupted or non-standard file, exclude its folder from Custom Scan targets.', 'wcp-security-scanner'),
                ];

            case self::REASON_STALE_HEARTBEAT:
            default:
                return [
                    'title'             => __('Scan Worker Heartbeat Lost / Request Abandoned', 'wcp-security-scanner'),
                    'severity'          => 'high',
                    'summary'           => __('The scanner stopped receiving background pulse heartbeats and was marked interrupted after a 10-minute timeout.', 'wcp-security-scanner'),
                    /* translators: %s: last active file path */
                    'technical_details' => sprintf(__('No AJAX or Cron progress was logged for > 10 minutes. Last registered active file was: "%s".', 'wcp-security-scanner'), $ctx['last_file'] ?: 'unknown'),
                    'remediation'       => __('Ensure your browser tab remains open during manual scans, verify HTTP keep-alive settings, or execute via WP-CLI on large sites.', 'wcp-security-scanner'),
                ];
        }
    }

    /**
     * Helper to parse size string (e.g. 256M, 1G) to integer bytes.
     */
    private static function parse_size_to_bytes(string $size): int {
        $size = trim($size);
        if ($size === '' || $size === '-1') {
            return -1;
        }
        $unit = strtolower(substr($size, -1));
        $val = (int) substr($size, 0, -1);
        switch ($unit) {
            case 'g':
                return $val * 1024 * 1024 * 1024;
            case 'm':
                return $val * 1024 * 1024;
            case 'k':
                return $val * 1024;
            default:
                return (int) $size;
        }
    }
}
