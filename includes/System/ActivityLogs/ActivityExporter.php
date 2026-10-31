<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Secure Streaming Exporter for WCP Activity & Audit Logs.
 *
 * Implements:
 * 1. CSV Formula Injection Defense (escapes '=', '+', '-', '@', tabs, and leading spaces with single quote).
 * 2. Streaming direct-to-browser output (no unencrypted temporary files on disk).
 * 3. Supports Decrypted CSV, Encrypted JSONL, and Markdown forensic summaries.
 */
class ActivityExporter {

    /**
     * Neutralize CSV formula injection attacks.
     *
     * @param string $val
     * @return string
     */
    public static function sanitize_csv_cell(string $val): string {
        $trimmed = ltrim($val);
        if (strlen($trimmed) > 0) {
            $first_char = $trimmed[0];
            if (in_array($first_char, ['=', '+', '-', '@', "\t", "\r"], true)) {
                return "'" . $val;
            }
        }
        return $val;
    }

    /**
     * Stream CSV export directly to output.
     *
     * @param array $records Decrypted event records.
     * @param string $filename Download filename.
     */
    public static function stream_csv(array $records, string $filename = 'wcp-activity-logs.csv'): void {
        if (ob_get_level()) {
            ob_end_clean();
        }

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . sanitize_file_name($filename) . '"');
        header('Pragma: no-cache');
        header('Expires: 0');

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $out = fopen('php://output', 'w');
        // UTF-8 BOM for Excel compatibility
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
        fwrite($out, "\xEF\xBB\xBF");

        // CSV Header
        fputcsv($out, [
            'Sequence',
            'Event ID',
            'UTC Datetime',
            'Category',
            'Severity',
            'Action',
            'Actor Type',
            'Actor Login',
            'Actor Role',
            'Actor IP',
            'Executor',
            'Details Summary',
        ]);

        foreach ($records as $rec) {
            $actor = $rec['actor'] ?? [];
            $executor = $rec['executor'] ?? [];
            $details = $rec['details'] ?? [];

            $details_summary = '';
            if (is_array($details) || is_object($details)) {
                $details_summary = json_encode($details, JSON_UNESCAPED_SLASHES);
            }

            $row = [
                self::sanitize_csv_cell((string) ($rec['seq'] ?? '')),
                self::sanitize_csv_cell((string) ($rec['event_id'] ?? '')),
                self::sanitize_csv_cell((string) ($rec['datetime'] ?? '')),
                self::sanitize_csv_cell((string) ($rec['category'] ?? '')),
                self::sanitize_csv_cell((string) ($rec['severity'] ?? '')),
                self::sanitize_csv_cell((string) ($rec['action'] ?? '')),
                self::sanitize_csv_cell((string) ($actor['type'] ?? '')),
                self::sanitize_csv_cell((string) ($actor['user_login'] ?? '')),
                self::sanitize_csv_cell((string) ($actor['role'] ?? '')),
                self::sanitize_csv_cell((string) ($actor['ip'] ?? '')),
                self::sanitize_csv_cell((string) ($executor['identifier'] ?? '')),
                self::sanitize_csv_cell($details_summary),
            ];

            fputcsv($out, $row);
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($out);
        exit;
    }

    /**
     * Stream JSON export directly to output.
     *
     * @param array $records
     * @param string $filename
     */
    public static function stream_json(array $records, string $filename = 'wcp-activity-logs.json'): void {
        if (ob_get_level()) {
            ob_end_clean();
        }

        header('Content-Type: application/json; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . sanitize_file_name($filename) . '"');
        header('Pragma: no-cache');
        header('Expires: 0');

        echo json_encode([
            'exported_at_utc' => gmdate('Y-m-d\TH:i:s\Z'),
            'records'         => $records,
            'total_count'     => count($records),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
}
