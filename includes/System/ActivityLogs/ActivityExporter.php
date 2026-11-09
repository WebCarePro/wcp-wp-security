<?php
namespace WebCareProScanner\System\ActivityLogs;

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
     * @param bool $include_system_info Whether to prepend environmental snapshot preamble.
     */
    public static function stream_csv(array $records, string $filename = 'wcp-activity-logs.csv', bool $include_system_info = false): void {
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

        // Optional System Diagnostic & Environmental Preheader
        if ($include_system_info && class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')) {
            $telemetry = \WebCareProScanner\System\TelemetrySnapshot::get_snapshot();
            $cf_text   = !empty($telemetry['edge_network']['powered_by_cloudflare']) ? 'YES (' . ($telemetry['edge_network']['cloudflare_status'] ?? 'Cloudflare Edge') . ')' : 'NO (Direct Origin)';
            $act_plugins = !empty($telemetry['plugins']['active_plugins']) ? array_column($telemetry['plugins']['active_plugins'], 'name') : [];
            $act_plugins_str = implode(', ', array_slice($act_plugins, 0, 15)) . (count($act_plugins) > 15 ? sprintf(' ... (+%d more)', count($act_plugins) - 15) : '');

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# =============================================================================\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# WEBCARE PRO SECURITY & FIREWALL - AUDIT & ACTIVITY LOG EXPORT\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# Site Domain: " . ($telemetry['site']['domain'] ?? 'Unknown') . " | Real Server IP: " . ($telemetry['server']['real_ip'] ?? 'Unknown') . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# Cloudflare Edge: " . $cf_text . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# Server Software: " . ($telemetry['server']['software'] ?? 'Unknown') . " | PHP: " . ($telemetry['server']['php_version'] ?? 'Unknown') . " | WP Core: " . ($telemetry['wordpress']['core_version'] ?? 'Unknown') . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# Active Theme: " . ($telemetry['theme']['active_theme']['name'] ?? 'Unknown') . " (v" . ($telemetry['theme']['active_theme']['version'] ?? 'Unknown') . ")\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# Active Plugins (" . count($act_plugins) . "): " . $act_plugins_str . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# Exported At (UTC): " . ($telemetry['exported_at_utc'] ?? gmdate('Y-m-d\TH:i:s\Z')) . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($out, "# =============================================================================\r\n");
        }

        // CSV Header
        fputcsv($out, [
            'Sequence',
            'Event ID',
            'UTC Datetime',
            'Category',
            'Severity',
            'Event Title',
            'Explanation',
            'Action Key',
            'Actor Type',
            'Actor Login',
            'Actor Role',
            'Actor IP',
            'Executor',
            'Raw Details JSON',
        ]);

        foreach ($records as $rec) {
            if (class_exists('\\WebCareProScanner\\System\\ActivityLogs\\ActivityHumanizer')) {
                $rec = ActivityHumanizer::humanize_record($rec);
            }

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
                self::sanitize_csv_cell((string) ($rec['friendly_title'] ?? $rec['action'] ?? '')),
                self::sanitize_csv_cell((string) ($rec['friendly_description'] ?? $details_summary)),
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
     * @param bool $include_system_info Whether to embed environmental snapshot.
     */
    public static function stream_json(array $records, string $filename = 'wcp-activity-logs.json', bool $include_system_info = false): void {
        if (ob_get_level()) {
            ob_end_clean();
        }

        header('Content-Type: application/json; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . sanitize_file_name($filename) . '"');
        header('Pragma: no-cache');
        header('Expires: 0');

        $payload = [
            'exported_at_utc' => gmdate('Y-m-d\TH:i:s\Z'),
            'records'         => $records,
            'total_count'     => count($records),
        ];

        if ($include_system_info && class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')) {
            $payload['environment_snapshot'] = \WebCareProScanner\System\TelemetrySnapshot::get_snapshot();
        }

        echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
}
