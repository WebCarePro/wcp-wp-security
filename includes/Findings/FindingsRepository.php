<?php
namespace WcpScanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

class FindingsRepository {

    /** Maximum rows per multi-row INSERT statement to stay safely below MySQL limits */
    private const MAX_ROWS_PER_QUERY = 80;

    /**
     * Bulk-insert file audit records into wcp_scan_files.
     *
     * @param int   $scan_id
     * @param array $rows Array of items: ['file_path' => string, 'file_size' => int, 'status' => 'clean'|'threat']
     */
    public function bulk_insert_files(int $scan_id, array $rows): void {
        if (empty($rows)) {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_scan_files';
        $now = current_time('mysql');

        foreach (array_chunk($rows, self::MAX_ROWS_PER_QUERY) as $chunk) {
            $placeholders = [];
            $values = [];

            foreach ($chunk as $row) {
                $placeholders[] = '(%d, %s, %d, %s, %s)';
                $values[] = $scan_id;
                $values[] = (string) ($row['file_path'] ?? '');
                $values[] = (int) ($row['file_size'] ?? 0);
                $values[] = (string) ($row['status'] ?? 'clean');
                $values[] = $now;
            }

            $sql = "INSERT INTO {$table} (scan_id, file_path, file_size, status, scanned_at) VALUES " . implode(', ', $placeholders);
            $prepared = $wpdb->prepare($sql, $values);
            $wpdb->query($prepared);
        }
    }

    /**
     * Bulk-insert threat findings into wcp_scan_issues.
     *
     * @param int   $scan_id
     * @param array $rows Array of finding arrays or objects
     */
    public function bulk_insert_issues(int $scan_id, array $rows): void {
        if (empty($rows)) {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_scan_issues';
        $now = current_time('mysql');

        foreach (array_chunk($rows, self::MAX_ROWS_PER_QUERY) as $chunk) {
            $placeholders = [];
            $values = [];

            foreach ($chunk as $row) {
                if (is_object($row) && method_exists($row, 'to_array')) {
                    $row = $row->to_array();
                }

                $placeholders[] = '(%d, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s)';
                $values[] = $scan_id;
                $values[] = (string) ($row['engine'] ?? 'filesystem');
                $values[] = (string) ($row['type'] ?? 'anomaly');
                $values[] = (string) ($row['severity'] ?? 'medium');
                $values[] = (int) ($row['confidence'] ?? 80);
                $values[] = (string) ($row['file_path'] ?? '');
                $values[] = isset($row['line_number']) && $row['line_number'] !== null ? (int) $row['line_number'] : null;
                $values[] = isset($row['code_snippet']) && $row['code_snippet'] !== null ? (string) $row['code_snippet'] : null;
                $values[] = isset($row['evidence']) && $row['evidence'] !== null ? (string) $row['evidence'] : null;
                $values[] = (string) ($row['description'] ?? '');
                $values[] = (string) ($row['status'] ?? 'open');
                $values[] = $now;
            }

            $sql = "INSERT INTO {$table} (scan_id, engine, type, severity, confidence, file_path, line_number, code_snippet, evidence, description, status, created_at) VALUES " . implode(', ', $placeholders);
            $prepared = $this->prepare_with_nulls($sql, $values);
            $wpdb->query($prepared);
        }
    }

    /**
     * Convenience method to persist both files and issues for a finished batch.
     */
    public function persist_batch(int $scan_id, array $file_rows, array $issue_rows): void {
        $this->bulk_insert_files($scan_id, $file_rows);
        $this->bulk_insert_issues($scan_id, $issue_rows);
    }

    /**
     * Safely prepare SQL queries containing nullable values with $wpdb->prepare.
     */
    private function prepare_with_nulls(string $sql, array $values): string {
        global $wpdb;

        $token = '##WCP_SQL_NULL##';
        $safe_values = [];

        foreach ($values as $v) {
            if ($v === null) {
                $safe_values[] = $token;
            } else {
                $safe_values[] = $v;
            }
        }

        $prepared = $wpdb->prepare($sql, $safe_values);
        return str_replace("'{$token}'", 'NULL', $prepared);
    }
}
