<?php
namespace WcpScanner\Database;

use WcpScanner\Findings\Finding;
use WcpScanner\Resource\ResourceMonitor;

if (!defined('ABSPATH')) {
    exit;
}

class DatabaseScanner {

    private $table_scanner;
    private $option_scanner;
    private $rogue_admin_detector;

    public function __construct() {
        $this->table_scanner = new TableScanner();
        $this->option_scanner = new OptionScanner();
        $this->rogue_admin_detector = new RogueAdminAnomalyDetector();
    }

    /**
     * Run full database inspection with resource awareness.
     *
     * @param string $scan_id
     * @param int $batch_size Rows per table batch
     * @return Finding[]
     */
    public function scan($scan_id, $batch_size = 100) {
        $findings = [];
        $monitor = new ResourceMonitor(70, 20, 'balanced');
        $adaptive_row_batch = $monitor->get_adaptive_batch_size($batch_size);

        // 1. Audit wp_options first
        if (!empty($scan_id)) {
            set_transient("wcpscan_active_scan_file_{$scan_id}", 'MySQL Database: Scanning wp_options & core settings...', 120);
        }
        $option_findings = $this->option_scanner->scan_options($scan_id);
        $findings = array_merge($findings, $option_findings);

        // 2. Audit Rogue Administrators & Database Micro-Anomalies
        if (!empty($scan_id)) {
            set_transient("wcpscan_active_scan_file_{$scan_id}", 'MySQL Database: Inspecting rogue administrators & user meta anomalies...', 120);
        }
        $rogue_findings = $this->rogue_admin_detector->scan((string) $scan_id);
        $findings = array_merge($findings, $rogue_findings);

        // 3. Discover all tables and calculate grand total row estimate upfront
        $tables = $this->table_scanner->get_tables();
        $total_tables = count($tables);
        $total_rows_scanned = 0;

        // Pre-calculate approximate grand total rows across all tables for accurate remaining counter
        $grand_total_rows = 0;
        $table_row_estimates = [];
        foreach ($tables as $t) {
            $est = $this->get_table_row_count($t);
            $table_row_estimates[$t] = $est;
            $grand_total_rows += $est;
        }

        foreach ($tables as $table_idx => $table) {
            if ($monitor->is_nearing_limits()) {
                break; // Stop early to prevent server strain
            }

            $meta = $this->table_scanner->get_table_metadata($table);
            if (empty($meta['columns'])) {
                continue;
            }

            $table_num = $table_idx + 1;
            $table_rows_scanned = 0;
            $table_approx_rows = $table_row_estimates[$table] ?? $this->get_table_row_count($table);

            if (!empty($scan_id)) {
                $status_msg = sprintf(
                    'MySQL Table: %s [%d/%d] (Row %s%s)',
                    $table,
                    $table_num,
                    $total_tables,
                    number_format($table_rows_scanned),
                    $table_approx_rows > 0 ? ' / ' . number_format($table_approx_rows) : ''
                );
                $rows_left = max(0, $grand_total_rows - $total_rows_scanned);
                set_transient("wcpscan_active_scan_file_{$scan_id}", $status_msg, 120);
                set_transient("wcpscan_scan_db_progress_{$scan_id}", [
                    'current_table'        => $table,
                    'table_index'          => $table_num,
                    'total_tables'         => $total_tables,
                    'table_rows_scanned'   => $table_rows_scanned,
                    'table_approx_rows'    => $table_approx_rows,
                    'overall_rows_scanned' => $total_rows_scanned,
                    'overall_total_rows'   => $grand_total_rows,
                    'overall_rows_left'    => $rows_left,
                    'completed'            => false,
                ], 120);
            }

            $cursor = 0;
            while ($cursor !== null) {
                if ($monitor->throttle_and_check()) {
                    break 2;
                }

                $batch_res = $this->table_scanner->scan_table_batch(
                    $table,
                    $meta['columns'],
                    $meta['primary_key'],
                    $cursor,
                    $adaptive_row_batch,
                    $scan_id
                );

                $batch_rows = (int) ($batch_res['rows_scanned'] ?? 0);
                $table_rows_scanned += $batch_rows;
                $total_rows_scanned += $batch_rows;

                if (!empty($scan_id)) {
                    $status_msg = sprintf(
                        'MySQL Table: %s [%d/%d] (Row %s%s)',
                        $table,
                        $table_num,
                        $total_tables,
                        number_format($table_rows_scanned),
                        $table_approx_rows > 0 ? ' / ' . number_format($table_approx_rows) : ''
                    );
                    $rows_left = max(0, $grand_total_rows - $total_rows_scanned);
                    set_transient("wcpscan_active_scan_file_{$scan_id}", $status_msg, 120);
                    set_transient("wcpscan_scan_db_progress_{$scan_id}", [
                        'current_table'        => $table,
                        'table_index'          => $table_num,
                        'total_tables'         => $total_tables,
                        'table_rows_scanned'   => $table_rows_scanned,
                        'table_approx_rows'    => $table_approx_rows,
                        'overall_rows_scanned' => $total_rows_scanned,
                        'overall_total_rows'   => $grand_total_rows,
                        'overall_rows_left'    => $rows_left,
                        'completed'            => false,
                    ], 120);
                }

                if (!empty($batch_res['findings'])) {
                    $findings = array_merge($findings, $batch_res['findings']);
                }

                $cursor = $batch_res['next_cursor'];
            }
        }

        if (!empty($scan_id)) {
            // Retain the final completion summary for 120 seconds so frontend poller never misses it
            set_transient("wcpscan_scan_db_progress_{$scan_id}", [
                'current_table'        => 'All MySQL Tables',
                'table_index'          => $total_tables,
                'total_tables'         => $total_tables,
                'table_rows_scanned'   => $total_rows_scanned,
                'table_approx_rows'    => $total_rows_scanned,
                'overall_rows_scanned' => $total_rows_scanned,
                'overall_total_rows'   => max($grand_total_rows, $total_rows_scanned),
                'overall_rows_left'    => 0,
                'completed'            => true,
            ], 120);
        }

        return $findings;
    }

    /**
     * Get fast approximate row count for a table without table-locking.
     *
     * @param string $table
     * @return int
     */
    private function get_table_row_count(string $table): int {
        global $wpdb;
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $table)) {
            return 0;
        }

        // Fast table status check via SHOW TABLE STATUS
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $status = $wpdb->get_row($wpdb->prepare("SHOW TABLE STATUS LIKE %s", $table), ARRAY_A);
        if (!empty($status['Rows'])) {
            return (int) $status['Rows'];
        }

        return 0;
    }

    public function get_table_scanner() {
        return $this->table_scanner;
    }

    public function get_option_scanner() {
        return $this->option_scanner;
    }
}
