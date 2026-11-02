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
    private $cron_persistence_scanner;
    private $snippet_code_auditor;

    public function __construct() {
        $this->table_scanner = new TableScanner();
        $this->option_scanner = new OptionScanner();
        $this->rogue_admin_detector = new RogueAdminAnomalyDetector();
        $this->cron_persistence_scanner = new CronPersistenceScanner();
        $this->snippet_code_auditor = new SnippetCodeAuditor();
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

        // 3. Audit Rogue MySQL Triggers (Ultimate Database-Level Persistence)
        if (!empty($scan_id)) {
            set_transient("wcpscan_active_scan_file_{$scan_id}", 'MySQL Database: Auditing engine triggers for database-level persistence...', 120);
        }
        $trigger_findings = $this->scan_rogue_triggers((string) $scan_id);
        $findings = array_merge($findings, $trigger_findings);

        // 4. Audit WP-Cron & Scheduled Hook Persistence
        if (!empty($scan_id)) {
            set_transient("wcpscan_active_scan_file_{$scan_id}", 'WP-Cron Sentinel: Auditing scheduled hooks & persistence backdoors...', 120);
        }
        try {
            $cron_findings = $this->cron_persistence_scanner->scan((string) $scan_id);
            $findings = array_merge($findings, $cron_findings);
        } catch (\Throwable $e) {}

        // 5. Audit Database-Stored Code Snippets & Custom Headers/Footers
        if (!empty($scan_id)) {
            set_transient("wcpscan_active_scan_file_{$scan_id}", 'Database Snippet Auditor: Inspecting Code Snippets & header/footer scripts...', 120);
        }
        try {
            $snippet_findings = $this->snippet_code_auditor->scan((string) $scan_id);
            $findings = array_merge($findings, $snippet_findings);
        } catch (\Throwable $e) {}

        // 6. Discover all tables and calculate grand total row estimate upfront
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

    /**
     * Audit MySQL INFORMATION_SCHEMA.TRIGGERS for rogue database-level triggers.
     *
     * Standard WordPress core, WooCommerce, and orthodox plugins NEVER create database
     * triggers. Attackers use MySQL triggers (AFTER UPDATE, BEFORE INSERT) on authentication
     * and options tables to automatically resurrect backdoors and rogue admin users even after
     * all PHP files are completely cleaned.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan_rogue_triggers(string $scan_id): array {
        global $wpdb;
        $findings = [];

        try {
            // Query in-memory INFORMATION_SCHEMA metadata (<2ms execution, 0 table locks)
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $triggers = $wpdb->get_results(
                "SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_STATEMENT 
                 FROM information_schema.TRIGGERS 
                 WHERE TRIGGER_SCHEMA = DATABASE()",
                OBJECT
            );

            if (empty($triggers) || !is_array($triggers)) {
                return $findings;
            }

            $base_prefix = !empty($wpdb->base_prefix) ? $wpdb->base_prefix : $wpdb->prefix;
            $quoted_base = preg_quote($base_prefix, '/');

            foreach ($triggers as $trigger) {
                $trigger_name = sanitize_text_field($trigger->TRIGGER_NAME ?? 'unknown_trigger');
                $target_table = sanitize_text_field($trigger->EVENT_OBJECT_TABLE ?? 'unknown_table');
                $event_manip  = sanitize_text_field($trigger->EVENT_MANIPULATION ?? '');
                $action_stmt  = (string) ($trigger->ACTION_STATEMENT ?? '');

                // Exclude verified non-malicious third-party integration schemas (e.g. CiviCRM)
                if (stripos($target_table, 'civicrm_') === 0) {
                    continue;
                }

                // Check 1: Multisite & custom prefix aware matching for core authentication and configuration tables
                $is_core_auth_or_config = (bool) preg_match(
                    '/^' . $quoted_base . '(?:\d+_)?(?:users|usermeta|options|posts)$/i',
                    $target_table
                );

                if ($is_core_auth_or_config) {
                    $preview_statement = substr(trim($action_stmt), 0, 150);
                    $findings[] = new Finding([
                        'engine'      => 'database-persistence',
                        'type'        => 'rogue_database_trigger',
                        'severity'    => 'critical',
                        'confidence'  => 98,
                        'file_path'   => "MySQL Trigger: {$trigger_name} on `{$target_table}`",
                        'description' => "Rogue MySQL trigger detected on core WordPress table `{$target_table}` ({$event_manip}). Standard WordPress never creates database triggers; attackers use triggers to automatically resurrect admin users or backdoors at the database engine level.",
                        'evidence'    => "Trigger: {$trigger_name} | Event: {$event_manip} on `{$target_table}` | Statement: {$preview_statement}",
                    ]);
                    continue;
                }

                // Check 2: Non-core table triggers with suspicious database modification, exfiltration, or hex primitives
                $has_suspicious_payload = (bool) preg_match(
                    '/\b(INSERT\s+INTO|UPDATE\s+|DELETE\s+FROM|INTO\s+OUTFILE|LOAD_FILE)\b|0x[0-9a-fA-F]{4,}/i',
                    $action_stmt
                );

                if ($has_suspicious_payload) {
                    $preview_statement = substr(trim($action_stmt), 0, 150);
                    $findings[] = new Finding([
                        'engine'      => 'database-persistence',
                        'type'        => 'suspicious_database_trigger',
                        'severity'    => 'high',
                        'confidence'  => 85,
                        'file_path'   => "MySQL Trigger: {$trigger_name} on `{$target_table}`",
                        'description' => "Suspicious MySQL trigger detected on table `{$target_table}` executing dynamic data modification or file primitives. Verify whether this trigger was authorized.",
                        'evidence'    => "Trigger: {$trigger_name} | Event: {$event_manip} on `{$target_table}` | Statement: {$preview_statement}",
                    ]);
                }
            }
        } catch (\Throwable $e) {
            // Guard against hosting environments where INFORMATION_SCHEMA.TRIGGERS access is restricted
        }

        return $findings;
    }

    public function get_table_scanner() {
        return $this->table_scanner;
    }

    public function get_option_scanner() {
        return $this->option_scanner;
    }
}
