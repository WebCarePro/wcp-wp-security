<?php
namespace WcpScanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

class FindingRepository {

    /**
     * Persist findings into database with correlation processing.
     *
     * @param int $scan_id
     * @param Finding[] $findings
     * @return int Number of findings saved
     */
    public function save_findings($scan_id, $findings) {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_scan_issues';
        $saved = 0;

        $correlation_engine = new CorrelationEngine();
        $processed_findings = $correlation_engine->correlate($findings);

        foreach ($processed_findings as $finding) {
            $f = is_array($finding) ? $finding : $finding->to_array();

            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->insert($table, [
                'scan_id'      => $scan_id,
                'engine'       => sanitize_text_field($f['engine'] ?? 'general'),
                'type'         => sanitize_text_field($f['type'] ?? 'unknown'),
                'severity'     => sanitize_text_field($f['severity'] ?? 'medium'),
                'confidence'   => (int) ($f['confidence'] ?? 100),
                'file_path'    => sanitize_text_field($f['file_path'] ?? ''),
                'line_number'  => isset($f['line_number']) ? (int) $f['line_number'] : null,
                'code_snippet' => $f['code_snippet'] ?? null,
                'evidence'     => $f['evidence'] ?? null,
                'description'  => sanitize_textarea_field($f['description'] ?? ''),
                'status'       => 'open',
                'created_at'   => current_time('mysql'),
                'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
            ]);
            $saved++;
        }

        return $saved;
    }

    /**
     * Get all findings for a scan with risk scoring summary.
     *
     * @param int $scan_id
     * @return array ['findings' => array, 'summary' => array]
     */
    public function get_scan_findings($scan_id) {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_scan_issues';

        $sql = "SELECT * FROM `{$table}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($sql, $scan_id),
            ARRAY_A
        );

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($results);

        return [
            'findings' => $results,
            'summary'  => $summary
        ];
    }
}
