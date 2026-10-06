<?php
namespace WCP\Scanner\Database;

use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Resource\ResourceMonitor;

if (!defined('ABSPATH')) {
    exit;
}

class DatabaseScanner {

    private $table_scanner;
    private $option_scanner;

    public function __construct() {
        $this->table_scanner = new TableScanner();
        $this->option_scanner = new OptionScanner();
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
        $monitor = new ResourceMonitor(80, 20);

        // 1. Audit wp_options first
        $option_findings = $this->option_scanner->scan_options($scan_id);
        $findings = array_merge($findings, $option_findings);

        // 2. Discover all tables
        $tables = $this->table_scanner->get_tables();

        foreach ($tables as $table) {
            if ($monitor->is_nearing_limits()) {
                break; // Stop early to prevent server strain
            }

            $meta = $this->table_scanner->get_table_metadata($table);
            if (empty($meta['columns'])) {
                continue;
            }

            $cursor = 0;
            while ($cursor !== null) {
                if ($monitor->is_nearing_limits()) {
                    break 2;
                }

                $batch_res = $this->table_scanner->scan_table_batch(
                    $table,
                    $meta['columns'],
                    $meta['primary_key'],
                    $cursor,
                    $batch_size,
                    $scan_id
                );

                if (!empty($batch_res['findings'])) {
                    $findings = array_merge($findings, $batch_res['findings']);
                }

                $cursor = $batch_res['next_cursor'];
            }
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
