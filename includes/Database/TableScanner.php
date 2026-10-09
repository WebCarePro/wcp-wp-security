<?php
namespace WCP\Scanner\Database;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class TableScanner {

    private $serialized_scanner;

    // High risk injection patterns for database text columns
    private $patterns = [
        'script_tag_injection' => [
            'regex'      => '/<script[\s\S]*?>[\s\S]*?<\/script>/i',
            'severity'   => 'high',
            'confidence' => 85,
            'desc'       => 'Injected script element tag detected in database content.'
        ],
        'iframe_injection' => [
            'regex'      => '/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/i',
            'severity'   => 'high',
            'confidence' => 85,
            'desc'       => 'Injected iframe element tag detected in database content.'
        ],
        'malicious_event_handler' => [
            'regex'      => '/\b(onload|onerror|onclick|onmouseover)\s*=\s*["\']?\s*(javascript:|eval|window\.location|document\.cookie)/i',
            'severity'   => 'high',
            'confidence' => 90,
            'desc'       => 'Suspicious JavaScript event handler attribute detected in database content.'
        ],
        'base64_eval_payload' => [
            'regex'      => '/(eval\s*\(\s*base64_decode|assert\s*\(\s*base64_decode|\bdocument\.write\s*\(\s*unescape)/i',
            'severity'   => 'critical',
            'confidence' => 95,
            'desc'       => 'Encoded evaluation payload (eval/base64/unescape) detected in database column.'
        ],
        'hidden_seo_spam' => [
            'regex'      => '/style\s*=\s*["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute\s*;\s*left\s*:\s*-[0-9]{3,}px)[^"\']*["\']\s*>[^<]*<a\s+href/i',
            'severity'   => 'medium',
            'confidence' => 80,
            'desc'       => 'Hidden anchor link / hidden CSS styling detected (SEO link injection spam).'
        ],
    ];

    public function __construct() {
        $this->serialized_scanner = new SerializedDataScanner();
    }

    /**
     * Get all tables in the current WordPress database.
     *
     * @return array List of table names
     */
    public function get_tables() {
        global $wpdb;
        $tables = $wpdb->get_col("SHOW TABLES");
        return is_array($tables) ? $tables : [];
    }

    /**
     * Get all text-like columns for a table and identify primary key.
     *
     * @param string $table
     * @return array ['columns' => [...], 'primary_key' => string|null]
     */
    public function get_table_metadata($table) {
        global $wpdb;
        $columns = [];
        $primary_key = null;

        // Safely validate table name matches word characters only
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $table)) {
            return ['columns' => [], 'primary_key' => null];
        }

        $cols_info = $wpdb->get_results("SHOW COLUMNS FROM `{$table}`");
        if (empty($cols_info)) {
            return ['columns' => [], 'primary_key' => null];
        }

        $text_types = ['varchar', 'text', 'tinytext', 'mediumtext', 'longtext', 'json'];

        foreach ($cols_info as $col) {
            $type = strtolower($col->Type);
            if ($col->Key === 'PRI' && $primary_key === null) {
                $primary_key = $col->Field;
            }

            foreach ($text_types as $text_type) {
                if (strpos($type, $text_type) !== false) {
                    $columns[] = $col->Field;
                    break;
                }
            }
        }

        return [
            'columns'     => $columns,
            'primary_key' => $primary_key
        ];
    }

    /**
     * Scan a batch of rows in a table.
     *
     * @param string $table
     * @param array $columns Text columns to scan
     * @param string|null $primary_key
     * @param int $last_id Keyset cursor or offset
     * @param int $batch_size
     * @param string $scan_id
     * @return array ['findings' => Finding[], 'rows_scanned' => int, 'next_cursor' => int|null]
     */
    public function scan_table_batch($table, $columns, $primary_key, $last_id = 0, $batch_size = 100, $scan_id = '') {
        global $wpdb;
        $findings = [];

        if (empty($columns) || !preg_match('/^[a-zA-Z0-9_]+$/', $table)) {
            return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
        }

        $select_cols = array_map(function($c) { return "`{$c}`"; }, $columns);
        if ($primary_key && !in_array("`{$primary_key}`", $select_cols)) {
            array_unshift($select_cols, "`{$primary_key}`");
        }
        $col_sql = implode(', ', $select_cols);

        // Keyset pagination when primary key exists, otherwise standard LIMIT/OFFSET
        if ($primary_key) {
            $sql = $wpdb->prepare(
                "SELECT {$col_sql} FROM `{$table}` WHERE `{$primary_key}` > %d ORDER BY `{$primary_key}` ASC LIMIT %d",
                $last_id,
                $batch_size
            );
        } else {
            $sql = $wpdb->prepare(
                "SELECT {$col_sql} FROM `{$table}` LIMIT %d OFFSET %d",
                $batch_size,
                $last_id
            );
        }

        $rows = $wpdb->get_results($sql, ARRAY_A);
        if (empty($rows)) {
            return ['findings' => [], 'rows_scanned' => 0, 'next_cursor' => null];
        }

        $rows_scanned = count($rows);
        $next_cursor = null;

        foreach ($rows as $row) {
            $row_id = $primary_key && isset($row[$primary_key]) ? $row[$primary_key] : null;
            if ($primary_key && $row_id !== null) {
                $next_cursor = (int) $row_id;
            }

            // Skip cached transients in options tables (e.g. RSS feeds from wordpress.org dashboard widgets)
            $is_options_table = (strpos($table, 'options') !== false);
            if ($is_options_table && isset($row['option_name'])) {
                $opt_name = strtolower($row['option_name']);
                if (strpos($opt_name, '_transient_') === 0 ||
                    strpos($opt_name, '_site_transient_') === 0 ||
                    strpos($opt_name, 'rss_') === 0 ||
                    strpos($opt_name, 'feed_') === 0 ||
                    strpos($opt_name, 'cache_') === 0) {
                    continue; // Skip transient/cache entries
                }
            }

            foreach ($columns as $column) {
                if (!isset($row[$column]) || empty($row[$column])) {
                    continue;
                }

                $raw_val = $row[$column];
                $strings_to_check = [];

                if (SerializedDataScanner::is_serialized($raw_val)) {
                    $strings_to_check = $this->serialized_scanner->extract_strings_safely($raw_val);
                } else {
                    $strings_to_check = [$raw_val];
                }

                foreach ($strings_to_check as $str) {
                    if (strlen($str) < 10) continue;

                    foreach ($this->patterns as $rule_key => $rule) {
                        if (preg_match($rule['regex'], $str, $matches)) {
                            $snippet = substr($matches[0], 0, 150);

                            // Whitelist check: Legitimate media embeds (YouTube, Vimeo, Google Maps, WordPress.org)
                            if ($rule_key === 'iframe_injection') {
                                $is_trusted_embed = preg_match('/src=["\']https?:\/\/(www\.)?(youtube\.com|youtube-nocookie\.com|vimeo\.com|player\.vimeo\.com|wordpress\.org|maps\.google\.com|google\.com\/maps|spotify\.com|soundcloud\.com)/i', $matches[0]);
                                if ($is_trusted_embed && !preg_match('/(display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)/i', $matches[0])) {
                                    continue; // Legitimate media embed
                                }
                            }

                            // Whitelist check: Legitimate tracking scripts (GTM, GA, etc.)
                            if ($rule_key === 'script_tag_injection') {
                                if (preg_match('/(googletagmanager\.com|google-analytics\.com|clarity\.ms|connect\.facebook\.net)/i', $matches[0])) {
                                    continue; // Legitimate analytics/marketing script
                                }
                            }
                            $findings[] = new Finding([
                                'engine'      => 'database-table',
                                'type'        => $rule_key,
                                'severity'    => $rule['severity'],
                                'confidence'  => $rule['confidence'],
                                'file_path'   => "{$table}.{$column}" . ($row_id !== null ? " [ID: {$row_id}]" : ""),
                                'description' => $rule['desc'],
                                'evidence'    => "Snippet: " . esc_html($snippet),
                                'code_snippet'=> $snippet
                            ]);
                            break; // Avoid spamming multiple identical matches per string
                        }
                    }
                }
            }
        }

        // If no primary key was used, increment offset
        if (!$primary_key) {
            $next_cursor = $last_id + $rows_scanned;
        }

        return [
            'findings'     => $findings,
            'rows_scanned' => $rows_scanned,
            'next_cursor'  => $rows_scanned < $batch_size ? null : $next_cursor
        ];
    }
}
