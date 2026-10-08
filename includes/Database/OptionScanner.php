<?php
namespace WCP\Scanner\Database;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class OptionScanner {

    private $serialized_scanner;

    public function __construct() {
        $this->serialized_scanner = new SerializedDataScanner();
    }

    /**
     * Scan wp_options table for suspicious options and configuration anomalies.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan_options($scan_id) {
        global $wpdb;
        $findings = [];
        $options_table = $wpdb->prefix . 'options';

        // 1. Check home & siteurl options for suspicious external redirection
        $siteurl = get_option('siteurl');
        $home = get_option('home');

        if (!empty($siteurl) && !empty($home)) {
            $parsed_siteurl = wp_parse_url($siteurl, PHP_URL_HOST);
            $parsed_home = wp_parse_url($home, PHP_URL_HOST);
            if ($parsed_siteurl && $parsed_home && strtolower($parsed_siteurl) !== strtolower($parsed_home)) {
                $findings[] = new Finding([
                    'engine'      => 'database-options',
                    'type'        => 'siteurl_home_mismatch',
                    'severity'    => 'medium',
                    'confidence'  => 85,
                    'file_path'   => $options_table . ':siteurl/home',
                    'description' => "siteurl ($siteurl) does not match home ($home) host. Possible domain hijacking or redirection.",
                    'evidence'    => "siteurl host: $parsed_siteurl, home host: $parsed_home"
                ]);
            }
        }

        // 2. Check for oversized autoloaded options (denial of service / hidden payloads)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $large_options = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS value_len 
             FROM `{$options_table}` 
             WHERE autoload = 'yes' OR autoload = 'on' 
             HAVING value_len > 500000 
             ORDER BY value_len DESC LIMIT 10"
        );

        if (!empty($large_options)) {
            foreach ($large_options as $opt) {
                $kb = round($opt->value_len / 1024, 2);
                $findings[] = new Finding([
                    'engine'      => 'database-options',
                    'type'        => 'oversized_autoload_option',
                    'severity'    => 'medium',
                    'confidence'  => 95,
                    'file_path'   => $options_table . ':' . $opt->option_name,
                    'description' => "Autoloaded option '{$opt->option_name}' is unusually large ({$kb} KB). May cause severe performance degradation or conceal payloads.",
                    'evidence'    => "Option: {$opt->option_name}, Size: {$kb} KB"
                ]);
            }
        }

        // 3. Inspect cron option for suspicious hooks or callbacks
        $cron_data = get_option('cron');
        if (is_array($cron_data)) {
            foreach ($cron_data as $timestamp => $hooks) {
                if (!is_array($hooks)) continue;
                foreach ($hooks as $hook => $details) {
                    // Check for eval or base64 patterns in hook name
                    if (preg_match('/(eval|base64|assert|passthru|shell_exec|system)/i', $hook)) {
                        $findings[] = new Finding([
                            'engine'      => 'database-options',
                            'type'        => 'suspicious_cron_hook',
                            'severity'    => 'critical',
                            'confidence'  => 99,
                            'file_path'   => $options_table . ':cron',
                            'description' => "Suspicious cron hook detected: '{$hook}'. Cron tasks are a common malware persistence vector.",
                            'evidence'    => "Hook: $hook, Timestamp: $timestamp"
                        ]);
                    }
                }
            }
        }

        // 4. Inspect active_plugins option for phantom or hidden plugins
        $active_plugins = get_option('active_plugins');
        if (is_array($active_plugins)) {
            foreach ($active_plugins as $plugin_rel_path) {
                $full_path = WP_PLUGIN_DIR . '/' . $plugin_rel_path;
                if (!file_exists($full_path)) {
                    $findings[] = new Finding([
                        'engine'      => 'database-options',
                        'type'        => 'phantom_active_plugin',
                        'severity'    => 'medium',
                        'confidence'  => 90,
                        'file_path'   => $options_table . ':active_plugins',
                        'description' => "Active plugin entry references a non-existent file: '{$plugin_rel_path}'.",
                        'evidence'    => "Missing file: $full_path"
                    ]);
                }
            }
        }

        return $findings;
    }
}
