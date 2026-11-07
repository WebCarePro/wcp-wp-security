<?php
namespace WcpScanner\Database;

use WcpScanner\Findings\Finding;

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

        // 1. Check home & siteurl options for suspicious external redirection & baseline integrity
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

        if (class_exists('\\WcpScanner\\Firewall\\RedirectCanaryEngine')) {
            $baseline_check = \WcpScanner\Firewall\RedirectCanaryEngine::verify_database_core_urls();
            if (!empty($baseline_check) && empty($baseline_check['clean']) && !empty($baseline_check['message'])) {
                $findings[] = new Finding([
                    'engine'      => 'database-options',
                    'type'        => 'database_url_hijacking',
                    'severity'    => 'critical',
                    'confidence'  => 100,
                    'file_path'   => $options_table . ':siteurl/home',
                    'description' => sprintf(
                        /* translators: %s: details */
                        __('Core WordPress database URL hijacking detected! %s', 'wcp-security-scanner'),
                        $baseline_check['message']
                    ),
                    'evidence'    => "siteurl: {$siteurl} | home: {$home}",
                ]);
            }
        }

        // 1b. In-Memory Object Cache (Redis / Memcached / APCu) RAM vs Disk Differential Audit
        if (class_exists('\\WcpScanner\\Integrity\\ObjectCacheIntegritySentinel')) {
            $cache_audit = \WcpScanner\Integrity\ObjectCacheIntegritySentinel::audit_ram_vs_disk();
            if (!empty($cache_audit['critical_issues'])) {
                foreach ($cache_audit['critical_issues'] as $crit) {
                    $findings[] = new Finding([
                        'engine'      => 'database-options',
                        'type'        => 'object_cache_poisoning_detected',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => 'ram:object-cache:' . $crit['option_name'],
                        'description' => sprintf(
                            /* translators: 1: option name, 2: threat forensics */
                            __('In-Memory Object Cache Poisoning on "%1$s": %2$s', 'wcp-security-scanner'),
                            $crit['option_name'],
                            $crit['forensics']
                        ),
                        'evidence'    => "Key: {$crit['option_name']} | DB Truth: {$crit['db_value']} | Live RAM: {$crit['ram_value']}",
                    ]);
                }
            }
            if (!empty($cache_audit['suspicious_sinks'])) {
                foreach ($cache_audit['suspicious_sinks'] as $sink) {
                    $findings[] = new Finding([
                        'engine'      => 'database-options',
                        'type'        => 'object_cache_execution_sink',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => 'ram:object-cache:' . $sink['option_name'],
                        'description' => sprintf(
                            /* translators: 1: option name, 2: sink message */
                            __('Fileless Execution Sink in Object Cache "%1$s": %2$s', 'wcp-security-scanner'),
                            $sink['option_name'],
                            $sink['message']
                        ),
                        'evidence'    => 'Snippet: ' . $sink['snippet'],
                        'code_snippet'=> substr($sink['snippet'], 0, 150),
                    ]);
                }
            }
        }

        // 2. Check for oversized autoloaded options (denial of service / hidden payloads)
        $large_options_sql = "SELECT option_name, LENGTH(option_value) AS value_len FROM `{$options_table}` WHERE autoload = 'yes' OR autoload = 'on' HAVING value_len > 500000 ORDER BY value_len DESC LIMIT 10";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $large_options = $wpdb->get_results($large_options_sql);

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

        // 5. Inspect widget and script injection options for cloaked redirects, meta-refresh, and Web3 loaders
        $target_option_patterns = [
            'widget_text',
            'widget_custom_html',
            'widget_block',
            'sidebars_widgets',
            'insert_headers_and_footers',
            'insert_headers_and_footers_scripts',
            'wp_head_scripts',
            'wp_footer_scripts',
            'header_scripts',
            'footer_scripts',
            'custom_css_post_id',
            'elementor_custom_snippets',
            'genesis_header_scripts',
            'genesis_footer_scripts',
            'wp_scripts',
            'custom_js',
        ];

        $escaped_options = "'" . implode("', '", array_map('esc_sql', $target_option_patterns)) . "'";
        $script_options_sql = "SELECT option_name, option_value FROM `{$options_table}` WHERE option_name IN ({$escaped_options}) OR option_name LIKE 'widget_%' LIMIT 60";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $script_options = $wpdb->get_results($script_options_sql);

        if (!empty($script_options)) {
            $html_analyzer = new \WcpScanner\Content\HTMLAnalyzer();

            foreach ($script_options as $s_opt) {
                $raw_val = maybe_unserialize($s_opt->option_value);
                $opt_text = stripslashes(is_array($raw_val) || is_object($raw_val) ? wp_json_encode($raw_val, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : (string) $raw_val);

                if (empty($opt_text) || strlen($opt_text) < 15) {
                    continue;
                }

                // Check HTML analyzer detections for meta refresh, base href, and inline redirects
                $hits = $html_analyzer->detect_hidden_elements($opt_text);
                foreach ($hits as $hit) {
                    if (in_array($hit['type'], ['content_meta_refresh_redirect', 'content_base_href_hijack', 'content_dom_redirect', 'content_malicious_inline_js', 'hidden_iframe', 'remote_script_injection'], true)) {
                        $findings[] = new Finding([
                            'engine'      => 'database-options',
                            'type'        => 'option_script_redirect_injection',
                            'severity'    => 'critical',
                            'confidence'  => 98,
                            'file_path'   => $options_table . ':' . $s_opt->option_name,
                            'description' => sprintf(
                                /* translators: 1: option name, 2: threat description */
                                __('Injected redirect or script exploit detected in database option "%1$s": %2$s', 'wcp-security-scanner'),
                                $s_opt->option_name,
                                $hit['desc']
                            ),
                            'evidence'    => 'Option: ' . $s_opt->option_name . ' | Snippet: ' . $hit['snippet'],
                            'code_snippet'=> substr($hit['snippet'], 0, 150),
                        ]);
                    }
                }
            }
        }

        return $findings;
    }
}
