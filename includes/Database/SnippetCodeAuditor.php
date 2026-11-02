<?php
namespace WcpScanner\Database;

use WcpScanner\Findings\Finding;
use WcpScanner\Malware\WebshellDetector;
use WcpScanner\Malware\JavaScriptSecurityScanner;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Database Fileless PHP & JS Code Snippet Auditor.
 *
 * Audits code snippets stored in MySQL tables (wp_snippets, wp_posts wpcode/elementor_snippet,
 * and wp_options headers/footers) using AST/tokenizer WebshellDetector and
 * in-memory JavaScriptSecurityScanner.
 */
class SnippetCodeAuditor {

    private $webshell_detector;
    private $js_scanner;

    public function __construct() {
        $this->webshell_detector = new WebshellDetector();
        $this->js_scanner = new JavaScriptSecurityScanner();
    }

    /**
     * Scan all known database code storage locations.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan(string $scan_id): array {
        $findings = [];

        // 1. Audit Code Snippets table (wp_snippets)
        $snippets_findings = $this->audit_code_snippets_table($scan_id);
        $findings = array_merge($findings, $snippets_findings);

        // 2. Audit Custom Code Posts (wpcode, elementor_snippet, custom_css, wbcr-snippets, custom_css_js)
        $posts_findings = $this->audit_code_posts($scan_id);
        $findings = array_merge($findings, $posts_findings);

        // 3. Audit Header/Footer & Snippet Options in wp_options
        $options_findings = $this->audit_snippet_options($scan_id);
        $findings = array_merge($findings, $options_findings);

        return $findings;
    }

    /**
     * Audit wp_snippets table (Code Snippets plugin).
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_code_snippets_table(string $scan_id): array {
        global $wpdb;
        $findings = [];
        $snippets_table = $wpdb->prefix . 'snippets';

        try {
            // Check if table exists (<1ms)
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $snippets_table));
            if ($table_exists !== $snippets_table) {
                return $findings;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $sql = "SELECT id, name, code, active FROM `{$snippets_table}` WHERE active = 1 LIMIT 500";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $rows = $wpdb->get_results($sql, OBJECT);

            if (empty($rows) || !is_array($rows)) {
                return $findings;
            }

            foreach ($rows as $row) {
                $id = (int) ($row->id ?? 0);
                $name = sanitize_text_field($row->name ?? "Snippet #{$id}");
                $code = (string) ($row->code ?? '');

                if (empty(trim($code))) {
                    continue;
                }

                $context_id = "{$snippets_table}:#{$id} ({$name})";
                $snippet_findings = $this->audit_code_string($code, $context_id, $scan_id, 'php');
                $findings = array_merge($findings, $snippet_findings);
            }
        } catch (\Throwable $e) {
            // Fails gracefully on schema differences
        }

        return $findings;
    }

    /**
     * Audit CPT rows storing code snippets (wpcode, elementor_snippet, wbcr-snippets, custom_css_js).
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_code_posts(string $scan_id): array {
        global $wpdb;
        $findings = [];

        try {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $rows = $wpdb->get_results(
                "SELECT ID, post_title, post_content, post_type 
                 FROM `{$wpdb->posts}` 
                 WHERE post_type IN ('wpcode', 'elementor_snippet', 'wbcr-snippets', 'custom_css_js', 'custom_css') 
                   AND post_status = 'publish' 
                 LIMIT 250",
                OBJECT
            );

            if (empty($rows) || !is_array($rows)) {
                return $findings;
            }

            foreach ($rows as $row) {
                $id = (int) ($row->ID ?? 0);
                $title = sanitize_text_field($row->post_title ?? "Post #{$id}");
                $content = (string) ($row->post_content ?? '');
                $type = (string) ($row->post_type ?? '');

                if (empty(trim($content))) {
                    continue;
                }

                // Core custom_css only renders in <style> tags. Only scan if it breaks out of CSS with script/PHP
                if ($type === 'custom_css') {
                    if (!preg_match('/(?:<\/(?:style|css)>|<script|<\?(?:php|=))/i', $content)) {
                        continue;
                    }
                }

                $context_id = "{$wpdb->posts}:#{$id} [{$type}] ({$title})";
                $snippet_findings = $this->audit_code_string($content, $context_id, $scan_id, 'mixed');
                $findings = array_merge($findings, $snippet_findings);
            }
        } catch (\Throwable $e) {
            // Fails gracefully on custom schemas
        }

        return $findings;
    }

    /**
     * Audit custom code and script injection options in wp_options.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_snippet_options(string $scan_id): array {
        global $wpdb;
        $findings = [];
        $options_table = $wpdb->prefix . 'options';

        $target_options = [
            'ihaf_insert_header',
            'ihaf_insert_footer',
            'wpcode_snippets',
            'wpcode_custom_snippets',
            'header_footer_scripts',
            'header_scripts',
            'footer_scripts',
            'et_divi', // Divi Builder integration code
            'wpex_custom_css',
        ];

        foreach ($target_options as $opt_name) {
            $raw_val = get_option($opt_name);
            if (empty($raw_val)) {
                continue;
            }

            // Handle serialized option structures (e.g. Divi theme options or wpcode arrays)
            if (is_array($raw_val)) {
                $this->recurse_array_code($raw_val, "{$options_table}:{$opt_name}", $scan_id, $findings);
            } elseif (is_string($raw_val) && !empty(trim($raw_val))) {
                $context_id = "{$options_table}:{$opt_name}";
                $snippet_findings = $this->audit_code_string($raw_val, $context_id, $scan_id, 'mixed');
                $findings = array_merge($findings, $snippet_findings);
            }
        }

        return $findings;
    }

    /**
     * Recursively scan nested arrays of options (such as Divi integration arrays).
     *
     * @param array $arr
     * @param string $prefix
     * @param string $scan_id
     * @param array $findings
     */
    private function recurse_array_code(array $arr, string $prefix, string $scan_id, array &$findings): void {
        foreach ($arr as $k => $v) {
            $curr_key = "{$prefix}[{$k}]";
            if (is_array($v)) {
                $this->recurse_array_code($v, $curr_key, $scan_id, $findings);
            } elseif (is_string($v) && strlen($v) > 20) {
                // Only scan strings that could conceivably contain scripts or PHP code
                if (preg_match('/(?:<script|<\?(?:php|=)|\beval\b|\bdocument\.write\b|function\s*\(|navigator\.clipboard)/i', $v)) {
                    $item_findings = $this->audit_code_string($v, $curr_key, $scan_id, 'mixed');
                    $findings = array_merge($findings, $item_findings);
                }
            }
        }
    }

    /**
     * Core Code Auditor: Normalizes code headers and executes WebshellDetector and JavaScriptSecurityScanner in memory.
     *
     * @param string $code
     * @param string $context_id
     * @param string $scan_id
     * @param string $mode 'php'|'js'|'mixed'
     * @return Finding[]
     */
    public function audit_code_string(string $code, string $context_id, string $scan_id, string $mode = 'mixed'): array {
        $findings = [];
        $unslashed_code = wp_unslash($code);

        // 1. PHP Code Inspection
        if ($mode === 'php' || $mode === 'mixed') {
            // Normalize header: Code Snippets & WPCode strip the opening <?php tag!
            // PHP's tokenizer treats code without <?php as raw T_INLINE_HTML, evading AST analysis.
            $php_code = $unslashed_code;
            if (!preg_match('/^\s*<\?(?:php|=)/i', $php_code)) {
                $php_code = "<?php\n" . $php_code;
            }

            $virtual_file = "/database_snippet/{$context_id}.php";
            $res = $this->webshell_detector->scan($virtual_file, $php_code, $scan_id);
            if ($res !== null) {
                $findings[] = new Finding([
                    'engine'      => 'database-snippets',
                    'type'        => 'database_stored_webshell',
                    'severity'    => 'critical',
                    'confidence'  => $res->confidence ?? 99,
                    'file_path'   => $context_id,
                    'description' => "Database-stored executable PHP backdoor/webshell detected in code snippet. Attackers use snippet plugins for fileless persistence.",
                    'evidence'    => $res->evidence ?? $res->description,
                    'code_snippet'=> substr($unslashed_code, 0, 400),
                ]);
            }
        }

        // 2. JavaScript Code Inspection
        if ($mode === 'js' || $mode === 'mixed') {
            // Extract raw JS if wrapped in <script> tags, or evaluate raw JS
            $js_to_scan = $unslashed_code;
            if (preg_match_all('/<script\b[^>]*>([\s\S]*?)<\/script>/i', $unslashed_code, $matches)) {
                $js_to_scan = implode("\n;\n", $matches[1]);
            }

            if (!empty(trim($js_to_scan))) {
                $virtual_path = "/database_snippet/{$context_id}.js";
                $js_findings = $this->js_scanner->scan_content($js_to_scan, $virtual_path, $scan_id);
                foreach ($js_findings as $jf) {
                    $findings[] = new Finding([
                        'engine'      => 'database-snippets',
                        'type'        => 'database_stored_js_trojan',
                        'severity'    => $jf->severity ?? 'critical',
                        'confidence'  => $jf->confidence ?? 95,
                        'file_path'   => $context_id,
                        'description' => "Database-stored malicious client-side JavaScript detected in snippet (Magecart, ClickFix, or malvertising redirect).",
                        'evidence'    => $jf->evidence ?? $jf->description,
                        'code_snippet'=> substr($js_to_scan, 0, 400),
                    ]);
                }
            }
        }

        return $findings;
    }
}
