<?php
namespace WcpScanner\Content;

use WcpScanner\Findings\Finding;
use WcpScanner\Resource\ResourceMonitor;

if (!defined('ABSPATH')) {
    exit;
}

class ContentScanner {

    private $html_analyzer;
    private $url_scanner;
    private $spam_detector;

    public function __construct() {
        $this->html_analyzer = new HTMLAnalyzer();
        $this->url_scanner = new URLScanner();
        $this->spam_detector = new SpamDetector();
    }

    /**
     * Run the content scanner across posts, pages, and comments in batches.
     *
     * @param string $scan_id
     * @param int $batch_size
     * @return Finding[]
     */
    public function scan($scan_id, $batch_size = 100) {
        $findings = $this->scan_posts_only($scan_id, $batch_size);
        $comment_findings = $this->scan_comments_only($scan_id, $batch_size);
        return array_merge($findings, $comment_findings);
    }

    /**
     * Scan posts and pages only.
     *
     * @param string $scan_id
     * @param int $batch_size
     * @return Finding[]
     */
    public function scan_posts_only($scan_id, $batch_size = 100) {
        global $wpdb;
        $findings = [];
        $monitor = new ResourceMonitor(80, 20);

        // 1. Scan Posts & Pages
        $posts_table = $wpdb->prefix . 'posts';
        $last_id = 0;
        $total_posts_scanned = 0;

        // Approximate count of publishable posts
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $approx_posts = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$posts_table}` WHERE post_status IN ('publish', 'future', 'draft', 'private')");

        while (true) {
            if ($monitor->is_nearing_limits()) {
                break;
            }

            $excluded_post_types = [
                'wp_navigation', 'wp_template', 'wp_template_part', 'wp_global_styles', 
                'nav_menu_item', 'revision', 'attachment', 'custom_css', 'oembed_cache',
                'custom-css-js', 'wplconsentlogs', 'action_log'
            ];
            $placeholders = implode("', '", array_map('esc_sql', $excluded_post_types));

            $sql = "SELECT ID, post_title, post_content, post_type, post_status FROM `{$posts_table}` WHERE ID > %d AND post_status IN ('publish', 'future', 'draft', 'private') AND post_type NOT IN ('{$placeholders}') ORDER BY ID ASC LIMIT %d";
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
            $posts = $wpdb->get_results($wpdb->prepare($sql, $last_id, $batch_size), ARRAY_A);

            if (empty($posts)) {
                break;
            }

            $total_posts_scanned += count($posts);

            if (!empty($scan_id)) {
                $status_msg = sprintf(
                    'Content & Posts: Inspecting Post #%d (%s%s posts audited)',
                    (int) ($posts[0]['ID'] ?? $last_id),
                    number_format($total_posts_scanned),
                    $approx_posts > 0 ? ' / ~' . number_format($approx_posts) : ''
                );
                set_transient("wcpscan_active_scan_file_{$scan_id}", $status_msg, 120);
            }

            foreach ($posts as $post) {
                $last_id = (int) $post['ID'];
                $full_text = $post['post_title'] . "\n" . $post['post_content'];

                // HTML cloak checks
                $html_hits = $this->html_analyzer->detect_hidden_elements($post['post_content']);
                foreach ($html_hits as $hit) {
                    $findings[] = new Finding([
                        'engine'      => 'content-spam',
                        'type'        => $hit['type'],
                        'severity'    => $hit['severity'],
                        'confidence'  => $hit['confidence'],
                        'file_path'   => "post:{$post['ID']} ({$post['post_type']}) - \"{$post['post_title']}\"",
                        'description' => $hit['desc'],
                        'evidence'    => $hit['snippet'],
                        'code_snippet'=> $hit['snippet']
                    ]);
                }

                // Spam pattern checks
                $spam_hits = $this->spam_detector->analyze($full_text);
                foreach ($spam_hits as $hit) {
                    $findings[] = new Finding([
                        'engine'      => 'content-spam',
                        'type'        => $hit['type'],
                        'severity'    => $hit['severity'],
                        'confidence'  => $hit['confidence'],
                        'file_path'   => "post:{$post['ID']} ({$post['post_type']}) - \"{$post['post_title']}\"",
                        'description' => $hit['desc'],
                        'evidence'    => $hit['evidence']
                    ]);
                }

                // URL checks
                $url_hits = $this->url_scanner->scan_urls($post['post_content']);
                foreach ($url_hits as $hit) {
                    $findings[] = new Finding([
                        'engine'      => 'content-url',
                        'type'        => $hit['type'],
                        'severity'    => $hit['severity'],
                        'confidence'  => $hit['confidence'],
                        'file_path'   => "post:{$post['ID']} ({$post['post_type']}) - \"{$post['post_title']}\"",
                        'description' => $hit['desc'],
                        'evidence'    => "URL: " . $hit['url']
                    ]);
                }
            }

            if (count($posts) < $batch_size) {
                break;
            }
        }

        return $findings;
    }

    /**
     * Scan user comments only.
     *
     * @param string $scan_id
     * @param int $batch_size
     * @return Finding[]
     */
    public function scan_comments_only($scan_id, $batch_size = 100) {
        $comment_scanner = new CommentScanner();
        return $comment_scanner->scan($scan_id, $batch_size);
    }
}
