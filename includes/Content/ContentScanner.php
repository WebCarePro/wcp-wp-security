<?php
namespace WCP\Scanner\Content;

use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Resource\ResourceMonitor;

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
        global $wpdb;
        $findings = [];
        $monitor = new ResourceMonitor(80, 20);

        // 1. Scan Posts & Pages
        $posts_table = $wpdb->prefix . 'posts';
        $last_id = 0;

        while (true) {
            if ($monitor->is_nearing_limits()) {
                break;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $posts = $wpdb->get_results($wpdb->prepare(
                "SELECT ID, post_title, post_content, post_type, post_status 
                 FROM `{$posts_table}` 
                 WHERE ID > %d AND post_status IN ('publish', 'future', 'draft', 'private')
                 ORDER BY ID ASC 
                 LIMIT %d",
                $last_id,
                $batch_size
            ), ARRAY_A);

            if (empty($posts)) {
                break;
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

        // 2. Scan Approved Comments
        $comments_table = $wpdb->prefix . 'comments';
        $last_comment_id = 0;

        while (true) {
            if ($monitor->is_nearing_limits()) {
                break;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $comments = $wpdb->get_results($wpdb->prepare(
                "SELECT comment_ID, comment_author_url, comment_content 
                 FROM `{$comments_table}` 
                 WHERE comment_ID > %d AND comment_approved = '1'
                 ORDER BY comment_ID ASC 
                 LIMIT %d",
                $last_comment_id,
                $batch_size
            ), ARRAY_A);

            if (empty($comments)) {
                break;
            }

            foreach ($comments as $comment) {
                $last_comment_id = (int) $comment['comment_ID'];

                $comment_text = $comment['comment_author_url'] . "\n" . $comment['comment_content'];

                $spam_hits = $this->spam_detector->analyze($comment_text);
                foreach ($spam_hits as $hit) {
                    $findings[] = new Finding([
                        'engine'      => 'content-comments',
                        'type'        => 'comment_' . $hit['type'],
                        'severity'    => 'medium',
                        'confidence'  => $hit['confidence'],
                        'file_path'   => "comment:{$comment['comment_ID']}",
                        'description' => "Spam detected in approved comment: " . $hit['desc'],
                        'evidence'    => $hit['evidence']
                    ]);
                }
            }

            if (count($comments) < $batch_size) {
                break;
            }
        }

        return $findings;
    }
}
