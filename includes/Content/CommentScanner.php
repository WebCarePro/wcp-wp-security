<?php
namespace WCP\Scanner\Content;

use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Resource\ResourceMonitor;

if (!defined('ABSPATH')) {
    exit;
}

class CommentScanner {

    private $url_scanner;
    private $spam_detector;

    public function __construct() {
        $this->url_scanner = new URLScanner();
        $this->spam_detector = new SpamDetector();
    }

    /**
     * Scan the wp_comments table for malicious payloads and spam.
     *
     * @param string $scan_id
     * @param int $batch_size
     * @return Finding[]
     */
    public function scan($scan_id, $batch_size = 300) {
        global $wpdb;
        $findings = [];
        $monitor = new ResourceMonitor(80, 20);

        $comments_table = $wpdb->prefix . 'comments';
        $last_id = 0;

        while (true) {
            if ($monitor->is_nearing_limits()) {
                break;
            }

            // Fetch approved or pending comments (ignore trash/spam)
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $comments = $wpdb->get_results($wpdb->prepare(
                "SELECT comment_ID, comment_author, comment_author_url, comment_content 
                 FROM `{$comments_table}` 
                 WHERE comment_ID > %d AND comment_approved IN ('0', '1')
                 ORDER BY comment_ID ASC 
                 LIMIT %d",
                $last_id,
                $batch_size
            ), ARRAY_A);

            if (empty($comments)) {
                break;
            }

            foreach ($comments as $comment) {
                $last_id = (int) $comment['comment_ID'];
                
                // 1. Scan for XSS Payloads in comments
                // Comments shouldn't contain raw script tags or event handlers
                if (preg_match('/(<script|onmouseover=|onload=|onerror=)/i', $comment['comment_content'])) {
                    $findings[] = new Finding([
                        'engine'      => 'content-comments',
                        'type'        => 'xss_payload_in_comment',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => "comment:{$comment['comment_ID']} by {$comment['comment_author']}",
                        'description' => "Cross-Site Scripting (XSS) payload detected in comment content.",
                        'evidence'    => substr($comment['comment_content'], 0, 150)
                    ]);
                }

                // 2. Scan URLs in content and author URL
                $text_to_scan = $comment['comment_content'] . "\n" . $comment['comment_author_url'];
                
                $url_hits = $this->url_scanner->scan_urls($text_to_scan);
                foreach ($url_hits as $hit) {
                    $findings[] = new Finding([
                        'engine'      => 'content-comments',
                        'type'        => $hit['type'],
                        'severity'    => $hit['severity'],
                        'confidence'  => $hit['confidence'],
                        'file_path'   => "comment:{$comment['comment_ID']} by {$comment['comment_author']}",
                        'description' => "Malicious or blacklisted URL found in comment.",
                        'evidence'    => $hit['evidence']
                    ]);
                }

                // 3. Scan for SEO Spam (Pharma, Casino, etc.)
                $spam_hits = $this->spam_detector->analyze($comment['comment_content']);
                foreach ($spam_hits as $hit) {
                    $findings[] = new Finding([
                        'engine'      => 'content-comments',
                        'type'        => $hit['type'],
                        'severity'    => $hit['severity'],
                        'confidence'  => $hit['confidence'],
                        'file_path'   => "comment:{$comment['comment_ID']} by {$comment['comment_author']}",
                        'description' => $hit['desc'],
                        'evidence'    => $hit['evidence']
                    ]);
                }
            }
        }

        return $findings;
    }
}
