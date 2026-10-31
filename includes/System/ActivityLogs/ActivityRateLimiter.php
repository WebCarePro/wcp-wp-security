<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Zero-SQL Cross-Worker Flood Rate Limiter for WCP Activity & Audit Logging.
 *
 * Implements:
 * 1. In-request in-memory deduplication (suppresses duplicate identical actions within one PHP run).
 * 2. Cross-worker synchronized rate limiting via file-backed bucket (.rate-buckets.json.php).
 * 3. Priority Protection: Critical security events (settings_updated, quarantine, firewall_ruleset_modified)
 *    are NEVER throttled.
 * 4. Automatic rollup summarization when high-frequency repetitive events exceed rate limits.
 */
class ActivityRateLimiter {

    const MAX_EVENTS_PER_WINDOW = 60; // Max 60 events per action per minute
    const WINDOW_SECONDS        = 60;

    /**
     * In-memory deduplication cache for the current PHP lifecycle.
     */
    private static array $in_memory_seen = [];

    /**
     * Actions that must NEVER be rate-limited or dropped.
     */
    private static array $priority_actions = [
        'settings_updated',
        'file_quarantined',
        'file_restored',
        'firewall_ruleset_modified',
        'user_login_failed_admin',
        'crash_detected',
        'tampering_detected',
        'corrupted_tail_healed',
        'logs_pruned',
    ];

    /**
     * Get path to the file-backed rate bucket.
     *
     * @return string
     */
    public static function get_bucket_path(): string {
        return ActivityStorage::get_log_dir() . '/.rate-buckets.json.php';
    }

    /**
     * Check if an event action should be logged or throttled.
     *
     * @param string $action   Event action name.
     * @param string $category Event category.
     * @param string $severity Severity level.
     * @return array ['allow' => bool, 'is_rollup_due' => bool, 'suppressed_count' => int]
     */
    public static function check_limit(string $action, string $category, string $severity): array {
        // Priority bypass
        if ($severity === ActivityEventSchema::SEVERITY_CRITICAL || in_array($action, self::$priority_actions, true)) {
            return ['allow' => true, 'is_rollup_due' => false, 'suppressed_count' => 0];
        }

        // Tier 1: In-Request deduplication
        $req_key = $action . ':' . $category;
        if (!isset(self::$in_memory_seen[$req_key])) {
            self::$in_memory_seen[$req_key] = 1;
        } else {
            self::$in_memory_seen[$req_key]++;
            if (self::$in_memory_seen[$req_key] > 5) {
                // Suppress excessive duplicates within same PHP execution
                return ['allow' => false, 'is_rollup_due' => false, 'suppressed_count' => self::$in_memory_seen[$req_key]];
            }
        }

        // Tier 2: Cross-Worker file bucket rate check
        return self::check_file_bucket($action);
    }

    /**
     * Synchronize and check counter in .rate-buckets.json.php under lock.
     *
     * @param string $action
     * @return array
     */
    private static function check_file_bucket(string $action): array {
        $path = self::get_bucket_path();
        $now = time();

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($path, 'c+');
        if (!$fp) {
            // If cannot lock bucket, fail open for safety
            return ['allow' => true, 'is_rollup_due' => false, 'suppressed_count' => 0];
        }

        flock($fp, LOCK_EX);
        $content = '';
        while (!feof($fp)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $content .= fread($fp, 8192);
        }

        if (strpos($content, ActivityStorage::PHP_HEADER_STUB) === 0) {
            $content = substr($content, strlen(ActivityStorage::PHP_HEADER_STUB));
        }

        $buckets = json_decode($content, true);
        if (!is_array($buckets)) {
            $buckets = [];
        }

        $bucket = $buckets[$action] ?? [
            'count'      => 0,
            'suppressed' => 0,
            'window_start' => $now,
        ];

        // Reset bucket if window expired
        if ($now - $bucket['window_start'] > self::WINDOW_SECONDS) {
            $suppressed_to_report = $bucket['suppressed'];
            $bucket['count'] = 1;
            $bucket['suppressed'] = 0;
            $bucket['window_start'] = $now;
            $buckets[$action] = $bucket;

            self::write_bucket_file($fp, $buckets);
            flock($fp, LOCK_UN);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);

            if ($suppressed_to_report > 0) {
                return ['allow' => true, 'is_rollup_due' => true, 'suppressed_count' => $suppressed_to_report];
            }
            return ['allow' => true, 'is_rollup_due' => false, 'suppressed_count' => 0];
        }

        // Within window: check count
        if ($bucket['count'] < self::MAX_EVENTS_PER_WINDOW) {
            $bucket['count']++;
            $buckets[$action] = $bucket;
            self::write_bucket_file($fp, $buckets);
            flock($fp, LOCK_UN);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return ['allow' => true, 'is_rollup_due' => false, 'suppressed_count' => 0];
        }

        // Over limit: suppress event
        $bucket['suppressed']++;
        $buckets[$action] = $bucket;
        self::write_bucket_file($fp, $buckets);
        flock($fp, LOCK_UN);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);

        return ['allow' => false, 'is_rollup_due' => false, 'suppressed_count' => $bucket['suppressed']];
    }

    /**
     * Write updated bucket content back to open file handle.
     *
     * @param resource $fp
     * @param array    $buckets
     */
    private static function write_bucket_file($fp, array $buckets): void {
        ftruncate($fp, 0);
        rewind($fp);
        $json = ActivityStorage::PHP_HEADER_STUB . json_encode($buckets, JSON_UNESCAPED_SLASHES);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
        fwrite($fp, $json);
        fflush($fp);
    }
}
