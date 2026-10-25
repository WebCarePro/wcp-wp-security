<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AdaptiveRateLimiter
 *
 * Sliding-Window Token-Bucket Rate Limiter & Smart Throttler.
 * Protects critical application boundaries (Authentication, Admin-AJAX, REST API, Global)
 * with adaptive HTTP 429 Retry-After throttling before harsh IP banning, avoiding
 * office NAT false positives while defending against automated DDoS and brute force.
 */
class AdaptiveRateLimiter {

    const OPTION_SETTINGS = 'wcpscan_rate_limiter_settings';
    const TRANSIENT_PREFIX = 'wcpscan_rl_';

    /**
     * Get rate limiter settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'             => true,
            'limit_auth'          => 20,   // Max login/xmlrpc hits per 60s
            'limit_ajax'          => 80,   // Max admin-ajax hits per 60s
            'limit_rest'          => 150,  // Max REST API hits per 60s
            'limit_global'        => 300,  // Max total HTTP hits per 60s
            'retry_after_seconds' => 30,
            'escalate_to_ban'     => true, // Ban IP if request exceeds 2.5x threshold
        ];
        $stored = get_option(self::OPTION_SETTINGS, []);
        return array_merge($defaults, is_array($stored) ? $stored : []);
    }

    /**
     * Update rate limiter settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();
        $updated = [
            'enabled'             => !empty($new_settings['enabled']),
            'limit_auth'          => max(5, min(120, intval($new_settings['limit_auth'] ?? 20))),
            'limit_ajax'          => max(10, min(500, intval($new_settings['limit_ajax'] ?? 80))),
            'limit_rest'          => max(20, min(1000, intval($new_settings['limit_rest'] ?? 150))),
            'limit_global'        => max(50, min(2000, intval($new_settings['limit_global'] ?? 300))),
            'retry_after_seconds' => max(5, min(300, intval($new_settings['retry_after_seconds'] ?? 30))),
            'escalate_to_ban'     => !empty($new_settings['escalate_to_ban']),
        ];
        update_option(self::OPTION_SETTINGS, $updated);
        return $updated;
    }

    /**
     * Evaluate incoming request against adaptive rate limiter buckets.
     *
     * @param string $client_ip
     * @return bool True if permitted, false if throttled/blocked.
     */
    public static function check_request(string $client_ip): bool {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return true;
        }

        // Exempt logged-in administrators
        if (current_user_can('manage_options')) {
            return true;
        }

        // Exempt loopback in local dev
        if ($client_ip === '127.0.0.1' || $client_ip === '::1') {
            return true;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

        // 1. Identify active bucket
        $bucket = 'global';
        $limit = $settings['limit_global'] ?? 300;

        if (strpos($uri, 'wp-login.php') !== false || strpos($uri, 'xmlrpc.php') !== false) {
            $bucket = 'auth';
            $limit = $settings['limit_auth'] ?? 20;
        } elseif (strpos($uri, 'admin-ajax.php') !== false) {
            $bucket = 'ajax';
            $limit = $settings['limit_ajax'] ?? 80;
        } elseif (strpos($uri, '/wp-json/') !== false) {
            $bucket = 'rest';
            $limit = $settings['limit_rest'] ?? 150;
        }

        // 2. Sliding window counter in transient cache (60-second window)
        $cache_key = self::TRANSIENT_PREFIX . $bucket . '_' . substr(md5($client_ip), 0, 16);
        $count = (int) get_transient($cache_key);
        $count++;
        set_transient($cache_key, $count, 60);

        // 3. Check if within threshold
        if ($count <= $limit) {
            return true;
        }

        // 4. Escalation to Temporary Ban if aggressively blasting server (> 2.5x threshold)
        if (!empty($settings['escalate_to_ban']) && $count > ($limit * 2.5)) {
            AuditLogger::log(
                'rate_limit_escalated_ban',
                sprintf('Adaptive Rate Limiter: Client IP "%s" exceeded 2.5x %s limit (%d hits). Temporary ban applied.', $client_ip, strtoupper($bucket), $count)
            );

            HoneyTokenEngine::ban_bot_ip($client_ip, 1); // 1-hour ban
            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Access Forbidden: Client rate limit severely violated. IP quarantined by WCP Security Limiter.';
            exit;
        }

        // 5. Tier 1 Throttling: HTTP 429 Too Many Requests
        $retry_after = $settings['retry_after_seconds'] ?? 30;
        self::record_throttle_incident($client_ip, $bucket, $count, $limit);

        status_header(429);
        header('Retry-After: ' . $retry_after);
        header('X-WCP-Rate-Limit-Bucket: ' . rawurlencode($bucket));
        header('X-WCP-Rate-Limit-Limit: ' . intval($limit));
        header('X-WCP-Rate-Limit-Current: ' . intval($count));

        $http_accept = isset($_SERVER['HTTP_ACCEPT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'])) : '';
        if (wp_is_json_request() || strpos($uri, '/wp-json/') !== false || strpos($http_accept, 'application/json') !== false) {
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode([
                'success'     => false,
                'status'      => 429,
                'error'       => 'too_many_requests',
                'message'     => 'Too many requests. Please wait before retrying.',
                'retry_after' => $retry_after,
                'bucket'      => $bucket,
            ]);
        } else {
            header('Content-Type: text/plain; charset=utf-8');
            echo esc_html("HTTP 429 Too Many Requests: Rate limit exceeded for {$bucket} boundary. Please wait {$retry_after} seconds before retrying.");
        }
        exit;
    }

    /**
     * Record a throttling incident.
     */
    private static function record_throttle_incident(string $ip, string $bucket, int $count, int $limit) {
        $transient_key = 'wcpscan_rl_stats_day';
        $stats = get_transient($transient_key);
        if (!is_array($stats)) {
            $stats = ['total_throttled' => 0, 'by_bucket' => []];
        }
        $stats['total_throttled']++;
        $stats['by_bucket'][$bucket] = ($stats['by_bucket'][$bucket] ?? 0) + 1;
        set_transient($transient_key, $stats, 86400);
    }

    /**
     * Get aggregate rate limiting telemetry.
     *
     * @return array
     */
    public static function get_telemetry(): array {
        $stats = get_transient('wcpscan_rl_stats_day');
        if (!is_array($stats)) {
            $stats = ['total_throttled' => 0, 'by_bucket' => []];
        }

        return [
            'settings'                 => self::get_settings(),
            'total_throttled'          => $stats['total_throttled'] ?? 0,
            'total_throttled_requests' => $stats['total_throttled'] ?? 0,
            'active_tracked_ips'       => count($stats['by_bucket'] ?? []),
            'by_bucket'                => $stats['by_bucket'] ?? [],
        ];
    }
}
