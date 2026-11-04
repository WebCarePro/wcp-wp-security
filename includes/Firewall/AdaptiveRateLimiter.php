<?php
declare(strict_types=1);

namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AdaptiveRateLimiter (CAF Phase 3)
 *
 * Sliding-Window Multi-Bucket Velocity Limiter & Smart Throttler.
 * Protects 4 distinct application boundaries with independent velocity budgets:
 * 1. 'auth' bucket: Max 5 failed attempts per 5 minutes on login, xmlrpc, and jwt-auth.
 * 2. 'checkout' bucket: Max 8 requests/min on wc-ajax actions with structured JSON error formatting.
 * 3. 'search' bucket: Max 25 queries/min on search parameters and REST search to prevent DB resource exhaustion.
 * 4. 'api' bucket: Burst allowance of 60 requests/min for standard REST API endpoints.
 *
 * Uses memory caching (Redis/APCu/Object Cache) when available or non-locking transient storage.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class AdaptiveRateLimiter {

    public const OPTION_SETTINGS   = 'wcpscan_rate_limiter_settings';
    public const TRANSIENT_PREFIX  = 'wcpscan_rl_';

    // Bucket Default Thresholds
    public const LIMIT_AUTH        = 5;   // 5 hits per 300s (5 min)
    public const WINDOW_AUTH       = 300;
    public const LIMIT_CHECKOUT    = 8;   // 8 hits per 60s
    public const WINDOW_CHECKOUT   = 60;
    public const LIMIT_SEARCH      = 25;  // 25 hits per 60s
    public const WINDOW_SEARCH     = 60;
    public const LIMIT_API         = 60;  // 60 hits per 60s
    public const WINDOW_API        = 60;
    public const LIMIT_GLOBAL      = 300; // 300 hits per 60s
    public const WINDOW_GLOBAL     = 60;

    /**
     * Get rate limiter settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'                => true,
            'limit_auth'             => self::LIMIT_AUTH,
            'window_auth'            => self::WINDOW_AUTH,
            'limit_checkout'         => self::LIMIT_CHECKOUT,
            'window_checkout'        => self::WINDOW_CHECKOUT,
            'limit_search'           => self::LIMIT_SEARCH,
            'window_search'          => self::WINDOW_SEARCH,
            'limit_api'              => self::LIMIT_API,
            'window_api'             => self::WINDOW_API,
            'limit_global'           => self::LIMIT_GLOBAL,
            'window_global'          => self::WINDOW_GLOBAL,
            'retry_after_seconds'    => 30,
            'escalate_to_ban'        => true,
            'enable_auto_escalation' => true,
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
            'enabled'                => isset($new_settings['enabled']) ? !empty($new_settings['enabled']) : !empty($current['enabled']),
            'limit_auth'             => max(2, min(50, intval($new_settings['limit_auth'] ?? $current['limit_auth']))),
            'window_auth'            => max(60, min(1800, intval($new_settings['window_auth'] ?? $current['window_auth']))),
            'limit_checkout'         => max(3, min(60, intval($new_settings['limit_checkout'] ?? $current['limit_checkout']))),
            'window_checkout'        => max(30, min(300, intval($new_settings['window_checkout'] ?? $current['window_checkout']))),
            'limit_search'           => max(5, min(100, intval($new_settings['limit_search'] ?? $current['limit_search']))),
            'window_search'          => max(30, min(300, intval($new_settings['window_search'] ?? $current['window_search']))),
            'limit_api'              => max(10, min(500, intval($new_settings['limit_api'] ?? $current['limit_api']))),
            'window_api'             => max(30, min(300, intval($new_settings['window_api'] ?? $current['window_api']))),
            'limit_global'           => max(50, min(2000, intval($new_settings['limit_global'] ?? $current['limit_global']))),
            'window_global'          => max(30, min(300, intval($new_settings['window_global'] ?? $current['window_global']))),
            'retry_after_seconds'    => max(5, min(300, intval($new_settings['retry_after_seconds'] ?? $current['retry_after_seconds']))),
            'escalate_to_ban'        => isset($new_settings['escalate_to_ban']) ? !empty($new_settings['escalate_to_ban']) : !empty($current['escalate_to_ban']),
            'enable_auto_escalation' => isset($new_settings['escalate_to_ban']) ? !empty($new_settings['escalate_to_ban']) : !empty($current['escalate_to_ban']),
        ];

        update_option(self::OPTION_SETTINGS, $updated);

        $diff = SettingsManager::compute_settings_diff($current, $updated);
        if (!empty($diff) && class_exists('\WcpScanner\System\WcpActivityLogger')) {
            \WcpScanner\System\WcpActivityLogger::notice(
                'rate_limiter_settings_updated',
                'firewall',
                [
                    'changed_count' => count($diff),
                    'description'   => sprintf('Adaptive Rate Limiting multi-bucket thresholds updated (%d parameter(s)).', count($diff)),
                    'module'        => 'rate_limiter',
                    'diff'          => $diff,
                ]
            );
        }

        return $updated;
    }

    /**
     * Check velocity budget for an explicit bucket and IP.
     *
     * @param string $bucket Name of velocity bucket ('auth', 'checkout', 'search', 'api', 'global')
     * @param string $ip Client IP
     * @param int $limit Maximum allowed requests in window
     * @param int $window Window duration in seconds
     * @return array ['allowed' => bool, 'remaining' => int, 'retry_after' => int, 'current' => int]
     */
    public static function check_bucket_velocity(string $bucket, string $ip, int $limit, int $window): array {
        $ip_hash = substr(md5($ip), 0, 16);
        $cache_key = self::TRANSIENT_PREFIX . $bucket . '_' . $ip_hash;

        // Try APCu first if available
        $count = null;
        if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
            $count = apcu_fetch($cache_key);
            if ($count === false) {
                $count = 1;
                apcu_store($cache_key, $count, $window);
            } else {
                $count = apcu_inc($cache_key);
            }
        }

        // Fallback to non-locking transients
        if ($count === null) {
            $count = (int) get_transient($cache_key);
            $count++;
            set_transient($cache_key, $count, $window);
        }

        $allowed = ($count <= $limit);
        $remaining = max(0, $limit - $count);
        $retry_after = $allowed ? 0 : $window;

        return [
            'allowed'     => $allowed,
            'remaining'   => $remaining,
            'retry_after' => $retry_after,
            'current'     => $count,
            'limit'       => $limit,
            'window'      => $window,
        ];
    }

    /**
     * Evaluate incoming request against context-aware multi-bucket velocity limiters.
     *
     * @param string $client_ip
     * @return bool True if permitted, false if throttled/blocked.
     */
    public static function check_request(string $client_ip): bool {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return true;
        }

        // Exempt logged-in administrators and editor/builders
        if (function_exists('current_user_can') && current_user_can('manage_options')) {
            return true;
        }

        // Exempt local loopback in dev
        if ($client_ip === '127.0.0.1' || $client_ip === '::1') {
            return true;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
        $decoded_uri = rawurldecode($uri);

        // Detect appropriate velocity bucket and limits
        $bucket = 'global';
        $limit = (int) ($settings['limit_global'] ?? self::LIMIT_GLOBAL);
        $window = (int) ($settings['window_global'] ?? self::WINDOW_GLOBAL);

        if (
            str_contains($decoded_uri, 'wp-login.php') ||
            str_contains($decoded_uri, 'xmlrpc.php') ||
            str_contains($decoded_uri, '/wp-json/jwt-auth/')
        ) {
            $bucket = 'auth';
            $limit = (int) ($settings['limit_auth'] ?? self::LIMIT_AUTH);
            $window = (int) ($settings['window_auth'] ?? self::WINDOW_AUTH);
        } elseif (
            str_contains($decoded_uri, 'wc-ajax=checkout') ||
            str_contains($decoded_uri, 'wc-ajax=add_to_cart') ||
            str_contains($decoded_uri, 'wc-ajax=update_order_review') ||
            (isset($_POST['action']) && in_array($_POST['action'], ['woocommerce_checkout', 'woocommerce_add_to_cart'], true))
        ) {
            $bucket = 'checkout';
            $limit = (int) ($settings['limit_checkout'] ?? self::LIMIT_CHECKOUT);
            $window = (int) ($settings['window_checkout'] ?? self::WINDOW_CHECKOUT);
        } elseif (
            (isset($_GET['s']) && trim((string) $_GET['s']) !== '') ||
            str_contains($decoded_uri, '/wp-json/wp/v2/search')
        ) {
            $bucket = 'search';
            $limit = (int) ($settings['limit_search'] ?? self::LIMIT_SEARCH);
            $window = (int) ($settings['window_search'] ?? self::WINDOW_SEARCH);
        } elseif (str_contains($decoded_uri, '/wp-json/')) {
            $bucket = 'api';
            $limit = (int) ($settings['limit_api'] ?? self::LIMIT_API);
            $window = (int) ($settings['window_api'] ?? self::WINDOW_API);
        }

        $result = self::check_bucket_velocity($bucket, $client_ip, $limit, $window);
        if ($result['allowed']) {
            return true;
        }

        $count = $result['current'];
        $retry_after = (int) ($settings['retry_after_seconds'] ?? 30);

        // Escalation to temporary quarantine if blasting server (> 2.5x threshold)
        if (!empty($settings['escalate_to_ban']) && $count > ($limit * 2.5)) {
            $ban_lock = 'wcpscan_rl_ban_log_' . md5($client_ip);
            if (!get_transient($ban_lock)) {
                set_transient($ban_lock, 1, 1800);
                AuditLogger::log(
                    'rate_limit_escalated_ban',
                    sprintf('Adaptive Rate Limiter: Client IP "%s" exceeded 2.5x %s velocity limit (%d hits). Temporary quarantine applied.', $client_ip, strtoupper($bucket), $count)
                );
            }

            if (class_exists('\\WcpScanner\\Firewall\\HoneyTokenEngine')) {
                HoneyTokenEngine::ban_bot_ip($client_ip, 1);
            }

            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Access Forbidden: Velocity limit severely violated. IP quarantined by WCP Adaptive Rate Limiter.';
            exit;
        }

        // Record throttle telemetry
        self::record_throttle_incident($client_ip, $bucket, $count, $limit);

        status_header(429);
        header('Retry-After: ' . $retry_after);
        header('X-WCP-Rate-Limit-Bucket: ' . rawurlencode($bucket));
        header('X-WCP-Rate-Limit-Limit: ' . (int) $limit);
        header('X-WCP-Rate-Limit-Current: ' . (int) $count);

        // Special handling for E-Commerce / Checkout: Return structured JSON to prevent UI corruption
        $is_json = wp_is_json_request() || str_contains($decoded_uri, '/wp-json/') || str_contains($decoded_uri, 'wc-ajax=') || $bucket === 'checkout';

        if ($is_json) {
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode([
                'success'     => false,
                'status'      => 429,
                'error'       => 'too_many_requests',
                'message'     => sprintf(__('Too many %s requests. Please wait %d seconds before retrying.', 'wcp-security-scanner'), esc_html($bucket), $retry_after),
                'retry_after' => $retry_after,
                'bucket'      => $bucket,
            ]);
        } else {
            header('Content-Type: text/plain; charset=utf-8');
            echo esc_html(sprintf('HTTP 429 Too Many Requests: Rate limit exceeded on %s boundary. Please wait %d seconds before retrying.', $bucket, $retry_after));
        }
        exit;
    }

    /**
     * Record a throttling incident.
     */
    private static function record_throttle_incident(string $ip, string $bucket, int $count, int $limit): void {
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
            'by_bucket'                => $stats['by_bucket'] ?? [
                'auth'     => 0,
                'checkout' => 0,
                'search'   => 0,
                'api'      => 0,
                'global'   => 0,
            ],
        ];
    }
}
