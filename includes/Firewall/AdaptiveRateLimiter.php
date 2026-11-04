<?php
declare(strict_types=1);

namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;
use WcpScanner\Firewall\CAF\ThreatScoreTracker;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AdaptiveRateLimiter (CAF Phase 3)
 *
 * Sliding-Window Multi-Bucket Velocity Limiter & Smart Throttler.
 *
 * Mathematical Sliding Window Model:
 *   C_{eff} = C_{prev} * (1 - (t - t_{window_start}) / W) + C_{curr}
 *
 * Protects 5 isolated velocity boundaries:
 * 1. BUCKET_AUTH: /wp-login.php, xmlrpc.php, jwt-auth, wc-ajax=login (Strict limit: 5 / 300s)
 * 2. BUCKET_CHECKOUT: wc-ajax=checkout, /wp-json/wc/store/v1/checkout (Limit: 8 / 60s, JSON response)
 * 3. BUCKET_CART_AJAX: add_to_cart, update_order_review, get_refreshed_fragments (Limit: 30 / 60s, JSON response)
 * 4. BUCKET_REST_WRITE: POST/PUT/PATCH/DELETE on /wp-json/ (Limit: 30 / 60s)
 * 5. BUCKET_SEARCH_PROBE: ?s= and /wp-json/wp/v2/search (Limit: 25 / 60s)
 *
 * On throttle on checkout/cart boundaries, always emits valid WooCommerce-compatible JSON.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class AdaptiveRateLimiter {

    public const OPTION_SETTINGS      = 'wcpscan_rate_limiter_settings';
    public const TRANSIENT_PREFIX     = 'wcpscan_rl_';

    // Bucket Identifier Constants
    public const BUCKET_AUTH          = 'auth';
    public const BUCKET_CHECKOUT      = 'checkout';
    public const BUCKET_CART_AJAX     = 'cart_ajax';
    public const BUCKET_REST_WRITE    = 'rest_write';
    public const BUCKET_SEARCH_PROBE  = 'search_probe';
    public const BUCKET_GLOBAL        = 'global';

    // Bucket Default Thresholds
    public const LIMIT_AUTH           = 5;   // 5 hits per 300s (5 min)
    public const WINDOW_AUTH          = 300;
    public const LIMIT_CHECKOUT       = 8;   // 8 hits per 60s
    public const WINDOW_CHECKOUT      = 60;
    public const LIMIT_CART_AJAX      = 30;  // 30 hits per 60s
    public const WINDOW_CART_AJAX     = 60;
    public const LIMIT_REST_WRITE     = 30;  // 30 mutations per 60s
    public const WINDOW_REST_WRITE    = 60;
    public const LIMIT_SEARCH_PROBE   = 25;  // 25 queries per 60s
    public const WINDOW_SEARCH_PROBE  = 60;
    public const LIMIT_GLOBAL         = 300; // 300 hits per 60s
    public const WINDOW_GLOBAL        = 60;

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
            'limit_cart_ajax'        => self::LIMIT_CART_AJAX,
            'window_cart_ajax'       => self::WINDOW_CART_AJAX,
            'limit_rest_write'       => self::LIMIT_REST_WRITE,
            'window_rest_write'      => self::WINDOW_REST_WRITE,
            'limit_search_probe'     => self::LIMIT_SEARCH_PROBE,
            'window_search_probe'    => self::WINDOW_SEARCH_PROBE,
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
            'limit_cart_ajax'        => max(10, min(200, intval($new_settings['limit_cart_ajax'] ?? $current['limit_cart_ajax']))),
            'window_cart_ajax'       => max(30, min(300, intval($new_settings['window_cart_ajax'] ?? $current['window_cart_ajax']))),
            'limit_rest_write'       => max(10, min(200, intval($new_settings['limit_rest_write'] ?? $current['limit_rest_write']))),
            'window_rest_write'      => max(30, min(300, intval($new_settings['window_rest_write'] ?? $current['window_rest_write']))),
            'limit_search_probe'     => max(5, min(100, intval($new_settings['limit_search_probe'] ?? ($new_settings['limit_search'] ?? $current['limit_search_probe'])))),
            'window_search_probe'    => max(30, min(300, intval($new_settings['window_search_probe'] ?? ($new_settings['window_search'] ?? $current['window_search_probe'])))),
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
     * Check velocity budget using Sliding-Window Counter for an explicit bucket and IP.
     *
     * Formula:
     *   C_{eff} = C_{prev} * (1 - (now - window_start) / window) + C_{curr}
     *
     * @param string $bucket Name of velocity bucket ('auth', 'checkout', 'cart_ajax', 'rest_write', 'search_probe', 'global')
     * @param string $ip Client IP
     * @param int $limit Maximum allowed requests in window
     * @param int $window Window duration in seconds
     * @return array ['allowed' => bool, 'remaining' => int, 'retry_after' => int, 'current' => float, 'limit' => int, 'window' => int]
     */
    public static function check_bucket_velocity(string $bucket, string $ip, int $limit, int $window): array {
        $ip_hash = substr(md5($ip), 0, 16);
        $cache_key = self::TRANSIENT_PREFIX . $bucket . '_' . $ip_hash;
        $now = time();

        $current_window_idx = (int) floor($now / $window);
        $window_start = $current_window_idx * $window;
        $elapsed_in_window = max(0, $now - $window_start);

        $data = null;
        if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
            $data = apcu_fetch($cache_key);
        }

        if (!is_array($data)) {
            $data = get_transient($cache_key);
        }

        if (!is_array($data) || ($data['window_idx'] ?? 0) !== $current_window_idx) {
            // New window or expired
            $prev_count = 0;
            if (is_array($data) && ($data['window_idx'] ?? 0) === ($current_window_idx - 1)) {
                $prev_count = (int) ($data['curr'] ?? 0);
            }
            $curr_count = 1;
            $data = [
                'window_idx' => $current_window_idx,
                'prev'       => $prev_count,
                'curr'       => $curr_count,
            ];
        } else {
            // Existing current window
            $data['curr'] = (int) ($data['curr'] ?? 0) + 1;
        }

        // Sliding window effective count: C_{prev} * (1 - elapsed/W) + C_{curr}
        $prev_weight = max(0.0, 1.0 - ($elapsed_in_window / (float) $window));
        $effective_count = round(($data['prev'] * $prev_weight) + $data['curr'], 2);

        // Store back
        $ttl = $window * 2;
        if (function_exists('apcu_store') && ini_get('apc.enabled')) {
            apcu_store($cache_key, $data, $ttl);
        }
        set_transient($cache_key, $data, $ttl);

        $allowed = ($effective_count <= (float) $limit);
        $remaining = max(0, (int) floor($limit - $effective_count));
        $retry_after = $allowed ? 0 : max(5, $window - $elapsed_in_window);

        return [
            'allowed'     => $allowed,
            'remaining'   => $remaining,
            'retry_after' => $retry_after,
            'current'     => (int) ceil($effective_count),
            'limit'       => $limit,
            'window'      => $window,
        ];
    }

    /**
     * Evaluate incoming request against context-aware 5-bucket velocity limiters.
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

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $decoded_uri = rawurldecode($raw_uri);
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early passive packet rate-limiting
        $post_action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $search_query = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';

        // Classify into one of 5 isolated velocity boundaries:
        $bucket = self::BUCKET_GLOBAL;
        $limit = (int) ($settings['limit_global'] ?? self::LIMIT_GLOBAL);
        $window = (int) ($settings['window_global'] ?? self::WINDOW_GLOBAL);

        if (
            str_contains($decoded_uri, 'wp-login.php') ||
            str_contains($decoded_uri, 'xmlrpc.php') ||
            str_contains($decoded_uri, '/wp-json/jwt-auth/') ||
            str_contains($decoded_uri, 'wc-ajax=login')
        ) {
            // Bucket 1: Auth
            $bucket = self::BUCKET_AUTH;
            $limit = (int) ($settings['limit_auth'] ?? self::LIMIT_AUTH);
            $window = (int) ($settings['window_auth'] ?? self::WINDOW_AUTH);
        } elseif (
            str_contains($decoded_uri, 'wc-ajax=checkout') ||
            str_contains($decoded_uri, '/wp-json/wc/store/v1/checkout') ||
            in_array($post_action, ['woocommerce_checkout'], true)
        ) {
            // Bucket 2: Checkout (High priority e-commerce boundary)
            $bucket = self::BUCKET_CHECKOUT;
            $limit = (int) ($settings['limit_checkout'] ?? self::LIMIT_CHECKOUT);
            $window = (int) ($settings['window_checkout'] ?? self::WINDOW_CHECKOUT);
        } elseif (
            str_contains($decoded_uri, 'wc-ajax=add_to_cart') ||
            str_contains($decoded_uri, 'wc-ajax=update_order_review') ||
            str_contains($decoded_uri, 'wc-ajax=get_refreshed_fragments') ||
            in_array($post_action, ['woocommerce_add_to_cart', 'woocommerce_update_order_review'], true)
        ) {
            // Bucket 3: Cart AJAX (Frequent legit interactions)
            $bucket = self::BUCKET_CART_AJAX;
            $limit = (int) ($settings['limit_cart_ajax'] ?? self::LIMIT_CART_AJAX);
            $window = (int) ($settings['window_cart_ajax'] ?? self::WINDOW_CART_AJAX);
        } elseif (
            trim($search_query) !== '' ||
            str_contains($decoded_uri, '/wp-json/wp/v2/search')
        ) {
            // Bucket 5: Search Probe (Prevents expensive wildcard queries)
            $bucket = self::BUCKET_SEARCH_PROBE;
            $limit = (int) ($settings['limit_search_probe'] ?? self::LIMIT_SEARCH_PROBE);
            $window = (int) ($settings['window_search_probe'] ?? self::WINDOW_SEARCH_PROBE);
        } elseif (
            str_contains($decoded_uri, '/wp-json/') &&
            in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)
        ) {
            // Bucket 4: REST Mutation/Write
            $bucket = self::BUCKET_REST_WRITE;
            $limit = (int) ($settings['limit_rest_write'] ?? self::LIMIT_REST_WRITE);
            $window = (int) ($settings['window_rest_write'] ?? self::WINDOW_REST_WRITE);
        }

        $result = self::check_bucket_velocity($bucket, $client_ip, $limit, $window);
        if ($result['allowed']) {
            return true;
        }

        $count = $result['current'];
        $retry_after = (int) ($settings['retry_after_seconds'] ?? 30);

        // Record in differential threat score engine
        if (class_exists('\\WcpScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            $event_tag = ($bucket === self::BUCKET_AUTH) ? 'auth_fail' : 'probe_404';
            ThreatScoreTracker::record_event($client_ip, $event_tag, 10.0);
        }

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
        $is_wc_or_json = wp_is_json_request() ||
            str_contains($decoded_uri, '/wp-json/') ||
            str_contains($decoded_uri, 'wc-ajax=') ||
            $bucket === self::BUCKET_CHECKOUT ||
            $bucket === self::BUCKET_CART_AJAX;

        if ($is_wc_or_json) {
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode([
                'result'      => 'failure',
                'status'      => 429,
                'error'       => 'too_many_requests',
                /* translators: %1$s: velocity bucket name, %2$d: retry after seconds */
                'message'     => sprintf(__('Too many %1$s requests. Please wait %2$d seconds before retrying.', 'wcp-security-scanner'), esc_html($bucket), $retry_after),
                /* translators: %d: retry after seconds */
                'messages'    => sprintf('<ul class="woocommerce-error"><li>%s</li></ul>', esc_html(sprintf(__('Too many requests. Please wait %d seconds before retrying.', 'wcp-security-scanner'), $retry_after))),
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
                self::BUCKET_AUTH         => 0,
                self::BUCKET_CHECKOUT     => 0,
                self::BUCKET_CART_AJAX    => 0,
                self::BUCKET_REST_WRITE   => 0,
                self::BUCKET_SEARCH_PROBE => 0,
                self::BUCKET_GLOBAL       => 0,
            ],
        ];
    }
}
