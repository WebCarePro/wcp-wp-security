<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LearningModeEngine
 *
 * Adaptive Route-Aware Learning Mode 2.0.
 * Profiles incoming traffic per WordPress route (Frontend, Admin-AJAX, REST API, WP-Admin, Auth),
 * mapping expected parameter schemas and calculating dynamic confidence scores.
 * Automatically graduates mature routes into active blocking enforcement while keeping
 * newly observed or rare custom plugin endpoints in safe learning mode.
 */
class LearningModeEngine {

    const OPTION_PROFILES = 'wcpscan_learning_route_profiles';
    const OPTION_SETTINGS = 'wcpscan_learning_settings';
    const DEFAULT_GRADUATION_THRESHOLD = 25; // Legitimate requests required to graduate a route

    /**
     * Get route profiles configuration settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'adaptive_learning_enabled' => true,
            'graduation_threshold'      => self::DEFAULT_GRADUATION_THRESHOLD,
            'auto_graduate_mature'      => true,
            'auto_graduate'             => true,
            'auto_tune_admin_benign'    => true,
            'graduation_confidence'     => 85,
        ];
        $stored = get_option(self::OPTION_SETTINGS, []);
        $merged = array_merge($defaults, is_array($stored) ? $stored : []);
        $auto_grad = isset($merged['auto_graduate']) ? !empty($merged['auto_graduate']) : !empty($merged['auto_graduate_mature']);
        $merged['auto_graduate'] = $auto_grad;
        $merged['auto_graduate_mature'] = $auto_grad;
        return $merged;
    }

    /**
     * Update Learning Mode settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();
        $auto_grad = isset($new_settings['auto_graduate'])
            ? !empty($new_settings['auto_graduate'])
            : (isset($new_settings['auto_graduate_mature']) ? !empty($new_settings['auto_graduate_mature']) : !empty($current['auto_graduate']));

        $updated = [
            'adaptive_learning_enabled' => isset($new_settings['adaptive_learning_enabled']) ? !empty($new_settings['adaptive_learning_enabled']) : !empty($current['adaptive_learning_enabled']),
            'graduation_threshold'      => max(5, min(500, intval($new_settings['graduation_threshold'] ?? self::DEFAULT_GRADUATION_THRESHOLD))),
            'auto_graduate_mature'      => $auto_grad,
            'auto_graduate'             => $auto_grad,
            'auto_tune_admin_benign'    => isset($new_settings['auto_tune_admin_benign']) ? !empty($new_settings['auto_tune_admin_benign']) : !empty($current['auto_tune_admin_benign']),
            'graduation_confidence'     => max(50, min(99, intval($new_settings['graduation_confidence'] ?? 85))),
        ];
        update_option(self::OPTION_SETTINGS, $updated);
        return $updated;
    }

    /**
     * Determine the canonical route key for the current request.
     *
     * @return string
     */
    public static function get_current_route_key(): string {
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

        // 1. Auth routes
        if (strpos($uri, 'wp-login.php') !== false) {
            return 'auth:wp-login';
        }
        if (strpos($uri, 'xmlrpc.php') !== false) {
            return 'endpoint:xmlrpc';
        }

        // 2. Admin AJAX routes
        if (strpos($uri, 'admin-ajax.php') !== false) {
            // phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Passive route inspection for WAF learning profiling
            $action = isset($_GET['action']) ? sanitize_key(wp_unslash($_GET['action'])) : (isset($_POST['action']) ? sanitize_key(wp_unslash($_POST['action'])) : 'unknown');
            // phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            return 'ajax:' . ($action ?: 'unknown');
        }

        // 3. REST API routes
        // phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Passive route inspection for WAF learning profiling
        $raw_rest_route = isset($_GET['rest_route']) ? sanitize_text_field(wp_unslash($_GET['rest_route'])) : '';
        if (strpos($uri, '/wp-json/') !== false || strpos($raw_rest_route, '/') === 0) {
            $rest_path = '';
            if (strpos($uri, '/wp-json/') !== false) {
                $rest_path = substr($uri, strpos($uri, '/wp-json/') + 9);
            } elseif (!empty($raw_rest_route)) {
                $rest_path = ltrim($raw_rest_route, '/');
            }
            $rest_path = strtok($rest_path, '?');
            $parts = explode('/', trim($rest_path, '/'));
            $prefix = implode('/', array_slice($parts, 0, 2));
            // phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            return 'rest:' . ($prefix ?: 'root');
        }
        // phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing

        // 4. WP-Admin screen routes
        if (is_admin() || strpos($uri, '/wp-admin/') !== false) {
            $script = isset($_SERVER['SCRIPT_NAME']) ? basename(sanitize_text_field(wp_unslash($_SERVER['SCRIPT_NAME']))) : 'admin.php';
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
            return 'admin:' . $script . ($page ? "?page={$page}" : '');
        }

        // 5. Frontend Public routes
        return 'frontend:public';
    }

    /**
     * Check if a route has graduated from learning mode into active blocking enforcement.
     *
     * @param string|null $route_key
     * @return bool
     */
    public static function is_route_graduated(?string $route_key = null): bool {
        $settings = self::get_settings();
        if (empty($settings['adaptive_learning_enabled'])) {
            return false;
        }

        $key = $route_key ?: self::get_current_route_key();
        $profiles = get_option(self::OPTION_PROFILES, []);

        if (empty($profiles[$key])) {
            return false;
        }

        $p = $profiles[$key];

        // Manual override takes precedence
        if (!empty($p['forced_status'])) {
            return $p['forced_status'] === 'enforcing';
        }

        return ($p['status'] ?? 'learning') === 'graduated';
    }

    /**
     * Profile a legitimate request and build behavioral parameter schema.
     *
     * @return void
     */
    public static function profile_benign_request(): void {
        $settings = self::get_settings();
        if (empty($settings['adaptive_learning_enabled'])) {
            return;
        }

        // Skip static asset hits
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (preg_match('/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|map)$/i', $uri)) {
            return;
        }

        $route_key = self::get_current_route_key();
        $profiles = get_option(self::OPTION_PROFILES, []);
        if (!is_array($profiles)) {
            $profiles = [];
        }

        $now = time();
        $threshold = $settings['graduation_threshold'] ?? self::DEFAULT_GRADUATION_THRESHOLD;

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $get_keys = array_keys($_GET);
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $post_keys = array_keys($_POST);
        $observed_params = array_values(array_unique(array_map('sanitize_key', array_merge($get_keys, $post_keys))));

        if (!isset($profiles[$route_key])) {
            $profiles[$route_key] = [
                'route_key'        => $route_key,
                'request_count'    => 1,
                'benign_count'     => 1,
                'threat_count'     => 0,
                'learned_params'   => $observed_params,
                'confidence'       => min(100, intval((1 / $threshold) * 100)),
                'status'           => 'learning',
                'forced_status'    => null,
                'first_seen'       => current_time('mysql'),
                'last_seen'        => current_time('mysql'),
            ];
        } else {
            $p = &$profiles[$route_key];
            $p['request_count']++;
            $p['benign_count']++;
            $p['last_seen'] = current_time('mysql');

            // Merge newly observed parameters
            $p['learned_params'] = array_values(array_unique(array_merge($p['learned_params'] ?? [], $observed_params)));

            // Recalculate confidence
            $p['confidence'] = min(100, intval(($p['benign_count'] / $threshold) * 100));

            // Auto-graduate when threshold met
            if (!empty($settings['auto_graduate_mature']) && $p['confidence'] >= 100 && $p['status'] !== 'graduated') {
                $p['status'] = 'graduated';
                AuditLogger::log(
                    'route_graduated',
                    sprintf('Adaptive Learning Mode: Route "%s" reached 100%% confidence (%d benign requests) and graduated to Active Enforcement.', $route_key, $p['benign_count'])
                );
            }
        }

        // Limit stored route profiles to top 150 active routes
        if (count($profiles) > 150) {
            uasort($profiles, fn($a, $b) => ($b['request_count'] ?? 0) <=> ($a['request_count'] ?? 0));
            $profiles = array_slice($profiles, 0, 150, true);
        }

        update_option(self::OPTION_PROFILES, $profiles);
    }

    /**
     * Record a threat violation encountered on a route.
     *
     * @param string $route_key
     * @return void
     */
    public static function record_threat_encountered(string $route_key): void {
        $profiles = get_option(self::OPTION_PROFILES, []);
        if (isset($profiles[$route_key])) {
            $profiles[$route_key]['request_count']++;
            $profiles[$route_key]['threat_count']++;
            $profiles[$route_key]['last_seen'] = current_time('mysql');
            update_option(self::OPTION_PROFILES, $profiles);
        }
    }

    /**
     * Get all active route profiles.
     *
     * @return array
     */
    public static function get_route_profiles(): array {
        $profiles = get_option(self::OPTION_PROFILES, []);
        if (!is_array($profiles)) {
            return [];
        }

        // Sort by request count descending
        uasort($profiles, fn($a, $b) => ($b['request_count'] ?? 0) <=> ($a['request_count'] ?? 0));
        return array_values($profiles);
    }

    /**
     * Manually graduate or force enforcement mode for a specific route.
     *
     * @param string $route_key
     * @param string $action ('graduate' | 'enforce' | 'learn' | 'reset')
     * @return array
     */
    public static function set_route_status(string $route_key, string $action): array {
        $profiles = get_option(self::OPTION_PROFILES, []);

        if ($action === 'reset') {
            unset($profiles[$route_key]);
            update_option(self::OPTION_PROFILES, $profiles);
            return ['success' => true, 'message' => "Route profile for '{$route_key}' was reset."];
        }

        if (!isset($profiles[$route_key])) {
            $profiles[$route_key] = [
                'route_key'      => $route_key,
                'request_count'  => 0,
                'benign_count'   => 0,
                'threat_count'   => 0,
                'learned_params' => [],
                'confidence'     => 100,
                'status'         => 'graduated',
                'forced_status'  => null,
                'first_seen'     => current_time('mysql'),
                'last_seen'      => current_time('mysql'),
            ];
        }

        if ($action === 'graduate') {
            $profiles[$route_key]['status'] = 'graduated';
            $profiles[$route_key]['confidence'] = 100;
            $profiles[$route_key]['forced_status'] = null;
        } elseif ($action === 'enforce') {
            $profiles[$route_key]['forced_status'] = 'enforcing';
        } elseif ($action === 'learn') {
            $profiles[$route_key]['forced_status'] = 'learning';
            $profiles[$route_key]['status'] = 'learning';
        }

        update_option(self::OPTION_PROFILES, $profiles);

        AuditLogger::log(
            'route_status_updated',
            sprintf('Route "%s" status manually updated to "%s".', $route_key, $action)
        );

        return [
            'success'   => true,
            'message'   => "Route '{$route_key}' status updated to '{$action}'.",
            'profile'   => $profiles[$route_key],
        ];
    }

    /**
     * Get aggregate statistics on Route Learning Mode 2.0.
     *
     * @return array
     */
    public static function get_summary_stats(): array {
        $profiles = self::get_route_profiles();
        $total_routes = count($profiles);
        $graduated = 0;
        $learning = 0;
        $total_requests = 0;
        $total_threats = 0;
        $sum_confidence = 0;

        foreach ($profiles as $p) {
            $total_requests += $p['request_count'] ?? 0;
            $total_threats  += $p['threat_count'] ?? 0;
            $sum_confidence += $p['confidence'] ?? 0;

            if (($p['status'] ?? '') === 'graduated' || ($p['forced_status'] ?? '') === 'enforcing') {
                $graduated++;
            } else {
                $learning++;
            }
        }

        $avg_confidence = $total_routes > 0 ? round($sum_confidence / $total_routes, 1) : 0;

        return [
            'total_routes'          => $total_routes,
            'total_profiles'        => $total_routes,
            'graduated_routes'      => $graduated,
            'graduated_count'       => $graduated,
            'learning_routes'       => $learning,
            'learning_count'        => $learning,
            'total_requests'        => $total_requests,
            'total_benign_requests' => $total_requests,
            'total_threats'         => $total_threats,
            'average_confidence'    => $avg_confidence,
            'settings'              => self::get_settings(),
        ];
    }
}
