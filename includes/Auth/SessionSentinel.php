<?php
namespace WcpScanner\Auth;

use WcpScanner\System\SettingsManager;
use WcpScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SessionSentinel
 *
 * Protects administrator sessions against hijackings, cookie replay, and unauthorized concurrency.
 * Provides active session tracking, concurrent login alerts, IP lock, and instant one-click session revocation.
 */
class SessionSentinel {

    private static $last_auth_token = '';

    /**
     * Bootstrap Session Sentinel
     */
    public static function init() {
        // Capture generated session token during auth cookie issuance
        add_action('set_auth_cookie', [__CLASS__, 'on_set_auth_cookie'], 10, 6);

        // Track session upon login
        add_action('wp_login', [__CLASS__, 'on_user_login'], 20, 2);

        // Verify session integrity on every authenticated request
        add_action('init', [__CLASS__, 'inspect_active_session'], 2);

        // Cleanup on logout
        add_action('wp_logout', [__CLASS__, 'on_user_logout']);
    }

    /**
     * Cache the freshly minted session token from WordPress core's set_auth_cookie hook
     */
    public static function on_set_auth_cookie($auth_cookie, $expire, $expiration, $user_id, $scheme, $token) {
        $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
        if (!empty($cookie_name) && (!isset($_COOKIE[$cookie_name]) || empty($_COOKIE[$cookie_name]))) {
            $_COOKIE[$cookie_name] = $auth_cookie;
        }
    }

    /**
     * Track new authenticated session
     */
    public static function on_user_login(string $user_login, \WP_User $user) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['session_sentinel_enabled'])) {
            return;
        }

        // Only enforce for administrators or editors
        if (!$user->has_cap('edit_posts')) {
            return;
        }

        $session_token = !empty(self::$last_auth_token) ? self::$last_auth_token : wp_get_session_token();
        if (empty($session_token)) {
            $wp_sessions = get_user_meta($user->ID, 'session_tokens', true);
            if (is_array($wp_sessions) && !empty($wp_sessions)) {
                $keys = array_keys($wp_sessions);
                $session_token = end($keys);
            }
        }

        $ip = FirewallEngine::get_client_ip();
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

        // Check concurrent sessions count
        if (!empty($settings['session_block_concurrent']) && $user->has_cap('administrator')) {
            $wp_sessions = get_user_meta($user->ID, 'session_tokens', true);
            if (is_array($wp_sessions) && count($wp_sessions) > 1 && $session_token) {
                $verifier = hash('sha256', $session_token);
                $preserved = [];
                if (isset($wp_sessions[$verifier])) {
                    $preserved[$verifier] = $wp_sessions[$verifier];
                } elseif (isset($wp_sessions[$session_token])) {
                    $preserved[$session_token] = $wp_sessions[$session_token];
                }
                if (!empty($preserved)) {
                    update_user_meta($user->ID, 'session_tokens', $preserved);
                } else {
                    $manager = \WP_Session_Tokens::get_instance($user->ID);
                    $manager->destroy_others($session_token);
                }
            }
        }

        // Store session metadata in user meta
        $sessions_meta = get_user_meta($user->ID, 'wcpscan_session_meta', true) ?: [];
        if (!is_array($sessions_meta)) {
            $sessions_meta = [];
        }

        if ($session_token) {
            $verifier = hash('sha256', $session_token);
            $entry = [
                'login_time'     => time(),
                'last_seen'      => time(),
                'encrypted_meta' => \WcpScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                    'login_ip'   => $ip,
                    'user_agent' => substr(sanitize_text_field($ua), 0, 255),
                ])),
            ];

            // Store metadata under both raw token and verifier so lookups by either succeed
            $sessions_meta[$session_token] = $entry;
            $sessions_meta[$verifier]      = $entry;

            update_user_meta($user->ID, 'wcpscan_session_meta', $sessions_meta);
        }
    }

    /**
     * Inspect session on each authenticated request to defend against hijacked cookies
     */
    public static function inspect_active_session() {
        if (!is_user_logged_in()) {
            return;
        }

        try {
            $settings = SettingsManager::get_settings();
            if (empty($settings['session_sentinel_enabled'])) {
                return;
            }

            $user_id = get_current_user_id();
            $user = wp_get_current_user();

            // Focus on administrative and editor sessions
            if (!$user || !$user->has_cap('edit_posts')) {
                return;
            }

            $current_token = wp_get_session_token();
            if (!$current_token) {
                return;
            }
            $current_verifier = hash('sha256', $current_token);

            $ip = FirewallEngine::get_client_ip();
            $sessions_meta = get_user_meta($user_id, 'wcpscan_session_meta', true);
            if (!is_array($sessions_meta)) {
                $sessions_meta = [];
            }

            $session_info = $sessions_meta[$current_verifier] ?? ($sessions_meta[$current_token] ?? null);

            $current_login_ip = '';
            if (!empty($session_info['encrypted_meta'])) {
                $decrypted_meta = \WcpScanner\Security\SecretVault::decrypt((string) $session_info['encrypted_meta']);
                $decoded = is_string($decrypted_meta) ? (json_decode($decrypted_meta, true) ?: []) : [];
                $current_login_ip = $decoded['login_ip'] ?? '';
            } else {
                $current_login_ip = $session_info['login_ip'] ?? '';
            }

            // Auto-initialize if session was active before sentinel activation or if IP was recorded as Cloudflare proxy
            if (!$session_info || empty($current_login_ip) || \WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($current_login_ip)) {
                $entry = [
                    'login_time'     => $session_info['login_time'] ?? time(),
                    'last_seen'      => time(),
                    'encrypted_meta' => \WcpScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                        'login_ip'   => $ip,
                        'user_agent' => substr(sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'), 0, 255),
                    ])),
                ];
                $sessions_meta[$current_token]    = $entry;
                $sessions_meta[$current_verifier] = $entry;
                update_user_meta($user_id, 'wcpscan_session_meta', $sessions_meta);
                return;
            }

            // 1. IP Lock / Hijack Defense Check
            if (!empty($settings['session_lock_ip']) && !empty($current_login_ip)) {
                if ($current_login_ip !== $ip) {
                    // Potential cookie replay or session hijack from a different IP address!
                    self::terminate_session($user_id, $current_token, 'Session terminated due to IP address mismatch (Anti-Hijack Lock).');
                    wp_safe_redirect(wp_login_url() . '?wcpscan_session_alert=ip_mismatch');
                    exit;
                }
            }

            // Update last seen timestamp (throttled every 60 seconds to save DB writes)
            if (time() - ($session_info['last_seen'] ?? 0) > 60) {
                $sessions_meta[$current_token]['last_seen'] = time();
                $sessions_meta[$current_verifier]['last_seen'] = time();
                update_user_meta($user_id, 'wcpscan_session_meta', $sessions_meta);
            }
        } catch (\Throwable $e) {
            // Failsafe: never disrupt WordPress admin execution
        }
    }

    /**
     * Terminate an individual session
     */
    public static function terminate_session(int $user_id, string $session_token, string $reason = '') {
        if (empty($user_id) || empty($session_token)) {
            return false;
        }

        try {
            // 1. Direct destruction from WordPress core 'session_tokens' user meta.
            // In WP core, sessions are stored in user meta 'session_tokens' keyed by the SHA-256 verifier hash.
            $sessions = get_user_meta($user_id, 'session_tokens', true);
            if (is_array($sessions)) {
                $hashed = hash('sha256', $session_token);
                $modified = false;

                // Check if $session_token is already the verifier hash (as returned by session_tokens user meta)
                if (isset($sessions[$session_token])) {
                    unset($sessions[$session_token]);
                    $modified = true;
                }
                // Check if $session_token was the raw plain text token
                if (isset($sessions[$hashed])) {
                    unset($sessions[$hashed]);
                    $modified = true;
                }

                if ($modified) {
                    if (!empty($sessions)) {
                        update_user_meta($user_id, 'session_tokens', $sessions);
                    } else {
                        delete_user_meta($user_id, 'session_tokens');
                    }
                }
            }

            // 2. Also invoke WP_Session_Tokens core manager destroy()
            try {
                $manager = \WP_Session_Tokens::get_instance($user_id);
                if ($manager) {
                    $manager->destroy($session_token);
                }
            } catch (\Throwable $e) {}

            // Flush WordPress user meta cache
            wp_cache_delete($user_id, 'user_meta');

            // 3. Clean up SessionSentinel metadata in wcpscan_session_meta
            $sessions_meta = get_user_meta($user_id, 'wcpscan_session_meta', true) ?: [];
            if (is_array($sessions_meta)) {
                $hashed = hash('sha256', $session_token);
                unset($sessions_meta[$session_token]);
                unset($sessions_meta[$hashed]);
                update_user_meta($user_id, 'wcpscan_session_meta', $sessions_meta);
            }

            // 4. Mark session terminated in LoginHistoryManager if available
            if (class_exists('\\WcpScanner\\Auth\\LoginHistoryManager')) {
                \WcpScanner\Auth\LoginHistoryManager::record_session_terminated($user_id, $session_token);
            }

            // 5. If the terminated session belongs to the current logged-in user, clear auth cookies
            if ($user_id === get_current_user_id()) {
                $current_raw = wp_get_session_token();
                $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
                $raw_logged_in_cookie = (!empty($cookie_name) && isset($_COOKIE[$cookie_name])) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
                if (empty($current_raw) && !empty($raw_logged_in_cookie)) {
                    $cookie_elements = wp_parse_auth_cookie($raw_logged_in_cookie, 'logged_in');
                    if (!empty($cookie_elements['token'])) {
                        $current_raw = $cookie_elements['token'];
                    }
                }
                if ($current_raw === $session_token || hash('sha256', (string) $current_raw) === $session_token) {
                    if (function_exists('wp_clear_auth_cookie')) {
                        wp_clear_auth_cookie();
                    }
                }
            }

            return true;
        } catch (\Throwable $e) {
            error_log('[WCP Security] Error terminating session: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Terminate all other sessions except the current administrator's active device
     */
    public static function terminate_all_other_sessions(int $target_user_id = 0, bool $revoke_all_admins = false): bool {
        try {
            $current_user_id = get_current_user_id();
            $current_token = wp_get_session_token();

            $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
            $raw_logged_in_cookie = (!empty($cookie_name) && isset($_COOKIE[$cookie_name])) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
            if (empty($current_token) && !empty($raw_logged_in_cookie)) {
                $cookie_elements = wp_parse_auth_cookie($raw_logged_in_cookie, 'logged_in');
                if (!empty($cookie_elements['token'])) {
                    $current_token = $cookie_elements['token'];
                }
            }

            $current_verifier = !empty($current_token) ? hash('sha256', $current_token) : '';

            // If target_user_id is 0 or revoke_all_admins is true: terminate all sessions across all admin users except current device!
            if (empty($target_user_id) || $revoke_all_admins) {
                $admins = get_users(['role' => 'administrator', 'number' => 100]);
                foreach ($admins as $admin) {
                    if ($admin->ID === $current_user_id) {
                        self::terminate_user_other_sessions($admin->ID, $current_token, $current_verifier);
                    } else {
                        // Destroy all sessions for other admin users
                        try {
                            $manager = \WP_Session_Tokens::get_instance($admin->ID);
                            $manager->destroy_all();
                        } catch (\Throwable $e) {}
                        delete_user_meta($admin->ID, 'session_tokens');
                        delete_user_meta($admin->ID, 'wcpscan_session_meta');
                        wp_cache_delete($admin->ID, 'user_meta');
                    }
                }
                return true;
            }

            // If a specific target_user_id was specified:
            if ($target_user_id === $current_user_id) {
                self::terminate_user_other_sessions($target_user_id, $current_token, $current_verifier);
            } else {
                // Destroy all sessions for this target user
                try {
                    $manager = \WP_Session_Tokens::get_instance($target_user_id);
                    $manager->destroy_all();
                } catch (\Throwable $e) {}
                delete_user_meta($target_user_id, 'session_tokens');
                delete_user_meta($target_user_id, 'wcpscan_session_meta');
                wp_cache_delete($target_user_id, 'user_meta');
            }

            return true;
        } catch (\Throwable $e) {
            error_log('[WCP Security] Error terminating other sessions: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Helper to terminate a user's other sessions while strictly preserving their active session
     */
    private static function terminate_user_other_sessions(int $user_id, string $current_token, string $current_verifier): void {
        try {
            $sessions = get_user_meta($user_id, 'session_tokens', true);
            if (is_array($sessions) && !empty($current_verifier)) {
                $preserved = isset($sessions[$current_verifier]) ? [$current_verifier => $sessions[$current_verifier]] : [];
                if (!empty($preserved)) {
                    update_user_meta($user_id, 'session_tokens', $preserved);
                } else {
                    $manager = \WP_Session_Tokens::get_instance($user_id);
                    $manager->destroy_others($current_token);
                }
            } else {
                $manager = \WP_Session_Tokens::get_instance($user_id);
                $manager->destroy_others($current_token);
            }

            $sessions_meta = get_user_meta($user_id, 'wcpscan_session_meta', true) ?: [];
            $preserved_meta = [];
            if (isset($sessions_meta[$current_token])) {
                $preserved_meta[$current_token] = $sessions_meta[$current_token];
            }
            if (isset($sessions_meta[$current_verifier])) {
                $preserved_meta[$current_verifier] = $sessions_meta[$current_verifier];
            }
            update_user_meta($user_id, 'wcpscan_session_meta', $preserved_meta);

            wp_cache_delete($user_id, 'user_meta');
        } catch (\Throwable $e) {}
    }

    /**
     * Cleanup on logout
     */
    public static function on_user_logout() {
        $user_id = get_current_user_id();
        $current_token = wp_get_session_token();

        if ($user_id && $current_token) {
            $sessions_meta = get_user_meta($user_id, 'wcpscan_session_meta', true) ?: [];
            $verifier = hash('sha256', $current_token);
            unset($sessions_meta[$current_token]);
            unset($sessions_meta[$verifier]);
            update_user_meta($user_id, 'wcpscan_session_meta', $sessions_meta);
        }
    }

    /**
     * Retrieve all active sessions across administrator accounts
     */
    public static function get_active_sessions(): array {
        $current_user_id = get_current_user_id();
        $current_token   = wp_get_session_token();

        // When called via REST API or admin-ajax, wp_get_session_token() can be empty.
        // Fall back to extracting the token directly from the authenticated logged_in cookie.
        $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : '';
        $raw_logged_in_cookie = (!empty($cookie_name) && isset($_COOKIE[$cookie_name])) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
        if (empty($current_token) && !empty($raw_logged_in_cookie)) {
            $cookie_elements = wp_parse_auth_cookie($raw_logged_in_cookie, 'logged_in');
            if (!empty($cookie_elements['token'])) {
                $current_token = $cookie_elements['token'];
            }
        }

        $current_verifier = !empty($current_token) ? hash('sha256', $current_token) : '';
        $client_ip = FirewallEngine::get_client_ip();

        // Get admin users
        $admins = get_users(['role' => 'administrator', 'number' => 50]);
        $results = [];
        $now = time();

        foreach ($admins as $admin) {
            // WordPress stores sessions in user meta 'session_tokens' as an associative array keyed by the SHA-256 verifier.
            $wp_sessions = get_user_meta($admin->ID, 'session_tokens', true);
            if (!is_array($wp_sessions) || empty($wp_sessions)) {
                continue;
            }
            $sessions_meta = get_user_meta($admin->ID, 'wcpscan_session_meta', true) ?: [];

            foreach ($wp_sessions as $verifier => $data) {
                if (!is_array($data)) {
                    continue;
                }
                // Filter out expired sessions
                if (isset($data['expiration']) && (int) $data['expiration'] <= $now) {
                    continue;
                }

                $meta = $sessions_meta[$verifier] ?? ($sessions_meta[$current_token] ?? []);

                // Determine if this is the current active session
                $is_current = false;
                if ($admin->ID === $current_user_id) {
                    if (!empty($current_verifier) && $verifier === $current_verifier) {
                        $is_current = true;
                    } elseif (!empty($current_token) && $verifier === $current_token) {
                        $is_current = true;
                    }
                }

                $ip = 'Unknown';
                $ua = 'Unknown';
                if (!empty($meta['encrypted_meta'])) {
                    $decrypted_meta = \WcpScanner\Security\SecretVault::decrypt((string) $meta['encrypted_meta']);
                    $decoded = is_string($decrypted_meta) ? (json_decode($decrypted_meta, true) ?: []) : [];
                    $ip = $decoded['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                    $ua = $decoded['user_agent'] ?? ($data['ua'] ?? 'Unknown');
                } else {
                    $ip = $meta['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                    $ua = $meta['user_agent'] ?? ($data['ua'] ?? 'Unknown');
                }

                // If $ip belongs to Cloudflare's Anycast proxy network, it's an edge node, not the visitor's device.
                // Heal current active session directly to the verified client IP.
                if (\WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($ip)) {
                    if ($is_current) {
                        $ip = $client_ip;
                        $entry = [
                            'login_time'     => isset($data['login']) ? (int) $data['login'] : time(),
                            'last_seen'      => time(),
                            'encrypted_meta' => \WcpScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                                'login_ip'   => $client_ip,
                                'user_agent' => $ua,
                            ])),
                        ];
                        $sessions_meta[$verifier] = $entry;
                        if (!empty($current_token)) {
                            $sessions_meta[$current_token] = $entry;
                        }
                        update_user_meta($admin->ID, 'wcpscan_session_meta', $sessions_meta);
                    }
                }

                // Determine browser / OS info
                $browser_info = self::parse_user_agent($ua);

                $login_ts = isset($meta['login_time']) ? (int) $meta['login_time'] : (isset($data['login']) ? (int) $data['login'] : time());
                $duration_sec = max(1, time() - $login_ts);
                $duration_formatted = class_exists('\\WcpScanner\\Auth\\LoginHistoryManager') 
                    ? \WcpScanner\Auth\LoginHistoryManager::format_duration($duration_sec)
                    : sprintf('%d mins', round($duration_sec / 60));

                $results[] = [
                    'session_id'               => substr((string) $verifier, 0, 16),
                    'token'                    => (string) $verifier,
                    'user_id'                  => $admin->ID,
                    'user_login'               => $admin->user_login,
                    'display_name'             => $admin->display_name ?: $admin->user_login,
                    'user_email'               => $admin->user_email,
                    'avatar_url'               => get_avatar_url($admin->ID, ['size' => 48]),
                    'is_current'               => $is_current,
                    'login_ip'                 => $ip,
                    'is_same_ip'               => ($ip === $client_ip),
                    'login_time'               => date_i18n('Y-m-d H:i:s', $login_ts),
                    'login_time_raw'           => $login_ts,
                    'login_time_human'         => human_time_diff($login_ts, time()) . ' ago',
                    'login_duration_seconds'   => $duration_sec,
                    'login_duration_formatted' => $duration_formatted,
                    'last_seen'                => isset($meta['last_seen']) ? date_i18n('Y-m-d H:i:s', $meta['last_seen']) : 'Recently',
                    'expiration'               => isset($data['expiration']) ? date_i18n('Y-m-d H:i:s', $data['expiration']) : null,
                    'browser'                  => $browser_info['browser'],
                    'platform'                 => $browser_info['platform'],
                    'user_agent'               => $ua,
                ];
            }
        }

        // If no session was matched directly by token (e.g. REST API environment cookie variations),
        // fallback to flagging the active user's newest session on the matching client IP as current.
        $has_current = false;
        foreach ($results as $res) {
            if (!empty($res['is_current'])) {
                $has_current = true;
                break;
            }
        }

        if (!$has_current && !empty($results)) {
            $best_match_idx = null;
            $best_time = 0;
            foreach ($results as $idx => $res) {
                if ($res['user_id'] === $current_user_id) {
                    $score = 0;
                    if ($res['is_same_ip']) {
                        $score += 1000;
                    }
                    if ($best_match_idx === null || $score > $best_time) {
                        $best_time = $score;
                        $best_match_idx = $idx;
                    }
                }
            }
            if ($best_match_idx !== null) {
                $results[$best_match_idx]['is_current'] = true;
            }
        }

        return $results;
    }

    /**
     * Simple parser for Browser & OS
     */
    private static function parse_user_agent(string $ua): array {
        $platform = 'Unknown OS';
        if (stripos($ua, 'Windows') !== false) {
            $platform = 'Windows';
        } elseif (stripos($ua, 'Macintosh') !== false || stripos($ua, 'Mac OS') !== false) {
            $platform = 'macOS';
        } elseif (stripos($ua, 'Linux') !== false) {
            $platform = 'Linux';
        } elseif (stripos($ua, 'Android') !== false) {
            $platform = 'Android';
        } elseif (stripos($ua, 'iPhone') !== false || stripos($ua, 'iPad') !== false) {
            $platform = 'iOS';
        }

        $browser = 'Browser';
        if (stripos($ua, 'Edg') !== false) {
            $browser = 'Microsoft Edge';
        } elseif (stripos($ua, 'Chrome') !== false) {
            $browser = 'Google Chrome';
        } elseif (stripos($ua, 'Firefox') !== false) {
            $browser = 'Mozilla Firefox';
        } elseif (stripos($ua, 'Safari') !== false) {
            $browser = 'Apple Safari';
        } elseif (stripos($ua, 'Opera') !== false || stripos($ua, 'OPR') !== false) {
            $browser = 'Opera';
        }

        return [
            'browser'  => $browser,
            'platform' => $platform,
        ];
    }
}
