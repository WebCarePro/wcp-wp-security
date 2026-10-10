<?php
namespace WCP\Scanner\Auth;

use WCP\Scanner\System\SettingsManager;
use WCP\Scanner\Firewall\FirewallEngine;

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

    /**
     * Bootstrap Session Sentinel
     */
    public static function init() {
        // Track session upon login
        add_action('wp_login', [__CLASS__, 'on_user_login'], 20, 2);

        // Verify session integrity on every authenticated request
        add_action('init', [__CLASS__, 'inspect_active_session'], 2);

        // Cleanup on logout
        add_action('wp_logout', [__CLASS__, 'on_user_logout']);
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

        $session_token = wp_get_session_token();
        $ip = FirewallEngine::get_client_ip();
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

        // Check concurrent sessions count
        if (!empty($settings['session_block_concurrent']) && $user->has_cap('administrator')) {
            $manager = \WP_Session_Tokens::get_instance($user->ID);
            $all_sessions = $manager->get_all();
            
            // If already logged in on other devices/IPs, destroy other sessions
            if (count($all_sessions) > 1 && $session_token) {
                $manager->destroy_others($session_token);
            }
        }

        // Store session metadata in user meta
        $sessions_meta = get_user_meta($user->ID, 'wcp_session_meta', true) ?: [];
        if (!is_array($sessions_meta)) {
            $sessions_meta = [];
        }

        if ($session_token) {
            $sessions_meta[$session_token] = [
                'login_time' => time(),
                'last_seen'  => time(),
                'login_ip'   => $ip,
                'user_agent' => substr(sanitize_text_field($ua), 0, 255),
            ];

            // Limit stored metadata to active WP sessions
            update_user_meta($user->ID, 'wcp_session_meta', $sessions_meta);
        }
    }

    /**
     * Inspect session on each authenticated request to defend against hijacked cookies
     */
    public static function inspect_active_session() {
        if (!is_user_logged_in()) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['session_sentinel_enabled'])) {
            return;
        }

        $user_id = get_current_user_id();
        $user = wp_get_current_user();

        // Focus on administrative and editor sessions
        if (!$user->has_cap('edit_posts')) {
            return;
        }

        $current_token = wp_get_session_token();
        if (!$current_token) {
            return;
        }

        $ip = FirewallEngine::get_client_ip();
        $sessions_meta = get_user_meta($user_id, 'wcp_session_meta', true);
        if (!is_array($sessions_meta)) {
            $sessions_meta = [];
        }

        // Auto-initialize if session was active before sentinel activation
        if (!isset($sessions_meta[$current_token])) {
            $sessions_meta[$current_token] = [
                'login_time' => time(),
                'last_seen'  => time(),
                'login_ip'   => $ip,
                'user_agent' => substr(sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'), 0, 255),
            ];
            update_user_meta($user_id, 'wcp_session_meta', $sessions_meta);
            return;
        }

        $session_info = $sessions_meta[$current_token];

        // 1. IP Lock / Hijack Defense Check
        if (!empty($settings['session_lock_ip']) && !empty($session_info['login_ip'])) {
            if ($session_info['login_ip'] !== $ip) {
                // Potential cookie replay or session hijack from a different IP address!
                self::terminate_session($user_id, $current_token, 'Session terminated due to IP address mismatch (Anti-Hijack Lock).');
                wp_safe_redirect(wp_login_url() . '?wcp_session_alert=ip_mismatch');
                exit;
            }
        }

        // 2. Max Idle Session Timeout Check
        $idle_timeout_minutes = (int) ($settings['session_idle_timeout'] ?? 120); // Default 120 minutes
        if ($idle_timeout_minutes > 0 && isset($session_info['last_seen'])) {
            $max_idle_seconds = $idle_timeout_minutes * 60;
            if ((time() - $session_info['last_seen']) > $max_idle_seconds) {
                self::terminate_session($user_id, $current_token, 'Session expired due to inactivity.');
                wp_safe_redirect(wp_login_url() . '?wcp_session_alert=idle_timeout');
                exit;
            }
        }

        // Update last seen timestamp (throttled every 60 seconds to save DB writes)
        if (time() - ($session_info['last_seen'] ?? 0) > 60) {
            $sessions_meta[$current_token]['last_seen'] = time();
            update_user_meta($user_id, 'wcp_session_meta', $sessions_meta);
        }
    }

    /**
     * Terminate an individual session
     */
    public static function terminate_session(int $user_id, string $session_token, string $reason = '') {
        $manager = \WP_Session_Tokens::get_instance($user_id);
        $manager->destroy($session_token);

        $sessions_meta = get_user_meta($user_id, 'wcp_session_meta', true) ?: [];
        if (isset($sessions_meta[$session_token])) {
            unset($sessions_meta[$session_token]);
            update_user_meta($user_id, 'wcp_session_meta', $sessions_meta);
        }
    }

    /**
     * Terminate all other sessions except current
     */
    public static function terminate_all_other_sessions(int $user_id): bool {
        $current_token = wp_get_session_token();
        $manager = \WP_Session_Tokens::get_instance($user_id);
        
        if ($current_token) {
            $manager->destroy_others($current_token);

            $sessions_meta = get_user_meta($user_id, 'wcp_session_meta', true) ?: [];
            $preserved = isset($sessions_meta[$current_token]) ? [$current_token => $sessions_meta[$current_token]] : [];
            update_user_meta($user_id, 'wcp_session_meta', $preserved);
        } else {
            $manager->destroy_all();
            delete_user_meta($user_id, 'wcp_session_meta');
        }

        return true;
    }

    /**
     * Cleanup on logout
     */
    public static function on_user_logout() {
        $user_id = get_current_user_id();
        $current_token = wp_get_session_token();

        if ($user_id && $current_token) {
            $sessions_meta = get_user_meta($user_id, 'wcp_session_meta', true) ?: [];
            if (isset($sessions_meta[$current_token])) {
                unset($sessions_meta[$current_token]);
                update_user_meta($user_id, 'wcp_session_meta', $sessions_meta);
            }
        }
    }

    /**
     * Retrieve all active sessions across administrator accounts
     */
    public static function get_active_sessions(): array {
        $current_user_id = get_current_user_id();
        $current_token   = wp_get_session_token();
        $client_ip       = FirewallEngine::get_client_ip();

        // Get admin users
        $admins = get_users(['role' => 'administrator', 'number' => 25]);
        $results = [];

        foreach ($admins as $admin) {
            $manager = \WP_Session_Tokens::get_instance($admin->ID);
            $wp_sessions = $manager->get_all();
            $sessions_meta = get_user_meta($admin->ID, 'wcp_session_meta', true) ?: [];

            foreach ($wp_sessions as $token => $data) {
                $meta = $sessions_meta[$token] ?? [];
                $is_current = ($admin->ID === $current_user_id && $token === $current_token);
                $ip = $meta['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                $ua = $meta['user_agent'] ?? ($data['ua'] ?? 'Unknown');

                // Determine browser / OS info
                $browser_info = self::parse_user_agent($ua);

                $results[] = [
                    'session_id'   => substr(hash('sha256', $token), 0, 16),
                    'token'        => $token,
                    'user_id'      => $admin->ID,
                    'user_login'   => $admin->user_login,
                    'user_email'   => $admin->user_email,
                    'avatar_url'   => get_avatar_url($admin->ID, ['size' => 48]),
                    'is_current'   => $is_current,
                    'login_ip'     => $ip,
                    'is_same_ip'   => ($ip === $client_ip),
                    'login_time'   => isset($meta['login_time']) ? date_i18n('Y-m-d H:i:s', $meta['login_time']) : (isset($data['login']) ? date_i18n('Y-m-d H:i:s', $data['login']) : 'Active'),
                    'last_seen'    => isset($meta['last_seen']) ? date_i18n('Y-m-d H:i:s', $meta['last_seen']) : 'Recently',
                    'expiration'   => isset($data['expiration']) ? date_i18n('Y-m-d H:i:s', $data['expiration']) : null,
                    'browser'      => $browser_info['browser'],
                    'platform'     => $browser_info['platform'],
                    'user_agent'   => $ua,
                ];
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
