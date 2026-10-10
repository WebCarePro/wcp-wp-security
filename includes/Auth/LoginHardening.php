<?php
namespace WCP\Scanner\Auth;

use WCP\Scanner\System\SettingsManager;
use WCP\Scanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Login Hardening & Brute Force Defense Service
 *
 * Intercepts failed login attempts, tracks client IP frequency,
 * enforces automatic lockouts, and blocks brute-force credentials stuffing.
 */
class LoginHardening {

    const OPTION_LOCKOUTS   = 'wcp_login_lockouts';
    const TRANSIENT_FAIL_PREFIX = 'wcp_lgn_fail_';

    /**
     * Initialize login hardening hooks
     */
    public static function init() {
        // Enforce lockout check early in authentication
        add_filter('authenticate', [__CLASS__, 'check_ip_lockout'], 25, 3);

        // Record failed attempt
        add_action('wp_login_failed', [__CLASS__, 'record_failed_attempt']);

        // Reset failed attempt count on successful login
        add_action('wp_login', [__CLASS__, 'record_successful_login'], 10, 2);
    }

    /**
     * Check if client IP is currently locked out
     */
    public static function check_ip_lockout($user, $username, $password) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['login_hardening_enabled'])) {
            return $user;
        }

        $ip = FirewallEngine::get_client_ip();

        // Check user IP whitelist
        if (!empty($settings['waf_whitelisted_ips']) && FirewallEngine::is_ip_whitelisted($ip, $settings['waf_whitelisted_ips'])) {
            return $user;
        }

        $lockouts = self::get_locked_ips();
        if (isset($lockouts[$ip])) {
            $lockout = $lockouts[$ip];
            $now     = time();

            if ($lockout['expires_at'] > $now) {
                $remaining_mins = max(1, (int) ceil(($lockout['expires_at'] - $now) / 60));

                return new \WP_Error(
                    'wcp_ip_locked',
                    sprintf(
                        __('<strong>Access Blocked:</strong> Too many failed login attempts from your IP (%s). You are temporarily locked out for security. Please try again in %d minute(s).', 'wcp-security-scanner'),
                        esc_html($ip),
                        $remaining_mins
                    )
                );
            } else {
                // Lockout expired, clean up
                self::unlock_ip($ip);
            }
        }

        return $user;
    }

    /**
     * Record a failed login attempt
     */
    public static function record_failed_attempt(string $username) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['login_hardening_enabled'])) {
            return;
        }

        $ip = FirewallEngine::get_client_ip();

        // Check if IP is whitelisted
        if (!empty($settings['waf_whitelisted_ips']) && FirewallEngine::is_ip_whitelisted($ip, $settings['waf_whitelisted_ips'])) {
            return;
        }

        $max_retries      = (int) ($settings['login_max_retries'] ?? 5);
        $lockout_duration = (int) ($settings['login_lockout_duration'] ?? 15); // in minutes
        $lockout_seconds  = max(60, $lockout_duration * 60);

        $fail_key = self::TRANSIENT_FAIL_PREFIX . md5($ip);
        $attempts = (int) get_transient($fail_key);
        $attempts++;

        // Store failed count with a sliding 1-hour window
        set_transient($fail_key, $attempts, 3600);

        if ($attempts >= $max_retries) {
            // Lock out IP
            $lockouts = self::get_locked_ips();
            $now      = time();

            $lockouts[$ip] = [
                'ip'          => $ip,
                'attempts'    => $attempts,
                'username'    => sanitize_user($username),
                'blocked_at'  => date('Y-m-d H:i:s', $now),
                'expires_at'  => $now + $lockout_seconds,
                'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            ];

            update_option(self::OPTION_LOCKOUTS, $lockouts, false);
            delete_transient($fail_key);

            // Trigger audit log if available
            if (class_exists('\\WCP\\Scanner\\System\\AuditLogger')) {
                \WCP\Scanner\System\AuditLogger::log(
                    'login_lockout',
                    sprintf(__('IP %s temporarily locked out after %d failed login attempts for user "%s".', 'wcp-security-scanner'), $ip, $attempts, $username)
                );
            }
        }
    }

    /**
     * Reset attempt counter on valid login
     */
    public static function record_successful_login(string $user_login, $user) {
        $ip = FirewallEngine::get_client_ip();
        $fail_key = self::TRANSIENT_FAIL_PREFIX . md5($ip);
        delete_transient($fail_key);
    }

    /**
     * Get list of currently locked out IPs
     */
    public static function get_locked_ips(): array {
        $lockouts = get_option(self::OPTION_LOCKOUTS, []);
        if (!is_array($lockouts)) {
            return [];
        }

        // Clean expired lockouts
        $now     = time();
        $cleaned = [];
        $changed = false;

        foreach ($lockouts as $ip => $data) {
            if (isset($data['expires_at']) && $data['expires_at'] > $now) {
                $cleaned[$ip] = $data;
            } else {
                $changed = true;
            }
        }

        if ($changed) {
            update_option(self::OPTION_LOCKOUTS, $cleaned, false);
        }

        return $cleaned;
    }

    /**
     * Unlock a specific IP address
     */
    public static function unlock_ip(string $ip): bool {
        $ip = trim($ip);
        $lockouts = get_option(self::OPTION_LOCKOUTS, []);
        if (is_array($lockouts) && isset($lockouts[$ip])) {
            unset($lockouts[$ip]);
            update_option(self::OPTION_LOCKOUTS, $lockouts, false);
            delete_transient(self::TRANSIENT_FAIL_PREFIX . md5($ip));
            return true;
        }
        delete_transient(self::TRANSIENT_FAIL_PREFIX . md5($ip));
        return true;
    }

    /**
     * Unlock all locked IPs
     */
    public static function clear_all_lockouts(): bool {
        update_option(self::OPTION_LOCKOUTS, [], false);
        return true;
    }

    /**
     * Get lockout statistics
     */
    public static function get_stats(): array {
        $locked = self::get_locked_ips();
        return [
            'total_locked' => count($locked),
            'locked_ips'   => array_values($locked),
        ];
    }
}
