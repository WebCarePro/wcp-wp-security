<?php
namespace WcpScanner\Auth;

use WcpScanner\System\SettingsManager;
use WcpScanner\Firewall\FirewallEngine;

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

    const OPTION_LOCKOUTS   = 'wcpscan_login_lockouts';
    const TRANSIENT_FAIL_PREFIX = 'wcpscan_lgn_fail_';

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

        // Real-time Rogue Admin & Elevated Privilege Monitor
        add_action('user_register', [__CLASS__, 'on_user_registered']);
        add_action('set_user_role', [__CLASS__, 'on_user_role_changed'], 10, 3);
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
                    'wcpscan_ip_locked',
                    sprintf(
                        /* translators: 1: IP address, 2: remaining minutes */
                        __('<strong>Access Blocked:</strong> Too many failed login attempts from your IP (%1$s). You are temporarily locked out for security. Please try again in %2$d minute(s).', 'wcp-security-scanner'),
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

        // Check if IP is whitelisted (whitelisted IPs bypass login brute force lockouts with telemetry)
        if (!empty($settings['waf_whitelisted_ips']) && FirewallEngine::is_ip_whitelisted($ip, $settings['waf_whitelisted_ips'])) {
            $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
            if ($log_telemetry) {
                $fail_key = self::TRANSIENT_FAIL_PREFIX . md5($ip);
                $attempts = (int) get_transient($fail_key) + 1;
                set_transient($fail_key, $attempts, 3600);
                $max_retries = (int) ($settings['login_max_retries'] ?? 5);
                if ($attempts >= $max_retries) {
                    FirewallEngine::log_incident([
                        'id'          => 'WAF-LOGIN-BRUTEFORCE-BYPASS',
                        'name'        => 'Login Brute Force Threshold Exceeded (Bypassed)',
                        'category'    => 'Brute Force & Auth Armor',
                        'description' => sprintf('Failed login threshold exceeded (%d attempts for user "%s") [Bypassed via IP Whitelist].', $attempts, esc_html($username)),
                        'payload'     => "User: {$username} Attempts: {$attempts} IP: {$ip}",
                    ], 'bypassed');
                }
            }
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
                'blocked_at'  => gmdate('Y-m-d H:i:s', $now),
                'expires_at'  => $now + $lockout_seconds,
                'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            ];

            update_option(self::OPTION_LOCKOUTS, $lockouts, false);
            delete_transient($fail_key);

            // Trigger audit log if available
            if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
                \WcpScanner\System\AuditLogger::log_event(
                    'login_lockout',
                    sprintf(
                        /* translators: 1: IP address, 2: attempt count, 3: username */
                        __('IP %1$s temporarily locked out after %2$d failed login attempts for user "%3$s".', 'wcp-security-scanner'),
                        $ip,
                        $attempts,
                        $username
                    )
                );
            }

            // Trigger granular notification via NotificationDispatcher
            if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_bruteforce_lockout', [
                    'severity' => 'high',
                    'message'  => sprintf(
                        /* translators: 1: attacker IP, 2: attempt count, 3: username */
                        __('Brute-force defense locked out IP "%1$s" after %2$d consecutive login failures targeting username "%3$s".', 'wcp-security-scanner'),
                        $ip,
                        $attempts,
                        $username
                    ),
                    'details'  => [
                        'attacker_ip'      => $ip,
                        'target_username'  => $username,
                        'failed_attempts'  => $attempts,
                        'lockout_duration' => $lockout_duration . ' minutes',
                    ],
                ]);
            }

            // Sync brute force attacker to Cloudflare Edge IP Access Rules if enabled
            if (!empty($settings['cloudflare_auto_sync_bans']) && class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
                \WcpScanner\Cloudflare\CloudflareService::block_ip(
                    $ip,
                    "WCP Brute Force: {$attempts} failed logins for {$username}"
                );

                if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                    \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_cf_edge_ban_synced', [
                        'severity' => 'info',
                        'message'  => sprintf(
                            /* translators: %s: banned IP address */
                            __('Attacker IP "%s" was escalated and synchronized to Cloudflare Edge IP Access Rules.', 'wcp-security-scanner'),
                            $ip
                        ),
                        'details'  => [
                            'banned_ip' => $ip,
                            'reason'    => "Brute force lockout ({$attempts} attempts)",
                        ],
                    ]);
                }
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

    /**
     * Hook: Detect newly registered Administrator accounts
     */
    public static function on_user_registered($user_id): void {
        $user = get_userdata($user_id);
        if ($user && in_array('administrator', (array) $user->roles, true)) {
            if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_rogue_admin_created', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: username, 2: email */
                        __('A new user account with Administrator privileges was registered: "%1$s" (%2$s).', 'wcp-security-scanner'),
                        $user->user_login,
                        $user->user_email
                    ),
                    'details'  => [
                        'user_id'    => $user_id,
                        'user_login' => $user->user_login,
                        'user_email' => $user->user_email,
                        'created_at' => current_time('mysql'),
                        'ip_address' => FirewallEngine::get_client_ip(),
                    ],
                ]);
            }
        }
    }

    /**
     * Hook: Detect user privilege escalation to Administrator
     */
    public static function on_user_role_changed($user_id, $role, $old_roles): void {
        if ($role === 'administrator' && !in_array('administrator', (array) $old_roles, true)) {
            if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                $user = get_userdata($user_id);
                \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_rogue_admin_created', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: %s: username */
                        __('Existing user "%s" was promoted to Administrator role.', 'wcp-security-scanner'),
                        $user ? $user->user_login : 'user #' . $user_id
                    ),
                    'details'  => [
                        'user_id'    => $user_id,
                        'user_login' => $user ? $user->user_login : 'user_' . $user_id,
                        'old_roles'  => implode(', ', (array) $old_roles),
                        'new_role'   => $role,
                        'promoted_at'=> current_time('mysql'),
                        'ip_address' => FirewallEngine::get_client_ip(),
                    ],
                ]);
            }
        }
    }
}
