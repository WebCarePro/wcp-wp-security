<?php
namespace WebCareProScanner\Auth;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\FirewallEngine;

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

    const OPTION_LOCKOUTS   = 'webcareproscan_login_lockouts';
    const TRANSIENT_FAIL_PREFIX = 'webcareproscan_lgn_fail_';

    /**
     * Initialize login hardening hooks
     */
    public static function init() {
        // Enforce lockout check early in authentication
        add_filter('authenticate', [__CLASS__, 'check_ip_lockout'], 25, 3);

        // Record failed attempt with failure context ($error)
        add_action('wp_login_failed', [__CLASS__, 'record_failed_attempt'], 10, 2);

        // Reset failed attempt count on successful login
        add_action('wp_login', [__CLASS__, 'record_successful_login'], 10, 2);

        // Real-time Rogue Admin & Elevated Privilege Monitor
        add_action('user_register', [__CLASS__, 'on_user_registered']);
        add_action('set_user_role', [__CLASS__, 'on_user_role_changed'], 10, 3);

        // Administrator Password Reset & Profile Password Change Monitor
        add_action('password_reset', [__CLASS__, 'on_password_reset'], 10, 2);
        add_action('profile_update', [__CLASS__, 'on_profile_update'], 10, 2);
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
                    'webcareproscan_ip_locked',
                    sprintf(
                        /* translators: 1: IP address, 2: remaining minutes */
                        __('<strong>Access Blocked:</strong> Too many failed login attempts from your IP (%1$s). You are temporarily locked out for security. Please try again in %2$d minute(s).', 'webcare-pro-security'),
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
     *
     * @param string                $username The attempted username or email.
     * @param \WP_Error|mixed|null  $error    The authentication failure error object if passed by core/plugins.
     */
    public static function record_failed_attempt(string $username, $error = null) {
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

        // Record global cross-IP authentication failure for distributed credential-stuffing defense
        if (class_exists('\\WebCareProScanner\\Firewall\\DistributedVelocityShield')) {
            \WebCareProScanner\Firewall\DistributedVelocityShield::record_auth_failure($ip, $username, $reason_label ?? '');
        }

        // Determine specific failure diagnosis (wrong password vs non-existent account)
        $reason_label = __('Unknown failure reason', 'webcare-pro-security');
        $error_code   = '';
        if ($error instanceof \WP_Error) {
            $error_code = (string) $error->get_error_code();
            switch ($error_code) {
                case 'incorrect_password':
                    $reason_label = __('Incorrect password (account exists)', 'webcare-pro-security');
                    break;
                case 'invalid_username':
                    $reason_label = __('Unknown username (account does not exist)', 'webcare-pro-security');
                    break;
                case 'invalid_email':
                    $reason_label = __('Unknown email address (account does not exist)', 'webcare-pro-security');
                    break;
                case 'empty_password':
                    $reason_label = __('Empty password submitted', 'webcare-pro-security');
                    break;
                case 'empty_username':
                    $reason_label = __('Empty username submitted', 'webcare-pro-security');
                    break;
                default:
                    $custom_msg   = sanitize_text_field($error->get_error_message());
                    $reason_label = !empty($custom_msg) ? $custom_msg : $error_code;
                    break;
            }
        } else {
            // Fallback user existence check when caller does not provide WP_Error
            $user_exists = is_email($username) ? (bool) get_user_by('email', $username) : (bool) get_user_by('login', $username);
            if ($user_exists) {
                $reason_label = __('Incorrect credentials (account exists)', 'webcare-pro-security');
            } else {
                $reason_label = __('Unknown identity (account does not exist)', 'webcare-pro-security');
            }
        }

        // Action taken: failed attempt monitored vs locked out threshold
        $action_taken = ($attempts >= $max_retries) ? 'blocked' : 'failed';

        // Stream individual failed login attempt to WAF Forensic Incident Log
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            \WebCareProScanner\Firewall\FirewallEngine::log_incident([
                'id'               => 'WAF-AUTH-FAILED',
                'name'             => 'Failed Authentication Attempt',
                'category'         => 'authentication',
                'description'      => sprintf(
                    /* translators: 1: attempted username, 2: attempt count, 3: specific failure reason */
                    __('Failed authentication for "%1$s" (attempt %2$d): %3$s.', 'webcare-pro-security'),
                    sanitize_user($username),
                    $attempts,
                    $reason_label
                ),
                'payload'          => sprintf('User: %s (Attempt %d) | Reason: %s', $username, $attempts, $reason_label),
                'username'         => sanitize_user($username),
                'is_authenticated' => false,
            ], $action_taken);
        }

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

            // Log security incident to WAF Forensic incident log
            if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
                \WebCareProScanner\Firewall\FirewallEngine::log_incident([
                    'id'          => 'WAF-LOGIN-BRUTEFORCE',
                    'name'        => 'Login Brute-Force Rate Limiter',
                    'category'    => 'Brute Force & Auth Armor',
                    'description' => sprintf(
                        /* translators: 1: IP address, 2: attempt count, 3: username */
                        __('IP %1$s locked out for %2$d failed login attempts targeting user "%3$s".', 'webcare-pro-security'),
                        $ip,
                        $attempts,
                        sanitize_user($username)
                    ),
                    'payload'     => "User: {$username} Attempts: {$attempts} IP: {$ip}",
                ], 'blocked');
            }

            // Trigger audit log if available (internal audit log file)
            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'login_lockout',
                    sprintf(
                        /* translators: 1: IP address, 2: attempt count, 3: username */
                        __('IP %1$s temporarily locked out after %2$d failed login attempts for user "%3$s".', 'webcare-pro-security'),
                        $ip,
                        $attempts,
                        $username
                    )
                );
            }

            // Trigger granular notification via NotificationDispatcher
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_bruteforce_lockout', [
                    'severity' => 'high',
                    'message'  => sprintf(
                        /* translators: 1: attacker IP, 2: attempt count, 3: username */
                        __('Brute-force defense locked out IP "%1$s" after %2$d consecutive login failures targeting username "%3$s".', 'webcare-pro-security'),
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

            // Sync brute-force attacker to local blocklist & Cloudflare Edge with automatic TTL expiration
            if (!empty($settings['cloudflare_auto_sync_bans']) && class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
                $incident_id = 'WEBCARE-' . strtoupper(substr(md5($ip . microtime(true)), 0, 8));
                \WebCareProScanner\Firewall\FirewallEngine::add_blocked_ip(
                    $ip,
                    sprintf('Brute Force Lockout: %d failed logins targeting "%s"', (int) $attempts, sanitize_user((string) $username, true)),
                    max(300, ((int) $lockout_duration) * 60),
                    'WAF-AUTH-BRUTE-FORCE',
                    'Login Brute-Force Lockout',
                    'Identity Defense',
                    $incident_id
                );

                if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_cf_edge_ban_synced', [
                        'severity' => 'info',
                        'message'  => sprintf(
                            /* translators: %s: banned IP address */
                            __('Attacker IP "%s" was escalated and synchronized to Cloudflare Edge IP Access Rules.', 'webcare-pro-security'),
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
     * Reset attempt counter on valid login and record successful authentication in WAF logs
     */
    public static function record_successful_login(string $user_login, $user) {
        $ip = FirewallEngine::get_client_ip();
        $fail_key = self::TRANSIENT_FAIL_PREFIX . md5($ip);
        delete_transient($fail_key);

        // Stream successful login to WAF Forensic Incident Log
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            $user_obj = ($user instanceof \WP_User) ? $user : get_user_by('login', $user_login);
            $roles = ($user_obj instanceof \WP_User) ? (array) $user_obj->roles : [];
            $role_label = !empty($roles) ? reset($roles) : 'user';
            $user_id = ($user_obj instanceof \WP_User) ? (int) $user_obj->ID : 0;

            \WebCareProScanner\Firewall\FirewallEngine::log_incident([
                'id'               => 'WAF-AUTH-SUCCESS',
                'name'             => 'Successful User Authentication',
                'category'         => 'authentication',
                'description'      => sprintf(
                    /* translators: 1: username, 2: role */
                    __('User "%1$s" (%2$s) authenticated successfully.', 'webcare-pro-security'),
                    sanitize_user($user_login),
                    sanitize_key($role_label)
                ),
                'payload'          => sprintf('User: %s Role: %s ID: %d', $user_login, $role_label, $user_id),
                'username'         => sanitize_user($user_login),
                'user_role'        => sanitize_key($role_label),
                'user_id'          => $user_id,
                'is_authenticated' => true,
            ], 'allowed');

            // Granular Alert: If an administrator authenticated, trigger immediate notification
            if (in_array('administrator', $roles, true) && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_admin_login', [
                    'severity' => 'info',
                    'message'  => sprintf(
                        /* translators: 1: admin username, 2: client IP address */
                        __('Administrator user "%1$s" logged in successfully from IP %2$s.', 'webcare-pro-security'),
                        sanitize_user($user_login),
                        $ip
                    ),
                    'details'  => [
                        'username'     => sanitize_user($user_login),
                        'role'         => 'Administrator',
                        'user_id'      => $user_id,
                        'ip_address'   => $ip,
                        'user_agent'   => substr($user_agent, 0, 160),
                        'login_time'   => current_time('mysql'),
                    ],
                ]);
            }
        }
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
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_rogue_admin_created', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: username, 2: email */
                        __('A new user account with Administrator privileges was registered: "%1$s" (%2$s).', 'webcare-pro-security'),
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
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                $user = get_userdata($user_id);
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_rogue_admin_created', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: %s: username */
                        __('Existing user "%s" was promoted to Administrator role.', 'webcare-pro-security'),
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

    /**
     * Hook: Detect password resets initiated via recovery link or WP-CLI/REST
     *
     * @param \WP_User|mixed $user
     * @param string $new_pass
     */
    public static function on_password_reset($user, $new_pass = ''): void {
        if (!($user instanceof \WP_User)) {
            return;
        }

        $is_admin = in_array('administrator', (array) $user->roles, true);
        if (!$is_admin) {
            return;
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            $ip = FirewallEngine::get_client_ip();
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';

            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_admin_password_reset', [
                'severity' => 'high',
                'message'  => sprintf(
                    /* translators: 1: admin username, 2: client IP address */
                    __('Administrator password was successfully reset for user "%1$s" from IP %2$s.', 'webcare-pro-security'),
                    $user->user_login,
                    $ip
                ),
                'details'  => [
                    'admin_user' => $user->user_login,
                    'user_email' => $user->user_email,
                    'user_id'    => $user->ID,
                    'action'     => 'Password Reset (Recovery Flow)',
                    'ip_address' => $ip,
                    'user_agent' => substr($user_agent, 0, 160),
                    'reset_at'   => current_time('mysql'),
                ],
            ]);
        }
    }

    /**
     * Hook: Detect password changes made directly inside wp-admin user profile edit screen
     *
     * @param int $user_id
     * @param \WP_User|null $old_user_data
     */
    public static function on_profile_update(int $user_id, $old_user_data = null): void {
        $user = get_userdata($user_id);
        if (!$user || !in_array('administrator', (array) $user->roles, true)) {
            return;
        }

        // Check if user_pass hash changed between updates
        if ($old_user_data && isset($old_user_data->user_pass) && $old_user_data->user_pass !== $user->user_pass) {
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                $ip = FirewallEngine::get_client_ip();
                $current_user = wp_get_current_user();
                $editor_name = ($current_user && $current_user->ID) ? $current_user->user_login : 'system/external';
                $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';

                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_admin_password_reset', [
                    'severity' => 'high',
                    'message'  => sprintf(
                        /* translators: 1: admin username, 2: editor username, 3: client IP address */
                        __('Administrator password for "%1$s" was updated by "%2$s" from IP %3$s.', 'webcare-pro-security'),
                        $user->user_login,
                        $editor_name,
                        $ip
                    ),
                    'details'  => [
                        'admin_user' => $user->user_login,
                        'user_email' => $user->user_email,
                        'user_id'    => $user->ID,
                        'updated_by' => $editor_name,
                        'action'     => 'Profile Password Update',
                        'ip_address' => $ip,
                        'user_agent' => substr($user_agent, 0, 160),
                        'updated_at' => current_time('mysql'),
                    ],
                ]);
            }
        }
    }
}
