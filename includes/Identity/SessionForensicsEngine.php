<?php
namespace WcpScanner\Identity;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;
use WcpScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SessionForensicsEngine
 *
 * Pillar 4: Zero-Trust Identity & Session Forensics.
 * Tracks active administrator & privileged sessions in real time.
 * Detects Impossible Travel (concurrent logins from disparate geolocations),
 * User-Agent fingerprint mismatches (cookie theft / token replay),
 * and computes granular 0-100% Session Risk Scores with 1-click global revocation.
 */
class SessionForensicsEngine {

    const OPTION_SETTINGS      = 'wcpscan_identity_forensics_settings';
    const OPTION_TRAVEL_ALERTS = 'wcpscan_impossible_travel_alerts';
    const META_SESSION_FINGERPRINTS = 'wcpscan_session_fingerprints';

    /**
     * Bootstrap Session Forensics Hooks.
     */
    public static function init() {
        add_action('wp_login', [__CLASS__, 'on_user_login'], 25, 2);
        add_action('init', [__CLASS__, 'inspect_active_session'], 5);
    }

    /**
     * Default settings for identity forensics.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'                       => true,
            'impossible_travel_enabled'     => true,
            'impossible_travel_hours'       => 2,
            'auto_revoke_impossible_travel' => false,
            'detect_ua_hijack'              => true,
            'notify_admin_on_suspicious'    => true,
        ];
        $saved = get_option(self::OPTION_SETTINGS, []);
        return is_array($saved) ? array_merge($defaults, $saved) : $defaults;
    }

    /**
     * Update settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();
        $updated = [
            'enabled'                       => !empty($new_settings['enabled']),
            'impossible_travel_enabled'     => !empty($new_settings['impossible_travel_enabled']),
            'impossible_travel_hours'       => max(1, min(24, intval($new_settings['impossible_travel_hours'] ?? 2))),
            'auto_revoke_impossible_travel' => !empty($new_settings['auto_revoke_impossible_travel']),
            'detect_ua_hijack'              => !empty($new_settings['detect_ua_hijack']),
            'notify_admin_on_suspicious'    => !empty($new_settings['notify_admin_on_suspicious']),
        ];
        update_option(self::OPTION_SETTINGS, $updated);
        return $updated;
    }

    /**
     * Hook on user login: capture fingerprint and evaluate Impossible Travel.
     *
     * @param string $user_login
     * @param \WP_User $user
     */
    public static function on_user_login(string $user_login, \WP_User $user) {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        // Only monitor privileged roles (Administrators and Editors)
        if (!$user->has_cap('edit_posts')) {
            return;
        }

        $client_ip = self::get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';
        $session_token = wp_get_session_token();
        $geo = self::resolve_ip_geo($client_ip);

        // Fetch existing session fingerprints for this user
        $fingerprints = get_user_meta($user->ID, self::META_SESSION_FINGERPRINTS, true);
        if (!is_array($fingerprints)) {
            $fingerprints = [];
        }

        // Evaluate Impossible Travel against existing active sessions
        if (!empty($settings['impossible_travel_enabled']) && !empty($fingerprints)) {
            $threshold_seconds = ($settings['impossible_travel_hours'] ?? 2) * 3600;

            foreach ($fingerprints as $prev_token => $fp) {
                $time_diff = abs(time() - ($fp['last_seen'] ?? 0));
                if ($time_diff <= $threshold_seconds && !empty($fp['ip']) && $fp['ip'] !== $client_ip) {
                    $prev_country = $fp['country'] ?? '';
                    $new_country = $geo['country'] ?? '';

                    // Flag if country changed within the time threshold (or cross-continent)
                    if (!empty($prev_country) && !empty($new_country) && $prev_country !== $new_country) {
                        self::record_impossible_travel_alert([
                            'user_id'       => $user->ID,
                            'user_login'    => $user_login,
                            'prev_ip'       => $fp['ip'],
                            'prev_country'  => $prev_country,
                            'prev_time'     => $fp['last_seen'],
                            'new_ip'        => $client_ip,
                            'new_country'   => $new_country,
                            'new_time'      => time(),
                            'delta_minutes' => round($time_diff / 60),
                        ]);

                        if (!empty($settings['auto_revoke_impossible_travel'])) {
                            // Immediately terminate the suspicious new session
                            wp_destroy_current_session();
                            wp_safe_redirect(wp_login_url() . '?wcp_sec_err=impossible_travel');
                            exit;
                        }
                    }
                }
            }
        }

        // Store or update fingerprint for current session token
        if ($session_token) {
            $token_key = hash('sha256', $session_token);
            $fingerprints[$token_key] = [
                'ip'         => $client_ip,
                'user_agent' => $user_agent,
                'ua_hash'    => md5($user_agent),
                'country'    => $geo['country'] ?? 'Unknown',
                'country_code' => $geo['country_code'] ?? 'XX',
                'city'       => $geo['city'] ?? 'Unknown',
                'login_time' => time(),
                'last_seen'  => time(),
            ];

            // Prune fingerprints older than 30 days
            $cutoff = time() - (30 * 86400);
            foreach ($fingerprints as $k => $fp) {
                if (($fp['last_seen'] ?? 0) < $cutoff) {
                    unset($fingerprints[$k]);
                }
            }

            update_user_meta($user->ID, self::META_SESSION_FINGERPRINTS, $fingerprints);
        }
    }

    /**
     * Inspect active session on authenticated requests to detect User-Agent hijacking.
     */
    public static function inspect_active_session() {
        if (!is_user_logged_in()) {
            return;
        }

        $user = wp_get_current_user();
        if (!$user || !$user->has_cap('edit_posts')) {
            return;
        }

        $session_token = wp_get_session_token();
        if (!$session_token) {
            return;
        }

        $token_key = hash('sha256', $session_token);
        $fingerprints = get_user_meta($user->ID, self::META_SESSION_FINGERPRINTS, true);

        if (!is_array($fingerprints) || empty($fingerprints[$token_key])) {
            return;
        }

        $settings = self::get_settings();
        $client_ip = self::get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';

        // Check for User-Agent mismatch (token theft / replay across different browsers)
        if (!empty($settings['detect_ua_hijack'])) {
            $recorded_ua_hash = $fingerprints[$token_key]['ua_hash'] ?? '';
            $current_ua_hash  = md5($user_agent);

            if (!empty($recorded_ua_hash) && !hash_equals($recorded_ua_hash, $current_ua_hash)) {
                AuditLogger::log(
                    'session_hijack_detected',
                    sprintf(
                        'Session Hijacking Alert: User-Agent shift detected on active token for user "%s". Original: %s | Current: %s',
                        $user->user_login,
                        substr($fingerprints[$token_key]['user_agent'] ?? '', 0, 50),
                        substr($user_agent, 0, 50)
                    )
                );

                if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                    \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_session_hijack_flag', [
                        'severity' => 'high',
                        /* translators: 1: username */
                        'message'  => sprintf(__('Session IP/User-Agent shift detected on active session for user "%1$s". Session auto-terminated.', 'wcp-security-scanner'), $user->user_login),
                        'details'  => [
                            'Affected User'   => $user->user_login,
                            'Original Agent'  => substr($fingerprints[$token_key]['user_agent'] ?? '', 0, 60),
                            'Hijacker Agent'  => substr($user_agent, 0, 60),
                            'Current IP'      => $client_ip,
                        ],
                    ]);
                }

                // Auto-terminate compromised session
                wp_destroy_current_session();
                unset($fingerprints[$token_key]);
                update_user_meta($user->ID, self::META_SESSION_FINGERPRINTS, $fingerprints);

                wp_die(
                    '<h1>Session Terminated for Security</h1><p>Your session signature changed unexpectedly. Please log in again to confirm your identity.</p>',
                    'Security Warning',
                    ['response' => 403]
                );
            }
        }

        // Update last seen timestamp
        $fingerprints[$token_key]['last_seen'] = time();
        if ($fingerprints[$token_key]['ip'] !== $client_ip) {
            $fingerprints[$token_key]['ip'] = $client_ip;
        }
        update_user_meta($user->ID, self::META_SESSION_FINGERPRINTS, $fingerprints);
    }

    /**
     * Record an impossible travel incident alert.
     *
     * @param array $alert_data
     */
    public static function record_impossible_travel_alert(array $alert_data) {
        $alerts = get_option(self::OPTION_TRAVEL_ALERTS, []);
        if (!is_array($alerts)) {
            $alerts = [];
        }

        $alert_id = 'alert_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3));
        $entry = array_merge([
            'id'        => $alert_id,
            'timestamp' => time(),
            'datetime'  => current_time('mysql'),
            'status'    => 'active',
        ], $alert_data);

        array_unshift($alerts, $entry);
        if (count($alerts) > 50) {
            $alerts = array_slice($alerts, 0, 50);
        }
        update_option(self::OPTION_TRAVEL_ALERTS, $alerts);

        AuditLogger::log(
            'impossible_travel_detected',
            sprintf(
                'Impossible Travel Alert for user "%s": login from %s (%s) within %d mins of session in %s (%s).',
                $alert_data['user_login'] ?? 'user',
                $alert_data['new_country'] ?? '',
                $alert_data['new_ip'] ?? '',
                $alert_data['delta_minutes'] ?? 0,
                $alert_data['prev_country'] ?? '',
                $alert_data['prev_ip'] ?? ''
            )
        );

        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('auth_impossible_travel_flag', [
                'severity' => 'critical',
                /* translators: 1: username, 2: new country, 3: previous country, 4: minutes */
                'message'  => sprintf(__('Impossible Geo-Velocity Travel detected for user "%1$s": Authenticated from %2$s within %4$d minutes of session in %3$s.', 'wcp-security-scanner'), $alert_data['user_login'] ?? 'user', $alert_data['new_country'] ?? '', $alert_data['prev_country'] ?? '', (int) ($alert_data['delta_minutes'] ?? 0)),
                'details'  => [
                    'User Account'   => $alert_data['user_login'] ?? 'user',
                    'Origin Location'=> ($alert_data['prev_country'] ?? 'Unknown') . ' (' . ($alert_data['prev_ip'] ?? '') . ')',
                    'New Location'   => ($alert_data['new_country'] ?? 'Unknown') . ' (' . ($alert_data['new_ip'] ?? '') . ')',
                    'Time Delta'     => ($alert_data['delta_minutes'] ?? 0) . ' minutes',
                    'Estimated Speed'=> ($alert_data['speed_kmh'] ?? 0) . ' km/h',
                ],
            ]);
        }
    }

    /**
     * Alias for get_active_sessions_report().
     *
     * @return array
     */
    public static function get_active_sessions_forensics(): array {
        return self::get_active_sessions_report();
    }

    /**
     * Get aggregate report of all active privileged sessions across users.
     *
     * @return array
     */
    public static function get_active_sessions_report(): array {
        $users = get_users([
            'role__in' => ['administrator', 'editor'],
            'number'   => 50,
        ]);

        $current_token = wp_get_session_token();
        $current_token_key = $current_token ? hash('sha256', $current_token) : '';
        $current_user_id = get_current_user_id();

        $active_sessions = [];
        $total_sessions = 0;
        $high_risk_sessions = 0;

        foreach ($users as $u) {
            $wp_sessions = get_user_meta($u->ID, 'session_tokens', true);
            if (!is_array($wp_sessions) || empty($wp_sessions)) {
                continue;
            }

            $fingerprints = get_user_meta($u->ID, self::META_SESSION_FINGERPRINTS, true) ?: [];

            foreach ($wp_sessions as $verifier => $session_data) {
                $total_sessions++;
                $token_key = $verifier; // WordPress keys session_tokens by verifier hash

                $fp = $fingerprints[$token_key] ?? null;
                $ip = $fp['ip'] ?? ($session_data['ip'] ?? 'Unknown');
                $ua = $fp['user_agent'] ?? ($session_data['ua'] ?? 'Unknown');
                $country = $fp['country'] ?? 'Unknown';
                $country_code = $fp['country_code'] ?? 'XX';
                $city = $fp['city'] ?? 'Unknown';
                $login_time = $session_data['login'] ?? ($fp['login_time'] ?? time());
                $last_seen = $fp['last_seen'] ?? $login_time;

                $is_current = ($u->ID === $current_user_id && ($token_key === $current_token_key || hash_equals($token_key, hash('sha256', (string)$current_token))));

                // Calculate Session Risk Score (0–100%)
                $risk_score = 0;
                $risk_factors = [];

                // Factor 1: Idle > 7 days (+25)
                if (time() - $last_seen > (7 * 86400)) {
                    $risk_score += 25;
                    $risk_factors[] = 'Idle for more than 7 days';
                }

                // Factor 2: Ancient session > 30 days (+20)
                if (time() - $login_time > (30 * 86400)) {
                    $risk_score += 20;
                    $risk_factors[] = 'Long-lived session (>30 days)';
                }

                // Factor 3: User has multiple active sessions from different countries (+40)
                $other_countries = [];
                foreach ($fingerprints as $k => $other_fp) {
                    if ($k !== $token_key && !empty($other_fp['country']) && $other_fp['country'] !== 'Unknown') {
                        $other_countries[] = $other_fp['country'];
                    }
                }
                if (!empty($other_countries) && !in_array($country, $other_countries, true)) {
                    $risk_score += 45;
                    $risk_factors[] = 'Multiple concurrent countries detected';
                }

                $risk_score = min(100, $risk_score);
                if ($risk_score >= 50) {
                    $high_risk_sessions++;
                }

                $active_sessions[] = [
                    'user_id'       => $u->ID,
                    'user_login'    => $u->user_login,
                    'user_email'    => $u->user_email,
                    'display_name'  => $u->display_name,
                    'role'          => reset($u->roles) ?: 'administrator',
                    'session_id'    => substr($token_key, 0, 16) . '...',
                    'verifier'      => $verifier,
                    'ip'            => $ip,
                    'country'       => $country,
                    'country_code'  => $country_code,
                    'city'          => $city,
                    'user_agent'    => $ua,
                    'login_time'    => $login_time,
                    'last_seen'     => $last_seen,
                    'is_current'    => $is_current,
                    'risk_score'    => $risk_score,
                    'risk_factors'  => $risk_factors,
                ];
            }
        }

        return [
            'total_sessions'     => $total_sessions,
            'high_risk_sessions' => $high_risk_sessions,
            'sessions'           => $active_sessions,
            'travel_alerts'      => self::get_impossible_travel_alerts(15),
            'settings'           => self::get_settings(),
        ];
    }

    /**
     * Revoke a specific session token for a user.
     *
     * @param int $user_id
     * @param string $verifier
     * @return array
     */
    public static function revoke_session(int $user_id, string $verifier): array {
        $manager = \WP_Session_Tokens::get_instance($user_id);
        $manager->destroy($verifier);

        // Also clean up our fingerprint record
        $fingerprints = get_user_meta($user_id, self::META_SESSION_FINGERPRINTS, true);
        if (is_array($fingerprints) && isset($fingerprints[$verifier])) {
            unset($fingerprints[$verifier]);
            update_user_meta($user_id, self::META_SESSION_FINGERPRINTS, $fingerprints);
        }

        AuditLogger::log(
            'session_revoked',
            sprintf('Administrator session verifier "%s" for user ID %d was revoked.', substr($verifier, 0, 12), $user_id)
        );

        return [
            'success' => true,
            'message' => __('Session was successfully revoked and terminated.', 'wcp-security-scanner'),
        ];
    }

    /**
     * Revoke all sessions for a user.
     *
     * @param int $user_id
     * @return array
     */
    public static function revoke_all_sessions(int $user_id): array {
        $manager = \WP_Session_Tokens::get_instance($user_id);
        $manager->destroy_all();
        delete_user_meta($user_id, self::META_SESSION_FINGERPRINTS);

        AuditLogger::log(
            'all_sessions_revoked',
            sprintf('All active sessions for user ID %d were terminated.', $user_id)
        );

        return [
            'success' => true,
            'message' => __('All sessions for this user have been terminated.', 'wcp-security-scanner'),
        ];
    }

    /**
     * Get recent impossible travel alerts.
     *
     * @param int $limit
     * @return array
     */
    public static function get_impossible_travel_alerts(int $limit = 20): array {
        $alerts = get_option(self::OPTION_TRAVEL_ALERTS, []);
        if (!is_array($alerts)) {
            return [];
        }
        return array_slice($alerts, 0, $limit);
    }

    /**
     * Dismiss / acknowledge an impossible travel alert.
     *
     * @param string $alert_id
     * @return array
     */
    public static function dismiss_travel_alert(string $alert_id): array {
        $alerts = get_option(self::OPTION_TRAVEL_ALERTS, []);
        if (is_array($alerts)) {
            foreach ($alerts as &$a) {
                if (($a['id'] ?? '') === $alert_id) {
                    $a['status'] = 'dismissed';
                    break;
                }
            }
            update_option(self::OPTION_TRAVEL_ALERTS, $alerts);
        }
        return ['success' => true];
    }

    /**
     * Resolve IP Geolocation via Cloudflare headers or lightweight local lookup.
     *
     * @param string $ip
     * @return array
     */
    private static function resolve_ip_geo(string $ip): array {
        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $code = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY']));
            return [
                'country'      => self::country_code_to_name($code),
                'country_code' => $code,
                'city'         => isset($_SERVER['HTTP_CF_IPCITY']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCITY'])) : 'Unknown',
            ];
        }

        // Loopback / private check
        if ($ip === '127.0.0.1' || $ip === '::1' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0) {
            return [
                'country'      => 'Localhost / Internal',
                'country_code' => 'LO',
                'city'         => 'Internal Network',
            ];
        }

        return [
            'country'      => 'Unknown',
            'country_code' => 'XX',
            'city'         => 'Unknown',
        ];
    }

    /**
     * Map common ISO country codes to readable names.
     */
    private static function country_code_to_name(string $code): string {
        $map = [
            'US' => 'United States',
            'GB' => 'United Kingdom',
            'CA' => 'Canada',
            'DE' => 'Germany',
            'FR' => 'France',
            'NL' => 'Netherlands',
            'AU' => 'Australia',
            'JP' => 'Japan',
            'SG' => 'Singapore',
            'IN' => 'India',
            'BR' => 'Brazil',
            'BD' => 'Bangladesh',
            'CN' => 'China',
            'RU' => 'Russia',
            'UA' => 'Ukraine',
            'SE' => 'Sweden',
            'CH' => 'Switzerland',
        ];
        return $map[strtoupper($code)] ?? strtoupper($code);
    }

    /**
     * Safe client IP resolution.
     */
    private static function get_client_ip(): string {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            return trim($parts[0]);
        }
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
    }
}
