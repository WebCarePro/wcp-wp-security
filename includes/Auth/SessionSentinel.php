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
    public static string $pending_auth_type = '';
    public static string $pending_auth_label = '';
    public static array $pending_auth_details = [];

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
        if (!empty($token)) {
            self::$last_auth_token = $token;
        }
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
        $wp_sessions = get_user_meta($user->ID, 'session_tokens', true);
        if (empty($session_token)) {
            if (is_array($wp_sessions) && !empty($wp_sessions)) {
                $keys = array_keys($wp_sessions);
                $session_token = end($keys);
            }
        }

        $ip = FirewallEngine::get_client_ip();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';

        // Dual-Device Concurrency Control: Allow at most 2 devices (strictly 1 Desktop + 1 Mobile)
        if (!empty($settings['session_block_concurrent']) && $user->has_cap('administrator')) {
            $wp_sessions = get_user_meta($user->ID, 'session_tokens', true);
            if (is_array($wp_sessions) && count($wp_sessions) > 1 && $session_token) {
                $verifier = hash('sha256', $session_token);
                $sessions_meta = get_user_meta($user->ID, 'wcpscan_session_meta', true) ?: [];

                // Determine current incoming device category ('mobile' vs 'desktop')
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                $screen_raw = isset($_POST['wcpscan_screen_res']) ? sanitize_text_field(wp_unslash($_POST['wcpscan_screen_res'])) : '';
                $current_parsed = \WcpScanner\Auth\LoginHistoryManager::parse_device_details($ua, $screen_raw);
                $current_cat = in_array($current_parsed['device_type'], ['Mobile', 'Tablet'], true) ? 'mobile' : 'desktop';

                $current_session_key = isset($wp_sessions[$verifier]) ? $verifier : (isset($wp_sessions[$session_token]) ? $session_token : '');
                $current_session_data = $current_session_key ? $wp_sessions[$current_session_key] : null;

                $preserved = [];
                $other_device_session = null;
                $other_device_key = '';

                // Examine prior active sessions and enforce category boundaries
                foreach ($wp_sessions as $s_key => $s_data) {
                    // Skip current newly created session in this loop
                    if ($s_key === $verifier || $s_key === $session_token) {
                        continue;
                    }

                    // Extract user-agent for this existing session
                    $s_ua = $s_data['ua'] ?? '';
                    if (empty($s_ua) && !empty($sessions_meta[$s_key]['encrypted_meta'])) {
                        $decrypted = \WcpScanner\Security\SecretVault::decrypt((string) $sessions_meta[$s_key]['encrypted_meta']);
                        $decoded = is_string($decrypted) ? (json_decode($decrypted, true) ?: []) : [];
                        $s_ua = $decoded['user_agent'] ?? '';
                    }

                    $s_parsed = \WcpScanner\Auth\LoginHistoryManager::parse_device_details($s_ua, '');
                    $s_cat = in_array($s_parsed['device_type'], ['Mobile', 'Tablet'], true) ? 'mobile' : 'desktop';

                    if ($s_cat === $current_cat) {
                        // Same category as new device (e.g. new desktop replacing previous desktop) -> Terminate!
                        \WcpScanner\Auth\LoginHistoryManager::record_session_terminated($user->ID, $s_key);
                        unset($sessions_meta[$s_key]);
                    } else {
                        // Different category (e.g. mobile session while logging in on desktop) -> Keep newest!
                        $s_login_time = $s_data['login'] ?? 0;
                        if (!$other_device_session || $s_login_time > ($other_device_session['login'] ?? 0)) {
                            if ($other_device_key) {
                                \WcpScanner\Auth\LoginHistoryManager::record_session_terminated($user->ID, $other_device_key);
                                unset($sessions_meta[$other_device_key]);
                            }
                            $other_device_session = $s_data;
                            $other_device_key = $s_key;
                        } else {
                            \WcpScanner\Auth\LoginHistoryManager::record_session_terminated($user->ID, $s_key);
                            unset($sessions_meta[$s_key]);
                        }
                    }
                }

                // Preserve the different device session (1 Desktop + 1 Mobile)
                if ($other_device_key && $other_device_session) {
                    $preserved[$other_device_key] = $other_device_session;
                }

                // Preserve current newly authenticated session
                if ($current_session_key && $current_session_data) {
                    $preserved[$current_session_key] = $current_session_data;
                } elseif ($session_token) {
                    $preserved[$verifier] = [
                        'expiration' => time() + (14 * DAY_IN_SECONDS),
                        'ip'         => $ip,
                        'ua'         => $ua,
                        'login'      => time(),
                    ];
                }

                update_user_meta($user->ID, 'session_tokens', $preserved);
                update_user_meta($user->ID, 'wcpscan_session_meta', $sessions_meta);
            }
        }

        // Determine login authentication factor / mechanism
        $auth_type = !empty(self::$pending_auth_type) ? self::$pending_auth_type : '';
        $auth_label = !empty(self::$pending_auth_label) ? self::$pending_auth_label : '';
        $auth_details = !empty(self::$pending_auth_details) ? self::$pending_auth_details : [];

        // Reset static pending properties
        self::$pending_auth_type = '';
        self::$pending_auth_label = '';
        self::$pending_auth_details = [];

        // If not explicitly set by the calling authenticator, deduce it accurately:
        if (empty($auth_type)) {
            $is_support = get_user_meta($user->ID, 'wcpscan_is_temporary_support', true);
            if ($is_support) {
                $auth_type = 'magic_link';
                $auth_label = __('Magic Support Link (Zero-Trust JIT)', 'wcp-security-scanner');
                $auth_details = ['type' => 'magic_link'];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Inspection during session authentication creation to detect 2FA submission
            } elseif (!empty($_POST['wcpscan_2fa_code'])) {
                $auth_type = '2fa';
                $auth_label = __('2FA (TOTP Authenticator)', 'wcp-security-scanner');
                $auth_details = ['type' => 'totp'];
            } elseif (class_exists('\\WcpScanner\\Auth\\TwoFactorAuth') && \WcpScanner\Auth\TwoFactorAuth::is_user_enabled($user->ID) && \WcpScanner\Auth\TwoFactorAuth::is_trusted_device($user->ID)) {
                $auth_type = '2fa';
                $auth_label = __('2FA (Remembered Trusted Device)', 'wcp-security-scanner');
                $auth_details = ['type' => 'trusted_device'];
            } else {
                $auth_type = 'password';
                $auth_label = __('Password Only (Single-Factor)', 'wcp-security-scanner');
                $auth_details = ['type' => 'password'];
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
                'auth_type'      => $auth_type,
                'auth_label'     => $auth_label,
                'auth_details'   => $auth_details,
                'encrypted_meta' => \WcpScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                    'login_ip'     => $ip,
                    'user_agent'   => substr(sanitize_text_field($ua), 0, 255),
                    'auth_type'    => $auth_type,
                    'auth_label'   => $auth_label,
                    'auth_details' => $auth_details,
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

            // Auto-initialize if session was active before sentinel activation or if IP was recorded as Cloudflare proxy or loopback
            $is_cf_ip = \WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($current_login_ip);
            $is_local_ip = ($current_login_ip === '127.0.0.1' || $current_login_ip === '::1' || \WcpScanner\Firewall\FirewallEngine::is_private_ip($current_login_ip));

            if (!$session_info || empty($current_login_ip) || $is_cf_ip || $is_local_ip) {
                self::anchor_session($user_id, $current_token, $current_verifier, $ip, $session_info ?: []);
                return;
            }

            // Update last seen timestamp (throttled every 60 seconds to save DB writes)
            if (time() - ($session_info['last_seen'] ?? 0) > 60) {
                $sessions_meta[$current_token]['last_seen'] = time();
                $sessions_meta[$current_verifier]['last_seen'] = time();
                update_user_meta($user_id, 'wcpscan_session_meta', $sessions_meta);
            }

            // Cryptographic Session Binding & ASN Drift Verification
            $current_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            $current_asn = isset($_SERVER['HTTP_CF_IPASN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPASN'])) : '';
            $recorded_asn = $decoded['asn'] ?? '';

            $is_ip_valid = self::is_ip_match_or_subnet($current_login_ip, $ip, $decoded, $current_ua);
            $asn_drift = (!empty($recorded_asn) && !empty($current_asn) && $recorded_asn !== $current_asn);
            $ua_mismatch = (!empty($decoded['user_agent']) && !empty($current_ua) && $decoded['user_agent'] !== substr($current_ua, 0, 255));

            // Record IP change / network shift in forensic directory if IP shifted
            if (!empty($ip) && $ip !== $current_login_ip && !\WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($ip) && $ip !== '127.0.0.1' && $ip !== '::1') {
                if (class_exists('\\WcpScanner\\Auth\\LoginHistoryManager')) {
                    \WcpScanner\Auth\LoginHistoryManager::record_session_ip_shift($user_id, $ip, $current_token);
                }
            }

            if ((!empty($settings['session_lock_ip']) && !$is_ip_valid) || ($asn_drift && $ua_mismatch)) {
                // Invalidate hijacked session
                self::terminate_session($user_id, $current_token, 'Session Hijacking / ASN Drift Detected');
                \WcpScanner\System\AuditLogger::log(
                    'session_hijack_deflected',
                    sprintf('Deflected hijacked administrative session for %s. Baseline IP %s (ASN %s) vs Incoming IP %s (ASN %s). Session liquidated.', $user->user_login, $current_login_ip, $recorded_asn ?: 'N/A', $ip, $current_asn ?: 'N/A')
                );
                wp_safe_redirect(add_query_arg('wcp_session_invalidated', '1', wp_login_url()));
                exit;
            }
        } catch (\Throwable $e) {
            // Failsafe: never disrupt WordPress admin execution
        }
    }

    /**
     * Check if an incoming IP address matches the recorded session baseline IP or falls within
     * the legitimate carrier/ISP subnet (IPv4 /24 or IPv6 /64 prefix) or verified dual-stack profile.
     *
     * @param string $baseline_ip
     * @param string $incoming_ip
     * @param array  $decoded_meta
     * @param string $current_ua
     * @return bool
     */
    public static function is_ip_match_or_subnet(string $baseline_ip, string $incoming_ip, array $decoded_meta = [], string $current_ua = ''): bool {
        if (empty($baseline_ip) || empty($incoming_ip)) {
            return true; // Failsafe
        }

        // 1. Exact string match
        if ($baseline_ip === $incoming_ip) {
            return true;
        }

        // 2. Check if incoming IP matches verified alternate dual-stack IP (IPv4 vs IPv6)
        if (!empty($decoded_meta['alt_ip']) && $decoded_meta['alt_ip'] === $incoming_ip) {
            return true;
        }

        // 3. IPv4 Subnet Comparison (/24 or /16 for ISP CGNAT/dynamic allocation)
        $is_base_v4 = filter_var($baseline_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $is_inc_v4  = filter_var($incoming_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

        if ($is_base_v4 && $is_inc_v4) {
            $base_parts = explode('.', $baseline_ip);
            $inc_parts  = explode('.', $incoming_ip);
            if (count($base_parts) === 4 && count($inc_parts) === 4) {
                // Strict /24 match (first 3 octets match)
                if ($base_parts[0] === $inc_parts[0] && $base_parts[1] === $inc_parts[1] && $base_parts[2] === $inc_parts[2]) {
                    return true;
                }

                // If behind Cloudflare and User-Agent is an exact identical match, tolerate /16 subnet (ISP regional CGNAT pool)
                $recorded_ua = $decoded_meta['user_agent'] ?? '';
                $is_cf = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);
                if ($is_cf && !empty($recorded_ua) && !empty($current_ua) && $recorded_ua === $current_ua) {
                    if ($base_parts[0] === $inc_parts[0] && $base_parts[1] === $inc_parts[1]) {
                        return true;
                    }
                }
            }
        }

        // 4. IPv6 Subnet Comparison (/64 - First 64 bits / 8 bytes match)
        // Defends against RFC 4941 client privacy interface identifier rotation
        $is_base_v6 = filter_var($baseline_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $is_inc_v6  = filter_var($incoming_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

        if ($is_base_v6 && $is_inc_v6) {
            $base_bin = @inet_pton($baseline_ip);
            $inc_bin  = @inet_pton($incoming_ip);
            if ($base_bin !== false && $inc_bin !== false && strlen($base_bin) === 16 && strlen($inc_bin) === 16) {
                if (substr($base_bin, 0, 8) === substr($inc_bin, 0, 8)) {
                    return true;
                }
            }
        }

        // 5. Dual-Stack Cloudflare Flapping (One is IPv4 and one is IPv6)
        // Under Cloudflare and modern browsers (RFC 8305 Happy Eyeballs),
        // browser races IPv4 and IPv6 sockets. If User-Agent is an exact match and request arrives via Cloudflare:
        if (($is_base_v4 && $is_inc_v6) || ($is_base_v6 && $is_inc_v4)) {
            $recorded_ua = $decoded_meta['user_agent'] ?? '';
            $is_cf = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);

            if ($is_cf && !empty($recorded_ua) && !empty($current_ua) && $recorded_ua === $current_ua) {
                return true;
            }
        }

        // 6. Loopback / Internal Proxy Failsafe
        // If incoming request resolved to localhost/private IP due to internal proxy/cron/loopback, do not kill admin session
        if ($incoming_ip === '127.0.0.1' || $incoming_ip === '::1' || \WcpScanner\Firewall\FirewallEngine::is_private_ip($incoming_ip)) {
            return true;
        }

        return false;
    }

    /**
     * Anchor or heal an active session with cryptographic metadata binding.
     *
     * @param int    $user_id
     * @param string $token
     * @param string $verifier
     * @param string $ip
     * @param array  $existing_info
     * @return void
     */
    public static function anchor_session(int $user_id, string $token, string $verifier, string $ip, array $existing_info = []): void {
        $sessions_meta = get_user_meta($user_id, 'wcpscan_session_meta', true);
        if (!is_array($sessions_meta)) {
            $sessions_meta = [];
        }

        $existing_decoded = [];
        if (!empty($existing_info['encrypted_meta'])) {
            $dec = \WcpScanner\Security\SecretVault::decrypt((string) $existing_info['encrypted_meta']);
            $existing_decoded = is_string($dec) ? (json_decode($dec, true) ?: []) : [];
        }

        $entry = [
            'login_time'     => $existing_info['login_time'] ?? time(),
            'last_seen'      => time(),
            'encrypted_meta' => \WcpScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                'login_ip'   => $ip,
                'alt_ip'     => $existing_decoded['alt_ip'] ?? '',
                'user_agent' => substr(!empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : ($existing_decoded['user_agent'] ?? 'Unknown'), 0, 255),
                'asn'        => isset($_SERVER['HTTP_CF_IPASN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPASN'])) : ($existing_decoded['asn'] ?? ''),
                'tls_fp'     => !empty($_SERVER['SSL_CIPHER']) ? hash('sha256', (string) sanitize_text_field(wp_unslash($_SERVER['SSL_CIPHER']))) : ($existing_decoded['tls_fp'] ?? ''),
            ])),
        ];

        $sessions_meta[$token]    = $entry;
        $sessions_meta[$verifier] = $entry;
        update_user_meta($user_id, 'wcpscan_session_meta', $sessions_meta);
    }

    /**
     * Re-anchor the current user's active session to their current verified IP address.
     * Keeps session metadata in sync with the administrator's active connection.
     */
    public static function reanchor_current_user_session(): void {
        if (!is_user_logged_in()) {
            return;
        }
        $user_id = get_current_user_id();
        $token = wp_get_session_token();
        if (empty($user_id) || empty($token)) {
            return;
        }
        $verifier = hash('sha256', $token);
        $ip = \WcpScanner\Firewall\FirewallEngine::get_client_ip();
        $sessions_meta = get_user_meta($user_id, 'wcpscan_session_meta', true) ?: [];
        $session_info = $sessions_meta[$verifier] ?? ($sessions_meta[$token] ?? []);

        self::anchor_session($user_id, $token, $verifier, $ip, $session_info);
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
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
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
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
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
                $auth_type = $meta['auth_type'] ?? '';
                $auth_label = $meta['auth_label'] ?? '';
                $auth_details = $meta['auth_details'] ?? [];

                if (!empty($meta['encrypted_meta'])) {
                    $decrypted_meta = \WcpScanner\Security\SecretVault::decrypt((string) $meta['encrypted_meta']);
                    $decoded = is_string($decrypted_meta) ? (json_decode($decrypted_meta, true) ?: []) : [];
                    $ip = $decoded['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                    $ua = $decoded['user_agent'] ?? ($data['ua'] ?? 'Unknown');
                    if (empty($auth_type) && !empty($decoded['auth_type'])) {
                        $auth_type = $decoded['auth_type'];
                        $auth_label = $decoded['auth_label'] ?? '';
                        $auth_details = $decoded['auth_details'] ?? [];
                    }
                } else {
                    $ip = $meta['login_ip'] ?? ($data['ip'] ?? 'Unknown');
                    $ua = $meta['user_agent'] ?? ($data['ua'] ?? 'Unknown');
                }

                $login_ts = isset($meta['login_time']) ? (int) $meta['login_time'] : (isset($data['login']) ? (int) $data['login'] : time());

                // Smart Deductive Inference for existing sessions without stored auth_type
                if (empty($auth_type)) {
                    $is_support = get_user_meta($admin->ID, 'wcpscan_is_temporary_support', true);
                    if ($is_support) {
                        $auth_type = 'magic_link';
                        $auth_label = __('Magic Support Link (Zero-Trust JIT)', 'wcp-security-scanner');
                        $auth_details = ['type' => 'magic_link'];
                    } else {
                        // Check if a passkey was used around the login time
                        $user_passkeys = class_exists('\\WcpScanner\\Auth\\WebAuthnManager') ? \WcpScanner\Auth\WebAuthnManager::get_user_credentials($admin->ID) : [];
                        $matched_pk = null;
                        foreach ($user_passkeys as $pk) {
                            if (!empty($pk['last_used']) && abs((int) $pk['last_used'] - $login_ts) <= 180) {
                                $matched_pk = $pk;
                                break;
                            }
                        }
                        if ($matched_pk) {
                            $auth_type = 'passkey';
                            $auth_label = sprintf(
                                /* translators: %s: device name */
                                __('Passkey (%s)', 'wcp-security-scanner'),
                                $matched_pk['name'] ?? 'Windows Hello / FIDO2'
                            );
                            $auth_details = [
                                'type'        => 'passkey',
                                'device_name' => $matched_pk['name'] ?? 'Hardware Key',
                            ];
                        } elseif (class_exists('\\WcpScanner\\Auth\\TwoFactorAuth') && \WcpScanner\Auth\TwoFactorAuth::is_user_enabled($admin->ID)) {
                            $auth_type = '2fa';
                            $auth_label = __('2FA (TOTP Authenticator)', 'wcp-security-scanner');
                            $auth_details = ['type' => 'totp'];
                        } else {
                            $auth_type = 'password';
                            $auth_label = __('Password Only (Single-Factor)', 'wcp-security-scanner');
                            $auth_details = ['type' => 'password'];
                        }
                    }
                }

                // If $ip belongs to Cloudflare's Anycast proxy network, it's an edge node, not the visitor's device.
                // Heal current active session directly to the verified client IP.
                if (\WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($ip)) {
                    if ($is_current) {
                        $ip = $client_ip;
                        $entry = [
                            'login_time'     => $login_ts,
                            'last_seen'      => time(),
                            'auth_type'      => $auth_type,
                            'auth_label'     => $auth_label,
                            'auth_details'   => $auth_details,
                            'encrypted_meta' => \WcpScanner\Security\SecretVault::encrypt((string) wp_json_encode([
                                'login_ip'     => $client_ip,
                                'user_agent'   => $ua,
                                'auth_type'    => $auth_type,
                                'auth_label'   => $auth_label,
                                'auth_details' => $auth_details,
                            ])),
                        ];
                        $sessions_meta[$verifier] = $entry;
                        if (!empty($current_token)) {
                            $sessions_meta[$current_token] = $entry;
                        }
                        update_user_meta($admin->ID, 'wcpscan_session_meta', $sessions_meta);
                    }
                }

                // Determine browser / OS / device type info
                $browser_info = self::parse_user_agent($ua);

                $duration_sec = max(1, time() - $login_ts);
                $duration_formatted = class_exists('\\WcpScanner\\Auth\\LoginHistoryManager') 
                    ? \WcpScanner\Auth\LoginHistoryManager::format_duration($duration_sec)
                    : sprintf('%d mins', round($duration_sec / 60));

                // Security posture level and risk factor calculation
                $security_level = 'hardened';
                if ($auth_type === 'password') {
                    $security_level = 'at_risk';
                } elseif ($auth_type === 'magic_link') {
                    $security_level = 'sandboxed';
                }

                $risk_factors = [];
                if ($auth_type === 'password') {
                    $risk_factors[] = __('Single-factor password login: Account lacks MFA (2FA or Passkey).', 'wcp-security-scanner');
                }
                if ($ip !== $client_ip && $is_current) {
                    $risk_factors[] = sprintf(
                        /* translators: 1: login IP, 2: current IP */
                        __('IP changed since login (%1$s &rarr; %2$s).', 'wcp-security-scanner'),
                        esc_html($ip),
                        esc_html($client_ip)
                    );
                }
                if ($auth_type === 'magic_link') {
                    $risk_factors[] = __('Temporary technician session confined by Zero-Trust MU Guardian.', 'wcp-security-scanner');
                }

                // Expiration calculations
                $expiration_ts = isset($data['expiration']) ? (int) $data['expiration'] : null;
                $expiration_formatted = $expiration_ts ? date_i18n('Y-m-d H:i:s', $expiration_ts) : 'Default (14 days)';
                $expiration_human = '';
                if ($expiration_ts) {
                    if ($expiration_ts < time()) {
                        $expiration_human = __('Expired', 'wcp-security-scanner');
                    } else {
                        $expiration_human = sprintf(
                            /* translators: %s: remaining time difference */
                            __('Expires in %s', 'wcp-security-scanner'),
                            human_time_diff(time(), $expiration_ts)
                        );
                    }
                } else {
                    $expiration_human = __('Expires in 14 days', 'wcp-security-scanner');
                }

                // Idle time calculation
                $last_seen_ts = isset($meta['last_seen']) ? (int) $meta['last_seen'] : $login_ts;
                $idle_diff = max(0, time() - $last_seen_ts);
                $idle_human = $idle_diff < 90 ? __('Active just now', 'wcp-security-scanner') : sprintf(
                    /* translators: %s: time difference */
                    __('Idle for %s', 'wcp-security-scanner'),
                    human_time_diff($last_seen_ts, time())
                );

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
                    'current_ip'               => $client_ip,
                    'is_same_ip'               => ($ip === $client_ip),
                    'is_local_ip'              => ($ip === '127.0.0.1' || $ip === '::1' || \WcpScanner\Firewall\FirewallEngine::is_private_ip($ip)),
                    'login_time'               => date_i18n('Y-m-d H:i:s', $login_ts),
                    'login_time_raw'           => $login_ts,
                    'login_time_human'         => human_time_diff($login_ts, time()) . ' ago',
                    'login_duration_seconds'   => $duration_sec,
                    'login_duration_formatted' => $duration_formatted,
                    'last_seen'                => isset($meta['last_seen']) ? date_i18n('Y-m-d H:i:s', $meta['last_seen']) : 'Recently',
                    'last_seen_raw'            => $last_seen_ts,
                    'idle_human'               => $idle_human,
                    'expiration'               => $expiration_formatted,
                    'expiration_raw'           => $expiration_ts,
                    'expiration_human'         => $expiration_human,
                    'browser'                  => $browser_info['browser'],
                    'platform'                 => $browser_info['platform'],
                    'device_type'              => $browser_info['device_type'],
                    'user_agent'               => $ua,
                    'auth_type'                => $auth_type,
                    'auth_label'               => $auth_label,
                    'auth_details'             => $auth_details,
                    'security_level'           => $security_level,
                    'risk_factors'             => $risk_factors,
                    'support_link_meta'        => $support_link_meta,
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
        $device_type = 'Desktop';

        if (stripos($ua, 'iPad') !== false || stripos($ua, 'Tablet') !== false) {
            $device_type = 'Tablet';
        } elseif (stripos($ua, 'Mobile') !== false || stripos($ua, 'Android') !== false || stripos($ua, 'iPhone') !== false) {
            $device_type = 'Mobile';
        }

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
            'browser'     => $browser,
            'platform'    => $platform,
            'device_type' => $device_type,
        ];
    }
}
