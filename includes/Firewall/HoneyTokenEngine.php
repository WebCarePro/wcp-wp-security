<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * HoneyTokenEngine
 *
 * Anti-Automation & Zero-Friction Bot Trap.
 * Renders invisible decoy fields on WordPress authentication forms and phantom API decoys.
 * Catches headless scrapers, credential-stuffing botnets, and vulnerability scanners
 * the instant they interact with decoys, banishing bot IPs before costly password hashing runs.
 */
class HoneyTokenEngine {

    const OPTION_CATCHES  = 'wcpscan_honeytoken_catches';
    const OPTION_SETTINGS = 'wcpscan_honeytoken_settings';
    const FIELD_NAME      = 'wcp_security_verify';
    const FIELD_FLAG      = 'wcp_hp_active';

    /**
     * Initialize HoneyToken hooks.
     */
    public static function init() {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        // 1. Render invisible honeypot form fields
        if (!empty($settings['trap_login_forms'])) {
            add_action('login_form', [__CLASS__, 'render_form_decoy']);
            add_action('register_form', [__CLASS__, 'render_form_decoy']);
            add_action('lostpassword_form', [__CLASS__, 'render_form_decoy']);
        }
        if (!empty($settings['trap_comment_forms'])) {
            add_action('comment_form_after_fields', [__CLASS__, 'render_form_decoy']);
        }

        // 2. Intercept submissions before core password hashing / registration executes
        add_filter('authenticate', [__CLASS__, 'inspect_auth_honeytoken'], 1, 3);
        add_filter('registration_errors', [__CLASS__, 'inspect_registration_honeytoken'], 1, 3);
        add_filter('preprocess_comment', [__CLASS__, 'inspect_comment_honeytoken'], 1);

        // 3. Phantom Decoy Endpoints
        if (!empty($settings['trap_phantom_endpoints'])) {
            add_action('init', [__CLASS__, 'check_phantom_endpoints'], 0);
        }
    }

    /**
     * Get HoneyToken configuration settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'                  => true,
            'trap_login_forms'         => true,
            'trap_comment_forms'       => true,
            'trap_phantom_endpoints'   => true,
            'auto_ban_bot_ip'          => true,
            'ban_duration_hours'       => 24,
            'enable_form_traps'        => true,
            'enable_phantom_endpoints' => true,
        ];
        $stored = get_option(self::OPTION_SETTINGS, []);
        $merged = array_merge($defaults, is_array($stored) ? $stored : []);

        $form_traps = !empty($merged['trap_login_forms']) || !empty($merged['enable_form_traps']);
        $phantom_traps = !empty($merged['trap_phantom_endpoints']) || !empty($merged['enable_phantom_endpoints']);

        $merged['trap_login_forms']         = $form_traps;
        $merged['trap_comment_forms']       = $form_traps;
        $merged['enable_form_traps']        = $form_traps;
        $merged['trap_phantom_endpoints']   = $phantom_traps;
        $merged['enable_phantom_endpoints'] = $phantom_traps;

        return $merged;
    }

    /**
     * Update HoneyToken settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();

        $form_traps = isset($new_settings['enable_form_traps'])
            ? !empty($new_settings['enable_form_traps'])
            : (!empty($new_settings['trap_login_forms']) || !empty($new_settings['trap_comment_forms']));

        $phantom_traps = isset($new_settings['enable_phantom_endpoints'])
            ? !empty($new_settings['enable_phantom_endpoints'])
            : !empty($new_settings['trap_phantom_endpoints']);

        $auto_ban = isset($new_settings['auto_ban_bot_ip'])
            ? !empty($new_settings['auto_ban_bot_ip'])
            : !empty($current['auto_ban_bot_ip']);

        $enabled = isset($new_settings['enabled'])
            ? !empty($new_settings['enabled'])
            : ($form_traps || $phantom_traps || !empty($current['enabled']));

        $ban_duration = isset($new_settings['ban_duration_hours'])
            ? max(1, min(720, intval($new_settings['ban_duration_hours'])))
            : intval($current['ban_duration_hours'] ?? 24);

        $updated = [
            'enabled'                  => $enabled,
            'trap_login_forms'         => $form_traps,
            'trap_comment_forms'       => $form_traps,
            'trap_phantom_endpoints'   => $phantom_traps,
            'auto_ban_bot_ip'          => $auto_ban,
            'ban_duration_hours'       => $ban_duration,
            'enable_form_traps'        => $form_traps,
            'enable_phantom_endpoints' => $phantom_traps,
        ];
        update_option(self::OPTION_SETTINGS, $updated);
        return $updated;
    }

    /**
     * Render invisible honeypot form fields in authentication / comment forms.
     */
    public static function render_form_decoy() {
        echo '<div style="position: absolute !important; left: -9999px !important; opacity: 0 !important; height: 0 !important; width: 0 !important; overflow: hidden !important; pointer-events: none !important; z-index: -1;" aria-hidden="true" tabindex="-1">';
        echo '<label for="' . esc_attr(self::FIELD_NAME) . '">Security Verification (Leave blank)</label>';
        echo '<input type="text" name="' . esc_attr(self::FIELD_NAME) . '" id="' . esc_attr(self::FIELD_NAME) . '" value="" tabindex="-1" autocomplete="off" />';
        echo '<input type="hidden" name="' . esc_attr(self::FIELD_FLAG) . '" value="1" />';
        echo '</div>';
    }

    /**
     * Intercept login authentication attempts.
     *
     * @param mixed $user
     * @param string $username
     * @param string $password
     * @return mixed
     */
    public static function inspect_auth_honeytoken($user, $username, $password) {
        // phpcs:disable WordPress.Security.NonceVerification.Missing -- Honeypot trap must inspect raw form data before auth to catch headless bots
        if (isset($_POST[self::FIELD_FLAG]) && !empty($_POST[self::FIELD_NAME])) {
            self::trigger_trap('login_autofill', [
                'target'   => 'Login Portal Form',
                'username' => sanitize_text_field(wp_unslash($username)),
                'payload'  => sanitize_text_field(wp_unslash($_POST[self::FIELD_NAME])),
            ]);
        }
        // phpcs:enable WordPress.Security.NonceVerification.Missing
        return $user;
    }

    /**
     * Intercept user registration submissions.
     */
    public static function inspect_registration_honeytoken($errors, $sanitized_user_login, $user_email) {
        // phpcs:disable WordPress.Security.NonceVerification.Missing -- Honeypot trap must inspect raw form data before registration to catch headless bots
        if (isset($_POST[self::FIELD_FLAG]) && !empty($_POST[self::FIELD_NAME])) {
            self::trigger_trap('registration_autofill', [
                'target'   => 'Registration Form',
                'username' => sanitize_text_field(wp_unslash($sanitized_user_login)),
                'email'    => sanitize_text_field(wp_unslash($user_email)),
                'payload'  => sanitize_text_field(wp_unslash($_POST[self::FIELD_NAME])),
            ]);
        }
        // phpcs:enable WordPress.Security.NonceVerification.Missing
        return $errors;
    }

    /**
     * Intercept comment submissions.
     */
    public static function inspect_comment_honeytoken($commentdata) {
        // phpcs:disable WordPress.Security.NonceVerification.Missing -- Honeypot trap must inspect raw form data before comment processing to catch spambots
        if (isset($_POST[self::FIELD_FLAG]) && !empty($_POST[self::FIELD_NAME])) {
            self::trigger_trap('comment_autofill', [
                'target'  => 'Comment Form',
                'payload' => sanitize_text_field(wp_unslash($_POST[self::FIELD_NAME])),
            ]);
        }
        // phpcs:enable WordPress.Security.NonceVerification.Missing
        return $commentdata;
    }

    /**
     * Check if request matches a phantom decoy endpoint.
     */
    public static function check_phantom_endpoints() {
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $decoys = [
            '/.well-known/wcp-security-decoy' => 'Phantom Well-Known Probe Decoy',
            '/wp-json/wcp-honeytoken/v1/auth' => 'Phantom REST Auth Decoy',
            '/xmlrpc_backup.php'              => 'Phantom XML-RPC Backup Decoy',
            '/wp-content/debug_dump.sql'      => 'Phantom Database Dump Decoy',
        ];

        foreach ($decoys as $path => $name) {
            if (strpos($uri, $path) !== false) {
                self::trigger_trap('phantom_endpoint', [
                    'target'   => $name,
                    'endpoint' => $path,
                    'payload'  => $uri,
                ]);
            }
        }
    }

    /**
     * Execute punitive action when a bot trips a honeypot decoy.
     *
     * @param string $trap_type
     * @param array  $context
     */
    private static function trigger_trap(string $trap_type, array $context = []) {
        $client_ip = self::get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown Bot';
        $settings = self::get_settings();

        // Check if IP is in the central WAF Whitelist
        $is_whitelisted = false;
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            $waf_settings = SettingsManager::get_settings();
            $is_whitelisted = FirewallEngine::is_ip_whitelisted($client_ip, $waf_settings['waf_whitelisted_ips'] ?? '');
        }

        // Whitelisted IPs bypass honeypot termination, but MUST store audit telemetry in WAF Incident Logs
        if ($is_whitelisted) {
            if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
                FirewallEngine::log_incident([
                    'id'          => 'WAF-HONEYTOKEN-TRAP-BYPASS',
                    'name'        => 'Honey-Token Decoy Tripped (Whitelist Bypass)',
                    'category'    => 'Identity Defense',
                    'description' => sprintf('Whitelisted IP tripped %s decoy (%s) [Bypassed via IP Whitelist].', esc_html($trap_type), esc_html($context['target'] ?? '')),
                    'match_type'  => 'Honeytoken Decoy',
                    'match_value' => $trap_type,
                    'payload'     => 'Trap: ' . $trap_type . ' Target: ' . ($context['target'] ?? '') . ' IP: ' . $client_ip,
                ], 'bypassed');
            }

            AuditLogger::log(
                'honeytoken_bot_bypassed',
                sprintf('Honey-Token Decoy tripped by Whitelisted IP "%s" via %s (%s). Bypassed with WAF log recorded.', $client_ip, $trap_type, $context['target'] ?? '')
            );

            // Allow request to continue without blocking
            return;
        }

        // 1. Record caught bot entry
        $catch_entry = [
            'id'         => 'bot_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
            'timestamp'  => time(),
            'datetime'   => current_time('mysql'),
            'ip'         => $client_ip,
            'trap_type'  => $trap_type,
            'user_agent' => $user_agent,
            'target'     => $context['target'] ?? 'Decoy Trap',
            'details'    => $context,
        ];

        self::record_catch($catch_entry);

        // 2. Auto-ban bot IP if enabled
        if (!empty($settings['auto_ban_bot_ip'])) {
            self::ban_bot_ip($client_ip, $settings['ban_duration_hours'] ?? 24);
        }

        // Log blocked incident to WAF Incident Logs
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            FirewallEngine::log_incident([
                'id'          => 'WAF-HONEYTOKEN-TRAP-BLOCKED',
                'name'        => 'Honey-Token Bot Decoy Tripped',
                'category'    => 'Identity Defense',
                'description' => sprintf('Bot trapped and quarantined by honeytoken decoy: %s (%s).', esc_html($trap_type), esc_html($context['target'] ?? '')),
                'match_type'  => 'Honeytoken Decoy',
                'match_value' => $trap_type,
                'payload'     => 'Trap: ' . $trap_type . ' Target: ' . ($context['target'] ?? '') . ' IP: ' . $client_ip,
            ], 'blocked');
        }

        AuditLogger::log(
            'honeytoken_bot_trapped',
            sprintf('Honey-Token Trapped Bot IP "%s" via %s (%s).', $client_ip, $trap_type, $context['target'] ?? '')
        );

        // 3. Immediately terminate bot request with HTTP 403 Forbidden
        status_header(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Access Denied: Automated bot activity detected and quarantined by WCP Security Scanner.';
        exit;
    }

    /**
     * Ban a trapped bot IP.
     *
     * @param string $ip
     * @param int $duration_hours
     */
    public static function ban_bot_ip(string $ip, int $duration_hours = 24) {
        $waf_settings = SettingsManager::get_settings();
        $blocked_ips = $waf_settings['waf_blocked_ips'] ?? '';

        $ip_list = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $blocked_ips))));
        if (!in_array($ip, $ip_list, true)) {
            $ip_list[] = $ip;
            SettingsManager::save_settings(['waf_blocked_ips' => implode("\n", $ip_list)]);
        }

        // Set transient with expiration for telemetry
        set_transient('wcpscan_bot_ban_' . md5($ip), [
            'ip'         => $ip,
            'banned_at'  => time(),
            'expires_at' => time() + ($duration_hours * 3600),
        ], $duration_hours * 3600);
    }

    /**
     * Unban an IP.
     *
     * @param string $ip
     * @return array
     */
    public static function unban_bot_ip(string $ip): array {
        $waf_settings = SettingsManager::get_settings();
        $blocked_ips = $waf_settings['waf_blocked_ips'] ?? '';

        $ip_list = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $blocked_ips))));
        $ip_list = array_values(array_filter($ip_list, fn($item) => $item !== $ip));
        SettingsManager::save_settings(['waf_blocked_ips' => implode("\n", $ip_list)]);
        delete_transient('wcpscan_bot_ban_' . md5($ip));

        AuditLogger::log(
            'honeytoken_ip_unbanned',
            sprintf('Honey-Token IP "%s" was unbanned by administrator.', $ip)
        );

        return [
            'success' => true,
            'message' => "IP {$ip} was unbanned successfully.",
        ];
    }

    /**
     * Record a catch into history.
     */
    public static function record_catch(array $entry) {
        $catches = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            $catches = [];
        }
        array_unshift($catches, $entry);
        if (count($catches) > 100) {
            $catches = array_slice($catches, 0, 100);
        }
        update_option(self::OPTION_CATCHES, $catches);
    }

    /**
     * Helper to manually or programmatically record and ban a trapped bot.
     *
     * @param string $ip
     * @param string $trap_type
     * @param string $target
     * @param string $user_agent
     * @param int $duration_hours
     */
    public static function record_and_ban(string $ip, string $trap_type = 'decoy_trap', string $target = '', string $user_agent = '', int $duration_hours = 24) {
        $catch_entry = [
            'id'         => 'bot_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
            'timestamp'  => time(),
            'datetime'   => current_time('mysql'),
            'ip'         => $ip,
            'trap_type'  => $trap_type,
            'user_agent' => $user_agent ?: 'Automated Bot',
            'target'     => $target ?: 'Phantom Decoy',
            'details'    => ['target' => $target],
        ];

        self::record_catch($catch_entry);
        self::ban_bot_ip($ip, $duration_hours);

        AuditLogger::log(
            'honeytoken_bot_trapped',
            sprintf('Honey-Token Trapped Bot IP "%s" via %s (%s).', $ip, $trap_type, $target)
        );
    }

    /**
     * Retrieve recent caught bots.
     *
     * @param int $limit
     * @return array
     */
    public static function get_recent_catches(int $limit = 30): array {
        $catches = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            return [];
        }
        return array_slice($catches, 0, $limit);
    }

    /**
     * Get summary telemetry on HoneyToken traps.
     *
     * @return array
     */
    public static function get_summary(): array {
        $catches = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            $catches = [];
        }

        $waf_settings = SettingsManager::get_settings();
        $blocked_ips = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $waf_settings['waf_blocked_ips'] ?? ''))));

        $traps_active = 0;
        $settings = self::get_settings();
        if ($settings['enabled']) {
            if ($settings['trap_login_forms']) $traps_active += 3;
            if ($settings['trap_comment_forms']) $traps_active += 1;
            if ($settings['trap_phantom_endpoints']) $traps_active += 4;
        }

        return [
            'enabled'           => !empty($settings['enabled']),
            'traps_active'      => $traps_active,
            'total_caught'      => count($catches),
            'active_ip_bans'    => count($blocked_ips),
            'active_banned_ips' => count($blocked_ips),
            'settings'          => $settings,
            'recent_catches'    => array_slice($catches, 0, 10),
        ];
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
