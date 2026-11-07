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

    const OPTION_CATCHES          = 'wcpscan_honeytoken_catches';
    const OPTION_SETTINGS         = 'wcpscan_honeytoken_settings';
    const FIELD_NAME              = 'wcp_security_verify';
    const FIELD_FLAG              = 'wcp_hp_active';
    const CANARY_ADMIN_USER        = 'wcp_canary_admin';
    const CANARY_USER_META         = '_wcpscan_is_canary';
    const OPTION_CANARY_DB_PLANTED = 'wcpscan_canary_db_planted';
    const CANARY_HONEY_OPTIONS     = [
        '_wcpscan_canary_aws_secret',
        '_wcpscan_canary_stripe_secret',
        '_wcpscan_canary_vault_backup',
    ];

    /**
     * Internal audit bypass flag to allow WCP Scanner telemetry to inspect canary options safely.
     *
     * @var bool
     */
    public static bool $internal_audit_bypass = false;

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

        // 3. Phantom Decoy Endpoints & Active Canary Callbacks
        add_action('init', [__CLASS__, 'inspect_for_canary_trigger'], 0);
        if (!empty($settings['trap_phantom_endpoints'])) {
            add_action('init', [__CLASS__, 'check_phantom_endpoints'], 0);
        }

        // 4. Ghost Admin Canary User & Authentication Tripwire (Pillar 8: Database Canaries)
        if (!empty($settings['enable_canary_admin'])) {
            add_filter('authenticate', [__CLASS__, 'inspect_canary_admin_auth'], 1, 3);
            add_action('init', [__CLASS__, 'ensure_canary_admin_seeded'], 20);
            add_action('pre_user_query', [__CLASS__, 'hide_canary_admin_from_user_list'], 10, 1);
        }

        // 5. Database Honey Options Sentinel (Pillar 8: Decoy Credentials)
        if (!empty($settings['enable_honey_options'])) {
            add_action('init', [__CLASS__, 'ensure_honey_options_seeded'], 20);
            foreach (self::CANARY_HONEY_OPTIONS as $honey_key) {
                add_filter('pre_option_' . $honey_key, function ($pre_val) use ($honey_key) {
                    return self::trap_honey_option_access($pre_val, $honey_key);
                }, 10, 1);
            }
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
            'enable_canary_admin'      => true,
            'enable_honey_options'     => true,
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
        $merged['enable_canary_admin']      = !isset($merged['enable_canary_admin']) || !empty($merged['enable_canary_admin']);
        $merged['enable_honey_options']     = !isset($merged['enable_honey_options']) || !empty($merged['enable_honey_options']);

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

        $canary_admin = isset($new_settings['enable_canary_admin'])
            ? !empty($new_settings['enable_canary_admin'])
            : (!isset($current['enable_canary_admin']) || !empty($current['enable_canary_admin']));

        $honey_options = isset($new_settings['enable_honey_options'])
            ? !empty($new_settings['enable_honey_options'])
            : (!isset($current['enable_honey_options']) || !empty($current['enable_honey_options']));

        $enabled = isset($new_settings['enabled'])
            ? !empty($new_settings['enabled'])
            : ($form_traps || $phantom_traps || $canary_admin || $honey_options || !empty($current['enabled']));

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
            'enable_canary_admin'      => $canary_admin,
            'enable_honey_options'     => $honey_options,
        ];
        update_option(self::OPTION_SETTINGS, $updated);

        if ($canary_admin) {
            self::ensure_canary_admin_seeded();
        }
        if ($honey_options) {
            self::ensure_honey_options_seeded();
        }

        // Audit Trail: Log Honey-Token bot trap policy modification
        $diff = \WcpScanner\System\SettingsManager::compute_settings_diff($current, $updated);
        if (!empty($diff) && class_exists('\WcpScanner\System\WcpActivityLogger')) {
            \WcpScanner\System\WcpActivityLogger::notice(
                'honeytoken_settings_updated',
                'firewall',
                [
                    'changed_count' => count($diff),
                    'description'   => sprintf('Honey-Token Bot Trap settings modified (%d parameter(s)).', count($diff)),
                    'module'        => 'honeytoken_traps',
                    'diff'          => $diff,
                ]
            );
        }

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

        // 0. Prefetch Immunity Check (Chrome Speculation Rules / Link Pre-loaders)
        $purpose_headers = [
            isset($_SERVER['HTTP_SEC_PURPOSE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_PURPOSE'])) : '',
            isset($_SERVER['HTTP_PURPOSE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_PURPOSE'])) : '',
            isset($_SERVER['HTTP_X_PURPOSE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PURPOSE'])) : '',
            isset($_SERVER['HTTP_X_MOZ']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_MOZ'])) : '',
        ];
        foreach ($purpose_headers as $h) {
            if (!empty($h) && (stripos((string) $h, 'prefetch') !== false || stripos((string) $h, 'preview') !== false)) {
                return; // Silently ignore speculative browser prefetch probes
            }
        }

        // Check if IP is in the central WAF Whitelist or belongs to server / local gateway
        $is_whitelisted = false;
        if ((function_exists('current_user_can') && current_user_can('manage_options'))
            || (class_exists('\\WcpScanner\\Firewall\\FirewallEngine') && FirewallEngine::is_authenticated_administrator())) {
            return; // Never terminate or ban a verified active administrator
        }

        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            if (FirewallEngine::is_server_origin_or_loopback($client_ip)) {
                return; // Never terminate or ban server origin or loopback/local dev gateways
            }
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
        if (php_sapi_name() !== 'cli' && !defined('WCPSCAN_TESTING')) {
            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Access Denied: Automated bot activity detected and quarantined by WCP Security Scanner.';
            exit;
        }
    }

    /**
     * Ban a trapped bot IP.
     *
     * @param string $ip
     * @param int $duration_hours
     */
    public static function ban_bot_ip(string $ip, int $duration_hours = 24) {
        if ((function_exists('current_user_can') && current_user_can('manage_options'))
            || (class_exists('\\WcpScanner\\Firewall\\FirewallEngine') && FirewallEngine::is_authenticated_administrator())) {
            return;
        }
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            if (FirewallEngine::is_server_origin_or_loopback($ip)) {
                return;
            }
            FirewallEngine::add_blocked_ip(
                $ip,
                'Honeytoken trap triggered',
                $duration_hours * 3600,
                null,
                'HONEYTOKEN-TRAP',
                'Honeytoken Trap',
                'Bot Trap'
            );
        } else {
            $waf_settings = SettingsManager::get_settings();
            $blocked_ips = $waf_settings['waf_blocked_ips'] ?? '';

            $ip_list = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $blocked_ips))));
            if (!in_array($ip, $ip_list, true)) {
                $ip_list[] = $ip;
                SettingsManager::save_settings(['waf_blocked_ips' => implode("\n", $ip_list)]);
            }
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
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            FirewallEngine::remove_blocked_ip($ip);
        } else {
            $waf_settings = SettingsManager::get_settings();
            $blocked_ips = $waf_settings['waf_blocked_ips'] ?? '';

            $ip_list = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $blocked_ips))));
            $ip_list = array_values(array_filter($ip_list, fn($item) => $item !== $ip));
            SettingsManager::save_settings(['waf_blocked_ips' => implode("\n", $ip_list)]);
        }
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
        update_option(self::OPTION_CATCHES, $catches, false);
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

        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('behavioral_bot_trap_triggered', [
                'severity' => 'high',
                /* translators: 1: IP address, 2: trap type */
                'message'  => sprintf(__('Behavioral Honeytoken tripped by offensive bot IP "%1$s" via %2$s.', 'wcp-security-scanner'), $ip, $trap_type),
                'details'  => [
                    'Offensive IP' => $ip,
                    'Trap Type'    => $trap_type,
                    'Target Decoy' => $target ?: 'Phantom Decoy',
                    'User Agent'   => $user_agent ?: 'Automated Bot',
                    'Ban Duration' => $duration_hours . ' hours',
                ],
            ]);
        }

        AuditLogger::log(
            'honeytoken_bot_trapped',
            sprintf('Honey-Token Trapped Bot IP "%s" via %s (%s).', $ip, $trap_type, $target)
        );
    }

    const CANARY_PREFIX   = 'sk-wcp-canary-';

    /**
     * Generate a realistic decoy .env payload with an active canary token tied to the probing IP.
     *
     * @param string $probing_ip
     * @return string
     */
    public static function generate_decoy_env_payload(string $probing_ip): string {
        $canary_id  = self::create_signed_canary_id($probing_ip);
        $api_token  = self::CANARY_PREFIX . $canary_id;
        $canary_url = add_query_arg(
            ['wcp_canary_ping' => $canary_id],
            home_url('/wp-json/wcp/v1/health-sync')
        );

        $salt = defined('AUTH_KEY') ? AUTH_KEY : 'wcp_canary_salt';
        $fake_aws_key = 'AKIA' . strtoupper(substr(hash_hmac('sha256', 'aws:' . $canary_id, $salt), 0, 16));

        return implode(
            "\n",
            [
                'APP_ENV=production',
                'DB_HOST=127.0.0.1',
                'OPENAI_API_KEY=' . $api_token,
                'WCP_MANAGEMENT_WEBHOOK=' . $canary_url,
                'AWS_ACCESS_KEY_ID=' . $fake_aws_key,
            ]
        ) . "\n";
    }

    /**
     * Inspect incoming request for triggered canary tokens or honeytoken Bearer headers.
     *
     * @return bool
     */
    public static function inspect_for_canary_trigger(): bool {
        $triggered_token = '';

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['wcp_canary_ping'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $triggered_token = sanitize_text_field(wp_unslash($_GET['wcp_canary_ping']));
        }

        $auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION'])) : '';
        if (str_contains($auth_header, self::CANARY_PREFIX)) {
            $triggered_token = trim(str_replace(['Bearer', self::CANARY_PREFIX], '', $auth_header));
        }

        if (empty($triggered_token) || !self::verify_signed_canary_id($triggered_token)) {
            return false;
        }

        $c2_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
        self::alert_and_contain_c2($c2_ip, $triggered_token);

        status_header(403);
        exit;
    }

    private static function create_signed_canary_id(string $probing_ip): string {
        $timestamp = (string) time();
        $data      = $probing_ip . '|' . $timestamp;
        $salt      = defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'wcp_canary_secure_salt';
        $mac       = substr(hash_hmac('sha256', $data, $salt), 0, 24);
        return base64_encode($data) . '.' . $mac;
    }

    private static function verify_signed_canary_id(string $token): bool {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return false;
        }

        $decoded = base64_decode($parts[0], true);
        if (false === $decoded || !str_contains($decoded, '|')) {
            return false;
        }

        $salt = defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'wcp_canary_secure_salt';
        $expected_mac = substr(hash_hmac('sha256', $decoded, $salt), 0, 24);
        return hash_equals($expected_mac, $parts[1]);
    }

    private static function alert_and_contain_c2(string $c2_ip, string $token): void {
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            FirewallEngine::add_blocked_ip($c2_ip, 'Canary Honeytoken Triggered: External C2 probing decoy credentials', 86400, 'canary_trap', 'Honeytoken Alert');
        }

        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('canary_honeytoken_triggered', [
                'severity' => 'critical',
                'c2_ip'    => $c2_ip,
                'token'    => $token,
                'ua'       => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
                'title'    => __('Hostile C2 Honeytoken Callback Intercepted', 'wcp-security-scanner'),
            ]);
        }
    }

    /**
     * Seed dormant Ghost Admin Canary user in wp_users if not present.
     */
    public static function ensure_canary_admin_seeded(): void {
        $settings = self::get_settings();
        if (empty($settings['enabled']) || empty($settings['enable_canary_admin'])) {
            return;
        }

        // Fast path: if already seeded, skip to prevent overhead on every request
        if (get_option('_wcpscan_canary_admin_planted', false)) {
            return;
        }

        self::$internal_audit_bypass = true;
        try {
            $existing = get_user_by('login', self::CANARY_ADMIN_USER);
            if ($existing instanceof \WP_User) {
                if (!get_user_meta($existing->ID, self::CANARY_USER_META, true)) {
                    update_user_meta($existing->ID, self::CANARY_USER_META, 1);
                }
                update_option('_wcpscan_canary_admin_planted', time(), false);
                return;
            }

            // Generate impossible password hash
            $impossible_pass = wp_hash_password(bin2hex(random_bytes(32))) . '!CANARY_LOCKED_' . bin2hex(random_bytes(8));
            $site_slug       = substr(md5(home_url()), 0, 8);
            $user_email      = 'security-canary-' . $site_slug . '@invalid.local';

            $user_id = wp_insert_user([
                'user_login'    => self::CANARY_ADMIN_USER,
                'user_pass'     => $impossible_pass,
                'user_email'    => $user_email,
                'user_nicename' => 'security-canary',
                'display_name'  => 'WCP Security Canary Admin',
                'nickname'      => 'canary-admin',
                'role'          => 'administrator',
            ]);

            if (!is_wp_error($user_id)) {
                update_user_meta($user_id, self::CANARY_USER_META, 1);
                update_user_meta($user_id, '_wcpscan_canary_created', time());
                update_option('_wcpscan_canary_admin_planted', time(), false);

                if (class_exists(AuditLogger::class)) {
                    AuditLogger::log(
                        'canary_admin_seeded',
                        sprintf('Seeded Ghost Admin canary user "%s" (ID: %d) as high-priority database tripwire.', self::CANARY_ADMIN_USER, $user_id)
                    );
                }
            }
        } finally {
            self::$internal_audit_bypass = false;
        }
    }

    /**
     * Intercept authentication attempts targeting the Ghost Admin Canary user.
     *
     * @param mixed  $user
     * @param string $username
     * @param string $password
     * @return mixed
     */
    public static function inspect_canary_admin_auth($user, $username, $password) {
        if (empty($username) || !is_string($username)) {
            return $user;
        }

        $clean_user = strtolower(trim($username));
        $is_canary  = false;

        if ($clean_user === strtolower(self::CANARY_ADMIN_USER)) {
            $is_canary = true;
        } else {
            $matched = get_user_by('login', $clean_user);
            if ($matched instanceof \WP_User && get_user_meta($matched->ID, self::CANARY_USER_META, true)) {
                $is_canary = true;
            }
        }

        if ($is_canary) {
            $client_ip = self::get_client_ip();

            // Fire immediate tripwire trap & auto-ban
            self::trigger_trap('canary_admin_login_breach', [
                'target'      => 'Ghost Admin Canary User (' . self::CANARY_ADMIN_USER . ')',
                'username'    => $clean_user,
                'ip'          => $client_ip,
                'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown',
                'description' => sprintf('CRITICAL BREACH: Unauthorized login attempt detected on dormant Ghost Admin Canary "%s". IP %s quarantined.', self::CANARY_ADMIN_USER, $client_ip),
            ]);

            if (class_exists(NotificationDispatcher::class)) {
                NotificationDispatcher::trigger('db_canary_tripwire_breach', [
                    'severity'    => 'critical',
                    'canary_type' => 'ghost_admin_user',
                    'username'    => $clean_user,
                    'ip'          => $client_ip,
                    'timestamp'   => current_time('mysql'),
                    'title'       => __('CRITICAL TRIPWIRE: Canary Ghost Admin Login Attempted', 'wcp-security-scanner'),
                ]);
            }

            return new \WP_Error('invalid_username', __('Unknown username. Check again or try your email address.', 'wcp-security-scanner'));
        }

        return $user;
    }

    /**
     * Hide Ghost Admin Canary from standard WordPress user management screens (users.php).
     *
     * @param \WP_User_Query $user_query
     */
    public static function hide_canary_admin_from_user_list($user_query): void {
        global $pagenow, $wpdb;

        if (is_admin() && $pagenow === 'users.php' && !self::$internal_audit_bypass) {
            $user_query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.user_login != %s", self::CANARY_ADMIN_USER);
        }
    }

    /**
     * Seed decoy honey options in wp_options.
     */
    public static function ensure_honey_options_seeded(): void {
        $settings = self::get_settings();
        if (empty($settings['enabled']) || empty($settings['enable_honey_options'])) {
            return;
        }

        // Fast path: if already seeded, skip immediately to prevent query overhead
        if (get_option(self::OPTION_CANARY_DB_PLANTED, false)) {
            return;
        }

        self::$internal_audit_bypass = true;
        try {
            global $wpdb;
            $salt     = defined('AUTH_KEY') ? AUTH_KEY : 'wcp_canary_salt';
            $site_key = substr(md5(home_url() . $salt), 0, 16);

            $decoys = [
                '_wcpscan_canary_aws_secret'    => 'AKIA' . strtoupper(substr(hash('sha256', 'aws:' . $site_key), 0, 16)) . ':' . bin2hex(random_bytes(20)),
                '_wcpscan_canary_stripe_secret' => 'sk_live_canary_' . substr(hash('sha256', 'stripe:' . $site_key), 0, 24),
                '_wcpscan_canary_vault_backup'  => 'https://vault-backup.internal/db-snap-' . $site_key . '.sql.enc',
            ];

            foreach ($decoys as $key => $val) {
                // Direct SQL query in $wpdb completely bypasses get_option filters and traps
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct check required to bypass honeypot pre_option filters
                $exists = $wpdb->get_var($wpdb->prepare("SELECT option_id FROM {$wpdb->options} WHERE option_name = %s", $key));
                if (!$exists) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Decoy option seeding must avoid triggering honeypot hooks
                    $wpdb->insert(
                        $wpdb->options,
                        [
                            'option_name'  => $key,
                            'option_value' => $val,
                            'autoload'     => 'no',
                        ],
                        ['%s', '%s', '%s']
                    );
                }
            }

            update_option(self::OPTION_CANARY_DB_PLANTED, time(), false);
        } finally {
            self::$internal_audit_bypass = false;
        }
    }

    /**
     * Intercept unauthorized access to Database Honey Options.
     *
     * @param mixed  $pre_val
     * @param string $option_name
     * @return mixed
     */
    public static function trap_honey_option_access($pre_val, string $option_name) {
        if (self::$internal_audit_bypass) {
            return $pre_val;
        }

        // Ignore internal CLI / cron executions
        if ((defined('WP_CLI') && WP_CLI && !defined('WCPSCAN_TESTING')) || (defined('DOING_CRON') && DOING_CRON)) {
            return $pre_val;
        }

        // If user is a verified administrator actively browsing wp-admin, bypass punitive termination
        if ((function_exists('current_user_can') && current_user_can('manage_options'))
            || (class_exists('\\WcpScanner\\Firewall\\FirewallEngine') && FirewallEngine::is_authenticated_administrator())) {
            return $pre_val;
        }

        $client_ip = self::get_client_ip();

        // Local loopback and server origin IPs are always immune
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine') && FirewallEngine::is_server_origin_or_loopback($client_ip)) {
            return $pre_val;
        }

        self::trigger_trap('canary_option_access_breach', [
            'target'      => 'Database Honey Option (' . $option_name . ')',
            'option_name' => $option_name,
            'ip'          => $client_ip,
            'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown',
            'description' => sprintf('CRITICAL BREACH: Unauthorized code or SQL probe queried decoy database option "%s". IP %s quarantined.', $option_name, $client_ip),
        ]);

        if (class_exists(NotificationDispatcher::class)) {
            NotificationDispatcher::trigger('db_canary_tripwire_breach', [
                'severity'    => 'critical',
                'canary_type' => 'honey_option',
                'option_name' => $option_name,
                'ip'          => $client_ip,
                'timestamp'   => current_time('mysql'),
                'title'       => __('CRITICAL TRIPWIRE: Database Honey Option Accessed', 'wcp-security-scanner'),
            ]);
        }

        return $pre_val;
    }

    /**
     * Reseed / verify all database canaries (Ghost Admin & Honey Options).
     *
     * @return array
     */
    public static function reseed_db_canaries(): array {
        delete_option(self::OPTION_CANARY_DB_PLANTED);
        delete_option('_wcpscan_canary_admin_planted');

        self::$internal_audit_bypass = true;
        try {
            self::ensure_canary_admin_seeded();
            self::ensure_honey_options_seeded();
        } finally {
            self::$internal_audit_bypass = false;
        }

        return [
            'success' => true,
            'message' => __('Database Canary Honey-Tokens and Ghost Admin user verified and seeded successfully.', 'wcp-security-scanner'),
            'summary' => self::get_summary(),
        ];
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
            if (!empty($settings['enable_canary_admin'])) $traps_active += 1;
            if (!empty($settings['enable_honey_options'])) $traps_active += count(self::CANARY_HONEY_OPTIONS);
        }

        // Check canary admin existence
        $canary_admin_user   = get_user_by('login', self::CANARY_ADMIN_USER);
        $canary_admin_active = ($canary_admin_user instanceof \WP_User);

        // Check honey options existence
        $honey_options_seeded = (bool) get_option(self::OPTION_CANARY_DB_PLANTED, false);

        return [
            'enabled'              => !empty($settings['enabled']),
            'traps_active'         => $traps_active,
            'total_caught'         => count($catches),
            'active_ip_bans'       => count($blocked_ips),
            'active_banned_ips'    => count($blocked_ips),
            'canary_admin_user'    => self::CANARY_ADMIN_USER,
            'canary_admin_active'  => $canary_admin_active,
            'canary_admin_id'      => $canary_admin_user instanceof \WP_User ? (int) $canary_admin_user->ID : null,
            'honey_options_seeded' => $honey_options_seeded,
            'honey_option_keys'    => self::CANARY_HONEY_OPTIONS,
            'settings'             => $settings,
            'recent_catches'       => array_slice($catches, 0, 10),
        ];
    }

    /**
     * Safe client IP resolution delegating to FirewallEngine.
     */
    private static function get_client_ip(): string {
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            return FirewallEngine::get_client_ip();
        }
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
    }
}
