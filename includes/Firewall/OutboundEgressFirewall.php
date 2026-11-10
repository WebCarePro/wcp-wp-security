<?php
namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * OutboundEgressFirewall
 *
 * Outbound AI & SSRF Egress Firewall.
 * Hooks into WordPress HTTP transport layers to inspect, govern, and block outbound network calls.
 * Prevents unauthorized external exfiltration, reverse shells, and SSRF attacks targeting cloud metadata.
 */
class OutboundEgressFirewall {

    const OPTION_SETTINGS = 'webcareproscan_egress_settings';
    const OPTION_EVENTS   = 'webcareproscan_egress_events';

    /**
     * Known dangerous exfiltration drop points and webhook APIs.
     */
    const MALICIOUS_SINK_PATTERNS = [
        'discord'  => '/(?:discord(?:app)?\.com\/api\/webhooks)/i',
        'telegram' => '/(?:api\.telegram\.org\/bot)/i',
        'pastebin' => '/(?:pastebin\.com\/api)/i',
        'iplogger' => '/(?:iplogger\.(?:org|com|ru))/i',
        'transfer' => '/(?:transfer\.sh)/i',
    ];

    /**
     * Default approved external domains and APIs (WordPress core, WooCommerce, payments, AI, CDNs, mailers).
     */
    const DEFAULT_APPROVED_HOSTS = [
        // WordPress Core & Community
        'wordpress.org',
        'api.wordpress.org',
        'downloads.wordpress.org',
        'dashboard.wordpress.org',
        // WooCommerce Ecosystem
        'woocommerce.com',
        'connect.woocommerce.com',
        // Payment Gateways
        'stripe.com',
        'api.stripe.com',
        'paypal.com',
        'api.paypal.com',
        // Official AI Providers
        'api.openai.com',
        'api.anthropic.com',
        'generativelanguage.googleapis.com',
        // Cloud Infrastructure & Updates
        'api.cloudflare.com',
        'secure.gravatar.com',
        'api.github.com',
        // Google Services & Gmail API (OAuth & SMTP)
        'gmail.googleapis.com',
        'oauth2.googleapis.com',
        'smtp.gmail.com',
        // Microsoft 365, Office 365 & Outlook Services
        'graph.microsoft.com',
        'login.microsoftonline.com',
        'outlook.office.com',
        'outlook.office365.com',
        'smtp.office365.com',
        // Transactional Mailers & SMTP Relays (Post SMTP, WP Mail SMTP, FluentSMTP)
        'sendgrid.com',
        'api.sendgrid.com',
        'sendgrid.net',
        'smtp.sendgrid.net',
        'mailgun.net',
        'api.mailgun.net',
        'mailgun.org',
        'smtp.mailgun.org',
        'postmarkapp.com',
        'api.postmarkapp.com',
        'smtp.postmarkapp.com',
        'brevo.com',
        'api.brevo.com',
        'smtp-relay.brevo.com',
        'sendinblue.com',
        'mailersend.com',
        'api.mailersend.com',
        'mailtrap.io',
        'api.mailtrap.io',
        'send.api.mailtrap.io',
        'live.smtp.mailtrap.io',
        'resend.com',
        'api.resend.com',
        'smtp.resend.com',
        'mandrillapp.com',
        'smtp.com',
        'api.smtp.com',
        'mailjet.com',
        'api.mailjet.com',
        'in-v3.mailjet.com',
        'sendpulse.com',
        'api.sendpulse.com',
        'smtp-pulse.com',
        'sparkpost.com',
        'api.sparkpost.com',
        'sparkpostmail.com',
        'smtp.sparkpostmail.com',
        'elasticemail.com',
        'api.elasticemail.com',
        'smtp.elasticemail.com',
        'smtp2go.com',
        'api.smtp2go.com',
        'mail.smtp2go.com',
        'emailit.com',
        'api.emailit.com',
        'maileroo.com',
        'api.maileroo.com',
        'smtp.maileroo.com',
        'sweego.com',
        'api.sweego.com',
        'zoho.com',
        'zoho.eu',
        'smtp.zoho.com',
        'accounts.zoho.com',
        'fastmail.com',
        'smtp.fastmail.com',
        // DevSecOps Webhooks & Notifications
        'hooks.slack.com',
        'slack.com',
        'api.clickup.com',
        'app.asana.com',
    ];

    /**
     * Suspicious high-risk TLDs commonly used by disposable C2 droplets.
     */
    const SUSPICIOUS_TLDS = [
        'xyz', 'top', 'click', 'buzz', 'pw', 'work', 'rest', 'monster',
    ];

    /**
     * Cache of pre-resolved validated safe IPs indexed by host for the current request cycle.
     * Prevents TOCTOU DNS rebinding by pinning IP via CURLOPT_RESOLVE in http_api_curl.
     *
     * @var array<string, array>
     */
    private static $resolved_safe_pins = [];

    /**
     * Initialize Outbound Egress Firewall.
     */
    public static function init() {
        $settings = self::get_settings();
        if ($settings['mode'] === 'disabled') {
            return;
        }

        // Intercept all HTTP requests executed via wp_remote_get, wp_remote_post, Requests, etc.
        add_filter('pre_http_request', [__CLASS__, 'inspect_outbound_request'], 10, 3);

        // Intercept Requests/cURL redirect hops to validate target before following redirect (defeats Redirect-Hop SSRF)
        add_action('requests-requests.before_redirect', [__CLASS__, 'inspect_redirect_hop'], 10, 1);

        // Constrain cURL redirect protocols and pin validated safe IPs via CURLOPT_RESOLVE (defeats TOCTOU DNS rebinding)
        add_action('http_api_curl', [__CLASS__, 'constrain_curl_transport'], 10, 3);
    }

    /**
     * Inspect redirect destination URL during HTTP requests before Requests transport follows it.
     *
     * @param string $location Redirect target location
     * @return void
     */
    public static function inspect_redirect_hop(string $location): void {
        if (empty($location)) {
            return;
        }

        $res = self::inspect_outbound_request(false, [], $location);
        if (is_wp_error($res)) {
            // Throw exception or terminate connection to prevent following malicious redirect hop
            wp_die(
                esc_html($res->get_error_message()),
                esc_html__('SSRF Redirect Blocked', 'webcare-pro-security'),
                ['response' => 403]
            );
        }
    }

    /**
     * Constrain cURL transport to HTTP/HTTPS, prevent dangerous protocol hopping on redirects,
     * and pin pre-validated safe IP addresses via CURLOPT_RESOLVE to defeat TOCTOU DNS rebinding.
     *
     * @param resource|\CurlHandle $handle
     * @param array                $parsed_args
     * @param string               $url
     * @return void
     */
    public static function constrain_curl_transport($handle, $parsed_args, $url): void {
        if (!is_resource($handle) && !(is_object($handle) && $handle instanceof \CurlHandle)) {
            return;
        }

        // Restrict allowed protocols and redirection protocols strictly to HTTP and HTTPS (and SMTP/SMTPS for verified mailers)
        $is_mailer = self::is_active_mailer_component(self::extract_calling_component());
        $allowed_protocols = 0;
        if (defined('CURLPROTO_HTTP')) {
            $allowed_protocols |= CURLPROTO_HTTP;
        }
        if (defined('CURLPROTO_HTTPS')) {
            $allowed_protocols |= CURLPROTO_HTTPS;
        }
        if ($is_mailer) {
            if (defined('CURLPROTO_SMTP')) {
                $allowed_protocols |= CURLPROTO_SMTP;
            }
            if (defined('CURLPROTO_SMTPS')) {
                $allowed_protocols |= CURLPROTO_SMTPS;
            }
        }

        if (defined('CURLOPT_PROTOCOLS') && $allowed_protocols > 0) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
            @curl_setopt($handle, CURLOPT_PROTOCOLS, $allowed_protocols);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS') && $allowed_protocols > 0) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
            @curl_setopt($handle, CURLOPT_REDIR_PROTOCOLS, $allowed_protocols);
        }

        // Redirect-Hop SSRF Defense: Limit internal cURL follow-redirect hops to 3 to prevent infinite redirect loops
        if (defined('CURLOPT_MAXREDIRS')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
            @curl_setopt($handle, CURLOPT_MAXREDIRS, 3);
        }

        // TOCTOU DNS Rebinding Defense: Pin validated safe IP directly to cURL via CURLOPT_RESOLVE
        if (!empty($url) && defined('CURLOPT_RESOLVE')) {
            $parsed_url = wp_parse_url($url);
            $host = strtolower($parsed_url['host'] ?? '');
            if (!empty($host) && isset(self::$resolved_safe_pins[$host])) {
                $pin_data = self::$resolved_safe_pins[$host];
                $safe_ip  = $pin_data['ip'] ?? '';
                $port     = (int) ($parsed_url['port'] ?? (($parsed_url['scheme'] ?? 'https') === 'http' ? 80 : 443));
                if (!empty($safe_ip) && $port > 0) {
                    // Strip ::ffff: IPv4-mapped IPv6 prefix if present
                    if (str_starts_with($safe_ip, '::ffff:')) {
                        $safe_ip = substr($safe_ip, 7);
                    }
                    // Format IPv6 with brackets in CURLOPT_RESOLVE (host:port:[ipv6])
                    $formatted_ip = (str_contains($safe_ip, ':') && !str_starts_with($safe_ip, '[')) ? "[{$safe_ip}]" : $safe_ip;
                    $resolve_entry = "{$host}:{$port}:{$formatted_ip}";
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
                    @curl_setopt($handle, CURLOPT_RESOLVE, [$resolve_entry]);
                }
            }
        }
    }

    /**
     * Get Outbound Egress Firewall settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'mode'                 => 'monitor', // disabled, monitor, enforce
            'block_ssrf_metadata'  => true,
            'block_exfil_webhooks' => true,
            'block_suspicious_tld' => false,
            'allowed_hosts'        => [],
        ];
        $saved = get_option(self::OPTION_SETTINGS, []);
        return is_array($saved) ? array_merge($defaults, $saved) : $defaults;
    }

    /**
     * Update Outbound Egress Firewall settings.
     *
     * @param array $settings
     * @return bool
     */
    public static function update_settings(array $settings): bool {
        $current = self::get_settings();
        $mode = $settings['mode'] ?? 'monitor';
        if (!in_array($mode, ['disabled', 'monitor', 'enforce'], true)) {
            $mode = 'monitor';
        }

        $allowed_hosts = [];
        if (!empty($settings['allowed_hosts'])) {
            $raw_hosts = is_array($settings['allowed_hosts']) ? $settings['allowed_hosts'] : explode("\n", $settings['allowed_hosts']);
            foreach ($raw_hosts as $h) {
                $cleaned = strtolower(trim(sanitize_text_field($h)));
                if (!empty($cleaned)) {
                    $allowed_hosts[] = $cleaned;
                }
            }
        }

        $updated = [
            'mode'                 => $mode,
            'block_ssrf_metadata'  => !empty($settings['block_ssrf_metadata']),
            'block_exfil_webhooks' => !empty($settings['block_exfil_webhooks']),
            'block_suspicious_tld' => !empty($settings['block_suspicious_tld']),
            'allowed_hosts'        => array_values(array_unique($allowed_hosts)),
        ];

        $final = array_merge($current, $updated);
        $res = update_option(self::OPTION_SETTINGS, $final, false);

        // Audit Trail: Log Outbound Egress policy changes
        $diff = \WebCareProScanner\System\SettingsManager::compute_settings_diff($current, $final);
        if (!empty($diff) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'egress_firewall_settings_updated',
                'firewall',
                [
                    'changed_count' => count($diff),
                    'description'   => sprintf('Outbound Egress & SSRF Firewall policy updated (%d parameter(s)).', count($diff)),
                    'module'        => 'egress_firewall',
                    'diff'          => $diff,
                ]
            );
        }

        return $res;
    }

    /**
     * Inspect outbound HTTP request initiated by WordPress core, plugins, or themes.
     *
     * @param false|array|\WP_Error $preempt
     * @param array                  $parsed_args
     * @param string                 $url
     * @return false|array|\WP_Error
     */
    public static function inspect_outbound_request($preempt, $parsed_args, $url) {
        if ($preempt !== false || empty($url)) {
            return $preempt;
        }

        $settings = self::get_settings();
        if ($settings['mode'] === 'disabled') {
            return false;
        }

        $parsed_url = wp_parse_url($url);
        $host = strtolower($parsed_url['host'] ?? '');
        if (empty($host)) {
            return false;
        }

        // 1. Identify calling plugin or theme via backtrace
        $caller = self::extract_calling_component();
        $is_mailer = self::is_active_mailer_component($caller);

        $threat = null;
        $reason = '';

        // 2. SSRF, Binary IP Normalization, Loopback & Cloud Metadata Check (HARD DENY PRECEDENCE)
        // Resolves hostnames and checks decimal/hex/IPv6 encodings, link-local, loopback, private subnets, and cloud metadata.
        // Pin validated safe IP to prevent TOCTOU DNS rebinding in curl.
        if (!empty($settings['block_ssrf_metadata'])) {
            $site_home_url = home_url();
            $site_host = strtolower(wp_parse_url($site_home_url, PHP_URL_HOST) ?? '');
            $site_port = (int) (wp_parse_url($site_home_url, PHP_URL_PORT) ?: (wp_parse_url(site_url(), PHP_URL_PORT) ?: (is_ssl() ? 443 : 80)));
            $port = isset($parsed_url['port']) ? (int) $parsed_url['port'] : null;
            $request_path = strtolower($parsed_url['path'] ?? '');

            // Standard allowed outbound web ports
            $allowed_web_ports = [80, 443, 8080, 8443];

            // Transactional mail ports (SMTP, SMTPS, Submission, Alternate)
            $standard_mail_ports = [465, 587, 2525];
            $is_host_approved = self::is_host_approved($host, $settings, '', $is_mailer);

            // Port 25 Hardening: Port 25 is ONLY permitted if caller is a verified mailer AND destination is an approved mail relay
            if ($is_mailer && $is_host_approved) {
                $standard_mail_ports[] = 25;
            }

            if ($is_mailer || $is_host_approved) {
                $allowed_web_ports = array_merge($allowed_web_ports, $standard_mail_ports);
            }

            if ($site_port > 0 && !in_array($site_port, $allowed_web_ports, true)) {
                $allowed_web_ports[] = $site_port;
            }
            // If the incoming HTTP host has a port (e.g. localhost:8282), allow it as well
            if (!empty($_SERVER['HTTP_HOST'])) {
                $raw_host_port = (int) (wp_parse_url('http://' . sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])), PHP_URL_PORT) ?: 0);
                if ($raw_host_port > 0 && !in_array($raw_host_port, $allowed_web_ports, true)) {
                    $allowed_web_ports[] = $raw_host_port;
                }
            }
            if (!empty($_SERVER['SERVER_PORT'])) {
                $server_port = (int) $_SERVER['SERVER_PORT'];
                if ($server_port > 0 && !in_array($server_port, $allowed_web_ports, true)) {
                    $allowed_web_ports[] = $server_port;
                }
            }

            // High-risk internal ports that should never be probed even on same host (e.g., Redis, Memcached, MySQL, Postgres, MongoDB, Elastic)
            $restricted_internal_ports = [3306, 5432, 6379, 11211, 27017, 9200, 22, 23, 21];
            // Restrict port 25 unless caller is a verified mailer contacting an approved mail relay
            if (!($is_mailer && $is_host_approved)) {
                $restricted_internal_ports[] = 25;
            }

            $is_same_host = ($host === $site_host) || in_array($host, ['localhost', '127.0.0.1', '::1'], true);
            $is_wp_cron_or_loopback = (strpos($request_path, 'wp-cron.php') !== false) || (strpos($request_path, 'wp-admin') !== false) || (strpos($request_path, 'wp-json') !== false);

            // Same-host loopbacks (e.g. wp-cron.php, site-health loopback checks, REST background calls)
            // are legitimate WordPress internal self-requests unless explicitly probing a database/cache service port.
            if ($is_same_host && ($port === null || !in_array($port, $restricted_internal_ports, true)) && ($is_wp_cron_or_loopback || in_array($port, $allowed_web_ports, true))) {
                // Legitimate internal self-request to site itself; do not treat as external SSRF
            } else {
                // 1. Restricted Port Defense: Port 25, DB, and cache service ports blocked unconditionally
                if ($port !== null && in_array($port, $restricted_internal_ports, true)) {
                    $threat = 'internal_port_probe';
                    $reason = sprintf('Outbound request targeting restricted internal/mail port (%1$d) on %2$s.', $port, $host);
                } else {
                    // 2. Hard SSRF Evaluation: Must run BEFORE any allowlist or mailer fast-path!
                    // An allowlisted host resolving to 127.0.0.1, 169.254.169.254, or RFC1918 will be caught and denied here.
                    $ssrf_eval = self::evaluate_ssrf_destination($host);
                    if (!empty($ssrf_eval['threat'])) {
                        $threat = $ssrf_eval['threat'];
                        $reason = $ssrf_eval['reason'];
                    } elseif (!empty($ssrf_eval['safe_ip'])) {
                        // Record safe pinned IP for CURLOPT_RESOLVE in constrain_curl_transport()
                        self::$resolved_safe_pins[$host] = [
                            'ip'        => $ssrf_eval['safe_ip'],
                            'timestamp' => time(),
                        ];
                    }
                }
            }
        }

        // 3. Post-SSRF Verified Mailer & Approved Host Fast-Path:
        // Now that the destination host is verified safe from SSRF/metadata/loopback/private IP,
        // grant safe-pass if caller is an active mailer component and host is in the approved registry.
        if (!$threat) {
            $is_host_approved = self::is_host_approved($host, $settings, '', $is_mailer);
            if ($is_mailer && $is_host_approved) {
                return false;
            }
        }

        // 3. Raw-IP Outbound Monitor (Catch unverified C2 callback beacons)
        if (!$threat && filter_var($host, FILTER_VALIDATE_IP)) {
            $site_home_url = home_url();
            $site_host = strtolower(wp_parse_url($site_home_url, PHP_URL_HOST) ?? '');
            if ($host !== $site_host && !self::is_host_approved($host, $settings)) {
                $threat = 'raw_ip_egress';
                $reason = sprintf('Outbound network request targeting raw IP address (%s).', $host);
            }
        }

        // 4. Known Exfiltration Webhooks Check
        if (!$threat && !empty($settings['block_exfil_webhooks'])) {
            if (!self::is_authorized_notification_webhook($url, $settings, $caller)) {
                foreach (self::MALICIOUS_SINK_PATTERNS as $name => $pattern) {
                    if (preg_match($pattern, $url)) {
                        $threat = 'exfiltration_webhook';
                        $reason = sprintf('Unauthorized outbound exfiltration webhook or drop point detected: %s', $name);
                        break;
                    }
                }
            }
        }

        // 4. Suspicious TLD Check
        if (!$threat && !empty($settings['block_suspicious_tld'])) {
            $parts = explode('.', $host);
            $tld = end($parts);
            if (in_array($tld, self::SUSPICIOUS_TLDS, true) && !self::is_host_approved($host, $settings)) {
                $threat = 'suspicious_tld';
                $reason = sprintf('Outbound request directed to high-risk unapproved TLD: .%s', $tld);
            }
        }

        // 5. Emergency Containment Lockdown Enforcement
        $is_containment = class_exists('\\WebCareProScanner\\Security\\EmergencyContainmentManager') && \WebCareProScanner\Security\EmergencyContainmentManager::is_active();
        if ($is_containment && !$threat) {
            $is_core_host = ($host === 'api.wordpress.org' || $host === 'wordpress.org' || $host === 'downloads.wordpress.org');
            if (!$is_core_host && !self::is_host_approved($host, $settings)) {
                $threat = 'containment_outbound_freeze';
                $reason = 'Outbound external network connection blocked by active Emergency Incident Containment protocol.';
            }
        }

        if ($threat) {
            // Cloud metadata, localhost SSRF, private network SSRF, restricted port probes, and unresolvable raw-IP/hex vectors are hard-blocked unconditionally even in monitor mode
            $is_hard_block = ($threat === 'ssrf_metadata' || $threat === 'ssrf_loopback' || $threat === 'ssrf_private_network' || $threat === 'internal_port_probe' || ($threat === 'unresolvable_host' && preg_match('/^[0-9a-fA-FxX.]+$/', $host)));
            // Raw-IP egress defaults to monitor mode unless global mode is enforce
            $is_enforced = $is_hard_block || ($settings['mode'] === 'enforce' && $threat !== 'raw_ip_egress') || $is_containment;

            self::record_egress_event($url, $host, $caller, $threat, $reason, $is_enforced ? 'blocked' : 'monitored');

            if ($is_enforced) {
                return new \WP_Error(
                    'webcare_egress_blocked',
                    /* translators: %s: Security reason description */
                    sprintf(__('Outbound network connection blocked by WebCare Egress Firewall. Reason: %s', 'webcare-pro-security'), esc_html($reason)),
                    ['status' => 403]
                );
            }
        }

        return false;
    }

    /**
     * Determine if an outbound webhook URL is an authorized administrative notification endpoint.
     *
     * @param string $url
     * @param array  $settings Egress firewall settings
     * @param array  $caller   Caller component metadata
     * @return bool
     */
    public static function is_authorized_notification_webhook(string $url, array $settings = [], array $caller = []): bool {
        if (empty($url)) {
            return false;
        }

        $clean_target_url = strtolower(trim($url));
        $parsed_url = wp_parse_url($url);
        $host = strtolower($parsed_url['host'] ?? '');

        // 1. If caller is WebCare Pro Security itself, verify if it's sending to an approved service or notification endpoint
        if (!empty($caller['slug']) && $caller['slug'] === 'webcare-pro-security') {
            // Scanner sending to Discord, Slack, ClickUp, Asana, Cloudflare, AI providers, or WordPress.org is trusted
            if (self::is_host_approved($host, $settings) ||
                str_contains($clean_target_url, 'discord.com/api/webhooks/') ||
                str_contains($clean_target_url, 'discordapp.com/api/webhooks/') ||
                str_contains($clean_target_url, 'hooks.slack.com/services/') ||
                str_contains($clean_target_url, 'api.telegram.org/bot')) {
                return true;
            }
        }

        // 2. Check against WebCare Pro Security's configured notification webhooks in SettingsManager
        if (class_exists('\\WebCareProScanner\\System\\SettingsManager')) {
            $webcare_settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $configured_keys = [
                'discord_webhook_url',
                'slack_webhook_url',
                'clickup_webhook_url',
                'asana_webhook_url',
                'generic_webhook_url',
            ];

            foreach ($configured_keys as $key) {
                $configured = strtolower(trim((string) ($webcare_settings[$key] ?? '')));
                if (!empty($configured)) {
                    // Exact match or prefix match
                    if ($clean_target_url === $configured || str_starts_with($clean_target_url, $configured) || str_starts_with($configured, $clean_target_url)) {
                        return true;
                    }
                    // For Discord: compare webhook ID if both are discord webhook URLs
                    if (str_contains($clean_target_url, '/api/webhooks/') && str_contains($configured, '/api/webhooks/')) {
                        $parts_target = explode('/api/webhooks/', $clean_target_url);
                        $parts_config = explode('/api/webhooks/', $configured);
                        if (!empty($parts_target[1]) && !empty($parts_config[1])) {
                            $target_id = explode('/', $parts_target[1])[0] ?? '';
                            $config_id = explode('/', $parts_config[1])[0] ?? '';
                            if (!empty($target_id) && $target_id === $config_id) {
                                return true;
                            }
                        }
                    }
                    // For Telegram: compare bot token ID
                    if (str_contains($clean_target_url, 'api.telegram.org/bot') && str_contains($configured, 'api.telegram.org/bot')) {
                        $parts_target = explode('api.telegram.org/bot', $clean_target_url);
                        $parts_config = explode('api.telegram.org/bot', $configured);
                        if (!empty($parts_target[1]) && !empty($parts_config[1])) {
                            $target_bot = explode('/', $parts_target[1])[0] ?? '';
                            $config_bot = explode('/', $parts_config[1])[0] ?? '';
                            if (!empty($target_bot) && $target_bot === $config_bot) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // 3. Check if host is explicitly listed in approved/allowed hosts
        if (self::is_host_approved($host, $settings)) {
            return true;
        }

        // 4. Extensibility filter: allow other plugins to register approved webhook destinations
        $approved_webhooks = apply_filters('webcare_approved_outbound_webhooks', []);
        if (is_array($approved_webhooks)) {
            foreach ($approved_webhooks as $approved_url) {
                $clean_approved = strtolower(trim((string) $approved_url));
                if (!empty($clean_approved) && (str_starts_with($clean_target_url, $clean_approved) || $clean_target_url === $clean_approved)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Extract the plugin, theme, or core file initiating the outbound call.
     *
     * @return array
     */
    private static function extract_calling_component(): array {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Backtrace required to detect caller plugin for outbound egress firewalling.
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15);
        $caller = [
            'type' => 'core',
            'name' => 'WordPress Core',
            'file' => 'unknown',
            'slug' => 'core',
            'line' => 0,
        ];

        $plugin_dir = defined('WEBCAREPROSCAN_PATH') ? str_replace('\\', '/', WEBCAREPROSCAN_PATH) : '';

        foreach ($trace as $frame) {
            $file = $frame['file'] ?? '';
            $norm = str_replace('\\', '/', $file);

            // Skip egress firewall itself and core HTTP classes
            if (str_contains($norm, 'OutboundEgressFirewall.php') || str_contains($norm, 'class-wp-http') || str_contains($norm, 'Requests/')) {
                continue;
            }

            // Detect calls initiated by WebCare Pro Security itself
            if (($plugin_dir !== '' && str_starts_with($norm, $plugin_dir)) || str_contains($norm, '/plugins/webcare-pro-security/') || str_contains($norm, 'webcare-pro-security')) {
                $caller['type'] = 'plugin';
                $caller['name'] = 'WebCare Pro Security';
                $caller['file'] = basename($norm);
                $caller['slug'] = 'webcare-pro-security';
                $caller['line'] = $frame['line'] ?? 0;
                break;
            }

            if (str_contains($norm, '/wp-content/plugins/')) {
                $parts = explode('/wp-content/plugins/', $norm);
                $sub = explode('/', $parts[1] ?? '');
                $caller['type'] = 'plugin';
                $caller['name'] = $sub[0] ?? 'Unknown Plugin';
                $caller['file'] = $sub[0] ?? 'plugin';
                $caller['slug'] = $sub[0] ?? 'unknown-plugin';
                $caller['line'] = $frame['line'] ?? 0;
                break;
            }

            if (str_contains($norm, '/wp-content/themes/')) {
                $parts = explode('/wp-content/themes/', $norm);
                $sub = explode('/', $parts[1] ?? '');
                $caller['type'] = 'theme';
                $caller['name'] = $sub[0] ?? 'Active Theme';
                $caller['file'] = $sub[0] ?? 'theme';
                $caller['slug'] = $sub[0] ?? 'theme';
                $caller['line'] = $frame['line'] ?? 0;
                break;
            }
        }

        return $caller;
    }

    /**
     * Evaluate SSRF risks, binary IPv4/IPv6 ranges, and decimal/hex/link-local encodings.
     *
     * Defeats decimal integer IPs (e.g. 2852039166 -> 169.254.169.254), hex IPs, IPv6 AWS metadata (fd00:ec2::254),
     * and IPv4-mapped IPv6 encodings (::ffff:169.254.169.254).
     *
     * @param string $host
     * @return array ['threat' => string|null, 'reason' => string]
     */
    private static function evaluate_ssrf_destination(string $host): array {
        static $dns_cache = [];

        $clean_host = trim($host, '[]');

        if (isset($dns_cache[$clean_host])) {
            return $dns_cache[$clean_host];
        }

        // Fast-path: Default approved official WordPress infrastructure hosts bypass DNS resolution penalty
        if (in_array($clean_host, ['api.wordpress.org', 'downloads.wordpress.org', 'wordpress.org', 'plugins.svn.wordpress.org'], true)) {
            return ($dns_cache[$clean_host] = ['threat' => null, 'reason' => '', 'safe_ip' => '']);
        }

        // Normalize or hard-block shorthand/octal/hex IPv4 representations (e.g. 0177.0.0.1, 127.1, 0x7f.1)
        if (preg_match('/^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){1,3}$/i', $clean_host)) {
            if (filter_var($clean_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                return [
                    'threat' => 'ssrf_loopback',
                    'reason' => 'Non-standard octal, hex, or shorthand IPv4 literal blocked to prevent SSRF bypass.',
                ];
            }
        }

        // Direct Cloud Metadata & Link-Local checks
        if ($clean_host === '169.254.169.254' || $clean_host === '100.100.100.200' || $clean_host === 'instance-data') {
            return [
                'threat' => 'ssrf_metadata',
                'reason' => 'Cloud metadata service access attempted (AWS/GCP/Alibaba 169.254.169.254 / 100.100.100.200).',
            ];
        }

        // IPv6 Cloud Metadata (AWS IMDSv2 fd00:ec2::254)
        if (strtolower($clean_host) === 'fd00:ec2::254') {
            return [
                'threat' => 'ssrf_metadata',
                'reason' => 'AWS IPv6 Cloud metadata service access attempted (fd00:ec2::254).',
            ];
        }

        // Direct Localhost & Loopback checks
        if ($clean_host === '127.0.0.1' || $clean_host === 'localhost' || $clean_host === '::1' || $clean_host === '0.0.0.0' || $clean_host === '0:0:0:0:0:0:0:1' || $clean_host === '0:0:0:0:0:0:0:0') {
            return [
                'threat' => 'ssrf_loopback',
                'reason' => 'Unauthorized internal localhost/loopback connection attempted.',
            ];
        }

        // Binary IP inspection using inet_pton if valid IP
        $packed = @inet_pton($clean_host);
        if ($packed !== false) {
            // IPv4 Range Checks
            if (strlen($packed) === 4) {
                $ip_long = ip2long($clean_host);
                if ($ip_long !== false) {
                    // Loopback: 127.0.0.0/8 (0x7F000000)
                    if (($ip_long & 0xFF000000) === 0x7F000000 || $ip_long === 0) {
                        return [
                            'threat' => 'ssrf_loopback',
                            'reason' => 'Unauthorized loopback network connection attempted (127.0.0.0/8).',
                        ];
                    }
                    // Link-Local / Cloud Metadata: 169.254.0.0/16 (0xA9FE0000)
                    if (($ip_long & 0xFFFF0000) === (int) 0xA9FE0000) {
                        return [
                            'threat' => 'ssrf_metadata',
                            'reason' => 'Cloud metadata/link-local address probe attempted (169.254.0.0/16).',
                        ];
                    }
                    // Private RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    if (($ip_long & 0xFF000000) === 0x0A000000 ||
                        ($ip_long & 0xFFF00000) === (int) 0xAC100000 ||
                        ($ip_long & 0xFFFF0000) === (int) 0xC0A80000) {
                        return [
                            'threat' => 'ssrf_private_network',
                            'reason' => 'Private internal RFC1918 network connection attempted.',
                        ];
                    }
                }
            } elseif (strlen($packed) === 16) {
                // IPv6 Loopback: ::1 or any packed representation matching \x00...1
                if ($packed === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" || $packed === str_repeat("\x00", 16)) {
                    return [
                        'threat' => 'ssrf_loopback',
                        'reason' => 'Unauthorized internal IPv6 loopback connection attempted (::1).',
                    ];
                }
                // IPv6 Range Checks: Link-Local fe80::/10
                $first_byte = ord($packed[0]);
                $second_byte = ord($packed[1]);
                if ($first_byte === 0xfe && ($second_byte & 0xc0) === 0x80) {
                    return [
                        'threat' => 'ssrf_metadata',
                        'reason' => 'IPv6 link-local network connection attempted (fe80::/10).',
                    ];
                }
                // IPv6 Unique Local Address: fc00::/7
                if (($first_byte & 0xfe) === 0xfc) {
                    return [
                        'threat' => 'ssrf_private_network',
                        'reason' => 'IPv6 unique local private network connection attempted (fc00::/7).',
                    ];
                }
                // IPv4-mapped IPv6 (::ffff:x.x.x.x) or IPv4-compatible IPv6 (::x.x.x.x)
                if (substr($packed, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" || substr($packed, 0, 12) === str_repeat("\x00", 12)) {
                    $ipv4_part = inet_ntop(substr($packed, 12));
                    if ($ipv4_part) {
                        return self::evaluate_ssrf_destination($ipv4_part);
                    }
                }
            }
            return ['threat' => null, 'reason' => '', 'safe_ip' => $clean_host];
        }

        // Hostname Resolution: Resolve all A and AAAA DNS records to verify and prevent TOCTOU DNS rebinding
        $first_safe_ip = '';
        $has_records = false;
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($clean_host, DNS_A | DNS_AAAA);
            if (is_array($records) && !empty($records)) {
                $has_records = true;
                foreach ($records as $record) {
                    $resolved_ip = $record['ip'] ?? ($record['ipv6'] ?? '');
                    if (!empty($resolved_ip)) {
                        $check = self::evaluate_ssrf_destination($resolved_ip);
                        // Strict zero-trust rule: Reject mixed public/private responses immediately
                        if (!empty($check['threat'])) {
                            return [
                                'threat' => $check['threat'],
                                'reason' => sprintf('DNS record for %s resolved to protected IP %s: %s', $clean_host, $resolved_ip, $check['reason']),
                            ];
                        }
                        if (empty($first_safe_ip)) {
                            $first_safe_ip = $resolved_ip;
                        }
                    }
                }
            }
        }

        // Fallback to gethostbynamel if dns_get_record returned nothing or is disabled
        if (!$has_records && function_exists('gethostbynamel')) {
            $ips = @gethostbynamel($clean_host);
            if (is_array($ips) && !empty($ips)) {
                $has_records = true;
                foreach ($ips as $resolved_ip) {
                    $check = self::evaluate_ssrf_destination($resolved_ip);
                    if (!empty($check['threat'])) {
                        return [
                            'threat' => $check['threat'],
                            'reason' => sprintf('DNS A record for %s resolved to protected IP %s: %s', $clean_host, $resolved_ip, $check['reason']),
                        ];
                    }
                    if (empty($first_safe_ip)) {
                        $first_safe_ip = $resolved_ip;
                    }
                }
            }
        }

        // Fail-safe: If hostname failed to resolve any valid IP records, block outbound connection to prevent blind routing
        if (!$has_records || empty($first_safe_ip)) {
            return [
                'threat' => 'unresolvable_host',
                'reason' => sprintf('Outbound destination host (%s) could not be resolved to a valid IP address.', $clean_host),
            ];
        }

        $result = ['threat' => null, 'reason' => '', 'safe_ip' => $first_safe_ip];
        return ($dns_cache[$clean_host] = $result);
    }

    /**
     * Check if caller or backtrace indicates an active email sending plugin or wp_mail dispatch.
     *
     * @param array $caller
     * @return bool
     */
    public static function is_active_mailer_component(array $caller): bool {
        $mailer_slugs = [
            'post-smtp',
            'wp-mail-smtp',
            'wp-mail-smtp-pro',
            'fluent-smtp',
            'easy-wp-smtp',
            'smtp-mailer',
            'suremails',
            'wp-offload-ses',
            'mailgun',
            'sendgrid-email-delivery-simplified',
            'sparkpost',
            'mailin',
            'brevo-mail',
            'postmark-approved-wordpress-plugin',
            'zoho-mail',
        ];

        $caller_slug = strtolower($caller['slug'] ?? '');
        if (in_array($caller_slug, $mailer_slugs, true)) {
            return true;
        }

        // Check if wp_mail or PHPMailer is active in the backtrace
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Backtrace inspection needed to verify legitimate wp_mail / PHPMailer transactional email dispatch.
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15);
        foreach ($trace as $frame) {
            $func = strtolower($frame['function'] ?? '');
            $cls  = strtolower($frame['class'] ?? '');
            if ($func === 'wp_mail' || str_contains($cls, 'phpmailer') || str_contains($func, 'postman') || str_contains($cls, 'postman')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a destination host belongs to the site's own primary apex domain (e.g. mail.example.com or smtp.example.com for example.com).
     * Strictly bounded to apex domain and legitimate mail service prefixes (mail., smtp., mx., webmail., imap., pop.).
     *
     * @param string $host Destination host to check
     * @param string $site_host_override Optional site host to check against (defaults to home_url/site_url)
     * @return bool
     */
    public static function is_same_domain_mail_host(string $host, string $site_host_override = ''): bool {
        if (empty($host)) {
            return false;
        }
        $clean_host = strtolower(trim($host));
        $site_host  = strtolower(trim($site_host_override));
        if (empty($site_host)) {
            $site_host = strtolower(wp_parse_url(home_url(), PHP_URL_HOST) ?? '');
            if (empty($site_host)) {
                $site_host = strtolower(wp_parse_url(site_url(), PHP_URL_HOST) ?? '');
            }
        }
        if (empty($site_host)) {
            return false;
        }
        if ($site_host_override === '' && in_array($site_host, ['localhost', '127.0.0.1', '::1'], true)) {
            return false;
        }

        // Strip leading www. to extract apex/root domain
        $root_domain = preg_replace('/^www\./i', '', $site_host);

        // 1. Exact match with site apex domain or full site host
        if ($clean_host === $root_domain || $clean_host === $site_host) {
            return true;
        }

        // 2. Strict mail-specific subdomain prefixes only (mail., smtp., mx., webmail., imap., pop.)
        // Defeats arbitrary subdomain bypasses (e.g. evil.example.com or dev.example.com)
        if (preg_match('/^(?:mail|smtp|mx|webmail|imap|pop)\.' . preg_quote($root_domain, '/') . '$/i', $clean_host)) {
            return true;
        }

        return false;
    }

    /**
     * Dynamically extract configured SMTP / API mailer hostnames from active WordPress mailer plugin options.
     *
     * @param bool $force Force fresh reload bypassing static cache
     * @return array<string>
     */
    public static function get_dynamic_mailer_hosts(bool $force = false): array {
        static $cached_hosts = null;
        if ($cached_hosts !== null && !$force) {
            return $cached_hosts;
        }

        $hosts = [];

        // 1. Post SMTP (post-smtp)
        $postman = get_option('postman_options', []);
        if (is_array($postman)) {
            if (!empty($postman['hostname'])) {
                $h = strtolower(trim((string) $postman['hostname']));
                if ($h !== '') {
                    $hosts[] = $h;
                }
            }
            if (!empty($postman['custom_smtp_server'])) {
                $h = strtolower(trim((string) $postman['custom_smtp_server']));
                if ($h !== '') {
                    $hosts[] = $h;
                }
            }
            if (!empty($postman['auth_domain'])) {
                $h = strtolower(trim((string) $postman['auth_domain']));
                if ($h !== '') {
                    $hosts[] = $h;
                }
            }
        }

        // 2. WP Mail SMTP (wp-mail-smtp)
        $wp_mail_smtp = get_option('wp_mail_smtp', []);
        if (is_array($wp_mail_smtp) && !empty($wp_mail_smtp['smtp']['host'])) {
            $hosts[] = strtolower(trim((string) $wp_mail_smtp['smtp']['host']));
        }

        // 3. FluentSMTP (fluent-smtp)
        $fluentmail = get_option('fluentmail_settings', []);
        if (is_array($fluentmail) && !empty($fluentmail['connections']) && is_array($fluentmail['connections'])) {
            foreach ($fluentmail['connections'] as $conn) {
                $cfg_host = $conn['config']['host'] ?? '';
                if (!empty($cfg_host)) {
                    $hosts[] = strtolower(trim((string) $cfg_host));
                }
            }
        }

        // 4. Easy WP SMTP (easy-wp-smtp)
        $swpsmtp = get_option('swpsmtp_options', []);
        if (is_array($swpsmtp) && !empty($swpsmtp['smtp_settings']['host'])) {
            $hosts[] = strtolower(trim((string) $swpsmtp['smtp_settings']['host']));
        }

        // 5. SMTP Mailer (smtp-mailer)
        $smtp_mailer = get_option('smtp_mailer_options', []);
        if (is_array($smtp_mailer) && !empty($smtp_mailer['smtp_host'])) {
            $hosts[] = strtolower(trim((string) $smtp_mailer['smtp_host']));
        }

        // 6. SureMails (suremails)
        $suremails = get_option('suremails_settings', []);
        if (is_array($suremails) && !empty($suremails['smtp_host'])) {
            $hosts[] = strtolower(trim((string) $suremails['smtp_host']));
        }

        $cached_hosts = array_values(array_unique(array_filter($hosts)));
        return $cached_hosts;
    }

    /**
     * Check if a host is in the approved hosts allowlist (including same-domain mail servers and dynamic mailer relays).
     *
     * @param string    $host Destination host to check
     * @param array     $settings Egress firewall settings
     * @param string    $site_host_override Optional site host to check against (defaults to home_url/site_url)
     * @param bool|null $is_mailer Optional flag indicating whether caller is an active mailer component
     * @return bool
     */
    public static function is_host_approved(string $host, array $settings = [], string $site_host_override = '', ?bool $is_mailer = null): bool {
        $clean_host = strtolower(trim($host));
        if ($clean_host === '') {
            return false;
        }

        // 1. Same-domain custom mail server (restricted to apex domain and mail/smtp/mx/webmail/imap/pop prefixes)
        if (self::is_same_domain_mail_host($clean_host, $site_host_override)) {
            return true;
        }

        // 2. Dynamic SMTP relay hostnames extracted from active mailer options
        $dynamic_mailers = self::get_dynamic_mailer_hosts();
        if (in_array($clean_host, $dynamic_mailers, true)) {
            return true;
        }

        // 3. Explicit AWS SES (Simple Email Service) SMTP and REST API endpoints (e.g. email-smtp.us-east-1.amazonaws.com, email.us-west-2.amazonaws.com)
        // Strictly bounds AWS allowlist to SES, preventing unmonitored S3, EC2, or Lambda API egress
        if (preg_match('/^(?:email|email-smtp)\.[a-z0-9-]+\.amazonaws\.com$/i', $clean_host)) {
            return true;
        }

        // 4. Google OAuth / API parent endpoints (accounts.google.com, www.googleapis.com)
        // Only allowed when email_smtp ecosystem is active or caller is a verified mailer component
        if ($clean_host === 'accounts.google.com' || $clean_host === 'www.googleapis.com') {
            $has_email_eco = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor') && \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('email_smtp');
            if ($is_mailer === true || $has_email_eco) {
                return true;
            }
        }

        // 5. Approved cloud providers, APIs, CDNs, and transactional mailers
        $approved = array_merge(self::DEFAULT_APPROVED_HOSTS, $settings['allowed_hosts'] ?? []);
        foreach ($approved as $pattern) {
            if ($clean_host === $pattern || str_ends_with($clean_host, '.' . $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record egress security telemetry.
     */
    private static function record_egress_event(string $url, string $host, array $caller, string $threat, string $reason, string $action) {
        $events = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }

        $event = [
            'id'        => 'egress_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
            'url'       => esc_url_raw($url),
            'host'      => sanitize_text_field($host),
            'threat'    => sanitize_key($threat),
            'reason'    => sanitize_text_field($reason),
            'caller'    => $caller,
            'action'    => $action,
            'timestamp' => current_time('mysql'),
        ];

        array_unshift($events, $event);
        if (count($events) > 100) {
            $events = array_slice($events, 0, 100);
        }
        update_option(self::OPTION_EVENTS, $events, false);

        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            WafFileLogger::log_incident([
                'category'    => 'egress_firewall_intercept',
                'rule_id'     => 'webcare_egress_' . $threat,
                'description' => sprintf('Outbound request by %s (%s) intercepted: %s', $caller['name'], $caller['file'], $reason),
                'payload'     => $url,
            ], ($action === 'blocked') ? 'blocked' : 'detected');
        }
    }

    /**
     * Retrieve status telemetry and recent events.
     *
     * @return array
     */
    public static function get_status(): array {
        $settings = self::get_settings();
        $events   = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }

        $blocked_count = count(array_filter($events, fn($e) => ($e['action'] ?? '') === 'blocked'));

        return [
            'settings'       => $settings,
            'total_events'   => count($events),
            'blocked_events' => $blocked_count,
            'approved_hosts' => array_merge(self::DEFAULT_APPROVED_HOSTS, $settings['allowed_hosts'] ?? []),
            'recent_events'  => array_slice($events, 0, 30),
        ];
    }
}
