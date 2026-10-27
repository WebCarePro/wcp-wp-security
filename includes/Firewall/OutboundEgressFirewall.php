<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\AuditLogger;

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

    const OPTION_SETTINGS = 'wcpscan_egress_settings';
    const OPTION_EVENTS   = 'wcpscan_egress_events';

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
     * Default approved external domains and APIs.
     */
    const DEFAULT_APPROVED_HOSTS = [
        'api.wordpress.org',
        'wordpress.org',
        'downloads.wordpress.org',
        'api.stripe.com',
        'api.paypal.com',
        'api.openai.com',
        'api.anthropic.com',
        'generativelanguage.googleapis.com',
        'api.cloudflare.com',
        'secure.gravatar.com',
    ];

    /**
     * Suspicious high-risk TLDs commonly used by disposable C2 droplets.
     */
    const SUSPICIOUS_TLDS = [
        'xyz', 'top', 'click', 'buzz', 'pw', 'work', 'rest', 'monster',
    ];

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

        return update_option(self::OPTION_SETTINGS, array_merge($current, $updated), false);
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

        $threat = null;
        $reason = '';

        // 2. SSRF & Internal Cloud Metadata Check (169.254.169.254, 127.0.0.1, internal RFC1918)
        if (!empty($settings['block_ssrf_metadata'])) {
            $site_host = strtolower(wp_parse_url(home_url(), PHP_URL_HOST) ?? '');
            if ($host !== $site_host) {
                if ($host === '169.254.169.254' || $host === 'instance-data') {
                    $threat = 'ssrf_metadata';
                    $reason = 'Cloud metadata service access attempted (AWS/GCP/Azure 169.254.169.254).';
                } elseif ($host === '127.0.0.1' || $host === 'localhost' || $host === '::1') {
                    $threat = 'ssrf_loopback';
                    $reason = 'Unauthorized internal localhost/loopback connection attempted.';
                } elseif (preg_match('/^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)/', $host)) {
                    $threat = 'ssrf_private_network';
                    $reason = 'Private internal network probe attempted (RFC1918 IP).';
                }
            }
        }

        // 3. Known Exfiltration Webhooks Check
        if (!$threat && !empty($settings['block_exfil_webhooks'])) {
            foreach (self::MALICIOUS_SINK_PATTERNS as $name => $pattern) {
                if (preg_match($pattern, $url)) {
                    $threat = 'exfiltration_webhook';
                    $reason = sprintf('Unauthorized outbound exfiltration webhook or drop point detected: %s', $name);
                    break;
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
        $is_containment = class_exists('\\WcpScanner\\Security\\EmergencyContainmentManager') && \WcpScanner\Security\EmergencyContainmentManager::is_active();
        if ($is_containment && !$threat) {
            $is_core_host = ($host === 'api.wordpress.org' || $host === 'wordpress.org' || $host === 'downloads.wordpress.org');
            if (!$is_core_host && !self::is_host_approved($host, $settings)) {
                $threat = 'containment_outbound_freeze';
                $reason = 'Outbound external network connection blocked by active Emergency Incident Containment protocol.';
            }
        }

        if ($threat) {
            $is_enforced = ($settings['mode'] === 'enforce' || $is_containment);
            self::record_egress_event($url, $host, $caller, $threat, $reason, $is_enforced ? 'blocked' : 'monitored');

            if ($is_enforced) {
                return new \WP_Error(
                    'wcp_egress_blocked',
                    /* translators: %s: Security reason description */
                    sprintf(__('Outbound network connection blocked by WCP Egress Firewall. Reason: %s', 'wcp-security-scanner'), esc_html($reason)),
                    ['status' => 403]
                );
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
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 12);
        $caller = [
            'type' => 'core',
            'name' => 'WordPress Core',
            'file' => 'unknown',
            'line' => 0,
        ];

        foreach ($trace as $frame) {
            $file = $frame['file'] ?? '';
            $norm = str_replace('\\', '/', $file);

            // Skip scanner's own code and core HTTP classes
            if (str_contains($norm, '/plugins/wcp-security-scanner/')) {
                continue;
            }
            if (str_contains($norm, 'class-wp-http') || str_contains($norm, 'Requests/')) {
                continue;
            }

            if (str_contains($norm, '/wp-content/plugins/')) {
                $parts = explode('/wp-content/plugins/', $norm);
                $sub = explode('/', $parts[1] ?? '');
                $caller['type'] = 'plugin';
                $caller['name'] = $sub[0] ?? 'Unknown Plugin';
                $caller['file'] = $sub[0] ?? 'plugin';
                $caller['line'] = $frame['line'] ?? 0;
                break;
            }

            if (str_contains($norm, '/wp-content/themes/')) {
                $parts = explode('/wp-content/themes/', $norm);
                $sub = explode('/', $parts[1] ?? '');
                $caller['type'] = 'theme';
                $caller['name'] = $sub[0] ?? 'Active Theme';
                $caller['file'] = $sub[0] ?? 'theme';
                $caller['line'] = $frame['line'] ?? 0;
                break;
            }
        }

        return $caller;
    }

    /**
     * Check if a host is in the approved hosts allowlist.
     *
     * @param string $host
     * @param array  $settings
     * @return bool
     */
    private static function is_host_approved(string $host, array $settings): bool {
        $approved = array_merge(self::DEFAULT_APPROVED_HOSTS, $settings['allowed_hosts'] ?? []);
        foreach ($approved as $pattern) {
            if ($host === $pattern || str_ends_with($host, '.' . $pattern)) {
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

        if (class_exists('\\WcpScanner\\Firewall\\WafFileLogger')) {
            WafFileLogger::log_incident([
                'category'    => 'egress_firewall_intercept',
                'rule_id'     => 'wcp_egress_' . $threat,
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
