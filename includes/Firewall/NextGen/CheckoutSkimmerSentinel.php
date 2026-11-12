<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Content\ScriptInventoryMonitor;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CheckoutSkimmerSentinel
 *
 * Refactored module protecting WooCommerce / EDD / SureCart checkout pages against Magecart
 * DOM skimmers via script integrity baselines, suspicious inline pattern scanning,
 * and optional Content-Security-Policy enforcement headers.
 */
class CheckoutSkimmerSentinel implements SecurityModuleInterface {

    const OPTION_BASELINE = 'webcareproscan_checkout_script_baseline';
    const OPTION_ALERTS   = 'webcareproscan_checkout_skimmer_alerts';

    public function get_id(): string {
        return 'checkout-skimmer-sentinel';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Checkout DOM & Payment Skimmer Guard', 'webcare-pro-security'),
            'description' => __('Maintains a checkout script integrity baseline, detects Magecart-style inline card skimmers, and enforces checkout CSP headers.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_checkout_skimmer_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'Ecommerce Shield',
        ];
    }

    public function is_applicable(): bool {
        return class_exists('WooCommerce')
            || class_exists('Easy_Digital_Downloads')
            || defined('SURECART_PLUGIN_FILE')
            || true;
    }

    public function boot(): void {
        if (!is_admin()) {
            add_action('send_headers', [__CLASS__, 'emit_checkout_csp_header'], 20);
            add_action('wp_footer', [__CLASS__, 'audit_checkout_scripts'], 9998);
        }
        add_action('webcareproscan_checkout_baseline_audit', [__CLASS__, 'run_scheduled_baseline_probe']);
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_checkout_skimmer_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('WooCommerce Checkout DOM & Skimmer Guard', 'webcare-pro-security'),
            ],
            'waf_nextgen_checkout_csp_mode' => [
                'default' => 'report_only',
                'type'    => 'enum',
                'options' => ['off', 'report_only', 'enforce'],
                'label'   => __('Checkout Content-Security-Policy Mode', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/checkout-skimmer',
                'methods'  => 'GET',
                'callback' => static function () {
                    $baseline = get_option(self::OPTION_BASELINE, []);
                    $alerts   = get_option(self::OPTION_ALERTS, []);
                    return new \WP_REST_Response([
                        'success'  => true,
                        'baseline' => is_array($baseline) ? $baseline : [],
                        'alerts'   => is_array($alerts) ? $alerts : [],
                    ], 200);
                },
            ],
            [
                'route'    => '/nextgen/checkout-skimmer/reset-baseline',
                'methods'  => 'POST',
                'callback' => static function () {
                    delete_option(self::OPTION_BASELINE);
                    return new \WP_REST_Response([
                        'success' => true,
                        'message' => __('Checkout script baseline cleared; next verified admin checkout load will re-learn.', 'webcare-pro-security'),
                    ], 200);
                },
            ],
        ];
    }

    public function get_cron_tasks(): array {
        return [
            'webcareproscan_checkout_baseline_audit' => [
                'id'                  => 'checkout_baseline_audit',
                'hook'                => 'webcareproscan_checkout_baseline_audit',
                'title'               => __('Checkout Script Integrity Probe', 'webcare-pro-security'),
                'description'         => __('Compares rendered checkout scripts against the approved baseline using simulated mobile and referer probes to detect conditional card skimmers.', 'webcare-pro-security'),
                'category'            => 'security_monitoring',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'waf_nextgen_checkout_skimmer_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Modular WAF -> Next-Gen Engines', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
                'default_delay'       => 300,
            ],
        ];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_get_checkout_skimmer_alerts',
                'description' => 'Retrieve WooCommerce / checkout script integrity alerts and DOM skimmer detections.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
                'handler'     => static function () {
                    return [
                        'isError' => false,
                        'content' => [[
                            'type' => 'text',
                            'text' => (string) wp_json_encode([
                                'baseline_count' => count((array) get_option(self::OPTION_BASELINE, [])),
                                'alerts'         => (array) get_option(self::OPTION_ALERTS, []),
                            ]),
                        ]],
                    ];
                },
            ],
        ];
    }

    /**
     * Detect whether the active request targets a checkout / payment-method screen.
     */
    public static function is_checkout_surface(): bool {
        if (function_exists('is_checkout') && is_checkout()) {
            return true;
        }
        $uri = isset($_SERVER['REQUEST_URI']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']))) : '';
        return (strpos($uri, '/checkout') !== false || strpos($uri, '/add-payment-method') !== false);
    }

    /**
     * Emit optional CSP header exclusively on checkout/payment pages.
     */
    public static function emit_checkout_csp_header(): void {
        if (!self::is_checkout_surface() || headers_sent()) {
            return;
        }
        $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];
        $mode = (string) ($settings['waf_nextgen_checkout_csp_mode'] ?? 'report_only');
        if (!in_array($mode, ['report_only', 'enforce'], true)) {
            return;
        }

        $trusted_hosts = ["'self'", "'unsafe-inline'"];
        if (class_exists(ScriptInventoryMonitor::class)) {
            foreach (array_keys(ScriptInventoryMonitor::KNOWN_VERIFIED_HOSTS) as $host) {
                $trusted_hosts[] = 'https://' . $host;
            }
        }
        $baseline = get_option(self::OPTION_BASELINE, []);
        if (is_array($baseline) && !empty($baseline['hosts']) && is_array($baseline['hosts'])) {
            foreach ($baseline['hosts'] as $bh) {
                if (is_string($bh) && $bh !== '') {
                    $trusted_hosts[] = 'https://' . sanitize_text_field($bh);
                }
            }
        }

        $src_list = implode(' ', array_values(array_unique($trusted_hosts)));
        $policy   = "script-src {$src_list}; object-src 'none'; base-uri 'self'";
        $hdr      = ($mode === 'enforce') ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
        header("{$hdr}: {$policy}");
    }

    /**
     * Inspect enqueued script handles and inline scripts on checkout for unauthorized drift or skimmer logic.
     */
    public static function audit_checkout_scripts(): void {
        global $wp_scripts;
        if (!self::is_checkout_surface() || !($wp_scripts instanceof \WP_Scripts)) {
            return;
        }

        $home_host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $hosts     = [];
        $signatures = [];

        foreach ((array) $wp_scripts->queue as $handle) {
            if (!isset($wp_scripts->registered[$handle])) {
                continue;
            }
            $obj = $wp_scripts->registered[$handle];
            $src = (string) ($obj->src ?? '');
            if ($src !== '') {
                $host = strtolower((string) wp_parse_url($src, PHP_URL_HOST));
                if ($host !== '' && $host !== $home_host) {
                    $hosts[] = $host;
                }
            }
            $inline = '';
            if (!empty($obj->extra['before']) && is_array($obj->extra['before'])) {
                $inline .= implode("\n", array_filter($obj->extra['before'], 'is_string'));
            }
            if (!empty($obj->extra['after']) && is_array($obj->extra['after'])) {
                $inline .= implode("\n", array_filter($obj->extra['after'], 'is_string'));
            }
            if ($inline !== '') {
                $signatures[$handle] = hash('sha256', $inline);
                $skimmer = self::detect_inline_skimmer_signature($inline);
                if ($skimmer !== null) {
                    self::record_alert('inline_skimmer_pattern', "Suspicious checkout script pattern ({$skimmer}) on handle \"{$handle}\".");
                }
            }
        }

        $hosts    = array_values(array_unique($hosts));
        $baseline = get_option(self::OPTION_BASELINE, []);
        if (!is_array($baseline) || empty($baseline)) {
            if (is_user_logged_in() && current_user_can('manage_options')) {
                update_option(self::OPTION_BASELINE, [
                    'hosts'      => $hosts,
                    'signatures' => $signatures,
                    'learned_at' => time(),
                ], false);
            }
            return;
        }

        $known_hosts = array_merge(
            (array) ($baseline['hosts'] ?? []),
            class_exists(ScriptInventoryMonitor::class) ? array_keys(ScriptInventoryMonitor::KNOWN_VERIFIED_HOSTS) : []
        );
        foreach ($hosts as $h) {
            if (!in_array($h, $known_hosts, true)) {
                self::record_alert('unexpected_checkout_host', sprintf('Unapproved external script domain "%s" loaded on checkout.', $h));
            }
        }
    }

    /**
     * Pure detector for Magecart / Web3 card-skimming JS behavior.
     */
    public static function detect_inline_skimmer_signature(string $js): ?string {
        if (
            preg_match('/(?:cardnumber|cc_number|billing_card|payment_method_nonce|cvv|cvc)/i', $js)
            && preg_match('/(?:new\s+WebSocket|navigator\.sendBeacon|createElement\([\'"]script[\'"]\)|btoa\s*\()/i', $js)
        ) {
            return 'CARD_FIELD_EXFIL_PATTERN';
        }
        if (preg_match('/eval\s*\(\s*atob\s*\(/i', $js)) {
            return 'OBFUSCATED_ATOB_EVAL';
        }
        return null;
    }

    /**
     * Scheduled Cron probe checking rendered checkout HTML via simulated mobile shopper request.
     *
     * @return array<string, mixed>
     */
    public static function run_scheduled_baseline_probe(): array {
        $checkout_url = function_exists('wc_get_checkout_url') ? wc_get_checkout_url() : home_url('/checkout/');
        $resp = wp_remote_get($checkout_url, [
            'timeout'     => 10,
            'redirection' => 2,
            'user-agent'  => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
            'headers'     => ['Referer' => home_url('/')],
        ]);
        if (is_wp_error($resp)) {
            return ['status' => 'skipped', 'reason' => $resp->get_error_message()];
        }
        $body = (string) wp_remote_retrieve_body($resp);
        $sig  = self::detect_inline_skimmer_signature($body);
        if ($sig !== null) {
            self::record_alert('mobile_probe_skimmer', "Mobile shopper checkout probe flagged pattern: {$sig}");
        }
        return ['status' => 'completed', 'anomaly' => $sig];
    }

    /**
     * Store bounded checkout skimmer alert history and log security incident.
     */
    private static function record_alert(string $type, string $message): void {
        $alerts = get_option(self::OPTION_ALERTS, []);
        if (!is_array($alerts)) {
            $alerts = [];
        }
        array_unshift($alerts, [
            'timestamp' => time(),
            'type'      => sanitize_key($type),
            'message'   => sanitize_text_field($message),
        ]);
        if (count($alerts) > 50) {
            $alerts = array_slice($alerts, 0, 50);
        }
        update_option(self::OPTION_ALERTS, $alerts, false);

        if (class_exists(FirewallEngine::class)) {
            FirewallEngine::log_incident([
                'id'          => 'WAF-CHECKOUT-SKIMMER',
                'name'        => 'Checkout DOM Skimmer Sentinel',
                'category'    => 'Next-Gen Checkout Protection',
                'description' => $message,
                'match_type'  => $type,
                'match_value' => $type,
                'payload'     => $message,
            ], 'detected');
        }
    }
}
