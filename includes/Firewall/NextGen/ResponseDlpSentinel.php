<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ResponseDlpSentinel
 *
 * Outbound Data-Loss Prevention (DLP) & Secret Leak Redactor.
 * Inspects unauthenticated HTTP/REST responses for credential dumps, private keys,
 * wp-config secrets, or /etc/passwd exfiltration before leaving the origin.
 */
class ResponseDlpSentinel implements SecurityModuleInterface {

    const OPTION_EVENTS = 'webcareproscan_dlp_events';

    public function get_id(): string {
        return 'response-dlp-sentinel';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Outbound Response DLP & Secret Redactor', 'webcare-pro-security'),
            'description' => __('Scans unauthenticated HTTP and REST responses to block leaked wp-config credentials, AWS keys, PEM private keys, and /etc/passwd before egress.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_response_dlp_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'Next-Gen DLP',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_filter('rest_post_dispatch', [__CLASS__, 'filter_rest_response'], 999, 3);
        add_action('template_redirect', [__CLASS__, 'start_guest_output_buffer'], -999);
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_response_dlp_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Outbound Response DLP & Secret Redactor', 'webcare-pro-security'),
            ],
            'waf_nextgen_dlp_auto_ban' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Auto-Ban Offenders Triggering Response DLP', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/dlp-events',
                'methods'  => 'GET',
                'callback' => static function () {
                    $events = get_option(self::OPTION_EVENTS, []);
                    return new \WP_REST_Response([
                        'success' => true,
                        'events'  => is_array($events) ? $events : [],
                    ], 200);
                },
            ],
        ];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_get_dlp_leak_events',
                'description' => 'Retrieve blocked outbound credential/secret exfiltration attempts caught by ResponseDlpSentinel.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
                'handler'     => static function () {
                    $events = get_option(self::OPTION_EVENTS, []);
                    return [
                        'isError' => false,
                        'content' => [[
                            'type' => 'text',
                            'text' => (string) wp_json_encode(['events' => is_array($events) ? $events : []]),
                        ]],
                    ];
                },
            ],
        ];
    }

    /**
     * Pure detector analyzing outbound response text for high-confidence credential/system leaks.
     *
     * @param string $body
     * @param bool   $is_guest
     * @return array{leaked: bool, pattern: string, safe_body: string}
     */
    public static function inspect_and_redact(string $body, bool $is_guest = true): array {
        if (!$is_guest || strlen($body) < 16) {
            return ['leaked' => false, 'pattern' => '', 'safe_body' => $body];
        }

        // Skip binary image/PDF buffers cleanly
        $head = substr($body, 0, 8);
        if (strpos($head, "\x89PNG") === 0 || strpos($head, "\xFF\xD8") === 0 || strpos($head, '%PDF-') === 0) {
            return ['leaked' => false, 'pattern' => '', 'safe_body' => $body];
        }

        $patterns = [
            'WP_CONFIG_SECRET_DEFINE' => '/define\s*\(\s*[\'"](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT)[\'"]\s*,/i',
            'LINUX_PASSWD_FILE_DUMP'  => '/root:[x*]:0:0:/',
            'AWS_IAM_ACCESS_KEY'      => '/\bAKIA[0-9A-Z]{16}\b/',
            'PRIVATE_CRYPTO_PEM_KEY'  => '/-----BEGIN (?:RSA |OPENSSH |EC |PGP |ENCRYPTED )?PRIVATE KEY-----/',
            'RAW_DB_AUTH_ERROR_DUMP'  => '/Access denied for user\s+\'[^\']+\'@\'[^\']+\'|SQLSTATE\[HY000\]\s*\[\d+\]/i',
        ];

        foreach ($patterns as $name => $rx) {
            if (preg_match($rx, $body) === 1) {
                return [
                    'leaked'    => true,
                    'pattern'   => $name,
                    'safe_body' => '403 Forbidden - Response blocked by WebCare Outbound Data-Loss Prevention Policy.',
                ];
            }
        }

        return ['leaked' => false, 'pattern' => '', 'safe_body' => $body];
    }

    /**
     * Start output buffer on guest public requests.
     */
    public static function start_guest_output_buffer(): void {
        if (
            (defined('WP_CLI') && WP_CLI)
            || (function_exists('wp_doing_cron') && wp_doing_cron())
            || is_admin()
            || (function_exists('is_user_logged_in') && is_user_logged_in())
        ) {
            return;
        }
        ob_start([__CLASS__, 'filter_guest_output_buffer']);
    }

    /**
     * Output buffer callback inspecting HTML/text guest responses.
     */
    public static function filter_guest_output_buffer(string $buffer): string {
        $result = self::inspect_and_redact($buffer, true);
        if (empty($result['leaked'])) {
            return $buffer;
        }

        self::handle_dlp_breach($result['pattern']);
        if (!headers_sent()) {
            status_header(403);
            header('Content-Type: text/plain; charset=UTF-8');
        }
        return $result['safe_body'];
    }

    /**
     * Filter REST API responses for unauthenticated callers.
     *
     * @param \WP_HTTP_Response $result
     * @param \WP_REST_Server   $server
     * @param \WP_REST_Request  $request
     * @return \WP_HTTP_Response
     */
    public static function filter_rest_response($result, $server, $request) {
        if (is_user_logged_in() || (defined('WP_CLI') && WP_CLI)) {
            return $result;
        }
        if ($result instanceof \WP_REST_Response) {
            $route = method_exists($request, 'get_route') ? (string) $request->get_route() : '';
            if (strpos($route, '/webcare-pro-security/') === 0) {
                return $result;
            }
            $encoded = (string) wp_json_encode($result->get_data());
            $check   = self::inspect_and_redact($encoded, true);
            if (!empty($check['leaked'])) {
                self::handle_dlp_breach($check['pattern']);
                return new \WP_REST_Response([
                    'code'    => 'webcare_dlp_blocked',
                    'message' => __('Outbound response blocked by security policy.', 'webcare-pro-security'),
                ], 403);
            }
        }
        return $result;
    }

    /**
     * Log redacted DLP incident and auto-ban offending probe IP when enabled.
     */
    private static function handle_dlp_breach(string $pattern): void {
        $ip     = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : '127.0.0.1';
        $uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $reason = sprintf('Outbound DLP neutralized secret exfiltration (%s) on guest response [REDACTED].', $pattern);

        $events = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }
        array_unshift($events, [
            'timestamp' => time(),
            'ip'        => sanitize_text_field($ip),
            'pattern'   => sanitize_key($pattern),
            'uri'       => sanitize_text_field(substr($uri, 0, 160)),
        ]);
        if (count($events) > 50) {
            $events = array_slice($events, 0, 50);
        }
        update_option(self::OPTION_EVENTS, $events, false);

        if (class_exists(FirewallEngine::class)) {
            FirewallEngine::log_incident([
                'id'          => 'WAF-DLP-EXFILTRATION-BLOCKED',
                'name'        => 'Outbound Response DLP Sentinel',
                'category'    => 'Next-Gen Response DLP',
                'description' => $reason,
                'match_type'  => $pattern,
                'match_value' => $pattern,
                'payload'     => 'URI: ' . $uri . ' | Payload redacted to protect credentials.',
            ], 'blocked');

            $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
                ? \WebCareProScanner\System\SettingsManager::get_settings()
                : [];
            if (!empty($settings['waf_nextgen_dlp_auto_ban']) && !FirewallEngine::is_server_origin_or_loopback($ip)) {
                FirewallEngine::add_blocked_ip(
                    $ip,
                    $reason,
                    86400,
                    'WAF-DLP-EXFILTRATION-BLOCKED',
                    'Outbound Response DLP Sentinel',
                    'Next-Gen Response DLP',
                    null,
                    null,
                    true
                );
            }
        }
    }
}
