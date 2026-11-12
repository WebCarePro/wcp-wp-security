<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * IntentChainSentinel
 *
 * Detects slow, human-paced autonomous AI pentest agents executing multi-step
 * kill-chain sequences across a 15-minute sliding window even below rate limits.
 */
class IntentChainSentinel implements SecurityModuleInterface, WafEvaluatorInterface {

    const STAGE_RECON_USER      = 1;
    const STAGE_RECON_README    = 2;
    const STAGE_NONCE_HARVEST   = 4;
    const STAGE_UNAUTH_MUTATION = 8;
    const STAGE_SENSITIVE_404   = 16;

    const OPTION_EVENTS = 'webcareproscan_intent_chain_events';
    const WINDOW_SECS   = 900; // 15 minutes

    public function get_id(): string {
        return 'intent-chain-sentinel';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('AI Agent Kill-Chain Sentinel', 'webcare-pro-security'),
            'description' => __('Tracks 15-minute multi-stage intent bitmasks per IP to neutralize autonomous LLM exploit runners that evade per-minute rate limits.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_intent_chain_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'Next-Gen AI Defense',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_action('template_redirect', [__CLASS__, 'observe_404_stage'], 20);
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_intent_chain_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('AI Agent Multi-Step Kill-Chain Sentinel', 'webcare-pro-security'),
            ],
            'waf_nextgen_intent_chain_action' => [
                'default' => 'challenge_pow',
                'type'    => 'enum',
                'options' => ['challenge_pow', 'block_and_ban', 'monitor'],
                'label'   => __('AI Agent Kill-Chain Enforcement Action', 'webcare-pro-security'),
            ],
            'waf_nextgen_intent_chain_threshold' => [
                'default' => 3,
                'type'    => 'int',
                'min'     => 2,
                'max'     => 5,
                'label'   => __('Kill-Chain Stage Threshold', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/intent-chains',
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
                'name'        => 'webcareproscan_get_intent_chain_telemetry',
                'description' => 'Retrieve recent multi-step AI pentest kill-chain detections captured by IntentChainSentinel.',
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

    public function compile_preload_ast(): array {
        return [];
    }

    /**
     * Evaluate incoming request for kill-chain stage transitions.
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        if ($ctx->isLoggedIn) {
            return null;
        }
        if (class_exists(FirewallEngine::class)) {
            if (FirewallEngine::is_ip_whitelisted($ctx->ip) || FirewallEngine::is_server_origin_or_loopback($ctx->ip)) {
                return null;
            }
        }
        if (class_exists(BotReconDefense::class) && BotReconDefense::is_genuine_search_engine($ctx->ip, $ctx->userAgent)) {
            return null;
        }

        $stage = self::classify_stage($ctx);
        if ($stage === 0) {
            return null;
        }

        $mask       = self::record_ip_stage($ctx->ip, $stage);
        $stage_cnt  = self::count_bits($mask);
        $settings   = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];
        $threshold  = max(2, min(5, intval($settings['waf_nextgen_intent_chain_threshold'] ?? 3)));
        $policy     = (string) ($settings['waf_nextgen_intent_chain_action'] ?? 'challenge_pow');

        // Trigger enforcement once an offender reaches >= threshold distinct kill-chain stages
        if ($stage_cnt >= $threshold && ($stage === self::STAGE_UNAUTH_MUTATION || $stage === self::STAGE_NONCE_HARVEST || $stage === self::STAGE_SENSITIVE_404)) {
            $labels = self::describe_bitmask($mask);
            $reason = sprintf(
                'Autonomous multi-step kill-chain detected (%d stages in 15m: %s)',
                $stage_cnt,
                implode(' -> ', $labels)
            );
            self::record_event($ctx->ip, $mask, $labels, $ctx->uri, $policy);

            if ($policy === 'monitor') {
                return new WafVerdict('monitor', 'WAF-AI-AGENT-KILLCHAIN', $reason, [
                    'category' => 'AI Agent Kill-Chain Defense',
                    'severity' => 'high',
                ]);
            }

            if ($policy === 'challenge_pow' && class_exists(BotReconDefense::class) && !BotReconDefense::has_valid_clearance_cookie($ctx->ip, $ctx->userAgent)) {
                return new WafVerdict('challenge_pow', 'WAF-AI-AGENT-KILLCHAIN', $reason, [
                    'category' => 'AI Agent Kill-Chain Defense',
                    'severity' => 'high',
                ]);
            }

            return new WafVerdict('block_and_ban', 'WAF-AI-AGENT-KILLCHAIN', $reason, [
                'category'        => 'AI Agent Kill-Chain Defense',
                'severity'        => 'critical',
                'ban_ttl'         => 86400,
                'sync_cloudflare' => true,
            ]);
        }

        return null;
    }

    /**
     * Classify which kill-chain stage this request corresponds to (0 if benign navigation).
     */
    public static function classify_stage(RequestContext $ctx): int {
        // Stage 1: User / author recon
        if (
            (isset($ctx->params['author']) && preg_match('/^\d+$/', (string) $ctx->params['author']))
            || ($ctx->restRoute !== '' && (strpos($ctx->restRoute, '/wp/v2/users') === 0 || strpos($ctx->restRoute, '/wc/v3/customers') === 0))
        ) {
            return self::STAGE_RECON_USER;
        }

        // Stage 2: Plugin/theme version fingerprinting via static readme/manifest probes
        if (preg_match('#/wp-content/(?:plugins|themes)/[^/]+/(?:readme\.txt|readme\.html|changelog\.txt|package\.json|composer\.json)$#i', $ctx->cleanUri)) {
            return self::STAGE_RECON_README;
        }

        // Stage 3: Nonce / AJAX discovery GET probe
        if (
            $ctx->method === 'GET'
            && (strpos($ctx->cleanUri, 'admin-ajax.php') !== false || strpos($ctx->restRoute, '/nonce') !== false)
            && empty($ctx->referer)
        ) {
            return self::STAGE_NONCE_HARVEST;
        }

        // Stage 4: Unauthenticated mutation targeting admin-ajax / admin-post / plugin REST namespace
        if (
            in_array($ctx->method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)
            && (
                strpos($ctx->cleanUri, 'admin-ajax.php') !== false
                || strpos($ctx->cleanUri, 'admin-post.php') !== false
                || ($ctx->restRoute !== '' && strpos($ctx->restRoute, '/wp/v2/') !== 0 && strpos($ctx->restRoute, '/webcare-pro-security/') !== 0)
            )
        ) {
            return self::STAGE_UNAUTH_MUTATION;
        }

        return 0;
    }

    /**
     * Record 404 probes on suspicious script/config URIs at template_redirect.
     */
    public static function observe_404_stage(): void {
        if (!function_exists('is_404') || !is_404() || (function_exists('is_user_logged_in') && is_user_logged_in())) {
            return;
        }
        $ctx = RequestContext::from_globals();
        if (preg_match('#\.(?:php|env|bak|sql|zip|tar|git|log)$#i', $ctx->cleanUri)) {
            self::record_ip_stage($ctx->ip, self::STAGE_SENSITIVE_404);
        }
    }

    /**
     * Persist per-IP kill-chain stage bitmask over a 15-minute window.
     */
    public static function record_ip_stage(string $ip, int $stage_bit): int {
        $key  = 'wcp_ic_' . substr(md5($ip), 0, 16);
        $mask = (int) get_transient($key);
        $next = $mask | $stage_bit;
        if ($next !== $mask || $mask === 0) {
            set_transient($key, $next, self::WINDOW_SECS);
        }
        return $next;
    }

    /**
     * Count active stage bits in bitmask.
     */
    public static function count_bits(int $mask): int {
        $count = 0;
        foreach ([self::STAGE_RECON_USER, self::STAGE_RECON_README, self::STAGE_NONCE_HARVEST, self::STAGE_UNAUTH_MUTATION, self::STAGE_SENSITIVE_404] as $bit) {
            if (($mask & $bit) !== 0) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Convert bitmask to readable kill-chain stages.
     *
     * @return string[]
     */
    public static function describe_bitmask(int $mask): array {
        $map = [
            self::STAGE_RECON_USER      => 'RECON_USER',
            self::STAGE_RECON_README    => 'RECON_README',
            self::STAGE_NONCE_HARVEST   => 'NONCE_HARVEST',
            self::STAGE_UNAUTH_MUTATION => 'UNAUTH_MUTATION',
            self::STAGE_SENSITIVE_404   => 'SENSITIVE_404',
        ];
        $out = [];
        foreach ($map as $bit => $label) {
            if (($mask & $bit) !== 0) {
                $out[] = $label;
            }
        }
        return $out;
    }

    /**
     * Store bounded telemetry history for dashboard inspection.
     *
     * @param string[] $labels
     */
    private static function record_event(string $ip, int $mask, array $labels, string $uri, string $action): void {
        $events = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }
        array_unshift($events, [
            'timestamp' => time(),
            'ip'        => sanitize_text_field($ip),
            'bitmask'   => $mask,
            'stages'    => $labels,
            'uri'       => sanitize_text_field(substr($uri, 0, 160)),
            'action'    => sanitize_key($action),
        ]);
        if (count($events) > 50) {
            $events = array_slice($events, 0, 50);
        }
        update_option(self::OPTION_EVENTS, $events, false);
    }
}
