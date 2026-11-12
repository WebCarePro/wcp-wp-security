<?php
namespace WebCareProScanner\Core\Modules;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer;
use WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Reference module adapter registering Modular Intelligence WAF & Visual Rule Studio.
 */
class ModularWafModule implements SecurityModuleInterface, WafEvaluatorInterface {

    public function get_id(): string {
        return 'modular-waf';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Modular Behavioral WAF & Visual Rule Studio', 'webcare-pro-security'),
            'description' => __('Autonomous AST-synthesized firewall rules paired with the Cloudflare-style Visual Condition & Wirefilter Studio.', 'webcare-pro-security'),
            'category'    => 'waf',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf',
            'badge'       => 'Core WAF',
        ];
    }

    public function is_applicable(): bool {
        return class_exists(ModularFirewallSynthesizer::class);
    }

    public function boot(): void {
        // Booted directly in early plugins_loaded WAF dispatch path for zero overhead.
    }

    public function get_settings_schema(): array {
        return [];
    }

    public function get_rest_routes(): array {
        return [];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_get_visual_waf_context',
                'description' => 'Retrieve the Visual Rule Studio schema (18 fields & operators), installed plugins/themes (slug, version, status, URL path), WordPress roles, discovered endpoints, existing #ID custom rules, Cloudflare status, and a Markdown AI prompt.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'goal' => [
                            'type'        => 'string',
                            'description' => 'Optional natural-language security goal to embed in the Markdown AI prompt.',
                        ],
                    ],
                ],
                'handler'     => [__CLASS__, 'mcp_get_visual_waf_context'],
            ],
            [
                'name'        => 'webcareproscan_list_modular_custom_rules',
                'description' => 'List all custom Visual/Modular firewall rules (#ID, priority order, Wirefilter expression, conditions, action_type, current_mode, ban_ttl).',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'include_baseline' => [
                            'type'        => 'boolean',
                            'description' => 'Include auto-synthesized AST baseline rules alongside custom rules (default false).',
                            'default'     => false,
                        ],
                    ],
                ],
                'handler'     => [__CLASS__, 'mcp_list_modular_custom_rules'],
            ],
            [
                'name'        => 'webcareproscan_validate_and_simulate_rule',
                'description' => 'Parse/validate a Wirefilter expression, Markdown code block, or AI JSON rule, run safety lint checks (admin lockout / GeoIP), and dry-run simulate against recent WAF traffic logs.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'wirefilter_expr' => [
                            'type'        => 'string',
                            'description' => 'Wirefilter expression or pasted AI Markdown/JSON rule payload to validate and simulate.',
                        ],
                        'limit'           => [
                            'type'        => 'integer',
                            'description' => 'Max recent WAF log rows to simulate against (10-1000, default 500).',
                            'default'     => 500,
                        ],
                    ],
                    'required' => ['wirefilter_expr'],
                ],
                'handler'     => [__CLASS__, 'mcp_validate_and_simulate_rule'],
            ],
            [
                'name'        => 'webcareproscan_save_custom_visual_rule',
                'description' => 'Create or update a local Visual/Custom Firewall Rule (#ID) from a Wirefilter expression or structured conditions, compiling immediately into Preload Micro-WAF & Runtime FirewallEngine.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'id'              => ['type' => 'string', 'description' => 'Existing rule ID (e.g. MOD-CUSTOM-XXXXXX) to update; omit to create a new rule.'],
                        'title'           => ['type' => 'string', 'description' => 'Human-readable rule name.'],
                        'description'     => ['type' => 'string', 'description' => 'Optional description/notes.'],
                        'wirefilter_expr' => ['type' => 'string', 'description' => 'Wirefilter expression (e.g. http.request.uri.path contains "/wp-content/plugins/foo/" and not wp.user.is_logged_in).'],
                        'conditions'      => ['type' => 'array', 'description' => 'Optional structured OR/AND condition groups array (if omitted, parsed from wirefilter_expr).'],
                        'group_logic'     => ['type' => 'string', 'enum' => ['OR', 'AND'], 'default' => 'OR'],
                        'action_type'     => ['type' => 'string', 'enum' => ['block', 'block_and_ban', 'rate_limit', 'challenge_pow', 'payload_inspect', 'monitor', 'allow'], 'default' => 'block'],
                        'current_mode'    => ['type' => 'string', 'enum' => ['enforce', 'monitor', 'off'], 'default' => 'enforce'],
                        'rate_limit'      => ['type' => 'integer', 'description' => 'Requests per minute when action_type=rate_limit.', 'default' => 15],
                        'ban_ttl'         => ['type' => 'integer', 'description' => 'IP ban duration in seconds (0 = block request only).', 'default' => 86400],
                        'sync_cloudflare' => ['type' => 'boolean', 'description' => 'Sync banned offender IPs to Cloudflare Edge when connected.', 'default' => false],
                        'block_uploads'   => ['type' => 'boolean', 'default' => true],
                        'placement'       => ['type' => 'string', 'enum' => ['first', 'last', 'custom'], 'default' => 'last'],
                        'order_position'  => ['type' => 'integer', 'description' => '1-based priority slot when placement=custom.'],
                    ],
                    'required' => ['title'],
                ],
                'handler'     => [__CLASS__, 'mcp_save_custom_visual_rule'],
            ],
            [
                'name'        => 'webcareproscan_reorder_custom_visual_rules',
                'description' => 'Reorder custom Visual Firewall Rules execution sequence and recompile Preload Micro-WAF.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'ordered_ids' => [
                            'type'        => 'array',
                            'items'       => ['type' => 'string'],
                            'description' => 'Complete ordered list of custom rule IDs (highest priority first).',
                        ],
                    ],
                    'required' => ['ordered_ids'],
                ],
                'handler'     => [__CLASS__, 'mcp_reorder_custom_visual_rules'],
            ],
            [
                'name'        => 'webcareproscan_toggle_or_delete_custom_rule',
                'description' => 'Change enforcement mode (enforce, monitor, off) or permanently delete a custom Visual Firewall Rule by ID.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'rule_id' => ['type' => 'string', 'description' => 'Target custom rule ID (e.g. MOD-CUSTOM-XXXXXX).'],
                        'action'  => ['type' => 'string', 'enum' => ['enforce', 'monitor', 'off', 'delete']],
                    ],
                    'required' => ['rule_id', 'action'],
                ],
                'handler'     => [__CLASS__, 'mcp_toggle_or_delete_custom_rule'],
            ],
        ];
    }

    /**
     * Format standard MCP tool JSON envelope.
     *
     * @param array<string, mixed> $res
     * @return array<string, mixed>
     */
    private static function format_mcp_result(array $res): array {
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => (string) wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    /** @param array<string, mixed> $args */
    public static function mcp_get_visual_waf_context(array $args): array {
        $goal    = sanitize_text_field((string) ($args['goal'] ?? ''));
        $ctx     = VisualRuleExpressionEngine::get_site_context_data();
        $prompt  = VisualRuleExpressionEngine::build_ai_markdown_prompt($goal);
        $ctx['success']         = true;
        $ctx['markdown_prompt'] = $prompt;
        return self::format_mcp_result($ctx);
    }

    /** @param array<string, mixed> $args */
    public static function mcp_list_modular_custom_rules(array $args): array {
        $include_baseline = !empty($args['include_baseline']);
        $all_rules        = ModularFirewallSynthesizer::get_active_rules();
        $custom           = [];
        $baseline         = [];
        foreach ($all_rules as $r) {
            if (!empty($r['is_custom']) || ($r['category'] ?? '') === 'custom') {
                $custom[] = $r;
            } elseif ($include_baseline) {
                $baseline[] = [
                    'id'           => $r['id'] ?? '',
                    'category'     => $r['category'] ?? '',
                    'title'        => $r['title'] ?? '',
                    'current_mode' => $r['current_mode'] ?? 'off',
                    'target_uri'   => $r['target_uri'] ?? '',
                ];
            }
        }
        return self::format_mcp_result([
            'success'        => true,
            'custom_rules'   => $custom,
            'baseline_rules' => $baseline,
            'count'          => count($custom),
        ]);
    }

    /** @param array<string, mixed> $args */
    public static function mcp_validate_and_simulate_rule(array $args): array {
        $raw   = (string) ($args['wirefilter_expr'] ?? '');
        $limit = isset($args['limit']) ? intval($args['limit']) : 500;
        $parsed = VisualRuleExpressionEngine::parse_ai_rule_payload($raw);
        if (empty($parsed['success'])) {
            return self::format_mcp_result($parsed);
        }
        $sim = VisualRuleExpressionEngine::simulate_against_recent_logs([
            'conditions'  => $parsed['conditions'],
            'group_logic' => $parsed['group_logic'],
        ], $limit);
        return self::format_mcp_result([
            'success'          => true,
            'format'           => $parsed['format'],
            'rule_meta'        => $parsed['rule_meta'],
            'conditions'       => $parsed['conditions'],
            'group_logic'      => $parsed['group_logic'],
            'wirefilter'       => $parsed['wirefilter'],
            'warnings'         => $parsed['warnings'],
            'unparsed_clauses' => $parsed['unparsed_clauses'],
            'simulation'       => $sim,
        ]);
    }

    /** @param array<string, mixed> $args */
    public static function mcp_save_custom_visual_rule(array $args): array {
        $payload = $args;
        if (empty($payload['conditions']) && !empty($payload['wirefilter_expr'])) {
            $parsed = VisualRuleExpressionEngine::parse_ai_rule_payload((string) $payload['wirefilter_expr']);
            if (empty($parsed['success'])) {
                return self::format_mcp_result($parsed);
            }
            $payload['conditions']  = $parsed['conditions'];
            $payload['group_logic'] = $parsed['group_logic'];
            $payload['wirefilter_expr'] = $parsed['wirefilter'];
            foreach (($parsed['rule_meta'] ?? []) as $mk => $mv) {
                if (empty($payload[$mk])) {
                    $payload[$mk] = $mv;
                }
            }
        }
        $res = ModularFirewallSynthesizer::create_custom_rule($payload);
        return self::format_mcp_result($res);
    }

    /** @param array<string, mixed> $args */
    public static function mcp_reorder_custom_visual_rules(array $args): array {
        $ordered_ids = is_array($args['ordered_ids'] ?? null) ? $args['ordered_ids'] : [];
        if (empty($ordered_ids)) {
            return self::format_mcp_result([
                'success' => false,
                'message' => __('ordered_ids array is required.', 'webcare-pro-security'),
            ]);
        }
        $res = ModularFirewallSynthesizer::reorder_custom_rules($ordered_ids);
        return self::format_mcp_result($res);
    }

    /** @param array<string, mixed> $args */
    public static function mcp_toggle_or_delete_custom_rule(array $args): array {
        $rule_id = sanitize_text_field((string) ($args['rule_id'] ?? ''));
        $action  = sanitize_key((string) ($args['action'] ?? ''));
        if ($rule_id === '' || !in_array($action, ['enforce', 'monitor', 'off', 'delete'], true)) {
            return self::format_mcp_result([
                'success' => false,
                'message' => __('Valid rule_id and action (enforce, monitor, off, delete) are required.', 'webcare-pro-security'),
            ]);
        }
        if ($action === 'delete') {
            $res = ModularFirewallSynthesizer::delete_custom_rule($rule_id);
        } else {
            $res = ModularFirewallSynthesizer::toggle_rule($rule_id, $action);
        }
        return self::format_mcp_result($res);
    }

    public function compile_preload_ast(): array {
        return ModularFirewallSynthesizer::get_compiled_preload_rules();
    }

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        return null;
    }
}
