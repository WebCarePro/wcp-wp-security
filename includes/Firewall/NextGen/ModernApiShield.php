<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ModernApiShield
 *
 * Defends WPGraphQL, Headless REST, and WordPress Interactivity / Batch API surfaces against:
 * - Unauthenticated GraphQL __schema / __type introspection harvesting
 * - Deeply nested GraphQL query amplification DoS & alias flooding
 * - Batched GraphQL mutation brute-force attacks
 */
class ModernApiShield implements SecurityModuleInterface, WafEvaluatorInterface {

    public function get_id(): string {
        return 'modern-api-shield';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('GraphQL, Headless & Interactivity API Shield', 'webcare-pro-security'),
            'description' => __('Blocks unauthenticated GraphQL schema introspection, deep nested query DoS, alias amplification, and batched mutation floods.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_modern_api_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'API & GraphQL',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        // Evaluated cleanly in early plugins_loaded WAF runtime via WafEvaluatorInterface.
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_modern_api_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('GraphQL & Modern API Shield', 'webcare-pro-security'),
            ],
            'waf_nextgen_graphql_block_introspection' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Block Unauthenticated GraphQL Introspection', 'webcare-pro-security'),
            ],
            'waf_nextgen_graphql_max_depth' => [
                'default' => 7,
                'type'    => 'int',
                'min'     => 2,
                'max'     => 20,
                'label'   => __('GraphQL Maximum AST Nesting Depth', 'webcare-pro-security'),
            ],
            'waf_nextgen_graphql_max_batch' => [
                'default' => 10,
                'type'    => 'int',
                'min'     => 1,
                'max'     => 50,
                'label'   => __('GraphQL Maximum Batched Operations', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [];
    }

    public function compile_preload_ast(): array {
        return [];
    }

    /**
     * Evaluate incoming GraphQL / batched API requests at plugins_loaded:0.
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        if ($ctx->isAdmin) {
            return null;
        }

        // Fast-path check for GraphQL surface
        $is_graphql = (strpos($ctx->cleanUri, '/graphql') !== false)
            || array_key_exists('graphql', $ctx->params)
            || (!empty($ctx->params['query']) && is_string($ctx->params['query']) && preg_match('/^\s*(?:query|mutation|subscription|\{)/i', $ctx->params['query']));

        if (!$is_graphql) {
            return null;
        }

        $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];

        $block_intro = !empty($settings['waf_nextgen_graphql_block_introspection']);
        $max_depth   = max(2, min(20, intval($settings['waf_nextgen_graphql_max_depth'] ?? 7)));
        $max_batch   = max(1, min(50, intval($settings['waf_nextgen_graphql_max_batch'] ?? 10)));

        $queries = self::extract_graphql_queries($ctx);
        if (empty($queries)) {
            return null;
        }

        if (count($queries) > $max_batch) {
            return new WafVerdict(
                'rate_limit',
                'WAF-GRAPHQL-BATCH-ABUSE',
                sprintf('Batched GraphQL request exceeded limit (%d operations > max %d).', count($queries), $max_batch),
                [
                    'category'    => 'Modern API & GraphQL Shield',
                    'severity'    => 'high',
                    'status_code' => 429,
                ]
            );
        }

        foreach ($queries as $q) {
            if ($block_intro && !$ctx->isLoggedIn && self::contains_introspection($q)) {
                return new WafVerdict(
                    'block',
                    'WAF-GRAPHQL-INTROSPECTION',
                    'Unauthenticated GraphQL __schema / __type introspection query blocked by Modern API Shield.',
                    [
                        'category'    => 'Modern API & GraphQL Shield',
                        'severity'    => 'medium',
                        'status_code' => 403,
                    ]
                );
            }

            $metrics = self::measure_query_complexity($q);
            if ($metrics['max_depth'] > $max_depth || $metrics['alias_count'] > 25) {
                return new WafVerdict(
                    'block',
                    'WAF-GRAPHQL-DEPTH-DOS',
                    sprintf(
                        'GraphQL amplification DoS neutralized (depth %d > max %d, aliases %d).',
                        $metrics['max_depth'],
                        $max_depth,
                        $metrics['alias_count']
                    ),
                    [
                        'category'    => 'Modern API & GraphQL Shield',
                        'severity'    => 'high',
                        'status_code' => 429,
                    ]
                );
            }
        }

        return null;
    }

    /**
     * Extract single or batched GraphQL query strings from RequestContext or php://input JSON array.
     *
     * @return string[]
     */
    public static function extract_graphql_queries(RequestContext $ctx): array {
        $queries = [];
        if (!empty($ctx->params['query']) && is_string($ctx->params['query'])) {
            $queries[] = $ctx->params['query'];
        }
        $ct = $ctx->headers['content-type'] ?? '';
        if (stripos($ct, 'application/json') !== false) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading bounded raw JSON body for GraphQL AST inspection
            $raw = (string) @file_get_contents('php://input', false, null, 0, 262144);
            if ($raw !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    if (isset($decoded['query']) && is_string($decoded['query']) && !in_array($decoded['query'], $queries, true)) {
                        $queries[] = $decoded['query'];
                    } elseif (isset($decoded[0]) && is_array($decoded[0])) {
                        foreach ($decoded as $item) {
                            if (is_array($item) && !empty($item['query']) && is_string($item['query'])) {
                                $queries[] = $item['query'];
                            }
                        }
                    }
                }
            }
        }
        return $queries;
    }

    /**
     * Detect unauthenticated introspection keywords outside quoted strings.
     */
    public static function contains_introspection(string $query): bool {
        $stripped = (string) preg_replace('/"(?:\\\\.|[^"\\\\])*"/', '""', $query);
        return preg_match('/\b__(?:schema|type)\b/', $stripped) === 1;
    }

    /**
     * Measure GraphQL brace nesting depth and alias count safely outside strings/comments.
     *
     * @return array{max_depth: int, alias_count: int}
     */
    public static function measure_query_complexity(string $query): array {
        $no_comments = (string) preg_replace('/#[^\r\n]*/', '', $query);
        $stripped    = (string) preg_replace('/"(?:\\\\.|[^"\\\\])*"/', '""', $no_comments);

        $depth     = 0;
        $max_depth = 0;
        $len       = strlen($stripped);

        for ($i = 0; $i < $len; $i++) {
            $ch = $stripped[$i];
            if ($ch === '{') {
                $depth++;
                if ($depth > $max_depth) {
                    $max_depth = $depth;
                }
            } elseif ($ch === '}') {
                $depth = max(0, $depth - 1);
            }
        }

        $alias_count = preg_match_all('/[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*[a-zA-Z_]/', $stripped);

        return [
            'max_depth'   => $max_depth,
            'alias_count' => is_int($alias_count) ? $alias_count : 0,
        ];
    }
}
