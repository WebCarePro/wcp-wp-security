<?php
namespace WebCareProScanner\Firewall\Modular;

use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * VisualRuleExpressionEngine
 *
 * Powers the Cloudflare-Style Visual Firewall Rule Studio:
 * - 18-field HTTP, Network/Geo/ASN, Payload/Upload, and WordPress/Plugin/WooCommerce evaluator
 * - Bidirectional OR-of-ANDs condition tree <-> Cloudflare Wirefilter translator
 * - Stateless pre-boot eligibility detection for MicroWafCompiler
 * - Historical traffic dry-run simulation against WafFileLogger
 * - 1-Click Cloudflare Edge Custom Ruleset (Wirefilter) deployment
 */
class VisualRuleExpressionEngine {

    const CF_VISUAL_TAG_PREFIX = '[WEBCARE-MOD-VISUAL:';

    /** @var array<string, string[]> */
    const LAYER_FIELDS_EDGE_MAP = [
        'http.request.uri.path'  => ['cf' => 'http.request.uri.path'],
        'http.request.uri.query' => ['cf' => 'http.request.uri.query'],
        'http.request.method'    => ['cf' => 'http.request.method'],
        'http.user_agent'        => ['cf' => 'http.user_agent'],
        'http.referer'           => ['cf' => 'http.referer'],
        'http.cookie'            => ['cf' => 'http.cookie'],
        'ip.src'                 => ['cf' => 'ip.src'],
        'ip.geoip.country'       => ['cf' => 'ip.geoip.country'],
        'ip.geoip.asnum'         => ['cf' => 'ip.geoip.asnum'],
    ];

    /**
     * Return full 18-field catalog with operator compatibility & edge/preload flags.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_field_catalog(): array {
        return [
            ['id' => 'http.request.uri.path',  'label' => 'URI Path',              'layer' => 'HTTP Request', 'needs_key' => false, 'edge' => true,  'preload' => true,  'ops' => ['eq', 'ne', 'contains', 'not_contains', 'starts_with', 'ends_with', 'matches_regex', 'in']],
            ['id' => 'http.request.uri.query', 'label' => 'URI Query String',      'layer' => 'HTTP Request', 'needs_key' => false, 'edge' => true,  'preload' => true,  'ops' => ['eq', 'ne', 'contains', 'not_contains', 'matches_regex']],
            ['id' => 'http.request.method',    'label' => 'HTTP Method',           'layer' => 'HTTP Request', 'needs_key' => false, 'edge' => true,  'preload' => true,  'ops' => ['eq', 'ne', 'in', 'not_in']],
            ['id' => 'http.user_agent',        'label' => 'User-Agent',            'layer' => 'HTTP Request', 'needs_key' => false, 'edge' => true,  'preload' => true,  'ops' => ['eq', 'contains', 'not_contains', 'matches_regex', 'in']],
            ['id' => 'http.referer',           'label' => 'Referer URL',           'layer' => 'HTTP Request', 'needs_key' => false, 'edge' => true,  'preload' => true,  'ops' => ['eq', 'contains', 'not_contains', 'matches_regex']],
            ['id' => 'http.cookie',            'label' => 'Cookie Header / Name',  'layer' => 'HTTP Request', 'needs_key' => false, 'edge' => true,  'preload' => true,  'ops' => ['contains', 'not_contains', 'matches_regex']],
            ['id' => 'http.headers',           'label' => 'Request Header [<name>]', 'layer' => 'HTTP Request', 'needs_key' => true, 'key_placeholder' => 'X-Forwarded-Host', 'edge' => true, 'preload' => true, 'ops' => ['exists', 'not_exists', 'eq', 'contains', 'matches_regex']],
            ['id' => 'ip.src',                 'label' => 'Client IP Address',     'layer' => 'Network & Geo', 'needs_key' => false, 'edge' => true, 'preload' => true,  'ops' => ['eq', 'ne', 'in_cidr', 'not_in_cidr']],
            ['id' => 'ip.geoip.country',       'label' => 'Country Code (ISO-2)',  'layer' => 'Network & Geo', 'needs_key' => false, 'edge' => true, 'preload' => true,  'ops' => ['eq', 'ne', 'in', 'not_in']],
            ['id' => 'ip.geoip.asnum',         'label' => 'ASN Number',            'layer' => 'Network & Geo', 'needs_key' => false, 'edge' => true, 'preload' => true,  'ops' => ['eq', 'ne', 'in', 'not_in']],
            ['id' => 'http.request.params',    'label' => 'Request Param [<key>]', 'layer' => 'Payload & Upload', 'needs_key' => true, 'key_placeholder' => 'action', 'edge' => false, 'preload' => true, 'ops' => ['exists', 'not_exists', 'eq', 'contains', 'matches_regex', 'is_array']],
            ['id' => 'http.upload.extension',  'label' => 'Upload File Extension', 'layer' => 'Payload & Upload', 'needs_key' => false, 'edge' => false, 'preload' => true, 'ops' => ['eq', 'in', 'matches_regex']],
            ['id' => 'wp.plugin.target_slug',  'label' => 'WP Plugin / Theme Slug','layer' => 'WordPress Runtime', 'needs_key' => false, 'edge' => false, 'preload' => false, 'ops' => ['eq', 'ne', 'in']],
            ['id' => 'wp.ajax.action',         'label' => 'WP AJAX Action',        'layer' => 'WordPress Runtime', 'needs_key' => false, 'edge' => false, 'preload' => true,  'ops' => ['eq', 'ne', 'starts_with', 'contains', 'in']],
            ['id' => 'wp.rest.route',          'label' => 'WP REST Route',         'layer' => 'WordPress Runtime', 'needs_key' => false, 'edge' => false, 'preload' => true,  'ops' => ['eq', 'starts_with', 'contains', 'matches_regex']],
            ['id' => 'wp.user.is_logged_in',   'label' => 'WP User Logged In',     'layer' => 'WordPress Runtime', 'needs_key' => false, 'edge' => false, 'preload' => false, 'ops' => ['is_true', 'is_false']],
            ['id' => 'wp.user.role',           'label' => 'WP User Role',          'layer' => 'WordPress Runtime', 'needs_key' => false, 'edge' => false, 'preload' => false, 'ops' => ['has', 'not_has', 'in']],
            ['id' => 'wp.woo.has_cart_session','label' => 'Woo / Cart Session',    'layer' => 'WordPress Runtime', 'needs_key' => false, 'edge' => false, 'preload' => false, 'ops' => ['is_true', 'is_false']],
        ];
    }

    /**
     * Validate and sanitize an incoming array of OR-joined condition groups.
     *
     * @param mixed $raw_groups
     * @return array<int, array{logic: string, rules: array<int, array<string, string>>}>
     */
    public static function sanitize_condition_groups($raw_groups): array {
        if (!is_array($raw_groups)) {
            return [];
        }

        $catalog     = self::get_field_catalog();
        $valid_map   = [];
        foreach ($catalog as $c) {
            $valid_map[$c['id']] = $c['ops'];
        }

        $clean_groups = [];
        foreach (array_slice($raw_groups, 0, 10) as $group) {
            if (!is_array($group) || empty($group['rules']) || !is_array($group['rules'])) {
                continue;
            }
            $clean_rules = [];
            foreach (array_slice($group['rules'], 0, 20) as $cond) {
                if (!is_array($cond)) {
                    continue;
                }
                $field = strtolower(trim(sanitize_text_field((string) ($cond['field'] ?? ''))));
                // Support shorthand http.headers[X-Foo] or http.request.params[bar]
                $key = sanitize_text_field((string) ($cond['key'] ?? ''));
                if (preg_match('/^(http\.headers|http\.request\.params)\[([^\]]+)\]$/i', $field, $m)) {
                    $field = strtolower($m[1]);
                    $key   = trim($m[2], "\"' ");
                }
                if (!isset($valid_map[$field])) {
                    continue;
                }

                $op = strtolower(trim(sanitize_text_field((string) ($cond['op'] ?? 'eq'))));
                if (!in_array($op, $valid_map[$field], true)) {
                    $op = $valid_map[$field][0];
                }

                $val = isset($cond['value']) ? sanitize_text_field((string) $cond['value']) : '';
                if (in_array($op, ['matches_regex'], true) && $val !== '') {
                    // Validate regex delimiter safety before storing
                    $delim_safe = self::wrap_regex($val);
                    if (@preg_match($delim_safe, '') === false) {
                        continue;
                    }
                }

                $clean_rules[] = [
                    'field' => $field,
                    'key'   => $key,
                    'op'    => $op,
                    'value' => $val,
                ];
            }

            if (!empty($clean_rules)) {
                $grp_logic = strtoupper(trim((string) ($group['logic'] ?? 'AND'))) === 'OR' ? 'OR' : 'AND';
                $clean_groups[] = [
                    'logic' => $grp_logic,
                    'rules' => $clean_rules,
                ];
            }
        }

        return $clean_groups;
    }

    /**
     * Wrap user-supplied regex cleanly with ~ delimiter.
     */
    private static function wrap_regex(string $pattern): string {
        $escaped = str_replace('~', '\~', $pattern);
        return '~' . $escaped . '~i';
    }

    /**
     * Determine if every condition in all groups can execute safely before WordPress boots.
     *
     * @param array<int, array<string, mixed>> $groups
     * @return bool
     */
    public static function is_stateless_preload_eligible(array $groups): bool {
        if (empty($groups)) {
            return false;
        }
        $catalog_map = [];
        foreach (self::get_field_catalog() as $item) {
            $catalog_map[$item['id']] = !empty($item['preload']);
        }
        foreach ($groups as $grp) {
            foreach (($grp['rules'] ?? []) as $cond) {
                $f = (string) ($cond['field'] ?? '');
                if (empty($catalog_map[$f])) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Evaluate multi-group AND/OR condition tree against a normalized RequestContext.
     *
     * @param array<int, array<string, mixed>> $groups
     * @param RequestContext $ctx
     * @param string $group_logic 'OR' (default) or 'AND'
     * @return bool
     */
    public static function evaluate_groups(array $groups, RequestContext $ctx, string $group_logic = 'OR'): bool {
        if (empty($groups)) {
            return false;
        }

        $top_and   = (strtoupper(trim($group_logic)) === 'AND');
        $evaluated = 0;

        foreach ($groups as $group) {
            $rules = $group['rules'] ?? [];
            if (empty($rules) || !is_array($rules)) {
                continue;
            }
            $evaluated++;
            $grp_or      = (strtoupper(trim((string) ($group['logic'] ?? 'AND'))) === 'OR');
            $group_match = !$grp_or;

            foreach ($rules as $cond) {
                $hit = self::evaluate_single_condition($cond, $ctx);
                if ($grp_or && $hit) {
                    $group_match = true;
                    break;
                }
                if (!$grp_or && !$hit) {
                    $group_match = false;
                    break;
                }
            }

            if ($top_and && !$group_match) {
                return false;
            }
            if (!$top_and && $group_match) {
                return true;
            }
        }

        return $top_and && $evaluated > 0;
    }

    /**
     * Evaluate one condition clause against RequestContext.
     *
     * @param array<string, mixed> $cond
     * @param RequestContext $ctx
     * @return bool
     */
    public static function evaluate_single_condition(array $cond, RequestContext $ctx): bool {
        $field = (string) ($cond['field'] ?? '');
        $key   = (string) ($cond['key'] ?? '');
        $op    = (string) ($cond['op'] ?? 'eq');
        $want  = (string) ($cond['value'] ?? '');

        // Boolean runtime predicates
        if ($field === 'wp.user.is_logged_in') {
            return ($op === 'is_true') ? $ctx->isLoggedIn : !$ctx->isLoggedIn;
        }
        if ($field === 'wp.woo.has_cart_session') {
            return ($op === 'is_true') ? $ctx->hasWooCart : !$ctx->hasWooCart;
        }

        // Array membership predicates (User Role, Uploaded File Extensions)
        if ($field === 'wp.user.role') {
            $want_list = self::split_list_values($want);
            $has_any   = !empty(array_intersect($want_list, $ctx->userRoles));
            if ($op === 'has' || $op === 'in') {
                return $has_any;
            }
            if ($op === 'not_has') {
                return !$has_any;
            }
            return false;
        }

        if ($field === 'http.upload.extension') {
            foreach ($ctx->uploadedExtensions as $ext) {
                if (self::match_string_operator($ext, $op, $want)) {
                    return true;
                }
            }
            return false;
        }

        // Keyed lookup fields (HTTP headers and request params)
        if ($field === 'http.headers') {
            $hkey   = strtolower(trim($key));
            $exists = ($hkey !== '' && array_key_exists($hkey, $ctx->headers));
            if ($op === 'exists') {
                return $exists;
            }
            if ($op === 'not_exists') {
                return !$exists;
            }
            if (!$exists) {
                return false;
            }
            return self::match_string_operator((string) $ctx->headers[$hkey], $op, $want);
        }

        if ($field === 'http.request.params') {
            $pkey   = sanitize_key($key);
            $exists = ($pkey !== '' && array_key_exists($pkey, $ctx->params));
            if ($op === 'exists') {
                return $exists;
            }
            if ($op === 'not_exists') {
                return !$exists;
            }
            if (!$exists) {
                return false;
            }
            $val = $ctx->params[$pkey];
            if ($op === 'is_array') {
                return is_array($val);
            }
            $scalar = is_array($val) ? (string) wp_json_encode($val) : (string) $val;
            return self::match_string_operator($scalar, $op, $want);
        }

        // IP / CIDR field
        if ($field === 'ip.src') {
            if ($op === 'eq') {
                return strtolower(trim($ctx->ip)) === strtolower(trim($want));
            }
            if ($op === 'ne') {
                return strtolower(trim($ctx->ip)) !== strtolower(trim($want));
            }
            $cidrs = self::split_list_values($want);
            $in_cidr = false;
            foreach ($cidrs as $cidr) {
                if (self::ip_matches_cidr($ctx->ip, $cidr)) {
                    $in_cidr = true;
                    break;
                }
            }
            return ($op === 'not_in_cidr') ? !$in_cidr : $in_cidr;
        }

        // Scalar string fields
        $subject = '';
        switch ($field) {
            case 'http.request.uri.path':
                $subject = $ctx->cleanUri;
                break;
            case 'http.request.uri.query':
                $subject = $ctx->query;
                break;
            case 'http.request.method':
                $subject = strtoupper($ctx->method);
                break;
            case 'http.user_agent':
                $subject = $ctx->userAgent;
                break;
            case 'http.referer':
                $subject = $ctx->referer;
                break;
            case 'http.cookie':
                $subject = $ctx->cookieHeader;
                break;
            case 'ip.geoip.country':
                $subject = strtoupper($ctx->country);
                if ($subject === '') {
                    return false;
                }
                break;
            case 'ip.geoip.asnum':
                $subject = $ctx->asn;
                if ($subject === '') {
                    return false;
                }
                break;
            case 'wp.plugin.target_slug':
                $subject = $ctx->targetSlug;
                break;
            case 'wp.ajax.action':
                $subject = $ctx->ajaxAction;
                break;
            case 'wp.rest.route':
                $subject = $ctx->restRoute;
                break;
            default:
                return false;
        }

        return self::match_string_operator($subject, $op, $want);
    }

    /**
     * Evaluate standard string / list / regex operator case-insensitively.
     */
    public static function match_string_operator(string $subject, string $op, string $want): bool {
        $subj_l = strtolower($subject);
        $want_l = strtolower(trim($want));

        switch ($op) {
            case 'eq':
                return $subj_l === $want_l;
            case 'ne':
                return $subj_l !== $want_l;
            case 'contains':
                return $want_l !== '' && strpos($subj_l, $want_l) !== false;
            case 'not_contains':
                return $want_l === '' || strpos($subj_l, $want_l) === false;
            case 'starts_with':
                return $want_l !== '' && strpos($subj_l, $want_l) === 0;
            case 'ends_with':
                if ($want_l === '') {
                    return false;
                }
                return substr($subj_l, -strlen($want_l)) === $want_l;
            case 'matches_regex':
                if ($want === '') {
                    return false;
                }
                $rx = self::wrap_regex($want);
                return @preg_match($rx, $subject) === 1;
            case 'in':
                return in_array($subj_l, self::split_list_values($want), true);
            case 'not_in':
                return !in_array($subj_l, self::split_list_values($want), true);
            default:
                return false;
        }
    }

    /**
     * Split comma / whitespace / brace-delimited values cleanly.
     *
     * @return string[]
     */
    private static function split_list_values(string $raw): array {
        $trimmed = trim($raw, " \t\n\r\0\x0B{}");
        if ($trimmed === '') {
            return [];
        }
        $parts = preg_split('/[\s,]+/', $trimmed, -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($parts)) {
            return [];
        }
        return array_values(array_map(static function ($item) {
            return strtolower(trim((string) $item, "\"' "));
        }, $parts));
    }

    /**
     * Exact IPv4 & IPv6 CIDR matcher via inet_pton bitmasks.
     */
    public static function ip_matches_cidr(string $ip, string $cidr): bool {
        $cidr = trim($cidr);
        if (strpos($cidr, '/') === false) {
            return strtolower(trim($ip)) === strtolower($cidr);
        }
        [$subnet, $bits_raw] = explode('/', $cidr, 2);
        $ip_bin     = @inet_pton(trim($ip));
        $subnet_bin = @inet_pton(trim($subnet));
        if ($ip_bin === false || $subnet_bin === false || strlen($ip_bin) !== strlen($subnet_bin)) {
            return false;
        }
        $max_bits = strlen($ip_bin) * 8;
        $bits     = max(0, min($max_bits, intval($bits_raw)));
        $full     = intdiv($bits, 8);
        $rem      = $bits % 8;

        if ($full > 0 && substr($ip_bin, 0, $full) !== substr($subnet_bin, 0, $full)) {
            return false;
        }
        if ($rem > 0) {
            $mask = (~((1 << (8 - $rem)) - 1)) & 0xFF;
            if ((ord($ip_bin[$full]) & $mask) !== (ord($subnet_bin[$full]) & $mask)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Render full Wirefilter expression representing the structured condition groups.
     *
     * @param array<int, array<string, mixed>> $groups
     * @param string $group_logic 'OR' (default) or 'AND'
     * @return string
     */
    public static function to_wirefilter(array $groups, string $group_logic = 'OR'): string {
        $group_strs = [];
        $valid_cnt  = 0;
        foreach ($groups as $grp) {
            if (!empty($grp['rules']) && is_array($grp['rules'])) {
                $valid_cnt++;
            }
        }
        $top_join = (strtoupper(trim($group_logic)) === 'AND') ? ' and ' : ' or ';

        foreach ($groups as $grp) {
            $clauses = [];
            foreach (($grp['rules'] ?? []) as $cond) {
                $clause = self::condition_to_wirefilter((array) $cond);
                if ($clause !== '') {
                    $clauses[] = $clause;
                }
            }
            if (!empty($clauses)) {
                $grp_join = (strtoupper(trim((string) ($grp['logic'] ?? 'AND'))) === 'OR') ? ' or ' : ' and ';
                $joined   = implode($grp_join, $clauses);
                $group_strs[] = ($valid_cnt > 1 && count($clauses) > 1) ? "({$joined})" : $joined;
            }
        }
        return implode($top_join, $group_strs);
    }

    /**
     * Convert a condition tree into a strictly Cloudflare-Edge-compatible Wirefilter expression.
     *
     * @param array<int, array<string, mixed>> $groups
     * @param string $group_logic 'OR' (default) or 'AND'
     * @return array{expression: string, partial: bool, skipped_fields: string[]}
     */
    public static function to_cloudflare_edge_wirefilter(array $groups, string $group_logic = 'OR'): array {
        $edge_groups    = [];
        $skipped_fields = [];
        $top_join       = (strtoupper(trim($group_logic)) === 'AND') ? ' and ' : ' or ';

        foreach ($groups as $grp) {
            $clauses = [];
            foreach (($grp['rules'] ?? []) as $cond) {
                $f = (string) ($cond['field'] ?? '');
                if (isset(self::LAYER_FIELDS_EDGE_MAP[$f]) || $f === 'http.headers') {
                    $c = self::condition_to_wirefilter((array) $cond, true);
                    if ($c !== '') {
                        $clauses[] = $c;
                        continue;
                    }
                }
                $skipped_fields[] = $f;
            }
            if (!empty($clauses)) {
                $grp_join      = (strtoupper(trim((string) ($grp['logic'] ?? 'AND'))) === 'OR') ? ' or ' : ' and ';
                $joined        = implode($grp_join, $clauses);
                $edge_groups[] = count($clauses) > 1 ? "({$joined})" : $joined;
            }
        }

        if (count($edge_groups) === 1 && substr($edge_groups[0], 0, 1) === '(' && substr($edge_groups[0], -1) === ')') {
            $edge_groups[0] = substr($edge_groups[0], 1, -1);
        }

        $skipped_fields = array_values(array_unique(array_filter($skipped_fields)));
        return [
            'expression'     => implode($top_join, $edge_groups),
            'partial'        => !empty($skipped_fields),
            'skipped_fields' => $skipped_fields,
        ];
    }

    /**
     * Format one condition clause in Cloudflare Wirefilter notation.
     *
     * @param array<string, mixed> $cond
     * @param bool $cf_strict Whether to emit strict Cloudflare field names
     * @return string
     */
    private static function condition_to_wirefilter(array $cond, bool $cf_strict = false): string {
        $field = (string) ($cond['field'] ?? '');
        $key   = (string) ($cond['key'] ?? '');
        $op    = (string) ($cond['op'] ?? 'eq');
        $val   = (string) ($cond['value'] ?? '');

        if ($field === 'wp.user.is_logged_in' || $field === 'wp.woo.has_cart_session') {
            return $op === 'is_false' ? "not {$field}" : $field;
        }

        $field_expr = $field;
        if ($field === 'http.headers') {
            $h_esc      = str_replace('"', '\"', $key);
            $field_expr = $cf_strict ? "http.request.headers[\"{$h_esc}\"]" : "http.headers[\"{$h_esc}\"]";
        } elseif ($field === 'http.request.params') {
            $p_esc      = str_replace('"', '\"', $key);
            $field_expr = "http.request.params[\"{$p_esc}\"]";
        }

        $qval = '"' . str_replace(['\\', '"'], ['\\\\', '\"'], $val) . '"';

        switch ($op) {
            case 'eq':
                return "{$field_expr} eq {$qval}";
            case 'ne':
                return "{$field_expr} ne {$qval}";
            case 'contains':
                return "{$field_expr} contains {$qval}";
            case 'not_contains':
                return "not ({$field_expr} contains {$qval})";
            case 'starts_with':
                return "starts_with({$field_expr}, {$qval})";
            case 'ends_with':
                return "ends_with({$field_expr}, {$qval})";
            case 'matches_regex':
                return "{$field_expr} matches {$qval}";
            case 'in':
            case 'has':
            case 'in_cidr':
                $items = array_map(static function ($x) {
                    return '"' . str_replace('"', '\"', $x) . '"';
                }, self::split_list_values($val));
                return $field_expr . ' in {' . implode(' ', $items) . '}';
            case 'not_in':
            case 'not_has':
            case 'not_in_cidr':
                $items = array_map(static function ($x) {
                    return '"' . str_replace('"', '\"', $x) . '"';
                }, self::split_list_values($val));
                return 'not (' . $field_expr . ' in {' . implode(' ', $items) . '})';
            case 'exists':
                return "{$field_expr} exists";
            case 'not_exists':
                return "not ({$field_expr} exists)";
            case 'is_array':
                return "{$field_expr} is_array";
            default:
                return "{$field_expr} eq {$qval}";
        }
    }

    /**
     * Parse a Wirefilter expression into structured condition groups plus top-level group join logic ('OR' | 'AND').
     *
     * @param string $expr
     * @return array{conditions: array<int, array<string, mixed>>, group_logic: string, unparsed_clauses: string[]}
     */
    public static function parse_wirefilter_tree(string $expr): array {
        $expr = self::strip_code_fences($expr);
        if ($expr === '') {
            return ['conditions' => [], 'group_logic' => 'OR', 'unparsed_clauses' => []];
        }

        $or_parts    = self::split_top_level($expr, 'or');
        $and_parts   = self::split_top_level($expr, 'and');
        $group_logic = 'OR';
        $raw_groups  = [];

        if (count($or_parts) > 1) {
            $group_logic = 'OR';
            $raw_groups  = $or_parts;
        } elseif (count($and_parts) > 1) {
            $has_inner_or = false;
            foreach ($and_parts as $ap) {
                $inner = trim($ap);
                if (substr($inner, 0, 1) === '(' && substr($inner, -1) === ')') {
                    $inner = trim(substr($inner, 1, -1));
                }
                if (count(self::split_top_level($inner, 'or')) > 1) {
                    $has_inner_or = true;
                    break;
                }
            }
            if ($has_inner_or) {
                $group_logic = 'AND';
                $raw_groups  = $and_parts;
            } else {
                $raw_groups = [$expr];
            }
        } else {
            $raw_groups = [$expr];
        }

        $groups           = [];
        $unparsed_clauses = [];
        foreach ($raw_groups as $part) {
            $part = trim($part);
            if (substr($part, 0, 1) === '(' && substr($part, -1) === ')') {
                $part = trim(substr($part, 1, -1));
            }
            $inner_or  = self::split_top_level($part, 'or');
            $inner_and = self::split_top_level($part, 'and');
            $grp_op    = (count($inner_or) > 1 && count($inner_and) <= 1) ? 'OR' : 'AND';
            $clauses   = ($grp_op === 'OR') ? $inner_or : $inner_and;
            $rules     = [];

            foreach ($clauses as $clause) {
                $trimmed_clause = trim($clause);
                if ($trimmed_clause === '') {
                    continue;
                }
                $parsed = self::parse_single_wirefilter_clause($trimmed_clause);
                if ($parsed !== null) {
                    $rules[] = $parsed;
                } else {
                    $unparsed_clauses[] = $trimmed_clause;
                }
            }
            if (!empty($rules)) {
                $groups[] = ['logic' => $grp_op, 'rules' => $rules];
            }
        }

        return [
            'conditions'       => self::sanitize_condition_groups($groups),
            'group_logic'      => $group_logic,
            'unparsed_clauses' => $unparsed_clauses,
        ];
    }

    /**
     * Strip surrounding Markdown code fences / backticks / comment lines cleanly.
     */
    private static function strip_code_fences(string $raw): string {
        $text = trim($raw);
        if (preg_match('/```(?:[a-z0-9_-]+)?\s*\R([\s\S]*?)\R```/i', $text, $m)) {
            $text = trim($m[1]);
        }
        $text = trim($text, " \t\n\r\0\x0B`");
        $lines = preg_split('/\R/', $text) ?: [];
        $kept  = [];
        foreach ($lines as $ln) {
            $t = trim($ln);
            if ($t === '' || str_starts_with($t, '#') || str_starts_with($t, '//')) {
                continue;
            }
            $kept[] = $t;
        }
        return trim(implode(' ', $kept));
    }

    /**
     * Parse a simple Wirefilter expression back into structured condition groups.
     *
     * @param string $expr
     * @return array<int, array<string, mixed>>
     */
    public static function parse_wirefilter(string $expr): array {
        $tree = self::parse_wirefilter_tree($expr);
        return $tree['conditions'];
    }

    /**
     * Parse a single Wirefilter predicate into ['field', 'key', 'op', 'value'].
     */
    private static function parse_single_wirefilter_clause(string $clause): ?array {
        // Strip balanced outer parens if not preceded by `not`
        while (preg_match('/^\((.+)\)$/', $clause, $pm) && !preg_match('/^not\s*\(/i', $clause)) {
            $clause = trim($pm[1]);
        }

        $negated = false;
        if (preg_match('/^not\s*\((.+)\)$/i', $clause, $m)) {
            $negated = true;
            $clause  = trim($m[1]);
        } elseif (preg_match('/^not\s+(.+)$/i', $clause, $m)) {
            $negated = true;
            $clause  = trim($m[1]);
        } elseif (preg_match('/^!\s*(.+)$/', $clause, $m)) {
            $negated = true;
            $clause  = trim($m[1]);
        }

        if ($clause === 'wp.user.is_logged_in' || $clause === 'wp.woo.has_cart_session') {
            return [
                'field' => $clause,
                'key'   => '',
                'op'    => $negated ? 'is_false' : 'is_true',
                'value' => '',
            ];
        }

        // Boolean equality variants: wp.user.is_logged_in eq false / == true
        if (preg_match('/^(wp\.user\.is_logged_in|wp\.woo\.has_cart_session)\s+(eq|==|ne|!=)\s+(true|false|1|0|"true"|"false")$/i', $clause, $m)) {
            $want_true = in_array(strtolower(trim($m[3], '"')), ['true', '1'], true);
            $is_ne     = in_array(strtolower($m[2]), ['ne', '!='], true);
            $final_true = ($negated xor $is_ne) ? !$want_true : $want_true;
            return [
                'field' => strtolower($m[1]),
                'key'   => '',
                'op'    => $final_true ? 'is_true' : 'is_false',
                'value' => '',
            ];
        }

        // starts_with(field, "val") / ends_with(field, "val")
        if (!$negated && preg_match('/^(starts_with|ends_with)\(\s*([a-z0-9_.\[\]"\'-]+)\s*,\s*"([^"]*)"\s*\)$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[2]);
            return ['field' => $field, 'key' => $key, 'op' => strtolower($m[1]), 'value' => $m[3]];
        }

        // Infix starts_with / ends_with: field starts_with "val"
        if (!$negated && preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+(starts_with|ends_with)\s+"((?:[^"\\\\]|\\\\.)*)"$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            return ['field' => $field, 'key' => $key, 'op' => strtolower($m[2]), 'value' => stripcslashes($m[3])];
        }

        // field in {"a" "b"} or {"a", "b"}
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+in\s+\{([^}]*)\}$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            $vals = preg_replace('/["\']/', '', trim($m[2]));
            $vals = preg_replace('/[\s,]+/', ', ', (string) $vals);
            $op = ($field === 'ip.src') ? ($negated ? 'not_in_cidr' : 'in_cidr') : ($negated ? 'not_in' : 'in');
            return ['field' => $field, 'key' => $key, 'op' => $op, 'value' => trim((string) $vals, ', ')];
        }

        // field exists
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+exists$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            return ['field' => $field, 'key' => $key, 'op' => $negated ? 'not_exists' : 'exists', 'value' => ''];
        }

        // field is_array
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+is_array$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            return ['field' => $field, 'key' => $key, 'op' => 'is_array', 'value' => ''];
        }

        // field not contains "value" or field not_contains "value"
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+(?:not\s+contains|not_contains)\s+"((?:[^"\\\\]|\\\\.)*)"$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            return ['field' => $field, 'key' => $key, 'op' => $negated ? 'contains' : 'not_contains', 'value' => stripcslashes($m[2])];
        }

        // field op "value" (supports eq, ==, ne, !=, contains, matches, matches_regex)
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+(eq|==|ne|!=|contains|matches|matches_regex)\s+"((?:[^"\\\\]|\\\\.)*)"$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            $raw_op = strtolower($m[2]);
            $op_map = ['==' => 'eq', '!=' => 'ne', 'matches' => 'matches_regex'];
            $op     = $op_map[$raw_op] ?? $raw_op;
            if ($negated) {
                if ($op === 'contains') {
                    $op = 'not_contains';
                } elseif ($op === 'eq') {
                    $op = 'ne';
                } elseif ($op === 'ne') {
                    $op = 'eq';
                }
            }
            return ['field' => $field, 'key' => $key, 'op' => $op, 'value' => stripcslashes($m[3])];
        }

        return null;
    }

    /**
     * Extract base field name and subscript key from Wirefilter token.
     *
     * @return array{0: string, 1: string}
     */
    private static function extract_field_and_key(string $raw_field): array {
        $raw_field = trim($raw_field);
        if (preg_match('/^(http\.headers|http\.request\.headers|http\.request\.params)\["?([^"\]]+)"?\]$/i', $raw_field, $m)) {
            $base = strtolower($m[1]) === 'http.request.headers' ? 'http.headers' : strtolower($m[1]);
            return [$base, trim($m[2])];
        }
        return [strtolower($raw_field), ''];
    }

    /**
     * Split expression on top-level keyword ('and' or 'or') outside quotes & parentheses.
     *
     * @return string[]
     */
    private static function split_top_level(string $expr, string $keyword): array {
        $parts   = [];
        $len     = strlen($expr);
        $depth   = 0;
        $in_quot = false;
        $escape  = false;
        $start   = 0;
        $kw_len  = strlen($keyword);

        for ($i = 0; $i < $len; $i++) {
            $ch = $expr[$i];
            if ($escape) {
                $escape = false;
                continue;
            }
            if ($ch === '\\') {
                $escape = true;
                continue;
            }
            if ($ch === '"') {
                $in_quot = !$in_quot;
                continue;
            }
            if ($in_quot) {
                continue;
            }
            if ($ch === '(') {
                $depth++;
            } elseif ($ch === ')') {
                $depth = max(0, $depth - 1);
            } elseif ($depth === 0) {
                $slice = substr($expr, $i, $kw_len + 2);
                if (preg_match('/^\s' . preg_quote($keyword, '/') . '\s$/i', $slice)) {
                    $parts[] = substr($expr, $start, $i - $start);
                    $i      += $kw_len + 1;
                    $start   = $i + 1;
                }
            }
        }
        $parts[] = substr($expr, $start);
        return $parts;
    }

    /**
     * Dry-run simulate a candidate Visual/Custom Rule against the last N entries in WafFileLogger.
     *
     * @param array<string, mixed> $rule_data
     * @param int $limit
     * @return array<string, mixed>
     */
    public static function simulate_against_recent_logs(array $rule_data, int $limit = 500): array {
        $limit       = max(10, min(1000, $limit));
        $group_logic = strtoupper(trim((string) ($rule_data['group_logic'] ?? 'OR'))) === 'AND' ? 'AND' : 'OR';
        $groups      = [];
        if (!empty($rule_data['conditions']) && is_array($rule_data['conditions'])) {
            $groups = self::sanitize_condition_groups($rule_data['conditions']);
        } elseif (!empty($rule_data['wirefilter_expr'])) {
            $parsed      = self::parse_wirefilter_tree((string) $rule_data['wirefilter_expr']);
            $groups      = $parsed['conditions'];
            $group_logic = $parsed['group_logic'];
        }

        $res = class_exists(WafFileLogger::class)
            ? WafFileLogger::query_logs([], $limit, 0)
            : ['logs' => []];
        $logs = is_array($res['logs'] ?? null) ? $res['logs'] : [];

        $matched_samples = [];
        $matched_count   = 0;
        $admin_hits      = 0;
        $logged_in_hits  = 0;
        $guest_hits      = 0;

        $target_uri_l = strtolower(trim((string) ($rule_data['target_uri'] ?? '')));
        $target_param = sanitize_key((string) ($rule_data['target_param'] ?? ''));
        $target_val_l = strtolower(trim((string) ($rule_data['target_value'] ?? '')));
        $methods      = is_array($rule_data['http_methods'] ?? null) ? array_map('strtoupper', $rule_data['http_methods']) : [];

        foreach ($logs as $row) {
            if (!is_array($row)) {
                continue;
            }
            $ctx = self::context_from_log_row($row);
            $hit = false;

            if (!empty($groups)) {
                $hit = self::evaluate_groups($groups, $ctx, $group_logic);
            } elseif ($target_uri_l !== '' || $target_param !== '') {
                $uri_m = ($target_uri_l === '')
                    || strpos($ctx->cleanUri, $target_uri_l) !== false
                    || ($ctx->restRoute !== '' && strpos($ctx->restRoute, $target_uri_l) !== false);
                $meth_m = empty($methods) || in_array($ctx->method, $methods, true);
                $param_m = true;
                if ($target_param !== '') {
                    $pv = isset($ctx->params[$target_param]) ? strtolower((string) $ctx->params[$target_param]) : '';
                    $param_m = $target_val_l !== '' ? ($pv === $target_val_l) : ($pv !== '');
                }
                $hit = $uri_m && $meth_m && $param_m;
            }

            if ($hit) {
                $matched_count++;
                if ($ctx->isAdmin) {
                    $admin_hits++;
                } elseif ($ctx->isLoggedIn) {
                    $logged_in_hits++;
                } else {
                    $guest_hits++;
                }

                if (count($matched_samples) < 15) {
                    $matched_samples[] = [
                        'timestamp' => (string) ($row['timestamp'] ?? ''),
                        'ip'        => $ctx->ip,
                        'method'    => $ctx->method,
                        'uri'       => $ctx->uri,
                        'rule_id'   => (string) ($row['rule_id'] ?? ''),
                        'action'    => (string) ($row['action'] ?? ''),
                    ];
                }
            }
        }

        return [
            'success'        => true,
            'total_scanned'  => count($logs),
            'matched_count'  => $matched_count,
            'admin_hits'     => $admin_hits,
            'logged_in_hits' => $logged_in_hits,
            'guest_hits'     => $guest_hits,
            'samples'        => $matched_samples,
            'wirefilter'     => self::to_wirefilter($groups, $group_logic),
            'cf_edge'        => self::to_cloudflare_edge_wirefilter($groups, $group_logic),
        ];
    }

    /**
     * Construct a synthetic RequestContext from a historical WafFileLogger entry.
     *
     * @param array<string, mixed> $row
     * @return RequestContext
     */
    private static function context_from_log_row(array $row): RequestContext {
        $ctx               = new RequestContext();
        $ctx->ip           = (string) ($row['ip'] ?? '0.0.0.0');
        $ctx->method       = strtoupper((string) ($row['method'] ?? 'GET'));
        $raw_uri           = (string) ($row['request_uri'] ?? ($row['uri'] ?? ''));
        $ctx->uri          = $raw_uri;
        $q_pos             = strpos($raw_uri, '?');
        $ctx->cleanUri     = strtolower($q_pos === false ? $raw_uri : substr($raw_uri, 0, $q_pos));
        $ctx->query        = $q_pos === false ? '' : substr($raw_uri, $q_pos + 1);
        $ctx->userAgent    = (string) ($row['user_agent'] ?? '');
        $ctx->referer      = (string) ($row['referer'] ?? '');
        $ctx->country      = strtoupper((string) ($row['country'] ?? ''));
        $ctx->isLoggedIn   = intval($row['user_id'] ?? 0) > 0 || !empty($row['user_login']);
        $role_str          = strtolower((string) ($row['user_role'] ?? ''));
        $ctx->userRoles    = $role_str !== '' ? [$role_str] : [];
        $ctx->isAdmin      = in_array('administrator', $ctx->userRoles, true);

        if ($ctx->query !== '') {
            parse_str($ctx->query, $q_arr);
            if (is_array($q_arr)) {
                $ctx->params = $q_arr;
                if (!empty($q_arr['action']) && is_string($q_arr['action'])) {
                    $ctx->ajaxAction = strtolower(trim($q_arr['action']));
                }
                if (!empty($q_arr['rest_route']) && is_string($q_arr['rest_route'])) {
                    $ctx->restRoute = '/' . ltrim(strtolower($q_arr['rest_route']), '/');
                }
            }
        }
        if ($ctx->restRoute === '' && ($p = strpos($ctx->cleanUri, '/wp-json')) !== false) {
            $ctx->restRoute = '/' . ltrim(substr($ctx->cleanUri, $p + 8), '/');
        }
        if (preg_match('#/wp-content/(?:plugins|themes)/([a-z0-9_-]+)#i', $ctx->cleanUri, $m)) {
            $ctx->targetSlug = strtolower($m[1]);
        }

        return $ctx;
    }

    /**
     * Push a Visual Custom Rule's edge-compatible Wirefilter expression into Cloudflare Custom Ruleset.
     *
     * @param array<string, mixed> $rule_data
     * @return array<string, mixed>
     */
    public static function push_rule_to_cloudflare_edge(array $rule_data): array {
        if (!class_exists(CloudflareService::class) || !CloudflareService::is_configured()) {
            return [
                'success' => false,
                'message' => __('Cloudflare API credentials are not configured yet.', 'webcare-pro-security'),
            ];
        }

        $settings    = SettingsManager::get_settings();
        $zone_id     = (string) ($settings['cloudflare_zone_id'] ?? '');
        $rule_id     = sanitize_text_field((string) ($rule_data['id'] ?? ('MOD-CUSTOM-' . strtoupper(wp_generate_password(6, false, false)))));
        $title       = sanitize_text_field((string) ($rule_data['title'] ?? 'Custom Firewall Rule'));
        $group_logic = strtoupper(trim((string) ($rule_data['group_logic'] ?? 'OR'))) === 'AND' ? 'AND' : 'OR';
        $groups      = self::sanitize_condition_groups($rule_data['conditions'] ?? []);
        $cf_conv     = !empty($groups)
            ? self::to_cloudflare_edge_wirefilter($groups, $group_logic)
            : [
                'expression'     => trim((string) ($rule_data['wirefilter_expr'] ?? '')),
                'partial'        => false,
                'skipped_fields' => [],
            ];

        if ($cf_conv['expression'] === '') {
            return [
                'success'        => false,
                'message'        => __('This rule relies strictly on WordPress runtime fields (user/plugin state) that cannot execute on Cloudflare Edge. It will remain enforced locally by WebCare WAF.', 'webcare-pro-security'),
                'skipped_fields' => $cf_conv['skipped_fields'],
            ];
        }

        $action_map = [
            'block'         => 'block',
            'block_and_ban' => 'block',
            'challenge_pow' => 'managed_challenge',
            'rate_limit'    => 'managed_challenge',
            'monitor'       => 'log',
            'allow'         => 'skip',
        ];
        $cf_action = $action_map[sanitize_key((string) ($rule_data['action_type'] ?? 'block'))] ?? 'block';

        $existing_res    = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        $visual_rules    = [];
        $other_rules     = [];
        $webcare_rules   = [];
        $tag_marker      = self::CF_VISUAL_TAG_PREFIX . $rule_id . ']';

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules']) && is_array($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $r) {
                $desc = (string) ($r['description'] ?? '');
                if (strpos($desc, $tag_marker) !== false) {
                    continue;
                }
                if (str_starts_with($desc, '[WebCare-WAF]') || strpos($desc, self::CF_VISUAL_TAG_PREFIX) !== false) {
                    $visual_rules[] = $r;
                } elseif (
                    strpos($desc, '[WebCare Pro') !== false ||
                    strpos($desc, '[WEBCARE-CAF:') !== false ||
                    strpos($desc, 'webcareproscan_compound_') !== false
                ) {
                    $webcare_rules[] = $r;
                } else {
                    $other_rules[] = $r;
                }
            }
        }

        $new_cf_rule = [
            'action'      => $cf_action,
            'expression'  => $cf_conv['expression'],
            'description' => '[WebCare-WAF] ' . $tag_marker . ' ' . $title,
            'enabled'     => true,
        ];
        if ($cf_action === 'skip') {
            $new_cf_rule['action_parameters'] = ['ruleset' => 'current'];
        }
        $visual_rules[] = $new_cf_rule;
        $preserved_rules = array_merge($visual_rules, $webcare_rules, $other_rules);

        $put_res = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint", 'PUT', [
            'rules' => $preserved_rules,
        ]);

        if (empty($put_res['success'])) {
            return [
                'success' => false,
                'message' => (string) ($put_res['message'] ?? __('Cloudflare Edge ruleset deployment failed.', 'webcare-pro-security')),
            ];
        }

        return [
            'success'        => true,
            'message'        => !empty($cf_conv['partial'])
                /* translators: %s: comma-separated list of WordPress-only fields evaluated locally */
                ? sprintf(__('Deployed HTTP/Network expression to Cloudflare Edge. WordPress-only fields (%s) continue enforcing locally.', 'webcare-pro-security'), implode(', ', $cf_conv['skipped_fields']))
                : __('Custom Firewall Rule deployed cleanly to Cloudflare Edge Firewall.', 'webcare-pro-security'),
            'expression'     => $cf_conv['expression'],
            'cf_action'      => $cf_action,
            'partial'        => $cf_conv['partial'],
            'skipped_fields' => $cf_conv['skipped_fields'],
        ];
    }

    /**
     * Collect normalized Custom Firewall Rules context (fields, installed plugins/themes, roles, endpoints, custom rules, Cloudflare status).
     * Shared across REST routes, MCP tools, and AI prompt generators.
     *
     * @return array<string, mixed>
     */
    public static function get_site_context_data(): array {
        $fields     = self::get_field_catalog();
        $components = [];

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (function_exists('get_plugins')) {
            $active_plugins = (array) get_option('active_plugins', []);
            $mu_plugins     = function_exists('get_mu_plugins') ? get_mu_plugins() : [];
            foreach (get_plugins() as $plugin_file => $pdata) {
                $pfile_str     = (string) $plugin_file;
                $is_dir_plugin = strpos($pfile_str, '/') !== false;
                $slug          = sanitize_key($is_dir_plugin ? explode('/', $pfile_str)[0] : basename($pfile_str, '.php'));
                if ($slug === '') {
                    continue;
                }
                $components[] = [
                    'slug'     => $slug,
                    'name'     => html_entity_decode(wp_strip_all_tags((string) ($pdata['Name'] ?? $slug)), ENT_QUOTES, 'UTF-8'),
                    'version'  => (string) ($pdata['Version'] ?? ''),
                    'type'     => 'plugin',
                    'status'   => in_array($plugin_file, $active_plugins, true) ? 'active' : 'inactive',
                    'url_path' => $is_dir_plugin ? ('/wp-content/plugins/' . $slug . '/') : ('/wp-content/plugins/' . ltrim($pfile_str, '/')),
                ];
            }
            foreach ((array) $mu_plugins as $mu_file => $mdata) {
                $slug = sanitize_key(basename((string) $mu_file, '.php'));
                if ($slug === '') {
                    continue;
                }
                $components[] = [
                    'slug'     => $slug,
                    'name'     => html_entity_decode(wp_strip_all_tags((string) ($mdata['Name'] ?? $slug)), ENT_QUOTES, 'UTF-8'),
                    'version'  => (string) ($mdata['Version'] ?? ''),
                    'type'     => 'mu-plugin',
                    'status'   => 'must-use',
                    'url_path' => '/wp-content/mu-plugins/' . basename((string) $mu_file),
                ];
            }
        }
        if (function_exists('wp_get_themes')) {
            $active_theme = get_stylesheet();
            foreach (wp_get_themes() as $stylesheet => $theme_obj) {
                $slug = sanitize_key((string) $stylesheet);
                if ($slug === '') {
                    continue;
                }
                $components[] = [
                    'slug'     => $slug,
                    'name'     => html_entity_decode(wp_strip_all_tags((string) $theme_obj->get('Name')), ENT_QUOTES, 'UTF-8'),
                    'version'  => (string) $theme_obj->get('Version'),
                    'type'     => 'theme',
                    'status'   => ($stylesheet === $active_theme) ? 'active' : 'inactive',
                    'url_path' => '/wp-content/themes/' . $slug . '/',
                ];
            }
        }

        usort($components, static function ($a, $b) {
            $a_act = ($a['status'] === 'active' || $a['status'] === 'must-use') ? 0 : 1;
            $b_act = ($b['status'] === 'active' || $b['status'] === 'must-use') ? 0 : 1;
            if ($a_act !== $b_act) {
                return $a_act <=> $b_act;
            }
            return strcasecmp((string) $a['name'], (string) $b['name']);
        });

        $roles = [];
        if (function_exists('wp_roles')) {
            $wp_r = wp_roles();
            if ($wp_r && !empty($wp_r->role_names) && is_array($wp_r->role_names)) {
                foreach ($wp_r->role_names as $r_slug => $r_label) {
                    $roles[] = [
                        'slug'  => sanitize_key((string) $r_slug),
                        'label' => translate_user_role((string) $r_label),
                    ];
                }
            }
        }

        $ajax_actions = [];
        $rest_routes  = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\BehavioralVaultManager')) {
            $ep_map = BehavioralVaultManager::read_shard(BehavioralVaultManager::SHARD_ENDPOINTS);
            if (is_array($ep_map)) {
                foreach (array_slice($ep_map, 0, 120) as $ep) {
                    if (!is_array($ep)) {
                        continue;
                    }
                    $ep_type = strtolower((string) ($ep['type'] ?? ''));
                    if ($ep_type === 'ajax' && !empty($ep['action'])) {
                        $ajax_actions[] = sanitize_text_field((string) $ep['action']);
                    } elseif ($ep_type === 'rest' && !empty($ep['route'])) {
                        $rest_routes[] = sanitize_text_field((string) $ep['route']);
                    }
                }
            }
        }

        $existing_custom_rules = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            $idx = 0;
            foreach (ModularFirewallSynthesizer::get_active_rules() as $ar) {
                if (!empty($ar['is_custom']) || ($ar['category'] ?? '') === 'custom') {
                    $idx++;
                    $existing_custom_rules[] = [
                        'id'           => (string) ($ar['id'] ?? ''),
                        'rule_number'  => (int) ($ar['rule_number'] ?? $idx),
                        'priority'     => (int) ($ar['priority'] ?? $idx),
                        'title'        => (string) ($ar['title'] ?? ($ar['id'] ?? 'Custom Rule')),
                        'action_type'  => (string) ($ar['action_type'] ?? 'block'),
                        'current_mode' => (string) ($ar['current_mode'] ?? 'enforce'),
                    ];
                }
            }
        }

        $cf_settings   = SettingsManager::get_settings();
        $cf_enabled    = !empty($cf_settings['cloudflare_enabled']);
        $cf_configured = $cf_enabled
            && class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')
            && CloudflareService::is_configured();
        $remote_peer   = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $trusted_proxy = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            && \WebCareProScanner\Firewall\FirewallEngine::is_trusted_proxy($remote_peer);
        $cf_proxied    = $trusted_proxy && (!empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']));
        $cf_zone_id    = (string) ($cf_settings['cloudflare_zone_id'] ?? '');
        $cf_zone_name  = '';
        $cf_connected  = false;
        if ($cf_configured && $cf_zone_id !== '') {
            $cf_cache_key = 'webcareproscan_cf_zone_meta_' . md5($cf_zone_id);
            $cached_zone  = get_transient($cf_cache_key);
            if (is_array($cached_zone)) {
                $cf_connected = !empty($cached_zone['connected']);
                $cf_zone_name = (string) ($cached_zone['zone_name'] ?? '');
            } else {
                $verify       = CloudflareService::verify_zone($cf_zone_id);
                $cf_connected = !empty($verify['success']);
                $cf_zone_name = (string) ($verify['zone_name'] ?? '');
                set_transient($cf_cache_key, [
                    'connected' => $cf_connected,
                    'zone_name' => $cf_zone_name,
                ], 180);
            }
        }

        return [
            'fields'                => $fields,
            'installed_components'  => $components,
            'roles'                 => $roles,
            'current_ip'            => class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : '',
            'discovered_endpoints'  => [
                'ajax_actions' => array_values(array_unique($ajax_actions)),
                'rest_routes'  => array_values(array_unique($rest_routes)),
            ],
            'custom_rules_count'    => count($existing_custom_rules),
            'existing_custom_rules' => $existing_custom_rules,
            'cloudflare_status'     => [
                'enabled'    => $cf_enabled,
                'configured' => $cf_configured,
                'connected'  => $cf_connected,
                'proxied'    => $cf_proxied,
                'zone_name'  => $cf_zone_name,
            ],
        ];
    }

    /**
     * Build a site-aware Markdown AI prompt for ChatGPT, Gemini, Claude, or built-in AIService.
     */
    public static function build_ai_markdown_prompt(string $goal = ''): string {
        $ctx   = self::get_site_context_data();
        $lines = [
            '# WebCare Pro Custom Firewall Rule Generator',
            '',
            'Generate a valid **WebCare Pro Wirefilter Expression** (or complete Rule JSON) compatible with this WordPress site\'s local origin firewall.',
            '',
            '## Security Requirements from User',
            $goal !== '' ? trim($goal) : '[Describe what traffic to block, challenge, rate-limit, monitor, or allow here]',
            '',
            '## Site Environment & Guardrails',
            '- WordPress Home: `' . home_url('/') . '`',
            '- Cloudflare Proxied Traffic (`CF-IPCountry` / `CF-IPASN` available): ' . (!empty($ctx['cloudflare_status']['proxied']) ? 'YES' : 'NO (Avoid `ip.geoip.country` / `ip.geoip.asnum` unless Cloudflare proxy is active)'),
            '- NEVER block `/wp-admin/` or `/wp-json/webcare-pro-security/` unless guarding with `not wp.user.is_logged_in`.',
            '',
            '## Allowed Fields & Operators',
        ];

        foreach ($ctx['fields'] as $f) {
            $ops = implode(', ', (array) ($f['ops'] ?? []));
            $lines[] = '- `' . $f['id'] . '` (' . $f['label'] . '): `' . $ops . '`';
        }

        if (!empty($ctx['installed_components'])) {
            $lines[] = '';
            $lines[] = '## Installed Plugins & Themes on This Site';
            foreach (array_slice($ctx['installed_components'], 0, 35) as $comp) {
                $lines[] = '- `' . $comp['slug'] . '` (' . $comp['status'] . ', v' . ($comp['version'] ?: '0') . ') -> `' . $comp['url_path'] . '`';
            }
        }

        if (!empty($ctx['roles'])) {
            $role_slugs = array_map(static fn($r) => '`' . $r['slug'] . '`', $ctx['roles']);
            $lines[] = '';
            $lines[] = '## WordPress Roles';
            $lines[] = implode(', ', $role_slugs);
        }

        if (!empty($ctx['existing_custom_rules'])) {
            $lines[] = '';
            $lines[] = '## Existing Custom Rules (Do Not Duplicate)';
            foreach (array_slice($ctx['existing_custom_rules'], 0, 20) as $er) {
                $lines[] = '- Order #' . $er['priority'] . ' (ID #' . $er['rule_number'] . '): ' . $er['title'] . ' [' . $er['action_type'] . ']';
            }
        }

        $lines = array_merge($lines, [
            '',
            '## Output Format (Choose ONE)',
            'Return either a single ```wirefilter expression block OR a complete ```json rule object:',
            '```json',
            '{',
            '  "title": "Short rule title",',
            '  "description": "Why this rule exists",',
            '  "expression": "(http.request.uri.path contains \\"/wp-content/plugins/example/\\" and not wp.user.is_logged_in)",',
            '  "action_type": "block",',
            '  "ban_ttl": 86400,',
            '  "block_uploads": true,',
            '  "placement": "last"',
            '}',
            '```',
            'Valid `action_type` values: `block`, `block_and_ban`, `rate_limit`, `challenge_pow`, `payload_inspect`, `monitor`, `allow`.',
        ]);

        return implode("\n", $lines);
    }

    /**
     * Parse raw AI output (JSON rule bundle, fenced Wirefilter block, or raw expression),
     * validate fields/operators, and emit plain-English safety lint warnings.
     *
     * @param string $raw_input
     * @return array<string, mixed>
     */
    public static function parse_ai_rule_payload(string $raw_input): array {
        $trimmed = trim($raw_input);
        if ($trimmed === '') {
            return [
                'success'          => false,
                'format'           => 'empty',
                'rule_meta'        => [],
                'conditions'       => [],
                'group_logic'      => 'OR',
                'wirefilter'       => '',
                'warnings'         => [],
                'unparsed_clauses' => [],
                'message'          => __('Please paste a Wirefilter expression or AI JSON rule first.', 'webcare-pro-security'),
            ];
        }

        $format    = 'wirefilter';
        $rule_meta = [];
        $expr_text = $trimmed;

        // Try extracting fenced JSON or raw JSON object from conversational Markdown output
        $json_candidate = $trimmed;
        if (preg_match('/```json\s*\R([\s\S]*?)\R```/i', $trimmed, $jm)) {
            $json_candidate = trim($jm[1]);
        } elseif (preg_match('/\{[\s\S]*"(?:expression|wirefilter_expr|conditions)"[\s\S]*\}/i', $trimmed, $jm)) {
            $json_candidate = trim($jm[0]);
        }

        $decoded = json_decode($json_candidate, true);
        if (is_array($decoded) && (isset($decoded['expression']) || isset($decoded['wirefilter_expr']) || isset($decoded['conditions']))) {
            $format = 'json';
            $valid_actions = ['block', 'block_and_ban', 'rate_limit', 'payload_inspect', 'challenge_pow', 'monitor', 'allow'];
            if (!empty($decoded['title'])) {
                $rule_meta['title'] = sanitize_text_field((string) $decoded['title']);
            }
            if (!empty($decoded['description'])) {
                $rule_meta['description'] = sanitize_textarea_field((string) $decoded['description']);
            }
            if (!empty($decoded['action_type']) && in_array(sanitize_key((string) $decoded['action_type']), $valid_actions, true)) {
                $rule_meta['action_type'] = sanitize_key((string) $decoded['action_type']);
            }
            if (isset($decoded['ban_ttl'])) {
                $rule_meta['ban_ttl'] = max(0, min(2592000, intval($decoded['ban_ttl'])));
            }
            if (isset($decoded['rate_limit'])) {
                $rule_meta['rate_limit'] = max(1, min(600, intval($decoded['rate_limit'])));
            }
            if (isset($decoded['block_uploads'])) {
                $rule_meta['block_uploads'] = !empty($decoded['block_uploads']);
            }
            if (!empty($decoded['placement']) && in_array($decoded['placement'], ['first', 'last', 'custom'], true)) {
                $rule_meta['placement'] = $decoded['placement'];
            }
            if (!empty($decoded['conditions']) && is_array($decoded['conditions'])) {
                $gl         = strtoupper((string) ($decoded['group_logic'] ?? 'OR')) === 'AND' ? 'AND' : 'OR';
                $conditions = self::sanitize_condition_groups($decoded['conditions']);
                $wf         = self::to_wirefilter($conditions, $gl);
                $warnings   = self::lint_rule_safety($conditions, $wf, []);
                return [
                    'success'          => !empty($conditions),
                    'format'           => 'json',
                    'rule_meta'        => $rule_meta,
                    'conditions'       => $conditions,
                    'group_logic'      => $gl,
                    'wirefilter'       => $wf,
                    'warnings'         => $warnings,
                    'unparsed_clauses' => [],
                    'message'          => !empty($conditions)
                        ? __('AI JSON rule parsed and loaded into Visual Builder.', 'webcare-pro-security')
                        : __('JSON rule lacked valid conditions.', 'webcare-pro-security'),
                ];
            }
            $expr_text = (string) ($decoded['expression'] ?? ($decoded['wirefilter_expr'] ?? ''));
        } elseif (preg_match('/```(?:wirefilter|text|txt)?\s*\R([\s\S]*?)\R```/i', $trimmed, $wm)) {
            $expr_text = trim($wm[1]);
        }

        $tree       = self::parse_wirefilter_tree($expr_text);
        $conditions = $tree['conditions'];
        $gl         = $tree['group_logic'];
        $unparsed   = $tree['unparsed_clauses'] ?? [];
        $wf         = self::to_wirefilter($conditions, $gl);
        $warnings   = self::lint_rule_safety($conditions, $wf, $unparsed);

        return [
            'success'          => !empty($conditions),
            'format'           => $format,
            'rule_meta'        => $rule_meta,
            'conditions'       => $conditions,
            'group_logic'      => $gl,
            'wirefilter'       => $wf !== '' ? $wf : self::strip_code_fences($expr_text),
            'warnings'         => $warnings,
            'unparsed_clauses' => $unparsed,
            'message'          => !empty($conditions)
                ? __('Expression parsed cleanly into Visual Builder conditions.', 'webcare-pro-security')
                : __('Could not recognize any valid fields in the pasted expression. Check field names against the 18 supported fields.', 'webcare-pro-security'),
        ];
    }

    /**
     * Evaluate structured condition groups for admin lockout risks or missing proxy dependencies.
     *
     * @param array<int, array<string, mixed>> $conditions
     * @param string $wirefilter
     * @param string[] $unparsed
     * @return string[]
     */
    public static function lint_rule_safety(array $conditions, string $wirefilter, array $unparsed = []): array {
        $warnings         = [];
        $has_geo          = false;
        $has_admin_guard  = false;
        $touches_wp_admin = false;
        $remote_peer      = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $trusted_proxy    = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            && \WebCareProScanner\Firewall\FirewallEngine::is_trusted_proxy($remote_peer);
        $cf_proxied       = $trusted_proxy && (!empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']));

        foreach ($conditions as $grp) {
            foreach (($grp['rules'] ?? []) as $r) {
                $f = (string) ($r['field'] ?? '');
                $v = strtolower((string) ($r['value'] ?? ''));
                if ($f === 'ip.geoip.country' || $f === 'ip.geoip.asnum') {
                    $has_geo = true;
                }
                if (($f === 'wp.user.is_logged_in' && ($r['op'] ?? '') === 'is_false') || ($f === 'wp.user.role' && ($r['op'] ?? '') === 'not_has' && strpos($v, 'administrator') !== false)) {
                    $has_admin_guard = true;
                }
                if ($f === 'http.request.uri.path' && (strpos($v, 'wp-admin') !== false || strpos($v, 'wp-login') !== false)) {
                    $touches_wp_admin = true;
                }
            }
        }

        if ($has_geo && !$cf_proxied) {
            $warnings[] = __('Cloudflare GeoIP headers (CF-IPCountry / CF-IPASN) are not active on this server request; Country/ASN rules will stay inert until proxied through Cloudflare.', 'webcare-pro-security');
        }
        if ($touches_wp_admin && !$has_admin_guard) {
            $warnings[] = __('Rule references /wp-admin or /wp-login without `not wp.user.is_logged_in` — consider excluding logged-in users to prevent self-lockout.', 'webcare-pro-security');
        }
        if (!empty($unparsed)) {
            $warnings[] = sprintf(
                /* translators: %s: unparsed expression clause(s) */
                __('Skipped unrecognized clause(s): %s', 'webcare-pro-security'),
                implode('; ', array_slice($unparsed, 0, 3))
            );
        }
        if ($wirefilter !== '' && strlen($wirefilter) > 4000) {
            $warnings[] = __('Expression exceeds 4,000 characters; consider simplifying clauses.', 'webcare-pro-security');
        }

        return $warnings;
    }
}
