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
                $clean_groups[] = [
                    'logic' => 'AND',
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
     * Evaluate OR-of-ANDs condition groups against a normalized RequestContext.
     *
     * @param array<int, array<string, mixed>> $groups
     * @param RequestContext $ctx
     * @return bool
     */
    public static function evaluate_groups(array $groups, RequestContext $ctx): bool {
        if (empty($groups)) {
            return false;
        }

        foreach ($groups as $group) {
            $rules = $group['rules'] ?? [];
            if (empty($rules) || !is_array($rules)) {
                continue;
            }
            $all_and_match = true;
            foreach ($rules as $cond) {
                if (!self::evaluate_single_condition($cond, $ctx)) {
                    $all_and_match = false;
                    break;
                }
            }
            if ($all_and_match) {
                return true;
            }
        }

        return false;
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
                break;
            case 'ip.geoip.asnum':
                $subject = $ctx->asn;
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
     * @return string
     */
    public static function to_wirefilter(array $groups): string {
        $group_strs = [];
        foreach ($groups as $grp) {
            $clauses = [];
            foreach (($grp['rules'] ?? []) as $cond) {
                $clause = self::condition_to_wirefilter((array) $cond);
                if ($clause !== '') {
                    $clauses[] = $clause;
                }
            }
            if (!empty($clauses)) {
                $joined = implode(' and ', $clauses);
                $group_strs[] = count($groups) > 1 ? "({$joined})" : $joined;
            }
        }
        return implode(' or ', $group_strs);
    }

    /**
     * Convert a condition tree into a strictly Cloudflare-Edge-compatible Wirefilter expression.
     *
     * @param array<int, array<string, mixed>> $groups
     * @return array{expression: string, partial: bool, skipped_fields: string[]}
     */
    public static function to_cloudflare_edge_wirefilter(array $groups): array {
        $edge_groups    = [];
        $skipped_fields = [];

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
                $joined        = implode(' and ', $clauses);
                $edge_groups[] = count($groups) > 1 ? "({$joined})" : $joined;
            }
        }

        $skipped_fields = array_values(array_unique(array_filter($skipped_fields)));
        return [
            'expression'     => implode(' or ', $edge_groups),
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
     * Parse a simple Wirefilter expression back into structured OR-of-ANDs condition groups.
     * Supports parenthesized `(a and b) or (c)` blocks, `not` prefixes, `starts_with()`, `ends_with()`, and `in {...}`.
     *
     * @param string $expr
     * @return array<int, array<string, mixed>>
     */
    public static function parse_wirefilter(string $expr): array {
        $expr = trim($expr);
        if ($expr === '') {
            return [];
        }

        // Split top-level OR groups respecting parentheses and quotes
        $or_parts = self::split_top_level($expr, 'or');
        $groups   = [];

        foreach ($or_parts as $part) {
            $part = trim($part);
            if (substr($part, 0, 1) === '(' && substr($part, -1) === ')') {
                $part = trim(substr($part, 1, -1));
            }
            $and_parts = self::split_top_level($part, 'and');
            $rules     = [];

            foreach ($and_parts as $clause) {
                $parsed = self::parse_single_wirefilter_clause(trim($clause));
                if ($parsed !== null) {
                    $rules[] = $parsed;
                }
            }
            if (!empty($rules)) {
                $groups[] = ['logic' => 'AND', 'rules' => $rules];
            }
        }

        return self::sanitize_condition_groups($groups);
    }

    /**
     * Parse a single Wirefilter predicate into ['field', 'key', 'op', 'value'].
     */
    private static function parse_single_wirefilter_clause(string $clause): ?array {
        $negated = false;
        if (preg_match('/^not\s+\((.+)\)$/i', $clause, $m)) {
            $negated = true;
            $clause  = trim($m[1]);
        } elseif (preg_match('/^not\s+([a-z0-9_.]+)$/i', $clause, $m)) {
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

        // starts_with(field, "val") / ends_with(field, "val")
        if (preg_match('/^(starts_with|ends_with)\(\s*([a-z0-9_.\[\]"\'-]+)\s*,\s*"([^"]*)"\s*\)$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[2]);
            return ['field' => $field, 'key' => $key, 'op' => strtolower($m[1]), 'value' => $m[3]];
        }

        // field in {"a" "b"}
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+in\s+\{([^}]*)\}$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            $vals = preg_replace('/["\']/', '', trim($m[2]));
            $vals = preg_replace('/\s+/', ', ', (string) $vals);
            $op = ($field === 'ip.src') ? ($negated ? 'not_in_cidr' : 'in_cidr') : ($negated ? 'not_in' : 'in');
            return ['field' => $field, 'key' => $key, 'op' => $op, 'value' => (string) $vals];
        }

        // field exists
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+exists$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            return ['field' => $field, 'key' => $key, 'op' => $negated ? 'not_exists' : 'exists', 'value' => ''];
        }

        // field op "value"
        if (preg_match('/^([a-z0-9_.\[\]"\'-]+)\s+(eq|ne|contains|matches)\s+"((?:[^"\\\\]|\\\\.)*)"$/i', $clause, $m)) {
            [$field, $key] = self::extract_field_and_key($m[1]);
            $op = strtolower($m[2]);
            if ($op === 'matches') {
                $op = 'matches_regex';
            }
            if ($negated && $op === 'contains') {
                $op = 'not_contains';
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
        $limit = max(10, min(1000, $limit));
        $groups = [];
        if (!empty($rule_data['conditions']) && is_array($rule_data['conditions'])) {
            $groups = self::sanitize_condition_groups($rule_data['conditions']);
        } elseif (!empty($rule_data['wirefilter_expr'])) {
            $groups = self::parse_wirefilter((string) $rule_data['wirefilter_expr']);
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
                $hit = self::evaluate_groups($groups, $ctx);
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
            'wirefilter'     => self::to_wirefilter($groups),
            'cf_edge'        => self::to_cloudflare_edge_wirefilter($groups),
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

        $settings = SettingsManager::get_settings();
        $zone_id  = (string) ($settings['cloudflare_zone_id'] ?? '');
        $rule_id  = sanitize_text_field((string) ($rule_data['id'] ?? ('MOD-CUSTOM-' . strtoupper(wp_generate_password(6, false, false)))));
        $title    = sanitize_text_field((string) ($rule_data['title'] ?? 'Custom Visual Rule'));
        $groups   = self::sanitize_condition_groups($rule_data['conditions'] ?? []);
        $cf_conv  = !empty($groups)
            ? self::to_cloudflare_edge_wirefilter($groups)
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
        $preserved_rules = [];
        $tag_marker      = self::CF_VISUAL_TAG_PREFIX . $rule_id . ']';

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules']) && is_array($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $r) {
                $desc = (string) ($r['description'] ?? '');
                if (strpos($desc, $tag_marker) !== false) {
                    continue;
                }
                $preserved_rules[] = $r;
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
        $preserved_rules[] = $new_cf_rule;

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
                : __('Custom Visual Rule deployed cleanly to Cloudflare Edge Firewall.', 'webcare-pro-security'),
            'expression'     => $cf_conv['expression'],
            'cf_action'      => $cf_action,
            'partial'        => $cf_conv['partial'],
            'skipped_fields' => $cf_conv['skipped_fields'],
        ];
    }
}
