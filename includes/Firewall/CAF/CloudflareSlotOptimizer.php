<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Cloudflare\CloudflareService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare Slot Optimizer (CAF Phase 2 - "4 + 1" Smart Cloudflare Edge System)
 *
 * Implements intelligent, non-destructive packing of WebCare Pro Edge rules into Cloudflare's Free Plan WAF (5-rule quota):
 * - Rule 1 (Action: BLOCK)             -> [WebCare Pro] Rule 1: Zero-Day Perimeter, Malicious Sinks & Threat List
 * - Rule 2 (Action: BLOCK)             -> [WebCare Pro] Rule 2: StackGuard Inactive Plugin Lockdown & Virtual Patches
 * - Rule 3 (Action: MANAGED_CHALLENGE) -> [WebCare Pro] Rule 3: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield
 * - Rule 4 (Action: BLOCK)             -> [WebCare Pro] Rule 4: Deep SQLi, LFI & Reconnaissance Armor
 * - Slot 5 (FREE / UNTOUCHED)          -> 100% Guaranteed Reserved for the Website Owner
 *
 * Enforces a strict 4,000-byte Wirefilter limit with graceful AST truncation and user rule preservation.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CloudflareSlotOptimizer {

    public const MAX_EXPRESSION_BYTES       = 4000; // Safety buffer below Cloudflare Free 4096-byte limit
    public const MAX_WEBCARE_SLOTS          = 4;    // Maximum slots WebCare can ever claim (Slot 5 is 100% reserved for owner)
    public const MAX_WCP_SLOTS              = 4;    // Backward compatibility alias
    public const WEBCARE_RULE_PREFIX        = '[WebCare Pro]';
    public const WEBCARE_RULE_TAG           = '[WebCare Pro Security]';
    public const WEBCARE_LEGACY_TAG         = '[WebCare Pro Security & Firewall]';
    public const WEBCARE_CAF_LEGACY_PREFIX  = '[WEBCARE-CAF:';

    /**
     * Fetch existing rules from Cloudflare Zone Custom Rulesets entrypoint.
     *
     * @param string $zone_id Cloudflare Zone ID
     * @return array
     */
    public function get_zone_rules(string $zone_id): array {
        if (empty($zone_id)) {
            return [];
        }

        $res = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (!empty($res['success']) && !empty($res['result']['rules']) && is_array($res['result']['rules'])) {
            return $res['result']['rules'];
        }

        return [];
    }

    /**
     * Calculate remaining slot budget for WebCare-managed rules.
     * Strictly preserves user-defined rules and guarantees 1 free slot for the website owner.
     *
     * WebCare claims at most min(4, max(0, 5 - count(user_rules))).
     *
     * @param array $existing_rules List of rules currently on Cloudflare
     * @return int Number of available slots for WebCare (0 to 4)
     */
    public function calculate_webcare_slot_budget(array $existing_rules): int {
        $user_rules = 0;
        foreach ($existing_rules as $rule) {
            $desc = (string) ($rule['description'] ?? '');
            if (!$this->is_webcare_rule($desc)) {
                $user_rules++;
            }
        }

        return (int) min(self::MAX_WEBCARE_SLOTS, max(0, 5 - $user_rules));
    }

    /**
     * Check if a rule description indicates a WebCare-managed rule.
     *
     * @param string $description
     * @return bool
     */
    public function is_webcare_rule(string $description): bool {
        return str_starts_with($description, self::WEBCARE_RULE_PREFIX)
            || str_starts_with($description, '[WebCare Pro:')
            || str_starts_with($description, self::WEBCARE_RULE_TAG)
            || str_starts_with($description, self::WEBCARE_LEGACY_TAG)
            || str_starts_with($description, self::WEBCARE_CAF_LEGACY_PREFIX)
            || str_contains($description, 'webcareproscan_compound_');
    }

    /**
     * Construct up to 4 optimized Master Compound Rules based on StackSnapshot and scoped patches.
     *
     * @param StackSnapshot $snapshot Current WordPress stack snapshot
     * @param array $scoped_patches Priority-sorted virtual patches relevant to active stack
     * @param bool $has_custom_ip_list Whether Account IP List ($webcare_threat_blocklist) is active
     * @param bool $origin_survival_active Whether Origin Survival Mode is currently active
     * @param int $slot_budget Maximum slots WebCare can occupy (capped at 4)
     * @return array
     */
    public function pack_ruleset_expressions(
        StackSnapshot $snapshot,
        array $scoped_patches = [],
        bool $has_custom_ip_list = false,
        bool $origin_survival_active = false,
        int $slot_budget = self::MAX_WEBCARE_SLOTS
    ): array {
        $budget = min(self::MAX_WEBCARE_SLOTS, max(0, $slot_budget));
        if ($budget <= 0) {
            return [];
        }

        // If scoped patches not passed, fetch automatically from VirtualPatchManager
        if (empty($scoped_patches) && class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
            $scoped_patches = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        }

        $webcare_rules = [];

        // RULE 1 (BLOCK): Zero-Day Perimeter, Malicious Sinks & Threat List
        $rule1_expr = $this->compile_rule1_perimeter_expression($has_custom_ip_list);
        $webcare_rules[] = [
            'action'      => 'block',
            'description' => self::WEBCARE_RULE_PREFIX . ' Rule 1: Zero-Day Perimeter, Malicious Sinks & Threat List',
            'enabled'     => true,
            'expression'  => $this->truncate_to_byte_budget($rule1_expr, self::MAX_EXPRESSION_BYTES),
        ];

        // RULE 2 (BLOCK): StackGuard Inactive Plugin Lockdown & Stack-Scoped CVE Virtual Patches
        if ($budget >= 2) {
            $rule2_expr = $this->compile_rule2_stackguard_expression($snapshot, $scoped_patches);
            $webcare_rules[] = [
                'action'      => 'block',
                'description' => self::WEBCARE_RULE_PREFIX . ' Rule 2: StackGuard Inactive Plugin Lockdown & Virtual Patches',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($rule2_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        // RULE 3 (MANAGED_CHALLENGE): Adaptive Bot, Brute-Force & Under-Attack Velocity Shield
        if ($budget >= 3) {
            $rule3_expr = $this->compile_rule3_bot_challenge_expression($origin_survival_active);
            $webcare_rules[] = [
                'action'      => 'managed_challenge',
                'description' => self::WEBCARE_RULE_PREFIX . ' Rule 3: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($rule3_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        // RULE 4 (BLOCK): Deep SQLi, LFI & Reconnaissance Armor
        if ($budget >= 4) {
            $rule4_expr = $this->compile_rule4_sqli_lfi_expression();
            $webcare_rules[] = [
                'action'      => 'block',
                'description' => self::WEBCARE_RULE_PREFIX . ' Rule 4: Deep SQLi, LFI & Reconnaissance Armor',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($rule4_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        return $webcare_rules;
    }

    /**
     * Evaluate expression string length and truncate lowest-priority clauses safely if approaching max bytes.
     *
     * @param string $expression Raw Wirefilter expression joined by ' or '
     * @param int $max_bytes Byte limit (default: 4000)
     * @return string
     */
    public function truncate_to_byte_budget(string $expression, int $max_bytes = self::MAX_EXPRESSION_BYTES): string {
        if (strlen($expression) <= $max_bytes) {
            return $expression;
        }

        $clauses = explode(' or ', $expression);
        $safe_clauses = [];

        foreach ($clauses as $clause) {
            $candidate = empty($safe_clauses) ? $clause : implode(' or ', array_merge($safe_clauses, [$clause]));
            if (strlen($candidate) > $max_bytes) {
                break;
            }
            $safe_clauses[] = $clause;
        }

        return !empty($safe_clauses) ? implode(' or ', $safe_clauses) : substr($expression, 0, $max_bytes);
    }

    /**
     * Executes non-destructive upsert via Cloudflare Ruleset API.
     * Strictly preserves user custom rules and guarantees 1 slot remains free for the owner.
     *
     * @param string $zone_id Cloudflare Zone ID
     * @param StackSnapshot|null $snapshot Optional snapshot; fetched automatically if omitted
     * @param array $scoped_patches Optional scoped virtual patches
     * @param bool $origin_survival_active Origin survival flag
     * @return array
     */
    public function deploy_to_cloudflare(
        string $zone_id,
        ?StackSnapshot $snapshot = null,
        array $scoped_patches = [],
        bool $origin_survival_active = false
    ): array {
        if (empty($zone_id)) {
            return [
                'success' => false,
                'message' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security'),
            ];
        }

        // 1. Fetch existing rules to preserve user-defined custom rules
        $existing_rules = $this->get_zone_rules($zone_id);
        $user_rules = [];

        foreach ($existing_rules as $rule) {
            $desc = (string) ($rule['description'] ?? '');
            if (!$this->is_webcare_rule($desc)) {
                $user_rules[] = $rule;
            }
        }

        // 2. Calculate slot budget (max 4 WebCare slots, preserving 1 slot for owner + all existing user rules)
        $slot_budget = (int) min(self::MAX_WEBCARE_SLOTS, max(0, 5 - count($user_rules)));
        if ($slot_budget === 0) {
            return [
                'success'     => false,
                'message'     => __('All 5 Cloudflare Free Plan custom rules are occupied by user-defined rules. WebCare cannot deploy edge rules without overwriting custom rules.', 'webcare-pro-security'),
                'user_rules'  => count($user_rules),
                'slot_budget' => 0,
            ];
        }

        // 3. Obtain snapshot if not provided
        if ($snapshot === null) {
            $advisor = new AdaptiveFirewallAdvisor();
            $snapshot = $advisor->get_stack_snapshot();
        }

        // 4. Check if Account Custom IP List is available
        $has_custom_ip_list = false;
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            $sync = new CloudflareIpListSynchronizer();
            $has_custom_ip_list = ($sync->detect_api_scope() === 'account');
        }

        // 5. Build packed WebCare Rules (strictly up to $slot_budget, max 4)
        $webcare_rules = $this->pack_ruleset_expressions(
            $snapshot,
            $scoped_patches,
            $has_custom_ip_list,
            $origin_survival_active,
            $slot_budget
        );

        // 6. Merge WebCare Rules + preserved user rules (WebCare Rules placed at top priority)
        $final_rules = array_merge($webcare_rules, $user_rules);

        $payload = [
            'rules' => $final_rules,
        ];

        $res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            $payload
        );

        if (!empty($res['success'])) {
            $reserved_owner_slots = max(0, 5 - count($final_rules));

            update_option('webcare_caf_last_cf_slot_sync', [
                'timestamp'             => time(),
                'slot_budget'           => $slot_budget,
                'webcare_rules'         => count($webcare_rules),
                'user_rules'            => count($user_rules),
                'total_rules'           => count($final_rules),
                'reserved_owner_slots'  => $reserved_owner_slots,
                'origin_survival'       => $origin_survival_active,
            ]);

            // Synchronize deployed edge rules cache for the Cloudflare settings tab
            $deployed_cache = [];
            foreach ($webcare_rules as $idx => $r) {
                $keys = ['compound_perimeter', 'compound_stackguard', 'compound_login_bot', 'compound_sqli_lfi'];
                $k = $keys[$idx] ?? ('rule_' . ($idx + 1));
                $deployed_cache[$k] = [
                    'id'          => $r['description'],
                    'enabled'     => true,
                    'action'      => $r['action'],
                    'description' => $r['description'],
                    'last_synced' => current_time('mysql'),
                ];
            }
            update_option(CloudflareService::DEPLOYED_RULES_OPTION, $deployed_cache);

            return [
                'success'     => true,
                'message'     => sprintf(
                    /* translators: %1$d: WebCare Rule count, %2$d: preserved user rule count, %3$d: free owner slots reserved */
                    __('Successfully synchronized %1$d WebCare Master Compound Rules to Cloudflare Edge (%2$d user rule(s) preserved, %3$d slot(s) guaranteed free for site owner).', 'webcare-pro-security'),
                    count($webcare_rules),
                    count($user_rules),
                    $reserved_owner_slots
                ),
                'slot_budget'          => $slot_budget,
                'webcare_rules'        => $webcare_rules,
                'user_rules'           => $user_rules,
                'reserved_owner_slots' => $reserved_owner_slots,
            ];
        }

        $error_msg = !empty($res['errors'][0]['message']) ? $res['errors'][0]['message'] : __('Cloudflare API ruleset update rejected.', 'webcare-pro-security');
        return [
            'success' => false,
            'message' => $error_msg,
            'errors'  => $res['errors'] ?? [],
        ];
    }

    /**
     * Compile Rule 1 expression: Zero-Day Perimeter, Malicious Sinks & Threat List.
     *
     * @param bool $has_custom_ip_list Whether Account IP list is available
     * @return string
     */
    public function compile_rule1_perimeter_expression(bool $has_custom_ip_list): string {
        $clauses = [];

        if ($has_custom_ip_list) {
            // Wirefilter Account IP List reference: $list_name
            $clauses[] = '(ip.src in $' . CloudflareIpListSynchronizer::LIST_NAME . ')';
        }

        $clauses[] = '(http.request.uri.path in {"/xmlrpc.php" "/wp-config.php" "/.env" "/.git/config" "/wp-content/debug.log"})';
        $clauses[] = '((http.request.uri.path contains "wp-content/uploads" or http.request.uri.path contains "wp-content/upgrade") and http.request.uri.path.extension in {"php" "phtml" "phar" "sh" "bash" "py" "pl" "exe" "cgi"})';
        $clauses[] = '(http.request.uri.path.extension in {"sql" "bak" "tar" "gz" "zip" "ini"})';
        $clauses[] = '(http.request.method in {"TRACE" "TRACK" "DEBUG"})';

        return implode(' or ', $clauses);
    }

    /**
     * Compile Rule 2 expression: StackGuard Inactive Plugin Lockdown & Stack-Scoped CVE Virtual Patches.
     *
     * @param StackSnapshot $snapshot Current WordPress stack snapshot
     * @param array $scoped_patches Active virtual patches
     * @return string
     */
    public function compile_rule2_stackguard_expression(StackSnapshot $snapshot, array $scoped_patches = []): string {
        $clauses = [];

        // 1. Inactive Plugin Lockdown: Block bot probes targeting dormant/deactivated plugins
        $inactive_plugins = $snapshot->inactive_plugins;
        if (!empty($inactive_plugins) && is_array($inactive_plugins)) {
            foreach ($inactive_plugins as $plugin) {
                $slug = is_array($plugin) ? (string) ($plugin['slug'] ?? '') : (string) $plugin;
                $slug = preg_replace('/[^a-zA-Z0-9_-]/', '', $slug);
                if ($slug === '') {
                    continue;
                }

                // Strict Cloudflare Wirefilter syntax: double quotes, forward slashes
                $candidate = sprintf('(starts_with(http.request.uri.path, "/wp-content/plugins/%s/"))', $slug);
                $projected = empty($clauses) ? $candidate : implode(' or ', array_merge($clauses, [$candidate]));
                if (strlen($projected) > 2400) {
                    // Reserve byte budget for CVE virtual patches
                    break;
                }
                $clauses[] = $candidate;
            }
        }

        // 2. Stack-Scoped CVE Virtual Patches
        if (empty($scoped_patches) && class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
            $scoped_patches = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        }

        if (!empty($scoped_patches)) {
            usort($scoped_patches, static function (array $a, array $b): int {
                return ($b['priority'] ?? 0) <=> ($a['priority'] ?? 0);
            });

            foreach ($scoped_patches as $patch) {
                $expr = trim((string) ($patch['cf_expression'] ?? ''));
                if ($expr === '') {
                    continue;
                }

                $candidate = '(' . $expr . ')';
                $projected = empty($clauses) ? $candidate : implode(' or ', array_merge($clauses, [$candidate]));
                if (strlen($projected) > self::MAX_EXPRESSION_BYTES) {
                    break;
                }
                $clauses[] = $candidate;
            }
        }

        if (empty($clauses)) {
            // Default baseline protection if no inactive plugins and no active patches
            $clauses[] = '((http.request.uri contains "../" or http.request.uri contains "..%2f") and http.request.uri.path contains "wp-content/plugins")';
        }

        return implode(' or ', $clauses);
    }

    /**
     * Compile Rule 3 expression: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield.
     *
     * @param bool $origin_survival_active Whether Origin Survival Mode is currently active
     * @return string
     */
    public function compile_rule3_bot_challenge_expression(bool $origin_survival_active): string {
        $has_woo = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : class_exists('WooCommerce');

        $login_paths = $has_woo
            ? '{"/wp-login.php" "/wp-register.php" "/my-account"}'
            : '{"/wp-login.php" "/wp-register.php"}';

        $clauses = [
            '((http.request.uri.path in ' . $login_paths . ') and (cf.client.bot or cf.threat_score gt 15 or not http.request.version in {"HTTP/2" "HTTP/3"}))',
            '((http.request.uri.path eq "/wp-comments-post.php") and http.request.method eq "POST" and (http.referer eq "" or http.request.version eq "HTTP/1.0" or cf.client.bot))',
            '(http.user_agent contains "sqlmap" or http.user_agent contains "wpscan" or http.user_agent contains "nuclei" or http.user_agent contains "nikto" or http.user_agent contains "masscan" or http.user_agent contains "python-requests")',
        ];

        // Origin Survival Mode dynamic escalation (Carding swarm / brute-force surge / CPU stress)
        if ($origin_survival_active) {
            $clauses[] = '(http.request.uri.path in ' . $login_paths . ')';
            $clauses[] = '(http.request.uri.query contains "s=" and not http.cookie contains "wordpress_logged_in_")';
            if ($has_woo) {
                $clauses[] = '((http.request.uri.path contains "/checkout" or http.request.uri.path contains "/cart") and cf.threat_score gt 5)';
            }
        }

        return implode(' or ', $clauses);
    }

    /**
     * Compile Rule 4 expression: Deep SQLi, LFI & Reconnaissance Armor.
     *
     * @return string
     */
    public function compile_rule4_sqli_lfi_expression(): string {
        $has_woo = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : class_exists('WooCommerce');

        $sqli_clause = '(lower(http.request.uri.query) contains "union" and lower(http.request.uri.query) contains "select") or (lower(http.request.uri.query) contains "information_schema") or (lower(http.request.uri.query) contains "sleep(" or lower(http.request.uri.query) contains "benchmark(" or lower(http.request.uri.query) contains "waitfor delay") or (lower(http.request.uri.query) contains "concat(" and lower(http.request.uri.query) contains "0x") or (lower(http.request.uri.query) contains "extractvalue(" or lower(http.request.uri.query) contains "updatexml(") or (lower(http.request.uri.query) contains " and 1=0" or lower(http.request.uri.query) contains " and 1=1" or lower(http.request.uri.query) contains "\' or 1=1" or lower(http.request.uri.query) contains "\\" or 1=1" or lower(http.request.uri.query) contains "group_concat" or lower(http.request.uri.query) contains "into outfile" or lower(http.request.uri.query) contains "into dumpfile")';

        $lfi_clause = '(http.request.uri contains "../" or http.request.uri contains "..%2f" or http.request.uri.query contains "etc/passwd" or http.request.uri.query contains "base64_decode" or http.request.uri.query contains "eval(" or http.request.uri contains "%00")';

        $user_enum_clause = '(http.request.uri.query contains "author=" or (http.request.uri.path contains "wp-json/wp/v2/users" and not http.request.uri.path contains "users/me" and not http.request.uri.query contains "context=edit" and not http.cookie contains "wordpress_logged_in"))';

        $combined = "({$sqli_clause}) or ({$lfi_clause}) or ({$user_enum_clause})";

        // WooCommerce REST API exemption: ensure /wp-json/wc/store/ is exempt from query false positives while keeping SQLi blocks strict
        if ($has_woo) {
            return '(not starts_with(http.request.uri.path, "/wp-json/wc/store/")) and (' . $combined . ')';
        }

        return $combined;
    }
}
