<?php
declare(strict_types=1);

namespace WcpScanner\Firewall\CAF;

use WcpScanner\Cloudflare\CloudflareService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare Slot Optimizer (CAF Phase 2)
 *
 * Implements intelligent, non-destructive packing of CAF rules into Cloudflare's Free Plan WAF (5-rule quota):
 * - Slot 1: Threat List, Core Artifacts & Dormant Stack lockdown (Action: block)
 * - Slot 2: Auth brute-force challenge, comment spam & Origin Survival Mode (Action: managed_challenge)
 * - Slot 3: Priority-sorted StackGuard Virtual Patches for installed vulnerable components (Action: block)
 *
 * Enforces a strict 4,000-byte Wirefilter limit with graceful AST truncation and user rule preservation.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CloudflareSlotOptimizer {

    public const MAX_EXPRESSION_BYTES = 4000; // Safety buffer below Cloudflare Free 4096-byte limit
    public const WCP_RULE_PREFIX      = '[WCP-CAF:';
    public const WCP_LEGACY_TAG       = '[WCP Security Scanner]';

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
     * Calculate remaining slot budget for WCP-managed rules.
     * Preserves user-defined rules and claims up to min(3, max(0, 5 - count(user_rules))).
     *
     * @param array $existing_rules List of rules currently on Cloudflare
     * @return int Number of available slots (0 to 3)
     */
    public function calculate_wcp_slot_budget(array $existing_rules): int {
        $user_rules = 0;
        foreach ($existing_rules as $rule) {
            $desc = (string) ($rule['description'] ?? '');
            if (!$this->is_wcp_rule($desc)) {
                $user_rules++;
            }
        }

        return (int) min(3, max(0, 5 - $user_rules));
    }

    /**
     * Construct up to 3 optimized rule payloads based on StackSnapshot and scoped patches.
     *
     * @param StackSnapshot $snapshot Current WordPress stack snapshot
     * @param array $scoped_patches Priority-sorted virtual patches relevant to active stack
     * @param bool $has_custom_ip_list Whether Account IP List ($wcp_threat_blocklist) is active
     * @param bool $origin_survival_active Whether Origin Survival Mode is currently active
     * @param int $slot_budget Maximum slots WCP can occupy (default: 3)
     * @return array
     */
    public function pack_ruleset_expressions(
        StackSnapshot $snapshot,
        array $scoped_patches = [],
        bool $has_custom_ip_list = false,
        bool $origin_survival_active = false,
        int $slot_budget = 3
    ): array {
        if ($slot_budget <= 0) {
            return [];
        }

        $wcp_rules = [];

        // SLOT 1: Highest ROI Hard Block (Threat List + Core Sensitive Files + Dormant Stack Lockdown)
        $slot1_expr = $this->compile_slot1_block_expression($snapshot, $has_custom_ip_list);
        $wcp_rules[] = [
            'action'      => 'block',
            'description' => self::WCP_RULE_PREFIX . 'SLOT-1] Hard Block: Threat List, Core Artifacts & Dormant Stack',
            'enabled'     => true,
            'expression'  => $this->truncate_to_byte_budget($slot1_expr, self::MAX_EXPRESSION_BYTES),
        ];

        // SLOT 2: Smart Managed Challenge (Brute-Force, Spammers & Origin Survival Shield)
        if ($slot_budget >= 2) {
            $slot2_expr = $this->compile_slot2_challenge_expression($origin_survival_active);
            $wcp_rules[] = [
                'action'      => 'managed_challenge',
                'description' => self::WCP_RULE_PREFIX . 'SLOT-2] Smart Challenge: Login, Spammers & Origin Load Shield',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($slot2_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        // SLOT 3: Priority-Sorted Stack-Scoped CVE Virtual Patches
        if ($slot_budget >= 3) {
            $slot3_expr = $this->compile_slot3_virtual_patch_expression($scoped_patches);
            $wcp_rules[] = [
                'action'      => 'block',
                'description' => self::WCP_RULE_PREFIX . 'SLOT-3] StackGuard Virtual Patches & Exploit Signatures',
                'enabled'     => true,
                'expression'  => $this->truncate_to_byte_budget($slot3_expr, self::MAX_EXPRESSION_BYTES),
            ];
        }

        return $wcp_rules;
    }

    /**
     * Evaluate expression string length and truncate lowest-priority clauses safely if approaching max bytes.
     *
     * @param string $expression Raw Wirefilter expression joined by ' or '
     * @param int $max_bytes Byte limit (default: 4000)
     * @return string
     */
    public function truncate_to_byte_budget(string $expression, int $max_bytes = 4000): string {
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
                'message' => __('Cloudflare Zone ID is missing.', 'wcp-security-scanner'),
            ];
        }

        // 1. Fetch existing rules to preserve user-defined custom rules
        $existing_rules = $this->get_zone_rules($zone_id);
        $user_rules = [];

        foreach ($existing_rules as $rule) {
            $desc = (string) ($rule['description'] ?? '');
            if (!$this->is_wcp_rule($desc)) {
                $user_rules[] = $rule;
            }
        }

        // 2. Calculate slot budget (max 3 WCP slots, preserving all user rules)
        $slot_budget = (int) min(3, max(0, 5 - count($user_rules)));
        if ($slot_budget === 0) {
            return [
                'success'     => false,
                'message'     => __('All 5 Cloudflare Free Plan custom rules are occupied by user-defined rules. WCP cannot deploy edge rules without overwriting custom rules.', 'wcp-security-scanner'),
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
        if (class_exists('\\WcpScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            $sync = new CloudflareIpListSynchronizer();
            $has_custom_ip_list = ($sync->detect_api_scope() === 'account');
        }

        // 5. Build packed WCP rules
        $wcp_rules = $this->pack_ruleset_expressions(
            $snapshot,
            $scoped_patches,
            $has_custom_ip_list,
            $origin_survival_active,
            $slot_budget
        );

        // 6. Merge WCP rules + preserved user rules (WCP rules placed at top priority)
        $final_rules = array_merge($wcp_rules, $user_rules);

        $payload = [
            'rules' => $final_rules,
        ];

        $res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            $payload
        );

        if (!empty($res['success'])) {
            update_option('wcp_caf_last_cf_slot_sync', [
                'timestamp'      => time(),
                'slot_budget'    => $slot_budget,
                'wcp_rules'      => count($wcp_rules),
                'user_rules'     => count($user_rules),
                'total_rules'    => count($final_rules),
                'origin_survival'=> $origin_survival_active,
            ]);

            return [
                'success'     => true,
                'message'     => sprintf(
                    /* translators: %1$d: WCP rule count, %2$d: preserved user rule count */
                    __('Successfully synchronized %1$d WCP-managed rule(s) to Cloudflare Edge (%2$d user rule(s) safely preserved).', 'wcp-security-scanner'),
                    count($wcp_rules),
                    count($user_rules)
                ),
                'slot_budget' => $slot_budget,
                'wcp_rules'   => $wcp_rules,
                'user_rules'  => $user_rules,
            ];
        }

        $error_msg = !empty($res['errors'][0]['message']) ? $res['errors'][0]['message'] : __('Cloudflare API ruleset update rejected.', 'wcp-security-scanner');
        return [
            'success' => false,
            'message' => $error_msg,
            'errors'  => $res['errors'] ?? [],
        ];
    }

    /**
     * Compile Slot 1 expression: Hard block threat list, sensitive files, and dormant plugins.
     */
    private function compile_slot1_block_expression(StackSnapshot $snapshot, bool $has_custom_ip_list): string {
        $clauses = [];

        if ($has_custom_ip_list) {
            // Note: Wirefilter expressions in Cloudflare Rulesets reference Account IP lists by the list NAME prefixed with $
            $clauses[] = '(ip.src in $' . CloudflareIpListSynchronizer::LIST_NAME . ')';
        }

        $clauses[] = '(http.request.uri.path in {"/xmlrpc.php" "/wp-config.php" "/.env" "/.git/config" "/wp-content/debug.log"})';
        $clauses[] = '(starts_with(http.request.uri.path, "/wp-content/uploads/") and ends_with(http.request.uri.path, ".php"))';

        // Add dormant inactive plugins from snapshot
        $inactive_plugins = $snapshot->inactive_plugins;
        if (!empty($inactive_plugins) && is_array($inactive_plugins)) {
            foreach ($inactive_plugins as $plugin) {
                $slug = is_array($plugin) ? (string) ($plugin['slug'] ?? '') : (string) $plugin;
                $slug = preg_replace('/[^a-zA-Z0-9_-]/', '', $slug);
                if ($slug === '') {
                    continue;
                }

                // Strict Cloudflare Wirefilter syntax: double quotes around string literal
                $candidate = sprintf('(starts_with(http.request.uri.path, %s))', wp_json_encode("/wp-content/plugins/{$slug}/"));
                $projected = implode(' or ', array_merge($clauses, [$candidate]));
                if (strlen($projected) > self::MAX_EXPRESSION_BYTES) {
                    break; // Graceful truncation: remaining inactive plugins handled by local WAF
                }
                $clauses[] = $candidate;
            }
        }

        return implode(' or ', $clauses);
    }

    /**
     * Compile Slot 2 expression: Smart Managed Challenge for bots, spammers, and Origin Survival Mode.
     */
    private function compile_slot2_challenge_expression(bool $origin_survival_active): string {
        $clauses = [
            '(http.user_agent contains "sqlmap" or http.user_agent contains "wpscan" or http.user_agent contains "nuclei" or http.user_agent contains "nikto" or http.user_agent contains "masscan" or http.user_agent contains "python-requests")',
            '(http.request.uri.path eq "/wp-comments-post.php" and http.request.method eq "POST" and (http.referer eq "" or http.request.version eq "HTTP/1.0"))',
            '(http.request.uri.path eq "/wp-login.php" and (cf.threat_score gt 10 or not http.request.version in {"HTTP/2" "HTTP/3"}))',
        ];

        if ($origin_survival_active) {
            $clauses[] = '(http.request.uri.path eq "/wp-login.php")';
            $clauses[] = '(http.request.uri.query contains "s=" and not http.cookie contains "wordpress_logged_in_")';
        }

        return implode(' or ', $clauses);
    }

    /**
     * Compile Slot 3 expression: Stack-scoped CVE virtual patches and high-risk exploit signatures.
     */
    private function compile_slot3_virtual_patch_expression(array $active_virtual_patches): string {
        // Sort patches by priority descending so high-severity RCE/SQLi patches fit first
        usort($active_virtual_patches, static function (array $a, array $b): int {
            return ($b['priority'] ?? 0) <=> ($a['priority'] ?? 0);
        });

        $clauses = [
            '(http.request.uri.query contains "../" or http.request.uri.query contains "..%2f" or lower(http.request.uri.query) contains "union%20select" or lower(http.request.uri.query) contains "base64_decode(")',
        ];

        foreach ($active_virtual_patches as $patch) {
            $expr = trim((string) ($patch['cf_expression'] ?? ''));
            if ($expr === '') {
                continue;
            }

            $candidate = '(' . $expr . ')';
            $projected = implode(' or ', array_merge($clauses, [$candidate]));
            if (strlen($projected) > self::MAX_EXPRESSION_BYTES) {
                break;
            }
            $clauses[] = $candidate;
        }

        return implode(' or ', $clauses);
    }

    /**
     * Check if a rule description indicates a WCP-managed rule.
     */
    private function is_wcp_rule(string $description): bool {
        return str_starts_with($description, self::WCP_RULE_PREFIX) || str_starts_with($description, self::WCP_LEGACY_TAG);
    }
}
