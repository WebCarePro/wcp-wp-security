<?php
namespace WCP\Scanner\Cloudflare;

use WCP\Scanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare Edge Defense Service
 *
 * Integrates Cloudflare v4 REST API to deploy Edge WAF rulesets, Rate Limiting,
 * IP Access block rules, and CDN cache purges directly from WordPress.
 */
class CloudflareService {

    const API_BASE = 'https://api.cloudflare.com/client/v4';
    const WCP_RULE_TAG = '[WCP Security Scanner]';

    /**
     * Send authenticated HTTP request to Cloudflare API
     *
     * @param string $endpoint
     * @param string $method
     * @param array|null $body
     * @param string|null $override_token
     * @return array
     */
    public static function request(string $endpoint, string $method = 'GET', ?array $body = null, ?string $override_token = null): array {
        $settings = SettingsManager::get_settings();
        $token = $override_token ?: ($settings['cloudflare_api_token'] ?? '');

        if (empty($token)) {
            return [
                'success' => false,
                'errors'  => [['message' => __('Cloudflare API Token is missing.', 'wcp-security-scanner')]],
            ];
        }

        $url = self::API_BASE . '/' . ltrim($endpoint, '/');
        $args = [
            'method'  => strtoupper($method),
            'timeout' => 20,
            'headers' => [
                'Authorization' => 'Bearer ' . trim($token),
                'Content-Type'  => 'application/json',
                'User-Agent'    => 'WCP-WP-Security-Scanner/' . (defined('WCP_SCANNER_VERSION') ? WCP_SCANNER_VERSION : '1.5.0'),
            ],
        ];

        if ($body !== null && in_array(strtoupper($method), ['POST', 'PUT', 'PATCH'], true)) {
            $args['body'] = wp_json_encode($body);
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'errors'  => [['message' => $response->get_error_message()]],
            ];
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw_body = wp_remote_retrieve_body($response);
        $data = json_decode($raw_body, true);

        if (!is_array($data)) {
            return [
                'success' => false,
                'errors'  => [['message' => sprintf(__('Invalid response from Cloudflare API (HTTP %d).', 'wcp-security-scanner'), $code)]],
            ];
        }

        return $data;
    }

    /**
     * Verify credentials and retrieve Zone Information
     *
     * @param string|null $zone_id
     * @param string|null $token
     * @return array
     */
    public static function verify_zone(?string $zone_id = null, ?string $token = null): array {
        $settings = SettingsManager::get_settings();
        $zid = $zone_id ?: ($settings['cloudflare_zone_id'] ?? '');

        if (empty($zid)) {
            return [
                'success' => false,
                'message' => __('Cloudflare Zone ID is required.', 'wcp-security-scanner'),
            ];
        }

        $res = self::request("zones/{$zid}", 'GET', null, $token);
        if (!empty($res['success']) && !empty($res['result'])) {
            $zone = $res['result'];
            return [
                'success'   => true,
                'zone_name' => $zone['name'] ?? '',
                'plan'      => $zone['plan']['name'] ?? 'Free',
                'status'    => $zone['status'] ?? 'active',
                'paused'    => !empty($zone['paused']),
            ];
        }

        $msg = $res['errors'][0]['message'] ?? __('Failed to verify Cloudflare Zone credentials.', 'wcp-security-scanner');
        return [
            'success' => false,
            'message' => $msg,
        ];
    }

    /**
     * Get Comprehensive Cloudflare Edge Status
     *
     * @return array
     */
    public static function get_status(): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $has_token = !empty($settings['cloudflare_api_token']);

        if (!$has_token || empty($zone_id)) {
            return [
                'configured'     => false,
                'zone_name'      => '',
                'plan'           => '',
                'active_rules'   => [],
                'rate_limiting'  => false,
                'ip_rules_count' => 0,
                'auto_sync_bans' => !empty($settings['cloudflare_auto_sync_bans']),
            ];
        }

        $verify = self::verify_zone($zone_id);
        if (!$verify['success']) {
            return [
                'configured'     => false,
                'error'          => $verify['message'],
                'auto_sync_bans' => !empty($settings['cloudflare_auto_sync_bans']),
            ];
        }

        // Fetch deployed WCP custom rules
        $active_rules = self::get_deployed_custom_rules($zone_id);
        $rate_limit = self::get_rate_limiting_status($zone_id);
        $ip_count = self::get_ip_rules_count($zone_id);

        return [
            'configured'     => true,
            'zone_name'      => $verify['zone_name'],
            'plan'           => $verify['plan'],
            'active_rules'   => $active_rules,
            'rate_limiting'  => $rate_limit,
            'ip_rules_count' => $ip_count,
            'auto_sync_bans' => !empty($settings['cloudflare_auto_sync_bans']),
        ];
    }

    /**
     * Get rule definitions for 5 Cloudflare Free Custom WAF Rules
     *
     * @return array
     */
    public static function get_rule_definitions(): array {
        return [
            'block_xmlrpc' => [
                'id'          => 'wcp_block_xmlrpc',
                'title'       => 'XML-RPC & Pingback Amplification Shield',
                'description' => 'Instantly terminates brute-force pingback and password spray attacks targeting /xmlrpc.php at the Cloudflare edge.',
                'action'      => 'block',
                'expression'  => '(http.request.uri.path contains "/xmlrpc.php")',
            ],
            'block_sensitive' => [
                'id'          => 'wcp_block_sensitive',
                'title'       => 'Sensitive Files & Dotfiles Armor',
                'description' => 'Drops automated probes seeking wp-config.php, .env, .git, and package manifests before they reach disk.',
                'action'      => 'block',
                'expression'  => '(http.request.uri.path in {"/wp-config.php" "/readme.html" "/license.txt" "/.env" "/.git" "/composer.json" "/package.json"})',
            ],
            'block_uploads_exec' => [
                'id'          => 'wcp_block_uploads_exec',
                'title'       => 'Uploads Directory Webshell Execution Trap',
                'description' => 'Stops direct HTTP execution of .php, .sh, or shell scripts disguised inside wp-content/uploads/ at the edge.',
                'action'      => 'block',
                'expression'  => '(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path matches "\\.(php[0-9]?|phtml|phar|sh|bash|py|pl|exe|cgi)$")',
            ],
            'block_author_scan' => [
                'id'          => 'wcp_block_author_scan',
                'title'       => 'Author Scan & Username Harvesting Recon Shield',
                'description' => 'Blocks bots scanning author parameter (?author=1) and enumerating usernames via public endpoints.',
                'action'      => 'block',
                'expression'  => '(http.request.uri.query contains "author=" or http.request.uri.path contains "/wp-json/wp/v2/users")',
            ],
            'challenge_wp_login' => [
                'id'          => 'wcp_challenge_wp_login',
                'title'       => 'Login Portal Threat Defense (Managed Challenge)',
                'description' => 'Triggers a non-intrusive Cloudflare Turnstile / Managed Challenge for automated bots targeting wp-login.php.',
                'action'      => 'managed_challenge',
                'expression'  => '(http.request.uri.path contains "/wp-login.php" and cf.client.bot)',
            ],
        ];
    }

    /**
     * Retrieve currently deployed WCP rules from the zone entrypoint ruleset
     *
     * @param string $zone_id
     * @return array
     */
    public static function get_deployed_custom_rules(string $zone_id): array {
        $res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (empty($res['success']) || empty($res['result']['rules'])) {
            return [];
        }

        $deployed = [];
        $rules = $res['result']['rules'];
        $definitions = self::get_rule_definitions();

        foreach ($rules as $r) {
            $desc = $r['description'] ?? '';
            foreach ($definitions as $key => $def) {
                if (strpos($desc, self::WCP_RULE_TAG) !== false && strpos($desc, $def['title']) !== false) {
                    $deployed[$key] = [
                        'id'      => $r['id'] ?? '',
                        'enabled' => !empty($r['enabled']),
                        'action'  => $r['action'] ?? $def['action'],
                    ];
                }
            }
        }

        return $deployed;
    }

    /**
     * Deploy or Update the Cloudflare Custom Ruleset
     *
     * @param array $selected_rules Associative array of rule_key => bool
     * @return array
     */
    public static function deploy_custom_rules(array $selected_rules): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id)) {
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'wcp-security-scanner')];
        }

        // 1. Fetch existing phase ruleset to avoid overwriting user's non-WCP rules
        $existing_res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        $preserved_rules = [];

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $rule) {
                $desc = $rule['description'] ?? '';
                // Keep rules that do not belong to WCP
                if (strpos($desc, self::WCP_RULE_TAG) === false) {
                    $preserved_rules[] = $rule;
                }
            }
        }

        // 2. Build newly selected WCP rules
        $definitions = self::get_rule_definitions();
        $new_wcp_rules = [];

        foreach ($definitions as $key => $def) {
            if (!empty($selected_rules[$key])) {
                $new_wcp_rules[] = [
                    'action'      => $def['action'],
                    'expression'  => $def['expression'],
                    'description' => self::WCP_RULE_TAG . ' ' . $def['title'],
                    'enabled'     => true,
                ];
            }
        }

        // Merge user non-WCP rules + WCP rules
        $all_rules = array_merge($preserved_rules, $new_wcp_rules);

        // 3. Put entrypoint ruleset
        $payload = [
            'rules' => $all_rules,
        ];

        $update_res = self::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            $payload
        );

        if (!empty($update_res['success'])) {
            return [
                'success' => true,
                'message' => sprintf(
                    __('Successfully synced %d Cloudflare Edge WAF rules.', 'wcp-security-scanner'),
                    count($new_wcp_rules)
                ),
                'active_rules' => self::get_deployed_custom_rules($zone_id),
            ];
        }

        $err = $update_res['errors'][0]['message'] ?? __('Failed to update Cloudflare Edge rules.', 'wcp-security-scanner');
        return [
            'success' => false,
            'message' => $err,
        ];
    }

    /**
     * Check if WCP rate limiting rule is active
     *
     * @param string $zone_id
     * @return bool
     */
    public static function get_rate_limiting_status(string $zone_id): bool {
        $res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint");
        if (empty($res['success']) || empty($res['result']['rules'])) {
            return false;
        }

        foreach ($res['result']['rules'] as $rule) {
            $desc = $rule['description'] ?? '';
            if (strpos($desc, self::WCP_RULE_TAG) !== false && !empty($rule['enabled'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Toggle Rate Limiting Rule on wp-login.php (10 requests / 10s per IP)
     *
     * @param bool $enable
     * @return array
     */
    public static function toggle_rate_limiting(bool $enable): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id)) {
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'wcp-security-scanner')];
        }

        $existing_res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint");
        $preserved_rules = [];

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $rule) {
                $desc = $rule['description'] ?? '';
                if (strpos($desc, self::WCP_RULE_TAG) === false) {
                    $preserved_rules[] = $rule;
                }
            }
        }

        if ($enable) {
            $preserved_rules[] = [
                'action'            => 'block',
                'expression'        => '(http.request.uri.path contains "/wp-login.php")',
                'description'       => self::WCP_RULE_TAG . ' wp-login.php Brute Force Rate Limiter',
                'enabled'           => true,
                'ratelimit'         => [
                    'characteristics'     => ['cf.unique_visitor'],
                    'period'              => 10,
                    'requests_per_period' => 10,
                    'mitigation_timeout'  => 60,
                ],
            ];
        }

        $payload = ['rules' => $preserved_rules];
        $res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint", 'PUT', $payload);

        if (!empty($res['success'])) {
            return [
                'success' => true,
                'enabled' => $enable,
                'message' => $enable
                    ? __('Cloudflare Edge Rate Limiter deployed on wp-login.php.', 'wcp-security-scanner')
                    : __('Cloudflare Edge Rate Limiter removed.', 'wcp-security-scanner'),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to configure Rate Limiting rule.', 'wcp-security-scanner');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Get count of WCP IP access rules
     *
     * @param string $zone_id
     * @return int
     */
    public static function get_ip_rules_count(string $zone_id): int {
        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules?notes=" . urlencode(self::WCP_RULE_TAG) . '&per_page=1');
        if (!empty($res['success']) && isset($res['result_info']['total_count'])) {
            return (int) $res['result_info']['total_count'];
        }
        return 0;
    }

    /**
     * Block an IP at the Cloudflare Edge via IP Access Rules
     *
     * @param string $ip
     * @param string $reason
     * @return array
     */
    public static function block_ip(string $ip, string $reason = 'Malicious activity detected by local WAF'): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return ['success' => false, 'message' => __('Cloudflare credentials not configured.', 'wcp-security-scanner')];
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['success' => false, 'message' => __('Invalid IP address.', 'wcp-security-scanner')];
        }

        $payload = [
            'mode'          => 'block',
            'configuration' => [
                'target' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6' : 'ip',
                'value'  => $ip,
            ],
            'notes'         => self::WCP_RULE_TAG . ' ' . substr($reason, 0, 70),
        ];

        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules", 'POST', $payload);

        if (!empty($res['success'])) {
            return [
                'success' => true,
                'message' => sprintf(__('IP %s successfully blocked at Cloudflare Edge.', 'wcp-security-scanner'), $ip),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to block IP at Cloudflare Edge.', 'wcp-security-scanner');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Purge Cloudflare CDN Cache
     *
     * @param array|null $files Specific URLs to purge or null for Purge Everything
     * @return array
     */
    public static function purge_cache(?array $files = null): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id)) {
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'wcp-security-scanner')];
        }

        $payload = empty($files) ? ['purge_everything' => true] : ['files' => $files];
        $res = self::request("zones/{$zone_id}/purge_cache", 'POST', $payload);

        if (!empty($res['success'])) {
            return [
                'success' => true,
                'message' => empty($files)
                    ? __('Cloudflare CDN Edge Cache purged completely.', 'wcp-security-scanner')
                    : __('Selected files purged from Cloudflare Edge Cache.', 'wcp-security-scanner'),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to purge Cloudflare cache.', 'wcp-security-scanner');
        return ['success' => false, 'message' => $err];
    }
}
