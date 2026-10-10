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
     * Extract root/apex domain from a hostname or URL
     * (e.g. dev2.miralamin.win -> miralamin.win, sub.example.co.uk -> example.co.uk)
     *
     * @param string $host
     * @return string
     */
    public static function extract_root_domain(string $host): string {
        $host = strtolower(trim($host));
        $host = preg_replace('#^https?://#i', '', $host);
        $host = explode('/', $host)[0];
        $host = explode(':', $host)[0];

        $parts = explode('.', $host);
        if (count($parts) <= 2) {
            return $host;
        }

        // Check common two-part TLDs (e.g. co.uk, com.au, org.uk, edu.bd)
        $last2 = implode('.', array_slice($parts, -2));
        $two_part_tlds = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'edu.bd', 'com.bd'];
        if (in_array($last2, $two_part_tlds, true) && count($parts) >= 3) {
            return implode('.', array_slice($parts, -3));
        }

        return implode('.', array_slice($parts, -2));
    }

    /**
     * Verify credentials and retrieve Zone Information
     * If zone_id is empty, attempts to auto-detect the zone from the current WordPress site's domain
     *
     * @param string|null $zone_id
     * @param string|null $token
     * @return array
     */
    public static function verify_zone(?string $zone_id = null, ?string $token = null): array {
        $settings = SettingsManager::get_settings();
        $zid = $zone_id ?: ($settings['cloudflare_zone_id'] ?? '');

        // If zone ID is provided directly, verify it
        if (!empty($zid)) {
            $res = self::request("zones/{$zid}", 'GET', null, $token);
            if (!empty($res['success']) && !empty($res['result'])) {
                $zone = $res['result'];
                return [
                    'success'   => true,
                    'zone_id'   => $zone['id'] ?? $zid,
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

        // If Zone ID is empty, auto-detect zone from current WordPress home URL
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
        $candidate_domain = self::extract_root_domain($site_host);

        // Fetch zones accessible by this token
        $res = self::request('zones?per_page=50', 'GET', null, $token);
        if (empty($res['success']) || !isset($res['result']) || !is_array($res['result'])) {
            $msg = $res['errors'][0]['message'] ?? __('Could not list zones. Please provide Zone ID manually.', 'wcp-security-scanner');
            return [
                'success' => false,
                'message' => $msg,
            ];
        }

        $zones = $res['result'];
        if (empty($zones)) {
            return [
                'success' => false,
                'message' => __('No accessible Cloudflare zones found for this token. Ensure your token has "Zone > Zone: Read" permissions.', 'wcp-security-scanner'),
            ];
        }

        // Find match for candidate root domain or exact site host
        $matched_zone = null;
        foreach ($zones as $z) {
            $z_name = strtolower($z['name'] ?? '');
            if ($z_name === strtolower($site_host) || $z_name === strtolower($candidate_domain)) {
                $matched_zone = $z;
                break;
            }
        }

        // If exact/root match not found, but token only has access to exactly 1 zone, use it
        if (!$matched_zone && count($zones) === 1) {
            $matched_zone = $zones[0];
        }

        if ($matched_zone) {
            return [
                'success'       => true,
                'auto_detected' => true,
                'zone_id'       => $matched_zone['id'],
                'zone_name'     => $matched_zone['name'],
                'plan'          => $matched_zone['plan']['name'] ?? 'Free',
                'status'        => $matched_zone['status'] ?? 'active',
                'paused'        => !empty($matched_zone['paused']),
            ];
        }

        // List available zones for the user to choose from
        $available_names = array_map(function($z) {
            return $z['name'] . ' (' . $z['id'] . ')';
        }, array_slice($zones, 0, 5));

        return [
            'success' => false,
            'message' => sprintf(
                __('Could not auto-match "%s". Available zones: %s. Please enter your Zone ID manually.', 'wcp-security-scanner'),
                $candidate_domain,
                implode(', ', $available_names)
            ),
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

        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
        $site_root_domain = self::extract_root_domain($site_host);

        if (!$has_token || empty($zone_id)) {
            return [
                'configured'       => false,
                'zone_name'        => '',
                'site_root_domain' => $site_root_domain,
                'plan'             => '',
                'active_rules'     => [],
                'rate_limiting'    => false,
                'ip_rules_count'   => 0,
                'auto_sync_bans'   => !empty($settings['cloudflare_auto_sync_bans']),
            ];
        }

        $verify = self::verify_zone($zone_id);
        if (!$verify['success']) {
            return [
                'configured'       => false,
                'error'            => $verify['message'],
                'site_root_domain' => $site_root_domain,
                'auto_sync_bans'   => !empty($settings['cloudflare_auto_sync_bans']),
            ];
        }

        // Fetch deployed WCP custom rules
        $active_rules = self::get_deployed_custom_rules($zone_id);
        $rate_limit = self::get_rate_limiting_status($zone_id);
        $ip_count = self::get_ip_rules_count($zone_id);

        $proxy_status = self::check_proxy_status($zone_id);

        return [
            'configured'       => true,
            'zone_id'          => $zone_id,
            'zone_name'        => $verify['zone_name'],
            'site_root_domain' => $site_root_domain,
            'has_token'        => true,
            'plan'             => $verify['plan'],
            'active_rules'     => $active_rules,
            'rate_limiting'    => $rate_limit,
            'ip_rules_count'   => $ip_count,
            'auto_sync_bans'   => !empty($settings['cloudflare_auto_sync_bans']),
            'proxy_status'     => $proxy_status,
        ];
    }

    /**
     * Check if the current WordPress site's domain / subdomain is proxied through Cloudflare (Orange Cloud)
     *
     * @param string|null $zone_id
     * @return array
     */
    public static function check_proxy_status(?string $zone_id = null): array {
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
        $is_proxied = false;
        $detection_method = 'dns_records';
        $details = '';

        // 1. First, check direct active server request headers
        $has_cf_headers = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);

        // 2. Query Cloudflare API DNS Records if zone_id is available
        if (!empty($zone_id)) {
            $dns_res = self::request("zones/{$zone_id}/dns_records?name=" . urlencode($site_host) . '&per_page=5');
            if (!empty($dns_res['success']) && isset($dns_res['result']) && is_array($dns_res['result'])) {
                foreach ($dns_res['result'] as $record) {
                    if (in_array(strtoupper($record['type'] ?? ''), ['A', 'AAAA', 'CNAME'], true)) {
                        $is_proxied = !empty($record['proxied']);
                        $detection_method = 'api_dns_record';
                        $details = sprintf(
                            __('DNS Record: %s (%s) → Proxied: %s', 'wcp-security-scanner'),
                            $record['name'] ?? $site_host,
                            $record['type'] ?? 'A',
                            $is_proxied ? 'Orange Cloud (Active)' : 'Grey Cloud (DNS Only)'
                        );
                        break;
                    }
                }
            }
        }

        // 3. Fallback to DNS resolution / CF IP Range Check if API returned no record or token lacked DNS permissions
        if ($detection_method === 'dns_records' || empty($zone_id)) {
            if ($has_cf_headers) {
                $is_proxied = true;
                $detection_method = 'server_headers';
                $details = __('Active web requests are arriving via Cloudflare Edge (CF-Ray / CF-Connecting-IP verified).', 'wcp-security-scanner');
            } else {
                // Check resolved A records of site_host
                $records = @dns_get_record($site_host, DNS_A);
                $found_cf_ip = false;
                if (!empty($records) && is_array($records)) {
                    foreach ($records as $r) {
                        $ip = $r['ip'] ?? '';
                        if (!empty($ip) && self::is_cloudflare_ip($ip)) {
                            $found_cf_ip = true;
                            break;
                        }
                    }
                }
                if ($found_cf_ip) {
                    $is_proxied = true;
                    $detection_method = 'resolved_ip_range';
                    $details = __('Site host resolves to Cloudflare Anycast IP proxy network.', 'wcp-security-scanner');
                } else {
                    $is_proxied = false;
                    $detection_method = 'resolved_ip_range';
                    $details = __('Domain DNS resolves directly to origin server (Grey Cloud / Not Proxied). Cloudflare Edge WAF rules will not intercept traffic until proxying is enabled.', 'wcp-security-scanner');
                }
            }
        }

        return [
            'is_proxied' => (bool) $is_proxied,
            'hostname'   => $site_host,
            'method'     => $detection_method,
            'details'    => $details,
        ];
    }

    /**
     * Check if an IPv4 address belongs to Cloudflare's Anycast Proxy ranges
     *
     * @param string $ip
     * @return bool
     */
    public static function is_cloudflare_ip(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $cf_ipv4_subnets = [
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '108.162.192.0/18',
            '131.0.72.0/22',
            '141.101.64.0/18',
            '162.158.0.0/15',
            '172.64.0.0/13',
            '173.245.48.0/20',
            '188.114.96.0/20',
            '190.93.240.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
        ];

        $ip_long = ip2long($ip);
        if ($ip_long === false) {
            return false;
        }

        foreach ($cf_ipv4_subnets as $cidr) {
            list($subnet, $bits) = explode('/', $cidr);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - (int) $bits);
            if (($ip_long & $mask) === ($subnet_long & $mask)) {
                return true;
            }
        }

        return false;
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
                'expression'  => '(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path.extension in {"php" "phtml" "phar" "sh" "bash" "py" "pl" "exe" "cgi"})',
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
        if (stripos($err, 'Authentication error') !== false || stripos($err, 'actor does not have permission') !== false) {
            $err .= ' ' . __('Ensure your Cloudflare API Token has "Zone > Firewall Services: Edit" permission.', 'wcp-security-scanner');
        }
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

    /**
     * Disconnect Cloudflare and wipe API token and Zone ID from database
     *
     * @return array
     */
    public static function disconnect(): array {
        SettingsManager::update_settings([
            'cloudflare_enabled'        => false,
            'cloudflare_api_token'      => '',
            'cloudflare_zone_id'        => '',
            'cloudflare_auto_sync_bans' => false,
        ]);

        return [
            'success' => true,
            'message' => __('Cloudflare disconnected and API token removed successfully.', 'wcp-security-scanner'),
        ];
    }
}
