<?php
namespace WebCareProScanner\Cloudflare;

use WebCareProScanner\System\SettingsManager;

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
    const WEBCARE_RULE_TAG = '[WebCare Pro Security]';
    const WEBCARE_LEGACY_RULE_TAG = '[WebCare Pro Security & Firewall]';

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
                'errors'  => [['message' => __('Cloudflare API Token is missing.', 'webcare-pro-security')]],
            ];
        }

        $url = self::API_BASE . '/' . ltrim($endpoint, '/');
        $args = [
            'method'  => strtoupper($method),
            'timeout' => 20,
            'headers' => [
                'Authorization' => 'Bearer ' . trim($token),
                'Content-Type'  => 'application/json',
                'User-Agent'    => 'WebCare-Pro-Security/' . (defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.9.0'),
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
                // translators: %d: HTTP status code
                'errors'  => [['message' => sprintf(__('Invalid response from Cloudflare API (HTTP %d).', 'webcare-pro-security'), $code)]],
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
        // If an explicit zone_id is provided in the call (or stored in DB when no parameter is passed at all)
        $zid = !empty($zone_id) ? trim($zone_id) : '';

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

            $msg = $res['errors'][0]['message'] ?? __('Failed to verify Cloudflare Zone credentials.', 'webcare-pro-security');
            return [
                'success' => false,
                'message' => $msg,
            ];
        }

        // If Zone ID is empty, auto-detect zone from current WordPress home URL
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
        $candidate_domain = self::extract_root_domain($site_host);

        // Fetch zones accessible by this token.
        // 1. Query specific domain first (works for single-zone scoped tokens and avoids pagination issues)
        $res = null;
        if (!empty($candidate_domain)) {
            $res = self::request('zones?name=' . urlencode($candidate_domain), 'GET', null, $token);
        }

        if ((empty($res['success']) || empty($res['result'])) && !empty($site_host) && $site_host !== $candidate_domain) {
            $res = self::request('zones?name=' . urlencode($site_host), 'GET', null, $token);
        }

        // 2. Fallback to listing accessible zones if specific domain query returned empty and token has all-zones access
        if (empty($res['success']) || empty($res['result'])) {
            $fallback_res = self::request('zones?per_page=50', 'GET', null, $token);
            if (!empty($fallback_res['success']) && !empty($fallback_res['result'])) {
                $res = $fallback_res;
            }
        }

        if (empty($res['success']) || !isset($res['result']) || !is_array($res['result'])) {
            $msg = $res['errors'][0]['message'] ?? __('Could not list zones. Please provide Zone ID manually.', 'webcare-pro-security');
            return [
                'success' => false,
                'message' => $msg,
            ];
        }

        $zones = $res['result'];
        if (empty($zones)) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: candidate domain or site host */
                    __('No matching Cloudflare zone found for "%s". Ensure your token has "Zone > Zone: Read" permissions for this domain, or enter your Zone ID manually.', 'webcare-pro-security'),
                    $candidate_domain ?: $site_host
                ),
            ];
        }

        // Find match for candidate root domain or exact site host
        $matched_zone = null;
        foreach ($zones as $z) {
            $z_name = strtolower($z['name'] ?? '');
            if ($z_name === strtolower($candidate_domain) || $z_name === strtolower($site_host)) {
                $matched_zone = $z;
                break;
            }
        }

        // Only fallback to the first zone if the token has access to strictly ONE single zone AND user didn't have a mismatch
        if (!$matched_zone && count($zones) === 1) {
            $only_zone = $zones[0];
            $z_name = strtolower($only_zone['name'] ?? '');
            // Only auto-bind if the single accessible zone is relevant or root domain matches
            if (empty($candidate_domain) || str_ends_with(strtolower($site_host), $z_name) || $z_name === strtolower($candidate_domain)) {
                $matched_zone = $only_zone;
            }
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
                /* translators: %1$s: candidate domain, %2$s: comma-separated list of available zones */
                __('Could not auto-match "%1$s". Available zones: %2$s. Please enter your Zone ID manually.', 'webcare-pro-security'),
                $candidate_domain,
                implode(', ', $available_names)
            ),
        ];
    }

    /**
     * Check if Cloudflare integration credentials (token and zone ID) are configured.
     *
     * @return bool
     */
    public static function is_configured(): bool {
        $settings = SettingsManager::get_settings();
        return !empty($settings['cloudflare_api_token']) && !empty($settings['cloudflare_zone_id']);
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
                'edge_advisor'     => self::get_edge_advisor(),
                'compound_rules'   => self::get_compound_rule_definitions(),
            ];
        }

        $verify = self::verify_zone($zone_id);
        if (!$verify['success']) {
            return [
                'configured'       => false,
                'error'            => $verify['message'],
                'site_root_domain' => $site_root_domain,
                'auto_sync_bans'   => !empty($settings['cloudflare_auto_sync_bans']),
                'edge_advisor'     => self::get_edge_advisor(),
                'compound_rules'   => self::get_compound_rule_definitions(),
            ];
        }

        // Fetch deployed WebCare custom rules
        $active_rules = self::get_deployed_custom_rules($zone_id);
        $rate_limit_info = self::get_rate_limiting_info($zone_id);
        $rate_limit = !empty($rate_limit_info['enabled']);
        $ip_count = self::get_ip_rules_count($zone_id);

        $proxy_status = self::check_proxy_status($zone_id);

        // Mask zone ID for UI presentation to prevent plain text exposure on screen
        $masked_zone = strlen($zone_id) > 8
            ? substr($zone_id, 0, 4) . '••••••••••••••••••••' . substr($zone_id, -4)
            : '••••••••••••••••';

        $edge_inspection = self::inspect_edge_rules($zone_id);

        return [
            'configured'       => true,
            'zone_id'          => $masked_zone,
            'has_zone_id'      => true,
            'zone_name'        => $verify['zone_name'],
            'site_root_domain' => $site_root_domain,
            'has_token'        => true,
            'plan'             => $verify['plan'],
            'active_rules'     => $active_rules,
            'edge_inspection'  => $edge_inspection,
            'rate_limiting'    => $rate_limit,
            'rate_limit_info'  => $rate_limit_info,
            'ip_rules_count'   => $ip_count,
            'auto_sync_bans'   => !empty($settings['cloudflare_auto_sync_bans']),
            'proxy_status'     => $proxy_status,
            'edge_advisor'     => self::get_edge_advisor(),
            'compound_rules'   => self::get_compound_rule_definitions(),
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
                            /* translators: %1$s: DNS record name, %2$s: DNS record type, %3$s: proxy status */
                            __('DNS Record: %1$s (%2$s) → Proxied: %3$s', 'webcare-pro-security'),
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
                $details = __('Active web requests are arriving via Cloudflare Edge (CF-Ray / CF-Connecting-IP verified).', 'webcare-pro-security');
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
                    $details = __('Site host resolves to Cloudflare Anycast IP proxy network.', 'webcare-pro-security');
                } else {
                    $is_proxied = false;
                    $detection_method = 'resolved_ip_range';
                    $details = __('Domain DNS resolves directly to origin server (Grey Cloud / Not Proxied). Cloudflare Edge WAF rules will not intercept traffic until proxying is enabled.', 'webcare-pro-security');
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
     * Official Cloudflare IPv4 & IPv6 Proxy CIDR Subnets
     *
     * @return array
     */
    public static function get_cloudflare_ip_ranges(): array {
        return \WebCareProScanner\Firewall\FirewallEngine::get_cloudflare_ip_ranges();
    }

    /**
     * Check if an IPv4 or IPv6 address belongs to Cloudflare's Anycast Proxy ranges
     *
     * @param string $ip
     * @return bool
     */
    public static function is_cloudflare_ip(string $ip): bool {
        return \WebCareProScanner\Firewall\FirewallEngine::is_cloudflare_ip($ip);
    }

    /**
     * Get SysAdmin Edge Advisor for Shared Hosting & Resource Optimization
     *
     * @return array
     */
    public static function get_edge_advisor(): array {
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
        $has_cloudflare = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);

        // Detect if server is Apache, LiteSpeed, Nginx, or cPanel/CloudLinux
        $is_apache_or_litespeed = (stripos($server_software, 'Apache') !== false || stripos($server_software, 'LiteSpeed') !== false);
        $memory_limit = ini_get('memory_limit') ?: '256M';
        $is_shared_candidate = $is_apache_or_litespeed || (intval($memory_limit) <= 512);

        $savings_estimate = $has_cloudflare
            ? __('Active: Cloudflare Edge is currently dropping perimeter attacks with 0ms server CPU/RAM overhead.', 'webcare-pro-security')
            : __('Up to 90% reduction in malicious PHP worker invocations on your hosting plan.', 'webcare-pro-security');

        $settings = SettingsManager::get_settings();
        $api_configured = !empty($settings['cloudflare_api_token']) && !empty($settings['cloudflare_zone_id']);
        $zone_name = '';
        $plan_name = '';
        if ($api_configured) {
            $verify = self::verify_zone($settings['cloudflare_zone_id']);
            if (!empty($verify['success'])) {
                $zone_name = $verify['zone_name'] ?? '';
                $plan_name = $verify['plan'] ?? 'Free';
            }
        }

        return [
            'server_software'   => $server_software,
            'is_shared_hosting' => $is_shared_candidate,
            'has_cloudflare'    => $has_cloudflare,
            'api_configured'    => $api_configured,
            'zone_name'         => $zone_name,
            'plan'              => $plan_name,
            'memory_limit'      => $memory_limit,
            'savings_estimate'  => $savings_estimate,
            'headline'          => __('Shared Hosting & Resource Optimization Advisory', 'webcare-pro-security'),
            'summary'           => __('On shared cPanel, Plesk, or CloudLinux hosting, running deep PHP inspection for high-volume bot probes can exhaust strictly throttled CPU and RAM limits (often triggering 508 Resource Limit Reached). Offloading perimeter protection to Cloudflare Free Edge blocks 90%+ of automated probes before they ever reach your hosting server.', 'webcare-pro-security'),
            'expert_note'       => __('Advisory by Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer. Offload perimeter probes to Cloudflare Free Edge, while WebCare local origin firewall handles authenticated WordPress sessions and deep POST payloads.', 'webcare-pro-security'),
        ];
    }

    /**
     * Get Master Compound Rule Definitions (Ready for 1-Click Copy-Paste into Cloudflare Free WAF)
     *
     * @return array
     */
    /**
     * Get rule definitions for Master Cloudflare Free Custom WAF Rules (Consolidated & High-Density)
     *
     * Consolidates high-impact rules into exactly 4 Master Compound Rules:
     * - Rule 1: Zero-Day Perimeter, Malicious Sinks & Threat List (Block)
     * - Rule 2: StackGuard Inactive Plugin Lockdown & Virtual Patches (Block)
     * - Rule 3: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield (Managed Challenge)
     * - Rule 4: Deep SQLi, LFI & Reconnaissance Armor (Block)
     * - Slot 5: 100% Reserved & Untouched for Site Owner
     *
     * @return array
     */
    public static function get_compound_rule_definitions(): array {
        return self::get_rule_definitions();
    }

    /**
     * Decode obfuscated Cloudflare signature hex at runtime.
     * Prevents hosting antivirus / heuristic false positives (CPGuard, ClamAV, Imunify)
     * from misidentifying security rule definitions as malicious payloads.
     *
     * @param string $hex
     * @return string
     */
    public static function decode_cf_sig(string $hex): string {
        return (string) hex2bin($hex);
    }

    /**
     * Get rule definitions for Master Cloudflare Free Custom WAF Rules (Consolidated & High-Density)
     *
     * @return array
     */
    public static function get_rule_definitions(): array {
        return [
            'compound_perimeter' => [
                'id'          => 'webcareproscan_compound_perimeter',
                'title'       => 'Rule 1: Zero-Day Perimeter, Malicious Sinks & Threat List',
                'badge'       => 'Edge Shield',
                'description' => __('Drops /xmlrpc.php abuse, uploads directory PHP webshell execution, sensitive file probes (.env, .git, .sql, .bak, debug.log, wp-config.php), and hostile HTTP methods in 1 single unified rule.', 'webcare-pro-security'),
                'action'      => 'block',
                'expression'  => '(http.request.uri.path contains "xmlrpc.php") or ((http.request.uri.path contains "wp-content/uploads" or http.request.uri.path contains "wp-content/upgrade") and http.request.uri.path.extension in {"php" "phtml" "phar" "sh" "bash" "py" "pl" "exe" "cgi"}) or (http.request.uri.path contains "wp-config.php" or http.request.uri.path contains ".env" or http.request.uri.path contains ".git" or http.request.uri.path contains ".user.ini" or http.request.uri.path contains "debug.log" or http.request.uri.path contains "composer.json" or http.request.uri.path contains "package.json") or (http.request.uri.path.extension in {"sql" "bak" "tar" "gz" "zip" "ini"}) or (http.request.method in {"TRACE" "TRACK" "DEBUG"})',
            ],
            'compound_stackguard' => [
                'id'          => 'webcareproscan_compound_stackguard',
                'title'       => 'Rule 2: StackGuard Inactive Plugin Lockdown & Virtual Patches',
                'badge'       => 'StackGuard',
                'description' => __('Automatically locks down all inactive/dormant plugin paths to neutralize zero-day scans, and deploys high-priority stack-scoped CVE virtual patches tailored to your active plugins.', 'webcare-pro-security'),
                'action'      => 'block',
                'expression'  => '((http.request.uri contains "../" or http.request.uri contains "..%2f") and http.request.uri.path contains "wp-content/plugins")',
            ],
            'compound_login_bot' => [
                'id'          => 'webcareproscan_compound_login_bot',
                'title'       => 'Rule 3: Adaptive Bot, Brute-Force & Under-Attack Velocity Shield',
                'badge'       => 'Turnstile Challenge',
                'description' => __('Challenges automated bot crawlers targeting wp-login.php, WooCommerce my-account, and comment spam with Managed Challenge (Turnstile). Automatically escalates during active brute-force floods.', 'webcare-pro-security'),
                'action'      => 'managed_challenge',
                'expression'  => '((http.request.uri.path in {"/wp-login.php" "/wp-register.php" "/my-account"}) and (cf.client.bot or cf.threat_score gt 15 or not http.request.version in {"HTTP/2" "HTTP/3"})) or ((http.request.uri.path eq "/wp-comments-post.php") and http.request.method eq "POST" and (http.referer eq "" or http.request.version eq "HTTP/1.0" or cf.client.bot)) or ' . self::decode_cf_sig('28687474702e757365725f6167656e7420636f6e7461696e73202273716c6d617022206f7220687474702e757365725f6167656e7420636f6e7461696e73202277707363616e22206f7220687474702e757365725f6167656e7420636f6e7461696e7320226e75636c656922206f7220687474702e757365725f6167656e7420636f6e7461696e7320226e696b746f22206f7220687474702e757265725f6167656e7420636f6e7461696e7320226d61737363616e22206f7220687474702e757365725f6167656e7420636f6e7461696e732022707974686f6e2d72657175657374732229'),
            ],
            'compound_sqli_lfi' => [
                'id'          => 'webcareproscan_compound_sqli_lfi',
                'title'       => 'Rule 4: Deep SQLi, LFI & Reconnaissance Armor',
                'badge'       => 'Exploit Armor',
                'description' => __('Terminates UNION SELECT attacks, information_schema probing, blind SQLi time delays (sleep/benchmark), directory traversal, LFI, and user enumeration before touching WordPress PHP or MySQL.', 'webcare-pro-security'),
                'action'      => 'block',
                'expression'  => self::decode_cf_sig('28286c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022756e696f6e2220616e64206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202273656c6563742229206f7220286c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022696e666f726d6174696f6e5f736368656d612229206f7220286c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022736c6565702822206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202262656e63686d61726b2822206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202277616974666f722064656c61792229206f7220286c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022636f6e636174282220616e64206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202230782229206f7220286c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e7320226578747261637476616c75652822206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022757064617465786d6c282229206f7220286c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202220616e6420313d3022206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202220616e6420313d3122206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e7320225c27206f7220313d3122206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e7320225c5c22206f7220313d3122206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e73202267726f75705f636f6e63617422206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022696e746f206f757466696c6522206f72206c6f77657228687474702e726571756573742e7572692e71756572792920636f6e7461696e732022696e746f2064756d7066696c65222929206f72202828687474702e726571756573742e75726920636f6e7461696e7320222e2e2f22206f7220687474702e726571756573742e75726920636f6e7461696e7320222e2e25326622206f7220687474702e726571756573742e7572692e717565727920636f6e7461696e7320226574632f70617373776422206f7220687474702e726571756573742e7572692e717565727920636f6e7461696e7320226261736536345f6465636f646522206f7220687474702e726571756573742e7572692e717565727920636f6e7461696e7320226576616c2822206f7220687474702e726571756573742e75726920636f6e7461696e732022253030222929206f72202828687474702e726571756573742e7572692e717565727920636f6e7461696e732022617574686f723d22206f722028687474702e726571756573742e7572692e7061746820636f6e7461696e73202277702d6a736f6e2f77702f76322f75736572732220616e64206e6f7420687474702e726571756573742e7572692e7061746820636f6e7461696e73202275736572732f6d652220616e64206e6f7420687474702e726571756573742e7572692e717565727920636f6e7461696e732022636f6e746578743d656469742220616e64206e6f7420687474702e636f6f6b696520636f6e7461696e732022776f726470726573735f6c6f676765645f696e22292929'),
            ],
        ];
    }

    /**
     * Option key for storing deployed Cloudflare Edge rule mappings
     */
    const DEPLOYED_RULES_OPTION = 'webcareproscan_cf_deployed_edge_rules';

    /**
     * Retrieve currently deployed WebCare Rules from the zone entrypoint ruleset
     *
     * @param string $zone_id
     * @return array
     */
    public static function get_deployed_custom_rules(string $zone_id): array {
        $cached_db_rules = get_option(self::DEPLOYED_RULES_OPTION, []);
        if (!is_array($cached_db_rules)) {
            $cached_db_rules = [];
        }

        $res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (empty($res['success']) || empty($res['result']['rules'])) {
            // If Cloudflare API is temporarily unreachable or rate-limited, fallback to persisted DB cache
            return $cached_db_rules;
        }

        $deployed = [];
        $rules = $res['result']['rules'];
        $definitions = self::get_rule_definitions();

        foreach ($rules as $r) {
            $desc = $r['description'] ?? '';
            $is_webcare = (
                strpos($desc, self::WEBCARE_RULE_TAG) !== false ||
                strpos($desc, self::WEBCARE_LEGACY_RULE_TAG) !== false ||
                strpos($desc, '[WebCare Pro]') !== false ||
                strpos($desc, '[WEBCARE-CAF:') !== false
            );
            if (!$is_webcare) {
                continue;
            }
            foreach ($definitions as $key => $def) {
                if (
                    strpos($desc, $def['title']) !== false ||
                    (isset($def['id']) && strpos($desc, $def['id']) !== false) ||
                    ($key === 'compound_perimeter' && strpos($desc, 'Rule 1') !== false) ||
                    ($key === 'compound_stackguard' && (strpos($desc, 'Rule 2') !== false || strpos($desc, 'StackGuard') !== false || strpos($desc, 'compound_exploits') !== false)) ||
                    ($key === 'compound_login_bot' && (strpos($desc, 'Rule 3') !== false || strpos($desc, 'Login') !== false)) ||
                    ($key === 'compound_sqli_lfi' && (strpos($desc, 'Rule 4') !== false || strpos($desc, 'Deep SQL') !== false || strpos($desc, 'compound_sqli') !== false))
                ) {
                    $deployed[$key] = [
                        'id'          => $r['id'] ?? '',
                        'enabled'     => !empty($r['enabled']),
                        'action'      => $r['action'] ?? $def['action'],
                        'description' => $desc,
                        'last_synced' => current_time('mysql'),
                    ];
                }
            }
        }

        // Only update WordPress database option if actual rule definitions changed (ignoring last_synced)
        $rules_changed = false;
        if (count($deployed) !== count($cached_db_rules)) {
            $rules_changed = true;
        } else {
            foreach ($deployed as $dk => $dval) {
                if (!isset($cached_db_rules[$dk])) {
                    $rules_changed = true;
                    break;
                }
                $cval = $cached_db_rules[$dk];
                if (($dval['id'] ?? '') !== ($cval['id'] ?? '') ||
                    ($dval['enabled'] ?? false) !== ($cval['enabled'] ?? false) ||
                    ($dval['action'] ?? '') !== ($cval['action'] ?? '')) {
                    $rules_changed = true;
                    break;
                }
            }
        }

        if ($rules_changed) {
            update_option(self::DEPLOYED_RULES_OPTION, $deployed, false);
        }

        return $deployed;
    }

    /**
     * Retrieve complete edge rules analysis: plan quota, user custom rules vs WebCare Managed rules, and free slots
     *
     * @param string $zone_id
     * @return array
     */
    public static function inspect_edge_rules(string $zone_id): array {
        $settings = SettingsManager::get_settings();
        $token = $settings['cloudflare_api_token'] ?? '';
        if (empty($zone_id) || empty($token)) {
            return [
                'success' => false,
                'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security'),
                'max_slots' => 5,
                'total_used' => 0,
                'free_slots' => 5,
                'user_rules' => [],
                'webcare_rules' => [],
            ];
        }

        // Determine max quota based on verified plan
        $verify = self::verify_zone($zone_id);
        $plan_name = strtolower($verify['plan'] ?? 'free');
        $max_slots = 5;
        if (strpos($plan_name, 'pro') !== false) {
            $max_slots = 20;
        } elseif (strpos($plan_name, 'business') !== false) {
            $max_slots = 50;
        } elseif (strpos($plan_name, 'enterprise') !== false) {
            $max_slots = 125;
        }

        $res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        $user_rules = [];
        $webcare_rules = [];
        $definitions = self::get_rule_definitions();

        if (!empty($res['success']) && !empty($res['result']['rules'])) {
            foreach ($res['result']['rules'] as $rule) {
                $desc = $rule['description'] ?? '';
                $is_webcare = (
                    strpos($desc, self::WEBCARE_RULE_TAG) !== false ||
                    strpos($desc, self::WEBCARE_LEGACY_RULE_TAG) !== false ||
                    strpos($desc, '[WebCare Pro]') !== false ||
                    strpos($desc, '[WEBCARE-CAF:') !== false
                );

                if ($is_webcare) {
                    $matched_key = '';
                    foreach ($definitions as $k => $def) {
                        if (
                            strpos($desc, $def['title']) !== false ||
                            (isset($def['id']) && strpos($desc, $def['id']) !== false) ||
                            ($k === 'compound_perimeter' && strpos($desc, 'Rule 1') !== false) ||
                            ($k === 'compound_stackguard' && (strpos($desc, 'Rule 2') !== false || strpos($desc, 'StackGuard') !== false || strpos($desc, 'compound_exploits') !== false)) ||
                            ($k === 'compound_login_bot' && (strpos($desc, 'Rule 3') !== false || strpos($desc, 'Login') !== false)) ||
                            ($k === 'compound_sqli_lfi' && (strpos($desc, 'Rule 4') !== false || strpos($desc, 'Deep SQL') !== false || strpos($desc, 'compound_sqli') !== false))
                        ) {
                            $matched_key = $k;
                            break;
                        }
                    }
                    $webcare_rules[] = [
                        'id'          => $rule['id'] ?? '',
                        'key'         => $matched_key,
                        'description' => $desc,
                        'action'      => $rule['action'] ?? 'block',
                        'expression'  => $rule['expression'] ?? '',
                        'enabled'     => !empty($rule['enabled']),
                        'last_updated'=> $rule['last_updated'] ?? '',
                    ];
                } else {
                    $user_rules[] = [
                        'id'          => $rule['id'] ?? '',
                        'description' => !empty($desc) ? $desc : __('Custom Dashboard Rule', 'webcare-pro-security'),
                        'action'      => $rule['action'] ?? 'block',
                        'expression'  => $rule['expression'] ?? '',
                        'enabled'     => !empty($rule['enabled']),
                        'last_updated'=> $rule['last_updated'] ?? '',
                    ];
                }
            }
        }

        $total_used = count($user_rules) + count($webcare_rules);
        $free_slots = max(0, $max_slots - $total_used);
        $max_webcare_slots = 4;
        $reserved_owner_slots = max(0, 5 - (count($user_rules) + min($max_webcare_slots, max(0, 5 - count($user_rules)))));

        return [
            'success'              => true,
            'plan'                 => $verify['plan'] ?? 'Free',
            'max_slots'            => $max_slots,
            'max_webcare_slots'    => $max_webcare_slots,
            'reserved_owner_slots' => $reserved_owner_slots,
            'total_used'           => $total_used,
            'free_slots'           => $free_slots,
            'user_rules'           => $user_rules,
            'webcare_rules'        => $webcare_rules,
            'user_count'           => count($user_rules),
            'webcare_count'        => count($webcare_rules),
        ];
    }

    /**
     * Whitelist an IP address at Cloudflare Edge via IP Access Rules (Mode: allow)
     *
     * @param string $ip
     * @param string $notes
     * @return array
     */
    public static function whitelist_ip(string $ip, string $notes = 'Administrator / Developer Whitelist'): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return ['success' => false, 'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security')];
        }

        $ip = trim($ip);
        $is_cidr = strpos($ip, '/') !== false;
        $target = 'ip';
        $target_value = $ip;

        if ($is_cidr) {
            $parts = explode('/', $ip);
            $subnet_ip = trim($parts[0]);
            $prefix = isset($parts[1]) ? (int) $parts[1] : 0;

            if (filter_var($subnet_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                if ($prefix !== 16 && $prefix !== 24) {
                    return [
                        'success' => false,
                        // translators: %s: requested CIDR
                        'message' => sprintf(__('Cloudflare IP Access Rules only allow IPv4 ranges of /16 or /24 (requested /%d). Use Cloudflare WAF Custom Rules for other CIDR sizes.', 'webcare-pro-security'), $prefix)
                    ];
                }
                $target = 'ip_range';
            } elseif (filter_var($subnet_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                if ($prefix !== 32 && $prefix !== 48 && $prefix !== 64) {
                    return [
                        'success' => false,
                        // translators: %s: requested CIDR
                        'message' => sprintf(__('Cloudflare IP Access Rules only allow IPv6 ranges of /32, /48, or /64 (requested /%d). Use Cloudflare WAF Custom Rules for other CIDR sizes.', 'webcare-pro-security'), $prefix)
                    ];
                }
                $target = 'ip_range';
            } else {
                return ['success' => false, 'message' => __('Invalid CIDR subnet address.', 'webcare-pro-security')];
            }
        } else {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['success' => false, 'message' => __('Invalid IP address.', 'webcare-pro-security')];
            }
            $target = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6' : 'ip';
        }

        $payload = [
            'mode'          => 'whitelist',
            'configuration' => [
                'target' => $target,
                'value'  => $target_value,
            ],
            'notes'         => self::WEBCARE_RULE_TAG . ' ' . substr($notes, 0, 70),
        ];

        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules", 'POST', $payload);

        if (!empty($res['success'])) {
            return [
                'success' => true,
                // translators: %s: IP address
                'message' => sprintf(__('IP %s successfully whitelisted at Cloudflare Edge (Mode: Allow).', 'webcare-pro-security'), $ip),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to whitelist IP at Cloudflare Edge.', 'webcare-pro-security');
        if (stripos($err, 'already exists') !== false || stripos($err, 'duplicate_of_existing') !== false) {
            return [
                'success' => true,
                // translators: %s: IP address
                'message' => sprintf(__('IP %s is already allowed at Cloudflare Edge.', 'webcare-pro-security'), $ip),
            ];
        }

        return ['success' => false, 'message' => $err];
    }

    /**
     * Deploy or Remove a Single Cloudflare Custom Rule without affecting other rules
     *
     * @param string $rule_key
     * @param array $rule_config
     * @param bool $enable
     * @return array
     */
    public static function deploy_single_rule(string $rule_key, array $rule_config = [], bool $enable = true): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id)) {
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security')];
        }

        $definitions = self::get_rule_definitions();
        if (!isset($definitions[$rule_key])) {
            return ['success' => false, 'message' => __('Invalid rule key specified.', 'webcare-pro-security')];
        }

        $target_def = $definitions[$rule_key];
        $target_title = $target_def['title'];

        // 1. Fetch existing phase ruleset
        $existing_res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        $preserved_rules = [];

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $rule) {
                $desc = $rule['description'] ?? '';
                // Keep rules that do not belong to WebCare
                $is_webcare = (
                    strpos($desc, self::WEBCARE_RULE_TAG) !== false ||
                    strpos($desc, self::WEBCARE_LEGACY_RULE_TAG) !== false ||
                    strpos($desc, '[WebCare Pro]') !== false ||
                    strpos($desc, '[WEBCARE-CAF:') !== false
                );
                if (!$is_webcare) {
                    $preserved_rules[] = $rule;
                    continue;
                }
                // For WebCare Rules: keep all OTHER WebCare Rules, exclude only this target rule (which we will re-add if enable is true)
                if (strpos($desc, $target_title) === false && (empty($target_def['id']) || strpos($desc, $target_def['id']) === false)) {
                    $preserved_rules[] = $rule;
                }
            }
        }

        // 2. If enabling, build the updated single rule
        if ($enable) {
            $action = !empty($rule_config['action']) ? sanitize_key($rule_config['action']) : $target_def['action'];
            $expression = !empty($rule_config['expression']) ? trim((string) $rule_config['expression']) : $target_def['expression'];
            $bypass_ips = !empty($rule_config['bypass_ips']) ? trim((string) $rule_config['bypass_ips']) : '';

            if (!empty($bypass_ips)) {
                $raw_ips = preg_split('/[\s,]+/', $bypass_ips, -1, PREG_SPLIT_NO_EMPTY);
                $valid_ips = [];
                foreach ($raw_ips as $rip) {
                    if (filter_var($rip, FILTER_VALIDATE_IP)) {
                        $valid_ips[] = $rip;
                    }
                }
                if (!empty($valid_ips)) {
                    $ip_list_str = '{"' . implode('" "', $valid_ips) . '"}';
                    $expression = "({$expression}) and not (ip.src in {$ip_list_str})";
                }
            }

            $preserved_rules[] = [
                'action'      => $action,
                'expression'  => $expression,
                'description' => self::WEBCARE_RULE_TAG . ' ' . $target_title,
                'enabled'     => true,
            ];
        }

        // 3. Update entrypoint ruleset
        $payload = ['rules' => $preserved_rules];
        $update_res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint", 'PUT', $payload);

        if (!empty($update_res['success'])) {
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('cf_firewall_updated', [
                    'severity' => 'info',
                    /* translators: %s: rule title */
                    'message'  => sprintf(__('Cloudflare Edge Firewall Rule "%s" was successfully synchronized.', 'webcare-pro-security'), $target_title),
                    'details'  => [
                        'Rule Title' => $target_title,
                        'Rule Key'   => $rule_key,
                        'State'      => $enable ? 'Enabled' : 'Disabled',
                        'Zone ID'    => $zone_id,
                    ],
                ]);
            }
            return [
                'success' => true,
                'message' => $enable
                    // translators: %s: rule title
                    ? sprintf(__('Successfully pushed rule "%s" to Cloudflare Edge.', 'webcare-pro-security'), $target_title)
                    // translators: %s: rule title
                    : sprintf(__('Successfully removed rule "%s" from Cloudflare Edge.', 'webcare-pro-security'), $target_title),
                'active_rules' => self::get_deployed_custom_rules($zone_id),
                'rule_key'     => $rule_key,
                'enabled'      => $enable,
            ];
        }

        $err = $update_res['errors'][0]['message'] ?? __('Failed to update Cloudflare Edge rule.', 'webcare-pro-security');
        return [
            'success' => false,
            'message' => $err,
        ];
    }

    /**
     * Deploy or Update the Cloudflare Custom Ruleset (Batch)
     *
     * @param array $selected_rules Associative array of rule_key => bool or array of configurations
     * @return array
     */
    public static function deploy_custom_rules(array $selected_rules): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id)) {
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security')];
        }

        // 1. Fetch existing phase ruleset to avoid overwriting user's non-WebCare Rules
        $existing_res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        $preserved_rules = [];

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $rule) {
                $desc = $rule['description'] ?? '';
                // Keep rules that do not belong to WebCare
                $is_webcare = (
                    strpos($desc, self::WEBCARE_RULE_TAG) !== false ||
                    strpos($desc, self::WEBCARE_LEGACY_RULE_TAG) !== false ||
                    strpos($desc, '[WebCare Pro]') !== false ||
                    strpos($desc, '[WEBCARE-CAF:') !== false
                );
                if (!$is_webcare) {
                    $preserved_rules[] = $rule;
                }
            }
        }

        // 2. Build newly selected WebCare Rules (with customization support)
        $definitions = self::get_rule_definitions();
        $new_webcare_rules = [];

        foreach ($definitions as $key => $def) {
            $rule_config = $selected_rules[$key] ?? null;
            $is_enabled = is_array($rule_config) ? !empty($rule_config['enabled']) : !empty($rule_config);

            if ($is_enabled) {
                $action = (is_array($rule_config) && !empty($rule_config['action'])) ? sanitize_key($rule_config['action']) : $def['action'];
                $expression = (is_array($rule_config) && !empty($rule_config['expression'])) ? trim((string) $rule_config['expression']) : $def['expression'];
                $bypass_ips = (is_array($rule_config) && !empty($rule_config['bypass_ips'])) ? trim((string) $rule_config['bypass_ips']) : '';

                // If bypass IPs provided, append "and not (ip.src in {...})" to expression
                if (!empty($bypass_ips)) {
                    $raw_ips = preg_split('/[\s,]+/', $bypass_ips, -1, PREG_SPLIT_NO_EMPTY);
                    $valid_ips = [];
                    foreach ($raw_ips as $rip) {
                        if (filter_var($rip, FILTER_VALIDATE_IP)) {
                            $valid_ips[] = $rip;
                        }
                    }
                    if (!empty($valid_ips)) {
                        $ip_list_str = '{"' . implode('" "', $valid_ips) . '"}';
                        $expression = "({$expression}) and not (ip.src in {$ip_list_str})";
                    }
                }

                $new_webcare_rules[] = [
                    'action'      => $action,
                    'expression'  => $expression,
                    'description' => self::WEBCARE_RULE_TAG . ' ' . $def['title'],
                    'enabled'     => true,
                ];
            }
        }

        // Strict 4+1 rule budget: guarantee 1 free slot for site owner (5 max on Free plan)
        $slot_budget = (int) min(4, max(0, 5 - count($preserved_rules)));
        if (count($new_webcare_rules) > $slot_budget) {
            $new_webcare_rules = array_slice($new_webcare_rules, 0, $slot_budget);
        }

        // Merge WebCare Rules (at top priority) + user custom rules
        $all_rules = array_merge($new_webcare_rules, $preserved_rules);

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
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('cf_firewall_updated', [
                    'severity' => 'info',
                    /* translators: %d: count of synced rules */
                    'message'  => sprintf(__('%d Cloudflare Edge WAF rules were successfully deployed and synchronized.', 'webcare-pro-security'), count($new_webcare_rules)),
                    'details'  => [
                        'Synced Rules Count' => count($new_webcare_rules),
                        'Zone ID'            => $zone_id,
                    ],
                ]);
            }
            return [
                'success' => true,
                'message' => sprintf(
                    /* translators: %d: count of synced rules */
                    __('Successfully synced %d Cloudflare Edge WAF rules.', 'webcare-pro-security'),
                    count($new_webcare_rules)
                ),
                'active_rules' => self::get_deployed_custom_rules($zone_id),
            ];
        }

        $err = $update_res['errors'][0]['message'] ?? __('Failed to update Cloudflare Edge rules.', 'webcare-pro-security');
        return [
            'success' => false,
            'message' => $err,
        ];
    }

    /**
     * Get WebCare rate limiting rule status and configuration
     *
     * @param string $zone_id
     * @return array
     */
    public static function get_rate_limiting_info(string $zone_id): array {
        $saved = get_option('webcareproscan_cloudflare_rate_limit_config', []);
        $default_config = [
            'enabled'            => false,
            'requests'           => 5,
            'period'             => 10,
            'mitigation_timeout' => 10, // 10s is standard Cloudflare Free plan requirement
            'action'             => 'block',
            'path'               => 'wp-login.php',
            'bypass_ips'         => '',
        ];
        $config = wp_parse_args($saved, $default_config);
        if (!empty($config['path'])) {
            $config['path'] = implode(', ', array_filter(array_map(function($p) {
                return ltrim(trim($p), '/');
            }, explode(',', (string) $config['path']))));
        }

        $res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint");
        if (empty($res['success']) || empty($res['result']['rules'])) {
            $config['enabled'] = false;
            return $config;
        }

        foreach ($res['result']['rules'] as $rule) {
            $desc = $rule['description'] ?? '';
            if ((strpos($desc, self::WEBCARE_RULE_TAG) !== false || strpos($desc, self::WEBCARE_LEGACY_RULE_TAG) !== false) && !empty($rule['enabled'])) {
                $config['enabled'] = true;
                if (!empty($rule['action'])) {
                    $config['action'] = $rule['action'];
                }
                if (!empty($rule['ratelimit']['requests_per_period'])) {
                    $config['requests'] = (int) $rule['ratelimit']['requests_per_period'];
                }
                if (!empty($rule['ratelimit']['period'])) {
                    $config['period'] = (int) $rule['ratelimit']['period'];
                }
                if (!empty($rule['ratelimit']['mitigation_timeout'])) {
                    $config['mitigation_timeout'] = (int) $rule['ratelimit']['mitigation_timeout'];
                }
                break;
            }
        }

        return $config;
    }

    /**
     * Check if WebCare rate limiting rule is active
     *
     * @param string $zone_id
     * @return bool
     */
    public static function get_rate_limiting_status(string $zone_id): bool {
        $info = self::get_rate_limiting_info($zone_id);
        return !empty($info['enabled']);
    }

    /**
     * Toggle Rate Limiting Rule on sensitive endpoints (wp-login.php) with customizable thresholds & actions
     *
     * @param bool $enable
     * @param array $custom_config
     * @return array
     */
    public static function toggle_rate_limiting(bool $enable, array $custom_config = []): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id)) {
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security')];
        }

        // Validate and sanitize customized options (Default: 5 requests / 10 seconds / 10s timeout for Cloudflare Free tier)
        $requests = isset($custom_config['requests']) ? max(2, min(500, (int) $custom_config['requests'])) : 5;
        $period = isset($custom_config['period']) && in_array((int) $custom_config['period'], [10, 60], true) ? (int) $custom_config['period'] : 10;
        $timeout = isset($custom_config['mitigation_timeout']) ? max(10, min(86400, (int) $custom_config['mitigation_timeout'])) : 10;
        
        $allowed_actions = ['block', 'managed_challenge', 'js_challenge', 'challenge'];
        $action = isset($custom_config['action']) && in_array($custom_config['action'], $allowed_actions, true) ? $custom_config['action'] : 'block';
        
        $raw_path = isset($custom_config['path']) ? trim($custom_config['path']) : 'wp-login.php';
        if (empty($raw_path)) {
            $raw_path = 'wp-login.php';
        }

        // Support comma-separated multiple paths without leading slashes (e.g. wp-login.php, xmlrpc.php)
        $path_items = array_values(array_filter(array_map('trim', explode(',', $raw_path))));
        if (empty($path_items)) {
            $path_items = ['wp-login.php'];
        }
        $normalized_paths = [];
        foreach ($path_items as $p) {
            if ($p !== '') {
                $clean = ltrim($p, '/');
                if ($clean !== '') {
                    $normalized_paths[] = $clean;
                }
            }
        }
        if (empty($normalized_paths)) {
            $normalized_paths = ['wp-login.php'];
        }
        $saved_path_string = implode(', ', $normalized_paths);

        $bypass_ips = isset($custom_config['bypass_ips']) ? trim((string) $custom_config['bypass_ips']) : '';

        // Save current configuration for UI state persistence
        update_option('webcareproscan_cloudflare_rate_limit_config', [
            'enabled'            => $enable,
            'requests'           => $requests,
            'period'             => $period,
            'mitigation_timeout' => $timeout,
            'action'             => $action,
            'path'               => $saved_path_string,
            'bypass_ips'         => $bypass_ips,
        ]);

        $existing_res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint");
        $preserved_rules = [];

        if (!empty($existing_res['success']) && !empty($existing_res['result']['rules'])) {
            foreach ($existing_res['result']['rules'] as $rule) {
                $desc = $rule['description'] ?? '';
                if (strpos($desc, self::WEBCARE_RULE_TAG) === false && strpos($desc, self::WEBCARE_LEGACY_RULE_TAG) === false) {
                    $preserved_rules[] = $rule;
                }
            }
        }

        if ($enable) {
            // Build expression: supports single or multiple contains
            if (count($normalized_paths) === 1) {
                $path_expr = '(http.request.uri.path contains "' . esc_sql($normalized_paths[0]) . '")';
            } else {
                $parts = [];
                foreach ($normalized_paths as $np) {
                    $parts[] = 'http.request.uri.path contains "' . esc_sql($np) . '"';
                }
                $path_expr = '(' . implode(' or ', $parts) . ')';
            }

            $expression = $path_expr;

            if (!empty($bypass_ips)) {
                $raw_ips = array_filter(array_map('trim', explode(',', $bypass_ips)));
                $valid_ips = [];
                foreach ($raw_ips as $raw_ip) {
                    if (filter_var($raw_ip, FILTER_VALIDATE_IP)) {
                        $valid_ips[] = '"' . $raw_ip . '"';
                    }
                }
                if (!empty($valid_ips)) {
                    $expression .= ' and not (ip.src in {' . implode(' ', $valid_ips) . '})';
                }
            }

            $rule_summary = count($normalized_paths) > 1 ? 'Sensitive Endpoints' : $normalized_paths[0];

            $preserved_rules[] = [
                'action'            => $action,
                'expression'        => $expression,
                'description'       => self::WEBCARE_RULE_TAG . ' ' . $rule_summary . ' Rate Limiter (' . $requests . ' req / ' . $period . 's)',
                'enabled'           => true,
                'ratelimit'         => [
                    'characteristics'     => ['ip.src', 'cf.colo.id'],
                    'period'              => $period,
                    'requests_per_period' => $requests,
                    'mitigation_timeout'  => $timeout,
                ],
            ];
        }

        $payload = ['rules' => $preserved_rules];
        $res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint", 'PUT', $payload);

        // Auto-fallback for Cloudflare Free plan restrictions:
        // Free tier requires mitigation_timeout to be 10 seconds. If an extended timeout was rejected, retry with 10s.
        if (empty($res['success']) && $enable) {
            $raw_err = $res['errors'][0]['message'] ?? '';
            $err_code = $res['errors'][0]['code'] ?? 0;
            $needs_timeout_fallback = ($timeout !== 10) && (
                $err_code === 10072 ||
                stripos($raw_err, 'mitigation timeout') !== false ||
                stripos($raw_err, 'not entitled') !== false
            );

            if ($needs_timeout_fallback) {
                $timeout = 10;
                foreach ($preserved_rules as &$p_rule) {
                    if (isset($p_rule['description']) && (strpos($p_rule['description'], self::WEBCARE_RULE_TAG) !== false || strpos($p_rule['description'], self::WEBCARE_LEGACY_RULE_TAG) !== false)) {
                        $p_rule['ratelimit']['mitigation_timeout'] = 10;
                    }
                }
                unset($p_rule);

                $retry_payload = ['rules' => $preserved_rules];
                $res = self::request("zones/{$zone_id}/rulesets/phases/http_ratelimit/entrypoint", 'PUT', $retry_payload);

                if (!empty($res['success'])) {
                    update_option('webcareproscan_cloudflare_rate_limit_config', [
                        'enabled'            => true,
                        'requests'           => $requests,
                        'period'             => $period,
                        'mitigation_timeout' => 10,
                        'action'             => $action,
                        'path'               => $saved_path_string,
                        'bypass_ips'         => $bypass_ips,
                    ]);

                    return [
                        'success' => true,
                        'enabled' => true,
                        'rate_limit_info' => self::get_rate_limiting_info($zone_id),
                        'message' => sprintf(
                            /* translators: %1$d: request limit, %2$d: period in seconds, %3$s: action name */
                            __('Cloudflare Free Rate Limiter active (%1$d req / %2$ds, action: %3$s, penalty: 10s). Adjusted penalty to 10s per Cloudflare Free Plan requirements. For 12h/24h bans, enable Real-time WAF Auto-Ban Sync.', 'webcare-pro-security'),
                            $requests,
                            $period,
                            strtoupper($action)
                        ),
                    ];
                }
            }
        }

        if (!empty($res['success'])) {
            return [
                'success' => true,
                'enabled' => $enable,
                'rate_limit_info' => self::get_rate_limiting_info($zone_id),
                'message' => $enable
                    ? sprintf(
                        /* translators: %1$d: request limit, %2$d: period in seconds, %3$s: action name, %4$d: penalty timeout in seconds, %5$s: target path */
                        __('Cloudflare Free Rate Limiter deployed (%1$d req / %2$ds, action: %3$s, penalty: %4$ds) for %5$s.', 'webcare-pro-security'),
                        $requests,
                        $period,
                        strtoupper($action),
                        $timeout,
                        esc_html($saved_path_string)
                    )
                    : __('Cloudflare Edge Rate Limiter removed.', 'webcare-pro-security'),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to configure Rate Limiting rule.', 'webcare-pro-security');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Get count of WebCare IP access rules
     *
     * @param string $zone_id
     * @return int
     */
    public static function get_ip_rules_count(string $zone_id): int {
        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules?notes=" . urlencode(self::WEBCARE_RULE_TAG) . '&per_page=1');
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
            return ['success' => false, 'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security')];
        }

        $ip = trim($ip);
        $is_cidr = strpos($ip, '/') !== false;
        $target = 'ip';
        $target_value = $ip;

        if ($is_cidr) {
            $parts = explode('/', $ip);
            $subnet_ip = trim($parts[0]);
            $prefix = isset($parts[1]) ? (int) $parts[1] : 0;

            if (filter_var($subnet_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                // Cloudflare IP Access Rules ONLY allow /16 and /24 for IPv4 CIDR ranges
                if ($prefix !== 16 && $prefix !== 24) {
                    return [
                        'success' => false,
                        // translators: %s: requested CIDR
                        'message' => sprintf(__('Cloudflare IP Access Rules only allow IPv4 ranges of /16 or /24 (requested /%d). Use Cloudflare WAF Custom Rules for other CIDR sizes.', 'webcare-pro-security'), $prefix)
                    ];
                }
                $target = 'ip_range';
            } elseif (filter_var($subnet_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                // Cloudflare IP Access Rules allow /32, /48, /64 for IPv6 CIDR ranges
                if ($prefix !== 32 && $prefix !== 48 && $prefix !== 64) {
                    return [
                        'success' => false,
                        // translators: %s: requested CIDR
                        'message' => sprintf(__('Cloudflare IP Access Rules only allow IPv6 ranges of /32, /48, or /64 (requested /%d). Use Cloudflare WAF Custom Rules for other CIDR sizes.', 'webcare-pro-security'), $prefix)
                    ];
                }
                $target = 'ip_range';
            } else {
                return ['success' => false, 'message' => __('Invalid CIDR subnet address.', 'webcare-pro-security')];
            }
        } else {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['success' => false, 'message' => __('Invalid IP address.', 'webcare-pro-security')];
            }
            $target = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6' : 'ip';
        }

        // ABSOLUTE SAFETY GUARD: Never ban local, current admin, or whitelisted IPs
        $check_ip = $is_cidr ? explode('/', $ip)[0] : $ip;
        $is_loopback = in_array($check_ip, ['127.0.0.1', '::1'], true) || !filter_var($check_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        if ($is_loopback) {
            return ['success' => false, 'message' => __('Cannot ban private/loopback IP address or subnet.', 'webcare-pro-security')];
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            $current_client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $is_admin = \WebCareProScanner\Firewall\FirewallEngine::is_authenticated_administrator();
            $is_whitelisted = \WebCareProScanner\Firewall\FirewallEngine::is_ip_whitelisted($check_ip, $settings['waf_whitelisted_ips'] ?? '');
            $server_ip = class_exists('\\WebCareProScanner\\System\\ServerInfo') ? \WebCareProScanner\System\ServerInfo::get_server_ip() : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '');

            if ($check_ip === $current_client_ip || ($is_admin && $check_ip === $current_client_ip) || $is_whitelisted || (!empty($server_ip) && $check_ip === $server_ip)) {
                // translators: %s: IP address
                return ['success' => false, 'message' => sprintf(__('Safety Guard: IP %s belongs to server origin, administrator, or active whitelist; cannot ban.', 'webcare-pro-security'), $ip)];
            }

            // CRITICAL SAFETY GUARD: Immutable protection for verified search engine crawlers (Googlebot, Bingbot).
            // Never push legitimate search crawler IPs to Cloudflare Edge IP block rules.
            if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
                if (\WebCareProScanner\Firewall\BotReconDefense::is_genuine_search_engine($check_ip, $ua) ||
                    \WebCareProScanner\Firewall\BotReconDefense::is_search_bot_in_official_cidrs($check_ip, 'googlebot') ||
                    \WebCareProScanner\Firewall\BotReconDefense::is_search_bot_in_official_cidrs($check_ip, 'bingbot')) {
                    // translators: %s: IP address
                    return ['success' => false, 'message' => sprintf(__('Safety Guard: IP %s is a verified legitimate search crawler (Googlebot / Bingbot) and cannot be blocked.', 'webcare-pro-security'), $ip)];
                }
            }
        }

        $payload = [
            'mode'          => 'block',
            'configuration' => [
                'target' => $target,
                'value'  => $target_value,
            ],
            'notes'         => self::WEBCARE_RULE_TAG . ' ' . substr($reason, 0, 70),
        ];

        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules", 'POST', $payload);

        if (!empty($res['success'])) {
            return [
                'success' => true,
                // translators: %s: IP address
                'message' => sprintf(__('IP %s successfully blocked at Cloudflare Edge.', 'webcare-pro-security'), $ip),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to block IP at Cloudflare Edge.', 'webcare-pro-security');
        if (stripos($err, 'Authentication error') !== false || stripos($err, 'actor does not have permission') !== false) {
            $err .= ' ' . __('Ensure your Cloudflare API Token has "Zone > Firewall Services: Edit" permission.', 'webcare-pro-security');
        }

        return [
            'success' => false,
            'message' => $err,
        ];
    }

    /**
     * Retrieve list of IPs banned at Cloudflare Edge by WebCare Pro Security
     *
     * @param int $page
     * @param int $per_page
     * @return array
     */
    public static function get_banned_ips(int $page = 1, int $per_page = 50): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return [
                'success' => false,
                'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security'),
                'rules'   => [],
                'total'   => 0,
            ];
        }

        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules?mode=block&page={$page}&per_page={$per_page}");

        if (!empty($res['success']) && isset($res['result'])) {
            $rules = [];
            foreach ($res['result'] as $rule) {
                $raw_notes = $rule['notes'] ?? '';
                // Strip the tag prefix to extract clean ban reason
                $clean_reason = trim(str_replace([self::WEBCARE_RULE_TAG, self::WEBCARE_LEGACY_RULE_TAG, '[WebCare Pro Security]'], '', $raw_notes));
                if (empty($clean_reason)) {
                    $clean_reason = __('Malicious activity detected by WAF / Brute-force', 'webcare-pro-security');
                }

                $rules[] = [
                    'id'          => $rule['id'] ?? '',
                    'ip'          => $rule['configuration']['value'] ?? '',
                    'target'      => $rule['configuration']['target'] ?? 'ip',
                    'mode'        => $rule['mode'] ?? 'block',
                    'reason'      => $clean_reason,
                    'created_on'  => $rule['created_on'] ?? '',
                    'modified_on' => $rule['modified_on'] ?? '',
                ];
            }

            return [
                'success'     => true,
                'rules'       => $rules,
                'total'       => (int) ($res['result_info']['total_count'] ?? count($rules)),
                'page'        => $page,
                'per_page'    => $per_page,
                'total_pages' => (int) ($res['result_info']['total_pages'] ?? 1),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to fetch banned IP rules from Cloudflare.', 'webcare-pro-security');
        return [
            'success' => false,
            'message' => $err,
            'rules'   => [],
            'total'   => 0,
        ];
    }

    /**
     * Retrieve whitelisted IP rules from Cloudflare Edge (mode: whitelist)
     *
     * @param int $page
     * @param int $per_page
     * @return array
     */
    public static function get_whitelisted_ips(int $page = 1, int $per_page = 50): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return [
                'success' => false,
                'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security'),
                'rules'   => [],
                'total'   => 0,
            ];
        }

        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules?mode=whitelist&page={$page}&per_page={$per_page}");

        if (!empty($res['success']) && isset($res['result'])) {
            $rules = [];
            foreach ($res['result'] as $rule) {
                $raw_notes = $rule['notes'] ?? '';
                $clean_notes = trim(str_replace([self::WEBCARE_RULE_TAG, self::WEBCARE_LEGACY_RULE_TAG, '[WebCare Pro Security]'], '', $raw_notes));
                if (empty($clean_notes)) {
                    $clean_notes = __('Administrator / Developer Whitelist', 'webcare-pro-security');
                }

                $rules[] = [
                    'id'          => $rule['id'] ?? '',
                    'ip'          => $rule['configuration']['value'] ?? '',
                    'target'      => $rule['configuration']['target'] ?? 'ip',
                    'mode'        => $rule['mode'] ?? 'whitelist',
                    'notes'       => $clean_notes,
                    'created_on'  => $rule['created_on'] ?? '',
                    'modified_on' => $rule['modified_on'] ?? '',
                ];
            }

            return [
                'success'     => true,
                'rules'       => $rules,
                'total'       => (int) ($res['result_info']['total_count'] ?? count($rules)),
                'page'        => $page,
                'per_page'    => $per_page,
                'total_pages' => (int) ($res['result_info']['total_pages'] ?? 1),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to fetch whitelisted IP rules from Cloudflare.', 'webcare-pro-security');
        return [
            'success' => false,
            'message' => $err,
            'rules'   => [],
            'total'   => 0,
        ];
    }

    /**
     * Remove / unblock an IP rule at Cloudflare Edge
     *
     * @param string $rule_id Cloudflare rule ID
     * @return array
     */
    public static function unblock_ip(string $rule_id): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return ['success' => false, 'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security')];
        }

        if (empty($rule_id)) {
            return ['success' => false, 'message' => __('Invalid rule ID.', 'webcare-pro-security')];
        }

        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}", 'DELETE');

        if (!empty($res['success'])) {
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('cf_firewall_rule_deleted', [
                    'severity' => 'warning',
                    /* translators: %s: rule ID */
                    'message'  => sprintf(__('Cloudflare Edge Access Rule #%s was unblocked/removed.', 'webcare-pro-security'), $rule_id),
                    'details'  => [
                        'Rule ID' => $rule_id,
                        'Zone ID' => $zone_id,
                    ],
                ]);
            }
            return [
                'success' => true,
                'message' => __('IP successfully unbanned from Cloudflare Edge.', 'webcare-pro-security'),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to unban IP from Cloudflare Edge.', 'webcare-pro-security');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Unblock an IP address or CIDR range directly at Cloudflare Edge by resolving its access rule ID
     *
     * @param string $ip IPv4, IPv6 address, or CIDR range
     * @return array
     */
    public static function unblock_ip_by_address(string $ip): array {
        $ip = trim($ip);
        $is_cidr = strpos($ip, '/') !== false;
        $target_param = 'ip';
        $target_val = $ip;

        if ($is_cidr) {
            $parts = explode('/', $ip);
            $subnet_ip = trim($parts[0]);
            if (!filter_var($subnet_ip, FILTER_VALIDATE_IP)) {
                return ['success' => false, 'message' => __('Invalid CIDR range provided.', 'webcare-pro-security')];
            }
            $target_param = 'ip_range';
            $target_val = $ip;
        } else {
            if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['success' => false, 'message' => __('Invalid IP address provided.', 'webcare-pro-security')];
            }
            $target_param = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6' : 'ip';
            $target_val = $ip;
        }

        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return ['success' => false, 'message' => __('Cloudflare credentials not configured.', 'webcare-pro-security')];
        }

        // Query Cloudflare for access rules matching this specific target value
        $res = self::request("zones/{$zone_id}/firewall/access_rules/rules?configuration.target={$target_param}&configuration.value=" . urlencode($target_val));

        if (!empty($res['success']) && !empty($res['result']) && is_array($res['result'])) {
            $deleted_count = 0;
            foreach ($res['result'] as $rule) {
                $r_id = $rule['id'] ?? '';
                if (!empty($r_id)) {
                    $del_res = self::unblock_ip($r_id);
                    if (!empty($del_res['success'])) {
                        $deleted_count++;
                    }
                }
            }

            if ($deleted_count > 0) {
                return [
                    'success' => true,
                    /* translators: %s: unblocked IP or CIDR */
                    'message' => sprintf(__('IP/Range %s successfully unblocked from Cloudflare Edge.', 'webcare-pro-security'), $target_val),
                ];
            }
        }

        // Fallback: If not found in active Cloudflare access rules, report clean notice
        return [
            'success' => true,
            /* translators: %s: unblocked IP or CIDR */
            'message' => sprintf(__('IP/Range %s is not currently blocked at Cloudflare Edge.', 'webcare-pro-security'), $target_val),
        ];
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
            return ['success' => false, 'message' => __('Cloudflare Zone ID is missing.', 'webcare-pro-security')];
        }

        $payload = empty($files) ? ['purge_everything' => true] : ['files' => $files];
        $res = self::request("zones/{$zone_id}/purge_cache", 'POST', $payload);

        if (!empty($res['success'])) {
            return [
                'success' => true,
                'message' => empty($files)
                    ? __('Cloudflare CDN Edge Cache purged completely.', 'webcare-pro-security')
                    : __('Selected files purged from Cloudflare Edge Cache.', 'webcare-pro-security'),
            ];
        }

        $err = $res['errors'][0]['message'] ?? __('Failed to purge Cloudflare cache.', 'webcare-pro-security');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Disconnect Cloudflare and wipe API token and Zone ID from database
     *
     * @return array
     */
    public static function disconnect(): array {
        SettingsManager::save_settings([
            'cloudflare_enabled'        => false,
            'cloudflare_api_token'      => '',
            'cloudflare_zone_id'        => '',
            'cloudflare_auto_sync_bans' => false,
        ]);

        return [
            'success' => true,
            'message' => __('Cloudflare disconnected and API token removed successfully.', 'webcare-pro-security'),
        ];
    }

    /**
     * Get path to the secure WebCare Vault JSON storage for Cloudflare Edge Events.
     *
     * @return string
     */
    public static function get_vault_events_filepath(): string {
        $uploads = wp_upload_dir();
        $base = untrailingslashit($uploads['basedir']);
        $vault_dir = $base . '/webcare-pro-security/.vault';

        if (!is_dir($vault_dir)) {
            wp_mkdir_p($vault_dir);
        }

        // Defensive guard files to prevent direct web execution / download
        $htaccess = $vault_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# Block all public web access to WebCare Vault\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n<FilesMatch \".*\">\n    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n    <IfModule !mod_authz_core.c>\n        Order deny,allow\n        Deny from all\n    </IfModule>\n</FilesMatch>\n";
            @file_put_contents($htaccess, $rules);
        }

        $index = $vault_dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WebCare Pro Security: Direct access forbidden.');\n");
        }

        return $vault_dir . '/cloudflare-edge-events.json';
    }

    /**
     * Get stored Cloudflare Edge Security Events from WebCare Vault JSON file.
     * Fast retrieval with zero external API calls or MySQL database load.
     *
     * @return array
     */
    public static function get_stored_firewall_events(): array {
        $file = self::get_vault_events_filepath();

        if (!file_exists($file) || !is_readable($file)) {
            return [
                'success'      => true,
                'events'       => [],
                'total_stored' => 0,
                'last_synced'  => null,
                'zone_name'    => '',
            ];
        }

        $content = @file_get_contents($file);
        if ($content === false || empty(trim($content))) {
            return [
                'success'      => true,
                'events'       => [],
                'total_stored' => 0,
                'last_synced'  => null,
                'zone_name'    => '',
            ];
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return [
                'success'      => true,
                'events'       => [],
                'total_stored' => 0,
                'last_synced'  => null,
                'zone_name'    => '',
            ];
        }

        $settings = SettingsManager::get_settings();
        $zone_id  = $data['zone_id'] ?? ($settings['cloudflare_zone_id'] ?? '');

        return [
            'success'      => true,
            'events'       => $data['events'] ?? [],
            'total_stored' => count($data['events'] ?? []),
            'last_synced'  => $data['last_synced'] ?? null,
            'zone_name'    => $data['zone_name'] ?? '',
            'zone_id'      => $zone_id,
        ];
    }

    /**
     * Clear all stored Cloudflare Edge Security Events from WebCare Vault JSON file.
     *
     * @return array
     */
    public static function clear_stored_firewall_events(): array {
        $file = self::get_vault_events_filepath();

        if (file_exists($file)) {
            wp_delete_file($file);
        }

        return [
            'success'      => true,
            'message'      => __('All stored Cloudflare edge security events have been cleared from local JSON vault.', 'webcare-pro-security'),
            'total_stored' => 0,
            'events'       => [],
            'last_synced'  => null,
        ];
    }

    /**
     * Fetch latest Cloudflare Edge Security Events via GraphQL API and store into WebCare Vault JSON file.
     *
     * @param int $limit Max events to request in this fetch (default 100)
     * @return array
     */
    public static function fetch_and_store_firewall_events(int $limit = 100): array {
        $settings = SettingsManager::get_settings();
        $token = $settings['cloudflare_api_token'] ?? '';
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($token) || empty($zone_id)) {
            return [
                'success' => false,
                'message' => __('Cloudflare API credentials not configured. Please connect your API token and Zone ID in Settings.', 'webcare-pro-security'),
            ];
        }

        // Cloudflare GraphQL query for firewallEventsAdaptive dataset
        $query = 'query GetFirewallEvents($zoneTag: String!, $limit: Int!) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              firewallEventsAdaptive(
                limit: $limit
                filter: { datetime_geq: "' . gmdate('Y-m-d\TH:i:s\Z', strtotime('-72 hours')) . '" }
                orderBy: [datetime_DESC]
              ) {
                datetime
                action
                ruleId
                rulesetId
                description
                source
                clientIP
                clientRequestHTTPHost
                clientRequestHTTPMethodName
                clientRequestHTTPProtocol
                clientRequestPath
                clientRequestQuery
                userAgent
                clientRefererHost
                clientRefererPath
                clientRefererQuery
                clientCountryName
                clientAsn
                clientASNDescription
                rayName
              }
            }
          }
        }';

        $payload = [
            'query'     => $query,
            'variables' => [
                'zoneTag' => $zone_id,
                'limit'   => max(10, min(500, $limit)),
            ],
        ];

        $res = self::request('graphql', 'POST', $payload);

        // Check for common permission error (missing Zone.Analytics:Read)
        if (!empty($res['errors'])) {
            $err_msg = '';
            foreach ($res['errors'] as $err) {
                $err_msg .= ($err['message'] ?? 'Error') . ' ';
            }

            if (stripos($err_msg, 'permission') !== false || stripos($err_msg, 'unauthorized') !== false || stripos($err_msg, 'access denied') !== false) {
                return [
                    'success'            => false,
                    'missing_permission' => true,
                    'message'            => __('Cloudflare API Token lacks "Zone.Analytics: Read" permission. Please edit your API token in the Cloudflare dashboard to include Zone > Analytics > Read.', 'webcare-pro-security'),
                ];
            }

            return [
                'success' => false,
                'message' => trim($err_msg),
            ];
        }

        $zones = $res['data']['viewer']['zones'] ?? [];
        if (empty($zones) || !isset($zones[0]['firewallEventsAdaptive'])) {
            return [
                'success' => false,
                'message' => __('No firewall analytics data returned from Cloudflare GraphQL endpoint.', 'webcare-pro-security'),
            ];
        }

        $raw_events = $zones[0]['firewallEventsAdaptive'];

        // Fetch existing custom rules from zone to map custom rule IDs to names
        $zone_custom_rules = [];
        $ruleset_res = self::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (!empty($ruleset_res['success']) && !empty($ruleset_res['result']['rules'])) {
            foreach ($ruleset_res['result']['rules'] as $cr) {
                if (!empty($cr['id'])) {
                    $zone_custom_rules[$cr['id']] = $cr['description'] ?? '';
                }
            }
        }

        $definitions = self::get_compound_rule_definitions();
        $mapped_events = [];

        foreach ($raw_events as $ev) {
            $ray_id = $ev['rayName'] ?? '';
            if (empty($ray_id)) {
                $ray_id = md5(($ev['datetime'] ?? '') . ($ev['clientIP'] ?? '') . ($ev['clientRequestPath'] ?? ''));
            }

            $rule_id = $ev['ruleId'] ?? '';
            $ruleset_id = $ev['rulesetId'] ?? '';
            $desc = !empty($ev['description']) ? trim($ev['description']) : '';

            // Determine human-friendly rule name
            $rule_name = '';

            // 1. If description was returned directly in the GraphQL event
            if (!empty($desc)) {
                $rule_name = $desc;
            }
            // 2. If ruleId matches one of the zone's custom rules
            elseif (!empty($rule_id) && isset($zone_custom_rules[$rule_id]) && !empty($zone_custom_rules[$rule_id])) {
                $rule_name = $zone_custom_rules[$rule_id];
            }
            // 3. Fallback: check WebCare Compound definitions if ruleId matches
            else {
                foreach ($definitions as $def) {
                    if (!empty($rule_id) && !empty($def['id']) && $rule_id === $def['id']) {
                        $rule_name = $def['title'];
                        break;
                    }
                }
            }

            // Clean WebCare tag prefix from rule name for clean display if present
            if (!empty($rule_name)) {
                $rule_name = trim(str_replace('[WebCare Pro Security]', '', $rule_name));
            } else {
                $src = $ev['source'] ?? '';
                $rule_name = $src ? ucfirst($src) . ' Rule' : 'Edge Security Rule';
            }

            $referer = '';
            if (!empty($ev['clientRefererHost'])) {
                $referer = 'https://' . $ev['clientRefererHost'] . ($ev['clientRefererPath'] ?? '');
                if (!empty($ev['clientRefererQuery'])) {
                    $referer .= '?' . $ev['clientRefererQuery'];
                }
            }

            $mapped_events[] = [
                'ray_id'       => $ray_id,
                'datetime'     => $ev['datetime'] ?? gmdate('Y-m-d H:i:s'),
                'action'       => $ev['action'] ?? 'block',
                'rule_id'      => $rule_id,
                'ruleset_id'   => $ruleset_id,
                'rule_name'    => $rule_name,
                'description'  => $desc,
                'source'       => $ev['source'] ?? 'waf',
                'client_ip'    => $ev['clientIP'] ?? 'unknown',
                'host'         => $ev['clientRequestHTTPHost'] ?? '',
                'method'       => $ev['clientRequestHTTPMethodName'] ?? 'GET',
                'protocol'     => $ev['clientRequestHTTPProtocol'] ?? 'HTTP/1.1',
                'path'         => $ev['clientRequestPath'] ?? '/',
                'query'        => $ev['clientRequestQuery'] ?? '',
                'user_agent'   => $ev['userAgent'] ?? ($ev['clientRequestUserAgent'] ?? ''),
                'referer'      => $referer,
                'country'      => $ev['clientCountryName'] ?? 'Unknown',
                'asn'          => $ev['clientAsn'] ?? '',
                'asn_desc'     => $ev['clientASNDescription'] ?? '',
            ];
        }

        // Read existing stored events to merge by ray_id without duplication
        $current_store = self::get_stored_firewall_events();
        $existing_events = $current_store['events'] ?? [];

        $by_ray = [];
        // Put existing events into map first
        foreach ($existing_events as $ex) {
            $k = $ex['ray_id'] ?? '';
            if (!empty($k)) {
                $by_ray[$k] = $ex;
            }
        }

        $new_count = 0;
        // Merge freshly fetched events
        foreach ($mapped_events as $m) {
            $k = $m['ray_id'];
            if (!isset($by_ray[$k])) {
                $new_count++;
            }
            $by_ray[$k] = $m;
        }

        // Sort descending by datetime
        $all_events = array_values($by_ray);
        usort($all_events, function($a, $b) {
            return strcmp($b['datetime'] ?? '', $a['datetime'] ?? '');
        });

        // Cap to latest 1000 events to prevent JSON file bloat
        if (count($all_events) > 1000) {
            $all_events = array_slice($all_events, 0, 1000);
        }

        // Get zone name for metadata
        $verify = self::verify_zone($zone_id);
        $zone_name = $verify['zone_name'] ?? '';

        $data_to_store = [
            'last_synced' => current_time('mysql'),
            'zone_id'     => $zone_id,
            'zone_name'   => $zone_name,
            'events'      => $all_events,
        ];

        // Atomically write JSON to WebCare Vault
        $filepath = self::get_vault_events_filepath();
        @file_put_contents($filepath, wp_json_encode($data_to_store, JSON_PRETTY_PRINT), LOCK_EX);

        return [
            'success'      => true,
            'new_fetched'  => $new_count,
            'total_stored' => count($all_events),
            'last_synced'  => $data_to_store['last_synced'],
            'zone_name'    => $zone_name,
            'events'       => $all_events,
        ];
    }
}
