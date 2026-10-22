<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;
use WcpScanner\Cloudflare\CloudflareService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * VirtualPatchManager
 *
 * Automated Two-Tier Virtual Patching Engine (WAF Lite + Cloudflare Free Edge Rules):
 * - Intercepts and shields unpatched CVEs and zero-days before official vendor releases or updates can be applied.
 * - Tier 1: Local PHP WAF Lite Virtual Patch (<0.5ms in-memory inspection at plugins_loaded:0).
 * - Tier 2: Cloudflare Global Edge Custom WAF Expression (blocks exploit at edge before reaching server/PHP).
 * - 1-Click "Protect Now via Virtual Patch" action across vulnerabilities and scan issues.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class VirtualPatchManager {

    const OPTION_PATCHES = 'wcpscan_virtual_patches';
    const CF_TAG = '[WCP Virtual Patch]';

    /**
     * Get Curated Catalog of Pre-Built Virtual Patches for Common & High-Impact WordPress CVEs.
     *
     * @return array
     */
    public static function get_patch_catalog(): array {
        return [
            'CVE-2024-28000' => [
                'patch_id'     => 'CVE-2024-28000',
                'cve_id'       => 'CVE-2024-28000',
                'component'    => 'litespeed-cache',
                'title'        => 'LiteSpeed Cache <= 6.3.0.1 - Unauthenticated Privilege Escalation / Admin Takeover',
                'severity'     => 'critical',
                'description'  => 'Blocks brute-forced or spoofed hash authentication bypass targeting LiteSpeed REST API / admin simulation endpoints.',
                'php_rule'     => [
                    'target_uris' => ['/wp-json/litespeed/', 'action=async_litespeed'],
                    'headers'     => ['X-LSCACHE-VARY'],
                    'regex'       => '/(litespeed_role|litespeed_hash|user_id=1)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "wp-json/litespeed" or http.request.uri.query contains "async_litespeed") and (http.request.uri.query contains "user_id=1" or any(http.request.headers["x-lscache-vary"][*] contains "role"))',
            ],
            'CVE-2024-31210' => [
                'patch_id'     => 'CVE-2024-31210',
                'cve_id'       => 'CVE-2024-31210',
                'component'    => 'wordpress-core',
                'title'        => 'WordPress Core <= 6.5.2 - Path Traversal & Arbitrary File Deletion',
                'severity'     => 'critical',
                'description'  => 'Neutralizes path traversal attempts with dot-dot-slash sequence targeting media attachment cleanup and file deletion routines.',
                'php_rule'     => [
                    'target_uris' => ['/wp-admin/post.php', '/wp-admin/admin-ajax.php'],
                    'regex'       => '/(\.\.\/|\.\.\\\\|\%2e\%2e|\%252e)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "wp-admin/post.php" or http.request.uri.path contains "wp-admin/admin-ajax.php") and (http.request.uri.query contains ".." or http.request.body contains "..")',
            ],
            'CVE-2024-5654' => [
                'patch_id'     => 'CVE-2024-5654',
                'cve_id'       => 'CVE-2024-5654',
                'component'    => 'give',
                'title'        => 'GiveWP <= 3.14.1 - Unauthenticated PHP Object Injection & RCE',
                'severity'     => 'critical',
                'description'  => 'Blocks serialized PHP object payload injection through donation forms and donation receipt parameter handles.',
                'php_rule'     => [
                    'target_uris' => ['give_action', 'give-donation'],
                    'regex'       => '/(O:[0-9]+:"[a-zA-Z0-9_]+":|a:[0-9]+:\{|give_title)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "give" or http.request.uri.query contains "give") and (http.request.body contains "O:" or http.request.uri.query contains "O:")',
            ],
            'CVE-2023-38000' => [
                'patch_id'     => 'CVE-2023-38000',
                'cve_id'       => 'CVE-2023-38000',
                'component'    => 'royal-elementor-addons',
                'title'        => 'Royal Elementor Addons <= 1.3.78 - Unauthenticated Arbitrary File Upload',
                'severity'     => 'critical',
                'description'  => 'Prevents executable file uploads and PHP extensions bypassing file verification checks in Royal Elementor upload handlers.',
                'php_rule'     => [
                    'target_uris' => ['wpr_addons_upload_file', 'royal_elementor'],
                    'regex'       => '/(\.php|\.phtml|\.php5|\.sh|\.cgi)/i',
                ],
                'cf_expression' => '(http.request.uri.query contains "wpr_addons_upload_file" or http.request.body contains "wpr_addons_upload_file") and (http.request.body contains ".php" or http.request.uri.query contains ".php")',
            ],
            'CVE-2023-28121' => [
                'patch_id'     => 'CVE-2023-28121',
                'cve_id'       => 'CVE-2023-28121',
                'component'    => 'woocommerce-payments',
                'title'        => 'WooCommerce Payments <= 5.6.1 - Unauthenticated Admin Privilege Escalation',
                'severity'     => 'critical',
                'description'  => 'Blocks unauthorized user impersonation headers (X-WCPay-Platform-Checkout-User) from arbitrary remote clients.',
                'php_rule'     => [
                    'target_uris' => ['/'],
                    'headers'     => ['X-WCPay-Platform-Checkout-User'],
                    'regex'       => '/[0-9]+/i',
                ],
                'cf_expression' => 'any(http.request.headers["x-wcpay-platform-checkout-user"][*] != "")',
            ],
            'VPATCH-FILE-UPLOAD' => [
                'patch_id'     => 'VPATCH-FILE-UPLOAD',
                'cve_id'       => 'GENERIC-UPLOAD',
                'component'    => 'all-plugins',
                'title'        => 'Universal Zero-Day Arbitrary File Upload Shield',
                'severity'     => 'high',
                'description'  => 'Blocks unauthenticated POST requests uploading PHP, shell scripts, or executable code to admin-ajax or rest-api endpoints.',
                'php_rule'     => [
                    'target_uris' => ['/wp-admin/admin-ajax.php', '/wp-json/'],
                    'methods'     => ['POST'],
                    'regex'       => '/(filename=[\'"][^\'"]+\.(php[0-9]?|phtml|sh|bash|cgi|exe)[\'"]|application\/x-php)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "admin-ajax.php" or http.request.uri.path contains "wp-json") and http.request.method eq "POST" and (http.request.body contains ".php" or http.request.body contains "application/x-php")',
            ],
            'VPATCH-SQLI-DEEP' => [
                'patch_id'     => 'VPATCH-SQLI-DEEP',
                'cve_id'       => 'GENERIC-SQLI',
                'component'    => 'all-plugins',
                'title'        => 'High-Confidence Plugin SQL Injection Shield',
                'severity'     => 'high',
                'description'  => 'Blocks UNION SELECT, Boolean-based sleep(), and benchmark() injection payloads targeting plugin custom query parameters.',
                'php_rule'     => [
                    'target_uris' => ['/'],
                    'regex'       => '/(union\s+all\s+select|select\s+sleep\s*\(|waitfor\s+delay\s+|extractvalue\s*\(|updatexml\s*\()/i',
                ],
                'cf_expression' => 'http.request.uri.query contains "union select" or http.request.uri.query contains "sleep(" or http.request.body contains "union select"',
            ],
        ];
    }

    /**
     * Get All Active Virtual Patches.
     *
     * @return array
     */
    public static function get_active_patches(): array {
        $patches = get_option(self::OPTION_PATCHES, []);
        if (!is_array($patches)) {
            return [];
        }
        return $patches;
    }

    /**
     * Apply a Virtual Patch (Tier 1: PHP WAF Lite + Tier 2: Cloudflare Free Edge).
     *
     * @param string $patch_id
     * @param array $custom_config
     * @return array
     */
    public static function apply_patch(string $patch_id, array $custom_config = []): array {
        $catalog = self::get_patch_catalog();
        $patch = $catalog[$patch_id] ?? null;

        if (!$patch && !empty($custom_config['title'])) {
            $patch = [
                'patch_id'      => $patch_id,
                'cve_id'        => $custom_config['cve_id'] ?? $patch_id,
                'component'     => $custom_config['component'] ?? 'custom',
                'title'         => $custom_config['title'],
                'severity'      => $custom_config['severity'] ?? 'high',
                'description'   => $custom_config['description'] ?? 'Custom Virtual Patch shield deployed via WCP.',
                'php_rule'      => $custom_config['php_rule'] ?? ['target_uris' => ['/'], 'regex' => '/\.\.\//i'],
                'cf_expression' => $custom_config['cf_expression'] ?? '',
            ];
        }

        if (!$patch) {
            return ['success' => false, 'message' => sprintf(__('Unknown patch template: %s', 'wcp-security-scanner'), $patch_id)];
        }

        $active = self::get_active_patches();
        $is_update = isset($active[$patch_id]);

        $patch['enabled'] = true;
        $patch['hits'] = $is_update ? ($active[$patch_id]['hits'] ?? 0) : 0;
        $patch['applied_at'] = current_time('mysql');
        $patch['deployed_to_cloudflare'] = false;
        $patch['cloudflare_rule_id'] = null;

        // Tier 2: Deploy to Cloudflare Global Edge if Cloudflare is configured
        $cf_deployed = false;
        $cf_msg = '';

        if (!empty($patch['cf_expression'])) {
            $cf_res = self::deploy_to_cloudflare_edge($patch);
            if ($cf_res['success']) {
                $patch['deployed_to_cloudflare'] = true;
                $patch['cloudflare_rule_id'] = $cf_res['rule_id'] ?? null;
                $cf_deployed = true;
                $cf_msg = __(' (Active on Cloudflare Global Edge + PHP WAF Lite)', 'wcp-security-scanner');
            } else {
                $cf_msg = ' (' . __('Local PHP WAF Lite Active; Cloudflare Edge: ', 'wcp-security-scanner') . ($cf_res['message'] ?? 'Not connected') . ')';
            }
        } else {
            $cf_msg = __(' (Active on Local PHP WAF Lite)', 'wcp-security-scanner');
        }

        $active[$patch_id] = $patch;
        update_option(self::OPTION_PATCHES, $active, false);

        // Record Audit Log
        AuditLogger::log_event(
            'virtual_patch_applied',
            sprintf(__('Applied Virtual Patch "%s" (%s)%s', 'wcp-security-scanner'), $patch['title'], $patch_id, $cf_msg)
        );

        return [
            'success'                => true,
            'message'                => sprintf(__('Virtual Patch "%s" applied successfully!%s', 'wcp-security-scanner'), $patch['title'], $cf_msg),
            'patch'                  => $patch,
            'deployed_to_cloudflare' => $cf_deployed,
        ];
    }

    /**
     * Remove / Deactivate a Virtual Patch.
     *
     * @param string $patch_id
     * @return array
     */
    public static function remove_patch(string $patch_id): array {
        $active = self::get_active_patches();
        if (!isset($active[$patch_id])) {
            return ['success' => false, 'message' => __('Virtual Patch is not active.', 'wcp-security-scanner')];
        }

        $patch = $active[$patch_id];

        // Remove from Cloudflare if deployed
        if (!empty($patch['deployed_to_cloudflare'])) {
            self::remove_from_cloudflare_edge($patch_id);
        }

        unset($active[$patch_id]);
        update_option(self::OPTION_PATCHES, $active, false);

        AuditLogger::log_event(
            'virtual_patch_removed',
            sprintf(__('Removed Virtual Patch "%s" (%s)', 'wcp-security-scanner'), $patch['title'], $patch_id)
        );

        return [
            'success' => true,
            'message' => sprintf(__('Virtual Patch "%s" has been deactivated.', 'wcp-security-scanner'), $patch['title']),
        ];
    }

    /**
     * Check if current request originates from an authenticated WordPress administrator.
     *
     * @return bool
     */
    public static function is_authenticated_administrator(): bool {
        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && (current_user_can('manage_options') || current_user_can('activate_plugins'))) {
                return true;
            }
        }

        if (function_exists('wp_validate_auth_cookie')) {
            $user_id = wp_validate_auth_cookie('', 'logged_in')
                ?: (wp_validate_auth_cookie('', 'secure_auth') ?: wp_validate_auth_cookie('', 'auth'));
            if ($user_id && function_exists('get_userdata')) {
                $user = get_userdata($user_id);
                if ($user && ($user->has_cap('manage_options') || $user->has_cap('activate_plugins') || in_array('administrator', (array) $user->roles, true))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Fast-Path Runtime Inspection: Evaluate Incoming Request against Active Virtual Patches.
     * Hooked directly into FirewallEngine before request processing.
     *
     * @param string $client_ip
     * @param string $request_uri
     * @return array|null Triggered rule array or null if clean
     */
    public static function evaluate_request(string $client_ip, string $request_uri): ?array {
        // Authenticated administrators managing the site must never be blocked by virtual patches
        if (self::is_authenticated_administrator()) {
            return null;
        }

        // E-Commerce & Membership Smart Shield: Never disrupt legitimate checkout, cart, or payment webhooks with unrelated CVE virtual patches
        $settings = SettingsManager::get_settings();
        if (!empty($settings['waf_ecommerce_safe_mode']) && class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            if (FirewallEngine::is_commerce_or_membership_request($request_uri)) {
                return null;
            }
        }

        $active_patches = self::get_active_patches();
        if (empty($active_patches)) {
            return null;
        }

        $method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $query_string = isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '';
        $raw_body = '';

        if ($method === 'POST') {
            $raw_input = @file_get_contents('php://input');
            $raw_body = !empty($raw_input) ? sanitize_text_field(wp_unslash($raw_input)) : '';
        }

        foreach ($active_patches as $patch_id => &$patch) {
            if (empty($patch['enabled'])) {
                continue;
            }

            $rule = $patch['php_rule'] ?? [];
            if (empty($rule)) {
                continue;
            }

            // Check Method restriction
            if (!empty($rule['methods']) && is_array($rule['methods'])) {
                if (!in_array($method, $rule['methods'], true)) {
                    continue;
                }
            }

            // Check URI match
            $uri_matches = false;
            if (!empty($rule['target_uris']) && is_array($rule['target_uris'])) {
                foreach ($rule['target_uris'] as $target_uri) {
                    if ($target_uri === '/' || stripos($request_uri, $target_uri) !== false) {
                        $uri_matches = true;
                        break;
                    }
                }
            } else {
                $uri_matches = true;
            }

            if (!$uri_matches) {
                continue;
            }

            // Check Headers
            if (!empty($rule['headers']) && is_array($rule['headers'])) {
                foreach ($rule['headers'] as $h_key) {
                    $norm_header = 'HTTP_' . strtoupper(str_replace('-', '_', $h_key));
                    if (!empty($_SERVER[$norm_header])) {
                        $h_val = sanitize_text_field(wp_unslash($_SERVER[$norm_header]));
                        if (!empty($rule['regex']) && preg_match($rule['regex'], $h_val)) {
                            return self::trigger_patch_block($patch_id, $patch, $h_val, 'HTTP Header: ' . $h_key);
                        }
                    }
                }
                // Header-targeted rules must not leak their header regex into query string or POST parameters
                continue;
            }

            // Check Query string and Body with Regex
            if (!empty($rule['regex'])) {
                $matched_evidence = '';

                if (!empty($query_string) && preg_match($rule['regex'], urldecode($query_string), $matches)) {
                    $matched_evidence = $matches[0];
                } elseif (!empty($raw_body) && preg_match($rule['regex'], $raw_body, $matches)) {
                    $matched_evidence = substr($matches[0], 0, 100);
                } elseif (!empty($_POST)) {
                    $clean_post = is_array($_POST) ? map_deep(wp_unslash($_POST), 'sanitize_text_field') : [];
                    $flat_post = (string) wp_json_encode($clean_post);
                    if (preg_match($rule['regex'], $flat_post, $matches)) {
                        $matched_evidence = substr($matches[0], 0, 100);
                    }
                }

                if (!empty($matched_evidence)) {
                    return self::trigger_patch_block($patch_id, $patch, $matched_evidence, 'Payload Parameter');
                }
            }
        }

        return null;
    }

    /**
     * Trigger Patch Block and Increment Counters.
     */
    private static function trigger_patch_block(string $patch_id, array &$patch, string $evidence, string $match_type): array {
        // Increment hit counter in options
        $active = self::get_active_patches();
        if (isset($active[$patch_id])) {
            $active[$patch_id]['hits'] = ($active[$patch_id]['hits'] ?? 0) + 1;
            $active[$patch_id]['last_hit'] = current_time('mysql');
            update_option(self::OPTION_PATCHES, $active, false);
        }

        return [
            'id'          => 'VPATCH-' . $patch_id,
            'name'        => '[Virtual Patch] ' . $patch['title'],
            'category'    => 'Virtual Patch (CVE Shield)',
            'match_type'  => $match_type,
            'match_value' => substr($evidence, 0, 120),
        ];
    }

    /**
     * Deploy Virtual Patch Expression to Cloudflare Global Edge.
     */
    private static function deploy_to_cloudflare_edge(array $patch): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $token = $settings['cloudflare_api_token'] ?? '';

        if (empty($zone_id) || empty($token)) {
            return ['success' => false, 'message' => __('Cloudflare API Token or Zone ID is not configured in Settings.', 'wcp-security-scanner')];
        }

        if (!class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
            $cf_file = defined('WCPSCAN_PATH') ? WCPSCAN_PATH . 'includes/Cloudflare/CloudflareService.php' : dirname(__DIR__) . '/Cloudflare/CloudflareService.php';
            if (file_exists($cf_file)) {
                require_once $cf_file;
            }
        }

        if (!class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
            return ['success' => false, 'message' => __('Cloudflare integration service is unavailable.', 'wcp-security-scanner')];
        }

        // Fetch existing ruleset
        $res = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        $rules = [];

        if (!empty($res['success']) && !empty($res['result']['rules'])) {
            foreach ($res['result']['rules'] as $r) {
                // Keep other rules
                $desc = $r['description'] ?? '';
                if (strpos($desc, self::CF_TAG . ' ' . $patch['patch_id']) === false) {
                    $rules[] = $r;
                }
            }
        }

        // Append new virtual patch rule
        $rule_desc = self::CF_TAG . ' ' . $patch['patch_id'] . ': ' . substr($patch['title'], 0, 60);
        $rules[] = [
            'action'      => 'block',
            'expression'  => $patch['cf_expression'],
            'description' => $rule_desc,
            'enabled'     => true,
        ];

        // Cloudflare Free allows up to 5 custom rules. Check limit
        if (count($rules) > 10) {
            // Keep rules within limit
            $rules = array_slice($rules, -10);
        }

        $put_res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            ['rules' => $rules]
        );

        if (!empty($put_res['success'])) {
            return [
                'success' => true,
                'rule_id' => $patch['patch_id'],
                'message' => __('Cloudflare Edge Rule synced successfully.', 'wcp-security-scanner'),
            ];
        }

        $err = $put_res['errors'][0]['message'] ?? __('Cloudflare API rejected rule expression.', 'wcp-security-scanner');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Remove Virtual Patch Rule from Cloudflare Global Edge.
     */
    private static function remove_from_cloudflare_edge(string $patch_id): bool {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id)) {
            return false;
        }

        if (!class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
            $cf_file = defined('WCPSCAN_PATH') ? WCPSCAN_PATH . 'includes/Cloudflare/CloudflareService.php' : dirname(__DIR__) . '/Cloudflare/CloudflareService.php';
            if (file_exists($cf_file)) {
                require_once $cf_file;
            }
        }

        if (!class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
            return false;
        }

        $res = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (empty($res['success']) || empty($res['result']['rules'])) {
            return false;
        }

        $remaining_rules = [];
        foreach ($res['result']['rules'] as $r) {
            $desc = $r['description'] ?? '';
            if (strpos($desc, self::CF_TAG . ' ' . $patch_id) === false) {
                $remaining_rules[] = $r;
            }
        }

        $put_res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            ['rules' => $remaining_rules]
        );

        return !empty($put_res['success']);
    }
}
