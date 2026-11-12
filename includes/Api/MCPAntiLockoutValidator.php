<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Auth\SessionSentinel;
use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\ServerInfo;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPAntiLockoutValidator
 *
 * Centralized invariant checks ensuring MCP-initiated firewall rules, IP bans,
 * and setting mutations can never lock out active administrators, origin servers,
 * Cloudflare proxy ranges, the Rescue Assistant, or the MCP endpoint itself.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
class MCPAntiLockoutValidator {

    /**
     * Gather all protected IP addresses and ranges that MCP actions must never ban.
     *
     * @return array<int, string>
     */
    public static function get_protected_ips(): array {
        $ips = ['127.0.0.1', '::1'];

        if (class_exists(FirewallEngine::class)) {
            $client_ip = FirewallEngine::get_client_ip();
            if ($client_ip !== '') {
                $ips[] = $client_ip;
            }
        }

        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $ips[] = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        if (class_exists(ServerInfo::class)) {
            foreach (ServerInfo::get_all_server_ips() as $srv_ip) {
                if (is_string($srv_ip) && $srv_ip !== '') {
                    $ips[] = $srv_ip;
                }
            }
        }

        if (class_exists(SessionSentinel::class)) {
            foreach (SessionSentinel::get_active_sessions() as $sess) {
                if (!empty($sess['ip']) && is_string($sess['ip'])) {
                    $ips[] = $sess['ip'];
                }
            }
        }

        return array_values(array_unique(array_filter(array_map('trim', $ips))));
    }

    /**
     * Check whether an IP address matches any IP or CIDR range in a list.
     *
     * @param string            $ip
     * @param array<int,string> $entries
     * @return bool
     */
    public static function ip_matches_cidr_list(string $ip, array $entries): bool {
        $ip = trim($ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        $ip_bin = @inet_pton($ip);
        if ($ip_bin === false) {
            return false;
        }

        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') === false) {
                $entry_bin = @inet_pton($entry);
                if ($entry_bin !== false && $entry_bin === $ip_bin) {
                    return true;
                }
                continue;
            }
            [$subnet, $prefix] = explode('/', $entry, 2);
            $subnet_bin = @inet_pton(trim($subnet));
            if ($subnet_bin === false || strlen($subnet_bin) !== strlen($ip_bin)) {
                continue;
            }
            $bits      = strlen($ip_bin) * 8;
            $prefix_i  = max(0, min($bits, (int) $prefix));
            $full_bytes = intdiv($prefix_i, 8);
            $rem_bits  = $prefix_i % 8;

            if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($subnet_bin, 0, $full_bytes)) {
                continue;
            }
            if ($rem_bits === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rem_bits)) & 0xFF;
            if ((ord($ip_bin[$full_bytes]) & $mask) === (ord($subnet_bin[$full_bytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse newline- or comma-separated CIDR/IP entries into a clean array.
     *
     * @param string $raw
     * @return array<int, string>
     */
    public static function parse_cidr_list(string $raw): array {
        $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
        $out   = [];
        foreach ($parts as $part) {
            $item = trim($part);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * Validate that banning an IP or CIDR will not lock out active admins, origin server, or Cloudflare proxy.
     *
     * @param string $target_ip
     * @return array{allowed:bool,reason:string}
     */
    public static function validate_ip_ban(string $target_ip): array {
        $target_ip = trim($target_ip);
        if ($target_ip === '') {
            return ['allowed' => false, 'reason' => __('Target IP address is empty.', 'webcare-pro-security')];
        }

        $is_valid_single = (bool) filter_var($target_ip, FILTER_VALIDATE_IP);
        $is_valid_cidr   = false;
        if (!$is_valid_single && strpos($target_ip, '/') !== false) {
            [$sub, $mask] = explode('/', $target_ip, 2);
            if (filter_var(trim($sub), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && is_numeric($mask) && (int) $mask >= 8 && (int) $mask <= 32) {
                $is_valid_cidr = true;
            } elseif (filter_var(trim($sub), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && is_numeric($mask) && (int) $mask >= 32 && (int) $mask <= 128) {
                $is_valid_cidr = true;
            }
        }
        if (!$is_valid_single && !$is_valid_cidr) {
            return ['allowed' => false, 'reason' => __('Invalid IPv4/IPv6 address or overly broad CIDR subnet.', 'webcare-pro-security')];
        }

        foreach (self::get_protected_ips() as $protected) {
            if (self::ip_matches_cidr_list($protected, [$target_ip])) {
                return [
                    'allowed' => false,
                    'reason'  => sprintf(
                        /* translators: %s: protected IP address */
                        __('Anti-Lockout Guard: "%s" matches a protected administrator, loopback, or server IP.', 'webcare-pro-security'),
                        $target_ip
                    ),
                ];
            }
        }

        if ($is_valid_single && class_exists(CloudflareService::class) && CloudflareService::is_cloudflare_ip($target_ip)) {
            return [
                'allowed' => false,
                'reason'  => __('Anti-Lockout Guard: Cannot ban an official Cloudflare proxy IP range.', 'webcare-pro-security'),
            ];
        }

        return ['allowed' => true, 'reason' => ''];
    }

    /**
     * Inspect a Visual/Modular rule payload for self-lockout risks against MCP control routes or admin paths.
     *
     * @param array<string, mixed> $rule_data
     * @return array{allowed:bool,escalate_tier:int,reason:string,warnings:array<int,string>}
     */
    public static function validate_custom_rule(array $rule_data): array {
        $action   = strtolower((string) ($rule_data['action_type'] ?? 'block'));
        $expr     = strtolower((string) ($rule_data['wirefilter_expr'] ?? $rule_data['expression'] ?? ''));
        $warnings = [];
        $escalate = 0;

        if (!empty($rule_data['conditions']) && is_array($rule_data['conditions']) && $expr === '') {
            $expr = strtolower((string) wp_json_encode($rule_data['conditions']));
        }

        $is_blocking = in_array($action, ['block', 'block_and_ban', 'challenge_pow', 'rate_limit'], true);
        if (!$is_blocking) {
            return ['allowed' => true, 'escalate_tier' => 0, 'reason' => '', 'warnings' => []];
        }

        // Never allow blocking MCP control routes or Rescue Assistant callbacks
        if (strpos($expr, 'webcare-pro-security/v1/mcp') !== false || strpos($expr, 'webcare_rescue') !== false) {
            return [
                'allowed'       => false,
                'escalate_tier' => 4,
                'reason'        => __('Anti-Lockout Guard: Firewall rules cannot block WebCare Pro MCP or Rescue Assistant endpoints.', 'webcare-pro-security'),
                'warnings'      => [],
            ];
        }

        // Block banning protected admin/server IPs via Visual Rule IP equals/in clauses
        foreach (self::get_protected_ips() as $protected) {
            if ($protected !== '' && strpos($expr, strtolower($protected)) !== false) {
                return [
                    'allowed'       => false,
                    'escalate_tier' => 4,
                    'reason'        => __('Anti-Lockout Guard: Rule references a protected administrator, loopback, or server IP.', 'webcare-pro-security'),
                    'warnings'      => [],
                ];
            }
        }

        // Admin or login paths without explicit logged-in exemption escalate to Tier 3 confirmation
        $targets_admin = (strpos($expr, '/wp-admin') !== false || strpos($expr, 'wp-login.php') !== false);
        $has_login_exempt = (strpos($expr, 'not wp.user.is_logged_in') !== false || strpos($expr, 'wp.user.is_logged_in eq false') !== false);
        if ($targets_admin && !$has_login_exempt) {
            $escalate   = 3;
            $warnings[] = __('Rule targets /wp-admin or wp-login.php without "not wp.user.is_logged_in" exemption; human approval is required.', 'webcare-pro-security');
        }

        return [
            'allowed'       => true,
            'escalate_tier' => $escalate,
            'reason'        => '',
            'warnings'      => $warnings,
        ];
    }
}
