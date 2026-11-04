<?php
declare(strict_types=1);

namespace WcpScanner\Firewall\CAF;

use WcpScanner\Cloudflare\CloudflareService;
use WcpScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare IP List Synchronizer (CAF Phase 2)
 *
 * Implements dual-engine bulk ban synchronization:
 * 1. Scope auto-discovery: Detects whether API token has Account Custom List or Zone Access Rules permissions.
 * 2. Subnet Aggregation: Consolidates >= 4 IPs in same /24 (IPv4) or /64 (IPv6) banned within 15 min into 1 CIDR.
 * 3. Asynchronous queue: Flushes queued bans via non-blocking WP-Cron hook (`wcp_cloudflare_ip_sync_cron`).
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CloudflareIpListSynchronizer {

    public const OPTION_BAN_QUEUE       = 'wcp_cf_pending_ban_queue';
    public const OPTION_TOKEN_SCOPE     = 'wcp_cf_token_scope';
    public const OPTION_ACCOUNT_LIST_ID = 'wcp_cf_account_list_id';
    public const LIST_NAME              = 'wcp_threat_blocklist';
    public const CRON_HOOK              = 'wcp_cloudflare_ip_sync_cron';

    /**
     * Test whether the configured Cloudflare API token has Account List permissions or Zone Access Rule permissions.
     * Caches the result in `wcp_cf_token_scope` for 6 hours.
     *
     * @param bool $force_refresh
     * @return string 'account' | 'zone' | 'none'
     */
    public function detect_api_scope(bool $force_refresh = false): string {
        if (!$force_refresh) {
            $cached = get_transient(self::OPTION_TOKEN_SCOPE);
            if (is_string($cached) && in_array($cached, ['account', 'zone', 'none'], true)) {
                return $cached;
            }
        }

        $settings = SettingsManager::get_settings();
        $token = $settings['cloudflare_api_token'] ?? '';
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($token)) {
            set_transient(self::OPTION_TOKEN_SCOPE, 'none', 3600);
            return 'none';
        }

        // Test 1: Probe Account List capability via /user/tokens/verify or by fetching accounts
        $accounts_res = CloudflareService::request('accounts');
        if (!empty($accounts_res['success']) && !empty($accounts_res['result'][0]['id'])) {
            $account_id = (string) $accounts_res['result'][0]['id'];
            // Check if lists endpoint is accessible
            $lists_res = CloudflareService::request("accounts/{$account_id}/rules/lists");
            if (!empty($lists_res['success'])) {
                set_transient(self::OPTION_TOKEN_SCOPE, 'account', 6 * 3600);
                return 'account';
            }
        }

        // Test 2: Fallback probe for Zone Access Rules
        if (!empty($zone_id)) {
            $zone_res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules?per_page=1");
            if (!empty($zone_res['success'])) {
                set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
                return 'zone';
            }
        }

        set_transient(self::OPTION_TOKEN_SCOPE, 'none', 1800);
        return 'none';
    }

    /**
     * Add a banned IP to the asynchronous queue in wp_options.
     *
     * @param string $ip Client IPv4 or IPv6
     * @param string $reason Reason description
     * @param int $ttl Time to live in seconds (default 86400)
     */
    public function queue_ip_ban(string $ip, string $reason = 'WCP WAF Threat', int $ttl = 86400): void {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        $queue = get_option(self::OPTION_BAN_QUEUE, []);
        if (!is_array($queue)) {
            $queue = [];
        }

        $queue[$ip] = [
            'ip'         => $ip,
            'reason'     => substr(sanitize_text_field($reason), 0, 100),
            'banned_at'  => time(),
            'expires_at' => time() + $ttl,
        ];

        // Keep queue capped at 500 entries to prevent option bloat
        if (count($queue) > 500) {
            $queue = array_slice($queue, -500, null, true);
        }

        update_option(self::OPTION_BAN_QUEUE, $queue, false);
    }

    /**
     * Group IPv4 addresses by /24 prefix (and IPv6 by /64).
     * If 4 or more distinct IPs in the same subnet were banned within 15 minutes (900s),
     * merges them into a single CIDR (e.g. xxx.xxx.xxx.0/24) to conserve rule quotas.
     *
     * @param array $queue_entries Raw queue entries `[ip => ['ip' => ..., 'banned_at' => ...]]`
     * @return array Consolidated targets: `[['target' => string, 'type' => 'ip'|'ip_range', 'notes' => string]]`
     */
    public function aggregate_subnets(array $queue_entries): array {
        $now = time();
        $subnets_v4 = []; // '192.0.2' => [entries]
        $subnets_v6 = []; // '2001:db8:1:1' => [entries]
        $singles = [];

        foreach ($queue_entries as $entry) {
            $ip = (string) ($entry['ip'] ?? '');
            $banned_at = (int) ($entry['banned_at'] ?? $now);

            // Only aggregate if banned within the last 15 minutes (900s)
            $is_recent = ($now - $banned_at) <= 900;

            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $octets = explode('.', $ip);
                if (count($octets) === 4) {
                    $prefix = "{$octets[0]}.{$octets[1]}.{$octets[2]}";
                    if ($is_recent) {
                        $subnets_v4[$prefix][] = $entry;
                    } else {
                        $singles[] = [
                            'target' => $ip,
                            'type'   => 'ip',
                            'notes'  => $entry['reason'] ?? 'WCP Local Ban',
                        ];
                    }
                    continue;
                }
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $expanded = inet_pton($ip);
                if ($expanded !== false) {
                    $hex = bin2hex(substr($expanded, 0, 8)); // First 64 bits
                    $prefix = implode(':', str_split($hex, 4));
                    if ($is_recent) {
                        $subnets_v6[$prefix][] = $entry;
                    } else {
                        $singles[] = [
                            'target' => $ip,
                            'type'   => 'ip',
                            'notes'  => $entry['reason'] ?? 'WCP Local Ban',
                        ];
                    }
                    continue;
                }
            }

            $singles[] = [
                'target' => $ip,
                'type'   => 'ip',
                'notes'  => $entry['reason'] ?? 'WCP Local Ban',
            ];
        }

        $results = [];

        // Check IPv4 clusters
        foreach ($subnets_v4 as $prefix => $cluster) {
            if (count($cluster) >= 4) {
                $results[] = [
                    'target' => "{$prefix}.0/24",
                    'type'   => 'ip_range',
                    'notes'  => sprintf('WCP Aggregated /24 (%d IPs in 15m)', count($cluster)),
                ];
            } else {
                foreach ($cluster as $c) {
                    $results[] = [
                        'target' => $c['ip'],
                        'type'   => 'ip',
                        'notes'  => $c['reason'] ?? 'WCP Local Ban',
                    ];
                }
            }
        }

        // Check IPv6 clusters
        foreach ($subnets_v6 as $prefix => $cluster) {
            if (count($cluster) >= 4) {
                $results[] = [
                    'target' => "{$prefix}::/64",
                    'type'   => 'ip_range',
                    'notes'  => sprintf('WCP Aggregated /64 (%d IPs in 15m)', count($cluster)),
                ];
            } else {
                foreach ($cluster as $c) {
                    $results[] = [
                        'target' => $c['ip'],
                        'type'   => 'ip',
                        'notes'  => $c['reason'] ?? 'WCP Local Ban',
                    ];
                }
            }
        }

        return array_merge($results, $singles);
    }

    /**
     * Flush queued bans to Cloudflare Edge.
     *
     * @return int Number of synchronized items
     */
    public function process_sync_queue(): int {
        $queue = get_option(self::OPTION_BAN_QUEUE, []);
        if (empty($queue) || !is_array($queue)) {
            return 0;
        }

        $scope = $this->detect_api_scope();
        if ($scope === 'none') {
            return 0;
        }

        $aggregated_targets = $this->aggregate_subnets($queue);
        if (empty($aggregated_targets)) {
            delete_option(self::OPTION_BAN_QUEUE);
            return 0;
        }

        $synced_count = 0;

        if ($scope === 'account') {
            $synced_count = $this->sync_via_account_list($aggregated_targets);
        } else {
            $synced_count = $this->sync_via_zone_access_rules($aggregated_targets);
        }

        // Clear queue upon processing
        delete_option(self::OPTION_BAN_QUEUE);

        return $synced_count;
    }

    /**
     * Sync targets to Cloudflare Account Custom IP List.
     */
    private function sync_via_account_list(array $targets): int {
        $accounts_res = CloudflareService::request('accounts');
        if (empty($accounts_res['success']) || empty($accounts_res['result'][0]['id'])) {
            return $this->sync_via_zone_access_rules($targets);
        }

        $account_id = (string) $accounts_res['result'][0]['id'];
        $list_id = $this->ensure_account_list($account_id);
        if (empty($list_id)) {
            return $this->sync_via_zone_access_rules($targets);
        }

        // Build items payload (up to 10,000 items in single call)
        $items = [];
        foreach ($targets as $t) {
            $items[] = [
                'ip'      => $t['target'],
                'comment' => substr((string) ($t['notes'] ?? 'WCP Threat Block'), 0, 100),
            ];
        }

        if (empty($items)) {
            return 0;
        }

        $post_res = CloudflareService::request(
            "accounts/{$account_id}/rules/lists/{$list_id}/items",
            'POST',
            $items
        );

        return !empty($post_res['success']) ? count($items) : 0;
    }

    /**
     * Ensure WCP threat blocklist exists in Cloudflare Account.
     */
    private function ensure_account_list(string $account_id): string {
        $stored = (string) get_option(self::OPTION_ACCOUNT_LIST_ID, '');
        if (!empty($stored)) {
            return $stored;
        }

        // Check if list already exists on Cloudflare
        $lists_res = CloudflareService::request("accounts/{$account_id}/rules/lists");
        if (!empty($lists_res['success']) && !empty($lists_res['result'])) {
            foreach ($lists_res['result'] as $list) {
                if (($list['name'] ?? '') === self::LIST_NAME) {
                    $id = (string) $list['id'];
                    update_option(self::OPTION_ACCOUNT_LIST_ID, $id, false);
                    return $id;
                }
            }
        }

        // Create list if not existing
        $create_res = CloudflareService::request(
            "accounts/{$account_id}/rules/lists",
            'POST',
            [
                'name'        => self::LIST_NAME,
                'description' => 'WCP Security Scanner Autonomous Threat Blocklist',
                'kind'        => 'ip',
            ]
        );

        if (!empty($create_res['success']) && !empty($create_res['result']['id'])) {
            $id = (string) $create_res['result']['id'];
            update_option(self::OPTION_ACCOUNT_LIST_ID, $id, false);
            return $id;
        }

        return '';
    }

    /**
     * Fallback driver: sync targets via Zone IP Access Rules API.
     */
    private function sync_via_zone_access_rules(array $targets): int {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id)) {
            return 0;
        }

        $synced = 0;
        foreach ($targets as $t) {
            $payload = [
                'mode'          => 'block',
                'configuration' => [
                    'target' => $t['type'] === 'ip_range' ? 'ip_range' : 'ip',
                    'value'  => $t['target'],
                ],
                'notes'         => substr((string) ($t['notes'] ?? 'WCP Local Ban'), 0, 100),
            ];

            $res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules", 'POST', $payload);
            if (!empty($res['success'])) {
                $synced++;
            }
        }

        return $synced;
    }

    /**
     * Register asynchronous sync cron hook.
     */
    public static function register_cron(): void {
        add_action(self::CRON_HOOK, static function () {
            $sync = new self();
            $sync->process_sync_queue();
        });

        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 300, 'wcp_every_five_minutes', self::CRON_HOOK);
        }
    }
}
