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

    public const OPTION_BAN_QUEUE        = 'wcp_cf_pending_ban_queue';
    public const OPTION_TOKEN_SCOPE      = 'wcp_cf_token_scope';
    public const OPTION_ACCOUNT_LIST_ID  = 'wcp_cf_account_list_id';
    public const OPTION_ACTIVE_EDGE_BANS = 'wcp_cf_active_edge_bans';
    public const LIST_NAME               = 'wcp_threat_blocklist';
    public const CRON_HOOK               = 'wcp_cloudflare_ip_sync_cron';

    /**
     * In-memory queue of bans to push to Cloudflare at PHP shutdown (post-response).
     *
     * @var array<string, array>
     */
    private static array $shutdown_immediate_queue = [];

    /**
     * Whether register_shutdown_function has been registered for this request.
     *
     * @var bool
     */
    private static bool $shutdown_registered = false;

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
     * Add a banned IP to the synchronization queue and schedule immediate edge push if under burst threshold.
     *
     * @param string $ip Client IPv4 or IPv6
     * @param string $reason Reason description
     * @param int $ttl Time to live in seconds (default 86400)
     */
    public static function queue_ip_ban(string $ip, string $reason = 'WCP WAF Threat', int $ttl = 86400): void {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        // Never push private/loopback/reserved IPs to Cloudflare
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['cloudflare_api_token']) || empty($settings['cloudflare_zone_id'])) {
            return;
        }

        $entry = [
            'ip'         => $ip,
            'reason'     => substr(sanitize_text_field($reason), 0, 100),
            'banned_at'  => time(),
            'expires_at' => $ttl > 0 ? (time() + $ttl) : 0,
        ];

        // Burst limiter: Check how many instant bans were pushed in the current 10-second window
        $burst_key = 'wcp_cf_instant_burst';
        $burst_count = function_exists('apcu_fetch') && ini_get('apc.enabled')
            ? (int) apcu_fetch($burst_key)
            : (int) get_transient($burst_key);

        if ($burst_count < 5) {
            if (function_exists('apcu_store') && ini_get('apc.enabled')) {
                apcu_store($burst_key, $burst_count + 1, 10);
            } else {
                set_transient($burst_key, $burst_count + 1, 10);
            }

            self::$shutdown_immediate_queue[$ip] = $entry;
            if (!self::$shutdown_registered) {
                self::$shutdown_registered = true;
                register_shutdown_function([__CLASS__, 'flush_immediate_shutdown_bans']);
            }
            return;
        }

        // High-velocity swarm (>5 bans in 10s): add to batch queue for subnet aggregation and background flush
        $queue = get_option(self::OPTION_BAN_QUEUE, []);
        if (!is_array($queue)) {
            $queue = [];
        }

        $queue[$ip] = $entry;

        // Keep queue capped at 500 entries to prevent option bloat
        if (count($queue) > 500) {
            $queue = array_slice($queue, -500, null, true);
        }

        update_option(self::OPTION_BAN_QUEUE, $queue, false);

        // WP-Cron Reliability on Edge-Cached Sites:
        // When Cloudflare aggressively caches edge pages, low-traffic sites may not trigger cron on schedule.
        // If queue exceeds 25 pending bans, immediately trigger background loopback flush.
        if (count($queue) >= 25) {
            self::trigger_background_queue_flush();
        }
    }

    /**
     * Flush immediate bans after sending the HTTP 403 response to the client (0ms visitor latency).
     */
    public static function flush_immediate_shutdown_bans(): void {
        if (empty(self::$shutdown_immediate_queue)) {
            return;
        }

        // Flush HTTP response buffer to client first so connection closes immediately
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        } elseif (function_exists('litespeed_finish_request')) {
            @litespeed_finish_request();
        }

        $sync = new self();
        $items_to_sync = self::$shutdown_immediate_queue;
        self::$shutdown_immediate_queue = [];

        $targets = $sync->aggregate_subnets($items_to_sync);
        $scope = $sync->detect_api_scope();

        if ($scope === 'account') {
            $sync->sync_via_account_list($targets, $items_to_sync);
        } elseif ($scope === 'zone') {
            $sync->sync_via_zone_access_rules($targets, $items_to_sync);
        }
    }

    /**
     * Trigger immediate non-blocking loopback request to flush bans without waiting for cron visitor.
     */
    public static function trigger_background_queue_flush(): void {
        $last_spawn = (int) get_transient('wcp_cf_queue_spawn_debounce');
        if (time() - $last_spawn < 60) {
            return; // Debounce to at most once per 60 seconds
        }
        set_transient('wcp_cf_queue_spawn_debounce', time(), 60);

        $ajax_url = admin_url('admin-ajax.php');
        wp_remote_post($ajax_url, [
            'timeout'   => 0.01,
            'blocking'  => false,
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Standard WordPress core filter for local loopback requests
            'sslverify' => apply_filters('https_local_ssl_verify', false),
            'body'      => [
                'action' => 'wcp_flush_cf_ban_queue',
                'nonce'  => wp_create_nonce('wcp_cf_queue_flush_nonce'),
            ],
        ]);
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
     * Flush queued bans to Cloudflare Edge and prune expired temporary bans.
     *
     * @return int Number of synchronized items
     */
    public function process_sync_queue(): int {
        // 1. Prune expired temporary edge bans
        $this->prune_expired_bans();

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
            $synced_count = $this->sync_via_account_list($aggregated_targets, $queue);
        } else {
            $synced_count = $this->sync_via_zone_access_rules($aggregated_targets, $queue);
        }

        // Clear queue upon processing
        delete_option(self::OPTION_BAN_QUEUE);

        return $synced_count;
    }

    /**
     * Sync targets to Cloudflare Account Custom IP List.
     *
     * @param array $targets
     * @param array $source_entries
     * @return int
     */
    private function sync_via_account_list(array $targets, array $source_entries = []): int {
        $accounts_res = CloudflareService::request('accounts');
        if (empty($accounts_res['success']) || empty($accounts_res['result'][0]['id'])) {
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        $account_id = (string) $accounts_res['result'][0]['id'];
        $list_id = $this->ensure_account_list($account_id);
        if (empty($list_id)) {
            return $this->sync_via_zone_access_rules($targets, $source_entries);
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

        if (!empty($post_res['success'])) {
            $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
            if (!is_array($active_bans)) {
                $active_bans = [];
            }

            if (!empty($post_res['result']) && is_array($post_res['result'])) {
                foreach ($post_res['result'] as $created) {
                    $c_ip = (string) ($created['ip'] ?? '');
                    $c_id = (string) ($created['id'] ?? '');
                    if (!empty($c_ip)) {
                        $active_bans[$c_ip] = [
                            'target'     => $c_ip,
                            'mode'       => 'account',
                            'item_id'    => $c_id,
                            'expires_at' => (int) ($source_entries[$c_ip]['expires_at'] ?? (time() + 86400)),
                            'synced_at'  => time(),
                        ];
                    }
                }
            } else {
                foreach ($targets as $t) {
                    $tip = $t['target'];
                    $active_bans[$tip] = [
                        'target'     => $tip,
                        'mode'       => 'account',
                        'item_id'    => '',
                        'expires_at' => (int) ($source_entries[$tip]['expires_at'] ?? (time() + 86400)),
                        'synced_at'  => time(),
                    ];
                }
            }

            if (count($active_bans) > 2000) {
                $active_bans = array_slice($active_bans, -2000, null, true);
            }
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);

            return count($items);
        }

        return 0;
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
     *
     * @param array $targets
     * @param array $source_entries
     * @return int
     */
    private function sync_via_zone_access_rules(array $targets, array $source_entries = []): int {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id)) {
            return 0;
        }

        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (!is_array($active_bans)) {
            $active_bans = [];
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
                $rule_id = (string) ($res['result']['id'] ?? '');
                $tip = $t['target'];
                $active_bans[$tip] = [
                    'target'     => $tip,
                    'mode'       => 'zone',
                    'item_id'    => $rule_id,
                    'expires_at' => (int) ($source_entries[$tip]['expires_at'] ?? (time() + 86400)),
                    'synced_at'  => time(),
                ];
            }
        }

        if ($synced > 0) {
            if (count($active_bans) > 2000) {
                $active_bans = array_slice($active_bans, -2000, null, true);
            }
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
        }

        return $synced;
    }

    /**
     * Prune expired edge bans from Cloudflare and the active bans ledger.
     *
     * @return int Number of pruned items
     */
    public function prune_expired_bans(): int {
        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (empty($active_bans) || !is_array($active_bans)) {
            return 0;
        }

        $now = time();
        $expired_items = [];
        $remaining = [];

        foreach ($active_bans as $target => $meta) {
            $expires_at = (int) ($meta['expires_at'] ?? 0);
            if ($expires_at > 0 && $now >= $expires_at) {
                $expired_items[$target] = $meta;
            } else {
                $remaining[$target] = $meta;
            }
        }

        if (empty($expired_items)) {
            return 0;
        }

        // Save remaining ledger first
        update_option(self::OPTION_ACTIVE_EDGE_BANS, $remaining, false);

        // Delete expired items from Cloudflare
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $account_items_to_del = [];

        foreach ($expired_items as $target => $meta) {
            $mode = $meta['mode'] ?? 'zone';
            $item_id = (string) ($meta['item_id'] ?? '');

            if ($mode === 'account' && !empty($item_id)) {
                $account_items_to_del[] = ['id' => $item_id];
            } elseif ($mode === 'zone' && !empty($item_id) && !empty($zone_id)) {
                CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$item_id}", 'DELETE');
            }
        }

        // Batch delete from account list if any
        if (!empty($account_items_to_del)) {
            $accounts_res = CloudflareService::request('accounts');
            if (!empty($accounts_res['success']) && !empty($accounts_res['result'][0]['id'])) {
                $account_id = (string) $accounts_res['result'][0]['id'];
                $list_id = $this->ensure_account_list($account_id);
                if (!empty($list_id)) {
                    CloudflareService::request(
                        "accounts/{$account_id}/rules/lists/{$list_id}/items",
                        'DELETE',
                        ['items' => $account_items_to_del]
                    );
                }
            }
        }

        return count($expired_items);
    }

    /**
     * Immediately unban an IP address from Cloudflare Edge (Zone Access Rules and Account Custom List)
     * and clear it from active ledgers and pending queues.
     *
     * @param string $ip
     * @return bool
     */
    public static function unban_ip_immediately(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        // 1. Remove from in-memory shutdown queue if present
        if (isset(self::$shutdown_immediate_queue[$ip])) {
            unset(self::$shutdown_immediate_queue[$ip]);
        }

        // 2. Remove from pending batch queue if queued
        $queue = get_option(self::OPTION_BAN_QUEUE, []);
        if (is_array($queue) && isset($queue[$ip])) {
            unset($queue[$ip]);
            update_option(self::OPTION_BAN_QUEUE, $queue, false);
        }

        // 3. Remove from active edge bans ledger
        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        $meta = is_array($active_bans) ? ($active_bans[$ip] ?? null) : null;
        if (is_array($active_bans) && isset($active_bans[$ip])) {
            unset($active_bans[$ip]);
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
        }

        // 4. Remove from Cloudflare Edge
        $settings = SettingsManager::get_settings();
        if (empty($settings['cloudflare_api_token'])) {
            return true;
        }

        $sync = new self();
        $scope = $sync->detect_api_scope();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        // If it was tracked in Account list
        if ($scope === 'account' && !empty($meta['item_id'])) {
            $accounts_res = CloudflareService::request('accounts');
            if (!empty($accounts_res['success']) && !empty($accounts_res['result'][0]['id'])) {
                $account_id = (string) $accounts_res['result'][0]['id'];
                $list_id = $sync->ensure_account_list($account_id);
                if (!empty($list_id)) {
                    CloudflareService::request(
                        "accounts/{$account_id}/rules/lists/{$list_id}/items",
                        'DELETE',
                        ['items' => [['id' => $meta['item_id']]]]
                    );
                }
            }
        }

        // Delete from Zone IP Access Rules (by direct rule ID if known, or by searching value)
        if (!empty($zone_id)) {
            if (!empty($meta['item_id']) && ($meta['mode'] ?? '') === 'zone') {
                CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$meta['item_id']}", 'DELETE');
            } else {
                $search = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules?configuration.value=" . rawurlencode($ip));
                if (!empty($search['success']) && !empty($search['result']) && is_array($search['result'])) {
                    foreach ($search['result'] as $r) {
                        if (!empty($r['id'])) {
                            CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$r['id']}", 'DELETE');
                        }
                    }
                }
            }
        }

        return true;
    }

    /**
     * Register asynchronous sync cron hook and AJAX loopback handler.
     */
    public static function register_cron(): void {
        add_action(self::CRON_HOOK, static function () {
            $sync = new self();
            $sync->process_sync_queue();
        });

        // Loopback AJAX handler for high-velocity queue flushing
        add_action('wp_ajax_nopriv_wcp_flush_cf_ban_queue', [__CLASS__, 'handle_loopback_flush']);
        add_action('wp_ajax_wcp_flush_cf_ban_queue', [__CLASS__, 'handle_loopback_flush']);

        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 300, 'wcp_every_five_minutes', self::CRON_HOOK);
        }
    }

    /**
     * Handle non-blocking loopback queue flush request.
     */
    public static function handle_loopback_flush(): void {
        check_ajax_referer('wcp_cf_queue_flush_nonce', 'nonce');
        $sync = new self();
        $sync->process_sync_queue();
        wp_send_json_success(['flushed' => true]);
    }
}
