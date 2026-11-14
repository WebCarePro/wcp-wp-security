<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cloudflare IP List Synchronizer (CAF Phase 2)
 *
 * Implements dual-engine bulk ban synchronization:
 * 1. Scope auto-discovery: Detects whether API token has Account Custom List or Zone Access Rules permissions.
 * 2. Subnet Aggregation: Consolidates >= 4 IPs in same /24 (IPv4) or /64 (IPv6) banned within 15 min into 1 CIDR.
 * 3. Asynchronous queue: Flushes queued bans via non-blocking WP-Cron hook (`webcare_cloudflare_ip_sync_cron`).
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CloudflareIpListSynchronizer {

    public const OPTION_BAN_QUEUE        = 'webcare_cf_pending_ban_queue';
    public const OPTION_TOKEN_SCOPE      = 'webcare_cf_token_scope';
    public const OPTION_ACCOUNT_LIST_ID  = 'webcare_cf_account_list_id';
    public const OPTION_ACTIVE_EDGE_BANS = 'webcare_cf_active_edge_bans';
    public const LIST_NAME               = 'webcare_threat_blocklist';
    public const CRON_HOOK               = 'webcare_cloudflare_ip_sync_cron';

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
     * Caches the result in `webcare_cf_token_scope` for 6 hours.
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
    public static function queue_ip_ban(string $ip, string $reason = 'WebCare WAF Threat', int $ttl = 86400): void {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        // Never push private/loopback/reserved IPs to Cloudflare
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['cloudflare_enabled']) || empty($settings['cloudflare_api_token']) || empty($settings['cloudflare_zone_id'])) {
            return;
        }

        $entry = [
            'ip'         => $ip,
            'reason'     => substr(sanitize_text_field($reason), 0, 240),
            'banned_at'  => time(),
            'expires_at' => $ttl > 0 ? (time() + $ttl) : 0,
            'status'     => 'pending',
            'attempts'   => 0,
            'next_retry' => 0,
            'last_error' => '',
        ];

        // Burst limiter: Check how many instant bans were pushed in the current 10-second window
        $burst_key = 'webcare_cf_instant_burst';
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

        $result = ['synced_targets' => [], 'error' => ''];
        if ($scope === 'account') {
            $result = $sync->sync_via_account_list($targets, $items_to_sync);
        } elseif ($scope === 'zone') {
            $result = $sync->sync_via_zone_access_rules($targets, $items_to_sync);
        }

        // Determine which items were confirmed synced (CF-01)
        $confirmed_targets = $result['synced_targets'] ?? [];
        $confirmed_source_ips = [];
        foreach ($targets as $t) {
            if (in_array($t['target'], $confirmed_targets, true)) {
                foreach (($t['source_ips'] ?? [$t['target']]) as $sip) {
                    $confirmed_source_ips[$sip] = true;
                }
            }
        }

        // Merge any unconfirmed items back into OPTION_BAN_QUEUE so they are never lost
        $unsynced_items = [];
        $now = time();
        foreach ($items_to_sync as $ip => $entry) {
            if (empty($confirmed_source_ips[$ip])) {
                $attempts = ((int) ($entry['attempts'] ?? 0)) + 1;
                $entry['status']     = ($attempts >= 5) ? 'failed' : 'retry';
                $entry['attempts']   = $attempts;
                $entry['next_retry'] = $now + min(3600, 30 * (2 ** $attempts));
                $entry['last_error'] = (string) ($result['error'] ?? 'Shutdown flush unconfirmed');
                $unsynced_items[$ip] = $entry;
            }
        }

        if (!empty($unsynced_items)) {
            $queue = get_option(self::OPTION_BAN_QUEUE, []);
            if (!is_array($queue)) {
                $queue = [];
            }
            foreach ($unsynced_items as $uip => $uentry) {
                $queue[$uip] = $uentry;
            }
            if (count($queue) > 500) {
                $queue = array_slice($queue, -500, null, true);
            }
            update_option(self::OPTION_BAN_QUEUE, $queue, false);
        }
    }

    /**
     * Trigger immediate non-blocking loopback request to flush bans without waiting for cron visitor.
     */
    public static function trigger_background_queue_flush(): void {
        $last_spawn = (int) get_transient('webcare_cf_queue_spawn_debounce');
        if (time() - $last_spawn < 60) {
            return; // Debounce to at most once per 60 seconds
        }
        set_transient('webcare_cf_queue_spawn_debounce', time(), 60);

        $ajax_url = admin_url('admin-ajax.php');
        wp_remote_post($ajax_url, [
            'timeout'   => 0.01,
            'blocking'  => false,
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Standard WordPress core filter for local loopback requests
            'sslverify' => apply_filters('https_local_ssl_verify', false),
            'body'      => [
                'action' => 'webcare_flush_cf_ban_queue',
                'nonce'  => wp_create_nonce('webcare_cf_queue_flush_nonce'),
            ],
        ]);
    }

    /**
     * Group IPv4 addresses by /24 prefix (and IPv6 by /64).
     * If enough distinct IPs in the same subnet were banned within 15 minutes (900s),
     * merges them into a single CIDR (e.g. xxx.xxx.xxx.0/24) to conserve rule quotas.
     *
     * Subnet aggregation is safe by default (CF-03): gated behind setting cloudflare_subnet_aggregation_enabled (default false).
     *
     * @param array $queue_entries Raw queue entries `[ip => ['ip' => ..., 'banned_at' => ...]]`
     * @return array Consolidated targets: `[['target' => string, 'type' => 'ip'|'ip_range', 'notes' => string, 'source_ips' => array]]`
     */
    public function aggregate_subnets(array $queue_entries): array {
        $settings = SettingsManager::get_settings();
        $aggregation_enabled = !empty($settings['cloudflare_subnet_aggregation_enabled']);

        // Safe Subnet Aggregation Defaults (CF-03): Default is disabled (individual IPs only)
        if (!$aggregation_enabled) {
            $singles = [];
            foreach ($queue_entries as $entry) {
                $ip = (string) ($entry['ip'] ?? '');
                if (!empty($ip)) {
                    $singles[] = [
                        'target'     => $ip,
                        'type'       => 'ip',
                        'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                        'source_ips' => [$ip],
                    ];
                }
            }
            return $singles;
        }

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
                            'target'     => $ip,
                            'type'       => 'ip',
                            'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                            'source_ips' => [$ip],
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
                            'target'     => $ip,
                            'type'       => 'ip',
                            'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                            'source_ips' => [$ip],
                        ];
                    }
                    continue;
                }
            }

            $singles[] = [
                'target'     => $ip,
                'type'       => 'ip',
                'notes'      => $entry['reason'] ?? 'WebCare Local Ban',
                'source_ips' => [$ip],
            ];
        }

        $results = [];

        // Check IPv4 clusters: Threshold defaults to 10 distinct IPs within 15 minutes (CF-03)
        $v4_threshold = (int) ($settings['cloudflare_subnet_v4_threshold'] ?? 10);
        if ($v4_threshold < 2) {
            $v4_threshold = 10;
        }

        foreach ($subnets_v4 as $prefix => $cluster) {
            $distinct_v4_ips = array_unique(array_column($cluster, 'ip'));
            if (count($distinct_v4_ips) >= $v4_threshold) {
                $results[] = [
                    'target'     => "{$prefix}.0/24",
                    'type'       => 'ip_range',
                    'notes'      => sprintf('WebCare Aggregated /24 (%d distinct IPs in 15m)', count($distinct_v4_ips)),
                    'source_ips' => array_values($distinct_v4_ips),
                ];
            } else {
                foreach ($cluster as $c) {
                    $results[] = [
                        'target'     => $c['ip'],
                        'type'       => 'ip',
                        'notes'      => $c['reason'] ?? 'WebCare Local Ban',
                        'source_ips' => [$c['ip']],
                    ];
                }
            }
        }

        // Check IPv6 clusters: NEVER auto-aggregate unless explicitly enabled and >= 16 distinct IPs (CF-03)
        $v6_enabled = !empty($settings['cloudflare_subnet_v6_aggregation_enabled']);
        $v6_threshold = max(16, (int) ($settings['cloudflare_subnet_v6_threshold'] ?? 16));

        foreach ($subnets_v6 as $prefix => $cluster) {
            $distinct_v6_ips = array_unique(array_column($cluster, 'ip'));
            if ($v6_enabled && count($distinct_v6_ips) >= $v6_threshold) {
                $results[] = [
                    'target'     => "{$prefix}::/64",
                    'type'       => 'ip_range',
                    'notes'      => sprintf('WebCare Aggregated /64 (%d distinct IPs in 15m)', count($distinct_v6_ips)),
                    'source_ips' => array_values($distinct_v6_ips),
                ];
            } else {
                foreach ($cluster as $c) {
                    $results[] = [
                        'target'     => $c['ip'],
                        'type'       => 'ip',
                        'notes'      => $c['reason'] ?? 'WebCare Local Ban',
                        'source_ips' => [$c['ip']],
                    ];
                }
            }
        }

        return array_merge($results, $singles);
    }

    /**
     * Flush queued bans to Cloudflare Edge and prune expired temporary bans.
     * Enforces durable queue state machine, retry backoff and atomic mutex locking (CF-01).
     *
     * @return int Number of synchronized items
     */
    public function process_sync_queue(): int {
        // Atomic mutex lock (CF-01): 60-second transient lock prevents race conditions
        $lock_key = 'webcare_cf_sync_queue_lock';
        if (get_transient($lock_key)) {
            return 0;
        }
        set_transient($lock_key, time(), 60);

        try {
            // 1. Prune expired temporary edge bans (with acknowledgement check)
            $this->prune_expired_bans();

            $queue = get_option(self::OPTION_BAN_QUEUE, []);
            if (empty($queue) || !is_array($queue)) {
                return 0;
            }

            $now = time();
            $eligible_entries = [];
            $ineligible_entries = [];

            foreach ($queue as $ip => $entry) {
                if (!is_array($entry)) {
                    continue;
                }
                $entry['ip']         = (string) ($entry['ip'] ?? $ip);
                $entry['reason']     = (string) ($entry['reason'] ?? 'WebCare Threat Block');
                $entry['status']     = (string) ($entry['status'] ?? 'pending');
                $entry['attempts']   = (int) ($entry['attempts'] ?? 0);
                $entry['next_retry'] = (int) ($entry['next_retry'] ?? 0);
                $entry['last_error'] = (string) ($entry['last_error'] ?? '');

                // Skip items that exceeded maximum attempts (5) or are waiting for exponential backoff
                if ($entry['attempts'] >= 5) {
                    $entry['status'] = 'failed';
                    $ineligible_entries[$ip] = $entry;
                    continue;
                }

                if ($entry['next_retry'] > $now) {
                    $ineligible_entries[$ip] = $entry;
                    continue;
                }

                $eligible_entries[$ip] = $entry;
            }

            if (empty($eligible_entries)) {
                return 0;
            }

            $scope = $this->detect_api_scope();
            if ($scope === 'none') {
                return 0;
            }

            $aggregated_targets = $this->aggregate_subnets($eligible_entries);
            if (empty($aggregated_targets)) {
                return 0;
            }

            $sync_result = ($scope === 'account')
                ? $this->sync_via_account_list($aggregated_targets, $eligible_entries)
                : $this->sync_via_zone_access_rules($aggregated_targets, $eligible_entries);

            $confirmed_targets = $sync_result['synced_targets'] ?? [];
            $confirmed_ips = [];

            foreach ($aggregated_targets as $t) {
                if (in_array($t['target'], $confirmed_targets, true)) {
                    foreach (($t['source_ips'] ?? [$t['target']]) as $sip) {
                        $confirmed_ips[$sip] = true;
                    }
                }
            }

            $remaining_queue = $ineligible_entries;
            $synced_count = count($confirmed_ips);

            foreach ($eligible_entries as $ip => $entry) {
                if (!empty($confirmed_ips[$ip])) {
                    // Confirmed synced on Cloudflare: drop from queue
                    continue;
                }

                // Failed or unconfirmed: increment attempt counter with exponential backoff (CF-01)
                $attempts = ((int) ($entry['attempts'] ?? 0)) + 1;
                $entry['attempts']   = $attempts;
                $entry['last_error'] = (string) ($sync_result['error'] ?? 'Synchronization unconfirmed');
                $entry['status']     = ($attempts >= 5) ? 'failed' : 'retry';
                $entry['next_retry'] = $now + min(3600, 30 * (2 ** $attempts));
                $remaining_queue[$ip] = $entry;
            }

            if (empty($remaining_queue)) {
                delete_option(self::OPTION_BAN_QUEUE);
            } else {
                if (count($remaining_queue) > 500) {
                    $remaining_queue = array_slice($remaining_queue, -500, null, true);
                }
                update_option(self::OPTION_BAN_QUEUE, $remaining_queue, false);
            }

            return $synced_count;
        } finally {
            delete_transient($lock_key);
        }
    }

    /**
     * Sync targets to Cloudflare Account Custom IP List.
     * Automatically downgrades to Zone Access Rules on write permission errors (CF-02).
     *
     * @param array $targets
     * @param array $source_entries
     * @return array ['synced_targets' => string[], 'error' => string]
     */
    private function sync_via_account_list(array $targets, array $source_entries = []): array {
        $accounts_res = CloudflareService::request('accounts');
        if (empty($accounts_res['success']) || empty($accounts_res['result'][0]['id'])) {
            // Downgrade scope and fallback immediately to zone access rules (CF-02)
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        $account_id = (string) $accounts_res['result'][0]['id'];
        $list_id = $this->ensure_account_list($account_id);
        if (empty($list_id)) {
            // Downgrade scope and fallback immediately to zone access rules (CF-02)
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        // Build items payload (up to 10,000 items in single call)
        $items = [];
        foreach ($targets as $t) {
            $items[] = [
                'ip'      => $t['target'],
                'comment' => substr((string) ($t['notes'] ?? '[WebCare-WAF] Threat Block'), 0, 240),
            ];
        }

        if (empty($items)) {
            return ['synced_targets' => [], 'error' => ''];
        }

        $post_res = CloudflareService::request(
            "accounts/{$account_id}/rules/lists/{$list_id}/items",
            'POST',
            $items
        );

        if (empty($post_res['success'])) {
            // Write permission error or failure on account list: downgrade scope to zone and retry immediately (CF-02)
            set_transient(self::OPTION_TOKEN_SCOPE, 'zone', 6 * 3600);
            return $this->sync_via_zone_access_rules($targets, $source_entries);
        }

        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (!is_array($active_bans)) {
            $active_bans = [];
        }

        $synced_targets = [];
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
                    $synced_targets[] = $c_ip;
                }
            }
        }

        if (empty($synced_targets)) {
            foreach ($targets as $t) {
                $tip = $t['target'];
                $active_bans[$tip] = [
                    'target'     => $tip,
                    'mode'       => 'account',
                    'item_id'    => '',
                    'expires_at' => (int) ($source_entries[$tip]['expires_at'] ?? (time() + 86400)),
                    'synced_at'  => time(),
                ];
                $synced_targets[] = $tip;
            }
        }

        if (count($active_bans) > 2000) {
            $active_bans = array_slice($active_bans, -2000, null, true);
        }
        update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);

        return ['synced_targets' => $synced_targets, 'error' => ''];
    }

    /**
     * Ensure WebCare Threat blocklist exists in Cloudflare Account.
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
                'description' => 'WebCare Pro Security Autonomous Threat Blocklist',
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
     * @return array ['synced_targets' => string[], 'error' => string]
     */
    private function sync_via_zone_access_rules(array $targets, array $source_entries = []): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id)) {
            return ['synced_targets' => [], 'error' => 'Cloudflare Zone ID missing'];
        }

        $active_bans = get_option(self::OPTION_ACTIVE_EDGE_BANS, []);
        if (!is_array($active_bans)) {
            $active_bans = [];
        }

        $synced_targets = [];
        $last_error = '';

        foreach ($targets as $t) {
            $raw_note = (string) ($t['notes'] ?? 'WebCare Local Ban');
            if (!str_starts_with($raw_note, '[WebCare-WAF]')) {
                $raw_note = '[WebCare-WAF] ' . $raw_note;
            }
            $payload = [
                'mode'          => 'block',
                'configuration' => [
                    'target' => $t['type'] === 'ip_range' ? 'ip_range' : 'ip',
                    'value'  => $t['target'],
                ],
                'notes'         => substr($raw_note, 0, 240),
            ];

            $res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules", 'POST', $payload);
            if (!empty($res['success'])) {
                $rule_id = (string) ($res['result']['id'] ?? '');
                $tip = $t['target'];
                $synced_targets[] = $tip;
                $active_bans[$tip] = [
                    'target'     => $tip,
                    'mode'       => 'zone',
                    'item_id'    => $rule_id,
                    'expires_at' => (int) ($source_entries[$tip]['expires_at'] ?? (time() + 86400)),
                    'synced_at'  => time(),
                ];
            } else {
                $last_error = $res['errors'][0]['message'] ?? 'Failed to create zone access rule';
            }
        }

        if (!empty($synced_targets)) {
            if (count($active_bans) > 2000) {
                $active_bans = array_slice($active_bans, -2000, null, true);
            }
            update_option(self::OPTION_ACTIVE_EDGE_BANS, $active_bans, false);
        }

        return ['synced_targets' => $synced_targets, 'error' => $last_error];
    }

    /**
     * Prune expired edge bans from Cloudflare and the active bans ledger.
     * Enforces acknowledgement-based deletion: only removes from local ledger if Cloudflare confirmed (CF-04).
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
        $updated_ledger = [];

        foreach ($active_bans as $target => $meta) {
            $expires_at = (int) ($meta['expires_at'] ?? 0);
            if ($expires_at > 0 && $now >= $expires_at) {
                $expired_items[$target] = $meta;
            } else {
                $updated_ledger[$target] = $meta;
            }
        }

        if (empty($expired_items)) {
            return 0;
        }

        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $account_items_to_del = [];
        $account_targets = [];
        $pruned_count = 0;

        foreach ($expired_items as $target => $meta) {
            $mode = $meta['mode'] ?? 'zone';
            $item_id = (string) ($meta['item_id'] ?? '');

            if ($mode === 'account' && !empty($item_id)) {
                $account_items_to_del[] = ['id' => $item_id];
                $account_targets[$item_id] = [$target, $meta];
            } elseif ($mode === 'zone') {
                if (empty($item_id) || empty($zone_id)) {
                    // No valid Cloudflare ID to delete; safely drop from local ledger
                    $pruned_count++;
                    continue;
                }

                $del_res = CloudflareService::request("zones/{$zone_id}/firewall/access_rules/rules/{$item_id}", 'DELETE');
                $err_code = (int) ($del_res['errors'][0]['code'] ?? 0);
                $err_msg = strtolower((string) ($del_res['errors'][0]['message'] ?? ''));
                $http_code = (int) ($del_res['http_code'] ?? 0);
                $is_already_deleted = ($http_code === 404 || $err_code === 10002 || str_contains($err_msg, 'not found') || str_contains($err_msg, 'does not exist'));

                if (!empty($del_res['success']) || $is_already_deleted) {
                    $pruned_count++;
                } else {
                    // Retain in active bans ledger for retry (CF-04)
                    $meta['unban_status'] = 'unban_retry';
                    $meta['last_unban_error'] = $del_res['errors'][0]['message'] ?? 'Cloudflare DELETE failed';
                    $meta['unban_attempts'] = ((int) ($meta['unban_attempts'] ?? 0)) + 1;
                    $updated_ledger[$target] = $meta;
                }
            } else {
                $pruned_count++;
            }
        }

        // Batch delete from account list if any
        if (!empty($account_items_to_del)) {
            $accounts_res = CloudflareService::request('accounts');
            $account_id = (string) ($accounts_res['result'][0]['id'] ?? '');
            $list_id = !empty($account_id) ? $this->ensure_account_list($account_id) : '';

            if (!empty($list_id)) {
                $del_res = CloudflareService::request(
                    "accounts/{$account_id}/rules/lists/{$list_id}/items",
                    'DELETE',
                    ['items' => $account_items_to_del]
                );

                if (!empty($del_res['success'])) {
                    $pruned_count += count($account_items_to_del);
                } else {
                    // Retain account items in active bans ledger for retry (CF-04)
                    foreach ($account_targets as $item_id => [$target, $meta]) {
                        $meta['unban_status'] = 'unban_retry';
                        $meta['last_unban_error'] = $del_res['errors'][0]['message'] ?? 'Account list item DELETE failed';
                        $meta['unban_attempts'] = ((int) ($meta['unban_attempts'] ?? 0)) + 1;
                        $updated_ledger[$target] = $meta;
                    }
                }
            } else {
                foreach ($account_targets as $item_id => [$target, $meta]) {
                    $meta['unban_status'] = 'unban_retry';
                    $meta['last_unban_error'] = 'Could not resolve Account List ID';
                    $updated_ledger[$target] = $meta;
                }
            }
        }

        // Save ledger AFTER inspecting Cloudflare responses (CF-04)
        if (count($updated_ledger) > 2000) {
            $updated_ledger = array_slice($updated_ledger, -2000, null, true);
        }
        update_option(self::OPTION_ACTIVE_EDGE_BANS, $updated_ledger, false);

        return $pruned_count;
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
        if (class_exists('\\WebCareProScanner\\System\\Cron\\CronControlCenter')) {
            add_action(self::CRON_HOOK, static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::invoke_task_handler(self::CRON_HOOK, 'wp_cron');
            });

            add_action('init', static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::ensure_scheduled(self::CRON_HOOK, 300, 'webcare_every_five_minutes');
            }, 20);
        } else {
            add_action(self::CRON_HOOK, static function () {
                $sync = new self();
                $sync->process_sync_queue();
            });

            if (!wp_next_scheduled(self::CRON_HOOK)) {
                wp_schedule_event(time() + 300, 'webcare_every_five_minutes', self::CRON_HOOK);
            }
        }

        // Loopback AJAX handler for high-velocity queue flushing
        add_action('wp_ajax_nopriv_webcare_flush_cf_ban_queue', [__CLASS__, 'handle_loopback_flush']);
        add_action('wp_ajax_webcare_flush_cf_ban_queue', [__CLASS__, 'handle_loopback_flush']);
    }

    /**
     * Handle non-blocking loopback queue flush request.
     */
    public static function handle_loopback_flush(): void {
        check_ajax_referer('webcare_cf_queue_flush_nonce', 'nonce');
        $sync = new self();
        $sync->process_sync_queue();
        wp_send_json_success(['flushed' => true]);
    }
}
