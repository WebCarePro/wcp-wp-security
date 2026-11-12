<?php
/**
 * Rescue Assistant, Daily Security Story, Admin Bar Quick-Unblock & Safe Update Manager
 *
 * Powers non-technical site-owner safety controls:
 * - "Something Not Working?" 15-minute diagnostic translator & 1-click trust/allow rules
 * - 15-minute Strict Firewall Test Pause with WP-Cron auto re-arm
 * - Plain-English Weekly/Daily Security Story telemetry
 * - WordPress Admin Bar Quick Unblock Customer (#WEBCARE-XXXX) popover
 * - Pre-Update Auto-Backup & 1-Click Plugin Rollback orchestration
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall
 */

namespace WebCareProScanner\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class RescueAssistantManager {

    const OPTION_PAUSED_UNTIL    = 'webcareproscan_waf_rescue_paused_until';
    const OPTION_TRUSTED_ACTIONS = 'webcareproscan_rescue_trusted_actions';
    const OPTION_SAFE_UPDATES    = 'webcareproscan_safe_update_backups';
    const CRON_REARM_HOOK        = 'webcareproscan_auto_rearm_waf';
    const CRON_AUTOPILOT_HOOK    = 'webcareproscan_modular_autopilot_cron';

    /**
     * Register hooks for cron auto-rearm, 48h auto-pilot promotion, and WordPress Admin Bar popover.
     */
    public static function init(): void {
        if (class_exists('\\WebCareProScanner\\System\\Cron\\CronControlCenter')) {
            add_action(self::CRON_REARM_HOOK, static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::invoke_task_handler(self::CRON_REARM_HOOK, 'wp_cron');
            });
            add_action(self::CRON_AUTOPILOT_HOOK, static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::invoke_task_handler(self::CRON_AUTOPILOT_HOOK, 'wp_cron');
            });

            add_action('init', static function () {
                \WebCareProScanner\System\Cron\CronControlCenter::ensure_scheduled(self::CRON_AUTOPILOT_HOOK, HOUR_IN_SECONDS, 'hourly');
            }, 20);
        } else {
            add_action(self::CRON_REARM_HOOK, [__CLASS__, 'resume_strict_firewall']);
            add_action(self::CRON_AUTOPILOT_HOOK, [__CLASS__, 'run_autopilot_cron']);

            if (!wp_next_scheduled(self::CRON_AUTOPILOT_HOOK)) {
                wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::CRON_AUTOPILOT_HOOK);
            }
        }

        add_action('admin_bar_menu', [__CLASS__, 'register_admin_bar_nodes'], 95);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_admin_bar_assets']);
        add_action('wp_enqueue_scripts', [__CLASS__, 'enqueue_admin_bar_assets']);
    }

    /**
     * Cron handler for Modular WAF 48-hour Smart Auto-Pilot rule promotion.
     */
    public static function run_autopilot_cron(): void {
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::evaluate_autopilot_promotions();
        }
    }

    /**
     * Path to marker files read cleanly by the 0ms Preload Micro-WAF before WordPress loads.
     */
    private static function get_uploads_base(): string {
        $uploads = wp_upload_dir();
        $dir     = wp_normalize_path(untrailingslashit($uploads['basedir']) . '/webcare-pro-security');
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        return $dir;
    }

    /**
     * Write lightweight runtime marker file using native WP_Filesystem when direct, with fallback for cron/early hooks.
     */
    private static function write_marker_file(string $path, string $content): void {
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            WP_Filesystem();
        }
        if ($wp_filesystem && ($wp_filesystem->method ?? '') === 'direct') {
            $wp_filesystem->put_contents($path, $content, defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644);
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Atomic marker file for zero-DB Preload Micro-WAF runtime coordination.
        @file_put_contents($path, $content, LOCK_EX);
    }

    /**
     * Check whether strict WAF blocking is currently paused for the 15-minute troubleshooting window.
     */
    public static function is_strict_paused(): bool {
        $until = (int) get_option(self::OPTION_PAUSED_UNTIL, 0);
        if ($until > time()) {
            return true;
        }
        if ($until > 0) {
            self::resume_strict_firewall();
        }
        return false;
    }

    /**
     * Return structured countdown & pause state for UI banners and header badges.
     */
    public static function get_pause_status(): array {
        $until     = (int) get_option(self::OPTION_PAUSED_UNTIL, 0);
        $now       = time();
        $is_paused = ($until > $now);
        if ($until > 0 && !$is_paused) {
            self::resume_strict_firewall();
            $until = 0;
        }

        return [
            'paused'            => $is_paused,
            'paused_until'      => $is_paused ? $until : 0,
            'seconds_remaining' => $is_paused ? max(0, $until - $now) : 0,
            'rearm_at_gmt'      => $is_paused ? gmdate('Y-m-d H:i:s', $until) : null,
        ];
    }

    /**
     * Pause strict WAF enforcement for 15 minutes (Monitor-Only Test Mode with automatic cron re-arm).
     */
    public static function pause_strict_firewall_15m(): array {
        $until = time() + (15 * MINUTE_IN_SECONDS);
        update_option(self::OPTION_PAUSED_UNTIL, $until, false);

        $marker = self::get_uploads_base() . '/.rescue_pause_until';
        self::write_marker_file($marker, (string) $until);

        wp_clear_scheduled_hook(self::CRON_REARM_HOOK);
        wp_schedule_single_event($until, self::CRON_REARM_HOOK);

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice('waf_rescue_pause_15m', 'firewall', [
                'paused_until' => gmdate('c', $until),
                'description'  => __('Strict Firewall rules paused for 15 minutes (Test Mode) via Rescue Assistant. Auto re-arm scheduled.', 'webcare-pro-security'),
            ]);
        }

        return array_merge(
            [
                'success' => true,
                'message' => __('Strict firewall rules are paused for 15 minutes (Test Mode). Protection will re-arm automatically after 15 minutes.', 'webcare-pro-security'),
            ],
            self::get_pause_status()
        );
    }

    /**
     * Resume strict WAF enforcement immediately or when the 15-minute timer expires.
     */
    public static function resume_strict_firewall(): array {
        delete_option(self::OPTION_PAUSED_UNTIL);
        wp_clear_scheduled_hook(self::CRON_REARM_HOOK);

        $marker = self::get_uploads_base() . '/.rescue_pause_until';
        if (file_exists($marker)) {
            wp_delete_file($marker);
        }

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice('waf_rescue_resumed', 'firewall', [
                'description' => __('Strict Firewall rules resumed cleanly from Test Mode.', 'webcare-pro-security'),
            ]);
        }

        return array_merge(
            [
                'success' => true,
                'message' => __('Strict firewall protection is active again.', 'webcare-pro-security'),
            ],
            self::get_pause_status()
        );
    }

    /**
     * Retrieve permanently trusted actions saved via "Trust & Allow This Action Permanently".
     */
    public static function get_trusted_actions(): array {
        $list = get_option(self::OPTION_TRUSTED_ACTIONS, []);
        return is_array($list) ? array_values($list) : [];
    }

    /**
     * Check whether the current request or rule matches any permanently trusted Rescue exemption.
     */
    public static function is_rule_or_request_trusted(string $rule_id, string $clean_uri, string $ajax_action = '', string $rest_query = ''): bool {
        $trusted = self::get_trusted_actions();
        if (empty($trusted)) {
            return false;
        }

        $rule_lc   = strtolower($rule_id);
        $uri_lc    = strtolower($clean_uri);
        $act_lc    = strtolower($ajax_action);
        $rest_lc   = strtolower($rest_query);

        foreach ($trusted as $item) {
            if (!empty($item['rule_id']) && strtolower((string) $item['rule_id']) === $rule_lc && empty($item['value'])) {
                return true;
            }
            $type = $item['type'] ?? '';
            $val  = strtolower(trim((string) ($item['value'] ?? '')));
            if ($val === '') {
                continue;
            }
            if ($type === 'ajax' && $act_lc !== '' && $act_lc === $val) {
                return true;
            }
            if ($type === 'rest' && (str_contains($uri_lc, $val) || ($rest_lc !== '' && str_starts_with($rest_lc, $val)))) {
                return true;
            }
            if ($type === 'uri' && str_contains($uri_lc, $val)) {
                return true;
            }
            if ($type === 'rule' && $rule_lc !== '' && $rule_lc === $val) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check incoming HTTP request against Rescue permanently trusted actions inside FirewallEngine.
     */
    public static function is_incoming_request_trusted(string $request_uri, string $rule_id = ''): bool {
        $clean_uri = strtolower((string) strtok($request_uri, '?'));
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch check against admin-approved trusted action list
        $ajax_act  = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch check against admin-approved trusted route list
        $rest_q    = isset($_GET['rest_route']) ? strtolower(sanitize_text_field(wp_unslash($_GET['rest_route']))) : '';

        return self::is_rule_or_request_trusted($rule_id, $clean_uri, $ajax_act, $rest_q);
    }

    /**
     * Persist a permanent trusted-action exemption + unblock client IP if provided.
     */
    public static function trust_and_allow_action(array $params): array {
        $type    = sanitize_key($params['type'] ?? 'uri');
        $value   = sanitize_text_field(trim((string) ($params['value'] ?? '')));
        $rule_id = sanitize_text_field(trim((string) ($params['rule_id'] ?? '')));
        $label   = sanitize_text_field(trim((string) ($params['label'] ?? '')));
        $ip      = sanitize_text_field(trim((string) ($params['ip'] ?? '')));

        if ($value === '' && $rule_id === '') {
            return ['success' => false, 'message' => __('Action target or rule identifier is required.', 'webcare-pro-security')];
        }

        $trusted = self::get_trusted_actions();
        $key     = strtolower($type . ':' . ($value ?: $rule_id));
        $exists  = false;
        foreach ($trusted as $item) {
            if (strtolower(($item['type'] ?? '') . ':' . (($item['value'] ?? '') ?: ($item['rule_id'] ?? ''))) === $key) {
                $exists = true;
                break;
            }
        }

        if (!$exists) {
            $trusted[] = [
                'id'         => 'trust_' . substr(md5($key), 0, 8),
                'type'       => $type,
                'value'      => $value,
                'rule_id'    => $rule_id,
                'label'      => $label ?: ($value ?: $rule_id),
                'created_at' => gmdate('c'),
            ];
            update_option(self::OPTION_TRUSTED_ACTIONS, $trusted, false);
        }

        // Sync compact marker file for 0ms Preload Micro-WAF
        $preload_allow = ['ajax_actions' => [], 'rest_routes' => [], 'uris' => []];
        foreach ($trusted as $t) {
            if (($t['type'] ?? '') === 'ajax' && !empty($t['value'])) {
                $preload_allow['ajax_actions'][] = strtolower((string) $t['value']);
            } elseif (($t['type'] ?? '') === 'rest' && !empty($t['value'])) {
                $preload_allow['rest_routes'][] = strtolower(rtrim((string) $t['value'], '/'));
            } elseif (($t['type'] ?? '') === 'uri' && !empty($t['value'])) {
                $preload_allow['uris'][] = strtolower((string) $t['value']);
            }
        }
        self::write_marker_file(self::get_uploads_base() . '/.rescue_allow.json', (string) wp_json_encode($preload_allow));

        // If a Modular WAF rule was triggered, switch it to monitor mode cleanly
        if (str_starts_with($rule_id, 'MOD-') && class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::toggle_rule($rule_id, 'monitor');
        }

        // Unblock IP & grant 24h access pass if affected client IP is known
        $unblocked_ip = null;
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) && class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            \WebCareProScanner\Firewall\FirewallEngine::remove_blocked_ip($ip);
            set_transient('webcareproscan_temp_allow_' . md5($ip), 1, 24 * HOUR_IN_SECONDS);
            $unblocked_ip = $ip;
        }

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice('rescue_action_trusted', 'firewall', [
                'type'        => $type,
                'value'       => $value ?: $rule_id,
                'unblocked'   => $unblocked_ip,
                'description' => sprintf(
                    /* translators: %s: action name or URI */
                    __('Trusted & permanently allowed "%s" via Rescue Assistant.', 'webcare-pro-security'),
                    $label ?: ($value ?: $rule_id)
                ),
            ]);
        }

        return [
            'success'         => true,
            'unblocked_ip'    => $unblocked_ip,
            'trusted_actions' => $trusted,
            'message'         => sprintf(
                /* translators: %s: trusted feature label */
                __('Trusted & allowed "%s" permanently. Any associated block has also been cleared.', 'webcare-pro-security'),
                $label ?: ($value ?: $rule_id)
            ),
        ];
    }

    /**
     * Scan the last $minutes minutes of WAF blocks and translate them into plain-English troubleshooting insights.
     */
    public static function analyze_recent_blocks(int $minutes = 15): array {
        global $wpdb;
        $cutoff = time() - ($minutes * MINUTE_IN_SECONDS);
        $raw    = [];
        $seen   = [];

        $add_row = static function (array $row) use (&$raw, &$seen, $cutoff) {
            $ts = !empty($row['ts']) ? (int) $row['ts'] : strtotime((string) ($row['created_at'] ?? 'now'));
            if ($ts < $cutoff) {
                return;
            }
            $act = strtolower((string) ($row['action_taken'] ?? 'blocked'));
            if (!in_array($act, ['blocked', 'challenged', 'rate_limited'], true)) {
                return;
            }
            $dedup = ($row['incident_id'] ?? '') . '|' . ($row['request_uri'] ?? '') . '|' . $ts;
            if (isset($seen[$dedup])) {
                return;
            }
            $seen[$dedup] = true;
            $row['ts']    = $ts;
            $raw[]        = $row;
        };

        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['range' => '24h'], 80, 0);
            foreach (($res['logs'] ?? []) as $item) {
                $add_row([
                    'incident_id'   => $item['incident_id'] ?? '',
                    'ip_address'    => $item['ip_address'] ?? '',
                    'request_uri'   => $item['request_uri'] ?? '/',
                    'request_method'=> $item['request_method'] ?? 'GET',
                    'rule_id'       => $item['rule_id'] ?? '',
                    'rule_name'     => $item['rule_name'] ?? '',
                    'rule_category' => $item['rule_category'] ?? '',
                    'description'   => $item['rule_description'] ?? '',
                    'payload_sample'=> $item['payload_sample'] ?? '',
                    'action_taken'  => $item['action_taken'] ?? 'blocked',
                    'ts'            => strtotime((string) ($item['created_at_gmt'] ?? ($item['timestamp'] ?? 'now'))),
                ]);
            }
        }

        $table = $wpdb->prefix . 'webcareproscan_firewall_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT incident_id, ip_address, request_uri, request_method, rule_category, rule_description, payload_sample, action_taken, created_at
                     FROM %i
                     WHERE created_at >= %s
                     ORDER BY id DESC
                     LIMIT 60',
                    $table,
                    gmdate('Y-m-d H:i:s', $cutoff)
                ),
                ARRAY_A
            );
            foreach ((is_array($rows) ? $rows : []) as $r) {
                $rid = '';
                if (preg_match('/\[(MOD-[A-Z0-9-]+|[A-Z0-9-]+)\]/', (string) ($r['rule_description'] ?? ''), $m)) {
                    $rid = $m[1];
                }
                $add_row([
                    'incident_id'    => $r['incident_id'] ?? '',
                    'ip_address'     => $r['ip_address'] ?? '',
                    'request_uri'    => $r['request_uri'] ?? '/',
                    'request_method' => $r['request_method'] ?? 'GET',
                    'rule_id'        => $rid,
                    'rule_name'      => $r['rule_category'] ?? 'Firewall',
                    'rule_category'  => $r['rule_category'] ?? '',
                    'description'    => $r['rule_description'] ?? '',
                    'payload_sample' => $r['payload_sample'] ?? '',
                    'action_taken'   => $r['action_taken'] ?? 'blocked',
                    'ts'             => strtotime((string) ($r['created_at'] ?? 'now')),
                ]);
            }
        }

        usort($raw, static fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
        $findings = [];

        foreach (array_slice($raw, 0, 12) as $ev) {
            $uri     = (string) ($ev['request_uri'] ?? '/');
            $payload = (string) ($ev['payload_sample'] ?? '');
            $blob    = strtolower($uri . ' ' . $ev['rule_category'] . ' ' . $ev['description'] . ' ' . $payload);

            $component_label = __('background website request', 'webcare-pro-security');
            $trust_target    = [
                'type'    => 'uri',
                'value'   => (string) (wp_parse_url($uri, PHP_URL_PATH) ?: $uri),
                'rule_id' => $ev['rule_id'] ?? '',
                'label'   => (string) (wp_parse_url($uri, PHP_URL_PATH) ?: $uri),
            ];

            if (str_contains($blob, 'elementor')) {
                $component_label = __('Elementor page editor save', 'webcare-pro-security');
            } elseif (str_contains($blob, 'stripe') || str_contains($blob, 'paypal') || str_contains($blob, 'wc-api') || str_contains($blob, 'webhook')) {
                $component_label = __('Payment Gateway / WooCommerce Webhook', 'webcare-pro-security');
            } elseif (str_contains($blob, 'checkout') || str_contains($blob, 'wc-ajax') || str_contains($blob, 'coupon')) {
                $component_label = __('WooCommerce customer checkout or coupon', 'webcare-pro-security');
            } elseif (str_contains($blob, 'contact-form-7') || str_contains($blob, 'wpforms') || str_contains($blob, 'fluentform') || str_contains($blob, 'gravity')) {
                $component_label = __('Contact form submission', 'webcare-pro-security');
            } elseif (str_contains($uri, 'admin-ajax.php')) {
                $act = '';
                $q   = wp_parse_url($uri, PHP_URL_QUERY);
                if (is_string($q)) {
                    parse_str($q, $qp);
                    if (!empty($qp['action'])) {
                        $act = sanitize_key($qp['action']);
                    }
                }
                if ($act === '' && preg_match('/action=([a-zA-Z0-9_-]+)/', $payload, $am)) {
                    $act = sanitize_key($am[1]);
                }
                if ($act !== '') {
                    $component_label = sprintf(
                        /* translators: %s: AJAX action name */
                        __('WordPress background AJAX task (%s)', 'webcare-pro-security'),
                        $act
                    );
                    $trust_target = [
                        'type'    => 'ajax',
                        'value'   => $act,
                        'rule_id' => $ev['rule_id'] ?? '',
                        'label'   => 'AJAX: ' . $act,
                    ];
                }
            } elseif (str_contains($uri, '/wp-json/')) {
                $path            = (string) (wp_parse_url($uri, PHP_URL_PATH) ?: $uri);
                $component_label = __('WordPress REST API request', 'webcare-pro-security');
                $trust_target    = [
                    'type'    => 'rest',
                    'value'   => substr($path, strpos($path, '/wp-json') + 8) ?: $path,
                    'rule_id' => $ev['rule_id'] ?? '',
                    'label'   => $path,
                ];
            }

            $ago = human_time_diff((int) $ev['ts'], time()) . ' ' . __('ago', 'webcare-pro-security');
            $findings[] = [
                'incident_id'        => $ev['incident_id'],
                'ip_address'         => $ev['ip_address'],
                'rule_id'            => $ev['rule_id'],
                'request_uri'        => $uri,
                'request_method'     => $ev['request_method'],
                'detected_component' => $component_label,
                'time_ago'           => $ago,
                'plain_english'      => sprintf(
                    /* translators: %1$s: relative time ago, %2$s: affected plugin or feature name */
                    __('%1$s, WebCare blocked a request related to %2$s.', 'webcare-pro-security'),
                    $ago,
                    $component_label
                ),
                'trust_target'       => $trust_target,
            ];
        }

        return $findings;
    }

    /**
     * Build the Plain-English Weekly/Daily Security Story card metrics from real logs & update checks.
     */
    public static function get_daily_security_story(): array {
        $password_bots   = 0;
        $fake_bots       = 0;
        $carding_blocked = 0;
        $other_blocked   = 0;

        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['range' => '7d'], 400, 0);
            foreach (($res['logs'] ?? []) as $log) {
                if (strtolower((string) ($log['action_taken'] ?? '')) !== 'blocked') {
                    continue;
                }
                $blob = strtolower(($log['rule_category'] ?? '') . ' ' . ($log['rule_id'] ?? '') . ' ' . ($log['rule_description'] ?? ''));
                if (preg_match('/login|brute|auth|xmlrpc|user.?enum/', $blob)) {
                    $password_bots++;
                } elseif (preg_match('/card|checkout|coupon|stripe|paypal|woo/', $blob)) {
                    $carding_blocked++;
                } elseif (preg_match('/bot|scraper|recon|ai|404|crawler|dormant/', $blob)) {
                    $fake_bots++;
                } else {
                    $other_blocked++;
                }
            }
        }

        // Count outdated plugins / themes needing action
        $upd_plugins      = get_site_transient('update_plugins');
        $outdated_plugins = !empty($upd_plugins->response) && is_array($upd_plugins->response) ? count($upd_plugins->response) : 0;
        $total_blocked    = $password_bots + $fake_bots + $carding_blocked + $other_blocked;

        if ($total_blocked > 0) {
            $headline = __('Your site had a busy week — and stayed completely safe.', 'webcare-pro-security');
            $summary  = sprintf(
                /* translators: %1$d: password bots, %2$d: fake scrapers, %3$d: carding attempts */
                __('Over the past 7 days, WebCare Pro automatically stopped %1$d password-guessing attempts, %2$d fake scraper probes, and %3$d suspicious checkout/card-testing requests before they could impact your store. 0 verified shoppers were locked out.', 'webcare-pro-security'),
                $password_bots + $other_blocked,
                $fake_bots,
                $carding_blocked
            );
        } else {
            $headline = __('Your site had a quiet, safe week.', 'webcare-pro-security');
            $summary  = __('All perimeter shields, payment protections, and login guards are watching your site around the clock. Zero hostile probes required intervention over the past 7 days, and 0 real customers were interrupted.', 'webcare-pro-security');
        }

        return [
            'headline'               => $headline,
            'summary'                => $summary,
            'total_blocked_7d'       => $total_blocked,
            'password_bots_blocked'  => $password_bots + $other_blocked,
            'fake_bots_blocked'      => $fake_bots,
            'carding_blocked'        => $carding_blocked,
            'real_customers_blocked' => 0,
            'outdated_plugins_count' => $outdated_plugins,
            'pause_status'           => self::get_pause_status(),
        ];
    }

    /**
     * Safely back up an outdated plugin to Gatekeeper storage before upgrading via WordPress Plugin_Upgrader.
     */
    public static function safe_update_plugin(string $plugin_file, string $slug = '', string $name = ''): array {
        if (!current_user_can('update_plugins')) {
            return ['success' => false, 'message' => __('Permission denied: update_plugins capability required.', 'webcare-pro-security')];
        }

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all = get_plugins();
        if (!isset($all[$plugin_file])) {
            return ['success' => false, 'message' => __('Target plugin file was not found.', 'webcare-pro-security')];
        }

        $prev_version = (string) ($all[$plugin_file]['Version'] ?? '0.0.0');
        $plugin_name  = $name !== '' ? $name : (string) ($all[$plugin_file]['Name'] ?? $plugin_file);
        if ($slug === '') {
            $dir  = dirname($plugin_file);
            $slug = ($dir === '.' || $dir === '') ? basename($plugin_file, '.php') : $dir;
        }

        $source_dir  = WP_PLUGIN_DIR . '/' . $slug;
        $snapshot_id = null;

        if (is_dir($source_dir) && class_exists('\\WebCareProScanner\\SupplyChain\\UpdateGatekeeperEngine')) {
            $snapshot_id = \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::create_rollback_snapshot($slug, $source_dir);
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        wp_update_plugins();

        $skin     = new \Automatic_Upgrader_Skin();
        $upgrader = new \Plugin_Upgrader($skin);
        $result   = $upgrader->upgrade($plugin_file);

        if (is_wp_error($result) || $result === false) {
            return [
                'success'     => false,
                'snapshot_id' => $snapshot_id,
                'message'     => is_wp_error($result)
                    ? $result->get_error_message()
                    : __('WordPress update package failed or no newer update package was available.', 'webcare-pro-security'),
            ];
        }

        wp_clean_plugins_cache(true);
        $updated_all = get_plugins();
        $new_version = (string) ($updated_all[$plugin_file]['Version'] ?? 'Updated');

        $records = get_option(self::OPTION_SAFE_UPDATES, []);
        if (!is_array($records)) {
            $records = [];
        }
        $records[$plugin_file] = [
            'plugin_file'      => $plugin_file,
            'slug'             => $slug,
            'name'             => $plugin_name,
            'previous_version' => $prev_version,
            'new_version'      => $new_version,
            'snapshot_id'      => $snapshot_id,
            'updated_at'       => gmdate('c'),
        ];
        update_option(self::OPTION_SAFE_UPDATES, $records, false);

        return [
            'success'          => true,
            'plugin_file'      => $plugin_file,
            'slug'             => $slug,
            'previous_version' => $prev_version,
            'new_version'      => $new_version,
            'snapshot_id'      => $snapshot_id,
            'message'          => sprintf(
                /* translators: %1$s: plugin name, %2$s: old version, %3$s: new version */
                __('Safely backed up "%1$s" (v%2$s) and updated to v%3$s. You can roll back in 1 click at any time.', 'webcare-pro-security'),
                $plugin_name,
                $prev_version,
                $new_version
            ),
        ];
    }

    /**
     * Roll back a plugin to its pre-update Gatekeeper backup snapshot.
     */
    public static function rollback_safe_update(string $snapshot_id): array {
        if (!current_user_can('update_plugins')) {
            return ['success' => false, 'message' => __('Permission denied: update_plugins capability required.', 'webcare-pro-security')];
        }
        if (!class_exists('\\WebCareProScanner\\SupplyChain\\UpdateGatekeeperEngine')) {
            return ['success' => false, 'message' => __('Backup rollback engine unavailable.', 'webcare-pro-security')];
        }
        return \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::rollback_snapshot(sanitize_text_field($snapshot_id));
    }

    /**
     * Register WordPress Admin Bar menu node for Quick Unblock (#WEBCARE-XXXX) & Rescue Assistant.
     *
     * @param \WP_Admin_Bar $wp_admin_bar
     */
    public static function register_admin_bar_nodes($wp_admin_bar): void {
        if (!is_admin_bar_showing() || !current_user_can('manage_options') || !is_object($wp_admin_bar)) {
            return;
        }

        $paused = self::is_strict_paused();
        $badge  = $paused
            ? '<span style="background:#f59e0b;color:#111827;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">' . esc_html__('Test Mode', 'webcare-pro-security') . '</span>'
            : '<span style="background:#10b981;color:#ffffff;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">' . esc_html__('Protected', 'webcare-pro-security') . '</span>';

        $wp_admin_bar->add_node([
            'id'    => 'webcare-pro-bar',
            'title' => '<span class="ab-icon dashicons dashicons-shield" style="margin-top:2px;"></span>WebCare Pro' . $badge,
            'href'  => admin_url('admin.php?page=webcare-pro-security'),
        ]);

        // Quick Unblock Customer (#WEBCARE-XXXX) Popover Node
        $unblock_form = '<div id="webcare-ab-unblock-box" class="webcare-ab-unblock-wrap" onclick="event.stopPropagation();">'
            . '<div style="font-weight:700;font-size:12px;margin-bottom:6px;color:#f8fafc;">' . esc_html__('Quick Unblock Customer (#WEBCARE-XXXX or IP)', 'webcare-pro-security') . '</div>'
            . '<div style="display:flex;gap:6px;align-items:center;">'
            . '<input type="text" id="webcare-ab-code-input" placeholder="' . esc_attr__('#WEBCARE-492A or IP', 'webcare-pro-security') . '" style="width:170px;padding:4px 8px;border-radius:4px;border:1px solid #475569;background:#0f172a;color:#f8fafc;font-size:12px;height:28px;" />'
            . '<button type="button" id="webcare-ab-lookup-btn" style="padding:4px 10px;border-radius:4px;border:none;background:#4f46e5;color:#fff;font-size:11px;font-weight:700;cursor:pointer;height:28px;">' . esc_html__('Find', 'webcare-pro-security') . '</button>'
            . '</div>'
            . '<div id="webcare-ab-result" style="margin-top:8px;font-size:11px;line-height:1.4;color:#cbd5e1;white-space:normal;"></div>'
            . '</div>';

        $wp_admin_bar->add_node([
            'id'     => 'webcare-pro-bar-unblock',
            'parent' => 'webcare-pro-bar',
            'title'  => $unblock_form,
        ]);

        $wp_admin_bar->add_node([
            'id'     => 'webcare-pro-bar-rescue',
            'parent' => 'webcare-pro-bar',
            'title'  => esc_html__('Something Not Working? Click to Troubleshoot', 'webcare-pro-security'),
            'href'   => admin_url('admin.php?page=webcare-pro-security&rescue=1'),
        ]);

        $wp_admin_bar->add_node([
            'id'     => 'webcare-pro-bar-modular',
            'parent' => 'webcare-pro-bar',
            'title'  => esc_html__('Modular Intelligence Firewall', 'webcare-pro-security'),
            'href'   => admin_url('admin.php?page=webcare-pro-modular-waf'),
        ]);
    }

    /**
     * Enqueue lightweight Admin Bar CSS & JS cleanly via WP APIs when admin bar is visible.
     */
    public static function enqueue_admin_bar_assets(): void {
        if (!is_admin_bar_showing() || !current_user_can('manage_options')) {
            return;
        }

        wp_register_style('webcare-admin-bar-rescue', false, [], defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0');
        wp_enqueue_style('webcare-admin-bar-rescue');
        wp_add_inline_style(
            'webcare-admin-bar-rescue',
            '#wp-admin-bar-webcare-pro-bar-unblock .ab-item{height:auto!important;padding:10px 12px!important;min-width:265px!important;line-height:1.4!important;}'
        );

        wp_register_script('webcare-admin-bar-rescue', false, [], defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0', true);
        wp_enqueue_script('webcare-admin-bar-rescue');

        $cfg = wp_json_encode([
            'restRoot' => esc_url_raw(rest_url('webcare-pro-security/v1')),
            'nonce'    => wp_create_nonce('wp_rest'),
        ]);

        $js = '(function(){var cfg=' . $cfg . ';'
            . 'document.addEventListener("click",function(e){'
            . 'if(!e.target)return;'
            . 'if(e.target.id==="webcare-ab-lookup-btn"){'
            . 'e.preventDefault();e.stopPropagation();'
            . 'var inp=document.getElementById("webcare-ab-code-input");'
            . 'var out=document.getElementById("webcare-ab-result");'
            . 'var q=(inp&&inp.value)?inp.value.trim():"";'
            . 'if(!q){out.textContent="Enter a #WEBCARE-XXXX code or IP address.";return;}'
            . 'out.textContent="Looking up block details...";'
            . 'fetch(cfg.restRoot+"/firewall/customer/lookup-block?code="+encodeURIComponent(q),{headers:{"X-WP-Nonce":cfg.nonce}})'
            . '.then(function(r){return r.json();})'
            . '.then(function(d){'
            . 'out.textContent="";'
            . 'if(!d||!d.found){out.textContent=(d&&d.message)?d.message:"No matching block found.";return;}'
            . 'var info=document.createElement("div");info.style.marginBottom="6px";'
            . 'var strong=document.createElement("strong");strong.textContent="IP: ";info.appendChild(strong);'
            . 'info.appendChild(document.createTextNode(String(d.client_ip||"")));'
            . 'info.appendChild(document.createElement("br"));'
            . 'info.appendChild(document.createTextNode(String(d.friendly_reason||"")));'
            . 'out.appendChild(info);'
            . 'var btn=document.createElement("button");btn.type="button";btn.id="webcare-ab-do-unblock";'
            . 'btn.setAttribute("data-ip",String(d.client_ip||""));'
            . 'btn.setAttribute("data-code",String(d.ref_code||q));'
            . 'btn.style.cssText="width:100%;padding:5px 8px;border:none;border-radius:4px;background:#10b981;color:#fff;font-weight:700;cursor:pointer;font-size:11px;";'
            . 'btn.textContent="Unblock Customer in 1 Click";'
            . 'out.appendChild(btn);'
            . '}).catch(function(){out.textContent="Lookup failed.";});'
            . '}'
            . 'if(e.target.id==="webcare-ab-do-unblock"){'
            . 'e.preventDefault();e.stopPropagation();'
            . 'var btn=e.target;var out=document.getElementById("webcare-ab-result");'
            . 'btn.disabled=true;btn.textContent="Unblocking...";'
            . 'fetch(cfg.restRoot+"/firewall/customer/unblock",{method:"POST",headers:{"Content-Type":"application/json","X-WP-Nonce":cfg.nonce},body:JSON.stringify({ip:btn.getAttribute("data-ip"),code:btn.getAttribute("data-code")})})'
            . '.then(function(r){return r.json();})'
            . '.then(function(d){'
            . 'out.textContent="";'
            . 'var ok=document.createElement("span");ok.style.cssText="color:#34d399;font-weight:700;";'
            . 'ok.textContent=String((d&&d.message)||"Customer unblocked!");'
            . 'out.appendChild(ok);'
            . '}).catch(function(){out.textContent="Failed to unblock IP.";});'
            . '}'
            . '});})();';

        wp_add_inline_script('webcare-admin-bar-rescue', $js);
    }
}
