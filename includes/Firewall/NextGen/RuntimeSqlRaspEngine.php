<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RuntimeSqlRaspEngine
 *
 * Hooks WordPress's `query` filter strictly for unauthenticated guest requests hitting
 * AJAX / non-core REST / custom plugin entrypoints to abort zero-day SQL injection AST anomalies
 * before MySQL executes them.
 */
class RuntimeSqlRaspEngine implements SecurityModuleInterface {

    const OPTION_EVENTS = 'webcareproscan_sql_rasp_events';

    /** @var bool Prevent recursive option updates while inside query filter */
    private static bool $in_guard = false;

    public function get_id(): string {
        return 'runtime-sql-rasp';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Runtime SQL Query AST RASP Guard', 'webcare-pro-security'),
            'description' => __('Inspects live database queries during unauthenticated plugin/AJAX/REST requests to neutralize zero-day blind and second-order SQL injections before execution.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_sql_rasp_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'Next-Gen RASP',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_filter('query', [__CLASS__, 'inspect_guest_sql_query'], 1);
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_sql_rasp_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Runtime SQL Query AST RASP Guard', 'webcare-pro-security'),
            ],
            'waf_nextgen_sql_rasp_auto_ban' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Auto-Ban SQL RASP Offenders on Cloudflare Edge', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/sql-rasp-events',
                'methods'  => 'GET',
                'callback' => static function () {
                    $events = get_option(self::OPTION_EVENTS, []);
                    return new \WP_REST_Response([
                        'success' => true,
                        'events'  => is_array($events) ? $events : [],
                    ], 200);
                },
            ],
        ];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_get_sql_rasp_events',
                'description' => 'List intercepted zero-day SQL injection AST anomalies caught inside WordPress query RASP.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
                'handler'     => static function () {
                    $events = get_option(self::OPTION_EVENTS, []);
                    return [
                        'isError' => false,
                        'content' => [[
                            'type' => 'text',
                            'text' => (string) wp_json_encode(['events' => is_array($events) ? $events : []]),
                        ]],
                    ];
                },
            ],
        ];
    }

    /**
     * Evaluate whether current request satisfies the strict 3-gate guest plugin surface check.
     * Always evaluates zero-cost URI and runtime checks BEFORE invoking WordPress user/DB lookups.
     */
    public static function is_guest_plugin_surface(): bool {
        if ((defined('WP_CLI') && WP_CLI) || (function_exists('wp_doing_cron') && wp_doing_cron()) || (function_exists('wp_installing') && wp_installing())) {
            return false;
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read-only surface routing check inside RASP guard
        $uri = strtolower((string) wp_unslash($_SERVER['REQUEST_URI'] ?? ''));
        $is_target_surface = (
            strpos($uri, 'admin-ajax.php') !== false
            || strpos($uri, 'admin-post.php') !== false
            || strpos($uri, 'rest_route=') !== false
            || (strpos($uri, '/wp-json/') !== false && strpos($uri, '/wp-json/webcare-pro-security/') === false)
        );
        if (!$is_target_surface) {
            return false;
        }

        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            return false;
        }
        if (class_exists(FirewallEngine::class)) {
            if (FirewallEngine::is_authenticated_administrator() || FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Pure testable SQL AST anomaly analyzer (strips quoted literals before structural checks).
     *
     * @param string $sql
     * @return string|null Anomaly identifier if dangerous AST construct found, null otherwise.
     */
    public static function detect_sql_anomaly(string $sql): ?string {
        global $wpdb;

        $trimmed = trim($sql);
        if ($trimmed === '') {
            return null;
        }

        $users_tbl    = isset($wpdb->users) ? preg_quote($wpdb->users, '/') : 'wp_users';
        $usermeta_tbl = isset($wpdb->usermeta) ? preg_quote($wpdb->usermeta, '/') : 'wp_usermeta';
        $options_tbl  = isset($wpdb->options) ? preg_quote($wpdb->options, '/') : 'wp_options';
        $posts_tbl    = isset($wpdb->posts) ? preg_quote($wpdb->posts, '/') : 'wp_posts';

        // Never block WebCare's own internal queries or standard WP transient writes
        if (stripos($trimmed, 'webcareproscan_') !== false || stripos($trimmed, 'SELECT NULL WHERE 1=0') === 0) {
            return null;
        }

        // Strip balanced string literals to prevent false positives on blog/post text content
        $skeleton = (string) preg_replace("/'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"/", "''", $trimmed);

        // 1. Cross-table UNION SELECT touching credential/usermeta tables
        if (preg_match('/\bUNION\s+(?:ALL\s+)?SELECT\b/i', $skeleton) && preg_match('/\b(?:' . $users_tbl . '|' . $usermeta_tbl . ')\b/i', $skeleton)) {
            return 'UNION_SELECT_CREDENTIAL_TABLE';
        }

        // 2. INFORMATION_SCHEMA metadata probing or time/file SQLi primitives in unquoted SQL skeleton
        if (preg_match('/\bINFORMATION_SCHEMA\.(?:TABLES|COLUMNS|SCHEMATA|USER_PRIVILEGES)\b/i', $skeleton)) {
            return 'INFORMATION_SCHEMA_PROBE';
        }
        if (preg_match('/\b(?:SLEEP|BENCHMARK)\s*\(/i', $skeleton)) {
            return 'TIME_BLIND_SQL_FUNCTION';
        }
        if (preg_match('/\bLOAD_FILE\s*\(/i', $skeleton) || preg_match('/\bINTO\s+(?:OUT|DUMP)FILE\b/i', $skeleton)) {
            return 'FILE_IO_SQLI_PRIMITIVE';
        }

        // 3. Unauthenticated critical privilege mutations inside guest plugin contexts
        if (preg_match('/^\s*(?:INSERT\s+(?:IGNORE\s+)?INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+`?' . $users_tbl . '`?\b/i', $skeleton)) {
            return 'UNAUTH_USERS_TABLE_MUTATION';
        }
        if (
            preg_match('/^\s*UPDATE\s+`?' . $options_tbl . '`?\s+SET\b/i', $skeleton)
            && preg_match('/\b(?:siteurl|home|users_can_register|default_role|active_plugins|admin_email)\b/i', $trimmed)
        ) {
            return 'UNAUTH_CRITICAL_OPTION_SQL_MUTATION';
        }
        if (preg_match('/^\s*DELETE\s+FROM\s+`?' . $posts_tbl . '`?\b/i', $skeleton) && stripos($skeleton, 'WHERE') === false) {
            return 'UNAUTH_MASS_POST_DELETE';
        }

        return null;
    }

    /**
     * WordPress `query` filter callback aborting dangerous guest plugin SQL queries before MySQL executes them.
     *
     * @param string $query
     * @return string
     */
    public static function inspect_guest_sql_query(string $query): string {
        if (self::$in_guard) {
            return $query;
        }

        self::$in_guard = true;
        try {
            if (!self::is_guest_plugin_surface()) {
                return $query;
            }

            $anomaly = self::detect_sql_anomaly($query);
            if ($anomaly === null) {
                return $query;
            }

            $caller = self::resolve_culprit_caller();
            $ip     = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : '127.0.0.1';
            $uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

            $rule_id = 'WAF-SQL-RASP-' . $anomaly;
            $reason  = sprintf('Runtime SQL RASP aborted anomalous guest query (%s) originating from %s', $anomaly, $caller);

            self::record_event($ip, $anomaly, $caller, $uri);

            if (class_exists(FirewallEngine::class)) {
                FirewallEngine::log_incident([
                    'id'          => $rule_id,
                    'name'        => 'Runtime SQL Query AST RASP Guard',
                    'category'    => 'Next-Gen SQL RASP Defense',
                    'description' => $reason,
                    'match_type'  => 'SQL AST Anomaly',
                    'match_value' => $anomaly,
                    'payload'     => "Caller: {$caller} URI: {$uri}",
                ], 'blocked');

                $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
                    ? \WebCareProScanner\System\SettingsManager::get_settings()
                    : [];
                if (!empty($settings['waf_nextgen_sql_rasp_auto_ban']) && !FirewallEngine::is_server_origin_or_loopback($ip)) {
                    FirewallEngine::add_blocked_ip(
                        $ip,
                        $reason,
                        86400,
                        $rule_id,
                        'Runtime SQL RASP Guard',
                        'Next-Gen SQL RASP Defense',
                        null,
                        null,
                        true
                    );
                }
            }
        } finally {
            self::$in_guard = false;
        }

        // Safely neutralize execution in MySQL without risking table corruption
        return 'SELECT NULL WHERE 1=0';
    }

    /**
     * Resolve first plugin/theme frame from debug_backtrace for attribution.
     */
    private static function resolve_culprit_caller(): string {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Security forensics attribution to pinpoint vulnerable plugin file on blocked SQLi query
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15);
        foreach ($frames as $frame) {
            $file = isset($frame['file']) ? wp_normalize_path((string) $frame['file']) : '';
            if ($file === '' || strpos($file, 'wcp-security-scanner') !== false || strpos($file, 'webcare-pro-security') !== false) {
                continue;
            }
            if (strpos($file, '/wp-content/plugins/') !== false || strpos($file, '/wp-content/themes/') !== false) {
                $rel  = preg_replace('#^.*/wp-content/#', 'wp-content/', $file);
                $line = intval($frame['line'] ?? 0);
                return $rel . ':' . $line;
            }
        }
        return 'wp-content/unknown';
    }

    /**
     * Record bounded RASP telemetry history.
     */
    private static function record_event(string $ip, string $anomaly, string $caller, string $uri): void {
        $events = get_option(self::OPTION_EVENTS, []);
        if (!is_array($events)) {
            $events = [];
        }
        array_unshift($events, [
            'timestamp' => time(),
            'ip'        => sanitize_text_field($ip),
            'anomaly'   => sanitize_key($anomaly),
            'caller'    => sanitize_text_field($caller),
            'uri'       => sanitize_text_field(substr($uri, 0, 160)),
        ]);
        if (count($events) > 50) {
            $events = array_slice($events, 0, 50);
        }
        update_option(self::OPTION_EVENTS, $events, false);
    }
}
