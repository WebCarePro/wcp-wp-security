<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Event Schema Validator & Factory for WCP Activity & Audit Logging.
 *
 * Enforces:
 * - Dual attribution: Actor (originating human or system) vs. Executor (execution context).
 * - Standardized severity enum ('info', 'notice', 'warning', 'error', 'critical').
 * - Standardized categories ('settings', 'scan', 'quarantine', 'firewall', 'crashguard', 'retention', 'auth', 'system').
 * - Microsecond integer durations and integer timestamps (strictly no floats).
 */
class ActivityEventSchema {

    public const SEVERITY_INFO     = 'info';
    public const SEVERITY_NOTICE   = 'notice';
    public const SEVERITY_WARNING  = 'warning';
    public const SEVERITY_ERROR    = 'error';
    public const SEVERITY_CRITICAL = 'critical';

    public const VALID_SEVERITIES = [
        self::SEVERITY_INFO,
        self::SEVERITY_NOTICE,
        self::SEVERITY_WARNING,
        self::SEVERITY_ERROR,
        self::SEVERITY_CRITICAL,
    ];

    public const VALID_CATEGORIES = [
        'settings',
        'scan',
        'quarantine',
        'firewall',
        'crashguard',
        'retention',
        'auth',
        'system',
    ];

    /**
     * Create and validate a normalized event data array ready for canonicalization and hashing.
     *
     * @param string      $action         Stable machine-readable action identifier (e.g. 'settings_updated').
     * @param string      $category       Event category.
     * @param string      $severity       Severity level.
     * @param array       $details        Event details and diffs (will be redacted).
     * @param array|null  $actor_override Custom actor snapshot if not deriving from current user/context.
     * @param string|null $correlation_id Correlation ID grouping related operations.
     * @return array
     */
    public static function build_event(
        string $action,
        string $category,
        string $severity = self::SEVERITY_INFO,
        array $details = [],
        ?array $actor_override = null,
        ?string $correlation_id = null
    ): array {
        // Validate category
        if (!in_array($category, self::VALID_CATEGORIES, true)) {
            $category = 'system';
        }

        // Validate severity
        if (!in_array($severity, self::VALID_SEVERITIES, true)) {
            $severity = self::SEVERITY_INFO;
        }

        $now = time();
        $event_id = 'act_' . wp_generate_password(16, false, false);
        if (empty($correlation_id)) {
            $correlation_id = 'req_' . substr(md5(uniqid('wcp_corr_', true)), 0, 16);
        }

        // Resolve Actor
        $actor = $actor_override ?? self::resolve_actor();

        // Resolve Executor
        $executor = self::resolve_executor();

        // Deep redact details
        $clean_details = ActivityRedactor::redact($details);
        if (empty($clean_details)) {
            $clean_details = (object) [];
        }

        return [
            'action'         => sanitize_key($action),
            'actor'          => $actor,
            'category'       => $category,
            'correlation_id' => sanitize_text_field($correlation_id),
            'datetime'       => gmdate('Y-m-d\TH:i:s\Z', $now),
            'details'        => $clean_details,
            'event_id'       => $event_id,
            'executor'       => $executor,
            'severity'       => $severity,
            'timestamp'      => (int) $now,
        ];
    }

    /**
     * Resolve the originating Actor based on the active execution context.
     *
     * @return array
     */
    public static function resolve_actor(): array {
        if (defined('DOING_CRON') && DOING_CRON) {
            return [
                'display_name' => 'System (WP-Cron)',
                'id'           => 0,
                'ip'           => '127.0.0.1',
                'role'         => 'system',
                'type'         => 'system',
                'user_agent'   => 'WordPress/' . get_bloginfo('version') . '; Cron',
                'user_login'   => 'System',
            ];
        }

        if (defined('WP_CLI') && WP_CLI) {
            return [
                'display_name' => 'System (WP-CLI)',
                'id'           => 0,
                'ip'           => '127.0.0.1',
                'role'         => 'sysadmin',
                'type'         => 'system',
                'user_agent'   => 'WP-CLI',
                'user_login'   => 'System',
            ];
        }

        $current_user = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
        if ($current_user && $current_user->exists()) {
            $roles = (array) $current_user->roles;
            $primary_role = !empty($roles) ? reset($roles) : 'none';
            return [
                'display_name' => (string) $current_user->display_name,
                'id'           => (int) $current_user->ID,
                'ip'           => self::get_client_ip(),
                'role'         => (string) $primary_role,
                'type'         => 'user',
                'user_agent'   => isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 255) : '',
                'user_login'   => (string) $current_user->user_login,
            ];
        }

        return [
            'display_name' => 'System (Automated Subsystem)',
            'id'           => 0,
            'ip'           => self::get_client_ip(),
            'role'         => 'system',
            'type'         => 'system',
            'user_agent'   => isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 255) : '',
            'user_login'   => 'System',
        ];
    }

    /**
     * Resolve the active PHP execution context (Executor).
     *
     * @return array
     */
    public static function resolve_executor(): array {
        $pid = function_exists('getmypid') ? (int) getmypid() : 0;

        if (defined('WP_CLI') && WP_CLI) {
            return [
                'identifier' => 'wp_cli',
                'pid'        => $pid,
                'type'       => 'cli',
            ];
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return [
                'identifier' => 'wp_cron',
                'pid'        => $pid,
                'type'       => 'cron',
            ];
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            $route = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            return [
                'identifier' => 'rest_api:' . substr($route, 0, 100),
                'pid'        => $pid,
                'type'       => 'rest_api',
            ];
        }

        if (defined('DOING_AJAX') && DOING_AJAX) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Context logging for ajax action identifier
            $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : 'unknown';
            return [
                'identifier' => 'admin_ajax:' . $action,
                'pid'        => $pid,
                'type'       => 'ajax',
            ];
        }

        return [
            'identifier' => 'web_request',
            'pid'        => $pid,
            'type'       => 'web',
        ];
    }

    /**
     * Extract and sanitize client IP address.
     *
     * @return string
     */
    private static function get_client_ip(): string {
        $ip = '127.0.0.1';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Forensic client IP resolution before authentication
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '127.0.0.1';
    }
}
