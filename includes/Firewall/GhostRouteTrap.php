<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\AuditLogger;
use WcpScanner\Cloudflare\CloudflareService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * GhostRouteTrap
 *
 * Autonomous AI Pentest Bot & Decoy Canary Trap.
 * Renders invisible canary honey-links on public templates and registers phantom REST endpoints.
 * Detects, fingerprints, and neutralizes autonomous LLM crawlers, automated reconnaissance bots,
 * and malicious vulnerability scanners the moment they probe phantom attack surfaces.
 */
class GhostRouteTrap {

    const OPTION_SETTINGS    = 'wcpscan_ghost_trap_settings';
    const OPTION_CATCHES     = 'wcpscan_ghost_trap_catches';
    const CANARY_QUERY_VAR   = 'wcp_canary_trap';
    const CANARY_PATH_PREFIX = 'wcp-internal-canary-bot-trap';

    /**
     * Phantom decoy REST endpoints.
     */
    const PHANTOM_REST_ROUTES = [
        'telemetry' => '/wcp-internal/v1/telemetry-debug',
        'sysenv'    => '/wcp-core/v1/system-env',
        'dbdump'    => '/wcp-admin/v1/database-dump',
    ];

    /**
     * Initialize Ghost Route Trap hooks.
     */
    public static function init() {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        // 1. Intercept early canary query and URI probes
        add_action('init', [__CLASS__, 'inspect_canary_probes'], 0);

        // 2. Register phantom REST API canary routes
        add_action('rest_api_init', [__CLASS__, 'register_phantom_rest_routes']);

        // 3. Render invisible canary decoy links in public and login footers
        if (!empty($settings['inject_canary_links'])) {
            add_action('wp_footer', [__CLASS__, 'render_canary_links'], 9999);
            add_action('login_footer', [__CLASS__, 'render_canary_links'], 9999);
        }

        // 4. Inject robots.txt exclusion directives to keep compliant crawlers off decoy routes
        add_filter('robots_txt', [__CLASS__, 'filter_robots_txt'], 10, 2);
    }

    /**
     * Get Ghost Route Trap settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'              => true,
            'inject_canary_links'  => true,
            'block_client_ip'      => false, // Default to monitor/detect mode for zero-breakage safety
            'sync_cloudflare_edge' => false, // Require explicit admin opt-in for automated Cloudflare Edge bans
            'tarpit_duration'      => 0,     // 0 = instant 403, >0 = artificial delay
        ];
        $saved = get_option(self::OPTION_SETTINGS, []);
        return is_array($saved) ? array_merge($defaults, $saved) : $defaults;
    }

    /**
     * Update Ghost Route Trap settings.
     *
     * @param array $settings
     * @return bool
     */
    public static function update_settings(array $settings): bool {
        $current = self::get_settings();
        $updated = [
            'enabled'              => !empty($settings['enabled']),
            'inject_canary_links'  => !empty($settings['inject_canary_links']),
            'block_client_ip'      => !empty($settings['block_client_ip']),
            'sync_cloudflare_edge' => !empty($settings['sync_cloudflare_edge']),
            'tarpit_duration'      => isset($settings['tarpit_duration']) ? min(10, max(0, (int) $settings['tarpit_duration'])) : 0,
        ];
        return update_option(self::OPTION_SETTINGS, array_merge($current, $updated), false);
    }

    /**
     * Register phantom REST API decoy routes.
     */
    public static function register_phantom_rest_routes() {
        foreach (self::PHANTOM_REST_ROUTES as $key => $route) {
            $parts = explode('/', ltrim($route, '/'));
            $namespace = $parts[0] . '/' . $parts[1];
            $endpoint  = '/' . implode('/', array_slice($parts, 2));

            register_rest_route($namespace, $endpoint, [
                'methods'             => ['GET', 'POST', 'PUT', 'DELETE'],
                'callback'            => function () use ($route) {
                    return self::handle_trap_activation('phantom_rest_route', $route);
                },
                'permission_callback' => '__return_true', // Intentionally open to bait unauthenticated bots
            ]);
        }
    }

    /**
     * Inspect early request probes for canary honey-tokens.
     */
    public static function inspect_canary_probes() {
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        
        // 1. Check query parameter canary probe
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET[self::CANARY_QUERY_VAR]) && sanitize_text_field(wp_unslash($_GET[self::CANARY_QUERY_VAR])) === '1') {
            self::handle_trap_activation('canary_query_parameter', $raw_uri);
        }

        // 2. Check path-based canary probe
        if (str_contains($raw_uri, self::CANARY_PATH_PREFIX)) {
            self::handle_trap_activation('canary_path_probe', $raw_uri);
        }
    }

    /**
     * Handle trap activation when a bot touches a canary.
     *
     * @param string $trigger_type
     * @param string $target_surface
     */
    public static function handle_trap_activation(string $trigger_type, string $target_surface) {
        $ip = self::get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';
        $settings = self::get_settings();

        // 0. Search Engine & Uptime Monitor Immunity:
        // Genuine search crawlers (Googlebot, Bingbot, etc.) or verified uptime monitors must NEVER be banned or blocked.
        $is_genuine_crawler = false;
        if (class_exists('\\WcpScanner\\Firewall\\BotReconDefense')) {
            $is_genuine_crawler = BotReconDefense::is_genuine_search_engine($ip, $user_agent)
                || BotReconDefense::is_genuine_uptime_monitor($ip, $user_agent, $settings);
        }

        if ($is_genuine_crawler) {
            status_header(404);
            nocache_headers();
            header('X-Robots-Tag: noindex, nofollow, noarchive');
            header('Content-Type: text/plain; charset=utf-8');
            echo "Not Found\n";
            exit;
        }

        // 1. Record catch telemetry
        $catches = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            $catches = [];
        }

        $event = [
            'id'             => 'ghost_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
            'ip'             => $ip,
            'trigger'        => sanitize_key($trigger_type),
            'target'         => esc_url_raw($target_surface),
            'user_agent'     => substr($user_agent, 0, 180),
            'timestamp'      => current_time('mysql'),
            'action_taken'   => !empty($settings['block_client_ip']) ? 'blocked' : 'logged',
        ];

        array_unshift($catches, $event);
        if (count($catches) > 100) {
            $catches = array_slice($catches, 0, 100);
        }
        update_option(self::OPTION_CATCHES, $catches, false);

        // 2. Forensic Incident Logging
        if (class_exists('\\WcpScanner\\Firewall\\WafFileLogger')) {
            WafFileLogger::log_incident([
                'category'    => 'ghost_route_trap',
                'rule_id'     => 'wcp_canary_ai_trap',
                'description' => sprintf('Autonomous reconnaissance or AI scraper probed canary honeypot: %s (%s)', $trigger_type, $target_surface),
                'payload'     => $target_surface,
            ], !empty($settings['block_client_ip']) ? 'blocked' : 'detected');
        }

        AuditLogger::log(
            'ghost_route_triggered',
            sprintf('Autonomous bot trap triggered by IP %s on canary surface "%s". Action: %s.', $ip, $target_surface, strtoupper($event['action_taken']))
        );

        // 3. Block client IP if enabled
        if (!empty($settings['block_client_ip']) && class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            FirewallEngine::add_blocked_ip($ip);
        }

        // 4. Sync to Cloudflare Edge IP Lists if configured
        if (!empty($settings['sync_cloudflare_edge']) && class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
            try {
                CloudflareService::add_to_ip_list($ip, 'WCP Decoy Ghost Trap Probed');
            } catch (\Throwable $e) {
                // Ignore Cloudflare API network failure during high-speed mitigation
            }
        }

        // 5. Artificial delay if tarpit duration is configured
        if (!empty($settings['tarpit_duration']) && $settings['tarpit_duration'] > 0) {
            sleep((int) $settings['tarpit_duration']);
        }

        // 6. Terminate request with 403 Forbidden payload
        status_header(403);
        nocache_headers();
        header('X-Robots-Tag: noindex, nofollow, noarchive');
        header('Content-Type: application/json; charset=utf-8');
        echo wp_json_encode([
            'code'    => 'wcp_canary_intercept',
            'message' => 'Automated access prohibited. Canary trap activated.',
            'status'  => 403,
        ]);
        exit;
    }

    /**
     * Filter virtual robots.txt output to instruct compliant web crawlers to ignore canary traps.
     *
     * @param string $output
     * @param bool $public
     * @return string
     */
    public static function filter_robots_txt(string $output, bool $public): string {
        $output .= "\n# WCP Decoy Canary Shield - Prohibit Automated Traversal\n";
        $output .= "Disallow: /" . self::CANARY_PATH_PREFIX . "/\n";
        $output .= "Disallow: /*" . self::CANARY_QUERY_VAR . "=\n";
        return $output;
    }

    /**
     * Render hidden canary link in public and login HTML templates.
     */
    public static function render_canary_links() {
        $canary_url = esc_url(add_query_arg(self::CANARY_QUERY_VAR, '1', home_url('/')));
        $path_canary = esc_url(home_url('/' . self::CANARY_PATH_PREFIX . '/telemetry'));

        echo "\n<!-- Internal Diagnostics Canary Shield -->\n";
        echo '<div style="position:absolute;left:-9999px;top:-9999px;opacity:0;pointer-events:none;z-index:-1;" aria-hidden="true" tabindex="-1" data-nosnippet="true">';
        echo '<a href="' . esc_url($canary_url) . '" rel="nofollow noindex noarchive" tabindex="-1">System Telemetry Diagnostics</a>';
        echo '<a href="' . esc_url($path_canary) . '" rel="nofollow noindex noarchive" tabindex="-1">Internal Environment Dump</a>';
        echo "</div>\n";
    }

    /**
     * Retrieve status telemetry and event history for the dashboard.
     *
     * @return array
     */
    public static function get_status(): array {
        $settings = self::get_settings();
        $catches  = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            $catches = [];
        }

        return [
            'enabled'              => !empty($settings['enabled']),
            'inject_canary_links'  => !empty($settings['inject_canary_links']),
            'block_client_ip'      => !empty($settings['block_client_ip']),
            'sync_cloudflare_edge' => !empty($settings['sync_cloudflare_edge']),
            'tarpit_duration'      => $settings['tarpit_duration'] ?? 0,
            'total_catches'        => count($catches),
            'phantom_routes'       => array_values(self::PHANTOM_REST_ROUTES),
            'recent_catches'       => array_slice($catches, 0, 25),
        ];
    }

    /**
     * Helper to safely resolve client IP.
     *
     * @return string
     */
    private static function get_client_ip(): string {
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            return FirewallEngine::get_client_ip();
        }
        $raw = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
        return filter_var($raw, FILTER_VALIDATE_IP) ? $raw : '127.0.0.1';
    }
}
