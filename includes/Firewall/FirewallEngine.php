<?php
namespace WCP\Scanner\Firewall;

use WCP\Scanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

class FirewallEngine {
    private static $real_ip = null;
    private static $detected_environment = null;

    /**
     * Bootstrap the Firewall
     */
    public static function init() {
        // Initialize Threat Intelligence Service
        ThreatIntelService::init();

        // Initialize Bot Recon Defense & AI Scraper Shield
        BotReconDefense::init();

        // Run early at plugins_loaded priority 0
        add_action('plugins_loaded', [__CLASS__, 'inspect_incoming_request'], 0);

        // Protect XML-RPC early if enabled
        add_action('init', [__CLASS__, 'check_xmlrpc_guard'], 0);
    }

    /**
     * Resolve Real Client IP Address with Strict Trusted Proxy Verification.
     *
     * Strictly verifies REMOTE_ADDR against Cloudflare and configured trusted proxies.
     * If the direct connecting peer is untrusted, forwarding headers (CF-Connecting-IP,
     * X-Forwarded-For) are completely ignored to prevent IP spoofing of firewalls and allowlists.
     *
     * @return string
     */
    public static function get_client_ip(): string {
        if (self::$real_ip !== null) {
            return self::$real_ip;
        }

        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? trim($_SERVER['REMOTE_ADDR']) : '';
        if (!filter_var($remote_addr, FILTER_VALIDATE_IP)) {
            $remote_addr = '127.0.0.1';
        }

        // DEFENSE: If REMOTE_ADDR is NOT a trusted proxy, forwarding headers MUST NOT be trusted.
        // Return REMOTE_ADDR directly to prevent spoofing of allowlists, rate limiters, and logs.
        if (!self::is_trusted_proxy($remote_addr)) {
            self::$real_ip = $remote_addr;
            return self::$real_ip;
        }

        $resolved_ip = '';

        // Priority 1: Cloudflare CF-Connecting-IP (if connecting via Cloudflare proxy)
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $cf_ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($cf_ip, FILTER_VALIDATE_IP)) {
                $resolved_ip = $cf_ip;
            }
        }

        // Priority 2: X-Forwarded-For (Multi-proxy chain defense: reverse order traversal)
        // Upstream reverse proxies append the connecting client IP to the end of X-Forwarded-For.
        // To prevent attackers from spoofing their IP by prepending arbitrary values,
        // we traverse from right to left, skipping intermediate trusted proxies until finding
        // the first non-trusted peer (the authentic client IP).
        if (empty($resolved_ip) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
            $reversed = array_reverse($parts);
            foreach ($reversed as $candidate) {
                if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                    if (!self::is_trusted_proxy($candidate)) {
                        $resolved_ip = $candidate;
                        break;
                    }
                }
            }

            // Security Fail-Closed Policy:
            // If all valid addresses in the forwarding chain are trusted proxies (or all entries are malformed),
            // do NOT treat an internal proxy as the client. Fail closed: leave $resolved_ip empty
            // so execution safely defaults to the verified connecting peer ($remote_addr).
        }

        self::$real_ip = $resolved_ip ?: $remote_addr;
        return self::$real_ip;
    }

    /**
     * Reset the cached resolved IP address (used for testing and lifecycle hooks).
     *
     * @return void
     */
    public static function reset_client_ip_cache(): void {
        self::$real_ip = null;
    }

    /**
     * Check if a remote connecting IP address belongs to a verified trusted proxy.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_trusted_proxy(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // 1. Check Cloudflare edge network proxy ranges
        if (class_exists('\\WCP\\Scanner\\Cloudflare\\CloudflareService') && \WCP\Scanner\Cloudflare\CloudflareService::is_cloudflare_ip($ip)) {
            return true;
        }

        // 2. Check explicitly configured reverse proxy CIDRs/IPs
        $configured = self::get_configured_trusted_proxies();
        foreach ($configured as $range) {
            if (self::ip_in_range($ip, $range)) {
                return true;
            }
        }

        // 3. Localhost / loopback check (if WCP_TRUST_LOCAL_PROXY is explicitly enabled)
        if (defined('WCP_TRUST_LOCAL_PROXY') && WCP_TRUST_LOCAL_PROXY) {
            if ($ip === '127.0.0.1' || $ip === '::1') {
                return true;
            }
        }

        return false;
    }

    /**
     * Retrieve array of configured trusted proxy IPs/CIDRs from constants, environment, or settings.
     *
     * @return array
     */
    public static function get_configured_trusted_proxies(): array {
        $proxies = [];

        // 1. From constant WCP_TRUSTED_PROXIES (e.g. define('WCP_TRUSTED_PROXIES', '10.0.0.1, 192.168.1.0/24');)
        if (defined('WCP_TRUSTED_PROXIES') && is_string(WCP_TRUSTED_PROXIES) && WCP_TRUSTED_PROXIES !== '') {
            $parts = preg_split('/[\s,;]+/', WCP_TRUSTED_PROXIES);
            foreach ($parts as $p) {
                $p = trim($p);
                if ($p !== '') {
                    $proxies[] = $p;
                }
            }
        }

        // 2. From environment variable WCP_TRUSTED_PROXIES
        $env_proxies = getenv('WCP_TRUSTED_PROXIES') ?: ($_ENV['WCP_TRUSTED_PROXIES'] ?? '');
        if (!empty($env_proxies) && is_string($env_proxies)) {
            $parts = preg_split('/[\s,;]+/', $env_proxies);
            foreach ($parts as $p) {
                $p = trim($p);
                if ($p !== '') {
                    $proxies[] = $p;
                }
            }
        }

        // 3. From WordPress option
        $opt = function_exists('get_option') ? get_option('wcp_trusted_proxies', '') : '';
        if (!empty($opt) && is_string($opt)) {
            $parts = preg_split('/[\s,;]+/', $opt);
            foreach ($parts as $p) {
                $p = trim($p);
                if ($p !== '') {
                    $proxies[] = $p;
                }
            }
        }

        return array_unique($proxies);
    }

    /**
     * Detect external security layers (Cloudflare, Wordfence, Sucuri, Solid Security)
     */
    public static function detect_environment(): array {
        if (self::$detected_environment !== null) {
            return self::$detected_environment;
        }

        $has_cloudflare = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);
        $has_wordfence  = defined('WORDFENCE_VERSION') || class_exists('wordfence');
        $has_sucuri     = defined('SUCURISCAN_INIT');
        $has_solid      = defined('ITSEC_VERSION');

        self::$detected_environment = [
            'has_cloudflare' => (bool) $has_cloudflare,
            'has_wordfence'  => (bool) $has_wordfence,
            'has_sucuri'     => (bool) $has_sucuri,
            'has_solid'      => (bool) $has_solid,
            'has_coexisting_waf' => ($has_wordfence || $has_sucuri || $has_solid),
        ];

        return self::$detected_environment;
    }

    /**
     * Inspect Incoming Request
     */
    public static function inspect_incoming_request() {
        // Skip CLI and background WordPress cron tasks
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }

        $settings = SettingsManager::get_settings();

        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        $client_ip = self::get_client_ip();

        // Check user IP whitelist
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return;
        }

        // Check Cloud Threat Intelligence Botnet / Malicious IP Blacklist
        if (!empty($settings['threat_intel_enabled']) && !empty($settings['threat_intel_block_blacklisted_ips'])) {
            if (ThreatIntelService::is_ip_blacklisted($client_ip)) {
                $rule_triggered = [
                    'id'          => 'THREAT-INTEL-BOTNET',
                    'name'        => 'Global Botnet / Malicious IP Blacklist',
                    'category'    => 'Threat Intelligence',
                    'match_type'  => 'IP Reputation',
                    'match_value' => $client_ip,
                ];

                $mode = $settings['waf_mode'] ?? 'enabled';
                if ($mode === 'learning') {
                    self::log_incident($rule_triggered, 'detected');
                } else {
                    self::log_incident($rule_triggered, 'blocked');
                    self::render_block_page($rule_triggered, $client_ip);
                    exit;
                }
            }
        }

        // Check Bot Recon Defense & AI Scraper Shield
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $bot_rule = BotReconDefense::inspect_bot($client_ip, $user_agent, $settings);
        if ($bot_rule !== null) {
            $mode = $settings['waf_mode'] ?? 'enabled';
            if ($mode === 'learning') {
                self::log_incident($bot_rule, 'detected');
            } else {
                self::log_incident($bot_rule, 'blocked');
                self::render_block_page($bot_rule, $client_ip);
                exit;
            }
        }

        // Check Active Virtual Patches (Tier 1: In-Memory WAF Lite Shield)
        $request_uri = $_SERVER['REQUEST_URI'] ?? '/';
        $vpatch_rule = VirtualPatchManager::evaluate_request($client_ip, $request_uri);
        if ($vpatch_rule !== null) {
            $mode = $settings['waf_mode'] ?? 'enabled';
            if ($mode === 'learning') {
                self::log_incident($vpatch_rule, 'detected');
            } else {
                self::log_incident($vpatch_rule, 'blocked');
                self::render_block_page($vpatch_rule, $client_ip);
                exit;
            }
        }

        $env = self::detect_environment();
        $is_complementary = !empty($settings['waf_complementary_mode']) && $env['has_coexisting_waf'];

        // In complementary mode, Wordfence/Sucuri handles generic attacks;
        // WCP WAF Lite focuses on WordPress virtual patching and deep injection protection
        $rule_triggered = self::evaluate_rules($settings, $is_complementary);

        if ($rule_triggered) {
            $mode = $settings['waf_mode'] ?? 'enabled';

            if ($mode === 'learning') {
                // Log only, do not block
                self::log_incident($rule_triggered, 'detected');
            } else {
                // Enforce block
                self::log_incident($rule_triggered, 'blocked');
                self::render_block_page($rule_triggered, $client_ip);
                exit;
            }
        }
    }

    /**
     * Evaluate protection rules across GET, POST, and URI
     */
    private static function evaluate_rules(array $settings, bool $is_complementary): ?array {
        $uri          = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        $user_agent   = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Combine request parameters for deep inspection
        $params_to_check = [];

        if (!empty($_GET) && is_array($_GET)) {
            $params_to_check[] = urldecode(http_build_query($_GET));
        }
        if (!empty($_POST) && is_array($_POST)) {
            $params_to_check[] = urldecode(http_build_query($_POST));
        }

        $raw_input = @file_get_contents('php://input');
        if (!empty($raw_input) && strlen($raw_input) < 131072) { // Inspect up to 128KB payload
            $params_to_check[] = $raw_input;
        }

        $combined_payload = implode(' ', $params_to_check);

        // 1. Path Traversal & LFI/RFI
        if (!empty($settings['waf_block_traversal'])) {
            $traversal_patterns = [
                '/\.\.\//i',
                '/\.\.\\\/i',
                '/\.\.%2f/i',
                '/\.\.%5c/i',
                '/php:\/\/filter/i',
                '/php:\/\/input/i',
                '/etc\/passwd/i',
            ];
            foreach ($traversal_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload)) {
                    return [
                        'category'    => 'Path Traversal',
                        'description' => 'Local/Remote file inclusion directory traversal probe detected.',
                        'payload'     => substr($combined_payload, 0, 200),
                    ];
                }
            }
        }

        // 2. SQL Injection (SQLi)
        if (!empty($settings['waf_block_sqli'])) {
            $sqli_patterns = [
                '/\bunion\s+(all\s+)?select\b/i',
                '/\bselect\b.+\bfrom\b.+\binformation_schema\b/i',
                '/\bwaitfor\s+delay\s+[\'"][0-9:]+[\'"]/i',
                '/\bbenchmark\s*\(\s*[0-9]+,\s*md5/i',
                '/\bconcat\s*\(\s*0x[0-9a-f]+/i',
                '/\bextractvalue\s*\(/i',
                '/\bupdatexml\s*\(/i',
            ];
            foreach ($sqli_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload)) {
                    return [
                        'category'    => 'SQL Injection',
                        'description' => 'Malicious SQL syntax exploitation pattern detected.',
                        'payload'     => substr($combined_payload, 0, 200),
                    ];
                }
            }
        }

        // 3. PHP Code & Command Injection
        if (!empty($settings['waf_block_php_injection'])) {
            $php_patterns = [
                '/<\?php/i',
                '/\beval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$)/i',
                '/\b(system|passthru|shell_exec|proc_open|popen)\s*\(/i',
                '/\bbase64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{20,}/i',
            ];
            foreach ($php_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload)) {
                    return [
                        'category'    => 'PHP Code Injection',
                        'description' => 'Direct PHP script tag or dangerous execution function payload detected.',
                        'payload'     => substr($combined_payload, 0, 200),
                    ];
                }
            }
        }

        // 4. Cross-Site Scripting (XSS)
        if (!empty($settings['waf_block_xss'])) {
            $xss_patterns = [
                '/<script\b[^>]*>/i',
                '/javascript\s*:\s*[a-z0-9_]+/i',
                '/<iframe\b[^>]*>/i',
                '/\bon(error|load|mouseover|click)\s*=\s*[\'"].+[\'"]/i',
            ];
            foreach ($xss_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload)) {
                    return [
                        'category'    => 'Cross-Site Scripting (XSS)',
                        'description' => 'Hostile JavaScript injection or payload tag detected.',
                        'payload'     => substr($combined_payload, 0, 200),
                    ];
                }
            }
        }

        return null;
    }

    /**
     * XML-RPC Guard
     */
    public static function check_xmlrpc_guard() {
        $settings = SettingsManager::get_settings();
        if (!empty($settings['waf_enabled']) && !empty($settings['waf_disable_xmlrpc'])) {
            $uri = $_SERVER['REQUEST_URI'] ?? '';
            if (strpos($uri, 'xmlrpc.php') !== false) {
                self::log_incident([
                    'category'    => 'XML-RPC Disabled',
                    'description' => 'XML-RPC request blocked by administrator policy.',
                    'payload'     => 'xmlrpc.php invocation',
                ], 'blocked');

                status_header(403);
                header('Content-Type: text/plain; charset=utf-8');
                echo 'XML-RPC services are disabled on this WordPress installation by WCP Security Scanner.';
                exit;
            }
        }
    }

    /**
     * Check if an IP is in the user-defined whitelist
     */
    private static function is_ip_whitelisted(string $ip, string $whitelist_str): bool {
        if (empty($whitelist_str)) {
            return false;
        }

        $lines = explode("\n", str_replace("\r", "", $whitelist_str));
        foreach ($lines as $line) {
            $clean = trim($line);
            if ($clean === '') {
                continue;
            }
            if ($clean === $ip) {
                return true;
            }
            // Simple CIDR / subnet support
            if (strpos($clean, '/') !== false && self::ip_in_range($ip, $clean)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP (IPv4 or IPv6) is within a CIDR subnet or matches an IP.
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    public static function ip_in_range(string $ip, string $range): bool {
        $ip = trim($ip);
        $range = trim($range);

        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range, 2);
        $bits = (int) $bits;

        // IPv4 check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return false;
            }
            if ($bits < 0 || $bits > 32) {
                return false;
            }
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            if ($ip_long === false || $subnet_long === false) {
                return false;
            }
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
            return (($ip_long & $mask) === ($subnet_long & $mask));
        }

        // IPv6 check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return false;
            }
            if ($bits < 0 || $bits > 128) {
                return false;
            }
            $ip_bin = @inet_pton($ip);
            $subnet_bin = @inet_pton($subnet);
            if ($ip_bin === false || $subnet_bin === false) {
                return false;
            }

            $bytes = intdiv($bits, 8);
            if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($subnet_bin, 0, $bytes)) {
                return false;
            }

            $rem_bits = $bits % 8;
            if ($rem_bits > 0) {
                $mask = (0xFF << (8 - $rem_bits)) & 0xFF;
                if ((ord($ip_bin[$bytes]) & $mask) !== (ord($subnet_bin[$bytes]) & $mask)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Log firewall incident to database
     */
    private static function log_incident(array $rule, string $action) {
        global $wpdb;
        $table = $wpdb->prefix . 'wcp_firewall_logs';

        $ip = self::get_client_ip();
        $uri = substr($_SERVER['REQUEST_URI'] ?? '/', 0, 500);
        $method = substr($_SERVER['REQUEST_METHOD'] ?? 'GET', 0, 10);
        $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300);

        // Deduplication safeguard: don't log the same IP/rule more than once per minute
        $recent = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM `{$table}` WHERE ip_address = %s AND rule_category = %s AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE) LIMIT 1",
            $ip,
            $rule['category']
        ));

        if ($recent) {
            return;
        }

        $wpdb->insert(
            $table,
            [
                'ip_address'       => $ip,
                'request_uri'      => $uri,
                'request_method'   => $method,
                'rule_category'    => $rule['category'],
                'rule_description' => $rule['description'],
                'payload_sample'   => substr($rule['payload'] ?? '', 0, 255),
                'user_agent'       => $user_agent,
                'action_taken'     => $action,
                'created_at'       => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );

        // Dispatch DevSecOps Webhook on blocked attack
        if ($action === 'blocked' && class_exists('\\WCP\\Scanner\\Notifications\\WebhookService')) {
            \WCP\Scanner\Notifications\WebhookService::send_waf_alert([
                'category'   => $rule['category'],
                'name'       => $rule['name'] ?? $rule['category'],
                'ip_address' => $ip,
            ]);
        }

        // Auto-sync banned IP to Cloudflare Edge Access Rules if enabled
        if ($action === 'blocked') {
            $settings = SettingsManager::get_settings();
            if (!empty($settings['cloudflare_auto_sync_bans']) && class_exists('\\WCP\\Scanner\\Cloudflare\\CloudflareService')) {
                // Only sync high-threat categories (SQLi, PHP Injection, Traversal) to avoid polluting access rules
                $critical_categories = ['SQL Injection', 'PHP Injection', 'Path Traversal', 'Threat Intelligence'];
                if (in_array($rule['category'], $critical_categories, true)) {
                    \WCP\Scanner\Cloudflare\CloudflareService::block_ip(
                        $ip,
                        "WCP WAF Auto-Ban: {$rule['category']} probe"
                    );
                }
            }
        }
    }

    /**
     * Render branded 403 Forbidden Error Screen
     */
    private static function render_block_page(array $rule, string $client_ip) {
        status_header(403);
        header('Content-Type: text/html; charset=utf-8');
        header('X-Robots-Tag: noindex, nofollow', true);

        $incident_id = 'WCP-' . strtoupper(substr(md5($client_ip . time()), 0, 8));
        $site_name = get_bloginfo('name');

        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>403 Forbidden - Security Shield Block</title>
            <style>
                body {
                    margin: 0;
                    padding: 40px 20px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: #090d16;
                    color: #f1f5f9;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 80vh;
                }
                .wcp-waf-box {
                    max-width: 580px;
                    background: #111827;
                    border: 1px solid #dc2626;
                    border-radius: 14px;
                    padding: 36px;
                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(220, 38, 38, 0.05);
                }
                .wcp-badge {
                    display: inline-block;
                    background: #fee2e2;
                    color: #991b1b;
                    font-size: 12px;
                    font-weight: 700;
                    padding: 4px 10px;
                    border-radius: 20px;
                    margin-bottom: 16px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                h1 {
                    font-size: 22px;
                    color: #fff;
                    margin: 0 0 12px 0;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                p {
                    font-size: 14px;
                    line-height: 1.6;
                    color: #94a3b8;
                    margin: 0 0 20px 0;
                }
                .wcp-meta-grid {
                    background: #1e293b;
                    border-radius: 8px;
                    padding: 16px;
                    font-size: 13px;
                    color: #cbd5e1;
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 12px;
                    margin-bottom: 24px;
                }
                .wcp-meta-grid strong {
                    color: #e2e8f0;
                    display: block;
                    font-size: 11px;
                    text-transform: uppercase;
                    margin-bottom: 2px;
                    color: #64748b;
                }
                .wcp-footer {
                    font-size: 12px;
                    color: #64748b;
                    border-top: 1px solid #1f2937;
                    padding-top: 16px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
            </style>
        </head>
        <body>
            <div class="wcp-waf-box">
                <span class="wcp-badge">Web Application Firewall</span>
                <h1>Access Denied by Security Shield</h1>
                <p>
                    Your request was blocked because it triggered an automated threat defense rule on <strong><?php echo esc_html($site_name); ?></strong>.
                    If you believe this is a false positive, please contact the site administrator and provide the Incident ID below.
                </p>

                <div class="wcp-meta-grid">
                    <div>
                        <strong>Incident ID</strong>
                        <code><?php echo esc_html($incident_id); ?></code>
                    </div>
                    <div>
                        <strong>Client IP</strong>
                        <code><?php echo esc_html($client_ip); ?></code>
                    </div>
                    <div>
                        <strong>Triggered Vector</strong>
                        <span><?php echo esc_html($rule['category']); ?></span>
                    </div>
                    <div>
                        <strong>Timestamp</strong>
                        <span><?php echo esc_html(gmdate('Y-m-d H:i:s \U\T\C')); ?></span>
                    </div>
                </div>

                <div class="wcp-footer">
                    <span>Protected by WCP Security Scanner</span>
                    <span>WAF Lite Engine</span>
                </div>
            </div>
        </body>
        </html>
        <?php
    }

    /**
     * Get statistics & summary of firewall activity
     */
    public static function get_status(): array {
        global $wpdb;
        $table = $wpdb->prefix . 'wcp_firewall_logs';

        $settings = SettingsManager::get_settings();
        $env = self::detect_environment();

        $total_blocks = 0;
        $blocks_24h = 0;
        $top_rules = [];

        // Check if table exists
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if ($table_exists) {
            $total_blocks = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked'");
            $blocks_24h   = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $top_rules    = $wpdb->get_results(
                "SELECT rule_category, COUNT(*) as count FROM `{$table}` WHERE action_taken = 'blocked' GROUP BY rule_category ORDER BY count DESC LIMIT 5",
                ARRAY_A
            ) ?: [];
        }

        $active_mode = 'disabled';
        if (!empty($settings['waf_enabled'])) {
            if (($settings['waf_mode'] ?? 'enabled') === 'learning') {
                $active_mode = 'learning';
            } elseif (!empty($settings['waf_complementary_mode']) && $env['has_coexisting_waf']) {
                $active_mode = 'complementary';
            } else {
                $active_mode = 'active';
            }
        }

        return [
            'enabled'            => !empty($settings['waf_enabled']),
            'mode'               => $settings['waf_mode'] ?? 'enabled',
            'active_mode'        => $active_mode,
            'environment'        => $env,
            'total_blocks'       => $total_blocks,
            'blocks_24h'         => $blocks_24h,
            'top_rules'          => $top_rules,
            'client_ip'          => self::get_client_ip(),
            'threat_intel'       => ThreatIntelService::get_status(),
        ];
    }

    /**
     * Get recent blocked logs
     */
    public static function get_logs(int $limit = 50): array {
        global $wpdb;
        $table = $wpdb->prefix . 'wcp_firewall_logs';

        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if (!$table_exists) {
            return [];
        }

        $limit = max(1, min(200, $limit));
        return $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM `{$table}` ORDER BY id DESC LIMIT %d", $limit),
            ARRAY_A
        ) ?: [];
    }

    /**
     * Clear firewall logs
     */
    public static function clear_logs(): bool {
        global $wpdb;
        $table = $wpdb->prefix . 'wcp_firewall_logs';
        return (bool) $wpdb->query("TRUNCATE TABLE `{$table}`");
    }
}
