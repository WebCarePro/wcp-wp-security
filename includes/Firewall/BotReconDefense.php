<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Bot Recon Defense & AI Scraper Shield
 *
 * Provides:
 * 1. Fake Search Engine Crawler Detection:
 *    Detects requests claiming to be Googlebot, Bingbot, Yahoo Slurp, or DuckDuckBot.
 *    Validates authenticity via reverse DNS lookup (PTR) followed by forward DNS confirmation (A/AAAA).
 *    Results are transiently cached for 24 hours to prevent repeated DNS resolution overhead.
 *    Any crawler impersonating genuine search engines is blocked as an adversarial reconnaissance probe.
 *
 * 2. AI Scraper & Unethical Harvester Shield:
 *    Identifies and blocks aggressive AI model scrapers (e.g. GPTBot, CCBot, Bytespider, ClaudeBot, PerplexityBot).
 *
 * 3. Dynamic Virtual robots.txt Ingestion:
 *    Automatically injects standard Disallow directives for AI scrapers into WordPress virtual robots.txt.
 */
class BotReconDefense {

    /**
     * Map of supported search engine bots and their authorized host suffixes.
     */
    private const SEARCH_BOTS = [
        'googlebot'   => ['googlebot.com', 'google.com'],
        'bingbot'     => ['search.msn.com', 'bing.com'],
        'slurp'       => ['crawl.yahoo.net', 'yahoo.com'],
        'duckduckbot' => ['duckduckgo.com'],
        'yandex'      => ['yandex.ru', 'yandex.net', 'yandex.com'],
        'baiduspider' => ['baidu.com', 'baidu.jp'],
    ];

    /**
     * Official Verified Search Crawler Network CIDR Ranges (IPv4 & IPv6).
     * High-speed authoritative fallback when reverse DNS PTR queries fail, time out,
     * or are blocked by container network resolvers (e.g. Docker, NAT environments).
     */
    private const CRAWLER_CIDR_RANGES = [
        'googlebot' => [
            // Googlebot Primary IPv4 Subnets
            '66.249.64.0/19',
            '64.233.160.0/19',
            '72.14.192.0/18',
            '209.85.128.0/17',
            '108.177.8.0/21',
            '172.217.0.0/16',
            '216.58.192.0/19',
            '173.194.0.0/16',
            '74.125.0.0/16',
            '34.22.85.0/27',
            '35.247.243.240/28',
            '192.178.4.0/22',
            // Googlebot Primary IPv6 Subnets
            '2001:4860::/32',
            '2404:6800::/32',
            '2607:f8b0::/32',
            '2800:3f0::/32',
            '2a00:1450::/32',
            '2c0f:fb50::/32',
        ],
        'bingbot' => [
            // Bingbot Primary IPv4 Subnets
            '157.55.39.0/24',
            '207.46.13.0/24',
            '40.77.167.0/24',
            '13.66.139.0/24',
            '13.66.144.0/24',
            '52.167.144.0/24',
            // Bingbot Primary IPv6 Subnets
            '2603:1030::/32',
            '2603:1040::/32',
            '2603:1050::/32',
        ],
    ];

    /**
     * Map of verified uptime & performance monitoring services and their authorized reverse DNS host suffixes.
     */
    private const MONITORING_BOTS = [
        'uptimerobot' => ['uptimerobot.com'],
        'pingdom'     => ['pingdom.com'],
        'statuscake'  => ['statuscake.com'],
        'betteruptime'=> ['betteruptime.com'],
        'gtmetrix'    => ['gtmetrix.com'],
    ];

    /**
     * Known AI scrapers & training harvesters User-Agent signatures.
     */
    private const AI_SCRAPERS = [
        'gptbot'         => 'OpenAI GPTBot',
        'chatgpt-user'   => 'ChatGPT Web Crawler',
        'ccbot'          => 'Common Crawl Bot',
        'bytespider'     => 'ByteDance Spider',
        'anthropic-ai'   => 'Anthropic AI Crawler',
        'claudebot'      => 'ClaudeBot',
        'perplexitybot'  => 'Perplexity AI Bot',
        'diffbot'        => 'Diffbot Harvester',
        'cohere-ai'      => 'Cohere AI Harvester',
        'omgili'         => 'Omgili Web Scraper',
        'facebookexternalhit' => false, // Leave Facebook unfrozen unless specified
    ];

    /**
     * Initialize Dynamic robots.txt Hook
     */
    public static function init() {
        add_filter('robots_txt', [__CLASS__, 'filter_dynamic_robots_txt'], 10, 2);
    }

    /**
     * Inspect Bot / User-Agent against Fake Search Engine and AI Scraper Shields
     *
     * @param string $client_ip
     * @param string $user_agent
     * @param array $settings
     * @return array|null Returns rule definition if suspicious/blocked, or null if allowed.
     */
    public static function inspect_bot(string $client_ip, string $user_agent, array $settings): ?array {
        if (empty($user_agent)) {
            return null;
        }

        $ua_lower = strtolower($user_agent);

        // 1. Check AI Scrapers Shield
        if (!empty($settings['waf_block_ai_scrapers'])) {
            $ai_bot_matched = self::match_ai_scraper($ua_lower);
            if ($ai_bot_matched) {
                return [
                    'id'          => 'BOT-AI-SCRAPER-BLOCKED',
                    'name'        => 'AI Content Scraper / Harvester Blocked (' . $ai_bot_matched . ')',
                    'category'    => 'Bot Recon Defense',
                    'match_type'  => 'User-Agent Signature',
                    'match_value' => substr($user_agent, 0, 150),
                ];
            }
        }

        // 2. Check Fake Search Engine Crawler
        if (!empty($settings['waf_block_fake_bots'])) {
            $bot_key = self::detect_claimed_search_bot($ua_lower);
            if ($bot_key !== null) {
                $is_genuine = self::verify_search_bot_reverse_dns($client_ip, $bot_key);
                if (!$is_genuine) {
                    return [
                        'id'          => 'BOT-FAKE-CRAWLER-SPOOF',
                        'name'        => 'Fake Search Engine Crawler Spoofing Detected (' . ucfirst($bot_key) . ')',
                        'category'    => 'Bot Recon Defense',
                        'match_type'  => 'Reverse DNS Verification Failure',
                        'match_value' => 'IP: ' . $client_ip . ' claiming UA: ' . substr($user_agent, 0, 100),
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Check if User Agent matches known AI Scrapers
     */
    public static function match_ai_scraper(string $ua_lower): ?string {
        foreach (self::AI_SCRAPERS as $signature => $label) {
            if ($label !== false && strpos($ua_lower, $signature) !== false) {
                return $label;
            }
        }
        return null;
    }

    /**
     * Detect if User Agent claims to be a well-known search crawler
     */
    public static function detect_claimed_search_bot(string $ua_lower): ?string {
        foreach (self::SEARCH_BOTS as $bot_key => $domains) {
            if (strpos($ua_lower, $bot_key) !== false) {
                return $bot_key;
            }
        }
        return null;
    }

    /**
     * Validate genuine search crawler via Reverse DNS (PTR) + Forward DNS (A)
     * with high-speed authoritative CIDR fallback for containerized/NAT environments.
     * Caches verification status for 24 hours (86400s) to keep latency minimal.
     */
    public static function verify_search_bot_reverse_dns(string $ip, string $bot_key): bool {
        // Skip private or local IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }

        $transient_key = 'wcpscan_bot_dns_' . md5($ip . '_' . $bot_key);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return ($cached === 'genuine');
        }

        // Fast-path CIDR check: If the IP falls strictly into the search engine's official published subnets,
        // it is verified authentic immediately, bypassing external DNS PTR resolution timeouts or docker limitations.
        if (self::is_search_bot_in_official_cidrs($ip, $bot_key)) {
            set_transient($transient_key, 'genuine', DAY_IN_SECONDS);
            return true;
        }

        $allowed_domains = self::SEARCH_BOTS[$bot_key] ?? [];
        if (empty($allowed_domains)) {
            return true;
        }

        $is_genuine = false;

        // 1. Reverse DNS Lookup (PTR)
        $hostname = @gethostbyaddr($ip);
        if (!empty($hostname) && $hostname !== $ip) {
            $hostname_lower = strtolower($hostname);

            // Check if hostname ends with authorized domain suffix
            $domain_matches = false;
            foreach ($allowed_domains as $domain) {
                if ($hostname_lower === $domain || str_ends_with($hostname_lower, '.' . $domain)) {
                    $domain_matches = true;
                    break;
                }
            }

            if ($domain_matches) {
                // 2. Forward DNS Lookup confirmation
                $resolved_ip = @gethostbyname($hostname);
                if ($resolved_ip === $ip) {
                    $is_genuine = true;
                }
            }
        }

        // Cache verdict for 24 hours
        set_transient($transient_key, $is_genuine ? 'genuine' : 'fake', DAY_IN_SECONDS);

        return $is_genuine;
    }

    /**
     * Check if client IP belongs to official verified search crawler CIDR ranges.
     */
    public static function is_search_bot_in_official_cidrs(string $ip, string $bot_key): bool {
        $cidrs = self::CRAWLER_CIDR_RANGES[$bot_key] ?? [];
        if (empty($cidrs)) {
            return false;
        }

        foreach ($cidrs as $cidr) {
            if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine') && FirewallEngine::ip_in_range($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check whether an incoming request belongs to an authenticated, verified search engine crawler.
     *
     * Examines the User-Agent string, and if it claims to be a recognized search engine (Google, Bing, DuckDuckGo,
     * Yandex, Baidu, Yahoo), executes full Reverse DNS (PTR) + Forward DNS (A/AAAA) confirmation.
     * Returns true ONLY if DNS cryptographic hostname confirmation succeeds.
     *
     * @param string $ip Client IP address.
     * @param string $user_agent Client User-Agent string.
     * @return bool True if genuine search engine, false otherwise.
     */
    public static function is_genuine_search_engine(string $ip, string $user_agent): bool {
        if (empty($user_agent)) {
            return false;
        }

        $ua_lower = strtolower($user_agent);
        $bot_key  = self::detect_claimed_search_bot($ua_lower);

        if ($bot_key === null) {
            return false;
        }

        return self::verify_search_bot_reverse_dns($ip, $bot_key);
    }

    /**
     * Check whether an incoming request belongs to an authenticated, verified uptime monitoring service
     * (UptimeRobot, Pingdom, StatusCake, BetterUptime, GTmetrix).
     *
     * Validates:
     * 1. Setting 'waf_allow_uptime_monitors' is active.
     * 2. User-Agent matches recognized monitoring service signature.
     * 3. Forward & reverse DNS confirmation against official domain suffix (cached for 24 hours).
     *
     * @param string $ip
     * @param string $user_agent
     * @param array $settings
     * @return bool
     */
    public static function is_genuine_uptime_monitor(string $ip, string $user_agent, array $settings): bool {
        if (empty($settings['waf_allow_uptime_monitors']) || empty($user_agent)) {
            return false;
        }

        $ua_lower = strtolower($user_agent);
        $matched_key = null;
        foreach (self::MONITORING_BOTS as $bot_key => $domains) {
            if (strpos($ua_lower, $bot_key) !== false) {
                $matched_key = $bot_key;
                break;
            }
        }

        if ($matched_key === null) {
            return false;
        }

        // Validate via cached DNS PTR / Forward A record check
        $transient_key = 'wcpscan_monitor_dns_' . md5($ip . '_' . $matched_key);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return ($cached === 'genuine');
        }

        // Skip private or local IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }

        $allowed_domains = self::MONITORING_BOTS[$matched_key] ?? [];
        $is_genuine = false;

        $hostname = @gethostbyaddr($ip);
        if (!empty($hostname) && $hostname !== $ip) {
            $hostname_lower = strtolower($hostname);
            $domain_matches = false;
            foreach ($allowed_domains as $domain) {
                if ($hostname_lower === $domain || str_ends_with($hostname_lower, '.' . $domain)) {
                    $domain_matches = true;
                    break;
                }
            }

            if ($domain_matches) {
                $resolved_ip = @gethostbyname($hostname);
                if ($resolved_ip === $ip) {
                    $is_genuine = true;
                }
            }
        }

        set_transient($transient_key, $is_genuine ? 'genuine' : 'fake', DAY_IN_SECONDS);
        return $is_genuine;
    }

    /**
     * Append AI Scraper blocking rules to virtual robots.txt
     */
    public static function filter_dynamic_robots_txt(string $output, bool $public): string {
        $settings = SettingsManager::get_settings();

        if (empty($settings['waf_dynamic_robots_ai'])) {
            return $output;
        }

        $ai_rules = "\n# WCP Security Scanner - AI Content Harvester Rules\n";
        $scrapers = ['GPTBot', 'ChatGPT-User', 'CCBot', 'Bytespider', 'anthropic-ai', 'ClaudeBot', 'PerplexityBot', 'Diffbot', 'Cohere-ai'];

        foreach ($scrapers as $bot) {
            $ai_rules .= "User-agent: " . $bot . "\n";
            $ai_rules .= "Disallow: /\n\n";
        }

        return $output . $ai_rules;
    }

    private const POW_COOKIE_NAME = 'wcp_pow_clearance';
    private const POW_DIFFICULTY  = 4; // 4 hex zeros = 16 leading zero bits (~65,536 hashes max)
    private const CLEARANCE_TTL   = 3600;

    /**
     * Verify if the client holds a valid PoW clearance cookie or just submitted a valid PoW solution.
     * Invoked when high-velocity reconnaissance or scraping anomaly is detected.
     */
    public static function verify_or_challenge_client(): void {
        $client_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
        $ua        = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        if (self::has_valid_clearance_cookie($client_ip, $ua)) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (isset($_POST['wcp_pow_challenge'], $_POST['wcp_pow_nonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $challenge = sanitize_text_field(wp_unslash($_POST['wcp_pow_challenge']));
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $nonce     = sanitize_text_field(wp_unslash($_POST['wcp_pow_nonce']));

            if (self::verify_pow_solution($challenge, $nonce, $client_ip, $ua)) {
                self::issue_clearance_cookie($client_ip, $ua);
                $req_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
                wp_safe_redirect($req_uri);
                exit;
            }
        }

        self::render_webcrypto_challenge($client_ip, $ua);
    }

    /**
     * Inspect HTTP/2 & HTTP/3 pseudo-header ordering and letter-case anomalies.
     * Genuine modern web browsers (Chrome, Firefox, Safari) strictly send pseudo-headers
     * in standardized order (:method -> :authority -> :scheme -> :path) in lowercase.
     * Automated scripts (Python requests, Go net/http, custom cURL scrapers) often violate this.
     *
     * @return array|null Anomaly report if detected, null if clean or non-HTTP/2
     */
    public static function check_http2_pseudo_header_anomaly(): ?array {
        $protocol = isset($_SERVER['SERVER_PROTOCOL']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'])) : '';
        $is_h2 = (strpos($protocol, 'HTTP/2') !== false || strpos($protocol, 'HTTP/3') !== false || (!empty($_SERVER['HTTP2']) && $_SERVER['HTTP2'] === 'on'));

        // If not running under HTTP/2 or HTTP/3, skip check
        if (!$is_h2) {
            return null;
        }

        // Check if raw request headers can be retrieved
        $raw_headers = [];
        if (function_exists('getallheaders')) {
            $raw_headers = getallheaders();
        }

        if (empty($raw_headers) && is_array($_SERVER)) {
            foreach ($_SERVER as $k => $v) {
                if (str_starts_with($k, 'HTTP_')) {
                    $raw_headers[substr($k, 5)] = $v;
                }
            }
        }

        // Anomaly 1: Check for uppercase HTTP/2 headers if raw headers exposed
        if (!empty($raw_headers)) {
            foreach (array_keys($raw_headers) as $header_name) {
                if (is_string($header_name) && str_starts_with($header_name, ':')) {
                    if ($header_name !== strtolower($header_name)) {
                        return [
                            'anomaly'     => 'uppercase_pseudo_header',
                            'description' => sprintf('Invalid uppercase HTTP/2 pseudo-header detected: %s', esc_html($header_name)),
                            'severity'    => 'high',
                        ];
                    }
                }
            }
        }

        // Anomaly 2: Check for missing standard User-Agent or known script agent impersonating browser HTTP/2
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        if (preg_match('/^(python|go-http-client|curl|libwww|aiohttp)/i', $ua)) {
            return [
                'anomaly'     => 'script_http2_signature',
                'description' => sprintf('Script scraper "%s" connecting over HTTP/2 with automated bot signature.', esc_html($ua)),
                'severity'    => 'medium',
            ];
        }

        // Anomaly 3: Client-Hint (Sec-CH-UA) Consistency Check (CAF Phase 3)
        // Modern Chromium browsers (Chrome >= 89, Edge >= 89) on HTTPS always emit Sec-CH-UA, Sec-CH-UA-Mobile, and Sec-CH-UA-Platform.
        // Scrapers claiming modern Chrome User-Agents without Client-Hints or with platform contradictions are flagged.
        $client_hint_anomaly = self::check_client_hint_consistency($ua, $raw_headers);
        if ($client_hint_anomaly !== null) {
            return $client_hint_anomaly;
        }

        return null;
    }

    /**
     * Inspect Client-Hint headers (Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform)
     * against declared User-Agent.
     *
     * @param string $ua
     * @param array $headers
     * @return array|null Anomaly description or null
     */
    public static function check_client_hint_consistency(string $ua, array $headers): ?array {
        if (empty($ua) || !is_ssl()) {
            return null; // Client-Hints are standard on HTTPS
        }

        // Normalize header keys to uppercase for search
        $normalized = [];
        foreach ($headers as $k => $v) {
            $normalized[strtoupper(str_replace('-', '_', (string) $k))] = (string) $v;
        }

        $sec_ch_ua          = $normalized['SEC_CH_UA'] ?? ($normalized['HTTP_SEC_CH_UA'] ?? '');
        $sec_ch_ua_mobile   = $normalized['SEC_CH_UA_MOBILE'] ?? ($normalized['HTTP_SEC_CH_UA_MOBILE'] ?? '');
        $sec_ch_ua_platform = $normalized['SEC_CH_UA_PLATFORM'] ?? ($normalized['HTTP_SEC_CH_UA_PLATFORM'] ?? '');

        // Pattern: User-Agent claims modern Chrome on Desktop (Version >= 90)
        $is_modern_desktop_chrome = false;
        if (preg_match('/Chrome\/([0-9]{2,3})\./i', $ua, $matches)) {
            $version = (int) $matches[1];
            if ($version >= 95 && !preg_match('/(Mobile|Android|iPhone|iPad)/i', $ua)) {
                $is_modern_desktop_chrome = true;
            }
        }

        // Check 1: User-Agent claims modern Chrome desktop but Sec-CH-UA header is completely absent
        if ($is_modern_desktop_chrome && empty($sec_ch_ua)) {
            return [
                'anomaly'     => 'missing_client_hints',
                'description' => 'User-Agent claims modern desktop Chrome but Sec-CH-UA Client-Hints are missing (bot spoofing signature).',
                'severity'    => 'medium',
            ];
        }

        // Check 2: Mobile Client-Hint mismatch (?1 on desktop UA or ?0 on mobile UA)
        if (!empty($sec_ch_ua_mobile)) {
            $is_mobile_ua = (bool) preg_match('/(Mobile|Android|iPhone|iPad)/i', $ua);
            if ($sec_ch_ua_mobile === '?1' && !$is_mobile_ua) {
                return [
                    'anomaly'     => 'client_hint_mobile_mismatch',
                    'description' => 'Sec-CH-UA-Mobile indicates mobile client (?1) but User-Agent indicates desktop.',
                    'severity'    => 'medium',
                ];
            }
        }

        // Check 3: Platform contradiction (e.g. Windows UA with Linux/Android Client-Hint)
        if (!empty($sec_ch_ua_platform)) {
            $platform_clean = strtolower(trim($sec_ch_ua_platform, '" '));
            if ($platform_clean === 'windows' && preg_match('/(Linux|Macintosh|Android)/i', $ua)) {
                return [
                    'anomaly'     => 'client_hint_platform_mismatch',
                    'description' => 'Sec-CH-UA-Platform ("Windows") contradicts non-Windows operating system in User-Agent.',
                    'severity'    => 'high',
                ];
            } elseif ($platform_clean === 'linux' && preg_match('/(Windows NT|Macintosh)/i', $ua)) {
                return [
                    'anomaly'     => 'client_hint_platform_mismatch',
                    'description' => 'Sec-CH-UA-Platform ("Linux") contradicts Windows/Mac operating system in User-Agent.',
                    'severity'    => 'high',
                ];
            }
        }

        return null;
    }

    /**
     * Render the stateless WebCrypto Proof-of-Work (PoW) HTML5 challenge.
     * Public alias for active bot defense and suspicious IP mitigation.
     *
     * @param string $ip
     * @param string $action_context
     */
    public static function render_pow_challenge(string $ip, string $action_context = 'High-velocity probe'): void {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        self::render_webcrypto_challenge($ip, $ua);
    }

    private static function generate_challenge(string $ip, string $ua): string {
        $window = (string) floor(time() / 300); // Valid for 5-minute window
        $salt   = defined('NONCE_KEY') ? NONCE_KEY : 'wcp_pow_salt';
        $mac    = hash_hmac('sha256', $ip . '|' . $ua . '|' . $window, $salt);
        return $window . '.' . substr($mac, 0, 32);
    }

    private static function verify_pow_solution(string $challenge, string $nonce, string $ip, string $ua): bool {
        $expected_challenge = self::generate_challenge($ip, $ua);
        if (!hash_equals($expected_challenge, $challenge)) {
            return false;
        }

        $digest = hash('sha256', $challenge . ':' . $nonce);
        return strpos($digest, str_repeat('0', self::POW_DIFFICULTY)) === 0;
    }

    private static function issue_clearance_cookie(string $ip, string $ua): void {
        $expires = time() + self::CLEARANCE_TTL;
        $salt    = defined('AUTH_KEY') ? AUTH_KEY : 'wcp_pow_auth_salt';
        $sig     = hash_hmac('sha256', $ip . '|' . $ua . '|' . $expires, $salt);
        $value   = $expires . '.' . $sig;

        setcookie(self::POW_COOKIE_NAME, $value, [
            'expires'  => $expires,
            'path'     => defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private static function has_valid_clearance_cookie(string $ip, string $ua): bool {
        if (empty($_COOKIE[self::POW_COOKIE_NAME])) {
            return false;
        }

        $raw   = sanitize_text_field(wp_unslash($_COOKIE[self::POW_COOKIE_NAME]));
        $parts = explode('.', $raw, 2);
        if (count($parts) !== 2) {
            return false;
        }

        $expires = (int) $parts[0];
        if (time() > $expires) {
            return false;
        }

        $salt         = defined('AUTH_KEY') ? AUTH_KEY : 'wcp_pow_auth_salt';
        $expected_sig = hash_hmac('sha256', $ip . '|' . $ua . '|' . $expires, $salt);
        return hash_equals($expected_sig, $parts[1]);
    }

    private static function render_webcrypto_challenge(string $ip, string $ua): void {
        $challenge = self::generate_challenge($ip, $ua);
        $zeros     = str_repeat('0', self::POW_DIFFICULTY);

        status_header(429);
        nocache_headers();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title><?php esc_html_e('Security Verification', 'wcp-security-scanner'); ?></title>
        </head>
        <body style="font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0f172a;color:#f8fafc;">
            <div style="text-align:center;max-width:420px;padding:32px;background:#1e293b;border-radius:12px;border:1px solid rgba(255,255,255,0.08);box-shadow:0 10px 25px -5px rgba(0,0,0,0.5);">
                <div style="font-size:36px;margin-bottom:12px;">🛡️</div>
                <h2 style="margin:0 0 8px 0;font-size:20px;font-weight:600;"><?php esc_html_e('Browser Integrity Verification', 'wcp-security-scanner'); ?></h2>
                <p id="wcp-status" style="color:#94a3b8;font-size:14px;margin:0 0 20px 0;line-height:1.5;"><?php esc_html_e('Verifying browser cryptographic environment to prevent automated scraping...', 'wcp-security-scanner'); ?></p>
                <div style="height:4px;width:100%;background:#334155;border-radius:2px;overflow:hidden;position:relative;">
                    <div style="height:100%;width:50%;background:#4f46e5;border-radius:2px;animation:wcpPulse 1.2s infinite ease-in-out;"></div>
                </div>
                <form id="wcp-pow-form" method="POST" action="">
                    <input type="hidden" name="wcp_pow_challenge" value="<?php echo esc_attr($challenge); ?>">
                    <input type="hidden" name="wcp_pow_nonce" id="wcp-pow-nonce" value="">
                </form>
            </div>
            <style>
                @keyframes wcpPulse {
                    0% { transform: translateX(-100%); }
                    100% { transform: translateX(250%); }
                }
            </style>
            <script>
            (async function() {
                const challenge = <?php echo wp_json_encode($challenge); ?>;
                const target = <?php echo wp_json_encode($zeros); ?>;
                const enc = new TextEncoder();
                let nonce = 0;
                while (true) {
                    const buf = await crypto.subtle.digest('SHA-256', enc.encode(challenge + ':' + nonce));
                    const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
                    if (hex.startsWith(target)) {
                        document.getElementById('wcp-pow-nonce').value = String(nonce);
                        document.getElementById('wcp-pow-form').submit();
                        return;
                    }
                    nonce++;
                }
            })();
            </script>
        </body>
        </html>
        <?php
        exit;
    }
}
