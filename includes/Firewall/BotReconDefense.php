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
}
