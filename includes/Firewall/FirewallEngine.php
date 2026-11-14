<?php
namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

class FirewallEngine {
    private static $real_ip = null;
    private static $connecting_peer_ip = null;
    private static $detected_environment = null;
    private static $last_incident_id = null;
    private static $last_ref_code = null;

    /**
     * Generate a short, unambiguous Customer Support Reference Code (#WEBCARE-XXXX).
     */
    public static function generate_ref_code(): string {
        $charset = '23456789ABCDEFGHJKMNPQRSTVWXYZ';
        $max_idx = strlen($charset) - 1;
        $ref_code = 'WEBCARE-';
        for ($i = 0; $i < 4; $i++) {
            $ref_code .= $charset[wp_rand(0, $max_idx)];
        }
        return $ref_code;
    }

    /**
     * Bootstrap the Firewall
     */
    public static function init() {
        // Record raw connecting peer IP before any normalization occurs
        if (!empty($_SERVER['REMOTE_ADDR']) && self::$connecting_peer_ip === null) {
            self::$connecting_peer_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        // Normalize $_SERVER['REMOTE_ADDR'] if incoming request connects via a verified trusted reverse proxy (e.g. Cloudflare)
        self::normalize_server_remote_addr();

        // Initialize Threat Intelligence Service
        ThreatIntelService::init();

        // Initialize Bot Recon Defense & AI Scraper Shield
        BotReconDefense::init();

        // Initialize Anti-Automation Honey-Token Traps & Phantom Decoy Grid
        if (class_exists('\\WebCareProScanner\\Firewall\\HoneyTokenEngine')) {
            HoneyTokenEngine::init();
        }

        // Run early at plugins_loaded priority 0
        add_action('plugins_loaded', [__CLASS__, 'inspect_incoming_request'], 0);

        // Protect XML-RPC early if enabled
        add_action('init', [__CLASS__, 'check_xmlrpc_guard'], 0);

        // Flush Preload Micro-WAF custom rule ban intents queued prior to WordPress boot
        add_action('init', [__CLASS__, 'flush_preload_ban_queue'], 5);

        // Synchronize and rotate Preload Auth HMAC Cookie for Pre-Boot WAF
        add_action('init', [__CLASS__, 'sync_preload_auth_cookie'], 1);
        add_action('wp_login', [__CLASS__, 'on_user_login_preload_auth'], 10, 2);
        add_action('wp_logout', [__CLASS__, 'clear_preload_auth_cookie']);
        add_action('clear_auth_cookie', [__CLASS__, 'clear_preload_auth_cookie']);

        // Smart 404 Scanner Rate Limiter & Reconnaissance Shield (Priority 999: Allow redirection plugins & template logic to process first)
        add_action('template_redirect', [__CLASS__, 'track_404_request'], 999);

        // Real-Time Malicious File Upload Interceptor
        add_filter('wp_handle_upload_prefilter', [__CLASS__, 'inspect_uploaded_file'], 1);

        // Disallow phpMyAdmin & File Manager Plugin Installations (Admin-ajax, REST API, & WP Upgrader)
        add_filter('upgrader_pre_install', [__CLASS__, 'prevent_prohibited_plugin_install'], 10, 2);
        add_filter('upgrader_source_selection', [__CLASS__, 'inspect_unpacked_plugin_source'], 1, 4);
        add_filter('plugins_api_result', [__CLASS__, 'filter_prohibited_plugin_api'], 10, 3);

        // Generic Login Error Masking (prevent revealing valid usernames)
        add_filter('login_errors', [__CLASS__, 'mask_login_errors'], 999);

        // Prevent Registering 'admin' or Prohibited Usernames
        add_filter('validate_username', [__CLASS__, 'validate_registration_username'], 10, 2);
        add_filter('registration_errors', [__CLASS__, 'filter_registration_errors'], 10, 3);

        // Immediately Block IP of Users Trying to Sign in as Forbidden Usernames
        add_filter('authenticate', [__CLASS__, 'check_forbidden_username_login'], 20, 3);

        // Enforce Strong Passwords & Check Leaked/Pwned Passwords on Password Change/Reset
        add_action('user_profile_update_errors', [__CLASS__, 'validate_user_password_policy'], 10, 3);
        add_action('validate_password_reset', [__CLASS__, 'validate_reset_password_policy'], 10, 2);

        // Rule #29: REST API User Enumeration Interceptor
        add_filter('rest_authentication_errors', [__CLASS__, 'check_rest_user_enumeration'], 20);

        // Rule #30: Author Permalink Query Suppression (?author=N)
        add_action('template_redirect', [__CLASS__, 'check_author_scan_suppression'], 0);

        // Rule #37: Guest REST API Mutation Guard
        add_filter('rest_pre_dispatch', [__CLASS__, 'inspect_guest_rest_dispatch'], 10, 3);

        // Rule #31: Lost-Password Reset Burst Flooding Guard
        add_action('login_form_lostpassword', [__CLASS__, 'check_lostpassword_flood'], 0);
        add_action('lostpassword_post', [__CLASS__, 'check_lostpassword_submission'], 0);

        // Context-Adaptive Firewall (CAF 2.0): Only register WooCommerce firewall hooks when WooCommerce is active
        $has_woocommerce = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : (class_exists('WooCommerce') || in_array('woocommerce/woocommerce.php', (array) get_option('active_plugins', []), true));

        if ($has_woocommerce) {
            // Rule #38: WooCommerce Carding Attack & Checkout Velocity Shield
            add_action('woocommerce_checkout_process', [__CLASS__, 'inspect_woo_checkout_attempt'], 0);
            add_action('woocommerce_after_checkout_validation', [__CLASS__, 'handle_woo_checkout_validation'], 999, 2);
            add_action('woocommerce_order_status_failed', [__CLASS__, 'handle_woo_payment_failure'], 10, 1);

            // Rule #39: WooCommerce Coupon Enumeration & Brute-Force Shield
            add_action('woocommerce_applied_coupon', [__CLASS__, 'handle_woo_coupon_success'], 10, 1);
            add_filter('woocommerce_coupon_error', [__CLASS__, 'handle_woo_coupon_error'], 999, 3);
            add_filter('rest_request_after_callbacks', [__CLASS__, 'handle_woo_store_api_coupon_response'], 10, 3);

            // Rule #40: WooCommerce Fake Customer Registration & Bot Shield
            add_filter('woocommerce_registration_errors', [__CLASS__, 'validate_woo_customer_registration'], 10, 3);
            add_action('woocommerce_created_customer', [__CLASS__, 'handle_woo_customer_created'], 10, 3);

            // Rule #41: WooCommerce Cart Flooding & Denial of Inventory (DoI) Defense
            add_filter('woocommerce_add_to_cart_validation', [__CLASS__, 'validate_woo_add_to_cart'], 10, 5);

            // Rule #42: WooCommerce Catalog & Price Scraping Mitigation
            add_action('template_redirect', [__CLASS__, 'inspect_woo_catalog_scraping'], 1);
        }

        // Rule #44: Runtime Privilege Escalation Guard (In-Memory RASP Hook Firewall)
        add_filter('pre_update_option', [__CLASS__, 'rasp_guard_critical_options'], 1, 3);
        add_action('set_user_role', [__CLASS__, 'rasp_guard_user_role_assignment'], 1, 3);
        add_action('user_register', [__CLASS__, 'rasp_guard_user_registration'], 1, 1);
        add_filter('update_user_metadata', [__CLASS__, 'rasp_guard_user_metadata_injection'], 1, 5);
        add_filter('add_user_metadata', [__CLASS__, 'rasp_guard_user_metadata_injection'], 1, 5);
        add_action('wp_create_application_password', [__CLASS__, 'telemetry_on_application_password_created'], 10, 4);
    }

    /**
     * Normalize $_SERVER['REMOTE_ADDR'] when connecting behind verified trusted reverse proxies (e.g. Cloudflare).
     *
     * Resolves the real client IP from CF-Connecting-IP or X-Forwarded-For if and only if
     * the incoming REMOTE_ADDR matches a verified trusted proxy CIDR (e.g. Cloudflare Anycast edge nodes).
     * This ensures WordPress core (e.g. WP_Session_Tokens, comment logs) and coexisting plugins record
     * the real visitor IP instead of Cloudflare internal proxy node IPs on origin servers lacking mod_remoteip.
     *
     * @return void
     */
    public static function normalize_server_remote_addr(): void {
        if (empty($_SERVER['REMOTE_ADDR'])) {
            return;
        }

        $real_ip = self::get_client_ip();
        if (!empty($real_ip) && $real_ip !== $_SERVER['REMOTE_ADDR']) {
            $_SERVER['REMOTE_ADDR'] = $real_ip;
        }
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

        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? trim(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']))) : '';
        if (stripos($remote_addr, '::ffff:') === 0) {
            $mapped_v4 = substr($remote_addr, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $remote_addr = $mapped_v4;
            }
        }
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

        // Priority 1: Cloudflare CF-Connecting-IP (ONLY if connecting peer is a verified Cloudflare proxy IP - Finding 1.5)
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && self::is_cloudflare_ip($remote_addr)) {
            $cf_ip = trim(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])));
            if (stripos($cf_ip, '::ffff:') === 0) {
                $mapped_cf = substr($cf_ip, 7);
                if (filter_var($mapped_cf, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $cf_ip = $mapped_cf;
                }
            }
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
            $raw_xff = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
            $parts = array_map('sanitize_text_field', array_map('trim', explode(',', $raw_xff)));
            $reversed = array_reverse($parts);
            foreach ($reversed as $candidate) {
                if (stripos($candidate, '::ffff:') === 0) {
                    $mapped_c = substr($candidate, 7);
                    if (filter_var($mapped_c, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $candidate = $mapped_c;
                    }
                }
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
        if (stripos(self::$real_ip, '::ffff:') === 0) {
            $mapped_final = substr(self::$real_ip, 7);
            if (filter_var($mapped_final, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                self::$real_ip = $mapped_final;
            }
        }
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
    /**
     * Official Cloudflare IPv4 and IPv6 CIDR ranges for Anycast edge proxy verification.
     *
     * @return array
     */
    public static function get_cloudflare_ip_ranges(): array {
        return [
            // Cloudflare IPv4 CIDRs
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '108.162.192.0/18',
            '131.0.72.0/22',
            '141.101.64.0/18',
            '162.158.0.0/15',
            '172.64.0.0/13',
            '173.245.48.0/20',
            '188.114.96.0/20',
            '190.93.240.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',

            // Cloudflare IPv6 CIDRs
            '2400:cb00::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            '2405:b500::/32',
            '2405:8100::/32',
            '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];
    }

    /**
     * Check if an IPv4 or IPv6 address belongs to Cloudflare's Anycast Proxy ranges.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_cloudflare_ip(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        foreach (self::get_cloudflare_ip_ranges() as $cidr) {
            if (self::ip_in_range($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a remote connecting IP address belongs to a verified trusted proxy.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_trusted_proxy(string $ip): bool {
        $ip = trim($ip);
        if (stripos($ip, '::ffff:') === 0) {
            $mapped_v4 = substr($ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip = $mapped_v4;
            }
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // 1. Check Cloudflare edge network proxy ranges
        if (self::is_cloudflare_ip($ip)) {
            return true;
        }

        // 2. Check explicitly configured reverse proxy CIDRs/IPs
        $configured = self::get_configured_trusted_proxies();
        foreach ($configured as $range) {
            if (self::ip_in_range($ip, $range)) {
                return true;
            }
        }

        // 3. Localhost / loopback / internal reverse proxy check (e.g. Cloudflare Tunnel, Docker, cPanel Nginx reverse proxy)
        // Local/private proxies are strictly trusted ONLY if WEBCARE_TRUST_LOCAL_PROXY is explicitly enabled by administrator
        $is_local_or_private = ($ip === '127.0.0.1' || $ip === '::1' || self::is_private_ip($ip));
        if ($is_local_or_private) {
            if (defined('WEBCARE_TRUST_LOCAL_PROXY') && WEBCARE_TRUST_LOCAL_PROXY) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP address belongs to private or loopback ranges (RFC 1918 / RFC 4193).
     *
     * @param string $ip
     * @return bool
     */
    public static function is_private_ip(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * Retrieve array of configured trusted proxy IPs/CIDRs from constants, environment, or settings.
     *
     * @return array
     */
    public static function get_configured_trusted_proxies(): array {
        $proxies = [];

        // 1. From constant WEBCARE_TRUSTED_PROXIES (e.g. define('WEBCARE_TRUSTED_PROXIES', '10.0.0.1, 192.168.1.0/24');)
        if (defined('WEBCARE_TRUSTED_PROXIES') && is_string(WEBCARE_TRUSTED_PROXIES) && WEBCARE_TRUSTED_PROXIES !== '') {
            $parts = preg_split('/[\s,;]+/', WEBCARE_TRUSTED_PROXIES);
            foreach ($parts as $p) {
                $p = trim($p);
                if ($p !== '') {
                    $proxies[] = $p;
                }
            }
        }

        // 2. From environment variable WEBCARE_TRUSTED_PROXIES
        $env_proxies = getenv('WEBCARE_TRUSTED_PROXIES') ?: (isset($_ENV['WEBCARE_TRUSTED_PROXIES']) ? sanitize_text_field(wp_unslash($_ENV['WEBCARE_TRUSTED_PROXIES'])) : '');
        if (!empty($env_proxies) && is_string($env_proxies)) {
            $parts = preg_split('/[\s,;]+/', $env_proxies);
            foreach ($parts as $p) {
                $p = trim($p);
                if ($p !== '') {
                    $proxies[] = $p;
                }
            }
        }

        // 3. From WordPress option and SettingsManager proxy keys
        $opt_sources = [
            function_exists('get_option') ? get_option('webcareproscan_trusted_proxies', '') : '',
            class_exists('\\WebCareProScanner\\System\\SettingsManager') ? SettingsManager::get('trusted_proxy_ips', '') : '',
            class_exists('\\WebCareProScanner\\System\\SettingsManager') ? SettingsManager::get('waf_trusted_proxy_cidrs', '') : '',
        ];
        foreach ($opt_sources as $opt) {
            if (!empty($opt) && is_string($opt)) {
                $parts = preg_split('/[\s,;]+/', $opt);
                foreach ($parts as $p) {
                    $p = trim($p);
                    if ($p !== '') {
                        $proxies[] = $p;
                    }
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
     * Check if the incoming request is made by a verified authenticated WordPress administrator.
     *
     * @return bool
     */
    public static function is_authenticated_administrator(): bool {
        static $cached_result = null;
        if ($cached_result === true) {
            return true;
        }
        if ($cached_result === false && function_exists('did_action') && did_action('init')) {
            return false;
        }

        $verified_user_id = 0;

        // Layer 1: Check standard WordPress authenticated session if available (skip during PCP _pc_ DB sandboxing so $current_user isn't cached as 0 against *_pc_users)
        if (!self::is_plugin_check_db_sandbox() && function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('get_current_user_id')) {
            $verified_user_id = (int) get_current_user_id();
        }

        // Layer 2: Independent Cryptographic Auth Cookie Validation (essential at plugins_loaded: 0)
        if ($verified_user_id <= 0) {
            if (!function_exists('wp_validate_auth_cookie') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
                require_once ABSPATH . 'wp-includes/pluggable.php';
            }
        }

        if ($verified_user_id <= 0 && function_exists('wp_validate_auth_cookie')) {
            $auth_cookie    = '';
            $cookie_schemes = ['logged_in', 'secure_auth', 'auth'];
            $is_pcp_sandbox = self::is_plugin_check_db_sandbox();
            $orig_prefix    = $is_pcp_sandbox ? self::get_original_table_prefix() : '';

            foreach ($cookie_schemes as $scheme) {
                if ($scheme === 'logged_in') {
                    $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : 'wordpress_logged_in_' . COOKIEHASH;
                } elseif ($scheme === 'secure_auth') {
                    $cookie_name = defined('SECURE_AUTH_COOKIE') ? SECURE_AUTH_COOKIE : 'wordpress_sec_' . COOKIEHASH;
                } else {
                    $cookie_name = defined('AUTH_COOKIE') ? AUTH_COOKIE : 'wordpress_' . COOKIEHASH;
                }

                if (!empty($_COOKIE[$cookie_name])) {
                    $auth_cookie = sanitize_text_field(wp_unslash($_COOKIE[$cookie_name]));
                    if (!$is_pcp_sandbox) {
                        $uid = (int) wp_validate_auth_cookie($auth_cookie, $scheme);
                        if ($uid > 0) {
                            $verified_user_id = $uid;
                            break;
                        }
                    } else {
                        $orig_auth = self::validate_cookie_against_original_tables($auth_cookie, $scheme, $orig_prefix);
                        if (!empty($orig_auth['user_id']) && !empty($orig_auth['is_admin'])) {
                            $verified_user_id = (int) $orig_auth['user_id'];
                            break;
                        }
                    }
                }
            }

            // Fallback for default cookie names if constants aren't defined yet
            if ($verified_user_id <= 0) {
                foreach ($_COOKIE as $c_name => $c_val) {
                    $scheme_guess = '';
                    if (strpos($c_name, 'wordpress_logged_in_') === 0) {
                        $scheme_guess = 'logged_in';
                    } elseif (strpos($c_name, 'wordpress_sec_') === 0) {
                        $scheme_guess = 'secure_auth';
                    } elseif (strpos($c_name, 'wordpress_') === 0 && $c_name !== 'wordpress_test_cookie') {
                        $scheme_guess = 'auth';
                    }

                    if ($scheme_guess === '') {
                        continue;
                    }

                    $cookie_val = sanitize_text_field(wp_unslash($c_val));
                    if (!$is_pcp_sandbox) {
                        $uid = (int) wp_validate_auth_cookie($cookie_val, $scheme_guess);
                        if ($uid > 0) {
                            $verified_user_id = $uid;
                            break;
                        }
                    } else {
                        $orig_auth = self::validate_cookie_against_original_tables($cookie_val, $scheme_guess, $orig_prefix);
                        if (!empty($orig_auth['user_id']) && !empty($orig_auth['is_admin'])) {
                            $verified_user_id = (int) $orig_auth['user_id'];
                            break;
                        }
                    }
                }
            }
        }

        if ($verified_user_id <= 0) {
            if (function_exists('did_action') && did_action('init')) {
                $cached_result = false;
            }
            return false;
        }

        // Layer 3: Role and High-Privilege Capability Verification
        if (function_exists('get_userdata')) {
            $user = get_userdata($verified_user_id);
            if (!$user || empty($user->ID)) {
                if (function_exists('did_action') && did_action('init')) {
                    $cached_result = false;
                }
                return false;
            }

            // Require administrator role or explicit manage_options capability
            $has_admin_cap = $user->has_cap('manage_options') || $user->has_cap('administrator');
            $has_admin_role = in_array('administrator', (array) $user->roles, true);

            // Resilient check: If $wpdb->prefix was temporarily amended (e.g. Plugin Check 'wp_pc_'),
            // look up the user's authentic capabilities under the true base prefix $orig_prefix
            if (!$has_admin_cap && !$has_admin_role) {
                global $wpdb;
                $base_prefix = self::get_original_table_prefix();
                if (isset($wpdb->prefix) && $wpdb->prefix !== $base_prefix) {
                    $base_caps = get_user_meta($verified_user_id, $base_prefix . 'capabilities', true);
                    if (is_array($base_caps) && (!empty($base_caps['administrator']) || !empty($base_caps['manage_options']))) {
                        $has_admin_cap = true;
                        $has_admin_role = true;
                    }
                }
            }

            if (!$has_admin_cap && !$has_admin_role) {
                if (function_exists('did_action') && did_action('init')) {
                    $cached_result = false;
                }
                return false;
            }
        } else {
            if (function_exists('did_action') && did_action('init')) {
                $cached_result = false;
            }
            return false;
        }

        // Layer 4: Cryptographic Nonce Verification on REST API & AJAX Mutation Requests
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $has_rest_query = !empty($_GET['rest_route']) || !empty($_POST['rest_route']);
        $is_rest_call = (strpos($request_uri, '/wp-json/') !== false)
            || (defined('REST_REQUEST') && REST_REQUEST)
            || $has_rest_query
            || (strpos($request_uri, 'rest_route=') !== false);

        if ($is_rest_call && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $nonce = isset($_SERVER['HTTP_X_WP_NONCE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE'])) : '';
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if (empty($nonce) && !empty($_REQUEST['_wpnonce'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $nonce = sanitize_text_field(wp_unslash($_REQUEST['_wpnonce']));
            }
            if (empty($nonce)) {
                // REST mutation without nonce header is untrusted (protects against CSRF)
                if (function_exists('did_action') && did_action('init')) {
                    $cached_result = false;
                }
                return false;
            }

            if (function_exists('wp_verify_nonce')) {
                // Switch current user context to verified user for accurate nonce calculation
                $prev_uid = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                if ($prev_uid !== $verified_user_id && function_exists('wp_set_current_user')) {
                    wp_set_current_user($verified_user_id);
                }

                $nonce_valid = wp_verify_nonce($nonce, 'wp_rest');

                if ($prev_uid !== $verified_user_id && function_exists('wp_set_current_user')) {
                    wp_set_current_user($prev_uid);
                }

                if (!$nonce_valid) {
                    if (function_exists('did_action') && did_action('init')) {
                        $cached_result = false;
                    }
                    return false;
                }
            }
        }

        return ($cached_result = true);
    }

    /**
     * Resolve and normalize REST API route from request URI or query parameters.
     * Returns normalized path with leading slash and without trailing slash (e.g. '/wp/v2/posts').
     *
     * @param string $request_uri
     * @return string Normalized route path or empty string.
     */
    public static function resolve_normalized_rest_route(string $request_uri): string {
        $parsed_path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?? '');
        if (preg_match('#/wp-json(/[^?]+)#i', $parsed_path, $rm)) {
            return '/' . trim($rm[1], '/');
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['rest_route']) && is_string($_GET['rest_route'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return '/' . trim(sanitize_text_field(wp_unslash($_GET['rest_route'])), '/');
        }
        return '';
    }

    /**
     * Safe-pass verification for authenticated Editors, Authors, and Shop Managers in page builder/REST contexts (WCP-16).
     */
    public static function is_verified_editor_builder_request(string $request_uri): bool {
        $req_method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])))
            : 'GET';
        if (!in_array($req_method, ['POST', 'PUT', 'PATCH'], true)) {
            return false;
        }

        if (!function_exists('is_user_logged_in') || !is_user_logged_in()) {
            return false;
        }

        if (!function_exists('current_user_can') || !(current_user_can('edit_posts') || current_user_can('manage_woocommerce'))) {
            return false;
        }

        $rest_route = self::resolve_normalized_rest_route($request_uri);
        $is_gutenberg_rest = (bool) preg_match(
            '#^/wp/v2/(?:(?:posts|pages|blocks)(?:/\d+)?(?:/autosaves)?|(?:templates|template-parts|navigation|global-styles)(?:/[a-z0-9_/-]+)?)$#i',
            $rest_route
        );
        $is_builder_rest = (bool) preg_match(
            '#^/(?:elementor/v\d+/(?:documents|globals|kits|template)(?:/[a-z0-9_/-]+)?|(?:breakdance|brizy|seedprod|droip|generateblocks|kadence|uag|fusion-builder)/v\d+/[a-z0-9_/-]+)$#i',
            $rest_route
        );

        $is_rest_authoring = ($is_gutenberg_rest || $is_builder_rest);

        $parsed_path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?? '');
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $req_action = isset($_REQUEST['action']) ? sanitize_key((string) $_REQUEST['action']) : '';
        $is_ajax_builder = str_contains($parsed_path, 'admin-ajax.php')
            && in_array($req_action, ['elementor_ajax', 'elementor_save_builder'], true);

        if (!$is_rest_authoring && !$is_ajax_builder) {
            return false;
        }

        // Verify standard WP REST nonce or Elementor AJAX nonce
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $rest_nonce = isset($_SERVER['HTTP_X_WP_NONCE'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE']))
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            : (isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '');
        if ($is_rest_authoring && $rest_nonce !== '' && function_exists('wp_verify_nonce')) {
            return (bool) wp_verify_nonce($rest_nonce, 'wp_rest');
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $ajax_nonce = isset($_REQUEST['_nonce'])
            ? sanitize_text_field(wp_unslash($_REQUEST['_nonce']))
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            : (isset($_REQUEST['nonce']) ? sanitize_text_field(wp_unslash($_REQUEST['nonce'])) : '');
        if ($is_ajax_builder && $ajax_nonce !== '' && function_exists('wp_verify_nonce')) {
            return (bool) (wp_verify_nonce($ajax_nonce, 'elementor_ajax') || wp_verify_nonce($ajax_nonce, 'wp_rest'));
        }

        return false;
    }

    /**
     * Check whether the current request is from an authenticated user with Content Editor privileges
     * or an active visual page builder session (Elementor, Divi, Gutenberg, Bricks, Beaver Builder).
     *
     * Validates:
     * 1. Cryptographically valid auth cookie for an active user.
     * 2. User holds 'edit_posts', 'edit_pages', or 'manage_options' capability.
     * 3. Request targets page builder AJAX, REST API, or frontend builder preview session with matching nonce.
     *
     * @return bool
     */
    public static function is_authenticated_editor_or_builder(bool $reset = false): bool {
        static $cached_builder_result = null;
        if ($reset) {
            $cached_builder_result = null;
        }
        if ($cached_builder_result !== null) {
            return $cached_builder_result;
        }

        // Require a state-changing write method before granting WAF authoring exemption (Fix 2)
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        if (!in_array($request_method, ['POST', 'PUT', 'PATCH'], true)) {
            return ($cached_builder_result = false);
        }

        // Check if page builder smart pass is enabled in settings
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        if (isset($settings['waf_allow_page_builders']) && empty($settings['waf_allow_page_builders'])) {
            return ($cached_builder_result = false);
        }

        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (self::is_verified_editor_builder_request($req_uri)) {
            return ($cached_builder_result = true);
        }

        $verified_user_id = 0;
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('get_current_user_id')) {
            $verified_user_id = (int) get_current_user_id();
        }

        if ($verified_user_id <= 0) {
            if (!function_exists('wp_validate_auth_cookie') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
                require_once ABSPATH . 'wp-includes/pluggable.php';
            }
            if (function_exists('wp_validate_auth_cookie') && !empty($_COOKIE)) {
                foreach ($_COOKIE as $c_name => $c_val) {
                    if (strpos($c_name, 'wordpress_logged_in_') === 0 || strpos($c_name, 'wordpress_sec_') === 0) {
                        $uid = (int) wp_validate_auth_cookie(sanitize_text_field(wp_unslash($c_val)), 'logged_in')
                            ?: (int) wp_validate_auth_cookie(sanitize_text_field(wp_unslash($c_val)), 'secure_auth');
                        if ($uid > 0) {
                            $verified_user_id = $uid;
                            break;
                        }
                    }
                }
            }
        }

        if ($verified_user_id <= 0) {
            return ($cached_builder_result = false);
        }

        // Verify Editor / Content Author capabilities (Must have unfiltered_html or manage_options to bypass WAF)
        if (function_exists('get_userdata')) {
            $user = get_userdata($verified_user_id);
            if (!$user || empty($user->ID)) {
                return ($cached_builder_result = false);
            }

            $has_editor_cap = $user->has_cap('unfiltered_html') || $user->has_cap('manage_options');
            if (!$has_editor_cap) {
                return ($cached_builder_result = false);
            }
        } else {
            return ($cached_builder_result = false);
        }

        // Require valid REST or builder nonce before granting WAF authoring exemption (Fix 2)
        $nonce = '';
        if (!empty($_SERVER['HTTP_X_WP_NONCE'])) {
            $nonce = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE']));
        } elseif (!empty($_REQUEST['_wpnonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $nonce = sanitize_text_field(wp_unslash($_REQUEST['_wpnonce']));
        } elseif (!empty($_REQUEST['editor_post_nonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $nonce = sanitize_text_field(wp_unslash($_REQUEST['editor_post_nonce']));
        }

        if (!function_exists('wp_verify_nonce') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
            require_once ABSPATH . 'wp-includes/pluggable.php';
        }

        $nonce_valid = false;
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        $action_hint = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
        if ($nonce !== '' && function_exists('wp_verify_nonce')) {
            if (wp_verify_nonce($nonce, 'wp_rest') || wp_verify_nonce($nonce, 'elementor_ajax') || wp_verify_nonce($nonce, -1) || ($action_hint !== '' && wp_verify_nonce($nonce, 'wp_ajax_' . $action_hint))) {
                $nonce_valid = true;
            }
        }

        if (!$nonce_valid) {
            return ($cached_builder_result = false);
        }

        // Identify builder-specific actions and endpoints
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early runtime WAF builder detection
        $ajax_action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');

        $has_builders = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('page_builder')
            : true;

        $rest_route = self::resolve_normalized_rest_route($request_uri);
        $is_gutenberg_rest = (bool) preg_match(
            '#^/wp/v2/(?:(?:posts|pages|blocks)(?:/\d+)?(?:/autosaves)?|(?:templates|template-parts|navigation|global-styles)(?:/[a-z0-9_/-]+)?)$#i',
            $rest_route
        );

        $is_builder_ajax = false;
        $is_builder_rest = false;

        if ($has_builders) {
            // 20 Popular WordPress Visual Builders & Block Suites:
            // 1. Elementor, 2. Divi, 3. Beaver, 4. Bricks, 5. Breakdance, 6. Oxygen, 7. SeedProd,
            // 8. Brizy, 9. Thrive Architect, 10. WPBakery, 11. Visual Composer, 12. Themify,
            // 13. SiteOrigin, 14. Droip, 15. Live Composer, 16. WP Site Editor / Gutenberg FSE,
            // 17. GenerateBlocks, 18. Kadence Blocks, 19. Spectra, 20. Avada Fusion Builder
            $is_builder_ajax = in_array($ajax_action, [
                // Elementor & Divi
                'elementor_ajax', 'elementor_save_builder', 'et_fb_save_builder', 'et_fb_ajax_save',
                // Beaver Builder & Bricks
                'fl_builder_save_layout', 'bricks_save_post',
                // Breakdance & Oxygen
                'breakdance_save_document', 'ct_save_oxygen_data',
                // SeedProd & Brizy
                'seedprod_save_page', 'brizy_update_item', 'brizy_create_item',
                // Thrive Architect & WPBakery
                'tve_ajax_save_post', 'wpb_save_post', 'vc_save', 'vcv-ajax',
                // Themify Builder & SiteOrigin
                'themify_builder_save_data', 'so_panels_save',
                // Droip & Live Composer
                'droip_save_page', 'dslc-ajax-save-composer',
                // Avada Fusion Builder
                'fusion_app_save_post', 'fusion_save_post',
                // Block Suites (Kadence, GenerateBlocks, Spectra)
                'kadence_save_block', 'generateblocks_save', 'uagb_save_block',
            ], true);

            $is_builder_rest = (bool) preg_match(
                '#^/(?:elementor/v\d+/(?:documents|globals|kits|template)(?:/[a-z0-9_/-]+)?|(?:breakdance|brizy|seedprod|droip|generateblocks|kadence|uag|fusion-builder)/v\d+/[a-z0-9_/-]+)$#i',
                $rest_route
            );
        }
        if ($is_builder_ajax || $is_gutenberg_rest || $is_builder_rest) {
            return ($cached_builder_result = true);
        }

        return ($cached_builder_result = false);
    }

    /**
     * Inspect Incoming Request
     */
    public static function inspect_incoming_request() {
        // Emergency Override / Failsafe: Bypass all firewall inspection if WEBCAREPROSCAN_DISABLE_WAF or WEBCAREPROSCAN_DISABLE_FIREWALL is defined in wp-config.php
        if ((defined('WEBCAREPROSCAN_DISABLE_WAF') && WEBCAREPROSCAN_DISABLE_WAF) || (defined('WEBCAREPROSCAN_DISABLE_FIREWALL') && WEBCAREPROSCAN_DISABLE_FIREWALL) || (defined('WEBCARE_CAF_DISABLE_PRELOAD') && WEBCARE_CAF_DISABLE_PRELOAD)) {
            return;
        }

        // CAF Killswitch check
        if (defined('WP_CONTENT_DIR') && (file_exists(WP_CONTENT_DIR . '/uploads/webcare-pro-security/.killswitch') || file_exists(WP_CONTENT_DIR . '/webcare-vault/.killswitch'))) {
            return;
        }

        // Skip CLI execution
        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) {
            return;
        }

        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

        // If DOING_CRON is defined, only skip if this is NOT an external HTTP trigger to wp-cron.php
        if (defined('DOING_CRON') && DOING_CRON) {
            $clean_cron_check = strtolower(wp_parse_url($req_uri, PHP_URL_PATH) ?: $req_uri);
            if (strpos($clean_cron_check, 'wp-cron.php') === false) {
                return;
            }
        }
        $is_rest = (defined('REST_REQUEST') && REST_REQUEST) || strpos($req_uri, '/wp-json/') !== false || strpos($req_uri, '?rest_route=') !== false;
        $is_ajax = (defined('DOING_AJAX') && DOING_AJAX) || strpos($req_uri, 'admin-ajax.php') !== false;
        $is_admin_area = is_admin() || strpos($req_uri, '/wp-admin/') !== false;

        if (!$is_admin_area && !$is_rest && !$is_ajax && !self::is_authenticated_administrator()) {
            if (get_transient('webcareproscan_active_visitor_traffic_15s') === false) {
                set_transient('webcareproscan_active_visitor_traffic_15s', 1, 15);
            }
        }

        $settings = SettingsManager::get_settings();

        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        $raw_req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $client_ip = self::get_client_ip();

        // Rescue Assistant Integration: Bypass permanently trusted actions or downgrade to learning during 15m Test Pause
        if (class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            if (\WebCareProScanner\Firewall\RescueAssistantManager::is_incoming_request_trusted($raw_req_uri)) {
                return;
            }
            if (\WebCareProScanner\Firewall\RescueAssistantManager::is_strict_paused()) {
                $settings['waf_mode'] = 'learning';
            }
        }

        // Tiered Context-Aware IP Whitelist Check (Replaces legacy unconditional early return)
        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted'] && $whitelist_ctx['full_bypass']) {
            // Verified Authenticated Administrator (or legacy full-bypass override mode):
            // Grant safe bypass across all frontend and backend inspection checks.
            return;
        }

        // Fast-path: Check custom user IP blocklist immediately to drop hostile banned bots
        // and prevent redundant downstream processing / repeated rate-limit escalations
        if (!empty($settings['waf_blocked_ips'])) {
            $matching_entry = self::get_matching_blocked_entry($client_ip, $settings['waf_blocked_ips']);
            if ($matching_entry !== null) {
                // Immunity check: Ensure legitimate search engine crawlers (Googlebot, Bingbot)
                // that may have been erroneously or transitively added are automatically pardoned and unblocked.
                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
                $is_legit_crawler = false;
                if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                    $is_legit_crawler = BotReconDefense::is_genuine_search_engine($client_ip, $ua);
                }

                if ($is_legit_crawler) {
                    // Auto-heal blocklist: Remove false-positive ban for verified search crawler
                    self::remove_blocked_ip($matching_entry);
                    self::remove_blocked_ip($client_ip);
                } else {
                    $block_meta = self::get_ip_block_meta($matching_entry) ?: self::get_ip_block_meta($client_ip);
                    $expires_at = !empty($block_meta['expires_at']) ? (int) $block_meta['expires_at'] : 0;

                    // Auto-heal expired temporary ban: unblock if duration has elapsed
                    if ($expires_at > 0 && time() >= $expires_at) {
                        self::remove_blocked_ip($matching_entry);
                        self::remove_blocked_ip($client_ip);
                        $matching_entry = null;
                    }

                    if ($matching_entry !== null) {
                        $ban_reason = !empty($block_meta['reason']) ? trim((string) $block_meta['reason']) : '';
                        $ban_source = !empty($block_meta['source']) ? trim((string) $block_meta['source']) : 'custom_blocklist';
                        $ban_rule   = !empty($block_meta['rule_name']) ? trim((string) $block_meta['rule_name']) : '';

                        // Shopper & E-Commerce Session Protection:
                        // If the visitor has an active e-commerce / membership cart session (e.g. WooCommerce cart cookies, EDD, SureCart)
                        // or is requesting checkout / payment gateway endpoints (wc-ajax, paypal, stripe),
                        // ensure legitimate paying customers are NOT permanently locked out by automated or non-admin bans.
                        $is_manual_admin_ban = ($ban_source === 'manual_admin') || (!empty($block_meta['admin_user']));
                        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

                        $description = 'Connection blocked by administrator-defined custom IP rule.';
                        if (!empty($ban_reason)) {
                            $description = sprintf('Connection blocked: %s', $ban_reason);
                        } elseif (!empty($ban_rule)) {
                            $description = sprintf('Connection blocked by automated rule: %s', $ban_rule);
                        }

                        $rule_triggered = [
                            'id'             => 'USER-CUSTOM-IP-BLOCK',
                            'name'           => 'Custom Administrator IP Blocklist',
                            'category'       => 'Custom IP Blocklist',
                            'description'    => $description,
                            'match_type'     => 'Custom Blocklist',
                            'match_value'    => $matching_entry,
                            'payload'        => $client_ip,
                            'ban_reason'     => $ban_reason,
                            'ban_source'     => $ban_source,
                            'matching_entry' => $matching_entry,
                            'expires_at'     => $expires_at,
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
            }
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

        $url_whitelisted = false;
        // Check Allowlisted URLs / URI paths (bypasses operational heuristics, but not explicit administrator block rules or mandatory signatures)
        if (!empty($settings['waf_whitelisted_urls']) && self::is_url_whitelisted($request_uri, $settings['waf_whitelisted_urls'])) {
            $url_whitelisted = true;
        }

        // Check Targeted User-Agent, Endpoint & IP Allowlist Rules (Zero-Trust granular bypass)
        $targeted_rules_raw = $settings['waf_targeted_allowlist_rules'] ?? '[]';
        $targeted_rules = is_array($targeted_rules_raw) ? $targeted_rules_raw : json_decode((string) $targeted_rules_raw, true);
        if (!$url_whitelisted && !empty($targeted_rules) && is_array($targeted_rules)) {
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            $http_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
            $matched_rule = self::match_targeted_allowlist_rule($request_uri, $user_agent, $client_ip, $http_method, $targeted_rules);
            if ($matched_rule !== null) {
                // Log granular forensic telemetry to WAF logs
                self::log_targeted_allowlist_hit($matched_rule, $client_ip, $request_uri, $user_agent, $http_method);
                $url_whitelisted = true;
            }
        }

        // Safe Bypass for Verified Authenticated Administrators and Page Builder Sessions
        // (Prevents false-positive blocks when managing comments, posts, plugins, or editing pages via Elementor/Divi/Gutenberg)
        // Two-Tier Privilege Architecture:
        // Authenticated administrators performing backend actions and verified page-builder sessions
        // bypass operational rate-limiting, velocity tracking, and format heuristics, but NEVER bypass
        // mandatory exploit signatures (SQLi, RCE, LFI, polyglot uploads) or explicit administrator block rules.
        $is_admin_operation   = false;
        $is_builder_operation = false;
        // Red Team Drill Exception: Never bypass when drill token is present
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Passive inspection of drill token for red team simulation bypass
        $is_drill_request = !empty($_GET['webcare_drill_token']) || !empty($_POST['webcare_drill_token']) || !empty($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']);
        if (!$is_drill_request) {
            if (self::is_authenticated_administrator()) {
                $is_admin_operation = (is_admin() || strpos($request_uri, '/wp-admin/') !== false || strpos($request_uri, '/wp-json/webcare-pro-security/') !== false);
            } elseif (self::is_verified_editor_builder_request($request_uri) || self::is_authenticated_editor_or_builder()) {
                $is_builder_operation = true;
            }
        }

        $custom_allow_matched = false;
        // Modular Intelligence Firewall & Custom Firewall Rules Runtime Enforcement
        // Evaluated ahead of rate-limiter/PoW gates so explicit Custom rules return exact configured verdicts immediately.
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            $modular_violation = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::evaluate_runtime_modular_rules();
            if ($modular_violation !== null) {
                $mod_action = (string) ($modular_violation['action_type'] ?? '');
                if ($mod_action === 'allow') {
                    $custom_allow_matched = true;
                } elseif ($mod_action === 'challenge_pow' && !empty($modular_violation['blocked']) && class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                    $ua_raw = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
                    if (!\WebCareProScanner\Firewall\BotReconDefense::has_valid_clearance_cookie($client_ip, $ua_raw)) {
                        $rule_triggered = [
                            'id'          => $modular_violation['rule_id'],
                            'name'        => 'Custom Firewall Rule PoW Challenge',
                            'category'    => 'Modular Behavioral WAF',
                            'description' => $modular_violation['reason'],
                            'match_type'  => $modular_violation['category'],
                            'match_value' => $modular_violation['rule_id'],
                            'payload'     => "Client IP: {$client_ip} URI: {$request_uri}",
                        ];
                        self::log_incident($rule_triggered, 'challenged');
                        \WebCareProScanner\Firewall\BotReconDefense::render_pow_challenge($client_ip, $modular_violation['reason']);
                    }
                } else {
                    $rule_triggered = [
                        'id'              => $modular_violation['rule_id'],
                        'name'            => !empty($modular_violation['title']) ? $modular_violation['title'] : 'Modular Intelligence Firewall Rule',
                        'category'        => !empty($modular_violation['category']) && $modular_violation['category'] === 'custom' ? 'Custom Modular Rule' : 'Modular Behavioral WAF',
                        'description'     => $modular_violation['reason'],
                        'match_type'      => $modular_violation['category'],
                        'match_value'     => $modular_violation['rule_id'],
                        'payload'         => "Client IP: {$client_ip} URI: {$request_uri}",
                        'sync_cloudflare' => !empty($modular_violation['sync_cloudflare']),
                        'ban_ttl'         => (int) ($modular_violation['ban_ttl'] ?? 0),
                    ];
                    if ($modular_violation['blocked']) {
                        $http_code = ($mod_action === 'rate_limit') ? 429 : 403;
                        self::handle_rule_violation($rule_triggered, $settings, $client_ip, $http_code);
                    } else {
                        self::log_incident($rule_triggered, 'detected');
                    }
                }
            }
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer') && \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::did_custom_allow_match()) {
            $custom_allow_matched = true;
        }

        $skip_operational_heuristics = ($url_whitelisted || $custom_allow_matched || $is_admin_operation || $is_builder_operation);

        // Differential Threat Score & Behavioral Pre-Flight Sentinel (CAF Phase 3)
        if (!$skip_operational_heuristics && class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::inspect_client_threat($client_ip);
        }

        // Adaptive Rate Limiter & Token-Bucket Throttling
        if (!$skip_operational_heuristics && class_exists('\\WebCareProScanner\\Firewall\\AdaptiveRateLimiter')) {
            \WebCareProScanner\Firewall\AdaptiveRateLimiter::check_request($client_ip);
        }

        // WebCrypto Proof-of-Work (PoW) Enforced Suspicious IP Sentinel
        if (!$skip_operational_heuristics) {
            $pow_ips = get_option('webcare_pow_enforced_ips', []);
            if (is_array($pow_ips) && isset($pow_ips[$client_ip])) {
                $pow_exp = (int) ($pow_ips[$client_ip]['expires_at'] ?? 0);
                if ($pow_exp > 0 && time() > $pow_exp) {
                    unset($pow_ips[$client_ip]);
                    update_option('webcare_pow_enforced_ips', $pow_ips, false);
                } elseif (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                    \WebCareProScanner\Firewall\BotReconDefense::verify_or_challenge_client();
                }
            }
        }

        // HTTP/2 & HTTP/3 Pseudo-Header and Client-Hint Anomaly Sentinel (CAF Phase 3)
        if (!$skip_operational_heuristics && class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
            $h2_anomaly = \WebCareProScanner\Firewall\BotReconDefense::check_http2_pseudo_header_anomaly();
            if ($h2_anomaly !== null) {
                // Record threat score increment for header anomaly (+15)
                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
                    \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, 'header_anomaly', 15.0);
                }

                // Only hard-block malformed uppercase HTTP/2 pseudo-headers (or when strict HTTP/2 blocking is explicitly enabled)
                if (($h2_anomaly['anomaly'] ?? '') === 'uppercase_pseudo_header' || !empty($settings['waf_block_http2_anomalies'])) {
                    $rule_triggered = [
                        'id'          => 'BOT-H2-HEADER-ANOMALY',
                        'name'        => 'HTTP/2 Header / Client-Hint Anomaly',
                        'category'    => 'Protocol Anomaly Defense',
                        'description' => $h2_anomaly['description'],
                        'match_type'  => 'Header Anomaly',
                        'match_value' => $h2_anomaly['anomaly'],
                        'payload'     => "Client IP: {$client_ip} URI: {$request_uri}",
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                }
            }
        }

        // Pluggable Module SDK & 2026-2027 Next-Gen WAF Sentinels Runtime Pipeline
        if (
            !$skip_operational_heuristics
            && class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')
            && class_exists('\\WebCareProScanner\\Contracts\\RequestContext')
        ) {
            $req_ctx = \WebCareProScanner\Contracts\RequestContext::from_globals();
            $verdict = \WebCareProScanner\Core\ModuleRegistry::evaluate_runtime_waf($req_ctx, $settings);
            if ($verdict !== null) {
                if ($verdict->action === 'allow') {
                    $custom_allow_matched = true;
                    $skip_operational_heuristics = true;
                } elseif ($verdict->action === 'challenge_pow' && class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                    if (!\WebCareProScanner\Firewall\BotReconDefense::has_valid_clearance_cookie($client_ip, $req_ctx->userAgent)) {
                        self::log_incident([
                            'id'          => $verdict->ruleId,
                            'name'        => $verdict->category,
                            'category'    => $verdict->category,
                            'description' => $verdict->reason,
                            'match_type'  => $verdict->action,
                            'match_value' => $verdict->ruleId,
                            'payload'     => "Client IP: {$client_ip} URI: {$request_uri}",
                        ], 'challenged');
                        \WebCareProScanner\Firewall\BotReconDefense::render_pow_challenge($client_ip, $verdict->reason);
                    }
                } else {
                    $ng_rule = [
                        'id'              => $verdict->ruleId,
                        'name'            => $verdict->category,
                        'category'        => $verdict->category,
                        'description'     => $verdict->reason,
                        'match_type'      => $verdict->action,
                        'match_value'     => $verdict->ruleId,
                        'payload'         => "Client IP: {$client_ip} URI: {$request_uri}",
                        'sync_cloudflare' => $verdict->syncCloudflare,
                        'ban_ttl'         => $verdict->action === 'block_and_ban' ? max(60, $verdict->banTtl) : $verdict->banTtl,
                    ];
                    if (in_array($verdict->action, ['block', 'block_and_ban', 'rate_limit'], true)) {
                        self::handle_rule_violation($ng_rule, $settings, $client_ip, $verdict->statusCode);
                    } else {
                        self::log_incident($ng_rule, 'detected');
                    }
                }
            }
        }

        // Emergency Containment Mode Enforcement
        if (class_exists('\\WebCareProScanner\\Security\\EmergencyContainmentManager') && \WebCareProScanner\Security\EmergencyContainmentManager::is_active()) {
            if (!self::is_authenticated_administrator()) {
                if (\WebCareProScanner\Security\EmergencyContainmentManager::is_maintenance_enabled()) {
                    \WebCareProScanner\Security\EmergencyContainmentManager::render_containment_screen();
                    exit;
                }

                $req_method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
                if (in_array($req_method, ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
                    $rule_triggered = [
                        'id'          => 'WAF-CONTAINMENT-LOCKDOWN',
                        'name'        => 'Emergency Containment Write Lockdown',
                        'category'    => 'Incident Containment',
                        'description' => 'Write operations are strictly prohibited while site is in Emergency Containment Mode.',
                        'match_type'  => 'Containment Policy',
                        'match_value' => $req_method,
                        'payload'     => "Method: {$req_method} URI: {$request_uri} IP: {$client_ip}",
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                                    }

                if (strpos($request_uri, 'xmlrpc.php') !== false || strpos($request_uri, '/wp/v2/users') !== false) {
                    $rule_triggered = [
                        'id'          => 'WAF-CONTAINMENT-SURFACE-LOCK',
                        'name'        => 'Emergency Containment Attack Surface Lock',
                        'category'    => 'Incident Containment',
                        'description' => 'Endpoint locked down by Emergency Containment Mode.',
                        'match_type'  => 'Containment Policy',
                        'match_value' => $request_uri,
                        'payload'     => "URI: {$request_uri} IP: {$client_ip}",
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                                    }
            }
        }

        // Atomic Upgrade Lock Route Shield: Block unauthenticated access to update endpoints while updates run
        if (class_exists('\\WebCareProScanner\\SupplyChain\\UpdateGatekeeperEngine')) {
            $active_lock = \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_active_lock();
            if ($active_lock !== null) {
                $is_admin = self::is_authenticated_administrator();
                $lock_ip = (string) ($active_lock['ip'] ?? '');
                if (!$is_admin && !hash_equals($lock_ip, $client_ip)) {
                    $decoded_uri = rawurldecode($request_uri);
                    if (preg_match('#(?:/wp-admin/(?:upgrade|maint/repair)\.php|/wp-content/(?:plugins|themes|upgrade)/)#i', $decoded_uri)) {
                        $rule_triggered = [
                            'id'          => 'WAF-ATOMIC-UPGRADE-LOCK',
                            'name'        => 'Atomic Upgrade Lock Route Shield',
                            'category'    => 'Supply Chain Defense',
                            'description' => 'Target resource is locked against unauthenticated access during an active software update.',
                            'match_type'  => 'Upgrade Window Lock',
                            'match_value' => $decoded_uri,
                            'payload'     => "URI: {$decoded_uri} IP: {$client_ip}",
                        ];
                        self::handle_rule_violation($rule_triggered, $settings, $client_ip, 423);
                                            }
                }
            }
        }

        // Context-Adaptive Firewall (CAF): Dormant Attack Surface Lockdown
        $lock_dormant = (bool) get_option('webcare_caf_lock_dormant_surface', true);
        if (!$skip_operational_heuristics && $lock_dormant) {
            $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            $decoded_check_uri = rawurldecode($raw_uri);

            // Check if URI targets an inactive plugin or theme directory
            if (preg_match('#/wp-content/plugins/([a-zA-Z0-9_-]+)/#i', $decoded_check_uri, $plugin_matches)) {
                $target_slug = strtolower($plugin_matches[1]);
                $cached_snapshot = get_option('webcare_caf_stack_snapshot');
                $inactive_plugins = is_array($cached_snapshot) && !empty($cached_snapshot['inactive_plugins']) ? array_keys($cached_snapshot['inactive_plugins']) : [];

                if (in_array($target_slug, $inactive_plugins, true)) {
                    $rule_triggered = [
                        'id'          => 'WAF-CAF-DORMANT-SURFACE',
                        'name'        => 'Context-Adaptive Dormant Attack Surface Lockdown',
                        'category'    => 'Dormant Surface Shield',
                        'description' => sprintf('Request targets deactivated plugin "%s". Direct requests to inactive components are strictly blocked.', esc_html($target_slug)),
                        'match_type'  => 'Dormant Plugin Policy',
                        'match_value' => $target_slug,
                        'payload'     => "Target Slug: {$target_slug} URI: {$raw_uri} IP: {$client_ip}",
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                                    }
            } elseif (preg_match('#/wp-content/themes/([a-zA-Z0-9_-]+)/#i', $decoded_check_uri, $theme_matches)) {
                $target_theme = strtolower($theme_matches[1]);
                $cached_snapshot = get_option('webcare_caf_stack_snapshot');
                $inactive_themes = is_array($cached_snapshot) && !empty($cached_snapshot['inactive_themes']) ? array_keys($cached_snapshot['inactive_themes']) : [];

                if (in_array($target_theme, $inactive_themes, true)) {
                    $rule_triggered = [
                        'id'          => 'WAF-CAF-DORMANT-THEME',
                        'name'        => 'Context-Adaptive Dormant Theme Surface Lockdown',
                        'category'    => 'Dormant Surface Shield',
                        'description' => sprintf('Request targets inactive theme "%s". Direct requests to inactive themes are strictly blocked.', esc_html($target_theme)),
                        'match_type'  => 'Dormant Theme Policy',
                        'match_value' => $target_theme,
                        'payload'     => "Target Theme: {$target_theme} URI: {$raw_uri} IP: {$client_ip}",
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                                    }
            }
        }

        $is_builder_session = self::is_authenticated_editor_or_builder();
        if ($is_builder_session) {
            // Verified editors in builder context (Elementor AJAX, Gutenberg REST, Divi save) are exempt from early admin area restrictions
            $is_admin_builder = (strpos($request_uri, 'admin-ajax.php') !== false || strpos($request_uri, '/wp-json/wp/v2/') !== false || strpos($request_uri, '/wp-json/elementor/') !== false);
            if ($is_admin_builder) {
                return;
            }
        }

        // Central Management Worker Bypass (ManageWP, MainWP, InfiniteWP)
        // Requests from central management plugins are flagged for context, but MUST still pass through standard WAF exploit inspection
        $is_central_mgmt = self::is_verified_central_management_request($request_uri, $settings);

        // Rule #34: Oversized Request Buffer & DoS Guard (Earliest execution check)
        if (!empty($settings['waf_block_oversized_requests'])) {
            $is_upload_endpoint = (strpos($request_uri, 'async-upload.php') !== false || strpos($request_uri, '/wp-json/wp/v2/media') !== false);
            $is_admin_area = is_admin() || strpos($request_uri, '/wp-admin/') !== false;
            $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && self::is_commerce_or_membership_request($request_uri);
            $is_exempt_endpoint = $is_upload_endpoint || $is_admin_area || $is_builder_session;
            $uri_length = strlen($request_uri);
            $query_length = strlen(isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '');
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early WAF payload size check executes before nonce lifecycle
            $post_count = !empty($_POST) && is_array($_POST) ? count($_POST, COUNT_RECURSIVE) : 0;

            // Bounded URI buffer guard: Commerce payment callbacks permit up to 4096 bytes; default ceiling is 2048 bytes
            $max_uri_limit = ($is_commerce_safe || $is_admin_area) ? 4096 : 2048;
            if ($uri_length > $max_uri_limit && !$is_exempt_endpoint) {
                $rule_triggered = [
                    'id'          => 'WAF-OVERSIZED-URI',
                    'name'        => 'Oversized URI Buffer Overflow Guard',
                    'category'    => 'DoS & Resource Shield',
                    'description' => sprintf('Request URI length of %d bytes exceeded security threshold (%d bytes).', $uri_length, $max_uri_limit),
                    'match_type'  => 'Buffer Overflow Protection',
                    'match_value' => (string) $uri_length,
                    'payload'     => "URI Length: {$uri_length} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 414);
            }

            // Bounded Query String guard: Commerce payment redirects permit up to 2048 bytes; default ceiling is 1024 bytes
            $max_query_limit = ($is_commerce_safe || $is_admin_area) ? 2048 : 1024;
            if ($query_length > $max_query_limit && !$is_exempt_endpoint) {
                $rule_triggered = [
                    'id'          => 'WAF-OVERSIZED-QUERY',
                    'name'        => 'Oversized Query String Guard',
                    'category'    => 'DoS & Resource Shield',
                    'description' => sprintf('Query string length of %d bytes exceeded security threshold (%d bytes).', $query_length, $max_query_limit),
                    'match_type'  => 'Buffer Overflow Protection',
                    'match_value' => (string) $query_length,
                    'payload'     => "Query Length: {$query_length} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
            }

            // Parameter flooding (HashDoS) is NEVER exempted for commerce checkouts (only builders and media uploads)
            $is_param_exempt = $is_upload_endpoint || $is_builder_session;
            if ($post_count > 1000 && !$is_param_exempt) {
                $rule_triggered = [
                    'id'          => 'WAF-OVERSIZED-POST-VARS',
                    'name'        => 'Excessive Parameter Count Flood Guard',
                    'category'    => 'DoS & Resource Shield',
                    'description' => sprintf('POST payload contains %d recursive variables, exceeding security threshold (1000).', $post_count),
                    'match_type'  => 'Parameter Flooding Defense',
                    'match_value' => (string) $post_count,
                    'payload'     => "Params: {$post_count} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 400);
            }
        }

        // Rule #32: Strict Host & Forwarded Host Header Allowlist Guard
        if (!empty($settings['waf_enforce_host_allowlist'])) {
            $is_valid_host = self::validate_host_headers($settings);
            if (!$is_valid_host) {
                $presented_host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : 'unknown';
                $forwarded_host = isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_HOST'])) : '';
                $rule_triggered = [
                    'id'          => 'WAF-HOST-HEADER-POISON',
                    'name'        => 'Host Header Poisoning & Cache Spoof Defense',
                    'category'    => 'Protocol Defense',
                    'description' => sprintf('HTTP Host ("%s") or X-Forwarded-Host ("%s") does not match configured site domain allowlist.', esc_html($presented_host), esc_html($forwarded_host)),
                    'match_type'  => 'Host Header Validation',
                    'match_value' => $presented_host,
                    'payload'     => "Host: {$presented_host} Forwarded: {$forwarded_host} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                            }
        }

        // Rule #33: admin-ajax.php Unauthenticated Request Burst Rate-Limiter
        if (!$skip_operational_heuristics && !empty($settings['waf_limit_admin_ajax'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (strpos($clean_path, 'admin-ajax.php') !== false) {
                $is_logged_in = is_user_logged_in() || self::is_authenticated_administrator() || self::is_authenticated_editor_or_builder();
                if (!$is_logged_in) {
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early admin-ajax rate limiter inspection
                    $ajax_action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
                    // Exclude WooCommerce public customer cart actions if e-commerce smart shield is active
                    $is_woo_public = !empty($settings['waf_ecommerce_safe_mode']) && in_array($ajax_action, [
                        'woocommerce_get_refreshed_fragments',
                        'woocommerce_apply_coupon',
                        'woocommerce_remove_coupon',
                        'woocommerce_update_shipping_method',
                        'woocommerce_update_order_review',
                        'woocommerce_checkout',
                        'woocommerce_add_to_cart',
                    ], true);

                    // Smart Form Plugin Shield: Automatically exempt legitimate form submissions (CF7, WPForms, Fluent Forms, Gravity, Ninja, etc.)
                    $is_form_submission = !empty($settings['waf_forms_safe_mode']) && (
                        self::is_form_submission_request($request_uri) ||
                        in_array($ajax_action, [
                            'wpforms_submit',
                            'wpforms_form_submit',
                            'wpforms_file_upload',
                            'fluentform_submit',
                            'fluentform_file_upload',
                            'fluentform_form_submit',
                            'nf_ajax_submit',
                            'ninja_forms_ajax_submit',
                            'frm_entries_create',
                            'frm_entries_update',
                            'wsf_submit',
                            'happyforms_message',
                            'everest_forms_ajax_submit',
                        ], true)
                    );

                    if (!$is_woo_public && !$is_form_submission) {
                        $limit_per_min = (int) ($settings['waf_admin_ajax_limit_per_min'] ?? 60);
                        $rate_check = self::check_rate_limit('ajax:' . md5($client_ip), $limit_per_min, 60);
                        if (!$rate_check['allowed']) {
                            $rule_triggered = [
                                'id'          => 'WAF-ADMIN-AJAX-BURST',
                                'name'        => 'admin-ajax.php Burst Flood Limit Exceeded',
                                'category'    => 'DoS & Resource Shield',
                                'description' => sprintf('Unauthenticated client exceeded rate threshold (%d requests/min) on admin-ajax.php.', $limit_per_min),
                                'match_type'  => 'AJAX Rate Limiting',
                                'match_value' => $ajax_action ?: 'unknown',
                                'payload'     => "Action: {$ajax_action} IP: {$client_ip}",
                            ];
                            self::log_incident($rule_triggered, 'blocked');
                            status_header(429);
                            header('Retry-After: ' . $rate_check['retry_after']);
                            header('Content-Type: application/json; charset=utf-8');
                            echo json_encode([
                                'success' => false,
                                'data'    => 'Too many AJAX requests. Please wait a moment and try again.'
                            ]);
                            exit;
                        }
                    }
                }
            }
        }

        // Rule #36: Guest admin-ajax.php & admin-post.php Action Matrix Guard
        if (!$skip_operational_heuristics) {
            self::check_guest_ajax_policy($request_uri, $settings, $client_ip);
        }

        // Check XML-RPC Disabled Guard early at plugins_loaded:0
        if (!empty($settings['waf_disable_xmlrpc']) && (strpos($request_uri, 'xmlrpc.php') !== false || (isset($_SERVER['SCRIPT_NAME']) && strpos(sanitize_text_field(wp_unslash($_SERVER['SCRIPT_NAME'])), 'xmlrpc.php') !== false))) {
            // Smart Pass: Exclude verified Automattic Jetpack sync requests
            if (self::is_verified_jetpack_request($client_ip, $request_uri, $settings)) {
                // Legitimate Jetpack request from official Automattic CIDR with valid tokens: permit execution
                return;
            }

            $rule_triggered = [
                'id'          => 'WAF-XMLRPC-DISABLED',
                'name'        => 'XML-RPC Access Prohibited',
                'category'    => 'XML-RPC Disabled',
                'description' => 'XML-RPC request blocked by administrator security policy.',
                'match_type'  => 'Endpoint Block',
                'match_value' => 'xmlrpc.php',
                'payload'     => 'xmlrpc.php invocation',
            ];

            $mode = $settings['waf_mode'] ?? 'enabled';
            if ($mode === 'learning') {
                self::log_incident($rule_triggered, 'detected');
            } else {
                self::log_incident($rule_triggered, 'blocked');
                status_header(403);
                header('Content-Type: text/plain; charset=utf-8');
                echo 'XML-RPC services are disabled on this WordPress installation by WebCare Pro Security.';
                exit;
            }
        }

        // Check HTTP Request Method Whitelist / Block Unsafe Methods (TRACE, TRACK, CONNECT, DEBUG)
        if (!empty($settings['waf_block_unsafe_http_methods'])) {
            $http_method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
            $unsafe_methods = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'];
            if (in_array($http_method, $unsafe_methods, true)) {
                $rule_triggered = [
                    'id'          => 'WAF-UNSAFE-HTTP-METHOD',
                    'name'        => 'Unsafe HTTP Method Block',
                    'category'    => 'Protocol Defense',
                    'description' => sprintf('HTTP %s request blocked by administrator firewall policy.', $http_method),
                    'match_type'  => 'HTTP Method',
                    'match_value' => $http_method,
                    'payload'     => "Method: {$http_method} URI: {$request_uri}",
                ];

                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 405);
                            }
        }

        // HTTP PUT / Arbitrary Webshell Upload Hardening:
        // Legitimate WordPress HTTP PUT mutations only occur within authenticated REST API routes.
        // Direct unauthenticated PUT requests targeting PHP files, uploads, or static paths are blocked.
        $raw_method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
        if ($raw_method === 'PUT') {
            $is_rest_put = (defined('REST_REQUEST') && REST_REQUEST) || (strpos($request_uri, '/wp-json/') !== false) || (strpos($request_uri, 'rest_route=') !== false);
            if (!$is_rest_put && !self::is_authenticated_administrator() && !self::is_authenticated_editor_or_builder()) {
                $rule_triggered = [
                    'id'          => 'WAF-UNAUTHORIZED-PUT-UPLOAD',
                    'name'        => 'Unauthorized HTTP PUT File Upload Guard',
                    'category'    => 'Protocol Defense',
                    'description' => sprintf(
                        /* translators: %s: Request URI path */
                        esc_html__('Unauthenticated HTTP PUT request rejected on non-REST endpoint "%s" to prevent arbitrary webshell upload.', 'webcare-pro-security'),
                        esc_html($request_uri)
                    ),
                    'match_type'  => 'HTTP Method',
                    'match_value' => 'PUT',
                    'payload'     => "Method: PUT URI: {$request_uri} IP: {$client_ip}",
                ];

                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 405);
                            }
        }

        // Smart Rule #48: HTTP Method Override & REST Route Smuggling Guard
        // Blocks unauthenticated guests attempting to smuggle PUT/DELETE/PATCH mutations via _method or X-HTTP-Method-Override
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Pre-flight method inspection
        $override_method = isset($_REQUEST['_method']) ? $_REQUEST['_method'] : (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']) ? $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] : (isset($_SERVER['HTTP_X_METHOD_OVERRIDE']) ? $_SERVER['HTTP_X_METHOD_OVERRIDE'] : ''));
        if (!empty($override_method)) {
            $override_clean = strtoupper(is_string($override_method) ? sanitize_text_field(wp_unslash($override_method)) : 'ARRAY');
            if (in_array($override_clean, ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'ARRAY'], true)) {
                $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in()) || self::is_authenticated_administrator() || self::is_authenticated_editor_or_builder();
                if (!$is_logged_in) {
                    $rule_triggered = [
                        'id'          => 'WAF-REST-METHOD-SMUGGLE',
                        'name'        => 'HTTP Method Override Smuggling Guard (Rule #48)',
                        'category'    => 'Execution Armor',
                        'description' => sprintf(
                            /* translators: %s: Smuggled HTTP method name */
                            esc_html__('Unauthenticated client attempted to smuggle privileged HTTP method (%s) via override parameter/header.', 'webcare-pro-security'),
                            esc_html($override_clean)
                        ),
                        'match_type'  => 'Method Override Smuggling',
                        'match_value' => $override_clean,
                        'payload'     => "Override: {$override_clean} URI: {$request_uri}",
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                }
            }
        }

        // Smart Rule #49: Authentication & Password-Reset Array Type-Confusion Trap
        // Defends against PHP 8+ TypeError crashes and loose comparison bypasses in custom login/reset handlers
        if (!self::is_authenticated_administrator() && !self::is_authenticated_editor_or_builder()) {
            $is_auth_endpoint = (strpos($request_uri, 'wp-login.php') !== false || strpos($request_uri, '/my-account') !== false || str_contains($request_uri, 'wc-ajax') || strpos($request_uri, 'lost-password') !== false || strpos($request_uri, 'action=rp') !== false || strpos($request_uri, 'action=resetpass') !== false);
            $sensitive_auth_keys = $is_auth_endpoint
                ? ['log', 'pwd', 'user_login', 'user_email', 'rp_key', 'key', 'pass1', 'pass2', 'username', 'password']
                : ['log', 'pwd', 'user_login', 'rp_key', 'pass1', 'pass2'];
            $has_auth_type_confusion = false;
            $confusion_key = '';

            foreach ($sensitive_auth_keys as $s_key) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Pre-flight auth array type-confusion audit
                if ((isset($_GET[$s_key]) && is_array($_GET[$s_key])) || (isset($_POST[$s_key]) && is_array($_POST[$s_key]))) {
                    $has_auth_type_confusion = true;
                    $confusion_key = $s_key;
                    break;
                }
            }
            if ($has_auth_type_confusion) {
                $rule_triggered = [
                    'id'          => 'WAF-AUTH-TYPE-CONFUSION',
                    'name'        => 'Authentication Array Type-Confusion Trap (Rule #49)',
                    'category'    => 'Brute Force & Auth Armor',
                    'description' => sprintf(
                        /* translators: %s: Parameter name subjected to type confusion */
                        esc_html__('Non-scalar array submitted for authentication credential (%s) to induce type-confusion or error state.', 'webcare-pro-security'),
                        esc_html($confusion_key)
                    ),
                    'match_type'  => 'Type Confusion Exploit',
                    'match_value' => $confusion_key . '[]',
                    'payload'     => "Parameter: {$confusion_key}[] URI: {$request_uri} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
            }
        }

        // Smart Rule #52: Forged Payment Gateway Webhook Signature Spoofing Trap
        // If an external client presents Stripe-Signature or PayPal transmission headers on a POST webhook endpoint
        // from an untrusted public IP that does NOT match official gateway CIDRs, block and ban the spoofing IP.
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
        $has_stripe_sig = !empty($_SERVER['HTTP_STRIPE_SIGNATURE']);
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
        $has_paypal_sig = !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG']);

        if (($has_stripe_sig || $has_paypal_sig) && !self::is_server_origin_or_loopback($client_ip) && !self::is_authenticated_administrator()) {
            $is_genuine_webhook_origin = false;
            if ($has_stripe_sig) {
                $stripe_cidrs = apply_filters('webcareproscan_stripe_webhook_cidrs', [
                    '3.18.12.63/32', '3.130.192.231/32', '13.235.14.237/32', '13.235.122.149/32',
                    '18.211.135.69/32', '35.154.171.200/32', '52.15.183.38/32', '54.187.174.169/32',
                    '54.187.205.235/32', '54.187.216.72/32', '54.241.31.99/32', '54.241.31.102/32',
                    '54.241.34.107/32',
                ]);
                foreach ((array) $stripe_cidrs as $stripe_cidr) {
                    if (self::ip_in_range($client_ip, $stripe_cidr)) {
                        $is_genuine_webhook_origin = true;
                        break;
                    }
                }
            }
            if (!$is_genuine_webhook_origin && $has_paypal_sig) {
                $paypal_cidrs = apply_filters('webcareproscan_paypal_webhook_cidrs', [
                    '173.0.80.0/20', '66.211.168.0/22', '64.4.240.0/21', '64.4.248.0/22',
                    '185.177.189.0/24', '3.253.0.0/16', '52.212.0.0/15',
                ]);
                foreach ((array) $paypal_cidrs as $paypal_cidr) {
                    if (self::ip_in_range($client_ip, $paypal_cidr)) {
                        $is_genuine_webhook_origin = true;
                        break;
                    }
                }
            }
            if (!$is_genuine_webhook_origin) {
                $sig_type = $has_stripe_sig ? 'Stripe-Signature' : 'PayPal-Transmission-Sig';
                $rule_triggered = [
                    'id'          => 'WAF-FORGED-WEBHOOK-TRAP',
                    'name'        => 'Forged Payment Gateway Webhook Trap (Rule #52)',
                    'category'    => 'Execution Armor',
                    'description' => sprintf(
                        /* translators: 1: Header name, 2: Spoofed IP address */
                        esc_html__('Forged %1$s webhook header presented by unauthorized non-gateway IP (%2$s).', 'webcare-pro-security'),
                        esc_html($sig_type),
                        esc_html($client_ip)
                    ),
                    'match_type'  => 'Webhook Origin Spoofing',
                    'match_value' => $client_ip,
                    'payload'     => "Header: {$sig_type} URI: {$request_uri} Spoofed IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
            }
        }

        // Block IPs who send POST requests with blank User-Agent and Referer
        if (!$skip_operational_heuristics && !empty($settings['waf_block_empty_post_ua_referer'])) {
            $is_post = (isset($_SERVER['REQUEST_METHOD']) && strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) === 'POST');
            if ($is_post) {
                // E-Commerce & Membership Safe Mode: Server-to-server payment gateway webhooks
                // (Stripe, PayPal IPN, Mollie, Square) frequently POST without browser Referer or standard UA.
                $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && self::is_commerce_or_membership_request($request_uri);
                $is_form_safe = !empty($settings['waf_forms_safe_mode']) && self::is_form_submission_request($request_uri);
                if (!$is_commerce_safe && !$is_form_safe) {
                    $has_ua  = !empty(trim(isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : ''));
                    $has_ref = !empty(trim(isset($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : ''));
                    if (!$has_ua && !$has_ref) {
                        $rule_triggered = [
                            'id'          => 'WAF-EMPTY-POST-UA-REFERER',
                            'name'        => 'Blank User-Agent & Referer POST Block',
                            'category'    => 'Bot Defense',
                            'description' => 'Automated POST payload rejected: Both User-Agent and Referer headers were missing or empty.',
                            'match_type'  => 'Missing Headers',
                            'match_value' => 'POST without UA or Referer',
                            'payload'     => "IP: {$client_ip} URI: {$request_uri}",
                        ];

                        self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                    }
                }
            }
        }

        // Rule 18 / Smart Rule #53: Sensitive Log, .env.* & Byte-Range Exfiltration Instant Ban
        if (!empty($settings['waf_block_sensitive_file_probes'])) {
            // Multi-pass URL decode to catch obfuscated probes (e.g. /%2eenv, /%252eenv, /%2egit)
            $decoded_check_path = $request_uri;
            for ($d_i = 0; $d_i < 3; $d_i++) {
                $prev_path = $decoded_check_path;
                $decoded_check_path = rawurldecode($decoded_check_path);
                if ($decoded_check_path === $prev_path) {
                    break;
                }
            }
            $clean_path = strtolower(wp_parse_url($decoded_check_path, PHP_URL_PATH) ?: $decoded_check_path);
            $clean_path = str_replace('\\', '/', $clean_path);
            $sensitive_patterns = [
                '/(?:\/|^)(?:\.env(?:\.[a-z0-9_-]+)?|\.git\/(?:config|HEAD|index|logs(?:\/.*)?)|wp-config\.(?:php\.)?(?:bak|old|save|swp|txt|orig|dist|~)|debug\.log|php_errorlog|error_log|wp-content\/uploads\/wc-logs(?:\/.*)?|auth\.json|docker-compose\.ya?ml|id_rsa(?:\.pub)?)(?:$|\?)/i',
                '/\.(env|git|svn|htaccess|user\.ini)(\/|$)/i',
                '/\.(sql|sql\.gz|tar\.gz|bak)$/i',
                '/(backup|dump|db_backup|wp-config\.php[~_\.bak])/i',
                '/(phpinfo\.php|info\.php)$/i',
            ];
            foreach ($sensitive_patterns as $spat) {
                if (preg_match($spat, $clean_path)) {
                    $range_hdr = isset($_SERVER['HTTP_RANGE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_RANGE'])) : '';
                    $rule_triggered = [
                        'id'          => 'WAF-SENSITIVE-FILE-PROBE',
                        'name'        => 'Sensitive Log & Configuration File Exfiltration Probe (Rule #53)',
                        'category'    => 'File Reconnaissance',
                        'description' => sprintf(
                            /* translators: %s: Probed sensitive file path */
                            esc_html__('Unauthorized probe targeting sensitive system configuration, log file, or database backup (%s).', 'webcare-pro-security'),
                            esc_html($clean_path)
                        ),
                        'match_type'  => 'Path Reconnaissance',
                        'match_value' => $clean_path,
                        'payload'     => "Path: {$clean_path}" . ($range_hdr !== '' ? " Range: {$range_hdr}" : '') . " IP: {$client_ip}",
                    ];

                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                    break;
                }
            }
        }

        // Rule 19: Direct Execution Deny for wp-content/uploads/ PHP Scripts
        if (!empty($settings['waf_block_uploads_php_exec'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (preg_match('/\/wp-content\/uploads\/.*\.php([0-9]|s|tml)?(\/|\?|$)/i', $clean_path) || preg_match('/\/wp-content\/uploads\/.*\.php([0-9]|s|tml)?/i', $request_uri)) {
                $rule_triggered = [
                    'id'          => 'WAF-UPLOADS-PHP-DENY',
                    'name'        => 'Uploads Directory PHP Execution Deny',
                    'category'    => 'Execution Armor',
                    'description' => 'Direct execution request to PHP script inside media uploads folder was blocked.',
                    'match_type'  => 'Script Execution Defense',
                    'match_value' => $clean_path,
                    'payload'     => "Upload Script: {$clean_path} IP: {$client_ip}",
                ];

                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
            }
        }

        // Rule 8: Multi-Dimensional $_FILES Payload Pre-Flight Inspection
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-flight upload inspection across all incoming POSTs
        if (!empty($_FILES) && !empty($settings['waf_block_malicious_uploads'])) {
            $files_overflow = false;
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-flight upload inspection across all incoming POSTs
            $all_uploaded_files = self::flatten_uploaded_files($_FILES, 4, 50, $files_overflow);
            if ($files_overflow) {
                $rule_triggered = [
                    'id'          => 'WAF-MULTIPART-FILE-COUNT-EXCEEDED',
                    'name'        => 'Multipart File Count / Nesting Ceiling Enforced',
                    'category'    => 'Protocol Defense',
                    'description' => 'Multipart request exceeds maximum allowed file count (50) or nesting depth (4); failing closed.',
                    'match_type'  => 'Upload Array Overflow',
                    'match_value' => 'count > 50 or depth > 4',
                    'payload'     => 'Multipart $_FILES overflow (>50 files or >4 nesting depth)',
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
            }
            foreach ($all_uploaded_files as $uploaded_item) {
                // Pre-flight inspection: pass log_and_ban = false to let handle_rule_violation() perform the single authoritative log, ban, and 403 block
                $upload_check = self::inspect_uploaded_file($uploaded_item, false);
                if (!empty($upload_check['error'])) {
                    $rule_triggered = [
                        'id'          => !empty($upload_check['rule_id']) ? $upload_check['rule_id'] : 'WAF-POLYGLOT-UPLOAD-TRAP',
                        'name'        => !empty($upload_check['rule_name']) ? $upload_check['rule_name'] : 'Malicious File Upload Shield (Rule 8)',
                        'category'    => !empty($upload_check['category']) ? $upload_check['category'] : 'Malicious File Upload',
                        'description' => (string) $upload_check['error'],
                        'match_type'  => 'Malicious File Upload',
                        'match_value' => (string) ($uploaded_item['name'] ?? ''),
                        'payload'     => 'Uploaded: ' . substr((string) ($uploaded_item['name'] ?? ''), 0, 100) . ' IP: ' . $client_ip,
                    ];
                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                    break;
                }
            }
        }

        // Specialized Rule: Disallow phpMyAdmin & Database Manager Plugin Installations (AJAX/REST/Query inspection)
        if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early WAF request inspection
            $req_slug = strtolower(isset($_POST['slug']) ? sanitize_text_field(wp_unslash($_POST['slug'])) : (isset($_GET['slug']) ? sanitize_text_field(wp_unslash($_GET['slug'])) : (isset($_POST['plugin']) ? sanitize_text_field(wp_unslash($_POST['plugin'])) : (isset($_GET['plugin']) ? sanitize_text_field(wp_unslash($_GET['plugin'])) : ''))));
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            if (empty($req_slug) && !empty($_POST['data']['slug'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                $req_slug = strtolower(sanitize_text_field(wp_unslash($_POST['data']['slug'])));
            }
            if (empty($req_slug) && preg_match('/(?:[?&]|%26)(?:slug|plugin)=([a-z0-9_-]+)/i', $request_uri, $slug_match)) {
                $req_slug = strtolower($slug_match[1]);
            }
            $pma_signatures = [
                'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                'ari-adminer', 'portable-phpmyadmin'
            ];
            $is_pma_install = false;
            foreach ($pma_signatures as $sig) {
                if (strpos($req_slug, $sig) !== false) {
                    $is_pma_install = true;
                    break;
                }
            }
            if ($is_pma_install) {
                $rule_triggered = [
                    'id'          => 'WAF-DISALLOW-PHPMYADMIN-PLUGIN',
                    'name'        => 'Prohibited Database Manager Plugin Installation',
                    'category'    => 'Security Policy Enforcement',
                    'description' => sprintf('Attempted installation of database manager / phpMyAdmin plugin ("%s") was blocked.', esc_html($req_slug)),
                    'match_type'  => 'Plugin Installation Policy',
                    'match_value' => $req_slug,
                    'payload'     => "Slug: {$req_slug} IP: {$client_ip}",
                ];

                $mode = $settings['waf_mode'] ?? 'enabled';
                if ($mode === 'learning') {
                    self::log_incident($rule_triggered, 'detected');
                } else {
                    self::log_incident($rule_triggered, 'blocked');
                    if (wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST)) {
                        status_header(403);
                        wp_send_json_error(['message' => 'Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is disallowed by WebCare Pro Security Firewall.']);
                    } else {
                        self::render_block_page($rule_triggered, $client_ip);
                    }
                    exit;
                }
            }
        }

        // Specialized Rule: Disallow File Manager Plugin Installations (AJAX/REST/Query inspection)
        if (!empty($settings['waf_disallow_filemanager_plugins'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early WAF request inspection
            $req_slug = strtolower(isset($_POST['slug']) ? sanitize_text_field(wp_unslash($_POST['slug'])) : (isset($_GET['slug']) ? sanitize_text_field(wp_unslash($_GET['slug'])) : (isset($_POST['plugin']) ? sanitize_text_field(wp_unslash($_POST['plugin'])) : (isset($_GET['plugin']) ? sanitize_text_field(wp_unslash($_GET['plugin'])) : ''))));
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            if (empty($req_slug) && !empty($_POST['data']['slug'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                $req_slug = strtolower(sanitize_text_field(wp_unslash($_POST['data']['slug'])));
            }
            if (empty($req_slug) && preg_match('/(?:[?&]|%26)(?:slug|plugin)=([a-z0-9_-]+)/i', $request_uri, $slug_match)) {
                $req_slug = strtolower($slug_match[1]);
            }
            $fm_signatures = [
                'file-manager', 'filemanager', 'fileorganizer', 'filester',
                'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
            ];
            $is_fm_install = false;
            foreach ($fm_signatures as $sig) {
                if (strpos($req_slug, $sig) !== false) {
                    $is_fm_install = true;
                    break;
                }
            }
            if ($is_fm_install) {
                $rule_triggered = [
                    'id'          => 'WAF-DISALLOW-FILEMANAGER-PLUGIN',
                    'name'        => 'Prohibited File Manager Plugin Installation',
                    'category'    => 'Security Policy Enforcement',
                    'description' => sprintf('Attempted installation of file manager plugin ("%s") was blocked.', esc_html($req_slug)),
                    'match_type'  => 'Plugin Installation Policy',
                    'match_value' => $req_slug,
                    'payload'     => "Slug: {$req_slug} IP: {$client_ip}",
                ];

                $mode = $settings['waf_mode'] ?? 'enabled';
                if ($mode === 'learning') {
                    self::log_incident($rule_triggered, 'detected');
                } else {
                    self::log_incident($rule_triggered, 'blocked');
                    if (wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST)) {
                        status_header(403);
                        wp_send_json_error(['message' => 'Security Policy Violation: Installation of File Manager plugins is disallowed by WebCare Pro Security Firewall.']);
                    } else {
                        self::render_block_page($rule_triggered, $client_ip);
                    }
                    exit;
                }
            }
        }

        // Rule 20: External wp-cron.php Abuse & Flooding Blocker
        if (!empty($settings['waf_block_external_cron'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (strpos($clean_path, 'wp-cron.php') !== false) {
                $is_loopback = self::is_server_origin_or_loopback($client_ip);
                $is_admin = self::is_authenticated_administrator();
                $is_whitelisted = self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '');

                if (!$is_loopback && !$is_admin && !$is_whitelisted) {
                    $rule_triggered = [
                        'id'          => 'WAF-EXTERNAL-CRON-BLOCK',
                        'name'        => 'External wp-cron.php Abuse Block',
                        'category'    => 'DoS & Resource Shield',
                        'description' => 'Direct external HTTP trigger to wp-cron.php rejected to prevent resource starvation.',
                        'match_type'  => 'Endpoint Protection',
                        'match_value' => 'wp-cron.php',
                        'payload'     => "External IP: {$client_ip} URI: {$request_uri}",
                    ];

                    self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                                    }
            }
        }

        // Rule 23: Lockdown install.php & upgrade.php on Already Installed Sites
        if (!empty($settings['waf_block_install_php'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (strpos($clean_path, 'wp-admin/install.php') !== false || strpos($clean_path, 'wp-admin/upgrade.php') !== false) {
                if (function_exists('is_blog_installed') && is_blog_installed()) {
                    $is_admin = self::is_authenticated_administrator();
                    if (!$is_admin) {
                        $rule_triggered = [
                            'id'          => 'WAF-INSTALL-LOCKDOWN',
                            'name'        => 'WordPress Installer Lockdown',
                            'category'    => 'Hardening Defense',
                            'description' => 'Public access to WordPress install.php/upgrade.php blocked on already established site.',
                            'match_type'  => 'Installer Probe',
                            'match_value' => $clean_path,
                            'payload'     => "Endpoint: {$clean_path} IP: {$client_ip}",
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
            }
        }

        // Check custom user IP blocklist
        if (!empty($settings['waf_blocked_ips'])) {
            $matching_entry = self::get_matching_blocked_entry($client_ip, $settings['waf_blocked_ips']);
            if ($matching_entry !== null) {
                // Immunity check: Ensure legitimate search engine crawlers (Googlebot, Bingbot)
                // that may have been erroneously or transitively added are automatically pardoned and unblocked.
                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
                $is_legit_crawler = false;
                if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
                    $is_legit_crawler = BotReconDefense::is_genuine_search_engine($client_ip, $ua);
                }

                if ($is_legit_crawler) {
                    // Auto-heal blocklist: Remove false-positive ban for verified search crawler
                    self::remove_blocked_ip($matching_entry);
                    self::remove_blocked_ip($client_ip);
                } else {
                    $block_meta = self::get_ip_block_meta($matching_entry) ?: self::get_ip_block_meta($client_ip);
                    $expires_at = !empty($block_meta['expires_at']) ? (int) $block_meta['expires_at'] : 0;

                    // Auto-heal expired temporary ban: unblock if duration has elapsed
                    if ($expires_at > 0 && time() >= $expires_at) {
                        self::remove_blocked_ip($matching_entry);
                        self::remove_blocked_ip($client_ip);
                        $matching_entry = null;
                    }

                    if ($matching_entry !== null) {
                        $ban_reason = !empty($block_meta['reason']) ? trim((string) $block_meta['reason']) : '';
                        $ban_source = !empty($block_meta['source']) ? trim((string) $block_meta['source']) : 'custom_blocklist';
                        $ban_rule   = !empty($block_meta['rule_name']) ? trim((string) $block_meta['rule_name']) : '';

                        // Shopper & E-Commerce Session Protection:
                        // If the visitor has an active e-commerce / membership cart session (e.g. WooCommerce cart cookies, EDD, SureCart)
                        // or is requesting checkout / payment gateway endpoints (wc-ajax, paypal, stripe),
                        // ensure legitimate paying customers are NOT permanently locked out by automated or non-admin bans.
                        $is_manual_admin_ban = ($ban_source === 'manual_admin') || (!empty($block_meta['admin_user']));
                        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

                        $description = 'Connection blocked by administrator-defined custom IP rule.';
                        if (!empty($ban_reason)) {
                            $description = sprintf('Connection blocked: %s', $ban_reason);
                        } elseif (!empty($ban_rule)) {
                            $description = sprintf('Connection blocked by automated rule: %s', $ban_rule);
                        }

                        $rule_triggered = [
                            'id'             => 'USER-CUSTOM-IP-BLOCK',
                            'name'           => 'Custom Administrator IP Blocklist',
                            'category'       => 'Custom IP Blocklist',
                            'description'    => $description,
                            'match_type'     => 'Custom Blocklist',
                            'match_value'    => $matching_entry,
                            'payload'        => $client_ip,
                            'ban_reason'     => $ban_reason,
                            'ban_source'     => $ban_source,
                            'matching_entry' => $matching_entry,
                            'expires_at'     => $expires_at,
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
            }
        }

        // Check active temporary 404 Scanner Lockout
        $lockout_transient = 'webcareproscan_404_lock_' . md5($client_ip);
        $lockout_data = get_transient($lockout_transient);
        if (!$skip_operational_heuristics && $lockout_data !== false) {
            $rule_triggered = [
                'id'          => 'RATE-LIMIT-404-LOCKOUT',
                'name'        => '404 Scanner Rate Limit Exceeded',
                'category'    => '404 Scanner Rate Limit',
                'description' => sprintf(
                    'Temporary lockout enforced: IP generated excessive 404 errors (%d probes in %ds). Locked out for %d minutes.',
                    (int) ($lockout_data['count'] ?? 10),
                    (int) ($lockout_data['window'] ?? 60),
                    (int) ($lockout_data['duration'] ?? 30)
                ),
                'match_type'  => '404 Threshold Exceeded',
                'match_value' => $client_ip,
                'payload'     => 'Recent 404 endpoint: ' . ($lockout_data['last_uri'] ?? 'N/A'),
            ];

            $mode = $settings['waf_mode'] ?? 'enabled';
            if ($mode === 'learning') {
                self::log_incident($rule_triggered, 'detected');
            } else {
                $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
                self::log_incident($rule_triggered, 'blocked', $incident_id);
                self::render_block_page($rule_triggered, $client_ip, $incident_id);
                exit;
            }
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

                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                            }
        }

        // Check Bot Recon Defense & AI Scraper Shield
        if (!$skip_operational_heuristics) {
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            $bot_rule = BotReconDefense::inspect_bot($client_ip, $user_agent, $settings);
            if ($bot_rule !== null) {
                self::handle_rule_violation($bot_rule, $settings, $client_ip, 403);
            }
        }

        // Check Active Virtual Patches (Tier 1: In-Memory WAF Lite Shield)
        if (class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
            $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
            $vpatch_rule = VirtualPatchManager::evaluate_request($client_ip, $request_uri);
            if ($vpatch_rule !== null) {
                if (class_exists('\\WebCareProScanner\\Firewall\\ThreatIntelNetwork')) {
                    ThreatIntelNetwork::record_consensus_beacon($client_ip, $vpatch_rule['name'] ?? 'Virtual Patch Violation', ['category' => 'Virtual Patch']);
                }
                self::handle_rule_violation($vpatch_rule, $settings, $client_ip, 403);
                            }
        }

        $env = self::detect_environment();
        $is_complementary = !empty($settings['waf_complementary_mode']) && $env['has_coexisting_waf'];

        // In complementary mode, Wordfence/Sucuri handles generic attacks;
        // WebCare WAF Lite focuses on WordPress virtual patching and deep injection protection
        $rule_triggered = self::evaluate_rules($settings, $is_complementary);

        if ($rule_triggered) {
            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
        } else {
            if ($custom_allow_matched) {
                return;
            }
            // Clean request passed all firewall filters: profile route parameters
            if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine')) {
                \WebCareProScanner\Firewall\LearningModeEngine::profile_benign_request();
            }
        }
    }

    /**
     * Evaluate protection rules across GET, POST, Cookies, User-Agent, Referer, and URI
     */
    private static function evaluate_rules(array $settings, bool $is_complementary): ?array {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw unstripped request URI for attack payloads
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';

        // Multi-pass URL decode for robust detection across multiple encoding layers
        $decoded_uri = $raw_uri;
        for ($d_i = 0; $d_i < 3; $d_i++) {
            $prev_u = $decoded_uri;
            $decoded_uri = rawurldecode($decoded_uri);
            if ($decoded_uri === $prev_u) {
                break;
            }
        }
        $uri = $decoded_uri;

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw query string, user-agent, and referer headers for injection payloads
        $raw_query = isset($_SERVER['QUERY_STRING']) ? (string) wp_unslash($_SERVER['QUERY_STRING']) : '';
        $query_string = rawurldecode($raw_query);
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? (string) wp_unslash($_SERVER['HTTP_USER_AGENT']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $referer = isset($_SERVER['HTTP_REFERER']) ? (string) wp_unslash($_SERVER['HTTP_REFERER']) : '';

        // Two-Tier Privilege Architecture (Finding 1):
        // Two-Tier Privilege Architecture:
        // Authenticated administrators and verified page-builder sessions are exempt ONLY from HTML/formatting
        // heuristic checks (such as raw <script>/<iframe> XSS rules and AI prompt-injection syntax when saving
        // post templates or WAF rules). Mandatory zero-tolerance exploit protections (SQLi, RCE, LFI, Object Injection)
        // execute unconditionally across 100% of requests without early return bypasses.
        $req_method_upper = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])))
            : 'GET';

        // Resolve exact REST route path separately from query string (Section 1 Guidelines)
        $parsed_path = (string) (wp_parse_url($raw_uri, PHP_URL_PATH) ?? '');
        $resolved_rest_route = self::resolve_normalized_rest_route($raw_uri);

        $exact_waf_config_write_routes = [
            '/webcare-pro-security/v1/settings',
            '/webcare-pro-security/v1/settings/import',
            '/webcare-pro-security/v1/modular-waf/rule/custom',
            '/webcare-pro-security/v1/modular-waf/rule/parse-wirefilter',
            '/webcare-pro-security/v1/modular-waf/rule/parse-ai',
            '/webcare-pro-security/v1/modular-waf/rule/ai-generate',
            '/webcare-pro-security/v1/modular-waf/rule/simulate',
            '/webcare-pro-security/v1/wizard/save',
        ];

        $has_valid_rest_nonce = false;
        $rest_nonce = !empty($_SERVER['HTTP_X_WP_NONCE'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE']))
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            : (isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '');
        if ($rest_nonce !== '' && function_exists('wp_verify_nonce')) {
            $has_valid_rest_nonce = (bool) wp_verify_nonce($rest_nonce, 'wp_rest');
        }

        $is_waf_config_write = (
            self::is_authenticated_administrator()
            && $has_valid_rest_nonce
            && in_array($req_method_upper, ['POST', 'PUT', 'PATCH'], true)
            && $resolved_rest_route !== ''
            && in_array($resolved_rest_route, $exact_waf_config_write_routes, true)
        );

        $is_core_post_editor_save = false;
        if (
            $req_method_upper === 'POST'
            && preg_match('#/wp-admin/(?:post|post-new)\.php$#i', $parsed_path)
            && self::is_authenticated_administrator()
        ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Passive verification of WordPress post-editor save nonce
            $post_id_hint = isset($_POST['post_ID']) ? absint($_POST['post_ID']) : 0;
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $post_nonce   = isset($_POST['_wpnonce']) ? sanitize_text_field(wp_unslash($_POST['_wpnonce'])) : '';
            if ($post_id_hint > 0 && $post_nonce !== '' && function_exists('wp_verify_nonce')) {
                $is_core_post_editor_save = (bool) wp_verify_nonce($post_nonce, 'update-post_' . $post_id_hint);
            }
        }

        $is_builder_saving_action  = self::is_authenticated_editor_or_builder();
        $is_privileged_html_author = ($is_core_post_editor_save || $is_builder_saving_action);

        // Combine request parameters for deep inspection (inspect raw inputs so WAF sees malicious script tags or encoding before sanitization)
        $params_to_check = [];

        if (!empty($query_string)) {
            $params_to_check[] = $query_string;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Early inspection of GET parameters before route execution
        if (!empty($_GET) && is_array($_GET)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $params_to_check[] = rawurldecode(http_build_query(wp_unslash($_GET), '', '&', PHP_QUERY_RFC3986));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early inspection of raw POST payload before WordPress nonce check
        if (!empty($_POST) && is_array($_POST)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $post_data = wp_unslash($_POST);
            $params_to_check[] = rawurldecode(http_build_query($post_data, '', '&', PHP_QUERY_RFC3986));
        }

        $cookie_str = '';
        // Inspect Cookies vector
        if (!empty($_COOKIE) && is_array($_COOKIE)) {
            $cookie_data = wp_unslash($_COOKIE);
            foreach ($cookie_data as $ck => $cv) {
                if (is_string($cv)) {
                    $cookie_str .= ' ' . $ck . '=' . $cv;
                }
            }
            if (!empty($cookie_str)) {
                $params_to_check[] = rawurldecode($cookie_str);
            }
        }

        // Inspect User-Agent and Referer headers
        if (!empty($user_agent)) {
            $params_to_check[] = $user_agent;
        }
        if (!empty($referer)) {
            $params_to_check[] = rawurldecode($referer);
        }

        $full_raw_body = '';
        $content_type  = isset($_SERVER['CONTENT_TYPE']) ? sanitize_text_field(wp_unslash($_SERVER['CONTENT_TYPE'])) : '';
        $is_multipart  = stripos($content_type, 'multipart/form-data') !== false;

        if (in_array($request_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            // Hard-bounded inspection ceiling: min 256 KB, default 4 MB, max 16 MB (Observation A)
            $max_inspect_bytes = isset($settings['waf_max_inspected_body_bytes'])
                ? min(16777216, max(262144, (int) $settings['waf_max_inspected_body_bytes']))
                : 4194304;
            $chunk_size        = 65536; // 64 KB chunks
            $overlap_size      = 8192;  // 8 KB rolling overlap

            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Raw header inspected for strict ctype_digit protocol validation
            $raw_cl_server = isset($_SERVER['CONTENT_LENGTH']) ? trim((string) wp_unslash($_SERVER['CONTENT_LENGTH'])) : '';
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Raw header inspected for strict ctype_digit protocol validation
            $raw_cl_http   = isset($_SERVER['HTTP_CONTENT_LENGTH']) ? trim((string) wp_unslash($_SERVER['HTTP_CONTENT_LENGTH'])) : '';

            if (
                ($raw_cl_server !== '' && $raw_cl_http !== '' && $raw_cl_server !== $raw_cl_http)
                || ($raw_cl_server !== '' && !ctype_digit($raw_cl_server))
                || ($raw_cl_http !== '' && !ctype_digit($raw_cl_http))
            ) {
                return [
                    'id'          => 'WAF-MALFORMED-CONTENT-LENGTH',
                    'name'        => 'Malformed or Conflicting Content-Length Guard',
                    'category'    => 'Protocol Defense',
                    'description' => 'Request contains a malformed, negative, or conflicting Content-Length header; failing closed.',
                    'payload'     => sprintf('CONTENT_LENGTH=%s HTTP_CONTENT_LENGTH=%s', substr($raw_cl_server, 0, 40), substr($raw_cl_http, 0, 40)),
                ];
            }

            $effective_cl_str        = $raw_cl_server !== '' ? $raw_cl_server : $raw_cl_http;
            $has_valid_cl            = ($effective_cl_str !== '' && ctype_digit($effective_cl_str));
            $expected_content_length = $has_valid_cl ? (int) $effective_cl_str : 0;

            // 1. Enforce explicit size ceiling across ALL body types (including multipart/form-data)
            if ($expected_content_length > $max_inspect_bytes) {
                return [
                    'id'          => 'WAF-BODY-INSPECTION-LIMIT-EXCEEDED',
                    'name'        => 'Request Body Inspection Ceiling Enforced',
                    'category'    => 'Protocol Defense',
                    'description' => 'Request body exceeds maximum safe deep-inspection size policy.',
                    'payload'     => sprintf('Content-Length: %d bytes (limit: %d)', $expected_content_length, $max_inspect_bytes),
                ];
            }

            // 2. Application-Layer Multipart Payload Consistency & Content-Length Under-Report Guard
            // Note: Validated server-provided CONTENT_LENGTH is the primary total wire-body limit (enforced above).
            // In standard PHP SAPIs, PHP parses multipart/form-data into $_POST and $_FILES prior to execution,
            // stripping transport-layer boundary delimiters, per-part headers, and framing overhead.
            // Therefore, $post_text_bytes + $total_files_bytes serves as an application-layer payload consistency check
            // and strict lower bound to verify that application data does not exceed the transport container size.
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-flight multipart resource ceiling validation
            if ($is_multipart) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                $has_php_multipart_data = (!empty($_POST) || !empty($_FILES));
                if ($has_php_multipart_data && !isset($GLOBALS['WEBCARE_TEST_RAW_INPUT']) && (!$has_valid_cl || $expected_content_length <= 0)) {
                    return [
                        'id'          => 'WAF-MULTIPART-MISSING-CONTENT-LENGTH',
                        'name'        => 'Multipart Content-Length Provenance Guard',
                        'category'    => 'Protocol Defense',
                        'description' => 'Multipart request is missing an authoritative positive Content-Length header; failing closed.',
                        'payload'     => 'Missing Content-Length on multipart request',
                    ];
                }

                // Account for multipart text fields in $_POST
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                $post_text_bytes = (!empty($_POST) && is_array($_POST))
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing
                    ? strlen(rawurldecode(http_build_query(wp_unslash($_POST), '', '&', PHP_QUERY_RFC3986)))
                    : 0;

                $total_files_bytes = 0;
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                if (!empty($_FILES) && is_array($_FILES)) {
                    $files_overflow = false;
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing
                    $flattened_files = self::flatten_uploaded_files($_FILES, 4, 50, $files_overflow);
                    if ($files_overflow) {
                        return [
                            'id'          => 'WAF-MULTIPART-FILE-COUNT-EXCEEDED',
                            'name'        => 'Multipart File Count / Nesting Ceiling Enforced',
                            'category'    => 'Protocol Defense',
                            'description' => 'Multipart request exceeds maximum allowed file count (50) or nesting depth (4); failing closed.',
                            'payload'     => 'Multipart $_FILES overflow (>50 files or >4 nesting depth)',
                        ];
                    }

                    foreach ($flattened_files as $uf) {
                        $u_err = isset($uf['error']) ? (int) $uf['error'] : 0;
                        if (in_array($u_err, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE, UPLOAD_ERR_PARTIAL, UPLOAD_ERR_NO_TMP_DIR, UPLOAD_ERR_CANT_WRITE], true)) {
                            return [
                                'id'          => 'WAF-MULTIPART-UPLOAD-INCOMPLETE-OR-OVERSIZED',
                                'name'        => 'Multipart Upload Size / Completeness Guard',
                                'category'    => 'Protocol Defense',
                                'description' => 'Multipart file upload exceeded size limits or was only partially received.',
                                'payload'     => sprintf('Upload error code: %d', $u_err),
                            ];
                        }
                        $declared_sz = isset($uf['size']) ? (int) $uf['size'] : -1;
                        $tmp_p       = isset($uf['tmp_name']) && is_string($uf['tmp_name']) ? $uf['tmp_name'] : '';
                        if ($tmp_p === '' || !file_exists($tmp_p) || !is_readable($tmp_p)) {
                            return [
                                'id'          => 'WAF-MULTIPART-UPLOAD-INCOMPLETE-OR-OVERSIZED',
                                'name'        => 'Multipart Temp File Verification Guard',
                                'category'    => 'Protocol Defense',
                                'description' => 'Uploaded temporary file is missing or unreadable during multipart accounting; failing closed.',
                                'payload'     => sprintf('Missing/unreadable tmp_name for %s', (string) ($uf['name'] ?? 'unknown')),
                            ];
                        }
                        clearstatcache(true, $tmp_p);
                        $disk_sz = @filesize($tmp_p);
                        if ($disk_sz === false || $disk_sz < 0 || ($declared_sz >= 0 && $declared_sz !== $disk_sz)) {
                            return [
                                'id'          => 'WAF-MULTIPART-SIZE-MISMATCH',
                                'name'        => 'Multipart Declared vs Actual File Size Mismatch',
                                'category'    => 'Protocol Defense',
                                'description' => 'Declared upload file size does not match actual temporary file size on disk; failing closed.',
                                'payload'     => sprintf('Declared: %d, Disk: %s', $declared_sz, is_int($disk_sz) ? (string) $disk_sz : 'false'),
                            ];
                        }
                        $total_files_bytes += $disk_sz;
                    }
                }

                $accounted_multipart_bytes = $post_text_bytes + $total_files_bytes;
                if ($accounted_multipart_bytes > $max_inspect_bytes) {
                    return [
                        'id'          => 'WAF-BODY-INSPECTION-LIMIT-EXCEEDED',
                        'name'        => 'Multipart Application Payload Ceiling Enforced',
                        'category'    => 'Protocol Defense',
                        'description' => 'Combined multipart application payload (text fields + files) exceeds maximum safe inspection size.',
                        'payload'     => sprintf('Multipart accounted application payload: %d bytes (limit: %d)', $accounted_multipart_bytes, $max_inspect_bytes),
                    ];
                }
                if ($has_valid_cl && $expected_content_length > 0 && $accounted_multipart_bytes > $expected_content_length) {
                    return [
                        'id'          => 'WAF-MULTIPART-SIZE-MISMATCH',
                        'name'        => 'Multipart Application Payload Exceeds Transport Length',
                        'category'    => 'Protocol Defense',
                        'description' => 'Application-layer multipart payload (POST fields + files) exceeds transport-layer Content-Length; failing closed.',
                        'payload'     => sprintf('Accounted payload: %d bytes > Content-Length: %d bytes', $accounted_multipart_bytes, $expected_content_length),
                    ];
                }
            }

            // 3. Explicit stream-state tracking (fail-closed on open/read failure or truncated body)
            $stream_opened        = false;
            $stream_read_failed   = false;
            $bytes_read           = 0;
            $exceeded             = false;
            $inspection_completed = false;
            $prev_tail            = '';

            // In standard PHP SAPIs, multipart/form-data bodies are consumed into $_POST and $_FILES before script start,
            // leaving php://input empty unless a raw test stream is injected.
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $php_consumed_multipart = $is_multipart && (!empty($_POST) || !empty($_FILES)) && !isset($GLOBALS['WEBCARE_TEST_RAW_INPUT']);

            if (!empty($GLOBALS['WEBCARE_TEST_FORCE_FOPEN_FAIL'])) {
                $stream_opened      = false;
                $stream_read_failed = true;
            } elseif (isset($GLOBALS['WEBCARE_TEST_RAW_INPUT']) && is_string($GLOBALS['WEBCARE_TEST_RAW_INPUT'])) {
                $stream_opened = true;
                $test_stream   = $GLOBALS['WEBCARE_TEST_RAW_INPUT'];
                $test_len      = strlen($test_stream);
                $offset        = 0;
                $fail_at       = isset($GLOBALS['WEBCARE_TEST_FORCE_FREAD_FAIL_AT']) && is_numeric($GLOBALS['WEBCARE_TEST_FORCE_FREAD_FAIL_AT'])
                    ? (int) $GLOBALS['WEBCARE_TEST_FORCE_FREAD_FAIL_AT']
                    : -1;

                while ($offset < $test_len) {
                    if ($fail_at >= 0 && $bytes_read >= $fail_at) {
                        $stream_read_failed = true;
                        break;
                    }
                    $chunk = substr($test_stream, $offset, $chunk_size);
                    $offset += strlen($chunk);
                    $bytes_read += strlen($chunk);
                    if ($bytes_read > $max_inspect_bytes) {
                        $exceeded = true;
                        break;
                    }
                    $full_raw_body .= $chunk;
                }
                if (!$stream_read_failed && !$exceeded) {
                    $inspection_completed = true;
                }
            } elseif (!$php_consumed_multipart) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming raw HTTP request body
                $in_fp = @fopen('php://input', 'rb');
                if (!is_resource($in_fp)) {
                    $stream_opened      = false;
                    $stream_read_failed = ($expected_content_length > 0);
                } else {
                    $fail_at = isset($GLOBALS['WEBCARE_TEST_FORCE_FREAD_FAIL_AT']) && is_numeric($GLOBALS['WEBCARE_TEST_FORCE_FREAD_FAIL_AT'])
                        ? (int) $GLOBALS['WEBCARE_TEST_FORCE_FREAD_FAIL_AT']
                        : -1;

                    while (!feof($in_fp)) {
                        if ($fail_at >= 0 && $bytes_read >= $fail_at) {
                            $stream_read_failed = true;
                            break;
                        }
                        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Chunked streaming of php://input
                        $raw_chunk = @fread($in_fp, $chunk_size);
                        if ($raw_chunk === false) {
                            $stream_read_failed = true;
                            break;
                        }
                        if ($raw_chunk === '') {
                            break;
                        }
                        $bytes_read += strlen($raw_chunk);
                        if ($bytes_read > $max_inspect_bytes) {
                            $exceeded = true;
                            break;
                        }
                        $full_raw_body .= $raw_chunk;
                    }
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                    @fclose($in_fp);
                    if (!$stream_read_failed && !$exceeded) {
                        $inspection_completed = true;
                    }
                }
            } else {
                $stream_opened        = true;
                $inspection_completed = true;
            }

            if ($exceeded) {
                return [
                    'id'          => 'WAF-BODY-INSPECTION-LIMIT-EXCEEDED',
                    'name'        => 'Request Body Inspection Ceiling Enforced',
                    'category'    => 'Protocol Defense',
                    'description' => 'Streamed request body exceeded maximum safe deep-inspection size.',
                    'payload'     => sprintf('Streamed > %d bytes', $max_inspect_bytes),
                ];
            }

            // Fail closed if stream failed to open/read, or if fewer bytes were read than declared Content-Length
            if (
                $stream_read_failed
                || !$inspection_completed
                || (!$php_consumed_multipart && $expected_content_length > 0 && $bytes_read < $expected_content_length)
            ) {
                return [
                    'id'          => 'WAF-STREAM-INSPECTION-INCOMPLETE',
                    'name'        => 'Request Body Stream Inspection Failure',
                    'category'    => 'Protocol Defense',
                    'description' => 'Request body stream could not be opened or read completely to declared Content-Length; failing closed.',
                    'payload'     => sprintf(
                        'Opened: %s, Failed: %s, Expected: %d, Read: %d',
                        $stream_opened ? 'yes' : 'no',
                        $stream_read_failed ? 'yes' : 'no',
                        $expected_content_length,
                        $bytes_read
                    ),
                ];
            }

            if ($full_raw_body !== '') {
                $norm_body = wp_unslash($full_raw_body);
                if (strpos($norm_body, '\\u') !== false) {
                    $norm_body = (string) preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function ($m) {
                        return html_entity_decode('&#x' . $m[1] . ';', ENT_QUOTES, 'UTF-8');
                    }, $norm_body);
                }
                $params_to_check[] = $norm_body;

                $batch_sub_payloads = self::extract_rest_batch_payloads($raw_uri, $full_raw_body);
                if (!empty($batch_sub_payloads)) {
                    $params_to_check = array_merge($params_to_check, $batch_sub_payloads);
                }
            }
        }

        // Mandatory inspection payload: 100% unredacted (never strips passwords or config expressions)
        $combined_payload = implode(' ', $params_to_check);

        // Multi-pass decode combined payload for deep matching (supports both RFC 3986 %20 and form-urlencoded +)
        $decoded_combined = str_replace('+', ' ', $combined_payload);
        for ($c_i = 0; $c_i < 2; $c_i++) {
            $prev_c = $decoded_combined;
            $decoded_combined = str_replace('+', ' ', rawurldecode($decoded_combined));
            if ($decoded_combined === $prev_c) {
                break;
            }
        }
        if (strpos($decoded_combined, '\\u') !== false) {
            $decoded_combined = (string) preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function ($m) {
                return html_entity_decode('&#x' . $m[1] . ';', ENT_QUOTES, 'UTF-8');
            }, $decoded_combined);
        }

        // Build Heuristic Payload from a single normalized source of truth (used ONLY by XSS and AI-Prompt checks):
        // 1. Parse $_POST, URL-encoded body, or JSON body.
        // 2. Mask recognized password fields (up to depth 4) in that parsed structure.
        // 3. Apply route-specific WAF expression masking when $is_waf_config_write is true.
        // 4. Never fall back to concatenating unmasked raw pwd=<script> chunks when the body is structured POST/JSON.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $heuristic_post = (!empty($_POST) && is_array($_POST)) ? self::mask_password_fields_for_heuristics(wp_unslash($_POST)) : [];
        if ($is_waf_config_write && !empty($heuristic_post)) {
            $heuristic_post = self::redact_waf_config_expressions($heuristic_post, $resolved_rest_route);
        }

        $heuristic_body_str = '';
        if ($full_raw_body !== '') {
            $raw_unslashed = wp_unslash($full_raw_body);
            if (strpos($raw_unslashed, '\\u') !== false) {
                $raw_unslashed = (string) preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function ($m) {
                    return html_entity_decode('&#x' . $m[1] . ';', ENT_QUOTES, 'UTF-8');
                }, $raw_unslashed);
            }
            $trimmed_body = ltrim($raw_unslashed);
            $is_json_body = ($trimmed_body !== '' && ($trimmed_body[0] === '{' || $trimmed_body[0] === '['))
                || stripos($content_type, 'application/json') !== false;
            $is_Urlencoded_body = stripos($content_type, 'application/x-www-form-urlencoded') !== false
                || (!$is_json_body && !$is_multipart && strpos($trimmed_body, '=') !== false);

            if ($is_json_body) {
                $parsed_json = json_decode($raw_unslashed, true);
                if (is_array($parsed_json)) {
                    $parsed_json = self::mask_password_fields_for_heuristics($parsed_json);
                    if ($is_waf_config_write) {
                        $parsed_json = self::redact_waf_config_expressions($parsed_json, $resolved_rest_route);
                    }
                    $heuristic_body_str = (string) wp_json_encode($parsed_json);
                } else {
                    $heuristic_body_str = $raw_unslashed;
                }
            } elseif ($is_Urlencoded_body) {
                $parsed_form = [];
                wp_parse_str($raw_unslashed, $parsed_form);
                if (is_array($parsed_form) && !empty($parsed_form)) {
                    $parsed_form = self::mask_password_fields_for_heuristics($parsed_form);
                    if ($is_waf_config_write) {
                        $parsed_form = self::redact_waf_config_expressions($parsed_form, $resolved_rest_route);
                    }
                    $heuristic_body_str = !empty($parsed_form)
                        ? rawurldecode(http_build_query($parsed_form, '', '&', PHP_QUERY_RFC3986))
                        : '';
                } else {
                    $heuristic_body_str = $raw_unslashed;
                }
            } else {
                $heuristic_body_str = $raw_unslashed;
            }
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $heuristic_get_str = (!empty($_GET) && is_array($_GET))
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            ? rawurldecode(http_build_query(wp_unslash($_GET), '', '&', PHP_QUERY_RFC3986))
            : '';
        $heuristic_post_str = !empty($heuristic_post)
            ? rawurldecode(http_build_query($heuristic_post, '', '&', PHP_QUERY_RFC3986))
            : '';

        $heuristic_combined = trim(implode(' ', array_filter([
            $query_string,
            $heuristic_get_str,
            $heuristic_post_str,
            $cookie_str !== '' ? rawurldecode($cookie_str) : '',
            $user_agent,
            $referer !== '' ? rawurldecode($referer) : '',
            $heuristic_body_str,
        ])));

        $heuristic_decoded = str_replace('+', ' ', $heuristic_combined);
        for ($h_i = 0; $h_i < 2; $h_i++) {
            $prev_h = $heuristic_decoded;
            $heuristic_decoded = str_replace('+', ' ', rawurldecode($heuristic_decoded));
            if ($heuristic_decoded === $prev_h) {
                break;
            }
        }
        if (strpos($heuristic_decoded, '\\u') !== false) {
            $heuristic_decoded = (string) preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function ($m) {
                return html_entity_decode('&#x' . $m[1] . ';', ENT_QUOTES, 'UTF-8');
            }, $heuristic_decoded);
        }

        // 1. Path Traversal & LFI/RFI
        if (!empty($settings['waf_block_traversal'])) {
            $traversal_patterns = [
                '/(?:\.\.\/|\.\.\\\\|\%2e\%2e|\%252e|\.\.%2f|\.\.%5c)/i',
                '/php:\/\/(?:filter|input|fd)/i',
                '/(?:\/|^)etc\/(?:passwd|shadow|hosts)/i',
                '/(?:proc\/self\/environ|boot\.ini|win\.ini)/i',
                '/(?:phar|zip|data|expect|glob):\/\/|wp-config(?:-sample)?\.php/i',
            ];
            foreach ($traversal_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload) || preg_match($pattern, $decoded_combined)) {
                    return [
                        'id'          => 'WAF-LFI-TRAVERSAL',
                        'name'        => 'Directory Traversal & LFI Shield',
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
                '/\bunion(?:\s+|\/\*.*?\*\/|\()+(?:all(?:\s+|\/\*.*?\*\/)+)?select\b/is',
                '/\bselect\b.+\bfrom\b.+\binformation_schema\b/is',
                '/\/\*![0-9]*\s*(?:select|union|insert|update|delete|drop|alter|sleep|benchmark)/is',
                '/\b(?:sleep|pg_sleep)\s*\(\s*[^)]+\)|\bbenchmark\s*\(\s*[0-9]+\s*,/is',
                '/\bwaitfor\s+delay\s+[\'"][0-9:]+[\'"]/is',
                '/\bconcat\s*\(\s*0x[0-9a-f]+/is',
                '/\b(?:gtid_subset|gtid_subtract|extractvalue|updatexml)\s*\(/is',
                '/\binto\s+(?:outfile|dumpfile)\b/is',
                '/\bload_file\s*\(/is',
            ];
            foreach ($sqli_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload) || preg_match($pattern, $decoded_combined)) {
                    return [
                        'id'          => 'WAF-SQLI-INJECTION',
                        'name'        => 'SQL Injection Signature Shield',
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
                '/<\?(?:php|=)/i',
                '/\b(?:eval|assert)\s*(?:\(\s*|\s*[\'"][^\'"]*[\'"]\s*\()(?:base64_decode|gzinflate|str_rot13|\$)/is',
                '/\b(?:passthru|shell_exec|proc_open|popen|pcntl_exec|posix_mkfifo|posix_setuid)\s*\(/is',
                '/(?:;\s*|\|\|\s*|\$\w+\s*=\s*|\.\s*|<\?(?:php)?\s+.*)system\s*\(\s*[\'"]?[\$\w]/is',
                '/\bbase64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{20,}/i',
            ];
            foreach ($php_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload) || preg_match($pattern, $decoded_combined)) {
                    return [
                        'id'          => 'WAF-RCE-PHP-INJECTION',
                        'name'        => 'PHP Code & Command Execution Shield',
                        'category'    => 'PHP Code Injection',
                        'description' => 'Direct PHP script tag or dangerous execution function payload detected.',
                        'payload'     => substr($combined_payload, 0, 200),
                    ];
                }
            }
        }

        // 3.5 PHP Object Injection (POP-chain gadgets) & Stream Wrapper Injection Shield
        if (!isset($settings['waf_block_object_injection']) || !empty($settings['waf_block_object_injection'])) {
            $stream_and_pop_regex = '/(?:(?:^|[\s"\';,\[\]{}=])(?:O|C):[+-]?\d+:"[^"]+":\d+:\{|(?:phar|expect|zip|glob|ogg|rar):\/\/|php:\/\/(?:filter|input|fd))/i';
            if (preg_match($stream_and_pop_regex, $uri) || preg_match($stream_and_pop_regex, $combined_payload) || preg_match($stream_and_pop_regex, $decoded_combined)) {
                return [
                    'id'          => 'WAF-OBJECT-STREAM-INJECTION',
                    'name'        => 'PHP Object Injection & Stream Wrapper Shield',
                    'category'    => 'Execution Armor',
                    'description' => 'Serialized PHP object payload or dangerous stream wrapper (phar://, php://filter) detected.',
                    'payload'     => substr($combined_payload, 0, 200),
                ];
            }
        }

        // 3.6 Smart Rule #50: Unauthenticated Shortcode & Callable Render Gadget Trap
        $is_logged_in_user = (function_exists('is_user_logged_in') && is_user_logged_in()) || self::is_authenticated_administrator() || self::is_authenticated_editor_or_builder();
        if (!$is_logged_in_user) {
            $gadget_regex = '/(?:\baction\s*=\s*(?:parse-media-shortcode|wp_ajax_parse_media_shortcode)\b|"(?:callback|render_callback|function|handler|callable)"\s*:\s*(?:"(?:system|exec|passthru|shell_exec|proc_open|popen|pcntl_exec|assert|eval|call_user_func|call_user_func_array|create_function|include|include_once|require|require_once|wp_insert_user|update_option)"|\[\s*"[^"]+"\s*,\s*"(?:exec|system|run|evaluate|update_option|delete_user|set_role)"\s*\])|\[(?:php|insert_php|exec|raw_php|eval)\b[^\]]*\])/i';
            if (preg_match($gadget_regex, $uri) || preg_match($gadget_regex, $combined_payload) || preg_match($gadget_regex, $decoded_combined)) {
                return [
                    'id'          => 'WAF-AJAX-SHORTCODE-GADGET',
                    'name'        => 'Unauthenticated Shortcode & Callable Gadget Trap (Rule #50)',
                    'category'    => 'PHP Code Injection',
                    'description' => esc_html__('Unauthenticated shortcode execution or PHP callable gadget chain intercepted.', 'webcare-pro-security'),
                    'payload'     => substr($decoded_combined, 0, 200),
                ];
            }
        }

        // 4. Cross-Site Scripting (XSS)
        // Exempt verified administrators and page builders authoring rich HTML/SVG post layouts from XSS false positives
        if (!$is_privileged_html_author && !empty($settings['waf_block_xss'])) {
            $xss_payload_stripped = preg_replace('/[\x00-\x20]+/', '', $heuristic_combined);
            if (preg_match('/(?:javascript|vbscript|data\s*:\s*text\/html)\s*:/is', $xss_payload_stripped)) {
                return [
                    'id'          => 'WAF-XSS-PAYLOAD',
                    'name'        => 'Cross-Site Scripting (XSS) Shield',
                    'category'    => 'Cross-Site Scripting (XSS)',
                    'description' => 'Obfuscated javascript: or data:text/html URI payload detected.',
                    'payload'     => substr($heuristic_combined, 0, 200),
                ];
            }

            $xss_patterns = [
                '/<script\b[^>]*>/is',
                '/(?:javascript|vbscript|data\s*:\s*text\/html)\s*:/is',
                '/<iframe\b[^>]*>/is',
                '/<svg\b[^>]*\bon\w+\s*=/is',
                '/(?:<[^>]+?\s|\b)on(?:error|load|mouseover|mouseenter|mouseleave|click|dblclick|auxclick|contextmenu|focus|blur|pointerenter|pointerover|pointerdown|toggle|beforetoggle|animationstart|animationend|animationiteration|transitionend|begin|pageshow|pagehide|input|invalid|submit|reset|wheel|drag|drop|copy|cut|paste)\s*=\s*(?:[\'"`][^\'"`]*?(?:\(|javascript:|alert|confirm|prompt|eval|fetch|document\.|window\.|location)|[^\s>&\'"`]+?\()/is',
            ];
            foreach ($xss_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $heuristic_combined) || preg_match($pattern, $heuristic_decoded)) {
                    return [
                        'id'          => 'WAF-XSS-PAYLOAD',
                        'name'        => 'Cross-Site Scripting (XSS) Shield',
                        'category'    => 'Cross-Site Scripting (XSS)',
                        'description' => 'Hostile JavaScript injection or payload tag detected.',
                        'payload'     => substr($heuristic_combined, 0, 200),
                    ];
                }
            }
        }

        // 5. Null Byte Poison Attacks (%00 / \0)
        if (!empty($settings['waf_block_null_byte_attacks'])) {
            if (strpos($uri, '%00') !== false || strpos($combined_payload, "\0") !== false || strpos($combined_payload, '%00') !== false) {
                return [
                    'id'          => 'WAF-NULL-BYTE-POISON',
                    'name'        => 'Null Byte String Termination Shield',
                    'category'    => 'Null Byte Poison',
                    'description' => 'Null byte string termination attack (%00) detected in URI or request payload.',
                    'payload'     => substr($combined_payload, 0, 200),
                ];
            }
        }

        // 6. AI Prompt Injection & Agent Poisoning Shield (Rule #35)
        // Exempt verified administrators and page builders writing content or editing posts from prompt-injection false positives
        if (!$is_privileged_html_author && !empty($settings['waf_block_ai_prompt_injection'])) {
            $prompt_patterns = [
                '/\b(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)\b/i',
                '/\b(system\s*prompt\s*:|\[\s*system\s*\]|\bDAN\s+mode\b|developer\s+mode\s+active)\b/i',
                '/\b(you\s+are\s+now\s+(an\s+unfiltered|unrestricted|in\s+developer|in\s+jailbreak))\b/i',
                '/\b(bypass\s+(safety|content)\s+guidelines|reveal\s+(your|the)\s+(system\s+)?instructions)\b/i',
                '/(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\])/i',
                '/\b(dump|output|exfiltrate)\s+(the\s+)?(contents\s+of\s+)?(wp-config\.php|passwd|database\s+credentials)\b/i',
            ];
            foreach ($prompt_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $heuristic_combined) || preg_match($pattern, $heuristic_decoded)) {
                    return [
                        'id'          => 'WAF-AI-PROMPT-INJECTION',
                        'name'        => 'AI Prompt Injection & Agent Poisoning Shield (Rule #35)',
                        'category'    => 'AI & Agent Defense',
                        'description' => 'Hostile LLM prompt-injection / tool-poisoning syntax detected in request payload.',
                        'payload'     => substr($heuristic_combined, 0, 200),
                    ];
                }
            }
        }

        // 6.5 Smart Rule #51: WordPress 7.0+ Interactivity API & Block Bindings Poisoning Shield
        $wp7_block_poison_regex = '/(?:data-wp-(?:init|watch|run|bind|text|class|style|on(?:--[a-z0-9_-]+)?)\s*=\s*[\'"][^\'"]*(?:__proto__|constructor|prototype|eval\s*\(|Function\s*\(|javascript:|data:text\/html)|"bindings"\s*:\s*\{[^}]*"(?:key|meta_key|field)"\s*:\s*"(?:_application_passwords|wp_capabilities|wp_user_level|session_tokens|_wc_stripe|_paypal|_user_activation_key))/i';
        if (preg_match($wp7_block_poison_regex, $combined_payload) || preg_match($wp7_block_poison_regex, $decoded_combined)) {
            return [
                'id'          => 'WAF-WP7-INTERACTIVITY-POISON',
                'name'        => 'WP 7.0+ Interactivity API & Block Bindings Shield (Rule #51)',
                'category'    => 'Execution Armor',
                'description' => esc_html__('Malicious WordPress Interactivity API prototype pollution or protected Block Binding meta exfiltration attempt detected.', 'webcare-pro-security'),
                'payload'     => substr($decoded_combined, 0, 200),
            ];
        }

        // Rule 21: Open Redirect Phishing Guard
        if (!empty($settings['waf_block_open_redirects'])) {
            $redirect_keys = ['redirect_to', 'redirect', 'url', 'return_to', 'next', 'target'];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Inspection of redirect params
            $all_params = array_merge($_GET, $_POST);

            // Collect all authorized site host variations (home_url, site_url, HTTP_HOST, SERVER_NAME, www vs non-www)
            $allowed_hosts = ['localhost', '127.0.0.1', '::1'];
            $base_hosts = [];

            $h_url = wp_parse_url(home_url(), PHP_URL_HOST);
            if ($h_url) {
                $base_hosts[] = strtolower($h_url);
            }
            $s_url = wp_parse_url(site_url(), PHP_URL_HOST);
            if ($s_url) {
                $base_hosts[] = strtolower($s_url);
            }
            if (!empty($_SERVER['HTTP_HOST'])) {
                $raw_http_host = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST']));
                $base_hosts[] = strtolower(trim(preg_replace('/:\d+$/', '', $raw_http_host)));
            }
            if (!empty($_SERVER['SERVER_NAME'])) {
                $raw_server_name = sanitize_text_field(wp_unslash($_SERVER['SERVER_NAME']));
                $base_hosts[] = strtolower(trim(preg_replace('/:\d+$/', '', $raw_server_name)));
            }

            foreach ($base_hosts as $bh) {
                if (!empty($bh)) {
                    $allowed_hosts[] = $bh;
                    if (str_starts_with($bh, 'www.')) {
                        $allowed_hosts[] = substr($bh, 4);
                    } else {
                        $allowed_hosts[] = 'www.' . $bh;
                    }
                }
            }

            // Custom administrator allowed host aliases
            if (!empty($settings['waf_allowed_host_aliases'])) {
                $aliases = preg_split('/[\r\n,]+/', (string) $settings['waf_allowed_host_aliases']);
                foreach ($aliases as $al) {
                    $al_clean = strtolower(trim(preg_replace('/:\d+$/', '', $al)));
                    if (!empty($al_clean)) {
                        $allowed_hosts[] = $al_clean;
                    }
                }
            }
            $allowed_hosts = array_unique(array_filter($allowed_hosts));

            foreach ($redirect_keys as $key) {
                if (!empty($all_params[$key]) && is_string($all_params[$key])) {
                    $val = trim(urldecode($all_params[$key]));
                    if (preg_match('#^https?://#i', $val) || strpos($val, '//') === 0) {
                        $parsed_host = strtolower(wp_parse_url($val, PHP_URL_HOST) ?: '');

                        // If host is specified and is not in our authorized site hosts
                        if (!empty($parsed_host) && !in_array($parsed_host, $allowed_hosts, true)) {
                            // E-Commerce, Membership & Transactional Mailer Intelligence:
                            // Exempt legitimate payment processor redirects and social/mailer OAuth return destinations
                            // (PayPal, Stripe, Mollie, Klarna, Square, Google, Microsoft 365, Zoho, Apple).
                            $trusted_redirect_domains = [
                                'paypal.com',
                                'stripe.com',
                                'mollie.com',
                                'klarna.com',
                                'squareup.com',
                                'razorpay.com',
                                'paystack.co',
                                '2checkout.com',
                                'authorize.net',
                                'accounts.google.com',
                                'login.microsoftonline.com',
                                'accounts.zoho.com',
                                'accounts.zoho.eu',
                                'login.zoho.com',
                                'facebook.com',
                                'appleid.apple.com',
                            ];
                            $is_trusted_redirect = false;
                            foreach ($trusted_redirect_domains as $td) {
                                if ($parsed_host === $td || (strlen($parsed_host) > strlen($td) && substr($parsed_host, -(strlen($td) + 1)) === '.' . $td)) {
                                    $is_trusted_redirect = true;
                                    break;
                                }
                            }

                            if (!$is_trusted_redirect) {
                                return [
                                    'id'          => 'WAF-OPEN-REDIRECT',
                                    'name'        => 'Open Redirect Phishing Guard',
                                    'category'    => 'Protocol Defense',
                                    'description' => sprintf('Unsanitized open redirect targeting unauthorized external destination: %s', substr($parsed_host, 0, 60)),
                                    'payload'     => substr($val, 0, 200),
                                ];
                            }
                        }
                    }
                }
            }
        }

        // Rule 22: Cloud Metadata & SSRF Shield (AWS/GCP/Azure IMDS)
        if (!empty($settings['waf_block_ssrf_metadata'])) {
            $ssrf_patterns = [
                '/169\.254\.169\.254/i',
                '/metadata\.google\.internal/i',
                '/metadata\.internal/i',
                '/instance-identity\/document/i',
            ];
            foreach ($ssrf_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload)) {
                    return [
                        'id'          => 'WAF-SSRF-METADATA',
                        'name'        => 'Cloud Metadata & SSRF Shield',
                        'category'    => 'SSRF Defense',
                        'description' => 'Cloud instance metadata service (IMDS) SSRF exploitation probe intercepted.',
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
            $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            if (strpos($uri, 'xmlrpc.php') !== false) {
                $client_ip = self::get_client_ip();
                // Smart Pass: Exclude verified Automattic Jetpack sync requests
                if (self::is_verified_jetpack_request($client_ip, $uri, $settings)) {
                    return;
                }

                self::log_incident([
                    'category'    => 'XML-RPC Disabled',
                    'description' => 'XML-RPC request blocked by administrator policy.',
                    'payload'     => 'xmlrpc.php invocation',
                ], 'blocked');

                status_header(403);
                header('Content-Type: text/plain; charset=utf-8');
                echo 'XML-RPC services are disabled on this WordPress installation by WebCare Pro Security.';
                exit;
            }
        }
    }

    /**
     * Smart 404 Scanner Rate Limiter & Reconnaissance Shield
     *
     * Hooks into template_redirect when WordPress evaluates is_404().
     * Accurately distinguishes between:
     * 1. Verified genuine search crawlers (Google, Bing, DuckDuckGo) -> ALWAYS exempt via reverse DNS.
     * 2. Static media/asset 404s (.css, .js, images, fonts) -> Ignored to prevent false-positives for humans.
     * 3. High-risk reconnaissance probes (.env, .git, .bak, shell.php, etc.) -> Rapid detection.
     * 4. Automated directory fuzzing / scanners exceeding threshold (e.g. 10 hits in 60s) -> Enforces temporary lockout.
     */
    public static function track_404_request() {
        if (!function_exists('is_404') || !is_404()) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_block_404_scanners'])) {
            return;
        }

        $client_ip = self::get_client_ip();

        // 1. Skip if client IP is whitelisted by administrator (with telemetry)
        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
            if ($log_telemetry && self::is_high_risk_recon_probe(isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/')) {
                self::log_incident([
                    'id'          => 'RATE-LIMIT-404-PROBE',
                    'name'        => '404 Vulnerability Probe (Bypassed)',
                    'category'    => '404 Scanner Rate Limit',
                    'description' => '404 probe detected on sensitive path [Bypassed via IP Whitelist]',
                    'payload'     => 'Probe: ' . substr(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/')), 0, 200),
                ], 'bypassed');
            }
            return;
        }

        $raw_uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // 2. Ignore missing static assets (images, fonts, stylesheets, scripts, favicons)
        if (self::is_static_asset($raw_uri)) {
            return;
        }

        // 2b. Standard RFC 8615 well-known endpoints are legitimate browser, SSL, and OS integration probes
        // (e.g. /.well-known/related-website-set.json, /.well-known/assetlinks.json, /.well-known/apple-app-site-association, /.well-known/acme-challenge)
        $parsed_path = wp_parse_url($raw_uri, PHP_URL_PATH) ?: $raw_uri;
        if (str_starts_with($parsed_path, '/.well-known/') && !self::is_high_risk_recon_probe($raw_uri)) {
            return;
        }

        // 3. Genuine Search Engine, Uptime Monitor, & Synthetic Performance Audit Exemption:
        // If the request belongs to an authenticated search crawler (Googlebot, Bingbot, etc.),
        // a verified uptime monitor (UptimeRobot, Pingdom, StatusCake),
        // or a read-only synthetic performance audit runner (WebPageTest/PTST, Chrome-Lighthouse, PageSpeed, GTmetrix, SpeedCurve),
        // DO NOT penalize or rate-limit.
        if (BotReconDefense::is_genuine_search_engine($client_ip, $user_agent)) {
            return;
        }
        if (BotReconDefense::is_genuine_uptime_monitor($client_ip, $user_agent, $settings)) {
            return;
        }
        if (BotReconDefense::is_synthetic_performance_tool($user_agent)) {
            return;
        }

        // 4. Redirection & Header Exemption:
        // If another plugin (e.g. Redirection, Rank Math, Yoast, Safe Redirect Manager) or WordPress core
        // has already emitted or staged a redirection (HTTP 301, 302, 307, 308 or Location header),
        // or if the URL is actively being redirected, do NOT penalize as a 404 scan probe.
        if (self::is_redirect_in_progress()) {
            return;
        }

        // 5. E-Commerce & Membership Shopper Immunity:
        // Genuine customers browsing a store with active cart cookies or accessing commerce endpoints
        // must not be locked out by harmless missing store assets (e.g., broken product images or expired variation links).
        // IMMUTABLE SECURITY RULE: High-risk reconnaissance probes (.env, .git, .sql, .bak, core PHP files)
        // are NEVER exempted from 404 tracking, regardless of cookie presence.
        if (!empty($settings['waf_ecommerce_safe_mode'])) {
            if (self::has_active_shopper_session() || self::is_commerce_or_membership_request($raw_uri)) {
                if (!self::is_high_risk_recon_probe($raw_uri)) {
                    $parsed_path = wp_parse_url($raw_uri, PHP_URL_PATH) ?: $raw_uri;
                    $ext = strtolower(pathinfo($parsed_path, PATHINFO_EXTENSION));
                    $static_asset_exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'css', 'js', 'woff', 'woff2', 'ttf', 'eot', 'avif'];
                    if (in_array($ext, $static_asset_exts, true) || strpos($raw_uri, '/wp-content/uploads/') !== false) {
                        return; // Auto-pass harmless missing media/asset 404s during customer browsing
                    }
                }
            }
        }

        $threshold        = (int) ($settings['waf_404_threshold'] ?? 10);
        $window_seconds   = (int) ($settings['waf_404_window_seconds'] ?? 60);
        $lockout_duration = (int) ($settings['waf_404_lockout_duration'] ?? 30);

        // Check if URI is a known high-risk vulnerability reconnaissance probe
        $is_high_risk = self::is_high_risk_recon_probe($raw_uri);

        // Transient tracking counter per IP
        $counter_transient = 'webcareproscan_404_cnt_' . md5($client_ip);
        $current_count     = (int) get_transient($counter_transient);

        // High risk probes advance counter by 3 to accelerate lockout
        $increment = $is_high_risk ? 3 : 1;
        $new_count = $current_count + $increment;

        // Record differential threat score event (CAF Phase 3: +4 for 404 probe, +25 if sensitive path)
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            $event_category = $is_high_risk ? 'honeypot' : 'probe_404';
            \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, $event_category);
        }

        if ($new_count >= $threshold) {
            // Threshold exceeded: Enforce temporary lockout
            $lockout_transient = 'webcareproscan_404_lock_' . md5($client_ip);
            set_transient($lockout_transient, [
                'ip'       => $client_ip,
                'count'    => $new_count,
                'window'   => $window_seconds,
                'duration' => $lockout_duration,
                'last_uri' => substr($raw_uri, 0, 200),
            ], $lockout_duration * MINUTE_IN_SECONDS);

            delete_transient($counter_transient);

            $rule_triggered = [
                'id'          => 'RATE-LIMIT-404-LOCKOUT',
                'name'        => '404 Scanner Rate Limit Enforced',
                'category'    => '404 Scanner Rate Limit',
                'description' => sprintf(
                    'IP triggered %d non-existent 404 endpoints within %d seconds. Enforced %d-minute automated lockout.',
                    $new_count,
                    $window_seconds,
                    $lockout_duration
                ),
                'match_type'  => '404 Flood Detection',
                'match_value' => $client_ip,
                'payload'     => 'Probe: ' . substr($raw_uri, 0, 200),
            ];

            $mode = $settings['waf_mode'] ?? 'enabled';
            if ($mode === 'learning') {
                self::log_incident($rule_triggered, 'detected');
            } else {
                $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
                self::log_incident($rule_triggered, 'blocked', $incident_id);
                self::render_block_page($rule_triggered, $client_ip, $incident_id);
                exit;
            }
        } else {
            // Update transient counter for rolling window
            set_transient($counter_transient, $new_count, $window_seconds);
        }
    }

    /**
     * Check if requested URI path is a static media/asset file.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_static_asset(string $uri): bool {
        $path = wp_parse_url($uri, PHP_URL_PATH);
        if (!$path) {
            return false;
        }

        // Common static extensions that shouldn't cause user lockouts
        $static_extensions = '/\.(jpg|jpeg|png|gif|webp|svg|ico|css|js|map|woff|woff2|ttf|eot|otf|mp4|webm|mp3|ogg|wav|pdf)$/i';
        if (preg_match($static_extensions, $path)) {
            return true;
        }

        // Common harmless web assets
        if ($path === '/favicon.ico' || $path === '/robots.txt' || $path === '/sitemap.xml') {
            return true;
        }

        return false;
    }

    /**
     * Check if a redirection has been emitted or staged by WordPress or a redirection plugin.
     * Prevents false-positive 404 lockout on URLs handled by redirection rules.
     *
     * @return bool
     */
    public static function is_redirect_in_progress(): bool {
        // 1. Check if PHP HTTP response code is already set to a 3xx redirect
        $http_code = http_response_code();
        if ($http_code && in_array($http_code, [301, 302, 303, 307, 308], true)) {
            return true;
        }

        // 2. Check if a 'Location' header has already been queued or sent
        $headers = headers_list();
        foreach ($headers as $header) {
            if (stripos($header, 'Location:') === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect high-risk reconnaissance probes seeking sensitive files or backdoors.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_high_risk_recon_probe(string $uri): bool {
        $path = strtolower(wp_parse_url($uri, PHP_URL_PATH) ?: $uri);

        $high_risk_patterns = [
            '/\.env($|\.)/i',
            '/\.git(\/|$)/i',
            '/\.svn(\/|$)/i',
            '/\.htaccess(\.bak|\.old|\.save)?$/i',
            '/wp-config\.php(\.bak|\.old|\.save|\.swp|\.dist|\.inc)?$/i',
            '/(phpinfo|phpmyadmin|pma|adminer|wso|c99|r57|alfa|shell)\.php$/i',
            '/\/(backup|dump|db|database|sql)\.(sql|tar|gz|zip|bz2)$/i',
            '/\/eval-stdin\.php$/i',
            '/\/vendor\/phpunit\//i',
            '/\/solr\/admin\//i',
        ];

        foreach ($high_risk_patterns as $pattern) {
            if (preg_match($pattern, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if WooCommerce, Easy Digital Downloads, or recognized Membership suites are present.
     *
     * @return bool
     */
    public static function is_commerce_active(): bool {
        // 1. Configured Archetype Profile from Setup Wizard or Site Advisor
        $archetype = get_option('webcareproscan_site_archetype', '');
        if (in_array($archetype, ['ecommerce', 'membership'], true)) {
            return true;
        }

        // 2. Explicit E-Commerce Safe Mode Setting
        $settings = get_option('webcareproscan_settings', []);
        if (!empty($settings['waf_ecommerce_safe_mode'])) {
            return true;
        }

        // 3. E-Commerce Suites
        $has_ecommerce = class_exists('WooCommerce')
            || class_exists('Easy_Digital_Downloads')
            || class_exists('\\SureCart\\SureCart') || defined('SURECART_PLUGIN_FILE') // SureCart
            || class_exists('Ecwid_Product') || defined('ECWID_PLUGIN_DIR') // Ecwid
            || class_exists('wp_easycart') || defined('EC_CURRENT_VERSION') // WP EasyCart
            || class_exists('\\FluentCart\\App\\App') || defined('FLUENTCART_VERSION') // FluentCart
            || class_exists('\\BigCommerce\\Container') || defined('BIGCOMMERCE_VERSION') // BigCommerce
            || class_exists('SimplePay') || defined('SIMPLE_PAY_VERSION') // WP Simple Pay
            || class_exists('Cart66') || defined('CART66_VERSION') // Cart66
            || class_exists('WP_DLM') // Download Monitor
            || class_exists('Give') || defined('GIVE_VERSION'); // GiveWP

        // Membership & Subscription Suites
        $has_membership = class_exists('MeprAppCtrl') // MemberPress
            || defined('PMPRO_VERSION') // Paid Memberships Pro
            || class_exists('Restrict_Content_Pro') || defined('RCP_PLUGIN_VERSION') // Restrict Content Pro / Kadence Memberships
            || class_exists('\\SureMembers\\SureMembers') || defined('SUREMEMBERS_VERSION') // SureMembers
            || class_exists('ARM_main') || defined('MEMBERSHIP_VERSION') // ARMember
            || class_exists('MemberMouse') || defined('MM_VERSION') // MemberMouse
            || class_exists('WishListMember') || defined('WLM_VERSION') // WishList Member
            || class_exists('SimpleWpMembership') || defined('SWPM_VERSION') // Simple Membership
            || class_exists('WC_Memberships') // WooCommerce Memberships
            || class_exists('Pms_Member') || defined('PMS_VERSION') // Paid Member Subscriptions
            || class_exists('c_ws_plugin__s2member_menu_pages') // s2Member
            || class_exists('IhsuMpMain') || defined('UHP_VERSION') // Ultimate Membership Pro
            || class_exists('LearnDash_Settings_Section') // LearnDash
            || class_exists('LifterLMS'); // LifterLMS

        // User Profile & Registration Management Suites
        $has_profiles = class_exists('UM') || defined('um_plugin') // Ultimate Member
            || class_exists('Profile_Builder') || defined('WPPB_PLUGIN_DIR') // User Profile Builder (Cozmoslabs)
            || class_exists('WP_User_Manager') || defined('WPUM_VERSION') // WP User Manager
            || class_exists('ProfilePress') || defined('PPRESS_VERSION_NUMBER') // ProfilePress
            || class_exists('User_Registration') || defined('UR_VERSION') // User Registration (WPEverest)
            || class_exists('Registration_Magic') || defined('RM_PLUGIN_VERSION') // RegistrationMagic
            || class_exists('Profile_Grid') || defined('PG_PLUGIN_VERSION') // ProfileGrid
            || class_exists('Theme_My_Login') || defined('TML_VERSION') // ThemeMyLogin
            || class_exists('FrmRegAppController') // Formidable Forms User Registration
            || class_exists('wpmembers') // WP-Members
            || class_exists('BuddyBoss_Platform') || defined('BP_PLATFORM_VERSION') // BuddyBoss Platform
            || class_exists('Youzify') || defined('YOUZIFY_VERSION'); // Youzify

        $has_archetype_commerce = in_array(get_option('webcareproscan_site_archetype'), ['ecommerce', 'membership'], true);

        return $has_ecommerce || $has_membership || $has_profiles || $has_archetype_commerce || defined('WEBCARE_COMMERCE_OVERRIDE');
    }

    /**
     * Check if current request has an active shopper or customer session.
     * Genuine shoppers browsing a store have cart cookies or active customer/membership sessions.
     *
     * @return bool
     */
    public static function has_active_shopper_session(): bool {
        // CAF 2.0: Instant O(1) short-circuit if site runs zero commerce or membership plugins
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            if (!\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('commerce') &&
                !\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('lms_membership')) {
                return false;
            }
        }

        if (empty($_COOKIE) || !is_array($_COOKIE)) {
            return false;
        }

        $has_woo = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : true;

        foreach ($_COOKIE as $cookie_name => $cookie_val) {
            if (is_string($cookie_name)) {
                // Cryptographically validated WooCommerce session cookie: customer_id||session_expiration||session_expiring||cookie_hash
                if ($has_woo && strpos($cookie_name, 'wp_woocommerce_session_') !== false && is_string($cookie_val)) {
                    $parts = explode('||', $cookie_val);
                    if (count($parts) >= 3 && (int) ($parts[1] ?? 0) > time()) {
                        return true;
                    }
                }
                if (is_string($cookie_val) && strlen($cookie_val) > 0) {
                    if (strpos($cookie_name, 'edd_items_in_cart') !== false || strpos($cookie_name, 'give_items_in_cart') !== false) {
                        if (is_numeric($cookie_val) && (int) $cookie_val > 0) {
                            return true;
                        }
                    } elseif (
                        strpos($cookie_name, 'mp_session_') !== false
                        || strpos($cookie_name, 'surecart_session') !== false
                        || strpos($cookie_name, 'surecart_customer') !== false
                        || strpos($cookie_name, 'wp_ec_session_') !== false
                        || strpos($cookie_name, 'swpm_session') !== false
                        || strpos($cookie_name, 'um_cache_') !== false
                    ) {
                        // Enforce non-trivial session token length (minimum 16 bytes)
                        if (strlen($cookie_val) >= 16) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Detect if the incoming URI or request belongs to legitimate E-Commerce, Cart,
     * Checkout, Customer Account, or Payment Gateway Webhook channels.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_commerce_or_membership_request(string $uri): bool {
        // CAF 2.0: Instant O(1) short-circuit if site runs zero commerce or membership plugins
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            if (!\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('commerce') &&
                !\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('lms_membership')) {
                return false;
            }
        }

        $parsed_path = strtolower(wp_parse_url($uri, PHP_URL_PATH) ?: $uri);
        $query_string = isset($_SERVER['QUERY_STRING']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';

        // 1. Direct E-Commerce AJAX & API parameters
        if (strpos($uri, 'wc-ajax=') !== false || strpos($query_string, 'wc-ajax=') !== false) {
            return true;
        }
        if (strpos($uri, 'wc-api=') !== false || strpos($query_string, 'wc-api=') !== false) {
            return true;
        }
        if (strpos($uri, 'surecart_action=') !== false || strpos($query_string, 'surecart_action=') !== false) {
            return true;
        }
        if (strpos($uri, 'give-api=') !== false || strpos($query_string, 'give-api=') !== false) {
            return true;
        }

        // 2. REST API Store, Cart, Profile & Webhook Endpoints
        $commerce_rest_prefixes = [
            '/wp-json/wc/store/',
            '/wp-json/wc/v3/',
            '/wp-json/wc/v2/',
            '/wp-json/stripe/',
            '/wp-json/wc-stripe/',
            '/wp-json/paypal/',
            '/wp-json/mollie/',
            '/wp-json/square/',
            '/wp-json/edd/',
            '/wp-json/surecart/',
            '/wp-json/give-api/',
            '/wp-json/fluentcart/',
            '/wp-json/bigcommerce/',
            '/wp-json/mp/v1/',       // MemberPress
            '/wp-json/pmpro/v1/',    // Paid Memberships Pro
            '/wp-json/rcp/v1/',      // Restrict Content Pro
            '/wp-json/suremembers/', // SureMembers
            '/wp-json/armember/',    // ARMember
            '/wp-json/wpum/',        // WP User Manager
            '/wp-json/profilepress/',
            '/wp-json/user-registration/',
            '/wp-json/buddyboss/',
            '/wp-json/youzify/',
        ];
        foreach ($commerce_rest_prefixes as $prefix) {
            if (strpos($parsed_path, $prefix) !== false) {
                return true;
            }
        }

        // 3. Typical Store, Cart, Checkout, Profile, and Member Portal URI slugs
        $store_slug_patterns = [
            '/\/shop(\/|$)/i',
            '/\/product(\/|$)/i',
            '/\/cart(\/|$)/i',
            '/\/checkout(\/|$)/i',
            '/\/my-account(\/|$)/i',
            '/\/order-received(\/|$)/i',
            '/\/member-account(\/|$)/i',
            '/\/membership-account(\/|$)/i',
            '/\/membership-checkout(\/|$)/i',
            '/\/register-membership(\/|$)/i',
            '/\/user-profile(\/|$)/i',
            '/\/my-profile(\/|$)/i',
            '/\/client-portal(\/|$)/i',
            '/\/donations(\/|$)/i',
            '/\/donate(\/|$)/i',
            '/\/give(\/|$)/i',
        ];
        foreach ($store_slug_patterns as $spat) {
            if (preg_match($spat, $parsed_path)) {
                return true;
            }
        }

        // 4. Payment Gateway Webhook Identifiers in Query String
        $gateway_webhook_signals = [
            'wc_stripe_webhook',
            'wc_square_webhook',
            'mollie_webhook',
            'paypal_ipn',
            'ipn_listener',
            'payment_listener',
            'razorpay_webhook',
            'paystack_webhook',
            'klarna_notification',
            'edd-listener',
            'authorizenet_silent_post',
            'wc_gateway_authorizenet',
            'surecart_webhook',
            'give_webhook',
            'fluentcart_webhook',
            'simple_pay_webhook',
        ];
        foreach ($gateway_webhook_signals as $signal) {
            if (strpos($query_string, $signal) !== false || strpos($uri, $signal) !== false) {
                return true;
            }
        }

        // 5. Cryptographic Payment Gateway Webhook Signatures (Wordfence Smart Pipeline)
        // Authentic server-to-server payment notifications are signed by gateways with dedicated headers on designated endpoints.
        $is_webhook_endpoint = (
            strpos($parsed_path, '/wp-json/stripe') !== false
            || strpos($parsed_path, '/wp-json/wc-stripe') !== false
            || strpos($parsed_path, '/wp-json/wc/v') !== false
            || strpos($parsed_path, '/wp-json/paypal') !== false
            || strpos($parsed_path, '/wp-json/mollie') !== false
            || strpos($parsed_path, '/wp-json/square') !== false
            || strpos($parsed_path, '/wp-json/surecart') !== false
            || strpos($uri, 'wc-api=') !== false
            || strpos($query_string, 'wc-api=') !== false
            || strpos($uri, 'wc-ajax=') !== false
        );

        if ($is_webhook_endpoint && (
            !empty($_SERVER['HTTP_STRIPE_SIGNATURE'])
            || !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG'])
            || !empty($_SERVER['HTTP_PAYPAL_CERT_URL'])
            || !empty($_SERVER['HTTP_X_SQUARE_HMACSHA256_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_WC_WEBHOOK_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_RAZORPAY_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'])
            || !empty($_SERVER['HTTP_X_MOLLIE_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_SURECART_SIGNATURE'])
        )) {
            return true;
        }

        // 6. Direct Gateway CIDR/IP Verification for E-Commerce Callbacks
        $client_ip = self::get_client_ip();
        if (in_array($client_ip, self::STRIPE_WEBHOOK_IPS, true)) {
            return true;
        }
        foreach (self::PAYPAL_WEBHOOK_CIDRS as $paypal_cidr) {
            if (self::ip_in_range($client_ip, $paypal_cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an incoming request corresponds to a legitimate form submission
     * across major WordPress form plugins (Contact Form 7, WPForms, Fluent Forms,
     * Gravity Forms, Ninja Forms, Formidable Forms, WS Form, HappyForms, etc.).
     *
     * @param string $uri
     * @return bool
     */
    public static function is_form_submission_request(string $uri): bool {
        $parsed_path = strtolower(wp_parse_url($uri, PHP_URL_PATH) ?: $uri);
        $query_string = isset($_SERVER['QUERY_STRING']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';
        $req_method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');

        // Form submissions are predominantly POST (or PUT/PATCH in specialized AJAX pipelines)
        $is_submit_method = in_array($req_method, ['POST', 'PUT', 'PATCH'], true);

        // 1. Contact Form 7 (CF7) REST API & Feedback Routes
        // Modern CF7 submits exclusively via: /wp-json/contact-form-7/v1/contact-forms/{id}/feedback
        if (strpos($parsed_path, '/contact-form-7/v1/contact-forms/') !== false || strpos($uri, 'contact-form-7/v1') !== false) {
            return true;
        }
        if (strpos($query_string, 'contact-form-7') !== false || strpos($query_string, '_wpcf7') !== false) {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['_wpcf7']) || !empty($_POST['_wpcf7_version']) || !empty($_POST['_wpcf7_unit_tag'])) {
            return true;
        }

        // 2. WPForms AJAX & REST Submissions
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        $action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
        if ($action === 'wpforms_submit' || $action === 'wpforms_form_submit' || $action === 'wpforms_file_upload') {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['wpforms']) && is_array($_POST['wpforms'])) {
            return true;
        }
        if (strpos($parsed_path, '/wp-json/wpforms/') !== false) {
            return true;
        }

        // 3. Fluent Forms AJAX & REST Submissions
        if ($action === 'fluentform_submit' || $action === 'fluentform_file_upload' || $action === 'fluentform_form_submit') {
            return true;
        }
        if (strpos($parsed_path, '/wp-json/fluentform/v1/') !== false) {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['fluent_forms_nonce']) || !empty($_POST['__fluent_form_embded_post_id'])) {
            return true;
        }

        // 4. Gravity Forms AJAX & Standard Submissions
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['gform_submit']) || !empty($_POST['gform_ajax']) || (isset($_POST['is_submit_']) && is_numeric($_POST['is_submit_']))) {
            return true;
        }
        if (strpos($parsed_path, '/wp-json/gf/v2/') !== false) {
            return true;
        }

        // 5. Ninja Forms AJAX Submissions
        if ($action === 'nf_ajax_submit' || $action === 'ninja_forms_ajax_submit' || $action === 'nf_async_upload') {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['nf_form_id']) || !empty($_POST['ninja_forms_form_id'])) {
            return true;
        }

        // 6. Formidable Forms Submissions
        if ($action === 'frm_entries_create' || $action === 'frm_entries_update' || $action === 'frm_forms_preview') {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['frm_action']) || !empty($_POST['form_id']) && isset($_POST['frm_hide_fields_'])) {
            return true;
        }

        // 7. WS Form, HappyForms, Kali Forms & Everest Forms
        if ($action === 'wsf_submit' || $action === 'happyforms_message' || $action === 'everest_forms_ajax_submit') {
            return true;
        }
        if (strpos($parsed_path, '/wp-json/ws-form/') !== false || strpos($parsed_path, '/wp-json/everest-forms/') !== false) {
            return true;
        }

        // 8. General Generic Form POST detection with verified nonces/honeytokens
        if ($is_submit_method) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
            if (!empty($_POST['_wp_http_referer']) && (!empty($_POST['form_id']) || !empty($_POST['form_token']) || !empty($_POST['_wpnonce']))) {
                // If it's not an admin panel or REST login action, treat as user form
                if (strpos($parsed_path, '/wp-admin/admin-post.php') !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if an IP is in the user-defined whitelist
     */
    /**
     * Check if an IP address belongs to the server itself (Loopback or Host Origin IPv4/IPv6)
     */
    public static function is_server_origin_or_loopback(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        // 1. Standard loopback
        if (in_array($ip, ['127.0.0.1', '::1'], true)) {
            return true;
        }

        // 2. Direct server environment address
        if (!empty($_SERVER['SERVER_ADDR']) && $ip === $_SERVER['SERVER_ADDR']) {
            return true;
        }
        if (!empty($_SERVER['LOCAL_ADDR']) && $ip === $_SERVER['LOCAL_ADDR']) {
            return true;
        }

        // 3. Compare against all resolved ServerInfo IPs (IPv4 and IPv6) with binary normalization
        if (class_exists('\\WebCareProScanner\\System\\ServerInfo')) {
            $all_server_ips = \WebCareProScanner\System\ServerInfo::get_all_server_ips();
            if (in_array($ip, $all_server_ips, true)) {
                return true;
            }
            $ip_bin = @inet_pton($ip);
            if ($ip_bin !== false) {
                foreach ($all_server_ips as $sip) {
                    $sip_bin = @inet_pton($sip);
                    if ($sip_bin !== false && $sip_bin === $ip_bin) {
                        return true;
                    }
                }
            }
        }

        // 4. Local Docker / Container bridge gateway in local environments
        if (strpos($ip, '172.17.') === 0 || strpos($ip, '172.18.') === 0 || strpos($ip, '172.19.') === 0 || strpos($ip, '10.0.2.') === 0) {
            $site_host = function_exists('home_url') ? (string) wp_parse_url(home_url(), PHP_URL_HOST) : '';
            $req_host  = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
            $combined  = strtolower($site_host . ' ' . $req_host);
            if (strpos($combined, 'localhost') !== false || strpos($combined, '127.0.0.1') !== false || strpos($combined, '.local') !== false || strpos($combined, '.test') !== false) {
                return true;
            }
        }

        return false;
    }

    public static function is_ip_whitelisted(string $ip, ?string $whitelist_str = null): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        if ($whitelist_str === null) {
            $settings = SettingsManager::get_settings();
            $whitelist_str = $settings['waf_whitelisted_ips'] ?? '';
        }

        // 0. Auto-accept server's own origin IP (IPv4 and IPv6) and loopback addresses across all sites
        if (self::is_server_origin_or_loopback($ip)) {
            return true;
        }

        // Emergency wp-config override constant: WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP
        if (defined('WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP')) {
            $override_ips = is_array(WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP) ? WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP : explode(',', (string) WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP);
            foreach ($override_ips as $override_ip) {
                $override_ip = trim($override_ip);
                if (!empty($override_ip)) {
                    if ($override_ip === $ip || (strpos($override_ip, '/') !== false && self::ip_in_range($ip, $override_ip))) {
                        return true;
                    }
                }
            }
        }

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

        // Check active temporary customer/merchant bypass allowlists (e.g. 24-hour customer unblock)
        if (get_transient('webcareproscan_temp_allow_' . md5($ip))) {
            return true;
        }

        return false;
    }

    /**
     * Check if an IP is in the user-defined blocklist
     */
    public static function is_ip_blocked(string $ip, string $blocklist_str): bool {
        return self::get_matching_blocked_entry($ip, $blocklist_str) !== null;
    }

    /**
     * Find the exact blocklist entry (IP or CIDR subnet) matching a client IP.
     *
     * @param string $ip
     * @param string $blocklist_str
     * @return string|null Matching line string or null if not blocked
     */
    public static function get_matching_blocked_entry(string $ip, string $blocklist_str): ?string {
        if (empty($blocklist_str)) {
            return null;
        }

        // Hard Guard: Local loopback can NEVER be blocked
        if (in_array($ip, ['127.0.0.1', '::1'], true)) {
            return null;
        }

        $lines = explode("\n", str_replace("\r", "", $blocklist_str));
        foreach ($lines as $line) {
            $clean = trim($line);
            if ($clean === '') {
                continue;
            }
            if ($clean === $ip) {
                return $clean;
            }
            // Simple CIDR / subnet support
            if (strpos($clean, '/') !== false && self::ip_in_range($ip, $clean)) {
                return $clean;
            }
        }

        return null;
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

        // Normalize IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        if (stripos($ip, '::ffff:') === 0) {
            $mapped_v4 = substr($ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip = $mapped_v4;
            }
        }

        if (strpos($range, '/') === false) {
            if (stripos($range, '::ffff:') === 0) {
                $mapped_r = substr($range, 7);
                if (filter_var($mapped_r, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $range = $mapped_r;
                }
            }
            return $ip === $range;
        }

        $parts = explode('/', $range, 2);
        if (count($parts) !== 2 || !ctype_digit(trim($parts[1]))) {
            return false;
        }

        $subnet = trim($parts[0]);
        if (stripos($subnet, '::ffff:') === 0) {
            $mapped_sub = substr($subnet, 7);
            if (filter_var($mapped_sub, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $subnet = $mapped_sub;
            }
        }
        $bits = (int) trim($parts[1]);

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
     * Automattic / WordPress.com Jetpack Official IP CIDR Ranges
     * Source: Automattic official Jetpack documentation & ARIN/RIPE allocations.
     */
    public const JETPACK_IP_RANGES = [
        '192.0.64.0/18',
        '192.0.80.0/20',
        '192.0.96.0/20',
        '192.0.112.0/20',
        '195.234.108.0/22',
        '122.248.245.244/32',
        '54.217.201.243/32',
        '54.232.116.4/32',
    ];

    /**
     * Official Stripe Webhook IP Addresses
     * Source: Stripe official webhook documentation (https://docs.stripe.com/ips)
     */
    public const STRIPE_WEBHOOK_IPS = [
        '3.18.12.63',
        '3.130.192.231',
        '13.235.14.237',
        '13.235.122.149',
        '18.211.135.69',
        '35.154.171.200',
        '52.15.183.38',
        '54.88.130.119',
        '54.88.130.237',
        '54.88.130.238',
        '54.88.130.241',
        '54.187.174.169',
        '54.187.205.235',
        '54.187.216.72',
        '54.241.31.99',
        '54.241.31.100',
        '54.241.34.23',
        '54.241.47.70',
        '54.243.149.206',
    ];

    /**
     * Official PayPal IPN & Webhook Subnet CIDRs
     * Source: PayPal Developer Documentation & ARIN allocations.
     */
    public const PAYPAL_WEBHOOK_CIDRS = [
        '173.0.80.0/20',
        '66.211.168.0/22',
        '64.4.240.0/21',
        '64.4.248.0/22',
        '91.243.72.0/23',
        '185.177.52.0/22',
        '192.160.215.0/24',
        '198.54.216.0/23',
    ];

    /**
     * Check whether an incoming request to xmlrpc.php is a verified, authentic Jetpack sync from Automattic.
     *
     * Validates:
     * 1. Setting 'waf_allow_jetpack_xmlrpc' is enabled.
     * 2. Request targets xmlrpc.php and contains query parameter ?for=jetpack.
     * 3. Client IP belongs strictly to Automattic's verified CIDR blocks (prevents User-Agent / parameter spoofing).
     * 4. Essential cryptographic signature parameters (token, timestamp, nonce, signature) are present.
     *
     * @param string $client_ip
     * @param string $request_uri
     * @param array $settings
     * @return bool
     */
    public static function is_verified_jetpack_request(string $client_ip, string $request_uri, array $settings): bool {
        if (empty($settings['waf_allow_jetpack_xmlrpc'])) {
            return false;
        }

        // Must explicitly target xmlrpc.php with for=jetpack
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Jetpack pingback incoming verification
        $for_param = isset($_GET['for']) ? sanitize_key(wp_unslash($_GET['for'])) : '';
        if ($for_param !== 'jetpack' && strpos($request_uri, 'for=jetpack') === false) {
            return false;
        }

        // 1. Strict IP Verification against Automattic's CIDRs
        $ip_matched = false;
        foreach (self::JETPACK_IP_RANGES as $cidr) {
            if (self::ip_in_range($client_ip, $cidr)) {
                $ip_matched = true;
                break;
            }
        }

        if (!$ip_matched) {
            return false;
        }

        // 2. Cryptographic signature parameters check (Jetpack signs all outbound syncs)
        // Requests must carry timestamp and at least signature or token (inspect both superglobals and request URI)
        $query_str = wp_parse_url($request_uri, PHP_URL_QUERY);
        $uri_params = [];
        if (!empty($query_str)) {
            parse_str($query_str, $uri_params);
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Jetpack HMAC signature inspection
        $has_timestamp = isset($_GET['timestamp']) || isset($_POST['timestamp']) || isset($uri_params['timestamp']);
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Jetpack token verification
        $has_signature = isset($_GET['signature']) || isset($_POST['signature']) || isset($_GET['token']) || isset($_POST['token'])
            || isset($uri_params['signature']) || isset($uri_params['token']);

        if (!$has_timestamp && !$has_signature) {
            return false;
        }

        return true;
    }

    /**
     * Check whether an incoming request belongs to an authenticated central WordPress management
     * network worker (ManageWP, MainWP, InfiniteWP).
     *
     * Validates:
     * 1. Setting 'waf_allow_central_management' is enabled.
     * 2. Request targets legitimate worker endpoints or carries worker cryptographic signature headers:
     *    - ManageWP Worker: HTTP_X_MWP_SIGNATURE or HTTP_X_MANAGEWP_SIGNATURE
     *    - MainWP Child: HTTP_X_MAINWP_SIGNATURE or POST parameter 'mainwp_signature'
     *    - InfiniteWP: HTTP_IWP_ACTION or POST parameter 'iwp_action'
     * 3. Confirms corresponding official worker plugin is actively installed and running.
     *
     * @param string $request_uri
     * @param array $settings
     * @return bool
     */
    public static function is_verified_central_management_request(string $request_uri, array $settings): bool {
        if (empty($settings['waf_allow_central_management'])) {
            return false;
        }

        // ManageWP Worker validation
        $has_mwp_sig = !empty($_SERVER['HTTP_X_MWP_SIGNATURE']) || !empty($_SERVER['HTTP_X_MANAGEWP_SIGNATURE']);
        if ($has_mwp_sig && (class_exists('MMB_Core') || defined('MMB_WORKER_VERSION') || function_exists('mwp_core'))) {
            return true;
        }

        // MainWP Child validation
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- MainWP worker signature check
        $has_mainwp_sig = !empty($_SERVER['HTTP_X_MAINWP_SIGNATURE']) || isset($_POST['mainwp_signature']);
        if ($has_mainwp_sig && (class_exists('MainWP_Child') || defined('MAINWP_CHILD_PLUGIN_DIR'))) {
            return true;
        }

        // InfiniteWP Client validation
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- InfiniteWP worker action check
        $has_iwp_action = !empty($_SERVER['HTTP_IWP_ACTION']) || isset($_POST['iwp_action']);
        if ($has_iwp_action && (class_exists('IWP_MMB_Core') || defined('IWP_MMB_USER_AGENT'))) {
            return true;
        }

        return false;
    }

    /**
     * Log firewall incident to database or partitioned JSON storage
     */
    public static function log_incident(array $rule, string $action, ?string $incident_id = null): ?string {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_firewall_logs';

        $ip = self::get_client_ip();
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $uri = substr($raw_uri, 0, 500);

        $raw_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $method = substr($raw_method, 0, 10);

        $raw_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $user_agent = substr($raw_ua, 0, 300);

        // Red Team Synthetic Attack Drill: NEVER log synthetic simulation probes to persistent incident table
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['webcare_drill_token']) ? sanitize_text_field(wp_unslash($_GET['webcare_drill_token'])) : (isset($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WebCareProScanner\\Security\\AttackSimulationEngine') && \WebCareProScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            return null;
        }

        // Server Origin IP Safety: Never log server's own outbound IP as an offending attacker
        $server_ip = class_exists('\\WebCareProScanner\\System\\ServerInfo') ? \WebCareProScanner\System\ServerInfo::get_server_ip() : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '');
        if (!empty($server_ip) && $ip === $server_ip) {
            return null;
        }

        $raw_referer = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '';
        $referer = substr($raw_referer, 0, 500);

        if (empty($incident_id)) {
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
        }
        self::$last_incident_id = $incident_id;

        if ($action === 'blocked' && empty($rule['ref_code'])) {
            $rule['ref_code'] = self::generate_ref_code();
        }
        if (!empty($rule['ref_code'])) {
            self::$last_ref_code = strtoupper(sanitize_text_field($rule['ref_code']));
        }

        // Determine HTTP Status Code
        $status_code = 403;
        if ($action === 'detected' || $action === 'bypassed' || $action === 'allowed' || $action === 'monitored') {
            $status_code = 200;
        } elseif (isset($rule['category']) && $rule['category'] === '404 Scanner Rate Limit') {
            $status_code = 404;
        } elseif (isset($rule['category']) && (stripos($rule['category'], 'method') !== false || stripos($rule['description'] ?? '', 'method') !== false)) {
            $status_code = 405;
        }
        $category = sanitize_key($rule['category'] ?? 'general_defense');

        // Delegate zero-SQL WAF incident logging to daily JSON filesystem partitioner
        $logged_id = WafFileLogger::log_incident($rule, $action, $incident_id);
        if ($logged_id === null) {
            return null;
        }
        $incident_id = $logged_id;

        // Dispatch DevSecOps Webhook on blocked attack
        if ($action === 'blocked' && class_exists('\\WebCareProScanner\\Notifications\\WebhookService')) {
            \WebCareProScanner\Notifications\WebhookService::send_waf_alert([
                'category'   => $rule['category'],
                'name'       => $rule['name'] ?? $rule['category'],
                'ip_address' => $ip,
                'incident_id'=> $incident_id,
            ]);
        }

        // Dispatch granular event notifications via NotificationDispatcher
        if ($action === 'blocked' && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            $is_virtual_patch = !empty($rule['is_virtual_patch']) || stripos($rule['category'] ?? '', 'Virtual Patch') !== false;
            if ($is_virtual_patch) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('waf_virtual_patch_hit', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: attacker IP address, 2: rule name or category, 3: incident ID */
                        __('Virtual Patch intercepted an exploit payload from %1$s targeting "%2$s" [Incident: %3$s].', 'webcare-pro-security'),
                        $ip,
                        $rule['name'] ?? $rule['category'],
                        $incident_id
                    ),
                    'details'  => [
                        'attacker_ip' => $ip,
                        'incident_id' => $incident_id,
                        'rule_name'   => $rule['name'] ?? $rule['category'],
                        'category'    => $rule['category'],
                    ],
                ]);
            }
        }

        return $incident_id;
    }

    /**
     * Render branded 403 Forbidden Error Screen via standard wp_die()
     */
    private static function render_block_page(array $rule, string $client_ip, ?string $incident_id = null) {
        // Red Team Drill Intercept Handler
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['webcare_drill_token']) ? sanitize_text_field(wp_unslash($_GET['webcare_drill_token'])) : (isset($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WebCareProScanner\\Security\\AttackSimulationEngine') && \WebCareProScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            \WebCareProScanner\Security\AttackSimulationEngine::record_intercept($drill_token, $rule, 403);
            header('X-WebCare-Drill-Intercepted: 1');
            header('X-WebCare-Drill-Rule-ID: ' . rawurlencode($rule['id'] ?? 'WAF-INTERCEPT'));
            header('X-WebCare-Drill-Category: ' . rawurlencode($rule['category'] ?? 'WAF'));
            status_header(403);
            echo wp_json_encode([
                'success'     => false,
                'drill'       => true,
                'intercepted' => true,
                'rule_id'     => $rule['id'] ?? 'WAF-INTERCEPT',
                'category'    => $rule['category'] ?? 'WAF',
            ]);
            exit;
        }

        if (empty($incident_id)) {
            $incident_id = self::$last_incident_id ?: ('WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8)));
        }

        // Reuse ref_code already attached to log_incident() so WAF Logs and Support Code match 1:1
        $ref_code = !empty($rule['ref_code'])
            ? strtoupper(sanitize_text_field($rule['ref_code']))
            : (!empty(self::$last_ref_code) ? self::$last_ref_code : self::generate_ref_code());
        self::$last_ref_code = null;

        // Fast transient lookup for non-technical site owners to unblock paying customers in 1 click
        $transient_data = [
            'ref_code'      => $ref_code,
            'incident_id'   => $incident_id,
            'client_ip'     => $client_ip,
            'rule_id'       => $rule['id'] ?? 'WAF-BLOCK',
            'rule_name'     => $rule['name'] ?? ($rule['category'] ?? 'Security Shield'),
            'rule_category' => $rule['category'] ?? 'Security Shield',
            'description'   => $rule['description'] ?? 'Automated defense rule triggered.',
            'request_uri'   => substr(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/')), 0, 255),
            'timestamp'     => time(),
            'formatted_time'=> gmdate('Y-m-d H:i:s \U\T\C'),
        ];
        set_transient('webcareproscan_lockout_' . $ref_code, $transient_data, 2 * DAY_IN_SECONDS);
        if (!empty($incident_id) && $incident_id !== $ref_code) {
            set_transient('webcareproscan_lockout_' . $incident_id, $transient_data, 2 * DAY_IN_SECONDS);
        }
        // Also index by md5(IP) for instant customer unblocking via IP search
        set_transient('webcareproscan_lockout_ip_' . md5($client_ip), $transient_data, 2 * DAY_IN_SECONDS);

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

        // 1. E-Commerce & Checkout AJAX handler (WooCommerce, SureCart, EDD)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Low-level firewall intercept inspects query parameters to determine structured JSON error formatting
        $is_wc_ajax = !empty($_GET['wc-ajax']) || !empty($_GET['wc-api']);
        if ($is_wc_ajax || (wp_doing_ajax() && self::is_commerce_or_membership_request($raw_uri))) {
            status_header(403);
            header('Content-Type: application/json; charset=utf-8');
            /* translators: 1: Security notice label, 2: Security explanation, 3: Support reference code label, 4: Support reference code */
            $ajax_msg = sprintf(
                '<div class="woocommerce-error" role="alert"><strong>%1$s</strong> %2$s<br/><span style="font-size:12px;opacity:0.9;">%3$s <strong>%4$s</strong></span></div>',
                esc_html__('Security Notice:', 'webcare-pro-security'),
                esc_html__('Your connection was temporarily held to protect this site.', 'webcare-pro-security'),
                esc_html__('Customer Support Reference Code:', 'webcare-pro-security'),
                esc_html($ref_code)
            );
            echo wp_json_encode([
                'result'        => 'failure',
                'messages'      => $ajax_msg,
                'reload'        => false,
                'refresh'       => false,
                'incident_id'   => $incident_id,
                'ref_code'      => $ref_code,
                'error'         => esc_html__('Security checkpoint active. Please quote reference code to support.', 'webcare-pro-security'),
            ]);
            exit;
        }

        // 2. Generic REST API structured JSON error
        if (defined('REST_REQUEST') && REST_REQUEST) {
            status_header(403);
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode([
                'code'          => 'webcareproscan_access_denied',
                'message'       => esc_html__('Your connection was temporarily held to protect this website against automated abusive traffic or invalid requests.', 'webcare-pro-security'),
                'data'          => [
                    'status'      => 403,
                    'incident_id' => $incident_id,
                    'ref_code'    => $ref_code,
                ],
            ]);
            exit;
        }

        $site_name   = get_bloginfo('name');
        $rule_cat    = esc_html($rule['category'] ?? 'Security Shield');

        $message = sprintf(
            '<div style="font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Oxygen-Sans, Ubuntu, Cantarell, \"Helvetica Neue\", sans-serif; max-width: 620px; margin: 40px auto; line-height: 1.6; color: #1e293b; background: #ffffff; padding: 36px; border-radius: 14px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.06), 0 8px 10px -6px rgba(0,0,0,0.04); border: 1px solid #e2e8f0;">' .
            '<div style="display: flex; align-items: center; margin-bottom: 20px;">' .
            '<div style="width: 44px; height: 44px; border-radius: 10px; background: #fee2e2; display: flex; align-items: center; justify-content: center; font-size: 22px; margin-right: 14px; text-align: center; line-height: 44px;">🛡️</div>' .
            '<div>' .
            '<h2 style="color: #0f172a; margin: 0; font-size: 22px; font-weight: 700;">%s</h2>' .
            '<p style="margin: 3px 0 0; color: #64748b; font-size: 13px;">%s</p>' .
            '</div>' .
            '</div>' .
            '<p style="font-size: 14px; color: #334155; margin-bottom: 20px;">%s</p>' .
            '<div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #3b82f6; padding: 16px 20px; border-radius: 8px; margin: 20px 0;">' .
            '<p style="margin: 0 0 6px; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; color: #64748b;">%s</p>' .
            '<div style="display: flex; align-items: baseline; gap: 10px;">' .
            '<span style="font-family: SFMono-Regular, Consolas, monospace; font-size: 24px; font-weight: 800; color: #1e40af; letter-spacing: 1px;">%s</span>' .
            '<span style="font-size: 12px; color: #64748b;">(%s)</span>' .
            '</div>' .
            '<p style="margin: 8px 0 0; font-size: 12px; color: #475569;">%s</p>' .
            '</div>' .
            '<div style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 12px 16px; border-radius: 8px; margin: 18px 0; font-size: 12px; color: #475569;">' .
            '<p style="margin: 3px 0;"><strong>%s:</strong> <code>%s</code></p>' .
            '<p style="margin: 3px 0;"><strong>%s:</strong> <code>%s</code></p>' .
            '<p style="margin: 3px 0;"><strong>%s:</strong> <span>%s</span></p>' .
            '<p style="margin: 3px 0;"><strong>%s:</strong> <span>%s</span></p>' .
            '</div>' .
            '<p style="font-size: 12px; color: #94a3b8; text-align: center; margin-top: 24px;">%s</p>' .
            '</div>',
            esc_html__('Protected by WebCare Pro Security', 'webcare-pro-security'),
            sprintf(
                /* translators: %s: site name */
                esc_html__('Automated safety checkpoint on %s', 'webcare-pro-security'),
                esc_html($site_name)
            ),
            esc_html__('Your connection was temporarily held to protect this website against automated abusive traffic or repeated invalid requests.', 'webcare-pro-security'),
            esc_html__('Customer Support Reference Code', 'webcare-pro-security'),
            esc_html($ref_code),
            esc_html__('Share with Store Owner', 'webcare-pro-security'),
            esc_html__('Are you a legitimate customer having trouble checking out or logging in? Share this code with the site owner or support team to restore access in 1 click.', 'webcare-pro-security'),
            esc_html__('Incident ID', 'webcare-pro-security'),
            esc_html($incident_id),
            esc_html__('Client IP', 'webcare-pro-security'),
            esc_html($client_ip),
            esc_html__('Defense Category', 'webcare-pro-security'),
            $rule_cat,
            esc_html__('Timestamp', 'webcare-pro-security'),
            esc_html(gmdate('Y-m-d H:i:s \U\T\C')),
            esc_html__('WebCare Pro Security Suite • Zero-Trust Perimeter Defense', 'webcare-pro-security')
        );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        wp_die($message, esc_html__('403 Forbidden - Security Shield Block', 'webcare-pro-security'), [
            'response'  => 403,
            'code'      => 'webcareproscan_access_denied',
            'back_link' => false,
        ]);
    }

    /**
     * Get statistics & summary of firewall activity
     */
    public static function get_status(): array {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_firewall_logs';

        $settings = SettingsManager::get_settings();
        $env = self::detect_environment();

        $total_blocks = 0;
        $blocks_24h = 0;
        $top_rules = [];

        // 1. Fetch aggregate metrics from primary WAF filesystem log engine (WafFileLogger)
        $file_stats = WafFileLogger::get_log_stats('all');
        $file_total = (int) ($file_stats['blocked_24h'] ?? 0); // In WafFileLogger, 'blocked_24h' key stores total blocked count across the queried range
        $top_rules  = array_slice($file_stats['top_categories'] ?? [], 0, 5);

        // Calculate accurate past 24-hour blocked count across active rolling log window
        $now = time();
        $cutoff_24h = $now - 86400;
        $file_24h = 0;
        $today_file = WafFileLogger::get_storage_dir() . DIRECTORY_SEPARATOR . WafFileLogger::get_daily_filename();
        $today_exists = file_exists($today_file);
        $all_available_files = WafFileLogger::get_available_files();

        // Inspect log files from the past 48 hours for precise 24-hour timestamp evaluation
        foreach ($all_available_files as $finfo) {
            $fdate_ts = strtotime((string) ($finfo['date'] ?? ''));
            if ($fdate_ts !== false && $fdate_ts < ($now - 172800)) {
                continue;
            }
            $fpath = WafFileLogger::get_storage_dir() . DIRECTORY_SEPARATOR . $finfo['filename'];
            if (!file_exists($fpath) || !is_readable($fpath)) {
                continue;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-memory progressive streaming of partitioned JSONL log files
            $handle = @fopen($fpath, 'r');
            if (!$handle) {
                continue;
            }
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if ($line === '' || $line[0] !== '{') {
                    continue;
                }
                $rec = json_decode($line, true);
                if (!is_array($rec)) {
                    continue;
                }
                $rec_ts = (int) ($rec['timestamp'] ?? (isset($rec['created_at']) ? strtotime($rec['created_at']) : 0));
                if ($rec_ts >= $cutoff_24h && ($rec['action_taken'] ?? '') === 'blocked') {
                    $file_24h++;
                }
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($handle);
        }

        // If no attacks have arrived today yet and today's file does not exist, fall back to the most recent day file
        if ($file_24h === 0 && !$today_exists && !empty($all_available_files)) {
            $latest_path = WafFileLogger::get_storage_dir() . DIRECTORY_SEPARATOR . $all_available_files[0]['filename'];
            if (file_exists($latest_path) && is_readable($latest_path)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
                $handle = @fopen($latest_path, 'r');
                if ($handle) {
                    while (($line = fgets($handle)) !== false) {
                        $line = trim($line);
                        if ($line === '' || $line[0] !== '{') {
                            continue;
                        }
                        $rec = json_decode($line, true);
                        if (!is_array($rec)) {
                            continue;
                        }
                        if (($rec['action_taken'] ?? '') === 'blocked') {
                            $file_24h++;
                        }
                    }
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                    fclose($handle);
                }
            }
        }

        $total_blocks = $file_total;
        $blocks_24h   = $file_24h;

        // 2. Fallback / merge legacy SQL database table if existing records are present
        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if ($table_exists) {
            $total_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked'";
            $blocks_24h_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
            $top_rules_sql = "SELECT rule_category, COUNT(*) as count FROM `{$table}` WHERE action_taken = 'blocked' GROUP BY rule_category ORDER BY count DESC LIMIT 5";
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
            $db_total = (int) $wpdb->get_var($total_sql);
            $db_24h   = (int) $wpdb->get_var($blocks_24h_sql);
            if ($db_total > 0) {
                $total_blocks += $db_total;
                $blocks_24h   += $db_24h;
                if (empty($top_rules)) {
                    $top_rules = $wpdb->get_results(
                        $top_rules_sql,
                        ARRAY_A
                    ) ?: [];
                }
            }
            // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
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
            'edge_advisor'       => class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')
                ? \WebCareProScanner\Cloudflare\CloudflareService::get_edge_advisor()
                : null,
            'server_telemetry'   => self::get_server_telemetry(),
            'available_roles'    => self::get_available_roles(),
            'commerce_telemetry' => [
                'is_active' => self::is_commerce_active(),
                'detected_names' => array_values(array_filter([
                    // Archetype Profile
                    in_array(get_option('webcareproscan_site_archetype'), ['ecommerce', 'membership'], true) ? 'Configured ' . ucfirst((string) get_option('webcareproscan_site_archetype')) . ' Archetype' : null,
                    // E-Commerce
                    class_exists('WooCommerce') ? 'WooCommerce' : null,
                    class_exists('Easy_Digital_Downloads') ? 'Easy Digital Downloads' : null,
                    (class_exists('\\SureCart\\SureCart') || defined('SURECART_PLUGIN_FILE')) ? 'SureCart' : null,
                    (class_exists('Ecwid_Product') || defined('ECWID_PLUGIN_DIR')) ? 'Ecwid by Lightspeed' : null,
                    (class_exists('wp_easycart') || defined('EC_CURRENT_VERSION')) ? 'WP EasyCart' : null,
                    (class_exists('\\FluentCart\\App\\App') || defined('FLUENTCART_VERSION')) ? 'FluentCart' : null,
                    (class_exists('\\BigCommerce\\Container') || defined('BIGCOMMERCE_VERSION')) ? 'BigCommerce' : null,
                    (class_exists('SimplePay') || defined('SIMPLE_PAY_VERSION')) ? 'WP Simple Pay' : null,
                    (class_exists('Cart66') || defined('CART66_VERSION')) ? 'Cart66' : null,
                    class_exists('WP_DLM') ? 'Download Monitor' : null,
                    (class_exists('Give') || defined('GIVE_VERSION')) ? 'GiveWP' : null,
                    // Membership
                    class_exists('MeprAppCtrl') ? 'MemberPress' : null,
                    defined('PMPRO_VERSION') ? 'Paid Memberships Pro' : null,
                    (class_exists('Restrict_Content_Pro') || defined('RCP_PLUGIN_VERSION')) ? 'Restrict Content Pro / Kadence Memberships' : null,
                    (class_exists('\\SureMembers\\SureMembers') || defined('SUREMEMBERS_VERSION')) ? 'SureMembers' : null,
                    (class_exists('ARM_main') || defined('MEMBERSHIP_VERSION')) ? 'ARMember' : null,
                    (class_exists('MemberMouse') || defined('MM_VERSION')) ? 'MemberMouse' : null,
                    (class_exists('WishListMember') || defined('WLM_VERSION')) ? 'WishList Member' : null,
                    (class_exists('SimpleWpMembership') || defined('SWPM_VERSION')) ? 'Simple Membership' : null,
                    class_exists('WC_Memberships') ? 'WooCommerce Memberships' : null,
                    (class_exists('Pms_Member') || defined('PMS_VERSION')) ? 'Paid Member Subscriptions' : null,
                    class_exists('c_ws_plugin__s2member_menu_pages') ? 's2Member' : null,
                    (class_exists('IhsuMpMain') || defined('UHP_VERSION')) ? 'Ultimate Membership Pro' : null,
                    class_exists('LearnDash_Settings_Section') ? 'LearnDash' : null,
                    class_exists('LifterLMS') ? 'LifterLMS' : null,
                    // Profiles & Registration
                    (class_exists('UM') || defined('um_plugin')) ? 'Ultimate Member' : null,
                    (class_exists('Profile_Builder') || defined('WPPB_PLUGIN_DIR')) ? 'User Profile Builder' : null,
                    (class_exists('WP_User_Manager') || defined('WPUM_VERSION')) ? 'WP User Manager' : null,
                    (class_exists('ProfilePress') || defined('PPRESS_VERSION_NUMBER')) ? 'ProfilePress' : null,
                    (class_exists('User_Registration') || defined('UR_VERSION')) ? 'User Registration' : null,
                    (class_exists('Registration_Magic') || defined('RM_PLUGIN_VERSION')) ? 'RegistrationMagic' : null,
                    (class_exists('Profile_Grid') || defined('PG_PLUGIN_VERSION')) ? 'ProfileGrid' : null,
                    (class_exists('Theme_My_Login') || defined('TML_VERSION')) ? 'ThemeMyLogin' : null,
                    class_exists('FrmRegAppController') ? 'Formidable User Registration' : null,
                    class_exists('wpmembers') ? 'WP-Members' : null,
                    (class_exists('BuddyBoss_Platform') || defined('BP_PLATFORM_VERSION')) ? 'BuddyBoss Platform' : null,
                    (class_exists('Youzify') || defined('YOUZIFY_VERSION')) ? 'Youzify' : null,
                ])),
            ],
            'forms_telemetry'    => [
                'is_active' => (
                    defined('WPCF7_VERSION') || class_exists('WPCF7') ||
                    defined('WPFORMS_VERSION') || class_exists('WPForms') ||
                    defined('FLUENTFORM_VERSION') ||
                    class_exists('GFForms') ||
                    class_exists('Ninja_Forms') ||
                    class_exists('FrmAppController') ||
                    defined('WS_FORM_VERSION') ||
                    defined('CALDERA_FORMS_VERSION') ||
                    defined('HAPPYFORMS_VERSION') ||
                    defined('EVEREST_FORMS_VERSION') ||
                    defined('ELEMENTOR_PRO_VERSION') || class_exists('\\ElementorPro\\Modules\\Forms\\Module')
                ),
                'detected_names' => array_values(array_filter([
                    (defined('ELEMENTOR_PRO_VERSION') || class_exists('\\ElementorPro\\Modules\\Forms\\Module')) ? 'Elementor Pro Forms' : null,
                    (defined('WPCF7_VERSION') || class_exists('WPCF7')) ? 'Contact Form 7' : null,
                    (defined('WPFORMS_VERSION') || class_exists('WPForms')) ? 'WPForms' : null,
                    defined('FLUENTFORM_VERSION') ? 'Fluent Forms' : null,
                    class_exists('GFForms') ? 'Gravity Forms' : null,
                    class_exists('Ninja_Forms') ? 'Ninja Forms' : null,
                    class_exists('FrmAppController') ? 'Formidable Forms' : null,
                    defined('WS_FORM_VERSION') ? 'WS Form' : null,
                    defined('CALDERA_FORMS_VERSION') ? 'Caldera Forms' : null,
                    defined('HAPPYFORMS_VERSION') ? 'HappyForms' : null,
                    defined('EVEREST_FORMS_VERSION') ? 'Everest Forms' : null,
                ])),
                'stats' => class_exists('WebCareProScanner\\Firewall\\FormSpamProtectionEngine') ? \WebCareProScanner\Firewall\FormSpamProtectionEngine::get_stats() : ['total_blocked' => 0],
            ],
            'integrations_telemetry' => [
                'has_builders' => (
                    defined('ELEMENTOR_VERSION') ||
                    defined('ET_BUILDER_VERSION') ||
                    defined('FL_BUILDER_VERSION') ||
                    defined('BRICKS_VERSION') ||
                    defined('BREAKDANCE_VERSION') ||
                    defined('CT_VERSION') || // Oxygen
                    defined('SEEDPROD_VERSION') ||
                    defined('BRIZY_VERSION') ||
                    defined('TVE_VERSION') || // Thrive Architect
                    defined('WPB_VC_VERSION') || // WPBakery
                    defined('VCV_VERSION') || // Visual Composer
                    defined('THEMIFY_BUILDER_VERSION') ||
                    defined('SITEORIGIN_PANELS_VERSION') ||
                    defined('DROIP_VERSION') ||
                    defined('DSLC_VERSION') || // Live Composer
                    (function_exists('wp_is_block_theme') && wp_is_block_theme()) || // WP Site Editor FSE
                    defined('GENERATEBLOCKS_VERSION') ||
                    defined('KADENCE_BLOCKS_VERSION') ||
                    defined('UAGB_VER') || // Spectra
                    defined('FUSION_BUILDER_VERSION') // Avada Fusion Builder
                ),
                'builder_names' => array_values(array_filter([
                    defined('ELEMENTOR_VERSION') ? 'Elementor' : null,
                    defined('ET_BUILDER_VERSION') ? 'Divi Builder' : null,
                    defined('FL_BUILDER_VERSION') ? 'Beaver Builder' : null,
                    defined('BRICKS_VERSION') ? 'Bricks Builder' : null,
                    defined('BREAKDANCE_VERSION') ? 'Breakdance' : null,
                    defined('CT_VERSION') ? 'Oxygen Builder' : null,
                    defined('SEEDPROD_VERSION') ? 'SeedProd' : null,
                    defined('BRIZY_VERSION') ? 'Brizy' : null,
                    defined('TVE_VERSION') ? 'Thrive Architect' : null,
                    defined('WPB_VC_VERSION') ? 'WPBakery' : null,
                    defined('VCV_VERSION') ? 'Visual Composer' : null,
                    defined('THEMIFY_BUILDER_VERSION') ? 'Themify Builder' : null,
                    defined('SITEORIGIN_PANELS_VERSION') ? 'SiteOrigin Page Builder' : null,
                    defined('DROIP_VERSION') ? 'Droip' : null,
                    defined('DSLC_VERSION') ? 'Live Composer' : null,
                    (function_exists('wp_is_block_theme') && wp_is_block_theme()) ? 'WordPress Site Editor (FSE)' : null,
                    defined('GENERATEBLOCKS_VERSION') ? 'GenerateBlocks' : null,
                    defined('KADENCE_BLOCKS_VERSION') ? 'Kadence Blocks' : null,
                    defined('UAGB_VER') ? 'Spectra' : null,
                    defined('FUSION_BUILDER_VERSION') ? 'Avada Fusion Builder' : null,
                ])),
                'has_jetpack' => class_exists('Jetpack'),
                'has_central_management' => (
                    class_exists('MMB_Core') ||
                    class_exists('MainWP_Child') ||
                    class_exists('IWP_MMB_Core') ||
                    defined('MMB_WORKER_VERSION')
                ),
                'management_names' => array_values(array_filter([
                    (class_exists('MMB_Core') || defined('MMB_WORKER_VERSION')) ? 'ManageWP Worker' : null,
                    class_exists('MainWP_Child') ? 'MainWP Child' : null,
                    class_exists('IWP_MMB_Core') ? 'InfiniteWP Client' : null,
                ])),
            ],
            'active_plugin_slugs' => self::get_active_plugin_slugs(),
        ];
    }

    /**
     * Get active plugin directory slugs on this site
     */
    public static function get_active_plugin_slugs(): array {
        $active_plugins = (array) get_option('active_plugins', []);
        if (is_multisite()) {
            $network_active = (array) get_site_option('active_sitewide_plugins', []);
            $active_plugins = array_merge($active_plugins, array_keys($network_active));
        }
        $slugs = [];
        foreach ($active_plugins as $plugin_path) {
            $parts = explode('/', (string) $plugin_path);
            $slugs[] = sanitize_key($parts[0]);
        }
        return array_values(array_unique(array_filter($slugs)));
    }

    /**
     * Get available WordPress user roles on this site.
     *
     * @return array Array of role slugs and their display names.
     */
    public static function get_available_roles(): array {
        global $wp_roles;
        if (!isset($wp_roles) && function_exists('wp_roles')) {
            $wp_roles = wp_roles();
        }
        $roles = [];
        if (!empty($wp_roles->roles) && is_array($wp_roles->roles)) {
            foreach ($wp_roles->roles as $slug => $data) {
                $roles[] = [
                    'slug' => (string) $slug,
                    'name' => isset($data['name']) ? translate_user_role($data['name']) : ucfirst((string) $slug),
                ];
            }
        }
        if (empty($roles)) {
            $roles = [
                ['slug' => 'administrator', 'name' => 'Administrator'],
                ['slug' => 'editor', 'name' => 'Editor'],
                ['slug' => 'author', 'name' => 'Author'],
                ['slug' => 'contributor', 'name' => 'Contributor'],
                ['slug' => 'subscriber', 'name' => 'Subscriber'],
            ];
        }
        return $roles;
    }

    /**
     * Compute comprehensive server, host runtime, and developer diagnostics for the Firewall dashboard.
     *
     * @return array
     */
    public static function get_server_telemetry(): array {
        // 1. Linux Uname & OS Distribution
        $uname_s = php_uname('s');
        $uname_r = php_uname('r');
        $uname_m = php_uname('m');
        $uname_n = php_uname('n');
        $uname_full = php_uname('a');
        $linux_uname_short = "{$uname_s} {$uname_r} ({$uname_m})";

        $distro_name = $uname_s . ' ' . $uname_r;

        // 2. Server Software & SAPI
        $server_software_raw = !empty($_SERVER['SERVER_SOFTWARE'])
            ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))
            : (function_exists('apache_get_version') ? (string) @apache_get_version() : '');
        if (empty($server_software_raw)) {
            if (strpos(php_sapi_name(), 'fpm') !== false) {
                $server_software_raw = 'nginx / PHP-FPM';
            } else {
                $server_software_raw = 'Web Server (' . php_sapi_name() . ')';
            }
        }
        $server_software_type = 'Other';
        if (stripos($server_software_raw, 'litespeed') !== false || stripos($server_software_raw, 'openlitespeed') !== false) {
            $server_software_type = 'LiteSpeed';
        } elseif (stripos($server_software_raw, 'nginx') !== false) {
            $server_software_type = 'Nginx';
        } elseif (stripos($server_software_raw, 'apache') !== false) {
            $server_software_type = 'Apache';
        } elseif (stripos($server_software_raw, 'caddy') !== false) {
            $server_software_type = 'Caddy';
        } elseif (stripos($server_software_raw, 'microsoft-iis') !== false) {
            $server_software_type = 'Microsoft IIS';
        }
        $php_sapi = php_sapi_name();

        // 3. PHP Version & Architecture
        $php_version = PHP_VERSION;
        $php_arch = PHP_INT_SIZE === 8 ? '64-bit' : '32-bit';
        $opcache_active = (bool) (extension_loaded('Zend OPcache') && ini_get('opcache.enable'));

        // 4. Real Server Origin IPs (IPv4 and IPv6)
        $real_server_ip = 'Unknown';
        $real_server_ipv4 = '';
        $real_server_ipv6 = '';

        if (class_exists('\\WebCareProScanner\\System\\ServerInfo')) {
            $all_server_ips = \WebCareProScanner\System\ServerInfo::get_all_server_ips();
            foreach ($all_server_ips as $s_ip) {
                if (filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $s_ip !== '127.0.0.1' && empty($real_server_ipv4)) {
                    $real_server_ipv4 = $s_ip;
                }
                if (filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && $s_ip !== '::1' && strpos($s_ip, 'fe80:') !== 0 && empty($real_server_ipv6)) {
                    $real_server_ipv6 = $s_ip;
                }
            }
            $real_server_ip = \WebCareProScanner\System\ServerInfo::get_server_ip();
        } else {
            $real_server_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown';
            if (filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $real_server_ipv4 = $real_server_ip;
            } elseif (filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $real_server_ipv6 = $real_server_ip;
            }
        }

        if (empty($real_server_ipv4) && filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $real_server_ipv4 = $real_server_ip;
        }

        $is_server_ip_private = !filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);

        // 5. Website CDN Detection & CDN IPs (IPv4 and IPv6)
        $cdn_detected = false;
        $cdn_provider = 'None (Direct Origin)';
        $cdn_ip = 'N/A';
        $cdn_ipv4 = '';
        $cdn_ipv6 = '';

        // Check if connecting peer or raw peer is an edge proxy
        $raw_peer = self::$connecting_peer_ip ?: (!empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '');

        // Check incoming CDN headers
        if (!empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Cloudflare Anycast';
            if (!empty($raw_peer) && self::is_cloudflare_ip($raw_peer)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_FASTLY_CLIENT_IP']) || !empty($_SERVER['HTTP_X_FASTLY_REQUEST_ID'])) {
            $cdn_detected = true;
            $cdn_provider = 'Fastly CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_X_AMZ_CF_ID']) || !empty($_SERVER['HTTP_CLOUDFRONT_FORWARDED_PROTO'])) {
            $cdn_detected = true;
            $cdn_provider = 'Amazon CloudFront';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_TRUE_CLIENT_IP']) || !empty($_SERVER['HTTP_X_AKAMAI_EDGESCAPE'])) {
            $cdn_detected = true;
            $cdn_provider = 'Akamai CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_X_SUCURI_CLIENTIP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Sucuri WAF/CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_INCAP_CLIENT_IP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Imperva / Incapsula';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_X_BUNNY_CLIENT_IP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Bunny CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        }

        // Domain Host resolution for Edge IP verification
        $site_host = wp_parse_url(get_site_url(), PHP_URL_HOST);
        $is_local_host = empty($site_host) || in_array($site_host, ['localhost', '127.0.0.1', '::1', 'local.test'], true) || preg_match('/\.local$/i', $site_host) || preg_match('/\.test$/i', $site_host);

        // Resolve DNS records (both A and AAAA) for site hostname to capture edge IPv4 and IPv6
        $resolved_ips = [];
        if (!$is_local_host) {
            // Method A: dns_get_record for A and AAAA
            if (function_exists('dns_get_record')) {
                $dns_a = @dns_get_record($site_host, DNS_A);
                if (is_array($dns_a)) {
                    foreach ($dns_a as $rec) {
                        if (!empty($rec['ip']) && filter_var($rec['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            $resolved_ips[] = $rec['ip'];
                        }
                    }
                }
                $dns_aaaa = @dns_get_record($site_host, DNS_AAAA);
                if (is_array($dns_aaaa)) {
                    foreach ($dns_aaaa as $rec) {
                        if (!empty($rec['ipv6']) && filter_var($rec['ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            $resolved_ips[] = $rec['ipv6'];
                        }
                    }
                }
            }

            // Method B: gethostbynamel / gethostbyname fallback
            if (empty($resolved_ips) && function_exists('gethostbynamel')) {
                $hosts = @gethostbynamel($site_host);
                if (is_array($hosts)) {
                    $resolved_ips = array_merge($resolved_ips, $hosts);
                }
            }
            if (empty($resolved_ips) && function_exists('gethostbyname')) {
                $single = @gethostbyname($site_host);
                if (!empty($single) && $single !== $site_host && filter_var($single, FILTER_VALIDATE_IP)) {
                    $resolved_ips[] = $single;
                }
            }

            $resolved_ips = array_values(array_unique(array_filter($resolved_ips)));

            // Extract IPv4 and IPv6 edge IPs
            foreach ($resolved_ips as $rip) {
                if (filter_var($rip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && empty($cdn_ipv4)) {
                    $cdn_ipv4 = $rip;
                }
                if (filter_var($rip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && empty($cdn_ipv6)) {
                    $cdn_ipv6 = $rip;
                }

                if (self::is_cloudflare_ip($rip)) {
                    $cdn_detected = true;
                    if ($cdn_provider === 'None (Direct Origin)') {
                        $cdn_provider = 'Cloudflare Anycast';
                    }
                }
            }

            // Assign primary CDN IP (prefer connecting raw peer if edge, or resolved IPv4, or resolved IPv6)
            if ($cdn_detected) {
                if (!empty($raw_peer) && (self::is_cloudflare_ip($raw_peer) || filter_var($raw_peer, FILTER_VALIDATE_IP))) {
                    $cdn_ip = $raw_peer;
                    if (filter_var($raw_peer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $cdn_ipv4 = $raw_peer;
                    } elseif (filter_var($raw_peer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $cdn_ipv6 = $raw_peer;
                    }
                } elseif (!empty($cdn_ipv4)) {
                    $cdn_ip = $cdn_ipv4;
                } elseif (!empty($cdn_ipv6)) {
                    $cdn_ip = $cdn_ipv6;
                } elseif (!empty($resolved_ips)) {
                    $cdn_ip = reset($resolved_ips);
                }
            }
        }

        // Contextual defaults when no CDN is active
        if (!$cdn_detected) {
            if ($is_local_host) {
                $cdn_ip = 'Local Dev (No CDN)';
            } else {
                $cdn_ip = 'Direct Connection';
            }
        } elseif ($cdn_ip === 'N/A') {
            $cdn_ip = $cdn_provider . ' Edge';
        }

        // 6. PHP RAM Limit & Process Allocation
        $raw_limit = ini_get('memory_limit') ?: '256M';
        $current_usage = memory_get_usage(true);
        $peak_usage = memory_get_peak_usage(true);
        $current_usage_mb = round($current_usage / (1024 * 1024), 1);
        $peak_usage_mb = round($peak_usage / (1024 * 1024), 1);

        // Shared hosting detection via server root path (without probing /proc or system directories)
        $is_shared_hosting = false;
        $hosting_env_label = 'Standard Web Hosting';
        $doc_root = isset($_SERVER['DOCUMENT_ROOT']) ? sanitize_text_field(wp_unslash($_SERVER['DOCUMENT_ROOT'])) : '';
        if (!empty($doc_root) && (strpos($doc_root, '/home/') !== false || strpos($doc_root, '/home2/') !== false || strpos($doc_root, '/vhosts/') !== false || strpos($doc_root, 'public_html') !== false)) {
            $is_shared_hosting = true;
            $hosting_env_label = 'cPanel Shared Hosting';
        }

        if ($raw_limit === '-1') {
            $display_limit = 'Unlimited (-1)';
            $free_str = 'Unlimited';
            $usage_percent = 5;
        } else {
            $display_limit = $raw_limit;
            $limit_bytes = 0;
            if (function_exists('wp_convert_hr_to_bytes')) {
                $limit_bytes = wp_convert_hr_to_bytes($raw_limit);
            } else {
                $value = trim($raw_limit);
                $last = strtolower($value[strlen($value) - 1]);
                $val = (int) $value;
                switch ($last) {
                    case 'g': $val *= 1024 * 1024 * 1024; break;
                    case 'm': $val *= 1024 * 1024; break;
                    case 'k': $val *= 1024; break;
                }
                $limit_bytes = $val;
            }
            $free_bytes = $limit_bytes > 0 ? max(0, $limit_bytes - $current_usage) : 0;
            $free_str = round($free_bytes / (1024 * 1024), 1) . ' MB';
            $usage_percent = ($limit_bytes > 0) ? min(100, round(($current_usage / $limit_bytes) * 100, 1)) : 0;
        }

        // 7. Developer Extras (Max Execution Time, Upload Limits, Execution User)
        $max_execution_time = ini_get('max_execution_time') ?: '30';
        $upload_max_filesize = ini_get('upload_max_filesize') ?: '32M';
        $post_max_size = ini_get('post_max_size') ?: '32M';
        $php_user = function_exists('get_current_user') ? get_current_user() : 'web-user';

        $auto_prepend = ini_get('auto_prepend_file');
        $waf_hook_mode = (!empty($auto_prepend) && strpos($auto_prepend, 'webcare') !== false)
            ? 'Early Prepend (auto_prepend_file)'
            : 'WordPress Runtime Filter (mu-plugin / action hook)';

        return [
            'linux_uname'          => $linux_uname_short,
            'linux_uname_full'     => $uname_full,
            'distro_name'          => $distro_name,
            'server_software'      => $server_software_raw,
            'server_software_type' => $server_software_type,
            'php_version'          => $php_version,
            'php_sapi'             => $php_sapi,
            'php_arch'             => $php_arch,
            'opcache_active'       => $opcache_active,
            'real_server_ip'       => $real_server_ip,
            'real_server_ipv4'     => $real_server_ipv4,
            'real_server_ipv6'     => $real_server_ipv6,
            'is_server_ip_private' => $is_server_ip_private,
            'cdn_available'        => $cdn_detected,
            'cdn_provider'         => $cdn_provider,
            'cdn_ip'               => $cdn_ip,
            'cdn_ipv4'             => $cdn_ipv4,
            'cdn_ipv6'             => $cdn_ipv6,
            'php_ram_limit'        => $display_limit,
            'php_ram_used'         => $current_usage_mb . ' MB',
            'php_ram_peak'         => $peak_usage_mb . ' MB',
            'php_ram_free'         => $free_str,
            'php_ram_percent'      => $usage_percent,
            'is_shared_hosting'    => $is_shared_hosting,
            'hosting_env_label'    => $hosting_env_label,
            'account_ram_limit'    => $is_shared_hosting ? 'cPanel Plan Limit (~1 GB)' : null,
            'max_execution_time'   => $max_execution_time . 's',
            'upload_max_filesize'  => $upload_max_filesize,
            'post_max_size'        => $post_max_size,
            'php_user'             => $php_user,
            'waf_hook_mode'        => $waf_hook_mode,
        ];
    }

    /**
     * Get recent blocked logs from daily JSON filesystem partitions
     */
    public static function get_logs(int $limit = 50, int $offset = 0, array $filters = []): array {
        return WafFileLogger::query_logs($filters, $limit, $offset);
    }

    /**
     * Get aggregate statistics and metrics for WAF logs dashboard
     */
    public static function get_log_stats(string $range = 'today'): array {
        return WafFileLogger::get_log_stats($range);
    }

    /**
     * Delete a single firewall incident log entry
     *
     * @param int|string $id
     */
    public static function delete_log($id): bool {
        return WafFileLogger::delete_log($id);
    }

    /**
     * Clear firewall logs
     */
    public static function clear_logs(): bool {
        return WafFileLogger::clear_all_logs();
    }

    /**
     * Option key for storing structured metadata for blocked IPs
     */
    const OPTION_BLOCKED_IPS_META = 'webcareproscan_blocked_ips_meta';

    /**
     * Retrieve all persistent block metadata for IPs
     */
    public static function get_all_block_meta(): array {
        $meta = get_option(self::OPTION_BLOCKED_IPS_META, []);
        return is_array($meta) ? $meta : [];
    }

    /**
     * Get block metadata for a specific IP
     */
    public static function get_ip_block_meta(string $ip): ?array {
        $meta = self::get_all_block_meta();
        return $meta[$ip] ?? null;
    }

    /**
     * Store or update metadata for a blocked IP
     */
    public static function set_ip_block_meta(string $ip, array $data): bool {
        $meta = self::get_all_block_meta();
        $existing = $meta[$ip] ?? [];
        $meta[$ip] = array_merge($existing, $data);
        return update_option(self::OPTION_BLOCKED_IPS_META, $meta, false);
    }

    /**
     * Delete block metadata for an unblocked IP
     */
    public static function delete_ip_block_meta(string $ip): bool {
        $meta = self::get_all_block_meta();
        if (isset($meta[$ip])) {
            unset($meta[$ip]);
            return update_option(self::OPTION_BLOCKED_IPS_META, $meta, false);
        }
        return false;
    }

    /**
     * Build a structured forensic note for Cloudflare IP Access Rules & Account Lists.
     *
     * Format: [WebCare-WAF] [WEBCARE-8F3A19C2] Rule:WAF-SQLI-INJECTION | Hit:POST /wp-admin/admin-ajax.php | Ev:... | TTL:24h
     *
     * @param string      $reason
     * @param string|null $rule_id
     * @param string|null $rule_category
     * @param string|null $incident_id
     * @param int         $duration_seconds
     * @param string|null $admin_user
     * @return string
     */
    public static function build_forensic_cf_note(
        string $reason,
        ?string $rule_id = null,
        ?string $rule_category = null,
        ?string $incident_id = null,
        int $duration_seconds = 86400,
        ?string $admin_user = null
    ): string {
        $method    = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'REQ';
        $raw_uri   = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $clean_uri = substr((string) preg_replace('/[\r\n\t\x00-\x1f]+/', '', $raw_uri), 0, 55);
        $ttl_label = $duration_seconds > 0 ? round($duration_seconds / 3600, 1) . 'h' : 'PERM';

        $parts = ['[WebCare-WAF]'];
        if (!empty($incident_id)) {
            $parts[] = '[' . preg_replace('/[^A-Za-z0-9_-]/', '', $incident_id) . ']';
        }
        if (!empty($rule_id)) {
            $parts[] = 'Rule:' . preg_replace('/[^A-Za-z0-9_-]/', '', $rule_id);
        } elseif (!empty($rule_category)) {
            $parts[] = 'Cat:' . substr(sanitize_text_field($rule_category), 0, 28);
        }
        if (!empty($admin_user)) {
            $parts[] = 'By:' . sanitize_user($admin_user, true);
        } else {
            $parts[] = "Hit:{$method} {$clean_uri}";
        }

        $clean_reason = trim((string) preg_replace('/^\[[^\]]+\]\s*/', '', $reason));
        if ($clean_reason !== '') {
            $parts[] = 'Ev:' . substr($clean_reason, 0, 75);
        }
        $parts[] = 'TTL:' . $ttl_label;

        return substr(implode(' | ', $parts), 0, 240);
    }

    /**
     * Add IP to custom blocklist with rich metadata
     *
     * @param string $ip IP address or CIDR subnet
     * @param string $reason Human-readable explanation or rule violation note
     * @param int $duration_seconds Ban duration in seconds (0 = permanent)
     * @param string|null $rule_id Unique rule identifier (e.g. 'WAF-FORBIDDEN-USERNAME')
     * @param string|null $rule_name Rule title
     * @param string|null $rule_category Rule category
     * @param string|null $incident_id Incident tracking ID (e.g. 'WEBCARE-80458BF3')
     * @param string|null $admin_user Username of administrator who added manual block
     * @return bool
     */
    public static function add_blocked_ip(
        string $ip,
        string $reason = '',
        int $duration_seconds = 0,
        ?string $rule_id = null,
        ?string $rule_name = null,
        ?string $rule_category = null,
        ?string $incident_id = null,
        ?string $admin_user = null,
        bool $sync_cloudflare = true
    ): bool {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP) && strpos($ip, '/') === false) {
            return false;
        }

        // Safety Guard 1: Never block local loopback IPs or server origin / Docker dev gateways
        if (in_array($ip, ['127.0.0.1', '::1'], true) || self::is_server_origin_or_loopback($ip)) {
            return false;
        }

        // Safety Guard 2: Refuse to add current administrator's active IP or whitelisted IP to custom blocklist
        $current_client_ip = self::get_client_ip();
        if ($ip === $current_client_ip && (self::is_authenticated_administrator() || self::is_authenticated_editor_or_builder())) {
            return false;
        }

        // Safety Guard 2b: Never ban an IP during a verified server-side Plugin Check / WP-CLI sandbox run
        if ($ip === $current_client_ip && self::is_trusted_plugin_check_or_cli_runtime()) {
            return false;
        }

        // Safety Guard 3: Immutable immunity for genuine search crawlers & uptime monitors.
        // Never allow automated honeypots or rules to inadvertently ban Googlebot, Bingbot, or verified monitors.
        if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            if (BotReconDefense::is_genuine_search_engine($ip, $user_agent)) {
                return false;
            }
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_blocked_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        if (!in_array($ip, $lines, true)) {
            $lines[] = $ip;
            $settings['waf_blocked_ips'] = implode("\n", $lines);
            SettingsManager::$suppress_firewall_ruleset_log = true;
            SettingsManager::save_settings($settings);
            SettingsManager::$suppress_firewall_ruleset_log = false;
        }

        // Persist structured metadata (enforce non-zero 24h default TTL on rule auto-bans)
        $now = time();
        $source = !empty($admin_user) ? 'manual_admin' : (!empty($rule_id) ? 'rule_auto_ban' : 'custom_blocklist');
        $effective_duration = ($source === 'rule_auto_ban' && $duration_seconds <= 0) ? 86400 : $duration_seconds;
        $expires_at = $effective_duration > 0 ? ($now + $effective_duration) : 0;

        self::set_ip_block_meta($ip, [
            'ip'               => $ip,
            'source'           => $source,
            'reason'           => !empty($reason) ? $reason : 'Blocked by security firewall policy',
            'duration_seconds' => $effective_duration,
            'blocked_at'       => $now,
            'expires_at'       => $expires_at,
            'rule_id'          => $rule_id,
            'rule_name'        => $rule_name,
            'rule_category'    => $rule_category,
            'incident_id'      => $incident_id,
            'admin_user'       => $admin_user,
        ]);

        // Context-Adaptive Firewall (CAF Phase 2): Queue IP ban for Cloudflare Edge synchronization
        if ($sync_cloudflare && class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            $forensic_note = self::build_forensic_cf_note(
                !empty($reason) ? $reason : 'Blocked by security firewall policy',
                $rule_id,
                $rule_category,
                $incident_id,
                $effective_duration,
                $admin_user
            );
            \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::queue_ip_ban(
                $ip,
                $forensic_note,
                $effective_duration > 0 ? $effective_duration : 86400
            );
        }

        return true;
    }

    /**
     * Compatibility alias for blocking an IP address (used by GhostRouteTrap / Bot Traps)
     *
     * @param string $ip
     * @param string $reason
     * @param int $duration_seconds
     * @return bool
     */
    public static function block_ip(string $ip, string $reason = '', int $duration_seconds = 0): bool {
        return self::add_blocked_ip($ip, $reason, $duration_seconds);
    }

    /**
     * Remove an IP or CIDR subnet from custom blocklist and clear any active temporary lockouts.
     * Restores normal visitor access with full WAF inspection protection active.
     *
     * @param string $ip
     * @return bool
     */
    public static function remove_blocked_ip(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        // 1. Remove from settings waf_blocked_ips
        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_blocked_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));
        $changed = false;

        $new_lines = [];
        foreach ($lines as $line) {
            $entry_ip = trim(preg_split('/[\s#]+/', $line)[0] ?? '');
            if ($entry_ip === $ip) {
                $changed = true;
                continue;
            }
            $new_lines[] = $line;
        }

        if ($changed) {
            $settings['waf_blocked_ips'] = implode("\n", $new_lines);
            SettingsManager::$suppress_firewall_ruleset_log = true;
            SettingsManager::save_settings($settings);
            SettingsManager::$suppress_firewall_ruleset_log = false;
        }

        // 2. Unlock from Login Hardening if locked
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
            \WebCareProScanner\Auth\LoginHardening::unlock_ip($ip);
        }

        // 3. Clear any active 404 lockout transients and WooCommerce checkout/coupon rate locks
        delete_transient('webcareproscan_404_lock_' . md5($ip));
        delete_transient('webcareproscan_404_cnt_' . md5($ip));
        delete_transient('webcareproscan_cpn_lock_' . md5($ip));
        delete_transient('webcareproscan_cpn_fail_' . md5($ip));
        delete_transient('webcareproscan_chk_lock_' . md5($ip));
        delete_transient('webcareproscan_chk_fail_' . md5($ip));
        delete_transient('webcareproscan_scrape_lock_' . md5($ip));
        delete_transient('webcareproscan_scrape_vel_' . md5($ip));
        delete_transient('webcareproscan_bot_ban_' . md5($ip));

        // 4. Clean up block metadata & lockout references
        self::delete_ip_block_meta($ip);
        delete_transient('webcareproscan_lockout_ip_' . md5($ip));

        // 5. Bi-Directional Cloudflare Unban Sync: Remove from Cloudflare Edge and queue
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::unban_ip_immediately($ip);
        }

        return true;
    }

    /**
     * Retrieve aggregated list of all currently locked or custom-blocked IPs across engines with rich forensics.
     *
     * @return array
     */
    public static function get_all_locked_ips(): array {
        $results = [];
        $settings = SettingsManager::get_settings();
        $all_meta = self::get_all_block_meta();
        $now = time();

        // 1. Custom WAF Blocklisted IPs
        $blocked_raw = trim($settings['waf_blocked_ips'] ?? '');
        $seen_ips = [];

        if (!empty($blocked_raw)) {
            $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $blocked_raw))));
            foreach ($lines as $ip) {
                $seen_ips[$ip] = true;
                $meta = $all_meta[$ip] ?? null;

                // Correlate with recent WAF logs if incident ID or detailed reason is missing
                $recent_logs = [];
                $last_incident_id = $meta['incident_id'] ?? null;
                $detected_rule = $meta['rule_name'] ?? null;
                $detected_cat = $meta['rule_category'] ?? null;
                $detected_desc = null;
                $log_first_seen = null;
                $log_last_seen = null;

                if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
                    $log_query = WafFileLogger::query_logs(['ip' => $ip], 3);
                    if (!empty($log_query['logs'])) {
                        $recent_logs = array_map(function($l) {
                            return [
                                'incident_id' => $l['incident_id'] ?? null,
                                'created_at'  => $l['created_at'] ?? null,
                                'category'    => $l['rule_category'] ?? null,
                                'description' => $l['rule_description'] ?? null,
                                'uri'         => $l['request_uri'] ?? null,
                                'method'      => $l['request_method'] ?? 'GET',
                                'status'      => $l['http_status_code'] ?? 403,
                                'user_agent'  => $l['user_agent'] ?? null,
                                'payload'     => $l['payload_sample'] ?? null,
                            ];
                        }, $log_query['logs']);

                        $top_log = $log_query['logs'][0];
                        if (empty($last_incident_id)) {
                            $last_incident_id = $top_log['incident_id'] ?? null;
                        }
                        if (empty($detected_rule)) {
                            $detected_rule = $top_log['rule_description'] ?? 'Malicious Request';
                        }
                        if (empty($detected_cat)) {
                            $detected_cat = $top_log['rule_category'] ?? 'Security Firewall';
                        }
                        $detected_desc = $top_log['rule_description'] ?? null;
                        $log_last_seen = $top_log['created_at'] ?? null;
                    }
                }

                $blocked_ts = !empty($meta['blocked_at']) ? (int) $meta['blocked_at'] : null;
                $expires_ts = !empty($meta['expires_at']) ? (int) $meta['expires_at'] : 0;
                $duration_secs = !empty($meta['duration_seconds']) ? (int) $meta['duration_seconds'] : 0;
                $admin_user = $meta['admin_user'] ?? null;
                $source = $meta['source'] ?? (!empty($admin_user) ? 'manual_admin' : 'custom_blocklist');

                // Determine Badge & Human-Readable Reason
                if ($source === 'manual_admin') {
                    $badge = 'Custom Admin Block';
                    $reason = !empty($meta['reason']) ? $meta['reason'] : sprintf('Blocked manually by administrator "%s"', $admin_user ?: 'admin');
                } elseif (!empty($detected_rule)) {
                    $badge = !empty($meta['rule_name']) ? $meta['rule_name'] : 'Firewall Violation';
                    $reason = !empty($meta['reason']) ? $meta['reason'] : ($detected_desc ?: 'Malicious activity blocked by security firewall policy');
                } else {
                    $badge = 'Custom Blocklist';
                    $reason = !empty($meta['reason']) ? $meta['reason'] : 'Permanently blocked by administrator policy';
                }

                // Timing & Duration Breakdown
                $timing = self::calculate_ban_timing($blocked_ts, $expires_ts, $duration_secs, $log_last_seen);

                $results[] = [
                    'ip'               => $ip,
                    'incident_id'      => $last_incident_id,
                    'type'             => $source,
                    'badge'            => $badge,
                    'rule_id'          => $meta['rule_id'] ?? null,
                    'rule_name'        => $detected_rule,
                    'rule_category'    => $detected_cat,
                    'reason'           => $reason,
                    'admin_user'       => $admin_user,
                    'admin_note'       => $meta['admin_note'] ?? null,
                    'blocked_at'       => $timing['ban_time'],
                    'blocked_at_raw'   => $timing['effective_ts'],
                    'ban_ago'          => $timing['ban_ago'],
                    'duration'         => $timing['duration'],
                    'duration_seconds' => $duration_secs,
                    'expires_at'       => $timing['unban_time'],
                    'expires_at_raw'   => $expires_ts,
                    'time_remaining'   => $timing['time_remaining'],
                    'countdown'        => $timing['countdown'],
                    'is_expired'       => $timing['is_expired'],
                    'is_permanent'     => $timing['is_permanent'],
                    'recent_history'   => $recent_logs,
                ];
            }
        }

        // 2. Brute-Force Login Hardening Lockouts
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
            $lockouts = \WebCareProScanner\Auth\LoginHardening::get_locked_ips();
            foreach ($lockouts as $ip => $data) {
                $expires_ts = $data['expires_at'] ?? 0;
                $blocked_raw = $data['blocked_at'] ?? null;
                $blocked_ts = !empty($blocked_raw) ? strtotime($blocked_raw) : null;
                $duration_secs = ($expires_ts > $blocked_ts && $blocked_ts > 0) ? ($expires_ts - $blocked_ts) : 900;

                // Correlate recent log history for brute-force IP
                $recent_logs = [];
                $last_incident_id = null;
                if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
                    $log_query = WafFileLogger::query_logs(['ip' => $ip], 3);
                    if (!empty($log_query['logs'])) {
                        $recent_logs = array_map(function($l) {
                            return [
                                'incident_id' => $l['incident_id'] ?? null,
                                'created_at'  => $l['created_at'] ?? null,
                                'category'    => $l['rule_category'] ?? null,
                                'description' => $l['rule_description'] ?? null,
                                'uri'         => $l['request_uri'] ?? null,
                                'method'      => $l['request_method'] ?? 'POST',
                                'status'      => $l['http_status_code'] ?? 403,
                                'user_agent'  => $l['user_agent'] ?? null,
                                'payload'     => $l['payload_sample'] ?? null,
                            ];
                        }, $log_query['logs']);
                        $last_incident_id = $log_query['logs'][0]['incident_id'] ?? null;
                    }
                }

                $timing = self::calculate_ban_timing($blocked_ts, $expires_ts, $duration_secs);

                // If already listed under custom blocklist, merge brute-force details
                $exists_idx = null;
                foreach ($results as $idx => $r) {
                    if ($r['ip'] === $ip) {
                        $exists_idx = $idx;
                        break;
                    }
                }

                $bf_item = [
                    'ip'               => $ip,
                    'incident_id'      => $last_incident_id,
                    'type'             => 'login_bruteforce',
                    'badge'            => 'Login Hardening',
                    'rule_id'          => 'WAF-LOGIN-BRUTEFORCE',
                    'rule_name'        => 'Login Brute-Force Rate Limiter',
                    'rule_category'    => 'Authentication Defense',
                    'reason'           => sprintf('Failed %d password attempts (user: "%s")', $data['attempts'] ?? 0, esc_html($data['username'] ?? 'unknown')),
                    'admin_user'       => null,
                    'admin_note'       => null,
                    'blocked_at'       => $timing['ban_time'],
                    'blocked_at_raw'   => $timing['effective_ts'],
                    'ban_ago'          => $timing['ban_ago'],
                    'duration'         => $timing['duration'],
                    'duration_seconds' => $duration_secs,
                    'expires_at'       => $timing['unban_time'],
                    'expires_at_raw'   => $expires_ts,
                    'time_remaining'   => $timing['time_remaining'],
                    'countdown'        => $timing['countdown'],
                    'is_expired'       => $timing['is_expired'],
                    'is_permanent'     => $timing['is_permanent'],
                    'recent_history'   => $recent_logs,
                ];

                if ($exists_idx !== null) {
                    // Update the custom blocklist card with incident details & brute-force note if higher severity
                    if (!empty($last_incident_id) && empty($results[$exists_idx]['incident_id'])) {
                        $results[$exists_idx]['incident_id'] = $last_incident_id;
                    }
                    if (!empty($recent_logs) && empty($results[$exists_idx]['recent_history'])) {
                        $results[$exists_idx]['recent_history'] = $recent_logs;
                    }
                } else {
                    $results[] = $bf_item;
                }
            }
        }

        // 3. Sort all blocked & locked IPs descending by latest ban timestamp so the latest banned IP appears first
        usort($results, function($a, $b) {
            $ts_a = isset($a['blocked_at_raw']) && is_numeric($a['blocked_at_raw']) ? (int) $a['blocked_at_raw'] : 0;
            $ts_b = isset($b['blocked_at_raw']) && is_numeric($b['blocked_at_raw']) ? (int) $b['blocked_at_raw'] : 0;
            return $ts_b <=> $ts_a;
        });

        return $results;
    }

    /**
     * Compute comprehensive human-readable ban timing, countdown, and duration breakdown.
     *
     * @param int|null $blocked_ts
     * @param int $expires_ts
     * @param int $duration_secs
     * @param string|null $fallback_last_seen
     * @return array
     */
    public static function calculate_ban_timing(?int $blocked_ts, int $expires_ts, int $duration_secs, ?string $fallback_last_seen = null): array {
        $now = time();

        $effective_ts = 0;
        if ($blocked_ts && $blocked_ts > 0) {
            $effective_ts = $blocked_ts;
            $ban_time = gmdate('M j, Y, g:i a \U\T\C', $blocked_ts);
            $seconds_ago = max(0, $now - $blocked_ts);
            $ban_ago = self::format_seconds_human($seconds_ago) . ' ago';
        } elseif ($fallback_last_seen) {
            $ts = strtotime($fallback_last_seen);
            $effective_ts = $ts ?: 0;
            $ban_time = gmdate('M j, Y, g:i a \U\T\C', $ts);
            $ban_ago = self::format_seconds_human(max(0, $now - $ts)) . ' ago';
        } else {
            $effective_ts = 0;
            $ban_time = 'Unknown (Active Policy)';
            $ban_ago = 'Previously Recorded';
        }

        // 2. Duration & Expiration
        $is_permanent = ($expires_ts <= 0 || $duration_secs === 0);
        if ($is_permanent) {
            $duration = 'Permanent';
            $unban_time = 'Never (Permanent)';
            $time_remaining = 'Permanent Policy';
            $is_expired = false;
            $countdown = [
                'years'   => 0,
                'months'  => 0,
                'days'    => 0,
                'hours'   => 0,
                'minutes' => 0,
                'seconds' => 0,
            ];
        } else {
            $duration = self::format_duration_label($duration_secs);
            $unban_time = gmdate('M j, Y, g:i a \U\T\C', $expires_ts);
            $diff = $expires_ts - $now;

            if ($diff <= 0) {
                $is_expired = true;
                $time_remaining = 'Expired';
                $countdown = [
                    'years'   => 0,
                    'months'  => 0,
                    'days'    => 0,
                    'hours'   => 0,
                    'minutes' => 0,
                    'seconds' => 0,
                ];
            } else {
                $is_expired = false;
                $countdown = self::breakdown_seconds($diff);
                $time_remaining = self::format_countdown_human($countdown);
            }
        }

        return [
            'effective_ts'   => $effective_ts,
            'ban_time'       => $ban_time,
            'ban_ago'        => $ban_ago,
            'duration'       => $duration,
            'unban_time'     => $unban_time,
            'time_remaining' => $time_remaining,
            'countdown'      => $countdown,
            'is_expired'     => $is_expired,
            'is_permanent'   => $is_permanent,
        ];
    }

    /**
     * Break down seconds into years, months, days, hours, minutes, seconds.
     *
     * @param int $seconds
     * @return array
     */
    public static function breakdown_seconds(int $seconds): array {
        $seconds = max(0, $seconds);
        $years   = (int) floor($seconds / (365 * 86400));
        $seconds %= (365 * 86400);

        $months  = (int) floor($seconds / (30 * 86400));
        $seconds %= (30 * 86400);

        $days    = (int) floor($seconds / 86400);
        $seconds %= 86400;

        $hours   = (int) floor($seconds / 3600);
        $seconds %= 3600;

        $minutes = (int) floor($seconds / 60);
        $sec     = $seconds % 60;

        return [
            'years'   => $years,
            'months'  => $months,
            'days'    => $days,
            'hours'   => $hours,
            'minutes' => $minutes,
            'seconds' => $sec,
        ];
    }

    /**
     * Format structured countdown into clear human words (e.g. "1 year, 2 months, 5 days, 4 hours, 10 mins").
     */
    public static function format_countdown_human(array $c): string {
        $parts = [];
        if (!empty($c['years'])) {
            $parts[] = $c['years'] . ($c['years'] === 1 ? ' yr' : ' yrs');
        }
        if (!empty($c['months'])) {
            $parts[] = $c['months'] . ($c['months'] === 1 ? ' mo' : ' mos');
        }
        if (!empty($c['days'])) {
            $parts[] = $c['days'] . ($c['days'] === 1 ? ' day' : ' days');
        }
        if (!empty($c['hours'])) {
            $parts[] = $c['hours'] . ($c['hours'] === 1 ? ' hr' : ' hrs');
        }
        if (!empty($c['minutes'])) {
            $parts[] = $c['minutes'] . ' mins';
        }
        if (empty($parts)) {
            $parts[] = max(1, $c['seconds'] ?? 0) . ' secs';
        }

        return implode(', ', $parts) . ' left';
    }

    /**
     * Format duration into standard human label.
     */
    public static function format_duration_label(int $seconds): string {
        if ($seconds >= 365 * 86400) {
            $y = (int) round($seconds / (365 * 86400));
            return $y . ($y === 1 ? ' Year' : ' Years');
        }
        if ($seconds >= 30 * 86400) {
            $m = (int) round($seconds / (30 * 86400));
            return $m . ($m === 1 ? ' Month' : ' Months');
        }
        if ($seconds >= 86400) {
            $d = (int) round($seconds / 86400);
            return $d . ($d === 1 ? ' Day' : ' Days');
        }
        if ($seconds >= 3600) {
            $h = (int) round($seconds / 3600);
            return $h . ($h === 1 ? ' Hour' : ' Hours');
        }
        $mins = (int) round($seconds / 60);
        return $mins . ($mins === 1 ? ' Minute' : ' Minutes');
    }

    /**
     * Format elapsed seconds into human string (e.g. "5 mins", "2 hours", "4 days").
     */
    public static function format_seconds_human(int $seconds): string {
        if ($seconds < 60) {
            return $seconds . ' secs';
        }
        if ($seconds < 3600) {
            $m = (int) floor($seconds / 60);
            return $m . ($m === 1 ? ' min' : ' mins');
        }
        if ($seconds < 86400) {
            $h = (int) floor($seconds / 3600);
            return $h . ($h === 1 ? ' hr' : ' hrs');
        }
        $d = (int) floor($seconds / 86400);
        return $d . ($d === 1 ? ' day' : ' days');
    }

    /**
     * Retrieve complete catalog of inspectable firewall rules and category groups
     *
     * @return array
     */
    public static function get_firewall_rules_catalog(): array {
        return [
            // Incident Containment & Upgrades
            ['id' => 'WAF-CONTAINMENT-LOCKDOWN', 'name' => 'Emergency Containment Write Lockdown', 'category' => 'Incident Containment', 'description' => 'Write operations are strictly prohibited while site is in Emergency Containment Mode.'],
            ['id' => 'WAF-CONTAINMENT-SURFACE-LOCK', 'name' => 'Emergency Containment Attack Surface Lock', 'category' => 'Incident Containment', 'description' => 'Endpoint locked down by Emergency Containment Mode.'],
            ['id' => 'WAF-ATOMIC-UPGRADE-LOCK', 'name' => 'Atomic Upgrade Lock Route Shield', 'category' => 'Supply Chain Defense', 'description' => 'Target resource is locked against unauthenticated access during an active software update.'],

            // Context-Adaptive & Dormant Surface
            ['id' => 'WAF-CAF-DORMANT-SURFACE', 'name' => 'Context-Adaptive Dormant Attack Surface Lockdown', 'category' => 'Dormant Surface Shield', 'description' => 'Direct requests to deactivated plugins are strictly blocked.'],
            ['id' => 'WAF-CAF-DORMANT-THEME', 'name' => 'Context-Adaptive Dormant Theme Surface Lockdown', 'category' => 'Dormant Surface Shield', 'description' => 'Direct requests to inactive themes are strictly blocked.'],

            // DoS, Buffer & Resource Floods
            ['id' => 'WAF-OVERSIZED-URI', 'name' => 'Oversized URI Buffer Overflow Guard', 'category' => 'DoS & Resource Shield', 'description' => 'Request URI length exceeded security buffer threshold.'],
            ['id' => 'WAF-OVERSIZED-QUERY', 'name' => 'Oversized Query String Guard', 'category' => 'DoS & Resource Shield', 'description' => 'Query string length exceeded security threshold.'],
            ['id' => 'WAF-OVERSIZED-POST-VARS', 'name' => 'Excessive Parameter Count Flood Guard', 'category' => 'DoS & Resource Shield', 'description' => 'POST payload exceeds recursive parameter threshold.'],
            ['id' => 'WAF-ADMIN-AJAX-BURST', 'name' => 'admin-ajax.php Burst Flood Limit Exceeded', 'category' => 'DoS & Resource Shield', 'description' => 'Unauthenticated client exceeded rate threshold on admin-ajax.php.'],
            ['id' => 'WAF-EXTERNAL-CRON-BLOCK', 'name' => 'External wp-cron.php Abuse Block', 'category' => 'DoS & Resource Shield', 'description' => 'External HTTP trigger to wp-cron.php blocked to prevent resource exhaustion.'],

            // Protocol, Header & Transport Defense
            ['id' => 'WAF-HOST-HEADER-POISON', 'name' => 'Host Header Poisoning & Cache Spoof Defense', 'category' => 'Protocol Defense', 'description' => 'HTTP Host header spoofing and poisoning attempt intercepted.'],
            ['id' => 'WAF-UNSAFE-HTTP-METHOD', 'name' => 'Unsafe HTTP Method Block', 'category' => 'Protocol Defense', 'description' => 'Unsafe or dangerous HTTP verbs (TRACE, TRACK, CONNECT, DEBUG) rejected.'],
            ['id' => 'WAF-UNAUTHORIZED-PUT-UPLOAD', 'name' => 'Unauthorized HTTP PUT File Upload Guard', 'category' => 'Protocol Defense', 'description' => 'Direct HTTP PUT file modification attempt blocked.'],
            ['id' => 'WAF-GUEST-AJAX-EMPTY', 'name' => 'Guest Endpoint Missing Action Probe', 'category' => 'Protocol Defense', 'description' => 'Unauthenticated empty action request to AJAX handler rejected.'],

            // Bot & Scraping Defense
            ['id' => 'WAF-EMPTY-POST-UA-REFERER', 'name' => 'Blank User-Agent & Referer POST Block', 'category' => 'Bot Defense', 'description' => 'Automated bot POST with empty User-Agent and Referer headers dropped.'],

            // File Reconnaissance & Path Traversal
            ['id' => 'WAF-SENSITIVE-FILE-PROBE', 'name' => 'Sensitive File & Backup Probe Block', 'category' => 'File Reconnaissance', 'description' => 'Probing for .git, .env, wp-config backups, or SQL dumps blocked.'],
            ['id' => 'WAF-PATH-TRAVERSAL', 'name' => 'Path Traversal & LFI/RFI File Inclusion Armor', 'category' => 'Path Traversal', 'description' => 'Directory traversal (../, ..\\) and system file inclusion (/etc/passwd, php://filter) intercepted.'],

            // Core Web Exploits & Injection Armor
            ['id' => 'WAF-SQLI-ARMOR', 'name' => 'SQL Injection (SQLi) Heuristic Armor', 'category' => 'SQL Injection', 'description' => 'Malicious SQL exploitation signatures (UNION SELECT, benchmark, sleep) dropped.'],
            ['id' => 'WAF-PHP-CODE-INJECTION', 'name' => 'PHP Code Injection & Web Shell Shield', 'category' => 'PHP Code Injection', 'description' => 'Direct PHP script tag or dangerous execution function payload blocked.'],
            ['id' => 'WAF-XSS-ARMOR', 'name' => 'Cross-Site Scripting (XSS) Sanitization Guard', 'category' => 'Cross-Site Scripting (XSS)', 'description' => 'Hostile JavaScript injection, malicious SVG, or payload script tag dropped.'],
            ['id' => 'WAF-OBJECT-STREAM-INJECTION', 'name' => 'PHP Object Injection & Stream Wrapper Shield', 'category' => 'Execution Armor', 'description' => 'Serialized object payload or dangerous stream wrapper (phar://) blocked.'],
            ['id' => 'WAF-UPLOADS-PHP-DENY', 'name' => 'Uploads Directory PHP Execution Deny', 'category' => 'Execution Armor', 'description' => 'Direct PHP script execution inside uploads directory strictly blocked.'],

            // Security Policy & Hardening
            ['id' => 'WAF-XMLRPC-DISABLED', 'name' => 'XML-RPC Access Prohibited', 'category' => 'XML-RPC Disabled', 'description' => 'XML-RPC invocation blocked by administrator security policy.'],
            ['id' => 'WAF-DISALLOW-PHPMYADMIN-PLUGIN', 'name' => 'Prohibited Database Manager Plugin Installation', 'category' => 'Security Policy Enforcement', 'description' => 'Ad-hoc web database manager plugins are prohibited.'],
            ['id' => 'WAF-DISALLOW-FILEMANAGER-PLUGIN', 'name' => 'Prohibited File Manager Plugin Installation', 'category' => 'Security Policy Enforcement', 'description' => 'Web file manager plugins are prohibited on production environments.'],
            ['id' => 'WAF-INSTALL-LOCKDOWN', 'name' => 'WordPress Installer Lockdown', 'category' => 'Hardening Defense', 'description' => 'Access to install.php/upgrade.php blocked on established site.'],

            // AI & Prompt Injection
            ['id' => 'WAF-AI-PROMPT-INJECTION', 'name' => 'AI Prompt Injection & Agent Poisoning Shield', 'category' => 'AI & Agent Defense', 'description' => 'Hostile prompt injection, jailbreak syntax, and agent poisoning patterns neutralized.'],

            // Identity, Honeypots & Reconnaissance
            ['id' => 'WAF-FORBIDDEN-USERNAME-TRAP', 'name' => 'Forbidden Honeypot Username Trap', 'category' => 'Identity Defense', 'description' => 'Authentication attempt using trap usernames (admin, root) blocked.'],
            ['id' => 'WAF-REST-USER-ENUM', 'name' => 'REST API User Enumeration Interceptor', 'category' => 'Reconnaissance & Enumeration', 'description' => 'Unauthenticated user enumeration on /wp/v2/users intercepted.'],
            ['id' => 'WAF-AUTHOR-ENUM', 'name' => 'Author Permalink Enumeration Suppression', 'category' => 'Reconnaissance & Enumeration', 'description' => 'Author scan attempts (?author=1) deflected.'],
            ['id' => 'WAF-LOSTPW-VIEW-FLOOD', 'name' => 'Lost-Password View Burst Limit Exceeded', 'category' => 'Brute Force & Auth Armor', 'description' => 'Excessive views on lost password endpoint throttled.'],
            ['id' => 'WAF-LOSTPW-FLOOD-IP', 'name' => 'Lost-Password Request Flood Limit (IP)', 'category' => 'Brute Force & Auth Armor', 'description' => 'Too many password reset requests originating from this IP.'],
            ['id' => 'WAF-LOSTPW-FLOOD-USER', 'name' => 'Lost-Password Target User Bombing Guard', 'category' => 'Brute Force & Auth Armor', 'description' => 'Too many reset attempts targeting a single account identifier.'],

            // Behavioral & Unauthenticated API Defense
            ['id' => 'WAF-GUEST-AJAX-PROBE', 'name' => 'Unregistered Guest Action Probe', 'category' => 'Behavioral Defense', 'description' => 'Probing unregistered AJAX action hooks blocked.'],
            ['id' => 'WAF-GUEST-REST-BATCH-MUTATION', 'name' => 'Unauthenticated REST Batch Mutation Probe', 'category' => 'Behavioral Defense', 'description' => 'Batch modification probes on REST API blocked.'],
            ['id' => 'WAF-GUEST-REST-MUTATION', 'name' => 'Unauthenticated REST API Mutation Probe', 'category' => 'Behavioral Defense', 'description' => 'Direct unauthenticated POST/PUT/DELETE mutations to REST endpoints blocked.'],

            // WooCommerce & E-Commerce Defenses
            ['id' => 'WAF-WOO-CARDING-BLOCKED', 'name' => 'WooCommerce Carding Attack & Checkout Velocity Mitigation', 'category' => 'Behavioral Defense', 'description' => 'Rapid card testing and checkout bot spray blocked.'],
            ['id' => 'WAF-WOO-CARDING-THRESHOLD', 'name' => 'WooCommerce Carding Velocity Threshold Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Excessive failed checkouts from this IP address.'],
            ['id' => 'WAF-WOO-COUPON-BLOCKED', 'name' => 'WooCommerce Coupon Enumeration & Brute-Force Shield', 'category' => 'Behavioral Defense', 'description' => 'Dictionary attack on coupon codes intercepted.'],
            ['id' => 'WAF-WOO-COUPON-THRESHOLD', 'name' => 'WooCommerce Coupon Velocity Threshold Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Coupon testing threshold breached.'],
            ['id' => 'WAF-WOO-REG-DISPOSABLE-EMAIL', 'name' => 'WooCommerce Disposable Email Registration Block', 'category' => 'Behavioral Defense', 'description' => 'Customer registration using disposable/throwaway domain blocked.'],
            ['id' => 'WAF-WOO-REG-VELOCITY-BLOCKED', 'name' => 'WooCommerce Customer Registration Velocity Limit', 'category' => 'Behavioral Defense', 'description' => 'Excessive new customer account creations from this IP.'],
            ['id' => 'WAF-WOO-CART-VELOCITY-BLOCKED', 'name' => 'WooCommerce Cart Flooding Velocity Limit', 'category' => 'Behavioral Defense', 'description' => 'Denial of inventory cart manipulation blocked.'],
            ['id' => 'WAF-WOO-INVENTORY-HOARDING', 'name' => 'WooCommerce Denial of Inventory Cap Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Mass cart abandonment holding stock captive blocked.'],
            ['id' => 'WAF-WOO-SCRAPING-BLOCKED', 'name' => 'WooCommerce Catalog & Price Scraping Mitigation', 'category' => 'Behavioral Defense', 'description' => 'Aggressive automated catalog pricing scraping blocked.'],
            ['id' => 'WAF-WOO-SCRAPING-THRESHOLD', 'name' => 'WooCommerce Catalog Scraping Threshold Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Product view request rate exceeded scraping threshold.'],

            // Runtime RASP Protections
            ['id' => 'WAF-RASP-OPTION-TAMPER', 'name' => 'Runtime Option Tampering Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Runtime tampering of core site options (siteurl, home) intercepted.'],
            ['id' => 'WAF-RASP-ROLE-ESCALATION', 'name' => 'Runtime Privilege Escalation Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Unauthorized promotion of user capabilities intercepted.'],
            ['id' => 'WAF-RASP-ADMIN-REG-BLOCKED', 'name' => 'Runtime Administrator Registration Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Unauthorized account creation with administrator privileges blocked.'],
            ['id' => 'WAF-RASP-META-INJECTION', 'name' => 'Runtime User Meta Injection Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Hostile user meta manipulation targeting wp_capabilities blocked.'],
        ];
    }

    /**
     * Map rule IDs to their human-readable title
     *
     * @param array $rule_ids
     * @return array
     */
    public static function resolve_rule_names(array $rule_ids): array {
        static $catalog_map = null;
        if ($catalog_map === null) {
            $catalog_map = [];
            foreach (self::get_firewall_rules_catalog() as $rule) {
                $catalog_map[$rule['id']] = $rule['name'];
            }
        }

        $names = [];
        foreach ($rule_ids as $id) {
            $names[$id] = $catalog_map[$id] ?? $id;
        }
        return $names;
    }

    /**
     * Option key for storing structured metadata for whitelisted IPs
     */
    const OPTION_WHITELISTED_IPS_META = 'webcareproscan_whitelisted_ips_meta';

    /**
     * Retrieve all persistent whitelist metadata for IPs
     */
    public static function get_all_whitelist_meta(): array {
        $meta = get_option(self::OPTION_WHITELISTED_IPS_META, []);
        return is_array($meta) ? $meta : [];
    }

    /**
     * Get whitelist metadata for a specific IP
     */
    public static function get_ip_whitelist_meta(string $ip): ?array {
        $meta = self::get_all_whitelist_meta();
        return $meta[$ip] ?? null;
    }

    /**
     * Store or update metadata for a whitelisted IP
     */
    public static function set_ip_whitelist_meta(string $ip, array $data): bool {
        $meta = self::get_all_whitelist_meta();
        $existing = $meta[$ip] ?? [];
        $meta[$ip] = array_merge($existing, $data);
        return update_option(self::OPTION_WHITELISTED_IPS_META, $meta, false);
    }

    /**
     * Delete whitelist metadata for an un-whitelisted IP
     */
    public static function delete_ip_whitelist_meta(string $ip): bool {
        $meta = self::get_all_whitelist_meta();
        if (isset($meta[$ip])) {
            unset($meta[$ip]);
            return update_option(self::OPTION_WHITELISTED_IPS_META, $meta, false);
        }
        return false;
    }

    /**
     * Add IP to custom whitelist with structured metadata and granular rule/category scoping.
     *
     * @param string      $ip          The IPv4, IPv6, or CIDR address.
     * @param string      $reason      Human-readable justification.
     * @param string|null $admin_user  The administrator login performing the action.
     * @param array       $scope_args  Granular scoping parameters:
     *                                 [
     *                                   'scope'         => 'rule'|'category'|'global',
     *                                   'allowed_rules' => string[],
     *                                   'allowed_cats'  => string[],
     *                                   'endpoint'      => string,
     *                                   'expires_in'    => int (seconds, 0 for permanent)
     *                                 ]
     * @return bool
     */
    public static function add_whitelisted_ip(string $ip, string $reason = '', ?string $admin_user = null, array $scope_args = []): bool {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP) && strpos($ip, '/') === false) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_whitelisted_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        if (!in_array($ip, $lines, true)) {
            $lines[] = $ip;
            $settings['waf_whitelisted_ips'] = implode("\n", $lines);
            SettingsManager::save_settings($settings);
        }

        $now = time();
        $scope = isset($scope_args['scope']) && in_array($scope_args['scope'], ['rule', 'category', 'global'], true)
            ? $scope_args['scope']
            : 'global';

        $allowed_rules = !empty($scope_args['allowed_rules']) && is_array($scope_args['allowed_rules'])
            ? array_map('sanitize_text_field', $scope_args['allowed_rules'])
            : [];

        $allowed_cats = !empty($scope_args['allowed_cats']) && is_array($scope_args['allowed_cats'])
            ? array_map('sanitize_text_field', $scope_args['allowed_cats'])
            : [];

        $endpoint = !empty($scope_args['endpoint']) ? sanitize_text_field($scope_args['endpoint']) : '';
        $expires_in = isset($scope_args['expires_in']) ? max(0, (int) $scope_args['expires_in']) : 0;
        $expires_at = $expires_in > 0 ? ($now + $expires_in) : 0;

        self::set_ip_whitelist_meta($ip, [
            'ip'            => $ip,
            'reason'        => !empty($reason) ? $reason : 'Trusted access policy approved by administrator',
            'added_at'      => $now,
            'added_by'      => !empty($admin_user) ? $admin_user : 'admin',
            'type'          => !empty($admin_user) ? 'manual_admin' : 'custom_whitelist',
            'scope'         => $scope,
            'allowed_rules' => $allowed_rules,
            'allowed_cats'  => $allowed_cats,
            'endpoint'      => $endpoint,
            'expires_at'    => $expires_at,
        ]);

        return true;
    }

    /**
     * Remove IP from custom whitelist
     */
    public static function remove_whitelisted_ip(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_whitelisted_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        $new_lines = [];
        $removed = false;
        foreach ($lines as $line) {
            if ($line === $ip) {
                $removed = true;
                continue;
            }
            $new_lines[] = $line;
        }

        if ($removed) {
            $settings['waf_whitelisted_ips'] = implode("\n", $new_lines);
            SettingsManager::save_settings($settings);
        }

        self::delete_ip_whitelist_meta($ip);
        return true;
    }

    /**
     * Get all whitelisted IPs with rich forensic metadata
     */
    public static function get_all_whitelisted_ips(): array {
        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_whitelisted_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));
        $all_meta = self::get_all_whitelist_meta();
        $now = time();

        $results = [];
        foreach ($lines as $ip) {
            $meta = $all_meta[$ip] ?? null;
            $added_at_ts = $meta['added_at'] ?? null;
            $added_at_formatted = $added_at_ts ? gmdate('M j, Y, g:i a \U\T\C', $added_at_ts) : 'Previously added';
            $added_ago = $added_at_ts ? self::format_seconds_human(max(0, $now - $added_at_ts)) . ' ago' : 'active';
            $expires_at = !empty($meta['expires_at']) ? (int) $meta['expires_at'] : 0;
            $is_expired = $expires_at > 0 && $now > $expires_at;

            $results[] = [
                'ip'                 => $ip,
                'reason'             => !empty($meta['reason']) ? $meta['reason'] : 'Trusted administrative access policy',
                'added_at'           => $added_at_formatted,
                'added_at_raw'       => $added_at_ts,
                'added_ago'          => $added_ago,
                'added_by'           => !empty($meta['added_by']) ? $meta['added_by'] : 'administrator',
                'type'               => !empty($meta['type']) ? $meta['type'] : 'manual_admin',
                'require_admin'      => !empty($settings['waf_whitelist_require_admin']),
                'scope'              => !empty($meta['scope']) ? $meta['scope'] : 'global',
                'allowed_rules'      => !empty($meta['allowed_rules']) ? (array) $meta['allowed_rules'] : [],
                'allowed_rule_names' => !empty($meta['allowed_rules']) ? self::resolve_rule_names((array) $meta['allowed_rules']) : (object) [],
                'allowed_cats'       => !empty($meta['allowed_cats']) ? (array) $meta['allowed_cats'] : [],
                'endpoint'           => !empty($meta['endpoint']) ? $meta['endpoint'] : '',
                'expires_at'         => $expires_at,
                'is_expired'         => $is_expired,
            ];
        }

        return $results;
    }
    /**
     * Check if a given request URI is whitelisted
     */
    public static function is_url_whitelisted(string $uri, string $whitelist_text): bool {
        if (empty(trim($whitelist_text))) {
            return false;
        }

        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $whitelist_text))));
        $path  = (string) wp_parse_url($uri, PHP_URL_PATH);

        foreach ($lines as $allowed) {
            if ($allowed === '') {
                continue;
            }
            // Strip any query or hash from whitelist line for comparison
            $allowed_clean = (string) wp_parse_url($allowed, PHP_URL_PATH);
            if (empty($allowed_clean)) {
                $allowed_clean = $allowed;
            }

            // Exact match or prefix match with boundary check (prevents / from wiping out entire whitelist)
            $trimmed = rtrim($allowed_clean, '/');
            if ($uri === $allowed || $path === $allowed_clean || ($trimmed !== '' && ($path === $trimmed || strpos($path, $trimmed . '/') === 0))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an incoming request matches any Targeted Allowlist Rules (User-Agent, Endpoint, and optional IP)
     * If matched, returns the matching rule definition array, or null if no match.
     */
    public static function match_targeted_allowlist_rule(string $uri, string $user_agent, string $ip, string $method, array $rules): ?array {
        if (empty($rules)) {
            return null;
        }

        $path = (string) wp_parse_url($uri, PHP_URL_PATH);
        if (empty($path)) {
            $path = '/';
        }
        $upper_method = strtoupper($method);

        foreach ($rules as $rule) {
            if (empty($rule['enabled'])) {
                continue;
            }

            // Security Hardening (Roadmap Finding 3): A rule specifying ONLY User-Agents
            // without an IP, specific Endpoint, or verified Hostname constraint is easily forged by attackers.
            // Reject allowlist rules that lack at least one network, endpoint, or cryptographic constraint.
            $has_ip_constraint       = !empty($rule['ip_addresses']) && is_array($rule['ip_addresses']);
            $has_endpoint_constraint = !empty($rule['endpoints']) && is_array($rule['endpoints']);
            $has_hostname_constraint = !empty($rule['hostnames']) && is_array($rule['hostnames']);
            $has_ua_constraint       = !empty($rule['user_agents']) && is_array($rule['user_agents']);

            if ($has_ua_constraint && !$has_ip_constraint && !$has_endpoint_constraint && !$has_hostname_constraint) {
                continue;
            }

            // 1. Method Check
            $allowed_methods = !empty($rule['methods']) && is_array($rule['methods']) ? array_map('strtoupper', $rule['methods']) : ['ALL'];
            if (!in_array('ALL', $allowed_methods, true) && !in_array($upper_method, $allowed_methods, true)) {
                continue;
            }

            // 2. IP / Subnet Check (If empty, any IP is allowed)
            $rule_ips = !empty($rule['ip_addresses']) && is_array($rule['ip_addresses']) ? $rule['ip_addresses'] : [];
            if (!empty($rule_ips)) {
                $ip_matched = false;
                foreach ($rule_ips as $target_ip) {
                    $target_ip = trim($target_ip);
                    if ($target_ip === '') {
                        continue;
                    }
                    if ($target_ip === $ip || (strpos($target_ip, '/') !== false && self::ip_in_range($ip, $target_ip))) {
                        $ip_matched = true;
                        break;
                    }
                }
                if (!$ip_matched) {
                    continue; // IP condition specified but didn't match
                }
            }

            // 3. Endpoint / URL Check (If empty, any endpoint passes)
            $rule_endpoints = !empty($rule['endpoints']) && is_array($rule['endpoints']) ? $rule['endpoints'] : [];
            if (!empty($rule_endpoints)) {
                $endpoint_matched = false;
                foreach ($rule_endpoints as $endpoint_pattern) {
                    $endpoint_pattern = trim($endpoint_pattern);
                    if ($endpoint_pattern === '') {
                        continue;
                    }
                    // Strip host/query for matching
                    $clean_pattern = (string) wp_parse_url($endpoint_pattern, PHP_URL_PATH);
                    if (empty($clean_pattern)) {
                        $clean_pattern = $endpoint_pattern;
                    }

                    // Check exact, wildcard, or prefix
                    if (strpos($clean_pattern, '*') !== false) {
                        $regex = '#^' . str_replace('\*', '.*', preg_quote($clean_pattern, '#')) . '$#i';
                        if (preg_match($regex, $uri) || preg_match($regex, $path)) {
                            $endpoint_matched = true;
                            break;
                        }
                    } else {
                        // Exact match or prefix match with boundary check
                        $trimmed = rtrim($clean_pattern, '/');
                        if ($uri === $clean_pattern || $path === $clean_pattern || ($trimmed !== '' && ($path === $trimmed || strpos($path, $trimmed . '/') === 0))) {
                            $endpoint_matched = true;
                            break;
                        }
                    }
                }
                if (!$endpoint_matched) {
                    continue; // Endpoint condition specified but didn't match
                }
            }

            // 4. User-Agent Check (If empty, any User-Agent passes)
            $rule_uas = !empty($rule['user_agents']) && is_array($rule['user_agents']) ? $rule['user_agents'] : [];
            if (!empty($rule_uas)) {
                $ua_matched = false;
                foreach ($rule_uas as $ua_pattern) {
                    $ua_pattern = trim($ua_pattern);
                    if ($ua_pattern === '') {
                        continue;
                    }
                    if (strpos($ua_pattern, '*') !== false) {
                        $regex = '#^' . str_replace('\*', '.*', preg_quote($ua_pattern, '#')) . '$#i';
                        if (preg_match($regex, $user_agent)) {
                            $ua_matched = true;
                            break;
                        }
                    } else {
                        if (stripos($user_agent, $ua_pattern) !== false) {
                            $ua_matched = true;
                            break;
                        }
                    }
                }
                if (!$ua_matched) {
                    continue; // User-Agent condition specified but didn't match
                }
            }

            // 5. Hostname / Reverse DNS (rDNS) Verification (If specified, verify IP resolves to allowed domain/hostname)
            $rule_hostnames = !empty($rule['hostnames']) && is_array($rule['hostnames']) ? $rule['hostnames'] : [];
            if (!empty($rule_hostnames)) {
                $host_matched = false;
                foreach ($rule_hostnames as $allowed_host) {
                    $allowed_host = trim($allowed_host);
                    if ($allowed_host === '') {
                        continue;
                    }
                    if (self::verify_rdns_domain($ip, $allowed_host)) {
                        $host_matched = true;
                        break;
                    }
                }
                if (!$host_matched) {
                    continue; // Hostname/rDNS condition specified but didn't match
                }
            }

            // 6. Autonomous System Number (ASN) Check (If specified, verify client ASN)
            $rule_asns = !empty($rule['asns']) && is_array($rule['asns']) ? $rule['asns'] : [];
            if (!empty($rule_asns)) {
                $client_asn = self::get_client_asn($ip);
                if (empty($client_asn)) {
                    continue; // ASN specified but could not be determined
                }
                $asn_matched = false;
                foreach ($rule_asns as $target_asn) {
                    $clean_target = strtoupper(trim($target_asn));
                    if ($clean_target === '') {
                        continue;
                    }
                    if ($clean_target === $client_asn || $clean_target === ('AS' . $client_asn) || ('AS' . $clean_target) === $client_asn) {
                        $asn_matched = true;
                        break;
                    }
                }
                if (!$asn_matched) {
                    continue; // ASN condition specified but didn't match
                }
            }

            // 7. Required HTTP Headers (e.g. X-Shopify-Hmac-Sha256, Stripe-Signature, X-Square-Hmacsha256-Signature)
            $rule_headers = !empty($rule['required_headers']) && is_array($rule['required_headers']) ? $rule['required_headers'] : [];
            if (!empty($rule_headers)) {
                $headers_matched = true;
                foreach ($rule_headers as $req_header) {
                    $req_header = trim($req_header);
                    if ($req_header === '') {
                        continue;
                    }
                    // Normalize to HTTP_ format
                    $server_key = 'HTTP_' . strtoupper(str_replace('-', '_', $req_header));
                    if (!isset($_SERVER[$server_key]) && !isset($_SERVER[strtoupper(str_replace('-', '_', $req_header))])) {
                        $headers_matched = false;
                        break;
                    }
                }
                if (!$headers_matched) {
                    continue; // Required header missing
                }
            }

            // If we reached here, all specified conditions matched!
            return $rule;
        }

        return null;
    }

    /**
     * Cryptographically verify IP reverse DNS (PTR) with forward DNS (A) resolution.
     * Caches verdict in WordPress transient for 24 hours to prevent DNS resolution latency.
     */
    public static function verify_rdns_domain(string $ip, string $target_domain): bool {
        $clean_target = strtolower(trim(ltrim($target_domain, '*.')));
        if ($clean_target === '') {
            return false;
        }

        $transient_key = 'webcare_rdns_' . md5($ip . '_' . $clean_target);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return ($cached === 'valid');
        }

        $is_valid = false;
        $hostname = @gethostbyaddr($ip);
        if (!empty($hostname) && $hostname !== $ip) {
            $hostname_lower = strtolower($hostname);
            if ($hostname_lower === $clean_target || str_ends_with($hostname_lower, '.' . $clean_target)) {
                // Forward DNS check to prevent PTR spoofing
                $resolved_ip = @gethostbyname($hostname);
                if ($resolved_ip === $ip) {
                    $is_valid = true;
                }
            }
        }

        // Cache 24 hours if valid, 2 hours if failed
        set_transient($transient_key, $is_valid ? 'valid' : 'invalid', $is_valid ? DAY_IN_SECONDS : 7200);
        return $is_valid;
    }

    /**
     * Resolve Client Autonomous System Number (ASN).
     * Checks Cloudflare CF-Connecting-ASN header, proxy headers, or Team Cymru DNS lookup.
     */
    public static function get_client_asn(string $ip): string {
        // 1. Direct Cloudflare Edge ASN Header
        if (!empty($_SERVER['HTTP_CF_CONNECTING_ASN'])) {
            return strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_ASN'])));
        }

        // 2. Check transient cache
        $transient_key = 'webcare_asn_' . md5($ip);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return (string) $cached;
        }

        // 3. Reverse DNS check against Team Cymru ASN mapping DNS service (origin.asn.cymru.com)
        $asn = '';
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $octets = explode('.', $ip);
            $rev_ip = implode('.', array_reverse($octets));
            $query_host = $rev_ip . '.origin.asn.cymru.com';
            $txt_records = @dns_get_record($query_host, DNS_TXT);
            if (!empty($txt_records[0]['txt'])) {
                // Format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
                $parts = explode('|', $txt_records[0]['txt']);
                $raw_asn = trim($parts[0] ?? '');
                if (!empty($raw_asn) && is_numeric($raw_asn)) {
                    $asn = 'AS' . $raw_asn;
                }
            }
        }

        set_transient($transient_key, $asn, !empty($asn) ? WEEK_IN_SECONDS : DAY_IN_SECONDS);
        return $asn;
    }

    /**
     * Log targeted allowlist bypass to WAF database with deep forensic telemetry
     */
    public static function log_targeted_allowlist_hit(array $rule, string $ip, string $uri, string $user_agent, string $method): void {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_firewall_logs';

        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_check = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if ($table_check !== $table) {
            return;
        }

        $incident_id = 'WEBCARE-ALLOW-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
        $rule_name = sanitize_text_field($rule['name'] ?? 'Targeted Allowlist');

        // Capture in-depth request payload & query details with sensitive data redaction
        $raw_body = '';
        if (in_array(strtoupper($method), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            // Read raw body stream or $_POST
            $raw_input = file_get_contents('php://input');
            if (!empty($raw_input)) {
                $raw_body = substr($raw_input, 0, 2500);
            } elseif (!empty($_POST)) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Inspection of inbound webhook/API payload occurs at low-level firewall layer before authentication
                // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Low-level packet forensic capture
                $raw_body = wp_json_encode(wp_unslash($_POST));
            }
        }

        // Privacy Redaction: Mask sensitive keys (passwords, tokens, api keys, secrets, authorization headers, credit cards)
        if (!empty($raw_body)) {
            $sensitive_patterns = [
                '/(["\']?(?:password|passwd|pass|secret|token|api[_-]?key|access[_-]?token|auth|authorization|card|cvv|cvc|pan)["\']?\s*[:=]\s*["\']?)([^"\'&,\s]{3,})/i',
                '/(Bearer\s+)[A-Za-z0-9_\-\.]{10,}/i'
            ];
            foreach ($sensitive_patterns as $pattern) {
                $raw_body = preg_replace($pattern, '$1[REDACTED]', $raw_body);
            }
        }

        $host_transient = 'webcare_ptr_' . md5($ip);
        $hostname = get_transient($host_transient);
        if ($hostname === false) {
            $hostname = @gethostbyaddr($ip);
            set_transient($host_transient, $hostname ?: $ip, DAY_IN_SECONDS);
        }
        $client_asn = self::get_client_asn($ip);

        $forensic_summary = [
            'rule_id'     => $rule['id'] ?? 'unknown',
            'rule_name'   => $rule_name,
            'query_data'  => !empty($query_str) ? $query_str : null,
            'body_sample' => !empty($raw_body) ? (strlen($raw_body) > 2000 ? substr($raw_body, 0, 2000) . '... [truncated]' : $raw_body) : null,
            'client_ip'   => $ip,
            'user_agent'  => $user_agent,
            'hostname'    => (!empty($hostname) && $hostname !== $ip) ? $hostname : null,
            'asn'         => !empty($client_asn) ? $client_asn : null,
            'matched_at'  => gmdate('Y-m-d H:i:s'),
        ];

        $payload_json = wp_json_encode($forensic_summary);
        $referer = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : null;

        // Rate limit logging for the same IP & rule to once every 10 seconds to avoid DB flooding on heavy sync batches
        $recent_sql = "SELECT id FROM `{$table}` WHERE ip_address = %s AND rule_category = 'targeted_allowlist' AND rule_description LIKE %s AND created_at > DATE_SUB(NOW(), INTERVAL 10 SECOND) LIMIT 1";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $recent = $wpdb->get_var(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $recent_sql,
                $ip,
                '%' . $wpdb->esc_like($rule_name) . '%'
            )
        );
        if ($recent) {
            return;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            [
                'incident_id'      => $incident_id,
                'ip_address'       => sanitize_text_field($ip),
                'request_uri'      => sanitize_text_field(substr($uri, 0, 500)),
                'request_method'   => sanitize_key(substr($method, 0, 10)),
                'http_status_code' => 200,
                'http_referer'     => !empty($referer) ? sanitize_text_field(substr($referer, 0, 500)) : null,
                'rule_category'    => 'targeted_allowlist',
                'rule_description' => sprintf(
                    /* translators: 1: rule name, 2: client user agent */
                    __('Granted safe WAF bypass via rule "%1$s" for User-Agent: %2$s', 'webcare-pro-security'),
                    $rule_name,
                    substr($user_agent, 0, 80)
                ),
                'payload_sample'   => sanitize_text_field($payload_json),
                'user_agent'       => sanitize_text_field(substr($user_agent, 0, 300)),
                'action_taken'     => 'allowed',
                'created_at'       => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    /**
     * Parse human-readable ini size strings (e.g. '64M', '2G', '512K') into bytes.
     *
     * @param string $val
     * @return int
     */
    public static function parse_ini_size_bytes(string $val): int {
        $val = trim($val);
        if ($val === '') {
            return 0;
        }
        $last = strtolower($val[strlen($val) - 1]);
        $num  = (int) $val;
        switch ($last) {
            case 'g':
                $num *= 1024 * 1024 * 1024;
                break;
            case 'm':
                $num *= 1024 * 1024;
                break;
            case 'k':
                $num *= 1024;
                break;
        }
        return $num;
    }

    /**
     * Resolve the maximum permitted upload body size in bytes based on WordPress and PHP runtime settings.
     *
     * @return int
     */
    public static function get_max_upload_limit_bytes(): int {
        if (function_exists('wp_max_upload_size')) {
            $wp_max = (int) wp_max_upload_size();
            if ($wp_max > 0) {
                return $wp_max;
            }
        }
        $post_max   = self::parse_ini_size_bytes((string) ini_get('post_max_size'));
        $upload_max = self::parse_ini_size_bytes((string) ini_get('upload_max_filesize'));
        $limit      = min($post_max ?: 67108864, $upload_max ?: 33554432);
        return max(4194304, $limit);
    }

    /**
     * Recursively normalize arbitrary multi-dimensional $_FILES structures into a flat list
     * of ['name' => string, 'tmp_name' => string, 'type' => string, 'error' => int, 'size' => int].
     *
     * Guarded with depth cap (<= 4) and max count (<= 50) to prevent pathological DOS arrays.
     * Sets $overflow = true if the array exceeds max files or max depth (fails closed).
     *
     * @param array $files_array
     * @param int   $max_depth
     * @param int   $max_files
     * @param bool  $overflow Passed by reference, set to true if count/depth exceeds limits.
     * @return array<int, array<string, mixed>>
     */
    public static function flatten_uploaded_files(array $files_array, int $max_depth = 4, int $max_files = 50, bool &$overflow = false): array {
        $normalized = [];
        $overflow   = false;

        $walk = static function ($names, $tmp_names, $types, $errors, $sizes, int $depth) use (&$walk, &$normalized, &$overflow, $max_depth, $max_files): void {
            if ($depth > $max_depth) {
                $overflow = true;
                return;
            }

            if (is_array($names)) {
                foreach ($names as $k => $sub_name) {
                    if (count($normalized) >= $max_files) {
                        $overflow = true;
                        break;
                    }
                    $walk(
                        $sub_name,
                        is_array($tmp_names) ? ($tmp_names[$k] ?? '') : '',
                        is_array($types) ? ($types[$k] ?? '') : '',
                        is_array($errors) ? ($errors[$k] ?? 0) : 0,
                        is_array($sizes) ? ($sizes[$k] ?? 0) : 0,
                        $depth + 1
                    );
                }
                return;
            }

            if (is_string($names) && $names !== '') {
                if (count($normalized) >= $max_files) {
                    $overflow = true;
                    return;
                }
                $normalized[] = [
                    'name'     => $names,
                    'tmp_name' => is_string($tmp_names) ? $tmp_names : '',
                    'type'     => is_string($types) ? $types : '',
                    'error'    => (int) $errors,
                    'size'     => (int) $sizes,
                ];
            }
        };

        foreach ($files_array as $file_info) {
            if (!is_array($file_info) || !isset($file_info['name'])) {
                continue;
            }
            if (count($normalized) >= $max_files) {
                $overflow = true;
                break;
            }
            $walk(
                $file_info['name'],
                $file_info['tmp_name'] ?? '',
                $file_info['type'] ?? '',
                $file_info['error'] ?? 0,
                $file_info['size'] ?? 0,
                1
            );
        }

        return $normalized;
    }

    /**
     * Intercept and audit uploaded files in real-time (Rule 8)
     */
    public static function inspect_uploaded_file(array $file, bool $log_and_ban = true): array {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_block_malicious_uploads'])) {
            return $file;
        }

        if (empty($file['name'])) {
            return $file;
        }

        // Handle multi-dimensional or multi-file uploads (e.g. $_FILES['form_fields']['name']['avatar'])
        if (is_array($file['name'])) {
            $flattened = self::flatten_uploaded_files([$file]);
            foreach ($flattened as $single_file) {
                $sub_res = self::inspect_uploaded_file($single_file, $log_and_ban);
                if (!empty($sub_res['error'])) {
                    $file['error'] = $sub_res['error'];
                    $file['rule_id'] = $sub_res['rule_id'] ?? 'WAF-POLYGLOT-UPLOAD-TRAP';
                    $file['rule_name'] = $sub_res['rule_name'] ?? 'Malicious File Upload Shield (Rule 8)';
                    $file['category'] = $sub_res['category'] ?? 'Malicious File Upload';
                    return $file;
                }
            }
            return $file;
        }

        if (empty($file['tmp_name'])) {
            return $file;
        }

        $raw_filename = (string) $file['name'];
        $filename = strtolower(basename($raw_filename));
        $tmp_path = $file['tmp_name'];
        $ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // Rule #47: Zip-Slip & Path Traversal / Null-Byte Armor
        if (!empty($settings['waf_upload_deep_mime_sanitizer'])) {
            if (
                strpos($raw_filename, '..') !== false ||
                strpos($raw_filename, "\0") !== false ||
                strpos($raw_filename, '/') !== false ||
                strpos($raw_filename, '\\') !== false
            ) {
                $client_ip = self::get_client_ip();
                if ($log_and_ban) {
                    if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                        self::add_blocked_ip(
                            $client_ip,
                            sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] Path traversal in upload: %s', $raw_filename),
                            86400,
                            'WAF-POLYGLOT-UPLOAD-TRAP',
                            'Zip-Slip Traversal Trap',
                            'Malicious File Upload'
                        );
                    }
                    self::log_incident([
                        'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                        'category'    => 'Malicious File Upload',
                        'description' => sprintf('Upload with Zip-Slip path traversal or null-byte characters "%s" was blocked by firewall.', esc_html($raw_filename)),
                        'payload'     => "Filename: {$raw_filename}",
                    ], 'blocked');
                }

                $file['error']     = __('Security Firewall: Path traversal or invalid characters detected in uploaded filename.', 'webcare-pro-security');
                $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
                $file['rule_name'] = 'Zip-Slip Traversal Trap (Rule #47)';
                $file['category']  = 'Malicious File Upload';
                return $file;
            }
        }

        // 1. Prohibited executable extensions
        $prohibited_exts = [
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'phps', 'pht', 'pgif', 'inc', 'shtml',
            'sh', 'bash', 'zsh', 'ksh', 'csh', 'bin', 'cgi', 'pl', 'py', 'pyc', 'pyw',
            'rb', 'asp', 'aspx', 'cer', 'csr', 'jsp', 'jspx', 'exe', 'com', 'bat', 'cmd',
            'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'msi', 'dll', 'drv', 'sys', 'htaccess', 'ini'
        ];

        if (in_array($ext, $prohibited_exts, true) || preg_match('/^\.(?:htaccess|htpasswd|user\.ini)$/i', $filename)) {
            $client_ip = self::get_client_ip();
            if ($log_and_ban) {
                if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                    self::add_blocked_ip(
                        $client_ip,
                        sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] Executable upload attempt: %s', $filename),
                        86400,
                        'WAF-POLYGLOT-UPLOAD-TRAP',
                        'Executable Upload Trap',
                        'Malicious File Upload'
                    );
                }
                self::log_incident([
                    'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                    'category'    => 'Malicious File Upload',
                    'description' => sprintf('Upload of executable or restricted file "%s" was blocked by firewall.', esc_html($filename)),
                    'payload'     => "Filename: {$filename} Extension: .{$ext}",
                ], 'blocked');
            }

            $file['error']     = __('Security Firewall: Uploading executable scripts or restricted server configurations is strictly prohibited.', 'webcare-pro-security');
            $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
            $file['rule_name'] = 'Executable Upload Trap';
            $file['category']  = 'Malicious File Upload';
            return $file;
        }

        // 2. Double extension check (e.g. image.php.jpg, doc.php.png)
        if (preg_match('/\.(php[0-9]?|phtml|phar|sh|bash|cgi|pl|py|exe)\.([a-z0-9]+)$/i', $filename, $m)) {
            $client_ip = self::get_client_ip();
            if ($log_and_ban) {
                if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                    self::add_blocked_ip(
                        $client_ip,
                        sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] Disguised double-extension upload attempt: %s', $filename),
                        86400,
                        'WAF-POLYGLOT-UPLOAD-TRAP',
                        'Double-Extension Trap',
                        'Malicious File Upload'
                    );
                }
                self::log_incident([
                    'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                    'category'    => 'Malicious File Upload',
                    'description' => sprintf('Upload with disguised double-extension "%s" was blocked by firewall.', esc_html($filename)),
                    'payload'     => "Filename: {$filename} Hidden extension: .{$m[1]}",
                ], 'blocked');
            }

            $file['error']     = __('Security Firewall: Disguised double-extension file upload detected and blocked.', 'webcare-pro-security');
            $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
            $file['rule_name'] = 'Double-Extension Trap';
            $file['category']  = 'Malicious File Upload';
            return $file;
        }

        // 3. Inspect binary magic bytes if temp file exists
        if (file_exists($tmp_path) && is_readable($tmp_path)) {
            $header = @file_get_contents($tmp_path, false, null, 0, 16);
            if ($header !== false) {
                if (strlen($header) >= 2) {
                    $binary_exploit_detected = false;
                    $binary_exploit_msg = '';

                    // Windows PE (MZ)
                    if (substr($header, 0, 2) === 'MZ') {
                        $binary_exploit_detected = true;
                        $binary_exploit_msg = __('Security Firewall: Spoofed Windows executable binary detected in upload.', 'webcare-pro-security');
                    }
                    // Linux ELF (\x7fELF)
                    elseif (substr($header, 0, 4) === "\x7fELF") {
                        $binary_exploit_detected = true;
                        $binary_exploit_msg = __('Security Firewall: Spoofed Linux ELF executable binary detected in upload.', 'webcare-pro-security');
                    }
                    // macOS Mach-O
                    elseif (in_array(substr($header, 0, 4), ["\xca\xfe\xba\xbe", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe"], true)) {
                        $binary_exploit_detected = true;
                        $binary_exploit_msg = __('Security Firewall: Spoofed Mach-O executable binary detected in upload.', 'webcare-pro-security');
                    }
                    // Unix Shebang in image/media
                    elseif (substr($header, 0, 2) === '#!' && preg_match('/^#!\s*\/(bin|usr)/i', $header)) {
                        $binary_exploit_detected = true;
                        $binary_exploit_msg = __('Security Firewall: Spoofed shell script detected in upload.', 'webcare-pro-security');
                    }

                    if ($binary_exploit_detected) {
                        $client_ip = self::get_client_ip();
                        if ($log_and_ban) {
                            if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                                self::add_blocked_ip(
                                    $client_ip,
                                    sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] Spoofed binary upload attempt: %s', $filename),
                                    86400,
                                    'WAF-POLYGLOT-UPLOAD-TRAP',
                                    'Binary Magic Byte Trap',
                                    'Malicious File Upload'
                                );
                            }
                            self::log_incident([
                                'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                                'category'    => 'Malicious File Upload',
                                'description' => sprintf('Upload with spoofed binary executable header "%s" was blocked by firewall.', esc_html($filename)),
                                'payload'     => "Filename: {$filename}",
                            ], 'blocked');
                        }

                        $file['error']     = $binary_exploit_msg;
                        $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
                        $file['rule_name'] = 'Binary Magic Byte Trap';
                        $file['category']  = 'Malicious File Upload';
                        return $file;
                    }
                }
            }

            // 4. Unified Upload Stream Integrity Pipeline & Deep Content Inspection (Media Polyglots & SVG/SVGZ Armor)
            $media_exts        = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'pdf', 'ico', 'avif'];
            $svg_exts          = ['svg', 'svgz'];
            $deep_inspect_exts = array_merge($media_exts, $svg_exts);

            if (in_array($ext, $deep_inspect_exts, true)) {
                clearstatcache(true, $tmp_path);
                $expected_fsize = @filesize($tmp_path);
                $initial_mtime  = @filemtime($tmp_path);
                $initial_inode  = @fileinode($tmp_path);
                $u_max = isset($settings['waf_max_inspected_body_bytes']) ? min(16777216, max(262144, (int) $settings['waf_max_inspected_body_bytes'])) : 10485760;

                $integrity_violation = false;
                $integrity_reason    = '';

                if ($expected_fsize === false || $expected_fsize < 0) {
                    $integrity_violation = true;
                    $integrity_reason    = 'Unreadable temp file size';
                } elseif ($expected_fsize > $u_max) {
                    $integrity_violation = true;
                    $integrity_reason    = sprintf('Temp file size (%d) exceeds inspection limit (%d)', $expected_fsize, $u_max);
                } elseif (isset($file['size']) && (int) $file['size'] > 0 && (int) $file['size'] !== $expected_fsize) {
                    $integrity_violation = true;
                    $integrity_reason    = sprintf('Declared size (%d) does not match disk size (%d)', (int) $file['size'], $expected_fsize);
                }

                if ($integrity_violation) {
                    $client_ip = self::get_client_ip();
                    if ($log_and_ban) {
                        if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                            self::add_blocked_ip(
                                $client_ip,
                                sprintf('[WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED] Upload verification failed: %s (%s)', $filename, $integrity_reason),
                                86400,
                                'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED',
                                'Upload Scan Integrity & Mutation Guard',
                                'Malicious File Upload'
                            );
                        }
                        self::log_incident([
                            'id'          => 'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED',
                            'category'    => 'Malicious File Upload',
                            'description' => sprintf('Upload verification failed for "%s": %s', esc_html($filename), esc_html($integrity_reason)),
                            'payload'     => "Filename: {$filename} Reason: {$integrity_reason}",
                        ], 'blocked');
                    }

                    $file['error']     = __('Security Firewall: Uploaded file verification failed (size mismatch or inspection limit exceeded).', 'webcare-pro-security');
                    $file['rule_id']   = 'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED';
                    $file['rule_name'] = 'Upload Scan Integrity & Mutation Guard';
                    $file['category']  = 'Malicious File Upload';
                    return $file;
                }

                $php_pattern  = '/<\?(?:php\s+[\s\S]{0,500}?(?:eval|assert|system|passthru|shell_exec|exec|base64_decode|\$_[A-Z]+|\$[a-zA-Z0-9_]+)|\=\s*[\s\S]{0,200}?(?:eval|assert|\$_[A-Z]+|\$[a-zA-Z0-9_]+))/i';
                $polyglot_hit = false;
                $h_ctx        = hash_init('sha256');
                $is_svg       = in_array($ext, $svg_exts, true);
                $svg_raw_buf  = '';

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
                $ufp = @fopen($tmp_path, 'rb');
                if (!is_resource($ufp)) {
                    $integrity_violation = true;
                    $integrity_reason    = 'Failed to open temp file for streaming inspection';
                } else {
                    $is_gzipped_upload = ($ext === 'svgz');
                    $u_prev = '';
                    $u_read = 0;
                    while (!feof($ufp)) {
                        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
                        $u_chunk = @fread($ufp, 65536);
                        if ($u_chunk === false) {
                            $integrity_violation = true;
                            $integrity_reason    = 'fread error during chunked scan';
                            break;
                        }
                        if ($u_chunk === '') {
                            break;
                        }

                        hash_update($h_ctx, $u_chunk);
                        $u_read += strlen($u_chunk);

                        if ($u_read === strlen($u_chunk) && substr($u_chunk, 0, 2) === "\x1f\x8b") {
                            $is_gzipped_upload = true;
                        }

                        if ($is_svg) {
                            $svg_raw_buf .= $u_chunk;
                        }

                        // Test injection hook for short read (simulate truncated read before reaching expected filesize)
                        if (!empty($GLOBALS['WEBCARE_TEST_UPLOAD_SHORT_READ'])) {
                            break;
                        }

                        // Test injection hook for mid-scan mutation callback
                        if (isset($GLOBALS['WEBCARE_TEST_UPLOAD_MUTATE_CALLBACK']) && is_callable($GLOBALS['WEBCARE_TEST_UPLOAD_MUTATE_CALLBACK'])) {
                            call_user_func($GLOBALS['WEBCARE_TEST_UPLOAD_MUTATE_CALLBACK'], $tmp_path);
                            unset($GLOBALS['WEBCARE_TEST_UPLOAD_MUTATE_CALLBACK']); // invoke once
                        }

                        if ($u_read > $u_max) {
                            $integrity_violation = true;
                            $integrity_reason    = 'Bytes read exceeded inspection limit during scan';
                            break;
                        }

                        if (!$is_gzipped_upload) {
                            $u_win = $u_prev . $u_chunk;
                            if (preg_match($php_pattern, $u_win) || stripos($u_win, '__HALT_COMPILER()') !== false) {
                                $polyglot_hit = true;
                                break;
                            }
                            $u_prev = strlen($u_chunk) > 1024 ? substr($u_chunk, -1024) : $u_chunk;
                        }
                    }
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                    @fclose($ufp);
                }

                $streamed_sha256 = hash_final($h_ctx);

                // Post-scan disk revalidation (identical across SVG, SVGZ, JPEG, PNG, PDF, etc.)
                if (!$polyglot_hit && !$integrity_violation) {
                    clearstatcache(true, $tmp_path);
                    $post_fsize = @filesize($tmp_path);
                    $post_mtime = @filemtime($tmp_path);
                    $post_inode = @fileinode($tmp_path);
                    $disk_sha   = (string) @hash_file('sha256', $tmp_path);

                    if ($u_read !== $expected_fsize) {
                        $integrity_violation = true;
                        $integrity_reason    = sprintf('Incomplete read: read %d bytes of expected %d bytes', $u_read, $expected_fsize);
                    } elseif ($post_fsize !== $expected_fsize) {
                        $integrity_violation = true;
                        $integrity_reason    = sprintf('File size mutated post-scan: was %d, now %d', $expected_fsize, $post_fsize);
                    } elseif ($post_mtime !== $initial_mtime) {
                        $integrity_violation = true;
                        $integrity_reason    = 'File mtime mutated during scan';
                    } elseif ($post_inode !== $initial_inode) {
                        $integrity_violation = true;
                        $integrity_reason    = 'File inode mutated during scan (file swap detected)';
                    } elseif (!hash_equals($streamed_sha256, $disk_sha)) {
                        $integrity_violation = true;
                        $integrity_reason    = 'Disk SHA-256 does not match streamed SHA-256 (file content mutated mid-scan)';
                    }
                }

                if ($integrity_violation) {
                    $client_ip = self::get_client_ip();
                    if ($log_and_ban) {
                        if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                            self::add_blocked_ip(
                                $client_ip,
                                sprintf('[WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED] Upload verification failed: %s (%s)', $filename, $integrity_reason),
                                86400,
                                'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED',
                                'Upload Scan Integrity & Mutation Guard',
                                'Malicious File Upload'
                            );
                        }
                        self::log_incident([
                            'id'          => 'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED',
                            'category'    => 'Malicious File Upload',
                            'description' => sprintf('Upload verification failed for "%s": %s', esc_html($filename), esc_html($integrity_reason)),
                            'payload'     => "Filename: {$filename} Reason: {$integrity_reason}",
                        ], 'blocked');
                    }

                    $file['error']     = __('Security Firewall: Uploaded file verification failed (incomplete read or disk mutation detected).', 'webcare-pro-security');
                    $file['rule_id']   = 'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED';
                    $file['rule_name'] = 'Upload Scan Integrity & Mutation Guard';
                    $file['category']  = 'Malicious File Upload';
                    return $file;
                }

                if ($polyglot_hit) {
                    $client_ip = self::get_client_ip();
                    if ($log_and_ban) {
                        if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                            self::add_blocked_ip(
                                $client_ip,
                                sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] PHP/Phar polyglot in media: %s', $filename),
                                86400,
                                'WAF-POLYGLOT-UPLOAD-TRAP',
                                'Polyglot Media Upload Armor (Rule #54)',
                                'Malicious File Upload'
                            );
                        }
                        self::log_incident([
                            'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                            'category'    => 'Malicious File Upload',
                            'description' => sprintf('Disguised PHP polyglot webshell or Phar deserialization header in media file "%s" was blocked.', esc_html($filename)),
                            'payload'     => "Filename: {$filename}",
                        ], 'blocked');
                    }

                    $file['error']     = __('Security Firewall: Disguised PHP polyglot webshell or Phar deserialization header detected inside media file.', 'webcare-pro-security');
                    $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
                    $file['rule_name'] = 'Polyglot Media Upload Armor (Rule #54)';
                    $file['category']  = 'Malicious File Upload';
                    return $file;
                }

                // Specific SVG / SVGZ deep vector inspection with bounded decompression (P1 Defense)
                if ($is_svg) {
                    $svg_content = $svg_raw_buf;
                    $is_gzipped  = (substr($svg_content, 0, 2) === "\x1f\x8b") || ($ext === 'svgz');

                    if ($is_gzipped) {
                        if (!function_exists('gzdecode')) {
                            $file['error']     = __('Security Firewall: SVGZ decompression unavailable on server; failing closed.', 'webcare-pro-security');
                            $file['rule_id']   = 'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR';
                            $file['rule_name'] = 'SVGZ Decompression Guard';
                            $file['category']  = 'Malicious File Upload';
                            return $file;
                        }

                        $max_decompressed_bytes = min(4194304, $u_max); // 4 MB maximum decompressed vector text
                        $decompressed = @gzdecode($svg_content, $max_decompressed_bytes);

                        if ($decompressed === false || !is_string($decompressed) || $decompressed === '') {
                            $client_ip = self::get_client_ip();
                            if ($log_and_ban) {
                                if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                                    self::add_blocked_ip(
                                        $client_ip,
                                        sprintf('[WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR] SVGZ decompression failed or limit exceeded: %s', $filename),
                                        86400,
                                        'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR',
                                        'SVGZ Decompression Bomb Guard',
                                        'Malicious File Upload'
                                    );
                                }
                                self::log_incident([
                                    'id'          => 'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR',
                                    'category'    => 'Malicious File Upload',
                                    'description' => sprintf('Decompression failed or decompressed payload exceeded inspection ceiling for SVGZ file "%s".', esc_html($filename)),
                                    'payload'     => "Filename: {$filename}",
                                ], 'blocked');
                            }

                            $file['error']     = __('Security Firewall: SVGZ decompression failed or decompressed payload exceeded inspection limit.', 'webcare-pro-security');
                            $file['rule_id']   = 'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR';
                            $file['rule_name'] = 'SVGZ Decompression Bomb Guard';
                            $file['category']  = 'Malicious File Upload';
                            return $file;
                        }

                        // Additional post-decompression safety policy: flag high-ratio compression bombs (> 200:1).
                        // Note: Bounded decompression via @gzdecode($svg_content, $max_decompressed_bytes) is the primary resource-safety
                        // mechanism preventing memory exhaustion; this check enforces an additional structural safety policy.
                        $c_len = strlen($svg_content);
                        $d_len = strlen($decompressed);
                        if ($c_len > 0 && ($d_len / $c_len) > 200) {
                            $client_ip = self::get_client_ip();
                            if ($log_and_ban) {
                                if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                                    self::add_blocked_ip(
                                        $client_ip,
                                        sprintf('[WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR] SVGZ compression ratio exceeded safety threshold: %s', $filename),
                                        86400,
                                        'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR',
                                        'SVGZ Decompression Bomb Guard',
                                        'Malicious File Upload'
                                    );
                                }
                                self::log_incident([
                                    'id'          => 'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR',
                                    'category'    => 'Malicious File Upload',
                                    'description' => sprintf('SVGZ file "%s" exceeded safe compression ratio threshold.', esc_html($filename)),
                                    'payload'     => sprintf('Filename: %s Ratio: %.1f:1 Comp: %d Decomp: %d', $filename, $d_len / $c_len, $c_len, $d_len),
                                ], 'blocked');
                            }

                            $file['error']     = __('Security Firewall: SVGZ compression ratio exceeded safety threshold.', 'webcare-pro-security');
                            $file['rule_id']   = 'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR';
                            $file['rule_name'] = 'SVGZ Decompression Bomb Guard';
                            $file['category']  = 'Malicious File Upload';
                            return $file;
                        }

                        $svg_content = $decompressed;
                    }

                    // PHP polyglot patterns & Phar deserialization headers in SVG / decompressed SVGZ
                    if (preg_match($php_pattern, $svg_content) || stripos($svg_content, '__HALT_COMPILER()') !== false) {
                        $client_ip = self::get_client_ip();
                        if ($log_and_ban) {
                            if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                                self::add_blocked_ip(
                                    $client_ip,
                                    sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] PHP/Phar polyglot in SVG/SVGZ: %s', $filename),
                                    86400,
                                    'WAF-POLYGLOT-UPLOAD-TRAP',
                                    'SVG/SVGZ Polyglot & Phar Armor (Rule #54)',
                                    'Malicious File Upload'
                                );
                            }
                            self::log_incident([
                                'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                                'category'    => 'Malicious File Upload',
                                'description' => sprintf('Disguised PHP polyglot webshell or Phar deserialization header in SVG/SVGZ file "%s" was blocked.', esc_html($filename)),
                                'payload'     => "Filename: {$filename}",
                            ], 'blocked');
                        }

                        $file['error']     = __('Security Firewall: Disguised PHP polyglot webshell or Phar deserialization header detected inside SVG/SVGZ file.', 'webcare-pro-security');
                        $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
                        $file['rule_name'] = 'SVG/SVGZ Polyglot & Phar Armor (Rule #54)';
                        $file['category']  = 'Malicious File Upload';
                        return $file;
                    }

                    // SVG XSS & Active JavaScript Audit (Rule #54)
                    if (preg_match('/(<\?php|<\?=\s*|<script\b|javascript\s*:|\b(onload|onerror|onclick|onmouseover)\s*=|<(foreignObject|iframe|embed|object|animate|set)\b)/i', $svg_content, $m)) {
                        $client_ip = self::get_client_ip();
                        if ($log_and_ban) {
                            if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                                self::add_blocked_ip(
                                    $client_ip,
                                    sprintf('[WAF-POLYGLOT-UPLOAD-TRAP] SVG/SVGZ XSS payload in upload: %s', $filename),
                                    86400,
                                    'WAF-POLYGLOT-UPLOAD-TRAP',
                                    'SVG/SVGZ Script Armor (Rule #54)',
                                    'Malicious File Upload'
                                );
                            }
                            self::log_incident([
                                'id'          => 'WAF-POLYGLOT-UPLOAD-TRAP',
                                'category'    => 'Malicious File Upload',
                                'description' => sprintf('Malicious SVG XSS payload (%s) in uploaded file "%s" was blocked.', esc_html($m[0]), esc_html($filename)),
                                'payload'     => "Filename: {$filename} Match: {$m[0]}",
                            ], 'blocked');
                        }

                        $file['error']     = __('Security Firewall: SVG vector file contains executable scripts or embedded XSS tags.', 'webcare-pro-security');
                        $file['rule_id']   = 'WAF-POLYGLOT-UPLOAD-TRAP';
                        $file['rule_name'] = 'SVG/SVGZ Script Armor (Rule #54)';
                        $file['category']  = 'Malicious File Upload';
                        return $file;
                    }
                }
            }

            // 6. Prohibited Standalone phpMyAdmin / Database Script Uploads
            if (!empty($settings['waf_disallow_phpmyadmin_uploads'])) {
                $pma_name_patterns = ['/pma/i', '/phpmyadmin/i', '/adminer/i', '/sql[_-]?buddy/i', '/db[_-]?admin/i', '/mini[_-]?sql/i'];
                $is_pma_file = false;
                foreach ($pma_name_patterns as $pma_pat) {
                    if (preg_match($pma_pat, $filename)) {
                        $is_pma_file = true;
                        break;
                    }
                }

                // Check text/script content if candidate extension (e.g. .txt, .inc, .sql, .zip)
                if (!$is_pma_file && in_array($ext, ['txt', 'inc', 'zip', 'gz', 'tar'], true)) {
                    $sample = @file_get_contents($tmp_path, false, null, 0, 16384);
                    if ($sample && (stripos($sample, 'phpMyAdmin') !== false || stripos($sample, 'Adminer - Compact database') !== false || stripos($sample, 'PMA_sendHeaderLocation') !== false)) {
                        $is_pma_file = true;
                    }
                }

                // Deep ZIP inspect if archive upload
                if (!$is_pma_file && $ext === 'zip' && class_exists('ZipArchive')) {
                    $zip = new \ZipArchive();
                    if ($zip->open($tmp_path) === true) {
                        for ($i = 0; $i < min(300, $zip->numFiles); $i++) {
                            $entry_name = strtolower($zip->getNameIndex($i));
                            if (preg_match('/(phpmyadmin|adminer|sqlbuddy|db-?manager|database-?manager|mysql-?manager)/i', $entry_name)) {
                                $is_pma_file = true;
                                break;
                            }
                            if (preg_match('/\.php$/i', $entry_name)) {
                                $stream = $zip->getStream($zip->getNameIndex($i));
                                if ($stream) {
                                    $chunk = stream_get_contents($stream, 4096);
                                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- ZipArchive stream resource cleanup
                                    fclose($stream);
                                    if ($chunk && (
                                        preg_match('/Plugin Name:\s*.*(?:phpmyadmin|adminer|database\s*browser|db-?manager|database\s*manager|sql\s*buddy)/i', $chunk) ||
                                        stripos($chunk, 'PMA_sendHeaderLocation') !== false ||
                                        stripos($chunk, 'Adminer - Compact database') !== false
                                    )) {
                                        $is_pma_file = true;
                                        break;
                                    }
                                }
                            }
                        }
                        $zip->close();
                    }
                }

                if ($is_pma_file) {
                    if ($log_and_ban) {
                        self::log_incident([
                            'id'          => 'WAF-DISALLOW-PHPMYADMIN-PLUGIN',
                            'category'    => 'Prohibited Script Upload',
                            'description' => sprintf('Upload of phpMyAdmin / Adminer / DBManager database management script or plugin archive "%s" was blocked by policy.', esc_html($filename)),
                            'payload'     => "Filename: {$filename} Temp: {$tmp_path}",
                        ], 'blocked');
                    }

                    $file['error']     = __('Security Firewall: Uploading phpMyAdmin or standalone database management scripts is strictly disallowed.', 'webcare-pro-security');
                    $file['rule_id']   = 'WAF-DISALLOW-PHPMYADMIN-PLUGIN';
                    $file['rule_name'] = 'Prohibited Database Manager Script Upload';
                    $file['category']  = 'Prohibited Script Upload';
                    return $file;
                }
            }

            // 7. Prohibited File Manager & Web Shell Explorer Script Uploads
            if (!empty($settings['waf_disallow_filemanager_uploads'])) {
                $fm_name_patterns = [
                    '/tinyfilemanager/i', '/filemanager/i', '/file_manager/i', '/fileorganizer/i',
                    '/filester/i', '/elfinder/i', '/responsivefilemanager/i', '/alfa[_-]?shell/i',
                    '/c99/i', '/r57/i', '/wso[_-]?shell/i', '/b374k/i', '/webadmin/i',
                    '/file[_-]?explorer/i', '/file[_-]?commander/i', '/file[_-]?browser/i'
                ];
                $is_fm_file = false;
                foreach ($fm_name_patterns as $fm_pat) {
                    if (preg_match($fm_pat, $filename)) {
                        $is_fm_file = true;
                        break;
                    }
                }

                // Check text/script content if candidate extension (do not scan binary archives as strings)
                if (!$is_fm_file && in_array($ext, ['txt', 'inc', 'php', 'phtml'], true)) {
                    $sample = @file_get_contents($tmp_path, false, null, 0, 16384);
                    if ($sample && (
                        stripos($sample, 'TinyFileManager') !== false ||
                        stripos($sample, 'elFinder') !== false ||
                        stripos($sample, 'Responsive FileManager') !== false ||
                        stripos($sample, 'WSO 4.2.5') !== false ||
                        stripos($sample, 'FilesMan') !== false
                    )) {
                        $is_fm_file = true;
                    }
                }

                // Deep ZIP inspect if archive upload
                if (!$is_fm_file && $ext === 'zip' && class_exists('ZipArchive')) {
                    $zip = new \ZipArchive();
                    if ($zip->open($tmp_path) === true) {
                        // Check if this archive is WebCare Pro Security itself (self update / release package)
                        $is_self_package = false;
                        for ($j = 0; $j < $zip->numFiles; $j++) {
                            $check_name = $zip->getNameIndex($j);
                            if (preg_match('/(?:^|\/)(?:webcare-pro-security)\.php$/i', $check_name)) {
                                $stream = $zip->getStream($check_name);
                                if ($stream) {
                                    $chunk = stream_get_contents($stream, 2048);
                                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                                    fclose($stream);
                                    if ($chunk && (stripos($chunk, 'WebCare Pro Security') !== false || stripos($chunk, 'WebCare Pro Security & Firewall') !== false || stripos($chunk, 'WEBCAREPROSCAN_VERSION') !== false)) {
                                        $is_self_package = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if (!$is_self_package) {
                            for ($i = 0; $i < min(400, $zip->numFiles); $i++) {
                                $entry_name = strtolower($zip->getNameIndex($i));
                                $entry_base = basename($entry_name);
                                // Target dedicated standalone file manager script/plugin archives specifically without false-flagging internal sub-services (like ProfileManager.php)
                                if (preg_match('/\.php$/i', $entry_name)) {
                                    if (
                                        (
                                            preg_match('/(tinyfilemanager|fileorganizer|elfinder|responsivefilemanager|filester|file-explorer|file-commander)/i', $entry_base) ||
                                            preg_match('/(^|[-_])file[-_]?manager([-_\.]|$)/i', $entry_base)
                                        ) &&
                                        !preg_match('/^(?:profile|cache|user|setting|option|asset|system|rule|log)manager\.php$/i', $entry_base)
                                    ) {
                                        $is_fm_file = true;
                                        break;
                                    }

                                    $stream = $zip->getStream($zip->getNameIndex($i));
                                    if ($stream) {
                                        $chunk = stream_get_contents($stream, 4096);
                                        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- ZipArchive stream resource cleanup
                                        fclose($stream);
                                        if ($chunk && (
                                            preg_match('/Plugin Name:\s*.*(?:file\s*manager|fileorganizer|filester|elfinder|tinyfilemanager|file\s*explorer)/i', $chunk) ||
                                            stripos($chunk, 'TinyFileManager') !== false ||
                                            stripos($chunk, 'elFinder') !== false
                                        )) {
                                            $is_fm_file = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        $zip->close();
                    }
                }

                if ($is_fm_file) {
                    if ($log_and_ban) {
                        self::log_incident([
                            'id'          => 'WAF-DISALLOW-FILEMANAGER-PLUGIN',
                            'category'    => 'Prohibited Script Upload',
                            'description' => sprintf('Upload of standalone File Manager / Web Shell script or plugin archive "%s" was blocked by policy.', esc_html($filename)),
                            'payload'     => "Filename: {$filename} Temp: {$tmp_path}",
                        ], 'blocked');
                    }

                    $file['error']     = __('Security Firewall: Uploading standalone File Manager or explorer scripts is strictly disallowed.', 'webcare-pro-security');
                    $file['rule_id']   = 'WAF-DISALLOW-FILEMANAGER-PLUGIN';
                    $file['rule_name'] = 'Prohibited File Manager Script Upload';
                    $file['category']  = 'Prohibited Script Upload';
                    return $file;
                }
            }
        }

        return $file;
    }

    /**
     * Intercept and prevent prohibited plugin installations via WP Upgrader (Rule 1 & 2)
     *
     * @param bool|object $response
     * @param array $hook_extra Extra upgrader hook arguments (contains 'plugin', 'package', 'type')
     * @return bool|object
     */
    public static function prevent_prohibited_plugin_install($response, array $hook_extra) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return $response;
        }

        $slug = '';
        if (!empty($hook_extra['plugin'])) {
            $slug = strtolower(dirname($hook_extra['plugin']));
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (empty($slug) && !empty($_POST['slug'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $slug = strtolower(sanitize_text_field(wp_unslash($_POST['slug'])));
        }

        // Check phpMyAdmin restriction
        if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
            $pma_signatures = [
                'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                'ari-adminer', 'portable-phpmyadmin'
            ];
            foreach ($pma_signatures as $sig) {
                if (strpos($slug, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Upgrader installation of database manager / phpMyAdmin plugin ("%s") was blocked.', esc_html($slug)),
                        'payload'     => "Slug: {$slug}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_pma',
                        __('Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is disallowed by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        // Check File Manager restriction
        if (!empty($settings['waf_disallow_filemanager_plugins'])) {
            $fm_signatures = [
                'file-manager', 'filemanager', 'fileorganizer', 'filester',
                'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
            ];
            foreach ($fm_signatures as $sig) {
                if (strpos($slug, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Upgrader installation of File Manager plugin ("%s") was blocked.', esc_html($slug)),
                        'payload'     => "Slug: {$slug}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_fm',
                        __('Security Policy Violation: Installation of File Manager plugins is disallowed by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        return $response;
    }

    /**
     * Inspect unpacked plugin folder before moving to wp-content/plugins/ (catches direct ZIP upload & WP-CLI)
     *
     * @param string|\WP_Error $source Source directory of extracted plugin files.
     * @param string           $remote_source Remote source directory.
     * @param object           $upgrader Upgrader instance.
     * @param array            $hook_extra Hook extra context arguments.
     * @return string|\WP_Error
     */
    public static function inspect_unpacked_plugin_source($source, $remote_source, $upgrader, array $hook_extra = []) {
        if (is_wp_error($source)) {
            return $source;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return $source;
        }

        $folder_name = strtolower(basename(untrailingslashit($source)));

        // Check if database manager plugins disallowed
        if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
            $pma_signatures = [
                'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                'ari-adminer', 'portable-phpmyadmin'
            ];
            foreach ($pma_signatures as $sig) {
                if (strpos($folder_name, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Source verification blocked installation of database manager plugin directory ("%s").', esc_html($folder_name)),
                        'payload'     => "Folder: {$folder_name} Source: {$source}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_source_pma',
                        __('Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is prohibited by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        // Check if file manager plugins disallowed
        if (!empty($settings['waf_disallow_filemanager_plugins'])) {
            $fm_signatures = [
                'file-manager', 'filemanager', 'fileorganizer', 'filester',
                'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
            ];
            foreach ($fm_signatures as $sig) {
                if (strpos($folder_name, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Source verification blocked installation of File Manager plugin directory ("%s").', esc_html($folder_name)),
                        'payload'     => "Folder: {$folder_name} Source: {$source}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_source_fm',
                        __('Security Policy Violation: Installation of File Manager plugins is prohibited by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        // Deep inspect candidate PHP plugin headers inside the unpacked folder
        if (!empty($settings['waf_disallow_phpmyadmin_plugins']) || !empty($settings['waf_disallow_filemanager_plugins'])) {
            $php_files = @glob(trailingslashit($source) . '*.php');
            if (!empty($php_files)) {
                foreach (array_slice($php_files, 0, 10) as $php_file) {
                    $header_content = @file_get_contents($php_file, false, null, 0, 8192);
                    if (empty($header_content)) {
                        continue;
                    }

                    // Check for database manager signatures in plugin header
                    if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
                        if (
                            preg_match('/Plugin Name:\s*.*(?:phpmyadmin|adminer|database\s*browser|db-?manager|database\s*manager|sql\s*buddy)/i', $header_content) ||
                            stripos($header_content, 'PMA_sendHeaderLocation') !== false ||
                            stripos($header_content, 'Adminer - Compact database') !== false
                        ) {
                            self::log_incident([
                                'category'    => 'Security Policy Enforcement',
                                'description' => sprintf('Deep inspection blocked database manager plugin header in "%s".', esc_html(basename($php_file))),
                                'payload'     => "File: " . basename($php_file),
                            ], 'blocked');

                            return new \WP_Error(
                                'webcare_prohibited_plugin_header_pma',
                                __('Security Policy Violation: Plugin header identifies as a prohibited database manager (phpMyAdmin/Adminer).', 'webcare-pro-security')
                            );
                        }
                    }

                    // Check for file manager signatures in plugin header
                    if (!empty($settings['waf_disallow_filemanager_plugins'])) {
                        if (
                            preg_match('/Plugin Name:\s*.*(?:file\s*manager|fileorganizer|filester|elfinder|tinyfilemanager|file\s*explorer)/i', $header_content) ||
                            stripos($header_content, 'TinyFileManager') !== false ||
                            stripos($header_content, 'elFinder') !== false
                        ) {
                            self::log_incident([
                                'category'    => 'Security Policy Enforcement',
                                'description' => sprintf('Deep inspection blocked file manager plugin header in "%s".', esc_html(basename($php_file))),
                                'payload'     => "File: " . basename($php_file),
                            ], 'blocked');

                            return new \WP_Error(
                                'webcare_prohibited_plugin_header_fm',
                                __('Security Policy Violation: Plugin header identifies as a prohibited File Manager plugin.', 'webcare-pro-security')
                            );
                        }
                    }
                }
            }
        }

        return $source;
    }

    /**
     * Filter WordPress.org Plugins API results to prevent 1-click install/queries of prohibited plugins
     */
    public static function filter_prohibited_plugin_api($res, $action, $args) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return $res;
        }

        if ($action === 'plugin_information' && isset($args->slug)) {
            $slug = strtolower($args->slug);

            if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
                $pma_signatures = [
                    'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                    'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                    'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                    'ari-adminer', 'portable-phpmyadmin'
                ];
                foreach ($pma_signatures as $sig) {
                    if (strpos($slug, $sig) !== false) {
                        return new \WP_Error(
                            'webcare_disallowed_plugin',
                            __('Security Policy: phpMyAdmin and database manager plugins are blocked by WebCare Pro Security Firewall.', 'webcare-pro-security')
                        );
                    }
                }
            }

            if (!empty($settings['waf_disallow_filemanager_plugins'])) {
                $fm_signatures = [
                    'file-manager', 'filemanager', 'fileorganizer', 'filester',
                    'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                    'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
                ];
                foreach ($fm_signatures as $sig) {
                    if (strpos($slug, $sig) !== false) {
                        return new \WP_Error(
                            'webcare_disallowed_plugin',
                            __('Security Policy: File Manager plugins are blocked by WebCare Pro Security Firewall.', 'webcare-pro-security')
                        );
                    }
                }
            }
        }

        return $res;
    }

    /**
     * Generic Login Error Masking (Rule 5)
     * Replaces detailed WordPress user enumeration errors with a generic message.
     */
    public static function mask_login_errors(string $error): string {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_mask_login_errors'])) {
            return $error;
        }

        if (!empty($error)) {
            return sprintf(
                '<strong>%s:</strong> %s',
                __('Error', 'webcare-pro-security'),
                __('Invalid username, email address, or password.', 'webcare-pro-security')
            );
        }

        return $error;
    }

    /**
     * Prevent Registering 'admin' or Forbidden Usernames (Rule 4)
     */
    public static function validate_registration_username(bool $valid, string $username): bool {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_prevent_admin_registration'])) {
            return $valid;
        }

        $sanitized = strtolower(trim($username));
        if ($sanitized === 'admin') {
            return false;
        }

        return $valid;
    }

    /**
     * Registration Errors Filter (Rule 4)
     */
    public static function filter_registration_errors(\WP_Error $errors, string $sanitized_user_login, string $user_email): \WP_Error {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_prevent_admin_registration'])) {
            return $errors;
        }

        $lower = strtolower(trim($sanitized_user_login));
        if ($lower === 'admin') {
            $errors->add(
                'registration_admin_prohibited',
                __('<strong>Error:</strong> The username "admin" is reserved and prohibited for security.', 'webcare-pro-security')
            );
        }

        return $errors;
    }

    /**
     * Immediately Block IP of Users Trying to Sign in as Forbidden Usernames (Rule 3)
     */
    public static function check_forbidden_username_login($user, $username, $password) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_block_forbidden_usernames'])) {
            return $user;
        }

        if (empty($username) || !is_string($username)) {
            return $user;
        }

        $forbidden_raw = $settings['waf_forbidden_usernames_list'] ?? "admin\nadministrator\nroot";
        $forbidden_list = array_filter(array_map('trim', explode("\n", str_replace("\r", "", strtolower($forbidden_raw)))));
        if (empty($forbidden_list)) {
            $forbidden_list = ['admin', 'administrator', 'root'];
        }

        $test_user = strtolower(trim($username));
        if (in_array($test_user, $forbidden_list, true)) {
            $client_ip = self::get_client_ip();

            // Skip whitelisted IPs (with forensic telemetry)
            $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
            if ($whitelist_ctx['is_whitelisted']) {
                $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
                if ($log_telemetry) {
                    self::log_incident([
                        'id'          => 'WAF-FORBIDDEN-USERNAME-TRAP',
                        'name'        => 'Forbidden Honeypot Username Trap (Bypassed)',
                        'category'    => 'Identity Defense',
                        'description' => sprintf('Whitelisted IP tried to log in using honeypot username "%s" [Bypassed via IP Whitelist].', esc_html($username)),
                        'match_type'  => 'Honeypot Username',
                        'match_value' => $username,
                        'payload'     => "User: {$username} IP: {$client_ip}",
                    ], 'bypassed');
                }
                return $user;
            }

            // Immediately permanently block IP with full metadata
            $honeypot_incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
            self::add_blocked_ip(
                $client_ip,
                sprintf('Attacker tried to log in using forbidden honeypot username "%s". Permanently blocked.', esc_html($username)),
                0,
                'WAF-FORBIDDEN-USERNAME-TRAP',
                'Forbidden Honeypot Username Trap',
                'Identity Defense',
                $honeypot_incident_id
            );

            // Log incident
            self::log_incident([
                'id'          => 'WAF-FORBIDDEN-USERNAME-TRAP',
                'name'        => 'Forbidden Honeypot Username Trap',
                'category'    => 'Identity Defense',
                'description' => sprintf('Attacker IP tried to log in using forbidden honeypot username "%s". IP permanently banned.', esc_html($username)),
                'match_type'  => 'Honeypot Username',
                'match_value' => $username,
                'payload'     => "User: {$username} IP: {$client_ip}",
            ], 'blocked', $honeypot_incident_id);

            // Also lock in LoginHardening
            if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
                $lockouts = \WebCareProScanner\Auth\LoginHardening::get_locked_ips();
                $now = time();
                $lockouts[$client_ip] = [
                    'ip'         => $client_ip,
                    'attempts'   => 999,
                    'username'   => $username,
                    'blocked_at' => gmdate('Y-m-d H:i:s', $now),
                    'expires_at' => $now + (365 * 86400),
                    'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
                ];
                update_option(\WebCareProScanner\Auth\LoginHardening::OPTION_LOCKOUTS, $lockouts, false);
            }

            // Return immediate access denied error
            return new \WP_Error(
                'webcare_forbidden_username_blocked',
                __('<strong>Access Blocked:</strong> Attempting to sign in with this username is strictly prohibited. Your IP has been permanently banned by the security firewall.', 'webcare-pro-security')
            );
        }

        return $user;
    }

    /**
     * Enforce Strong Passwords & Check Pwned Passwords on Profile Update (Rules 6 & 7)
     */
    public static function validate_user_password_policy(\WP_Error $errors, bool $update, \stdClass $user): void {
        // phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $pass1 = isset($_POST['pass1']) ? (string) wp_unslash($_POST['pass1']) : '';
        // phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        if (empty($pass1)) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return;
        }

        // Get user roles
        $target_roles = [];
        if (!empty($user->roles) && is_array($user->roles)) {
            $target_roles = $user->roles;
        } elseif (!empty($user->role)) {
            $target_roles = [$user->role];
        } elseif (!empty($user->ID)) {
            $existing = get_userdata($user->ID);
            if ($existing) {
                $target_roles = (array) $existing->roles;
            }
        }

        // 1. Strong Passwords Check (Rule 6)
        if (!empty($settings['waf_enforce_strong_passwords'])) {
            $configured_roles_raw = $settings['waf_strong_passwords_roles'] ?? 'administrator, editor';
            $configured_roles = array_map('trim', explode(',', strtolower($configured_roles_raw)));

            $role_match = false;
            foreach ($target_roles as $r) {
                if (in_array(strtolower($r), $configured_roles, true)) {
                    $role_match = true;
                    break;
                }
            }

            if ($role_match && !self::check_password_strength($pass1)) {
                $errors->add(
                    'webcare_weak_password',
                    __('<strong>Security Policy:</strong> Your role requires a strong password. It must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and symbols.', 'webcare-pro-security')
                );
            }
        }

        // 2. Leaked / Pwned Passwords Check (Rule 7)
        if (!empty($settings['waf_check_pwned_passwords'])) {
            if (self::is_password_pwned($pass1)) {
                $errors->add(
                    'webcare_pwned_password',
                    __('<strong>Security Breach Warning:</strong> This password has appeared in known public data breaches and cannot be used. Please choose a different, secure password.', 'webcare-pro-security')
                );
            }
        }
    }

    /**
     * Enforce Strong Passwords & Check Pwned Passwords on Reset Password (Rules 6 & 7)
     */
    public static function validate_reset_password_policy(\WP_Error $errors, $user): void {
        // phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $pass1 = isset($_POST['pass1']) ? (string) wp_unslash($_POST['pass1']) : '';
        // phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        if (empty($pass1) || !is_object($user)) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return;
        }

        $target_roles = (array) ($user->roles ?? []);

        // Strong password check
        if (!empty($settings['waf_enforce_strong_passwords'])) {
            $configured_roles_raw = $settings['waf_strong_passwords_roles'] ?? 'administrator, editor';
            $configured_roles = array_map('trim', explode(',', strtolower($configured_roles_raw)));

            $role_match = false;
            foreach ($target_roles as $r) {
                if (in_array(strtolower($r), $configured_roles, true)) {
                    $role_match = true;
                    break;
                }
            }

            if ($role_match && !self::check_password_strength($pass1)) {
                $errors->add(
                    'webcare_weak_password',
                    __('<strong>Security Policy:</strong> Your role requires a strong password. It must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and symbols.', 'webcare-pro-security')
                );
            }
        }

        // Leaked password check
        if (!empty($settings['waf_check_pwned_passwords'])) {
            if (self::is_password_pwned($pass1)) {
                $errors->add(
                    'webcare_pwned_password',
                    __('<strong>Security Breach Warning:</strong> This password has appeared in known public data breaches and cannot be used. Please choose a different, secure password.', 'webcare-pro-security')
                );
            }
        }
    }

    /**
     * Validate password complexity: Min 12 chars, upper, lower, number, symbol
     */
    public static function check_password_strength(string $password): bool {
        if (strlen($password) < 12) {
            return false;
        }
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }
        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return false;
        }
        return true;
    }

    /**
     * Check if a password was compromised in public data breaches using HaveIBeenPwned k-Anonymity API
     */
    public static function is_password_pwned(string $password): bool {
        $hash   = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $url = 'https://api.pwnedpasswords.com/range/' . $prefix;
        $response = wp_remote_get($url, [
            'timeout'   => 3,
            'sslverify' => true,
            'headers'   => [
                'User-Agent' => 'WEBCARE-Security-Scanner-Password-Sentinel/1.0',
            ],
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Fail open if HIBP API is unreachable to prevent locking out legitimate admins
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $lines = explode("\n", str_replace("\r", "", $body));

        foreach ($lines as $line) {
            $parts = explode(':', trim($line));
            if (strtoupper($parts[0]) === $suffix) {
                $count = isset($parts[1]) ? (int) $parts[1] : 0;
                if ($count > 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Handle firewall rule violation with mode sensitivity (learning vs blocking).
     *
     * @param array  $rule
     * @param array  $settings
     * @param string $client_ip
     * @param int    $status_code
     * @return void
     */
    /**
     * Determine if an IP matches the configured whitelist and whether the current session qualifies for complete bypass.
     *
     * Two-Tier Context-Aware Architecture:
     * - Tier 1 (Pre-Auth): IP is in whitelist, but user is NOT logged in as Administrator.
     *   Can bypass operational/rate-limiting/debug rules, but CANNOT bypass critical exploits (SQLi, Webshell, RCE, LFI).
     * - Tier 2 (Post-Auth): IP is in whitelist AND user is verified Authenticated Administrator.
     *   Full developer/administrator bypass across all firewall checks.
     *
     * @param string $client_ip
     * @param array  $settings
     * @return array [ 'is_whitelisted' => bool, 'is_admin' => bool, 'full_bypass' => bool ]
     */
    public static function check_ip_whitelist_context(string $client_ip, array $settings, ?array $rule = null): array {
        $whitelist_str = $settings['waf_whitelisted_ips'] ?? '';
        $is_whitelisted = self::is_ip_whitelisted($client_ip, $whitelist_str);

        if (!$is_whitelisted) {
            return [
                'is_whitelisted' => false,
                'is_admin'       => false,
                'full_bypass'    => false,
                'rule_bypass'    => false,
            ];
        }

        // Check if this IP has granular rule or category scoping
        $all_meta = self::get_all_whitelist_meta();
        $meta = $all_meta[$client_ip] ?? null;

        if ($meta && !empty($meta['expires_at']) && time() > (int) $meta['expires_at']) {
            return [
                'is_whitelisted' => false,
                'is_admin'       => false,
                'full_bypass'    => false,
                'rule_bypass'    => false,
            ];
        }

        $rule_bypass = false;
        if ($meta && !empty($meta['scope']) && $meta['scope'] !== 'global') {
            $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            $endpoint_allowed = empty($meta['endpoint']) || strpos($req_uri, $meta['endpoint']) !== false;

            if ($endpoint_allowed && $rule !== null) {
                if ($meta['scope'] === 'rule') {
                    $rule_id = (string) ($rule['id'] ?? '');
                    $allowed_rules = (array) ($meta['allowed_rules'] ?? []);
                    if (!empty($rule_id) && in_array($rule_id, $allowed_rules, true)) {
                        $rule_bypass = true;
                    }
                } elseif ($meta['scope'] === 'category') {
                    $rule_cat = (string) ($rule['category'] ?? '');
                    $allowed_cats = (array) ($meta['allowed_cats'] ?? []);
                    if (!empty($rule_cat) && in_array($rule_cat, $allowed_cats, true)) {
                        $rule_bypass = true;
                    }
                }
            }

            // Scoped rule allowlist: only bypasses if matched!
            return [
                'is_whitelisted' => true,
                'is_admin'       => false,
                'full_bypass'    => false,
                'rule_bypass'    => $rule_bypass,
            ];
        }

        $is_admin = self::is_authenticated_administrator();
        $require_admin = isset($settings['waf_whitelist_require_admin']) ? !empty($settings['waf_whitelist_require_admin']) : true;

        // If require_admin is FALSE, all whitelisted traffic gets full bypass (classic mode).
        // If require_admin is TRUE, only authenticated admins get full bypass; unauthenticated get tiered pre-auth protection.
        $full_bypass = !$require_admin || $is_admin;

        return [
            'is_whitelisted' => true,
            'is_admin'       => $is_admin,
            'full_bypass'    => $full_bypass,
            'rule_bypass'    => false,
        ];
    }

    /**
     * Handle firewall rule violation with mode sensitivity (learning vs blocking).
     *
     * @param array  $rule
     * @param array  $settings
     * @param string $client_ip
     * @param int    $status_code
     * @return void
     */
    public static function handle_rule_violation(array $rule, array $settings, string $client_ip, int $status_code = 403): void {
        // Honor ModularFirewallSynthesizer runtime exempt rule IDs (WCP-14)
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            $modular_exempt_ids = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_runtime_exempt_rule_ids();
            $cand_id = strtoupper((string) ($rule['id'] ?? ''));
            $is_exemptible_rule = (bool) preg_match('/^(?:MOD-(?:AJAX|REST|CVE|CUSTOM|UPLOAD|EGRESS)-[A-Z0-9_\-]+|BOT-[A-Z0-9_\-]+|RATE-[A-Z0-9_\-]+)$/', $cand_id);
            if ($is_exemptible_rule && !empty($modular_exempt_ids) && in_array($cand_id, $modular_exempt_ids, true)) {
                return;
            }
        }

        // Red Team Drill Intercept Handler
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['webcare_drill_token']) ? sanitize_text_field(wp_unslash($_GET['webcare_drill_token'])) : (isset($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WebCareProScanner\\Security\\AttackSimulationEngine') && \WebCareProScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            \WebCareProScanner\Security\AttackSimulationEngine::record_intercept($drill_token, $rule, $status_code);
            header('X-WebCare-Drill-Intercepted: 1');
            header('X-WebCare-Drill-Rule-ID: ' . rawurlencode($rule['id'] ?? 'WAF-INTERCEPT'));
            header('X-WebCare-Drill-Category: ' . rawurlencode($rule['category'] ?? 'WAF'));
            status_header($status_code);
            echo wp_json_encode([
                'success'     => false,
                'drill'       => true,
                'intercepted' => true,
                'rule_id'     => $rule['id'] ?? 'WAF-INTERCEPT',
                'category'    => $rule['category'] ?? 'WAF',
                'status_code' => $status_code,
            ]);
            exit;
        }

        // Tiered Context-Aware & Rule-Scoped IP Whitelist Interceptor
        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings, $rule);
        if ($whitelist_ctx['is_whitelisted']) {
            $is_admin = $whitelist_ctx['is_admin'];
            $full_bypass = $whitelist_ctx['full_bypass'];
            $rule_bypass = !empty($whitelist_ctx['rule_bypass']);

            // Critical Exploit Categories & Explicit Custom Rules that Pre-Auth (unauthenticated) traffic can NEVER bypass on global mode
            $critical_exploit_categories = [
                'SQL Injection',
                'PHP Code Injection',
                'Path Traversal',
                'Cross-Site Scripting (XSS)',
                'Execution Armor',
                'AI & Agent Defense',
                'Virtual Patch',
                'Next-Gen SQL RASP Defense',
                'Next-Gen Response DLP',
                'Modern API & GraphQL Shield',
                'AI Agent Kill-Chain Defense',
            ];
            $rule_id_check = (string) ($rule['id'] ?? '');
            $rule_cat      = (string) ($rule['category'] ?? '');
            $is_critical_exploit = in_array($rule_cat, $critical_exploit_categories, true)
                || strpos($rule_id_check, 'MOD-CUSTOM-') === 0
                || strpos($rule_id_check, 'WAF-SQL-RASP-') === 0
                || strpos($rule_id_check, 'WAF-DLP-') === 0
                || strpos($rule_id_check, 'WAF-GRAPHQL-') === 0
                || $rule_id_check === 'WAF-AI-AGENT-KILLCHAIN';

            // If granted specific rule/category exemption, OR
            // if full bypass is permitted (verified authenticated admin session), OR
            // if this is an operational / rate limit / scan probe rule (NOT a critical exploit payload):
            if ($rule_bypass || $full_bypass || !$is_critical_exploit) {
                // Log incident telemetry as 'bypassed' if telemetry logging is enabled
                $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
                if ($log_telemetry) {
                    $bypass_rule = $rule;
                    if ($rule_bypass) {
                        $bypass_context = 'Rule-Scoped Allowlist Exemption';
                    } elseif ($is_admin) {
                        $bypass_context = 'Authenticated Administrator Session';
                    } else {
                        $bypass_context = 'Pre-Auth Whitelisted IP';
                    }
                    $bypass_rule['description'] = ($rule['description'] ?? 'Firewall trigger') . " [Bypassed via {$bypass_context}]";
                    self::log_incident($bypass_rule, 'bypassed');
                }
                return; // Traffic allowed without dropping connection
            }
        }

        $mode = $settings['waf_mode'] ?? 'enabled';

        // Check Synthesized Exemptions (CAF Phase 3): 1-Click safe-passes generated via Learning Mode
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\LearningModeEngine')) {
            $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
            $r_id = (string) ($rule['id'] ?? '');
            if (\WebCareProScanner\Firewall\CAF\LearningModeEngine::is_request_exempted($req_uri, $r_id)) {
                $bypass_rule = $rule;
                $bypass_rule['description'] = ($rule['description'] ?? 'Firewall trigger') . ' [Bypassed via Synthesized Exemption]';
                self::log_incident($bypass_rule, 'bypassed');
                return; // Granted targeted safe-pass!
            }

            // If in learning mode or CAF adaptive learning mode active: record observation
            if ($mode === 'learning' || !empty($settings['caf_adaptive_learning_mode'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Passive observation recording of incoming request payload
                \WebCareProScanner\Firewall\CAF\LearningModeEngine::record_observation($rule, $client_ip, $req_uri, array_merge((array)($_GET ?? []), (array)($_POST ?? [])));
            }
        }

        if ($mode === 'learning') {
            if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine') && \WebCareProScanner\Firewall\LearningModeEngine::is_route_graduated()) {
                // Route has graduated: enforce blocking even during global learning mode!
            } else {
                if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine')) {
                    \WebCareProScanner\Firewall\LearningModeEngine::record_threat_encountered(\WebCareProScanner\Firewall\LearningModeEngine::get_current_route_key());
                }
                self::log_incident($rule, 'detected');
                return;
            }
        } elseif ($mode === 'enabled') {
            // Check if specific route was explicitly forced into learning mode by admin
            if (class_exists('\\WebCareProScanner\\Firewall\\LearningModeEngine')) {
                $route_key = \WebCareProScanner\Firewall\LearningModeEngine::get_current_route_key();
                $profiles = get_option(\WebCareProScanner\Firewall\LearningModeEngine::OPTION_PROFILES, []);
                if (isset($profiles[$route_key]['forced_status']) && $profiles[$route_key]['forced_status'] === 'learning') {
                    \WebCareProScanner\Firewall\LearningModeEngine::record_threat_encountered($route_key);
                    self::log_incident($rule, 'detected');
                    return;
                }
            }
        }

        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
        self::log_incident($rule, 'blocked', $incident_id);

        // Record blocked probe for 60-second rolling velocity counter (OS-01)
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker')) {
            \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker::record_blocked_probe();
        }

        // Record differential threat score event & trigger immediate Cloudflare Edge Ban on critical exploits
        $rule_id_str = (string) ($rule['id'] ?? '');
        $rule_cat    = (string) ($rule['category'] ?? '');
        $critical_ban_categories = [
            'SQL Injection',
            'PHP Code Injection',
            'Execution Armor',
            'Path Traversal',
            'Cross-Site Scripting (XSS)',
            'Malicious File Upload',
            'Virtual Patch',
            'AI & Agent Defense',
            'Null Byte Poison',
            'SSRF Defense',
        ];

        $is_instant_ban_exploit = in_array($rule_cat, $critical_ban_categories, true)
            || str_contains($rule_id_str, 'VPATCH')
            || str_contains($rule_id_str, 'SQLI')
            || str_contains($rule_id_str, 'RCE')
            || str_contains($rule_id_str, 'NULL-BYTE')
            || str_contains($rule_id_str, 'SSRF')
            || str_contains($rule_id_str, 'OBJECT-STREAM')
            || str_contains($rule_id_str, 'SENSITIVE')
            || str_contains($rule_id_str, 'LOG-EXFIL')
            || str_contains($rule_id_str, 'POLYGLOT')
            || str_contains($rule_id_str, 'SHORTCODE-GADGET')
            || str_contains($rule_id_str, 'INTERACTIVITY-POISON')
            || str_contains($rule_id_str, 'FORGED-WEBHOOK')
            || str_contains($rule_id_str, 'AUTH-TYPE-CONFUSION')
            || str_contains($rule_id_str, 'REST-METHOD-SMUGGLE');

        $rule_ban_ttl       = max(0, (int) ($rule['ban_ttl'] ?? 0));
        $has_explicit_sync  = array_key_exists('sync_cloudflare', $rule);
        $rule_sync_cf       = $has_explicit_sync ? !empty($rule['sync_cloudflare']) : true;
        $wants_custom_ban   = !empty($rule['sync_cloudflare']) || $rule_ban_ttl > 0;

        if ($is_instant_ban_exploit || $wants_custom_ban) {
            $effective_ban_ttl = $rule_ban_ttl > 0 ? $rule_ban_ttl : 86400;
            $ban_reason        = sprintf('[%s] %s', $rule_id_str ?: $rule_cat, $rule['description'] ?? 'Critical WAF exploit intercepted');
            self::add_blocked_ip(
                $client_ip,
                $ban_reason,
                $effective_ban_ttl,
                $rule_id_str ?: 'WAF-CRITICAL',
                $rule['name'] ?? $rule_cat,
                $rule_cat,
                $incident_id,
                null,
                $rule_sync_cf
            );
        } elseif (class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            // Skip ThreatScoreTracker accumulation when genuine crawlers follow on-page links (?add-to-cart= or /wp-login.php) with GET/HEAD
            $req_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
            if ($rule_id_str === 'BOT-CRAWLER-MUTATION-BLOCKED' && in_array($req_method, ['GET', 'HEAD', 'OPTIONS'], true)) {
                // Return 403 block on the specific link without accumulating toward a 24h IP ban for genuine crawlers
            } else {
                $event_type = 'probe_404';
                if (str_contains($rule_id_str, 'HONEY') || str_contains($rule_id_str, 'SENSITIVE') || str_contains($rule_id_str, 'ENV') || str_contains($rule_id_str, 'GIT')) {
                    $event_type = 'honeypot';
                } elseif (str_contains($rule_id_str, 'DORMANT') || str_contains($rule_id_str, 'CAF')) {
                    $event_type = 'dormant_surface';
                } elseif (str_contains($rule_id_str, 'AUTH') || str_contains($rule_id_str, 'LOGIN') || str_contains($rule_id_str, 'XMLRPC')) {
                    $event_type = 'auth_fail';
                }
                \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, $event_type);
            }
        }

        // Surge detection: Check if blocked count in the last 60 seconds exceeds surge threshold (e.g. 15 blocks/min)
        $surge_key = 'webcareproscan_waf_block_surge_window';
        $blocks = (int) get_transient($surge_key) + 1;
        set_transient($surge_key, $blocks, 60);

        if ($blocks === 15 || ($blocks > 15 && $blocks % 25 === 0)) {
            $surge_alert_sent = get_transient('webcareproscan_waf_block_surge_alerted');
            if (!$surge_alert_sent && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                set_transient('webcareproscan_waf_block_surge_alerted', 1, 300); // Throttle alerts to once per 5 minutes
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('waf_block_surge', [
                    'severity' => 'high',
                    /* translators: 1: number of blocks */
                    'message'  => sprintf(__('WAF Lite intercepted an abnormal surge of blocked attacks (%1$d blocks in under 60 seconds).', 'webcare-pro-security'), $blocks),
                    'details'  => [
                        'Blocks in Window' => $blocks,
                        'Latest Attacker'  => $client_ip,
                        'Triggering Rule'  => $rule['title'] ?? ($rule['id'] ?? 'WAF Rule'),
                        'Incident ID'      => $incident_id,
                    ],
                ]);
            }
        }

        if ($status_code !== 403) {
            status_header($status_code);
        }

        self::render_block_page($rule, $client_ip, $incident_id);
        exit;
    }

    /**
     * Strict Host Header & Forwarded Host Header Allowlist Validator (Rule #32).
     * Defends against Host Header Poisoning, Password Reset Poisoning, and Cache Poisoning.
     *
     * @param array $settings
     * @return bool
     */
    public static function validate_host_headers(array $settings): bool {
        $raw_host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
        if (empty($raw_host)) {
            return false;
        }

        // Strip port if present (e.g. localhost:8181 -> localhost)
        $clean_host = strtolower(trim(preg_replace('/:\d+$/', '', $raw_host)));

        // Build list of valid hosts from site_url, home_url, and optional aliases
        $allowed = [];

        $site_host = wp_parse_url(site_url(), PHP_URL_HOST);
        if ($site_host) {
            $allowed[] = strtolower($site_host);
        }

        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        if ($home_host) {
            $allowed[] = strtolower($home_host);
        }

        // Automatically tolerate www vs non-www variant of configured site domains
        foreach ([$site_host, $home_host] as $h) {
            if ($h) {
                $h = strtolower($h);
                if (strpos($h, 'www.') === 0) {
                    $allowed[] = substr($h, 4);
                } else {
                    $allowed[] = 'www.' . $h;
                }
            }
        }

        // Custom administrator aliases
        $custom_aliases = $settings['waf_allowed_host_aliases'] ?? '';
        if (!empty($custom_aliases)) {
            $lines = preg_split('/[\r\n,]+/', $custom_aliases);
            foreach ($lines as $line) {
                $alias = strtolower(trim($line));
                if ($alias !== '') {
                    $alias = preg_replace('/:\d+$/', '', $alias);
                    $allowed[] = $alias;
                }
            }
        }

        $allowed = array_unique(array_filter($allowed));

        // 1. Verify HTTP_HOST against allowed list
        if (!in_array($clean_host, $allowed, true)) {
            return false;
        }

        // 2. If HTTP_X_FORWARDED_HOST is present, every host segment MUST strictly match the allowed list and cannot contain @
        if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
            $fwd_raw = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_HOST'])));
            foreach ($fwd_raw as $raw_seg) {
                $fwd_host = strtolower(trim(preg_replace('/:\d+$/', '', $raw_seg)));
                if ($fwd_host === '' || strpos($fwd_host, '@') !== false || !in_array($fwd_host, $allowed, true)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Sliding Transient Rate Limiter for firewall controls.
     *
     * @param string $key Unique identifier (e.g. 'lostpw:ip:127.0.0.1')
     * @param int    $limit Max requests allowed
     * @param int    $window_seconds Window duration in seconds
     * @return array ['allowed' => bool, 'retry_after' => int, 'current' => int]
     */
    public static function check_rate_limit(string $key, int $limit, int $window_seconds): array {
        $transient_name = 'webcareproscan_rl_' . substr(md5($key), 0, 24);
        $data = get_transient($transient_name);
        $now = time();

        if ($data === false || !is_array($data) || empty($data['reset'])) {
            $data = [
                'count' => 1,
                'reset' => $now + $window_seconds,
            ];
            set_transient($transient_name, $data, $window_seconds);
            return [
                'allowed'     => true,
                'retry_after' => 0,
                'current'     => 1,
            ];
        }

        if ($now > $data['reset']) {
            $data = [
                'count' => 1,
                'reset' => $now + $window_seconds,
            ];
            set_transient($transient_name, $data, $window_seconds);
            return [
                'allowed'     => true,
                'retry_after' => 0,
                'current'     => 1,
            ];
        }

        $data['count'] = (int) $data['count'] + 1;
        $remaining_ttl = max(1, $data['reset'] - $now);
        set_transient($transient_name, $data, $remaining_ttl);

        if ($data['count'] > $limit) {
            return [
                'allowed'     => false,
                'retry_after' => $remaining_ttl,
                'current'     => $data['count'],
            ];
        }

        return [
            'allowed'     => true,
            'retry_after' => 0,
            'current'     => $data['count'],
        ];
    }

    /**
     * Rule #29: REST API User Enumeration Interceptor.
     * Blocks unauthenticated access to /wp-json/wp/v2/users, user archives, and ?rest_route=/wp/v2/users.
     *
     * @param mixed $access
     * @return mixed
     */
    public static function check_rest_user_enumeration($access) {
        if (is_wp_error($access)) {
            return $access;
        }

        // Authenticated users are completely permitted
        if (is_user_logged_in() || self::is_authenticated_administrator()) {
            return $access;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return $access;
        }

        if (empty($settings['waf_block_rest_user_enum'])) {
            return $access;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public REST query check
        $rest_route  = isset($_GET['rest_route']) ? sanitize_text_field(wp_unslash($_GET['rest_route'])) : null;
        $canonical_route = self::canonicalize_rest_route($request_uri, $rest_route);

        // Check for /wp/v2/users endpoint queries
        $is_user_endpoint = ($canonical_route === '/wp/v2/users' || str_starts_with($canonical_route, '/wp/v2/users/'));

        if (!$is_user_endpoint) {
            return $access;
        }

        // Allow /wp/v2/users/me (standard profile query) to flow to core auth handler
        // Canonical comparison prevents query-string smuggling (e.g. /wp/v2/users?bypass=/wp/v2/users/me)
        if ($canonical_route === '/wp/v2/users/me') {
            return $access;
        }

        $client_ip = self::get_client_ip();

        $rule_triggered = [
            'id'          => 'WAF-REST-USER-ENUM',
            'name'        => 'REST API User Enumeration Interceptor',
            'category'    => 'Reconnaissance & Enumeration',
            'description' => 'Unauthenticated REST API user enumeration request intercepted on /wp/v2/users.',
            'match_type'  => 'REST Route Intercept',
            'match_value' => '/wp/v2/users',
            'payload'     => "URI: {$request_uri} IP: {$client_ip}",
        ];

        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            if ($whitelist_ctx['full_bypass'] || true) { // User enumeration is an operational probe, whitelisted IP can bypass
                $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
                if ($log_telemetry) {
                    $bypass_rule = $rule_triggered;
                    $bypass_rule['description'] .= ' [Bypassed via IP Whitelist]';
                    self::log_incident($bypass_rule, 'bypassed');
                }
                return $access;
            }
        }

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            self::log_incident($rule_triggered, 'detected');
            return $access;
        }

        self::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'rest_user_enum_forbidden',
            __('User enumeration via REST API is disabled by WebCare Pro Security Firewall.', 'webcare-pro-security'),
            ['status' => 403]
        );
    }

    /**
     * Rule #30: Author Permalink Query Suppression (?author=N).
     * Defends against query-based author enumeration scans that probe WordPress user IDs to harvest usernames.
     *
     * @return void
     */
    public static function check_author_scan_suppression(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Author enumeration scan inspection
        if (!isset($_GET['author'])) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_block_author_scan'])) {
            return;
        }

        // Only suppress if unauthenticated or non-editor (editors may need author filters in admin)
        if (is_admin() || current_user_can('edit_others_posts')) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $author_param = isset($_GET['author']) ? sanitize_text_field(wp_unslash($_GET['author'])) : '';
        if (!preg_match('/^[0-9]+$/', trim($author_param))) {
            return;
        }

        $client_ip = self::get_client_ip();

        $rule_triggered = [
            'id'          => 'WAF-AUTHOR-ENUM',
            'name'        => 'Author Permalink Enumeration Suppression',
            'category'    => 'Reconnaissance & Enumeration',
            'description' => sprintf('Author ID enumeration query (?author=%s) blocked from harvesting usernames.', esc_html($author_param)),
            'match_type'  => 'Author Query Probe',
            'match_value' => '?author=' . $author_param,
            'payload'     => "URI: {$author_param} IP: {$client_ip}",
        ];

        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
            if ($log_telemetry) {
                $bypass_rule = $rule_triggered;
                $bypass_rule['description'] .= ' [Bypassed via IP Whitelist]';
                self::log_incident($bypass_rule, 'bypassed');
            }
            return;
        }

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            self::log_incident($rule_triggered, 'detected');
            return;
        }

        self::log_incident($rule_triggered, 'blocked');

        // Clean suppression: 301 Permanent Redirect to homepage, preventing username enumeration leaks
        wp_safe_redirect(home_url('/'), 301);
        exit;
    }

    /**
     * Rule #31: Lost-Password Rate Limiter on Form View (GET).
     * Prevents automated bots from flooding the lost password endpoint.
     *
     * @return void
     */
    public static function check_lostpassword_flood(): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_limit_lostpassword'])) {
            return;
        }

        $client_ip = self::get_client_ip();

        // Allow max 10 view requests per 15 minutes per IP
        $rate_check = self::check_rate_limit('lostpw_view:' . md5($client_ip), 10, 900);
        if (!$rate_check['allowed']) {
            $rule_triggered = [
                'id'          => 'WAF-LOSTPW-VIEW-FLOOD',
                'name'        => 'Lost-Password View Burst Limit Exceeded',
                'category'    => 'Brute Force & Auth Armor',
                'description' => 'Client IP exceeded threshold for lost-password page views.',
                'match_type'  => 'Form Rate Limiting',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip}",
            ];

            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 429);
                    }
    }

    /**
     * Rule #31: Lost-Password Reset Submission Guard (POST).
     * Rate-limits password reset email triggers per IP (max 3 / 15m) and per target user (max 3 / 15m).
     * Defends against transactional email quota exhaustion and inbox bombing.
     *
     * @return void
     */
    public static function check_lostpassword_submission(): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_limit_lostpassword'])) {
            return;
        }

        $client_ip = self::get_client_ip();

        // 1. IP-based limit: max 3 reset submissions per 15 minutes
        $ip_check = self::check_rate_limit('lostpw_post_ip:' . md5($client_ip), 3, 900);
        if (!$ip_check['allowed']) {
            $rule_triggered = [
                'id'          => 'WAF-LOSTPW-FLOOD-IP',
                'name'        => 'Lost-Password Request Flood Limit (IP)',
                'category'    => 'Brute Force & Auth Armor',
                'description' => sprintf('Too many password reset requests from IP (%s). Limit is 3 per 15 minutes.', $client_ip),
                'match_type'  => 'Email Flood Protection',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Submissions: {$ip_check['current']}",
            ];

            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 429);
                    }

        // 2. User/Login identifier-based limit: max 3 reset submissions per target login/email per 15 minutes
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Lost password POST form submission rate limiting
        $user_login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';
        if (!empty($user_login)) {
            $user_key = 'lostpw_post_user:' . md5(strtolower(trim($user_login)));
            $user_check = self::check_rate_limit($user_key, 3, 900);
            if (!$user_check['allowed']) {
                $rule_triggered = [
                    'id'          => 'WAF-LOSTPW-FLOOD-USER',
                    'name'        => 'Lost-Password Target User Bombing Guard',
                    'category'    => 'Brute Force & Auth Armor',
                    'description' => 'Too many password reset requests targeted at this account identifier within 15 minutes.',
                    'match_type'  => 'Email Bombing Defense',
                    'match_value' => substr(md5($user_login), 0, 10),
                    'payload'     => "Target hash: " . md5($user_login) . " IP: {$client_ip}",
                ];

                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 429);
                            }
        }
    }

    /**
     * Rule #36: Guest admin-ajax.php & admin-post.php Action Matrix Guard.
     * Evaluates unauthenticated visitors invoking WordPress backend entrypoints.
     * Enforces Tier 1 default allowed guest actions and custom administrator allowlist.
     * In 'monitor' mode: logs unknown probes to WAF telemetry without blocking.
     * In 'block' mode: terminates unregistered guest actions with HTTP 403 / 400.
     *
     * @param string $request_uri
     * @param array $settings
     * @param string $client_ip
     * @return void
     */
    public static function check_guest_ajax_policy(string $request_uri, array $settings, string $client_ip): void {
        $policy = $settings['waf_guest_ajax_policy'] ?? 'monitor';
        if ($policy === 'off') {
            return;
        }

        $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
        $is_ajax = strpos($clean_path, 'admin-ajax.php') !== false;
        $is_post = strpos($clean_path, 'admin-post.php') !== false;

        if (!$is_ajax && !$is_post) {
            return;
        }

        // Apply policy strictly to unauthenticated visitors
        $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in())
            || self::is_authenticated_administrator()
            || self::is_authenticated_editor_or_builder();

        if ($is_logged_in) {
            return;
        }

        // Server Origin & Host Loopback Immunity:
        // Internal loopback requests originating from the server itself (e.g. Wordfence scan forks,
        // Gravity Forms background tasks, local wp-cron) are trusted internal operations.
        if (self::is_server_origin_or_loopback($client_ip)) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early guest action matrix inspection
        $action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
        $endpoint_name = $is_ajax ? 'admin-ajax.php' : 'admin-post.php';

        // 1. Missing or Empty Action Handling
        if ($action === '') {
            $rule_triggered = [
                'id'          => 'WAF-GUEST-AJAX-EMPTY',
                'name'        => 'Guest Endpoint Missing Action Probe (Rule #36)',
                'category'    => 'Protocol Defense',
                'description' => sprintf('Unauthenticated hit to %s without an action parameter.', $endpoint_name),
                'match_type'  => 'Missing Action Probe',
                'match_value' => $endpoint_name,
                'payload'     => "Endpoint: {$endpoint_name} IP: {$client_ip}",
            ];

            if ($policy === 'block') {
                self::log_incident($rule_triggered, 'blocked');
                status_header(400);
                header('Content-Type: application/json; charset=utf-8');
                echo wp_json_encode([
                    'success' => false,
                    'data'    => 'Missing or invalid action parameter.'
                ]);
                exit;
            }

            // In monitor mode, record telemetry and allow fall-through to core
            self::log_incident($rule_triggered, 'monitored');
            return;
        }

        // 2. Tier 1 Built-in Allowed Actions Hash Map (O(1) lookup)
        static $tier1_actions = null;
        if ($tier1_actions === null) {
            $tier1_actions = array_fill_keys([
                // WordPress Core & Heartbeat
                'heartbeat',
                // WooCommerce Customer & Cart Lifecycle (Always permitted for guests regardless of session)
                'woocommerce_get_refreshed_fragments',
                'woocommerce_add_to_cart',
                'woocommerce_apply_coupon',
                'woocommerce_remove_coupon',
                'woocommerce_update_shipping_method',
                'woocommerce_update_order_review',
                'woocommerce_checkout',
                'woocommerce_get_customer_location',
                // Form Plugins (CF7, WPForms, Fluent Forms, Gravity Forms, Ninja Forms, Formidable, WS Form, HappyForms, Everest)
                'wpforms_submit',
                'wpforms_form_submit',
                'wpforms_file_upload',
                'fluentform_submit',
                'fluentform_file_upload',
                'fluentform_form_submit',
                'ninja_forms_ajax_submit',
                'nf_ajax_submit',
                'frm_entries_create',
                'frm_entries_update',
                'gform_submit',
                'gform_ajax',
                'wsf_submit',
                'happyforms_message',
                'everest_forms_ajax_submit',
                // Frontend Content Loaders & Live Search
                'load_more_posts',
                'infinite_scroll',
                'search_autocomplete',
                'ajax_search',
                'wp_ajax_nopriv_search',
                // WooCommerce Compliance, Tax & VAT Gateways (EAS EU Compliance, Avalara, TaxJar)
                'eascompliance_status_ajax',
                'eas_compliance_ajax',
                'eas_tax_calculation',
                'woocommerce_calc_line_taxes',
                // Security & Audit Companion Plugins (Wordfence Security loopbacks & test AJAX)
                'wordfence_doScan',
                'wordfence_testAjax',
                // Gravity Forms Personal Data & Upload Handlers
                'wp_gf_personal_data',
                'gf_ajax_upload',
                // AffiliateWP Guest Referral Tracking & Nonces
                'affwp_track_visit',
                'affwp_get_affiliate_id',
                // Ninja Forms Guest File Upload Nonce Fetcher
                'nf_fu_get_new_nonce',
                // WooCommerce Payment Gateway Handshakes (PayPal Payments & Stripe Checkout AJAX)
                'ppc-sdk-v6-client-token',
                'ppc_create_order',
                'ppc_approve_order',
                'wc_stripe_create_order',
                'wc_stripe_get_cart_details',
            ], true);
        }

        // Only permit Plugin Check admin runner AJAX when executed by an authenticated admin or trusted runtime
        if ($action === 'plugin_check_run_checks' && (self::is_authenticated_administrator() || self::is_trusted_plugin_check_or_cli_runtime())) {
            return;
        }

        if (isset($tier1_actions[$action])) {
            // Rule #39: Check coupon lockout for apply_coupon action
            if ($action === 'apply_coupon' || $action === 'woocommerce_apply_coupon') {
                $coupon_lock_error = self::check_woo_coupon_lockout();
                if ($coupon_lock_error) {
                    if (wp_doing_ajax()) {
                        wp_send_json([
                            'result'   => 'failure',
                            'messages' => '<ul class="woocommerce-error" role="alert"><li>' . esc_html($coupon_lock_error->get_error_message()) . '</li></ul>',
                        ]);
                        exit;
                    }
                    if (function_exists('wc_add_notice')) {
                        wc_add_notice($coupon_lock_error->get_error_message(), 'error');
                    }
                }
            }
            return; // Legitimate Tier 1 guest action permitted
        }

        // Smart E-Commerce & Checkout Context Heuristic:
        // If the request originates from an active WooCommerce checkout/cart session or referer
        // and uses a known storefront prefix (e.g. eascompliance_, wc_, woocommerce_), permit smoothly
        $action_lower = strtolower($action);
        if (str_starts_with($action_lower, 'eascompliance_') || str_starts_with($action_lower, 'eas_')) {
            return;
        }

        $referer_raw      = isset($_SERVER['HTTP_REFERER']) ? strtolower(esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER']))) : '';
        $referer_host     = $referer_raw !== '' ? strtolower((string) wp_parse_url($referer_raw, PHP_URL_HOST)) : '';
        $home_host        = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $same_origin_cart = $referer_raw !== ''
            && $referer_host !== ''
            && $home_host !== ''
            && $referer_host === $home_host
            && (strpos($referer_raw, '/checkout') !== false || strpos($referer_raw, '/cart') !== false);
        if (self::has_active_shopper_session() || $same_origin_cart) {
            if (str_starts_with($action_lower, 'wc_') || str_starts_with($action_lower, 'woocommerce_') || strpos($action_lower, 'tax') !== false || strpos($action_lower, 'vat') !== false || strpos($action_lower, 'shipping') !== false) {
                return; // Auto-pass benign cart/checkout companion plugin actions
            }
        }

        // 3. Custom Administrator Allowlist Lookup (Case-Insensitive)
        $custom_allowlist_raw = $settings['waf_guest_ajax_custom_allowlist'] ?? '';
        if (!empty($custom_allowlist_raw)) {
            $custom_actions = array_map('strtolower', array_filter(array_map('trim', explode("\n", $custom_allowlist_raw))));
            if (in_array(strtolower($action), $custom_actions, true)) {
                return; // Custom permitted guest action
            }
        }

        // 4. Unknown Guest Action Handling
        $rule_triggered = [
            'id'          => 'WAF-GUEST-AJAX-PROBE',
            'name'        => 'Unregistered Guest Action Probe (Rule #36)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf('Unregistered action "%s" invoked by guest on %s.', esc_html($action), $endpoint_name),
            'match_type'  => 'Guest Action Policy',
            'match_value' => $action,
            'payload'     => "Action: {$action} Endpoint: {$endpoint_name} IP: {$client_ip}",
        ];

        if ($policy === 'block') {
            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
        } else {
            // In 'monitor' mode: log to WAF telemetry with status 'monitored' and permit execution
            self::log_incident($rule_triggered, 'monitored');
        }
    }

    /**
     * Rule #37: Guest REST API Mutation Guard.
     * Inspects REST API mutations (POST, PUT, PATCH, DELETE) from unauthenticated visitors.
     * Whitelists safe public namespaces (contact forms, analytics, store carts).
     * Normalizes HTTP method overrides and unpacks REST batch requests (/wp/v2/batch, /batch/v1).
     * Flags anomalous unknown guest write mutations in WAF telemetry.
     *
     * @param mixed $result
     * @param \WP_REST_Server $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function inspect_guest_rest_dispatch($result, $server, $request) {
        if (is_wp_error($result)) {
            return $result;
        }

        $settings = SettingsManager::get_settings();
        $policy = $settings['waf_guest_rest_policy'] ?? 'monitor';
        if ($policy === 'off') {
            return $result;
        }

        // Canonicalize Method (normalize _method query param and X-HTTP-Method-Override header)
        $method = strtoupper($request->get_method());
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $override_method = isset($_GET['_method']) ? strtoupper(sanitize_key(wp_unslash($_GET['_method']))) : '';
        if (empty($override_method) && !empty($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $override_method = strtoupper(sanitize_key(wp_unslash($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])));
        }
        if (!empty($override_method) && in_array($override_method, ['POST', 'PUT', 'PATCH', 'DELETE', 'GET'], true)) {
            $method = $override_method;
        }

        // Authenticated users and verified administrators are completely permitted
        $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in())
            || self::is_authenticated_administrator()
            || self::is_authenticated_editor_or_builder();

        if ($is_logged_in) {
            return $result;
        }

        // Server Origin & Host Loopback Immunity:
        // Internal loopback requests originating from the server itself are trusted internal operations.
        $client_ip = self::get_client_ip();
        if (self::is_server_origin_or_loopback($client_ip)) {
            return $result;
        }

        $route = strtolower($request->get_route());

        // 1. Check Store API Catalog Scraping (Rule #42) on ALL methods (including GET /wc/store/v1/products)
        if (preg_match('#^/wc/store(?:/v\d+)?/products#i', $route)) {
            $scrape_lock_error = self::check_and_track_catalog_scraping('Store API Products Endpoint');
            if ($scrape_lock_error) {
                return $scrape_lock_error;
            }
        }

        // Only inspect mutating methods beyond this point
        if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $result;
        }

        // 2. Enforce Rule #38 (Carding Lockout) & Rule #39 (Coupon Lockout) on Store API BEFORE safe_prefixes
        if (preg_match('#^/wc/store(?:/v\d+)?/checkout#i', $route)) {
            $block_error = self::check_woo_carding_lockout();
            if ($block_error) {
                return $block_error;
            }
        }
        if (preg_match('#^/wc/store(?:/v\d+)?/cart/(?:coupons|apply-coupon)#i', $route)) {
            $coupon_lock_error = self::check_woo_coupon_lockout();
            if ($coupon_lock_error) {
                return $coupon_lock_error;
            }
        }

        // Special handling for REST batch requests (/wp/v2/batch or /batch/v1):
        // Walk nested requests[] inside the batch payload to ensure unauthorized guest mutations aren't smuggled
        if (str_contains($route, '/batch')) {
            $body_params = $request->get_json_params();
            if (is_array($body_params) && !empty($body_params['requests']) && is_array($body_params['requests'])) {
                foreach ($body_params['requests'] as $sub_req) {
                    $sub_method = strtoupper($sub_req['method'] ?? 'GET');
                    $sub_path   = strtolower($sub_req['path'] ?? '');

                    // Inspect sub-requests targeting WooCommerce Block Checkout or Coupons
                    if (preg_match('#^/wc/store(?:/v\d+)?/checkout#i', $sub_path) && in_array($sub_method, ['POST', 'PUT', 'PATCH'], true)) {
                        $block_error = self::check_woo_carding_lockout();
                        if ($block_error) {
                            return $block_error;
                        }
                    }
                    if (preg_match('#^/wc/store(?:/v\d+)?/cart/(?:coupons|apply-coupon)#i', $sub_path) && in_array($sub_method, ['POST', 'PUT', 'PATCH'], true)) {
                        $coupon_lock_error = self::check_woo_coupon_lockout();
                        if ($coupon_lock_error) {
                            return $coupon_lock_error;
                        }
                    }

                    if (in_array($sub_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                        $is_sub_safe = false;
                        $safe_sub_prefixes = [
                            '/wc/store/', '/contact-form-7/', '/wpforms/', '/fluentform/',
                            '/ninja-forms/', '/frm/', '/gf/', '/paypal/', '/wc-stripe/',
                            '/stripe/', '/surecart/', '/wp/v2/comments',
                        ];
                        foreach ($safe_sub_prefixes as $ssp) {
                            if (str_starts_with($sub_path, $ssp) || str_contains($sub_path, $ssp)) {
                                $is_sub_safe = true;
                                break;
                            }
                        }
                        if (!$is_sub_safe) {
                            $rule_triggered = [
                                'id'          => 'WAF-GUEST-REST-BATCH-MUTATION',
                                'name'        => 'Unauthenticated REST Batch Mutation Probe (Rule #37)',
                                'category'    => 'Behavioral Defense',
                                'description' => sprintf('Unauthenticated %s request smuggled inside REST batch for route "%s".', $sub_method, esc_html($sub_path)),
                                'match_type'  => 'Guest REST Batch Mutation',
                                'match_value' => $sub_path,
                                'payload'     => "Method: {$sub_method} SubRoute: {$sub_path} IP: {$client_ip}",
                            ];
                            if ($policy === 'block') {
                                self::log_incident($rule_triggered, 'blocked');
                                return new \WP_Error('webcare_waf_rest_batch_blocked', __('Unauthorized guest REST batch mutation blocked by WebCare Firewall.', 'webcare-pro-security'), ['status' => 403]);
                            }
                            self::log_incident($rule_triggered, 'monitored');
                            break;
                        }
                    }
                }
            }
            return $result;
        }

        // Whitelist recognized safe public mutating routes
        $safe_prefixes = [
            '/contact-form-7/',
            '/wpforms/',
            '/fluentform/',
            '/ninja-forms/',
            '/frm/',
            '/gf/',
            '/wc/store/',
            '/paypal/',
            '/wc-stripe/',
            '/stripe/',
            '/mollie/',
            '/square/',
            '/surecart/',
            '/givewp/',
            '/wp/v2/comments',
            '/akismet/',
            '/jetpack/',
            '/webcare-pro-security/v1/auth/webauthn/assertion/',
        ];

        foreach ($safe_prefixes as $prefix) {
            if (strpos($route, $prefix) === 0 || strpos($route, $prefix) !== false) {
                return $result;
            }
        }

        // Flag unregistered guest REST write mutation
        $client_ip = self::get_client_ip();
        $rule_triggered = [
            'id'          => 'WAF-GUEST-REST-MUTATION',
            'name'        => 'Unauthenticated REST API Mutation Probe (Rule #37)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf('Unauthenticated %s request targeted at REST route "%s".', $method, esc_html($route)),
            'match_type'  => 'Guest REST Mutation',
            'match_value' => $route,
            'payload'     => "Method: {$method} Route: {$route} IP: {$client_ip}",
        ];

        if ($policy === 'block') {
            self::log_incident($rule_triggered, 'blocked');
            return new \WP_Error('webcare_waf_rest_blocked', __('Unauthorized guest REST mutation blocked by WebCare Firewall.', 'webcare-pro-security'), ['status' => 403]);
        }

        self::log_incident($rule_triggered, 'monitored');
        return $result;
    }

    /**
     * Rule #38: Check if client IP is currently locked out by WooCommerce Carding Attack Mitigation.
     *
     * @return \WP_Error|false Returns WP_Error if locked out, or false if clear.
     */
    public static function check_woo_carding_lockout() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_carding_protection'])) {
            return false;
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return false;
        }

        $lock_key = 'webcareproscan_chk_lock_' . md5($client_ip);
        $is_locked = get_transient($lock_key);
        if (!$is_locked) {
            return false;
        }

        $rule_triggered = [
            'id'          => 'WAF-WOO-CARDING-BLOCKED',
            'name'        => 'WooCommerce Carding Attack & Checkout Velocity Mitigation (Rule #38)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf(
                /* translators: 1: Client IP address */
                __('Blocked repeated checkout attempt from temporarily locked-out IP %1$s (Carding Velocity Defense).', 'webcare-pro-security'),
                $client_ip
            ),
            'match_type'  => 'Carding Velocity Threshold',
            'match_value' => $client_ip,
            'payload'     => "IP: {$client_ip} Locked due to excessive failed checkout attempts",
        ];

        self::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'webcareproscan_carding_lockout',
            esc_html__('Too many checkout attempts detected from your connection. For security purposes, checkout has been temporarily paused for 30 minutes. Please contact customer support if you need immediate assistance.', 'webcare-pro-security'),
            ['status' => 429]
        );
    }

    /**
     * Rule #38: Inspect early WooCommerce checkout attempts before validation/order processing.
     *
     * Intercepts `woocommerce_checkout_process` hook.
     * If client IP is locked out, prevents order processing and displays notice or JSON error.
     *
     * @return void
     */
    public static function inspect_woo_checkout_attempt(): void {
        $lock_error = self::check_woo_carding_lockout();
        if (!$lock_error) {
            return;
        }

        $error_message = $lock_error->get_error_message();

        if (wp_doing_ajax()) {
            wp_send_json([
                'result'   => 'failure',
                'messages' => '<ul class="woocommerce-error" role="alert"><li>' . esc_html($error_message) . '</li></ul>',
                'refresh'  => false,
                'reload'   => false,
            ]);
            exit;
        }

        if (function_exists('wc_add_notice')) {
            wc_add_notice($error_message, 'error');
        }
    }

    /**
     * Rule #38: Track checkout failures from validation errors on checkout form.
     *
     * @param array $data
     * @param \WP_Error $errors
     * @return void
     */
    public static function handle_woo_checkout_validation($data, $errors): void {
        if (!is_wp_error($errors) || empty($errors->errors)) {
            return;
        }

        // Only count payment/critical checkout validation failures
        $has_critical_failure = false;
        foreach ($errors->errors as $code => $messages) {
            $code_lower = strtolower((string) $code);
            if (strpos($code_lower, 'payment') !== false || strpos($code_lower, 'card') !== false || strpos($code_lower, 'stripe') !== false || strpos($code_lower, 'paypal') !== false || strpos($code_lower, 'gateway') !== false) {
                $has_critical_failure = true;
                break;
            }
        }

        if ($has_critical_failure) {
            self::record_failed_checkout_attempt('Payment gateway validation error');
        }
    }

    /**
     * Rule #38: Track order payment status changing to 'failed'.
     *
     * @param int $order_id
     * @return void
     */
    public static function handle_woo_payment_failure($order_id): void {
        $customer_ip = '';
        if (function_exists('wc_get_order')) {
            $order = wc_get_order($order_id);
            if ($order && method_exists($order, 'get_customer_ip_address')) {
                $customer_ip = (string) $order->get_customer_ip_address();
            }
        }
        self::record_failed_checkout_attempt('Order status transitioned to failed', $customer_ip);
    }

    /**
     * Rule #38: Record a failed checkout attempt and trigger lockout if threshold is exceeded.
     *
     * @param string $reason
     * @param string $override_ip Explicit shopper IP address (e.g. from async payment webhook order context)
     * @return void
     */
    public static function record_failed_checkout_attempt(string $reason = '', string $override_ip = ''): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_carding_protection'])) {
            return;
        }

        // If triggered by an async payment webhook (Stripe, PayPal, Mollie, 3DS), strictly use the order's customer IP
        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $is_webhook = !empty($_SERVER['HTTP_STRIPE_SIGNATURE']) || !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG']) || str_contains($req_uri, 'wc-api');
        if ($is_webhook && empty($override_ip)) {
            return; // Never lock out a payment gateway webhook server IP
        }

        $client_ip = !empty($override_ip) ? trim($override_ip) : self::get_client_ip();
        if (empty($client_ip)) {
            return;
        }

        // Whitelist check
        if (self::is_ip_whitelisted($client_ip)) {
            return;
        }

        $max_attempts = (int) ($settings['waf_woo_checkout_max_attempts'] ?? 3);
        $lockout_duration_mins = (int) ($settings['waf_woo_carding_lockout_duration'] ?? 30);
        $window_seconds = 300; // 5-minute rolling window for attempts

        $attempt_key = 'webcareproscan_chk_fail_' . md5($client_ip);
        $lock_key    = 'webcareproscan_chk_lock_' . md5($client_ip);

        // Check if already locked
        if (get_transient($lock_key)) {
            return;
        }

        $current_attempts = (int) get_transient($attempt_key);
        $new_attempts = $current_attempts + 1;

        if ($new_attempts >= $max_attempts) {
            // Lock out IP for configured lockout duration
            set_transient($lock_key, [
                'ip'         => $client_ip,
                'attempts'   => $new_attempts,
                'locked_at'  => time(),
                'expires_at' => time() + ($lockout_duration_mins * MINUTE_IN_SECONDS),
                'reason'     => $reason,
            ], $lockout_duration_mins * MINUTE_IN_SECONDS);

            delete_transient($attempt_key);

            $rule_triggered = [
                'id'          => 'WAF-WOO-CARDING-THRESHOLD',
                'name'        => 'WooCommerce Carding Attack Velocity Threshold Exceeded (Rule #38)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP address, 2: Number of failed attempts, 3: Lockout duration in minutes */
                    __('IP %1$s exceeded checkout failure threshold (%2$d attempts in 5 min) - locked out for %3$d minutes.', 'webcare-pro-security'),
                    $client_ip,
                    $new_attempts,
                    $lockout_duration_mins
                ),
                'match_type'  => 'Carding Velocity Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Trigger: {$reason} Attempts: {$new_attempts} / Limit: {$max_attempts}",
            ];

            self::log_incident($rule_triggered, 'blocked');
        } else {
            set_transient($attempt_key, $new_attempts, $window_seconds);
        }
    }

    /**
     * Rule #39: Check if client IP is currently locked out by WooCommerce Coupon Enumeration Mitigation.
     *
     * @return \WP_Error|false Returns WP_Error if locked out, or false if clear.
     */
    public static function check_woo_coupon_lockout() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_coupon_protection'])) {
            return false;
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return false;
        }

        $lock_key = 'webcareproscan_cpn_lock_' . md5($client_ip);
        $is_locked = get_transient($lock_key);
        if (!$is_locked) {
            return false;
        }

        $rule_triggered = [
            'id'          => 'WAF-WOO-COUPON-BLOCKED',
            'name'        => 'WooCommerce Coupon Enumeration & Brute-Force Shield (Rule #39)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf(
                /* translators: 1: Client IP address */
                __('Blocked repeated coupon testing attempt from temporarily locked-out IP %1$s (Coupon Brute-Force Defense).', 'webcare-pro-security'),
                $client_ip
            ),
            'match_type'  => 'Coupon Velocity Threshold',
            'match_value' => $client_ip,
            'payload'     => "IP: {$client_ip} Locked due to excessive invalid coupon attempts",
        ];

        self::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'webcareproscan_coupon_lockout',
            esc_html__('Too many invalid coupon attempts detected from your connection. For security purposes, coupon redemption has been temporarily paused for 15 minutes. Please contact support if you need assistance.', 'webcare-pro-security'),
            ['status' => 429]
        );
    }

    /**
     * Rule #39: Intercept WooCommerce coupon application error filter (`woocommerce_coupon_error`).
     *
     * Tracks failed/invalid coupon attempts. If locked out, replaces error message with lockout notice.
     *
     * @param string $err
     * @param int|string $err_code
     * @param \WC_Coupon|null $coupon
     * @return string
     */
    public static function handle_woo_coupon_error($err, $err_code, $coupon = null): string {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_coupon_protection'])) {
            return $err;
        }

        // Check if currently locked out
        $lock_error = self::check_woo_coupon_lockout();
        if ($lock_error) {
            return $lock_error->get_error_message();
        }

        // Record invalid coupon attempt (coupon doesn't exist, invalid code, expired)
        $coupon_code = ($coupon instanceof \WC_Coupon) ? $coupon->get_code() : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Low-level packet inspection of failed coupon attempt in filter
        if (empty($coupon_code) && !empty($_POST['coupon_code'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $coupon_code = sanitize_text_field(wp_unslash($_POST['coupon_code']));
        }

        self::record_failed_coupon_attempt($coupon_code, is_numeric($err_code) ? (int) $err_code : 0);

        // Re-check if this failure triggered a lockout
        $recheck_lock = self::check_woo_coupon_lockout();
        if ($recheck_lock) {
            return $recheck_lock->get_error_message();
        }

        return $err;
    }

    /**
     * Rule #39: Clear failed attempts when a valid coupon is successfully applied.
     *
     * Intercepts `woocommerce_applied_coupon` hook.
     *
     * @param string $coupon_code
     * @return void
     */
    public static function handle_woo_coupon_success(string $coupon_code): void {
        $client_ip = self::get_client_ip();
        if (!empty($client_ip)) {
            delete_transient('webcareproscan_cpn_fail_' . md5($client_ip));
        }
    }

    /**
     * Rule #39: Intercept Store API coupon REST response to catch invalid coupon errors.
     *
     * @param \WP_REST_Response|\WP_Error|mixed $response
     * @param array $handler
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function handle_woo_store_api_coupon_response($response, $handler, $request) {
        $route = $request->get_route();
        if (!preg_match('#^/wc/store(?:/v\d+)?/cart/(?:coupons|apply-coupon)#i', $route)) {
            return $response;
        }

        // If it's an error on applying coupon
        if (is_wp_error($response)) {
            $code = $response->get_error_code();
            if ($code === 'woocommerce_rest_cart_coupon_error' || $code === 'invalid_coupon') {
                $coupon_code = $request->get_param('code') ?: '';
                self::record_failed_coupon_attempt($coupon_code, 0);

                $lock_error = self::check_woo_coupon_lockout();
                if ($lock_error) {
                    return $lock_error;
                }
            }
        } elseif ($response instanceof \WP_REST_Response && $response->get_status() >= 400) {
            $coupon_code = $request->get_param('code') ?: '';
            self::record_failed_coupon_attempt($coupon_code, 0);

            $lock_error = self::check_woo_coupon_lockout();
            if ($lock_error) {
                return $lock_error;
            }
        }

        return $response;
    }

    /**
     * Rule #39: Record a failed coupon attempt and trigger lockout if threshold is exceeded.
     *
     * @param string $coupon_code
     * @param int $err_code
     * @return void
     */
    public static function record_failed_coupon_attempt(string $coupon_code = '', int $err_code = 0): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_coupon_protection'])) {
            return;
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return;
        }

        // Whitelist check
        if (self::is_ip_whitelisted($client_ip)) {
            return;
        }

        $max_failures = (int) ($settings['waf_woo_coupon_max_failures'] ?? 8);
        $lockout_duration_mins = (int) ($settings['waf_woo_coupon_lockout_duration'] ?? 15);
        $window_seconds = 300; // 5-minute rolling window

        // Genuine Shopper Leniency: If client has an active shopping cart or customer session, grant additional headroom (+4 attempts)
        // because real shoppers frequently test multiple promo codes from newsletters, influencers, or coupon extensions (e.g. Honey).
        if (self::has_active_shopper_session()) {
            $max_failures += 4;
        }

        $attempt_key = 'webcareproscan_cpn_fail_' . md5($client_ip);
        $lock_key    = 'webcareproscan_cpn_lock_' . md5($client_ip);

        if (get_transient($lock_key)) {
            return;
        }

        $current_attempts = (int) get_transient($attempt_key);
        $new_attempts = $current_attempts + 1;

        if ($new_attempts >= $max_failures) {
            set_transient($lock_key, [
                'ip'         => $client_ip,
                'attempts'   => $new_attempts,
                'locked_at'  => time(),
                'expires_at' => time() + ($lockout_duration_mins * MINUTE_IN_SECONDS),
                'last_code'  => $coupon_code,
            ], $lockout_duration_mins * MINUTE_IN_SECONDS);

            delete_transient($attempt_key);

            $rule_triggered = [
                'id'          => 'WAF-WOO-COUPON-THRESHOLD',
                'name'        => 'WooCommerce Coupon Enumeration Velocity Threshold Exceeded (Rule #39)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP address, 2: Number of failed attempts, 3: Lockout duration in minutes */
                    __('IP %1$s exceeded coupon failure threshold (%2$d invalid attempts in 5 min) - locked out from coupon testing for %3$d minutes.', 'webcare-pro-security'),
                    $client_ip,
                    $new_attempts,
                    $lockout_duration_mins
                ),
                'match_type'  => 'Coupon Velocity Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Last Coupon: {$coupon_code} ErrorCode: {$err_code} Attempts: {$new_attempts} / Limit: {$max_failures}",
            ];

            self::log_incident($rule_triggered, 'blocked');
        } else {
            set_transient($attempt_key, $new_attempts, $window_seconds);
        }
    }

    /**
     * Common disposable, temporary, and throwaway email domains used by spam registration bots.
     */
    const DISPOSABLE_EMAIL_DOMAINS = [
        'mailinator.com', 'guerrillamail.com', 'sharklasers.com', 'grr.la', 'guerrillamail.biz',
        'tempmail.com', 'temp-mail.org', '10minutemail.com', '10minutemail.net', 'throwawaymail.com',
        'getairmail.com', 'mohmal.com', 'dispostable.com', 'trashmail.com', 'yopmail.com',
        'yopmail.fr', 'yopmail.net', 'mytemp.email', 'crazymailing.com', 'fakeinbox.com',
        'generator.email', 'tempail.com', 'burnermail.io', 'mailnesia.com', 'inboxkitten.com',
        'fakemailgenerator.com', 'getnada.com', 'abcvg.com', 'dropmail.me', 'emailondeck.com',
        'tempr.email', 'discard.email', 'spambog.com', 'zoemail.org', 'bupmail.com',
        'tmpmail.net', 'tmpmail.org', 'tmail.ws', 'tmailor.com', 'minuteinbox.com'
    ];

    /**
     * Rule #40: Validate customer registration attempts across WooCommerce (my-account, checkout, Store API).
     *
     * Enforces velocity rate-limiting per IP and rejects disposable/temporary email providers.
     *
     * @param \WP_Error $errors
     * @param string $username
     * @param string $email
     * @return \WP_Error
     */
    public static function validate_woo_customer_registration($errors, $username, $email) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_registration_protection'])) {
            return $errors;
        }

        if (!is_wp_error($errors)) {
            $errors = new \WP_Error();
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return $errors;
        }

        // Whitelist check
        if (self::is_ip_whitelisted($client_ip)) {
            return $errors;
        }

        // 1. Disposable / Temporary Email Domain Filter
        if (!empty($settings['waf_woo_reg_block_disposable_emails']) && !empty($email)) {
            $parts = explode('@', $email);
            if (count($parts) === 2) {
                $domain = strtolower(trim($parts[1]));
                if (in_array($domain, self::DISPOSABLE_EMAIL_DOMAINS, true)) {
                    $rule_triggered = [
                        'id'          => 'WAF-WOO-REG-DISPOSABLE-EMAIL',
                        'name'        => 'WooCommerce Disposable Email Registration Block (Rule #40)',
                        'category'    => 'Behavioral Defense',
                        'description' => sprintf(
                            /* translators: 1: Client IP, 2: Disposable email domain */
                            __('Blocked customer registration from IP %1$s using throwaway email domain "@%2$s".', 'webcare-pro-security'),
                            $client_ip,
                            $domain
                        ),
                        'match_type'  => 'Disposable Email Domain',
                        'match_value' => $domain,
                        'payload'     => "IP: {$client_ip} Email: {$email} Domain: {$domain}",
                    ];

                    self::log_incident($rule_triggered, 'blocked');

                    $errors->add(
                        'webcareproscan_disposable_email_blocked',
                        esc_html__('Temporary and disposable email addresses are not permitted. Please register with a permanent, valid email address.', 'webcare-pro-security')
                    );
                    return $errors;
                }
            }
        }

        // 2. IP Registration Velocity Rate-Limiting
        $max_registrations = (int) ($settings['waf_woo_reg_max_per_ip'] ?? 3);
        $window_hours = (int) ($settings['waf_woo_reg_window_hours'] ?? 1);
        $window_seconds = $window_hours * HOUR_IN_SECONDS;

        $reg_key = 'webcareproscan_reg_ip_' . md5($client_ip);
        $count = (int) get_transient($reg_key);

        if ($count >= $max_registrations) {
            $rule_triggered = [
                'id'          => 'WAF-WOO-REG-VELOCITY-BLOCKED',
                'name'        => 'WooCommerce Customer Registration Velocity Limit (Rule #40)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP, 2: Registration limit, 3: Window hours */
                    __('Customer registration rate limit exceeded from IP %1$s (%2$d accounts created in %3$d hour(s)).', 'webcare-pro-security'),
                    $client_ip,
                    $max_registrations,
                    $window_hours
                ),
                'match_type'  => 'Registration Velocity Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Attempted Email: {$email} Count: {$count} / Limit: {$max_registrations}",
            ];

            self::log_incident($rule_triggered, 'blocked');

            $errors->add(
                'webcareproscan_reg_velocity_limit',
                esc_html__('Too many accounts have been created from your connection recently. Please wait before attempting to register another account or contact customer service.', 'webcare-pro-security')
            );
            return $errors;
        }

        return $errors;
    }

    /**
     * Rule #40: Increment customer registration count for the client IP upon successful account creation.
     *
     * @param int $customer_id
     * @param array $new_customer_data
     * @param bool $password_generated
     * @return void
     */
    public static function handle_woo_customer_created($customer_id, $new_customer_data = [], $password_generated = false): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_registration_protection'])) {
            return;
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return;
        }

        $window_hours = (int) ($settings['waf_woo_reg_window_hours'] ?? 1);
        $window_seconds = $window_hours * HOUR_IN_SECONDS;

        $reg_key = 'webcareproscan_reg_ip_' . md5($client_ip);
        $count = (int) get_transient($reg_key);
        set_transient($reg_key, $count + 1, $window_seconds);
    }

    /**
     * Rule #41: Validate WooCommerce add-to-cart operations against cart flooding and inventory exhaustion.
     *
     * Intercepts `woocommerce_add_to_cart_validation` hook across Classic AJAX, single product forms, and Store API.
     *
     * @param bool $passed
     * @param int $product_id
     * @param int $quantity
     * @param int $variation_id
     * @param array $variations
     * @return bool
     */
    public static function validate_woo_add_to_cart($passed, $product_id, $quantity, $variation_id = 0, $variations = []): bool {
        if (!$passed) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_cart_flood_protection'])) {
            return $passed;
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return $passed;
        }

        // Whitelist check
        if (self::is_ip_whitelisted($client_ip)) {
            return $passed;
        }

        // 1. Add-to-Cart Velocity Rate-Limiting (per minute per IP)
        $rate_limit = (int) ($settings['waf_woo_add_to_cart_rate_limit'] ?? 15);
        $velocity_key = 'webcareproscan_cart_vel_' . md5($client_ip);
        $current_hits = (int) get_transient($velocity_key);

        if ($current_hits >= $rate_limit) {
            $rule_triggered = [
                'id'          => 'WAF-WOO-CART-VELOCITY-BLOCKED',
                'name'        => 'WooCommerce Cart Flooding Velocity Limit (Rule #41)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP, 2: Rate limit count */
                    __('Blocked rapid add-to-cart flood from IP %1$s (exceeded %2$d additions per minute).', 'webcare-pro-security'),
                    $client_ip,
                    $rate_limit
                ),
                'match_type'  => 'Cart Addition Velocity',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Product: {$product_id} Hits: {$current_hits} / Limit: {$rate_limit}",
            ];

            self::log_incident($rule_triggered, 'blocked');

            if (function_exists('wc_add_notice')) {
                wc_add_notice(
                    esc_html__('You are adding items too quickly. Please pause for a moment before adding more items to your cart.', 'webcare-pro-security'),
                    'error'
                );
            }
            return false;
        }

        // Increment velocity counter (60-second window)
        set_transient($velocity_key, $current_hits + 1, 60);

        // 2. Maximum Cumulative Cart Items Check (Denial of Inventory defense)
        if (function_exists('WC') && WC()->cart) {
            $max_cart_items = (int) ($settings['waf_woo_max_cart_items'] ?? 50);
            $current_cart_count = (int) WC()->cart->get_cart_contents_count();
            $target_count = $current_cart_count + max(1, (int) $quantity);

            if ($target_count > $max_cart_items) {
                $rule_triggered = [
                    'id'          => 'WAF-WOO-INVENTORY-HOARDING',
                    'name'        => 'WooCommerce Denial of Inventory Cap Exceeded (Rule #41)',
                    'category'    => 'Behavioral Defense',
                    'description' => sprintf(
                        /* translators: 1: Client IP, 2: Target item count, 3: Max allowed items */
                        __('Blocked inventory hoarding attempt from IP %1$s (cart item count %2$d would exceed cap %3$d).', 'webcare-pro-security'),
                        $client_ip,
                        $target_count,
                        $max_cart_items
                    ),
                    'match_type'  => 'Cart Volume Cap',
                    'match_value' => $client_ip,
                    'payload'     => "IP: {$client_ip} Current: {$current_cart_count} Adding: {$quantity} Cap: {$max_cart_items}",
                ];

                self::log_incident($rule_triggered, 'blocked');

                if (function_exists('wc_add_notice')) {
                    wc_add_notice(
                        sprintf(
                            /* translators: %d: Maximum allowed items in cart */
                            esc_html__('Your shopping cart has reached the maximum permitted volume of %d items. Please proceed to checkout or remove unused items.', 'webcare-pro-security'),
                            $max_cart_items
                        ),
                        'error'
                    );
                }
                return false;
            }
        }

        return $passed;
    }

    /**
     * Rule #42: Inspect incoming storefront requests on `template_redirect` for aggressive catalog scraping.
     *
     * Monitors shop, product category, product tag, and single product views.
     * Exempts genuine search engine crawlers (Googlebot, Bingbot) and verified uptime monitors.
     *
     * @return void
     */
    public static function inspect_woo_catalog_scraping(): void {
        if (!function_exists('is_woocommerce') && !function_exists('is_product')) {
            return;
        }

        // Check if viewing product catalog pages
        $is_catalog_page = (function_exists('is_shop') && is_shop())
            || (function_exists('is_product_taxonomy') && is_product_taxonomy())
            || (function_exists('is_product_category') && is_product_category())
            || (function_exists('is_product_tag') && is_product_tag())
            || (function_exists('is_product') && is_product());

        if (!$is_catalog_page) {
            return;
        }

        $lock_error = self::check_and_track_catalog_scraping('Storefront Catalog Page');
        if ($lock_error) {
            status_header(429);
            header('Retry-After: 900');
            $settings = SettingsManager::get_settings();
            $client_ip = self::get_client_ip();
            $rule_triggered = [
                'id'          => 'WAF-WOO-SCRAPING-BLOCKED',
                'name'        => 'WooCommerce Catalog & Price Scraping Mitigation (Rule #42)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP address */
                    __('Catalog request blocked from IP %1$s due to aggressive price/inventory scraping velocity.', 'webcare-pro-security'),
                    $client_ip
                ),
                'match_type'  => 'Catalog Scraping Velocity',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} URI: " . (isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : ''),
            ];
            self::log_incident($rule_triggered, 'blocked');
            wp_die(
                esc_html__('Too many requests. Automated catalog scraping has been temporarily restricted for your connection. Please wait 15 minutes before browsing again.', 'webcare-pro-security'),
                esc_html__('Too Many Requests', 'webcare-pro-security'),
                ['response' => 429]
            );
        }
    }

    /**
     * Rule #42: Check if client IP is locked out or increments catalog hit velocity.
     *
     * @param string $source
     * @return \WP_Error|false
     */
    public static function check_and_track_catalog_scraping(string $source = '') {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_scraping_protection'])) {
            return false;
        }

        $client_ip = self::get_client_ip();
        if (empty($client_ip)) {
            return false;
        }

        // Whitelist check
        if (self::is_ip_whitelisted($client_ip)) {
            return false;
        }

        // Exempt logged-in store administrators & shop managers
        if (is_user_logged_in() && (current_user_can('manage_woocommerce') || current_user_can('manage_options'))) {
            return false;
        }

        // Exempt genuine search engine crawlers (Google, Bing) and uptime monitors
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
            if (\WebCareProScanner\Firewall\BotReconDefense::is_genuine_search_engine($client_ip, $user_agent)) {
                return false;
            }
            if (\WebCareProScanner\Firewall\BotReconDefense::is_genuine_uptime_monitor($client_ip, $user_agent, $settings)) {
                return false;
            }
        }

        $lock_key = 'webcareproscan_scrape_lock_' . md5($client_ip);
        if (get_transient($lock_key)) {
            return new \WP_Error(
                'webcareproscan_catalog_scrape_lockout',
                esc_html__('Catalog and pricing access temporarily restricted due to high-frequency scraping. Please try again later.', 'webcare-pro-security'),
                ['status' => 429]
            );
        }

        $max_requests = (int) ($settings['waf_woo_scraping_max_requests'] ?? 60);
        $lockout_mins = (int) ($settings['waf_woo_scraping_lockout_duration'] ?? 15);
        $velocity_key = 'webcareproscan_scrape_vel_' . md5($client_ip);
        $current_hits = (int) get_transient($velocity_key);
        $new_hits = $current_hits + 1;

        if ($new_hits > $max_requests) {
            set_transient($lock_key, [
                'ip'         => $client_ip,
                'hits'       => $new_hits,
                'locked_at'  => time(),
                'expires_at' => time() + ($lockout_mins * MINUTE_IN_SECONDS),
                'source'     => $source,
            ], $lockout_mins * MINUTE_IN_SECONDS);

            delete_transient($velocity_key);

            $rule_triggered = [
                'id'          => 'WAF-WOO-SCRAPING-THRESHOLD',
                'name'        => 'WooCommerce Catalog Scraping Threshold Exceeded (Rule #42)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP, 2: Hit count, 3: Lockout duration in minutes */
                    __('IP %1$s exceeded catalog scraping threshold (%2$d requests in 1 min) - locked out for %3$d minutes.', 'webcare-pro-security'),
                    $client_ip,
                    $new_hits,
                    $lockout_mins
                ),
                'match_type'  => 'Scraping Threshold Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Source: {$source} Hits: {$new_hits} / Limit: {$max_requests}",
            ];

            self::log_incident($rule_triggered, 'blocked');

            return new \WP_Error(
                'webcareproscan_catalog_scrape_lockout',
                esc_html__('Catalog and pricing access temporarily restricted due to high-frequency scraping. Please try again later.', 'webcare-pro-security'),
                ['status' => 429]
            );
        }

        set_transient($velocity_key, $new_hits, 60);
        return false;
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Intercept unauthenticated / unauthorized core option tampering.
     *
     * Aborts guest requests attempting to modify critical WordPress authentication & registration options
     * (e.g. users_can_register, default_role, siteurl, active_plugins) via 0-day form or booking exploits.
     *
     * @param mixed  $value     New option value
     * @param string $option    Option name being updated
     * @param mixed  $old_value Old option value
     * @return mixed Original or reverted value
     */
    /**
     * Canonicalize REST API route from either /wp-json/<route> path or ?rest_route=<route> query parameter.
     * Hardened against query-string smuggling, double-encoding (%252f), null bytes, and traversal.
     */
    public static function canonicalize_rest_route(string $request_uri = '', ?string $query_rest_route = null): string {
        $route = '';
        if ($query_rest_route !== null && $query_rest_route !== '') {
            $route = '/' . ltrim($query_rest_route, '/');
        } else {
            $parsed_q = wp_parse_url($request_uri, PHP_URL_QUERY);
            if (is_string($parsed_q) && $parsed_q !== '') {
                parse_str($parsed_q, $qp);
                if (!empty($qp['rest_route']) && is_string($qp['rest_route'])) {
                    $route = '/' . ltrim($qp['rest_route'], '/');
                }
            }
            if ($route === '') {
                $path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?: '');
                $pos  = stripos($path, '/wp-json');
                if ($pos !== false) {
                    $route = '/' . ltrim(substr($path, $pos + 8), '/');
                }
            }
        }

        if ($route === '') {
            return '/';
        }

        // 1. Strip query string and fragment from route
        $route = explode('?', $route, 2)[0];
        $route = explode('#', $route, 2)[0];

        // 2. Strip null bytes
        $route = str_replace(chr(0), '', $route);

        // 3. Decode up to 2 passes to eliminate double-encoding evasion (%252f -> %2f -> /)
        $passes = 0;
        while (strpos($route, '%') !== false && $passes < 2) {
            $decoded = rawurldecode($route);
            if ($decoded === $route) {
                break;
            }
            $route = $decoded;
            $passes++;
        }

        // 4. Strip any newly surfaced query or fragment delimiters post-decode
        $route = explode('?', $route, 2)[0];
        $route = explode('#', $route, 2)[0];

        // 5. Replace backslashes with forward slashes and collapse consecutive slashes
        $route = str_replace('\\', '/', $route);
        $route = (string) preg_replace('#/{2,}#', '/', $route);

        // 6. Normalize traversal tokens (/./ and /../)
        $parts = explode('/', trim($route, '/'));
        $resolved = [];
        foreach ($parts as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($resolved);
            } else {
                $resolved[] = $part;
            }
        }

        $normalized = strtolower('/' . implode('/', $resolved));
        return $normalized !== '' ? $normalized : '/';
    }

    /**
     * Resolve the original immutable table prefix defined in wp-config.php before runtime sandboxing.
     *
     * @return string
     */
    public static function get_original_table_prefix(): string {
        if (isset($GLOBALS['table_prefix']) && is_string($GLOBALS['table_prefix']) && preg_match('/^[a-zA-Z0-9_]+$/', $GLOBALS['table_prefix'])) {
            return $GLOBALS['table_prefix'];
        }
        global $wpdb;
        if (isset($wpdb->base_prefix) && is_string($wpdb->base_prefix) && $wpdb->base_prefix !== '') {
            return $wpdb->base_prefix;
        }
        return isset($wpdb->prefix) && is_string($wpdb->prefix) && $wpdb->prefix !== '' ? $wpdb->prefix : 'wp_';
    }

    /**
     * Detect whether Plugin Check (PCP) runtime DB sandboxing (*_pc_ prefix) is active in-process.
     *
     * Validates server-side $wpdb state alongside loaded Plugin Check classes/constants rather than client headers.
     *
     * @return bool
     */
    public static function is_plugin_check_db_sandbox(): bool {
        global $wpdb;
        $orig_prefix = isset($GLOBALS['table_prefix']) && is_string($GLOBALS['table_prefix']) ? $GLOBALS['table_prefix'] : '';
        if ($orig_prefix === '' || !isset($wpdb->base_prefix) || !is_string($wpdb->base_prefix)) {
            return false;
        }
        if ($wpdb->base_prefix === $orig_prefix) {
            return false;
        }
        if (!str_starts_with($wpdb->base_prefix, $orig_prefix) || !str_ends_with($wpdb->base_prefix, '_pc_')) {
            return false;
        }

        return defined('WP_PLUGIN_CHECK_OBJECT_CACHE_DROPIN_VERSION')
            || defined('WP_PLUGIN_CHECK_PLUGIN_DIR_PATH')
            || (defined('WEBCAREPROSCAN_PCP_TEST_HARNESS') && WEBCAREPROSCAN_PCP_TEST_HARNESS)
            || class_exists('WordPress\\Plugin_Check\\Traits\\Amend_DB_Base_Prefix', false)
            || class_exists('WordPress\\Plugin_Check\\Checker\\Runtime_Environment_Setup', false);
    }

    /**
     * Validate a WordPress auth cookie directly against the real site users/usermeta tables when DB tables are sandboxed.
     *
     * Prevents premature wp_get_current_user() cache poisoning or lookup failures when $wpdb->users points to *_pc_users.
     *
     * @param string $cookie      Raw auth cookie value.
     * @param string $scheme      Cookie scheme ('logged_in', 'secure_auth', 'auth').
     * @param string $orig_prefix Original production table prefix from $GLOBALS['table_prefix'].
     * @return array{user_id:int,is_admin:bool}
     */
    private static function validate_cookie_against_original_tables(string $cookie, string $scheme, string $orig_prefix): array {
        $empty = ['user_id' => 0, 'is_admin' => false];

        if ($cookie === '' || !function_exists('wp_parse_auth_cookie') || !function_exists('wp_hash')) {
            return $empty;
        }
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $orig_prefix)) {
            return $empty;
        }

        $cookie_elements = wp_parse_auth_cookie($cookie, $scheme);
        if (!$cookie_elements || empty($cookie_elements['username']) || empty($cookie_elements['hmac']) || empty($cookie_elements['token']) || empty($cookie_elements['expiration'])) {
            return $empty;
        }

        $parsed_scheme = (string) ($cookie_elements['scheme'] ?? $scheme);
        $username      = (string) $cookie_elements['username'];
        $hmac          = (string) $cookie_elements['hmac'];
        $token         = (string) $cookie_elements['token'];
        $expiration    = (string) $cookie_elements['expiration'];

        $expired = (int) $expiration;
        $req_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : '';
        if ((function_exists('wp_doing_ajax') && wp_doing_ajax()) || $req_method === 'POST') {
            $expired += HOUR_IN_SECONDS;
        }
        if ($expired < time()) {
            return $empty;
        }

        global $wpdb;
        if (!isset($wpdb) || !is_object($wpdb)) {
            return $empty;
        }

        $users_table    = defined('CUSTOM_USER_TABLE') ? CUSTOM_USER_TABLE : ($orig_prefix . 'users');
        $usermeta_table = defined('CUSTOM_USER_META_TABLE') ? CUSTOM_USER_META_TABLE : ($orig_prefix . 'usermeta');
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $users_table) || !preg_match('/^[a-zA-Z0-9_]+$/', $usermeta_table)) {
            return $empty;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Pre-boot validation against original users table during DB prefix sandboxing.
        $user_row = $wpdb->get_row(
            $wpdb->prepare('SELECT ID, user_login, user_pass FROM %i WHERE user_login = %s LIMIT 1', $users_table, $username)
        );
        if (!$user_row || empty($user_row->user_pass)) {
            return $empty;
        }

        $user_pass = (string) $user_row->user_pass;
        if (str_starts_with($user_pass, '$P$') || str_starts_with($user_pass, '$2y$')) {
            $pass_frag = substr($user_pass, 8, 4);
        } else {
            $pass_frag = substr($user_pass, -4);
        }

        $key  = wp_hash($username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $parsed_scheme);
        $hash = hash_hmac('sha256', $username . '|' . $expiration . '|' . $token, $key);
        if (!hash_equals($hash, $hmac)) {
            return $empty;
        }

        $blog_id   = !empty($wpdb->blogid) ? (int) $wpdb->blogid : 1;
        $cap_key_1 = $orig_prefix . 'capabilities';
        $cap_key_2 = ($blog_id > 1) ? ($orig_prefix . $blog_id . '_capabilities') : $cap_key_1;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Reads verified session tokens and capabilities from original usermeta table during DB prefix sandboxing.
        $meta_rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT meta_key, meta_value FROM %i WHERE user_id = %d AND meta_key IN ('session_tokens', %s, %s)",
                $usermeta_table,
                (int) $user_row->ID,
                $cap_key_1,
                $cap_key_2
            )
        );
        if (!is_array($meta_rows)) {
            return $empty;
        }

        $meta_map = [];
        foreach ($meta_rows as $meta_row) {
            if (isset($meta_row->meta_key)) {
                $meta_map[$meta_row->meta_key] = $meta_row->meta_value;
            }
        }

        $sessions = isset($meta_map['session_tokens'])
            ? (class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($meta_map['session_tokens'])
                : maybe_unserialize($meta_map['session_tokens']))
            : [];
        $verifier = hash('sha256', $token);
        if (!is_array($sessions) || !isset($sessions[$verifier]) || !is_array($sessions[$verifier])) {
            return $empty;
        }
        $session_exp = (int) ($sessions[$verifier]['expiration'] ?? 0);
        if ($session_exp > 0 && $session_exp < time()) {
            return $empty;
        }

        $caps = [];
        if (isset($meta_map[$cap_key_2])) {
            $caps = class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($meta_map[$cap_key_2])
                : maybe_unserialize($meta_map[$cap_key_2]);
        }
        if (!is_array($caps) && isset($meta_map[$cap_key_1])) {
            $caps = class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($meta_map[$cap_key_1])
                : maybe_unserialize($meta_map[$cap_key_1]);
        }
        $is_admin = is_array($caps) && (!empty($caps['administrator']) || !empty($caps['manage_options']));

        return [
            'user_id'  => (int) $user_row->ID,
            'is_admin' => $is_admin,
        ];
    }

    /**
     * Verify whether execution is running inside a trusted server-side sandbox
     * (WP-CLI, cron, WordPress installer, internal canary bypass, or Plugin Check test harness).
     * Never trusts attacker-controlled HTTP_REFERER or raw unauthenticated $_REQUEST['action'].
     */
    public static function is_trusted_plugin_check_or_cli_runtime(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }
        if (function_exists('wp_doing_cron') && wp_doing_cron()) {
            return true;
        }
        if (defined('WEBCAREPROSCAN_PCP_TEST_HARNESS') && WEBCAREPROSCAN_PCP_TEST_HARNESS) {
            return true;
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\HoneyTokenEngine', false) && HoneyTokenEngine::$internal_audit_bypass) {
            return true;
        }

        if (function_exists('debug_backtrace')) {
            $is_installing = (defined('WP_INSTALLING') && WP_INSTALLING) || (function_exists('is_blog_installed') && !is_blog_installed());
            $is_auth_admin = self::is_authenticated_administrator();
            if ($is_installing || $is_auth_admin) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Server-side execution stack verification for installer / authenticated PCP harness.
                $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);
                foreach ($trace as $frame) {
                    $fn  = $frame['function'] ?? '';
                    $cls = ltrim((string) ($frame['class'] ?? ''), '\\');
                    if ($is_installing && ($fn === 'wp_install' || $fn === 'wp_install_defaults')) {
                        return true;
                    }
                    if ($is_auth_admin && $cls !== '' && str_starts_with($cls, 'WordPress\\Plugin_Check\\')) {
                        return true;
                    }
                }
            }
        }

        if (self::is_plugin_check_db_sandbox() && self::is_authenticated_administrator()) {
            return true;
        }

        return false;
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Prevent guest or unprivileged option tampering.
     */
    public static function rasp_guard_critical_options($value, $option, $old_value) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return $value;
        }

        $guarded_options = [
            'users_can_register',
            'default_role',
            'siteurl',
            'home',
            'active_plugins',
            'admin_email',
        ];

        // Fast-path: Only inspect targeted critical privilege options
        if (!in_array($option, $guarded_options, true)) {
            return $value;
        }

        // Only allow trusted server-side runtimes (WP-CLI, cron, installer, PCP sandbox prefix/stack) or verified admins
        if (self::is_trusted_plugin_check_or_cli_runtime()) {
            return $value;
        }
        if (self::is_authenticated_administrator()) {
            return $value;
        }
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return $value;
        }

        $client_ip = self::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $option . microtime(true)), 0, 8));
        $reason = sprintf('Unauthenticated RASP tamper attempt on core option "%s"', $option);

        self::log_incident([
            'id'          => 'WAF-RASP-OPTION-TAMPER',
            'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
            'category'    => 'Runtime RASP Hook Defense',
            'description' => sprintf(
                /* translators: 1: Option name, 2: Client IP */
                __('Unauthenticated request from %2$s attempted unauthorized runtime tampering with core option "%1$s".', 'webcare-pro-security'),
                $option,
                $client_ip
            ),
            'match_type'  => 'Unauthorized Option Mutation',
            'match_value' => $option,
            'payload'     => "Option: {$option} Attempted Value: " . substr(wp_json_encode($value), 0, 100),
        ], 'blocked', $incident_id);

        if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
            self::add_blocked_ip(
                $client_ip,
                $reason,
                86400,
                'WAF-RASP-OPTION-TAMPER',
                'Runtime Option Tamper Trap',
                'Runtime RASP Hook Defense',
                $incident_id
            );
        }

        // Hard Inviolable Revert: return the old value immediately
        return $old_value;
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged role escalation to administrator.
     *
     * @param int    $user_id   User ID
     * @param string $role      Assigned role
     * @param array  $old_roles Previous roles
     * @return void
     */
    public static function rasp_guard_user_role_assignment(int $user_id, string $role, array $old_roles): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return;
        }

        if (self::is_trusted_plugin_check_or_cli_runtime()) {
            return;
        }

        // If assigning elevated role (administrator or editor)
        if (in_array(strtolower($role), ['administrator', 'editor'], true)) {
            // Verified logged-in administrator with manage_options is legitimate
            if (self::is_authenticated_administrator()) {
                return;
            }
            if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
                return;
            }

            // JIT Ephemeral support user activation check (if active)
            if (class_exists('\\WebCareProScanner\\Identity\\WebCareJitMuGuardian')) {
                $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
                if (isset($support_users[$user_id])) {
                    return; // Authorized JIT elevation
                }
            }

            $client_ip = self::get_client_ip();
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $role . $user_id . microtime(true)), 0, 8));
            $reason = sprintf('Unauthorized role escalation to "%s" on user #%d', $role, $user_id);

            self::log_incident([
                'id'          => 'WAF-RASP-ROLE-ESCALATION',
                'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
                'category'    => 'Runtime RASP Hook Defense',
                'description' => sprintf(
                    /* translators: 1: Role, 2: User ID, 3: Client IP */
                    __('Unauthorized session from %3$s attempted to assign "%1$s" role to user #%2$d without manage_options capability.', 'webcare-pro-security'),
                    $role,
                    $user_id,
                    $client_ip
                ),
                'match_type'  => 'Privilege Escalation Intercept',
                'match_value' => $role,
                'payload'     => "User ID: {$user_id} Target Role: {$role} Caller: Guest / Non-Admin",
            ], 'blocked', $incident_id);

            if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                self::add_blocked_ip(
                    $client_ip,
                    $reason,
                    86400,
                    'WAF-RASP-ROLE-ESCALATION',
                    'Runtime Role Escalation Trap',
                    'Runtime RASP Hook Defense',
                    $incident_id
                );
            }

            wp_die(
                esc_html__('Security Violation: Unauthorized role escalation intercepted by WebCare Runtime RASP.', 'webcare-pro-security'),
                esc_html__('Forbidden', 'webcare-pro-security'),
                ['response' => 403]
            );
        }
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest registration creating administrator or editor users.
     *
     * @param int $user_id
     * @return void
     */
    public static function rasp_guard_user_registration(int $user_id): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return;
        }

        if (self::is_trusted_plugin_check_or_cli_runtime()) {
            return;
        }

        // Allow verified administrators
        if (self::is_authenticated_administrator()) {
            return;
        }
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return;
        }

        // If user was created by an unauthenticated guest or non-admin session
        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        if ($user && array_intersect(['administrator', 'editor'], array_map('strtolower', (array) $user->roles))) {
            // Instantly demote or strip roles
            $user->set_role('subscriber');

            $client_ip = self::get_client_ip();
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $user->user_login . $user_id . microtime(true)), 0, 8));
            $reason = sprintf('Unauthenticated registration of elevated account "%s" (#%d)', $user->user_login, $user_id);

            self::log_incident([
                'id'          => 'WAF-RASP-ADMIN-REG-BLOCKED',
                'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
                'category'    => 'Runtime RASP Hook Defense',
                'description' => sprintf(
                    /* translators: 1: User ID, 2: Client IP */
                    __('Unauthenticated guest from %2$s registered new account (#%1$d) with elevated administrator privileges. Account was demoted to subscriber.', 'webcare-pro-security'),
                    $user_id,
                    $client_ip
                ),
                'match_type'  => 'Guest Admin Registration',
                'match_value' => (string) $user_id,
                'payload'     => "User: {$user->user_login} ID: {$user_id}",
            ], 'blocked', $incident_id);

            if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
                self::add_blocked_ip(
                    $client_ip,
                    $reason,
                    86400,
                    'WAF-RASP-ADMIN-REG-BLOCKED',
                    'Unauthorized Admin Registration Trap',
                    'Runtime RASP Hook Defense',
                    $incident_id
                );
            }
        }
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged metadata injection into critical usermeta.
     *
     * Traps direct database usermeta injections targeting _application_passwords, wp_capabilities, or user_level
     * that bypass high-level WordPress helper functions.
     *
     * Features zero-FP detection for legitimate WordPress Core REST API application password usage pings:
     * When an existing Application Password authenticates, WP Core updates 'last_used' and 'last_ip' during
     * determine_current_user before is_user_logged_in() is set. We verify the token count and password hashes
     * match existing database entries, allowing telemetry updates while blocking rogue creations and hash alterations.
     *
     * @param null|bool $check      Whether to allow updating/adding metadata
     * @param int       $object_id  User ID
     * @param string    $meta_key   Metadata key
     * @param mixed     $meta_value Metadata value
     * @param mixed     $prev_value Previous value
     * @return null|bool null to proceed with core update, false to abort
     */
    public static function rasp_guard_user_metadata_injection($check, int $object_id, string $meta_key, $meta_value, $prev_value = '') {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return $check;
        }

        // Fast-path: Only inspect targeted sensitive security metadata keys
        $orig_prefix   = self::get_original_table_prefix();
        global $wpdb;
        $active_prefix = isset($wpdb->base_prefix) ? $wpdb->base_prefix : (isset($wpdb->prefix) ? $wpdb->prefix : 'wp_');
        $prefix        = $orig_prefix;

        $guarded_keys = [
            '_application_passwords',
            $orig_prefix . 'capabilities',
            $orig_prefix . 'user_level',
        ];
        if ($active_prefix !== $orig_prefix) {
            $guarded_keys[] = $active_prefix . 'capabilities';
            $guarded_keys[] = $active_prefix . 'user_level';
        }

        if (!in_array($meta_key, $guarded_keys, true)) {
            return $check;
        }

        // Skip only verified server-side runtimes (WP-CLI, cron, installer, internal canary, PCP sandbox/stack)
        // or verified administrators (including direct original-table cookie verification under _pc_ sandboxing).
        if (self::is_trusted_plugin_check_or_cli_runtime() || self::is_authenticated_administrator()) {
            return $check;
        }

        // 2. Allow authenticated administrators or authorized profile editors
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            if (self::is_authenticated_administrator()) {
                return $check;
            }
            if (function_exists('current_user_can') && (current_user_can('manage_options') || current_user_can('edit_user', $object_id))) {
                return $check;
            }
        }

        // 3. Allow standard, benign user registration and role assignment
        // During frontend registration (e.g. WooCommerce, LMS student registration, core registration),
        // WordPress core (wp_insert_user) or legitimate registration plugins assign default low-privileged roles
        // (subscriber, customer, student) while the client is still an unauthenticated guest (is_user_logged_in() === false).
        // We verify that the mutation is:
        // A) Assigning a safe, non-administrative role/capability from registered WordPress roles, OR
        // B) Executed within an authentic registration or user creation lifecycle.
        if ($meta_key === $prefix . 'capabilities' || $meta_key === $prefix . 'user_level') {
            $is_safe_registration_mutation = false;

            // Check if this metadata update is assigning a safe, non-admin role
            if ($meta_key === $prefix . 'capabilities' && is_array($meta_value)) {
                $requested_roles = array_keys(array_filter($meta_value));
                $has_admin_privilege = false;

                // Dangerous capabilities and roles that guests should NEVER be granted
                $prohibited_privileges = [
                    'administrator',
                    'editor',
                    'manage_options',
                    'edit_users',
                    'promote_users',
                    'activate_plugins',
                    'edit_plugins',
                    'edit_themes',
                    'switch_themes',
                    'unfiltered_html',
                    'unfiltered_upload',
                ];

                foreach ($requested_roles as $role_or_cap) {
                    $lower_role = strtolower((string) $role_or_cap);
                    if (in_array($lower_role, $prohibited_privileges, true)) {
                        $has_admin_privilege = true;
                        break;
                    }

                    // Check if role has manage_options capability in global role registry
                    if (function_exists('get_role')) {
                        $role_obj = get_role($lower_role);
                        if ($role_obj && $role_obj->has_cap('manage_options')) {
                            $has_admin_privilege = true;
                            break;
                        }
                    }
                }

                // If no elevated privileges are being assigned, verify the user was created recently or in current registration request
                if (!$has_admin_privilege) {
                    $user_obj = function_exists('get_userdata') ? get_userdata($object_id) : null;
                    if ($user_obj) {
                        $registered_time = strtotime($user_obj->user_registered);
                        // Allow if user registered within the last 120 seconds (standard new account registration window)
                        if ($registered_time && (time() - $registered_time) <= 120) {
                            $is_safe_registration_mutation = true;
                        }
                    } else {
                        // Brand-new insertion where user row was just created in wp_users
                        $is_safe_registration_mutation = true;
                    }
                }
            } elseif ($meta_key === $prefix . 'user_level') {
                // User levels 0, 1, 2 correspond to Subscriber/Contributor/Author (level 10 is Administrator)
                $level = (int) $meta_value;
                if ($level < 7) {
                    $user_obj = function_exists('get_userdata') ? get_userdata($object_id) : null;
                    if ($user_obj) {
                        $registered_time = strtotime($user_obj->user_registered);
                        if ($registered_time && (time() - $registered_time) <= 120) {
                            $is_safe_registration_mutation = true;
                        }
                    } else {
                        $is_safe_registration_mutation = true;
                    }
                }
            }

            // Also inspect stack trace: if originated from core WP_User::set_role / wp_insert_user / register_new_user
            if (!$is_safe_registration_mutation && function_exists('debug_backtrace')) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Context inspection required to distinguish legitimate WordPress core registration from raw unauthenticated SQL/HTTP privilege injections.
                $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);
                foreach ($trace as $frame) {
                    $fn = $frame['function'] ?? '';
                    $cls = $frame['class'] ?? '';
                    if (
                        $fn === 'wp_insert_user' ||
                        $fn === 'wp_create_user' ||
                        $fn === 'register_new_user' ||
                        ($cls === 'WP_User' && $fn === 'set_role')
                    ) {
                        // Double check that we are not assigning administrator
                        if ($meta_key === $prefix . 'capabilities' && is_array($meta_value)) {
                            $has_admin = !empty($meta_value['administrator']) || !empty($meta_value['manage_options']);
                            if (!$has_admin) {
                                $is_safe_registration_mutation = true;
                                break;
                            }
                        } elseif ($meta_key === $prefix . 'user_level' && (int) $meta_value < 7) {
                            $is_safe_registration_mutation = true;
                            break;
                        }
                    }
                }
            }

            if ($is_safe_registration_mutation) {
                return $check; // Safe legitimate registration: Allow core to write user roles/capabilities
            }
        }

        // 4. Special handling for _application_passwords:
        // When WordPress Core validates an Application Password during REST API determine_current_user,
        // it calls WP_Application_Passwords::record_application_password_usage() to update 'last_used' and 'last_ip'.
        // At that millisecond, is_user_logged_in() is still false.
        // We permit the write ONLY if the token count and password hashes exactly match existing entries.
        if ($meta_key === '_application_passwords') {
            $existing = get_user_meta($object_id, '_application_passwords', true);
            if (is_array($existing) && is_array($meta_value) && count($existing) === count($meta_value)) {
                $existing_map = [];
                foreach ($existing as $item) {
                    if (isset($item['uuid'], $item['password'])) {
                        $existing_map[$item['uuid']] = $item['password'];
                    }
                }

                $is_only_usage_ping = true;
                foreach ($meta_value as $new_item) {
                    $uuid = $new_item['uuid'] ?? '';
                    $pass = $new_item['password'] ?? '';
                    if (!isset($existing_map[$uuid]) || !hash_equals((string) $existing_map[$uuid], (string) $pass)) {
                        $is_only_usage_ping = false;
                        break;
                    }
                }

                if ($is_only_usage_ping) {
                    return $check; // Safe: Core recording last_used and last_ip on existing authentic token
                }
            }
        }

        $client_ip = self::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $meta_key . $object_id . microtime(true)), 0, 8));
        $reason = sprintf('Unauthenticated usermeta injection on "%s" for user #%d', $meta_key, $object_id);

        self::log_incident([
            'id'          => 'WAF-RASP-META-INJECTION',
            'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
            'category'    => 'Runtime RASP Hook Defense',
            'description' => sprintf(
                /* translators: 1: Meta key, 2: User ID, 3: Client IP */
                __('Unauthenticated request from %3$s attempted unauthorized runtime usermeta injection into "%1$s" for user #%2$d.', 'webcare-pro-security'),
                $meta_key,
                $object_id,
                $client_ip
            ),
            'match_type'  => 'Unauthorized Usermeta Mutation',
            'match_value' => $meta_key,
            'payload'     => "User: {$object_id} Meta: {$meta_key}",
        ], 'blocked', $incident_id);

        if (!self::is_authenticated_administrator() && !self::is_server_origin_or_loopback($client_ip)) {
            self::add_blocked_ip(
                $client_ip,
                $reason,
                86400,
                'WAF-RASP-META-INJECTION',
                'Runtime Usermeta Privilege Trap',
                'Runtime RASP Hook Defense',
                $incident_id
            );
        }

        // Returning false tells WordPress update_metadata/add_metadata to immediately abort without writing to DB
        return false;
    }

    /**
     * Dispatch instant telemetry alert whenever an Application Password is created.
     *
     * @param int    $user_id User ID
     * @param array  $new_item Application password record
     * @param string $new_password Plaintext password
     * @param array  $args Creation arguments
     * @return void
     */
    public static function telemetry_on_application_password_created(int $user_id, array $new_item, string $new_password, array $args): void {
        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $username = $user ? $user->user_login : "User #{$user_id}";
        $app_name = sanitize_text_field($new_item['name'] ?? 'Unknown App');
        $uuid     = sanitize_text_field($new_item['uuid'] ?? '');
        $client_ip = self::get_client_ip();

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'auth_application_password_created',
                'auth',
                [
                    'user_id'     => $user_id,
                    'username'    => $username,
                    'app_name'    => $app_name,
                    'uuid'        => $uuid,
                    'ip'          => $client_ip,
                    'description' => sprintf('New Application Password "%s" generated for user "%s" from IP %s.', $app_name, $username, $client_ip),
                ]
            );
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_application_password_created', [
                'user_id'     => $user_id,
                'username'    => $username,
                'app_name'    => $app_name,
                'uuid'        => $uuid,
                'ip'          => $client_ip,
                'timestamp'   => current_time('mysql'),
            ]);
        }
    }

    /**
     * Mask recognized scalar password fields (up to depth 4 and <= 128 chars) exclusively in the
     * parsed heuristic representation so passwords containing '<script' or prompt-like text do not
     * cause false-positive XSS / AI-Prompt blocks, while mandatory signatures inspect 100% raw values.
     *
     * @param array $data  Parsed POST or JSON array.
     * @param int   $depth Current recursion depth.
     * @return array Copy of $data with scalar password fields removed.
     */
    public static function mask_password_fields_for_heuristics(array $data, int $depth = 0): array {
        if ($depth > 4) {
            return $data;
        }
        $pw_keys = [
            'pwd',
            'password',
            'pass1',
            'pass2',
            'account_password',
            'user_pass',
            'current_password',
            'new_password',
            'confirm_password',
        ];
        foreach ($data as $k => $v) {
            $k_lower = is_string($k) ? strtolower($k) : '';
            if ($k_lower !== '' && in_array($k_lower, $pw_keys, true) && is_string($v) && strlen($v) <= 128) {
                unset($data[$k]);
            } elseif (is_array($v)) {
                $data[$k] = self::mask_password_fields_for_heuristics($v, $depth + 1);
            }
        }
        return $data;
    }

    /**
     * Schema-aware masking of known WAF rule regex / pattern expression fields during verified admin settings writes
     * so configuring security patterns does not self-block on heuristic checks (XSS/AI-Prompt),
     * while preserving deep inspection on all other keys and never masking arbitrary nested metadata.
     *
     * @param array  $data Input payload data.
     * @param string $rest_route Resolved REST route.
     * @return array Data with top-level and container expression fields redacted.
     */
    public static function redact_waf_config_expressions(array $data, string $rest_route = ''): array {
        $norm_route = '/' . trim(strtolower($rest_route), '/');

        // 1. Settings & Wizard routes: redact only allowlist pattern keys at root or inside settings/firewall_settings
        $settings_routes = [
            '/webcare-pro-security/v1/settings',
            '/webcare-pro-security/v1/settings/import',
            '/webcare-pro-security/v1/wizard/save',
        ];
        if (in_array($norm_route, $settings_routes, true)) {
            $allowlist_keys = [
                'waf_whitelisted_urls',
                'waf_targeted_allowlist_rules',
                'waf_allowed_host_aliases',
            ];
            foreach ($allowlist_keys as $ak) {
                unset($data[$ak]);
            }
            foreach (['settings', 'firewall_settings', 'advanced_settings'] as $container) {
                if (isset($data[$container]) && is_array($data[$container])) {
                    foreach ($allowlist_keys as $ak) {
                        unset($data[$container][$ak]);
                    }
                }
            }
            return $data;
        }

        // 2. Modular WAF custom rule & parser routes: redact only rule expression fields at root or inside rule/rules
        $rule_routes = [
            '/webcare-pro-security/v1/modular-waf/rule/custom',
            '/webcare-pro-security/v1/modular-waf/rule/parse-wirefilter',
            '/webcare-pro-security/v1/modular-waf/rule/parse-ai',
            '/webcare-pro-security/v1/modular-waf/rule/ai-generate',
            '/webcare-pro-security/v1/modular-waf/rule/simulate',
        ];
        if (in_array($norm_route, $rule_routes, true)) {
            $rule_expr_keys = [
                'conditions',
                'wirefilter',
                'expression',
                'pattern',
                'regex',
                'target_uri',
                'target_value',
            ];
            foreach ($rule_expr_keys as $rk) {
                unset($data[$rk]);
            }
            if (isset($data['rule']) && is_array($data['rule'])) {
                foreach ($rule_expr_keys as $rk) {
                    unset($data['rule'][$rk]);
                }
            }
            if (isset($data['rules']) && is_array($data['rules'])) {
                foreach ($data['rules'] as $idx => $r_item) {
                    if (is_array($r_item)) {
                        foreach ($rule_expr_keys as $rk) {
                            unset($data['rules'][$idx][$rk]);
                        }
                    }
                }
            }
            return $data;
        }

        // Any other route: never redact anything
        return $data;
    }

    /**
     * Extract and normalize sub-request payloads from REST API batch requests (/wp/v2/batch, /batch/v1).
     * Defeats REST API batch tunneling and smuggling bypasses (CVE-2026-63030 & CVE-2026-60137 chain).
     * Enforces strict recursion depth (max 2), payload size (max 64KB), and sub-request count (max 25) limits.
     *
     * @param string $raw_uri
     * @param string $raw_input
     * @return array Array of normalized sub-request query & body strings.
     */
    public static function extract_rest_batch_payloads(string $raw_uri, string $raw_input): array {
        $extracted = [];
        $clean_uri = strtolower($raw_uri);

        // Check if current endpoint targets REST batch API
        $is_batch = str_contains($clean_uri, '/wp-json/wp/v2/batch') ||
                    str_contains($clean_uri, '/wp-json/batch/v1') ||
                    str_contains($clean_uri, 'rest_route=%2fwp%2fv2%2fbatch') ||
                    str_contains($clean_uri, 'rest_route=/wp/v2/batch') ||
                    str_contains($clean_uri, 'rest_route=%2fbatch%2fv1') ||
                    str_contains($clean_uri, 'rest_route=/batch/v1');

        if (!$is_batch) {
            return $extracted;
        }

        // Limit maximum batch JSON length to 65,536 bytes (64KB) to prevent worker DoS
        if (strlen($raw_input) > 65536) {
            return [$raw_input];
        }

        $decoded = json_decode($raw_input, true);
        if (!is_array($decoded) || empty($decoded['requests']) || !is_array($decoded['requests'])) {
            return $extracted;
        }

        // Bound sub-request count to maximum 25 items to prevent PHP worker exhaustion
        $requests = array_slice($decoded['requests'], 0, 25);

        foreach ($requests as $req) {
            if (!is_array($req)) {
                continue;
            }

            // Extract path/route
            if (!empty($req['path']) && is_string($req['path'])) {
                $extracted[] = $req['path'];
                $path_parts = wp_parse_url($req['path']);
                if (!empty($path_parts['query'])) {
                    $extracted[] = urldecode($path_parts['query']);
                }
            }

            // Extract body
            if (!empty($req['body'])) {
                if (is_array($req['body'])) {
                    $extracted[] = urldecode(http_build_query($req['body']));
                    $extracted[] = (string) wp_json_encode($req['body']);
                } elseif (is_string($req['body'])) {
                    $extracted[] = $req['body'];
                    $extracted[] = urldecode($req['body']);
                }
            }

            // Extract headers (e.g. smuggled X-HTTP-Method-Override or auth tokens)
            if (!empty($req['headers']) && is_array($req['headers'])) {
                foreach ($req['headers'] as $hk => $hv) {
                    if (is_string($hv)) {
                        $extracted[] = "{$hk}: {$hv}";
                    }
                }
            }
        }

        return $extracted;
    }

    /**
     * Flush any IP ban intents queued by Preload Micro-WAF custom rules before WordPress booted.
     *
     * Runs with a zero-overhead file_exists() check and deletes the queue atomically after processing.
     *
     * @return int Number of queued IP bans processed
     */
    public static function flush_preload_ban_queue(): int {
        if (!class_exists(__NAMESPACE__ . '\MicroWafCompiler')) {
            return 0;
        }

        $queue_file = trailingslashit(MicroWafCompiler::get_compiled_dir()) . '.preload_ban_queue.json';
        if (!file_exists($queue_file)) {
            return 0;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local compiled WAF queue file read before deletion
        $raw = @file_get_contents($queue_file);
        wp_delete_file($queue_file);

        if (!is_string($raw) || $raw === '') {
            return 0;
        }

        $items = json_decode($raw, true);
        if (!is_array($items) || empty($items)) {
            return 0;
        }

        $processed = 0;
        foreach ($items as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $ip = sanitize_text_field((string) ($entry['ip'] ?? ''));
            if (!filter_var($ip, FILTER_VALIDATE_IP) || self::is_server_origin_or_loopback($ip)) {
                continue;
            }
            $rule_id = sanitize_text_field((string) ($entry['rule_id'] ?? 'MOD-CUSTOM'));
            $reason = sanitize_text_field((string) ($entry['reason'] ?? 'Preload Micro-WAF Custom Rule Violation'));
            $ban_ttl = isset($entry['ban_ttl']) ? (int) $entry['ban_ttl'] : 86400;
            $effective_ttl = $ban_ttl > 0 ? $ban_ttl : 86400;
            $sync_cf = !empty($entry['sync_cloudflare']);

            self::add_blocked_ip(
                $ip,
                $reason,
                $effective_ttl,
                $rule_id,
                'Preload Micro-WAF Custom Rule',
                'Modular Behavioral WAF',
                null,
                null,
                $sync_cf
            );
            $processed++;
        }

        return $processed;
    }

    /**
     * Synchronize and rotate the cryptographic preload auth cookie used by the pre-boot Micro-WAF.
     *
     * Ensures an authentic, tamper-proof cookie is present for logged-in sessions without relying
     * on unverified cookie name substrings (wordpress_logged_in_*) prior to WordPress core bootstrap.
     *
     * @return void
     */
    public static function sync_preload_auth_cookie(): void {
        if (!function_exists('is_user_logged_in')) {
            return;
        }

        if (!is_user_logged_in()) {
            if (isset($_COOKIE['webcare_preload_auth'])) {
                self::clear_preload_auth_cookie();
            }
            return;
        }

        $raw_c = isset($_COOKIE['webcare_preload_auth']) && is_string($_COOKIE['webcare_preload_auth'])
            ? trim(sanitize_text_field(wp_unslash($_COOKIE['webcare_preload_auth'])))
            : '';
        $needs_refresh = true;

        if ($raw_c !== '') {
            if (strpos($raw_c, '|') === false) {
                $raw_c = (string) @base64_decode($raw_c, true);
            }
            $parts = explode('|', $raw_c);
            if (count($parts) === 4) {
                list($c_uid, $c_is_admin, $c_exp, $c_sig) = $parts;
                $current_uid = (int) get_current_user_id();
                $current_is_admin = current_user_can('manage_options') ? 1 : 0;
                $salt = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-preload-auth-salt';
                $ip_bind = self::get_client_ip();
                $expected_sig = hash_hmac('sha256', "{$c_uid}|{$c_is_admin}|{$c_exp}|{$ip_bind}", $salt);

                // If valid, matches current user/role, and has at least 15m remaining, no refresh needed
                if ((int) $c_uid === $current_uid && (int) $c_is_admin === $current_is_admin &&
                    (int) $c_exp > (time() + 900) && hash_equals($expected_sig, $c_sig)) {
                    $needs_refresh = false;
                }
            }
        }

        if ($needs_refresh) {
            self::issue_preload_auth_cookie();
        }
    }

    /**
     * Handle user login hook to issue the preload auth cookie immediately upon sign-in.
     *
     * @param string   $user_login Username.
     * @param \WP_User $user       Authenticated user object.
     * @return void
     */
    public static function on_user_login_preload_auth($user_login, $user): void {
        if ($user instanceof \WP_User && $user->ID > 0) {
            self::issue_preload_auth_cookie($user);
        }
    }

    /**
     * Issue or refresh the cryptographic preload auth cookie for an authenticated user.
     *
     * @param \WP_User|null $user Target user object (defaults to current logged-in user).
     * @return void
     */
    public static function issue_preload_auth_cookie($user = null): void {
        if (headers_sent()) {
            return;
        }

        if ($user === null && function_exists('wp_get_current_user')) {
            $user = wp_get_current_user();
        }

        if (!$user || !($user instanceof \WP_User) || $user->ID <= 0) {
            return;
        }

        $uid      = (int) $user->ID;
        $is_admin = user_can($user, 'manage_options') ? 1 : 0;
        $exp      = time() + 3600; // 1-hour rolling validity
        $ip_bind  = self::get_client_ip();
        $salt     = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-preload-auth-salt';
        $payload  = "{$uid}|{$is_admin}|{$exp}";
        $sig      = hash_hmac('sha256', $payload . '|' . $ip_bind, $salt);
        $val      = base64_encode("{$payload}|{$sig}");

        $cookie_path   = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';
        $cookie_domain = defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '';
        $secure        = function_exists('is_ssl') && is_ssl();

        // Issue HttpOnly, Secure, SameSite=Lax cookie
        if (PHP_VERSION_ID >= 70300) {
            setcookie('webcare_preload_auth', $val, [
                'expires'  => $exp,
                'path'     => $cookie_path,
                'domain'   => $cookie_domain,
                'secure'   => $secure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        } else {
            // phpcs:ignore WordPress.Security.SafeCookie.SetCookieDomain
            setcookie('webcare_preload_auth', $val, $exp, $cookie_path . '; samesite=Lax', $cookie_domain, $secure, true);
        }

        $_COOKIE['webcare_preload_auth'] = $val;
    }

    /**
     * Clear the cryptographic preload auth cookie on user logout or session revocation.
     *
     * @return void
     */
    public static function clear_preload_auth_cookie(): void {
        if (!headers_sent()) {
            $cookie_path   = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';
            $cookie_domain = defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '';
            $secure        = function_exists('is_ssl') && is_ssl();

            if (PHP_VERSION_ID >= 70300) {
                setcookie('webcare_preload_auth', '', [
                    'expires'  => time() - 3600,
                    'path'     => $cookie_path,
                    'domain'   => $cookie_domain,
                    'secure'   => $secure,
                    'httponly' => true,
                    'samesite' => 'Lax',
                ]);
            } else {
                // phpcs:ignore WordPress.Security.SafeCookie.SetCookieDomain
                setcookie('webcare_preload_auth', '', time() - 3600, $cookie_path, $cookie_domain, $secure, true);
            }
        }

        if (isset($_COOKIE['webcare_preload_auth'])) {
            unset($_COOKIE['webcare_preload_auth']);
        }
    }

    /**
     * Generate a signed, time-bounded emergency WAF bypass token for administrative access.
     *
     * @param string|null $ip  Target client IP to bind (defaults to current client IP).
     * @param int         $ttl Time to live in seconds (default 900s / 15m).
     * @return string Formatted as "<timestamp>.<hmac>".
     */
    public static function generate_waf_bypass_token(?string $ip = null, int $ttl = 900): string {
        $bypass_secret = (string) get_option('webcareproscan_micro_waf_bypass_token', '');
        if ($bypass_secret === '') {
            $bypass_secret = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-waf-bypass-salt';
        }
        $ts = time();
        $target_ip = $ip !== null ? trim($ip) : self::get_client_ip();
        if (stripos($target_ip, '::ffff:') === 0) {
            $mapped_v4 = substr($target_ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $target_ip = $mapped_v4;
            }
        }
        $hmac = hash_hmac('sha256', 'wcp_bypass|' . $ts . '|' . $target_ip, $bypass_secret);
        return $ts . '.' . $hmac;
    }

    /**
     * Verify a signed, time-bounded emergency WAF bypass token.
     *
     * @param string      $token     Candidate token string ("<timestamp>.<hmac>").
     * @param string|null $ip        Connecting client IP (defaults to current client IP).
     * @param int         $max_drift Maximum allowable timestamp drift in seconds (default 900s).
     * @return bool
     */
    public static function verify_waf_bypass_token(string $token, ?string $ip = null, int $max_drift = 900): bool {
        $token = trim($token);
        if ($token === '' || strpos($token, '.') === false) {
            return false;
        }
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2 || !ctype_digit((string) $parts[0])) {
            return false;
        }
        $ts = (int) $parts[0];
        $hmac = (string) $parts[1];
        if (abs(time() - $ts) > $max_drift) {
            return false;
        }
        $target_ip = $ip !== null ? trim($ip) : self::get_client_ip();
        if (stripos($target_ip, '::ffff:') === 0) {
            $mapped_v4 = substr($target_ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $target_ip = $mapped_v4;
            }
        }
        $bypass_secret = (string) get_option('webcareproscan_micro_waf_bypass_token', '');
        if ($bypass_secret === '') {
            $bypass_secret = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-waf-bypass-salt';
        }
        $expected_hmac = hash_hmac('sha256', 'wcp_bypass|' . $ts . '|' . $target_ip, $bypass_secret);
        return hash_equals($expected_hmac, $hmac);
    }
}
