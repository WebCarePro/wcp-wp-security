<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

class FirewallEngine {
    private static $real_ip = null;
    private static $connecting_peer_ip = null;
    private static $detected_environment = null;

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
        if (class_exists('\\WcpScanner\\Firewall\\HoneyTokenEngine')) {
            HoneyTokenEngine::init();
        }

        // Run early at plugins_loaded priority 0
        add_action('plugins_loaded', [__CLASS__, 'inspect_incoming_request'], 0);

        // Protect XML-RPC early if enabled
        add_action('init', [__CLASS__, 'check_xmlrpc_guard'], 0);

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

        // Rule #31: Lost-Password Reset Burst Flooding Guard
        add_action('login_form_lostpassword', [__CLASS__, 'check_lostpassword_flood'], 0);
        add_action('lostpassword_post', [__CLASS__, 'check_lostpassword_submission'], 0);
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
            $cf_ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
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
        // If connecting from local/private network AND Cloudflare header is present or WCP_TRUST_LOCAL_PROXY is enabled
        $is_local_or_private = ($ip === '127.0.0.1' || $ip === '::1' || self::is_private_ip($ip));
        if ($is_local_or_private) {
            if ((defined('WCP_TRUST_LOCAL_PROXY') && WCP_TRUST_LOCAL_PROXY) || !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
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
        $env_proxies = getenv('WCP_TRUSTED_PROXIES') ?: (isset($_ENV['WCP_TRUSTED_PROXIES']) ? sanitize_text_field(wp_unslash($_ENV['WCP_TRUSTED_PROXIES'])) : '');
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
        $opt = function_exists('get_option') ? get_option('wcpscan_trusted_proxies', '') : '';
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
     * Check if the incoming request is made by a verified authenticated WordPress administrator.
     *
     * @return bool
     */
    public static function is_authenticated_administrator(): bool {
        static $cached_result = null;
        if ($cached_result !== null) {
            return $cached_result;
        }

        $cached_result = false;
        $verified_user_id = 0;

        // Layer 1: Check standard WordPress authenticated session if available
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('get_current_user_id')) {
            $verified_user_id = (int) get_current_user_id();
        }

        // Layer 2: Independent Cryptographic Auth Cookie Validation (essential at plugins_loaded: 0)
        if ($verified_user_id <= 0) {
            if (!function_exists('wp_validate_auth_cookie') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
                require_once ABSPATH . 'wp-includes/pluggable.php';
            }
        }

        if ($verified_user_id <= 0 && function_exists('wp_validate_auth_cookie')) {
            $auth_cookie = '';
            $cookie_schemes = ['logged_in', 'secure_auth', 'auth'];

            foreach ($cookie_schemes as $scheme) {
                $cookie_name = ($scheme === 'logged_in')
                    ? (defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : 'wordpress_logged_in_' . COOKIEHASH)
                    : (defined('SECURE_AUTH_COOKIE') ? SECURE_AUTH_COOKIE : 'wordpress_sec_' . COOKIEHASH);

                if (!empty($_COOKIE[$cookie_name])) {
                    $auth_cookie = sanitize_text_field(wp_unslash($_COOKIE[$cookie_name]));
                    $uid = (int) wp_validate_auth_cookie($auth_cookie, $scheme);
                    if ($uid > 0) {
                        $verified_user_id = $uid;
                        break;
                    }
                }
            }

            // Fallback for default cookie names if constants aren't defined yet
            if ($verified_user_id <= 0) {
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
            return ($cached_result = false);
        }

        // Layer 3: Role and High-Privilege Capability Verification
        if (function_exists('get_userdata')) {
            $user = get_userdata($verified_user_id);
            if (!$user || empty($user->ID)) {
                return ($cached_result = false);
            }

            // Require administrator role or explicit manage_options capability
            $has_admin_cap = $user->has_cap('manage_options') || $user->has_cap('administrator');
            $has_admin_role = in_array('administrator', (array) $user->roles, true);

            if (!$has_admin_cap && !$has_admin_role) {
                return ($cached_result = false);
            }
        } else {
            return ($cached_result = false);
        }

        // Layer 4: Cryptographic Nonce Verification on REST API & AJAX Mutation Requests
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
        $is_rest_call = (strpos($request_uri, '/wp-json/') !== false) || (defined('REST_REQUEST') && REST_REQUEST);

        if ($is_rest_call && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $nonce = isset($_SERVER['HTTP_X_WP_NONCE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE'])) : '';
            if (empty($nonce)) {
                // REST mutation without nonce header is untrusted (protects against CSRF)
                return ($cached_result = false);
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
                    return ($cached_result = false);
                }
            }
        }

        return ($cached_result = true);
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
    public static function is_authenticated_editor_or_builder(): bool {
        static $cached_builder_result = null;
        if ($cached_builder_result !== null) {
            return $cached_builder_result;
        }

        // Check if page builder smart pass is enabled in settings
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        if (isset($settings['waf_allow_page_builders']) && empty($settings['waf_allow_page_builders'])) {
            return ($cached_builder_result = false);
        }

        // Fast-path: Verified administrator always has builder privileges
        if (self::is_authenticated_administrator()) {
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

        // Verify Editor / Content Author capabilities
        if (function_exists('get_userdata')) {
            $user = get_userdata($verified_user_id);
            if (!$user || empty($user->ID)) {
                return ($cached_builder_result = false);
            }

            $has_editor_cap = $user->has_cap('edit_posts') || $user->has_cap('edit_pages') || $user->has_cap('manage_options');
            if (!$has_editor_cap) {
                return ($cached_builder_result = false);
            }
        } else {
            return ($cached_builder_result = false);
        }

        // Identify builder-specific actions and endpoints
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early runtime WAF builder detection
        $ajax_action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');

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

        $is_gutenberg_rest = (
            strpos($request_uri, '/wp-json/wp/v2/posts') !== false ||
            strpos($request_uri, '/wp-json/wp/v2/pages') !== false ||
            strpos($request_uri, '/wp-json/wp/v2/blocks') !== false ||
            strpos($request_uri, '/wp-json/wp/v2/templates') !== false ||
            strpos($request_uri, '/wp-json/wp/v2/template-parts') !== false
        );

        $is_builder_rest = (
            strpos($request_uri, '/wp-json/elementor/') !== false ||
            strpos($request_uri, '/wp-json/breakdance/') !== false ||
            strpos($request_uri, '/wp-json/brizy/') !== false ||
            strpos($request_uri, '/wp-json/seedprod/') !== false ||
            strpos($request_uri, '/wp-json/droip/') !== false ||
            strpos($request_uri, '/wp-json/generateblocks/') !== false ||
            strpos($request_uri, '/wp-json/kadence/') !== false ||
            strpos($request_uri, '/wp-json/uag/') !== false ||
            strpos($request_uri, '/wp-json/fusion-builder/') !== false
        );

        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- Page builder preview detection at early runtime
        $is_builder_preview = (
            isset($_GET['elementor-preview']) ||
            isset($_GET['et_fb']) ||
            isset($_GET['fl_builder']) ||
            isset($_GET['bricks']) ||
            isset($_GET['breakdance']) ||
            isset($_GET['ct_builder']) ||
            isset($_GET['seedprod_builder']) ||
            isset($_GET['brizy-edit']) ||
            isset($_GET['tve']) ||
            isset($_GET['vc_editable']) ||
            isset($_GET['vcv-action']) ||
            isset($_GET['tb_preview']) ||
            isset($_GET['siteorigin_panels_live_editor']) ||
            isset($_GET['droip_editor']) ||
            isset($_GET['dslc']) ||
            isset($_GET['fb-edit'])
        );
        // phpcs:enable WordPress.Security.NonceVerification.Recommended
        if ($is_builder_ajax || $is_gutenberg_rest || $is_builder_rest || $is_builder_preview) {
            return ($cached_builder_result = true);
        }

        return ($cached_builder_result = false);
    }

    /**
     * Inspect Incoming Request
     */
    public static function inspect_incoming_request() {
        // Skip CLI and background WordPress cron tasks
        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) {
            return;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }

        // Record real-time visitor traffic pulse (15s rolling transient) for scanner governor
        // Only count actual public frontend visitor hits (exclude admin-ajax, REST API, admin panel, CLI, and static assets)
        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $is_rest = (defined('REST_REQUEST') && REST_REQUEST) || strpos($req_uri, '/wp-json/') !== false || strpos($req_uri, '?rest_route=') !== false;
        $is_ajax = (defined('DOING_AJAX') && DOING_AJAX) || strpos($req_uri, 'admin-ajax.php') !== false;
        $is_admin_area = is_admin() || strpos($req_uri, '/wp-admin/') !== false;

        if (!$is_admin_area && !$is_rest && !$is_ajax && !self::is_authenticated_administrator()) {
            $visitor_hits = (int) get_transient('wcpscan_active_visitor_traffic_15s');
            set_transient('wcpscan_active_visitor_traffic_15s', $visitor_hits + 1, 15);
        }

        $settings = SettingsManager::get_settings();

        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        $raw_req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $client_ip = self::get_client_ip();

        // Check user IP whitelist
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';

        // Check Allowlisted URLs / URI paths (bypasses all subsequent firewall rules)
        if (!empty($settings['waf_whitelisted_urls']) && self::is_url_whitelisted($request_uri, $settings['waf_whitelisted_urls'])) {
            return;
        }

        // Check Targeted User-Agent, Endpoint & IP Allowlist Rules (Zero-Trust granular bypass)
        $targeted_rules_raw = $settings['waf_targeted_allowlist_rules'] ?? '[]';
        $targeted_rules = is_array($targeted_rules_raw) ? $targeted_rules_raw : json_decode((string) $targeted_rules_raw, true);
        if (!empty($targeted_rules) && is_array($targeted_rules)) {
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            $http_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
            $matched_rule = self::match_targeted_allowlist_rule($request_uri, $user_agent, $client_ip, $http_method, $targeted_rules);
            if ($matched_rule !== null) {
                // Log granular forensic telemetry to WAF logs
                self::log_targeted_allowlist_hit($matched_rule, $client_ip, $request_uri, $user_agent, $http_method);
                return; // Granted safe bypass
            }
        }

        // Adaptive Rate Limiter & Token-Bucket Throttling
        if (class_exists('\\WcpScanner\\Firewall\\AdaptiveRateLimiter')) {
            \WcpScanner\Firewall\AdaptiveRateLimiter::check_request($client_ip);
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Passive inspection of drill token for red team simulation bypass
        $is_drill_request = !empty($_GET['wcp_drill_token']) || !empty($_POST['wcp_drill_token']) || !empty($_SERVER['HTTP_X_WCP_DRILL_TOKEN']);

        // Safe Bypass for Verified Authenticated Administrators and Page Builder Sessions
        // (Prevents false-positive blocks when managing comments, posts, plugins, or editing pages via Elementor/Divi/Gutenberg)
        // Red Team Drill Exception: Never bypass when drill token is present
        if (!$is_drill_request && self::is_authenticated_administrator()) {
            $is_admin_path = (is_admin() || strpos($request_uri, '/wp-admin/') !== false || strpos($request_uri, '/wp-json/wcp-scanner/') !== false);
            if ($is_admin_path) {
                return;
            }
        }

        // Emergency Containment Mode Enforcement
        if (class_exists('\\WcpScanner\\Security\\EmergencyContainmentManager') && \WcpScanner\Security\EmergencyContainmentManager::is_active()) {
            if (!self::is_authenticated_administrator()) {
                if (\WcpScanner\Security\EmergencyContainmentManager::is_maintenance_enabled()) {
                    \WcpScanner\Security\EmergencyContainmentManager::render_containment_screen();
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
                    exit;
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
                    exit;
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
        $is_central_mgmt = self::is_verified_central_management_request($request_uri, $settings);
        if ($is_central_mgmt) {
            return;
        }

        // Rule #34: Oversized Request Buffer & DoS Guard (Earliest execution check)
        if (!empty($settings['waf_block_oversized_requests'])) {
            $is_upload_endpoint = (strpos($request_uri, 'async-upload.php') !== false || strpos($request_uri, '/wp-json/wp/v2/media') !== false);
            $is_admin_area = is_admin() || strpos($request_uri, '/wp-admin/') !== false;
            $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && self::is_commerce_or_membership_request($request_uri);
            $is_exempt_endpoint = $is_upload_endpoint || $is_admin_area || $is_commerce_safe || $is_builder_session;
            $uri_length = strlen($request_uri);
            $query_length = strlen(isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '');
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early WAF payload size check executes before nonce lifecycle
            $post_count = !empty($_POST) && is_array($_POST) ? count($_POST, COUNT_RECURSIVE) : 0;

            if ($uri_length > 2048 && !$is_exempt_endpoint) {
                $rule_triggered = [
                    'id'          => 'WAF-OVERSIZED-URI',
                    'name'        => 'Oversized URI Buffer Overflow Guard',
                    'category'    => 'DoS & Resource Shield',
                    'description' => sprintf('Request URI length of %d bytes exceeded security threshold (2048 bytes).', $uri_length),
                    'match_type'  => 'Buffer Overflow Protection',
                    'match_value' => (string) $uri_length,
                    'payload'     => "URI Length: {$uri_length} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 414);
                exit;
            }

            if ($query_length > 1024 && !$is_exempt_endpoint) {
                $rule_triggered = [
                    'id'          => 'WAF-OVERSIZED-QUERY',
                    'name'        => 'Oversized Query String Guard',
                    'category'    => 'DoS & Resource Shield',
                    'description' => sprintf('Query string length of %d bytes exceeded security threshold (1024 bytes).', $query_length),
                    'match_type'  => 'Buffer Overflow Protection',
                    'match_value' => (string) $query_length,
                    'payload'     => "Query Length: {$query_length} IP: {$client_ip}",
                ];
                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
                exit;
            }

            if ($post_count > 1000 && !$is_exempt_endpoint) {
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
                exit;
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
                exit;
            }
        }

        // Rule #33: admin-ajax.php Unauthenticated Request Burst Rate-Limiter
        if (!empty($settings['waf_limit_admin_ajax'])) {
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

                    if (!$is_woo_public) {
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
                echo 'XML-RPC services are disabled on this WordPress installation by WCP Security Scanner.';
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

        // Block IPs who send POST requests with blank User-Agent and Referer
        if (!empty($settings['waf_block_empty_post_ua_referer'])) {
            $is_post = (isset($_SERVER['REQUEST_METHOD']) && strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) === 'POST');
            if ($is_post) {
                // E-Commerce & Membership Safe Mode: Server-to-server payment gateway webhooks
                // (Stripe, PayPal IPN, Mollie, Square) frequently POST without browser Referer or standard UA.
                $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && self::is_commerce_or_membership_request($request_uri);
                if (!$is_commerce_safe) {
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

        // Rule 18: Instant Sensitive File & Backup Probes Shield
        if (!empty($settings['waf_block_sensitive_file_probes'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            $sensitive_patterns = [
                '/\.(env|git|svn|htaccess|user\.ini)(\/|$)/i',
                '/\.(sql|sql\.gz|tar\.gz|bak)$/i',
                '/(backup|dump|db_backup|wp-config\.php[~_\.bak])/i',
                '/(phpinfo\.php|info\.php)$/i',
            ];
            foreach ($sensitive_patterns as $spat) {
                if (preg_match($spat, $clean_path)) {
                    $rule_triggered = [
                        'id'          => 'WAF-SENSITIVE-FILE-PROBE',
                        'name'        => 'Sensitive File & Backup Probe Block',
                        'category'    => 'File Reconnaissance',
                        'description' => 'Unauthorized probe targeting sensitive system configuration, git repository, or database backup file.',
                        'match_type'  => 'Path Reconnaissance',
                        'match_value' => $clean_path,
                        'payload'     => "Path: {$clean_path} IP: {$client_ip}",
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
                        wp_send_json_error(['message' => 'Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is disallowed by WCP Security Firewall.']);
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
                        wp_send_json_error(['message' => 'Security Policy Violation: Installation of File Manager plugins is disallowed by WCP Security Firewall.']);
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
                $server_addr = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '';
                $is_loopback = in_array($client_ip, ['127.0.0.1', '::1', $server_addr], true);
                $is_admin = self::is_authenticated_administrator();

                if (!$is_loopback && !$is_admin) {
                    $rule_triggered = [
                        'id'          => 'WAF-EXTERNAL-CRON-BLOCK',
                        'name'        => 'External wp-cron.php Abuse Block',
                        'category'    => 'DoS & Resource Shield',
                        'description' => 'Direct external HTTP trigger to wp-cron.php rejected to prevent resource starvation.',
                        'match_type'  => 'Endpoint Protection',
                        'match_value' => 'wp-cron.php',
                        'payload'     => "External IP: {$client_ip} URI: {$request_uri}",
                    ];

                    $mode = $settings['waf_mode'] ?? 'enabled';
                    if ($mode === 'learning') {
                        self::log_incident($rule_triggered, 'detected');
                    } else {
                        self::log_incident($rule_triggered, 'blocked');
                        status_header(403);
                        header('Content-Type: text/plain; charset=utf-8');
                        echo 'External access to wp-cron.php is blocked by WCP Security Scanner.';
                        exit;
                    }
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
        if (!empty($settings['waf_blocked_ips']) && self::is_ip_blocked($client_ip, $settings['waf_blocked_ips'])) {
            $rule_triggered = [
                'id'          => 'USER-CUSTOM-IP-BLOCK',
                'name'        => 'Custom Administrator IP Blocklist',
                'category'    => 'Custom IP Blocklist',
                'description' => 'Connection blocked by administrator-defined custom IP rule.',
                'match_type'  => 'Custom Blocklist',
                'match_value' => $client_ip,
                'payload'     => $client_ip,
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

        // Check active temporary 404 Scanner Lockout
        $lockout_transient = 'wcpscan_404_lock_' . md5($client_ip);
        $lockout_data = get_transient($lockout_transient);
        if ($lockout_data !== false) {
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
                $incident_id = 'WCP-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
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
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
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
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $vpatch_rule = VirtualPatchManager::evaluate_request($client_ip, $request_uri);
        if ($vpatch_rule !== null) {
            ThreatIntelNetwork::record_consensus_beacon($client_ip, $vpatch_rule['name'] ?? 'Virtual Patch Violation', ['category' => 'Virtual Patch']);
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
                if (class_exists('\\WcpScanner\\Firewall\\LearningModeEngine') && \WcpScanner\Firewall\LearningModeEngine::is_route_graduated()) {
                    // Graduated route: actively enforce blocking even in learning mode
                    self::log_incident($rule_triggered, 'blocked');
                    self::render_block_page($rule_triggered, $client_ip);
                    exit;
                } else {
                    if (class_exists('\\WcpScanner\\Firewall\\LearningModeEngine')) {
                        \WcpScanner\Firewall\LearningModeEngine::record_threat_encountered(\WcpScanner\Firewall\LearningModeEngine::get_current_route_key());
                    }
                    // Log only, do not block
                    self::log_incident($rule_triggered, 'detected');
                }
            } else {
                // Enforce block
                self::log_incident($rule_triggered, 'blocked');
                self::render_block_page($rule_triggered, $client_ip);
                exit;
            }
        } else {
            // Clean request passed all firewall filters: profile route parameters
            if (class_exists('\\WcpScanner\\Firewall\\LearningModeEngine')) {
                \WcpScanner\Firewall\LearningModeEngine::profile_benign_request();
            }
        }
    }

    /**
     * Evaluate protection rules across GET, POST, and URI
     */
    private static function evaluate_rules(array $settings, bool $is_complementary): ?array {
        $raw_uri      = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $uri          = urldecode($raw_uri);
        $query_string = isset($_SERVER['QUERY_STRING']) ? urldecode(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';
        $user_agent   = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // Authenticated administrators performing back-end actions in wp-admin or via authenticated WCP REST API are exempt from payload heuristic blocks
        // (Ensures an administrator browsing public frontend pages is STILL fully inspected and protected)
        $is_admin_backend = is_admin() || strpos($raw_uri, '/wp-admin/') !== false;
        $is_wcp_rest_api  = (strpos($raw_uri, '/wp-json/wcp-scanner/') !== false) || (defined('REST_REQUEST') && REST_REQUEST && strpos($raw_uri, 'wcp-scanner') !== false);
        if (self::is_authenticated_administrator() && ($is_admin_backend || $is_wcp_rest_api)) {
            return null;
        }

        // Authenticated Page Builder Smart Pass (Elementor, Divi, Gutenberg, Bricks, Beaver Builder)
        // Verified users with 'edit_posts' saving layouts via builder AJAX or REST endpoints are exempt from false-positive XSS/SQLi payload drops
        if (self::is_authenticated_editor_or_builder()) {
            return null;
        }

        // Combine request parameters for deep inspection (inspect raw inputs so WAF sees malicious script tags or encoding before sanitization)
        $params_to_check = [];

        $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && self::is_commerce_or_membership_request($raw_uri);

        if (!empty($query_string)) {
            $params_to_check[] = $query_string;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Early inspection of GET parameters before route execution
        if (!empty($_GET) && is_array($_GET)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $params_to_check[] = urldecode(http_build_query(wp_unslash($_GET)));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early inspection of raw POST payload before WordPress nonce check
        if (!empty($_POST) && is_array($_POST)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $post_data = wp_unslash($_POST);
            // (e.g. "Apt. #4", "O'Reilly", "Suite / Flat 2B", "Deliver c/o neighbor")
            // must not be concatenated directly into generic path traversal or SQL heuristics.
            if ($is_commerce_safe) {
                $benign_customer_fields = [
                    'billing_address_1', 'billing_address_2', 'shipping_address_1', 'shipping_address_2',
                    'billing_city', 'shipping_city', 'billing_company', 'shipping_company',
                    'order_comments', 'customer_note', 'billing_last_name', 'shipping_last_name',
                    'payment_method_title', 'terms', 'ship_to_different_address'
                ];
                foreach ($benign_customer_fields as $field_key) {
                    unset($post_data[$field_key]);
                }
            }
            $params_to_check[] = urldecode(http_build_query($post_data));
        }

        $raw_input = @file_get_contents('php://input');
        if (!empty($raw_input) && strlen($raw_input) < 131072) { // Inspect up to 128KB payload
            $params_to_check[] = wp_unslash($raw_input);
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

        // 5. Null Byte Poison Attacks (%00 / \0)
        if (!empty($settings['waf_block_null_byte_attacks'])) {
            if (strpos($uri, '%00') !== false || strpos($combined_payload, "\0") !== false || strpos($combined_payload, '%00') !== false) {
                return [
                    'category'    => 'Null Byte Poison',
                    'description' => 'Null byte string termination attack (%00) detected in URI or request payload.',
                    'payload'     => substr($combined_payload, 0, 200),
                ];
            }
        }

        // 6. AI Prompt Injection & Agent Poisoning Shield (Rule #35)
        if (!empty($settings['waf_block_ai_prompt_injection'])) {
            $prompt_patterns = [
                '/\b(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)\b/i',
                '/\b(system\s*prompt\s*:|\[\s*system\s*\]|\bDAN\s+mode\b|developer\s+mode\s+active)\b/i',
                '/\b(you\s+are\s+now\s+(an\s+unfiltered|unrestricted|in\s+developer|in\s+jailbreak))\b/i',
                '/\b(bypass\s+(safety|content)\s+guidelines|reveal\s+(your|the)\s+(system\s+)?instructions)\b/i',
                '/(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\])/i',
                '/\b(dump|output|exfiltrate)\s+(the\s+)?(contents\s+of\s+)?(wp-config\.php|passwd|database\s+credentials)\b/i',
            ];
            foreach ($prompt_patterns as $pattern) {
                if (preg_match($pattern, $uri) || preg_match($pattern, $combined_payload)) {
                    return [
                        'id'          => 'WAF-AI-PROMPT-INJECTION',
                        'name'        => 'AI Prompt Injection & Agent Poisoning Shield (Rule #35)',
                        'category'    => 'AI & Agent Defense',
                        'description' => 'Hostile LLM prompt-injection / tool-poisoning syntax detected in request payload.',
                        'payload'     => substr($combined_payload, 0, 200),
                    ];
                }
            }
        }

        // Rule 21: Open Redirect Phishing Guard
        if (!empty($settings['waf_block_open_redirects'])) {
            $redirect_keys = ['redirect_to', 'redirect', 'url', 'return_to', 'next', 'target'];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Inspection of redirect params
            $all_params = array_merge($_GET, $_POST);
            $home_host = strtolower(wp_parse_url(home_url(), PHP_URL_HOST) ?: '');

            foreach ($redirect_keys as $key) {
                if (!empty($all_params[$key]) && is_string($all_params[$key])) {
                    $val = trim(urldecode($all_params[$key]));
                    if (preg_match('#^https?://#i', $val) || strpos($val, '//') === 0) {
                        $parsed_host = strtolower(wp_parse_url($val, PHP_URL_HOST) ?: '');
                        // If host is specified and does not match the home host or localhost
                        if (!empty($parsed_host) && $parsed_host !== $home_host && $parsed_host !== 'localhost' && $parsed_host !== '127.0.0.1') {
                            // E-Commerce & Membership Intelligence: Exempt legitimate payment processor redirects
                            // and social OAuth return destinations (PayPal, Stripe, Mollie, Klarna, Square, Google, Apple).
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
                echo 'XML-RPC services are disabled on this WordPress installation by WCP Security Scanner.';
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

        // 1. Skip if client IP is whitelisted by administrator
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return;
        }

        $raw_uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // 2. Ignore missing static assets (images, fonts, stylesheets, scripts, favicons)
        if (self::is_static_asset($raw_uri)) {
            return;
        }

        // 3. Genuine Search Engine & Uptime Monitor Exemption:
        // If the request belongs to an authenticated search crawler (Googlebot, Bingbot, etc.)
        // or a verified uptime monitor (UptimeRobot, Pingdom, StatusCake), DO NOT penalize or rate-limit.
        if (BotReconDefense::is_genuine_search_engine($client_ip, $user_agent)) {
            return;
        }
        if (BotReconDefense::is_genuine_uptime_monitor($client_ip, $user_agent, $settings)) {
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
        // must never be locked out by 404 scanner rate-limits (e.g., broken product images or expired variation links).
        if (!empty($settings['waf_ecommerce_safe_mode'])) {
            if (self::has_active_shopper_session() || self::is_commerce_or_membership_request($raw_uri)) {
                return;
            }
        }

        $threshold        = (int) ($settings['waf_404_threshold'] ?? 10);
        $window_seconds   = (int) ($settings['waf_404_window_seconds'] ?? 60);
        $lockout_duration = (int) ($settings['waf_404_lockout_duration'] ?? 30);

        // Check if URI is a known high-risk vulnerability reconnaissance probe
        $is_high_risk = self::is_high_risk_recon_probe($raw_uri);

        // Transient tracking counter per IP
        $counter_transient = 'wcpscan_404_cnt_' . md5($client_ip);
        $current_count     = (int) get_transient($counter_transient);

        // High risk probes advance counter by 3 to accelerate lockout
        $increment = $is_high_risk ? 3 : 1;
        $new_count = $current_count + $increment;

        if ($new_count >= $threshold) {
            // Threshold exceeded: Enforce temporary lockout
            $lockout_transient = 'wcpscan_404_lock_' . md5($client_ip);
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
                $incident_id = 'WCP-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
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
        // E-Commerce Suites
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

        return $has_ecommerce || $has_membership || $has_profiles || defined('WCP_COMMERCE_OVERRIDE');
    }

    /**
     * Check if current request has an active shopper or customer session.
     * Genuine shoppers browsing a store have cart cookies or active customer/membership sessions.
     *
     * @return bool
     */
    public static function has_active_shopper_session(): bool {
        if (empty($_COOKIE) || !is_array($_COOKIE)) {
            return false;
        }

        foreach (array_keys($_COOKIE) as $cookie_name) {
            if (strpos($cookie_name, 'woocommerce_items_in_cart') !== false
                || strpos($cookie_name, 'woocommerce_cart_hash') !== false
                || strpos($cookie_name, 'wp_woocommerce_session_') !== false
                || strpos($cookie_name, 'edd_items_in_cart') !== false
                || strpos($cookie_name, 'mp_session_') !== false
                || strpos($cookie_name, 'surecart_session') !== false
                || strpos($cookie_name, 'surecart_customer') !== false
                || strpos($cookie_name, 'give_items_in_cart') !== false
                || strpos($cookie_name, 'wp_ec_session_') !== false
                || strpos($cookie_name, 'swpm_session') !== false
                || strpos($cookie_name, 'um_cache_') !== false
            ) {
                return true;
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
        // Authentic server-to-server payment notifications are signed by gateways with dedicated headers.
        if (!empty($_SERVER['HTTP_STRIPE_SIGNATURE'])
            || !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG'])
            || !empty($_SERVER['HTTP_PAYPAL_CERT_URL'])
            || !empty($_SERVER['HTTP_X_SQUARE_HMACSHA256_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_WC_WEBHOOK_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_RAZORPAY_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'])
            || !empty($_SERVER['HTTP_X_MOLLIE_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_SURECART_SIGNATURE'])
        ) {
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
     * Check if an IP is in the user-defined whitelist
     */
    public static function is_ip_whitelisted(string $ip, string $whitelist_str): bool {
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
     * Check if an IP is in the user-defined blocklist
     */
    public static function is_ip_blocked(string $ip, string $blocklist_str): bool {
        if (empty($blocklist_str)) {
            return false;
        }

        $lines = explode("\n", str_replace("\r", "", $blocklist_str));
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
     * Log firewall incident to database
     */
    private static function log_incident(array $rule, string $action, ?string $incident_id = null): ?string {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';

        $ip = self::get_client_ip();
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $uri = substr($raw_uri, 0, 500);

        $raw_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $method = substr($raw_method, 0, 10);

        $raw_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $user_agent = substr($raw_ua, 0, 300);

        // Red Team Synthetic Attack Drill: NEVER log synthetic simulation probes to persistent incident table
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['wcp_drill_token']) ? sanitize_text_field(wp_unslash($_GET['wcp_drill_token'])) : (isset($_SERVER['HTTP_X_WCP_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WCP_DRILL_TOKEN'])) : '');
        if (!empty($drill_token)) {
            return null;
        }

        // Server Origin IP Safety: Never log server's own outbound IP as an offending attacker
        $server_ip = class_exists('\\WcpScanner\\System\\ServerInfo') ? \WcpScanner\System\ServerInfo::get_server_ip() : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '');
        if (!empty($server_ip) && $ip === $server_ip) {
            return null;
        }

        $raw_referer = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '';
        $referer = substr($raw_referer, 0, 500);

        if (empty($incident_id)) {
            $incident_id = 'WCP-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
        }

        // Determine HTTP Status Code
        $status_code = 403;
        if ($action === 'detected') {
            $status_code = 200;
        } elseif (isset($rule['category']) && $rule['category'] === '404 Scanner Rate Limit') {
            $status_code = 404;
        } elseif (isset($rule['category']) && (stripos($rule['category'], 'method') !== false || stripos($rule['description'] ?? '', 'method') !== false)) {
            $status_code = 405;
        }
        $category = sanitize_key($rule['category'] ?? 'general_defense');

        // Deduplication safeguard: don't log the same IP/rule more than once per minute
        $recent_sql = "SELECT id FROM `{$table}` WHERE ip_address = %s AND rule_category = %s AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE) LIMIT 1";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $recent = $wpdb->get_var(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $recent_sql,
                $ip,
                $category
            )
        );

        if ($recent) {
            return $incident_id;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            [
                'incident_id'      => sanitize_text_field($incident_id),
                'ip_address'       => sanitize_text_field($ip),
                'request_uri'      => sanitize_text_field($uri),
                'request_method'   => sanitize_key($method),
                'http_status_code' => (int) $status_code,
                'http_referer'     => !empty($referer) ? sanitize_text_field($referer) : null,
                'rule_category'    => $category,
                'rule_description' => sanitize_text_field($rule['description'] ?? $rule['name'] ?? 'Threat payload blocked by firewall policy.'),
                'payload_sample'   => sanitize_text_field(substr($rule['payload'] ?? $rule['match_value'] ?? '', 0, 255)),
                'user_agent'       => sanitize_text_field($user_agent),
                'action_taken'     => sanitize_key($action),
                'created_at'       => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );

        // Dispatch DevSecOps Webhook on blocked attack
        if ($action === 'blocked' && class_exists('\\WcpScanner\\Notifications\\WebhookService')) {
            \WcpScanner\Notifications\WebhookService::send_waf_alert([
                'category'   => $rule['category'],
                'name'       => $rule['name'] ?? $rule['category'],
                'ip_address' => $ip,
                'incident_id'=> $incident_id,
            ]);
        }

        // Dispatch granular event notifications via NotificationDispatcher
        if ($action === 'blocked' && class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            $is_virtual_patch = !empty($rule['is_virtual_patch']) || stripos($rule['category'] ?? '', 'Virtual Patch') !== false;
            if ($is_virtual_patch) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('waf_virtual_patch_hit', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: attacker IP address, 2: rule name or category, 3: incident ID */
                        __('Virtual Patch intercepted an exploit payload from %1$s targeting "%2$s" [Incident: %3$s].', 'wcp-security-scanner'),
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

        // Auto-sync banned IP to Cloudflare Edge Access Rules if enabled
        if ($action === 'blocked') {
            $settings = SettingsManager::get_settings();
            if (!empty($settings['cloudflare_auto_sync_bans']) && class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')) {
                // SAFETY SHIELD: Never auto-ban authenticated admins, whitelisted IPs, or current admin IP
                $is_admin = self::is_authenticated_administrator();
                $is_whitelisted = self::is_ip_whitelisted($ip, $settings['waf_whitelisted_ips'] ?? '');
                $current_client_ip = self::get_client_ip();

                if (!$is_admin && !$is_whitelisted && $ip !== $current_client_ip) {
                    // Only sync high-threat categories (SQLi, PHP Injection, Traversal) to avoid polluting access rules
                    $critical_categories = ['SQL Injection', 'PHP Injection', 'Path Traversal', 'Threat Intelligence'];
                    if (in_array($rule['category'] ?? '', $critical_categories, true)) {
                        \WcpScanner\Cloudflare\CloudflareService::block_ip(
                            $ip,
                            "WCP WAF Auto-Ban: {$rule['category']} probe [{$incident_id}]"
                        );
                    }
                }
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
        $drill_token = isset($_GET['wcp_drill_token']) ? sanitize_text_field(wp_unslash($_GET['wcp_drill_token'])) : (isset($_SERVER['HTTP_X_WCP_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WCP_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WcpScanner\\Security\\AttackSimulationEngine') && \WcpScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            \WcpScanner\Security\AttackSimulationEngine::record_intercept($drill_token, $rule, 403);
            header('X-WCP-Drill-Intercepted: 1');
            header('X-WCP-Drill-Rule-ID: ' . rawurlencode($rule['id'] ?? 'WAF-INTERCEPT'));
            header('X-WCP-Drill-Category: ' . rawurlencode($rule['category'] ?? 'WAF'));
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
            $incident_id = 'WCP-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
        }
        $site_name   = get_bloginfo('name');
        $rule_cat    = esc_html($rule['category'] ?? 'Security Shield');

        $message = sprintf(
            '<div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 580px; margin: 0 auto; line-height: 1.6;">' .
            '<h2 style="color: #dc2626; margin-top: 0;">%s</h2>' .
            '<p>%s</p>' .
            '<div style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 14px 18px; border-radius: 8px; margin: 18px 0; font-size: 13px;">' .
            '<p style="margin: 4px 0;"><strong>%s:</strong> <code>%s</code></p>' .
            '<p style="margin: 4px 0;"><strong>%s:</strong> <code>%s</code></p>' .
            '<p style="margin: 4px 0;"><strong>%s:</strong> <span>%s</span></p>' .
            '<p style="margin: 4px 0;"><strong>%s:</strong> <span>%s</span></p>' .
            '</div>' .
            '<p style="font-size: 13px; color: #64748b;">%s</p>' .
            '</div>',
            esc_html__('Access Denied by Security Shield', 'wcp-security-scanner'),
            sprintf(
                /* translators: %s: site name */
                esc_html__('Your request was blocked because it triggered an automated threat defense rule on %s.', 'wcp-security-scanner'),
                '<strong>' . esc_html($site_name) . '</strong>'
            ),
            esc_html__('Incident ID', 'wcp-security-scanner'),
            esc_html($incident_id),
            esc_html__('Client IP', 'wcp-security-scanner'),
            esc_html($client_ip),
            esc_html__('Violation Type', 'wcp-security-scanner'),
            $rule_cat,
            esc_html__('Timestamp', 'wcp-security-scanner'),
            esc_html(gmdate('Y-m-d H:i:s \U\T\C')),
            esc_html__('If you believe this is a false positive, please contact the site administrator and provide the Incident ID above.', 'wcp-security-scanner')
        );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        wp_die($message, esc_html__('403 Forbidden - Security Shield Block', 'wcp-security-scanner'), [
            'response'  => 403,
            'code'      => 'wcpscan_access_denied',
            'back_link' => false,
        ]);
    }

    /**
     * Get statistics & summary of firewall activity
     */
    public static function get_status(): array {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';

        $settings = SettingsManager::get_settings();
        $env = self::detect_environment();

        $total_blocks = 0;
        $blocks_24h = 0;
        $top_rules = [];

        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if ($table_exists) {
            $total_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked'";
            $blocks_24h_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
            $top_rules_sql = "SELECT rule_category, COUNT(*) as count FROM `{$table}` WHERE action_taken = 'blocked' GROUP BY rule_category ORDER BY count DESC LIMIT 5";
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
            $total_blocks = (int) $wpdb->get_var($total_sql);
            $blocks_24h   = (int) $wpdb->get_var($blocks_24h_sql);
            $top_rules    = $wpdb->get_results(
                $top_rules_sql,
                ARRAY_A
            ) ?: [];
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
            'edge_advisor'       => class_exists('\\WcpScanner\\Cloudflare\\CloudflareService')
                ? \WcpScanner\Cloudflare\CloudflareService::get_edge_advisor()
                : null,
            'server_telemetry'   => self::get_server_telemetry(),
            'available_roles'    => self::get_available_roles(),
            'commerce_telemetry' => [
                'is_active' => self::is_commerce_active(),
                'detected_names' => array_values(array_filter([
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

        // 4. Real Server Origin IP
        $real_server_ip = class_exists('\\WcpScanner\\System\\ServerInfo')
            ? \WcpScanner\System\ServerInfo::get_server_ip()
            : (isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown');

        $is_server_ip_private = !filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);

        // 5. Website CDN Detection & CDN IP
        $cdn_detected = false;
        $cdn_provider = 'None (Direct Origin)';
        $cdn_ip = 'N/A';

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

        // If CDN was detected via headers, but CDN IP could not be derived from connecting peer (e.g. mod_remoteip restored client IP)
        // OR if CDN was not detected via request headers, query DNS records for the website hostname
        if ((!$cdn_detected || $cdn_ip === 'N/A') && !$is_local_host) {
            $resolved_ips = [];

            // Method A: dns_get_record for A and AAAA
            if (function_exists('dns_get_record')) {
                $dns_a = @dns_get_record($site_host, DNS_A);
                if (is_array($dns_a)) {
                    foreach ($dns_a as $rec) {
                        if (!empty($rec['ip'])) {
                            $resolved_ips[] = $rec['ip'];
                        }
                    }
                }
                $dns_aaaa = @dns_get_record($site_host, DNS_AAAA);
                if (is_array($dns_aaaa)) {
                    foreach ($dns_aaaa as $rec) {
                        if (!empty($rec['ipv6'])) {
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

            $resolved_ips = array_unique(array_filter($resolved_ips));

            // Test resolved IPs against CDN networks
            foreach ($resolved_ips as $rip) {
                if (self::is_cloudflare_ip($rip)) {
                    $cdn_detected = true;
                    if ($cdn_provider === 'None (Direct Origin)') {
                        $cdn_provider = 'Cloudflare Anycast';
                    }
                    $cdn_ip = $rip;
                    break;
                }
            }

            // If still no CDN IP found, but CDN headers confirmed provider, use first public DNS resolved IP
            if ($cdn_detected && $cdn_ip === 'N/A' && !empty($resolved_ips)) {
                $cdn_ip = reset($resolved_ips);
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
        $waf_hook_mode = (!empty($auto_prepend) && strpos($auto_prepend, 'wcp') !== false)
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
            'is_server_ip_private' => $is_server_ip_private,
            'cdn_available'        => $cdn_detected,
            'cdn_provider'         => $cdn_provider,
            'cdn_ip'               => $cdn_ip,
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
     * Get recent blocked logs with optional filtering, search, pagination, and category filters
     */
    public static function get_logs(int $limit = 50, int $offset = 0, array $filters = []): array {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if (!$table_exists) {
            return [
                'logs'        => [],
                'total'       => 0,
                'page'        => 1,
                'total_pages' => 1,
            ];
        }

        $limit = max(1, min(500, $limit));
        $offset = max(0, $offset);

        $where_clauses = ['1=1'];
        $where_params = [];

        // Search Incident ID or IP or URI or Payload or Referer
        if (!empty($filters['search'])) {
            $like = '%' . $wpdb->esc_like(trim($filters['search'])) . '%';
            $where_clauses[] = "(incident_id LIKE %s OR ip_address LIKE %s OR request_uri LIKE %s OR rule_description LIKE %s OR payload_sample LIKE %s OR user_agent LIKE %s OR http_referer LIKE %s)";
            $where_params[] = $like;
            $where_params[] = $like;
            $where_params[] = $like;
            $where_params[] = $like;
            $where_params[] = $like;
            $where_params[] = $like;
            $where_params[] = $like;
        }

        // Filter by HTTP Status Code
        if (!empty($filters['status_code']) && $filters['status_code'] !== 'all') {
            $where_clauses[] = "http_status_code = %d";
            $where_params[] = (int) $filters['status_code'];
        }

        // Filter by rule category
        if (!empty($filters['category']) && $filters['category'] !== 'all') {
            $cat_input = sanitize_text_field($filters['category']);
            $cat_slug  = sanitize_key($cat_input);
            $where_clauses[] = "(rule_category = %s OR rule_category = %s OR rule_category LIKE %s)";
            $where_params[] = $cat_input;
            $where_params[] = $cat_slug;
            $where_params[] = '%' . $wpdb->esc_like($cat_slug) . '%';
        }

        // Filter by action taken (blocked vs detected)
        if (!empty($filters['action']) && $filters['action'] !== 'all') {
            $where_clauses[] = "action_taken = %s";
            $where_params[] = sanitize_text_field($filters['action']);
        }

        // Filter by HTTP method
        if (!empty($filters['method']) && $filters['method'] !== 'all') {
            $where_clauses[] = "request_method = %s";
            $where_params[] = sanitize_text_field($filters['method']);
        }

        // Filter by specific IP
        if (!empty($filters['ip'])) {
            $where_clauses[] = "ip_address = %s";
            $where_params[] = sanitize_text_field($filters['ip']);
        }

        $where_sql = implode(' AND ', $where_clauses);

        // Count total matching
        $count_sql = "SELECT COUNT(*) FROM `{$table}` WHERE {$where_sql}";
        if (!empty($where_params)) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $count_sql = $wpdb->prepare($count_sql, ...$where_params);
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total = (int) $wpdb->get_var($count_sql);

        // Fetch paginated results
        $data_sql = "SELECT * FROM `{$table}` WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";
        $data_params = array_merge($where_params, [$limit, $offset]);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($data_sql, ...$data_params),
            ARRAY_A
        ) ?: [];

        $page = (int) floor($offset / $limit) + 1;
        $total_pages = max(1, (int) ceil($total / $limit));

        return [
            'logs'        => $rows,
            'total'       => $total,
            'page'        => $page,
            'total_pages' => $total_pages,
            'limit'       => $limit,
            'offset'      => $offset,
        ];
    }

    /**
     * Get aggregate statistics and metrics for WAF logs dashboard
     */
    public static function get_log_stats(): array {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if (!$table_exists) {
            return [
                'total_intercepted' => 0,
                'blocked_24h'       => 0,
                'detected_learning' => 0,
                'unique_attack_ips' => 0,
                'top_categories'    => [],
                'top_ips'           => [],
                'top_targets'       => [],
                'methods_breakdown' => [],
                'hourly_trend'      => [],
            ];
        }

        $total_int_sql = "SELECT COUNT(*) FROM `{$table}`";
        $blocked_24h_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)";
        $det_learn_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'detected'";
        $uniq_ips_sql = "SELECT COUNT(DISTINCT ip_address) FROM `{$table}`";

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
        $total_intercepted = (int) $wpdb->get_var($total_int_sql);
        $blocked_24h       = (int) $wpdb->get_var($blocked_24h_sql);
        $detected_learning = (int) $wpdb->get_var($det_learn_sql);
        $unique_attack_ips = (int) $wpdb->get_var($uniq_ips_sql);

        // Top Attack Categories
        $top_cat_sql = "SELECT rule_category, COUNT(*) as count FROM `{$table}` GROUP BY rule_category ORDER BY count DESC LIMIT 8";
        $top_categories = $wpdb->get_results(
            $top_cat_sql,
            ARRAY_A
        ) ?: [];

        // Top Offending IPs
        $top_ips_sql = "SELECT ip_address, COUNT(*) as count, MAX(created_at) as last_seen, rule_category as primary_reason FROM `{$table}` GROUP BY ip_address ORDER BY count DESC LIMIT 10";
        $top_ips = $wpdb->get_results(
            $top_ips_sql,
            ARRAY_A
        ) ?: [];

        // Top Targeted Endpoints
        $top_targets_sql = "SELECT request_uri, COUNT(*) as count FROM `{$table}` GROUP BY request_uri ORDER BY count DESC LIMIT 8";
        $top_targets = $wpdb->get_results(
            $top_targets_sql,
            ARRAY_A
        ) ?: [];

        // HTTP Methods Breakdown
        $methods_sql = "SELECT request_method, COUNT(*) as count FROM `{$table}` GROUP BY request_method ORDER BY count DESC";
        $methods_breakdown = $wpdb->get_results(
            $methods_sql,
            ARRAY_A
        ) ?: [];

        // 24-hour volume trend by hour
        $trend_sql = "SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') as hour_slot, COUNT(*) as count 
             FROM `{$table}` 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) 
             GROUP BY hour_slot 
             ORDER BY hour_slot ASC";
        $hourly_trend = $wpdb->get_results(
            $trend_sql,
            ARRAY_A
        ) ?: [];
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
        return [
            'total_intercepted' => $total_intercepted,
            'blocked_24h'       => $blocked_24h,
            'detected_learning' => $detected_learning,
            'unique_attack_ips' => $unique_attack_ips,
            'top_categories'    => $top_categories,
            'top_ips'           => $top_ips,
            'top_targets'       => $top_targets,
            'methods_breakdown' => $methods_breakdown,
            'hourly_trend'      => $hourly_trend,
        ];
    }

    /**
     * Delete a single firewall incident log row
     */
    public static function delete_log(int $id): bool {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->delete($table, ['id' => $id], ['%d']);
    }

    /**
     * Clear firewall logs
     */
    public static function clear_logs(): bool {
        global $wpdb;
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';
        $truncate_sql = "TRUNCATE TABLE `{$table}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
        return (bool) $wpdb->query($truncate_sql);
    }

    /**
     * Add IP to custom blocklist
     */
    public static function add_blocked_ip(string $ip): bool {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP) && strpos($ip, '/') === false) {
            return false;
        }

        // Safety Guard: Refuse to add current administrator's active IP or whitelisted IP to custom blocklist
        $current_client_ip = self::get_client_ip();
        if ($ip === $current_client_ip && self::is_authenticated_administrator()) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_blocked_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        if (!in_array($ip, $lines, true)) {
            $lines[] = $ip;
            $settings['waf_blocked_ips'] = implode("\n", $lines);
            SettingsManager::save_settings($settings);
        }
        return true;
    }

    /**
     * Add IP to custom whitelist
     */
    public static function add_whitelisted_ip(string $ip): bool {
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
        return true;
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

            // Exact match or prefix match
            if ($uri === $allowed || $path === $allowed_clean || strpos($path, rtrim($allowed_clean, '/')) === 0) {
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
                        // Exact match or prefix match
                        if ($uri === $clean_pattern || $path === $clean_pattern || strpos($path, rtrim($clean_pattern, '/')) === 0) {
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

        $transient_key = 'wcp_rdns_' . md5($ip . '_' . $clean_target);
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
        $transient_key = 'wcp_asn_' . md5($ip);
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
        $table = $wpdb->prefix . 'wcpscan_firewall_logs';

        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_check = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if ($table_check !== $table) {
            return;
        }

        $incident_id = 'WCP-ALLOW-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
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

        $host_transient = 'wcp_ptr_' . md5($ip);
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
                    __('Granted safe WAF bypass via rule "%1$s" for User-Agent: %2$s', 'wcp-security-scanner'),
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
     * Intercept and audit uploaded files in real-time (Rule 8)
     */
    public static function inspect_uploaded_file(array $file): array {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_block_malicious_uploads'])) {
            return $file;
        }

        if (empty($file['name']) || empty($file['tmp_name'])) {
            return $file;
        }

        $filename = strtolower(basename($file['name']));
        $tmp_path = $file['tmp_name'];
        $ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // 1. Prohibited executable extensions
        $prohibited_exts = [
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'phps',
            'sh', 'bash', 'zsh', 'ksh', 'csh', 'bin', 'cgi', 'pl', 'py', 'pyc', 'pyw',
            'rb', 'asp', 'aspx', 'cer', 'csr', 'jsp', 'jspx', 'exe', 'com', 'bat', 'cmd',
            'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'msi', 'dll', 'drv', 'sys'
        ];

        if (in_array($ext, $prohibited_exts, true)) {
            self::log_incident([
                'category'    => 'Malicious File Upload',
                'description' => sprintf('Upload of executable file "%s" was blocked by firewall.', esc_html($filename)),
                'payload'     => "Filename: {$filename} Extension: .{$ext}",
            ], 'blocked');

            $file['error'] = __('Security Firewall: Uploading executable scripts or programs is strictly prohibited.', 'wcp-security-scanner');
            return $file;
        }

        // 2. Double extension check (e.g. image.php.jpg, doc.php.png)
        if (preg_match('/\.(php[0-9]?|phtml|phar|sh|bash|cgi|pl|py|exe)\.([a-z0-9]+)$/i', $filename, $m)) {
            self::log_incident([
                'category'    => 'Malicious File Upload',
                'description' => sprintf('Upload with disguised double-extension "%s" was blocked by firewall.', esc_html($filename)),
                'payload'     => "Filename: {$filename} Hidden extension: .{$m[1]}",
            ], 'blocked');

            $file['error'] = __('Security Firewall: Disguised double-extension file upload detected and blocked.', 'wcp-security-scanner');
            return $file;
        }

        // 3. Inspect binary magic bytes if temp file exists
        if (file_exists($tmp_path) && is_readable($tmp_path)) {
            $header = @file_get_contents($tmp_path, false, null, 0, 16);
            if ($header !== false) {
                if (strlen($header) >= 2) {
                    // Windows PE (MZ)
                    if (substr($header, 0, 2) === 'MZ') {
                        $file['error'] = __('Security Firewall: Spoofed Windows executable binary detected in upload.', 'wcp-security-scanner');
                        return $file;
                    }
                    // Linux ELF (\x7fELF)
                    if (substr($header, 0, 4) === "\x7fELF") {
                        $file['error'] = __('Security Firewall: Spoofed Linux ELF executable binary detected in upload.', 'wcp-security-scanner');
                        return $file;
                    }
                    // macOS Mach-O
                    $macho_sigs = ["\xca\xfe\xba\xbe", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe"];
                    if (in_array(substr($header, 0, 4), $macho_sigs, true)) {
                        $file['error'] = __('Security Firewall: Spoofed Mach-O executable binary detected in upload.', 'wcp-security-scanner');
                        return $file;
                    }
                    // Unix Shebang in image/media
                    if (substr($header, 0, 2) === '#!' && preg_match('/^#!\s*\/(bin|usr)/i', $header)) {
                        $file['error'] = __('Security Firewall: Spoofed shell script detected in upload.', 'wcp-security-scanner');
                        return $file;
                    }
                }
            }

            // 4. SVG XSS & Active JavaScript Audit
            if ($ext === 'svg' || $ext === 'svgz') {
                $content = @file_get_contents($tmp_path, false, null, 0, 1048576); // Inspect up to 1MB
                if (!empty($content)) {
                    if (substr($content, 0, 2) === "\x1f\x8b" && function_exists('gzdecode')) {
                        $decompressed = @gzdecode($content);
                        if ($decompressed !== false) {
                            $content = $decompressed;
                        }
                    }

                    if (preg_match('/(<\?php|<\?=\s*|<script\b|javascript\s*:|\b(onload|onerror|onclick|onmouseover)\s*=|<(foreignObject|iframe|embed|object)\b)/i', $content, $m)) {
                        self::log_incident([
                            'category'    => 'Malicious File Upload',
                            'description' => sprintf('Malicious SVG XSS payload (%s) in uploaded file "%s" was blocked.', esc_html($m[0]), esc_html($filename)),
                            'payload'     => "Filename: {$filename} Match: {$m[0]}",
                        ], 'blocked');

                        $file['error'] = __('Security Firewall: SVG vector file contains executable scripts or embedded XSS tags.', 'wcp-security-scanner');
                        return $file;
                    }
                }
            }

            // 5. Embedded PHP Polyglots in Media
            $image_exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'pdf'];
            if (in_array($ext, $image_exts, true)) {
                $head = @file_get_contents($tmp_path, false, null, 0, 8192);
                $php_pattern = '/<\?(?:php\s+[\s\S]{0,500}?(?:eval|assert|system|passthru|shell_exec|exec|base64_decode|\$_[A-Z]+|\$[a-zA-Z0-9_]+)|\=\s*[\s\S]{0,200}?(?:eval|assert|\$_[A-Z]+|\$[a-zA-Z0-9_]+))/i';
                if (!empty($head) && preg_match($php_pattern, $head)) {
                    $file['error'] = __('Security Firewall: Disguised PHP polyglot webshell detected inside image headers.', 'wcp-security-scanner');
                    return $file;
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
                    self::log_incident([
                        'category'    => 'Prohibited Script Upload',
                        'description' => sprintf('Upload of phpMyAdmin / Adminer / DBManager database management script or plugin archive "%s" was blocked by policy.', esc_html($filename)),
                        'payload'     => "Filename: {$filename} Temp: {$tmp_path}",
                    ], 'blocked');

                    $file['error'] = __('Security Firewall: Uploading phpMyAdmin or standalone database management scripts is strictly disallowed.', 'wcp-security-scanner');
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

                // Check text/script content if candidate extension
                if (!$is_fm_file && in_array($ext, ['txt', 'inc', 'zip', 'tar', 'gz'], true)) {
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
                        for ($i = 0; $i < min(300, $zip->numFiles); $i++) {
                            $entry_name = strtolower($zip->getNameIndex($i));
                            if (preg_match('/(tinyfilemanager|filemanager|fileorganizer|elfinder|responsivefilemanager|filester|file-explorer|file-commander)/i', $entry_name)) {
                                $is_fm_file = true;
                                break;
                            }
                            if (preg_match('/\.php$/i', $entry_name)) {
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
                        $zip->close();
                    }
                }

                if ($is_fm_file) {
                    self::log_incident([
                        'category'    => 'Prohibited Script Upload',
                        'description' => sprintf('Upload of standalone File Manager / Web Shell script or plugin archive "%s" was blocked by policy.', esc_html($filename)),
                        'payload'     => "Filename: {$filename} Temp: {$tmp_path}",
                    ], 'blocked');

                    $file['error'] = __('Security Firewall: Uploading standalone File Manager or explorer scripts is strictly disallowed.', 'wcp-security-scanner');
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
                        'wcp_prohibited_plugin_pma',
                        __('Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is disallowed by WCP Security Firewall.', 'wcp-security-scanner')
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
                        'wcp_prohibited_plugin_fm',
                        __('Security Policy Violation: Installation of File Manager plugins is disallowed by WCP Security Firewall.', 'wcp-security-scanner')
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
                        'wcp_prohibited_plugin_source_pma',
                        __('Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is prohibited by WCP Security Firewall.', 'wcp-security-scanner')
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
                        'wcp_prohibited_plugin_source_fm',
                        __('Security Policy Violation: Installation of File Manager plugins is prohibited by WCP Security Firewall.', 'wcp-security-scanner')
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
                                'wcp_prohibited_plugin_header_pma',
                                __('Security Policy Violation: Plugin header identifies as a prohibited database manager (phpMyAdmin/Adminer).', 'wcp-security-scanner')
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
                                'wcp_prohibited_plugin_header_fm',
                                __('Security Policy Violation: Plugin header identifies as a prohibited File Manager plugin.', 'wcp-security-scanner')
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
                            'wcp_disallowed_plugin',
                            __('Security Policy: phpMyAdmin and database manager plugins are blocked by WCP Security Firewall.', 'wcp-security-scanner')
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
                            'wcp_disallowed_plugin',
                            __('Security Policy: File Manager plugins are blocked by WCP Security Firewall.', 'wcp-security-scanner')
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
                __('Error', 'wcp-security-scanner'),
                __('Invalid username, email address, or password.', 'wcp-security-scanner')
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
                __('<strong>Error:</strong> The username "admin" is reserved and prohibited for security.', 'wcp-security-scanner')
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

            // Skip whitelisted IPs
            if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
                return $user;
            }

            // Immediately permanently block IP
            self::add_blocked_ip($client_ip);

            // Log incident
            self::log_incident([
                'id'          => 'WAF-FORBIDDEN-USERNAME-TRAP',
                'name'        => 'Forbidden Honeypot Username Trap',
                'category'    => 'Identity Defense',
                'description' => sprintf('Attacker IP tried to log in using forbidden honeypot username "%s". IP permanently banned.', esc_html($username)),
                'match_type'  => 'Honeypot Username',
                'match_value' => $username,
                'payload'     => "User: {$username} IP: {$client_ip}",
            ], 'blocked');

            // Also lock in LoginHardening
            if (class_exists('\\WcpScanner\\Auth\\LoginHardening')) {
                $lockouts = \WcpScanner\Auth\LoginHardening::get_locked_ips();
                $now = time();
                $lockouts[$client_ip] = [
                    'ip'         => $client_ip,
                    'attempts'   => 999,
                    'username'   => $username,
                    'blocked_at' => gmdate('Y-m-d H:i:s', $now),
                    'expires_at' => $now + (365 * 86400),
                    'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
                ];
                update_option(\WcpScanner\Auth\LoginHardening::OPTION_LOCKOUTS, $lockouts, false);
            }

            // Return immediate access denied error
            return new \WP_Error(
                'wcp_forbidden_username_blocked',
                __('<strong>Access Blocked:</strong> Attempting to sign in with this username is strictly prohibited. Your IP has been permanently banned by the security firewall.', 'wcp-security-scanner')
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
                    'wcp_weak_password',
                    __('<strong>Security Policy:</strong> Your role requires a strong password. It must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and symbols.', 'wcp-security-scanner')
                );
            }
        }

        // 2. Leaked / Pwned Passwords Check (Rule 7)
        if (!empty($settings['waf_check_pwned_passwords'])) {
            if (self::is_password_pwned($pass1)) {
                $errors->add(
                    'wcp_pwned_password',
                    __('<strong>Security Breach Warning:</strong> This password has appeared in known public data breaches and cannot be used. Please choose a different, secure password.', 'wcp-security-scanner')
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
                    'wcp_weak_password',
                    __('<strong>Security Policy:</strong> Your role requires a strong password. It must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and symbols.', 'wcp-security-scanner')
                );
            }
        }

        // Leaked password check
        if (!empty($settings['waf_check_pwned_passwords'])) {
            if (self::is_password_pwned($pass1)) {
                $errors->add(
                    'wcp_pwned_password',
                    __('<strong>Security Breach Warning:</strong> This password has appeared in known public data breaches and cannot be used. Please choose a different, secure password.', 'wcp-security-scanner')
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
                'User-Agent' => 'WCP-Security-Scanner-Password-Sentinel/1.0',
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
    public static function handle_rule_violation(array $rule, array $settings, string $client_ip, int $status_code = 403): void {
        // Red Team Drill Intercept Handler
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $drill_token = isset($_GET['wcp_drill_token']) ? sanitize_text_field(wp_unslash($_GET['wcp_drill_token'])) : (isset($_SERVER['HTTP_X_WCP_DRILL_TOKEN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WCP_DRILL_TOKEN'])) : '');
        if (!empty($drill_token) && class_exists('\\WcpScanner\\Security\\AttackSimulationEngine') && \WcpScanner\Security\AttackSimulationEngine::verify_drill_token($drill_token)) {
            \WcpScanner\Security\AttackSimulationEngine::record_intercept($drill_token, $rule, $status_code);
            header('X-WCP-Drill-Intercepted: 1');
            header('X-WCP-Drill-Rule-ID: ' . rawurlencode($rule['id'] ?? 'WAF-INTERCEPT'));
            header('X-WCP-Drill-Category: ' . rawurlencode($rule['category'] ?? 'WAF'));
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

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            if (class_exists('\\WcpScanner\\Firewall\\LearningModeEngine') && \WcpScanner\Firewall\LearningModeEngine::is_route_graduated()) {
                // Route has graduated: enforce blocking even during global learning mode!
            } else {
                if (class_exists('\\WcpScanner\\Firewall\\LearningModeEngine')) {
                    \WcpScanner\Firewall\LearningModeEngine::record_threat_encountered(\WcpScanner\Firewall\LearningModeEngine::get_current_route_key());
                }
                self::log_incident($rule, 'detected');
                return;
            }
        } elseif ($mode === 'enabled') {
            // Check if specific route was explicitly forced into learning mode by admin
            if (class_exists('\\WcpScanner\\Firewall\\LearningModeEngine')) {
                $route_key = \WcpScanner\Firewall\LearningModeEngine::get_current_route_key();
                $profiles = get_option(\WcpScanner\Firewall\LearningModeEngine::OPTION_PROFILES, []);
                if (isset($profiles[$route_key]['forced_status']) && $profiles[$route_key]['forced_status'] === 'learning') {
                    \WcpScanner\Firewall\LearningModeEngine::record_threat_encountered($route_key);
                    self::log_incident($rule, 'detected');
                    return;
                }
            }
        }

        $incident_id = 'WCP-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
        self::log_incident($rule, 'blocked', $incident_id);

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

        // 2. If HTTP_X_FORWARDED_HOST is present, it MUST also strictly match the allowed list
        if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
            $fwd_raw = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_HOST'])));
            $fwd_host = strtolower(trim(preg_replace('/:\d+$/', '', $fwd_raw[0])));
            if (!in_array($fwd_host, $allowed, true)) {
                return false;
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
        $transient_name = 'wcpscan_rl_' . substr(md5($key), 0, 24);
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
        $rest_route  = isset($_GET['rest_route']) ? sanitize_text_field(wp_unslash($_GET['rest_route'])) : '';
        $clean_uri   = strtolower(urldecode($request_uri));
        $clean_route = strtolower(urldecode($rest_route));

        // Check for /wp/v2/users endpoint queries
        $is_user_endpoint = (
            strpos($clean_uri, '/wp-json/wp/v2/users') !== false ||
            strpos($clean_route, '/wp/v2/users') !== false
        );

        if (!$is_user_endpoint) {
            return $access;
        }

        // Check if accessing /wp/v2/users/me (standard profile query)
        // If unauthenticated, core returns not logged in, but we allow /me to flow to core auth handler
        $is_me_endpoint = (
            strpos($clean_uri, '/wp/v2/users/me') !== false ||
            strpos($clean_route, '/wp/v2/users/me') !== false
        );

        if ($is_me_endpoint) {
            return $access;
        }

        $client_ip = self::get_client_ip();
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return $access;
        }

        $rule_triggered = [
            'id'          => 'WAF-REST-USER-ENUM',
            'name'        => 'REST API User Enumeration Interceptor',
            'category'    => 'Reconnaissance & Enumeration',
            'description' => 'Unauthenticated REST API user enumeration request intercepted on /wp/v2/users.',
            'match_type'  => 'REST Route Intercept',
            'match_value' => '/wp/v2/users',
            'payload'     => "URI: {$request_uri} IP: {$client_ip}",
        ];

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            self::log_incident($rule_triggered, 'detected');
            return $access;
        }

        self::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'rest_user_enum_forbidden',
            __('User enumeration via REST API is disabled by WCP Security Firewall.', 'wcp-security-scanner'),
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
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return;
        }

        $rule_triggered = [
            'id'          => 'WAF-AUTHOR-ENUM',
            'name'        => 'Author Permalink Enumeration Suppression',
            'category'    => 'Reconnaissance & Enumeration',
            'description' => sprintf('Author ID enumeration query (?author=%s) blocked from harvesting usernames.', esc_html($author_param)),
            'match_type'  => 'Author Query Probe',
            'match_value' => '?author=' . $author_param,
            'payload'     => "URI: {$raw_req_uri} IP: {$client_ip}",
        ];

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
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return;
        }

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
            exit;
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
        if (self::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '')) {
            return;
        }

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
            exit;
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
                exit;
            }
        }
    }
}
