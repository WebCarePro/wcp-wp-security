<?php
namespace WcpScanner\Advisor;

if (!defined('ABSPATH')) {
    exit;
}

use WcpScanner\System\SettingsManager;

/**
 * PolicyRegistry
 *
 * Strict, authoritative catalog of verified WAF firewall settings.
 * Explicitly segregates True Protections from Compatibility Exemptions,
 * defines trigger capabilities, target safe values, and decay rules.
 *
 * @package WcpScanner\Advisor
 * @author Mir Alamin (WebCare Pro)
 */
class PolicyRegistry {

    public const TYPE_PROTECTION = 'protection';
    public const TYPE_EXEMPTION  = 'compatibility_exemption';

    public const ACTION_ENFORCE          = 'safe_enforce';
    public const ACTION_MONITOR          = 'monitor_first';
    public const ACTION_EXEMPTION_REVIEW = 'compatibility_review';

    /**
     * Get the authoritative policy registry.
     * Every setting key is strictly verified against SettingsManager::get_default_settings().
     *
     * @return array
     */
    public static function get_policies(): array {
        return [
            // ==========================================
            // 1. COMMERCE PROTECTIONS (Rules #38 - #42)
            // ==========================================
            'waf_woo_carding_protection' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => ['commerce'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => true,
                'title'               => __('Carding Attack & Checkout Velocity Shield', 'wcp-security-scanner'),
                'description'         => __('Locks out rogue IPs repeatedly failing checkout payments (default: 3 failures / 5 min).', 'wcp-security-scanner'),
                'security_benefit'    => __('Prevents automated card testing bots from running stolen credit cards and incurring payment gateway fines.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_woo_coupon_protection' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => ['commerce'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => true,
                'title'               => __('Coupon Enumeration & Brute-Force Shield', 'wcp-security-scanner'),
                'description'         => __('Throttles dictionary attacks and scraper extensions guessing promotional coupon codes.', 'wcp-security-scanner'),
                'security_benefit'    => __('Stops coupon harvesting bots and brute-force dictionary attempts from discovering internal discount codes.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_woo_registration_protection' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => ['commerce', 'membership'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Fake Customer Registration & Bot Shield', 'wcp-security-scanner'),
                'description'         => __('Blocks disposable throwaway emails and caps registration rate per IP (default: 3 accounts / hour).', 'wcp-security-scanner'),
                'security_benefit'    => __('Protects WordPress user database and email delivery reputation from automated spam user creation.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_woo_cart_flood_protection' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => ['commerce'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => true,
                'title'               => __('Cart Flooding & Denial of Inventory Defense', 'wcp-security-scanner'),
                'description'         => __('Caps cumulative items per cart (50 items) and throttles rapid add-to-cart bursts (15 ops/min).', 'wcp-security-scanner'),
                'security_benefit'    => __('Thwarts competitor scalpers and bots from reserving all store stock and causing inventory exhaustion.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'medium',
            ],
            'waf_woo_scraping_protection' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => ['commerce'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => true,
                'title'               => __('Catalog & Price Scraping Mitigation', 'wcp-security-scanner'),
                'description'         => __('Limits high-frequency catalog harvesting (60 req/min) while exempting verified search crawlers.', 'wcp-security-scanner'),
                'security_benefit'    => __('Shields store catalog, pricing matrices, and database query workers from competitor scraping crawlers.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],

            // ==========================================
            // 2. COMPATIBILITY EXEMPTIONS (Honest Labels)
            // ==========================================
            'waf_ecommerce_safe_mode' => [
                'type'                => self::TYPE_EXEMPTION,
                'trigger_capability'  => ['commerce'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_EXEMPTION_REVIEW,
                'stale_when_absent'   => true, // Recommend disabling if WooCommerce is removed!
                'requires_ip_trust'   => false,
                'title'               => __('E-Commerce & Membership Compatibility Safe Mode', 'wcp-security-scanner'),
                'description'         => __('Exempts recognized WooCommerce AJAX and Store API actions from generic rate-limits and payload blocks.', 'wcp-security-scanner'),
                'security_benefit'    => __('Compatibility Exemption: Relaxes generic WAF false-positive triggers on legitimate cart and checkout operations.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'none',
            ],
            'waf_forms_safe_mode' => [
                'type'                => self::TYPE_EXEMPTION,
                'trigger_capability'  => ['forms'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_EXEMPTION_REVIEW,
                'stale_when_absent'   => true, // Recommend disabling if forms are removed!
                'requires_ip_trust'   => false,
                'title'               => __('Contact Forms Compatibility Safe Mode', 'wcp-security-scanner'),
                'description'         => __('Exempts standard contact form submissions from aggressive generic packet inspection.', 'wcp-security-scanner'),
                'security_benefit'    => __('Compatibility Exemption: Ensures legitimate visitor contact messages and quote requests reach the inbox.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'none',
            ],
            'waf_allow_page_builders' => [
                'type'                => self::TYPE_EXEMPTION,
                'trigger_capability'  => ['builder'],
                'target_value'        => true,
                'action_mode'         => self::ACTION_EXEMPTION_REVIEW,
                'stale_when_absent'   => true, // Stale if Elementor/Divi deleted!
                'requires_ip_trust'   => false,
                'title'               => __('Visual Page Builders Compatibility Safe Mode', 'wcp-security-scanner'),
                'description'         => __('Exempts authenticated editor preview frames and builder REST mutations (Elementor, Divi, Bricks).', 'wcp-security-scanner'),
                'security_benefit'    => __('Compatibility Exemption: Prevents visual page editors from experiencing 403 Forbidden errors while designing.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'none',
            ],

            // ==========================================
            // 3. CORE UNIVERSAL PROTECTIONS
            // ==========================================
            'waf_block_uploads_php_exec' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Uploads Direct PHP Execution Lockdown', 'wcp-security-scanner'),
                'description'         => __('Stops web shells and rogue backdoor scripts from executing inside wp-content/uploads/.', 'wcp-security-scanner'),
                'security_benefit'    => __('Neutralizes 90%+ of automated WordPress compromise payloads by rendering uploaded PHP files inert.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_block_sensitive_file_probes' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Sensitive File & Backup Probing Blocker', 'wcp-security-scanner'),
                'description'         => __('Blocks automated bots scanning for .env, .git, wp-config.php.bak, and database SQL dumps.', 'wcp-security-scanner'),
                'security_benefit'    => __('Prevents credential leaks and database exposure from opportunistic vulnerability crawlers.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_block_fake_bots' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Fake Search Engine Bots Defense', 'wcp-security-scanner'),
                'description'         => __('Verifies authentic Googlebot/Bingbot via reverse-DNS caching and drops malicious impersonators.', 'wcp-security-scanner'),
                'security_benefit'    => __('Eliminates stealth scraping spiders and vulnerability scanners masquerading as legitimate search indexers.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_login_rate_limit' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => true,
                'title'               => __('Login Brute-Force Rate Limiting', 'wcp-security-scanner'),
                'description'         => __('Throttles rapid password guessing attempts on wp-login.php and XML-RPC.', 'wcp-security-scanner'),
                'security_benefit'    => __('Protects administrator and customer credentials from credential-stuffing dictionary attacks.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_runtime_rasp_privilege_guard' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Runtime Privilege Escalation Guard (In-Memory RASP)', 'wcp-security-scanner'),
                'description'         => __('In-Memory RASP hook firewall aborting unauthenticated attempts to assign administrator roles or mutate core options.', 'wcp-security-scanner'),
                'security_benefit'    => __('Stops zero-day form, booking, and membership plugin privilege escalations before database commits.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],
            'waf_upload_deep_mime_sanitizer' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => true,
                'action_mode'         => self::ACTION_ENFORCE,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Deep MIME & Zip-Slip Polyglot Upload Armor', 'wcp-security-scanner'),
                'description'         => __('Enforces path-traversal sanitization (Zip-Slip), binary magic bytes inspection, and polyglot detection on file uploads.', 'wcp-security-scanner'),
                'security_benefit'    => __('Renders polyglot web shells, Phar deserialization triggers, and traversal filenames inert.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'low',
            ],

            // ==========================================
            // 4. OBSERVATION FIRST / SENSITIVE POLICIES
            // ==========================================
            'waf_guest_ajax_policy' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => 'monitor',
                'action_mode'         => self::ACTION_MONITOR,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Guest AJAX Action Policy', 'wcp-security-scanner'),
                'description'         => __('Inspects unauthenticated admin-ajax.php requests against known theme/plugin allowlists.', 'wcp-security-scanner'),
                'security_benefit'    => __('Monitors unauthenticated AJAX probe activity before strict blocking to prevent breaking custom widgets.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'medium',
            ],
            'waf_guest_rest_policy' => [
                'type'                => self::TYPE_PROTECTION,
                'trigger_capability'  => [], // Universal
                'target_value'        => 'monitor',
                'action_mode'         => self::ACTION_MONITOR,
                'stale_when_absent'   => false,
                'requires_ip_trust'   => false,
                'title'               => __('Guest REST API Mutation Policy', 'wcp-security-scanner'),
                'description'         => __('Monitors unauthenticated POST, PUT, and DELETE mutations across WordPress REST API routes.', 'wcp-security-scanner'),
                'security_benefit'    => __('Detects unauthorized data modification attempts on public REST routes without breaking legitimate webhooks.', 'wcp-security-scanner'),
                'compatibility_risk'  => 'medium',
            ],
        ];
    }

    /**
     * Self-check validation: verifies that every registered setting key actually exists
     * in SettingsManager defaults to guarantee 0 drift.
     *
     * @return bool
     */
    public static function validate_registry(): bool {
        $defaults = SettingsManager::get_defaults();
        foreach (self::get_policies() as $key => $policy) {
            if (!array_key_exists($key, $defaults)) {
                return false;
            }
        }
        return true;
    }
}
