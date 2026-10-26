<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class SettingsManager {
    const OPTION_KEY = 'wcpscan_settings';
    const CRON_HOOK = 'wcpscan_scheduled_scan_event';

    /**
     * Default configuration options
     */
    public static function get_defaults(): array {
        return [
            // 1. Schedule Scan Settings
            'schedule_enabled'         => false,
            'schedule_frequency'       => 'daily', // hourly, twicedaily, daily, weekly
            'schedule_time'            => '02:00', // 24hr HH:MM server time
            'schedule_scan_type'       => 'plugins_themes', // plugins_themes, full, core_integrity, suspicious_uploads

            // 2. Email Notifications
            'email_alerts_enabled'     => false,
            'alert_emails'             => get_option('admin_email', ''),
            'alert_min_severity'       => 'high', // critical, high, medium, all
            'email_digest_enabled'     => false,
            'email_on_scan_completed'  => false,
            'notify_on_cve_detected'   => true,

            // 3. AI Threat & Code Analysis Integration
            'ai_enabled'               => false,
            'ai_provider'              => 'gemini', // gemini, openai, claude
            'gemini_api_key'           => '',
            'gemini_model'             => 'gemini-3.5-flash-lite',
            'openai_api_key'           => '',
            'openai_model'             => 'gpt-6.1-sol',
            'claude_api_key'           => '',
            'claude_model'             => 'claude-sonnet-5-5',
            'ai_temperature'           => 0.2,
            'ai_auto_analyze_critical' => false,

            // 4. Scanner Engine Performance & Throttle
            'scan_batch_size'                => 50, // 25, 50, 100, 200
            'scan_memory_safety_envelope'    => 'balanced', // strict (60%), balanced (70%), performance (80%)
            'scan_adaptive_throttling'       => true, // Dynamically throttle batch size and pace micro-sleeps for visitors
            'memory_limit_override'          => '512M',
            'max_file_size_kb'               => 1024, // Skip files larger than 1MB from heuristic scanning
            'auto_quarantine_critical'       => false, // Safeguard off by default

            // 5. Exclusions & Ignore Rules
            'excluded_paths'           => "wp-content/cache/*\nnode_modules/*\n*.log\n*.tar.gz\n*.zip",
            'custom_extensions'        => 'php, phtml, phps, inc, tpl',

            // 6. Developer & Admin Security Tweaks & HTTP Headers
            'disable_file_editing'     => false,
            'hide_wp_version'          => false,
            'block_sensitive_files'    => false, // .env, .git, etc.
            'block_user_enumeration'   => true,  // Block ?author=1 and REST API user discovery

            // HTTP Security Headers
            'header_hsts'                      => true,
            'header_hsts_preload'              => false,
            'header_x_frame_options'           => true,
            'header_x_frame_options_mode'      => 'SAMEORIGIN', // SAMEORIGIN or DENY
            'header_nosniff'                   => true,
            'header_referrer_policy'           => true,
            'header_referrer_policy_value'     => 'strict-origin-when-cross-origin',
            'header_permissions_policy'        => true,
            'header_permissions_policy_value'  => 'geolocation=(), camera=(), microphone=(), payment=()',
            'header_xss_protection'            => true,
            'header_csp_enabled'               => false,
            'header_csp_custom'                => '',

            // 7. Cleanup & Data Privacy on Plugin Uninstall (Disabled by default to protect quarantine vault and configuration)
            'delete_data_on_uninstall' => false,

            // 8. Web Application Firewall (WAF) Lite
            'waf_enabled'              => true,
            'waf_mode'                 => 'enabled', // 'enabled' | 'learning' | 'disabled'
            'waf_complementary_mode'   => true, // Auto-negotiate if Wordfence/Cloudflare active
            'waf_block_sqli'           => true,
            'waf_block_xss'            => true,
            'waf_block_traversal'      => true,
            'waf_block_php_injection'  => true,
            'waf_disable_xmlrpc'       => false,
            'waf_allow_jetpack_xmlrpc' => false, // Allow verified Automattic Jetpack sync via xmlrpc.php if Jetpack is used
            'waf_login_rate_limit'     => true,
            'waf_whitelisted_ips'      => '',
            'waf_blocked_ips'          => '',
            'waf_block_fake_bots'      => true,
            'waf_block_ai_scrapers'    => false,
            'waf_dynamic_robots_ai'    => true,
            'waf_block_404_scanners'   => true, // Smart 404 scanner rate limiter
            'waf_404_threshold'        => 10,   // Max 404s before temporary ban (e.g. 10)
            'waf_404_window_seconds'   => 60,   // Rolling time window in seconds (default 60s)
            'waf_404_lockout_duration' => 30,   // Lockout duration in minutes (default 30 mins)
            'waf_allow_uptime_monitors'        => false, // Allow verified Uptime Monitoring services (UptimeRobot, Pingdom, StatusCake, BetterUptime)
            'waf_allow_central_management'     => false, // Allow central WordPress management workers (ManageWP, MainWP, InfiniteWP) via cryptographic handshake

            // Enhanced Perimeter & Identity Protection Rules
            'waf_ecommerce_safe_mode'           => false, // E-Commerce & Membership Smart Shield (off by default, recommended when shop/membership active)
            'waf_allow_page_builders'           => false, // Visual Page Builder & Editor Smart Pass (off by default, recommended when Elementor/Divi active)
            'waf_block_empty_post_ua_referer'   => true, // Block IPs who send POST requests with blank User-Agent and Referer
            'waf_whitelisted_urls'              => '',   // Allowlisted URLs / URI paths (one per line)
            'waf_targeted_allowlist_rules'      => '[]', // Granular User-Agent, Endpoint & IP allowlist rules (JSON string)
            'waf_block_forbidden_usernames'     => true, // Immediately block IP trying to sign in as forbidden honeypot usernames
            'waf_forbidden_usernames_list'      => "admin\nadministrator\nroot", // Forbidden/honeypot username list
            'waf_prevent_admin_registration'    => true, // Prevent users from registering 'admin' username
            'waf_mask_login_errors'             => true, // Don't let WordPress reveal valid users in login errors
            'waf_enforce_strong_passwords'      => true, // Enforce strong passwords for specific roles
            'waf_strong_passwords_roles'        => 'administrator, editor', // Roles subject to strong password policy
            'waf_check_pwned_passwords'         => true, // Prevent use of passwords leaked in data breaches (HIBP API)
            'waf_block_malicious_uploads'       => true, // Intercept & prevent malicious file uploads (executables, double ext, polyglots, SVG XSS)
            'waf_block_unsafe_http_methods'     => true, // Block TRACE, TRACK, CONNECT, DEBUG HTTP methods
            'waf_block_null_byte_attacks'       => true, // Block null byte (%00) poison attacks in URI & inputs
            'waf_block_sensitive_file_probes'   => true, // Block instant .env, .git, .sql, and backup file reconnaissance
            'waf_block_uploads_php_exec'        => true, // Deny direct execution requests to php files in wp-content/uploads/
            'waf_block_external_cron'           => false, // Block external HTTP hits to wp-cron.php (exempt loopback/cli)
            'waf_block_open_redirects'          => true, // Block open redirects targeting external phishing destinations
            'waf_block_ssrf_metadata'           => true, // Block SSRF probes targeting 169.254.169.254 cloud metadata
            'waf_block_install_php'             => true, // Lockdown install.php and upgrade.php on installed sites

            // Specialized Armor: phpMyAdmin & File Manager Restrictions
            'waf_disallow_phpmyadmin_plugins'   => true, // Disallow installation of phpMyAdmin & database manager plugins
            'waf_disallow_filemanager_plugins'  => true, // Disallow installation of File Manager plugins
            'waf_disallow_phpmyadmin_uploads'   => true, // Block uploads of phpMyAdmin / Adminer / standalone database scripts
            'waf_disallow_filemanager_uploads'  => true, // Block uploads of standalone File Manager / Webshell explorer scripts

            // Phase 2: Enumeration Suppression & Abuse / Rate Guards (Rules #29 - #34)
            'waf_block_rest_user_enum'          => true, // Rule #29: Block unauthenticated REST API user enumeration (/wp/v2/users)
            'waf_block_author_scan'             => true, // Rule #30: Suppress author ID permalink query scans (?author=N)
            'waf_limit_lostpassword'            => true, // Rule #31: Rate-limit lost-password reset attempts (3 / 15 min per IP & identity)
            'waf_enforce_host_allowlist'        => true, // Rule #32: Strict Host header allowlist against cache & reset poisoning
            'waf_allowed_host_aliases'          => '',   // Extra allowed host aliases/domains (one per line)
            'waf_limit_admin_ajax'              => true, // Rule #33: admin-ajax.php unauthenticated request burst rate limiter
            'waf_admin_ajax_limit_per_min'      => 60,   // Max unauthenticated admin-ajax requests per minute per IP
            'waf_block_oversized_requests'      => true, // Rule #34: Oversized request URI, query string, & parameter count guard
            'waf_block_ai_prompt_injection'     => true, // Rule #35: AI Prompt Injection & Agent Poisoning Shield

            // 9. Cloud Threat Intelligence & Community Blacklists
            'threat_intel_enabled'               => true,
            'threat_intel_block_blacklisted_ips' => true,

            // 10. Multi-Factor Authentication (2FA), Login Hardening & Session Sentinel
            'auth_2fa_enabled'                   => true,
            'auth_2fa_remember_device'           => true,
            'auth_2fa_remember_days'             => 7, // Days to remember trusted device (default 7 days)
            'auth_2fa_enforce_admins'            => false, // Force all administrator accounts to enable 2FA
            'auth_2fa_policy_mode'               => 'remind_login', // 'immediate' | 'grace_period' | 'remind_login'
            'auth_2fa_grace_days'                => 30, // Grace period in days (default 30 days when remind_login is active)
            'auth_2fa_enforce_since'             => 0, // Timestamp when enforcement policy was activated
            'login_hardening_enabled'            => true,
            'login_max_retries'                  => 5,
            'login_lockout_duration'             => 15,
            'session_sentinel_enabled'           => true,
            'session_block_concurrent'           => false,

            // 11. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n)
            'slack_enabled'                      => false,
            'slack_webhook_url'                  => '',
            'discord_enabled'                    => false,
            'discord_webhook_url'                => '',
            'clickup_enabled'                    => false,
            'clickup_webhook_url'                => '',
            'asana_enabled'                      => false,
            'asana_webhook_url'                  => '',
            'generic_webhook_enabled'            => false,
            'generic_webhook_url'                => '',
            'webhook_notify_on_critical'         => true,
            'webhook_notify_on_fim'              => true,
            'webhook_notify_on_waf_block'        => false,
            'webhook_notify_on_scan_finish'      => true,

            // 12. Cloudflare Edge Defense Integration
            'cloudflare_enabled'                 => false,
            'cloudflare_api_token'               => '',
            'cloudflare_zone_id'                 => '',
            'cloudflare_auto_sync_bans'          => false,

            // 13. False-Positive Tuning & Confidence Thresholds
            'confidence_threshold_filesystem'    => 50,
            'confidence_threshold_lotl'          => 60,
            'confidence_threshold_ai'            => 70,
            'confidence_threshold_db'            => 50,
            'auto_suppress_whitelisted'          => true,

            // 14. Model Context Protocol (MCP) Agent Service Surface
            'mcp_enabled'                        => true,
            'mcp_token'                          => '',
            'mcp_permission_scope'               => 'read_write',
            'mcp_rate_limit_per_min'             => 60,
            'mcp_tool_matrix'                    => self::get_default_mcp_tool_matrix(),

            // 15. Custom Scan Engine Options (Wordfence-style scan customization)
            'custom_scan_options'                => self::get_default_custom_scan_options(),

            // 16. Plugin Self-Defense & Anti-Tamper Attestation
            'self_defense_watchdog_enabled'      => true,
            'self_defense_notify_email'          => true,

            // 17. Granular Event Notifications Matrix
            'notification_master_enabled'        => true,
            'notification_events'                => self::get_default_notification_events(),
        ];
    }

    /**
     * Default states for all granular notification events
     */
    public static function get_default_notification_events(): array {
        return [
            // Core Scans & Threats
            'scan_scheduled_complete'   => ['email' => false, 'webhook' => false],
            'scan_manual_complete'      => ['email' => false, 'webhook' => false],
            'scan_targeted_complete'    => ['email' => false, 'webhook' => false],
            'scan_threats_found'        => ['email' => true,  'webhook' => true],
            'scan_auto_quarantine'      => ['email' => false, 'webhook' => false],
            'scan_aborted_timeout'      => ['email' => false, 'webhook' => false],

            // Plugin Self-Defense
            'plugin_file_tampered'      => ['email' => false, 'webhook' => false],
            'plugin_file_missing'       => ['email' => false, 'webhook' => false],
            'plugin_deactivate_attempt' => ['email' => true,  'webhook' => true],
            'plugin_uninstall'          => ['email' => false, 'webhook' => false],

            // Cloudflare & WAF
            'cf_firewall_updated'       => ['email' => false, 'webhook' => false],
            'cf_firewall_rule_deleted'  => ['email' => false, 'webhook' => false],
            'waf_block_surge'           => ['email' => false, 'webhook' => false],
            'waf_virtual_patch_hit'     => ['email' => false, 'webhook' => false],
            'waf_server_rules_updated'  => ['email' => false, 'webhook' => false],

            // Authentication & 2FA
            'auth_2fa_enabled'          => ['email' => false, 'webhook' => false],
            'auth_2fa_disabled'         => ['email' => false, 'webhook' => false],
            'auth_admin_password_reset' => ['email' => false, 'webhook' => false],
            'auth_bruteforce_lockout'   => ['email' => false, 'webhook' => false],
            'auth_cf_edge_ban_synced'   => ['email' => false, 'webhook' => false],
            'auth_session_hijack_flag'  => ['email' => false, 'webhook' => false],
            'auth_rogue_admin_created'  => ['email' => false, 'webhook' => false],

            // File Integrity Monitoring (FIM)
            'fim_core_file_modified'    => ['email' => false, 'webhook' => false],
            'fim_plugin_theme_modified' => ['email' => false, 'webhook' => false],
            'fim_suspicious_php_found'  => ['email' => false, 'webhook' => false],
            'fim_auto_cure_applied'     => ['email' => false, 'webhook' => false],
            'fim_baseline_refreshed'    => ['email' => false, 'webhook' => false],

            // Vulnerabilities & Updates (CVE)
            'vuln_core_cve_detected'    => ['email' => false, 'webhook' => false],
            'vuln_plugin_theme_cve'     => ['email' => false, 'webhook' => false],
            'vuln_abandoned_extension'  => ['email' => false, 'webhook' => false],
            'vuln_feed_synced'          => ['email' => false, 'webhook' => false],

            // Database Backups & Vault
            'backup_db_completed'       => ['email' => false, 'webhook' => false],
            'backup_db_failed'          => ['email' => false, 'webhook' => false],
            'backup_db_restored'        => ['email' => false, 'webhook' => false],
            'vault_quarantine_restored' => ['email' => false, 'webhook' => false],
            'vault_quarantine_deleted'  => ['email' => false, 'webhook' => false],

            // DevSecOps Webhooks & AI Forensics
            'webhook_status_toggled'    => ['email' => false, 'webhook' => false],
            'webhook_delivery_failed'   => ['email' => false, 'webhook' => false],
            'ai_forensics_toggled'      => ['email' => false, 'webhook' => false],
            'mcp_service_toggled'       => ['email' => false, 'webhook' => false],
        ];
    }

    /**
     * Default state for customizable scan engine options
     */
    public static function get_default_custom_scan_options(): array {
        return [
            // Reputation Checks (Free On-Premise DNSBL & Spam Feeds)
            'check_domain_blocklist'     => true,
            'check_spamvertised'         => true,
            'check_spam_ip'              => true,

            // General & Deep Detection Engines
            'scan_ip_detection'          => true,
            'scan_public_config'         => true,
            'scan_public_quarantine'     => true,
            'scan_core_integrity'        => true,
            'scan_theme_integrity'       => true,
            'scan_plugin_integrity'      => true,
            'scan_unbundled_files'       => true,
            'scan_known_malware'         => true,
            'scan_backdoors_heuristics'  => true,
            'scan_malicious_urls'        => true,
            'scan_posts_content'         => true,
            'scan_comments_content'      => true,
            'scan_options_content'       => true,
            'scan_vulnerable_software'   => true,
            'scan_rogue_admins'          => true,
            'scan_password_strength'     => false, // Disabled by default matching screenshot
            'monitor_disk_space'         => true,
            'monitor_firewall_status'    => true,
            'scan_outside_root'          => true,
            'scan_images_executable'     => true,
        ];
    }

    /**
     * Sanitize custom scan engine options
     */
    public static function sanitize_custom_scan_options(array $opts): array {
        $defaults = self::get_default_custom_scan_options();
        $clean = [];
        foreach ($defaults as $key => $default_val) {
            $clean[$key] = !empty($opts[$key]);
        }
        return $clean;
    }

    /**
     * Sanitize granular notification events dictionary
     */
    public static function sanitize_notification_events(array $events): array {
        $defaults = self::get_default_notification_events();
        $clean = [];
        foreach ($defaults as $key => $default_channels) {
            $incoming = isset($events[$key]) && is_array($events[$key]) ? $events[$key] : [];
            $clean[$key] = [
                'email'   => isset($incoming['email']) ? !empty($incoming['email']) : ($default_channels['email'] ?? false),
                'webhook' => isset($incoming['webhook']) ? !empty($incoming['webhook']) : ($default_channels['webhook'] ?? false),
            ];
        }
        return $clean;
    }

    /**
     * Default governance policy matrix for all MCP agent tools.
     */
    public static function get_default_mcp_tool_matrix(): array {
        return [
            'wcpscan_get_security_posture'      => 'allowed',
            'wcpscan_list_findings'             => 'allowed',
            'wcpscan_audit_behavioral_baseline' => 'allowed',
            'wcpscan_get_containment_status'    => 'allowed',
            'wcpscan_list_staged_actions'       => 'allowed',
            'wcpscan_whitelist_finding'         => 'allowed',
            'wcpscan_rollback_remediation'      => 'confirmation_required',
            'wcpscan_deploy_virtual_patch'      => 'confirmation_required',
            'wcpscan_quarantine_file'           => 'confirmation_required',
            'wcpscan_run_security_drill'        => 'allowed',
            'wcpscan_set_containment_mode'           => 'confirmation_required',
            'wcpscan_approve_staged_action'          => 'confirmation_required',
            'wcpscan_get_supply_chain_sbom'          => 'allowed',
            'wcpscan_get_gatekeeper_history'         => 'allowed',
            'wcpscan_recalibrate_sbom_baseline'      => 'confirmation_required',
            'wcpscan_quarantine_supply_chain_anchor' => 'confirmation_required',
            'wcpscan_get_behavioral_waf_status'      => 'allowed',
            'wcpscan_set_route_learning_status'       => 'confirmation_required',
            'wcpscan_get_identity_forensics'         => 'allowed',
            'wcpscan_revoke_user_session'            => 'confirmation_required',
            'wcpscan_grant_ephemeral_elevation'      => 'confirmation_required',
            'wcpscan_revoke_ephemeral_elevation'     => 'confirmation_required',
            'wcpscan_get_threat_intel_network'       => 'allowed',
            'wcpscan_sync_threat_intel'              => 'allowed',
            'wcpscan_synthesize_virtual_patch'       => 'confirmation_required',
            'wcpscan_test_virtual_patch'             => 'allowed',
            'wcpscan_deploy_synthesized_patch'       => 'confirmation_required',
        ];
    }

    /**
     * Sanitize MCP tool policy governance matrix.
     */
    public static function sanitize_mcp_tool_matrix(array $matrix): array {
        $valid_policies = ['allowed', 'confirmation_required', 'blocked'];
        $defaults = self::get_default_mcp_tool_matrix();
        $clean = [];
        foreach ($defaults as $tool => $def_policy) {
            $incoming = $matrix[$tool] ?? $def_policy;
            $clean[$tool] = in_array($incoming, $valid_policies, true) ? $incoming : $def_policy;
        }
        return $clean;
    }

    /**
     * Get a specific setting by key with decrypted value.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public static function get(string $key, $default = null) {
        $settings = self::get_settings();
        return array_key_exists($key, $settings) ? $settings[$key] : $default;
    }

    /**
     * Retrieve all settings merged with defaults and decrypted.
     */
    public static function get_settings(): array {
        $saved = get_option(self::OPTION_KEY, []);
        if (!is_array($saved)) {
            $saved = [];
        }

        $defaults = self::get_defaults();
        $merged = array_merge($defaults, $saved);

        // Transparently decrypt sensitive credentials if encrypted
        $sensitive_keys = [
            'cloudflare_api_token',
            'cloudflare_zone_id',
            'openai_api_key',
            'gemini_api_key',
            'claude_api_key',
            'slack_webhook_url',
            'discord_webhook_url',
            'clickup_webhook_url',
            'asana_webhook_url',
            'generic_webhook_url',
        ];

        foreach ($sensitive_keys as $k) {
            if (!empty($merged[$k])) {
                $raw_val = (string) $merged[$k];
                if (\WcpScanner\Security\SecretVault::is_encrypted($raw_val)) {
                    $merged[$k] = \WcpScanner\Security\SecretVault::decrypt($raw_val);
                }
            }
        }

        // Mask API keys and credentials for security in UI output
        $merged['has_openai_key']          = !empty($merged['openai_api_key']);
        $merged['has_gemini_key']          = !empty($merged['gemini_api_key']);
        $merged['has_claude_key']          = !empty($merged['claude_api_key']);
        $merged['has_cloudflare_key']      = !empty($merged['cloudflare_api_token']);
        $merged['has_slack_webhook']       = !empty($merged['slack_webhook_url']);
        $merged['has_discord_webhook']     = !empty($merged['discord_webhook_url']);
        $merged['has_clickup_webhook']     = !empty($merged['clickup_webhook_url']);
        $merged['has_asana_webhook']       = !empty($merged['asana_webhook_url']);
        $merged['has_generic_webhook']     = !empty($merged['generic_webhook_url']);

        return $merged;
    }

    /**
     * Save settings with sanitization and hook updates
     */
    public static function save_settings(array $input): array {
        $current = get_option(self::OPTION_KEY, []);
        if (!is_array($current)) {
            $current = [];
        }

        $defaults = self::get_defaults();
        // Merge defaults, current options, and input so partial saves (from individual rule toggles,
        // specific settings pages, or cloudflare verifications) NEVER inadvertently reset or uncheck omitted rules!
        $merged = array_merge($defaults, $current, $input);

        $clean = [];

        // 1. Schedule Scan Settings
        $clean['schedule_enabled']   = !empty($merged['schedule_enabled']);
        $valid_freq = ['hourly', 'twicedaily', 'daily', 'weekly'];
        $clean['schedule_frequency'] = in_array($merged['schedule_frequency'] ?? '', $valid_freq, true) 
            ? $merged['schedule_frequency'] 
            : 'daily';
        $clean['schedule_time']      = sanitize_text_field($merged['schedule_time'] ?? '02:00');
        $valid_targets = ['plugins_themes', 'full', 'core_integrity', 'suspicious_uploads', 'spam_content'];
        $clean['schedule_scan_type'] = in_array($merged['schedule_scan_type'] ?? '', $valid_targets, true)
            ? $merged['schedule_scan_type']
            : 'plugins_themes';

        // 2. Email Notifications
        $clean['email_alerts_enabled']    = !empty($merged['email_alerts_enabled']);
        $clean['alert_emails']            = sanitize_textarea_field($merged['alert_emails'] ?? '');
        $valid_sev = ['critical', 'high', 'medium', 'all'];
        $clean['alert_min_severity']      = in_array($merged['alert_min_severity'] ?? '', $valid_sev, true) 
            ? $merged['alert_min_severity'] 
            : 'high';
        $clean['email_digest_enabled']    = !empty($merged['email_digest_enabled']);
        $clean['email_on_scan_completed'] = !empty($merged['email_on_scan_completed']);
        $clean['notify_on_cve_detected']  = !empty($merged['notify_on_cve_detected']);

        // 3. AI Threat Integration
        $clean['ai_enabled']               = !empty($merged['ai_enabled']);
        $valid_ai = ['openai', 'gemini', 'claude', 'wp_ai_connect'];
        $clean['ai_provider']              = in_array($merged['ai_provider'] ?? '', $valid_ai, true) 
            ? $merged['ai_provider'] 
            : 'openai';

        // Preserve existing keys if incoming is masked or empty, and securely encrypt for database storage
        $in_openai = trim($input['openai_api_key'] ?? '');
        $openai_val = ($in_openai === '' || $in_openai === '••••••••') 
            ? \WcpScanner\Security\SecretVault::decrypt($current['openai_api_key'] ?? '') 
            : sanitize_text_field($in_openai);
        $clean['openai_api_key'] = \WcpScanner\Security\SecretVault::encrypt($openai_val);
        $clean['openai_model'] = sanitize_text_field($merged['openai_model'] ?? 'gpt-6.1-sol');

        $in_gemini = trim($input['gemini_api_key'] ?? '');
        $gemini_val = ($in_gemini === '' || $in_gemini === '••••••••') 
            ? \WcpScanner\Security\SecretVault::decrypt($current['gemini_api_key'] ?? '') 
            : sanitize_text_field($in_gemini);
        $clean['gemini_api_key'] = \WcpScanner\Security\SecretVault::encrypt($gemini_val);
        $clean['gemini_model'] = sanitize_text_field($merged['gemini_model'] ?? 'gemini-3.8-flash');

        $in_claude = trim($input['claude_api_key'] ?? '');
        $claude_val = ($in_claude === '' || $in_claude === '••••••••') 
            ? \WcpScanner\Security\SecretVault::decrypt($current['claude_api_key'] ?? '') 
            : sanitize_text_field($in_claude);
        $clean['claude_api_key'] = \WcpScanner\Security\SecretVault::encrypt($claude_val);
        $clean['claude_model'] = sanitize_text_field($merged['claude_model'] ?? 'claude-sonnet-5-5');

        $clean['ai_temperature']           = max(0.0, min(1.0, floatval($merged['ai_temperature'] ?? 0.2)));
        $clean['ai_auto_analyze_critical'] = !empty($merged['ai_auto_analyze_critical']);

        // 4. Scanner Performance & Throttle
        $batch = intval($merged['scan_batch_size'] ?? 50);
        $clean['scan_batch_size']          = ($batch >= 10 && $batch <= 300) ? $batch : 50;
        $clean['memory_limit_override']    = sanitize_text_field($merged['memory_limit_override'] ?? '512M');
        $clean['max_file_size_kb']         = max(100, intval($merged['max_file_size_kb'] ?? 1024));
        $clean['auto_quarantine_critical'] = !empty($merged['auto_quarantine_critical']);

        // 5. Exclusions & Ignore Rules
        $clean['excluded_paths']    = sanitize_textarea_field($merged['excluded_paths'] ?? $defaults['excluded_paths']);
        $clean['custom_extensions'] = sanitize_text_field($merged['custom_extensions'] ?? $defaults['custom_extensions']);

        // 6. Security Tweaks & HTTP Security Headers
        $clean['disable_file_editing']  = !empty($merged['disable_file_editing']);
        $clean['hide_wp_version']       = !empty($merged['hide_wp_version']);
        $clean['block_sensitive_files'] = !empty($merged['block_sensitive_files']);
        $clean['block_user_enumeration'] = !empty($merged['block_user_enumeration']);

        // HTTP Security Headers
        $clean['header_hsts']                 = !empty($merged['header_hsts']);
        $clean['header_hsts_preload']         = !empty($merged['header_hsts_preload']);
        $clean['header_x_frame_options']      = !empty($merged['header_x_frame_options']);
        $clean['header_x_frame_options_mode'] = in_array(strtoupper($merged['header_x_frame_options_mode'] ?? ''), ['DENY', 'SAMEORIGIN'], true) ? strtoupper($merged['header_x_frame_options_mode']) : 'SAMEORIGIN';
        $clean['header_nosniff']              = !empty($merged['header_nosniff']);
        $clean['header_referrer_policy']      = !empty($merged['header_referrer_policy']);
        $clean['header_referrer_policy_value'] = sanitize_text_field($merged['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin');
        $clean['header_permissions_policy']   = !empty($merged['header_permissions_policy']);
        $clean['header_permissions_policy_value'] = sanitize_text_field($merged['header_permissions_policy_value'] ?? 'geolocation=(), camera=(), microphone=(), payment=()');
        $clean['header_xss_protection']       = !empty($merged['header_xss_protection']);
        $clean['header_csp_enabled']          = !empty($merged['header_csp_enabled']);
        $clean['header_csp_custom']           = sanitize_text_field($merged['header_csp_custom'] ?? '');

        // 7. Cleanup & Data Privacy on Plugin Uninstall
        $clean['delete_data_on_uninstall'] = !empty($merged['delete_data_on_uninstall']);

        // 8. Web Application Firewall (WAF) Lite
        $clean['waf_enabled']             = !empty($merged['waf_enabled']);
        $valid_waf_modes                  = ['enabled', 'learning', 'disabled'];
        $clean['waf_mode']                = in_array($merged['waf_mode'] ?? '', $valid_waf_modes, true) ? $merged['waf_mode'] : 'enabled';
        $clean['waf_complementary_mode']  = !empty($merged['waf_complementary_mode']);
        $clean['waf_block_sqli']          = !empty($merged['waf_block_sqli']);
        $clean['waf_block_xss']           = !empty($merged['waf_block_xss']);
        $clean['waf_block_traversal']     = !empty($merged['waf_block_traversal']);
        $clean['waf_block_php_injection'] = !empty($merged['waf_block_php_injection']);
        $clean['waf_disable_xmlrpc']      = !empty($merged['waf_disable_xmlrpc']);
        $clean['waf_allow_jetpack_xmlrpc'] = !empty($merged['waf_allow_jetpack_xmlrpc']);
        $clean['waf_login_rate_limit']    = !empty($merged['waf_login_rate_limit']);
        $clean['waf_whitelisted_ips']     = sanitize_textarea_field($merged['waf_whitelisted_ips'] ?? '');
        $clean['waf_blocked_ips']         = sanitize_textarea_field($merged['waf_blocked_ips'] ?? '');
        $clean['waf_block_fake_bots']     = !empty($merged['waf_block_fake_bots']);
        $clean['waf_block_ai_scrapers']   = !empty($merged['waf_block_ai_scrapers']);
        $clean['waf_dynamic_robots_ai']   = !empty($merged['waf_dynamic_robots_ai']);
        $clean['waf_block_404_scanners']   = !empty($merged['waf_block_404_scanners']);
        $clean['waf_404_threshold']        = max(3, min(100, (int) ($merged['waf_404_threshold'] ?? 10)));
        $clean['waf_404_window_seconds']   = max(10, min(600, (int) ($merged['waf_404_window_seconds'] ?? 60)));
        $clean['waf_404_lockout_duration'] = max(1, min(1440, (int) ($merged['waf_404_lockout_duration'] ?? 30)));
        $clean['waf_allow_uptime_monitors']        = !empty($merged['waf_allow_uptime_monitors']);
        $clean['waf_allow_central_management']     = !empty($merged['waf_allow_central_management']);
        $clean['waf_allow_page_builders']          = !empty($merged['waf_allow_page_builders']);

        // Enhanced Perimeter & Identity Protection Rules
        $clean['waf_ecommerce_safe_mode']         = !empty($merged['waf_ecommerce_safe_mode']);
        $clean['waf_block_empty_post_ua_referer'] = !empty($merged['waf_block_empty_post_ua_referer']);
        $clean['waf_whitelisted_urls']            = sanitize_textarea_field($merged['waf_whitelisted_urls'] ?? '');

        // Targeted User-Agent, Endpoint & IP Allowlist Rules
        $raw_targeted = $merged['waf_targeted_allowlist_rules'] ?? '[]';
        if (is_array($raw_targeted)) {
            $parsed_targeted = $raw_targeted;
        } else {
            $parsed_targeted = json_decode((string) $raw_targeted, true);
        }
        $clean_targeted = [];
        if (is_array($parsed_targeted)) {
            foreach ($parsed_targeted as $rule) {
                if (!is_array($rule)) {
                    continue;
                }
                $rule_id = !empty($rule['id']) ? sanitize_key($rule['id']) : 'rule_' . substr(md5(uniqid((string) wp_rand(), true)), 0, 8);
                $clean_targeted[] = [
                    'id'           => $rule_id,
                    'name'         => sanitize_text_field($rule['name'] ?? 'Custom Allowlist Rule'),
                    'enabled'      => isset($rule['enabled']) ? (bool) $rule['enabled'] : true,
                    'user_agents'  => is_array($rule['user_agents'] ?? null) 
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['user_agents'])))
                        : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['user_agents'] ?? '')))))),
                    'endpoints'    => is_array($rule['endpoints'] ?? null)
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['endpoints'])))
                        : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['endpoints'] ?? '')))))),
                    'ip_addresses'     => is_array($rule['ip_addresses'] ?? null)
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['ip_addresses'])))
                        : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['ip_addresses'] ?? '')))))),
                    'hostnames'        => is_array($rule['hostnames'] ?? null)
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['hostnames'])))
                        : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['hostnames'] ?? '')))))),
                    'asns'             => is_array($rule['asns'] ?? null)
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['asns'])))
                        : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['asns'] ?? '')))))),
                    'required_headers' => is_array($rule['required_headers'] ?? null)
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['required_headers'])))
                        : array_values(array_filter(array_map('sanitize_text_field', explode("\n", str_replace("\r", "", (string) ($rule['required_headers'] ?? '')))))),
                    'methods'          => is_array($rule['methods'] ?? null)
                        ? array_values(array_filter(array_map('sanitize_text_field', $rule['methods'])))
                        : ['ALL'],
                    'log_payload'      => isset($rule['log_payload']) ? (bool) $rule['log_payload'] : true,
                    'description'      => sanitize_text_field($rule['description'] ?? ''),
                ];
            }
        }
        $clean['waf_targeted_allowlist_rules']    = wp_json_encode($clean_targeted);

        $clean['waf_block_forbidden_usernames']   = !empty($merged['waf_block_forbidden_usernames']);
        $clean['waf_forbidden_usernames_list']    = sanitize_textarea_field($merged['waf_forbidden_usernames_list'] ?? "admin\nadministrator\nroot");
        $clean['waf_prevent_admin_registration']  = !empty($merged['waf_prevent_admin_registration']);
        $clean['waf_mask_login_errors']           = !empty($merged['waf_mask_login_errors']);
        $clean['waf_enforce_strong_passwords']    = !empty($merged['waf_enforce_strong_passwords']);
        $clean['waf_strong_passwords_roles']      = sanitize_text_field($merged['waf_strong_passwords_roles'] ?? 'administrator, editor');
        $clean['waf_check_pwned_passwords']       = !empty($merged['waf_check_pwned_passwords']);
        $clean['waf_block_malicious_uploads']     = !empty($merged['waf_block_malicious_uploads']);
        $clean['waf_block_unsafe_http_methods']   = !empty($merged['waf_block_unsafe_http_methods']);
        $clean['waf_block_null_byte_attacks']     = !empty($merged['waf_block_null_byte_attacks']);
        $clean['waf_block_sensitive_file_probes'] = !empty($merged['waf_block_sensitive_file_probes']);
        $clean['waf_block_uploads_php_exec']      = !empty($merged['waf_block_uploads_php_exec']);
        $clean['waf_block_external_cron']         = !empty($merged['waf_block_external_cron']);
        $clean['waf_block_open_redirects']        = !empty($merged['waf_block_open_redirects']);
        $clean['waf_block_ssrf_metadata']         = !empty($merged['waf_block_ssrf_metadata']);
        $clean['waf_block_install_php']           = !empty($merged['waf_block_install_php']);

        // Specialized Armor: phpMyAdmin & File Manager Restrictions
        $clean['waf_disallow_phpmyadmin_plugins']  = !empty($merged['waf_disallow_phpmyadmin_plugins']);
        $clean['waf_disallow_filemanager_plugins'] = !empty($merged['waf_disallow_filemanager_plugins']);
        $clean['waf_disallow_phpmyadmin_uploads']  = !empty($merged['waf_disallow_phpmyadmin_uploads']);
        $clean['waf_disallow_filemanager_uploads'] = !empty($merged['waf_disallow_filemanager_uploads']);

        // Phase 2: Enumeration Suppression & Abuse / Rate Guards (Rules #29 - #34)
        $clean['waf_block_rest_user_enum']     = !empty($merged['waf_block_rest_user_enum']);
        $clean['waf_block_author_scan']        = !empty($merged['waf_block_author_scan']);
        $clean['waf_limit_lostpassword']       = !empty($merged['waf_limit_lostpassword']);
        $clean['waf_enforce_host_allowlist']   = !empty($merged['waf_enforce_host_allowlist']);
        $clean['waf_allowed_host_aliases']     = sanitize_textarea_field($merged['waf_allowed_host_aliases'] ?? '');
        $clean['waf_limit_admin_ajax']         = !empty($merged['waf_limit_admin_ajax']);
        $clean['waf_admin_ajax_limit_per_min'] = max(10, min(300, (int) ($merged['waf_admin_ajax_limit_per_min'] ?? 60)));
        $clean['waf_block_oversized_requests'] = !empty($merged['waf_block_oversized_requests']);
        $clean['waf_block_ai_prompt_injection'] = !empty($merged['waf_block_ai_prompt_injection']);

        // 9. Cloud Threat Intelligence & Community Blacklists
        $clean['threat_intel_enabled']               = !empty($merged['threat_intel_enabled']);
        $clean['threat_intel_block_blacklisted_ips'] = !empty($merged['threat_intel_block_blacklisted_ips']);

        // 10. Multi-Factor Authentication (2FA), Login Hardening & Session Sentinel
        $clean['auth_2fa_enabled']          = !empty($merged['auth_2fa_enabled']);
        $clean['auth_2fa_remember_device']  = !empty($merged['auth_2fa_remember_device']);
        $clean['auth_2fa_remember_days']    = max(1, min(90, (int) ($merged['auth_2fa_remember_days'] ?? 7)));
        $clean['auth_2fa_enforce_admins']   = !empty($merged['auth_2fa_enforce_admins']);
        $raw_mode                           = sanitize_key($merged['auth_2fa_policy_mode'] ?? 'remind_login');
        $clean['auth_2fa_policy_mode']      = in_array($raw_mode, ['immediate', 'grace_period', 'remind_login'], true) ? $raw_mode : 'remind_login';
        $clean['auth_2fa_grace_days']       = max(0, min(90, (int) ($merged['auth_2fa_grace_days'] ?? 0)));
        // Record timestamp when enforcement is newly enabled
        $prev_enforce = !empty($current['auth_2fa_enforce_admins']);
        if ($clean['auth_2fa_enforce_admins'] && !$prev_enforce) {
            $clean['auth_2fa_enforce_since'] = time();
        } elseif (!$clean['auth_2fa_enforce_admins']) {
            $clean['auth_2fa_enforce_since'] = 0;
        } else {
            $clean['auth_2fa_enforce_since'] = (int) ($current['auth_2fa_enforce_since'] ?? time());
        }
        $clean['login_hardening_enabled']   = !empty($merged['login_hardening_enabled']);
        $clean['login_max_retries']         = max(1, min(20, (int) ($merged['login_max_retries'] ?? 5)));
        $clean['login_lockout_duration']    = max(1, min(1440, (int) ($merged['login_lockout_duration'] ?? 15)));
        $clean['session_sentinel_enabled']  = !empty($merged['session_sentinel_enabled']);
        $clean['session_block_concurrent']  = !empty($merged['session_block_concurrent']);


        // 11. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n - Encrypted with SecretVault)
        $clean['slack_enabled']                 = !empty($merged['slack_enabled']);
        $in_slack                               = trim($input['slack_webhook_url'] ?? '');
        $is_masked_slack                        = $in_slack === '' || strpos($in_slack, '••') !== false;
        $slack_val                              = $is_masked_slack
            ? \WcpScanner\Security\SecretVault::decrypt($current['slack_webhook_url'] ?? '')
            : esc_url_raw($in_slack);
        $clean['slack_webhook_url']             = \WcpScanner\Security\SecretVault::encrypt($slack_val);

        $clean['discord_enabled']               = !empty($merged['discord_enabled']);
        $in_discord                             = trim($input['discord_webhook_url'] ?? '');
        $is_masked_discord                      = $in_discord === '' || strpos($in_discord, '••') !== false;
        $discord_val                            = $is_masked_discord
            ? \WcpScanner\Security\SecretVault::decrypt($current['discord_webhook_url'] ?? '')
            : esc_url_raw($in_discord);
        $clean['discord_webhook_url']           = \WcpScanner\Security\SecretVault::encrypt($discord_val);

        $clean['clickup_enabled']               = !empty($merged['clickup_enabled']);
        $in_clickup                             = trim($input['clickup_webhook_url'] ?? '');
        $is_masked_clickup                      = $in_clickup === '' || strpos($in_clickup, '••') !== false;
        $clickup_val                            = $is_masked_clickup
            ? \WcpScanner\Security\SecretVault::decrypt($current['clickup_webhook_url'] ?? '')
            : esc_url_raw($in_clickup);
        $clean['clickup_webhook_url']           = \WcpScanner\Security\SecretVault::encrypt($clickup_val);

        $clean['asana_enabled']                 = !empty($merged['asana_enabled']);
        $in_asana                               = trim($input['asana_webhook_url'] ?? '');
        $is_masked_asana                        = $in_asana === '' || strpos($in_asana, '••') !== false;
        $asana_val                              = $is_masked_asana
            ? \WcpScanner\Security\SecretVault::decrypt($current['asana_webhook_url'] ?? '')
            : esc_url_raw($in_asana);
        $clean['asana_webhook_url']             = \WcpScanner\Security\SecretVault::encrypt($asana_val);

        $clean['generic_webhook_enabled']       = !empty($merged['generic_webhook_enabled']);
        $in_generic                             = trim($input['generic_webhook_url'] ?? '');
        $is_masked_generic                      = $in_generic === '' || strpos($in_generic, '••') !== false;
        $generic_val                            = $is_masked_generic
            ? \WcpScanner\Security\SecretVault::decrypt($current['generic_webhook_url'] ?? '')
            : esc_url_raw($in_generic);
        $clean['generic_webhook_url']           = \WcpScanner\Security\SecretVault::encrypt($generic_val);

        $clean['webhook_notify_on_critical']    = !empty($merged['webhook_notify_on_critical']);
        $clean['webhook_notify_on_fim']         = !empty($merged['webhook_notify_on_fim']);
        $clean['webhook_notify_on_waf_block']   = !empty($merged['webhook_notify_on_waf_block']);
        $clean['webhook_notify_on_scan_finish'] = !empty($merged['webhook_notify_on_scan_finish']);

        // 12. Cloudflare Edge Defense Integration (Encrypted with SecretVault)
        $clean['cloudflare_enabled']        = !empty($merged['cloudflare_enabled']);
        $in_cf_token                        = trim($input['cloudflare_api_token'] ?? '');
        $is_masked_token                    = $in_cf_token === '' || strpos($in_cf_token, '••') !== false;
        $cf_token_val                       = $is_masked_token
            ? \WcpScanner\Security\SecretVault::decrypt($current['cloudflare_api_token'] ?? '')
            : sanitize_text_field($in_cf_token);
        $clean['cloudflare_api_token']      = \WcpScanner\Security\SecretVault::encrypt($cf_token_val);

        $in_zone_id                         = trim($input['cloudflare_zone_id'] ?? '');
        $is_masked_zone                     = $in_zone_id === '' || strpos($in_zone_id, '••') !== false;
        $zone_id_val                        = $is_masked_zone
            ? \WcpScanner\Security\SecretVault::decrypt($current['cloudflare_zone_id'] ?? '')
            : sanitize_text_field($in_zone_id);
        $clean['cloudflare_zone_id']        = \WcpScanner\Security\SecretVault::encrypt($zone_id_val);

        $clean['cloudflare_auto_sync_bans'] = !empty($merged['cloudflare_auto_sync_bans']);

        // 13. False-Positive Tuning & Confidence Thresholds
        $clean['confidence_threshold_filesystem'] = max(1, min(100, intval($merged['confidence_threshold_filesystem'] ?? 50)));
        $clean['confidence_threshold_lotl']       = max(1, min(100, intval($merged['confidence_threshold_lotl'] ?? 60)));
        $clean['confidence_threshold_ai']         = max(1, min(100, intval($merged['confidence_threshold_ai'] ?? 70)));
        $clean['confidence_threshold_db']         = max(1, min(100, intval($merged['confidence_threshold_db'] ?? 50)));
        $clean['auto_suppress_whitelisted']       = !empty($merged['auto_suppress_whitelisted']);

        // 14. Model Context Protocol (MCP) Agent Service Surface
        $clean['mcp_enabled'] = !empty($merged['mcp_enabled']);
        $mcp_tok = trim($input['mcp_token'] ?? '');
        if (empty($mcp_tok) && !empty($current['mcp_token'])) {
            $clean['mcp_token'] = $current['mcp_token'];
        } elseif (!empty($mcp_tok)) {
            $clean['mcp_token'] = sanitize_text_field($mcp_tok);
        } else {
            $clean['mcp_token'] = $current['mcp_token'] ?? ('wcpscan_mcp_' . bin2hex(random_bytes(16)));
        }

        $valid_scopes = ['read_only', 'read_write'];
        $clean['mcp_permission_scope'] = in_array($merged['mcp_permission_scope'] ?? '', $valid_scopes, true)
            ? $merged['mcp_permission_scope']
            : ($current['mcp_permission_scope'] ?? 'read_write');

        $clean['mcp_rate_limit_per_min'] = max(10, min(600, intval($merged['mcp_rate_limit_per_min'] ?? ($current['mcp_rate_limit_per_min'] ?? 60))));

        if (isset($input['mcp_tool_matrix']) && is_array($input['mcp_tool_matrix'])) {
            $clean['mcp_tool_matrix'] = self::sanitize_mcp_tool_matrix($input['mcp_tool_matrix']);
        } elseif (isset($current['mcp_tool_matrix']) && is_array($current['mcp_tool_matrix'])) {
            $clean['mcp_tool_matrix'] = self::sanitize_mcp_tool_matrix($current['mcp_tool_matrix']);
        } else {
            $clean['mcp_tool_matrix'] = self::get_default_mcp_tool_matrix();
        }

        // 15. Custom Scan Engine Options
        if (isset($input['custom_scan_options']) && is_array($input['custom_scan_options'])) {
            $clean['custom_scan_options'] = self::sanitize_custom_scan_options($input['custom_scan_options']);
        } elseif (isset($current['custom_scan_options']) && is_array($current['custom_scan_options'])) {
            $clean['custom_scan_options'] = $current['custom_scan_options'];
        } else {
            $clean['custom_scan_options'] = self::get_default_custom_scan_options();
        }

        // 16. Plugin Self-Defense
        $clean['self_defense_watchdog_enabled'] = !empty($merged['self_defense_watchdog_enabled']);
        $clean['self_defense_notify_email']     = !empty($merged['self_defense_notify_email']);

        // 17. Granular Event Notifications Matrix
        $clean['notification_master_enabled']   = !empty($merged['notification_master_enabled']);
        if (isset($input['notification_events']) && is_array($input['notification_events'])) {
            $clean['notification_events'] = self::sanitize_notification_events($input['notification_events']);
        } elseif (isset($current['notification_events']) && is_array($current['notification_events'])) {
            $clean['notification_events'] = self::sanitize_notification_events($current['notification_events']);
        } else {
            $clean['notification_events'] = self::get_default_notification_events();
        }

        update_option(self::OPTION_KEY, $clean);

        // Synchronize Cron Schedule
        self::sync_cron_schedule($clean);

        return self::get_settings();
    }

    /**
     * Set a single setting by key and save.
     *
     * @param string $key
     * @param mixed $value
     * @return array
     */
    public static function set(string $key, $value) {
        $settings = self::get_settings();
        $settings[$key] = $value;
        return self::save_settings($settings);
    }

    /**
     * Synchronize WordPress Cron for scheduled scanning
     */
    public static function sync_cron_schedule(array $settings) {
        $timestamp = wp_next_scheduled(self::CRON_HOOK);

        if (empty($settings['schedule_enabled'])) {
            if ($timestamp) {
                wp_unschedule_event($timestamp, self::CRON_HOOK);
            }
            return;
        }

        $frequency = $settings['schedule_frequency'] ?? 'daily';
        
        // If not scheduled or scheduled with different frequency, recreate schedule
        if ($timestamp) {
            wp_unschedule_event($timestamp, self::CRON_HOOK);
        }

        $now_utc = time();
        $time_str = !empty($settings['schedule_time']) ? $settings['schedule_time'] : '02:00';
        $parts = explode(':', $time_str);
        $target_hour = isset($parts[0]) ? (int) $parts[0] : 2;
        $target_minute = isset($parts[1]) ? (int) $parts[1] : 0;

        // Use WordPress site timezone for clean datetime arithmetic
        $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone(get_option('timezone_string') ?: 'UTC');
        $site_now = new \DateTimeImmutable('now', $tz);

        if ($frequency === 'hourly') {
            // Anchor to the specific minute of each hour (e.g. 11:59 -> :59 past the hour)
            $cand = $site_now->setTime((int) $site_now->format('H'), $target_minute, 0);
            if ($cand->getTimestamp() <= $now_utc) {
                $cand = $cand->modify('+1 hour');
            }
            $target_utc = $cand->getTimestamp();

            // Safety guard: guarantee target is in the future
            while ($target_utc <= $now_utc) {
                $target_utc += HOUR_IN_SECONDS;
            }
        } elseif ($frequency === 'twicedaily') {
            // Twice daily (every 12 hours) anchored to schedule_time
            $cand = $site_now->setTime($target_hour, $target_minute, 0);
            $anchor_utc = $cand->getTimestamp();

            // Find nearest upcoming occurrence (every 12 hours from anchor)
            $target_utc = $anchor_utc;
            while ($target_utc <= $now_utc) {
                $target_utc += (12 * HOUR_IN_SECONDS);
            }
            while (($target_utc - (12 * HOUR_IN_SECONDS)) > $now_utc) {
                $target_utc -= (12 * HOUR_IN_SECONDS);
            }
        } else {
            // Daily or Weekly at the configured schedule_time in site timezone
            $cand = $site_now->setTime($target_hour, $target_minute, 0);
            $target_utc = $cand->getTimestamp();

            if ($target_utc <= $now_utc) {
                $target_utc += DAY_IN_SECONDS;
            }
        }

        wp_schedule_event($target_utc, $frequency, self::CRON_HOOK);
    }

    /**
     * Export all settings as JSON payload
     */
    public static function export_settings(): array {
        $settings = get_option(self::OPTION_KEY, self::get_defaults());
        return [
            'app'        => 'WCP Security Scanner',
            'version'    => defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.3.0',
            'exported_at'=> current_time('mysql'),
            'site_url'   => get_site_url(),
            'settings'   => $settings,
        ];
    }

    /**
     * Import settings from JSON payload
     */
    public static function import_settings(array $payload): array {
        if (empty($payload['settings']) || !is_array($payload['settings'])) {
            throw new \Exception(esc_html__('Invalid settings backup file format.', 'wcp-security-scanner'));
        }

        return self::save_settings($payload['settings']);
    }

    /**
     * Reset settings to factory defaults
     */
    public static function reset_defaults(): array {
        $defaults = self::get_defaults();
        update_option(self::OPTION_KEY, $defaults);
        self::sync_cron_schedule($defaults);
        return self::get_settings();
    }

    /**
     * Test if a file path matches user-configured excluded paths/patterns.
     *
     * @param string $file_path
     * @return bool
     */
    public static function is_path_excluded(string $file_path): bool {
        $raw = self::get('excluded_paths');
        if (empty($raw)) {
            return false;
        }

        $normalized = str_replace('\\', '/', $file_path);
        $lines = explode("\n", $raw);

        foreach ($lines as $line) {
            $pattern = trim($line);
            if (empty($pattern) || strpos($pattern, '#') === 0) {
                continue;
            }
            $pattern = str_replace('\\', '/', $pattern);
            
            // Substring or wildcard match
            if (fnmatch("*{$pattern}*", $normalized) || fnmatch($pattern, $normalized) || stripos($normalized, trim($pattern, '*')) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Test if an index.php or index.html file is a harmless directory listing prevention placeholder.
     *
     * Handles:
     * 1. 0-byte or whitespace-only index files.
     * 2. Purely comment / docblock placeholders (e.g. WP Staging, Elementor, Wordfence directory protection notices).
     * 3. Standard WordPress "Silence is golden." placeholders.
     * 4. Harmless exit, die, 403 Forbidden header, or defined('ABSPATH') guard scripts.
     * 5. Static HTML directory disabled notices without embedded scripts.
     *
     * @param string $file_path
     * @return bool
     */
    public static function is_safe_directory_index(string $file_path): bool {
        if (!file_exists($file_path)) {
            return false;
        }

        $file_size = @filesize($file_path);
        // Harmless silence/protection files are compact (up to 8KB to accommodate multi-paragraph developer docblocks)
        if ($file_size === false || $file_size > 8192) {
            return false;
        }

        // 0-byte file is completely safe
        if ($file_size === 0) {
            return true;
        }

        $content = @file_get_contents($file_path, false, null, 0, 8192);
        if ($content === false) {
            return false;
        }

        $trimmed = trim($content);
        if ($trimmed === '' || $trimmed === '<?php' || $trimmed === '<?php ?>' || $trimmed === '<?php ?>\n') {
            return true;
        }

        // Must NOT contain any dangerous execution functions, webshell signatures, superglobals, or backdoors
        $dangerous_pattern = '/(eval\s*\(|base64_decode\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|gzinflate\s*\(|gzuncompress\s*\(|create_function\s*\(|file_put_contents\s*\(|curl_exec\s*\(|include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\(|\$_POST|\$_GET|\$_REQUEST|\$_COOKIE|\$_SERVER|\$GLOBALS)/i';
        if (preg_match($dangerous_pattern, $content)) {
            return false;
        }

        // Static HTML index files without script tags
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        if (in_array($ext, ['html', 'htm'], true)) {
            if (stripos($content, '<?') === false && stripos($content, '<script') === false) {
                return true;
            }
            return false;
        }

        // Tokenize PHP to inspect actual AST tokens
        $tokens = @token_get_all($content);
        if (!is_array($tokens)) {
            return false;
        }

        $allowed_token_ids = [
            T_OPEN_TAG,
            T_CLOSE_TAG,
            T_WHITESPACE,
            T_COMMENT,
            T_DOC_COMMENT,
            T_INLINE_HTML,
            T_EXIT,
            T_STRING,
            T_CONSTANT_ENCAPSED_STRING,
            T_LNUMBER,
            T_BOOLEAN_OR,
            T_BOOLEAN_AND,
            T_IS_IDENTICAL,
            T_IS_NOT_IDENTICAL,
            T_IS_EQUAL,
            T_IS_NOT_EQUAL,
        ];

        $allowed_chars = ['(', ')', ';', ',', '!', ':', '{', '}'];
        $allowed_function_names = ['header', 'http_response_code', 'defined', 'exit', 'die'];

        foreach ($tokens as $token) {
            if (is_array($token)) {
                $id = $token[0];
                $text = trim($token[1]);

                // Harmless structural, comment, and docblock tokens (WP Staging, Silence is Golden, etc.)
                if (in_array($id, [T_OPEN_TAG, T_CLOSE_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                // Inline HTML check
                if ($id === T_INLINE_HTML) {
                    if (stripos($text, '<?') !== false || stripos($text, '<script') !== false) {
                        return false;
                    }
                    continue;
                }

                if (!in_array($id, $allowed_token_ids, true)) {
                    return false;
                }

                // If identifier/string, verify it is only harmless exit/header/defined statements
                if ($id === T_STRING) {
                    $lower = strtolower($text);
                    if (!in_array($lower, $allowed_function_names, true) && !in_array($text, ['ABSPATH', 'WPINC'], true)) {
                        return false;
                    }
                }
            } else {
                if (!in_array($token, $allowed_chars, true)) {
                    return false;
                }
            }
        }

        // If file contains only comments, docblocks, whitespace, or safe guards, it is completely benign
        return true;
    }

    /**
     * Checks if a PHP file in the uploads directory is a benign, compiled cache file generated
     * by recognized legitimate WordPress plugins (such as MailPoet Twig template cache or W3TC cache),
     * while rigorously verifying it contains zero malware, webshells, or backdoor signatures.
     *
     * @param string $file_path
     * @return bool True if benign plugin cache file with zero malware indicators.
     */
    public static function is_legitimate_uploads_cache_file(string $file_path): bool {
        if (!file_exists($file_path)) {
            return false;
        }

        $norm = str_replace('\\', '/', $file_path);

        // 1. Must match a known legitimate plugin cache directory pattern within wp-content/uploads/
        $is_recognized_cache_dir = (
            preg_match('#/wp-content/uploads/mailpoet/cache/[a-f0-9]{2}/[a-f0-9]{64}\.php$#i', $norm) ||
            preg_match('#/wp-content/uploads/w3tc-cache/#i', $norm) ||
            preg_match('#/wp-content/uploads/wp-optimize-cache/#i', $norm) ||
            preg_match('#/wp-content/uploads/elementor/css/#i', $norm)
        );

        if (!$is_recognized_cache_dir) {
            return false;
        }

        $size = @filesize($file_path);
        // Twig template caches can be 10KB - 500KB, but shouldn't exceed 2MB
        if ($size === false || $size > 2 * 1024 * 1024) {
            return false;
        }

        $content = @file_get_contents($file_path);
        if ($content === false || strlen($content) < 10) {
            return false;
        }

        // 2. Strict Zero-Tolerance Malware / Webshell Signature Scan
        // If it contains ANY dangerous webshell/backdoor patterns, it MUST NOT be ignored!
        $backdoor_patterns = [
            '/\b(eval|assert|passthru|shell_exec|exec|system|proc_open|popen|pcntl_exec)\s*\(/i',
            '/\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*["\']?[a-zA-Z0-9+\/]{40,}/i',
            '/\b(file_put_contents|fwrite|fputs)\s*\(\s*["\']?[^,\)]+\.(php|phtml|phar)/i',
            '/\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/i', // Dynamic execution: $_POST['x'](...)
            '/\$\w+\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',       // Dynamic variable execution: $cmd($_POST['a'])
            '/preg_replace\s*\(\s*["\']\/[^\/]*\/e["\']/i',      // preg_replace /e modifier code execution
            '/\b(c99shell|r57shell|b374k|wso_version|alfa_team|indosec|loggershell)\b/i',
            '/\b(chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}/i',           // Obfuscated string concatenation chains
        ];

        foreach ($backdoor_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return false; // Real malware detected! Do NOT ignore!
            }
        }

        // 3. For MailPoet Twig template cache: verify authentic MailPoet Twig template footprint
        if (strpos($norm, '/mailpoet/cache/') !== false) {
            $is_twig = (
                strpos($content, 'MailPoetVendor\Twig') !== false ||
                strpos($content, '__TwigTemplate_') !== false ||
                strpos($content, 'extends \MailPoetVendor\Twig\Template') !== false
            );
            return $is_twig;
        }

        return true;
    }
}
