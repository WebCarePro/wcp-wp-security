<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPSettingsPolicy
 *
 * Strict allowlist & risk-tier classifier for SettingsManager keys exposed through
 * webcareproscan_get_settings_catalog and webcareproscan_update_plugin_settings.
 * Secrets and MCP governance keys are unconditionally masked on read and rejected on write.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
class MCPSettingsPolicy {

    /**
     * Secret / governance keys that MCP can NEVER read in plaintext or modify.
     */
    const IMMUTABLE_KEYS = [
        'mcp_enabled',
        'mcp_token',
        'mcp_permission_scope',
        'mcp_persona_preset',
        'mcp_rate_limit_per_min',
        'mcp_tool_matrix',
        'mcp_token_ttl_days',
        'mcp_token_created_at',
        'mcp_allowed_cidrs',
        'openai_api_key',
        'gemini_api_key',
        'claude_api_key',
        'deepseek_api_key',
        'openrouter_api_key',
        'cloudflare_api_token',
        'cloudflare_zone_id',
        'slack_webhook_url',
        'discord_webhook_url',
        'clickup_webhook_url',
        'asana_webhook_url',
        'generic_webhook_url',
        'delete_data_on_uninstall',
        'uninstall_drop_tables',
        'uninstall_delete_options',
        'uninstall_delete_crons',
        'uninstall_delete_uploads',
    ];

    /**
     * Tier 2: Safe reversible configuration settings.
     */
    const TIER2_KEYS = [
        'header_hsts',
        'header_hsts_preload',
        'header_x_frame_options',
        'header_x_frame_options_mode',
        'header_nosniff',
        'header_referrer_policy',
        'header_referrer_policy_value',
        'header_permissions_policy',
        'header_permissions_policy_value',
        'header_xss_protection',
        'hide_wp_version',
        'waf_forms_safe_mode',
        'waf_ecommerce_safe_mode',
        'waf_allow_page_builders',
        'waf_allow_jetpack_xmlrpc',
        'waf_allow_uptime_monitors',
        'waf_allow_central_management',
        'waf_block_rest_user_enum',
        'waf_block_author_scan',
        'waf_block_404_scanners',
        'waf_404_threshold',
        'waf_404_window_seconds',
        'waf_404_lockout_duration',
        'waf_woo_carding_protection',
        'waf_woo_coupon_protection',
        'waf_woo_registration_protection',
        'waf_woo_cart_flood_protection',
        'waf_woo_scraping_protection',
        'waf_block_ai_scrapers',
        'waf_dynamic_robots_ai',
        'waf_block_ai_prompt_injection',
        'scan_batch_size',
        'scan_batch_delay_ms',
        'scan_adaptive_throttling',
        'scan_memory_safety_envelope',
        'scan_uploads_mode',
        'email_digest_enabled',
        'waf_log_retention_days',
        'cron_log_retention_days',
    ];

    /**
     * Tier 3: Sensitive security posture settings (auto-staged for WP Admin approval).
     */
    const TIER3_KEYS = [
        'waf_enabled',
        'waf_mode',
        'waf_complementary_mode',
        'waf_block_sqli',
        'waf_block_xss',
        'waf_block_traversal',
        'waf_block_php_injection',
        'waf_block_sensitive_files',
        'waf_block_uploads_php_exec',
        'waf_block_malicious_uploads',
        'waf_upload_deep_mime_sanitizer',
        'waf_block_external_cron',
        'waf_block_open_redirects',
        'waf_block_ssrf_metadata',
        'waf_disable_xmlrpc',
        'waf_runtime_rasp_privilege_guard',
        'waf_whitelisted_ips',
        'waf_whitelisted_urls',
        'waf_whitelist_require_admin',
        'waf_targeted_allowlist_rules',
        'waf_guest_ajax_policy',
        'waf_guest_ajax_custom_allowlist',
        'waf_guest_rest_policy',
        'login_hardening_enabled',
        'login_max_retries',
        'login_lockout_duration',
        'session_sentinel_enabled',
        'cloudflare_enabled',
        'cloudflare_auto_sync_bans',
        'threat_intel_enabled',
        'threat_intel_block_blacklisted_ips',
        'schedule_enabled',
        'schedule_frequency',
        'schedule_time',
        'schedule_scan_type',
        'excluded_paths',
        'scan_excluded_tables',
        'disable_file_editing',
        'block_sensitive_files',
        'block_user_enumeration',
        'header_csp_enabled',
        'header_csp_custom',
    ];

    /**
     * Tier 4: Lockout-critical or destructive settings (always staged + step-up approval).
     */
    const TIER4_KEYS = [
        'auth_2fa_enabled',
        'auth_2fa_enforce_admins',
        'auth_2fa_policy_mode',
        'auth_2fa_grace_days',
        'session_block_concurrent',
        'auto_quarantine_critical',
        'self_defense_watchdog_enabled',
    ];

    /**
     * Classify a single setting key into its tier ('blocked' | 2 | 3 | 4).
     *
     * @param string $key
     * @return int|string
     */
    public static function get_key_tier(string $key) {
        if (in_array($key, self::IMMUTABLE_KEYS, true)) {
            return 'blocked';
        }
        if (in_array($key, self::TIER4_KEYS, true)) {
            return 4;
        }
        if (in_array($key, self::TIER3_KEYS, true)) {
            return 3;
        }
        if (in_array($key, self::TIER2_KEYS, true)) {
            return 2;
        }
        return 'blocked';
    }

    /**
     * Build grouped, secret-masked settings catalog for MCP inspection.
     *
     * @param string $domain Optional domain filter (all|headers|waf|scanner|auth|cloudflare|schedule|immutable)
     * @return array<string, mixed>
     */
    public static function get_catalog(string $domain = 'all'): array {
        $settings = SettingsManager::get_settings();
        $groups   = [
            'waf'        => [],
            'headers'    => [],
            'scanner'    => [],
            'auth'       => [],
            'cloudflare' => [],
            'schedule'   => [],
            'other'      => [],
            'immutable'  => [],
        ];

        $all_allowed = array_merge(self::TIER2_KEYS, self::TIER3_KEYS, self::TIER4_KEYS);
        foreach ($all_allowed as $key) {
            $val  = $settings[$key] ?? null;
            $tier = self::get_key_tier($key);
            $cat  = 'other';
            if (strpos($key, 'header_') === 0 || $key === 'hide_wp_version') {
                $cat = 'headers';
            } elseif (strpos($key, 'waf_') === 0 || strpos($key, 'threat_intel_') === 0) {
                $cat = 'waf';
            } elseif (strpos($key, 'scan_') === 0 || $key === 'excluded_paths' || $key === 'auto_quarantine_critical') {
                $cat = 'scanner';
            } elseif (strpos($key, 'auth_') === 0 || strpos($key, 'login_') === 0 || strpos($key, 'session_') === 0) {
                $cat = 'auth';
            } elseif (strpos($key, 'cloudflare_') === 0) {
                $cat = 'cloudflare';
            } elseif (strpos($key, 'schedule_') === 0) {
                $cat = 'schedule';
            }
            $groups[$cat][$key] = [
                'value' => $val,
                'tier'  => $tier,
            ];
        }

        foreach (self::IMMUTABLE_KEYS as $ikey) {
            $raw = $settings[$ikey] ?? '';
            $is_secret = (bool) preg_match('/(?:token|key|webhook)/i', $ikey);
            $groups['immutable'][$ikey] = [
                'configured' => !empty($raw),
                'masked'     => $is_secret ? (!empty($raw) ? '••••••••' : '') : $raw,
                'writable'   => false,
            ];
        }

        if ($domain !== '' && $domain !== 'all' && isset($groups[$domain])) {
            return [
                'domain'   => $domain,
                'settings' => [$domain => $groups[$domain]],
            ];
        }

        return [
            'domain'   => 'all',
            'settings' => $groups,
        ];
    }

    /**
     * Validate a batch of setting updates, reject unknown/immutable keys, compute max risk tier,
     * and construct a human-readable Before -> After diff preview.
     *
     * @param array<string, mixed> $updates
     * @return array<string, mixed>
     */
    public static function validate_and_classify_update(array $updates): array {
        if (empty($updates)) {
            return [
                'valid'   => false,
                'message' => __('No settings updates provided.', 'webcare-pro-security'),
            ];
        }

        $current      = SettingsManager::get_settings();
        $clean_patch  = [];
        $max_tier     = 2;
        $diff_preview = [];

        foreach ($updates as $raw_key => $new_val) {
            $key  = sanitize_key((string) $raw_key);
            $tier = self::get_key_tier($key);

            if ($tier === 'blocked') {
                return [
                    'valid'   => false,
                    'message' => sprintf(
                        /* translators: %s: blocked or unknown setting key */
                        __('Setting key "%s" is immutable or not in the MCP allowlist.', 'webcare-pro-security'),
                        $key
                    ),
                ];
            }

            // Anti-lockout guard on direct IP blocklist/allowlist/exclusion mutations
            if ($key === 'waf_whitelisted_ips' || $key === 'excluded_paths') {
                $raw_str = (string) $new_val;
                if ($key === 'excluded_paths' && preg_match('/(?:^|\n)\s*(?:\*|\/|\.\.)\s*(?:\n|$)/', $raw_str)) {
                    return [
                        'valid'   => false,
                        'message' => __('Wildcard root "*" or ".." traversal paths cannot be added to excluded_paths via MCP.', 'webcare-pro-security'),
                    ];
                }
            }

            if ((int) $tier > $max_tier) {
                $max_tier = (int) $tier;
            }

            $clean_patch[$key] = $new_val;
            $diff_preview[]    = [
                'key'    => $key,
                'tier'   => (int) $tier,
                'before' => $current[$key] ?? null,
                'after'  => $new_val,
            ];
        }

        return [
            'valid'        => true,
            'max_tier'     => $max_tier,
            'patch'        => $clean_patch,
            'diff_preview' => $diff_preview,
        ];
    }
}
