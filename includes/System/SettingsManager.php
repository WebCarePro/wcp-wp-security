<?php
namespace WCP\Scanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class SettingsManager {
    const OPTION_KEY = 'wcp_scanner_settings';
    const CRON_HOOK = 'wcp_scanner_scheduled_scan_event';

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
            'scan_batch_size'          => 50, // 25, 50, 100, 200
            'memory_limit_override'    => '512M',
            'max_file_size_kb'         => 1024, // Skip files larger than 1MB from heuristic scanning
            'auto_quarantine_critical' => false, // Safeguard off by default

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

            // 7. Cleanup & Data Privacy on Plugin Uninstall (Enabled by default)
            'delete_data_on_uninstall' => true,

            // 8. Web Application Firewall (WAF) Lite
            'waf_enabled'              => true,
            'waf_mode'                 => 'enabled', // 'enabled' | 'learning' | 'disabled'
            'waf_complementary_mode'   => true, // Auto-negotiate if Wordfence/Cloudflare active
            'waf_block_sqli'           => true,
            'waf_block_xss'            => true,
            'waf_block_traversal'      => true,
            'waf_block_php_injection'  => true,
            'waf_disable_xmlrpc'       => false,
            'waf_login_rate_limit'     => true,
            'waf_whitelisted_ips'      => '',
            'waf_block_fake_bots'      => true,
            'waf_block_ai_scrapers'    => false,
            'waf_dynamic_robots_ai'    => true,

            // 9. Cloud Threat Intelligence & Community Blacklists
            'threat_intel_enabled'               => true,
            'threat_intel_block_blacklisted_ips' => true,

            // 10. Multi-Factor Authentication (2FA), Login Hardening & Session Sentinel
            'auth_2fa_enabled'                   => true,
            'auth_2fa_remember_device'           => true,
            'auth_2fa_remember_days'             => 7, // Days to remember trusted device (default 7 days)
            'login_hardening_enabled'            => true,
            'login_max_retries'                  => 5,
            'login_lockout_duration'             => 15,
            'session_sentinel_enabled'           => true,
            'session_block_concurrent'           => false,
            'session_lock_ip'                    => false,
            'session_idle_timeout'               => 120, // Minutes before inactive session is revoked

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
        ];
    }

    /**
     * Retrieve all settings merged with defaults
     */
    public static function get_settings(): array {
        $saved = get_option(self::OPTION_KEY, []);
        if (!is_array($saved)) {
            $saved = [];
        }

        $defaults = self::get_defaults();
        $merged = array_merge($defaults, $saved);

        // Mask API keys for security in UI output
        $merged['has_openai_key']     = !empty($merged['openai_api_key']);
        $merged['has_gemini_key']     = !empty($merged['gemini_api_key']);
        $merged['has_claude_key']     = !empty($merged['claude_api_key']);
        $merged['has_cloudflare_key'] = !empty($merged['cloudflare_api_token']);

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
        $clean = [];

        // 1. Schedule Scan Settings
        $clean['schedule_enabled']   = !empty($input['schedule_enabled']);
        $valid_freq = ['hourly', 'twicedaily', 'daily', 'weekly'];
        $clean['schedule_frequency'] = in_array($input['schedule_frequency'] ?? '', $valid_freq, true) 
            ? $input['schedule_frequency'] 
            : 'daily';
        $clean['schedule_time']      = sanitize_text_field($input['schedule_time'] ?? '02:00');
        $valid_targets = ['plugins_themes', 'full', 'core_integrity', 'suspicious_uploads', 'spam_content'];
        $clean['schedule_scan_type'] = in_array($input['schedule_scan_type'] ?? '', $valid_targets, true)
            ? $input['schedule_scan_type']
            : 'plugins_themes';

        // 2. Email Notifications
        $clean['email_alerts_enabled']    = !empty($input['email_alerts_enabled']);
        $clean['alert_emails']            = sanitize_textarea_field($input['alert_emails'] ?? '');
        $valid_sev = ['critical', 'high', 'medium', 'all'];
        $clean['alert_min_severity']      = in_array($input['alert_min_severity'] ?? '', $valid_sev, true) 
            ? $input['alert_min_severity'] 
            : 'high';
        $clean['email_digest_enabled']    = !empty($input['email_digest_enabled']);
        $clean['email_on_scan_completed'] = !empty($input['email_on_scan_completed']);
        $clean['notify_on_cve_detected']  = !empty($input['notify_on_cve_detected']);

        // 3. AI Threat Integration
        $clean['ai_enabled']               = !empty($input['ai_enabled']);
        $valid_ai = ['openai', 'gemini', 'claude'];
        $clean['ai_provider']              = in_array($input['ai_provider'] ?? '', $valid_ai, true) 
            ? $input['ai_provider'] 
            : 'openai';

        // Preserve existing keys if incoming is masked or empty
        $in_openai = trim($input['openai_api_key'] ?? '');
        $clean['openai_api_key'] = ($in_openai === '' || $in_openai === '••••••••') 
            ? ($current['openai_api_key'] ?? '') 
            : sanitize_text_field($in_openai);
        $clean['openai_model'] = sanitize_text_field($input['openai_model'] ?? 'gpt-6.1-sol');

        $in_gemini = trim($input['gemini_api_key'] ?? '');
        $clean['gemini_api_key'] = ($in_gemini === '' || $in_gemini === '••••••••') 
            ? ($current['gemini_api_key'] ?? '') 
            : sanitize_text_field($in_gemini);
        $clean['gemini_model'] = sanitize_text_field($input['gemini_model'] ?? 'gemini-3.8-flash');

        $in_claude = trim($input['claude_api_key'] ?? '');
        $clean['claude_api_key'] = ($in_claude === '' || $in_claude === '••••••••') 
            ? ($current['claude_api_key'] ?? '') 
            : sanitize_text_field($in_claude);
        $clean['claude_model'] = sanitize_text_field($input['claude_model'] ?? 'claude-sonnet-5-5');

        $clean['ai_temperature']           = max(0.0, min(1.0, floatval($input['ai_temperature'] ?? 0.2)));
        $clean['ai_auto_analyze_critical'] = !empty($input['ai_auto_analyze_critical']);

        // 4. Scanner Performance & Throttle
        $batch = intval($input['scan_batch_size'] ?? 50);
        $clean['scan_batch_size']          = ($batch >= 10 && $batch <= 300) ? $batch : 50;
        $clean['memory_limit_override']    = sanitize_text_field($input['memory_limit_override'] ?? '512M');
        $clean['max_file_size_kb']         = max(100, intval($input['max_file_size_kb'] ?? 1024));
        $clean['auto_quarantine_critical'] = !empty($input['auto_quarantine_critical']);

        // 5. Exclusions & Ignore Rules
        $clean['excluded_paths']    = sanitize_textarea_field($input['excluded_paths'] ?? $defaults['excluded_paths']);
        $clean['custom_extensions'] = sanitize_text_field($input['custom_extensions'] ?? $defaults['custom_extensions']);

        // 6. Security Tweaks & HTTP Security Headers
        $clean['disable_file_editing']  = !empty($input['disable_file_editing']);
        $clean['hide_wp_version']       = !empty($input['hide_wp_version']);
        $clean['block_sensitive_files'] = !empty($input['block_sensitive_files']);
        $clean['block_user_enumeration'] = isset($input['block_user_enumeration']) ? !empty($input['block_user_enumeration']) : true;

        // HTTP Security Headers
        $clean['header_hsts']                 = isset($input['header_hsts']) ? !empty($input['header_hsts']) : true;
        $clean['header_hsts_preload']         = !empty($input['header_hsts_preload']);
        $clean['header_x_frame_options']      = isset($input['header_x_frame_options']) ? !empty($input['header_x_frame_options']) : true;
        $clean['header_x_frame_options_mode'] = in_array(strtoupper($input['header_x_frame_options_mode'] ?? ''), ['DENY', 'SAMEORIGIN'], true) ? strtoupper($input['header_x_frame_options_mode']) : 'SAMEORIGIN';
        $clean['header_nosniff']              = isset($input['header_nosniff']) ? !empty($input['header_nosniff']) : true;
        $clean['header_referrer_policy']      = isset($input['header_referrer_policy']) ? !empty($input['header_referrer_policy']) : true;
        $clean['header_referrer_policy_value'] = sanitize_text_field($input['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin');
        $clean['header_permissions_policy']   = isset($input['header_permissions_policy']) ? !empty($input['header_permissions_policy']) : true;
        $clean['header_permissions_policy_value'] = sanitize_text_field($input['header_permissions_policy_value'] ?? 'geolocation=(), camera=(), microphone=(), payment=()');
        $clean['header_xss_protection']       = isset($input['header_xss_protection']) ? !empty($input['header_xss_protection']) : true;
        $clean['header_csp_enabled']          = !empty($input['header_csp_enabled']);
        $clean['header_csp_custom']           = sanitize_text_field($input['header_csp_custom'] ?? '');

        // 7. Cleanup & Data Privacy on Plugin Uninstall
        $clean['delete_data_on_uninstall'] = isset($input['delete_data_on_uninstall']) ? !empty($input['delete_data_on_uninstall']) : true;

        // 8. Web Application Firewall (WAF) Lite
        $clean['waf_enabled']             = isset($input['waf_enabled']) ? !empty($input['waf_enabled']) : true;
        $valid_waf_modes                  = ['enabled', 'learning', 'disabled'];
        $clean['waf_mode']                = in_array($input['waf_mode'] ?? '', $valid_waf_modes, true) ? $input['waf_mode'] : 'enabled';
        $clean['waf_complementary_mode']  = isset($input['waf_complementary_mode']) ? !empty($input['waf_complementary_mode']) : true;
        $clean['waf_block_sqli']          = isset($input['waf_block_sqli']) ? !empty($input['waf_block_sqli']) : true;
        $clean['waf_block_xss']           = isset($input['waf_block_xss']) ? !empty($input['waf_block_xss']) : true;
        $clean['waf_block_traversal']     = isset($input['waf_block_traversal']) ? !empty($input['waf_block_traversal']) : true;
        $clean['waf_block_php_injection'] = isset($input['waf_block_php_injection']) ? !empty($input['waf_block_php_injection']) : true;
        $clean['waf_disable_xmlrpc']      = !empty($input['waf_disable_xmlrpc']);
        $clean['waf_login_rate_limit']    = isset($input['waf_login_rate_limit']) ? !empty($input['waf_login_rate_limit']) : true;
        $clean['waf_whitelisted_ips']     = sanitize_textarea_field($input['waf_whitelisted_ips'] ?? '');
        $clean['waf_block_fake_bots']     = isset($input['waf_block_fake_bots']) ? !empty($input['waf_block_fake_bots']) : true;
        $clean['waf_block_ai_scrapers']   = !empty($input['waf_block_ai_scrapers']);
        $clean['waf_dynamic_robots_ai']   = isset($input['waf_dynamic_robots_ai']) ? !empty($input['waf_dynamic_robots_ai']) : true;

        // 9. Cloud Threat Intelligence & Community Blacklists
        $clean['threat_intel_enabled']               = isset($input['threat_intel_enabled']) ? !empty($input['threat_intel_enabled']) : true;
        $clean['threat_intel_block_blacklisted_ips'] = isset($input['threat_intel_block_blacklisted_ips']) ? !empty($input['threat_intel_block_blacklisted_ips']) : true;

        // 10. Multi-Factor Authentication (2FA), Login Hardening & Session Sentinel
        $clean['auth_2fa_enabled']          = isset($input['auth_2fa_enabled']) ? !empty($input['auth_2fa_enabled']) : true;
        $clean['auth_2fa_remember_device']  = isset($input['auth_2fa_remember_device']) ? !empty($input['auth_2fa_remember_device']) : true;
        $clean['auth_2fa_remember_days']    = max(1, min(90, (int) ($input['auth_2fa_remember_days'] ?? 7)));
        $clean['login_hardening_enabled']   = isset($input['login_hardening_enabled']) ? !empty($input['login_hardening_enabled']) : true;
        $clean['login_max_retries']         = max(1, min(20, (int) ($input['login_max_retries'] ?? 5)));
        $clean['login_lockout_duration']    = max(1, min(1440, (int) ($input['login_lockout_duration'] ?? 15)));
        $clean['session_sentinel_enabled']  = isset($input['session_sentinel_enabled']) ? !empty($input['session_sentinel_enabled']) : true;
        $clean['session_block_concurrent']  = !empty($input['session_block_concurrent']);
        $clean['session_lock_ip']           = !empty($input['session_lock_ip']);
        $clean['session_idle_timeout']      = max(0, min(1440, (int) ($input['session_idle_timeout'] ?? 120)));


        // 11. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n)
        $clean['slack_enabled']                 = !empty($input['slack_enabled']);
        $clean['slack_webhook_url']             = esc_url_raw(trim($input['slack_webhook_url'] ?? ''));
        $clean['discord_enabled']               = !empty($input['discord_enabled']);
        $clean['discord_webhook_url']           = esc_url_raw(trim($input['discord_webhook_url'] ?? ''));
        $clean['clickup_enabled']               = !empty($input['clickup_enabled']);
        $clean['clickup_webhook_url']           = esc_url_raw(trim($input['clickup_webhook_url'] ?? ''));
        $clean['asana_enabled']                 = !empty($input['asana_enabled']);
        $clean['asana_webhook_url']             = esc_url_raw(trim($input['asana_webhook_url'] ?? ''));
        $clean['generic_webhook_enabled']       = !empty($input['generic_webhook_enabled']);
        $clean['generic_webhook_url']           = esc_url_raw(trim($input['generic_webhook_url'] ?? ''));
        $clean['webhook_notify_on_critical']    = isset($input['webhook_notify_on_critical']) ? !empty($input['webhook_notify_on_critical']) : true;
        $clean['webhook_notify_on_fim']         = isset($input['webhook_notify_on_fim']) ? !empty($input['webhook_notify_on_fim']) : true;
        $clean['webhook_notify_on_waf_block']   = !empty($input['webhook_notify_on_waf_block']);
        $clean['webhook_notify_on_scan_finish'] = isset($input['webhook_notify_on_scan_finish']) ? !empty($input['webhook_notify_on_scan_finish']) : true;

        // 12. Cloudflare Edge Defense Integration
        $clean['cloudflare_enabled']        = !empty($input['cloudflare_enabled']);
        $in_cf_token                        = trim($input['cloudflare_api_token'] ?? '');
        $clean['cloudflare_api_token']      = ($in_cf_token === '' || $in_cf_token === '••••••••')
            ? ($current['cloudflare_api_token'] ?? '')
            : sanitize_text_field($in_cf_token);
        $clean['cloudflare_zone_id']        = sanitize_text_field(trim($input['cloudflare_zone_id'] ?? ''));
        $clean['cloudflare_auto_sync_bans'] = !empty($input['cloudflare_auto_sync_bans']);

        update_option(self::OPTION_KEY, $clean);

        // Synchronize Cron Schedule
        self::sync_cron_schedule($clean);

        return self::get_settings();
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

        // Calculate next run time based on schedule_time (HH:MM in site's timezone)
        $time_str = $settings['schedule_time'] ?: '02:00';
        $parts = explode(':', $time_str);
        $hour = isset($parts[0]) ? (int) $parts[0] : 2;
        $minute = isset($parts[1]) ? (int) $parts[1] : 0;

        $now = current_time('timestamp');
        $target_time = mktime($hour, $minute, 0, (int) gmdate('m', $now), (int) gmdate('d', $now), (int) gmdate('Y', $now));
        if ($target_time <= $now) {
            $target_time += DAY_IN_SECONDS;
        }

        wp_schedule_event($target_time, $frequency, self::CRON_HOOK);
    }

    /**
     * Export all settings as JSON payload
     */
    public static function export_settings(): array {
        $settings = get_option(self::OPTION_KEY, self::get_defaults());
        return [
            'app'        => 'WCP Security Scanner',
            'version'    => defined('WCP_SCANNER_VERSION') ? WCP_SCANNER_VERSION : '1.3.0',
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
            throw new \Exception(__('Invalid settings backup file format.', 'wcp-security-scanner'));
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
     * Test if an index.php or index.html file in uploads is a harmless directory listing prevention placeholder.
     *
     * @param string $file_path
     * @return bool
     */
    public static function is_safe_directory_index(string $file_path): bool {
        if (!file_exists($file_path)) {
            return false;
        }

        $file_size = @filesize($file_path);
        // Harmless silence/protection files are always small (under 1KB)
        if ($file_size === false || $file_size > 1024) {
            return false;
        }

        // 0-byte file is completely safe
        if ($file_size === 0) {
            return true;
        }

        $content = @file_get_contents($file_path, false, null, 0, 1024);
        if ($content === false) {
            return false;
        }

        // Must NOT contain any dangerous execution functions, webshell signatures, or superglobals
        if (preg_match('/(eval\s*\(|base64_decode\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|gzinflate\s*\(|gzuncompress\s*\(|create_function\s*\(|\$_POST|\$_GET|\$_REQUEST|\$_COOKIE|\$_SERVER)/i', $content)) {
            return false;
        }

        // Standard WordPress "Silence is golden"
        if (stripos($content, 'silence is golden') !== false) {
            return true;
        }

        $trimmed = trim($content);
        // Just empty PHP open/close tags
        if ($trimmed === '<?php' || $trimmed === '<?php ?>' || $trimmed === '<?php ?>\n') {
            return true;
        }

        // Exit / Die / 403 Forbidden header
        if (preg_match('/^<\?php\s*(?:\/\/[^\r\n]*|\/\*.*?\*\/)?\s*(?:exit;?|die\s*\([^)]*\);?|header\s*\([^)]*\);?\s*exit;?)\s*(?:\?>)?\s*$/is', $trimmed)) {
            return true;
        }

        return false;
    }
}
