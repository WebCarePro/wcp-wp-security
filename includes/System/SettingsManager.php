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

            // 6. Developer & Admin Security Tweaks
            'disable_file_editing'     => false,
            'hide_wp_version'          => false,
            'block_sensitive_files'    => false, // .env, .git, etc.

            // 7. Cleanup & Data Privacy on Plugin Uninstall (Enabled by default)
            'delete_data_on_uninstall' => true,
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
        $merged['has_openai_key'] = !empty($merged['openai_api_key']);
        $merged['has_gemini_key'] = !empty($merged['gemini_api_key']);
        $merged['has_claude_key'] = !empty($merged['claude_api_key']);

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

        // 6. Security Tweaks
        $clean['disable_file_editing']  = !empty($input['disable_file_editing']);
        $clean['hide_wp_version']       = !empty($input['hide_wp_version']);
        $clean['block_sensitive_files'] = !empty($input['block_sensitive_files']);

        // 7. Cleanup & Data Privacy on Plugin Uninstall
        $clean['delete_data_on_uninstall'] = isset($input['delete_data_on_uninstall']) ? !empty($input['delete_data_on_uninstall']) : true;

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
}
