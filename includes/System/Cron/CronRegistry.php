<?php
namespace WebCareProScanner\System\Cron;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Canonical catalog and recurrence metadata for all WebCare Pro Security & Firewall
 * WP-Cron hooks and background continuation workers.
 */
class CronRegistry {

    /**
     * All custom recurrence intervals registered by WebCare Pro.
     *
     * @return array<string, array{interval: int, display: string}>
     */
    public static function get_custom_intervals(): array {
        return [
            'weekly' => [
                'interval' => 7 * DAY_IN_SECONDS,
                'display'  => __('Once Weekly', 'webcare-pro-security'),
            ],
            'webcare_every_five_minutes' => [
                'interval' => 300,
                'display'  => __('Every 5 Minutes (WebCare Pro Security)', 'webcare-pro-security'),
            ],
            'webcare_15min' => [
                'interval' => 900,
                'display'  => __('Every 15 Minutes (WebCare Pro Security)', 'webcare-pro-security'),
            ],
            'webcare_30min' => [
                'interval' => 1800,
                'display'  => __('Every 30 Minutes (WebCare Pro Security)', 'webcare-pro-security'),
            ],
        ];
    }

    /**
     * Recurrence options exposed to the UI schedule selector.
     *
     * @return array<string, array{label: string, interval: int}>
     */
    public static function get_recurrence_catalog(): array {
        return [
            'webcare_every_five_minutes' => [
                'label'    => __('Every 5 Minutes', 'webcare-pro-security'),
                'interval' => 300,
            ],
            'webcare_15min' => [
                'label'    => __('Every 15 Minutes', 'webcare-pro-security'),
                'interval' => 900,
            ],
            'webcare_30min' => [
                'label'    => __('Every 30 Minutes', 'webcare-pro-security'),
                'interval' => 1800,
            ],
            'hourly' => [
                'label'    => __('Every Hour', 'webcare-pro-security'),
                'interval' => HOUR_IN_SECONDS,
            ],
            'twicedaily' => [
                'label'    => __('Twice Daily (12h)', 'webcare-pro-security'),
                'interval' => 12 * HOUR_IN_SECONDS,
            ],
            'daily' => [
                'label'    => __('Once Daily', 'webcare-pro-security'),
                'interval' => DAY_IN_SECONDS,
            ],
            'weekly' => [
                'label'    => __('Once Weekly', 'webcare-pro-security'),
                'interval' => WEEK_IN_SECONDS,
            ],
        ];
    }

    /**
     * Category metadata for grouping tasks in the Control Center.
     *
     * @return array<string, string>
     */
    public static function get_categories(): array {
        return [
            'scanning'                  => __('Scanning & AST', 'webcare-pro-security'),
            'firewall_edge'             => __('Firewall & Cloudflare Edge', 'webcare-pro-security'),
            'integrity_quarantine'      => __('Integrity & Watchdogs', 'webcare-pro-security'),
            'notifications_maintenance' => __('Reports & Maintenance', 'webcare-pro-security'),
            'background_workers'        => __('Background Workers & Safeguards', 'webcare-pro-security'),
        ];
    }

    /**
     * Master registry of all 15 plugin cron hooks & background workers.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_tasks(): array {
        $tasks = [
            'webcareproscan_scheduled_scan_event' => [
                'id'                  => 'scheduled_scan',
                'hook'                => 'webcareproscan_scheduled_scan_event',
                'title'               => __('Automated Malware & Integrity Scan', 'webcare-pro-security'),
                'description'         => __('Executes the configured full, plugin/theme, core integrity, or upload malware audit on schedule.', 'webcare-pro-security'),
                'category'            => 'scanning',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'schedule_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Settings -> Schedule & Automation', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-settings&tab=schedule',
                'default_delay'       => 0,
            ],
            'webcareproscan_modular_ast_step' => [
                'id'                  => 'modular_ast_worker',
                'hook'                => 'webcareproscan_modular_ast_step',
                'title'               => __('Modular WAF AST Scan Continuation', 'webcare-pro-security'),
                'description'         => __('Resumes and finishes in-progress Modular WAF PHP AST scans via WP-Cron if the browser tab is closed.', 'webcare-pro-security'),
                'category'            => 'scanning',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'cron_modular_ast_bg_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Modular WAF -> Live AST Telemetry', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-modular-waf',
                'default_delay'       => 15,
            ],
            'webcareproscan_threat_intel_cron_sync' => [
                'id'                  => 'threat_intel_sync',
                'hook'                => 'webcareproscan_threat_intel_cron_sync',
                'title'               => __('Threat Intelligence & CVE Feed Sync', 'webcare-pro-security'),
                'description'         => __('Refreshes community malicious IP blocklists and known WordPress CVE advisories.', 'webcare-pro-security'),
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'twicedaily',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'threat_intel_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Firewall -> Threat Intelligence', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-firewall',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_redirect_canary_event' => [
                'id'                  => 'redirect_canary_watchdog',
                'hook'                => 'webcareproscan_redirect_canary_event',
                'title'               => __('Redirect Canary & Cloaking Watchdog', 'webcare-pro-security'),
                'description'         => __('Runs synthetic search-bot, mobile, AI crawler, and DB URL probes to detect and auto-heal hidden redirects.', 'webcare-pro-security'),
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'webcare_15min',
                'allowed_recurrences' => ['webcare_15min', 'webcare_30min', 'hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'cron_redirect_canary_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Firewall -> Redirect Shield', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-firewall',
                'default_delay'       => 60,
            ],
            'webcareproscan_modular_autopilot_cron' => [
                'id'                  => 'modular_autopilot_promo',
                'hook'                => 'webcareproscan_modular_autopilot_cron',
                'title'               => __('Modular WAF 48h Auto-Pilot Promotion', 'webcare-pro-security'),
                'description'         => __('Evaluates monitored Modular WAF rules after the 48-hour false-positive soak period for safe promotion.', 'webcare-pro-security'),
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'hourly',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'cron_modular_autopilot_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Modular WAF -> Smart Auto-Pilot', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-modular-waf',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcare_cloudflare_ip_sync_cron' => [
                'id'                  => 'cloudflare_ip_sync',
                'hook'                => 'webcare_cloudflare_ip_sync_cron',
                'title'               => __('Cloudflare Edge IP Ban Queue Sync', 'webcare-pro-security'),
                'description'         => __('Flushes queued origin WAF attacker IPs to your Cloudflare IP Access Rules & Edge lists.', 'webcare-pro-security'),
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'webcare_every_five_minutes',
                'allowed_recurrences' => ['webcare_every_five_minutes', 'webcare_15min', 'webcare_30min', 'hourly'],
                'can_disable'         => true,
                'setting_key'         => 'cloudflare_auto_sync_bans',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Settings -> Cloudflare Edge', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-settings&tab=cloudflare',
                'default_delay'       => 300,
            ],
            'webcare_cf_auto_sync_edge_cron' => [
                'id'                  => 'cloudflare_edge_auto_sync',
                'hook'                => 'webcare_cf_auto_sync_edge_cron',
                'title'               => __('Cloudflare Edge Rule Auto-Deploy Worker', 'webcare-pro-security'),
                'description'         => __('Automatically deploys optimized Cloudflare Edge WAF slot rules 5 seconds after stack or settings updates.', 'webcare-pro-security'),
                'category'            => 'firewall_edge',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'webcare_cf_auto_sync_edge',
                'setting_type'        => 'wp_option',
                'setting_location'    => __('Firewall -> Context-Adaptive (CAF)', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-caf',
                'default_delay'       => 5,
            ],
            'webcareproscan_self_defense_watchdog_event' => [
                'id'                  => 'self_defense_watchdog',
                'hook'                => 'webcareproscan_self_defense_watchdog_event',
                'title'               => __('Plugin Self-Defense Integrity Watchdog', 'webcare-pro-security'),
                'description'         => __('Verifies SHA-256 checksums across WebCare Pro files to detect host deletions or malicious tampering.', 'webcare-pro-security'),
                'category'            => 'integrity_quarantine',
                'kind'                => 'recurring',
                'default_recurrence'  => 'twicedaily',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'self_defense_watchdog_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Forensics -> Plugin Self-Defense', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-forensics&tab=self_defense',
                'default_delay'       => 300,
            ],
            'webcareproscan_reinfection_hourly_check' => [
                'id'                  => 'reinfection_watchdog',
                'hook'                => 'webcareproscan_reinfection_hourly_check',
                'title'               => __('72-Hour Post-Remediation Watchdog', 'webcare-pro-security'),
                'description'         => __('Inspects recently quarantined or cleaned file paths to intercept malware resurrection loops.', 'webcare-pro-security'),
                'category'            => 'integrity_quarantine',
                'kind'                => 'recurring',
                'default_recurrence'  => 'hourly',
                'allowed_recurrences' => ['webcare_15min', 'webcare_30min', 'hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'cron_reinfection_watchdog_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Forensics -> 72h Watchdog', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-forensics&tab=watchdog',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_domain_reputation_daily_check' => [
                'id'                  => 'domain_reputation_check',
                'hook'                => 'webcareproscan_domain_reputation_daily_check',
                'title'               => __('Domain Reputation, SSL & DNSBL Audit', 'webcare-pro-security'),
                'description'         => __('Checks SSL expiration, SPF/DMARC records, and major DNSBL blacklists for site reputation health.', 'webcare-pro-security'),
                'category'            => 'integrity_quarantine',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'cron_domain_reputation_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Forensics -> Domain Reputation', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-forensics&tab=watchdog&subtab=reputation',
                'default_delay'       => DAY_IN_SECONDS,
            ],
            'webcareproscan_waf_log_retention_prune' => [
                'id'                  => 'waf_log_retention_prune',
                'hook'                => 'webcareproscan_waf_log_retention_prune',
                'title'               => __('WAF Incident Log Retention Pruner', 'webcare-pro-security'),
                'description'         => __('Deletes daily WAF JSON log shards older than the configured retention period.', 'webcare-pro-security'),
                'category'            => 'notifications_maintenance',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'cron_waf_log_prune_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('WAF Logs -> Retention Policy', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-waf-logs',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_weekly_digest_event' => [
                'id'                  => 'weekly_digest_report',
                'hook'                => 'webcareproscan_weekly_digest_event',
                'title'               => __('Weekly Security Digest Report', 'webcare-pro-security'),
                'description'         => __('Compiles and dispatches Monday morning peace-of-mind email and webhook security summaries.', 'webcare-pro-security'),
                'category'            => 'notifications_maintenance',
                'kind'                => 'recurring',
                'default_recurrence'  => 'weekly',
                'allowed_recurrences' => ['daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'email_digest_enabled',
                'setting_type'        => 'settings_digest',
                'setting_location'    => __('Notifications -> Weekly Digest', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-notifications',
                'default_delay'       => 0,
            ],
            'webcareproscan_backup_step_worker' => [
                'id'                  => 'database_backup_worker',
                'hook'                => 'webcareproscan_backup_step_worker',
                'title'               => __('Database Backup Vault Step Worker', 'webcare-pro-security'),
                'description'         => __('Streams active Database Backup Vault table exports sequentially in background WP-Cron ticks.', 'webcare-pro-security'),
                'category'            => 'background_workers',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'cron_backup_bg_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => __('Vault -> Database Backup', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-backup',
                'default_delay'       => 1,
            ],
            'webcareproscan_auto_rearm_waf' => [
                'id'                  => 'waf_rescue_auto_rearm',
                'hook'                => 'webcareproscan_auto_rearm_waf',
                'title'               => __('WAF Rescue Mode Auto Re-Arm Timer', 'webcare-pro-security'),
                'description'         => __('Automatically restores strict WAF blocking 15 minutes after Rescue Assistant Monitor-Only test mode starts.', 'webcare-pro-security'),
                'category'            => 'background_workers',
                'kind'                => 'security_safeguard',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => false,
                'setting_key'         => null,
                'setting_location'    => __('Rescue Assistant -> 15m Test Pause', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-firewall',
                'default_delay'       => 900,
            ],
            'webcareproscan_ephemeral_admin_expire' => [
                'id'                  => 'ephemeral_admin_expire',
                'hook'                => 'webcareproscan_ephemeral_admin_expire',
                'title'               => __('JIT Temporary Admin Auto-Demotion', 'webcare-pro-security'),
                'description'         => __('Enforces time-boxed privilege revocation so temporary administrator grants automatically revert to baseline roles.', 'webcare-pro-security'),
                'category'            => 'background_workers',
                'kind'                => 'security_safeguard',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => false,
                'setting_key'         => null,
                'setting_location'    => __('Identity & Access -> JIT Elevation', 'webcare-pro-security'),
                'deep_link'           => 'admin.php?page=webcare-pro-auth',
                'default_delay'       => 0,
            ],
        ];

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            $mod_tasks = \WebCareProScanner\Core\ModuleRegistry::get_cron_tasks();
            if (!empty($mod_tasks)) {
                $tasks = array_merge($tasks, $mod_tasks);
            }
        }

        return $tasks;
    }

    /**
     * Get metadata definition for a single hook name.
     *
     * @param string $hook
     * @return array<string, mixed>|null
     */
    public static function get_task(string $hook): ?array {
        $tasks = self::get_tasks();
        return $tasks[$hook] ?? null;
    }

    /**
     * All plugin hook names including historical aliases to ensure clean deactivation & uninstall cleanup.
     *
     * @return string[]
     */
    public static function get_all_hook_names(): array {
        return array_values(
            array_unique(
                array_merge(
                    array_keys(self::get_tasks()),
                    ['webcareproscan_scheduled_scan_cron']
                )
            )
        );
    }
}
