<?php
namespace WcpScanner\Notifications;

use WcpScanner\System\SettingsManager;
use WcpScanner\Notifications\WebhookService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * NotificationDispatcher
 *
 * Centralized, multi-channel security notification engine.
 * Dispatches granular security events to Email (wp_mail) and DevSecOps Webhooks
 * (Slack, Discord, ClickUp, Asana, Custom JSON) based on developer configuration.
 */
class NotificationDispatcher {

    /**
     * Map of event definitions with human-readable titles, descriptions, categories, and default severities.
     */
    public static function get_event_catalog(): array {
        return [
            // Category: Scans
            'scan_scheduled_complete' => [
                'category'    => 'scans',
                'category_label' => __('Core Scans & Threats', 'wcp-security-scanner'),
                'title'       => __('Scheduled Scan Complete', 'wcp-security-scanner'),
                'description' => __('Fires when an automated background cron scan finishes auditing the site.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'scan_manual_complete' => [
                'category'    => 'scans',
                'category_label' => __('Core Scans & Threats', 'wcp-security-scanner'),
                'title'       => __('Manual Scan Complete', 'wcp-security-scanner'),
                'description' => __('Fires when an on-demand scan manually started from the dashboard finishes.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'scan_targeted_complete' => [
                'category'    => 'scans',
                'category_label' => __('Core Scans & Threats', 'wcp-security-scanner'),
                'title'       => __('Targeted Scan Complete', 'wcp-security-scanner'),
                'description' => __('Fires when an audit targeting a specific directory, theme, or file list concludes.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'scan_threats_found' => [
                'category'    => 'scans',
                'category_label' => __('Core Scans & Threats', 'wcp-security-scanner'),
                'title'       => __('Critical / High Threats Detected', 'wcp-security-scanner'),
                'description' => __('Dispatches immediately when severe vulnerabilities, backdoors, or malicious webshells are discovered.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'scan_auto_quarantine' => [
                'category'    => 'scans',
                'category_label' => __('Core Scans & Threats', 'wcp-security-scanner'),
                'title'       => __('Auto-Quarantined Malicious Threat', 'wcp-security-scanner'),
                'description' => __('Fires when an active exploit or malicious payload is safely neutralized into the WCP Vault.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'scan_aborted_timeout' => [
                'category'    => 'scans',
                'category_label' => __('Core Scans & Threats', 'wcp-security-scanner'),
                'title'       => __('Scan Aborted / Execution Timeout', 'wcp-security-scanner'),
                'description' => __('Alerts when a running security scan stalls, aborts due to PHP memory limits, or times out.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],

            // Category: Self Defense
            'plugin_file_tampered' => [
                'category'    => 'self_defense',
                'category_label' => __('Plugin Self-Defense', 'wcp-security-scanner'),
                'title'       => __('Plugin File Tampering / Hash Mismatch', 'wcp-security-scanner'),
                'description' => __('Fires if any core file of WCP Security Scanner has been modified or injected with rogue code.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'plugin_file_missing' => [
                'category'    => 'self_defense',
                'category_label' => __('Plugin Self-Defense', 'wcp-security-scanner'),
                'title'       => __('Plugin File Missing / Deleted', 'wcp-security-scanner'),
                'description' => __('Fires if a required plugin file was deleted by host scanners, mod_security, or an intruder.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'plugin_deactivate_attempt' => [
                'category'    => 'self_defense',
                'category_label' => __('Plugin Self-Defense', 'wcp-security-scanner'),
                'title'       => __('Unauthorized Plugin Deactivation', 'wcp-security-scanner'),
                'description' => __('Alerts when an administrator or external script attempts to deactivate WCP Security Scanner.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'plugin_uninstall' => [
                'category'    => 'self_defense',
                'category_label' => __('Plugin Self-Defense', 'wcp-security-scanner'),
                'title'       => __('Plugin Uninstallation Event', 'wcp-security-scanner'),
                'description' => __('Fires when WCP Security Scanner is deleted from WordPress plugins manager.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],

            // Category: Cloudflare & WAF
            'cf_firewall_updated' => [
                'category'    => 'cloudflare_waf',
                'category_label' => __('Cloudflare & WAF Defense', 'wcp-security-scanner'),
                'title'       => __('Cloudflare Firewall Rule Deployed/Updated', 'wcp-security-scanner'),
                'description' => __('Notifies when an edge firewall rule, IP block, or rate limit is synchronized with Cloudflare.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'cf_firewall_rule_deleted' => [
                'category'    => 'cloudflare_waf',
                'category_label' => __('Cloudflare & WAF Defense', 'wcp-security-scanner'),
                'title'       => __('Cloudflare Firewall Rule Removed', 'wcp-security-scanner'),
                'description' => __('Alerts when an active edge security rule or IP ban is removed from Cloudflare.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],
            'waf_block_surge' => [
                'category'    => 'cloudflare_waf',
                'category_label' => __('Cloudflare & WAF Defense', 'wcp-security-scanner'),
                'title'       => __('WAF Block Surge / Attack Spike', 'wcp-security-scanner'),
                'description' => __('Dispatches when WAF Lite intercepts an abnormal surge of blocked malicious HTTP requests.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'waf_virtual_patch_hit' => [
                'category'    => 'cloudflare_waf',
                'category_label' => __('Cloudflare & WAF Defense', 'wcp-security-scanner'),
                'title'       => __('Virtual Patch Exploit Intercepted', 'wcp-security-scanner'),
                'description' => __('Fires when an unpatched plugin or zero-day vulnerability payload is blocked by virtual patching.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'waf_server_rules_updated' => [
                'category'    => 'cloudflare_waf',
                'category_label' => __('Cloudflare & WAF Defense', 'wcp-security-scanner'),
                'title'       => __('Server Security Rules Updated (.htaccess/Nginx)', 'wcp-security-scanner'),
                'description' => __('Notifies when hardening directives are appended or updated in web server configuration files.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],

            // Category: Authentication & 2FA
            'auth_2fa_enabled' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Two-Factor Authentication (2FA) Activated', 'wcp-security-scanner'),
                'description' => __('Notifies when an administrator or user sets up TOTP multi-factor authentication.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'auth_2fa_disabled' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('2FA Deactivated / Emergency Code Used', 'wcp-security-scanner'),
                'description' => __('Fires when 2FA is removed from an administrator profile or an emergency recovery code is spent.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'auth_admin_password_reset' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Admin Password Changed / Reset', 'wcp-security-scanner'),
                'description' => __('Alerts when an administrator password is changed or a recovery email link is requested.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'auth_bruteforce_lockout' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Brute-Force Lockout Triggered', 'wcp-security-scanner'),
                'description' => __('Dispatches when an offensive IP address exceeds maximum login failures and is locked out.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'auth_cf_edge_ban_synced' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Cloudflare Edge IP Ban Synchronized', 'wcp-security-scanner'),
                'description' => __('Notifies when a locked-out brute-force IP is escalated to Cloudflare edge WAF ruleset.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'auth_session_hijack_flag' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Session IP Shift / Potential Hijack', 'wcp-security-scanner'),
                'description' => __('Alerts when an active logged-in admin session abruptly changes IP address or user-agent fingerprint.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'auth_rogue_admin_created' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Unauthorized / Rogue Admin User Created', 'wcp-security-scanner'),
                'description' => __('Fires immediately if a new administrator or super-admin account is registered.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],

            // Category: File Integrity Monitoring (FIM)
            'fim_core_file_modified' => [
                'category'    => 'fim',
                'category_label' => __('File Integrity Monitoring (FIM)', 'wcp-security-scanner'),
                'title'       => __('WordPress Core File Modified', 'wcp-security-scanner'),
                'description' => __('Alerts when an official WordPress core system file checksum differs from the official release.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'fim_plugin_theme_modified' => [
                'category'    => 'fim',
                'category_label' => __('File Integrity Monitoring (FIM)', 'wcp-security-scanner'),
                'title'       => __('Plugin or Theme File Modified', 'wcp-security-scanner'),
                'description' => __('Fires when changes are detected in an official WordPress.org plugin or active theme folder.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'fim_suspicious_php_found' => [
                'category'    => 'fim',
                'category_label' => __('File Integrity Monitoring (FIM)', 'wcp-security-scanner'),
                'title'       => __('Rogue PHP Script Discovered in Uploads', 'wcp-security-scanner'),
                'description' => __('Critical alert when an executable PHP/PHTML script is discovered inside media or cache directories.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'fim_auto_cure_applied' => [
                'category'    => 'fim',
                'category_label' => __('File Integrity Monitoring (FIM)', 'wcp-security-scanner'),
                'title'       => __('Auto-Cure Restored Pristine File', 'wcp-security-scanner'),
                'description' => __('Notifies when FIM Auto-Cure automatically repairs an altered core or plugin file from pristine source.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'fim_baseline_refreshed' => [
                'category'    => 'fim',
                'category_label' => __('File Integrity Monitoring (FIM)', 'wcp-security-scanner'),
                'title'       => __('FIM Baseline Snapshot Refreshed', 'wcp-security-scanner'),
                'description' => __('Fires when the file integrity baseline checksum database is newly generated or recalculated.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],

            // Category: Vulnerabilities (CVE)
            'vuln_core_cve_detected' => [
                'category'    => 'vulnerabilities',
                'category_label' => __('Vulnerabilities & CVE Feeds', 'wcp-security-scanner'),
                'title'       => __('WordPress Core Known CVE Found', 'wcp-security-scanner'),
                'description' => __('Critical warning when the installed WordPress version is affected by an unpatched CVE advisory.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'vuln_plugin_theme_cve' => [
                'category'    => 'vulnerabilities',
                'category_label' => __('Vulnerabilities & CVE Feeds', 'wcp-security-scanner'),
                'title'       => __('Plugin / Theme Vulnerability Advisory Flagged', 'wcp-security-scanner'),
                'description' => __('Dispatches when an installed plugin or theme has a known security bulletin or exploit published.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'vuln_abandoned_extension' => [
                'category'    => 'vulnerabilities',
                'category_label' => __('Vulnerabilities & CVE Feeds', 'wcp-security-scanner'),
                'title'       => __('Abandoned or Closed Plugin Detected', 'wcp-security-scanner'),
                'description' => __('Notifies when a plugin is removed from the WordPress.org repository due to security issues or neglect.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],
            'vuln_feed_synced' => [
                'category'    => 'vulnerabilities',
                'category_label' => __('Vulnerabilities & CVE Feeds', 'wcp-security-scanner'),
                'title'       => __('Threat Intelligence Feed Synchronized', 'wcp-security-scanner'),
                'description' => __('Fires when local vulnerability definitions and community IP blacklists update successfully.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],

            // Category: Backups & Vault
            'backup_db_completed' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Database Backup Completed', 'wcp-security-scanner'),
                'description' => __('Notifies when a full compressed database backup archive is created successfully.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'backup_db_failed' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Database Backup Failed / Aborted', 'wcp-security-scanner'),
                'description' => __('Urgent alert when database backup export fails due to disk space or database permissions.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'backup_db_restored' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Database Restored From Backup', 'wcp-security-scanner'),
                'description' => __('Critical notification when a database restore operation is executed from an archive.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'vault_quarantine_restored' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Quarantined File Restored to Filesystem', 'wcp-security-scanner'),
                'description' => __('Alerts when a file previously placed in security quarantine is restored back to active disk.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],
            'vault_quarantine_deleted' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Quarantined File Permanently Purged', 'wcp-security-scanner'),
                'description' => __('Fires when malicious files in quarantine storage are permanently erased from disk.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],

            // Category: DevSecOps & AI
            'webhook_status_toggled' => [
                'category'    => 'devsecops_ai',
                'category_label' => __('DevSecOps & AI Forensics', 'wcp-security-scanner'),
                'title'       => __('Webhook Channel Enabled / Disabled', 'wcp-security-scanner'),
                'description' => __('Notifies when Slack, Discord, ClickUp, Asana, or custom webhooks are turned on or off.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'webhook_delivery_failed' => [
                'category'    => 'devsecops_ai',
                'category_label' => __('DevSecOps & AI Forensics', 'wcp-security-scanner'),
                'title'       => __('Webhook HTTP Delivery Error', 'wcp-security-scanner'),
                'description' => __('Alerts via email when a security webhook fails to deliver after multiple HTTP retries.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],
            'ai_forensics_toggled' => [
                'category'    => 'devsecops_ai',
                'category_label' => __('DevSecOps & AI Forensics', 'wcp-security-scanner'),
                'title'       => __('AI Code Forensics Engine Toggled', 'wcp-security-scanner'),
                'description' => __('Notifies when Gemini / OpenAI / Claude deep forensic analysis is enabled or disabled.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'mcp_service_toggled' => [
                'category'    => 'devsecops_ai',
                'category_label' => __('DevSecOps & AI Forensics', 'wcp-security-scanner'),
                'title'       => __('MCP AI Agent Service Surface Toggled', 'wcp-security-scanner'),
                'description' => __('Fires when Model Context Protocol agent API access is toggled on or off.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
        ];
    }

    /**
     * Detect client browser device type (Desktop, Mobile, Tablet)
     */
    public static function detect_device_type(): string {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower((string)$_SERVER['HTTP_USER_AGENT']) : '';
        if (empty($ua)) {
            return 'Unknown Device';
        }
        if (strpos($ua, 'ipad') !== false || strpos($ua, 'tablet') !== false || strpos($ua, 'playbook') !== false) {
            return 'Tablet';
        }
        if (strpos($ua, 'mobile') !== false || strpos($ua, 'iphone') !== false || strpos($ua, 'android') !== false || strpos($ua, 'blackberry') !== false) {
            return 'Mobile';
        }
        return 'Desktop';
    }

    /**
     * Detect real client IP address respecting Cloudflare, proxy headers, and direct remote address
     */
    public static function get_real_client_ip(): string {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR'
        ];
        foreach ($headers as $h) {
            if (!empty($_SERVER[$h])) {
                $ips = explode(',', (string)$_SERVER[$h]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '127.0.0.1';
    }

    /**
     * Trigger a granular security event notification
     *
     * @param string $event_key
     * @param array $payload Key-value context (e.g. ['title' => '...', 'message' => '...', 'details' => ...])
     * @return array Results per channel ['email' => bool|null, 'webhook' => bool|null]
     */
    public static function trigger(string $event_key, array $payload = []): array {
        $settings = SettingsManager::get_settings();

        // 1. Check global master switch
        if (empty($settings['notification_master_enabled'])) {
            return ['skipped' => 'master_disabled', 'email' => null, 'webhook' => null];
        }

        $events_config = $settings['notification_events'] ?? [];
        $event_cfg = $events_config[$event_key] ?? null;

        // Fallback to default catalog if missing
        if ($event_cfg === null) {
            $defaults = SettingsManager::get_default_notification_events();
            $event_cfg = $defaults[$event_key] ?? ['email' => false, 'webhook' => false];
        }

        $catalog = self::get_event_catalog();
        $meta = $catalog[$event_key] ?? [
            'title'       => ucwords(str_replace('_', ' ', $event_key)),
            'description' => '',
            'severity'    => 'info',
        ];

        // Contextual user & execution intelligence
        $is_cli = (php_sapi_name() === 'cli') || defined('WP_CLI');
        $is_cron = defined('DOING_CRON') && DOING_CRON;
        $is_system = $is_cli || $is_cron;

        $current_user = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
        $admin_username = ($current_user && $current_user->exists()) ? $current_user->user_login : null;
        $client_ip = self::get_real_client_ip();
        $device_type = self::detect_device_type();
        $gmt_time = gmdate('Y-m-d H:i:s') . ' GMT';

        // Prepare standard developer-friendly details
        $enhanced_details = [];

        // Check if explicitly passed or extract
        $incoming_details = $payload['details'] ?? [];

        // 1. Triggered By (with Real Client IP)
        if (!empty($admin_username)) {
            $enhanced_details['Triggered By'] = sprintf('%s (%s)', $admin_username, $client_ip);
            // Mention device/browser only if triggered by an authenticated admin user (not system auto generated)
            $enhanced_details['User Browser Type'] = $device_type;
        } elseif (!empty($incoming_details['triggered_by'])) {
            $user_str = (string)$incoming_details['triggered_by'];
            if (strpos($user_str, '(') === false) {
                $enhanced_details['Triggered By'] = sprintf('%s (%s)', $user_str, $client_ip);
            } else {
                $enhanced_details['Triggered By'] = $user_str;
            }
            if (!$is_system) {
                $enhanced_details['User Browser Type'] = $device_type;
            }
        } elseif ($is_cron) {
            $enhanced_details['Triggered By'] = 'Automated WP-Cron Scheduler (Server)';
        } elseif ($is_cli) {
            $enhanced_details['Triggered By'] = 'WP-CLI / Server Process';
        } else {
            $enhanced_details['Triggered By'] = sprintf('Visitor / External Request (%s)', $client_ip);
        }

        // 2. Event Code
        $enhanced_details['Event Code'] = $event_key;

        // 3. Test Mode / Additional Details
        if (isset($incoming_details['test_mode'])) {
            $enhanced_details['Test Mode'] = $incoming_details['test_mode'];
        }

        // Merge any other diagnostic fields passed by caller
        foreach ($incoming_details as $dk => $dv) {
            $normalized_key = ucwords(str_replace('_', ' ', $dk));
            if (!in_array($dk, ['triggered_by', 'event_code', 'test_mode', 'date', 'date_gmt', 'Date', 'Event Code', 'Triggered By', 'Test Mode', 'User Browser Type'], true)) {
                $enhanced_details[$normalized_key] = $dv;
            }
        }

        // 4. Date in GMT
        $enhanced_details['Date'] = $gmt_time;

        // Merge payload defaults
        $full_payload = array_merge([
            'event_key'   => $event_key,
            'title'       => $meta['title'],
            'message'     => $payload['message'] ?? $meta['description'],
            'severity'    => $payload['severity'] ?? $meta['severity'],
            'timestamp'   => time(),
            'datetime'    => $gmt_time,
            'site_name'   => wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) ?: 'WordPress',
            'site_url'    => get_site_url(),
            'dashboard_url' => admin_url('admin.php?page=wcp-security-scanner'),
            'notifications_url' => admin_url('admin.php?page=wcp-scanner-notifications'),
        ], $payload);

        $full_payload['details'] = $enhanced_details;

        $results = [
            'email'   => null,
            'webhook' => null,
        ];

        // 2. Dispatch Email Channel
        if (!empty($event_cfg['email'])) {
            $results['email'] = self::dispatch_email($full_payload);
        }

        // 3. Dispatch Webhook Channel
        if (!empty($event_cfg['webhook'])) {
            $results['webhook'] = self::dispatch_webhooks($full_payload);
        }

        return $results;
    }

    /**
     * Dispatch structured HTML email alert
     */
    private static function dispatch_email(array $payload): bool {
        $settings = SettingsManager::get_settings();
        $to = !empty($settings['alert_emails']) ? $settings['alert_emails'] : get_option('admin_email');
        if (empty($to)) {
            return false;
        }

        $site_name = $payload['site_name'];
        $severity  = strtoupper($payload['severity']);
        $title     = $payload['title'];
        $message   = $payload['message'];
        $time      = $payload['datetime'];
        $site_url  = $payload['site_url'];
        $dash_url  = $payload['dashboard_url'];
        $notif_url = !empty($payload['notifications_url']) ? $payload['notifications_url'] : admin_url('admin.php?page=wcp-scanner-notifications');

        $subject = sprintf('[%s Alert: %s] %s', $site_name, $severity, $title);

        $severity_color = '#0284c7';
        if ($severity === 'CRITICAL') {
            $severity_color = '#dc2626';
        } elseif ($severity === 'HIGH') {
            $severity_color = '#ea580c';
        } elseif ($severity === 'WARNING') {
            $severity_color = '#d97706';
        }

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'From: WCP Security Scanner <' . get_option('admin_email') . '>',
        ];

        // Logo URL as requested: siteurl.tld/wp-content/plugins/wcp-security-scanner/assets/logo.png
        $logo_url = defined('WCPSCAN_URL') ? WCPSCAN_URL . 'assets/logo.png' : plugins_url('assets/logo.png', dirname(__DIR__));

        $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head><body style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #0f172a; background-color: #f1f5f9; margin: 0; padding: 28px 12px;">';
        $html .= '<div style="max-width: 620px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.08);">';
        
        // Header matching screenshot: Dark Obsidian background (#0b1120 / #0f172a), subtle top blue highlight, pill badge with shield icon, large brand logo, title & subtitle
        $html .= '<div style="background: #0b1120; padding: 36px 32px 30px 32px; text-align: center; border-top: 4px solid #3b82f6; border-bottom: 3px solid ' . esc_attr($severity_color) . ';">';
        
        // Protocol / Priority pill badge matching screenshot (semi-transparent dark pill with cyan border/glow)
        $html .= '<div style="display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; background: rgba(59, 130, 246, 0.12); color: #60a5fa; border: 1px solid rgba(96, 165, 250, 0.3); margin-bottom: 20px;">';
        $html .= '🛡️ ' . esc_html($severity) . ' PRIORITY ALERT';
        $html .= '</div>';

        // Logo placement
        $html .= '<div style="margin-bottom: 14px;">';
        $html .= '<img src="' . esc_url($logo_url) . '" alt="WebCare Pro Logo" style="max-height: 48px; width: auto; display: inline-block;" onerror="this.style.display=\'none\';">';
        $html .= '</div>';

        // Subtitle banner under brand
        $html .= '<div style="color: #94a3b8; font-size: 13.5px; font-weight: 500; margin-bottom: 18px; letter-spacing: 0.3px;">';
        $html .= 'High-Performance WordPress Security & Autonomous Defense';
        $html .= '</div>';

        // Event Title Card
        $html .= '<div style="background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 12px 18px; margin-top: 8px;">';
        $html .= '<h1 style="color: #ffffff; font-size: 18px; margin: 0; font-weight: 700; line-height: 1.4;">' . esc_html($title) . '</h1>';
        $html .= '<p style="color: #64748b; font-size: 12.5px; margin: 6px 0 0 0;">Site: <strong style="color: #cbd5e1;">' . esc_html($site_name) . '</strong> (<a href="' . esc_url($site_url) . '" style="color: #38bdf8; text-decoration: none;">' . esc_html($site_url) . '</a>)</p>';
        $html .= '</div>';

        $html .= '</div>';

        // Body Content
        $html .= '<div style="padding: 32px 32px 28px 32px; background: #ffffff;">';
        $html .= '<p style="font-size: 15px; color: #334155; margin-top: 0; line-height: 1.6;">' . nl2br(esc_html($message)) . '</p>';

        if (!empty($payload['details']) && is_array($payload['details'])) {
            $html .= '<div style="background: #f8fafc; border-radius: 10px; padding: 18px; margin: 24px 0; border: 1px solid #e2e8f0; border-left: 4px solid ' . esc_attr($severity_color) . ';">';
            $html .= '<div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #475569; margin-bottom: 10px;">Event Diagnostic Details:</div>';
            $html .= '<table style="width: 100%; font-size: 13px; color: #0f172a; border-collapse: collapse;">';
            foreach ($payload['details'] as $k => $v) {
                $val = is_scalar($v) ? (string)$v : wp_json_encode($v);
                $html .= '<tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 7px 10px 7px 0; font-weight: 600; width: 150px; color: #64748b;">' . esc_html(ucwords(str_replace('_', ' ', (string)$k))) . ':</td><td style="padding: 7px 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: #0f172a; word-break: break-all;">' . esc_html((string)$val) . '</td></tr>';
            }
            $html .= '</table></div>';
        }

        // Action CTA Button
        $html .= '<div style="margin: 32px 0 16px 0; text-align: center;">';
        $html .= '<a href="' . esc_url($dash_url) . '" style="display: inline-block; background: #4f46e5; color: #ffffff; font-size: 14px; font-weight: 700; text-decoration: none; padding: 13px 30px; border-radius: 8px; box-shadow: 0 4px 14px rgba(79, 70, 229, 0.35);">';
        $html .= 'Open WCP Security Dashboard &rarr;';
        $html .= '</a>';
        $html .= '</div>';

        $html .= '</div>';

        // About Us & Company Footer
        $html .= '<div style="background: #0f172a; padding: 28px 32px; border-top: 1px solid #1e293b; color: #94a3b8; font-size: 12.5px; line-height: 1.6;">';
        $html .= '<div style="display: flex; align-items: center; margin-bottom: 12px;">';
        $html .= '<strong style="color: #ffffff; font-size: 14px; letter-spacing: 0.2px;">About WebCare Pro</strong>';
        $html .= '<span style="color: #475569; margin: 0 8px;">•</span>';
        $html .= '<a href="https://webcarespro.com" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: 600;">https://webcarespro.com</a>';
        $html .= '</div>';
        $html .= '<p style="margin: 0 0 16px 0; color: #cbd5e1; font-size: 12.5px; line-height: 1.6;">';
        $html .= 'WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux &amp; cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—we keep your online presence fast, secure, and always available.';
        $html .= '</p>';
        // Polished footer note color (#94a3b8 high-contrast) and hyperlinked Notifications
        $html .= '<div style="border-top: 1px solid #1e293b; padding-top: 14px; font-size: 12px; color: #94a3b8; text-align: center; line-height: 1.6;">';
        $html .= 'Dispatched by WCP Security Scanner on <span style="color: #e2e8f0; font-weight: 600;">' . esc_html($time) . '</span>. You can manage granular notification preferences anytime under <strong>WCP Scanner &gt; <a href="' . esc_url($notif_url) . '" style="color: #38bdf8; text-decoration: underline; font-weight: 600;">Notifications</a></strong>.';
        $html .= '</div>';
        $html .= '</div>';

        $html .= '</div></body></html>';

        return (bool) wp_mail($to, $subject, $html, $headers);
    }

    /**
     * Dispatch structured payload across configured DevSecOps webhooks
     */
    private static function dispatch_webhooks(array $payload): bool {
        $settings = SettingsManager::get_settings();
        $has_slack   = !empty($settings['slack_enabled']) && !empty($settings['slack_webhook_url']);
        $has_discord = !empty($settings['discord_enabled']) && !empty($settings['discord_webhook_url']);
        $has_clickup = !empty($settings['clickup_enabled']) && !empty($settings['clickup_webhook_url']);
        $has_asana   = !empty($settings['asana_enabled']) && !empty($settings['asana_webhook_url']);
        $has_generic = !empty($settings['generic_webhook_enabled']) && !empty($settings['generic_webhook_url']);

        if (!$has_slack && !$has_discord && !$has_clickup && !$has_asana && !$has_generic) {
            return false;
        }

        $severity  = strtolower($payload['severity']);
        $site_name = $payload['site_name'];
        $site_url  = $payload['site_url'];
        $title     = $payload['title'];
        $message   = $payload['message'];
        $dash_url  = $payload['dashboard_url'];

        $is_danger = ($severity === 'critical' || $severity === 'high');
        $color_hex = $is_danger ? WebhookService::COLOR_CRITICAL : WebhookService::COLOR_INFO;
        $color_int = $is_danger ? 14428198 : 164999;
        $status_emoji = $severity === 'critical' ? '🚨' : ($severity === 'high' ? '⚠️' : '🛡️');

        // 1. Slack
        if ($has_slack) {
            $slack_payload = [
                'text' => "{$status_emoji} [{$payload['severity']}] {$title} on {$site_name}",
                'attachments' => [
                    [
                        'color' => $color_hex,
                        'blocks' => [
                            [
                                'type' => 'header',
                                'text' => ['type' => 'plain_text', 'text' => "{$status_emoji} {$title}", 'emoji' => true]
                            ],
                            [
                                'type' => 'section',
                                'text' => [
                                    'type' => 'mrkdwn',
                                    'text' => "*Site:* <{$site_url}|{$site_name}>\n*Severity:* `{$payload['severity']}`\n*Details:* {$message}"
                                ]
                            ],
                            [
                                'type' => 'actions',
                                'elements' => [
                                    [
                                        'type' => 'button',
                                        'text' => ['type' => 'plain_text', 'text' => 'Review Incident in Dashboard'],
                                        'url' => $dash_url,
                                        'style' => $is_danger ? 'danger' : 'primary'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ];
            WebhookService::send_test('slack', null); // Or send directly
            self::post_webhook_direct($settings['slack_webhook_url'], $slack_payload);
        }

        // 2. Discord
        if ($has_discord) {
            $discord_payload = [
                'username' => 'WCP Security Sentinel',
                'embeds' => [
                    [
                        'title' => "{$status_emoji} {$title}",
                        'description' => $message,
                        'url' => $dash_url,
                        'color' => $color_int,
                        'fields' => [
                            ['name' => 'Site', 'value' => $site_name, 'inline' => true],
                            ['name' => 'Severity', 'value' => strtoupper($payload['severity']), 'inline' => true],
                            ['name' => 'Event Key', 'value' => $payload['event_key'], 'inline' => true],
                        ],
                        'footer' => ['text' => 'WCP Security Scanner Notifications'],
                        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                    ]
                ]
            ];
            self::post_webhook_direct($settings['discord_webhook_url'], $discord_payload);
        }

        // 3. ClickUp
        if ($has_clickup) {
            $clickup_payload = [
                'name'        => "{$status_emoji} [{$payload['severity']}] {$title} - {$site_name}",
                'content'     => "{$message}\n\n- Site: {$site_name} ({$site_url})\n- Security Dashboard: {$dash_url}",
                'priority'    => $is_danger ? 1 : 3,
                'tags'        => ['security', 'wcp-scanner', $payload['event_key']],
                'event'       => $payload['event_key'],
                'site_name'   => $site_name,
            ];
            self::post_webhook_direct($settings['clickup_webhook_url'], $clickup_payload);
        }

        // 4. Asana
        if ($has_asana) {
            $asana_payload = [
                'name'  => "{$status_emoji} [{$payload['severity']}] {$title} - {$site_name}",
                'notes' => "{$message}\n\nSite: {$site_name} ({$site_url})\nDashboard: {$dash_url}",
                'data'  => [
                    'name'  => "{$status_emoji} [{$payload['severity']}] {$title} - {$site_name}",
                    'notes' => "{$message}\n\nSite: {$site_name} ({$site_url})\nDashboard: {$dash_url}",
                ],
            ];
            self::post_webhook_direct($settings['asana_webhook_url'], $asana_payload);
        }

        // 5. Generic Automation Webhook
        if ($has_generic) {
            $generic_payload = [
                'event'         => $payload['event_key'],
                'title'         => $title,
                'message'       => $message,
                'severity'      => $payload['severity'],
                'site_name'     => $site_name,
                'site_url'      => $site_url,
                'dashboard_url' => $dash_url,
                'timestamp'     => $payload['timestamp'],
                'datetime'      => $payload['datetime'],
                'details'       => $payload['details'] ?? [],
            ];
            self::post_webhook_direct($settings['generic_webhook_url'], $generic_payload);
        }

        return true;
    }

    /**
     * Send HTTP POST to a webhook endpoint
     */
    private static function post_webhook_direct(string $url, array $payload): bool {
        if (empty($url)) {
            return false;
        }
        $resp = wp_remote_post($url, [
            'timeout'     => 8,
            'blocking'    => false, // Non-blocking async dispatch for maximum performance
            'headers'     => ['Content-Type' => 'application/json'],
            'body'        => wp_json_encode($payload),
            'data_format' => 'body',
        ]);
        return !is_wp_error($resp);
    }
}
