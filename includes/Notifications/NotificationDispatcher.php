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
            'auth_admin_login' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Administrator Login Successful', 'wcp-security-scanner'),
                'description' => __('Dispatches an immediate alert whenever an administrator user logs in to WordPress.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'auth_admin_password_reset' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Admin Password Changed / Reset', 'wcp-security-scanner'),
                'description' => __('Alerts when an administrator password is reset or updated via profile, recovery link, or REST API.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
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
            // Category: Supply-Chain Defense & SBOM
            'supply_chain_anchor_tampered' => [
                'category'    => 'supply_chain',
                'category_label' => __('Supply-Chain Defense & SBOM', 'wcp-security-scanner'),
                'title'       => __('Runtime Anchor / Drop-in Tampering Detected', 'wcp-security-scanner'),
                'description' => __('Fires when a cryptographic hash mismatch or stealth modification is detected in object-cache.php, db.php, or advanced-cache.php.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'supply_chain_gatekeeper_blocked' => [
                'category'    => 'supply_chain',
                'category_label' => __('Supply-Chain Defense & SBOM', 'wcp-security-scanner'),
                'title'       => __('Hostile Plugin Update Intercepted by Gatekeeper', 'wcp-security-scanner'),
                'description' => __('Alerts immediately when an automated or manual plugin update contains critical webshells, obfuscated payloads, or unauthorized mutations.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'supply_chain_gatekeeper_rollback' => [
                'category'    => 'supply_chain',
                'category_label' => __('Supply-Chain Defense & SBOM', 'wcp-security-scanner'),
                'title'       => __('Pre-Install Gatekeeper Rollback Executed', 'wcp-security-scanner'),
                'description' => __('Notifies when a hazardous plugin update is reverted back to its verified pre-install snapshot.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'supply_chain_risk_advisor_alert' => [
                'category'    => 'supply_chain',
                'category_label' => __('Supply-Chain Defense & SBOM', 'wcp-security-scanner'),
                'title'       => __('High-Risk Plugin Installation Flagged', 'wcp-security-scanner'),
                'description' => __('Dispatches when Shift-Left Risk Analyzer detects critical risk signals, abandoned code, or severe supply-chain flags.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'supply_chain_lockfile_cve' => [
                'category'    => 'supply_chain',
                'category_label' => __('Supply-Chain Defense & SBOM', 'wcp-security-scanner'),
                'title'       => __('Vulnerable Dependency in Lockfile (Composer / NPM)', 'wcp-security-scanner'),
                'description' => __('Alerts when known CVE vulnerabilities or supply-chain advisories match packages in composer.lock or package-lock.json.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'supply_chain_script_drift' => [
                'category'    => 'supply_chain',
                'category_label' => __('Supply-Chain Defense & SBOM', 'wcp-security-scanner'),
                'title'       => __('Client JS Drift / Unauthorized Remote Hostname', 'wcp-security-scanner'),
                'description' => __('Fires when newly enqueued frontend JavaScript loads from an uncalibrated third-party domain or external CDN.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],

            // Category: Behavioral WAF & Active Traps
            'behavioral_bot_trap_triggered' => [
                'category'    => 'behavioral',
                'category_label' => __('Behavioral WAF & Active Traps', 'wcp-security-scanner'),
                'title'       => __('Behavioral Honeytoken / Ghost Route Tripped', 'wcp-security-scanner'),
                'description' => __('Fires when an automated crawler, scraper, or scanner touches hidden ghost routes or deceptive canary endpoints.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'behavioral_rate_limit_exceeded' => [
                'category'    => 'behavioral',
                'category_label' => __('Behavioral WAF & Active Traps', 'wcp-security-scanner'),
                'title'       => __('Behavioral Rate Anomaly Fence Tripped', 'wcp-security-scanner'),
                'description' => __('Dispatches when an offensive IP exceeds heuristic burst frequency thresholds across critical endpoints.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'ai_defense_prompt_injection' => [
                'category'    => 'behavioral',
                'category_label' => __('Behavioral WAF & Active Traps', 'wcp-security-scanner'),
                'title'       => __('AI Prompt Injection & Jailbreak Decoy Intercepted', 'wcp-security-scanner'),
                'description' => __('Alerts when malicious system-prompt override attempts, adversarial jailbreaks, or LLM scraping probes are terminated.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'attack_drill_completed' => [
                'category'    => 'behavioral',
                'category_label' => __('Behavioral WAF & Active Traps', 'wcp-security-scanner'),
                'title'       => __('Red Team Attack Drill Simulation Finished', 'wcp-security-scanner'),
                'description' => __('Summarizes firewall defensibility, payload interception ratios, and alert responsiveness upon drill completion.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],

            // Category: Zero-Trust Identity & Session Forensics
            'auth_passkey_registered' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('FIDO2 / WebAuthn Biometric Passkey Enrolled', 'wcp-security-scanner'),
                'description' => __('Notifies when an administrator binds a new biometric credential, YubiKey, or hardware passkey.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'auth_passkey_revoked' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('WebAuthn Hardware Passkey Revoked / Deleted', 'wcp-security-scanner'),
                'description' => __('Alerts when a hardware security key or biometric credential is removed from an account.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],
            'auth_temporary_access_granted' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Zero-Trust Temporary Support Access Created', 'wcp-security-scanner'),
                'description' => __('Notifies when a time-limited, sandboxed technician link is issued under MU Guardian supervision.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'auth_temporary_access_revoked' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Temporary Support Access Revoked / Expired', 'wcp-security-scanner'),
                'description' => __('Fires when a technician session is prematurely terminated or reaches its expiration boundary.', 'wcp-security-scanner'),
                'severity'    => 'info',
            ],
            'auth_impossible_travel_flag' => [
                'category'    => 'auth',
                'category_label' => __('Authentication & Access Security', 'wcp-security-scanner'),
                'title'       => __('Impossible Geo-Velocity Travel Anomaly Detected', 'wcp-security-scanner'),
                'description' => __('Critical alert when an admin account authenticates from two distant geographical locations in an impossible timeframe.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],

            // Category: Advanced Forensics, Vault & Quarantine
            'forensics_reinfection_resurrection' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('72-Hour Watchdog: Malware Resurrection Intercepted', 'wcp-security-scanner'),
                'description' => __('Urgent alert when a previously cleaned or quarantined file is recreated by persistent rogue crons or hidden web shells.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'vault_secrets_rotated' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Secrets Vault Master Key / Cryptographic Salt Rotated', 'wcp-security-scanner'),
                'description' => __('Notifies when master encryption keys or authentication salts are re-encrypted and safely rotated in wp-config.php.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
            'remediation_transaction_rollback' => [
                'category'    => 'backups_vault',
                'category_label' => __('Database Backups & Vault', 'wcp-security-scanner'),
                'title'       => __('Atomic Remediation Transaction Reverted', 'wcp-security-scanner'),
                'description' => __('Fires when an administrative rollback action restores previous file, database, or user states from a transaction log.', 'wcp-security-scanner'),
                'severity'    => 'warning',
            ],

            // Category: Emergency Containment Protocol
            'containment_mode_activated' => [
                'category'    => 'self_defense',
                'category_label' => __('Plugin Self-Defense', 'wcp-security-scanner'),
                'title'       => __('1-Click Incident Containment Protocol ACTIVATED', 'wcp-security-scanner'),
                'description' => __('Emergency broadcast: Host egress severed, unauthorized admin sessions frozen, and public maintenance lockdown engaged.', 'wcp-security-scanner'),
                'severity'    => 'critical',
            ],
            'containment_mode_deactivated' => [
                'category'    => 'self_defense',
                'category_label' => __('Plugin Self-Defense', 'wcp-security-scanner'),
                'title'       => __('Incident Containment Protocol Disengaged', 'wcp-security-scanner'),
                'description' => __('Notifies when emergency containment lockdown is lifted and normal platform operations resume.', 'wcp-security-scanner'),
                'severity'    => 'high',
            ],
        ];
    }

    /**
     * Detect client browser device type (Desktop, Mobile, Tablet)
     */
    public static function detect_device_type(): string {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))) : '';
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
                $raw_val = sanitize_text_field(wp_unslash($_SERVER[$h]));
                $ips = explode(',', $raw_val);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
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

        // High-density factual subject line for AI parsing
        $host = wp_parse_url($site_url, PHP_URL_HOST) ?: $site_url;
        $subject = sprintf('[%s Alert: %s] %s for %s', $site_name, $severity, $title, $host);

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

        // Gemini AI Overview format (e.g. "WebCare Pro detected an unauthorized plugin deactivation attempt on example.com by user dev2admin.")
        $details = $payload['details'] ?? [];
        $actor   = !empty($details['Triggered By']) ? $details['Triggered By'] : 'system process';
        $ai_overview_summary = sprintf(
            'WebCare Pro triggered a %s security alert (%s) for %s on %s. Triggered by: %s.',
            $severity,
            $title,
            $host,
            $time,
            $actor
        );

        // Build Schema.org / JSON-LD machine-readable envelope for Gmail & Gemini
        $json_ld = [
            '@context'         => 'https://schema.org',
            '@type'            => 'SecurityIncident',
            'name'             => $title,
            'description'      => $ai_overview_summary,
            'disambiguatingDescription' => $message,
            'severity'         => $severity,
            'eventCode'        => $payload['event_key'] ?? 'security_event',
            'datePublished'    => $time,
            'about'            => [
                '@type' => 'WebSite',
                'name'  => $site_name,
                'url'   => $site_url,
            ],
            'publisher'        => [
                '@type' => 'Organization',
                'name'  => 'WebCare Pro',
                'url'   => 'https://webcarespro.com',
            ],
            'diagnosticDetails' => $details,
            'potentialAction'  => [
                '@type'  => 'ViewAction',
                'name'   => 'Open Security Dashboard',
                'target' => $dash_url,
            ],
        ];
        $json_ld_string = wp_json_encode($json_ld, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

        $html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
        $html .= '<meta name="description" content="' . esc_attr($ai_overview_summary) . '">';
        $html .= '<meta name="wcp-security-severity" content="' . esc_attr($severity) . '">';
        $html .= '<meta name="wcp-event-code" content="' . esc_attr($payload['event_key'] ?? '') . '">';
        $html .= '<meta name="wcp-site-url" content="' . esc_attr($site_url) . '">';
        $html .= '<script type="application/ld+json">' . $json_ld_string . '</script>';
        $html .= '<style>';
        $html .= '@media only screen and (max-width: 540px) {';
        $html .= '  .wcp-container { width: 100% !important; border-radius: 0 !important; }';
        $html .= '  .wcp-content { padding: 22px 16px !important; }';
        $html .= '  .wcp-header { padding: 24px 18px !important; }';
        $html .= '  .wcp-kv-table { width: 100% !important; }';
        $html .= '  .wcp-kv-row { display: block !important; width: 100% !important; padding: 10px 14px !important; box-sizing: border-box !important; }';
        $html .= '  .wcp-kv-label { display: block !important; width: 100% !important; padding: 0 0 4px 0 !important; font-size: 11px !important; }';
        $html .= '  .wcp-kv-val { display: block !important; width: 100% !important; padding: 0 !important; font-size: 12.5px !important; word-break: break-word !important; }';
        $html .= '  .wcp-btn { display: block !important; width: 100% !important; box-sizing: border-box !important; text-align: center !important; }';
        $html .= '  .wcp-footer { padding: 22px 18px !important; }';
        $html .= '}';
        $html .= '</style>';
        $html .= '</head><body style="margin: 0; padding: 24px 8px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #0f172a;">';

        // Hidden AI & Email Client Preheader (Zero visible footprint, ingested by Gemini / Gmail AI)
        $html .= '<div style="display:none;font-size:1px;color:#f1f5f9;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;mso-hide:all;">';
        $html .= esc_html($ai_overview_summary);
        $html .= ' &zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;';
        $html .= '</div>';

        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f1f5f9;">';
        $html .= '<tr><td align="center">';
        $html .= '<table role="presentation" class="wcp-container" width="600" cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);">';

        // Top Accent Gradient Bar
        $html .= '<tr><td style="height: 4px; background: linear-gradient(90deg, #4f46e5 0%, #38bdf8 50%, ' . esc_attr($severity_color) . ' 100%);"></td></tr>';

        // Header: Deep Obsidian (#0f172a), high-contrast badges, logo, and title
        $html .= '<tr><td class="wcp-header" style="padding: 30px 32px; background: #0f172a; text-align: left; border-bottom: 3px solid ' . esc_attr($severity_color) . ';">';
        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td>';

        // Severity Status Pill Badge
        $badge_bg = 'rgba(59, 130, 246, 0.15)';
        $badge_color = '#60a5fa';
        $badge_border = 'rgba(96, 165, 250, 0.35)';
        $badge_icon = '🛡️';
        if ($severity === 'CRITICAL') {
            $badge_bg = 'rgba(239, 68, 68, 0.18)';
            $badge_color = '#f87171';
            $badge_border = 'rgba(239, 68, 68, 0.4)';
            $badge_icon = '🚨';
        } elseif ($severity === 'HIGH') {
            $badge_bg = 'rgba(249, 115, 22, 0.18)';
            $badge_color = '#fb923c';
            $badge_border = 'rgba(249, 115, 22, 0.4)';
            $badge_icon = '⚠️';
        } elseif ($severity === 'WARNING') {
            $badge_bg = 'rgba(245, 158, 11, 0.18)';
            $badge_color = '#fbbf24';
            $badge_border = 'rgba(245, 158, 11, 0.4)';
            $badge_icon = '⚡';
        }

        $html .= '<div style="display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase; background: ' . esc_attr($badge_bg) . '; color: ' . esc_attr($badge_color) . '; border: 1px solid ' . esc_attr($badge_border) . '; margin-bottom: 12px;">';
        $html .= $badge_icon . ' ' . esc_html($severity) . ' PRIORITY ALERT';
        $html .= '</div>';

        // Title and Site
        $html .= '<h1 style="margin: 0 0 6px 0; font-size: 20px; font-weight: 800; color: #ffffff; line-height: 1.35;">' . esc_html($title) . '</h1>';
        $html .= '<div style="font-size: 13px; color: #94a3b8;">Target Site: <strong style="color: #38bdf8;">' . esc_html($site_name) . '</strong> (<a href="' . esc_url($site_url) . '" style="color: #38bdf8; text-decoration: none;">' . esc_html($site_url) . '</a>)</div>';
        $html .= '</td></tr></table></td></tr>';

        // Content Body: Clean White Surface
        $html .= '<tr><td class="wcp-content" style="padding: 28px 32px; background: #ffffff;">';

        // AI Summary Quick-Glance Callout (Clean Blue Card)
        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; margin-bottom: 20px;">';
        $html .= '<tr><td style="padding: 14px 16px;">';
        $html .= '<div style="font-size: 11px; font-weight: 800; color: #1d4ed8; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 4px;">⚡ AI Executive Incident Brief</div>';
        $html .= '<div style="font-size: 13px; color: #1e3a8a; line-height: 1.5; font-weight: 500;">' . esc_html($ai_overview_summary) . '</div>';
        $html .= '</td></tr></table>';

        $html .= '<p style="font-size: 14.5px; color: #334155; margin: 0 0 20px 0; line-height: 1.6;">' . nl2br(esc_html($message)) . '</p>';

        // Diagnostic Details: Clean Matrix (#f8fafc with #e2e8f0 border)
        if (!empty($payload['details']) && is_array($payload['details'])) {
            $html .= '<div style="font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-bottom: 10px;">Forensic Event Dossier</div>';
            $html .= '<table role="presentation" class="wcp-kv-table" width="100%" cellpadding="0" cellspacing="0" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; overflow: hidden; margin-bottom: 24px;">';
            $total_items = count($payload['details']);
            $curr = 0;
            foreach ($payload['details'] as $k => $v) {
                $curr++;
                $val = is_scalar($v) ? (string)$v : wp_json_encode($v);
                $is_last = ($curr === $total_items);
                $border_style = $is_last ? '' : 'border-bottom: 1px solid #e2e8f0;';

                $val_color = '#0f172a';
                if (stripos((string)$k, 'code') !== false || stripos((string)$k, 'key') !== false) {
                    $val_color = '#0284c7';
                } elseif (stripos((string)$k, 'status') !== false) {
                    $val_color = '#b45309';
                }

                $html .= '<tr><td style="padding: 12px 16px; ' . $border_style . '" class="wcp-kv-row">';
                $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>';
                $html .= '<td width="35%" class="wcp-kv-label" style="font-size: 12px; color: #64748b; font-weight: 600; vertical-align: top;">' . esc_html(ucwords(str_replace('_', ' ', (string)$k))) . '</td>';
                $html .= '<td width="65%" class="wcp-kv-val" style="font-size: 13px; color: ' . esc_attr($val_color) . '; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; vertical-align: top;">' . esc_html((string)$val) . '</td>';
                $html .= '</tr></table></td></tr>';
            }
            $html .= '</table>';
        }

        // Action CTA Button
        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top: 24px;">';
        $html .= '<tr><td align="center">';
        $html .= '<a href="' . esc_url($dash_url) . '" class="wcp-btn" style="display: inline-block; background: #4f46e5; color: #ffffff; font-size: 14px; font-weight: 700; text-decoration: none; padding: 14px 32px; border-radius: 8px; box-shadow: 0 4px 16px rgba(79, 70, 229, 0.4);">';
        $html .= 'Open WCP Security Dashboard &rarr;';
        $html .= '</a></td></tr></table>';

        $html .= '</td></tr>';

        // Sleek Dark Footer matching exact requested screenshot format
        $html .= '<tr><td class="wcp-footer" style="background: #0b1120; padding: 28px 32px; border-top: 1px solid rgba(255, 255, 255, 0.08); font-size: 12.5px; color: #94a3b8; line-height: 1.6;">';
        $html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td>';
        $html .= '<div style="margin-bottom: 12px;">';
        $html .= '<strong style="color: #ffffff; font-size: 14px; letter-spacing: 0.2px;">About WebCare Pro</strong>';
        $html .= '<span style="color: #475569; margin: 0 8px;">•</span>';
        $html .= '<a href="https://webcarespro.com" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: 600;">https://webcarespro.com</a>';
        $html .= '</div>';
        $html .= '<p style="margin: 0 0 16px 0; color: #cbd5e1; font-size: 12.5px; line-height: 1.6;">';
        $html .= 'WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux &amp; cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—we keep your online presence fast, secure, and always available.';
        $html .= '</p>';
        $html .= '<div style="border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 14px; font-size: 12px; color: #94a3b8; text-align: left; line-height: 1.6;">';
        $html .= 'Dispatched by WCP Security Scanner on <strong style="color: #ffffff;">' . esc_html($time) . '</strong>. You can manage granular notification preferences anytime under <strong>WCP Scanner &gt; <a href="' . esc_url($notif_url) . '" style="color: #38bdf8; text-decoration: underline;">Notifications</a></strong>.';
        $html .= '</div></td></tr></table></td></tr>';

        $html .= '</table></td></tr></table></body></html>';

        try {
            return (bool) wp_mail($to, $subject, $html, $headers);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WCP Scanner: wp_mail failed due to mailer engine error: ' . $e->getMessage());
            return false;
        }
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
        if (is_wp_error($resp)) {
            if ($payload['event_key'] !== 'webhook_delivery_failed') {
                self::trigger('webhook_delivery_failed', [
                    'severity' => 'warning',
                    /* translators: 1: webhook endpoint URL, 2: error message */
                    'message'  => sprintf(__('Webhook delivery failed to destination "%1$s": %2$s', 'wcp-security-scanner'), esc_url($url), $resp->get_error_message()),
                    'details'  => [
                        'Destination URL' => esc_url($url),
                        'Failed Event'    => $payload['event_key'] ?? 'unknown',
                        'Error Message'   => $resp->get_error_message(),
                    ],
                ]);
            }
            return false;
        }
        return true;
    }
}
