<?php
namespace WebCareProScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Enterprise Activity & Forensic Audit Log Humanizer.
 *
 * Converts raw internal actions, cryptographic hashes, and option diffs
 * into clean, plain-English summaries, intuitive titles, and semantic badges
 * suitable for non-technical site administrators, store owners, and clients.
 */
class ActivityHumanizer {

    /**
     * Humanize a decrypted activity record.
     *
     * @param array $record Decrypted event record.
     * @return array Enriched record with friendly fields.
     */
    public static function humanize_record(array $record): array {
        $action   = $record['action'] ?? '';
        $details  = $record['details'] ?? [];
        $actor    = $record['actor'] ?? [];
        $category = $record['category'] ?? 'system';

        $user_login = !empty($actor['user_login']) ? $actor['user_login'] : (!empty($actor['display_name']) ? $actor['display_name'] : 'Administrator');
        $actor_ip   = !empty($actor['ip']) ? $actor['ip'] : '127.0.0.1';

        $title       = '';
        $description = '';
        $badge       = 'info';
        $badge_label = ucfirst($category);
        $is_internal = false;

        switch ($action) {
            case 'firewall_ip_unblocked':
                $ip = $details['ip'] ?? 'IP';
                $title       = sprintf('Unblocked IP Address: %s', $ip);
                $description = sprintf('IP address %1$s was unblocked by %2$s (from IP %3$s). Standard WAF traffic filtering remains active.', $ip, $user_login, $actor_ip);
                $badge       = 'clean';
                $badge_label = 'Firewall Access';
                break;

            case 'firewall_ip_blocked':
                $ip = $details['ip'] ?? 'IP';
                $title       = sprintf('Blocked Threat IP: %s', $ip);
                $description = sprintf('IP address %1$s was manually blocked from accessing the site by %2$s.', $ip, $user_login);
                $badge       = 'danger';
                $badge_label = 'Perimeter Defense';
                break;

            case 'firewall_ip_whitelisted':
                $ip = $details['ip'] ?? 'IP';
                $title       = sprintf('Added to Trusted Allowlist: %s', $ip);
                $description = sprintf('IP %1$s was added to the trusted allowlist by %2$s. Requests from this IP bypass standard WAF inspection.', $ip, $user_login);
                $badge       = 'clean';
                $badge_label = 'Allowlist';
                break;

            case 'firewall_ip_whitelist_removed':
                $ip = $details['ip'] ?? 'IP';
                $title       = sprintf('Removed from Allowlist: %s', $ip);
                $description = sprintf('IP %1$s was removed from the trusted allowlist by %2$s. Standard security filtering has been restored.', $ip, $user_login);
                $badge       = 'warning';
                $badge_label = 'Allowlist';
                break;

            case 'customer_lockout_unblocked':
                $ip = $details['ip'] ?? 'Customer IP';
                $title       = sprintf('Customer Store Access Granted: %s', $ip);
                $description = sprintf('Customer IP %1$s was unblocked and granted a 24-hour store access bypass token to complete checkout.', $ip);
                $badge       = 'clean';
                $badge_label = 'Store Protection';
                break;

            case 'login_lockout':
                $ip = $details['ip'] ?? 'Attacker IP';
                $title       = sprintf('Brute Force Login Lockout: %s', $ip);
                $description = sprintf('IP %1$s was temporarily locked out after repeated consecutive failed login attempts.', $ip);
                $badge       = 'danger';
                $badge_label = 'Account Defense';
                break;

            case 'plugin_activated':
                $desc = $details['description'] ?? '';
                $p_name = '';
                if (preg_match("/Plugin '([^']+)' was activated/i", $desc, $m)) {
                    $p_name = $m[1];
                } elseif (!empty($details['plugin_name'])) {
                    $p_name = $details['plugin_name'];
                }
                $clean_plugin = self::format_plugin_title($p_name ?: ($details['raw_event'] ?? 'Plugin'));
                $title       = sprintf('Plugin Activated: %s', $clean_plugin);
                $description = sprintf('Plugin "%1$s" was activated on this site by %2$s.', $clean_plugin, $user_login);
                $badge       = 'info';
                $badge_label = 'Extensions';
                break;

            case 'plugin_deactivated':
                $desc = $details['description'] ?? '';
                $p_name = '';
                if (preg_match("/Plugin '([^']+)' was deactivated/i", $desc, $m)) {
                    $p_name = $m[1];
                }
                $clean_plugin = self::format_plugin_title($p_name ?: 'Plugin');
                $title       = sprintf('Plugin Deactivated: %s', $clean_plugin);
                $description = sprintf('Plugin "%1$s" was deactivated by %2$s.', $clean_plugin, $user_login);
                $badge       = 'warning';
                $badge_label = 'Extensions';
                break;

            case 'theme_switched':
                $desc = $details['description'] ?? '';
                $t_name = 'Theme';
                if (preg_match("/to '([^']+)'/i", $desc, $m)) {
                    $t_name = $m[1];
                }
                $title       = sprintf('Theme Switched: %s', $t_name);
                $description = sprintf('Active site theme was switched to "%1$s" by %2$s.', $t_name, $user_login);
                $badge       = 'info';
                $badge_label = 'Appearance';
                break;

            case 'core_updated':
                $title       = 'WordPress Core Updated';
                $description = !empty($details['description']) ? $details['description'] : 'WordPress core software was updated to the latest release.';
                $badge       = 'clean';
                $badge_label = 'System';
                break;

            case 'canary_admin_seeded':
                $canary_user = $details['username'] ?? 'webcare_canary_admin';
                $title       = sprintf('Decoy Admin Tripwire Created: %s', $canary_user);
                $description = sprintf('Stealth decoy administrator account "%1$s" was deployed as a database tripwire. Any unauthorized login attempt to this account triggers an immediate high-priority lockout.', $canary_user);
                $badge       = 'clean';
                $badge_label = 'Tripwire Defense';
                break;

            case 'onboarding_wizard_completed':
                $arch = ucfirst($details['archetype'] ?? 'Standard');
                $title       = sprintf('Security Onboarding Completed (%s Profile)', $arch);
                $description = !empty($details['description']) ? $details['description'] : sprintf('Initial security setup wizard completed by %1$s; applied %2$s profile baseline hardening policies.', $user_login, $arch);
                $badge       = 'clean';
                $badge_label = 'Setup Wizard';
                break;

            case 'whitelist_policy_modified':
                $new_ip = '';
                if (!empty($details['diff']['webcareproscan_waf_whitelisted_ips']['new'])) {
                    $new_ip = trim((string) $details['diff']['webcareproscan_waf_whitelisted_ips']['new']);
                }
                $title       = !empty($new_ip) ? sprintf('Trusted IP Added to Allowlist: %s', $new_ip) : 'Trusted IP Allowlist Updated';
                $description = !empty($new_ip)
                    ? sprintf('IP address %1$s was added to the trusted allowlist by %2$s. Permitted IP addresses bypass standard WAF inspection.', $new_ip, $user_login)
                    : sprintf('Trusted IP allowlist was updated by %1$s.', $user_login);
                $badge       = 'clean';
                $badge_label = 'Allowlist';
                break;

            case 'gatekeeper_update_audited':
                $plugin = $details['plugin_slug'] ?? 'Plugin';
                $title       = sprintf('Safe Plugin Update: %s', self::slug_to_title($plugin));
                $description = sprintf('WebCare Gatekeeper verified the update for "%1$s". Cryptographic code inspection confirmed zero malicious payloads or backdoor modifications.', self::slug_to_title($plugin));
                $badge       = 'clean';
                $badge_label = 'Extension Security';
                break;

            case 'auth_success':
                $title       = 'Admin Session Authenticated';
                $description = sprintf('User "%1$s" successfully logged into WordPress admin from IP %2$s.', $user_login, $actor_ip);
                $badge       = 'info';
                $badge_label = 'Identity & Auth';
                break;

            case 'auth_failed':
                $title       = 'Failed Login Attempt Blocked';
                $description = sprintf('Failed login attempt for username "%1$s" from IP %2$s.', $details['username'] ?? 'unknown', $actor_ip);
                $badge       = 'warning';
                $badge_label = 'Identity & Auth';
                break;

            case 'impossible_travel_detected':
                $title       = sprintf('Impossible Travel Alert: %s', $user_login);
                $description = sprintf('User "%1$s" logged in from two geographically distant locations in an impossibly short timeframe. Session flagged for review.', $user_login);
                $badge       = 'danger';
                $badge_label = 'Identity & Auth';
                break;

            case 'webauthn_passkey_registered':
                $name = $details['label'] ?? ($details['name'] ?? 'Biometric Device');
                $title       = 'Biometric Passkey Registered';
                $description = sprintf('New hardware biometric passkey ("%1$s") was successfully registered for user "%2$s".', $name, $user_login);
                $badge       = 'clean';
                $badge_label = 'Identity & Auth';
                break;

            case 'webauthn_passkey_deleted':
                $title       = 'Biometric Passkey Revoked';
                $description = sprintf('Biometric passkey credential was deleted and revoked for user "%1$s".', $user_login);
                $badge       = 'warning';
                $badge_label = 'Identity & Auth';
                break;

            case 'webauthn_passkey_login_success':
                $title       = 'Biometric Passkey Sign-In Verified';
                $description = sprintf('User "%1$s" authenticated securely via hardware biometric passkey (FIDO2/WebAuthn).', $user_login);
                $badge       = 'clean';
                $badge_label = 'Identity & Auth';
                break;

            case 'all_sessions_revoked':
                $title       = 'All Active Sessions Terminated';
                $description = sprintf('All active WordPress login sessions and authentication cookies were revoked for user "%1$s".', $user_login);
                $badge       = 'warning';
                $badge_label = 'Identity & Auth';
                break;

            case 'route_graduated':
                $route = $details['route'] ?? 'API Route';
                $title       = sprintf('Adaptive Learning: Route Graduated (%s)', $route);
                $description = sprintf('REST API route "%1$s" achieved 100%% confidence with 25+ verified benign requests. Added to adaptive allowlist.', $route);
                $badge       = 'clean';
                $badge_label = 'Adaptive Learning';
                break;

            case 'firewall_logs_cleared':
                $title       = 'Firewall Incident Logs Purged';
                $description = sprintf('Historical firewall incident logs were manually purged by %1$s from IP %2$s.', $user_login, $actor_ip);
                $badge       = 'warning';
                $badge_label = 'Maintenance';
                break;

            case 'cloudflare_ip_blocked':
                $ip = $details['ip'] ?? 'IP';
                $title       = sprintf('Cloudflare Edge Block: %s', $ip);
                $description = sprintf('IP %1$s was blocked globally at the Cloudflare Edge network by %2$s.', $ip, $user_login);
                $badge       = 'danger';
                $badge_label = 'Cloudflare Edge';
                break;

            case 'cloudflare_ip_unblocked':
                $ip = $details['ip'] ?? ($details['rule_id'] ?? 'Target');
                $title       = sprintf('Cloudflare Edge Block Removed: %s', $ip);
                $description = sprintf('Cloudflare Edge block rule for %1$s was removed by %2$s.', $ip, $user_login);
                $badge       = 'clean';
                $badge_label = 'Cloudflare Edge';
                break;

            case 'cloudflare_ip_whitelisted':
                $ip = $details['ip'] ?? 'IP';
                $title       = sprintf('Cloudflare Edge Allowlist Added: %s', $ip);
                $description = sprintf('IP %1$s was granted Edge-level bypass on Cloudflare by %2$s.', $ip, $user_login);
                $badge       = 'clean';
                $badge_label = 'Cloudflare Edge';
                break;

            case 'cloudflare_rules_deployed':
                $count = (int) ($details['rules_count'] ?? 1);
                $title       = sprintf('Cloudflare Edge WAF Rules Deployed (%d)', $count);
                $description = sprintf('Synchronized %1$d active firewall rule(s) to Cloudflare Global Edge network.', $count);
                $badge       = 'clean';
                $badge_label = 'Cloudflare Edge';
                break;

            case 'firewall_ruleset_modified':
                $count = (int) ($details['changed_count'] ?? 1);
                $title       = sprintf('Firewall Protection Policy Updated (%d setting%s)', $count, $count === 1 ? '' : 's');
                $description = sprintf('Firewall protection rules or access controls were saved by %1$s.', $user_login);
                $badge       = 'info';
                $badge_label = 'Firewall Policy';
                break;

            case 'settings_updated':
                $count = (int) ($details['changed_count'] ?? 1);
                $title       = sprintf('Scanner Settings Saved (%d change%s)', $count, $count === 1 ? '' : 's');
                $description = sprintf('Plugin configuration or automated scan schedule parameters were saved by %1$s.', $user_login);
                $badge       = 'info';
                $badge_label = 'Settings';
                break;

            case 'permission_hardening':
                $title       = 'Filesystem Permission Hardening';
                $description = !empty($details['description']) ? $details['description'] : '1-Click filesystem permission repair applied: directories set to 0755 and sensitive files to 0644.';
                $badge       = 'clean';
                $badge_label = 'Filesystem Security';
                break;

            case 'script_baseline_calibrated':
                $title       = 'Supply Chain Script Baseline Calibrated';
                $description = !empty($details['description']) ? $details['description'] : 'Calibrated approved external domains and script integrity for supply chain monitoring.';
                $badge       = 'clean';
                $badge_label = 'Extension Security';
                break;

            case 'domain_reputation_anomaly':
                $title       = 'Domain Reputation & Health Audit';
                $description = !empty($details['description']) ? $details['description'] : 'Domain reputation check evaluated domain health and security blacklists.';
                $badge       = 'info';
                $badge_label = 'System Health';
                break;

            case 'htaccess_vault_snapshot_saved':
                $v = $details['version'] ?? 1;
                $reason = $details['reason'] ?? 'auto';
                $title       = sprintf('Archived .htaccess to Vault Snapshot #%d', $v);
                $description = sprintf('Verified-clean root .htaccess configuration was archived into Vault Snapshot #%1$d (trigger: %2$s).', $v, $reason);
                $badge       = 'info';
                $badge_label = 'Server Armor';
                break;

            case 'htaccess_restored_from_vault':
                $v = $details['version'] ?? 1;
                $source = $details['source'] ?? 'disk';
                $title       = sprintf('Restored .htaccess from Vault Snapshot #%d', $v);
                $description = sprintf('Root .htaccess was restored from Vault Snapshot #%1$d (%2$s) and all site caches were purged.', $v, $source);
                $badge       = 'clean';
                $badge_label = 'Auto-Healing';
                break;

            case 'waf_runtime_redirect_intercepted':
                $t_host = $details['target_host'] ?? 'External';
                $src = $details['source_file'] ?? 'unknown';
                $title       = sprintf('Runtime Guest Redirect Hijack Blocked: %s', $t_host);
                $description = sprintf('An unauthorized external guest redirect to "%1$s" was intercepted and neutralized back to homepage (attributed to %2$s).', $details['target_url'] ?? $t_host, $src);
                $badge       = 'danger';
                $badge_label = 'Redirect Defense';
                break;

            case 'database_core_urls_healed':
                $home = $details['restored_home'] ?? '';
                $title       = 'Database Core URLs Restored to Baseline';
                $description = sprintf('Tampered "siteurl" and "home" database options were automatically restored back to baseline ("%s").', $home);
                $badge       = 'clean';
                $badge_label = 'Auto-Healing';
                break;

            case 'policy_updated':
                $option = $details['option'] ?? '';
                if (str_contains($option, 'micro_waf_status')) {
                    $title       = 'Pre-Boot Micro-WAF Engine Synchronized';
                    $description = 'Standalone Pre-Boot Micro-WAF script recompiled into wp-content/micro-waf.php to enforce active rules, IP blocklists, and Context-Adaptive Firewall (CAF) policies before WordPress loads.';
                    $badge       = 'clean';
                    $badge_label = 'Pre-Boot Firewall';
                    $is_internal = true;
                } elseif (str_contains($option, 'ip_reputation_log')) {
                    $title       = 'IP Threat Reputation Cache Updated';
                    $description = 'Threat risk scores and autonomous behavioral tiering updated for evaluated client IP addresses.';
                    $badge       = 'info';
                    $badge_label = 'Threat Intelligence';
                    $is_internal = true;
                } elseif (str_contains($option, 'blocked_ips_meta')) {
                    $title       = 'Firewall IP Blocklist Registry Synchronized';
                    $description = 'Ban duration, strike counter, and incident tracking metadata updated for blocked IP addresses.';
                    $badge       = 'info';
                    $badge_label = 'Firewall Policy';
                    $is_internal = true;
                } elseif (str_contains($option, 'self_defense_last_audit')) {
                    $title       = 'Self-Defense Cryptographic Integrity Audit';
                    $description = 'Automated integrity scanner verified core plugin file hashes and manifests against tampering.';
                    $badge       = 'clean';
                    $badge_label = 'Self-Defense';
                    $is_internal = true;
                } elseif (str_contains($option, 'wizard_completed')) {
                    $title       = 'Initial Security Onboarding Completed';
                    $description = sprintf('Initial security setup wizard completed by %1$s; recommended baseline hardening policies applied.', $user_login);
                    $badge       = 'clean';
                    $badge_label = 'Setup Wizard';
                } elseif (str_contains($option, 'site_archetype')) {
                    $arch = is_string($details['diff']['webcareproscan_site_archetype']['new'] ?? null) ? $details['diff']['webcareproscan_site_archetype']['new'] : 'Standard';
                    $title       = sprintf('Site Posture Profile Calibrated: %s', ucfirst($arch));
                    $description = sprintf('Security scanner operational posture calibrated for site archetype "%1$s" by %2$s.', ucfirst($arch), $user_login);
                    $badge       = 'info';
                    $badge_label = 'Site Profile';
                } elseif (str_contains($option, 'server_security_options')) {
                    $title       = 'Web Server Armor Configuration Updated';
                    $description = 'Server-level hardening directives updated for web server rules (.htaccess / Nginx).';
                    $badge       = 'clean';
                    $badge_label = 'Server Armor';
                } elseif (str_contains($option, 'waf_log_retention_days')) {
                    $days = $details['diff']['webcareproscan_waf_log_retention_days']['new'] ?? ($details['diff']['old'] ?? 60);
                    $days_int = is_numeric($days) ? (int) $days : 60;
                    $title       = sprintf('Firewall Incident Log Retention: %d Days', $days_int);
                    $description = sprintf('Administrator %1$s set the firewall incident log retention period to %2$d days.', $user_login, $days_int);
                    $badge       = 'clean';
                    $badge_label = 'Firewall Policy';
                } elseif (str_contains($option, 'waf_whitelisted_ips')) {
                    $new_ip = $details['diff']['webcareproscan_waf_whitelisted_ips']['new'] ?? '';
                    if (is_string($new_ip) && filter_var(trim($new_ip), FILTER_VALIDATE_IP)) {
                        $title       = sprintf('Trusted IP Added to Allowlist: %s', trim($new_ip));
                        $description = sprintf('IP address %1$s was added to the trusted allowlist by %2$s. Permitted IP addresses bypass standard WAF filtering.', trim($new_ip), $user_login);
                    } else {
                        $title       = 'Firewall Trusted IP Allowlist Updated';
                        $description = sprintf('Trusted IP allowlist updated by %1$s. Permitted IP addresses bypass standard WAF filtering.', $user_login);
                    }
                    $badge       = 'clean';
                    $badge_label = 'Firewall Policy';
                } elseif (str_contains($option, 'waf_settings')) {
                    $title       = 'Firewall Baseline Protection Policy Saved';
                    $description = sprintf('Administrator %1$s enabled core firewall shields: Bad Bot Blocker, Uploads Execution Armor, Brute-Force Shield, and Virtual Patching.', $user_login);
                    $badge       = 'clean';
                    $badge_label = 'Firewall Policy';
                } elseif (str_contains($option, 'notification_settings')) {
                    $recip = $details['diff']['webcareproscan_notification_settings']['new']['email_recipient'] ?? 'Administrator';
                    $title       = 'Security Alert Notifications Configured';
                    $description = sprintf('Administrator %1$s configured security incident alert delivery for %2$s (Critical threats, Logins, and Panic containment).', $user_login, $recip);
                    $badge       = 'info';
                    $badge_label = 'Notifications';
                } elseif (str_contains($option, 'circuit_breaker')) {
                    $title       = 'CrashGuard Self-Preservation Engaged';
                    $description = 'CrashGuard temporarily paused firewall hook execution to prevent site downtime after an uncaught PHP error.';
                    $badge       = 'warning';
                    $badge_label = 'Self-Preservation';
                    $is_internal = true;
                } elseif (str_contains($option, 'gatekeeper_logs')) {
                    $title       = 'Plugin Update Files Verified';
                    $description = 'Gatekeeper recorded file modification digests following a clean plugin update.';
                    $badge       = 'clean';
                    $badge_label = 'Extension Security';
                    $is_internal = true;
                } elseif (str_contains($option, 'threat_intel')) {
                    $title       = 'Threat Intelligence Feed Synchronized';
                    $description = 'Community threat intelligence feed updated with active malicious IPs and botnets.';
                    $badge       = 'info';
                    $badge_label = 'Threat Intelligence';
                    $is_internal = true;
                } elseif (str_contains($option, 'ghost_trap')) {
                    $title       = 'Decoy Bot Trap Telemetry Recorded';
                    $description = 'Automated bot reconnaissance probes were intercepted by decoy honeytoken endpoints.';
                    $badge       = 'warning';
                    $badge_label = 'Decoy Traps';
                    $is_internal = true;
                } elseif (str_contains($option, 'webauthn_index')) {
                    $title       = 'Biometric Security Registry Synchronized';
                    $description = 'Cryptographic public key indexes updated for biometric passkey authentication.';
                    $badge       = 'clean';
                    $badge_label = 'Identity & Auth';
                    $is_internal = true;
                } else {
                    $clean_name = self::slug_to_title(str_replace('webcareproscan_', '', $option));
                    $title       = sprintf('%s Updated', $clean_name);
                    $description = sprintf('Configuration parameters updated for %1$s.', $clean_name);
                    $badge       = 'info';
                    $badge_label = 'Security Policy';
                }
                break;

            default:
                $clean_action = ucwords(str_replace('_', ' ', $action));
                $title       = $clean_action;
                $description = !empty($details['description']) ? $details['description'] : sprintf('Security event "%1$s" executed by %2$s.', $clean_action, $user_login);
                $badge       = 'info';
                $badge_label = ucfirst($category);
                break;
        }

        $record['friendly_title']          = $title;
        $record['friendly_description']    = $description;
        $record['friendly_badge']          = $badge;
        $record['friendly_badge_label']    = $badge_label;
        $record['is_system_internal']      = $is_internal;

        return $record;
    }

    /**
     * Convert slug to title.
     *
     * @param string $slug
     * @return string
     */
    private static function slug_to_title(string $slug): string {
        $clean = str_replace(['webcareproscan_', '-', '_'], ' ', $slug);
        return ucwords(trim($clean));
    }

    /**
     * Format raw plugin file path into clean, human-readable title.
     *
     * @param string $path
     * @return string
     */
    public static function format_plugin_title(string $path): string {
        if (str_contains($path, 'webcare-pro-security')) {
            return 'WebCare Pro Security & Firewall';
        }
        if (str_contains($path, 'plugin-check')) {
            return 'Plugin Check (PCP)';
        }
        if (str_contains($path, 'akismet')) {
            return 'Akismet Anti-Spam';
        }
        if (str_contains($path, 'woocommerce')) {
            return 'WooCommerce';
        }
        if (str_contains($path, 'hello')) {
            return 'Hello Dolly';
        }

        $base = basename($path);
        if (str_contains($path, '/')) {
            $parts = explode('/', $path);
            $slug = $parts[0];
        } else {
            $slug = str_replace('.php', '', $base);
        }
        return ucwords(str_replace(['-', '_'], ' ', $slug));
    }
}
