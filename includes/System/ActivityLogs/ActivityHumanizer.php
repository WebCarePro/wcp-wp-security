<?php
namespace WcpScanner\System\ActivityLogs;

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

            case 'gatekeeper_update_audited':
                $plugin = $details['plugin_slug'] ?? 'Plugin';
                $title       = sprintf('Safe Plugin Update: %s', self::slug_to_title($plugin));
                $description = sprintf('WCP Gatekeeper verified the update for "%1$s". Cryptographic code inspection confirmed zero malicious payloads or backdoor modifications.', self::slug_to_title($plugin));
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

            case 'policy_updated':
                $option = $details['option'] ?? '';
                if (str_contains($option, 'circuit_breaker')) {
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
                    $clean_name = self::slug_to_title(str_replace('wcpscan_', '', $option));
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
        $clean = str_replace(['wcpscan_', '-', '_'], ' ', $slug);
        return ucwords(trim($clean));
    }
}
