<?php
/**
 * Scoped, Time-Bombed Emergency Support Access Engine
 *
 * Provisions cryptographically signed, passwordless magic access links for external developers
 * and support technicians. Features time-bound auto-expiry, optional IP subnet locking,
 * Secret Vault boundary protection, and 1-click revocation.
 *
 * @package WcpScanner\Identity
 * @author  Mir Alamin (WebCare Pro)
 */

namespace WcpScanner\Identity;

use WcpScanner\System\AuditLogger;
use WcpScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

class TemporarySupportAccess {

    const OPTION_LINKS = 'wcpscan_temporary_support_links';
    const CRON_HOOK    = 'wcpscan_temporary_support_cleanup';

    /**
     * Bootstrap Temporary Support Access hooks.
     */
    public static function init(): void {
        // Intercept incoming magic login links before template rendering
        add_action('init', [__CLASS__, 'handle_magic_link_login'], 1);

        // Schedule hourly cleanup cron
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time(), 'hourly', self::CRON_HOOK);
        }
        add_action(self::CRON_HOOK, [__CLASS__, 'cleanup_expired_links']);

        // Restrict Secret Vault and administrative role escalation for temporary support sessions
        add_filter('user_has_cap', [__CLASS__, 'filter_support_capabilities'], 99, 4);
    }

    /**
     * Retrieve all active temporary support access records.
     *
     * @return array
     */
    public static function get_active_links(): array {
        $acting_uid = get_current_user_id();
        if (!empty(get_user_meta($acting_uid, 'wcpscan_is_temporary_support', true))) {
            return [];
        }

        $links = get_option(self::OPTION_LINKS, []);
        if (!is_array($links)) {
            return [];
        }

        $now = time();
        $cleaned = [];
        foreach ($links as $id => $link) {
            if ($link['expires_at'] > $now && empty($link['revoked'])) {
                $link['is_expired'] = false;
                $link['remaining_seconds'] = $link['expires_at'] - $now;
                $link['remaining_human'] = human_time_diff($now, $link['expires_at']);
                $cleaned[$id] = $link;
            }
        }

        return array_values($cleaned);
    }

    /**
     * Create a scoped, time-bombed magic support link.
     *
     * @param array $args
     * @return array
     */
    public static function create_support_link(array $args): array {
        $acting_uid = get_current_user_id();
        if (!empty(get_user_meta($acting_uid, 'wcpscan_is_temporary_support', true))) {
            return [
                'success' => false,
                'message' => __('Access Denied: Temporary support technicians are strictly prohibited from generating support links.', 'wcp-security-scanner'),
            ];
        }

        $label = !empty($args['label']) ? sanitize_text_field(wp_unslash($args['label'])) : 'External Technician Access';
        $duration_hours = max(1, min(168, (int) ($args['duration_hours'] ?? 4))); // Default 4 hours, max 7 days (168h)
        $restrict_ip = !empty($args['restrict_ip']) ? sanitize_text_field(wp_unslash($args['restrict_ip'])) : '';
        $restrict_vault = isset($args['restrict_vault']) ? !empty($args['restrict_vault']) : true;
        $block_plugin_deactivation  = isset($args['block_plugin_deactivation']) ? !empty($args['block_plugin_deactivation']) : true;
        $block_plugin_deletion      = isset($args['block_plugin_deletion']) ? !empty($args['block_plugin_deletion']) : true;
        $block_plugin_install       = isset($args['block_plugin_install']) ? !empty($args['block_plugin_install']) : true;
        $block_file_editor          = isset($args['block_file_editor']) ? !empty($args['block_file_editor']) : true;
        $block_user_management      = isset($args['block_user_management']) ? !empty($args['block_user_management']) : true;
        $block_database_and_options = isset($args['block_database_and_options']) ? !empty($args['block_database_and_options']) : true;
        $block_tools_and_exports    = isset($args['block_tools_and_exports']) ? !empty($args['block_tools_and_exports']) : true;
        $block_remediation_actions  = isset($args['block_remediation_actions']) ? !empty($args['block_remediation_actions']) : true;
        $block_settings_modification = isset($args['block_settings_modification']) ? !empty($args['block_settings_modification']) : true;
        $acting_admin = wp_get_current_user()->user_login ?: 'administrator';

        $token = wp_generate_password(48, false, false);
        $link_id = 'sup_' . substr(md5($token . wp_salt()), 0, 16);
        $created_at = time();
        $expires_at = $created_at + ($duration_hours * HOUR_IN_SECONDS);

        // Generate HMAC signature
        $signature = hash_hmac('sha256', $link_id . '|' . $expires_at . '|' . $restrict_ip, wp_salt('auth'));

        $record = [
            'id'                          => $link_id,
            'label'                       => $label,
            'token_hash'                  => hash('sha256', $token),
            'signature'                   => $signature,
            'created_at'                  => $created_at,
            'created_by'                  => $acting_admin,
            'expires_at'                  => $expires_at,
            'duration_hours'              => $duration_hours,
            'restrict_ip'                 => $restrict_ip,
            'restrict_vault'              => $restrict_vault,
            'protect_security_plugin'     => true, // Inviolable MU guardian protection
            'block_plugin_deactivation'   => $block_plugin_deactivation,
            'block_plugin_deletion'       => $block_plugin_deletion,
            'block_plugin_install'        => $block_plugin_install,
            'block_file_editor'           => $block_file_editor,
            'block_user_management'       => $block_user_management,
            'block_database_and_options'  => $block_database_and_options,
            'block_tools_and_exports'     => $block_tools_and_exports,
            'block_remediation_actions'   => $block_remediation_actions,
            'block_settings_modification' => $block_settings_modification,
            'used_count'                  => 0,
            'last_used'                   => null,
            'revoked'                     => false,
        ];

        $links = get_option(self::OPTION_LINKS, []);
        if (!is_array($links)) {
            $links = [];
        }
        $links[$link_id] = $record;
        update_option(self::OPTION_LINKS, $links, false);

        // Ensure MU Guardian watchdog is deployed
        WcpJitMuGuardian::ensure_installed();

        // Construct magic login URL
        $magic_url = add_query_arg([
            'wcp_support_access' => $link_id,
            'wcp_key'            => $token,
            'sig'                => $signature,
        ], admin_url('admin.php?page=wcp-security-scanner'));

        AuditLogger::log(
            'temporary_support_link_created',
            sprintf('Temporary Support Link ("%s") created by %s. Valid for %d hours (Expires: %s). IP lock: %s. Zero-Trust MU Shield active.', $label, $acting_admin, $duration_hours, gmdate('Y-m-d H:i:s', $expires_at), $restrict_ip ?: 'None')
        );

        return [
            'success'                     => true,
            'link_id'                     => $link_id,
            'label'                       => $label,
            'magic_url'                   => $magic_url,
            'expires_at'                  => $expires_at,
            'remaining_human'             => human_time_diff($created_at, $expires_at),
            'restrict_ip'                 => $restrict_ip,
            'restrict_vault'              => $restrict_vault,
            'protect_security_plugin'     => true,
            'block_plugin_deactivation'   => $block_plugin_deactivation,
            'block_plugin_deletion'       => $block_plugin_deletion,
            'block_plugin_install'        => $block_plugin_install,
            'block_file_editor'           => $block_file_editor,
            'block_user_management'       => $block_user_management,
            'block_database_and_options'  => $block_database_and_options,
            'block_tools_and_exports'     => $block_tools_and_exports,
            'block_remediation_actions'   => $block_remediation_actions,
            'block_settings_modification' => $block_settings_modification,
            'message'                     => __('Temporary Support Link generated with Zero-Trust MU Guardian protection. Copy and share securely with the authorized technician.', 'wcp-security-scanner'),
        ];
    }

    /**
     * Intercept and authenticate incoming magic support links.
     */
    public static function handle_magic_link_login(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!isset($_GET['wcp_support_access'], $_GET['wcp_key'], $_GET['sig'])) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $link_id = sanitize_key($_GET['wcp_support_access']);
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $token   = sanitize_text_field(wp_unslash($_GET['wcp_key']));
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $sig     = sanitize_text_field(wp_unslash($_GET['sig']));

        $links = get_option(self::OPTION_LINKS, []);
        if (!is_array($links) || !isset($links[$link_id])) {
            wp_die(esc_html__('Invalid or unrecognized support access link.', 'wcp-security-scanner'), 403);
        }

        $record = $links[$link_id];

        // 1. Check revocation & expiry
        if (!empty($record['revoked'])) {
            wp_die(esc_html__('This support access link has been revoked by an administrator.', 'wcp-security-scanner'), 403);
        }
        if (time() > $record['expires_at']) {
            wp_die(esc_html__('This support access link has expired.', 'wcp-security-scanner'), 403);
        }

        // 2. Validate token hash
        if (!hash_equals($record['token_hash'], hash('sha256', $token))) {
            wp_die(esc_html__('Cryptographic token authentication failure.', 'wcp-security-scanner'), 403);
        }

        // 3. Validate signature
        $expected_sig = hash_hmac('sha256', $link_id . '|' . $record['expires_at'] . '|' . $record['restrict_ip'], wp_salt('auth'));
        if (!hash_equals($expected_sig, $sig)) {
            wp_die(esc_html__('HMAC signature verification failed.', 'wcp-security-scanner'), 403);
        }

        // 4. Validate IP restriction if enforced
        $client_ip = FirewallEngine::get_client_ip();
        if (!empty($record['restrict_ip'])) {
            if ($client_ip !== $record['restrict_ip'] && !self::ip_in_range($client_ip, $record['restrict_ip'])) {
                AuditLogger::log(
                    'temporary_support_ip_blocked',
                    sprintf('Blocked temporary support link attempt from unauthorized IP: %s (Restricted to: %s).', $client_ip, $record['restrict_ip'])
                );
                wp_die(
                    sprintf(
                        /* translators: 1: Client IP, 2: Allowed IP */
                        esc_html__('Access denied. This support link is locked to IP: %2$s. Your IP is: %1$s.', 'wcp-security-scanner'),
                        esc_html($client_ip),
                        esc_html($record['restrict_ip'])
                    ),
                    403
                );
            }
        }

        // 5. Authenticate or provision ephemeral technician user session
        $support_user = self::get_or_create_support_user($record);
        if (!$support_user) {
            wp_die(esc_html__('Failed to provision temporary technician user account.', 'wcp-security-scanner'), 500);
        }

        // Mark session metadata
        update_user_meta($support_user->ID, 'wcpscan_is_temporary_support', $link_id);

        // Register with Zero-Trust Must-Use Guardian watchdog
        WcpJitMuGuardian::register_support_user($support_user->ID, $record, $client_ip);

        // Update record stats
        $record['used_count'] = ($record['used_count'] ?? 0) + 1;
        $record['last_used']  = time();
        $record['last_ip']    = $client_ip;
        $links[$link_id]      = $record;
        update_option(self::OPTION_LINKS, $links, false);

        wp_clear_auth_cookie();
        wp_set_current_user($support_user->ID);
        wp_set_auth_cookie($support_user->ID, false);

        AuditLogger::log(
            'temporary_support_login_success',
            sprintf('Temporary technician logged in via magic link "%s" from IP %s. Zero-Trust MU Guardian active.', $record['label'], $client_ip)
        );

        wp_safe_redirect(admin_url('admin.php?page=wcp-security-scanner'));
        exit;
    }

    /**
     * Revoke a temporary support access link immediately.
     *
     * @param string $link_id
     * @return bool
     */
    public static function revoke_link(string $link_id): bool {
        $acting_uid = get_current_user_id();
        if (!empty(get_user_meta($acting_uid, 'wcpscan_is_temporary_support', true))) {
            return false;
        }

        $links = get_option(self::OPTION_LINKS, []);
        if (!is_array($links) || !isset($links[$link_id])) {
            return false;
        }

        $links[$link_id]['revoked'] = true;
        $links[$link_id]['revoked_at'] = time();
        $links[$link_id]['revoked_by'] = wp_get_current_user()->user_login ?: 'administrator';
        update_option(self::OPTION_LINKS, $links, false);

        // Terminate any active sessions tied to this link
        self::terminate_link_user_sessions($link_id);

        AuditLogger::log(
            'temporary_support_link_revoked',
            sprintf('Temporary Support Link "%s" REVOKED by %s.', $links[$link_id]['label'], $links[$link_id]['revoked_by'])
        );

        return true;
    }

    /**
     * Terminate sessions and demote ephemeral technician users.
     *
     * @param string $link_id
     */
    private static function terminate_link_user_sessions(string $link_id): void {
        // Revoke active sessions from Must-Use watchdog
        WcpJitMuGuardian::revoke_link_sessions($link_id);

        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $user_ids = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'wcpscan_is_temporary_support' AND meta_value = %s",
                $link_id
            )
        );

        if (!empty($user_ids)) {
            foreach ($user_ids as $uid) {
                $uid = (int) $uid;
                delete_user_meta($uid, 'wcpscan_is_temporary_support');
                // Terminate session
                if (class_exists('\\WP_Session_Tokens')) {
                    $manager = \WP_Session_Tokens::get_instance($uid);
                    $manager->destroy_all();
                }
            }
        }
    }

    /**
     * Automatic cleanup cron for expired links.
     */
    public static function cleanup_expired_links(): void {
        $links = get_option(self::OPTION_LINKS, []);
        if (!is_array($links)) {
            return;
        }

        $now = time();
        $retained = [];
        $changed = false;

        foreach ($links as $id => $link) {
            // Retain records for 14 days after expiry for audit trails, but clean up active session metadata
            if ($link['expires_at'] < $now && empty($link['revoked'])) {
                self::terminate_link_user_sessions($id);
                $link['revoked'] = true;
                $link['revoked_at'] = $now;
                $link['revoked_by'] = 'cron_auto_expiry';
                $changed = true;
            }
            if ($link['expires_at'] > ($now - (14 * DAY_IN_SECONDS))) {
                $retained[$id] = $link;
            } else {
                $changed = true; // Prune records older than 14 days
            }
        }

        if ($changed) {
            update_option(self::OPTION_LINKS, $retained, false);
        }

        // Clean up any stale support users in MU guardian
        $active_support = get_option(WcpJitMuGuardian::OPTION_SUPPORT_USERS, []);
        if (is_array($active_support) && !empty($active_support)) {
            $sup_changed = false;
            foreach ($active_support as $uid => $conf) {
                if (!empty($conf['expires_at']) && $conf['expires_at'] < $now) {
                    unset($active_support[$uid]);
                    $sup_changed = true;
                }
            }
            if ($sup_changed) {
                update_option(WcpJitMuGuardian::OPTION_SUPPORT_USERS, $active_support, true);
            }
        }
    }

    /**
     * Filter capabilities to restrict Secret Vault, plugins, and user management for temporary support sessions.
     *
     * @param array $allcaps
     * @param array $caps
     * @param array $args
     * @param \WP_User $user
     * @return array
     */
    public static function filter_support_capabilities(array $allcaps, array $caps, array $args, \WP_User $user): array {
        $link_id = get_user_meta($user->ID, 'wcpscan_is_temporary_support', true);
        if (empty($link_id)) {
            return $allcaps;
        }

        $links = get_option(self::OPTION_LINKS, []);
        $record = is_array($links) ? ($links[$link_id] ?? null) : null;

        // Disallow user creation or user deletion for temporary support accounts
        if (!isset($record['block_user_management']) || !empty($record['block_user_management'])) {
            $allcaps['create_users']  = false;
            $allcaps['delete_users']  = false;
            $allcaps['promote_users'] = false;
            $allcaps['remove_users']  = false;
        }

        // Disallow deactivating plugins
        if (!isset($record['block_plugin_deactivation']) || !empty($record['block_plugin_deactivation'])) {
            $allcaps['deactivate_plugins'] = false;
        }

        // Disallow deleting plugins or themes
        if (!isset($record['block_plugin_deletion']) || !empty($record['block_plugin_deletion'])) {
            $allcaps['delete_plugins'] = false;
            $allcaps['delete_themes']  = false;
        }

        // Disallow installing, uploading, or updating arbitrary plugins or themes
        if (!isset($record['block_plugin_install']) || !empty($record['block_plugin_install'])) {
            $allcaps['install_plugins'] = false;
            $allcaps['upload_plugins']  = false;
            $allcaps['update_plugins']  = false;
            $allcaps['install_themes']  = false;
            $allcaps['upload_themes']   = false;
            $allcaps['update_themes']   = false;
            $allcaps['switch_themes']   = false;
            $allcaps['update_core']     = false;
        }

        // Disallow theme and plugin code editors
        if (!isset($record['block_file_editor']) || !empty($record['block_file_editor'])) {
            $allcaps['edit_plugins'] = false;
            $allcaps['edit_themes']  = false;
            $allcaps['edit_files']   = false;
        }

        // Disallow core tools, database export, import, and personal data erasure
        if (!isset($record['block_tools_and_exports']) || !empty($record['block_tools_and_exports'])) {
            $allcaps['export']                      = false;
            $allcaps['import']                      = false;
            $allcaps['erase_others_personal_data']  = false;
            $allcaps['manage_privacy_options']      = false;
            $allcaps['export_others_personal_data'] = false;
        }

        // Disallow dashboard customization & options
        if (!isset($record['block_database_and_options']) || !empty($record['block_database_and_options'])) {
            $allcaps['edit_dashboard'] = false;
            $allcaps['customize']      = false;
        }

        // If vault restricted, disallow export and credential viewing
        if (!empty($record['restrict_vault'])) {
            $allcaps['export'] = false;
        }

        return $allcaps;
    }

    /**
     * Find or create the dedicated temporary technician user.
     *
     * @param array $record
     * @return \WP_User|null
     */
    private static function get_or_create_support_user(array $record): ?\WP_User {
        $username = 'wcp_support_tech';
        $user = get_user_by('login', $username);

        if (!$user) {
            $user_id = wp_create_user($username, wp_generate_password(32, true, true), 'support-technician@local.invalid');
            if (is_wp_error($user_id)) {
                return null;
            }
            $user = get_userdata($user_id);
            if ($user) {
                $user->set_role('administrator');
                $user->display_name = 'External Support Technician';
                wp_update_user($user);
            }
        } else {
            if (!in_array('administrator', $user->roles, true)) {
                $user->set_role('administrator');
            }
        }

        return $user ?: null;
    }

    /**
     * Check if an IP address falls within a CIDR range.
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    private static function ip_in_range(string $ip, string $range): bool {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }

        $mask = -1 << (32 - (int) $bits);
        return ($ip_long & $mask) === ($subnet_long & $mask);
    }
}
