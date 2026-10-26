<?php
namespace WcpScanner\Identity;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * EphemeralAdminEngine
 *
 * Pillar 4: Zero-Trust Ephemeral Just-In-Time (JIT) Admin Elevation.
 * Prevents permanent administrative privilege creep on WordPress sites.
 * Allows site owners to temporarily elevate non-admin users (e.g. editors, contractors, developers)
 * to administrator for a defined time window (e.g. 1 hour, 4 hours, 24 hours).
 * Automatically de-elevates back to baseline role via WP-Cron, displays visual admin bar countdown,
 * and maintains an immutable audit trail.
 */
class EphemeralAdminEngine {

    const OPTION_EPHEMERAL_ADMINS = 'wcpscan_ephemeral_admins';
    const CRON_HOOK               = 'wcpscan_ephemeral_admin_expire';

    /**
     * Bootstrap Ephemeral Admin engine.
     */
    public static function init() {
        // Cron expiration handler
        add_action(self::CRON_HOOK, [__CLASS__, 'on_cron_expire_elevation'], 10, 1);

        // Safety fallback check on admin page requests
        add_action('admin_init', [__CLASS__, 'check_and_expire_elevations'], 1);

        // Admin bar badge notification for elevated user
        add_action('admin_bar_menu', [__CLASS__, 'render_admin_bar_badge'], 99);
    }

    /**
     * Grant temporary Just-In-Time (JIT) administrative privileges to a user.
     *
     * @param int $user_id
     * @param int $duration_minutes
     * @param string $reason
     * @param int $granted_by
     * @return array
     */
    public static function grant_elevation(int $user_id, int $duration_minutes = 60, string $reason = '', int $granted_by = 0): array {
        $user = get_userdata($user_id);
        if (!$user) {
            return [
                'success' => false,
                'message' => __('User not found.', 'wcp-security-scanner'),
            ];
        }

        $current_roles = (array) $user->roles;
        $baseline_role = reset($current_roles) ?: 'subscriber';

        if ($baseline_role === 'administrator') {
            return [
                'success' => false,
                'message' => __('User is already a permanent administrator.', 'wcp-security-scanner'),
            ];
        }

        $duration_minutes = max(15, min(10080, $duration_minutes)); // Between 15 mins and 7 days
        $expires_at = time() + ($duration_minutes * 60);

        // Capture elevation entry
        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($elevations)) {
            $elevations = [];
        }

        $elevation_id = 'jit_' . $user_id . '_' . time();
        $granter_id = $granted_by ?: get_current_user_id();
        $granter = get_userdata($granter_id);

        $entry = [
            'id'               => $elevation_id,
            'user_id'          => $user_id,
            'user_login'       => $user->user_login,
            'user_email'       => $user->user_email,
            'display_name'     => $user->display_name,
            'baseline_role'    => $baseline_role,
            'granted_at'       => time(),
            'expires_at'       => $expires_at,
            'duration_minutes' => $duration_minutes,
            'reason'           => sanitize_text_field($reason ?: 'Temporary troubleshooting/maintenance'),
            'granted_by_id'    => $granter_id,
            'granted_by_login' => $granter ? $granter->user_login : 'admin',
            'status'           => 'active',
        ];

        // Elevate user role to administrator
        $user->set_role('administrator');

        // Schedule WP-Cron auto-expiry
        wp_clear_scheduled_hook(self::CRON_HOOK, [$user_id]);
        wp_schedule_single_event($expires_at, self::CRON_HOOK, [$user_id]);

        $elevations[$user_id] = $entry;
        update_option(self::OPTION_EPHEMERAL_ADMINS, $elevations);

        AuditLogger::log(
            'jit_elevation_granted',
            sprintf(
                'JIT Ephemeral Elevation granted to user "%s" (baseline: %s) for %d minutes. Reason: %s',
                $user->user_login,
                $baseline_role,
                $duration_minutes,
                $entry['reason']
            )
        );

        /* translators: 1: user login, 2: duration in minutes */
        $msg = sprintf(__('JIT Admin elevation granted to %1$s for %2$d minutes.', 'wcp-security-scanner'), $user->user_login, $duration_minutes);
        return [
            'success'   => true,
            'message'   => $msg,
            'elevation' => $entry,
        ];
    }

    /**
     * Manually revoke temporary elevation and restore baseline role.
     *
     * @param int $user_id
     * @param string $reason
     * @return array
     */
    public static function revoke_elevation(int $user_id, string $reason = 'manual_revocation'): array {
        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($elevations) || empty($elevations[$user_id])) {
            return [
                'success' => false,
                'message' => __('No active temporary elevation found for this user.', 'wcp-security-scanner'),
            ];
        }

        $entry = $elevations[$user_id];
        $baseline_role = $entry['baseline_role'] ?? 'subscriber';

        $user = get_userdata($user_id);
        if ($user) {
            $user->set_role($baseline_role);
        }

        // Clear scheduled event
        wp_clear_scheduled_hook(self::CRON_HOOK, [$user_id]);

        // Update record
        $entry['status']     = 'revoked';
        $entry['revoked_at'] = time();
        $entry['revoke_reason'] = $reason;

        // Archive into history and remove active
        unset($elevations[$user_id]);
        update_option(self::OPTION_EPHEMERAL_ADMINS, $elevations);

        self::archive_elevation_record($entry);

        AuditLogger::log(
            'jit_elevation_revoked',
            sprintf('JIT Ephemeral Elevation revoked for user "%s". Restored to baseline role "%s".', $entry['user_login'] ?? "ID {$user_id}", $baseline_role)
        );

        /* translators: 1: user login, 2: restored baseline role name */
        $msg = sprintf(__('Elevation revoked. User %1$s reverted to %2$s.', 'wcp-security-scanner'), $entry['user_login'], $baseline_role);
        return [
            'success' => true,
            'message' => $msg,
        ];
    }

    /**
     * Cron callback: automatically expire elevation and restore baseline role.
     *
     * @param int $user_id
     */
    public static function on_cron_expire_elevation(int $user_id) {
        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($elevations) || empty($elevations[$user_id])) {
            return;
        }

        $entry = $elevations[$user_id];
        $baseline_role = $entry['baseline_role'] ?? 'subscriber';

        $user = get_userdata($user_id);
        if ($user) {
            $user->set_role($baseline_role);
        }

        $entry['status']     = 'expired';
        $entry['expired_at'] = time();

        unset($elevations[$user_id]);
        update_option(self::OPTION_EPHEMERAL_ADMINS, $elevations);

        self::archive_elevation_record($entry);

        AuditLogger::log(
            'jit_elevation_expired',
            sprintf('JIT Ephemeral Elevation time expired for user "%s". Automatically restored to baseline role "%s".', $entry['user_login'] ?? "ID {$user_id}", $baseline_role)
        );
    }

    /**
     * Check and expire any overdue elevations if cron execution was delayed.
     */
    public static function check_and_expire_elevations() {
        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($elevations) || empty($elevations)) {
            return;
        }

        $now = time();
        foreach ($elevations as $user_id => $entry) {
            if (!empty($entry['expires_at']) && $entry['expires_at'] <= $now) {
                self::on_cron_expire_elevation((int) $user_id);
            }
        }
    }

    /**
     * Render countdown badge in WordPress admin bar if the current user is elevated.
     *
     * @param \WP_Admin_Bar $wp_admin_bar
     */
    public static function render_admin_bar_badge(\WP_Admin_Bar $wp_admin_bar) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return;
        }

        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($elevations) || empty($elevations[$user_id])) {
            return;
        }

        $entry = $elevations[$user_id];
        $remaining_seconds = max(0, ($entry['expires_at'] ?? 0) - time());
        $remaining_mins = ceil($remaining_seconds / 60);

        $badge_title = sprintf('⚡ JIT Admin: %dm left', $remaining_mins);

        $wp_admin_bar->add_node([
            'id'    => 'wcp-jit-elevation-badge',
            'title' => '<span style="background:#ea580c;color:#ffffff;padding:2px 8px;border-radius:10px;font-weight:700;font-size:11px;">' . esc_html($badge_title) . '</span>',
            'href'  => admin_url('admin.php?page=wcp-security-auth&tab=zero_trust'),
            'meta'  => [
                'title' => sprintf('Temporary elevation expires in %d minutes. Click to view Zero-Trust details.', $remaining_mins),
            ],
        ]);
    }

    /**
     * Check if a user is currently elevated under JIT.
     *
     * @param int $user_id
     * @return bool
     */
    public static function is_user_elevated(int $user_id): bool {
        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        return is_array($elevations) && isset($elevations[$user_id]);
    }

    /**
     * Get all active elevations with live remaining minutes.
     *
     * @return array
     */
    public static function get_active_elevations(): array {
        $elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($elevations)) {
            return [];
        }

        $now = time();
        $active = [];
        foreach ($elevations as $uid => $entry) {
            $remaining = max(0, ($entry['expires_at'] ?? 0) - $now);
            $entry['remaining_seconds'] = $remaining;
            $entry['remaining_minutes'] = ceil($remaining / 60);
            $entry['is_expired'] = ($remaining === 0);
            $active[] = $entry;
        }

        return $active;
    }

    /**
     * Get recent elevation history.
     *
     * @param int $limit
     * @return array
     */
    public static function get_elevation_history(int $limit = 25): array {
        $history = get_option('wcpscan_ephemeral_admin_history', []);
        if (!is_array($history)) {
            return [];
        }
        return array_slice($history, 0, $limit);
    }

    /**
     * Archive an expired or revoked elevation entry into history.
     */
    private static function archive_elevation_record(array $entry) {
        $history = get_option('wcpscan_ephemeral_admin_history', []);
        if (!is_array($history)) {
            $history = [];
        }
        array_unshift($history, $entry);
        if (count($history) > 100) {
            $history = array_slice($history, 0, 100);
        }
        update_option('wcpscan_ephemeral_admin_history', $history);
    }

    /**
     * Get candidate non-admin users available for temporary JIT elevation.
     *
     * @param int $limit
     * @return array
     */
    public static function get_candidate_users(int $limit = 200): array {
        $users = get_users([
            'number'  => $limit,
            'orderby' => 'display_name',
            'order'   => 'ASC',
        ]);

        $candidates = [];
        $active_elevations = get_option(self::OPTION_EPHEMERAL_ADMINS, []);
        if (!is_array($active_elevations)) {
            $active_elevations = [];
        }

        foreach ($users as $user) {
            $roles = (array) $user->roles;
            $primary_role = reset($roles) ?: 'subscriber';

            // Filter out permanent administrators unless currently elevated via JIT
            $is_elevated = isset($active_elevations[$user->ID]);
            if (in_array('administrator', $roles, true) && !$is_elevated) {
                continue; // Permanent administrator, cannot elevate
            }

            $candidates[] = [
                'id'           => (int) $user->ID,
                'user_login'   => $user->user_login,
                'display_name' => !empty($user->display_name) ? $user->display_name : $user->user_login,
                'user_email'   => $user->user_email,
                'role'         => $is_elevated ? ($active_elevations[$user->ID]['baseline_role'] ?? $primary_role) : $primary_role,
                'is_elevated'  => $is_elevated,
            ];
        }

        return $candidates;
    }
}
