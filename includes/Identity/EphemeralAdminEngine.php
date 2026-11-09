<?php
namespace WebCareProScanner\Identity;

use WebCareProScanner\System\AuditLogger;

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

    const OPTION_EPHEMERAL_ADMINS = 'webcareproscan_ephemeral_admins';
    const CRON_HOOK               = 'webcareproscan_ephemeral_admin_expire';

    /**
     * Bootstrap Ephemeral Admin engine.
     */
    public static function init() {
        // Emergency bypass constant: define('WCP_DISABLE_JIT', true); in wp-config.php completely disables JIT restrictions
        if (defined('WCP_DISABLE_JIT') && WCP_DISABLE_JIT) {
            return;
        }

        // Auto-install / sync the Must-Use (MU) plugin watchdog
        if (class_exists('\\WebCareProScanner\\Identity\\WcpJitMuGuardian')) {
            WcpJitMuGuardian::ensure_installed();
        }

        // Cron expiration handler
        add_action(self::CRON_HOOK, [__CLASS__, 'on_cron_expire_elevation'], 10, 1);

        // Safety fallback check on admin page requests
        add_action('admin_init', [__CLASS__, 'check_and_expire_elevations'], 1);

        // Admin bar badge notification for elevated user
        add_action('admin_bar_menu', [__CLASS__, 'render_admin_bar_badge'], 99);

        // Protect WebCare Pro Security from deactivation & deletion by elevated users
        add_filter('plugin_action_links_' . plugin_basename(WEBCAREPROSCAN_FILE), [__CLASS__, 'filter_plugin_action_links'], 20);
        add_action('admin_init', [__CLASS__, 'intercept_unauthorized_plugin_actions'], 1);
        add_filter('map_meta_cap', [__CLASS__, 'restrict_elevated_admin_capabilities'], 10, 4);

        // Cache busting hooks for primary admin resolution
        add_action('user_register', [__CLASS__, 'clear_primary_admin_cache']);
        add_action('deleted_user', [__CLASS__, 'clear_primary_admin_cache']);
        add_action('set_user_role', [__CLASS__, 'clear_primary_admin_cache']);
        add_action('remove_user_role', [__CLASS__, 'clear_primary_admin_cache']);
        add_action('update_option_admin_email', [__CLASS__, 'clear_primary_admin_cache']);
    }

    /**
     * Clear cached first registered administrator ID on user or role mutations.
     */
    public static function clear_primary_admin_cache() {
        delete_transient('webcareproscan_first_admin_id');
    }

    /**
     * Determine if a user is a primary site owner / root administrator.
     * Evaluates multi-signal hierarchy to prevent lockouts even if user ID 1 was reassigned (e.g. Solid Security).
     *
     * Order of evaluation:
     * 1. Multisite Super Admin check (is_super_admin)
     * 2. WordPress site settings match: get_option('admin_email')
     * 3. Oldest registered administrator in wp_users
     * 4. User ID 1 fallback (only if the account actively possesses manage_options)
     *
     * @param int $user_id
     * @return bool
     */
    public static function is_primary_admin(int $user_id): bool {
        if ($user_id <= 0) {
            return false;
        }

        // 1. Multisite Super Admin protection
        if (is_multisite() && function_exists('is_super_admin') && is_super_admin($user_id)) {
            return true;
        }

        $user = get_userdata($user_id);
        if (!$user) {
            return false;
        }

        // 2. Exact match with site admin_email option
        $site_admin_email = (string) get_option('admin_email');
        if (!empty($site_admin_email) && !empty($user->user_email) && strcasecmp($user->user_email, $site_admin_email) === 0) {
            return true;
        }

        // 3. Oldest registered administrator in database
        $first_admin_id = self::get_first_registered_admin_id();
        if ($first_admin_id > 0 && $user_id === $first_admin_id) {
            return true;
        }

        // 4. User ID 1 fallback, guarded by active capability check
        if ($user_id === 1 && (user_can($user, 'manage_options') || in_array('administrator', (array) $user->roles, true))) {
            return true;
        }

        return false;
    }

    /**
     * Resolve the ID of the oldest registered administrator account.
     * Cached via memory and transient to eliminate redundant SQL overhead.
     *
     * @return int
     */
    public static function get_first_registered_admin_id(): int {
        static $memory_cache = null;
        if ($memory_cache !== null) {
            return $memory_cache;
        }

        $transient_key = 'webcareproscan_first_admin_id';
        $stored = get_transient($transient_key);
        if ($stored !== false && is_numeric($stored)) {
            $memory_cache = (int) $stored;
            return $memory_cache;
        }

        global $wpdb;
        $cap_key = $wpdb->get_blog_prefix() . 'capabilities';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $admin_candidates = $wpdb->get_results($wpdb->prepare(
            "SELECT u.ID, m.meta_value FROM {$wpdb->users} u
             INNER JOIN {$wpdb->usermeta} m ON u.ID = m.user_id
             WHERE m.meta_key = %s
             ORDER BY u.user_registered ASC, u.ID ASC
             LIMIT 50",
            $cap_key
        ));

        $found_id = 0;
        if (!empty($admin_candidates)) {
            foreach ($admin_candidates as $cand) {
                $caps = maybe_unserialize($cand->meta_value);
                if (is_array($caps) && !empty($caps['administrator'])) {
                    $found_id = (int) $cand->ID;
                    break;
                }
            }
        }

        if ($found_id === 0) {
            $found_id = 1;
        }

        $memory_cache = $found_id;
        set_transient($transient_key, $found_id, HOUR_IN_SECONDS * 12);
        return $found_id;
    }

    /**
     * Filter plugin action links on plugins.php: Replace "Deactivate" with a protected badge if current user is JIT elevated.
     *
     * @param array $actions
     * @return array
     */
    public static function filter_plugin_action_links(array $actions): array {
        $user_id = get_current_user_id();
        if ($user_id && self::is_user_elevated($user_id)) {
            if (isset($actions['deactivate'])) {
                $actions['deactivate'] = '<span style="color:#94a3b8;font-weight:600;cursor:not-allowed;" title="' . esc_attr__('Deactivation is strictly disabled while your account has temporary Just-In-Time (JIT) elevation.', 'webcare-pro-security') . '">' . esc_html__('Deactivation Locked (JIT)', 'webcare-pro-security') . '</span>';
            }
        }
        return $actions;
    }

    /**
     * Intercept direct HTTP GET/POST deactivation and deletion attempts by JIT elevated users.
     */
    public static function intercept_unauthorized_plugin_actions() {
        $user_id = get_current_user_id();
        if (!$user_id || !self::is_user_elevated($user_id)) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $plugin = isset($_REQUEST['plugin']) ? sanitize_text_field(wp_unslash($_REQUEST['plugin'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $checked = isset($_REQUEST['checked']) && is_array($_REQUEST['checked']) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['checked'])) : [];

        $is_targeting_wcp = false;
        if ($plugin && strpos($plugin, 'webcare-pro-security') !== false) {
            $is_targeting_wcp = true;
        }

        if (!empty($checked)) {
            foreach ($checked as $p) {
                if (strpos($p, 'webcare-pro-security') !== false) {
                    $is_targeting_wcp = true;
                    break;
                }
            }
        }

        if ($is_targeting_wcp && in_array($action, ['deactivate', 'delete-selected', 'deactivate-selected'], true)) {
            AuditLogger::log(
                'jit_tamper_attempt_blocked',
                sprintf('Security alert: JIT elevated user (ID %d) attempted to deactivate or delete WebCare Pro Security. Action was blocked.', $user_id)
            );

            wp_die(
                '<h1>' . esc_html__('Security Access Denied', 'webcare-pro-security') . '</h1>' .
                '<p>' . esc_html__('Users with temporary Just-In-Time (JIT) Administrative elevation are strictly prohibited from deactivating or deleting WebCare Pro Security.', 'webcare-pro-security') . '</p>' .
                '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('← Return to Plugins', 'webcare-pro-security') . '</a></p>',
                esc_html__('Security Access Denied', 'webcare-pro-security'),
                ['response' => 403]
            );
        }
    }

    /**
     * Map meta capabilities to forbid JIT elevated admins from deactivating WCP or modifying permanent admins.
     *
     * @param array $caps
     * @param string $cap
     * @param int $user_id
     * @param array $args
     * @return array
     */
    public static function restrict_elevated_admin_capabilities(array $caps, string $cap, int $user_id, array $args): array {
        if (!$user_id || !self::is_user_elevated($user_id)) {
            return $caps;
        }

        // Prevent deactivating WebCare Pro Security
        if ($cap === 'deactivate_plugin' || $cap === 'deactivate_plugins') {
            $target_plugin = !empty($args[0]) ? $args[0] : '';
            if (empty($target_plugin) || strpos($target_plugin, 'webcare-pro-security') !== false) {
                return ['do_not_allow'];
            }
        }

        // Prevent modifying, demoting, or deleting permanent administrator accounts
        if (in_array($cap, ['delete_user', 'edit_user', 'remove_user'], true)) {
            $target_uid = !empty($args[0]) ? (int) $args[0] : 0;
            if ($target_uid && $target_uid !== $user_id) {
                $target_user = get_userdata($target_uid);
                if ($target_user && in_array('administrator', (array) $target_user->roles, true)) {
                    if (!self::is_user_elevated($target_uid)) {
                        return ['do_not_allow'];
                    }
                }
            }
        }

        return $caps;
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
                'message' => __('User not found.', 'webcare-pro-security'),
            ];
        }

        $current_roles = (array) $user->roles;
        $baseline_role = reset($current_roles) ?: 'subscriber';

        // Safety Guardrail: Primary site administrators are permanently immune from JIT restriction or demotion
        if (self::is_primary_admin($user_id)) {
            return [
                'success' => false,
                'message' => __('Primary site administrator / site owner is permanently immune from JIT restriction or demotion.', 'webcare-pro-security'),
            ];
        }

        if ($baseline_role === 'administrator') {
            return [
                'success' => false,
                'message' => __('User is already a permanent administrator.', 'webcare-pro-security'),
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

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_temporary_access_granted', [
                'severity' => 'high',
                /* translators: 1: user login, 2: duration in minutes */
                'message'  => sprintf(__('JIT Ephemeral Administrator elevation granted to %1$s for %2$d minutes.', 'webcare-pro-security'), $user->user_login, $duration_minutes),
                'details'  => [
                    'Elevated User'  => $user->user_login,
                    'Baseline Role'  => $baseline_role,
                    'Duration'       => $duration_minutes . ' minutes',
                    'Granted By'     => $entry['granted_by_login'] ?? 'admin',
                    'Reason'         => $entry['reason'],
                ],
            ]);
        }

        /* translators: 1: user login, 2: duration in minutes */
        $msg = sprintf(__('JIT Admin elevation granted to %1$s for %2$d minutes.', 'webcare-pro-security'), $user->user_login, $duration_minutes);
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
                'message' => __('No active temporary elevation found for this user.', 'webcare-pro-security'),
            ];
        }

        $entry = $elevations[$user_id];
        $baseline_role = $entry['baseline_role'] ?? 'subscriber';

        $user = get_userdata($user_id);
        if (self::is_primary_admin($user_id)) {
            unset($elevations[$user_id]);
            update_option(self::OPTION_EPHEMERAL_ADMINS, $elevations);
            return [
                'success' => false,
                'message' => __('Cannot alter role for primary site administrator or site owner.', 'webcare-pro-security'),
            ];
        }

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

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_temporary_access_revoked', [
                'severity' => 'info',
                /* translators: 1: user login, 2: restored baseline role name */
                'message'  => sprintf(__('JIT Ephemeral Administrator elevation revoked for %1$s. Restored to %2$s.', 'webcare-pro-security'), $entry['user_login'] ?? "ID {$user_id}", $baseline_role),
                'details'  => [
                    'User Account'   => $entry['user_login'] ?? "ID {$user_id}",
                    'Restored Role'  => $baseline_role,
                    'Revoke Reason'  => $reason,
                ],
            ]);
        }

        /* translators: 1: user login, 2: restored baseline role name */
        $msg = sprintf(__('Elevation revoked. User %1$s reverted to %2$s.', 'webcare-pro-security'), $entry['user_login'], $baseline_role);
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
        if (self::is_primary_admin($user_id)) {
            unset($elevations[$user_id]);
            update_option(self::OPTION_EPHEMERAL_ADMINS, $elevations);
            return [
                'success' => false,
                'message' => __('Cannot alter role for primary site administrator or site owner.', 'webcare-pro-security'),
            ];
        }

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

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_temporary_access_revoked', [
                'severity' => 'info',
                /* translators: 1: user login, 2: restored baseline role name */
                'message'  => sprintf(__('JIT Ephemeral Administrator elevation expired for %1$s. Automatically restored to %2$s.', 'webcare-pro-security'), $entry['user_login'] ?? "ID {$user_id}", $baseline_role),
                'details'  => [
                    'User Account'   => $entry['user_login'] ?? "ID {$user_id}",
                    'Restored Role'  => $baseline_role,
                    'Revoke Reason'  => 'time_expired',
                ],
            ]);
        }
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
        $history = get_option('webcareproscan_ephemeral_admin_history', []);
        if (!is_array($history)) {
            return [];
        }
        return array_slice($history, 0, $limit);
    }

    /**
     * Archive an expired or revoked elevation entry into history.
     */
    private static function archive_elevation_record(array $entry) {
        $history = get_option('webcareproscan_ephemeral_admin_history', []);
        if (!is_array($history)) {
            $history = [];
        }
        array_unshift($history, $entry);
        if (count($history) > 100) {
            $history = array_slice($history, 0, 100);
        }
        update_option('webcareproscan_ephemeral_admin_history', $history);
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

            // Filter out permanent administrators and protected primary owners
            $is_elevated = isset($active_elevations[$user->ID]);
            if (self::is_primary_admin((int) $user->ID) || (in_array('administrator', $roles, true) && !$is_elevated)) {
                continue; // Permanent administrator / primary site owner, cannot elevate
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
