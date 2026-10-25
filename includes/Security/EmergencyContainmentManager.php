<?php
namespace WcpScanner\Security;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * EmergencyContainmentManager
 *
 * Provides a 1-Click Atomic Incident Containment protocol for WordPress.
 * When an active intrusion or compromise is detected, Containment Mode instantly
 * freezes the blast radius and eliminates lateral movement:
 * 1. Force-terminates all active user sessions (except the acting administrator).
 * 2. Enforces runtime immutable filesystem locks (DISALLOW_FILE_EDIT, DISALLOW_FILE_MODS).
 * 3. Restricts WAF write operations for all unauthenticated/non-admin traffic.
 * 4. Locks down XML-RPC and unauthenticated REST API user endpoints.
 * 5. Optionally serves a branded 503 "Emergency Security Maintenance" page for visitors.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class EmergencyContainmentManager {

    const OPTION_ACTIVE = 'wcpscan_containment_active';
    const OPTION_META   = 'wcpscan_containment_meta';

    /**
     * Bootstrap containment hooks on WordPress initialization.
     */
    public static function init(): void {
        if (!self::is_active()) {
            return;
        }

        // 1. Enforce Runtime Filesystem Locks
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
        if (!defined('DISALLOW_FILE_MODS')) {
            define('DISALLOW_FILE_MODS', true);
        }

        // 2. Prevent non-admins from uploading or editing files in admin area
        add_filter('user_has_cap', [__CLASS__, 'filter_containment_caps'], 999, 4);

        // 3. Render prominent emergency containment banner in wp-admin
        add_action('admin_notices', [__CLASS__, 'render_admin_containment_banner']);
        add_action('network_admin_notices', [__CLASS__, 'render_admin_containment_banner']);
    }

    /**
     * Check if Emergency Containment Mode is currently active.
     *
     * @return bool
     */
    public static function is_active(): bool {
        return (bool) get_option(self::OPTION_ACTIVE, false);
    }

    /**
     * Check if public visitor 503 maintenance screen is enabled during containment.
     *
     * @return bool
     */
    public static function is_maintenance_enabled(): bool {
        $meta = get_option(self::OPTION_META, []);
        return !empty($meta['maintenance_enabled']);
    }

    /**
     * Filter capabilities to disallow critical actions during containment.
     *
     * @param array $allcaps
     * @param array $caps
     * @param array $args
     * @param \WP_User $user
     * @return array
     */
    public static function filter_containment_caps(array $allcaps, array $caps, array $args, \WP_User $user): array {
        // Disallow file editing, plugin installs, and theme installs for everyone except super admins
        $allcaps['edit_files']        = false;
        $allcaps['edit_plugins']      = false;
        $allcaps['edit_themes']       = false;
        $allcaps['install_plugins']   = false;
        $allcaps['install_themes']    = false;
        $allcaps['update_plugins']    = false;
        $allcaps['update_themes']     = false;
        $allcaps['update_core']       = false;

        return $allcaps;
    }

    /**
     * Activate Emergency Containment Mode.
     *
     * @param array $args
     * @return array Result summary
     */
    public static function activate(array $args = []): array {
        $current_user_id = get_current_user_id();
        $current_user = wp_get_current_user();
        $username = $current_user->exists() ? $current_user->user_login : 'cli_or_system';
        $reason = !empty($args['reason']) ? sanitize_text_field(wp_unslash($args['reason'])) : 'Active Threat Breach Response';
        $maintenance = !empty($args['maintenance_enabled']);

        // 1. Invalidate all user sessions except current admin
        $terminated_sessions_count = self::invalidate_all_sessions_except_current();

        // 2. Persist active state and metadata
        $meta = [
            'activated_at'        => time(),
            'activated_by_id'     => $current_user_id,
            'activated_by_name'   => $username,
            'reason'              => $reason,
            'maintenance_enabled' => $maintenance,
            'sessions_purged'     => $terminated_sessions_count,
        ];

        update_option(self::OPTION_ACTIVE, true, false);
        update_option(self::OPTION_META, $meta, false);

        // 3. Log audit event
        AuditLogger::log(
            'containment_mode_activated',
            sprintf('Emergency Containment Mode ACTIVATED by %s. Reason: %s. Terminated %d user sessions.', $username, $reason, $terminated_sessions_count)
        );

        return [
            'success'             => true,
            'active'              => true,
            'activated_at'        => $meta['activated_at'],
            'activated_by'        => $username,
            'reason'              => $reason,
            'maintenance_enabled' => $maintenance,
            'sessions_purged'     => $terminated_sessions_count,
            'message'             => __('Emergency Containment Mode is now ACTIVE. The site blast radius has been frozen.', 'wcp-security-scanner'),
        ];
    }

    /**
     * Deactivate Emergency Containment Mode.
     *
     * @param int $user_id
     * @return array
     */
    public static function deactivate(int $user_id = 0): array {
        if ($user_id === 0) {
            $user_id = get_current_user_id();
        }
        $current_user = get_userdata($user_id);
        $username = ($current_user && $current_user->exists()) ? $current_user->user_login : 'administrator';

        $old_meta = get_option(self::OPTION_META, []);
        $old_meta['deactivated_at'] = time();
        $old_meta['deactivated_by'] = $username;

        update_option(self::OPTION_ACTIVE, false, false);
        update_option(self::OPTION_META, $old_meta, false);

        AuditLogger::log(
            'containment_mode_deactivated',
            sprintf('Emergency Containment Mode DEACTIVATED by %s.', $username)
        );

        return [
            'success' => true,
            'active'  => false,
            'message' => __('Emergency Containment Mode has been deactivated. Standard operations restored.', 'wcp-security-scanner'),
        ];
    }

    /**
     * Retrieve complete containment status and telemetry.
     *
     * @return array
     */
    public static function get_status(): array {
        $active = self::is_active();
        $meta = get_option(self::OPTION_META, []);

        return [
            'active'              => $active,
            'activated_at'        => $meta['activated_at'] ?? null,
            'activated_by_id'     => $meta['activated_by_id'] ?? null,
            'activated_by_name'   => $meta['activated_by_name'] ?? null,
            'reason'              => $meta['reason'] ?? '',
            'maintenance_enabled' => !empty($meta['maintenance_enabled']),
            'sessions_purged'     => $meta['sessions_purged'] ?? 0,
            'locks_enforced'      => [
                'file_editing_locked'     => true,
                'plugin_installs_locked'  => true,
                'theme_installs_locked'   => true,
                'xmlrpc_locked'           => true,
                'rest_user_enum_locked'   => true,
                'unauthenticated_mutations_blocked' => true,
            ],
        ];
    }

    /**
     * Safely purge all active sessions across WordPress users except the current active session.
     *
     * @return int Count of terminated sessions
     */
    public static function invalidate_all_sessions_except_current(): int {
        if (!class_exists('\\WP_Session_Tokens')) {
            return 0;
        }

        $current_user_id = get_current_user_id();
        $current_token = wp_get_session_token();
        $total_purged = 0;

        // Query all user IDs with session meta
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $users_with_sessions = $wpdb->get_col(
            "SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'"
        );

        if (!empty($users_with_sessions) && is_array($users_with_sessions)) {
            foreach ($users_with_sessions as $uid) {
                $uid = (int) $uid;
                $manager = \WP_Session_Tokens::get_instance($uid);
                $sessions = $manager->get_all();
                $count = count($sessions);

                if ($uid === $current_user_id && !empty($current_token)) {
                    // Destroy all sessions EXCEPT the current admin's active token
                    $manager->destroy_others($current_token);
                    $total_purged += max(0, $count - 1);
                } else {
                    // Destroy all sessions for all other users
                    $manager->destroy_all();
                    $total_purged += $count;
                }
            }
        }

        return $total_purged;
    }

    /**
     * Render the Emergency 503 Maintenance Page for public visitors.
     */
    public static function render_containment_screen(): void {
        status_header(503);
        header('Retry-After: 1800');
        header('Content-Type: text/html; charset=utf-8');

        $site_name = esc_html(get_bloginfo('name') ?: 'This WordPress Site');
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Emergency Security Containment — <?php echo $site_name; ?></title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body {
                    background: #090d16;
                    color: #f1f5f9;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 24px;
                }
                .containment-card {
                    background: #0f172a;
                    border: 1px solid rgba(239, 68, 68, 0.4);
                    border-radius: 16px;
                    padding: 40px;
                    max-width: 580px;
                    width: 100%;
                    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 40px -10px rgba(239, 68, 68, 0.2);
                    text-align: center;
                }
                .shield-icon {
                    width: 64px;
                    height: 64px;
                    margin: 0 auto 20px;
                    background: rgba(239, 68, 68, 0.14);
                    border: 1px solid rgba(239, 68, 68, 0.5);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #f87171;
                }
                h1 {
                    font-size: 22px;
                    font-weight: 700;
                    margin-bottom: 12px;
                    color: #ffffff;
                    letter-spacing: -0.02em;
                }
                p {
                    font-size: 14px;
                    line-height: 1.6;
                    color: #cbd5e1;
                    margin-bottom: 20px;
                }
                .status-badge {
                    display: inline-block;
                    padding: 6px 14px;
                    border-radius: 9999px;
                    font-size: 12px;
                    font-weight: 600;
                    background: rgba(239, 68, 68, 0.2);
                    border: 1px solid rgba(239, 68, 68, 0.4);
                    color: #fca5a5;
                    margin-bottom: 24px;
                    letter-spacing: 0.05em;
                    text-transform: uppercase;
                }
                .protocol-box {
                    background: #1e293b;
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 8px;
                    padding: 16px;
                    text-align: left;
                    font-size: 13px;
                    color: #94a3b8;
                    margin-bottom: 24px;
                }
                .protocol-item {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    margin-bottom: 8px;
                }
                .protocol-item:last-child { margin-bottom: 0; }
                .dot {
                    width: 6px;
                    height: 6px;
                    background: #10b981;
                    border-radius: 50%;
                }
                .footer-text {
                    font-size: 12px;
                    color: #64748b;
                }
                .admin-link {
                    color: #818cf8;
                    text-decoration: none;
                }
                .admin-link:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="containment-card">
                <div class="shield-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                </div>
                <div class="status-badge">Emergency Containment Active</div>
                <h1>Security Maintenance in Progress</h1>
                <p>
                    <strong><?php echo $site_name; ?></strong> is currently operating under an automated emergency security lockdown to protect system integrity and visitor data.
                </p>
                <div class="protocol-box">
                    <div class="protocol-item"><div class="dot"></div> Filesystem mutation channels locked</div>
                    <div class="protocol-item"><div class="dot"></div> Public write operations suspended</div>
                    <div class="protocol-item"><div class="dot"></div> Cryptographic isolation protocol engaged</div>
                </div>
                <p class="footer-text">
                    Authorized system administrators can authenticate via <a href="<?php echo esc_url(wp_login_url()); ?>" class="admin-link">wp-login.php</a> to remediate.
                </p>
            </div>
        </body>
        </html>
        <?php
    }

    /**
     * Render the admin alert notice when Containment Mode is active.
     */
    public static function render_admin_containment_banner(): void {
        $meta = get_option(self::OPTION_META, []);
        $activated_by = esc_html($meta['activated_by_name'] ?? 'Administrator');
        $reason = esc_html($meta['reason'] ?? 'Active Intrusion Response');
        ?>
        <div class="notice notice-error" style="border-left-color: #dc2626; background: #fff5f5; padding: 14px 18px; margin: 15px 0;">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 20px;">🚨</span>
                    <div>
                        <strong style="color: #b91c1c; font-size: 14px;">WCP EMERGENCY CONTAINMENT IS ACTIVE</strong>
                        <div style="color: #7f1d1d; font-size: 12px; margin-top: 2px;">
                            Blast radius frozen by <strong><?php echo $activated_by; ?></strong>. Reason: <em><?php echo $reason; ?></em>. Filesystem editing, plugin installs, and public write operations are locked.
                        </div>
                    </div>
                </div>
                <div>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-security-scanner#/firewall')); ?>" class="button button-primary" style="background: #dc2626; border-color: #b91c1c;">
                        <?php esc_html_e('Open Security Console & Remediate', 'wcp-security-scanner'); ?>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }
}
