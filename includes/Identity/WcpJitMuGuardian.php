<?php
namespace WcpScanner\Identity;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WcpJitMuGuardian
 *
 * Installs and maintains an infallible Must-Use (MU) plugin watchdog:
 * `wp-content/mu-plugins/wcp-jit-guardian.php`.
 *
 * Architecture & Purpose:
 * Must-Use plugins execute on EVERY request before standard plugins load and
 * CANNOT be deactivated via the WordPress admin UI.
 *
 * This guardian guarantees:
 * 1. Even if WCP Security Scanner is somehow deactivated or inoperative, JIT elevations
 *    cannot escape their expiration: the MU-plugin checks `wcpscan_ephemeral_admins` on every
 *    request and auto-restores baseline roles.
 * 2. If WCP Security Scanner is deactivated while any JIT elevations are active, the watchdog
 *    immediately reverts all elevated users to their baseline roles.
 * 3. Any attempt by an active JIT elevated user to deactivate or delete WCP Security Scanner
 *    is unconditionally aborted at the earliest WordPress bootstrap hook (`muplugins_loaded`).
 * 4. JIT elevated users are prevented from creating new administrators or deleting existing administrators.
 */
class WcpJitMuGuardian {

    const MU_FILENAME = 'wcp-jit-guardian.php';

    /**
     * Ensure the MU watchdog file is deployed and matches current code.
     *
     * @return bool
     */
    public static function ensure_installed(): bool {
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        $target_file = $mu_dir . '/' . self::MU_FILENAME;

        $mu_code = self::generate_mu_code();
        $target_hash = hash('sha256', $mu_code);

        if (file_exists($target_file)) {
            $current_hash = @hash_file('sha256', $target_file);
            if ($current_hash === $target_hash) {
                return true;
            }
        }

        if (!is_dir($mu_dir)) {
            wp_mkdir_p($mu_dir);
        }

        global $wp_filesystem;
        if (!$wp_filesystem) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        if ($wp_filesystem) {
            // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- Intentional deployment of Must-Use plugin watchdog into mu-plugins directory
            $written = $wp_filesystem->put_contents($target_file, $mu_code, FS_CHMOD_FILE);
            return (bool) $written;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        if (!is_writable($mu_dir)) {
            return false;
        }

        // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Fallback deployment of Must-Use plugin watchdog into mu-plugins directory
        $written = @file_put_contents($target_file, $mu_code);
        if ($written !== false) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($target_file, 0644);
            return true;
        }

        return false;
    }

    /**
     * Remove the MU watchdog on complete uninstallation.
     *
     * @return bool
     */
    public static function remove_mu_file(): bool {
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        $target_file = $mu_dir . '/' . self::MU_FILENAME;

        if (file_exists($target_file)) {
            return wp_delete_file($target_file);
        }

        return true;
    }

    /**
     * Generate standalone MU-plugin watchdog code.
     *
     * @return string
     */
    public static function generate_mu_code(): string {
        return <<<'PHP'
<?php
/**
 * Plugin Name: WCP Security - JIT Elevation Guardian (Must-Use)
 * Description: Zero-Trust Must-Use watchdog ensuring Just-In-Time (JIT) ephemeral administrative elevations cannot escape expiration or tamper with security controls.
 * Version: 1.26.0
 * Author: Mir Alamin
 * Author URI: https://webcarespro.com
 * License: GPLv2 or later
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WcpJitMuGuardianRuntime
 * Runtime watchdog executing at earliest muplugins_loaded phase.
 */
class WcpJitMuGuardianRuntime {

    const OPTION_ELEVATIONS = 'wcpscan_ephemeral_admins';
    const OPTION_HISTORY    = 'wcpscan_ephemeral_admin_history';

    public static function init() {
        // Enforce expiration check once pluggable/user functions are available
        add_action('plugins_loaded', [__CLASS__, 'check_expirations'], 1);
        add_action('init', [__CLASS__, 'check_expirations'], 1);

        // Block direct plugin deactivation & deletion attempts by JIT elevated users
        add_action('admin_init', [__CLASS__, 'intercept_unauthorized_plugin_actions'], 0);

        // Fail-Safe: If WCP Security Scanner plugin is deactivated, instantly revoke all active JIT elevations
        add_action('deactivated_plugin', [__CLASS__, 'on_plugin_deactivated']);

        // Capabilities Lockdown: Block JIT elevated users from deactivating WCP or deleting other administrators
        add_filter('map_meta_cap', [__CLASS__, 'restrict_capabilities'], 10, 4);
    }

    /**
     * Intercept direct HTTP deactivation and deletion attempts targeting WCP Security Scanner
     */
    public static function intercept_unauthorized_plugin_actions() {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return;
        }

        $elevations = get_option(self::OPTION_ELEVATIONS, []);
        if (!is_array($elevations) || !isset($elevations[$user_id])) {
            return;
        }

        // Active JIT elevated user detected
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $plugin = isset($_REQUEST['plugin']) ? sanitize_text_field(wp_unslash($_REQUEST['plugin'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $checked = isset($_REQUEST['checked']) && is_array($_REQUEST['checked']) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['checked'])) : [];

        $is_targeting_wcp = false;
        if ($plugin && (strpos($plugin, 'wcp-wp-scanner') !== false || strpos($plugin, 'wcp-security-scanner') !== false)) {
            $is_targeting_wcp = true;
        }

        if (!empty($checked)) {
            foreach ($checked as $p) {
                if (strpos($p, 'wcp-wp-scanner') !== false || strpos($p, 'wcp-security-scanner') !== false) {
                    $is_targeting_wcp = true;
                    break;
                }
            }
        }

        if ($is_targeting_wcp && in_array($action, ['deactivate', 'delete-selected', 'deactivate-selected'], true)) {
            wp_die(
                '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                '<p>' . esc_html__('Ephemeral Just-In-Time (JIT) Elevated Administrators are strictly prohibited from deactivating or deleting WCP Security Scanner.', 'wcp-security-scanner') . '</p>' .
                '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('← Return to Plugins', 'wcp-security-scanner') . '</a></p>',
                esc_html__('Access Denied', 'wcp-security-scanner'),
                ['response' => 403]
            );
        }
    }

    /**
     * If WCP Security Scanner is deactivated, immediately demote all JIT elevated users back to baseline
     */
    public static function on_plugin_deactivated($plugin) {
        if (strpos($plugin, 'wcp-wp-scanner') !== false || strpos($plugin, 'wcp-security-scanner') !== false) {
            self::revert_all_elevations('Emergency de-elevation: WCP Security Scanner plugin was deactivated.');
        }
    }

    /**
     * Restrict capabilities of JIT elevated users
     */
    public static function restrict_capabilities(array $caps, string $cap, int $user_id, array $args): array {
        if (!$user_id) {
            return $caps;
        }

        $elevations = get_option(self::OPTION_ELEVATIONS, []);
        if (!is_array($elevations) || !isset($elevations[$user_id])) {
            return $caps;
        }

        // Target user is an active JIT elevated admin
        if ($cap === 'deactivate_plugin' || $cap === 'deactivate_plugins') {
            $target_plugin = !empty($args[0]) ? $args[0] : '';
            if (empty($target_plugin) || strpos($target_plugin, 'wcp-wp-scanner') !== false || strpos($target_plugin, 'wcp-security-scanner') !== false) {
                return ['do_not_allow'];
            }
        }

        // Prevent JIT elevated admin from deleting or editing permanent administrators
        if (in_array($cap, ['delete_user', 'edit_user', 'remove_user'], true)) {
            $target_uid = !empty($args[0]) ? (int) $args[0] : 0;
            if ($target_uid && $target_uid !== $user_id) {
                $target_user = get_userdata($target_uid);
                if ($target_user && in_array('administrator', (array) $target_user->roles, true)) {
                    if (!isset($elevations[$target_uid])) {
                        return ['do_not_allow'];
                    }
                }
            }
        }

        return $caps;
    }

    /**
     * Check and expire overdue elevations on every request
     */
    public static function check_expirations() {
        if (!function_exists('get_userdata')) {
            return;
        }

        $elevations = get_option(self::OPTION_ELEVATIONS, []);
        if (!is_array($elevations) || empty($elevations)) {
            return;
        }

        $now = time();
        $changed = false;

        foreach ($elevations as $uid => $entry) {
            if (!empty($entry['expires_at']) && $entry['expires_at'] <= $now) {
                $baseline_role = !empty($entry['baseline_role']) ? $entry['baseline_role'] : 'subscriber';
                $user = get_userdata((int) $uid);
                if ($user) {
                    $user->set_role($baseline_role);
                }

                $entry['status'] = 'expired';
                $entry['expired_at'] = $now;
                unset($elevations[$uid]);
                $changed = true;

                // Archive into history
                $history = get_option(self::OPTION_HISTORY, []);
                if (!is_array($history)) {
                    $history = [];
                }
                array_unshift($history, $entry);
                if (count($history) > 100) {
                    $history = array_slice($history, 0, 100);
                }
                update_option(self::OPTION_HISTORY, $history);
            }
        }

        if ($changed) {
            update_option(self::OPTION_ELEVATIONS, $elevations);
        }
    }

    /**
     * Emergency revert of all JIT elevations
     */
    public static function revert_all_elevations(string $reason = '') {
        $elevations = get_option(self::OPTION_ELEVATIONS, []);
        if (!is_array($elevations) || empty($elevations)) {
            return;
        }

        $now = time();
        $history = get_option(self::OPTION_HISTORY, []);
        if (!is_array($history)) {
            $history = [];
        }

        foreach ($elevations as $uid => $entry) {
            $baseline_role = !empty($entry['baseline_role']) ? $entry['baseline_role'] : 'subscriber';
            $user = get_userdata((int) $uid);
            if ($user) {
                $user->set_role($baseline_role);
            }

            $entry['status'] = 'revoked';
            $entry['revoked_at'] = $now;
            $entry['revoke_reason'] = $reason;
            array_unshift($history, $entry);
        }

        if (count($history) > 100) {
            $history = array_slice($history, 0, 100);
        }

        update_option(self::OPTION_HISTORY, $history);
        update_option(self::OPTION_ELEVATIONS, []);
    }
}

WcpJitMuGuardianRuntime::init();
PHP;
    }
}
