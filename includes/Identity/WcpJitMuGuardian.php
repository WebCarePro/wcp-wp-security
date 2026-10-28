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
 * Architecture & Zero-Trust Purpose:
 * Must-Use plugins execute on EVERY request before standard plugins load and
 * CANNOT be deactivated or deleted via the WordPress admin UI.
 *
 * This watchdog guarantees:
 * 1. Security Plugin Anti-Tamper: ANY attempt by an ephemeral JIT administrator or
 *    temporary support user to deactivate, delete, or modify WCP Security Scanner is
 *    unconditionally blocked with a 403 Forbidden intercept at earliest execution.
 * 2. Temporary Support Sandboxing: Enforces strict Zero-Trust boundaries on external
 *    support technicians:
 *    - Prevents deactivating or deleting ANY WordPress plugins (when configured).
 *    - Prevents installing or uploading arbitrary plugins/themes.
 *    - Blocks Theme & Plugin File Code Editors (`theme-editor.php`, `plugin-editor.php`).
 *    - Blocks creating, promoting, editing, or deleting user accounts.
 *    - Protects Secret Vault from credential exfiltration.
 * 3. Infallible Expiration: On every request, expired JIT elevations and support
 *    sessions are auto-pruned and active user sessions instantly terminated.
 * 4. Emergency Fail-Safe: If WCP Security Scanner is deactivated, all active JIT elevations
 *    and temporary support sessions are instantly revoked and destroyed.
 *
 * @package WcpScanner\Identity
 * @author  Mir Alamin (WebCare Pro)
 */
class WcpJitMuGuardian {

    const MU_FILENAME          = 'wcp-jit-guardian.php';
    const OPTION_ELEVATIONS    = 'wcpscan_ephemeral_admins';
    const OPTION_HISTORY       = 'wcpscan_ephemeral_admin_history';
    const OPTION_SUPPORT_USERS = 'wcpscan_support_active_users';

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
            if (!function_exists('wp_generate_password')) {
                require_once ABSPATH . WPINC . '/pluggable.php';
            }
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        if ($wp_filesystem) {
            $mode = defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644;
            // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite,PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Intentional deployment of Must-Use plugin watchdog into mu-plugins directory
            $written = $wp_filesystem->put_contents($target_file, $mu_code, $mode);
            return (bool) $written;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        if (!is_writable($mu_dir)) {
            return false;
        }

        // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite,PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Fallback deployment of Must-Use plugin watchdog into mu-plugins directory
        $written = @file_put_contents($target_file, $mu_code);
        if ($written !== false) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($target_file, 0644);
            return true;
        }

        return false;
    }

    /**
     * Register an active temporary support user session for MU Guardian enforcement.
     *
     * @param int    $user_id
     * @param array  $record
     * @param string $client_ip
     */
    public static function register_support_user(int $user_id, array $record, string $client_ip = ''): void {
        self::ensure_installed();

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users)) {
            $support_users = [];
        }

        $user = get_userdata($user_id);

        $support_users[$user_id] = [
            'link_id'                     => $record['id'] ?? '',
            'label'                       => $record['label'] ?? 'External Technician',
            'user_login'                  => $user ? $user->user_login : '',
            'expires_at'                  => $record['expires_at'] ?? (time() + 14400),
            'protect_security_plugin'     => true,
            'block_plugin_deactivation'   => !empty($record['block_plugin_deactivation']),
            'block_plugin_deletion'       => !empty($record['block_plugin_deletion']),
            'block_plugin_install'        => !empty($record['block_plugin_install']),
            'block_file_editor'           => !empty($record['block_file_editor']),
            'block_user_management'       => !empty($record['block_user_management']),
            'block_database_and_options'  => !empty($record['block_database_and_options']),
            'block_tools_and_exports'     => !empty($record['block_tools_and_exports']),
            'block_remediation_actions'   => !empty($record['block_remediation_actions']),
            'block_settings_modification' => !empty($record['block_settings_modification']),
            'restrict_vault'              => !empty($record['restrict_vault']),
            'client_ip'                   => $client_ip,
            'login_at'                    => time(),
        ];

        update_option(self::OPTION_SUPPORT_USERS, $support_users, true);
    }

    /**
     * Unregister a temporary support user and terminate their session.
     *
     * @param int $user_id
     */
    public static function unregister_support_user(int $user_id): void {
        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (is_array($support_users) && isset($support_users[$user_id])) {
            unset($support_users[$user_id]);
            update_option(self::OPTION_SUPPORT_USERS, $support_users, true);
        }

        delete_user_meta($user_id, 'wcpscan_is_temporary_support');

        if (class_exists('\\WP_Session_Tokens')) {
            $manager = \WP_Session_Tokens::get_instance($user_id);
            $manager->destroy_all();
        }
    }

    /**
     * Terminate all active sessions tied to a specific support link ID.
     *
     * @param string $link_id
     */
    public static function revoke_link_sessions(string $link_id): void {
        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || empty($support_users)) {
            return;
        }

        $changed = false;
        foreach ($support_users as $uid => $conf) {
            if (!empty($conf['link_id']) && $conf['link_id'] === $link_id) {
                unset($support_users[$uid]);
                $changed = true;

                delete_user_meta((int) $uid, 'wcpscan_is_temporary_support');
                if (class_exists('\\WP_Session_Tokens')) {
                    $manager = \WP_Session_Tokens::get_instance((int) $uid);
                    $manager->destroy_all();
                }
            }
        }

        if ($changed) {
            update_option(self::OPTION_SUPPORT_USERS, $support_users, true);
        }
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
 * Plugin Name: WCP Security - Zero-Trust & JIT Guardian (Must-Use)
 * Description: Zero-Trust Must-Use watchdog ensuring Just-In-Time (JIT) elevations and Temporary Support sessions cannot escape expiration, deactivate security defenses, or tamper with WordPress plugins.
 * Version: 1.28.0
 * Author: Mir Alamin (WebCare Pro)
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

    const OPTION_ELEVATIONS    = 'wcpscan_ephemeral_admins';
    const OPTION_HISTORY       = 'wcpscan_ephemeral_admin_history';
    const OPTION_SUPPORT_USERS = 'wcpscan_support_active_users';

    public static function init() {
        // Enforce expiration check once pluggable/user functions are available
        add_action('plugins_loaded', [__CLASS__, 'check_expirations'], 1);
        add_action('init', [__CLASS__, 'check_expirations'], 1);

        // Block direct plugin deactivation & deletion attempts by JIT or support users
        add_action('admin_init', [__CLASS__, 'intercept_unauthorized_plugin_actions'], 0);

        // Block options.php, core settings, tools, export/import, file editors, and user creation
        add_action('admin_init', [__CLASS__, 'enforce_editor_and_settings_restrictions'], 0);

        // Intercept AJAX calls attempting to install, upload, or modify plugins/themes/users
        add_action('admin_init', [__CLASS__, 'intercept_unauthorized_ajax_actions'], 0);

        // Inviolable Database Options Shield: reject modifications to core options
        add_filter('pre_update_option', [__CLASS__, 'guard_critical_options'], 1, 3);
        $core_opts = ['siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'active_plugins'];
        foreach ($core_opts as $c_opt) {
            add_filter('pre_update_option_' . $c_opt, [__CLASS__, 'guard_critical_option_direct'], 1, 3);
        }

        // Anti-Hijacking User Shield: disallow modifying credentials of support user or editing others
        add_filter('wp_pre_insert_user_data', [__CLASS__, 'guard_user_tampering'], 1, 4);

        // Fail-Safe: If WCP Security Scanner is deactivated, instantly revoke all elevations and support sessions
        add_action('deactivated_plugin', [__CLASS__, 'on_plugin_deactivated']);

        // Capabilities Lockdown: Block capability escalations, plugin modifications, and user tampering
        add_filter('map_meta_cap', [__CLASS__, 'restrict_capabilities'], 10, 4);

        // UI Hardening: Filter out Deactivate / Delete links in Plugins list
        add_filter('plugin_action_links', [__CLASS__, 'filter_plugin_action_links'], 10, 4);
        add_filter('network_admin_plugin_action_links', [__CLASS__, 'filter_plugin_action_links'], 10, 4);

        // Admin Notice: Display informative sandboxed session indicator for temporary technicians
        add_action('admin_notices', [__CLASS__, 'render_support_session_notice']);

        // Zero-Trust REST API Intercept: Block resetting defaults, importing, user/plugin creation, database remediation
        add_filter('rest_pre_dispatch', [__CLASS__, 'intercept_unauthorized_rest_actions'], 10, 3);
    }

    /**
     * Intercept destructive REST API requests
     */
    public static function intercept_unauthorized_rest_actions($result, $server, $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return $result;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || !isset($support_users[$user_id])) {
            return $result;
        }

        $route = (is_object($request) && method_exists($request, 'get_route')) ? $request->get_route() : '';
        if (empty($route)) {
            return $result;
        }

        $cfg = $support_users[$user_id];
        $method = (is_object($request) && method_exists($request, 'get_method')) ? strtoupper($request->get_method()) : 'GET';

        // 1. Inviolable: Prohibit creating, viewing, or revoking temporary support links
        if (strpos($route, '/wcp-scanner/v1/identity/temporary-access') !== false) {
            return new \WP_Error(
                'rest_forbidden',
                esc_html__('Temporary Support Technicians are strictly prohibited from generating, viewing, or revoking temporary support access links.', 'wcp-security-scanner'),
                ['status' => 403]
            );
        }

        // 2. Inviolable: Prohibit Reset Defaults & Import Settings
        if (strpos($route, '/wcp-scanner/v1/settings/reset') !== false) {
            return new \WP_Error(
                'rest_forbidden',
                esc_html__('Temporary Support Technicians are strictly prohibited from resetting plugin settings to factory defaults.', 'wcp-security-scanner'),
                ['status' => 403]
            );
        }

        if (strpos($route, '/wcp-scanner/v1/settings/import') !== false) {
            return new \WP_Error(
                'rest_forbidden',
                esc_html__('Temporary Support Technicians are strictly prohibited from importing or overwriting plugin settings.', 'wcp-security-scanner'),
                ['status' => 403]
            );
        }

        // 3. Prohibit modifying settings or whitelist if block_settings_modification
        if (!empty($cfg['block_settings_modification'])) {
            if (strpos($route, '/wcp-scanner/v1/settings') !== false && $method === 'POST') {
                return new \WP_Error(
                    'rest_forbidden',
                    esc_html__('Temporary Support Technicians are operating in read-only diagnostic mode and cannot modify security settings.', 'wcp-security-scanner'),
                    ['status' => 403]
                );
            }
            if (strpos($route, '/wcp-scanner/v1/whitelist') !== false && $method === 'POST') {
                return new \WP_Error(
                    'rest_forbidden',
                    esc_html__('Temporary Support Technicians are prohibited from modifying false-positive whitelist rules.', 'wcp-security-scanner'),
                    ['status' => 403]
                );
            }
        }

        // 4. Prohibit database row remediation / deletion / cleansing
        if (!empty($cfg['block_database_and_options'])) {
            if (strpos($route, '/wcp-scanner/v1/database') !== false && $method === 'POST') {
                return new \WP_Error(
                    'rest_forbidden',
                    esc_html__('Temporary Support Technicians are prohibited from deleting or cleansing database records.', 'wcp-security-scanner'),
                    ['status' => 403]
                );
            }
        }

        // 5. Prohibit file remediation and user repair
        if (!empty($cfg['block_remediation_actions'])) {
            if ((strpos($route, '/wcp-scanner/v1/remediation') !== false || strpos($route, '/wcp-scanner/v1/user/remediate') !== false) && $method === 'POST') {
                return new \WP_Error(
                    'rest_forbidden',
                    esc_html__('Remediation file deletion and user repairs are restricted during temporary support sessions.', 'wcp-security-scanner'),
                    ['status' => 403]
                );
            }
        }

        // 6. Prohibit updater operations
        if (strpos($route, '/wcp-scanner/v1/updater') !== false && $method === 'POST') {
            return new \WP_Error(
                'rest_forbidden',
                esc_html__('Plugin updates and rollbacks are restricted to permanent administrators.', 'wcp-security-scanner'),
                ['status' => 403]
            );
        }

        // 7. WordPress Core REST API: Block creating/modifying/deleting users
        if (!empty($cfg['block_user_management'])) {
            if (strpos($route, '/wp/v2/users') !== false && in_array($method, ['POST', 'PUT', 'DELETE'], true)) {
                return new \WP_Error(
                    'rest_forbidden',
                    esc_html__('Temporary support technicians cannot create, modify, or delete user accounts via the REST API.', 'wcp-security-scanner'),
                    ['status' => 403]
                );
            }
        }

        // 8. WordPress Core REST API: Block installing or deleting plugins & themes
        if (!empty($cfg['block_plugin_install'])) {
            if ((strpos($route, '/wp/v2/plugins') !== false || strpos($route, '/wp/v2/themes') !== false) && in_array($method, ['POST', 'DELETE'], true)) {
                return new \WP_Error(
                    'rest_forbidden',
                    esc_html__('Temporary support technicians cannot install or delete plugins or themes via the REST API.', 'wcp-security-scanner'),
                    ['status' => 403]
                );
            }
        }

        return $result;
    }

    /**
     * Intercept direct HTTP deactivation and deletion attempts targeting WCP or locked plugins
     */
    public static function intercept_unauthorized_plugin_actions() {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return;
        }

        $elevations    = get_option(self::OPTION_ELEVATIONS, []);
        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);

        $is_jit     = is_array($elevations) && isset($elevations[$user_id]);
        $is_support = is_array($support_users) && isset($support_users[$user_id]);

        if (!$is_jit && !$is_support) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action  = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action2 = isset($_REQUEST['action2']) ? sanitize_key($_REQUEST['action2']) : '';
        $target_action = ($action && $action !== '-1') ? $action : $action2;

        if (empty($target_action)) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $plugin = isset($_REQUEST['plugin']) ? sanitize_text_field(wp_unslash($_REQUEST['plugin'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $checked = isset($_REQUEST['checked']) && is_array($_REQUEST['checked']) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['checked'])) : [];

        $is_targeting_wcp = false;
        if ($plugin && strpos($plugin, 'wcp-security-scanner') !== false) {
            $is_targeting_wcp = true;
        }

        if (!empty($checked)) {
            foreach ($checked as $p) {
                if (strpos($p, 'wcp-security-scanner') !== false) {
                    $is_targeting_wcp = true;
                    break;
                }
            }
        }

        // Rule 1 (Inviolable): Block deactivating or deleting WCP Security Scanner
        if ($is_targeting_wcp && in_array($target_action, ['deactivate', 'delete-selected', 'deactivate-selected', 'delete'], true)) {
            wp_die(
                '<h1>' . esc_html__('Security Access Denied (WCP Anti-Tamper Shield)', 'wcp-security-scanner') . '</h1>' .
                '<p>' . esc_html__('Temporary Support Technicians and Ephemeral Administrators are strictly prohibited from deactivating, modifying, or deleting WCP Security Scanner.', 'wcp-security-scanner') . '</p>' .
                '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('← Return to Plugins', 'wcp-security-scanner') . '</a></p>',
                esc_html__('Access Denied', 'wcp-security-scanner'),
                ['response' => 403]
            );
        }

        // Rule 2: If temporary support user has general plugin restrictions active
        if ($is_support) {
            $cfg = $support_users[$user_id];

            if (!empty($cfg['block_plugin_deactivation']) && in_array($target_action, ['deactivate', 'deactivate-selected'], true)) {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Your temporary support access is sandboxed. Deactivating plugins is restricted by the site administrator.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('← Return to Plugins', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }

            if (!empty($cfg['block_plugin_deletion']) && in_array($target_action, ['delete-selected', 'delete'], true)) {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Your temporary support access is sandboxed. Deleting or uninstalling plugins is strictly restricted.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('← Return to Plugins', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }
        }
    }

    /**
     * Enforce restrictions against options.php, core settings, code editors, and user management
     */
    public static function enforce_editor_and_settings_restrictions() {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || !isset($support_users[$user_id])) {
            return;
        }

        $cfg = $support_users[$user_id];
        global $pagenow;

        // 1. Unconditional Lockout: options.php
        if ($pagenow === 'options.php') {
            wp_die(
                '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                '<p>' . esc_html__('Direct modification of WordPress database options via options.php is strictly blocked for temporary support technicians.', 'wcp-security-scanner') . '</p>' .
                '<p><a href="' . esc_url(admin_url('index.php')) . '">' . esc_html__('← Return to Dashboard', 'wcp-security-scanner') . '</a></p>',
                esc_html__('Access Denied', 'wcp-security-scanner'),
                ['response' => 403]
            );
        }

        // 2. Block Core Settings screens
        if (!empty($cfg['block_database_and_options'])) {
            $blocked_options_pages = [
                'options-general.php', 'options-writing.php', 'options-reading.php',
                'options-discussion.php', 'options-media.php', 'options-permalink.php', 'options-privacy.php'
            ];
            if (in_array($pagenow, $blocked_options_pages, true)) {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Modifying core WordPress site settings and database options is restricted during temporary support sessions.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('index.php')) . '">' . esc_html__('← Return to Dashboard', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }
        }

        // 3. Block Plugin & Theme Installation screens and update.php uploads
        if (!empty($cfg['block_plugin_install'])) {
            if (in_array($pagenow, ['plugin-install.php', 'theme-install.php'], true)) {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Installing or uploading new plugins and themes is strictly disabled during temporary support sessions.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('index.php')) . '">' . esc_html__('← Return to Dashboard', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }

            if ($pagenow === 'update.php') {
                $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
                if (in_array($action, ['upload-plugin', 'upload-theme', 'install-plugin', 'install-theme', 'upload-plugin-cancel'], true)) {
                    wp_die(
                        '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                        '<p>' . esc_html__('Uploading or installing packages is strictly prohibited for temporary support technicians.', 'wcp-security-scanner') . '</p>',
                        esc_html__('Access Denied', 'wcp-security-scanner'),
                        ['response' => 403]
                    );
                }
            }
        }

        // 4. Block Core Tools, Export, Import, Erase Personal Data
        if (!empty($cfg['block_tools_and_exports'])) {
            $blocked_tools_pages = [
                'tools.php', 'import.php', 'export.php', 'export-personal-data.php', 'erase-personal-data.php'
            ];
            if (in_array($pagenow, $blocked_tools_pages, true)) {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Core tools, database exports, and data import operations are restricted during temporary support sessions.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('index.php')) . '">' . esc_html__('← Return to Dashboard', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }
        }

        // 5. Block File Editors
        if (!empty($cfg['block_file_editor']) && in_array($pagenow, ['plugin-editor.php', 'theme-editor.php'], true)) {
            wp_die(
                '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                '<p>' . esc_html__('File editors (Plugin & Theme Editor) are strictly disabled for temporary support sessions.', 'wcp-security-scanner') . '</p>' .
                '<p><a href="' . esc_url(admin_url('index.php')) . '">' . esc_html__('← Return to Dashboard', 'wcp-security-scanner') . '</a></p>',
                esc_html__('Access Denied', 'wcp-security-scanner'),
                ['response' => 403]
            );
        }

        // 6. Block User Creation and User Deletion screens
        if (!empty($cfg['block_user_management'])) {
            if ($pagenow === 'user-new.php') {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Creating new user accounts is disabled during temporary support sessions.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('index.php')) . '">' . esc_html__('← Return to Dashboard', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }

            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
            if ($pagenow === 'users.php' && in_array($action, ['delete', 'dodelete', 'delete-selected'], true)) {
                wp_die(
                    '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('Deleting user accounts is strictly prohibited during temporary support sessions.', 'wcp-security-scanner') . '</p>' .
                    '<p><a href="' . esc_url(admin_url('users.php')) . '">' . esc_html__('← Return to Users', 'wcp-security-scanner') . '</a></p>',
                    esc_html__('Access Denied', 'wcp-security-scanner'),
                    ['response' => 403]
                );
            }
        }
    }

    /**
     * Intercept AJAX actions attempting to install, upload, or modify plugins/themes/users
     */
    public static function intercept_unauthorized_ajax_actions() {
        if (!wp_doing_ajax()) {
            return;
        }

        $user_id = get_current_user_id();
        if (!$user_id) {
            return;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || !isset($support_users[$user_id])) {
            return;
        }

        $cfg = $support_users[$user_id];
        $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
        if (empty($action)) {
            return;
        }

        $blocked_ajax = [];
        if (!empty($cfg['block_plugin_install'])) {
            $blocked_ajax = array_merge($blocked_ajax, [
                'install-plugin', 'upload-plugin', 'install-theme', 'upload-theme',
                'update-plugin', 'update-theme'
            ]);
        }
        if (!empty($cfg['block_plugin_deletion'])) {
            $blocked_ajax = array_merge($blocked_ajax, ['delete-plugin', 'delete-theme']);
        }
        if (!empty($cfg['block_file_editor'])) {
            $blocked_ajax = array_merge($blocked_ajax, ['edit-theme-plugin-file']);
        }
        if (!empty($cfg['block_user_management'])) {
            $blocked_ajax = array_merge($blocked_ajax, ['save-user', 'create-user', 'delete-user']);
        }

        if (in_array($action, $blocked_ajax, true)) {
            wp_send_json_error([
                'message' => esc_html__('This action is strictly prohibited during temporary support sessions.', 'wcp-security-scanner')
            ], 403);
        }
    }

    /**
     * Inviolable Database Options Shield: reject modifications to core options
     */
    public static function guard_critical_options($value, $option, $old_value) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return $value;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || !isset($support_users[$user_id])) {
            return $value;
        }

        $cfg = $support_users[$user_id];
        if (!empty($cfg['block_database_and_options'])) {
            $guarded_options = [
                'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role',
                'active_plugins', 'permalink_structure', 'category_base', 'tag_base',
                'WPLANG', 'blogname', 'blogdescription'
            ];
            if (in_array($option, $guarded_options, true) || strpos($option, 'wcpscan_') === 0) {
                return $old_value;
            }
        }

        return $value;
    }

    /**
     * Direct Option Filter Adapter for pre_update_option_{$option} hook
     */
    public static function guard_critical_option_direct($value, $old_value, $option = '') {
        if (empty($option)) {
            $filter = current_filter();
            if (strpos($filter, 'pre_update_option_') === 0) {
                $option = substr($filter, strlen('pre_update_option_'));
            }
        }
        return self::guard_critical_options($value, $option, $old_value);
    }

    /**
     * Anti-Hijacking User Shield: disallow modifying credentials of support user or editing others
     */
    public static function guard_user_tampering($data, $update, $user_id, $userdata) {
        $acting_uid = get_current_user_id();
        if (!$acting_uid) {
            return $data;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || !isset($support_users[$acting_uid])) {
            return $data;
        }

        // Rule 1: Temporary support technician cannot edit other user accounts
        if ($acting_uid !== (int) $user_id) {
            wp_die(
                '<h1>' . esc_html__('Security Access Denied', 'wcp-security-scanner') . '</h1>' .
                '<p>' . esc_html__('Temporary support technicians are prohibited from modifying other user accounts.', 'wcp-security-scanner') . '</p>',
                esc_html__('Access Denied', 'wcp-security-scanner'),
                ['response' => 403]
            );
        }

        // Rule 2: Cannot change their own username, email, or password (prevents account hijacking/persistence)
        if ($update && isset($userdata['user_pass']) && $data['user_pass'] !== $userdata['user_pass']) {
            $data['user_pass'] = $userdata['user_pass'];
        }
        if ($update && isset($userdata['user_email'])) {
            $data['user_email'] = $userdata['user_email'];
        }
        if ($update && isset($userdata['user_login'])) {
            $data['user_login'] = $userdata['user_login'];
        }

        return $data;
    }

    /**
     * If WCP Security Scanner is deactivated, immediately demote JIT admins and terminate support sessions
     */
    public static function on_plugin_deactivated($plugin) {
        if (strpos($plugin, 'wcp-security-scanner') !== false) {
            self::revert_all_elevations('Emergency de-elevation: WCP Security Scanner plugin was deactivated.');
            self::terminate_all_support_sessions('Emergency termination: WCP Security Scanner plugin was deactivated.');
        }
    }

    /**
     * Restrict capabilities of JIT elevated users and temporary support users
     */
    public static function restrict_capabilities(array $caps, string $cap, int $user_id, array $args): array {
        if (!$user_id) {
            return $caps;
        }

        $elevations    = get_option(self::OPTION_ELEVATIONS, []);
        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);

        $is_jit     = is_array($elevations) && isset($elevations[$user_id]);
        $is_support = is_array($support_users) && isset($support_users[$user_id]);

        if (!$is_jit && !$is_support) {
            return $caps;
        }

        // Rule 1 (Inviolable): Block deactivating or deleting WCP Security Scanner
        if (in_array($cap, ['deactivate_plugin', 'deactivate_plugins', 'delete_plugins'], true)) {
            $target_plugin = !empty($args[0]) ? (string) $args[0] : '';
            if (empty($target_plugin) || strpos($target_plugin, 'wcp-security-scanner') !== false) {
                return ['do_not_allow'];
            }
        }

        // Rule 2: Support User Capabilities Lockdown
        if ($is_support) {
            $cfg = $support_users[$user_id];

            // Block all plugin deactivations
            if (!empty($cfg['block_plugin_deactivation']) && ($cap === 'deactivate_plugin' || $cap === 'deactivate_plugins')) {
                return ['do_not_allow'];
            }

            // Block all plugin/theme deletions
            if (!empty($cfg['block_plugin_deletion']) && in_array($cap, ['delete_plugins', 'delete_themes'], true)) {
                return ['do_not_allow'];
            }

            // Block arbitrary plugin/theme installations, uploads, and updates
            if (!empty($cfg['block_plugin_install']) && in_array($cap, ['install_plugins', 'upload_plugins', 'update_plugins', 'install_themes', 'upload_themes', 'update_themes', 'switch_themes', 'update_core'], true)) {
                return ['do_not_allow'];
            }

            // Block Theme & Plugin code editors
            if (!empty($cfg['block_file_editor']) && in_array($cap, ['edit_plugins', 'edit_themes', 'edit_files'], true)) {
                return ['do_not_allow'];
            }

            // Block core tools, database export, import, and personal data erasure
            if (!empty($cfg['block_tools_and_exports']) && in_array($cap, ['export', 'import', 'erase_others_personal_data', 'manage_privacy_options', 'export_others_personal_data'], true)) {
                return ['do_not_allow'];
            }

            // Block user creation, deletion, or promotion
            if (!empty($cfg['block_user_management'])) {
                if (in_array($cap, ['create_users', 'delete_users', 'promote_users', 'remove_users'], true)) {
                    return ['do_not_allow'];
                }
                if ($cap === 'edit_user') {
                    $target_uid = !empty($args[0]) ? (int) $args[0] : 0;
                    if ($target_uid && $target_uid !== $user_id) {
                        return ['do_not_allow'];
                    }
                }
            }

            // Block export / vault credentials
            if (!empty($cfg['restrict_vault']) && $cap === 'export') {
                return ['do_not_allow'];
            }
        }

        // Rule 3: JIT-specific restrictions (Prevent deleting or editing permanent administrators)
        if ($is_jit) {
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
        }

        return $caps;
    }

    /**
     * Filter plugin action links to remove Deactivate & Delete buttons for protected plugins
     */
    public static function filter_plugin_action_links(array $actions, string $plugin_file, ?array $plugin_data = null, string $context = 'all'): array {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return $actions;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        $elevations    = get_option(self::OPTION_ELEVATIONS, []);

        $is_support = is_array($support_users) && isset($support_users[$user_id]);
        $is_jit     = is_array($elevations) && isset($elevations[$user_id]);

        if (!$is_support && !$is_jit) {
            return $actions;
        }

        $is_wcp = (strpos($plugin_file, 'wcp-security-scanner') !== false);

        // Anti-Tamper: Remove Deactivate and Delete for WCP Security Scanner
        if ($is_wcp) {
            unset($actions['deactivate'], $actions['delete']);
            $actions['wcp_anti_tamper'] = '<span style="color:#059669;font-weight:600;font-size:12px;">🛡️ Anti-Tamper Protected</span>';
        }

        // Support User specific link filtering
        if ($is_support) {
            $cfg = $support_users[$user_id];
            if (!empty($cfg['block_plugin_deactivation']) && !$is_wcp) {
                unset($actions['deactivate']);
                $actions['wcp_locked'] = '<span style="color:#64748b;font-size:11px;">🔒 Locked</span>';
            }
            if (!empty($cfg['block_plugin_deletion']) && !$is_wcp) {
                unset($actions['delete']);
            }
        }

        return $actions;
    }

    /**
     * Render an informative sandboxed session indicator for temporary technicians
     */
    public static function render_support_session_notice() {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return;
        }

        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || !isset($support_users[$user_id])) {
            return;
        }

        $cfg = $support_users[$user_id];
        $remaining = !empty($cfg['expires_at']) ? max(0, $cfg['expires_at'] - time()) : 0;
        $remaining_str = $remaining > 0 ? human_time_diff(time(), $cfg['expires_at']) : 'expired';

        echo '<div class="notice notice-info" style="border-left: 4px solid #0284c7; background: #f0f9ff; color: #0369a1; padding: 12px 16px; font-size: 13px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">';
        echo '<div><strong>🛡️ WCP Security Sandboxed Session:</strong> ' . esc_html__('Authenticated via Temporary Support Access', 'wcp-security-scanner') . ' (<em>' . esc_html($cfg['label'] ?? 'Technician') . '</em>). ' . esc_html__('Session valid for', 'wcp-security-scanner') . ' <strong>' . esc_html($remaining_str) . '</strong>. ' . esc_html__('Zero-Trust MU Guardian is actively enforcing anti-tamper plugin locks and security boundaries.', 'wcp-security-scanner') . '</div>';
        echo '<span style="background: #0284c7; color: #ffffff; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">' . esc_html__('MU Protected', 'wcp-security-scanner') . '</span>';
        echo '</div>';
    }

    /**
     * Check and expire overdue elevations and support sessions on every request
     */
    public static function check_expirations() {
        if (!function_exists('get_userdata')) {
            return;
        }

        $now = time();

        // 1. Check JIT elevations
        $elevations = get_option(self::OPTION_ELEVATIONS, []);
        if (is_array($elevations) && !empty($elevations)) {
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

        // 2. Check Temporary Support Sessions
        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (is_array($support_users) && !empty($support_users)) {
            $support_changed = false;
            $current_uid = get_current_user_id();
            $current_user_expired = false;

            foreach ($support_users as $uid => $entry) {
                if (!empty($entry['expires_at']) && $entry['expires_at'] <= $now) {
                    unset($support_users[$uid]);
                    $support_changed = true;

                    delete_user_meta((int) $uid, 'wcpscan_is_temporary_support');
                    if (class_exists('\\WP_Session_Tokens')) {
                        $manager = \WP_Session_Tokens::get_instance((int) $uid);
                        $manager->destroy_all();
                    }

                    if ($current_uid === (int) $uid) {
                        $current_user_expired = true;
                    }
                }
            }

            if ($support_changed) {
                update_option(self::OPTION_SUPPORT_USERS, $support_users);
            }

            if ($current_user_expired) {
                wp_logout();
                wp_safe_redirect(wp_login_url() . '?loggedout=true');
                exit;
            }
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

    /**
     * Emergency termination of all active support sessions
     */
    public static function terminate_all_support_sessions(string $reason = '') {
        $support_users = get_option(self::OPTION_SUPPORT_USERS, []);
        if (!is_array($support_users) || empty($support_users)) {
            return;
        }

        foreach ($support_users as $uid => $cfg) {
            delete_user_meta((int) $uid, 'wcpscan_is_temporary_support');
            if (class_exists('\\WP_Session_Tokens')) {
                $manager = \WP_Session_Tokens::get_instance((int) $uid);
                $manager->destroy_all();
            }
        }

        update_option(self::OPTION_SUPPORT_USERS, []);
    }
}

WcpJitMuGuardianRuntime::init();
PHP;
    }
}

