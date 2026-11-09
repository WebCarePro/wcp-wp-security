<?php
namespace WebCareProScanner\Auth;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Notifications\NotificationDispatcher;
use WebCareProScanner\System\WebCareActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ApplicationPasswordSentinel
 *
 * Pillar 1: Authorize-Application REST Token Phishing Lockdown & Credential Sentinel:
 * 1. Callback Trap Blocker: Intercepts /wp-admin/authorize-application.php requests to verify
 *    that any success_url / redirect destination matches trusted local hosts or an approved
 *    whitelist, blocking 1-click REST token theft and 2FA bypass phishing attacks.
 * 2. Global Kill-Switch & Policy: Filters wp_is_application_passwords_available to allow site-wide
 *    disabling or restricting application passwords strictly to Administrators.
 * 3. Real-Time Telemetry: Dispatches instant out-of-band notifications on creation or blocked traps.
 * 4. Stale Credential Audit & 1-Click Revocation: Identifies abandoned or unprivileged tokens.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class ApplicationPasswordSentinel {

    const OPTION_DISABLED        = 'webcareproscan_disable_application_passwords';
    const OPTION_ADMIN_ONLY       = 'webcareproscan_app_pass_admin_only';
    const OPTION_ALLOWED_DOMAINS  = 'webcareproscan_app_pass_allowed_callback_domains';
    const OPTION_STRICT_CALLBACK  = 'webcareproscan_app_pass_strict_callback';
    const OPTION_REQUIRE_STEP_UP  = 'webcareproscan_app_pass_require_step_up_2fa';

    /**
     * Initialize sentinel hooks
     */
    public static function init(): void {
        // 1. Enforce global availability policy
        add_filter('wp_is_application_passwords_available', [__CLASS__, 'filter_is_available'], 10, 1);
        add_filter('wp_is_application_passwords_available_for_user', [__CLASS__, 'filter_is_available_for_user'], 10, 2);

        // 2. Intercept /wp-admin/authorize-application.php requests for callback phishing traps & step-up 2FA
        add_filter('wp_authorize_application_password_request_errors', [__CLASS__, 'inspect_authorization_request'], 10, 3);

        // 3. Early screen on authorize-application page load
        add_action('load-authorize-application.php', [__CLASS__, 'on_load_authorize_screen']);

        // 4. Render Step-Up 2FA / Password verification inside native authorize-application form
        add_action('wp_authorize_application_password_form', [__CLASS__, 'render_step_up_2fa_form'], 10, 2);

        // 5. Hook password creation for forensic logging and telemetry
        add_action('wp_create_application_password', [__CLASS__, 'on_application_password_created'], 20, 4);
    }

    /**
     * Filter global availability of Application Passwords.
     *
     * @param bool $available Core availability flag
     * @return bool
     */
    public static function filter_is_available(bool $available): bool {
        if (!empty(get_option(self::OPTION_DISABLED, 0))) {
            return false;
        }
        return $available;
    }

    /**
     * Filter per-user availability of Application Passwords.
     *
     * @param bool     $available Core per-user availability flag
     * @param \WP_User $user WordPress user instance
     * @return bool
     */
    public static function filter_is_available_for_user(bool $available, $user): bool {
        // If disabled globally, return false
        if (!empty(get_option(self::OPTION_DISABLED, 0))) {
            return false;
        }

        // If restricted to Administrators only (default policy)
        $admin_only = get_option(self::OPTION_ADMIN_ONLY, 1);
        if (!empty($admin_only)) {
            if (!$user instanceof \WP_User || !user_can($user, 'manage_options')) {
                return false;
            }
        }

        return $available;
    }

    /**
     * Inspect incoming /wp-admin/authorize-application.php requests for external callback traps.
     * WordPress fires this filter on both initial GET page render and POST approval.
     *
     * @param \WP_Error $error Current error bag
     * @param array     $request Request payload (app_name, success_url, reject_url)
     * @param \WP_User  $user Authenticated user
     * @return \WP_Error
     */
    public static function inspect_authorization_request($error, array $request, $user) {
        if (!$error instanceof \WP_Error) {
            $error = new \WP_Error();
        }

        // 1. If Application Passwords are site-wide disabled, reject immediately
        if (!empty(get_option(self::OPTION_DISABLED, 0))) {
            $error->add(
                'webcareproscan_app_pass_disabled',
                __('WebCare Pro Security Sentinel: Application Passwords have been disabled site-wide by your administrator.', 'webcare-pro-security')
            );
            return $error;
        }

        // 2. Check role restriction
        $admin_only = get_option(self::OPTION_ADMIN_ONLY, 1);
        if (!empty($admin_only)) {
            if (!$user instanceof \WP_User || !user_can($user, 'manage_options')) {
                $error->add(
                    'webcareproscan_app_pass_admin_only',
                    __('WebCare Pro Security Sentinel: Application Passwords on this site are restricted strictly to Administrators.', 'webcare-pro-security')
                );
                return $error;
            }
        }

        $app_name    = sanitize_text_field($request['app_name'] ?? '');
        $success_url = isset($request['success_url']) ? trim((string) $request['success_url']) : '';
        $reject_url  = isset($request['reject_url']) ? trim((string) $request['reject_url']) : '';

        // 3. Inspect success_url destination
        if ($success_url !== '') {
            $parsed_url = wp_parse_url($success_url);
            $host       = !empty($parsed_url['host']) ? strtolower((string) $parsed_url['host']) : '';
            $scheme     = !empty($parsed_url['scheme']) ? strtolower((string) $parsed_url['scheme']) : '';

            $is_trusted = self::is_host_trusted($host, $scheme);

            if (!$is_trusted) {
                $client_ip = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : (sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1')));
                $username  = $user instanceof \WP_User ? $user->user_login : 'Unknown';
                $user_id   = $user instanceof \WP_User ? (int) $user->ID : 0;

                // Log critical phishing trap incident
                if (class_exists(WebCareActivityLogger::class)) {
                    WebCareActivityLogger::log(
                        'app_password_consent_trap_blocked',
                        'auth',
                        'critical',
                        [
                            'user_id'     => $user_id,
                            'username'    => $username,
                            'app_name'    => $app_name,
                            'success_url' => $success_url,
                            'host'        => $host,
                            'ip'          => $client_ip,
                            'user_agent'  => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
                            'description' => sprintf(
                                'Blocked unauthorized Application Password callback trap for "%s" to untrusted host "%s" by %s from IP %s.',
                                $app_name ?: 'Unknown App',
                                $host,
                                $username,
                                $client_ip
                            ),
                        ]
                    );
                }

                // Dispatch out-of-band security notification
                if (class_exists(NotificationDispatcher::class)) {
                    NotificationDispatcher::trigger('auth_app_password_consent_trap', [
                        'user_id'     => $user_id,
                        'username'    => $username,
                        'app_name'    => $app_name ?: 'Unknown App',
                        'success_url' => $success_url,
                        'host'        => $host,
                        'ip'          => $client_ip,
                        'timestamp'   => current_time('mysql'),
                    ]);
                }

                $error->add(
                    'webcareproscan_untrusted_callback',
                    sprintf(
                        /* translators: 1: Application name, 2: Destination host */
                        __('SECURITY ALERT (WebCare Sentinel): Authorization for "%1$s" was blocked because the callback domain "%2$s" is an untrusted external host. Directing Application Passwords to unapproved external servers is blocked to prevent 1-click token phishing and 2FA bypass.', 'webcare-pro-security'),
                        esc_html($app_name ?: __('Unknown Application', 'webcare-pro-security')),
                        esc_html($host ?: __('Malformed URL', 'webcare-pro-security'))
                    )
                );

                return $error;
            }
        }

        // 4. Also verify reject_url if present
        if ($reject_url !== '') {
            $parsed_reject = wp_parse_url($reject_url);
            $reject_host   = !empty($parsed_reject['host']) ? strtolower((string) $parsed_reject['host']) : '';
            $reject_scheme = !empty($parsed_reject['scheme']) ? strtolower((string) $parsed_reject['scheme']) : '';

            if (!self::is_host_trusted($reject_host, $reject_scheme)) {
                $error->add(
                    'webcareproscan_untrusted_reject_callback',
                    sprintf(
                        /* translators: 1: Destination host */
                        __('SECURITY ALERT (WebCare Sentinel): The reject callback domain "%1$s" is not in the approved domain whitelist.', 'webcare-pro-security'),
                        esc_html($reject_host ?: __('Malformed URL', 'webcare-pro-security'))
                    )
                );
            }
        }

        // 5. Enforce Step-Up 2FA / Identity Verification before approving credentials
        $require_step_up = !empty(get_option(self::OPTION_REQUIRE_STEP_UP, 1));
        $req_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : '';

        // phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified upstream by WordPress core authorize-application flow
        $is_approval_attempt = ($req_method === 'POST') && (
            isset($_POST['approve']) ||
            (isset($_POST['action']) && $_POST['action'] === 'authorize_application_password')
        );

        if ($require_step_up && $is_approval_attempt && $user instanceof \WP_User) {
            $user_id = (int) $user->ID;
            $has_2fa = class_exists(TwoFactorAuth::class) && TwoFactorAuth::is_user_enabled($user_id);

            if ($has_2fa) {
                $step_up_code = isset($_POST['webcareproscan_step_up_totp']) ? sanitize_text_field(wp_unslash($_POST['webcareproscan_step_up_totp'])) : '';
                if ($step_up_code === '') {
                    $error->add(
                        'webcareproscan_step_up_totp_required',
                        __('WebCare Pro Security Sentinel: Re-authentication required. Please enter your 6 or 8-digit Two-Factor Authentication (TOTP) code to authorize minting this Application Password.', 'webcare-pro-security')
                    );
                    return $error;
                }

                $secret      = TwoFactorAuth::get_user_secret($user_id);
                $user_algo   = (string) (get_user_meta($user_id, TwoFactorAuth::META_ALGORITHM, true) ?: 'sha1');
                $user_digits = (int) (get_user_meta($user_id, TwoFactorAuth::META_DIGITS, true) ?: 6);

                $totp_valid = $secret && TwoFactorAuth::verify_code($secret, $step_up_code, 1, $user_algo, $user_digits);

                if (!$totp_valid && method_exists(TwoFactorAuth::class, 'verify_and_consume_backup_code')) {
                    $totp_valid = TwoFactorAuth::verify_and_consume_backup_code($user_id, $step_up_code);
                }

                if (!$totp_valid) {
                    $error->add(
                        'webcareproscan_step_up_totp_invalid',
                        __('WebCare Pro Security Sentinel: Invalid Two-Factor Authentication code. Please verify the code in your authenticator app and try again.', 'webcare-pro-security')
                    );
                    return $error;
                }

                if (class_exists(WebCareActivityLogger::class)) {
                    WebCareActivityLogger::log(
                        'app_password_step_up_verified',
                        'auth',
                        'info',
                        [
                            'user_id'     => $user_id,
                            'username'    => $user->user_login,
                            'method'      => 'totp',
                            'description' => sprintf(
                                /* translators: %s: username */
                                __('User %s verified 2FA TOTP step-up for Application Password authorization.', 'webcare-pro-security'),
                                $user->user_login
                            ),
                        ]
                    );
                }
            } else {
                // Fallback step-up: Account password verification for accounts without TOTP
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passwords must retain raw special characters for hash checking
                $step_up_pass = isset($_POST['webcareproscan_step_up_password']) ? (string) wp_unslash($_POST['webcareproscan_step_up_password']) : '';
                if ($step_up_pass === '') {
                    $error->add(
                        'webcareproscan_step_up_password_required',
                        __('WebCare Pro Security Sentinel: Re-authentication required. Please enter your WordPress account password to approve minting this Application Password.', 'webcare-pro-security')
                    );
                    return $error;
                }

                if (!wp_check_password($step_up_pass, $user->user_pass, $user_id)) {
                    $error->add(
                        'webcareproscan_step_up_password_invalid',
                        __('WebCare Pro Security Sentinel: Incorrect account password entered for step-up identity verification.', 'webcare-pro-security')
                    );
                    return $error;
                }

                if (class_exists(WebCareActivityLogger::class)) {
                    WebCareActivityLogger::log(
                        'app_password_step_up_verified',
                        'auth',
                        'info',
                        [
                            'user_id'     => $user_id,
                            'username'    => $user->user_login,
                            'method'      => 'password',
                            'description' => sprintf(
                                /* translators: %s: username */
                                __('User %s verified account password step-up for Application Password authorization.', 'webcare-pro-security'),
                                $user->user_login
                            ),
                        ]
                    );
                }
            }
        }
        // phpcs:enable WordPress.Security.NonceVerification.Missing

        return $error;
    }

    /**
     * Early screening hook when loading /wp-admin/authorize-application.php
     */
    public static function on_load_authorize_screen(): void {
        if (!empty(get_option(self::OPTION_DISABLED, 0))) {
            wp_die(
                '<h1>' . esc_html__('Application Passwords Disabled', 'webcare-pro-security') . '</h1>' .
                '<p>' . esc_html__('WebCare Pro Security Sentinel: REST Application Passwords have been disabled on this site to prevent unauthorized API access.', 'webcare-pro-security') . '</p>',
                esc_html__('Authorization Blocked', 'webcare-pro-security'),
                ['response' => 403]
            );
        }
    }

    /**
     * Render Step-Up 2FA / Identity Verification UI inside native authorize-application form.
     *
     * @param array    $request Authorize request payload
     * @param \WP_User $user Current user
     */
    public static function render_step_up_2fa_form($request, $user): void {
        if (!empty(get_option(self::OPTION_DISABLED, 0))) {
            return;
        }

        if (empty(get_option(self::OPTION_REQUIRE_STEP_UP, 1))) {
            return;
        }

        if (!$user instanceof \WP_User) {
            return;
        }

        $user_id = (int) $user->ID;
        $has_2fa = class_exists(TwoFactorAuth::class) && TwoFactorAuth::is_user_enabled($user_id);

        if ($has_2fa) {
            ?>
            <div class="webcare-step-up-card" style="margin: 20px 0; padding: 18px; border: 1px solid #c7d2fe; border-radius: 8px; background: #f8faff;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                    <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #4f46e5;"></span>
                    <strong style="color: #1e1b4b; font-size: 14px;"><?php esc_html_e('WebCare Pro Security Sentinel: Step-Up 2FA Verification Required', 'webcare-pro-security'); ?></strong>
                </div>
                <p style="margin: 0 0 12px; font-size: 13px; color: #4338ca; line-height: 1.5;">
                    <?php esc_html_e('Because Application Passwords grant persistent REST API access, you must verify your identity with your Two-Factor Authentication (TOTP) code before minting this credential.', 'webcare-pro-security'); ?>
                </p>
                <div class="form-field" style="margin-bottom: 0;">
                    <label for="webcareproscan_step_up_totp" style="font-weight: 600; display: block; margin-bottom: 6px;">
                        <?php esc_html_e('Authenticator Code (6 or 8 Digits):', 'webcare-pro-security'); ?>
                    </label>
                    <input type="text" name="webcareproscan_step_up_totp" id="webcareproscan_step_up_totp" class="regular-text" style="font-family: monospace; font-size: 16px; letter-spacing: 2px; width: 180px;" placeholder="123456" autocomplete="one-time-code" inputmode="numeric" required />
                </div>
            </div>
            <?php
        } else {
            ?>
            <div class="webcare-step-up-card" style="margin: 20px 0; padding: 18px; border: 1px solid #fed7aa; border-radius: 8px; background: #fffaf5;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                    <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ea580c;"></span>
                    <strong style="color: #7c2d12; font-size: 14px;"><?php esc_html_e('WebCare Pro Security Sentinel: Step-Up Identity Verification Required', 'webcare-pro-security'); ?></strong>
                </div>
                <p style="margin: 0 0 12px; font-size: 13px; color: #9a3412; line-height: 1.5;">
                    <?php esc_html_e('To protect against 1-click consent traps and unattended session misuse, enter your account password before minting this Application Password.', 'webcare-pro-security'); ?>
                </p>
                <div class="form-field" style="margin-bottom: 0;">
                    <label for="webcareproscan_step_up_password" style="font-weight: 600; display: block; margin-bottom: 6px;">
                        <?php esc_html_e('Your WordPress Password:', 'webcare-pro-security'); ?>
                    </label>
                    <input type="password" name="webcareproscan_step_up_password" id="webcareproscan_step_up_password" class="regular-text" style="width: 260px;" placeholder="••••••••••••" autocomplete="current-password" required />
                </div>
            </div>
            <?php
        }
    }

    /**
     * Verify whether a given callback hostname and scheme is trusted.
     *
     * @param string $host Hostname from success_url
     * @param string $scheme Protocol scheme (https, http, or custom app)
     * @return bool
     */
    public static function is_host_trusted(string $host, string $scheme = ''): bool {
        // If empty host or scheme, consider untrusted
        if ($host === '') {
            // Check for valid local custom mobile app URI schemes (e.g. "my-app://callback" where host may be empty)
            if ($scheme !== '' && !in_array($scheme, ['http', 'https'], true)) {
                return true;
            }
            return false;
        }

        $host = strtolower(trim($host));

        // 1. Loopback addresses are always trusted for local CLI or native apps
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return true;
        }

        // 2. Local canonical site hostnames
        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $site_host = wp_parse_url(site_url(), PHP_URL_HOST);

        if ($home_host && strtolower($home_host) === $host) {
            return true;
        }
        if ($site_host && strtolower($site_host) === $host) {
            return true;
        }

        // 3. User-approved whitelist
        $allowed = get_option(self::OPTION_ALLOWED_DOMAINS, []);
        if (is_array($allowed) && !empty($allowed)) {
            foreach ($allowed as $allowed_pattern) {
                $pattern = strtolower(trim((string) $allowed_pattern));
                if ($pattern === '') {
                    continue;
                }

                // Direct exact match
                if ($pattern === $host) {
                    return true;
                }

                // Wildcard subdomain matching (*.example.com)
                if (str_starts_with($pattern, '*.')) {
                    $suffix = substr($pattern, 1); // e.g. .example.com
                    if (str_ends_with($host, $suffix)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Hook into wp_create_application_password for telemetry and audit logging.
     *
     * @param int    $user_id User ID
     * @param string $new_password Generated raw password
     * @param array  $new_item Created item record (uuid, app_id, name, created)
     * @param string $raw_password Unhashed password
     * @return void
     */
    public static function on_application_password_created(int $user_id, string $new_password, array $new_item, string $raw_password): void {
        $user      = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $username  = $user instanceof \WP_User ? $user->user_login : "User #{$user_id}";
        $app_name  = sanitize_text_field($new_item['name'] ?? 'Unknown App');
        $uuid      = sanitize_text_field($new_item['uuid'] ?? '');
        $client_ip = class_exists(FirewallEngine::class) ? FirewallEngine::get_client_ip() : (sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1')));

        // Log to WebCareActivityLogger
        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::log(
                'application_password_created',
                'auth',
                'notice',
                [
                    'user_id'     => $user_id,
                    'username'    => $username,
                    'app_name'    => $app_name,
                    'uuid'        => $uuid,
                    'ip'          => $client_ip,
                    'user_agent'  => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
                    'description' => sprintf(
                        'New Application Password "%s" (UUID: %s) generated for user "%s" from IP %s.',
                        $app_name,
                        $uuid,
                        $username,
                        $client_ip
                    ),
                ]
            );
        }
    }

    /**
     * Query all active Application Passwords across all user accounts.
     *
     * @return array
     */
    public static function get_all_passwords(): array {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_id, meta_value FROM `{$wpdb->usermeta}` WHERE meta_key = %s",
                '_application_passwords'
            )
        );

        $passwords = [];
        $now       = time();

        if (!empty($rows)) {
            foreach ($rows as $row) {
                $user_id = (int) $row->user_id;
                $user    = function_exists('get_userdata') ? get_userdata($user_id) : null;
                if (!$user instanceof \WP_User) {
                    continue;
                }

                $meta_items = maybe_unserialize($row->meta_value);
                if (!is_array($meta_items)) {
                    continue;
                }

                $is_admin = user_can($user, 'manage_options');
                $roles    = !empty($user->roles) ? (array) $user->roles : [];

                foreach ($meta_items as $item) {
                    if (!is_array($item) || empty($item['uuid'])) {
                        continue;
                    }

                    $created   = isset($item['created']) ? (int) $item['created'] : 0;
                    $last_used = isset($item['last_used']) ? (int) $item['last_used'] : null;
                    $last_ip   = !empty($item['last_ip']) ? (string) $item['last_ip'] : null;

                    // Stale calculation: Never used after 30 days, OR last used > 90 days ago
                    $is_stale = false;
                    if ($last_used === null && $created > 0 && ($now - $created) > (30 * DAY_IN_SECONDS)) {
                        $is_stale = true;
                    } elseif ($last_used !== null && ($now - $last_used) > (90 * DAY_IN_SECONDS)) {
                        $is_stale = true;
                    }

                    $passwords[] = [
                        'user_id'         => $user_id,
                        'user_login'      => $user->user_login,
                        'display_name'    => $user->display_name,
                        'user_email'      => $user->user_email,
                        'user_roles'      => $roles,
                        'is_admin'        => $is_admin,
                        'uuid'            => (string) $item['uuid'],
                        'app_id'          => !empty($item['app_id']) ? (string) $item['app_id'] : '',
                        'name'            => !empty($item['name']) ? (string) $item['name'] : __('(Unnamed Application)', 'webcare-pro-security'),
                        'created'         => $created,
                        'created_human'   => $created > 0 ? human_time_diff($created, $now) . ' ' . __('ago', 'webcare-pro-security') : __('Unknown', 'webcare-pro-security'),
                        'created_date'    => $created > 0 ? gmdate('Y-m-d H:i:s', $created) : '',
                        'last_used'       => $last_used,
                        'last_used_human' => $last_used ? human_time_diff($last_used, $now) . ' ' . __('ago', 'webcare-pro-security') : __('Never Used', 'webcare-pro-security'),
                        'last_used_date'  => $last_used ? gmdate('Y-m-d H:i:s', $last_used) : null,
                        'last_ip'         => $last_ip,
                        'is_stale'        => $is_stale,
                    ];
                }
            }
        }

        // Sort by created descending
        usort($passwords, function ($a, $b) {
            return ($b['created'] ?? 0) <=> ($a['created'] ?? 0);
        });

        return $passwords;
    }

    /**
     * Revoke a specific Application Password for a user.
     *
     * @param int    $user_id User ID
     * @param string $uuid Application password UUID
     * @return bool
     */
    public static function revoke_password(int $user_id, string $uuid): bool {
        if (!class_exists(\WP_Application_Passwords::class)) {
            require_once ABSPATH . 'wp-includes/class-wp-application-passwords.php';
        }

        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $username = $user instanceof \WP_User ? $user->user_login : "User #{$user_id}";

        $result = \WP_Application_Passwords::delete_application_password($user_id, $uuid);

        if ($result && class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::log(
                'application_password_revoked',
                'auth',
                'notice',
                [
                    'user_id'     => $user_id,
                    'username'    => $username,
                    'uuid'        => $uuid,
                    'description' => sprintf('Revoked Application Password (UUID: %s) for user "%s".', $uuid, $username),
                ]
            );
        }

        return (bool) $result;
    }

    /**
     * Revoke all Application Passwords for a user.
     *
     * @param int $user_id User ID
     * @return bool
     */
    public static function revoke_all_for_user(int $user_id): bool {
        if (!class_exists(\WP_Application_Passwords::class)) {
            require_once ABSPATH . 'wp-includes/class-wp-application-passwords.php';
        }

        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $username = $user instanceof \WP_User ? $user->user_login : "User #{$user_id}";

        $result = \WP_Application_Passwords::delete_all_application_passwords($user_id);

        if ($result && class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::log(
                'application_passwords_bulk_revoked',
                'auth',
                'notice',
                [
                    'user_id'     => $user_id,
                    'username'    => $username,
                    'description' => sprintf('Revoked ALL Application Passwords for user "%s".', $username),
                ]
            );
        }

        return (bool) $result;
    }

    /**
     * Get current sentinel configuration and telemetry metrics.
     *
     * @return array
     */
    public static function get_settings(): array {
        $disabled   = (bool) get_option(self::OPTION_DISABLED, 0);
        $admin_only = (bool) get_option(self::OPTION_ADMIN_ONLY, 1);
        $allowed    = get_option(self::OPTION_ALLOWED_DOMAINS, []);
        if (!is_array($allowed)) {
            $allowed = [];
        }

        $passwords = self::get_all_passwords();
        $total     = count($passwords);
        $stale     = 0;
        $admin_cnt = 0;
        $user_cnt  = 0;

        foreach ($passwords as $p) {
            if (!empty($p['is_stale'])) {
                $stale++;
            }
            if (!empty($p['is_admin'])) {
                $admin_cnt++;
            } else {
                $user_cnt++;
            }
        }

        $home_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: 'localhost';
        $site_host = wp_parse_url(site_url(), PHP_URL_HOST) ?: 'localhost';

        return [
            'disabled_globally'        => $disabled,
            'admin_only'               => $admin_only,
            'require_step_up_2fa'      => (bool) get_option(self::OPTION_REQUIRE_STEP_UP, 1),
            'allowed_callback_domains' => array_values(array_unique(array_filter($allowed))),
            'canonical_hosts'          => array_values(array_unique([$home_host, $site_host, '127.0.0.1', 'localhost'])),
            'core_supports_app_pass'   => function_exists('wp_is_application_passwords_available') && wp_is_application_passwords_available(),
            'stats'                    => [
                'total_active'      => $total,
                'stale_count'       => $stale,
                'admin_count'       => $admin_cnt,
                'non_admin_count'   => $user_cnt,
            ],
        ];
    }

    /**
     * Update sentinel settings.
     *
     * @param array $params Settings array
     * @return bool
     */
    public static function update_settings(array $params): bool {
        if (isset($params['disabled_globally'])) {
            update_option(self::OPTION_DISABLED, !empty($params['disabled_globally']) ? 1 : 0);
        }

        if (isset($params['admin_only'])) {
            update_option(self::OPTION_ADMIN_ONLY, !empty($params['admin_only']) ? 1 : 0);
        }

        if (isset($params['require_step_up_2fa'])) {
            update_option(self::OPTION_REQUIRE_STEP_UP, !empty($params['require_step_up_2fa']) ? 1 : 0);
        }

        if (isset($params['allowed_callback_domains']) && is_array($params['allowed_callback_domains'])) {
            $cleaned = [];
            foreach ($params['allowed_callback_domains'] as $domain) {
                $domain = strtolower(trim((string) $domain));
                // Remove protocol if user typed https://
                $domain = preg_replace('#^https?://#i', '', $domain);
                // Remove path
                $domain = explode('/', $domain)[0];
                $domain = trim($domain);
                if ($domain !== '' && preg_match('/^(\*\.)?[a-z0-9\.\-]+$/i', $domain)) {
                    $cleaned[] = $domain;
                }
            }
            update_option(self::OPTION_ALLOWED_DOMAINS, array_values(array_unique($cleaned)));
        }

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::log(
                'app_password_sentinel_settings_updated',
                'settings',
                'info',
                [
                    'disabled_globally'   => (bool) get_option(self::OPTION_DISABLED, 0),
                    'admin_only'          => (bool) get_option(self::OPTION_ADMIN_ONLY, 1),
                    'require_step_up_2fa' => (bool) get_option(self::OPTION_REQUIRE_STEP_UP, 1),
                    'allowed_domains'     => get_option(self::OPTION_ALLOWED_DOMAINS, []),
                ]
            );
        }

        return true;
    }
}
