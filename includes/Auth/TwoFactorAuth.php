<?php
namespace WcpScanner\Auth;

use WcpScanner\System\SettingsManager;
use WcpScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Two-Factor Authentication (2FA) Service
 *
 * Implements RFC 6238 TOTP (Time-based One-Time Password) algorithm in pure PHP.
 * Supports Google Authenticator, Authy, 1Password, Microsoft Authenticator.
 */
class TwoFactorAuth {

    const META_ENABLED         = '_wcpscan_2fa_enabled';
    const META_SECRET          = '_wcpscan_2fa_secret';
    const META_BACKUP_CODES    = '_wcpscan_2fa_backup_codes';
    const META_TRUSTED_DEVICES = '_wcpscan_2fa_trusted_devices';
    const META_GRACE_START     = '_wcpscan_2fa_grace_start';
    const SESSION_TRANSIENT    = 'wcpscan_2fa_pending_';
    const COOKIE_DEVICE        = 'wcpscan_2fa_trusted_device';

    /**
     * Initialize 2FA hooks
     */
    public static function init() {
        // Intercept WordPress authentication
        add_filter('authenticate', [__CLASS__, 'filter_authenticate'], 50, 3);
        add_action('login_form_wcpscan_2fa', [__CLASS__, 'render_2fa_challenge_screen']);
        // Revoke trusted devices on password reset for security
        add_action('password_reset', [__CLASS__, 'on_password_reset'], 10, 2);
        // Intercept admin dashboard if 2FA is strictly enforced and user grace period expired
        add_action('admin_init', [__CLASS__, 'enforce_admin_dashboard_access']);
        // Display admin notice during grace period
        add_action('admin_notices', [__CLASS__, 'render_enforcement_grace_notice']);
    }

    /**
     * Check if 2FA is globally enabled in settings
     */
    public static function is_globally_enabled(): bool {
        $settings = SettingsManager::get_settings();
        return !empty($settings['auth_2fa_enabled']);
    }

    /**
     * Check if 2FA is enforced for administrators
     */
    public static function is_enforced_for_admins(): bool {
        if (!self::is_globally_enabled()) {
            return false;
        }
        $settings = SettingsManager::get_settings();
        return !empty($settings['auth_2fa_enforce_admins']);
    }

    /**
     * Get 2FA enforcement policy mode ('immediate' | 'grace_period' | 'remind_login')
     */
    public static function get_enforcement_policy_mode(): string {
        $settings = SettingsManager::get_settings();
        $mode = $settings['auth_2fa_policy_mode'] ?? 'remind_login';
        return in_array($mode, ['immediate', 'grace_period', 'remind_login'], true) ? $mode : 'remind_login';
    }

    /**
     * Get 2FA grace period in days (0 = immediate)
     */
    public static function get_enforcement_grace_days(): int {
        $settings = SettingsManager::get_settings();
        return max(0, min(90, (int) ($settings['auth_2fa_grace_days'] ?? 0)));
    }

    /**
     * Check compliance status for a specific user
     * Returns: 'compliant' | 'grace_period' | 'remind_login' | 'enforcement_required' | 'not_enforced'
     */
    public static function get_user_compliance_status(int $user_id): array {
        $is_enabled = self::is_user_enabled($user_id);
        if ($is_enabled) {
            return [
                'status'         => 'compliant',
                'label'          => __('2FA Active & Compliant', 'wcp-security-scanner'),
                'is_compliant'   => true,
                'grace_remaining'=> 0,
                'days_left'      => 0,
            ];
        }

        if (!self::is_enforced_for_admins()) {
            return [
                'status'         => 'not_enforced',
                'label'          => __('2FA Optional / Disabled', 'wcp-security-scanner'),
                'is_compliant'   => false,
                'grace_remaining'=> 0,
                'days_left'      => 0,
            ];
        }

        $user = get_user_by('id', $user_id);
        if (!$user || !in_array('administrator', (array) $user->roles, true)) {
            return [
                'status'         => 'not_enforced',
                'label'          => __('Non-Admin (Exempt)', 'wcp-security-scanner'),
                'is_compliant'   => true,
                'grace_remaining'=> 0,
                'days_left'      => 0,
            ];
        }

        $mode       = self::get_enforcement_policy_mode();
        $grace_days = self::get_enforcement_grace_days();

        // 1. Immediate Enforcement
        if ($mode === 'immediate' || ($mode === 'grace_period' && $grace_days <= 0)) {
            return [
                'status'         => 'enforcement_required',
                'label'          => __('Enforced Immediately (Action Required)', 'wcp-security-scanner'),
                'is_compliant'   => false,
                'grace_remaining'=> 0,
                'days_left'      => 0,
                'mode'           => 'immediate',
            ];
        }

        // 2. Check user grace start
        $grace_start = (int) get_user_meta($user_id, self::META_GRACE_START, true);
        if ($grace_start <= 0) {
            $settings = SettingsManager::get_settings();
            $grace_start = !empty($settings['auth_2fa_enforce_since']) ? (int) $settings['auth_2fa_enforce_since'] : time();
            update_user_meta($user_id, self::META_GRACE_START, $grace_start);
        }

        $grace_expires = $grace_start + ($grace_days * DAY_IN_SECONDS);
        $now = time();

        if ($now >= $grace_expires) {
            return [
                'status'         => 'enforcement_required',
                'label'          => __('Grace Period Expired (Locked)', 'wcp-security-scanner'),
                'is_compliant'   => false,
                'grace_remaining'=> 0,
                'days_left'      => 0,
                'mode'           => $mode,
            ];
        }

        $seconds_left = $grace_expires - $now;
        $days_left    = max(1, (int) ceil($seconds_left / DAY_IN_SECONDS));

        // 3. Remind on Next Login (with Grace Period)
        if ($mode === 'remind_login') {
            return [
                'status'         => 'remind_login',
                'label'          => sprintf(__('Remind on Login (%dd grace left)', 'wcp-security-scanner'), $days_left),
                'is_compliant'   => false,
                'grace_remaining'=> $seconds_left,
                'days_left'      => $days_left,
                'expires_at'     => $grace_expires,
                'mode'           => 'remind_login',
            ];
        }

        // 4. Standard Grace Period
        return [
            'status'         => 'grace_period',
            'label'          => sprintf(__('Grace Period: %d day(s) left', 'wcp-security-scanner'), $days_left),
            'is_compliant'   => false,
            'grace_remaining'=> $seconds_left,
            'days_left'      => $days_left,
            'expires_at'     => $grace_expires,
            'mode'           => 'grace_period',
        ];
    }

    /**
     * Enforce admin dashboard access: redirect unconfigured administrators if enforcement is mandatory
     */
    public static function enforce_admin_dashboard_access() {
        if (wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST)) {
            return;
        }

        $user_id = get_current_user_id();
        if (!$user_id || !current_user_can('administrator')) {
            return;
        }

        if (self::is_user_enabled($user_id)) {
            return;
        }

        if (!self::is_enforced_for_admins()) {
            return;
        }

        $compliance = self::get_user_compliance_status($user_id);
        if ($compliance['status'] === 'enforcement_required') {
            // Allow access ONLY to the 2FA configuration page
            $current_page = isset($_GET['page']) ? sanitize_text_field($_GET['page']) : '';
            if ($current_page !== 'wcp-security-scanner' || (isset($_GET['tab']) && $_GET['tab'] !== 'auth')) {
                wp_safe_redirect(admin_url('admin.php?page=wcp-security-scanner&tab=auth&forced=1'));
                exit;
            }
        }
    }

    /**
     * Render Grace Period Warning Notice in WP Admin Header
     */
    public static function render_enforcement_grace_notice() {
        $user_id = get_current_user_id();
        if (!$user_id || !current_user_can('administrator')) {
            return;
        }

        if (self::is_user_enabled($user_id) || !self::is_enforced_for_admins()) {
            return;
        }

        $compliance = self::get_user_compliance_status($user_id);
        if ($compliance['status'] === 'remind_login') {
            $days_left = $compliance['days_left'] ?? 1;
            $setup_url = admin_url('admin.php?page=wcp-scanner-auth&tab=2fa&setup=1');
            ?>
            <div class="notice notice-info is-dismissible" style="border-left-color: #0284c7; padding: 12px 16px;">
                <p style="margin: 0; font-size: 13.5px; font-weight: 500; color: #1e293b;">
                    <strong style="color: #0284c7;">🔔 <?php esc_html_e('Security Reminder: Configure Administrator 2FA', 'wcp-security-scanner'); ?></strong> —
                    <?php printf(esc_html__('Two-factor authentication is recommended for your account. You have %d day(s) before enforcement is finalized.', 'wcp-security-scanner'), (int) $days_left); ?>
                    <a href="<?php echo esc_url($setup_url); ?>" class="button button-primary" style="margin-left: 10px; background: #0284c7; border-color: #0284c7; font-weight: 600;">
                        <?php esc_html_e('Configure 2FA', 'wcp-security-scanner'); ?> &rarr;
                    </a>
                </p>
            </div>
            <?php
        } elseif ($compliance['status'] === 'grace_period') {
            $days_left = $compliance['days_left'] ?? 1;
            $setup_url = admin_url('admin.php?page=wcp-scanner-auth&tab=2fa&setup=1');
            ?>
            <div class="notice notice-warning is-dismissible" style="border-left-color: #f59e0b; padding: 12px 16px;">
                <p style="margin: 0; font-size: 13.5px; font-weight: 500; color: #1e293b;">
                    <strong style="color: #b45309;">⚠️ <?php esc_html_e('Action Required: Administrator 2FA Policy Enforced', 'wcp-security-scanner'); ?></strong> —
                    <?php printf(esc_html__('Two-factor authentication is mandatory for all administrator accounts. You have %d day(s) remaining before your account is restricted.', 'wcp-security-scanner'), (int) $days_left); ?>
                    <a href="<?php echo esc_url($setup_url); ?>" class="button button-secondary" style="margin-left: 10px; font-weight: 600;">
                        <?php esc_html_e('Setup 2FA Now', 'wcp-security-scanner'); ?> &rarr;
                    </a>
                </p>
            </div>
            <?php
        } elseif ($compliance['status'] === 'enforcement_required') {
            $setup_url = admin_url('admin.php?page=wcp-scanner-auth&tab=2fa&setup=1');
            ?>
            <div class="notice notice-error" style="border-left-color: #ef4444; padding: 12px 16px;">
                <p style="margin: 0; font-size: 13.5px; font-weight: 600; color: #991b1b;">
                    🛑 <?php esc_html_e('Mandatory Security Enforcement: Administrator 2FA Required', 'wcp-security-scanner'); ?> —
                    <?php esc_html_e('Your grace period has expired. You must configure two-factor authentication to restore full administrator privileges.', 'wcp-security-scanner'); ?>
                    <a href="<?php echo esc_url($setup_url); ?>" class="button button-primary" style="margin-left: 10px; background: #dc2626; border-color: #dc2626; font-weight: 600;">
                        <?php esc_html_e('Enable 2FA Now', 'wcp-security-scanner'); ?>
                    </a>
                </p>
            </div>
            <?php
        }
    }

    /**
     * Check if a specific user has 2FA enabled
     */
    public static function is_user_enabled(int $user_id): bool {
        if (!self::is_globally_enabled()) {
            return false;
        }
        return (bool) get_user_meta($user_id, self::META_ENABLED, true);
    }

    /**
     * Get user secret key (automatically decrypts encrypted secret and migrates plaintext)
     */
    public static function get_user_secret(int $user_id): ?string {
        $stored = get_user_meta($user_id, self::META_SECRET, true);
        if (empty($stored)) {
            return null;
        }

        $raw = (string) $stored;
        if (!SecretVault::is_encrypted($raw)) {
            // Auto-migrate plaintext secret to encrypted format in DB
            $encrypted = SecretVault::encrypt($raw);
            update_user_meta($user_id, self::META_SECRET, $encrypted);
            return $raw;
        }

        $decrypted = SecretVault::decrypt($raw);
        return !empty($decrypted) ? $decrypted : null;
    }

    /**
     * Generate a cryptographically secure Base32 secret key (16 characters)
     */
    public static function generate_secret(int $length = 16): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret   = '';
        $bytes    = random_bytes($length);

        for ($i = 0; $i < $length; $i++) {
            $secret .= $alphabet[ord($bytes[$i]) % 32];
        }

        return $secret;
    }

    /**
     * Decode a Base32 string into binary
     */
    public static function base32_decode(string $b32): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32      = strtoupper(trim($b32));
        $buffer   = 0;
        $bitsLeft = 0;
        $output   = '';

        for ($i = 0; $i < strlen($b32); $i++) {
            $val = strpos($alphabet, $b32[$i]);
            if ($val === false) {
                continue; // Skip padding or invalid characters
            }

            $buffer = ($buffer << 5) | $val;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $output;
    }

    /**
     * Calculate TOTP 6-digit code for a given timestamp
     */
    public static function calculate_code(string $secret, ?int $timestamp = null): string {
        if ($timestamp === null) {
            $timestamp = time();
        }

        $timeSlice    = (int) floor($timestamp / 30);
        $binarySecret = self::base32_decode($secret);

        // Pack 64-bit int into big-endian binary
        $binaryTime = pack('N*', 0) . pack('N*', $timeSlice);
        $hash       = hash_hmac('sha1', $binaryTime, $binarySecret, true);

        // Dynamic truncation (RFC 4226)
        $offset = ord($hash[19]) & 0x0F;
        $binary = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        );

        $otp = $binary % 1000000;
        return str_pad((string) $otp, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a 6-digit TOTP code with clock drift tolerance
     */
    public static function verify_code(string $secret, string $code, int $window = 1): bool {
        $code = trim($code);
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            return false;
        }

        $currentTime = time();

        for ($i = -$window; $i <= $window; $i++) {
            $checkTime = $currentTime + ($i * 30);
            if (hash_equals(self::calculate_code($secret, $checkTime), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate 8 single-use emergency backup codes
     */
    public static function generate_backup_codes(int $count = 8): array {
        $plain  = [];
        $hashed = [];

        for ($i = 0; $i < $count; $i++) {
            $part1   = strtolower(wp_generate_password(4, false, false));
            $part2   = strtolower(wp_generate_password(4, false, false));
            $code    = $part1 . '-' . $part2;
            $plain[] = $code;
            $hashed[] = wp_hash_password($code);
        }

        return [
            'plain'  => $plain,
            'hashed' => $hashed,
        ];
    }

    /**
     * Verify and consume a backup code for a user
     */
    public static function verify_and_consume_backup_code(int $user_id, string $code): bool {
        $code = strtolower(trim($code));
        $stored = get_user_meta($user_id, self::META_BACKUP_CODES, true);

        if (!is_array($stored) || empty($stored)) {
            return false;
        }

        foreach ($stored as $index => $hashed_code) {
            if (wp_check_password($code, $hashed_code)) {
                // Consume code
                unset($stored[$index]);
                update_user_meta($user_id, self::META_BACKUP_CODES, array_values($stored));
                return true;
            }
        }

        return false;
    }

    /**
     * Enable 2FA for a user
     */
    public static function enable_user(int $user_id, string $secret, array $hashed_backup_codes): bool {
        $encrypted_secret = SecretVault::encrypt($secret);
        update_user_meta($user_id, self::META_SECRET, $encrypted_secret);
        update_user_meta($user_id, self::META_BACKUP_CODES, $hashed_backup_codes);
        update_user_meta($user_id, self::META_ENABLED, 1);
        return true;
    }

    /**
     * Disable 2FA for a user
     */
    public static function disable_user(int $user_id): bool {
        delete_user_meta($user_id, self::META_ENABLED);
        delete_user_meta($user_id, self::META_SECRET);
        delete_user_meta($user_id, self::META_BACKUP_CODES);
        delete_user_meta($user_id, self::META_TRUSTED_DEVICES);
        delete_user_meta($user_id, self::META_GRACE_START);
        self::clear_trusted_device_cookie();
        return true;
    }

    /**
     * Reset 2FA for a user and generate new provisioning package
     */
    public static function reset_user_2fa(int $user_id): array {
        self::disable_user($user_id);
        $user = get_user_by('id', $user_id);
        if (!$user) {
            throw new \Exception(__('User not found.', 'wcp-security-scanner'));
        }

        $secret           = self::generate_secret(16);
        $provisioning_uri = self::get_provisioning_uri($secret, $user->user_login);
        $qr_data_uri      = self::get_qr_data_uri($provisioning_uri);
        $backup_bundle    = self::generate_backup_codes(8);

        // Auto-enable with the generated secret and backup codes
        self::enable_user($user_id, $secret, $backup_bundle['hashed']);

        return [
            'user_id'          => $user_id,
            'user_login'       => $user->user_login,
            'secret'           => $secret,
            'provisioning_uri' => $provisioning_uri,
            'qr_code_url'      => $qr_data_uri,
            'backup_codes'     => $backup_bundle['plain'],
        ];
    }

    /**
     * Clear all login failures/lockouts for a user's associated IP addresses or username
     */
    public static function unlock_user_lockouts(int $user_id): array {
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return ['unlocked_ips' => [], 'cleared_attempts' => false];
        }

        $unlocked_ips = [];
        $username = $user->user_login;

        if (class_exists('\\WcpScanner\\Auth\\LoginHardening')) {
            $lockouts = \WcpScanner\Auth\LoginHardening::get_locked_ips();
            foreach ($lockouts as $ip => $data) {
                if (isset($data['username']) && strtolower($data['username']) === strtolower($username)) {
                    \WcpScanner\Auth\LoginHardening::unlock_ip($ip);
                    $unlocked_ips[] = $ip;
                }
            }
        }

        return [
            'unlocked_ips'     => $unlocked_ips,
            'cleared_attempts' => true,
        ];
    }

    /**
     * Get all administrator users with 2FA status, compliance, lockouts, and session forensics
     */
    public static function get_administrators_status(): array {
        $admins = get_users(['role' => 'administrator', 'orderby' => 'registered', 'order' => 'ASC']);
        $result = [];

        $locked_ips = class_exists('\\WcpScanner\\Auth\\LoginHardening') ? \WcpScanner\Auth\LoginHardening::get_locked_ips() : [];
        $locked_usernames = [];
        foreach ($locked_ips as $ip => $data) {
            if (!empty($data['username'])) {
                $locked_usernames[strtolower($data['username'])][] = $ip;
            }
        }

        $current_user_id = get_current_user_id();

        foreach ($admins as $user) {
            $uid = (int) $user->ID;
            $compliance = self::get_user_compliance_status($uid);
            $devices    = self::get_trusted_devices($uid);
            $last_login = get_user_meta($uid, '_wcpscan_last_login', true);

            $user_locked_ips = $locked_usernames[strtolower($user->user_login)] ?? [];

            $result[] = [
                'user_id'          => $uid,
                'user_login'       => $user->user_login,
                'display_name'     => $user->display_name ?: $user->user_login,
                'user_email'       => $user->user_email,
                'avatar_url'       => get_avatar_url($user->user_email, ['size' => 64]),
                'is_current_user'  => ($uid === $current_user_id),
                'is_2fa_enabled'   => self::is_user_enabled($uid),
                'compliance'       => $compliance,
                'trusted_devices'  => count($devices),
                'registered_at'    => $user->user_registered,
                'last_login'       => !empty($last_login) ? $last_login : null,
                'is_locked'        => !empty($user_locked_ips),
                'locked_ips'       => $user_locked_ips,
            ];
        }

        return $result;
    }

    /**
     * Hook: On user password reset, purge all trusted devices
     */
    public static function on_password_reset($user, $new_pass = '') {
        if ($user instanceof \WP_User) {
            self::revoke_all_trusted_devices($user->ID);
        }
    }

    /**
     * Check if "Remember Device" feature is allowed in settings
     */
    public static function is_remember_device_enabled(): bool {
        $settings = SettingsManager::get_settings();
        return !empty($settings['auth_2fa_remember_device']);
    }

    /**
     * Get number of days to remember trusted devices (default 7 days)
     */
    public static function get_remember_device_days(): int {
        $settings = SettingsManager::get_settings();
        $days     = (int) ($settings['auth_2fa_remember_days'] ?? 7);
        return max(1, min(90, $days));
    }

    /**
     * Check if the current client request is an authenticated trusted device for a user
     */
    public static function is_trusted_device(int $user_id): bool {
        if (!self::is_remember_device_enabled()) {
            return false;
        }

        if (empty($_COOKIE[self::COOKIE_DEVICE])) {
            return false;
        }

        $raw_cookie = sanitize_text_field(wp_unslash($_COOKIE[self::COOKIE_DEVICE]));
        if (empty($raw_cookie) || strpos($raw_cookie, ':') === false) {
            return false;
        }

        list($cookie_user_id, $token) = explode(':', $raw_cookie, 2);
        if ((int) $cookie_user_id !== $user_id || empty($token)) {
            return false;
        }

        $devices = get_user_meta($user_id, self::META_TRUSTED_DEVICES, true);
        if (!is_array($devices) || empty($devices)) {
            return false;
        }

        $now          = time();
        $token_hash   = hash('sha256', $token);
        $found        = false;
        $active_list  = [];

        foreach ($devices as $id => $device) {
            // Prune expired devices
            if (empty($device['expires_at']) || $device['expires_at'] < $now) {
                continue;
            }

            if (hash_equals($device['token_hash'], $token_hash)) {
                $found = true;
                // Update last used timestamp
                $device['last_used'] = current_time('mysql');
            }

            $active_list[$id] = $device;
        }

        // Persist cleaned up list if any expired were pruned or last_used was updated
        if (count($active_list) !== count($devices) || $found) {
            update_user_meta($user_id, self::META_TRUSTED_DEVICES, $active_list);
        }

        return $found;
    }

    /**
     * Issue a cryptographically secure trusted device cookie and save hash in user meta
     */
    public static function set_trusted_device(int $user_id, int $days = 7): bool {
        if (!self::is_remember_device_enabled()) {
            return false;
        }

        $token        = wp_generate_password(48, false);
        $token_hash   = hash('sha256', $token);
        $days         = $days > 0 ? $days : self::get_remember_device_days();
        $expires_at   = time() + ($days * DAY_IN_SECONDS);
        $user_agent   = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';
        $ip           = class_exists('\\WcpScanner\\Firewall\\FirewallEngine')
            ? \WcpScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '');
        $device_id    = wp_generate_password(16, false);

        $devices = get_user_meta($user_id, self::META_TRUSTED_DEVICES, true);
        if (!is_array($devices)) {
            $devices = [];
        }

        // Prune expired devices & keep maximum 10 active devices per user
        $now         = time();
        $active_list = [];
        foreach ($devices as $id => $d) {
            if (!empty($d['expires_at']) && $d['expires_at'] > $now) {
                $active_list[$id] = $d;
            }
        }

        if (count($active_list) >= 10) {
            // Remove oldest
            array_shift($active_list);
        }

        $active_list[$device_id] = [
            'id'          => $device_id,
            'token_hash'  => $token_hash,
            'expires_at'  => $expires_at,
            'created_at'  => current_time('mysql'),
            'last_used'   => current_time('mysql'),
            'ip'          => $ip,
            'user_agent'  => $user_agent,
            'days'        => $days,
        ];

        update_user_meta($user_id, self::META_TRUSTED_DEVICES, $active_list);

        // Set hardened cookie: HttpOnly, Secure, SameSite=Lax
        $cookie_value = $user_id . ':' . $token;
        $cookie_path  = COOKIEPATH ?: '/';
        $cookie_domain = COOKIE_DOMAIN ?: '';
        $is_ssl       = is_ssl();

        if (PHP_VERSION_ID >= 70300) {
            setcookie(self::COOKIE_DEVICE, $cookie_value, [
                'expires'  => $expires_at,
                'path'     => $cookie_path,
                'domain'   => $cookie_domain,
                'secure'   => $is_ssl,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        } else {
            setcookie(self::COOKIE_DEVICE, $cookie_value, $expires_at, $cookie_path, $cookie_domain, $is_ssl, true);
        }

        return true;
    }

    /**
     * Clear the trusted device cookie from the browser
     */
    public static function clear_trusted_device_cookie() {
        $cookie_path   = COOKIEPATH ?: '/';
        $cookie_domain = COOKIE_DOMAIN ?: '';
        if (PHP_VERSION_ID >= 70300) {
            setcookie(self::COOKIE_DEVICE, '', [
                'expires'  => time() - 3600,
                'path'     => $cookie_path,
                'domain'   => $cookie_domain,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        } else {
            setcookie(self::COOKIE_DEVICE, '', time() - 3600, $cookie_path, $cookie_domain, is_ssl(), true);
        }
    }

    /**
     * Revoke all trusted devices for a user
     */
    public static function revoke_all_trusted_devices(int $user_id): bool {
        delete_user_meta($user_id, self::META_TRUSTED_DEVICES);
        self::clear_trusted_device_cookie();
        return true;
    }

    /**
     * Get active trusted devices list for a user
     */
    public static function get_trusted_devices(int $user_id): array {
        $devices = get_user_meta($user_id, self::META_TRUSTED_DEVICES, true);
        if (!is_array($devices)) {
            return [];
        }

        $now    = time();
        $output = [];
        foreach ($devices as $d) {
            if (!empty($d['expires_at']) && $d['expires_at'] > $now) {
                $output[] = [
                    'id'         => $d['id'] ?? '',
                    'ip'         => $d['ip'] ?? '',
                    'user_agent' => $d['user_agent'] ?? '',
                    'created_at' => $d['created_at'] ?? '',
                    'last_used'  => $d['last_used'] ?? '',
                    'expires_at' => $d['expires_at'] ?? 0,
                    'days'       => $d['days'] ?? 7,
                ];
            }
        }
        return $output;
    }


    /**
     * Build provisioning URI for QR code generators
     */
    public static function get_provisioning_uri(string $secret, string $username): string {
        $issuer = get_bloginfo('name') ?: 'WordPress';
        $issuer = sanitize_text_field($issuer);
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
            rawurlencode($issuer),
            rawurlencode($username),
            $secret,
            rawurlencode($issuer)
        );
    }

    /**
     * Generate an inline SVG QR Code representation locally (zero external dependencies)
     */
    public static function get_qr_data_uri(string $content): string {
        try {
            return QRCodeGenerator::get_data_uri($content, 200);
        } catch (\Throwable $e) {
            $escaped = esc_html($content);
            return 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200"><rect width="100%" height="100%" fill="%23f1f5f9"/><text x="10" y="100" font-size="10" fill="%23334155">' . rawurlencode($escaped) . '</text></svg>';
        }
    }

    /**
     * Intercept WordPress Login Authentication
     */
    public static function filter_authenticate($user, $username, $password) {
        // If credentials already failed, let core handle it
        if (is_wp_error($user) || empty($username) || empty($password)) {
            return $user;
        }

        if (!($user instanceof \WP_User)) {
            return $user;
        }

        // Check if user has 2FA enabled
        if (!self::is_user_enabled($user->ID)) {
            // Check if user is an administrator and 2FA is enforced
            if (self::is_enforced_for_admins() && in_array('administrator', (array) $user->roles, true)) {
                $compliance = self::get_user_compliance_status($user->ID);
                if ($compliance['status'] === 'enforcement_required') {
                    // Force redirect directly to 2FA configuration wizard upon completing password auth
                    add_filter('login_redirect', function ($url, $requested, $user_obj) {
                        return admin_url('admin.php?page=wcp-security-scanner&tab=auth&subtab=2fa&setup=1&forced=1');
                    }, 99, 3);
                }
            }
            return $user;
        }

        // Check if current browser is a verified trusted device (e.g. remembered for 7 days)
        if (self::is_trusted_device($user->ID)) {
            return $user; // Trusted device bypass granted!
        }

        // Check if 2FA code was submitted
        $auth_code = isset($_POST['wcpscan_2fa_code']) ? sanitize_text_field(wp_unslash($_POST['wcpscan_2fa_code'])) : '';
        $secret    = self::get_user_secret($user->ID);

        if (!empty($auth_code)) {
            $code_valid = false;
            // Check TOTP code
            if ($secret && self::verify_code($secret, $auth_code)) {
                $code_valid = true;
            } elseif (self::verify_and_consume_backup_code($user->ID, $auth_code)) {
                $code_valid = true;
            }

            if ($code_valid) {
                if (!empty($_POST['wcpscan_2fa_remember_device'])) {
                    self::set_trusted_device($user->ID, self::get_remember_device_days());
                }
                return $user; // Authentication passed!
            }

            // Invalid code submitted
            return new \WP_Error(
                'wcpscan_2fa_invalid_code',
                __('<strong>Error:</strong> The two-factor authentication code you entered is invalid or has expired.', 'wcp-security-scanner')
            );
        }

        // If no 2FA code was provided on initial login submission, create a pending session and redirect to challenge screen
        $pending_key = wp_generate_password(32, false);
        set_transient(self::SESSION_TRANSIENT . $pending_key, [
            'user_id'    => $user->ID,
            'user_login' => $user->user_login,
            'remember'   => !empty($_POST['rememberme']),
        ], 300); // 5 minutes window

        $redirect_to = !empty($_REQUEST['redirect_to']) ? esc_url_raw($_REQUEST['redirect_to']) : admin_url();
        $challenge_url = add_query_arg([
            'action'      => 'wcpscan_2fa',
            'pending_key' => $pending_key,
            'redirect_to' => urlencode($redirect_to),
        ], wp_login_url());

        wp_safe_redirect($challenge_url);
        exit;
    }

    /**
     * Render the 2FA Challenge Screen on wp-login.php
     */
    public static function render_2fa_challenge_screen() {
        $pending_key = isset($_GET['pending_key']) ? sanitize_text_field(wp_unslash($_GET['pending_key'])) : '';
        $redirect_to = isset($_GET['redirect_to']) ? esc_url_raw(wp_unslash($_GET['redirect_to'])) : admin_url();
        $session     = get_transient(self::SESSION_TRANSIENT . $pending_key);

        if (!$session || empty($session['user_id'])) {
            wp_die(
                __('Your two-factor verification session has expired. Please log in again.', 'wcp-security-scanner'),
                __('Session Expired', 'wcp-security-scanner'),
                ['response' => 403, 'back_link' => true]
            );
        }

        $user_id = (int) $session['user_id'];
        $user    = get_user_by('id', $user_id);
        if (!$user) {
            wp_die(__('Invalid user session.', 'wcp-security-scanner'));
        }

        $remember_device_allowed = self::is_remember_device_enabled();
        $remember_days           = self::get_remember_device_days();
        $error_msg               = '';

        // Handle Form Submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['wcpscan_2fa_code'])) {
            check_admin_referer('wcpscan_2fa_verify_' . $pending_key);

            $code   = sanitize_text_field(wp_unslash($_POST['wcpscan_2fa_code']));
            $secret = self::get_user_secret($user_id);
            $valid  = false;

            if ($secret && self::verify_code($secret, $code)) {
                $valid = true;
            } elseif (self::verify_and_consume_backup_code($user_id, $code)) {
                $valid = true;
            }

            if ($valid) {
                // Delete session transient
                delete_transient(self::SESSION_TRANSIENT . $pending_key);

                // Handle "Remember this device"
                if (!empty($_POST['wcpscan_2fa_remember_device']) && $remember_device_allowed) {
                    self::set_trusted_device($user_id, $remember_days);
                }

                // Complete authentication
                wp_set_auth_cookie($user_id, !empty($session['remember']));
                do_action('wp_login', $user->user_login, $user);

                wp_safe_redirect($redirect_to);
                exit;
            } else {
                $error_msg = __('Invalid two-factor code. Please check your authenticator app or enter a recovery code.', 'wcp-security-scanner');
            }
        }

        // Render HTML Challenge Page
        login_header(__('Two-Factor Authentication', 'wcp-security-scanner'));
        ?>
        <div style="margin-bottom: 20px; text-align: center;">
            <div style="display: inline-block; background: #e0f2fe; padding: 12px; border-radius: 50%; margin-bottom: 12px;">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#0284c7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
            </div>
            <h2 style="font-size: 18px; margin: 0 0 6px 0; color: #0f172a; font-weight: 700;">
                <?php esc_html_e('Two-Factor Verification', 'wcp-security-scanner'); ?>
            </h2>
            <p style="font-size: 13px; color: #64748b; margin: 0;">
                <?php printf(esc_html__('Logged in as %s. Enter the 6-digit code from your authenticator app to complete sign-in.', 'wcp-security-scanner'), '<strong>' . esc_html($user->user_login) . '</strong>'); ?>
            </p>
        </div>

        <?php if (!empty($error_msg)): ?>
            <div id="login_error" style="border-left-color: #dc2626; margin-bottom: 20px;">
                <strong><?php esc_html_e('Verification Failed:', 'wcp-security-scanner'); ?></strong> <?php echo esc_html($error_msg); ?>
            </div>
        <?php endif; ?>

        <form name="wcp2faform" id="wcp2faform" action="" method="post" style="padding-bottom: 16px;">
            <?php wp_nonce_field('wcpscan_2fa_verify_' . $pending_key); ?>
            <p>
                <label for="wcpscan_2fa_code" style="font-weight: 600; font-size: 13px; color: #334155;">
                    <?php esc_html_e('Security Code or Recovery Code', 'wcp-security-scanner'); ?>
                </label>
                <input type="text" name="wcpscan_2fa_code" id="wcpscan_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" autofocus inputmode="numeric" placeholder="123456" style="font-size: 22px; letter-spacing: 4px; text-align: center; font-weight: 700; border-radius: 8px; border: 1px solid #cbd5e1; padding: 10px;" required />
            </p>

            <?php if ($remember_device_allowed): ?>
                <p style="margin: 14px 0 6px 0; display: flex; align-items: center; gap: 8px;">
                    <label for="wcpscan_2fa_remember_device" style="font-size: 13px; color: #334155; cursor: pointer; display: inline-flex; align-items: center; gap: 8px;">
                        <input type="checkbox" name="wcpscan_2fa_remember_device" id="wcpscan_2fa_remember_device" value="1" checked style="accent-color: #0284c7; width: 16px; height: 16px; margin: 0;" />
                        <span><?php printf(esc_html__('Remember this device for %d days', 'wcp-security-scanner'), (int) $remember_days); ?></span>
                    </label>
                </p>
            <?php endif; ?>

            <p class="submit" style="margin-top: 18px;">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e('Verify & Continue', 'wcp-security-scanner'); ?>" style="width: 100%; border-radius: 8px; background: #0284c7; border-color: #0284c7; height: 42px; font-weight: 600;" />
            </p>
        </form>

        <p id="backtoblog" style="text-align: center; margin-top: 20px;">
            <a href="<?php echo esc_url(wp_login_url()); ?>" style="font-size: 13px; color: #64748b;">
                &larr; <?php esc_html_e('Cancel and Return to Login', 'wcp-security-scanner'); ?>
            </a>
        </p>
        <?php
        login_footer();
        exit;
    }
}

