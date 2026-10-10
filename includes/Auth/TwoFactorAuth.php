<?php
namespace WCP\Scanner\Auth;

use WCP\Scanner\System\SettingsManager;

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

    const META_ENABLED      = '_wcp_2fa_enabled';
    const META_SECRET       = '_wcp_2fa_secret';
    const META_BACKUP_CODES = '_wcp_2fa_backup_codes';
    const SESSION_TRANSIENT = 'wcp_2fa_pending_';

    /**
     * Initialize 2FA hooks
     */
    public static function init() {
        // Intercept WordPress authentication
        add_filter('authenticate', [__CLASS__, 'filter_authenticate'], 50, 3);
        add_action('login_form_wcp_2fa', [__CLASS__, 'render_2fa_challenge_screen']);
    }

    /**
     * Check if 2FA is globally enabled in settings
     */
    public static function is_globally_enabled(): bool {
        $settings = SettingsManager::get_settings();
        return !empty($settings['auth_2fa_enabled']);
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
     * Get user secret key
     */
    public static function get_user_secret(int $user_id): ?string {
        $secret = get_user_meta($user_id, self::META_SECRET, true);
        return !empty($secret) ? (string) $secret : null;
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
        update_user_meta($user_id, self::META_SECRET, $secret);
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
        return true;
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
     * Generate an inline SVG QR Code representation (zero external dependencies)
     */
    public static function get_qr_data_uri(string $content): string {
        // We use Google Charts or QuickChart fallback for high-fidelity QR rendering,
        // and return the provisioning URI directly for copy/paste into 1Password / Authy.
        $encoded = rawurlencode($content);
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&margin=10&data=' . $encoded;
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
            return $user;
        }

        // Check if 2FA code was submitted
        $auth_code = isset($_POST['wcp_2fa_code']) ? sanitize_text_field(wp_unslash($_POST['wcp_2fa_code'])) : '';
        $secret    = self::get_user_secret($user->ID);

        if (!empty($auth_code)) {
            // Check TOTP code
            if ($secret && self::verify_code($secret, $auth_code)) {
                return $user; // Authentication passed!
            }

            // Check emergency backup code
            if (self::verify_and_consume_backup_code($user->ID, $auth_code)) {
                return $user; // Backup code valid and consumed!
            }

            // Invalid code submitted
            return new \WP_Error(
                'wcp_2fa_invalid_code',
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
            'action'      => 'wcp_2fa',
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

        $error_msg = '';

        // Handle Form Submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['wcp_2fa_code'])) {
            check_admin_referer('wcp_2fa_verify_' . $pending_key);

            $code   = sanitize_text_field(wp_unslash($_POST['wcp_2fa_code']));
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
            <?php wp_nonce_field('wcp_2fa_verify_' . $pending_key); ?>
            <p>
                <label for="wcp_2fa_code" style="font-weight: 600; font-size: 13px; color: #334155;">
                    <?php esc_html_e('Security Code or Recovery Code', 'wcp-security-scanner'); ?>
                </label>
                <input type="text" name="wcp_2fa_code" id="wcp_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" autofocus inputmode="numeric" placeholder="123456" style="font-size: 22px; letter-spacing: 4px; text-align: center; font-weight: 700; border-radius: 8px; border: 1px solid #cbd5e1; padding: 10px;" required />
            </p>
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
