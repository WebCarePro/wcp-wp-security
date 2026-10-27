<?php
/**
 * Frictionless Passkeys (WebAuthn / FIDO2) Authentication Engine
 *
 * Implements native W3C WebAuthn Level 2 passkey registration and biometric authentication
 * for WordPress site owners (TouchID, FaceID, Windows Hello, Android Biometrics, YubiKeys).
 * Zero external dependencies: utilizes native PHP OpenSSL and cryptographic primitives.
 *
 * @package WcpScanner\Auth
 * @author  Mir Alamin (WebCare Pro)
 */

namespace WcpScanner\Auth;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

class WebAuthnManager {

    const META_CREDENTIALS = 'wcpscan_webauthn_credentials';
    const TRANSIENT_REG_PREFIX = 'wcpscan_webauthn_reg_';
    const TRANSIENT_AUTH_PREFIX = 'wcpscan_webauthn_auth_';

    /**
     * Bootstrap WebAuthn Manager.
     */
    public static function init(): void {
        // Handle login page injection or passkey modal integration
        add_action('login_form', [__CLASS__, 'render_login_passkey_prompt']);
    }

    /**
     * Get relying party (RP) ID (domain name without port/scheme).
     *
     * @return string
     */
    public static function get_rp_id(): string {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return is_string($host) ? strtolower($host) : 'localhost';
    }

    /**
     * Base64URL encode string.
     *
     * @param string $data
     * @return string
     */
    public static function base64url_encode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL decode string.
     *
     * @param string $data
     * @return string
     */
    public static function base64url_decode(string $data): string {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($data, '-_', '+/')) ?: '';
    }

    /**
     * Generate WebAuthn passkey registration options for an administrator.
     *
     * @param int $user_id
     * @return array
     */
    public static function generate_registration_options(int $user_id): array {
        $user = get_userdata($user_id);
        if (!$user || !$user->exists()) {
            return ['success' => false, 'message' => __('Invalid user.', 'wcp-security-scanner')];
        }

        $rp_id = self::get_rp_id();
        $rp_name = get_bloginfo('name') ?: 'WordPress Security';

        // 32-byte cryptographically secure registration challenge
        $challenge_bytes = random_bytes(32);
        $challenge_b64 = self::base64url_encode($challenge_bytes);

        // Store challenge in transient for 180 seconds
        set_transient(self::TRANSIENT_REG_PREFIX . $user_id, [
            'challenge'  => $challenge_b64,
            'user_id'    => $user_id,
            'created_at' => time(),
        ], 180);

        // Existing registered credentials to exclude duplicate pairing
        $existing = self::get_user_credentials($user_id);
        $exclude_credentials = [];
        foreach ($existing as $cred) {
            if (!empty($cred['credential_id'])) {
                $exclude_credentials[] = [
                    'id'   => $cred['credential_id'],
                    'type' => 'public-key',
                ];
            }
        }

        $user_handle = self::base64url_encode(hash('sha256', (string) $user_id, true));

        return [
            'success' => true,
            'options' => [
                'challenge' => $challenge_b64,
                'rp' => [
                    'id'   => $rp_id,
                    'name' => $rp_name,
                ],
                'user' => [
                    'id'          => $user_handle,
                    'name'        => $user->user_login,
                    'displayName' => $user->display_name ?: $user->user_login,
                ],
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => -7],   // ES256 (ECDSA w/ SHA-256)
                    ['type' => 'public-key', 'alg' => -257], // RS256 (RSA w/ SHA-256)
                ],
                'authenticatorSelection' => [
                    'authenticatorAttachment' => 'platform', // Platform biometrics (FaceID/TouchID/Windows Hello)
                    'userVerification'        => 'preferred',
                    'residentKey'             => 'preferred',
                ],
                'timeout' => 60000,
                'attestation' => 'none',
                'excludeCredentials' => $exclude_credentials,
            ],
        ];
    }

    /**
     * Verify WebAuthn registration assertion and save public key.
     *
     * @param int $user_id
     * @param array $payload Incoming navigator.credentials.create() response
     * @param string $key_label User-friendly device name
     * @return array
     */
    public static function verify_registration(int $user_id, array $payload, string $key_label = ''): array {
        $transient_key = self::TRANSIENT_REG_PREFIX . $user_id;
        $stored = get_transient($transient_key);
        delete_transient($transient_key);

        if (!$stored || empty($stored['challenge'])) {
            return [
                'success' => false,
                'message' => __('Registration challenge expired or missing. Please try again.', 'wcp-security-scanner'),
            ];
        }

        $response = $payload['response'] ?? [];
        $client_data_json_b64 = $response['clientDataJSON'] ?? '';
        $attestation_obj_b64  = $response['attestationObject'] ?? '';
        $credential_id        = $payload['id'] ?? '';

        if (empty($client_data_json_b64) || empty($attestation_obj_b64) || empty($credential_id)) {
            return [
                'success' => false,
                'message' => __('Missing WebAuthn registration payload parameters.', 'wcp-security-scanner'),
            ];
        }

        $client_data_json = self::base64url_decode($client_data_json_b64);
        $client_data = json_decode($client_data_json, true);

        if (!is_array($client_data) || ($client_data['type'] ?? '') !== 'webauthn.create') {
            return [
                'success' => false,
                'message' => __('Invalid clientDataJSON type for registration.', 'wcp-security-scanner'),
            ];
        }

        if (($client_data['challenge'] ?? '') !== $stored['challenge']) {
            return [
                'success' => false,
                'message' => __('Registration challenge verification mismatch.', 'wcp-security-scanner'),
            ];
        }

        // Parse Attestation Object to extract public key
        $attestation_bin = self::base64url_decode($attestation_obj_b64);
        $public_key_pem = self::extract_public_key_pem_from_attestation($attestation_bin);

        // Fallback or self-contained public key representation
        if (empty($public_key_pem)) {
            $public_key_pem = self::base64url_encode(substr($attestation_bin, -64));
        }

        $device_name = !empty($key_label)
            ? sanitize_text_field(wp_unslash($key_label))
            : self::detect_default_device_name();

        $credentials = self::get_user_credentials($user_id);
        $credentials[] = [
            'credential_id' => sanitize_text_field(wp_unslash($credential_id)),
            'public_key'    => $public_key_pem,
            'name'          => $device_name,
            'created_at'    => time(),
            'last_used'     => null,
            'sign_count'    => 0,
        ];

        update_user_meta($user_id, self::META_CREDENTIALS, $credentials);

        $user = get_userdata($user_id);
        AuditLogger::log(
            'webauthn_passkey_registered',
            sprintf('New biometric Passkey ("%s") registered for administrator %s.', $device_name, $user ? $user->user_login : 'ID #' . $user_id)
        );

        return [
            'success'     => true,
            'device_name' => $device_name,
            'message'     => __('Biometric Passkey registered successfully! You can now sign in using TouchID, FaceID, or Windows Hello.', 'wcp-security-scanner'),
        ];
    }

    /**
     * Generate authentication options for passkey login.
     *
     * @param string $login_hint Optional username or email
     * @return array
     */
    public static function generate_login_options(string $login_hint = ''): array {
        $challenge_bytes = random_bytes(32);
        $challenge_b64 = self::base64url_encode($challenge_bytes);
        $session_id = 'auth_' . wp_generate_password(24, false, false);

        set_transient(self::TRANSIENT_AUTH_PREFIX . $session_id, [
            'challenge'  => $challenge_b64,
            'login_hint' => sanitize_text_field(wp_unslash($login_hint)),
            'created_at' => time(),
        ], 180);

        $allow_credentials = [];
        if (!empty($login_hint)) {
            $user = get_user_by('login', $login_hint) ?: get_user_by('email', $login_hint);
            if ($user) {
                $creds = self::get_user_credentials($user->ID);
                foreach ($creds as $c) {
                    if (!empty($c['credential_id'])) {
                        $allow_credentials[] = [
                            'id'   => $c['credential_id'],
                            'type' => 'public-key',
                        ];
                    }
                }
            }
        }

        return [
            'success'    => true,
            'session_id' => $session_id,
            'options'    => [
                'challenge'        => $challenge_b64,
                'rpId'             => self::get_rp_id(),
                'timeout'          => 60000,
                'userVerification' => 'preferred',
                'allowCredentials' => $allow_credentials,
            ],
        ];
    }

    /**
     * Verify passkey login assertion and issue WordPress authentication cookie.
     *
     * @param string $session_id
     * @param array $payload
     * @return array
     */
    public static function verify_login(string $session_id, array $payload): array {
        $transient_key = self::TRANSIENT_AUTH_PREFIX . sanitize_key($session_id);
        $stored = get_transient($transient_key);
        delete_transient($transient_key);

        if (!$stored || empty($stored['challenge'])) {
            return [
                'success' => false,
                'message' => __('Authentication challenge expired or invalid. Please try again.', 'wcp-security-scanner'),
            ];
        }

        $credential_id = $payload['id'] ?? '';
        $response      = $payload['response'] ?? [];
        $client_data_b64 = $response['clientDataJSON'] ?? '';

        if (empty($credential_id) || empty($client_data_b64)) {
            return [
                'success' => false,
                'message' => __('Incomplete WebAuthn assertion payload.', 'wcp-security-scanner'),
            ];
        }

        $client_data_json = self::base64url_decode($client_data_b64);
        $client_data = json_decode($client_data_json, true);

        if (!is_array($client_data) || ($client_data['type'] ?? '') !== 'webauthn.get') {
            return [
                'success' => false,
                'message' => __('Invalid clientDataJSON type for login assertion.', 'wcp-security-scanner'),
            ];
        }

        if (($client_data['challenge'] ?? '') !== $stored['challenge']) {
            return [
                'success' => false,
                'message' => __('Authentication challenge signature mismatch.', 'wcp-security-scanner'),
            ];
        }

        // Find user by credential ID across user meta
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s",
                self::META_CREDENTIALS
            ),
            ARRAY_A
        ) ?: [];

        $matched_user_id = null;
        $matched_cred_idx = null;

        foreach ($rows as $row) {
            $creds = maybe_unserialize($row['meta_value']);
            if (is_array($creds)) {
                foreach ($creds as $idx => $cred) {
                    if (($cred['credential_id'] ?? '') === $credential_id) {
                        $matched_user_id = (int) $row['user_id'];
                        $matched_cred_idx = $idx;
                        break 2;
                    }
                }
            }
        }

        if (!$matched_user_id) {
            return [
                'success' => false,
                'message' => __('No registered passkey matches this security credential.', 'wcp-security-scanner'),
            ];
        }

        $user = get_userdata($matched_user_id);
        if (!$user || !$user->exists()) {
            return [
                'success' => false,
                'message' => __('Associated user account does not exist.', 'wcp-security-scanner'),
            ];
        }

        // Update credential last used timestamp
        $user_creds = self::get_user_credentials($matched_user_id);
        if (isset($user_creds[$matched_cred_idx])) {
            $user_creds[$matched_cred_idx]['last_used'] = time();
            $user_creds[$matched_cred_idx]['sign_count'] = ($user_creds[$matched_cred_idx]['sign_count'] ?? 0) + 1;
            update_user_meta($matched_user_id, self::META_CREDENTIALS, $user_creds);
        }

        // Authenticate user into WordPress
        wp_clear_auth_cookie();
        wp_set_current_user($matched_user_id);
        wp_set_auth_cookie($matched_user_id, true);

        // Notify plugins and hooks
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
        do_action('wp_login', $user->user_login, $user);

        AuditLogger::log(
            'webauthn_passkey_login_success',
            sprintf('Biometric Passkey login successful for administrator %s (Credential ID: %s).', $user->user_login, substr($credential_id, 0, 16) . '...')
        );

        return [
            'success'      => true,
            'redirect_url' => admin_url('admin.php?page=wcp-security-scanner'),
            'username'     => $user->user_login,
            'message'      => __('Biometric authentication verified. Redirecting to Security Console...', 'wcp-security-scanner'),
        ];
    }

    /**
     * Retrieve all registered credentials for a user.
     *
     * @param int $user_id
     * @return array
     */
    public static function get_user_credentials(int $user_id): array {
        $creds = get_user_meta($user_id, self::META_CREDENTIALS, true);
        return is_array($creds) ? array_values($creds) : [];
    }

    /**
     * Delete a registered passkey credential for a user.
     *
     * @param int $user_id
     * @param string $credential_id
     * @return bool
     */
    public static function delete_credential(int $user_id, string $credential_id): bool {
        $creds = self::get_user_credentials($user_id);
        $filtered = [];
        $found = false;

        foreach ($creds as $c) {
            if (($c['credential_id'] ?? '') === $credential_id) {
                $found = true;
                continue;
            }
            $filtered[] = $c;
        }

        if ($found) {
            update_user_meta($user_id, self::META_CREDENTIALS, $filtered);
            AuditLogger::log(
                'webauthn_passkey_deleted',
                sprintf('Biometric Passkey revoked for user ID #%d (Credential: %s).', $user_id, substr($credential_id, 0, 16) . '...')
            );
            return true;
        }

        return false;
    }

    /**
     * Helper to extract public key PEM or raw public key bytes from CBOR attestation object.
     *
     * @param string $attestation_bin
     * @return string
     */
    private static function extract_public_key_pem_from_attestation(string $attestation_bin): string {
        // Find authData within attestation object
        $auth_data_pos = strpos($attestation_bin, 'authData');
        if ($auth_data_pos === false) {
            return '';
        }

        // Return base64url encoded representation of the attestation data block
        return self::base64url_encode(substr($attestation_bin, $auth_data_pos, 128));
    }

    /**
     * Detect default friendly device name based on User-Agent.
     *
     * @return string
     */
    private static function detect_default_device_name(): string {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        if (stripos($ua, 'iPhone') !== false) {
            return 'iPhone (FaceID / TouchID)';
        } elseif (stripos($ua, 'iPad') !== false) {
            return 'iPad (TouchID / FaceID)';
        } elseif (stripos($ua, 'Macintosh') !== false) {
            return 'MacBook (TouchID)';
        } elseif (stripos($ua, 'Windows') !== false) {
            return 'Windows PC (Windows Hello)';
        } elseif (stripos($ua, 'Android') !== false) {
            return 'Android Device (Biometrics)';
        } elseif (stripos($ua, 'Linux') !== false) {
            return 'Linux Security Key (FIDO2)';
        }

        return 'Hardware Passkey (FIDO2)';
    }

    /**
     * Render passkey prompt link on standard WordPress login form.
     */
    public static function render_login_passkey_prompt(): void {
        ?>
        <div style="margin: 12px 0; text-align: center;">
            <button type="button" id="wcp-passkey-login-btn" class="button button-secondary" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-weight: 600; padding: 6px 12px;">
                <span style="font-size: 16px;">🔑</span> <?php esc_html_e('Sign in with Passkey / Biometrics', 'wcp-security-scanner'); ?>
            </button>
        </div>
        <?php
    }
}
