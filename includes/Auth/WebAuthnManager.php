<?php
/**
 * Frictionless Passkeys (WebAuthn / FIDO2) Authentication Engine
 *
 * Implements native W3C WebAuthn Level 2 passkey registration and biometric authentication
 * for WordPress site owners (TouchID, FaceID, Windows Hello, Android Biometrics, YubiKeys).
 * Zero external dependencies: utilizes native PHP OpenSSL and cryptographic primitives.
 *
 * @package WebCareProScanner\Auth
 * @author  Mir Alamin (WebCare Pro)
 */

namespace WebCareProScanner\Auth;

use WebCareProScanner\System\AuditLogger;
use WebCareProScanner\Notifications\NotificationDispatcher;

if (!defined('ABSPATH')) {
    exit;
}

class WebAuthnManager {

    const META_CREDENTIALS = 'webcareproscan_webauthn_credentials';
    const OPTION_CREDENTIAL_INDEX = 'webcareproscan_webauthn_index';
    const TRANSIENT_REG_PREFIX = 'webcareproscan_webauthn_reg_';
    const TRANSIENT_AUTH_PREFIX = 'webcareproscan_webauthn_auth_';

    /**
     * Bootstrap WebAuthn Manager.
     */
    public static function init(): void {
        // Handle login page injection and WebAuthn browser ceremony scripts
        add_action('login_form', [__CLASS__, 'render_login_passkey_prompt']);
        add_action('login_footer', [__CLASS__, 'render_login_passkey_scripts']);
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
     * Check if two credential IDs match, tolerating base64 vs base64url encoding and padding differences.
     *
     * @param string $id1
     * @param string $id2
     * @return bool
     */
    public static function credential_ids_match(string $id1, string $id2): bool {
        if (hash_equals($id1, $id2)) {
            return true;
        }

        // Normalize base64url to standard base64 without padding
        $norm1 = rtrim(strtr($id1, '-_', '+/'), '=');
        $norm2 = rtrim(strtr($id2, '-_', '+/'), '=');

        if (hash_equals($norm1, $norm2)) {
            return true;
        }

        // Decode to raw bytes comparison
        $raw1 = self::base64url_decode($id1);
        $raw2 = self::base64url_decode($id2);

        return (!empty($raw1) && !empty($raw2) && hash_equals($raw1, $raw2));
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
     * Rate limit client IP for WebAuthn authentication attempts.
     *
     * @param string $action 'options' or 'verify'
     * @param int $max_attempts Maximum attempts allowed within window
     * @param int $window_seconds Time window in seconds
     * @return bool True if within rate limit, false if exceeded
     */
    public static function check_ip_rate_limit(string $action = 'verify', int $max_attempts = 15, int $window_seconds = 300): bool {
        $ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

        $transient_key = 'webcareproscan_wa_rl_' . md5($action . '_' . $ip);
        $attempts = (int) get_transient($transient_key);

        if ($attempts >= $max_attempts) {
            return false;
        }

        set_transient($transient_key, $attempts + 1, $window_seconds);
        return true;
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
            return ['success' => false, 'message' => __('Invalid user.', 'webcare-pro-security')];
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
                'message' => __('Registration challenge expired or missing. Please try again.', 'webcare-pro-security'),
            ];
        }

        $response = $payload['response'] ?? [];
        $client_data_json_b64 = $response['clientDataJSON'] ?? '';
        $attestation_obj_b64  = $response['attestationObject'] ?? '';
        $credential_id        = $payload['id'] ?? '';

        if (empty($client_data_json_b64) || empty($attestation_obj_b64) || empty($credential_id)) {
            return [
                'success' => false,
                'message' => __('Missing WebAuthn registration payload parameters.', 'webcare-pro-security'),
            ];
        }

        $client_data_json = self::base64url_decode($client_data_json_b64);
        $client_data = json_decode($client_data_json, true);

        if (!is_array($client_data) || ($client_data['type'] ?? '') !== 'webauthn.create') {
            return [
                'success' => false,
                'message' => __('Invalid clientDataJSON type for registration.', 'webcare-pro-security'),
            ];
        }

        if (($client_data['challenge'] ?? '') !== $stored['challenge']) {
            return [
                'success' => false,
                'message' => __('Registration challenge verification mismatch.', 'webcare-pro-security'),
            ];
        }

        // Strictly verify origin to prevent cross-origin registration relay attacks
        $expected_origin_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $client_origin = (string) ($client_data['origin'] ?? '');
        $client_origin_host = wp_parse_url($client_origin, PHP_URL_HOST);
        if (empty($client_origin_host) || empty($expected_origin_host)) {
            return [
                'success' => false,
                'message' => __('Registration origin verification failed: missing or invalid origin.', 'webcare-pro-security'),
            ];
        }
        $is_dev_env = defined('WP_DEBUG') && WP_DEBUG && in_array($client_origin_host, ['localhost', '127.0.0.1'], true);
        if (strtolower($client_origin_host) !== strtolower($expected_origin_host) && !$is_dev_env) {
            return [
                'success' => false,
                'message' => __('WebAuthn registration origin mismatch.', 'webcare-pro-security'),
            ];
        }

        // Parse Attestation Object to extract public key PEM
        $attestation_bin = self::base64url_decode($attestation_obj_b64);

        // Verify rpIdHash in authenticatorData inside attestation object
        $expected_rp_id = self::get_rp_id();
        $expected_rp_hash = hash('sha256', $expected_rp_id, true);
        $auth_data_pos = strpos($attestation_bin, 'authData');
        if ($auth_data_pos !== false) {
            $after_tag = $auth_data_pos + 8;
            if ($after_tag < strlen($attestation_bin)) {
                $lead = ord($attestation_bin[$after_tag]);
                $auth_offset = $after_tag + 1;
                if ($lead === 0x58) {
                    $auth_offset = $after_tag + 2;
                } elseif ($lead === 0x59) {
                    $auth_offset = $after_tag + 3;
                }
                $auth_data = substr($attestation_bin, $auth_offset);
                if (strlen($auth_data) >= 32) {
                    $incoming_rp_hash = substr($auth_data, 0, 32);
                    if (!hash_equals($expected_rp_hash, $incoming_rp_hash)) {
                        return [
                            'success' => false,
                            'message' => __('WebAuthn registration RP ID verification failed.', 'webcare-pro-security'),
                        ];
                    }
                }
            }
        }

        $public_key_pem = self::extract_public_key_pem_from_attestation($attestation_bin);

        // Fallback: check if client provided direct DER public key via getPublicKey()
        $client_pk_b64 = $payload['response']['publicKey'] ?? '';
        if (empty($public_key_pem) && !empty($client_pk_b64)) {
            $pk_der = self::base64url_decode($client_pk_b64);
            $public_key_pem = self::parse_public_key_to_pem($pk_der);
        }

        // Strict Cryptographic Enforcement: Passkeys without verifiable public keys cannot be registered
        if (empty($public_key_pem) || strpos($public_key_pem, '-----BEGIN PUBLIC KEY-----') === false) {
            return [
                'success' => false,
                'message' => __('Registration failed: Could not extract a valid cryptographic public key from authenticator.', 'webcare-pro-security'),
            ];
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
        self::index_credential($credential_id, $user_id);

        $user = get_userdata($user_id);
        AuditLogger::log(
            'webauthn_passkey_registered',
            sprintf('New biometric Passkey ("%s") registered for administrator %s.', $device_name, $user ? $user->user_login : 'ID #' . $user_id)
        );

        NotificationDispatcher::trigger('auth_passkey_registered', [
            'title'   => __('FIDO2 / WebAuthn Biometric Passkey Enrolled', 'webcare-pro-security'),
            /* translators: 1: device name, 2: user login or ID */
            'message' => sprintf(__('Biometric passkey (%1$s) enrolled for user "%2$s".', 'webcare-pro-security'), $device_name, $user ? $user->user_login : 'ID #' . $user_id),
            'details' => [
                'triggered_by' => $user ? $user->user_login : 'ID #' . $user_id,
                'device_name'  => $device_name,
                'status'       => 'Biometric Key Bound',
            ],
        ]);

        return [
            'success'     => true,
            'device_name' => $device_name,
            'message'     => __('Biometric Passkey registered successfully! You can now sign in using TouchID, FaceID, or Windows Hello.', 'webcare-pro-security'),
        ];
    }

    /**
     * Generate authentication options for passkey login.
     *
     * @param string $login_hint Optional username or email
     * @return array
     */
    public static function generate_login_options(string $login_hint = ''): array {
        if (!self::check_ip_rate_limit('options', 25, 300)) {
            return [
                'success' => false,
                'message' => __('Too many passkey requests. Please wait a few minutes.', 'webcare-pro-security'),
            ];
        }

        $challenge_bytes = random_bytes(32);
        $challenge_b64 = self::base64url_encode($challenge_bytes);
        $session_id = 'auth_' . bin2hex(random_bytes(16));

        set_transient(self::TRANSIENT_AUTH_PREFIX . $session_id, [
            'challenge'  => $challenge_b64,
            'login_hint' => sanitize_text_field(wp_unslash($login_hint)),
            'created_at' => time(),
        ], 180);

        // Support resident / discoverable credentials without disclosing account credentials:
        // By leaving allowCredentials empty, WebAuthn authenticators (Windows Hello, TouchID, YubiKey)
        // automatically prompt the user to choose or present their resident passkey.
        // This strictly prevents unauthenticated callers from enumerating valid users or credential IDs.
        $allow_credentials = [];

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
        if (!self::check_ip_rate_limit('verify', 10, 300)) {
            return [
                'success' => false,
                'message' => __('Too many failed authentication attempts. Please try again in 5 minutes.', 'webcare-pro-security'),
            ];
        }

        $transient_key = self::TRANSIENT_AUTH_PREFIX . sanitize_key($session_id);
        $stored = get_transient($transient_key);
        delete_transient($transient_key);

        if (!$stored || empty($stored['challenge'])) {
            return [
                'success' => false,
                'message' => __('Authentication challenge expired or invalid. Please try again.', 'webcare-pro-security'),
            ];
        }

        $credential_id = !empty($payload['rawId']) ? sanitize_text_field($payload['rawId']) : sanitize_text_field($payload['id'] ?? '');
        $response      = $payload['response'] ?? [];
        $client_data_b64 = $response['clientDataJSON'] ?? '';
        $auth_data_b64   = $response['authenticatorData'] ?? '';
        $signature_b64   = $response['signature'] ?? '';

        if (empty($credential_id) || empty($client_data_b64)) {
            return [
                'success' => false,
                'message' => __('Incomplete WebAuthn assertion payload.', 'webcare-pro-security'),
            ];
        }

        $client_data_json = self::base64url_decode($client_data_b64);
        $client_data = json_decode($client_data_json, true);

        if (!is_array($client_data) || ($client_data['type'] ?? '') !== 'webauthn.get') {
            return [
                'success' => false,
                'message' => __('Invalid clientDataJSON type for login assertion.', 'webcare-pro-security'),
            ];
        }

        if (!hash_equals((string) $stored['challenge'], (string) ($client_data['challenge'] ?? ''))) {
            return [
                'success' => false,
                'message' => __('Authentication challenge verification failed.', 'webcare-pro-security'),
            ];
        }

        // Validate origin strictly to prevent cross-site assertion relay
        $expected_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $client_origin = (string) ($client_data['origin'] ?? '');
        $client_origin_host = wp_parse_url($client_origin, PHP_URL_HOST);
        if (empty($client_origin_host) || empty($expected_host)) {
            return [
                'success' => false,
                'message' => __('WebAuthn assertion origin invalid or missing.', 'webcare-pro-security'),
            ];
        }
        $is_dev_env = defined('WP_DEBUG') && WP_DEBUG && in_array($client_origin_host, ['localhost', '127.0.0.1'], true);
        if (strtolower($client_origin_host) !== strtolower($expected_host) && !$is_dev_env) {
            return [
                'success' => false,
                'message' => __('WebAuthn assertion origin mismatch.', 'webcare-pro-security'),
            ];
        }

        // Fast O(1) indexed lookup for user owning this credential ID
        $matched_user_id = self::find_user_by_credential_id($credential_id);
        $matched_cred_idx = null;
        $matched_cred = null;

        if ($matched_user_id) {
            $user_creds = self::get_user_credentials($matched_user_id);
            foreach ($user_creds as $idx => $cred) {
                if (isset($cred['credential_id']) && self::credential_ids_match((string) $cred['credential_id'], $credential_id)) {
                    $matched_cred_idx = $idx;
                    $matched_cred = $cred;
                    break;
                }
            }
        }

        if (!$matched_user_id || !$matched_cred) {
            return [
                'success' => false,
                'message' => __('Passkey authentication failed. Invalid credential or signature.', 'webcare-pro-security'),
            ];
        }

        $user = get_userdata($matched_user_id);
        if (!$user || !$user->exists()) {
            return [
                'success' => false,
                'message' => __('Passkey authentication failed. Invalid credential or signature.', 'webcare-pro-security'),
            ];
        }

        // Mandatory Cryptographic Signature Verification (Fail-Closed)
        if (empty($auth_data_b64) || empty($signature_b64)) {
            return [
                'success' => false,
                'message' => __('Incomplete assertion: authenticator data or signature missing.', 'webcare-pro-security'),
            ];
        }

        $stored_pubkey = $matched_cred['public_key'] ?? '';
        if (empty($stored_pubkey) || strpos($stored_pubkey, '-----BEGIN PUBLIC KEY-----') === false) {
            return [
                'success' => false,
                'message' => __('Passkey authentication failed. Invalid credential or signature.', 'webcare-pro-security'),
            ];
        }

        $auth_data_bin = self::base64url_decode($auth_data_b64);
        $signature_bin = self::base64url_decode($signature_b64);
        $client_hash = hash('sha256', $client_data_json, true);
        $signed_data = $auth_data_bin . $client_hash;

        // Verify user presence flag (bit 0 of flags byte at index 32)
        if (strlen($auth_data_bin) < 37) {
            return [
                'success' => false,
                'message' => __('Authenticator data truncated or invalid.', 'webcare-pro-security'),
            ];
        }

        // Verify rpIdHash matches expected RP ID hash (first 32 bytes of authenticatorData)
        $expected_rp_id = self::get_rp_id();
        $expected_rp_hash = hash('sha256', $expected_rp_id, true);
        $incoming_rp_hash = substr($auth_data_bin, 0, 32);
        if (!hash_equals($expected_rp_hash, $incoming_rp_hash)) {
            return [
                'success' => false,
                'message' => __('WebAuthn RP ID hash mismatch for login assertion.', 'webcare-pro-security'),
            ];
        }

        $flags = ord($auth_data_bin[32]);
        $user_present = ($flags & 0x01) !== 0;
        if (!$user_present) {
            return [
                'success' => false,
                'message' => __('User presence verification flag was not set by authenticator.', 'webcare-pro-security'),
            ];
        }

        // Parse signature counter from authenticatorData (bytes 33-36, 32-bit big-endian)
        $incoming_sign_count = (ord($auth_data_bin[33]) << 24)
            | (ord($auth_data_bin[34]) << 16)
            | (ord($auth_data_bin[35]) << 8)
            | ord($auth_data_bin[36]);

        $stored_sign_count = (int) ($matched_cred['sign_count'] ?? 0);
        // Authenticator Clone Detection: If both counts are > 0 and incoming is less than stored, flag cloning
        if ($stored_sign_count > 0 && $incoming_sign_count > 0 && $incoming_sign_count < $stored_sign_count) {
            AuditLogger::log(
                'webauthn_clone_suspected',
                sprintf('CRITICAL: Possible cloned authenticator detected for user %s (Stored count: %d, Received: %d).', $user->user_login, $stored_sign_count, $incoming_sign_count)
            );
            return [
                'success' => false,
                'message' => __('Authentication rejected: Authenticator sequence anomaly detected (potential clone).', 'webcare-pro-security'),
            ];
        }

        // Strict Cryptographic Signature Verification via OpenSSL
        $verified = openssl_verify($signed_data, $signature_bin, $stored_pubkey, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            return [
                'success' => false,
                'message' => __('Passkey authentication failed. Invalid credential or signature.', 'webcare-pro-security'),
            ];
        }

        // Update credential last used timestamp and monotonic counter
        $user_creds = self::get_user_credentials($matched_user_id);
        if (isset($user_creds[$matched_cred_idx])) {
            $user_creds[$matched_cred_idx]['last_used'] = time();
            $user_creds[$matched_cred_idx]['sign_count'] = max($incoming_sign_count, ($user_creds[$matched_cred_idx]['sign_count'] ?? 0) + 1);
            update_user_meta($matched_user_id, self::META_CREDENTIALS, $user_creds);
        }

        // Authenticate user into WordPress
        wp_clear_auth_cookie();
        wp_set_current_user($matched_user_id);

        if (class_exists('\\WebCareProScanner\\Auth\\SessionSentinel')) {
            $pk_name = !empty($user_creds[$matched_cred_idx]['name']) ? $user_creds[$matched_cred_idx]['name'] : __('FIDO2 / Windows Hello', 'webcare-pro-security');
            \WebCareProScanner\Auth\SessionSentinel::$pending_auth_type = 'passkey';
            /* translators: %s: name or model of the passkey authenticator */
            \WebCareProScanner\Auth\SessionSentinel::$pending_auth_label = sprintf(__('Passkey (%s)', 'webcare-pro-security'), $pk_name);
            \WebCareProScanner\Auth\SessionSentinel::$pending_auth_details = [
                'type'          => 'passkey',
                'device_name'   => $pk_name,
                'credential_id' => substr((string) $credential_id, 0, 16) . '...',
            ];
        }

        wp_set_auth_cookie($matched_user_id, true);

        // Notify plugins and hooks
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Standard WordPress core login hook invocation
        do_action('wp_login', $user->user_login, $user);

        AuditLogger::log(
            'webauthn_passkey_login_success',
            sprintf('Biometric Passkey login successful for administrator %s (Credential ID: %s).', $user->user_login, substr($credential_id, 0, 16) . '...')
        );

        return [
            'success'      => true,
            'redirect_url' => admin_url('admin.php?page=webcare-pro-security'),
            'username'     => $user->user_login,
            'message'      => __('Biometric authentication verified. Redirecting to Security Console...', 'webcare-pro-security'),
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
            self::unindex_credential($credential_id);
            AuditLogger::log(
                'webauthn_passkey_deleted',
                sprintf('Biometric Passkey revoked for user ID #%d (Credential: %s).', $user_id, substr($credential_id, 0, 16) . '...')
            );

            $u = get_userdata($user_id);
            $u_login = $u ? $u->user_login : ('user #' . $user_id);
            NotificationDispatcher::trigger('auth_passkey_revoked', [
                'title'   => __('WebAuthn Hardware Passkey Revoked / Deleted', 'webcare-pro-security'),
                /* translators: %s: user login or ID */
            'message' => sprintf(__('Biometric passkey revoked for user "%s".', 'webcare-pro-security'), $u_login),
                'details' => [
                    'triggered_by'    => $u_login,
                    'credential_stub' => substr($credential_id, 0, 16) . '...',
                    'status'          => 'Passkey Removed',
                ],
            ]);
            return true;
        }

        return false;
    }

    /**
     * Map a credential ID to its owning user ID in the fast index.
     *
     * @param string $credential_id
     * @param int $user_id
     * @return void
     */
    private static function index_credential(string $credential_id, int $user_id): void {
        $index = get_option(self::OPTION_CREDENTIAL_INDEX, []);
        if (!is_array($index)) {
            $index = [];
        }
        $key = hash('sha256', $credential_id);
        $index[$key] = $user_id;
        update_option(self::OPTION_CREDENTIAL_INDEX, $index, false);
    }

    /**
     * Remove a credential from the fast lookup index.
     *
     * @param string $credential_id
     * @return void
     */
    private static function unindex_credential(string $credential_id): void {
        $index = get_option(self::OPTION_CREDENTIAL_INDEX, []);
        if (!is_array($index)) {
            return;
        }
        $key = hash('sha256', $credential_id);
        if (isset($index[$key])) {
            unset($index[$key]);
            update_option(self::OPTION_CREDENTIAL_INDEX, $index, false);
        }
    }

    /**
     * Find user ID owning a credential ID via the fast index (with fallback to usermeta).
     *
     * @param string $credential_id
     * @return int|null
     */
    private static function find_user_by_credential_id(string $credential_id): ?int {
        $index = get_option(self::OPTION_CREDENTIAL_INDEX, []);
        $key = hash('sha256', $credential_id);
        if (is_array($index) && isset($index[$key])) {
            return (int) $index[$key];
        }

        // Also check raw bytes hash if base64url padding differed
        $raw = self::base64url_decode($credential_id);
        if (!empty($raw)) {
            $raw_key = hash('sha256', $raw);
            if (is_array($index) && isset($index[$raw_key])) {
                return (int) $index[$raw_key];
            }
        }

        // Fallback: search usermeta and backfill the fast index
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s",
                self::META_CREDENTIALS
            ),
            ARRAY_A
        ) ?: [];

        foreach ($rows as $row) {
            $creds = class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($row['meta_value'])
                : maybe_unserialize($row['meta_value']);
            if (is_array($creds)) {
                foreach ($creds as $cred) {
                    if (isset($cred['credential_id']) && self::credential_ids_match((string) $cred['credential_id'], $credential_id)) {
                        $uid = (int) $row['user_id'];
                        self::index_credential($credential_id, $uid);
                        return $uid;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Parse raw WebAuthn public key bytes (DER, SPKI, uncompressed EC point, or COSE) into standard PEM format.
     *
     * @param string $raw_bytes
     * @return string
     */
    public static function parse_public_key_to_pem(string $raw_bytes): string {
        if (empty($raw_bytes)) {
            return '';
        }

        // 1. If already in PEM format
        if (strpos($raw_bytes, '-----BEGIN PUBLIC KEY-----') !== false) {
            return $raw_bytes;
        }

        // 2. If valid DER SubjectPublicKeyInfo (sequence header 0x30 and standard length)
        if (strlen($raw_bytes) >= 60 && ord($raw_bytes[0]) === 0x30) {
            return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($raw_bytes), 64, "\n") . "-----END PUBLIC KEY-----\n";
        }

        // 3. If raw 65-byte uncompressed EC point (0x04 || X || Y) for secp256r1 (P-256)
        if (strlen($raw_bytes) === 65 && $raw_bytes[0] === "\x04") {
            $spki_prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
            $spki = $spki_prefix . $raw_bytes;
            return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        }

        // 4. Parse COSE EC2 P-256 map directly
        // Key -2 (X coord, 32 bytes): 0x21 0x58 0x20
        // Key -3 (Y coord, 32 bytes): 0x22 0x58 0x20
        $pos_x = strpos($raw_bytes, "\x21\x58\x20");
        $pos_y = strpos($raw_bytes, "\x22\x58\x20");
        if ($pos_x !== false && $pos_y !== false) {
            $x = substr($raw_bytes, $pos_x + 3, 32);
            $y = substr($raw_bytes, $pos_y + 3, 32);
            if (strlen($x) === 32 && strlen($y) === 32) {
                $raw_point = "\x04" . $x . $y;
                $spki_prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
                $spki = $spki_prefix . $raw_point;
                return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
            }
        }

        return '';
    }

    /**
     * Helper to extract public key PEM from CBOR attestation object.
     *
     * @param string $attestation_bin
     * @return string
     */
    private static function extract_public_key_pem_from_attestation(string $attestation_bin): string {
        $pos = strpos($attestation_bin, 'authData');
        if ($pos === false) {
            return '';
        }

        $after_tag = $pos + 8;
        if ($after_tag >= strlen($attestation_bin)) {
            return '';
        }

        $lead = ord($attestation_bin[$after_tag]);
        $auth_offset = $after_tag + 1;
        if ($lead === 0x58) {
            $auth_offset = $after_tag + 2;
        } elseif ($lead === 0x59) {
            $auth_offset = $after_tag + 3;
        }

        $auth_data = substr($attestation_bin, $auth_offset);
        if (strlen($auth_data) < 55) {
            return '';
        }

        $flags = ord($auth_data[32]);
        $has_attested_cred = ($flags & 0x40) !== 0;
        if (!$has_attested_cred) {
            return '';
        }

        $cred_len = (ord($auth_data[53]) << 8) | ord($auth_data[54]);
        $cose_offset = 55 + $cred_len;
        if ($cose_offset >= strlen($auth_data)) {
            return '';
        }

        $cose_bytes = substr($auth_data, $cose_offset);
        return self::parse_public_key_to_pem($cose_bytes);
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
        <div style="margin: 14px 0 10px; text-align: center;">
            <button type="button" id="webcare-passkey-login-btn" class="button button-secondary" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-weight: 600; padding: 6px 12px; height: auto; min-height: 38px; cursor: pointer; border-radius: 4px; box-shadow: 0 1px 2px rgba(0,0,0,0.06); transition: all 0.2s ease;">
                <span style="font-size: 16px;">🔑</span> <?php esc_html_e('Sign in with Passkey / Biometrics', 'webcare-pro-security'); ?>
            </button>
        </div>
        <?php
    }

    /**
     * Render passkey authentication scripts on login page.
     */
    public static function render_login_passkey_scripts(): void {
        $options_url = esc_url_raw(rest_url('webcare-pro-security/v1/auth/webauthn/login-options'));
        $verify_url  = esc_url_raw(rest_url('webcare-pro-security/v1/auth/webauthn/login-verify'));
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading public standard login redirect_to parameter on wp-login.php
        $requested_redirect = isset($_GET['redirect_to']) ? esc_url_raw(wp_unslash($_GET['redirect_to'])) : '';
        $validated_redirect = !empty($requested_redirect) ? wp_validate_redirect($requested_redirect, admin_url()) : admin_url();
        $default_redirect = esc_url_raw($validated_redirect);
        ?>
        <script>
        (function() {
            var btn = document.getElementById('webcare-passkey-login-btn');
            if (!btn) return;

            var isSupported = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);

            function showNotice(msg, isSuccess) {
                var loginForm = document.getElementById('loginform') || document.getElementById('login');
                var existing = document.getElementById('webcare-passkey-notice');
                if (existing) existing.remove();

                var notice = document.createElement('div');
                notice.id = 'webcare-passkey-notice';
                notice.className = isSuccess ? 'notice notice-success' : 'notice notice-error';
                notice.style.cssText = 'padding: 10px 14px; margin-bottom: 16px; border-left: 4px solid ' + (isSuccess ? '#46b450' : '#dc3232') + '; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 13px; line-height: 1.4;';
                notice.innerHTML = '<p style="margin: 0;">' + msg + '</p>';
                if (loginForm && loginForm.parentNode) {
                    loginForm.parentNode.insertBefore(notice, loginForm);
                }
            }

            function base64urlToUint8Array(base64url) {
                var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4) {
                    base64 += '=';
                }
                var raw = window.atob(base64);
                var buffer = new Uint8Array(raw.length);
                for (var i = 0; i < raw.length; i++) {
                    buffer[i] = raw.charCodeAt(i);
                }
                return buffer;
            }

            function arrayBufferToBase64url(buffer) {
                var bytes = new Uint8Array(buffer);
                var binary = '';
                for (var i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            }

            var activeAbortCtrl = null;

            btn.addEventListener('click', async function(e) {
                e.preventDefault();

                if (!isSupported) {
                    showNotice('<?php echo esc_js(__('WebAuthn Passkeys are not supported by this browser, or require HTTPS.', 'webcare-pro-security')); ?>', false);
                    return;
                }

                if (!window.isSecureContext) {
                    showNotice('<?php echo esc_js(__('Passkeys require a secure HTTPS connection or localhost.', 'webcare-pro-security')); ?>', false);
                    return;
                }

                // Abort any prior pending ceremony to prevent "A request is already pending"
                if (activeAbortCtrl) {
                    try {
                        activeAbortCtrl.abort();
                    } catch (e) {}
                    activeAbortCtrl = null;
                }
                activeAbortCtrl = new AbortController();

                var origHtml = btn.innerHTML;
                btn.disabled = true;
                btn.innerHTML = '<span style="display: inline-block;">⏳</span> <?php echo esc_js(__('Connecting to Windows Hello / Passkey...', 'webcare-pro-security')); ?>';

                var userLoginInput = document.getElementById('user_login');
                var username = userLoginInput ? userLoginInput.value.trim() : '';

                try {
                    // 1. Fetch challenge and options from REST endpoint
                    var optRes = await fetch('<?php echo esc_url($options_url); ?>', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: username }),
                        signal: activeAbortCtrl.signal
                    });
                    var optData = await optRes.json();

                    if (!optData || !optData.success || !optData.options) {
                        throw new Error(optData && optData.message ? optData.message : '<?php echo esc_js(__('Failed to initialize passkey challenge.', 'webcare-pro-security')); ?>');
                    }

                    var opts = optData.options;
                    opts.challenge = base64urlToUint8Array(opts.challenge);

                    if (opts.allowCredentials && opts.allowCredentials.length > 0) {
                        opts.allowCredentials = opts.allowCredentials.map(function(c) {
                            return {
                                id: base64urlToUint8Array(c.id),
                                type: c.type || 'public-key'
                            };
                        });
                    } else {
                        // Allow discoverable/resident credentials (e.g. Windows Hello passwordless)
                        delete opts.allowCredentials;
                    }

                    // 2. Prompt native Windows Hello / biometric authenticator
                    var assertion = await navigator.credentials.get({ 
                        publicKey: opts,
                        signal: activeAbortCtrl.signal
                    });
                    if (!assertion) {
                        throw new Error('<?php echo esc_js(__('Authentication cancelled by user.', 'webcare-pro-security')); ?>');
                    }

                    btn.innerHTML = '<span>🔑</span> <?php echo esc_js(__('Verifying credential signature...', 'webcare-pro-security')); ?>';

                    // 3. Prepare assertion payload
                    var assertionPayload = {
                        id: assertion.id,
                        type: assertion.type,
                        response: {
                            clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
                            authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
                            signature: arrayBufferToBase64url(assertion.response.signature),
                            userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null
                        }
                    };

                    // 4. Verify assertion on server and authenticate session
                    var verifyRes = await fetch('<?php echo esc_url($verify_url); ?>', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            session_id: optData.session_id,
                            payload: assertionPayload
                        }),
                        signal: activeAbortCtrl.signal
                    });
                    var verifyData = await verifyRes.json();

                    if (!verifyData || !verifyData.success) {
                        throw new Error(verifyData && verifyData.message ? verifyData.message : '<?php echo esc_js(__('Biometric verification failed.', 'webcare-pro-security')); ?>');
                    }

                    btn.style.background = '#46b450';
                    btn.style.color = '#ffffff';
                    btn.style.borderColor = '#46b450';
                    btn.innerHTML = '✓ <?php echo esc_js(__('Authenticated! Redirecting...', 'webcare-pro-security')); ?>';

                    var redirectTo = verifyData.redirect_url || '<?php echo esc_url($default_redirect); ?>';
                    window.location.href = redirectTo;

                } catch (err) {
                    if (err.name === 'AbortError') {
                        // Suppress manual abort notifications
                        btn.disabled = false;
                        btn.innerHTML = origHtml;
                        return;
                    }

                    console.error('Passkey login error:', err);
                    btn.disabled = false;
                    btn.innerHTML = origHtml;

                    var msg = err.message || '<?php echo esc_js(__('Passkey authentication failed.', 'webcare-pro-security')); ?>';
                    if (err.name === 'NotAllowedError') {
                        msg = '<?php echo esc_js(__('Windows Hello / Passkey prompt was cancelled or timed out.', 'webcare-pro-security')); ?>';
                    }
                    showNotice(msg, false);
                } finally {
                    activeAbortCtrl = null;
                }
            });
        })();
        </script>
        <?php
    }
}
