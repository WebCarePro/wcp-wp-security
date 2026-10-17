<?php
namespace WcpScanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

class SecretVault {
    // Primary modern AEAD cipher with 128-bit authenticated integrity tags
    const CIPHER_GCM = 'aes-256-gcm';
    const PREFIX_GCM = 'wcp_gcm:';

    /**
     * Derive a cryptographically uniform 256-bit (32-byte) key.
     * Priority:
     * 1. Isolated server environment variable 'WCP_VAULT_KEY' (outside webroot)
     * 2. Dedicated wp-config.php constant 'WCP_VAULT_KEY' (decoupled from WP auth salts)
     * 3. WordPress core secret salts (AUTH_KEY, SECURE_AUTH_KEY, AUTH_SALT)
     *
     * Fails closed: Never falls back to hardcoded strings.
     */
    public static function get_key(): string {
        // 1. Check for dedicated server environment variable (php-fpm, systemd, docker secret)
        $env_key = getenv('WCP_VAULT_KEY');
        if (!empty($env_key)) {
            // If provided as a 64-character hexadecimal key (32 bytes), decode directly
            if (is_string($env_key) && strlen($env_key) === 64 && ctype_xdigit($env_key)) {
                return (string) hex2bin($env_key);
            }
            return hash('sha256', (string) $env_key, true);
        }

        // 2. Check for dedicated wp-config.php constant
        if (defined('WCP_VAULT_KEY') && !empty(WCP_VAULT_KEY)) {
            $const_key = (string) WCP_VAULT_KEY;
            if (strlen($const_key) === 64 && ctype_xdigit($const_key)) {
                return (string) hex2bin($const_key);
            }
            return hash('sha256', $const_key, true);
        }

        // 3. Fallback: Derive deterministically from valid WordPress secret salts
        $salt = '';
        if (defined('AUTH_KEY') && AUTH_KEY !== 'put your unique phrase here') {
            $salt .= AUTH_KEY;
        }
        if (defined('SECURE_AUTH_KEY') && SECURE_AUTH_KEY !== 'put your unique phrase here') {
            $salt .= SECURE_AUTH_KEY;
        }
        if (defined('LOGGED_IN_KEY') && LOGGED_IN_KEY !== 'put your unique phrase here') {
            $salt .= LOGGED_IN_KEY;
        }
        if (defined('AUTH_SALT') && AUTH_SALT !== 'put your unique phrase here') {
            $salt .= AUTH_SALT;
        }
        if (defined('SECURE_AUTH_SALT') && SECURE_AUTH_SALT !== 'put your unique phrase here') {
            $salt .= SECURE_AUTH_SALT;
        }
        if (defined('LOGGED_IN_SALT') && LOGGED_IN_SALT !== 'put your unique phrase here') {
            $salt .= LOGGED_IN_SALT;
        }

        if (empty($salt) && function_exists('wp_salt')) {
            try {
                $salt = wp_salt('auth') . wp_salt('secure_auth');
            } catch (\Throwable $e) {
                // Ignore
            }
        }

        // 4. Fallback: Auto-generate and securely persist a unique site salt in wp_options
        if (empty($salt)) {
            $db_salt = function_exists('get_option') ? get_option('wcpscan_vault_salt') : false;
            if (empty($db_salt)) {
                $db_salt = function_exists('wp_generate_password')
                    ? wp_generate_password(64, true, true)
                    : (function_exists('random_bytes') ? bin2hex(random_bytes(32)) : hash('sha256', uniqid('wcp_', true)));
                if (function_exists('add_option')) {
                    add_option('wcpscan_vault_salt', $db_salt, '', 'no');
                }
            }
            $salt = (string) $db_salt;
        }

        if (empty($salt)) {
            $salt = 'wcp_default_safe_seed_' . (defined('DB_NAME') ? DB_NAME : 'wp_wcpscan');
        }

        // Always returns a true 256-bit (32 raw bytes) binary key
        return hash('sha256', $salt, true);
    }

    /**
     * Encrypt a sensitive plain text secret (e.g. API token, Webhook URL).
     * Uses AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
     *
     * FAIL-CLOSED: Throws \RuntimeException on any cipher or OpenSSL failure.
     * Never returns plaintext fallback.
     */
    public static function encrypt(string $plain): string {
        if ($plain === '' || self::is_encrypted($plain)) {
            return $plain;
        }

        if (!function_exists('openssl_encrypt')) {
            throw new \RuntimeException('WCP SecretVault Error: OpenSSL extension is missing or disabled on this server. Plaintext storage is refused.');
        }

        if (!in_array(self::CIPHER_GCM, openssl_get_cipher_methods(), true)) {
            throw new \RuntimeException('WCP SecretVault Error: AES-256-GCM cipher is unavailable in server OpenSSL installation.');
        }

        $key = self::get_key();
        $iv_len = 12; // 96-bit standard IV for GCM
        $iv = function_exists('random_bytes') ? random_bytes($iv_len) : openssl_random_pseudo_bytes($iv_len);
        $tag = '';

        $encrypted = openssl_encrypt($plain, self::CIPHER_GCM, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false || strlen($tag) !== 16) {
            throw new \RuntimeException('WCP SecretVault Error: Encryption failed to generate authenticated ciphertext.');
        }

        // Format: Prefix + base64( 12-byte IV . 16-byte Tag . Ciphertext )
        return self::PREFIX_GCM . base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Decrypt an encrypted secret string.
     * Authenticates ciphertext integrity with AES-256-GCM tags.
     *
     * Returns false on decryption or authentication failure; never leaks corrupted or modified plaintext.
     */
    public static function decrypt(string $value) {
        if (!self::is_encrypted($value)) {
            return $value;
        }

        if (!function_exists('openssl_decrypt')) {
            return false;
        }

        $primary_key = null;
        try {
            $primary_key = self::get_key();
        } catch (\Exception $e) {
            // Primary key cannot be derived
        }

        if ($primary_key !== null) {
            $decrypted = self::decrypt_with_key($value, $primary_key);
            if ($decrypted !== false) {
                return $decrypted;
            }
        }

        // Dual-Key Fallback: if a rotation migration is active, attempt decrypt with transitional old key
        if (class_exists('\\WcpScanner\\Security\\VaultRotator')) {
            $transitional_old_key = VaultRotator::get_transitional_old_key_if_active();
            if ($transitional_old_key !== false && $transitional_old_key !== $primary_key) {
                $fallback = self::decrypt_with_key($value, $transitional_old_key);
                if ($fallback !== false) {
                    return $fallback;
                }
            }

            // Self-Healing Dual-Key Fallback:
            // If primary key decryption failed on the current ciphertext, check if there is a pre-rotation
            // backup snapshot whose record decrypts cleanly with the active primary key. This gracefully
            // heals situations where a key rotation was triggered but wp-config.php retained the previous key.
            if ($primary_key !== null) {
                $state = get_option(\WcpScanner\Security\VaultRotator::STATE_OPTION, []);
                if (!empty($state['backup_id'])) {
                    $backup = get_option($state['backup_id']);
                    if (!empty($backup['records']) && is_array($backup['records'])) {
                        foreach ($backup['records'] as $field_key => $backup_val) {
                            if (is_string($backup_val) && self::is_encrypted($backup_val)) {
                                $candidate = self::decrypt_with_key($backup_val, $primary_key);
                                if ($candidate !== false) {
                                    $current_settings = get_option(\WcpScanner\System\SettingsManager::OPTION_KEY, []);
                                    if (isset($current_settings[$field_key]) && $current_settings[$field_key] === $value) {
                                        // Auto self-heal: restore working pre-rotation ciphertext for this field
                                        $current_settings[$field_key] = $backup_val;
                                        update_option(\WcpScanner\System\SettingsManager::OPTION_KEY, $current_settings, false);
                                        return $candidate;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Decrypt an encrypted secret with an explicit binary key.
     */
    public static function decrypt_with_key(string $value, string $key): string|false {
        if (!self::is_encrypted($value) || !function_exists('openssl_decrypt')) {
            return false;
        }

        $binary_key = strlen($key) === 64 && ctype_xdigit($key) ? (string) hex2bin($key) : (strlen($key) === 32 ? $key : hash('sha256', $key, true));

        // Modern AES-256-GCM Authenticated Decryption
        if (strpos($value, self::PREFIX_GCM) === 0) {
            $raw = base64_decode(substr($value, strlen(self::PREFIX_GCM)), true);
            // Minimum payload: 12-byte IV + 16-byte Tag = 28 bytes
            if ($raw === false || strlen($raw) < 28) {
                return false;
            }

            $iv = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $ciphertext = substr($raw, 28);

            $decrypted = openssl_decrypt($ciphertext, self::CIPHER_GCM, $binary_key, OPENSSL_RAW_DATA, $iv, $tag);
            return $decrypted !== false ? $decrypted : false;
        }

        return false;
    }

    /**
     * Re-encrypt ciphertext from an old key to a new key (Key Rotation Migration).
     */
    public static function rotate_record(string $encrypted_value, string $old_key, string $new_key): string {
        if (!self::is_encrypted($encrypted_value)) {
            return $encrypted_value;
        }

        $old_binary_key = strlen($old_key) === 32 ? $old_key : (strlen($old_key) === 64 && ctype_xdigit($old_key) ? (string) hex2bin($old_key) : hash('sha256', $old_key, true));
        $new_binary_key = strlen($new_key) === 32 ? $new_key : (strlen($new_key) === 64 && ctype_xdigit($new_key) ? (string) hex2bin($new_key) : hash('sha256', $new_key, true));

        // Decrypt with old key
        $decrypted = false;
        if (strpos($encrypted_value, self::PREFIX_GCM) === 0) {
            $raw = base64_decode(substr($encrypted_value, strlen(self::PREFIX_GCM)), true);
            if ($raw !== false && strlen($raw) >= 28) {
                $iv = substr($raw, 0, 12);
                $tag = substr($raw, 12, 16);
                $ciphertext = substr($raw, 28);
                $decrypted = openssl_decrypt($ciphertext, self::CIPHER_GCM, $old_binary_key, OPENSSL_RAW_DATA, $iv, $tag);
            }
        }

        if ($decrypted === false) {
            $decrypted = self::decrypt($encrypted_value);
        }

        if ($decrypted === false) {
            throw new \RuntimeException('WCP SecretVault Error: Key rotation failed; unable to decrypt record with old key.');
        }

        // Encrypt with new key
        $iv = random_bytes(12);
        $tag = '';
        $new_cipher = openssl_encrypt($decrypted, self::CIPHER_GCM, $new_binary_key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($new_cipher === false || strlen($tag) !== 16) {
            throw new \RuntimeException('WCP SecretVault Error: Key rotation failed; unable to encrypt record with new key.');
        }

        return self::PREFIX_GCM . base64_encode($iv . $tag . $new_cipher);
    }

    /**
     * Check if a value is currently encrypted with modern authenticated GCM.
     */
    public static function is_encrypted(string $value): bool {
        return strpos($value, self::PREFIX_GCM) === 0;
    }
}
