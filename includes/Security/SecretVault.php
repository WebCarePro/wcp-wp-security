<?php
namespace WCP\Scanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

class SecretVault {
    // Primary modern AEAD cipher with authenticated integrity tags (128-bit)
    const CIPHER_GCM = 'aes-256-gcm';
    const PREFIX_GCM = 'wcp_gcm:';

    // Legacy cipher support for backward compatibility with existing encrypted settings
    const CIPHER_CBC = 'aes-256-cbc';
    const PREFIX_CBC = 'wcp_enc:';

    /**
     * Derive a unique 256-bit encryption key.
     * Priority:
     * 1. Dedicated environment variable 'WCP_VAULT_KEY' (outside webroot / php-fpm / systemd)
     * 2. Dedicated wp-config.php constant 'WCP_VAULT_KEY' (decoupled from WordPress auth salts)
     * 3. WordPress secret salts (AUTH_KEY, SECURE_AUTH_KEY, AUTH_SALT)
     */
    private static function get_key(): string {
        // Check for dedicated system environment variable first (DevOps / Server hardening)
        $env_key = getenv('WCP_VAULT_KEY');
        if (!empty($env_key)) {
            return hash('sha256', $env_key, true);
        }

        // Check for dedicated wp-config.php constant
        if (defined('WCP_VAULT_KEY') && !empty(WCP_VAULT_KEY)) {
            return hash('sha256', (string) WCP_VAULT_KEY, true);
        }

        // Default: Derive deterministically from WordPress secret salts
        $salt = defined('AUTH_KEY') && AUTH_KEY !== 'put your unique phrase here'
            ? AUTH_KEY
            : (defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'wcp-default-fallback-salt-key-2026');

        if (defined('AUTH_SALT') && AUTH_SALT !== 'put your unique phrase here') {
            $salt .= AUTH_SALT;
        }

        if (defined('SECURE_AUTH_KEY') && SECURE_AUTH_KEY !== 'put your unique phrase here') {
            $salt .= SECURE_AUTH_KEY;
        }

        return hash('sha256', $salt, true);
    }

    /**
     * Encrypt a sensitive plain text secret (e.g. API token, Webhook URL).
     * Uses AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
     * Falls back to AES-256-CBC if GCM is unavailable on legacy OpenSSL.
     */
    public static function encrypt(string $plain): string {
        if ($plain === '' || self::is_encrypted($plain)) {
            return $plain;
        }

        if (!function_exists('openssl_encrypt')) {
            return $plain;
        }

        $key = self::get_key();

        // Check if AES-256-GCM is supported (standard in modern PHP 7.1+ / OpenSSL)
        if (in_array(self::CIPHER_GCM, openssl_get_cipher_methods(), true)) {
            $iv_len = 12; // 96-bit recommended IV for GCM
            $iv = function_exists('random_bytes') ? random_bytes($iv_len) : openssl_random_pseudo_bytes($iv_len);
            $tag = '';

            $encrypted = openssl_encrypt($plain, self::CIPHER_GCM, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($encrypted !== false && strlen($tag) === 16) {
                // Format: prefix + base64(iv:12 + tag:16 + ciphertext)
                return self::PREFIX_GCM . base64_encode($iv . $tag . $encrypted);
            }
        }

        // Fallback: AES-256-CBC
        $iv_length = openssl_cipher_iv_length(self::CIPHER_CBC);
        $iv = function_exists('random_bytes') ? random_bytes($iv_length) : openssl_random_pseudo_bytes($iv_length);
        $encrypted = openssl_encrypt($plain, self::CIPHER_CBC, $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            return $plain;
        }

        return self::PREFIX_CBC . base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt an encrypted secret string.
     * Authenticates ciphertext integrity with AES-256-GCM tags.
     * Backwards-compatible with legacy AES-256-CBC encrypted strings.
     */
    public static function decrypt(string $value): string {
        if (!self::is_encrypted($value)) {
            return $value;
        }

        if (!function_exists('openssl_decrypt')) {
            return $value;
        }

        $key = self::get_key();

        // Modern AES-256-GCM Authenticated Decryption
        if (strpos($value, self::PREFIX_GCM) === 0) {
            $raw = base64_decode(substr($value, strlen(self::PREFIX_GCM)), true);
            if ($raw === false || strlen($raw) < (12 + 16)) {
                return $value;
            }

            $iv = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $ciphertext = substr($raw, 28);

            $decrypted = openssl_decrypt($ciphertext, self::CIPHER_GCM, $key, OPENSSL_RAW_DATA, $iv, $tag);
            return $decrypted !== false ? $decrypted : $value;
        }

        // Legacy AES-256-CBC Decryption
        if (strpos($value, self::PREFIX_CBC) === 0) {
            $data = base64_decode(substr($value, strlen(self::PREFIX_CBC)), true);
            if ($data === false) {
                return $value;
            }

            $iv_length = openssl_cipher_iv_length(self::CIPHER_CBC);
            if (strlen($data) <= $iv_length) {
                return $value;
            }

            $iv = substr($data, 0, $iv_length);
            $ciphertext = substr($data, $iv_length);

            $decrypted = openssl_decrypt($ciphertext, self::CIPHER_CBC, $key, OPENSSL_RAW_DATA, $iv);
            return $decrypted !== false ? $decrypted : $value;
        }

        return $value;
    }

    /**
     * Check if a value is currently encrypted with either modern GCM or legacy CBC prefix.
     */
    public static function is_encrypted(string $value): bool {
        return strpos($value, self::PREFIX_GCM) === 0 || strpos($value, self::PREFIX_CBC) === 0;
    }
}
