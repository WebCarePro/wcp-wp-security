<?php
namespace WCP\Scanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

class SecretVault {
    const CIPHER = 'aes-256-cbc';
    const PREFIX = 'wcp_enc:';

    /**
     * Derive a unique 256-bit encryption key using WordPress salt constants.
     */
    private static function get_key(): string {
        $salt = defined('AUTH_KEY') && AUTH_KEY !== 'put your unique phrase here'
            ? AUTH_KEY
            : (defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'wcp-default-fallback-salt-key-2026');

        if (defined('AUTH_SALT') && AUTH_SALT !== 'put your unique phrase here') {
            $salt .= AUTH_SALT;
        }

        return hash('sha256', $salt, true);
    }

    /**
     * Encrypt a sensitive plain text secret (e.g. API token, Zone ID).
     * Returns string with prefix 'wcp_enc:' or original string if encryption fails.
     */
    public static function encrypt(string $plain): string {
        if ($plain === '' || self::is_encrypted($plain)) {
            return $plain;
        }

        if (!function_exists('openssl_encrypt')) {
            return $plain;
        }

        $iv_length = openssl_cipher_iv_length(self::CIPHER);
        $iv = function_exists('random_bytes') ? random_bytes($iv_length) : openssl_random_pseudo_bytes($iv_length);

        $encrypted = openssl_encrypt($plain, self::CIPHER, self::get_key(), OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            return $plain;
        }

        return self::PREFIX . base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt an encrypted secret string.
     * If the string is not encrypted (legacy plain text), returns it directly.
     */
    public static function decrypt(string $value): string {
        if (!self::is_encrypted($value)) {
            return $value;
        }

        if (!function_exists('openssl_decrypt')) {
            return $value;
        }

        $data = base64_decode(substr($value, strlen(self::PREFIX)), true);
        if ($data === false) {
            return $value;
        }

        $iv_length = openssl_cipher_iv_length(self::CIPHER);
        if (strlen($data) <= $iv_length) {
            return $value;
        }

        $iv = substr($data, 0, $iv_length);
        $ciphertext = substr($data, $iv_length);

        $decrypted = openssl_decrypt($ciphertext, self::CIPHER, self::get_key(), OPENSSL_RAW_DATA, $iv);
        return $decrypted !== false ? $decrypted : $value;
    }

    /**
     * Check if a value is currently encrypted with the SecretVault prefix.
     */
    public static function is_encrypted(string $value): bool {
        return strpos($value, self::PREFIX) === 0;
    }
}
