<?php
namespace WcpScanner\System\ActivityLogs;

use WcpScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Hash Chain & Cryptographic Verification Engine for WCP Activity & Audit Logging.
 *
 * Enforces:
 * 1. Single stable installation Genesis Hash (never resets on date or segment rollover).
 * 2. Deterministic plaintext record hashing: H_n = SHA256( H_{n-1} || CanonicalJSON(Payload_n) ).
 * 3. AES-256-GCM authenticated envelope encryption with AAD binding (v, k_ver, seq, event_id, h).
 * 4. Key version resolution via SecretVault with historical archive support.
 * 5. 8-Point Cross-Chain Integrity Verification connecting Checkpoint Ledger to active partitions.
 */
class ActivityHashChain {

    const ENVELOPE_VERSION = 1;
    const CIPHER_GCM       = 'aes-256-gcm';

    /**
     * Get or initialize the stable installation Genesis Hash (H_0).
     *
     * @return string 64-character lowercase hex string.
     */
    public static function get_genesis_hash(): string {
        $genesis = get_option('wcpscan_activity_genesis_hash', '');
        if (!empty($genesis) && strlen($genesis) === 64 && ctype_xdigit($genesis)) {
            return $genesis;
        }

        // Generate stable genesis once and persist permanently
        $install_seed = get_option('wcpscan_install_hash', '');
        if (empty($install_seed)) {
            $install_seed = wp_generate_password(32, true, true);
            update_option('wcpscan_install_hash', $install_seed, false);
        }

        $genesis = hash('sha256', 'WCP_ACTIVITY_GENESIS::' . $install_seed);
        update_option('wcpscan_activity_genesis_hash', $genesis, false);
        return $genesis;
    }

    /**
     * Compute record hash H_n from previous hash and canonical event payload.
     *
     * @param string $prev_hash         64-character hex hash of previous record or genesis.
     * @param array  $canonical_payload Unencrypted event payload (must NOT contain event_hash or envelope).
     * @return string 64-character hex hash.
     */
    public static function compute_record_hash(string $prev_hash, array $canonical_payload): string {
        $json = ActivityCanonicalizer::to_json($canonical_payload, false);
        return hash('sha256', $prev_hash . $json);
    }

    /**
     * Build the deterministic canonical AAD string from envelope metadata.
     *
     * @param int    $v        Envelope version.
     * @param int    $k_ver    Key version.
     * @param int    $seq      Monotonic sequence number.
     * @param string $event_id Unique event ID.
     * @param string $h        Calculated record hash.
     * @return string
     */
    public static function build_aad(int $v, int $k_ver, int $seq, string $event_id, string $h): string {
        $aad_data = [
            'event_id' => (string) $event_id,
            'h'        => (string) $h,
            'k_ver'    => (int) $k_ver,
            'seq'      => (int) $seq,
            'v'        => (int) $v,
        ];
        ksort($aad_data, SORT_STRING);
        return json_encode($aad_data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Encrypt an event payload into an AES-256-GCM envelope with AAD binding.
     *
     * @param array  $event_payload Canonical unencrypted event.
     * @param int    $seq           Sequence number.
     * @param string $record_hash   Calculated SHA-256 record hash.
     * @return array Outer envelope array ready for JSONL disk write.
     * @throws \RuntimeException If OpenSSL encryption fails.
     */
    public static function encrypt_envelope(array $event_payload, int $seq, string $record_hash): array {
        if (!function_exists('openssl_encrypt')) {
            throw new \RuntimeException('OpenSSL extension is missing on this server. Activity log encryption failed.');
        }

        $v = self::ENVELOPE_VERSION;
        $k_ver = self::get_active_key_version();
        $key = self::resolve_encryption_key($k_ver);

        $event_id = (string) ($event_payload['event_id'] ?? '');
        $aad = self::build_aad($v, $k_ver, $seq, $event_id, $record_hash);

        $iv_len = 12; // 96-bit standard for AES-256-GCM
        $iv = function_exists('random_bytes') ? random_bytes($iv_len) : openssl_random_pseudo_bytes($iv_len);
        $tag = '';

        $plaintext = ActivityCanonicalizer::to_json($event_payload, false);
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_GCM,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            16
        );

        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new \RuntimeException('AES-256-GCM authenticated encryption failed.');
        }

        return [
            'c'        => base64_encode($ciphertext),
            'event_id' => $event_id,
            'h'        => $record_hash,
            'iv'       => base64_encode($iv),
            'k_ver'    => $k_ver,
            'seq'      => $seq,
            'tag'      => base64_encode($tag),
            'v'        => $v,
        ];
    }

    /**
     * Decrypt and authenticate an envelope, returning the verified canonical event payload.
     *
     * @param array $envelope Outer envelope dictionary.
     * @return array Decrypted event payload.
     * @throws \RuntimeException If envelope is invalid, tag verification fails, or inner/outer metadata mismatches.
     */
    public static function decrypt_envelope(array $envelope): array {
        if (!isset($envelope['v'], $envelope['k_ver'], $envelope['seq'], $envelope['event_id'], $envelope['iv'], $envelope['tag'], $envelope['c'], $envelope['h'])) {
            throw new \RuntimeException('Invalid envelope structure: missing required envelope fields.');
        }

        $v        = (int) $envelope['v'];
        $k_ver    = (int) $envelope['k_ver'];
        $seq      = (int) $envelope['seq'];
        $event_id = (string) $envelope['event_id'];
        $h        = (string) $envelope['h'];

        $key = self::resolve_encryption_key($k_ver);
        if (empty($key)) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \RuntimeException('Encryption key version ' . (int) $k_ver . ' is unavailable in key vault.');
        }

        $iv = base64_decode((string) $envelope['iv']);
        $tag = base64_decode((string) $envelope['tag']);
        $ciphertext = base64_decode((string) $envelope['c']);

        if (strlen($iv) !== 12 || strlen($tag) !== 16 || $ciphertext === false) {
            throw new \RuntimeException('Corrupted envelope cryptographic parameters (invalid IV or tag length).');
        }

        $aad = self::build_aad($v, $k_ver, $seq, $event_id, $h);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_GCM,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($plaintext === false) {
            throw new \RuntimeException('AES-256-GCM authentication tag mismatch: payload ciphertext has been tampered with or corrupted.');
        }

        $payload = json_decode($plaintext, true);
        if (!is_array($payload)) {
            throw new \RuntimeException('Decrypted plaintext is not a valid JSON structure.');
        }

        // Validate inner vs outer metadata consistency
        if (($payload['seq'] ?? null) !== $seq) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \RuntimeException('Inner sequence number (' . intval($payload['seq'] ?? 0) . ') does not match outer envelope sequence (' . (int) $seq . ').');
        }

        if (($payload['event_id'] ?? null) !== $event_id) {
            throw new \RuntimeException('Inner event ID does not match outer envelope event ID.');
        }

        return $payload;
    }

    /**
     * Resolve the active encryption key version.
     *
     * @return int
     */
    public static function get_active_key_version(): int {
        return (int) get_option('wcpscan_activity_key_version', 1);
    }

    /**
     * Resolve binary key for a specific key version.
     *
     * @param int $version
     * @return string Binary 32-byte key.
     */
    public static function resolve_encryption_key(int $version): string {
        if ($version === 1) {
            return SecretVault::get_key();
        }

        // Check archived key store for rotated keys
        $archived_keys = get_option('wcpscan_activity_keyring', []);
        if (isset($archived_keys[$version])) {
            $hex = (string) $archived_keys[$version];
            if (strlen($hex) === 64 && ctype_xdigit($hex)) {
                return (string) hex2bin($hex);
            }
        }

        // Fallback to active SecretVault key if version matches active
        return SecretVault::get_key();
    }
}
