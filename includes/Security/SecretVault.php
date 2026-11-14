<?php
namespace WebCareProScanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

class SecretVault {
    // Primary modern AEAD cipher with 128-bit authenticated integrity tags
    const CIPHER_GCM = 'aes-256-gcm';
    const PREFIX_GCM = 'webcare_gcm:';

    public const VAULT_FORMAT_CHUNKED = 'V2_CHUNKED_GCM';
    public const VAULT_FORMAT_INLINE  = 'V2_INLINE_AEAD';
    public const CHUNK_SIZE           = 1048576; // 1 MB (1,048,576 bytes) chunking for constant memory
    public const GUARD_HEADER         = "<?php http_response_code(403); exit('WebCare Pro Security: Direct access forbidden.'); __halt_compiler(); ?>\n";

    /**
     * Derive a cryptographically uniform 256-bit (32-byte) key.
     * Priority:
     * 1. Isolated server environment variable 'WEBCARE_VAULT_KEY' (outside webroot)
     * 2. Dedicated wp-config.php constant 'WEBCARE_VAULT_KEY' (decoupled from WP auth salts)
     * 3. WordPress core secret salts (AUTH_KEY, SECURE_AUTH_KEY, AUTH_SALT)
     *
     * Fails closed: Never falls back to hardcoded strings.
     */
    public static function get_key(): string {
        // 1. Check for dedicated server environment variable (php-fpm, systemd, docker secret)
        $env_key = getenv('WEBCARE_VAULT_KEY');
        if (!empty($env_key)) {
            // If provided as a 64-character hexadecimal key (32 bytes), decode directly
            if (is_string($env_key) && strlen($env_key) === 64 && ctype_xdigit($env_key)) {
                return (string) hex2bin($env_key);
            }
            return hash('sha256', (string) $env_key, true);
        }

        // 2. Check for dedicated wp-config.php constant
        if (defined('WEBCARE_VAULT_KEY') && !empty(WEBCARE_VAULT_KEY)) {
            $const_key = (string) WEBCARE_VAULT_KEY;
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
            $db_salt = function_exists('get_option') ? get_option('webcareproscan_vault_salt') : false;
            if (empty($db_salt)) {
                $db_salt = function_exists('wp_generate_password')
                    ? wp_generate_password(64, true, true)
                    : (function_exists('random_bytes') ? bin2hex(random_bytes(32)) : hash('sha256', uniqid('webcare_', true)));
                if (function_exists('add_option')) {
                    add_option('webcareproscan_vault_salt', $db_salt, '', 'no');
                }
            }
            $salt = (string) $db_salt;
        }

        if (empty($salt)) {
            throw new \RuntimeException('SecretVault Key Derivation Failed: No cryptographically secure salt or secret key found in WordPress environment.');
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
            throw new \RuntimeException('WebCare SecretVault Error: OpenSSL extension is missing or disabled on this server. Plaintext storage is refused.');
        }

        if (!in_array(self::CIPHER_GCM, openssl_get_cipher_methods(), true)) {
            throw new \RuntimeException('WebCare SecretVault Error: AES-256-GCM cipher is unavailable in server OpenSSL installation.');
        }

        $key = self::get_key();
        $iv_len = 12; // 96-bit standard IV for GCM
        $iv = function_exists('random_bytes') ? random_bytes($iv_len) : openssl_random_pseudo_bytes($iv_len);
        $tag = '';

        $encrypted = openssl_encrypt($plain, self::CIPHER_GCM, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false || strlen($tag) !== 16) {
            throw new \RuntimeException('WebCare SecretVault Error: Encryption failed to generate authenticated ciphertext.');
        }

        // Format: Prefix + base64( 12-byte IV . 16-byte Tag . Ciphertext )
        return self::PREFIX_GCM . base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Alias for encrypt() for standard AEAD secret vaulting.
     *
     * @param string $plaintext
     * @return string|null
     */
    public static function encrypt_secret(string $plaintext): ?string {
        try {
            return self::encrypt($plaintext);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Alias for decrypt() for standard AEAD secret unvaulting.
     *
     * @param string $enc_payload
     * @return string|null
     */
    public static function decrypt_secret(string $enc_payload): ?string {
        $res = self::decrypt($enc_payload);
        return is_string($res) ? $res : null;
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
        if (class_exists('\\WebCareProScanner\\Security\\VaultRotator')) {
            $transitional_old_key = VaultRotator::get_transitional_old_key_if_active();
            if ($transitional_old_key !== false && $transitional_old_key !== $primary_key) {
                $fallback = self::decrypt_with_key($value, $transitional_old_key);
                if ($fallback !== false) {
                    return $fallback;
                }
            }

            // Self-Healing Dual-Key Fallback:
            // If primary key decryption failed on the current ciphertext, search pre-rotation
            // backup snapshots in reverse chronological order whose record decrypts cleanly with the active
            // primary key. This gracefully heals situations where a key rotation was triggered but
            // wp-config.php retained the previous key or key rotation was interrupted.
            if ($primary_key !== null) {
                $backup_ids = [];
                $state = get_option(\WebCareProScanner\Security\VaultRotator::STATE_OPTION, []);
                if (!empty($state['backup_id'])) {
                    $backup_ids[] = (string) $state['backup_id'];
                }

                global $wpdb;
                if ($wpdb && isset($wpdb->options)) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $recent_backups = $wpdb->get_col("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'webcareproscan_vault_backup_%' ORDER BY option_id DESC LIMIT 10");
                    if (!empty($recent_backups) && is_array($recent_backups)) {
                        $backup_ids = array_unique(array_merge($backup_ids, $recent_backups));
                    }
                }

                foreach ($backup_ids as $bid) {
                    $backup = get_option($bid);
                    if (!empty($backup['records']) && is_array($backup['records'])) {
                        foreach ($backup['records'] as $field_key => $backup_val) {
                            if (is_string($backup_val) && self::is_encrypted($backup_val)) {
                                $candidate = self::decrypt_with_key($backup_val, $primary_key);
                                if ($candidate !== false) {
                                    $current_settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
                                    if (isset($current_settings[$field_key]) && $current_settings[$field_key] === $value) {
                                        // Auto self-heal: restore working pre-rotation ciphertext for this field
                                        $current_settings[$field_key] = $backup_val;
                                        update_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, $current_settings, false);
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
            throw new \RuntimeException('WebCare SecretVault Error: Key rotation failed; unable to decrypt record with old key.');
        }

        // Encrypt with new key
        $iv = random_bytes(12);
        $tag = '';
        $new_cipher = openssl_encrypt($decrypted, self::CIPHER_GCM, $new_binary_key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($new_cipher === false || strlen($tag) !== 16) {
            throw new \RuntimeException('WebCare SecretVault Error: Key rotation failed; unable to encrypt record with new key.');
        }

        return self::PREFIX_GCM . base64_encode($iv . $tag . $new_cipher);
    }

    /**
     * Check if a value is currently encrypted with modern authenticated GCM.
     */
    public static function is_encrypted(string $value): bool {
        return strpos($value, self::PREFIX_GCM) === 0;
    }

    /**
     * Encrypt any file of arbitrary size (1 byte to 500 MB+) into an authenticated WebCare Vault archive.
     * Uses 1 MB chunked streaming AES-256-GCM AEAD encryption with chunk-index binding (Q-02, Q-03).
     *
     * @param string $src_path Source file path
     * @param string $dest_path Target encrypted vault path
     * @param string|null $binary_key Optional explicit key; uses self::get_key() if omitted
     * @return array ['success' => bool, 'error' => string, 'sha256' => string, 'bytes' => int, 'chunks' => int]
     */
    // phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fclose, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_fread, WordPress.WP.AlternativeFunctions.file_system_operations_chmod, WordPress.WP.AlternativeFunctions.rename_rename -- Low-level streaming binary chunked cryptographic operations require direct file handle I/O
    public static function encrypt_file_to_vault(string $src_path, string $dest_path, ?string $binary_key = null): array {
        if (!file_exists($src_path) || !is_file($src_path)) {
            return ['success' => false, 'error' => 'Source file does not exist or is not a regular file.'];
        }

        if (!function_exists('openssl_encrypt')) {
            return ['success' => false, 'error' => 'OpenSSL extension is missing. Encrypted vault operations are disabled.'];
        }

        $key = $binary_key;
        if ($key === null) {
            try {
                $key = self::get_key();
            } catch (\Throwable $e) {
                return ['success' => false, 'error' => 'Vault key derivation failed: ' . $e->getMessage()];
            }
        }
        $raw_key = strlen($key) === 64 && ctype_xdigit($key)
            ? (string) hex2bin($key)
            : (strlen($key) === 32 ? $key : hash('sha256', $key, true));

        $file_size = (int) @filesize($src_path);
        $orig_sha256 = @hash_file('sha256', $src_path) ?: '';

        // Ensure parent directory exists
        $dest_dir = dirname($dest_path);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }

        $temp_dest = $dest_path . '.webcare_tmp_' . bin2hex(random_bytes(6));
        $src_fp = @fopen($src_path, 'rb');
        if (!$src_fp) {
            return ['success' => false, 'error' => 'Failed to open source file for reading.'];
        }

        $dst_fp = @fopen($temp_dest, 'wb');
        if (!$dst_fp) {
            fclose($src_fp);
            return ['success' => false, 'error' => 'Failed to open temporary vault destination for writing.'];
        }

        $chunk_size = self::CHUNK_SIZE;
        $total_chunks = (int) ceil(max(1, $file_size) / $chunk_size);

        $meta = [
            'format'      => self::VAULT_FORMAT_CHUNKED,
            'chunks'      => $total_chunks,
            'file_size'   => $file_size,
            'orig_sha256' => $orig_sha256,
            'chunk_size'  => $chunk_size,
            'created_at'  => time(),
        ];

        $header_line = "// WEBCARE_VAULT_FORMAT:" . self::VAULT_FORMAT_CHUNKED . ":" . wp_json_encode($meta) . "\n";
        $header_full = self::GUARD_HEADER . $header_line;
        $written_hdr = fwrite($dst_fp, $header_full);
        if ($written_hdr !== strlen($header_full)) {
            fclose($src_fp);
            fclose($dst_fp);
            wp_delete_file($temp_dest);
            return ['success' => false, 'error' => 'Failed to write complete vault guard header.'];
        }

        $h_ctx = hash_init('sha256');
        $bytes_read = 0;
        $chunk_idx = 0;

        while (!feof($src_fp)) {
            $chunk = fread($src_fp, $chunk_size);
            if ($chunk === false) {
                fclose($src_fp);
                fclose($dst_fp);
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => "I/O read failure on source file at chunk index {$chunk_idx}."];
            }
            if ($chunk === '' && $chunk_idx > 0) {
                break;
            }

            $bytes_read += strlen($chunk);
            hash_update($h_ctx, $chunk);

            $iv = random_bytes(12);
            $tag = '';
            $aad = pack('N', $chunk_idx);
            $ciphertext = openssl_encrypt($chunk, self::CIPHER_GCM, $raw_key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
            if ($ciphertext === false || strlen($tag) !== 16) {
                fclose($src_fp);
                fclose($dst_fp);
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => "AEAD chunk encryption failed at chunk index {$chunk_idx}."];
            }

            $cipher_len = strlen($ciphertext);
            $frame_hdr = pack('N', $cipher_len) . $iv . $tag;
            $frame_payload = $frame_hdr . $ciphertext;
            $frame_bytes = fwrite($dst_fp, $frame_payload);
            if ($frame_bytes !== strlen($frame_payload)) {
                fclose($src_fp);
                fclose($dst_fp);
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => "Failed to write complete ciphertext frame for chunk {$chunk_idx}."];
            }

            $chunk_idx++;
            if ($file_size === 0) {
                break;
            }
        }

        fclose($src_fp);
        fflush($dst_fp);
        fclose($dst_fp);

        // Verification checks (Finding 1.1):
        // 1. Verify total chunks written matches declared chunk count
        if ($chunk_idx !== $total_chunks) {
            wp_delete_file($temp_dest);
            return ['success' => false, 'error' => "Chunk count mismatch: expected {$total_chunks}, wrote {$chunk_idx}."];
        }

        // 2. Verify total bytes read matches source file size
        if ($bytes_read !== $file_size) {
            wp_delete_file($temp_dest);
            return ['success' => false, 'error' => "Byte count mismatch: expected {$file_size} bytes, read {$bytes_read} bytes."];
        }

        // 3. Verify streamed plaintext SHA-256 matches initial file hash
        $streamed_sha = hash_final($h_ctx);
        if (!hash_equals($orig_sha256, $streamed_sha)) {
            wp_delete_file($temp_dest);
            return ['success' => false, 'error' => 'Streamed plaintext SHA-256 does not match original pre-encryption hash.'];
        }

        // 4. Atomically finalize to destination
        if (!@rename($temp_dest, $dest_path)) {
            wp_delete_file($temp_dest);
            return ['success' => false, 'error' => 'Failed to atomically finalize encrypted vault file.'];
        }

        @chmod($dest_path, 0600);

        // 5. Independent validation: Reopen and verify the completed vault archive structure
        $inspect = self::inspect_vault_file($dest_path);
        if (empty($inspect['valid']) || ($inspect['format'] ?? '') !== self::VAULT_FORMAT_CHUNKED || ($inspect['chunks'] ?? 0) !== $total_chunks) {
            wp_delete_file($dest_path);
            return ['success' => false, 'error' => 'Post-encryption validation failed: completed vault archive structure is invalid.'];
        }

        return [
            'success'     => true,
            'vault_path'  => $dest_path,
            'file_size'   => $file_size,
            'vault_size'  => (int) @filesize($dest_path),
            'orig_sha256' => $orig_sha256,
            'chunks'      => $chunk_idx,
            'format'      => self::VAULT_FORMAT_CHUNKED,
        ];
    }

    /**
     * Decrypt an authenticated WebCare Vault archive back to its original plaintext file.
     * Supports V2 Chunked Streaming AEAD, V2 Inline AEAD, and verified fallback (Q-02, Q-03).
     *
     * @param string $vault_path Encrypted vault archive path
     * @param string $dest_path Destination plaintext restore path
     * @param string|null $binary_key Optional explicit key; uses self::get_key() if omitted
     * @param bool $allow_legacy_unverified Whether to allow legacy unencrypted archives
     * @return array ['success' => bool, 'error' => string, 'dest_path' => string, 'sha256' => string, 'bytes' => int]
     */
    public static function decrypt_vault_to_file(
        string $vault_path,
        string $dest_path,
        ?string $binary_key = null,
        bool $allow_legacy_unverified = false
    ): array {
        if (!file_exists($vault_path) || !is_file($vault_path)) {
            return ['success' => false, 'error' => 'Vault file does not exist or is unreadable.'];
        }

        $key = $binary_key;
        if ($key === null) {
            try {
                $key = self::get_key();
            } catch (\Throwable $e) {
                return ['success' => false, 'error' => 'Vault key derivation failed: ' . $e->getMessage()];
            }
        }
        $raw_key = strlen($key) === 64 && ctype_xdigit($key)
            ? (string) hex2bin($key)
            : (strlen($key) === 32 ? $key : hash('sha256', $key, true));

        $v_fp = @fopen($vault_path, 'rb');
        if (!$v_fp) {
            return ['success' => false, 'error' => 'Failed to open vault file for reading.'];
        }

        // Seek past PHP guard header
        $header_buffer = fread($v_fp, 4096);
        $halt_marker = '__halt_compiler(); ' . '?>';
        $halt_pos = strpos($header_buffer, $halt_marker);

        $payload_offset = 0;
        if ($halt_pos !== false) {
            $payload_offset = $halt_pos + strlen($halt_marker);
            while ($payload_offset < strlen($header_buffer) && ($header_buffer[$payload_offset] === "\r" || $header_buffer[$payload_offset] === "\n")) {
                $payload_offset++;
            }
        }
        fseek($v_fp, $payload_offset, SEEK_SET);

        // Read format line
        $format_line = fgets($v_fp, 4096);
        $format = 'UNKNOWN';
        $meta = [];

        if (is_string($format_line) && str_starts_with($format_line, '// WEBCARE_VAULT_FORMAT:V2_CHUNKED_GCM:')) {
            $format = self::VAULT_FORMAT_CHUNKED;
            $json_str = trim(substr($format_line, strlen('// WEBCARE_VAULT_FORMAT:V2_CHUNKED_GCM:')));
            $meta = json_decode($json_str, true);
            if (!is_array($meta) || empty($meta)) {
                fclose($v_fp);
                return ['success' => false, 'error' => 'Corrupt vault header: malformed JSON metadata in chunked archive.'];
            }
        } elseif (is_string($format_line) && str_starts_with($format_line, '// WEBCARE_VAULT_FORMAT:V2_INLINE_AEAD')) {
            $format = self::VAULT_FORMAT_INLINE;
        } else {
            fseek($v_fp, $payload_offset, SEEK_SET);
            $peek = fread($v_fp, 20);
            if (str_starts_with($peek, self::PREFIX_GCM)) {
                $format = self::VAULT_FORMAT_INLINE;
            } else {
                $format = 'LEGACY_PLAINTEXT';
            }
            fseek($v_fp, $payload_offset, SEEK_SET);
        }

        $dest_dir = dirname($dest_path);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }
        $temp_dest = $dest_path . '.webcare_rst_tmp_' . bin2hex(random_bytes(6));

        if ($format === self::VAULT_FORMAT_CHUNKED) {
            $total_chunks  = (int) ($meta['chunks'] ?? 0);
            $expected_sha  = (string) ($meta['orig_sha256'] ?? '');
            $expected_size = isset($meta['file_size']) ? (int) $meta['file_size'] : -1;
            $chunk_size    = (int) ($meta['chunk_size'] ?? 0);

            // Strict metadata schema and boundary validation (Finding 1.2)
            if (
                ($meta['format'] ?? '') !== self::VAULT_FORMAT_CHUNKED
                || $total_chunks < 1
                || $total_chunks > 1000000
                || $expected_size < 0
                || $chunk_size < 1024
                || $chunk_size > 10485760
                || !preg_match('/^[a-f0-9]{64}$/i', $expected_sha)
            ) {
                fclose($v_fp);
                return ['success' => false, 'error' => 'Vault metadata validation rejected: invalid chunk schema or hash specification.'];
            }

            $dst_fp = @fopen($temp_dest, 'wb');
            if (!$dst_fp) {
                fclose($v_fp);
                return ['success' => false, 'error' => 'Failed to create destination stream.'];
            }

            $dec_h_ctx       = hash_init('sha256');
            $dec_bytes_total = 0;

            for ($chunk_idx = 0; $chunk_idx < $total_chunks; $chunk_idx++) {
                $len_buf = fread($v_fp, 4);
                if ($len_buf === false || strlen($len_buf) < 4) {
                    fclose($v_fp);
                    fclose($dst_fp);
                    wp_delete_file($temp_dest);
                    return ['success' => false, 'error' => "Vault truncated: missing chunk frame {$chunk_idx} header."];
                }

                $cipher_len = unpack('N', $len_buf)[1];
                if ($cipher_len > ($chunk_size + 64)) {
                    fclose($v_fp);
                    fclose($dst_fp);
                    wp_delete_file($temp_dest);
                    return ['success' => false, 'error' => "Vault frame {$chunk_idx} exceeds maximum permitted chunk length."];
                }

                $iv = fread($v_fp, 12);
                $tag = fread($v_fp, 16);
                if (strlen($iv) !== 12 || strlen($tag) !== 16) {
                    fclose($v_fp);
                    fclose($dst_fp);
                    wp_delete_file($temp_dest);
                    return ['success' => false, 'error' => "Vault truncated: invalid IV/Tag in chunk {$chunk_idx}."];
                }

                $ciphertext = ($cipher_len > 0) ? fread($v_fp, $cipher_len) : '';
                if (strlen($ciphertext) !== $cipher_len) {
                    fclose($v_fp);
                    fclose($dst_fp);
                    wp_delete_file($temp_dest);
                    return ['success' => false, 'error' => "Vault truncated: incomplete ciphertext in chunk {$chunk_idx}."];
                }

                $aad = pack('N', $chunk_idx);
                $plain = openssl_decrypt($ciphertext, self::CIPHER_GCM, $raw_key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
                if ($plain === false) {
                    // Decryption failed with primary key: attempt with transitional old key if rotation active
                    $fallback_ok = false;
                    if (class_exists('\\WebCareProScanner\\Security\\VaultRotator')) {
                        $transitional_key = \WebCareProScanner\Security\VaultRotator::get_transitional_old_key_if_active();
                        if ($transitional_key && $transitional_key !== $raw_key) {
                            $plain = openssl_decrypt($ciphertext, self::CIPHER_GCM, $transitional_key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
                            if ($plain !== false) {
                                $fallback_ok = true;
                            }
                        }
                    }

                    if (!$fallback_ok && $plain === false) {
                        fclose($v_fp);
                        fclose($dst_fp);
                        wp_delete_file($temp_dest);
                        return ['success' => false, 'error' => "Cryptographic authentication failed on chunk {$chunk_idx}."];
                    }
                }

                if ($plain !== '') {
                    $written = fwrite($dst_fp, $plain);
                    if ($written !== strlen($plain)) {
                        fclose($v_fp);
                        fclose($dst_fp);
                        wp_delete_file($temp_dest);
                        return ['success' => false, 'error' => "Disk write failure while writing restored chunk {$chunk_idx}."];
                    }
                    $dec_bytes_total += strlen($plain);
                    hash_update($dec_h_ctx, $plain);
                }
            }

            // Check for trailing unexpected data in vault stream
            $trailing = fread($v_fp, 1024);
            fclose($v_fp);
            fflush($dst_fp);
            fclose($dst_fp);

            if ($trailing !== '' && $trailing !== false) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => 'Integrity verification failed: unexpected trailing data beyond declared chunks in vault file.'];
            }

            // Verify decrypted byte count strictly matches declared file size
            if ($dec_bytes_total !== $expected_size) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => "Byte count verification failed: expected {$expected_size} bytes, decrypted {$dec_bytes_total} bytes."];
            }

            // Verify decrypted plaintext hash strictly matches declared SHA-256
            $actual_sha = hash_final($dec_h_ctx);
            if (!hash_equals($expected_sha, (string) $actual_sha)) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => 'Integrity verification failed: Decrypted file SHA-256 does not match vault manifest.'];
            }

            if (!@rename($temp_dest, $dest_path)) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => 'Failed to atomically move restored file into destination path.'];
            }

            return [
                'success'   => true,
                'dest_path' => $dest_path,
                'sha256'    => $expected_sha,
                'bytes'     => $dec_bytes_total,
                'format'    => self::VAULT_FORMAT_CHUNKED,
            ];
        }

        if ($format === self::VAULT_FORMAT_INLINE) {
            $payload = stream_get_contents($v_fp);
            fclose($v_fp);

            $payload = trim((string) $payload);
            $decrypted = self::decrypt_with_key($payload, $raw_key);
            if ($decrypted === false) {
                if (class_exists('\\WebCareProScanner\\Security\\VaultRotator')) {
                    $transitional_key = \WebCareProScanner\Security\VaultRotator::get_transitional_old_key_if_active();
                    if ($transitional_key && $transitional_key !== $raw_key) {
                        $decrypted = self::decrypt_with_key($payload, $transitional_key);
                    }
                }
            }

            if ($decrypted === false) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => 'Inline AEAD decryption failed: Invalid key or corrupted payload.'];
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents($temp_dest, $decrypted, LOCK_EX);
            if (!@rename($temp_dest, $dest_path)) {
                wp_delete_file($temp_dest);
                return ['success' => false, 'error' => 'Failed to move restored file into place.'];
            }

            return [
                'success'   => true,
                'dest_path' => $dest_path,
                'sha256'    => hash_file('sha256', $dest_path),
                'bytes'     => (int) @filesize($dest_path),
                'format'    => self::VAULT_FORMAT_INLINE,
            ];
        }

        // LEGACY_PLAINTEXT: Reject unless explicitly authorized
        if (!$allow_legacy_unverified) {
            fclose($v_fp);
            wp_delete_file($temp_dest);
            return [
                'success' => false,
                'error'   => 'Security Policy Violation: Unencrypted legacy vault archives are prohibited without explicit admin authorization.',
            ];
        }

        $dst_fp = @fopen($temp_dest, 'wb');
        if (!$dst_fp) {
            fclose($v_fp);
            return ['success' => false, 'error' => 'Failed to create destination stream for legacy restore.'];
        }
        stream_copy_to_stream($v_fp, $dst_fp);
        fclose($v_fp);
        fflush($dst_fp);
        fclose($dst_fp);

        if (!@rename($temp_dest, $dest_path)) {
            wp_delete_file($temp_dest);
            return ['success' => false, 'error' => 'Failed to move legacy restored file into place.'];
        }

        return [
            'success'   => true,
            'dest_path' => $dest_path,
            'sha256'    => hash_file('sha256', $dest_path),
            'bytes'     => (int) @filesize($dest_path),
            'format'    => 'LEGACY_PLAINTEXT',
        ];
    }

    /**
     * Inspect a vault file format and cryptographic envelope.
     *
     * @param string $vault_path
     * @return array
     */
    public static function inspect_vault_file(string $vault_path): array {
        if (!file_exists($vault_path) || !is_file($vault_path)) {
            return ['valid' => false, 'error' => 'File does not exist.'];
        }

        $fp = @fopen($vault_path, 'rb');
        if (!$fp) {
            return ['valid' => false, 'error' => 'File unreadable.'];
        }

        $header_buffer = fread($fp, 4096);
        $halt_marker = '__halt_compiler(); ' . '?>';
        $halt_pos = strpos($header_buffer, $halt_marker);
        if ($halt_pos === false) {
            fclose($fp);
            return ['valid' => false, 'error' => 'Missing PHP guard header.'];
        }

        $offset = $halt_pos + strlen($halt_marker);
        while ($offset < strlen($header_buffer) && ($header_buffer[$offset] === "\r" || $header_buffer[$offset] === "\n")) {
            $offset++;
        }
        fseek($fp, $offset, SEEK_SET);

        $line = fgets($fp, 4096);
        fclose($fp);

        if (is_string($line) && str_starts_with($line, '// WEBCARE_VAULT_FORMAT:V2_CHUNKED_GCM:')) {
            $json_str = substr(trim($line), strlen('// WEBCARE_VAULT_FORMAT:V2_CHUNKED_GCM:'));
            $meta = json_decode($json_str, true);
            if (!is_array($meta) || empty($meta) || empty($meta['chunks']) || (int) $meta['chunks'] < 1 || empty($meta['orig_sha256']) || !isset($meta['file_size'])) {
                return ['valid' => false, 'error' => 'Malformed chunked vault metadata or schema mismatch.'];
            }
            return [
                'valid'       => true,
                'format'      => self::VAULT_FORMAT_CHUNKED,
                'chunks'      => (int) ($meta['chunks'] ?? 0),
                'orig_sha256' => (string) ($meta['orig_sha256'] ?? ''),
                'file_size'   => (int) ($meta['file_size'] ?? 0),
                'meta'        => $meta,
            ];
        }

        if (is_string($line) && str_starts_with($line, '// WEBCARE_VAULT_FORMAT:V2_INLINE_AEAD')) {
            return [
                'valid'  => true,
                'format' => self::VAULT_FORMAT_INLINE,
            ];
        }

        if (is_string($line) && str_starts_with(trim($line), self::PREFIX_GCM)) {
            return [
                'valid'  => true,
                'format' => self::VAULT_FORMAT_INLINE,
            ];
        }

        return [
            'valid'  => true,
            'format' => 'LEGACY_PLAINTEXT',
        ];
    }
    // phpcs:enable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fclose, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_fread, WordPress.WP.AlternativeFunctions.file_system_operations_chmod, WordPress.WP.AlternativeFunctions.rename_rename
}
