<?php
namespace WebCareProScanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

class VaultRotator {

    const STATE_OPTION         = 'webcareproscan_vault_rotation_state';
    const LOCK_TRANSIENT       = 'webcareproscan_vault_rotation_lock';
    const BACKUP_PREFIX        = 'webcareproscan_vault_backup_';
    const OLD_KEY_BLOB         = 'webcareproscan_vault_old_key_blob';
    const EPHEMERAL_KEY_PREFIX = 'webcareproscan_vault_ephem_';
    const NEW_KEY_BLOB         = 'webcareproscan_vault_new_key_blob';
    const MAX_LOCK_TIME        = 600; // 10 minutes
    const DEFAULT_BATCH_SIZE   = 10;

    /**
     * Start a new key rotation with two-phase commit preparation.
     *
     * @param string $new_key_material
     * @param bool   $force
     * @return array|\WP_Error
     */
    public static function start_rotation(string $new_key_material, bool $force = false): array|\WP_Error {
        if (!current_user_can('manage_options')) {
            return new \WP_Error('forbidden', 'Insufficient privileges to rotate vault keys.');
        }

        if (empty(trim($new_key_material))) {
            return new \WP_Error('invalid_key', 'New key material cannot be empty.');
        }

        $state = get_option(self::STATE_OPTION, []);
        $started = intval($state['started_at'] ?? 0);

        // Auto-clear stale state and lock if previous rotation is older than MAX_LOCK_TIME (600s) or force requested
        if ($force || $started === 0 || (time() - $started) > self::MAX_LOCK_TIME) {
            self::clear_transitional_keys();
            self::release_lock();
            if (!empty($state['status']) && in_array($state['status'], ['preparing', 'migrating', 'verifying'], true)) {
                $state['status'] = 'idle';
                $state['last_error'] = 'Previous rotation timed out and was automatically cleared.';
                update_option(self::STATE_OPTION, $state, false);
            }
        }

        if (!self::acquire_lock()) {
            return new \WP_Error('locked', 'Another vault key rotation is already in progress.');
        }

        $state = get_option(self::STATE_OPTION, []);
        if (!$force && !empty($state['status']) && in_array($state['status'], ['preparing', 'migrating', 'verifying'], true)) {
            self::release_lock();
            return new \WP_Error('busy', 'A rotation migration is already actively running. Please wait a moment.');
        }

        // Capture current old key
        try {
            $old_binary_key = SecretVault::get_key();
        } catch (\Throwable $e) {
            self::release_lock();
            return new \WP_Error('key_error', 'Cannot derive current active key: ' . $e->getMessage());
        }

        // Create full backup of all encrypted settings
        $backup_id = self::BACKUP_PREFIX . gmdate('Ymd_His') . '_' . wp_generate_password(8, false);
        $backup_result = self::create_backup($backup_id);
        if (is_wp_error($backup_result)) {
            self::release_lock();
            return $backup_result;
        }

        // Store transitional old key securely using ephemeral sealed envelope
        self::store_transitional_old_key($old_binary_key);
        self::store_transitional_new_key($new_key_material);

        $state = [
            'status'         => 'migrating',
            'old_key_hash'   => hash('sha256', $old_binary_key),
            'new_key_hash'   => hash('sha256', $new_key_material),
            'started_at'     => time(),
            'records_total'  => $backup_result['count'],
            'records_done'   => 0,
            'failed_records' => [],
            'backup_id'      => $backup_id,
            'last_error'     => null,
        ];

        update_option(self::STATE_OPTION, $state, false);
        self::release_lock();

        return $state;
    }

    /**
     * Continue batch migration (resumable and idempotent).
     *
     * @param int $batch_size
     * @return array|\WP_Error
     */
    public static function continue_rotation(int $batch_size = self::DEFAULT_BATCH_SIZE): array|\WP_Error {
        if (!self::acquire_lock()) {
            return new \WP_Error('locked', 'Could not acquire rotation lock.');
        }

        $state = get_option(self::STATE_OPTION, []);
        if (($state['status'] ?? '') !== 'migrating') {
            self::release_lock();
            return new \WP_Error('invalid_state', 'Rotation is not in migrating state.');
        }

        $old_key = self::retrieve_transitional_old_key();
        $new_key = self::retrieve_transitional_new_key();

        if ($old_key === false || $new_key === false) {
            $state['status'] = 'failed';
            $state['last_error'] = 'Transitional key envelope expired or missing.';
            update_option(self::STATE_OPTION, $state, false);
            self::release_lock();
            return new \WP_Error('keys_missing', $state['last_error']);
        }

        $old_binary_key = strlen($old_key) === 32
            ? $old_key
            : (strlen($old_key) === 64 && ctype_xdigit($old_key) ? (string) hex2bin($old_key) : hash('sha256', $old_key, true));
        $new_binary_key = strlen($new_key) === 32
            ? $new_key
            : (strlen($new_key) === 64 && ctype_xdigit($new_key) ? (string) hex2bin($new_key) : hash('sha256', $new_key, true));

        // Fetch encrypted settings keys from webcareproscan_settings
        $settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
        $secret_fields = self::get_rotatable_secret_fields($settings);

        $processed = 0;
        $modified_settings = false;

        foreach ($secret_fields as $field) {
            if ($processed >= $batch_size) {
                break;
            }

            if (empty($settings[$field]) || !SecretVault::is_encrypted((string) $settings[$field])) {
                continue;
            }

            $current_cipher = (string) $settings[$field];

            // Idempotency: skip if already successfully encrypted under new key
            if (self::is_under_key($current_cipher, $new_binary_key)) {
                $processed++;
                continue;
            }

            try {
                $re_encrypted = SecretVault::rotate_record($current_cipher, $old_key, $new_key);
                $settings[$field] = $re_encrypted;
                $modified_settings = true;
                $state['records_done']++;
            } catch (\Throwable $e) {
                $state['failed_records'][] = "webcareproscan_settings.{$field}";
                $state['last_error'] = $e->getMessage();
            }

            $processed++;
        }

        if ($modified_settings) {
            update_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, $settings, false);
        }

        // If any records failed, mark failed and release lock
        if (!empty($state['failed_records'])) {
            $state['status'] = 'failed';
            update_option(self::STATE_OPTION, $state, false);
            self::release_lock();
            return new \WP_Error('migration_failed', 'Key rotation failed for: ' . implode(', ', $state['failed_records']) . '. ' . ($state['last_error'] ?? ''));
        }

        // If all settings records migrated and no failures, rotate <20MB encrypted vault archives on disk before verifying
        if ($state['records_done'] >= $state['records_total']) {
            $disk_rotation = self::rotate_encrypted_disk_archives($old_binary_key, $new_binary_key);
            $state['archives_rotated'] = (int) ($disk_rotation['rotated'] ?? 0);
            if (!empty($disk_rotation['failed'])) {
                $state['failed_records'] = array_merge($state['failed_records'] ?? [], $disk_rotation['failed']);
                $state['status']         = 'failed';
                $state['last_error']     = 'Disk archive key rotation failed for one or more vault files.';
                update_option(self::STATE_OPTION, $state, false);
                self::release_lock();
                return new \WP_Error('archive_migration_failed', $state['last_error']);
            }
            $state['status'] = 'verifying';
        }

        update_option(self::STATE_OPTION, $state, false);
        self::release_lock();

        return $state;
    }

    /**
     * Verify all records decrypt cleanly under the new key, then commit.
     *
     * @return array|\WP_Error
     */
    public static function verify_and_commit(): array|\WP_Error {
        if (!self::acquire_lock()) {
            return new \WP_Error('locked', 'Could not acquire rotation lock.');
        }

        $state = get_option(self::STATE_OPTION, []);
        if (($state['status'] ?? '') !== 'verifying') {
            self::release_lock();
            return new \WP_Error('invalid_state', 'Rotation is not in verifying state.');
        }

        $new_key = self::retrieve_transitional_new_key();
        if ($new_key === false) {
            $state['status'] = 'failed';
            $state['last_error'] = 'New key material missing during verification phase.';
            update_option(self::STATE_OPTION, $state, false);
            self::release_lock();
            return new \WP_Error('keys_missing', $state['last_error']);
        }

        $new_binary_key = strlen($new_key) === 32
            ? $new_key
            : (strlen($new_key) === 64 && ctype_xdigit($new_key) ? (string) hex2bin($new_key) : hash('sha256', $new_key, true));

        $settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
        $secret_fields = self::get_rotatable_secret_fields($settings);

        $all_verified = true;
        foreach ($secret_fields as $field) {
            if (empty($settings[$field]) || !SecretVault::is_encrypted((string) $settings[$field])) {
                continue;
            }

            $decrypted = SecretVault::decrypt_with_key((string) $settings[$field], $new_binary_key);
            if ($decrypted === false) {
                $all_verified = false;
                $state['failed_records'][] = "webcareproscan_settings.{$field}";
            }
        }

        if (!$all_verified) {
            $state['status'] = 'failed';
            $state['last_error'] = 'Verification failed: one or more records failed decryption under the new key.';
            update_option(self::STATE_OPTION, $state, false);
            self::release_lock();
            return new \WP_Error('verification_failed', $state['last_error']);
        }

        // Commit: mark committed and destroy transitional keys
        $state['status'] = 'committed';
        $state['committed_at'] = time();
        update_option(self::STATE_OPTION, $state, false);

        self::clear_transitional_keys();
        self::release_lock();

        return $state;
    }

    /**
     * Roll back all migrated values to the pre-rotation backup.
     *
     * @return array|\WP_Error
     */
    public static function rollback(): array|\WP_Error {
        if (!self::acquire_lock()) {
            return new \WP_Error('locked', 'Could not acquire rotation lock.');
        }

        $state = get_option(self::STATE_OPTION, []);
        $backup_id = $state['backup_id'] ?? null;

        if (!$backup_id) {
            self::release_lock();
            return new \WP_Error('no_backup', 'No pre-rotation backup ID found to roll back.');
        }

        $restored = self::restore_backup($backup_id);
        if (is_wp_error($restored)) {
            self::release_lock();
            return $restored;
        }

        self::clear_transitional_keys();
        $state['status'] = 'rolled_back';
        $state['rolled_back_at'] = time();
        update_option(self::STATE_OPTION, $state, false);

        self::release_lock();
        return [
            'status'   => 'rolled_back',
            'restored' => $restored,
        ];
    }

    /**
     * Get current status of key rotation.
     */
    public static function get_status(): array {
        return get_option(self::STATE_OPTION, ['status' => 'idle']);
    }

    /**
     * Force reset any active or stuck key rotation state and release all locks.
     */
    public static function reset_state(): void {
        self::clear_transitional_keys();
        self::release_lock();
        update_option(self::STATE_OPTION, ['status' => 'idle', 'reset_at' => time()], false);
    }

    /**
     * Provide transitional old key during active migration window for dual-key decrypt fallback.
     */
    public static function get_transitional_old_key_if_active(): string|false {
        $state = get_option(self::STATE_OPTION, []);
        $status = $state['status'] ?? '';
        if (!in_array($status, ['migrating', 'verifying'], true)) {
            return false;
        }
        return self::retrieve_transitional_old_key();
    }

    /* ---------------------------------------------------------------
     * Internal Helpers
     * --------------------------------------------------------------- */

    private static function acquire_lock(): bool {
        if (get_transient(self::LOCK_TRANSIENT)) {
            return false;
        }
        return set_transient(self::LOCK_TRANSIENT, get_current_user_id() ?: 'cli', self::MAX_LOCK_TIME);
    }

    private static function release_lock(): void {
        delete_transient(self::LOCK_TRANSIENT);
    }

    private static function is_under_key(string $ciphertext, string $binary_key): bool {
        return SecretVault::decrypt_with_key($ciphertext, $binary_key) !== false;
    }

    /**
     * Store transitional key sealed in an ephemeral envelope.
     */
    private static function store_transitional_old_key(string $old_binary_key): void {
        $ephemeral_key = random_bytes(32);

        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = sodium_crypto_secretbox($old_binary_key, $nonce, $ephemeral_key);
            $payload = 'sod:' . base64_encode($nonce . $cipher);
        } else {
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($old_binary_key, 'aes-256-gcm', $ephemeral_key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            $payload = 'gcm:' . base64_encode($iv . $tag . $cipher);
        }

        set_transient(self::OLD_KEY_BLOB, $payload, 45 * MINUTE_IN_SECONDS);
        set_transient(self::EPHEMERAL_KEY_PREFIX . 'old', base64_encode($ephemeral_key), 45 * MINUTE_IN_SECONDS);
    }

    private static function retrieve_transitional_old_key(): string|false {
        $payload = get_transient(self::OLD_KEY_BLOB);
        $ephem_b64 = get_transient(self::EPHEMERAL_KEY_PREFIX . 'old');
        if (!$payload || !$ephem_b64) {
            return false;
        }

        $ephemeral_key = base64_decode($ephem_b64, true);
        if (!$ephemeral_key || strlen($ephemeral_key) !== 32) {
            return false;
        }

        if (str_starts_with($payload, 'sod:') && function_exists('sodium_crypto_secretbox_open')) {
            $raw = base64_decode(substr($payload, 4), true);
            $nonce_len = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
            if (!$raw || strlen($raw) < $nonce_len) {
                return false;
            }
            $nonce = substr($raw, 0, $nonce_len);
            $cipher = substr($raw, $nonce_len);
            $decrypted = sodium_crypto_secretbox_open($cipher, $nonce, $ephemeral_key);
            return $decrypted !== false ? $decrypted : false;
        }

        if (str_starts_with($payload, 'gcm:') && function_exists('openssl_decrypt')) {
            $raw = base64_decode(substr($payload, 4), true);
            if (!$raw || strlen($raw) < 28) {
                return false;
            }
            $iv = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $cipher = substr($raw, 28);
            $decrypted = openssl_decrypt($cipher, 'aes-256-gcm', $ephemeral_key, OPENSSL_RAW_DATA, $iv, $tag);
            return $decrypted !== false ? $decrypted : false;
        }

        return false;
    }

    private static function store_transitional_new_key(string $new_key): void {
        $ephemeral_key = random_bytes(32);
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($new_key, 'aes-256-gcm', $ephemeral_key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        $payload = base64_encode($iv . $tag . $cipher);

        set_transient(self::NEW_KEY_BLOB, $payload, 45 * MINUTE_IN_SECONDS);
        set_transient(self::EPHEMERAL_KEY_PREFIX . 'new', base64_encode($ephemeral_key), 45 * MINUTE_IN_SECONDS);
    }

    private static function retrieve_transitional_new_key(): string|false {
        $payload = get_transient(self::NEW_KEY_BLOB);
        $ephem_b64 = get_transient(self::EPHEMERAL_KEY_PREFIX . 'new');
        if (!$payload || !$ephem_b64) {
            return false;
        }

        $ephemeral_key = base64_decode($ephem_b64, true);
        $raw = base64_decode($payload, true);
        if (!$ephemeral_key || !$raw || strlen($raw) < 28) {
            return false;
        }

        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $cipher = substr($raw, 28);
        $decrypted = openssl_decrypt($cipher, 'aes-256-gcm', $ephemeral_key, OPENSSL_RAW_DATA, $iv, $tag);
        return $decrypted !== false ? $decrypted : false;
    }

    private static function clear_transitional_keys(): void {
        delete_transient(self::OLD_KEY_BLOB);
        delete_transient(self::NEW_KEY_BLOB);
        delete_transient(self::EPHEMERAL_KEY_PREFIX . 'old');
        delete_transient(self::EPHEMERAL_KEY_PREFIX . 'new');
    }

    /**
     * Return all setting keys that store SecretVault ciphertexts (static + dynamic discovery).
     */
    private static function get_rotatable_secret_fields(array $settings): array {
        $fields = [
            'gemini_api_key',
            'openai_api_key',
            'claude_api_key',
            'deepseek_api_key',
            'openrouter_api_key',
            'mcp_token',
            'cloudflare_api_token',
            'cloudflare_zone_id',
            'slack_webhook_url',
            'discord_webhook_url',
            'clickup_webhook_url',
            'asana_webhook_url',
            'generic_webhook_url',
            'tamper_webhook_url',
        ];

        foreach ($settings as $k => $v) {
            if (is_string($k) && is_string($v) && SecretVault::is_encrypted($v) && !in_array($k, $fields, true)) {
                $fields[] = $k;
            }
        }

        return $fields;
    }

    /**
     * Test whether the first chunk of a V2 Chunked Streaming vault file decrypts with the specified key.
     */
    private static function is_chunked_vault_under_key(string $vault_path, string $binary_key): bool {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($vault_path, 'rb');
        if (!$fp) {
            return false;
        }

        // Seek past PHP guard header
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
        $header_buffer = fread($fp, 4096);
        $halt_marker = '__halt_compiler(); ?' . '>';
        $halt_pos = strpos($header_buffer, $halt_marker);
        if ($halt_pos === false) {
            $halt_marker_alt = '__halt_compiler(); ' . '?>';
            $halt_pos = strpos($header_buffer, $halt_marker_alt);
            if ($halt_pos === false) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }
            $halt_marker = $halt_marker_alt;
        }

        $payload_offset = $halt_pos + strlen($halt_marker);
        while ($payload_offset < strlen($header_buffer) && ($header_buffer[$payload_offset] === "\r" || $header_buffer[$payload_offset] === "\n")) {
            $payload_offset++;
        }
        fseek($fp, $payload_offset, SEEK_SET);

        $format_line = fgets($fp, 4096);
        if (!is_string($format_line) || !str_starts_with($format_line, '// WEBCARE_VAULT_FORMAT:V2_CHUNKED_GCM:')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        $json_str = trim(substr($format_line, strlen('// WEBCARE_VAULT_FORMAT:V2_CHUNKED_GCM:')));
        $meta = json_decode($json_str, true);
        if (!is_array($meta) || empty($meta)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        $total_chunks  = (int) ($meta['chunks'] ?? 0);
        $expected_sha  = (string) ($meta['orig_sha256'] ?? '');
        $expected_size = isset($meta['file_size']) ? (int) $meta['file_size'] : -1;
        $chunk_size    = (int) ($meta['chunk_size'] ?? 2097152);

        // Strict archive metadata schema and boundary validation (Finding 1.5)
        if (
            ($meta['format'] ?? '') !== \WebCareProScanner\Security\SecretVault::VAULT_FORMAT_CHUNKED
            || $total_chunks < 1
            || $total_chunks > 1000000
            || $expected_size < 0
            || $chunk_size < 1024
            || $chunk_size > 10485760
            || !preg_match('/^[a-f0-9]{64}$/i', $expected_sha)
        ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        $raw_key = strlen($binary_key) === 64 && ctype_xdigit($binary_key)
            ? (string) hex2bin($binary_key)
            : (strlen($binary_key) === 32 ? $binary_key : hash('sha256', $binary_key, true));

        $dec_h_ctx       = hash_init('sha256');
        $dec_bytes_total = 0;

        // Verify ALL chunks under key and stream plaintext hash (Finding 1.5)
        for ($chunk_idx = 0; $chunk_idx < $total_chunks; $chunk_idx++) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $len_buf = fread($fp, 4);
            if ($len_buf === false || strlen($len_buf) < 4) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }

            $cipher_len = unpack('N', $len_buf)[1];
            if ($cipher_len < 0 || $cipher_len > ($chunk_size + 64)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $iv  = fread($fp, 12);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $tag = fread($fp, 16);
            if (strlen($iv) !== 12 || strlen($tag) !== 16) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
            $ciphertext = ($cipher_len > 0) ? fread($fp, $cipher_len) : '';
            if (strlen($ciphertext) !== $cipher_len) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }

            $plaintext = @openssl_decrypt($ciphertext, 'aes-256-gcm', $raw_key, OPENSSL_RAW_DATA, $iv, $tag, pack('N', $chunk_idx));
            if ($plaintext === false) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }

            hash_update($dec_h_ctx, $plaintext);
            $dec_bytes_total += strlen($plaintext);
        }

        // Verify total decrypted bytes and plaintext hash (Finding 1.5)
        if ($dec_bytes_total !== $expected_size) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        $actual_sha = hash_final($dec_h_ctx);
        if (!hash_equals($expected_sha, $actual_sha)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        // Verify no trailing data exists after the final declared chunk (Finding 1.5)
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
        $trailing = fread($fp, 1);
        if ($trailing !== '' && $trailing !== false) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);
        return true;
    }

    /**
     * Re-encrypt quarantined files, remediation backups, and transaction snapshots under the new key.
     * Supports both V2 Chunked Streaming AEAD (constant RAM) and legacy inline archives.
     */
    private static function rotate_encrypted_disk_archives(string $old_binary_key, string $new_binary_key): array {
        $result     = ['rotated' => 0, 'failed' => []];
        $upload_dir = wp_upload_dir();
        $base_dir   = trailingslashit($upload_dir['basedir']);
        $candidates = array_merge(
            @glob($base_dir . 'webcare-quarantine/*.vault*') ?: [],
            @glob($base_dir . 'webcare-pro-security/.vault/*.quarantine*') ?: [],
            @glob($base_dir . 'webcare-pro-security/.backups/remediation/*.bak.php') ?: [],
            @glob($base_dir . 'webcare-pro-security/.remediation/transactions/*/files/*.bak*') ?: []
        );

        $halt_marker = '__halt_compiler(); ?' . '>';
        foreach ($candidates as $file_path) {
            if (!is_file($file_path) || is_link($file_path)) {
                continue;
            }

            // Inspect file format
            $inspect = SecretVault::inspect_vault_file($file_path);
            if ($inspect['format'] === SecretVault::VAULT_FORMAT_CHUNKED) {
                // If already under new key, count as rotated and proceed
                if (self::is_chunked_vault_under_key($file_path, $new_binary_key)) {
                    $result['rotated']++;
                    continue;
                }

                $temp_dec   = $file_path . '.rot_dec_' . bin2hex(random_bytes(4));
                $temp_reenc = $file_path . '.rot_enc_' . bin2hex(random_bytes(4));

                $dec_res = SecretVault::decrypt_vault_to_file($file_path, $temp_dec, $old_binary_key);
                if (empty($dec_res['success'])) {
                    if (file_exists($temp_dec)) {
                        wp_delete_file($temp_dec);
                    }
                    $result['failed'][] = 'archive:' . basename($file_path);
                    continue;
                }

                $enc_res = SecretVault::encrypt_file_to_vault($temp_dec, $temp_reenc, $new_binary_key);
                wp_delete_file($temp_dec);

                if (empty($enc_res['success']) || !file_exists($temp_reenc) || filesize($temp_reenc) === 0) {
                    if (file_exists($temp_reenc)) {
                        wp_delete_file($temp_reenc);
                    }
                    $result['failed'][] = 'archive:' . basename($file_path);
                    continue;
                }

                // Verify the newly encrypted archive is 100% decipherable under new key before replacing (Finding 1.3)
                if (!self::is_chunked_vault_under_key($temp_reenc, $new_binary_key)) {
                    wp_delete_file($temp_reenc);
                    $result['failed'][] = 'archive:' . basename($file_path);
                    continue;
                }

                // Atomically swap in re-encrypted vault archive (never destructive copy - Finding 1.3)
                // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic swap of rotated archive
                if (!@rename($temp_reenc, $file_path)) {
                    wp_delete_file($temp_reenc);
                    $result['failed'][] = 'archive:' . basename($file_path);
                    continue;
                }

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                @chmod($file_path, 0600);
                $result['rotated']++;
                continue;
            }

            // Fallback for inline AEAD and legacy archives (<20MB)
            $size = (int) @filesize($file_path);
            if ($size <= 0 || $size > 20971520) {
                continue;
            }
            $raw = @file_get_contents($file_path);
            if ($raw === false) {
                continue;
            }
            $pos = strpos($raw, $halt_marker);
            if ($pos === false) {
                continue;
            }
            $split_pos = $pos + strlen($halt_marker);
            while ($split_pos < strlen($raw) && ($raw[$split_pos] === "\r" || $raw[$split_pos] === "\n")) {
                $split_pos++;
            }
            $header  = substr($raw, 0, $split_pos);
            $payload = substr($raw, $split_pos);

            // Strip format prefix if present (V2_INLINE_AEAD support - Finding 1.3)
            $format_prefix = '';
            if (str_starts_with($payload, '// WEBCARE_VAULT_FORMAT:V2_INLINE_AEAD')) {
                $nl_pos = strpos($payload, "\n");
                if ($nl_pos !== false) {
                    $format_prefix = substr($payload, 0, $nl_pos + 1);
                    $payload = ltrim(substr($payload, $nl_pos + 1), "\r\n");
                }
            }

            if (!SecretVault::is_encrypted($payload)) {
                continue;
            }
            if (self::is_under_key($payload, $new_binary_key)) {
                $result['rotated']++;
                continue;
            }

            $plain = SecretVault::decrypt_with_key($payload, $old_binary_key);
            if ($plain === false) {
                $result['failed'][] = 'archive:' . basename($file_path);
                continue;
            }

            try {
                $reencrypted = SecretVault::encrypt_with_key($plain, $new_binary_key);
                $temp_file   = $file_path . '.rot_' . bin2hex(random_bytes(4));
                $new_content = $header . $format_prefix . $reencrypted;
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                if (@file_put_contents($temp_file, $new_content, LOCK_EX) === strlen($new_content)) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
                    if (@rename($temp_file, $file_path)) {
                        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                        @chmod($file_path, 0600);
                        $result['rotated']++;
                        continue;
                    }
                }
                wp_delete_file($temp_file);
                $result['failed'][] = 'archive:' . basename($file_path);
            } catch (\Throwable $e) {
                $result['failed'][] = 'archive:' . basename($file_path);
            }
        }

        return $result;
    }

    /**
     * Create isolated single-row serialized backup of all encrypted settings.
     */
    private static function create_backup(string $backup_id): array|\WP_Error {
        $settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
        $backup_data = [];
        $count = 0;

        foreach ($settings as $k => $v) {
            if (is_string($v) && SecretVault::is_encrypted($v)) {
                $backup_data[$k] = $v;
                $count++;
            }
        }

        $saved = update_option($backup_id, [
            'created_at' => time(),
            'records'    => $backup_data,
        ], false);

        if (!$saved && !get_option($backup_id)) {
            return new \WP_Error('backup_failed', 'Failed to create pre-rotation backup snapshot.');
        }

        return ['count' => $count];
    }

    /**
     * Restore encrypted settings from pre-rotation backup snapshot.
     */
    private static function restore_backup(string $backup_id): int|\WP_Error {
        $backup = get_option($backup_id);
        if (!$backup || !isset($backup['records']) || !is_array($backup['records'])) {
            return new \WP_Error('invalid_backup', 'Backup record is missing or corrupted.');
        }

        $settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
        $restored = 0;

        foreach ($backup['records'] as $k => $v) {
            $settings[$k] = $v;
            $restored++;
        }

        update_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, $settings, false);
        return $restored;
    }
}
