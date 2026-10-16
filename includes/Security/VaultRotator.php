<?php
namespace WcpScanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

class VaultRotator {

    const STATE_OPTION         = 'wcpscan_vault_rotation_state';
    const LOCK_TRANSIENT       = 'wcpscan_vault_rotation_lock';
    const BACKUP_PREFIX        = 'wcpscan_vault_backup_';
    const OLD_KEY_BLOB         = 'wcpscan_vault_old_key_blob';
    const EPHEMERAL_KEY_PREFIX = 'wcpscan_vault_ephem_';
    const NEW_KEY_BLOB         = 'wcpscan_vault_new_key_blob';
    const MAX_LOCK_TIME        = 600; // 10 minutes
    const DEFAULT_BATCH_SIZE   = 10;

    /**
     * Start a new key rotation with two-phase commit preparation.
     *
     * @param string $new_key_material
     * @return array|\WP_Error
     */
    public static function start_rotation(string $new_key_material): array|\WP_Error {
        if (!current_user_can('manage_options')) {
            return new \WP_Error('forbidden', 'Insufficient privileges to rotate vault keys.');
        }

        if (empty(trim($new_key_material))) {
            return new \WP_Error('invalid_key', 'New key material cannot be empty.');
        }

        if (!self::acquire_lock()) {
            return new \WP_Error('locked', 'Another vault key rotation is already in progress.');
        }

        $state = get_option(self::STATE_OPTION, []);
        if (!empty($state['status']) && in_array($state['status'], ['preparing', 'migrating', 'verifying'], true)) {
            self::release_lock();
            return new \WP_Error('busy', 'A rotation migration is already actively running.');
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

        $new_binary_key = strlen($new_key) === 64 && ctype_xdigit($new_key) ? (string) hex2bin($new_key) : hash('sha256', $new_key, true);

        // Fetch encrypted settings keys from wcpscan_settings
        $settings = get_option(\WcpScanner\System\SettingsManager::OPTION_KEY, []);
        $secret_fields = [
            'gemini_api_key', 'openai_api_key', 'claude_api_key',
            'cloudflare_api_token', 'cloudflare_zone_id',
            'slack_webhook_url', 'discord_webhook_url',
            'clickup_webhook_url', 'asana_webhook_url', 'generic_webhook_url'
        ];

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
                $state['failed_records'][] = "wcpscan_settings.{$field}";
                $state['last_error'] = $e->getMessage();
            }

            $processed++;
        }

        if ($modified_settings) {
            update_option(\WcpScanner\System\SettingsManager::OPTION_KEY, $settings, false);
        }

        // If all records migrated and no failures, move to verifying
        if ($state['records_done'] >= $state['records_total'] && empty($state['failed_records'])) {
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

        $new_binary_key = strlen($new_key) === 64 && ctype_xdigit($new_key) ? (string) hex2bin($new_key) : hash('sha256', $new_key, true);

        $settings = get_option(\WcpScanner\System\SettingsManager::OPTION_KEY, []);
        $secret_fields = [
            'gemini_api_key', 'openai_api_key', 'claude_api_key',
            'cloudflare_api_token', 'cloudflare_zone_id',
            'slack_webhook_url', 'discord_webhook_url',
            'clickup_webhook_url', 'asana_webhook_url', 'generic_webhook_url'
        ];

        $all_verified = true;
        foreach ($secret_fields as $field) {
            if (empty($settings[$field]) || !SecretVault::is_encrypted((string) $settings[$field])) {
                continue;
            }

            $decrypted = SecretVault::decrypt_with_key((string) $settings[$field], $new_binary_key);
            if ($decrypted === false) {
                $all_verified = false;
                $state['failed_records'][] = "wcpscan_settings.{$field}";
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
     * Create isolated single-row serialized backup of all encrypted settings.
     */
    private static function create_backup(string $backup_id): array|\WP_Error {
        $settings = get_option(\WcpScanner\System\SettingsManager::OPTION_KEY, []);
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

        $settings = get_option(\WcpScanner\System\SettingsManager::OPTION_KEY, []);
        $restored = 0;

        foreach ($backup['records'] as $k => $v) {
            $settings[$k] = $v;
            $restored++;
        }

        update_option(\WcpScanner\System\SettingsManager::OPTION_KEY, $settings, false);
        return $restored;
    }
}
