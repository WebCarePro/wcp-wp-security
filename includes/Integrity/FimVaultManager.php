<?php
namespace WcpScanner\Integrity;

use WcpScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * FimVaultManager
 *
 * Enterprise-grade File Integrity Monitoring (FIM) Vault Engine.
 * Manages sharded, cryptographically authenticated filesystem manifests
 * in isolated storage (outside database) to support 1M+ file footprints.
 *
 * Features:
 * - Collects rich forensic metadata: Path, Type, Permissions, Owner, Group, Mtime, Ctime, Size, SHA-256
 * - HMAC-SHA256 authenticated tamper-detection for all manifest shards
 * - Gzip compression (.json.gz) maintaining low disk (< 1.5MB per 50k files) & memory footprint
 * - Scope sharding: Core, Plugins, Themes, Root Config, and Uploads Code
 * - Fail-closed security with instant tamper alarms if any shard is altered outside WCP
 */
class FimVaultManager {

    const VAULT_FOLDER = 'wcp-vault';
    const MANIFEST_EXT = '.manifest.gz';
    const META_FILE    = 'fim_meta.json';
    const OPTION_STATUS = 'wcpscan_fim_vault_status';

    const SCOPES = [
        'core'        => 'WordPress Core (wp-admin, wp-includes)',
        'core_root'   => 'WordPress Root & System Configs',
        'plugins'     => 'Active & Installed Plugins',
        'themes'      => 'Active & Installed Themes',
        'uploads'     => 'Uploads Directory Code & Executables',
    ];

    /**
     * Get or create the isolated, hardened vault directory in uploads.
     *
     * @return string Absolute directory path
     * @throws \RuntimeException
     */
    public static function get_vault_dir(): string {
        $upload_dir = wp_upload_dir();
        $base = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : WP_CONTENT_DIR . '/uploads';
        $vault_dir = wp_normalize_path(rtrim($base, '/\\') . '/' . self::VAULT_FOLDER);

        if (!is_dir($vault_dir)) {
            if (!wp_mkdir_p($vault_dir)) {
                throw new \RuntimeException(esc_html("Failed to initialize FIM Vault directory at: {$vault_dir}"));
            }
        }

        // Enforce webserver access lockdown (.htaccess for Apache/LiteSpeed, index.php for all)
        self::lockdown_vault_directory($vault_dir);

        return $vault_dir;
    }

    /**
     * Ensure vault directory is fortified against direct HTTP exposure.
     */
    private static function lockdown_vault_directory(string $dir) {
        $htaccess = rtrim($dir, '/\\') . '/.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "# WCP Security Vault - Direct Access Prohibited\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n");
        }

        $index = rtrim($dir, '/\\') . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\nexit;\n");
        }
    }

    /**
     * Get path to a specific scope manifest file.
     */
    public static function get_shard_path(string $scope): string {
        $dir = self::get_vault_dir();
        $safe_scope = sanitize_key($scope);
        return rtrim($dir, '/\\') . "/fim_{$safe_scope}" . self::MANIFEST_EXT;
    }

    /**
     * Build and write an HMAC-sealed, gzip-compressed manifest shard.
     *
     * Format:
     * [64-char Hex HMAC-SHA256] + "\n" + [Binary Gzip-Compressed JSON Payload]
     *
     * @param string $scope Scope identifier
     * @param array $files_data Array of file metadata items
     * @return bool
     */
    public static function write_shard(string $scope, array $files_data): bool {
        $path = self::get_shard_path($scope);
        $json_payload = wp_json_encode($files_data);
        if ($json_payload === false) {
            return false;
        }

        $compressed = function_exists('gzencode') ? gzencode($json_payload, 9) : $json_payload;
        $key = SecretVault::get_key();
        $hmac = hash_hmac('sha256', $compressed, $key);

        $sealed = $hmac . "\n" . $compressed;
        $written = @file_put_contents($path, $sealed, LOCK_EX);

        if ($written !== false) {
            global $wp_filesystem;
            if ($wp_filesystem) {
                $wp_filesystem->chmod($path, 0600);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                @chmod($path, 0600);
            }
            return true;
        }

        return false;
    }

    /**
     * Read and cryptographically verify an HMAC-sealed manifest shard.
     *
     * @param string $scope Scope identifier
     * @return array Array with ['valid' => bool, 'tampered' => bool, 'data' => array, 'count' => int]
     */
    public static function read_shard(string $scope): array {
        $path = self::get_shard_path($scope);
        if (!file_exists($path)) {
            return [
                'exists'   => false,
                'valid'    => false,
                'tampered' => false,
                'data'     => [],
                'count'    => 0,
            ];
        }

        $raw = @file_get_contents($path);
        if ($raw === false || strlen($raw) < 66) {
            return [
                'exists'   => true,
                'valid'    => false,
                'tampered' => true,
                'error'    => 'Corrupted or truncated manifest shard file.',
                'data'     => [],
                'count'    => 0,
            ];
        }

        // Split HMAC line (first 64 chars + newline)
        $first_newline = strpos($raw, "\n");
        if ($first_newline !== 64) {
            return [
                'exists'   => true,
                'valid'    => false,
                'tampered' => true,
                'error'    => 'Invalid cryptographic HMAC signature header format.',
                'data'     => [],
                'count'    => 0,
            ];
        }

        $stored_hmac = substr($raw, 0, 64);
        $compressed  = substr($raw, 65);

        $key = SecretVault::get_key();
        $computed_hmac = hash_hmac('sha256', $compressed, $key);

        // Strict constant-time HMAC attestation
        if (!hash_equals($stored_hmac, $computed_hmac)) {
            return [
                'exists'   => true,
                'valid'    => false,
                'tampered' => true,
                'error'    => "Cryptographic attestation mismatch! Shard [{$scope}] has been altered or forged outside WCP Vault.",
                'data'     => [],
                'count'    => 0,
            ];
        }

        $json = function_exists('gzdecode') ? @gzdecode($compressed) : $compressed;
        if ($json === false) {
            return [
                'exists'   => true,
                'valid'    => false,
                'tampered' => true,
                'error'    => "Gzip decompression failed for shard [{$scope}]. File may have been corrupted on disk.",
                'data'     => [],
                'count'    => 0,
            ];
        }

        $data = json_decode($json, true);
        if (!is_array($data)) {
            return [
                'exists'   => true,
                'valid'    => false,
                'tampered' => true,
                'error'    => "JSON parsing failed for verified shard [{$scope}].",
                'data'     => [],
                'count'    => 0,
            ];
        }

        return [
            'exists'   => true,
            'valid'    => true,
            'tampered' => false,
            'data'     => $data,
            'count'    => count($data),
        ];
    }

    /**
     * Get overall status across all FIM Vault shards.
     *
     * @return array
     */
    public static function get_vault_status(): array {
        $meta = self::get_meta();
        $shards_status = [];
        $has_tamper = false;
        $total_files = 0;
        $tampered_shards = [];
        $is_calibrated = !empty($meta['calibrated_at']);

        foreach (array_keys(self::SCOPES) as $scope) {
            $path = self::get_shard_path($scope);
            if (!file_exists($path)) {
                $shards_status[$scope] = [
                    'exists'   => false,
                    'count'    => 0,
                    'size'     => 0,
                    'tampered' => false,
                ];
                continue;
            }

            $res = self::read_shard($scope);
            if ($res['tampered']) {
                $has_tamper = true;
                $tampered_shards[] = $scope;
            }

            $total_files += $res['count'];
            $shards_status[$scope] = [
                'exists'   => true,
                'count'    => $res['count'],
                'size'     => @filesize($path),
                'tampered' => $res['tampered'],
                'error'    => $res['error'] ?? null,
            ];
        }

        return [
            'is_calibrated'    => $is_calibrated,
            'calibrated_at'    => $meta['calibrated_at'] ?? null,
            'calibrated_by'    => $meta['calibrated_by'] ?? 'admin',
            'last_verified_at' => $meta['last_verified_at'] ?? null,
            'has_tamper'       => $has_tamper,
            'tampered_shards'  => $tampered_shards,
            'total_files'      => $total_files,
            'shards'           => $shards_status,
            'vault_path'       => wp_normalize_path(self::get_vault_dir()),
        ];
    }

    /**
     * Retrieve metadata file content.
     */
    public static function get_meta(): array {
        $dir = self::get_vault_dir();
        $meta_file = rtrim($dir, '/\\') . '/' . self::META_FILE;
        if (!file_exists($meta_file)) {
            return [];
        }

        $content = @file_get_contents($meta_file);
        if (!$content) {
            return [];
        }

        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
    }

    /**
     * Look up baseline forensic metadata for a specific relative file path across shards.
     *
     * @param string $relative_path File path relative to ABSPATH (e.g. 'wp-config.php' or 'wp-content/plugins/...')
     * @return array|null Returns baseline record or null if not found
     */
    public static function get_file_baseline_record(string $relative_path): ?array {
        $relative_path = ltrim(wp_normalize_path($relative_path), '/');

        // Determine scope
        $scope = 'core';
        if (strpos($relative_path, 'wp-content/plugins/') === 0) {
            $scope = 'plugins';
        } elseif (strpos($relative_path, 'wp-content/themes/') === 0) {
            $scope = 'themes';
        } elseif (strpos($relative_path, 'wp-content/uploads/') === 0) {
            $scope = 'uploads';
        } elseif (strpos($relative_path, '/') === false) {
            $scope = 'core_root';
        }

        $res = self::read_shard($scope);
        if (!empty($res['valid']) && isset($res['data'][$relative_path])) {
            $record = $res['data'][$relative_path];
            $record['scope'] = $scope;
            return $record;
        }

        // Fallback: check core_root or core if not found
        if ($scope !== 'core_root') {
            $root_res = self::read_shard('core_root');
            if (!empty($root_res['valid']) && isset($root_res['data'][$relative_path])) {
                $record = $root_res['data'][$relative_path];
                $record['scope'] = 'core_root';
                return $record;
            }
        }

        return null;
    }

    /**
     * Update metadata file with calibration details.
     *
     * @param array $meta_data Metadata dictionary
     * @return bool
     */
    public static function save_meta(array $meta_data): bool {
        $dir = self::get_vault_dir();
        $meta_file = rtrim($dir, '/\\') . '/' . self::META_FILE;
        $encoded = wp_json_encode($meta_data, JSON_PRETTY_PRINT);
        return @file_put_contents($meta_file, $encoded, LOCK_EX) !== false;
    }
}
