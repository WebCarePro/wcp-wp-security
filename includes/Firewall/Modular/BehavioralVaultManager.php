<?php
/**
 * Behavioral Intelligence Vault Manager
 *
 * Manages an isolated, encrypted, and HMAC-SHA256 sealed on-premise vault
 * storing website behavioral intelligence, AST analysis findings, endpoint maps,
 * and synthesized modular firewall rules.
 *
 * Storage Location: wp-content/uploads/webcare-pro-security/intel-vault/
 * Shard Format: [64-char Hex HMAC-SHA256] + "\n" + [gzencode(json)]
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Modular
 */

namespace WebCareProScanner\Firewall\Modular;

if (!defined('ABSPATH')) {
    exit;
}

class BehavioralVaultManager {

    const VAULT_FOLDER = 'webcare-pro-security/intel-vault';
    const SHARD_EXT    = '.intel.gz';
    const META_FILE    = 'intel_meta.json';
    const OPTION_STATE = 'webcareproscan_modular_scan_state';

    const SHARD_INVENTORY = 'extension_inventory';
    const SHARD_ENDPOINTS = 'endpoint_behavior_map';
    const SHARD_FINDINGS  = 'ast_taint_findings';
    const SHARD_RULES     = 'modular_firewall_rules';

    /**
     * Get or create the isolated, hardened intel vault directory in uploads.
     *
     * @return string Absolute directory path.
     * @throws \RuntimeException If directory creation fails.
     */
    public static function get_vault_dir(): string {
        $upload_dir = wp_upload_dir();
        $base = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : WP_CONTENT_DIR . '/uploads';
        $vault_dir = wp_normalize_path(rtrim($base, '/\\') . '/' . self::VAULT_FOLDER);

        if (!is_dir($vault_dir)) {
            if (!wp_mkdir_p($vault_dir)) {
                throw new \RuntimeException(esc_html("Failed to initialize Behavioral Intelligence Vault directory at: {$vault_dir}"));
            }
        }

        // Fortify against direct HTTP exposure
        self::lockdown_vault_directory($vault_dir);

        return $vault_dir;
    }

    /**
     * Ensure vault directory is fortified against direct HTTP exposure with .htaccess and index.php.
     *
     * @param string $dir
     */
    private static function lockdown_vault_directory(string $dir): void {
        $htaccess = rtrim($dir, '/\\') . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# WebCare Pro Behavioral Intelligence Vault - Direct Access Prohibited\n" .
                     "<IfModule mod_authz_core.c>\n" .
                     "    Require all denied\n" .
                     "</IfModule>\n" .
                     "<IfModule !mod_authz_core.c>\n" .
                     "    Order deny,allow\n" .
                     "    Deny from all\n" .
                     "</IfModule>\n";
            @file_put_contents($htaccess, $rules);
        }

        $index = rtrim($dir, '/\\') . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }
    }

    /**
     * Get path to a specific shard file.
     *
     * @param string $shard_name
     * @return string
     */
    public static function get_shard_path(string $shard_name): string {
        $dir = self::get_vault_dir();
        $safe_name = sanitize_key($shard_name);
        return rtrim($dir, '/\\') . '/' . $safe_name . self::SHARD_EXT;
    }

    /**
     * Derive a high-entropy HMAC signing key.
     *
     * @return string
     */
    private static function get_signing_key(): string {
        if (class_exists('\\WebCareProScanner\\Security\\SecretVault') && method_exists('\\WebCareProScanner\\Security\\SecretVault', 'get_key')) {
            $key = \WebCareProScanner\Security\SecretVault::get_key();
            if (!empty($key)) {
                return (string) $key;
            }
        }

        return hash('sha256', wp_salt('auth') . 'webcare_pro_behavioral_intel_vault_key_' . get_current_blog_id());
    }

    /**
     * Build and write an HMAC-sealed, gzip-compressed shard.
     *
     * Format:
     * Line 1: [64-char Hex HMAC-SHA256 signature]
     * Line 2+: [Binary Gzip-Compressed JSON Payload]
     *
     * @param string $shard_name Shard identifier.
     * @param array  $data       Data array to serialize and store.
     * @return bool
     */
    public static function write_shard(string $shard_name, array $data): bool {
        try {
            $path = self::get_shard_path($shard_name);
            $json_payload = wp_json_encode($data, JSON_UNESCAPED_SLASHES);
            if ($json_payload === false) {
                return false;
            }

            // Gzip compress if zlib available, fallback to uncompressed payload
            $compressed = function_exists('gzencode') ? gzencode($json_payload, 6) : $json_payload;
            if ($compressed === false) {
                $compressed = $json_payload;
            }

            // Compute HMAC-SHA256 signature over binary payload
            $key = self::get_signing_key();
            $signature = hash_hmac('sha256', $compressed, $key);

            // Atomic file write using temporary staging file
            $final_content = $signature . "\n" . $compressed;
            $tmp_path = $path . '.' . wp_generate_password(8, false) . '.tmp';

            $written = @file_put_contents($tmp_path, $final_content);
            if ($written === false) {
                return false;
            }

            global $wp_filesystem;
            if (empty($wp_filesystem) && file_exists(ABSPATH . 'wp-admin/includes/file.php')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
            }

            $moved = false;
            if ($wp_filesystem instanceof \WP_Filesystem_Base && ($wp_filesystem->method ?? '') === 'direct') {
                $moved = (bool) $wp_filesystem->move($tmp_path, $path, true);
            }

            if (!$moved) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic local shard swap fallback when WP_Filesystem direct transport is unavailable (e.g. REST/CLI/FTP default hosts).
                if (!@rename($tmp_path, $path)) {
                    wp_delete_file($tmp_path);
                    return false;
                }
            }

            // Update shard metadata entry
            self::update_shard_meta($shard_name, [
                'sha256'    => $signature,
                'size'      => $written,
                'timestamp' => time(),
                'records'   => count($data),
            ]);

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Read, verify HMAC signature, and decompress a shard.
     *
     * @param string $shard_name
     * @return array|null Null on failure or tamper detection.
     */
    public static function read_shard(string $shard_name): ?array {
        $path = self::get_shard_path($shard_name);
        if (!file_exists($path) || !is_readable($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        if ($raw === false || strlen($raw) < 66) {
            return null;
        }

        $newline_pos = strpos($raw, "\n");
        if ($newline_pos !== 64) {
            self::record_tamper_incident($shard_name, 'Malformed signature line offset');
            return null;
        }

        $stored_sig = substr($raw, 0, 64);
        $payload    = substr($raw, 65);

        // Verify cryptographic HMAC
        $key = self::get_signing_key();
        $expected_sig = hash_hmac('sha256', $payload, $key);

        if (!hash_equals($expected_sig, $stored_sig)) {
            self::record_tamper_incident($shard_name, 'HMAC signature verification failed (file modified externally)');
            return null;
        }

        // Decompress payload
        $decompressed = (function_exists('gzdecode') && substr($payload, 0, 2) === "\x1f\x8b")
            ? @gzdecode($payload)
            : $payload;

        if ($decompressed === false) {
            return null;
        }

        $data = json_decode($decompressed, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Verify the HMAC integrity of a specific shard without returning data.
     *
     * @param string $shard_name
     * @return bool
     */
    public static function verify_shard_integrity(string $shard_name): bool {
        $path = self::get_shard_path($shard_name);
        if (!file_exists($path)) {
            return false;
        }

        $raw = @file_get_contents($path);
        if ($raw === false || strlen($raw) < 66) {
            return false;
        }

        $newline_pos = strpos($raw, "\n");
        if ($newline_pos !== 64) {
            return false;
        }

        $stored_sig = substr($raw, 0, 64);
        $payload    = substr($raw, 65);
        $key        = self::get_signing_key();

        return hash_equals(hash_hmac('sha256', $payload, $key), $stored_sig);
    }

    /**
     * Update metadata file with shard entry info.
     *
     * @param string $shard_name
     * @param array  $info
     */
    private static function update_shard_meta(string $shard_name, array $info): void {
        $meta = self::read_meta();
        $meta['shards'][$shard_name] = $info;
        $meta['last_updated'] = time();
        self::write_meta($meta);
    }

    /**
     * Read the vault metadata JSON.
     *
     * @return array
     */
    public static function read_meta(): array {
        try {
            $dir = self::get_vault_dir();
            $path = rtrim($dir, '/\\') . '/' . self::META_FILE;
            if (!file_exists($path) || !is_readable($path)) {
                return [
                    'version'      => '1.0',
                    'site_url'     => home_url(),
                    'last_updated' => 0,
                    'last_scan'    => 0,
                    'shards'       => [],
                ];
            }

            $raw = @file_get_contents($path);
            $parsed = json_decode($raw, true);
            return is_array($parsed) ? $parsed : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Write the vault metadata JSON atomically.
     *
     * @param array $meta
     * @return bool
     */
    public static function write_meta(array $meta): bool {
        try {
            $dir = self::get_vault_dir();
            $path = rtrim($dir, '/\\') . '/' . self::META_FILE;
            $json = wp_json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            return @file_put_contents($path, $json, LOCK_EX) !== false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Record an alert or activity event when vault tampering is detected.
     *
     * @param string $shard_name
     * @param string $reason
     */
    private static function record_tamper_incident(string $shard_name, string $reason): void {
        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::log(
                'intel_vault_tamper_detected',
                sprintf(
                    /* translators: %1$s: shard name, %2$s: reason */
                    __('Tamper Alert: Behavioral Vault shard "%1$s" failed HMAC verification: %2$s', 'webcare-pro-security'),
                    sanitize_key($shard_name),
                    sanitize_text_field($reason)
                ),
                'critical',
                [
                    'shard'  => $shard_name,
                    'reason' => $reason,
                    'time'   => current_time('mysql'),
                ]
            );
        }
    }

    /**
     * Get a comprehensive summary of the Intelligence Vault status.
     *
     * @return array
     */
    public static function get_vault_summary(): array {
        try {
            $dir = self::get_vault_dir();
            $meta = self::read_meta();

            $shards = [
                self::SHARD_INVENTORY => 'Component Inventory & Versions',
                self::SHARD_ENDPOINTS => 'AJAX & REST Behavior Map',
                self::SHARD_FINDINGS  => 'AST & Source-to-Sink Findings',
                self::SHARD_RULES     => 'Modular Firewall Rules',
            ];

            $shard_details = [];
            $all_intact = true;
            $total_bytes = 0;

            foreach ($shards as $key => $label) {
                $path = self::get_shard_path($key);
                $exists = file_exists($path);
                $size = $exists ? filesize($path) : 0;
                $is_valid = $exists ? self::verify_shard_integrity($key) : false;

                if ($exists && !$is_valid) {
                    $all_intact = false;
                }

                $total_bytes += $size;
                $shard_details[$key] = [
                    'label'     => $label,
                    'exists'    => $exists,
                    'size'      => $size,
                    'is_valid'  => $is_valid,
                    'timestamp' => $meta['shards'][$key]['timestamp'] ?? ($exists ? filemtime($path) : 0),
                    'records'   => $meta['shards'][$key]['records'] ?? 0,
                ];
            }

            return [
                'vault_dir'          => $dir,
                'vault_accessible'   => is_dir($dir) && wp_is_writable($dir),
                'shards'             => $shard_details,
                'all_shards_intact'  => $all_intact,
                'total_bytes'        => $total_bytes,
                'total_shards_count' => count(array_filter($shard_details, fn($s) => $s['exists'])),
                'last_scan'          => $meta['last_scan'] ?? 0,
                'last_updated'       => $meta['last_updated'] ?? 0,
            ];
        } catch (\Throwable $e) {
            return [
                'vault_accessible'  => false,
                'error'             => $e->getMessage(),
                'shards'            => [],
                'all_shards_intact' => false,
            ];
        }
    }

    /**
     * Purge all shards and metadata from the vault.
     *
     * @return bool
     */
    public static function purge_vault(): bool {
        try {
            $dir = self::get_vault_dir();
            $files = glob(rtrim($dir, '/\\') . '/*' . self::SHARD_EXT);
            if (is_array($files)) {
                foreach ($files as $f) {
                    if (is_file($f)) {
                        wp_delete_file($f);
                    }
                }
            }

            $meta_path = rtrim($dir, '/\\') . '/' . self::META_FILE;
            if (file_exists($meta_path)) {
                wp_delete_file($meta_path);
            }

            delete_option(self::OPTION_STATE);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
