<?php
declare(strict_types=1);

namespace WebCareProScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * System Readiness & Environment Pre-Flight Checker
 *
 * Performs deep, multi-vector compatibility audits covering PHP extensions,
 * authenticated AES-256-GCM AEAD encryption prerequisites, memory thresholds,
 * MySQL capabilities, and filesystem vault write permissions.
 *
 * @package WebCareProScanner\System
 * @author  Mir Alamin (WebCare Pro)
 */
class SystemReadinessChecker {

    const MIN_PHP_VERSION       = '8.3.0';
    const RECOMMENDED_PHP       = '8.4.0';
    const MIN_WP_VERSION        = '6.2.0';
    const RECOMMENDED_WP        = '6.7.0';
    const MIN_MEMORY_LIMIT_MB   = 128;
    const RECOMMENDED_MEMORY_MB = 256;

    const OPTION_WELCOME_DISMISSED = 'webcareproscan_welcome_dismissed';

    /**
     * Run full pre-flight compatibility audit.
     *
     * @return array Multi-dimensional audit results with score and granular check vectors.
     */
    public static function check_all(): array {
        $checks = [];

        // 1. PHP Version
        $php_version = PHP_VERSION;
        $php_ok = version_compare($php_version, self::MIN_PHP_VERSION, '>=');
        $php_recommended = version_compare($php_version, self::RECOMMENDED_PHP, '>=');
        $checks['php_version'] = [
            'key'         => 'php_version',
            'title'       => __('PHP Runtime Version', 'webcare-pro-security'),
            'category'    => 'runtime',
            'status'      => $php_ok ? ($php_recommended ? 'pass' : 'warn') : 'fail',
            'is_critical' => true,
            'current'     => $php_version,
            'required'    => '>= ' . self::MIN_PHP_VERSION,
            'recommended' => '>= ' . self::RECOMMENDED_PHP,
            'description' => __('Requires PHP 8.3+ for modern cryptographic primitives, read-only classes, typed constants, and memory optimizations (PHP 8.1 and 8.2 are officially EOL).', 'webcare-pro-security'),
            'remedy'      => __('Upgrade your hosting environment or cPanel/Plesk PHP version selector to PHP 8.3 or PHP 8.4.', 'webcare-pro-security'),
        ];

        // 2. WordPress Version
        global $wp_version;
        $wp_ver = (string) ($wp_version ?? '0.0.0');
        $wp_ok = version_compare($wp_ver, self::MIN_WP_VERSION, '>=');
        $wp_recommended = version_compare($wp_ver, self::RECOMMENDED_WP, '>=');
        $checks['wp_version'] = [
            'key'         => 'wp_version',
            'title'       => __('WordPress Core Version', 'webcare-pro-security'),
            'category'    => 'runtime',
            'status'      => $wp_ok ? ($wp_recommended ? 'pass' : 'warn') : 'fail',
            'is_critical' => true,
            'current'     => $wp_ver,
            'required'    => '>= ' . self::MIN_WP_VERSION,
            'recommended' => '>= ' . self::RECOMMENDED_WP,
            'description' => __('Requires WordPress 7.0+ for native AI Connectors (options-connectors.php), Script Modules API, and modern REST security schema.', 'webcare-pro-security'),
            'remedy'      => __('Update WordPress to the latest stable release (WordPress 7.0+) via Dashboard -> Updates.', 'webcare-pro-security'),
        ];

        // 3. PHP Memory Limit
        $memory_raw = ini_get('memory_limit') ?: '128M';
        $memory_mb = self::parse_memory_to_mb($memory_raw);
        $mem_ok = $memory_mb >= self::MIN_MEMORY_LIMIT_MB;
        $mem_recommended = $memory_mb >= self::RECOMMENDED_MEMORY_MB;
        $checks['memory_limit'] = [
            'key'         => 'memory_limit',
            'title'       => __('PHP Allocated Memory Limit', 'webcare-pro-security'),
            'category'    => 'performance',
            'status'      => $mem_ok ? ($mem_recommended ? 'pass' : 'warn') : 'fail',
            'is_critical' => false,
            'current'     => $memory_raw . ' (' . $memory_mb . ' MB)',
            'required'    => self::MIN_MEMORY_LIMIT_MB . ' MB',
            'recommended' => self::RECOMMENDED_MEMORY_MB . ' MB',
            'description' => __('Large recursive file integrity scanning and Gzip database backups perform optimally with 256MB+ memory.', 'webcare-pro-security'),
            'remedy'      => __('Increase memory_limit in php.ini, .htaccess (php_value memory_limit 256M), or wp-config.php (define("WP_MEMORY_LIMIT", "256M")).', 'webcare-pro-security'),
        ];

        // 4. OpenSSL & AES-256-GCM AEAD Authenticated Encryption
        $openssl_loaded = extension_loaded('openssl');
        $ciphers = $openssl_loaded ? openssl_get_cipher_methods() : [];
        $gcm_supported = in_array('aes-256-gcm', $ciphers, true);
        $crypto_ok = $openssl_loaded && $gcm_supported;
        $checks['crypto_aead'] = [
            'key'         => 'crypto_aead',
            'title'       => __('OpenSSL AES-256-GCM AEAD Encryption', 'webcare-pro-security'),
            'category'    => 'security',
            'status'      => $crypto_ok ? 'pass' : 'fail',
            'is_critical' => true,
            'current'     => $crypto_ok ? __('Available & Verified', 'webcare-pro-security') : ($openssl_loaded ? __('Cipher aes-256-gcm Missing', 'webcare-pro-security') : __('OpenSSL Extension Missing', 'webcare-pro-security')),
            'required'    => __('OpenSSL with aes-256-gcm support', 'webcare-pro-security'),
            'recommended' => __('OpenSSL 1.1.1+ or 3.x with hardware AES acceleration', 'webcare-pro-security'),
            'description' => __('Mandatory for the Secret & Key Vault. Encrypts all credentials, 2FA secrets, and login telemetry using 128-bit integrity tags.', 'webcare-pro-security'),
            'remedy'      => __('Enable the PHP OpenSSL extension in your server PHP configuration (extension=openssl).', 'webcare-pro-security'),
        ];

        // 5. Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
        $csprng_ok = function_exists('random_bytes') && function_exists('random_int');
        $checks['csprng'] = [
            'key'         => 'csprng',
            'title'       => __('CSPRNG Entropy Source (random_bytes)', 'webcare-pro-security'),
            'category'    => 'security',
            'status'      => $csprng_ok ? 'pass' : 'fail',
            'is_critical' => true,
            'current'     => $csprng_ok ? __('Hardware-backed CSPRNG Active', 'webcare-pro-security') : __('Unavailable', 'webcare-pro-security'),
            'required'    => __('System /dev/urandom or CryptGenRandom access', 'webcare-pro-security'),
            'recommended' => __('Kernel-level secure entropy source', 'webcare-pro-security'),
            'description' => __('Generates cryptographically unpredictable 96-bit IVs and 256-bit encryption keys.', 'webcare-pro-security'),
            'remedy'      => __('Ensure your PHP binary was compiled with kernel random device support.', 'webcare-pro-security'),
        ];

        // 6. cURL Extension (Threat Intel & Remote Lookups)
        $curl_ok = extension_loaded('curl');
        $checks['curl'] = [
            'key'         => 'curl',
            'title'       => __('cURL Network Extension', 'webcare-pro-security'),
            'category'    => 'network',
            'status'      => $curl_ok ? 'pass' : 'warn',
            'is_critical' => false,
            'current'     => $curl_ok ? ('cURL ' . (curl_version()['version'] ?? 'Active')) : __('Missing', 'webcare-pro-security'),
            'required'    => __('cURL PHP extension', 'webcare-pro-security'),
            'recommended' => __('cURL with OpenSSL/TLS 1.3', 'webcare-pro-security'),
            'description' => __('Used by WordPress HTTP API to sync threat intelligence feeds and official WordPress.org checksum baselines.', 'webcare-pro-security'),
            'remedy'      => __('Install or enable php-curl on your server.', 'webcare-pro-security'),
        ];

        // 7. ZipArchive Extension (Quarantine & Forensic Packaging)
        $zip_ok = class_exists('\ZipArchive');
        $checks['zip'] = [
            'key'         => 'zip',
            'title'       => __('ZipArchive Extension', 'webcare-pro-security'),
            'category'    => 'filesystem',
            'status'      => $zip_ok ? 'pass' : 'warn',
            'is_critical' => false,
            'current'     => $zip_ok ? __('Available', 'webcare-pro-security') : __('Missing', 'webcare-pro-security'),
            'required'    => __('ZipArchive PHP class', 'webcare-pro-security'),
            'recommended' => __('libzip 1.7+', 'webcare-pro-security'),
            'description' => __('Used for compressed quarantine archives, forensic package downloads, and pre-remediation snapshots.', 'webcare-pro-security'),
            'remedy'      => __('Install php-zip (sudo apt install php-zip / cPanel PHP Extensions).', 'webcare-pro-security'),
        ];

        // 8. Zlib Extension (Gzip Database Vault)
        $zlib_ok = function_exists('gzopen') && function_exists('gzwrite');
        $checks['zlib'] = [
            'key'         => 'zlib',
            'title'       => __('Zlib Compression (gzopen)', 'webcare-pro-security'),
            'category'    => 'filesystem',
            'status'      => $zlib_ok ? 'pass' : 'warn',
            'is_critical' => false,
            'current'     => $zlib_ok ? __('Available', 'webcare-pro-security') : __('Missing', 'webcare-pro-security'),
            'required'    => __('Zlib extension', 'webcare-pro-security'),
            'recommended' => __('Zlib 1.2.11+', 'webcare-pro-security'),
            'description' => __('Used for on-demand streaming Gzip compression in the Database Backup Vault (.sql.gz).', 'webcare-pro-security'),
            'remedy'      => __('Enable the zlib PHP extension in php.ini.', 'webcare-pro-security'),
        ];

        // 9. JSON Extension
        $json_ok = function_exists('json_encode') && function_exists('json_decode');
        $checks['json'] = [
            'key'         => 'json',
            'title'       => __('JSON Extension', 'webcare-pro-security'),
            'category'    => 'runtime',
            'status'      => $json_ok ? 'pass' : 'fail',
            'is_critical' => true,
            'current'     => $json_ok ? __('Active', 'webcare-pro-security') : __('Missing', 'webcare-pro-security'),
            'required'    => __('JSON extension', 'webcare-pro-security'),
            'recommended' => __('Native PHP JSON serializer', 'webcare-pro-security'),
            'description' => __('Mandatory for REST API serialization, JSON-RPC 2.0 MCP agent server, and settings storage.', 'webcare-pro-security'),
            'remedy'      => __('Ensure the json extension is compiled into your PHP runtime.', 'webcare-pro-security'),
        ];

        // 10. Multibyte String (mbstring)
        $mbstring_ok = extension_loaded('mbstring');
        $checks['mbstring'] = [
            'key'         => 'mbstring',
            'title'       => __('Multibyte String (mbstring)', 'webcare-pro-security'),
            'category'    => 'runtime',
            'status'      => $mbstring_ok ? 'pass' : 'warn',
            'is_critical' => false,
            'current'     => $mbstring_ok ? __('Active', 'webcare-pro-security') : __('Missing', 'webcare-pro-security'),
            'required'    => __('mbstring extension', 'webcare-pro-security'),
            'recommended' => __('mbstring enabled with UTF-8 encoding', 'webcare-pro-security'),
            'description' => __('Ensures safe byte-accurate regex pattern evaluation and malware detection across international character sets.', 'webcare-pro-security'),
            'remedy'      => __('Install php-mbstring on your server.', 'webcare-pro-security'),
        ];

        // 11. Sodium Extension (Optional Sealed Key Envelopes)
        $sodium_ok = extension_loaded('sodium');
        $checks['sodium'] = [
            'key'         => 'sodium',
            'title'       => __('Libsodium Sealed Cryptography (Optional)', 'webcare-pro-security'),
            'category'    => 'security',
            'status'      => $sodium_ok ? 'pass' : 'info',
            'is_critical' => false,
            'current'     => $sodium_ok ? __('Available & Verified', 'webcare-pro-security') : __('Not Loaded (Fallback Active)', 'webcare-pro-security'),
            'required'    => __('Optional', 'webcare-pro-security'),
            'recommended' => __('Sodium extension for hardware-sealed key rotation envelopes', 'webcare-pro-security'),
            'description' => __('Provides sealed box key envelopes for zero-downtime key rotation. Built-in fallback uses AES-256-GCM if absent.', 'webcare-pro-security'),
            'remedy'      => __('Enable php-sodium in your PHP extensions selector for enhanced key rotation protection.', 'webcare-pro-security'),
        ];

        // 12. Vault Storage Directory & Write Permissions
        $vault_check = self::test_vault_storage();
        $checks['vault_storage'] = [
            'key'         => 'vault_storage',
            'title'       => __('Vault Storage Filesystem Permissions', 'webcare-pro-security'),
            'category'    => 'filesystem',
            'status'      => $vault_check['ok'] ? 'pass' : 'fail',
            'is_critical' => true,
            'current'     => $vault_check['ok'] ? __('Writable & Verified', 'webcare-pro-security') : $vault_check['message'],
            'required'    => __('Writable uploads/wcp-security-scanner directory', 'webcare-pro-security'),
            'recommended' => __('Directory permissions 0755 or 0775 owned by web server', 'webcare-pro-security'),
            'description' => __('Secure local storage under wp-content/uploads/wcp-security-scanner for quarantine, backups, and diff caches.', 'webcare-pro-security'),
            'remedy'      => __('Ensure wp-content/uploads is writable by your web server user (e.g., www-data, chown -R www-data:www-data).', 'webcare-pro-security'),
        ];

        // 13. MySQL Database Capability & Schema Permissions
        $db_check = self::test_database_permissions();
        $checks['database'] = [
            'key'         => 'database',
            'title'       => __('Database Schema & Table Privileges', 'webcare-pro-security'),
            'category'    => 'database',
            'status'      => $db_check['ok'] ? 'pass' : 'fail',
            'is_critical' => true,
            'current'     => $db_check['ok'] ? __('All Privileges Verified', 'webcare-pro-security') : $db_check['message'],
            'required'    => __('CREATE TABLE, ALTER TABLE, SELECT, INSERT, UPDATE, DELETE', 'webcare-pro-security'),
            'recommended' => __('MySQL 5.7+ or MariaDB 10.3+ with InnoDB engine', 'webcare-pro-security'),
            'description' => __('Required to manage custom tables for file audits, threat issues, quarantine registry, and login history.', 'webcare-pro-security'),
            'remedy'      => __('Grant CREATE and ALTER privileges to your WordPress database user.', 'webcare-pro-security'),
        ];

        // 14. SSL / HTTPS Status
        $ssl_ok = is_ssl();
        $checks['ssl'] = [
            'key'         => 'ssl',
            'title'       => __('HTTPS / Transport Layer Security (TLS)', 'webcare-pro-security'),
            'category'    => 'security',
            'status'      => $ssl_ok ? 'pass' : 'warn',
            'is_critical' => false,
            'current'     => $ssl_ok ? __('HTTPS Active', 'webcare-pro-security') : __('Insecure HTTP Detected', 'webcare-pro-security'),
            'required'    => __('Recommended for admin security', 'webcare-pro-security'),
            'recommended' => __('TLS 1.2 or TLS 1.3 certificate', 'webcare-pro-security'),
            'description' => __('Protects administrative session tokens, 2FA QR secrets, and REST API communication from network eavesdropping.', 'webcare-pro-security'),
            'remedy'      => __('Install an SSL certificate (e.g. free Let\'s Encrypt) and enforce HTTPS.', 'webcare-pro-security'),
        ];

        // Summary Calculations
        $total_checks = count($checks);
        $passed = 0;
        $warnings = 0;
        $failures = 0;
        $critical_failures = 0;

        foreach ($checks as $item) {
            if ($item['status'] === 'pass') {
                $passed++;
            } elseif ($item['status'] === 'warn') {
                $warnings++;
            } elseif ($item['status'] === 'fail') {
                $failures++;
                if (!empty($item['is_critical'])) {
                    $critical_failures++;
                }
            }
        }

        $score = round(($passed / $total_checks) * 100);
        $is_compatible = ($critical_failures === 0);

        return [
            'is_compatible'      => $is_compatible,
            'readiness_score'    => $score,
            'summary'            => [
                'total'             => $total_checks,
                'passed'            => $passed,
                'warnings'          => $warnings,
                'failures'          => $failures,
                'critical_failures' => $critical_failures,
            ],
            'checks'             => $checks,
            'welcome_dismissed'  => (bool) get_option(self::OPTION_WELCOME_DISMISSED, false),
            'checked_at'         => current_time('mysql'),
        ];
    }

    /**
     * Parse memory limit string into integer megabytes.
     */
    private static function parse_memory_to_mb(string $val): int {
        $val = trim($val);
        if ($val === '-1') {
            return 99999; // Unlimited
        }
        $last = strtolower(substr($val, -1));
        $num = (int) substr($val, 0, -1);
        switch ($last) {
            case 'g':
                return $num * 1024;
            case 'm':
                return $num;
            case 'k':
                return (int) round($num / 1024);
            default:
                return (int) round(((int) $val) / (1024 * 1024));
        }
    }

    /**
     * Test upload vault directory creation and file write/read/delete.
     */
    private static function test_vault_storage(): array {
        $upload_dir = wp_upload_dir();
        if (!empty($upload_dir['error'])) {
            return [
                'ok'      => false,
                /* translators: %s: error message */
                'message' => sprintf(__('wp_upload_dir error: %s', 'webcare-pro-security'), $upload_dir['error']),
            ];
        }

        $base = untrailingslashit($upload_dir['basedir']);
        if (!is_dir($base) || !wp_is_writable($base)) {
            return [
                'ok'      => false,
                'message' => sprintf(
                    /* translators: %s: directory path */
                    __('Directory %s is not writable.', 'webcare-pro-security'),
                    $base
                ),
            ];
        }

        $vault_dir = $base . '/wcp-security-scanner';
        if (!is_dir($vault_dir)) {
            if (!wp_mkdir_p($vault_dir)) {
                return [
                    'ok'      => false,
                    /* translators: %s: directory path */
                    'message' => sprintf(__('Unable to create vault directory: %s', 'webcare-pro-security'), $vault_dir),
                ];
            }
        }

        // Test canary write
        $canary_file = $vault_dir . '/.wcp_canary_' . wp_generate_password(8, false) . '.tmp';
        $written = @file_put_contents($canary_file, 'wcp_canary_test');
        if ($written === false) {
            return [
                'ok'      => false,
                'message' => __('Unable to write temporary test file inside vault directory.', 'webcare-pro-security'),
            ];
        }

        if (file_exists($canary_file)) {
            wp_delete_file($canary_file);
        }

        return [
            'ok'      => true,
            'message' => __('Vault storage verified writable.', 'webcare-pro-security'),
        ];
    }

    /**
     * Test database capabilities.
     */
    private static function test_database_permissions(): array {
        global $wpdb;

        // Verify basic table query
        $test_table = $wpdb->prefix . 'webcareproscan_readiness_test_' . time();
        $charset_collate = $wpdb->get_charset_collate();

        $create_sql = "CREATE TABLE IF NOT EXISTS `{$test_table}` (`id` int(11) NOT NULL AUTO_INCREMENT, `val` varchar(64) DEFAULT NULL, PRIMARY KEY (`id`)) {$charset_collate};";
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $created = $wpdb->query($create_sql);

        if ($created === false) {
            return [
                'ok'      => false,
                /* translators: %s: database error description */
                'message' => sprintf(__('Database user lacks CREATE TABLE privilege: %s', 'webcare-pro-security'), $wpdb->last_error),
            ];
        }

        // Cleanup test table
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS `{$test_table}`;");

        return [
            'ok'      => true,
            'message' => __('Database schema privileges verified.', 'webcare-pro-security'),
        ];
    }

    /**
     * Run activation-time compatibility gate.
     * If critical requirements fail, deactivates the plugin and halts with a styled error screen.
     */
    public static function run_activation_check(): void {
        $report = self::check_all();

        if ($report['is_compatible']) {
            return;
        }

        // Critical failure: gather details
        $critical_errors = [];
        foreach ($report['checks'] as $check) {
            if ($check['status'] === 'fail' && !empty($check['is_critical'])) {
                $critical_errors[] = $check;
            }
        }

        // Deactivate plugin cleanly
        deactivate_plugins(plugin_basename(WEBCAREPROSCAN_FILE));

        // Format aesthetic failure screen
        $errors_html = '';
        foreach ($critical_errors as $err) {
            $errors_html .= '<li style="margin-bottom: 14px; padding: 12px 14px; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px;">';
            $errors_html .= '<strong style="color: #ef4444; font-size: 14px;">❌ ' . esc_html($err['title']) . '</strong><br>';
            $errors_html .= '<span style="color: #cbd5e1; font-size: 13px;">' . esc_html($err['description']) . '</span><br>';
            $errors_html .= '<span style="color: #94a3b8; font-size: 12px;"><strong>Current:</strong> ' . esc_html($err['current']) . ' | <strong>Required:</strong> ' . esc_html($err['required']) . '</span><br>';
            $errors_html .= '<span style="color: #38bdf8; font-size: 12px;"><strong>Remedy:</strong> ' . esc_html($err['remedy']) . '</span>';
            $errors_html .= '</li>';
        }

        $html = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; max-width: 680px; margin: 40px auto; background: #0b1329; border: 1px solid #1e293b; border-radius: 16px; padding: 32px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); color: #f8fafc;">
            <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 20px; border-bottom: 1px solid #1e293b; padding-bottom: 16px;">
                <div style="width: 44px; height: 44px; border-radius: 10px; background: linear-gradient(135deg, #0284c7, #10b581); display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: bold; color: white;">W</div>
                <div>
                    <h2 style="margin: 0; font-size: 20px; color: #f1f5f9; font-weight: 700;">WebCare Pro Security — Activation Pre-Check</h2>
                    <p style="margin: 2px 0 0; font-size: 12px; color: #94a3b8;">System Readiness & Environment Verification Gate</p>
                </div>
            </div>
            <p style="color: #e2e8f0; font-size: 14px; line-height: 1.6; margin-bottom: 18px;">
                Plugin activation has been paused. Your server environment does not meet the minimum prerequisites required for authenticated encryption or safe malware scanning:
            </p>
            <ul style="list-style: none; padding: 0; margin: 0 0 24px 0;">
                ' . $errors_html . '
            </ul>
            <div style="display: flex; align-items: center; justify-content: space-between; pt: 16px; border-top: 1px solid #1e293b;">
                <span style="font-size: 12px; color: #64748b;">Authored by Mir Alamin (WebCare Pro)</span>
                <a href="' . esc_url(admin_url('plugins.php')) . '" style="display: inline-block; background: #0284c7; color: white; text-decoration: none; padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600;">Back to Plugins</a>
            </div>
        </div>';

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        wp_die($html, esc_html__('WebCare Pro Security — Compatibility Requirement Unmet', 'webcare-pro-security'), [
            'response'  => 500,
            'back_link' => true,
        ]);
    }

    /**
     * Dismiss first-time welcome dialog.
     */
    public static function dismiss_welcome(): bool {
        return (bool) update_option(self::OPTION_WELCOME_DISMISSED, 1, false);
    }

    /**
     * Check if first-time welcome dialog is dismissed.
     */
    public static function is_welcome_dismissed(): bool {
        return (bool) get_option(self::OPTION_WELCOME_DISMISSED, false);
    }
}
