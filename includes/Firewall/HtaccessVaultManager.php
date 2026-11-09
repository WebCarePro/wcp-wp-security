<?php
/**
 * HtaccessVaultManager
 *
 * 5-Version Rolling Dual-Medium Vault & Break-Glass Recovery Engine for .htaccess Armor.
 * Stores encrypted snapshots both on disk (.vault/) and mirrored in the database (wp_options).
 * Provides atomic restoration, read-only chmod locks, and automated full-page cache purging.
 *
 * @package WebCareProScanner\Firewall
 * @author  Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer
 */

namespace WebCareProScanner\Firewall;

use WebCareProScanner\Security\SecretVault;
use WebCareProScanner\Filesystem\PathValidator;
use WebCareProScanner\Notifications\NotificationDispatcher;
use WebCareProScanner\System\WcpActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

final class HtaccessVaultManager {

    public const OPTION_DB_MIRROR     = 'webcareproscan_htaccess_vault_snapshots';
    public const OPTION_READONLY_LOCK = 'webcareproscan_htaccess_readonly_lock';
    public const VAULT_SUBDIR         = 'wcp-security-scanner/.vault';
    public const EMERGENCY_FILE_NAME  = '.htaccess.emergency-clean';
    public const MAX_SNAPSHOTS        = 5;
    public const HEADER_GUARD         = "<?php http_response_code(403); exit('WCP Security: Direct access forbidden.'); __halt_compiler(); ?>\n";

    /**
     * Get the absolute path to the hardened vault directory.
     *
     * @return string
     */
    public static function get_vault_dir(): string {
        $upload_dir = wp_upload_dir();
        $vault_dir  = untrailingslashit($upload_dir['basedir']) . '/' . self::VAULT_SUBDIR;
        self::ensure_vault_secured($vault_dir);
        return $vault_dir;
    }

    /**
     * Safely set filesystem permissions using WP_Filesystem with direct fallback.
     *
     * @param string $path Target file path.
     * @param int    $mode Octal permission mode.
     * @return bool
     */
    public static function safe_chmod(string $path, int $mode): bool {
        global $wp_filesystem;
        if ($wp_filesystem instanceof \WP_Filesystem_Direct) {
            return (bool) $wp_filesystem->chmod($path, $mode);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Direct chmod fallback for vault isolation and permission hardening.
        return (bool) @chmod($path, $mode);
    }

    /**
     * Ensure the vault directory exists and is heavily locked down against public web execution.
     *
     * @param string $vault_dir Absolute directory path.
     * @return void
     */
    public static function ensure_vault_secured(string $vault_dir): void {
        if (!is_dir($vault_dir)) {
            wp_mkdir_p($vault_dir);
        }

        // 1. Lock with root .htaccess (Apache / LiteSpeed deny rules)
        $htaccess = $vault_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules  = "# Block all public web access to WCP security vault\n";
            $rules .= "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n";
            $rules .= "<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
            $rules .= "<FilesMatch \".*\">\n";
            $rules .= "    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n";
            $rules .= "    <IfModule !mod_authz_core.c>\n        Order deny,allow\n        Deny from all\n    </IfModule>\n";
            $rules .= "</FilesMatch>\n";
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($htaccess, $rules);
            self::safe_chmod($htaccess, 0644);
        }

        // 2. Lock with index.php
        $index = $vault_dir . '/index.php';
        if (!file_exists($index)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WCP Security: Direct access forbidden.');\n");
            self::safe_chmod($index, 0644);
        }
    }

    /**
     * Snapshot the current root .htaccess file if it passes semantic verification.
     *
     * @param string $reason Context or trigger description (e.g., 'manual', 'cron', 'rewrite_rules_flush').
     * @return array Result array with status, message, and snapshot details.
     */
    public static function snapshot_current_if_clean(string $reason = 'auto'): array {
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path)) {
            return [
                'success' => false,
                'message' => __('No .htaccess file present in root directory.', 'webcare-pro-security'),
            ];
        }

        $content = (string) @file_get_contents($htaccess_path);
        if (trim($content) === '') {
            return [
                'success' => false,
                'message' => __('.htaccess file is empty; snapshot skipped.', 'webcare-pro-security'),
            ];
        }

        // 1. Run semantic analysis to verify clean status
        $analysis = HtaccessShield::analyze_htaccess_content($content);
        if ($analysis['is_hostile']) {
            return [
                'success'   => false,
                'message'   => __('Cannot snapshot .htaccess: Hostile redirect or malicious directives detected.', 'webcare-pro-security'),
                'score'     => $analysis['score'],
                'severity'  => $analysis['severity'],
                'findings'  => $analysis['findings'],
            ];
        }

        $hash = hash('sha256', $content);
        $size = strlen($content);
        $now  = time();
        $gmt  = gmdate('Y-m-d H:i:s');

        // 2. Check if latest snapshot #1 has identical hash (idempotent)
        $existing = self::list_snapshots();
        if (!empty($existing) && isset($existing[0]['sha256']) && hash_equals($existing[0]['sha256'], $hash)) {
            return [
                'success'   => true,
                'message'   => __('Current .htaccess is identical to latest vault snapshot #1. Snapshot skipped.', 'webcare-pro-security'),
                'unchanged' => true,
                'sha256'    => $hash,
                'version'   => 1,
            ];
        }

        $vault_dir = self::get_vault_dir();

        // 3. Rolling shift on disk: 4->5, 3->4, 2->3, 1->2
        for ($i = self::MAX_SNAPSHOTS - 1; $i >= 1; $i--) {
            $from = $vault_dir . '/.htaccess.vault.' . $i . '.php';
            $to   = $vault_dir . '/.htaccess.vault.' . ($i + 1) . '.php';
            if (file_exists($from)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
                @rename($from, $to);
            }
        }

        // 4. Create snapshot #1 payload
        $snapshot_data = [
            'version'         => 1,
            'created_at'      => $now,
            'created_at_gmt'  => $gmt,
            'sha256'          => $hash,
            'size'            => $size,
            'reason'          => sanitize_text_field($reason),
            'content'         => $content,
        ];

        $json_payload      = (string) wp_json_encode($snapshot_data);
        $encrypted_payload = SecretVault::encrypt($json_payload);
        $disk_file_content = self::HEADER_GUARD . $encrypted_payload;
        $dest_file         = $vault_dir . '/.htaccess.vault.1.php';

        $written = PathValidator::safe_atomic_write($dest_file, $disk_file_content, $vault_dir, 0600);
        if (!$written) {
            // Fallback direct write
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($dest_file, $disk_file_content);
            self::safe_chmod($dest_file, 0600);
        }

        // 5. Update Emergency Clean Copy (used by Preload Micro-WAF watchdog with zero WP bootstrap overhead)
        $emergency_file = $vault_dir . '/' . self::EMERGENCY_FILE_NAME;
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents($emergency_file, $content, LOCK_EX);
        self::safe_chmod($emergency_file, 0600);

        // 6. Update Encrypted Database Fallback Mirror
        $db_snapshots = self::get_db_snapshots();
        array_unshift($db_snapshots, [
            'version'        => 1,
            'created_at'     => $now,
            'created_at_gmt' => $gmt,
            'sha256'         => $hash,
            'size'           => $size,
            'reason'         => sanitize_text_field($reason),
            'content_enc'    => SecretVault::encrypt($content),
        ]);

        if (count($db_snapshots) > self::MAX_SNAPSHOTS) {
            $db_snapshots = array_slice($db_snapshots, 0, self::MAX_SNAPSHOTS);
        }

        // Re-index version numbers in DB mirror
        foreach ($db_snapshots as $idx => &$snap) {
            $snap['version'] = $idx + 1;
        }
        unset($snap);

        $db_raw = (string) wp_json_encode($db_snapshots);
        update_option(self::OPTION_DB_MIRROR, SecretVault::encrypt($db_raw), false);

        if (class_exists('\\WebCareProScanner\\System\\WcpActivityLogger')) {
            WcpActivityLogger::log(
                'htaccess_vault_snapshot_saved',
                'firewall',
                'info',
                [
                    'version' => 1,
                    'sha256'  => substr($hash, 0, 16) . '...',
                    'reason'  => $reason,
                    'size'    => $size,
                ]
            );
        }

        return [
            'success'        => true,
            'message'        => __('Verified-clean .htaccess successfully archived into Vault Snapshot #1.', 'webcare-pro-security'),
            'sha256'         => $hash,
            'size'           => $size,
            'version'        => 1,
            'created_at_gmt' => $gmt,
        ];
    }

    /**
     * List all rolling snapshots in the vault (reading disk first, falling back to DB mirror).
     *
     * @return array List of snapshot summaries.
     */
    public static function list_snapshots(): array {
        $vault_dir = self::get_vault_dir();
        $snapshots = [];

        for ($i = 1; $i <= self::MAX_SNAPSHOTS; $i++) {
            $file = $vault_dir . '/.htaccess.vault.' . $i . '.php';
            if (file_exists($file)) {
                $raw = (string) @file_get_contents($file);
                if (strpos($raw, '__halt_compiler(); ?>') !== false) {
                    $parts = explode('__halt_compiler(); ?>', $raw, 2);
                    $enc   = trim($parts[1] ?? '');
                    if (!empty($enc)) {
                        $dec = SecretVault::decrypt($enc);
                        $data = json_decode($dec, true);
                        if (is_array($data) && !empty($data['sha256'])) {
                            $snapshots[] = [
                                'version'        => $i,
                                'created_at'     => $data['created_at'] ?? 0,
                                'created_at_gmt' => $data['created_at_gmt'] ?? '',
                                'sha256'         => $data['sha256'],
                                'size'           => $data['size'] ?? 0,
                                'reason'         => $data['reason'] ?? 'auto',
                                'source'         => 'disk',
                            ];
                            continue;
                        }
                    }
                }
            }
        }

        // If disk snapshots are missing or incomplete, merge or fall back to DB mirror
        if (empty($snapshots)) {
            $db_list = self::get_db_snapshots();
            foreach ($db_list as $idx => $db_snap) {
                $snapshots[] = [
                    'version'        => $db_snap['version'] ?? ($idx + 1),
                    'created_at'     => $db_snap['created_at'] ?? 0,
                    'created_at_gmt' => $db_snap['created_at_gmt'] ?? '',
                    'sha256'         => $db_snap['sha256'] ?? '',
                    'size'           => $db_snap['size'] ?? 0,
                    'reason'         => $db_snap['reason'] ?? 'auto',
                    'source'         => 'database_mirror',
                ];
            }
        }

        return $snapshots;
    }

    /**
     * Restore .htaccess from the specified vault snapshot.
     *
     * @param int $version Snapshot version (1 to 5). Default is 1 (most recent clean).
     * @return array Result array with status and message.
     */
    public static function restore_snapshot(int $version = 1): array {
        if ($version < 1 || $version > self::MAX_SNAPSHOTS) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %d: maximum snapshot version */
                    __('Invalid vault version requested. Must be between 1 and %d.', 'webcare-pro-security'),
                    self::MAX_SNAPSHOTS
                ),
            ];
        }

        $vault_dir     = self::get_vault_dir();
        $target_file   = $vault_dir . '/.htaccess.vault.' . $version . '.php';
        $clean_content = '';
        $source        = 'disk';

        // 1. Try reading from disk vault
        if (file_exists($target_file)) {
            $raw = (string) @file_get_contents($target_file);
            if (strpos($raw, '__halt_compiler(); ?>') !== false) {
                $parts = explode('__halt_compiler(); ?>', $raw, 2);
                $enc   = trim($parts[1] ?? '');
                if (!empty($enc)) {
                    $dec  = SecretVault::decrypt($enc);
                    $data = json_decode($dec, true);
                    if (is_array($data) && !empty($data['content'])) {
                        $clean_content = $data['content'];
                    }
                }
            }
        }

        // 2. If disk is missing or corrupted, fall back to encrypted DB mirror
        if ($clean_content === '') {
            $db_list = self::get_db_snapshots();
            foreach ($db_list as $db_snap) {
                if (($db_snap['version'] ?? 0) === $version && !empty($db_snap['content_enc'])) {
                    $clean_content = SecretVault::decrypt($db_snap['content_enc']);
                    $source        = 'database_mirror';
                    break;
                }
            }
        }

        // 3. Fallback to emergency clean file if disk/db snapshot unavailable
        if ($clean_content === '') {
            $emergency_file = $vault_dir . '/' . self::EMERGENCY_FILE_NAME;
            if (file_exists($emergency_file)) {
                $clean_content = (string) @file_get_contents($emergency_file);
                $source        = 'emergency_clean_file';
            }
        }

        if (trim($clean_content) === '') {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %d: snapshot version number */
                    __('Vault Snapshot #%d could not be found or decrypted.', 'webcare-pro-security'),
                    $version
                ),
            ];
        }

        // 4. Fail-safe semantic scan on target content to ensure restored version is 100% clean
        $check = HtaccessShield::analyze_htaccess_content($clean_content);
        if ($check['is_hostile']) {
            return [
                'success' => false,
                'message' => __('Refusing restore: Snapshot payload contains hostile directives or cloaking patterns.', 'webcare-pro-security'),
                'score'   => $check['score'],
            ];
        }

        // 5. Restore root .htaccess atomically
        $htaccess_path = ABSPATH . '.htaccess';

        // Unlock read-only mode if currently active
        if (file_exists($htaccess_path) && !wp_is_writable($htaccess_path)) {
            self::safe_chmod($htaccess_path, 0644);
        }

        $written = PathValidator::safe_atomic_write($htaccess_path, $clean_content, ABSPATH, 0644);
        if (!$written) {
            // Direct write fallback
            // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Direct write to root .htaccess to restore clean permalinks and server armor from vault.
            $res = @file_put_contents($htaccess_path, $clean_content, LOCK_EX);
            if ($res === false) {
                return [
                    'success' => false,
                    'message' => __('Failed to write restored content to root .htaccess. Please check filesystem permissions.', 'webcare-pro-security'),
                ];
            }
        }

        // Re-apply read-only lock if enabled
        if (get_option(self::OPTION_READONLY_LOCK, false)) {
            self::safe_chmod($htaccess_path, 0444);
        }

        // 6. Purge all full-page and opcode caches
        self::purge_all_site_caches();

        // 7. Recompile Micro-WAF so preloader recognizes updated .htaccess mtime
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            try {
                MicroWafCompiler::compile();
            } catch (\Throwable $e) {
                // Fail safely
            }
        }

        $restored_hash = hash('sha256', $clean_content);

        // 8. Log activity
        if (class_exists('\\WebCareProScanner\\System\\WcpActivityLogger')) {
            WcpActivityLogger::log(
                'htaccess_restored_from_vault',
                'firewall',
                'info',
                [
                    'version' => $version,
                    'source'  => $source,
                    'sha256'  => substr($restored_hash, 0, 16) . '...',
                ]
            );
        }

        // 9. Dispatch notification
        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            NotificationDispatcher::trigger('redirect_hack_auto_healed', [
                'severity' => 'info',
                'message'  => sprintf(
                    /* translators: 1: snapshot version, 2: storage source */
                    __('.htaccess was successfully restored from Vault Snapshot #%1$d (%2$s) and site caches were purged.', 'webcare-pro-security'),
                    $version,
                    $source
                ),
                'details'  => [
                    'Vault Version'  => $version,
                    'Source Medium'  => $source,
                    'SHA-256'        => $restored_hash,
                    'Target File'    => $htaccess_path,
                ],
            ]);
        }

        return [
            'success' => true,
            'message' => sprintf(
                /* translators: 1: snapshot version, 2: storage source */
                __('Root .htaccess successfully restored from Vault Snapshot #%1$d (%2$s). All site caches invalidated.', 'webcare-pro-security'),
                $version,
                $source
            ),
            'version' => $version,
            'source'  => $source,
            'sha256'  => $restored_hash,
        ];
    }

    /**
     * Purge all full-page, object, and edge caches across major WordPress caching plugins.
     * Also sets the 24-hour transient to emit 'Clear-Site-Data: "cache"' on front-end responses.
     *
     * @return void
     */
    public static function purge_all_site_caches(): void {
        // 1. WP Rocket
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
        }

        // 2. LiteSpeed Cache
        if (has_action('litespeed_purge_all')) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Triggering LiteSpeed Cache plugin purge hook.
            do_action('litespeed_purge_all');
        }

        // 3. W3 Total Cache
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all();
        }

        // 4. WP Super Cache
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
        }

        // 5. SiteGround Optimizer (SG CachePress)
        if (function_exists('sg_cachepress_purge_cache')) {
            sg_cachepress_purge_cache();
        }

        // 6. WP Fastest Cache
        if (isset($GLOBALS['wp_fastest_cache']) && method_exists($GLOBALS['wp_fastest_cache'], 'deleteCache')) {
            $GLOBALS['wp_fastest_cache']->deleteCache(true);
        }

        // 7. Autoptimize
        if (class_exists('\\autoptimizeCache') && method_exists('\\autoptimizeCache', 'clearall')) {
            \autoptimizeCache::clearall();
        }

        // 8. Core WordPress Object Cache
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }

        // 9. Reset OPcache for .htaccess-adjacent PHP files if available
        if (function_exists('opcache_reset')) {
            @opcache_reset();
        }

        // 10. Emit Clear-Site-Data: "cache" for 24 hours on guest front-end responses
        set_transient('webcareproscan_emit_clear_site_data', time(), DAY_IN_SECONDS);
    }

    /**
     * Toggle read-only 0444 lock on root .htaccess.
     *
     * @param bool $locked True to apply 0444, false to restore 0644.
     * @return bool True on success.
     */
    public static function set_readonly_lock(bool $locked): bool {
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path)) {
            return false;
        }

        $perms = $locked ? 0444 : 0644;
        $res   = self::safe_chmod($htaccess_path, $perms);
        update_option(self::OPTION_READONLY_LOCK, (bool) $locked);
        return $res;
    }

    /**
     * Check if read-only lock is currently active.
     *
     * @return bool
     */
    public static function is_readonly_locked(): bool {
        return (bool) get_option(self::OPTION_READONLY_LOCK, false);
    }

    /**
     * Retrieve decrypted snapshots list from the database mirror.
     *
     * @return array
     */
    private static function get_db_snapshots(): array {
        $raw = get_option(self::OPTION_DB_MIRROR, '');
        if (empty($raw) || !is_string($raw)) {
            return [];
        }

        $dec = SecretVault::decrypt($raw);
        if (empty($dec)) {
            return [];
        }

        $list = json_decode($dec, true);
        return is_array($list) ? $list : [];
    }

    /**
     * Register WP-CLI break-glass command.
     *
     * @return void
     */
    public static function register_cli(): void {
        if (defined('WP_CLI') && WP_CLI && class_exists('\\WP_CLI')) {
            \WP_CLI::add_command('wcp htaccess', HtaccessCliCommand::class);
        }
    }
}

/**
 * WP-CLI Break-Glass Command Controller for .htaccess Armor.
 */
class HtaccessCliCommand {

    /**
     * Inspect current .htaccess for redirects, cloaking, and suspicious directives.
     *
     * ## EXAMPLES
     *
     *     wp wcp htaccess status
     *
     * @param array $args Positional arguments.
     * @param array $assoc_args Associative arguments.
     */
    public function status($args, $assoc_args) {
        $htaccess = ABSPATH . '.htaccess';
        if (!file_exists($htaccess)) {
            \WP_CLI::error('Root .htaccess does not exist.');
            return;
        }

        $content  = (string) @file_get_contents($htaccess);
        $analysis = HtaccessShield::analyze_htaccess_content($content);

        \WP_CLI::line('--------------------------------------------------');
        \WP_CLI::line('WCP .htaccess Armor Status & Semantic Classification');
        \WP_CLI::line('--------------------------------------------------');
        \WP_CLI::line('Threat Score: ' . $analysis['score'] . '/100');
        \WP_CLI::line('Severity:     ' . strtoupper($analysis['severity']));
        \WP_CLI::line('Hostile Flag: ' . ($analysis['is_hostile'] ? 'YES (TAMPERED)' : 'NO (CLEAN)'));
        \WP_CLI::line('Lines Scanned:' . $analysis['scanned_lines']);
        \WP_CLI::line('Read-Only Lock:' . (HtaccessVaultManager::is_readonly_locked() ? 'ENABLED (0444)' : 'DISABLED (0644)'));

        if (!empty($analysis['findings'])) {
            \WP_CLI::line('');
            \WP_CLI::warning('Detected Issues:');
            $rows = [];
            foreach ($analysis['findings'] as $f) {
                $rows[] = [
                    'Line'     => $f['line'] ?? '-',
                    'Severity' => strtoupper($f['severity'] ?? 'high'),
                    'Type'     => $f['type'] ?? '',
                    'Evidence' => substr($f['evidence'] ?? '', 0, 60),
                ];
            }
            \WP_CLI\Utils\format_items('table', $rows, ['Line', 'Severity', 'Type', 'Evidence']);
        } else {
            \WP_CLI::success('No hostile directives found. Root .htaccess is clean.');
        }
    }

    /**
     * List all rolling snapshots in the vault.
     *
     * ## EXAMPLES
     *
     *     wp wcp htaccess vault
     *
     * @param array $args Positional arguments.
     * @param array $assoc_args Associative arguments.
     */
    public function vault($args, $assoc_args) {
        $snapshots = HtaccessVaultManager::list_snapshots();
        if (empty($snapshots)) {
            \WP_CLI::warning('No snapshots found in vault.');
            return;
        }

        $rows = [];
        foreach ($snapshots as $snap) {
            $rows[] = [
                'Version'   => '#' . $snap['version'],
                'Date GMT'  => $snap['created_at_gmt'],
                'SHA-256'   => substr($snap['sha256'], 0, 16) . '...',
                'Size'      => $snap['size'] . ' B',
                'Reason'    => $snap['reason'],
                'Source'    => $snap['source'],
            ];
        }

        \WP_CLI\Utils\format_items('table', $rows, ['Version', 'Date GMT', 'SHA-256', 'Size', 'Reason', 'Source']);
    }

    /**
     * Restore .htaccess from the vault and flush all site caches.
     *
     * ## OPTIONS
     *
     * [--version=<version>]
     * : Snapshot version to restore (1 to 5). Default is 1 (most recent clean).
     *
     * ## EXAMPLES
     *
     *     wp wcp htaccess restore
     *     wp wcp htaccess restore --version=2
     *
     * @param array $args Positional arguments.
     * @param array $assoc_args Associative arguments.
     */
    public function restore($args, $assoc_args) {
        $version = isset($assoc_args['version']) ? (int) $assoc_args['version'] : 1;
        \WP_CLI::line("Attempting restoration of .htaccess from Vault Snapshot #{$version}...");

        $res = HtaccessVaultManager::restore_snapshot($version);
        if ($res['success']) {
            \WP_CLI::success($res['message']);
            \WP_CLI::line('Restored SHA-256: ' . $res['sha256']);
        } else {
            \WP_CLI::error($res['message']);
        }
    }
}
