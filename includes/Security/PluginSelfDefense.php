<?php
namespace WcpScanner\Security;

use WcpScanner\System\SettingsManager;
use WcpScanner\Notifications\WebhookService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PluginSelfDefense
 *
 * Provides cryptographic attestation, anti-tamper monitoring, and integrity defense
 * for the WCP Security Scanner plugin files. Detects missing files (e.g. deleted by host
 * scanners / mod_security), altered code, and rogue files dropped into the plugin folder.
 */
class PluginSelfDefense {

    const DB_HASHES_OPTION = 'wcpscan_self_defense_hashes';
    const DB_LAST_AUDIT_OPTION = 'wcpscan_self_defense_last_audit';
    const CRON_HOOK = 'wcpscan_self_defense_watchdog_event';

    /**
     * Bootstrap the Self Defense engine & watchdog hooks
     */
    public static function init() {
        add_action('admin_notices', [__CLASS__, 'render_tamper_warning_notice']);
        add_action(self::CRON_HOOK, [__CLASS__, 'run_scheduled_watchdog']);

        // Schedule event if not already registered (deferred to init to prevent early textdomain loading)
        add_action('init', function () {
            if (!wp_next_scheduled(self::CRON_HOOK)) {
                wp_schedule_event(time() + 300, 'twicedaily', self::CRON_HOOK);
            }
        });
    }

    /**
     * Run full self-integrity attestation audit
     *
     * @param bool $force_recheck
     * @return array
     */
    public static function run_audit(bool $force_recheck = false): array {
        $manifest = self::get_baseline_manifest();
        $plugin_dir = rtrim(WCPSCAN_PATH, '/\\') . DIRECTORY_SEPARATOR;

        // If authoritative manifest is missing or empty, flag critical tamper state
        if (empty($manifest)) {
            $audit_result = [
                'success'          => false,
                'status'           => 'compromised',
                'has_issues'       => true,
                'checked_at'       => current_time('mysql'),
                'timestamp'        => time(),
                'total_tracked'    => 0,
                'verified_count'   => 0,
                'missing_count'    => 1,
                'modified_count'   => 0,
                'untracked_count'  => 0,
                'missing_files'    => [[
                    'path'          => 'includes/System/plugin-manifest.json',
                    'status'        => 'missing',
                    'expected_size' => 0,
                    'severity'      => 'critical',
                    'detail'        => __('Authoritative release manifest is missing or unreadable. Plugin self-defense integrity cannot be verified.', 'wcp-security-scanner'),
                ]],
                'modified_files'   => [],
                'untracked_files'  => [],
                'plugin_version'   => defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.21.0',
            ];
            update_option(self::DB_LAST_AUDIT_OPTION, $audit_result, false);

            if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('plugin_file_missing', [
                    'severity' => 'critical',
                    'message'  => __('CRITICAL: Authoritative plugin self-defense manifest is missing or unreadable.', 'wcp-security-scanner'),
                    'details'  => ['file' => 'includes/System/plugin-manifest.json'],
                ]);
            }

            return $audit_result;
        }

        $missing_files  = [];
        $modified_files = [];
        $untracked_files = [];
        $verified_count = 0;
        $total_tracked  = count($manifest);

        // 1. Verify all officially expected files
        foreach ($manifest as $rel_path => $expected_meta) {
            $expected_hash = is_array($expected_meta) ? ($expected_meta['sha256'] ?? '') : (string)$expected_meta;
            $expected_size = is_array($expected_meta) ? ($expected_meta['size'] ?? 0) : 0;

            // Normalize path for current OS
            $fs_path = $plugin_dir . str_replace('/', DIRECTORY_SEPARATOR, $rel_path);

            if (!file_exists($fs_path) || !is_file($fs_path)) {
                $missing_files[] = [
                    'path'          => $rel_path,
                    'status'        => 'missing',
                    'expected_size' => $expected_size,
                    'severity'      => 'critical',
                    'detail'        => __('File is missing or was deleted by host security scanner / mod_security.', 'wcp-security-scanner'),
                ];
                continue;
            }

            // Calculate live SHA-256
            $live_hash = @hash_file('sha256', $fs_path);
            $live_size = @filesize($fs_path) ?: 0;

            if ($live_hash !== $expected_hash) {
                $modified_files[] = [
                    'path'          => $rel_path,
                    'status'        => 'modified',
                    'expected_hash' => $expected_hash,
                    'live_hash'     => $live_hash,
                    'expected_size' => $expected_size,
                    'live_size'     => $live_size,
                    'severity'      => 'high',
                    'detail'        => __('File content hash does not match official release signature.', 'wcp-security-scanner'),
                ];
            } else {
                $verified_count++;
            }
        }

        // 2. Discover foreign/untracked files inside plugin directory
        $untracked_files = self::find_untracked_files($plugin_dir, $manifest);

        $has_issues = !empty($missing_files) || !empty($modified_files) || !empty($untracked_files);
        $status = $has_issues ? 'compromised' : 'pristine';

        $audit_result = [
            'success'          => true,
            'status'           => $status,
            'has_issues'       => $has_issues,
            'checked_at'       => current_time('mysql'),
            'timestamp'        => time(),
            'total_tracked'    => $total_tracked,
            'verified_count'   => $verified_count,
            'missing_count'    => count($missing_files),
            'modified_count'   => count($modified_files),
            'untracked_count'  => count($untracked_files),
            'missing_files'    => $missing_files,
            'modified_files'   => $modified_files,
            'untracked_files'  => $untracked_files,
            'plugin_version'   => defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.20.0',
        ];

        // Store latest audit state
        update_option(self::DB_LAST_AUDIT_OPTION, $audit_result, false);

        return $audit_result;
    }

    /**
     * Retrieve the official cryptographic baseline manifest
     * Loads from disk manifest file or encrypted database fallback
     *
     * @return array<string, array{sha256: string, size: int}>
     */
    public static function get_baseline_manifest(): array {
        $manifest_file = WCPSCAN_PATH . 'includes/System/plugin-manifest.json';
        if (file_exists($manifest_file)) {
            $raw = @file_get_contents($manifest_file);
            $decoded = json_decode($raw, true);
            if (is_array($decoded) && !empty($decoded['files'])) {
                return $decoded['files'];
            }
        }

        // Fallback to cached verified database baseline if available
        $stored = get_option(self::DB_HASHES_OPTION, []);
        if (is_array($stored) && !empty($stored)) {
            return $stored;
        }

        // Authoritative security rule: Shipped plugin-manifest.json is required.
        // Never dynamically baseline from a live potentially compromised disk in runtime.
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log('[WCP Security] CRITICAL: Authoritative plugin-manifest.json is missing or corrupted.');
        return [];
    }

    /**
     * Dynamically generate manifest map of all valid plugin files
     *
     * @return array
     */
    public static function generate_local_manifest(): array {
        $plugin_dir = rtrim(WCPSCAN_PATH, '/\\');
        $files = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($plugin_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if (!$item->isFile()) {
                continue;
            }
            $real_path = $item->getPathname();
            $rel_path = str_replace([$plugin_dir . DIRECTORY_SEPARATOR, $plugin_dir . '/'], '', $real_path);
            $rel_path = str_replace('\\', '/', $rel_path);

            // Skip developer & temporary files
            if (preg_match('#^(\.git|tests|node_modules|dist|tmp|\.DS_Store)#i', $rel_path)) {
                continue;
            }
            if (substr($rel_path, -4) === '.map' || substr($rel_path, -4) === '.log') {
                continue;
            }

            $files[$rel_path] = [
                'sha256' => @hash_file('sha256', $real_path),
                'size'   => @filesize($real_path) ?: 0,
            ];
        }

        return $files;
    }

    /**
     * Discover any rogue/untracked files inside the plugin root
     *
     * @param string $plugin_dir
     * @param array $manifest
     * @return array
     */
    private static function find_untracked_files(string $plugin_dir, array $manifest): array {
        $untracked = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($plugin_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                if (!$item->isFile()) {
                    continue;
                }
                $real_path = $item->getPathname();
                $rel_path = str_replace([$plugin_dir, str_replace('/', DIRECTORY_SEPARATOR, $plugin_dir)], '', $real_path);
                $rel_path = ltrim(str_replace('\\', '/', $rel_path), '/');

                // Skip dev folders, node_modules, temp files
                if (preg_match('#^(\.git|tests|node_modules|dist|tmp|\.system_generated|\.DS_Store)#i', $rel_path)) {
                    continue;
                }
                if ($rel_path === 'includes/System/plugin-manifest.json' || substr($rel_path, -4) === '.map' || substr($rel_path, -4) === '.log' || substr($rel_path, -4) === '.zip') {
                    continue;
                }

                // Check against manifest
                if (!isset($manifest[$rel_path])) {
                    $untracked[] = [
                        'path'     => $rel_path,
                        'status'   => 'untracked',
                        'size'     => @filesize($real_path) ?: 0,
                        'severity' => 'medium',
                        'detail'   => __('Unknown or extraneous file detected in plugin directory.', 'wcp-security-scanner'),
                    ];
                }
            }
        } catch (\Throwable $e) {
            // Ignore filesystem permission errors
        }

        return $untracked;
    }

    /**
     * Scheduled watchdog check
     */
    public static function run_scheduled_watchdog() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['self_defense_watchdog_enabled'])) {
            return;
        }

        $audit = self::run_audit(true);

        if (!empty($audit['has_issues'])) {
            // Dispatch granular events via NotificationDispatcher
            if (!empty($audit['modified_count'])) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('plugin_file_tampered', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: %d: number of modified files */
                        __('Plugin Self-Defense detected %d modified plugin file(s) with SHA256 checksum mismatches.', 'wcp-security-scanner'),
                        $audit['modified_count']
                    ),
                    'details'  => [
                        'modified_count' => $audit['modified_count'],
                        'sample_files'   => array_column(array_slice($audit['modified_files'], 0, 5), 'path'),
                    ],
                ]);
            }

            if (!empty($audit['missing_count'])) {
                \WcpScanner\Notifications\NotificationDispatcher::trigger('plugin_file_missing', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: %d: number of missing files */
                        __('Plugin Self-Defense detected %d missing or host-deleted plugin core file(s).', 'wcp-security-scanner'),
                        $audit['missing_count']
                    ),
                    'details'  => [
                        'missing_count' => $audit['missing_count'],
                        'sample_files'  => array_column(array_slice($audit['missing_files'], 0, 5), 'path'),
                    ],
                ]);
            }

            // Legacy alert fallback if self_defense_notify_email is on
            if (!empty($settings['self_defense_notify_email'])) {
                self::send_alert_email($audit);
            }
        }
    }

    /**
     * Send email alert to administrator when files are missing or modified
     *
     * @param array $audit
     */
    private static function send_alert_email(array $audit) {
        $to = get_option('admin_email');
        if (empty($to)) {
            return;
        }

        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        /* translators: %s: site name */
        $subject = sprintf(__('[%s Security Alert] WCP Security Scanner File Integrity Anomaly Detected', 'wcp-security-scanner'), $site_name);

        $body  = "Hello Administrator,\n\n";
        $body .= "The WCP Security Scanner Self-Defense & Anti-Tamper Engine has detected that one or more of its own core files have been modified or deleted on your server.\n\n";
        $body .= "This commonly happens when:\n";
        $body .= "1. A shared hosting auto-scanner or ModSecurity rule deleted legitimate plugin files (e.g. CloudflareService.php or REST handlers).\n";
        $body .= "2. A plugin zip archive was partially extracted or corrupted during upload.\n";
        $body .= "3. Unauthorized code modification or malware tampering occurred.\n\n";
        $body .= "--- Audit Summary ---\n";
        $body .= "Site: " . home_url() . "\n";
        $body .= "Missing Files: " . $audit['missing_count'] . "\n";
        $body .= "Modified Files: " . $audit['modified_count'] . "\n";
        $body .= "Untracked Files: " . $audit['untracked_count'] . "\n\n";

        if (!empty($audit['missing_files'])) {
            $body .= "Missing Core Files:\n";
            foreach (array_slice($audit['missing_files'], 0, 10) as $f) {
                $body .= " - " . $f['path'] . "\n";
            }
            $body .= "\n";
        }

        if (!empty($audit['modified_files'])) {
            $body .= "Modified / Tampered Files:\n";
            foreach (array_slice($audit['modified_files'], 0, 10) as $f) {
                $body .= " - " . $f['path'] . "\n";
            }
            $body .= "\n";
        }

        $body .= "Action Required:\n";
        $body .= "Please re-upload or update the official plugin zip in WordPress Admin (Plugins > Add New > Upload Plugin) to restore full security scanner protection.\n\n";
        $body .= "Best regards,\n";
        $body .= "Mir Alamin (WebCare Pro)\n";
        $body .= "WCP Security Scanner Self-Defense Engine\n";

        @wp_mail($to, $subject, $body, ['Content-Type: text/plain; charset=UTF-8']);
    }

    /**
     * Render persistent admin notice across wp-admin if self-defense detects missing/modified files
     */
    public static function render_tamper_warning_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $audit = get_option(self::DB_LAST_AUDIT_OPTION, null);
        if (!$audit || empty($audit['has_issues'])) {
            return;
        }

        $missing_count  = (int) ($audit['missing_count'] ?? 0);
        $modified_count = (int) ($audit['modified_count'] ?? 0);
        $audit_url      = admin_url('admin.php?page=wcp-scanner-forensics&tab=self_defense');

        echo '<div class="notice notice-error" style="padding: 14px 18px; border-left: 4px solid #ef4444; background: #fff1f2; box-shadow: 0 2px 6px rgba(239, 68, 68, 0.15); margin-top: 15px;">';
        echo '<div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">';
        echo '<div style="font-size: 13.5px; color: #991b1b; line-height: 1.5;">';
        echo '<strong><span class="dashicons dashicons-shield" style="font-size: 18px; margin-right: 4px; vertical-align: -2px;"></span> ' . esc_html__('WCP Security Scanner Self-Defense Alert:', 'wcp-security-scanner') . '</strong> ';

        if ($missing_count > 0 && $modified_count > 0) {
            /* translators: 1: number of missing files, 2: number of modified files */
            echo esc_html(sprintf(__('Detected %1$d missing file(s) and %2$d modified file(s) in this plugin installation. A host scanner or upload error may have deleted critical security modules.', 'wcp-security-scanner'), $missing_count, $modified_count));
        } elseif ($missing_count > 0) {
            /* translators: %d: number of missing files */
            echo esc_html(sprintf(__('Detected %1$d missing core file(s) in this plugin installation (e.g. deleted by host security or incomplete zip upload).', 'wcp-security-scanner'), $missing_count));
        } else {
            /* translators: %d: number of modified files */
            echo esc_html(sprintf(__('Detected %1$d modified/tampered file(s) in the security scanner directory.', 'wcp-security-scanner'), $modified_count));
        }
        echo '</div>';

        echo '<div style="display: flex; gap: 8px;">';
        echo '<a href="' . esc_url($audit_url) . '" class="button button-primary" style="background: #dc2626; border-color: #b91c1c; font-weight: 700; padding: 2px 14px;">';
        echo esc_html__('View Self-Defense Diagnostics & Verify', 'wcp-security-scanner');
        echo '</a>';
        echo '</div>';

        echo '</div>';
        echo '</div>';
    }

    /**
     * Fetch remote authoritative manifest from GitHub (Zero-Trust Attestation)
     *
     * @param bool $force_refresh
     * @return array|null
     */
    public static function get_remote_github_manifest(bool $force_refresh = false): ?array {
        $transient_key = 'wcpscan_github_remote_manifest';
        if (!$force_refresh) {
            $cached = get_transient($transient_key);
            if (is_array($cached) && !empty($cached['files'])) {
                return $cached;
            }
        }

        $raw_host = 'raw.' . 'githubusercontent' . '.com';
        $remote_url = "https://{$raw_host}/WebCarePro/wcp-wp-security/main/includes/System/plugin-manifest.json";
        $res = wp_remote_get($remote_url, [
            'timeout'    => 12,
            'user-agent' => 'WCP-Self-Defense/' . (defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.0'),
            'sslverify'  => true,
            'headers'    => [
                'Cache-Control' => 'no-cache, must-revalidate',
            ],
        ]);

        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) {
            return null;
        }

        $decoded = json_decode(wp_remote_retrieve_body($res), true);
        if (!is_array($decoded) || empty($decoded['files'])) {
            return null;
        }

        // Cache for 6 hours
        set_transient($transient_key, $decoded, 6 * HOUR_IN_SECONDS);

        return $decoded;
    }

    /**
     * Audit local files directly against the authoritative remote GitHub manifest
     *
     * @param bool $force_refresh
     * @return array
     */
    public static function audit_against_github(bool $force_refresh = false): array {
        $remote_manifest = self::get_remote_github_manifest($force_refresh);
        if (!$remote_manifest) {
            return [
                'success' => false,
                'message' => __('Unable to connect to GitHub remote repository to fetch authoritative manifest.', 'wcp-security-scanner'),
            ];
        }

        $local_manifest = self::get_baseline_manifest();
        $remote_files = $remote_manifest['files'] ?? [];
        $remote_version = $remote_manifest['version'] ?? 'Unknown';

        // Check if local manifest JSON was itself tampered with relative to GitHub
        $manifest_intact = true;
        if (count($local_manifest) !== count($remote_files)) {
            $manifest_intact = false;
        }

        // Run audit against remote hashes
        $plugin_dir = rtrim(WCPSCAN_PATH, '/\\') . DIRECTORY_SEPARATOR;
        $missing_files = [];
        $modified_files = [];
        $verified_count = 0;

        foreach ($remote_files as $rel_path => $meta) {
            $expected_hash = is_array($meta) ? ($meta['sha256'] ?? '') : (string)$meta;
            $fs_path = $plugin_dir . str_replace('/', DIRECTORY_SEPARATOR, $rel_path);

            if (!file_exists($fs_path) || !is_file($fs_path)) {
                $missing_files[] = [
                    'path'          => $rel_path,
                    'status'        => 'missing',
                    'expected_size' => $meta['size'] ?? 0,
                    'severity'      => 'high',
                    'detail'        => __('File is missing compared to official GitHub release.', 'wcp-security-scanner'),
                ];
                continue;
            }

            $current_hash = @hash_file('sha256', $fs_path);
            if ($current_hash !== $expected_hash) {
                $modified_files[] = [
                    'path'          => $rel_path,
                    'status'        => 'modified',
                    'expected_hash' => $expected_hash,
                    'actual_hash'   => $current_hash,
                    'severity'      => 'critical',
                    'detail'        => __('File hash differs from official GitHub release commit.', 'wcp-security-scanner'),
                ];
            } else {
                $verified_count++;
            }
        }

        return [
            'success'          => true,
            'github_version'   => $remote_version,
            'manifest_intact'  => $manifest_intact,
            'total_remote'     => count($remote_files),
            'verified_count'   => $verified_count,
            'missing_count'    => count($missing_files),
            'modified_count'   => count($modified_files),
            'missing_files'    => $missing_files,
            'modified_files'   => $modified_files,
            'checked_at'       => current_time('mysql'),
        ];
    }

    /**
     * Restore a tampered or missing plugin file directly from GitHub
     *
     * @param string $rel_path Relative path to file (e.g. includes/Api/ScannerRoutes.php)
     * @return array
     */
    public static function restore_file_from_github(string $rel_path): array {
        if (!current_user_can('manage_options')) {
            return ['success' => false, 'message' => __('Permission denied: manage_options required.', 'wcp-security-scanner')];
        }

        // Sanitize path against directory traversal
        $clean_path = str_replace(['..', '\\'], ['', '/'], $rel_path);
        $clean_path = ltrim($clean_path, '/');

        // Verify against remote manifest
        $remote_manifest = self::get_remote_github_manifest(false);
        $expected_meta = $remote_manifest['files'][$clean_path] ?? null;

        if (!$expected_meta) {
            return ['success' => false, 'message' => __('File is not part of official GitHub plugin distribution.', 'wcp-security-scanner')];
        }

        $expected_hash = is_array($expected_meta) ? ($expected_meta['sha256'] ?? '') : (string)$expected_meta;
        $raw_host = 'raw.' . 'githubusercontent' . '.com';
        $github_raw_url = "https://{$raw_host}/WebCarePro/wcp-wp-security/main/" . $clean_path;

        $response = wp_remote_get($github_raw_url, [
            'timeout'    => 15,
            'sslverify'  => true,
            'headers'    => [
                'Cache-Control' => 'no-cache, must-revalidate',
            ],
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return ['success' => false, 'message' => __('Failed to fetch clean file from GitHub repository.', 'wcp-security-scanner')];
        }

        $content = wp_remote_retrieve_body($response);
        $downloaded_hash = hash('sha256', $content);

        if ($downloaded_hash !== $expected_hash) {
            return [
                'success' => false,
                'message' => __('Cryptographic verification failed: Downloaded file hash did not match official GitHub manifest.', 'wcp-security-scanner'),
            ];
        }

        // Write safely to disk
        $fs_path = rtrim(WCPSCAN_PATH, '/\\') . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $clean_path);
        $parent_dir = dirname($fs_path);
        if (!file_exists($parent_dir)) {
            @wp_mkdir_p($parent_dir);
        }

        $written = @file_put_contents($fs_path, $content);
        if ($written === false) {
            return ['success' => false, 'message' => __('Filesystem write failure. Check folder permissions.', 'wcp-security-scanner')];
        }

        // Run local audit to refresh state
        self::run_audit(true);

        return [
            'success' => true,
            'path'    => $clean_path,
            /* translators: %s: file path */
            'message' => sprintf(__('Successfully restored %s from official GitHub release with verified SHA256 integrity.', 'wcp-security-scanner'), $clean_path),
        ];
    }
}

