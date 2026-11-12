<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Findings\FindingTranslator;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\HtaccessVaultManager;
use WebCareProScanner\Firewall\ServerSecurityEngine;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Quarantine\QuarantineManager;
use WebCareProScanner\Remediation\RemediationManager;
use WebCareProScanner\Reports\IncidentReportEngine;
use WebCareProScanner\Security\PromptInjectionGuard;
use WebCareProScanner\System\Scheduler;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPExtendedTools
 *
 * Domain handlers for full governed WebCare Pro plugin control via MCP:
 * Settings Catalog/Updates, Scanner & Reports, Quarantine & RemediationManager,
 * WAF Incidents/IP Access/Cloudflare, Server Hardening, and Snapshot Undo.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
class MCPExtendedTools {

    /**
     * Catalog definitions for extended core tools (merged into MCPAgentService::get_tools_catalog()).
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_tool_definitions(): array {
        return [
            [
                'name'        => 'webcareproscan_get_settings_catalog',
                'description' => 'Read allowlisted WebCare Pro plugin settings grouped by domain (waf, headers, scanner, auth, cloudflare, schedule) with risk tiers. Secrets are masked.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'domain' => [
                            'type'        => 'string',
                            'enum'        => ['all', 'waf', 'headers', 'scanner', 'auth', 'cloudflare', 'schedule', 'other'],
                            'default'     => 'all',
                            'description' => 'Optional setting domain filter.',
                        ],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_update_plugin_settings',
                'description' => 'Safely update allowlisted WebCare Pro plugin settings (Tier 2 reversible toggles run with pre-change snapshot; Tier 3/4 sensitive keys auto-stage for WP Admin confirmation).',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'updates' => [
                            'type'        => 'object',
                            'description' => 'Key-value map of allowlisted WebCare Pro setting keys and new values.',
                        ],
                    ],
                    'required' => ['updates'],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_server_hardening_status',
                'description' => 'Inspect Apache .htaccess / Nginx / Caddy server hardening rules, verification state, and HtaccessVault snapshots.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
            ],
            [
                'name'        => 'webcareproscan_apply_htaccess_hardening',
                'description' => 'Deploy verified Apache .htaccess security hardening directives after capturing an automatic rollback vault snapshot.',
                'category'    => 'mutating',
                'tier'        => 3,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'options' => [
                            'type'        => 'object',
                            'description' => 'Optional ServerSecurityEngine boolean hardening flags; omits to keep/apply active options.',
                        ],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_start_security_scan',
                'description' => 'Start a WebCare Pro malware & integrity scan immediately (quick, full, plugins_themes, core_integrity, or suspicious_uploads).',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'scan_type' => [
                            'type'    => 'string',
                            'enum'    => ['plugins_themes', 'full', 'core_integrity', 'suspicious_uploads'],
                            'default' => 'plugins_themes',
                        ],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_scan_status',
                'description' => 'Retrieve recent scan history, active running scan progress, file counts, and overall risk score.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'scan_id' => ['type' => 'integer', 'description' => 'Optional specific scan ID to inspect; defaults to latest scans.'],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_explain_finding',
                'description' => 'Get a plain-English non-technical explanation and recommended safe action for a scan issue ID.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'issue_id' => ['type' => 'integer', 'description' => 'Database ID from webcareproscan_list_findings.'],
                    ],
                    'required' => ['issue_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_manage_scan_exclusions',
                'description' => 'Add or remove normalized relative scan exclusion patterns in excluded_paths (blocks ".." traversal or global "*" wildcards).',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'action' => ['type' => 'string', 'enum' => ['add', 'remove']],
                        'path'   => ['type' => 'string', 'description' => 'Relative path under wp-content/ or pattern (e.g. wp-content/cache/*).'],
                    ],
                    'required' => ['action', 'path'],
                ],
            ],
            [
                'name'        => 'webcareproscan_export_security_report',
                'description' => 'Compile an executive JSON security incident & posture report using IncidentReportEngine.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'client_name' => ['type' => 'string', 'description' => 'Optional label for report header.'],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_list_quarantine_items',
                'description' => 'List quarantined files stored in the secure isolation vault with hashes, timestamps, and original paths.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
            ],
            [
                'name'        => 'webcareproscan_restore_quarantined_file',
                'description' => 'Restore a quarantined file back to its original WordPress path (requires admin approval confirmation).',
                'category'    => 'mutating',
                'tier'        => 3,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'quarantine_id' => ['type' => 'integer', 'description' => 'Quarantine record ID.'],
                    ],
                    'required' => ['quarantine_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_delete_quarantined_file',
                'description' => 'Permanently delete a quarantined file from the isolation vault (Tier 4 destructive action with step-up admin approval).',
                'category'    => 'mutating',
                'tier'        => 4,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'quarantine_id' => ['type' => 'integer', 'description' => 'Quarantine record ID to permanently delete.'],
                    ],
                    'required' => ['quarantine_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_repair_official_file',
                'description' => 'Restore a tampered WordPress core, WordPress.org plugin, or theme file bit-for-bit using RemediationManager.',
                'category'    => 'mutating',
                'tier'        => 3,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'scope'     => ['type' => 'string', 'enum' => ['core', 'plugin', 'theme']],
                        'file_path' => ['type' => 'string', 'description' => 'Relative path from ABSPATH or plugin/theme file path.'],
                        'issue_id'  => ['type' => 'integer', 'description' => 'Optional scan issue ID to mark remediated.'],
                    ],
                    'required' => ['scope', 'file_path'],
                ],
            ],
            [
                'name'        => 'webcareproscan_list_waf_incidents',
                'description' => 'Query recent blocked or monitored WAF incident logs (payload strings wrapped in prompt-injection-safe untrusted delimiters).',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'ip'     => ['type' => 'string', 'description' => 'Optional source IP filter.'],
                        'action' => ['type' => 'string', 'description' => 'Optional action filter (blocked, monitor, allow).'],
                        'limit'  => ['type' => 'integer', 'default' => 25, 'description' => 'Max rows (1-100).'],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_manage_ip_access',
                'description' => 'Ban an attacker IP locally (with anti-lockout guard), remove an IP ban, or add an IP to the firewall allowlist.',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'action'           => ['type' => 'string', 'enum' => ['ban', 'unban', 'whitelist']],
                        'ip'               => ['type' => 'string', 'description' => 'Target IPv4, IPv6, or CIDR address.'],
                        'reason'           => ['type' => 'string', 'description' => 'Short justification recorded in firewall logs.'],
                        'duration_seconds' => ['type' => 'integer', 'default' => 86400, 'description' => 'Ban TTL in seconds (0 = permanent).'],
                    ],
                    'required' => ['action', 'ip'],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_cloudflare_status',
                'description' => 'Inspect Cloudflare connection health, proxy status, active custom rules count, and edge ban count (never exposes API tokens).',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
            ],
            [
                'name'        => 'webcareproscan_sync_cloudflare_ip_ban',
                'description' => 'Push an IP block or remove an IP block on connected Cloudflare Edge Access Rules.',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'action' => ['type' => 'string', 'enum' => ['ban', 'unban']],
                        'ip'     => ['type' => 'string', 'description' => 'External IPv4/IPv6 address to block or unblock on Cloudflare Edge.'],
                        'reason' => ['type' => 'string', 'description' => 'Note stored on the Cloudflare IP access rule.'],
                    ],
                    'required' => ['action', 'ip'],
                ],
            ],
            [
                'name'        => 'webcareproscan_list_mcp_snapshots',
                'description' => 'List the latest 15 pre-change rollback snapshots captured before mutating MCP operations.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'limit' => ['type' => 'integer', 'default' => 15],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_undo_last_mcp_change',
                'description' => 'Revert plugin settings, modular rules, or IP access lists back to a pre-change MCP snapshot (defaults to most recent active snapshot).',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'snapshot_id' => ['type' => 'string', 'description' => 'Optional snapshot ID; omit to revert the latest un-reverted MCP mutation.'],
                    ],
                ],
            ],
        ];
    }

    /**
     * Dispatch an extended core tool if handled here, or return null when unknown to this handler.
     *
     * @param string               $tool
     * @param array<string, mixed> $args
     * @return array<string, mixed>|null
     */
    public static function dispatch(string $tool, array $args): ?array {
        switch ($tool) {
            case 'webcareproscan_get_settings_catalog':
                $domain = sanitize_key((string) ($args['domain'] ?? 'all'));
                return self::envelope(array_merge(['success' => true], MCPSettingsPolicy::get_catalog($domain)));

            case 'webcareproscan_update_plugin_settings':
                return self::handle_update_settings($args);

            case 'webcareproscan_get_server_hardening_status':
                return self::handle_server_hardening_status();

            case 'webcareproscan_apply_htaccess_hardening':
                return self::handle_apply_htaccess($args);

            case 'webcareproscan_start_security_scan':
                return self::handle_start_scan($args);

            case 'webcareproscan_get_scan_status':
                return self::handle_get_scan_status($args);

            case 'webcareproscan_explain_finding':
                return self::handle_explain_finding($args);

            case 'webcareproscan_manage_scan_exclusions':
                return self::handle_manage_exclusions($args);

            case 'webcareproscan_export_security_report':
                $opts = [];
                if (!empty($args['client_name'])) {
                    $opts['client_name'] = sanitize_text_field((string) $args['client_name']);
                }
                $report = IncidentReportEngine::generate_report($opts);
                $report = PromptInjectionGuard::sanitize_mcp_telemetry($report);
                return self::envelope(array_merge(['success' => true], $report));

            case 'webcareproscan_list_quarantine_items':
                $qm   = new QuarantineManager();
                $rows = $qm->list_records();
                return self::envelope(['success' => true, 'items' => $rows, 'count' => count($rows)]);

            case 'webcareproscan_restore_quarantined_file':
                $qid = intval($args['quarantine_id'] ?? 0);
                if ($qid <= 0) {
                    return self::error(__('Valid quarantine_id is required.', 'webcare-pro-security'));
                }
                $qm  = new QuarantineManager();
                return self::envelope($qm->restore_file($qid));

            case 'webcareproscan_delete_quarantined_file':
                $qid = intval($args['quarantine_id'] ?? 0);
                if ($qid <= 0) {
                    return self::error(__('Valid quarantine_id is required.', 'webcare-pro-security'));
                }
                $qm  = new QuarantineManager();
                return self::envelope($qm->delete_record($qid));

            case 'webcareproscan_repair_official_file':
                return self::handle_repair_official_file($args);

            case 'webcareproscan_list_waf_incidents':
                return self::handle_list_waf_incidents($args);

            case 'webcareproscan_manage_ip_access':
                return self::handle_manage_ip_access($args);

            case 'webcareproscan_get_cloudflare_status':
                return self::handle_cloudflare_status();

            case 'webcareproscan_sync_cloudflare_ip_ban':
                return self::handle_sync_cloudflare_ip_ban($args);

            case 'webcareproscan_list_mcp_snapshots':
                $limit = max(1, min(15, intval($args['limit'] ?? 15)));
                $snaps = MCPSnapshotManager::list_snapshots($limit);
                return self::envelope(['success' => true, 'snapshots' => $snaps, 'count' => count($snaps)]);

            case 'webcareproscan_undo_last_mcp_change':
                $snap_id = sanitize_text_field((string) ($args['snapshot_id'] ?? ''));
                return self::envelope(MCPSnapshotManager::restore_snapshot($snap_id));
        }

        return null;
    }

    /** @param array<string, mixed> $args */
    private static function handle_update_settings(array $args): array {
        $updates = is_array($args['updates'] ?? null) ? $args['updates'] : [];
        $check   = MCPSettingsPolicy::validate_and_classify_update($updates);
        if (empty($check['valid'])) {
            return self::error((string) ($check['message'] ?? __('Invalid setting updates.', 'webcare-pro-security')));
        }

        $saved = SettingsManager::save_settings($check['patch']);
        return self::envelope([
            'success'      => true,
            'updated_keys' => array_keys($check['patch']),
            'max_tier'     => $check['max_tier'],
            'diff'         => $check['diff_preview'],
            'waf_enabled'  => !empty($saved['waf_enabled']),
            'message'      => sprintf(
                /* translators: %d: number of settings updated */
                __('Successfully updated %d allowlisted WebCare Pro setting(s).', 'webcare-pro-security'),
                count($check['patch'])
            ),
        ]);
    }

    private static function handle_server_hardening_status(): array {
        $opts      = ServerSecurityEngine::get_options();
        $file_info = ServerSecurityEngine::get_file_info();
        $verify    = ServerSecurityEngine::verify_rule_enforcement();
        $snapshots = HtaccessVaultManager::list_snapshots();
        return self::envelope([
            'success'           => true,
            'options'           => $opts,
            'file_info'         => $file_info,
            'verification'      => $verify,
            'vault_snapshots'   => count($snapshots),
            'htaccess_locked'   => HtaccessVaultManager::is_readonly_locked(),
        ]);
    }

    /** @param array<string, mixed> $args */
    private static function handle_apply_htaccess(array $args): array {
        $current = ServerSecurityEngine::get_options();
        $custom  = is_array($args['options'] ?? null) ? $args['options'] : [];
        $merged  = array_merge($current, $custom);
        $res     = ServerSecurityEngine::deploy_to_htaccess($merged);
        return self::envelope($res);
    }

    /** @param array<string, mixed> $args */
    private static function handle_start_scan(array $args): array {
        $scan_type = sanitize_key((string) ($args['scan_type'] ?? 'plugins_themes'));
        $valid     = ['plugins_themes', 'full', 'core_integrity', 'suspicious_uploads'];
        if (!in_array($scan_type, $valid, true)) {
            return self::error(__('Invalid scan_type. Choose plugins_themes, full, core_integrity, or suspicious_uploads.', 'webcare-pro-security'));
        }
        $settings = SettingsManager::get_settings();
        $prev_type = $settings['schedule_scan_type'] ?? 'plugins_themes';
        if ($prev_type !== $scan_type) {
            SettingsManager::save_settings(['schedule_scan_type' => $scan_type]);
        }
        $scan_id = Scheduler::run_scheduled_scan(true);
        if ($prev_type !== $scan_type) {
            SettingsManager::save_settings(['schedule_scan_type' => $prev_type]);
        }
        if (empty($scan_id)) {
            return self::error(__('A security scan could not start right now (another scan lock may already be active).', 'webcare-pro-security'));
        }
        return self::envelope([
            'success'   => true,
            'scan_id'   => (int) $scan_id,
            'scan_type' => $scan_type,
            'message'   => sprintf(
                /* translators: 1: scan ID, 2: scan type */
                __('Security scan #%1$d (%2$s) executed and recorded.', 'webcare-pro-security'),
                (int) $scan_id,
                $scan_type
            ),
        ]);
    }

    /** @param array<string, mixed> $args */
    private static function handle_get_scan_status(array $args): array {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_scans';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) !== $table) {
            return self::envelope(['success' => true, 'scans' => []]);
        }
        $scan_id = intval($args['scan_id'] ?? 0);
        if ($scan_id > 0) {
            $sql = "SELECT id, status, scan_target, trigger_type, scanned_files, total_files, issues_found, risk_score, duration, created_at FROM `{$table}` WHERE id = %d LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $row = $wpdb->get_row($wpdb->prepare($sql, $scan_id), ARRAY_A);
            return self::envelope(['success' => (bool) $row, 'scan' => $row ?: null]);
        }
        $sql = "SELECT id, status, scan_target, trigger_type, scanned_files, total_files, issues_found, risk_score, duration, created_at FROM `{$table}` ORDER BY id DESC LIMIT 5";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results($sql, ARRAY_A) ?: [];
        return self::envelope(['success' => true, 'recent_scans' => $rows]);
    }

    /** @param array<string, mixed> $args */
    private static function handle_explain_finding(array $args): array {
        global $wpdb;
        $issue_id = intval($args['issue_id'] ?? 0);
        if ($issue_id <= 0) {
            return self::error(__('Valid issue_id is required.', 'webcare-pro-security'));
        }
        $table = $wpdb->prefix . 'webcareproscan_scan_issues';
        $sql   = "SELECT * FROM `{$table}` WHERE id = %d LIMIT 1";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issue = $wpdb->get_row($wpdb->prepare($sql, $issue_id), ARRAY_A);
        if (!$issue) {
            return self::error(__('Scan finding not found.', 'webcare-pro-security'));
        }
        $translated = FindingTranslator::translate($issue);
        $payload    = PromptInjectionGuard::sanitize_mcp_telemetry([
            'success'     => true,
            'issue'       => $issue,
            'explanation' => $translated,
        ]);
        return self::envelope($payload);
    }

    /** @param array<string, mixed> $args */
    private static function handle_manage_exclusions(array $args): array {
        $action = sanitize_key((string) ($args['action'] ?? ''));
        $path   = trim(str_replace('\\', '/', sanitize_text_field((string) ($args['path'] ?? ''))));
        if (!in_array($action, ['add', 'remove'], true) || $path === '') {
            return self::error(__('Valid action (add/remove) and relative path are required.', 'webcare-pro-security'));
        }
        if (strpos($path, '..') !== false || $path === '*' || $path === '/') {
            return self::error(__('Invalid or overly broad exclusion path.', 'webcare-pro-security'));
        }

        $settings = SettingsManager::get_settings();
        $lines    = array_values(array_filter(array_map('trim', explode("\n", str_replace("\r", '', (string) ($settings['excluded_paths'] ?? ''))))));
        if ($action === 'add') {
            if (!in_array($path, $lines, true)) {
                $lines[] = $path;
            }
        } else {
            $lines = array_values(array_filter($lines, static fn($l) => $l !== $path));
        }

        SettingsManager::save_settings(['excluded_paths' => implode("\n", $lines)]);
        return self::envelope([
            'success'        => true,
            'action'         => $action,
            'path'           => $path,
            'excluded_paths' => $lines,
        ]);
    }

    /** @param array<string, mixed> $args */
    private static function handle_repair_official_file(array $args): array {
        $scope     = sanitize_key((string) ($args['scope'] ?? ''));
        $file_path = sanitize_text_field((string) ($args['file_path'] ?? ''));
        $issue_id  = !empty($args['issue_id']) ? intval($args['issue_id']) : null;
        if ($file_path === '' || !in_array($scope, ['core', 'plugin', 'theme'], true)) {
            return self::error(__('Valid scope (core, plugin, theme) and file_path are required.', 'webcare-pro-security'));
        }

        $rm = new RemediationManager();
        if ($scope === 'plugin') {
            $res = $rm->restore_official_plugin_file($file_path, $issue_id);
        } elseif ($scope === 'theme') {
            $res = $rm->restore_official_theme_file($file_path, $issue_id);
        } else {
            $res = $rm->restore_official_core_file($file_path, $issue_id);
        }
        return self::envelope(is_array($res) ? $res : ['success' => false]);
    }

    /** @param array<string, mixed> $args */
    private static function handle_list_waf_incidents(array $args): array {
        $filters = [];
        if (!empty($args['ip'])) {
            $filters['ip'] = sanitize_text_field((string) $args['ip']);
        }
        if (!empty($args['action'])) {
            $filters['action'] = sanitize_key((string) $args['action']);
        }
        $limit = max(1, min(100, intval($args['limit'] ?? 25)));
        $res   = WafFileLogger::query_logs($filters, $limit, 1);
        $safe  = PromptInjectionGuard::sanitize_mcp_telemetry($res);
        return self::envelope(array_merge(['success' => true], is_array($safe) ? $safe : []));
    }

    /** @param array<string, mixed> $args */
    private static function handle_manage_ip_access(array $args): array {
        $action = sanitize_key((string) ($args['action'] ?? ''));
        $ip     = trim(sanitize_text_field((string) ($args['ip'] ?? '')));
        $reason = sanitize_text_field((string) ($args['reason'] ?? 'Managed via MCP Agent'));
        $ttl    = max(0, intval($args['duration_seconds'] ?? 86400));

        if (!in_array($action, ['ban', 'unban', 'whitelist'], true) || $ip === '') {
            return self::error(__('Valid action (ban, unban, whitelist) and IP address are required.', 'webcare-pro-security'));
        }

        if ($action === 'ban') {
            $guard = MCPAntiLockoutValidator::validate_ip_ban($ip);
            if (empty($guard['allowed'])) {
                return self::error($guard['reason']);
            }
            $ok = FirewallEngine::block_ip($ip, $reason, $ttl);
            return self::envelope([
                'success'          => $ok,
                'action'           => 'ban',
                'ip'               => $ip,
                'duration_seconds' => $ttl,
                'message'          => $ok ? __('IP added to firewall blocklist.', 'webcare-pro-security') : __('Failed to ban IP.', 'webcare-pro-security'),
            ]);
        }

        if ($action === 'unban') {
            $ok = FirewallEngine::remove_blocked_ip($ip);
            return self::envelope([
                'success' => $ok,
                'action'  => 'unban',
                'ip'      => $ip,
                'message' => __('IP removed from blocklist and temporary lockouts.', 'webcare-pro-security'),
            ]);
        }

        // Whitelist IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return self::error(__('Valid single IPv4 or IPv6 address is required for whitelist.', 'webcare-pro-security'));
        }
        $settings = SettingsManager::get_settings();
        $lines    = array_values(array_filter(array_map('trim', explode("\n", str_replace("\r", '', (string) ($settings['waf_whitelisted_ips'] ?? ''))))));
        $exists   = false;
        foreach ($lines as $line) {
            if (trim(preg_split('/[\s#]+/', $line)[0] ?? '') === $ip) {
                $exists = true;
                break;
            }
        }
        if (!$exists) {
            $lines[] = $ip . ' # ' . $reason;
            SettingsManager::save_settings(['waf_whitelisted_ips' => implode("\n", $lines)]);
        }
        return self::envelope([
            'success' => true,
            'action'  => 'whitelist',
            'ip'      => $ip,
            'message' => __('IP added to firewall allowlist.', 'webcare-pro-security'),
        ]);
    }

    private static function handle_cloudflare_status(): array {
        $status = CloudflareService::get_status();
        $proxy  = CloudflareService::check_proxy_status();
        unset($status['api_token'], $status['token'], $status['cloudflare_api_token']);
        return self::envelope([
            'success'      => true,
            'connected'    => CloudflareService::is_configured(),
            'status'       => $status,
            'proxy_status' => $proxy,
        ]);
    }

    /** @param array<string, mixed> $args */
    private static function handle_sync_cloudflare_ip_ban(array $args): array {
        if (!CloudflareService::is_configured()) {
            return self::error(__('Cloudflare Edge integration is not configured on this site.', 'webcare-pro-security'));
        }
        $action = sanitize_key((string) ($args['action'] ?? ''));
        $ip     = trim(sanitize_text_field((string) ($args['ip'] ?? '')));
        $reason = sanitize_text_field((string) ($args['reason'] ?? 'WebCare Pro MCP Edge Ban'));

        if (!in_array($action, ['ban', 'unban'], true) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return self::error(__('Valid action (ban or unban) and IP address are required.', 'webcare-pro-security'));
        }

        if ($action === 'ban') {
            $guard = MCPAntiLockoutValidator::validate_ip_ban($ip);
            if (empty($guard['allowed'])) {
                return self::error($guard['reason']);
            }
            return self::envelope(CloudflareService::block_ip($ip, $reason));
        }

        return self::envelope(CloudflareService::unblock_ip_by_address($ip));
    }

    /** @param array<string, mixed> $res */
    private static function envelope(array $res): array {
        return [
            'isError' => empty($res['success']),
            'content' => [['type' => 'text', 'text' => (string) wp_json_encode($res, JSON_PRETTY_PRINT)]],
            'result'  => $res,
        ];
    }

    private static function error(string $message): array {
        return [
            'isError' => true,
            'content' => [['type' => 'text', 'text' => $message]],
            'result'  => ['success' => false, 'message' => $message],
        ];
    }
}
