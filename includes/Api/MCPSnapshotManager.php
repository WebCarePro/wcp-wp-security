<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\HtaccessVaultManager;
use WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer;
use WebCareProScanner\Remediation\TransactionalRemediation;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\WebCareActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPSnapshotManager
 *
 * Captures rolling 15-state pre-execution snapshots right before any mutating MCP tool
 * runs and supports atomic 1-click Undo / Rollback from both WP Admin and MCP.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
class MCPSnapshotManager {

    const OPTION_KEY    = 'webcareproscan_mcp_snapshots';
    const MAX_SNAPSHOTS = 15;

    /**
     * Capture a domain-scoped pre-change snapshot immediately before executing a mutating MCP tool.
     *
     * @param string               $tool
     * @param array<string, mixed> $args
     * @param string               $actor
     * @param string               $summary
     * @return array<string, mixed>
     */
    public static function capture_pre_change_snapshot(string $tool, array $args = [], string $actor = 'MCP Agent', string $summary = ''): array {
        $snap_id = 'mcp_snap_' . time() . '_' . substr(md5(uniqid('snap_', true)), 0, 6);
        $bundle  = [];

        // Capture affected state based on tool domain to keep option compact (< 30KB)
        if (strpos($tool, 'visual_rule') !== false || strpos($tool, 'modular') !== false || strpos($tool, 'cve_virtual_shield') !== false || strpos($tool, 'custom_rule') !== false) {
            $rules = get_option(ModularFirewallSynthesizer::OPTION_RULES, []);
            $bundle['modular_rules']    = is_array($rules) ? $rules : [];
            $bundle['modular_autopilot'] = ModularFirewallSynthesizer::is_autopilot_enabled();
        }

        if ($tool === 'webcareproscan_update_plugin_settings' || $tool === 'webcareproscan_manage_scan_exclusions') {
            $stored   = get_option(SettingsManager::OPTION_KEY, []);
            $stored   = is_array($stored) ? $stored : [];
            $defaults = SettingsManager::get_defaults();
            $subset   = [];
            $keys     = ($tool === 'webcareproscan_manage_scan_exclusions')
                ? ['excluded_paths']
                : array_keys(is_array($args['updates'] ?? null) ? $args['updates'] : []);
            foreach ($keys as $k) {
                $sk = sanitize_key((string) $k);
                if ($sk !== '' && !in_array($sk, MCPSettingsPolicy::IMMUTABLE_KEYS, true)) {
                    $subset[$sk] = array_key_exists($sk, $stored) ? $stored[$sk] : ($defaults[$sk] ?? null);
                }
            }
            $bundle['settings_subset'] = $subset;
        }

        if ($tool === 'webcareproscan_manage_ip_access') {
            $stored   = get_option(SettingsManager::OPTION_KEY, []);
            $stored   = is_array($stored) ? $stored : [];
            $defaults = SettingsManager::get_defaults();
            $bundle['settings_subset'] = [
                'waf_blocked_ips'     => $stored['waf_blocked_ips'] ?? ($defaults['waf_blocked_ips'] ?? ''),
                'waf_whitelisted_ips' => $stored['waf_whitelisted_ips'] ?? ($defaults['waf_whitelisted_ips'] ?? ''),
            ];
            if (class_exists(FirewallEngine::class)) {
                $bundle['blocked_ips_meta'] = get_option(FirewallEngine::OPTION_BLOCKED_IPS_META, []);
            }
        }

        if ($tool === 'webcareproscan_toggle_cron_task') {
            $stored   = get_option(SettingsManager::OPTION_KEY, []);
            $stored   = is_array($stored) ? $stored : [];
            $defaults = SettingsManager::get_defaults();
            $bundle['settings_subset'] = [
                'cron_task_schedules' => $stored['cron_task_schedules'] ?? ($defaults['cron_task_schedules'] ?? []),
            ];
            foreach ($defaults as $ck => $dv) {
                if (strpos($ck, 'cron_') === 0 && substr($ck, -8) === '_enabled') {
                    $bundle['settings_subset'][$ck] = array_key_exists($ck, $stored) ? $stored[$ck] : $dv;
                }
            }
        }

        if ($tool === 'webcareproscan_apply_htaccess_hardening' && class_exists(HtaccessVaultManager::class)) {
            $vault_res = HtaccessVaultManager::snapshot_current_if_clean('mcp_pre_change');
            if (!empty($vault_res['version'])) {
                $bundle['htaccess_vault_version'] = (int) $vault_res['version'];
            }
        }

        if ($summary === '') {
            /* translators: %s: MCP tool name */
            $summary = sprintf(__('Pre-change snapshot before %s', 'webcare-pro-security'), $tool);
        }

        $entry = [
            'id'             => $snap_id,
            'timestamp'      => time(),
            'created_at_gmt' => gmdate('Y-m-d H:i:s'),
            'tool'           => sanitize_text_field($tool),
            'actor'          => sanitize_text_field($actor),
            'summary'        => sanitize_text_field($summary),
            'restored'       => false,
            'restored_at'    => 0,
            'domains'        => array_keys($bundle),
            'state_bundle'   => $bundle,
        ];

        $list = get_option(self::OPTION_KEY, []);
        if (!is_array($list)) {
            $list = [];
        }
        array_unshift($list, $entry);
        if (count($list) > self::MAX_SNAPSHOTS) {
            $list = array_slice($list, 0, self::MAX_SNAPSHOTS);
        }
        update_option(self::OPTION_KEY, $list, false);

        return $entry;
    }

    /**
     * List compact snapshot summaries (omits heavy serialized state_bundle payloads).
     *
     * @param int $limit
     * @return array<int, array<string, mixed>>
     */
    public static function list_snapshots(int $limit = 15): array {
        $list = get_option(self::OPTION_KEY, []);
        if (!is_array($list)) {
            return [];
        }
        $out = [];
        foreach (array_slice($list, 0, max(1, min(self::MAX_SNAPSHOTS, $limit))) as $item) {
            if (!is_array($item)) {
                continue;
            }
            $out[] = [
                'id'             => $item['id'] ?? '',
                'timestamp'      => (int) ($item['timestamp'] ?? 0),
                'created_at_gmt' => $item['created_at_gmt'] ?? '',
                'tool'           => $item['tool'] ?? '',
                'actor'          => $item['actor'] ?? '',
                'summary'        => $item['summary'] ?? '',
                'domains'        => $item['domains'] ?? [],
                'restored'       => !empty($item['restored']),
                'restored_at'    => (int) ($item['restored_at'] ?? 0),
            ];
        }
        return $out;
    }

    /**
     * Atomically restore the targeted snapshot (or the latest un-reverted snapshot if $snapshot_id is empty).
     *
     * @param string $snapshot_id
     * @return array<string, mixed>
     */
    public static function restore_snapshot(string $snapshot_id = ''): array {
        $list = get_option(self::OPTION_KEY, []);
        if (!is_array($list) || empty($list)) {
            return ['success' => false, 'message' => __('No MCP pre-change snapshots available to restore.', 'webcare-pro-security')];
        }

        $target_idx = -1;
        foreach ($list as $idx => $item) {
            if ($snapshot_id !== '') {
                if (($item['id'] ?? '') === $snapshot_id) {
                    $target_idx = $idx;
                    break;
                }
            } elseif (empty($item['restored']) && !empty($item['state_bundle'])) {
                $target_idx = $idx;
                break;
            }
        }

        if ($target_idx === -1 || empty($list[$target_idx])) {
            return ['success' => false, 'message' => __('Requested MCP snapshot was not found or has nothing to restore.', 'webcare-pro-security')];
        }

        $target  = $list[$target_idx];
        $bundle  = is_array($target['state_bundle'] ?? null) ? $target['state_bundle'] : [];
        $applied = [];

        if (isset($bundle['settings_subset']) && is_array($bundle['settings_subset']) && !empty($bundle['settings_subset'])) {
            $raw = get_option(SettingsManager::OPTION_KEY, []);
            $raw = is_array($raw) ? $raw : [];
            foreach ($bundle['settings_subset'] as $k => $v) {
                if (!in_array($k, MCPSettingsPolicy::IMMUTABLE_KEYS, true)) {
                    $raw[$k] = $v;
                }
            }
            update_option(SettingsManager::OPTION_KEY, $raw);
            $applied[] = 'settings_subset';
        }

        if (isset($bundle['blocked_ips_meta']) && is_array($bundle['blocked_ips_meta']) && class_exists(FirewallEngine::class)) {
            update_option(FirewallEngine::OPTION_BLOCKED_IPS_META, $bundle['blocked_ips_meta'], false);
            $applied[] = 'blocked_ips_meta';
        }

        if (isset($bundle['modular_rules']) && is_array($bundle['modular_rules']) && class_exists(ModularFirewallSynthesizer::class)) {
            ModularFirewallSynthesizer::save_rules($bundle['modular_rules']);
            if (array_key_exists('modular_autopilot', $bundle)) {
                ModularFirewallSynthesizer::set_autopilot_enabled(!empty($bundle['modular_autopilot']));
            }
            $applied[] = 'modular_rules';
        }

        if (!empty($bundle['htaccess_vault_version']) && class_exists(HtaccessVaultManager::class)) {
            HtaccessVaultManager::restore_snapshot((int) $bundle['htaccess_vault_version']);
            $applied[] = 'htaccess_vault';
        }

        if (!empty($bundle['tx_id']) && class_exists(TransactionalRemediation::class)) {
            $applied[] = 'tx_id';
        }

        $list[$target_idx]['restored']    = true;
        $list[$target_idx]['restored_at'] = time();
        update_option(self::OPTION_KEY, $list, false);

        // Recompile standalone Preload Micro-WAF so undo immediately synchronizes micro-waf-compiled.php on disk
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            \WebCareProScanner\Firewall\MicroWafCompiler::compile();
        }

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::log(
                'mcp_snapshot_restored',
                'settings',
                'info',
                [
                    'description' => sprintf('Restored MCP pre-change snapshot %s (%s)', $target['id'], implode(', ', $applied)),
                    'snapshot_id' => $target['id'],
                    'tool'        => $target['tool'] ?? '',
                ]
            );
        }

        return [
            'success'          => true,
            'snapshot_id'      => $target['id'],
            'tool'             => $target['tool'] ?? '',
            'restored_domains' => $applied,
            'message'          => sprintf(
                /* translators: %s: snapshot identifier */
                __('Successfully reverted changes using snapshot %s.', 'webcare-pro-security'),
                $target['id']
            ),
        ];
    }
}
