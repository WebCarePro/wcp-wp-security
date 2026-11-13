<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Findings\WhitelistManager;
use WebCareProScanner\Integrity\BehavioralBaselineEngine;
use WebCareProScanner\Remediation\TransactionalRemediation;
use WebCareProScanner\Quarantine\QuarantineManager;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Firewall\ThreatIntelNetwork;
use WebCareProScanner\Firewall\VirtualPatchSynthesizer;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Findings\RiskScorer;
use WebCareProScanner\Security\AttackSimulationEngine;
use WebCareProScanner\Security\EmergencyContainmentManager;
use WebCareProScanner\Security\PromptInjectionGuard;
use WebCareProScanner\Auth\TwoFactorAuth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPAgentService
 *
 * Implements standard Model Context Protocol (MCP) tool declarations,
 * granular tool governance policy matrix, staged action confirmation gates,
 * and autonomous AI SecOps execution surface.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class MCPAgentService {

    const READ_TOOLS = [
        'webcareproscan_get_security_posture',
        'webcareproscan_list_findings',
        'webcareproscan_audit_behavioral_baseline',
        'webcareproscan_get_containment_status',
        'webcareproscan_list_staged_actions',
        'webcareproscan_get_supply_chain_sbom',
        'webcareproscan_get_gatekeeper_history',
        'webcareproscan_get_behavioral_waf_status',
        'webcareproscan_get_identity_forensics',
        'webcareproscan_get_threat_intel_network',
        'webcareproscan_test_virtual_patch',
        'webcareproscan_get_settings_catalog',
        'webcareproscan_get_server_hardening_status',
        'webcareproscan_get_scan_status',
        'webcareproscan_explain_finding',
        'webcareproscan_export_security_report',
        'webcareproscan_list_quarantine_items',
        'webcareproscan_list_waf_incidents',
        'webcareproscan_get_cloudflare_status',
        'webcareproscan_list_mcp_snapshots',
    ];

    const MUTATING_TOOLS = [
        'webcareproscan_whitelist_finding',
        'webcareproscan_rollback_remediation',
        'webcareproscan_deploy_virtual_patch',
        'webcareproscan_quarantine_file',
        'webcareproscan_run_security_drill',
        'webcareproscan_set_containment_mode',
        'webcareproscan_recalibrate_sbom_baseline',
        'webcareproscan_quarantine_supply_chain_anchor',
        'webcareproscan_set_route_learning_status',
        'webcareproscan_revoke_user_session',
        'webcareproscan_grant_ephemeral_elevation',
        'webcareproscan_revoke_ephemeral_elevation',
        'webcareproscan_sync_threat_intel',
        'webcareproscan_synthesize_virtual_patch',
        'webcareproscan_deploy_synthesized_patch',
        'webcareproscan_update_plugin_settings',
        'webcareproscan_apply_htaccess_hardening',
        'webcareproscan_start_security_scan',
        'webcareproscan_manage_scan_exclusions',
        'webcareproscan_restore_quarantined_file',
        'webcareproscan_delete_quarantined_file',
        'webcareproscan_repair_official_file',
        'webcareproscan_manage_ip_access',
        'webcareproscan_sync_cloudflare_ip_ban',
        'webcareproscan_undo_last_mcp_change',
    ];

    const TIER4_TOOLS = [
        'webcareproscan_delete_quarantined_file',
        'webcareproscan_set_containment_mode',
        'webcareproscan_grant_ephemeral_elevation',
        'webcareproscan_quarantine_supply_chain_anchor',
    ];

    const TIER3_TOOLS = [
        'webcareproscan_apply_htaccess_hardening',
        'webcareproscan_restore_quarantined_file',
        'webcareproscan_repair_official_file',
        'webcareproscan_rollback_remediation',
        'webcareproscan_deploy_virtual_patch',
        'webcareproscan_deploy_synthesized_patch',
        'webcareproscan_recalibrate_sbom_baseline',
        'webcareproscan_revoke_user_session',
        'webcareproscan_apply_recommended_modular_rules',
        'webcareproscan_toggle_modular_autopilot',
        'webcareproscan_toggle_cron_task',
    ];

    const AUDIT_OPTION_KEY  = 'webcareproscan_mcp_audit_log';
    const MAX_AUDIT_LOGS    = 150;
    const STAGED_OPTION_KEY = 'webcareproscan_mcp_staged_actions';
    const MAX_STAGED_ACTIONS = 100;

    /**
     * Build map of all registered valid tools (core + dynamic ModuleRegistry).
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_registered_tool_map(): array {
        $map = [];
        foreach (self::READ_TOOLS as $rt) {
            $map[$rt] = ['name' => $rt, 'isMutating' => false, 'tier' => 1];
        }
        foreach (self::MUTATING_TOOLS as $mt) {
            $tier = in_array($mt, self::TIER4_TOOLS, true) ? 4 : (in_array($mt, self::TIER3_TOOLS, true) ? 3 : 2);
            $map[$mt] = ['name' => $mt, 'isMutating' => true, 'tier' => $tier];
        }
        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            foreach (\WebCareProScanner\Core\ModuleRegistry::get_mcp_tools() as $mod_t) {
                $t_name = (string) ($mod_t['name'] ?? '');
                if ($t_name !== '') {
                    $is_mut = !empty($mod_t['isMutating']);
                    $tier   = isset($mod_t['tier']) ? (int) $mod_t['tier'] : ($is_mut ? (in_array($t_name, self::TIER3_TOOLS, true) ? 3 : 2) : 1);
                    $map[$t_name] = ['name' => $t_name, 'isMutating' => $is_mut, 'tier' => $tier];
                }
            }
        }
        return $map;
    }

    /**
     * Classify a tool into Risk Tier 1 (Read), 2 (Reversible), 3 (Sensitive), or 4 (Destructive).
     */
    public static function get_tool_tier(string $tool, array $args = []): int {
        $map  = self::get_registered_tool_map();
        $base = (int) ($map[$tool]['tier'] ?? (in_array($tool, self::READ_TOOLS, true) ? 1 : 2));

        // Dynamic tier escalation based on call arguments
        if ($tool === 'webcareproscan_toggle_or_delete_custom_rule' && ($args['action'] ?? '') === 'delete') {
            return 4;
        }
        if ($tool === 'webcareproscan_manage_ip_access' && in_array($args['action'] ?? '', ['unban', 'whitelist'], true)) {
            return 3;
        }
        if ($tool === 'webcareproscan_sync_cloudflare_ip_ban' && ($args['action'] ?? '') === 'unban') {
            return 3;
        }
        if ($tool === 'webcareproscan_save_custom_visual_rule') {
            $check = MCPAntiLockoutValidator::validate_custom_rule($args);
            if ((int) ($check['escalate_tier'] ?? 0) > $base) {
                $base = (int) $check['escalate_tier'];
            }
            if (($args['action_type'] ?? '') === 'allow') {
                $base = max($base, 3);
            }
        }
        if ($tool === 'webcareproscan_update_plugin_settings' && !empty($args['updates']) && is_array($args['updates'])) {
            $res = MCPSettingsPolicy::validate_and_classify_update($args['updates']);
            if (!empty($res['max_tier']) && (int) $res['max_tier'] > $base) {
                $base = (int) $res['max_tier'];
            }
        }

        return $base;
    }

    /**
     * Compute SHA-256 session token hash from Bearer header or client IP.
     *
     * @return string
     */
    public static function get_current_session_token_hash(): string {
        $auth_header = isset($_SERVER['HTTP_AUTHORIZATION'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']))
            : (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) : '');
        if (!empty($auth_header) && preg_match('/Bearer\s+(\S+)/i', $auth_header, $m)) {
            return hash('sha256', $m[1]);
        }
        $ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');
        return hash('sha256', 'mcp_session_' . $ip);
    }

    /**
     * Check if the current MCP session is marked as tainted by untrusted external evidence.
     *
     * @return bool
     */
    public static function is_session_tainted(): bool {
        $hash = self::get_current_session_token_hash();
        return (bool) get_transient('webcareproscan_mcp_tainted_' . $hash);
    }

    /**
     * Mark the current MCP session as tainted for the given TTL (default: 120s).
     *
     * @param int $ttl
     * @return void
     */
    public static function mark_session_tainted(int $ttl = 120): void {
        $hash = self::get_current_session_token_hash();
        set_transient('webcareproscan_mcp_tainted_' . $hash, time(), $ttl);
    }

    /**
     * Enforce Boundary 2: Scoped Token Authorization hard ceilings.
     *
     * @param string               $tool
     * @param array<string, mixed> $args
     * @param int                  $dynamic_tier
     * @return array{allowed: bool, force_stage: bool, reason: string}
     */
    public static function verify_mcp_permission(string $tool, array $args = [], int $dynamic_tier = 1): array {
        $catalog = self::get_registered_tool_map();
        $is_mut  = !empty($catalog[$tool]['isMutating']);
        $scope   = SettingsManager::get('mcp_permission_scope', 'read_only');
        $persona = SettingsManager::get('mcp_persona_preset', 'guided');

        // Normalize effective scope
        $effective_scope = $scope;
        if ($scope === 'read_only' || $persona === 'observer') {
            $effective_scope = 'read_only';
        } elseif ($scope === 'staged_proposer') {
            $effective_scope = 'staged_proposer';
        } elseif ($scope === 'safe_operator' || $persona === 'safe_operator') {
            $effective_scope = 'safe_operator';
        }

        // Scope 1: read_only - Tier 1 tools only (zero mutating actions)
        if ($effective_scope === 'read_only') {
            if ($is_mut || $dynamic_tier > 1) {
                return [
                    'allowed'     => false,
                    'force_stage' => false,
                    'reason'      => sprintf(
                        /* translators: %s: tool name */
                        __('Scope Violation: MCP token scope is "read_only". Mutating tool "%s" is blocked.', 'webcare-pro-security'),
                        $tool
                    ),
                ];
            }
            return ['allowed' => true, 'force_stage' => false, 'reason' => ''];
        }

        // Scope 2: staged_proposer - Tier 1 reads + Tier 2-4 staged proposals only (zero live unconfirmed writes)
        if ($effective_scope === 'staged_proposer') {
            if ($is_mut || $dynamic_tier > 1) {
                return [
                    'allowed'     => true,
                    'force_stage' => true,
                    'reason'      => __('Scope Policy: "staged_proposer" requires all mutating actions to be staged for human review.', 'webcare-pro-security'),
                ];
            }
            return ['allowed' => true, 'force_stage' => false, 'reason' => ''];
        }

        // Scope 3: safe_operator - Tier 1 + Tier 2 reversible tools; Tier 3+ always staged
        if ($effective_scope === 'safe_operator') {
            if ($dynamic_tier >= 3) {
                return [
                    'allowed'     => true,
                    'force_stage' => true,
                    'reason'      => __('Scope Policy: "safe_operator" requires all Tier 3+ actions to be staged for human review.', 'webcare-pro-security'),
                ];
            }
            return ['allowed' => true, 'force_stage' => false, 'reason' => ''];
        }

        return ['allowed' => true, 'force_stage' => false, 'reason' => ''];
    }

    /**
     * Retrieve current tool policy: 'allowed' | 'confirmation_required' | 'blocked' | 'unknown'.
     *
     * @param string $tool
     * @return string
     */
    public static function get_tool_policy(string $tool): string {
        $catalog = self::get_registered_tool_map();
        if (!isset($catalog[$tool])) {
            return 'unknown';
        }

        $meta   = $catalog[$tool];
        $is_mut = !empty($meta['isMutating']);
        $tier   = (int) ($meta['tier'] ?? ($is_mut ? 2 : 1));
        $scope  = SettingsManager::get('mcp_permission_scope', 'read_only');

        if ($scope === 'read_only' && $is_mut) {
            return 'blocked';
        }
        if ($scope === 'staged_proposer' && $is_mut) {
            return 'confirmation_required';
        }
        if ($scope === 'safe_operator' && $tier >= 3) {
            return 'confirmation_required';
        }

        $matrix = SettingsManager::get('mcp_tool_matrix', []);
        if (is_array($matrix) && isset($matrix[$tool])) {
            $pol = $matrix[$tool];
            if ($tier >= 4 && $pol === 'allowed') {
                return 'confirmation_required';
            }
            return $pol;
        }

        if (!$is_mut || $tool === 'webcareproscan_run_security_drill') {
            return 'allowed';
        }

        return 'confirmation_required';
    }

    /**
     * Retrieve the MCP tools catalog with JSON schemas, safety classifications, and active governance policies.
     *
     * @return array
     */
    public static function get_tools_catalog(): array {
        $scope = SettingsManager::get('mcp_permission_scope', 'read_only');

        $tools = [
            [
                'name'        => 'webcareproscan_get_security_posture',
                'description' => 'Retrieve comprehensive WordPress security posture, risk score, vulnerability metrics, firewall status, and baseline health.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_security_posture'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_list_findings',
                'description' => 'Query current vulnerability and malware findings with filtering by severity, status, or engine.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_list_findings'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'severity' => [
                            'type'        => 'string',
                            'enum'        => ['all', 'critical', 'high', 'medium', 'low', 'info'],
                            'description' => 'Filter by issue severity (default: all)',
                        ],
                        'status' => [
                            'type'        => 'string',
                            'enum'        => ['open', 'ignored', 'quarantined', 'repaired', 'all'],
                            'description' => 'Filter by issue status (default: open)',
                        ],
                        'limit' => [
                            'type'        => 'integer',
                            'description' => 'Maximum findings to return (1-100, default 25)',
                        ],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_audit_behavioral_baseline',
                'description' => 'Execute an instant behavioral baseline audit to detect hook injections, rogue cron tasks, or backdoor drop-ins.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_audit_behavioral_baseline'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_get_containment_status',
                'description' => 'Retrieve active status of Emergency Containment Mode, blast-radius freeze policies, and session termination telemetry.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_containment_status'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_list_staged_actions',
                'description' => 'List pending AI agent mutation actions awaiting human administrator approval in the Staged Action Queue.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_list_staged_actions'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'status' => [
                            'type'        => 'string',
                            'enum'        => ['pending_approval', 'approved', 'rejected', 'all'],
                            'description' => 'Filter by approval status (default: pending_approval)',
                        ],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_whitelist_finding',
                'description' => 'Suppress false-positive finding by exact SHA-256 hash-lock, file path, or issue signature with audit reason.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_whitelist_finding'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'target_path' => [
                            'type'        => 'string',
                            'description' => 'Relative file path under WordPress root (e.g. wp-content/plugins/custom/lib.php)',
                        ],
                        'rule_type' => [
                            'type'        => 'string',
                            'enum'        => ['file_hash', 'file_path', 'issue_type'],
                            'description' => 'Type of whitelist matching (file_hash is strongest: auto-invalidates if modified)',
                        ],
                        'duration' => [
                            'type'        => 'string',
                            'enum'        => ['30_days', '90_days', 'permanent'],
                            'description' => 'Suppression lifespan before re-audit is required',
                        ],
                        'reason' => [
                            'type'        => 'string',
                            'description' => 'Administrator explanation for whitelisting this code/file',
                        ],
                        'issue_id' => [
                            'type'        => 'integer',
                            'description' => 'Optional database issue ID to immediately mark as ignored',
                        ],
                    ],
                    'required' => ['target_path', 'reason'],
                ],
            ],
            [
                'name'        => 'webcareproscan_rollback_remediation',
                'description' => 'Perform 1-click safe rollback of a previous remediation transaction, restoring original byte-for-byte files and DB states.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_rollback_remediation'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'tx_id' => [
                            'type'        => 'string',
                            'description' => 'Remediation transaction ID (e.g. tx_20261017_123456_abcdef)',
                        ],
                    ],
                    'required' => ['tx_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_deploy_virtual_patch',
                'description' => 'Apply or remove an edge/runtime virtual patch rule for a known CVE without waiting for upstream plugin updates.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_deploy_virtual_patch'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'rule_id' => [
                            'type'        => 'string',
                            'description' => 'Virtual patch identifier (e.g. vp_cve_2024_27956)',
                        ],
                        'action' => [
                            'type'        => 'string',
                            'enum'        => ['apply', 'remove'],
                            'description' => 'Apply or deactivate the patch rule',
                        ],
                    ],
                    'required' => ['rule_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_quarantine_file',
                'description' => 'Safely isolate a malicious file into the encrypted quarantine vault with automatic pre-remediation transactional backup.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_quarantine_file'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'file_path' => [
                            'type'        => 'string',
                            'description' => 'Relative file path under WordPress root to quarantine',
                        ],
                        'issue_id' => [
                            'type'        => 'integer',
                            'description' => 'Optional scan issue ID associated with this file',
                        ],
                    ],
                    'required' => ['file_path'],
                ],
            ],
            [
                'name'        => 'webcareproscan_run_security_drill',
                'description' => 'Execute a safe, self-contained Red Team penetration drill simulating SQLi, LFI, XSS, Recon, and AI Prompt-Injection to measure real-time WAF defensibility score (0-100%).',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_run_security_drill'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'vectors' => [
                            'type'        => 'array',
                            'items'       => ['type' => 'string'],
                            'description' => 'Optional specific vector IDs to test. Default runs full suite.',
                        ],
                    ],
                ],
            ],
            [
                'name'        => 'webcareproscan_set_containment_mode',
                'description' => 'Activate or deactivate Emergency Containment Mode to freeze the blast radius during an active security incident.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_set_containment_mode'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'action' => [
                            'type'        => 'string',
                            'enum'        => ['activate', 'deactivate'],
                            'description' => 'Containment action to perform',
                        ],
                        'reason' => [
                            'type'        => 'string',
                            'description' => 'Explanation or incident reference for activating containment',
                        ],
                        'maintenance_page' => [
                            'type'        => 'boolean',
                            'description' => 'Serve public 503 Security Maintenance page for non-admin visitors (default: false)',
                        ],
                    ],
                    'required' => ['action'],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_supply_chain_sbom',
                'description' => 'Retrieve Software Bill of Materials (SBOM) tracking standard/custom drop-ins, mu-plugins, autoloaders, and PHP INI directives with drift detection.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_supply_chain_sbom'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_get_gatekeeper_history',
                'description' => 'Retrieve history of plugin update differential integrity audits, blocked updates, and available pre-update rollback snapshots.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_gatekeeper_history'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_recalibrate_sbom_baseline',
                'description' => 'Calibrate a new clean cryptographic SHA-256 baseline of all active drop-ins and runtime anchors.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_recalibrate_sbom_baseline'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_quarantine_supply_chain_anchor',
                'description' => 'Quarantine an unauthorized, rogue, or modified drop-in or must-use plugin to the WebCare Vault.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_quarantine_supply_chain_anchor'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'item_id' => [
                            'type'        => 'string',
                            'description' => 'Item ID to quarantine (e.g. "dropin:db.php" or "mu:loader.php")',
                        ],
                    ],
                    'required' => ['item_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_behavioral_waf_status',
                'description' => 'Retrieve Behavioral WAF telemetry: Learning Mode 2.0 route profiles, confidence scores, Honey-Token bot traps, and Adaptive Rate Limiter stats.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_behavioral_waf_status'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_set_route_learning_status',
                'description' => 'Manually change the behavioral learning status of a specific route ("graduate", "enforce", "learn", or "reset").',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_set_route_learning_status'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'route_key' => [
                            'type'        => 'string',
                            'description' => 'Route identifier (e.g. "rest:/wp/v2/posts", "ajax:action_name", "admin:options.php", "frontend:public")',
                        ],
                        'action'    => [
                            'type'        => 'string',
                            'enum'        => ['graduate', 'enforce', 'learn', 'reset'],
                            'description' => 'Action to perform on the route profile',
                        ],
                    ],
                    'required' => ['route_key', 'action'],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_identity_forensics',
                'description' => 'Retrieve Zero-Trust Identity forensics: active privileged sessions with 0-100% risk scores, Impossible Travel alerts, JIT Ephemeral Admin elevations, and HIBP breach status.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_identity_forensics'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_revoke_user_session',
                'description' => 'Revoke a specific authenticated session token or all sessions for a compromised user account.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_revoke_user_session'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'user_id'  => [
                            'type'        => 'integer',
                            'description' => 'User ID whose session is to be revoked',
                        ],
                        'verifier' => [
                            'type'        => 'string',
                            'description' => 'Session verifier hash or "all" to terminate all sessions for the user',
                        ],
                    ],
                    'required' => ['user_id', 'verifier'],
                ],
            ],
            [
                'name'        => 'webcareproscan_grant_ephemeral_elevation',
                'description' => 'Temporarily elevate a user (e.g. editor or contractor) to administrator for a defined time window with auto-expiry via WP-Cron.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_grant_ephemeral_elevation'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'user_id'          => [
                            'type'        => 'integer',
                            'description' => 'User ID to elevate',
                        ],
                        'duration_minutes' => [
                            'type'        => 'integer',
                            'description' => 'Duration in minutes (e.g. 60, 240, 1440)',
                            'default'     => 60,
                        ],
                        'reason'           => [
                            'type'        => 'string',
                            'description' => 'Justification for elevation (e.g. "Emergency bugfix")',
                        ],
                    ],
                    'required' => ['user_id', 'duration_minutes'],
                ],
            ],
            [
                'name'        => 'webcareproscan_revoke_ephemeral_elevation',
                'description' => 'Immediately revoke temporary JIT administrator elevation and revert user to their baseline role.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_revoke_ephemeral_elevation'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'user_id' => [
                            'type'        => 'integer',
                            'description' => 'User ID whose elevation is to be revoked',
                        ],
                        'reason'  => [
                            'type'        => 'string',
                            'description' => 'Revocation reason',
                        ],
                    ],
                    'required' => ['user_id'],
                ],
            ],
            [
                'name'        => 'webcareproscan_get_threat_intel_network',
                'description' => 'Retrieve live multi-feed threat intelligence telemetry, active botnet blacklist counts, Tor exit relays, attack consensus hash ring, and top attacking subnets.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_get_threat_intel_network'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_sync_threat_intel',
                'description' => 'Trigger real-time synchronization and aggregation of all 4 external threat intelligence community feeds (Ipsum L1/L2, Blocklist.de, Tor Exits).',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_sync_threat_intel'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'webcareproscan_synthesize_virtual_patch',
                'description' => 'Synthesize a custom two-tier virtual hotpatch rule (PHP WAF regex + Cloudflare Free Edge expression) with immediate in-memory synthetic payload dry-run benchmark.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_synthesize_virtual_patch'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'cve_id'      => [
                            'type'        => 'string',
                            'description' => 'CVE or vulnerability identifier (e.g. CVE-2024-99999 or HOTPATCH-CUSTOM)',
                        ],
                        'component'   => [
                            'type'        => 'string',
                            'description' => 'Target plugin or theme component slug (e.g. elementor, give, custom-plugin)',
                        ],
                        'vector_type' => [
                            'type'        => 'string',
                            'enum'        => ['sqli', 'rce', 'file_upload', 'auth_bypass', 'path_traversal', 'ssrf', 'custom'],
                            'description' => 'Vulnerability exploit vector',
                        ],
                        'target_uris' => [
                            'type'        => 'string',
                            'description' => 'Comma-separated target URI paths (e.g. /wp-admin/admin-ajax.php, /wp-json/)',
                        ],
                        'parameters'  => [
                            'type'        => 'string',
                            'description' => 'Comma-separated vulnerable parameter names (e.g. id, action, file)',
                        ],
                        'custom_regex'=> [
                            'type'        => 'string',
                            'description' => 'Optional explicit regular expression override',
                        ],
                        'severity'    => [
                            'type'        => 'string',
                            'enum'        => ['critical', 'high', 'medium'],
                            'default'     => 'high',
                        ],
                    ],
                    'required' => ['vector_type'],
                ],
            ],
            [
                'name'        => 'webcareproscan_test_virtual_patch',
                'description' => 'Execute an in-memory synthetic simulation against candidate virtual patch rules, testing 3 calibrated exploits and 3 benign queries to benchmark match rate and latency.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('webcareproscan_test_virtual_patch'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'patch' => [
                            'type'        => 'object',
                            'description' => 'Virtual patch object containing php_rule with regex',
                        ],
                    ],
                    'required' => ['patch'],
                ],
            ],
            [
                'name'        => 'webcareproscan_deploy_synthesized_patch',
                'description' => 'Deploy, activate, toggle, or delete a synthesized virtual hotpatch with optional Cloudflare Global Edge synchronization.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('webcareproscan_deploy_synthesized_patch'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'action'                => [
                            'type'        => 'string',
                            'enum'        => ['deploy', 'toggle', 'delete'],
                            'description' => 'Action to perform',
                        ],
                        'patch_id'              => [
                            'type'        => 'string',
                            'description' => 'Synthesized patch identifier',
                        ],
                        'patch'                 => [
                            'type'        => 'object',
                            'description' => 'Synthesized patch definition (required for deploy)',
                        ],
                        'enable'                => [
                            'type'        => 'boolean',
                            'description' => 'Enable or disable state (for toggle action)',
                        ],
                        'deploy_to_cloudflare'  => [
                            'type'        => 'boolean',
                            'description' => 'Push rule to Cloudflare Global Edge WAF (if configured)',
                            'default'     => false,
                        ],
                    ],
                    'required' => ['action'],
                ],
            ],
        ];

        foreach ($tools as &$base_t) {
            if (!isset($base_t['tier'])) {
                $base_t['tier'] = self::get_tool_tier((string) ($base_t['name'] ?? ''));
            }
        }
        unset($base_t);

        if (class_exists(MCPExtendedTools::class)) {
            foreach (MCPExtendedTools::get_tool_definitions() as $ext_tool) {
                $t_name          = (string) $ext_tool['name'];
                $ext_tool['policy'] = self::get_tool_policy($t_name);
                $tools[]         = $ext_tool;
            }
        }

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            foreach (\WebCareProScanner\Core\ModuleRegistry::get_mcp_tools() as $mod_tool) {
                $t_name = sanitize_text_field((string) ($mod_tool['name'] ?? ''));
                if ($t_name === '') {
                    continue;
                }
                $is_mut  = !empty($mod_tool['isMutating']);
                $t_pol   = ($scope === 'read_only' && $is_mut) ? 'blocked' : self::get_tool_policy($t_name);
                $tools[] = [
                    'name'        => $t_name,
                    'description' => sanitize_text_field((string) ($mod_tool['description'] ?? '')),
                    'category'    => sanitize_key((string) ($mod_tool['category'] ?? ($is_mut ? 'mutating' : 'read'))),
                    'tier'        => isset($mod_tool['tier']) ? (int) $mod_tool['tier'] : ($is_mut ? 2 : 1),
                    'isMutating'  => $is_mut,
                    'policy'      => $t_pol,
                    'inputSchema' => is_array($mod_tool['inputSchema'] ?? null)
                        ? $mod_tool['inputSchema']
                        : ['type' => 'object', 'properties' => new \stdClass()],
                ];
            }
        }

        return [
            'scope'         => $scope,
            'personaPreset' => (string) SettingsManager::get('mcp_persona_preset', 'guided'),
            'isReadOnly'    => ($scope === 'read_only'),
            'tools'         => $tools,
        ];
    }

    /**
     * Check rate limiting for MCP requests (sliding window).
     *
     * @param string $identifier
     * @param int $limit_per_min
     * @return bool True if permitted, false if rate limit exceeded.
     */
    public static function check_rate_limit(string $identifier, int $limit_per_min = 60): bool {
        $transient_key = 'webcareproscan_mcp_rl_' . substr(md5($identifier), 0, 16);
        $current = (int) get_transient($transient_key);
        if ($current >= $limit_per_min) {
            return false;
        }
        set_transient($transient_key, $current + 1, 60);
        return true;
    }

    /**
     * Log an MCP execution event to persistent ring-buffer audit log.
     *
     * @param array $entry
     */
    public static function log_audit_event(array $entry): void {
        $logs = get_option(self::AUDIT_OPTION_KEY, []);
        if (!is_array($logs)) {
            $logs = [];
        }
        array_unshift($logs, $entry);
        if (count($logs) > self::MAX_AUDIT_LOGS) {
            $logs = array_slice($logs, 0, self::MAX_AUDIT_LOGS);
        }
        update_option(self::AUDIT_OPTION_KEY, $logs, false);
    }

    /**
     * Retrieve recent audit log entries.
     *
     * @param int $limit
     * @return array
     */
    public static function get_audit_log(int $limit = 50): array {
        $logs = get_option(self::AUDIT_OPTION_KEY, []);
        if (!is_array($logs)) {
            return [];
        }
        return array_slice($logs, 0, $limit);
    }

    /**
     * Clear the MCP audit log.
     *
     * @return bool
     */
    public static function clear_audit_log(): bool {
        return delete_option(self::AUDIT_OPTION_KEY);
    }

    /**
     * Sanitize, redact secrets, and summarize arguments for safe audit logging.
     *
     * @param array $args
     * @return string
     */
    private static function summarize_args(array $args): string {
        if (empty($args)) {
            return '{}';
        }
        $clean = self::redact_recursive($args);
        return (string) wp_json_encode($clean);
    }

    /**
     * Recursively mask secret keys and truncate overly long strings before audit storage.
     *
     * @param mixed $data
     * @param int   $depth
     * @return mixed
     */
    private static function redact_recursive($data, int $depth = 0) {
        if ($depth > 4) {
            return '[DEPTH_LIMIT]';
        }
        if (is_array($data)) {
            $out = [];
            foreach ($data as $k => $v) {
                if (preg_match('/(?:pass|token|secret|key|auth|webhook|cookie|nonce|pwd)/i', (string) $k)) {
                    $out[$k] = '[REDACTED]';
                } elseif (is_array($v) && $depth >= 2) {
                    $out[$k] = '[Array(' . count($v) . ')]';
                } else {
                    $out[$k] = self::redact_recursive($v, $depth + 1);
                }
            }
            return $out;
        }
        if (is_string($data) && strlen($data) > 60) {
            return substr($data, 0, 57) . '...';
        }
        return $data;
    }

    /**
     * Execute an MCP tool by name with arguments, rate limiting, governance checks, staged gates, and audit logging.
     *
     * @param string $tool
     * @param array  $args
     * @param bool   $bypass_gate If true, executes without checking confirmation_required policy (e.g. human approved)
     * @return array
     */
    public static function execute_tool(string $tool, array $args = [], bool $bypass_gate = false): array {
        $start_time = microtime(true);
        $tool       = sanitize_text_field($tool);

        $client_ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $raw_ua     = isset($_SERVER['HTTP_USER_AGENT']) ? (string) wp_unslash($_SERVER['HTTP_USER_AGENT']) : '';
        $user_agent = $raw_ua !== '' ? sanitize_text_field(substr($raw_ua, 0, 120)) : 'Unknown AI Agent';

        // 0. Reject unknown tools & block self-approval calls immediately (never stage)
        if ($tool === 'webcareproscan_approve_staged_action') {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => __('Staged actions can only be approved inside the WP Admin Console.', 'webcare-pro-security')]],
            ];
        }

        $catalog_map = self::get_registered_tool_map();
        if (!isset($catalog_map[$tool])) {
            self::log_audit_event([
                'id'          => uniqid('mcp_', true),
                'timestamp'   => time(),
                'client_ip'   => $client_ip,
                'user_agent'  => $user_agent,
                'tool'        => $tool,
                'args'        => self::summarize_args($args),
                'duration_ms' => round((microtime(true) - $start_time) * 1000, 2),
                'status'      => 'denied_unknown_tool',
                'message'     => 'Unknown or unregistered MCP tool rejected',
            ]);
            return [
                'isError' => true,
                'content' => [
                    [
                        'type' => 'text',
                        /* translators: %s: MCP tool name */
                        'text' => sprintf(__('Unknown or unregistered MCP tool "%s".', 'webcare-pro-security'), $tool),
                    ],
                ],
            ];
        }

        // 1. Sliding-window rate limit check
        $rate_limit = (int) SettingsManager::get('mcp_rate_limit_per_min', 60);
        if (!self::check_rate_limit($client_ip, $rate_limit)) {
            $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
            self::log_audit_event([
                'id'          => uniqid('mcp_', true),
                'timestamp'   => time(),
                'client_ip'   => $client_ip,
                'user_agent'  => $user_agent,
                'tool'        => $tool,
                'args'        => self::summarize_args($args),
                'duration_ms' => $duration_ms,
                'status'      => 'rate_limited',
                'message'     => sprintf('Rate limit exceeded (>%d req/min)', $rate_limit),
            ]);

            return [
                'isError' => true,
                'content' => [
                    [
                        'type' => 'text',
                        /* translators: %d: request rate limit count */
                        'text' => sprintf(__('Rate limit exceeded: Maximum %d requests per minute allowed for MCP Agent tools.', 'webcare-pro-security'), $rate_limit),
                    ],
                ],
            ];
        }

        // 2. Payload Validation & Anti-Lockout Invariants before policy/staging
        $preflight = self::preflight_guardrails($tool, $args);
        if (!empty($preflight['reject'])) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => (string) $preflight['message']]],
                'result'  => ['success' => false, 'message' => (string) $preflight['message']],
            ];
        }

        // 3. Tool Governance & Dynamic Risk-Tier Enforcement
        $policy       = self::get_tool_policy($tool);
        $dynamic_tier = self::get_tool_tier($tool, $args);
        if (!empty($preflight['escalate_tier']) && (int) $preflight['escalate_tier'] > $dynamic_tier) {
            $dynamic_tier = (int) $preflight['escalate_tier'];
        }

        // Boundary 2: Scoped Token Authorization Check
        $scope_check = self::verify_mcp_permission($tool, $args, $dynamic_tier);
        if (!$scope_check['allowed']) {
            $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
            self::log_audit_event([
                'id'          => uniqid('mcp_', true),
                'timestamp'   => time(),
                'client_ip'   => $client_ip,
                'user_agent'  => $user_agent,
                'tool'        => $tool,
                'args'        => self::summarize_args($args),
                'duration_ms' => $duration_ms,
                'status'      => 'denied_scope_ceiling',
                'message'     => $scope_check['reason'],
            ]);

            return [
                'isError' => true,
                'content' => [
                    [
                        'type' => 'text',
                        'text' => $scope_check['reason'],
                    ],
                ],
            ];
        }

        if ($policy === 'blocked') {
            $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
            self::log_audit_event([
                'id'          => uniqid('mcp_', true),
                'timestamp'   => time(),
                'client_ip'   => $client_ip,
                'user_agent'  => $user_agent,
                'tool'        => $tool,
                'args'        => self::summarize_args($args),
                'duration_ms' => $duration_ms,
                'status'      => 'denied_policy_blocked',
                'message'     => 'Action blocked by tool governance policy',
            ]);

            return [
                'isError' => true,
                'content' => [
                    [
                        'type' => 'text',
                        /* translators: %s: MCP tool name */
                        'text' => sprintf(__('Permission Denied: Tool "%s" is blocked by administrator governance policy.', 'webcare-pro-security'), sanitize_text_field($tool)),
                    ],
                ],
            ];
        }

        $needs_gate = ($policy === 'confirmation_required');
        if (!empty($scope_check['force_stage'])) {
            $needs_gate = true;
        }
        if ($dynamic_tier >= 3 && !empty($catalog_map[$tool]['isMutating'])) {
            // Tier 3/4 sensitive payloads auto-escalate to confirmation gate unless tool policy explicitly opted in AND tier < 4
            if ($dynamic_tier >= 3 || !empty($preflight['force_stage'])) {
                $needs_gate = true;
            }
        }

        // 4. Staged Action Confirmation Gate
        if (!$bypass_gate && $needs_gate) {
            return self::stage_action_for_approval($tool, $args, $client_ip, $user_agent, $start_time, $dynamic_tier, $preflight);
        }

        // 5. Capture Authoritative Pre-Execution Undo Snapshot right before mutating execution
        if (!empty($catalog_map[$tool]['isMutating']) && $tool !== 'webcareproscan_undo_last_mcp_change' && class_exists(MCPSnapshotManager::class)) {
            $actor_label = $bypass_gate ? 'Approved Admin Session' : ('MCP Agent (' . $user_agent . ')');
            MCPSnapshotManager::capture_pre_change_snapshot($tool, $args, $actor_label, (string) ($preflight['summary'] ?? ''));
        }

        // 4. Tool Execution
        $response = null;
        switch ($tool) {
            case 'webcareproscan_get_security_posture':
                $response = self::tool_get_posture();
                break;

            case 'webcareproscan_list_findings':
                $response = self::tool_list_findings($args);
                break;

            case 'webcareproscan_audit_behavioral_baseline':
                $response = self::tool_audit_baseline();
                break;

            case 'webcareproscan_get_containment_status':
                $response = self::tool_get_containment_status();
                break;

            case 'webcareproscan_list_staged_actions':
                $response = self::tool_list_staged_actions($args);
                break;

            case 'webcareproscan_whitelist_finding':
                $response = self::tool_whitelist_finding($args);
                break;

            case 'webcareproscan_rollback_remediation':
                $response = self::tool_rollback_remediation($args);
                break;

            case 'webcareproscan_deploy_virtual_patch':
                $response = self::tool_deploy_virtual_patch($args);
                break;

            case 'webcareproscan_quarantine_file':
                $response = self::tool_quarantine_file($args);
                break;

            case 'webcareproscan_run_security_drill':
                $response = self::tool_run_security_drill($args);
                break;

            case 'webcareproscan_set_containment_mode':
                $response = self::tool_set_containment_mode($args);
                break;

            case 'webcareproscan_get_supply_chain_sbom':
                $response = self::tool_get_supply_chain_sbom();
                break;

            case 'webcareproscan_get_gatekeeper_history':
                $response = self::tool_get_gatekeeper_history();
                break;

            case 'webcareproscan_recalibrate_sbom_baseline':
                $response = self::tool_recalibrate_sbom_baseline();
                break;

            case 'webcareproscan_quarantine_supply_chain_anchor':
                $response = self::tool_quarantine_supply_chain_anchor($args);
                break;

            case 'webcareproscan_get_behavioral_waf_status':
                $response = self::tool_get_behavioral_waf_status();
                break;

            case 'webcareproscan_set_route_learning_status':
                $response = self::tool_set_route_learning_status($args);
                break;

            case 'webcareproscan_get_identity_forensics':
                $response = self::tool_get_identity_forensics();
                break;

            case 'webcareproscan_revoke_user_session':
                $response = self::tool_revoke_user_session($args);
                break;

            case 'webcareproscan_grant_ephemeral_elevation':
                $response = self::tool_grant_ephemeral_elevation($args);
                break;

            case 'webcareproscan_revoke_ephemeral_elevation':
                $response = self::tool_revoke_ephemeral_elevation($args);
                break;

            case 'webcareproscan_get_threat_intel_network':
                $response = self::tool_get_threat_intel_network();
                break;

            case 'webcareproscan_sync_threat_intel':
                $response = self::tool_sync_threat_intel();
                break;

            case 'webcareproscan_synthesize_virtual_patch':
                $response = self::tool_synthesize_virtual_patch($args);
                break;

            case 'webcareproscan_test_virtual_patch':
                $response = self::tool_test_virtual_patch($args);
                break;

            case 'webcareproscan_deploy_synthesized_patch':
                $response = self::tool_deploy_synthesized_patch($args);
                break;

            default:
                if (class_exists(MCPExtendedTools::class)) {
                    $ext_res = MCPExtendedTools::dispatch($tool, $args);
                    if (is_array($ext_res)) {
                        $response = $ext_res;
                        break;
                    }
                }
                if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
                    $mod_res = \WebCareProScanner\Core\ModuleRegistry::execute_mcp_tool($tool, $args);
                    if (is_array($mod_res)) {
                        $response = $mod_res;
                        break;
                    }
                }
                $response = [
                    'isError' => true,
                    'content' => [
                        [
                            'type' => 'text',
                            /* translators: %s: MCP tool name */
                            'text' => sprintf(__('Unknown MCP tool "%s".', 'webcare-pro-security'), sanitize_text_field($tool)),
                        ],
                    ],
                ];
                break;
        }

        $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
        $is_error = !empty($response['isError']);

        // Boundary 1: Untrusted-Data Taint Tracking
        // When an MCP read tool returns external logs, scanner findings, or security telemetry,
        // mark the session as tainted for 120 seconds to guard subsequent mutating calls.
        if (!$is_error) {
            $taint_producing_tools = [
                'webcareproscan_list_findings',
                'webcareproscan_list_waf_incidents',
                'webcareproscan_list_quarantine_items',
                'webcareproscan_get_identity_forensics',
                'webcareproscan_get_behavioral_waf_status',
                'webcareproscan_get_threat_intel_network',
                'webcareproscan_explain_finding',
                'webcareproscan_get_recent_logs',
                'webcareproscan_get_scan_results',
                'webcareproscan_get_quarantine_list',
                'webcareproscan_get_blocked_ips',
            ];
            if (in_array($tool, $taint_producing_tools, true)) {
                self::mark_session_tainted(120);
            }
        }

        self::log_audit_event([
            'id'          => uniqid('mcp_', true),
            'timestamp'   => time(),
            'client_ip'   => $client_ip,
            'user_agent'  => $user_agent,
            'tool'        => $tool,
            'args'        => self::summarize_args($args),
            'duration_ms' => $duration_ms,
            'status'      => $is_error ? 'error' : ($bypass_gate ? 'approved_executed' : 'success'),
            'message'     => $is_error ? 'Tool returned error' : 'Executed successfully',
        ]);

        return $response;
    }

    /**
     * Stage an action into the Staged Action Queue for human confirmation.
     *
     * @param string               $tool
     * @param array<string, mixed> $args
     * @param string               $client_ip
     * @param string               $user_agent
     * @param float                $start_time
     * @param int                  $risk_tier
     * @param array<string, mixed> $preflight
     * @return array<string, mixed>
     */
    public static function stage_action_for_approval(
        string $tool,
        array $args = [],
        string $client_ip = '127.0.0.1',
        string $user_agent = 'WebCare Agent Service',
        float $start_time = 0.0,
        int $risk_tier = 3,
        array $preflight = []
    ): array {
        if ($start_time <= 0.0) {
            $start_time = microtime(true);
        }
        $staged_id = 'stg_' . substr(md5(uniqid('webcare_stg_', true)), 0, 12);

        // Generate Out-of-Band Cryptographic Confirmation Token signed with site auth salt
        $salt = defined('AUTH_KEY') ? AUTH_KEY : 'webcare_mcp_default_salt';
        $confirmation_token = 'webcare_mcp_' . hash_hmac('sha256', $staged_id . '|' . $tool . '|' . time(), $salt);

        $staged_entry = [
            'id'                 => $staged_id,
            'confirmation_token' => $confirmation_token,
            'tool'               => $tool,
            'args'               => $args,
            'risk_tier'          => max(2, min(4, $risk_tier)),
            'summary'            => sanitize_text_field((string) ($preflight['summary'] ?? '')),
            'diff_preview'       => is_array($preflight['diff_preview'] ?? null) ? $preflight['diff_preview'] : [],
            'warnings'           => is_array($preflight['warnings'] ?? null) ? $preflight['warnings'] : [],
            'client_ip'          => $client_ip,
            'user_agent'         => $user_agent,
            'status'             => 'pending_approval',
            'created_at'         => time(),
            'expires_at'         => time() + 86400, // 24 hours
        ];

        $staged_list = get_option(self::STAGED_OPTION_KEY, []);
        if (!is_array($staged_list)) {
            $staged_list = [];
        }
        array_unshift($staged_list, $staged_entry);
        if (count($staged_list) > self::MAX_STAGED_ACTIONS) {
            $staged_list = array_slice($staged_list, 0, self::MAX_STAGED_ACTIONS);
        }
        update_option(self::STAGED_OPTION_KEY, $staged_list, false);

        $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
        self::log_audit_event([
            'id'          => uniqid('mcp_', true),
            'timestamp'   => time(),
            'client_ip'   => $client_ip,
            'user_agent'  => $user_agent,
            'tool'        => $tool,
            'args'        => self::summarize_args($args),
            'duration_ms' => $duration_ms,
            'status'      => 'staged_for_approval',
            'message'     => sprintf('Action staged for human approval (Tier %d, ID: %s)', $risk_tier, $staged_id),
        ]);

        return [
            'isError'            => false,
            'isStaged'           => true,
            'staged_id'          => $staged_id,
            'tool'               => $tool,
            'risk_tier'          => $staged_entry['risk_tier'],
            'status'             => 'pending_approval',
            'content'   => [
                [
                    'type' => 'text',
                    'text' => sprintf(
                        /* translators: 1: tool name, 2: staged action ID, 3: risk tier number */
                        __('Action Staged in Confirmation Gate (Tier %3$d): Tool "%1$s" requires administrator review in WP Admin. Staged Action ID: %2$s.', 'webcare-pro-security'),
                        sanitize_text_field($tool),
                        $staged_id,
                        $staged_entry['risk_tier']
                    ),
                ],
            ],
            'result' => [
                'staged_id'    => $staged_id,
                'risk_tier'    => $staged_entry['risk_tier'],
                'summary'      => $staged_entry['summary'],
                'diff_preview' => $staged_entry['diff_preview'],
                'warnings'     => $staged_entry['warnings'],
                'status'       => 'pending_approval',
                'description'  => 'Awaiting administrator confirmation in WebCare Console by an authenticated administrator session.',
            ],
        ];
    }

    /**
     * Retrieve all staged actions.
     *
     * @param string $filter_status
     * @return array
     */
    public static function get_staged_actions(string $filter_status = 'all'): array {
        $list = get_option(self::STAGED_OPTION_KEY, []);
        if (!is_array($list)) {
            return [];
        }

        if ($filter_status !== 'all') {
            $list = array_filter($list, function ($item) use ($filter_status) {
                return ($item['status'] ?? '') === $filter_status;
            });
            $list = array_values($list);
        }

        // Never leak internal confirmation tokens in staged action listings
        foreach ($list as &$item) {
            unset($item['confirmation_token']);
        }
        unset($item);

        return $list;
    }

    /**
     * Approve and execute a staged action.
     * Requires active interactive WP Admin session, valid 24h TTL, and Step-Up Auth for Tier 4.
     *
     * @param string $staged_id
     * @param int    $approver_id
     * @param string $step_up_secret Password or 2FA TOTP code for Tier 4 actions
     * @return array
     */
    public static function approve_staged_action(string $staged_id, int $approver_id = 0, string $step_up_secret = ''): array {
        $list = get_option(self::STAGED_OPTION_KEY, []);
        if (!is_array($list)) {
            return ['success' => false, 'message' => __('No staged actions found.', 'webcare-pro-security')];
        }

        $target_index = -1;
        $target_action = null;

        foreach ($list as $idx => $action) {
            if (($action['id'] ?? '') === $staged_id) {
                $target_index = $idx;
                $target_action = $action;
                break;
            }
        }

        if ($target_index === -1 || !$target_action) {
            return ['success' => false, 'message' => __('Staged action not found.', 'webcare-pro-security')];
        }

        if ($target_action['status'] !== 'pending_approval') {
            /* translators: %s: status of the action */
            return ['success' => false, 'message' => sprintf(__('Action is already %s.', 'webcare-pro-security'), $target_action['status'])];
        }

        if (!empty($target_action['expires_at']) && time() > (int) $target_action['expires_at']) {
            $list[$target_index]['status'] = 'expired';
            $list[$target_index]['confirmation_token'] = null;
            update_option(self::STAGED_OPTION_KEY, $list, false);
            return ['success' => false, 'message' => __('Staged action has expired (> 24 hours old) and cannot be executed.', 'webcare-pro-security')];
        }

        // Boundary 4: Reject any call carrying an Authorization Bearer token; require interactive admin session
        $auth_header = isset($_SERVER['HTTP_AUTHORIZATION'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']))
            : (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) : '');
        if (stripos($auth_header, 'Bearer ') === 0) {
            return [
                'success' => false,
                'message' => __('Execution Rejected: Staged actions cannot be approved via MCP Bearer token. Human confirmation in WP Admin is strictly required.', 'webcare-pro-security'),
            ];
        }

        // Must strictly be called by an interactive authenticated administrator with manage_options
        $is_admin = function_exists('is_user_logged_in') && is_user_logged_in()
            && function_exists('current_user_can') && current_user_can('manage_options');

        if (!$is_admin) {
            return [
                'success' => false,
                'message' => __('Execution Rejected: Staged actions require an active interactive WordPress administrator session.', 'webcare-pro-security'),
            ];
        }

        // Step-Up Verification for Tier 4 Destructive / Lockout-Critical Actions
        $risk_tier = (int) ($target_action['risk_tier'] ?? self::get_tool_tier((string) ($target_action['tool'] ?? ''), is_array($target_action['args'] ?? null) ? $target_action['args'] : []));
        if ($risk_tier >= 4) {
            $uid = $approver_id > 0 ? $approver_id : get_current_user_id();
            $step_up_ok = false;
            $has_2fa = class_exists(TwoFactorAuth::class) && TwoFactorAuth::is_user_enabled($uid);
            if ($step_up_secret !== '') {
                if ($has_2fa) {
                    $secret = TwoFactorAuth::get_user_secret($uid);
                    $algo   = TwoFactorAuth::get_user_algorithm($uid);
                    $digits = TwoFactorAuth::get_user_digits($uid);
                    if (!empty($secret) && TwoFactorAuth::verify_code($secret, $step_up_secret, 1, $algo, $digits)) {
                        $step_up_ok = true;
                    } elseif (TwoFactorAuth::verify_and_consume_backup_code($uid, $step_up_secret)) {
                        $step_up_ok = true;
                    }
                }
                if (!$step_up_ok) {
                    $user_obj = get_userdata($uid);
                    if ($user_obj && wp_check_password($step_up_secret, $user_obj->user_pass, $uid)) {
                        $step_up_ok = true;
                    }
                }
            }
            if (!$step_up_ok) {
                return [
                    'success'         => false,
                    'step_up_required'=> true,
                    'has_2fa'         => $has_2fa,
                    'risk_tier'       => $risk_tier,
                    'message'         => $has_2fa
                        ? __('Tier 4 Destructive Action: Please confirm with your 2FA TOTP code or WordPress administrator password.', 'webcare-pro-security')
                        : __('Tier 4 Destructive Action: Please confirm with your WordPress administrator password.', 'webcare-pro-security'),
                ];
            }
        }

        // Single-Use Atomic Invalidation: Mark token as consumed immediately before executing the tool to prevent replay attacks
        $list[$target_index]['status']      = 'executing';
        $list[$target_index]['consumed_at'] = time();
        $list[$target_index]['confirmation_token'] = null; // Invalidate token immediately
        update_option(self::STAGED_OPTION_KEY, $list, false);

        // Execute the tool with gate bypass
        $exec_result = self::execute_tool($target_action['tool'], $target_action['args'], true);

        // Update staged action record
        $current_user = get_userdata($approver_id);
        $approver_name = ($current_user && $current_user->exists()) ? $current_user->user_login : 'administrator';

        $list[$target_index]['status']      = 'approved';
        $list[$target_index]['approved_at'] = time();
        $list[$target_index]['approved_by'] = $approver_name;
        $list[$target_index]['exec_result'] = $exec_result;

        update_option(self::STAGED_OPTION_KEY, $list, false);

        return [
            'success'     => true,
            'staged_id'   => $staged_id,
            'exec_result' => $exec_result,
            'message'     => __('Staged action approved and executed successfully.', 'webcare-pro-security'),
        ];
    }

    /**
     * Reject a staged action.
     *
     * @param string $staged_id
     * @param int    $rejector_id
     * @return array
     */
    public static function reject_staged_action(string $staged_id, int $rejector_id = 0): array {
        $list = get_option(self::STAGED_OPTION_KEY, []);
        if (!is_array($list)) {
            return ['success' => false, 'message' => __('No staged actions found.', 'webcare-pro-security')];
        }

        $found = false;
        $current_user = get_userdata($rejector_id);
        $rejector_name = ($current_user && $current_user->exists()) ? $current_user->user_login : 'administrator';

        foreach ($list as $idx => $action) {
            if (($action['id'] ?? '') === $staged_id) {
                $list[$idx]['status']      = 'rejected';
                $list[$idx]['rejected_at'] = time();
                $list[$idx]['rejected_by'] = $rejector_name;
                $found = true;
                break;
            }
        }

        if (!$found) {
            return ['success' => false, 'message' => __('Staged action not found.', 'webcare-pro-security')];
        }

        update_option(self::STAGED_OPTION_KEY, $list, false);

        return [
            'success'   => true,
            'staged_id' => $staged_id,
            'message'   => __('Staged action rejected.', 'webcare-pro-security'),
        ];
    }

    // ==========================================
    // Tool Execution Implementations
    // ==========================================

    private static function tool_get_posture(): array {
        $scorer = new RiskScorer();
        $health = $scorer->get_site_health();
        $baseline_drift = BehavioralBaselineEngine::audit_baseline();

        $waf_enabled = (bool) SettingsManager::get('waf_enabled', true);
        $containment_active = EmergencyContainmentManager::is_active();

        $data = [
            'risk_score'         => $health['risk_score'],
            'grade'              => $health['grade'],
            'status'             => $health['status'],
            'total_issues'       => $health['total_issues'],
            'critical_count'     => $health['critical_count'],
            'high_count'         => $health['high_count'],
            'waf_status'         => $waf_enabled ? 'active' : 'disabled',
            'containment_mode'   => $containment_active ? 'active' : 'normal',
            'baseline_has_drift' => !empty($baseline_drift['has_drift']),
            'drift_count'        => count($baseline_drift['drifts'] ?? []),
            'timestamp'          => current_time('mysql'),
        ];

        return [
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($data, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $data,
        ];
    }

    private static function tool_list_findings(array $args): array {
        global $wpdb;

        $table = $wpdb->prefix . 'webcareproscan_scan_issues';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table)) !== $table) {
            return [
                'content' => [['type' => 'text', 'text' => '[]']],
                'result'  => [],
            ];
        }

        $severity = sanitize_text_field($args['severity'] ?? 'all');
        $status   = sanitize_text_field($args['status'] ?? 'open');
        $limit    = max(1, min(100, intval($args['limit'] ?? 25)));

        $where = ['1=1'];
        $params = [];

        if ($severity !== 'all') {
            $where[] = 'severity = %s';
            $params[] = $severity;
        }

        if ($status !== 'all') {
            $where[] = 'status = %s';
            $params[] = $status;
        }

        $sql = "SELECT id, engine, type, severity, confidence, file_path, line_number, description, status, created_at FROM {$table} WHERE " . implode(' AND ', $where) . " ORDER BY id DESC LIMIT %d";
        $params[] = $limit;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results($wpdb->prepare($sql, ...$params), ARRAY_A) ?: [];

        return [
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($rows, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $rows,
        ];
    }

    private static function tool_audit_baseline(): array {
        $drift = BehavioralBaselineEngine::audit_baseline();

        return [
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($drift, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $drift,
        ];
    }

    private static function tool_get_containment_status(): array {
        $status = EmergencyContainmentManager::get_status();

        return [
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($status, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $status,
        ];
    }

    private static function tool_list_staged_actions(array $args): array {
        $status = sanitize_text_field($args['status'] ?? 'pending_approval');
        $actions = self::get_staged_actions($status);

        return [
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($actions, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $actions,
        ];
    }

    private static function tool_whitelist_finding(array $args): array {
        $target_path = sanitize_text_field($args['target_path'] ?? '');
        $rule_type   = sanitize_text_field($args['rule_type'] ?? 'file_hash');
        $duration    = sanitize_text_field($args['duration'] ?? '90_days');
        $reason      = sanitize_text_field($args['reason'] ?? 'Whitelisted autonomously by MCP Agent');
        $issue_id    = isset($args['issue_id']) ? (int) $args['issue_id'] : null;

        $res = WhitelistManager::add_rule([
            'target_path' => $target_path,
            'rule_type'   => $rule_type,
            'duration'    => $duration,
            'reason'      => $reason,
            'issue_id'    => $issue_id,
        ]);

        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_rollback_remediation(array $args): array {
        $tx_id = sanitize_text_field($args['tx_id'] ?? '');
        if (empty($tx_id)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing required parameter: tx_id']],
            ];
        }

        $res = TransactionalRemediation::rollback_transaction($tx_id);
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_deploy_virtual_patch(array $args): array {
        $rule_id = sanitize_text_field($args['rule_id'] ?? '');
        $action  = sanitize_text_field($args['action'] ?? 'apply');

        if ($action === 'apply') {
            $res = VirtualPatchManager::apply_patch($rule_id);
        } else {
            $res = VirtualPatchManager::remove_patch($rule_id);
        }

        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_quarantine_file(array $args): array {
        global $wpdb;

        $file_path = sanitize_text_field($args['file_path'] ?? '');
        $issue_id  = isset($args['issue_id']) ? (int) $args['issue_id'] : null;

        $real_path = realpath($file_path);
        if (!$real_path) {
            $candidate = wp_normalize_path(ABSPATH . ltrim($file_path, '/\\'));
            if (file_exists($candidate)) {
                $real_path = realpath($candidate);
            }
        }
        if (!$real_path || !is_file($real_path) || is_link($real_path)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Action Blocked: Target file does not exist or is a symlink.']],
                'result'  => ['success' => false, 'message' => 'Target file does not exist or is a symlink.'],
            ];
        }

        $normalized_real = wp_normalize_path($real_path);

        // Enforce strict MCP containment: require a verified malware/rogue scan issue ID when targeting any active plugin or active theme directory
        $protected_component_dirs = [];
        if (function_exists('get_stylesheet_directory')) {
            $protected_component_dirs[] = trailingslashit(wp_normalize_path(get_stylesheet_directory()));
        }
        if (function_exists('get_template_directory')) {
            $protected_component_dirs[] = trailingslashit(wp_normalize_path(get_template_directory()));
        }
        if (function_exists('wp_get_active_and_valid_plugins')) {
            foreach (wp_get_active_and_valid_plugins() as $active_plugin_file) {
                $protected_component_dirs[] = trailingslashit(wp_normalize_path(dirname($active_plugin_file)));
            }
        }

        $in_active_component = false;
        foreach (array_unique($protected_component_dirs) as $comp_dir) {
            if ($comp_dir !== '/' && strpos($normalized_real, $comp_dir) === 0) {
                $in_active_component = true;
                break;
            }
        }

        if ($in_active_component) {
            $allowed_issue = false;
            if ($issue_id && $issue_id > 0) {
                $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $issue_row = $wpdb->get_row($wpdb->prepare("SELECT type, file_path FROM `{$table_issues}` WHERE id = %d", (int) $issue_id));
                if ($issue_row && strpos((string) $issue_row->type, 'modified_') !== 0 && strpos((string) $issue_row->type, 'wp_config_') !== 0 && $issue_row->type !== 'injected_wp_config') {
                    $allowed_issue = true;
                }
            }
            if (!$allowed_issue) {
                $msg = 'Action Blocked: MCP cannot quarantine files inside an active plugin or active theme without a verified non-core malware/rogue scan issue_id.';
                return [
                    'isError' => true,
                    'content' => [['type' => 'text', 'text' => $msg]],
                    'result'  => ['success' => false, 'message' => $msg],
                ];
            }
        }

        // Automatically begin a transactional snapshot before quarantining
        $tx_id   = TransactionalRemediation::start_transaction('Agent Quarantine: ' . basename($real_path), 'Autonomous AI quarantine remediation');
        $snap_ok = TransactionalRemediation::record_file_snapshot($tx_id, $real_path, 'quarantine', $issue_id);

        if (!$snap_ok) {
            return [
                'isError' => true,
                'content' => [
                    [
                        'type' => 'text',
                        'text' => wp_json_encode([
                            'success' => false,
                            'message' => 'Action Aborted: Could not record pre-remediation safety snapshot. File was not quarantined.',
                        ], JSON_PRETTY_PRINT),
                    ],
                ],
                'result'  => ['success' => false, 'message' => 'Safety snapshot failed.'],
            ];
        }

        $qm  = new QuarantineManager();
        $res = $qm->quarantine_file($real_path, null, $issue_id);

        if (!empty($res['success'])) {
            TransactionalRemediation::commit_transaction($tx_id);
            $res['tx_id'] = $tx_id;
        } else {
            // Clean up uncommitted transaction directory if quarantine was rejected
            $tx_dir = TransactionalRemediation::get_transactions_dir() . '/' . TransactionalRemediation::sanitize_tx_id($tx_id);
            if (is_dir($tx_dir)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
                @unlink($tx_dir . '/manifest.json');
                foreach (@glob($tx_dir . '/files/*') ?: [] as $bf) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
                    @unlink($bf);
                }
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
                @rmdir($tx_dir . '/files');
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
                @rmdir($tx_dir);
            }
        }

        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_run_security_drill(array $args): array {
        $vectors = is_array($args['vectors'] ?? null) ? $args['vectors'] : [];
        $report = AttackSimulationEngine::run_simulation($vectors);

        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($report, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $report,
        ];
    }

    private static function tool_set_containment_mode(array $args): array {
        $action = sanitize_text_field($args['action'] ?? '');
        if ($action === 'activate') {
            $res = EmergencyContainmentManager::activate([
                'reason'              => sanitize_text_field($args['reason'] ?? 'Autonomous AI Incident Containment'),
                'maintenance_enabled' => !empty($args['maintenance_page']),
            ]);
        } elseif ($action === 'deactivate') {
            $res = EmergencyContainmentManager::deactivate();
        } else {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Invalid action: must be "activate" or "deactivate"']],
            ];
        }

        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_get_supply_chain_sbom(): array {
        $report = \WebCareProScanner\SupplyChain\SbomSentinelEngine::check_drift();
        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($report, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $report,
        ];
    }

    private static function tool_get_gatekeeper_history(): array {
        $data = [
            'logs'      => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_logs(30),
            'snapshots' => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_snapshots(),
            'settings'  => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_settings(),
        ];
        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($data, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $data,
        ];
    }

    private static function tool_recalibrate_sbom_baseline(): array {
        $res = \WebCareProScanner\SupplyChain\SbomSentinelEngine::calibrate_baseline();
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_quarantine_supply_chain_anchor(array $args): array {
        $item_id = sanitize_text_field($args['item_id'] ?? '');
        if (empty($item_id)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: item_id']],
            ];
        }

        $res = \WebCareProScanner\SupplyChain\SbomSentinelEngine::isolate_anchor($item_id);
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_get_behavioral_waf_status(): array {
        $data = [
            'learning_stats' => class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_summary_stats() : [],
            'route_profiles' => class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_route_profiles() : [],
            'honeytoken'     => class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine') ? \WebCareProScanner\Firewall\HoneyTokenEngine::get_summary() : [],
            'rate_limiter'   => class_exists('\WebCareProScanner\Firewall\AdaptiveRateLimiter') ? \WebCareProScanner\Firewall\AdaptiveRateLimiter::get_telemetry() : [],
        ];

        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($data, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $data,
        ];
    }

    private static function tool_set_route_learning_status(array $args): array {
        $route_key = sanitize_text_field($args['route_key'] ?? '');
        $action    = sanitize_key($args['action'] ?? '');

        if (empty($route_key) || empty($action)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: route_key and action are required.']],
            ];
        }

        if (!class_exists('\WebCareProScanner\Firewall\LearningModeEngine')) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'LearningModeEngine not available.']],
            ];
        }

        $res = \WebCareProScanner\Firewall\LearningModeEngine::set_route_status($route_key, $action);
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_get_identity_forensics(): array {
        $data = [
            'sessions_report'   => class_exists('\WebCareProScanner\Identity\SessionForensicsEngine') ? \WebCareProScanner\Identity\SessionForensicsEngine::get_active_sessions_report() : [],
            'active_elevations' => class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine') ? \WebCareProScanner\Identity\EphemeralAdminEngine::get_active_elevations() : [],
            'elevation_history' => class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine') ? \WebCareProScanner\Identity\EphemeralAdminEngine::get_elevation_history(20) : [],
            'hibp_summary'      => class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor') ? \WebCareProScanner\Identity\HIBPBreachAuditor::get_summary() : [],
        ];

        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($data, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $data,
        ];
    }

    private static function tool_revoke_user_session(array $args): array {
        $user_id  = intval($args['user_id'] ?? 0);
        $verifier = sanitize_text_field($args['verifier'] ?? '');

        if (!$user_id || empty($verifier)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: user_id and verifier are required.']],
            ];
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'SessionForensicsEngine not available.']],
            ];
        }

        if ($verifier === 'all') {
            $res = \WebCareProScanner\Identity\SessionForensicsEngine::revoke_all_sessions($user_id);
        } else {
            $res = \WebCareProScanner\Identity\SessionForensicsEngine::revoke_session($user_id, $verifier);
        }

        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_grant_ephemeral_elevation(array $args): array {
        $user_id  = intval($args['user_id'] ?? 0);
        $duration = intval($args['duration_minutes'] ?? 60);
        $reason   = sanitize_text_field($args['reason'] ?? '');

        if (!$user_id) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: user_id is required.']],
            ];
        }

        if (!class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'EphemeralAdminEngine not available.']],
            ];
        }

        $res = \WebCareProScanner\Identity\EphemeralAdminEngine::grant_elevation($user_id, $duration, $reason);
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_revoke_ephemeral_elevation(array $args): array {
        $user_id = intval($args['user_id'] ?? 0);
        $reason  = sanitize_text_field($args['reason'] ?? 'Revoked via MCP agent command');

        if (!$user_id) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: user_id is required.']],
            ];
        }

        if (!class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'EphemeralAdminEngine not available.']],
            ];
        }

        $res = \WebCareProScanner\Identity\EphemeralAdminEngine::revoke_elevation($user_id, $reason);
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_get_threat_intel_network(): array {
        $telemetry = ThreatIntelNetwork::get_network_telemetry();
        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($telemetry, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $telemetry,
        ];
    }

    private static function tool_sync_threat_intel(): array {
        $sync_res = ThreatIntelNetwork::sync_all_feeds();
        $telemetry = ThreatIntelNetwork::get_network_telemetry();
        $payload = [
            'sync'      => $sync_res,
            'telemetry' => $telemetry,
        ];

        return [
            'isError' => empty($sync_res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($payload, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $payload,
        ];
    }

    private static function tool_synthesize_virtual_patch(array $args): array {
        $res = VirtualPatchSynthesizer::synthesize_patch($args);
        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    private static function tool_test_virtual_patch(array $args): array {
        $patch = $args['patch'] ?? [];
        if (empty($patch) || empty($patch['php_rule']['regex'])) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: patch object with valid regex is required.']],
            ];
        }

        $custom_payloads = $args['custom_payloads'] ?? null;
        $sim_res = VirtualPatchSynthesizer::run_dryrun_simulation($patch, $custom_payloads);

        return [
            'isError' => ($sim_res['status'] === 'failed'),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($sim_res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $sim_res,
        ];
    }

    private static function tool_deploy_synthesized_patch(array $args): array {
        $action = sanitize_key($args['action'] ?? 'deploy');
        $patch_id = sanitize_text_field($args['patch_id'] ?? '');

        if ($action === 'deploy') {
            $patch = $args['patch'] ?? [];
            if (empty($patch['patch_id'])) {
                return [
                    'isError' => true,
                    'content' => [['type' => 'text', 'text' => 'Missing parameter: patch object is required for deploy.']],
                ];
            }
            $deploy_cf = !empty($args['deploy_to_cloudflare']);
            $res = VirtualPatchSynthesizer::save_synthesized_patch($patch, $deploy_cf);
        } elseif ($action === 'toggle') {
            if (empty($patch_id)) {
                return [
                    'isError' => true,
                    'content' => [['type' => 'text', 'text' => 'Missing parameter: patch_id is required for toggle.']],
                ];
            }
            $enable = !empty($args['enable']);
            $res = VirtualPatchSynthesizer::toggle_synthesized_patch($patch_id, $enable);
        } elseif ($action === 'delete') {
            if (empty($patch_id)) {
                return [
                    'isError' => true,
                    'content' => [['type' => 'text', 'text' => 'Missing parameter: patch_id is required for delete.']],
                ];
            }
            $res = VirtualPatchSynthesizer::delete_synthesized_patch($patch_id);
        } else {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Invalid action: must be deploy, toggle, or delete.']],
            ];
        }

        return [
            'isError' => empty($res['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($res, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $res,
        ];
    }

    /**
     * Evaluate payload-level anti-lockout invariants, taint escalation, and Before->After diffs.
     *
     * @param string               $tool
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    private static function preflight_guardrails(string $tool, array $args): array {
        $out = [
            'reject'        => false,
            'message'       => '',
            'escalate_tier' => 0,
            'force_stage'   => false,
            'summary'       => '',
            'diff_preview'  => [],
            'warnings'      => [],
        ];

        if ($tool === 'webcareproscan_update_plugin_settings') {
            $updates = is_array($args['updates'] ?? null) ? $args['updates'] : [];
            $check   = MCPSettingsPolicy::validate_and_classify_update($updates);
            if (empty($check['valid'])) {
                $out['reject']  = true;
                $out['message'] = (string) ($check['message'] ?? __('Invalid setting update.', 'webcare-pro-security'));
                return $out;
            }
            $out['diff_preview']  = $check['diff_preview'];
            $out['escalate_tier'] = (int) $check['max_tier'];
            if ((int) $check['max_tier'] >= 3) {
                $out['force_stage'] = true;
            }
            $out['summary'] = sprintf(
                /* translators: %s: comma-separated list of setting keys */
                __('Update settings: %s', 'webcare-pro-security'),
                implode(', ', array_keys($check['patch']))
            );
        } elseif ($tool === 'webcareproscan_save_custom_visual_rule') {
            $lock_check = MCPAntiLockoutValidator::validate_custom_rule($args);
            if (empty($lock_check['allowed'])) {
                $out['reject']  = true;
                $out['message'] = (string) $lock_check['reason'];
                return $out;
            }
            if ((int) $lock_check['escalate_tier'] > 0) {
                $out['escalate_tier'] = (int) $lock_check['escalate_tier'];
                $out['force_stage']   = true;
            }
            if (($args['action_type'] ?? '') === 'allow') {
                $out['escalate_tier'] = max((int) ($out['escalate_tier'] ?? 0), 3);
                $out['force_stage']   = true;
            }
            $out['warnings'] = $lock_check['warnings'];
            $out['summary']  = sprintf(
                /* translators: %1$s: rule title, %2$s: action type */
                __('Save custom firewall rule "%1$s" (%2$s)', 'webcare-pro-security'),
                sanitize_text_field((string) ($args['title'] ?? 'Custom Rule')),
                sanitize_key((string) ($args['action_type'] ?? 'block'))
            );
        } elseif ($tool === 'webcareproscan_manage_ip_access' || $tool === 'webcareproscan_sync_cloudflare_ip_ban') {
            $action = sanitize_key((string) ($args['action'] ?? ''));
            $ip     = trim((string) ($args['ip'] ?? ''));
            if ($action === 'ban') {
                $guard = MCPAntiLockoutValidator::validate_ip_ban($ip);
                if (empty($guard['allowed'])) {
                    $out['reject']  = true;
                    $out['message'] = (string) $guard['reason'];
                    return $out;
                }
            } elseif (in_array($action, ['unban', 'whitelist'], true)) {
                $out['force_stage']   = true;
                $out['escalate_tier'] = 3;
                if ($ip !== '' && class_exists(PromptInjectionGuard::class) && PromptInjectionGuard::is_ip_flagged_in_recent_telemetry($ip)) {
                    $out['warnings'][] = __('Tainted-Payload Guard: Target IP recently appeared in WAF / Prompt-Injection telemetry. Verify manually before approving.', 'webcare-pro-security');
                }
            }
            $out['summary'] = strtoupper($action) . ' IP ' . sanitize_text_field($ip);
        } elseif ($tool === 'webcareproscan_toggle_or_delete_custom_rule' && ($args['action'] ?? '') === 'delete') {
            $out['escalate_tier'] = 4;
            $out['force_stage']   = true;
            $out['summary']       = 'Delete custom rule ' . sanitize_text_field((string) ($args['rule_id'] ?? ''));
        } elseif ($tool === 'webcareproscan_delete_quarantined_file') {
            $out['escalate_tier'] = 4;
            $out['force_stage']   = true;
            $out['summary']       = 'Permanently delete quarantined file #' . intval($args['quarantine_id'] ?? 0);
        }

        // Boundary 3: Taint-Aware Dynamic Escalation
        if (self::is_session_tainted()) {
            $action      = sanitize_key((string) ($args['action'] ?? ''));
            $action_type = sanitize_key((string) ($args['action_type'] ?? ''));
            $is_permissive = in_array($tool, [
                'webcareproscan_restore_quarantined_file',
                'webcareproscan_delete_quarantined_file',
                'webcareproscan_undo_last_mcp_change',
                'webcareproscan_whitelist_finding',
                'webcareproscan_rollback_remediation',
                'webcareproscan_update_plugin_settings',
            ], true)
                || ($tool === 'webcareproscan_manage_ip_access' && in_array($action, ['unban', 'whitelist'], true))
                || ($tool === 'webcareproscan_sync_cloudflare_ip_ban' && in_array($action, ['unban', 'whitelist'], true))
                || ($tool === 'webcareproscan_save_custom_visual_rule' && $action_type === 'allow');

            if ($is_permissive) {
                $out['force_stage']   = true;
                $out['escalate_tier'] = max((int) ($out['escalate_tier'] ?? 0), 3);
                $out['warnings'][]    = __('Tainted Session Guard: Active session observed untrusted external telemetry. Sensitive operation was escalated to Staged Action confirmation queue.', 'webcare-pro-security');
            }
        }

        return $out;
    }

    /**
     * Apply a user-friendly governance preset across scope + per-tool matrix.
     * Presets: 'observer' (Read-Only), 'guided' (Co-Pilot Staged), 'safe_operator' (Tier 2 Auto + Snapshots).
     *
     * @param string $preset
     * @return array<string, mixed>
     */
    public static function apply_persona_preset(string $preset): array {
        $preset = sanitize_key($preset);
        if (!in_array($preset, ['observer', 'guided', 'safe_operator'], true)) {
            return ['success' => false, 'message' => __('Invalid MCP persona preset.', 'webcare-pro-security')];
        }

        $catalog = self::get_registered_tool_map();
        $matrix  = [];
        $scope   = ($preset === 'observer') ? 'read_only' : 'read_write';

        foreach ($catalog as $name => $meta) {
            $is_mut = !empty($meta['isMutating']);
            $tier   = (int) ($meta['tier'] ?? ($is_mut ? 2 : 1));
            if (!$is_mut || $tier <= 1) {
                $matrix[$name] = 'allowed';
            } elseif ($preset === 'observer') {
                $matrix[$name] = 'blocked';
            } elseif ($preset === 'guided') {
                $matrix[$name] = 'confirmation_required';
            } else {
                // Safe Operator: Tier 2 reversible writes run autonomously (with snapshots & anti-lockout), Tier 3/4 stay staged
                $matrix[$name] = ($tier <= 2) ? 'allowed' : 'confirmation_required';
            }
        }

        $clean_matrix = SettingsManager::sanitize_mcp_tool_matrix($matrix);
        SettingsManager::save_settings([
            'mcp_persona_preset'   => $preset,
            'mcp_permission_scope' => $scope,
            'mcp_tool_matrix'      => $clean_matrix,
        ]);

        return [
            'success' => true,
            'preset'  => $preset,
            'scope'   => $scope,
            'matrix'  => $clean_matrix,
        ];
    }

    /**
     * Unified JSON-RPC 2.0 MCP transport dispatcher supporting Claude Desktop, Cursor, Windsurf, and Antigravity.
     *
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public static function handle_json_rpc(array $payload): array {
        $id     = $payload['id'] ?? null;
        $method = sanitize_text_field((string) ($payload['method'] ?? ''));
        $params = is_array($payload['params'] ?? null) ? $payload['params'] : [];

        if ($method === '') {
            return [
                'jsonrpc' => '2.0',
                'id'      => $id,
                'error'   => ['code' => -32600, 'message' => 'Invalid Request: missing method'],
            ];
        }

        switch ($method) {
            case 'initialize':
                return [
                    'jsonrpc' => '2.0',
                    'id'      => $id,
                    'result'  => [
                        'protocolVersion' => '2024-11-05',
                        'capabilities'    => [
                            'tools' => ['listChanged' => false],
                        ],
                        'serverInfo'      => [
                            'name'    => 'webcare-pro-security',
                            'version' => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
                        ],
                    ],
                ];

            case 'notifications/initialized':
            case 'ping':
                return [
                    'jsonrpc' => '2.0',
                    'id'      => $id,
                    'result'  => new \stdClass(),
                ];

            case 'tools/list':
                $catalog = self::get_tools_catalog();
                $rpc_tools = [];
                foreach ($catalog['tools'] as $t) {
                    $rpc_tools[] = [
                        'name'        => $t['name'],
                        'description' => sprintf('[Tier %d | %s] %s', (int) ($t['tier'] ?? 1), strtoupper((string) ($t['policy'] ?? 'allowed')), (string) $t['description']),
                        'inputSchema' => $t['inputSchema'],
                    ];
                }
                return [
                    'jsonrpc' => '2.0',
                    'id'      => $id,
                    'result'  => ['tools' => $rpc_tools],
                ];

            case 'tools/call':
                $tool_name = sanitize_text_field((string) ($params['name'] ?? ''));
                $tool_args = is_array($params['arguments'] ?? null) ? $params['arguments'] : [];
                if ($tool_name === '') {
                    return [
                        'jsonrpc' => '2.0',
                        'id'      => $id,
                        'error'   => ['code' => -32602, 'message' => 'Invalid params: tool name required'],
                    ];
                }
                $exec = self::execute_tool($tool_name, $tool_args);
                return [
                    'jsonrpc' => '2.0',
                    'id'      => $id,
                    'result'  => [
                        'content' => $exec['content'] ?? [['type' => 'text', 'text' => (string) wp_json_encode($exec)]],
                        'isError' => !empty($exec['isError']),
                    ],
                ];

            default:
                return [
                    'jsonrpc' => '2.0',
                    'id'      => $id,
                    'error'   => ['code' => -32601, 'message' => sprintf('Method not found: %s', $method)],
                ];
        }
    }
}
