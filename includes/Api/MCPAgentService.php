<?php
namespace WcpScanner\Api;

use WcpScanner\Findings\WhitelistManager;
use WcpScanner\Integrity\BehavioralBaselineEngine;
use WcpScanner\Remediation\TransactionalRemediation;
use WcpScanner\Quarantine\QuarantineManager;
use WcpScanner\Firewall\VirtualPatchManager;
use WcpScanner\System\SettingsManager;
use WcpScanner\Findings\RiskScorer;
use WcpScanner\Security\AttackSimulationEngine;
use WcpScanner\Security\EmergencyContainmentManager;

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
        'wcpscan_get_security_posture',
        'wcpscan_list_findings',
        'wcpscan_audit_behavioral_baseline',
        'wcpscan_get_containment_status',
        'wcpscan_list_staged_actions',
        'wcpscan_get_supply_chain_sbom',
        'wcpscan_get_gatekeeper_history',
        'wcpscan_get_behavioral_waf_status',
    ];

    const MUTATING_TOOLS = [
        'wcpscan_whitelist_finding',
        'wcpscan_rollback_remediation',
        'wcpscan_deploy_virtual_patch',
        'wcpscan_quarantine_file',
        'wcpscan_run_security_drill',
        'wcpscan_set_containment_mode',
        'wcpscan_approve_staged_action',
        'wcpscan_recalibrate_sbom_baseline',
        'wcpscan_quarantine_supply_chain_anchor',
        'wcpscan_set_route_learning_status',
    ];

    const AUDIT_OPTION_KEY  = 'wcpscan_mcp_audit_log';
    const MAX_AUDIT_LOGS    = 150;
    const STAGED_OPTION_KEY = 'wcpscan_mcp_staged_actions';
    const MAX_STAGED_ACTIONS = 100;

    /**
     * Retrieve current tool policy for a given tool: 'allowed' | 'confirmation_required' | 'blocked'.
     *
     * @param string $tool
     * @return string
     */
    public static function get_tool_policy(string $tool): string {
        $scope = SettingsManager::get('mcp_permission_scope', 'read_write');
        if ($scope === 'read_only' && in_array($tool, self::MUTATING_TOOLS, true)) {
            return 'blocked';
        }

        $matrix = SettingsManager::get('mcp_tool_matrix', []);
        if (is_array($matrix) && isset($matrix[$tool])) {
            return $matrix[$tool];
        }

        // Default policies
        if (in_array($tool, self::READ_TOOLS, true)) {
            return 'allowed';
        }
        if ($tool === 'wcpscan_run_security_drill' || $tool === 'wcpscan_whitelist_finding') {
            return 'allowed';
        }

        // Potentially high-impact mutating tools require human confirmation by default
        return 'confirmation_required';
    }

    /**
     * Retrieve the MCP tools catalog with JSON schemas, safety classifications, and active governance policies.
     *
     * @return array
     */
    public static function get_tools_catalog(): array {
        $scope = SettingsManager::get('mcp_permission_scope', 'read_write');

        $tools = [
            [
                'name'        => 'wcpscan_get_security_posture',
                'description' => 'Retrieve comprehensive WordPress security posture, risk score, vulnerability metrics, firewall status, and baseline health.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_get_security_posture'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_list_findings',
                'description' => 'Query current vulnerability and malware findings with filtering by severity, status, or engine.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_list_findings'),
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
                'name'        => 'wcpscan_audit_behavioral_baseline',
                'description' => 'Execute an instant behavioral baseline audit to detect hook injections, rogue cron tasks, or backdoor drop-ins.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_audit_behavioral_baseline'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_get_containment_status',
                'description' => 'Retrieve active status of Emergency Containment Mode, blast-radius freeze policies, and session termination telemetry.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_get_containment_status'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_list_staged_actions',
                'description' => 'List pending AI agent mutation actions awaiting human administrator approval in the Staged Action Queue.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_list_staged_actions'),
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
                'name'        => 'wcpscan_whitelist_finding',
                'description' => 'Suppress false-positive finding by exact SHA-256 hash-lock, file path, or issue signature with audit reason.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_whitelist_finding'),
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
                'name'        => 'wcpscan_rollback_remediation',
                'description' => 'Perform 1-click safe rollback of a previous remediation transaction, restoring original byte-for-byte files and DB states.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_rollback_remediation'),
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
                'name'        => 'wcpscan_deploy_virtual_patch',
                'description' => 'Apply or remove an edge/runtime virtual patch rule for a known CVE without waiting for upstream plugin updates.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_deploy_virtual_patch'),
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
                'name'        => 'wcpscan_quarantine_file',
                'description' => 'Safely isolate a malicious file into the encrypted quarantine vault with automatic pre-remediation transactional backup.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_quarantine_file'),
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
                'name'        => 'wcpscan_run_security_drill',
                'description' => 'Execute a safe, self-contained Red Team penetration drill simulating SQLi, LFI, XSS, Recon, and AI Prompt-Injection to measure real-time WAF defensibility score (0-100%).',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_run_security_drill'),
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
                'name'        => 'wcpscan_set_containment_mode',
                'description' => 'Activate or deactivate Emergency Containment Mode to freeze the blast radius during an active security incident.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_set_containment_mode'),
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
                'name'        => 'wcpscan_approve_staged_action',
                'description' => 'Approve and execute a staged mutation action that was held in the human confirmation gate.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_approve_staged_action'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'staged_id' => [
                            'type'        => 'string',
                            'description' => 'Staged Action ID (e.g. stg_a1b2c3d4e5f6)',
                        ],
                    ],
                    'required' => ['staged_id'],
                ],
            [
                'name'        => 'wcpscan_get_supply_chain_sbom',
                'description' => 'Retrieve Software Bill of Materials (SBOM) tracking standard/custom drop-ins, mu-plugins, autoloaders, and PHP INI directives with drift detection.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_get_supply_chain_sbom'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_get_gatekeeper_history',
                'description' => 'Retrieve history of plugin update differential integrity audits, blocked updates, and available pre-update rollback snapshots.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_get_gatekeeper_history'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_recalibrate_sbom_baseline',
                'description' => 'Calibrate a new clean cryptographic SHA-256 baseline of all active drop-ins and runtime anchors.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_recalibrate_sbom_baseline'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_quarantine_supply_chain_anchor',
                'description' => 'Quarantine an unauthorized, rogue, or modified drop-in or must-use plugin to the WCP Vault.',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_quarantine_supply_chain_anchor'),
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
                'name'        => 'wcpscan_get_behavioral_waf_status',
                'description' => 'Retrieve Behavioral WAF telemetry: Learning Mode 2.0 route profiles, confidence scores, Honey-Token bot traps, and Adaptive Rate Limiter stats.',
                'category'    => 'read',
                'isMutating'  => false,
                'policy'      => self::get_tool_policy('wcpscan_get_behavioral_waf_status'),
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => new \stdClass(),
                ],
            ],
            [
                'name'        => 'wcpscan_set_route_learning_status',
                'description' => 'Manually change the behavioral learning status of a specific route ("graduate", "enforce", "learn", or "reset").',
                'category'    => 'mutating',
                'isMutating'  => true,
                'policy'      => self::get_tool_policy('wcpscan_set_route_learning_status'),
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
        ];

        return [
            'scope'      => $scope,
            'isReadOnly' => ($scope === 'read_only'),
            'tools'      => $tools,
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
        $transient_key = 'wcpscan_mcp_rl_' . substr(md5($identifier), 0, 16);
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
     * Sanitize and summarize arguments for safe audit logging.
     *
     * @param array $args
     * @return string
     */
    private static function summarize_args(array $args): string {
        if (empty($args)) {
            return '{}';
        }
        $clean = [];
        foreach ($args as $k => $v) {
            if (is_array($v)) {
                $clean[$k] = '[Array(' . count($v) . ')]';
            } elseif (is_string($v) && strlen($v) > 50) {
                $clean[$k] = substr($v, 0, 47) . '...';
            } else {
                $clean[$k] = $v;
            }
        }
        return wp_json_encode($clean);
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

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $raw_cf_ip  = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? (string) wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $raw_xf_ip  = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? (string) wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $raw_rem_ip = isset($_SERVER['REMOTE_ADDR']) ? (string) wp_unslash($_SERVER['REMOTE_ADDR']) : '127.0.0.1';
        $client_ip  = $raw_cf_ip !== '' ? $raw_cf_ip : ($raw_xf_ip !== '' ? $raw_xf_ip : $raw_rem_ip);

        if (strpos($client_ip, ',') !== false) {
            $parts = explode(',', $client_ip);
            $client_ip = trim($parts[0]);
        }
        $client_ip  = sanitize_text_field($client_ip);
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $raw_ua     = isset($_SERVER['HTTP_USER_AGENT']) ? (string) wp_unslash($_SERVER['HTTP_USER_AGENT']) : '';
        $user_agent = $raw_ua !== '' ? sanitize_text_field(substr($raw_ua, 0, 120)) : 'Unknown AI Agent';

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
                        'text' => sprintf(__('Rate limit exceeded: Maximum %d requests per minute allowed for MCP Agent tools.', 'wcp-security-scanner'), $rate_limit),
                    ],
                ],
            ];
        }

        // 2. Tool Governance & Policy Enforcement
        $policy = self::get_tool_policy($tool);

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
                        'text' => sprintf(__('Permission Denied: Tool "%s" is blocked by administrator governance policy.', 'wcp-security-scanner'), sanitize_text_field($tool)),
                    ],
                ],
            ];
        }

        // 3. Staged Action Confirmation Gate
        if (!$bypass_gate && $policy === 'confirmation_required') {
            return self::stage_action_for_approval($tool, $args, $client_ip, $user_agent, $start_time);
        }

        // 4. Tool Execution
        $response = null;
        switch ($tool) {
            case 'wcpscan_get_security_posture':
                $response = self::tool_get_posture();
                break;

            case 'wcpscan_list_findings':
                $response = self::tool_list_findings($args);
                break;

            case 'wcpscan_audit_behavioral_baseline':
                $response = self::tool_audit_baseline();
                break;

            case 'wcpscan_get_containment_status':
                $response = self::tool_get_containment_status();
                break;

            case 'wcpscan_list_staged_actions':
                $response = self::tool_list_staged_actions($args);
                break;

            case 'wcpscan_whitelist_finding':
                $response = self::tool_whitelist_finding($args);
                break;

            case 'wcpscan_rollback_remediation':
                $response = self::tool_rollback_remediation($args);
                break;

            case 'wcpscan_deploy_virtual_patch':
                $response = self::tool_deploy_virtual_patch($args);
                break;

            case 'wcpscan_quarantine_file':
                $response = self::tool_quarantine_file($args);
                break;

            case 'wcpscan_run_security_drill':
                $response = self::tool_run_security_drill($args);
                break;

            case 'wcpscan_set_containment_mode':
                $response = self::tool_set_containment_mode($args);
                break;

            case 'wcpscan_approve_staged_action':
                $response = self::tool_approve_staged_action($args);
                break;

            case 'wcpscan_get_supply_chain_sbom':
                $response = self::tool_get_supply_chain_sbom();
                break;

            case 'wcpscan_get_gatekeeper_history':
                $response = self::tool_get_gatekeeper_history();
                break;

            case 'wcpscan_recalibrate_sbom_baseline':
                $response = self::tool_recalibrate_sbom_baseline();
                break;

            case 'wcpscan_quarantine_supply_chain_anchor':
                $response = self::tool_quarantine_supply_chain_anchor($args);
                break;

            case 'wcpscan_get_behavioral_waf_status':
                $response = self::tool_get_behavioral_waf_status();
                break;

            case 'wcpscan_set_route_learning_status':
                $response = self::tool_set_route_learning_status($args);
                break;

            default:
                $response = [
                    'isError' => true,
                    'content' => [
                        [
                            'type' => 'text',
                            /* translators: %s: MCP tool name */
                            'text' => sprintf(__('Unknown MCP tool "%s".', 'wcp-security-scanner'), sanitize_text_field($tool)),
                        ],
                    ],
                ];
                break;
        }

        $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
        $is_error = !empty($response['isError']);

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
     * @param string $tool
     * @param array  $args
     * @param string $client_ip
     * @param string $user_agent
     * @param float  $start_time
     * @return array
     */
    public static function stage_action_for_approval(string $tool, array $args = [], string $client_ip = '127.0.0.1', string $user_agent = 'WCP Agent Service', float $start_time = 0.0): array {
        if ($start_time <= 0.0) {
            $start_time = microtime(true);
        }
        $staged_id = 'stg_' . substr(md5(uniqid('wcp_stg_', true)), 0, 12);

        $staged_entry = [
            'id'          => $staged_id,
            'tool'        => $tool,
            'args'        => $args,
            'client_ip'   => $client_ip,
            'user_agent'  => $user_agent,
            'status'      => 'pending_approval',
            'created_at'  => time(),
            'expires_at'  => time() + 86400, // 24 hours
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
            'message'     => sprintf('Action staged for human approval (ID: %s)', $staged_id),
        ]);

        return [
            'isError'   => false,
            'isStaged'  => true,
            'staged_id' => $staged_id,
            'tool'      => $tool,
            'status'    => 'pending_approval',
            'content'   => [
                [
                    'type' => 'text',
                    'text' => sprintf(
                        /* translators: 1: tool name, 2: staged action ID */
                        __('Action Staged in Confirmation Gate: Tool "%1$s" modifies site security state and requires human approval. Staged Action ID: %2$s. An administrator must approve this action in WCP Security Console before execution.', 'wcp-security-scanner'),
                        sanitize_text_field($tool),
                        $staged_id
                    ),
                ],
            ],
            'result' => [
                'staged_id'   => $staged_id,
                'status'      => 'pending_approval',
                'description' => 'Awaiting administrator confirmation in WCP Console.',
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

        return $list;
    }

    /**
     * Approve and execute a staged action.
     *
     * @param string $staged_id
     * @param int    $approver_id
     * @return array
     */
    public static function approve_staged_action(string $staged_id, int $approver_id = 0): array {
        $list = get_option(self::STAGED_OPTION_KEY, []);
        if (!is_array($list)) {
            return ['success' => false, 'message' => __('No staged actions found.', 'wcp-security-scanner')];
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
            return ['success' => false, 'message' => __('Staged action not found.', 'wcp-security-scanner')];
        }

        if ($target_action['status'] !== 'pending_approval') {
            return ['success' => false, 'message' => sprintf(__('Action is already %s.', 'wcp-security-scanner'), $target_action['status'])];
        }

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
            'message'     => __('Staged action approved and executed successfully.', 'wcp-security-scanner'),
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
            return ['success' => false, 'message' => __('No staged actions found.', 'wcp-security-scanner')];
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
            return ['success' => false, 'message' => __('Staged action not found.', 'wcp-security-scanner')];
        }

        update_option(self::STAGED_OPTION_KEY, $list, false);

        return [
            'success'   => true,
            'staged_id' => $staged_id,
            'message'   => __('Staged action rejected.', 'wcp-security-scanner'),
        ];
    }

    // ==========================================
    // Tool Execution Implementations
    // ==========================================

    private static function tool_get_posture(): array {
        $scorer = new RiskScorer();
        $health = $scorer->get_site_health();
        $baseline_engine = new BehavioralBaselineEngine();
        $baseline_drift = $baseline_engine->detect_drift();

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

        $table = $wpdb->prefix . 'wcpscan_scan_issues';
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

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
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
        $engine = new BehavioralBaselineEngine();
        $drift = $engine->detect_drift();

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
            $res = VirtualPatchManager::apply_virtual_patch($rule_id);
        } else {
            $res = VirtualPatchManager::remove_virtual_patch($rule_id);
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
        $file_path = sanitize_text_field($args['file_path'] ?? '');
        $issue_id  = isset($args['issue_id']) ? (int) $args['issue_id'] : null;

        // Automatically begin a transactional snapshot before quarantining
        $tx_id = TransactionalRemediation::start_transaction('Agent Quarantine: ' . basename($file_path), 'Autonomous AI quarantine remediation');
        TransactionalRemediation::record_file_snapshot($tx_id, $file_path, 'quarantine', $issue_id);

        $qm = new QuarantineManager();
        $res = $qm->quarantine_file($file_path, null, $issue_id);

        if (!empty($res['success'])) {
            TransactionalRemediation::commit_transaction($tx_id);
            $res['tx_id'] = $tx_id;
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

    private static function tool_approve_staged_action(array $args): array {
        $staged_id = sanitize_text_field($args['staged_id'] ?? '');
        if (empty($staged_id)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'Missing parameter: staged_id']],
            ];
        }

        $res = self::approve_staged_action($staged_id, get_current_user_id());
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
        $report = \WcpScanner\SupplyChain\SbomSentinelEngine::check_drift();
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
            'logs'      => \WcpScanner\SupplyChain\UpdateGatekeeperEngine::get_logs(30),
            'snapshots' => \WcpScanner\SupplyChain\UpdateGatekeeperEngine::get_snapshots(),
            'settings'  => \WcpScanner\SupplyChain\UpdateGatekeeperEngine::get_settings(),
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
        $res = \WcpScanner\SupplyChain\SbomSentinelEngine::calibrate_baseline();
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

        $res = \WcpScanner\SupplyChain\SbomSentinelEngine::isolate_anchor($item_id);
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
            'learning_stats' => class_exists('\WcpScanner\Firewall\LearningModeEngine') ? \WcpScanner\Firewall\LearningModeEngine::get_summary_stats() : [],
            'route_profiles' => class_exists('\WcpScanner\Firewall\LearningModeEngine') ? \WcpScanner\Firewall\LearningModeEngine::get_route_profiles() : [],
            'honeytoken'     => class_exists('\WcpScanner\Firewall\HoneyTokenEngine') ? \WcpScanner\Firewall\HoneyTokenEngine::get_summary() : [],
            'rate_limiter'   => class_exists('\WcpScanner\Firewall\AdaptiveRateLimiter') ? \WcpScanner\Firewall\AdaptiveRateLimiter::get_telemetry() : [],
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

        if (!class_exists('\WcpScanner\Firewall\LearningModeEngine')) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'LearningModeEngine not available.']],
            ];
        }

        $res = \WcpScanner\Firewall\LearningModeEngine::set_route_status($route_key, $action);
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
}
