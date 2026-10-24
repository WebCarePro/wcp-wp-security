<?php
namespace WcpScanner\Api;

use WcpScanner\Findings\WhitelistManager;
use WcpScanner\Integrity\BehavioralBaselineEngine;
use WcpScanner\Remediation\TransactionalRemediation;
use WcpScanner\Quarantine\QuarantineManager;
use WcpScanner\Firewall\VirtualPatchManager;
use WcpScanner\System\SettingsManager;
use WcpScanner\Findings\RiskScorer;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MCPAgentService
 *
 * Implements standard Model Context Protocol (MCP) tool declarations and execution surface.
 * Enables external AI agentic assistants (Claude Desktop, Antigravity, Cursor, OpenAI Agents)
 * to autonomously inspect site security posture, list findings, deploy virtual patches,
 * run baseline audits, and perform safe remediation with transactional rollback.
 */
class MCPAgentService {

    const READ_TOOLS = [
        'wcpscan_get_security_posture',
        'wcpscan_list_findings',
        'wcpscan_audit_behavioral_baseline',
    ];

    const MUTATING_TOOLS = [
        'wcpscan_whitelist_finding',
        'wcpscan_rollback_remediation',
        'wcpscan_deploy_virtual_patch',
        'wcpscan_quarantine_file',
    ];

    const AUDIT_OPTION_KEY = 'wcpscan_mcp_audit_log';
    const MAX_AUDIT_LOGS   = 150;

    /**
     * Retrieve the MCP tools catalog with JSON schemas and safety classification.
     *
     * @return array
     */
    public static function get_tools_catalog(): array {
        $scope = SettingsManager::get('mcp_permission_scope', 'read_write');

        return [
            'scope'      => $scope,
            'isReadOnly' => ($scope === 'read_only'),
            'tools'      => [
                [
                    'name'        => 'wcpscan_get_security_posture',
                    'description' => 'Retrieve comprehensive WordPress security posture, risk score, vulnerability metrics, firewall status, and baseline health.',
                    'category'    => 'read',
                    'isMutating'  => false,
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
                    'name'        => 'wcpscan_whitelist_finding',
                    'description' => 'Suppress false-positive finding by exact SHA-256 hash-lock, file path, or issue signature with audit reason.',
                    'category'    => 'mutating',
                    'isMutating'  => true,
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
                    'name'        => 'wcpscan_audit_behavioral_baseline',
                    'description' => 'Execute an instant behavioral baseline audit to detect hook injections, rogue cron tasks, or backdoor drop-ins.',
                    'category'    => 'read',
                    'isMutating'  => false,
                    'inputSchema' => [
                        'type'       => 'object',
                        'properties' => new \stdClass(),
                    ],
                ],
                [
                    'name'        => 'wcpscan_rollback_remediation',
                    'description' => 'Perform 1-click safe rollback of a previous remediation transaction, restoring original byte-for-byte files and DB states.',
                    'category'    => 'mutating',
                    'isMutating'  => true,
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
            ],
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
     * Execute an MCP tool by name with arguments, rate limiting, permission checks, and audit logging.
     *
     * @param string $tool
     * @param array $args
     * @return array
     */
    public static function execute_tool(string $tool, array $args = []): array {
        $start_time = microtime(true);

        $raw_cf_ip  = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? (string) wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']) : '';
        $raw_xf_ip  = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? (string) wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']) : '';
        $raw_rem_ip = isset($_SERVER['REMOTE_ADDR']) ? (string) wp_unslash($_SERVER['REMOTE_ADDR']) : '127.0.0.1';
        $client_ip  = $raw_cf_ip !== '' ? $raw_cf_ip : ($raw_xf_ip !== '' ? $raw_xf_ip : $raw_rem_ip);

        if (strpos($client_ip, ',') !== false) {
            $parts = explode(',', $client_ip);
            $client_ip = trim($parts[0]);
        }
        $client_ip  = sanitize_text_field($client_ip);
        $user_agent = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(substr((string) wp_unslash($_SERVER['HTTP_USER_AGENT']), 0, 120)) : 'Unknown AI Agent';

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
                        'text' => sprintf(__('Rate limit exceeded: Maximum %d requests per minute allowed for MCP Agent tools.', 'wcp-security-scanner'), $rate_limit),
                    ],
                ],
            ];
        }

        // 2. Permission scope enforcement (Read-Only vs Read/Write)
        $scope = SettingsManager::get('mcp_permission_scope', 'read_write');
        if ($scope === 'read_only' && in_array($tool, self::MUTATING_TOOLS, true)) {
            $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
            self::log_audit_event([
                'id'          => uniqid('mcp_', true),
                'timestamp'   => time(),
                'client_ip'   => $client_ip,
                'user_agent'  => $user_agent,
                'tool'        => $tool,
                'args'        => self::summarize_args($args),
                'duration_ms' => $duration_ms,
                'status'      => 'denied_read_only',
                'message'     => 'Action blocked: Agent is in Read-Only mode',
            ]);

            return [
                'isError' => true,
                'content' => [
                    [
                        'type' => 'text',
                        'text' => sprintf(__('Permission Denied: Tool "%s" modifies site state, but MCP Agent Service is locked in "Read-Only (Observation)" mode. Change to "Full Remediation" mode in WCP Settings to allow autonomous file actions.', 'wcp-security-scanner'), sanitize_text_field($tool)),
                    ],
                ],
            ];
        }

        // 3. Tool execution
        $response = null;
        switch ($tool) {
            case 'wcpscan_get_security_posture':
                $response = self::tool_get_posture();
                break;

            case 'wcpscan_list_findings':
                $response = self::tool_list_findings($args);
                break;

            case 'wcpscan_whitelist_finding':
                $response = self::tool_whitelist_finding($args);
                break;

            case 'wcpscan_audit_behavioral_baseline':
                $response = self::tool_audit_baseline();
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

            default:
                $response = [
                    'isError' => true,
                    'content' => [
                        [
                            'type' => 'text',
                            'text' => sprintf(__('Unknown MCP tool "%s".', 'wcp-security-scanner'), sanitize_text_field($tool)),
                        ],
                    ],
                ];
                break;
        }

        // 4. Audit logging
        $duration_ms = round((microtime(true) - $start_time) * 1000, 2);
        $status = empty($response['isError']) ? 'success' : 'error';
        $message = empty($response['isError']) ? 'Executed successfully' : ($response['content'][0]['text'] ?? 'Execution error');

        self::log_audit_event([
            'id'          => uniqid('mcp_', true),
            'timestamp'   => time(),
            'client_ip'   => $client_ip,
            'user_agent'  => $user_agent,
            'tool'        => $tool,
            'args'        => self::summarize_args($args),
            'duration_ms' => $duration_ms,
            'status'      => $status,
            'message'     => substr($message, 0, 160),
        ]);

        return $response;
    }

    private static function tool_get_posture(): array {
        global $wpdb;
        $table_scans  = $wpdb->prefix . 'wcpscan_scans';
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';

        $latest_scan = $wpdb->get_row("SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1", ARRAY_A);
        $open_issues = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table_issues}` WHERE status = 'open'");
        $critical    = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table_issues}` WHERE status = 'open' AND severity = 'critical'");
        $high        = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table_issues}` WHERE status = 'open' AND severity = 'high'");

        $baseline_data = BehavioralBaselineEngine::get_baseline();
        $baseline_aud  = $baseline_data ? BehavioralBaselineEngine::audit_baseline() : null;

        $posture = [
            'site_url'           => get_site_url(),
            'wp_version'         => get_bloginfo('version'),
            'php_version'        => PHP_VERSION,
            'risk_score'         => $latest_scan ? (int) $latest_scan['risk_score'] : 0,
            'open_issues_count'  => $open_issues,
            'critical_count'     => $critical,
            'high_count'         => $high,
            'last_scan_date'     => $latest_scan['created_at'] ?? 'Never',
            'waf_enabled'        => (bool) SettingsManager::get('waf_enabled', true),
            'cloudflare_enabled' => (bool) SettingsManager::get('cloudflare_enabled', false),
            'baseline_status'    => $baseline_aud ? ($baseline_aud['status'] ?? 'unknown') : 'uncalibrated',
            'baseline_health'    => $baseline_aud['health_score'] ?? null,
            'active_rules_count' => count(WhitelistManager::get_whitelist_rules(true)),
        ];

        return [
            'isError' => false,
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($posture, JSON_PRETTY_PRINT),
                ],
            ],
            'posture' => $posture,
        ];
    }

    private static function tool_list_findings(array $args): array {
        global $wpdb;
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';

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

        $query = "SELECT id, scan_id, engine, type, severity, confidence, file_path, line_number, description, status, created_at FROM `{$table_issues}` WHERE " . implode(' AND ', $where) . " ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC LIMIT %d";
        $params[] = $limit;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $results = $wpdb->get_results($wpdb->prepare($query, ...$params), ARRAY_A);

        return [
            'isError'  => false,
            'count'    => count($results),
            'content'  => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($results, JSON_PRETTY_PRINT),
                ],
            ],
            'findings' => $results,
        ];
    }

    private static function tool_whitelist_finding(array $args): array {
        $result = WhitelistManager::add_rule($args);
        return [
            'isError' => empty($result['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($result, JSON_PRETTY_PRINT),
                ],
            ],
            'result'  => $result,
        ];
    }

    private static function tool_audit_baseline(): array {
        $audit = BehavioralBaselineEngine::audit_baseline();
        return [
            'isError' => empty($audit['success']),
            'content' => [
                [
                    'type' => 'text',
                    'text' => wp_json_encode($audit, JSON_PRETTY_PRINT),
                ],
            ],
            'audit'   => $audit,
        ];
    }

    private static function tool_rollback_remediation(array $args): array {
        $tx_id = sanitize_text_field($args['tx_id'] ?? '');
        if (empty($tx_id)) {
            return [
                'isError' => true,
                'content' => [['type' => 'text', 'text' => 'tx_id argument is required.']],
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
}
