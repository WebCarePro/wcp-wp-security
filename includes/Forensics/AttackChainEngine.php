<?php
namespace WcpScanner\Forensics;

use WcpScanner\WordPress\PersistenceScanner;
use WcpScanner\WordPress\UserRemediationManager;
use WcpScanner\Remediation\RemediationManager;
use WcpScanner\Filesystem\PathValidator;
use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AttackChainEngine
 *
 * Behavioral Anomaly & Attack-Chain Correlation Engine for WordPress.
 * Correlates isolated, multi-vector signals across the entire WordPress kill chain:
 * 1. Initial Access & Exploitation (CVEs, WAF Exploit Probes, Brute-Force)
 * 2. Execution & Dropper Staging (WebShells, Uploads Executables, Obfuscated Backdoors)
 * 3. Multi-Persistence Anchors (Drop-ins, mu-plugins, DB Autoload Options, Rogue Cron)
 * 4. Privilege Escalation & Account Takeover (Rogue Admins, Injected Capabilities)
 * 5. Command & Control (C2) & Lateral Exfiltration (Decentralized EtherHiding, IPFS, Beacons)
 *
 * Computes Blast-Radius Exposure (0-100%), detects Lateral Movement across layers,
 * synthesizes human-readable executive incident narratives, and enables 1-Click
 * Full-Chain Surgical Eradication.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class AttackChainEngine {

    /**
     * Audit and correlate all system signals into consolidated attack chains.
     *
     * @return array
     */
    public function audit_attack_chains(): array {
        global $wpdb;

        // 1. Gather Open Scan Findings from Database
        $issues_table = $wpdb->prefix . 'wcpscan_scan_issues';
        $open_issues = [];
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $issues_table)) === $issues_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $open_issues = $wpdb->get_results(
                "SELECT id, engine, type, severity, confidence, file_path, line_number, evidence, description, created_at 
                 FROM {$issues_table} 
                 WHERE status = 'open' 
                 ORDER BY id DESC LIMIT 200",
                ARRAY_A
            ) ?: [];
        }

        // 2. Gather Persistence Findings via PersistenceScanner
        $persistence_scanner = new PersistenceScanner();
        $persistence_audit = $persistence_scanner->audit_full();

        // 3. Gather Recent Firewall Exploit Probes from wp_wcp_firewall_logs (Past 14 Days)
        $firewall_table = $wpdb->prefix . 'wcpscan_firewall_logs';
        $firewall_probes = [];
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $firewall_table)) === $firewall_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $firewall_probes = $wpdb->get_results(
                "SELECT id, ip_address, request_uri, request_method, rule_category, rule_description, created_at 
                 FROM {$firewall_table} 
                 WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
                 ORDER BY id DESC LIMIT 150",
                ARRAY_A
            ) ?: [];
        }

        // 4. Gather Users Created in Past 14 Days (or with Administrator role)
        $recent_users = $this->gather_recent_or_suspicious_users();

        // 5. Partition Signals into Kill-Chain Stages
        $staged_signals = [
            'initial_access'       => [],
            'execution_staging'    => [],
            'persistence'          => [],
            'privilege_escalation' => [],
            'c2_beacon'            => [],
        ];

        // Process Scan Issues
        foreach ($open_issues as $issue) {
            $type = $issue['type'] ?? '';
            $desc = $issue['description'] ?? '';
            $path = $issue['file_path'] ?? '';
            $evidence = $issue['evidence'] ?? '';

            // Stage 1: Vulnerability / CVE
            if (strpos($type, 'vulnerable_') !== false || strpos($type, 'outdated_') !== false) {
                $staged_signals['initial_access'][] = [
                    'source'      => 'scan_issue',
                    'id'          => $issue['id'],
                    'label'       => $desc,
                    'file_path'   => $path,
                    'type'        => $type,
                    'severity'    => $issue['severity'],
                    'timestamp'   => strtotime($issue['created_at']),
                    'evidence'    => $evidence,
                ];
            }
            // Stage 2: Staged WebShells / Upload Executables / Malware
            elseif (
                strpos($type, 'executable_in_uploads') !== false ||
                strpos($type, 'webshell') !== false ||
                strpos($type, 'backdoor') !== false ||
                strpos($type, 'malware') !== false ||
                strpos($type, 'obfuscated') !== false
            ) {
                $mtime = file_exists($path) ? @filemtime($path) : strtotime($issue['created_at']);
                $signal_item = [
                    'source'      => 'scan_issue',
                    'id'          => $issue['id'],
                    'label'       => basename($path) . ' - ' . $desc,
                    'file_path'   => $path,
                    'type'        => $type,
                    'severity'    => $issue['severity'],
                    'timestamp'   => $mtime ?: strtotime($issue['created_at']),
                    'evidence'    => $evidence,
                ];

                $staged_signals['execution_staging'][] = $signal_item;

                // Check if file contains C2 or EtherHiding strings
                if (stripos($evidence, 'eth.limo') !== false || stripos($evidence, 'ipfs') !== false || stripos($desc, 'C2') !== false) {
                    $staged_signals['c2_beacon'][] = [
                        'source'    => 'scan_issue',
                        'id'        => $issue['id'],
                        'label'     => 'Outbound C2 / Decentralized RPC in ' . basename($path),
                        'file_path' => $path,
                        'type'      => 'c2_beacon',
                        'severity'  => 'critical',
                        'timestamp' => $mtime,
                        'evidence'  => $evidence,
                    ];
                }
            }
            // Stage 4: Rogue Admin findings from issues
            elseif (strpos($type, 'rogue_admin') !== false || strpos($type, 'stealth_admin') !== false || strpos($type, 'capability') !== false) {
                $staged_signals['privilege_escalation'][] = [
                    'source'    => 'scan_issue',
                    'id'        => $issue['id'],
                    'label'     => $desc,
                    'file_path' => $path,
                    'type'      => $type,
                    'severity'  => $issue['severity'],
                    'timestamp' => strtotime($issue['created_at']),
                    'evidence'  => $evidence,
                ];
            }
        }

        // Process Persistence Signals
        // Drop-ins
        foreach ($persistence_audit['dropins'] as $d) {
            if ($d['status'] === 'malicious' || $d['is_unexpected']) {
                $staged_signals['persistence'][] = [
                    'source'    => 'dropin',
                    'id'        => $d['filename'],
                    'label'     => "Unauthorized Drop-in: {$d['filename']} ({$d['purpose']})",
                    'file_path' => $d['path'],
                    'type'      => 'dropin',
                    'severity'  => 'critical',
                    'timestamp' => $d['mtime'],
                    'evidence'  => $d['threat_summary'],
                ];
            }
        }
        // MU-Plugins
        foreach ($persistence_audit['mu_plugins'] as $m) {
            if ($m['status'] === 'malicious') {
                $staged_signals['persistence'][] = [
                    'source'    => 'mu_plugin',
                    'id'        => $m['filename'],
                    'label'     => "Stealth MU-Plugin: {$m['filename']}",
                    'file_path' => $m['path'],
                    'type'      => 'mu_plugin',
                    'severity'  => 'critical',
                    'timestamp' => $m['mtime'],
                    'evidence'  => $m['threat_summary'],
                ];
            }
        }
        // Autoload DB Options
        foreach ($persistence_audit['autoload_options'] as $o) {
            $sig = [
                'source'    => 'autoload_option',
                'id'        => $o['option_name'],
                'label'     => "Autoload Option Anchor: {$o['option_name']}",
                'file_path' => 'wp_options:' . $o['option_name'],
                'type'      => 'autoload_option',
                'severity'  => $o['severity'],
                'timestamp' => time(),
                'evidence'  => $o['reason'],
            ];
            $staged_signals['persistence'][] = $sig;

            if (stripos($o['reason'], 'EtherHiding') !== false || stripos($o['reason'], 'C2') !== false || stripos($o['snippet'], 'eth.limo') !== false) {
                $staged_signals['c2_beacon'][] = [
                    'source'    => 'autoload_option',
                    'id'        => $o['option_name'],
                    'label'     => "Decentralized EtherHiding C2 in option: {$o['option_name']}",
                    'file_path' => 'wp_options:' . $o['option_name'],
                    'type'      => 'c2_beacon',
                    'severity'  => 'critical',
                    'timestamp' => time(),
                    'evidence'  => $o['snippet'],
                ];
            }
        }
        // Rogue Cron Schedulers
        foreach ($persistence_audit['cron_tasks'] as $c) {
            if ($c['severity'] === 'critical' || $c['severity'] === 'high') {
                $staged_signals['persistence'][] = [
                    'source'    => 'cron_hook',
                    'id'        => $c['hook'],
                    'label'     => "Orphan / Rogue Cron Hook: {$c['hook']}",
                    'file_path' => 'wp_cron:' . $c['hook'],
                    'type'      => 'cron_hook',
                    'severity'  => $c['severity'],
                    'timestamp' => time(),
                    'evidence'  => $c['reason'],
                ];
            }
        }
        // Resurrections
        foreach ($persistence_audit['resurrections'] as $r) {
            $staged_signals['persistence'][] = [
                'source'    => 'resurrection',
                'id'        => $r['filename'],
                'label'     => "Resurrected Malware File: {$r['filename']}",
                'file_path' => $r['file_path'],
                'type'      => 'resurrection',
                'severity'  => 'critical',
                'timestamp' => $r['mtime'],
                'evidence'  => sprintf(__('File was remediated on %s but re-appeared on disk.', 'wcp-security-scanner'), $r['remediated_date']),
            ];
        }

        // Process Suspicious Users (Stage 4)
        foreach ($recent_users as $u) {
            $staged_signals['privilege_escalation'][] = [
                'source'    => 'user',
                'id'        => $u['ID'],
                'label'     => "Recently Created Admin: '{$u['user_login']}' (ID #{$u['ID']})",
                'file_path' => 'wp_users:' . $u['user_login'],
                'type'      => 'recent_admin_user',
                'severity'  => 'high',
                'timestamp' => strtotime($u['user_registered']),
                'evidence'  => "Registered: {$u['user_registered']} | Email: {$u['user_email']}",
            ];
        }

        // Process Firewall Exploit Probes (Stage 1 Correlation)
        $top_probe_ips = [];
        foreach ($firewall_probes as $probe) {
            $ip = $probe['ip_address'];
            if (!isset($top_probe_ips[$ip])) {
                $top_probe_ips[$ip] = [
                    'ip'         => $ip,
                    'hits'       => 0,
                    'categories' => [],
                    'last_seen'  => $probe['created_at'],
                ];
            }
            $top_probe_ips[$ip]['hits']++;
            $top_probe_ips[$ip]['categories'][$probe['rule_category']] = true;
        }

        // 6. Build Correlated Attack Chains
        $chains = $this->synthesize_chains($staged_signals, $top_probe_ips);

        // 7. Calculate Aggregated Blast Radius & Lateral Metrics
        $max_blast = 0;
        $highest_severity = 'clean';
        $lateral_detected = false;

        foreach ($chains as $chain) {
            if ($chain['blast_radius'] > $max_blast) {
                $max_blast = $chain['blast_radius'];
            }
            if ($chain['severity'] === 'critical') {
                $highest_severity = 'critical';
            } elseif ($chain['severity'] === 'high' && $highest_severity !== 'critical') {
                $highest_severity = 'high';
            }
            if ($chain['lateral_movement']) {
                $lateral_detected = true;
            }
        }

        return [
            'success'   => true,
            'timestamp' => time(),
            'summary'   => [
                'total_chains'          => count($chains),
                'max_blast_score'       => $max_blast,
                'highest_severity'      => $highest_severity,
                'lateral_movement'      => $lateral_detected,
                'total_isolated_threats'=> count($open_issues),
                'total_persistence_keys'=> count($persistence_audit['dropins']) + count($persistence_audit['mu_plugins']) + count($persistence_audit['autoload_options']),
                'firewall_threat_ips'   => count($top_probe_ips),
            ],
            'chains'    => $chains,
        ];
    }

    /**
     * Synthesize multi-stage signals into correlated attack chain incident graphs.
     */
    private function synthesize_chains(array $staged_signals, array $top_probe_ips): array {
        $chains = [];

        $has_initial = !empty($staged_signals['initial_access']);
        $has_staging = !empty($staged_signals['execution_staging']);
        $has_persist = !empty($staged_signals['persistence']);
        $has_privesc = !empty($staged_signals['privilege_escalation']);
        $has_c2      = !empty($staged_signals['c2_beacon']);

        // Incident Scenario A: WebShell Dropper + Persistence (Most Common Modern Kill Chain)
        if ($has_staging && ($has_persist || $has_privesc || $has_initial)) {
            $chain_id = 'chain_' . substr(md5('dropper_chain_' . time()), 0, 10);
            $stages = [];
            $remediation_plan = [
                'quarantine_files' => [],
                'delete_options'   => [],
                'delete_users'     => [],
                'clear_crons'      => [],
                'block_ips'        => [],
            ];

            // 1. Initial Access Stage
            if ($has_initial) {
                $init = $staged_signals['initial_access'][0];
                $stages[] = [
                    'stage_id'    => 'initial_access',
                    'stage_name'  => __('Initial Access (Vulnerability / Probe)', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $init['label'],
                    'details'     => $init['evidence'] ?: $init['label'],
                    'item_type'   => 'cve',
                    'item_id'     => $init['id'],
                ];
            } else {
                // Check if top firewall probe IP exists
                $top_ip = !empty($top_probe_ips) ? array_keys($top_probe_ips)[0] : null;
                $stages[] = [
                    'stage_id'    => 'initial_access',
                    'stage_name'  => __('Initial Access (Exploitation Probe)', 'wcp-security-scanner'),
                    'status'      => $top_ip ? 'breached' : 'bypassed',
                    'title'       => $top_ip ? "Arbitrary File Upload / Exploit Probing from {$top_ip}" : __('Direct Unauthenticated Injection / File Drop', 'wcp-security-scanner'),
                    'details'     => $top_ip ? "Repeated automated probing blocked by WAF lite from IP {$top_ip}." : __('Direct unauthorized file creation in writable WordPress directory.', 'wcp-security-scanner'),
                    'item_type'   => 'firewall_ip',
                    'item_id'     => $top_ip ?: '0.0.0.0',
                ];
                if ($top_ip) {
                    $remediation_plan['block_ips'][] = $top_ip;
                }
            }

            // 2. Execution & Staging
            foreach ($staged_signals['execution_staging'] as $stg) {
                $stages[] = [
                    'stage_id'    => 'execution_staging',
                    'stage_name'  => __('Execution & WebShell Staging', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $stg['label'],
                    'details'     => "Path: {$stg['file_path']} | Risk: {$stg['type']}",
                    'item_type'   => 'file',
                    'item_id'     => $stg['file_path'],
                ];
                $remediation_plan['quarantine_files'][] = $stg['file_path'];
            }

            // 3. Multi-Persistence
            foreach ($staged_signals['persistence'] as $pst) {
                $stages[] = [
                    'stage_id'    => 'persistence',
                    'stage_name'  => __('Persistence & Self-Healing Anchor', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $pst['label'],
                    'details'     => $pst['evidence'],
                    'item_type'   => $pst['type'],
                    'item_id'     => $pst['id'],
                ];

                if (in_array($pst['type'], ['dropin', 'mu_plugin', 'resurrection'], true)) {
                    $remediation_plan['quarantine_files'][] = $pst['file_path'];
                } elseif ($pst['type'] === 'autoload_option') {
                    $remediation_plan['delete_options'][] = $pst['id'];
                } elseif ($pst['type'] === 'cron_hook') {
                    $remediation_plan['clear_crons'][] = $pst['id'];
                }
            }

            // 4. Privilege Escalation
            foreach ($staged_signals['privilege_escalation'] as $pesc) {
                $stages[] = [
                    'stage_id'    => 'privilege_escalation',
                    'stage_name'  => __('Privilege Escalation & Account Takeover', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $pesc['label'],
                    'details'     => $pesc['evidence'],
                    'item_type'   => 'user',
                    'item_id'     => $pesc['id'],
                ];
                if (is_numeric($pesc['id'])) {
                    $remediation_plan['delete_users'][] = (int) $pesc['id'];
                }
            }

            // 5. C2 Communication
            foreach ($staged_signals['c2_beacon'] as $c2) {
                $stages[] = [
                    'stage_id'    => 'c2_beacon',
                    'stage_name'  => __('Command & Control (C2) / Exfiltration', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $c2['label'],
                    'details'     => $c2['evidence'],
                    'item_type'   => 'c2',
                    'item_id'     => $c2['file_path'],
                ];
            }

            // Calculate Blast Radius
            $blast_radius = 35; // Base for verified execution
            if ($has_initial) $blast_radius += 15;
            if ($has_persist) $blast_radius += 25;
            if ($has_privesc) $blast_radius += 15;
            if ($has_c2)      $blast_radius += 10;
            $blast_radius = min(100, $blast_radius);

            // Generate Narrative
            $narrative = $this->synthesize_narrative($stages, $blast_radius);

            $chains[] = [
                'chain_id'         => $chain_id,
                'title'            => __('Compounded WebShell Infiltration & Persistence Chain', 'wcp-security-scanner'),
                'severity'         => $blast_radius >= 70 ? 'critical' : 'high',
                'blast_radius'     => $blast_radius,
                'lateral_movement' => ($has_persist || $has_privesc),
                'narrative'        => $narrative,
                'stages'           => $stages,
                'remediation_plan' => $remediation_plan,
            ];
        }

        // Incident Scenario B: Standalone Persistence or Ghost Admin Escalation
        elseif ($has_persist || $has_privesc) {
            $chain_id = 'chain_' . substr(md5('persistence_chain_' . time()), 0, 10);
            $stages = [];
            $remediation_plan = [
                'quarantine_files' => [],
                'delete_options'   => [],
                'delete_users'     => [],
                'clear_crons'      => [],
                'block_ips'        => [],
            ];

            foreach ($staged_signals['persistence'] as $pst) {
                $stages[] = [
                    'stage_id'    => 'persistence',
                    'stage_name'  => __('Persistence & Self-Healing Anchor', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $pst['label'],
                    'details'     => $pst['evidence'],
                    'item_type'   => $pst['type'],
                    'item_id'     => $pst['id'],
                ];
                if (in_array($pst['type'], ['dropin', 'mu_plugin', 'resurrection'], true)) {
                    $remediation_plan['quarantine_files'][] = $pst['file_path'];
                } elseif ($pst['type'] === 'autoload_option') {
                    $remediation_plan['delete_options'][] = $pst['id'];
                } elseif ($pst['type'] === 'cron_hook') {
                    $remediation_plan['clear_crons'][] = $pst['id'];
                }
            }

            foreach ($staged_signals['privilege_escalation'] as $pesc) {
                $stages[] = [
                    'stage_id'    => 'privilege_escalation',
                    'stage_name'  => __('Privilege Escalation & Account Takeover', 'wcp-security-scanner'),
                    'status'      => 'breached',
                    'title'       => $pesc['label'],
                    'details'     => $pesc['evidence'],
                    'item_type'   => 'user',
                    'item_id'     => $pesc['id'],
                ];
                if (is_numeric($pesc['id'])) {
                    $remediation_plan['delete_users'][] = (int) $pesc['id'];
                }
            }

            $blast_radius = 45;
            if ($has_privesc) $blast_radius += 25;
            if ($has_c2)      $blast_radius += 15;

            $narrative = $this->synthesize_narrative($stages, $blast_radius);

            $chains[] = [
                'chain_id'         => $chain_id,
                'title'            => __('Dormant Persistence Anchor & Privilege Drift', 'wcp-security-scanner'),
                'severity'         => $blast_radius >= 70 ? 'critical' : 'high',
                'blast_radius'     => $blast_radius,
                'lateral_movement' => $has_privesc,
                'narrative'        => $narrative,
                'stages'           => $stages,
                'remediation_plan' => $remediation_plan,
            ];
        }

        return $chains;
    }

    /**
     * Synthesize human-readable incident narrative storyline.
     */
    private function synthesize_narrative(array $stages, int $blast_radius): string {
        $parts = [];

        $has_init = false;
        $has_exec = false;
        $has_persist = false;
        $has_privesc = false;
        $has_c2 = false;

        foreach ($stages as $s) {
            if ($s['stage_id'] === 'initial_access') $has_init = true;
            if ($s['stage_id'] === 'execution_staging') $has_exec = true;
            if ($s['stage_id'] === 'persistence') $has_persist = true;
            if ($s['stage_id'] === 'privilege_escalation') $has_privesc = true;
            if ($s['stage_id'] === 'c2_beacon') $has_c2 = true;
        }

        if ($has_init) {
            $parts[] = __('Threat actor probed edge entry points or leveraged known component vulnerabilities to compromise the WordPress boundary.', 'wcp-security-scanner');
        }

        if ($has_exec) {
            $parts[] = __('A dropper or executable webshell payload was deposited into a writable directory (e.g. wp-content/uploads/ or plugin tree) to establish arbitrary code execution.', 'wcp-security-scanner');
        }

        if ($has_persist) {
            $parts[] = __('To evade standard file deletion, the payload established persistent anchors inside drop-in files, mu-plugins, or database autoload transients.', 'wcp-security-scanner');
        }

        if ($has_privesc) {
            $parts[] = __('Lateral privilege escalation was achieved through the creation of unauthorized administrator accounts or capability injection.', 'wcp-security-scanner');
        }

        if ($has_c2) {
            $parts[] = __('Outbound beaconing or decentralized Web3 / IPFS C2 infrastructure was observed communicating commands.', 'wcp-security-scanner');
        }

        $posture = $blast_radius >= 75
            ? __('Critical blast radius: Full administrative and filesystem takeover detected across multiple architectural layers.', 'wcp-security-scanner')
            : ($blast_radius >= 45
                ? __('Substantial blast radius: Lateral movement detected between the filesystem and WordPress database.', 'wcp-security-scanner')
                : __('Contained threat: Activity was caught before full lateral compromise could complete.', 'wcp-security-scanner'));

        return implode(' ', $parts) . ' ' . $posture;
    }

    /**
     * Gather recent or suspicious users created in past 14 days.
     */
    private function gather_recent_or_suspicious_users(): array {
        global $wpdb;

        // Query users created in past 14 days with administrator capabilities
        $cap_key = $wpdb->prefix . 'capabilities';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $users = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT u.ID, u.user_login, u.user_email, u.user_registered 
                 FROM {$wpdb->users} u
                 INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id AND um.meta_key = %s
                 WHERE um.meta_value LIKE %s 
                   AND u.user_registered >= DATE_SUB(NOW(), INTERVAL 14 DAY)
                   AND u.ID != %d
                 ORDER BY u.ID DESC LIMIT 20",
                $cap_key,
                '%administrator%',
                get_current_user_id()
            ),
            ARRAY_A
        ) ?: [];

        return $users;
    }

    /**
     * 1-Click Surgical Full Attack-Chain Eradication.
     * Transactionally neutralizes all correlated stages across files, database, users, and firewall.
     *
     * @param string $chain_id
     * @param array $plan Plan containing quarantine_files, delete_options, delete_users, clear_crons, block_ips
     * @return array
     */
    public function eradicate_chain(string $chain_id, array $plan): array {
        $remediation_mgr = new RemediationManager();
        $persistence_scanner = new PersistenceScanner();
        $user_mgr = new UserRemediationManager();

        $actions_taken = [];
        $errors = [];
        $vault_backups = [];

        // Begin atomic remediation transaction with 1-click safe rollback capability
        $tx_id = \WcpScanner\Remediation\TransactionalRemediation::start_transaction(
            sprintf(__('Attack Chain Eradication: %s', 'wcp-security-scanner'), $chain_id),
            sprintf(__('Autonomous multi-threat remediation for chain %s', 'wcp-security-scanner'), $chain_id),
            ['chain_id' => $chain_id]
        );

        // 1. Quarantine Staged Files
        if (!empty($plan['quarantine_files']) && is_array($plan['quarantine_files'])) {
            foreach ($plan['quarantine_files'] as $file_path) {
                if (!file_exists($file_path)) {
                    continue;
                }
                if (!PathValidator::is_inside_root($file_path, ABSPATH)) {
                    $errors[] = "File outside root: {$file_path}";
                    continue;
                }

                // Record pre-remediation byte-for-byte snapshot in the transaction vault
                \WcpScanner\Remediation\TransactionalRemediation::record_file_snapshot($tx_id, $file_path, 'quarantine');

                $backup = $remediation_mgr->create_file_backup($file_path, 'attack_chain_eradication');
                if ($backup['success']) {
                    $vault_backups[] = $backup['backup_id'];
                    $quarantined_name = $file_path . '.wcp-chain-quarantine-' . time();
                    if (@rename($file_path, $quarantined_name) || @unlink($file_path)) {
                        $actions_taken[] = sprintf(__('Quarantined file: %s', 'wcp-security-scanner'), basename($file_path));
                    } else {
                        $errors[] = "Could not delete/rename file: {$file_path}";
                    }
                } else {
                    $errors[] = "Safety backup failed for: {$file_path}";
                }
            }
        }

        // 2. Delete Database Autoload Options & Transients
        if (!empty($plan['delete_options']) && is_array($plan['delete_options'])) {
            foreach ($plan['delete_options'] as $opt_name) {
                $res = $persistence_scanner->neutralize_item('autoload_option', $opt_name);
                if ($res['success']) {
                    $actions_taken[] = sprintf(__('Deleted malicious DB option: %s', 'wcp-security-scanner'), $opt_name);
                    if (!empty($res['backup_id'])) {
                        $vault_backups[] = $res['backup_id'];
                    }
                } else {
                    $errors[] = "Failed to delete DB option: {$opt_name}";
                }
            }
        }

        // 3. Demote or Delete Rogue Users
        if (!empty($plan['delete_users']) && is_array($plan['delete_users'])) {
            foreach ($plan['delete_users'] as $user_id) {
                $uid = (int) $user_id;
                if ($uid === get_current_user_id() || $uid <= 0) {
                    continue;
                }
                $res = $user_mgr->delete_user($uid);
                if ($res['success']) {
                    $actions_taken[] = sprintf(__('Deleted rogue user #%d', 'wcp-security-scanner'), $uid);
                } else {
                    // Try demoting to subscriber instead
                    $demote_res = $user_mgr->assign_role($uid, 'subscriber');
                    if ($demote_res['success']) {
                        $actions_taken[] = sprintf(__('Demoted user #%d to subscriber', 'wcp-security-scanner'), $uid);
                    } else {
                        $errors[] = "Could not remove or demote user #{$uid}: " . ($res['error'] ?? '');
                    }
                }
            }
        }

        // 4. Clear Orphan / Rogue Cron Hooks
        if (!empty($plan['clear_crons']) && is_array($plan['clear_crons'])) {
            foreach ($plan['clear_crons'] as $hook) {
                wp_clear_scheduled_hook($hook);
                $actions_taken[] = sprintf(__('Cleared cron hook: %s', 'wcp-security-scanner'), $hook);
            }
        }

        // 5. Block Attacker IPs in WAF
        if (!empty($plan['block_ips']) && is_array($plan['block_ips'])) {
            $existing_blocked = get_option('wcpscan_firewall_blacklist_ips', '');
            $blocked_lines = array_filter(array_map('trim', explode("\n", (string) $existing_blocked)));
            foreach ($plan['block_ips'] as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) && !in_array($ip, $blocked_lines, true)) {
                    $blocked_lines[] = $ip;
                    $actions_taken[] = sprintf(__('Blocked threat IP in WAF: %s', 'wcp-security-scanner'), $ip);
                }
            }
            update_option('wcpscan_firewall_blacklist_ips', implode("\n", $blocked_lines));
        }

        // 6. Auto-reconcile open scan issues associated with these quarantined files
        global $wpdb;
        $issues_table = $wpdb->prefix . 'wcpscan_scan_issues';
        if (!empty($plan['quarantine_files']) && $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $issues_table)) === $issues_table) {
            foreach ($plan['quarantine_files'] as $fp) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update(
                    $issues_table,
                    ['status' => 'repaired'],
                    ['file_path' => $fp, 'status' => 'open'],
                    ['%s'],
                    ['%s', '%s']
                );
            }
        }

        // 7. Commit Transaction & Record Audit Log Entry
        \WcpScanner\Remediation\TransactionalRemediation::commit_transaction($tx_id);

        AuditLogger::log_event(
            'attack_chain_eradicated',
            sprintf(__('Eradicated attack chain "%s": %d actions executed under transaction %s.', 'wcp-security-scanner'), $chain_id, count($actions_taken), $tx_id)
        );

        return [
            'success'       => empty($errors) || count($actions_taken) > 0,
            'chain_id'      => $chain_id,
            'tx_id'         => $tx_id,
            'actions_taken' => $actions_taken,
            'vault_backups' => $vault_backups,
            'errors'        => $errors,
            'message'       => sprintf(
                __('Attack Chain Eradication Complete: %d actions executed successfully across files, database, and firewall. Transaction snapshot "%s" saved for safe rollback.', 'wcp-security-scanner'),
                count($actions_taken),
                $tx_id
            ),
        ];
    }
}
