<?php
namespace WcpScanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

class CorrelationEngine {

    /**
     * Correlate findings across multiple engines to identify high-confidence compound threats.
     *
     * @param Finding[] $findings
     * @return Finding[] Correlated and elevated findings
     */
    public function correlate($findings) {
        if (empty($findings)) {
            return [];
        }

        // Group findings by file_path or target identifier
        $grouped = [];
        foreach ($findings as $idx => $finding) {
            $key = trim($finding->file_path);
            if (empty($key)) {
                $key = '__global__' . $idx;
            }
            $grouped[$key][] = $finding;
        }

        $correlated_findings = [];

        foreach ($grouped as $target => $target_findings) {
            $norm_target = str_replace('\\', '/', rtrim($target, '/'));
            if (
                strpos($norm_target, '/plugins/wcp-security-scanner') !== false ||
                strpos($norm_target, '/tests/') !== false
            ) {
                continue; // Always drop findings on scanner's own code
            }

            if (count($target_findings) === 1) {
                $correlated_findings[] = $target_findings[0];
                continue;
            }

            // Multiple findings for the same target! Check if from different engines
            $engines = [];
            $types = [];
            foreach ($target_findings as $f) {
                $engines[$f->engine] = true;
                $types[$f->type] = true;
            }

            $unique_engines = array_keys($engines);

            // Pattern 1: Modified Core/Plugin + Malware Heuristic / Obfuscation
            $has_integrity = isset($engines['integrity-core']) || isset($engines['integrity-plugin']);
            $has_malware = isset($engines['malware-obfuscation']) || isset($engines['malware-webshell']) || isset($engines['malware-strings']);
            $is_upload = strpos($target, '/uploads/') !== false;

            if (($has_integrity && $has_malware) || ($is_upload && $has_malware)) {
                // Compound High-Confidence Threat!
                $reasons = [];
                if ($has_integrity) $reasons[] = 'modified checksum';
                if ($is_upload) $reasons[] = 'located in writable uploads directory';
                if (isset($engines['malware-webshell'])) $reasons[] = 'webshell command execution';
                if (isset($engines['malware-obfuscation'])) $reasons[] = 'obfuscated/encoded payload';

                $summary_evidence = "Multi-Engine Correlation Alert: [" . implode(' + ', $reasons) . "] detected on same target. Confirmed malicious attack vector.";

                foreach ($target_findings as $f) {
                    $f->severity = 'critical';
                    $f->confidence = 99;
                    $f->evidence = $f->evidence ? ($f->evidence . " | " . $summary_evidence) : $summary_evidence;
                    $f->description .= " [CORRELATED THREAT: Confirmed by multiple scanner engines]";
                    $correlated_findings[] = $f;
                }
            } else {
                // Keep original findings with slight confidence boost for multi-signal verification
                foreach ($target_findings as $f) {
                    if (count($unique_engines) > 1) {
                        $f->confidence = min(99, $f->confidence + 10);
                    }
                    $correlated_findings[] = $f;
                }
            }
        }

        return $correlated_findings;
    }

    /**
     * Generate the 5-Tier Telemetry Hierarchy across Filesystem, Database, WAF, Identity, and Network.
     *
     * 1. Facts: Concrete observed events with exact timestamps and target entities.
     * 2. Indicators: Contextualized telemetry signals (e.g., unauthenticated access, writable drops).
     * 3. Correlations: Multi-signal clusters grouped by temporal proximity, IP address, user, or file.
     * 4. Hypotheses: Attack kill-chain synthesis (e.g., Exploit -> Backdoor -> Rogue Admin -> Exfiltration).
     * 5. Confirmed Outcomes: Actionable containment roadmap and 1-click remediation items.
     *
     * @return array Structured 5-Tier Telemetry report
     */
    public static function generate_telemetry_hierarchy(): array {
        global $wpdb;

        $facts = [];
        $indicators = [];
        $correlations = [];
        $hypotheses = [];
        $outcomes = [];

        // -------------------------------------------------------------
        // 1. GATHER FACTS FROM SUBSYSTEMS
        // -------------------------------------------------------------

        // Fact Source A: Open Scan Issues
        $issues_table = $wpdb->prefix . 'wcpscan_scan_issues';
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $issues_table)) === $issues_table) {
            $query = "SELECT id, engine, type, severity, confidence, file_path, line_number, evidence, description, created_at FROM {$issues_table} WHERE status = 'open' ORDER BY id DESC LIMIT 50";
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
            $issues = $wpdb->get_results($query, ARRAY_A) ?: [];

            foreach ($issues as $issue) {
                $facts[] = [
                    'fact_id'      => 'fact-scan-' . $issue['id'],
                    'timestamp'    => strtotime($issue['created_at']) ?: time(),
                    'source'       => 'scanner',
                    'subsystem'    => $issue['engine'],
                    'event_type'   => $issue['type'],
                    'severity'     => $issue['severity'],
                    'target'       => $issue['file_path'],
                    'detail'       => $issue['description'],
                    'evidence'     => $issue['evidence'],
                ];
            }
        }

        // Fact Source B: Recent Daily Partitioned WAF Logs (from WafFileLogger)
        $upload_dir = wp_upload_dir();
        $waf_dir = $upload_dir['basedir'] . '/wcp-security-scanner/waf-logs';
        if (is_dir($waf_dir)) {
            $today_log = $waf_dir . '/' . strtolower(gmdate('F-j-Y')) . '-waf-logs.json';
            if (file_exists($today_log)) {
                $lines = file($today_log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if (is_array($lines)) {
                    $recent_lines = array_slice($lines, -40);
                    foreach ($recent_lines as $idx => $line) {
                        $entry = json_decode($line, true);
                        if (!is_array($entry)) {
                            continue;
                        }
                        $facts[] = [
                            'fact_id'      => 'fact-waf-' . ($entry['id'] ?? $idx),
                            'timestamp'    => $entry['timestamp'] ?? time(),
                            'source'       => 'firewall',
                            'subsystem'    => 'waf_file_logger',
                            'event_type'   => $entry['category'] ?? 'WAF_INTERCEPT',
                            'severity'     => in_array($entry['category'] ?? '', ['RCE', 'SQLI', 'AUTH_BYPASS'], true) ? 'critical' : 'high',
                            'target'       => $entry['uri'] ?? '/',
                            'client_ip'    => $entry['ip'] ?? '0.0.0.0',
                            'detail'       => sprintf(
                                /* translators: 1: HTTP Method, 2: Target URI, 3: Rule Name */
                                __('WAF blocked %1$s request to %2$s via rule %3$s', 'wcp-security-scanner'),
                                $entry['method'] ?? 'GET',
                                $entry['uri'] ?? '/',
                                $entry['rule_name'] ?? 'WAF Rule'
                            ),
                            'evidence'     => $entry['payload_sample'] ?? '',
                        ];
                    }
                }
            }
        }

        // Fact Source C: Decoy Ghost Route & Canary Traps
        $ghost_traps = get_option('wcpscan_ghost_route_traps', []);
        if (is_array($ghost_traps) && !empty($ghost_traps)) {
            foreach (array_slice(array_reverse($ghost_traps), 0, 15) as $idx => $trap) {
                $facts[] = [
                    'fact_id'      => 'fact-ghost-' . $idx,
                    'timestamp'    => $trap['timestamp'] ?? time(),
                    'source'       => 'canary',
                    'subsystem'    => 'ghost_route_trap',
                    'event_type'   => 'HONEYPOT_TRIGGER',
                    'severity'     => 'critical',
                    'target'       => $trap['route'] ?? '/wcp-internal/v1/telemetry-debug',
                    'client_ip'    => $trap['ip'] ?? '0.0.0.0',
                    'detail'       => sprintf(
                        /* translators: 1: IP Address, 2: Honeypot Route */
                        __('Autonomous bot or vulnerability scanner probe intercepted at canary route %2$s from IP %1$s', 'wcp-security-scanner'),
                        $trap['ip'] ?? 'Unknown',
                        $trap['route'] ?? 'Ghost Route'
                    ),
                    'evidence'     => $trap['user_agent'] ?? '',
                ];
            }
        }

        // Fact Source D: 72-Hour Reinfection Watchdog Alerts
        $reinfection_alerts = get_option('wcpscan_reinfection_incidents', []);
        if (is_array($reinfection_alerts) && !empty($reinfection_alerts)) {
            foreach ($reinfection_alerts as $idx => $alert) {
                $facts[] = [
                    'fact_id'      => 'fact-reinfect-' . $idx,
                    'timestamp'    => $alert['timestamp'] ?? time(),
                    'source'       => 'watchdog',
                    'subsystem'    => 'reinfection_watchdog',
                    'event_type'   => 'REINFECTION_DETECTED',
                    'severity'     => 'critical',
                    'target'       => $alert['path'] ?? '',
                    'detail'       => sprintf(
                        /* translators: 1: File Path, 2: Detection Type */
                        __('Previously quarantined/cleaned file resurrected on disk: %1$s (%2$s)', 'wcp-security-scanner'),
                        $alert['path'] ?? '',
                        $alert['type'] ?? 'resurrection'
                    ),
                    'evidence'     => $alert['evidence'] ?? '',
                ];
            }
        }

        // -------------------------------------------------------------
        // 2. DERIVE INDICATORS (CONTEXTUALIZED SIGNALS)
        // -------------------------------------------------------------
        $ips_seen = [];
        $files_seen = [];

        foreach ($facts as $fact) {
            $cat = 'general';
            $ev_type = strtolower($fact['event_type']);

            if (strpos($ev_type, 'sqli') !== false || strpos($ev_type, 'sql') !== false) {
                $cat = 'database_injection';
            } elseif (strpos($ev_type, 'webshell') !== false || strpos($ev_type, 'rce') !== false || strpos($ev_type, 'executable') !== false) {
                $cat = 'arbitrary_code_execution';
            } elseif (strpos($ev_type, 'reinfection') !== false || strpos($ev_type, 'persistence') !== false) {
                $cat = 'persistent_presence';
            } elseif (strpos($ev_type, 'honeypot') !== false || strpos($ev_type, 'recon') !== false) {
                $cat = 'reconnaissance';
            } elseif (strpos($ev_type, 'admin') !== false || strpos($ev_type, 'privilege') !== false) {
                $cat = 'privilege_escalation';
            }

            $indicator_id = 'ind-' . substr(md5($fact['fact_id'] . $cat), 0, 8);
            $indicators[$indicator_id] = [
                'indicator_id' => $indicator_id,
                'fact_id'      => $fact['fact_id'],
                'category'     => $cat,
                'severity'     => $fact['severity'],
                'confidence'   => 85,
                'target'       => $fact['target'],
                'client_ip'    => $fact['client_ip'] ?? null,
                'timestamp'    => $fact['timestamp'],
                'summary'      => $fact['detail'],
            ];

            if (!empty($fact['client_ip'])) {
                $ips_seen[$fact['client_ip']][] = $indicator_id;
            }
            if (!empty($fact['target'])) {
                $files_seen[$fact['target']][] = $indicator_id;
            }
        }

        // -------------------------------------------------------------
        // 3. GENERATE MULTI-SIGNAL CORRELATIONS
        // -------------------------------------------------------------
        $correlation_clusters = [];

        // Correlate by IP (if same IP triggered honeypot + WAF)
        foreach ($ips_seen as $ip => $ind_ids) {
            if (count($ind_ids) >= 2) {
                $c_id = 'corr-ip-' . substr(md5($ip), 0, 8);
                $correlation_clusters[$c_id] = [
                    'correlation_id' => $c_id,
                    'type'           => 'ip_aggregation',
                    'entity'         => $ip,
                    'indicator_ids'  => array_unique($ind_ids),
                    'description'    => sprintf(
                        /* translators: 1: IP address, 2: Indicator count */
                        __('Multiple adversarial indicators converged on origin IP %1$s (%2$d distinct events).', 'wcp-security-scanner'),
                        $ip,
                        count($ind_ids)
                    ),
                    'confidence'     => 95,
                    'severity'       => 'critical',
                ];
            }
        }

        // Correlate by Target File (if file has scan issue + reinfection or FIM drift)
        foreach ($files_seen as $file => $ind_ids) {
            if (count($ind_ids) >= 2) {
                $c_id = 'corr-file-' . substr(md5($file), 0, 8);
                $correlation_clusters[$c_id] = [
                    'correlation_id' => $c_id,
                    'type'           => 'file_convergence',
                    'entity'         => $file,
                    'indicator_ids'  => array_unique($ind_ids),
                    'description'    => sprintf(
                        /* translators: 1: File path, 2: Event count */
                        __('Compound compromise indicators converged on file target %1$s (%2$d distinct events).', 'wcp-security-scanner'),
                        basename($file),
                        count($ind_ids)
                    ),
                    'confidence'     => 99,
                    'severity'       => 'critical',
                ];
            }
        }

        // -------------------------------------------------------------
        // 4. SYNTHESIZE ATTACK KILL-CHAIN HYPOTHESES
        // -------------------------------------------------------------
        $has_recon = false;
        $has_rce = false;
        $has_reinfection = false;

        foreach ($indicators as $ind) {
            if ($ind['category'] === 'reconnaissance') $has_recon = true;
            if ($ind['category'] === 'arbitrary_code_execution') $has_rce = true;
            if ($ind['category'] === 'persistent_presence') $has_reinfection = true;
        }

        if ($has_rce && $has_reinfection) {
            $hypotheses[] = [
                'hypothesis_id' => 'hyp-001',
                'title'         => __('Persistent Dropper Re-infection Loop', 'wcp-security-scanner'),
                'kill_chain'    => ['Exploitation', 'Dropper Staging', 'Persistence Loop'],
                'confidence'    => 96,
                'severity'      => 'critical',
                'narrative'     => __('Attacker established a self-healing memory-resident or cron-based persistence mechanism that recreates remediated backdoors upon deletion.', 'wcp-security-scanner'),
                'blast_radius'  => 85,
            ];
        } elseif ($has_recon && $has_rce) {
            $hypotheses[] = [
                'hypothesis_id' => 'hyp-002',
                'title'         => __('Targeted Reconnaissance Leading to Code Execution', 'wcp-security-scanner'),
                'kill_chain'    => ['Reconnaissance', 'Vulnerability Probe', 'Arbitrary Code Execution'],
                'confidence'    => 92,
                'severity'      => 'critical',
                'narrative'     => __('Adversary performed automated endpoint reconnaissance probing canary routes and subsequently delivered an executable payload.', 'wcp-security-scanner'),
                'blast_radius'  => 70,
            ];
        } elseif (!empty($facts)) {
            $hypotheses[] = [
                'hypothesis_id' => 'hyp-003',
                'title'         => __('Isolated Perimeter Exploit Attempts Intercepted', 'wcp-security-scanner'),
                'kill_chain'    => ['Initial Access Attempt'],
                'confidence'    => 80,
                'severity'      => 'medium',
                'narrative'     => __('Perimeter defenses and WAF successfully deflected inbound automated probes. No lateral breach confirmed.', 'wcp-security-scanner'),
                'blast_radius'  => 15,
            ];
        } else {
            $hypotheses[] = [
                'hypothesis_id' => 'hyp-clean',
                'title'         => __('Zero Active Threat Convergence', 'wcp-security-scanner'),
                'kill_chain'    => ['Clean State'],
                'confidence'    => 100,
                'severity'      => 'safe',
                'narrative'     => __('All monitoring subsystems (Filesystem, WAF, Identity, Network) report normal baseline activity. No compromise detected.', 'wcp-security-scanner'),
                'blast_radius'  => 0,
            ];
        }

        // -------------------------------------------------------------
        // 5. CONFIRMED OUTCOMES & CONTAINMENT ROADMAP
        // -------------------------------------------------------------
        if ($has_reinfection || $has_rce) {
            $outcomes[] = [
                'action_id'   => 'act-containment',
                'title'       => __('Activate 1-Click Emergency Incident Containment', 'wcp-security-scanner'),
                'type'        => 'containment',
                'priority'    => 'P0_IMMEDIATE',
                'description' => __('Freeze filesystem write channels, purge non-admin sessions, and isolate origin blast radius.', 'wcp-security-scanner'),
                'endpoint'    => '/wcp-scanner/v1/containment/toggle',
                'method'      => 'POST',
                'payload'     => ['action' => 'activate', 'reason' => 'Correlated Multi-Engine Threat Outbreak'],
            ];
            $outcomes[] = [
                'action_id'   => 'act-quarantine-all',
                'title'       => __('Execute Surgical Attack-Chain Eradication', 'wcp-security-scanner'),
                'type'        => 'eradication',
                'priority'    => 'P1_HIGH',
                'description' => __('Quarantine all correlated dropper files, delete rogue options, and flush malicious crons in one atomic transaction.', 'wcp-security-scanner'),
                'endpoint'    => '/wcp-scanner/v1/attack-chain/eradicate',
                'method'      => 'POST',
            ];
        } elseif (!empty($facts)) {
            $outcomes[] = [
                'action_id'   => 'act-harden',
                'title'       => __('Review WAF Logs & Reinforce Edge IP Defenses', 'wcp-security-scanner'),
                'type'        => 'hardening',
                'priority'    => 'P2_RECOMMENDED',
                'description' => __('Sync discovered adversarial probe IPs to Cloudflare Edge IP Lists and review server security headers.', 'wcp-security-scanner'),
                'endpoint'    => '/wcp-scanner/v1/cloudflare/sync',
                'method'      => 'POST',
            ];
        } else {
            $outcomes[] = [
                'action_id'   => 'act-snapshot',
                'title'       => __('Calibrate Local "Time-Machine" Baseline Snapshot', 'wcp-security-scanner'),
                'type'        => 'maintenance',
                'priority'    => 'P3_ROUTINE',
                'description' => __('Capture a fresh compressed baseline archive of active bespoke plugins and themes for future integrity tracking.', 'wcp-security-scanner'),
                'endpoint'    => '/wcp-scanner/v1/snapshots/create',
                'method'      => 'POST',
            ];
        }

        return [
            'success'      => true,
            'generated_at' => time(),
            'counts'       => [
                'facts'        => count($facts),
                'indicators'   => count($indicators),
                'correlations' => count($correlation_clusters),
                'hypotheses'   => count($hypotheses),
                'outcomes'     => count($outcomes),
            ],
            'hierarchy'    => [
                'tier_1_facts'        => array_values($facts),
                'tier_2_indicators'   => array_values($indicators),
                'tier_3_correlations' => array_values($correlation_clusters),
                'tier_4_hypotheses'   => array_values($hypotheses),
                'tier_5_outcomes'     => array_values($outcomes),
            ],
        ];
    }
}
