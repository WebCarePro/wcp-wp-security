<?php
namespace WCP\Scanner\Reports;

use WCP\Scanner\Findings\RiskScorer;
use WCP\Scanner\System\ServerInfo;
use WCP\Scanner\Forensics\AttackChainEngine;
use WCP\Scanner\WordPress\PersistenceScanner;
use WCP\Scanner\Firewall\VirtualPatchManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * IncidentReportEngine
 *
 * Compiles executive-grade board and client incident response reports
 * and security posture audits. Generates machine-readable SIEM JSON
 * and print-optimized Executive HTML/PDF documents.
 *
 * Prepared by: Mir Alamin (WebCare Pro) - Senior Linux SysAdmin & WordPress Security Engineer.
 */
class IncidentReportEngine {

    /**
     * Compile comprehensive incident and posture report data.
     *
     * @param array $options Custom options (client_name, auditor_notes, include_chains, etc.)
     * @return array
     */
    public static function generate_report(array $options = []): array {
        global $wpdb;

        $table_scans  = $wpdb->prefix . 'wcp_scans';
        $table_issues = $wpdb->prefix . 'wcp_scan_issues';

        // 1. Fetch Latest Scan
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $scan = $wpdb->get_row(
            "SELECT * FROM `{$table_scans}` WHERE scan_target IN ('plugins_themes', 'full') ORDER BY id DESC LIMIT 1",
            ARRAY_A
        );

        $scan_id = $scan ? (int) $scan['id'] : 0;
        $issues = [];
        if ($scan_id > 0) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $issues = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC",
                $scan_id
            ), ARRAY_A) ?: [];
        }

        // 2. Compute Issue Statistics & Status Ledger
        $counts = [
            'critical' => 0,
            'high'     => 0,
            'medium'   => 0,
            'low'      => 0,
            'info'     => 0,
        ];
        $status_ledger = [
            'open'        => 0,
            'remediated'  => 0,
            'quarantined' => 0,
            'patched'     => 0,
            'ignored'     => 0,
        ];

        foreach ($issues as $issue) {
            $sev = strtolower($issue['severity'] ?? 'low');
            if (isset($counts[$sev])) {
                $counts[$sev]++;
            } else {
                $counts['low']++;
            }

            $st = strtolower($issue['status'] ?? 'open');
            if (isset($status_ledger[$st])) {
                $status_ledger[$st]++;
            } else {
                $status_ledger['open']++;
            }
        }

        // 3. Behavioral Attack Chains (Phase 2)
        $attack_chains = [];
        try {
            $chain_data = AttackChainEngine::correlate_chains();
            $attack_chains = $chain_data['chains'] ?? [];
        } catch (\Throwable $e) {
            $attack_chains = [];
        }

        // 4. Multi-Persistence Sentinel (Phase 1)
        $persistence_data = [];
        try {
            $persistence_data = PersistenceScanner::audit();
        } catch (\Throwable $e) {
            $persistence_data = ['threat_count' => 0, 'threats' => []];
        }

        // 5. Virtual Patching Coverage (Phase 3)
        $virtual_patches = [];
        $active_patches_count = 0;
        try {
            $catalog = VirtualPatchManager::get_catalog();
            $active_rules = VirtualPatchManager::get_active_patches();
            $active_patches_count = count($active_rules);

            foreach ($catalog as $patch) {
                $patch_id = $patch['id'] ?? '';
                $is_active = isset($active_rules[$patch_id]) && !empty($active_rules[$patch_id]['active']);
                $virtual_patches[] = [
                    'id'               => $patch_id,
                    'name'             => $patch['name'] ?? '',
                    'target_slug'      => $patch['target_slug'] ?? '',
                    'target_type'      => $patch['target_type'] ?? 'plugin',
                    'cve_id'           => $patch['cve_id'] ?? '',
                    'severity'         => $patch['severity'] ?? 'critical',
                    'active'           => $is_active,
                    'tier1_php_active' => $is_active && ($active_rules[$patch_id]['tier1_php'] ?? true),
                    'tier2_cf_active'  => $is_active && !empty($active_rules[$patch_id]['tier2_cf_rule_id']),
                    'description'      => $patch['description'] ?? '',
                ];
            }
        } catch (\Throwable $e) {
            $virtual_patches = [];
        }

        // 6. Server & Runtime Telemetry
        $server_info = [];
        try {
            $server_info = ServerInfo::get_info();
        } catch (\Throwable $e) {
            $server_info = [];
        }

        // 7. Calculate Executive Score & Letter Grade
        $base_score = 100;
        $unresolved_critical = 0;
        $unresolved_high = 0;
        $unresolved_medium = 0;

        foreach ($issues as $issue) {
            $st = strtolower($issue['status'] ?? 'open');
            if ($st === 'open') {
                $sev = strtolower($issue['severity'] ?? 'low');
                if ($sev === 'critical') $unresolved_critical++;
                elseif ($sev === 'high') $unresolved_high++;
                elseif ($sev === 'medium') $unresolved_medium++;
            }
        }

        $deductions = ($unresolved_critical * 25) + ($unresolved_high * 12) + ($unresolved_medium * 5);
        $unresolved_chains = count($attack_chains);
        $deductions += ($unresolved_chains * 15);

        $persistence_threats = $persistence_data['threat_count'] ?? 0;
        $deductions += ($persistence_threats * 15);

        // Mitigation bonus for active virtual patches
        $mitigation_bonus = min(15, $active_patches_count * 5);

        $calculated_score = max(5, min(100, $base_score - $deductions + $mitigation_bonus));

        // Determine Letter Grade
        if ($calculated_score >= 95) {
            $grade = 'A+';
            $grade_label = 'Hardened Posture';
            $grade_color = '#10b981';
            $grade_bg = '#ecfdf5';
        } elseif ($calculated_score >= 90) {
            $grade = 'A';
            $grade_label = 'Secure Posture';
            $grade_color = '#059669';
            $grade_bg = '#f0fdf4';
        } elseif ($calculated_score >= 80) {
            $grade = 'B';
            $grade_label = 'Acceptable Posture';
            $grade_color = '#0284c7';
            $grade_bg = '#f0f9ff';
        } elseif ($calculated_score >= 70) {
            $grade = 'C';
            $grade_label = 'Moderate Risk';
            $grade_color = '#f59e0b';
            $grade_bg = '#fffbeb';
        } elseif ($calculated_score >= 60) {
            $grade = 'D';
            $grade_label = 'High Risk Exposure';
            $grade_color = '#ea580c';
            $grade_bg = '#fff7ed';
        } else {
            $grade = 'F';
            $grade_label = 'Critical Compromise';
            $grade_color = '#dc2626';
            $grade_bg = '#fef2f2';
        }

        // 8. Synthesize Dynamic Executive Narrative
        $site_name = !empty($options['client_name']) ? sanitize_text_field($options['client_name']) : get_bloginfo('name');
        $site_url = home_url();

        $narrative = self::synthesize_narrative([
            'site_name'            => $site_name,
            'grade'                => $grade,
            'grade_label'          => $grade_label,
            'score'                => $calculated_score,
            'counts'               => $counts,
            'unresolved_critical'  => $unresolved_critical,
            'unresolved_high'      => $unresolved_high,
            'chains_count'         => $unresolved_chains,
            'persistence_threats'  => $persistence_threats,
            'active_patches_count' => $active_patches_count,
            'status_ledger'        => $status_ledger,
        ]);

        $report_id = 'WCP-IR-' . gmdate('Ymd') . '-' . strtoupper(substr(md5($site_url . ($scan['id'] ?? '0')), 0, 6));

        return [
            'report_id'    => $report_id,
            'generated_at' => gmdate('c'),
            'date_human'   => gmdate('F j, Y g:i A \U\T\C'),
            'version'      => defined('WCP_SCANNER_VERSION') ? WCP_SCANNER_VERSION : '1.15.0',
            'client'       => [
                'name'     => $site_name,
                'site_url' => $site_url,
                'wp_ver'   => $server_info['wordpress']['wp_version'] ?? get_bloginfo('version'),
                'php_ver'  => $server_info['php']['version'] ?? phpversion(),
                'server'   => $server_info['server']['software'] ?? ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'),
            ],
            'auditor'      => [
                'name'         => 'Mir Alamin (WebCare Pro)',
                'title'        => 'Senior Linux SysAdmin & WordPress Security Engineer',
                'service'      => 'WebCare Pro Dedicated 1-on-1 Security & Hardening',
                'contact_url'  => 'https://webcarepro.com',
                'notes'        => !empty($options['auditor_notes']) ? sanitize_textarea_field($options['auditor_notes']) : '',
            ],
            'posture'      => [
                'letter_grade'       => $grade,
                'grade_label'        => $grade_label,
                'grade_color'        => $grade_color,
                'grade_bg'           => $grade_bg,
                'health_score'       => $calculated_score,
                'total_issues'       => count($issues),
                'counts'             => $counts,
                'status_ledger'      => $status_ledger,
                'active_chains'      => $unresolved_chains,
                'active_patches'     => $active_patches_count,
                'persistence_threats'=> $persistence_threats,
                'executive_summary'  => $narrative,
            ],
            'scan_meta'    => [
                'scan_id'        => $scan['id'] ?? null,
                'scan_target'    => $scan['scan_target'] ?? 'full',
                'duration'       => $scan['duration'] ?? 0,
                'scanned_files'  => $scan['scanned_files'] ?? 0,
                'started_at'     => $scan['started_at'] ?? null,
                'completed_at'   => $scan['completed_at'] ?? null,
            ],
            'attack_chains'      => $attack_chains,
            'persistence'        => $persistence_data,
            'virtual_patches'    => $virtual_patches,
            'issues_ledger'      => array_slice($issues, 0, 150), // Cap at 150 items for performant printable rendering
            'recommendations'    => self::generate_actionable_recommendations($issues, $attack_chains, $persistence_data, $active_patches_count, $server_info),
        ];
    }

    /**
     * Synthesize professional, executive narrative.
     */
    private static function synthesize_narrative(array $params): string {
        $name = $params['site_name'];
        $grade = $params['grade'];
        $label = $params['grade_label'];
        $score = $params['score'];
        $unresolved_crit = $params['unresolved_critical'];
        $unresolved_high = $params['unresolved_high'];
        $chains = $params['chains_count'];
        $persistence = $params['persistence_threats'];
        $patches = $params['active_patches_count'];
        $remediated = ($params['status_ledger']['remediated'] ?? 0) + ($params['status_ledger']['quarantined'] ?? 0) + ($params['status_ledger']['patched'] ?? 0);

        $summary = "This executive security posture report summarizes the independent forensic audit conducted on {$name}. ";
        $summary .= "The overall security posture is graded as **{$grade} ({$label})** with a composite score of **{$score}/100**. ";

        if ($unresolved_crit === 0 && $unresolved_high === 0 && $chains === 0 && $persistence === 0) {
            $summary .= "No unmitigated critical vulnerabilities, attack chains, or unauthorized persistence mechanisms were identified. ";
            if ($remediated > 0) {
                $summary .= "A total of {$remediated} previously isolated threats have been successfully quarantined or sanitized. ";
            }
            if ($patches > 0) {
                $summary .= "The perimeter is actively safeguarded by {$patches} Two-Tier Virtual Patches operating at both the PHP application boundary and Cloudflare edge. ";
            }
            $summary .= "The production environment currently adheres to recommended WordPress hardening standards.";
        } else {
            $summary .= "Critical items requiring priority intervention were detected: ";
            $details = [];
            if ($unresolved_crit > 0) {
                $details[] = "{$unresolved_crit} critical unmitigated vulnerability finding(s)";
            }
            if ($unresolved_high > 0) {
                $details[] = "{$unresolved_high} high-severity risk finding(s)";
            }
            if ($chains > 0) {
                $details[] = "{$chains} active behavioral attack chain(s) exhibiting lateral progression";
            }
            if ($persistence > 0) {
                $details[] = "{$persistence} stealth persistence mechanism(s) (e.g., mu-plugin/autoload vectors)";
            }
            $summary .= implode(', ', $details) . '. ';
            if ($patches > 0) {
                $summary .= "Active Virtual Patches ({$patches} deployed) are mitigating immediate exploit attempts while underlying components undergo permanent remediation.";
            } else {
                $summary .= "Immediate application of surgical virtual patches and root-cause eradication is strongly advised.";
            }
        }

        return $summary;
    }

    /**
     * Generate priority-ordered sysadmin recommendations.
     */
    private static function generate_actionable_recommendations(
        array $issues,
        array $attack_chains,
        array $persistence,
        int $active_patches_count,
        array $server_info
    ): array {
        $recs = [];

        // 1. Attack Chains
        if (!empty($attack_chains)) {
            $recs[] = [
                'priority' => 'P1 - Immediate',
                'action'   => 'Eradicate Correlated Attack Chains',
                'details'  => 'Execute 1-click surgical eradication of all stages across correlated MITRE ATT&CK vectors to prevent attacker persistence and lateral movement.',
            ];
        }

        // 2. Multi-Persistence
        if (!empty($persistence['threats'])) {
            $recs[] = [
                'priority' => 'P1 - Immediate',
                'action'   => 'Neutralize Stealth Persistence Vectors',
                'details'  => 'Remove unapproved drop-ins, mu-plugins, and database autoload keys identified as stealth execution footholds.',
            ];
        }

        // 3. Virtual Patching
        if ($active_patches_count === 0 && !empty($issues)) {
            $recs[] = [
                'priority' => 'P2 - High',
                'action'   => 'Activate Two-Tier Virtual Patching',
                'details'  => 'Deploy in-memory PHP WAF Lite shields and Cloudflare Free edge WAF rules for detected CVEs to neutralize zero-day exploits before backend execution.',
            ];
        }

        // 4. File Permissions
        $recs[] = [
            'priority' => 'P2 - High',
            'action'   => 'Hardened Linux File Permissions',
            'details'  => 'Enforce strict 0755 permissions on directories, 0644 on PHP files, and 0440 / 0400 on wp-config.php with correct www-data ownership.',
        ];

        // 5. PHP Environment
        $php_ver = $server_info['php']['version'] ?? phpversion();
        if (version_compare($php_ver, '8.1', '<')) {
            $recs[] = [
                'priority' => 'P2 - High',
                'action'   => "Upgrade PHP Runtime (Current: PHP {$php_ver})",
                'details'  => 'Upgrade server runtime to PHP 8.2 or 8.3 with OPcache enabled to receive active security updates and JIT execution speed.',
            ];
        }

        // 6. Regular Automated Scans
        $recs[] = [
            'priority' => 'P3 - Medium',
            'action'   => 'Enable Automated Daily Integrity & LotL Scans',
            'details'  => 'Schedule automatic daily background scans and real-time FIM alerts to detect Living-off-the-Land (LotL) PHP tampering instantly.',
        ];

        return $recs;
    }

    /**
     * Render the executive report as a standalone, print-optimized HTML page.
     *
     * @param array $report The compiled report data array
     * @return string Standalone HTML document
     */
    public static function render_html(array $report): string {
        $p = $report['posture'];
        $c = $report['client'];
        $a = $report['auditor'];
        $counts = $p['counts'];
        $ledger = $p['status_ledger'];

        $escape = function ($str) {
            return htmlspecialchars((string) $str, ENT_QUOTES, 'UTF-8');
        };

        // Format severity rows
        $issues_html = '';
        foreach ($report['issues_ledger'] as $idx => $issue) {
            $sev = strtolower($issue['severity'] ?? 'low');
            $sev_color = $sev === 'critical' ? '#ef4444' : ($sev === 'high' ? '#f97316' : ($sev === 'medium' ? '#f59e0b' : '#10b981'));
            $sev_bg = $sev === 'critical' ? '#fee2e2' : ($sev === 'high' ? '#ffedd5' : ($sev === 'medium' ? '#fef3c7' : '#ecfdf5'));

            $st = strtolower($issue['status'] ?? 'open');
            $st_badge = $st === 'remediated' ? '<span class="status-badge st-green">Remediated</span>' :
                        ($st === 'quarantined' ? '<span class="status-badge st-purple">Quarantined</span>' :
                        ($st === 'patched' ? '<span class="status-badge st-blue">Virtual Patched</span>' :
                        '<span class="status-badge st-amber">Open Finding</span>'));

            $path = $issue['file_path'] ?? ($issue['resource'] ?? 'System Core');
            $line = !empty($issue['line_number']) ? ' : Line ' . (int) $issue['line_number'] : '';

            $issues_html .= "
            <tr>
                <td style=\"text-align: center; color: #64748b; font-weight: 600;\">" . ($idx + 1) . "</td>
                <td>
                    <span style=\"display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase; background: {$sev_bg}; color: {$sev_color}; border: 1px solid {$sev_color}33;\">
                        {$escape($sev)}
                    </span>
                </td>
                <td>
                    <div style=\"font-weight: 700; color: #0f172a;\">{$escape($issue['title'] ?? $issue['type'] ?? 'Security Finding')}</div>
                    <div style=\"font-size: 11px; color: #64748b; margin-top: 2px;\">Engine: {$escape($issue['engine'] ?? 'System')}</div>
                </td>
                <td style=\"font-family: monospace; font-size: 11px; color: #334155; word-break: break-all;\">
                    {$escape($path)}{$line}
                </td>
                <td style=\"text-align: center;\">{$st_badge}</td>
            </tr>";
        }

        if (empty($issues_html)) {
            $issues_html = "<tr><td colspan=\"5\" style=\"text-align:center; padding: 24px; color: #10b981; font-weight: 600;\">✨ No unresolved threats or anomalous vulnerabilities detected on this system.</td></tr>";
        }

        // Recommendations HTML
        $recs_html = '';
        foreach ($report['recommendations'] as $rec) {
            $recs_html .= "
            <div class=\"rec-card\">
                <div class=\"rec-badge\">{$escape($rec['priority'])}</div>
                <div class=\"rec-body\">
                    <div class=\"rec-title\">{$escape($rec['action'])}</div>
                    <div class=\"rec-desc\">{$escape($rec['details'])}</div>
                </div>
            </div>";
        }

        // Attack Chains HTML
        $chains_html = '';
        if (!empty($report['attack_chains'])) {
            $chains_html .= '<div class="section-title">Correlated Attack Chains (MITRE ATT&CK for WordPress)</div>';
            foreach ($report['attack_chains'] as $ch) {
                $chains_html .= "
                <div class=\"chain-box\">
                    <div class=\"chain-header\">
                        <div class=\"chain-title\">⚠️ {$escape($ch['name'] ?? 'Correlated Threat Sequence')}</div>
                        <div class=\"chain-meta\">Blast Radius: <strong>" . count($ch['affected_components'] ?? []) . " components exposed</strong></div>
                    </div>
                    <div class=\"chain-narrative\">{$escape($ch['narrative'] ?? '')}</div>
                </div>";
            }
        }

        // Virtual Patches HTML
        $patches_html = '';
        if (!empty($report['virtual_patches'])) {
            $active_only = array_filter($report['virtual_patches'], function($v) { return !empty($v['active']); });
            if (!empty($active_only)) {
                $patches_html .= '<div class="section-title">Active Two-Tier Virtual Patches</div><div class="patches-grid">';
                foreach ($active_only as $vp) {
                    $tier1 = !empty($vp['tier1_php_active']) ? '<span class="tier-pill tier-php">Tier 1: In-Memory PHP Shield</span>' : '';
                    $tier2 = !empty($vp['tier2_cf_active']) ? '<span class="tier-pill tier-cf">Tier 2: Cloudflare Edge Rule</span>' : '';
                    $patches_html .= "
                    <div class=\"patch-card\">
                        <div class=\"patch-top\">
                            <strong>{$escape($vp['name'])}</strong>
                            <span class=\"cve-tag\">{$escape($vp['cve_id'])}</span>
                        </div>
                        <div class=\"patch-desc\">{$escape($vp['description'])}</div>
                        <div class=\"patch-tiers\">{$tier1} {$tier2}</div>
                    </div>";
                }
                $patches_html .= '</div>';
            }
        }

        // Auditor notes block
        $notes_html = '';
        if (!empty($a['notes'])) {
            $notes_html = "
            <div class=\"auditor-notes-box\">
                <div class=\"notes-title\">Auditor Commentary & Custom Instructions</div>
                <div class=\"notes-body\">{$escape($a['notes'])}</div>
            </div>";
        }

        return "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Executive Incident Response & Security Posture Report - {$escape($c['name'])}</title>
    <style>
        :root {
            --primary: #0f172a;
            --accent: #0284c7;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --text-dark: #0f172a;
            --text-muted: #64748b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text-dark);
            line-height: 1.5;
            padding: 32px 16px;
        }
        .report-container {
            max-width: 960px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: 12px;
            border: 1px solid var(--border);
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            padding: 40px;
        }
        .action-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #0f172a;
            color: #ffffff;
            padding: 12px 24px;
            border-radius: 8px;
            margin-bottom: 28px;
        }
        .action-bar-btn {
            background: #38bdf8;
            color: #0f172a;
            font-weight: 700;
            padding: 8px 16px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
        }
        .action-bar-btn:hover { background: #7dd3fc; }
        .action-bar-btn-secondary {
            background: #334155;
            color: #f8fafc;
            margin-left: 8px;
        }
        .action-bar-btn-secondary:hover { background: #475569; }

        /* Report Header */
        .report-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }
        .header-brand h1 { font-size: 22px; font-weight: 800; color: #0f172a; }
        .header-brand .subtitle { font-size: 13px; color: #64748b; margin-top: 2px; }
        .header-meta { text-align: right; font-size: 12px; color: #475569; line-height: 1.6; }
        .header-meta strong { color: #0f172a; }

        /* Grade & Summary Banner */
        .grade-banner {
            display: flex;
            gap: 28px;
            align-items: center;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border-radius: 10px;
            padding: 28px;
            color: #ffffff;
            margin-bottom: 28px;
        }
        .grade-badge-circle {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: {$p['grade_color']};
            color: #ffffff;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            border: 4px solid rgba(255,255,255,0.2);
        }
        .grade-badge-circle .grade-letter { font-size: 44px; font-weight: 900; line-height: 1; }
        .grade-badge-circle .grade-sub { font-size: 10px; font-weight: 700; text-transform: uppercase; margin-top: 2px; }
        .grade-content h2 { font-size: 18px; font-weight: 700; margin-bottom: 8px; color: #38bdf8; }
        .grade-content p { font-size: 13px; color: #cbd5e1; line-height: 1.6; }

        /* KPI Metric Cards */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-bottom: 28px;
        }
        .kpi-card {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }
        .kpi-card .kpi-val { font-size: 24px; font-weight: 800; color: #0f172a; }
        .kpi-card .kpi-lbl { font-size: 11px; font-weight: 600; text-transform: uppercase; color: #64748b; margin-top: 4px; }

        /* Auditor Certification Box */
        .auditor-box {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 28px;
        }
        .auditor-left { display: flex; align-items: center; gap: 14px; }
        .auditor-avatar {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            background: #0284c7;
            color: #ffffff;
            font-weight: 800;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .auditor-name { font-size: 14px; font-weight: 700; color: #0369a1; }
        .auditor-role { font-size: 12px; color: #475569; }
        .auditor-cta {
            background: #0284c7;
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            padding: 6px 12px;
            border-radius: 6px;
            text-decoration: none;
        }

        /* Section Titles */
        .section-title {
            font-size: 16px;
            font-weight: 800;
            color: #0f172a;
            margin-top: 28px;
            margin-bottom: 14px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 24px;
        }
        th {
            background: #f1f5f9;
            color: #475569;
            font-weight: 700;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid var(--border);
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        .status-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .st-green { background: #dcfce7; color: #15803d; }
        .st-purple { background: #f3e8ff; color: #7e22ce; }
        .st-blue { background: #e0f2fe; color: #0369a1; }
        .st-amber { background: #fef3c7; color: #b45309; }

        /* Recommendations */
        .rec-card {
            display: flex;
            gap: 14px;
            padding: 14px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .rec-badge {
            background: #0f172a;
            color: #38bdf8;
            font-weight: 700;
            font-size: 10px;
            padding: 4px 8px;
            border-radius: 4px;
            height: fit-content;
            white-space: nowrap;
        }
        .rec-title { font-weight: 700; color: #0f172a; font-size: 13px; }
        .rec-desc { font-size: 12px; color: #475569; margin-top: 3px; }

        /* Attack Chains */
        .chain-box {
            background: #fff1f2;
            border: 1px solid #fecdd3;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }
        .chain-title { font-weight: 700; color: #be123c; font-size: 13px; }
        .chain-meta { font-size: 11px; color: #881337; margin-top: 4px; }
        .chain-narrative { font-size: 12px; color: #4c0519; margin-top: 8px; line-height: 1.5; }

        /* Patches */
        .patches-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 24px; }
        .patch-card { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 12px; }
        .patch-top { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: #166534; }
        .cve-tag { font-family: monospace; font-size: 10px; font-weight: 700; background: #dcfce7; padding: 2px 6px; border-radius: 4px; }
        .patch-desc { font-size: 11px; color: #374151; margin-top: 6px; line-height: 1.4; }
        .patch-tiers { margin-top: 8px; display: flex; gap: 6px; }
        .tier-pill { font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; }
        .tier-php { background: #e0f2fe; color: #0284c7; }
        .tier-cf { background: #ffedd5; color: #ea580c; }

        /* Auditor commentary */
        .auditor-notes-box {
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
        }
        .notes-title { font-size: 12px; font-weight: 700; color: #92400e; text-transform: uppercase; margin-bottom: 6px; }
        .notes-body { font-size: 13px; color: #78350f; white-space: pre-wrap; line-height: 1.5; }

        /* Report Footer */
        .report-footer {
            margin-top: 36px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 11px;
            color: #94a3b8;
        }

        /* Print Media Styles */
        @media print {
            body { background: #ffffff !important; padding: 0 !important; color: #000000 !important; }
            .report-container { max-width: 100% !important; border: none !important; box-shadow: none !important; padding: 0 !important; }
            .no-print { display: none !important; }
            .grade-banner { background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .grade-badge-circle { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            table { page-break-inside: auto; }
            tr { page-break-inside: avoid; page-break-after: auto; }
            .section-title { page-break-after: avoid; }
            @page { margin: 1.5cm; }
        }
    </style>
</head>
<body>

<div class=\"report-container\">

    <!-- No-Print Action Bar -->
    <div class=\"action-bar no-print\">
        <div>
            <strong>WCP Executive Incident Report Engine</strong> &bull; v{$escape($report['version'])}
        </div>
        <div style=\"display:flex;\">
            <button class=\"action-bar-btn\" onclick=\"window.print()\">
                🖨️ Print / Save as PDF
            </button>
            <a class=\"action-bar-btn action-bar-btn-secondary\" href=\"?format=json\" target=\"_blank\">
                📥 SIEM JSON
            </a>
            <button class=\"action-bar-btn action-bar-btn-secondary\" onclick=\"window.close()\">
                ✖ Close
            </button>
        </div>
    </div>

    <!-- Header -->
    <div class=\"report-header\">
        <div class=\"header-brand\">
            <h1>{$escape($c['name'])}</h1>
            <div class=\"subtitle\">Executive Incident Response &amp; Security Posture Audit Report</div>
        </div>
        <div class=\"header-meta\">
            <div>Report ID: <strong>{$escape($report['report_id'])}</strong></div>
            <div>Date: <strong>{$escape($report['date_human'])}</strong></div>
            <div>Target URL: <strong>{$escape($c['site_url'])}</strong></div>
            <div>Platform: <strong>WordPress {$escape($c['wp_ver'])} &bull; PHP {$escape($c['php_ver'])}</strong></div>
        </div>
    </div>

    <!-- Grade & Summary Banner -->
    <div class=\"grade-banner\">
        <div class=\"grade-badge-circle\">
            <div class=\"grade-letter\">{$escape($p['letter_grade'])}</div>
            <div class=\"grade-sub\">Grade</div>
        </div>
        <div class=\"grade-content\">
            <h2>Executive Posture: {$escape($p['grade_label'])} ({$p['health_score']}/100)</h2>
            <p>" . nl2br($escape($p['executive_summary'])) . "</p>
        </div>
    </div>

    <!-- KPI Metric Cards -->
    <div class=\"kpi-grid\">
        <div class=\"kpi-card\">
            <div class=\"kpi-val\" style=\"color: #dc2626;\">{$p['counts']['critical']}</div>
            <div class=\"kpi-lbl\">Critical Threats</div>
        </div>
        <div class=\"kpi-card\">
            <div class=\"kpi-val\" style=\"color: #ea580c;\">{$p['counts']['high']}</div>
            <div class=\"kpi-lbl\">High Risk Items</div>
        </div>
        <div class=\"kpi-card\">
            <div class=\"kpi-val\" style=\"color: #0284c7;\">{$p['active_patches']}</div>
            <div class=\"kpi-lbl\">Virtual Patches</div>
        </div>
        <div class=\"kpi-card\">
            <div class=\"kpi-val\" style=\"color: #16a34a;\">" . ($ledger['remediated'] + $ledger['quarantined'] + $ledger['patched']) . "</div>
            <div class=\"kpi-lbl\">Remediated Items</div>
        </div>
    </div>

    <!-- Solo Freelancer Auditor Certification -->
    <div class=\"auditor-box\">
        <div class=\"auditor-left\">
            <div class=\"auditor-avatar\">MA</div>
            <div>
                <div class=\"auditor-name\">{$escape($a['name'])}</div>
                <div class=\"auditor-role\">{$escape($a['title'])} &bull; Direct 1-on-1 Consultation</div>
            </div>
        </div>
        <a class=\"auditor-cta no-print\" href=\"{$escape($a['contact_url'])}\" target=\"_blank\" rel=\"noopener noreferrer\">
            Connect with Mir Alamin
        </a>
    </div>

    {$notes_html}

    {$chains_html}

    {$patches_html}

    <!-- Remediated & Open Threat Ledger -->
    <div class=\"section-title\">Incident Findings &amp; Remediation Ledger</div>
    <table>
        <thead>
            <tr>
                <th style=\"width: 5%; text-align: center;\">#</th>
                <th style=\"width: 12%;\">Severity</th>
                <th style=\"width: 33%;\">Vulnerability / Threat</th>
                <th style=\"width: 35%;\">Target Resource</th>
                <th style=\"width: 15%; text-align: center;\">Status</th>
            </tr>
        </thead>
        <tbody>
            {$issues_html}
        </tbody>
    </table>

    <!-- Actionable Recommendations -->
    <div class=\"section-title\">Actionable Hardening Roadmap &amp; SysAdmin Next Steps</div>
    {$recs_html}

    <!-- Footer -->
    <div class=\"report-footer\">
        Certified by Mir Alamin (WebCare Pro) &bull; Generated by WCP Security Scanner Pro Engine v{$escape($report['version'])} &bull; {$escape($report['report_id'])}
    </div>

</div>

</body>
</html>";
    }
}
