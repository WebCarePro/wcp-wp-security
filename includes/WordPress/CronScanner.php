<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class CronScanner {

    /**
     * Inspect scheduled WordPress cron jobs and Linux system crontab for anomalies and malware persistence.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];
        $findings = array_merge($findings, $this->scan_wp_cron($scan_id));
        $findings = array_merge($findings, $this->scan_system_crontab($scan_id));
        return $findings;
    }

    /**
     * Inspect WordPress virtual cron array for dangerous hooks and orphaned actions.
     */
    private function scan_wp_cron($scan_id) {
        $findings = [];
        $cron_jobs = _get_cron_array();

        if (empty($cron_jobs) || !is_array($cron_jobs)) {
            return $findings;
        }

        foreach ($cron_jobs as $timestamp => $hooks) {
            if (!is_array($hooks)) continue;

            foreach ($hooks as $hook_name => $hook_events) {
                // 1. Check hook name for dangerous keywords
                if (preg_match('/(eval|base64|system|shell|assert|passthru|exec|curl_exec|backdoor)/i', $hook_name)) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-cron',
                        'type'        => 'malicious_cron_hook_name',
                        'severity'    => 'critical',
                        'confidence'  => 98,
                        'file_path'   => "cron:hook:{$hook_name}",
                        'description' => "Scheduled cron hook contains dangerous code execution keywords: '{$hook_name}'.",
                        'evidence'    => "Hook: {$hook_name}, Timestamp: {$timestamp}"
                    ]);
                }

                // 2. Check for missing callbacks on custom hooks
                if (has_filter($hook_name) === false && !in_array($hook_name, ['wp_version_check', 'wp_update_plugins', 'wp_update_themes', 'recovery_mode_clean_expired_keys'])) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-cron',
                        'type'        => 'orphaned_cron_hook',
                        'severity'    => 'low',
                        'confidence'  => 80,
                        'file_path'   => "cron:hook:{$hook_name}",
                        'description' => "Scheduled cron hook '{$hook_name}' has no registered callback handler. May be left behind by uninstalled plugins.",
                        'evidence'    => "Hook: {$hook_name}"
                    ]);
                }
            }
        }

        return $findings;
    }

    /**
     * Audit Linux server crontab and scheduled tasks for malware persistence.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan_system_crontab($scan_id) {
        $findings = [];

        // Skip Windows environments where Unix crontab does not exist
        if (stripos(PHP_OS, 'WIN') === 0) {
            return $findings;
        }

        $raw_entries = [];

        // 1. Check user crontab via CLI (crontab -l) if command execution is permitted
        if (function_exists('shell_exec')) {
            $disabled = explode(',', (string) ini_get('disable_functions'));
            $disabled = array_map('trim', $disabled);

            if (!in_array('shell_exec', $disabled, true)) {
                $output = @shell_exec('crontab -l 2>/dev/null');
                if (!empty($output) && is_string($output)) {
                    foreach (explode("\n", $output) as $line) {
                        $line = trim($line);
                        if (!empty($line) && strpos($line, '#') !== 0) {
                            $raw_entries[] = [
                                'source' => 'crontab -l',
                                'line'   => $line
                            ];
                        }
                    }
                }
            }
        }

        // 2. Check direct crontab files if readable
        $paths_to_check = [
            '/etc/crontab',
            '/var/spool/cron/crontabs/' . get_current_user(),
            '/var/spool/cron/' . get_current_user(),
        ];

        // Also check /etc/cron.d/ files if directory exists
        if (is_dir('/etc/cron.d')) {
            $cron_d_files = @glob('/etc/cron.d/*');
            if (is_array($cron_d_files)) {
                $paths_to_check = array_merge($paths_to_check, $cron_d_files);
            }
        }

        foreach ($paths_to_check as $c_path) {
            if (is_file($c_path) && is_readable($c_path)) {
                $content = @file_get_contents($c_path);
                if (!empty($content)) {
                    foreach (explode("\n", $content) as $line) {
                        $line = trim($line);
                        if (!empty($line) && strpos($line, '#') !== 0) {
                            $raw_entries[] = [
                                'source' => $c_path,
                                'line'   => $line
                            ];
                        }
                    }
                }
            }
        }

        // 3. Heuristic inspection of crontab entries
        $seen = [];
        foreach ($raw_entries as $entry) {
            $line = $entry['line'];
            $source = $entry['source'];

            if (isset($seen[$line])) continue;
            $seen[$line] = true;

            // Ignore standard legitimate WordPress cron executions (e.g. php .../wp-cron.php)
            if (preg_match('/wp-cron\.php/i', $line) && !preg_match('/(curl|wget).*\|\s*(bash|sh)/i', $line)) {
                continue;
            }

            // High Severity Pattern A: Remote download piped directly to shell
            if (preg_match('/(curl|wget|fetch)\s+[^|]+\|\s*(bash|sh|python|perl|zsh)/i', $line)) {
                $findings[] = new Finding([
                    'engine'      => 'system-crontab',
                    'type'        => 'malicious_system_crontab',
                    'severity'    => 'critical',
                    'confidence'  => 100,
                    'file_path'   => $source,
                    'description' => "Server crontab contains remote payload download piped into shell execution: persistent backdoor vector.",
                    'evidence'    => $line
                ]);
                continue;
            }

            // High Severity Pattern B: Reverse shell or network pipe execution
            if (preg_match('/(\/dev\/tcp\/|nc\s+-[a-zA-Z0-9]*e|ncat\s+-[a-zA-Z0-9]*e|socat\s+|base64\s+-d\s*\|)/i', $line)) {
                $findings[] = new Finding([
                    'engine'      => 'system-crontab',
                    'type'        => 'malicious_system_crontab',
                    'severity'    => 'critical',
                    'confidence'  => 99,
                    'file_path'   => $source,
                    'description' => "Server crontab contains reverse shell, raw TCP redirect, or base64 decoding pipe.",
                    'evidence'    => $line
                ]);
                continue;
            }

            // High Severity Pattern C: Execution of scripts in uploads, cache, or temp folders
            if (preg_match('/(wp-content\/uploads|wp-content\/cache|\/tmp\/|\/dev\/shm\/|\/var\/tmp\/).*\.(php|sh|pl|py|bin|elf)/i', $line)) {
                $findings[] = new Finding([
                    'engine'      => 'system-crontab',
                    'type'        => 'suspicious_crontab_execution',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => $source,
                    'description' => "Server crontab executes scripts stored in non-executable uploads, cache, or temp directories.",
                    'evidence'    => $line
                ]);
                continue;
            }

            // Medium Severity Pattern D: Execution in hidden dot directories
            if (preg_match('/(\/\.[a-zA-Z0-9_-]+\/)/i', $line)) {
                $findings[] = new Finding([
                    'engine'      => 'system-crontab',
                    'type'        => 'hidden_directory_crontab',
                    'severity'    => 'high',
                    'confidence'  => 90,
                    'file_path'   => $source,
                    'description' => "Server crontab executes files located within hidden Unix dot directories.",
                    'evidence'    => $line
                ]);
                continue;
            }
        }

        return $findings;
    }
}

