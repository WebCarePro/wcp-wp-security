<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class CronScanner {

    /**
     * Inspect scheduled WordPress cron jobs for anomalies and malware persistence.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
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
                    // Check if it's an orphaned action
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
}
