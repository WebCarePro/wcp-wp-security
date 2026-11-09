<?php
namespace WebCareProScanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * FindingTranslator
 *
 * Translates complex, technical security scanner finding slugs and AST evidence
 * into a structured 3-part schema answering the top 3 questions of non-technical store owners:
 *  1. What is this?
 *  2. Is my store/checkout safe?
 *  3. What should I do?
 */
class FindingTranslator {

    /**
     * Translate a finding into plain-English non-technical explanations.
     *
     * @param array $finding
     * @return array [
     *   'what_is_this' => string,
     *   'is_store_safe' => string,
     *   'recommended_action' => string,
     *   'action_button_label' => string
     * ]
     */
    public static function translate(array $finding): array {
        $engine = strtolower($finding['engine'] ?? '');
        $type   = strtolower($finding['type'] ?? '');
        $path   = $finding['file_path'] ?? '';
        $basename = basename($path);

        // 1. Webshells & Backdoors
        if (strpos($engine, 'malware') !== false || strpos($type, 'webshell') !== false || strpos($type, 'backdoor') !== false) {
            return [
                /* translators: %s: file basename */
                'what_is_this'        => sprintf(__('A suspicious script or backdoor (%s) was detected. It contains code commonly used by attackers to gain unauthorized remote control.', 'webcare-pro-security'), $basename),
                'is_store_safe'       => __('Your payment gateways (Stripe/PayPal) process credit cards on isolated secure servers, but this file gives attackers server access and must be isolated immediately.', 'webcare-pro-security'),
                'recommended_action'  => __('Move this file to Safe Quarantine. It will be immediately neutralized, and you can undo the quarantine in 1 click if needed.', 'webcare-pro-security'),
                'action_button_label' => __('Quarantine File (1-Click Safe)', 'webcare-pro-security'),
            ];
        }

        // 2. ActionScheduler & Database Trojans
        if (strpos($engine, 'database') !== false || strpos($type, 'actionscheduler') !== false || strpos($type, 'cron') !== false) {
            return [
                'what_is_this'        => __('A background automated task in your database was found pointing to suspicious code or an orphaned execution hook.', 'webcare-pro-security'),
                'is_store_safe'       => __('Your customer database and store orders remain intact, but background tasks can be scheduled to run silently without your knowledge.', 'webcare-pro-security'),
                'recommended_action'  => __('Delete or purge this orphaned database task to keep your server fast and clean.', 'webcare-pro-security'),
                'action_button_label' => __('Purge Background Hook', 'webcare-pro-security'),
            ];
        }

        // 3. Plugin & Core Integrity
        if (strpos($engine, 'integrity') !== false) {
            if (strpos($type, 'unknown') !== false) {
                return [
                    /* translators: %s: file basename */
                    'what_is_this'        => sprintf(__('An unexpected extra file (%s) was found inside official WordPress or plugin folders that is not part of the official release.', 'webcare-pro-security'), $basename),
                    'is_store_safe'       => __('Yes—the site is currently running normally. This is often an unlisted tool, temporary cache, or leftover file from an old update.', 'webcare-pro-security'),
                    'recommended_action'  => __('Review the file location. If you or your developer did not add it, isolate it in Quarantine.', 'webcare-pro-security'),
                    'action_button_label' => __('Quarantine Unknown File', 'webcare-pro-security'),
                ];
            }

            return [
                /* translators: %s: file basename */
                'what_is_this'        => sprintf(__('File %s differs from the official release checksum verified on WordPress.org.', 'webcare-pro-security'), $basename),
                'is_store_safe'       => __('Your store is operational. The file may contain a custom developer patch or may have been modified by an unauthorized script.', 'webcare-pro-security'),
                'recommended_action'  => __('View the visual diff to inspect modifications, or reinstall the official clean copy of the plugin.', 'webcare-pro-security'),
                'action_button_label' => __('View File Changes', 'webcare-pro-security'),
            ];
        }

        // 4. User Accounts & Weak Passwords
        if (strpos($engine, 'user') !== false || strpos($type, 'password') !== false || strpos($type, 'author') !== false) {
            if (strpos($type, 'weak_password') !== false) {
                return [
                    'what_is_this'        => __('A user account on your site has a weak password that easily matches their username, email, or a common dictionary word.', 'webcare-pro-security'),
                    'is_store_safe'       => __('Automated bots attempt brute-force guessing against user accounts. An easy password is the #1 way attackers gain entry.', 'webcare-pro-security'),
                    'recommended_action'  => __('Require a password reset for this user or enforce two-factor authentication (2FA).', 'webcare-pro-security'),
                    'action_button_label' => __('Send Password Reset', 'webcare-pro-security'),
                ];
            }

            return [
                'what_is_this'        => __('A database user consistency issue or orphaned post author was discovered.', 'webcare-pro-security'),
                'is_store_safe'       => __('Yes—this is a harmless database integrity gap from previously deleted users with remaining post records.', 'webcare-pro-security'),
                'recommended_action'  => __('Reassign orphaned posts to an active administrator or allow the automated cleanup to resolve it.', 'webcare-pro-security'),
                'action_button_label' => __('Resolve Author Link', 'webcare-pro-security'),
            ];
        }

        // 5. Default Fallback
        return [
            'what_is_this'        => !empty($finding['description']) ? $finding['description'] : __('A security advisory was flagged during the system inspection.', 'webcare-pro-security'),
            'is_store_safe'       => __('Your core store and customer checkout are protected by the active WebCare Pro firewall.', 'webcare-pro-security'),
            'recommended_action'  => __('Review the finding details and apply the recommended 1-click remediation if applicable.', 'webcare-pro-security'),
            'action_button_label' => __('Inspect Details', 'webcare-pro-security'),
        ];
    }
}
