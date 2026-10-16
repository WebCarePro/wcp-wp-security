<?php
namespace WcpScanner\Findings;

use WcpScanner\Security\PathValidator;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WhitelistManager
 *
 * First-class false-positive suppression and whitelist management.
 * Supports file path matching, SHA-256 hash-locking (auto-invalidates if modified),
 * per-engine rule suppression, configurable expiration (30 days, 90 days, permanent),
 * and administrator audit reasons.
 */
class WhitelistManager {

    const OPTION_KEY = 'wcpscan_whitelist_rules';

    /**
     * Retrieve all whitelist rules.
     *
     * @param bool $active_only
     * @return array
     */
    public static function get_whitelist_rules(bool $active_only = false): array {
        $rules = get_option(self::OPTION_KEY, []);
        if (!is_array($rules)) {
            $rules = [];
        }

        $now = time();
        $updated = false;

        foreach ($rules as &$rule) {
            if (!empty($rule['expires_at']) && $rule['expires_at'] < $now && $rule['status'] === 'active') {
                $rule['status'] = 'expired';
                $updated = true;
            }
        }
        unset($rule);

        if ($updated) {
            update_option(self::OPTION_KEY, $rules, false);
        }

        if ($active_only) {
            return array_values(array_filter($rules, function ($r) {
                return ($r['status'] ?? '') === 'active';
            }));
        }

        return array_values($rules);
    }

    /**
     * Add a new whitelist / ignore rule.
     *
     * @param array $data
     * @return array Result with rule or error
     */
    public static function add_rule(array $data): array {
        $rules = get_option(self::OPTION_KEY, []);
        if (!is_array($rules)) {
            $rules = [];
        }

        $rule_type   = sanitize_text_field($data['rule_type'] ?? 'file_hash'); // 'file_hash', 'file_path', 'issue_type'
        $target_path = sanitize_text_field($data['target_path'] ?? '');
        $issue_type  = sanitize_text_field($data['issue_type'] ?? '*');
        $engine      = sanitize_text_field($data['engine'] ?? 'all');
        $duration    = sanitize_text_field($data['duration'] ?? '30_days'); // '30_days', '90_days', 'permanent'
        $reason      = sanitize_textarea_field($data['reason'] ?? 'Legitimate code / developer whitelist');

        $target_hash = '';
        if (!empty($target_path)) {
            $abs = PathValidator::resolve_under_root(ABSPATH, $target_path);
            if ($abs && file_exists($abs) && is_file($abs)) {
                $target_hash = hash_file('sha256', $abs);
            }
        }

        if (!empty($data['file_hash'])) {
            $target_hash = sanitize_text_field($data['file_hash']);
        }

        $now = time();
        $expires_at = null;
        if ($duration === '30_days') {
            $expires_at = $now + (30 * DAY_IN_SECONDS);
        } elseif ($duration === '90_days') {
            $expires_at = $now + (90 * DAY_IN_SECONDS);
        }

        $current_user = wp_get_current_user();
        $author = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';

        $rule_id = 'wl_' . bin2hex(random_bytes(6));
        $new_rule = [
            'id'           => $rule_id,
            'rule_type'    => $rule_type,
            'target_path'  => $target_path,
            'file_hash'    => $target_hash,
            'issue_type'   => $issue_type,
            'engine'       => $engine,
            'duration'     => $duration,
            'reason'       => $reason,
            'created_by'   => $author,
            'created_at'   => current_time('mysql'),
            'expires_at'   => $expires_at,
            'status'       => 'active',
        ];

        // Deduplicate against existing active rules matching exact target & type
        $filtered = [];
        foreach ($rules as $r) {
            if ($r['target_path'] === $target_path && $r['issue_type'] === $issue_type && $r['rule_type'] === $rule_type && $r['status'] === 'active') {
                continue; // Replace duplicate
            }
            $filtered[] = $r;
        }

        array_unshift($filtered, $new_rule);
        update_option(self::OPTION_KEY, $filtered, false);

        // Update issue status in database if issue_id was provided
        if (!empty($data['issue_id'])) {
            global $wpdb;
            $table = $wpdb->prefix . 'wcpscan_scan_issues';
            $wpdb->update(
                $table,
                ['status' => 'ignored'],
                ['id' => (int) $data['issue_id']]
            );
        }

        return [
            'success' => true,
            'message' => __('Finding successfully whitelisted.', 'wcp-security-scanner'),
            'rule'    => $new_rule,
        ];
    }

    /**
     * Remove / revoke a whitelist rule.
     *
     * @param string $rule_id
     * @return bool
     */
    public static function remove_rule(string $rule_id): bool {
        $rules = get_option(self::OPTION_KEY, []);
        if (!is_array($rules)) {
            return false;
        }

        $removed = false;
        $updated = [];
        foreach ($rules as $rule) {
            if ($rule['id'] === $rule_id) {
                $removed = true;
                continue; // Exclude
            }
            $updated[] = $rule;
        }

        if ($removed) {
            update_option(self::OPTION_KEY, $updated, false);
        }

        return $removed;
    }

    /**
     * Test whether a specific finding matches an active whitelist rule.
     *
     * @param array $finding
     * @return array|null Returns matching rule if whitelisted, null otherwise.
     */
    public static function match_finding(array $finding): ?array {
        $active_rules = self::get_whitelist_rules(true);
        if (empty($active_rules)) {
            return null;
        }

        $path       = wp_normalize_path($finding['file_path'] ?? '');
        $issue_type = $finding['type'] ?? '';
        $engine     = $finding['engine'] ?? '';

        $current_hash = '';
        if (!empty($path)) {
            $abs = PathValidator::resolve_under_root(ABSPATH, $path);
            if ($abs && file_exists($abs) && is_file($abs)) {
                $current_hash = hash_file('sha256', $abs);
            }
        }

        foreach ($active_rules as $rule) {
            // Check engine matching
            if ($rule['engine'] !== 'all' && !empty($engine) && $rule['engine'] !== $engine) {
                continue;
            }

            // Check issue type matching
            if ($rule['issue_type'] !== '*' && !empty($issue_type) && $rule['issue_type'] !== $issue_type) {
                continue;
            }

            // Rule Type: SHA-256 Hash Lock (Strongest Security)
            // If the file was whitelisted by hash, but an attacker subsequently modified it, hash check fails!
            if ($rule['rule_type'] === 'file_hash') {
                if (!empty($rule['file_hash']) && !empty($current_hash) && hash_equals($rule['file_hash'], $current_hash)) {
                    return $rule;
                }
            }

            // Rule Type: Exact File Path
            if ($rule['rule_type'] === 'file_path') {
                $rule_path = wp_normalize_path($rule['target_path'] ?? '');
                if (!empty($rule_path) && !empty($path) && ($rule_path === $path || str_ends_with($path, '/' . ltrim($rule_path, '/')))) {
                    return $rule;
                }
            }

            // Rule Type: Issue Type Global
            if ($rule['rule_type'] === 'issue_type') {
                if (!empty($rule['issue_type']) && $rule['issue_type'] === $issue_type) {
                    return $rule;
                }
            }
        }

        return null;
    }

    /**
     * Filter findings list: decorates findings with whitelist status and suppresses ignored from primary counts.
     *
     * @param array $findings
     * @return array ['active' => array, 'ignored' => array]
     */
    public static function process_findings_whitelist(array $findings): array {
        $active  = [];
        $ignored = [];

        foreach ($findings as $finding) {
            $matched_rule = self::match_finding($finding);
            if ($matched_rule !== null || ($finding['status'] ?? '') === 'ignored') {
                $finding['is_whitelisted'] = true;
                $finding['whitelist_rule'] = $matched_rule;
                $finding['status']         = 'ignored';
                $ignored[] = $finding;
            } else {
                $finding['is_whitelisted'] = false;
                $active[] = $finding;
            }
        }

        return [
            'active'  => $active,
            'ignored' => $ignored,
        ];
    }
}
