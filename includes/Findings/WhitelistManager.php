<?php
namespace WcpScanner\Findings;

use WcpScanner\Filesystem\PathValidator;

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
     * Resolve the absolute path to a file if it exists.
     * Handles absolute paths, paths relative to ABSPATH, and paths in parent directory of ABSPATH.
     *
     * @param string $path
     * @return string|null
     */
    public static function resolve_file_path(string $path): ?string {
        if (empty($path)) {
            return null;
        }

        // Direct path check
        if (file_exists($path) && is_file($path)) {
            return $path;
        }

        // Relative to ABSPATH
        $under_abs = ABSPATH . ltrim($path, '/\\');
        if (file_exists($under_abs) && is_file($under_abs)) {
            return $under_abs;
        }

        // One level above ABSPATH (common for wp-config.php)
        $parent_abs = dirname(ABSPATH) . '/' . ltrim($path, '/\\');
        if (file_exists($parent_abs) && is_file($parent_abs)) {
            return $parent_abs;
        }

        return null;
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
            $abs = self::resolve_file_path($target_path);
            if ($abs && file_exists($abs) && is_file($abs)) {
                $target_hash = hash_file('sha256', $abs);
            }
        }

        if (!empty($data['file_hash'])) {
            $target_hash = sanitize_text_field($data['file_hash']);
        }

        // If rule_type was requested as 'file_hash' but no physical file hash could be calculated (e.g. virtual user, comment, cron, db, or virtual target), automatically fall back to 'file_path'
        if ($rule_type === 'file_hash' && empty($target_hash)) {
            $rule_type = !empty($target_path) ? 'file_path' : 'issue_type';
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
     * Revoke any active whitelist / ignore rules for a target file path or finding.
     *
     * @param string $file_path
     * @param string $issue_type
     * @return int Number of rules revoked
     */
    public static function revoke_rules_for_target(string $file_path, string $issue_type = ''): int {
        $rules = get_option(self::OPTION_KEY, []);
        if (!is_array($rules) || empty($rules)) {
            return 0;
        }

        $norm_target = strtolower(trim(wp_normalize_path($file_path)));
        $revoked_count = 0;
        $updated = [];

        foreach ($rules as $rule) {
            $rule_norm = strtolower(trim(wp_normalize_path($rule['target_path'] ?? '')));
            
            // Check path match (exact, relative, or directory-boundary suffix match)
            $is_path_match = false;
            if (!empty($norm_target) && !empty($rule_norm)) {
                $is_path_match = (
                    $norm_target === $rule_norm ||
                    str_ends_with($norm_target, '/' . ltrim($rule_norm, '/')) ||
                    str_ends_with($rule_norm, '/' . ltrim($norm_target, '/'))
                );
            }

            $is_type_match = empty($issue_type) || empty($rule['issue_type']) || $rule['issue_type'] === '*' || $rule['issue_type'] === $issue_type;

            if ($is_path_match && $is_type_match) {
                $revoked_count++;
                continue; // Revoke and remove rule
            }
            $updated[] = $rule;
        }

        if ($revoked_count > 0) {
            update_option(self::OPTION_KEY, $updated, false);
        }

        return $revoked_count;
    }

    /**
     * Test whether a specific finding matches an active whitelist rule.
     *
     * @param array $finding
     * @param array|null $hash_cache Optional memoization cache array [path => sha256] passed by reference
     * @return array|null Returns matching rule if whitelisted, null otherwise.
     */
    public static function match_finding(array $finding, ?array &$hash_cache = null): ?array {
        $active_rules = self::get_whitelist_rules(true);
        if (empty($active_rules)) {
            return null;
        }

        $path       = wp_normalize_path($finding['file_path'] ?? '');
        $issue_type = $finding['type'] ?? '';
        $engine     = $finding['engine'] ?? '';

        $current_hash = '';
        if (!empty($path)) {
            if ($hash_cache !== null && isset($hash_cache[$path])) {
                $current_hash = $hash_cache[$path];
            } else {
                $abs = self::resolve_file_path($path);
                if ($abs && file_exists($abs) && is_file($abs)) {
                    $current_hash = hash_file('sha256', $abs);
                }
                if ($hash_cache !== null) {
                    $hash_cache[$path] = $current_hash;
                }
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

            // 1. Rule Type: SHA-256 Hash Lock (Strongest Security for physical files with hash)
            if ($rule['rule_type'] === 'file_hash' && !empty($rule['file_hash'])) {
                if (!empty($current_hash) && hash_equals($rule['file_hash'], $current_hash)) {
                    return $rule;
                }
                // If a physical file was modified after whitelisting, the hash lock breaks
                continue;
            }

            // 2. Rule Type: File Path, Virtual Target, or legacy file_hash without hash
            if ($rule['rule_type'] === 'file_path' || empty($rule['rule_type']) || ($rule['rule_type'] === 'file_hash' && empty($rule['file_hash']))) {
                $rule_path = wp_normalize_path($rule['target_path'] ?? '');
                if (!empty($rule_path) && !empty($path)) {
                    $norm_p1 = strtolower(trim($path));
                    $norm_p2 = strtolower(trim($rule_path));

                    // Exact match
                    if ($norm_p1 === $norm_p2) {
                        return $rule;
                    }

                    // Controlled directory boundary matching (e.g. /var/www/html/wp-content/... vs wp-content/...)
                    // Must start after a path separator ('/') to prevent over-matching (e.g. not_evil.php matching evil.php)
                    if (str_ends_with($norm_p1, '/' . ltrim($norm_p2, '/')) || str_ends_with($norm_p2, '/' . ltrim($norm_p1, '/'))) {
                        return $rule;
                    }

                    // Virtual user targets (e.g. "user:1 (localwp)" vs "user:1")
                    if (strpos($norm_p1, 'user:') === 0 && strpos($norm_p2, 'user:') === 0) {
                        if (preg_match('/user:(\d+)/', $norm_p1, $m1) && preg_match('/user:(\d+)/', $norm_p2, $m2)) {
                            if ($m1[1] === $m2[1]) {
                                return $rule;
                            }
                        }
                    }

                    // Virtual comment targets (e.g. "comment:123" vs "comment:123 (author)")
                    if (strpos($norm_p1, 'comment:') === 0 && strpos($norm_p2, 'comment:') === 0) {
                        if (preg_match('/comment:(\d+)/', $norm_p1, $m1) && preg_match('/comment:(\d+)/', $norm_p2, $m2)) {
                            if ($m1[1] === $m2[1]) {
                                return $rule;
                            }
                        }
                    }

                    // Virtual cron hook targets (e.g. "cron:wcp_scheduled_scan")
                    if (strpos($norm_p1, 'cron:') === 0 && strpos($norm_p2, 'cron:') === 0) {
                        if (explode(' ', $norm_p1)[0] === explode(' ', $norm_p2)[0]) {
                            return $rule;
                        }
                    }

                    // Virtual database options / tables
                    if (strpos($norm_p1, 'wp_options:') === 0 && strpos($norm_p2, 'wp_options:') === 0) {
                        if (explode(' ', $norm_p1)[0] === explode(' ', $norm_p2)[0]) {
                            return $rule;
                        }
                    }
                }
            }

            // 3. Rule Type: Issue Type Global
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
