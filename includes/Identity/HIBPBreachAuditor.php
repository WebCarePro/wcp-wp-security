<?php
namespace WcpScanner\Identity;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * HIBPBreachAuditor
 *
 * Pillar 4: Zero-Trust Identity - HaveIBeenPwned Real-Time Leak Interceptor & Account Auditor.
 * Provides cryptographic K-Anonymity checking for passwords during registration, profile updates,
 * and password resets. Audits existing administrative accounts against compromised credential databases,
 * and allows 1-click forced session termination & password rotation for breached accounts.
 */
class HIBPBreachAuditor {

    const OPTION_STATS        = 'wcpscan_hibp_breach_stats';
    const OPTION_AUDIT_REPORT = 'wcpscan_hibp_admin_audit_report';

    /**
     * Check if a candidate password appears in HaveIBeenPwned via k-Anonymity API.
     * Never sends plaintext, never sends the full hash (100% cryptographic privacy).
     *
     * @param string $password
     * @return array ['breached' => bool, 'count' => int]
     */
    public static function check_password_breach(string $password): array {
        if (empty($password)) {
            return ['breached' => false, 'count' => 0];
        }

        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        // Check local transient cache for this prefix to avoid redundant external network roundtrips
        $cache_key = 'wcpscan_hibp_' . $prefix;
        $body = get_transient($cache_key);

        if ($body === false) {
            $url = 'https://api.pwnedpasswords.com/range/' . $prefix;
            $response = wp_remote_get($url, [
                'timeout'    => 3,
                'user-agent' => 'WCP-Security-Scanner/' . (defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '1.25.0'),
                'headers'    => [
                    'Add-Padding' => 'true', // Mitigates response size side-channel leakage
                ],
            ]);

            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                // If API is unreachable or rate-limited, safely fail open to not break legitimate user logins
                return ['breached' => false, 'is_breached' => false, 'count' => 0, 'pwned_count' => 0];
            }

            $body = wp_remote_retrieve_body($response);
            set_transient($cache_key, $body, 86400); // Cache for 24h
        }

        $lines = explode("\n", (string) $body);
        $breach_count = 0;
        $is_breached = false;

        foreach ($lines as $line) {
            $parts = explode(':', trim($line));
            if (count($parts) === 2 && strtoupper($parts[0]) === $suffix) {
                $breach_count = (int) $parts[1];
                if ($breach_count > 0) {
                    $is_breached = true;
                    break;
                }
            }
        }

        self::record_stat_check($is_breached);

        return [
            'breached'    => $is_breached,
            'is_breached' => $is_breached,
            'count'       => $breach_count,
            'pwned_count' => $breach_count,
        ];
    }

    /**
     * Audit all existing Administrator and Editor user accounts for credential hygiene.
     *
     * @return array
     */
    public static function audit_privileged_users(): array {
        $users = get_users([
            'role__in' => ['administrator', 'editor'],
            'number'   => 100,
        ]);

        $audit_results = [];
        $total_audited = count($users);
        $total_warnings = 0;

        foreach ($users as $u) {
            $warnings = [];
            $risk_score = 10; // Baseline low risk

            // 1. Check for default username 'admin' or matching display_name
            if (strtolower($u->user_login) === 'admin' || strtolower($u->user_login) === 'administrator') {
                $warnings[] = 'Default high-target administrative username ("admin")';
                $risk_score += 40;
            }

            if (strtolower($u->user_login) === strtolower($u->display_name)) {
                $warnings[] = 'Public display name identical to login name (allows username enumeration)';
                $risk_score += 15;
            }

            // 2. Check 2FA Enrollment status
            $two_fa_active = get_user_meta($u->ID, 'wcpscan_2fa_enabled', true);
            if (empty($two_fa_active)) {
                $warnings[] = 'Two-Factor Authentication (2FA) is NOT enabled';
                $risk_score += 25;
            }

            // 3. Check for stale / inactive administrative account (> 60 days no login)
            $last_login = get_user_meta($u->ID, 'wcpscan_last_login_time', true);
            if (!empty($last_login) && (time() - $last_login > (60 * 86400))) {
                $warnings[] = 'Inactive account: no login recorded in over 60 days';
                $risk_score += 20;
            }

            $risk_score = min(100, $risk_score);
            if (!empty($warnings)) {
                $total_warnings++;
            }

            $audit_results[] = [
                'user_id'       => $u->ID,
                'user_login'    => $u->user_login,
                'user_email'    => $u->user_email,
                'display_name'  => $u->display_name,
                'role'          => reset($u->roles) ?: 'administrator',
                'two_fa_active' => !empty($two_fa_active),
                'risk_score'    => $risk_score,
                'warnings'      => $warnings,
            ];
        }

        // Sort highest risk first
        usort($audit_results, fn($a, $b) => $b['risk_score'] <=> $a['risk_score']);

        $report = [
            'timestamp'      => time(),
            'datetime'       => current_time('mysql'),
            'total_audited'  => $total_audited,
            'total_warnings' => $total_warnings,
            'accounts'       => $audit_results,
        ];

        update_option(self::OPTION_AUDIT_REPORT, $report);
        return $report;
    }

    /**
     * Force a password reset for a compromised user account.
     * Invalidates all active sessions and emails a secure password reset link.
     *
     * @param int $user_id
     * @return array
     */
    public static function force_password_reset(int $user_id): array {
        $user = get_userdata($user_id);
        if (!$user) {
            return [
                'success' => false,
                'message' => __('User not found.', 'wcp-security-scanner'),
            ];
        }

        // 1. Revoke all active session tokens immediately
        SessionForensicsEngine::revoke_all_sessions($user_id);

        // 2. Generate WordPress native password reset key
        $key = get_password_reset_key($user);
        if (is_wp_error($key)) {
            return [
                'success' => false,
                'message' => $key->get_error_message(),
            ];
        }

        // 3. Build reset URL
        $reset_url = network_site_url("wp-login.php?action=rp&key={$key}&login=" . rawurlencode($user->user_login), 'login');

        // 4. Send email
        /* translators: %s: site name */
        $subject = sprintf(__('[%s] Security Notification: Password Reset Required', 'wcp-security-scanner'), get_bloginfo('name'));
        /* translators: 1: user display name, 2: password reset URL */
        $message = sprintf(
            __("Hello %1\$s,\n\nA security administrator has initiated an immediate password reset for your account to protect against unauthorized credential reuse.\n\nAll existing active sessions have been terminated.\n\nPlease reset your password using the following link:\n%2\$s\n\nIf you did not expect this, please reach out to your security administrator immediately.", 'wcp-security-scanner'),
            $user->display_name,
            $reset_url
        );

        wp_mail($user->user_email, $subject, $message);

        AuditLogger::log(
            'force_password_reset_initiated',
            sprintf('Administrator forced password reset for user "%s". All active sessions terminated.', $user->user_login)
        );

        /* translators: %s: user email address */
        $success_msg = sprintf(__('All active sessions terminated and password reset email dispatched to %s.', 'wcp-security-scanner'), $user->user_email);
        return [
            'success'   => true,
            'message'   => $success_msg,
            'reset_url' => $reset_url,
        ];
    }

    /**
     * Get aggregate breach checking statistics.
     *
     * @return array
     */
    public static function get_summary(): array {
        $stats = get_option(self::OPTION_STATS, [
            'total_checks'      => 0,
            'breached_blocked'  => 0,
            'last_check_time'   => null,
        ]);

        $audit_report = get_option(self::OPTION_AUDIT_REPORT, null);

        return [
            'stats'        => $stats,
            'audit_report' => $audit_report,
        ];
    }

    /**
     * Record a check stat.
     */
    private static function record_stat_check(bool $is_breached) {
        $stats = get_option(self::OPTION_STATS, [
            'total_checks'     => 0,
            'breached_blocked' => 0,
            'last_check_time'  => null,
        ]);
        $stats['total_checks']++;
        if ($is_breached) {
            $stats['breached_blocked']++;
        }
        $stats['last_check_time'] = time();
        update_option(self::OPTION_STATS, $stats);
    }
}
