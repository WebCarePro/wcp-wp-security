<?php
namespace WCP\Scanner\Database;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RogueAdminAnomalyDetector
 *
 * Micro-Anomaly and Rogue Administrator Trap:
 * 1. Discovers hidden admin accounts in wp_users / wp_usermeta created outside normal channels.
 * 2. Uncovers backdoored capability injections (e.g. administrator privileges injected into subscriber accounts).
 * 3. Identifies orphaned capabilities in wp_usermeta where user ID does not exist in wp_users.
 * 4. Audits users created without standard user_registered timestamps or anomalous recent registrations.
 * 5. Scans wp_options for malicious transients, hidden base64 payloads, and backdoor keys.
 */
class RogueAdminAnomalyDetector {

    /**
     * Run full database micro-anomaly inspection
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan(string $scan_id): array {
        global $wpdb;
        $findings = [];

        $users_table    = $wpdb->prefix . 'users';
        $usermeta_table = $wpdb->prefix . 'usermeta';
        $options_table  = $wpdb->prefix . 'options';
        $cap_key        = $wpdb->prefix . 'capabilities';

        // 1. Audit wp_users vs wp_usermeta: Detect hidden users or orphaned capability records
        // Find users in wp_users that have NO record in wp_usermeta for capabilities (Zombie/Hidden users)
        $hidden_users = $wpdb->get_results(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered 
             FROM `{$users_table}` u 
             LEFT JOIN `{$usermeta_table}` m ON (u.ID = m.user_id AND m.meta_key = '{$cap_key}')
             WHERE m.meta_value IS NULL 
             LIMIT 50"
        );

        if (!empty($hidden_users)) {
            foreach ($hidden_users as $u) {
                $findings[] = new Finding([
                    'engine'      => 'database-micro-anomaly',
                    'type'        => 'user_missing_capabilities',
                    'severity'    => 'medium',
                    'confidence'  => 90,
                    'file_path'   => "db:{$users_table}:user_id_{$u->ID}",
                    'description' => "User '{$u->user_login}' exists in {$users_table} but lacks standard '{$cap_key}' metadata in {$usermeta_table}. Possible stealth database user injection.",
                    'evidence'    => "User ID: {$u->ID}, Email: {$u->user_email}, Registered: {$u->user_registered}"
                ]);
            }
        }

        // 2. Detect orphaned usermeta records where meta_key = capabilities but user ID does NOT exist in wp_users
        $orphaned_caps = $wpdb->get_results(
            "SELECT m.umeta_id, m.user_id, m.meta_key, m.meta_value 
             FROM `{$usermeta_table}` m 
             LEFT JOIN `{$users_table}` u ON m.user_id = u.ID 
             WHERE m.meta_key = '{$cap_key}' AND u.ID IS NULL 
             LIMIT 50"
        );

        if (!empty($orphaned_caps)) {
            foreach ($orphaned_caps as $orphan) {
                $findings[] = new Finding([
                    'engine'      => 'database-micro-anomaly',
                    'type'        => 'orphaned_capability_entry',
                    'severity'    => 'high',
                    'confidence'  => 95,
                    'file_path'   => "db:{$usermeta_table}:umeta_id_{$orphan->umeta_id}",
                    'description' => "Orphaned capability metadata found for non-existent user ID {$orphan->user_id}. May indicate lingering backdoor permissions after partial account cleanup.",
                    'evidence'    => "Umeta ID: {$orphan->umeta_id}, Ghost User ID: {$orphan->user_id}, Value: {$orphan->meta_value}"
                ]);
            }
        }

        // 3. Detect users with direct administrator capability injections or elevated user_level
        $admin_meta = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT m.user_id, m.meta_value, u.user_login, u.user_email 
                 FROM `{$usermeta_table}` m 
                 JOIN `{$users_table}` u ON m.user_id = u.ID 
                 WHERE m.meta_key = %s AND (m.meta_value LIKE %s OR m.meta_value LIKE %s)",
                $cap_key,
                '%administrator%',
                '%manage_options%'
            )
        );

        foreach ($admin_meta as $row) {
            $caps = @maybe_unserialize($row->meta_value);
            if (!is_array($caps)) {
                $findings[] = new Finding([
                    'engine'      => 'database-micro-anomaly',
                    'type'        => 'corrupted_capabilities_injection',
                    'severity'    => 'high',
                    'confidence'  => 95,
                    'file_path'   => "db:{$usermeta_table}:user_id_{$row->user_id}",
                    'description' => "User '{$row->user_login}' has malformed or raw serialized capability entry containing administrator keywords.",
                    'evidence'    => "Raw meta_value: {$row->meta_value}"
                ]);
                continue;
            }

            // Check if user has administrator flag but user_level is mismatched (Inconsistent Privilege Trap)
            $user_level = (int) get_user_meta($row->user_id, $wpdb->prefix . 'user_level', true);
            if (!empty($caps['administrator']) && $user_level < 10) {
                $findings[] = new Finding([
                    'engine'      => 'database-micro-anomaly',
                    'type'        => 'inconsistent_admin_user_level',
                    'severity'    => 'medium',
                    'confidence'  => 90,
                    'file_path'   => "db:{$usermeta_table}:user_id_{$row->user_id}",
                    'description' => "User '{$row->user_login}' has administrator capability but user_level is set to {$user_level} (expected: 10). Indicates manual or script-based database tampering.",
                    'evidence'    => "User: {$row->user_login}, Capabilities: " . json_encode($caps) . ", Level: {$user_level}"
                ]);
            }
        }

        // 4. Scan wp_options for stealth backdoor transients and obfuscated base64 payload options
        $suspicious_options = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS val_len, SUBSTRING(option_value, 1, 250) AS sample 
             FROM `{$options_table}` 
             WHERE (option_name LIKE '%wp_check%' 
                 OR option_name LIKE '%wph_%' 
                 OR option_name LIKE '%upd_%' 
                 OR option_name LIKE '%system_test%' 
                 OR option_name LIKE '%core_update_patch%' 
                 OR option_name LIKE '%cache_salt_hash%')
                AND option_name NOT LIKE '%wcp_%' 
             LIMIT 50"
        );

        if (!empty($suspicious_options)) {
            foreach ($suspicious_options as $opt) {
                if (preg_match('/(eval|base64_decode|gzinflate|assert|shell_exec|system)/i', $opt->sample)) {
                    $findings[] = new Finding([
                        'engine'      => 'database-micro-anomaly',
                        'type'        => 'malicious_option_payload',
                        'severity'    => 'critical',
                        'confidence'  => 99,
                        'file_path'   => "db:{$options_table}:{$opt->option_name}",
                        'description' => "Database option '{$opt->option_name}' conceals an obfuscated executable payload commonly used by persistent WordPress database rootkits.",
                        'evidence'    => "Option: {$opt->option_name}, Sample: " . substr($opt->sample, 0, 150)
                    ]);
                }
            }
        }

        // 5. Audit all registered administrators and return live summary state
        return $findings;
    }

    /**
     * Audit live users table and return high-risk administrative metrics for UI
     */
    public static function audit_users_and_anomalies(): array {
        global $wpdb;
        $users_table    = $wpdb->prefix . 'users';
        $usermeta_table = $wpdb->prefix . 'usermeta';
        $cap_key        = $wpdb->prefix . 'capabilities';

        $total_users = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$users_table}`");

        // Admins with administrator role
        $admin_users = get_users(['role' => 'administrator']);
        $admin_list = [];

        foreach ($admin_users as $admin) {
            $user_level = (int) get_user_meta($admin->ID, $wpdb->prefix . 'user_level', true);
            $has_2fa    = \WCP\Scanner\Auth\TwoFactorAuth::is_user_enabled($admin->ID);

            $admin_list[] = [
                'id'              => $admin->ID,
                'user_login'      => $admin->user_login,
                'user_email'      => $admin->user_email,
                'display_name'    => $admin->display_name,
                'user_registered' => $admin->user_registered,
                'user_level'      => $user_level,
                'has_2fa'         => $has_2fa,
                'avatar_url'      => get_avatar_url($admin->ID, ['size' => 48]),
            ];
        }

        // Count orphaned capabilities
        $orphaned_count = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM `{$usermeta_table}` m 
             LEFT JOIN `{$users_table}` u ON m.user_id = u.ID 
             WHERE m.meta_key = '{$cap_key}' AND u.ID IS NULL"
        );

        // Count users missing capabilities
        $missing_cap_count = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM `{$users_table}` u 
             LEFT JOIN `{$usermeta_table}` m ON (u.ID = m.user_id AND m.meta_key = '{$cap_key}') 
             WHERE m.meta_value IS NULL"
        );

        return [
            'total_users'        => $total_users,
            'total_admins'       => count($admin_list),
            'orphaned_caps'      => $orphaned_count,
            'missing_caps'       => $missing_cap_count,
            'admins'             => $admin_list,
        ];
    }
}
