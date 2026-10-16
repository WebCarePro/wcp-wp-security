<?php
namespace WcpScanner\Auth;

use WcpScanner\Security\SecretVault;
use WcpScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LoginHistoryManager
 *
 * Tracks, logs, and forensics-audits administrator authentication sessions.
 * ENCRYPTION GUARANTEE: All sensitive telemetry (IP, User-Agent, Screen Resolution,
 * Viewport, Timezone, Device Type) is encrypted at rest using AES-256-GCM AEAD
 * via SecretVault before writing to the database. Zero plaintext in MySQL.
 */
class LoginHistoryManager {

    const TABLE_NAME = 'wcpscan_login_history';

    private static $last_auth_token = '';

    /**
     * Bootstrap Login History tracking hooks
     */
    public static function init() {
        // Capture generated session token during auth cookie issuance
        add_action('set_auth_cookie', [__CLASS__, 'on_set_auth_cookie'], 10, 6);

        // Inject lightweight screen detection into standard WordPress login form
        add_action('login_form', [__CLASS__, 'render_login_screen_detector']);

        // Record session upon login
        add_action('wp_login', [__CLASS__, 'on_user_login'], 25, 2);

        // Record logout timestamp
        add_action('wp_logout', [__CLASS__, 'on_user_logout']);
    }

    /**
     * Cache the freshly minted session token from WordPress core's set_auth_cookie hook
     */
    public static function on_set_auth_cookie($auth_cookie, $expire, $expiration, $user_id, $scheme, $token) {
        self::$last_auth_token = (string) $token;
    }

    /**
     * Inject screen size detector into login form
     */
    public static function render_login_screen_detector() {
        echo '<input type="hidden" name="wcpscan_screen_res" id="wcpscan_screen_res" value="">' . "\n";
        echo '<input type="hidden" name="wcpscan_client_tz" id="wcpscan_client_tz" value="">' . "\n";
        echo '<script>(function(){try{var s=document.getElementById("wcpscan_screen_res");if(s&&window.screen){s.value=window.screen.width+"x"+window.screen.height+"@"+(window.devicePixelRatio||1);}var t=document.getElementById("wcpscan_client_tz");if(t&&window.Intl){t.value=Intl.DateTimeFormat().resolvedOptions().timeZone||"";}}catch(e){}})();</script>' . "\n";
    }

    /**
     * Record login event into encrypted table
     */
    public static function on_user_login(string $user_login, \WP_User $user) {
        if (!$user->has_cap('edit_posts')) {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_NAME;

        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if (!$table_exists) {
            \WcpScanner\Database\Migration::install();
        }

        $session_token = !empty(self::$last_auth_token) ? self::$last_auth_token : wp_get_session_token();
        if (empty($session_token)) {
            $manager = \WP_Session_Tokens::get_instance($user->ID);
            $all = $manager->get_all();
            if (!empty($all)) {
                $keys = array_keys($all);
                $session_token = end($keys);
            }
        }

        $token_hash    = $session_token ? substr(hash('sha256', $session_token), 0, 64) : '';
        $ip            = FirewallEngine::get_client_ip();
        $ua            = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';
        $screen_raw    = isset($_POST['wcpscan_screen_res']) ? sanitize_text_field(wp_unslash($_POST['wcpscan_screen_res'])) : '';
        $tz_raw        = isset($_POST['wcpscan_client_tz']) ? sanitize_text_field(wp_unslash($_POST['wcpscan_client_tz'])) : '';

        $parsed = self::parse_device_details($ua, $screen_raw);

        $auth_method = 'Username & Password';
        if (!empty($_POST['wcpscan_2fa_code'])) {
            $auth_method = 'Password + 2FA TOTP Verified';
        } elseif (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            $auth_method = 'XML-RPC Protocol';
        } elseif (defined('REST_REQUEST') && REST_REQUEST) {
            $auth_method = 'REST API Application Password';
        }

        $telemetry = [
            'ip'                => $ip,
            'user_agent'        => $ua,
            'browser'           => $parsed['browser'],
            'browser_version'   => $parsed['browser_version'],
            'platform'          => $parsed['platform'],
            'device_type'       => $parsed['device_type'],
            'screen_resolution' => $parsed['screen_resolution'],
            'viewport'          => $parsed['viewport'],
            'timezone'          => $tz_raw ?: 'UTC',
            'auth_method'       => $auth_method,
        ];

        // Encrypt everything with AES-256-GCM before writing to database
        $encrypted_data = SecretVault::encrypt((string) wp_json_encode($telemetry));

        $now = current_time('mysql');

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            [
                'user_id'        => $user->ID,
                'session_token'  => $token_hash,
                'login_time'     => $now,
                'last_seen'      => $now,
                'encrypted_data' => $encrypted_data,
                'created_at'     => $now,
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s']
        );

        // Keep last 25 logins per user to maintain high performance
        self::prune_old_logins($user->ID);
    }

    /**
     * Update active session heartbeat and telemetry (Screen size, Viewport)
     */
    public static function update_session_telemetry(int $user_id, array $client_telemetry) {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_NAME;

        $session_token = wp_get_session_token();
        $token_hash    = $session_token ? substr(hash('sha256', $session_token), 0, 64) : '';

        if (empty($token_hash)) {
            // Find newest open session for this user
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM `{$table}` WHERE user_id = %d AND logout_time IS NULL ORDER BY id DESC LIMIT 1",
                $user_id
            ));
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM `{$table}` WHERE user_id = %d AND session_token = %s ORDER BY id DESC LIMIT 1",
                $user_id,
                $token_hash
            ));
        }

        if (!$row) {
            return false;
        }

        $decrypted_raw = SecretVault::decrypt($row->encrypted_data);
        $payload = is_string($decrypted_raw) ? (json_decode($decrypted_raw, true) ?: []) : [];

        if (!empty($client_telemetry['screen_resolution'])) {
            $payload['screen_resolution'] = sanitize_text_field($client_telemetry['screen_resolution']);
        }
        if (!empty($client_telemetry['viewport'])) {
            $payload['viewport'] = sanitize_text_field($client_telemetry['viewport']);
        }
        if (!empty($client_telemetry['timezone'])) {
            $payload['timezone'] = sanitize_text_field($client_telemetry['timezone']);
        }

        $re_encrypted = SecretVault::encrypt((string) wp_json_encode($payload));
        $now = current_time('mysql');

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        return $wpdb->update(
            $table,
            [
                'last_seen'      => $now,
                'encrypted_data' => $re_encrypted,
            ],
            ['id' => $row->id],
            ['%s', '%s'],
            ['%d']
        );
    }

    /**
     * Mark session logged out
     */
    public static function on_user_logout() {
        $user_id = get_current_user_id();
        if ($user_id <= 0) {
            return;
        }

        $session_token = wp_get_session_token();
        $token_hash    = $session_token ? substr(hash('sha256', $session_token), 0, 64) : '';

        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_NAME;
        $now   = current_time('mysql');

        if ($token_hash) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $wpdb->query($wpdb->prepare(
                "UPDATE `{$table}` SET logout_time = %s WHERE user_id = %d AND session_token = %s AND logout_time IS NULL",
                $now,
                $user_id,
                $token_hash
            ));
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $wpdb->query($wpdb->prepare(
                "UPDATE `{$table}` SET logout_time = %s WHERE user_id = %d AND logout_time IS NULL ORDER BY id DESC LIMIT 1",
                $now,
                $user_id
            ));
        }
    }

    /**
     * Mark session terminated via Session Sentinel
     */
    public static function record_session_terminated(int $user_id, string $session_token) {
        if ($user_id <= 0 || empty($session_token)) {
            return;
        }

        try {
            global $wpdb;
            if (!$wpdb) {
                return;
            }
            $table = $wpdb->prefix . self::TABLE_NAME;
            $now   = current_time('mysql');

            $raw_hash = substr(hash('sha256', $session_token), 0, 64);

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $wpdb->query($wpdb->prepare(
                "UPDATE `{$table}` SET logout_time = %s WHERE user_id = %d AND (session_token = %s OR session_token = %s) AND logout_time IS NULL",
                $now,
                $user_id,
                $session_token,
                $raw_hash
            ));
        } catch (\Throwable $e) {
            // Silently suppress if table does not exist yet or DB query fails
        }
    }

    /**
     * Get decrypted login history for a specific user (Last 10 records by default)
     */
    public static function get_user_history(int $user_id, int $limit = 10): array {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_NAME;

        $user = get_userdata($user_id);
        if (!$user) {
            return [
                'success' => false,
                'message' => 'User not found'
            ];
        }

        // Ensure table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if (!$table_exists) {
            \WcpScanner\Database\Migration::install();
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table}` WHERE user_id = %d ORDER BY id DESC LIMIT %d",
            $user_id,
            max(1, min(50, $limit))
        ));

        // Get currently active sessions from WP core session tokens
        $manager = \WP_Session_Tokens::get_instance($user_id);
        $wp_sessions = $manager->get_all();
        $current_token = wp_get_session_token();

        $history = [];
        $total_active_seconds = 0;
        $latest_login_time = null;

        foreach ($rows as $idx => $row) {
            $decrypted_raw = SecretVault::decrypt($row->encrypted_data);
            $data = is_string($decrypted_raw) ? (json_decode($decrypted_raw, true) ?: []) : [];

            $login_ts = strtotime($row->login_time);
            $logout_ts = !empty($row->logout_time) ? strtotime($row->logout_time) : null;
            $last_seen_ts = !empty($row->last_seen) ? strtotime($row->last_seen) : $login_ts;

            // Check if this record corresponds to an active WP session
            $is_active = false;
            if (empty($logout_ts)) {
                // If it's the latest session and last_seen is within reasonable activity window
                if ($idx === 0 && !empty($wp_sessions)) {
                    $is_active = true;
                }
            }

            // Duration calculation
            if ($is_active) {
                $duration_sec = max(1, time() - $login_ts);
                $duration_formatted = self::format_duration($duration_sec);
                if ($idx === 0) {
                    $total_active_seconds = $duration_sec;
                }
            } elseif ($logout_ts) {
                $duration_sec = max(1, $logout_ts - $login_ts);
                $duration_formatted = self::format_duration($duration_sec);
            } else {
                $duration_sec = max(1, $last_seen_ts - $login_ts);
                $duration_formatted = self::format_duration($duration_sec);
            }

            if ($idx === 0) {
                $latest_login_time = $row->login_time;
            }

            $row_ip = $data['ip'] ?? 'Unknown IP';
            if ($is_active && \WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($row_ip)) {
                $row_ip = FirewallEngine::get_client_ip();
            }

            $history[] = [
                'id'                 => (int) $row->id,
                'login_time'         => $row->login_time,
                'login_time_human'   => human_time_diff($login_ts, time()) . ' ago',
                'logout_time'        => $row->logout_time,
                'last_seen'          => $row->last_seen,
                'duration_seconds'   => $duration_sec,
                'duration_formatted' => $duration_formatted,
                'is_active'          => $is_active,
                'ip'                 => $row_ip,
                'browser'            => $data['browser'] ?? 'Browser',
                'browser_version'    => $data['browser_version'] ?? '',
                'platform'           => $data['platform'] ?? 'OS',
                'device_type'        => $data['device_type'] ?? 'Desktop',
                'screen_resolution'  => $data['screen_resolution'] ?? 'Standard Desktop',
                'viewport'           => $data['viewport'] ?? '',
                'timezone'           => $data['timezone'] ?? 'UTC',
                'user_agent'         => $data['user_agent'] ?? '',
                'auth_method'        => $data['auth_method'] ?? 'Password',
            ];
        }

        // If no rows were logged yet in custom table (e.g. initial install), generate fallback from active sessions
        if (empty($history) && !empty($wp_sessions)) {
            $client_ip = FirewallEngine::get_client_ip();
            $client_ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            $parsed    = self::parse_device_details($client_ua, '');

            foreach ($wp_sessions as $token => $sdata) {
                $s_login = isset($sdata['login']) ? (int) $sdata['login'] : time();
                $dur = max(1, time() - $s_login);
                $session_ip = $sdata['ip'] ?? $client_ip;
                if (\WcpScanner\Firewall\FirewallEngine::is_cloudflare_ip($session_ip)) {
                    $session_ip = $client_ip;
                }

                $history[] = [
                    'id'                 => 1,
                    'login_time'         => date_i18n('Y-m-d H:i:s', $s_login),
                    'login_time_human'   => human_time_diff($s_login, time()) . ' ago',
                    'logout_time'        => null,
                    'last_seen'          => date_i18n('Y-m-d H:i:s', time()),
                    'duration_seconds'   => $dur,
                    'duration_formatted' => self::format_duration($dur),
                    'is_active'          => true,
                    'ip'                 => $session_ip,
                    'browser'            => $parsed['browser'],
                    'browser_version'    => $parsed['browser_version'],
                    'platform'           => $parsed['platform'],
                    'device_type'        => $parsed['device_type'],
                    'screen_resolution'  => '1920x1080 (Estimated)',
                    'viewport'           => '',
                    'timezone'           => 'UTC',
                    'user_agent'         => $sdata['ua'] ?? $client_ua,
                    'auth_method'        => 'Active WordPress Session',
                ];
                if ($total_active_seconds === 0) {
                    $total_active_seconds = $dur;
                    $latest_login_time = date_i18n('Y-m-d H:i:s', $s_login);
                }
            }
        }

        return [
            'success'                => true,
            'user'                   => [
                'id'           => $user->ID,
                'login'        => $user->user_login,
                'display_name' => $user->display_name ?: $user->user_login,
                'email'        => $user->user_email,
                'avatar_url'   => get_avatar_url($user->ID, ['size' => 96]),
                'roles'        => (array) $user->roles,
                'registered'   => $user->user_registered,
            ],
            'last_login_time'        => $latest_login_time ?: current_time('mysql'),
            'total_active_seconds'   => $total_active_seconds,
            'total_active_formatted' => self::format_duration($total_active_seconds),
            'active_sessions_count'  => count($wp_sessions),
            'history'                => $history,
        ];
    }

    /**
     * Format elapsed duration into human readable format: e.g. "1 hour 5 min 2s"
     */
    public static function format_duration(int $seconds): string {
        if ($seconds < 60) {
            return "{$seconds}s";
        }

        $days    = floor($seconds / 86400);
        $seconds = $seconds % 86400;
        $hours   = floor($seconds / 3600);
        $seconds = $seconds % 3600;
        $minutes = floor($seconds / 60);
        $secs    = $seconds % 60;

        $parts = [];
        if ($days > 0) {
            $parts[] = $days . ' ' . _n('day', 'days', $days, 'wcp-security-scanner');
        }
        if ($hours > 0) {
            $parts[] = $hours . ' ' . _n('hour', 'hours', $hours, 'wcp-security-scanner');
        }
        if ($minutes > 0) {
            $parts[] = $minutes . ' min';
        }
        if ($secs > 0 || empty($parts)) {
            $parts[] = $secs . 's';
        }

        return implode(' ', $parts);
    }

    /**
     * Parse User Agent into structured device details
     */
    public static function parse_device_details(string $ua, string $screen_raw = ''): array {
        $device_type = 'Desktop';
        $platform    = 'Windows';
        $browser     = 'Google Chrome';
        $version     = '';

        // Device Type
        if (preg_match('/(tablet|ipad|playbook|silk)|(android(?!.*mobi))/i', $ua)) {
            $device_type = 'Tablet';
        } elseif (preg_match('/(mobile|iphone|ipod|blackberry|opera mini|iemobile|wpdesktop)/i', $ua)) {
            $device_type = 'Mobile';
        }

        // Platform / OS
        if (stripos($ua, 'Windows NT 10.0') !== false) {
            $platform = 'Windows 10 / 11';
        } elseif (stripos($ua, 'Windows NT 6.3') !== false) {
            $platform = 'Windows 8.1';
        } elseif (stripos($ua, 'Windows NT 6.1') !== false) {
            $platform = 'Windows 7';
        } elseif (stripos($ua, 'Windows') !== false) {
            $platform = 'Windows';
        } elseif (stripos($ua, 'Macintosh') !== false || stripos($ua, 'Mac OS X') !== false) {
            $platform = 'macOS';
        } elseif (stripos($ua, 'Android') !== false) {
            $platform = 'Android';
        } elseif (stripos($ua, 'iPhone') !== false) {
            $platform = 'iOS (iPhone)';
        } elseif (stripos($ua, 'iPad') !== false) {
            $platform = 'iPadOS';
        } elseif (stripos($ua, 'Linux') !== false) {
            $platform = 'Linux';
        }

        // Browser & Version
        if (preg_match('/Edg\/([0-9.]+)/i', $ua, $m)) {
            $browser = 'Microsoft Edge';
            $version = $m[1];
        } elseif (preg_match('/Chrome\/([0-9.]+)/i', $ua, $m) && stripos($ua, 'Edg') === false) {
            $browser = 'Google Chrome';
            $version = $m[1];
        } elseif (preg_match('/Firefox\/([0-9.]+)/i', $ua, $m)) {
            $browser = 'Mozilla Firefox';
            $version = $m[1];
        } elseif (preg_match('/Version\/([0-9.]+).*Safari/i', $ua, $m)) {
            $browser = 'Apple Safari';
            $version = $m[1];
        } elseif (preg_match('/OPR\/([0-9.]+)/i', $ua, $m)) {
            $browser = 'Opera';
            $version = $m[1];
        }

        // Format screen resolution
        $screen_res = '1920x1080';
        $viewport   = '';
        if (!empty($screen_raw)) {
            $screen_res = $screen_raw;
        } elseif ($device_type === 'Mobile') {
            $screen_res = '390x844 (Mobile)';
        } elseif ($device_type === 'Tablet') {
            $screen_res = '820x1180 (Tablet)';
        }

        return [
            'device_type'       => $device_type,
            'platform'          => $platform,
            'browser'           => $browser,
            'browser_version'   => $version,
            'screen_resolution' => $screen_res,
            'viewport'          => $viewport,
        ];
    }

    /**
     * Prune older login records keeping recent 25 per user
     */
    private static function prune_old_logins(int $user_id) {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_NAME;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $cutoff_id = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM `{$table}` WHERE user_id = %d ORDER BY id DESC LIMIT 1 OFFSET 25",
            $user_id
        ));

        if ($cutoff_id) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $wpdb->query($wpdb->prepare(
                "DELETE FROM `{$table}` WHERE user_id = %d AND id < %d",
                $user_id,
                $cutoff_id
            ));
        }
    }
}
