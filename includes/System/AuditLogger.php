<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class AuditLogger {

    private $log_dir;
    private $log_file;

    public function __construct() {
        $upload_dir = wp_upload_dir();
        // Dot-prefixed protected directory blocked by Nginx /\.(?!well-known).* rules
        $this->log_dir = untrailingslashit($upload_dir['basedir']) . '/wcp-security-scanner/.logs';
        $this->log_file = $this->log_dir . '/audit.log.php';
    }

    public function init() {
        $this->ensure_log_directory();
        $this->register_hooks();
    }

    private function ensure_log_directory() {
        if (!is_dir($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
        }

        // Secure the logs directory for Apache / LiteSpeed
        $htaccess = $this->log_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# Block all public access\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n<FilesMatch \".*\">\n    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n    <IfModule !mod_authz_core.c>\n        Order deny,allow\n        Deny from all\n    </IfModule>\n</FilesMatch>\n";
            @file_put_contents($htaccess, $rules);
        }

        $index = $this->log_dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\nexit('WCP Security: Direct access forbidden.');\n");
        }
    }

    /**
     * Register hooks to monitor critical administrative events.
     */
    private function register_hooks() {
        // User Logins
        add_action('wp_login', [$this, 'log_user_login'], 10, 2);
        add_action('wp_login_failed', [$this, 'log_failed_login']);
        
        // Plugin Management
        add_action('activated_plugin', [$this, 'log_plugin_activation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivation'], 10, 2);
        
        // Theme Management
        add_action('switch_theme', [$this, 'log_theme_switch'], 10, 3);
        
        // User Management
        add_action('user_register', [$this, 'log_user_registered']);
        add_action('delete_user', [$this, 'log_user_deleted']);
        
        // Core Updates
        add_action('_core_updated_successfully', [$this, 'log_core_update']);
    }

    private function write_log($event_type, $message) {
        $timestamp = gmdate('Y-m-d H:i:s');
        $raw_ip = class_exists('\\WcpScanner\\Firewall\\FirewallEngine')
            ? \WcpScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '');
        $ip_address = filter_var($raw_ip, FILTER_VALIDATE_IP) ? $raw_ip : 'UNKNOWN';
        
        $current_user = wp_get_current_user();
        $username = ($current_user && $current_user->exists()) ? sanitize_user($current_user->user_login) : 'System/Guest';

        $clean_event = sanitize_key($event_type);
        $clean_message = is_array($message) ? wp_json_encode($message) : str_replace(["\r", "\n"], ' ', sanitize_text_field((string) $message));

        // Format: [TIMESTAMP] [IP] [USER] [EVENT] Message
        $log_entry = sprintf("[%s] [IP: %s] [User: %s] [%s] %s" . PHP_EOL, $timestamp, $ip_address, $username, $clean_event, $clean_message);

        // Prepend PHP exit guard on file creation so direct web requests immediately terminate
        if (!file_exists($this->log_file)) {
            @file_put_contents($this->log_file, "<?php http_response_code(403); exit('WCP Security: Direct access forbidden.'); ?>\n", LOCK_EX);
        }

        @file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);

        // Enterprise Activity Log Bridge: Forward into cryptographic hash-chained activity log ledger
        self::bridge_to_wcp_activity_logger($event_type, $message);
    }

    /**
     * Bridge legacy and subsystem audit events into WcpActivityLogger.
     * Note: Pure WAF packet drops, runtime rate limits, and bot traps are EXCLUDED
     * to keep Plugin Activity & Audit Logs strictly focused on plugin configuration
     * and intentional administrator actions.
     *
     * @param string $event_type
     * @param mixed  $message
     */
    public static function bridge_to_wcp_activity_logger($event_type, $message): void {
        if (!class_exists('\\WcpScanner\\System\\WcpActivityLogger')) {
            return;
        }

        $clean_action = sanitize_key(strtolower((string) $event_type));

        // Filter out transient runtime attacks, automated bot traps, and WAF drops (handled in WAF logs)
        $traffic_actions = [
            'rate_limit_ban',
            'rate_limit_escalated_ban',
            'bot_trapped',
            'bot_trap_triggered',
            'honeytoken_triggered',
            'honeytoken_trapped',
            'ghost_route_triggered',
            'ghost_route_trapped',
            'form_spam_neutralized',
            'waf_block',
            'ip_blocked',
            'waf_incident',
            'learning_mode_route_learned',
        ];

        foreach ($traffic_actions as $ta) {
            if (str_contains($clean_action, $ta)) {
                return;
            }
        }

        $category = self::map_event_to_category($clean_action);
        $severity = self::map_event_to_severity($clean_action);

        $details = [];
        if (is_array($message)) {
            $details = $message;
            if (!isset($details['description'])) {
                $details['description'] = sprintf('Event %s recorded with structured payload.', $clean_action);
            }
        } else {
            $details = [
                'description' => (string) $message,
                'raw_event'   => (string) $event_type,
            ];
        }

        \WcpScanner\System\WcpActivityLogger::log($clean_action, $category, $severity, $details);
    }

    /**
     * Map audit event action name to valid WcpActivityLogger category.
     *
     * @param string $action
     * @return string
     */
    private static function map_event_to_category(string $action): string {
        if (str_contains($action, 'vpatch') || str_contains($action, 'virtual_patch') || str_contains($action, 'firewall') || str_contains($action, 'micro_waf') || str_contains($action, 'rate_limit') || str_contains($action, 'honey') || str_contains($action, 'ghost_route') || str_contains($action, 'spam')) {
            return 'firewall';
        }

        if (str_contains($action, 'auth') || str_contains($action, 'login') || str_contains($action, 'webauthn') || str_contains($action, 'session') || str_contains($action, 'ephemeral') || str_contains($action, 'user') || str_contains($action, 'breach')) {
            return 'auth';
        }

        if (str_contains($action, 'quarantine') || str_contains($action, 'reinfection')) {
            return 'quarantine';
        }

        if (str_contains($action, 'scan') || str_contains($action, 'monitor') || str_contains($action, 'simulation') || str_contains($action, 'exposure')) {
            return 'scan';
        }

        if (str_contains($action, 'setting') || str_contains($action, 'whitelist') || str_contains($action, 'policy') || str_contains($action, 'containment')) {
            return 'settings';
        }

        if (str_contains($action, 'crash') || str_contains($action, 'safe_mode')) {
            return 'crashguard';
        }

        return 'system';
    }

    /**
     * Map audit event action name to valid WcpActivityLogger severity level.
     *
     * @param string $action
     * @return string
     */
    private static function map_event_to_severity(string $action): string {
        if (str_contains($action, 'failed') || str_contains($action, 'breach') || str_contains($action, 'quarantine') || str_contains($action, 'blocked') || str_contains($action, 'lockout') || str_contains($action, 'containment')) {
            return \WcpScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_WARNING;
        }

        if (str_contains($action, 'tamper') || str_contains($action, 'compromise') || str_contains($action, 'critical')) {
            return \WcpScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_CRITICAL;
        }

        if (str_contains($action, 'applied') || str_contains($action, 'removed') || str_contains($action, 'updated') || str_contains($action, 'switched') || str_contains($action, 'activated') || str_contains($action, 'deactivated') || str_contains($action, 'created') || str_contains($action, 'deleted')) {
            return \WcpScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_NOTICE;
        }

        return \WcpScanner\System\ActivityLogs\ActivityEventSchema::SEVERITY_INFO;
    }

    public function log_user_login($user_login, $user) {
        $this->write_log('AUTH_SUCCESS', "User '{$user_login}' logged in successfully.");
    }

    public function log_failed_login($username) {
        $this->write_log('AUTH_FAILED', "Failed login attempt for username: '{$username}'.");
    }

    public function log_plugin_activation($plugin, $network_wide) {
        $scope = $network_wide ? 'network-wide' : 'locally';
        $this->write_log('PLUGIN_ACTIVATED', "Plugin '{$plugin}' was activated $scope.");
    }

    public function log_plugin_deactivation($plugin, $network_wide) {
        $scope = $network_wide ? 'network-wide' : 'locally';
        $this->write_log('PLUGIN_DEACTIVATED', "Plugin '{$plugin}' was deactivated $scope.");
    }

    public function log_theme_switch($new_name, $new_theme, $old_theme) {
        $old_name = $old_theme ? $old_theme->get('Name') : 'Unknown';
        $this->write_log('THEME_SWITCHED', "Theme switched from '{$old_name}' to '{$new_name}'.");
    }

    public function log_user_registered($user_id) {
        $user_info = get_userdata($user_id);
        if ($user_info) {
            $this->write_log('USER_REGISTERED', "New user registered: '{$user_info->user_login}' (ID: {$user_id}, Role: " . implode(', ', $user_info->roles) . ").");
        }
    }

    public function log_user_deleted($user_id) {
        $this->write_log('USER_DELETED', "User account deleted (ID: {$user_id}).");
    }

    public function log_core_update($wp_version) {
        $this->write_log('CORE_UPDATED', "WordPress core successfully updated to version {$wp_version}.");
    }

    /**
     * Public static helper to log custom administrative and security events.
     *
     * @param string $event_type
     * @param string $message
     */
    public static function log_event($event_type, $message) {
        $instance = new self();
        $instance->ensure_log_directory();
        $instance->write_log($event_type, $message);
    }

    /**
     * Alias for log_event
     */
    public static function log($event_type, $message) {
        self::log_event($event_type, $message);
    }
}

