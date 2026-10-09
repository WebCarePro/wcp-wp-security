<?php
namespace WCP\Scanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class AuditLogger {

    private $log_dir;
    private $log_file;

    public function __construct() {
        $upload_dir = wp_upload_dir();
        $this->log_dir = untrailingslashit($upload_dir['basedir']) . '/wcp-security-scanner/logs';
        $this->log_file = $this->log_dir . '/audit.log';
    }

    public function init() {
        $this->ensure_log_directory();
        $this->register_hooks();
    }

    private function ensure_log_directory() {
        if (!is_dir($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
        }

        // Secure the logs directory
        $htaccess = $this->log_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n");
        }

        $index = $this->log_dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\nexit;\n");
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
        $raw_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $ip_address = filter_var($raw_ip, FILTER_VALIDATE_IP) ? $raw_ip : 'UNKNOWN';
        
        $current_user = wp_get_current_user();
        $username = ($current_user && $current_user->exists()) ? sanitize_user($current_user->user_login) : 'System/Guest';

        $clean_event = sanitize_key($event_type);
        $clean_message = str_replace(["\r", "\n"], ' ', sanitize_text_field($message));

        // Format: [TIMESTAMP] [IP] [USER] [EVENT] Message
        $log_entry = sprintf("[%s] [IP: %s] [User: %s] [%s] %s" . PHP_EOL, $timestamp, $ip_address, $username, $clean_event, $clean_message);

        @file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);
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
}
