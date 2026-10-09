<?php
namespace WCP\Scanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class ServerInfo {

    /**
     * Collect comprehensive server, PHP, database, and environment metrics.
     *
     * @return array
     */
    public static function get_info() {
        global $wpdb, $wp_version;

        // 1. PHP Configuration
        $memory_limit = ini_get('memory_limit');
        $memory_usage = memory_get_usage(true);
        $max_execution_time = ini_get('max_execution_time');
        $upload_max_filesize = ini_get('upload_max_filesize');
        $post_max_size = ini_get('post_max_size');
        $disabled_functions = ini_get('disable_functions') ? explode(',', ini_get('disable_functions')) : [];
        $disabled_functions = array_map('trim', array_filter($disabled_functions));

        // 2. MySQL Information
        $mysql_version = $wpdb->db_version();
        $db_name = DB_NAME;
        $db_host = DB_HOST;
        $db_charset = $wpdb->charset;
        $db_collate = $wpdb->collate;

        // Calculate Database Size
        $db_size_bytes = (int) $wpdb->get_var(
            "SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema = '{$db_name}'"
        );
        $db_size_mb = round($db_size_bytes / (1024 * 1024), 2);

        // 3. Web Server & OS
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
        $server_os = php_uname('s') . ' ' . php_uname('r');
        $server_arch = php_uname('m');
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : gethostbyname(gethostname());

        // 4. Critical Extensions Check
        $critical_extensions = [
            'openssl'  => extension_loaded('openssl'),
            'curl'     => extension_loaded('curl'),
            'zip'      => extension_loaded('zip'),
            'zlib'     => extension_loaded('zlib'),
            'opcache'  => extension_loaded('Zend OPcache'),
            'mbstring' => extension_loaded('mbstring'),
            'gd'       => extension_loaded('gd') || extension_loaded('imagick'),
            'intl'     => extension_loaded('intl'),
            'json'     => extension_loaded('json'),
            'sodium'   => extension_loaded('sodium'),
        ];

        // 5. WordPress Environment
        $wp_debug = defined('WP_DEBUG') && WP_DEBUG;
        $wp_debug_log = defined('WP_DEBUG_LOG') && WP_DEBUG_LOG;
        $wp_debug_display = defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY;
        $ssl_active = is_ssl();
        $multisite = is_multisite();

        $upload_dir = wp_upload_dir();
        $uploads_basedir = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : '';

        // 6. Security Critical File Permissions
        $permissions = [
            'wp-config.php' => file_exists(ABSPATH . 'wp-config.php') ? substr(sprintf('%o', fileperms(ABSPATH . 'wp-config.php')), -4) : 'N/A',
            '.htaccess'     => file_exists(ABSPATH . '.htaccess') ? substr(sprintf('%o', fileperms(ABSPATH . '.htaccess')), -4) : 'N/A',
            'wp-content'    => is_dir(WP_CONTENT_DIR) ? substr(sprintf('%o', fileperms(WP_CONTENT_DIR)), -4) : 'N/A',
            'uploads'       => (!empty($uploads_basedir) && is_dir($uploads_basedir)) ? substr(sprintf('%o', fileperms($uploads_basedir)), -4) : 'N/A',
        ];

        return [
            'php' => [
                'version'             => PHP_VERSION,
                'sapi'                => php_sapi_name(),
                'memory_limit'        => $memory_limit,
                'memory_usage_mb'     => round($memory_usage / (1024 * 1024), 2),
                'max_execution_time'  => (int) $max_execution_time,
                'upload_max_filesize' => $upload_max_filesize,
                'post_max_size'       => $post_max_size,
                'display_errors'      => ini_get('display_errors') ? 'On' : 'Off',
                'disabled_functions'  => $disabled_functions,
                'extensions'          => $critical_extensions,
            ],
            'database' => [
                'version'      => $mysql_version,
                'name'         => $db_name,
                'host'         => $db_host,
                'charset'      => $db_charset,
                'collate'      => $db_collate,
                'size_mb'      => $db_size_mb,
                'table_prefix' => $wpdb->prefix,
            ],
            'server' => [
                'software'    => $server_software,
                'os'          => $server_os,
                'arch'        => $server_arch,
                'server_ip'   => $server_ip,
                'php_user'    => function_exists('posix_getpwuid') && function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'www-data') : get_current_user(),
                'server_time' => current_time('mysql'),
                'timezone'    => wp_timezone_string(),
            ],
            'wordpress' => [
                'version'          => $wp_version,
                'site_url'         => get_site_url(),
                'home_url'         => get_home_url(),
                'ssl_active'       => $ssl_active,
                'multisite'        => $multisite,
                'wp_debug'         => $wp_debug,
                'wp_debug_log'     => $wp_debug_log,
                'wp_debug_display' => $wp_debug_display,
                'file_permissions' => $permissions,
            ],
            'permissions' => $permissions,
        ];
    }
}
