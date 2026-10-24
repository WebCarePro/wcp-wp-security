<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class ServerInfo {

    /**
     * Collect comprehensive server, PHP, database, and environment metrics.
     *
     * @return array
     */
    public static function get_info(bool $compute_filesystem = false) {
        global $wpdb, $wp_version;

        try {
            // 1. PHP Configuration
            $memory_limit = ini_get('memory_limit') ?: '256M';
            $memory_usage = memory_get_usage(true);
            $max_execution_time = ini_get('max_execution_time') ?: 30;
            $upload_max_filesize = ini_get('upload_max_filesize') ?: '32M';
            $post_max_size = ini_get('post_max_size') ?: '32M';
            $disabled_functions = ini_get('disable_functions') ? explode(',', ini_get('disable_functions')) : [];
            $disabled_functions = array_map('trim', array_filter($disabled_functions));

            // 2. MySQL Information
            $mysql_version = method_exists($wpdb, 'db_version') ? $wpdb->db_version() : '5.7';
            $db_name = defined('DB_NAME') ? DB_NAME : '';
            $db_host = defined('DB_HOST') ? DB_HOST : 'localhost';
            $db_charset = $wpdb->charset ?? 'utf8mb4';
            $db_collate = $wpdb->collate ?? 'utf8mb4_unicode_ci';

            // Calculate Database Size safely
            $db_size_mb = 0.0;
            if (!empty($db_name)) {
                try {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $db_size_bytes = (int) $wpdb->get_var(
                        $wpdb->prepare("SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema = %s", $db_name)
                    );
                    $db_size_mb = round($db_size_bytes / (1024 * 1024), 2);
                } catch (\Throwable $e) {
                    $db_size_mb = 0.0;
                }
            }

            // 3. Web Server & OS
            $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
            $server_os = php_uname('s') . ' ' . php_uname('r');
            $server_arch = php_uname('m');
            $server_ip = self::get_server_ip();

            // Safe POSIX PHP User Resolution (never throws on boolean false in PHP 8+)
            $posix_user = (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) ? @posix_getpwuid(posix_geteuid()) : null;
            $php_user = (is_array($posix_user) && !empty($posix_user['name'])) ? $posix_user['name'] : (function_exists('get_current_user') ? get_current_user() : 'www-data');

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
            $ssl_active = self::is_ssl_active();
            $multisite = is_multisite();

            $upload_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
            $uploads_basedir = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : '';

            // 6. Security Critical File Permissions
            $permissions = [
                'wp-config.php' => file_exists(ABSPATH . 'wp-config.php') ? substr(sprintf('%o', fileperms(ABSPATH . 'wp-config.php')), -4) : 'N/A',
                '.htaccess'     => file_exists(ABSPATH . '.htaccess') ? substr(sprintf('%o', fileperms(ABSPATH . '.htaccess')), -4) : 'N/A',
                'wp-content'    => is_dir(WP_CONTENT_DIR) ? substr(sprintf('%o', fileperms(WP_CONTENT_DIR)), -4) : 'N/A',
                'uploads'       => (!empty($uploads_basedir) && is_dir($uploads_basedir)) ? substr(sprintf('%o', fileperms($uploads_basedir)), -4) : 'N/A',
            ];

            // Filesystem metrics: only crawl disk if explicitly requested or already cached in transient
            $filesystem = null;
            if ($compute_filesystem) {
                $filesystem = self::get_filesystem_metrics(false);
            } else {
                $cached_fs = function_exists('get_transient') ? get_transient('wcpscan_server_filesystem_metrics') : false;
                $filesystem = is_array($cached_fs) ? $cached_fs : null;
            }

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
                    'table_prefix' => $wpdb->prefix ?? 'wp_',
                ],
                'server' => [
                    'software'    => $server_software,
                    'os'          => $server_os,
                    'arch'        => $server_arch,
                    'ip'          => $server_ip,
                    'server_ip'   => $server_ip,
                    'php_user'    => $php_user,
                    'server_time' => current_time('mysql'),
                    'timezone'    => wp_timezone_string(),
                ],
                'wordpress' => [
                    'version'          => $wp_version ?? '',
                    'site_url'         => get_site_url(),
                    'home_url'         => get_home_url(),
                    'ssl'              => (bool) $ssl_active,
                    'ssl_active'       => (bool) $ssl_active,
                    'multisite'        => (bool) $multisite,
                    'debug'            => (bool) $wp_debug,
                    'debug_log'        => (bool) $wp_debug_log,
                    'debug_display'    => (bool) $wp_debug_display,
                    'wp_debug'         => (bool) $wp_debug,
                    'wp_debug_log'     => (bool) $wp_debug_log,
                    'wp_debug_display' => (bool) $wp_debug_display,
                    'file_permissions' => $permissions,
                ],
                'permissions' => $permissions,
                'filesystem'  => $filesystem,
            ];
        } catch (\Throwable $e) {
            return [
                'php' => [
                    'version'         => PHP_VERSION,
                    'memory_limit'    => ini_get('memory_limit') ?: '256M',
                    'memory_usage_mb' => round(memory_get_usage(true) / (1024 * 1024), 2),
                ],
                'server' => [
                    'software'  => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
                    'server_ip' => self::get_server_ip(),
                ],
                'wordpress' => [
                    'version' => $GLOBALS['wp_version'] ?? '',
                ],
            ];
        }
    }

    /**
     * Accurately determine Server IP Address across environments (LiteSpeed, Nginx, Apache, IIS, CLI, and Docker).
     *
     * @return string
     */
    public static function get_server_ip(): string {
        // 1. Direct server environment variables
        $env_candidates = [
            isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '',
            isset($_SERVER['LOCAL_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['LOCAL_ADDR'])) : '',
        ];

        foreach ($env_candidates as $candidate) {
            $candidate = trim((string) $candidate);
            if (!empty($candidate) && filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        // 2. Resolve server hostnames via local resolver
        $host_candidates = [];
        if (function_exists('gethostname')) {
            $hostname = @gethostname();
            if (!empty($hostname)) {
                $host_candidates[] = $hostname;
            }
        }
        $nodename = php_uname('n');
        if (!empty($nodename)) {
            $host_candidates[] = $nodename;
        }
        if (!empty($_SERVER['SERVER_NAME'])) {
            $host_candidates[] = sanitize_text_field(wp_unslash($_SERVER['SERVER_NAME']));
        }
        if (!empty($_SERVER['HTTP_HOST'])) {
            $host_candidates[] = preg_replace('/:[0-9]+$/', '', sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])));
        }
        $site_host = wp_parse_url(get_site_url(), PHP_URL_HOST);
        if (!empty($site_host)) {
            $host_candidates[] = $site_host;
        }

        foreach ($host_candidates as $host) {
            $host = trim((string) $host);
            if (empty($host)) {
                continue;
            }
            if (filter_var($host, FILTER_VALIDATE_IP)) {
                return $host;
            }
            $resolved = @gethostbyname($host);
            if (!empty($resolved) && $resolved !== $host && filter_var($resolved, FILTER_VALIDATE_IP)) {
                return $resolved;
            }
        }

        // 3. Fallback to raw SERVER_ADDR if present
        if (!empty($_SERVER['SERVER_ADDR'])) {
            return sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR']));
        }

        return 'Unavailable';
    }

    /**
     * Accurately determine if SSL/HTTPS is active, including behind Reverse Proxies,
     * Load Balancers, Cloudflare, LiteSpeed, and HTTPS WordPress site URLs.
     *
     * @return bool
     */
    public static function is_ssl_active(): bool {
        if (function_exists('is_ssl') && is_ssl()) {
            return true;
        }

        if (!empty($_SERVER['HTTPS']) && strtolower(sanitize_text_field(wp_unslash($_SERVER['HTTPS']))) !== 'off') {
            return true;
        }

        if (isset($_SERVER['SERVER_PORT']) && ('443' == sanitize_text_field(wp_unslash($_SERVER['SERVER_PORT'])))) {
            return true;
        }

        // Reverse proxy headers (Cloudflare, LiteSpeed, Nginx, AWS ALB/ELB)
        if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower(sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_PROTO']))) === 'https') {
            return true;
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && strtolower(sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_SSL']))) === 'on') {
            return true;
        }

        if (!empty($_SERVER['HTTP_CF_VISITOR'])) {
            $cf_visitor = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_VISITOR']));
            $visitor = json_decode($cf_visitor, true);
            if (is_array($visitor) && isset($visitor['scheme']) && $visitor['scheme'] === 'https') {
                return true;
            }
            if (strpos($cf_visitor, 'https') !== false) {
                return true;
            }
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_PORT']) && ('443' == sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_PORT'])))) {
            return true;
        }

        if (!empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower(sanitize_text_field(wp_unslash($_SERVER['HTTP_FRONT_END_HTTPS']))) !== 'off') {
            return true;
        }

        // WordPress site & home URL protocol check
        $site_url = function_exists('get_site_url') ? get_site_url() : '';
        if (strpos($site_url, 'https://') === 0) {
            return true;
        }

        $home_url = function_exists('get_home_url') ? get_home_url() : '';
        if (strpos($home_url, 'https://') === 0) {
            return true;
        }

        return false;
    }

    /**
     * Compute comprehensive filesystem storage metrics and file inventory by extension.
     *
     * @param bool $force_refresh
     * @return array
     */
    public static function get_filesystem_metrics(bool $force_refresh = false): array {
        $transient_key = 'wcpscan_server_filesystem_metrics';
        if (!$force_refresh) {
            $cached = function_exists('get_transient') ? get_transient($transient_key) : false;
            if ($cached && is_array($cached)) {
                return $cached;
            }
        }

        $root = wp_normalize_path(untrailingslashit(ABSPATH));
        $admin_path = wp_normalize_path(ABSPATH . 'wp-admin');
        $includes_path = wp_normalize_path(ABSPATH . WPINC);
        $content_path = wp_normalize_path(WP_CONTENT_DIR);
        $plugins_path = wp_normalize_path(WP_PLUGIN_DIR);
        $themes_path = wp_normalize_path(function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes'));
        $upload_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
        $uploads_path = !empty($upload_dir['basedir']) ? wp_normalize_path($upload_dir['basedir']) : '';

        $sizes = [
            'wp_admin_bytes'    => 0,
            'wp_includes_bytes' => 0,
            'wp_content_bytes'  => 0,
            'plugins_bytes'     => 0,
            'themes_bytes'      => 0,
            'uploads_bytes'     => 0,
            'total_bytes'       => 0,
        ];

        $extension_counts = [];
        $total_files = 0;
        $excluded_dirs = ['.git', '.svn', 'node_modules', 'vendor', 'cache', 'wfcache', '.vault', '.backups'];

        try {
            if (is_dir($root)) {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::UNIX_PATHS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($iterator as $item) {
                    if ($item->isDir()) {
                        continue;
                    }
                    if (!$item->isFile()) {
                        continue;
                    }

                    $path = wp_normalize_path($item->getPathname());
                    $rel = substr($path, strlen($root));

                    $skip = false;
                    foreach ($excluded_dirs as $ex) {
                        if (strpos($rel, '/' . $ex . '/') !== false || strpos($rel, '/' . $ex) === 0) {
                            $skip = true;
                            break;
                        }
                    }
                    if ($skip) {
                        continue;
                    }

                    $size = (int) $item->getSize();
                    $sizes['total_bytes'] += $size;
                    $total_files++;

                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION)) ?: 'no_ext';
                    $extension_counts[$ext] = ($extension_counts[$ext] ?? 0) + 1;

                    if (strpos($path, $admin_path . '/') === 0 || $path === $admin_path) {
                        $sizes['wp_admin_bytes'] += $size;
                    } elseif (strpos($path, $includes_path . '/') === 0 || $path === $includes_path) {
                        $sizes['wp_includes_bytes'] += $size;
                    } elseif (strpos($path, $content_path . '/') === 0 || $path === $content_path) {
                        $sizes['wp_content_bytes'] += $size;
                        if (strpos($path, $plugins_path . '/') === 0) {
                            $sizes['plugins_bytes'] += $size;
                        } elseif (strpos($path, $themes_path . '/') === 0) {
                            $sizes['themes_bytes'] += $size;
                        } elseif (!empty($uploads_path) && strpos($path, $uploads_path . '/') === 0) {
                            $sizes['uploads_bytes'] += $size;
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Gracefully ignore directory permission limits
        }

        arsort($extension_counts);

        $metrics = [
            'total_files'          => $total_files,
            'total_size_mb'        => round($sizes['total_bytes'] / (1024 * 1024), 2),
            'wp_admin_size_mb'     => round($sizes['wp_admin_bytes'] / (1024 * 1024), 2),
            'wp_includes_size_mb'  => round($sizes['wp_includes_bytes'] / (1024 * 1024), 2),
            'wp_content_size_mb'   => round($sizes['wp_content_bytes'] / (1024 * 1024), 2),
            'plugins_size_mb'      => round($sizes['plugins_bytes'] / (1024 * 1024), 2),
            'themes_size_mb'       => round($sizes['themes_bytes'] / (1024 * 1024), 2),
            'uploads_size_mb'      => round($sizes['uploads_bytes'] / (1024 * 1024), 2),
            'php_files'            => (int) ($extension_counts['php'] ?? 0),
            'js_files'             => (int) ($extension_counts['js'] ?? 0),
            'css_files'            => (int) ($extension_counts['css'] ?? 0),
            'extension_counts'     => $extension_counts,
        ];

        if (function_exists('set_transient')) {
            set_transient($transient_key, $metrics, 30 * MINUTE_IN_SECONDS);
        }

        return $metrics;
    }
}
