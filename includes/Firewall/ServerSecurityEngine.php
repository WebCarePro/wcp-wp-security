<?php
/**
 * Server-Level Web Server Security & Firewall Rule Generator Engine
 *
 * Generates tailored Nginx and Apache/LiteSpeed web server security configurations
 * based on auto-detected server software and customized interactive matrix settings.
 *
 * @package WcpScanner\Firewall
 * @author  Mir Alamin (WebCare Pro)
 */

namespace WcpScanner\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class ServerSecurityEngine {

    const OPTION_KEY = 'wcpscan_server_security_options';
    const WAF_FOLDER = 'wcp-security-scanner/waf';
    const NGINX_FILENAME = 'nginx-wcp-security.conf';
    const APACHE_FILENAME = 'apache-wcp-security.conf';
    const CADDY_FILENAME = 'caddy-wcp-security.conf';

    /**
     * Default security matrix options
     */
    public static function get_default_options(): array {
        return [
            // Core Perimeter Security (Checkboxes)
            'block_uploads_php'       => true,
            'block_sensitive_files'   => true,
            'block_xmlrpc'            => true,
            'block_author_scans'      => true,
            'block_exploit_queries'   => true,
            'block_bad_bots'          => true,
            'disable_directory_index' => true,
            'protect_wp_config'       => true,

            // Rate Limiting & Throttling (Sliders / Numeric)
            'rate_limit_login'        => true,
            'login_rate_limit'        => 5,    // requests per minute
            'login_burst_limit'       => 10,   // burst allowance
            'rate_limit_global'       => false,
            'global_rate_limit'       => 30,   // req/sec per IP
            'client_max_body_mb'      => 64,   // max body size in MB
            'restrict_http_methods'   => true, // GET, POST, HEAD only

            // HTTP Security Headers (Checkboxes)
            'header_x_frame_options'  => true,
            'header_x_content_type'   => true,
            'header_referrer_policy'  => true,
            'header_permissions'      => true,
            'header_hsts'             => false, // Optional for strict SSL sites
        ];
    }

    /**
     * Get active options merged with defaults
     */
    public static function get_options(): array {
        $saved = get_option(self::OPTION_KEY, []);
        if (!is_array($saved)) {
            $saved = [];
        }
        return array_merge(self::get_default_options(), $saved);
    }

    /**
     * Save security matrix options
     */
    public static function save_options(array $options): array {
        $clean = [];
        $existing = self::get_options();

        foreach (self::get_default_options() as $k => $def_val) {
            if (!array_key_exists($k, $options)) {
                $clean[$k] = $existing[$k] ?? $def_val;
            } elseif (is_bool($def_val)) {
                $clean[$k] = !empty($options[$k]);
            } elseif (is_int($def_val)) {
                $clean[$k] = max(1, min(1024, (int) $options[$k]));
            } else {
                $clean[$k] = sanitize_text_field((string) $options[$k]);
            }
        }

        update_option(self::OPTION_KEY, $clean, false);
        return $clean;
    }

    /**
     * Get the storage directory for generated server configs
     */
    public static function get_storage_dir(): string {
        $upload_dir = wp_upload_dir();
        $base = $upload_dir['basedir'] . '/' . self::WAF_FOLDER;
        if (!file_exists($base)) {
            wp_mkdir_p($base);
            // Protect directory from web indexing
            @file_put_contents($base . '/index.php', '<?php // Silence is golden.');
            @file_put_contents($base . '/.htaccess', "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>");
        }

        return untrailingslashit($base);
    }

    /**
     * Get paths and file statuses
     */
    public static function get_file_info(): array {
        $dir = self::get_storage_dir();
        $nginx_path = $dir . '/' . self::NGINX_FILENAME;
        $apache_path = $dir . '/' . self::APACHE_FILENAME;
        $caddy_path = $dir . '/' . self::CADDY_FILENAME;
        $htaccess_root = ABSPATH . '.htaccess';

        return [
            'storage_dir'          => $dir,
            'nginx_path'           => $nginx_path,
            'nginx_exists'         => file_exists($nginx_path),
            'nginx_writable'       => wp_is_writable(dirname($nginx_path)),
            'nginx_size'           => file_exists($nginx_path) ? filesize($nginx_path) : 0,
            'nginx_updated_at'     => file_exists($nginx_path) ? gmdate('Y-m-d H:i:s', filemtime($nginx_path)) : null,
            'nginx_include_code'   => 'include ' . $nginx_path . ';',
            'apache_path'          => $apache_path,
            'apache_exists'        => file_exists($apache_path),
            'apache_updated_at'    => file_exists($apache_path) ? gmdate('Y-m-d H:i:s', filemtime($apache_path)) : null,
            'caddy_path'           => $caddy_path,
            'caddy_exists'         => file_exists($caddy_path),
            'caddy_updated_at'     => file_exists($caddy_path) ? gmdate('Y-m-d H:i:s', filemtime($caddy_path)) : null,
            'caddy_import_code'    => 'import ' . $caddy_path,
            'htaccess_root'        => $htaccess_root,
            'htaccess_writable'    => wp_is_writable($htaccess_root) || (!file_exists($htaccess_root) && wp_is_writable(ABSPATH)),
        ];
    }

    /**
     * Generate complete Nginx Security Configuration
     */
    public static function generate_nginx_config(array $opts): string {
        $now = gmdate('Y-m-d H:i:s \U\T\C');
        $site_url = get_site_url();

        $c = "# =========================================================================\n";
        $c .= "# WebCare Pro - High Performance Nginx Security & Web Server Armor\n";
        $c .= "# Site: {$site_url}\n";
        $c .= "# Generated: {$now}\n";
        $c .= "# Architecture: Tailored Modular Server-Level Protection\n";
        $c .= "# =========================================================================\n\n";

        // Global Rate Limiting Zones (Must be placed in http {} or top of server block)
        if (!empty($opts['rate_limit_login'])) {
            $login_rate = max(1, (int) $opts['login_rate_limit']);
            $burst = max(1, (int) $opts['login_burst_limit']);
            $c .= "# --- 1. Login Brute Force Throttling Zone ---\n";
            $c .= "# Tip: Ensure 'limit_req_zone' is defined in your nginx.conf http {} block if needed:\n";
            $c .= "# limit_req_zone \$binary_remote_addr zone=wcp_wp_login:10m rate={$login_rate}r/m;\n\n";
            $c .= "location = /wp-login.php {\n";
            $c .= "    limit_req zone=wcp_wp_login burst={$burst} nodelay;\n";
            $c .= "    include fastcgi_params;\n";
            $c .= "    fastcgi_pass php-fpm;\n";
            $c .= "}\n\n";
        }

        // Global Request Rate Limit
        if (!empty($opts['rate_limit_global'])) {
            $global_rate = max(5, (int) $opts['global_rate_limit']);
            $c .= "# --- 2. Global IP Request Throttling ---\n";
            $c .= "# limit_req_zone \$binary_remote_addr zone=wcp_global:10m rate={$global_rate}r/s;\n";
            $c .= "limit_req zone=wcp_global burst=50 nodelay;\n\n";
        }

        // Client Max Body Size
        $body_mb = max(1, (int) $opts['client_max_body_mb']);
        $c .= "# --- 3. Maximum Request Payload Armor ---\n";
        $c .= "client_max_body_size {$body_mb}M;\n\n";

        // Restrict HTTP Methods
        if (!empty($opts['restrict_http_methods'])) {
            $c .= "# --- 4. Restrict Hostile HTTP Methods ---\n";
            $c .= "if (\$request_method !~ ^(GET|POST|HEAD)$ ) {\n";
            $c .= "    return 405;\n";
            $c .= "}\n\n";
        }

        // Block Uploads PHP Execution
        if (!empty($opts['block_uploads_php'])) {
            $c .= "# --- 5. Block Direct PHP Script Execution in Uploads & Cache ---\n";
            $c .= "location ~* /(?:uploads|files|cache)/.*\\.php$ {\n";
            $c .= "    deny all;\n";
            $c .= "    access_log off;\n";
            $c .= "    log_not_found off;\n";
            $c .= "}\n\n";
        }

        // Block Sensitive & Hidden Files
        if (!empty($opts['block_sensitive_files'])) {
            $c .= "# --- 6. Block Sensitive Files, Backups, and Git/SVN Probes ---\n";
            $c .= "location ~* /\\.(?!well-known/) {\n";
            $c .= "    deny all;\n";
            $c .= "    access_log off;\n";
            $c .= "    log_not_found off;\n";
            $c .= "}\n";
            $c .= "location ~* (?:composer\\.(?:json|lock)|package\\.(?:json|lock)|\\.env|\\.git|\\.sql|\\.bak|\\.tar|\\.gz|\\.zip|debug\\.log)\$ {\n";
            $c .= "    deny all;\n";
            $c .= "    access_log off;\n";
            $c .= "    log_not_found off;\n";
            $c .= "}\n\n";
        }

        // Protect wp-config.php
        if (!empty($opts['protect_wp_config'])) {
            $c .= "# --- 7. Strict wp-config.php Lockdown ---\n";
            $c .= "location = /wp-config.php {\n";
            $c .= "    deny all;\n";
            $c .= "    access_log off;\n";
            $c .= "    log_not_found off;\n";
            $c .= "}\n\n";
        }

        // Disable XML-RPC
        if (!empty($opts['block_xmlrpc'])) {
            $c .= "# --- 8. Disable XML-RPC Pingback & Amplification ---\n";
            $c .= "location = /xmlrpc.php {\n";
            $c .= "    deny all;\n";
            $c .= "    access_log off;\n";
            $c .= "    log_not_found off;\n";
            $c .= "}\n\n";
        }

        // Block Author Scans
        if (!empty($opts['block_author_scans'])) {
            $c .= "# --- 9. Block Username Enumeration Attacks (?author=N) ---\n";
            $c .= "if (\$query_string ~ \"author=\\d+\") {\n";
            $c .= "    return 403;\n";
            $c .= "}\n\n";
        }

        // Block Exploit Query Strings (LFI/RFI/Injection)
        if (!empty($opts['block_exploit_queries'])) {
            $c .= "# --- 10. LFI/RFI Directory Traversal & Remote Code Injection Armor ---\n";
            $c .= "if (\$query_string ~* \"(\\.\\./|\\.\\.%2f|base64_decode\\(|eval\\(|<script|GLOBALS|_REQUEST)\") {\n";
            $c .= "    return 403;\n";
            $c .= "}\n\n";
        }

        // Block Bad Bots & Scanners
        if (!empty($opts['block_bad_bots'])) {
            $c .= "# --- 11. Malicious Vulnerability Scanners & Scrapers Filter ---\n";
            $c .= "if (\$http_user_agent ~* (sqlmap|nikto|wpscan|dirbuster|gobuster|masscan|zgrab|acunetix|nmap|havij)) {\n";
            $c .= "    return 403;\n";
            $c .= "}\n\n";
        }

        // Disable Directory Indexing
        if (!empty($opts['disable_directory_index'])) {
            $c .= "# --- 12. Disable Directory Browsing ---\n";
            $c .= "autoindex off;\n\n";
        }

        // Security Headers
        $c .= "# --- 13. Hardened HTTP Response Headers ---\n";
        if (!empty($opts['header_x_frame_options'])) {
            $c .= "add_header X-Frame-Options \"SAMEORIGIN\" always;\n";
        }
        if (!empty($opts['header_x_content_type'])) {
            $c .= "add_header X-Content-Type-Options \"nosniff\" always;\n";
        }
        if (!empty($opts['header_referrer_policy'])) {
            $c .= "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n";
        }
        if (!empty($opts['header_permissions'])) {
            $c .= "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n";
        }
        if (!empty($opts['header_hsts'])) {
            $c .= "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n";
        }

        return $c;
    }

    /**
     * Generate complete Apache / LiteSpeed .htaccess Configuration
     */
    public static function generate_apache_config(array $opts): string {
        $now = gmdate('Y-m-d H:i:s \U\T\C');
        $site_url = get_site_url();

        $c = "# =========================================================================\n";
        $c .= "# WebCare Pro - Apache & LiteSpeed Security Directives\n";
        $c .= "# Site: {$site_url}\n";
        $c .= "# Generated: {$now}\n";
        $c .= "# =========================================================================\n\n";

        // Disable Directory Indexing
        if (!empty($opts['disable_directory_index'])) {
            $c .= "# --- 1. Prevent Directory Browsing ---\n";
            $c .= "Options -Indexes\n\n";
        }

        // Restrict HTTP Methods
        if (!empty($opts['restrict_http_methods'])) {
            $c .= "# --- 2. Restrict Hostile HTTP Request Methods ---\n";
            $c .= "<LimitExcept GET POST HEAD>\n";
            $c .= "    Deny from all\n";
            $c .= "</LimitExcept>\n\n";
        }

        // Request Body Limit
        $body_mb = max(1, (int) $opts['client_max_body_mb']);
        $body_bytes = $body_mb * 1024 * 1024;
        $c .= "# --- 3. Request Payload Size Armor ({$body_mb} MB) ---\n";
        $c .= "LimitRequestBody {$body_bytes}\n\n";

        // Protect wp-config.php and Sensitive Files
        $c .= "# --- 4. Sensitive File & Configuration Armor ---\n";
        $c .= "<FilesMatch \"^(wp-config\\.php|\\.env|composer\\.(json|lock)|package\\.(json|lock)|\\.git|debug\\.log)\">\n";
        $c .= "    Order Allow,Deny\n";
        $c .= "    Deny from all\n";
        $c .= "    <IfModule mod_authz_core.c>\n";
        $c .= "        Require all denied\n";
        $c .= "    </IfModule>\n";
        $c .= "</FilesMatch>\n\n";

        // Block backup archives
        $c .= "<FilesMatch \"\\.(sql|bak|tar|gz|zip|ini|sh)$\">\n";
        $c .= "    Order Allow,Deny\n";
        $c .= "    Deny from all\n";
        $c .= "    <IfModule mod_authz_core.c>\n";
        $c .= "        Require all denied\n";
        $c .= "    </IfModule>\n";
        $c .= "</FilesMatch>\n\n";

        // Block XML-RPC
        if (!empty($opts['block_xmlrpc'])) {
            $c .= "# --- 5. Disable XML-RPC Endpoint ---\n";
            $c .= "<Files xmlrpc.php>\n";
            $c .= "    Order Deny,Allow\n";
            $c .= "    Deny from all\n";
            $c .= "    <IfModule mod_authz_core.c>\n";
            $c .= "        Require all denied\n";
            $c .= "    </IfModule>\n";
            $c .= "</Files>\n\n";
        }

        // RewriteEngine Rules for Exploits, Bots, and Recon
        $c .= "<IfModule mod_rewrite.c>\n";
        $c .= "    RewriteEngine On\n";
        $c .= "    RewriteBase /\n\n";

        // Block PHP in Uploads
        if (!empty($opts['block_uploads_php'])) {
            $c .= "    # Block direct PHP script execution in uploads\n";
            $c .= "    RewriteRule ^wp-content/uploads/.*\\.(php|phtml|phar|sh|pl|py|exe)$ - [F,L,NC]\n\n";
        }

        // Block Author Scans
        if (!empty($opts['block_author_scans'])) {
            $c .= "    # Block username enumeration (?author=N)\n";
            $c .= "    RewriteCond %{QUERY_STRING} ^author=\\d+ [NC]\n";
            $c .= "    RewriteRule .* - [F,L]\n\n";
        }

        // Block Exploit Query Strings
        if (!empty($opts['block_exploit_queries'])) {
            $c .= "    # Block LFI/RFI Directory Traversal and code injection\n";
            $c .= "    RewriteCond %{QUERY_STRING} (\\.\\./|\\.\\.%2f|base64_decode|eval\\(|<script|GLOBALS|_REQUEST) [NC]\n";
            $c .= "    RewriteRule .* - [F,L]\n\n";
        }

        // Block Bad Bots
        if (!empty($opts['block_bad_bots'])) {
            $c .= "    # Block aggressive vulnerability scanners & hostile user-agents\n";
            $c .= "    RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto|wpscan|dirbuster|gobuster|masscan|zgrab|acunetix|nmap|havij) [NC]\n";
            $c .= "    RewriteRule .* - [F,L]\n\n";
        }

        $c .= "</IfModule>\n\n";

        // Security Headers
        $c .= "<IfModule mod_headers.c>\n";
        $c .= "    # Hardened HTTP Response Security Headers\n";
        if (!empty($opts['header_x_frame_options'])) {
            $c .= "    Header always set X-Frame-Options \"SAMEORIGIN\"\n";
        }
        if (!empty($opts['header_x_content_type'])) {
            $c .= "    Header always set X-Content-Type-Options \"nosniff\"\n";
        }
        if (!empty($opts['header_referrer_policy'])) {
            $c .= "    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n";
        }
        if (!empty($opts['header_permissions'])) {
            $c .= "    Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n";
        }
        if (!empty($opts['header_hsts'])) {
            $c .= "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n";
        }
        $c .= "</IfModule>\n";

        return $c;
    }

    /**
     * Save generated config file to disk
     */
    public static function save_config_file(string $server_type, array $options): array {
        $saved_opts = self::save_options($options);
        $file_info = self::get_file_info();

        global $wp_filesystem;
        if ($server_type === 'nginx') {
            $content = self::generate_nginx_config($saved_opts);
            $target_file = $file_info['nginx_path'];
            $written = @file_put_contents($target_file, $content);
            if ($written === false) {
                return [
                    'success' => false,
                    'message' => sprintf(
                        /* translators: %s: target file path */
                        __('Unable to write to %s. Please verify directory permissions.', 'wcp-security-scanner'),
                        $target_file
                    ),
                ];
            }
            if ($wp_filesystem) {
                $wp_filesystem->chmod($target_file, 0644);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                @chmod($target_file, 0644);
            }
            return [
                'success'      => true,
                'message'      => __('Nginx security configuration file generated and saved successfully.', 'wcp-security-scanner'),
                'file_path'    => $target_file,
                'include_code' => 'include ' . $target_file . ';',
                'options'      => $saved_opts,
                'content'      => $content,
            ];
        } elseif ($server_type === 'caddy') {
            $content = self::generate_caddy_config($saved_opts);
            $target_file = $file_info['caddy_path'];
            $written = @file_put_contents($target_file, $content);
            if ($written === false) {
                return [
                    'success' => false,
                    'message' => sprintf(
                        /* translators: %s: target file path */
                        __('Unable to write to %s. Please verify directory permissions.', 'wcp-security-scanner'),
                        $target_file
                    ),
                ];
            }
            if ($wp_filesystem) {
                $wp_filesystem->chmod($target_file, 0644);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                @chmod($target_file, 0644);
            }
            return [
                'success'      => true,
                'message'      => __('Caddy v2 security rules saved successfully.', 'wcp-security-scanner'),
                'file_path'    => $target_file,
                'include_code' => 'import ' . $target_file,
                'options'      => $saved_opts,
                'content'      => $content,
            ];
        } else {
            // Apache / LiteSpeed
            $content = self::generate_apache_config($saved_opts);
            $target_file = $file_info['apache_path'];
            $written = @file_put_contents($target_file, $content);
            if ($written === false) {
                return [
                    'success' => false,
                    'message' => sprintf(
                        /* translators: %s: target file path */
                        __('Unable to write to %s. Please verify directory permissions.', 'wcp-security-scanner'),
                        $target_file
                    ),
                ];
            }
            if ($wp_filesystem) {
                $wp_filesystem->chmod($target_file, 0644);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                @chmod($target_file, 0644);
            }
            return [
                'success'   => true,
                'message'   => __('Apache/LiteSpeed security rules saved successfully.', 'wcp-security-scanner'),
                'file_path' => $target_file,
                'options'   => $saved_opts,
                'content'   => $content,
            ];
        }
    }

    /**
     * Deploy rules directly into root .htaccess for Apache / LiteSpeed
     */
    public static function deploy_to_htaccess(array $options): array {
        $saved_opts = self::save_options($options);
        $rules = self::generate_apache_config($saved_opts);
        $htaccess_path = ABSPATH . '.htaccess';

        $marker = 'WCP_SECURITY_SCANNER_SERVER_RULES';
        $marker_start = "# BEGIN {$marker}";
        $marker_end = "# END {$marker}";

        $current = file_exists($htaccess_path) ? (string) @file_get_contents($htaccess_path) : '';

        // Backup existing .htaccess first
        if (!empty($current)) {
            $backup_path = self::get_storage_dir() . '/.htaccess.backup-' . gmdate('Ymd-His');
            @file_put_contents($backup_path, $current);
        }

        $wrapped = "{$marker_start}\n" . trim($rules) . "\n{$marker_end}\n";

        if (strpos($current, $marker_start) !== false && strpos($current, $marker_end) !== false) {
            $pattern = '/' . preg_quote($marker_start, '/') . '.*?' . preg_quote($marker_end, '/') . '/s';
            $updated = preg_replace($pattern, trim($wrapped), $current);
        } else {
            $updated = trim($wrapped) . "\n\n" . $current;
        }

        // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Direct writing of server rules to root .htaccess
        $written = @file_put_contents($htaccess_path, $updated);
        if ($written === false) {
            return [
                'success' => false,
                'message' => __('Unable to write to root .htaccess. Please verify write permissions.', 'wcp-security-scanner'),
            ];
        }

        return [
            'success'   => true,
            'message'   => __('Server security rules deployed directly into root .htaccess successfully.', 'wcp-security-scanner'),
            'file_path' => $htaccess_path,
        ];
    }

    /**
     * Generate complete Caddy v2 Security Configuration snippet.
     *
     * @param array $opts
     * @return string
     */
    public static function generate_caddy_config(array $opts): string {
        $now = gmdate('Y-m-d H:i:s \U\T\C');
        $site_url = get_site_url();

        $c = "# =========================================================================\n";
        $c .= "# WebCare Pro - High Performance Caddy v2 Security Snippet\n";
        $c .= "# Site: {$site_url}\n";
        $c .= "# Generated: {$now}\n";
        $c .= "# Import into your Caddyfile: import " . self::get_file_info()['caddy_path'] . "\n";
        $c .= "# =========================================================================\n\n";

        $c .= "(wcp_security_rules) {\n";

        if (!empty($opts['block_uploads_php'])) {
            $c .= "    # Deny direct PHP execution in media uploads directory\n";
            $c .= "    @wcp_uploads_php path /wp-content/uploads/*.php /wp-content/uploads/*.phtml\n";
            $c .= "    respond @wcp_uploads_php 403\n\n";
        }

        if (!empty($opts['block_sensitive_files'])) {
            $c .= "    # Block access to hidden dotfiles, git repositories, and env files\n";
            $c .= "    @wcp_sensitive_files path /.git* /.env* /.user.ini /wp-config.php*\n";
            $c .= "    respond @wcp_sensitive_files 403\n\n";
        }

        if (!empty($opts['block_xmlrpc'])) {
            $c .= "    # Disable XML-RPC endpoint to prevent brute-force amplification\n";
            $c .= "    @wcp_xmlrpc path /xmlrpc.php\n";
            $c .= "    respond @wcp_xmlrpc 403\n\n";
        }

        if (!empty($opts['block_author_scans'])) {
            $c .= "    # Block author enumeration query strings\n";
            $c .= "    @wcp_author {\n";
            $c .= "        query author=*\n";
            $c .= "    }\n";
            $c .= "    respond @wcp_author 403\n\n";
        }

        // HTTP Security Headers
        $c .= "    # Security Headers\n";
        $c .= "    header {\n";
        if (!empty($opts['header_x_frame_options'])) {
            $c .= "        X-Frame-Options \"SAMEORIGIN\"\n";
        }
        if (!empty($opts['header_x_content_type'])) {
            $c .= "        X-Content-Type-Options \"nosniff\"\n";
        }
        if (!empty($opts['header_referrer_policy'])) {
            $c .= "        Referrer-Policy \"strict-origin-when-cross-origin\"\n";
        }
        if (!empty($opts['header_permissions'])) {
            $c .= "        Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n";
        }
        if (!empty($opts['header_hsts'])) {
            $c .= "        Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n";
        }
        $c .= "    }\n";
        $c .= "}\n";

        return $c;
    }

    /**
     * Safe loopback probe tester to verify whether server security rules are actively enforced.
     *
     * @return array
     */
    public static function verify_rule_enforcement(): array {
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';

        // Probe 1: Uploads Executable Probe
        $probe_url = home_url('/wp-content/uploads/wcp_server_enforcement_test.php');
        $args = [
            'timeout'     => 8,
            'redirection' => 0,
            'sslverify'   => false,
            'user-agent'  => 'WCP-Server-Verifier/1.0',
        ];

        $uploads_res = wp_remote_get($probe_url, $args);
        $uploads_code = !is_wp_error($uploads_res) ? (int) wp_remote_retrieve_response_code($uploads_res) : 0;
        $uploads_blocked = in_array($uploads_code, [400, 403, 404, 410], true);

        // Probe 2: Sensitive Dotfile (.env) Probe
        $env_url = home_url('/.env');
        $env_res = wp_remote_get($env_url, $args);
        $env_code = !is_wp_error($env_res) ? (int) wp_remote_retrieve_response_code($env_res) : 0;
        $env_blocked = in_array($env_code, [400, 403, 404, 410], true);

        $is_enforced = ($uploads_blocked && $env_blocked);

        return [
            'success'            => true,
            'server_software'    => $server_software,
            'uploads_code'       => $uploads_code,
            'uploads_blocked'    => $uploads_blocked,
            'env_code'           => $env_code,
            'env_blocked'        => $env_blocked,
            'active_enforcement' => $is_enforced,
            'message'            => $is_enforced
                ? __('Web server security rules are actively enforced at the perimeter (HTTP 403/404 responses confirmed).', 'wcp-security-scanner')
                : __('Perimeter enforcement test inconclusive. Ensure the generated server config has been included in your Nginx, Apache, or Caddy configuration.', 'wcp-security-scanner'),
        ];
    }
}
