<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class ConfigScanner {

    /**
     * Audit wp-config.php, .htaccess, and .user.ini for malware directives and security weaknesses.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];

        // 1. Audit wp-config.php
        $wp_config_path = ABSPATH . 'wp-config.php';
        if (!file_exists($wp_config_path) && file_exists(dirname(ABSPATH) . '/wp-config.php')) {
            $wp_config_path = dirname(ABSPATH) . '/wp-config.php';
        }

        if (file_exists($wp_config_path)) {
            $config_content = @file_get_contents($wp_config_path);
            if ($config_content) {
                // Check for auto_prepend_file or auto_append_file
                if (preg_match('/(auto_prepend_file|auto_append_file|allow_url_include)/i', $config_content, $matches)) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-config',
                        'type'        => 'suspicious_config_directive',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => $wp_config_path,
                        'description' => "Suspicious PHP directive '{$matches[1]}' found in wp-config.php. Often used for stealth backdoor persistence.",
                        'evidence'    => "Matched directive: {$matches[1]}"
                    ]);
                }

                // Check for debug mode enabled in production
                if (preg_match('/define\s*\(\s*[\'"]WP_DEBUG[\'"]\s*,\s*true\s*\)/i', $config_content)) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-config',
                        'type'        => 'wp_debug_enabled',
                        'severity'    => 'low',
                        'confidence'  => 100,
                        'file_path'   => $wp_config_path,
                        'description' => 'WP_DEBUG is enabled. Detailed errors, stack traces, and database credentials may be exposed to visitors.',
                        'evidence'    => 'WP_DEBUG = true'
                    ]);
                }
            }
        }

        // 2. Audit .htaccess
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path)) {
            $htaccess_content = @file_get_contents($htaccess_path);
            if ($htaccess_content) {
                // Cloaking: Checking for Googlebot/crawler user agent + redirecting
                if (preg_match('/RewriteCond\s+%{HTTP_USER_AGENT}\s+.*(googlebot|bingbot|yahoo|baidu|slurp)/i', $htaccess_content) &&
                    preg_match('/RewriteRule\s+.*https?:\/\//i', $htaccess_content)) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-config',
                        'type'        => 'htaccess_search_engine_cloaking',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => $htaccess_path,
                        'description' => 'Search engine user-agent cloaking redirect detected in .htaccess. Delivers separate content or redirects search engines to spam.',
                        'evidence'    => 'RewriteCond user-agent crawler rule with external RewriteRule redirect.'
                    ]);
                }

                // Check for malicious PHP handlers or auto_prepend in .htaccess
                if (preg_match('/(php_value\s+auto_prepend_file|php_value\s+auto_append_file|SetHandler\s+application\/x-httpd-php)/i', $htaccess_content, $matches)) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-config',
                        'type'        => 'htaccess_malicious_handler',
                        'severity'    => 'critical',
                        'confidence'  => 98,
                        'file_path'   => $htaccess_path,
                        'description' => "Malicious PHP handler/prepend directive found in .htaccess: '{$matches[0]}'.",
                        'evidence'    => "Matched line: {$matches[0]}"
                    ]);
                }
            }
        }

        // 3. Audit .user.ini and php.ini
        $ini_files = [ABSPATH . '.user.ini', ABSPATH . 'php.ini'];
        foreach ($ini_files as $ini_file) {
            if (file_exists($ini_file)) {
                $ini_content = @file_get_contents($ini_file);
                if ($ini_content && preg_match('/(auto_prepend_file|auto_append_file|allow_url_include)\s*=/i', $ini_content, $matches)) {
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-config',
                        'type'        => 'ini_auto_prepend_injection',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => $ini_file,
                        'description' => "Backdoor persistence directive '{$matches[1]}' found in INI configuration.",
                        'evidence'    => "Matched directive: {$matches[1]}"
                    ]);
                }
            }
        }

        return $findings;
    }
}
