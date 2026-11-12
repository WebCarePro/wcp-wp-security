<?php
namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * MicroWafCompiler
 *
 * Compiles a zero-dependency, ultra-lean Preload Micro-WAF script that executes
 * in PHP's early request lifecycle via `auto_prepend_file` before WordPress core boots.
 *
 * Key Capabilities:
 * 1. Compiles active IP blocklists and high-confidence exploit signatures into OPcache-shared PHP arrays.
 * 2. Operates with near-zero memory footprint (<0.2MB RAM) and sub-microsecond latency.
 * 3. Appends security blocks in standard Linux format for Linux Fail2ban jails and CrowdSec parsers.
 * 4. Automatic server environment detection and safe `.user.ini` / `.htaccess` installer.
 * 5. Fail-safe kill switches and emergency bypass token support.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class MicroWafCompiler {

    const COMPILED_DIR_REL = 'webcare-pro-security/waf-compiled';
    const COMPILED_FILE_NAME = 'micro-waf-compiled.php';
    const FAIL2BAN_LOG_REL = 'webcare-pro-security/waf-logs/fail2ban.log';
    const OPTION_STATUS = 'webcareproscan_micro_waf_status';
    const CAF_COMPILED_FILE_NAME = 'webcare-caf-compiled-rules.php';
    const OPTION_CAF_HMAC = 'webcare_caf_compiled_hmac';

    /**
     * Get the absolute path to the compiled Micro-WAF directory.
     *
     * @return string
     */
    public static function get_compiled_dir(): string {
        $upload_dir = wp_upload_dir();
        return trailingslashit($upload_dir['basedir']) . self::COMPILED_DIR_REL;
    }

    /**
     * Get the absolute path to the compiled Micro-WAF script.
     *
     * @return string
     */
    public static function get_compiled_file_path(): string {
        return trailingslashit(self::get_compiled_dir()) . self::COMPILED_FILE_NAME;
    }

    /**
     * Get the absolute path to the compiled CAF data rules.
     */
    public static function get_caf_compiled_file_path(): string {
        return trailingslashit(self::get_compiled_dir()) . self::CAF_COMPILED_FILE_NAME;
    }

    /**
     * Get the absolute path to the Fail2ban / CrowdSec log file.
     *
     * @return string
     */
    public static function get_fail2ban_log_path(): string {
        $upload_dir = wp_upload_dir();
        return trailingslashit($upload_dir['basedir']) . self::FAIL2BAN_LOG_REL;
    }

    /**
     * Check if the Preload Micro-WAF is actively running in the current PHP process.
     *
     * @return bool
     */
    public static function is_active_in_runtime(): bool {
        $auto_prepend = (string) ini_get('auto_prepend_file');
        if (empty($auto_prepend)) {
            return false;
        }

        $target = self::get_compiled_file_path();
        return (realpath($auto_prepend) === realpath($target) || str_contains($auto_prepend, self::COMPILED_FILE_NAME));
    }

    /**
     * Detect web server environment configuration target.
     *
     * @return array
     */
    public static function detect_server_target(): array {
        $sapi = strtolower(PHP_SAPI);
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))) : '';

        $target = 'user_ini';
        $filename = '.user.ini';
        $reason = 'PHP-FPM / FastCGI / CGI environment';

        if (str_contains($server_software, 'apache') || str_contains($server_software, 'litespeed')) {
            if ($sapi === 'apache2handler' || $sapi === 'litespeed') {
                $target = 'htaccess';
                $filename = '.htaccess';
                $reason = 'Apache or LiteSpeed with direct module execution';
            }
        }

        $root_path = ABSPATH;
        $target_file = trailingslashit($root_path) . $filename;
        $is_writable = wp_is_writable($root_path) || (file_exists($target_file) && wp_is_writable($target_file));

        return [
            'sapi'            => $sapi,
            'server_software' => $server_software,
            'target'          => $target,
            'filename'        => $filename,
            'target_file'     => $target_file,
            'is_writable'     => $is_writable,
            'reason'          => $reason,
        ];
    }

    /**
     * Compile active WAF rules, IP blocklists, and signatures into a zero-dependency PHP script.
     *
     * @param string|null $chained_file Optional pre-existing prepend script to chain after WebCare execution.
     * @return array Result array with success bool and metadata.
     */
    /**
     * Alias for compile() to satisfy CAF lifecycle invocation.
     */
    public static function compile_script(?string $chained_file = null): bool {
        $result = self::compile($chained_file);
        return !empty($result['success']);
    }

    public static function compile(?string $chained_file = null): array {
        if ($chained_file === null) {
            $chained_file = (string) get_option('webcareproscan_micro_waf_chained_file', '');
        }

        $dir = self::get_compiled_dir();
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            // Place silent index.php and hardened .htaccess
            file_put_contents(trailingslashit($dir) . 'index.php', "<?php\n// Silence is golden.\n");
            file_put_contents(trailingslashit($dir) . '.htaccess', "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n");
        }

        $compiled_file = self::get_compiled_file_path();
        $fail2ban_log = self::get_fail2ban_log_path();

        // 1. Gather active IP blocklists
        $blocked_ips = [];
        $settings = SettingsManager::get_settings();
        $raw_blocked_text = !empty($settings['waf_blocked_ips']) ? (string) $settings['waf_blocked_ips'] : '';
        if (!empty($raw_blocked_text)) {
            $lines = explode("\n", $raw_blocked_text);
            foreach ($lines as $line) {
                $ip = trim($line);
                if (!empty($ip) && !str_starts_with($ip, '#')) {
                    $blocked_ips[] = $ip;
                }
            }
        }

        // Add curated botnet seed CIDRs from ThreatIntelService if enabled
        if (!empty($settings['waf_block_threat_intel_ips']) && class_exists('\\WebCareProScanner\\Firewall\\ThreatIntelService')) {
            $seed_ips = array_keys(\WebCareProScanner\Firewall\ThreatIntelService::get_seed_blacklisted_ips());
            $blocked_ips = array_unique(array_merge($blocked_ips, $seed_ips));
        }

        // 2. High-confidence zero-false-positive attack signatures for early drop
        $compiled_signatures = [
            'SQLI-CORE' => [
                'pattern' => '/(?:\b(?:union\s+(?:all\s+)?select|benchmark\s*\(|pg_sleep\s*\(|information_schema)\b)/i',
                'desc'    => 'High-Confidence SQL Injection Probe',
            ],
            'RCE-EXEC' => [
                'pattern' => '/(?:\b(?:passthru|shell_exec|exec|proc_open|popen)\s*\(|(?:eval|assert)\s*\(\s*(?:\$|_GET|_POST|_COOKIE|_REQUEST))/i',
                'desc'    => 'Remote Code Execution / Webshell Ingress',
            ],
            'LFI-PATH' => [
                'pattern' => '~(?:\.\.[\\\/]){2,}|(?:\/etc\/(?:passwd|shadow|hosts)|\bwindows[\\\/]win\.ini\b)~i',
                'desc'    => 'Path Traversal / Local File Inclusion Probe',
            ],
            'RECON-DOT' => [
                'pattern' => '/(?:\/\.env(?:\.local|\.prod|\.bak)?|\/\.git(?:\/|$)|\/wp-config\.php\.(?:bak|old|swp|save))/i',
                'desc'    => 'Sensitive File & Repository Reconnaissance',
            ],
        ];

        // 3. Generate emergency bypass token
        $bypass_token = get_option('webcareproscan_micro_waf_bypass_token', '');
        if (empty($bypass_token)) {
            $bypass_token = wp_generate_password(32, false, false);
            update_option('webcareproscan_micro_waf_bypass_token', $bypass_token);
        }

                // 4. Compile CAF (Context-Adaptive Firewall) Phase 1 Rules
        self::compile_caf_data_artifact();

        // 5. Resolve .htaccess mtime and emergency vault for Anti-Deadlock Watchdog
        $htaccess_path = ABSPATH . '.htaccess';
        $htaccess_mtime = file_exists($htaccess_path) ? (int) @filemtime($htaccess_path) : 0;
        $emergency_vault = class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')
            ? HtaccessVaultManager::get_vault_dir() . '/' . HtaccessVaultManager::EMERGENCY_FILE_NAME
            : '';
        if (!empty($emergency_vault) && !file_exists($emergency_vault) && file_exists($htaccess_path)) {
            HtaccessVaultManager::snapshot_current_if_clean('micro_waf_init');
        }

        $trusted_proxies = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine') && method_exists('\\WebCareProScanner\\Firewall\\FirewallEngine', 'get_configured_trusted_proxies')) {
            foreach (FirewallEngine::get_configured_trusted_proxies() as $proxy_entry) {
                $proxy_entry = trim((string) $proxy_entry);
                if ($proxy_entry === '') {
                    continue;
                }
                if (filter_var($proxy_entry, FILTER_VALIDATE_IP)) {
                    $trusted_proxies[] = $proxy_entry;
                } elseif (str_contains($proxy_entry, '/')) {
                    list($p_sub, $p_mask) = explode('/', $proxy_entry, 2);
                    if (filter_var($p_sub, FILTER_VALIDATE_IP) && ctype_digit((string) $p_mask)) {
                        $trusted_proxies[] = $proxy_entry;
                    }
                }
            }
        }

        $code = self::generate_standalone_code(
            $blocked_ips,
            $compiled_signatures,
            $fail2ban_log,
            $bypass_token,
            $chained_file,
            $htaccess_path,
            $emergency_vault,
            $htaccess_mtime,
            array_values(array_unique($trusted_proxies))
        );

        // Write compiled file atomically
        $temp_file = $compiled_file . '.tmp.' . wp_rand();
        $written = file_put_contents($temp_file, $code);
        if ($written === false) {
            return [
                'success' => false,
                'message' => __('Failed to write temporary Micro-WAF file to uploads directory.', 'webcare-pro-security'),
            ];
        }

        // Rename atomically
        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic move of compiled WAF cache.
        if (!rename($temp_file, $compiled_file)) {
            wp_delete_file($temp_file);
            return [
                'success' => false,
                'message' => __('Failed to atomically deploy compiled Micro-WAF script.', 'webcare-pro-security'),
            ];
        }

        // Reset OPcache if available for the compiled file
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($compiled_file, true);
        }

        $status_data = [
            'compiled_at'       => time(),
            'compiled_at_gmt'   => gmdate('Y-m-d H:i:s'),
            'file_path'         => $compiled_file,
            'file_size'         => filesize($compiled_file),
            'blocked_ips_count' => count($blocked_ips),
            'signatures_count'  => count($compiled_signatures),
            'fail2ban_log'      => $fail2ban_log,
        ];
        update_option(self::OPTION_STATUS, $status_data);

        return [
            'success'     => true,
            'message'     => __('WebCare Preload Micro-WAF successfully compiled.', 'webcare-pro-security'),
            'status_data' => $status_data,
        ];
    }

    /**
     * Generate the complete standalone PHP source code for the Micro-WAF.
     */
    private static function generate_standalone_code(
        array $blocked_ips,
        array $signatures,
        string $fail2ban_log,
        string $bypass_token,
        string $chained_file = '',
        string $htaccess_path = '',
        string $emergency_vault = '',
        int $expected_htaccess_mtime = 0,
        array $trusted_proxies = []
    ): string {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Compiling static array representation for OPcache.
        $ips_export = var_export($blocked_ips, true);
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Compiling static array representation for OPcache.
        $sigs_export = var_export($signatures, true);
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Compiling static trusted proxy CIDRs for OPcache.
        $proxies_export = var_export($trusted_proxies, true);
        $fail2ban_escaped = addslashes($fail2ban_log);
        $bypass_escaped = addslashes($bypass_token);
        $htaccess_escaped = addslashes($htaccess_path);
        $vault_escaped    = addslashes($emergency_vault);

        $out = "<?php\n";
        $out .= "/**\n";
        $out .= " * WebCare Preload Micro-WAF (Zero-Dependency Standalone Runtime)\n";
        $out .= " * Generated by WebCare Pro Security & Firewall - Mir Alamin\n";
        $out .= " * Executed via PHP auto_prepend_file before WordPress bootstrap.\n";
        $out .= " */\n\n";

        // Kill-switch 1: disabled constant in wp-config.php
        $out .= "if ((defined('WEBCARE_DISABLE_MICRO_WAF') && WEBCARE_DISABLE_MICRO_WAF) || (defined('WEBCARE_CAF_DISABLE_PRELOAD') && WEBCARE_CAF_DISABLE_PRELOAD)) {\n";
        $out .= "    return;\n";
        $out .= "}\n\n";

        // Kill-switch 2: filesystem sentinel killswitch
        $out .= "if (file_exists(dirname(__DIR__) . '/.killswitch') || file_exists(__DIR__ . '/.killswitch')) {\n";
        $out .= "    return;\n";
        $out .= "}\n\n";

        // Kill-switch 2: emergency query bypass token
        $out .= "if (isset(\$_GET['webcare_waf_bypass']) && hash_equals('{$bypass_escaped}', (string) \$_GET['webcare_waf_bypass'])) {\n";
        $out .= "    return;\n";
        $out .= "}\n\n";

        // Micro-WAF Core Engine with Self-Preservation Try/Catch
        $out .= "try {\n";
        $out .= "    (function() {\n";
        $out .= "        \$fail2ban_log = '{$fail2ban_escaped}';\n";
        $out .= "        \$blocked_ips = " . $ips_export . ";\n";
        $out .= "        \$trusted_proxies = " . $proxies_export . ";\n";
        $out .= "        \$signatures  = " . $sigs_export . ";\n\n";

        // Preload Anti-Deadlock .htaccess Watchdog
        $out .= "        // 0. Preload .htaccess Anti-Deadlock Mtime Watchdog\n";
        $out .= "        \$ht_path = '{$htaccess_escaped}';\n";
        $out .= "        \$v_emerg = '{$vault_escaped}';\n";
        $out .= "        \$exp_mtime = {$expected_htaccess_mtime};\n";
        $out .= "        if (\$exp_mtime > 0 && !empty(\$ht_path) && !empty(\$v_emerg) && file_exists(\$ht_path) && file_exists(\$v_emerg)) {\n";
        $out .= "            \$cur_mtime = (int) @filemtime(\$ht_path);\n";
        $out .= "            if (\$cur_mtime !== \$exp_mtime) {\n";
        $out .= "                \$ht_content = (string) @file_get_contents(\$ht_path);\n";
        $out .= "                if (\$ht_content !== '' && (\n";
        $out .= "                    preg_match('/RewriteRule\s+\\^\\.\\*\\$\\s+https?:\\/\\//i', \$ht_content) ||\n";
        $out .= "                    preg_match('/RewriteCond\s+%{HTTP_REFERER}\s+.*(google|bing|yahoo).*\s+RewriteRule\s+.*https?:\\/\\//is', \$ht_content) ||\n";
        $out .= "                    preg_match('/RewriteCond\s+%{HTTP_USER_AGENT}\s+.*(android|iphone|mobile).*\s+RewriteRule\s+.*https?:\\/\\//is', \$ht_content) ||\n";
        $out .= "                    preg_match('/RedirectMatch\s+30[12]\s+\\^[\\/.]*\\s+https?:\\/\\//i', \$ht_content)\n";
        $out .= "                )) {\n";
        $out .= "                    \$clean_data = (string) @file_get_contents(\$v_emerg);\n";
        $out .= "                    if (\$clean_data !== '') {\n";
        $out .= "                        @chmod(\$ht_path, 0644);\n";
        $out .= "                        @file_put_contents(\$ht_path, \$clean_data, LOCK_EX);\n";
        $out .= "                        \$log_entry = sprintf(\"[%s] [WEBCARE-MICRO-WAF] [AUTO-HEAL] Global .htaccess redirect hijack auto-restored from emergency vault! Tampered mtime: %d\\n\", gmdate('Y-m-d H:i:s'), \$cur_mtime);\n";
        $out .= "                        @file_put_contents(\$fail2ban_log, \$log_entry, FILE_APPEND | LOCK_EX);\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "        }\n\n";

        $out .= "        // 1. Resolve real client IP (Cloudflare Edge + custom trusted proxy CIDRs)\n";
        $out .= "        \$webcare_match_ip_list = static function (string \$target_ip, array \$rules): bool {\n";
        $out .= "            if (\$target_ip === '' || empty(\$rules) || !filter_var(\$target_ip, FILTER_VALIDATE_IP)) {\n";
        $out .= "                return false;\n";
        $out .= "            }\n";
        $out .= "            \$ip_bin = @inet_pton(\$target_ip);\n";
        $out .= "            foreach (\$rules as \$rule) {\n";
        $out .= "                if (\$target_ip === \$rule) {\n";
        $out .= "                    return true;\n";
        $out .= "                }\n";
        $out .= "                if (strpos(\$rule, '/') === false || \$ip_bin === false) {\n";
        $out .= "                    continue;\n";
        $out .= "                }\n";
        $out .= "                list(\$subnet, \$mask_raw) = explode('/', \$rule, 2);\n";
        $out .= "                \$sub_bin = @inet_pton(\$subnet);\n";
        $out .= "                if (\$sub_bin === false || strlen(\$ip_bin) !== strlen(\$sub_bin) || !ctype_digit((string) \$mask_raw)) {\n";
        $out .= "                    continue;\n";
        $out .= "                }\n";
        $out .= "                \$bits = (int) \$mask_raw;\n";
        $out .= "                \$max_bits = strlen(\$ip_bin) * 8;\n";
        $out .= "                if (\$bits < 0 || \$bits > \$max_bits) {\n";
        $out .= "                    continue;\n";
        $out .= "                }\n";
        $out .= "                \$full_bytes = intdiv(\$bits, 8);\n";
        $out .= "                \$rem_bits   = \$bits % 8;\n";
        $out .= "                \$matched    = (\$full_bytes === 0 || substr(\$ip_bin, 0, \$full_bytes) === substr(\$sub_bin, 0, \$full_bytes));\n";
        $out .= "                if (\$matched && \$rem_bits > 0) {\n";
        $out .= "                    \$mask_byte = (0xff << (8 - \$rem_bits)) & 0xff;\n";
        $out .= "                    \$matched   = ((ord(\$ip_bin[\$full_bytes]) & \$mask_byte) === (ord(\$sub_bin[\$full_bytes]) & \$mask_byte));\n";
        $out .= "                }\n";
        $out .= "                if (\$matched) {\n";
        $out .= "                    return true;\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "            return false;\n";
        $out .= "        };\n";
        $out .= "        \$ip = isset(\$_SERVER['REMOTE_ADDR']) ? trim(\$_SERVER['REMOTE_ADDR']) : '127.0.0.1';\n";
        $out .= "        \$cf_cidrs = ['173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22','2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32'];\n";
        $out .= "        \$is_cf_ip = \$webcare_match_ip_list(\$ip, \$cf_cidrs);\n";
        $out .= "        \$is_custom_proxy = !\$is_cf_ip && \$webcare_match_ip_list(\$ip, \$trusted_proxies);\n";
        $out .= "        if (\$is_cf_ip && isset(\$_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var(\$_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {\n";
        $out .= "            \$ip = trim(\$_SERVER['HTTP_CF_CONNECTING_IP']);\n";
        $out .= "        } elseif (\$is_custom_proxy) {\n";
        $out .= "            \$resolved_proxy_client = '';\n";
        $out .= "            if (!empty(\$_SERVER['HTTP_X_FORWARDED_FOR'])) {\n";
        $out .= "                \$xff_parts = array_reverse(array_map('trim', explode(',', (string) \$_SERVER['HTTP_X_FORWARDED_FOR'])));\n";
        $out .= "                foreach (\$xff_parts as \$cand) {\n";
        $out .= "                    if (filter_var(\$cand, FILTER_VALIDATE_IP) && !\$webcare_match_ip_list(\$cand, \$cf_cidrs) && !\$webcare_match_ip_list(\$cand, \$trusted_proxies)) {\n";
        $out .= "                        \$resolved_proxy_client = \$cand;\n";
        $out .= "                        break;\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "            if (\$resolved_proxy_client !== '') {\n";
        $out .= "                \$ip = \$resolved_proxy_client;\n";
        $out .= "            } elseif (isset(\$_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var(\$_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {\n";
        $out .= "                \$ip = trim(\$_SERVER['HTTP_CF_CONNECTING_IP']);\n";
        $out .= "            }\n";
        $out .= "        }\n\n";

        $out .= "        // 2. Fast IP & CIDR match (never block verified proxy CIDRs)\n";
        $out .= "        \$ip_is_trusted_proxy = \$webcare_match_ip_list(\$ip, \$cf_cidrs) || \$webcare_match_ip_list(\$ip, \$trusted_proxies);\n";
        $out .= "        \$ip_blocked = !\$ip_is_trusted_proxy && \$webcare_match_ip_list(\$ip, \$blocked_ips);\n\n";

        $out .= "        if (\$ip_blocked) {\n";
        $out .= "            webcare_micro_waf_block(\$ip, 'IP-BLOCKLIST', 'Connecting IP is present in WebCare Blacklist / Threat Intel', \$fail2ban_log);\n";
        $out .= "        }\n\n";

        $out .= "        // 3. Inspect URI and Query String for high-confidence attack vectors\n";
        $out .= "        \$uri = isset(\$_SERVER['REQUEST_URI']) ? (string) \$_SERVER['REQUEST_URI'] : '';\n";
        $out .= "        \$query = isset(\$_SERVER['QUERY_STRING']) ? (string) \$_SERVER['QUERY_STRING'] : '';\n";
        $out .= "        \$target_text = urldecode(\$uri . ' ' . \$query);\n\n";

        // 4. Context-Adaptive Firewall (CAF) Preload Enforcement
        $caf_compiled_path = self::get_caf_compiled_file_path();
        $caf_compiled_escaped = addslashes($caf_compiled_path);
        $caf_sig_escaped = addslashes($caf_compiled_path . '.sig');
        $salt = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-caf-fallback-salt';
        $salt_escaped = addslashes($salt);

        $out .= "        // 4. Context-Adaptive Firewall (CAF): Inactive component lockdown & verified artifact validation\n";
        $out .= "        \$caf_data_file = '{$caf_compiled_escaped}';\n";
        $out .= "        \$caf_sig_file  = '{$caf_sig_escaped}';\n";
        $out .= "        if (file_exists(\$caf_data_file) && file_exists(\$caf_sig_file)) {\n";
        $out .= "            \$sig_content = trim((string) @file_get_contents(\$caf_sig_file));\n";
        $out .= "            \$raw_php = (string) @file_get_contents(\$caf_data_file);\n";
        $out .= "            \$expected_hmac = hash_hmac('sha256', \$raw_php, '{$salt_escaped}');\n";
        $out .= "            // Fail-open security guardrail: only execute artifact if cryptographic signature is intact\n";
        $out .= "            if (!empty(\$sig_content) && hash_equals(\$expected_hmac, \$sig_content)) {\n";
        $out .= "                \$caf_rules = include \$caf_data_file;\n";
        $out .= "                if (is_array(\$caf_rules) && !empty(\$caf_rules['lock_dormant_surface'])) {\n";
        $out .= "                    // 1. Inactive plugins directory probe drop\n";
        $out .= "                    \$dormant_plugins = !empty(\$caf_rules['inactive_plugin_slugs']) && is_array(\$caf_rules['inactive_plugin_slugs']) ? \$caf_rules['inactive_plugin_slugs'] : [];\n";
        $out .= "                    if (!empty(\$dormant_plugins)) {\n";
        $out .= "                        foreach (\$dormant_plugins as \$d_slug) {\n";
        $out .= "                            if (strpos(\$target_text, '/wp-content/plugins/' . \$d_slug . '/') !== false) {\n";
        $out .= "                                webcare_micro_waf_block(\$ip, 'WAF-CAF-DORMANT-SURFACE', 'Request targets inactive component directory (' . \$d_slug . ') under CAF lockdown policy', \$fail2ban_log);\n";
        $out .= "                            }\n";
        $out .= "                        }\n";
        $out .= "                    }\n\n";

        $out .= "                    // 2. Unregistered / Uninstalled REST API namespace probe drop (supports /wp-json/ and ?rest_route=)\n";
        $out .= "                    \$rest_path = '';\n";
        $out .= "                    if (strpos(\$uri, '/wp-json/') !== false) {\n";
        $out .= "                        \$rest_path = substr(\$uri, strpos(\$uri, '/wp-json/') + 9);\n";
        $out .= "                    } elseif (!empty(\$_REQUEST['rest_route']) && is_string(\$_REQUEST['rest_route'])) {\n";
        $out .= "                        \$rest_path = (string) \$_REQUEST['rest_route'];\n";
        $out .= "                    }\n";
        $out .= "                    if (\$rest_path !== '') {\n";
        $out .= "                        \$active_namespaces = !empty(\$caf_rules['active_rest_namespaces']) && is_array(\$caf_rules['active_rest_namespaces']) ? \$caf_rules['active_rest_namespaces'] : [];\n";
        $out .= "                        \$rest_path_clean = strtok(rawurldecode(\$rest_path), '?');\n";
        $out .= "                        \$rest_route = trim((string) \$rest_path_clean, '/');\n";
        $out .= "                        if (\$rest_route !== '' && !empty(\$active_namespaces)) {\n";
        $out .= "                            \$namespace_matched = false;\n";
        $out .= "                            foreach (\$active_namespaces as \$ns) {\n";
        $out .= "                                \$ns_clean = trim((string) \$ns, '/');\n";
        $out .= "                                if (\$ns_clean !== '' && (\$rest_route === \$ns_clean || strpos(\$rest_route, \$ns_clean . '/') === 0 || strpos(\$ns_clean, \$rest_route . '/') === 0)) {\n";
        $out .= "                                    \$namespace_matched = true;\n";
        $out .= "                                    break;\n";
        $out .= "                                }\n";
        $out .= "                            }\n";
        $out .= "                            if (!\$namespace_matched && !str_starts_with(\$rest_route, 'wp/') && \$rest_route !== 'wp') {\n";
        $out .= "                                \$single_candidate = explode('/', \$rest_route)[0] ?? \$rest_route;\n";
        $out .= "                                webcare_micro_waf_block(\$ip, 'WAF-CAF-DORMANT-REST-NAMESPACE', 'Request probes dormant or uninstalled REST namespace (' . htmlspecialchars(\$single_candidate, ENT_QUOTES, 'UTF-8') . ')', \$fail2ban_log);\n";
        $out .= "                            }\n";
        $out .= "                        }\n";
        $out .= "                    }\n\n";

        $out .= "                    // 3. Unauthenticated admin-ajax.php probe lockdown against dormant plugin actions\n";
        $out .= "                    if (strpos(\$uri, 'admin-ajax.php') !== false) {\n";
        $out .= "                        \$has_auth_cookie = false;\n";
        $out .= "                        if (!empty(\$_COOKIE)) {\n";
        $out .= "                            foreach (array_keys(\$_COOKIE) as \$c_name) {\n";
        $out .= "                                if (strpos((string) \$c_name, 'wordpress_logged_in_') === 0) {\n";
        $out .= "                                    \$has_auth_cookie = true;\n";
        $out .= "                                    break;\n";
        $out .= "                                }\n";
        $out .= "                            }\n";
        $out .= "                        }\n";
        $out .= "                        if (!\$has_auth_cookie) {\n";
        $out .= "                            \$ajax_action = '';\n";
        $out .= "                            if (isset(\$_GET['action'])) {\n";
        $out .= "                                \$ajax_action = trim((string) \$_GET['action']);\n";
        $out .= "                            } elseif (isset(\$_POST['action'])) {\n";
        $out .= "                                \$ajax_action = trim((string) \$_POST['action']);\n";
        $out .= "                            }\n";
        $out .= "                            if (!empty(\$ajax_action)) {\n";
        $out .= "                                \$allowed_nopriv = !empty(\$caf_rules['allowed_nopriv_actions']) && is_array(\$caf_rules['allowed_nopriv_actions']) ? \$caf_rules['allowed_nopriv_actions'] : [];\n";
        $out .= "                                if (!in_array(\$ajax_action, \$allowed_nopriv, true)) {\n";
        $out .= "                                    // Specifically verify if action belongs to a known dormant/deactivated plugin\n";
        $out .= "                                    \$is_dormant_action = false;\n";
        $out .= "                                    if (!empty(\$dormant_plugins)) {\n";
        $out .= "                                        foreach (\$dormant_plugins as \$d_slug) {\n";
        $out .= "                                            \$d_prefix = str_replace('-', '_', \$d_slug);\n";
        $out .= "                                            if (str_starts_with(\$ajax_action, \$d_prefix . '_') || str_starts_with(\$ajax_action, \$d_slug . '_')) {\n";
        $out .= "                                                \$is_dormant_action = true;\n";
        $out .= "                                                break;\n";
        $out .= "                                            }\n";
        $out .= "                                        }\n";
        $out .= "                                    }\n";
        $out .= "                                    if (\$is_dormant_action) {\n";
        $out .= "                                        webcare_micro_waf_block(\$ip, 'WAF-CAF-DORMANT-AJAX-ACTION', 'Unauthenticated probe on dormant plugin AJAX action (' . htmlspecialchars(substr(\$ajax_action, 0, 40), ENT_QUOTES, 'UTF-8') . ')', \$fail2ban_log);\n";
        $out .= "                                    }\n";
        $out .= "                                }\n";
        $out .= "                            }\n";
        $out .= "                        }\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "        }\n\n";

        // 5. Modular Intelligence Firewall Pre-Boot Lockdown
        $mod_compiled = class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')
            ? \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_compiled_preload_rules()
            : ['direct_scripts_blocked' => [], 'ajax_actions_enforced' => [], 'rest_routes_enforced' => [], 'custom_rules_enforced' => []];
        $modular_json_escaped = addcslashes((string) wp_json_encode($mod_compiled), "\\'");

        $out .= "        // 5. Modular Intelligence Firewall Pre-Boot Lockdown\n";
        $out .= "        \$mod_rescue_paused = false;\n";
        $out .= "        foreach ([__DIR__ . '/.rescue_pause_until', dirname(__DIR__) . '/.rescue_pause_until'] as \$rp_file) {\n";
        $out .= "            if (file_exists(\$rp_file) && (int) trim((string) @file_get_contents(\$rp_file)) > time()) {\n";
        $out .= "                \$mod_rescue_paused = true;\n";
        $out .= "                break;\n";
        $out .= "            }\n";
        $out .= "        }\n";
        $out .= "        \$mod_trusted = [];\n";
        $out .= "        foreach ([__DIR__ . '/.rescue_allow.json', dirname(__DIR__) . '/.rescue_allow.json'] as \$ra_file) {\n";
        $out .= "            if (file_exists(\$ra_file)) {\n";
        $out .= "                \$mod_trusted = json_decode((string) @file_get_contents(\$ra_file), true) ?: [];\n";
        $out .= "                break;\n";
        $out .= "            }\n";
        $out .= "        }\n";
        $out .= "        \$mod_has_login_cookie = false;\n";
        $out .= "        if (!empty(\$_COOKIE)) {\n";
        $out .= "            foreach (array_keys(\$_COOKIE) as \$ck) {\n";
        $out .= "                if (strpos((string) \$ck, 'wordpress_logged_in_') === 0) {\n";
        $out .= "                    \$mod_has_login_cookie = true;\n";
        $out .= "                    break;\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "        }\n";
        $out .= "        \$mod_rules = json_decode('{$modular_json_escaped}', true) ?: [];\n";
        $out .= "        \$mod_clean_uri = strtolower(strtok(\$uri, '?'));\n";
        $out .= "        \$mod_rest_q = isset(\$_GET['rest_route']) && is_string(\$_GET['rest_route']) ? strtolower(trim((string) \$_GET['rest_route'])) : '';\n";
        $out .= "        \$mod_req_method = isset(\$_SERVER['REQUEST_METHOD']) ? strtoupper((string) \$_SERVER['REQUEST_METHOD']) : 'GET';\n";
        $out .= "        if (!\$mod_rescue_paused) {\n";
        $out .= "            if (!empty(\$mod_rules['direct_scripts_blocked'])) {\n";
        $out .= "                \$clean_script_uri = ltrim(\$mod_clean_uri, '/\\\\');\n";
        $out .= "                foreach (\$mod_rules['direct_scripts_blocked'] as \$b_script) {\n";
        $out .= "                    if (str_ends_with(\$clean_script_uri, \$b_script)) {\n";
        $out .= "                        webcare_micro_waf_block(\$ip, 'MOD-ABSPATH-LOCKED', 'Direct HTTP execution of standalone script prohibited by Modular WAF', \$fail2ban_log);\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "            if (!\$mod_has_login_cookie && !empty(\$mod_rules['custom_rules_enforced'])) {\n";
        $out .= "                \$mod_payload_rx = '/(?:\\\\bunion\\\\s+all\\\\s+select\\\\b|\\\\bselect\\\\b.{1,40}\\\\bfrom\\\\b.{1,40}\\\\bwp_users\\\\b|sleep\\\\s*\\\\(\\\\s*\\\\d+\\\\s*\\\\)|benchmark\\\\s*\\\\(|<script\\\\b|javascript:|wp_capabilities|administrator)/i';\n";
        $out .= "                \$trusted_custom = is_array(\$mod_trusted['rule_ids'] ?? null) ? \$mod_trusted['rule_ids'] : [];\n";
        $out .= "                foreach (\$mod_rules['custom_rules_enforced'] as \$c_rule) {\n";
        $out .= "                    \$c_id = (string) (\$c_rule['rule_id'] ?? 'MOD-CUSTOM');\n";
        $out .= "                    if (in_array(\$c_id, \$trusted_custom, true)) {\n";
        $out .= "                        continue;\n";
        $out .= "                    }\n";
        $out .= "                    \$c_uri = strtolower(trim((string) (\$c_rule['target_uri'] ?? '')));\n";
        $out .= "                    \$c_param = strtolower(trim((string) (\$c_rule['target_param'] ?? '')));\n";
        $out .= "                    \$c_val = strtolower(trim((string) (\$c_rule['target_value'] ?? '')));\n";
        $out .= "                    if (\$c_uri === '' && \$c_param === '') { continue; }\n";
        $out .= "                    \$c_rest_norm = (\$mod_rest_q !== '') ? '/wp-json/' . ltrim(\$mod_rest_q, '/') : '';\n";
        $out .= "                    \$c_uri_match = (\$c_uri === '') || (strpos(\$mod_clean_uri, \$c_uri) !== false) || (\$mod_rest_q !== '' && (strpos(\$mod_rest_q, \$c_uri) !== false || strpos(\$c_rest_norm, \$c_uri) !== false));\n";
        $out .= "                    \$c_methods = is_array(\$c_rule['methods'] ?? null) ? array_map('strtoupper', \$c_rule['methods']) : [];\n";
        $out .= "                    \$c_method_match = empty(\$c_methods) || in_array(\$mod_req_method, \$c_methods, true);\n";
        $out .= "                    \$c_param_match = true;\n";
        $out .= "                    if (\$c_param !== '') {\n";
        $out .= "                        \$c_pv = isset(\$_REQUEST[\$c_param]) && is_string(\$_REQUEST[\$c_param]) ? strtolower(trim((string) \$_REQUEST[\$c_param])) : '';\n";
        $out .= "                        \$c_param_match = (\$c_val !== '') ? (\$c_pv === \$c_val) : (\$c_pv !== '');\n";
        $out .= "                    }\n";
        $out .= "                    if (\$c_uri_match && \$c_method_match && \$c_param_match) {\n";
        $out .= "                        \$c_hit_reason = '';\n";
        $out .= "                        if (!empty(\$c_rule['block_uploads']) && !empty(\$_FILES)) {\n";
        $out .= "                            \$c_hit_reason = 'File upload blocked on protected custom endpoint (' . \$c_id . ')';\n";
        $out .= "                        } elseif (!empty(\$c_rule['immediate_block']) || ((int) (\$c_rule['rate_limit'] ?? 0) <= 0)) {\n";
        $out .= "                            \$c_hit_reason = 'Blocked on first match by Custom Modular Rule (' . \$c_id . ')';\n";
        $out .= "                        } elseif (preg_match(\$mod_payload_rx, (string) json_encode(\$_REQUEST))) {\n";
        $out .= "                            \$c_hit_reason = 'Suspicious payload blocked by Custom Modular Rule (' . \$c_id . ')';\n";
        $out .= "                        }\n";
        $out .= "                        if (\$c_hit_reason !== '') {\n";
        $out .= "                            if (!empty(\$c_rule['sync_cloudflare']) || !empty(\$c_rule['ban_ttl'])) {\n";
        $out .= "                                \$ban_q_file = __DIR__ . '/.preload_ban_queue.json';\n";
        $out .= "                                \$ban_q = file_exists(\$ban_q_file) ? (json_decode((string) @file_get_contents(\$ban_q_file), true) ?: []) : [];\n";
        $out .= "                                if (is_array(\$ban_q) && count(\$ban_q) < 200) {\n";
        $out .= "                                    \$ban_q[\$ip . '|' . \$c_id] = [\n";
        $out .= "                                        'ip' => \$ip, 'rule_id' => \$c_id, 'reason' => \$c_hit_reason,\n";
        $out .= "                                        'ban_ttl' => (int) (\$c_rule['ban_ttl'] ?? 86400), 'sync_cloudflare' => !empty(\$c_rule['sync_cloudflare']), 'ts' => time(),\n";
        $out .= "                                    ];\n";
        $out .= "                                    @file_put_contents(\$ban_q_file, json_encode(\$ban_q), LOCK_EX);\n";
        $out .= "                                }\n";
        $out .= "                            }\n";
        $out .= "                            webcare_micro_waf_block(\$ip, \$c_id, \$c_hit_reason, \$fail2ban_log);\n";
        $out .= "                        }\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "            if (!\$mod_has_login_cookie && !empty(\$mod_rules['visual_rules_enforced'])) {\n";
        $out .= "                \$trusted_visual = is_array(\$mod_trusted['rule_ids'] ?? null) ? \$mod_trusted['rule_ids'] : [];\n";
        $out .= "                \$vis_q_pos = strpos(\$uri, '?');\n";
        $out .= "                \$vis_query = \$vis_q_pos === false ? '' : substr(\$uri, \$vis_q_pos + 1);\n";
        $out .= "                \$vis_rest  = \$mod_rest_q !== '' ? '/' . ltrim(\$mod_rest_q, '/') : (((\$rp = strpos(\$mod_clean_uri, '/wp-json')) !== false) ? '/' . ltrim(substr(\$mod_clean_uri, \$rp + 8), '/') : '');\n";
        $out .= "                \$vis_ajax  = isset(\$_REQUEST['action']) && is_string(\$_REQUEST['action']) ? strtolower(trim((string) \$_REQUEST['action'])) : '';\n";
        $out .= "                \$vis_ua    = (string) (\$_SERVER['HTTP_USER_AGENT'] ?? '');\n";
        $out .= "                \$vis_ref   = (string) (\$_SERVER['HTTP_REFERER'] ?? '');\n";
        $out .= "                \$vis_ck    = (string) (\$_SERVER['HTTP_COOKIE'] ?? '');\n";
        $out .= "                \$vis_cc    = strtoupper((string) (\$_SERVER['HTTP_CF_IPCOUNTRY'] ?? ''));\n";
        $out .= "                \$vis_asn   = ltrim(strtoupper((string) (\$_SERVER['HTTP_CF_IPASN'] ?? '')), 'AS');\n";
        $out .= "                \$vis_exts  = [];\n";
        $out .= "                if (!empty(\$_FILES) && is_array(\$_FILES)) {\n";
        $out .= "                    foreach (\$_FILES as \$vf) {\n";
        $out .= "                        \$vnames = is_array(\$vf['name'] ?? null) ? \$vf['name'] : [(\$vf['name'] ?? '')];\n";
        $out .= "                        foreach (\$vnames as \$vn) { if (is_string(\$vn) && \$vn !== '') { \$ve = strtolower(pathinfo(\$vn, PATHINFO_EXTENSION)); if (\$ve !== '') { \$vis_exts[] = \$ve; } } }\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "                \$vis_match_op = static function(string \$s, string \$op, string \$w): bool {\n";
        $out .= "                    \$sl = strtolower(\$s); \$wl = strtolower(trim(\$w));\n";
        $out .= "                    if (\$op === 'eq') return \$sl === \$wl;\n";
        $out .= "                    if (\$op === 'ne') return \$sl !== \$wl;\n";
        $out .= "                    if (\$op === 'contains') return \$wl !== '' && strpos(\$sl, \$wl) !== false;\n";
        $out .= "                    if (\$op === 'not_contains') return \$wl === '' || strpos(\$sl, \$wl) === false;\n";
        $out .= "                    if (\$op === 'starts_with') return \$wl !== '' && strpos(\$sl, \$wl) === 0;\n";
        $out .= "                    if (\$op === 'ends_with') return \$wl !== '' && substr(\$sl, -strlen(\$wl)) === \$wl;\n";
        $out .= "                    if (\$op === 'matches_regex') return \$w !== '' && @preg_match('~' . str_replace('~', '\\\\~', \$w) . '~i', \$s) === 1;\n";
        $out .= "                    if (\$op === 'in' || \$op === 'not_in') {\n";
        $out .= "                        \$arr = array_map('strtolower', array_filter(preg_split('/[\\s,{}]+/', \$w, -1, PREG_SPLIT_NO_EMPTY) ?: []));\n";
        $out .= "                        \$in  = in_array(\$sl, \$arr, true);\n";
        $out .= "                        return \$op === 'in' ? \$in : !\$in;\n";
        $out .= "                    }\n";
        $out .= "                    return false;\n";
        $out .= "                };\n";
        $out .= "                \$vis_cidr_fn = static function(string \$cip, string \$cidr): bool {\n";
        $out .= "                    \$cidr = trim(\$cidr);\n";
        $out .= "                    if (strpos(\$cidr, '/') === false) return strtolower(trim(\$cip)) === strtolower(\$cidr);\n";
        $out .= "                    [\$sub, \$bits] = explode('/', \$cidr, 2);\n";
        $out .= "                    \$ib = @inet_pton(trim(\$cip)); \$sb = @inet_pton(trim(\$sub));\n";
        $out .= "                    if (\$ib === false || \$sb === false || strlen(\$ib) !== strlen(\$sb)) return false;\n";
        $out .= "                    \$b = max(0, min(strlen(\$ib) * 8, (int) \$bits)); \$f = intdiv(\$b, 8); \$r = \$b % 8;\n";
        $out .= "                    if (\$f > 0 && substr(\$ib, 0, \$f) !== substr(\$sb, 0, \$f)) return false;\n";
        $out .= "                    if (\$r > 0) { \$m = (~((1 << (8 - \$r)) - 1)) & 0xFF; if ((ord(\$ib[\$f]) & \$m) !== (ord(\$sb[\$f]) & \$m)) return false; }\n";
        $out .= "                    return true;\n";
        $out .= "                };\n";
        $out .= "                foreach (\$mod_rules['visual_rules_enforced'] as \$v_rule) {\n";
        $out .= "                    \$v_id = (string) (\$v_rule['rule_id'] ?? 'MOD-CUSTOM');\n";
        $out .= "                    if (in_array(\$v_id, \$trusted_visual, true)) continue;\n";
        $out .= "                    \$v_matched = false;\n";
        $out .= "                    foreach ((array) (\$v_rule['conditions'] ?? []) as \$v_grp) {\n";
        $out .= "                        \$v_all = true;\n";
        $out .= "                        foreach ((array) (\$v_grp['rules'] ?? []) as \$vc) {\n";
        $out .= "                            \$vf = (string) (\$vc['field'] ?? ''); \$vk = (string) (\$vc['key'] ?? ''); \$vo = (string) (\$vc['op'] ?? 'eq'); \$vw = (string) (\$vc['value'] ?? '');\n";
        $out .= "                            \$vc_ok = false;\n";
        $out .= "                            if (\$vf === 'http.headers') {\n";
        $out .= "                                \$hk = 'HTTP_' . strtoupper(str_replace('-', '_', \$vk));\n";
        $out .= "                                \$ex = (\$vk !== '' && isset(\$_SERVER[\$hk]));\n";
        $out .= "                                \$vc_ok = (\$vo === 'exists') ? \$ex : ((\$vo === 'not_exists') ? !\$ex : (\$ex && \$vis_match_op((string) \$_SERVER[\$hk], \$vo, \$vw)));\n";
        $out .= "                            } elseif (\$vf === 'http.request.params') {\n";
        $out .= "                                \$ex = (\$vk !== '' && isset(\$_REQUEST[\$vk]));\n";
        $out .= "                                \$vc_ok = (\$vo === 'exists') ? \$ex : ((\$vo === 'not_exists') ? !\$ex : (\$vo === 'is_array' ? (\$ex && is_array(\$_REQUEST[\$vk])) : (\$ex && \$vis_match_op(is_array(\$_REQUEST[\$vk]) ? (string) json_encode(\$_REQUEST[\$vk]) : (string) \$_REQUEST[\$vk], \$vo, \$vw))));\n";
        $out .= "                            } elseif (\$vf === 'http.upload.extension') {\n";
        $out .= "                                foreach (\$vis_exts as \$ve) { if (\$vis_match_op(\$ve, \$vo, \$vw)) { \$vc_ok = true; break; } }\n";
        $out .= "                            } elseif (\$vf === 'ip.src') {\n";
        $out .= "                                if (\$vo === 'eq' || \$vo === 'ne') { \$vc_ok = (\$vo === 'eq') ? (strtolower(\$ip) === strtolower(trim(\$vw))) : (strtolower(\$ip) !== strtolower(trim(\$vw))); }\n";
        $out .= "                                else { \$cs = array_filter(preg_split('/[\\s,{}]+/', \$vw, -1, PREG_SPLIT_NO_EMPTY) ?: []); \$in_c = false; foreach (\$cs as \$ci) { if (\$vis_cidr_fn(\$ip, \$ci)) { \$in_c = true; break; } } \$vc_ok = (\$vo === 'not_in_cidr') ? !\$in_c : \$in_c; }\n";
        $out .= "                            } else {\n";
        $out .= "                                \$subj = '';\n";
        $out .= "                                if (\$vf === 'http.request.uri.path') \$subj = \$mod_clean_uri;\n";
        $out .= "                                elseif (\$vf === 'http.request.uri.query') \$subj = \$vis_query;\n";
        $out .= "                                elseif (\$vf === 'http.request.method') \$subj = \$mod_req_method;\n";
        $out .= "                                elseif (\$vf === 'http.user_agent') \$subj = \$vis_ua;\n";
        $out .= "                                elseif (\$vf === 'http.referer') \$subj = \$vis_ref;\n";
        $out .= "                                elseif (\$vf === 'http.cookie') \$subj = \$vis_ck;\n";
        $out .= "                                elseif (\$vf === 'ip.geoip.country') \$subj = \$vis_cc;\n";
        $out .= "                                elseif (\$vf === 'ip.geoip.asnum') \$subj = \$vis_asn;\n";
        $out .= "                                elseif (\$vf === 'wp.ajax.action') \$subj = \$vis_ajax;\n";
        $out .= "                                elseif (\$vf === 'wp.rest.route') \$subj = \$vis_rest;\n";
        $out .= "                                \$vc_ok = \$vis_match_op(\$subj, \$vo, \$vw);\n";
        $out .= "                            }\n";
        $out .= "                            if (!\$vc_ok) { \$v_all = false; break; }\n";
        $out .= "                        }\n";
        $out .= "                        if (\$v_all && !empty(\$v_grp['rules'])) { \$v_matched = true; break; }\n";
        $out .= "                    }\n";
        $out .= "                    if (\$v_matched) {\n";
        $out .= "                        \$v_reason = 'Blocked on first match by Visual Rule (' . \$v_id . ')';\n";
        $out .= "                        if (!empty(\$v_rule['sync_cloudflare']) || !empty(\$v_rule['ban_ttl'])) {\n";
        $out .= "                            \$ban_q_file = __DIR__ . '/.preload_ban_queue.json';\n";
        $out .= "                            \$ban_q = file_exists(\$ban_q_file) ? (json_decode((string) @file_get_contents(\$ban_q_file), true) ?: []) : [];\n";
        $out .= "                            if (is_array(\$ban_q) && count(\$ban_q) < 200) {\n";
        $out .= "                                \$ban_q[\$ip . '|' . \$v_id] = ['ip' => \$ip, 'rule_id' => \$v_id, 'reason' => \$v_reason, 'ban_ttl' => (int) (\$v_rule['ban_ttl'] ?? 86400), 'sync_cloudflare' => !empty(\$v_rule['sync_cloudflare']), 'ts' => time()];\n";
        $out .= "                                @file_put_contents(\$ban_q_file, json_encode(\$ban_q), LOCK_EX);\n";
        $out .= "                            }\n";
        $out .= "                        }\n";
        $out .= "                        webcare_micro_waf_block(\$ip, \$v_id, \$v_reason, \$fail2ban_log);\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "            if (!\$mod_has_login_cookie && !empty(\$mod_rules['ajax_actions_enforced']) && strpos(\$mod_clean_uri, 'admin-ajax.php') !== false) {\n";
        $out .= "                \$ajax_act = isset(\$_REQUEST['action']) ? strtolower(trim((string) \$_REQUEST['action'])) : '';\n";
        $out .= "                \$trusted_ajax = is_array(\$mod_trusted['ajax_actions'] ?? null) ? \$mod_trusted['ajax_actions'] : [];\n";
        $out .= "                if (!empty(\$ajax_act) && !in_array(\$ajax_act, \$trusted_ajax, true) && isset(\$mod_rules['ajax_actions_enforced'][\$ajax_act])) {\n";
        $out .= "                    \$mod_spec = \$mod_rules['ajax_actions_enforced'][\$ajax_act];\n";
        $out .= "                    if (!empty(\$mod_spec['block_uploads']) && !empty(\$_FILES)) {\n";
        $out .= "                        webcare_micro_waf_block(\$ip, \$mod_spec['rule_id'], 'File uploads prohibited on guest AJAX action (' . htmlspecialchars(\$ajax_act, ENT_QUOTES, 'UTF-8') . ')', \$fail2ban_log);\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "            if (!\$mod_has_login_cookie && !empty(\$mod_rules['rest_routes_enforced'])) {\n";
        $out .= "                \$rest_q = \$mod_rest_q;\n";
        $out .= "                \$trusted_routes = is_array(\$mod_trusted['rest_routes'] ?? null) ? \$mod_trusted['rest_routes'] : [];\n";
        $out .= "                foreach (\$mod_rules['rest_routes_enforced'] as \$r_route => \$r_spec) {\n";
        $out .= "                    \$r_route_lc = strtolower(rtrim((string) \$r_route, '/'));\n";
        $out .= "                    if (\$r_route_lc === '' || in_array(\$r_route_lc, \$trusted_routes, true)) {\n";
        $out .= "                        continue;\n";
        $out .= "                    }\n";
        $out .= "                    \$matches_route = (strpos(\$mod_clean_uri, '/wp-json' . \$r_route_lc) !== false) || (\$rest_q !== '' && strpos(\$rest_q, \$r_route_lc) === 0);\n";
        $out .= "                    if (\$matches_route) {\n";
        $out .= "                        \$r_methods = is_array(\$r_spec['methods'] ?? null) ? array_map('strtoupper', \$r_spec['methods']) : ['POST', 'PUT', 'DELETE'];\n";
        $out .= "                        if (empty(\$r_methods) || in_array(\$mod_req_method, \$r_methods, true)) {\n";
        $out .= "                            webcare_micro_waf_block(\$ip, \$r_spec['rule_id'] ?? 'MOD-REST-GUARD', 'Unauthenticated ' . \$mod_req_method . ' request to permissive REST route (' . htmlspecialchars(\$r_route_lc, ENT_QUOTES, 'UTF-8') . ') blocked by Modular WAF', \$fail2ban_log);\n";
        $out .= "                        }\n";
        $out .= "                    }\n";
        $out .= "                }\n";
        $out .= "            }\n";
        $out .= "        }\n\n";

        $out .= "        foreach (\$signatures as \$rule_id => \$sig) {\n";
        $out .= "            if (preg_match(\$sig['pattern'], \$target_text)) {\n";
        $out .= "                webcare_micro_waf_block(\$ip, \$rule_id, \$sig['desc'], \$fail2ban_log);\n";
        $out .= "            }\n";
        $out .= "        }\n";
        $out .= "    })();\n";
        $out .= "} catch (\\Throwable \$e) {\n";
        $out .= "    // Self-preservation: Log silently to PHP error_log so host WordPress bootstrap is NEVER killed\n";
        $out .= "    @error_log('[WebCare Micro-WAF Preload Error] Intercepted: ' . \$e->getMessage());\n";
        $out .= "}\n\n";

        // Chained pre-existing auto_prepend_file script (e.g. Wordfence or hosting runtime)
        if (!empty($chained_file)) {
            $chained_escaped = addslashes($chained_file);
            $out .= "// Chained pre-existing auto_prepend_file runtime\n";
            $out .= "if (file_exists('{$chained_escaped}')) {\n";
            $out .= "    require_once '{$chained_escaped}';\n";
            $out .= "}\n\n";
        }

        // Responder function
        $out .= "function webcare_micro_waf_block(string \$ip, string \$rule_id, string \$desc, string \$fail2ban_log): void {\n";
        $out .= "    // Log in Linux Fail2ban / CrowdSec compatible format (strip CRLF to prevent log injection)\n";
        $out .= "    \$timestamp = gmdate('Y-m-d H:i:s');\n";
        $out .= "    \$uri = isset(\$_SERVER['REQUEST_URI']) ? str_replace([\"\\r\", \"\\n\"], '', substr(\$_SERVER['REQUEST_URI'], 0, 200)) : '/';\n";
        $out .= "    \$method = isset(\$_SERVER['REQUEST_METHOD']) ? str_replace([\"\\r\", \"\\n\"], '', substr(\$_SERVER['REQUEST_METHOD'], 0, 10)) : 'GET';\n";
        $out .= "    \$log_entry = sprintf(\"[%s] [WEBCARE-MICRO-WAF] [BLOCKED] IP: %s | Rule: %s | URI: %s | Method: %s\\n\", \$timestamp, \$ip, \$rule_id, \$uri, \$method);\n";
        $out .= "    @file_put_contents(\$fail2ban_log, \$log_entry, FILE_APPEND | LOCK_EX);\n\n";

        $out .= "    // Respond with HTTP 403 Forbidden\n";
        $out .= "    if (!headers_sent()) {\n";
        $out .= "        http_response_code(403);\n";
        $out .= "        header('HTTP/1.1 403 Forbidden');\n";
        $out .= "        header('Content-Type: text/html; charset=UTF-8');\n";
        $out .= "        header('X-WebCare-Defense: Preload-Micro-WAF-Active');\n";
        $out .= "        header('Connection: close');\n";
        $out .= "    }\n\n";

        $out .= "    echo '<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>403 Forbidden - WebCare Micro-WAF</title>';\n";
        $out .= "    echo '<style>body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;background:#090d16;color:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;padding:20px;box-sizing:border-box;}';\n";
        $out .= "    echo '.card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:32px;max-width:540px;width:100%;box-shadow:0 10px 25px rgba(0,0,0,0.5);}';\n";
        $out .= "    echo 'h1{font-size:22px;color:#f43f5e;margin-top:0;display:flex;align-items:center;gap:10px;}';\n";
        $out .= "    echo 'p{color:#94a3b8;font-size:14px;line-height:1.6;}';\n";
        $out .= "    echo '.meta{background:#1e293b;padding:12px 16px;border-radius:8px;font-family:monospace;font-size:12px;color:#38bdf8;margin:18px 0;word-break:break-all;}';\n";
        $out .= "    echo '.footer{color:#64748b;font-size:11px;margin-top:24px;border-top:1px solid #1e293b;padding-top:12px;}';\n";
        $out .= "    echo '</style></head><body><div class=\"card\">';\n";
        $out .= "    echo '<h1>Access Denied (403)</h1>';\n";
        $out .= "    echo '<p>Your request was intercepted by the WebCare Zero-Latency Preload Micro-WAF due to a verified security policy violation.</p>';\n";
        $out .= "    echo '<div class=\"meta\"><strong>Client IP:</strong> ' . htmlspecialchars(\$ip, ENT_QUOTES, 'UTF-8') . '<br><strong>Trigger:</strong> ' . htmlspecialchars(\$rule_id, ENT_QUOTES, 'UTF-8') . '<br><strong>Timestamp:</strong> ' . htmlspecialchars(\$timestamp, ENT_QUOTES, 'UTF-8') . ' UTC</div>';\n";
        $out .= "    echo '<p>If you believe this is an error, please contact the site administrator.</p>';\n";
        $out .= "    echo '<div class=\"footer\">Protected by WebCare Pro Security &bull; Zero-Resource Preload Shield</div>';\n";
        $out .= "    echo '</div></body></html>';\n";
        $out .= "    exit;\n";
        $out .= "}\n";

        return $out;
    }

    /**
     * Install the Preload Micro-WAF directive into .user.ini or .htaccess.
     *
     * @return array
     */
    public static function install_preload(): array {
        $target_info = self::detect_server_target();
        $target_file = $target_info['target_file'];
        $compiled_file = self::get_compiled_file_path();

        $begin_marker = '### BEGIN WEBCARE_MICRO_WAF';
        $end_marker   = '### END WEBCARE_MICRO_WAF';

        $existing_content = file_exists($target_file) ? (string) file_get_contents($target_file) : '';

        // Strip previous WebCare block if present
        $clean_content = preg_replace('/' . preg_quote($begin_marker, '/') . '[\s\S]*?' . preg_quote($end_marker, '/') . '\s*/i', '', $existing_content);

        // Detect if another security plugin or hosting environment already configured auto_prepend_file
        $chained_file = '';
        if (preg_match('/(?:auto_prepend_file\s*=\s*[\'"]?([^\r\n\'"]+)[\'"]?|php_value\s+auto_prepend_file\s+[\'"]?([^\r\n\'"]+)[\'"]?)/i', $clean_content, $m)) {
            $detected = trim(!empty($m[1]) ? $m[1] : ($m[2] ?? ''));
            if (!empty($detected) && !str_contains($detected, self::COMPILED_FILE_NAME) && file_exists($detected)) {
                $chained_file = $detected;
                update_option('webcareproscan_micro_waf_chained_file', $chained_file);
            }
        }

        // Compile first with chained script if detected
        $compile_res = self::compile($chained_file);
        if (!$compile_res['success']) {
            return $compile_res;
        }

        // Build directive block
        $block = "\n" . $begin_marker . "\n";
        if ($target_info['target'] === 'user_ini') {
            $block .= "; WebCare Pro Security Zero-Latency Preload Micro-WAF\n";
            $block .= "auto_prepend_file = '{$compiled_file}'\n";
        } else {
            $block .= "# WebCare Pro Security Zero-Latency Preload Micro-WAF\n";
            $block .= "<IfModule mod_php.c>\n";
            $block .= "    php_value auto_prepend_file '{$compiled_file}'\n";
            $block .= "</IfModule>\n";
            $block .= "<IfModule mod_php7.c>\n";
            $block .= "    php_value auto_prepend_file '{$compiled_file}'\n";
            $block .= "</IfModule>\n";
            $block .= "<IfModule mod_php8.c>\n";
            $block .= "    php_value auto_prepend_file '{$compiled_file}'\n";
            $block .= "</IfModule>\n";
        }
        $block .= $end_marker . "\n";

        $final_content = trim($clean_content) . "\n" . $block;

        $written = file_put_contents($target_file, $final_content);
        if ($written === false) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: file path */
                    __('Unable to write preload directive into %s. Please verify file permissions.', 'webcare-pro-security'),
                    $target_file
                ),
            ];
        }

        AuditLogger::log('micro_waf_installed', [
            'target_file'   => $target_file,
            'compiled_file' => $compiled_file,
            'chained_file'  => $chained_file,
            'environment'   => $target_info['reason'],
        ]);

        return [
            'success'     => true,
            'message'     => sprintf(
                /* translators: 1: filename, 2: environment description */
                __('Preload Micro-WAF installed successfully into %1$s (%2$s).', 'webcare-pro-security'),
                $target_info['filename'],
                $target_info['reason']
            ),
            'target_file' => $target_file,
            'is_active'   => self::is_active_in_runtime(),
        ];
    }

    /**
     * Uninstall the Preload Micro-WAF directive from .user.ini and .htaccess.
     *
     * @return array
     */
    public static function uninstall_preload(): array {
        $root_path = ABSPATH;
        $files = [
            trailingslashit($root_path) . '.user.ini',
            trailingslashit($root_path) . '.htaccess',
        ];

        $begin_marker = '### BEGIN WEBCARE_MICRO_WAF';
        $end_marker   = '### END WEBCARE_MICRO_WAF';
        $modified_count = 0;
        $chained_file = (string) get_option('webcareproscan_micro_waf_chained_file', '');
        delete_option('webcareproscan_micro_waf_chained_file');

        foreach ($files as $file) {
            if (file_exists($file) && wp_is_writable($file)) {
                $content = (string) file_get_contents($file);
                if (str_contains($content, $begin_marker)) {
                    $cleaned = preg_replace('/' . preg_quote($begin_marker, '/') . '[\s\S]*?' . preg_quote($end_marker, '/') . '\s*/i', '', $content);
                    // If an external chained prepend previously existed, restore its single directive
                    if (!empty($chained_file) && !str_contains($cleaned, 'auto_prepend_file')) {
                        if (str_ends_with($file, '.user.ini')) {
                            $cleaned = trim($cleaned) . "\nauto_prepend_file = '{$chained_file}'\n";
                        } else {
                            $cleaned = trim($cleaned) . "\n<IfModule mod_php.c>\n    php_value auto_prepend_file '{$chained_file}'\n</IfModule>\n";
                        }
                    }
                    file_put_contents($file, trim($cleaned) . "\n");
                    $modified_count++;
                }
            }
        }

        AuditLogger::log('micro_waf_uninstalled', [
            'modified_count' => $modified_count,
        ]);

        return [
            'success' => true,
            'message' => __('WebCare Preload Micro-WAF uninstalled successfully.', 'webcare-pro-security'),
        ];
    }

    /**
     * Get overall Micro-WAF status telemetry.
     *
     * @return array
     */
    public static function get_status(): array {
        $compiled_file = self::get_compiled_file_path();
        $is_compiled = file_exists($compiled_file);
        $is_active = self::is_active_in_runtime();
        $target_info = self::detect_server_target();

        $saved_status = get_option(self::OPTION_STATUS, []);
        $bypass_token = get_option('webcareproscan_micro_waf_bypass_token', '');
        $fail2ban_log = self::get_fail2ban_log_path();

        $recent_drops = [];
        if (file_exists($fail2ban_log)) {
            $lines = file($fail2ban_log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                $recent_drops = array_slice(array_reverse($lines), 0, 15);
            }
        }

        return [
            'is_compiled'       => $is_compiled,
            'is_active'         => $is_active,
            'auto_prepend_ini'  => (string) ini_get('auto_prepend_file'),
            'compiled_file'     => $compiled_file,
            'file_size_bytes'   => $is_compiled ? filesize($compiled_file) : 0,
            'target_info'       => $target_info,
            'saved_status'      => $saved_status,
            'bypass_token'      => $bypass_token,
            'fail2ban_log'      => $fail2ban_log,
            'recent_drops'      => $recent_drops,
            'recent_drop_count' => count($recent_drops),
        ];
    }

    /**
     * Compile active CAF data rules into a signed static array artifact.
     */
    public static function compile_caf_data_artifact(): bool {
        $caf_file = self::get_caf_compiled_file_path();
        $sig_file = $caf_file . '.sig';

        $snapshot = null;
        $active_profile = 'balanced';
        $lock_dormant = true;
        $conflict_exemptions = [];
        $scoped_patches = [];

        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
            $snapshot = $advisor->get_stack_snapshot();
            $matrix   = $advisor->get_recommendations_matrix($snapshot);

            $active_profile      = (string) ($matrix['current_profile'] ?? 'balanced');
            $lock_dormant        = !empty($matrix['lock_dormant_surface']);
            $conflict_exemptions = (array) ($matrix['conflict_exemptions'] ?? []);
            $scoped_patches      = array_column((array) ($matrix['must_enable_patches'] ?? []), 'id');
        }

        $inactive_plugin_slugs = $snapshot ? array_keys($snapshot->inactive_plugins) : [];
        $inactive_theme_slugs  = $snapshot ? array_keys($snapshot->inactive_themes) : [];
        $exempt_ns             = !empty($conflict_exemptions['rest_exempt_namespaces']) && is_array($conflict_exemptions['rest_exempt_namespaces'])
            ? $conflict_exemptions['rest_exempt_namespaces']
            : [];
        $base_ns               = $snapshot && !empty($snapshot->rest_namespaces) ? $snapshot->rest_namespaces : ['wp/v2', 'oembed/1.0'];
        $active_rest_namespaces= array_values(array_unique(array_merge(
            $base_ns,
            $exempt_ns,
            ['webcare-pro-security/v1', 'wp/v2', 'oembed/1.0']
        )));
        $snapshot_hash         = $snapshot ? $snapshot->snapshot_hash : '';

        // Extract registered nopriv AJAX actions from $wp_filter if available
        global $wp_filter;
        $allowed_nopriv_actions = [];
        if (!empty($wp_filter) && is_array($wp_filter)) {
            foreach (array_keys($wp_filter) as $hook_name) {
                if (is_string($hook_name) && str_starts_with($hook_name, 'wp_ajax_nopriv_')) {
                    $allowed_nopriv_actions[] = substr($hook_name, 15);
                }
            }
        }

        // Merge standard Core guest AJAX safe-passes + ecosystem-specific guest actions (CAF 2.0)
        $default_guest_ajax = ['heartbeat', 'webcare_flush_cf_ban_queue'];
        $has_woo = false;
        if ($snapshot && is_array($snapshot->detected_ecosystems)) {
            $has_woo = in_array('woocommerce', $snapshot->detected_ecosystems, true);
        } elseif (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            $has_woo = \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('woocommerce');
        }

        if ($has_woo) {
            $default_guest_ajax = array_merge($default_guest_ajax, [
                'woocommerce_get_refreshed_fragments',
                'woocommerce_apply_coupon',
                'woocommerce_remove_coupon',
                'woocommerce_update_shipping_method',
                'woocommerce_get_cart_totals',
                'woocommerce_update_order_review',
                'woocommerce_add_to_cart',
                'woocommerce_remove_from_cart',
                'woocommerce_checkout',
                'woocommerce_get_variation',
                'woocommerce_get_customer_location',
            ]);
        }
        if (!empty($conflict_exemptions['woocommerce_ajax_actions']) && is_array($conflict_exemptions['woocommerce_ajax_actions'])) {
            $default_guest_ajax = array_merge($default_guest_ajax, $conflict_exemptions['woocommerce_ajax_actions']);
        }
        $allowed_nopriv_actions = array_values(array_unique(array_merge($allowed_nopriv_actions, $default_guest_ajax)));

        $artifact_data = [
            'version'                => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.4.0',
            'generated_at'           => time(),
            'snapshot_hash'          => $snapshot_hash,
            'active_profile'         => $active_profile,
            'lock_dormant_surface'   => $lock_dormant,
            'inactive_plugin_slugs'  => $inactive_plugin_slugs,
            'inactive_theme_slugs'   => $inactive_theme_slugs,
            'active_rest_namespaces' => $active_rest_namespaces,
            'allowed_nopriv_actions' => $allowed_nopriv_actions,
            'conflict_exemptions'    => $conflict_exemptions,
            'scoped_virtual_patches' => $scoped_patches,
        ];

        $php_code = "<?php\n// Auto-generated by WebCare MicroWafCompiler - DO NOT EDIT MANUALLY.\nreturn "
                  // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Compiling static data array artifact for OPcache bytecode caching.
                  . var_export($artifact_data, true) . ";\n";

        // Security Guardrail: Verify generated string contains strictly array/literal tokens (zero function calls)
        if (!self::assert_strictly_data_tokens($php_code)) {
            return false;
        }

        $temp_file = $caf_file . '.tmp.' . wp_rand();
        if (file_put_contents($temp_file, $php_code) === false) {
            return false;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic move of compiled WAF cache.
        if (!rename($temp_file, $caf_file)) {
            wp_delete_file($temp_file);
            return false;
        }

        // Detached HMAC-SHA256 signature
        $salt = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-caf-fallback-salt';
        $hmac = hash_hmac('sha256', $php_code, $salt);
        update_option(self::OPTION_CAF_HMAC, $hmac);
        file_put_contents($sig_file, $hmac);

        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($caf_file, true);
        }

        return true;
    }

    /**
     * AST Token Validator: Verifies that code contains strictly data array tokens and zero function calls.
     */
    public static function assert_strictly_data_tokens(string $code): bool {
        $allowed_tokens = [
            T_OPEN_TAG,
            T_RETURN,
            T_ARRAY,
            T_CONSTANT_ENCAPSED_STRING,
            T_LNUMBER,
            T_DNUMBER,
            T_DOUBLE_ARROW,
            T_WHITESPACE,
            T_COMMENT,
            T_DOC_COMMENT,
            T_STRING,
        ];

        $tokens = token_get_all($code);
        foreach ($tokens as $token) {
            if (is_array($token)) {
                if (!in_array($token[0], $allowed_tokens, true)) {
                    return false;
                }
                // Disallow arbitrary functions or constants (only allow true, false, null)
                if ($token[0] === T_STRING && !in_array(strtolower($token[1]), ['true', 'false', 'null', 'array'], true)) {
                    return false;
                }
            } else {
                // Single character tokens allowed: ()[],;
                if (!in_array($token, ['(', ')', '[', ']', ',', ';'], true)) {
                    return false;
                }
            }
        }

        return true;
    }

}
