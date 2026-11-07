<?php
/**
 * HtaccessShield
 *
 * Directive-Grouping Semantic Classifier, Flush Grace Tracker, and Runtime Redirect Firewall.
 * Analyzes .htaccess directives by grouping contiguous RewriteCond with RewriteRules,
 * audits inside vendor blocks without blind trust, and intercepts guest runtime wp_redirect hijacks.
 *
 * @package WcpScanner\Firewall
 * @author  Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer
 */

namespace WcpScanner\Firewall;

use WcpScanner\System\SettingsManager;
use WcpScanner\System\WcpActivityLogger;
use WcpScanner\Notifications\NotificationDispatcher;

if (!defined('ABSPATH')) {
    exit;
}

final class HtaccessShield {

    public const FLUSH_GRACE_TRANSIENT    = 'wcpscan_htaccess_flush_grace';
    public const RUNTIME_REDIRECT_OPTION  = 'wcpscan_block_runtime_redirects';
    public const APPROVED_HOSTS_OPTION    = 'wcpscan_redirect_approved_hosts';

    /**
     * Known vendor block identifiers for contextual auditing.
     */
    private const VENDOR_BLOCKS = [
        'WordPress',
        'LSCACHE',
        'Litespeed',
        'WP Rocket',
        'W3TC',
        'Yoast',
        'Rank Math',
        'Redirection',
        'WCP_SECURITY_SCANNER_SERVER_RULES',
        'WCP_MICRO_WAF',
    ];

    /**
     * Default approved external hosts for commerce, OAuth, and payment gateways.
     */
    private const DEFAULT_APPROVED_HOSTS = [
        'checkout.stripe.com',
        'hooks.stripe.com',
        'api.stripe.com',
        'paypal.com',
        'www.paypal.com',
        'sandbox.paypal.com',
        'accounts.google.com',
        'login.microsoftonline.com',
        'appleid.apple.com',
        'auth0.com',
        'okta.com',
        'squareup.com',
        'mollie.com',
        'surecart.com',
        'paddle.com',
        'lemonsqueezy.com',
        'pay.woocommerce.com',
        'gravatar.com',
        'wordpress.org',
    ];

    /**
     * Initialize event hooks and runtime filters.
     *
     * @return void
     */
    public static function init(): void {
        // 1. Legitimate rewrite flush & plugin change observers
        add_action('flush_rewrite_rules_hard', [self::class, 'handle_rewrite_flush'], 10);
        add_action('activated_plugin', [self::class, 'handle_plugin_change'], 10);
        add_action('deactivated_plugin', [self::class, 'handle_plugin_change'], 10);
        add_action('upgrader_process_complete', [self::class, 'handle_plugin_change'], 10);

        // 2. Runtime wp_redirect call-stack firewall
        add_filter('wp_redirect', [self::class, 'inspect_runtime_redirect'], 999999, 2);

        // 3. Clear-Site-Data header emitter after remediation
        add_action('send_headers', [self::class, 'handle_send_headers'], 10);
    }

    /**
     * Mark a temporary grace window during which legitimate plugin flushes are expected.
     *
     * @param int $ttl Time to live in seconds (default 300 = 5 minutes).
     * @return void
     */
    public static function mark_legitimate_flush_window(int $ttl = 300): void {
        set_transient(self::FLUSH_GRACE_TRANSIENT, time() + $ttl, $ttl);
    }

    /**
     * Check if the site is currently within a legitimate flush grace window.
     *
     * @return bool True if active.
     */
    public static function is_within_flush_grace_window(): bool {
        return get_transient(self::FLUSH_GRACE_TRANSIENT) !== false;
    }

    /**
     * Handle flush_rewrite_rules_hard action.
     *
     * @return void
     */
    public static function handle_rewrite_flush(): void {
        self::mark_legitimate_flush_window(300);

        // Automatically archive newly generated .htaccess if verified clean
        if (class_exists('\\WcpScanner\\Firewall\\HtaccessVaultManager')) {
            HtaccessVaultManager::snapshot_current_if_clean('rewrite_rules_flush');
        }
    }

    /**
     * Handle plugin activation/deactivation/update.
     *
     * @return void
     */
    public static function handle_plugin_change(): void {
        self::mark_legitimate_flush_window(300);
    }

    /**
     * Emit Clear-Site-Data: "cache" on front-end guest requests if transient is set.
     *
     * @return void
     */
    public static function handle_send_headers(): void {
        if (!is_admin() && get_transient('wcpscan_emit_clear_site_data')) {
            if (!headers_sent()) {
                header('Clear-Site-Data: "cache"');
            }
        }
    }

    /**
     * Parse and semantically classify .htaccess directives.
     * Groups contiguous RewriteCond with their following RewriteRule,
     * inspects inside vendor blocks, and scores external targets and cloaking vectors.
     *
     * @param string $content Raw .htaccess text.
     * @return array Semantic analysis report.
     */
    public static function analyze_htaccess_content(string $content): array {
        $lines = preg_split("/\r\n|\n|\r/", $content);
        if ($lines === false || empty($lines)) {
            return [
                'score'            => 0,
                'severity'         => 'clean',
                'is_hostile'       => false,
                'findings'         => [],
                'has_cloaking'     => false,
                'has_catch_all'    => false,
                'external_targets' => [],
                'scanned_lines'    => 0,
                'vendor_blocks'    => [],
            ];
        }

        $findings          = [];
        $total_score       = 0;
        $has_cloaking      = false;
        $has_catch_all     = false;
        $external_targets  = [];
        $vendor_blocks     = [];
        $current_block     = 'root';

        // Local canonical hosts
        $canonical_hosts   = self::get_canonical_hosts();

        // Accumulated RewriteCond directives for the current rule
        $pending_conditions = [];

        foreach ($lines as $line_num_zero => $raw_line) {
            $line_num = $line_num_zero + 1;
            $line     = trim($raw_line);

            if ($line === '') {
                continue;
            }

            // 1. Detect Vendor Block Markers (tracked for context, but rules inside are still audited)
            if (preg_match('/^#\s*BEGIN\s+(.+)$/i', $line, $m_begin)) {
                $current_block = trim($m_begin[1]);
                $vendor_blocks[] = $current_block;
                continue;
            }
            if (preg_match('/^#\s*END\s+(.+)$/i', $line, $m_end)) {
                $current_block = 'root';
                continue;
            }

            // Skip comments that aren't directives
            if (str_starts_with($line, '#')) {
                continue;
            }

            // 2. Accumulate RewriteCond directives
            if (preg_match('/^RewriteCond\s+([^\s]+)\s+([^\s]+)(?:\s+\[(.*)\])?/i', $line, $cond_match)) {
                $pending_conditions[] = [
                    'line'     => $line_num,
                    'raw'      => $line,
                    'variable' => $cond_match[1],
                    'pattern'  => $cond_match[2],
                    'flags'    => $cond_match[3] ?? '',
                ];
                continue;
            }

            // 3. Process RewriteRule directives paired with accumulated RewriteConds
            if (preg_match('/^RewriteRule\s+([^\s]+)\s+([^\s]+)(?:\s+\[(.*)\])?/i', $line, $rule_match)) {
                $rule_pattern = $rule_match[1];
                $rule_target  = $rule_match[2];
                $rule_flags   = $rule_match[3] ?? '';

                $rule_evaluation = self::evaluate_rewrite_rule(
                    $rule_pattern,
                    $rule_target,
                    $rule_flags,
                    $pending_conditions,
                    $canonical_hosts,
                    $line_num,
                    $current_block
                );

                if (!empty($rule_evaluation['findings'])) {
                    foreach ($rule_evaluation['findings'] as $f) {
                        $findings[] = $f;
                        $total_score += $f['score'];
                        if (!empty($f['is_cloaking'])) {
                            $has_cloaking = true;
                        }
                        if (!empty($f['is_catch_all'])) {
                            $has_catch_all = true;
                        }
                        if (!empty($f['external_target'])) {
                            $external_targets[] = $f['external_target'];
                        }
                    }
                }

                // Reset conditions after evaluating the governing RewriteRule
                $pending_conditions = [];
                continue;
            }

            // If a non-RewriteCond line interrupts conditions, clear conditions
            $pending_conditions = [];

            // 4. Evaluate direct Redirect / RedirectMatch directives
            if (preg_match('/^(Redirect(?:Match)?)\s+(?:(\d{3})\s+)?([^\s]+)\s+([^\s]+)/i', $line, $redir_match)) {
                $redir_type   = $redir_match[1];
                $redir_code   = $redir_match[2] ?? '302';
                $redir_source = $redir_match[3];
                $redir_target = $redir_match[4];

                if (self::is_external_target($redir_target, $canonical_hosts)) {
                    $target_host        = wp_parse_url($redir_target, PHP_URL_HOST);
                    $external_targets[] = $target_host;
                    $score              = 90;
                    $total_score       += $score;
                    $has_catch_all      = true;

                    $findings[] = [
                        'line'            => $line_num,
                        'score'           => $score,
                        'severity'        => 'high',
                        'type'            => 'htaccess_external_redirect_match',
                        'evidence'        => $line,
                        'block'           => $current_block,
                        'external_target' => $target_host,
                        'description'     => sprintf(
                            /* translators: 1: line number, 2: redirect type, 3: target URL */
                            __('Line %1$d: Direct %2$s redirects visitors to external target "%3$s".', 'wcp-security-scanner'),
                            $line_num,
                            $redir_type,
                            $redir_target
                        ),
                    ];
                }
                continue;
            }

            // 5. Evaluate Rogue PHP Handlers (AddHandler / SetHandler)
            if (preg_match('/(?:AddHandler|SetHandler)\s+application\/x-httpd-php(?:-source)?\s*(.*)/i', $line, $handler_match)) {
                $extensions = trim($handler_match[1] ?? '');
                // Check if mapping PHP execution to image or non-PHP extensions (.jpg, .png, .ico, .txt, .css, etc.)
                if (preg_match('/\.(jpe?g|png|gif|ico|bmp|webp|svg|txt|css|js|html?|pdf|zip|mp3|mp4)\b/i', $extensions) || $extensions === '') {
                    $score        = 95;
                    $total_score += $score;
                    $findings[]   = [
                        'line'        => $line_num,
                        'score'       => $score,
                        'severity'    => 'critical',
                        'type'        => 'htaccess_rogue_php_handler',
                        'evidence'    => $line,
                        'block'       => $current_block,
                        'description' => sprintf(
                            /* translators: 1: line number, 2: directive */
                            __('Line %1$d: Rogue PHP handler directive "%2$s" executes non-PHP static files as executable PHP code.', 'wcp-security-scanner'),
                            $line_num,
                            $line
                        ),
                    ];
                }
                continue;
            }

            // 6. Evaluate Rogue php_value auto_prepend_file or auto_append_file
            if (preg_match('/php_value\s+(auto_prepend_file|auto_append_file)\s+["\']?([^"\'\r\n\s]+)/i', $line, $prep_match)) {
                $directive_name = $prep_match[1];
                $target_path    = $prep_match[2];

                // Whitelist WCP's own compiled micro-waf file
                if (!str_contains($target_path, 'micro-waf-compiled.php') && !str_contains($target_path, 'wordfence-waf.php')) {
                    $score        = 95;
                    $total_score += $score;
                    $findings[]   = [
                        'line'        => $line_num,
                        'score'       => $score,
                        'severity'    => 'critical',
                        'type'        => 'htaccess_unauthorized_preloader',
                        'evidence'    => $line,
                        'block'       => $current_block,
                        'description' => sprintf(
                            /* translators: 1: line number, 2: directive name, 3: file path */
                            __('Line %1$d: Unauthorized %2$s directive injects external script "%3$s" into every PHP request.', 'wcp-security-scanner'),
                            $line_num,
                            $directive_name,
                            $target_path
                        ),
                    ];
                }
                continue;
            }
        }

        $total_score = min(100, $total_score);

        $severity = 'clean';
        if ($total_score >= 80) {
            $severity = 'critical';
        } elseif ($total_score >= 50) {
            $severity = 'high';
        } elseif ($total_score >= 25) {
            $severity = 'medium';
        } elseif ($total_score > 0) {
            $severity = 'low';
        }

        return [
            'score'            => $total_score,
            'severity'         => $severity,
            'is_hostile'       => $total_score >= 60,
            'findings'         => $findings,
            'has_cloaking'     => $has_cloaking,
            'has_catch_all'    => $has_catch_all,
            'external_targets' => array_values(array_unique($external_targets)),
            'scanned_lines'    => count($lines),
            'vendor_blocks'    => array_values(array_unique($vendor_blocks)),
        ];
    }

    /**
     * Evaluate a RewriteRule combined with its governing RewriteCond directives.
     *
     * @param string $pattern Rewrite pattern (regex).
     * @param string $target Rewrite target.
     * @param string $flags Rewrite flags (e.g., L, R=301, NC).
     * @param array  $conditions List of accumulated RewriteCond directives.
     * @param array  $canonical_hosts Array of known valid hostnames for this WordPress site.
     * @param int    $line_num Line number in file.
     * @param string $current_block Name of current vendor block.
     * @return array Findings list.
     */
    private static function evaluate_rewrite_rule(
        string $pattern,
        string $target,
        string $flags,
        array $conditions,
        array $canonical_hosts,
        int $line_num,
        string $current_block
    ): array {
        $findings = [];

        // Check if target is an external URL
        $is_external_target = self::is_external_target($target, $canonical_hosts);
        $target_host        = $is_external_target ? wp_parse_url($target, PHP_URL_HOST) : '';

        // Check if redirect flag is present (R, R=301, R=302, etc.)
        $is_redirect_flag   = (bool) preg_match('/\bR(?:=(\d{3}))?\b/i', $flags);

        // Check if rule is a catch-all / global redirect pattern
        $is_catch_all = (bool) preg_match('/^(?:\^\.\*\$|\^\/\.\*\$|\.\*|\^\.\*|\^\/\?\$|\^\.\+\$|\\\.php\$|\^\(\.\*\)\$)/i', $pattern);

        // Analyze conditions for cloaking (Referer, User-Agent, Remote Address)
        $referer_cloak = false;
        $ua_cloak      = false;
        $ip_cloak      = false;
        $cond_evidences = [];

        foreach ($conditions as $c) {
            $cond_evidences[] = $c['raw'];
            $var = strtoupper($c['variable']);
            $pat = $c['pattern'];

            if (str_contains($var, 'HTTP_REFERER')) {
                if (preg_match('/(google|bing|yahoo|yandex|duckduckgo|chatgpt|perplexity|facebook|twitter|instagram|tiktok|t\.co|aol|ask)/i', $pat)) {
                    $referer_cloak = true;
                }
            } elseif (str_contains($var, 'HTTP_USER_AGENT')) {
                if (preg_match('/(android|iphone|ipad|mobile|phone|blackberry|googlebot|bingbot|slurp|crawler|spider|oai-searchbot|chatgpt)/i', $pat)) {
                    $ua_cloak = true;
                }
            } elseif (str_contains($var, 'REMOTE_ADDR') || str_contains($var, 'GEOIP')) {
                $ip_cloak = true;
            }
        }

        // 1. Cloaked External Redirect (Highest Confidence Threat)
        if (($referer_cloak || $ua_cloak) && ($is_external_target || $is_redirect_flag)) {
            $score = 100;
            $type  = $referer_cloak ? 'htaccess_cloaked_referer_redirect' : 'htaccess_cloaked_useragent_redirect';
            $findings[] = [
                'line'            => $line_num,
                'score'           => $score,
                'severity'        => 'critical',
                'type'            => $type,
                'is_cloaking'     => true,
                'is_catch_all'    => $is_catch_all,
                'external_target' => $target_host,
                'evidence'        => implode("\n", $cond_evidences) . "\nRewriteRule {$pattern} {$target} [{$flags}]",
                'block'           => $current_block,
                'description'     => sprintf(
                    /* translators: 1: line number, 2: target host, 3: cloaking factor */
                    __('Line %1$d: Malicious cloaked redirect targeting external destination "%2$s" conditioned on %3$s.', 'wcp-security-scanner'),
                    $line_num,
                    $target_host ?: $target,
                    $referer_cloak ? __('Search Engine Referer', 'wcp-security-scanner') : __('Mobile / Crawler User-Agent', 'wcp-security-scanner')
                ),
            ];
            return ['findings' => $findings];
        }

        // 2. Global / Catch-All External Redirect (Kills entire site or all PHP files)
        if ($is_catch_all && $is_external_target) {
            $score = 95;
            $findings[] = [
                'line'            => $line_num,
                'score'           => $score,
                'severity'        => 'critical',
                'type'            => 'htaccess_catch_all_external_redirect',
                'is_cloaking'     => false,
                'is_catch_all'    => true,
                'external_target' => $target_host,
                'evidence'        => (!empty($cond_evidences) ? implode("\n", $cond_evidences) . "\n" : '') . "RewriteRule {$pattern} {$target} [{$flags}]",
                'block'           => $current_block,
                'description'     => sprintf(
                    /* translators: 1: line number, 2: rewrite pattern, 3: destination host */
                    __('Line %1$d: Catch-all rewrite pattern "%2$s" redirects all incoming traffic to external host "%3$s".', 'wcp-security-scanner'),
                    $line_num,
                    $pattern,
                    $target_host
                ),
            ];
            return ['findings' => $findings];
        }

        // 3. General External Redirect
        if ($is_external_target && $is_redirect_flag) {
            $score = 80;
            $findings[] = [
                'line'            => $line_num,
                'score'           => $score,
                'severity'        => 'high',
                'type'            => 'htaccess_external_rewrite_rule',
                'is_cloaking'     => false,
                'is_catch_all'    => false,
                'external_target' => $target_host,
                'evidence'        => (!empty($cond_evidences) ? implode("\n", $cond_evidences) . "\n" : '') . "RewriteRule {$pattern} {$target} [{$flags}]",
                'block'           => $current_block,
                'description'     => sprintf(
                    /* translators: 1: line number, 2: external host */
                    __('Line %1$d: RewriteRule redirects visitors to unapproved external host "%2$s".', 'wcp-security-scanner'),
                    $line_num,
                    $target_host
                ),
            ];
            return ['findings' => $findings];
        }

        return ['findings' => $findings];
    }

    /**
     * Check if a redirect target is an external host (outside current site and approved domains).
     *
     * @param string $target Target path or full URL.
     * @param array  $canonical_hosts Array of known canonical site hostnames.
     * @return bool True if target is an unapproved external destination.
     */
    public static function is_external_target(string $target, array $canonical_hosts): bool {
        $trimmed = trim($target);
        if ($trimmed === '' || $trimmed === '-' || str_starts_with($trimmed, '/') || str_starts_with($trimmed, 'index.php')) {
            return false;
        }

        // Relative path or anchor
        if (!preg_match('/^(?:https?:)?\/\//i', $trimmed)) {
            return false;
        }

        $parsed = wp_parse_url($trimmed, PHP_URL_HOST);
        if (empty($parsed)) {
            return false;
        }

        $host_lower = strtolower((string) $parsed);

        // Check if matches any canonical host of this site
        foreach ($canonical_hosts as $can_host) {
            if ($host_lower === $can_host || str_ends_with($host_lower, '.' . $can_host)) {
                return false;
            }
        }

        // Check against approved external hosts (commerce, payment, auth)
        $approved = self::get_approved_redirect_hosts();
        foreach ($approved as $app_host) {
            if ($host_lower === $app_host || str_ends_with($host_lower, '.' . $app_host)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get list of canonical local hostnames for this WordPress installation.
     *
     * @return array
     */
    public static function get_canonical_hosts(): array {
        $hosts = [];

        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        if (!empty($home_host)) {
            $h_low = strtolower($home_host);
            $hosts[] = $h_low;
            if (str_starts_with($h_low, 'www.')) {
                $hosts[] = substr($h_low, 4);
            } else {
                $hosts[] = 'www.' . $h_low;
            }
        }

        $site_host = wp_parse_url(site_url(), PHP_URL_HOST);
        if (!empty($site_host)) {
            $s_low = strtolower($site_host);
            $hosts[] = $s_low;
            if (str_starts_with($s_low, 'www.')) {
                $hosts[] = substr($s_low, 4);
            } else {
                $hosts[] = 'www.' . $s_low;
            }
        }

        // Local loopback addresses
        $hosts[] = 'localhost';
        $hosts[] = '127.0.0.1';
        $hosts[] = '::1';

        return array_values(array_unique($hosts));
    }

    /**
     * Get complete list of approved redirect hosts (defaults + user settings + active redirection plugins).
     *
     * @return array
     */
    public static function get_approved_redirect_hosts(): array {
        $hosts = self::DEFAULT_APPROVED_HOSTS;

        // Merge with canonical hosts
        foreach (self::get_canonical_hosts() as $h) {
            $hosts[] = $h;
        }

        // Merge with user-configured allowlist in SettingsManager
        $user_allowed = SettingsManager::get('waf_redirect_allowlist', []);
        if (is_array($user_allowed)) {
            foreach ($user_allowed as $u_host) {
                if (is_string($u_host) && trim($u_host) !== '') {
                    $hosts[] = strtolower(trim($u_host));
                }
            }
        }

        $opt_allowed = get_option(self::APPROVED_HOSTS_OPTION, []);
        if (is_array($opt_allowed)) {
            foreach ($opt_allowed as $o_host) {
                if (is_string($o_host) && trim($o_host) !== '') {
                    $hosts[] = strtolower(trim($o_host));
                }
            }
        }

        // Merge active domains from Redirection plugin if active
        global $wpdb;
        if (!empty($wpdb)) {
            $table_redirection = $wpdb->prefix . 'redirection_items';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $check_table = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_redirection));
            if ($check_table === $table_redirection) {
                // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Whitelisted dynamic table name from verified $wpdb->prefix.
                $plugin_targets = $wpdb->get_col("SELECT action_data FROM `{$table_redirection}` WHERE action_type = 'url' AND action_data LIKE 'http%' LIMIT 100");
                if (is_array($plugin_targets)) {
                    foreach ($plugin_targets as $p_url) {
                        $p_host = wp_parse_url($p_url, PHP_URL_HOST);
                        if (!empty($p_host)) {
                            $hosts[] = strtolower($p_host);
                        }
                    }
                }
            }
        }

        return array_values(array_unique($hosts));
    }

    /**
     * Runtime wp_redirect Call-Stack Firewall.
     * Hooks wp_redirect at priority 999999 to inspect, attribute, and neutralize malicious guest redirects.
     *
     * @param string $location Destination redirect URL.
     * @param int    $status HTTP status code.
     * @return string Validated destination URL.
     */
    public static function inspect_runtime_redirect(string $location, int $status): string {
        $trimmed = trim($location);
        if ($trimmed === '' || str_starts_with($trimmed, '/') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '?')) {
            return $location;
        }

        // Allow authenticated administrators, editors, or backend operations
        if (is_admin() || is_user_logged_in()) {
            return $location;
        }

        $canonical_hosts = self::get_canonical_hosts();
        if (!self::is_external_target($trimmed, $canonical_hosts)) {
            return $location;
        }

        $target_host = wp_parse_url($trimmed, PHP_URL_HOST);

        // Capture forensic call stack to pinpoint the offending file and line
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Forensic call stack analysis to attribute malicious caller file in runtime redirect firewall.
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20);
        $offending_file = 'unknown';
        $offending_line = 0;

        foreach ($backtrace as $frame) {
            $f_file = $frame['file'] ?? '';
            // Skip core WordPress pluggable/redirect machinery
            if (empty($f_file) || str_contains($f_file, 'wp-includes/pluggable.php') || str_contains($f_file, 'wp-includes/canonical.php') || str_contains($f_file, __FILE__)) {
                continue;
            }
            $offending_file = str_replace(ABSPATH, '', $f_file);
            $offending_line = $frame['line'] ?? 0;
            break;
        }

        $attribution = sprintf('%s:%d', $offending_file, $offending_line);

        // Log forensic activity
        if (class_exists('\\WcpScanner\\System\\WcpActivityLogger')) {
            WcpActivityLogger::log(
                'waf_runtime_redirect_intercepted',
                'firewall',
                'critical',
                [
                    'target_url'   => substr($trimmed, 0, 120),
                    'target_host'  => $target_host,
                    'status_code'  => $status,
                    'source_file'  => $attribution,
                ]
            );
        }

        // Dispatch out-of-band notification
        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            NotificationDispatcher::trigger('redirect_hack_detected', [
                'severity' => 'critical',
                'message'  => sprintf(
                    /* translators: 1: target destination, 2: attributed PHP file */
                    __('Unauthorized guest runtime redirect intercepted by WCP Redirect Firewall: "%1$s" initiated by "%2$s".', 'wcp-security-scanner'),
                    $trimmed,
                    $attribution
                ),
                'details'  => [
                    'Target URL'        => $trimmed,
                    'Attributed Source' => $attribution,
                    'Status Code'       => $status,
                    'Client IP'         => !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1',
                    'Referer'           => !empty($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : 'Direct',
                ],
            ]);
        }

        // If runtime redirect blocking is active (enabled by default), neutralize back to home_url('/')
        $blocking_active = (bool) get_option(self::RUNTIME_REDIRECT_OPTION, true);
        if ($blocking_active) {
            return home_url('/');
        }

        return $location;
    }
}
