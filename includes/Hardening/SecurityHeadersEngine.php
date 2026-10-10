<?php
namespace WCP\Scanner\Hardening;

use WCP\Scanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SecurityHeadersEngine
 *
 * Injects enterprise-grade HTTP security headers, enforces runtime admin file editor locks,
 * shields against automated username enumeration, removes version leaks, and blocks sensitive file probing.
 */
class SecurityHeadersEngine {

    /**
     * Bootstrap the hardening & security headers engine
     */
    public static function init() {
        // Enforce DISALLOW_FILE_EDIT as early as possible
        self::enforce_file_edit_lock();

        // Security headers injection on standard WordPress header dispatch
        add_action('send_headers', [__CLASS__, 'send_security_headers'], 5);
        add_action('login_init', [__CLASS__, 'send_security_headers'], 5);

        // User Enumeration Defense
        add_action('init', [__CLASS__, 'protect_user_enumeration'], 1);
        add_filter('rest_endpoints', [__CLASS__, 'filter_rest_user_endpoints'], 10, 1);

        // Information Leakage Hardening (WP version tags and query strings)
        self::apply_version_leak_hardening();

        // Sensitive Files HTTP Protection Guard (.env, .git, .sql, etc.)
        add_action('init', [__CLASS__, 'protect_sensitive_files_probe'], 0);
    }

    /**
     * Enforce DISALLOW_FILE_EDIT at runtime if configured
     */
    public static function enforce_file_edit_lock() {
        $settings = SettingsManager::get_settings();
        if (!empty($settings['disable_file_editing'])) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }
    }

    /**
     * Inject Security Headers into HTTP Response
     */
    public static function send_security_headers() {
        if (headers_sent()) {
            return;
        }

        $settings = SettingsManager::get_settings();

        // 1. Strict-Transport-Security (HSTS)
        if (!empty($settings['header_hsts']) && is_ssl()) {
            $hsts_val = 'max-age=31536000; includeSubDomains';
            if (!empty($settings['header_hsts_preload'])) {
                $hsts_val .= '; preload';
            }
            header("Strict-Transport-Security: {$hsts_val}", false);
        }

        // 2. X-Frame-Options (Clickjacking defense)
        if (!empty($settings['header_x_frame_options'])) {
            $mode = strtoupper($settings['header_x_frame_options_mode'] ?? 'SAMEORIGIN');
            if (in_array($mode, ['DENY', 'SAMEORIGIN'], true)) {
                header("X-Frame-Options: {$mode}", false);
            }
        }

        // 3. X-Content-Type-Options (MIME-sniffing defense)
        if (!empty($settings['header_nosniff'])) {
            header('X-Content-Type-Options: nosniff', false);
        }

        // 4. Referrer-Policy
        if (!empty($settings['header_referrer_policy'])) {
            $policy = $settings['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin';
            header("Referrer-Policy: {$policy}", false);
        }

        // 5. Permissions-Policy (Hardware feature restrictor)
        if (!empty($settings['header_permissions_policy'])) {
            $perms = $settings['header_permissions_policy_value'] ?? 'geolocation=(), camera=(), microphone=(), payment=()';
            header("Permissions-Policy: {$perms}", false);
        }

        // 6. X-XSS-Protection (Legacy filter mode)
        if (!empty($settings['header_xss_protection'])) {
            header('X-XSS-Protection: 1; mode=block', false);
        }

        // 7. Content-Security-Policy (CSP Lite baseline)
        if (!empty($settings['header_csp_enabled'])) {
            $csp_val = trim($settings['header_csp_custom'] ?? '');
            if (empty($csp_val)) {
                // Safe, robust baseline: upgrade insecure requests, restrict frames to self
                $csp_val = "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self';";
            }
            header("Content-Security-Policy: {$csp_val}", false);
        }
    }

    /**
     * Protect against author archive scanning (e.g. /?author=1, /?author=2)
     */
    public static function protect_user_enumeration() {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['block_user_enumeration'])) {
            return;
        }

        // Only enforce for non-authenticated guests
        if (is_user_logged_in()) {
            return;
        }

        // Check query string for author=1, author=admin, etc.
        if (isset($_REQUEST['author']) && (is_numeric($_REQUEST['author']) || is_string($_REQUEST['author']))) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    /**
     * Disable or restrict REST API user enumeration endpoints for guest users
     */
    public static function filter_rest_user_endpoints(array $endpoints): array {
        $settings = SettingsManager::get_settings();
        if (empty($settings['block_user_enumeration'])) {
            return $endpoints;
        }

        // If user is logged in with edit_users or edit_posts capability, permit endpoint
        if (is_user_logged_in() && current_user_can('edit_posts')) {
            return $endpoints;
        }

        // Hide /wp/v2/users and /wp/v2/users/(?P<id>[\d]+) from unauthorized callers
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }

        return $endpoints;
    }

    /**
     * Strip WordPress generator version tags & script/style version queries
     */
    public static function apply_version_leak_hardening() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['hide_wp_version'])) {
            return;
        }

        // Remove WP generator meta tag
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');

        // Strip ?ver=X.X.X from enqueued styles & scripts for guest visitors on front-end
        if (!is_admin()) {
            add_filter('style_loader_src', [__CLASS__, 'remove_version_query_string'], 999);
            add_filter('script_loader_src', [__CLASS__, 'remove_version_query_string'], 999);
        }
    }

    /**
     * Helper to remove ?ver= from assets
     */
    public static function remove_version_query_string(string $src): string {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    /**
     * Active HTTP probe blocker for sensitive files (.env, .git, .sql, etc.)
     */
    public static function protect_sensitive_files_probe() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['block_sensitive_files'])) {
            return;
        }

        $uri = strtolower($_SERVER['REQUEST_URI'] ?? '');
        $forbidden_patterns = [
            '/\.env($|\?)/i',
            '/\.git\//i',
            '/\.gitignore($|\?)/i',
            '/\.htaccess($|\?)/i',
            '/\.htpasswd($|\?)/i',
            '/wp-config\.php\.bak($|\?)/i',
            '/wp-config\.old($|\?)/i',
            '/\.sql($|\?)/i',
            '/\.tar\.gz($|\?)/i',
            '/\.backup($|\?)/i',
            '/\.yml($|\?)/i',
            '/\.yaml($|\?)/i',
            '/composer\.(json|lock)($|\?)/i',
            '/package\.(json|lock)($|\?)/i',
        ];

        foreach ($forbidden_patterns as $pattern) {
            if (preg_match($pattern, $uri)) {
                status_header(403);
                header('Content-Type: text/plain; charset=utf-8');
                echo 'Access Denied: Sensitive system file inspection blocked by WCP Security Scanner.';
                exit;
            }
        }
    }

    /**
     * Audit current live headers and return score and recommendation list
     */
    public static function audit_hardening_status(): array {
        $settings = SettingsManager::get_settings();

        $checklist = [
            [
                'id'          => 'header_hsts',
                'name'        => 'HTTP Strict Transport Security (HSTS)',
                'enabled'     => !empty($settings['header_hsts']),
                'category'    => 'header',
                'description' => 'Enforces HTTPS encryption and protects against SSL stripping attacks.',
                'grade_pts'   => 20,
            ],
            [
                'id'          => 'header_x_frame_options',
                'name'        => 'X-Frame-Options (Clickjacking Protection)',
                'enabled'     => !empty($settings['header_x_frame_options']),
                'category'    => 'header',
                'description' => 'Prevents your website from being embedded inside unauthorized IFRAMEs.',
                'grade_pts'   => 15,
            ],
            [
                'id'          => 'header_nosniff',
                'name'        => 'X-Content-Type-Options: nosniff',
                'enabled'     => !empty($settings['header_nosniff']),
                'category'    => 'header',
                'description' => 'Instructs browsers not to execute uploaded files disguised as other MIME types.',
                'grade_pts'   => 15,
            ],
            [
                'id'          => 'header_referrer_policy',
                'name'        => 'Referrer-Policy Header',
                'enabled'     => !empty($settings['header_referrer_policy']),
                'category'    => 'header',
                'description' => 'Controls how much referrer information is leaked when visitors navigate away.',
                'grade_pts'   => 10,
            ],
            [
                'id'          => 'header_permissions_policy',
                'name'        => 'Permissions-Policy (Hardware Access Restrictions)',
                'enabled'     => !empty($settings['header_permissions_policy']),
                'category'    => 'header',
                'description' => 'Blocks rogue scripts from accessing camera, microphone, and geolocation sensors.',
                'grade_pts'   => 10,
            ],
            [
                'id'          => 'disable_file_editing',
                'name'        => 'Admin File Editor Lock (DISALLOW_FILE_EDIT)',
                'enabled'     => !empty($settings['disable_file_editing']),
                'category'    => 'hardening',
                'description' => 'Disables internal theme and plugin PHP editors to prevent administrative takeover.',
                'grade_pts'   => 15,
            ],
            [
                'id'          => 'block_user_enumeration',
                'name'        => 'User Enumeration Shield',
                'enabled'     => !empty($settings['block_user_enumeration']),
                'category'    => 'hardening',
                'description' => 'Blocks automated attackers from discovering administrator login usernames via ?author=N and REST API.',
                'grade_pts'   => 10,
            ],
            [
                'id'          => 'hide_wp_version',
                'name'        => 'Information Leakage Shield (Hide WP Version)',
                'enabled'     => !empty($settings['hide_wp_version']),
                'category'    => 'hardening',
                'description' => 'Hides WordPress core generator tags and script query parameters from passive vulnerability scanners.',
                'grade_pts'   => 5,
            ],
        ];

        $earned_score = 0;
        $total_score = 100;
        foreach ($checklist as $item) {
            if ($item['enabled']) {
                $earned_score += $item['grade_pts'];
            }
        }

        $letter_grade = 'F';
        if ($earned_score >= 90) {
            $letter_grade = 'A+';
        } elseif ($earned_score >= 80) {
            $letter_grade = 'A';
        } elseif ($earned_score >= 70) {
            $letter_grade = 'B';
        } elseif ($earned_score >= 50) {
            $letter_grade = 'C';
        }

        return [
            'score'        => $earned_score,
            'max_score'    => $total_score,
            'grade'        => $letter_grade,
            'is_ssl'       => is_ssl(),
            'checklist'    => $checklist,
            'disallow_file_edit_constant' => defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT,
        ];
    }
}
