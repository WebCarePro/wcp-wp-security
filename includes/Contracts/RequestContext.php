<?php
namespace WebCareProScanner\Contracts;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Normalized immutable-style request snapshot shared across WAF evaluators and custom rule engines.
 */
class RequestContext {

    /** @var string */
    public string $ip = '127.0.0.1';

    /** @var string */
    public string $method = 'GET';

    /** @var string */
    public string $uri = '';

    /** @var string */
    public string $cleanUri = '';

    /** @var string */
    public string $query = '';

    /** @var string */
    public string $userAgent = '';

    /** @var string */
    public string $referer = '';

    /** @var string */
    public string $cookieHeader = '';

    /** @var array<string, string> */
    public array $headers = [];

    /** @var array<string, mixed> */
    public array $params = [];

    /** @var array<int, string> */
    public array $uploadedExtensions = [];

    /** @var string */
    public string $country = '';

    /** @var string */
    public string $asn = '';

    /** @var string */
    public string $ajaxAction = '';

    /** @var string */
    public string $restRoute = '';

    /** @var string */
    public string $targetSlug = '';

    /** @var bool */
    public bool $isLoggedIn = false;

    /** @var bool */
    public bool $isAdmin = false;

    /** @var string[] */
    public array $userRoles = [];

    /** @var string[] */
    public array $userCaps = [];

    /** @var bool */
    public bool $hasWooCart = false;

    /** @var bool */
    public bool $cf_proxied = false;

    /**
     * Build a RequestContext from current PHP / WordPress superglobals.
     *
     * @return self
     */
    public static function from_globals(): self {
        $ctx = new self();

        $ctx->ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

        $ctx->method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])))
            : 'GET';

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Raw URI decomposed cleanly before field sanitization
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $ctx->uri = sanitize_text_field($raw_uri);
        $q_pos    = strpos($raw_uri, '?');
        $raw_clean = strtolower(sanitize_text_field($q_pos === false ? $raw_uri : substr($raw_uri, 0, $q_pos)));
        if (strpos($raw_clean, '/.') !== false || strpos($raw_clean, '//') !== false) {
            $raw_clean = preg_replace('#/+#', '/', $raw_clean);
            $p_parts = explode('/', $raw_clean);
            $p_stack = [];
            foreach ($p_parts as $p_seg) {
                if ($p_seg === '' || $p_seg === '.') {
                    continue;
                }
                if ($p_seg === '..') {
                    array_pop($p_stack);
                } else {
                    $p_stack[] = $p_seg;
                }
            }
            $raw_clean = '/' . implode('/', $p_stack);
        }
        $ctx->cleanUri = $raw_clean;
        $ctx->query    = $q_pos === false ? '' : sanitize_text_field(substr($raw_uri, $q_pos + 1));

        $ctx->userAgent    = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $ctx->referer      = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '';
        $ctx->cookieHeader = isset($_SERVER['HTTP_COOKIE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_COOKIE'])) : '';
        $remote_peer     = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $is_cf_peer      = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            && \WebCareProScanner\Firewall\FirewallEngine::is_cloudflare_ip($remote_peer);
        $ctx->country    = $is_cf_peer && isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY']))) : '';
        $raw_asn         = $is_cf_peer && isset($_SERVER['HTTP_CF_IPASN']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPASN'])) : '';
        $ctx->asn        = $raw_asn !== '' ? ltrim(strtoupper($raw_asn), 'AS') : '';
        $ctx->cf_proxied = $is_cf_peer && !empty($_SERVER['HTTP_CF_RAY']);

        foreach ($_SERVER as $k => $v) {
            if (is_string($k) && strpos($k, 'HTTP_') === 0 && is_string($v)) {
                $hname = strtolower(str_replace('_', '-', substr($k, 5)));
                $ctx->headers[$hname] = sanitize_text_field(wp_unslash($v));
            }
        }
        if (isset($_SERVER['CONTENT_TYPE']) && is_string($_SERVER['CONTENT_TYPE'])) {
            $ctx->headers['content-type'] = sanitize_text_field(wp_unslash($_SERVER['CONTENT_TYPE']));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch WAF context extraction across request parameters
        if (is_array($_REQUEST)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch WAF parameter snapshot
            foreach ($_REQUEST as $pk => $pv) {
                $key_clean = sanitize_key((string) $pk);
                if ($key_clean !== '') {
                    $ctx->params[$key_clean] = $pv;
                }
            }
        }

        // Collect JSON body top-level fields on application/json requests
        $ct = $ctx->headers['content-type'] ?? '';
        if (stripos($ct, 'application/json') !== false) {
            $raw_body = (string) @file_get_contents('php://input');
            if ($raw_body !== '' && strlen($raw_body) <= 262144) {
                $decoded = json_decode($raw_body, true);
                if (is_array($decoded)) {
                    foreach ($decoded as $dk => $dv) {
                        $dkey = sanitize_key((string) $dk);
                        if ($dkey !== '' && !isset($ctx->params[$dkey])) {
                            $ctx->params[$dkey] = $dv;
                        }
                    }
                }
            }
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch file extension extraction from $_FILES
        if (!empty($_FILES) && is_array($_FILES)) {
            $queue = [];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch file metadata audit
            foreach ($_FILES as $fitem) {
                if (isset($fitem['name'])) {
                    $queue[] = $fitem['name'];
                }
            }
            while (!empty($queue)) {
                $next = array_shift($queue);
                if (is_array($next)) {
                    foreach ($next as $sub) {
                        $queue[] = $sub;
                    }
                } elseif (is_string($next) && $next !== '') {
                    $ext = strtolower(pathinfo($next, PATHINFO_EXTENSION));
                    if ($ext !== '') {
                        $ctx->uploadedExtensions[] = $ext;
                    }
                }
            }
            $ctx->uploadedExtensions = array_values(array_unique($ctx->uploadedExtensions));
        }

        // Canonical AJAX & REST tokens
        if (isset($ctx->params['action']) && is_string($ctx->params['action'])) {
            $ctx->ajaxAction = strtolower(trim(sanitize_text_field($ctx->params['action'])));
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch REST query extraction
        $rest_q = isset($_GET['rest_route']) && is_string($_GET['rest_route']) ? strtolower(trim(sanitize_text_field(wp_unslash($_GET['rest_route'])))) : '';
        if ($rest_q !== '') {
            $ctx->restRoute = '/' . ltrim($rest_q, '/');
        } elseif (($pos = strpos($ctx->cleanUri, '/wp-json')) !== false) {
            $ctx->restRoute = '/' . ltrim(substr($ctx->cleanUri, $pos + 8), '/');
        }

        // Resolve target plugin/theme slug heuristic from URI or REST namespace
        if (preg_match('#/wp-content/(?:plugins|themes)/([a-z0-9_-]+)#i', $ctx->cleanUri, $m)) {
            $ctx->targetSlug = strtolower($m[1]);
        } elseif ($ctx->restRoute !== '' && preg_match('#^/([a-z0-9_-]+)/v\d+#i', $ctx->restRoute, $m)) {
            $ctx->targetSlug = strtolower($m[1]);
        }

        // Login state & user roles/capabilities
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            $ctx->isLoggedIn = true;
            $ctx->isAdmin    = function_exists('current_user_can') && current_user_can('manage_options');
            $user            = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
            if ($user && !empty($user->roles) && is_array($user->roles)) {
                $ctx->userRoles = array_map('strtolower', $user->roles);
            }
            if ($user && !empty($user->allcaps) && is_array($user->allcaps)) {
                $ctx->userCaps = array_keys(array_filter($user->allcaps));
            }
        }

        // Ecommerce session cookie detection (WooCommerce, EDD, SureCart)
        if (!empty($_COOKIE) && is_array($_COOKIE)) {
            foreach (array_keys($_COOKIE) as $ck) {
                $ck_str = (string) $ck;
                if (
                    strpos($ck_str, 'wp_woocommerce_session_') === 0
                    || strpos($ck_str, 'woocommerce_items_in_cart') === 0
                    || strpos($ck_str, 'edd_items_in_cart') === 0
                    || strpos($ck_str, 'sc_cart_') === 0
                ) {
                    $ctx->hasWooCart = true;
                    break;
                }
            }
        }

        return $ctx;
    }
}
