<?php
namespace WebCareProScanner\WordPress;

use WebCareProScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RestApiInventory
 *
 * REST API & AJAX Attack Surface Matrix.
 * Enumerates all registered REST API endpoints and unauthenticated AJAX hooks.
 * Identifies public attack surfaces, unauthenticated user enumeration routes,
 * and provides 1-click defenses to shield sensitive API namespaces.
 */
class RestApiInventory {

    const OPTION_SETTINGS = 'webcareproscan_attack_surface_settings';

    /**
     * Initialize RestApiInventory hooks.
     */
    public static function init() {
        $settings = self::get_settings();

        // 1. Block unauthenticated REST User Enumeration (/wp/v2/users)
        if (!empty($settings['block_user_enumeration'])) {
            add_filter('rest_authentication_errors', [__CLASS__, 'guard_user_enumeration'], 20);
        }

        // 2. Optional: Global REST API Authentication Requirement
        if (!empty($settings['require_auth_global'])) {
            add_filter('rest_authentication_errors', [__CLASS__, 'enforce_global_rest_auth'], 30);
        }
    }

    /**
     * Get settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'block_user_enumeration' => true,
            'require_auth_global'    => false,
            'whitelisted_namespaces' => ['webcare-pro-security/v1'],
        ];
        $saved = get_option(self::OPTION_SETTINGS, []);
        return is_array($saved) ? array_merge($defaults, $saved) : $defaults;
    }

    /**
     * Update settings.
     *
     * @param array $settings
     * @return bool
     */
    public static function update_settings(array $settings): bool {
        $current = self::get_settings();
        $whitelisted = [];
        if (!empty($settings['whitelisted_namespaces'])) {
            $raw = is_array($settings['whitelisted_namespaces']) ? $settings['whitelisted_namespaces'] : explode("\n", $settings['whitelisted_namespaces']);
            foreach ($raw as $ns) {
                $cleaned = trim(sanitize_text_field($ns));
                if (!empty($cleaned)) {
                    $whitelisted[] = $cleaned;
                }
            }
        }

        $updated = [
            'block_user_enumeration' => !empty($settings['block_user_enumeration']),
            'require_auth_global'    => !empty($settings['require_auth_global']),
            'whitelisted_namespaces' => array_values(array_unique($whitelisted)),
        ];

        return update_option(self::OPTION_SETTINGS, array_merge($current, $updated), false);
    }

    /**
     * Guard against unauthenticated REST user enumeration (/wp/v2/users).
     * Normalizes both pretty permalinks (/wp-json/wp/v2/users) and query-based (?rest_route=/wp/v2/users),
     * as well as nested sub-requests inside /wp/v2/batch payloads.
     *
     * @param mixed $result
     * @return mixed
     */
    public static function guard_user_enumeration($result) {
        if (!empty($result)) {
            return $result;
        }

        if (is_user_logged_in()) {
            return $result;
        }

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? strtolower(esc_url_raw(wp_unslash($_SERVER['REQUEST_URI']))) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $rest_route = isset($_GET['rest_route']) ? strtolower(sanitize_text_field(wp_unslash($_GET['rest_route']))) : '';

        $is_user_enum = str_contains($raw_uri, '/wp/v2/users') || str_contains($rest_route, '/wp/v2/users');

        // Allow /wp/v2/users/me through to standard core authentication error handler
        if ($is_user_enum && (str_contains($raw_uri, '/wp/v2/users/me') || str_contains($rest_route, '/wp/v2/users/me'))) {
            return $result;
        }

        // Check if user enumeration is being smuggled inside a REST batch request
        if (!$is_user_enum && (str_contains($raw_uri, '/batch') || str_contains($rest_route, '/batch'))) {
            $raw_input = @file_get_contents('php://input');
            if (!empty($raw_input)) {
                $batch_data = json_decode($raw_input, true);
                if (is_array($batch_data) && !empty($batch_data['requests']) && is_array($batch_data['requests'])) {
                    foreach ($batch_data['requests'] as $req) {
                        $path = strtolower($req['path'] ?? '');
                        if (str_contains($path, '/wp/v2/users') && !str_contains($path, '/wp/v2/users/me')) {
                            $is_user_enum = true;
                            break;
                        }
                    }
                }
            }
        }

        if ($is_user_enum) {
            return new \WP_Error(
                'rest_user_enumeration_forbidden',
                esc_html__('User enumeration via REST API is disabled for unauthenticated visitors.', 'webcare-pro-security'),
                ['status' => 401]
            );
        }

        return $result;
    }

    /**
     * Enforce global authentication for all REST API endpoints.
     *
     * @param mixed $result
     * @return mixed
     */
    public static function enforce_global_rest_auth($result) {
        if (!empty($result)) {
            return $result;
        }

        if (is_user_logged_in()) {
            return $result;
        }

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $settings = self::get_settings();
        $whitelist = $settings['whitelisted_namespaces'] ?? ['webcare-pro-security/v1'];

        foreach ($whitelist as $allowed_ns) {
            if (!empty($allowed_ns) && str_contains($raw_uri, '/' . trim($allowed_ns, '/') . '/')) {
                return $result;
            }
        }

        return new \WP_Error(
            'rest_forbidden_auth_required',
            esc_html__('REST API access requires authentication.', 'webcare-pro-security'),
            ['status' => 401]
        );
    }

    /**
     * Generate the complete REST API & AJAX attack surface inventory with
     * accurate per-method authentication evaluation, live PHP reflection
     * handler attribution, official origin/vendor classification, and
     * active Modular WAF shielding correlation.
     *
     * @param bool $deep_forensics Include cryptographic file SHA-256 hashes & official checksum lookups.
     * @return array
     */
    public static function get_inventory(bool $deep_forensics = false): array {
        $server = rest_get_server();
        $routes = $server->get_routes();

        $settings      = self::get_settings();
        $component_idx = self::build_component_path_index();
        $modular_map   = self::build_active_modular_rule_map();
        $file_cache    = [];

        $namespaces          = [];
        $total_routes        = count($routes);
        $public_routes_count = 0;
        $unauth_post_routes  = 0;
        $mixed_auth_routes   = 0;
        $inventory           = [];

        foreach ($routes as $route_path => $endpoints) {
            $parts     = explode('/', ltrim($route_path, '/'));
            $namespace = $parts[0] ?? 'root';
            if (isset($parts[1]) && !str_starts_with($parts[1], '(')) {
                $namespace = $parts[0] . '/' . $parts[1];
            }

            $is_core_ns = ($route_path === '/' || str_starts_with($namespace, 'wp/') || str_starts_with($namespace, 'oembed/') || str_starts_with($namespace, 'wp-site-health/') || str_starts_with($namespace, 'wp-block-editor/'));

            if (!isset($namespaces[$namespace])) {
                $namespaces[$namespace] = [
                    'namespace'    => $namespace,
                    'total_routes' => 0,
                    'is_core'      => $is_core_ns,
                    'is_webcare'   => str_starts_with($namespace, 'webcare-'),
                ];
            }
            $namespaces[$namespace]['total_routes']++;

            $methods              = [];
            $public_methods       = [];
            $auth_methods         = [];
            $unauth_write_methods = [];
            $perm_descriptions    = [];
            $primary_callback     = null;
            $is_locked_false      = false;

            foreach ($endpoints as $ep) {
                $ep_methods = [];
                if (isset($ep['methods'])) {
                    if (is_array($ep['methods'])) {
                        $ep_methods = array_keys($ep['methods']);
                    } else {
                        $ep_methods = [(string) $ep['methods']];
                    }
                }
                $methods = array_merge($methods, $ep_methods);

                if ($primary_callback === null && isset($ep['callback'])) {
                    $primary_callback = $ep['callback'];
                }

                // Evaluate permission_callback per handler so public GET never leaks onto authenticated POST
                $perm_cb   = $ep['permission_callback'] ?? null;
                $perm_desc = self::describe_callable($perm_cb);
                if (!in_array($perm_desc, $perm_descriptions, true)) {
                    $perm_descriptions[] = $perm_desc;
                }

                $ep_is_locked = ($perm_cb === '__return_false');
                if ($ep_is_locked) {
                    $is_locked_false = true;
                }

                $ep_is_public = (!$ep_is_locked && ($perm_cb === '__return_true' || $perm_cb === null || $perm_cb === ''));
                if ($ep_is_public) {
                    $public_methods = array_merge($public_methods, $ep_methods);
                    foreach ($ep_methods as $m) {
                        if (in_array(strtoupper($m), ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
                            $unauth_write_methods[] = strtoupper($m);
                        }
                    }
                } else {
                    $auth_methods = array_merge($auth_methods, $ep_methods);
                }
            }

            $methods              = array_values(array_unique($methods));
            $public_methods       = array_values(array_unique($public_methods));
            $auth_methods         = array_values(array_unique($auth_methods));
            $unauth_write_methods = array_values(array_unique($unauth_write_methods));

            $is_canary_decoy  = in_array($namespace, ['webcare-internal/v1', 'webcare-core/v1', 'webcare-admin/v1'], true);
            $is_public        = !empty($public_methods);
            $has_unauth_write = !empty($unauth_write_methods) && !$is_canary_decoy;
            $has_mixed_auth   = ($is_public && !empty($auth_methods) && !$has_unauth_write && !$is_canary_decoy);

            if ($is_public) {
                $public_routes_count++;
            }
            if ($has_unauth_write) {
                $unauth_post_routes++;
            }
            if ($has_mixed_auth) {
                $mixed_auth_routes++;
            }

            $is_user_endpoint = str_contains($route_path, '/wp/v2/users');
            $attribution      = self::reflect_callable_attribution($primary_callback, $component_idx, $deep_forensics, $file_cache);

            // Fallback namespace attribution when handler isClosure inside WP core or unknown
            if ($attribution['owner_type'] === 'unknown' && $is_core_ns) {
                $attribution['owner_component'] = 'WordPress Core';
                $attribution['owner_type']      = 'wp_core';
                $attribution['origin_type']     = 'official_core';
                $attribution['is_official']     = true;
            }

            // Correlate active shields (REST User Enum guard + Canary Decoys + Modular WAF rules)
            $shielded_by = [];
            if ($is_canary_decoy) {
                $shielded_by[] = 'AI Canary Decoy Trap';
            }
            if ($is_user_endpoint && !empty($settings['block_user_enumeration'])) {
                $shielded_by[] = 'REST User Enumeration Shield';
            }
            $norm_route = strtolower(rtrim($route_path, '/'));
            if (isset($modular_map['rest'][$norm_route])) {
                $shielded_by[] = $modular_map['rest'][$norm_route];
            }

            $inventory[] = [
                'route'                => $route_path,
                'namespace'            => $namespace,
                'methods'              => $methods,
                'public_methods'       => $public_methods,
                'auth_methods'         => $auth_methods,
                'unauth_write_methods' => $unauth_write_methods,
                'permission_callbacks' => $perm_descriptions,
                'is_public'            => $is_public,
                'has_unauth_write'     => $has_unauth_write,
                'has_mixed_auth'       => $has_mixed_auth,
                'is_locked'            => $is_locked_false && !$is_public && empty($auth_methods),
                'is_user_enum'         => $is_user_endpoint,
                'is_canary_decoy'      => $is_canary_decoy,
                'is_core'              => $is_core_ns,
                'shielded_by'          => $shielded_by,
                'handler'              => $attribution,
            ];
        }

        // Enumerate nopriv AJAX hooks with full reflection attribution
        global $wp_filter;
        $ajax_nopriv = [];
        if (isset($wp_filter) && is_array($wp_filter)) {
            foreach ($wp_filter as $hook_name => $hook_obj) {
                if (!str_starts_with($hook_name, 'wp_ajax_nopriv_')) {
                    continue;
                }
                $action       = sanitize_key(substr($hook_name, strlen('wp_ajax_nopriv_')));
                $first_cb     = null;
                $callback_cnt = 0;

                if (is_object($hook_obj) && isset($hook_obj->callbacks) && is_array($hook_obj->callbacks)) {
                    foreach ($hook_obj->callbacks as $prio_group) {
                        if (!is_array($prio_group)) {
                            continue;
                        }
                        foreach ($prio_group as $cb_entry) {
                            $callback_cnt++;
                            if ($first_cb === null && isset($cb_entry['function'])) {
                                $first_cb = $cb_entry['function'];
                            }
                        }
                    }
                }

                $attribution = self::reflect_callable_attribution($first_cb, $component_idx, $deep_forensics, $file_cache);
                $shielded_by = [];
                $act_lower   = strtolower($action);
                if (isset($modular_map['ajax'][$act_lower])) {
                    $shielded_by[] = $modular_map['ajax'][$act_lower];
                }

                $ajax_nopriv[] = [
                    'action'       => $action,
                    'hook'         => $hook_name,
                    'callback'     => self::describe_callable($first_cb),
                    'callback_cnt' => max(1, $callback_cnt),
                    'is_core'      => ($attribution['owner_type'] === 'wp_core'),
                    'shielded_by'  => $shielded_by,
                    'handler'      => $attribution,
                ];
            }
        }

        return [
            'total_routes'                 => $total_routes,
            'public_routes_count'          => $public_routes_count,
            'unauth_post_routes'           => $unauth_post_routes,
            'mixed_auth_protected_routes'  => $mixed_auth_routes,
            'total_namespaces'             => count($namespaces),
            'total_nopriv_ajax'            => count($ajax_nopriv),
            'namespaces'                   => array_values($namespaces),
            'routes'                       => $inventory,
            'ajax_nopriv'                  => $ajax_nopriv,
            'settings'                     => $settings,
        ];
    }

    /**
     * Build a normalized filesystem path lookup index mapping installed plugins/themes/WP core
     * with their official origin & vendor metadata from ComponentIntegrityVerifier.
     *
     * @return array
     */
    private static function build_component_path_index(): array {
        $index = [];

        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer')) {
            // Leverage existing component discovery (non-blocking fast cached provenance lookup)
            $comps = \WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer::discover_all_components(false);
            foreach ($comps as $c) {
                if (!empty($c['path'])) {
                    $index[] = [
                        'prefix'          => rtrim(wp_normalize_path($c['path']), '/') . '/',
                        'file_exact'      => !is_dir($c['path']) && file_exists($c['path'] . '.php') ? wp_normalize_path($c['path'] . '.php') : '',
                        'name'            => $c['name'] ?? ($c['slug'] ?? 'Plugin'),
                        'slug'            => $c['slug'] ?? '',
                        'type'            => $c['type'] ?? 'plugin',
                        'origin_type'     => $c['origin_type'] ?? 'custom_unmanaged',
                        'is_official'     => !empty($c['is_official_wporg']),
                        'is_known_vendor' => !empty($c['is_known_vendor']),
                        'vendor_name'     => $c['vendor_name'] ?? null,
                        'checksum_status' => $c['checksum_status'] ?? 'not_available',
                    ];
                }
            }
        }

        // Longest path prefix matches first (handles child themes or nested plugins accurately)
        usort($index, static function ($a, $b) {
            return strlen($b['prefix']) <=> strlen($a['prefix']);
        });

        return $index;
    }

    /**
     * Map currently active Modular WAF rules onto normalized REST routes and AJAX actions.
     */
    private static function build_active_modular_rule_map(): array {
        $map = ['rest' => [], 'ajax' => []];
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return $map;
        }

        $rules = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_active_rules();
        foreach ($rules as $r) {
            $mode = $r['current_mode'] ?? 'off';
            if ($mode === 'off') {
                continue;
            }
            $label = ($r['id'] ?? 'MOD') . ' (' . $mode . ')';
            $cat   = $r['category'] ?? '';
            if ($cat === 'rest_guard' && !empty($r['target_uri'])) {
                $map['rest'][strtolower(rtrim($r['target_uri'], '/'))] = $label;
            } elseif ($cat === 'ajax_shield' && !empty($r['target_value'])) {
                $map['ajax'][strtolower($r['target_value'])] = $label;
            }
        }

        return $map;
    }

    /**
     * Format a human-readable descriptor for a PHP callback / permission_callback.
     */
    private static function describe_callable($callable): string {
        if ($callable === null) {
            return 'missing (public default)';
        }
        if (is_string($callable)) {
            return $callable;
        }
        if (is_array($callable) && count($callable) >= 2) {
            $target = is_object($callable[0]) ? get_class($callable[0]) : (string) $callable[0];
            return $target . '::' . (string) $callable[1];
        }
        if ($callable instanceof \Closure) {
            return 'Closure';
        }
        if (is_object($callable)) {
            return get_class($callable) . '::__invoke';
        }
        return 'callable';
    }

    /**
     * Use PHP Reflection to trace the defining file, line, component owner, and cryptographic forensics
     * of a live REST endpoint or wp_ajax_nopriv handler.
     */
    private static function reflect_callable_attribution($callable, array $comp_index, bool $deep_forensics, array &$file_cache): array {
        $result = [
            'callback'        => self::describe_callable($callable),
            'file'            => null,
            'line'            => null,
            'owner_component' => 'Unknown',
            'owner_type'      => 'unknown',
            'origin_type'     => 'custom_unmanaged',
            'is_official'     => false,
            'is_known_vendor' => false,
            'vendor_name'     => null,
            'file_sha256'     => null,
            'checksum_status' => null,
        ];

        $abs_file = null;
        $line     = null;

        try {
            if ($callable instanceof \Closure || (is_string($callable) && function_exists($callable))) {
                $ref      = new \ReflectionFunction($callable);
                $abs_file = $ref->getFileName() ?: null;
                $line     = $ref->getStartLine() ?: null;
            } elseif (is_array($callable) && count($callable) >= 2 && (is_object($callable[0]) || is_string($callable[0])) && method_exists($callable[0], (string) $callable[1])) {
                $ref      = new \ReflectionMethod($callable[0], (string) $callable[1]);
                $abs_file = $ref->getFileName() ?: null;
                $line     = $ref->getStartLine() ?: null;
            } elseif (is_string($callable) && str_contains($callable, '::')) {
                [$cls, $meth] = explode('::', $callable, 2);
                if (class_exists($cls) && method_exists($cls, $meth)) {
                    $ref      = new \ReflectionMethod($cls, $meth);
                    $abs_file = $ref->getFileName() ?: null;
                    $line     = $ref->getStartLine() ?: null;
                }
            } elseif (is_object($callable) && method_exists($callable, '__invoke')) {
                $ref      = new \ReflectionMethod($callable, '__invoke');
                $abs_file = $ref->getFileName() ?: null;
                $line     = $ref->getStartLine() ?: null;
            }
        } catch (\Throwable $e) {
            return $result;
        }

        if (!$abs_file) {
            return $result;
        }

        $norm_file    = wp_normalize_path($abs_file);
        $abspath_norm = wp_normalize_path(rtrim(ABSPATH, '/\\') . '/');
        $content_norm = wp_normalize_path(rtrim(WP_CONTENT_DIR, '/\\') . '/');

        $rel_path = str_starts_with($norm_file, $content_norm)
            ? ltrim(substr($norm_file, strlen($content_norm)), '/')
            : ltrim(str_replace($abspath_norm, '', $norm_file), '/');

        $result['file'] = $rel_path;
        $result['line'] = $line;

        // Match against installed plugins / themes / mu-plugins
        $matched_comp = null;
        foreach ($comp_index as $c) {
            if ($norm_file === $c['file_exact'] || str_starts_with($norm_file, $c['prefix'])) {
                $matched_comp = $c;
                break;
            }
        }

        if ($matched_comp) {
            $result['owner_component'] = $matched_comp['name'];
            $result['owner_type']      = $matched_comp['type'];
            $result['origin_type']     = $matched_comp['origin_type'];
            $result['is_official']     = $matched_comp['is_official'];
            $result['is_known_vendor'] = $matched_comp['is_known_vendor'];
            $result['vendor_name']     = $matched_comp['vendor_name'];
            $result['checksum_status'] = $matched_comp['checksum_status'];
        } elseif (
            str_starts_with($norm_file, $abspath_norm . WPINC . '/') ||
            str_starts_with($norm_file, $abspath_norm . 'wp-admin/')
        ) {
            $result['owner_component'] = 'WordPress Core';
            $result['owner_type']      = 'wp_core';
            $result['origin_type']     = 'official_core';
            $result['is_official']     = true;
            $result['vendor_name']     = 'WordPress Core';
            $result['checksum_status'] = 'core_runtime';
        }

        // Compute file cryptographic SHA-256 hash & per-file checksum check during deep forensic exports
        if ($deep_forensics) {
            if (!isset($file_cache[$norm_file])) {
                if ($result['owner_type'] === 'wp_core') {
                    $file_cache[$norm_file] = [
                        'file_sha256'     => is_readable($norm_file) ? (@hash_file('sha256', $norm_file) ?: null) : null,
                        'file_md5'        => is_readable($norm_file) ? (@md5_file($norm_file) ?: null) : null,
                        'checksum_status' => class_exists('\\WebCareProScanner\\Integrity\\ChecksumProvider') && \WebCareProScanner\Integrity\ChecksumProvider::is_authentic_core_file($norm_file)
                            ? 'authentic'
                            : 'core_runtime',
                    ];
                } elseif (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ComponentIntegrityVerifier')) {
                    $file_cache[$norm_file] = \WebCareProScanner\Firewall\Modular\ComponentIntegrityVerifier::verify_file_forensics(
                        $norm_file,
                        $matched_comp ?: []
                    );
                } else {
                    $file_cache[$norm_file] = [];
                }
            }

            $forensics = $file_cache[$norm_file];
            $result['file_sha256']     = $forensics['file_sha256'] ?? null;
            $result['file_md5']        = $forensics['file_md5'] ?? null;
            $result['checksum_status'] = $forensics['checksum_status'] ?? $result['checksum_status'];
            if (!empty($forensics['known_vendor_lib'])) {
                $result['known_vendor_lib'] = $forensics['known_vendor_lib'];
            }
        }

        return $result;
    }
}
