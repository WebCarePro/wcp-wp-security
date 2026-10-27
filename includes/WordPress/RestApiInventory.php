<?php
namespace WcpScanner\WordPress;

use WcpScanner\System\AuditLogger;

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

    const OPTION_SETTINGS = 'wcpscan_attack_surface_settings';

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
            'whitelisted_namespaces' => ['wcp-scanner/v1'],
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
     *
     * @param mixed $result
     * @return mixed
     */
    public static function guard_user_enumeration($result) {
        if (!empty($result)) {
            return $result;
        }

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (str_contains($raw_uri, '/wp/v2/users') && !is_user_logged_in()) {
            return new \WP_Error(
                'rest_user_enumeration_forbidden',
                esc_html__('User enumeration via REST API is disabled for unauthenticated visitors.', 'wcp-security-scanner'),
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
        $whitelist = $settings['whitelisted_namespaces'] ?? ['wcp-scanner/v1'];

        foreach ($whitelist as $allowed_ns) {
            if (!empty($allowed_ns) && str_contains($raw_uri, '/' . trim($allowed_ns, '/') . '/')) {
                return $result;
            }
        }

        return new \WP_Error(
            'rest_forbidden_auth_required',
            esc_html__('REST API access requires authentication.', 'wcp-security-scanner'),
            ['status' => 401]
        );
    }

    /**
     * Generate the complete REST API & AJAX attack surface inventory.
     *
     * @return array
     */
    public static function get_inventory(): array {
        $server = rest_get_server();
        $routes = $server->get_routes();

        $namespaces = [];
        $total_routes = count($routes);
        $public_routes_count = 0;
        $unauth_post_routes = 0;
        $inventory = [];

        foreach ($routes as $route_path => $endpoints) {
            $parts = explode('/', ltrim($route_path, '/'));
            $namespace = $parts[0] ?? 'root';
            if (isset($parts[1]) && !str_starts_with($parts[1], '(')) {
                $namespace = $parts[0] . '/' . $parts[1];
            }

            if (!isset($namespaces[$namespace])) {
                $namespaces[$namespace] = [
                    'namespace'    => $namespace,
                    'total_routes' => 0,
                    'is_core'      => str_starts_with($namespace, 'wp/'),
                    'is_wcp'       => str_starts_with($namespace, 'wcp-'),
                ];
            }
            $namespaces[$namespace]['total_routes']++;

            $methods = [];
            $is_public = false;

            foreach ($endpoints as $ep) {
                if (isset($ep['methods'])) {
                    if (is_array($ep['methods'])) {
                        $methods = array_merge($methods, array_keys($ep['methods']));
                    } else {
                        $methods[] = (string) $ep['methods'];
                    }
                }

                // Check permission callback
                $callback = $ep['permission_callback'] ?? null;
                if ($callback === '__return_true' || $callback === null) {
                    $is_public = true;
                }
            }

            $methods = array_values(array_unique($methods));

            if ($is_public) {
                $public_routes_count++;
                if (in_array('POST', $methods, true) || in_array('PUT', $methods, true) || in_array('DELETE', $methods, true)) {
                    $unauth_post_routes++;
                }
            }

            $is_user_endpoint = str_contains($route_path, '/wp/v2/users');

            $inventory[] = [
                'route'           => $route_path,
                'namespace'       => $namespace,
                'methods'         => $methods,
                'is_public'       => $is_public,
                'is_user_enum'    => $is_user_endpoint,
                'is_core'         => str_starts_with($namespace, 'wp/'),
            ];
        }

        // Enumerate nopriv AJAX hooks
        global $wp_filter;
        $ajax_nopriv = [];
        if (isset($wp_filter) && is_array($wp_filter)) {
            foreach ($wp_filter as $hook_name => $hook_obj) {
                if (str_starts_with($hook_name, 'wp_ajax_nopriv_')) {
                    $action = substr($hook_name, strlen('wp_ajax_nopriv_'));
                    $ajax_nopriv[] = [
                        'action'      => sanitize_key($action),
                        'hook'        => $hook_name,
                        'callback_cnt'=> is_object($hook_obj) && isset($hook_obj->callbacks) ? count($hook_obj->callbacks) : 1,
                    ];
                }
            }
        }

        return [
            'total_routes'          => $total_routes,
            'public_routes_count'   => $public_routes_count,
            'unauth_post_routes'    => $unauth_post_routes,
            'total_namespaces'      => count($namespaces),
            'total_nopriv_ajax'     => count($ajax_nopriv),
            'namespaces'            => array_values($namespaces),
            'routes'                => $inventory,
            'ajax_nopriv'           => $ajax_nopriv,
            'settings'              => self::get_settings(),
        ];
    }
}
