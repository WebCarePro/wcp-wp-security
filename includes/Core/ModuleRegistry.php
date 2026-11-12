<?php
namespace WebCareProScanner\Core;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Central micro-kernel discovery and lifecycle registry for WebCare Pro modules and add-ons.
 */
class ModuleRegistry {

    /** @var array<string, SecurityModuleInterface> */
    private static array $modules = [];

    /** @var bool */
    private static bool $discovered = false;

    /** @var bool */
    private static bool $booted = false;

    /** @var array<string, bool> */
    private static array $booted_ids = [];

    /**
     * Register a module instance implementing SecurityModuleInterface.
     *
     * @param SecurityModuleInterface $module
     * @return void
     */
    public static function register(SecurityModuleInterface $module): void {
        $id = sanitize_key($module->get_id());
        if ($id === '') {
            return;
        }
        self::$modules[$id] = $module;
    }

    /**
     * Discover all built-in core/next-gen modules and allow third-party plugins to register add-ons.
     *
     * @return void
     */
    public static function discover_modules(): void {
        if (self::$discovered) {
            return;
        }
        self::$discovered = true;

        $builtin_classes = [
            '\\WebCareProScanner\\Core\\Modules\\CronControlCenterModule',
            '\\WebCareProScanner\\Core\\Modules\\ModularWafModule',
            '\\WebCareProScanner\\Firewall\\NextGen\\IntentChainSentinel',
            '\\WebCareProScanner\\Firewall\\NextGen\\RuntimeSqlRaspEngine',
            '\\WebCareProScanner\\Firewall\\NextGen\\UpgraderDeltaSentinel',
            '\\WebCareProScanner\\Firewall\\NextGen\\CheckoutSkimmerSentinel',
            '\\WebCareProScanner\\Firewall\\NextGen\\ModernApiShield',
            '\\WebCareProScanner\\Firewall\\NextGen\\ResponseDlpSentinel',
        ];

        foreach ($builtin_classes as $cls) {
            if (class_exists($cls)) {
                $instance = new $cls();
                if ($instance instanceof SecurityModuleInterface) {
                    self::register($instance);
                }
            }
        }

        /**
         * Allow first-party vertical packs and third-party companion plugins to register custom modules.
         *
         * @param string $registry_class ModuleRegistry class name for calling ::register().
         */
        if (function_exists('do_action')) {
            do_action('webcareproscan_register_modules', __CLASS__);
        }
    }

    /**
     * Retrieve all registered modules.
     *
     * @return array<string, SecurityModuleInterface>
     */
    public static function get_modules(): array {
        self::discover_modules();
        return self::$modules;
    }

    /**
     * Retrieve a single registered module by ID.
     *
     * @param string $id
     * @return SecurityModuleInterface|null
     */
    public static function get_module(string $id): ?SecurityModuleInterface {
        self::discover_modules();
        return self::$modules[sanitize_key($id)] ?? null;
    }

    /**
     * Determine whether a registered module is enabled in SettingsManager.
     *
     * @param SecurityModuleInterface $module
     * @param array<string, mixed>|null $settings Optional preloaded settings array
     * @return bool
     */
    public static function is_module_enabled(SecurityModuleInterface $module, ?array $settings = null): bool {
        $manifest   = $module->get_manifest();
        $enable_key = (string) ($manifest['enable_key'] ?? '');
        if ($enable_key === '') {
            return true;
        }
        if ($settings === null) {
            $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
                ? \WebCareProScanner\System\SettingsManager::get_settings()
                : [];
        }
        return !empty($settings[$enable_key]);
    }

    /**
     * Boot all applicable and enabled modules once per request.
     *
     * @return void
     */
    public static function boot_all(): void {
        if (self::$booted) {
            return;
        }
        self::$booted = true;

        $modules  = self::get_modules();
        $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];

        foreach ($modules as $id => $module) {
            if (!empty(self::$booted_ids[$id])) {
                continue;
            }
            if (!$module->is_applicable()) {
                continue;
            }
            if (!self::is_module_enabled($module, $settings)) {
                continue;
            }
            self::$booted_ids[$id] = true;
            $module->boot();
        }
    }

    /**
     * Collect default settings from all discovered modules without touching options storage.
     *
     * @return array<string, mixed>
     */
    public static function get_settings_defaults(): array {
        $defaults = [];
        foreach (self::get_modules() as $module) {
            $schema = $module->get_settings_schema();
            if (!is_array($schema)) {
                continue;
            }
            foreach ($schema as $key => $meta) {
                $clean_key = sanitize_key((string) $key);
                if ($clean_key !== '' && is_array($meta) && array_key_exists('default', $meta)) {
                    $defaults[$clean_key] = $meta['default'];
                }
            }
        }
        return $defaults;
    }

    /**
     * Sanitize registered module settings using declared schema rules.
     *
     * @param array<string, mixed> $merged
     * @param array<string, mixed> $current
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    public static function sanitize_module_settings(array $merged, array $current, array $input): array {
        $sanitized = [];
        foreach (self::get_modules() as $module) {
            $schema = $module->get_settings_schema();
            if (!is_array($schema)) {
                continue;
            }
            foreach ($schema as $key => $meta) {
                $k = sanitize_key((string) $key);
                if ($k === '' || !is_array($meta)) {
                    continue;
                }
                $type    = (string) ($meta['type'] ?? 'string');
                $default = $meta['default'] ?? null;
                $raw_val = $merged[$k] ?? $default;

                switch ($type) {
                    case 'bool':
                        $sanitized[$k] = !empty($raw_val);
                        break;

                    case 'int':
                        $val = intval($raw_val);
                        if (isset($meta['min'])) {
                            $val = max(intval($meta['min']), $val);
                        }
                        if (isset($meta['max'])) {
                            $val = min(intval($meta['max']), $val);
                        }
                        $sanitized[$k] = $val;
                        break;

                    case 'enum':
                        $allowed = is_array($meta['options'] ?? null) ? $meta['options'] : [];
                        $val_s   = sanitize_key((string) $raw_val);
                        $sanitized[$k] = in_array($val_s, $allowed, true) ? $val_s : (string) $default;
                        break;

                    case 'array':
                        $arr = is_array($raw_val) ? $raw_val : [];
                        $sanitized[$k] = array_values(array_map('sanitize_text_field', $arr));
                        break;

                    case 'secret':
                        $in_val  = trim((string) ($input[$k] ?? ''));
                        $old_val = class_exists('\\WebCareProScanner\\Security\\SecretVault')
                            ? SecretVault::decrypt((string) ($current[$k] ?? ''))
                            : (string) ($current[$k] ?? '');
                        $plain = ($in_val === '' || $in_val === '••••••••') ? $old_val : sanitize_text_field($in_val);
                        $sanitized[$k] = ($plain === $old_val && !empty($current[$k]))
                            ? $current[$k]
                            : (class_exists('\\WebCareProScanner\\Security\\SecretVault') ? SecretVault::encrypt($plain) : $plain);
                        break;

                    default:
                        $sanitized[$k] = sanitize_text_field((string) $raw_val);
                        break;
                }
            }
        }
        return $sanitized;
    }

    /**
     * Collect human-readable labels for module settings keys for audit logs.
     *
     * @return array<string, string>
     */
    public static function get_setting_labels(): array {
        $labels = [];
        foreach (self::get_modules() as $module) {
            $schema = $module->get_settings_schema();
            if (!is_array($schema)) {
                continue;
            }
            foreach ($schema as $key => $meta) {
                $k = sanitize_key((string) $key);
                if ($k !== '' && !empty($meta['label'])) {
                    $labels[$k] = (string) $meta['label'];
                }
            }
        }
        return $labels;
    }

    /**
     * Collect CRON task definitions declared by all applicable modules.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_cron_tasks(): array {
        $tasks = [];
        foreach (self::get_modules() as $module) {
            $mod_tasks = $module->get_cron_tasks();
            if (!is_array($mod_tasks)) {
                continue;
            }
            foreach ($mod_tasks as $hook => $def) {
                if (is_string($hook) && $hook !== '' && is_array($def)) {
                    $tasks[$hook] = $def;
                }
            }
        }
        return $tasks;
    }

    /**
     * Register all module-provided REST API routes under the plugin namespace.
     * Enforces an administrator permission callback wrapper by default so no module
     * can inadvertently expose an unauthenticated route.
     *
     * @param string $namespace
     * @return void
     */
    public static function register_rest_routes(string $namespace): void {
        foreach (self::get_modules() as $module) {
            $routes = $module->get_rest_routes();
            if (!is_array($routes)) {
                continue;
            }
            foreach ($routes as $route_def) {
                if (empty($route_def['route']) || empty($route_def['callback']) || !is_callable($route_def['callback'])) {
                    continue;
                }
                $route   = '/' . ltrim((string) $route_def['route'], '/');
                $methods = $route_def['methods'] ?? 'GET';
                $perm_cb = (isset($route_def['permission_callback']) && is_callable($route_def['permission_callback']) && $route_def['permission_callback'] !== '__return_true')
                    ? $route_def['permission_callback']
                    : static function () {
                        return current_user_can('manage_options');
                    };

                $args = [
                    'methods'             => $methods,
                    'callback'            => $route_def['callback'],
                    'permission_callback' => $perm_cb,
                ];
                if (!empty($route_def['args']) && is_array($route_def['args'])) {
                    $args['args'] = $route_def['args'];
                }
                register_rest_route($namespace, $route, $args);
            }
        }
    }

    /**
     * Collect MCP tool definitions declared by all applicable modules.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_mcp_tools(): array {
        $tools = [];
        foreach (self::get_modules() as $module) {
            $mod_tools = $module->get_mcp_tools();
            if (!is_array($mod_tools)) {
                continue;
            }
            foreach ($mod_tools as $t) {
                if (!empty($t['name']) && !empty($t['handler']) && is_callable($t['handler'])) {
                    $tools[] = $t;
                }
            }
        }
        return $tools;
    }

    /**
     * Execute a dynamically registered MCP tool from a module if found.
     *
     * @param string $tool_name
     * @param array<string, mixed> $args
     * @return array<string, mixed>|null
     */
    public static function execute_mcp_tool(string $tool_name, array $args): ?array {
        foreach (self::get_mcp_tools() as $tool) {
            if (($tool['name'] ?? '') === $tool_name && is_callable($tool['handler'])) {
                $res = call_user_func($tool['handler'], $args);
                return is_array($res) ? $res : null;
            }
        }
        return null;
    }

    /**
     * Evaluate all applicable, enabled WafEvaluatorInterface modules at plugins_loaded runtime.
     *
     * @param RequestContext $ctx
     * @param array<string, mixed> $settings
     * @return WafVerdict|null
     */
    public static function evaluate_runtime_waf(RequestContext $ctx, array $settings): ?WafVerdict {
        foreach (self::get_modules() as $module) {
            if (!($module instanceof WafEvaluatorInterface)) {
                continue;
            }
            if (!$module->is_applicable() || !self::is_module_enabled($module, $settings)) {
                continue;
            }
            $verdict = $module->evaluate_runtime_request($ctx);
            if ($verdict instanceof WafVerdict) {
                return $verdict;
            }
        }
        return null;
    }

    /**
     * Return full status payload for the Module Ecosystem & Next-Gen Engines UI.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_ecosystem_status(): array {
        $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];
        $list = [];
        foreach (self::get_modules() as $id => $module) {
            $manifest   = $module->get_manifest();
            $enable_key = (string) ($manifest['enable_key'] ?? '');
            $list[]     = [
                'id'           => $id,
                'title'        => (string) ($manifest['title'] ?? $id),
                'description'  => (string) ($manifest['description'] ?? ''),
                'category'     => (string) ($manifest['category'] ?? 'security'),
                'version'      => (string) ($manifest['version'] ?? '2.12.0'),
                'author'       => (string) ($manifest['author'] ?? 'Mir Alamin (WebCare Pro)'),
                'enable_key'   => $enable_key,
                'enabled'      => $enable_key !== '' ? !empty($settings[$enable_key]) : true,
                'applicable'   => $module->is_applicable(),
                'is_waf'       => ($module instanceof WafEvaluatorInterface),
                'cron_count'   => count($module->get_cron_tasks()),
                'route_count'  => count($module->get_rest_routes()),
                'mcp_count'    => count($module->get_mcp_tools()),
                'deep_link'    => (string) ($manifest['deep_link'] ?? ''),
                'badge'        => (string) ($manifest['badge'] ?? ''),
            ];
        }
        return $list;
    }
}
