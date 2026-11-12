<?php
namespace WebCareProScanner\Core\Modules;

use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\System\Cron\CronControlCenter;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Reference module adapter exposing the Centralized Cron Control Center via ModuleRegistry.
 */
class CronControlCenterModule implements SecurityModuleInterface {

    public function get_id(): string {
        return 'cron-control-center';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Centralized Cron & Task Control Center', 'webcare-pro-security'),
            'description' => __('Unified governance, recurrence control, manual run triggers, and execution audit logs across all scheduled security jobs.', 'webcare-pro-security'),
            'category'    => 'operations',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'deep_link'   => 'admin.php?page=webcare-pro-cron-manager',
            'badge'       => 'Core Module',
        ];
    }

    public function is_applicable(): bool {
        return class_exists('\\WebCareProScanner\\System\\Cron\\CronControlCenter');
    }

    public function boot(): void {
        // Core filters registered cleanly during Plugin::init().
    }

    public function get_settings_schema(): array {
        return [];
    }

    public function get_rest_routes(): array {
        return [];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_list_cron_jobs',
                'description' => 'List all WebCare Pro scheduled security tasks, recurrence frequencies, next scheduled timestamps, 24h health telemetry, and cron diagnostics.',
                'category'    => 'read',
                'tier'        => 1,
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
                'handler'     => [__CLASS__, 'mcp_list_cron_jobs'],
            ],
            [
                'name'        => 'webcareproscan_toggle_cron_task',
                'description' => 'Enable, disable, or change the recurrence frequency of a WebCare Pro scheduled security task hook.',
                'category'    => 'mutating',
                'tier'        => 3,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'hook'      => ['type' => 'string', 'description' => 'WordPress cron hook name from webcareproscan_list_cron_jobs.'],
                        'enabled'   => ['type' => 'boolean', 'description' => 'Enable or pause the task (respects safeguard locks).'],
                        'frequency' => ['type' => 'string', 'description' => 'Optional recurrence frequency slug (e.g. hourly, twicedaily, daily, weekly).'],
                    ],
                    'required' => ['hook'],
                ],
                'handler'     => [__CLASS__, 'mcp_toggle_cron_task'],
            ],
            [
                'name'        => 'webcareproscan_run_cron_task_now',
                'description' => 'Trigger immediate monitored execution of an allowlisted WebCare Pro scheduled task hook.',
                'category'    => 'mutating',
                'tier'        => 2,
                'isMutating'  => true,
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'hook' => ['type' => 'string', 'description' => 'WordPress cron hook name to run immediately.'],
                    ],
                    'required' => ['hook'],
                ],
                'handler'     => [__CLASS__, 'mcp_run_cron_task_now'],
            ],
        ];
    }

    /** @param array<string, mixed> $args */
    public static function mcp_list_cron_jobs(array $args): array {
        unset($args);
        $overview = CronControlCenter::get_overview();
        return self::format_mcp_result(array_merge(['success' => true], $overview));
    }

    /** @param array<string, mixed> $args */
    public static function mcp_toggle_cron_task(array $args): array {
        $hook = sanitize_text_field((string) ($args['hook'] ?? ''));
        if ($hook === '') {
            return self::format_mcp_result([
                'success' => false,
                'message' => __('Cron hook name is required.', 'webcare-pro-security'),
            ]);
        }
        $res = null;
        if (isset($args['frequency']) && is_string($args['frequency']) && $args['frequency'] !== '') {
            $res = CronControlCenter::update_task_schedule($hook, sanitize_key($args['frequency']));
            if (is_wp_error($res)) {
                return self::format_mcp_result(['success' => false, 'message' => $res->get_error_message()]);
            }
        }
        if (array_key_exists('enabled', $args)) {
            $res = CronControlCenter::toggle_task($hook, !empty($args['enabled']));
            if (is_wp_error($res)) {
                return self::format_mcp_result(['success' => false, 'message' => $res->get_error_message()]);
            }
        }
        return self::format_mcp_result(is_array($res) ? $res : [
            'success' => false,
            'message' => __('Provide enabled (boolean) or frequency to update the cron task.', 'webcare-pro-security'),
        ]);
    }

    /** @param array<string, mixed> $args */
    public static function mcp_run_cron_task_now(array $args): array {
        $hook = sanitize_text_field((string) ($args['hook'] ?? ''));
        if ($hook === '') {
            return self::format_mcp_result([
                'success' => false,
                'message' => __('Cron hook name is required.', 'webcare-pro-security'),
            ]);
        }
        $res = CronControlCenter::run_task_now($hook);
        if (is_wp_error($res)) {
            return self::format_mcp_result(['success' => false, 'message' => $res->get_error_message()]);
        }
        return self::format_mcp_result(is_array($res) ? array_merge(['success' => true], $res) : ['success' => false]);
    }

    /** @param array<string, mixed> $res */
    private static function format_mcp_result(array $res): array {
        return [
            'isError' => empty($res['success']),
            'content' => [['type' => 'text', 'text' => (string) wp_json_encode($res, JSON_PRETTY_PRINT)]],
            'result'  => $res,
        ];
    }
}
