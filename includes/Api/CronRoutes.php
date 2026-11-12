<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\System\Cron\CronControlCenter;
use WebCareProScanner\System\Cron\CronExecutionLogger;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\WebCareActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * REST API endpoints for Centralized WP-Cron & Scheduled Tasks Control Center.
 * Strictly gated to administrators with manage_options capability.
 */
class CronRoutes {

    /**
     * Register routes under the plugin REST namespace.
     *
     * @param callable $permission Admin authorization callback.
     */
    public static function register(callable $permission): void {
        $ns = ScannerRoutes::NAMESPACE;

        register_rest_route($ns, '/cron-manager/overview', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_overview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/task/toggle', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_task'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/task/schedule', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_schedule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/task/run', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'run_task'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/bulk', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'bulk_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/retention', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_retention'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/logs', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/logs/clear', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($ns, '/cron-manager/logs/export', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'export_logs'],
            'permission_callback' => $permission,
        ]);
    }

    /**
     * GET /cron-manager/overview
     */
    public static function get_overview(\WP_REST_Request $request) {
        return rest_ensure_response(array_merge(['success' => true], CronControlCenter::get_overview()));
    }

    /**
     * POST /cron-manager/task/toggle
     */
    public static function toggle_task(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $hook    = sanitize_text_field((string) ($params['hook'] ?? ''));
        $enabled = !empty($params['enabled']);

        $res = CronControlCenter::toggle_task($hook, $enabled);
        if (is_wp_error($res)) {
            return $res;
        }

        return rest_ensure_response(array_merge($res, [
            'overview' => CronControlCenter::get_overview(),
        ]));
    }

    /**
     * POST /cron-manager/task/schedule
     */
    public static function update_schedule(\WP_REST_Request $request) {
        $params    = $request->get_json_params() ?: [];
        $hook      = sanitize_text_field((string) ($params['hook'] ?? ''));
        $frequency = sanitize_key((string) ($params['frequency'] ?? ''));

        $extra = [];
        if (isset($params['schedule_time'])) {
            $extra['schedule_time'] = sanitize_text_field((string) $params['schedule_time']);
        }
        if (isset($params['schedule_scan_type'])) {
            $extra['schedule_scan_type'] = sanitize_key((string) $params['schedule_scan_type']);
        }

        $res = CronControlCenter::update_task_schedule($hook, $frequency, $extra);
        if (is_wp_error($res)) {
            return $res;
        }

        return rest_ensure_response(array_merge($res, [
            'overview' => CronControlCenter::get_overview(),
        ]));
    }

    /**
     * POST /cron-manager/task/run
     */
    public static function run_task(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $hook   = sanitize_text_field((string) ($params['hook'] ?? ''));

        $res = CronControlCenter::run_task_now($hook);
        if (is_wp_error($res)) {
            return $res;
        }

        return rest_ensure_response(array_merge($res, [
            'overview' => CronControlCenter::get_overview(),
        ]));
    }

    /**
     * POST /cron-manager/bulk
     */
    public static function bulk_action(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $action = sanitize_key((string) ($params['action'] ?? ''));

        $res = CronControlCenter::bulk_action($action);
        if (is_wp_error($res)) {
            return $res;
        }

        return rest_ensure_response($res);
    }

    /**
     * POST /cron-manager/retention
     */
    public static function update_retention(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $days   = max(7, min(365, intval($params['retention_days'] ?? 30)));

        SettingsManager::save_settings([
            'cron_log_retention_days' => $days,
        ]);

        return rest_ensure_response([
            'success'        => true,
            'retention_days' => $days,
            /* translators: %d: retention days */
            'message'        => sprintf(__('Cron execution log retention updated to %d days.', 'webcare-pro-security'), $days),
        ]);
    }

    /**
     * GET /cron-manager/logs
     */
    public static function get_logs(\WP_REST_Request $request) {
        $filters = [
            'hook'     => sanitize_text_field((string) ($request->get_param('hook') ?? 'all')),
            'status'   => sanitize_key((string) ($request->get_param('status') ?? 'all')),
            'trigger'  => sanitize_key((string) ($request->get_param('trigger') ?? 'all')),
            'search'   => sanitize_text_field((string) ($request->get_param('search') ?? '')),
            'days'     => intval($request->get_param('days') ?? 30),
            'page'     => intval($request->get_param('page') ?? 1),
            'per_page' => intval($request->get_param('per_page') ?? 25),
        ];

        $data = CronExecutionLogger::query_logs($filters);
        return rest_ensure_response(array_merge(['success' => true], $data));
    }

    /**
     * POST /cron-manager/logs/clear
     */
    public static function clear_logs(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $hook   = sanitize_text_field((string) ($params['hook'] ?? 'all'));

        $deleted = CronExecutionLogger::clear_logs($hook);

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::notice(
                'cron_logs_cleared',
                'retention',
                [
                    /* translators: %d: deleted log rows count */
                    'description' => sprintf(__('Cleared %d cron execution log record(s) via Cron Control Center.', 'webcare-pro-security'), $deleted),
                    'hook'        => $hook,
                ]
            );
        }

        return rest_ensure_response([
            'success' => true,
            'deleted' => $deleted,
            /* translators: %d: deleted rows count */
            'message' => sprintf(__('Cleared %d cron execution log entry(s).', 'webcare-pro-security'), $deleted),
        ]);
    }

    /**
     * GET /cron-manager/logs/export
     */
    public static function export_logs(\WP_REST_Request $request) {
        $logs     = CronExecutionLogger::query_logs([
            'hook'     => sanitize_text_field((string) ($request->get_param('hook') ?? 'all')),
            'status'   => sanitize_key((string) ($request->get_param('status') ?? 'all')),
            'trigger'  => sanitize_key((string) ($request->get_param('trigger') ?? 'all')),
            'search'   => sanitize_text_field((string) ($request->get_param('search') ?? '')),
            'days'     => intval($request->get_param('days') ?? 30),
            'page'     => 1,
            'per_page' => 100,
        ]);
        $overview = CronControlCenter::get_overview();

        return rest_ensure_response([
            'success'            => true,
            'webcare_export_type'=> 'cron_manager_telemetry',
            'exported_at_gmt'    => gmdate('c'),
            'site_url'           => get_site_url(),
            'version'            => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'health'             => $overview['health'],
            'tasks'              => $overview['tasks'],
            'logs'               => $logs['items'],
        ]);
    }
}
