<?php
namespace WebCareProScanner\Core\Modules;

use WebCareProScanner\Contracts\SecurityModuleInterface;

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
        return [];
    }
}
