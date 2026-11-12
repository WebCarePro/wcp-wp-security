<?php
namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Contract for pluggable internal subsystems and third-party WebCare Pro security modules.
 */
interface SecurityModuleInterface {

    /**
     * Unique machine slug (e.g. 'modular-waf', 'cron-control-center', 'intent-chain-sentinel').
     */
    public function get_id(): string;

    /**
     * Module metadata for the Module Ecosystem dashboard, Setup Studio, and Mega-Menu.
     *
     * @return array<string, mixed>
     */
    public function get_manifest(): array;

    /**
     * Whether runtime prerequisites (PHP extensions, active companion plugins like WooCommerce) are met.
     */
    public function is_applicable(): bool;

    /**
     * Register WordPress hooks and runtime listeners when the module is active.
     */
    public function boot(): void;

    /**
     * Return default settings and sanitization definitions merged into SettingsManager.
     * Schema entries: ['setting_key' => ['default' => mixed, 'type' => 'bool|int|string|array|enum|secret', ...]].
     *
     * @return array<string, array<string, mixed>>
     */
    public function get_settings_schema(): array;

    /**
     * Return REST route definitions registered under /webcare-pro-security/v1/.
     * Permission callbacks default strictly to current_user_can('manage_options').
     *
     * @return array<int, array<string, mixed>>
     */
    public function get_rest_routes(): array;

    /**
     * Return WP-Cron task definitions merged automatically into CronRegistry.
     *
     * @return array<string, array<string, mixed>>
     */
    public function get_cron_tasks(): array;

    /**
     * Return MCP Agent tools merged automatically into MCPAgentService.
     *
     * @return array<int, array<string, mixed>>
     */
    public function get_mcp_tools(): array;
}
