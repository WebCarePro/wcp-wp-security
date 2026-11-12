<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Scanner\Engine;
use WebCareProScanner\Filesystem\FileScanner;
use WebCareProScanner\Integrity\CoreIntegrity;
use WebCareProScanner\Integrity\ImportantFileFIM;
use WebCareProScanner\Integrity\PluginIntegrity;
use WebCareProScanner\Integrity\ThemeIntegrity;
use WebCareProScanner\Database\DatabaseScanner;
use WebCareProScanner\Content\ContentScanner;
use WebCareProScanner\WordPress\WordPressSecurityScanner;
use WebCareProScanner\WordPress\UserScanner;
use WebCareProScanner\WordPress\UpdateScanner;
use WebCareProScanner\System\ServerInfo;
use WebCareProScanner\Backup\DatabaseBackup;
use WebCareProScanner\Findings\CorrelationEngine;
use WebCareProScanner\Findings\RiskScorer;
use WebCareProScanner\Quarantine\QuarantineManager;
use WebCareProScanner\Quarantine\CoreRepairManager;
use WebCareProScanner\Scan\ScanLock;
use WebCareProScanner\Filesystem\UploadsScanner;
use WebCareProScanner\WordPress\CronScanner;
use WebCareProScanner\WordPress\PersistenceScanner;
use WebCareProScanner\Forensics\AttackChainEngine;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Firewall\ThreatIntelNetwork;
use WebCareProScanner\Firewall\VirtualPatchSynthesizer;
use WebCareProScanner\Firewall\HtaccessVaultManager;
use WebCareProScanner\Firewall\HtaccessShield;
use WebCareProScanner\Firewall\RedirectCanaryEngine;
use WebCareProScanner\Filesystem\PathValidator;
use WebCareProScanner\Reports\IncidentReportEngine;

if (!defined('ABSPATH')) {
    exit;
}

class ScannerRoutes {
    const NAMESPACE = 'webcare-pro-security/v1';

    public static function register() {
        $permission = function () {
            return current_user_can('manage_options');
        };

        if (class_exists('\\WebCareProScanner\\Api\\CronRoutes')) {
            \WebCareProScanner\Api\CronRoutes::register($permission);
        }

        // Start scan
        register_rest_route(self::NAMESPACE, '/scan/start', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'start_scan'],
            'permission_callback' => $permission,
        ]);

        // Process file batch
        register_rest_route(self::NAMESPACE, '/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'process_batch'],
            'permission_callback' => $permission,
        ]);

        // Run deep engines (DB, Content, WP Security, Integrity)
        register_rest_route(self::NAMESPACE, '/scan/deep-audit', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'run_deep_audit'],
            'permission_callback' => $permission,
        ]);

        // Get latest summary & findings
        register_rest_route(self::NAMESPACE, '/scan/latest', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_latest_scan'],
            'permission_callback' => $permission,
        ]);

        // Get currently active running scan
        register_rest_route(self::NAMESPACE, '/scan/active', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_active_scan'],
            'permission_callback' => $permission,
        ]);

        // Abort running scan
        register_rest_route(self::NAMESPACE, '/scan/abort', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'abort_scan'],
            'permission_callback' => $permission,
        ]);

        // Scan History & Logs
        register_rest_route(self::NAMESPACE, '/scan/history', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/scan/history/clear', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/scan/history/(?P<id>\d+)', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_scan_log_detail'],
            'permission_callback' => $permission,
        ]);

        // Scan Findings Export Endpoint (JSON, CSV)
        register_rest_route(self::NAMESPACE, '/scan/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'export_scan_results'],
            'permission_callback' => $permission,
        ]);

        // Server Information
        register_rest_route(self::NAMESPACE, '/server-info', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_server_info'],
            'permission_callback' => $permission,
        ]);

        // Diagnostic & Environmental Telemetry Snapshot for Log Analysis
        register_rest_route(self::NAMESPACE, '/telemetry/snapshot', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_telemetry_snapshot'],
            'permission_callback' => $permission,
        ]);

        // System Readiness & Pre-Flight Compatibility Report
        register_rest_route(self::NAMESPACE, '/readiness', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_system_readiness'],
            'permission_callback' => $permission,
        ]);

        // First-Time Welcome Modal Dismissal
        register_rest_route(self::NAMESPACE, '/welcome/dismiss', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'dismiss_welcome_modal'],
            'permission_callback' => $permission,
        ]);

        // Vulnerabilities & Outdated Software Report
        register_rest_route(self::NAMESPACE, '/vulnerabilities/report', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_vulnerabilities_report'],
            'permission_callback' => $permission,
        ]);

        // Database Backup
        register_rest_route(self::NAMESPACE, '/backup/preflight', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_backup_preflight'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/session/start', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'start_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/session/step', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'step_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/session/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_backup_session_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/active', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_active_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/session/cancel', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'cancel_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/create', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'create_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'list_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/delete', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/backup/download', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'download_backup'],
            'permission_callback' => $permission,
        ]);

        // Secure File Content Viewer
        register_rest_route(self::NAMESPACE, '/file/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'view_file_content'],
            'permission_callback' => $permission,
        ]);

        // Secure Post/Page Content Viewer
        register_rest_route(self::NAMESPACE, '/post/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'view_post_content'],
            'permission_callback' => $permission,
        ]);

        // Component Changelog Viewer (Plugins & Themes)
        register_rest_route(self::NAMESPACE, '/component/changelog', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'get_component_changelog'],
            'permission_callback' => $permission,
        ]);

        // Update issue status (ignore, safe, etc.)
        register_rest_route(self::NAMESPACE, '/issues/(?P<id>\d+)', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_issue'],
            'permission_callback' => $permission,
        ]);

        // Quarantine endpoints
        register_rest_route(self::NAMESPACE, '/quarantine', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'quarantine_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/(?P<id>\d+)/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/restored', [
            'methods'             => 'DELETE',
            'callback'            => [__CLASS__, 'clear_restored_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/(?P<id>\d+)', [
            'methods'             => 'DELETE',
            'callback'            => [__CLASS__, 'delete_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine/repair', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'repair_core_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/quarantine', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'list_quarantine'],
            'permission_callback' => $permission,
        ]);

        // Settings Endpoints
        register_rest_route(self::NAMESPACE, '/settings', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/export', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'export_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/import', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'import_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/reset', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'reset_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/settings/trigger-cron', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'trigger_cron_now'],
            'permission_callback' => $permission,
        ]);

        // HTTP Security Headers & Hardening Endpoints
        register_rest_route(self::NAMESPACE, '/hardening/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_hardening_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/hardening/apply-preset', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'apply_hardening_preset'],
            'permission_callback' => $permission,
        ]);

        // AI Threat Analysis & Connection Test Endpoints
        register_rest_route(self::NAMESPACE, '/ai/test', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_ai_connection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/ai/analyze', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'analyze_code_with_ai'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/ai/models', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_ai_models'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/ai/models/update', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_ai_models'],
            'permission_callback' => $permission,
        ]);

        // Firewall (WAF Lite) Endpoints
        register_rest_route(self::NAMESPACE, '/firewall/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/stats', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_log_stats'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/files', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_log_files'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/retention', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_firewall_log_retention'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/prune', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'prune_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/download', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'download_firewall_log_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/delete', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_firewall_log'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/block-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'add_firewall_blocked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/unblock-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'unblock_firewall_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/customer/lookup-block', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'lookup_customer_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/customer/unblock', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'unblock_customer_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/blocklist', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_blocklist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/logs/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'add_firewall_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/whitelist', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_whitelist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/whitelist/remove', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remove_firewall_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/clear-logs', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/toggle', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_firewall'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/save-rule', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_single_firewall_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/roles', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_firewall_roles'],
            'permission_callback' => $permission,
        ]);

        // Server Security (Web Server Level Armor) Endpoints
        register_rest_route(self::NAMESPACE, '/firewall/server-security/config', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_server_security_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/server-security/save', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_server_security_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/server-security/deploy-htaccess', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'deploy_server_security_htaccess'],
            'permission_callback' => $permission,
        ]);

        // Redirect Hack Defense & .htaccess Armor Endpoints
        register_rest_route(self::NAMESPACE, '/firewall/redirect-shield/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_redirect_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/redirect-shield/probe', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'run_redirect_canary_probe'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/redirect-shield/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_htaccess_vault_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/redirect-shield/lock', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_htaccess_lock'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/redirect-shield/heal-urls', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'heal_database_core_urls'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/redirect-shield/snapshot', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'create_htaccess_vault_snapshot'],
            'permission_callback' => $permission,
        ]);

        // Context-Adaptive Firewall (CAF) & StackGuard Endpoints
        register_rest_route(self::NAMESPACE, '/caf/overview', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_caf_overview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/apply-profile', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'apply_caf_profile'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/reprofile', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'reprofile_caf_stack'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/killswitch', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_caf_killswitch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/cloudflare-status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_caf_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/sync-cloudflare', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'sync_caf_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/toggle-circuit-breaker', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_origin_circuit_breaker'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/behavioral-status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_caf_behavioral_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/create-exemption', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'create_caf_exemption'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/caf/toggle-pow-challenge', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_caf_pow_challenge'],
            'permission_callback' => $permission,
        ]);

        // Site Archetype Intelligence & Adaptive Firewall Advisor Endpoints
        register_rest_route(self::NAMESPACE, '/site-advisor', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_site_advisor_evaluation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/site-advisor/apply', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'apply_site_advisor_recommendations'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/site-advisor/rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rollback_site_advisor_snapshot'],
            'permission_callback' => $permission,
        ]);

        // Preload Micro-WAF (Zero-Latency Early Execution) Endpoints
        register_rest_route(self::NAMESPACE, '/firewall/micro-waf/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_micro_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/micro-waf/compile', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'compile_micro_waf'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/micro-waf/install', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'install_micro_waf_preload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/firewall/micro-waf/uninstall', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'uninstall_micro_waf_preload'],
            'permission_callback' => $permission,
        ]);

        // File Integrity Monitoring (FIM) & Code Diff Endpoints
        register_rest_route(self::NAMESPACE, '/integrity/recent-changes', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_integrity_recent_changes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/vault-status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_integrity_vault_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/calibrate-vault', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'calibrate_integrity_vault'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/recheck-drift', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'recheck_integrity_drift'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/diff', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'get_integrity_file_diff'],
            'permission_callback' => $permission,
        ]);

        // One-Click Remediation & Auto-Cure Endpoints
        register_rest_route(self::NAMESPACE, '/remediation/strip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_strip_webshell'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/restore-plugin', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_restore_plugin'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/restore-theme', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_restore_theme'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/restore-core', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_restore_core'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/fix-permissions', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_fix_permissions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/delete-file', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_delete_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/disable-wp-debug', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_disable_wp_debug'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/permissions/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'permissions_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/permissions/fix-all', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'permissions_fix_all'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/persistence/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'persistence_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/persistence/neutralize', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'persistence_neutralize'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/attack-chain/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'attack_chain_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/attack-chain/eradicate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'attack_chain_eradicate'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'virtual_patch_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/apply', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'virtual_patch_apply'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/remove', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'virtual_patch_remove'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/reports/incident-response', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_incident_report'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/backups', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_remediation_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rollback_remediation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/remediation/delete-cron-hook', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_delete_cron_hook'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/comment/moderate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'moderate_comment'],
            'permission_callback' => $permission,
        ]);

        // Database Table & Record Remediation Endpoints (Auto-Backup & Quarantine)
        register_rest_route(self::NAMESPACE, '/database/remediate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/database/row', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/database/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_database_row'],
            'permission_callback' => $permission,
        ]);

        // User Account & Role Remediation Endpoint (Auto-Backup Snapshot & Repair)
        register_rest_route(self::NAMESPACE, '/user/remediate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remediate_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/users/backups', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_user_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/users/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_user_account'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/users/backups/dismiss', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'dismiss_user_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/users/backups/delete', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_user_backup'],
            'permission_callback' => $permission,
        ]);

        // Cloud Threat Intelligence & Community Blacklist Endpoints
        register_rest_route(self::NAMESPACE, '/threat-intel/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_threat_intel_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'sync_threat_intel'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/threat-intel/cves', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_threat_intel_cves'],
            'permission_callback' => $permission,
        ]);

        // Multi-Factor Authentication (2FA) & Login Security Endpoints
        register_rest_route(self::NAMESPACE, '/auth/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_auth_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/setup', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'setup_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/verify-setup', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'verify_and_enable_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'disable_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/revoke-trusted-devices', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_2fa_trusted_devices'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/2fa/regenerate-backup-codes', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'regenerate_user_backup_codes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/unlock-ip', [

            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'unlock_locked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/clear-lockouts', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_all_lockouts'],
            'permission_callback' => $permission,
        ]);

        // Administrator 2FA Governance & Management Endpoints
        register_rest_route(self::NAMESPACE, '/auth/admins', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_admin_directory_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/admin-2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'admin_disable_user_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/admin-2fa/reset', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'admin_reset_user_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/admin-2fa/regenerate-backup-codes', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'admin_regenerate_user_backup_codes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/admin-lockout/clear', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'admin_clear_user_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/policy/save', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_auth_security_policy'],
            'permission_callback' => $permission,
        ]);

        // Session Sentinel Endpoints
        register_rest_route(self::NAMESPACE, '/auth/sessions/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_active_sessions_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/sessions/revoke', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_active_session'],
            'permission_callback' => $permission,
        ]);

        // User Login History & Device Forensics (Encrypted Telemetry)
        register_rest_route(self::NAMESPACE, '/auth/user-history', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_user_login_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/telemetry', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'record_client_telemetry'],
            'permission_callback' => function () {
                return is_user_logged_in() && current_user_can('read');
            },
        ]);

        // Rogue Administrator & Database Anomaly Audit
        register_rest_route(self::NAMESPACE, '/database/rogue-admin-audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_rogue_admin_audit'],
            'permission_callback' => $permission,
        ]);

        // Living-off-the-Land (LotL) Hook Infiltration Audit
        register_rest_route(self::NAMESPACE, '/hooks/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_hook_sentinel_audit'],
            'permission_callback' => $permission,
        ]);

        // DevSecOps Webhook Testing
        register_rest_route(self::NAMESPACE, '/notifications/test-webhook', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_chat_webhook'],
            'permission_callback' => $permission,
        ]);

        // Granular Event Notifications Endpoints
        register_rest_route(self::NAMESPACE, '/notifications/settings', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_notification_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/notifications/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_notification_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/notifications/test-event', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_notification_event'],
            'permission_callback' => $permission,
        ]);

        // Plugin Self-Defense & Anti-Tamper Attestation Endpoints
        register_rest_route(self::NAMESPACE, '/self-defense/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_self_defense_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/self-defense/verify', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'verify_plugin_self_defense'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/self-defense/audit-github', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'audit_self_defense_against_github'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/self-defense/restore-file', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_self_defense_file'],
            'permission_callback' => $permission,
        ]);

        // Cloudflare Edge Defense Endpoints
        register_rest_route(self::NAMESPACE, '/cloudflare/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/verify', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'verify_cloudflare_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/deploy-rules', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'deploy_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/deploy-single-rule', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'deploy_single_cloudflare_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/rate-limiting', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_cloudflare_rate_limiting'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/sync-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'block_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/banned-ips', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_cloudflare_banned_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/unblock-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'unblock_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/purge-cache', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'purge_cloudflare_cache'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/inspect-rules', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'inspect_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'whitelist_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/whitelisted-ips', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_cloudflare_whitelisted_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/remove-whitelisted-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remove_cloudflare_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);


        register_rest_route(self::NAMESPACE, '/cloudflare/disconnect', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'disconnect_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/firewall-events', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/fetch-firewall-events', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'fetch_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/cloudflare/clear-firewall-events', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        // 13. Whitelist & False-Positive Tuning Routes
        register_rest_route(self::NAMESPACE, '/whitelist/rules', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_whitelist_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/whitelist/add', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'add_whitelist_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/whitelist/remove', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'remove_whitelist_rule'],
            'permission_callback' => $permission,
        ]);

        // 14. Behavioral Baseline Engine Routes
        register_rest_route(self::NAMESPACE, '/baseline/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_baseline_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/baseline/calibrate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'calibrate_baseline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/baseline/audit', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'audit_baseline_deviations'],
            'permission_callback' => $permission,
        ]);

        // 15. Remediation Transaction History & Atomic Safe Rollback
        register_rest_route(self::NAMESPACE, '/transactions/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_remediation_transactions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/transactions/rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rollback_remediation_transaction'],
            'permission_callback' => $permission,
        ]);

        // 15b. Unified Vault Status & Key Rotator
        register_rest_route(self::NAMESPACE, '/vault/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_vault_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/vault/rotate-key', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rotate_vault_key'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/vault/rollback-rotation', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rollback_vault_rotation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/vault/reset-rotation', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'reset_vault_rotation'],
            'permission_callback' => $permission,
        ]);

        // 16. Model Context Protocol (MCP) Agent Service Surface
        $mcp_permission = function (\WP_REST_Request $request) {
            $mcp_enabled = (bool) \WebCareProScanner\System\SettingsManager::get('mcp_enabled', false);
            if (!$mcp_enabled) {
                return false;
            }
            if (current_user_can('manage_options')) {
                return true;
            }
            $auth_header = $request->get_header('Authorization');
            if (!empty($auth_header) && preg_match('/Bearer\s+(\S+)/i', $auth_header, $matches)) {
                $token = $matches[1];
                $expected = \WebCareProScanner\System\SettingsManager::get('mcp_token', '');
                if (!empty($expected) && hash_equals($expected, $token)) {
                    return true;
                }
            }
            return false;
        };

        register_rest_route(self::NAMESPACE, '/mcp/tools', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_mcp_tools'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route(self::NAMESPACE, '/mcp/execute', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'execute_mcp_tool'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route(self::NAMESPACE, '/mcp/audit', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_mcp_audit'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route(self::NAMESPACE, '/mcp/audit/clear', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_mcp_audit'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // MCP Staged Actions Approval Gate & Governance Matrix
        register_rest_route(self::NAMESPACE, '/mcp/staged-actions', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_mcp_staged_actions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/mcp/staged-actions/approve', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'approve_mcp_staged_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/mcp/staged-actions/reject', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'reject_mcp_staged_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/mcp/matrix', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'handle_mcp_matrix'],
            'permission_callback' => $permission,
        ]);

        // Red Team Attack Simulation Drill
        register_rest_route(self::NAMESPACE, '/security/run-drill', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'run_security_drill'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/security/drill-results', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_security_drill_results'],
            'permission_callback' => $permission,
        ]);

        // Emergency Incident Containment Protocol
        register_rest_route(self::NAMESPACE, '/containment/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_containment_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/containment/toggle', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_containment'],
            'permission_callback' => $permission,
        ]);

        // 17. Supply-Chain Defense & SBOM Sentinel
        register_rest_route(self::NAMESPACE, '/supply-chain/sbom', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_supply_chain_sbom'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/sbom/calibrate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'calibrate_supply_chain_sbom'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/sbom/isolate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'isolate_supply_chain_anchor'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/gatekeeper', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_supply_chain_gatekeeper'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/gatekeeper/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_supply_chain_gatekeeper_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/gatekeeper/rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rollback_supply_chain_gatekeeper'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/gatekeeper/clear', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'clear_supply_chain_gatekeeper_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/analyze-plugin', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'analyze_supply_chain_plugin'],
            'permission_callback' => $permission,
        ]);

        // Script Inventory & Third-Party Hostname Drift Monitor
        register_rest_route(self::NAMESPACE, '/supply-chain/scripts', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_script_inventory_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/scripts/calibrate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'calibrate_script_inventory'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/scripts/dismiss', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'dismiss_script_drift_alert'],
            'permission_callback' => $permission,
        ]);

        // Offline Dependency Lockfile Auditor
        register_rest_route(self::NAMESPACE, '/supply-chain/lockfiles', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_supply_chain_lockfiles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/supply-chain/lockfiles/scan', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'scan_supply_chain_lockfiles'],
            'permission_callback' => $permission,
        ]);

        // 18. Behavioral WAF & Anti-Automated Abuse (Pillar 3)
        register_rest_route(self::NAMESPACE, '/behavioral/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_behavioral_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/behavioral/route-status', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'set_behavioral_route_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/behavioral/learning-settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_behavioral_learning_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/behavioral/honeytoken/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_honeytoken_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/behavioral/honeytoken/unban', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'unban_honeytoken_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/behavioral/honeytoken/reseed-db-canaries', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'reseed_db_canaries'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/behavioral/rate-limiter/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_rate_limiter_settings'],
            'permission_callback' => $permission,
        ]);

        // Global Cross-IP Distributed Velocity & Under-Attack Shield (2026 AI-Era Defense Pillar 4)
        register_rest_route(self::NAMESPACE, '/defense/distributed-shield/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_distributed_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/distributed-shield/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_distributed_shield_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/distributed-shield/toggle-under-attack', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_under_attack_mode'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/distributed-shield/simulate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'simulate_distributed_attack'],
            'permission_callback' => $permission,
        ]);

        // AST Source-to-Sink Taint Flow Engine (2026 AI-Era Defense Pillar 5)
        register_rest_route(self::NAMESPACE, '/defense/taint-engine/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_taint_engine_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/taint-engine/analyze', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'analyze_code_taint_flow'],
            'permission_callback' => $permission,
        ]);

        // AI SEO, /llms.txt & JSON-LD GEO Shield (2026 AI-Era Defense Pillar 6)
        register_rest_route(self::NAMESPACE, '/defense/geo-shield/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_geo_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/geo-shield/save-baseline', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_geo_llms_baseline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/geo-shield/audit-content', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'audit_geo_content'],
            'permission_callback' => $permission,
        ]);

        // Gutenberg Interactivity API & Block Directives Guard (2026 AI-Era Defense Pillar 7)
        register_rest_route(self::NAMESPACE, '/defense/block-security/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_block_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/block-security/audit', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'audit_block_directives'],
            'permission_callback' => $permission,
        ]);

        // 19. Zero-Trust Identity, Session Forensics & Ephemeral Elevation (Pillar 4)
        register_rest_route(self::NAMESPACE, '/identity/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_identity_forensics_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/revoke-session', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_identity_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/revoke-all-sessions', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_all_identity_sessions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/jit-elevate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'grant_identity_jit_elevation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/jit-revoke', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_identity_jit_elevation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/users/candidates', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_candidate_users_route'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/audit-users', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'audit_identity_privileged_users'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/force-reset', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'force_identity_password_reset'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_identity_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/identity/dismiss-travel-alert', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'dismiss_impossible_travel_alert'],
            'permission_callback' => $permission,
        ]);

        // 20. Continuous Threat Intel Network & Automated Virtual Patching Ecosystem (Pillar 5)
        register_rest_route(self::NAMESPACE, '/threat-intel/network', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_threat_intel_network'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'sync_threat_intel_network'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/threat-intel/reputation-check', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'check_threat_intel_reputation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/synthesized', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_synthesized_virtual_patches'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/synthesize', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'synthesize_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/test-simulation', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_virtual_patch_simulation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/deploy-synthesized', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'deploy_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/toggle-synthesized', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/delete-synthesized', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/cve-lookup', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'virtual_patch_cve_lookup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/virtual-patch/deactivate-component', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'virtual_patch_deactivate_component'],
            'permission_callback' => $permission,
        ]);

        // 20. 2026 AI Threat Defense, MCP Governance & Decoy Ghost Routes (Pillar 3 & Phase 4)
        register_rest_route(self::NAMESPACE, '/defense/ai-status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_ai_defense_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/ghost-routes', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_ghost_routes_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/ghost-routes/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_ghost_routes_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/egress', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_egress_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/egress/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_egress_firewall_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/credentials', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_credential_exposure_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/credentials/scan', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'scan_credential_exposure'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/prompt-guard', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_prompt_guard_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/prompt-guard/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_prompt_guard_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/prompt-guard/test', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'test_prompt_injection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/attack-surface', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_attack_surface_inventory'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/attack-surface/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_attack_surface_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/defense/attack-surface/export', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'export_attack_surface_bundle'],
            'permission_callback' => $permission,
        ]);

        // Phase 5: 72-Hour Reinfection Watchdog Endpoints
        register_rest_route(self::NAMESPACE, '/reinfection-watchdog/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_reinfection_watchdog_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/reinfection-watchdog/register', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'register_reinfection_watch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/reinfection-watchdog/dismiss', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'dismiss_reinfection_watch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/reinfection-watchdog/check-now', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'check_reinfection_watchdog_now'],
            'permission_callback' => $permission,
        ]);

        // Phase 5: "Time-Machine" Local Snapshots & Diff Endpoints
        register_rest_route(self::NAMESPACE, '/snapshots/list', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_local_snapshots_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/snapshots/create', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'create_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/snapshots/compare', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'compare_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/snapshots/diff', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_local_snapshot_diff'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/snapshots/restore', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'restore_local_snapshot_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/snapshots/delete', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        // Phase 5: Domain Reputation & SSL Sentinel Endpoints
        register_rest_route(self::NAMESPACE, '/domain-reputation/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_domain_reputation_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/domain-reputation/check', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'check_domain_reputation_now'],
            'permission_callback' => $permission,
        ]);

        // Phase 6: Threat Correlation Telemetry Hierarchy
        register_rest_route(self::NAMESPACE, '/correlation/hierarchy', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_correlation_hierarchy'],
            'permission_callback' => $permission,
        ]);

        // Phase 6: WebAuthn Passkeys (Biometric FIDO2) Endpoints
        register_rest_route(self::NAMESPACE, '/auth/webauthn/register-options', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'webauthn_register_options'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/webauthn/register-verify', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'webauthn_register_verify'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/webauthn/credentials', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'webauthn_get_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/webauthn/delete-credential', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'webauthn_delete_credential'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/webauthn/login-options', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'webauthn_login_options'],
            'permission_callback' => [__CLASS__, 'check_webauthn_public_rate_limit'],
        ]);

        register_rest_route(self::NAMESPACE, '/auth/webauthn/login-verify', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'webauthn_login_verify'],
            'permission_callback' => [__CLASS__, 'check_webauthn_public_rate_limit'],
        ]);

        // Pillar 1: Authorize-Application REST Passwords & Phishing Sentinel Endpoints
        register_rest_route(self::NAMESPACE, '/auth/app-passwords', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_app_passwords'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/app-passwords/settings', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_app_passwords_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/app-passwords/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_app_passwords_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/app-passwords/revoke', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_app_password'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/auth/app-passwords/revoke-all', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'revoke_all_app_passwords'],
            'permission_callback' => $permission,
        ]);

        // Pillar 2: In-Memory Object Cache (Redis / Memcached / APCu) Sentinel Endpoints
        register_rest_route(self::NAMESPACE, '/integrity/object-cache/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_object_cache_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/object-cache/audit', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'run_object_cache_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/integrity/object-cache/flush', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'flush_object_cache_resync'],
            'permission_callback' => $permission,
        ]);



        // Phase 6: Server Security Verification & Caddy
        register_rest_route(self::NAMESPACE, '/server-security/verify', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'verify_server_security_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/server-security/caddy-config', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_caddy_server_config'],
            'permission_callback' => $permission,
        ]);

        // ==========================================
        // 21. Activity & Forensic Audit Log Engine
        // ==========================================
        register_rest_route(self::NAMESPACE, '/activity-logs', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/activity-logs/verify', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'verify_activity_logs_integrity'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/activity-logs/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [__CLASS__, 'export_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/activity-logs/prune', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'prune_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/activity-logs/acknowledge-tamper', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'acknowledge_activity_tamper_alert'],
            'permission_callback' => $permission,
        ]);

        // Onboarding & Protection Quickstart Wizard Routes
        register_rest_route(self::NAMESPACE, '/wizard/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_wizard_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/wizard/save', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_wizard_settings'],
            'permission_callback' => $permission,
        ]);

        // =========================================================================
        // BEHAVIORAL MODULAR FIREWALL & INTEL VAULT ROUTES
        // =========================================================================

        register_rest_route(self::NAMESPACE, '/modular-waf/scan/start', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'start_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'process_modular_scan_batch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/scan/pause', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'pause_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/scan/resume', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'resume_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/scan/cancel', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'cancel_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_modular_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/toggle', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/bulk-apply', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'bulk_apply_modular_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/custom', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'save_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/code-preview', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_modular_code_preview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/export', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'export_modular_waf_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/autopilot', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_modular_autopilot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/fields', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_modular_visual_fields'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/simulate', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'simulate_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/custom/delete', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'delete_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/cloudflare-push', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'push_custom_rule_to_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modular-waf/rule/parse-wirefilter', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'parse_wirefilter_expression'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modules/ecosystem', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_modules_ecosystem'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/modules/toggle', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'toggle_ecosystem_module'],
            'permission_callback' => $permission,
        ]);

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            \WebCareProScanner\Core\ModuleRegistry::register_rest_routes(self::NAMESPACE);
        }

        // Rescue Assistant, 15m Test Mode & Daily Security Story
        register_rest_route(self::NAMESPACE, '/rescue/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_rescue_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/rescue/trust-action', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rescue_trust_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/rescue/pause-15m', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rescue_pause_15m'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/rescue/resume', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'rescue_resume'],
            'permission_callback' => $permission,
        ]);

        // 1-Click Virtual Shield & Safe Plugin Update with Auto-Backup
        register_rest_route(self::NAMESPACE, '/vulnerabilities/virtual-shield', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'activate_vulnerability_virtual_shield'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/vulnerabilities/safe-update', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'execute_safe_plugin_update'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/vulnerabilities/safe-rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'execute_safe_plugin_rollback'],
            'permission_callback' => $permission,
        ]);
    }

    /**
     * Retrieve status and environmental signals for the Onboarding Protection Wizard.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_wizard_status(\WP_REST_Request $request) {
        $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        
        // Detect live Cloudflare edge proxy
        $is_cloudflare = !empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']);
        $cf_ray = !empty($_SERVER['HTTP_CF_RAY']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_RAY'])) : '';

        // Detect archetype
        $archetype = 'business';
        $saved_archetype = get_option('webcareproscan_site_archetype');
        if (!empty($saved_archetype) && in_array($saved_archetype, ['ecommerce', 'membership', 'business', 'blog'], true)) {
            $archetype = $saved_archetype;
        } elseif (class_exists('WooCommerce')) {
            $archetype = 'ecommerce';
        } elseif (class_exists('MemberPress') || class_exists('LearnDash_Settings_Section') || class_exists('LifterLMS')) {
            $archetype = 'membership';
        }

        $waf_settings = get_option('webcareproscan_waf_settings', []);
        if (!is_array($waf_settings)) {
            $waf_settings = [];
        }

        $current_whitelist = (string) get_option('webcareproscan_waf_whitelisted_ips', '');
        $is_whitelisted = strpos($current_whitelist, $client_ip) !== false;

        $ip_whitelist_entries = get_option('webcareproscan_ip_whitelist', []);
        if (!is_array($ip_whitelist_entries)) {
            $ip_whitelist_entries = [];
        }
        if (empty($ip_whitelist_entries) && !empty($current_whitelist)) {
            $lines = array_filter(array_map('trim', explode("\n", $current_whitelist)));
            foreach ($lines as $line) {
                $ip_whitelist_entries[] = [
                    'ip'         => $line,
                    'label'      => __('Allowlisted Address', 'webcare-pro-security'),
                    'created_at' => current_time('mysql'),
                ];
            }
        }

        $uid = get_current_user_id();
        $support_code = '#WEBCARE-' . strtoupper(substr(md5((string) $uid . wp_salt('auth')), 0, 4));

        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
        $root_domain = class_exists('\WebCareProScanner\Cloudflare\CloudflareService')
            ? \WebCareProScanner\Cloudflare\CloudflareService::extract_root_domain($site_host)
            : $site_host;

        $server_info = class_exists('\WebCareProScanner\System\ServerInfo')
            ? \WebCareProScanner\System\ServerInfo::get_info(false)
            : null;

        $global_settings = class_exists('\WebCareProScanner\System\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];

        $active_plugin_slugs = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_active_plugin_slugs()
            : [];

        // Check if Cloudflare token is stored
        $cf_token_saved = !empty($global_settings['has_cloudflare_key']) || !empty($global_settings['cloudflare_api_token']);
        $cf_zone_id     = (string) ($global_settings['cloudflare_zone_id'] ?? get_option('webcareproscan_cf_zone_id', ''));
        $cloudflare_status = [
            'has_saved_token' => $cf_token_saved,
            'zone_id'         => $cf_zone_id,
            'is_active'       => $is_cloudflare,
        ];

        // Check Preload Micro-WAF status
        $preload_waf_status = [
            'is_active'        => defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE,
            'is_compiled'      => false,
            'auto_prepend_ini' => (string) ini_get('auto_prepend_file'),
            'target_info'      => null,
        ];
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $mw_stat = \WebCareProScanner\Firewall\MicroWafCompiler::get_status();
            $preload_waf_status['is_compiled']      = !empty($mw_stat['is_compiled']);
            $preload_waf_status['is_active']        = !empty($mw_stat['is_active']) || $preload_waf_status['is_active'];
            $preload_waf_status['target_info']      = $mw_stat['target_info'] ?? null;
            $preload_waf_status['auto_prepend_ini'] = $mw_stat['auto_prepend_ini'] ?? $preload_waf_status['auto_prepend_ini'];
        }

        // Outbound Egress status
        $egress_status = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\OutboundEgressFirewall')) {
            $egress_status = \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status();
        }

        // Stack Profile & Capabilities
        $stack_snapshot = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
            $snapshot_obj = $advisor->get_stack_snapshot();
            if (method_exists($snapshot_obj, 'to_array')) {
                $stack_snapshot = $snapshot_obj->to_array();
            }
        }
        $capability_profile = [];
        if (class_exists('\\WebCareProScanner\\Advisor\\SiteCapabilityProfiler')) {
            $capability_profile = \WebCareProScanner\Advisor\SiteCapabilityProfiler::profile();
        }

        $notification_settings = get_option('webcareproscan_notification_settings', []);
        if (!is_array($notification_settings)) {
            $notification_settings = [];
        }

        // Strip raw secrets before sending settings dictionary to frontend
        $safe_settings = $global_settings;
        unset(
            $safe_settings['cloudflare_api_token'],
            $safe_settings['ai_api_key'],
            $safe_settings['openai_api_key'],
            $safe_settings['gemini_api_key'],
            $safe_settings['claude_api_key'],
            $safe_settings['virus_total_api_key'],
            $safe_settings['wpscan_api_key'],
            $safe_settings['mcp_token']
        );

        // PHP Extension & Server Requirement Gate
        $php_ver = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $extensions_checklist = [
            [
                'id'       => 'json',
                'name'     => 'JSON Serialization',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('json'),
                'purpose'  => __('REST API & Vault manifest serialization', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-json",
                'pkg_rpm'  => 'php-json',
            ],
            [
                'id'       => 'mbstring',
                'name'     => 'Multibyte String (mbstring)',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('mbstring'),
                'purpose'  => __('Multi-byte UTF-8 evasion normalization in WAF', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-mbstring",
                'pkg_rpm'  => 'php-mbstring',
            ],
            [
                'id'       => 'openssl',
                'name'     => 'OpenSSL Cryptography',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('openssl'),
                'purpose'  => __('Cryptographic HMAC ledger signatures & TLS inspection', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-openssl",
                'pkg_rpm'  => 'php-openssl',
            ],
            [
                'id'       => 'curl',
                'name'     => 'Client URL Library (cURL)',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('curl'),
                'purpose'  => __('Cloudflare API sync, webhook dispatch & CVE signature updates', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-curl",
                'pkg_rpm'  => 'php-curl',
            ],
            [
                'id'       => 'tokenizer',
                'name'     => 'PHP Tokenizer & AST',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('tokenizer') || function_exists('token_get_all'),
                'purpose'  => __('Required for PHP AST behavioral code analysis', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-tokenizer",
                'pkg_rpm'  => 'php-tokenizer',
            ],
            [
                'id'       => 'sodium',
                'name'     => 'Libsodium (AEAD)',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('sodium'),
                'purpose'  => __('Hardware-accelerated AEAD encryption for Secret Vault', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-sodium",
                'pkg_rpm'  => 'php-sodium',
            ],
            [
                'id'       => 'zip',
                'name'     => 'ZipArchive Engine',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('zip'),
                'purpose'  => __('Safe quarantine packaging & core repair backups', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-zip",
                'pkg_rpm'  => 'php-zip',
            ],
            [
                'id'       => 'zlib',
                'name'     => 'Zlib Compression',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('zlib'),
                'purpose'  => __('Compressed .intel.gz and .manifest.gz vault shards', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-zlib",
                'pkg_rpm'  => 'php-zlib',
            ],
            [
                'id'       => 'intl',
                'name'     => 'Internationalization (intl)',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('intl'),
                'purpose'  => __('IDN Punycode homograph phishing detection', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-intl",
                'pkg_rpm'  => 'php-intl',
            ],
            [
                'id'       => 'image',
                'name'     => 'Image Processing (GD / Imagick)',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('gd') || extension_loaded('imagick'),
                'purpose'  => __('Polyglot image upload payload inspection', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-gd",
                'pkg_rpm'  => 'php-gd',
            ],
            [
                'id'       => 'opcache',
                'name'     => 'Zend OPcache',
                'tier'     => 'runtime',
                'loaded'   => extension_loaded('Zend OPcache'),
                'purpose'  => __('High-performance bytecode caching for 0ms Pre-Boot WAF', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-opcache",
                'pkg_rpm'  => 'php-opcache',
            ],
        ];

        $missing_deb = [];
        $missing_rpm = [];
        $missing_critical = [];
        $missing_recommended = [];

        foreach ($extensions_checklist as $ext) {
            if (!$ext['loaded']) {
                if ($ext['tier'] === 'critical') {
                    $missing_critical[] = $ext['name'];
                } elseif ($ext['tier'] === 'recommended') {
                    $missing_recommended[] = $ext['name'];
                }
                if (!empty($ext['pkg_deb'])) {
                    $missing_deb[] = $ext['pkg_deb'];
                }
                if (!empty($ext['pkg_rpm'])) {
                    $missing_rpm[] = $ext['pkg_rpm'];
                }
            }
        }

        $apt_cmd = !empty($missing_deb)
            ? "sudo apt update && sudo apt install -y " . implode(' ', array_unique($missing_deb)) . " && sudo systemctl restart php{$php_ver}-fpm"
            : "sudo apt update && sudo apt install -y php{$php_ver}-mbstring php{$php_ver}-curl php{$php_ver}-zip && sudo systemctl restart php{$php_ver}-fpm";

        $dnf_cmd = !empty($missing_rpm)
            ? "sudo dnf install -y " . implode(' ', array_unique($missing_rpm)) . " && sudo systemctl restart php-fpm"
            : "sudo dnf install -y php-mbstring php-curl php-zip && sudo systemctl restart php-fpm";

        $memory_limit_str = (string) ini_get('memory_limit');
        $memory_limit_bytes = wp_convert_hr_to_bytes($memory_limit_str);
        $is_memory_sufficient = ($memory_limit_str === '-1' || $memory_limit_bytes === -1 || $memory_limit_bytes >= 134217728); // >= 128MB or unlimited

        $upload_dir_info = wp_upload_dir();
        $upload_dir_writable = !empty($upload_dir_info['basedir']) && wp_is_writable($upload_dir_info['basedir']);

        $php_extension_gate = [
            'php_version'          => PHP_VERSION,
            'extensions'           => $extensions_checklist,
            'all_critical_met'     => empty($missing_critical),
            'missing_critical'     => $missing_critical,
            'missing_recommended'  => $missing_recommended,
            'memory_limit'         => $memory_limit_str,
            'is_memory_sufficient' => $is_memory_sufficient,
            'max_execution_time'   => (int) ini_get('max_execution_time'),
            'upload_dir_writable'  => $upload_dir_writable,
            'commands'             => [
                'apt'    => $apt_cmd,
                'dnf'    => $dnf_cmd,
                'cpanel' => __('cPanel → Software → Select PHP Version → Extensions', 'webcare-pro-security'),
                'plesk'  => __('Plesk → Tools & Settings → PHP Settings → Select Version → Extensions', 'webcare-pro-security'),
            ],
        ];

        // Behavioral Vault & Modular Rules Summary
        $modular_vault_summary = class_exists('\\WebCareProScanner\\Firewall\\Modular\\BehavioralVaultManager')
            ? \WebCareProScanner\Firewall\Modular\BehavioralVaultManager::get_vault_summary()
            : null;

        $modular_rules = class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')
            ? \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_active_rules()
            : [];

        $modular_rules_summary = [
            'total'    => count($modular_rules),
            'enforced' => count(array_filter($modular_rules, fn($r) => ($r['current_mode'] ?? '') === 'enforce')),
            'monitor'  => count(array_filter($modular_rules, fn($r) => ($r['current_mode'] ?? '') === 'monitor')),
            'off'      => count(array_filter($modular_rules, fn($r) => ($r['current_mode'] ?? '') === 'off')),
        ];

        return new \WP_REST_Response([
            'success'               => true,
            'client_ip'             => $client_ip,
            'is_whitelisted'        => $is_whitelisted,
            'ip_whitelist'          => $ip_whitelist_entries,
            'is_cloudflare_active'  => $is_cloudflare,
            'cf_ray'                => $cf_ray,
            'admin_email'           => get_option('admin_email'),
            'site_name'             => get_bloginfo('name'),
            'site_domain'           => $site_host,
            'root_domain'           => $root_domain,
            'detected_archetype'    => $archetype,
            'wizard_completed'      => (bool) get_option('webcareproscan_wizard_completed', false),
            'wizard_current_step'   => (int) get_option('webcareproscan_wizard_current_step', 1),
            'wizard_mode'           => (string) get_option('webcareproscan_wizard_mode', 'developer'),
            'support_code'          => $support_code,
            'waf_settings'          => $waf_settings,
            'server_info'           => $server_info,
            'active_plugin_slugs'   => $active_plugin_slugs,
            'scan_schedule'         => !empty($global_settings['schedule_enabled'])
                ? ($global_settings['schedule_frequency'] ?? 'daily')
                : 'manual',
            'cloudflare_status'     => $cloudflare_status,
            'preload_waf'           => $preload_waf_status,
            'egress_status'         => $egress_status,
            'stack_snapshot'        => $stack_snapshot,
            'capability_profile'    => $capability_profile,
            'notification_settings' => $notification_settings,
            'php_extension_gate'    => $php_extension_gate,
            'modular_vault_summary' => $modular_vault_summary,
            'modular_rules_summary' => $modular_rules_summary,
            'settings'              => $safe_settings,
        ], 200);
    }

    /**
     * Atomic save handler for Onboarding Quickstart settings.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function save_wizard_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];

        // Suppress fragmented option watcher entries so wizard produces 1 clean consolidated event
        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::$suppress_option_watcher = true;
        }

        try {
            // 1. Whitelist Owner IP & Multi-IP/CIDR Entries
            $whitelist_updated = false;
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $existing_ips = (string) get_option('webcareproscan_waf_whitelisted_ips', '');
            $ip_lines = array_filter(array_map('trim', explode("\n", $existing_ips)));

            if (!empty($params['whitelist_ip'])) {
                if (!in_array($client_ip, $ip_lines, true)) {
                    $ip_lines[] = $client_ip;
                    $whitelist_updated = true;
                }
            }

            $custom_whitelist = $request->get_param('ip_whitelist_entries');
            if (is_array($custom_whitelist)) {
                $sanitized_whitelist = [];
                foreach ($custom_whitelist as $entry) {
                    if (!is_array($entry) || empty($entry['ip'])) {
                        continue;
                    }
                    $cand = sanitize_text_field((string) $entry['ip']);
                    if (filter_var($cand, FILTER_VALIDATE_IP) || preg_match('/^[0-9a-fA-F:\.]+\/\d{1,3}$/', $cand)) {
                        $sanitized_whitelist[] = [
                            'ip'         => $cand,
                            'label'      => sanitize_text_field((string) ($entry['label'] ?? __('Setup Studio Whitelist', 'webcare-pro-security'))),
                            'created_at' => sanitize_text_field((string) ($entry['created_at'] ?? current_time('mysql'))),
                        ];
                        if (!in_array($cand, $ip_lines, true)) {
                            $ip_lines[] = $cand;
                            $whitelist_updated = true;
                        }
                    }
                }
                update_option('webcareproscan_ip_whitelist', $sanitized_whitelist);
            }

            if ($whitelist_updated) {
                update_option('webcareproscan_waf_whitelisted_ips', implode("\n", array_unique($ip_lines)));
            }

            // 2. Archetype & Profile
            $archetype = sanitize_key($params['archetype'] ?? 'business');
            update_option('webcareproscan_site_archetype', $archetype);

            // 3. Firewall Toggles & Archetype Smart Rules
            $waf_settings = get_option('webcareproscan_waf_settings', []);
            if (!is_array($waf_settings)) {
                $waf_settings = [];
            }
            $firewall_payload = [];

            if (isset($params['firewall_settings']) && is_array($params['firewall_settings'])) {
                $fs = $params['firewall_settings'];

                $bool_waf_keys = [
                    'waf_enabled', 'waf_learning_mode', 'waf_block_uploads_exec',
                    'waf_enable_brute_force_shield', 'waf_enable_virtual_patching',
                    'waf_block_bad_bots', 'waf_rasp_enabled', 'waf_allow_seo_bots',
                    'waf_caf_block_inactive_plugins', 'waf_caf_lock_dormant_rest',
                    'waf_caf_strict_guest_admin_ajax', 'waf_ecommerce_safe_mode',
                    'waf_woo_carding_protection', 'waf_woo_coupon_protection',
                    'waf_woo_registration_protection', 'waf_woo_cart_flood_protection',
                    'waf_woo_scraping_protection', 'cf_auto_ban_sync', 'cf_ddos_protection_enabled',
                    'waf_smart_rule_48', 'waf_smart_rule_49', 'waf_smart_rule_50',
                    'waf_smart_rule_51', 'waf_smart_rule_52', 'waf_smart_rule_53', 'waf_smart_rule_54',
                ];
                foreach ($bool_waf_keys as $k) {
                    if (isset($fs[$k])) {
                        $waf_settings[$k] = (bool) $fs[$k];
                    }
                }

                $int_waf_keys = [
                    'waf_max_404_per_minute'            => [5, 200],
                    'waf_lockout_duration_mins'         => [1, 10080],
                    'waf_woo_carding_max_attempts'      => [2, 50],
                    'waf_woo_carding_max_declines'      => [1, 25],
                    'waf_woo_coupon_max_failures'       => [3, 50],
                    'waf_woo_cart_max_adds_per_min'     => [5, 300],
                    'waf_woo_reg_max_per_hour'          => [1, 100],
                    'waf_woo_scraping_max_reqs_per_min' => [10, 600],
                    'cf_ddos_threshold'                 => [20, 5000],
                ];
                foreach ($int_waf_keys as $k => $bounds) {
                    if (isset($fs[$k])) {
                        $waf_settings[$k] = max($bounds[0], min($bounds[1], (int) $fs[$k]));
                    }
                }
                update_option('webcareproscan_waf_settings', $waf_settings);

                // Map high-level wizard switches to exact SettingsManager keys
                if (isset($fs['waf_block_uploads_exec'])) {
                    $firewall_payload['waf_block_malicious_uploads'] = (bool) $fs['waf_block_uploads_exec'];
                    $firewall_payload['waf_block_uploads_php_exec']  = (bool) $fs['waf_block_uploads_exec'];
                }
                if (isset($fs['waf_enable_brute_force_shield'])) {
                    $firewall_payload['login_hardening_enabled'] = (bool) $fs['waf_enable_brute_force_shield'];
                    $firewall_payload['waf_login_rate_limit']    = (bool) $fs['waf_enable_brute_force_shield'];
                    $firewall_payload['waf_disable_xmlrpc']      = (bool) $fs['waf_enable_brute_force_shield'];
                }
                if (isset($fs['waf_enable_virtual_patching'])) {
                    $firewall_payload['waf_block_sqli']          = (bool) $fs['waf_enable_virtual_patching'];
                    $firewall_payload['waf_block_xss']           = (bool) $fs['waf_enable_virtual_patching'];
                    $firewall_payload['waf_block_traversal']     = (bool) $fs['waf_enable_virtual_patching'];
                    $firewall_payload['waf_block_php_injection'] = (bool) $fs['waf_enable_virtual_patching'];
                }
                if (isset($fs['waf_block_bad_bots'])) {
                    $firewall_payload['waf_block_fake_bots']    = (bool) $fs['waf_block_bad_bots'];
                    $firewall_payload['waf_block_404_scanners'] = (bool) $fs['waf_block_bad_bots'];
                }

                // Passthrough any explicit settings keys passed
                foreach ($fs as $k => $v) {
                    $clean_k = sanitize_key($k);
                    if (str_starts_with($clean_k, 'waf_') || str_starts_with($clean_k, 'form_') || str_starts_with($clean_k, 'login_')) {
                        if (is_bool($v) || is_numeric($v)) {
                            $firewall_payload[$clean_k] = $v;
                        }
                    }
                }
            }

            // Apply Archetype-specific Smart Rules & CAF Protection Profile
            if ($archetype === 'ecommerce') {
                $firewall_payload['waf_ecommerce_safe_mode']         = true;
                $firewall_payload['waf_woo_carding_protection']      = true;
                $firewall_payload['waf_woo_coupon_protection']       = true;
                $firewall_payload['waf_woo_registration_protection'] = true;
                $firewall_payload['waf_woo_cart_flood_protection']   = true;
                $firewall_payload['waf_woo_scraping_protection']     = true;

                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_ECOMMERCE_HARDENED);
                }
            } elseif ($archetype === 'membership') {
                $firewall_payload['waf_ecommerce_safe_mode'] = true;

                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_ECOMMERCE_HARDENED);
                }
            } elseif ($archetype === 'business' || $archetype === 'blog') {
                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_BALANCED);
                }
            }

            // 4. Outbound Egress Settings
            if (isset($params['egress_settings']) && is_array($params['egress_settings'])) {
                $es = $params['egress_settings'];
                if (class_exists('\\WebCareProScanner\\Firewall\\OutboundEgressFirewall')) {
                    $mode = sanitize_key($es['mode'] ?? 'monitor');
                    if (!in_array($mode, ['disabled', 'monitor', 'enforce'], true)) {
                        $mode = 'monitor';
                    }
                    $allowed_hosts = [];
                    if (!empty($es['allowed_hosts'])) {
                        $raw_hosts = is_array($es['allowed_hosts']) ? $es['allowed_hosts'] : explode("\n", (string) $es['allowed_hosts']);
                        foreach ($raw_hosts as $h) {
                            $cleaned = strtolower(trim(sanitize_text_field($h)));
                            if (!empty($cleaned)) {
                                $allowed_hosts[] = $cleaned;
                            }
                        }
                    }
                    \WebCareProScanner\Firewall\OutboundEgressFirewall::update_settings([
                        'mode'                 => $mode,
                        'block_ssrf_metadata'  => !empty($es['block_ssrf_metadata']),
                        'block_exfil_webhooks' => !empty($es['block_exfil_webhooks']),
                        'block_suspicious_tld' => !empty($es['block_suspicious_tld']),
                        'allowed_hosts'        => $allowed_hosts,
                    ]);
                }
            }

            // 5. Cloudflare Integration (if provided)
            if (!empty($params['cloudflare']['api_token'])) {
                $cf_token = sanitize_text_field($params['cloudflare']['api_token']);
                $cf_zone  = !empty($params['cloudflare']['zone_id']) ? sanitize_text_field($params['cloudflare']['zone_id']) : '';

                // If Zone ID is empty, attempt auto-detect via CloudflareService
                if (empty($cf_zone) && class_exists('\WebCareProScanner\Cloudflare\CloudflareService')) {
                    $verify = \WebCareProScanner\Cloudflare\CloudflareService::verify_zone(null, $cf_token);
                    if (!empty($verify['success']) && !empty($verify['zone_id'])) {
                        $cf_zone = $verify['zone_id'];
                    }
                }

                if (!empty($cf_zone)) {
                    $firewall_payload['cloudflare_enabled']        = true;
                    $firewall_payload['cloudflare_api_token']      = $cf_token;
                    $firewall_payload['cloudflare_zone_id']        = $cf_zone;
                    $firewall_payload['cloudflare_auto_sync_bans'] = true;
                }
            }

            // 6. Scheduled Scan Frequency & Advanced Engine Settings
            $advanced_payload = $firewall_payload;

            if (!empty($params['scan_schedule'])) {
                $freq = sanitize_key($params['scan_schedule']);
                if (in_array($freq, ['hourly', 'twicedaily', 'daily', 'weekly', 'manual'], true)) {
                    $is_enabled = ($freq !== 'manual');
                    $actual_freq = $is_enabled ? $freq : 'daily';
                    $advanced_payload['schedule_enabled']   = $is_enabled;
                    $advanced_payload['schedule_frequency'] = $actual_freq;
                }
            }

            if (isset($params['custom_scan_options']) && is_array($params['custom_scan_options'])) {
                $advanced_payload['custom_scan_options'] = $params['custom_scan_options'];
            }

            if (isset($params['scan_batch_size'])) {
                $advanced_payload['scan_batch_size'] = max(10, min(500, intval($params['scan_batch_size'])));
            }

            if (isset($params['scan_memory_safety_envelope'])) {
                $advanced_payload['scan_memory_safety_envelope'] = sanitize_key($params['scan_memory_safety_envelope']);
            }

            if (isset($params['scan_adaptive_throttling'])) {
                $advanced_payload['scan_adaptive_throttling'] = (bool) $params['scan_adaptive_throttling'];
            }

            if (isset($params['scan_batch_delay_ms'])) {
                $advanced_payload['scan_batch_delay_ms'] = max(0, min(2000, intval($params['scan_batch_delay_ms'])));
            }

            if (isset($params['delete_data_on_uninstall'])) {
                $advanced_payload['delete_data_on_uninstall'] = (bool) $params['delete_data_on_uninstall'];
            }

            if (isset($params['uninstall_drop_tables'])) {
                $advanced_payload['uninstall_drop_tables'] = (bool) $params['uninstall_drop_tables'];
            }

            if (isset($params['uninstall_delete_options'])) {
                $advanced_payload['uninstall_delete_options'] = (bool) $params['uninstall_delete_options'];
            }

            if (isset($params['activity_log_settings']) && is_array($params['activity_log_settings'])) {
                $advanced_payload['activity_log_settings'] = [
                    'retention_days'     => max(7, min(365, intval($params['activity_log_settings']['retention_days'] ?? 30))),
                    'tamper_webhook_url' => esc_url_raw($params['activity_log_settings']['tamper_webhook_url'] ?? ''),
                ];
            }

            if (isset($params['waf_targeted_allowlist_rules'])) {
                $advanced_payload['waf_targeted_allowlist_rules'] = is_string($params['waf_targeted_allowlist_rules'])
                    ? $params['waf_targeted_allowlist_rules']
                    : wp_json_encode($params['waf_targeted_allowlist_rules']);
            }

            // Advanced controls from Step 9, 10, 11, 13
            if (isset($params['advanced_settings']) && is_array($params['advanced_settings'])) {
                $adv = $params['advanced_settings'];
                
                // Login Hardening & 2FA
                if (isset($adv['login_max_retries'])) {
                    $advanced_payload['login_max_retries'] = max(2, min(50, intval($adv['login_max_retries'])));
                }
                if (isset($adv['login_lockout_duration'])) {
                    $advanced_payload['login_lockout_duration'] = max(1, min(10080, intval($adv['login_lockout_duration'])));
                }
                if (isset($adv['auth_2fa_enabled'])) {
                    $advanced_payload['auth_2fa_enabled'] = (bool) $adv['auth_2fa_enabled'];
                }
                if (isset($adv['auth_2fa_enforce_admins'])) {
                    $advanced_payload['auth_2fa_enforce_admins'] = (bool) $adv['auth_2fa_enforce_admins'];
                }
                if (isset($adv['auth_2fa_policy_mode']) && in_array($adv['auth_2fa_policy_mode'], ['immediate', 'grace_period', 'remind_login'], true)) {
                    $advanced_payload['auth_2fa_policy_mode'] = $adv['auth_2fa_policy_mode'];
                }
                if (isset($adv['auth_2fa_grace_days'])) {
                    $advanced_payload['auth_2fa_grace_days'] = max(1, min(90, intval($adv['auth_2fa_grace_days'])));
                }

                // Password security & hardening
                $direct_bools = [
                    'waf_enforce_strong_passwords', 'waf_check_pwned_passwords',
                    'disable_file_editing', 'hide_wp_version', 'block_user_enumeration',
                    'header_hsts', 'header_nosniff', 'header_x_frame_options',
                    'header_referrer_policy', 'header_permissions_policy',
                    'auto_quarantine_critical', 'self_defense_watchdog_enabled'
                ];
                foreach ($direct_bools as $db_key) {
                    if (isset($adv[$db_key])) {
                        $advanced_payload[$db_key] = (bool) $adv[$db_key];
                    }
                }

                // AI Copilot settings
                if (isset($adv['ai_enabled'])) {
                    $advanced_payload['ai_enabled'] = (bool) $adv['ai_enabled'];
                }
                if (!empty($adv['ai_provider']) && in_array($adv['ai_provider'], ['openai', 'gemini', 'claude', 'wp_ai_connect', 'deepseek', 'openrouter'], true)) {
                    $advanced_payload['ai_provider'] = $adv['ai_provider'];
                }
                if (!empty($adv['openai_api_key'])) {
                    $advanced_payload['openai_api_key'] = sanitize_text_field($adv['openai_api_key']);
                }
                if (!empty($adv['gemini_api_key'])) {
                    $advanced_payload['gemini_api_key'] = sanitize_text_field($adv['gemini_api_key']);
                }
                if (!empty($adv['claude_api_key'])) {
                    $advanced_payload['claude_api_key'] = sanitize_text_field($adv['claude_api_key']);
                }
                if (!empty($adv['deepseek_api_key'])) {
                    $advanced_payload['deepseek_api_key'] = sanitize_text_field($adv['deepseek_api_key']);
                }
                if (!empty($adv['openrouter_api_key'])) {
                    $advanced_payload['openrouter_api_key'] = sanitize_text_field($adv['openrouter_api_key']);
                }
                if (!empty($adv['openai_model'])) {
                    $advanced_payload['openai_model'] = sanitize_text_field($adv['openai_model']);
                }
                if (!empty($adv['gemini_model'])) {
                    $advanced_payload['gemini_model'] = sanitize_text_field($adv['gemini_model']);
                }
                if (!empty($adv['claude_model'])) {
                    $advanced_payload['claude_model'] = sanitize_text_field($adv['claude_model']);
                }
                if (!empty($adv['deepseek_model'])) {
                    $advanced_payload['deepseek_model'] = sanitize_text_field($adv['deepseek_model']);
                }
                if (!empty($adv['openrouter_model'])) {
                    $advanced_payload['openrouter_model'] = sanitize_text_field($adv['openrouter_model']);
                }

                // Trusted proxy IPs
                if (!empty($adv['trusted_proxy_ips'])) {
                    $advanced_payload['trusted_proxy_ips'] = sanitize_textarea_field($adv['trusted_proxy_ips']);
                }
                // Excluded paths & extensions
                if (!empty($adv['excluded_paths'])) {
                    $advanced_payload['excluded_paths'] = sanitize_textarea_field($adv['excluded_paths']);
                }
                if (!empty($adv['custom_extensions'])) {
                    $advanced_payload['custom_extensions'] = sanitize_text_field($adv['custom_extensions']);
                }
            }

            // Save via SettingsManager
            if (!empty($advanced_payload) && class_exists('\\WebCareProScanner\\System\\SettingsManager')) {
                \WebCareProScanner\System\SettingsManager::save_settings($advanced_payload);
            }

            // 7. Security Alert Notifications & Webhooks
            if (!empty($params['alerts'])) {
                $alert_email = sanitize_email($params['alerts']['email'] ?? get_option('admin_email'));
                $notif_settings = get_option('webcareproscan_notification_settings', []);
                if (!is_array($notif_settings)) {
                    $notif_settings = [];
                }
                $notif_settings['email_recipient'] = $alert_email;
                $notif_settings['notify_critical'] = !empty($params['alerts']['notify_critical']);
                $notif_settings['notify_logins']   = !empty($params['alerts']['notify_logins']);
                $notif_settings['notify_panic']    = !empty($params['alerts']['notify_panic']);
                update_option('webcareproscan_notification_settings', $notif_settings);

                // Also save to SettingsManager for webhook dispatch
                $webhook_updates = [
                    'email_alerts_enabled' => true,
                    'alert_emails'         => $alert_email,
                ];
                if (!empty($params['alerts']['slack_webhook_url'])) {
                    $webhook_updates['slack_enabled']     = true;
                    $webhook_updates['slack_webhook_url'] = esc_url_raw($params['alerts']['slack_webhook_url']);
                }
                if (!empty($params['alerts']['discord_webhook_url'])) {
                    $webhook_updates['discord_enabled']     = true;
                    $webhook_updates['discord_webhook_url'] = esc_url_raw($params['alerts']['discord_webhook_url']);
                }
                if (!empty($params['alerts']['generic_webhook_url'])) {
                    $webhook_updates['generic_webhook_enabled'] = true;
                    $webhook_updates['generic_webhook_url']     = esc_url_raw($params['alerts']['generic_webhook_url']);
                }
                if (class_exists('\\WebCareProScanner\\System\\SettingsManager')) {
                    \WebCareProScanner\System\SettingsManager::save_settings($webhook_updates);
                }
            }

            // 8. Recompile Pre-Boot Micro-WAF Snapshot with all updated exemptions & rules
            if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
                \WebCareProScanner\Firewall\MicroWafCompiler::compile();
            }

            // 9. Save Step Progress & Completion Status
            if (!empty($params['current_step'])) {
                update_option('webcareproscan_wizard_current_step', max(1, min(14, intval($params['current_step']))));
            }
            if (!empty($params['wizard_mode'])) {
                update_option('webcareproscan_wizard_mode', sanitize_key($params['wizard_mode']));
            }
            if (empty($params['is_intermediate_step'])) {
                update_option('webcareproscan_wizard_completed', true);
            }
        } finally {
            if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                \WebCareProScanner\System\WebCareActivityLogger::$suppress_option_watcher = false;
            }
        }

        // Consolidated single master activity event for initial security onboarding (only upon full completion)
        if (empty($params['is_intermediate_step']) && class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $alert_email = sanitize_email($params['alerts']['email'] ?? get_option('admin_email'));
            $arch_label = ucfirst($archetype ?? 'business');
            $event_desc = sprintf(
                /* translators: 1: Site archetype profile label, 2: Client IP address, 3: Notification email */
                __('Completed initial security onboarding setup with %1$s profile: enabled core firewall shields, whitelisted administrator IP (%2$s), and configured security alerts for %3$s.', 'webcare-pro-security'),
                $arch_label,
                $client_ip,
                $alert_email
            );
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'onboarding_wizard_completed',
                'settings',
                [
                    'archetype'       => $archetype ?? 'business',
                    'whitelisted_ip'  => !empty($params['whitelist_ip']) ? $client_ip : null,
                    'alert_email'     => $alert_email,
                    'firewall_active' => true,
                    'description'     => $event_desc,
                ]
            );
        }

        return new \WP_REST_Response([
            'success' => true,
            'message' => __('WebCare Protection Quickstart successfully configured.', 'webcare-pro-security'),
        ], 200);
    }

    /**
     * Initialize a new behavioral intelligence scan session.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function start_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $result = \WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer::start_scan($params);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Process a chunked batch of files in the active behavioral scan session.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function process_modular_scan_batch(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $batch_size = max(10, min(500, intval($params['batch_size'] ?? 400)));
        $result = \WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer::process_batch($batch_size);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Pause an active behavioral AST scan session cleanly.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function pause_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer::pause_scan(), 200);
    }

    /**
     * Resume a paused or stale behavioral AST scan session.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function resume_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer::resume_scan(), 200);
    }

    /**
     * Cancel and discard an in-progress behavioral AST scan session while preserving previously sealed Vault rules.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function cancel_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer::cancel_scan(), 200);
    }

    /**
     * Shared helper assembling enriched modular rules, component provenance/checksum dossiers,
     * and trust summary telemetry without duplicating logic across status and export routes.
     *
     * @param bool $deep_verify Whether to execute full disk & WP.org checksum verification.
     * @return array
     */
    private static function build_modular_dossier_context(bool $deep_verify = false): array {
        $vault_mgr = '\\WebCareProScanner\\Firewall\\Modular\\BehavioralVaultManager';
        $synth     = '\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer';
        $analyzer  = '\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer';
        $verifier  = '\\WebCareProScanner\\Firewall\\Modular\\ComponentIntegrityVerifier';

        $vault_summary = class_exists($vault_mgr) ? $vault_mgr::get_vault_summary() : null;
        $rules         = class_exists($synth) ? $synth::get_active_rules() : [];
        $raw_inv       = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_INVENTORY) ?: []) : [];

        if (empty($raw_inv) && class_exists($analyzer) && method_exists($analyzer, 'discover_all_components')) {
            $raw_inv = $analyzer::discover_all_components($deep_verify);
        }

        $endpoint_map  = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_ENDPOINTS) ?: []) : [];
        $findings      = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_FINDINGS) ?: []) : [];
        $scan_progress = class_exists($analyzer) ? $analyzer::get_scan_progress() : null;

        $endpoint_counts = [];
        if (is_array($endpoint_map)) {
            foreach ($endpoint_map as $ep) {
                $comp_name = $ep['component'] ?? '';
                if ($comp_name !== '') {
                    $endpoint_counts[$comp_name] = ($endpoint_counts[$comp_name] ?? 0) + 1;
                }
            }
        }

        $finding_counts = [];
        if (is_array($findings)) {
            foreach ($findings as $fd) {
                $comp_name = $fd['component'] ?? '';
                if ($comp_name !== '') {
                    $finding_counts[$comp_name] = ($finding_counts[$comp_name] ?? 0) + 1;
                }
            }
        }

        $rules_list  = is_array($rules) ? array_values($rules) : [];
        $rule_counts = [];
        foreach ($rules_list as $rl) {
            $comp_name = $rl['origin_component'] ?? ($rl['target_component'] ?? '');
            if ($comp_name !== '' && ($rl['current_mode'] ?? 'off') !== 'off') {
                $rule_counts[$comp_name] = ($rule_counts[$comp_name] ?? 0) + 1;
            }
        }

        $inventory        = [];
        $comp_by_name     = [];
        $trust_summary    = [
            'official_wporg_count'    => 0,
            'known_vendor_count'      => 0,
            'custom_unmanaged_count'  => 0,
            'checksum_verified_count' => 0,
            'tamper_alert_count'      => 0,
            'outdated_count'          => 0,
        ];

        if (is_array($raw_inv)) {
            foreach ($raw_inv as $comp) {
                if (!is_array($comp)) {
                    continue;
                }
                // Always attach/refresh provenance & checksum status when missing or during deep verification
                if (class_exists($verifier) && ($deep_verify || !isset($comp['origin_type']))) {
                    $comp = array_merge($comp, $verifier::verify_component($comp, $deep_verify));
                }

                $name = $comp['name'] ?? ($comp['slug'] ?? '');
                $comp['endpoints_count'] = $endpoint_counts[$name] ?? 0;
                $comp['findings_count']  = $finding_counts[$name] ?? 0;
                $comp['rules_count']     = $rule_counts[$name] ?? 0;

                if (!empty($comp['is_official_wporg'])) {
                    $trust_summary['official_wporg_count']++;
                } elseif (!empty($comp['is_known_vendor'])) {
                    $trust_summary['known_vendor_count']++;
                } else {
                    $trust_summary['custom_unmanaged_count']++;
                }

                if (!empty($comp['checksum_verified'])) {
                    $trust_summary['checksum_verified_count']++;
                }
                if (($comp['trust_tier'] ?? '') === 'tamper_alert') {
                    $trust_summary['tamper_alert_count']++;
                }
                if (!empty($comp['update_available'])) {
                    $trust_summary['outdated_count']++;
                }

                $inventory[] = $comp;
                if ($name !== '') {
                    $comp_by_name[$name] = $comp;
                }
            }
        }

        // Enrich rules that are missing provenance/hash metadata (e.g. from pre-upgrade scans or custom rules)
        $findings_by_file = [];
        if (is_array($findings)) {
            foreach ($findings as $idx => $fd) {
                if (!empty($fd['file'])) {
                    $findings_by_file[$fd['file']] = $fd;
                }
            }
        }

        foreach ($rules_list as &$rl) {
            if (!isset($rl['file_sha256']) || !isset($rl['checksum_status']) || $deep_verify) {
                $matched_finding = !empty($rl['file']) ? ($findings_by_file[$rl['file']] ?? []) : [];
                if (class_exists($synth) && method_exists($synth, 'enrich_synthesized_rule')) {
                    $rl = $synth::enrich_synthesized_rule($rl, $matched_finding, $comp_by_name);
                }
            }
        }
        unset($rl);

        return [
            'vault_summary' => $vault_summary,
            'rules'         => $rules_list,
            'inventory'     => $inventory,
            'comp_by_name'  => $comp_by_name,
            'trust_summary' => $trust_summary,
            'endpoint_map'  => is_array($endpoint_map) ? array_values($endpoint_map) : [],
            'findings'      => is_array($findings) ? array_values($findings) : [],
            'scan_progress' => $scan_progress,
        ];
    }

    /**
     * Build a deduplicated cryptographic hash index for all PHP files referenced by rules and findings.
     */
    private static function build_file_hash_index(array $rules, array $findings): array {
        $verifier = '\\WebCareProScanner\\Firewall\\Modular\\ComponentIntegrityVerifier';
        $index    = [];

        foreach ($findings as $fd) {
            $rel = $fd['file'] ?? '';
            if ($rel === '') {
                continue;
            }
            if (!isset($index[$rel])) {
                $forensics = (!empty($fd['file_sha256']) && !empty($fd['file_md5']))
                    ? [
                        'file_sha256'       => $fd['file_sha256'],
                        'file_md5'          => $fd['file_md5'],
                        'file_size'         => $fd['file_size'] ?? 0,
                        'file_mtime'        => $fd['file_mtime'] ?? null,
                        'checksum_status'   => $fd['checksum_status'] ?? 'unmanaged_custom',
                        'expected_checksum' => $fd['expected_checksum'] ?? null,
                        'known_vendor_lib'  => $fd['known_vendor_lib'] ?? null,
                    ]
                    : (class_exists($verifier) ? $verifier::verify_file_forensics($rel) : []);

                $index[$rel] = array_merge([
                    'file'                => $rel,
                    'component'           => $fd['component'] ?? '',
                    'origin_type'         => $fd['origin_type'] ?? 'custom_unmanaged',
                    'finding_types'       => [],
                    'referenced_by_rules' => [],
                ], $forensics);
            }
            if (!empty($fd['type']) && !in_array($fd['type'], $index[$rel]['finding_types'], true)) {
                $index[$rel]['finding_types'][] = $fd['type'];
            }
        }

        foreach ($rules as $rl) {
            $rel = $rl['file'] ?? '';
            if ($rel === '') {
                continue;
            }
            if (!isset($index[$rel])) {
                $forensics = class_exists($verifier) ? $verifier::verify_file_forensics($rel) : [];
                $index[$rel] = array_merge([
                    'file'                => $rel,
                    'component'           => $rl['origin_component'] ?? '',
                    'origin_type'         => $rl['component_origin_type'] ?? 'custom_unmanaged',
                    'finding_types'       => [],
                    'referenced_by_rules' => [],
                ], $forensics);
            }
            if (!empty($rl['id']) && !in_array($rl['id'], $index[$rel]['referenced_by_rules'], true)) {
                $index[$rel]['referenced_by_rules'][] = $rl['id'];
            }
        }

        return $index;
    }

    /**
     * Collect firewall & pre-boot log correlation telemetry for false-positive analysis.
     * Pseudonymizes client IPs via keyed SHA-256 prefix so exported dossiers stay privacy-safe.
     */
    private static function build_modular_log_analysis_context(): array {
        global $wpdb;

        $salt        = function_exists('wp_salt') ? wp_salt('auth') : 'webcare_log_salt';
        $hash_ip     = static fn(string $ip): string => $ip !== '' ? substr(hash('sha256', $salt . $ip), 0, 12) : '';
        $records     = [];
        $seen_ids    = [];
        $hits_by_rule = [];
        $hits_by_uri  = [];
        $hits_by_act  = [];
        $top_uas      = [];

        $record_event = static function (array $row) use (&$records, &$seen_ids, &$hits_by_rule, &$hits_by_uri, &$hits_by_act, &$top_uas) {
            $dedup_key = ($row['incident_id'] ?? '') . '|' . ($row['created_at'] ?? '') . '|' . ($row['request_uri'] ?? '');
            if (isset($seen_ids[$dedup_key])) {
                return;
            }
            $seen_ids[$dedup_key] = true;
            $records[] = $row;

            $rid = $row['rule_id'] ?: ($row['rule_category'] ?: 'UNKNOWN');
            if (!isset($hits_by_rule[$rid])) {
                $hits_by_rule[$rid] = [
                    'count'          => 0,
                    'last_seen'      => $row['created_at'] ?? '',
                    'sample_uris'    => [],
                    'methods'        => [],
                    'actions'        => [],
                ];
            }
            $hits_by_rule[$rid]['count']++;
            $uri_clean = strtok((string) ($row['request_uri'] ?? '/'), '?') ?: '/';
            if (count($hits_by_rule[$rid]['sample_uris']) < 5 && !in_array($row['request_uri'] ?? '', $hits_by_rule[$rid]['sample_uris'], true)) {
                $hits_by_rule[$rid]['sample_uris'][] = $row['request_uri'] ?? '';
            }
            if (!empty($row['request_method']) && !in_array($row['request_method'], $hits_by_rule[$rid]['methods'], true)) {
                $hits_by_rule[$rid]['methods'][] = $row['request_method'];
            }
            if (!empty($row['action_taken']) && !in_array($row['action_taken'], $hits_by_rule[$rid]['actions'], true)) {
                $hits_by_rule[$rid]['actions'][] = $row['action_taken'];
            }

            $hits_by_uri[$uri_clean] = ($hits_by_uri[$uri_clean] ?? 0) + 1;
            $act = $row['action_taken'] ?? 'unknown';
            $hits_by_act[$act] = ($hits_by_act[$act] ?? 0) + 1;
            if (!empty($row['user_agent'])) {
                $ua = substr((string) $row['user_agent'], 0, 120);
                $top_uas[$ua] = ($top_uas[$ua] ?? 0) + 1;
            }
        };

        // 1. Query JSON WafFileLogger (last 30 days, modular & endpoint-relevant incidents)
        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $json_res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['range' => '30d'], 150, 0);
            $items    = is_array($json_res['logs'] ?? null) ? $json_res['logs'] : [];
            foreach ($items as $item) {
                $rid   = (string) ($item['rule_id'] ?? '');
                $rcat  = (string) ($item['rule_category'] ?? '');
                $rdesc = (string) ($item['rule_description'] ?? '');
                $ruri  = (string) ($item['request_uri'] ?? '');
                $is_relevant = str_starts_with($rid, 'MOD-')
                    || stripos($rcat, 'modular') !== false
                    || str_contains($rdesc, 'MOD-')
                    || str_contains($ruri, 'admin-ajax.php')
                    || str_contains($ruri, '/wp-json/');

                if ($is_relevant) {
                    $record_event([
                        'source'           => 'waf_file_logger',
                        'incident_id'      => $item['incident_id'] ?? ($item['id'] ?? ''),
                        'ip_hash'          => $hash_ip((string) ($item['ip_address'] ?? '')),
                        'rule_id'          => $rid,
                        'rule_name'        => $item['rule_name'] ?? '',
                        'rule_category'    => $rcat,
                        'rule_description' => $rdesc,
                        'request_method'   => $item['request_method'] ?? 'GET',
                        'request_uri'      => $ruri,
                        'http_status_code' => $item['http_status_code'] ?? 403,
                        'http_referer'     => $item['http_referer'] ?? null,
                        'payload_sample'   => $item['payload_sample'] ?? '',
                        'user_agent'       => $item['user_agent'] ?? '',
                        'action_taken'     => $item['action_taken'] ?? '',
                        'is_authenticated' => !empty($item['is_authenticated']),
                        'user_role'        => $item['user_role'] ?? '',
                        'created_at'       => $item['created_at_gmt'] ?? ($item['created_at'] ?? ''),
                    ]);
                }
            }
        }

        // 2. Query SQL webcareproscan_firewall_logs table for modular & endpoint events
        $firewall_logs_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $firewall_logs_table));
        if ($table_exists === $firewall_logs_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT id, incident_id, ip_address, request_uri, request_method, http_status_code, http_referer, rule_category, rule_description, payload_sample, user_agent, action_taken, created_at
                     FROM %i
                     WHERE rule_category = %s OR rule_description LIKE %s OR request_uri LIKE %s OR request_uri LIKE %s
                     ORDER BY id DESC
                     LIMIT 100',
                    $firewall_logs_table,
                    'Modular Behavioral WAF',
                    '%MOD-%',
                    '%admin-ajax.php%',
                    '%/wp-json/%'
                ),
                ARRAY_A
            );
            if (is_array($rows)) {
                foreach ($rows as $r) {
                    $extracted_id = '';
                    if (preg_match('/\[(MOD-[A-Z0-9-]+)\]/', (string) ($r['rule_description'] ?? ''), $m)) {
                        $extracted_id = $m[1];
                    }
                    $record_event([
                        'source'           => 'sql_firewall_logs',
                        'incident_id'      => $r['incident_id'] ?? ('sql_' . $r['id']),
                        'ip_hash'          => $hash_ip((string) ($r['ip_address'] ?? '')),
                        'rule_id'          => $extracted_id,
                        'rule_name'        => '',
                        'rule_category'    => $r['rule_category'] ?? '',
                        'rule_description' => $r['rule_description'] ?? '',
                        'request_method'   => $r['request_method'] ?? 'GET',
                        'request_uri'      => $r['request_uri'] ?? '',
                        'http_status_code' => intval($r['http_status_code'] ?? 403),
                        'http_referer'     => $r['http_referer'] ?? null,
                        'payload_sample'   => $r['payload_sample'] ?? '',
                        'user_agent'       => $r['user_agent'] ?? '',
                        'action_taken'     => $r['action_taken'] ?? '',
                        'is_authenticated' => false,
                        'user_role'        => '',
                        'created_at'       => $r['created_at'] ?? '',
                    ]);
                }
            }
        }

        // 3. Parse Pre-Boot Micro-WAF Fail2ban log tail for MOD-* events (masking raw IPs)
        $preboot_mod_lines = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f2b_path = \WebCareProScanner\Firewall\MicroWafCompiler::get_fail2ban_log_path();
            if ($f2b_path && file_exists($f2b_path) && is_readable($f2b_path)) {
                $lines = @file($f2b_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if (is_array($lines)) {
                    $tail = array_slice($lines, -200);
                    foreach (array_reverse($tail) as $line) {
                        if (str_contains($line, 'MOD-')) {
                            $masked = preg_replace_callback('/\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{6,39}/', static function ($m) use ($hash_ip) {
                                return 'iphash:' . $hash_ip($m[0]);
                            }, $line);
                            $preboot_mod_lines[] = $masked;
                            if (count($preboot_mod_lines) >= 50) {
                                break;
                            }
                        }
                    }
                }
            }
        }

        arsort($hits_by_uri);
        arsort($top_uas);

        return [
            'total_events_analyzed' => count($records),
            'hits_by_rule'          => $hits_by_rule,
            'hits_by_action'        => $hits_by_act,
            'top_target_uris'       => array_slice($hits_by_uri, 0, 30, true),
            'top_user_agents'       => array_slice($top_uas, 0, 15, true),
            'preboot_fail2ban_lines'=> $preboot_mod_lines,
            'recent_log_records'    => array_slice($records, 0, 200),
        ];
    }

    /**
     * Retrieve behavioral intelligence vault summary, component dossiers, and synthesized modular rules.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_modular_waf_status(\WP_REST_Request $request) {
        $ctx            = self::build_modular_dossier_context(false);
        $preload_active = defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE;
        $autopilot      = class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')
            && \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::is_autopilot_enabled();

        return new \WP_REST_Response([
            'success'           => true,
            'vault_summary'     => $ctx['vault_summary'],
            'rules'             => $ctx['rules'],
            'inventory'         => $ctx['inventory'],
            'trust_summary'     => $ctx['trust_summary'],
            'endpoint_map'      => $ctx['endpoint_map'],
            'findings'          => $ctx['findings'],
            'scan_progress'     => $ctx['scan_progress'],
            'preload_active'    => $preload_active,
            'autopilot_enabled' => $autopilot,
        ], 200);
    }

    /**
     * Toggle Smart 48-Hour Auto-Pilot for Modular Firewall rules.
     */
    public static function toggle_modular_autopilot(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security')], 500);
        }
        $params  = $request->get_json_params() ?: [];
        $enabled = !empty($params['enabled']);
        $res     = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::set_autopilot_enabled($enabled);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Retrieve Rescue Assistant recent block diagnostics, 15m pause state, trusted actions, and Daily Security Story.
     */
    public static function get_rescue_status(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        $minutes = max(5, min(60, intval($request->get_param('minutes') ?: 15)));
        return new \WP_REST_Response([
            'success'         => true,
            'pause_status'    => \WebCareProScanner\Firewall\RescueAssistantManager::get_pause_status(),
            'recent_blocks'   => \WebCareProScanner\Firewall\RescueAssistantManager::analyze_recent_blocks($minutes),
            'trusted_actions' => \WebCareProScanner\Firewall\RescueAssistantManager::get_trusted_actions(),
            'daily_story'     => \WebCareProScanner\Firewall\RescueAssistantManager::get_daily_security_story(),
        ], 200);
    }

    /**
     * Trust and permanently allow a blocked request or plugin action via Rescue Assistant.
     */
    public static function rescue_trust_action(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $res    = \WebCareProScanner\Firewall\RescueAssistantManager::trust_and_allow_action($params);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    /**
     * Pause strict WAF enforcement for 15 minutes (Monitor-Only Test Mode with auto re-arm).
     */
    public static function rescue_pause_15m(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\RescueAssistantManager::pause_strict_firewall_15m(), 200);
    }

    /**
     * Resume strict WAF enforcement immediately.
     */
    public static function rescue_resume(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\RescueAssistantManager::resume_strict_firewall(), 200);
    }

    /**
     * Toggle a modular firewall rule mode (enforce, monitor, off) or update parameters.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function toggle_modular_rule(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params  = $request->get_json_params() ?: [];
        $rule_id = isset($params['rule_id']) ? sanitize_text_field(wp_unslash($params['rule_id'])) : '';
        $mode    = isset($params['mode']) ? sanitize_key($params['mode']) : 'enforce';

        if (empty($rule_id)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Rule ID is required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::toggle_rule($rule_id, $mode, $params);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Bulk activate/enforce all recommended modular firewall rules.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function bulk_apply_modular_rules(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $result = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::bulk_apply_recommendations();
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Create or save a developer-defined custom modular rule.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function save_custom_modular_rule(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $result = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::create_custom_rule($params);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Return Visual Rule Studio field catalog.
     */
    public static function get_modular_visual_fields(\WP_REST_Request $request) {
        $fields = class_exists('\\WebCareProScanner\\Firewall\\Modular\\VisualRuleExpressionEngine')
            ? \WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine::get_field_catalog()
            : [];
        return new \WP_REST_Response([
            'success' => true,
            'fields'  => $fields,
        ], 200);
    }

    /**
     * Dry-run simulate a Visual/Custom rule against recent WafFileLogger history.
     */
    public static function simulate_custom_modular_rule(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Visual expression engine unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $limit  = isset($params['limit']) ? intval($params['limit']) : 500;
        $res    = \WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine::simulate_against_recent_logs($params, $limit);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Delete a developer-defined custom rule.
     */
    public static function delete_custom_modular_rule(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field((string) ($params['rule_id'] ?? ''));
        if ($rule_id === '') {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rule ID is required.', 'webcare-pro-security')], 400);
        }
        $res = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::delete_custom_rule($rule_id);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Push a Visual Rule's HTTP/Network Wirefilter expression directly to Cloudflare Edge Custom Ruleset.
     */
    public static function push_custom_rule_to_cloudflare(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Visual expression engine unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $res    = \WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine::push_rule_to_cloudflare_edge($params);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Parse an edited Wirefilter expression into structured visual condition groups.
     */
    public static function parse_wirefilter_expression(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'conditions' => []], 200);
        }
        $params     = $request->get_json_params() ?: [];
        $expr       = sanitize_text_field(wp_unslash((string) ($params['wirefilter_expr'] ?? '')));
        $conditions = \WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine::parse_wirefilter($expr);
        return new \WP_REST_Response([
            'success'    => true,
            'conditions' => $conditions,
            'wirefilter' => \WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine::to_wirefilter($conditions),
            'cf_edge'    => \WebCareProScanner\Firewall\Modular\VisualRuleExpressionEngine::to_cloudflare_edge_wirefilter($conditions),
        ], 200);
    }

    /**
     * Retrieve registered Module Ecosystem & Next-Gen Engines status.
     */
    public static function get_modules_ecosystem(\WP_REST_Request $request) {
        $modules = class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')
            ? \WebCareProScanner\Core\ModuleRegistry::get_ecosystem_status()
            : [];
        return new \WP_REST_Response([
            'success' => true,
            'modules' => $modules,
        ], 200);
    }

    /**
     * Toggle a pluggable module on/off via its declared SettingsManager enable_key.
     */
    public static function toggle_ecosystem_module(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $mod_id  = sanitize_key((string) ($params['module_id'] ?? ''));
        $enabled = !empty($params['enabled']);
        if ($mod_id === '' || !class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Module ID is required.', 'webcare-pro-security')], 400);
        }
        $mod = \WebCareProScanner\Core\ModuleRegistry::get_module($mod_id);
        if (!$mod) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Module not found.', 'webcare-pro-security')], 404);
        }
        $manifest   = $mod->get_manifest();
        $enable_key = (string) ($manifest['enable_key'] ?? '');
        if ($enable_key === '') {
            return new \WP_REST_Response(['success' => false, 'message' => __('Core module is permanently active.', 'webcare-pro-security')], 400);
        }
        \WebCareProScanner\System\SettingsManager::save_settings([$enable_key => $enabled]);
        return new \WP_REST_Response([
            'success' => true,
            'modules' => \WebCareProScanner\Core\ModuleRegistry::get_ecosystem_status(),
        ], 200);
    }

    /**
     * Read a safe 15-line preview snippet of the code that triggered a modular rule.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_modular_code_preview(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $file = isset($_GET['file']) ? sanitize_text_field(wp_unslash($_GET['file'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $line = isset($_GET['line']) ? max(1, intval($_GET['line'])) : 1;

        if (empty($file)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('File parameter is required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_code_preview($file, $line);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Export complete Modular Intelligence Firewall forensic bundle as JSON.
     *
     * Provides complete visibility into synthesized rules, component inventory,
     * behavioral endpoint maps, AST taint findings, recent modular triggers,
     * and scan telemetry so false positives can be rapidly investigated.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function export_modular_waf_bundle(\WP_REST_Request $request) {
        $synth = '\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer';

        $ctx        = self::build_modular_dossier_context(true);
        $rules_list = $ctx['rules'];
        $inventory  = $ctx['inventory'];
        $findings   = $ctx['findings'];
        $endpoints  = $ctx['endpoint_map'];

        $enforced_count = 0;
        $monitor_count  = 0;
        $off_count      = 0;
        $custom_count   = 0;
        $by_category    = [];

        foreach ($rules_list as $rl) {
            $mode = $rl['current_mode'] ?? 'off';
            if ($mode === 'enforce') {
                $enforced_count++;
            } elseif ($mode === 'monitor') {
                $monitor_count++;
            } else {
                $off_count++;
            }
            if (!empty($rl['is_custom'])) {
                $custom_count++;
            }
            $cat = $rl['category'] ?? 'unknown';
            $by_category[$cat] = ($by_category[$cat] ?? 0) + 1;
        }

        // Assemble deduplicated file cryptographic hash index & log correlation context
        $file_hash_index      = self::build_file_hash_index($rules_list, $findings);
        $log_analysis_context = self::build_modular_log_analysis_context();

        // Collect compiled 0ms Pre-Boot Micro-WAF snapshot
        $preload_active = defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE;
        $compiled_file  = class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')
            ? \WebCareProScanner\Firewall\MicroWafCompiler::get_compiled_file_path()
            : '';
        $compiled_preload_waf = [
            'preload_waf_active'  => $preload_active,
            'compiled_file_exists'=> ($compiled_file && file_exists($compiled_file)),
            'compiled_file_sha256'=> ($compiled_file && file_exists($compiled_file)) ? (@hash_file('sha256', $compiled_file) ?: null) : null,
            'compiled_file_mtime' => ($compiled_file && file_exists($compiled_file)) ? gmdate('c', (int) @filemtime($compiled_file)) : null,
            'compiled_rules'      => class_exists($synth) ? $synth::get_compiled_preload_rules() : [],
        ];

        $active_theme = wp_get_theme();
        $site_host    = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'localhost';

        $payload = [
            'success'                     => true,
            'webcare_export_type'         => 'modular_waf_forensic_dossier',
            'format_version'              => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
            'exported_at'                 => gmdate('c'),
            'exported_timestamp'          => time(),
            'author'                      => 'Mir Alamin (WebCare Pro)',
            'environment'                 => [
                'site_url'           => get_site_url(),
                'home_url'           => get_home_url(),
                'wordpress_version'  => $GLOBALS['wp_version'] ?? 'Unknown',
                'php_version'        => PHP_VERSION,
                'server_software'    => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
                'webcare_version'    => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
                'preload_waf_active' => $preload_active,
                'site_archetype'     => get_option('webcareproscan_site_archetype', 'business'),
                'active_theme'       => [
                    'name'       => $active_theme ? $active_theme->get('Name') : '',
                    'version'    => $active_theme ? $active_theme->get('Version') : '',
                    'template'   => $active_theme ? $active_theme->get_template() : '',
                    'stylesheet' => $active_theme ? $active_theme->get_stylesheet() : '',
                ],
            ],
            'summary'                     => [
                'total_rules'          => count($rules_list),
                'enforced_rules'       => $enforced_count,
                'monitored_rules'      => $monitor_count,
                'disabled_rules'       => $off_count,
                'custom_rules'         => $custom_count,
                'rules_by_category'    => $by_category,
                'components_profiled'  => count($inventory),
                'endpoints_mapped'     => count($endpoints),
                'ast_findings_count'   => count($findings),
                'unique_files_hashed'  => count($file_hash_index),
                'recent_modular_hits'  => $log_analysis_context['total_events_analyzed'],
                'vault_sealed'         => !empty($ctx['vault_summary']),
            ],
            'trust_and_integrity_summary' => $ctx['trust_summary'],
            'rules'                       => $rules_list,
            'component_inventory'         => $inventory,
            'file_hash_index'             => $file_hash_index,
            'compiled_preload_waf'        => $compiled_preload_waf,
            'log_analysis_context'        => $log_analysis_context,
            'endpoint_behavior_map'       => $endpoints,
            'ast_taint_findings'          => $findings,
            'recent_modular_hits'         => $log_analysis_context['recent_log_records'],
            'vault_summary'               => $ctx['vault_summary'],
            'scan_progress'               => $ctx['scan_progress'],
        ];

        $is_download = !empty($request->get_param('download'));
        if ($is_download) {
            $filename = 'webcare-modular-waf-' . sanitize_file_name($site_host) . '-' . gmdate('Y-m-d') . '.json';
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('X-Content-Type-Options: nosniff');
            echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            exit;
        }

        return new \WP_REST_Response($payload, 200);
    }

    public static function start_scan(\WP_REST_Request $request) {
        global $wpdb;

        // Check for concurrent active scan lock
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            $exist_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($exist_sql, $locked_id),
                ARRAY_A
            );
            if (!$existing_scan || $existing_scan['status'] !== 'running') {
                ScanLock::release($locked_id);
            } else {
                $remaining = \WebCareProScanner\Scan\ScanQueueManager::get_remaining_count($locked_id);
                return rest_ensure_response([
                    'success'       => true,
                    'scan_id'       => $locked_id,
                    'scan_target'   => $existing_scan['scan_target'],
                    'total_files'   => (int) $existing_scan['total_files'],
                    'scanned_files' => (int) $existing_scan['scanned_files'],
                    'remaining'     => $remaining,
                    'status'        => 'running',
                    'resumed'       => true,
                ]);
            }
        }

        $target = sanitize_text_field($request->get_param('target') ?: 'plugins_themes');
        $custom_options = $request->get_param('custom_options');
        if (!is_array($custom_options)) {
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $custom_options = $settings['custom_scan_options'] ?? \WebCareProScanner\System\SettingsManager::get_default_custom_scan_options();
        } else {
            $custom_options = \WebCareProScanner\System\SettingsManager::sanitize_custom_scan_options($custom_options);
        }
        
        $paths = [];

        // Determine scannable filesystem files based on scan profile (0 = unlimited)
        $file_limit = (int) apply_filters('webcareproscan_file_limit', 0, $target);

        if ($target === 'custom') {
            $has_filesystem_scan = !empty($custom_options['scan_known_malware'])
                || !empty($custom_options['scan_backdoors_heuristics'])
                || !empty($custom_options['scan_malicious_urls'])
                || !empty($custom_options['scan_core_integrity'])
                || !empty($custom_options['scan_theme_integrity'])
                || !empty($custom_options['scan_plugin_integrity'])
                || !empty($custom_options['scan_unbundled_files'])
                || !empty($custom_options['scan_outside_root'])
                || !empty($custom_options['scan_images_executable']);

            if ($has_filesystem_scan) {
                if (!empty($custom_options['scan_outside_root'])) {
                    $parent = dirname(ABSPATH);
                    if (is_dir($parent) && is_readable($parent) && realpath($parent) !== realpath(ABSPATH)) {
                        $paths[] = untrailingslashit($parent);
                    } else {
                        $paths[] = untrailingslashit(ABSPATH);
                    }
                } elseif (!empty($custom_options['scan_core_integrity']) || !empty($custom_options['scan_unbundled_files'])) {
                    $paths[] = untrailingslashit(ABSPATH);
                } else {
                    if (!empty($custom_options['scan_plugin_integrity'])) {
                        $paths[] = WP_PLUGIN_DIR;
                    }
                    if (!empty($custom_options['scan_theme_integrity'])) {
                        $paths[] = get_theme_root();
                    }
                    if (empty($paths)) {
                        $paths[] = untrailingslashit(ABSPATH);
                    }
                }
            }
        } elseif (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity', 'rogue_admin', 'hook_sentinel', 'modified_files'], true)) {
            // Targeted deep engines do not queue filesystem files
            $paths = [];
        } elseif ($target === 'filesystem_only' || $target === 'full') {
            $paths[] = untrailingslashit(ABSPATH);
        } else { // default plugins_themes
            $paths[] = WP_PLUGIN_DIR;
            $paths[] = get_theme_root();
        }

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $now_exact = self::now_fractional_mysql();
        $start_micro = microtime(true);

        // Pre-insert scan record to obtain unique scan_id
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert($table_scans, [
            'status'        => 'running',
            'scan_target'   => $target,
            'trigger_type'  => 'manual',
            'scanned_files' => 0,
            'total_files'   => 0,
            'issues_found'  => 0,
            'risk_score'    => 0,
            'duration'      => 0,
            'duration_ms'   => 0,
            'created_at'    => current_time('mysql'),
            'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
            'started_at'    => $now_exact,
        ]);
        $scan_id = (int) $wpdb->insert_id;

        // Acquire lock
        ScanLock::acquire($scan_id);

        // Initialize high-performance streaming session queue on disk
        $total_files = 0;
        if (!empty($paths)) {
            $total_files = \WebCareProScanner\Scan\ScanQueueManager::init_queue($scan_id, $paths, $file_limit);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_scans, [
            'total_files' => $total_files,
        ], ['id' => $scan_id]);

        if ($target === 'custom' && !empty($custom_options)) {
            set_transient("webcareproscan_custom_options_{$scan_id}", $custom_options, HOUR_IN_SECONDS);
        }

        set_transient("webcareproscan_scan_start_micro_{$scan_id}", $start_micro, HOUR_IN_SECONDS);

        $init_telemetry = self::get_realtime_resource_stats(null, null, 0, $total_files, 0, 0.0);
        set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $init_telemetry, 600);

        return rest_ensure_response([
            'success'     => true,
            'scan_id'     => $scan_id,
            'total_files' => $total_files,
            'status'      => 'running',
            'started_at'  => $now_exact,
            'telemetry'   => $init_telemetry,
        ]);
    }

    public static function process_batch(\WP_REST_Request $request) {
        global $wpdb;

        $scan_id = (int) $request->get_param('scan_id');
        $configured_batch = (int) \WebCareProScanner\System\SettingsManager::get('scan_batch_size', 50);
        $param_batch = (int) $request->get_param('batch_size');
        $batch_size = $param_batch > 0 ? max($param_batch, $configured_batch) : $configured_batch;
        $batch_start = microtime(true);
        $batch_ru_start = function_exists('getrusage') ? @getrusage() : null;

        // Update lock heartbeat
        ScanLock::heartbeat($scan_id);

        // Initialize Dynamic Resource Governor
        $governor = new \WebCareProScanner\Resource\ResourceMonitor(70, 18, 'balanced');
        $effective_batch_size = $governor->get_adaptive_batch_size($batch_size);

        $batch_data = \WebCareProScanner\Scan\ScanQueueManager::get_batch($scan_id, $effective_batch_size);
        $files_to_process = $batch_data['files'];
        $line_bytes = $batch_data['line_bytes'];
        $remaining = $batch_data['remaining'];

        if (empty($files_to_process)) {
            // Check if scan exists in DB to prevent hard 404 failure
            $check_sql = "SELECT id FROM {$wpdb->prefix}webcareproscan_scans WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_exists = $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($check_sql, $scan_id)
            );
            if ($scan_exists) {
                \WebCareProScanner\Scan\ScanQueueManager::cleanup($scan_id);
                return rest_ensure_response([
                    'success'     => true,
                    'is_finished' => true,
                    'remaining'   => 0,
                    'processed'   => 0,
                    'last_file'   => '',
                ]);
            }
            return new \WP_Error('scan_not_found', 'Scan queue expired or not found', ['status' => 404]);
        }

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        $file_scanner = new FileScanner();
        $processed_count = 0;
        $accumulated_weight = 0.0;
        $bytes_consumed = 0;
        $batch_files_records = [];

        foreach ($files_to_process as $idx => $filepath) {
            // Adaptive breathing and resource headroom check before each file
            if ($governor->throttle_and_check()) {
                break;
            }

            // Update live heartbeat and last active file path
            set_transient("webcareproscan_active_scan_file_{$scan_id}", $filepath, 120);

            // Factor in file complexity weight
            $weight = \WebCareProScanner\Resource\ResourceMonitor::get_file_weight($filepath);
            $accumulated_weight += $weight;

            // If heavy files filled the batch weight budget early, save remaining and yield
            if ($accumulated_weight >= ($effective_batch_size * 1.25) && $processed_count > 10) {
                break;
            }

            $findings = $file_scanner->scan_file($filepath, (string) $scan_id);
            $rel_path = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($filepath)), '/');
            $file_size = @filesize($filepath) ?: 0;
            $file_status = !empty($findings) ? 'threat' : 'clean';

            $batch_files_records[] = [
                'file_path' => $rel_path,
                'file_size' => $file_size,
                'status'    => $file_status,
            ];

            $processed_count++;
            if (!empty($line_bytes[$idx])) {
                $bytes_consumed += $line_bytes[$idx];
            }

            foreach ($findings as $f) {
                $item = $f->to_array();
                $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
                $status = ($matched_rule !== null) ? 'ignored' : 'open';

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $item['engine'],
                    'type'         => $item['type'],
                    'severity'     => $item['severity'],
                    'confidence'   => $item['confidence'],
                    'file_path'    => $item['file_path'],
                    'line_number'  => $item['line_number'] ?? null,
                    'code_snippet' => $item['code_snippet'] ?? null,
                    'evidence'     => $item['evidence'] ?? null,
                    'description'  => $item['description'],
                    'status'       => $status,
                    'created_at'   => current_time('mysql'),
                    'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
                ]);
            }
        }

        // Bulk insert scanned file telemetry in a single high-efficiency SQL query instead of N individual queries
        if (!empty($batch_files_records)) {
            $now_mysql = current_time('mysql');
            $now_gmt   = gmdate('Y-m-d H:i:s');
            $placeholders = [];
            $values = [];
            foreach ($batch_files_records as $rec) {
                $placeholders[] = '(%d, %s, %d, %s, %s, %s)';
                $values[] = $scan_id;
                $values[] = $rec['file_path'];
                $values[] = $rec['file_size'];
                $values[] = $rec['status'];
                $values[] = $now_mysql;
                $values[] = $now_gmt;
            }
            $insert_query = "INSERT INTO `{$table_files}` (scan_id, file_path, file_size, status, scanned_at, scanned_at_gmt) VALUES " . implode(', ', $placeholders);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($insert_query, $values)
            );
        }

        $remaining = \WebCareProScanner\Scan\ScanQueueManager::advance($scan_id, $processed_count, $bytes_consumed);
        $is_finished = ($remaining === 0);


        $tot_sql = "SELECT total_files FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan_row = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($tot_sql, $scan_id),
            ARRAY_A
        );
        if (!$scan_row) {
            // Self-healing: recreate running scan row if missing
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->insert($table_scans, [
                'id'            => $scan_id,
                'status'        => 'running',
                'scan_type'     => 'full',
                'scanned_files' => 0,
                'total_files'   => max(1, $remaining),
                'issues_found'  => 0,
                'risk_score'    => 0,
                'created_at'    => current_time('mysql'),
                'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
            ]);
            $scan_row = ['total_files' => max(1, $remaining)];
        }
        $scan_total = (int) ($scan_row['total_files'] ?? 0);
        $scanned_so_far = max(0, $scan_total - $remaining);
        $iss_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $current_issues_total = (int) $wpdb->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_sql, $scan_id)
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_scans, [
            'scanned_files' => $scanned_so_far,
            'issues_found'  => $current_issues_total,
        ], ['id' => $scan_id]);

        $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
        $elapsed_sec = ($start_micro && is_numeric($start_micro)) ? max(0.1, microtime(true) - (float) $start_micro) : 0.0;
        $telemetry = self::get_realtime_resource_stats(
            $batch_start,
            $batch_ru_start,
            $scanned_so_far,
            $scan_total,
            $current_issues_total,
            $elapsed_sec,
            $governor
        );
        set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $telemetry, 600);

        return rest_ensure_response([
            'success'        => true,
            'is_finished'    => $is_finished,
            'remaining'      => $remaining,
            'processed'      => count($files_to_process),
            'scanned_files'  => $scanned_so_far,
            'total_files'    => $scan_total,
            'issues_found'   => $current_issues_total,
            'last_file'      => !empty($files_to_process) ? basename(end($files_to_process)) : '',
            'telemetry'      => $telemetry,
        ]);
    }

    public static function run_deep_audit(\WP_REST_Request $request) {
        global $wpdb;

        // Ensure sufficient execution time and memory for deep forensic correlation
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(180);
        }
        if (function_exists('wp_raise_memory_limit')) {
            @wp_raise_memory_limit('admin');
        }

        $scan_id = (int) $request->get_param('scan_id');
        $target = sanitize_text_field($request->get_param('target') ?: '');
        $admins_only = (bool) $request->get_param('admins_only');

        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';

        // Keep lock alive
        ScanLock::heartbeat($scan_id);

        // If scan is already completed, return results directly (idempotent for reconnects)
        $scan_query = "SELECT * FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan_row = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($scan_query, $scan_id),
            ARRAY_A
        );
        if ($scan_row && $scan_row['status'] === 'completed') {
            $issues_query = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $all_scan_issues = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($issues_query, $scan_id),
                ARRAY_A
            );
            $scorer = new RiskScorer();
            $summary = $scorer->calculate($all_scan_issues);
            $diagnostics = self::build_scan_diagnostics($scan_row);
            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => self::enrich_issues($all_scan_issues),
                'diagnostics' => $diagnostics,
                'status'      => 'completed'
            ]);
        }

        if (empty($target)) {
            $target = $scan_row ? ($scan_row['scan_target'] ?? 'plugins_themes') : 'plugins_themes';
        }

        $all_deep_findings = [];

        try {
            if ($target === 'unknown_files') {
                // Find only unknown files (core & plugins & themes)
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                // Filter strictly for unknown/unrecognized files
                $all_deep_findings = array_filter($all_deep_findings, function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'], ['unknown_core_file', 'unknown_plugin_file'], true);
                });
            } elseif ($target === 'spam_content') {
                // Scan for spam posts/pages only
                $content_scanner = new ContentScanner();
                $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 300));
            } elseif ($target === 'user_security') {
                // Password strength, privilege escalation, and Trojan capability injection audit across all accounts
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, false));
            } elseif ($target === 'outdated_software') {
                // Check outdated WP core, plugins, themes
                $update_scanner = new UpdateScanner();
                $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
            } elseif ($target === 'suspicious_uploads') {
                // Detect .php, .sh, or suspicious file extensions inside wp-content/uploads
                $uploads_scanner = new UploadsScanner();
                $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
            } elseif ($target === 'crontab_audit') {
                // Crontab & WP-Cron scheduled tasks audit
                $cron_scanner = new CronScanner();
                $all_deep_findings = array_merge($all_deep_findings, $cron_scanner->scan((string) $scan_id));
            } elseif ($target === 'core_integrity') {
                // WordPress Core files integrity check against official checksums
                $core_integrity = new CoreIntegrity();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
            } elseif ($target === 'rogue_admin') {
                // Rogue Administrator & Database Micro-Anomaly Audit
                $rogue_detector = new \WebCareProScanner\Database\RogueAdminAnomalyDetector();
                $all_deep_findings = array_merge($all_deep_findings, $rogue_detector->scan((string) $scan_id));
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true));
            } elseif ($target === 'hook_sentinel') {
                // Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
                $hook_sentinel = new \WebCareProScanner\WordPress\HookInfiltrationSentinel();
                $all_deep_findings = array_merge($all_deep_findings, $hook_sentinel->scan((string) $scan_id));
                $persistence_scanner = new PersistenceScanner();
                $all_deep_findings = array_merge($all_deep_findings, $persistence_scanner->scan((string) $scan_id));
            } elseif ($target === 'modified_files') {
                // Modified Core, Plugins, and Themes Audit against official WordPress.org checksums
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $theme_integrity = new ThemeIntegrity();
                $important_fim = new ImportantFileFIM();

                $integrity_findings = array_merge(
                    $core_integrity->verify((string) $scan_id),
                    $plugin_integrity->verify((string) $scan_id),
                    $theme_integrity->verify((string) $scan_id),
                    $important_fim->verify((string) $scan_id)
                );

                // Filter strictly for modified or tampered files (excluding informational notes)
                $modified_items = array_filter($integrity_findings, function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'], [
                        'modified_core_file',
                        'modified_plugin_file',
                        'modified_theme_file',
                        'missing_core_file',
                        'missing_plugin_file',
                        'missing_theme_file',
                        'important_file_modified',
                    ], true);
                });

                $all_deep_findings = array_merge($all_deep_findings, $modified_items);

                // Additionally run AST malware inspection on any modified files to identify injected backdoors
                $file_scanner = new FileScanner();
                foreach ($modified_items as $mf) {
                    $item = is_array($mf) ? $mf : $mf->to_array();
                    $file_path = $item['file_path'] ?? '';
                    if ($file_path) {
                        $abs_path = (strpos($file_path, ABSPATH) === 0) ? $file_path : (rtrim(ABSPATH, '/\\') . '/' . ltrim($file_path, '/\\'));
                        if (file_exists($abs_path) && is_file($abs_path)) {
                            $code_findings = $file_scanner->scan_file($abs_path, (string) $scan_id);
                            if (!empty($code_findings)) {
                                $all_deep_findings = array_merge($all_deep_findings, $code_findings);
                            }
                        }
                    }
                }
            } elseif ($target === 'custom') {
                $custom_options = get_transient("webcareproscan_custom_options_{$scan_id}");
                if (!is_array($custom_options)) {
                    $req_custom = $request->get_param('custom_options');
                    if (is_array($req_custom)) {
                        $custom_options = \WebCareProScanner\System\SettingsManager::sanitize_custom_scan_options($req_custom);
                    } else {
                        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
                        $custom_options = $settings['custom_scan_options'] ?? \WebCareProScanner\System\SettingsManager::get_default_custom_scan_options();
                    }
                }

                // 1. Scan core files against repository versions for changes
                if (!empty($custom_options['scan_core_integrity'])) {
                    $core_integrity = new CoreIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                }

                // 2. Scan theme files against repository versions for changes
                if (!empty($custom_options['scan_theme_integrity'])) {
                    $theme_integrity = new ThemeIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));
                }

                // 3. Scan plugin files against repository versions for changes
                if (!empty($custom_options['scan_plugin_integrity'])) {
                    $plugin_integrity = new PluginIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                }

                // 4. Scan wp-admin and wp-includes for files not bundled with WordPress
                if (!empty($custom_options['scan_unbundled_files']) && empty($custom_options['scan_core_integrity'])) {
                    $core_integrity = new CoreIntegrity();
                    $core_results = $core_integrity->verify((string) $scan_id);
                    $unbundled = array_filter($core_results, function ($f) {
                        $arr = is_array($f) ? $f : $f->to_array();
                        return in_array($arr['type'] ?? '', ['unknown_core_file'], true);
                    });
                    $all_deep_findings = array_merge($all_deep_findings, $unbundled);
                }

                // 5. Scan for publicly accessible configuration, backup, or log files
                if (!empty($custom_options['scan_public_config'])) {
                    $important_fim = new ImportantFileFIM();
                    $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                    $config_scanner = new \WebCareProScanner\WordPress\ConfigScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $config_scanner->scan((string) $scan_id));
                    $exposed = self::audit_exposed_sensitive_files((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $exposed);
                }

                // 6. Scan for publicly accessible quarantined files
                if (!empty($custom_options['scan_public_quarantine'])) {
                    $quarantine_exposure = self::audit_quarantine_exposure((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $quarantine_exposure);
                }

                // 7. Scan for misconfigured visitor IP detection headers
                if (!empty($custom_options['scan_ip_detection'])) {
                    $ip_findings = self::audit_visitor_ip_detection((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $ip_findings);
                }

                // 8. Scan posts for known dangerous URLs and suspicious content
                if (!empty($custom_options['scan_posts_content'])) {
                    $content_scanner = new ContentScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan_posts_only((string) $scan_id, 100));
                }

                // 9. Scan comments for known dangerous URLs and suspicious content
                if (!empty($custom_options['scan_comments_content'])) {
                    $content_scanner = new ContentScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan_comments_only((string) $scan_id, 100));
                }

                // 10. Scan WordPress core, plugin, and theme options
                if (!empty($custom_options['scan_options_content'])) {
                    $option_scanner = new \WebCareProScanner\Database\OptionScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $option_scanner->scan_options((string) $scan_id));
                }

                // 11. Scan for out of date, abandoned, and vulnerable plugins, themes, and WP
                if (!empty($custom_options['scan_vulnerable_software'])) {
                    $update_scanner = new UpdateScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
                }

                // 12. Scan for suspicious admin users created outside of WordPress
                if (!empty($custom_options['scan_rogue_admins'])) {
                    $rogue_detector = new \WebCareProScanner\Database\RogueAdminAnomalyDetector();
                    $all_deep_findings = array_merge($all_deep_findings, $rogue_detector->scan((string) $scan_id));
                    $user_scanner = new UserScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true));
                }

                // 13. Check the strength of passwords
                if (!empty($custom_options['scan_password_strength'])) {
                    $pwd_findings = self::audit_password_strength((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $pwd_findings);
                }

                // 14. Monitor disk space
                if (!empty($custom_options['monitor_disk_space'])) {
                    $disk_findings = self::audit_disk_space((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $disk_findings);
                }

                // 15. Monitor Web Application Firewall status
                if (!empty($custom_options['monitor_firewall_status'])) {
                    $waf_findings = self::audit_waf_status((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $waf_findings);
                }

                // 16. Scan images, binary, and other files as if they were executable
                if (!empty($custom_options['scan_images_executable'])) {
                    $uploads_scanner = new UploadsScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
                }

                // 17. Reputation Checks (Domain blocklist, spamvertised, spam IP)
                if (!empty($custom_options['check_domain_blocklist']) || !empty($custom_options['check_spamvertised']) || !empty($custom_options['check_spam_ip'])) {
                    $reputation_findings = self::audit_reputation_checks((string) $scan_id, $custom_options);
                    $all_deep_findings = array_merge($all_deep_findings, $reputation_findings);
                }
            } elseif ($target === 'filesystem_only') {
                // Filesystem-only scan: no additional deep audit engines needed
            } else {
                // Full or plugins_themes: execute deep audit engines with heartbeat & fault isolation
                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Core Integrity: Verifying WordPress core files against official WP.org API checksums...', 120);
                    $core_integrity = new CoreIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                } catch (\Throwable $e) {}

                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'File Integrity: Checking critical system files (wp-config.php, .htaccess, index.php)...', 120);
                    $important_fim = new ImportantFileFIM();
                    $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Plugin Integrity: Verifying installed plugins against official WordPress.org checksums...', 120);
                    $plugin_integrity = new PluginIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Theme Integrity: Verifying active and installed themes against repository checksums...', 120);
                    $theme_integrity = new ThemeIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    $db_scanner = new DatabaseScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $db_scanner->scan((string) $scan_id, 100));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Content & Post Scanner: Inspecting published posts and comments for hidden SEO spam and XSS...', 120);
                    $content_scanner = new ContentScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 100));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'User & Auth Sentinel: Auditing user accounts, administrator privileges, and password strength...', 120);
                    $wp_security = new WordPressSecurityScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $wp_security->scan((string) $scan_id));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Vulnerability Intelligence: Checking installed plugins, themes, and WP Core against CVE database...', 120);
                    $update_scanner = new UpdateScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
                } catch (\Throwable $e) {}

                try {
                    ScanLock::heartbeat($scan_id);
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Media & Uploads Audit: Inspecting image metadata and attachments for embedded PHP code...', 120);
                    $uploads_scanner = new UploadsScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
                } catch (\Throwable $e) {}

                // Quick reputation check (skips if non-responsive or local)
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Reputation Intel: Verifying domain blocklists, Google Safe Browsing, and spamvertising...', 120);
                    $reputation_findings = self::audit_reputation_checks((string) $scan_id, [
                        'check_domain_blocklist' => true,
                        'check_spamvertised'     => true,
                        'check_spam_ip'          => true,
                    ]);
                    $all_deep_findings = array_merge($all_deep_findings, $reputation_findings);
                } catch (\Throwable $e) {}
            }

            // Cross-engine Correlation
            $correlation = new CorrelationEngine();
            $correlated = $correlation->correlate($all_deep_findings);

            // Pre-load all existing findings already saved for this scan to prevent any duplicate insertions
            $exist_sql = "SELECT engine, type, file_path, line_number, description FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing_issues = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($exist_sql, $scan_id),
                ARRAY_A
            ) ?: [];

            $inserted_signatures = [];
            foreach ($existing_issues as $ex) {
                $norm_path = self::normalize_finding_path($ex['file_path'] ?? '');
                $line_no = (int) ($ex['line_number'] ?? 0);
                $sig = strtolower($ex['type'] ?? '') . '|' . $norm_path . '|' . $line_no;
                $inserted_signatures[$sig] = true;
            }

            foreach ($correlated as $f) {
                $item = $f->to_array();
                $norm_path = self::normalize_finding_path($item['file_path'] ?? '');
                $line_no = (int) ($item['line_number'] ?? 0);
                $sig = strtolower($item['type'] ?? '') . '|' . $norm_path . '|' . $line_no;
                if (isset($inserted_signatures[$sig])) {
                    continue; // Skip exact duplicate finding for this scan
                }
                $inserted_signatures[$sig] = true;

                $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
                $status = ($matched_rule !== null) ? 'ignored' : 'open';

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $item['engine'],
                    'type'         => $item['type'],
                    'severity'     => $item['severity'],
                    'confidence'   => $item['confidence'],
                    'file_path'    => $item['file_path'],
                    'line_number'  => $item['line_number'] ?? null,
                    'code_snippet' => UploadsScanner::sanitize_utf8($item['code_snippet'] ?? null),
                    'evidence'     => UploadsScanner::sanitize_utf8($item['evidence'] ?? null),
                    'description'  => $item['description'],
                    'status'       => $status,
                    'created_at'   => current_time('mysql'),
                    'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
                ]);
            }

            // Prune any duplicate issue rows to ensure clean database storage
            self::prune_duplicate_issues($scan_id);

            // Calculate final risk score across all findings (decorating whitelist status)
            $all_iss_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $all_scan_issues = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($all_iss_sql, $scan_id),
                ARRAY_A
            );
            $enriched_issues = self::enrich_issues($all_scan_issues);

            $scorer = new RiskScorer();
            $summary = $scorer->calculate($enriched_issues);

            $cnt_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $open_issues_count = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($cnt_sql, $scan_id)
            );

            // Calculate duration accurately with millisecond precision
            $row_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_row = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($row_sql, $scan_id),
                ARRAY_A
            );
            $client_duration_ms = (int) $request->get_param('client_duration_ms');
            $client_duration = (int) $request->get_param('client_duration');
            $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
            $completed_at_exact = self::now_fractional_mysql();

            $duration_ms = 0;
            $duration_sec = 0;

            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }

            if ($duration_ms <= 0 && $client_duration_ms > 0) {
                $duration_ms = $client_duration_ms;
                $duration_sec = max(1, (int) round($client_duration_ms / 1000));
            } elseif ($duration_ms <= 0 && $client_duration > 0) {
                $duration_sec = $client_duration;
                $duration_ms = $client_duration * 1000;
            } elseif ($duration_ms <= 0 && $scan_row) {
                if (!empty($scan_row['started_at'])) {
                    $start_dt = date_create($scan_row['started_at'], wp_timezone());
                    $end_dt = date_create($completed_at_exact, wp_timezone());
                    if ($start_dt && $end_dt) {
                        $diff_sec = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                        if ($diff_sec > 0) {
                            $duration_ms = (int) round($diff_sec * 1000);
                            $duration_sec = max(1, (int) round($diff_sec));
                        }
                    }
                }

                if ($duration_ms <= 0 && !empty($scan_row['created_at'])) {
                    $created_dt = date_create($scan_row['created_at'], wp_timezone());
                    if ($created_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        $diff_sec = max(0.1, $now_dt->getTimestamp() - $created_dt->getTimestamp());
                        $duration_ms = (int) round($diff_sec * 1000);
                        $duration_sec = max(1, (int) round($diff_sec));
                    }
                }
            }

            if ($duration_ms <= 0) {
                $duration_ms = 100;
                $duration_sec = 1;
            }

            delete_transient("webcareproscan_scan_start_micro_{$scan_id}");

            $started_at_db = !empty($scan_row['started_at']) ? $scan_row['started_at'] : ($scan_row['created_at'] ?? $completed_at_exact);

            if (!$scan_row) {
                // Self-healing: recreate missing scan record so results are guaranteed to persist
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_scans, [
                    'id'            => $scan_id,
                    'status'        => 'completed',
                    'scan_target'   => $target ?: 'full',
                    'trigger_type'  => 'manual',
                    'scanned_files' => (int) ($scan_row['scanned_files'] ?? ($scan_row['total_files'] ?? count($all_scan_issues))),
                    'total_files'   => (int) ($scan_row['total_files'] ?? count($all_scan_issues)),
                    'issues_found'  => $open_issues_count,
                    'risk_score'    => $summary['score'],
                    'duration'      => $duration_sec,
                    'duration_ms'   => $duration_ms,
                    'created_at'    => current_time('mysql'),
                    'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
                    'started_at'    => $started_at_db,
                    'completed_at'  => $completed_at_exact,
                ]);
            } else {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update($table_scans, [
                    'status'        => 'completed',
                    'issues_found'  => $open_issues_count,
                    'risk_score'    => $summary['score'],
                    'duration'      => $duration_sec,
                    'duration_ms'   => $duration_ms,
                    'started_at'    => $started_at_db,
                    'completed_at'  => $completed_at_exact,
                ], ['id' => $scan_id]);
            }

            $completed_scan_row = [
                'id'            => $scan_id,
                'status'        => 'completed',
                'issues_found'  => $open_issues_count,
                'risk_score'    => $summary['score'],
                'duration'      => $duration_sec,
                'duration_ms'   => $duration_ms,
                'scanned_files' => (int) ($scan_row['scanned_files'] ?? ($scan_row['total_files'] ?? 0)),
                'total_files'   => (int) ($scan_row['total_files'] ?? 0),
                'created_at'    => $scan_row['created_at'] ?? current_time('mysql'),
                'started_at'    => $started_at_db,
                'completed_at'  => $completed_at_exact,
            ];
            $diagnostics = self::build_scan_diagnostics($completed_scan_row);

            // Release the scan lock upon completion
            ScanLock::release($scan_id);

            // Dispatch granular event notifications via NotificationDispatcher
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                $is_targeted = ($target && !in_array($target, ['full', 'full_filesystem', 'plugins_themes', 'custom'], true));
                if ($is_targeted) {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_targeted_complete', [
                        'severity' => ($open_issues_count > 0) ? 'high' : 'info',
                        /* translators: 1: scan ID, 2: target name, 3: issues found, 4: risk score */
                        'message'  => sprintf(__('Targeted scan #%1$d finished for target "%2$s". %3$d issue(s) identified (Risk Score: %4$d/100).', 'webcare-pro-security'), $scan_id, $target, $open_issues_count, $summary['score']),
                        'details'  => [
                            'Scan ID'        => $scan_id,
                            'Target'         => $target,
                            'Scanned Files'  => number_format((int) ($completed_scan_row['scanned_files'] ?? 0)),
                            'Issues Found'   => $open_issues_count,
                            'Risk Score'     => $summary['score'] . '/100',
                            'Duration'       => $duration_sec . 's',
                        ],
                    ]);
                } else {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_manual_complete', [
                        'severity' => ($open_issues_count > 0) ? 'high' : 'info',
                        /* translators: 1: scan ID, 2: issues found, 3: risk score */
                        'message'  => sprintf(__('Manual scan #%1$d finished. %2$d issue(s) identified (Risk Score: %3$d/100).', 'webcare-pro-security'), $scan_id, $open_issues_count, $summary['score']),
                        'details'  => [
                            'Scan ID'        => $scan_id,
                            'Target'         => $target,
                            'Scanned Files'  => number_format((int) ($completed_scan_row['scanned_files'] ?? 0)),
                            'Issues Found'   => $open_issues_count,
                            'Risk Score'     => $summary['score'] . '/100',
                            'Duration'       => $duration_sec . 's',
                        ],
                    ]);
                }

                // Critical or High threats event
                $critical_or_high = array_filter($enriched_issues, function($iss) {
                    $sev = is_array($iss) ? ($iss['severity'] ?? '') : ($iss->severity ?? '');
                    return in_array($sev, ['critical', 'high'], true);
                });
                if (!empty($critical_or_high)) {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_threats_found', [
                        'severity' => 'critical',
                        /* translators: 1: scan ID, 2: threat count */
                        'message'  => sprintf(__('Critical or high-priority security threats were detected during scan #%1$d (%2$d threats).', 'webcare-pro-security'), $scan_id, count($critical_or_high)),
                        'details'  => [
                            'Scan ID'        => $scan_id,
                            'Critical Threats' => count($critical_or_high),
                            'Top Threats'    => implode(', ', array_slice(array_map(function($i) { return is_array($i) ? ($i['description'] ?? '') : ($i->description ?? ''); }, $critical_or_high), 0, 3)),
                        ],
                    ]);
                }
            }

            // Dispatch DevSecOps Webhooks (Slack, Discord, ClickUp, Asana, Generic)
            if (class_exists('\\WebCareProScanner\\Notifications\\WebhookService')) {
                \WebCareProScanner\Notifications\WebhookService::send_scan_alert($scan_id, $open_issues_count, $summary['score'], $target, $enriched_issues);
            }

            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => $enriched_issues,
                'diagnostics' => $diagnostics,
                'status'      => 'completed'
            ]);
        } catch (\Throwable $e) {
            ScanLock::release($scan_id);
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WebCare Pro] Error during deep audit: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());

            return new \WP_Error(
                'audit_error',
                /* translators: %s: error message */
                sprintf(__('Audit failed: %s', 'webcare-pro-security'), $e->getMessage()),
                ['status' => 500]
            );
        }
    }

    public static function get_latest_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        // Retrieve available scans for the Dashboard scan ID switcher (comprehensive, custom & targeted scans)
        $avail_sql = "SELECT id, scan_target, status, started_at, completed_at, total_files, scanned_files, issues_found, risk_score FROM `{$table_scans}` ORDER BY id DESC LIMIT 50";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $available_scans_raw = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $avail_sql,
            ARRAY_A
        );
        $available_scans = [];
        if (!empty($available_scans_raw)) {
            foreach ($available_scans_raw as $as_row) {
                $as_meta = self::format_scan_target_meta($as_row['scan_target'] ?? 'plugins_themes');
                $as_row['scan_target_name'] = $as_meta['name'];
                $as_row['scan_target_short'] = $as_meta['short_name'];
                $as_row['scan_target_category'] = $as_meta['category'];
                $as_row['scan_category'] = $as_meta['category'];
                $as_row['target_meta'] = $as_meta;
                $available_scans[] = $as_row;
            }
        }

        $requested_scan_id = (int) $request->get_param('scan_id');
        if (!$requested_scan_id && !empty($_SERVER['REQUEST_URI'])) {
            $raw_req_uri = sanitize_text_field((string) wp_unslash($_SERVER['REQUEST_URI']));
            if (preg_match('/[?&]scan_id=(\d+)/', $raw_req_uri, $m)) {
                $requested_scan_id = (int) $m[1];
            }
        }
        $target_filter = sanitize_text_field($request->get_param('target'));

        if ($requested_scan_id > 0) {
            // Specific scan ID requested via dashboard switcher
            $req_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $latest_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($req_sql, $requested_scan_id),
                ARRAY_A
            );
        } elseif ($target_filter) {
            $target_sql = "SELECT * FROM `{$table_scans}` WHERE scan_target = %s ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $latest_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($target_sql, $target_filter),
                ARRAY_A
            );
        } else {
            // Prefer comprehensive or custom scan for main dashboard view
            $std_sql = "SELECT * FROM `{$table_scans}` WHERE scan_target IN ('plugins_themes', 'full', 'custom') ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $latest_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $std_sql,
                ARRAY_A
            );
            if (!$latest_scan) {
                // Fallback to any latest scan if no standard/custom scan exists
                $fall_sql = "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $latest_scan = $wpdb->get_row(
                    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                    $fall_sql,
                    ARRAY_A
                );
            }
        }

        if (!$latest_scan) {
            return rest_ensure_response([
                'has_scan'        => false,
                'scan'            => null,
                'summary'         => null,
                'issues'          => [],
                'files'           => [],
                'available_scans' => $available_scans ?: [],
            ]);
        }

        // Prune any duplicate issue rows for this scan to keep database clean
        self::prune_duplicate_issues((int) $latest_scan['id']);

        $iss_list_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_list_sql, $latest_scan['id']),
            ARRAY_A
        );
        $issues = self::enrich_issues($issues);

        // Recalculate true active open issues count for latest scan record
        $open_issues_count = count(array_filter($issues, function ($i) {
            return ($i['status'] ?? 'open') === 'open' && empty($i['is_whitelisted']);
        }));
        if ((int) $latest_scan['issues_found'] !== $open_issues_count) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $open_issues_count], ['id' => $latest_scan['id']]);
            $latest_scan['issues_found'] = $open_issues_count;
        }

        $files_list_sql = "SELECT * FROM `{$table_files}` WHERE scan_id = %d ORDER BY id ASC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scanned_files = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($files_list_sql, $latest_scan['id']),
            ARRAY_A
        );

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);
        if ((int) $latest_scan['risk_score'] !== (int) $summary['score']) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['risk_score' => (int) $summary['score']], ['id' => $latest_scan['id']]);
            $latest_scan['risk_score'] = (int) $summary['score'];
        }
        $latest_target_meta = self::format_scan_target_meta($latest_scan['scan_target'] ?? 'plugins_themes');
        $latest_scan['target_meta'] = $latest_target_meta;
        $latest_scan['scan_target_name'] = $latest_target_meta['name'];
        $latest_scan['scan_target_short'] = $latest_target_meta['short_name'];
        $latest_scan['scan_target_category'] = $latest_target_meta['category'];

        $diagnostics = self::build_scan_diagnostics($latest_scan);

        return rest_ensure_response([
            'has_scan'        => true,
            'scan'            => $latest_scan,
            'summary'         => $summary,
            'issues'          => $issues,
            'files'           => $scanned_files,
            'diagnostics'     => $diagnostics,
            'available_scans' => $available_scans ?: [],
        ]);
    }

    public static function update_issue(\WP_REST_Request $request) {
        global $wpdb;

        $issue_id = (int) $request->get_param('id');
        $status = sanitize_text_field($request->get_param('status') ?: 'ignored');

        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $iss_row_sql = "SELECT * FROM {$table_issues} WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issue = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_row_sql, $issue_id)
        );

        if ($status === 'open' && $issue && !empty($issue->file_path)) {
            \WebCareProScanner\Findings\WhitelistManager::revoke_rules_for_target($issue->file_path, $issue->type ?? '');
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $updated = $wpdb->update($table_issues, ['status' => $status], ['id' => $issue_id]);

        if ($issue && !empty($issue->scan_id)) {
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            $open_iss_sql = "SELECT COUNT(*) FROM {$table_issues} WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $open_issues = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($open_iss_sql, $issue->scan_id)
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $open_issues], ['id' => $issue->scan_id]);
        }

        return rest_ensure_response([
            'success' => $updated !== false,
            'id'      => $issue_id,
            'status'  => $status,
        ]);
    }

    public static function quarantine_file(\WP_REST_Request $request) {
        $file_path = sanitize_text_field($request->get_param('file_path'));
        $issue_id = $request->get_param('issue_id') ? (int) $request->get_param('issue_id') : null;
        $scan_id = $request->get_param('scan_id') ? (int) $request->get_param('scan_id') : null;

        $qm = new QuarantineManager();
        $result = $qm->quarantine_file($file_path, $scan_id, $issue_id);

        return rest_ensure_response($result);
    }

    public static function restore_quarantine(\WP_REST_Request $request) {
        $quarantine_id = (int) $request->get_param('id');

        $qm = new QuarantineManager();
        $result = $qm->restore_file($quarantine_id);

        return rest_ensure_response($result);
    }

    public static function delete_quarantine(\WP_REST_Request $request) {
        $quarantine_id = (int) $request->get_param('id');
        $qm = new QuarantineManager();
        $result = $qm->delete_record($quarantine_id);

        return rest_ensure_response($result);
    }

    public static function clear_restored_quarantine(\WP_REST_Request $request) {
        $qm = new QuarantineManager();
        $result = $qm->clear_restored_records();

        return rest_ensure_response($result);
    }

    public static function list_quarantine(\WP_REST_Request $request) {
        $qm = new QuarantineManager();
        $records = $qm->list_records();

        return rest_ensure_response([
            'success' => true,
            'records' => $records,
        ]);
    }

    public static function get_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $limit = (int) ($request->get_param('limit') ?: 50);
        $hist_sql = "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $history = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($hist_sql, $limit),
            ARRAY_A
        );

        $scans = [];
        if (!empty($history)) {
            foreach ($history as $row) {
                $diag = self::build_scan_diagnostics($row);
                $row['diagnostics'] = $diag;
                $row['duration_formatted'] = $diag['duration_formatted'] ?? ($row['duration'] . 's');
                if (empty($row['trigger_type'])) {
                    $row['trigger_type'] = 'manual';
                }
                $t_meta = self::format_scan_target_meta($row['scan_target'] ?? 'plugins_themes');
                $row['target_meta'] = $t_meta;
                $row['scan_target_name'] = $t_meta['name'];
                $row['scan_target_short'] = $t_meta['short_name'];
                $row['scan_target_category'] = $t_meta['category'];
                $row['id'] = (int) $row['id'];
                $row['scanned_files'] = (int) ($row['scanned_files'] ?? 0);
                $row['issues_found'] = (int) ($row['issues_found'] ?? 0);
                $row['risk_score'] = (int) ($row['risk_score'] ?? 0);
                $row['duration'] = is_numeric($row['duration'] ?? null) ? (float) $row['duration'] : 0.0;
                $row = self::enrich_scan_row_timestamps($row);

                if (in_array($row['status'], ['interrupted', 'aborted', 'failed'], true)) {
                    $row['interruption'] = \WebCareProScanner\Scan\ScanInterruptionForensics::get($row['id']);
                }

                $scans[] = $row;
            }
        }

        return rest_ensure_response([
            'success' => true,
            'scans'   => $scans,
        ]);
    }


    public static function clear_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        // 1. Identify any scans that are actively running or in progress
        $run_sql = "SELECT id FROM `{$table_scans}` WHERE status = 'running'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $running_scans = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $run_sql,
            ARRAY_A
        );
        $running_ids = !empty($running_scans) ? array_map('intval', wp_list_pluck($running_scans, 'id')) : [];

        // Check if there is an active lock for an additional running scan
        $locked_id = (int) ScanLock::get_locked_scan_id();
        if ($locked_id > 0 && !in_array($locked_id, $running_ids, true)) {
            $running_ids[] = $locked_id;
        }

        if (!empty($running_ids)) {
            // There IS an active scan in progress!
            // Preserve the active running scan(s) and their issues/files. Delete only historical records.
            $placeholders = implode(',', array_map('intval', $running_ids));
            $del_iss_sql = "DELETE FROM `{$table_issues}` WHERE scan_id NOT IN ({$placeholders})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_iss_sql);

            $del_files_sql = "DELETE FROM `{$table_files}` WHERE scan_id NOT IN ({$placeholders})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_files_sql);

            $del_scans_sql = "DELETE FROM `{$table_scans}` WHERE id NOT IN ({$placeholders})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_scans_sql);

            // Do NOT release lock because the scan is actively running!
            return rest_ensure_response([
                'success'        => true,
                'has_active'     => true,
                'active_scan_id' => reset($running_ids),
                'message'        => sprintf(
                    /* translators: %s: running scan IDs */
                    __('Past scan logs cleared successfully. Actively running scan (#%s) was preserved and continues executing uninterrupted.', 'webcare-pro-security'),
                    implode(', #', $running_ids)
                ),
            ]);
        }

        // 2. No scan is currently running: safe to truncate all tables cleanly
        $trunc_scans = "TRUNCATE TABLE `{$table_scans}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($trunc_scans);
        $trunc_issues = "TRUNCATE TABLE `{$table_issues}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($trunc_issues);
        $trunc_files = "TRUNCATE TABLE `{$table_files}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($trunc_files);

        ScanLock::release(ScanLock::get_locked_scan_id() ?: 0);

        return rest_ensure_response([
            'success'    => true,
            'has_active' => false,
            'message'    => __('All old scan logs and history records cleared successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function get_scan_log_detail(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('id');
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        $get_scan_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($get_scan_sql, $scan_id),
            ARRAY_A
        );
        if (!$scan) {
            return new \WP_Error('scan_not_found', 'Scan log not found', ['status' => 404]);
        }

        // Prune any duplicate issue rows for this historical log to heal database
        self::prune_duplicate_issues($scan_id);

        $scan_iss_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($scan_iss_sql, $scan_id),
            ARRAY_A
        );
        $issues = self::enrich_issues($issues);

        $fc_sql = "SELECT COUNT(*) FROM `{$table_files}` WHERE scan_id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $files_count = (int) $wpdb->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($fc_sql, $scan_id)
        );

        if (empty($scan['trigger_type'])) {
            $scan['trigger_type'] = 'manual';
        }
        $detail_target_meta = self::format_scan_target_meta($scan['scan_target'] ?? 'plugins_themes');
        $scan['target_meta'] = $detail_target_meta;
        $scan['scan_target_name'] = $detail_target_meta['name'];
        $scan['scan_target_short'] = $detail_target_meta['short_name'];
        $scan['scan_target_category'] = $detail_target_meta['category'];
        $scan = self::enrich_scan_row_timestamps($scan);

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);
        $diagnostics = self::build_scan_diagnostics($scan);

        $interruption = null;
        if (in_array($scan['status'], ['interrupted', 'aborted', 'failed'], true)) {
            $interruption = \WebCareProScanner\Scan\ScanInterruptionForensics::get($scan_id);
        }

        return rest_ensure_response([
            'success'      => true,
            'scan'         => $scan,
            'summary'      => $summary,
            'issues'       => $issues,
            'files_count'  => $files_count,
            'diagnostics'  => $diagnostics,
            'interruption' => $interruption,
        ]);
    }

    public static function export_scan_results(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('scan_id');
        $format  = sanitize_key($request->get_param('format') ?: 'json');

        $table_scans  = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';

        if ($scan_id > 0) {
            $get_s_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($get_s_sql, $scan_id),
                ARRAY_A
            );
        } else {
            $get_s_sql = "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $get_s_sql,
                ARRAY_A
            );
        }

        if (!$scan) {
            return new \WP_Error('scan_not_found', 'No scan record found to export.', ['status' => 404]);
        }

        $iss_s_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_s_sql, (int) $scan['id']),
            ARRAY_A
        );
        $issues = self::enrich_issues($issues);

        $scorer  = new RiskScorer();
        $summary = $scorer->calculate($issues);
        $diagnostics = self::build_scan_diagnostics($scan);

        $include_system_info = !empty($request->get_param('include_system_info'));

        if ($format === 'csv') {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Writing to in-memory temporary stream for REST CSV export
            $output  = fopen('php://temp', 'r+');
            // Sysadmin Telemetry & Environment comments header
            $site_url = get_site_url();
            $site_name = get_bloginfo('name');

            if ($include_system_info) {
                $peak_ram = $diagnostics['peak_memory_fmt'] . ' / ' . $diagnostics['memory_limit_raw'] . ' (' . $diagnostics['memory_percent'] . '%)';
                $throughput = $diagnostics['files_per_second'] . ' files/sec';
                $cpu_str = !empty($diagnostics['cpu_load'])
                    ? '1m: ' . ($diagnostics['cpu_load']['1m'] ?? '-') . ', 5m: ' . ($diagnostics['cpu_load']['5m'] ?? '-') . ', 15m: ' . ($diagnostics['cpu_load']['15m'] ?? '-')
                    : 'N/A';
                if (!empty($diagnostics['cpu_cores'])) {
                    $cpu_str .= ' (' . $diagnostics['cpu_cores'] . ' Cores)';
                }
                $server_soft = $diagnostics['server_software'] ?? 'Unknown';
                $server_os = $diagnostics['server_os'] . ' (' . ($diagnostics['server_arch'] ?? 'x86_64') . ')';
                $php_info = 'PHP ' . $diagnostics['php_version'] . ' (' . $diagnostics['php_sapi'] . ') | Max Execution: ' . ($diagnostics['php_max_execution_time'] ?? '30') . 's';
                $db_info = 'MySQL ' . ($diagnostics['database_version'] ?? 'N/A');

                $telemetry = class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot') ? \WebCareProScanner\System\TelemetrySnapshot::get_snapshot() : null;
                $cf_text = !empty($telemetry['edge_network']['powered_by_cloudflare']) ? 'YES (' . ($telemetry['edge_network']['cloudflare_status'] ?? 'Cloudflare Edge') . ')' : 'NO (Direct Origin)';
                $act_plugins = !empty($telemetry['plugins']['active_plugins']) ? array_column($telemetry['plugins']['active_plugins'], 'name') : [];
                $act_plugins_str = implode(', ', array_slice($act_plugins, 0, 15)) . (count($act_plugins) > 15 ? sprintf(' ... (+%d more)', count($act_plugins) - 15) : '');

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# ====================================================================\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# WebCare Pro Security & Firewall - Audit Findings Report\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Auditor: Mir Alamin (WebCare Pro) - Senior Linux SysAdmin & WordPress Security Engineer\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Target: {$site_name} ({$site_url})\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Real Server IP: " . ($telemetry['server']['real_ip'] ?? 'Unknown') . " | Cloudflare: {$cf_text}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Peak RAM: {$peak_ram}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Throughput: {$throughput}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# CPU Load: {$cpu_str}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Server Software: {$server_soft}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Platform & OS: {$server_os}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# PHP Environment: {$php_info}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Database: {$db_info}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Active Theme: " . ($telemetry['theme']['active_theme']['name'] ?? 'Unknown') . " (v" . ($telemetry['theme']['active_theme']['version'] ?? 'Unknown') . ")\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Active Plugins (" . count($act_plugins) . "): {$act_plugins_str}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Active Engines: " . ($diagnostics['engines_active'] ?? 23) . " Core Security Engines\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Exported: " . current_time('mysql') . "\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# ====================================================================\r\n");
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Target: {$site_name} ({$site_url})\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Peak RAM: {$peak_ram}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Throughput: {$throughput}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# CPU Load: {$cpu_str}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Server Software: {$server_soft}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Platform & OS: {$server_os}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# PHP Environment: {$php_info}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Database: {$db_info}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Active Engines: " . ($diagnostics['engines_active'] ?? 23) . " Core Security Engines\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Exported: " . current_time('mysql') . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# ====================================================================\r\n");

            $headers = [
                'ID',
                'Severity',
                'Engine',
                'Threat Type',
                'File / Target',
                'Line Number',
                'SHA-256 Hash',
                'File Permissions',
                'Owner:Group',
                'File Size',
                'Created Time (ctime)',
                'Last Edited (mtime)',
                'Last Accessed (atime)',
                'MIME Type',
                'Is Writable',
                'Status',
                'Description & Remediation',
            ];
            fputcsv($output, $headers);

            foreach ($issues as $issue) {
                $fs = $issue['fs_forensics'] ?? [];
                $sha256 = $issue['sha256'] ?? ($issue['file_sha256'] ?? ($fs['sha256'] ?? ''));
                $perms = !empty($fs['current_permissions']) ? $fs['current_permissions'] . ' (' . ($fs['symbolic_permissions'] ?? '') . ')' : '';
                $owner_group = (!empty($fs['owner']) || !empty($fs['group'])) ? ($fs['owner'] ?? 'unknown') . ':' . ($fs['group'] ?? 'unknown') : '';
                $size = $fs['file_size_formatted'] ?? (!empty($fs['file_size']) ? $fs['file_size'] . ' B' : '');
                $ctime = $fs['created_time'] ?? '';
                $mtime = $fs['modified_time'] ?? '';
                $atime = $fs['accessed_time'] ?? '';
                $mime = $fs['mime_type'] ?? '';
                $writable = isset($fs['is_writable']) ? ($fs['is_writable'] ? 'Yes' : 'No') : '';

                fputcsv($output, [
                    $issue['id'] ?? '',
                    strtoupper($issue['severity'] ?? 'low'),
                    $issue['engine'] ?? '',
                    $issue['display_title'] ?? ($issue['type'] ?? ''),
                    $issue['file_path'] ?? '',
                    $issue['line_number'] ?? '',
                    $sha256,
                    $perms,
                    $owner_group,
                    $size,
                    $ctime,
                    $mtime,
                    $atime,
                    $mime,
                    $writable,
                    $issue['status'] ?? 'open',
                    $issue['description'] ?? '',
                ]);
            }

            rewind($output);
            $csv_data = stream_get_contents($output);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($output);

            $host_raw   = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
            $domain     = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
            $date_token = gmdate('Y-m-d');
            $time_token = gmdate('His');
            $rand_token = substr(wp_generate_password(8, false), 0, 5);
            $filename   = "scan-report-{$date_token}-{$time_token}-{$domain}-{$rand_token}.csv";

            return rest_ensure_response([
                'success'     => true,
                'format'      => 'csv',
                'filename'    => $filename,
                'csv_data'    => $csv_data,
                'diagnostics' => $diagnostics,
            ]);
        }

        $host_raw   = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
        $domain     = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
        $date_token = gmdate('Y-m-d');
        $time_token = gmdate('His');
        $rand_token = substr(wp_generate_password(8, false), 0, 5);
        $filename   = "scan-report-{$date_token}-{$time_token}-{$domain}-{$rand_token}.json";

        $response_data = [
            'success'            => true,
            'format'             => 'json',
            'filename'           => $filename,
            'report_generator'   => 'WebCare Pro Security & Firewall',
            'specialist'         => 'Mir Alamin (WebCare Pro)',
            'specialist_role'    => 'Senior Linux SysAdmin & WordPress Security Engineer',
            'site_url'           => get_site_url(),
            'site_name'          => get_bloginfo('name'),
            'exported_at'        => current_time('mysql'),
            'scan'               => $scan,
            'summary'            => $summary,
            'diagnostics'        => $diagnostics,
            'server_diagnostics' => [
                'peak_ram'               => $diagnostics['peak_memory_fmt'],
                'peak_ram_mb'            => $diagnostics['peak_memory_mb'],
                'memory_limit'           => $diagnostics['memory_limit_raw'],
                'memory_usage_percent'   => $diagnostics['memory_percent'] . '%',
                'throughput'             => $diagnostics['files_per_second'] . ' files/sec',
                'files_per_second'       => $diagnostics['files_per_second'],
                'cpu_load'               => $diagnostics['cpu_load'],
                'cpu_cores'              => $diagnostics['cpu_cores'] ?? null,
                'server_software'        => $diagnostics['server_software'] ?? 'Unknown',
                'server_os'              => $diagnostics['server_os'],
                'server_architecture'    => $diagnostics['server_arch'] ?? 'x86_64',
                'php_version'            => $diagnostics['php_version'],
                'php_sapi'               => $diagnostics['php_sapi'],
                'php_max_execution_time' => ($diagnostics['php_max_execution_time'] ?? 30) . 's',
                'database_version'       => $diagnostics['database_version'] ?? 'N/A',
                'database_name'          => $diagnostics['database_name'] ?? 'N/A',
                'wordpress_version'      => $diagnostics['wordpress_version'] ?? 'N/A',
                'ssl_active'             => !empty($diagnostics['ssl_active']) ? 'Active (HTTPS)' : 'Inactive (HTTP)',
                'opcache'                => $diagnostics['opcache_status'] ?? 'Disabled',
                'active_engines'         => $diagnostics['engines_active'] ?? 23,
            ],
            'findings_count'     => count($issues),
            'findings'           => $issues,
        ];

        if ($include_system_info && class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')) {
            $response_data['environment_snapshot'] = \WebCareProScanner\System\TelemetrySnapshot::get_snapshot();
        }

        return rest_ensure_response($response_data);
    }

    public static function get_server_info(\WP_REST_Request $request) {
        $refresh = (bool) $request->get_param('refresh');
        if ($refresh && function_exists('delete_transient')) {
            delete_transient('webcareproscan_server_filesystem_metrics');
        }
        return rest_ensure_response([
            'success' => true,
            'info'    => ServerInfo::get_info(true),
        ]);
    }

    /**
     * Get diagnostic telemetry snapshot for log export & incident triage.
     */
    public static function get_telemetry_snapshot(\WP_REST_Request $request): \WP_REST_Response {
        $snapshot = class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')
            ? \WebCareProScanner\System\TelemetrySnapshot::get_snapshot()
            : [];

        return rest_ensure_response([
            'success'  => true,
            'snapshot' => $snapshot,
        ]);
    }

    /**
     * Get comprehensive system readiness & compatibility audit report.
     */
    public static function get_system_readiness(\WP_REST_Request $request): \WP_REST_Response {
        $report = \WebCareProScanner\System\SystemReadinessChecker::check_all();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    /**
     * Dismiss first-time welcome modal.
     */
    public static function dismiss_welcome_modal(\WP_REST_Request $request): \WP_REST_Response {
        \WebCareProScanner\System\SystemReadinessChecker::dismiss_welcome();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Welcome dialog dismissed successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function get_vulnerabilities_report(\WP_REST_Request $request) {
        $report = UpdateScanner::get_detailed_report();

        $shielded_slugs = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            foreach (\WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_active_rules() as $mr) {
                if (($mr['category'] ?? '') === 'cve_patch' && ($mr['current_mode'] ?? '') === 'enforce' && !empty($mr['component_slug'])) {
                    $shielded_slugs[$mr['component_slug']] = $mr['id'];
                }
            }
        }
        $safe_backups = get_option(\WebCareProScanner\Firewall\RescueAssistantManager::OPTION_SAFE_UPDATES, []);

        return rest_ensure_response([
            'success'             => true,
            'report'              => $report,
            'virtual_shields'     => $shielded_slugs,
            'safe_update_backups' => is_array($safe_backups) ? $safe_backups : [],
        ]);
    }

    /**
     * Activate 1-click Virtual Shield (MOD-CVE-*) for an outdated or vulnerable component without updating.
     */
    public static function activate_vulnerability_virtual_shield(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Virtual shield synthesizer unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $slug   = sanitize_key($params['slug'] ?? '');
        $type   = sanitize_key($params['type'] ?? 'plugin');
        $res    = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::activate_cve_shield($slug, $type);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    /**
     * Safely back up a plugin to Gatekeeper storage and run WordPress Plugin_Upgrader.
     */
    public static function execute_safe_plugin_update(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Safe update manager unavailable.', 'webcare-pro-security')], 500);
        }
        $params      = $request->get_json_params() ?: [];
        $plugin_file = sanitize_text_field(wp_unslash($params['plugin_file'] ?? ''));
        $slug        = sanitize_key($params['slug'] ?? '');
        $name        = sanitize_text_field(wp_unslash($params['name'] ?? ''));
        $res         = \WebCareProScanner\Firewall\RescueAssistantManager::safe_update_plugin($plugin_file, $slug, $name);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    /**
     * Roll back a safely updated plugin to its Gatekeeper pre-update backup snapshot.
     */
    public static function execute_safe_plugin_rollback(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Safe update manager unavailable.', 'webcare-pro-security')], 500);
        }
        $params      = $request->get_json_params() ?: [];
        $snapshot_id = sanitize_text_field(wp_unslash($params['snapshot_id'] ?? ''));
        $res         = \WebCareProScanner\Firewall\RescueAssistantManager::rollback_safe_update($snapshot_id);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    public static function get_backup_preflight(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $info = $db_backup->get_preflight_info();
        return rest_ensure_response([
            'success' => true,
            'info'    => $info,
        ]);
    }

    public static function start_backup_session(\WP_REST_Request $request) {
        $throttle_ms = $request->get_param('throttle_ms');
        $batch_size = $request->get_param('batch_size');
        $db_backup = new DatabaseBackup();
        $options = [];
        if ($throttle_ms !== null) {
            $options['throttle_ms'] = (int) $throttle_ms;
        }
        if ($batch_size !== null) {
            $options['batch_size'] = (int) $batch_size;
        }
        $res = $db_backup->start_session($options);
        return rest_ensure_response($res);
    }

    public static function step_backup_session(\WP_REST_Request $request) {
        $session_id = sanitize_text_field($request->get_param('session_id'));
        $throttle_ms = $request->get_param('throttle_ms');
        $db_backup = new DatabaseBackup();
        $res = $db_backup->step_session($session_id, $throttle_ms !== null ? (int) $throttle_ms : null);
        return rest_ensure_response($res);
    }

    public static function get_backup_session_status(\WP_REST_Request $request) {
        $session_id = sanitize_text_field($request->get_param('session_id'));
        $db_backup = new DatabaseBackup();
        $state = $db_backup->get_session_state($session_id);
        if (!$state) {
            return new \WP_Error('session_not_found', 'Backup session not found.', ['status' => 404]);
        }
        return rest_ensure_response([
            'success'   => true,
            'status'    => $state['status'],
            'state'     => $state,
        ]);
    }

    public static function get_active_backup(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $active = $db_backup->get_active_session();
        return rest_ensure_response([
            'success'   => true,
            'is_running'=> !empty($active) && ($active['status'] ?? '') === 'running',
            'session'   => $active,
        ]);
    }

    public static function cancel_backup_session(\WP_REST_Request $request) {
        $session_id = sanitize_text_field($request->get_param('session_id'));
        $db_backup = new DatabaseBackup();
        $res = $db_backup->cancel_session($session_id);
        return rest_ensure_response($res);
    }

    public static function create_backup(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $res = $db_backup->create_backup();
        return rest_ensure_response($res);
    }

    public static function list_backups(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        return rest_ensure_response([
            'success' => true,
            'backups' => $db_backup->list_backups(),
        ]);
    }

    public static function delete_backup(\WP_REST_Request $request) {
        $filename = sanitize_text_field($request->get_param('filename'));
        $db_backup = new DatabaseBackup();
        $deleted = $db_backup->delete_backup($filename);
        return rest_ensure_response([
            'success' => $deleted,
            'message' => $deleted ? 'Backup deleted successfully.' : 'Could not delete backup.',
        ]);
    }

    public static function download_backup(\WP_REST_Request $request) {
        $filename = sanitize_text_field($request->get_param('filename'));
        $db_backup = new DatabaseBackup();
        $path = $db_backup->get_backup_path($filename);

        if (!$path || !file_exists($path)) {
            return new \WP_Error('not_found', 'Backup file not found.', ['status' => 404]);
        }

        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($path) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($path));
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- Streaming raw binary backup file to HTTP client
        readfile($path);
        exit;
    }

    public static function get_active_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $locked_id = ScanLock::get_locked_scan_id();

        // If no lock option exists, check if there is an active scan record in the DB created recently
        if (!$locked_id) {
            // Find and record any stale scans marked 'running' older than 10 minutes
            $stale_scans_sql = "SELECT id, scanned_files, total_files FROM `{$table_scans}` WHERE status = 'running' AND created_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $stale_scans = $wpdb->get_results($stale_scans_sql, ARRAY_A);
            if (!empty($stale_scans)) {
                foreach ($stale_scans as $stale_row) {
                    $stale_id = (int) $stale_row['id'];
                    \WebCareProScanner\Scan\ScanInterruptionForensics::record($stale_id, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT);
                }
            }

            // Clean up any stale scans marked 'running' older than 10 minutes
            $cleanup_stale = "UPDATE `{$table_scans}` SET status = 'interrupted', completed_at = NOW() WHERE status = 'running' AND created_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($cleanup_stale);

            // Fallback: check if any recent scan (< 5 mins) is legitimately running in database
            $rec_act_sql = "SELECT * FROM `{$table_scans}` WHERE status = 'running' AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $recent_active = $wpdb->get_row($rec_act_sql, ARRAY_A);

            if ($recent_active) {
                $locked_id = (int) $recent_active['id'];
                ScanLock::acquire($locked_id);
            } else {
                return rest_ensure_response([
                    'is_running' => false,
                ]);
            }
        }

        $run_scan_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $running_scan = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($run_scan_sql, $locked_id),
            ARRAY_A
        );

        if (!$running_scan || $running_scan['status'] !== 'running') {
            ScanLock::release($locked_id);
            return rest_ensure_response([
                'is_running' => false,
            ]);
        }

        // Lock heartbeat
        $total = (int) $running_scan['total_files'];
        $scanned = (int) $running_scan['scanned_files'];
        $trigger_type = !empty($running_scan['trigger_type']) ? $running_scan['trigger_type'] : 'manual';
        $remaining = \WebCareProScanner\Scan\ScanQueueManager::get_remaining_count($locked_id);
        if ($remaining === 0 && $total > $scanned) {
            $remaining = max(0, $total - $scanned);
        }
        $last_file = get_transient("webcareproscan_active_scan_file_{$locked_id}") ?: '';
        $db_progress = get_transient("webcareproscan_scan_db_progress_{$locked_id}");

        $live_telemetry = get_transient("webcareproscan_scan_live_telemetry_{$locked_id}");
        if (!$live_telemetry || !is_array($live_telemetry)) {
            $live_telemetry = self::get_realtime_resource_stats(null, null, $scanned, $total, (int) $running_scan['issues_found'], 0.0);
        }

        return rest_ensure_response([
            'is_running'     => true,
            'scan_id'        => $locked_id,
            'scan_target'    => $running_scan['scan_target'],
            'trigger_type'   => $trigger_type,
            'status'         => 'running',
            'scanned_files'  => $scanned,
            'total_files'    => $total,
            'remaining'      => $remaining,
            'last_file'      => $last_file,
            'db_progress'    => is_array($db_progress) ? $db_progress : null,
            'issues_found'   => (int) $running_scan['issues_found'],
            'telemetry'      => $live_telemetry,
            'phase'          => ($trigger_type === 'scheduled') 
                ? (($scanned >= $total && $total > 0) ? 'deep_audit' : 'batch')
                : (($remaining > 0) ? 'batch' : 'deep_audit'),
            'created_at'     => $running_scan['created_at'],
            'started_at'     => $running_scan['started_at'] ?? $running_scan['created_at'],
            'elapsed'        => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("webcareproscan_scan_start_micro_{$locked_id}");
                if ($start_micro && is_numeric($start_micro)) {
                    $diff = microtime(true) - (float) $start_micro;
                    if ($diff > 0) return max(1, (int) round($diff));
                }
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], wp_timezone());
                    if ($start_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        return max(1, $now_dt->getTimestamp() - $start_dt->getTimestamp());
                    }
                }
                if (empty($running_scan['created_at'])) return 1;
                $created_dt = date_create($running_scan['created_at'], wp_timezone());
                if ($created_dt) {
                    $now_dt = date_create('now', wp_timezone());
                    return max(1, $now_dt->getTimestamp() - $created_dt->getTimestamp());
                }
                return 1;
            })(),
            'elapsed_ms'     => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("webcareproscan_scan_start_micro_{$locked_id}");
                if ($start_micro && is_numeric($start_micro)) {
                    $diff = microtime(true) - (float) $start_micro;
                    if ($diff > 0) return (int) round($diff * 1000);
                }
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], wp_timezone());
                    if ($start_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        $diff = $now_dt->getTimestamp() - $start_dt->getTimestamp() + (($now_dt->format('u') - $start_dt->format('u')) / 1000000);
                        return max(100, (int) round($diff * 1000));
                    }
                }
                return 1000;
            })(),
        ]);
    }

    public static function abort_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $scan_id = (int) $request->get_param('scan_id');
        if (!$scan_id) {
            $scan_id = ScanLock::get_locked_scan_id();
        }

        $now_exact = self::now_fractional_mysql();

        if ($scan_id) {
            $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
            $duration_ms = 0;
            $duration_sec = 0;
            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }
            $last_file = get_transient("webcareproscan_active_scan_file_{$scan_id}") ?: '';
            delete_transient("webcareproscan_scan_start_micro_{$scan_id}");

            // Record manual abort forensic details
            \WebCareProScanner\Scan\ScanInterruptionForensics::record($scan_id, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_MANUAL_ABORT, [
                'last_file' => $last_file,
            ]);

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'duration'     => $duration_sec,
                'duration_ms'  => $duration_ms,
                'completed_at' => $now_exact,
            ], ['id' => $scan_id]);
            \WebCareProScanner\Scan\ScanQueueManager::cleanup($scan_id);
            ScanLock::release($scan_id);
        }

        // Also release any active scan lock and ensure any hanging scans are aborted
        ScanLock::release();
        $abort_sql = "UPDATE `{$table_scans}` SET status = 'aborted', completed_at = %s WHERE status = 'running'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($abort_sql, $now_exact)
        );

        return rest_ensure_response([
            'success' => true,
            'message' => 'Scan successfully aborted and lock released.',
        ]);
    }

    /**
     * Enrich findings with real-time WordPress post/page URLs, edit links, and file metadata.
     *
     * @param array $issues
     * @return array
     */
    public static function enrich_issues(array $issues) {
        $norm_abspath = wp_normalize_path(ABSPATH);

        foreach ($issues as &$item) {
            $filePath = $item['file_path'] ?? '';
            $engine = $item['engine'] ?? '';
            $type = $item['type'] ?? '';

            // 0. Check if finding is WordPress Updates / CVE Advisory
            if ($engine === 'wordpress-updates' || in_array($type, ['outdated_core', 'vulnerable_core', 'outdated_plugin', 'vulnerable_plugin', 'outdated_theme', 'vulnerable_theme'])) {
                $item['is_software_update'] = true;
                $evidence = $item['evidence'] ?? '';
                if (!empty($evidence) && is_string($evidence)) {
                    $decoded = json_decode($evidence, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $item['cves'] = $decoded['cves'] ?? [];
                        $item['has_cve'] = !empty($decoded['has_cve']);
                        $item['is_outdated'] = !empty($decoded['is_outdated']);
                        $item['installed_version'] = $decoded['installed'] ?? '';
                        $item['latest_version'] = $decoded['latest'] ?? '';
                        $item['component_name'] = $decoded['name'] ?? '';
                        $item['component_type'] = $decoded['type'] ?? '';
                    }
                }
            }

            // 0b. Check if finding is Theme Checksums Unavailable (Custom / Child / Premium Theme)
            if ($type === 'theme_checksums_unavailable' || ($engine === 'integrity-theme' && (strpos($filePath, '/themes/') !== false || strpos($filePath, '\\themes\\') !== false) && !preg_match('/\.[a-zA-Z0-9]{2,5}$/', $filePath))) {
                $item['is_dir'] = true;
                $item['is_file'] = false;
                $item['can_view'] = false;
                $item['component_type'] = 'theme';

                $evidence_data = !empty($item['evidence']) && is_string($item['evidence']) ? json_decode($item['evidence'], true) : [];
                $path_lower = strtolower($filePath);
                $desc_lower = strtolower($item['description'] ?? '');

                $is_child = !empty($evidence_data['is_child']) || strpos($path_lower, '-child') !== false || strpos($desc_lower, 'child') !== false;
                $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/\b(premium|pro|commercial|license|themeforest|envato)\b/i', $filePath . ' ' . $desc_lower);

                if (!empty($evidence_data['display_title'])) {
                    $item['display_title'] = $evidence_data['display_title'];
                } elseif ($is_child) {
                    $item['display_title'] = __('Custom Child Theme', 'webcare-pro-security');
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Theme', 'webcare-pro-security');
                } else {
                    $item['display_title'] = __('Custom or Premium Theme', 'webcare-pro-security');
                }

                $meta = self::get_theme_forensics_meta($filePath, is_array($evidence_data) ? $evidence_data : []);
                $item['component_meta'] = $meta;
                $item['component_name'] = $meta['name'];
                $item['installed_version'] = $meta['version'];
                $item['latest_version'] = $meta['latest_version'];
                $item['has_update'] = $meta['has_update'];
                $item['author_name'] = $meta['author'];
                $item['author_url'] = $meta['author_uri'];
                $item['component_status'] = $meta['status_label'];
                $item['last_updated'] = $meta['last_modified'];
                $item['has_changelog'] = $meta['has_changelog'];
            }
            // 0c. Check if finding is Plugin Checksums Unavailable (Custom or Premium Plugin)
            elseif ($type === 'plugin_checksums_unavailable' || ($engine === 'integrity-plugin' && (strpos($filePath, '/plugins/') !== false || strpos($filePath, '\\plugins\\') !== false) && !preg_match('/\.[a-zA-Z0-9]{2,5}$/', $filePath))) {
                $item['is_dir'] = true;
                $item['is_file'] = false;
                $item['can_view'] = false;
                $item['component_type'] = 'plugin';

                $evidence_data = !empty($item['evidence']) && is_string($item['evidence']) ? json_decode($item['evidence'], true) : [];
                $path_lower = strtolower($filePath);
                $desc_lower = strtolower($item['description'] ?? '');

                $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/(?:^|[-_])(premium|pro|addon|addons|unlimited|commercial)(?:[-_]|$)/i', $filePath) || (bool) preg_match('/\b(premium|pro|yith|woocommerce)\b/i', $desc_lower);

                if (!empty($evidence_data['display_title'])) {
                    $item['display_title'] = $evidence_data['display_title'];
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Plugin', 'webcare-pro-security');
                } else {
                    $item['display_title'] = __('Custom or Premium Plugin', 'webcare-pro-security');
                }

                $meta = self::get_plugin_forensics_meta($filePath, is_array($evidence_data) ? $evidence_data : []);
                $item['component_meta'] = $meta;
                $item['component_name'] = $meta['name'];
                $item['installed_version'] = $meta['version'];
                $item['latest_version'] = $meta['latest_version'];
                $item['has_update'] = $meta['has_update'];
                $item['author_name'] = $meta['author'];
                $item['author_url'] = $meta['author_uri'];
                $item['component_status'] = $meta['status_label'];
                $item['last_updated'] = $meta['last_modified'];
                $item['has_changelog'] = $meta['has_changelog'];
            }

            // 1. Check if finding is a WordPress Post or Page
            if (preg_match('/^post:(\d+)/i', $filePath, $matches)) {
                $postId = (int) $matches[1];
                $post = get_post($postId);
                if ($post) {
                    $item['is_post'] = true;
                    $item['post_id'] = $postId;
                    $item['post_title'] = $post->post_title ?: __('(Untitled)', 'webcare-pro-security');
                    $item['post_type'] = $post->post_type;
                    $item['view_url'] = get_permalink($postId) ?: '';
                    $item['edit_url'] = get_edit_post_link($postId, 'raw') ?: admin_url("post.php?post={$postId}&action=edit");
                }
            } 
            // 2. Check if finding is a WordPress Comment
            elseif (preg_match('/comment[:_#]?\s*(\d+)/i', $filePath, $matches) || $engine === 'content-comments' || strpos($filePath, 'comment:') === 0) {
                $commentId = !empty($matches[1]) ? (int) $matches[1] : 0;
                $comment = $commentId > 0 ? get_comment($commentId) : null;
                $item['is_comment'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['comment_id'] = $commentId;

                if ($comment) {
                    $item['author_id'] = (int) $comment->user_id;
                    $item['author_name'] = $comment->comment_author ?: __('(Anonymous)', 'webcare-pro-security');
                    $item['author_email'] = $comment->comment_author_email ?: '';
                    $item['author_url'] = $comment->comment_author_url ?: '';
                    $item['author_ip'] = $comment->comment_author_IP ?: '';
                    $item['comment_date'] = $comment->comment_date ?: '';
                    $item['comment_content'] = $comment->comment_content ?: '';
                    if (empty($item['code_snippet'])) {
                        $item['code_snippet'] = $comment->comment_content ?: '';
                    }
                    $postId = (int) $comment->comment_post_ID;
                    $item['post_id'] = $postId;
                    $item['post_title'] = $postId > 0 ? (get_the_title($postId) ?: __('(Untitled Post)', 'webcare-pro-security')) : '';
                    $item['post_url'] = $postId > 0 ? (get_permalink($postId) ?: '') : '';
                    $item['view_url'] = get_comment_link($comment) ?: '';
                    $item['edit_url'] = admin_url("comment.php?action=editcomment&c={$commentId}");
                } else {
                    $item['author_id'] = 0;
                    $item['author_name'] = preg_match('/by\s+(.+)$/i', $filePath, $am) ? trim($am[1]) : __('Unknown Author', 'webcare-pro-security');
                    $item['author_email'] = '';
                    $item['author_url'] = '';
                    $item['author_ip'] = '';
                    $item['comment_date'] = '';
                    $item['comment_content'] = $item['code_snippet'] ?? '';
                    $item['post_id'] = 0;
                    $item['post_title'] = '';
                    $item['post_url'] = '';
                    $item['view_url'] = '';
                    $item['edit_url'] = $commentId > 0 ? admin_url("comment.php?action=editcomment&c={$commentId}") : '';
                }
            } 
            // 3. Check if finding is a WordPress User Account
            elseif (
                preg_match('/(?:^user:|_users:user_id_|users\.ID\s*=\s*)(\d+)/i', $filePath, $userMatches) ||
                preg_match('/User ID:\s*(\d+)/i', $item['evidence'] ?? '', $userMatches) ||
                $engine === 'wordpress-users' ||
                strpos($filePath, 'user:') === 0 ||
                strpos($filePath, '_users:user_id_') !== false ||
                strpos($type, 'user_') === 0 ||
                in_array($type, ['rogue_admin_user', 'hidden_admin_user', 'elevated_privilege_user', 'suspicious_user_capabilities', 'tampered_role_definition', 'generic_admin_username', 'weak_password_detected', 'username_enumeration_risk', 'user_missing_capabilities'], true)
            ) {
                $userId = 0;
                if (!empty($userMatches[1])) {
                    $userId = (int) $userMatches[1];
                } elseif (preg_match('/(?:^user:|^author:|_users:user_id_|users\.ID\s*=\s*)(\d+)/i', $filePath, $m)) {
                    $userId = (int) $m[1];
                } elseif (preg_match('/(?:User|Author)\s*ID:\s*(\d+)/i', $item['evidence'] ?? '', $m)) {
                    $userId = (int) $m[1];
                } elseif (preg_match('/author\s*user\s*ID\s*\((\d+)\)/i', $item['description'] ?? '', $m)) {
                    $userId = (int) $m[1];
                }

                $user = $userId > 0 ? get_userdata($userId) : null;
                $item['is_user'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['user_id'] = $userId;
                $item['user_login'] = $user ? $user->user_login : (preg_match('/\(([^)]+)\)/', $filePath, $m) ? $m[1] : (preg_match('/User\s*\'([^\']+)\'/i', $item['description'] ?? '', $m) ? $m[1] : 'user'));
                $item['user_email'] = $user ? $user->user_email : (preg_match('/Email:\s*([^,\s]+)/i', $item['evidence'] ?? '', $m) ? $m[1] : '');
                $item['user_registered'] = $user ? $user->user_registered : (preg_match('/Registered:\s*([^,\n]+)/i', $item['evidence'] ?? '', $m) ? trim($m[1]) : '');
                $item['user_display_name'] = $user ? $user->display_name : $item['user_login'];
                $item['user_nicename'] = $user ? $user->user_nicename : '';
                $item['first_name'] = $user ? $user->first_name : '';
                $item['last_name'] = $user ? $user->last_name : '';
                
                // User Roles extraction
                $user_roles = $user && !empty($user->roles) ? array_values((array) $user->roles) : [];
                $item['user_roles_list'] = $user_roles;
                $item['user_roles'] = !empty($user_roles) ? implode(', ', $user_roles) : ($item['user_roles'] ?? 'none');

                $current_user_id = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                $is_current_user = ($userId > 0 && $userId === $current_user_id);
                $is_admin = ($user && in_array('administrator', $user_roles, true));

                $item['is_current_user'] = $is_current_user;
                $item['is_admin'] = $is_admin;
                $item['profile_url'] = $is_current_user ? admin_url('profile.php') : ($userId > 0 ? admin_url("user-edit.php?user_id={$userId}") : admin_url('users.php'));
                $item['password_url'] = $is_current_user ? admin_url('profile.php#password') : ($userId > 0 ? admin_url("user-edit.php?user_id={$userId}#password") : admin_url('users.php'));
                $item['edit_url'] = $userId > 0 ? admin_url("user-edit.php?user_id={$userId}") : admin_url("users.php");

                // Injected custom capabilities & complete capabilities matrix
                if ($userId > 0) {
                    global $wpdb;
                    $cap_key = $wpdb->prefix . 'capabilities';
                    $stored_caps = get_user_meta($userId, $cap_key, true);
                    $wp_roles = wp_roles();
                    $injected_caps = [];
                    if (is_array($stored_caps)) {
                        foreach ($stored_caps as $cap_name => $granted) {
                            if (!isset($wp_roles->roles[$cap_name])) {
                                $injected_caps[] = $cap_name;
                            }
                        }
                    }
                    $item['injected_caps'] = $injected_caps;

                    // Comprehensive Developer & Permissions Forensics
                    if ($user) {
                        $allcaps = !empty($user->allcaps) && is_array($user->allcaps) ? $user->allcaps : [];
                        $active_caps = array_keys(array_filter($allcaps));
                        sort($active_caps);
                        $item['all_capabilities'] = $active_caps;
                        $item['capabilities_count'] = count($active_caps);

                        // User Level
                        $user_level = get_user_meta($userId, $wpdb->prefix . 'user_level', true);
                        $item['user_level'] = $user_level !== '' ? (int) $user_level : 0;

                        // Authored Posts Count across published, drafts, pending
                        if (function_exists('count_user_posts')) {
                            $item['authored_posts_count'] = (int) count_user_posts($userId, 'post', true);
                        }

                        // Password hash algorithm preview (safe hint without disclosing hash)
                        if (!empty($user->user_pass)) {
                            $pass_str = (string) $user->user_pass;
                            if (strpos($pass_str, '$P$') === 0) {
                                $item['hash_type'] = 'WordPress phpass ($P$)';
                            } elseif (strpos($pass_str, '$2y$') === 0 || strpos($pass_str, '$2a$') === 0) {
                                $item['hash_type'] = 'Bcrypt ($2y$)';
                            } elseif (strpos($pass_str, '$argon2i$') === 0 || strpos($pass_str, '$argon2id$') === 0) {
                                $item['hash_type'] = 'Argon2';
                            } elseif (strlen($pass_str) === 32 && ctype_xdigit($pass_str)) {
                                $item['hash_type'] = 'Insecure Legacy MD5 (32-char hex)';
                            } else {
                                $item['hash_type'] = 'Standard Hash';
                            }
                        }

                        // Two Factor & Application Passwords detection
                        $app_passwords = get_user_meta($userId, '_application_passwords', true);
                        $item['has_application_passwords'] = is_array($app_passwords) && !empty($app_passwords);
                        $item['application_passwords_count'] = is_array($app_passwords) ? count($app_passwords) : 0;

                        $has_two_factor = get_user_meta($userId, '_two_factor_enabled', true) 
                            || get_user_meta($userId, 'two_factor_provider', true)
                            || get_user_meta($userId, 'wfls-2fa-enabled', true);
                        $item['two_factor_enabled'] = (bool) $has_two_factor;
                    }
                }

                // Specialized handling for Orphaned Post Author
                if ($type === 'orphaned_post_author' || strpos($filePath, 'author:') === 0) {
                    $item['is_orphaned_author'] = true;
                    $item['user_login'] = "Missing User #{$userId}";
                    $item['user_display_name'] = "Missing User #{$userId}";
                    $item['user_roles'] = 'MISSING (Deleted Account)';
                    $item['edit_url'] = ''; // Cannot edit non-existent user profile
                    $item['profile_url'] = '';

                    // Parse evidence or query sample post details
                    $sampleId = 0;
                    $metaJson = null;
                    if (!empty($item['evidence']) && preg_match('/Meta:\s*(\{.*\})/i', $item['evidence'], $mJson)) {
                        $metaJson = json_decode($mJson[1], true);
                    }
                    if ($metaJson && !empty($metaJson['sample_id'])) {
                        $sampleId = (int) $metaJson['sample_id'];
                        $item['orphaned_meta'] = $metaJson;
                    } elseif (!empty($item['description']) && preg_match('/Sample:\s*Post\s*#(\d+)/i', $item['description'], $sm)) {
                        $sampleId = (int) $sm[1];
                    }

                    if ($sampleId > 0) {
                        $samplePost = get_post($sampleId);
                        if ($samplePost) {
                            $item['sample_post_id'] = $sampleId;
                            $item['sample_post_title'] = !empty($samplePost->post_title) ? $samplePost->post_title : __('(Untitled Post)', 'webcare-pro-security');
                            $item['sample_post_slug'] = !empty($samplePost->post_name) ? $samplePost->post_name : '';
                            $item['sample_post_type'] = $samplePost->post_type;
                            $item['sample_post_status'] = $samplePost->post_status;
                            $item['sample_post_date'] = $samplePost->post_date;
                            $permalink = get_permalink($sampleId);
                            $item['sample_view_url'] = $permalink ?: '';
                            $editUrl = get_edit_post_link($sampleId, 'raw');
                            $item['sample_edit_url'] = $editUrl ?: admin_url("post.php?post={$sampleId}&action=edit");
                        }
                    }

                    // Provide current admin info and all active administrator choices for reassignment
                    $currId = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                    $currUser = $currId > 0 ? get_userdata($currId) : null;
                    $item['reassign_target_id'] = $currId;
                    $item['reassign_target_name'] = $currUser ? ($currUser->display_name ?: $currUser->user_login) : 'Administrator';

                    $admin_users_raw = get_users([
                        'role'    => 'administrator',
                        'orderby' => 'display_name',
                        'order'   => 'ASC',
                        'fields'  => ['ID', 'user_login', 'display_name', 'user_email'],
                    ]);
                    $admin_options = [];
                    foreach ($admin_users_raw as $adm) {
                        $admin_options[] = [
                            'id'           => (int) $adm->ID,
                            'user_login'   => $adm->user_login,
                            'display_name' => $adm->display_name ?: $adm->user_login,
                            'user_email'   => $adm->user_email,
                            'is_current'   => ((int) $adm->ID === $currId),
                        ];
                    }
                    $item['admin_options'] = $admin_options;
                }
            } 
            // 4. Check if finding is a Database Table Row
            elseif ($engine === 'database-table' || preg_match('/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i', $filePath)) {
                $tableName = '';
                $columnName = '';
                $rowId = null;

                if (preg_match('/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i', $filePath, $dbMatches)) {
                    $tableName = !empty($dbMatches[1]) ? $dbMatches[1] : '';
                    $columnName = !empty($dbMatches[2]) ? $dbMatches[2] : '';
                    $rowId = !empty($dbMatches[3]) ? (int) $dbMatches[3] : null;
                }
                if (!$rowId && preg_match('/\[ID:\s*(\d+)\]/i', $filePath, $idM)) {
                    $rowId = (int) $idM[1];
                }
                if (!$tableName && strpos($filePath, '.') !== false) {
                    $tableName = explode('.', $filePath)[0];
                }
                if (!$columnName && strpos($filePath, '.') !== false) {
                    $parts = explode('.', $filePath);
                    $columnName = explode(' ', $parts[1])[0];
                }

                $item['is_db_table'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['table_name'] = $tableName;
                $item['column_name'] = $columnName;
                $item['row_id'] = $rowId;
                $item['is_log_table'] = (bool) preg_match('/(log|logs|redirection|audit|history|stat|stats|traffic|404)/i', $tableName);

                // Pre-load full row data if available
                if ($tableName && $rowId) {
                    $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();
                    $dbRow = $mgr->get_row($tableName, $rowId);
                    if ($dbRow) {
                        $item['db_row'] = $dbRow;
                        $item['db_primary_key'] = $mgr->get_primary_key($tableName);
                        if (empty($item['code_snippet']) && isset($dbRow[$columnName])) {
                            $item['code_snippet'] = (string) $dbRow[$columnName];
                        }
                    }

                    // Check if table is WordPress Posts table
                    if (preg_match('/(?:^|_)posts$/i', $tableName)) {
                        $post = get_post($rowId);
                        if ($post) {
                            $item['is_post'] = true;
                            $item['post_id'] = (int) $rowId;
                            $item['post_title'] = !empty($post->post_title) ? $post->post_title : __('(Untitled Post)', 'webcare-pro-security');
                            $item['post_slug'] = !empty($post->post_name) ? $post->post_name : '';
                            $item['post_status'] = !empty($post->post_status) ? $post->post_status : 'publish';
                            $item['post_type'] = !empty($post->post_type) ? $post->post_type : 'post';
                            $item['post_date'] = !empty($post->post_date) ? $post->post_date : '';
                            $item['post_modified'] = !empty($post->post_modified) ? $post->post_modified : '';
                            $item['post_author'] = (int) $post->post_author;
                            $authorData = get_userdata($post->post_author);
                            $item['post_author_name'] = $authorData ? $authorData->display_name : '';
                            $permalink = get_permalink($rowId);
                            $item['post_url'] = $permalink ? $permalink : '';
                            $editUrl = get_edit_post_link($rowId, 'raw');
                            $item['edit_url'] = $editUrl ? $editUrl : admin_url("post.php?post={$rowId}&action=edit");
                        }
                    }
                }
            }
            // 4b. Check if finding is a Server/Network Configuration entity (e.g. reverse proxy, IP detection, network headers)
            elseif (
                $engine === 'ip-detection' ||
                $engine === 'waf-status' ||
                $type === 'reverse_proxy_misconfigured' ||
                strpos($filePath, 'server:') === 0
            ) {
                $item['is_server_config'] = true;
                $item['is_network'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['file_exists'] = false;

                // Environment reconciliation: If running on local development or Docker container, reconcile open false-positives
                $env_type = function_exists('wp_get_environment_type') ? wp_get_environment_type() : (defined('WP_ENVIRONMENT_TYPE') ? WP_ENVIRONMENT_TYPE : 'production');
                $is_local_env = in_array($env_type, ['local', 'development'], true);
                $site_url = get_site_url();
                $host = wp_parse_url($site_url, PHP_URL_HOST) ?: '';
                $is_local_host = in_array($host, ['localhost', '127.0.0.1', '::1'], true)
                    || (bool) preg_match('/\.(local|test|site|internal|lan|docker|localwp|ddev)$/i', $host);
                $is_docker = file_exists('/.dockerenv')
                    || (file_exists('/proc/1/cgroup') && strpos(@file_get_contents('/proc/1/cgroup'), 'docker') !== false);

                if (($is_local_env || $is_local_host || $is_docker) && ($item['status'] ?? 'open') === 'open') {
                    $item['status'] = 'ignored';
                    $item['is_whitelisted'] = false;
                    $item['ignore_reason'] = 'Local development / Docker container environment (internal IP is normal).';
                }
            }
            // 5. Otherwise treat as a Filesystem finding
            else {
                $cleanPath = ltrim(str_replace(['../', '..\\'], '', $filePath), '/\\');
                $fullPath = wp_normalize_path(ABSPATH . $cleanPath);

                if (!file_exists($fullPath) && file_exists($filePath)) {
                    $fullPath = wp_normalize_path($filePath);
                }

                $realPath = realpath($fullPath);
                $isInsideRoot = $realPath && \WebCareProScanner\Filesystem\PathValidator::is_inside_root($realPath, ABSPATH);

                $item['file_exists'] = $isInsideRoot && file_exists($realPath);
                if (!isset($item['is_dir'])) {
                    $item['is_dir'] = $item['file_exists'] && is_dir($realPath);
                }
                if (!isset($item['is_file'])) {
                    $item['is_file'] = $item['file_exists'] && is_file($realPath);
                }
                // Only allow viewing if it is a regular readable file (not a folder/directory)
                if (!isset($item['can_view'])) {
                    $item['can_view'] = !empty($item['is_file']) && is_readable($realPath);
                }

                // Real-Time Integrity Reconciliation: If finding was recorded as modified but local file is now restored/clean
                if (!empty($item['is_file']) && ($item['status'] ?? 'open') === 'open' && in_array($item['type'] ?? '', ['modified_core_file', 'modified_plugin_file', 'modified_theme_file'], true)) {
                    if (preg_match('/Expected:\s*([a-f0-9]{32})/i', $item['evidence'] ?? '', $em)) {
                        $expected_hash = strtolower($em[1]);
                        $current_hash = md5_file($realPath);
                        $is_now_clean = ($current_hash === $expected_hash);
                        if (!$is_now_clean) {
                            $raw_content = @file_get_contents($realPath);
                            if ($raw_content !== false && md5(str_replace("\r\n", "\n", $raw_content)) === $expected_hash) {
                                $is_now_clean = true;
                            }
                        }
                        if ($is_now_clean) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            // Persist repaired state to database so it stays solved
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        }
                    }
                }

                // Attach deep filesystem forensics for developers and site owners
                if ($item['file_exists'] && $realPath) {
                    $mtime = @filemtime($realPath);
                    $ctime = @filectime($realPath);
                    $atime = @fileatime($realPath);
                    $fsize = @filesize($realPath);
                    $raw_perms = @fileperms($realPath);
                    $current_perms = $raw_perms !== false ? substr(sprintf('%o', $raw_perms), -4) : '0755';
                    $is_dir = is_dir($realPath);
                    $file_basename = strtolower(basename($realPath));
                    $is_wp_config = ($file_basename === 'wp-config.php');
                    $recommended_perms = $is_wp_config ? '0600' : ($is_dir ? '0755' : '0644');
                    $recommended_symbolic = $is_wp_config ? '-rw-------' : ($is_dir ? 'drwxr-xr-x' : '-rw-r--r--');

                    // Convert raw permissions to standard symbolic notation (e.g. -rw-r--r-- or -rwxrwxrwx)
                    $symbolic = '';
                    if ($raw_perms !== false) {
                        if ($is_dir) {
                            $symbolic .= 'd';
                        } elseif (is_link($realPath)) {
                            $symbolic .= 'l';
                        } else {
                            $symbolic .= '-';
                        }
                        $symbolic .= (($raw_perms & 0x0100) ? 'r' : '-');
                        $symbolic .= (($raw_perms & 0x0080) ? 'w' : '-');
                        $symbolic .= (($raw_perms & 0x0040) ? (($raw_perms & 0x0800) ? 's' : 'x') : (($raw_perms & 0x0800) ? 'S' : '-'));
                        $symbolic .= (($raw_perms & 0x0020) ? 'r' : '-');
                        $symbolic .= (($raw_perms & 0x0010) ? 'w' : '-');
                        $symbolic .= (($raw_perms & 0x0008) ? (($raw_perms & 0x0400) ? 's' : 'x') : (($raw_perms & 0x0400) ? 'S' : '-'));
                        $symbolic .= (($raw_perms & 0x0004) ? 'r' : '-');
                        $symbolic .= (($raw_perms & 0x0002) ? 'w' : '-');
                        $symbolic .= (($raw_perms & 0x0001) ? (($raw_perms & 0x0200) ? 't' : 'x') : (($raw_perms & 0x0200) ? 'T' : '-'));
                    }

                    // Owner and Group
                    $owner_uid = @fileowner($realPath);
                    $owner_name = ($owner_uid !== false && function_exists('posix_getpwuid')) ? (posix_getpwuid($owner_uid)['name'] ?? $owner_uid) : ($owner_uid !== false ? (string) $owner_uid : 'Unknown');
                    $group_gid = @filegroup($realPath);
                    $group_name = ($group_gid !== false && function_exists('posix_getgrgid')) ? (posix_getgrgid($group_gid)['name'] ?? $group_gid) : ($group_gid !== false ? (string) $group_gid : 'Unknown');

                    $parent_dir = dirname($realPath);
                    $parent_perms = file_exists($parent_dir) ? substr(sprintf('%o', fileperms($parent_dir)), -4) : '0755';
                    $now = current_time('timestamp', 1);

                    $sha256 = !$is_dir && $fsize <= 10485760 ? (hash_file('sha256', $realPath) ?: '') : '';
                    if ($sha256) {
                        $item['sha256'] = $sha256;
                        $item['file_sha256'] = $sha256;
                    }

                    $item['fs_forensics'] = [
                        'file_size'             => $fsize !== false ? $fsize : 0,
                        'file_size_formatted'   => $fsize !== false ? size_format($fsize) : '0 B',
                        'sha256'                => $sha256,
                        'created_time'          => $ctime ? gmdate('Y-m-d H:i:s', $ctime) . ' UTC' : null,
                        'created_time_human'    => $ctime ? human_time_diff($ctime, $now) . ' ago' : 'Unknown',
                        'modified_time'         => $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : null,
                        'modified_time_human'   => $mtime ? human_time_diff($mtime, $now) . ' ago' : 'Unknown',
                        'accessed_time'         => $atime ? gmdate('Y-m-d H:i:s', $atime) . ' UTC' : null,
                        'accessed_time_human'   => $atime ? human_time_diff($atime, $now) . ' ago' : 'Unknown',
                        'current_permissions'   => $current_perms,
                        'symbolic_permissions'  => $symbolic ?: ($is_dir ? 'drwxr-xr-x' : '-rw-r--r--'),
                        'recommended_perms'     => $recommended_perms,
                        'recommended_symbolic'  => $recommended_symbolic,
                        'is_dir'                => $is_dir,
                        'is_writable'           => wp_is_writable($realPath),
                        'is_readable'           => is_readable($realPath),
                        'is_executable'         => is_executable($realPath),
                        'owner'                 => $owner_name,
                        'owner_uid'             => $owner_uid !== false ? $owner_uid : null,
                        'group'                 => $group_name,
                        'group_gid'             => $group_gid !== false ? $group_gid : null,
                        'parent_dir'            => $parent_dir,
                        'parent_perms'          => $parent_perms,
                        'file_extension'        => strtolower(pathinfo($realPath, PATHINFO_EXTENSION)),
                        'mime_type'             => function_exists('mime_content_type') ? @mime_content_type($realPath) : null,
                        'is_safe_directory_index' => in_array(strtolower(basename($realPath)), ['index.php', 'index.html', 'index.htm'], true) && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($realPath),
                    ];

                    // Real-Time Directory Protection Index Reconciliation: If executable_in_uploads finding but file is a benign silence/protection index or legitimate plugin cache file
                    if (($item['type'] ?? '') === 'executable_in_uploads' && ($item['status'] ?? 'open') === 'open') {
                        $file_basename = strtolower(basename($realPath));
                        if (in_array($file_basename, ['index.php', 'index.html', 'index.htm'], true) && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($realPath)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            $item['reconciliation_reason'] = __('Benign directory listing protection index file (Silence is Golden / Directory Browsing Prevention).', 'webcare-pro-security');
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        } elseif (\WebCareProScanner\System\SettingsManager::is_legitimate_uploads_cache_file($realPath)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            $item['reconciliation_reason'] = __('Benign plugin compiled cache file (e.g. MailPoet Twig template cache) verified free of malware/webshells.', 'webcare-pro-security');
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        }
                    }

                    // Real-Time Permission Reconciliation: If unsafe_permissions finding but file on disk is already hardened (not 0777 or 0666)
                    if (($item['type'] ?? '') === 'unsafe_permissions' && ($item['status'] ?? 'open') === 'open') {
                        if (!in_array($current_perms, ['0777', '0666', '0776', '0667'], true)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        }
                    }
                }
            }

            // Attach component forensics for any theme or plugin finding if not already populated
            if (empty($item['component_meta']) && !empty($filePath)) {
                if (strpos($filePath, '/themes/') !== false || strpos($filePath, '\\themes\\') !== false) {
                    if (preg_match('#(?:wp-content[\\\\/])?themes[\\\\/]([^\\\\/]+)#i', $filePath, $tm)) {
                        $theme_root = function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes');
                        $theme_dir = wp_normalize_path($theme_root . '/' . $tm[1]);
                        if (is_dir($theme_dir)) {
                            $item['component_meta'] = self::get_theme_forensics_meta($theme_dir, ['theme_slug' => $tm[1]]);
                        }
                    }
                } elseif (strpos($filePath, '/plugins/') !== false || strpos($filePath, '\\plugins\\') !== false) {
                    if (preg_match('#(?:wp-content[\\\\/])?plugins[\\\\/]([^\\\\/]+)#i', $filePath, $pm)) {
                        $plugin_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $pm[1]);
                        if (is_dir($plugin_dir)) {
                            $item['component_meta'] = self::get_plugin_forensics_meta($plugin_dir, ['plugin_dir' => $pm[1]]);
                        }
                    }
                }
            }

            if (!empty($item['component_meta'])) {
                if ($item['engine'] === 'wordpress-updates' || in_array($item['type'], ['outdated_plugin', 'outdated_theme', 'vulnerable_plugin', 'vulnerable_theme', 'outdated_core', 'vulnerable_core'], true)) {
                    // Outdated or vulnerable software update findings should preserve their descriptive update title
                    if ($item['type'] === 'vulnerable_plugin') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: plugin name */
                            ? sprintf(__('Vulnerable Plugin: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Vulnerable Plugin', 'webcare-pro-security');
                    } elseif ($item['type'] === 'outdated_plugin') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: plugin name */
                            ? sprintf(__('Outdated Plugin: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Outdated Plugin', 'webcare-pro-security');
                    } elseif ($item['type'] === 'vulnerable_theme') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: theme name */
                            ? sprintf(__('Vulnerable Theme: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Vulnerable Theme', 'webcare-pro-security');
                    } elseif ($item['type'] === 'outdated_theme') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: theme name */
                            ? sprintf(__('Outdated Theme: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Outdated Theme', 'webcare-pro-security');
                    } elseif ($item['type'] === 'vulnerable_core') {
                        $item['display_title'] = __('Vulnerable WordPress Core', 'webcare-pro-security');
                    } elseif ($item['type'] === 'outdated_core') {
                        $item['display_title'] = __('Outdated WordPress Core', 'webcare-pro-security');
                    } else {
                        $item['display_title'] = __('Software Update Available', 'webcare-pro-security');
                    }
                } elseif (!empty($item['component_meta']['classification'])) {
                    if (empty($item['display_title'])) {
                        $item['display_title'] = $item['component_meta']['classification'];
                    }
                }
                if (isset($item['component_meta']['is_wporg'])) {
                    $item['is_wporg'] = (bool) $item['component_meta']['is_wporg'];
                }
                if (!empty($item['component_meta']['is_custom']) || !empty($item['component_meta']['is_premium'])) {
                    $item['is_custom'] = !empty($item['component_meta']['is_custom']);
                    $item['is_premium'] = !empty($item['component_meta']['is_premium']);
                    $item['is_wporg'] = false;
                }
                if (empty($item['component_name']) && !empty($item['component_meta']['name'])) {
                    $item['component_name'] = $item['component_meta']['name'];
                }
                if (empty($item['installed_version']) && !empty($item['component_meta']['version'])) {
                    $item['installed_version'] = $item['component_meta']['version'];
                }
                if (empty($item['latest_version']) && !empty($item['component_meta']['latest_version'])) {
                    $item['latest_version'] = $item['component_meta']['latest_version'];
                }
                if (!isset($item['has_update']) && isset($item['component_meta']['has_update'])) {
                    $item['has_update'] = $item['component_meta']['has_update'];
                }
            }

            if (empty($item['display_title'])) {
                $type_map = [
                    'weak_password_detected'         => __('Weak User Password', 'webcare-pro-security'),
                    'weak_admin_password'            => __('Weak Administrator Password', 'webcare-pro-security'),
                    'weak_user_password'             => __('Weak User Password', 'webcare-pro-security'),
                    'username_enumeration_risk'      => __('Username Enumeration Vulnerability', 'webcare-pro-security'),
                    'generic_admin_username'         => __('Generic Admin Username', 'webcare-pro-security'),
                    'user_missing_capabilities'      => __('User Account Missing Role Capabilities', 'webcare-pro-security'),
                    'suspicious_user_capabilities'   => __('Suspicious User Capabilities', 'webcare-pro-security'),
                    'injected_user_capabilities'     => __('Injected User Capabilities', 'webcare-pro-security'),
                    'tampered_role_definition'       => __('Tampered Role Definition', 'webcare-pro-security'),
                    'orphaned_post_author'           => __('Orphaned Post Author', 'webcare-pro-security'),
                    'webshell_pattern'               => __('Webshell Signature Pattern', 'webcare-pro-security'),
                    'obfuscated_malware_payload'     => __('Obfuscated Malware Payload', 'webcare-pro-security'),
                    'suspicious_strings'             => __('Suspicious Remote Code Strings', 'webcare-pro-security'),
                    'obfuscation_detected'           => __('Code Obfuscation Detected', 'webcare-pro-security'),
                    'executable_in_uploads'          => __('Executable Script in Uploads Directory', 'webcare-pro-security'),
                    'unsafe_permissions'             => __('Unsafe File Permissions', 'webcare-pro-security'),
                    'symlink_detected'               => __('Filesystem Symbolic Link', 'webcare-pro-security'),
                    'unknown_core_file'              => __('Unrecognized Core Directory File', 'webcare-pro-security'),
                    'unknown_wp_admin_file'          => __('Unrecognized WP-Admin File', 'webcare-pro-security'),
                    'unknown_wp_includes_file'       => __('Unrecognized WP-Includes File', 'webcare-pro-security'),
                    'modified_core_file'             => __('Modified WordPress Core File', 'webcare-pro-security'),
                    'modified_theme_file'            => __('Modified Theme File', 'webcare-pro-security'),
                    'modified_plugin_file'           => __('Modified Plugin File', 'webcare-pro-security'),
                    'missing_core_file'              => __('Missing WordPress Core File', 'webcare-pro-security'),
                    'eval_in_options'                => __('PHP Code in WordPress Options', 'webcare-pro-security'),
                    'base64_in_options'              => __('Base64 Payload in Options', 'webcare-pro-security'),
                    'serialized_injection'           => __('Serialized Object Injection', 'webcare-pro-security'),
                    'malicious_cron_hook'            => __('Suspicious Scheduled Cron Hook', 'webcare-pro-security'),
                    'malicious_cron_hook_name'       => __('Suspicious Scheduled Cron Hook', 'webcare-pro-security'),
                    'orphaned_cron_hook'             => __('Orphaned Scheduled Cron Hook', 'webcare-pro-security'),
                    'malicious_system_crontab'       => __('Malicious System Crontab Entry', 'webcare-pro-security'),
                    'suspicious_crontab_execution'   => __('Suspicious Crontab Execution', 'webcare-pro-security'),
                    'hidden_directory_crontab'       => __('Hidden Directory Crontab Task', 'webcare-pro-security'),
                    'malicious_mu_plugin'            => __('Suspicious Must-Use (MU) Plugin', 'webcare-pro-security'),
                    'mu_plugin_warning'              => __('Unverified Must-Use Plugin', 'webcare-pro-security'),
                    'unexpected_wp_content_file'     => __('Unexpected File in WP-Content', 'webcare-pro-security'),
                    'malicious_dropin'               => __('Malicious WordPress Drop-in', 'webcare-pro-security'),
                    'unauthorized_dropin'            => __('Unauthorized WordPress Drop-in', 'webcare-pro-security'),
                    'db_autoload_malware_anchor'     => __('Autoload Database Malware Anchor', 'webcare-pro-security'),
                    'self_healing_malware_resurrection' => __('Self-Healing Malware Persistence', 'webcare-pro-security'),
                    'rogue_server_preloader'         => __('Rogue Server Auto-Preloader', 'webcare-pro-security'),
                    'ini_auto_prepend'               => __('PHP INI auto_prepend_file Injection', 'webcare-pro-security'),
                    'ini_auto_append'                => __('PHP INI auto_append_file Injection', 'webcare-pro-security'),
                    'user_ini_preloader'             => __('User INI Preload Injection', 'webcare-pro-security'),
                    'htaccess_preloader'             => __('htaccess Preload Injection', 'webcare-pro-security'),
                    'core_checksums_unavailable'     => __('WordPress Core Checksums Unavailable', 'webcare-pro-security'),
                    'theme_checksums_unavailable'    => __('Theme Checksums Unavailable', 'webcare-pro-security'),
                    'plugin_checksums_unavailable'   => __('Plugin Checksums Unavailable', 'webcare-pro-security'),
                ];

                if (!empty($item['type']) && isset($type_map[$item['type']])) {
                    $item['display_title'] = $type_map[$item['type']];
                } elseif (!empty($item['type'])) {
                    // Fallback to formatted title case: "my_suspicious_finding" -> "My Suspicious Finding"
                    $item['display_title'] = ucwords(str_replace(['_', '-'], ' ', $item['type']));
                }
            }

            // 6. Whitelist & False-Positive Rule Matching (Auto-suppression)
            $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
            if ($matched_rule !== null) {
                $item['is_whitelisted'] = true;
                $item['whitelist_rule'] = $matched_rule;
                if (!empty($item['id']) && ($item['status'] ?? '') === 'open') {
                    global $wpdb;
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'ignored'], ['id' => (int) $item['id']]);
                }
                $item['status']         = 'ignored';
            } else {
                $item['is_whitelisted'] = false;
            }

            if (!empty($item['created_at_gmt'])) {
                $item['created_at_gmt'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($item['created_at_gmt']));
            } elseif (!empty($item['created_at'])) {
                $item['created_at_gmt'] = get_gmt_from_date($item['created_at'], 'Y-m-d\TH:i:s\Z');
            }

            // Non-Technical Owner Suite: Plain-English Translation Schema
            if (class_exists('\\WebCareProScanner\\Findings\\FindingTranslator')) {
                $item['plain_english'] = \WebCareProScanner\Findings\FindingTranslator::translate($item);
            }
        }
        unset($item);

        // Deduplicate identical issues by normalized signature (type + normalized target path + line number)
        $deduped = [];
        $seen_signatures = [];
        foreach ($issues as $entry) {
            $norm_path = self::normalize_finding_path($entry['file_path'] ?? ($entry['target'] ?? ''));
            $type = strtolower(trim($entry['type'] ?? ''));
            $line = (int) ($entry['line_number'] ?? 0);
            $sig = $type . '|' . $norm_path . '|' . $line;
            if (isset($seen_signatures[$sig])) {
                continue;
            }
            $seen_signatures[$sig] = true;
            $deduped[] = $entry;
        }

        return $deduped;
    }

    /**
     * Normalize a finding target key (file path or entity ID) to canonical format.
     *
     * @param string $path
     * @return string Canonical normalized target key
     */
    public static function normalize_finding_path(string $path): string {
        $clean = trim($path);
        if ($clean === '') {
            return '';
        }
        $normalized = str_replace('\\', '/', $clean);
        $normalized = preg_replace('#/+#', '/', $normalized);
        $normalized = strtolower(rtrim($normalized, '/'));

        if (defined('ABSPATH')) {
            $norm_abspath = strtolower(rtrim(str_replace('\\', '/', ABSPATH), '/'));
            if (!empty($norm_abspath) && str_starts_with($normalized, $norm_abspath)) {
                $normalized = ltrim(substr($normalized, strlen($norm_abspath)), '/');
            }
        }

        return $normalized;
    }

    /**
     * Prune duplicate issue rows for a scan to ensure each file/anomaly type is stored only once.
     *
     * @param int $scan_id
     * @return int Number of pruned duplicate rows
     */
    public static function prune_duplicate_issues(int $scan_id): int {
        global $wpdb;
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';

        if ($scan_id <= 0) {
            return 0;
        }

        $iss_query = "SELECT id, engine, type, file_path, line_number, confidence FROM `{$table_issues}` WHERE scan_id = %d ORDER BY id ASC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_query, $scan_id),
            ARRAY_A
        ) ?: [];

        if (empty($rows)) {
            return 0;
        }

        $seen = [];
        $ids_to_delete = [];

        foreach ($rows as $row) {
            $norm_path = self::normalize_finding_path($row['file_path'] ?? '');
            $type = strtolower(trim($row['type'] ?? ''));
            $line = (int) ($row['line_number'] ?? 0);
            $sig = $type . '|' . $norm_path . '|' . $line;

            if (isset($seen[$sig])) {
                $ids_to_delete[] = (int) $row['id'];
            } else {
                $seen[$sig] = (int) $row['id'];
            }
        }

        if (!empty($ids_to_delete)) {
            foreach (array_chunk($ids_to_delete, 80) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '%d'));
                $del_sql = "DELETE FROM `{$table_issues}` WHERE id IN ($placeholders)";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query(
                    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                    $wpdb->prepare($del_sql, ...$chunk)
                );
            }

            // Recalculate true active open issues on scan row
            $cnt_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $open_count = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($cnt_sql, $scan_id)
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $open_count], ['id' => $scan_id]);
        }

        return count($ids_to_delete);
    }

    /**
     * Extract deep forensic metadata for a WordPress theme directory.
     *
     * @param string $filePath
     * @param array $evidence_data
     * @return array
     */
    public static function get_theme_forensics_meta(string $filePath, array $evidence_data = []): array {
        if (!function_exists('wp_get_theme')) {
            require_once ABSPATH . WPINC . '/theme.php';
        }

        $norm_path = wp_normalize_path($filePath);
        if (!empty($evidence_data['theme_slug'])) {
            $theme_slug = $evidence_data['theme_slug'];
        } elseif (preg_match('#(?:wp-content/themes|themes)/([^/]+)#i', $norm_path, $m)) {
            $theme_slug = $m[1];
        } else {
            $theme_slug = basename($norm_path);
        }
        $theme = wp_get_theme($theme_slug);

        // Fallback: check if directory exists even if slug slightly differed
        if (!$theme->exists() && file_exists($norm_path . '/style.css')) {
            $all_themes = function_exists('wp_get_themes') ? wp_get_themes() : [];
            foreach ($all_themes as $s => $t) {
                if (wp_normalize_path($t->get_stylesheet_directory()) === $norm_path) {
                    $theme = $t;
                    $theme_slug = $s;
                    break;
                }
            }
        }

        $theme_dir = $theme->exists() ? wp_normalize_path($theme->get_stylesheet_directory()) : (is_dir($norm_path) ? $norm_path : dirname($norm_path));

        $name = $theme->exists() ? $theme->get('Name') : (!empty($evidence_data['theme_name']) ? $evidence_data['theme_name'] : $theme_slug);
        $version = $theme->exists() ? (string) $theme->get('Version') : (!empty($evidence_data['version']) ? (string) $evidence_data['version'] : '');
        $author = $theme->exists() ? wp_strip_all_tags($theme->get('Author')) : '';
        $author_uri = $theme->exists() ? (string) $theme->get('AuthorURI') : '';
        $theme_uri = $theme->exists() ? (string) $theme->get('ThemeURI') : '';
        $description = $theme->exists() ? wp_strip_all_tags($theme->get('Description')) : '';
        $requires_wp = $theme->exists() ? (string) $theme->get('RequiresWP') : '';
        $requires_php = $theme->exists() ? (string) $theme->get('RequiresPHP') : '';
        $text_domain = $theme->exists() ? (string) $theme->get('TextDomain') : '';

        // Active state detection
        $current_stylesheet = function_exists('get_stylesheet') ? get_stylesheet() : '';
        $current_template = function_exists('get_template') ? get_template() : '';
        $is_active_child = ($theme_slug === $current_stylesheet && $theme_slug !== $current_template);
        $is_active_parent = ($theme_slug === $current_template);
        $is_active = ($theme_slug === $current_stylesheet || $theme_slug === $current_template);

        $parent_obj = $theme->exists() ? $theme->parent() : null;
        $is_child = (bool) $parent_obj || !empty($evidence_data['is_child']) || strpos(strtolower($norm_path), '-child') !== false;
        $parent_name = $parent_obj ? $parent_obj->get('Name') : (!empty($evidence_data['parent_theme']) ? $evidence_data['parent_theme'] : null);
        $parent_version = $parent_obj ? (string) $parent_obj->get('Version') : null;

        if ($is_active_child) {
            $status_label = 'Active Child Theme';
        } elseif ($is_active_parent && $current_stylesheet !== $current_template) {
            $status_label = 'Active Parent Template';
        } elseif ($is_active) {
            $status_label = 'Active Theme';
        } else {
            $status_label = 'Inactive';
        }

        // Check latest version in update_themes transient
        $latest_version = null;
        $has_update = false;
        $update_package = '';
        $is_wporg = false;
        $update_themes = get_site_transient('update_themes');
        if (!empty($update_themes->response[$theme_slug])) {
            $theme_update = (array) $update_themes->response[$theme_slug];
            $latest_version = $theme_update['new_version'] ?? null;
            $has_update = !empty($latest_version) && (!empty($version) ? version_compare($latest_version, $version, '>') : true);
            $update_package = $theme_update['package'] ?? '';
            $package_url = is_string($update_package) ? $update_package : '';
            $theme_url = is_string($theme_update['url'] ?? '') ? $theme_update['url'] : '';
            if (strpos($package_url, 'wordpress.org') !== false || strpos($theme_url, 'wordpress.org') !== false) {
                $is_wporg = true;
            }
        } elseif (!empty($update_themes->checked[$theme_slug])) {
            $latest_version = $update_themes->checked[$theme_slug];
            if (strpos($theme_uri, 'wordpress.org/themes') !== false || (bool) preg_match('/^twenty(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|nineteen|twenty|twentyone|twentytwo|twentythree|twentyfour|twentyfive|twentysix)/i', $theme_slug)) {
                $is_wporg = true;
            }
        }

        $is_explicit_non_wporg = !empty($evidence_data['is_premium'])
            || !empty($evidence_data['is_child'])
            || $is_child
            || (isset($evidence_data['is_wporg']) && !$evidence_data['is_wporg'])
            || (!empty($evidence_data['display_title']) && in_array($evidence_data['display_title'], ['Premium Theme', 'Custom Child Theme', 'Custom or Premium Theme'], true));

        $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/\b(premium|pro|commercial|license|themeforest|envato)\b/i', $norm_path . ' ' . $name . ' ' . $description);

        if ($is_explicit_non_wporg || $is_premium) {
            $is_wporg = false;
        }

        if ($is_wporg) {
            $classification = __('Official WordPress Theme', 'webcare-pro-security');
        } elseif (!empty($evidence_data['display_title'])) {
            $classification = $evidence_data['display_title'];
        } elseif ($is_child) {
            $classification = __('Custom Child Theme', 'webcare-pro-security');
        } else {
            $classification = $is_premium ? __('Premium Theme', 'webcare-pro-security') : __('Custom or Premium Theme', 'webcare-pro-security');
        }

        // File stats and timestamps
        $mtime = file_exists($norm_path) ? filemtime($norm_path) : (file_exists($theme_dir . '/style.css') ? filemtime($theme_dir . '/style.css') : 0);
        $last_updated = $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : 'Unknown';
        $last_updated_human = $mtime ? human_time_diff($mtime, current_time('timestamp', 1)) . ' ago' : 'Unknown';

        // Permissions
        $folder_perms = file_exists($theme_dir) ? substr(sprintf('%o', fileperms($theme_dir)), -4) : '0755';
        $style_css_path = file_exists($theme_dir . '/style.css') ? ($theme_dir . '/style.css') : (file_exists($norm_path) ? $norm_path : '');
        $file_perms = (!empty($style_css_path) && file_exists($style_css_path)) ? substr(sprintf('%o', fileperms($style_css_path)), -4) : '0644';

        // Check for changelog or readme file
        $changelog_info = self::detect_component_changelog($theme_dir);

        return [
            'type'                => 'theme',
            'slug'                => $theme_slug,
            'name'                => $name,
            'version'             => $version,
            'latest_version'      => $latest_version,
            'has_update'          => $has_update,
            'update_package'      => !empty($update_package),
            'author'              => $author,
            'author_uri'          => $author_uri,
            'theme_uri'           => $theme_uri,
            'description'         => $description,
            'is_active'           => $is_active,
            'is_child'            => $is_child,
            'parent_name'         => $parent_name,
            'parent_version'      => $parent_version,
            'status_label'        => $status_label,
            'requires_wp'         => $requires_wp,
            'requires_php'        => $requires_php,
            'text_domain'         => $text_domain,
            'path'                => $norm_path,
            'last_modified'       => $last_updated,
            'last_modified_human' => $last_updated_human,
            'folder_perms'        => $folder_perms,
            'main_file_perms'     => $file_perms,
            'main_file'           => file_exists($style_css_path) ? 'style.css' : '',
            'has_changelog'       => $changelog_info['has_changelog'],
            'changelog_file'      => $changelog_info['filename'],
            'admin_url'           => admin_url('themes.php'),
            'is_wporg'            => $is_wporg,
            'classification'      => $classification,
        ];
    }

    /**
     * Extract deep forensic metadata for a WordPress plugin directory or file.
     *
     * @param string $filePath
     * @param array $evidence_data
     * @return array
     */
    public static function get_plugin_forensics_meta(string $filePath, array $evidence_data = []): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $norm_path = wp_normalize_path($filePath);

        $matched_file = '';
        $matched_data = [];

        // Check direct plugin_file from evidence_data first
        if (!empty($evidence_data['plugin_file']) && isset($all_plugins[$evidence_data['plugin_file']])) {
            $matched_file = $evidence_data['plugin_file'];
            $matched_data = $all_plugins[$matched_file];
        }

        if (empty($matched_file)) {
            $folder_name = !empty($evidence_data['plugin_dir']) ? $evidence_data['plugin_dir'] : basename($norm_path);
            foreach ($all_plugins as $plugin_file => $data) {
                $dir_name = dirname($plugin_file);
                if ($dir_name === $folder_name || $plugin_file === $folder_name) {
                    $matched_file = $plugin_file;
                    $matched_data = $data;
                    break;
                }
                $full_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $dir_name);
                if ($full_dir === $norm_path) {
                    $matched_file = $plugin_file;
                    $matched_data = $data;
                    break;
                }
            }
        }

        $name = !empty($matched_data['Name']) ? $matched_data['Name'] : (!empty($evidence_data['plugin_name']) ? $evidence_data['plugin_name'] : basename($norm_path));
        $version = !empty($matched_data['Version']) ? (string) $matched_data['Version'] : (!empty($evidence_data['version']) ? (string) $evidence_data['version'] : '');
        $author = !empty($matched_data['Author']) ? wp_strip_all_tags($matched_data['Author']) : '';
        $author_uri = (string) ($matched_data['AuthorURI'] ?? '');
        $plugin_uri = (string) ($matched_data['PluginURI'] ?? '');
        $description = !empty($matched_data['Description']) ? wp_strip_all_tags($matched_data['Description']) : '';
        $requires_wp = (string) ($matched_data['RequiresWP'] ?? '');
        $requires_php = (string) ($matched_data['RequiresPHP'] ?? '');
        $text_domain = (string) ($matched_data['TextDomain'] ?? '');

        // Active state detection
        $is_active = false;
        $network_active = false;
        if (!empty($matched_file) && function_exists('is_plugin_active')) {
            $is_active = is_plugin_active($matched_file);
            if (is_multisite() && function_exists('is_plugin_active_for_network')) {
                $network_active = is_plugin_active_for_network($matched_file);
                if ($network_active) {
                    $is_active = true;
                }
            }
        }

        if ($network_active) {
            $status_label = 'Network Active';
        } elseif ($is_active) {
            $status_label = 'Active';
        } else {
            $status_label = 'Inactive';
        }

        // Check latest version in update_plugins transient
        $latest_version = null;
        $has_update = false;
        $update_package = '';
        $is_wporg = false;
        $update_plugins = get_site_transient('update_plugins');

        $update_entry = null;
        if (!empty($matched_file) && !empty($update_plugins->response[$matched_file])) {
            $update_entry = $update_plugins->response[$matched_file];
            $latest_version = $update_entry->new_version ?? null;
            $has_update = !empty($latest_version) && (!empty($version) ? version_compare($latest_version, $version, '>') : true);
            $update_package = $update_entry->package ?? '';
        } elseif (!empty($matched_file) && !empty($update_plugins->no_update[$matched_file])) {
            $update_entry = $update_plugins->no_update[$matched_file];
            $latest_version = $update_entry->new_version ?? $version;
        }

        // Check if update entry is verified from WordPress.org repository
        if (is_object($update_entry)) {
            $entry_id = is_string($update_entry->id ?? '') ? $update_entry->id : '';
            $entry_url = is_string($update_entry->url ?? '') ? $update_entry->url : '';
            $entry_pkg = is_string($update_entry->package ?? '') ? $update_entry->package : '';
            if (strpos($entry_id, 'w.org/') !== false || strpos($entry_id, 'wordpress.org') !== false
                || strpos($entry_url, 'wordpress.org/plugins') !== false
                || strpos($entry_pkg, 'downloads.wordpress.org') !== false
                || strpos($entry_pkg, 'wordpress.org') !== false) {
                $is_wporg = true;
            }
        }

        if (!$is_wporg && strpos($plugin_uri, 'wordpress.org/plugins') !== false) {
            $is_wporg = true;
        }

        // Check explicit non-wporg evidence or finding context (e.g. from PluginIntegrity / plugin_checksums_unavailable)
        $is_explicit_non_wporg = !empty($evidence_data['is_premium']) 
            || !empty($evidence_data['is_custom'])
            || (isset($evidence_data['is_wporg']) && !$evidence_data['is_wporg'])
            || (!empty($evidence_data['classification']) && in_array($evidence_data['classification'], ['premium_plugin', 'custom_plugin'], true))
            || (!empty($evidence_data['display_title']) && in_array($evidence_data['display_title'], ['Premium Plugin', 'Custom or Premium Plugin', 'Custom Plugin'], true));

        // Name, description or directory indicating commercial/pro/premium product
        $is_premium = !empty($evidence_data['is_premium']) 
            || (bool) preg_match('/(?:^|[-_])(premium|pro|addon|addons|unlimited|commercial)(?:[-_]|$)/i', $norm_path) 
            || (bool) preg_match('/\b(premium|pro|codecanyon|themeforest|envato|commercial|license)\b/i', $name . ' ' . $description);

        if ($is_explicit_non_wporg || $is_premium) {
            $is_wporg = false;
        }

        if ($is_wporg) {
            $classification = __('Official WordPress Plugin', 'webcare-pro-security');
        } elseif (!empty($evidence_data['display_title'])) {
            $classification = $evidence_data['display_title'];
        } elseif ($is_premium) {
            $classification = __('Premium Plugin', 'webcare-pro-security');
        } else {
            $classification = __('Custom or Premium Plugin', 'webcare-pro-security');
        }

        // Timestamps
        $main_file_full = (!empty($matched_file) && file_exists(WP_PLUGIN_DIR . '/' . $matched_file)) ? wp_normalize_path(WP_PLUGIN_DIR . '/' . $matched_file) : '';
        $mtime = $main_file_full ? filemtime($main_file_full) : (file_exists($norm_path) ? filemtime($norm_path) : 0);
        $last_updated = $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : 'Unknown';
        $last_updated_human = $mtime ? human_time_diff($mtime, current_time('timestamp', 1)) . ' ago' : 'Unknown';

        // Permissions
        $folder_perms = file_exists($norm_path) ? substr(sprintf('%o', fileperms($norm_path)), -4) : '0755';
        $main_file_perms = $main_file_full ? substr(sprintf('%o', fileperms($main_file_full)), -4) : '0644';

        // Changelog detection
        $changelog_info = self::detect_component_changelog($norm_path);

        return [
            'type'                => 'plugin',
            'slug'                => !empty($matched_file) ? dirname($matched_file) : basename($norm_path),
            'plugin_file'         => $matched_file,
            'name'                => $name,
            'version'             => $version,
            'latest_version'      => $latest_version,
            'has_update'          => $has_update,
            'update_package'      => !empty($update_package),
            'author'              => $author,
            'author_uri'          => $author_uri,
            'plugin_uri'          => $plugin_uri,
            'description'         => $description,
            'is_active'           => $is_active,
            'network_active'      => $network_active,
            'status_label'        => $status_label,
            'requires_wp'         => $requires_wp,
            'requires_php'        => $requires_php,
            'text_domain'         => $text_domain,
            'path'                => $norm_path,
            'last_modified'       => $last_updated,
            'last_modified_human' => $last_updated_human,
            'folder_perms'        => $folder_perms,
            'main_file_perms'     => $main_file_perms,
            'main_file'           => $matched_file ? basename($matched_file) : '',
            'has_changelog'       => $changelog_info['has_changelog'],
            'changelog_file'      => $changelog_info['filename'],
            'admin_url'           => admin_url('plugins.php'),
            'is_wporg'            => $is_wporg,
            'classification'      => $classification,
        ];
    }

    /**
     * Inspect component folder for changelog or release history files.
     *
     * @param string $component_path
     * @return array
     */
    public static function detect_component_changelog(string $component_path): array {
        $candidates = [
            'changelog.txt', 'CHANGELOG.txt',
            'changelog.md', 'CHANGELOG.md',
            'readme.txt', 'README.txt',
            'readme.md', 'README.md',
            'history.md', 'HISTORY.md',
            'releases.md', 'RELEASES.md',
            'docs/changelog.txt', 'docs/CHANGELOG.md'
        ];

        foreach ($candidates as $cand) {
            $target = $component_path . '/' . $cand;
            if (file_exists($target) && is_readable($target) && is_file($target)) {
                return [
                    'has_changelog' => true,
                    'filename'      => basename($cand),
                    'full_path'     => wp_normalize_path($target)
                ];
            }
        }

        return [
            'has_changelog' => false,
            'filename'      => '',
            'full_path'     => ''
        ];
    }

    /**
     * Extract the Changelog section from a WordPress readme.txt / readme.md file.
     *
     * @param string $content
     * @return string
     */
    public static function extract_changelog_from_readme(string $content): string {
        if (empty($content)) {
            return '';
        }

        // Standard WordPress readme.txt: == Changelog ==
        if (preg_match('/==\s*Changelog\s*==(.*?)(?=(?:\n==\s*[^=]+\s*==|\Z))/is', $content, $matches)) {
            return trim("== Changelog ==\n" . trim($matches[1]));
        }

        // Markdown style: ## Changelog or # Changelog
        if (preg_match('/(?:^|\n)#{1,3}\s*Changelog\b(.*?)(?=(?:\n#{1,3}\s+[^\n]+|\Z))/is', $content, $matches)) {
            return trim("## Changelog\n" . trim($matches[1]));
        }

        return '';
    }

    /**
     * Convert WordPress.org API HTML changelog section into readable, formatted markdown text.
     *
     * @param string $html
     * @return string
     */
    public static function format_changelog_html(string $html): string {
        if (empty($html)) {
            return '';
        }

        $s = $html;
        $s = preg_replace('/<h[1-6][^>]*>(.*?)<\/h[1-6]>/is', "\n\n= $1 =\n", $s);
        $s = preg_replace('/<li[^>]*>(.*?)<\/li>/is', "* $1\n", $s);
        $s = preg_replace('/<code[^>]*>(.*?)<\/code>/is', '`$1`', $s);
        $s = preg_replace('/<\/p>/is', "\n\n", $s);
        $s = preg_replace('/<br\s*\/?>/is', "\n", $s);
        $s = wp_strip_all_tags($s);
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $s = preg_replace("/\n{3,}/", "\n\n", $s);

        return trim($s);
    }

    /**
     * Retrieve changelog content for a specific theme or plugin component.
     * Prioritizes fetching the latest upstream release changelog from official WordPress.org.
     * If latest version changelog is not found or fails, gracefully falls back to the locally installed version.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response|\WP_Error
     */
    public static function get_component_changelog(\WP_REST_Request $request) {
        $raw_path = sanitize_text_field($request->get_param('path') ?: ($request->get_param('file_path') ?: ''));
        $slug = sanitize_text_field($request->get_param('slug') ?: '');
        $type = sanitize_key($request->get_param('type') ?: 'plugin'); // 'plugin' or 'theme'
        $installed_ver = sanitize_text_field($request->get_param('installed_version') ?: '');
        $latest_ver = sanitize_text_field($request->get_param('latest_version') ?: '');

        $target_dir = '';
        if (!empty($raw_path)) {
            $raw_path = str_replace(['../', '..\\'], '', $raw_path);
            if (is_dir($raw_path)) {
                $target_dir = wp_normalize_path($raw_path);
            } elseif (is_file($raw_path)) {
                $target_dir = wp_normalize_path(dirname($raw_path));
            }
        }

        if (empty($target_dir) && !empty($slug)) {
            if ($type === 'theme') {
                $theme_root = function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes');
                $candidate = wp_normalize_path($theme_root . '/' . $slug);
                if (file_exists($candidate) && is_dir($candidate)) {
                    $target_dir = $candidate;
                }
            } else {
                $candidate = wp_normalize_path(WP_PLUGIN_DIR . '/' . $slug);
                if (file_exists($candidate) && is_dir($candidate)) {
                    $target_dir = $candidate;
                }
            }
        }

        // Derive slug if empty
        if (empty($slug)) {
            $check_path = $target_dir ?: $raw_path;
            if (preg_match('#[\\\\/]wp-content[\\\\/]themes[\\\\/]([^\\\\/]+)#i', $check_path, $m)) {
                $slug = $m[1];
                $type = 'theme';
            } elseif (preg_match('#[\\\\/]wp-content[\\\\/]plugins[\\\\/]([^\\\\/]+)#i', $check_path, $m)) {
                $slug = $m[1];
                $type = 'plugin';
            } elseif (!empty($target_dir)) {
                $slug = basename($target_dir);
            }
        }
        $slug = preg_replace('/\.php$/i', '', $slug);

        // Fetch component metadata if versions are not provided
        if (empty($installed_ver) || empty($latest_ver)) {
            if ($type === 'theme' && !empty($target_dir)) {
                $meta = self::get_theme_forensics_meta($target_dir, ['theme_slug' => $slug]);
                $installed_ver = $installed_ver ?: ($meta['version'] ?? '');
                $latest_ver = $latest_ver ?: ($meta['latest_version'] ?? '');
            } elseif (!empty($target_dir)) {
                $meta = self::get_plugin_forensics_meta($target_dir, ['plugin_dir' => $slug]);
                $installed_ver = $installed_ver ?: ($meta['version'] ?? '');
                $latest_ver = $latest_ver ?: ($meta['latest_version'] ?? '');
            }
        }

        $latest_changelog_found = false;
        $latest_content = '';
        $latest_source = '';
        $resolved_latest_version = $latest_ver;

        // --- STEP 1: Attempt to retrieve latest version changelog from WordPress Update Manager / Vendor API / Official Repository ---
        if ($type === 'plugin' && (!empty($slug) || !empty($target_dir))) {
            $cache_key = 'webcareproscan_up_cl_pl_' . substr(md5(($slug ?: basename($target_dir)) . '_' . $latest_ver), 0, 16);
            $cached = function_exists('get_transient') ? get_transient($cache_key) : false;
            if (!empty($cached) && is_array($cached) && !empty($cached['content'])) {
                $latest_changelog_found = true;
                $latest_content = $cached['content'];
                $latest_source = $cached['source'];
                $resolved_latest_version = $cached['version'] ?: $latest_ver;
            } else {
                // 1.1 Resolve plugin main file
                $matched_file = '';
                if (!function_exists('get_plugins')) {
                    require_once ABSPATH . 'wp-admin/includes/plugin.php';
                }
                $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
                $norm_target = wp_normalize_path($target_dir);
                $folder_name = $slug ?: basename($norm_target);

                foreach ($all_plugins as $p_file => $p_data) {
                    if (dirname($p_file) === $folder_name || $p_file === $folder_name || (!empty($norm_target) && wp_normalize_path(WP_PLUGIN_DIR . '/' . dirname($p_file)) === $norm_target)) {
                        $matched_file = $p_file;
                        break;
                    }
                }

                // 1.2 Inspect WordPress update transient (handles premium updaters like YITH, EDD, PUC, WooCommerce Helper)
                $update_plugins = function_exists('get_site_transient') ? get_site_transient('update_plugins') : false;
                $update_entry = null;

                if (!empty($update_plugins) && is_object($update_plugins)) {
                    if (!empty($matched_file) && !empty($update_plugins->response[$matched_file])) {
                        $update_entry = $update_plugins->response[$matched_file];
                    } elseif (!empty($matched_file) && !empty($update_plugins->no_update[$matched_file])) {
                        $update_entry = $update_plugins->no_update[$matched_file];
                    } else {
                        foreach ($update_plugins->response ?? [] as $up_file => $up_data) {
                            if (dirname($up_file) === $folder_name || (!empty($up_data->slug) && $up_data->slug === $folder_name)) {
                                $update_entry = $up_data;
                                $matched_file = $up_file;
                                break;
                            }
                        }
                        if (!$update_entry) {
                            foreach ($update_plugins->no_update ?? [] as $up_file => $up_data) {
                                if (dirname($up_file) === $folder_name || (!empty($up_data->slug) && $up_data->slug === $folder_name)) {
                                    $update_entry = $up_data;
                                    $matched_file = $up_file;
                                    break;
                                }
                            }
                        }
                    }
                }

                if (is_object($update_entry)) {
                    if (!empty($update_entry->new_version)) {
                        $resolved_latest_version = $update_entry->new_version;
                    }
                    // Check direct changelog inside update transient
                    if (!empty($update_entry->sections['changelog'])) {
                        $latest_content = self::format_changelog_html($update_entry->sections['changelog']);
                        $latest_changelog_found = true;
                        $latest_source = 'WordPress Plugin Update Manager';
                    } elseif (!empty($update_entry->changelog)) {
                        $latest_content = self::format_changelog_html($update_entry->changelog);
                        $latest_changelog_found = true;
                        $latest_source = 'WordPress Plugin Update Manager';
                    } elseif (!empty($update_entry->upgrade_notice)) {
                        $latest_content = self::format_changelog_html($update_entry->upgrade_notice);
                        $latest_changelog_found = true;
                        $latest_source = 'WordPress Plugin Update Manager';
                    }
                }

                // 1.3 Native WordPress plugins_api (queries registered updater filters e.g. YITH License Manager, PUC, etc.)
                if (!$latest_changelog_found) {
                    if (!function_exists('plugins_api')) {
                        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
                    }

                    $slug_candidates = [];
                    if (is_object($update_entry)) {
                        if (!empty($update_entry->slug)) $slug_candidates[] = (string) $update_entry->slug;
                        if (!empty($update_entry->id)) $slug_candidates[] = (string) $update_entry->id;
                    }
                    if (!empty($slug)) $slug_candidates[] = $slug;
                    if (!empty($folder_name)) $slug_candidates[] = $folder_name;
                    if (!empty($matched_file)) {
                        $slug_candidates[] = $matched_file;
                        $slug_candidates[] = dirname($matched_file);
                    }
                    $slug_candidates = array_unique(array_filter($slug_candidates));

                    if (function_exists('plugins_api')) {
                        foreach ($slug_candidates as $try_slug) {
                            $api = plugins_api('plugin_information', [
                                'slug'   => $try_slug,
                                'is_ssl' => is_ssl(),
                                'fields' => [
                                    'sections' => true,
                                    'version'  => true,
                                    'banners'  => false,
                                    'reviews'  => false,
                                ],
                            ]);

                            if (!is_wp_error($api) && is_object($api) && !empty($api->sections['changelog'])) {
                                $latest_content = self::format_changelog_html($api->sections['changelog']);
                                $latest_changelog_found = true;
                                $vendor_name = !empty($api->name) ? $api->name : 'Plugin Update Manager';
                                $latest_source = $vendor_name . ' Update API';
                                if (!empty($api->version)) {
                                    $resolved_latest_version = $api->version;
                                }
                                break;
                            }
                        }
                    }
                }

                // 1.4 Official WordPress.org SVN Repository (for free/official directory plugins)
                if (!$latest_changelog_found && !empty($slug)) {
                    $svn_urls = [];
                    if (!empty($latest_ver)) {
                        $svn_urls[] = "https://plugins.svn.wordpress.org/{$slug}/tags/{$latest_ver}/readme.txt";
                    }
                    $svn_urls[] = "https://plugins.svn.wordpress.org/{$slug}/trunk/readme.txt";

                    foreach ($svn_urls as $url) {
                        $response = function_exists('wp_remote_get')
                            ? wp_remote_get($url, ['timeout' => 4, 'sslverify' => true, 'headers' => ['User-Agent' => 'WordPress/' . get_bloginfo('version')]])
                            : false;

                        if (!is_wp_error($response) && is_array($response)) {
                            $code = wp_remote_retrieve_response_code($response);
                            if ($code === 200) {
                                $body = wp_remote_retrieve_body($response);
                                if (!empty($body)) {
                                    $extracted = self::extract_changelog_from_readme($body);
                                    $latest_content = !empty($extracted) ? $extracted : $body;
                                    $latest_changelog_found = true;
                                    $latest_source = 'WordPress.org SVN Repository';
                                    break;
                                }
                            }
                        }
                    }
                }

                if ($latest_changelog_found && function_exists('set_transient')) {
                    set_transient($cache_key, [
                        'content' => $latest_content,
                        'source'  => $latest_source,
                        'version' => $resolved_latest_version,
                    ], 12 * HOUR_IN_SECONDS);
                }
            }
        } elseif ($type === 'theme' && !empty($slug)) {
            $cache_key = 'webcareproscan_up_cl_th_' . substr(md5($slug . '_' . $latest_ver), 0, 16);
            $cached = function_exists('get_transient') ? get_transient($cache_key) : false;
            if (!empty($cached) && is_array($cached) && !empty($cached['content'])) {
                $latest_changelog_found = true;
                $latest_content = $cached['content'];
                $latest_source = $cached['source'];
                $resolved_latest_version = $cached['version'] ?: $latest_ver;
            } else {
                $candidates = [];
                if (!empty($latest_ver)) {
                    $candidates[] = "https://themes.svn.wordpress.org/{$slug}/{$latest_ver}/readme.txt";
                    $candidates[] = "https://themes.svn.wordpress.org/{$slug}/{$latest_ver}/changelog.txt";
                }
                foreach ($candidates as $url) {
                    $response = function_exists('wp_remote_get')
                        ? wp_remote_get($url, ['timeout' => 4, 'sslverify' => true])
                        : false;
                    if (!is_wp_error($response) && is_array($response)) {
                        $code = wp_remote_retrieve_response_code($response);
                        if ($code === 200) {
                            $body = wp_remote_retrieve_body($response);
                            if (!empty($body)) {
                                $latest_content = self::extract_changelog_from_readme($body) ?: $body;
                                $latest_changelog_found = true;
                                $latest_source = 'WordPress.org Themes Repository';
                                break;
                            }
                        }
                    }
                }
                if ($latest_changelog_found && function_exists('set_transient')) {
                    set_transient($cache_key, [
                        'content' => $latest_content,
                        'source'  => $latest_source,
                        'version' => $resolved_latest_version,
                    ], 12 * HOUR_IN_SECONDS);
                }
            }
        }

        // If latest upstream changelog was found, return it immediately
        if ($latest_changelog_found && !empty($latest_content)) {
            $version_label = $resolved_latest_version ? "v{$resolved_latest_version}" : 'Latest';
            $source_title = !empty($latest_source) ? $latest_source : 'WordPress Update Manager';
            return rest_ensure_response([
                'success'           => true,
                'has_changelog'     => true,
                'is_latest'         => true,
                'latest_not_found'  => false,
                'source'            => 'upstream_latest',
                /* translators: 1: version label, 2: source title */
                'source_label'      => sprintf(__('Latest Upstream Version (%1$s) from %2$s', 'webcare-pro-security'), $version_label, $source_title),
                'filename'          => "{$source_title} {$version_label} Release Notes",
                'file_size'         => strlen($latest_content),
                'version_shown'     => $resolved_latest_version ?: ($latest_ver ?: 'Latest'),
                'installed_version' => $installed_ver,
                'latest_version'    => $resolved_latest_version ?: $latest_ver,
                'content'           => $latest_content,
                'notice'            => '',
            ]);
        }

        // --- STEP 2: Fallback to reading the locally installed version changelog ---
        if (!empty($target_dir) && PathValidator::is_inside_root($target_dir, ABSPATH)) {
            $changelog = self::detect_component_changelog($target_dir);
            if ($changelog['has_changelog']) {
                $file_path = $changelog['full_path'];
                if (PathValidator::is_inside_root($file_path, $target_dir)) {
                    $max_bytes = 250 * 1024;
                    $content = file_get_contents($file_path, false, null, 0, $max_bytes);
                    if ($content !== false) {
                        if (function_exists('mb_check_encoding') && !mb_check_encoding($content, 'UTF-8')) {
                            $content = mb_convert_encoding($content, 'UTF-8', 'ISO-8859-1');
                        }

                        $target_label = $latest_ver ? "v{$latest_ver}" : 'latest upstream';
                        $installed_label = $installed_ver ? "v{$installed_ver}" : 'local';

                        return rest_ensure_response([
                            'success'           => true,
                            'has_changelog'     => true,
                            'is_latest'         => false,
                            'latest_not_found'  => true,
                            'source'            => 'local_installed',
                            'source_label'      => sprintf(
                                /* translators: %s: installed version label */
                                __('Currently Installed Version (%s) [Local Disk]', 'webcare-pro-security'),
                                $installed_label
                            ),
                            'filename'          => $changelog['filename'],
                            'file_size'         => (int) filesize($file_path),
                            'last_modified'     => gmdate('Y-m-d H:i:s', filemtime($file_path)) . ' UTC',
                            'version_shown'     => $installed_ver ?: 'Installed',
                            'installed_version' => $installed_ver,
                            'latest_version'    => $latest_ver,
                            'content'           => $content,
                            'notice'            => sprintf(
                                /* translators: 1: target version label, 2: installed version label */
                                __('Latest version (%1$s) changelog was not found on remote repositories or plugin update manager. Displaying currently installed version (%2$s) changelog from local disk below.', 'webcare-pro-security'),
                                $target_label,
                                $installed_label
                            ),
                        ]);
                    }
                }
            }
        }

        // --- STEP 3: Neither latest nor local changelog found ---
        return rest_ensure_response([
            'success'           => true,
            'has_changelog'     => false,
            'is_latest'         => false,
            'latest_not_found'  => true,
            'source'            => 'none',
            'filename'          => '',
            'content'           => '',
            'message'           => sprintf(
                /* translators: %s: latest version label */
                __('Latest version (%s) changelog was not found on WordPress.org, and no local changelog file (changelog.txt, readme.txt, or changelog.md) exists in the installed component folder.', 'webcare-pro-security'),
                $latest_ver ? "v{$latest_ver}" : 'upstream'
            ),
        ]);
    }

    /**
     * Get high-precision current timestamp in WordPress local time.
     *
     * @return string e.g. "2026-10-12 01:10:12.345"
     */
    public static function now_fractional_mysql() {
        $micro = microtime(true);
        $seconds = (int) $micro;
        $millis = (int) round(($micro - $seconds) * 1000);
        if ($millis >= 1000) {
            $seconds++;
            $millis = 0;
        }
        $date_str = wp_date('Y-m-d H:i:s', $seconds);
        return sprintf('%s.%03d', $date_str, $millis);
    }

    /**
     * Formats duration in seconds or fractional seconds into human-readable representation.
     *
     * @param float $duration_secs Duration in seconds (e.g. 0.42, 1.85, 65.2)
     * @param int $duration_ms Duration in milliseconds (e.g. 420)
     * @return string e.g. "420ms", "1.85s", "1m 5s"
     */
    public static function format_duration_precise($duration_secs, $duration_ms = 0) {
        $ms = (int) $duration_ms;
        if ($ms <= 0 && $duration_secs > 0) {
            $ms = (int) round($duration_secs * 1000);
        }

        if ($ms < 1000 && $ms > 0) {
            return "{$ms}ms";
        }

        $secs = $duration_secs > 0 ? $duration_secs : round($ms / 1000, 2);
        if ($secs < 10) {
            return sprintf('%.2fs', $secs);
        } elseif ($secs < 60) {
            return sprintf('%.1fs', $secs);
        }

        $total_sec = (int) round($secs);
        $mins = floor($total_sec / 60);
        $rem_sec = $total_sec % 60;
        return "{$mins}m {$rem_sec}s";
    }

    /**
     * Resolves and formats descriptive metadata for any scan target (standard, custom, or targeted).
     *
     * @param string $target The raw scan target identifier (e.g. 'custom', 'plugins_themes', 'suspicious_uploads', etc.)
     * @return array Metadata array with name, short_name, category, category_label, and description.
     */
    public static function format_scan_target_meta(string $target): array {
        $target = sanitize_key($target);

        $definitions = [
            'custom' => [
                'name'           => 'Custom Security Scan',
                'short_name'     => 'Custom Scan',
                'category'       => 'custom',
                'category_label' => 'Custom Scan',
                'description'    => 'Administrator-configured modular audit tailored to specific security engines and directories.',
            ],
            'plugins_themes' => [
                'name'           => 'Quick Scan (Plugins & Themes)',
                'short_name'     => 'Quick Scan',
                'category'       => 'standard',
                'category_label' => 'Standard Scan',
                'description'    => 'Standard audit of active and installed plugins and themes.',
            ],
            'full' => [
                'name'           => 'Complete Website Scan (Full Filesystem)',
                'short_name'     => 'Complete Scan',
                'category'       => 'standard',
                'category_label' => 'Standard Scan',
                'description'    => 'Comprehensive audit of entire WordPress root, core, plugins, themes, uploads, and database.',
            ],
            'full_filesystem' => [
                'name'           => 'Complete Website Scan (Full Filesystem)',
                'short_name'     => 'Complete Scan',
                'category'       => 'standard',
                'category_label' => 'Standard Scan',
                'description'    => 'Comprehensive audit of entire WordPress root filesystem and database.',
            ],
            'modified_files' => [
                'name'           => 'Targeted: Modified Themes, Plugins & Core Audit',
                'short_name'     => 'Targeted: Modified Files',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted cryptographic checksum verification against official WordPress.org manifests.',
            ],
            'suspicious_uploads' => [
                'name'           => 'Targeted: Uploads Executables & Shell Audit',
                'short_name'     => 'Targeted: Uploads',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted forensic scan isolating dangerous scripts, shells, and double extensions in uploads.',
            ],
            'unknown_files' => [
                'name'           => 'Targeted: Unknown Files Integrity Audit',
                'short_name'     => 'Targeted: Unknown Files',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted reconciliation against official repositories to detect orphan files and backdoors.',
            ],
            'spam_content' => [
                'name'           => 'Targeted: Spam Content & Database Audit',
                'short_name'     => 'Targeted: Spam Content',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted database scan hunting for cloaked spam, blackhat SEO injections, and malicious comments.',
            ],
            'filesystem_only' => [
                'name'           => 'Targeted: Filesystem Permissions & Symlinks Audit',
                'short_name'     => 'Targeted: Filesystem',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted audit evaluating Unix permissions, writeability hazards, and symlink breakouts.',
            ],
            'user_security' => [
                'name'           => 'Targeted: User Accounts, Roles & Capability Auditor',
                'short_name'     => 'Targeted: User Accounts',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted scan inspecting rogue administrator privileges, ghost users, and weak credentials.',
            ],
            'outdated_software' => [
                'name'           => 'Targeted: Outdated Software & Vulnerability Audit',
                'short_name'     => 'Targeted: Outdated Software',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted CVE intelligence matching against active WordPress core, plugins, and themes.',
            ],
            'crontab_audit' => [
                'name'           => 'Targeted: Crontab & Scheduled Tasks Audit',
                'short_name'     => 'Targeted: Crontab Audit',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted Linux crontab and WP-Cron virtual hook inspection for scheduled stealth persistence.',
            ],
            'crontab_hooks' => [
                'name'           => 'Targeted: Crontab & Scheduled Tasks Audit',
                'short_name'     => 'Targeted: Crontab Audit',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted Linux crontab and WP-Cron virtual hook inspection.',
            ],
            'core_integrity' => [
                'name'           => 'Targeted: WordPress Core Integrity Audit',
                'short_name'     => 'Targeted: Core Integrity',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted cryptographic checksum verification strictly auditing core WordPress files.',
            ],
            'rogue_admin' => [
                'name'           => 'Targeted: Rogue Admins & DB Anomalies Audit',
                'short_name'     => 'Targeted: Rogue Admins',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted database scan detecting backdoor accounts, hidden administrators, and tampered capability roles.',
            ],
            'hook_sentinel' => [
                'name'           => 'Targeted: Hook Sentinel & LotL Traps Audit',
                'short_name'     => 'Targeted: Hook Sentinel',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted runtime inspection uncovering malicious filters, actions, and Living-off-the-Land persistence hooks.',
            ],
            'uploads_database' => [
                'name'           => 'Targeted: Uploads & Database Audit',
                'short_name'     => 'Targeted: Uploads & DB',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted inspection of media uploads folder and database tables.',
            ],
        ];

        $res = isset($definitions[$target]) ? $definitions[$target] : null;
        if (!$res) {
            $human_target = ucwords(str_replace(['_', '-'], ' ', $target));
            $is_custom = strpos($target, 'custom') !== false;
            $res = [
                'name'           => $is_custom ? ('Custom Scan: ' . $human_target) : ('Targeted: ' . $human_target),
                'short_name'     => $is_custom ? 'Custom Scan' : ('Targeted: ' . $human_target),
                'category'       => $is_custom ? 'custom' : 'targeted',
                'category_label' => $is_custom ? 'Custom Scan' : 'Targeted Scan',
                'description'    => 'Specialized security audit.',
            ];
        }

        $res['badge'] = $res['category_label'];
        if ($res['category'] === 'custom') {
            $res['badge_bg'] = '#faf5ff';
            $res['badge_color'] = '#7e22ce';
            $res['badge_border'] = '#e9d5ff';
        } elseif ($res['category'] === 'targeted') {
            $res['badge_bg'] = '#ecfeff';
            $res['badge_color'] = '#0891b2';
            $res['badge_border'] = '#a5f3fc';
        } else {
            $res['badge_bg'] = '#eff6ff';
            $res['badge_color'] = '#1d4ed8';
            $res['badge_border'] = '#bfdbfe';
        }

        return $res;
    }

    /**
     * Enriches scan row with unambiguous ISO 8601 UTC / GMT timestamps
     * using official WordPress get_gmt_from_date() conversion.
     *
     * @param array $row
     * @return array
     */
    public static function enrich_scan_row_timestamps(array $row): array {
        $tz_string = wp_timezone_string();
        $row['site_timezone'] = $tz_string;
        if (!empty($row['created_at_gmt'])) {
            $row['created_at_gmt'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($row['created_at_gmt']));
        } elseif (!empty($row['created_at'])) {
            $row['created_at_gmt'] = get_gmt_from_date($row['created_at'], 'Y-m-d\TH:i:s\Z');
        }
        if (!empty($row['started_at'])) {
            $base_s = substr($row['started_at'], 0, 19);
            $sub_s  = substr($row['started_at'], 19);
            $gmt_s  = get_gmt_from_date($base_s, 'Y-m-d\TH:i:s');
            $row['started_at_gmt'] = $gmt_s ? ($gmt_s . ($sub_s ?: '') . 'Z') : null;
        }
        if (!empty($row['completed_at'])) {
            $base_c = substr($row['completed_at'], 0, 19);
            $sub_c  = substr($row['completed_at'], 19);
            $gmt_c  = get_gmt_from_date($base_c, 'Y-m-d\TH:i:s');
            $row['completed_at_gmt'] = $gmt_c ? ($gmt_c . ($sub_c ?: '') . 'Z') : null;
        }
        return $row;
    }

    /**
     * Build rich performance and system diagnostic telemetry for a scan.
     *
     * @param array $scan
     * @return array
     */
    public static function build_scan_diagnostics(array $scan) {
        $scan_id = (int) ($scan['id'] ?? 0);
        $cached_diag = $scan_id > 0 ? get_transient("webcareproscan_diag_{$scan_id}") : null;

        // Peak Memory
        $peak_bytes = memory_get_peak_usage(true);
        if ($cached_diag && !empty($cached_diag['peak_memory_bytes'])) {
            $peak_bytes = max($peak_bytes, (int) $cached_diag['peak_memory_bytes']);
        }
        $peak_mb = round($peak_bytes / (1024 * 1024), 2);

        // Memory Limit
        $memory_limit_raw = ini_get('memory_limit') ?: '256M';
        $limit_bytes = 256 * 1024 * 1024;
        if (preg_match('/^(\d+)(.)$/i', $memory_limit_raw, $m)) {
            $val = (int) $m[1];
            $unit = strtoupper($m[2]);
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }
        $memory_pct = $limit_bytes > 0 ? round(($peak_bytes / $limit_bytes) * 100, 1) : 0;

        // Accurate Duration & Throughput
        $duration_ms = (int) ($scan['duration_ms'] ?? 0);
        $duration_sec = isset($scan['duration']) ? (float) $scan['duration'] : 0.0;

        if ($duration_ms > 0) {
            $duration_sec = round($duration_ms / 1000, 3);
        } elseif ($duration_sec <= 0 && !empty($scan['started_at']) && !empty($scan['completed_at'])) {
            $start_dt = date_create_from_format('Y-m-d H:i:s.u', $scan['started_at']) ?: date_create($scan['started_at']);
            $end_dt = date_create_from_format('Y-m-d H:i:s.u', $scan['completed_at']) ?: date_create($scan['completed_at']);
            if ($start_dt && $end_dt) {
                $diff = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                if ($diff > 0) {
                    $duration_sec = round($diff, 3);
                    $duration_ms = (int) round($diff * 1000);
                }
            }
        } elseif ($duration_sec <= 0 && !empty($scan['created_at'])) {
            $created_dt = date_create($scan['created_at'], wp_timezone());
            if ($created_dt) {
                $now_dt = date_create('now', wp_timezone());
                $diff = $now_dt->getTimestamp() - $created_dt->getTimestamp();
                $duration_sec = max(0.1, (float) $diff);
                $duration_ms = (int) round($duration_sec * 1000);
            }
        }

        $duration_fmt = self::format_duration_precise($duration_sec, $duration_ms);
        $scanned_files = (int) ($scan['scanned_files'] ?? ($scan['total_files'] ?? 0));
        $effective_sec = max(0.1, $duration_sec);
        $files_per_sec = round($scanned_files / $effective_sec, 1);

        // CPU Load Average
        $cpu_load = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $cpu_load = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2)
                ];
            }
        }

        // Server & System Environment details
        $php_version = PHP_VERSION;
        $php_sapi = php_sapi_name();
        $server_os = php_uname('s') . ' ' . php_uname('r');
        $server_arch = php_uname('m');
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
        $max_execution_time = (int) ini_get('max_execution_time');
        $opcache_status = (extension_loaded('Zend OPcache') && ini_get('opcache.enable')) ? 'Enabled' : 'Disabled';

        // CPU Cores Detection
        $cpu_cores = null;
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            $cpu_cores = (int) $win_cores;
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                $cpu_cores = substr_count($cpuinfo, 'processor');
            }
        }

        global $wpdb;
        $db_version = $wpdb ? $wpdb->db_version() : null;
        $db_name = defined('DB_NAME') ? DB_NAME : null;

        return [
            'duration_seconds'       => round($duration_sec, 2),
            'duration_ms'            => $duration_ms,
            'duration_formatted'     => $duration_fmt,
            'peak_memory_mb'         => $peak_mb,
            'peak_memory_fmt'        => "{$peak_mb} MB",
            'memory_limit_raw'       => $memory_limit_raw,
            'memory_percent'         => $memory_pct,
            'scanned_files'          => $scanned_files,
            'total_files'            => (int) ($scan['total_files'] ?? 0),
            'files_per_second'       => $files_per_sec,
            'cpu_load'               => $cpu_load,
            'cpu_cores'              => $cpu_cores,
            'server_software'        => $server_software,
            'server_os'              => $server_os,
            'server_arch'            => $server_arch,
            'php_version'            => $php_version,
            'php_sapi'               => $php_sapi,
            'php_max_execution_time' => $max_execution_time,
            'database_version'       => $db_version,
            'database_name'          => $db_name,
            'wordpress_version'      => get_bloginfo('version'),
            'ssl_active'             => is_ssl(),
            'opcache_status'         => $opcache_status,
            'engines_active'         => 23,
        ];
    }

    /**
     * Compute real-time telemetry metrics (memory, CPU, speed, progress, system context)
     * during active scan execution for administrator visibility.
     *
     * @param float|null $batch_start_time
     * @param array|null $batch_ru_start
     * @param int $scanned_files
     * @param int $total_files
     * @param int $issues_found
     * @param float $elapsed_sec
     * @param \WebCareProScanner\Resource\ResourceMonitor|null $governor
     * @return array
     */
    public static function get_realtime_resource_stats($batch_start_time = null, $batch_ru_start = null, $scanned_files = 0, $total_files = 0, $issues_found = 0, $elapsed_sec = 0.0, $governor = null) {
        // 1. Memory Metrics
        $mem_bytes = memory_get_usage(true);
        $mem_peak_bytes = memory_get_peak_usage(true);
        $mem_mb = round($mem_bytes / (1024 * 1024), 1);
        $mem_peak_mb = round($mem_peak_bytes / (1024 * 1024), 1);

        $memory_limit_raw = ini_get('memory_limit') ?: '256M';
        $limit_bytes = 256 * 1024 * 1024;
        if ($memory_limit_raw === '-1') {
            $limit_bytes = 0; // unlimited
        } elseif (preg_match('/^(\d+)(.)$/i', $memory_limit_raw, $m)) {
            $val = (int) $m[1];
            $unit = strtoupper($m[2]);
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }

        $mem_percent = $limit_bytes > 0 ? round(($mem_bytes / $limit_bytes) * 100, 1) : 0.0;
        $mem_peak_percent = $limit_bytes > 0 ? round(($mem_peak_bytes / $limit_bytes) * 100, 1) : 0.0;
        $mem_free_mb = $limit_bytes > 0 ? max(0, round(($limit_bytes - $mem_bytes) / (1024 * 1024), 1)) : 9999.0;

        // 2. CPU / Load Metrics
        $cpu_percent = null;
        if ($batch_start_time && $batch_ru_start && function_exists('getrusage')) {
            $batch_wall_time = max(0.001, microtime(true) - $batch_start_time);
            $ru_end = @getrusage();
            if (is_array($ru_end) && is_array($batch_ru_start)) {
                $user_start = ($batch_ru_start['ru_utime.tv_sec'] ?? 0) + (($batch_ru_start['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_start  = ($batch_ru_start['ru_stime.tv_sec'] ?? 0) + (($batch_ru_start['ru_stime.tv_usec'] ?? 0) / 1000000);
                $user_end   = ($ru_end['ru_utime.tv_sec'] ?? 0) + (($ru_end['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_end    = ($ru_end['ru_stime.tv_sec'] ?? 0) + (($ru_end['ru_stime.tv_usec'] ?? 0) / 1000000);
                $cpu_time_used = max(0, ($user_end + $sys_end) - ($user_start + $sys_start));
                $cpu_percent = min(100.0, round(($cpu_time_used / $batch_wall_time) * 100, 1));
            }
        }

        $cpu_load = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $cpu_load = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2),
                ];
            }
        }

        $cpu_cores = null;
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            $cpu_cores = (int) $win_cores;
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                $cpu_cores = substr_count($cpuinfo, 'processor');
            }
        }

        // 3. Scan Throughput & ETA
        $files_per_sec = ($elapsed_sec > 0 && $scanned_files > 0) ? round($scanned_files / $elapsed_sec, 1) : 0.0;
        $remaining_files = max(0, $total_files - $scanned_files);
        $eta_seconds = ($files_per_sec > 0 && $remaining_files > 0) ? (int) round($remaining_files / $files_per_sec) : null;

        // 4. Server environment details
        $php_version = PHP_VERSION;
        $server_os = php_uname('s');
        $max_exec = (int) ini_get('max_execution_time');

        // 5. Dynamic Governor Telemetry & Visitor Protection Diagnostics
        $governor_info = null;
        if ($governor instanceof \WebCareProScanner\Resource\ResourceMonitor) {
            $governor_info = $governor->get_telemetry_payload();
        } else {
            $temp_gov = new \WebCareProScanner\Resource\ResourceMonitor(70, 18, 'balanced');
            $governor_info = $temp_gov->get_telemetry_payload();
        }

        return [
            'memory_mb'           => $mem_mb,
            'memory_peak_mb'      => $mem_peak_mb,
            'memory_limit_raw'    => $memory_limit_raw,
            'memory_percent'      => $mem_percent,
            'memory_peak_percent' => $mem_peak_percent,
            'memory_free_mb'      => $mem_free_mb,
            'cpu_percent'         => $cpu_percent,
            'cpu_load'            => $cpu_load,
            'cpu_cores'           => $cpu_cores,
            'scanned_files'       => $scanned_files,
            'total_files'         => $total_files,
            'files_per_sec'       => $files_per_sec,
            'eta_seconds'         => $eta_seconds,
            'issues_found'        => $issues_found,
            'php_version'         => $php_version,
            'server_os'           => $server_os,
            'max_execution_time'  => $max_exec,
            'governor'            => $governor_info,
        ];
    }

    /**
     * Safely read and return file content for code inspection popup modal.
     */
    public static function view_file_content(\WP_REST_Request $request) {
        $raw_path = sanitize_text_field($request->get_param('file_path') ?: ($request->get_param('path') ?: ''));
        if (empty($raw_path)) {
            return new \WP_Error('missing_path', __('File path parameter is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Clean path and ensure inside ABSPATH
        $raw_path = str_replace(['../', '..\\'], '', $raw_path);
        $norm_abspath = wp_normalize_path(ABSPATH);

        $target_full = '';
        if (file_exists($raw_path)) {
            $target_full = wp_normalize_path($raw_path);
        } else {
            $candidate = wp_normalize_path(ABSPATH . ltrim($raw_path, '/\\'));
            if (file_exists($candidate)) {
                $target_full = $candidate;
            }
        }

        if (empty($target_full) || !file_exists($target_full)) {
            return new \WP_Error('file_not_found', __('File does not exist or has been removed from server.', 'webcare-pro-security'), ['status' => 404]);
        }

        // Canonical directory boundary check: Enforce trailing slash on root to eliminate sibling directory escapes
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_root($target_full, ABSPATH)) {
            return new \WP_Error('forbidden_path', __('Access to this file path is restricted outside WordPress root.', 'webcare-pro-security'), ['status' => 403]);
        }

        $real_path = realpath($target_full);
        if (!$real_path || !is_file($real_path)) {
            return new \WP_Error('not_a_file', __('The requested path is a directory or special file, not a viewable file.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!is_readable($real_path)) {
            return new \WP_Error('unreadable_file', __('File is not readable due to server permissions.', 'webcare-pro-security'), ['status' => 403]);
        }

        $file_size = (int) filesize($real_path);
        $max_read = 750 * 1024; // 750KB limit to protect memory
        $is_truncated = $file_size > $max_read;

        $content = file_get_contents($real_path, false, null, 0, $max_read);
        if ($content === false) {
            return new \WP_Error('read_error', __('Failed to read file content.', 'webcare-pro-security'), ['status' => 500]);
        }

        $perms = substr(sprintf('%o', fileperms($real_path)), -4);

        $extension = strtolower(pathinfo($real_path, PATHINFO_EXTENSION));
        $image_mimes = [
            'png'  => 'image/png',
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif'  => 'image/gif',
            'webp' => 'image/webp',
            'svg'  => 'image/svg+xml',
            'ico'  => 'image/x-icon',
            'bmp'  => 'image/bmp',
        ];

        $is_image_ext = isset($image_mimes[$extension]);
        $is_image = false;
        $image_base64 = null;
        $image_dimensions = null;
        $image_security = [
            'is_valid_binary'    => false,
            'detected_type'      => null,
            'magic_bytes_match'  => false,
            'threat_warning'     => null,
            'has_embedded_php'   => false,
            'disguised_exec'     => null,
        ];

        if ($is_image_ext) {
            $magic_header = @file_get_contents($real_path, false, null, 0, 32);

            // 1. Binary Magic Header Check for True Image Formats
            $magic_matches = false;
            $detected_format = null;

            if ($magic_header !== false && strlen($magic_header) >= 4) {
                // PNG: 89 50 4E 47 0D 0A 1A 0A
                if (str_starts_with($magic_header, "\x89PNG\r\n\x1a\n")) {
                    $magic_matches = in_array($extension, ['png'], true);
                    $detected_format = 'PNG Image';
                }
                // JPEG: FF D8 FF
                elseif (str_starts_with($magic_header, "\xFF\xD8\xFF")) {
                    $magic_matches = in_array($extension, ['jpg', 'jpeg'], true);
                    $detected_format = 'JPEG Image';
                }
                // GIF: GIF87a or GIF89a
                elseif (str_starts_with($magic_header, 'GIF87a') || str_starts_with($magic_header, 'GIF89a')) {
                    $magic_matches = in_array($extension, ['gif'], true);
                    $detected_format = 'GIF Image';
                }
                // WebP: RIFF....WEBP
                elseif (str_starts_with($magic_header, 'RIFF') && strlen($magic_header) >= 12 && substr($magic_header, 8, 4) === 'WEBP') {
                    $magic_matches = in_array($extension, ['webp'], true);
                    $detected_format = 'WebP Image';
                }
                // BMP: BM
                elseif (str_starts_with($magic_header, 'BM')) {
                    $magic_matches = in_array($extension, ['bmp'], true);
                    $detected_format = 'BMP Image';
                }
                // ICO: 00 00 01 00
                elseif (str_starts_with($magic_header, "\x00\x00\x01\x00")) {
                    $magic_matches = in_array($extension, ['ico'], true);
                    $detected_format = 'ICO Icon';
                }
                // SVG: XML header or <svg tag
                elseif ($extension === 'svg') {
                    $trimmed_head = ltrim($magic_header);
                    if (str_starts_with($trimmed_head, '<?xml') || str_starts_with($trimmed_head, '<svg')) {
                        $magic_matches = true;
                        $detected_format = 'SVG Vector';
                    }
                }
            }

            // 2. Check for Disguised Executable Binaries (PE, ELF, Mach-O, Shell Shebang)
            $disguised_exec = null;
            if ($magic_header !== false) {
                if (str_starts_with($magic_header, 'MZ')) {
                    $disguised_exec = 'Windows PE Executable / DLL (MZ Header)';
                } elseif (str_starts_with($magic_header, "\x7fELF")) {
                    $disguised_exec = 'Linux ELF Binary Executable';
                } elseif (in_array(substr($magic_header, 0, 4), ["\xca\xfe\xba\xbe", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe"], true)) {
                    $disguised_exec = 'Mach-O Binary Executable';
                } elseif (str_starts_with($magic_header, '#!') && preg_match('/^#!\s*\/(bin|usr)/i', $magic_header)) {
                    $disguised_exec = 'Unix Shell Script (Shebang Header)';
                } elseif (preg_match('/^\s*<\?php/i', $magic_header)) {
                    $disguised_exec = 'Pure PHP Script disguised with Image Extension';
                }
            }

            // 3. Check for Embedded Active PHP Polyglots (Head, EXIF, or Tail)
            $has_embedded_php = false;
            $php_pattern = '/<\?(?:php\s+[\s\S]{0,500}?(?:eval|assert|system|passthru|shell_exec|exec|base64_decode|\$_[A-Z]+|\$[a-zA-Z0-9_]+)|\=\s*[\s\S]{0,200}?(?:eval|assert|\$_[A-Z]+|\$[a-zA-Z0-9_]+))/i';
            
            // Scan first 8KB
            $head_8k = @file_get_contents($real_path, false, null, 0, 8192);
            if ($head_8k !== false && preg_match($php_pattern, $head_8k)) {
                $has_embedded_php = true;
            }

            // Scan trailing 8KB for appended payloads
            if (!$has_embedded_php && $file_size > 8192) {
                $tail_offset = max(0, $file_size - 8192);
                $tail_8k = @file_get_contents($real_path, false, null, $tail_offset, 8192);
                if ($tail_8k !== false && preg_match($php_pattern, $tail_8k)) {
                    $has_embedded_php = true;
                }
            }

            // Determine if safe to render visually as image
            $is_image = $magic_matches && empty($disguised_exec);

            $threat_warning = null;
            if (!empty($disguised_exec)) {
                $threat_warning = "MALICIOUS DISGUISED EXECUTABLE: File has a '.{$extension}' extension but its binary signature indicates it is a {$disguised_exec}.";
            } elseif (!$magic_matches) {
                $threat_warning = "MISMATCHED BINARY SIGNATURE: File claims to be an image (.{$extension}), but lacks valid image magic bytes. " . ($detected_format ? "Detected as: {$detected_format}." : "It may be a disguised script or corrupt file.");
            } elseif ($has_embedded_php) {
                $threat_warning = "MALICIOUS POLYGLOT: File is a valid {$detected_format}, but contains embedded executable PHP script code or backdoor tokens.";
            }

            $image_security = [
                'is_valid_binary'   => $magic_matches,
                'detected_type'     => $detected_format,
                'magic_bytes_match' => $magic_matches,
                'threat_warning'    => $threat_warning,
                'has_embedded_php'  => $has_embedded_php,
                'disguised_exec'    => $disguised_exec,
            ];

            // If genuine image, load base64 preview and dimensions
            if ($is_image) {
                $raw_bytes = file_get_contents($real_path, false, null, 0, 5 * 1024 * 1024);
                if ($raw_bytes !== false) {
                    $image_base64 = 'data:' . $image_mimes[$extension] . ';base64,' . base64_encode($raw_bytes);
                }
                if ($extension !== 'svg' && function_exists('getimagesize')) {
                    $img_size = @getimagesize($real_path);
                    if (!empty($img_size)) {
                        $image_dimensions = [
                            'width'  => $img_size[0] ?? null,
                            'height' => $img_size[1] ?? null,
                        ];
                    }
                }
            }
        }

        $is_masked = false;
        $file_basename = strtolower(basename($real_path));
        if (preg_match('/(?:^|[\\/\\\\])wp-config(?:-[^\\/\\\\]+)?\\.php$/i', $real_path) ||
            preg_match('/^(?:\\.env(?:\\.[a-z0-9_-]+)?|wp-config(?:-[^\\/\\\\]+)?\\.php)$/i', $file_basename)
        ) {
            $masked_res = self::mask_sensitive_config_content($content);
            $content = $masked_res['content'];
            $is_masked = $masked_res['is_masked'];
        }

        $lines = explode("\n", $content);
        $line_count = count($lines);

        $rel_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($real_path));
        $rel_path = ltrim($rel_path, '/\\');

        $sha256 = hash_file('sha256', $real_path) ?: '';
        $md5 = md5_file($real_path) ?: '';

        // Forensic filesystem timestamps & stat metadata
        $stat = @stat($real_path) ?: [];
        $ctime = isset($stat['ctime']) ? (int) $stat['ctime'] : @filectime($real_path);
        $mtime = isset($stat['mtime']) ? (int) $stat['mtime'] : @filemtime($real_path);
        $atime = isset($stat['atime']) ? (int) $stat['atime'] : @fileatime($real_path);

        $owner_uid = isset($stat['uid']) ? (int) $stat['uid'] : (function_exists('fileowner') ? @fileowner($real_path) : null);
        $group_gid = isset($stat['gid']) ? (int) $stat['gid'] : (function_exists('filegroup') ? @filegroup($real_path) : null);

        $owner_name = null;
        if ($owner_uid !== null && function_exists('posix_getpwuid')) {
            $pw = @posix_getpwuid($owner_uid);
            if (!empty($pw['name'])) {
                $owner_name = $pw['name'];
            }
        }
        if (!$owner_name && $owner_uid !== null) {
            $owner_name = (string) $owner_uid;
        }

        $group_name = null;
        if ($group_gid !== null && function_exists('posix_getgrgid')) {
            $gr = @posix_getgrgid($group_gid);
            if (!empty($gr['name'])) {
                $group_name = $gr['name'];
            }
        }
        if (!$group_name && $group_gid !== null) {
            $group_name = (string) $group_gid;
        }

        $ownership_formatted = ($owner_name && $group_name) ? "{$owner_name}:{$group_name}" : ($owner_name ?: 'unknown');

        // Detected MIME type
        $mime_type = null;
        if (function_exists('mime_content_type')) {
            $mime_type = @mime_content_type($real_path) ?: null;
        }
        if (!$mime_type && function_exists('finfo_open')) {
            $finfo = @finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo) {
                $mime_type = @finfo_file($finfo, $real_path) ?: null;
                @finfo_close($finfo);
            }
        }
        if (!$mime_type) {
            $mime_type = $is_image_ext ? ($image_mimes[$extension] ?? 'image/' . $extension) : 'text/plain';
        }

        return rest_ensure_response([
            'success'          => true,
            'filename'         => basename($real_path),
            'file_path'        => $rel_path,
            'full_path'        => $real_path,
            'sha256'           => $sha256,
            'md5'              => $md5,
            'size_bytes'       => $file_size,
            'size_formatted'   => size_format($file_size, 2),
            'permissions'      => $perms,
            'is_writable'      => wp_is_writable($real_path),
            'ctime'            => $ctime ? gmdate('Y-m-d H:i:s \U\T\C', $ctime) : 'N/A',
            'mtime'            => $mtime ? gmdate('Y-m-d H:i:s \U\T\C', $mtime) : 'N/A',
            'atime'            => $atime ? gmdate('Y-m-d H:i:s \U\T\C', $atime) : 'N/A',
            'ctime_raw'        => $ctime ?: null,
            'mtime_raw'        => $mtime ?: null,
            'atime_raw'        => $atime ?: null,
            'owner'            => $owner_name ?: 'unknown',
            'group'            => $group_name ?: 'unknown',
            'ownership'        => $ownership_formatted,
            'mime_type'        => $mime_type,
            'line_count'       => $line_count,
            'content'          => $content,
            'is_truncated'     => $is_truncated,
            'is_masked'        => $is_masked,
            'is_image'         => $is_image_ext,
            'is_valid_image'   => $is_image,
            'image_mime'       => $is_image_ext ? $image_mimes[$extension] : null,
            'image_base64'     => $image_base64,
            'image_dimensions' => $image_dimensions,
            'image_security'   => $image_security,
        ]);
    }

    /**
     * Redact database credentials and secret authentication keys from wp-config.php and env files.
     */
    public static function mask_sensitive_config_content($content) {
        $is_masked = false;

        $sensitive_keys = [
            'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST',
            'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
            'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
            'FTP_USER', 'FTP_PASS', 'FTP_HOST', 'FTP_BASE',
            'FTP_SSL', 'FTP_SSH', 'FTP_PUBKEY', 'FTP_PRIKEY',
        ];

        $keys_pattern = implode('|', array_map('preg_quote', $sensitive_keys));

        // Mask define( 'KEY', 'VALUE' ) or define("KEY", "VALUE")
        $new_content = preg_replace_callback(
            "/define\\s*\\(\\s*(['\"])(" . $keys_pattern . ")\\1\\s*,\\s*(['\"])(.*?)\\3(\\s*\\))/i",
            function ($matches) use (&$is_masked) {
                $is_masked = true;
                $quote = $matches[1];
                $key = $matches[2];
                $val_quote = $matches[3];
                $close = $matches[5];
                return "define( {$quote}{$key}{$quote}, {$val_quote}••••••••••••••••{$val_quote}{$close} /* [REDACTED BY WEBCARE PRO SECURITY] */";
            },
            $content
        );

        // Also mask .env style or assignment style: DB_PASSWORD=xxxx or DB_PASS=xxxx
        $env_keys = 'DB_PASSWORD|DB_PASS|DB_USER|DB_USERNAME|DB_HOST|DB_NAME|FTP_PASS|FTP_PASSWORD';
        $new_content = preg_replace_callback(
            "/^(\\s*(" . $env_keys . ")\\s*=\\s*)(['\"]?)(.+?)\\3(\\s*(?:#.*)?)$/mi",
            function ($matches) use (&$is_masked) {
                $is_masked = true;
                $prefix = $matches[1];
                $quote = $matches[3];
                $suffix = $matches[5];
                return "{$prefix}{$quote}••••••••••••••••{$quote}{$suffix} # [REDACTED BY WEBCARE PRO SECURITY]";
            },
            $new_content
        );

        return [
            'content'   => $new_content,
            'is_masked' => $is_masked,
        ];
    }

    /**
     * Safely read and return post/page content for inspection popup modal.
     */
    public static function view_post_content(\WP_REST_Request $request) {
        $post_id = (int) $request->get_param('post_id');
        if (!$post_id) {
            $path = sanitize_text_field($request->get_param('path') ?: '');
            if (preg_match('/^post:(\d+)/i', $path, $matches)) {
                $post_id = (int) $matches[1];
            }
        }

        if (!$post_id) {
            return new \WP_Error('missing_post_id', __('Valid post ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $post = get_post($post_id);
        if (!$post) {
            return new \WP_Error('post_not_found', __('The requested post or page was not found.', 'webcare-pro-security'), ['status' => 404]);
        }

        return rest_ensure_response([
            'success'      => true,
            'post_id'      => $post_id,
            'title'        => $post->post_title ?: __('(Untitled)', 'webcare-pro-security'),
            'post_type'    => $post->post_type,
            'post_status'  => $post->post_status,
            'author'       => get_the_author_meta('display_name', $post->post_author),
            'content'      => $post->post_content,
            'view_url'     => get_permalink($post_id) ?: '',
            'edit_url'     => get_edit_post_link($post_id, 'raw') ?: admin_url("post.php?post={$post_id}&action=edit"),
            'date'         => $post->post_date,
            'modified'     => $post->post_modified,
        ]);
    }

    /**
     * Helper to build schedule time info payload
     */
    public static function build_schedule_time_info() {
        $next_run_timestamp = wp_next_scheduled(\WebCareProScanner\System\SettingsManager::CRON_HOOK);
        $now_utc = time();
        $diff_seconds = $next_run_timestamp ? max(0, $next_run_timestamp - $now_utc) : 0;

        $tz_string = get_option('timezone_string');
        $gmt_offset = get_option('gmt_offset');
        if (empty($tz_string)) {
            $offset_sign = $gmt_offset >= 0 ? '+' : '-';
            $offset_hours = abs((int) $gmt_offset);
            $offset_mins = abs((int) (($gmt_offset - (int) $gmt_offset) * 60));
            $tz_string = sprintf('UTC%s%02d:%02d', $offset_sign, $offset_hours, $offset_mins);
        }

        $is_cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;

        return [
            'next_run_timestamp' => $next_run_timestamp ?: null,
            'next_scheduled_wp'  => $next_run_timestamp ? (function_exists('wp_date') ? wp_date('Y-m-d H:i:s', $next_run_timestamp) : date_i18n('Y-m-d H:i:s', $next_run_timestamp + (int) ($gmt_offset * 3600))) : null,
            'next_scheduled_gmt' => $next_run_timestamp ? gmdate('Y-m-d H:i:s', $next_run_timestamp) . ' GMT' : null,
            'diff_seconds'       => $diff_seconds,
            'current_wp_time'    => current_time('Y-m-d H:i:s'),
            'current_gmt_time'   => gmdate('Y-m-d H:i:s') . ' GMT',
            'timezone'           => $tz_string,
            'gmt_offset'         => (float) $gmt_offset,
            'cron_disabled'      => $is_cron_disabled,
        ];
    }

    /**
     * Get plugin settings
     */
    public static function get_settings(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $time_info = self::build_schedule_time_info();

        $uid = get_current_user_id();
        $is_support = false;
        $restrictions = [];
        if ($uid) {
            $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
            $is_support = !empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid]));
            if ($is_support && is_array($support_users) && isset($support_users[$uid])) {
                $restrictions = $support_users[$uid];
            }
        }

        // Redact Secret Vault keys if accessed by temporary support technician
        if ($is_support) {
            $secret_keys = [
                'cloudflare_api_token',
                'cloudflare_global_api_key',
                'ai_api_key',
                'mcp_token',
                'smtp_password',
                'webhook_url',
            ];
            foreach ($secret_keys as $skey) {
                if (!empty($settings[$skey])) {
                    $settings[$skey] = '••••••••••••••••';
                }
            }
        }

        return rest_ensure_response([
            'success'                        => true,
            'settings'                       => $settings,
            'ai_connect_status'              => \WebCareProScanner\System\AIService::get_ai_connect_status(),
            'next_scheduled'                 => $time_info['next_scheduled_wp'],
            'schedule_time'                  => $time_info,
            'current_time'                   => $time_info['current_wp_time'],
            'is_temporary_support'           => $is_support,
            'temporary_support_restrictions' => $restrictions,
        ]);
    }

    /**
     * Save plugin settings
     */
    public static function save_settings(\WP_REST_Request $request) {
        $uid = get_current_user_id();
        if ($uid) {
            $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
            if (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid]))) {
                $cfg = $support_users[$uid] ?? [];
                if (!isset($cfg['block_settings_modification']) || !empty($cfg['block_settings_modification'])) {
                    return new \WP_Error(
                        'rest_forbidden',
                        __('Access Denied: Temporary support technicians are prohibited from modifying security settings.', 'webcare-pro-security'),
                        ['status' => 403]
                    );
                }
            }
        }

        $params = $request->get_json_params();
        if (!is_array($params)) {
            $params = $request->get_body_params();
        }

        $old_settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $saved = \WebCareProScanner\System\SettingsManager::save_settings((array) $params);
        $time_info = self::build_schedule_time_info();

        // Check toggles for Webhooks, AI Forensics, and MCP Service
        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            $old_webhook = !empty($old_settings['generic_webhook_enabled']) || !empty($old_settings['slack_enabled']) || !empty($old_settings['discord_enabled']);
            $new_webhook = !empty($saved['generic_webhook_enabled']) || !empty($saved['slack_enabled']) || !empty($saved['discord_enabled']);
            if ($old_webhook !== $new_webhook) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('webhook_status_toggled', [
                    'severity' => 'info',
                    /* translators: %s: status string */
                    'message'  => sprintf(__('DevSecOps Webhook channels were %s.', 'webcare-pro-security'), $new_webhook ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
                    'details'  => [
                        'State' => $new_webhook ? 'Enabled' : 'Disabled',
                    ],
                ]);
            }

            if (!empty($old_settings['ai_enabled']) !== !empty($saved['ai_enabled'])) {
                $ai_on = !empty($saved['ai_enabled']);
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('ai_forensics_toggled', [
                    'severity' => 'info',
                    /* translators: %s: status string */
                    'message'  => sprintf(__('AI Code Forensics engine was %s.', 'webcare-pro-security'), $ai_on ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
                    'details'  => [
                        'State'    => $ai_on ? 'Enabled' : 'Disabled',
                        'Provider' => $saved['ai_provider'] ?? 'gemini',
                    ],
                ]);
            }

            if (!empty($old_settings['mcp_enabled']) !== !empty($saved['mcp_enabled'])) {
                $mcp_on = !empty($saved['mcp_enabled']);
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('mcp_service_toggled', [
                    'severity' => 'info',
                    /* translators: %s: status string */
                    'message'  => sprintf(__('Model Context Protocol (MCP) Agent Service was %s.', 'webcare-pro-security'), $mcp_on ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
                    'details'  => [
                        'State' => $mcp_on ? 'Enabled' : 'Disabled',
                    ],
                ]);
            }
        }

        return rest_ensure_response([
            'success'           => true,
            'message'           => __('Settings successfully saved.', 'webcare-pro-security'),
            'settings'          => $saved,
            'ai_connect_status' => \WebCareProScanner\System\AIService::get_ai_connect_status(),
            'next_scheduled'    => $time_info['next_scheduled_wp'],
            'schedule_time'     => $time_info,
        ]);
    }

    /**
     * Export settings as downloadable JSON payload
     */
    public static function export_settings(\WP_REST_Request $request) {
        $data = \WebCareProScanner\System\SettingsManager::export_settings();
        return rest_ensure_response([
            'success' => true,
            'export'  => $data,
        ]);
    }

    /**
     * Import settings from uploaded JSON payload
     */
    public static function import_settings(\WP_REST_Request $request) {
        $payload = $request->get_json_params();
        if (empty($payload)) {
            $raw = $request->get_body();
            if (!empty($raw)) {
                $payload = json_decode($raw, true);
            }
            if (empty($payload)) {
                $payload = $request->get_body_params();
            }
        }
        if (empty($payload) || !is_array($payload)) {
            return new \WP_Error('invalid_import', __('Invalid JSON data.', 'webcare-pro-security'), ['status' => 400]);
        }

        $uid = get_current_user_id();
        if ($uid) {
            $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
            if (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid]))) {
                return new \WP_Error(
                    'rest_forbidden',
                    __('Temporary support technicians are strictly prohibited from importing or overwriting plugin settings.', 'webcare-pro-security'),
                    ['status' => 403]
                );
            }
        }

        try {
            $imported = \WebCareProScanner\System\SettingsManager::import_settings($payload);
            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Settings successfully imported and applied.', 'webcare-pro-security'),
                'settings' => $imported,
            ]);
        } catch (\Exception $e) {
            return new \WP_Error('import_failed', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Reset settings to factory defaults
     */
    public static function reset_settings(\WP_REST_Request $request) {
        $uid = get_current_user_id();
        if ($uid) {
            $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
            if (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid]))) {
                return new \WP_Error(
                    'rest_forbidden',
                    __('Temporary support technicians are strictly prohibited from resetting plugin settings to factory defaults.', 'webcare-pro-security'),
                    ['status' => 403]
                );
            }
        }

        $defaults = \WebCareProScanner\System\SettingsManager::reset_defaults();
        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Settings have been reset to factory defaults.', 'webcare-pro-security'),
            'settings' => $defaults,
        ]);
    }

    /**
     * Manually trigger the scheduled cron scan immediately (for test / on-demand cron execution)
     */
    public static function trigger_cron_now(\WP_REST_Request $request) {
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            return new \WP_Error(
                'scan_locked',
                sprintf(
                    /* translators: %d: active scan ID */
                    __('A scan is already actively running (ID: %d).', 'webcare-pro-security'),
                    $locked_id
                ),
                ['status' => 409]
            );
        }

        // Run scheduled scan synchronously or trigger the hook
        try {
            \WebCareProScanner\System\Scheduler::run_scheduled_scan();
            return rest_ensure_response([
                'success' => true,
                'message' => __('Scheduled security scan was triggered and executed successfully.', 'webcare-pro-security'),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('cron_trigger_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Audit HTTP security headers & site hardening status
     */
    public static function get_hardening_audit(\WP_REST_Request $request) {
        $audit = \WebCareProScanner\Hardening\SecurityHeadersEngine::audit_hardening_status();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Apply recommended A+ hardening preset
     */
    public static function apply_hardening_preset(\WP_REST_Request $request) {
        $current = \WebCareProScanner\System\SettingsManager::get_settings();
        
        $preset = [
            'header_hsts'                      => true,
            'header_hsts_preload'              => false,
            'header_x_frame_options'           => true,
            'header_x_frame_options_mode'      => 'SAMEORIGIN',
            'header_nosniff'                   => true,
            'header_referrer_policy'           => true,
            'header_referrer_policy_value'     => 'strict-origin-when-cross-origin',
            'header_permissions_policy'        => true,
            'header_permissions_policy_value'  => 'geolocation=(), camera=(), microphone=(), payment=()',
            'header_xss_protection'            => true,
            'disable_file_editing'             => true,
            'block_user_enumeration'           => true,
            'hide_wp_version'                  => true,
            'block_sensitive_files'            => true,
            'waf_disable_xmlrpc'               => true,
        ];

        $updated = array_merge($current, $preset);
        $saved = \WebCareProScanner\System\SettingsManager::save_settings($updated);
        $audit = \WebCareProScanner\Hardening\SecurityHeadersEngine::audit_hardening_status();

        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Recommended A+ Security Hardening preset applied successfully.', 'webcare-pro-security'),
            'settings' => $saved,
            'audit'    => $audit,
        ]);
    }

    /**
     * Test AI connection
     */
    public static function test_ai_connection(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $provider = sanitize_text_field($params['provider'] ?? 'openai');
        $api_key  = trim($params['api_key'] ?? '');
        $model    = sanitize_text_field($params['model'] ?? '');

        if ($provider === 'wp_ai_connect') {
            $result = \WebCareProScanner\System\AIService::test_connection($provider, '', $model);
            if (empty($result['success'])) {
                return new \WP_Error('ai_test_failed', $result['error'] ?? 'WordPress Native AI Connect Test Failed', ['status' => 400]);
            }
            return rest_ensure_response($result);
        }

        // If key is masked or empty, fall back to stored key
        if ($api_key === '' || $api_key === '••••••••') {
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            if ($provider === 'gemini') {
                $api_key = $settings['gemini_api_key'] ?? '';
                if (!$model) $model = $settings['gemini_model'] ?? 'gemini-3.8-flash';
            } elseif ($provider === 'claude') {
                $api_key = $settings['claude_api_key'] ?? '';
                if (!$model) $model = $settings['claude_model'] ?? 'claude-sonnet-5-5';
            } else {
                $api_key = $settings['openai_api_key'] ?? '';
                if (!$model) $model = $settings['openai_model'] ?? 'gpt-6.1-sol';
            }
        }

        $result = \WebCareProScanner\System\AIService::test_connection($provider, $api_key, $model);
        if (empty($result['success'])) {
            return new \WP_Error('ai_test_failed', $result['error'] ?? 'AI Test Connection Failed', ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Run AI forensic analysis on code or suspicious finding
     */
    public static function analyze_code_with_ai(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        try {
            $analysis = \WebCareProScanner\System\AIService::analyze_code($params);
            return rest_ensure_response($analysis);
        } catch (\Exception $e) {
            return new \WP_Error('ai_analysis_error', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Get available AI model catalog
     */
    public static function get_ai_models(\WP_REST_Request $request) {
        $catalog = \WebCareProScanner\System\AIService::get_available_models();
        return rest_ensure_response([
            'success' => true,
            'catalog' => $catalog,
        ]);
    }

    /**
     * Check provider APIs for new agent releases and update catalog & settings
     */
    public static function update_ai_models(\WP_REST_Request $request) {
        try {
            $params = $request->get_json_params() ?: [];
            $auto_upgrade = !isset($params['auto_upgrade']) || !empty($params['auto_upgrade']);
            $result = \WebCareProScanner\System\AIService::check_and_update_models($auto_upgrade);
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $result['settings'] = $settings;
            return rest_ensure_response($result);
        } catch (\Exception $e) {
            return new \WP_Error('ai_models_update_error', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Safely repair an infected core file by pulling the pristine version from WP.org.
     */
    public static function repair_core_file(\WP_REST_Request $request) {
        $file_path = sanitize_text_field($request->get_param('file_path'));
        $issue_id = (int) $request->get_param('issue_id');

        if (empty($file_path)) {
            return new \WP_Error('missing_params', 'File path is required.', ['status' => 400]);
        }

        $repair_manager = new CoreRepairManager();
        $result = $repair_manager->repair_core_file($file_path);

        if ($result['success'] && $issue_id) {
            global $wpdb;
            $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response($result);
    }

    public static function get_firewall_status() {
        return rest_ensure_response(\WebCareProScanner\Firewall\FirewallEngine::get_status());
    }

    public static function get_firewall_logs(\WP_REST_Request $request) {
        $limit       = (int) ($request->get_param('limit') ?: 50);
        $offset      = (int) ($request->get_param('offset') ?: 0);
        $range       = sanitize_key((string) ($request->get_param('range') ?: 'today'));
        $date        = sanitize_text_field((string) ($request->get_param('date') ?: ''));
        $search      = sanitize_text_field((string) ($request->get_param('search') ?: ''));
        $category    = sanitize_text_field((string) ($request->get_param('category') ?: ''));
        $action      = sanitize_text_field((string) ($request->get_param('action') ?: ''));
        $method      = sanitize_text_field((string) ($request->get_param('method') ?: ''));
        $ip          = sanitize_text_field((string) ($request->get_param('ip') ?: ''));
        $status_code = sanitize_text_field((string) ($request->get_param('status_code') ?: ''));
        $sort_by     = sanitize_key((string) ($request->get_param('sort_by') ?: 'created_at'));
        $sort_order  = strtolower(sanitize_key((string) ($request->get_param('sort_order') ?: 'desc')));
        $is_export   = !empty($request->get_param('is_export'));
        $include_system_info = !empty($request->get_param('include_system_info'));

        $filters = array_filter([
            'range'       => $range,
            'date'        => $date,
            'search'      => $search,
            'category'    => $category,
            'action'      => $action,
            'method'      => $method,
            'ip'          => $ip,
            'status_code' => $status_code,
            'sort_by'     => $sort_by,
            'sort_order'  => $sort_order,
            'is_export'   => $is_export,
        ]);

        $res = \WebCareProScanner\Firewall\FirewallEngine::get_logs($limit, $offset, $filters);
        $res['current_client_ip'] = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        $res['retention_days']    = \WebCareProScanner\Firewall\WafFileLogger::get_retention_days();
        $res['active_range']      = $range;

        if ($include_system_info && class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')) {
            $res['environment_snapshot'] = \WebCareProScanner\System\TelemetrySnapshot::get_snapshot();
        }

        return rest_ensure_response($res);
    }

    public static function get_firewall_log_stats(\WP_REST_Request $request) {
        $range = sanitize_key((string) ($request->get_param('range') ?: 'today'));
        return rest_ensure_response([
            'stats'          => \WebCareProScanner\Firewall\FirewallEngine::get_log_stats($range),
            'retention_days' => \WebCareProScanner\Firewall\WafFileLogger::get_retention_days(),
        ]);
    }

    public static function get_firewall_log_files() {
        return rest_ensure_response([
            'files'          => \WebCareProScanner\Firewall\WafFileLogger::get_available_files(),
            'storage_dir'    => \WebCareProScanner\Firewall\WafFileLogger::get_storage_dir(),
            'retention_days' => \WebCareProScanner\Firewall\WafFileLogger::get_retention_days(),
        ]);
    }

    public static function update_firewall_log_retention(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $days   = (int) ($params['retention_days'] ?? 30);
        $saved  = \WebCareProScanner\Firewall\WafFileLogger::set_retention_days($days);
        return rest_ensure_response([
            'success'        => $saved,
            'retention_days' => \WebCareProScanner\Firewall\WafFileLogger::get_retention_days(),
            'message'        => $saved ? __('WAF log retention period updated.', 'webcare-pro-security') : __('Failed to update retention period.', 'webcare-pro-security'),
        ]);
    }

    public static function prune_firewall_logs() {
        $pruned = \WebCareProScanner\Firewall\WafFileLogger::prune_expired_logs();
        return rest_ensure_response([
            'success'      => true,
            'pruned_count' => $pruned,
            'message'      => sprintf(
                /* translators: %d: number of pruned daily log files */
                _n('%d expired daily WAF log file pruned.', '%d expired daily WAF log files pruned.', $pruned, 'webcare-pro-security'),
                $pruned
            ),
        ]);
    }

    public static function download_firewall_log_file(\WP_REST_Request $request) {
        $filename = sanitize_file_name((string) $request->get_param('filename'));
        if (empty($filename) || !preg_match('/-waf-logs\.json$/', $filename)) {
            return new \WP_Error('invalid_file', 'Valid daily WAF log filename is required.', ['status' => 400]);
        }

        $dir      = \WebCareProScanner\Firewall\WafFileLogger::get_storage_dir();
        $filepath = $dir . '/' . $filename;
        if (!file_exists($filepath) || !is_readable($filepath)) {
            return new \WP_Error('not_found', 'Log file does not exist on disk.', ['status' => 404]);
        }

        $lines = @file($filepath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $records = [];
        if (is_array($lines)) {
            foreach ($lines as $line) {
                $decoded = json_decode($line, true);
                if (is_array($decoded)) {
                    $records[] = $decoded;
                }
            }
        }

        return rest_ensure_response([
            'filename' => $filename,
            'count'    => count($records),
            'records'  => $records,
        ]);
    }

    public static function delete_firewall_log(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $id = sanitize_text_field(trim((string) ($params['id'] ?? '')));
        if (empty($id)) {
            return new \WP_Error('invalid_id', 'Valid log ID is required', ['status' => 400]);
        }
        $deleted = \WebCareProScanner\Firewall\FirewallEngine::delete_log($id);
        return rest_ensure_response([
            'success' => $deleted,
            'message' => $deleted ? 'Log entry deleted successfully.' : 'Failed to delete log entry.',
        ]);
    }

    public static function add_firewall_blocked_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }

        $current_client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        if ($ip === $current_client_ip && \WebCareProScanner\Firewall\FirewallEngine::is_authenticated_administrator()) {
            return new \WP_Error(
                'self_ban_prohibited',
                /* translators: %s: current IP address */
                sprintf(__('Safety Guard: IP %s is your active administrator connection. You cannot block your own IP to prevent site lockout.', 'webcare-pro-security'), $ip),
                ['status' => 400]
            );
        }

        $reason = isset($params['reason']) ? sanitize_text_field(trim($params['reason'])) : '';
        $duration_seconds = isset($params['duration_seconds']) ? max(0, (int) $params['duration_seconds']) : 0;
        $current_user = wp_get_current_user();
        $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';

        $added = \WebCareProScanner\Firewall\FirewallEngine::add_blocked_ip(
            $ip,
            !empty($reason) ? $reason : sprintf('Blocked manually by administrator "%s"', $user_login),
            $duration_seconds,
            null,
            'Custom Administrator Block',
            'Manual Blocklist',
            null,
            $user_login
        );

        if ($added && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_blocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s manually added to WAF blocklist by %s from IP %s (Reason: %s).', $ip, $user_login, $client_ip, $reason ?: 'Administrator policy'),
                ]
            );
        }

        return rest_ensure_response([
            'success' => $added,
            'message' => $added ? sprintf('IP %s added to custom WAF blocklist.', $ip) : 'Failed to add IP.',
            'locked_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips(),
        ]);
    }

    public static function unblock_firewall_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }

        $unblocked = \WebCareProScanner\Firewall\FirewallEngine::remove_blocked_ip($ip);
        if ($unblocked && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_unblocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s unblocked from firewall by %s from IP %s.', $ip, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response([
            'success' => $unblocked,
            /* translators: %s: unblocked IP address */
            'message' => sprintf(__('IP %s has been unblocked. Standard WAF protection remains active.', 'webcare-pro-security'), $ip),
            'locked_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips(),
        ]);
    }

    /**
     * Customer Lockout Finder: Look up blocked customer by 6-digit Support Code (#WEBCARE-XXXX) or IP address
     */
    public static function lookup_customer_lockout(\WP_REST_Request $request) {
        $query = strtoupper(trim($request->get_param('code') ?? ''));
        if (empty($query)) {
            return new \WP_Error('missing_code', __('Support Code or IP address is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Clean code formatting: allow #WEBCARE-492A, WEBCARE-492A, or 492A
        $clean_code = ltrim($query, '#');
        if (!str_starts_with($clean_code, 'WEBCARE-') && strlen($clean_code) === 4) {
            $clean_code = 'WEBCARE-' . $clean_code;
        }

        // 1. Try finding by support reference code
        $data = get_transient('webcareproscan_lockout_' . $clean_code);

        // 2. Fallback: Try finding by IP address if user entered an IP
        if (!$data && filter_var($query, FILTER_VALIDATE_IP)) {
            $data = get_transient('webcareproscan_lockout_ip_' . md5($query));
        }

        // 3. Fallback: Search recent filesystem logs if transient expired
        if (!$data && class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $file_query = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
                'search' => $query,
                'action' => 'blocked',
            ], 1);
            if (!empty($file_query['logs'][0])) {
                $top = $file_query['logs'][0];
                $data = [
                    'ref_code'       => $query,
                    'incident_id'    => $top['incident_id'] ?? 'WEBCARE-LOG',
                    'client_ip'      => $top['ip_address'] ?? '',
                    'rule_id'        => $top['rule_id'] ?? 'WAF-BLOCK',
                    'rule_name'      => $top['rule_name'] ?? ($top['rule_category'] ?? 'Security Shield'),
                    'rule_category'  => $top['rule_category'] ?? 'Security Shield',
                    'description'    => $top['rule_description'] ?? 'Automated defense rule triggered.',
                    'request_uri'    => $top['request_uri'] ?? '/',
                    'timestamp'      => strtotime($top['timestamp'] ?? 'now'),
                    'formatted_time' => $top['timestamp'] ?? gmdate('Y-m-d H:i:s \U\T\C'),
                ];
            }
        }

        // 4. Fallback: Search SQL firewall_logs table by incident_id or IP
        if (!$data) {
            global $wpdb;
            $fw_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $fw_table)) === $fw_table) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $sql_row = $wpdb->get_row(
                    $wpdb->prepare(
                        'SELECT incident_id, ip_address, rule_category, rule_description, request_uri, created_at FROM %i WHERE incident_id = %s OR ip_address = %s ORDER BY id DESC LIMIT 1',
                        $fw_table,
                        $clean_code,
                        $query
                    ),
                    ARRAY_A
                );
                if (is_array($sql_row) && !empty($sql_row['ip_address'])) {
                    $data = [
                        'ref_code'       => $clean_code,
                        'incident_id'    => $sql_row['incident_id'],
                        'client_ip'      => $sql_row['ip_address'],
                        'rule_category'  => $sql_row['rule_category'] ?? 'Security Shield',
                        'description'    => $sql_row['rule_description'] ?? '',
                        'request_uri'    => $sql_row['request_uri'] ?? '/',
                        'timestamp'      => strtotime((string) ($sql_row['created_at'] ?? 'now')),
                        'formatted_time' => $sql_row['created_at'] ?? gmdate('Y-m-d H:i:s'),
                    ];
                }
            }
        }

        if (!$data) {
            return rest_ensure_response([
                'found'   => false,
                'message' => __('No active lockout record found for this Support Reference Code or IP. The visitor may already be unblocked or the block event expired.', 'webcare-pro-security'),
            ]);
        }

        // Translate reason into customer-friendly plain English
        $friendly_reason = __('Security shield temporarily held the request due to suspicious request signatures.', 'webcare-pro-security');
        $cat = strtolower($data['rule_category'] ?? '');
        $desc = strtolower($data['description'] ?? '');

        if (strpos($cat, 'coupon') !== false || strpos($desc, 'coupon') !== false) {
            $friendly_reason = __('Customer was temporarily held because invalid discount coupon codes were attempted multiple times in a short window.', 'webcare-pro-security');
        } elseif (strpos($cat, 'checkout') !== false || strpos($desc, 'checkout') !== false) {
            $friendly_reason = __('Customer was rate-limited during checkout due to rapid order submissions or repeated card payment verification attempts.', 'webcare-pro-security');
        } elseif (strpos($cat, 'login') !== false || strpos($desc, 'login') !== false) {
            $friendly_reason = __('Customer was held because an account password was entered incorrectly multiple times.', 'webcare-pro-security');
        } elseif (strpos($cat, 'rate') !== false || strpos($desc, 'rate') !== false) {
            $friendly_reason = __('Customer refreshed or requested store pages faster than normal browsing velocity.', 'webcare-pro-security');
        }

        return rest_ensure_response([
            'found'           => true,
            'lockout'         => $data,
            'friendly_reason' => $friendly_reason,
            'client_ip'       => $data['client_ip'],
            'ref_code'        => $data['ref_code'],
            'formatted_time'  => $data['formatted_time'],
        ]);
    }

    /**
     * Unblock customer in 1 click and grant temporary 24-hour bypass immunity
     */
    public static function unblock_customer_lockout(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        $code = sanitize_text_field(trim($params['code'] ?? ''));

        if (empty($ip) && !empty($code)) {
            $clean_code = ltrim($code, '#');
            if (!str_starts_with($clean_code, 'WEBCARE-') && strlen($clean_code) === 4) {
                $clean_code = 'WEBCARE-' . $clean_code;
            }
            $t = get_transient('webcareproscan_lockout_' . $clean_code);
            if (!empty($t['client_ip'])) {
                $ip = $t['client_ip'];
            } elseif (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
                $fq = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['search' => $clean_code, 'action' => 'blocked'], 1);
                if (!empty($fq['logs'][0]['ip_address'])) {
                    $ip = (string) $fq['logs'][0]['ip_address'];
                }
            }
            if (empty($ip)) {
                global $wpdb;
                $fw_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $fw_table)) === $fw_table) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $ip_hit = $wpdb->get_var(
                        $wpdb->prepare('SELECT ip_address FROM %i WHERE incident_id = %s ORDER BY id DESC LIMIT 1', $fw_table, $clean_code)
                    );
                    if (is_string($ip_hit) && $ip_hit !== '') {
                        $ip = $ip_hit;
                    }
                }
            }
        }

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_Error('invalid_ip', __('Valid client IP is required to unblock.', 'webcare-pro-security'), ['status' => 400]);
        }

        // 1. Remove all active rate limiters and blocklists
        \WebCareProScanner\Firewall\FirewallEngine::remove_blocked_ip($ip);

        // 2. Grant temporary 24-hour bypass allowlist
        set_transient('webcareproscan_temp_allow_' . md5($ip), 1, 24 * HOUR_IN_SECONDS);

        // 3. Log audit event
        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'customer_lockout_unblocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'code'        => $code,
                    'unblocked_by'=> $user_login,
                    'duration'    => '24 hours',
                    'description' => sprintf('Customer IP %s was unblocked and granted 24-hour store access by %s.', $ip, $user_login),
                ]
            );
        }

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: customer IP address */
            'message' => sprintf(__('Customer IP %s has been successfully unblocked and granted 24-hour checkout access.', 'webcare-pro-security'), $ip),
            'client_ip' => $ip,
        ]);
    }

    public static function get_firewall_blocklist(\WP_REST_Request $request) {
        $locked_ips = \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        return rest_ensure_response([
            'success'          => true,
            'locked_ips'       => $locked_ips,
            'total_locked'     => count($locked_ips),
            'waf_blocked_ips'  => $settings['waf_blocked_ips'] ?? '',
        ]);
    }

    public static function add_firewall_whitelisted_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        $reason = sanitize_text_field(trim($params['reason'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address or CIDR range is required', ['status' => 400]);
        }

        $current_user = wp_get_current_user();
        $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';

        $scope_args = [
            'scope'         => sanitize_key($params['scope'] ?? 'global'),
            'allowed_rules' => !empty($params['allowed_rules']) && is_array($params['allowed_rules']) ? $params['allowed_rules'] : [],
            'allowed_cats'  => !empty($params['allowed_cats']) && is_array($params['allowed_cats']) ? $params['allowed_cats'] : [],
            'endpoint'      => sanitize_text_field($params['endpoint'] ?? ''),
            'expires_in'    => isset($params['expires_in']) ? intval($params['expires_in']) : 0,
        ];

        $added = \WebCareProScanner\Firewall\FirewallEngine::add_whitelisted_ip($ip, $reason, $user_login, $scope_args);
        if ($added && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $scope_desc = $scope_args['scope'] === 'rule' 
                ? sprintf('Rule: %s', implode(', ', $scope_args['allowed_rules'])) 
                : ($scope_args['scope'] === 'category' ? sprintf('Category: %s', implode(', ', $scope_args['allowed_cats'])) : 'Global Bypass');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_whitelisted',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s allowlisted (%s) by %s from IP %s (Reason: %s).', $ip, $scope_desc, $user_login, $client_ip, $reason ?: 'Administrator policy'),
                ]
            );
        }

        $success_msg = sprintf('IP %s added to allowlist.', $ip);
        if ($scope_args['scope'] === 'rule' && !empty($scope_args['allowed_rules'])) {
            $success_msg = sprintf('IP %s successfully allowed strictly for rule %s.', $ip, implode(', ', $scope_args['allowed_rules']));
        } elseif ($scope_args['scope'] === 'category' && !empty($scope_args['allowed_cats'])) {
            $success_msg = sprintf('IP %s successfully allowed for category %s.', $ip, implode(', ', $scope_args['allowed_cats']));
        }

        return rest_ensure_response([
            'success'         => $added,
            'message'         => $added ? $success_msg : 'Failed to whitelist IP.',
            'whitelisted_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_whitelisted_ips(),
        ]);
    }

    public static function remove_firewall_whitelisted_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }

        $removed = \WebCareProScanner\Firewall\FirewallEngine::remove_whitelisted_ip($ip);
        if ($removed && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_whitelist_removed',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s removed from trusted WAF allowlist by %s from IP %s.', $ip, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response([
            'success' => $removed,
            'message' => sprintf('IP %s removed from trusted WAF allowlist.', $ip),
            'whitelisted_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_whitelisted_ips(),
        ]);
    }

    public static function get_firewall_whitelist(\WP_REST_Request $request) {
        $whitelisted_ips = \WebCareProScanner\Firewall\FirewallEngine::get_all_whitelisted_ips();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $rules_catalog = \WebCareProScanner\Firewall\FirewallEngine::get_firewall_rules_catalog();
        return rest_ensure_response([
            'success'             => true,
            'whitelisted_ips'     => $whitelisted_ips,
            'total_whitelisted'   => count($whitelisted_ips),
            'waf_whitelisted_ips' => $settings['waf_whitelisted_ips'] ?? '',
            'rules_catalog'       => $rules_catalog,
        ]);
    }

    public static function clear_firewall_logs() {
        $cleared = \WebCareProScanner\Firewall\FirewallEngine::clear_logs();
        if ($cleared && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_logs_cleared',
                'firewall',
                [
                    'description' => sprintf('Firewall incident logs purged by %s from IP %s.', $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response([
            'success' => $cleared,
            'message' => 'Firewall incident logs cleared successfully.',
        ]);
    }

    public static function toggle_firewall(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enabled = !empty($params['enabled']);
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $settings['waf_enabled'] = $enabled;
        if ($enabled && ($settings['waf_mode'] ?? '') === 'disabled') {
            $settings['waf_mode'] = 'enabled';
        } elseif (!$enabled) {
            $settings['waf_mode'] = 'disabled';
        }
        \WebCareProScanner\System\SettingsManager::save_settings($settings);

        return rest_ensure_response([
            'success' => true,
            'enabled' => $enabled,
            'status'  => \WebCareProScanner\Firewall\FirewallEngine::get_status(),
        ]);
    }

    /**
     * Save an individual firewall rule or setting immediately
     */
    public static function save_single_firewall_rule(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $key = sanitize_key($params['key'] ?? '');
        if (empty($key)) {
            return new \WP_Error('invalid_key', 'Setting key is required.', ['status' => 400]);
        }

        $val = $params['value'] ?? null;
        $saved = \WebCareProScanner\System\SettingsManager::save_settings([$key => $val]);
        return rest_ensure_response([
            'success'  => true,
            'message'  => sprintf('Rule "%s" successfully saved.', $key),
            'key'      => $key,
            'value'    => $saved[$key] ?? $val,
            'settings' => $saved,
        ]);
    }

    /**
     * Get available WordPress user roles for firewall role-enforcement rules
     */
    public static function get_firewall_roles() {
        return rest_ensure_response([
            'success' => true,
            'roles'   => \WebCareProScanner\Firewall\FirewallEngine::get_available_roles(),
        ]);
    }

    public static function get_server_security_config() {
        if (!class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $options = \WebCareProScanner\Firewall\ServerSecurityEngine::get_options();
        $file_info = \WebCareProScanner\Firewall\ServerSecurityEngine::get_file_info();
        $nginx_content = \WebCareProScanner\Firewall\ServerSecurityEngine::generate_nginx_config($options);
        $apache_content = \WebCareProScanner\Firewall\ServerSecurityEngine::generate_apache_config($options);

        return rest_ensure_response([
            'options'        => $options,
            'file_info'      => $file_info,
            'nginx_content'  => $nginx_content,
            'apache_content' => $apache_content,
        ]);
    }

    public static function save_server_security_config(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $params = $request->get_json_params() ?: [];
        $server_type = !empty($params['server_type']) ? sanitize_key($params['server_type']) : 'nginx';
        $options = !empty($params['options']) && is_array($params['options']) ? $params['options'] : [];

        $result = \WebCareProScanner\Firewall\ServerSecurityEngine::save_config_file($server_type, $options);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'server_security_saved',
                'firewall',
                [
                    'server_type' => $server_type,
                    'description' => sprintf('Web server armor configuration for %s updated by %s from IP %s.', strtoupper($server_type), $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function deploy_server_security_htaccess(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $params = $request->get_json_params() ?: [];
        $options = !empty($params['options']) && is_array($params['options']) ? $params['options'] : [];

        $result = \WebCareProScanner\Firewall\ServerSecurityEngine::deploy_to_htaccess($options);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'server_security_htaccess_deployed',
                'firewall',
                [
                    'description' => sprintf('Web server armor rules deployed directly to root .htaccess by %s from IP %s.', $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function get_redirect_shield_status() {
        $htaccess_path = ABSPATH . '.htaccess';
        $htaccess_exists = file_exists($htaccess_path);
        $htaccess_content = $htaccess_exists ? (@file_get_contents($htaccess_path) ?: '') : '';
        $htaccess_writable = $htaccess_exists ? wp_is_writable($htaccess_path) : wp_is_writable(ABSPATH);

        $analysis = class_exists('\\WebCareProScanner\\Firewall\\HtaccessShield')
            ? \WebCareProScanner\Firewall\HtaccessShield::analyze_htaccess_content($htaccess_content)
            : ['score' => 0, 'hostile_count' => 0, 'findings' => [], 'summary' => ''];

        $snapshots = class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')
            ? \WebCareProScanner\Firewall\HtaccessVaultManager::list_snapshots()
            : [];

        $canary_state = get_option(\WebCareProScanner\Firewall\RedirectCanaryEngine::STATE_OPTION, []);

        $db_urls = class_exists('\\WebCareProScanner\\Firewall\\RedirectCanaryEngine')
            ? \WebCareProScanner\Firewall\RedirectCanaryEngine::verify_database_core_urls()
            : ['clean' => true, 'siteurl' => get_option('siteurl'), 'home' => get_option('home')];

        $auto_heal = (bool) \WebCareProScanner\System\SettingsManager::get('htaccess_auto_heal_enabled', false);
        $next_canary = wp_next_scheduled('webcareproscan_redirect_canary_event');

        return rest_ensure_response([
            'success'             => true,
            'is_htaccess_active'  => $htaccess_exists,
            'is_read_only_locked' => !$htaccess_writable,
            'auto_heal_enabled'   => $auto_heal,
            'file_size'           => strlen($htaccess_content),
            'mtime'               => $htaccess_exists ? (int) @filemtime($htaccess_path) : 0,
            'mtime_human'         => $htaccess_exists ? human_time_diff((int) @filemtime($htaccess_path), time()) . ' ago' : 'N/A',
            'analysis'            => $analysis,
            'snapshots'           => $snapshots,
            'canary_state'        => $canary_state,
            'database_urls'       => $db_urls,
            'server_software'     => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
            'next_canary_ts'      => $next_canary ?: 0,
            'next_canary_human'   => $next_canary ? human_time_diff(time(), $next_canary) . ' from now' : 'Not scheduled',
        ]);
    }

    public static function run_redirect_canary_probe() {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RedirectCanaryEngine')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('RedirectCanaryEngine not loaded.', 'webcare-pro-security'),
            ]);
        }

        $report = \WebCareProScanner\Firewall\RedirectCanaryEngine::execute_probes();
        $auto_heal_res = \WebCareProScanner\Firewall\RedirectCanaryEngine::evaluate_and_auto_heal($report);

        return rest_ensure_response([
            'success'   => true,
            'report'    => $report,
            'auto_heal' => $auto_heal_res,
        ]);
    }

    public static function restore_htaccess_vault_snapshot(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('HtaccessVaultManager not loaded.', 'webcare-pro-security'),
            ]);
        }

        $params = $request->get_json_params() ?: [];
        $version = isset($params['version']) ? max(1, min(5, (int) $params['version'])) : 1;

        $res = \WebCareProScanner\Firewall\HtaccessVaultManager::restore_snapshot($version);
        return rest_ensure_response($res);
    }

    public static function toggle_htaccess_lock(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('HtaccessVaultManager not loaded.', 'webcare-pro-security'),
            ]);
        }

        $params = $request->get_json_params() ?: [];
        $locked = !empty($params['locked']);

        $res = \WebCareProScanner\Firewall\HtaccessVaultManager::set_readonly_lock($locked);

        if (isset($params['auto_heal'])) {
            \WebCareProScanner\System\SettingsManager::set('htaccess_auto_heal_enabled', !empty($params['auto_heal']));
        }

        return rest_ensure_response([
            'success'   => $res,
            'is_locked' => $locked,
            'auto_heal' => (bool) \WebCareProScanner\System\SettingsManager::get('htaccess_auto_heal_enabled', false),
            'message'   => $locked
                ? __('Root .htaccess locked to read-only (0444). Direct modification by processes is disabled.', 'webcare-pro-security')
                : __('Root .htaccess unlocked (0644). Caching and SEO plugins can write configuration updates.', 'webcare-pro-security'),
        ]);
    }

    public static function heal_database_core_urls() {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RedirectCanaryEngine')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('RedirectCanaryEngine not loaded.', 'webcare-pro-security'),
            ]);
        }

        $res = \WebCareProScanner\Firewall\RedirectCanaryEngine::restore_database_core_urls();
        return rest_ensure_response($res);
    }

    public static function create_htaccess_vault_snapshot() {
        if (!class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('HtaccessVaultManager not loaded.', 'webcare-pro-security'),
            ]);
        }

        $res = \WebCareProScanner\Firewall\HtaccessVaultManager::snapshot_current_if_clean('manual_admin_cockpit');
        return rest_ensure_response($res);
    }

    public static function get_micro_waf_status(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $status = \WebCareProScanner\Firewall\MicroWafCompiler::get_status();
        return rest_ensure_response($status);
    }

    public static function compile_micro_waf(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $result = \WebCareProScanner\Firewall\MicroWafCompiler::compile();
        return rest_ensure_response($result);
    }

    public static function install_micro_waf_preload(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $result = \WebCareProScanner\Firewall\MicroWafCompiler::install_preload();
        return rest_ensure_response($result);
    }

    public static function uninstall_micro_waf_preload(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $result = \WebCareProScanner\Firewall\MicroWafCompiler::uninstall_preload();
        return rest_ensure_response($result);
    }

    public static function get_integrity_recent_changes(\WP_REST_Request $request) {
        $hours = (int) ($request->get_param('hours') ?: 48);
        $category = sanitize_key($request->get_param('category') ?: 'all');
        $limit = (int) ($request->get_param('limit') ?: 150);

        $fim = new \WebCareProScanner\Integrity\FileIntegrityMonitor();
        $data = $fim->get_recent_changes($hours, $category, $limit);

        return rest_ensure_response($data);
    }

    public static function get_integrity_vault_status(\WP_REST_Request $request) {
        $status = \WebCareProScanner\Integrity\FimVaultManager::get_vault_status();
        return rest_ensure_response($status);
    }

    public static function calibrate_integrity_vault(\WP_REST_Request $request) {
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(300);
        }
        if (function_exists('ini_set')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @ini_set('memory_limit', '512M');
        }
        try {
            $result = \WebCareProScanner\Integrity\FimDriftDetector::calibrate_all();

            if (!empty($result['success']) && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('fim_baseline_refreshed', [
                    'severity' => 'info',
                    /* translators: %d: count of files indexed */
                    'message'  => sprintf(__('FIM Integrity Baseline snapshot refreshed (%d files indexed across all scopes).', 'webcare-pro-security'), (int) ($result['total_files'] ?? 0)),
                    'details'  => [
                        'Indexed Files'   => number_format((int) ($result['total_files'] ?? 0)),
                        'Duration'        => ($result['duration_sec'] ?? 0) . 's',
                        'Calibrated At'   => current_time('mysql'),
                    ],
                ]);
            }

            return rest_ensure_response($result);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WEBCARE-FIM] Calibration Fatal Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
            return new \WP_Error(
                'fim_calibration_failed',
                'FIM Vault Calibration Failed: ' . $e->getMessage(),
                ['status' => 500]
            );
        }
    }

    public static function recheck_integrity_drift(\WP_REST_Request $request) {
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(180);
        }
        if (function_exists('ini_set')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @ini_set('memory_limit', '512M');
        }
        try {
            $category = sanitize_key($request->get_param('category') ?: 'all');
            $limit = (int) ($request->get_param('limit') ?: 250);

            $result = \WebCareProScanner\Integrity\FimDriftDetector::audit_drift($category, $limit);
            return rest_ensure_response($result);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WEBCARE-FIM] Drift Audit Fatal Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
            return new \WP_Error(
                'fim_drift_audit_failed',
                'FIM Drift Audit Failed: ' . $e->getMessage(),
                ['status' => 500]
            );
        }
    }

    public static function get_integrity_file_diff(\WP_REST_Request $request) {
        $uid = get_current_user_id();
        if ($uid) {
            $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
            if (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid]))) {
                $cfg = $support_users[$uid] ?? [];
                $scope = $cfg['scope'] ?? 'read_only';
                if ($scope === 'quarantine_only') {
                    return new \WP_Error('jit_access_denied', __('Temporary support sessions with quarantine-only scope cannot inspect source diffs.', 'webcare-pro-security'), ['status' => 403]);
                }
            }
        }

        $file_path = $request->get_param('file_path') ?: $request->get_param('path');
        if (empty($file_path)) {
            $json_params = $request->get_json_params();
            if (!empty($json_params['file_path'])) {
                $file_path = $json_params['file_path'];
            } elseif (!empty($json_params['path'])) {
                $file_path = $json_params['path'];
            }
        }

        if (empty($file_path)) {
            return new \WP_Error('missing_file_path', __('Missing required file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $file_path = sanitize_text_field(wp_unslash($file_path));

        // Support base64 encoded path to avoid WAF false positives on sensitive filenames in URL
        if (strpos($file_path, 'b64:') === 0) {
            $decoded = base64_decode(substr($file_path, 4), true);
            if ($decoded !== false && is_string($decoded)) {
                $file_path = $decoded;
            }
        } elseif (preg_match('/^[a-zA-Z0-9+\/]+=*$/', $file_path) && strlen($file_path) >= 8) {
            $decoded = base64_decode($file_path, true);
            if ($decoded !== false && is_string($decoded) && (strpos($decoded, '/') !== false || strpos($decoded, '\\') !== false || strpos($decoded, '.php') !== false)) {
                $file_path = $decoded;
            }
        }

        $fim = new \WebCareProScanner\Integrity\FileIntegrityMonitor();
        $diff_data = $fim->get_file_diff($file_path);

        return rest_ensure_response($diff_data);
    }

    public static function remediate_strip_webshell(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->strip_malware_injection($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_plugin(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_plugin_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_theme(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_theme_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_core(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_core_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_fix_permissions(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;
        $target_perm = !empty($params['target_perm']) ? sanitize_text_field(wp_unslash($params['target_perm'])) : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->fix_permissions($file_path, $target_perm, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_delete_file(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->delete_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_disable_wp_debug(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->disable_wp_debug($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function permissions_audit(\WP_REST_Request $request) {
        $manager = new \WebCareProScanner\Hardening\PermissionHardeningManager();
        $result = $manager->audit();
        return rest_ensure_response($result);
    }

    public static function permissions_fix_all(\WP_REST_Request $request) {
        $manager = new \WebCareProScanner\Hardening\PermissionHardeningManager();
        $result = $manager->fix_all();
        return rest_ensure_response($result);
    }

    public static function persistence_audit(\WP_REST_Request $request) {
        $scanner = new \WebCareProScanner\WordPress\PersistenceScanner();
        $result = $scanner->audit_full();
        return rest_ensure_response($result);
    }

    public static function persistence_neutralize(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $type = sanitize_key($params['type'] ?? '');
        $id = sanitize_text_field(wp_unslash($params['id'] ?? ''));
        $bulk = !empty($params['bulk']);

        $scanner = new \WebCareProScanner\WordPress\PersistenceScanner();

        if ($bulk) {
            $result = $scanner->neutralize_all();
            return rest_ensure_response($result);
        }

        if (empty($type) || empty($id)) {
            return new \WP_Error('missing_params', __('Type and identifier are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = $scanner->neutralize_item($type, $id);
        if (!$result['success']) {
            return new \WP_Error('neutralize_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function attack_chain_audit(\WP_REST_Request $request) {
        $engine = new \WebCareProScanner\Forensics\AttackChainEngine();
        $result = $engine->audit_attack_chains();
        return rest_ensure_response($result);
    }

    public static function attack_chain_eradicate(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $chain_id = sanitize_text_field(wp_unslash($params['chain_id'] ?? ''));
        $plan = is_array($params['plan'] ?? null) ? $params['plan'] : [];

        if (empty($chain_id)) {
            return new \WP_Error('missing_chain_id', __('Chain ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $engine = new \WebCareProScanner\Forensics\AttackChainEngine();
        $result = $engine->eradicate_chain($chain_id, $plan);
        return rest_ensure_response($result);
    }

    public static function virtual_patch_list(\WP_REST_Request $request) {
        $catalog = \WebCareProScanner\Firewall\VirtualPatchManager::get_patch_catalog();
        $active = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $cf_ready = !empty($settings['cloudflare_api_token']) && !empty($settings['cloudflare_zone_id']);

        return rest_ensure_response([
            'success'           => true,
            'catalog'           => array_values($catalog),
            'active_patches'    => array_values($active),
            'cloudflare_ready'  => $cf_ready,
        ]);
    }

    public static function virtual_patch_apply(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field(wp_unslash($params['patch_id'] ?? ''));
        $custom_config = is_array($params['custom_config'] ?? null) ? $params['custom_config'] : [];

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch($patch_id, $custom_config);
        if (!$result['success']) {
            return new \WP_Error('patch_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function virtual_patch_remove(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field(wp_unslash($params['patch_id'] ?? ''));

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch($patch_id);
        if (!$result['success']) {
            return new \WP_Error('remove_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function get_incident_report(\WP_REST_Request $request) {
        $format = sanitize_text_field($request->get_param('format') ?: 'json');
        $client_name = sanitize_text_field($request->get_param('client_name') ?: '');
        $auditor_notes = sanitize_textarea_field($request->get_param('auditor_notes') ?: '');

        $options = [
            'client_name'   => $client_name,
            'auditor_notes' => $auditor_notes,
        ];

        $report = IncidentReportEngine::generate_report($options);

        if ($format === 'html') {
            $html = IncidentReportEngine::render_html($report);
            header('Content-Type: text/html; charset=UTF-8');
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo $html;
            exit;
        }

        return rest_ensure_response($report);
    }

    public static function get_remediation_backups() {
        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        return rest_ensure_response([
            'backups' => $manager->get_backups(),
        ]);
    }

    public static function rollback_remediation(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field(wp_unslash($params['backup_id'])) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_param', __('Missing backup_id parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->rollback_remediation($backup_id);

        return rest_ensure_response($result);
    }

    public static function remediate_delete_cron_hook(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $hook_name = !empty($params['hook_name']) ? sanitize_text_field(wp_unslash($params['hook_name'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($hook_name) && !empty($params['file_path'])) {
            $path = sanitize_text_field(wp_unslash($params['file_path']));
            if (strpos($path, 'cron:hook:') === 0) {
                $hook_name = substr($path, strlen('cron:hook:'));
            } else {
                $hook_name = $path;
            }
        }

        if (empty($hook_name)) {
            return new \WP_Error('missing_param', __('Missing hook_name parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Safety check: protect essential WordPress core cron hooks from being cleared
        $protected_core_crons = [
            'wp_version_check',
            'wp_update_plugins',
            'wp_update_themes',
            'recovery_mode_clean_expired_keys',
            'wp_scheduled_delete',
            'delete_expired_transients',
            'wp_privacy_delete_old_export_files',
        ];

        if (in_array($hook_name, $protected_core_crons, true)) {
            return new \WP_Error('protected_core_hook', __('Cannot delete essential WordPress core system cron hooks.', 'webcare-pro-security'), ['status' => 403]);
        }

        // Clear all scheduled instances of this cron hook
        $cleared = wp_clear_scheduled_hook($hook_name);

        if ($issue_id) {
            global $wpdb;
            $table = $wpdb->prefix . 'webcareproscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: cron hook name */
            'message' => sprintf(__('Scheduled cron hook "%s" was successfully removed from the WordPress database.', 'webcare-pro-security'), $hook_name),
            'cleared' => $cleared,
            'hook'    => $hook_name,
        ]);
    }

    /**
     * Moderate or delete a spam/malicious WordPress comment.
     */
    public static function moderate_comment(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $comment_id = !empty($params['comment_id']) ? (int) $params['comment_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (!$comment_id) {
            return new \WP_Error('missing_comment_id', __('Valid comment ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $comment = get_comment($comment_id);
        if (!$comment && $action !== 'delete') {
            return new \WP_Error('comment_not_found', __('Comment not found or already deleted.', 'webcare-pro-security'), ['status' => 404]);
        }

        $success = false;
        $message = '';

        switch ($action) {
            case 'trash':
                $success = (bool) wp_trash_comment($comment_id);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been moved to Trash (quarantined from public view).', 'webcare-pro-security'), $comment_id);
                break;

            case 'spam':
                $success = (bool) wp_spam_comment($comment_id);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been marked as Spam and delisted.', 'webcare-pro-security'), $comment_id);
                break;

            case 'delete':
                $success = (bool) wp_delete_comment($comment_id, true);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been permanently deleted from the database.', 'webcare-pro-security'), $comment_id);
                break;

            case 'approve':
                $success = (bool) wp_set_comment_status($comment_id, 'approve');
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d status updated to approved.', 'webcare-pro-security'), $comment_id);
                break;

            default:
                return new \WP_Error('invalid_action', __('Invalid moderation action. Supported: trash, spam, delete.', 'webcare-pro-security'), ['status' => 400]);
        }

        if ($success) {
            global $wpdb;
            $table = $wpdb->prefix . 'webcareproscan_scan_issues';
            if ($issue_id) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
            }
            // Mark all open findings associated with this comment as solved/repaired
            $com_up_sql = "UPDATE {$table} SET status = 'repaired' WHERE (file_path LIKE %s OR file_path = %s) AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($com_up_sql, "comment:{$comment_id}%", "comment:{$comment_id}")
            );
        }

        return rest_ensure_response([
            'success'    => $success,
            'message'    => $message,
            'action'     => $action,
            'comment_id' => $comment_id,
        ]);
    }

    /**
     * Database Row Remediation (Delete row or cleanse field with auto-backup snapshot)
     */
    public static function remediate_database_row(\WP_REST_Request $request) {
        $uid = get_current_user_id();
        $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
        if ($uid && (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid])))) {
            return new \WP_Error('rest_forbidden', __('Access Denied: Database row remediation and deletion is prohibited during temporary support sessions.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $table = !empty($params['table']) ? sanitize_text_field($params['table']) : '';
        $column = !empty($params['column']) ? sanitize_text_field($params['column']) : '';
        $row_id = !empty($params['row_id']) ? sanitize_text_field($params['row_id']) : '';
        $action = !empty($params['action']) ? sanitize_key($params['action']) : 'delete_row';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table name and Row ID are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();

        if ($action === 'delete_row') {
            $result = $mgr->delete_row_with_backup($table, $row_id, $column, $issue_id);
        } elseif ($action === 'cleanse_field') {
            if (empty($column)) {
                return new \WP_Error('missing_column', __('Column name is required for field cleansing.', 'webcare-pro-security'), ['status' => 400]);
            }
            $result = $mgr->cleanse_field_with_backup($table, $column, $row_id, $issue_id);
        } else {
            return new \WP_Error('invalid_action', __('Invalid database remediation action.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!$result['success']) {
            return new \WP_Error('db_remediation_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Get Database Row Data for Live Forensic Inspection
     */
    public static function get_database_row(\WP_REST_Request $request) {
        $table = sanitize_text_field($request->get_param('table') ?: '');
        $row_id = sanitize_text_field($request->get_param('row_id') ?: '');

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table and Row ID are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();
        $pk = $mgr->get_primary_key($table);
        $row = $mgr->get_row($table, $row_id);

        if (!$row) {
            return new \WP_Error('row_not_found', __('Database record not found or already deleted.', 'webcare-pro-security'), ['status' => 404]);
        }

        $is_log_table = (bool) preg_match('/(log|logs|redirection|audit|history|stat|stats|traffic|404)/i', $table);

        return rest_ensure_response([
            'success'      => true,
            'table'        => $table,
            'row_id'       => $row_id,
            'primary_key'  => $pk,
            'is_log_table' => $is_log_table,
            'row'          => $row,
            'data'         => [
                'table'        => $table,
                'row_id'       => $row_id,
                'primary_key'  => $pk,
                'is_log_table' => $is_log_table,
                'row'          => $row,
            ],
        ]);
    }

    /**
     * Restore Database Row from Auto-Backup Snapshot
     */
    public static function restore_database_row(\WP_REST_Request $request) {
        $uid = get_current_user_id();
        $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
        if ($uid && (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid])))) {
            return new \WP_Error('rest_forbidden', __('Access Denied: Database restoration is prohibited during temporary support sessions.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field($params['backup_id']) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_backup_id', __('Backup ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();
        $result = $mgr->restore_backup($backup_id);

        if (!$result['success']) {
            return new \WP_Error('db_restore_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Remediate User Account / Capabilities Anomaly
     *
     * Actions:
     * - 'assign_default_role': Assigns default role (subscriber) to user missing capabilities.
     * - 'strip_capabilities': Strips unauthorized/trojan capabilities from non-admin accounts.
     * - 'delete_user': Safely deletes anomalous/ghost account with mandatory pre-action snapshot.
     */
    public static function remediate_user(\WP_REST_Request $request) {
        $uid = get_current_user_id();
        $support_users = get_option(\WebCareProScanner\Identity\WebCareJitMuGuardian::OPTION_SUPPORT_USERS, []);
        if ($uid && (!empty(get_user_meta($uid, 'webcareproscan_is_temporary_support', true)) || (is_array($support_users) && isset($support_users[$uid])))) {
            return new \WP_Error('rest_forbidden', __('Access Denied: User account remediation is prohibited during temporary support sessions.', 'webcare-pro-security'), ['status' => 403]);
        }

        global $wpdb;

        $params = $request->get_json_params() ?: [];
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $role = !empty($params['role']) ? sanitize_key($params['role']) : null;
        $reassign_to = !empty($params['reassign_to']) ? (int) $params['reassign_to'] : null;
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if ($user_id <= 0) {
            return new \WP_Error('invalid_user_id', __('Valid User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();

        if ($action === 'assign_default_role') {
            $result = $mgr->assign_default_role($user_id, $role);
        } elseif ($action === 'strip_capabilities') {
            $result = $mgr->strip_injected_capabilities($user_id);
        } elseif ($action === 'delete_user') {
            $result = $mgr->delete_user($user_id, $reassign_to);
        } elseif ($action === 'restore_user') {
            $result = $mgr->restore_user_by_id($user_id);
        } elseif ($action === 'reassign_orphaned_posts') {
            $result = $mgr->reassign_orphaned_posts($user_id, $reassign_to);
        } else {
            return new \WP_Error('invalid_action', __('Invalid user remediation action.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            return new \WP_Error('remediation_failed', $result['error'] ?? __('User remediation failed.', 'webcare-pro-security'), ['status' => 500]);
        }

        // Mark associated scan issue as repaired if issue_id is provided
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        if ($issue_id > 0) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        // Also mark open issues for this user account or author as repaired
        $repair_sql = "UPDATE `{$table_issues}` SET status = 'repaired' WHERE (file_path LIKE %s OR file_path LIKE %s OR file_path LIKE %s OR file_path = %s) AND status = 'open'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $repair_sql,
                "user:{$user_id}%",
                "%_users:user_id_{$user_id}%",
                "%users.ID = {$user_id}%",
                "author:{$user_id}"
            )
        );

        return rest_ensure_response($result);
    }

    /**
     * Get all quarantined or backed-up user accounts.
     */
    public static function get_user_backups(\WP_REST_Request $request) {
        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();
        $backups = $mgr->list_user_backups();
        return rest_ensure_response([
            'success' => true,
            'backups' => $backups,
            'count'   => count($backups),
        ]);
    }

    /**
     * 1-Click Restore a deleted or quarantined user account.
     */
    public static function restore_user_account(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $backup_file = !empty($params['backup_file']) ? sanitize_text_field($params['backup_file']) : '';
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $restore_all = !empty($params['all']);

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();

        if ($restore_all) {
            $result = $mgr->restore_all_user_backups();
            return rest_ensure_response($result);
        }

        if (!empty($backup_file)) {
            $result = $mgr->restore_user($backup_file);
        } elseif ($user_id > 0) {
            $result = $mgr->restore_user_by_id($user_id);
        } else {
            return new \WP_Error('missing_param', __('Specify backup_file or user_id or all.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            return new \WP_Error('restore_failed', $result['error'] ?? __('Failed to restore user account.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Dismiss / Acknowledge user backup snapshot(s) so they no longer prompt restoration alerts.
     */
    public static function dismiss_user_backup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $backup_file = !empty($params['backup_file']) ? sanitize_text_field($params['backup_file']) : '';
        $user_login = !empty($params['user_login']) ? sanitize_text_field($params['user_login']) : '';
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $dismiss_all = !empty($params['all']);

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();

        if ($dismiss_all) {
            $count = $mgr->dismiss_all_missing_backups();
            return rest_ensure_response([
                'success' => true,
                /* translators: %d: count */
                'message' => sprintf(__('Dismissed %d missing user backup notifications.', 'webcare-pro-security'), $count),
            ]);
        }

        if (!empty($backup_file)) {
            $mgr->dismiss_user_backup($backup_file);
        }
        if (!empty($user_login)) {
            $mgr->dismiss_user_backup($user_login);
        }
        if ($user_id > 0) {
            $mgr->dismiss_user_backups_for_id($user_id);
        }

        return rest_ensure_response([
            'success' => true,
            'message' => __('User backup alert dismissed successfully.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Permanently delete a user backup snapshot file from disk.
     */
    public static function delete_user_backup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $backup_file = !empty($params['backup_file']) ? sanitize_text_field($params['backup_file']) : '';

        if (empty($backup_file)) {
            return new \WP_Error('missing_param', __('Specify backup_file to delete.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();
        $result = $mgr->delete_backup_file($backup_file);

        if (empty($result['success'])) {
            return new \WP_Error('delete_failed', $result['error'] ?? __('Failed to delete user backup file.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get Status
     */
    public static function get_threat_intel_status() {
        return rest_ensure_response(\WebCareProScanner\Firewall\ThreatIntelService::get_status());
    }

    /**
     * Threat Intelligence: Sync live data
     */
    public static function sync_threat_intel() {
        $result = \WebCareProScanner\Firewall\ThreatIntelService::sync_threat_data();
        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get CVE catalog
     */
    public static function get_threat_intel_cves() {
        return rest_ensure_response([
            'cves' => \WebCareProScanner\Firewall\ThreatIntelService::get_cve_catalog(),
        ]);
    }

    /**
     * Auth Security: Get Status & Lockouts
     */
    public static function get_auth_security_status() {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $user_id  = get_current_user_id();
        $user     = wp_get_current_user();

        return rest_ensure_response([
            'auth_2fa_enabled'          => !empty($settings['auth_2fa_enabled']),
            'auth_2fa_algorithm'        => !empty($settings['auth_2fa_algorithm']) ? $settings['auth_2fa_algorithm'] : 'sha1',
            'auth_2fa_digits'           => (!empty($settings['auth_2fa_digits']) && (int) $settings['auth_2fa_digits'] === 8) ? 8 : 6,
            'auth_2fa_remember_device'  => !empty($settings['auth_2fa_remember_device']),
            'auth_2fa_remember_days'    => (int) ($settings['auth_2fa_remember_days'] ?? 7),
            'auth_2fa_enforce_admins'   => !empty($settings['auth_2fa_enforce_admins']),
            'auth_2fa_policy_mode'      => $settings['auth_2fa_policy_mode'] ?? 'immediate',
            'auth_2fa_grace_days'       => (int) ($settings['auth_2fa_grace_days'] ?? 0),
            'auth_2fa_enforce_since'    => (int) ($settings['auth_2fa_enforce_since'] ?? 0),
            'login_hardening_enabled'   => !empty($settings['login_hardening_enabled']),
            'login_max_retries'         => (int) ($settings['login_max_retries'] ?? 5),
            'login_lockout_duration'    => (int) ($settings['login_lockout_duration'] ?? 15),
            'session_sentinel_enabled'  => !empty($settings['session_sentinel_enabled']),
            'session_block_concurrent'  => !empty($settings['session_block_concurrent']),
            'user_2fa_enabled'          => \WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user_id),
            'user_2fa_algorithm'        => \WebCareProScanner\Auth\TwoFactorAuth::get_user_algorithm($user_id),
            'user_2fa_digits'           => \WebCareProScanner\Auth\TwoFactorAuth::get_user_digits($user_id),
            'user_compliance'           => \WebCareProScanner\Auth\TwoFactorAuth::get_user_compliance_status($user_id),
            'user_login'                => $user ? $user->user_login : '',
            'user_email'                => $user ? $user->user_email : '',
            'trusted_devices_count'     => count(\WebCareProScanner\Auth\TwoFactorAuth::get_trusted_devices($user_id)),
            'trusted_devices'           => \WebCareProScanner\Auth\TwoFactorAuth::get_trusted_devices($user_id),
            'lockouts'                  => array_values(\WebCareProScanner\Auth\LoginHardening::get_locked_ips()),
            'stats'                     => \WebCareProScanner\Auth\LoginHardening::get_stats(),
            'active_sessions'           => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
            'backup_codes_count'        => \WebCareProScanner\Auth\TwoFactorAuth::get_remaining_backup_codes_count($user_id),
            'current_ip'                => \WebCareProScanner\Firewall\FirewallEngine::get_client_ip(),
        ]);
    }

    /**
     * Auth Security: Generate 2FA Setup Package
     */
    public static function setup_2fa_for_user() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $algo     = !empty($settings['auth_2fa_algorithm']) ? (string) $settings['auth_2fa_algorithm'] : 'sha1';
        $digits   = (!empty($settings['auth_2fa_digits']) && (int) $settings['auth_2fa_digits'] === 8 || $algo === 'sha512') ? 8 : 6;
        $secretLen = ($algo === 'sha512') ? 64 : 16;

        $secret           = \WebCareProScanner\Auth\TwoFactorAuth::generate_secret($secretLen);
        $provisioning_uri = \WebCareProScanner\Auth\TwoFactorAuth::get_provisioning_uri($secret, $user->user_login, $algo, $digits);
        $qr_data_uri      = \WebCareProScanner\Auth\TwoFactorAuth::get_qr_data_uri($provisioning_uri);
        $backup_bundle    = \WebCareProScanner\Auth\TwoFactorAuth::generate_backup_codes(8);

        // Store setup state in transient for 10 minutes
        set_transient('webcareproscan_2fa_setup_' . $user_id, [
            'secret'       => $secret,
            'algorithm'    => $algo,
            'digits'       => $digits,
            'hashed_codes' => $backup_bundle['hashed'],
        ], 600);

        return rest_ensure_response([
            'secret'           => $secret,
            'algorithm'        => $algo,
            'digits'           => $digits,
            'provisioning_uri' => $provisioning_uri,
            'qr_code_url'      => $qr_data_uri,
            'backup_codes'     => $backup_bundle['plain'],
        ]);
    }

    /**
     * Auth Security: Verify and Enable 2FA
     */
    public static function verify_and_enable_2fa(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        $params  = $request->get_json_params() ?: [];
        $code    = sanitize_text_field($params['code'] ?? '');

        $setup_state = get_transient('webcareproscan_2fa_setup_' . $user_id);
        if (!$setup_state || empty($setup_state['secret'])) {
            return new \WP_Error('session_expired', __('2FA setup session expired. Please click "Setup 2FA" again.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Always read the pending secret strictly from server storage; never trust client-supplied secret overrides
        $active_secret = $setup_state['secret'];
        $algo          = $setup_state['algorithm'] ?? 'sha1';
        $digits        = (int) ($setup_state['digits'] ?? 6);

        if (!\WebCareProScanner\Auth\TwoFactorAuth::verify_code($active_secret, $code, 1, $algo, $digits)) {
            return new \WP_Error('invalid_code', sprintf(
                /* translators: %d: count of digits expected */
                __('The %d-digit verification code you entered is invalid. Please check your authenticator clock and try again.', 'webcare-pro-security'),
                $digits
            ), ['status' => 400]);
        }

        \WebCareProScanner\Auth\TwoFactorAuth::enable_user($user_id, $active_secret, $setup_state['hashed_codes'], $algo, $digits);
        delete_transient('webcareproscan_2fa_setup_' . $user_id);

        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) is now active on your account!', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Disable 2FA
     */
    public static function disable_2fa_for_user() {
        $user_id = get_current_user_id();
        \WebCareProScanner\Auth\TwoFactorAuth::disable_user($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) has been disabled.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Revoke All Trusted Devices
     */
    public static function revoke_2fa_trusted_devices() {
        $user_id = get_current_user_id();
        \WebCareProScanner\Auth\TwoFactorAuth::revoke_all_trusted_devices($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('All remembered/trusted devices have been revoked. 2FA verification will be required on all browsers.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Regenerate Backup Codes for Current User
     */
    public static function regenerate_user_backup_codes() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        if (!\WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user_id)) {
            return new \WP_Error('2fa_not_enabled', __('Two-Factor Authentication is not enabled for your account.', 'webcare-pro-security'), ['status' => 400]);
        }

        try {
            $bundle = \WebCareProScanner\Auth\TwoFactorAuth::regenerate_backup_codes($user_id, 8);

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    '2fa_backup_codes_regenerated',
                    /* translators: %s: username */
                    sprintf(__('Administrator %s regenerated 2FA emergency backup codes.', 'webcare-pro-security'), $user->user_login)
                );
            }

            return rest_ensure_response([
                'success'            => true,
                'message'            => __('New 2FA emergency backup codes generated successfully.', 'webcare-pro-security'),
                'backup_codes'       => $bundle['backup_codes'],
                'backup_codes_count' => $bundle['count'],
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('regen_failed', $e->getMessage(), ['status' => 500]);
        }
    }


    /**
     * Auth Security: Unlock IP
     */
    public static function unlock_locked_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field($params['ip'] ?? '');
        if (empty($ip)) {
            return new \WP_Error('missing_ip', __('Missing IP parameter.', 'webcare-pro-security'), ['status' => 400]);
        }
        \WebCareProScanner\Auth\LoginHardening::unlock_ip($ip);
        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: IP address */
                __('IP %s has been unlocked.', 'webcare-pro-security'),
                $ip
            ),
        ]);
    }

    /**
     * Auth Security: Clear all lockouts
     */
    public static function clear_all_lockouts() {
        \WebCareProScanner\Auth\LoginHardening::clear_all_lockouts();
        return rest_ensure_response([
            'success' => true,
            'message' => __('All temporary IP lockouts have been cleared.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Get Administrator Directory & 2FA Compliance Status
     */
    public static function get_admin_directory_status() {
        $admins = \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        return rest_ensure_response([
            'success'            => true,
            'admins'             => $admins,
            'total_admins'       => count($admins),
            'enforce_admins'     => !empty($settings['auth_2fa_enforce_admins']),
            'policy_mode'        => $settings['auth_2fa_policy_mode'] ?? 'immediate',
            'grace_days'         => (int) ($settings['auth_2fa_grace_days'] ?? 0),
            'enforce_since'      => (int) ($settings['auth_2fa_enforce_since'] ?? 0),
            'global_2fa_enabled' => !empty($settings['auth_2fa_enabled']),
        ]);
    }

    /**
     * Auth Security: Admin Disable 2FA for target user (Emergency recovery / lockout unlock)
     */
    public static function admin_disable_user_2fa(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        \WebCareProScanner\Auth\TwoFactorAuth::disable_user($user_id);

        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
            \WebCareProScanner\System\AuditLogger::log_event(
                'admin_2fa_disabled',
                sprintf(
                    /* translators: 1: admin username, 2: target username, 3: user ID */
                    __('Administrator %1$s disabled 2FA for user "%2$s" (ID: %3$d).', 'webcare-pro-security'),
                    wp_get_current_user()->user_login,
                    $user->user_login,
                    $user_id
                )
            );
        }

        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: username */
                __('2FA has been disabled and unlocked for administrator %s.', 'webcare-pro-security'),
                $user->user_login
            ),
            'admins'  => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
        ]);
    }

    /**
     * Auth Security: Admin Reset 2FA & Generate New Setup Package for target user
     */
    public static function admin_reset_user_2fa(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        $current_uid = get_current_user_id();
        // If resetting another administrator, reset their 2FA and require self-enrollment on next login
        // to prevent immediate lockout and cross-admin secret exposure
        if ($user_id !== $current_uid) {
            \WebCareProScanner\Auth\TwoFactorAuth::disable_user($user_id);
            update_user_meta($user_id, 'webcareproscan_force_2fa_setup', 1);
            delete_user_meta($user_id, 'webcareproscan_2fa_secret');
            delete_user_meta($user_id, 'webcareproscan_2fa_backup_codes');

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'admin_2fa_reset',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s reset 2FA policy for user "%2$s" (ID: %3$d), requiring re-enrollment on next login.', 'webcare-pro-security'),
                        wp_get_current_user()->user_login,
                        $user->user_login,
                        $user_id
                    )
                );
            }

            return rest_ensure_response([
                'success'       => true,
                'message'       => sprintf(
                    /* translators: %s: username */
                    __('2FA has been reset for administrator %s. They will be prompted to safely enroll their own authenticator upon next login.', 'webcare-pro-security'),
                    $user->user_login
                ),
                'setup_package' => null,
                'admins'        => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            ]);
        }

        try {
            $setup_pkg = \WebCareProScanner\Auth\TwoFactorAuth::reset_user_2fa($user_id);

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'admin_2fa_reset',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s regenerated 2FA credentials for user "%2$s" (ID: %3$d).', 'webcare-pro-security'),
                        wp_get_current_user()->user_login,
                        $user->user_login,
                        $user_id
                    )
                );
            }

            return rest_ensure_response([
                'success'       => true,
                'message'       => sprintf(
                    /* translators: %s: username */
                    __('New 2FA credentials generated for %s.', 'webcare-pro-security'),
                    $user->user_login
                ),
                'setup_package' => $setup_pkg,
                'admins'        => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('reset_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Admin Regenerate Backup Codes for Target Administrator
     */
    public static function admin_regenerate_user_backup_codes(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        if (!\WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user_id)) {
            return new \WP_Error(
                '2fa_not_enabled',
                sprintf(
                    /* translators: %s: username */
                    __('2FA is not enabled for user %s.', 'webcare-pro-security'),
                    $user->user_login
                ),
                ['status' => 400]
            );
        }

        try {
            $bundle = \WebCareProScanner\Auth\TwoFactorAuth::regenerate_backup_codes($user_id, 8);

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'admin_2fa_backup_codes_regenerated',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s regenerated backup codes for user "%2$s" (ID: %3$d).', 'webcare-pro-security'),
                        wp_get_current_user()->user_login,
                        $user->user_login,
                        $user_id
                    )
                );
            }

            return rest_ensure_response([
                'success'            => true,
                'message'            => sprintf(
                    /* translators: %s: username */
                    __('New backup codes generated for administrator %s.', 'webcare-pro-security'),
                    $user->user_login
                ),
                'user_login'         => $user->user_login,
                'backup_codes'       => $bundle['backup_codes'],
                'backup_codes_count' => $bundle['count'],
                'admins'             => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('regen_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Clear Login Hardening Lockouts for Target Administrator
     */
    public static function admin_clear_user_lockout(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        $res = \WebCareProScanner\Auth\TwoFactorAuth::unlock_user_lockouts($user_id);

        return rest_ensure_response([
            'success'          => true,
            'message'          => sprintf(
                /* translators: %s: username */
                __('Login lockouts and rate-limiting blocks cleared for user %s.', 'webcare-pro-security'),
                $user->user_login
            ),
            'unlocked_ips'     => $res['unlocked_ips'],
            'admins'           => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            'lockouts'         => array_values(\WebCareProScanner\Auth\LoginHardening::get_locked_ips()),
        ]);
    }

    /**
     * Auth Security: Save 2FA Policy & Enforce Settings
     */
    public static function save_auth_security_policy(\WP_REST_Request $request) {
        $params   = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_params();
        }
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        $enforce_admins = !empty($params['auth_2fa_enforce_admins']);
        $raw_mode       = sanitize_key($params['auth_2fa_policy_mode'] ?? 'remind_login');
        $policy_mode    = in_array($raw_mode, ['immediate', 'grace_period', 'remind_login'], true) ? $raw_mode : 'remind_login';
        $grace_days     = max(0, min(90, (int) ($params['auth_2fa_grace_days'] ?? ($policy_mode === 'immediate' ? 0 : 30))));

        $settings['auth_2fa_enforce_admins'] = $enforce_admins;
        $settings['auth_2fa_policy_mode']    = $policy_mode;
        $settings['auth_2fa_grace_days']     = $grace_days;

        if ($enforce_admins && empty($settings['auth_2fa_enforce_since'])) {
            $settings['auth_2fa_enforce_since'] = time();
        } elseif (!$enforce_admins) {
            $settings['auth_2fa_enforce_since'] = 0;
        }

        \WebCareProScanner\System\SettingsManager::save_settings($settings);

        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
            \WebCareProScanner\System\AuditLogger::log_event(
                'auth_policy_updated',
                sprintf(
                    /* translators: 1: enforce status, 2: policy mode, 3: grace days */
                    __('Administrator 2FA policy updated: Enforce=%1$s, Mode=%2$s, Grace Days=%3$d.', 'webcare-pro-security'),
                    $enforce_admins ? 'YES' : 'NO',
                    strtoupper($policy_mode),
                    $grace_days
                )
            );
        }

        return rest_ensure_response([
            'success' => true,
            'message' => __('2FA enforcement policy updated successfully.', 'webcare-pro-security'),
            'policy'  => [
                'enforce_admins' => $enforce_admins,
                'policy_mode'    => $policy_mode,
                'grace_days'     => $grace_days,
                'enforce_since'  => $settings['auth_2fa_enforce_since'],
            ],
            'admins'  => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
        ]);
    }

    /**
     * Session Sentinel: Get active sessions list
     */
    public static function get_active_sessions_list() {
        return rest_ensure_response([
            'success'    => true,
            'sessions'   => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
            'current_ip' => \WebCareProScanner\Firewall\FirewallEngine::get_client_ip(),
        ]);
    }

    /**
     * Session Sentinel: Revoke session
     */
    public static function revoke_active_session(\WP_REST_Request $request) {
        try {
            $params  = $request->get_json_params() ?: [];
            $token   = sanitize_text_field($params['token'] ?? '');
            $user_id = (int) ($params['user_id'] ?? 0);
            $revoke_others = !empty($params['revoke_others']);

            if ($revoke_others) {
                $target_user_id = $user_id ?: 0;
                \WebCareProScanner\Auth\SessionSentinel::terminate_all_other_sessions($target_user_id, empty($user_id));
                return rest_ensure_response([
                    'success' => true,
                    'message' => __('All other active sessions have been terminated.', 'webcare-pro-security'),
                    'sessions' => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
                ]);
            }

            if (empty($token) || empty($user_id)) {
                return new \WP_Error('missing_params', __('Session token and user ID are required.', 'webcare-pro-security'), ['status' => 400]);
            }

            \WebCareProScanner\Auth\SessionSentinel::terminate_session($user_id, $token, 'Revoked by administrator via Session Sentinel.');

            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Session successfully revoked.', 'webcare-pro-security'),
                'sessions' => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('session_revoke_error', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Get User Login History & Device Forensics (Encrypted Telemetry Decrypted for Admin)
     */
    public static function get_user_login_history(\WP_REST_Request $request) {
        $user_id = (int) $request->get_param('user_id');
        if (empty($user_id)) {
            $user_id = get_current_user_id();
        }

        $raw_limit = $request->get_param('limit');
        if ($raw_limit === '0' || $raw_limit === 0 || $raw_limit === 'all' || $raw_limit === 'unlimited') {
            $limit = 0; // Retrieve full historical audit log
        } elseif (!empty($raw_limit)) {
            $limit = max(1, (int) $raw_limit);
        } else {
            $limit = 10;
        }

        $result = \WebCareProScanner\Auth\LoginHistoryManager::get_user_history($user_id, $limit);

        return rest_ensure_response($result);
    }

    /**
     * Auth Security: Record Dynamic Client Telemetry (Screen Resolution, Viewport, Timezone)
     */
    public static function record_client_telemetry(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Unauthorized', 'webcare-pro-security'), ['status' => 401]);
        }

        // Rate-limiting: Max 5 submissions per user per 60 seconds to prevent telemetry flooding
        $transient_key = 'webcareproscan_telemetry_rate_' . $user_id;
        $hit_count = (int) get_transient($transient_key);
        if ($hit_count >= 5) {
            return new \WP_Error('too_many_requests', __('Telemetry submission rate limit exceeded. Please wait a minute.', 'webcare-pro-security'), ['status' => 429]);
        }
        set_transient($transient_key, $hit_count + 1, 60);

        $params = $request->get_json_params();
        if (!is_array($params)) {
            return new \WP_Error('invalid_payload', __('Invalid JSON payload structure.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Strict input sanitization and length bounds
        $raw_res = sanitize_text_field(substr((string) ($params['screen_resolution'] ?? ''), 0, 20));
        $raw_vp  = sanitize_text_field(substr((string) ($params['viewport'] ?? ''), 0, 20));
        $raw_tz  = sanitize_text_field(substr((string) ($params['timezone'] ?? ''), 0, 64));

        // Format validation (screen and viewport should follow WxH format e.g. 1920x1080)
        $clean_res = preg_match('/^\d{2,5}x\d{2,5}$/', $raw_res) ? $raw_res : '';
        $clean_vp  = preg_match('/^\d{2,5}x\d{2,5}$/', $raw_vp) ? $raw_vp : '';
        $clean_tz  = preg_match('/^[a-zA-Z0-9_\-\/\+\:\. ]{1,64}$/', $raw_tz) ? $raw_tz : '';

        $telemetry = [
            'screen_resolution' => $clean_res,
            'viewport'          => $clean_vp,
            'timezone'          => $clean_tz,
        ];

        \WebCareProScanner\Auth\LoginHistoryManager::update_session_telemetry($user_id, $telemetry);

        return rest_ensure_response([
            'success' => true,
        ]);
    }

    /**
     * Database: Get Rogue Administrator & Micro-Anomaly Audit
     */
    public static function get_rogue_admin_audit(\WP_REST_Request $request) {
        $audit = \WebCareProScanner\Database\RogueAdminAnomalyDetector::audit_users_and_anomalies();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Living-off-the-Land (LotL) Hook Infiltration Audit
     */
    public static function get_hook_sentinel_audit(\WP_REST_Request $request) {
        $sentinel = new \WebCareProScanner\WordPress\HookInfiltrationSentinel();
        $findings = $sentinel->scan('manual_api_' . time());
        $results = [];
        foreach ($findings as $f) {
            $results[] = $f->to_array();
        }
        return rest_ensure_response([
            'success'  => true,
            'count'    => count($results),
            'findings' => $results,
        ]);
    }

    /**
     * Webhook Testing Endpoint
     */
    public static function test_chat_webhook(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $platform = sanitize_text_field($params['platform'] ?? 'slack');
        $url      = !empty($params['webhook_url']) ? esc_url_raw(trim($params['webhook_url'])) : null;

        $result = \WebCareProScanner\Notifications\WebhookService::send_test($platform, $url);
        return rest_ensure_response($result);
    }

    /**
     * Get granular notification settings & catalog
     */
    public static function get_notification_settings(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $catalog  = \WebCareProScanner\Notifications\NotificationDispatcher::get_event_catalog();

        return rest_ensure_response([
            'success'                     => true,
            'notification_master_enabled' => !empty($settings['notification_master_enabled']),
            'notification_events'         => $settings['notification_events'] ?? \WebCareProScanner\System\SettingsManager::get_default_notification_events(),
            'catalog'                     => $catalog,
            'alert_emails'                => $settings['alert_emails'] ?? get_option('admin_email'),
            'webhooks_configured'         => [
                'slack'   => !empty($settings['slack_enabled']) && !empty($settings['slack_webhook_url']),
                'discord' => !empty($settings['discord_enabled']) && !empty($settings['discord_webhook_url']),
                'clickup' => !empty($settings['clickup_enabled']) && !empty($settings['clickup_webhook_url']),
                'asana'   => !empty($settings['asana_enabled']) && !empty($settings['asana_webhook_url']),
                'generic' => !empty($settings['generic_webhook_enabled']) && !empty($settings['generic_webhook_url']),
            ],
        ]);
    }

    /**
     * Save granular notification settings
     */
    public static function save_notification_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $current = \WebCareProScanner\System\SettingsManager::get_settings();

        if (isset($params['notification_master_enabled'])) {
            $current['notification_master_enabled'] = !empty($params['notification_master_enabled']);
        }
        if (isset($params['notification_events']) && is_array($params['notification_events'])) {
            $current['notification_events'] = \WebCareProScanner\System\SettingsManager::sanitize_notification_events($params['notification_events']);
        }
        if (isset($params['alert_emails'])) {
            $current['alert_emails'] = sanitize_text_field($params['alert_emails']);
        }

        $saved = \WebCareProScanner\System\SettingsManager::save_settings($current);

        return rest_ensure_response([
            'success'                     => true,
            'message'                     => __('Notification settings saved successfully.', 'webcare-pro-security'),
            'notification_master_enabled' => !empty($saved['notification_master_enabled']),
            'notification_events'         => $saved['notification_events'],
        ]);
    }

    /**
     * Test a specific notification event
     */
    public static function test_notification_event(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $event_key = sanitize_text_field($params['event_key'] ?? '');

        if (empty($event_key)) {
            return new \WP_Error('missing_event', __('Event key is required for notification testing.', 'webcare-pro-security'), ['status' => 400]);
        }

        $catalog = \WebCareProScanner\Notifications\NotificationDispatcher::get_event_catalog();
        if (!isset($catalog[$event_key])) {
            return new \WP_Error('invalid_event', __('Unknown security event identifier.', 'webcare-pro-security'), ['status' => 404]);
        }

        $result = \WebCareProScanner\Notifications\NotificationDispatcher::trigger($event_key, [
            /* translators: %s: event title */
            'title'   => sprintf(__('[TEST] %s', 'webcare-pro-security'), $catalog[$event_key]['title']),
            /* translators: %s: event title */
            'message' => sprintf(__('This is an instant verification alert triggered from the WebCare Notification Center for "%s".', 'webcare-pro-security'), $catalog[$event_key]['title']),
            'details' => [
                'triggered_by' => wp_get_current_user()->user_login ?: 'admin',
                'event_code'   => $event_key,
                'test_mode'    => 'manual_verification',
            ],
        ]);

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: event title */
            'message' => sprintf(__('Test notification dispatched for event: %s', 'webcare-pro-security'), $catalog[$event_key]['title']),
            'result'  => $result,
        ]);
    }

    /**
     * Helper to load CloudflareService reliably
     */
    private static function ensure_cloudflare_service(): bool {
        if (!class_exists('\WebCareProScanner\Cloudflare\CloudflareService')) {
            $candidates = [
                WEBCAREPROSCAN_PATH . 'includes/Cloudflare/CloudflareService.php',
                WEBCAREPROSCAN_PATH . 'includes/cloudflare/CloudflareService.php',
                WEBCAREPROSCAN_PATH . 'includes/Firewall/CloudflareService.php',
            ];
            foreach ($candidates as $file) {
                if (file_exists($file)) {
                    require_once $file;
                    break;
                }
            }
        }
        return class_exists('\WebCareProScanner\Cloudflare\CloudflareService');
    }

    /**
     * Cloudflare Edge Defense Handlers
     */
    public static function get_cloudflare_status(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation.', 'webcare-pro-security'), ['status' => 500]);
        }
        $status = \WebCareProScanner\Cloudflare\CloudflareService::get_status();
        $definitions = \WebCareProScanner\Cloudflare\CloudflareService::get_rule_definitions();
        $compound_rules = \WebCareProScanner\Cloudflare\CloudflareService::get_compound_rule_definitions();
        $edge_advisor = \WebCareProScanner\Cloudflare\CloudflareService::get_edge_advisor();
        return rest_ensure_response([
            'success'        => true,
            'status'         => $status,
            'definitions'    => $definitions,
            'compound_rules' => $compound_rules,
            'edge_advisor'   => $edge_advisor,
        ]);
    }

    public static function verify_cloudflare_credentials(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation. Please reinstall or update the plugin zip.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $token   = !empty($params['token']) ? trim(sanitize_text_field($params['token'])) : null;
        $zone_id = !empty($params['zone_id']) ? trim(sanitize_text_field($params['zone_id'])) : null;

        $result = \WebCareProScanner\Cloudflare\CloudflareService::verify_zone($zone_id, $token);
        return rest_ensure_response($result);
    }

    public static function deploy_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $rules  = is_array($params['rules'] ?? null) ? $params['rules'] : [];

        $result = \WebCareProScanner\Cloudflare\CloudflareService::deploy_custom_rules($rules);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_rules_deployed',
                'firewall',
                [
                    'rules_count' => count($rules),
                    'description' => sprintf('Cloudflare Edge WAF rules deployed (%d rules configured) by %s from IP %s.', count($rules), $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function deploy_single_cloudflare_rule(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params   = $request->get_json_params() ?: [];
        $rule_key = sanitize_key($params['rule_key'] ?? '');
        $config   = is_array($params['config'] ?? null) ? $params['config'] : [];
        $enable   = !isset($params['enabled']) || !empty($params['enabled']);

        $result = \WebCareProScanner\Cloudflare\CloudflareService::deploy_single_rule($rule_key, $config, $enable);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $action_state = $enable ? 'enabled' : 'disabled';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_rule_modified',
                'firewall',
                [
                    'rule_key'    => $rule_key,
                    'enabled'     => $enable,
                    'description' => sprintf('Cloudflare Edge rule "%s" was %s by %s from IP %s.', $rule_key, $action_state, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function toggle_cloudflare_rate_limiting(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $enable  = !empty($params['enabled']);
        $options = is_array($params['options'] ?? null) ? $params['options'] : [];

        $result = \WebCareProScanner\Cloudflare\CloudflareService::toggle_rate_limiting($enable, $options);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $state_text = $enable ? 'activated' : 'paused';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_rate_limiting_toggled',
                'firewall',
                [
                    'enabled'     => $enable,
                    'description' => sprintf('Cloudflare Edge rate limiting was %s by %s from IP %s.', $state_text, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function block_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Manual block via Security Scanner');

        $result = \WebCareProScanner\Cloudflare\CloudflareService::block_ip($ip, $reason);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_ip_blocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'reason'      => $reason,
                    'rule_id'     => $result['rule_id'] ?? '',
                    'description' => sprintf('IP %s manually blocked at Cloudflare Edge by %s from IP %s. Reason: %s', $ip, $user_login, $client_ip, $reason),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function get_cloudflare_banned_ips(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(100, (int) ($request->get_param('per_page') ?: 50)));

        $result = \WebCareProScanner\Cloudflare\CloudflareService::get_banned_ips($page, $per_page);
        return rest_ensure_response($result);
    }

    public static function unblock_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field($params['rule_id'] ?? '');
        $target_ip = sanitize_text_field(trim($params['ip'] ?? ''));

        if (!empty($rule_id)) {
            $result = \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip($rule_id);
        } elseif (!empty($target_ip)) {
            $result = \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip_by_address($target_ip);
        } else {
            return new \WP_Error('invalid_param', __('Either rule_id or ip is required to unblock.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $ip_text = !empty($target_ip) ? sprintf('IP %s', $target_ip) : sprintf('Rule %s', $rule_id);
            $desc = !empty($target_ip)
                ? sprintf('Cloudflare Edge block rule for IP %s removed by %s from IP %s (Rule ID: %s).', $target_ip, $user_login, $client_ip, $rule_id)
                : sprintf('Cloudflare Edge block rule %s removed by %s from IP %s.', $rule_id, $user_login, $client_ip);

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_ip_unblocked',
                'firewall',
                [
                    'ip'          => $target_ip,
                    'rule_id'     => $rule_id,
                    'description' => $desc,
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function purge_cloudflare_cache(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $files  = !empty($params['files']) && is_array($params['files']) ? array_map('esc_url_raw', $params['files']) : null;

        $result = \WebCareProScanner\Cloudflare\CloudflareService::purge_cache($files);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $target_desc = !empty($files) ? sprintf('%d specific file(s)', count($files)) : 'all cached assets (Everything)';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_cache_purged',
                'firewall',
                [
                    'target'      => $target_desc,
                    'description' => sprintf('Cloudflare Edge cache purged (%s) by %s from IP %s.', $target_desc, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function inspect_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $result = \WebCareProScanner\Cloudflare\CloudflareService::inspect_edge_rules($zone_id);
        return rest_ensure_response($result);
    }

    public static function get_cloudflare_whitelisted_ips(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(100, (int) ($request->get_param('per_page') ?: 50)));

        $result = \WebCareProScanner\Cloudflare\CloudflareService::get_whitelisted_ips($page, $per_page);
        return rest_ensure_response($result);
    }

    public static function remove_cloudflare_whitelisted_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field($params['rule_id'] ?? '');
        $target_ip = sanitize_text_field(trim($params['ip'] ?? ''));

        $result = \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip($rule_id);
        if (!empty($result['success'])) {
            $result['message'] = __('Whitelisted IP rule successfully removed from Cloudflare Edge.', 'webcare-pro-security');

            if (class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
                $current_user = wp_get_current_user();
                $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
                $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                    ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                    : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

                $desc = !empty($target_ip)
                    ? sprintf('Cloudflare Edge allowlist rule for IP %s removed by %s from IP %s (Rule ID: %s).', $target_ip, $user_login, $client_ip, $rule_id)
                    : sprintf('Cloudflare Edge allowlist rule %s removed by %s from IP %s.', $rule_id, $user_login, $client_ip);

                \WebCareProScanner\System\WebCareActivityLogger::notice(
                    'cloudflare_whitelist_removed',
                    'firewall',
                    [
                        'ip'          => $target_ip,
                        'rule_id'     => $rule_id,
                        'description' => $desc,
                    ]
                );
            }
        }
        return rest_ensure_response($result);
    }

    public static function whitelist_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $notes  = sanitize_text_field($params['notes'] ?? 'Administrator / Developer Whitelist via WebCare');

        $result = \WebCareProScanner\Cloudflare\CloudflareService::whitelist_ip($ip, $notes);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_ip_whitelisted',
                'firewall',
                [
                    'ip'          => $ip,
                    'notes'       => $notes,
                    'rule_id'     => $result['rule_id'] ?? '',
                    'description' => sprintf('IP %s added to Cloudflare Edge Allowlist by %s from IP %s. Notes: %s', $ip, $user_login, $client_ip, $notes),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function disconnect_cloudflare(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Cloudflare\CloudflareService::disconnect();
        return rest_ensure_response($result);
    }

    public static function get_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Cloudflare\CloudflareService::get_stored_firewall_events();
        return rest_ensure_response($result);
    }

    public static function fetch_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $limit  = isset($params['limit']) ? intval($params['limit']) : 100;

        $result = \WebCareProScanner\Cloudflare\CloudflareService::fetch_and_store_firewall_events($limit);
        return rest_ensure_response($result);
    }

    public static function clear_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Cloudflare\CloudflareService::clear_stored_firewall_events();
        return rest_ensure_response($result);
    }

    // ==========================================
    // 13. Whitelist & False-Positive Endpoints
    // ==========================================

    public static function get_whitelist_rules(\WP_REST_Request $request) {
        $rules = \WebCareProScanner\Findings\WhitelistManager::get_whitelist_rules(false);
        return rest_ensure_response([
            'success' => true,
            'rules'   => $rules,
            'active_count' => count(array_filter($rules, fn($r) => ($r['status'] ?? '') === 'active')),
        ]);
    }

    public static function add_whitelist_rule(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $result = \WebCareProScanner\Findings\WhitelistManager::add_rule($params);
        return rest_ensure_response($result);
    }

    public static function remove_whitelist_rule(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: $request->get_params();
        $rule_id = sanitize_text_field($params['id'] ?? $params['rule_id'] ?? '');

        if (empty($rule_id)) {
            return new \WP_Error('missing_param', __('Rule ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $removed = \WebCareProScanner\Findings\WhitelistManager::remove_rule($rule_id);
        return rest_ensure_response([
            'success' => $removed,
            'rule_id' => $rule_id,
            'message' => $removed ? __('Whitelist rule revoked successfully.', 'webcare-pro-security') : __('Rule not found or could not be revoked.', 'webcare-pro-security'),
        ]);
    }

    // ==========================================
    // 14. Behavioral Baseline Engine Endpoints
    // ==========================================

    public static function get_baseline_status(\WP_REST_Request $request) {
        $baseline = \WebCareProScanner\Integrity\BehavioralBaselineEngine::get_baseline();
        return rest_ensure_response([
            'success'    => true,
            'calibrated' => ($baseline !== null),
            'baseline'   => $baseline,
        ]);
    }

    public static function calibrate_baseline(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Integrity\BehavioralBaselineEngine::calibrate();
        return rest_ensure_response($result);
    }

    public static function audit_baseline_deviations(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Integrity\BehavioralBaselineEngine::audit_baseline();
        return rest_ensure_response($result);
    }

    // ==========================================
    // 15. Transactional Remediation & Rollback
    // ==========================================

    public static function get_remediation_transactions(\WP_REST_Request $request) {
        $limit = max(1, min(100, intval($request->get_param('limit') ?: 30)));
        $list  = \WebCareProScanner\Remediation\TransactionalRemediation::list_transactions($limit);
        return rest_ensure_response([
            'success'      => true,
            'transactions' => $list,
        ]);
    }

    public static function rollback_remediation_transaction(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $tx_id  = sanitize_text_field($params['tx_id'] ?? '');

        if (empty($tx_id)) {
            return new \WP_Error('missing_param', __('Transaction ID (tx_id) is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Remediation\TransactionalRemediation::rollback_transaction($tx_id);
        return rest_ensure_response($result);
    }

    // ==========================================
    // 16. Model Context Protocol (MCP) Agent Service
    // ==========================================

    public static function get_mcp_tools(\WP_REST_Request $request) {
        $catalog = \WebCareProScanner\Api\MCPAgentService::get_tools_catalog();
        return rest_ensure_response($catalog);
    }

    public static function execute_mcp_tool(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $tool   = sanitize_text_field($params['tool'] ?? $params['name'] ?? '');
        $args   = is_array($params['arguments'] ?? null) ? $params['arguments'] : (is_array($params['args'] ?? null) ? $params['args'] : []);

        if (empty($tool)) {
            return new \WP_Error('missing_tool', __('Tool name is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Api\MCPAgentService::execute_tool($tool, $args);
        return rest_ensure_response($result);
    }

    public static function get_mcp_audit(\WP_REST_Request $request) {
        $limit = max(10, min(150, intval($request->get_param('limit') ?? 50)));
        return rest_ensure_response([
            'success' => true,
            'entries' => \WebCareProScanner\Api\MCPAgentService::get_audit_log($limit),
        ]);
    }

    public static function clear_mcp_audit(\WP_REST_Request $request) {
        \WebCareProScanner\Api\MCPAgentService::clear_audit_log();
        return rest_ensure_response([
            'success' => true,
            'message' => __('MCP agent audit trail cleared.', 'webcare-pro-security'),
        ]);
    }

    public static function get_mcp_staged_actions(\WP_REST_Request $request) {
        $status = sanitize_text_field($request->get_param('status') ?? 'all');
        return rest_ensure_response([
            'success' => true,
            'actions' => \WebCareProScanner\Api\MCPAgentService::get_staged_actions($status),
        ]);
    }

    public static function approve_mcp_staged_action(\WP_REST_Request $request) {
        $staged_id = sanitize_text_field($request->get_param('staged_id') ?? '');
        if (empty($staged_id)) {
            return new \WP_Error('missing_param', __('Staged action ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Api\MCPAgentService::approve_staged_action($staged_id, get_current_user_id());
        return rest_ensure_response($res);
    }

    public static function reject_mcp_staged_action(\WP_REST_Request $request) {
        $staged_id = sanitize_text_field($request->get_param('staged_id') ?? '');
        if (empty($staged_id)) {
            return new \WP_Error('missing_param', __('Staged action ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Api\MCPAgentService::reject_staged_action($staged_id, get_current_user_id());
        return rest_ensure_response($res);
    }

    public static function handle_mcp_matrix(\WP_REST_Request $request) {
        if ($request->get_method() === 'POST') {
            $params = $request->get_json_params() ?: [];
            $matrix = is_array($params['matrix'] ?? null) ? $params['matrix'] : [];
            $clean_matrix = \WebCareProScanner\System\SettingsManager::sanitize_mcp_tool_matrix($matrix);
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $settings['mcp_tool_matrix'] = $clean_matrix;
            \WebCareProScanner\System\SettingsManager::save_settings($settings);

            return rest_ensure_response([
                'success' => true,
                'matrix'  => $clean_matrix,
                'message' => __('MCP tool policy governance matrix saved.', 'webcare-pro-security'),
            ]);
        }

        $matrix = \WebCareProScanner\System\SettingsManager::get('mcp_tool_matrix', \WebCareProScanner\System\SettingsManager::get_default_mcp_tool_matrix());
        return rest_ensure_response([
            'success' => true,
            'matrix'  => $matrix,
        ]);
    }

    public static function run_security_drill(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $vectors = is_array($params['vectors'] ?? null) ? $params['vectors'] : [];
        $report = \WebCareProScanner\Security\AttackSimulationEngine::run_simulation($vectors);

        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function get_security_drill_results(\WP_REST_Request $request) {
        $report = \WebCareProScanner\Security\AttackSimulationEngine::get_latest_results();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function get_containment_status(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success' => true,
            'status'  => \WebCareProScanner\Security\EmergencyContainmentManager::get_status(),
        ]);
    }

    public static function toggle_containment(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $action = sanitize_text_field($params['action'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Administrator Security Incident Action');
        $maintenance = !empty($params['maintenance_enabled']);

        if ($action === 'activate') {
            $res = \WebCareProScanner\Security\EmergencyContainmentManager::activate([
                'reason'              => $reason,
                'maintenance_enabled' => $maintenance,
            ]);
        } elseif ($action === 'deactivate') {
            $res = \WebCareProScanner\Security\EmergencyContainmentManager::deactivate(get_current_user_id());
        } else {
            return new \WP_Error('invalid_action', __('Invalid containment action. Must be "activate" or "deactivate".', 'webcare-pro-security'), ['status' => 400]);
        }

        return rest_ensure_response($res);
    }

    // ==========================================
    // 17. Supply-Chain Defense & SBOM Sentinel Handlers
    // ==========================================

    public static function get_supply_chain_sbom(\WP_REST_Request $request) {
        $report = \WebCareProScanner\SupplyChain\SbomSentinelEngine::check_drift();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function calibrate_supply_chain_sbom(\WP_REST_Request $request) {
        $result = \WebCareProScanner\SupplyChain\SbomSentinelEngine::calibrate_baseline();
        return rest_ensure_response($result);
    }

    public static function isolate_supply_chain_anchor(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $item_id = sanitize_text_field($params['item_id'] ?? '');

        if (empty($item_id)) {
            return new \WP_Error('missing_item_id', __('Item ID is required for isolation.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\SupplyChain\SbomSentinelEngine::isolate_anchor($item_id);
        return rest_ensure_response($result);
    }

    public static function get_supply_chain_gatekeeper(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success'   => true,
            'logs'      => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_logs(30),
            'snapshots' => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_snapshots(),
            'settings'  => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_settings(),
        ]);
    }

    public static function update_supply_chain_gatekeeper_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $updated = \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Gatekeeper settings saved successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function rollback_supply_chain_gatekeeper(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $snapshot_id = sanitize_text_field($params['snapshot_id'] ?? '');

        if (empty($snapshot_id)) {
            return new \WP_Error('missing_snapshot_id', __('Snapshot ID is required for rollback.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::rollback_snapshot($snapshot_id);
        return rest_ensure_response($result);
    }

    public static function clear_supply_chain_gatekeeper_logs(\WP_REST_Request $request) {
        \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::clear_logs();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Gatekeeper intercepted logs cleared successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function analyze_supply_chain_plugin(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $slug = sanitize_text_field($params['slug'] ?? '');

        if (empty($slug)) {
            return new \WP_Error('missing_slug', __('Plugin slug is required for risk analysis.', 'webcare-pro-security'), ['status' => 400]);
        }

        $analysis = \WebCareProScanner\SupplyChain\InstallRiskAdvisor::analyze_installed_plugin($slug);
        return rest_ensure_response([
            'success'  => true,
            'analysis' => $analysis,
        ]);
    }

    public static function get_script_inventory_status(\WP_REST_Request $request) {
        $data = \WebCareProScanner\Content\ScriptInventoryMonitor::get_status();
        return rest_ensure_response($data);
    }

    public static function calibrate_script_inventory(\WP_REST_Request $request) {
        $data = \WebCareProScanner\Content\ScriptInventoryMonitor::calibrate_baseline();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Script inventory baseline calibrated successfully.', 'webcare-pro-security'),
            'status'  => $data,
        ]);
    }

    public static function dismiss_script_drift_alert(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $alert_id = sanitize_text_field($params['alert_id'] ?? '');

        if (empty($alert_id)) {
            return new \WP_Error('missing_alert_id', __('Alert ID is required to dismiss.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Content\ScriptInventoryMonitor::dismiss_alert($alert_id);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Script drift alert dismissed.', 'webcare-pro-security'),
        ]);
    }

    public static function get_supply_chain_lockfiles(\WP_REST_Request $request) {
        $data = \WebCareProScanner\SupplyChain\LockfileAuditEngine::run_audit(false);
        return rest_ensure_response($data);
    }

    public static function scan_supply_chain_lockfiles(\WP_REST_Request $request) {
        $data = \WebCareProScanner\SupplyChain\LockfileAuditEngine::run_audit(true);
        return rest_ensure_response($data);
    }

    // ==========================================
    // 17.5. Behavioral WAF, Bot Traps & Rate Limiting (Pillar 3)
    // ==========================================

    public static function get_behavioral_waf_status(\WP_REST_Request $request) {
        $learning_stats    = class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_summary_stats() : [];
        $route_profiles    = class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_route_profiles() : [];
        $learning_settings = class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_settings() : [];
        $honeytoken        = class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine') ? \WebCareProScanner\Firewall\HoneyTokenEngine::get_summary() : [];
        $rate_limiter      = class_exists('\WebCareProScanner\Firewall\AdaptiveRateLimiter') ? \WebCareProScanner\Firewall\AdaptiveRateLimiter::get_telemetry() : [];

        return rest_ensure_response([
            'success'           => true,
            'learning_stats'    => $learning_stats,
            'route_profiles'    => $route_profiles,
            'learning_settings' => $learning_settings,
            'honeytoken'        => $honeytoken,
            'rate_limiter'      => $rate_limiter,
        ]);
    }

    public static function set_behavioral_route_status(\WP_REST_Request $request) {
        $params    = $request->get_json_params() ?: [];
        $route_key = sanitize_text_field($params['route_key'] ?? '');
        $action    = sanitize_key($params['action'] ?? '');

        if (empty($route_key) || empty($action)) {
            return new \WP_Error('missing_params', __('Route key and action are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Firewall\LearningModeEngine')) {
            return new \WP_Error('missing_engine', __('LearningModeEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $result = \WebCareProScanner\Firewall\LearningModeEngine::set_route_status($route_key, $action);
        return rest_ensure_response($result);
    }

    public static function update_behavioral_learning_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Firewall\LearningModeEngine')) {
            return new \WP_Error('missing_engine', __('LearningModeEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $updated = \WebCareProScanner\Firewall\LearningModeEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Learning Mode 2.0 settings updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function update_honeytoken_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $updated = \WebCareProScanner\Firewall\HoneyTokenEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Honey-Token Bot Trap settings updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function unban_honeytoken_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field($params['ip'] ?? '');
        if (empty($ip)) {
            return new \WP_Error('missing_ip', __('IP address is required.', 'webcare-pro-security'), ['status' => 400]);
        }
        if (!class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Firewall\HoneyTokenEngine::unban_bot_ip($ip);
        return rest_ensure_response($result);
    }

    public static function reseed_db_canaries(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Firewall\HoneyTokenEngine::reseed_db_canaries();
        return rest_ensure_response($result);
    }

    public static function update_rate_limiter_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Firewall\AdaptiveRateLimiter')) {
            return new \WP_Error('missing_engine', __('AdaptiveRateLimiter not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $updated = \WebCareProScanner\Firewall\AdaptiveRateLimiter::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Adaptive Rate Limiter thresholds updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function get_distributed_shield_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Firewall\DistributedVelocityShield::get_telemetry()));
    }

    public static function update_distributed_shield_settings(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $updated = \WebCareProScanner\Firewall\DistributedVelocityShield::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Distributed velocity shield settings saved successfully.', 'webcare-pro-security'),
            'settings' => $updated,
            'status'   => \WebCareProScanner\Firewall\DistributedVelocityShield::get_telemetry(),
        ]);
    }

    public static function toggle_under_attack_mode(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params   = $request->get_json_params() ?: [];
        $active   = !empty($params['active']);
        $duration = max(60, min(86400, intval($params['duration'] ?? 900)));
        $action   = !empty($params['action']) ? sanitize_key($params['action']) : 'pow';
        $reason   = !empty($params['reason']) ? sanitize_text_field($params['reason']) : __('Manual administrator activation', 'webcare-pro-security');

        if ($active) {
            \WebCareProScanner\Firewall\DistributedVelocityShield::activate_under_attack(
                'manual_lockdown',
                $duration,
                $action,
                'manual',
                [
                    'failures'   => 0,
                    'unique_ips' => 0,
                    'surface'    => 'admin_manual',
                    'reason'     => $reason,
                ]
            );
            $msg = __('Under-Attack Mode manually activated.', 'webcare-pro-security');
        } else {
            \WebCareProScanner\Firewall\DistributedVelocityShield::deactivate_under_attack();
            $msg = __('Under-Attack Mode deactivated.', 'webcare-pro-security');
        }

        return rest_ensure_response([
            'success'      => true,
            'message'      => $msg,
            'under_attack' => \WebCareProScanner\Firewall\DistributedVelocityShield::get_under_attack_status(),
        ]);
    }

    public static function simulate_distributed_attack(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $type   = !empty($params['type']) ? sanitize_key($params['type']) : 'carding';

        $res = \WebCareProScanner\Firewall\DistributedVelocityShield::simulate_attack_swarm($type);

        return rest_ensure_response(array_merge([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: simulated swarm type */
                __('Simulated distributed %s attack generated. Check Under-Attack status.', 'webcare-pro-security'),
                esc_html($type)
            ),
        ], $res));
    }

    /**
     * Retrieve status and capabilities of the AST Taint Analysis Engine.
     */
    public static function get_taint_engine_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Malware\TaintAnalysisEngine')) {
            return new \WP_Error('missing_module', __('TaintAnalysisEngine module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $engine = new \WebCareProScanner\Malware\TaintAnalysisEngine();
        return rest_ensure_response(array_merge([
            'success' => true,
        ], $engine->get_telemetry()));
    }

    /**
     * Run on-demand AST Source-to-Sink Taint Flow Analysis on PHP code or file.
     */
    public static function analyze_code_taint_flow(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Malware\TaintAnalysisEngine')) {
            return new \WP_Error('missing_module', __('TaintAnalysisEngine module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $code = $request->get_param('code');
        $file_path = $request->get_param('file_path');

        $engine = new \WebCareProScanner\Malware\TaintAnalysisEngine();

        if (!empty($file_path)) {
            $sanitized_path = sanitize_text_field(wp_unslash($file_path));
            $finding = $engine->analyze_file($sanitized_path);
        } elseif (!empty($code)) {
            $raw_code = (string) $request->get_param('code');
            $finding = $engine->analyze_content($raw_code, 'sandbox_evaluation.php');
        } else {
            return new \WP_Error('missing_params', __('Please provide either "code" or "file_path" to analyze.', 'webcare-pro-security'), ['status' => 400]);
        }

        if ($finding !== null) {
            return rest_ensure_response([
                'success'     => true,
                'has_taint'   => true,
                'finding'     => $finding->to_array(),
                'taint_chain' => $finding->taint_chain,
                'message'     => __('Polymorphic taint flow detected into execution sink!', 'webcare-pro-security')
            ]);
        }

        return rest_ensure_response([
            'success'     => true,
            'has_taint'   => false,
            'finding'     => null,
            'taint_chain' => [],
            'message'     => __('Clean: No untrusted taint flow reached an execution sink.', 'webcare-pro-security')
        ]);
    }

    /**
     * Retrieve telemetry and status of the AI SEO & GEO Shield.
     */
    public static function get_geo_shield_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\GeoShieldService')) {
            return new \WP_Error('missing_module', __('GeoShieldService module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response(\WebCareProScanner\Content\GeoShieldService::get_telemetry());
    }

    /**
     * Save the pristine cryptographic baseline for /llms.txt and /llms-full.txt.
     */
    public static function save_geo_llms_baseline(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\GeoShieldService')) {
            return new \WP_Error('missing_module', __('GeoShieldService module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Content\GeoShieldService::save_llms_baseline();
        return rest_ensure_response($res);
    }

    /**
     * On-demand audit of HTML or content for GEO invisible cloaking and JSON-LD poisoning.
     */
    public static function audit_geo_content(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\GeoShieldService')) {
            return new \WP_Error('missing_module', __('GeoShieldService module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $raw_html = (string) $request->get_param('html');
        if (empty($raw_html)) {
            return new \WP_Error('missing_param', __('Please provide "html" content to audit.', 'webcare-pro-security'), ['status' => 400]);
        }

        $jsonld_hits = \WebCareProScanner\Content\GeoShieldService::audit_jsonld_schemas($raw_html);
        $cloak_hits  = \WebCareProScanner\Content\GeoShieldService::audit_geo_cloaking($raw_html);
        $all_hits    = array_merge($jsonld_hits, $cloak_hits);

        return rest_ensure_response([
            'success'     => true,
            'has_threats' => !empty($all_hits),
            'detections'  => $all_hits,
            'jsonld_hits' => count($jsonld_hits),
            'cloak_hits'  => count($cloak_hits),
            'message'     => !empty($all_hits)
                ? sprintf(
                    /* translators: %d: threat count */
                    __('GEO Audit: %d deceptive elements or poisoned schema attributes detected.', 'webcare-pro-security'),
                    count($all_hits)
                )
                : __('GEO Audit: Content verified clean. No cloaking or schema poisoning detected.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Retrieve telemetry status for Gutenberg Interactivity API & Block Directives defense.
     */
    public static function get_block_security_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\BlockDirectiveSanitizer')) {
            return new \WP_Error('missing_module', __('BlockDirectiveSanitizer module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response(\WebCareProScanner\Content\BlockDirectiveSanitizer::get_telemetry());
    }

    /**
     * On-demand audit or sanitization of Gutenberg block markup or HTML content.
     */
    public static function audit_block_directives(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\BlockDirectiveSanitizer')) {
            return new \WP_Error('missing_module', __('BlockDirectiveSanitizer module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $content = (string) $request->get_param('content');
        if (empty($content)) {
            return new \WP_Error('missing_param', __('Please provide "content" to audit.', 'webcare-pro-security'), ['status' => 400]);
        }

        $audit_hits = \WebCareProScanner\Content\BlockDirectiveSanitizer::audit_content($content);
        $sanitized  = \WebCareProScanner\Content\BlockDirectiveSanitizer::sanitize_content($content);

        return rest_ensure_response([
            'success'           => true,
            'has_threats'       => !empty($audit_hits),
            'detections'        => $audit_hits,
            'threat_count'      => count($audit_hits),
            'sanitized_content' => $sanitized['content'],
            'is_modified'       => $sanitized['modified'],
            'message'           => !empty($audit_hits)
                ? sprintf(
                    /* translators: %d: threat count */
                    __('Block Security: %d hostile directive(s) or sensitive bindings detected.', 'webcare-pro-security'),
                    count($audit_hits)
                )
                : __('Block Security: Block directives verified clean and valid.', 'webcare-pro-security'),
        ]);
    }

    // ==========================================
    // 17.6. Zero-Trust Identity, Session Forensics & JIT Elevation (Pillar 4)
    // ==========================================

    public static function get_identity_forensics_status(\WP_REST_Request $request) {
        $sessions_report = class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')
            ? \WebCareProScanner\Identity\SessionForensicsEngine::get_active_sessions_report()
            : [];
        $active_elevations = class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')
            ? \WebCareProScanner\Identity\EphemeralAdminEngine::get_active_elevations()
            : [];
        $elevation_history = class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')
            ? \WebCareProScanner\Identity\EphemeralAdminEngine::get_elevation_history(20)
            : [];
        $hibp_summary = class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor')
            ? \WebCareProScanner\Identity\HIBPBreachAuditor::get_summary()
            : [];

        $candidate_users = class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')
            ? \WebCareProScanner\Identity\EphemeralAdminEngine::get_candidate_users(200)
            : [];

        return rest_ensure_response([
            'success'           => true,
            'sessions_report'   => $sessions_report,
            'active_elevations' => $active_elevations,
            'elevation_history' => $elevation_history,
            'hibp_summary'      => $hibp_summary,
            'candidate_users'   => $candidate_users,
        ]);
    }

    public static function revoke_identity_session(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $user_id  = intval($params['user_id'] ?? 0);
        $verifier = sanitize_text_field($params['verifier'] ?? '');

        if (!$user_id || empty($verifier)) {
            return new \WP_Error('missing_params', __('User ID and session verifier are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\SessionForensicsEngine::revoke_session($user_id, $verifier);
        return rest_ensure_response($res);
    }

    public static function revoke_all_identity_sessions(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\SessionForensicsEngine::revoke_all_sessions($user_id);
        return rest_ensure_response($res);
    }

    public static function grant_identity_jit_elevation(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $user_id  = intval($params['user_id'] ?? 0);
        $duration = intval($params['duration_minutes'] ?? 60);
        $reason   = sanitize_text_field($params['reason'] ?? '');

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required for elevation.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')) {
            return new \WP_Error('missing_engine', __('EphemeralAdminEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\EphemeralAdminEngine::grant_elevation($user_id, $duration, $reason);
        return rest_ensure_response($res);
    }

    public static function revoke_identity_jit_elevation(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);
        $reason  = sanitize_text_field($params['reason'] ?? 'Manual revocation by administrator');

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')) {
            return new \WP_Error('missing_engine', __('EphemeralAdminEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\EphemeralAdminEngine::revoke_elevation($user_id, $reason);
        return rest_ensure_response($res);
    }

    public static function get_candidate_users_route(\WP_REST_Request $request) {
        $users = class_exists('\WebCareProScanner\Identity\EphemeralAdminEngine')
            ? \WebCareProScanner\Identity\EphemeralAdminEngine::get_candidate_users(200)
            : [];

        return rest_ensure_response([
            'success' => true,
            'users'   => $users,
        ]);
    }

    public static function audit_identity_privileged_users(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor')) {
            return new \WP_Error('missing_engine', __('HIBPBreachAuditor not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $report = \WebCareProScanner\Identity\HIBPBreachAuditor::audit_privileged_users();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function force_identity_password_reset(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor')) {
            return new \WP_Error('missing_engine', __('HIBPBreachAuditor not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\HIBPBreachAuditor::force_password_reset($user_id);
        return rest_ensure_response($res);
    }

    public static function update_identity_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $updated = \WebCareProScanner\Identity\SessionForensicsEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Identity forensics settings updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function dismiss_impossible_travel_alert(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $alert_id = sanitize_text_field($params['alert_id'] ?? '');

        if (empty($alert_id)) {
            return new \WP_Error('missing_alert_id', __('Alert ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\SessionForensicsEngine::dismiss_travel_alert($alert_id);
        return rest_ensure_response($res);
    }

    // ==========================================
    // 18. Unified WebCare Vault Status & Rotator
    // ==========================================

    public static function get_vault_status(\WP_REST_Request $request) {
        // 1. Quarantine stats
        $qm = new \WebCareProScanner\Quarantine\QuarantineManager();
        $quarantine_records = $qm->list_records();
        $q_active = 0;
        $q_restored = 0;
        foreach ($quarantine_records as $qr) {
            if (($qr['status'] ?? '') === 'quarantined') {
                $q_active++;
            } elseif (($qr['status'] ?? '') === 'restored') {
                $q_restored++;
            }
        }

        // 2. Database backup stats
        $db_backup = new \WebCareProScanner\Backup\DatabaseBackup();
        $db_backups = $db_backup->list_backups();
        $db_count = count($db_backups);
        $db_size_mb = 0;
        foreach ($db_backups as $b) {
            $db_size_mb += floatval($b['size_mb'] ?? 0);
        }

        // 3. Transactions & Missing Users stats
        $transactions = \WebCareProScanner\Remediation\TransactionalRemediation::list_transactions(50);
        $tx_count = count($transactions);
        $user_mgr = new \WebCareProScanner\WordPress\UserRemediationManager();
        $missing_users = $user_mgr->get_missing_user_backups();
        $missing_users_count = count($missing_users);

        // 4. Secret Vault & Key Rotator stats
        $key_source = 'wp_salt';
        $env_key = getenv('WEBCARE_VAULT_KEY');
        if (!empty($env_key)) {
            $key_source = 'env';
        } elseif (defined('WEBCARE_VAULT_KEY') && !empty(WEBCARE_VAULT_KEY)) {
            $key_source = 'constant';
        }

        $raw_key = \WebCareProScanner\Security\SecretVault::get_key();
        $key_fingerprint = substr(hash('sha256', $raw_key), 0, 16) . '...';
        $is_hex_key = defined('WEBCARE_VAULT_KEY') && strlen((string) WEBCARE_VAULT_KEY) === 64 && ctype_xdigit((string) WEBCARE_VAULT_KEY);

        $openssl_ok = function_exists('openssl_encrypt');
        $gcm_ok = $openssl_ok && in_array(\WebCareProScanner\Security\SecretVault::CIPHER_GCM, openssl_get_cipher_methods(), true);

        $settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
        $secret_fields = [
            'gemini_api_key'       => 'Google Gemini AI Key',
            'openai_api_key'       => 'OpenAI API Key',
            'claude_api_key'       => 'Anthropic Claude Key',
            'cloudflare_api_token' => 'Cloudflare API Token',
            'cloudflare_zone_id'   => 'Cloudflare Zone ID',
            'slack_webhook_url'    => 'Slack Webhook URL',
            'discord_webhook_url'  => 'Discord Webhook URL',
            'clickup_webhook_url'  => 'ClickUp Webhook URL',
            'asana_webhook_url'    => 'Asana Webhook URL',
            'generic_webhook_url'  => 'Generic Automation Webhook',
        ];

        $secrets_status = [];
        $encrypted_count = 0;
        foreach ($secret_fields as $field_key => $label) {
            $val = (string) ($settings[$field_key] ?? '');
            $is_set = !empty($val);
            $is_enc = $is_set && \WebCareProScanner\Security\SecretVault::is_encrypted($val);
            if ($is_enc) {
                $encrypted_count++;
            }
            $secrets_status[] = [
                'key'          => $field_key,
                'label'        => $label,
                'is_configured'=> $is_set,
                'is_encrypted' => $is_enc,
            ];
        }

        $rot_state = get_option(\WebCareProScanner\Security\VaultRotator::STATE_OPTION, ['status' => 'idle']);

        return rest_ensure_response([
            'success' => true,
            'quarantine' => [
                'total_records'  => count($quarantine_records),
                'active_threats' => $q_active,
                'restored_files' => $q_restored,
            ],
            'database' => [
                'count'    => $db_count,
                'total_mb' => round($db_size_mb, 2),
            ],
            'rollback' => [
                'transactions_count'  => $tx_count,
                'missing_users_count' => $missing_users_count,
                'missing_users'       => array_map(fn($u) => [
                    'user_id'    => $u['user_id'],
                    'user_login' => $u['user_login'],
                    'user_email' => $u['user_email'],
                ], $missing_users),
            ],
            'secrets' => [
                'cipher'              => 'AES-256-GCM AEAD',
                'key_source'          => $key_source,
                'key_fingerprint'     => $key_fingerprint,
                'is_constant_defined' => defined('WEBCARE_VAULT_KEY') && !empty(WEBCARE_VAULT_KEY),
                'is_hex_256'          => $is_hex_key,
                'openssl_available'   => $openssl_ok,
                'gcm_available'       => $gcm_ok,
                'encrypted_count'     => $encrypted_count,
                'fields'              => $secrets_status,
                'rotation_state'      => $rot_state,
            ],
        ]);
    }

    public static function rotate_vault_key(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: $request->get_params();
        $new_key = sanitize_text_field($params['new_key'] ?? '');
        $force   = !empty($params['force']);

        if (empty($new_key)) {
            $new_key = bin2hex(random_bytes(32));
        }

        $init = \WebCareProScanner\Security\VaultRotator::start_rotation($new_key, $force);
        if (is_wp_error($init)) {
            return $init;
        }

        $cont = \WebCareProScanner\Security\VaultRotator::continue_rotation(100);
        if (is_wp_error($cont)) {
            return $cont;
        }

        $commit = \WebCareProScanner\Security\VaultRotator::verify_and_commit();
        if (is_wp_error($commit)) {
            return $commit;
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('vault_secrets_rotated', [
                'severity' => 'high',
                'message'  => __('Secrets Vault Master Key / Cryptographic Salt was successfully rotated and re-encrypted.', 'webcare-pro-security'),
                'details'  => [
                    'Rotated At'     => current_time('mysql'),
                    'Rotated By'     => wp_get_current_user()->user_login ?: 'admin',
                    'Key Algorithm'  => 'AES-256-GCM',
                ],
            ]);
        }

        return rest_ensure_response([
            'success'          => true,
            'message'          => __('Vault encryption keys rotated and all credentials safely re-encrypted.', 'webcare-pro-security'),
            'new_key_material' => $new_key,
            'status'           => $commit,
        ]);
    }

    public static function rollback_vault_rotation(\WP_REST_Request $request) {
        $res = \WebCareProScanner\Security\VaultRotator::rollback();
        if (is_wp_error($res)) {
            return $res;
        }
        return rest_ensure_response([
            'success' => true,
            'message' => __('Vault key rotation rolled back to pre-rotation state.', 'webcare-pro-security'),
            'status'  => $res,
        ]);
    }

    public static function reset_vault_rotation(\WP_REST_Request $request) {
        \WebCareProScanner\Security\VaultRotator::reset_state();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Vault rotation state and locks cleared successfully.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Security\VaultRotator::get_status(),
        ]);
    }

    /**
     * Audit exposed sensitive files (.env, debug.log, backup.sql, .git/config, wp-config.php.bak)
     */
    public static function audit_exposed_sensitive_files(string $scan_id): array {
        $findings = [];
        $sensitive_files = [
            '.env'                 => ['severity' => 'critical', 'desc' => 'Environment configuration file containing plain-text database credentials, API keys, or JWT secrets.'],
            'debug.log'            => ['severity' => 'medium',   'desc' => 'WordPress debug log file containing stack traces, SQL errors, or sensitive payload data.'],
            'wp-content/debug.log' => ['severity' => 'medium',   'desc' => 'WordPress debug log in wp-content containing runtime exceptions and system filepaths.'],
            'wp-config.php.bak'    => ['severity' => 'critical', 'desc' => 'Backup copy of wp-config.php accessible via HTTP request, leaking raw database credentials.'],
            'wp-config.bak'        => ['severity' => 'critical', 'desc' => 'Backup copy of wp-config.php accessible via HTTP request.'],
            'wp-config.old'        => ['severity' => 'critical', 'desc' => 'Archived wp-config file leaking database secrets.'],
            '.git/config'          => ['severity' => 'high',     'desc' => 'Exposed Git version control repository exposing source code commits and deploy keys.'],
            'backup.sql'           => ['severity' => 'critical', 'desc' => 'Raw database dump backup file accessible in web root.'],
            'database.sql'         => ['severity' => 'critical', 'desc' => 'Raw database SQL dump file located in publicly accessible folder.'],
        ];

        foreach ($sensitive_files as $rel => $meta) {
            $abs = ABSPATH . $rel;
            if (file_exists($abs) && is_readable($abs)) {
                $size = @filesize($abs) ?: 0;
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'system-config',
                    'type'        => 'exposed_sensitive_file',
                    'severity'    => $meta['severity'],
                    'confidence'  => 100,
                    'file_path'   => $rel,
                    'description' => "Publicly accessible sensitive file found: {$rel}. {$meta['desc']}",
                    'evidence'    => "File size: {$size} bytes. Permissions: " . substr(sprintf('%o', fileperms($abs)), -4),
                ]);
            }
        }

        return $findings;
    }

    /**
     * Audit quarantine directory isolation & .htaccess protection
     */
    public static function audit_quarantine_exposure(string $scan_id): array {
        $findings = [];
        $quarantine_dir = \WebCareProScanner\Quarantine\QuarantineManager::get_quarantine_dir();
        if (!is_dir($quarantine_dir)) {
            return $findings;
        }

        $htaccess = rtrim($quarantine_dir, '/\\') . '/.htaccess';
        if (!file_exists($htaccess)) {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'quarantine',
                'type'        => 'quarantine_unprotected',
                'severity'    => 'high',
                'confidence'  => 95,
                'file_path'   => str_replace(ABSPATH, '', $quarantine_dir),
                'description' => 'Quarantine isolation storage is missing .htaccess web protection. Quarantined malware could potentially be executed or retrieved via direct URL requests.',
                'evidence'    => 'Missing .htaccess blocking directive in quarantine vault directory.'
            ]);
        } else {
            $content = (string) @file_get_contents($htaccess);
            if (strpos($content, 'Deny from all') === false && strpos($content, 'Require all denied') === false) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'quarantine',
                    'type'        => 'quarantine_permissive_access',
                    'severity'    => 'medium',
                    'confidence'  => 90,
                    'file_path'   => str_replace(ABSPATH, '', $htaccess),
                    'description' => 'Quarantine .htaccess directive does not include strict "Require all denied" or "Deny from all" access control.',
                    'evidence'    => 'Permissive quarantine web server rule.'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Audit visitor IP detection headers & reverse proxy trust with high-level architecture intelligence.
     *
     * Handles:
     * 1. Localhost / Docker / Local Development: Auto-suppressed (100% normal for local testing).
     * 2. Direct VPS / Dedicated / Shared Hosting: Verifies raw public visitor IP (Direct mode, healthy).
     * 3. Reverse Proxies & CDNs: Inspects all 8 standard proxy headers (Cloudflare, AWS ALB, Nginx, Fastly, Akamai, RFC 7239).
     * 4. WP-Cron & CLI executions: Ignores internal loopback runs to prevent false-positives.
     */
    public static function audit_visitor_ip_detection(string $scan_id): array {
        $findings = [];

        // 1. Check for CLI, WP-Cron, or internal self-scan contexts
        if ((php_sapi_name() === 'cli') || defined('WP_CLI') || (defined('DOING_CRON') && DOING_CRON)) {
            return [];
        }

        // 2. High-Level Localhost & Containerized Environment Intelligence
        $env_type = function_exists('wp_get_environment_type') ? wp_get_environment_type() : (defined('WP_ENVIRONMENT_TYPE') ? WP_ENVIRONMENT_TYPE : 'production');
        $is_local_env = in_array($env_type, ['local', 'development'], true);

        $site_url = get_site_url();
        $host = wp_parse_url($site_url, PHP_URL_HOST) ?: '';
        $is_local_host = in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || (bool) preg_match('/\.(local|test|site|internal|lan|docker|localwp|ddev)$/i', $host);

        $is_docker = file_exists('/.dockerenv')
            || (file_exists('/proc/1/cgroup') && strpos(@file_get_contents('/proc/1/cgroup'), 'docker') !== false);

        // If running in local development or Docker container environment, internal IPs are standard and safe
        if ($is_local_env || $is_local_host || $is_docker) {
            return [];
        }

        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        if (empty($remote_addr)) {
            return [];
        }

        // 3. Loopback Request Check (Server connecting to itself via HTTP loopback during background audit)
        $server_addr = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['SERVER_ADDR'])) : '';
        if ($remote_addr === '127.0.0.1' || $remote_addr === '::1' || ($server_addr && $remote_addr === $server_addr)) {
            return [];
        }

        // 4. Direct Public Connection Mode (VPS / Dedicated / Shared hosting with no CDN or reverse proxy)
        // If REMOTE_ADDR is already a public non-private IP, direct visitor logging is operating correctly!
        $is_public_remote = filter_var($remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
        if ($is_public_remote) {
            return [];
        }

        // 5. Multi-Architecture Reverse Proxy & CDN Header Detection
        // Inspects all 8 standard reverse proxy headers across Cloudflare, AWS ALB, Nginx, Fastly, Akamai, Traefik, RFC 7239
        $proxy_headers = [
            'HTTP_CF_CONNECTING_IP',       // Cloudflare
            'HTTP_X_FORWARDED_FOR',        // Standard Reverse Proxy / AWS ALB / GCP
            'HTTP_X_REAL_IP',              // Nginx Upstream
            'HTTP_TRUE_CLIENT_IP',         // Akamai & Cloudflare Enterprise
            'HTTP_FASTLY_CLIENT_IP',       // Fastly CDN
            'HTTP_FORWARDED',              // RFC 7239 Standard (Forwarded: for=...)
            'HTTP_X_CLUSTER_CLIENT_IP',    // Clustered Load Balancers
            'HTTP_CLIENT_IP',              // Apache mod_remoteip / Proxies
        ];

        foreach ($proxy_headers as $hdr) {
            if (!empty($_SERVER[$hdr])) {
                $raw_val = sanitize_text_field((string) wp_unslash($_SERVER[$hdr]));
                // RFC 7239 Forwarded: for=198.51.100.1
                if ($hdr === 'HTTP_FORWARDED' && preg_match('/for="?([^";,\s]+)"?/i', $raw_val, $fm)) {
                    $raw_val = $fm[1];
                }
                $first_ip = trim(explode(',', $raw_val)[0]);
                // If a valid IP was forwarded by any proxy/CDN, headers are operating properly
                if (filter_var($first_ip, FILTER_VALIDATE_IP)) {
                    return [];
                }
            }
        }

        // 6. Genuine Live Production Misconfiguration Alert:
        // A live production website on a public domain is receiving external traffic through a private upstream IP
        // with ZERO forwarding headers, collapsing all visitor IPs into a single internal proxy address.
        $evidence_payload = [
            'remote_addr'      => $remote_addr,
            'environment'      => $env_type,
            'is_server_config' => true,
            'is_network'       => true,
            'remediation'      => [
                'type'        => 'reverse_proxy_config',
                'description' => 'Configure your reverse proxy (Nginx, Apache, or Cloudflare) to pass standard visitor IP headers (X-Forwarded-For or CF-Connecting-IP), or define reverse proxy headers in wp-config.php.',
                'wp_config_snippet' => "if (isset(\$_SERVER['HTTP_X_FORWARDED_FOR'])) {\n    \$ips = explode(',', \$_SERVER['HTTP_X_FORWARDED_FOR']);\n    \$_SERVER['REMOTE_ADDR'] = trim(\$ips[0]);\n}",
            ],
        ];

        $findings[] = new \WebCareProScanner\Findings\Finding([
            'engine'      => 'ip-detection',
            'type'        => 'reverse_proxy_misconfigured',
            'severity'    => 'medium',
            'confidence'  => 85,
            'file_path'   => 'server:REMOTE_ADDR',
            'description' => "Server REMOTE_ADDR is an internal or loopback IP ({$remote_addr}) while no reverse proxy forwarding header was received. Rate limiting and IP bans may affect all visitors uniformly.",
            'evidence'    => wp_json_encode($evidence_payload)
        ]);

        return $findings;
    }

    /**
     * Audit password strength against common predictable dictionary terms
     */
    public static function audit_password_strength(string $scan_id): array {
        $findings = [];
        $common_passwords = [
            'password', '123456', '12345678', '123456789', 'admin', 'admin123',
            'root', 'welcome', 'qwerty', 'login', 'pass123', 'wordpress', 'master',
            'pass@123', 'admin@123', 'change_me', 'iloveyou'
        ];

        $admins = get_users(['role' => 'administrator', 'number' => 50]);
        foreach ($admins as $admin) {
            $test_passwords = array_unique(array_filter([
                $admin->user_login,
                strtolower($admin->user_login),
                $admin->user_nicename,
                $admin->display_name,
                strtolower(get_bloginfo('name')),
                ...$common_passwords,
            ]));

            foreach ($test_passwords as $weak_pwd) {
                if (strlen($weak_pwd) < 3) continue;
                if (wp_check_password($weak_pwd, $admin->user_pass, $admin->ID)) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'user-credentials',
                        'type'        => 'weak_admin_password',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => "user:{$admin->ID} ({$admin->user_login})",
                        'description' => "CRITICAL: Administrator account '{$admin->user_login}' has an extremely weak password matching common dictionary entries or account username.",
                        'evidence'    => "Password match verified against high-frequency attack wordlist. Immediate password change required."
                    ]);
                    break;
                }
            }
        }

        return $findings;
    }

    /**
     * Monitor disk space & inode capacity
     */
    public static function audit_disk_space(string $scan_id): array {
        $findings = [];
        $path = untrailingslashit(ABSPATH);
        $total = @disk_total_space($path);
        $free = @disk_free_space($path);

        if ($total && $free && $total > 0) {
            $used = $total - $free;
            $percent_used = round(($used / $total) * 100, 1);
            $free_mb = round($free / 1024 / 1024);

            if ($percent_used >= 95 || $free_mb < 250) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'system-storage',
                    'type'        => 'disk_space_critical',
                    'severity'    => 'critical',
                    'confidence'  => 100,
                    'file_path'   => 'system:storage:disk',
                    'description' => "Server disk space is dangerously exhausted ({$percent_used}% used, only {$free_mb} MB available). Risk of immediate database corruption, failed updates, and log write halts.",
                    'evidence'    => "Total: " . round($total / 1024 / 1024 / 1024, 2) . " GB, Free: " . round($free / 1024 / 1024 / 1024, 2) . " GB ({$percent_used}% used)."
                ]);
            } elseif ($percent_used >= 88) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'system-storage',
                    'type'        => 'disk_space_warning',
                    'severity'    => 'medium',
                    'confidence'  => 95,
                    'file_path'   => 'system:storage:disk',
                    'description' => "Server disk space usage is high ({$percent_used}% used, {$free_mb} MB available). Consider pruning old backups or log files.",
                    'evidence'    => "Used: {$percent_used}%."
                ]);
            }
        }

        return $findings;
    }

    /**
     * Monitor Web Application Firewall status
     */
    public static function audit_waf_status(string $scan_id): array {
        $findings = [];
        $waf_enabled = \WebCareProScanner\System\SettingsManager::get('waf_enabled', true);
        $waf_mode = \WebCareProScanner\System\SettingsManager::get('waf_mode', 'enabled');

        if (!$waf_enabled || $waf_mode === 'disabled') {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'firewall',
                'type'        => 'waf_inactive',
                'severity'    => 'high',
                'confidence'  => 100,
                'file_path'   => 'firewall:status',
                'description' => 'Web Application Firewall (WAF) is currently disabled. Incoming malicious HTTP payloads (SQLi, XSS, Path Traversal) are not being filtered at the application boundary.',
                'evidence'    => 'WAF state: disabled in plugin security settings.'
            ]);
        } elseif ($waf_mode === 'learning') {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'firewall',
                'type'        => 'waf_learning_mode',
                'severity'    => 'low',
                'confidence'  => 100,
                'file_path'   => 'firewall:status',
                'description' => 'Web Application Firewall is in Learning Mode. Requests are being inspected and logged but malicious requests are not actively blocked.',
                'evidence'    => 'WAF mode: learning.'
            ]);
        }

        return $findings;
    }

    /**
     * Reputation checks (Domain blocklist, Spamvertised, Spam IP)
     */
    public static function audit_reputation_checks(string $scan_id, array $opts): array {
        $findings = [];
        $site_url = get_bloginfo('url');
        $host = wp_parse_url($site_url, PHP_URL_HOST);

        // Allow test domain/IP override via options or filter for testing/verification
        $test_host = apply_filters('webcareproscan_test_reputation_domain', $opts['test_domain'] ?? null);
        if (!empty($test_host)) {
            $host = $test_host;
        }

        // Skip loopback/local dev hosts for public DNSBL checks unless a test domain is explicitly passed
        $is_local_host = in_array(strtolower((string)$host), ['localhost', '127.0.0.1', '::1'], true) || preg_match('/\.(local|test|example|invalid)$/i', (string)$host);

        // 1. Check if website is on a domain blocklist (Spamhaus DBL & SURBL)
        if (!empty($opts['check_domain_blocklist']) && !empty($host) && (!$is_local_host || !empty($test_host))) {
            // Forward lookup format: {domain}.dbl.spamhaus.org
            $dbl_query = "{$host}.dbl.spamhaus.org";
            $ip = @gethostbyname($dbl_query);
            // 127.0.1.x indicates legitimate Spamhaus DBL listing; 127.255.255.x indicates public resolver rate-limit
            if ($ip && $ip !== $dbl_query && strpos($ip, '127.0.1.') === 0) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'reputation',
                    'type'        => 'domain_blocklisted',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => "domain:{$host}",
                    'description' => "CRITICAL REPUTATION ALERT: The domain '{$host}' is listed on the Spamhaus Domain Blocklist (DBL) as spam, malicious, or compromised.",
                    'evidence'    => "Spamhaus DBL response code: {$ip}"
                ]);
            }
        }

        // 2. Check if website is being "Spamvertised" (SURBL multi.surbl.org)
        if (!empty($opts['check_spamvertised']) && !empty($host) && (!$is_local_host || !empty($test_host))) {
            $surbl_query = "{$host}.multi.surbl.org";
            $surbl_res = @gethostbyname($surbl_query);
            if ($surbl_res && $surbl_res !== $surbl_query && strpos($surbl_res, '127.0.0.') === 0) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'reputation',
                    'type'        => 'domain_spamvertised',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => "domain:{$host}",
                    'description' => "CRITICAL REPUTATION ALERT: The domain '{$host}' is listed on SURBL as actively 'Spamvertised' in bulk unsolicited email or phishing campaigns.",
                    'evidence'    => "SURBL return code: {$surbl_res}"
                ]);
            }
        }

        // 3. Check if website IP is generating spam (Spamcop, Barracuda, Spamhaus ZEN)
        if (!empty($opts['check_spam_ip'])) {
            $test_ip = apply_filters('webcareproscan_test_reputation_ip', $opts['test_ip'] ?? null);
            $raw_srv_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['SERVER_ADDR'])) : '';
            $server_ip = !empty($test_ip) ? $test_ip : ($raw_srv_ip ?: gethostbyname($host ?: 'localhost'));

            if (filter_var($server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || !empty($test_ip)) {
                $rev_ip = implode('.', array_reverse(explode('.', $server_ip)));

                // 3.1 Spamcop SCBL
                $spamcop_query = "{$rev_ip}.bl.spamcop.net";
                $sc_res = @gethostbyname($spamcop_query);
                if ($sc_res && $sc_res !== $spamcop_query && strpos($sc_res, '127.0.0.') === 0) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => "ip:{$server_ip}",
                        'description' => "Server outbound IP '{$server_ip}' is actively listed on the Spamcop Blocking List (SCBL) as an active source of unsolicited spam.",
                        'evidence'    => "Spamcop DNSBL code: {$sc_res}"
                    ]);
                }

                // 3.2 Barracuda Reputation Network (BRBL)
                $barracuda_query = "{$rev_ip}.b.barracudacentral.org";
                $bc_res = @gethostbyname($barracuda_query);
                if ($bc_res && $bc_res !== $barracuda_query && strpos($bc_res, '127.0.0.') === 0) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => "ip:{$server_ip}",
                        'description' => "Server outbound IP '{$server_ip}' is listed on the Barracuda Reputation Network blocklist (BRBL). Outbound transactional emails may be rejected as spam.",
                        'evidence'    => "Barracuda DNSBL code: {$bc_res}"
                    ]);
                }

                // 3.3 Spamhaus ZEN
                $zen_query = "{$rev_ip}.zen.spamhaus.org";
                $zen_res = @gethostbyname($zen_query);
                if ($zen_res && $zen_res !== $zen_query && strpos($zen_res, '127.0.0.') === 0) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => "ip:{$server_ip}",
                        'description' => "Server outbound IP '{$server_ip}' is listed on the Spamhaus ZEN anti-spam database. Outbound transactional emails may be rejected as spam.",
                        'evidence'    => "Spamhaus ZEN code: {$zen_res}"
                    ]);
                }
            }
        }

        return $findings;
    }

    // ==========================================
    // 16. Plugin Self-Defense & Anti-Tamper Endpoints
    // ==========================================

    public static function get_self_defense_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $last_audit = get_option(\WebCareProScanner\Security\PluginSelfDefense::DB_LAST_AUDIT_OPTION, null);
        if (!$last_audit) {
            $last_audit = \WebCareProScanner\Security\PluginSelfDefense::run_audit(false);
        }

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        return rest_ensure_response([
            'success'  => true,
            'audit'    => $last_audit,
            'settings' => [
                'watchdog_enabled' => !empty($settings['self_defense_watchdog_enabled']),
                'notify_email'     => !empty($settings['self_defense_notify_email']),
                'admin_email'      => get_option('admin_email', ''),
            ],
        ]);
    }

    public static function verify_plugin_self_defense(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $audit = \WebCareProScanner\Security\PluginSelfDefense::run_audit(true);

        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
            'message' => !empty($audit['has_issues'])
                ? __('Self-defense verification completed: anomalies detected in plugin files.', 'webcare-pro-security')
                : __('All plugin core files are 100% authentic, intact, and verified against the official release signature.', 'webcare-pro-security'),
        ]);
    }

    public static function audit_self_defense_against_github(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $res = \WebCareProScanner\Security\PluginSelfDefense::audit_against_github(true);
        return rest_ensure_response($res);
    }

    public static function restore_self_defense_file(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $params = $request->get_json_params();
        $path = sanitize_text_field($params['path'] ?? '');

        if (empty($path)) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('Path parameter is required for file restoration.', 'webcare-pro-security'),
            ]);
        }

        $res = \WebCareProScanner\Security\PluginSelfDefense::restore_file_from_github($path);
        return rest_ensure_response($res);
    }

    // =========================================================================
    // Pillar 5: Continuous Threat Intel Network & Automated Virtual Patching Ecosystem
    // =========================================================================

    public static function get_threat_intel_network(\WP_REST_Request $request) {
        $telemetry = ThreatIntelNetwork::get_network_telemetry();
        return rest_ensure_response([
            'success'   => true,
            'telemetry' => $telemetry,
        ]);
    }

    public static function sync_threat_intel_network(\WP_REST_Request $request) {
        $res = ThreatIntelNetwork::sync_all_feeds();
        $telemetry = ThreatIntelNetwork::get_network_telemetry();
        return rest_ensure_response([
            'success'   => true,
            'sync'      => $res,
            'telemetry' => $telemetry,
            'message'   => sprintf(
                /* translators: 1: total active threat IPs, 2: total Tor nodes */
                __('Threat intelligence feeds synchronized! Active pool: %1$d botnet IPs, %2$d Tor exit nodes.', 'webcare-pro-security'),
                $res['total_active_ips'] ?? 0,
                $res['tor_exit_nodes_count'] ?? 0
            ),
        ]);
    }

    public static function check_threat_intel_reputation(\WP_REST_Request $request) {
        $ip = sanitize_text_field($request->get_param('ip') ?: '');
        if (empty($ip)) {
            $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
        }

        $assessment = ThreatIntelNetwork::calculate_reputation_score($ip);
        return rest_ensure_response([
            'success'    => true,
            'assessment' => $assessment,
        ]);
    }

    public static function get_synthesized_virtual_patches(\WP_REST_Request $request) {
        $patches = VirtualPatchSynthesizer::get_synthesized_patches();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $cf_ready = !empty($settings['cloudflare_api_token']) && !empty($settings['cloudflare_zone_id']);

        return rest_ensure_response([
            'success'          => true,
            'patches'          => array_values($patches),
            'total'            => count($patches),
            'cloudflare_ready' => $cf_ready,
        ]);
    }

    public static function synthesize_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $result = VirtualPatchSynthesizer::synthesize_patch($params);

        if (!$result['success']) {
            return new \WP_Error('synthesis_failed', $result['message'], ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    public static function test_virtual_patch_simulation(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch = $params['patch'] ?? [];
        $custom_payloads = $params['custom_payloads'] ?? null;

        if (empty($patch) || empty($patch['php_rule']['regex'])) {
            return new \WP_Error('missing_patch_rule', __('Virtual patch definition and regex pattern are required for simulation.', 'webcare-pro-security'), ['status' => 400]);
        }

        $simulation = VirtualPatchSynthesizer::run_dryrun_simulation($patch, $custom_payloads);
        return rest_ensure_response([
            'success'    => true,
            'simulation' => $simulation,
        ]);
    }

    public static function deploy_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch = $params['patch'] ?? [];
        $deploy_cf = !empty($params['deploy_to_cloudflare']);

        if (empty($patch['patch_id'])) {
            return new \WP_Error('missing_patch_id', __('Valid patch definition with patch_id is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::save_synthesized_patch($patch, $deploy_cf);
        return rest_ensure_response($result);
    }

    public static function toggle_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field($params['patch_id'] ?? '');
        $enable = !empty($params['enable']);

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::toggle_synthesized_patch($patch_id, $enable);
        return rest_ensure_response($result);
    }

    public static function delete_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field($params['patch_id'] ?? '');

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::delete_synthesized_patch($patch_id);
        return rest_ensure_response($result);
    }

    public static function virtual_patch_cve_lookup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $cve_id = sanitize_text_field(wp_unslash($params['cve_id'] ?? ''));

        if (empty($cve_id)) {
            return new \WP_Error('missing_cve_id', __('CVE ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\CVEIntelligenceService::lookup_and_correlate($cve_id);
        if (!$result['success']) {
            return new \WP_Error('cve_lookup_failed', $result['message'], ['status' => 404]);
        }

        return rest_ensure_response($result);
    }

    public static function virtual_patch_deactivate_component(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $plugin_file = sanitize_text_field(wp_unslash($params['plugin_file'] ?? ''));

        if (empty($plugin_file)) {
            return new \WP_Error('missing_plugin_file', __('Target plugin file is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\CVEIntelligenceService::deactivate_vulnerable_plugin($plugin_file);
        if (!$result['success']) {
            return new \WP_Error('deactivation_failed', $result['message'], ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    // =========================================================================
    // 20. 2026 AI Threat Defense, MCP Governance & Decoy Ghost Routes Handlers
    // =========================================================================

    public static function get_ai_defense_status() {
        return rest_ensure_response([
            'success'        => true,
            'ghost_routes'   => \WebCareProScanner\Firewall\GhostRouteTrap::get_status(),
            'egress'         => \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status(),
            'prompt_guard'   => \WebCareProScanner\Security\PromptInjectionGuard::get_status(),
            'credentials'    => \WebCareProScanner\Security\CredentialExposureScanner::get_status(),
            'attack_surface' => \WebCareProScanner\WordPress\RestApiInventory::get_inventory(),
        ]);
    }

    public static function get_ghost_routes_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Firewall\GhostRouteTrap::get_status()));
    }

    public static function update_ghost_routes_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\Firewall\GhostRouteTrap::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Ghost route trap settings updated.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Firewall\GhostRouteTrap::get_status(),
        ]);
    }

    public static function get_egress_firewall_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status()));
    }

    public static function update_egress_firewall_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\Firewall\OutboundEgressFirewall::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Outbound egress firewall settings updated.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status(),
        ]);
    }

    public static function get_credential_exposure_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Security\CredentialExposureScanner::get_status()));
    }

    public static function scan_credential_exposure() {
        $report = \WebCareProScanner\Security\CredentialExposureScanner::run_scan(true);
        return rest_ensure_response(array_merge([
            'success' => true,
        ], $report));
    }

    public static function get_prompt_guard_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Security\PromptInjectionGuard::get_status()));
    }

    public static function update_prompt_guard_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\Security\PromptInjectionGuard::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Prompt injection guard settings updated.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Security\PromptInjectionGuard::get_status(),
        ]);
    }

    public static function test_prompt_injection(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $text    = !empty($params['text']) ? (string) $params['text'] : '';
        $context = !empty($params['context']) ? sanitize_key($params['context']) : 'generic';

        if (trim($text) === '') {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Prompt text is required for analysis.', 'webcare-pro-security'),
            ], 400);
        }

        $analysis = \WebCareProScanner\Security\PromptInjectionGuard::inspect_prompt($text, $context);

        return rest_ensure_response([
            'success'  => true,
            'analysis' => $analysis,
        ]);
    }

    public static function get_attack_surface_inventory() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\WordPress\RestApiInventory::get_inventory()));
    }

    public static function update_attack_surface_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\WordPress\RestApiInventory::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Attack surface defense settings updated.', 'webcare-pro-security'),
            'data'    => \WebCareProScanner\WordPress\RestApiInventory::get_inventory(),
        ]);
    }

    /**
     * Export complete REST API & wp_ajax_nopriv attack surface inventory, PHP Reflection handler provenance,
     * deduplicated cryptographic file hash index, active shields, and correlated WAF incident logs as JSON.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response|void
     */
    public static function export_attack_surface_bundle(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\WordPress\\RestApiInventory')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('REST API & AJAX Attack Surface inventory engine is unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $inventory = \WebCareProScanner\WordPress\RestApiInventory::get_inventory(true);
        $routes    = is_array($inventory['routes'] ?? null) ? $inventory['routes'] : [];
        $ajax_list = is_array($inventory['ajax_nopriv'] ?? null) ? $inventory['ajax_nopriv'] : [];

        // 1. Build deduplicated cryptographic file hash index across REST & AJAX handler files
        $handler_file_index = [];
        $index_handler_file = static function (array $handler, string $kind) use (&$handler_file_index) {
            $rel = isset($handler['file']) ? (string) $handler['file'] : '';
            if ($rel === '') {
                return;
            }
            if (!isset($handler_file_index[$rel])) {
                $handler_file_index[$rel] = [
                    'file'            => $rel,
                    'owner_component' => $handler['owner_component'] ?? 'Unknown',
                    'owner_type'      => $handler['owner_type'] ?? 'unknown',
                    'origin_type'     => $handler['origin_type'] ?? 'custom_unmanaged',
                    'vendor_name'     => $handler['vendor_name'] ?? null,
                    'is_official'     => !empty($handler['is_official']),
                    'is_known_vendor' => !empty($handler['is_known_vendor']),
                    'checksum_status' => $handler['checksum_status'] ?? 'not_available',
                    'file_sha256'     => $handler['file_sha256'] ?? null,
                    'file_md5'        => $handler['file_md5'] ?? null,
                    'rest_routes_cnt' => 0,
                    'ajax_hooks_cnt'  => 0,
                ];
                if (!empty($handler['known_vendor_lib'])) {
                    $handler_file_index[$rel]['known_vendor_lib'] = $handler['known_vendor_lib'];
                }
            }
            if ($kind === 'rest') {
                $handler_file_index[$rel]['rest_routes_cnt']++;
            } else {
                $handler_file_index[$rel]['ajax_hooks_cnt']++;
            }
        };

        foreach ($routes as $r) {
            if (!empty($r['handler']) && is_array($r['handler'])) {
                $index_handler_file($r['handler'], 'rest');
            }
        }
        foreach ($ajax_list as $ax) {
            if (!empty($ax['handler']) && is_array($ax['handler'])) {
                $index_handler_file($ax['handler'], 'ajax');
            }
        }

        // 2. Collect WAF logs & cross-reference hits against registered REST routes and nopriv AJAX actions
        $log_ctx          = self::build_modular_log_analysis_context();
        $all_log_records  = is_array($log_ctx['recent_log_records'] ?? null) ? $log_ctx['recent_log_records'] : [];
        $surface_logs     = [];
        $hits_by_route    = [];
        $hits_by_ajax_act = [];

        foreach ($all_log_records as $rec) {
            $uri     = (string) ($rec['request_uri'] ?? '');
            $payload = (string) ($rec['payload_sample'] ?? '');
            $rid     = (string) ($rec['rule_id'] ?? '');
            $is_rest = str_contains($uri, '/wp-json/') || str_contains($uri, 'rest_route=');
            $is_ajax = str_contains($uri, 'admin-ajax.php');
            $is_mod  = str_starts_with($rid, 'MOD-REST-') || str_starts_with($rid, 'MOD-AJAX-');

            if (!$is_rest && !$is_ajax && !$is_mod) {
                continue;
            }

            $surface_logs[] = $rec;

            if ($is_rest) {
                $matched_route = '';
                $parsed_q = wp_parse_url($uri, PHP_URL_QUERY);
                $q_params = [];
                if (is_string($parsed_q) && $parsed_q !== '') {
                    parse_str($parsed_q, $q_params);
                }
                if (!empty($q_params['rest_route']) && is_string($q_params['rest_route'])) {
                    $matched_route = '/' . ltrim($q_params['rest_route'], '/');
                } else {
                    $parsed_path = (string) (wp_parse_url($uri, PHP_URL_PATH) ?: '');
                    $pos         = strpos($parsed_path, '/wp-json');
                    if ($pos !== false) {
                        $matched_route = '/' . ltrim(substr($parsed_path, $pos + strlen('/wp-json')), '/');
                    }
                }
                if ($matched_route !== '') {
                    $rkey = strtolower(rtrim($matched_route, '/') ?: '/');
                    if (!isset($hits_by_route[$rkey])) {
                        $hits_by_route[$rkey] = [
                            'route_sample'  => $matched_route,
                            'hits'          => 0,
                            'actions_taken' => [],
                            'rule_ids'      => [],
                            'last_seen'     => $rec['created_at'] ?? '',
                        ];
                    }
                    $hits_by_route[$rkey]['hits']++;
                    if (!empty($rec['action_taken']) && !in_array($rec['action_taken'], $hits_by_route[$rkey]['actions_taken'], true)) {
                        $hits_by_route[$rkey]['actions_taken'][] = $rec['action_taken'];
                    }
                    if ($rid !== '' && !in_array($rid, $hits_by_route[$rkey]['rule_ids'], true)) {
                        $hits_by_route[$rkey]['rule_ids'][] = $rid;
                    }
                }
            }

            if ($is_ajax) {
                $ajax_act = '';
                $parsed_q = wp_parse_url($uri, PHP_URL_QUERY);
                $q_params = [];
                if (is_string($parsed_q) && $parsed_q !== '') {
                    parse_str($parsed_q, $q_params);
                }
                if (!empty($q_params['action']) && is_string($q_params['action'])) {
                    $ajax_act = sanitize_key($q_params['action']);
                } elseif (preg_match('/(?:^|[&\s,;=\'"(])action\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]+)/', $payload, $m)) {
                    $ajax_act = sanitize_key($m[1]);
                }
                if ($ajax_act !== '') {
                    $akey = strtolower($ajax_act);
                    if (!isset($hits_by_ajax_act[$akey])) {
                        $hits_by_ajax_act[$akey] = [
                            'action'        => $ajax_act,
                            'hits'          => 0,
                            'actions_taken' => [],
                            'rule_ids'      => [],
                            'last_seen'     => $rec['created_at'] ?? '',
                        ];
                    }
                    $hits_by_ajax_act[$akey]['hits']++;
                    if (!empty($rec['action_taken']) && !in_array($rec['action_taken'], $hits_by_ajax_act[$akey]['actions_taken'], true)) {
                        $hits_by_ajax_act[$akey]['actions_taken'][] = $rec['action_taken'];
                    }
                    if ($rid !== '' && !in_array($rid, $hits_by_ajax_act[$akey]['rule_ids'], true)) {
                        $hits_by_ajax_act[$akey]['rule_ids'][] = $rid;
                    }
                }
            }
        }

        // Annotate route & AJAX items with matching log telemetry counts
        foreach ($routes as &$rt) {
            $rkey = strtolower(rtrim((string) ($rt['route'] ?? ''), '/') ?: '/');
            if (isset($hits_by_route[$rkey])) {
                $rt['recent_waf_hits'] = $hits_by_route[$rkey];
            }
        }
        unset($rt);

        foreach ($ajax_list as &$ax) {
            $akey = strtolower((string) ($ax['action'] ?? ''));
            if ($akey !== '' && isset($hits_by_ajax_act[$akey])) {
                $ax['recent_waf_hits'] = $hits_by_ajax_act[$akey];
            }
        }
        unset($ax);

        // 3. Gather active Modular WAF rules protecting REST / AJAX surfaces
        $active_surface_rules = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            $all_rules = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_active_rules();
            foreach ($all_rules as $rule) {
                $cat = $rule['category'] ?? '';
                if ($cat === 'rest_guard' || $cat === 'ajax_shield' || str_contains((string) ($rule['target_uri'] ?? ''), 'wp-json') || str_contains((string) ($rule['target_uri'] ?? ''), 'admin-ajax.php')) {
                    $active_surface_rules[] = $rule;
                }
            }
        }

        // 4. Environment & breakdown statistics
        $origin_breakdown = [];
        $flag_stats = [
            'public_routes'               => (int) ($inventory['public_routes_count'] ?? 0),
            'discovery_index_routes'      => (int) ($inventory['discovery_index_routes_count'] ?? 0),
            'storefront_guarded_routes'   => (int) ($inventory['storefront_guarded_routes_count'] ?? 0),
            'unauth_write_routes'         => (int) ($inventory['unauth_post_routes'] ?? 0),
            'mixed_auth_protected_routes' => (int) ($inventory['mixed_auth_protected_routes'] ?? 0),
            'locked_routes'               => 0,
            'shielded_routes'             => 0,
            'unguarded_nopriv_ajax'       => (int) ($inventory['unguarded_nopriv_ajax_count'] ?? 0),
            'protected_nopriv_ajax'       => (int) ($inventory['protected_nopriv_ajax_count'] ?? 0),
            'shielded_ajax_nopriv'        => 0,
        ];
        foreach ($routes as $rt) {
            if (!empty($rt['is_locked'])) {
                $flag_stats['locked_routes']++;
            }
            if (!empty($rt['shielded_by'])) {
                $flag_stats['shielded_routes']++;
            }
            $orig = $rt['handler']['origin_type'] ?? 'unknown';
            $origin_breakdown[$orig] = ($origin_breakdown[$orig] ?? 0) + 1;
        }
        foreach ($ajax_list as $ax) {
            if (!empty($ax['shielded_by'])) {
                $flag_stats['shielded_ajax_nopriv']++;
            }
        }

        $active_theme   = wp_get_theme();
        $site_host      = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'localhost';
        $preload_active = defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE;

        $payload = [
            'success'               => true,
            'webcare_export_type'   => 'attack_surface_forensic_bundle',
            'format_version'        => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
            'exported_at'           => gmdate('c'),
            'exported_timestamp'    => time(),
            'author'                => 'Mir Alamin (WebCare Pro)',
            'environment'           => [
                'site_url'           => get_site_url(),
                'home_url'           => get_home_url(),
                'wordpress_version'  => $GLOBALS['wp_version'] ?? 'Unknown',
                'php_version'        => PHP_VERSION,
                'server_software'    => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
                'webcare_version'    => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
                'preload_waf_active' => $preload_active,
                'active_theme'       => [
                    'name'       => $active_theme ? $active_theme->get('Name') : '',
                    'version'    => $active_theme ? $active_theme->get('Version') : '',
                    'template'   => $active_theme ? $active_theme->get_template() : '',
                    'stylesheet' => $active_theme ? $active_theme->get_stylesheet() : '',
                ],
            ],
            'summary'               => array_merge([
                'total_routes'               => count($routes),
                'total_namespaces'           => (int) ($inventory['total_namespaces'] ?? 0),
                'total_nopriv_ajax'          => count($ajax_list),
                'unique_handler_files_hashed'=> count($handler_file_index),
                'active_surface_rules_count' => count($active_surface_rules),
                'surface_waf_events_count'   => count($surface_logs),
                'total_modular_events_30d'   => (int) ($log_ctx['total_events_analyzed'] ?? 0),
                'routes_by_origin_type'      => $origin_breakdown,
            ], $flag_stats),
            'settings'              => $inventory['settings'] ?? [],
            'namespaces'            => $inventory['namespaces'] ?? [],
            'routes'                => $routes,
            'ajax_nopriv'           => $ajax_list,
            'active_surface_rules'  => $active_surface_rules,
            'handler_file_hash_index'=> array_values($handler_file_index),
            'log_analysis_context'  => [
                'surface_events_matched'   => count($surface_logs),
                'hits_by_rest_route'       => $hits_by_route,
                'hits_by_ajax_action'      => $hits_by_ajax_act,
                'hits_by_rule'             => $log_ctx['hits_by_rule'] ?? [],
                'hits_by_action'           => $log_ctx['hits_by_action'] ?? [],
                'top_target_uris'          => $log_ctx['top_target_uris'] ?? [],
                'top_user_agents'          => $log_ctx['top_user_agents'] ?? [],
                'preboot_fail2ban_lines'   => $log_ctx['preboot_fail2ban_lines'] ?? [],
                'recent_surface_waf_logs'  => array_slice($surface_logs, 0, 200),
            ],
        ];

        $is_download = !empty($request->get_param('download'));
        if ($is_download) {
            $filename = 'webcare-attack-surface-' . sanitize_file_name($site_host) . '-' . gmdate('Y-m-d') . '.json';
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('X-Content-Type-Options: nosniff');
            echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            exit;
        }

        return new \WP_REST_Response($payload, 200);
    }

    // ==========================================
    // Phase 5: 72-Hour Reinfection Watchdog Handlers
    // ==========================================

    public static function get_reinfection_watchdog_status() {
        return rest_ensure_response(\WebCareProScanner\Quarantine\ReinfectionWatchdog::get_status());
    }

    public static function register_reinfection_watch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = sanitize_text_field($params['file_path'] ?? '');
        $status = sanitize_key($params['expected_status'] ?? 'deleted');
        $clean_hash = sanitize_text_field($params['clean_hash'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? '');

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Quarantine\ReinfectionWatchdog::register_watch($file_path, $status, $clean_hash ?: null, $reason);
        return rest_ensure_response($res);
    }

    public static function dismiss_reinfection_watch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $watch_id = sanitize_key($params['watch_id'] ?? '');
        if (empty($watch_id)) {
            return new \WP_Error('missing_param', __('Missing watch_id parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Quarantine\ReinfectionWatchdog::dismiss_watch($watch_id);
        return rest_ensure_response([
            'success' => $res,
            'message' => $res ? __('Watchdog monitor dismissed.', 'webcare-pro-security') : __('Watch not found.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Quarantine\ReinfectionWatchdog::get_status(),
        ]);
    }

    public static function check_reinfection_watchdog_now() {
        $res = \WebCareProScanner\Quarantine\ReinfectionWatchdog::inspect_all_monitors();
        return rest_ensure_response(array_merge([
            'status' => \WebCareProScanner\Quarantine\ReinfectionWatchdog::get_status(),
        ], $res));
    }

    // ==========================================
    // Phase 5: "Time-Machine" Local Snapshots Handlers
    // ==========================================

    public static function get_local_snapshots_list() {
        return rest_ensure_response(\WebCareProScanner\Integrity\LocalSnapshotManager::list_snapshots());
    }

    public static function create_local_snapshot(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $target = sanitize_text_field($params['target_rel_path'] ?? '');
        $label = sanitize_text_field($params['label'] ?? '');

        if (empty($target)) {
            return new \WP_Error('missing_target', __('Target relative directory path is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::create_snapshot($target, $label);
        return rest_ensure_response($res);
    }

    public static function compare_local_snapshot(\WP_REST_Request $request) {
        $snap_id = sanitize_key($request->get_param('snapshot_id') ?: '');
        if (empty($snap_id)) {
            return new \WP_Error('missing_id', __('Snapshot ID required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::compare_snapshot($snap_id);
        return rest_ensure_response($res);
    }

    public static function get_local_snapshot_diff(\WP_REST_Request $request) {
        $snap_id = sanitize_key($request->get_param('snapshot_id') ?: '');
        $rel_path = sanitize_text_field($request->get_param('rel_path') ?: '');

        if (empty($snap_id) || empty($rel_path)) {
            return new \WP_Error('missing_params', __('Snapshot ID and rel_path are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::get_file_diff($snap_id, $rel_path);
        return rest_ensure_response($res);
    }

    public static function restore_local_snapshot_file(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $snap_id = sanitize_key($params['snapshot_id'] ?? '');
        $rel_path = sanitize_text_field($params['rel_path'] ?? '');

        if (empty($snap_id) || empty($rel_path)) {
            return new \WP_Error('missing_params', __('Snapshot ID and rel_path are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::restore_file($snap_id, $rel_path);
        return rest_ensure_response($res);
    }

    public static function delete_local_snapshot(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $snap_id = sanitize_key($params['snapshot_id'] ?? '');

        if (empty($snap_id)) {
            return new \WP_Error('missing_id', __('Snapshot ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $deleted = \WebCareProScanner\Integrity\LocalSnapshotManager::delete_snapshot($snap_id);
        return rest_ensure_response([
            'success'   => $deleted,
            'message'   => $deleted ? __('Snapshot deleted.', 'webcare-pro-security') : __('Snapshot not found.', 'webcare-pro-security'),
            'snapshots' => \WebCareProScanner\Integrity\LocalSnapshotManager::list_snapshots(),
        ]);
    }

    // ==========================================
    // Phase 5: Domain Reputation & SSL Sentinel Handlers
    // ==========================================

    public static function get_domain_reputation_status() {
        return rest_ensure_response(\WebCareProScanner\Firewall\DomainReputationMonitor::run_reputation_audit(false));
    }

    public static function check_domain_reputation_now() {
        return rest_ensure_response(\WebCareProScanner\Firewall\DomainReputationMonitor::run_reputation_audit(true));
    }

    // ==========================================
    // Phase 6: Threat Correlation Hierarchy Handlers
    // ==========================================

    public static function get_correlation_hierarchy() {
        $engine = new \WebCareProScanner\Findings\CorrelationEngine();
        return rest_ensure_response($engine->generate_telemetry_hierarchy());
    }

    // ==========================================
    // Phase 6: WebAuthn Passkeys (Biometric FIDO2) Handlers
    // ==========================================

    public static function webauthn_register_options(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Authentication required.', 'webcare-pro-security'), ['status' => 401]);
        }
        return rest_ensure_response(\WebCareProScanner\Auth\WebAuthnManager::generate_registration_options($user_id));
    }

    public static function webauthn_register_verify(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Authentication required.', 'webcare-pro-security'), ['status' => 401]);
        }
        $params = $request->get_json_params() ?: [];
        $payload = is_array($params['payload'] ?? null) ? $params['payload'] : [];
        $label = sanitize_text_field(wp_unslash($params['label'] ?? ''));

        $res = \WebCareProScanner\Auth\WebAuthnManager::verify_registration($user_id, $payload, $label);
        if (empty($res['success'])) {
            return new \WP_Error('verification_failed', $res['message'] ?? __('Passkey registration failed.', 'webcare-pro-security'), ['status' => 400]);
        }
        return rest_ensure_response($res);
    }

    public static function webauthn_get_credentials(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        return rest_ensure_response([
            'success'     => true,
            'credentials' => \WebCareProScanner\Auth\WebAuthnManager::get_user_credentials($user_id),
            'rp_id'       => \WebCareProScanner\Auth\WebAuthnManager::get_rp_id(),
        ]);
    }

    public static function webauthn_delete_credential(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        $params = $request->get_json_params() ?: [];
        $credential_id = sanitize_text_field(wp_unslash($params['credential_id'] ?? ''));

        if (empty($credential_id)) {
            return new \WP_Error('missing_id', __('Credential ID required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $deleted = \WebCareProScanner\Auth\WebAuthnManager::delete_credential($user_id, $credential_id);
        return rest_ensure_response([
            'success'     => $deleted,
            'message'     => $deleted ? __('Passkey removed successfully.', 'webcare-pro-security') : __('Passkey not found.', 'webcare-pro-security'),
            'credentials' => \WebCareProScanner\Auth\WebAuthnManager::get_user_credentials($user_id),
        ]);
    }

    /**
     * Rate-limiting and anti-enumeration permission check for public WebAuthn routes.
     * Enforces proxy-aware sliding window rate limits per IP and per account.
     *
     * @param \WP_REST_Request $request
     * @return true|\WP_Error
     */
    public static function check_webauthn_public_rate_limit(\WP_REST_Request $request) {
        $client_ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

        $route = (string) $request->get_route();
        $is_verify = strpos($route, 'login-verify') !== false;
        $action = $is_verify ? 'verify' : 'options';
        $max_ip_attempts = $is_verify ? 10 : 25; // 10 verifications / 5 min, 25 options / 5 min
        $window = 300;

        if (class_exists('\\WebCareProScanner\\Auth\\WebAuthnManager')) {
            if (!\WebCareProScanner\Auth\WebAuthnManager::check_ip_rate_limit($action, $max_ip_attempts, $window)) {
                return new \WP_Error(
                    'rest_rate_limited',
                    __('Too many authentication requests from this IP. Please wait a few minutes.', 'webcare-pro-security'),
                    ['status' => 429]
                );
            }
        }

        // Per-account rate limiting when login_hint or username is provided
        $params = $request->get_json_params() ?: [];
        $username = !empty($params['username']) ? sanitize_text_field(wp_unslash($params['username'])) : '';
        if (!empty($username)) {
            $acc_key = 'webcareproscan_wa_acc_' . md5(strtolower($username));
            $acc_attempts = (int) get_transient($acc_key);
            if ($acc_attempts >= 15) {
                return new \WP_Error(
                    'rest_account_rate_limited',
                    __('Too many authentication attempts for this account. Please wait a few minutes.', 'webcare-pro-security'),
                    ['status' => 429]
                );
            }
            set_transient($acc_key, $acc_attempts + 1, $window);
        }

        return true;
    }

    public static function webauthn_login_options(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $username = sanitize_text_field(wp_unslash($params['username'] ?? ''));
        $options = \WebCareProScanner\Auth\WebAuthnManager::generate_login_options($username);
        if (empty($options['success'])) {
            return new \WP_Error(
                'options_rate_limited',
                $options['message'] ?? __('Too many passkey requests. Please wait a few minutes.', 'webcare-pro-security'),
                ['status' => 429]
            );
        }
        return rest_ensure_response($options);
    }

    public static function webauthn_login_verify(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $session_id = sanitize_key($params['session_id'] ?? '');
        $payload = is_array($params['payload'] ?? null) ? $params['payload'] : [];

        if (empty($session_id) || empty($payload)) {
            return new \WP_Error('missing_params', __('Authentication session and payload required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Auth\WebAuthnManager::verify_login($session_id, $payload);
        if (empty($res['success'])) {
            return new \WP_Error('login_failed', $res['message'] ?? __('Biometric login failed.', 'webcare-pro-security'), ['status' => 401]);
        }
        return rest_ensure_response($res);
    }

    // ==========================================
    // Phase 6: Server Security Verification & Caddy
    // ==========================================

    public static function verify_server_security_rules() {
        return rest_ensure_response(\WebCareProScanner\Firewall\ServerSecurityEngine::verify_rule_enforcement());
    }

    public static function get_caddy_server_config() {
        $options = \WebCareProScanner\Firewall\ServerSecurityEngine::get_options();
        $config = \WebCareProScanner\Firewall\ServerSecurityEngine::generate_caddy_config($options);
        return rest_ensure_response([
            'success'   => true,
            'config'    => $config,
            'file_info' => \WebCareProScanner\Firewall\ServerSecurityEngine::get_file_info(),
        ]);
    }

    // ==========================================
    // 21. Activity & Forensic Audit Log Handlers
    // ==========================================

    public static function get_activity_logs(\WP_REST_Request $request) {
        $limit      = max(1, min(100, intval($request->get_param('limit') ?: 50)));
        $page       = max(1, intval($request->get_param('page') ?: 1));
        $category   = sanitize_key($request->get_param('category') ?: '');
        $actor_type = sanitize_key($request->get_param('actor_type') ?: '');
        $severity   = sanitize_key($request->get_param('severity') ?: '');
        $search     = sanitize_text_field($request->get_param('search') ?: '');

        $result = \WebCareProScanner\System\WebCareActivityLogger::query_records([
            'actor_type' => $actor_type,
            'category'   => $category,
            'limit'      => $limit,
            'page'       => $page,
            'search'     => $search,
            'severity'   => $severity,
        ]);

        $settings = get_option('webcareproscan_activity_log_settings', []);
        $tamper_alert = get_option('webcareproscan_activity_tamper_active', null);

        return rest_ensure_response([
            'current_page'   => $result['current_page'] ?? $page,
            'has_next'       => $result['has_next'] ?? false,
            'has_prev'       => $result['has_prev'] ?? false,
            'per_page'       => $result['per_page'] ?? $limit,
            'records'        => $result['records'],
            'settings'       => [
                'retention_days'     => isset($settings['retention_days']) ? (int) $settings['retention_days'] : 30,
                'tamper_webhook_url' => $settings['tamper_webhook_url'] ?? '',
            ],
            'success'        => true,
            'tamper_alert'   => $tamper_alert,
            'total'          => $result['total'] ?? count($result['records']),
            'total_pages'    => $result['total_pages'] ?? 1,
            'total_read'     => $result['total_read'],
        ]);
    }

    public static function verify_activity_logs_integrity(\WP_REST_Request $request) {
        $report = \WebCareProScanner\System\WebCareActivityLogger::verify_integrity();
        return rest_ensure_response([
            'report'  => $report,
            'success' => true,
        ]);
    }

    public static function export_activity_logs(\WP_REST_Request $request) {
        $format              = sanitize_key($request->get_param('format') ?: 'csv');
        $category            = sanitize_key($request->get_param('category') ?: '');
        $actor_type          = sanitize_key($request->get_param('actor_type') ?: '');
        $severity            = sanitize_key($request->get_param('severity') ?: '');
        $search              = sanitize_text_field($request->get_param('search') ?: '');
        $date                = sanitize_text_field($request->get_param('date') ?: '');
        $include_system_info = !empty($request->get_param('include_system_info'));

        $result = \WebCareProScanner\System\WebCareActivityLogger::query_records([
            'actor_type' => $actor_type,
            'category'   => $category,
            'is_export'  => true,
            'limit'      => 10000,
            'search'     => $search,
            'severity'   => $severity,
            'date'       => $date,
        ]);

        $host_raw   = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
        $domain     = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
        $date_token = $date && preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) ? $date : gmdate('Y-m-d');
        $time_token = gmdate('His');
        $rand_token = substr(wp_generate_password(8, false), 0, 5);
        $filename   = "activity-logs-{$date_token}-{$time_token}-{$domain}-{$rand_token}.{$format}";

        if ($format === 'json') {
            \WebCareProScanner\System\ActivityLogs\ActivityExporter::stream_json($result['records'], $filename, $include_system_info);
        } else {
            \WebCareProScanner\System\ActivityLogs\ActivityExporter::stream_csv($result['records'], $filename, $include_system_info);
        }
        exit;
    }

    public static function prune_activity_logs(\WP_REST_Request $request) {
        $results = \WebCareProScanner\System\ActivityLogs\ActivityRetention::prune_expired_partitions();

        // Audit Trail: Log manual partition prune execution
        \WebCareProScanner\System\WebCareActivityLogger::notice(
            'logs_pruned',
            'retention',
            [
                'description'  => sprintf('Pruned %d expired partition file(s) beyond 7-day minimum immutability.', $results['pruned_count']),
                'pruned_count' => (int) $results['pruned_count'],
                'pruned_files' => $results['files'],
            ]
        );

        /* translators: %d: Number of pruned partitions */
        $message = sprintf(__('Pruned %d expired partition(s).', 'webcare-pro-security'), $results['pruned_count']);

        return rest_ensure_response([
            'message'      => $message,
            'pruned_count' => $results['pruned_count'],
            'pruned_files' => $results['files'],
            'success'      => true,
        ]);
    }

    public static function acknowledge_activity_tamper_alert(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $incident_id = sanitize_key($params['incident_id'] ?? '');

        \WebCareProScanner\System\ActivityLogs\ActivityTamperNotifier::acknowledge_alert($incident_id);

        return rest_ensure_response([
            'message' => __('Tamper security incident acknowledged and dismissed.', 'webcare-pro-security'),
            'success' => true,
        ]);
    }

    /**
     * Get Site Archetype Intelligence evaluation & recommendation matrix.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_site_advisor_evaluation(\WP_REST_Request $request) {
        $evaluation = \WebCareProScanner\Advisor\SiteAdvisorEngine::evaluate();
        return rest_ensure_response($evaluation);
    }

    /**
     * Atomically apply approved recommendations with a versioned snapshot.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function apply_site_advisor_recommendations(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $approved = $params['approved'] ?? [];

        if (!is_array($approved)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Invalid approved recommendations payload.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Advisor\SiteAdvisorEngine::apply_recommendations($approved);
        return rest_ensure_response($result);
    }

    /**
     * Rollback the last Site Advisor snapshot with conflict awareness.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function rollback_site_advisor_snapshot(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Advisor\SiteAdvisorEngine::rollback();
        return rest_ensure_response($result);
    }

    /**
     * Get complete CAF overview including stack snapshot and recommendations matrix.
     */
    public static function get_caf_overview(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'CAF module is not initialized.',
            ], 500);
        }

        $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
        $snapshot = $advisor->get_stack_snapshot();
        $matrix   = $advisor->get_recommendations_matrix($snapshot);

        // Preload status
        $killswitch_file = defined('WP_CONTENT_DIR') ? (WP_CONTENT_DIR . '/uploads/webcare-pro-security/.killswitch') : '';
        $is_killed = (defined('WEBCARE_CAF_DISABLE_PRELOAD') && WEBCARE_CAF_DISABLE_PRELOAD) || ($killswitch_file && file_exists($killswitch_file));

        return rest_ensure_response([
            'success'              => true,
            'snapshot'             => $snapshot->to_array(),
            'recommendations'      => $matrix,
            'is_killswitch_active' => $is_killed,
            'active_profile'       => $matrix['current_profile'],
            'residual_risk_score'  => $matrix['residual_risk_score'],
        ]);
    }

    /**
     * Apply a CAF Protection Profile.
     */
    public static function apply_caf_profile(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $profile_id   = sanitize_key($params['profile_id'] ?? 'balanced');
        $lock_dormant = isset($params['lock_dormant_surface']) ? (bool) $params['lock_dormant_surface'] : true;

        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            return new \WP_REST_Response(['success' => false, 'message' => 'CAF module missing.'], 500);
        }

        $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
        $result  = $advisor->apply_profile($profile_id, $lock_dormant);

        $auto_enabled = $result['auto_enabled'] ?? [];

        /* translators: %s: CAF profile identifier (e.g. ecommerce_hardened) */
        $base_msg = sprintf( __( 'CAF Profile "%s" applied and Micro-WAF recompiled.', 'webcare-pro-security' ), esc_html( $profile_id ) );

        return rest_ensure_response([
            'success'      => true,
            'message'      => $base_msg,
            'auto_enabled' => $auto_enabled,
            'result'       => $result,
        ]);
    }

    /**
     * Force immediate stack re-profiling and re-compilation.
     */
    public static function reprofile_caf_stack(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            return new \WP_REST_Response(['success' => false, 'message' => 'CAF module missing.'], 500);
        }

        $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
        $snapshot = $advisor->capture_stack_snapshot();

        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            \WebCareProScanner\Firewall\MicroWafCompiler::compile_script();
        }

        return rest_ensure_response([
            'success'         => true,
            'message'         => 'Stack snapshot refreshed and CAF Micro-WAF recompiled.',
            'snapshot'        => $snapshot->to_array(),
            'recommendations' => $advisor->get_recommendations_matrix($snapshot),
        ]);
    }

    /**
     * Toggle the emergency preload killswitch.
     */
    public static function toggle_caf_killswitch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enable_killswitch = !empty($params['killswitch']);

        $vault_dir = defined('WP_CONTENT_DIR') ? (WP_CONTENT_DIR . '/uploads/webcare-pro-security') : '';
        if (!$vault_dir || !is_dir($vault_dir)) {
            wp_mkdir_p($vault_dir);
        }

        $killswitch_file = $vault_dir . '/.killswitch';

        if ($enable_killswitch) {
            file_put_contents($killswitch_file, '1');
            $active = true;
        } else {
            if (file_exists($killswitch_file)) {
                wp_delete_file($killswitch_file);
            }
            $active = false;
        }

        return rest_ensure_response([
            'success'              => true,
            'is_killswitch_active' => $active,
            'message'              => $active ? 'Emergency Killswitch activated. Preload WAF bypassed.' : 'Emergency Killswitch deactivated. Preload WAF active.',
        ]);
    }

    /**
     * Get Cloudflare CAF Status (Phase 2): Slots, Token Capability, Ban Queue, Origin Circuit Breaker
     */
    public static function get_caf_cloudflare_status(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $configured = !empty($settings['cloudflare_api_token']) && !empty($zone_id);

        $optimizer = class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareSlotOptimizer') ? new \WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer() : null;
        $synchronizer = class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer') ? new \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer() : null;
        $breaker = class_exists('\\WebCareProScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker') ? new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker() : null;

        $existing_rules = [];
        $slot_budget = 4;
        $user_rules_count = 0;
        $webcare_rules_count = 0;

        if ($configured && $optimizer) {
            $existing_rules = $optimizer->get_zone_rules($zone_id);
            $slot_budget = $optimizer->calculate_webcare_slot_budget($existing_rules);

            foreach ($existing_rules as $r) {
                $desc = (string) ($r['description'] ?? '');
                if ($optimizer->is_webcare_rule($desc)) {
                    $webcare_rules_count++;
                } else {
                    $user_rules_count++;
                }
            }
        }

        $token_scope = $synchronizer ? $synchronizer->detect_api_scope() : 'none';
        $pending_queue = get_option(\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $pending_count = is_array($pending_queue) ? count($pending_queue) : 0;

        $circuit_breaker_state = $breaker ? $breaker->get_state() : [];

        return rest_ensure_response([
            'success'               => true,
            'configured'            => $configured,
            'zone_id'               => $zone_id,
            'token_scope'           => $token_scope,
            'slot_usage'            => [
                'total_quota'      => 5,
                'user_rules'       => $user_rules_count,
                'webcare_rules'    => $webcare_rules_count,
                'available_slots'  => $slot_budget,
                'free_unallocated' => max(0, 5 - ($user_rules_count + $webcare_rules_count)),
                'reserved_owner_slot' => 1,
            ],
            'existing_rules'        => array_map(function ($r) use ($optimizer) {
                $desc = (string) ($r['description'] ?? '');
                return [
                    'id'          => $r['id'] ?? '',
                    'description' => $desc,
                    'action'      => $r['action'] ?? '',
                    'enabled'     => !empty($r['enabled']),
                    'bytes'       => strlen((string) ($r['expression'] ?? '')),
                    'is_webcare'  => $optimizer ? $optimizer->is_webcare_rule($desc) : (strpos($desc, '[WebCare Pro]') !== false),
                ];
            }, $existing_rules),
            'pending_ban_queue_size'=> $pending_count,
            'circuit_breaker'       => $circuit_breaker_state,
        ]);
    }

    /**
     * Trigger immediate on-demand synchronization of Cloudflare Edge slots and IP lists.
     */
    public static function sync_caf_cloudflare(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Cloudflare API token and Zone ID must be configured in Settings first.',
            ], 400);
        }

        $optimizer = new \WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer();
        $synchronizer = new \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer();
        $breaker = new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker();

        // 1. Sync IP ban queue
        $synced_ips = $synchronizer->process_sync_queue();

        // 2. Sync 3-slot ruleset
        $origin_survival = $breaker->is_survival_mode_active();
        $slot_result = $optimizer->deploy_to_cloudflare($zone_id, null, [], $origin_survival);

        return rest_ensure_response([
            'success'     => $slot_result['success'] ?? false,
            'message'     => $slot_result['message'] ?? 'Cloudflare Edge synchronized.',
            'synced_ips'  => $synced_ips,
            'slot_result' => $slot_result,
        ]);
    }

    /**
     * Manual toggle for Origin Survival Mode (Circuit Breaker).
     */
    public static function toggle_origin_circuit_breaker(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enable = !empty($params['enable']);

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        $breaker = new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker();

        if ($enable) {
            $reason = !empty($params['reason']) ? sanitize_text_field($params['reason']) : 'Administrator Manual Trigger';
            $success = $breaker->escalate_edge_defense($zone_id, $reason, false);
            $msg = $success ? 'Origin Survival Mode engaged. Cloudflare Edge defense escalated.' : 'Failed to escalate Cloudflare Edge defense.';
        } else {
            $success = $breaker->deescalate_edge_defense($zone_id);
            $msg = $success ? 'Origin Survival Mode disengaged. Cloudflare Edge returned to standard baseline.' : 'Failed to deescalate Cloudflare Edge defense.';
        }

        return rest_ensure_response([
            'success'               => $success,
            'message'               => $msg,
            'circuit_breaker_state' => $breaker->get_state(),
        ]);
    }

    /**
     * Get CAF Phase 3 Behavioral Status: Multi-Bucket Velocity, PoW Counters, Learning Observations, Threat Scores
     */
    public static function get_caf_behavioral_status(\WP_REST_Request $request) {
        $rate_limiter_stats = class_exists('\\WebCareProScanner\\Firewall\\AdaptiveRateLimiter')
            ? \WebCareProScanner\Firewall\AdaptiveRateLimiter::get_telemetry()
            : [];

        $threat_score_stats = class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')
            ? \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::get_telemetry()
            : [];

        $learning_observations = get_option(\WebCareProScanner\Firewall\CAF\LearningModeEngine::OPTION_OBSERVATIONS, []);
        $synthesized_exemptions = get_option(\WebCareProScanner\Firewall\CAF\LearningModeEngine::OPTION_SYNTHESIZED, []);

        $pow_enforced_ips = get_option('webcare_pow_enforced_ips', []);

        return rest_ensure_response([
            'success'                => true,
            'rate_limiter'           => $rate_limiter_stats,
            'threat_scorer'          => $threat_score_stats,
            'learning_observations'  => is_array($learning_observations) ? array_values(array_slice($learning_observations, 0, 50)) : [],
            'observation_count'      => is_array($learning_observations) ? count($learning_observations) : 0,
            'synthesized_exemptions' => is_array($synthesized_exemptions) ? array_values($synthesized_exemptions) : [],
            'exemption_count'        => is_array($synthesized_exemptions) ? count($synthesized_exemptions) : 0,
            'pow_enforced_ips'       => is_array($pow_enforced_ips) ? array_values($pow_enforced_ips) : [],
        ]);
    }

    /**
     * Synthesize 1-click targeted safe-pass exemption from incident or observation ID.
     */
    public static function create_caf_exemption(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $finding_id = !empty($params['finding_id']) ? sanitize_text_field($params['finding_id']) : '';

        if (empty($finding_id)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Finding or Incident ID is required.',
            ], 400);
        }

        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\LearningModeEngine')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Learning Mode Engine is not loaded.',
            ], 500);
        }

        $result = \WebCareProScanner\Firewall\CAF\LearningModeEngine::synthesize_exemption($finding_id);
        return rest_ensure_response($result);
    }

    /**
     * Toggle manual WebCrypto PoW challenge for suspicious IP.
     */
    public static function toggle_caf_pow_challenge(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = !empty($params['ip']) ? sanitize_text_field($params['ip']) : '';
        $enable = !empty($params['enable']);

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Valid IP address is required.',
            ], 400);
        }

        $enforced = get_option('webcare_pow_enforced_ips', []);
        if (!is_array($enforced)) {
            $enforced = [];
        }

        if ($enable) {
            $enforced[$ip] = [
                'ip'         => $ip,
                'enforced_at'=> time(),
                'reason'     => sanitize_text_field($params['reason'] ?? 'Administrator Suspicious Traffic Flag'),
            ];
        } else {
            unset($enforced[$ip]);
        }

        update_option('webcare_pow_enforced_ips', $enforced, false);

        return rest_ensure_response([
            'success' => true,
            'message' => $enable ? sprintf('WebCrypto PoW challenge enforced for IP %s.', $ip) : sprintf('WebCrypto PoW challenge lifted for IP %s.', $ip),
            'enforced'=> array_values($enforced),
        ]);
    }

    /**
     * Get all active Application Passwords across all user accounts.
     */
    public static function get_app_passwords(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $passwords = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_all_passwords();
        $settings  = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'   => true,
            'passwords' => $passwords,
            'settings'  => $settings,
        ]);
    }

    /**
     * Get Application Password Sentinel settings.
     */
    public static function get_app_passwords_settings(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $settings = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'  => true,
            'settings' => $settings,
        ]);
    }

    /**
     * Update Application Password Sentinel policy settings.
     */
    public static function update_app_passwords_settings(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $result = \WebCareProScanner\Auth\ApplicationPasswordSentinel::update_settings($params);
        $settings = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'  => $result,
            'message'  => __('Application Password policy settings updated successfully.', 'webcare-pro-security'),
            'settings' => $settings,
        ]);
    }

    /**
     * Revoke a single Application Password.
     */
    public static function revoke_app_password(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $params  = $request->get_json_params() ?: [];
        $user_id = isset($params['user_id']) ? (int) $params['user_id'] : 0;
        $uuid    = !empty($params['uuid']) ? sanitize_text_field($params['uuid']) : '';

        if ($user_id <= 0 || empty($uuid)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('User ID and Application Password UUID are required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Auth\ApplicationPasswordSentinel::revoke_password($user_id, $uuid);

        if (!$result) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Failed to revoke Application Password or password not found.', 'webcare-pro-security'),
            ], 400);
        }

        $passwords = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_all_passwords();
        $settings  = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'   => true,
            'message'   => __('Application Password revoked successfully.', 'webcare-pro-security'),
            'passwords' => $passwords,
            'settings'  => $settings,
        ]);
    }

    /**
     * Revoke all Application Passwords for a user.
     */
    public static function revoke_all_app_passwords(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $params  = $request->get_json_params() ?: [];
        $user_id = isset($params['user_id']) ? (int) $params['user_id'] : 0;

        if ($user_id <= 0) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Valid User ID is required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Auth\ApplicationPasswordSentinel::revoke_all_for_user($user_id);

        $passwords = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_all_passwords();
        $settings  = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'   => true,
            'message'   => __('All Application Passwords for the user were revoked successfully.', 'webcare-pro-security'),
            'passwords' => $passwords,
            'settings'  => $settings,
        ]);
    }

    /**
     * Get In-Memory Object Cache Integrity status & environment.
     */
    public static function get_object_cache_status(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Object Cache Sentinel service not available.',
            ], 500);
        }

        $audit = \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::audit_ram_vs_disk();

        return rest_ensure_response([
            'success' => true,
            'report'  => $audit,
        ]);
    }

    /**
     * Run on-demand deep differential audit of RAM Object Cache vs MySQL disk.
     */
    public static function run_object_cache_audit(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Object Cache Sentinel service not available.',
            ], 500);
        }

        $audit = \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::audit_ram_vs_disk();

        return rest_ensure_response([
            'success' => true,
            'message' => __('Differential RAM vs Disk audit completed successfully.', 'webcare-pro-security'),
            'report'  => $audit,
        ]);
    }

    /**
     * 1-Click Surgical Flush & Resynchronization from MySQL Database Truth.
     */
    public static function flush_object_cache_resync(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Object Cache Sentinel service not available.',
            ], 500);
        }

        $result = \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::resynchronize_and_flush();

        return rest_ensure_response($result);
    }

}
