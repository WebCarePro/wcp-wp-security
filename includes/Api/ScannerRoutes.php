<?php
namespace WcpScanner\Api;

use WcpScanner\Scanner\Engine;
use WcpScanner\Filesystem\FileScanner;
use WcpScanner\Integrity\CoreIntegrity;
use WcpScanner\Integrity\ImportantFileFIM;
use WcpScanner\Integrity\PluginIntegrity;
use WcpScanner\Integrity\ThemeIntegrity;
use WcpScanner\Database\DatabaseScanner;
use WcpScanner\Content\ContentScanner;
use WcpScanner\WordPress\WordPressSecurityScanner;
use WcpScanner\WordPress\UserScanner;
use WcpScanner\WordPress\UpdateScanner;
use WcpScanner\System\ServerInfo;
use WcpScanner\Backup\DatabaseBackup;
use WcpScanner\Findings\CorrelationEngine;
use WcpScanner\Findings\RiskScorer;
use WcpScanner\Quarantine\QuarantineManager;
use WcpScanner\Quarantine\CoreRepairManager;
use WcpScanner\Scan\ScanLock;
use WcpScanner\Filesystem\UploadsScanner;
use WcpScanner\WordPress\CronScanner;
use WcpScanner\WordPress\PersistenceScanner;
use WcpScanner\Forensics\AttackChainEngine;
use WcpScanner\Firewall\VirtualPatchManager;
use WcpScanner\Firewall\ThreatIntelNetwork;
use WcpScanner\Firewall\VirtualPatchSynthesizer;
use WcpScanner\Filesystem\PathValidator;
use WcpScanner\Reports\IncidentReportEngine;

if (!defined('ABSPATH')) {
    exit;
}

class ScannerRoutes {
    const NAMESPACE = 'wcp-scanner/v1';

    public static function register() {
        $permission = function () {
            return current_user_can('manage_options');
        };

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

        register_rest_route(self::NAMESPACE, '/firewall/logs/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'add_firewall_whitelisted_ip'],
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

        // Plugin GitHub Update & Rollback Endpoints
        register_rest_route(self::NAMESPACE, '/updater/status', [
            'methods'             => 'GET',
            'callback'            => [__CLASS__, 'get_updater_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/updater/check', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'check_for_updates'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/updater/update-now', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'execute_plugin_update'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/updater/create-backup', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'create_plugin_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route(self::NAMESPACE, '/updater/rollback', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'execute_plugin_rollback'],
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
            if (current_user_can('manage_options')) {
                return true;
            }
            $auth_header = $request->get_header('Authorization');
            if (!empty($auth_header) && preg_match('/Bearer\s+(\S+)/i', $auth_header, $matches)) {
                $token = $matches[1];
                $expected = \WcpScanner\System\SettingsManager::get('mcp_token', '');
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

        register_rest_route(self::NAMESPACE, '/behavioral/rate-limiter/settings', [
            'methods'             => 'POST',
            'callback'            => [__CLASS__, 'update_rate_limiter_settings'],
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
    }

    public static function start_scan(\WP_REST_Request $request) {
        global $wpdb;

        // Check for concurrent active scan lock
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            $table_scans = $wpdb->prefix . 'wcpscan_scans';
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
                $queue = get_transient("wcpscan_scan_queue_{$locked_id}");
                $remaining = is_array($queue) ? count($queue) : 0;
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
            $settings = \WcpScanner\System\SettingsManager::get_settings();
            $custom_options = $settings['custom_scan_options'] ?? \WcpScanner\System\SettingsManager::get_default_custom_scan_options();
        } else {
            $custom_options = \WcpScanner\System\SettingsManager::sanitize_custom_scan_options($custom_options);
        }
        
        $paths = [];
        $all_files = [];

        // Determine scannable filesystem files based on scan profile (0 = unlimited)
        $file_limit = (int) apply_filters('wcpscan_file_limit', 0, $target);

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

            if (!$has_filesystem_scan) {
                $all_files = [];
            } else {
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
                foreach (array_unique($paths) as $path) {
                    $all_files = array_merge($all_files, Engine::get_scannable_files($path, $file_limit));
                }
            }
        } elseif (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity', 'rogue_admin', 'hook_sentinel', 'modified_files'], true)) {
            // Targeted deep engines do not queue filesystem files
            $all_files = [];
        } elseif ($target === 'filesystem_only' || $target === 'full') {
            $paths[] = untrailingslashit(ABSPATH);
            foreach ($paths as $path) {
                $all_files = array_merge($all_files, Engine::get_scannable_files($path, $file_limit));
            }
        } else { // default plugins_themes
            $paths[] = WP_PLUGIN_DIR;
            $paths[] = get_theme_root();
            foreach ($paths as $path) {
                $all_files = array_merge($all_files, Engine::get_scannable_files($path, $file_limit));
            }
        }

        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $now_exact = self::now_fractional_mysql();
        $start_micro = microtime(true);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert($table_scans, [
            'status'        => 'running',
            'scan_target'   => $target,
            'trigger_type'  => 'manual',
            'scanned_files' => 0,
            'total_files'   => count($all_files),
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

        if ($target === 'custom' && !empty($custom_options)) {
            set_transient("wcpscan_custom_options_{$scan_id}", $custom_options, HOUR_IN_SECONDS);
        }

        set_transient("wcpscan_scan_start_micro_{$scan_id}", $start_micro, HOUR_IN_SECONDS);
        set_transient("wcpscan_scan_queue_{$scan_id}", $all_files, HOUR_IN_SECONDS);

        $init_telemetry = self::get_realtime_resource_stats(null, null, 0, count($all_files), 0, 0.0);
        set_transient("wcpscan_scan_live_telemetry_{$scan_id}", $init_telemetry, 600);

        return rest_ensure_response([
            'success'     => true,
            'scan_id'     => $scan_id,
            'total_files' => count($all_files),
            'status'      => 'running',
            'started_at'  => $now_exact,
            'telemetry'   => $init_telemetry,
        ]);
    }

    public static function process_batch(\WP_REST_Request $request) {
        global $wpdb;

        $scan_id = (int) $request->get_param('scan_id');
        $configured_batch = (int) \WcpScanner\System\SettingsManager::get('scan_batch_size', 50);
        $param_batch = (int) $request->get_param('batch_size');
        $batch_size = $param_batch > 0 ? max($param_batch, $configured_batch) : $configured_batch;
        $batch_start = microtime(true);
        $batch_ru_start = function_exists('getrusage') ? @getrusage() : null;

        // Update lock heartbeat
        ScanLock::heartbeat($scan_id);

        $queue = get_transient("wcpscan_scan_queue_{$scan_id}");
        if ($queue === false || !is_array($queue)) {
            // Check if scan exists in DB to prevent hard 404 failure
            $check_sql = "SELECT id FROM {$wpdb->prefix}wcpscan_scans WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_exists = $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($check_sql, $scan_id)
            );
            if ($scan_exists) {
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

        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $table_files = $wpdb->prefix . 'wcpscan_scan_files';

        // Initialize Dynamic Resource Governor
        $governor = new \WcpScanner\Resource\ResourceMonitor(70, 18, 'balanced');
        $effective_batch_size = $governor->get_adaptive_batch_size($batch_size);

        $total_files = count($queue);
        $files_to_process = array_splice($queue, 0, $effective_batch_size);

        $file_scanner = new FileScanner();
        $processed_count = 0;
        $accumulated_weight = 0.0;

        foreach ($files_to_process as $filepath) {
            // Adaptive breathing and resource headroom check before each file
            if ($governor->throttle_and_check()) {
                // If nearing limit or OS pressure, push remaining files in this slice back onto queue front
                $unprocessed = array_slice($files_to_process, $processed_count);
                if (!empty($unprocessed)) {
                    $queue = array_merge($unprocessed, $queue);
                }
                break;
            }

            // Factor in file complexity weight
            $weight = \WcpScanner\Resource\ResourceMonitor::get_file_weight($filepath);
            $accumulated_weight += $weight;

            // If heavy files filled the batch weight budget early, save remaining and yield
            if ($accumulated_weight >= ($effective_batch_size * 1.25) && $processed_count > 10) {
                $unprocessed = array_slice($files_to_process, $processed_count);
                if (!empty($unprocessed)) {
                    $queue = array_merge($unprocessed, $queue);
                }
                break;
            }

            $findings = $file_scanner->scan_file($filepath, (string) $scan_id);
            $rel_path = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($filepath)), '/');
            $file_size = @filesize($filepath) ?: 0;
            $file_status = !empty($findings) ? 'threat' : 'clean';

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->insert($table_files, [
                'scan_id'    => $scan_id,
                'file_path'  => $rel_path,
                'file_size'  => $file_size,
                'status'         => $file_status,
                'scanned_at'     => current_time('mysql'),
                'scanned_at_gmt' => gmdate('Y-m-d H:i:s'),
            ]);

            $processed_count++;

            foreach ($findings as $f) {
                $item = $f->to_array();
                $matched_rule = \WcpScanner\Findings\WhitelistManager::match_finding($item);
                $status = ($matched_rule !== null) ? 'ignored' : 'open';

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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

        $remaining = count($queue);
        $is_finished = ($remaining === 0);

        if ($is_finished) {
            delete_transient("wcpscan_scan_queue_{$scan_id}");
        } else {
            set_transient("wcpscan_scan_queue_{$scan_id}", $queue, HOUR_IN_SECONDS);
        }

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

        $start_micro = get_transient("wcpscan_scan_start_micro_{$scan_id}");
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
        set_transient("wcpscan_scan_live_telemetry_{$scan_id}", $telemetry, 600);

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

        $scan_id = (int) $request->get_param('scan_id');
        $target = sanitize_text_field($request->get_param('target') ?: '');
        $admins_only = (bool) $request->get_param('admins_only');

        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $table_scans = $wpdb->prefix . 'wcpscan_scans';

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
                $rogue_detector = new \WcpScanner\Database\RogueAdminAnomalyDetector();
                $all_deep_findings = array_merge($all_deep_findings, $rogue_detector->scan((string) $scan_id));
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true));
            } elseif ($target === 'hook_sentinel') {
                // Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
                $hook_sentinel = new \WcpScanner\WordPress\HookInfiltrationSentinel();
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
                $custom_options = get_transient("wcpscan_custom_options_{$scan_id}");
                if (!is_array($custom_options)) {
                    $req_custom = $request->get_param('custom_options');
                    if (is_array($req_custom)) {
                        $custom_options = \WcpScanner\System\SettingsManager::sanitize_custom_scan_options($req_custom);
                    } else {
                        $settings = \WcpScanner\System\SettingsManager::get_settings();
                        $custom_options = $settings['custom_scan_options'] ?? \WcpScanner\System\SettingsManager::get_default_custom_scan_options();
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
                    $config_scanner = new \WcpScanner\WordPress\ConfigScanner();
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
                    $option_scanner = new \WcpScanner\Database\OptionScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $option_scanner->scan_options((string) $scan_id));
                }

                // 11. Scan for out of date, abandoned, and vulnerable plugins, themes, and WP
                if (!empty($custom_options['scan_vulnerable_software'])) {
                    $update_scanner = new UpdateScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
                }

                // 12. Scan for suspicious admin users created outside of WordPress
                if (!empty($custom_options['scan_rogue_admins'])) {
                    $rogue_detector = new \WcpScanner\Database\RogueAdminAnomalyDetector();
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
                // Full or plugins_themes: run all engines
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $theme_integrity = new ThemeIntegrity();
                $important_fim = new ImportantFileFIM();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));

                $db_scanner = new DatabaseScanner();
                $all_deep_findings = array_merge($all_deep_findings, $db_scanner->scan((string) $scan_id, 100));

                $content_scanner = new ContentScanner();
                $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 100));

                $wp_security = new WordPressSecurityScanner();
                $all_deep_findings = array_merge($all_deep_findings, $wp_security->scan((string) $scan_id));

                $update_scanner = new UpdateScanner();
                $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));

                $uploads_scanner = new UploadsScanner();
                $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));

                // Reputation Checks (Domain blocklist, Spamvertised, Spam IP)
                $reputation_findings = self::audit_reputation_checks((string) $scan_id, [
                    'check_domain_blocklist' => true,
                    'check_spamvertised'     => true,
                    'check_spam_ip'          => true,
                ]);
                $all_deep_findings = array_merge($all_deep_findings, $reputation_findings);
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
                $sig = md5(($ex['engine'] ?? '') . '|' . ($ex['type'] ?? '') . '|' . ($ex['file_path'] ?? '') . '|' . ($ex['line_number'] ?? '') . '|' . ($ex['description'] ?? ''));
                $inserted_signatures[$sig] = true;
            }

            foreach ($correlated as $f) {
                $item = $f->to_array();
                $sig = md5(($item['engine'] ?? '') . '|' . ($item['type'] ?? '') . '|' . ($item['file_path'] ?? '') . '|' . ($item['line_number'] ?? '') . '|' . ($item['description'] ?? ''));
                if (isset($inserted_signatures[$sig])) {
                    continue; // Skip exact duplicate finding for this scan
                }
                $inserted_signatures[$sig] = true;

                $matched_rule = \WcpScanner\Findings\WhitelistManager::match_finding($item);
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
            $start_micro = get_transient("wcpscan_scan_start_micro_{$scan_id}");
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

            delete_transient("wcpscan_scan_start_micro_{$scan_id}");

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
            error_log('[WCP Scanner] Error during deep audit: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());

            return new \WP_Error(
                'audit_error',
                /* translators: %s: error message */
                sprintf(__('Audit failed: %s', 'wcp-security-scanner'), $e->getMessage()),
                ['status' => 500]
            );
        }
    }

    public static function get_latest_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $table_files = $wpdb->prefix . 'wcpscan_scan_files';

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
        $dup_sql = "SELECT MIN(id) as keep_id, scan_id, engine, type, file_path, line_number, description, COUNT(*) as cnt FROM `{$table_issues}` WHERE scan_id = %d GROUP BY scan_id, engine, type, file_path, line_number, description HAVING cnt > 1";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $duplicates = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($dup_sql, $latest_scan['id']),
            ARRAY_A
        );

        if (!empty($duplicates)) {
            foreach ($duplicates as $dup) {
                $del_dup_sql = "DELETE FROM `{$table_issues}` WHERE scan_id = %d AND engine = %s AND type = %s AND file_path = %s AND description = %s AND id != %d";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query(
                    $wpdb->prepare(
                        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                        $del_dup_sql,
                        $dup['scan_id'],
                        $dup['engine'],
                        $dup['type'],
                        $dup['file_path'],
                        $dup['description'],
                        $dup['keep_id']
                    )
                );
            }
            // Update issues_found count on scan record
            $fc_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $fixed_count = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($fc_sql, $latest_scan['id'])
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $fixed_count], ['id' => $latest_scan['id']]);
            $latest_scan['issues_found'] = $fixed_count;
        }

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

        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $iss_row_sql = "SELECT * FROM {$table_issues} WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issue = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_row_sql, $issue_id)
        );

        if ($status === 'open' && $issue && !empty($issue->file_path)) {
            \WcpScanner\Findings\WhitelistManager::revoke_rules_for_target($issue->file_path, $issue->type ?? '');
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $updated = $wpdb->update($table_issues, ['status' => $status], ['id' => $issue_id]);

        if ($issue && !empty($issue->scan_id)) {
            $table_scans = $wpdb->prefix . 'wcpscan_scans';
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
        $table_scans = $wpdb->prefix . 'wcpscan_scans';
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
        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $table_files = $wpdb->prefix . 'wcpscan_scan_files';

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
                    __('Past scan logs cleared successfully. Actively running scan (#%s) was preserved and continues executing uninterrupted.', 'wcp-security-scanner'),
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
            'message'    => __('All old scan logs and history records cleared successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function get_scan_log_detail(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('id');
        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
        $table_files = $wpdb->prefix . 'wcpscan_scan_files';

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

        return rest_ensure_response([
            'success'     => true,
            'scan'        => $scan,
            'summary'     => $summary,
            'issues'      => $issues,
            'files_count' => $files_count,
            'diagnostics' => $diagnostics,
        ]);
    }

    public static function export_scan_results(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('scan_id');
        $format  = sanitize_key($request->get_param('format') ?: 'json');

        $table_scans  = $wpdb->prefix . 'wcpscan_scans';
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';

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

        if ($format === 'csv') {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Writing to in-memory temporary stream for REST CSV export
            $output  = fopen('php://temp', 'r+');
            // Sysadmin Telemetry & Environment comments header
            $site_url = get_site_url();
            $site_name = get_bloginfo('name');
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

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# ====================================================================\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# WCP Security Scanner Pro - Audit Findings Report\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Auditor: Mir Alamin (WebCare Pro) - Senior Linux SysAdmin & WordPress Security Engineer\r\n");
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
            fwrite($output, "# Active Engines: " . ($diagnostics['engines_active'] ?? 10) . " Core Security Engines\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Exported: " . current_time('mysql') . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# ====================================================================\r\n");

            $headers = ['ID', 'Severity', 'Engine', 'Threat Type', 'File / Target', 'Line Number', 'Status', 'Description'];
            fputcsv($output, $headers);

            foreach ($issues as $issue) {
                fputcsv($output, [
                    $issue['id'] ?? '',
                    strtoupper($issue['severity'] ?? 'low'),
                    $issue['engine'] ?? '',
                    $issue['type'] ?? '',
                    $issue['file_path'] ?? '',
                    $issue['line_number'] ?? '',
                    $issue['status'] ?? 'open',
                    $issue['description'] ?? '',
                ]);
            }

            rewind($output);
            $csv_data = stream_get_contents($output);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($output);

            return rest_ensure_response([
                'success'     => true,
                'format'      => 'csv',
                'filename'    => 'wcp-scan-' . $scan['id'] . '-' . gmdate('Ymd-His') . '.csv',
                'csv_data'    => $csv_data,
                'diagnostics' => $diagnostics,
            ]);
        }

        return rest_ensure_response([
            'success'            => true,
            'format'             => 'json',
            'filename'           => 'wcp-scan-' . $scan['id'] . '-' . gmdate('Ymd-His') . '.json',
            'report_generator'   => 'WCP Security Scanner Pro',
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
                'active_engines'         => $diagnostics['engines_active'] ?? 10,
            ],
            'findings_count'     => count($issues),
            'findings'           => $issues,
        ]);
    }

    public static function get_server_info(\WP_REST_Request $request) {
        $refresh = (bool) $request->get_param('refresh');
        if ($refresh && function_exists('delete_transient')) {
            delete_transient('wcpscan_server_filesystem_metrics');
        }
        return rest_ensure_response([
            'success' => true,
            'info'    => ServerInfo::get_info(true),
        ]);
    }

    /**
     * Get comprehensive system readiness & compatibility audit report.
     */
    public static function get_system_readiness(\WP_REST_Request $request): \WP_REST_Response {
        $report = \WcpScanner\System\SystemReadinessChecker::check_all();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    /**
     * Dismiss first-time welcome modal.
     */
    public static function dismiss_welcome_modal(\WP_REST_Request $request): \WP_REST_Response {
        \WcpScanner\System\SystemReadinessChecker::dismiss_welcome();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Welcome dialog dismissed successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function get_vulnerabilities_report(\WP_REST_Request $request) {
        $report = UpdateScanner::get_detailed_report();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
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

        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $locked_id = ScanLock::get_locked_scan_id();

        // If no lock option exists, check if there is an active scan record in the DB created recently
        if (!$locked_id) {
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
        ScanLock::heartbeat($locked_id);

        $queue = get_transient("wcpscan_scan_queue_{$locked_id}");
        $total = (int) $running_scan['total_files'];
        $scanned = (int) $running_scan['scanned_files'];
        $trigger_type = !empty($running_scan['trigger_type']) ? $running_scan['trigger_type'] : 'manual';
        $remaining = is_array($queue) ? count($queue) : max(0, $total - $scanned);
        $last_file = get_transient("wcpscan_active_scan_file_{$locked_id}") ?: '';

        $live_telemetry = get_transient("wcpscan_scan_live_telemetry_{$locked_id}");
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
            'issues_found'   => (int) $running_scan['issues_found'],
            'telemetry'      => $live_telemetry,
            'phase'          => ($trigger_type === 'scheduled') 
                ? (($scanned >= $total && $total > 0) ? 'deep_audit' : 'batch')
                : (($remaining > 0) ? 'batch' : 'deep_audit'),
            'created_at'     => $running_scan['created_at'],
            'started_at'     => $running_scan['started_at'] ?? $running_scan['created_at'],
            'elapsed'        => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("wcpscan_scan_start_micro_{$locked_id}");
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
                $start_micro = get_transient("wcpscan_scan_start_micro_{$locked_id}");
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

        $table_scans = $wpdb->prefix . 'wcpscan_scans';
        $scan_id = (int) $request->get_param('scan_id');
        if (!$scan_id) {
            $scan_id = ScanLock::get_locked_scan_id();
        }

        $now_exact = self::now_fractional_mysql();

        if ($scan_id) {
            $start_micro = get_transient("wcpscan_scan_start_micro_{$scan_id}");
            $duration_ms = 0;
            $duration_sec = 0;
            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }
            delete_transient("wcpscan_scan_start_micro_{$scan_id}");

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'duration'     => $duration_sec,
                'duration_ms'  => $duration_ms,
                'completed_at' => $now_exact,
            ], ['id' => $scan_id]);
            delete_transient("wcpscan_scan_queue_{$scan_id}");
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
                    $item['display_title'] = __('Custom Child Theme', 'wcp-security-scanner');
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Theme', 'wcp-security-scanner');
                } else {
                    $item['display_title'] = __('Custom or Premium Theme', 'wcp-security-scanner');
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
                    $item['display_title'] = __('Premium Plugin', 'wcp-security-scanner');
                } else {
                    $item['display_title'] = __('Custom or Premium Plugin', 'wcp-security-scanner');
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
                    $item['post_title'] = $post->post_title ?: __('(Untitled)', 'wcp-security-scanner');
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
                    $item['author_name'] = $comment->comment_author ?: __('(Anonymous)', 'wcp-security-scanner');
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
                    $item['post_title'] = $postId > 0 ? (get_the_title($postId) ?: __('(Untitled Post)', 'wcp-security-scanner')) : '';
                    $item['post_url'] = $postId > 0 ? (get_permalink($postId) ?: '') : '';
                    $item['view_url'] = get_comment_link($comment) ?: '';
                    $item['edit_url'] = admin_url("comment.php?action=editcomment&c={$commentId}");
                } else {
                    $item['author_id'] = 0;
                    $item['author_name'] = preg_match('/by\s+(.+)$/i', $filePath, $am) ? trim($am[1]) : __('Unknown Author', 'wcp-security-scanner');
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
                            $item['sample_post_title'] = !empty($samplePost->post_title) ? $samplePost->post_title : __('(Untitled Post)', 'wcp-security-scanner');
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
                    $mgr = new \WcpScanner\Database\DatabaseRemediationManager();
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
                            $item['post_title'] = !empty($post->post_title) ? $post->post_title : __('(Untitled Post)', 'wcp-security-scanner');
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
                $isInsideRoot = $realPath && \WcpScanner\Filesystem\PathValidator::is_inside_root($realPath, ABSPATH);

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
                                $wpdb->update($wpdb->prefix . 'wcpscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
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

                    $item['fs_forensics'] = [
                        'file_size'             => $fsize !== false ? $fsize : 0,
                        'file_size_formatted'   => $fsize !== false ? size_format($fsize) : '0 B',
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
                        'is_safe_directory_index' => in_array(strtolower(basename($realPath)), ['index.php', 'index.html', 'index.htm'], true) && \WcpScanner\System\SettingsManager::is_safe_directory_index($realPath),
                    ];

                    // Real-Time Directory Protection Index Reconciliation: If executable_in_uploads finding but file is a benign silence/protection index or legitimate plugin cache file
                    if (($item['type'] ?? '') === 'executable_in_uploads' && ($item['status'] ?? 'open') === 'open') {
                        $file_basename = strtolower(basename($realPath));
                        if (in_array($file_basename, ['index.php', 'index.html', 'index.htm'], true) && \WcpScanner\System\SettingsManager::is_safe_directory_index($realPath)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            $item['reconciliation_reason'] = __('Benign directory listing protection index file (Silence is Golden / Directory Browsing Prevention).', 'wcp-security-scanner');
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'wcpscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        } elseif (\WcpScanner\System\SettingsManager::is_legitimate_uploads_cache_file($realPath)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            $item['reconciliation_reason'] = __('Benign plugin compiled cache file (e.g. MailPoet Twig template cache) verified free of malware/webshells.', 'wcp-security-scanner');
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'wcpscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
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
                                $wpdb->update($wpdb->prefix . 'wcpscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
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
                if (!empty($item['component_meta']['classification'])) {
                    if (empty($item['display_title']) || $item['engine'] === 'wordpress-updates' || in_array($item['type'], ['outdated_plugin', 'outdated_theme', 'vulnerable_plugin', 'vulnerable_theme'])) {
                        $item['display_title'] = $item['component_meta']['classification'];
                    }
                }
                if (!empty($item['component_meta']['is_wporg']) || $item['engine'] === 'wordpress-updates') {
                    $item['is_wporg'] = true;
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

            // 6. Whitelist & False-Positive Rule Matching (Auto-suppression)
            $matched_rule = \WcpScanner\Findings\WhitelistManager::match_finding($item);
            if ($matched_rule !== null) {
                $item['is_whitelisted'] = true;
                $item['whitelist_rule'] = $matched_rule;
                if (!empty($item['id']) && ($item['status'] ?? '') === 'open') {
                    global $wpdb;
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->update($wpdb->prefix . 'wcpscan_scan_issues', ['status' => 'ignored'], ['id' => (int) $item['id']]);
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
        }
        unset($item);

        // Deduplicate identical issues by unique signature
        $deduped = [];
        $seen_signatures = [];
        foreach ($issues as $entry) {
            $sig = ($entry['engine'] ?? '') . '|' . ($entry['type'] ?? '') . '|' . ($entry['file_path'] ?? '') . '|' . ($entry['line_number'] ?? '') . '|' . ($entry['description'] ?? '');
            if (isset($seen_signatures[$sig])) {
                continue;
            }
            $seen_signatures[$sig] = true;
            $deduped[] = $entry;
        }

        return $deduped;
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
            $classification = __('Official WordPress Theme', 'wcp-security-scanner');
        } elseif (!empty($evidence_data['display_title'])) {
            $classification = $evidence_data['display_title'];
        } elseif ($is_child) {
            $classification = __('Custom Child Theme', 'wcp-security-scanner');
        } else {
            $classification = $is_premium ? __('Premium Theme', 'wcp-security-scanner') : __('Custom or Premium Theme', 'wcp-security-scanner');
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
            $classification = __('Official WordPress Plugin', 'wcp-security-scanner');
        } elseif (!empty($evidence_data['display_title'])) {
            $classification = $evidence_data['display_title'];
        } elseif ($is_premium) {
            $classification = __('Premium Plugin', 'wcp-security-scanner');
        } else {
            $classification = __('Custom or Premium Plugin', 'wcp-security-scanner');
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
            $cache_key = 'wcpscan_up_cl_pl_' . substr(md5(($slug ?: basename($target_dir)) . '_' . $latest_ver), 0, 16);
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
            $cache_key = 'wcpscan_up_cl_th_' . substr(md5($slug . '_' . $latest_ver), 0, 16);
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
                'source_label'      => sprintf(__('Latest Upstream Version (%1$s) from %2$s', 'wcp-security-scanner'), $version_label, $source_title),
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
                                __('Currently Installed Version (%s) [Local Disk]', 'wcp-security-scanner'),
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
                                __('Latest version (%1$s) changelog was not found on remote repositories or plugin update manager. Displaying currently installed version (%2$s) changelog from local disk below.', 'wcp-security-scanner'),
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
                __('Latest version (%s) changelog was not found on WordPress.org, and no local changelog file (changelog.txt, readme.txt, or changelog.md) exists in the installed component folder.', 'wcp-security-scanner'),
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
        $cached_diag = $scan_id > 0 ? get_transient("wcpscan_diag_{$scan_id}") : null;

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
            'engines_active'         => 10,
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
     * @param \WcpScanner\Resource\ResourceMonitor|null $governor
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
        if ($governor instanceof \WcpScanner\Resource\ResourceMonitor) {
            $governor_info = $governor->get_telemetry_payload();
        } else {
            $temp_gov = new \WcpScanner\Resource\ResourceMonitor(70, 18, 'balanced');
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
            return new \WP_Error('missing_path', __('File path parameter is required.', 'wcp-security-scanner'), ['status' => 400]);
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
            return new \WP_Error('file_not_found', __('File does not exist or has been removed from server.', 'wcp-security-scanner'), ['status' => 404]);
        }

        // Canonical directory boundary check: Enforce trailing slash on root to eliminate sibling directory escapes
        if (!\WcpScanner\Filesystem\PathValidator::is_inside_root($target_full, ABSPATH)) {
            return new \WP_Error('forbidden_path', __('Access to this file path is restricted outside WordPress root.', 'wcp-security-scanner'), ['status' => 403]);
        }

        $real_path = realpath($target_full);
        if (!$real_path || !is_file($real_path)) {
            return new \WP_Error('not_a_file', __('The requested path is a directory or special file, not a viewable file.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!is_readable($real_path)) {
            return new \WP_Error('unreadable_file', __('File is not readable due to server permissions.', 'wcp-security-scanner'), ['status' => 403]);
        }

        $file_size = (int) filesize($real_path);
        $max_read = 750 * 1024; // 750KB limit to protect memory
        $is_truncated = $file_size > $max_read;

        $content = file_get_contents($real_path, false, null, 0, $max_read);
        if ($content === false) {
            return new \WP_Error('read_error', __('Failed to read file content.', 'wcp-security-scanner'), ['status' => 500]);
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

        $lines = explode("\n", $content);
        $line_count = count($lines);

        $rel_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($real_path));
        $rel_path = ltrim($rel_path, '/\\');

        return rest_ensure_response([
            'success'          => true,
            'filename'         => basename($real_path),
            'file_path'        => $rel_path,
            'full_path'        => $real_path,
            'size_bytes'       => $file_size,
            'size_formatted'   => size_format($file_size, 2),
            'permissions'      => $perms,
            'is_writable'      => wp_is_writable($real_path),
            'line_count'       => $line_count,
            'content'          => $content,
            'is_truncated'     => $is_truncated,
            'is_image'         => $is_image_ext,
            'is_valid_image'   => $is_image,
            'image_mime'       => $is_image_ext ? $image_mimes[$extension] : null,
            'image_base64'     => $image_base64,
            'image_dimensions' => $image_dimensions,
            'image_security'   => $image_security,
        ]);
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
            return new \WP_Error('missing_post_id', __('Valid post ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $post = get_post($post_id);
        if (!$post) {
            return new \WP_Error('post_not_found', __('The requested post or page was not found.', 'wcp-security-scanner'), ['status' => 404]);
        }

        return rest_ensure_response([
            'success'      => true,
            'post_id'      => $post_id,
            'title'        => $post->post_title ?: __('(Untitled)', 'wcp-security-scanner'),
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
        $next_run_timestamp = wp_next_scheduled(\WcpScanner\System\SettingsManager::CRON_HOOK);
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
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $time_info = self::build_schedule_time_info();

        return rest_ensure_response([
            'success'           => true,
            'settings'          => $settings,
            'ai_connect_status' => \WcpScanner\System\AIService::get_ai_connect_status(),
            'next_scheduled'    => $time_info['next_scheduled_wp'],
            'schedule_time'     => $time_info,
            'current_time'      => $time_info['current_wp_time'],
        ]);
    }

    /**
     * Save plugin settings
     */
    public static function save_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params();
        if (!is_array($params)) {
            $params = $request->get_body_params();
        }

        $saved = \WcpScanner\System\SettingsManager::save_settings((array) $params);
        $time_info = self::build_schedule_time_info();

        return rest_ensure_response([
            'success'           => true,
            'message'           => __('Settings successfully saved.', 'wcp-security-scanner'),
            'settings'          => $saved,
            'ai_connect_status' => \WcpScanner\System\AIService::get_ai_connect_status(),
            'next_scheduled'    => $time_info['next_scheduled_wp'],
            'schedule_time'     => $time_info,
        ]);
    }

    /**
     * Export settings as downloadable JSON payload
     */
    public static function export_settings(\WP_REST_Request $request) {
        $data = \WcpScanner\System\SettingsManager::export_settings();
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
            return new \WP_Error('invalid_import', __('Invalid JSON data.', 'wcp-security-scanner'), ['status' => 400]);
        }

        try {
            $imported = \WcpScanner\System\SettingsManager::import_settings($payload);
            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Settings successfully imported and applied.', 'wcp-security-scanner'),
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
        $defaults = \WcpScanner\System\SettingsManager::reset_defaults();
        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Settings have been reset to factory defaults.', 'wcp-security-scanner'),
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
                    __('A scan is already actively running (ID: %d).', 'wcp-security-scanner'),
                    $locked_id
                ),
                ['status' => 409]
            );
        }

        // Run scheduled scan synchronously or trigger the hook
        try {
            \WcpScanner\System\Scheduler::run_scheduled_scan();
            return rest_ensure_response([
                'success' => true,
                'message' => __('Scheduled security scan was triggered and executed successfully.', 'wcp-security-scanner'),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('cron_trigger_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Audit HTTP security headers & site hardening status
     */
    public static function get_hardening_audit(\WP_REST_Request $request) {
        $audit = \WcpScanner\Hardening\SecurityHeadersEngine::audit_hardening_status();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Apply recommended A+ hardening preset
     */
    public static function apply_hardening_preset(\WP_REST_Request $request) {
        $current = \WcpScanner\System\SettingsManager::get_settings();
        
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
        $saved = \WcpScanner\System\SettingsManager::save_settings($updated);
        $audit = \WcpScanner\Hardening\SecurityHeadersEngine::audit_hardening_status();

        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Recommended A+ Security Hardening preset applied successfully.', 'wcp-security-scanner'),
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
            $result = \WcpScanner\System\AIService::test_connection($provider, '', $model);
            if (empty($result['success'])) {
                return new \WP_Error('ai_test_failed', $result['error'] ?? 'WordPress Native AI Connect Test Failed', ['status' => 400]);
            }
            return rest_ensure_response($result);
        }

        // If key is masked or empty, fall back to stored key
        if ($api_key === '' || $api_key === '••••••••') {
            $settings = \WcpScanner\System\SettingsManager::get_settings();
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

        $result = \WcpScanner\System\AIService::test_connection($provider, $api_key, $model);
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
            $analysis = \WcpScanner\System\AIService::analyze_code($params);
            return rest_ensure_response($analysis);
        } catch (\Exception $e) {
            return new \WP_Error('ai_analysis_error', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Get available AI model catalog
     */
    public static function get_ai_models(\WP_REST_Request $request) {
        $catalog = \WcpScanner\System\AIService::get_available_models();
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
            $result = \WcpScanner\System\AIService::check_and_update_models($auto_upgrade);
            $settings = \WcpScanner\System\SettingsManager::get_settings();
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
            $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response($result);
    }

    public static function get_firewall_status() {
        return rest_ensure_response(\WcpScanner\Firewall\FirewallEngine::get_status());
    }

    public static function get_firewall_logs(\WP_REST_Request $request) {
        $limit   = (int) ($request->get_param('limit') ?: 50);
        $offset  = (int) ($request->get_param('offset') ?: 0);
        $search   = sanitize_text_field((string) ($request->get_param('search') ?: ''));
        $category = sanitize_text_field((string) ($request->get_param('category') ?: ''));
        $action   = sanitize_text_field((string) ($request->get_param('action') ?: ''));
        $method      = sanitize_text_field((string) ($request->get_param('method') ?: ''));
        $ip          = sanitize_text_field((string) ($request->get_param('ip') ?: ''));
        $status_code = sanitize_text_field((string) ($request->get_param('status_code') ?: ''));

        $filters = array_filter([
            'search'      => $search,
            'category'    => $category,
            'action'      => $action,
            'method'      => $method,
            'ip'          => $ip,
            'status_code' => $status_code,
        ]);

        $res = \WcpScanner\Firewall\FirewallEngine::get_logs($limit, $offset, $filters);
        $res['current_client_ip'] = \WcpScanner\Firewall\FirewallEngine::get_client_ip();
        return rest_ensure_response($res);
    }

    public static function get_firewall_log_stats() {
        return rest_ensure_response([
            'stats' => \WcpScanner\Firewall\FirewallEngine::get_log_stats(),
        ]);
    }

    public static function delete_firewall_log(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $id = (int) ($params['id'] ?? 0);
        if ($id <= 0) {
            return new \WP_Error('invalid_id', 'Valid log ID is required', ['status' => 400]);
        }
        $deleted = \WcpScanner\Firewall\FirewallEngine::delete_log($id);
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

        $current_client_ip = \WcpScanner\Firewall\FirewallEngine::get_client_ip();
        if ($ip === $current_client_ip && \WcpScanner\Firewall\FirewallEngine::is_authenticated_administrator()) {
            return new \WP_Error(
                'self_ban_prohibited',
                /* translators: %s: current IP address */
                sprintf(__('Safety Guard: IP %s is your active administrator connection. You cannot block your own IP to prevent site lockout.', 'wcp-security-scanner'), $ip),
                ['status' => 400]
            );
        }

        $added = \WcpScanner\Firewall\FirewallEngine::add_blocked_ip($ip);
        return rest_ensure_response([
            'success' => $added,
            'message' => $added ? sprintf('IP %s added to custom WAF blocklist.', $ip) : 'Failed to add IP.',
        ]);
    }

    public static function add_firewall_whitelisted_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }
        $added = \WcpScanner\Firewall\FirewallEngine::add_whitelisted_ip($ip);
        return rest_ensure_response([
            'success' => $added,
            'message' => $added ? sprintf('IP %s added to trusted WAF allowlist.', $ip) : 'Failed to whitelist IP.',
        ]);
    }

    public static function clear_firewall_logs() {
        $cleared = \WcpScanner\Firewall\FirewallEngine::clear_logs();
        return rest_ensure_response([
            'success' => $cleared,
            'message' => 'Firewall incident logs cleared successfully.',
        ]);
    }

    public static function toggle_firewall(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enabled = !empty($params['enabled']);
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $settings['waf_enabled'] = $enabled;
        if ($enabled && ($settings['waf_mode'] ?? '') === 'disabled') {
            $settings['waf_mode'] = 'enabled';
        } elseif (!$enabled) {
            $settings['waf_mode'] = 'disabled';
        }
        \WcpScanner\System\SettingsManager::save_settings($settings);

        return rest_ensure_response([
            'success' => true,
            'enabled' => $enabled,
            'status'  => \WcpScanner\Firewall\FirewallEngine::get_status(),
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
        $saved = \WcpScanner\System\SettingsManager::save_settings([$key => $val]);
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
            'roles'   => \WcpScanner\Firewall\FirewallEngine::get_available_roles(),
        ]);
    }

    public static function get_server_security_config() {
        if (!class_exists('\\WcpScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WCPSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $options = \WcpScanner\Firewall\ServerSecurityEngine::get_options();
        $file_info = \WcpScanner\Firewall\ServerSecurityEngine::get_file_info();
        $nginx_content = \WcpScanner\Firewall\ServerSecurityEngine::generate_nginx_config($options);
        $apache_content = \WcpScanner\Firewall\ServerSecurityEngine::generate_apache_config($options);

        return rest_ensure_response([
            'options'        => $options,
            'file_info'      => $file_info,
            'nginx_content'  => $nginx_content,
            'apache_content' => $apache_content,
        ]);
    }

    public static function save_server_security_config(\WP_REST_Request $request) {
        if (!class_exists('\\WcpScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WCPSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $params = $request->get_json_params() ?: [];
        $server_type = !empty($params['server_type']) ? sanitize_key($params['server_type']) : 'nginx';
        $options = !empty($params['options']) && is_array($params['options']) ? $params['options'] : [];

        $result = \WcpScanner\Firewall\ServerSecurityEngine::save_config_file($server_type, $options);
        return rest_ensure_response($result);
    }

    public static function deploy_server_security_htaccess(\WP_REST_Request $request) {
        if (!class_exists('\\WcpScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WCPSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $params = $request->get_json_params() ?: [];
        $options = !empty($params['options']) && is_array($params['options']) ? $params['options'] : [];

        $result = \WcpScanner\Firewall\ServerSecurityEngine::deploy_to_htaccess($options);
        return rest_ensure_response($result);
    }

    public static function get_integrity_recent_changes(\WP_REST_Request $request) {
        $hours = (int) ($request->get_param('hours') ?: 48);
        $category = sanitize_key($request->get_param('category') ?: 'all');
        $limit = (int) ($request->get_param('limit') ?: 150);

        $fim = new \WcpScanner\Integrity\FileIntegrityMonitor();
        $data = $fim->get_recent_changes($hours, $category, $limit);

        return rest_ensure_response($data);
    }

    public static function get_integrity_vault_status(\WP_REST_Request $request) {
        $status = \WcpScanner\Integrity\FimVaultManager::get_vault_status();
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
            $result = \WcpScanner\Integrity\FimDriftDetector::calibrate_all();
            return rest_ensure_response($result);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WCP-FIM] Calibration Fatal Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
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

            $result = \WcpScanner\Integrity\FimDriftDetector::audit_drift($category, $limit);
            return rest_ensure_response($result);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WCP-FIM] Drift Audit Fatal Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
            return new \WP_Error(
                'fim_drift_audit_failed',
                'FIM Drift Audit Failed: ' . $e->getMessage(),
                ['status' => 500]
            );
        }
    }

    public static function get_integrity_file_diff(\WP_REST_Request $request) {
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
            return new \WP_Error('missing_file_path', __('Missing required file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
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

        $fim = new \WcpScanner\Integrity\FileIntegrityMonitor();
        $diff_data = $fim->get_file_diff($file_path);

        return rest_ensure_response($diff_data);
    }

    public static function remediate_strip_webshell(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
        $result = $manager->strip_malware_injection($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_plugin(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_plugin_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_theme(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_theme_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_core(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_core_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_fix_permissions(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;
        $target_perm = !empty($params['target_perm']) ? sanitize_text_field(wp_unslash($params['target_perm'])) : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
        $result = $manager->fix_permissions($file_path, $target_perm, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_delete_file(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
        $result = $manager->delete_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function permissions_audit(\WP_REST_Request $request) {
        $manager = new \WcpScanner\Hardening\PermissionHardeningManager();
        $result = $manager->audit();
        return rest_ensure_response($result);
    }

    public static function permissions_fix_all(\WP_REST_Request $request) {
        $manager = new \WcpScanner\Hardening\PermissionHardeningManager();
        $result = $manager->fix_all();
        return rest_ensure_response($result);
    }

    public static function persistence_audit(\WP_REST_Request $request) {
        $scanner = new \WcpScanner\WordPress\PersistenceScanner();
        $result = $scanner->audit_full();
        return rest_ensure_response($result);
    }

    public static function persistence_neutralize(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $type = sanitize_key($params['type'] ?? '');
        $id = sanitize_text_field(wp_unslash($params['id'] ?? ''));
        $bulk = !empty($params['bulk']);

        $scanner = new \WcpScanner\WordPress\PersistenceScanner();

        if ($bulk) {
            $result = $scanner->neutralize_all();
            return rest_ensure_response($result);
        }

        if (empty($type) || empty($id)) {
            return new \WP_Error('missing_params', __('Type and identifier are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = $scanner->neutralize_item($type, $id);
        if (!$result['success']) {
            return new \WP_Error('neutralize_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function attack_chain_audit(\WP_REST_Request $request) {
        $engine = new \WcpScanner\Forensics\AttackChainEngine();
        $result = $engine->audit_attack_chains();
        return rest_ensure_response($result);
    }

    public static function attack_chain_eradicate(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $chain_id = sanitize_text_field(wp_unslash($params['chain_id'] ?? ''));
        $plan = is_array($params['plan'] ?? null) ? $params['plan'] : [];

        if (empty($chain_id)) {
            return new \WP_Error('missing_chain_id', __('Chain ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $engine = new \WcpScanner\Forensics\AttackChainEngine();
        $result = $engine->eradicate_chain($chain_id, $plan);
        return rest_ensure_response($result);
    }

    public static function virtual_patch_list(\WP_REST_Request $request) {
        $catalog = \WcpScanner\Firewall\VirtualPatchManager::get_patch_catalog();
        $active = \WcpScanner\Firewall\VirtualPatchManager::get_active_patches();
        
        $settings = \WcpScanner\System\SettingsManager::get_settings();
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
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\Firewall\VirtualPatchManager::apply_patch($patch_id, $custom_config);
        if (!$result['success']) {
            return new \WP_Error('patch_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function virtual_patch_remove(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field(wp_unslash($params['patch_id'] ?? ''));

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\Firewall\VirtualPatchManager::remove_patch($patch_id);
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
        $manager = new \WcpScanner\Remediation\RemediationManager();
        return rest_ensure_response([
            'backups' => $manager->get_backups(),
        ]);
    }

    public static function rollback_remediation(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field(wp_unslash($params['backup_id'])) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_param', __('Missing backup_id parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $manager = new \WcpScanner\Remediation\RemediationManager();
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
            return new \WP_Error('missing_param', __('Missing hook_name parameter.', 'wcp-security-scanner'), ['status' => 400]);
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
            return new \WP_Error('protected_core_hook', __('Cannot delete essential WordPress core system cron hooks.', 'wcp-security-scanner'), ['status' => 403]);
        }

        // Clear all scheduled instances of this cron hook
        $cleared = wp_clear_scheduled_hook($hook_name);

        if ($issue_id) {
            global $wpdb;
            $table = $wpdb->prefix . 'wcpscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: cron hook name */
            'message' => sprintf(__('Scheduled cron hook "%s" was successfully removed from the WordPress database.', 'wcp-security-scanner'), $hook_name),
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
            return new \WP_Error('missing_comment_id', __('Valid comment ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $comment = get_comment($comment_id);
        if (!$comment && $action !== 'delete') {
            return new \WP_Error('comment_not_found', __('Comment not found or already deleted.', 'wcp-security-scanner'), ['status' => 404]);
        }

        $success = false;
        $message = '';

        switch ($action) {
            case 'trash':
                $success = (bool) wp_trash_comment($comment_id);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been moved to Trash (quarantined from public view).', 'wcp-security-scanner'), $comment_id);
                break;

            case 'spam':
                $success = (bool) wp_spam_comment($comment_id);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been marked as Spam and delisted.', 'wcp-security-scanner'), $comment_id);
                break;

            case 'delete':
                $success = (bool) wp_delete_comment($comment_id, true);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been permanently deleted from the database.', 'wcp-security-scanner'), $comment_id);
                break;

            case 'approve':
                $success = (bool) wp_set_comment_status($comment_id, 'approve');
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d status updated to approved.', 'wcp-security-scanner'), $comment_id);
                break;

            default:
                return new \WP_Error('invalid_action', __('Invalid moderation action. Supported: trash, spam, delete.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if ($success) {
            global $wpdb;
            $table = $wpdb->prefix . 'wcpscan_scan_issues';
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
        $params = $request->get_json_params() ?: [];
        $table = !empty($params['table']) ? sanitize_text_field($params['table']) : '';
        $column = !empty($params['column']) ? sanitize_text_field($params['column']) : '';
        $row_id = !empty($params['row_id']) ? sanitize_text_field($params['row_id']) : '';
        $action = !empty($params['action']) ? sanitize_key($params['action']) : 'delete_row';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table name and Row ID are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WcpScanner\Database\DatabaseRemediationManager();

        if ($action === 'delete_row') {
            $result = $mgr->delete_row_with_backup($table, $row_id, $column, $issue_id);
        } elseif ($action === 'cleanse_field') {
            if (empty($column)) {
                return new \WP_Error('missing_column', __('Column name is required for field cleansing.', 'wcp-security-scanner'), ['status' => 400]);
            }
            $result = $mgr->cleanse_field_with_backup($table, $column, $row_id, $issue_id);
        } else {
            return new \WP_Error('invalid_action', __('Invalid database remediation action.', 'wcp-security-scanner'), ['status' => 400]);
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
            return new \WP_Error('missing_params', __('Table and Row ID are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WcpScanner\Database\DatabaseRemediationManager();
        $pk = $mgr->get_primary_key($table);
        $row = $mgr->get_row($table, $row_id);

        if (!$row) {
            return new \WP_Error('row_not_found', __('Database record not found or already deleted.', 'wcp-security-scanner'), ['status' => 404]);
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
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field($params['backup_id']) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_backup_id', __('Backup ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WcpScanner\Database\DatabaseRemediationManager();
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
        global $wpdb;

        $params = $request->get_json_params() ?: [];
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $role = !empty($params['role']) ? sanitize_key($params['role']) : null;
        $reassign_to = !empty($params['reassign_to']) ? (int) $params['reassign_to'] : null;
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if ($user_id <= 0) {
            return new \WP_Error('invalid_user_id', __('Valid User ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $mgr = new \WcpScanner\WordPress\UserRemediationManager();

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
            return new \WP_Error('invalid_action', __('Invalid user remediation action.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            return new \WP_Error('remediation_failed', $result['error'] ?? __('User remediation failed.', 'wcp-security-scanner'), ['status' => 500]);
        }

        // Mark associated scan issue as repaired if issue_id is provided
        $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
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
        $mgr = new \WcpScanner\WordPress\UserRemediationManager();
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

        $mgr = new \WcpScanner\WordPress\UserRemediationManager();

        if ($restore_all) {
            $result = $mgr->restore_all_user_backups();
            return rest_ensure_response($result);
        }

        if (!empty($backup_file)) {
            $result = $mgr->restore_user($backup_file);
        } elseif ($user_id > 0) {
            $result = $mgr->restore_user_by_id($user_id);
        } else {
            return new \WP_Error('missing_param', __('Specify backup_file or user_id or all.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            return new \WP_Error('restore_failed', $result['error'] ?? __('Failed to restore user account.', 'wcp-security-scanner'), ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get Status
     */
    public static function get_threat_intel_status() {
        return rest_ensure_response(\WcpScanner\Firewall\ThreatIntelService::get_status());
    }

    /**
     * Threat Intelligence: Sync live data
     */
    public static function sync_threat_intel() {
        $result = \WcpScanner\Firewall\ThreatIntelService::sync_threat_data();
        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get CVE catalog
     */
    public static function get_threat_intel_cves() {
        return rest_ensure_response([
            'cves' => \WcpScanner\Firewall\ThreatIntelService::get_cve_catalog(),
        ]);
    }

    /**
     * Auth Security: Get Status & Lockouts
     */
    public static function get_auth_security_status() {
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $user_id  = get_current_user_id();
        $user     = wp_get_current_user();

        return rest_ensure_response([
            'auth_2fa_enabled'          => !empty($settings['auth_2fa_enabled']),
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
            'user_2fa_enabled'          => \WcpScanner\Auth\TwoFactorAuth::is_user_enabled($user_id),
            'user_compliance'           => \WcpScanner\Auth\TwoFactorAuth::get_user_compliance_status($user_id),
            'user_login'                => $user ? $user->user_login : '',
            'user_email'                => $user ? $user->user_email : '',
            'trusted_devices_count'     => count(\WcpScanner\Auth\TwoFactorAuth::get_trusted_devices($user_id)),
            'trusted_devices'           => \WcpScanner\Auth\TwoFactorAuth::get_trusted_devices($user_id),
            'lockouts'                  => array_values(\WcpScanner\Auth\LoginHardening::get_locked_ips()),
            'stats'                     => \WcpScanner\Auth\LoginHardening::get_stats(),
            'active_sessions'           => \WcpScanner\Auth\SessionSentinel::get_active_sessions(),
            'backup_codes_count'        => \WcpScanner\Auth\TwoFactorAuth::get_remaining_backup_codes_count($user_id),
            'current_ip'                => \WcpScanner\Firewall\FirewallEngine::get_client_ip(),
        ]);
    }

    /**
     * Auth Security: Generate 2FA Setup Package
     */
    public static function setup_2fa_for_user() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        $secret           = \WcpScanner\Auth\TwoFactorAuth::generate_secret(16);
        $provisioning_uri = \WcpScanner\Auth\TwoFactorAuth::get_provisioning_uri($secret, $user->user_login);
        $qr_data_uri      = \WcpScanner\Auth\TwoFactorAuth::get_qr_data_uri($provisioning_uri);
        $backup_bundle    = \WcpScanner\Auth\TwoFactorAuth::generate_backup_codes(8);

        // Store setup state in transient for 10 minutes
        set_transient('wcpscan_2fa_setup_' . $user_id, [
            'secret'       => $secret,
            'hashed_codes' => $backup_bundle['hashed'],
        ], 600);

        return rest_ensure_response([
            'secret'           => $secret,
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
        $secret  = sanitize_text_field($params['secret'] ?? '');

        $setup_state = get_transient('wcpscan_2fa_setup_' . $user_id);
        if (!$setup_state || empty($setup_state['secret'])) {
            return new \WP_Error('session_expired', __('2FA setup session expired. Please click "Setup 2FA" again.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $active_secret = $secret ?: $setup_state['secret'];

        if (!\WcpScanner\Auth\TwoFactorAuth::verify_code($active_secret, $code)) {
            return new \WP_Error('invalid_code', __('The 6-digit verification code you entered is invalid. Please check your authenticator clock and try again.', 'wcp-security-scanner'), ['status' => 400]);
        }

        \WcpScanner\Auth\TwoFactorAuth::enable_user($user_id, $active_secret, $setup_state['hashed_codes']);
        delete_transient('wcpscan_2fa_setup_' . $user_id);

        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) is now active on your account!', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Auth Security: Disable 2FA
     */
    public static function disable_2fa_for_user() {
        $user_id = get_current_user_id();
        \WcpScanner\Auth\TwoFactorAuth::disable_user($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) has been disabled.', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Auth Security: Revoke All Trusted Devices
     */
    public static function revoke_2fa_trusted_devices() {
        $user_id = get_current_user_id();
        \WcpScanner\Auth\TwoFactorAuth::revoke_all_trusted_devices($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('All remembered/trusted devices have been revoked. 2FA verification will be required on all browsers.', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Auth Security: Regenerate Backup Codes for Current User
     */
    public static function regenerate_user_backup_codes() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        if (!\WcpScanner\Auth\TwoFactorAuth::is_user_enabled($user_id)) {
            return new \WP_Error('2fa_not_enabled', __('Two-Factor Authentication is not enabled for your account.', 'wcp-security-scanner'), ['status' => 400]);
        }

        try {
            $bundle = \WcpScanner\Auth\TwoFactorAuth::regenerate_backup_codes($user_id, 8);

            if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
                \WcpScanner\System\AuditLogger::log_event(
                    '2fa_backup_codes_regenerated',
                    /* translators: %s: username */
                    sprintf(__('Administrator %s regenerated 2FA emergency backup codes.', 'wcp-security-scanner'), $user->user_login)
                );
            }

            return rest_ensure_response([
                'success'            => true,
                'message'            => __('New 2FA emergency backup codes generated successfully.', 'wcp-security-scanner'),
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
            return new \WP_Error('missing_ip', __('Missing IP parameter.', 'wcp-security-scanner'), ['status' => 400]);
        }
        \WcpScanner\Auth\LoginHardening::unlock_ip($ip);
        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: IP address */
                __('IP %s has been unlocked.', 'wcp-security-scanner'),
                $ip
            ),
        ]);
    }

    /**
     * Auth Security: Clear all lockouts
     */
    public static function clear_all_lockouts() {
        \WcpScanner\Auth\LoginHardening::clear_all_lockouts();
        return rest_ensure_response([
            'success' => true,
            'message' => __('All temporary IP lockouts have been cleared.', 'wcp-security-scanner'),
        ]);
    }

    /**
     * Auth Security: Get Administrator Directory & 2FA Compliance Status
     */
    public static function get_admin_directory_status() {
        $admins = \WcpScanner\Auth\TwoFactorAuth::get_administrators_status();
        $settings = \WcpScanner\System\SettingsManager::get_settings();

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
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'wcp-security-scanner'), ['status' => 404]);
        }

        \WcpScanner\Auth\TwoFactorAuth::disable_user($user_id);

        if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
            \WcpScanner\System\AuditLogger::log_event(
                'admin_2fa_disabled',
                sprintf(
                    /* translators: 1: admin username, 2: target username, 3: user ID */
                    __('Administrator %1$s disabled 2FA for user "%2$s" (ID: %3$d).', 'wcp-security-scanner'),
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
                __('2FA has been disabled and unlocked for administrator %s.', 'wcp-security-scanner'),
                $user->user_login
            ),
            'admins'  => \WcpScanner\Auth\TwoFactorAuth::get_administrators_status(),
        ]);
    }

    /**
     * Auth Security: Admin Reset 2FA & Generate New Setup Package for target user
     */
    public static function admin_reset_user_2fa(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'wcp-security-scanner'), ['status' => 404]);
        }

        try {
            $setup_pkg = \WcpScanner\Auth\TwoFactorAuth::reset_user_2fa($user_id);

            if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
                \WcpScanner\System\AuditLogger::log_event(
                    'admin_2fa_reset',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s regenerated 2FA credentials for user "%2$s" (ID: %3$d).', 'wcp-security-scanner'),
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
                    __('New 2FA credentials generated for %s.', 'wcp-security-scanner'),
                    $user->user_login
                ),
                'setup_package' => $setup_pkg,
                'admins'        => \WcpScanner\Auth\TwoFactorAuth::get_administrators_status(),
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
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'wcp-security-scanner'), ['status' => 404]);
        }

        if (!\WcpScanner\Auth\TwoFactorAuth::is_user_enabled($user_id)) {
            return new \WP_Error(
                '2fa_not_enabled',
                sprintf(
                    /* translators: %s: username */
                    __('2FA is not enabled for user %s.', 'wcp-security-scanner'),
                    $user->user_login
                ),
                ['status' => 400]
            );
        }

        try {
            $bundle = \WcpScanner\Auth\TwoFactorAuth::regenerate_backup_codes($user_id, 8);

            if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
                \WcpScanner\System\AuditLogger::log_event(
                    'admin_2fa_backup_codes_regenerated',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s regenerated backup codes for user "%2$s" (ID: %3$d).', 'wcp-security-scanner'),
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
                    __('New backup codes generated for administrator %s.', 'wcp-security-scanner'),
                    $user->user_login
                ),
                'user_login'         => $user->user_login,
                'backup_codes'       => $bundle['backup_codes'],
                'backup_codes_count' => $bundle['count'],
                'admins'             => \WcpScanner\Auth\TwoFactorAuth::get_administrators_status(),
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
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'wcp-security-scanner'), ['status' => 404]);
        }

        $res = \WcpScanner\Auth\TwoFactorAuth::unlock_user_lockouts($user_id);

        return rest_ensure_response([
            'success'          => true,
            'message'          => sprintf(
                /* translators: %s: username */
                __('Login lockouts and rate-limiting blocks cleared for user %s.', 'wcp-security-scanner'),
                $user->user_login
            ),
            'unlocked_ips'     => $res['unlocked_ips'],
            'admins'           => \WcpScanner\Auth\TwoFactorAuth::get_administrators_status(),
            'lockouts'         => array_values(\WcpScanner\Auth\LoginHardening::get_locked_ips()),
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
        $settings = \WcpScanner\System\SettingsManager::get_settings();

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

        \WcpScanner\System\SettingsManager::save_settings($settings);

        if (class_exists('\\WcpScanner\\System\\AuditLogger')) {
            \WcpScanner\System\AuditLogger::log_event(
                'auth_policy_updated',
                sprintf(
                    /* translators: 1: enforce status, 2: policy mode, 3: grace days */
                    __('Administrator 2FA policy updated: Enforce=%1$s, Mode=%2$s, Grace Days=%3$d.', 'wcp-security-scanner'),
                    $enforce_admins ? 'YES' : 'NO',
                    strtoupper($policy_mode),
                    $grace_days
                )
            );
        }

        return rest_ensure_response([
            'success' => true,
            'message' => __('2FA enforcement policy updated successfully.', 'wcp-security-scanner'),
            'policy'  => [
                'enforce_admins' => $enforce_admins,
                'policy_mode'    => $policy_mode,
                'grace_days'     => $grace_days,
                'enforce_since'  => $settings['auth_2fa_enforce_since'],
            ],
            'admins'  => \WcpScanner\Auth\TwoFactorAuth::get_administrators_status(),
        ]);
    }

    /**
     * Session Sentinel: Get active sessions list
     */
    public static function get_active_sessions_list() {
        return rest_ensure_response([
            'success'    => true,
            'sessions'   => \WcpScanner\Auth\SessionSentinel::get_active_sessions(),
            'current_ip' => \WcpScanner\Firewall\FirewallEngine::get_client_ip(),
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
                \WcpScanner\Auth\SessionSentinel::terminate_all_other_sessions($target_user_id, empty($user_id));
                return rest_ensure_response([
                    'success' => true,
                    'message' => __('All other active sessions have been terminated.', 'wcp-security-scanner'),
                    'sessions' => \WcpScanner\Auth\SessionSentinel::get_active_sessions(),
                ]);
            }

            if (empty($token) || empty($user_id)) {
                return new \WP_Error('missing_params', __('Session token and user ID are required.', 'wcp-security-scanner'), ['status' => 400]);
            }

            \WcpScanner\Auth\SessionSentinel::terminate_session($user_id, $token, 'Revoked by administrator via Session Sentinel.');

            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Session successfully revoked.', 'wcp-security-scanner'),
                'sessions' => \WcpScanner\Auth\SessionSentinel::get_active_sessions(),
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

        $result = \WcpScanner\Auth\LoginHistoryManager::get_user_history($user_id, $limit);

        return rest_ensure_response($result);
    }

    /**
     * Auth Security: Record Dynamic Client Telemetry (Screen Resolution, Viewport, Timezone)
     */
    public static function record_client_telemetry(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Unauthorized', 'wcp-security-scanner'), ['status' => 401]);
        }

        // Rate-limiting: Max 5 submissions per user per 60 seconds to prevent telemetry flooding
        $transient_key = 'wcpscan_telemetry_rate_' . $user_id;
        $hit_count = (int) get_transient($transient_key);
        if ($hit_count >= 5) {
            return new \WP_Error('too_many_requests', __('Telemetry submission rate limit exceeded. Please wait a minute.', 'wcp-security-scanner'), ['status' => 429]);
        }
        set_transient($transient_key, $hit_count + 1, 60);

        $params = $request->get_json_params();
        if (!is_array($params)) {
            return new \WP_Error('invalid_payload', __('Invalid JSON payload structure.', 'wcp-security-scanner'), ['status' => 400]);
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

        \WcpScanner\Auth\LoginHistoryManager::update_session_telemetry($user_id, $telemetry);

        return rest_ensure_response([
            'success' => true,
        ]);
    }

    /**
     * Database: Get Rogue Administrator & Micro-Anomaly Audit
     */
    public static function get_rogue_admin_audit(\WP_REST_Request $request) {
        $audit = \WcpScanner\Database\RogueAdminAnomalyDetector::audit_users_and_anomalies();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Living-off-the-Land (LotL) Hook Infiltration Audit
     */
    public static function get_hook_sentinel_audit(\WP_REST_Request $request) {
        $sentinel = new \WcpScanner\WordPress\HookInfiltrationSentinel();
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

        $result = \WcpScanner\Notifications\WebhookService::send_test($platform, $url);
        return rest_ensure_response($result);
    }

    /**
     * Get granular notification settings & catalog
     */
    public static function get_notification_settings(\WP_REST_Request $request) {
        $settings = \WcpScanner\System\SettingsManager::get_settings();
        $catalog  = \WcpScanner\Notifications\NotificationDispatcher::get_event_catalog();

        return rest_ensure_response([
            'success'                     => true,
            'notification_master_enabled' => !empty($settings['notification_master_enabled']),
            'notification_events'         => $settings['notification_events'] ?? \WcpScanner\System\SettingsManager::get_default_notification_events(),
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
        $current = \WcpScanner\System\SettingsManager::get_settings();

        if (isset($params['notification_master_enabled'])) {
            $current['notification_master_enabled'] = !empty($params['notification_master_enabled']);
        }
        if (isset($params['notification_events']) && is_array($params['notification_events'])) {
            $current['notification_events'] = \WcpScanner\System\SettingsManager::sanitize_notification_events($params['notification_events']);
        }
        if (isset($params['alert_emails'])) {
            $current['alert_emails'] = sanitize_text_field($params['alert_emails']);
        }

        $saved = \WcpScanner\System\SettingsManager::save_settings($current);

        return rest_ensure_response([
            'success'                     => true,
            'message'                     => __('Notification settings saved successfully.', 'wcp-security-scanner'),
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
            return new \WP_Error('missing_event', __('Event key is required for notification testing.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $catalog = \WcpScanner\Notifications\NotificationDispatcher::get_event_catalog();
        if (!isset($catalog[$event_key])) {
            return new \WP_Error('invalid_event', __('Unknown security event identifier.', 'wcp-security-scanner'), ['status' => 404]);
        }

        $result = \WcpScanner\Notifications\NotificationDispatcher::trigger($event_key, [
            /* translators: %s: event title */
            'title'   => sprintf(__('[TEST] %s', 'wcp-security-scanner'), $catalog[$event_key]['title']),
            /* translators: %s: event title */
            'message' => sprintf(__('This is an instant verification alert triggered from the WCP Notification Center for "%s".', 'wcp-security-scanner'), $catalog[$event_key]['title']),
            'details' => [
                'triggered_by' => wp_get_current_user()->user_login ?: 'admin',
                'event_code'   => $event_key,
                'test_mode'    => 'manual_verification',
            ],
        ]);

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: event title */
            'message' => sprintf(__('Test notification dispatched for event: %s', 'wcp-security-scanner'), $catalog[$event_key]['title']),
            'result'  => $result,
        ]);
    }

    /**
     * Helper to load CloudflareService reliably
     */
    private static function ensure_cloudflare_service(): bool {
        if (!class_exists('\WcpScanner\Cloudflare\CloudflareService')) {
            $candidates = [
                WCPSCAN_PATH . 'includes/Cloudflare/CloudflareService.php',
                WCPSCAN_PATH . 'includes/cloudflare/CloudflareService.php',
                WCPSCAN_PATH . 'includes/Firewall/CloudflareService.php',
            ];
            foreach ($candidates as $file) {
                if (file_exists($file)) {
                    require_once $file;
                    break;
                }
            }
        }
        return class_exists('\WcpScanner\Cloudflare\CloudflareService');
    }

    /**
     * Cloudflare Edge Defense Handlers
     */
    public static function get_cloudflare_status(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $status = \WcpScanner\Cloudflare\CloudflareService::get_status();
        $definitions = \WcpScanner\Cloudflare\CloudflareService::get_rule_definitions();
        $compound_rules = \WcpScanner\Cloudflare\CloudflareService::get_compound_rule_definitions();
        $edge_advisor = \WcpScanner\Cloudflare\CloudflareService::get_edge_advisor();
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
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation. Please reinstall or update the plugin zip.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $token   = !empty($params['token']) ? trim(sanitize_text_field($params['token'])) : null;
        $zone_id = !empty($params['zone_id']) ? trim(sanitize_text_field($params['zone_id'])) : null;

        $result = \WcpScanner\Cloudflare\CloudflareService::verify_zone($zone_id, $token);
        return rest_ensure_response($result);
    }

    public static function deploy_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $rules  = is_array($params['rules'] ?? null) ? $params['rules'] : [];

        $result = \WcpScanner\Cloudflare\CloudflareService::deploy_custom_rules($rules);
        return rest_ensure_response($result);
    }

    public static function deploy_single_cloudflare_rule(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params   = $request->get_json_params() ?: [];
        $rule_key = sanitize_key($params['rule_key'] ?? '');
        $config   = is_array($params['config'] ?? null) ? $params['config'] : [];
        $enable   = !isset($params['enabled']) || !empty($params['enabled']);

        $result = \WcpScanner\Cloudflare\CloudflareService::deploy_single_rule($rule_key, $config, $enable);
        return rest_ensure_response($result);
    }

    public static function toggle_cloudflare_rate_limiting(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $enable  = !empty($params['enabled']);
        $options = is_array($params['options'] ?? null) ? $params['options'] : [];

        $result = \WcpScanner\Cloudflare\CloudflareService::toggle_rate_limiting($enable, $options);
        return rest_ensure_response($result);
    }

    public static function block_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Manual block via Security Scanner');

        $result = \WcpScanner\Cloudflare\CloudflareService::block_ip($ip, $reason);
        return rest_ensure_response($result);
    }

    public static function get_cloudflare_banned_ips(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(100, (int) ($request->get_param('per_page') ?: 50)));

        $result = \WcpScanner\Cloudflare\CloudflareService::get_banned_ips($page, $per_page);
        return rest_ensure_response($result);
    }

    public static function unblock_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field($params['rule_id'] ?? '');

        $result = \WcpScanner\Cloudflare\CloudflareService::unblock_ip($rule_id);
        return rest_ensure_response($result);
    }

    public static function purge_cloudflare_cache(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $files  = !empty($params['files']) && is_array($params['files']) ? array_map('esc_url_raw', $params['files']) : null;

        $result = \WcpScanner\Cloudflare\CloudflareService::purge_cache($files);
        return rest_ensure_response($result);
    }

    public static function inspect_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $settings = \WcpScanner\Settings\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $result = \WcpScanner\Cloudflare\CloudflareService::inspect_edge_rules($zone_id);
        return rest_ensure_response($result);
    }

    public static function whitelist_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $notes  = sanitize_text_field($params['notes'] ?? 'Administrator / Developer Whitelist via WCP');

        $result = \WcpScanner\Cloudflare\CloudflareService::whitelist_ip($ip, $notes);
        return rest_ensure_response($result);
    }

    public static function disconnect_cloudflare(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $result = \WcpScanner\Cloudflare\CloudflareService::disconnect();
        return rest_ensure_response($result);
    }

    public static function get_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $result = \WcpScanner\Cloudflare\CloudflareService::get_stored_firewall_events();
        return rest_ensure_response($result);
    }

    public static function fetch_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $limit  = isset($params['limit']) ? intval($params['limit']) : 100;

        $result = \WcpScanner\Cloudflare\CloudflareService::fetch_and_store_firewall_events($limit);
        return rest_ensure_response($result);
    }

    // ==========================================
    // 13. Whitelist & False-Positive Endpoints
    // ==========================================

    public static function get_whitelist_rules(\WP_REST_Request $request) {
        $rules = \WcpScanner\Findings\WhitelistManager::get_whitelist_rules(false);
        return rest_ensure_response([
            'success' => true,
            'rules'   => $rules,
            'active_count' => count(array_filter($rules, fn($r) => ($r['status'] ?? '') === 'active')),
        ]);
    }

    public static function add_whitelist_rule(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $result = \WcpScanner\Findings\WhitelistManager::add_rule($params);
        return rest_ensure_response($result);
    }

    public static function remove_whitelist_rule(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: $request->get_params();
        $rule_id = sanitize_text_field($params['id'] ?? $params['rule_id'] ?? '');

        if (empty($rule_id)) {
            return new \WP_Error('missing_param', __('Rule ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $removed = \WcpScanner\Findings\WhitelistManager::remove_rule($rule_id);
        return rest_ensure_response([
            'success' => $removed,
            'rule_id' => $rule_id,
            'message' => $removed ? __('Whitelist rule revoked successfully.', 'wcp-security-scanner') : __('Rule not found or could not be revoked.', 'wcp-security-scanner'),
        ]);
    }

    // ==========================================
    // 14. Behavioral Baseline Engine Endpoints
    // ==========================================

    public static function get_baseline_status(\WP_REST_Request $request) {
        $baseline = \WcpScanner\Integrity\BehavioralBaselineEngine::get_baseline();
        return rest_ensure_response([
            'success'    => true,
            'calibrated' => ($baseline !== null),
            'baseline'   => $baseline,
        ]);
    }

    public static function calibrate_baseline(\WP_REST_Request $request) {
        $result = \WcpScanner\Integrity\BehavioralBaselineEngine::calibrate();
        return rest_ensure_response($result);
    }

    public static function audit_baseline_deviations(\WP_REST_Request $request) {
        $result = \WcpScanner\Integrity\BehavioralBaselineEngine::audit_baseline();
        return rest_ensure_response($result);
    }

    // ==========================================
    // 15. Transactional Remediation & Rollback
    // ==========================================

    public static function get_remediation_transactions(\WP_REST_Request $request) {
        $limit = max(1, min(100, intval($request->get_param('limit') ?: 30)));
        $list  = \WcpScanner\Remediation\TransactionalRemediation::list_transactions($limit);
        return rest_ensure_response([
            'success'      => true,
            'transactions' => $list,
        ]);
    }

    public static function rollback_remediation_transaction(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $tx_id  = sanitize_text_field($params['tx_id'] ?? '');

        if (empty($tx_id)) {
            return new \WP_Error('missing_param', __('Transaction ID (tx_id) is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\Remediation\TransactionalRemediation::rollback_transaction($tx_id);
        return rest_ensure_response($result);
    }

    // ==========================================
    // 16. Model Context Protocol (MCP) Agent Service
    // ==========================================

    public static function get_mcp_tools(\WP_REST_Request $request) {
        $catalog = \WcpScanner\Api\MCPAgentService::get_tools_catalog();
        return rest_ensure_response($catalog);
    }

    public static function execute_mcp_tool(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $tool   = sanitize_text_field($params['tool'] ?? $params['name'] ?? '');
        $args   = is_array($params['arguments'] ?? null) ? $params['arguments'] : (is_array($params['args'] ?? null) ? $params['args'] : []);

        if (empty($tool)) {
            return new \WP_Error('missing_tool', __('Tool name is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\Api\MCPAgentService::execute_tool($tool, $args);
        return rest_ensure_response($result);
    }

    public static function get_mcp_audit(\WP_REST_Request $request) {
        $limit = max(10, min(150, intval($request->get_param('limit') ?? 50)));
        return rest_ensure_response([
            'success' => true,
            'entries' => \WcpScanner\Api\MCPAgentService::get_audit_log($limit),
        ]);
    }

    public static function clear_mcp_audit(\WP_REST_Request $request) {
        \WcpScanner\Api\MCPAgentService::clear_audit_log();
        return rest_ensure_response([
            'success' => true,
            'message' => __('MCP agent audit trail cleared.', 'wcp-security-scanner'),
        ]);
    }

    public static function get_mcp_staged_actions(\WP_REST_Request $request) {
        $status = sanitize_text_field($request->get_param('status') ?? 'all');
        return rest_ensure_response([
            'success' => true,
            'actions' => \WcpScanner\Api\MCPAgentService::get_staged_actions($status),
        ]);
    }

    public static function approve_mcp_staged_action(\WP_REST_Request $request) {
        $staged_id = sanitize_text_field($request->get_param('staged_id') ?? '');
        if (empty($staged_id)) {
            return new \WP_Error('missing_param', __('Staged action ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $res = \WcpScanner\Api\MCPAgentService::approve_staged_action($staged_id, get_current_user_id());
        return rest_ensure_response($res);
    }

    public static function reject_mcp_staged_action(\WP_REST_Request $request) {
        $staged_id = sanitize_text_field($request->get_param('staged_id') ?? '');
        if (empty($staged_id)) {
            return new \WP_Error('missing_param', __('Staged action ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $res = \WcpScanner\Api\MCPAgentService::reject_staged_action($staged_id, get_current_user_id());
        return rest_ensure_response($res);
    }

    public static function handle_mcp_matrix(\WP_REST_Request $request) {
        if ($request->get_method() === 'POST') {
            $params = $request->get_json_params() ?: [];
            $matrix = is_array($params['matrix'] ?? null) ? $params['matrix'] : [];
            $clean_matrix = \WcpScanner\System\SettingsManager::sanitize_mcp_tool_matrix($matrix);
            $settings = \WcpScanner\System\SettingsManager::get_settings();
            $settings['mcp_tool_matrix'] = $clean_matrix;
            \WcpScanner\System\SettingsManager::save_settings($settings);

            return rest_ensure_response([
                'success' => true,
                'matrix'  => $clean_matrix,
                'message' => __('MCP tool policy governance matrix saved.', 'wcp-security-scanner'),
            ]);
        }

        $matrix = \WcpScanner\System\SettingsManager::get('mcp_tool_matrix', \WcpScanner\System\SettingsManager::get_default_mcp_tool_matrix());
        return rest_ensure_response([
            'success' => true,
            'matrix'  => $matrix,
        ]);
    }

    public static function run_security_drill(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $vectors = is_array($params['vectors'] ?? null) ? $params['vectors'] : [];
        $report = \WcpScanner\Security\AttackSimulationEngine::run_simulation($vectors);

        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function get_security_drill_results(\WP_REST_Request $request) {
        $report = \WcpScanner\Security\AttackSimulationEngine::get_latest_results();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function get_containment_status(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success' => true,
            'status'  => \WcpScanner\Security\EmergencyContainmentManager::get_status(),
        ]);
    }

    public static function toggle_containment(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $action = sanitize_text_field($params['action'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Administrator Security Incident Action');
        $maintenance = !empty($params['maintenance_enabled']);

        if ($action === 'activate') {
            $res = \WcpScanner\Security\EmergencyContainmentManager::activate([
                'reason'              => $reason,
                'maintenance_enabled' => $maintenance,
            ]);
        } elseif ($action === 'deactivate') {
            $res = \WcpScanner\Security\EmergencyContainmentManager::deactivate(get_current_user_id());
        } else {
            return new \WP_Error('invalid_action', __('Invalid containment action. Must be "activate" or "deactivate".', 'wcp-security-scanner'), ['status' => 400]);
        }

        return rest_ensure_response($res);
    }

    // ==========================================
    // 17. Supply-Chain Defense & SBOM Sentinel Handlers
    // ==========================================

    public static function get_supply_chain_sbom(\WP_REST_Request $request) {
        $report = \WcpScanner\SupplyChain\SbomSentinelEngine::check_drift();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function calibrate_supply_chain_sbom(\WP_REST_Request $request) {
        $result = \WcpScanner\SupplyChain\SbomSentinelEngine::calibrate_baseline();
        return rest_ensure_response($result);
    }

    public static function isolate_supply_chain_anchor(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $item_id = sanitize_text_field($params['item_id'] ?? '');

        if (empty($item_id)) {
            return new \WP_Error('missing_item_id', __('Item ID is required for isolation.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\SupplyChain\SbomSentinelEngine::isolate_anchor($item_id);
        return rest_ensure_response($result);
    }

    public static function get_supply_chain_gatekeeper(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success'   => true,
            'logs'      => \WcpScanner\SupplyChain\UpdateGatekeeperEngine::get_logs(30),
            'snapshots' => \WcpScanner\SupplyChain\UpdateGatekeeperEngine::get_snapshots(),
            'settings'  => \WcpScanner\SupplyChain\UpdateGatekeeperEngine::get_settings(),
        ]);
    }

    public static function update_supply_chain_gatekeeper_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $updated = \WcpScanner\SupplyChain\UpdateGatekeeperEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Gatekeeper settings saved successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function rollback_supply_chain_gatekeeper(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $snapshot_id = sanitize_text_field($params['snapshot_id'] ?? '');

        if (empty($snapshot_id)) {
            return new \WP_Error('missing_snapshot_id', __('Snapshot ID is required for rollback.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\SupplyChain\UpdateGatekeeperEngine::rollback_snapshot($snapshot_id);
        return rest_ensure_response($result);
    }

    public static function clear_supply_chain_gatekeeper_logs(\WP_REST_Request $request) {
        \WcpScanner\SupplyChain\UpdateGatekeeperEngine::clear_logs();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Gatekeeper intercepted logs cleared successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function analyze_supply_chain_plugin(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $slug = sanitize_text_field($params['slug'] ?? '');

        if (empty($slug)) {
            return new \WP_Error('missing_slug', __('Plugin slug is required for risk analysis.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $analysis = \WcpScanner\SupplyChain\InstallRiskAdvisor::analyze_installed_plugin($slug);
        return rest_ensure_response([
            'success'  => true,
            'analysis' => $analysis,
        ]);
    }

    // ==========================================
    // 17.5. Behavioral WAF, Bot Traps & Rate Limiting (Pillar 3)
    // ==========================================

    public static function get_behavioral_waf_status(\WP_REST_Request $request) {
        $learning_stats    = class_exists('\WcpScanner\Firewall\LearningModeEngine') ? \WcpScanner\Firewall\LearningModeEngine::get_summary_stats() : [];
        $route_profiles    = class_exists('\WcpScanner\Firewall\LearningModeEngine') ? \WcpScanner\Firewall\LearningModeEngine::get_route_profiles() : [];
        $learning_settings = class_exists('\WcpScanner\Firewall\LearningModeEngine') ? \WcpScanner\Firewall\LearningModeEngine::get_settings() : [];
        $honeytoken        = class_exists('\WcpScanner\Firewall\HoneyTokenEngine') ? \WcpScanner\Firewall\HoneyTokenEngine::get_summary() : [];
        $rate_limiter      = class_exists('\WcpScanner\Firewall\AdaptiveRateLimiter') ? \WcpScanner\Firewall\AdaptiveRateLimiter::get_telemetry() : [];

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
            return new \WP_Error('missing_params', __('Route key and action are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Firewall\LearningModeEngine')) {
            return new \WP_Error('missing_engine', __('LearningModeEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $result = \WcpScanner\Firewall\LearningModeEngine::set_route_status($route_key, $action);
        return rest_ensure_response($result);
    }

    public static function update_behavioral_learning_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WcpScanner\Firewall\LearningModeEngine')) {
            return new \WP_Error('missing_engine', __('LearningModeEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $updated = \WcpScanner\Firewall\LearningModeEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Learning Mode 2.0 settings updated successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function update_honeytoken_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WcpScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $updated = \WcpScanner\Firewall\HoneyTokenEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Honey-Token Bot Trap settings updated successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function unban_honeytoken_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field($params['ip'] ?? '');
        if (empty($ip)) {
            return new \WP_Error('missing_ip', __('IP address is required.', 'wcp-security-scanner'), ['status' => 400]);
        }
        if (!class_exists('\WcpScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $result = \WcpScanner\Firewall\HoneyTokenEngine::unban_bot_ip($ip);
        return rest_ensure_response($result);
    }

    public static function update_rate_limiter_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WcpScanner\Firewall\AdaptiveRateLimiter')) {
            return new \WP_Error('missing_engine', __('AdaptiveRateLimiter not available.', 'wcp-security-scanner'), ['status' => 500]);
        }
        $updated = \WcpScanner\Firewall\AdaptiveRateLimiter::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Adaptive Rate Limiter thresholds updated successfully.', 'wcp-security-scanner'),
        ]);
    }

    // ==========================================
    // 17.6. Zero-Trust Identity, Session Forensics & JIT Elevation (Pillar 4)
    // ==========================================

    public static function get_identity_forensics_status(\WP_REST_Request $request) {
        $sessions_report = class_exists('\WcpScanner\Identity\SessionForensicsEngine')
            ? \WcpScanner\Identity\SessionForensicsEngine::get_active_sessions_report()
            : [];
        $active_elevations = class_exists('\WcpScanner\Identity\EphemeralAdminEngine')
            ? \WcpScanner\Identity\EphemeralAdminEngine::get_active_elevations()
            : [];
        $elevation_history = class_exists('\WcpScanner\Identity\EphemeralAdminEngine')
            ? \WcpScanner\Identity\EphemeralAdminEngine::get_elevation_history(20)
            : [];
        $hibp_summary = class_exists('\WcpScanner\Identity\HIBPBreachAuditor')
            ? \WcpScanner\Identity\HIBPBreachAuditor::get_summary()
            : [];

        $candidate_users = class_exists('\WcpScanner\Identity\EphemeralAdminEngine')
            ? \WcpScanner\Identity\EphemeralAdminEngine::get_candidate_users(200)
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
            return new \WP_Error('missing_params', __('User ID and session verifier are required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $res = \WcpScanner\Identity\SessionForensicsEngine::revoke_session($user_id, $verifier);
        return rest_ensure_response($res);
    }

    public static function revoke_all_identity_sessions(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $res = \WcpScanner\Identity\SessionForensicsEngine::revoke_all_sessions($user_id);
        return rest_ensure_response($res);
    }

    public static function grant_identity_jit_elevation(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $user_id  = intval($params['user_id'] ?? 0);
        $duration = intval($params['duration_minutes'] ?? 60);
        $reason   = sanitize_text_field($params['reason'] ?? '');

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required for elevation.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Identity\EphemeralAdminEngine')) {
            return new \WP_Error('missing_engine', __('EphemeralAdminEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $res = \WcpScanner\Identity\EphemeralAdminEngine::grant_elevation($user_id, $duration, $reason);
        return rest_ensure_response($res);
    }

    public static function revoke_identity_jit_elevation(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);
        $reason  = sanitize_text_field($params['reason'] ?? 'Manual revocation by administrator');

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Identity\EphemeralAdminEngine')) {
            return new \WP_Error('missing_engine', __('EphemeralAdminEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $res = \WcpScanner\Identity\EphemeralAdminEngine::revoke_elevation($user_id, $reason);
        return rest_ensure_response($res);
    }

    public static function get_candidate_users_route(\WP_REST_Request $request) {
        $users = class_exists('\WcpScanner\Identity\EphemeralAdminEngine')
            ? \WcpScanner\Identity\EphemeralAdminEngine::get_candidate_users(200)
            : [];

        return rest_ensure_response([
            'success' => true,
            'users'   => $users,
        ]);
    }

    public static function audit_identity_privileged_users(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\Identity\HIBPBreachAuditor')) {
            return new \WP_Error('missing_engine', __('HIBPBreachAuditor not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $report = \WcpScanner\Identity\HIBPBreachAuditor::audit_privileged_users();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function force_identity_password_reset(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Identity\HIBPBreachAuditor')) {
            return new \WP_Error('missing_engine', __('HIBPBreachAuditor not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $res = \WcpScanner\Identity\HIBPBreachAuditor::force_password_reset($user_id);
        return rest_ensure_response($res);
    }

    public static function update_identity_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WcpScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $updated = \WcpScanner\Identity\SessionForensicsEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Identity forensics settings updated successfully.', 'wcp-security-scanner'),
        ]);
    }

    public static function dismiss_impossible_travel_alert(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $alert_id = sanitize_text_field($params['alert_id'] ?? '');

        if (empty($alert_id)) {
            return new \WP_Error('missing_alert_id', __('Alert ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        if (!class_exists('\WcpScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'wcp-security-scanner'), ['status' => 500]);
        }

        $res = \WcpScanner\Identity\SessionForensicsEngine::dismiss_travel_alert($alert_id);
        return rest_ensure_response($res);
    }

    // ==========================================
    // 18. Unified WCP Vault Status & Rotator
    // ==========================================

    public static function get_vault_status(\WP_REST_Request $request) {
        // 1. Quarantine stats
        $qm = new \WcpScanner\Quarantine\QuarantineManager();
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
        $db_backup = new \WcpScanner\Backup\DatabaseBackup();
        $db_backups = $db_backup->list_backups();
        $db_count = count($db_backups);
        $db_size_mb = 0;
        foreach ($db_backups as $b) {
            $db_size_mb += floatval($b['size_mb'] ?? 0);
        }

        // 3. Transactions & Missing Users stats
        $transactions = \WcpScanner\Remediation\TransactionalRemediation::list_transactions(50);
        $tx_count = count($transactions);
        $user_mgr = new \WcpScanner\WordPress\UserRemediationManager();
        $missing_users = $user_mgr->get_missing_user_backups();
        $missing_users_count = count($missing_users);

        // 4. Secret Vault & Key Rotator stats
        $key_source = 'wp_salt';
        $env_key = getenv('WCP_VAULT_KEY');
        if (!empty($env_key)) {
            $key_source = 'env';
        } elseif (defined('WCP_VAULT_KEY') && !empty(WCP_VAULT_KEY)) {
            $key_source = 'constant';
        }

        $raw_key = \WcpScanner\Security\SecretVault::get_key();
        $key_fingerprint = substr(hash('sha256', $raw_key), 0, 16) . '...';
        $is_hex_key = defined('WCP_VAULT_KEY') && strlen((string) WCP_VAULT_KEY) === 64 && ctype_xdigit((string) WCP_VAULT_KEY);

        $openssl_ok = function_exists('openssl_encrypt');
        $gcm_ok = $openssl_ok && in_array(\WcpScanner\Security\SecretVault::CIPHER_GCM, openssl_get_cipher_methods(), true);

        $settings = get_option(\WcpScanner\System\SettingsManager::OPTION_KEY, []);
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
            $is_enc = $is_set && \WcpScanner\Security\SecretVault::is_encrypted($val);
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

        $rot_state = get_option(\WcpScanner\Security\VaultRotator::STATE_OPTION, ['status' => 'idle']);

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
                'is_constant_defined' => defined('WCP_VAULT_KEY') && !empty(WCP_VAULT_KEY),
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

        $init = \WcpScanner\Security\VaultRotator::start_rotation($new_key, $force);
        if (is_wp_error($init)) {
            return $init;
        }

        $cont = \WcpScanner\Security\VaultRotator::continue_rotation(100);
        if (is_wp_error($cont)) {
            return $cont;
        }

        $commit = \WcpScanner\Security\VaultRotator::verify_and_commit();
        if (is_wp_error($commit)) {
            return $commit;
        }

        return rest_ensure_response([
            'success'          => true,
            'message'          => __('Vault encryption keys rotated and all credentials safely re-encrypted.', 'wcp-security-scanner'),
            'new_key_material' => $new_key,
            'status'           => $commit,
        ]);
    }

    public static function rollback_vault_rotation(\WP_REST_Request $request) {
        $res = \WcpScanner\Security\VaultRotator::rollback();
        if (is_wp_error($res)) {
            return $res;
        }
        return rest_ensure_response([
            'success' => true,
            'message' => __('Vault key rotation rolled back to pre-rotation state.', 'wcp-security-scanner'),
            'status'  => $res,
        ]);
    }

    public static function reset_vault_rotation(\WP_REST_Request $request) {
        \WcpScanner\Security\VaultRotator::reset_state();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Vault rotation state and locks cleared successfully.', 'wcp-security-scanner'),
            'status'  => \WcpScanner\Security\VaultRotator::get_status(),
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
                $findings[] = new \WcpScanner\Findings\Finding([
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
        $quarantine_dir = \WcpScanner\Quarantine\QuarantineManager::get_quarantine_dir();
        if (!is_dir($quarantine_dir)) {
            return $findings;
        }

        $htaccess = rtrim($quarantine_dir, '/\\') . '/.htaccess';
        if (!file_exists($htaccess)) {
            $findings[] = new \WcpScanner\Findings\Finding([
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
                $findings[] = new \WcpScanner\Findings\Finding([
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

        $findings[] = new \WcpScanner\Findings\Finding([
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
                    $findings[] = new \WcpScanner\Findings\Finding([
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
                $findings[] = new \WcpScanner\Findings\Finding([
                    'engine'      => 'system-storage',
                    'type'        => 'disk_space_critical',
                    'severity'    => 'critical',
                    'confidence'  => 100,
                    'file_path'   => 'system:storage:disk',
                    'description' => "Server disk space is dangerously exhausted ({$percent_used}% used, only {$free_mb} MB available). Risk of immediate database corruption, failed updates, and log write halts.",
                    'evidence'    => "Total: " . round($total / 1024 / 1024 / 1024, 2) . " GB, Free: " . round($free / 1024 / 1024 / 1024, 2) . " GB ({$percent_used}% used)."
                ]);
            } elseif ($percent_used >= 88) {
                $findings[] = new \WcpScanner\Findings\Finding([
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
        $waf_enabled = \WcpScanner\System\SettingsManager::get('waf_enabled', true);
        $waf_mode = \WcpScanner\System\SettingsManager::get('waf_mode', 'enabled');

        if (!$waf_enabled || $waf_mode === 'disabled') {
            $findings[] = new \WcpScanner\Findings\Finding([
                'engine'      => 'firewall',
                'type'        => 'waf_inactive',
                'severity'    => 'high',
                'confidence'  => 100,
                'file_path'   => 'firewall:status',
                'description' => 'Web Application Firewall (WAF) is currently disabled. Incoming malicious HTTP payloads (SQLi, XSS, Path Traversal) are not being filtered at the application boundary.',
                'evidence'    => 'WAF state: disabled in plugin security settings.'
            ]);
        } elseif ($waf_mode === 'learning') {
            $findings[] = new \WcpScanner\Findings\Finding([
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
        $test_host = apply_filters('wcpscan_test_reputation_domain', $opts['test_domain'] ?? null);
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
                $findings[] = new \WcpScanner\Findings\Finding([
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
                $findings[] = new \WcpScanner\Findings\Finding([
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
            $test_ip = apply_filters('wcpscan_test_reputation_ip', $opts['test_ip'] ?? null);
            $raw_srv_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['SERVER_ADDR'])) : '';
            $server_ip = !empty($test_ip) ? $test_ip : ($raw_srv_ip ?: gethostbyname($host ?: 'localhost'));

            if (filter_var($server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || !empty($test_ip)) {
                $rev_ip = implode('.', array_reverse(explode('.', $server_ip)));

                // 3.1 Spamcop SCBL
                $spamcop_query = "{$rev_ip}.bl.spamcop.net";
                $sc_res = @gethostbyname($spamcop_query);
                if ($sc_res && $sc_res !== $spamcop_query && strpos($sc_res, '127.0.0.') === 0) {
                    $findings[] = new \WcpScanner\Findings\Finding([
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
                    $findings[] = new \WcpScanner\Findings\Finding([
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
                    $findings[] = new \WcpScanner\Findings\Finding([
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
        if (!class_exists('\WcpScanner\Security\PluginSelfDefense')) {
            $file = WCPSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $last_audit = get_option(\WcpScanner\Security\PluginSelfDefense::DB_LAST_AUDIT_OPTION, null);
        if (!$last_audit) {
            $last_audit = \WcpScanner\Security\PluginSelfDefense::run_audit(false);
        }

        $settings = \WcpScanner\System\SettingsManager::get_settings();

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
        if (!class_exists('\WcpScanner\Security\PluginSelfDefense')) {
            $file = WCPSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $audit = \WcpScanner\Security\PluginSelfDefense::run_audit(true);

        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
            'message' => !empty($audit['has_issues'])
                ? __('Self-defense verification completed: anomalies detected in plugin files.', 'wcp-security-scanner')
                : __('All plugin core files are 100% authentic, intact, and verified against the official release signature.', 'wcp-security-scanner'),
        ]);
    }

    public static function audit_self_defense_against_github(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\Security\PluginSelfDefense')) {
            $file = WCPSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $res = \WcpScanner\Security\PluginSelfDefense::audit_against_github(true);
        return rest_ensure_response($res);
    }

    public static function restore_self_defense_file(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\Security\PluginSelfDefense')) {
            $file = WCPSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $params = $request->get_json_params();
        $path = sanitize_text_field($params['path'] ?? '');

        if (empty($path)) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('Path parameter is required for file restoration.', 'wcp-security-scanner'),
            ]);
        }

        $res = \WcpScanner\Security\PluginSelfDefense::restore_file_from_github($path);
        return rest_ensure_response($res);
    }

    // ==========================================
    // 17. Plugin GitHub Updater & Rollback Endpoints
    // ==========================================

    public static function get_updater_status(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\System\PluginUpdater')) {
            $file = WCPSCAN_PATH . 'includes/System/PluginUpdater.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $status = \WcpScanner\System\PluginUpdater::check_update_status(false);
        $backups = \WcpScanner\System\PluginUpdater::get_local_backups();

        return rest_ensure_response([
            'success' => true,
            'status'  => $status,
            'backups' => $backups,
        ]);
    }

    public static function check_for_updates(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\System\PluginUpdater')) {
            $file = WCPSCAN_PATH . 'includes/System/PluginUpdater.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $status = \WcpScanner\System\PluginUpdater::check_update_status(true);
        $backups = \WcpScanner\System\PluginUpdater::get_local_backups();

        return rest_ensure_response([
            'success' => true,
            'status'  => $status,
            'backups' => $backups,
            'message' => $status['has_update']
                /* translators: %s: new version */
                ? sprintf(__('New update %s is available on GitHub!', 'wcp-security-scanner'), $status['latest_version'])
                : __('You are running the latest version directly from GitHub.', 'wcp-security-scanner'),
        ]);
    }

    public static function execute_plugin_update(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\System\PluginUpdater')) {
            $file = WCPSCAN_PATH . 'includes/System/PluginUpdater.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $params = $request->get_json_params();
        $download_url = !empty($params['download_url']) ? esc_url_raw($params['download_url']) : null;

        $res = \WcpScanner\System\PluginUpdater::execute_update($download_url);
        return rest_ensure_response($res);
    }

    public static function create_plugin_backup(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\System\PluginUpdater')) {
            $file = WCPSCAN_PATH . 'includes/System/PluginUpdater.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $res = \WcpScanner\System\PluginUpdater::create_local_backup();
        $backups = \WcpScanner\System\PluginUpdater::get_local_backups();

        return rest_ensure_response([
            'success' => $res['success'],
            'message' => $res['message'],
            'backups' => $backups,
        ]);
    }

    public static function execute_plugin_rollback(\WP_REST_Request $request) {
        if (!class_exists('\WcpScanner\System\PluginUpdater')) {
            $file = WCPSCAN_PATH . 'includes/System/PluginUpdater.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $params = $request->get_json_params();
        $backup_id = sanitize_text_field($params['backup_id'] ?? '');
        $download_url = !empty($params['download_url']) ? esc_url_raw($params['download_url']) : null;

        $res = \WcpScanner\System\PluginUpdater::execute_rollback($backup_id, $download_url);
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
                __('Threat intelligence feeds synchronized! Active pool: %1$d botnet IPs, %2$d Tor exit nodes.', 'wcp-security-scanner'),
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
        $settings = \WcpScanner\System\SettingsManager::get_settings();
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
            return new \WP_Error('missing_patch_rule', __('Virtual patch definition and regex pattern are required for simulation.', 'wcp-security-scanner'), ['status' => 400]);
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
            return new \WP_Error('missing_patch_id', __('Valid patch definition with patch_id is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::save_synthesized_patch($patch, $deploy_cf);
        return rest_ensure_response($result);
    }

    public static function toggle_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field($params['patch_id'] ?? '');
        $enable = !empty($params['enable']);

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::toggle_synthesized_patch($patch_id, $enable);
        return rest_ensure_response($result);
    }

    public static function delete_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field($params['patch_id'] ?? '');

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::delete_synthesized_patch($patch_id);
        return rest_ensure_response($result);
    }

    public static function virtual_patch_cve_lookup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $cve_id = sanitize_text_field(wp_unslash($params['cve_id'] ?? ''));

        if (empty($cve_id)) {
            return new \WP_Error('missing_cve_id', __('CVE ID is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\Firewall\CVEIntelligenceService::lookup_and_correlate($cve_id);
        if (!$result['success']) {
            return new \WP_Error('cve_lookup_failed', $result['message'], ['status' => 404]);
        }

        return rest_ensure_response($result);
    }

    public static function virtual_patch_deactivate_component(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $plugin_file = sanitize_text_field(wp_unslash($params['plugin_file'] ?? ''));

        if (empty($plugin_file)) {
            return new \WP_Error('missing_plugin_file', __('Target plugin file is required.', 'wcp-security-scanner'), ['status' => 400]);
        }

        $result = \WcpScanner\Firewall\CVEIntelligenceService::deactivate_vulnerable_plugin($plugin_file);
        if (!$result['success']) {
            return new \WP_Error('deactivation_failed', $result['message'], ['status' => 400]);
        }

        return rest_ensure_response($result);
    }
}


