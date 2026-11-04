<?php
namespace WcpScanner\Database;

use WcpScanner\Findings\Finding;
use Closure;
use ReflectionFunction;
use ReflectionMethod;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WP-Cron & Scheduled Event Persistence Sentinel.
 *
 * Inspects serialized cron options in wp_options and ActionScheduler database tables
 * for rogue scheduled hooks, orphaned callbacks, closures originating from eval or uploads,
 * weaponized $args payloads, and core-spoofing cron hooks.
 */
class CronPersistenceScanner {

    /**
     * Official WordPress Core cron hooks.
     */
    private const CORE_CRON_HOOKS = [
        'wp_version_check',
        'wp_update_plugins',
        'wp_update_themes',
        'wp_maybe_auto_update',
        'wp_scheduled_delete',
        'wp_scheduled_auto_draft_delete',
        'wp_privacy_delete_old_export_files',
        'wp_site_health_scheduled_check',
        'wp_https_detection',
        'wp_update_user_counts',
        'wp_delete_temp_updater_backups',
        'recovery_mode_clean_expired_keys',
        'delete_expired_transients',
        'do_pings',
        'publish_future_post',
        'importer_scheduled_cleanup',
        'upgrader_scheduled_cleanup',
        'wp_clean_up_personal_data',
        'wp_split_shared_term_batch',
    ];

    /**
     * High-risk PHP execution sinks.
     */
    private const DANGEROUS_SINKS = [
        'system',
        'exec',
        'passthru',
        'shell_exec',
        'popen',
        'proc_open',
        'assert',
        'eval',
        'create_function',
        'file_put_contents',
        'copy',
        'touch',
    ];

    /**
     * Scan cron option and ActionScheduler tables for persistence backdoors.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan(string $scan_id): array {
        $findings = [];

        // 1. Audit wp_options['cron']
        $cron_findings = $this->audit_wp_cron_option($scan_id);
        $findings = array_merge($findings, $cron_findings);

        // 2. Audit ActionScheduler database table if present
        $as_findings = $this->audit_actionscheduler_table($scan_id);
        $findings = array_merge($findings, $as_findings);

        return $findings;
    }

    /**
     * Audit serialized cron option in wp_options.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_wp_cron_option(string $scan_id): array {
        global $wpdb, $wp_filter;
        $findings = [];
        $options_table = $wpdb->prefix . 'options';

        $cron_data = _get_cron_array();
        if (empty($cron_data) || !is_array($cron_data)) {
            $cron_data = get_option('cron');
        }

        if (empty($cron_data) || !is_array($cron_data)) {
            return $findings;
        }

        foreach ($cron_data as $timestamp => $hooks) {
            if (!is_array($hooks)) {
                continue;
            }

            foreach ($hooks as $hook_name => $events) {
                if (!is_string($hook_name) || !is_array($events)) {
                    continue;
                }

                $is_core_hook = in_array($hook_name, self::CORE_CRON_HOOKS, true);

                foreach ($events as $event_sig => $event_data) {
                    $args = $event_data['args'] ?? [];

                    // Check 1: Audit $args payload for weaponized content (URLs to raw IPs/scripts, base64, eval, shell)
                    $args_str = is_array($args) ? serialize($args) : (string) $args;
                    $arg_finding = $this->inspect_args_payload($args_str, $hook_name, $timestamp, $options_table);
                    if ($arg_finding !== null) {
                        $findings[] = $arg_finding;
                        continue;
                    }

                    // If it's a verified standard WordPress core cron hook and args are clean, it is safe
                    if ($is_core_hook) {
                        continue;
                    }

                    // Check 2: Inspect callbacks registered on this hook in $wp_filter
                    $has_filter_callbacks = isset($wp_filter[$hook_name]) && !empty($wp_filter[$hook_name]->callbacks);
                    if ($has_filter_callbacks) {
                        $callback_findings = $this->inspect_filter_callbacks($hook_name, $wp_filter[$hook_name]->callbacks, $options_table);
                        if (!empty($callback_findings)) {
                            $findings = array_merge($findings, $callback_findings);
                            continue;
                        }
                    } else {
                        // Check 3: Orphaned Hook in WP-Admin context:
                        // Only flag if hook mimics core system/auth/update primitives OR matches high-entropy hex
                        $orphan_finding = $this->inspect_orphaned_hook_name($hook_name, $timestamp, $options_table);
                        if ($orphan_finding !== null) {
                            $findings[] = $orphan_finding;
                        }
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Inspect $args payload of a cron event for malware.
     *
     * @param string $args_str
     * @param string $hook_name
     * @param int|string $timestamp
     * @param string $options_table
     * @return Finding|null
     */
    private function inspect_args_payload(string $args_str, string $hook_name, $timestamp, string $options_table): ?Finding {
        if (empty($args_str) || $args_str === 'a:0:{}') {
            return null;
        }

        // Dangerous PHP code or execution primitives in args
        if (preg_match('/(?:<\?(?:php|=)|eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\()/i', $args_str, $m)) {
            return new Finding([
                'engine'      => 'database-persistence',
                'type'        => 'weaponized_cron_args',
                'severity'    => 'critical',
                'confidence'  => 99,
                'file_path'   => "{$options_table}:cron ({$hook_name})",
                'description' => "Weaponized executable PHP code detected inside scheduled cron event arguments for hook '{$hook_name}'. Attackers use cron arguments to pass serialized malware payloads.",
                'evidence'    => "Hook: {$hook_name} | Match: {$m[0]} | Args: " . substr($args_str, 0, 150),
            ]);
        }

        // External URLs targeting raw IPs, .php scripts, or shell scripts in args
        if (preg_match('/https?:\/\/(?:(?:\d{1,3}\.){3}\d{1,3}|[^\s\'"]+\.(?:php|sh|txt|ico|png|py|pl))\b/i', $args_str, $m)) {
            return new Finding([
                'engine'      => 'database-persistence',
                'type'        => 'suspicious_cron_url_args',
                'severity'    => 'critical',
                'confidence'  => 95,
                'file_path'   => "{$options_table}:cron ({$hook_name})",
                'description' => "Scheduled cron event for hook '{$hook_name}' contains suspicious external network download URL in its argument payload.",
                'evidence'    => "Hook: {$hook_name} | Match: {$m[0]} | Args: " . substr($args_str, 0, 150),
            ]);
        }

        // Shell command runners in args
        if (preg_match('/\b(?:powershell|curl\s+-[sS]|wget\s+|bash\s+-i|sh\s+-c|cmd(?:\.exe|\s*\/c)|mshta)\b/i', $args_str, $m)) {
            return new Finding([
                'engine'      => 'database-persistence',
                'type'        => 'shell_command_cron_args',
                'severity'    => 'critical',
                'confidence'  => 98,
                'file_path'   => "{$options_table}:cron ({$hook_name})",
                'description' => "Terminal/shell execution commands detected inside scheduled cron arguments for hook '{$hook_name}'.",
                'evidence'    => "Hook: {$hook_name} | Match: {$m[0]} | Args: " . substr($args_str, 0, 150),
            ]);
        }

        return null;
    }

    /**
     * Inspect active callbacks attached to a hook via safe PHP reflection.
     *
     * @param string $hook_name
     * @param array $callback_groups
     * @param string $options_table
     * @return Finding[]
     */
    private function inspect_filter_callbacks(string $hook_name, array $callback_groups, string $options_table): array {
        $findings = [];

        foreach ($callback_groups as $priority => $callbacks) {
            if (!is_array($callbacks)) {
                continue;
            }

            foreach ($callbacks as $sig => $entry) {
                $function = $entry['function'] ?? null;
                if (!$function) {
                    continue;
                }

                // Check A: Is callback directly pointing to a dangerous PHP sink?
                if (is_string($function) && in_array(strtolower($function), self::DANGEROUS_SINKS, true)) {
                    $findings[] = new Finding([
                        'engine'      => 'database-persistence',
                        'type'        => 'dangerous_cron_callback',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => "{$options_table}:cron ({$hook_name})",
                        'description' => "Scheduled cron hook '{$hook_name}' directly executes dangerous native PHP execution function '{$function}'. This is an active backdoor callback.",
                        'evidence'    => "Hook: {$hook_name} | Callback: {$function} (Priority {$priority})",
                    ]);
                    continue;
                }

                // Check B: Safe Reflection Dispatcher to determine origin file
                $origin_file = $this->resolve_callback_file($function);
                if (!empty($origin_file)) {
                    $norm_origin = str_replace('\\', '/', $origin_file);

                    // Flag if callback origin is eval()'d code or runtime-created function
                    if (stripos($norm_origin, "eval()'d code") !== false || stripos($norm_origin, 'runtime-created function') !== false) {
                        $findings[] = new Finding([
                            'engine'      => 'database-persistence',
                            'type'        => 'eval_closure_cron_callback',
                            'severity'    => 'critical',
                            'confidence'  => 99,
                            'file_path'   => "{$options_table}:cron ({$hook_name})",
                            'description' => "Scheduled cron hook '{$hook_name}' executes a dynamic closure created inside eval()'d code. Standard plugins never schedule eval-based closures.",
                            'evidence'    => "Hook: {$hook_name} | Origin: {$norm_origin}",
                        ]);
                        continue;
                    }

                    // Flag if callback origin resides inside /wp-content/uploads/ or /tmp/
                    if (preg_match('#/(?:wp-content/uploads|tmp|temp)/#i', $norm_origin)) {
                        $findings[] = new Finding([
                            'engine'      => 'database-persistence',
                            'type'        => 'untrusted_origin_cron_callback',
                            'severity'    => 'critical',
                            'confidence'  => 98,
                            'file_path'   => "{$options_table}:cron ({$hook_name})",
                            'description' => "Scheduled cron hook '{$hook_name}' executes a callback originating from an untrusted media or temporary directory ({$norm_origin}).",
                            'evidence'    => "Hook: {$hook_name} | Origin: {$norm_origin}",
                        ]);
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Safely resolve the origin file of any PHP callable without throwing exceptions.
     *
     * @param mixed $callback
     * @return string|null
     */
    private function resolve_callback_file($callback): ?string {
        try {
            // Case 1: Array callable [$object, 'method'] or ['Class', 'method']
            if (is_array($callback) && isset($callback[0], $callback[1])) {
                $ref = new ReflectionMethod($callback[0], $callback[1]);
                return $ref->getFileName() ?: null;
            }

            // Case 2: Invokable object (excluding Closure)
            if (is_object($callback) && !($callback instanceof Closure)) {
                if (method_exists($callback, '__invoke')) {
                    $ref = new ReflectionMethod($callback, '__invoke');
                    return $ref->getFileName() ?: null;
                }
                return null;
            }

            // Case 3: Closure or String function name
            if ($callback instanceof Closure || (is_string($callback) && function_exists($callback))) {
                $ref = new ReflectionFunction($callback);
                return $ref->getFileName() ?: null;
            }
        } catch (\Throwable $e) {
            // Reflection fails gracefully on native PHP internal C functions (e.g. phpinfo)
        }

        return null;
    }

    /**
     * Inspect orphaned hook name using strict Core-Spoofing and High-Entropy regexes.
     *
     * @param string $hook_name
     * @param int|string $timestamp
     * @param string $options_table
     * @return Finding|null
     */
    private function inspect_orphaned_hook_name(string $hook_name, $timestamp, string $options_table): ?Finding {
        // Condition A: Fake Core System/Auth Spoofing
        // Catches fake backdoors like wp_version_check_update, wp_core_sync, wp_salt_cron, wp_auth_check, wp_init_hook
        $is_core_spoof = (bool) preg_match('/^wp_(?:core|version|update|auth|login|admin|salt|security|init|cron|system|check|verify|backup)_/i', $hook_name)
                         && !in_array($hook_name, self::CORE_CRON_HOOKS, true)
                         && !preg_match('/^wp_(?:rocket|mail_smtp|all_import|all_export|fastest_cache|super_cache|optimize|smush|stateless|offload|crontrol|sweep|seopress)_/i', $hook_name);

        if ($is_core_spoof) {
            return new Finding([
                'engine'      => 'database-persistence',
                'type'        => 'core_spoofing_cron_hook',
                'severity'    => 'high',
                'confidence'  => 88,
                'file_path'   => "{$options_table}:cron ({$hook_name})",
                'description' => "Scheduled cron hook '{$hook_name}' spoofs WordPress core naming conventions but has no active registered callback and is not an authentic core hook.",
                'evidence'    => "Hook: {$hook_name} | Scheduled Timestamp: {$timestamp}",
            ]);
        }

        // Condition B: High-entropy random hex or base64-like hook name (e.g. cron_8f9a2b1c, a1b2c3d4e5f6, wp_7f8e9a)
        $is_random_hex = (bool) preg_match('/^(?:wp_|cron_)?[a-f0-9]{8,32}$/i', $hook_name);
        if ($is_random_hex) {
            return new Finding([
                'engine'      => 'database-persistence',
                'type'        => 'high_entropy_cron_hook',
                'severity'    => 'high',
                'confidence'  => 85,
                'file_path'   => "{$options_table}:cron ({$hook_name})",
                'description' => "Scheduled cron hook '{$hook_name}' contains a high-entropy random hex name without an active handler. Malware frequently uses randomized hook identifiers.",
                'evidence'    => "Hook: {$hook_name} | Scheduled Timestamp: {$timestamp}",
            ]);
        }

        return null;
    }

    /**
     * Audit WooCommerce ActionScheduler database table for malicious pending actions.
     * Uses non-locking primary-key cursor pagination (WHERE action_id > %d ORDER BY action_id ASC LIMIT 250)
     * to eliminate InnoDB row-lock contention and checkout slowdowns on high-volume stores.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    private function audit_actionscheduler_table(string $scan_id): array {
        global $wpdb;
        $findings = [];
        $as_table = $wpdb->prefix . 'actionscheduler_actions';

        try {
            // Check if table exists (<1ms)
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $as_table));
            if ($table_exists !== $as_table) {
                return $findings;
            }

            $last_id = 0;
            $batch_size = 250;
            $max_batches = 10;
            $batches = 0;

            while ($batches < $max_batches) {
                $batches++;

                // Keyset pagination avoids table locks and OFFSET slowdowns on large WooCommerce stores
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $pending_actions = $wpdb->get_results(
                    $wpdb->prepare(
                        "SELECT action_id, hook, status, args, extended_args FROM `{$as_table}` WHERE action_id > %d AND status IN ('pending', 'in-progress') ORDER BY action_id ASC LIMIT %d",
                        $last_id,
                        $batch_size
                    ),
                    OBJECT
                );

                if (empty($pending_actions) || !is_array($pending_actions)) {
                    break;
                }

                foreach ($pending_actions as $action) {
                    $action_id = (int) ($action->action_id ?? 0);
                    $last_id = $action_id;
                    $hook = (string) ($action->hook ?? '');
                    $args = (string) (!empty($action->extended_args) ? $action->extended_args : ($action->args ?? ''));

                    // Dangerous function in hook column
                    if (in_array(strtolower($hook), self::DANGEROUS_SINKS, true)) {
                        $findings[] = new Finding([
                            'engine'      => 'database-persistence',
                            'type'        => 'dangerous_actionscheduler_hook',
                            'severity'    => 'critical',
                            'confidence'  => 100,
                            'file_path'   => "{$as_table}:action #{$action_id}",
                            'description' => "ActionScheduler persistence trojan: Pending action directly targets dangerous PHP sink '{$hook}'.",
                            'evidence'    => "Action #{$action_id} | Hook: {$hook} | Args: " . substr($args, 0, 100),
                        ]);
                        continue;
                    }

                    // Check for disguised executable payloads, dynamic callables, or shell commands in args
                    if (preg_match('/\b(eval|assert|create_function|call_user_func(?:_array)?|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|base64_decode|gzinflate)\b/i', $args, $m)) {
                        $findings[] = new Finding([
                            'engine'      => 'database-persistence',
                            'type'        => 'weaponized_actionscheduler_args',
                            'severity'    => 'critical',
                            'confidence'  => 98,
                            'file_path'   => "{$as_table}:action #{$action_id}",
                            'description' => "ActionScheduler persistence trojan: Pending action contains weaponized executable callable payload in its arguments.",
                            'evidence'    => "Action #{$action_id} | Hook: {$hook} | Match: {$m[0]} | Args: " . substr($args, 0, 100),
                        ]);
                        continue;
                    }

                    // Class-aware Serialized Object Validation: permit benign WooCommerce value objects, flag POP gadgets
                    if (preg_match('/(?:O|C):[+-]?\d+:"([^"]+)"/i', $args, $class_match)) {
                        $class_name = $class_match[1];
                        if (class_exists('\\WcpScanner\\Database\\SerializedDataScanner') && !SerializedDataScanner::is_allowed_commerce_class($class_name)) {
                            $findings[] = new Finding([
                                'engine'      => 'database-persistence',
                                'type'        => 'actionscheduler_unauthorized_serialized_class',
                                'severity'    => 'high',
                                'confidence'  => 92,
                                'file_path'   => "{$as_table}:action #{$action_id}",
                                'description' => sprintf("ActionScheduler persistence risk: Unauthorized serialized PHP class '%s' found inside scheduled arguments.", esc_html($class_name)),
                                'evidence'    => "Action #{$action_id} | Hook: {$hook} | Class: {$class_name}",
                            ]);
                        }
                    }
                }

                if (count($pending_actions) < $batch_size) {
                    break;
                }
            }
        } catch (\Throwable $e) {
            // Fails gracefully on schema variations
        }

        return $findings;
    }
}
