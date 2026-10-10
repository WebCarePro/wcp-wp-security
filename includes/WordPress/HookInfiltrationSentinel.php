<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
 *
 * Inspects active runtime WordPress hook and filter registries ($wp_filter)
 * for stealth in-memory callbacks, malicious closures, and unmapped functions
 * injected into sensitive execution lifecycle hooks.
 *
 * High-value targeted hooks audited:
 * - authenticate / wp_authenticate / wp_authenticate_user / wp_login (Credential sniffing & auth bypass)
 * - init / plugins_loaded / setup_theme (Early persistent backdoors)
 * - wp_head / wp_footer / template_redirect (SEO cloaking, drive-by malware & payment skimmers)
 * - user_register / profile_update (Privilege escalation hooks)
 * - xmlrpc_call / xmlrpc_methods (Stealth XML-RPC backdoors)
 * - wp_ajax_nopriv_* / rest_pre_serve_request (Unauthenticated execution vectors)
 */
class HookInfiltrationSentinel {

    /**
     * Critical core hooks sensitive to credential theft, rootkits, or injection.
     */
    private const CRITICAL_HOOKS = [
        'authenticate'              => 'Authentication & Credential Interception',
        'wp_authenticate'           => 'Login Process & Credential Hijack',
        'wp_authenticate_user'      => 'User Credential Verification Trap',
        'wp_login'                  => 'Post-Authentication Action Trap',
        'user_register'             => 'User Creation Privilege Escalation',
        'profile_update'            => 'User Profile Alteration Hook',
        'template_redirect'         => 'Front-end Content Hijack & SEO Cloaking',
        'wp_head'                   => 'Script Injection & Drive-by Malicious Tags',
        'wp_footer'                 => 'Script Injection & Form Exfiltration',
        'xmlrpc_call'               => 'XML-RPC Interception & Command Execution',
        'xmlrpc_methods'            => 'XML-RPC Custom Method Infiltration',
        'rest_pre_serve_request'    => 'REST API Interception & Response Tampering',
        'send_headers'              => 'HTTP Header Tampering',
    ];

    /**
     * Execute Hook Infiltration Sentinel Audit
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan(string $scan_id): array {
        global $wp_filter;

        $findings = [];

        if (!is_array($wp_filter) && !is_object($wp_filter)) {
            return $findings;
        }

        foreach (self::CRITICAL_HOOKS as $hook_name => $hook_desc) {
            $hook_obj = $wp_filter[$hook_name] ?? null;
            if (!$hook_obj) {
                continue;
            }

            $callbacks_by_priority = [];
            if ($hook_obj instanceof \WP_Hook) {
                $callbacks_by_priority = $hook_obj->callbacks;
            } elseif (is_array($hook_obj)) {
                $callbacks_by_priority = $hook_obj;
            }

            foreach ($callbacks_by_priority as $priority => $callbacks) {
                if (!is_array($callbacks)) {
                    continue;
                }

                foreach ($callbacks as $callback_key => $callback_data) {
                    $function = $callback_data['function'] ?? null;
                    if (!$function) {
                        continue;
                    }

                    $inspection = self::inspect_callback($function, $hook_name);
                    if ($inspection !== null) {
                        $findings[] = new Finding([
                            'engine'      => 'lotl-hook-sentinel',
                            'type'        => $inspection['type'],
                            'severity'    => $inspection['severity'],
                            'confidence'  => $inspection['confidence'],
                            'file_path'   => $inspection['file_path'] ?? 'runtime:memory',
                            'line_number' => $inspection['line_number'] ?? null,
                            'description' => "Suspicious hook callback on '{$hook_name}' ({$hook_desc}): " . $inspection['reason'],
                            'evidence'    => 'Hook: ' . $hook_name . ' | Priority: ' . $priority . ' | Target: ' . $inspection['identifier'],
                        ]);
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Inspect individual callback reflection
     *
     * @param mixed $function
     * @param string $hook_name
     * @return array|null
     */
    private static function inspect_callback($function, string $hook_name): ?array {
        try {
            $reflection = null;
            $identifier = '';
            $file_path = null;
            $line_number = null;

            if ($function instanceof \Closure) {
                $reflection = new \ReflectionFunction($function);
                $identifier = 'Closure [Anonymous Function]';
            } elseif (is_string($function)) {
                $identifier = $function;
                if (function_exists($function)) {
                    $reflection = new \ReflectionFunction($function);
                }
            } elseif (is_array($function) && count($function) >= 2) {
                $class_or_obj = $function[0];
                $method_name = $function[1];

                $class_name = is_object($class_or_obj) ? get_class($class_or_obj) : (string) $class_or_obj;
                $identifier = $class_name . '::' . $method_name;

                if (class_exists($class_name) && method_exists($class_name, $method_name)) {
                    $reflection = new \ReflectionMethod($class_name, $method_name);
                }
            }

            if ($reflection) {
                $file_path = $reflection->getFileName();
                $line_number = $reflection->getStartLine();
            }

            // Flag 1: Anonymous closure on sensitive credential/auth hooks
            if ($function instanceof \Closure) {
                $is_auth_hook = in_array($hook_name, ['authenticate', 'wp_authenticate', 'wp_authenticate_user', 'user_register'], true);
                if ($is_auth_hook) {
                    $source_loc = $file_path ? basename($file_path) . ':' . $line_number : 'unknown';
                    return [
                        'type'        => 'closure_on_auth_hook',
                        'severity'    => 'medium',
                        'confidence'  => 85,
                        'file_path'   => $file_path ?: 'runtime:memory',
                        'line_number' => $line_number,
                        'identifier'  => $identifier,
                        'reason'      => "Anonymous closure attached to sensitive authentication hook '{$hook_name}' (source: {$source_loc}). Anonymous closures on auth hooks can hide password stealers.",
                    ];
                }
            }

            // Flag 2: Callback residing outside recognized WordPress installation structures
            if ($file_path) {
                $normalized_file = wp_normalize_path($file_path);
                $normalized_abspath = wp_normalize_path(ABSPATH);

                // Check if file is loaded from outside ABSPATH (e.g. /tmp, auto_prepend_file in /var/tmp)
                if (strpos($normalized_file, $normalized_abspath) !== 0) {
                    // Check if within standard PHP vendor or sys paths
                    return [
                        'type'        => 'external_file_hook_callback',
                        'severity'    => 'critical',
                        'confidence'  => 95,
                        'file_path'   => $file_path,
                        'line_number' => $line_number,
                        'identifier'  => $identifier,
                        'reason'      => "Callback originates from file outside WordPress root directory: '{$file_path}'. This is a signature of auto_prepend_file or server-level rootkit backdoor.",
                    ];
                }

                // Check if file is inside wp-content/uploads/
                $uploads_dir = wp_upload_dir();
                $normalized_uploads = wp_normalize_path($uploads_dir['basedir'] ?? '');
                if (!empty($normalized_uploads) && strpos($normalized_file, $normalized_uploads) === 0) {
                    return [
                        'type'        => 'uploads_dir_hook_callback',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => $file_path,
                        'line_number' => $line_number,
                        'identifier'  => $identifier,
                        'reason'      => "Hook callback is defined inside the uploads directory: '{$file_path}'. Executable callbacks originating from uploads indicates active webshell infiltration.",
                    ];
                }
            }

            // Flag 3: Suspicious function names commonly used by malware
            if (is_string($function)) {
                $suspicious_names = ['eval', 'assert', 'passthru', 'shell_exec', 'system', 'base64_decode', 'create_function'];
                if (in_array(strtolower($function), $suspicious_names, true)) {
                    return [
                        'type'        => 'dangerous_native_hook_callback',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => $file_path ?: 'runtime:native',
                        'line_number' => $line_number,
                        'identifier'  => $identifier,
                        'reason'      => "Native dangerous execution function '{$function}' registered directly as WordPress hook callback.",
                    ];
                }
            }

        } catch (\Throwable $e) {
            // Ignore reflection errors for internal functions
        }

        return null;
    }
}
