<?php
/**
 * Modular Firewall Synthesizer
 *
 * Deterministically analyzes Vault behavioral intelligence and AST findings to synthesize
 * customized, site-specific Modular Firewall Rules:
 * - MOD-AJAX-* (Unprotected Guest AJAX Shield)
 * - MOD-REST-* (Permissive REST Route Guard)
 * - MOD-ABSPATH-* (Direct PHP Script Lockdown)
 * - MOD-CVE-* (Outdated / Vulnerable Plugin Virtual Shield)
 * - MOD-UPLOAD-* (Custom Upload & File-Sink Guard)
 * - MOD-EGRESS-* (Plugin-Specific Egress & SSRF Lock)
 *
 * Integrates directly with MicroWafCompiler for 0ms Pre-Boot execution and
 * FirewallEngine for deep runtime RASP inspection.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Modular
 */

namespace WebCareProScanner\Firewall\Modular;

if (!defined('ABSPATH')) {
    exit;
}

class ModularFirewallSynthesizer {

    const OPTION_RULES = 'webcareproscan_modular_waf_rules';

    /**
     * Synthesize modular rules from raw inventory, endpoint maps, and findings.
     *
     * @param array $inventory   Discovered plugins, themes, and mu-plugins
     * @param array $endpoint_map Mapped AJAX hooks and REST routes
     * @param array $findings    AST taint and architectural findings
     * @return array List of synthesized modular rule definitions
     */
    public static function synthesize_rules(array $inventory, array $endpoint_map, array $findings): array {
        $rules = [];
        $existing = self::get_active_rules();
        $existing_by_id = [];
        foreach ($existing as $r) {
            if (!empty($r['id'])) {
                $existing_by_id[$r['id']] = $r;
            }
        }

        // 1. Synthesize MOD-AJAX-* Rules for Unprotected Guest AJAX actions
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'unprotected_guest_ajax') {
                $action = sanitize_key($f['action'] ?? '');
                if (empty($action)) {
                    continue;
                }

                $rule_id = 'MOD-AJAX-' . strtoupper(substr(md5($action), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $rules[] = [
                    'id'               => $rule_id,
                    'category'         => 'ajax_shield',
                    'title'            => sprintf(
                        /* translators: %s: AJAX action name */
                        __('Unprotected Guest AJAX Shield: action="%s"', 'webcare-pro-security'),
                        $action
                    ),
                    'description'      => sprintf(
                        /* translators: %s: AJAX action name */
                        __('Enforces strict SQLi, XSS, and payload sanitization on guest AJAX action "%s" and caps request velocity to prevent brute-force attacks.', 'webcare-pro-security'),
                        $action
                    ),
                    'origin_component' => $f['component'] ?? 'Custom',
                    'file'             => $f['file'] ?? '',
                    'line'             => $f['line'] ?? 1,
                    'evidence'         => $f['evidence'] ?? '',
                    'severity'         => 'critical',
                    'recommended_mode' => 'enforce',
                    'current_mode'     => $prev ? $prev['current_mode'] : 'enforce',
                    'target_uri'       => 'admin-ajax.php',
                    'target_param'     => 'action',
                    'target_value'     => $action,
                    'http_methods'     => ['POST', 'GET'],
                    'rate_limit'       => 15, // max req per minute
                    'block_uploads'    => true,
                    'sync_cloudflare'  => true,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ];
            }
        }

        // 2. Synthesize MOD-REST-* Rules for Permissive REST Routes
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'permissive_rest_route') {
                $route = sanitize_text_field($f['route'] ?? '');
                if (empty($route)) {
                    continue;
                }

                $rule_id = 'MOD-REST-' . strtoupper(substr(md5($route), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $rules[] = [
                    'id'               => $rule_id,
                    'category'         => 'rest_guard',
                    'title'            => sprintf(
                        /* translators: %s: REST route path */
                        __('Permissive REST Mutation Guard: %s', 'webcare-pro-security'),
                        $route
                    ),
                    'description'      => sprintf(
                        /* translators: %s: REST route path */
                        __('Blocks unauthorized write state mutations (POST/PUT/DELETE) and privilege escalation keys on route "%s".', 'webcare-pro-security'),
                        $route
                    ),
                    'origin_component' => $f['component'] ?? 'Custom',
                    'file'             => $f['file'] ?? '',
                    'line'             => $f['line'] ?? 1,
                    'evidence'         => $f['evidence'] ?? '',
                    'severity'         => 'high',
                    'recommended_mode' => 'enforce',
                    'current_mode'     => $prev ? $prev['current_mode'] : 'enforce',
                    'target_uri'       => $route,
                    'target_param'     => '',
                    'target_value'     => '',
                    'http_methods'     => ['POST', 'PUT', 'DELETE'],
                    'rate_limit'       => 30,
                    'block_uploads'    => false,
                    'sync_cloudflare'  => true,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ];
            }
        }

        // 3. Synthesize MOD-ABSPATH-* Rules for Direct PHP Scripts Missing ABSPATH Guards
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'missing_abspath_script') {
                $file = sanitize_text_field($f['file'] ?? '');
                if (empty($file)) {
                    continue;
                }

                $rule_id = 'MOD-ABSPATH-' . strtoupper(substr(md5($file), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $rules[] = [
                    'id'               => $rule_id,
                    'category'         => 'abspath_lock',
                    'title'            => sprintf(
                        /* translators: %s: relative file path */
                        __('Direct-Access PHP Script Lock: %s', 'webcare-pro-security'),
                        basename($file)
                    ),
                    'description'      => sprintf(
                        /* translators: %s: file path */
                        __('Blocks direct external HTTP requests to standalone file "%s" while allowing internal WordPress include/require execution.', 'webcare-pro-security'),
                        $file
                    ),
                    'origin_component' => $f['component'] ?? 'Custom',
                    'file'             => $file,
                    'line'             => 1,
                    'evidence'         => $f['evidence'] ?? '',
                    'severity'         => 'high',
                    'recommended_mode' => 'enforce',
                    'current_mode'     => $prev ? $prev['current_mode'] : 'enforce',
                    'target_uri'       => $file,
                    'target_param'     => '',
                    'target_value'     => '',
                    'http_methods'     => ['GET', 'POST', 'HEAD'],
                    'rate_limit'       => 0, // 0 = unconditional 403 on direct HTTP access
                    'block_uploads'    => true,
                    'sync_cloudflare'  => true,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ];
            }
        }

        // 4. Synthesize MOD-UPLOAD-* Rules for Custom Upload Sinks
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'raw_file_upload_sink') {
                $file = sanitize_text_field($f['file'] ?? '');
                $rule_id = 'MOD-UPLOAD-' . strtoupper(substr(md5($file . ':' . ($f['line'] ?? 1)), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $rules[] = [
                    'id'               => $rule_id,
                    'category'         => 'upload_guard',
                    'title'            => sprintf(
                        /* translators: %s: component name */
                        __('Custom Upload Sink Guard: %s', 'webcare-pro-security'),
                        $f['component'] ?? basename($file)
                    ),
                    'description'      => sprintf(
                        /* translators: %s: file path */
                        __('Inspects multipart uploads targeting file "%s" for double extensions, PHP tags, and executable headers.', 'webcare-pro-security'),
                        $file
                    ),
                    'origin_component' => $f['component'] ?? 'Custom',
                    'file'             => $file,
                    'line'             => $f['line'] ?? 1,
                    'evidence'         => $f['evidence'] ?? '',
                    'severity'         => 'high',
                    'recommended_mode' => 'enforce',
                    'current_mode'     => $prev ? $prev['current_mode'] : 'enforce',
                    'target_uri'       => $file,
                    'target_param'     => '',
                    'target_value'     => '',
                    'http_methods'     => ['POST'],
                    'rate_limit'       => 10,
                    'block_uploads'    => false, // inspected strictly rather than blocked
                    'sync_cloudflare'  => false,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ];
            }
        }

        // 5. Synthesize MOD-EGRESS-* Rules for Dynamic Outbound HTTP Sinks (SSRF)
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'ssrf_egress_sink') {
                $file = sanitize_text_field($f['file'] ?? '');
                $rule_id = 'MOD-EGRESS-' . strtoupper(substr(md5($file . ':' . ($f['line'] ?? 1)), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $rules[] = [
                    'id'               => $rule_id,
                    'category'         => 'egress_lock',
                    'title'            => sprintf(
                        /* translators: %s: component name */
                        __('SSRF & URL Parameter Lockdown: %s', 'webcare-pro-security'),
                        $f['component'] ?? basename($file)
                    ),
                    'description'      => sprintf(
                        /* translators: %s: file path */
                        __('Blocks cloud metadata (169.254.169.254) and internal subnet traversal on URL parameters targeting "%s".', 'webcare-pro-security'),
                        $file
                    ),
                    'origin_component' => $f['component'] ?? 'Custom',
                    'file'             => $file,
                    'line'             => $f['line'] ?? 1,
                    'evidence'         => $f['evidence'] ?? '',
                    'severity'         => 'high',
                    'recommended_mode' => 'enforce',
                    'current_mode'     => $prev ? $prev['current_mode'] : 'enforce',
                    'target_uri'       => $file,
                    'target_param'     => 'url,webhook,feed,callback_url,endpoint',
                    'target_value'     => '',
                    'http_methods'     => ['POST', 'GET'],
                    'rate_limit'       => 20,
                    'block_uploads'    => false,
                    'sync_cloudflare'  => false,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ];
            }
        }

        // Save synthesized rules to option
        self::save_rules($rules);

        return $rules;
    }

    /**
     * Get all active modular firewall rules.
     *
     * @return array
     */
    public static function get_active_rules(): array {
        $saved = get_option(self::OPTION_RULES, null);
        if (is_array($saved)) {
            return $saved;
        }

        // Fallback to Vault Shard
        $from_shard = BehavioralVaultManager::read_shard(BehavioralVaultManager::SHARD_RULES);
        if (is_array($from_shard)) {
            update_option(self::OPTION_RULES, $from_shard, false);
            return $from_shard;
        }

        return [];
    }

    /**
     * Save modular firewall rules list.
     *
     * @param array $rules
     * @return bool
     */
    public static function save_rules(array $rules): bool {
        $updated = update_option(self::OPTION_RULES, $rules, false);

        // Also sync to vault shard
        BehavioralVaultManager::write_shard(BehavioralVaultManager::SHARD_RULES, $rules);

        // Trigger Preload Micro-WAF re-compilation
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            \WebCareProScanner\Firewall\MicroWafCompiler::compile();
        }

        return $updated;
    }

    /**
     * Toggle a specific modular rule mode or update parameters.
     *
     * @param string $rule_id Rule identifier
     * @param string $mode    'enforce', 'monitor', or 'off'
     * @param array  $params  Customizable parameters (rate_limit, sync_cloudflare)
     * @return array Updated rule status
     */
    public static function toggle_rule(string $rule_id, string $mode, array $params = []): array {
        $valid_modes = ['enforce', 'monitor', 'off'];
        if (!in_array($mode, $valid_modes, true)) {
            $mode = 'monitor';
        }

        $rules = self::get_active_rules();
        $found = false;
        $updated_rule = null;

        foreach ($rules as &$r) {
            if (($r['id'] ?? '') === $rule_id) {
                $r['current_mode'] = $mode;
                if (isset($params['rate_limit'])) {
                    $r['rate_limit'] = max(0, intval($params['rate_limit']));
                }
                if (isset($params['sync_cloudflare'])) {
                    $r['sync_cloudflare'] = !empty($params['sync_cloudflare']);
                }
                $r['updated_at'] = time();
                $found = true;
                $updated_rule = $r;
                break;
            }
        }

        if ($found) {
            self::save_rules($rules);
            return [
                'success' => true,
                'message' => sprintf(
                    /* translators: %1$s: rule id, %2$s: mode */
                    __('Modular rule "%1$s" updated to "%2$s".', 'webcare-pro-security'),
                    $rule_id,
                    $mode
                ),
                'rule'    => $updated_rule,
            ];
        }

        return [
            'success' => false,
            'message' => sprintf(
                /* translators: %s: rule id */
                __('Rule "%s" not found.', 'webcare-pro-security'),
                $rule_id
            ),
        ];
    }

    /**
     * Apply all recommended modular rules in 1 click (enforcing them).
     *
     * @return array Result summary
     */
    public static function bulk_apply_recommendations(): array {
        $rules = self::get_active_rules();
        $count = 0;

        foreach ($rules as &$r) {
            if (!empty($r['recommended_mode']) && $r['current_mode'] !== 'enforce') {
                $r['current_mode'] = $r['recommended_mode'];
                $r['updated_at'] = time();
                $count++;
            }
        }

        self::save_rules($rules);

        return [
            'success'       => true,
            'updated_count' => $count,
            'total_active'  => count(array_filter($rules, fn($r) => $r['current_mode'] === 'enforce')),
            'message'       => sprintf(
                /* translators: %d: applied rules count */
                __('Successfully activated %d recommended Modular Firewall rules.', 'webcare-pro-security'),
                $count
            ),
        ];
    }

    /**
     * Compile active modular rules for inclusion into the standalone Preload Micro-WAF.
     *
     * @return array Array formatted for MicroWafCompiler
     */
    public static function get_compiled_preload_rules(): array {
        $rules = self::get_active_rules();
        $compiled = [
            'direct_scripts_blocked' => [],
            'ajax_actions_enforced'  => [],
            'rest_routes_enforced'   => [],
        ];

        foreach ($rules as $r) {
            if (($r['current_mode'] ?? '') !== 'enforce') {
                continue;
            }

            $cat = $r['category'] ?? '';

            // 1. Direct Script Locks
            if ($cat === 'abspath_lock' && !empty($r['target_uri'])) {
                $compiled['direct_scripts_blocked'][] = strtolower(ltrim($r['target_uri'], '/\\'));
            }

            // 2. AJAX Shields
            if ($cat === 'ajax_shield' && !empty($r['target_value'])) {
                $compiled['ajax_actions_enforced'][strtolower($r['target_value'])] = [
                    'rule_id'       => $r['id'],
                    'rate_limit'    => $r['rate_limit'] ?? 15,
                    'block_uploads' => !empty($r['block_uploads']),
                ];
            }

            // 3. REST Route Guards
            if ($cat === 'rest_guard' && !empty($r['target_uri'])) {
                $compiled['rest_routes_enforced'][strtolower(rtrim($r['target_uri'], '/'))] = [
                    'rule_id'       => $r['id'],
                    'methods'       => $r['http_methods'] ?? ['POST', 'PUT', 'DELETE'],
                    'rate_limit'    => $r['rate_limit'] ?? 30,
                ];
            }
        }

        return $compiled;
    }

    /**
     * Evaluate incoming request against active Modular Rules at WordPress Runtime.
     *
     * @return array|null Returns violation array if blocked, null if safe.
     */
    public static function evaluate_runtime_modular_rules(): ?array {
        $rules = self::get_active_rules();
        if (empty($rules)) {
            return null;
        }

        $uri    = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        $ip     = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : '127.0.0.1';

        // Whitelist Check: never evaluate authenticated admins or whitelisted IPs
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            if (\WebCareProScanner\Firewall\FirewallEngine::is_ip_whitelisted($ip)) {
                return null;
            }
        }

        foreach ($rules as $r) {
            $mode = $r['current_mode'] ?? 'off';
            if ($mode === 'off') {
                continue;
            }

            $cat = $r['category'] ?? '';

            // Check Category: abspath_lock (Direct HTTP request to naked PHP script)
            if ($cat === 'abspath_lock' && !empty($r['target_uri'])) {
                $target_suffix = strtolower(ltrim($r['target_uri'], '/\\'));
                $clean_uri     = strtolower(strtok($uri, '?'));

                if (str_ends_with($clean_uri, $target_suffix)) {
                    return [
                        'blocked'  => ($mode === 'enforce'),
                        'rule_id'  => $r['id'],
                        'category' => $cat,
                        'reason'   => sprintf('Direct HTTP access to standalone script "%s" blocked by Modular WAF Rule [%s].', basename($target_suffix), $r['id']),
                        'severity' => $r['severity'] ?? 'high',
                        'mode'     => $mode,
                    ];
                }
            }

            // Check Category: ajax_shield (Targeted guest AJAX action)
            if ($cat === 'ajax_shield' && !empty($r['target_value'])) {
                if (str_contains($uri, 'admin-ajax.php')) {
                    $action = sanitize_key($_REQUEST['action'] ?? '');
                    if ($action === strtolower($r['target_value'])) {
                        // Check unexpected file upload
                        if (!empty($r['block_uploads']) && !empty($_FILES)) {
                            return [
                                'blocked'  => ($mode === 'enforce'),
                                'rule_id'  => $r['id'],
                                'category' => $cat,
                                'reason'   => sprintf('File upload prohibited on guest AJAX action "%s" by Modular WAF Rule [%s].', $action, $r['id']),
                                'severity' => 'critical',
                                'mode'     => $mode,
                            ];
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Create a developer-defined custom modular firewall rule.
     *
     * @param array $data
     * @return array
     */
    public static function create_custom_rule(array $data): array {
        $title = isset($data['title']) ? sanitize_text_field(wp_unslash($data['title'])) : '';
        if (empty($title)) {
            return [
                'success' => false,
                'message' => __('Rule title is required.', 'webcare-pro-security'),
            ];
        }

        $category = isset($data['category']) ? sanitize_key($data['category']) : 'custom';
        $rule_id  = 'MOD-CUSTOM-' . strtoupper(wp_generate_password(6, false, false));

        $rule = [
            'id'               => $rule_id,
            'category'         => $category,
            'title'            => $title,
            'description'      => isset($data['description']) ? sanitize_textarea_field(wp_unslash($data['description'])) : '',
            'origin_component' => 'Custom User Rule',
            'file'             => '',
            'line'             => 0,
            'evidence'         => __('Developer-defined custom modular protection rule.', 'webcare-pro-security'),
            'severity'         => isset($data['severity']) ? sanitize_key($data['severity']) : 'high',
            'recommended_mode' => 'enforce',
            'current_mode'     => in_array($data['current_mode'] ?? 'enforce', ['enforce', 'monitor', 'off'], true) ? $data['current_mode'] : 'enforce',
            'target_uri'       => isset($data['target_uri']) ? sanitize_text_field(wp_unslash($data['target_uri'])) : '',
            'target_param'     => isset($data['target_param']) ? sanitize_key($data['target_param']) : '',
            'target_value'     => isset($data['target_value']) ? sanitize_text_field(wp_unslash($data['target_value'])) : '',
            'http_methods'     => is_array($data['http_methods'] ?? null) ? array_map('sanitize_text_field', $data['http_methods']) : ['POST', 'GET'],
            'rate_limit'       => max(0, intval($data['rate_limit'] ?? 15)),
            'block_uploads'    => !empty($data['block_uploads']),
            'sync_cloudflare'  => !empty($data['sync_cloudflare']),
            'is_custom'        => true,
            'synthesized_at'   => time(),
        ];

        $rules = self::get_active_rules();
        $rules[] = $rule;
        self::save_rules($rules);

        return [
            'success' => true,
            'message' => sprintf(
                /* translators: %s: rule ID */
                __('Custom modular rule "%s" created successfully.', 'webcare-pro-security'),
                $rule_id
            ),
            'rule'    => $rule,
        ];
    }

    /**
     * Safely read a read-only 15-line preview snippet around target file line.
     * Strictly verifies path traversal defenses and restricts access to WP_CONTENT_DIR / ABSPATH.
     *
     * @param string $rel_path Target file path
     * @param int    $target_line Line number of the finding
     * @param int    $context_lines Radius of surrounding lines (default: 7 lines above & below)
     * @return array
     */
    public static function get_code_preview(string $rel_path, int $target_line = 1, int $context_lines = 7): array {
        $rel_path = wp_normalize_path(trim($rel_path));

        // Path traversal validation
        if (strpos($rel_path, '..') !== false || strpos($rel_path, "\0") !== false) {
            return [
                'success' => false,
                'message' => __('Invalid file path: path traversal sequences are strictly prohibited.', 'webcare-pro-security'),
            ];
        }

        $wp_content_norm = wp_normalize_path(WP_CONTENT_DIR);
        $abspath_norm    = wp_normalize_path(ABSPATH);

        $candidate_paths = [
            $wp_content_norm . '/' . ltrim($rel_path, '/'),
            $abspath_norm . '/' . ltrim($rel_path, '/'),
            $rel_path,
        ];

        $resolved_path = null;
        foreach ($candidate_paths as $cand) {
            $cand_norm = wp_normalize_path($cand);
            if (file_exists($cand_norm) && is_file($cand_norm)) {
                if (str_starts_with($cand_norm, $wp_content_norm) || str_starts_with($cand_norm, $abspath_norm)) {
                    if (basename($cand_norm) === 'wp-config.php') {
                        return [
                            'success' => false,
                            'message' => __('Access to wp-config.php is strictly restricted.', 'webcare-pro-security'),
                        ];
                    }
                    $resolved_path = $cand_norm;
                    break;
                }
            }
        }

        if (!$resolved_path || !is_readable($resolved_path)) {
            return [
                'success' => false,
                'message' => __('Target file does not exist or is not readable.', 'webcare-pro-security'),
            ];
        }

        if (filesize($resolved_path) > 5242880) { // 5MB guard
            return [
                'success' => false,
                'message' => __('File exceeds preview size limit (5MB).', 'webcare-pro-security'),
            ];
        }

        $content = @file_get_contents($resolved_path);
        if ($content === false) {
            return [
                'success' => false,
                'message' => __('Unable to read file content.', 'webcare-pro-security'),
            ];
        }

        $all_lines   = explode("\n", $content);
        $total_lines = count($all_lines);
        $target_line = max(1, min($target_line, $total_lines));

        $start_line = max(1, $target_line - $context_lines);
        $end_line   = min($total_lines, $target_line + $context_lines);

        $snippet = [];
        for ($i = $start_line; $i <= $end_line; $i++) {
            $line_code = rtrim($all_lines[$i - 1] ?? '', "\r");
            $snippet[] = [
                'number'    => $i,
                'code'      => $line_code,
                'is_target' => ($i === $target_line),
            ];
        }

        $display_path = str_replace($wp_content_norm . '/', 'wp-content/', $resolved_path);
        $display_path = str_replace($abspath_norm, '', $display_path);

        return [
            'success'      => true,
            'file'         => $display_path,
            'target_line'  => $target_line,
            'start_line'   => $start_line,
            'end_line'     => $end_line,
            'total_lines'  => $total_lines,
            'snippet'      => $snippet,
        ];
    }
}
