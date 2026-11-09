<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Firewall\WafFileLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LearningModeEngine (CAF Phase 3)
 *
 * Provides intelligent traffic observation, passive learning mode recording,
 * and 1-click false-positive rule softening synthesis:
 * - Passive Telemetry Collector: Records potential WAF blocks in `wcp_caf_learning_observations` during learning mode.
 * - 1-Click Exemption Synthesizer: Translates a blocked incident finding into a surgical, parameter-level safe-pass rule
 *   bound to specific routes and user capabilities, resolving false positives without lowering global firewall shields.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class LearningModeEngine {

    public const OPTION_OBSERVATIONS = 'wcp_caf_learning_observations';
    public const OPTION_SYNTHESIZED  = 'wcp_caf_synthesized_exemptions';
    public const MAX_OBSERVATIONS    = 250;

    /**
     * Record a passive learning mode observation when a rule would have blocked a request.
     *
     * @param array $rule Rule metadata
     * @param string $client_ip Client IP
     * @param string $request_uri Target URI
     * @param array $request_payload Key-value payload elements
     */
    public static function record_observation(array $rule, string $client_ip, string $request_uri, array $request_payload = []): void {
        $observations = get_option(self::OPTION_OBSERVATIONS, []);
        if (!is_array($observations)) {
            $observations = [];
        }

        $now = time();
        $obs_id = 'OBS-' . strtoupper(substr(md5($client_ip . $request_uri . microtime(true)), 0, 8));

        $clean_uri = (string) wp_parse_url($request_uri, PHP_URL_PATH);
        $raw_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $method = strtoupper($raw_method);
        $is_user_logged = function_exists('is_user_logged_in') && is_user_logged_in();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Passive observation of request auth context
        $has_nonce = !empty($_SERVER['HTTP_X_WP_NONCE']) || !empty($_REQUEST['_wpnonce']);

        $entry = [
            'id'             => $obs_id,
            'rule_id'        => $rule['id'] ?? 'WAF-GENERIC',
            'rule_name'      => $rule['name'] ?? 'Firewall Rule',
            'rule_category'  => $rule['category'] ?? 'Security Policy',
            'ip'             => $client_ip,
            'method'         => $method,
            'uri'            => substr($request_uri, 0, 300),
            'clean_route'    => substr($clean_uri, 0, 150),
            'payload_sample' => substr(wp_json_encode($request_payload), 0, 500),
            'is_logged_in'   => $is_user_logged,
            'has_nonce'      => $has_nonce,
            'auth_context'   => $is_user_logged ? ($has_nonce ? 'authenticated_nonce' : 'authenticated_session') : 'anonymous_guest',
            'observed_at'    => $now,
            'status'         => 'observed',
        ];

        array_unshift($observations, $entry);

        if (count($observations) > self::MAX_OBSERVATIONS) {
            $observations = array_slice($observations, 0, self::MAX_OBSERVATIONS);
        }

        update_option(self::OPTION_OBSERVATIONS, $observations, false);
    }

    /**
     * Synthesize a targeted safe-pass exemption for a blocked finding/incident ID.
     *
     * @param string $finding_id Incident reference ID (e.g. WCP-XXXX or OBS-XXXX)
     * @return array Result containing created exemption rule definition
     */
    public static function synthesize_exemption(string $finding_id): array {
        $incident = self::locate_incident_record($finding_id);
        if (!$incident) {
            return [
                'success' => false,
                /* translators: %s: incident or finding ID */
                'message' => sprintf(__('Incident record "%s" not found in active WAF telemetry or learning observations.', 'webcare-pro-security'), esc_html($finding_id)),
            ];
        }

        $raw_uri = (string) ($incident['uri'] ?? ($incident['url'] ?? ($incident['request_uri'] ?? '')));
        $clean_path = (string) (wp_parse_url($raw_uri, PHP_URL_PATH) ?: '/');
        $rule_id = (string) ($incident['rule_id'] ?? ($incident['id'] ?? 'WAF-GENERIC'));
        $rule_category = (string) ($incident['category'] ?? ($incident['rule_category'] ?? 'Generic'));

        // Determine specific parameter and route pattern
        $param_target = '';
        if (!empty($incident['match_value'])) {
            $param_target = (string) $incident['match_value'];
        } elseif (!empty($incident['payload'])) {
            // Extract field name if present (e.g. "param: content" or "field=value")
            if (preg_match('/(?:param|field|key)[:=]\s*([a-zA-Z0-9_-]+)/i', (string) $incident['payload'], $m)) {
                $param_target = $m[1];
            }
        }

        // Determine capability binding
        $capability = 'manage_options';
        if (str_contains($clean_path, 'admin-ajax.php') || str_contains($clean_path, 'wp-json')) {
            $capability = 'edit_posts';
        }

        // Generate surgical scoped exemption
        $exemption_id = 'EXEMPT-' . strtoupper(substr(md5($clean_path . $rule_id . $param_target), 0, 8));
        $exemption_rule = [
            'id'            => $exemption_id,
            'source_id'     => $finding_id,
            'route'         => $clean_path,
            'rule_id'       => $rule_id,
            'rule_category' => $rule_category,
            'param_key'     => $param_target,
            'capability'    => $capability,
            'description'   => sprintf(
                'Surgical safe-pass for "%s" on route "%s" (%s) synthesized via 1-click learning mode.',
                $param_target ?: $rule_id,
                $clean_path,
                $capability
            ),
            'created_at'    => time(),
            'status'        => 'active',
        ];

        $synthesized = get_option(self::OPTION_SYNTHESIZED, []);
        if (!is_array($synthesized)) {
            $synthesized = [];
        }

        $synthesized[$exemption_id] = $exemption_rule;
        update_option(self::OPTION_SYNTHESIZED, $synthesized, false);

        // Also mark observation as synthesized if in learning table
        self::mark_observation_synthesized($finding_id);

        return [
            'success'   => true,
            /* translators: %s: exemption ID */
            'message'   => sprintf(__('Surgical safe-pass exemption "%s" created successfully.', 'webcare-pro-security'), esc_html($exemption_id)),
            'exemption' => $exemption_rule,
        ];
    }

    /**
     * Get all active synthesized exemptions.
     *
     * @return array
     */
    public static function get_synthesized_exemptions(): array {
        $stored = get_option(self::OPTION_SYNTHESIZED, []);
        return is_array($stored) ? array_values($stored) : [];
    }

    /**
     * Check if a request matches any active synthesized exemption.
     *
     * @param string $route Current route path
     * @param string $rule_id Rule identifier being evaluated
     * @return bool True if exempted, false otherwise
     */
    public static function is_request_exempted(string $route, string $rule_id): bool {
        $exemptions = self::get_synthesized_exemptions();
        if (empty($exemptions)) {
            return false;
        }

        $clean_route = (string) (wp_parse_url($route, PHP_URL_PATH) ?: $route);

        foreach ($exemptions as $ex) {
            if (($ex['status'] ?? '') !== 'active') {
                continue;
            }

            if (!empty($ex['rule_id']) && $ex['rule_id'] !== $rule_id) {
                continue;
            }

            // Verify route match
            if (!empty($ex['route']) && !str_contains($clean_route, $ex['route'])) {
                continue;
            }

            // Verify user capability if required
            if (!empty($ex['capability']) && function_exists('current_user_can')) {
                if (!current_user_can($ex['capability'])) {
                    continue;
                }
            }

            return true; // Match found -> grant safe pass!
        }

        return false;
    }

    /**
     * Locate an incident record from recent learning observations or WafFileLogger logs.
     */
    private static function locate_incident_record(string $id): ?array {
        // 1. Search learning observations
        $observations = get_option(self::OPTION_OBSERVATIONS, []);
        if (is_array($observations)) {
            foreach ($observations as $obs) {
                if (($obs['id'] ?? '') === $id) {
                    return $obs;
                }
            }
        }

        // 2. Search WafFileLogger
        if (class_exists(WafFileLogger::class)) {
            $logs = WafFileLogger::query_logs(['limit' => 100]);
            $entries = $logs['logs'] ?? ($logs['items'] ?? []);
            if (!empty($entries) && is_array($entries)) {
                foreach ($entries as $item) {
                    if (($item['incident_id'] ?? '') === $id || ($item['id'] ?? '') === $id) {
                        return $item;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Mark an observation record as synthesized.
     */
    private static function mark_observation_synthesized(string $id): void {
        $observations = get_option(self::OPTION_OBSERVATIONS, []);
        if (!is_array($observations)) {
            return;
        }

        foreach ($observations as &$obs) {
            if (($obs['id'] ?? '') === $id) {
                $obs['status'] = 'synthesized';
                break;
            }
        }
        update_option(self::OPTION_OBSERVATIONS, $observations, false);
    }
}
