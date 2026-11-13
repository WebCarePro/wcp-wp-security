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

    const OPTION_RULES         = 'webcareproscan_modular_waf_rules';
    const OPTION_AUTOPILOT     = 'webcareproscan_modular_autopilot';
    const OPTION_AUTOPILOT_OBS = 'webcareproscan_modular_autopilot_obs';
    const OPTION_CUSTOM_SEQ    = 'webcareproscan_modular_custom_rule_seq';

    /**
     * Check whether Smart 48-Hour Auto-Pilot is enabled.
     */
    public static function is_autopilot_enabled(): bool {
        return (bool) get_option(self::OPTION_AUTOPILOT, false);
    }

    /**
     * Toggle Smart 48-Hour Auto-Pilot across synthesized modular rules.
     */
    public static function set_autopilot_enabled(bool $enabled): array {
        update_option(self::OPTION_AUTOPILOT, $enabled, false);
        $rules   = self::get_active_rules();
        $updated = 0;
        $now     = time();

        foreach ($rules as &$r) {
            $cat = $r['category'] ?? '';
            if ($enabled) {
                if (in_array($cat, ['tamper_guard', 'abspath_lock'], true)) {
                    if (($r['current_mode'] ?? 'off') !== 'enforce') {
                        $r['current_mode'] = 'enforce';
                        $r['updated_at']   = $now;
                        $updated++;
                    }
                } elseif (in_array($cat, ['ajax_shield', 'rest_guard'], true)) {
                    if (($r['current_mode'] ?? 'off') !== 'off') {
                        $r['current_mode']        = 'smart_learning';
                        $r['learning_started_at'] = $r['learning_started_at'] ?? $now;
                        $r['updated_at']          = $now;
                        $updated++;
                    }
                }
            } else {
                if (($r['current_mode'] ?? '') === 'smart_learning') {
                    $r['current_mode'] = $r['recommended_mode'] ?? 'enforce';
                    $r['updated_at']   = $now;
                    $updated++;
                }
            }
        }
        unset($r);

        if ($updated > 0) {
            self::save_rules($rules);
        }

        return [
            'success'           => true,
            'autopilot_enabled' => $enabled,
            'updated_rules'     => $updated,
            'rules'             => $rules,
            'message'           => $enabled
                ? __('Smart 48-Hour Auto-Pilot activated: high-risk file locks enforced immediately, while active plugin AJAX/REST endpoints learn normal traffic safely for 48 hours.', 'webcare-pro-security')
                : __('Smart 48-Hour Auto-Pilot paused: rules switched back to explicit recommended enforcement states.', 'webcare-pro-security'),
        ];
    }

    /**
     * Record a clean benign hit against a smart_learning rule (at most once per request, capped option writes).
     */
    private static function record_autopilot_benign_hit(string $rule_id): void {
        static $recorded_this_req = [];
        if (isset($recorded_this_req[$rule_id])) {
            return;
        }
        $recorded_this_req[$rule_id] = true;

        $obs = get_option(self::OPTION_AUTOPILOT_OBS, []);
        if (!is_array($obs)) {
            $obs = [];
        }
        $entry = $obs[$rule_id] ?? ['first_seen' => time(), 'benign_hits' => 0, 'last_seen' => 0];
        // Throttle option writes for high-traffic rules to once every 60 seconds
        if ((time() - (int) ($entry['last_seen'] ?? 0)) < 60 && (int) ($entry['benign_hits'] ?? 0) > 0) {
            return;
        }
        $entry['benign_hits'] = (int) ($entry['benign_hits'] ?? 0) + 1;
        $entry['last_seen']   = time();
        $obs[$rule_id]        = $entry;
        update_option(self::OPTION_AUTOPILOT_OBS, $obs, false);
    }

    /**
     * Evaluate whether dormant smart_learning rules (48h+ elapsed with 0 legitimate traffic) should promote to enforce.
     */
    public static function evaluate_autopilot_promotions(): int {
        if (!self::is_autopilot_enabled()) {
            return 0;
        }
        $rules    = self::get_active_rules();
        $obs      = get_option(self::OPTION_AUTOPILOT_OBS, []);
        $promoted = 0;
        $now      = time();

        foreach ($rules as &$r) {
            if (($r['current_mode'] ?? '') !== 'smart_learning') {
                continue;
            }
            $started = (int) ($r['learning_started_at'] ?? ($r['synthesized_at'] ?? $now));
            if (($now - $started) < 48 * HOUR_IN_SECONDS) {
                continue;
            }
            $hits = (int) ($obs[$r['id']]['benign_hits'] ?? 0);
            if ($hits === 0) {
                $r['current_mode'] = 'enforce';
                $r['updated_at']   = $now;
                $r['autopilot_note'] = __('Auto-promoted to Enforce after 48h with zero legitimate visitor traffic.', 'webcare-pro-security');
                $promoted++;
            } else {
                $r['autopilot_note'] = sprintf(
                    /* translators: %d: observed clean hits */
                    __('Kept open under SQLi/XSS payload filtering (%d legitimate requests verified cleanly over 48h).', 'webcare-pro-security'),
                    $hits
                );
            }
        }
        unset($r);

        if ($promoted > 0) {
            self::save_rules($rules);
        }
        return $promoted;
    }

    /**
     * Synthesize modular rules from raw inventory, endpoint maps, and findings.
     *
     * @param array $inventory   Discovered plugins, themes, and mu-plugins
     * @param array $endpoint_map Mapped AJAX hooks and REST routes
     * @param array $findings    AST taint and architectural findings
     * @return array List of synthesized modular rule definitions
     */
    public static function synthesize_rules(array $inventory, array $endpoint_map, array $findings): array {
        $rules          = [];
        $existing       = self::get_active_rules();
        $existing_by_id = [];
        $custom_rules   = [];
        $autopilot_on   = self::is_autopilot_enabled();

        foreach ($existing as $r) {
            if (!empty($r['id'])) {
                $existing_by_id[$r['id']] = $r;
            }
            if (!empty($r['is_custom'])) {
                $custom_rules[] = $r;
            }
        }

        // Build component lookup index by name
        $component_map = [];
        foreach ($inventory as $comp) {
            if (is_array($comp) && !empty($comp['name'])) {
                $component_map[$comp['name']] = $comp;
            }
        }

        // 0. Synthesize MOD-TAMPER-* Rules for Modified/Injected Files in Official Plugins/Themes
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'integrity_tamper_mismatch') {
                $file = sanitize_text_field($f['file'] ?? '');
                if (empty($file)) {
                    continue;
                }

                $rule_id = 'MOD-TAMPER-' . strtoupper(substr(md5($file), 0, 8));
                $prev    = $existing_by_id[$rule_id] ?? null;

                $rules[] = self::enrich_synthesized_rule([
                    'id'               => $rule_id,
                    'category'         => 'tamper_guard',
                    'title'            => sprintf(
                        /* translators: %s: relative file path */
                        __('Checksum Tamper / Unrecognized File Lock: %s', 'webcare-pro-security'),
                        basename($file)
                    ),
                    'description'      => sprintf(
                        /* translators: %s: file path */
                        __('Immediately blocks direct HTTP access to "%s" because it failed official release checksum verification or is untracked inside an official extension.', 'webcare-pro-security'),
                        $file
                    ),
                    'origin_component' => $f['component'] ?? 'Custom',
                    'file'             => $file,
                    'line'             => 1,
                    'evidence'         => $f['evidence'] ?? '',
                    'severity'         => 'critical',
                    'recommended_mode' => 'enforce',
                    'current_mode'     => $prev ? $prev['current_mode'] : 'enforce',
                    'target_uri'       => $file,
                    'target_param'     => '',
                    'target_value'     => '',
                    'http_methods'     => ['GET', 'POST', 'HEAD'],
                    'rate_limit'       => 0,
                    'block_uploads'    => true,
                    'sync_cloudflare'  => true,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ], $f, $component_map);
            }
        }

        // 1. Synthesize MOD-AJAX-* Rules for Unprotected Guest AJAX actions
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'unprotected_guest_ajax') {
                $action = self::normalize_action_token((string) ($f['action'] ?? ''));
                if (empty($action)) {
                    continue;
                }

                $rule_id = 'MOD-AJAX-' . strtoupper(substr(md5($action), 0, 8));
                $prev    = $existing_by_id[$rule_id] ?? null;

                $is_tampered       = self::is_tampered_finding($f);
                $is_trusted_source = self::is_verified_non_tampered_finding($f);
                $has_sink          = array_key_exists('has_dangerous_sink', $f) ? !empty($f['has_dangerous_sink']) : true;

                // Read-only or checksum-verified / trusted vendor callbacks recommend monitor to avoid blocking legitimate features
                $rec_mode = ($is_trusted_source || !$has_sink) ? 'monitor' : 'enforce';
                $sev      = (!$has_sink && $is_trusted_source) ? 'medium' : ($has_sink && !$is_trusted_source ? 'critical' : 'high');
                $cur_mode = $prev ? $prev['current_mode'] : ($autopilot_on ? 'smart_learning' : $rec_mode);

                $rules[] = self::enrich_synthesized_rule([
                    'id'                  => $rule_id,
                    'category'            => 'ajax_shield',
                    'title'               => sprintf(
                        /* translators: %s: AJAX action name */
                        __('Unprotected Guest AJAX Shield: action="%s"', 'webcare-pro-security'),
                        $action
                    ),
                    'description'         => sprintf(
                        /* translators: %s: AJAX action name */
                        __('Enforces strict SQLi, XSS, and payload sanitization on guest AJAX action "%s" and caps request velocity to prevent brute-force attacks.', 'webcare-pro-security'),
                        $action
                    ),
                    'origin_component'    => $f['component'] ?? 'Custom',
                    'file'                => $f['file'] ?? '',
                    'line'                => $f['line'] ?? 1,
                    'evidence'            => $f['evidence'] ?? '',
                    'severity'            => $sev,
                    'recommended_mode'    => $rec_mode,
                    'current_mode'        => $cur_mode,
                    'target_uri'          => 'admin-ajax.php',
                    'target_param'        => 'action',
                    'target_value'        => $action,
                    'http_methods'        => ['POST', 'GET'],
                    'rate_limit'          => 15, // max req per minute
                    'block_uploads'       => $has_sink,
                    'sync_cloudflare'     => true,
                    'learning_started_at' => $prev['learning_started_at'] ?? time(),
                    'synthesized_at'      => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ], $f, $component_map);
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
                $prev    = $existing_by_id[$rule_id] ?? null;

                $is_tampered_rest  = self::is_tampered_finding($f);
                $is_read_only_rest = !$is_tampered_rest && array_key_exists('has_dangerous_sink', $f) && empty($f['has_dangerous_sink']) && !empty($f['scope_found']);
                $is_trusted_rest   = !$is_tampered_rest && (
                    !empty($f['has_internal_guard'])
                    || self::is_verified_non_tampered_finding($f)
                );
                $rest_rec_mode = ($is_trusted_rest || $is_read_only_rest) ? 'monitor' : 'enforce';
                $rest_sev      = ($is_trusted_rest || $is_read_only_rest) ? 'medium' : 'high';

                $rules[] = self::enrich_synthesized_rule([
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
                    'severity'            => $rest_sev,
                    'recommended_mode'    => $rest_rec_mode,
                    'current_mode'        => $prev ? $prev['current_mode'] : ($autopilot_on ? 'smart_learning' : $rest_rec_mode),
                    'target_uri'          => $route,
                    'target_param'        => '',
                    'target_value'        => '',
                    'http_methods'        => ['POST', 'PUT', 'DELETE'],
                    'rate_limit'          => 30,
                    'block_uploads'       => false,
                    'sync_cloudflare'     => true,
                    'learning_started_at' => $prev['learning_started_at'] ?? time(),
                    'synthesized_at'      => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ], $f, $component_map);
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

                $rules[] = self::enrich_synthesized_rule([
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
                    'severity'         => $f['severity'] ?? 'high',
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
                ], $f, $component_map);
            }
        }

        // 4. Synthesize MOD-UPLOAD-* Rules for Custom Upload Sinks
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'raw_file_upload_sink') {
                $file = sanitize_text_field($f['file'] ?? '');
                $rule_id = 'MOD-UPLOAD-' . strtoupper(substr(md5($file . ':' . ($f['line'] ?? 1)), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $is_trusted_upload = self::is_verified_non_tampered_finding($f);
                $upload_rec_mode   = $is_trusted_upload ? 'monitor' : 'enforce';
                $upload_sev        = $is_trusted_upload ? 'medium' : 'high';

                $rules[] = self::enrich_synthesized_rule([
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
                    'severity'         => $upload_sev,
                    'recommended_mode' => $upload_rec_mode,
                    'current_mode'     => $prev ? $prev['current_mode'] : ($autopilot_on ? 'smart_learning' : $upload_rec_mode),
                    'target_uri'       => $file,
                    'target_param'     => '',
                    'target_value'     => '',
                    'http_methods'     => ['POST'],
                    'rate_limit'       => 10,
                    'block_uploads'    => false, // inspected strictly rather than blocked
                    'sync_cloudflare'  => false,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ], $f, $component_map);
            }
        }

        // 5. Synthesize MOD-EGRESS-* Rules for Dynamic Outbound HTTP Sinks (SSRF)
        foreach ($findings as $f) {
            if (($f['type'] ?? '') === 'ssrf_egress_sink') {
                $file = sanitize_text_field($f['file'] ?? '');
                $rule_id = 'MOD-EGRESS-' . strtoupper(substr(md5($file . ':' . ($f['line'] ?? 1)), 0, 8));
                $prev = $existing_by_id[$rule_id] ?? null;

                $is_trusted_egress = self::is_verified_non_tampered_finding($f);
                $egress_rec_mode   = $is_trusted_egress ? 'monitor' : 'enforce';
                $egress_sev        = $is_trusted_egress ? 'medium' : 'high';

                $rules[] = self::enrich_synthesized_rule([
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
                    'severity'         => $egress_sev,
                    'recommended_mode' => $egress_rec_mode,
                    'current_mode'     => $prev ? $prev['current_mode'] : ($autopilot_on ? 'smart_learning' : $egress_rec_mode),
                    'target_uri'       => $file,
                    'target_param'     => 'url,webhook,feed,callback_url,endpoint',
                    'target_value'     => '',
                    'http_methods'     => ['POST', 'GET'],
                    'rate_limit'       => 20,
                    'block_uploads'    => false,
                    'sync_cloudflare'  => false,
                    'synthesized_at'   => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
                ], $f, $component_map);
            }
        }

        // 6. Synthesize MOD-CVE-* Virtual Shield Rules for Outdated / Vulnerable Components
        foreach ($inventory as $comp) {
            if (!is_array($comp)) {
                continue;
            }
            $has_cve = !empty($comp['has_cve']);
            $has_upd = !empty($comp['update_available']);
            if (!$has_cve && !$has_upd) {
                continue;
            }

            $c_slug  = sanitize_key($comp['slug'] ?? ($comp['name'] ?? 'component'));
            $c_type  = sanitize_key($comp['type'] ?? 'plugin');
            $c_name  = (string) ($comp['name'] ?? $c_slug);
            $c_ver   = (string) ($comp['version'] ?? '0.0.0');
            $l_ver   = (string) ($comp['latest_version'] ?? '');
            $cves    = is_array($comp['cves'] ?? null) ? $comp['cves'] : [];
            $cve_ids = array_values(array_filter(array_map(static fn($c) => $c['cve_id'] ?? '', $cves)));
            $rule_id = 'MOD-CVE-' . strtoupper(substr(md5($c_type . ':' . $c_slug), 0, 8));
            $prev    = $existing_by_id[$rule_id] ?? null;

            $rec_mode = $has_cve ? 'enforce' : 'monitor';
            $sev      = $has_cve ? 'critical' : 'medium';

            $rules[] = self::enrich_synthesized_rule([
                'id'                => $rule_id,
                'category'          => 'cve_patch',
                'title'             => $has_cve
                    ? sprintf(
                        /* translators: %1$s: component name, %2$s: CVE ID list */
                        __('Virtual CVE Shield: %1$s (%2$s)', 'webcare-pro-security'),
                        $c_name,
                        implode(', ', array_slice($cve_ids, 0, 3)) ?: 'Known CVE'
                    )
                    : sprintf(
                        /* translators: %1$s: component name, %2$s: version */
                        __('Outdated Component Shield: %1$s (v%2$s)', 'webcare-pro-security'),
                        $c_name,
                        $c_ver
                    ),
                'description'       => $has_cve
                    ? sprintf(
                        /* translators: %1$s: component name, %2$s: installed version, %3$s: CVE count */
                        __('Shields "%1$s" v%2$s against SQLi, XSS, path traversal, PHP object injection, and dangerous uploads for %3$d documented CVE advisory(s) until safely updated.', 'webcare-pro-security'),
                        $c_name,
                        $c_ver,
                        count($cves)
                    )
                    : sprintf(
                        /* translators: %1$s: component name, %2$s: installed version, %3$s: latest version */
                        __('Applies protective payload & upload inspection for outdated extension "%1$s" (v%2$s → v%3$s available).', 'webcare-pro-security'),
                        $c_name,
                        $c_ver,
                        $l_ver !== '' ? $l_ver : 'Latest'
                    ),
                'origin_component'  => $c_name,
                'component_slug'    => $c_slug,
                'component_type'    => $c_type,
                'installed_version' => $c_ver,
                'latest_version'    => $l_ver,
                'cve_ids'           => $cve_ids,
                'file'              => ($c_type === 'plugin' ? 'plugins/' : 'themes/') . $c_slug,
                'line'              => 1,
                'evidence'          => !empty($cve_ids)
                    ? implode(', ', $cve_ids)
                    : sprintf('Pending update available: v%s -> v%s', $c_ver, $l_ver ?: 'latest'),
                'severity'          => $sev,
                'recommended_mode'  => $rec_mode,
                'current_mode'      => $prev ? $prev['current_mode'] : $rec_mode,
                'target_uri'        => $c_slug,
                'target_param'      => '',
                'target_value'      => $c_slug,
                'http_methods'      => ['GET', 'POST', 'PUT', 'DELETE'],
                'rate_limit'        => 30,
                'block_uploads'     => true,
                'sync_cloudflare'   => $has_cve,
                'synthesized_at'    => $prev ? ($prev['synthesized_at'] ?? time()) : time(),
            ], [
                'origin_type'       => $comp['origin_type'] ?? 'custom_unmanaged',
                'is_official_wporg' => !empty($comp['is_official_wporg']),
                'is_known_vendor'   => !empty($comp['is_known_vendor']),
                'vendor_name'       => $comp['vendor_name'] ?? null,
                'checksum_status'   => $comp['checksum_status'] ?? 'not_available',
            ], $component_map);
        }

        // Re-append developer-created custom rules so behavioral re-scans never remove custom rules
        foreach ($custom_rules as $cr) {
            $rules[] = $cr;
        }

        // Save synthesized rules to option
        self::save_rules($rules);

        return $rules;
    }

    /**
     * Enrich a synthesized rule with component origin, official checksum attestation,
     * cryptographic file hashes, and false-positive risk indicator.
     */
    public static function enrich_synthesized_rule(array $rule, array $finding, array $component_map = []): array {
        $comp_name = $rule['origin_component'] ?? '';
        $comp      = $component_map[$comp_name] ?? [];

        $origin_type       = $finding['origin_type'] ?? ($comp['origin_type'] ?? 'custom_unmanaged');
        $is_official_wporg = !empty($finding['is_official_wporg']) || !empty($comp['is_official_wporg']);
        $is_known_vendor   = !empty($finding['is_known_vendor']) || !empty($comp['is_known_vendor']);
        $vendor_name       = $finding['vendor_name'] ?? ($comp['vendor_name'] ?? null);

        $file_sha256       = $finding['file_sha256'] ?? null;
        $file_md5          = $finding['file_md5'] ?? null;
        $checksum_status   = $finding['checksum_status'] ?? 'unmanaged_custom';
        $expected_checksum = $finding['expected_checksum'] ?? null;
        $known_vendor_lib  = $finding['known_vendor_lib'] ?? null;

        // Fallback live verification if finding didn't include hashes
        if ($file_sha256 === null && !empty($rule['file']) && class_exists('\\WebCareProScanner\\Firewall\\Modular\\ComponentIntegrityVerifier')) {
            $forensics = ComponentIntegrityVerifier::verify_file_forensics($rule['file'], $comp);
            $file_sha256       = $forensics['file_sha256'];
            $file_md5          = $forensics['file_md5'];
            $checksum_status   = $forensics['checksum_status'];
            $expected_checksum = $forensics['expected_checksum'];
            $known_vendor_lib  = $forensics['known_vendor_lib'];
        }

        // Calculate diagnostic false-positive risk level for log analysts
        $fp_risk = 'low';
        $cat     = $rule['category'] ?? '';
        if (in_array($checksum_status, ['modified', 'unknown_in_official', 'self_modified', 'self_untracked'], true)) {
            $fp_risk = 'very_low';
            $provenance_note = __('ALERT: File failed official release checksum or is untracked inside an official extension.', 'webcare-pro-security');
        } elseif ($checksum_status === 'authentic' || $checksum_status === 'self_verified') {
            $provenance_note = __('File verified bit-for-bit against official release checksum manifest.', 'webcare-pro-security');
            if ($cat === 'rest_guard') {
                // Legitimate WP.org plugins occasionally register __return_true routes that validate tokens inside the callback
                $fp_risk = 'medium';
            }
        } elseif ($checksum_status === 'known_vendor_hash_match') {
            $fp_risk = 'medium';
            $provenance_note = sprintf(
                /* translators: %s: library name */
                __('Matched 128-bit SHA-256 fingerprint of known upstream library: %s', 'webcare-pro-security'),
                (string) $known_vendor_lib
            );
        } elseif ($is_known_vendor) {
            $provenance_note = sprintf(
                /* translators: %s: vendor name */
                __('Commercial / verified vendor extension: %s', 'webcare-pro-security'),
                (string) $vendor_name
            );
            if ($cat === 'rest_guard') {
                $fp_risk = 'medium';
            }
        } else {
            $provenance_note = __('Custom or unmanaged code — no official WordPress.org checksum manifest available.', 'webcare-pro-security');
        }

        $rule['component_origin_type'] = $origin_type;
        $rule['is_official_wporg']     = $is_official_wporg;
        $rule['is_known_vendor']       = $is_known_vendor;
        $rule['vendor_name']           = $vendor_name;
        $rule['file_sha256']           = $file_sha256;
        $rule['file_md5']              = $file_md5;
        $rule['checksum_status']       = $checksum_status;
        $rule['expected_checksum']     = $expected_checksum;
        $rule['known_vendor_lib']      = $known_vendor_lib;
        $rule['false_positive_risk']   = $fp_risk;
        $rule['provenance_note']       = $provenance_note;

        return $rule;
    }

    /**
     * Get all active modular firewall rules.
     *
     * @return array
     */
    public static function get_active_rules(): array {
        $saved = get_option(self::OPTION_RULES, null);
        if (is_array($saved)) {
            return self::normalize_custom_rule_ordering($saved, false);
        }

        // Fallback to Vault Shard
        $from_shard = BehavioralVaultManager::read_shard(BehavioralVaultManager::SHARD_RULES);
        if (is_array($from_shard)) {
            $normalized = self::normalize_custom_rule_ordering($from_shard, false);
            update_option(self::OPTION_RULES, $normalized, false);
            return $normalized;
        }

        return [];
    }

    /**
     * Allocate next unique monotonic numeric ID (#1, #2, #3...) for custom rules.
     */
    private static function allocate_custom_rule_number(array $existing_rules = []): int {
        $seq = (int) get_option(self::OPTION_CUSTOM_SEQ, 0);
        foreach ($existing_rules as $r) {
            if (!empty($r['rule_number'])) {
                $seq = max($seq, (int) $r['rule_number']);
            }
        }
        $next = $seq + 1;
        update_option(self::OPTION_CUSTOM_SEQ, $next, false);
        return $next;
    }

    /**
     * Normalize custom rule ordering so custom rules always evaluate before baseline rules in ascending `priority` (1..N)
     * and every custom rule holds an immutable sequential `rule_number` ID.
     */
    private static function normalize_custom_rule_ordering(array $rules, bool $persist_seq = true): array {
        $custom     = [];
        $baseline   = [];
        $max_num    = (int) get_option(self::OPTION_CUSTOM_SEQ, 0);
        $seq_bumped = false;

        foreach ($rules as $idx => $r) {
            if (!is_array($r)) {
                continue;
            }
            if (!empty($r['is_custom']) || ($r['category'] ?? '') === 'custom') {
                if (!empty($r['rule_number'])) {
                    $max_num = max($max_num, (int) $r['rule_number']);
                }
                $custom[] = ['idx' => $idx, 'rule' => $r];
            } else {
                $baseline[] = $r;
            }
        }

        if (empty($custom)) {
            return $baseline;
        }

        // Assign unique numeric IDs to any legacy custom rules missing one
        foreach ($custom as &$item) {
            if (empty($item['rule']['rule_number'])) {
                $max_num++;
                $item['rule']['rule_number'] = $max_num;
                $seq_bumped = true;
            }
        }
        unset($item);

        if ($persist_seq && $seq_bumped) {
            update_option(self::OPTION_CUSTOM_SEQ, $max_num, false);
        }

        // Stable sort by priority ascending (rules with unset priority preserve creation/list order at end)
        usort($custom, static function ($a, $b) {
            $pa = isset($a['rule']['priority']) && intval($a['rule']['priority']) > 0 ? intval($a['rule']['priority']) : (100000 + $a['idx']);
            $pb = isset($b['rule']['priority']) && intval($b['rule']['priority']) > 0 ? intval($b['rule']['priority']) : (100000 + $b['idx']);
            if ($pa === $pb) {
                return $a['idx'] <=> $b['idx'];
            }
            return $pa <=> $pb;
        });

        $normalized_custom = [];
        $pos = 1;
        foreach ($custom as $item) {
            $r             = $item['rule'];
            $r['priority'] = $pos++;
            $normalized_custom[] = $r;
        }

        return array_merge($normalized_custom, $baseline);
    }

    /**
     * Save modular firewall rules list.
     *
     * @param array $rules
     * @return bool
     */
    public static function save_rules(array $rules): bool {
        $rules   = self::normalize_custom_rule_ordering($rules, true);
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
        $valid_modes = ['enforce', 'smart_learning', 'monitor', 'off'];
        if (!in_array($mode, $valid_modes, true)) {
            $mode = 'monitor';
        }

        $rules = self::get_active_rules();
        $found = false;
        $updated_rule = null;

        foreach ($rules as &$r) {
            if (($r['id'] ?? '') === $rule_id) {
                $r['current_mode'] = $mode;
                if ($mode === 'smart_learning' && empty($r['learning_started_at'])) {
                    $r['learning_started_at'] = time();
                }
                if (isset($params['rate_limit'])) {
                    $r['rate_limit']      = max(0, intval($params['rate_limit']));
                    $r['immediate_block'] = ($r['rate_limit'] <= 0);
                }
                if (isset($params['immediate_block'])) {
                    $r['immediate_block'] = !empty($params['immediate_block']);
                }
                if (isset($params['ban_ttl'])) {
                    $r['ban_ttl'] = max(0, min(2592000, intval($params['ban_ttl'])));
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
            'custom_rules_enforced'  => [],
            'visual_rules_enforced'  => [],
        ];

        foreach ($rules as $r) {
            if (($r['current_mode'] ?? '') !== 'enforce') {
                continue;
            }

            $cat = $r['category'] ?? '';

            // 0. Custom Developer-Defined & Custom Firewall Rules (MOD-CUSTOM-*)
            if (!empty($r['is_custom']) || $cat === 'custom') {
                $action_type = (string) ($r['action_type'] ?? '');
                $rate_lim    = max(0, intval($r['rate_limit'] ?? 0));
                $immediate   = !empty($r['immediate_block']) || $rate_lim <= 0 || in_array($action_type, ['block', 'block_and_ban'], true);
                $sync_cf     = !empty($r['sync_cloudflare']);
                $ban_ttl     = isset($r['ban_ttl']) ? max(0, (int) $r['ban_ttl']) : (($sync_cf || $action_type === 'block_and_ban') ? 86400 : 0);

                // Visual condition tree rules: compile stateless HTTP/Network trees directly into pre-boot Micro-WAF (block & allow in priority order)
                if (!empty($r['conditions']) && is_array($r['conditions']) && class_exists(VisualRuleExpressionEngine::class)) {
                    if (in_array($action_type, ['', 'block', 'block_and_ban', 'allow'], true) && VisualRuleExpressionEngine::is_stateless_preload_eligible($r['conditions'])) {
                        $compiled['visual_rules_enforced'][] = [
                            'rule_id'         => (string) ($r['id'] ?? 'MOD-CUSTOM'),
                            'rule_number'     => (int) ($r['rule_number'] ?? 0),
                            'priority'        => (int) ($r['priority'] ?? 0),
                            'title'           => (string) ($r['title'] ?? ''),
                            'action_type'     => $action_type !== '' ? $action_type : 'block',
                            'group_logic'     => strtoupper((string) ($r['group_logic'] ?? 'OR')) === 'AND' ? 'AND' : 'OR',
                            'conditions'      => $r['conditions'],
                            'exempt_rules'    => is_array($r['exempt_rules'] ?? null) ? $r['exempt_rules'] : [],
                            'sync_cloudflare' => $sync_cf,
                            'ban_ttl'         => $action_type === 'block_and_ban' && $ban_ttl <= 0 ? 86400 : $ban_ttl,
                        ];
                    }
                    continue;
                }

                $t_uri   = strtolower(trim((string) ($r['target_uri'] ?? '')));
                $t_param = !empty($r['target_param'])
                    ? sanitize_key((string) $r['target_param'])
                    : (($cat === 'ajax_shield' && !empty($r['target_value'])) ? 'action' : '');
                if ($t_uri === '' && $t_param === '') {
                    continue;
                }

                $compiled['custom_rules_enforced'][] = [
                    'rule_id'         => (string) ($r['id'] ?? 'MOD-CUSTOM'),
                    'category'        => (string) $cat,
                    'title'           => (string) ($r['title'] ?? ''),
                    'action_type'     => $action_type !== '' ? $action_type : ($immediate ? 'block' : 'rate_limit'),
                    'target_uri'      => $t_uri,
                    'target_param'    => $t_param,
                    'target_value'    => strtolower(trim((string) ($r['target_value'] ?? ''))),
                    'methods'         => is_array($r['http_methods'] ?? null)
                        ? array_values(array_filter(array_map('strtoupper', $r['http_methods'])))
                        : [],
                    'rate_limit'      => $rate_lim,
                    'immediate_block' => $immediate,
                    'block_uploads'   => !empty($r['block_uploads']),
                    'sync_cloudflare' => $sync_cf,
                    'ban_ttl'         => $ban_ttl,
                ];
                continue;
            }

            // 1. Direct Script Locks & Checksum Tamper Guards
            if (in_array($cat, ['abspath_lock', 'tamper_guard'], true) && !empty($r['target_uri'])) {
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
    /**
     * Activate a 1-click MOD-CVE-* virtual shield for a specific outdated/vulnerable component without waiting for an update.
     */
    public static function activate_cve_shield(string $slug, string $type = 'plugin'): array {
        $clean_slug = sanitize_key($slug);
        if (empty($clean_slug)) {
            return ['success' => false, 'message' => __('Component slug is required.', 'webcare-pro-security')];
        }

        $rules        = self::get_active_rules();
        $matched_rule = null;

        foreach ($rules as &$r) {
            $r_slug = sanitize_key($r['component_slug'] ?? '');
            if (($r['category'] ?? '') === 'cve_patch' && $r_slug === $clean_slug) {
                $r['current_mode'] = 'enforce';
                $r['updated_at']   = time();
                $matched_rule      = $r;
                break;
            }
        }
        unset($r);

        if (!$matched_rule) {
            $comps = SiteBehavioralAnalyzer::discover_all_components(false);
            $comp  = null;
            foreach ($comps as $c) {
                if (sanitize_key($c['slug'] ?? '') === $clean_slug) {
                    $comp = $c;
                    break;
                }
            }
            $c_name = $comp['name'] ?? ucwords(str_replace('-', ' ', $clean_slug));
            $c_ver  = $comp['version'] ?? '0.0.0';
            $l_ver  = $comp['latest_version'] ?? '';
            $cves   = is_array($comp['cves'] ?? null) ? $comp['cves'] : [];
            $cve_ids = array_values(array_filter(array_map(static fn($c) => $c['cve_id'] ?? '', $cves)));
            $rule_id = 'MOD-CVE-' . strtoupper(substr(md5($type . ':' . $clean_slug), 0, 8));

            $matched_rule = self::enrich_synthesized_rule([
                'id'                => $rule_id,
                'category'          => 'cve_patch',
                'title'             => sprintf(
                    /* translators: %s: component name */
                    __('1-Click Virtual Shield: %s', 'webcare-pro-security'),
                    $c_name
                ),
                'description'       => sprintf(
                    /* translators: %1$s: component name, %2$s: version */
                    __('Shields "%1$s" (v%2$s) against SQLi, XSS, LFI path traversal, object injection, and executable uploads until you apply a Safe Update.', 'webcare-pro-security'),
                    $c_name,
                    $c_ver
                ),
                'origin_component'  => $c_name,
                'component_slug'    => $clean_slug,
                'component_type'    => $type,
                'installed_version' => $c_ver,
                'latest_version'    => $l_ver,
                'cve_ids'           => $cve_ids,
                'file'              => ($type === 'plugin' ? 'plugins/' : 'themes/') . $clean_slug,
                'line'              => 1,
                'evidence'          => !empty($cve_ids) ? implode(', ', $cve_ids) : __('Activated manually via 1-Click Virtual Shield', 'webcare-pro-security'),
                'severity'          => !empty($cve_ids) ? 'critical' : 'high',
                'recommended_mode'  => 'enforce',
                'current_mode'      => 'enforce',
                'target_uri'        => $clean_slug,
                'target_param'      => '',
                'target_value'      => $clean_slug,
                'http_methods'      => ['GET', 'POST', 'PUT', 'DELETE'],
                'rate_limit'        => 30,
                'block_uploads'     => true,
                'sync_cloudflare'   => true,
                'synthesized_at'    => time(),
            ], [
                'origin_type'       => $comp['origin_type'] ?? 'custom_unmanaged',
                'is_official_wporg' => !empty($comp['is_official_wporg']),
                'is_known_vendor'   => !empty($comp['is_known_vendor']),
                'vendor_name'       => $comp['vendor_name'] ?? null,
                'checksum_status'   => $comp['checksum_status'] ?? 'not_available',
            ]);
            $rules[] = $matched_rule;
        }

        self::save_rules($rules);

        // Also activate matching curated VirtualPatchManager rules if available for any known CVE on this component
        $vpatch_activated = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager') && !empty($matched_rule['cve_ids'])) {
            $catalog = \WebCareProScanner\Firewall\VirtualPatchManager::get_patch_catalog();
            foreach ($matched_rule['cve_ids'] as $cid) {
                if (isset($catalog[$cid])) {
                    \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch($cid);
                    $vpatch_activated[] = $cid;
                }
            }
        }

        return [
            'success'          => true,
            'rule'             => $matched_rule,
            'rule_id'          => $matched_rule['id'],
            'vpatch_activated' => $vpatch_activated,
            'message'          => sprintf(
                /* translators: %1$s: component name, %2$s: modular rule ID */
                __('Virtual Shield activated for "%1$s" (%2$s). Vulnerable endpoints and attack vectors are now blocked.', 'webcare-pro-security'),
                $matched_rule['origin_component'] ?? $clean_slug,
                $matched_rule['id']
            ),
        ];
    }

    /**
     * Build a normalized Modular WAF violation payload carrying Cloudflare sync and ban TTL metadata.
     *
     * @param array  $rule
     * @param string $reason
     * @param bool   $should_block
     * @param string $severity_fallback
     * @return array
     */
    private static function build_violation(array $rule, string $reason, bool $should_block, string $severity_fallback = 'high'): array {
        $sync_cf     = !empty($rule['sync_cloudflare']);
        $action_type = (string) ($rule['action_type'] ?? ($should_block ? 'block' : 'monitor'));
        $ban_ttl     = isset($rule['ban_ttl'])
            ? max(0, (int) $rule['ban_ttl'])
            : (($sync_cf || $action_type === 'block_and_ban') ? 86400 : 0);
        if ($action_type === 'block_and_ban' && $ban_ttl <= 0) {
            $ban_ttl = 86400;
        }

        return [
            'blocked'         => $should_block,
            'rule_id'         => (string) ($rule['id'] ?? ''),
            'title'           => (string) ($rule['title'] ?? ''),
            'category'        => (string) ($rule['category'] ?? 'custom'),
            'action_type'     => $action_type,
            'reason'          => $reason,
            'severity'        => (string) ($rule['severity'] ?? $severity_fallback),
            'mode'            => (string) ($rule['current_mode'] ?? 'enforce'),
            'sync_cloudflare' => $sync_cf,
            'ban_ttl'         => $ban_ttl,
            'exempt_rules'    => is_array($rule['exempt_rules'] ?? null) ? $rule['exempt_rules'] : [],
        ];
    }

    /**
     * Evaluate incoming request against active Modular Rules at WordPress Runtime.
     * Covers all 6 synthesized categories plus custom rules & MOD-CVE virtual shields,
     * honors Rescue Mode 15-minute pauses and permanent trusted-action exemptions,
     * and enforces per-rule velocity limits & logged-in/admin safety guards.
     *
     * @return array|null Returns violation array if blocked/monitored, null if safe.
     */
    public static function evaluate_runtime_modular_rules(): ?array {
        $rules = self::get_active_rules();
        if (empty($rules)) {
            return null;
        }

        $uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        $ip     = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : '127.0.0.1';

        // 1. Tiered Context-Aware Whitelist & Admin Safety Check
        $fw_settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];
        $wl_ctx = ['is_whitelisted' => false, 'full_bypass' => false, 'rule_bypass' => false];
        $is_fw_admin = false;
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            $wl_ctx = \WebCareProScanner\Firewall\FirewallEngine::check_ip_whitelist_context($ip, $fw_settings);
            if (!empty($wl_ctx['full_bypass'])) {
                return null;
            }
            $is_fw_admin = \WebCareProScanner\Firewall\FirewallEngine::is_authenticated_administrator();
        }
        $is_logged_in = function_exists('is_user_logged_in') && is_user_logged_in();
        $is_admin     = $is_fw_admin || ($is_logged_in && function_exists('current_user_can') && current_user_can('manage_options'));
        if ($is_admin) {
            return null;
        }

        $clean_uri = strtolower((string) strtok($uri, '?'));
        if (
            strpos($clean_uri, 'wp-cron.php') !== false
            && class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            && \WebCareProScanner\Firewall\FirewallEngine::is_server_origin_or_loopback($ip)
        ) {
            return null;
        }

        $is_rescue_paused = class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')
            && \WebCareProScanner\Firewall\RescueAssistantManager::is_strict_paused();

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch security inspection of raw AJAX action token
        $req_action = isset($_REQUEST['action']) ? self::normalize_action_token(sanitize_text_field(wp_unslash($_REQUEST['action']))) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch security inspection of REST query route smuggling
        $rest_query = isset($_GET['rest_route']) ? strtolower(sanitize_text_field(wp_unslash($_GET['rest_route']))) : '';
        $payload_rx = '/(?:\bunion\s+all\s+select\b|\bselect\b.{1,40}\bfrom\b.{1,40}\bwp_users\b|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|<script\b|javascript:|wp_capabilities|administrator)/i';

        // Read raw body once for REST JSON / API payloads up to 64KB
        $raw_body = '';
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $raw_body = (string) @file_get_contents('php://input', false, null, 0, 65536);
        }
        $raw_json_data = null;
        $content_type  = isset($_SERVER['CONTENT_TYPE']) ? sanitize_text_field(wp_unslash($_SERVER['CONTENT_TYPE'])) : '';
        if ($raw_body !== '' && ($raw_body[0] === '{' || $raw_body[0] === '[' || str_contains($content_type, 'application/json'))) {
            $raw_json_data = json_decode($raw_body, true);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Pre-dispatch runtime WAF payload inspection
        $raw_payload = wp_json_encode($_REQUEST) ?: '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch runtime WAF file payload inspection
        $files_payload = !empty($_FILES) ? (wp_json_encode($_FILES) ?: '') : '';
        $has_malicious_payload = (bool) (
            preg_match($payload_rx, $raw_payload)
            || ($raw_body !== '' && preg_match($payload_rx, $raw_body))
            || ($files_payload !== '' && preg_match($payload_rx, $files_payload))
        );

        $visual_ctx = null;
        $exempt_all = false;
        $exempt_ids = [];

        foreach ($rules as $r) {
            $mode = $r['current_mode'] ?? 'off';
            if ($mode === 'off') {
                continue;
            }

            $cat     = $r['category'] ?? '';
            $rule_id = (string) ($r['id'] ?? '');
            if ($exempt_all || in_array($rule_id, $exempt_ids, true) || in_array($cat, $exempt_ids, true)) {
                continue;
            }

            // Skip any rule/target explicitly whitelisted via Rescue Assistant ("Trust & Allow Permanently")
            if (
                class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')
                && \WebCareProScanner\Firewall\RescueAssistantManager::is_rule_or_request_trusted($rule_id, $clean_uri, $req_action, $rest_query)
            ) {
                continue;
            }

            $should_block = ($mode === 'enforce') && !$is_rescue_paused;
            $is_smart     = ($mode === 'smart_learning');
            $methods      = is_array($r['http_methods'] ?? null) ? array_map('strtoupper', $r['http_methods']) : [];

            // Custom Developer-Defined & Visual Modular Rule (MOD-CUSTOM-*)
            if (!empty($r['is_custom']) || $cat === 'custom') {
                $matched_custom = false;

                if (!empty($r['conditions']) && is_array($r['conditions']) && class_exists(VisualRuleExpressionEngine::class)) {
                    if ($visual_ctx === null && class_exists('\\WebCareProScanner\\Contracts\\RequestContext')) {
                        $visual_ctx = \WebCareProScanner\Contracts\RequestContext::from_globals();
                    }
                    if ($visual_ctx !== null) {
                        $grp_logic      = strtoupper((string) ($r['group_logic'] ?? 'OR')) === 'AND' ? 'AND' : 'OR';
                        $matched_custom = VisualRuleExpressionEngine::evaluate_groups($r['conditions'], $visual_ctx, $grp_logic);
                    }
                } else {
                    $target_uri_l = strtolower(trim((string) ($r['target_uri'] ?? '')));
                    $tp           = !empty($r['target_param'])
                        ? sanitize_key((string) $r['target_param'])
                        : (($cat === 'ajax_shield' && !empty($r['target_value'])) ? 'action' : '');

                    if ($target_uri_l === '' && $tp === '') {
                        continue;
                    }

                    $norm_rest_q = $rest_query !== '' ? '/wp-json/' . ltrim($rest_query, '/') : '';
                    $uri_match   = ($target_uri_l === '')
                        || str_contains($clean_uri, $target_uri_l)
                        || ($rest_query !== '' && (str_contains($rest_query, $target_uri_l) || str_contains($norm_rest_q, $target_uri_l)));
                    $method_match = empty($methods) || in_array($method, $methods, true);
                    $param_match  = true;

                    if ($tp !== '') {
                        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch custom Modular WAF rule inspection
                        $pv = isset($_REQUEST[$tp]) && is_string($_REQUEST[$tp]) ? strtolower(trim(sanitize_text_field(wp_unslash($_REQUEST[$tp])))) : '';
                        if ($pv === '' && is_array($raw_json_data) && isset($raw_json_data[$tp])) {
                            $pv = strtolower(trim(sanitize_text_field((string) $raw_json_data[$tp])));
                        }
                        $param_match = !empty($r['target_value'])
                            ? ($pv === strtolower(trim((string) $r['target_value'])))
                            : ($pv !== '');
                    }
                    $matched_custom = ($uri_match && $method_match && $param_match);
                }

                if ($matched_custom) {
                    $act = (string) ($r['action_type'] ?? '');
                    if ($act === '') {
                        $lim = intval($r['rate_limit'] ?? 0);
                        $act = (!empty($r['immediate_block']) || $lim <= 0) ? 'block' : 'rate_limit';
                    }

                    if ($act === 'allow') {
                        $ex = is_array($r['exempt_rules'] ?? null) ? $r['exempt_rules'] : [];
                        if (empty($ex)) {
                            if ($mode === 'enforce' && !$is_rescue_paused) {
                                return [
                                    'rule_id'      => $r['id'],
                                    'category'     => $r['category'] ?? 'custom',
                                    'action_type'  => 'allow',
                                    'blocked'      => false,
                                    'reason'       => sprintf('Allowed by Custom Firewall Rule "%1$s" [%2$s].', (string) ($r['title'] ?? $r['id']), $r['id']),
                                    'severity'     => 'info',
                                    'exempt_rules' => [],
                                ];
                            }
                            return self::build_violation(
                                $r,
                                sprintf('Dry-run Allow match for Custom Firewall Rule "%1$s" [%2$s].', (string) ($r['title'] ?? $r['id']), $r['id']),
                                false,
                                'info'
                            );
                        } else {
                            $exempt_ids = array_values(array_unique(array_merge($exempt_ids, $ex)));
                        }
                        continue;
                    }

                    if ($act === 'monitor') {
                        return self::build_violation(
                            $r,
                            sprintf('Monitored request matched Custom Firewall Rule "%1$s" [%2$s].', (string) ($r['title'] ?? $r['id']), $r['id']),
                            false,
                            'medium'
                        );
                    }

                    if ($act === 'challenge_pow') {
                        return self::build_violation(
                            $r,
                            sprintf('WebCrypto PoW challenge required by Custom Firewall Rule "%1$s" [%2$s].', (string) ($r['title'] ?? $r['id']), $r['id']),
                            $should_block,
                            'medium'
                        );
                    }

                    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch upload inspection for custom modular rule
                    if (!empty($r['block_uploads']) && !empty($_FILES)) {
                        return self::build_violation(
                            $r,
                            sprintf('File upload blocked on protected custom endpoint [%s].', $r['id']),
                            $should_block
                        );
                    }
                    // Pre-dispatch payload inspection for custom modular rule (inspects $_REQUEST, JSON input body, and $_FILES)
                    if ($has_malicious_payload) {
                        return self::build_violation(
                            $r,
                            sprintf('Suspicious payload blocked by custom Modular WAF Rule [%s].', $r['id']),
                            $should_block
                        );
                    }
                    $limit = intval($r['rate_limit'] ?? 0);
                    if (in_array($act, ['block', 'block_and_ban'], true) || !empty($r['immediate_block']) || ($act === 'rate_limit' && $limit <= 0)) {
                        return self::build_violation(
                            $r,
                            sprintf('Blocked by Custom Modular WAF Rule "%1$s" [%2$s].', (string) ($r['title'] ?? $r['id']), $r['id']),
                            $should_block
                        );
                    }
                    if ($act === 'rate_limit' && $limit > 0 && self::is_modular_rate_limited($r['id'], $ip, $limit)) {
                        return self::build_violation(
                            $r,
                            sprintf('Rate limit (%1$d req/min) exceeded on custom protected endpoint [%2$s].', $limit, $r['id']),
                            $should_block
                        );
                    }
                }
                continue;
            }

            // Category 1: abspath_lock / tamper_guard (Direct HTTP request to standalone or checksum-modified PHP script)
            if (in_array($cat, ['abspath_lock', 'tamper_guard'], true) && !empty($r['target_uri'])) {
                $target_suffix = strtolower(ltrim((string) $r['target_uri'], '/\\'));
                if ($target_suffix !== '' && str_ends_with($clean_uri, $target_suffix)) {
                    return self::build_violation(
                        $r,
                        ($cat === 'tamper_guard')
                            ? sprintf('Direct HTTP access to checksum-flagged script "%s" blocked by Modular WAF Rule [%s].', basename($target_suffix), $r['id'])
                            : sprintf('Direct HTTP access to standalone script "%s" blocked by Modular WAF Rule [%s].', basename($target_suffix), $r['id']),
                        $should_block
                    );
                }
            }

            // Category 2: ajax_shield (Targeted guest AJAX action — exempt logged-in users)
            if ($cat === 'ajax_shield' && !$is_logged_in && !empty($r['target_value'])) {
                if (str_contains($clean_uri, 'admin-ajax.php') && $req_action !== '' && $req_action === strtolower((string) $r['target_value'])) {
                    // A. Block unauthorized multipart file uploads on guest AJAX
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Runtime WAF inspection blocking multipart uploads on unprotected guest AJAX actions
                    if (!empty($r['block_uploads']) && !empty($_FILES)) {
                        return self::build_violation(
                            $r,
                            sprintf('File upload prohibited on guest AJAX action "%s" by Modular WAF Rule [%s].', $req_action, $r['id']),
                            ($should_block || ($is_smart && !$is_rescue_paused)),
                            'critical'
                        );
                    }

                    // B. Inspect parameters for SQLi / XSS / Privilege Escalation payloads on unprotected guest AJAX
                    if ($has_malicious_payload) {
                        return self::build_violation(
                            $r,
                            sprintf('Malicious SQLi/XSS/PrivEsc payload intercepted on unprotected guest AJAX action "%s" [%s].', $req_action, $r['id']),
                            ($should_block || ($is_smart && !$is_rescue_paused)),
                            'critical'
                        );
                    }

                    // C. Enforce per-IP velocity rate limit if configured
                    $limit = intval($r['rate_limit'] ?? 0);
                    if ($limit > 0 && self::is_modular_rate_limited($r['id'], $ip, $limit)) {
                        return self::build_violation(
                            $r,
                            sprintf('Rate limit (%d req/min) exceeded on guest AJAX action "%s" [%s].', $limit, $req_action, $r['id']),
                            ($should_block || ($is_smart && !$is_rescue_paused)),
                            'high'
                        );
                    }

                    if ($is_smart) {
                        self::record_autopilot_benign_hit($r['id']);
                    }
                }
            }

            // Category 3: rest_guard (Permissive REST route guard — exempt logged-in users)
            if ($cat === 'rest_guard' && !$is_logged_in && !empty($r['target_uri'])) {
                $target_route = strtolower(rtrim((string) $r['target_uri'], '/'));
                if (($target_route !== '' && str_contains($clean_uri, '/wp-json' . $target_route)) || ($rest_query !== '' && str_starts_with($rest_query, $target_route))) {
                    if (empty($methods) || in_array($method, $methods, true)) {
                        if ($is_smart) {
                            // In 48h Smart Learning mode, permit clean requests while enforcing SQLi/XSS & rate limits
                            if ($has_malicious_payload) {
                                return self::build_violation(
                                    $r,
                                    sprintf('Malicious payload intercepted on REST route "%s" [%s].', $target_route, $r['id']),
                                    !$is_rescue_paused,
                                    'critical'
                                );
                            }
                            $limit = intval($r['rate_limit'] ?? 0);
                            if ($limit > 0 && self::is_modular_rate_limited($r['id'], $ip, $limit)) {
                                return self::build_violation(
                                    $r,
                                    sprintf('Rate limit (%d req/min) exceeded on REST route "%s" [%s].', $limit, $target_route, $r['id']),
                                    !$is_rescue_paused,
                                    'high'
                                );
                            }
                            self::record_autopilot_benign_hit($r['id']);
                        } else {
                            return self::build_violation(
                                $r,
                                sprintf('Unauthenticated %s mutation on permissive REST route "%s" blocked by Modular WAF Rule [%s].', $method, $target_route, $r['id']),
                                $should_block
                            );
                        }
                    }
                }
            }

            // Category 4: upload_guard (Inspect multipart $_FILES for executable extensions / PHP tags across all dimensions)
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Runtime WAF inspection auditing uploaded file metadata & headers
            if ($cat === 'upload_guard' && !empty($_FILES)) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Runtime WAF inspection of incoming $_FILES payload
                $flat_files = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Runtime WAF inspection of incoming $_FILES payload
                    ? \WebCareProScanner\Firewall\FirewallEngine::flatten_uploaded_files($_FILES)
                    : [];
                if (empty($flat_files)) {
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Runtime WAF inspection of incoming $_FILES payload
                    foreach ($_FILES as $file_item) {
                        $names   = is_array($file_item['name'] ?? null) ? $file_item['name'] : [($file_item['name'] ?? '')];
                        $tmp_arr = is_array($file_item['tmp_name'] ?? null) ? $file_item['tmp_name'] : [($file_item['tmp_name'] ?? '')];
                        foreach ($names as $idx => $fname) {
                            $flat_files[] = [
                                'name'     => (string) $fname,
                                'tmp_name' => (string) ($tmp_arr[$idx] ?? ''),
                            ];
                        }
                    }
                }

                foreach ($flat_files as $f_item) {
                    $fname   = (string) ($f_item['name'] ?? '');
                    $fname_l = strtolower($fname);
                    if ($fname_l !== '' && preg_match('/\.(?:php\d*|phtml|phar|pgif|htaccess|user\.ini|sh|pl|py|cgi|asp|aspx)\b/i', $fname_l)) {
                        return self::build_violation(
                            $r,
                            sprintf('Dangerous executable upload filename "%s" blocked by Modular Upload Guard [%s].', sanitize_file_name($fname), $r['id']),
                            $should_block,
                            'critical'
                        );
                    }
                    $tmp_f = (string) ($f_item['tmp_name'] ?? '');
                    if ($tmp_f !== '' && is_uploaded_file($tmp_f)) {
                        $head = (string) @file_get_contents($tmp_f, false, null, 0, 4096);
                        if (preg_match('/<\?(?:php|=)|__HALT_COMPILER\s*\(\s*\)/i', $head)) {
                            return self::build_violation(
                                $r,
                                sprintf('Embedded PHP/PHAR payload inside uploaded file "%s" blocked by Modular Upload Guard [%s].', sanitize_file_name($fname), $r['id']),
                                $should_block,
                                'critical'
                            );
                        }
                    }
                }
            }

            // Category 5: egress_lock (SSRF parameter inspection for internal/metadata targets across query, POST & JSON body)
            if ($cat === 'egress_lock' && !empty($r['target_param'])) {
                $param_keys = array_filter(array_map('trim', explode(',', strtolower((string) $r['target_param']))));
                foreach ($param_keys as $pk) {
                    $val = '';
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch SSRF inspection on untrusted URL query/body parameters
                    if (isset($_REQUEST[$pk]) && is_string($_REQUEST[$pk])) {
                        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch SSRF inspection on untrusted URL query/body parameters
                        $val = strtolower(trim(sanitize_text_field(wp_unslash($_REQUEST[$pk]))));
                    } elseif (is_array($raw_json_data) && isset($raw_json_data[$pk]) && is_string($raw_json_data[$pk])) {
                        $val = strtolower(trim(sanitize_text_field((string) $raw_json_data[$pk])));
                    }
                    if ($val !== '' && preg_match('#^(?:file|gopher|dict|ftp|ldap|tftp)://|(?:\b169\.254\.169\.254\b|\b127\.\d+\.\d+\.\d+\b|\blocalhost\b|\b0\.0\.0\.0\b|\[::1\]|\bmetadata\.google\.internal\b)#i', $val)) {
                        return self::build_violation(
                            $r,
                            sprintf('SSRF target in parameter "%s" blocked by Modular Egress Lock [%s].', $pk, $r['id']),
                            $should_block,
                            'critical'
                        );
                    }
                }
            }

            // Category 7: cve_patch (MOD-CVE-* Virtual Shield targeting outdated / vulnerable component slugs)
            if ($cat === 'cve_patch' && !$is_logged_in) {
                $slug_lc   = strtolower(str_replace('-', '_', (string) ($r['component_slug'] ?? ($r['target_uri'] ?? ''))));
                $slug_dash = strtolower((string) ($r['component_slug'] ?? ($r['target_uri'] ?? '')));
                $hits_comp = ($slug_dash !== '' && (str_contains($clean_uri, $slug_dash) || ($rest_query !== '' && str_contains($rest_query, $slug_dash))))
                    || ($slug_lc !== '' && $req_action !== '' && str_contains($req_action, $slug_lc));

                if ($hits_comp) {
                    // Check upload of executable PHP scripts + common CVE exploit payloads (LFI, SQLi, PHP Object Injection)
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch virtual CVE shield auditing incoming file uploads
                    if (!empty($_FILES)) {
                        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-dispatch virtual CVE shield auditing uploaded filename extensions
                        foreach ($_FILES as $file_item) {
                            $names = is_array($file_item['name'] ?? null) ? $file_item['name'] : [($file_item['name'] ?? '')];
                            foreach ($names as $fname) {
                                if (preg_match('/\.(?:php\d*|phtml|phar|sh|pl|py|cgi)\b/i', (string) $fname)) {
                                    return self::build_violation(
                                        $r,
                                        sprintf('Exploit upload targeting component "%s" blocked by Virtual CVE Shield [%s].', $slug_dash, $r['id']),
                                        $should_block,
                                        'critical'
                                    );
                                }
                            }
                        }
                    }

                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-dispatch virtual CVE shield inspecting SQLi/LFI/Object-Injection vectors
                    $raw_payload = wp_json_encode($_REQUEST) ?: '';
                    if (preg_match('/(?:\.\.\/|\.\.\\\\|%2e%2e|O:\d+:"[a-zA-Z0-9_\\\\]+"\s*:|\bunion\s+all\s+select\b|sleep\s*\(\s*\d+\s*\)|<script\b|wp_capabilities)/i', $raw_payload)) {
                        return self::build_violation(
                            $r,
                            sprintf('Vulnerability exploit vector targeting outdated/vulnerable component "%s" blocked by Virtual CVE Shield [%s].', $slug_dash, $r['id']),
                            $should_block,
                            'critical'
                        );
                    }

                    $limit = intval($r['rate_limit'] ?? 0);
                    if ($limit > 0 && self::is_modular_rate_limited($r['id'], $ip, $limit)) {
                        return self::build_violation(
                            $r,
                            sprintf('Excessive automated probing (%d req/min) on vulnerable component "%s" throttled by [%s].', $limit, $slug_dash, $r['id']),
                            $should_block,
                            'high'
                        );
                    }
                }
            }
        }

        return null;
    }

    /**
     * Lightweight 60-second sliding counter for Modular WAF rule rate limits.
     */
    private static function is_modular_rate_limited(string $rule_id, string $ip, int $limit_per_min): bool {
        $key   = 'wcp_mod_rl_' . substr(md5($rule_id . '|' . $ip), 0, 16);
        $count = (int) get_transient($key);
        if ($count >= $limit_per_min) {
            return true;
        }
        set_transient($key, $count + 1, 60);
        return false;
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

        $category     = isset($data['category']) ? sanitize_key($data['category']) : 'custom';
        $incoming_id  = isset($data['id']) ? sanitize_text_field(wp_unslash((string) $data['id'])) : '';
        $rules        = self::get_active_rules();
        $edit_index   = null;
        $existing_ts  = time();
        $existing_num = 0;
        $existing_pri = 0;

        if ($incoming_id !== '') {
            foreach ($rules as $idx => $existing_rule) {
                if (($existing_rule['id'] ?? '') === $incoming_id && !empty($existing_rule['is_custom'])) {
                    $edit_index   = $idx;
                    $existing_ts  = (int) ($existing_rule['synthesized_at'] ?? time());
                    $existing_num = (int) ($existing_rule['rule_number'] ?? 0);
                    $existing_pri = (int) ($existing_rule['priority'] ?? 0);
                    break;
                }
            }
            if ($edit_index === null) {
                return [
                    'success' => false,
                    'message' => __('Editable custom rule not found.', 'webcare-pro-security'),
                ];
            }
        }

        $rule_id      = ($edit_index !== null) ? $incoming_id : ('MOD-CUSTOM-' . strtoupper(wp_generate_password(6, false, false)));
        $rule_number  = ($existing_num > 0) ? $existing_num : self::allocate_custom_rule_number($rules);
        $raw_mode     = isset($data['current_mode']) ? sanitize_key($data['current_mode']) : 'enforce';
        $valid_actions = ['block', 'block_and_ban', 'rate_limit', 'payload_inspect', 'challenge_pow', 'monitor', 'allow'];
        $rate_limit   = max(0, intval($data['rate_limit'] ?? 0));
        $raw_action   = isset($data['action_type']) ? sanitize_key((string) $data['action_type']) : '';
        if (!in_array($raw_action, $valid_actions, true)) {
            $raw_action = ($raw_mode === 'monitor')
                ? 'monitor'
                : ((!empty($data['immediate_block']) || $rate_limit <= 0) ? 'block' : 'rate_limit');
        }
        if ($raw_action === 'monitor') {
            $raw_mode = 'monitor';
        }

        $group_logic = strtoupper(trim((string) ($data['group_logic'] ?? 'OR'))) === 'AND' ? 'AND' : 'OR';
        $conditions  = [];
        if (class_exists(VisualRuleExpressionEngine::class)) {
            if (!empty($data['conditions']) && is_array($data['conditions'])) {
                $conditions = VisualRuleExpressionEngine::sanitize_condition_groups($data['conditions']);
            } elseif (!empty($data['wirefilter_expr']) && is_string($data['wirefilter_expr'])) {
                $parsed      = VisualRuleExpressionEngine::parse_wirefilter_tree(sanitize_text_field(wp_unslash($data['wirefilter_expr'])));
                $conditions  = $parsed['conditions'];
                $group_logic = $parsed['group_logic'];
            }
        }
        $wirefilter_expr = class_exists(VisualRuleExpressionEngine::class) && !empty($conditions)
            ? VisualRuleExpressionEngine::to_wirefilter($conditions, $group_logic)
            : (isset($data['wirefilter_expr']) ? sanitize_text_field(wp_unslash($data['wirefilter_expr'])) : '');

        $immediate = !empty($data['immediate_block'])
            || in_array($raw_action, ['block', 'block_and_ban'], true)
            || ($raw_action === 'rate_limit' && $rate_limit <= 0);
        $sync_cf   = !empty($data['sync_cloudflare']);
        $ban_ttl   = isset($data['ban_ttl'])
            ? max(0, min(2592000, intval($data['ban_ttl'])))
            : (($sync_cf || $raw_action === 'block_and_ban') ? 86400 : 0);
        if ($raw_action === 'block_and_ban' && $ban_ttl <= 0) {
            $ban_ttl = 86400;
        }

        $target_val   = isset($data['target_value']) ? sanitize_text_field(wp_unslash($data['target_value'])) : '';
        $target_param = isset($data['target_param']) ? sanitize_key($data['target_param']) : '';
        if ($target_param === '' && $category === 'ajax_shield' && $target_val !== '') {
            $target_param = 'action';
        }
        $methods = is_array($data['http_methods'] ?? null)
            ? array_values(array_filter(array_map(static fn($m) => strtoupper(sanitize_text_field((string) $m)), $data['http_methods'])))
            : ['POST', 'GET'];
        $exempt_rules = is_array($data['exempt_rules'] ?? null)
            ? array_values(array_filter(array_map('sanitize_text_field', $data['exempt_rules'])))
            : [];

        $rule = [
            'id'               => $rule_id,
            'rule_number'      => $rule_number,
            'priority'         => $existing_pri > 0 ? $existing_pri : 1,
            'category'         => $category,
            'action_type'      => $raw_action,
            'title'            => $title,
            'description'      => isset($data['description']) ? sanitize_textarea_field(wp_unslash($data['description'])) : '',
            'origin_component' => !empty($conditions) ? 'Custom Firewall Rules' : 'Custom User Rule',
            'file'             => '',
            'line'             => 0,
            'evidence'         => !empty($wirefilter_expr) ? $wirefilter_expr : __('Developer-defined custom modular protection rule.', 'webcare-pro-security'),
            'severity'         => isset($data['severity']) ? sanitize_key($data['severity']) : 'high',
            'recommended_mode' => 'enforce',
            'current_mode'     => in_array($raw_mode, ['enforce', 'smart_learning', 'monitor', 'off'], true) ? $raw_mode : 'enforce',
            'target_uri'       => isset($data['target_uri']) ? sanitize_text_field(wp_unslash($data['target_uri'])) : '',
            'target_param'     => $target_param,
            'target_value'     => $target_val,
            'http_methods'     => $methods,
            'rate_limit'       => $rate_limit,
            'immediate_block'  => $immediate,
            'ban_ttl'          => $ban_ttl,
            'block_uploads'    => !empty($data['block_uploads']),
            'sync_cloudflare'  => $sync_cf,
            'group_logic'      => $group_logic,
            'conditions'       => $conditions,
            'wirefilter_expr'  => $wirefilter_expr,
            'exempt_rules'     => $exempt_rules,
            'is_custom'        => true,
            'synthesized_at'   => $existing_ts,
            'updated_at'       => time(),
        ];

        // Position custom rule according to Cloudflare-style placement selector ('first' | 'last' | 'custom')
        $placement      = sanitize_key((string) ($data['placement'] ?? ($edit_index !== null ? 'keep' : 'last')));
        $order_position = isset($data['order_position']) ? max(1, intval($data['order_position'])) : 0;

        $custom_list   = [];
        $baseline_list = [];
        foreach ($rules as $existing_r) {
            if (($existing_r['id'] ?? '') === $rule_id && $edit_index !== null) {
                continue;
            }
            if (!empty($existing_r['is_custom']) || ($existing_r['category'] ?? '') === 'custom') {
                $custom_list[] = $existing_r;
            } else {
                $baseline_list[] = $existing_r;
            }
        }

        if ($placement === 'first') {
            array_unshift($custom_list, $rule);
        } elseif ($placement === 'custom' && $order_position > 0) {
            $insert_idx = min(count($custom_list), max(0, $order_position - 1));
            array_splice($custom_list, $insert_idx, 0, [$rule]);
        } elseif ($placement === 'keep' && $existing_pri > 0) {
            $insert_idx = min(count($custom_list), max(0, $existing_pri - 1));
            array_splice($custom_list, $insert_idx, 0, [$rule]);
        } else {
            $custom_list[] = $rule;
        }

        foreach ($custom_list as $p_idx => &$c_item) {
            $c_item['priority'] = $p_idx + 1;
        }
        unset($c_item);
        $rule['priority'] = 1;
        foreach ($custom_list as $c_item) {
            if (($c_item['id'] ?? '') === $rule_id) {
                $rule['priority'] = (int) ($c_item['priority'] ?? 1);
                break;
            }
        }

        self::save_rules(array_merge($custom_list, $baseline_list));

        return [
            'success' => true,
            'updated' => ($edit_index !== null),
            'message' => ($edit_index !== null)
                ? sprintf(
                    /* translators: 1: numeric rule ID, 2: rule code, 3: order position */
                    __('Custom rule ID #%1$d (%2$s) updated at Order #%3$d.', 'webcare-pro-security'),
                    $rule_number,
                    $rule_id,
                    $rule['priority']
                )
                : sprintf(
                    /* translators: 1: numeric rule ID, 2: rule code, 3: order position */
                    __('Custom rule ID #%1$d (%2$s) created at Order #%3$d.', 'webcare-pro-security'),
                    $rule_number,
                    $rule_id,
                    $rule['priority']
                ),
            'rule'    => $rule,
        ];
    }

    /**
     * Reorder custom modular firewall rules in explicit execution priority sequence and recompile Micro-WAF.
     *
     * @param string[] $ordered_ids Ordered list of custom rule IDs (highest priority first)
     * @return array
     */
    public static function reorder_custom_rules(array $ordered_ids): array {
        $clean_ids = array_values(array_unique(array_filter(array_map('sanitize_text_field', $ordered_ids))));
        $rules     = self::get_active_rules();

        $custom_by_id = [];
        $baseline     = [];
        foreach ($rules as $r) {
            if (!is_array($r)) {
                continue;
            }
            if (!empty($r['is_custom']) || ($r['category'] ?? '') === 'custom') {
                $custom_by_id[(string) ($r['id'] ?? '')] = $r;
            } else {
                $baseline[] = $r;
            }
        }

        $reordered = [];
        foreach ($clean_ids as $cid) {
            if (isset($custom_by_id[$cid])) {
                $reordered[] = $custom_by_id[$cid];
                unset($custom_by_id[$cid]);
            }
        }
        // Preserve any custom rules not included in the client payload cleanly at the tail
        foreach ($custom_by_id as $remaining_rule) {
            $reordered[] = $remaining_rule;
        }

        foreach ($reordered as $idx => &$cr) {
            $cr['priority']   = $idx + 1;
            $cr['updated_at'] = time();
        }
        unset($cr);

        $merged = array_merge($reordered, $baseline);
        self::save_rules($merged);

        return [
            'success'      => true,
            'message'      => sprintf(
                /* translators: %d: number of custom rules ordered */
                __('Saved execution priority order for %d custom firewall rule(s) and recompiled Pre-Boot Micro-WAF.', 'webcare-pro-security'),
                count($reordered)
            ),
            'custom_count' => count($reordered),
            'rules'        => self::get_active_rules(),
        ];
    }

    /**
     * Delete a developer-defined custom modular firewall rule.
     *
     * @param string $rule_id
     * @return array
     */
    public static function delete_custom_rule(string $rule_id): array {
        $rule_id = sanitize_text_field($rule_id);
        $rules   = self::get_active_rules();
        $before  = count($rules);
        $filtered = array_values(array_filter($rules, static function ($r) use ($rule_id) {
            return !(($r['id'] ?? '') === $rule_id && !empty($r['is_custom']));
        }));

        if (count($filtered) === $before) {
            return [
                'success' => false,
                'message' => __('Custom rule not found or cannot be deleted.', 'webcare-pro-security'),
            ];
        }

        self::save_rules($filtered);
        return [
            'success' => true,
            'message' => sprintf(
                /* translators: %s: rule ID */
                __('Custom rule "%s" deleted cleanly.', 'webcare-pro-security'),
                $rule_id
            ),
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
            if (!file_exists($cand_norm) || !is_file($cand_norm)) {
                continue;
            }
            $real = realpath($cand_norm);
            if ($real === false) {
                continue;
            }
            $real_norm = wp_normalize_path($real);
            $in_root   = class_exists('\\WebCareProScanner\\Filesystem\\PathValidator')
                ? (\WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_norm, WP_CONTENT_DIR, true)
                    || \WebCareProScanner\Filesystem\PathValidator::is_inside_root($real_norm, ABSPATH, true))
                : (str_starts_with($real_norm, rtrim($wp_content_norm, '/') . '/') || str_starts_with($real_norm, rtrim($abspath_norm, '/') . '/'));

            if (!$in_root) {
                continue;
            }

            $real_base = strtolower(basename($real_norm));
            if (
                in_array($real_base, ['wp-config.php', 'wp-config-sample.php', '.htaccess', '.htpasswd', '.user.ini', '.env'], true)
                || str_starts_with($real_base, '.env.')
            ) {
                return [
                    'success' => false,
                    'message' => __('Access to sensitive configuration files is strictly restricted.', 'webcare-pro-security'),
                ];
            }

            $resolved_path = $real_norm;
            break;
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

    /**
     * Normalize an AJAX action token while preserving namespaced path slashes (e.g. "acf/fields/select/query").
     */
    private static function normalize_action_token(string $raw): string {
        $clean = strtolower(sanitize_text_field($raw));
        $norm  = preg_replace('/[^a-z0-9_\-\/]/', '', $clean);
        return is_string($norm) ? trim($norm, '/') : '';
    }

    /**
     * Determine whether a finding carries an integrity tamper status.
     */
    private static function is_tampered_finding(array $finding): bool {
        return in_array($finding['checksum_status'] ?? '', ['modified', 'unknown_in_official', 'self_modified', 'self_untracked'], true);
    }

    /**
     * Determine whether a finding belongs to an untampered official WordPress.org component or known vendor.
     */
    private static function is_verified_non_tampered_finding(array $finding): bool {
        if (self::is_tampered_finding($finding)) {
            return false;
        }
        if (!empty($finding['is_known_vendor'])) {
            return true;
        }
        $chk = $finding['checksum_status'] ?? '';
        if ($chk === 'self_verified') {
            return true;
        }
        return !empty($finding['is_official_wporg']) && in_array($chk, ['authentic', 'self_verified'], true);
    }
}
