<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Cloudflare\CloudflareService;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Origin Load Circuit Breaker (CAF Phase 2)
 *
 * Real-world cPanel / shared hosting survival mode against 508 Resource Limit crashes:
 * - Monitors CPU load (`sys_getloadavg()`), memory consumption, and 60-second probe velocity.
 * - Detects origin distress (> 4.0 load average or > 120 bad requests/min).
 * - Escalate: Triggers Cloudflare "Under Attack Mode" or shifts WebCare Edge rules to Managed Challenge.
 * - Deescalate: Automatically restores normal baseline when origin metrics remain healthy for 10 minutes.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class OriginLoadCircuitBreaker {

    public const OPTION_STATE             = 'webcare_origin_survival_state';
    public const CPU_THRESHOLD            = 4.0;
    public const PROBE_VELOCITY_THRESHOLD = 120; // 403/404 per minute
    public const RECOVERY_WINDOW_SECONDS  = 600; // 10 minutes

    /**
     * Record a blocked request in the 60-second rolling window counter.
     */
    public static function record_blocked_probe(): void {
        $now    = time();
        $bucket = get_transient('webcare_waf_60s_bucket');
        if (!is_array($bucket) || empty($bucket['window_start']) || ($now - (int) $bucket['window_start']) >= 60) {
            $bucket = ['window_start' => $now, 'count' => 1];
        } else {
            $bucket['count'] = ((int) ($bucket['count'] ?? 0)) + 1;
        }
        set_transient('webcare_waf_60s_bucket', $bucket, 60);
        set_transient('webcare_waf_probe_velocity_60s', (int) $bucket['count'], 60);
    }

    /**
     * Detect available CPU core count (defaults to 2 on restricted shared hosting).
     */
    private function detect_cpu_cores(): int {
        static $cores = null;
        if ($cores !== null) {
            return $cores;
        }
        if (@is_readable('/proc/cpuinfo')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            $cpuinfo = (string) @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo !== '' && preg_match_all('/^processor\s*:/m', $cpuinfo, $m)) {
                $cores = max(1, count($m[0]));
                return $cores;
            }
        }
        $cores = 2;
        return $cores;
    }

    /**
     * Sample CPU load, memory usage, and 60-second probe velocity.
     *
     * @return array
     */
    public function check_resource_stress(): array {
        $cpu_load = 0.0;
        if (function_exists('sys_getloadavg')) {
            $loads = @sys_getloadavg();
            if (is_array($loads) && isset($loads[0])) {
                $cpu_load = (float) $loads[0];
            }
        }

        $cores = $this->detect_cpu_cores();
        $effective_cpu_threshold = max(self::CPU_THRESHOLD, round($cores * 1.5, 2));

        $memory_usage = memory_get_usage(true);
        $memory_peak  = memory_get_peak_usage(true);
        $memory_limit = (string) ini_get('memory_limit');
        $limit_bytes  = function_exists('wp_convert_hr_to_bytes') ? wp_convert_hr_to_bytes($memory_limit) : 0;
        $memory_ratio = ($limit_bytes > 0) ? round($memory_usage / $limit_bytes, 4) : 0.0;

        // Real 60-second rolling probe velocity only (never divide 24h totals by 60 — OS-01)
        $bucket = get_transient('webcare_waf_60s_bucket');
        $probe_velocity = 0;
        if (is_array($bucket) && !empty($bucket['window_start']) && (time() - (int) $bucket['window_start']) < 60) {
            $probe_velocity = (int) ($bucket['count'] ?? 0);
        } else {
            $probe_velocity = (int) get_transient('webcare_waf_probe_velocity_60s');
        }

        $is_stressed = ($cpu_load >= $effective_cpu_threshold)
            || ($probe_velocity >= self::PROBE_VELOCITY_THRESHOLD)
            || ($memory_ratio >= 0.90 && $probe_velocity >= 40);

        return [
            'cpu_load'               => round($cpu_load, 2),
            'cpu_cores'              => $cores,
            'cpu_threshold'          => $effective_cpu_threshold,
            'probe_velocity_per_min' => $probe_velocity,
            'velocity_threshold'     => self::PROBE_VELOCITY_THRESHOLD,
            'memory_usage_bytes'     => $memory_usage,
            'memory_peak_bytes'      => $memory_peak,
            'memory_limit'           => $memory_limit,
            'memory_ratio'           => $memory_ratio,
            'is_stressed'            => $is_stressed,
            'timestamp'              => time(),
        ];
    }

    /**
     * Check if origin server is currently under stress.
     *
     * @return bool
     */
    public function is_origin_under_stress(): bool {
        $stress = $this->check_resource_stress();
        return (bool) ($stress['is_stressed'] ?? false);
    }

    /**
     * Check whether Origin Survival Mode is currently engaged.
     *
     * @return bool
     */
    public function is_survival_mode_active(): bool {
        $state = get_option(self::OPTION_STATE, []);
        return !empty($state['active']);
    }

    /**
     * Get current survival state dossier.
     *
     * @return array
     */
    public function get_state(): array {
        $state = get_option(self::OPTION_STATE, []);
        $stress = $this->check_resource_stress();

        return [
            'active'       => !empty($state['active']),
            'engaged_at'   => $state['engaged_at'] ?? null,
            'reason'       => $state['reason'] ?? '',
            'escalation'   => $state['escalation_type'] ?? 'none',
            'stress'       => $stress,
            'auto_managed' => !empty($state['auto_managed']),
        ];
    }

    /**
     * Escalate edge defense via Cloudflare to offload origin CPU and bad requests.
     *
     * @param string $zone_id Cloudflare Zone ID
     * @param string $reason Escalation trigger reason
     * @param bool $auto_managed Whether triggered by auto-monitor vs admin manual click
     * @return bool
     */
    public function escalate_edge_defense(string $zone_id, string $reason = 'Origin Resource Saturation', bool $auto_managed = true): bool {
        if (empty($zone_id)) {
            $settings = SettingsManager::get_settings();
            $zone_id  = $settings['cloudflare_zone_id'] ?? '';
        }

        if (empty($zone_id)) {
            return false;
        }

        // Snapshot prior security_level before changing it (OS-03)
        $existing_state = get_option(self::OPTION_STATE, []);
        $prior_level    = (string) ($existing_state['prior_security_level'] ?? '');
        if ($prior_level === '' || $prior_level === 'under_attack') {
            $cur_res = CloudflareService::request("zones/{$zone_id}/settings/security_level", 'GET');
            $fetched = (string) ($cur_res['result']['value'] ?? 'medium');
            $prior_level = ($fetched !== '' && $fetched !== 'under_attack') ? $fetched : 'medium';
        }

        // 1. Escalate Cloudflare Security Level to 'under_attack'
        $cf_res = CloudflareService::request(
            "zones/{$zone_id}/settings/security_level",
            'PATCH',
            ['value' => 'under_attack']
        );
        $patch_ok = !empty($cf_res['success']);

        // 2. Also re-pack CAF Cloudflare slots with origin_survival_active = true
        $optimizer = new CloudflareSlotOptimizer();
        $slot_res  = $optimizer->deploy_to_cloudflare($zone_id, null, [], true);
        $slot_ok   = !empty($slot_res['success']);

        if (!$patch_ok && !$slot_ok) {
            return false;
        }

        $escalation_type = $patch_ok ? 'under_attack' : 'slot_repack';

        // 3. Persist survival state only after confirmed edge action
        update_option(self::OPTION_STATE, [
            'active'               => true,
            'engaged_at'           => time(),
            'healthy_since'        => null,
            'reason'               => sanitize_text_field($reason),
            'escalation_type'      => $escalation_type,
            'prior_security_level' => $prior_level,
            'auto_managed'         => $auto_managed,
        ]);

        return true;
    }

    /**
     * Deescalate edge defense back to normal baseline.
     *
     * @param string $zone_id Cloudflare Zone ID
     * @return bool
     */
    public function deescalate_edge_defense(string $zone_id): bool {
        if (empty($zone_id)) {
            $settings = SettingsManager::get_settings();
            $zone_id  = $settings['cloudflare_zone_id'] ?? '';
        }

        if (empty($zone_id)) {
            return false;
        }

        $state       = get_option(self::OPTION_STATE, []);
        $prior_level = (string) ($state['prior_security_level'] ?? 'medium');
        if (!in_array($prior_level, ['essentially_off', 'low', 'medium', 'high'], true)) {
            $prior_level = 'medium';
        }

        $patch_ok = true;
        if (($state['escalation_type'] ?? 'under_attack') === 'under_attack') {
            $cf_res   = CloudflareService::request(
                "zones/{$zone_id}/settings/security_level",
                'PATCH',
                ['value' => $prior_level]
            );
            $patch_ok = !empty($cf_res['success']);
        }

        $optimizer = new CloudflareSlotOptimizer();
        $slot_res  = $optimizer->deploy_to_cloudflare($zone_id, null, [], false);
        $slot_ok   = !empty($slot_res['success']);

        if (!$patch_ok && !$slot_ok) {
            return false;
        }

        update_option(self::OPTION_STATE, [
            'active'               => false,
            'engaged_at'           => null,
            'healthy_since'        => time(),
            'reason'               => 'Normal operating thresholds restored.',
            'escalation_type'      => 'none',
            'prior_security_level' => $prior_level,
            'auto_managed'         => false,
        ]);

        return true;
    }

    /**
     * Evaluate health status during periodic cron; auto-escalate or auto-deescalate.
     *
     * @param string $zone_id Cloudflare Zone ID
     */
    public function evaluate_auto_survival(string $zone_id): void {
        $state = get_option(self::OPTION_STATE, []);
        $is_active = !empty($state['active']);
        $stress = $this->check_resource_stress();

        if ($stress['is_stressed']) {
            if (!$is_active) {
                // Trigger auto-escalation
                $reason = sprintf(
                    'Origin load spike detected: CPU %s (limit %s), Velocity %d/min.',
                    $stress['cpu_load'],
                    $stress['cpu_threshold'],
                    $stress['probe_velocity_per_min']
                );
                $this->escalate_edge_defense($zone_id, $reason, true);
            } else {
                // Still stressed, reset healthy timer
                if (!empty($state['healthy_since'])) {
                    $state['healthy_since'] = null;
                    update_option(self::OPTION_STATE, $state, false);
                }
            }
        } else {
            // Server is healthy
            if ($is_active && !empty($state['auto_managed'])) {
                $now = time();
                $healthy_since = (int) ($state['healthy_since'] ?? 0);
                if ($healthy_since === 0) {
                    $state['healthy_since'] = $now;
                    update_option(self::OPTION_STATE, $state, false);
                } elseif (($now - $healthy_since) >= self::RECOVERY_WINDOW_SECONDS) {
                    // Origin metrics have stayed clean for >= 10 minutes -> auto-deescalate!
                    $this->deescalate_edge_defense($zone_id);
                }
            }
        }
    }
}
