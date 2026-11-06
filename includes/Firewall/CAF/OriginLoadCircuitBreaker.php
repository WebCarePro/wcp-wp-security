<?php
declare(strict_types=1);

namespace WcpScanner\Firewall\CAF;

use WcpScanner\Cloudflare\CloudflareService;
use WcpScanner\Firewall\WafFileLogger;
use WcpScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Origin Load Circuit Breaker (CAF Phase 2)
 *
 * Real-world cPanel / shared hosting survival mode against 508 Resource Limit crashes:
 * - Monitors CPU load (`sys_getloadavg()`), memory consumption, and 60-second probe velocity.
 * - Detects origin distress (> 4.0 load average or > 120 bad requests/min).
 * - Escalate: Triggers Cloudflare "Under Attack Mode" or shifts WCP Edge rules to Managed Challenge.
 * - Deescalate: Automatically restores normal baseline when origin metrics remain healthy for 10 minutes.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class OriginLoadCircuitBreaker {

    public const OPTION_STATE             = 'wcp_origin_survival_state';
    public const CPU_THRESHOLD            = 4.0;
    public const PROBE_VELOCITY_THRESHOLD = 120; // 403/404 per minute
    public const RECOVERY_WINDOW_SECONDS  = 600; // 10 minutes

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

        $memory_usage = memory_get_usage(true);
        $memory_peak = memory_get_peak_usage(true);
        $memory_limit = ini_get('memory_limit');

        // Probe velocity: inspect recent bad requests in transient buffer
        $probe_velocity = (int) get_transient('wcp_waf_probe_velocity_60s');
        if ($probe_velocity === 0 && class_exists(WafFileLogger::class)) {
            // Read lightweight stats from today's log if transient empty
            $stats = WafFileLogger::get_log_stats('today');
            $blocked_today = (int) ($stats['blocked_24h'] ?? ($stats['actions']['blocked'] ?? 0));
            $probe_velocity = min(150, (int) round($blocked_today / 60));
        }

        $is_stressed = ($cpu_load >= self::CPU_THRESHOLD) || ($probe_velocity >= self::PROBE_VELOCITY_THRESHOLD);

        return [
            'cpu_load'               => round($cpu_load, 2),
            'cpu_threshold'          => self::CPU_THRESHOLD,
            'probe_velocity_per_min' => $probe_velocity,
            'velocity_threshold'     => self::PROBE_VELOCITY_THRESHOLD,
            'memory_usage_bytes'     => $memory_usage,
            'memory_peak_bytes'      => $memory_peak,
            'memory_limit'           => $memory_limit,
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
            $zone_id = $settings['cloudflare_zone_id'] ?? '';
        }

        if (empty($zone_id)) {
            return false;
        }

        // 1. Escalate Cloudflare Security Level to 'under_attack' or deploy challenge
        $cf_res = CloudflareService::request(
            "zones/{$zone_id}/settings/security_level",
            'PATCH',
            ['value' => 'under_attack']
        );

        $escalation_type = (!empty($cf_res['success'])) ? 'under_attack' : 'slot_repack';

        // 2. Also re-pack CAF Cloudflare slots with origin_survival_active = true
        $optimizer = new CloudflareSlotOptimizer();
        $optimizer->deploy_to_cloudflare($zone_id, null, [], true);

        // 3. Persist survival state
        update_option(self::OPTION_STATE, [
            'active'          => true,
            'engaged_at'      => time(),
            'healthy_since'   => null,
            'reason'          => sanitize_text_field($reason),
            'escalation_type' => $escalation_type,
            'auto_managed'    => $auto_managed,
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
            $zone_id = $settings['cloudflare_zone_id'] ?? '';
        }

        if (empty($zone_id)) {
            return false;
        }

        // 1. Restore Cloudflare Security Level to 'medium'
        CloudflareService::request(
            "zones/{$zone_id}/settings/security_level",
            'PATCH',
            ['value' => 'medium']
        );

        // 2. Re-pack CAF Cloudflare slots with origin_survival_active = false
        $optimizer = new CloudflareSlotOptimizer();
        $optimizer->deploy_to_cloudflare($zone_id, null, [], false);

        // 3. Reset survival state
        update_option(self::OPTION_STATE, [
            'active'          => false,
            'engaged_at'      => null,
            'healthy_since'   => time(),
            'reason'          => 'Normal operating thresholds restored.',
            'escalation_type' => 'none',
            'auto_managed'    => false,
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
                    update_option(self::OPTION_STATE, $state);
                }
            }
        } else {
            // Server is healthy
            if ($is_active && !empty($state['auto_managed'])) {
                $now = time();
                $healthy_since = (int) ($state['healthy_since'] ?? 0);
                if ($healthy_since === 0) {
                    $state['healthy_since'] = $now;
                    update_option(self::OPTION_STATE, $state);
                } elseif (($now - $healthy_since) >= self::RECOVERY_WINDOW_SECONDS) {
                    // Origin metrics have stayed clean for >= 10 minutes -> auto-deescalate!
                    $this->deescalate_edge_defense($zone_id);
                }
            }
        }
    }
}
