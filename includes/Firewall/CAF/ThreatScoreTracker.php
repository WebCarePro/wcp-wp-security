<?php
declare(strict_types=1);

namespace WcpScanner\Firewall\CAF;

use WcpScanner\System\SettingsManager;
use WcpScanner\Firewall\BotReconDefense;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ThreatScoreTracker (CAF Phase 3)
 *
 * Implements Differential 403/404 & Behavioral Probe Velocity Tracking with Exponential Decay:
 *
 * Mathematical Model:
 *   T_{IP}(t) = T_{IP}(t_{last}) * e^{-\lambda * (t - t_{last})} + \Delta S_{event}
 *   where \lambda = ln(2) / 900 \approx 0.0007701635 s^{-1} (15-minute half-life)
 *
 * Score Weights (\Delta S):
 *   - Honeypot / Sensitive File Probe (.env, .git, wp-config.php~): +25
 *   - Dormant Surface Hit (Inactive Plugin, Uninstalled REST, Unapproved Guest AJAX): +15
 *   - Auth Endpoint 403 / Credential Stuffing / XML-RPC: +10
 *   - Consecutive 404 Probes on .php / sensitive extensions: +4
 *   - Client-Hint / HTTP/2 Anomaly: +15
 *
 * Escalation Policy:
 *   - T < \theta_{PoW} (default: 40): Normal visitor traffic (no friction)
 *   - \theta_{PoW} <= T < 85: Stateless WebCrypto SHA-256 Proof-of-Work Challenge (k = 16 zero bits)
 *   - T >= 85: Local hard drop + Async Queue push to Cloudflare Edge Ban List
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class ThreatScoreTracker {

    public const OPTION_HIGH_RISK_IPS = 'wcpscan_caf_high_risk_ips';
    public const TRANSIENT_PREFIX     = 'wcpscan_tscore_';

    // Exponential Decay Parameters
    public const HALF_LIFE_SECONDS    = 900;       // 15 minutes
    public const DECAY_LAMBDA         = 0.0007701635; // ln(2) / 900

    // Threat Escalation Thresholds
    public const THRESHOLD_POW        = 40.0;      // \theta_{PoW}: Trigger WebCrypto challenge
    public const THRESHOLD_HARD_BAN   = 85.0;      // Hard drop & Cloudflare Ban Queue

    // Event Score Weights (\Delta S)
    public const WEIGHT_CRITICAL_EXPLOIT = 85.0; // Immediate hard ban & Cloudflare Edge push on first exploit
    public const WEIGHT_HONEYPOT         = 25.0;
    public const WEIGHT_DORMANT_SURF     = 15.0;
    public const WEIGHT_AUTH_VIOLATE     = 10.0;
    public const WEIGHT_PROBE_404        = 4.0;
    public const WEIGHT_HEADER_ANOMALY   = 15.0;

    /**
     * Record a security event for an IP and compute decayed threat score.
     *
     * @param string $ip Offending Client IP
     * @param string $event_type Event category ('honeypot', 'dormant_surface', 'auth_fail', 'probe_404', 'header_anomaly')
     * @param float|null $custom_weight Optional explicit weight
     * @return array Array containing ['score' => float, 'action' => 'allow'|'challenge'|'ban', 'escalated' => bool]
     */
    public static function record_event(string $ip, string $event_type, ?float $custom_weight = null): array {
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return ['score' => 0.0, 'action' => 'allow', 'escalated' => false];
        }

        // Determine score increment
        $delta = $custom_weight !== null ? $custom_weight : self::get_event_weight($event_type);

        $now = time();
        $state = self::get_ip_state($ip);

        $last_score = (float) ($state['score'] ?? 0.0);
        $last_time  = (int) ($state['time'] ?? $now);

        // Apply exponential decay: T_{IP}(t_{last}) * e^{-\lambda * \Delta t}
        $time_diff = max(0, $now - $last_time);
        $decayed_score = $last_score * exp(-self::DECAY_LAMBDA * $time_diff);

        // Add event weight and clamp between 0.0 and 100.0
        $new_score = round(min(100.0, max(0.0, $decayed_score + $delta)), 2);

        // Update state in transient / memory
        self::save_ip_state($ip, [
            'score'        => $new_score,
            'time'         => $now,
            'last_event'   => $event_type,
            'event_count'  => (int) ($state['event_count'] ?? 0) + 1,
        ]);

        // Determine Action & Escalation
        $action = 'allow';
        $escalated = false;

        if ($new_score >= self::THRESHOLD_HARD_BAN) {
            $action = 'ban';
            $escalated = true;
            self::escalate_to_hard_ban($ip, $new_score, $event_type);
        } elseif ($new_score >= self::THRESHOLD_POW) {
            $action = 'challenge';
            $escalated = true;
            self::mark_for_pow_challenge($ip);
        }

        return [
            'score'     => $new_score,
            'action'    => $action,
            'escalated' => $escalated,
            'delta'     => $delta,
        ];
    }

    /**
     * Get current decayed threat score for an IP without adding a new event.
     *
     * @param string $ip
     * @return float
     */
    public static function get_current_score(string $ip): float {
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return 0.0;
        }

        $state = self::get_ip_state($ip);
        if (empty($state['score'])) {
            return 0.0;
        }

        $now = time();
        $time_diff = max(0, $now - (int) ($state['time'] ?? $now));
        $decayed = (float) $state['score'] * exp(-self::DECAY_LAMBDA * $time_diff);
        return round(max(0.0, $decayed), 2);
    }

    /**
     * Pre-flight check: evaluate client on early request entry.
     * If score >= 85, drops connection immediately.
     * If score >= 40, invokes WebCrypto PoW challenge.
     *
     * @param string $ip
     * @return void
     */
    public static function inspect_client_threat(string $ip): void {
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return;
        }

        // Exempt logged-in administrators
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return;
        }

        $score = self::get_current_score($ip);
        if ($score <= 0.0) {
            return;
        }

        // Tier 1: Severe threat (score >= 85) -> Immediate Hard Drop
        if ($score >= self::THRESHOLD_HARD_BAN) {
            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
            header('X-WCP-Threat-Score: ' . $score);
            echo 'Access Denied: Severe behavioral threat score accumulated. Connection terminated by WCP Context-Adaptive Firewall.';
            exit;
        }

        // Tier 2: Suspicious probe velocity (40 <= score < 85) -> WebCrypto PoW Challenge
        if ($score >= self::THRESHOLD_POW) {
            if (class_exists('\\WcpScanner\\Firewall\\BotReconDefense')) {
                BotReconDefense::verify_or_challenge_client();
            }
        }
    }

    /**
     * Escalate an IP to local quarantine and push to Cloudflare Edge Ban Queue.
     */
    private static function escalate_to_hard_ban(string $ip, float $score, string $reason): void {
        // Enforce hard quarantine via central FirewallEngine
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            \WcpScanner\Firewall\FirewallEngine::add_blocked_ip(
                $ip,
                sprintf('ThreatScore %.1f: %s', $score, $reason),
                86400,
                null,
                'CAF-THREAT-SCORE',
                'CAF Autonomous Threat Score Ban',
                'Context-Adaptive Firewall'
            );
        } elseif (class_exists('\\WcpScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            CloudflareIpListSynchronizer::queue_ip_ban($ip, sprintf('ThreatScore %.1f: %s', $score, $reason));
        }

        // Record in high-risk list for local blocklist caching
        $high_risk = get_option(self::OPTION_HIGH_RISK_IPS, []);
        if (!is_array($high_risk)) {
            $high_risk = [];
        }

        $high_risk[$ip] = [
            'ip'         => $ip,
            'score'      => $score,
            'reason'     => $reason,
            'banned_at'  => time(),
            'expires_at' => time() + 86400, // 24-hour quarantine
        ];

        // Keep top 200 high-risk IPs
        if (count($high_risk) > 200) {
            uasort($high_risk, fn($a, $b) => ($b['score'] ?? 0) <=> ($a['score'] ?? 0));
            $high_risk = array_slice($high_risk, 0, 200, true);
        }

        update_option(self::OPTION_HIGH_RISK_IPS, $high_risk, false);
    }

    /**
     * Mark IP in the PoW enforcement registry.
     */
    private static function mark_for_pow_challenge(string $ip): void {
        $pow_ips = get_option('wcp_pow_enforced_ips', []);
        if (!is_array($pow_ips)) {
            $pow_ips = [];
        }

        if (!isset($pow_ips[$ip])) {
            $pow_ips[$ip] = [
                'ip'         => $ip,
                'marked_at'  => time(),
                'expires_at' => time() + 3600, // 1 hour PoW requirement
            ];
            update_option('wcp_pow_enforced_ips', $pow_ips, false);
        }
    }

    /**
     * Get event score weight based on classification.
     */
    private static function get_event_weight(string $event_type): float {
        return match ($event_type) {
            'critical_exploit' => self::WEIGHT_CRITICAL_EXPLOIT,
            'honeypot'         => self::WEIGHT_HONEYPOT,
            'dormant_surface'  => self::WEIGHT_DORMANT_SURF,
            'auth_fail'        => self::WEIGHT_AUTH_VIOLATE,
            'probe_404'        => self::WEIGHT_PROBE_404,
            'header_anomaly'   => self::WEIGHT_HEADER_ANOMALY,
            default            => 5.0,
        };
    }

    /**
     * Read IP state from memory (APCu) or transient storage.
     */
    private static function get_ip_state(string $ip): array {
        $key = self::TRANSIENT_PREFIX . substr(md5($ip), 0, 16);

        if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
            $res = apcu_fetch($key);
            if (is_array($res)) {
                return $res;
            }
        }

        $stored = get_transient($key);
        return is_array($stored) ? $stored : [];
    }

    /**
     * Save IP state to memory (APCu) or transient storage.
     */
    private static function save_ip_state(string $ip, array $state): void {
        $key = self::TRANSIENT_PREFIX . substr(md5($ip), 0, 16);
        $ttl = 7200; // 2 hours

        if (function_exists('apcu_store') && ini_get('apc.enabled')) {
            apcu_store($key, $state, $ttl);
        }

        set_transient($key, $state, $ttl);
    }

    /**
     * Get behavioral telemetry overview for administrative reporting.
     *
     * @return array
     */
    public static function get_telemetry(): array {
        $high_risk = get_option(self::OPTION_HIGH_RISK_IPS, []);
        $pow_ips   = get_option('wcp_pow_enforced_ips', []);

        $active_high_risk = [];
        $now = time();

        if (is_array($high_risk)) {
            foreach ($high_risk as $ip => $data) {
                if (($data['expires_at'] ?? 0) > $now) {
                    $active_high_risk[] = $data;
                }
            }
        }

        return [
            'high_risk_ips_count' => count($active_high_risk),
            'high_risk_ips'       => array_slice($active_high_risk, 0, 25),
            'pow_active_count'    => is_array($pow_ips) ? count($pow_ips) : 0,
            'threshold_pow'       => self::THRESHOLD_POW,
            'threshold_ban'       => self::THRESHOLD_HARD_BAN,
            'half_life_seconds'   => self::HALF_LIFE_SECONDS,
        ];
    }
}
