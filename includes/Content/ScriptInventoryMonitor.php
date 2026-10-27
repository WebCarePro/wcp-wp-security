<?php
namespace WcpScanner\Content;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ScriptInventoryMonitor
 *
 * Client-Side Supply Chain & Third-Party Hostname Drift Monitor.
 * Intercepts enqueued frontend JavaScript resources, maintains an approved domain baseline,
 * and detects unauthorized script injections and external hostname drift (e.g. Magecart skimmers).
 */
class ScriptInventoryMonitor {

    const OPTION_INVENTORY = 'wcpscan_script_inventory';
    const OPTION_BASELINE  = 'wcpscan_script_inventory_baseline';
    const OPTION_ALERTS    = 'wcpscan_script_drift_alerts';

    /**
     * Initialize frontend hooks to capture enqueued scripts.
     */
    public static function init() {
        if (!is_admin()) {
            add_action('wp_print_footer_scripts', [__CLASS__, 'capture_enqueued_scripts'], 9999);
        }
    }

    /**
     * Inspect all enqueued scripts at footer execution and track drift against baseline.
     */
    public static function capture_enqueued_scripts(): void {
        global $wp_scripts;

        if (!($wp_scripts instanceof \WP_Scripts) || empty($wp_scripts->queue)) {
            return;
        }

        $home_host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $inventory = get_option(self::OPTION_INVENTORY, []);
        if (!is_array($inventory)) {
            $inventory = [];
        }

        $baseline = get_option(self::OPTION_BASELINE, null);
        $alerts = get_option(self::OPTION_ALERTS, []);
        if (!is_array($alerts)) {
            $alerts = [];
        }

        $is_sensitive_page = self::is_sensitive_checkout_or_auth();
        $updated_inventory = false;

        foreach ($wp_scripts->queue as $handle) {
            if (!isset($wp_scripts->registered[$handle])) {
                continue;
            }

            $src = $wp_scripts->registered[$handle]->src ?? '';
            if (empty($src) || !is_string($src)) {
                continue;
            }

            // Normalise schema-relative URLs (e.g. //cdn.example.com/lib.js)
            if (str_starts_with($src, '//')) {
                $src = 'https:' . $src;
            }

            $host = strtolower((string) wp_parse_url($src, PHP_URL_HOST));
            if (empty($host) || $host === $home_host) {
                continue; // First-party local script
            }

            $key = md5($handle . '|' . $host);

            if (!isset($inventory[$key])) {
                $inventory[$key] = [
                    'handle'       => sanitize_text_field($handle),
                    'host'         => sanitize_text_field($host),
                    'src'          => esc_url_raw($src),
                    'first_seen'   => current_time('mysql'),
                    'last_seen'    => current_time('mysql'),
                    'is_sensitive' => $is_sensitive_page,
                ];
                $updated_inventory = true;

                // Drift detection against calibrated baseline
                if (is_array($baseline) && !isset($baseline[$host])) {
                    $alert_id = 'drift_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3));
                    $severity = $is_sensitive_page ? 'critical' : 'high';
                    
                    $alerts[$alert_id] = [
                        'id'          => $alert_id,
                        'handle'      => sanitize_text_field($handle),
                        'host'        => sanitize_text_field($host),
                        'src'         => esc_url_raw($src),
                        'severity'    => $severity,
                        'is_sensitive'=> $is_sensitive_page,
                        'detected_at' => current_time('mysql'),
                        'status'      => 'open',
                    ];

                    AuditLogger::log(
                        'script_drift_detected',
                        sprintf('Unseen third-party script domain "%s" enqueued via handle "%s" (Severity: %s).', $host, $handle, strtoupper($severity))
                    );
                }
            } else {
                $inventory[$key]['last_seen'] = current_time('mysql');
                if ($is_sensitive_page) {
                    $inventory[$key]['is_sensitive'] = true;
                }
            }
        }

        if ($updated_inventory) {
            update_option(self::OPTION_INVENTORY, $inventory, false);
            if (!empty($alerts)) {
                // Keep only last 100 alerts
                if (count($alerts) > 100) {
                    $alerts = array_slice($alerts, -100, 100, true);
                }
                update_option(self::OPTION_ALERTS, $alerts, false);
            }
        }
    }

    /**
     * Determine if current request is on a payment, checkout, or login page.
     *
     * @return bool
     */
    private static function is_sensitive_checkout_or_auth(): bool {
        if (function_exists('is_checkout') && is_checkout()) {
            return true;
        }
        if (function_exists('is_cart') && is_cart()) {
            return true;
        }
        if (function_exists('is_account_page') && is_account_page()) {
            return true;
        }

        $raw_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $uri = strtolower($raw_uri);
        if (strpos($uri, 'wp-login.php') !== false || strpos($uri, 'checkout') !== false || strpos($uri, 'payment') !== false || strpos($uri, 'cart') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Get complete script inventory telemetry and drift status.
     *
     * @return array
     */
    public static function get_status(): array {
        $inventory = get_option(self::OPTION_INVENTORY, []);
        $baseline = get_option(self::OPTION_BASELINE, null);
        $alerts = get_option(self::OPTION_ALERTS, []);

        if (!is_array($inventory)) {
            $inventory = [];
        }
        if (!is_array($alerts)) {
            $alerts = [];
        }

        // Unique domains summary
        $domains = [];
        foreach ($inventory as $item) {
            $host = $item['host'];
            if (!isset($domains[$host])) {
                $domains[$host] = [
                    'host'         => $host,
                    'script_count' => 0,
                    'is_baseline'  => is_array($baseline) && isset($baseline[$host]),
                    'has_sensitive'=> false,
                ];
            }
            $domains[$host]['script_count']++;
            if (!empty($item['is_sensitive'])) {
                $domains[$host]['has_sensitive'] = true;
            }
        }

        $open_alerts = array_filter($alerts, fn($a) => ($a['status'] ?? 'open') === 'open');

        return [
            'success'          => true,
            'is_calibrated'    => is_array($baseline),
            'total_scripts'    => count($inventory),
            'total_domains'    => count($domains),
            'open_alerts_count'=> count($open_alerts),
            'domains'          => array_values($domains),
            'scripts'          => array_values($inventory),
            'alerts'           => array_values(array_reverse($alerts)),
        ];
    }

    /**
     * Calibrate baseline: mark all current third-party domains as approved.
     *
     * @return array
     */
    public static function calibrate_baseline(): array {
        $inventory = get_option(self::OPTION_INVENTORY, []);
        if (!is_array($inventory)) {
            $inventory = [];
        }

        $baseline = [];
        foreach ($inventory as $item) {
            $baseline[$item['host']] = [
                'host'          => $item['host'],
                'calibrated_at' => current_time('mysql'),
            ];
        }

        update_option(self::OPTION_BASELINE, $baseline, false);

        // Clear or resolve open alerts
        $alerts = get_option(self::OPTION_ALERTS, []);
        if (is_array($alerts)) {
            foreach ($alerts as &$alert) {
                if (($alert['status'] ?? 'open') === 'open') {
                    $alert['status'] = 'resolved';
                    $alert['resolved_at'] = current_time('mysql');
                }
            }
            update_option(self::OPTION_ALERTS, $alerts, false);
        }

        AuditLogger::log(
            'script_baseline_calibrated',
            sprintf('Calibrated third-party script baseline with %d approved domains.', count($baseline))
        );

        return self::get_status();
    }

    /**
     * Acknowledge or dismiss a specific drift alert.
     *
     * @param string $alert_id
     * @return bool
     */
    public static function dismiss_alert(string $alert_id): bool {
        $alerts = get_option(self::OPTION_ALERTS, []);
        if (!is_array($alerts) || !isset($alerts[$alert_id])) {
            return false;
        }

        $alerts[$alert_id]['status'] = 'dismissed';
        $alerts[$alert_id]['dismissed_at'] = current_time('mysql');
        update_option(self::OPTION_ALERTS, $alerts, false);

        AuditLogger::log(
            'script_drift_dismissed',
            sprintf('Dismissed third-party script drift alert for "%s".', $alerts[$alert_id]['host'] ?? 'unknown')
        );

        return true;
    }
}
