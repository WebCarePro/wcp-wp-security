<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Automated Tamper Detection & Emergency Admin Notification Engine.
 *
 * Implements:
 * 1. Immediate high-priority email alerts (wp_mail) with detailed forensic breakdowns.
 * 2. Un-dismissible persistent WP-Admin red security warning banner.
 * 3. In-app dashboard notification badge & webhook alerts.
 * 4. Anti-spam throttling to prevent email inbox flooding (max 1 email / 6 hours per incident).
 */
class ActivityTamperNotifier {

    const ALERT_FILE = '.tamper-alert.json.php';
    const THROTTLE_HOURS = 6;

    /**
     * Get path to the tamper alert state file.
     *
     * @return string
     */
    public static function get_alert_file_path(): string {
        return ActivityStorage::get_log_dir() . '/' . self::ALERT_FILE;
    }

    /**
     * Trigger all tamper alert channels for a detected integrity breach.
     *
     * @param string $status  'tampering_detected' or 'incomplete_history'
     * @param array  $details Forensic details (file, seq, event_id, reason, etc.)
     */
    public static function trigger(string $status, array $details = []): void {
        $now = time();
        $incident_id = sanitize_key($details['file'] ?? 'unknown') . '_' . intval($details['seq'] ?? 0);

        // Check throttle state
        $alert_state = self::read_alert_state();
        $last_alert_time = intval($alert_state[$incident_id]['alerted_at'] ?? 0);

        // Always update persistent tamper state for the admin banner
        $alert_state[$incident_id] = [
            'acknowledged' => false,
            'alerted_at'   => $now,
            'details'      => $details,
            'status'       => $status,
        ];
        self::write_alert_state($alert_state);

        // Also set persistent option so admin notices hook catches it everywhere
        update_option('wcpscan_activity_tamper_active', [
            'detected_at' => $now,
            'details'     => $details,
            'incident_id' => $incident_id,
            'status'      => $status,
        ], false);

        // If throttled, skip email and external webhooks to protect inbox
        if (($now - $last_alert_time) < (self::THROTTLE_HOURS * 3600)) {
            return;
        }

        // Dispatch Email
        self::send_emergency_email($status, $details);

        // Dispatch Webhook if configured
        self::dispatch_webhook($status, $details);
    }

    /**
     * Send emergency security email to site administrator.
     *
     * @param string $status
     * @param array  $details
     */
    private static function send_emergency_email(string $status, array $details): void {
        $admin_email = get_option('admin_email');
        if (empty($admin_email)) {
            return;
        }

        $site_name = get_bloginfo('name');
        $site_url  = get_site_url();
        $file      = esc_html($details['file'] ?? 'Unknown Partition');
        $seq       = intval($details['seq'] ?? 0);
        $reason    = esc_html($details['reason'] ?? 'Cryptographic hash mismatch or tag failure');
        $time_utc  = gmdate('Y-m-d H:i:s \U\T\C');

        /* translators: %s: Site name */
        $subject = sprintf(__('[CRITICAL SECURITY ALERT] Cryptographic Activity Log Tampering Detected on %s', 'wcp-security-scanner'), $site_name);

        $message = "=========================================================================\n";
        $message .= " CRITICAL SECURITY ALERT: IMMUTABLE AUDIT LOG TAMPERING DETECTED\n";
        $message .= "=========================================================================\n\n";
        $message .= "Site: " . $site_name . " (" . $site_url . ")\n";
        $message .= "Incident Classification: " . strtoupper($status) . "\n";
        $message .= "Detected At: " . $time_utc . "\n\n";
        $message .= "FORENSIC INCIDENT DOSSIER:\n";
        $message .= "-------------------------------------------------------------------------\n";
        $message .= "- Compromised File: " . $file . "\n";
        $message .= "- Affected Sequence: #" . $seq . "\n";
        $message .= "- Failure Cause: " . $reason . "\n\n";
        $message .= "WHAT THIS MEANS:\n";
        $message .= "An encrypted partition record or cryptographic checkpoint has been modified,\n";
        $message .= "truncated, or corrupted on the server filesystem. This indicates either an\n";
        $message .= "unauthorized server intrusion attempting to erase forensic evidence or\n";
        $message .= "an unauthorized direct file modification.\n\n";
        $message .= "IMMEDIATE RECOMMENDED ACTIONS:\n";
        $message .= "1. Log into your WordPress administrative dashboard to review the incident report:\n";
        $message .= "   " . admin_url('admin.php?page=wcp-scanner&tab=activity-logs') . "\n";
        $message .= "2. Inspect web server access logs around " . $time_utc . ".\n";
        $message .= "3. Run a complete WCP Security Scanner Deep System & Malware Audit.\n";
        $message .= "4. Check for newly created or modified administrator accounts.\n\n";
        $message .= "-------------------------------------------------------------------------\n";
        $message .= "WCP Security Scanner Cryptographic Defense Engine\n";

        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        @wp_mail($admin_email, $subject, $message, $headers);
    }

    /**
     * Dispatch webhook if configured in settings.
     *
     * @param string $status
     * @param array  $details
     */
    private static function dispatch_webhook(string $status, array $details): void {
        $settings = get_option('wcpscan_activity_log_settings', []);
        $webhook_url = $settings['tamper_webhook_url'] ?? '';
        if (empty($webhook_url) || !filter_var($webhook_url, FILTER_VALIDATE_URL)) {
            return;
        }

        $payload = [
            'details'         => $details,
            'event'           => 'wcp_log_tampering_detected',
            'severity'        => 'CRITICAL',
            'site_name'       => get_bloginfo('name'),
            'site_url'        => get_site_url(),
            'status'          => $status,
            'timestamp_utc'   => gmdate('Y-m-d\TH:i:s\Z'),
        ];

        wp_remote_post($webhook_url, [
            'blocking' => false,
            'body'     => json_encode($payload),
            'headers'  => ['Content-Type' => 'application/json'],
            'timeout'  => 5,
        ]);
    }

    /**
     * Read the alert state file.
     *
     * @return array
     */
    public static function read_alert_state(): array {
        $path = self::get_alert_file_path();
        if (!file_exists($path)) {
            return [];
        }
        $raw = @file_get_contents($path);
        if (empty($raw)) {
            return [];
        }
        if (strpos($raw, ActivityStorage::PHP_HEADER_STUB) === 0) {
            $raw = substr($raw, strlen(ActivityStorage::PHP_HEADER_STUB));
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    /**
     * Write updated alert state file.
     *
     * @param array $state
     */
    private static function write_alert_state(array $state): void {
        $path = self::get_alert_file_path();
        $json = ActivityStorage::PHP_HEADER_STUB . json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        @file_put_contents($path, $json, LOCK_EX);
    }

    /**
     * Acknowledge and resolve an active tamper alert (by administrator).
     *
     * @param string $incident_id
     * @return bool
     */
    public static function acknowledge_alert(string $incident_id): bool {
        $state = self::read_alert_state();
        if (isset($state[$incident_id])) {
            $state[$incident_id]['acknowledged'] = true;
            $state[$incident_id]['acknowledged_at'] = time();
            self::write_alert_state($state);
        }
        delete_option('wcpscan_activity_tamper_active');
        return true;
    }
}
