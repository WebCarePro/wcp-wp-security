<?php
namespace WcpScanner\System;

use WcpScanner\System\ActivityLogs\ActivityCanonicalizer;
use WcpScanner\System\ActivityLogs\ActivityEventSchema;
use WcpScanner\System\ActivityLogs\ActivityHashChain;
use WcpScanner\System\ActivityLogs\ActivityHumanizer;
use WcpScanner\System\ActivityLogs\ActivityRateLimiter;
use WcpScanner\System\ActivityLogs\ActivityRecovery;
use WcpScanner\System\ActivityLogs\ActivityRetention;
use WcpScanner\System\ActivityLogs\ActivityStorage;
use WcpScanner\System\ActivityLogs\ActivityTamperNotifier;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Central Enterprise Activity & Forensic Audit Logging Facade.
 *
 * Implements:
 * 1. Thread-safe, crash-safe, zero-SQL, AES-256-GCM encrypted daily audit logging.
 * 2. Unbroken cryptographic SHA-256 hash chaining across days, months, and segments.
 * 3. 7-Day minimum forensic immutability guarded by Hash-Chained Checkpoint Ledgers.
 * 4. Dual human-vs-system attribution with automatic "System" initiator detection for scheduled tasks.
 * 5. Re-entrancy guards and automatic tamper detection alerts.
 */
class WcpActivityLogger {

    /**
     * Recursion / Re-entrancy guard to prevent infinite logging loops.
     */
    private static bool $is_logging = false;

    /**
     * Deduplication registry for option watcher within single request lifecycle.
     */
    private static array $logged_options_in_request = [];

    /**
     * Registry of distinct actions logged within this request lifecycle.
     */
    public static array $logged_actions_in_request = [];

    /**
     * Initialize listeners and hooks.
     */
    public static function init(): void {
        // Universal WordPress Option Watcher for all wcpscan_* plugin state changes
        add_action('updated_option', [__CLASS__, 'on_option_updated'], 10, 3);
        add_action('added_option', [__CLASS__, 'on_option_added'], 10, 2);
    }

    /**
     * Primary public logging method.
     *
     * @param string      $action         Stable action key (e.g. 'settings_updated', 'scan_started').
     * @param string      $category       Event category ('settings', 'scan', 'quarantine', 'firewall', etc.).
     * @param string      $severity       Severity level ('info', 'notice', 'warning', 'error', 'critical').
     * @param array       $details        Event details and diffs (automatically redacted).
     * @param array|null  $actor_override Explicit actor snapshot if not deriving from execution context.
     * @param string|null $correlation_id Grouping identifier.
     * @return bool True if durably committed to disk, false otherwise.
     */
    public static function log(
        string $action,
        string $category,
        string $severity = ActivityEventSchema::SEVERITY_INFO,
        array $details = [],
        ?array $actor_override = null,
        ?string $correlation_id = null
    ): bool {
        // Prevent re-entrancy
        if (self::$is_logging) {
            return false;
        }

        self::$is_logging = true;

        try {
            // Check rate limiter
            $limit_check = ActivityRateLimiter::check_limit($action, $category, $severity);
            if (!$limit_check['allow']) {
                self::$is_logging = false;
                return false;
            }

            // Build normalized event data structure
            $event_payload = ActivityEventSchema::build_event(
                $action,
                $category,
                $severity,
                $details,
                $actor_override,
                $correlation_id
            );

            // Track action in current request registry
            self::$logged_actions_in_request[$action] = true;

            // Execute transaction under 3-tier lock
            $success = self::execute_wal_transaction($event_payload);

            // If a rate limit rollup summary is due, emit it now
            if ($success && !empty($limit_check['is_rollup_due']) && $limit_check['suppressed_count'] > 0) {
                self::$is_logging = false;
                self::log(
                    'event_flood_rollup',
                    'system',
                    ActivityEventSchema::SEVERITY_NOTICE,
                    [
                        'action_throttled' => $action,
                        'description'      => sprintf('Suppressed %d repeated events during throttle window.', $limit_check['suppressed_count']),
                        'suppressed_count' => (int) $limit_check['suppressed_count'],
                    ]
                );
                return true;
            }

            self::$is_logging = false;
            return $success;
        } catch (\Throwable $e) {
            self::$is_logging = false;
            // Record degraded logging state if disk write fails
            self::mark_degraded_state('write_exception', $e->getMessage());
            return false;
        }
    }

    /**
     * Convenience helpers for structured logging.
     */
    public static function info(string $action, string $category, array $details = []): bool {
        return self::log($action, $category, ActivityEventSchema::SEVERITY_INFO, $details);
    }

    public static function notice(string $action, string $category, array $details = []): bool {
        return self::log($action, $category, ActivityEventSchema::SEVERITY_NOTICE, $details);
    }

    public static function warning(string $action, string $category, array $details = []): bool {
        return self::log($action, $category, ActivityEventSchema::SEVERITY_WARNING, $details);
    }

    public static function error(string $action, string $category, array $details = []): bool {
        return self::log($action, $category, ActivityEventSchema::SEVERITY_ERROR, $details);
    }

    public static function critical(string $action, string $category, array $details = []): bool {
        return self::log($action, $category, ActivityEventSchema::SEVERITY_CRITICAL, $details);
    }

    /**
     * Execute full crash-consistent Write-Ahead Transaction under 3-tier lock.
     *
     * @param array $event_payload
     * @return bool
     */
    private static function execute_wal_transaction(array $event_payload): bool {
        // Step 1: Acquire Level 1 Lock (.chain-state.lock)
        $lock1_fp = ActivityStorage::acquire_lock(ActivityStorage::get_chain_lock_path(), 1.5);
        if (!$lock1_fp) {
            self::mark_degraded_state('lock_timeout', 'Failed to acquire .chain-state.lock');
            return false;
        }

        // Step 2: Acquire Level 2 Lock (.journal.lock)
        $lock2_fp = ActivityStorage::acquire_lock(ActivityStorage::get_journal_lock_path(), 1.5);
        if (!$lock2_fp) {
            ActivityStorage::release_lock($lock1_fp);
            self::mark_degraded_state('lock_timeout', 'Failed to acquire .journal.lock');
            return false;
        }

        try {
            // Read current committed chain state
            $state = ActivityStorage::read_chain_state();
            if (isset($state['state_valid']) && !$state['state_valid']) {
                ActivityStorage::release_lock($lock2_fp);
                ActivityStorage::release_lock($lock1_fp);
                self::mark_degraded_state('corrupt_chain_state', 'Chain state is unreadable or corrupted: ' . ($state['error'] ?? 'Unknown error'));
                return false;
            }

            $current_seq = (int) ($state['current_seq'] ?? 0);
            $latest_hash = (string) ($state['latest_hash'] ?? ActivityHashChain::get_genesis_hash());
            $active_segment = (string) ($state['active_segment'] ?? '');

            // Allocate next sequence number and previous hash link
            $next_seq = $current_seq + 1;
            $prev_hash = $latest_hash;

            // Inject chain metadata into inner canonical payload
            $event_payload['seq'] = $next_seq;
            $event_payload['prev_hash'] = $prev_hash;

            // Resolve target segment with capacity check & rollover
            $target_segment = ActivityStorage::resolve_active_segment($active_segment);
            $target_file_path = ActivityStorage::get_log_dir() . '/' . $target_segment;

            // Step 3: Compute Record Hash & Encrypted Envelope
            $record_hash = ActivityHashChain::compute_record_hash($prev_hash, $event_payload);
            $envelope = ActivityHashChain::encrypt_envelope($event_payload, $next_seq, $record_hash);

            // Step 4: Write WAL pending journal transaction and verify durable write
            $journal_payload = [
                'envelope'       => $envelope,
                'h'              => $record_hash,
                'seq'            => $next_seq,
                'status'         => 'pending',
                'target_segment' => $target_segment,
                'timestamp'      => time(),
            ];
            $journal_json = ActivityStorage::PHP_HEADER_STUB . json_encode($journal_payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $wal_bytes = @file_put_contents(ActivityStorage::get_journal_path(), $journal_json, LOCK_EX);
            if ($wal_bytes === false || $wal_bytes === 0) {
                ActivityStorage::release_lock($lock2_fp);
                ActivityStorage::release_lock($lock1_fp);
                self::mark_degraded_state('wal_journal_write_failure', 'Failed to write pending WAL journal transaction to disk.');
                return false;
            }

            // Step 5: Append complete envelope line to active segment using verified write loop
            $line = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
            $append_ok = ActivityStorage::atomic_append_line($target_file_path, $line);

            if (!$append_ok) {
                // If append failed, preserve journal for recovery and release locks
                ActivityStorage::release_lock($lock2_fp);
                ActivityStorage::release_lock($lock1_fp);
                self::mark_degraded_state('disk_append_failure', 'Failed to append record to segment ' . $target_segment);
                return false;
            }

            // Step 6: Commit new chain state and verify commit
            $commit_ok = ActivityStorage::write_chain_state($next_seq, $record_hash, $target_segment);
            if (!$commit_ok) {
                // If state commit failed, preserve journal for recovery; DO NOT delete journal
                ActivityStorage::release_lock($lock2_fp);
                ActivityStorage::release_lock($lock1_fp);
                self::mark_degraded_state('chain_state_commit_failure', 'Appended record #' . $next_seq . ' but failed to commit chain state.');
                return false;
            }

            // Step 7: Clear journal transaction only after confirmed state commit
            wp_delete_file(ActivityStorage::get_journal_path());

            // Release locks in reverse order
            ActivityStorage::release_lock($lock2_fp);
            ActivityStorage::release_lock($lock1_fp);

            return true;
        } catch (\Throwable $e) {
            ActivityStorage::release_lock($lock2_fp);
            ActivityStorage::release_lock($lock1_fp);
            self::mark_degraded_state('wal_exception', $e->getMessage());
            return false;
        }
    }

    /**
     * Mark degraded operational state zero-SQL.
     *
     * @param string $code
     * @param string $message
     */
    public static function mark_degraded_state(string $code, string $message): void {
        $status_file = ActivityStorage::get_log_dir() . '/.status.json.php';
        $data = [
            'code'           => $code,
            'degraded'       => true,
            'message'        => substr($message, 0, 255),
            'updated_at_utc' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
        $json = ActivityStorage::PHP_HEADER_STUB . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        @file_put_contents($status_file, $json, LOCK_EX);
    }

    /**
     * Clear degraded operational state after successful verification.
     */
    public static function clear_degraded_state(): void {
        $status_file = ActivityStorage::get_log_dir() . '/.status.json.php';
        $data = [
            'code'           => null,
            'degraded'       => false,
            'message'        => 'Logging engine is healthy.',
            'updated_at_utc' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
        $json = ActivityStorage::PHP_HEADER_STUB . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        @file_put_contents($status_file, $json, LOCK_EX);
    }

    /**
     * Check if specific actions were already committed in the current request.
     * Useful for preventing secondary duplicate setting/option diff logs.
     *
     * @param string ...$actions
     * @return bool
     */
    public static function has_action_logged(string ...$actions): bool {
        foreach ($actions as $act) {
            if (!empty(self::$logged_actions_in_request[$act])) {
                return true;
            }
        }
        return false;
    }

    /**
     * Read records with cursor pagination and filters.
     *
     * @param array $args ['cursor' => string, 'limit' => int, 'category' => string, 'actor_type' => string, 'severity' => string, 'search' => string]
     * @return array ['records' => array, 'next_cursor' => ?string, 'total_read' => int]
     */
    public static function query_records(array $args = []): array {
        $max_allowed_limit = !empty($args['is_export']) ? 10000 : 100;
        $limit      = isset($args['limit']) ? min($max_allowed_limit, max(1, (int) $args['limit'])) : 50;
        $page       = isset($args['page']) ? max(1, (int) $args['page']) : 1;
        $offset     = ($page - 1) * $limit;
        $category   = !empty($args['category']) ? sanitize_key($args['category']) : null;
        $actor_type = !empty($args['actor_type']) ? sanitize_key($args['actor_type']) : null;
        $severity   = !empty($args['severity']) ? sanitize_key($args['severity']) : null;
        $search     = !empty($args['search']) ? strtolower(sanitize_text_field($args['search'])) : null;
        $date       = !empty($args['date']) ? sanitize_text_field($args['date']) : null;

        $dir = ActivityStorage::get_log_dir();
        if ($date && preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
            $files = glob($dir . '/activity-' . $date . '-*.json.php');
        } else {
            $files = glob($dir . '/activity-*-*.json.php');
        }
        if (empty($files)) {
            return [
                'current_page' => $page,
                'has_next'     => false,
                'has_prev'     => false,
                'per_page'     => $limit,
                'records'      => [],
                'total'        => 0,
                'total_pages'  => 0,
                'total_read'   => 0,
            ];
        }

        // Sort descending to read newest records first
        rsort($files);

        $matched_records = [];
        $total_matched = 0;

        foreach ($files as $file_path) {
            $lines = @file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (empty($lines)) {
                continue;
            }

            // Reverse lines in partition to process newest first
            $lines = array_reverse($lines);

            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line) || strpos($line, '<?php') === 0) {
                    continue;
                }

                $envelope = json_decode($line, true);
                if (!is_array($envelope) || !isset($envelope['c'])) {
                    continue;
                }

                try {
                    $record = ActivityHashChain::decrypt_envelope($envelope);
                } catch (\Throwable $e) {
                    continue;
                }

                // Filter Category
                if ($category) {
                    $rec_cat = $record['category'] ?? '';
                    $matches_cat = ($rec_cat === $category);

                    // Dual-matching: If filtering for 'firewall', also include legacy records whose diff touches waf_ keys
                    if (!$matches_cat && $category === 'firewall' && !empty($record['details']['diff'])) {
                        foreach (array_keys($record['details']['diff']) as $diff_k) {
                            if (strpos($diff_k, 'waf_') === 0 || strpos($diff_k, 'threat_intel_') === 0 || strpos($diff_k, 'cloudflare_') === 0) {
                                $matches_cat = true;
                                break;
                            }
                        }
                    }

                    if (!$matches_cat) {
                        continue;
                    }
                }

                // Filter Severity
                if ($severity && ($record['severity'] ?? '') !== $severity) {
                    continue;
                }

                // Filter Actor Type
                if ($actor_type) {
                    $rec_actor_type = $record['actor']['type'] ?? '';
                    if ($rec_actor_type !== $actor_type) {
                        continue;
                    }
                }

                // Filter Search
                if ($search) {
                    $json_searchable = strtolower(json_encode($record));
                    if (strpos($json_searchable, $search) === false) {
                        continue;
                    }
                }

                // This record matches all criteria
                if ($total_matched >= $offset && count($matched_records) < $limit) {
                    $matched_records[] = ActivityHumanizer::humanize_record($record);
                }
                $total_matched++;
            }
        }

        $total_pages = $total_matched > 0 ? (int) ceil($total_matched / $limit) : 0;

        return [
            'current_page' => $page,
            'has_next'     => $page < $total_pages,
            'has_prev'     => $page > 1,
            'per_page'     => $limit,
            'records'      => $matched_records,
            'total'        => $total_matched,
            'total_pages'  => $total_pages,
            'total_read'   => count($matched_records),
        ];
    }

    /**
     * Run full cryptographic verification across active partitions and Checkpoint Ledger.
     *
     * @return array Verification report.
     */
    public static function verify_integrity(): array {
        // Step 1: Reconcile any lingering WAL state
        $rec_status = ActivityRecovery::reconcile_wal();
        if (isset($rec_status['reconciled']) && !$rec_status['reconciled']) {
            return [
                'broken_at_seq'   => null,
                'checked_records' => 0,
                'details'         => 'Integrity check suspended: Unresolved WAL transaction: ' . ($rec_status['error'] ?? 'recovery pending'),
                'status'          => 'degraded',
            ];
        }

        $dir = ActivityStorage::get_log_dir();
        $files = glob($dir . '/activity-*-*.json.php');
        $checkpoints = ActivityRetention::read_checkpoints();

        if (empty($files) && empty($checkpoints)) {
            return [
                'broken_at_seq'   => null,
                'checked_records' => 0,
                'details'         => 'No activity logs or checkpoints exist yet.',
                'status'          => 'verified',
            ];
        }

        // Sort ascending (chronological order)
        sort($files);

        $expected_prev_hash = ActivityHashChain::get_genesis_hash();
        $expected_seq = 1;

        // If checkpoints exist, verify checkpoint chain and recompute canonical hash
        if (!empty($checkpoints)) {
            $prev_chk_hash = ActivityRetention::get_checkpoint_genesis_hash();
            foreach ($checkpoints as $chk) {
                // Verify previous link
                if (($chk['previous_checkpoint_hash'] ?? '') !== $prev_chk_hash) {
                    ActivityTamperNotifier::trigger('incomplete_history', [
                        'file'   => '.checkpoints.json.php',
                        'reason' => 'Checkpoint chain link broken',
                        'seq'    => $chk['checkpoint_seq'] ?? 0,
                    ]);
                    return [
                        'broken_at_seq' => $chk['checkpoint_seq'] ?? 0,
                        'details'       => 'Checkpoint hash link mismatch at sequence ' . ($chk['checkpoint_seq'] ?? 0),
                        'status'        => 'tampering_detected',
                    ];
                }

                // Recompute canonical checkpoint hash from payload
                $copy_chk = $chk;
                $recorded_hash = $copy_chk['checkpoint_hash'] ?? '';
                unset($copy_chk['checkpoint_hash']);
                ksort($copy_chk, SORT_STRING);
                $chk_json = json_encode($copy_chk, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                $recomputed_chk_hash = hash('sha256', $prev_chk_hash . $chk_json);

                if (!hash_equals($recomputed_chk_hash, $recorded_hash)) {
                    ActivityTamperNotifier::trigger('tampering_detected', [
                        'file'   => '.checkpoints.json.php',
                        'reason' => 'Checkpoint self-hash mismatch',
                        'seq'    => $chk['checkpoint_seq'] ?? 0,
                    ]);
                    return [
                        'broken_at_seq' => $chk['checkpoint_seq'] ?? 0,
                        'details'       => 'Checkpoint payload hash corrupted at sequence ' . ($chk['checkpoint_seq'] ?? 0),
                        'status'        => 'tampering_detected',
                    ];
                }

                $prev_chk_hash = $chk['checkpoint_hash'] ?? '';
            }

            // Expected starting hash and sequence for active partitions connects to the last checkpoint
            $last_chk = end($checkpoints);
            $expected_prev_hash = $last_chk['closing_hash'] ?? '';
            $expected_seq = ($last_chk['last_seq'] ?? 0) + 1;
        }

        $total_checked = 0;

        foreach ($files as $file_path) {
            $filename = basename($file_path);
            $lines = @file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (empty($lines)) {
                continue;
            }

            foreach ($lines as $line_idx => $line) {
                $line = trim($line);
                if (empty($line) || strpos($line, '<?php') === 0) {
                    continue;
                }

                $envelope = json_decode($line, true);
                if (!is_array($envelope)) {
                    ActivityTamperNotifier::trigger('tampering_detected', [
                        'file'   => $filename,
                        'line'   => $line_idx + 1,
                        'reason' => 'Malformed JSON envelope',
                        'seq'    => $expected_seq,
                    ]);
                    return [
                        'broken_at_seq' => $expected_seq,
                        'details'       => 'Corrupted envelope line in ' . $filename . ' at line ' . ($line_idx + 1),
                        'status'        => 'tampering_detected',
                    ];
                }

                // Verify Decryption & GCM Authentication Tag
                try {
                    $payload = ActivityHashChain::decrypt_envelope($envelope);
                } catch (\Throwable $e) {
                    ActivityTamperNotifier::trigger('tampering_detected', [
                        'file'   => $filename,
                        'line'   => $line_idx + 1,
                        'reason' => $e->getMessage(),
                        'seq'    => $envelope['seq'] ?? $expected_seq,
                    ]);
                    return [
                        'broken_at_seq' => $envelope['seq'] ?? $expected_seq,
                        'details'       => 'Cryptographic verification failed: ' . $e->getMessage(),
                        'status'        => 'tampering_detected',
                    ];
                }

                // Verify Monotonic Sequence
                if ($payload['seq'] !== $expected_seq) {
                    ActivityTamperNotifier::trigger('incomplete_history', [
                        'file'   => $filename,
                        'reason' => sprintf('Sequence gap: expected %d, got %d', $expected_seq, $payload['seq']),
                        'seq'    => $expected_seq,
                    ]);
                    return [
                        'broken_at_seq' => $expected_seq,
                        'details'       => sprintf('Sequence gap detected: expected %d but found %d', $expected_seq, $payload['seq']),
                        'status'        => 'incomplete_history',
                    ];
                }

                // Verify Previous Hash Link
                if ($payload['prev_hash'] !== $expected_prev_hash) {
                    ActivityTamperNotifier::trigger('tampering_detected', [
                        'file'   => $filename,
                        'reason' => 'Previous record hash mismatch',
                        'seq'    => $expected_seq,
                    ]);
                    return [
                        'broken_at_seq' => $expected_seq,
                        'details'       => 'Previous hash link broken at sequence ' . $expected_seq,
                        'status'        => 'tampering_detected',
                    ];
                }

                // Recalculate record hash
                $calculated_hash = ActivityHashChain::compute_record_hash($expected_prev_hash, $payload);
                if ($calculated_hash !== $envelope['h']) {
                    ActivityTamperNotifier::trigger('tampering_detected', [
                        'file'   => $filename,
                        'reason' => 'Calculated payload hash does not match stored hash',
                        'seq'    => $expected_seq,
                    ]);
                    return [
                        'broken_at_seq' => $expected_seq,
                        'details'       => 'Record hash mismatch at sequence ' . $expected_seq,
                        'status'        => 'tampering_detected',
                    ];
                }

                // Advance chain state
                $expected_prev_hash = $envelope['h'];
                $expected_seq++;
                $total_checked++;
            }
        }

        self::clear_degraded_state();

        return [
            'broken_at_seq'   => null,
            'checked_records' => $total_checked,
            'details'         => sprintf('All %d records and retained checkpoints verified unbroken.', $total_checked),
            'status'          => 'verified',
        ];
    }

    /**
     * Universal hook listener for updated_option.
     *
     * @param string $option
     * @param mixed  $old_value
     * @param mixed  $value
     */
    public static function on_option_updated($option, $old_value, $value): void {
        if (!is_string($option) || !str_starts_with($option, 'wcpscan_')) {
            return;
        }

        // Ignore internal high-frequency operational / ledger / telemetry / volatile lock pointers
        // Also ignore options already explicitly instrumented with rich before/after activity logging
        $ignored_patterns = [
            'wcpscan_activity_',
            'wcpscan_install_hash',
            'wcpscan_transient_',
            'wcpscan_rate_limit_',
            '_transient_',
            'wcpscan_active_visitor_',
            'wcpscan_last_scan_state',
            'wcpscan_scan_checkpoint',
            'wcpscan_session_forensics_active_tokens',
            'wcpscan_db_last_audit',
            'wcpscan_active_scan_lock',
            'wcpscan_learning_route_profiles',
            'wcpscan_quarantine_manifest',
            'wcpscan_quarantine_remediation_journal',
            'wcpscan_circuit_breaker_',
            'wcpscan_crashguard_last_incident',
            'wcpscan_crash_history',
            'wcpscan_tor_exit_nodes',
            'wcpscan_threat_intel_network_meta',
            'wcpscan_threat_intel_consensus_ring',
            'wcpscan_threat_intel_reputation_log',
            'wcpscan_server_security_state',
            'wcpscan_gatekeeper_snapshots',
            'wcpscan_gatekeeper_logs',
            'wcpscan_gatekeeper_audit_logs',
            'wcpscan_outbound_egress_events',
            'wcpscan_prompt_injection_catches',
            'wcpscan_ghost_route_catches',
            'wcpscan_ghost_trap_catches',
            'wcpscan_blocked_ips_meta',
            'wcpscan_whitelisted_ips_meta',
            'wcpscan_webauthn_index',
            'wcpscan_threat_intel_ips',
            'wcpscan_threat_intel_meta',
            'wcpscan_threat_intel_cves',
            'wcpscan_self_defense_hashes',
            'wcpscan_self_defense_last_audit',
            'wcpscan_honeytoken_catches',
            'wcpscan_login_lockouts',
            'wcpscan_script_inventory_alerts',
            'wcpscan_script_inventory',
            'wcpscan_domain_reputation_report',
            'wcpscan_form_spam_stats',
            'wcpscan_form_spam_session_salt',
            'wcpscan_mcp_agent_audit',
            'wcpscan_mcp_staged_actions',
            'wcpscan_cf_deployed_edge_rules',
            'wcpscan_cloudflare_rate_limit_config',
            'wcpscan_remediation_backups',
            'wcpscan_vault_salt',
            'wcpscan_micro_waf_bypass_token',
            'wcpscan_micro_waf_chained_file',
            'wcpscan_ephemeral_admin_history',
            'wcpscan_dismissed_backups',
            'wcpscan_welcome_dismissed',
            'wcpscan_db_version',
            'wcpscan_activity_log_settings',
            'wcpscan_bot_ban_',
            'wcpscan_active_scan_lock',
            'wcpscan_learning_route_profiles',
            'wcpscan_learning_mode_profiles',
            'wcpscan_active_scan_lock_pid',
            'wcpscan_scan_progress',
            'wcpscan_live_scan_status',
            'wcpscan_waf_events',
            'wcpscan_waf_blocked_ips',

            // Subsystems that manage their own rich activity log emissions (prevent duplicate option watcher events)
            'wcpscan_settings',
            'wcpscan_rate_limiter_settings',
            'wcpscan_ghost_trap_settings',
            'wcpscan_honeytoken_settings',
            'wcpscan_learning_settings',
            'wcpscan_egress_settings',
            'wcpscan_prompt_guard_settings',
            'wcpscan_identity_forensics_settings',
            'wcpscan_gatekeeper_settings',
            'wcpscan_attack_surface_settings',
            'wcpscan_virtual_patches',
        ];

        foreach ($ignored_patterns as $pattern) {
            if (str_contains($option, $pattern)) {
                return;
            }
        }

        // Normalize comparison
        if ($old_value === $value) {
            return;
        }

        $req_sig = $option . '_' . md5(serialize($value));
        if (isset(self::$logged_options_in_request[$req_sig])) {
            return;
        }
        self::$logged_options_in_request[$req_sig] = true;

        // Determine category and human-readable action
        $category = self::resolve_option_category($option);
        $action = self::resolve_option_action($option);

        // Build diff structure
        $diff = [];
        if (is_array($old_value) && is_array($value)) {
            $all_keys = array_unique(array_merge(array_keys($old_value), array_keys($value)));
            foreach ($all_keys as $k) {
                $val_old = $old_value[$k] ?? null;
                $val_new = $value[$k] ?? null;
                if ($val_old !== $val_new) {
                    $diff[(string) $k] = [
                        'old' => $val_old,
                        'new' => $val_new,
                    ];
                }
            }
        } else {
            $diff[$option] = [
                'old' => $old_value,
                'new' => $value,
            ];
        }

        // If diff was already explicitly captured in this request, avoid duplicate noise
        $count = count($diff);
        if ($count === 0) {
            return;
        }

        $details = [
            'option'        => $option,
            'changed_count' => $count,
            'diff'          => $diff,
            'description'   => self::build_option_friendly_description($option, $count, $diff),
        ];

        self::notice($action, $category, $details);
    }

    /**
     * Universal hook listener for added_option.
     *
     * @param string $option
     * @param mixed  $value
     */
    public static function on_option_added($option, $value): void {
        if (!is_string($option) || !str_starts_with($option, 'wcpscan_')) {
            return;
        }

        self::on_option_updated($option, null, $value);
    }

    /**
     * Resolve option name to activity category.
     *
     * @param string $option
     * @return string
     */
    private static function resolve_option_category(string $option): string {
        if (str_contains($option, 'firewall') || str_contains($option, 'waf') || str_contains($option, 'patch') || str_contains($option, 'trap') || str_contains($option, 'honey') || str_contains($option, 'egress') || str_contains($option, 'cloudflare')) {
            return 'firewall';
        }
        if (str_contains($option, 'quarantine') || str_contains($option, 'reinfection')) {
            return 'quarantine';
        }
        if (str_contains($option, 'custom_scan') || str_contains($option, 'scan_schedule') || str_contains($option, 'scheduled_scan')) {
            return 'scan';
        }
        return 'settings';
    }

    /**
     * Resolve option name to clean action key.
     *
     * @param string $option
     * @return string
     */
    private static function resolve_option_action(string $option): string {
        if (str_contains($option, 'virtual_patches') || str_contains($option, 'synthesized_virtual_patches')) {
            return 'virtual_patch_rules_modified';
        }
        if (str_contains($option, 'whitelist')) {
            return 'whitelist_policy_modified';
        }
        if (str_contains($option, 'cloudflare_rate_limit')) {
            return 'cloudflare_rate_limit_modified';
        }
        if (str_contains($option, 'cloudflare_deployed')) {
            return 'cloudflare_rules_modified';
        }
        if (str_contains($option, 'settings')) {
            return 'settings_updated';
        }
        return 'policy_updated';
    }

    /**
     * Build non-technical friendly summary description for changed options.
     *
     * @param string $option
     * @param int    $count
     * @param array  $diff
     * @return string
     */
    private static function build_option_friendly_description(string $option, int $count, array $diff): string {
        $keys = array_keys($diff);
        $keys_summary = implode(', ', array_slice($keys, 0, 3));
        if (count($keys) > 3) {
            $keys_summary .= ' +' . (count($keys) - 3) . ' more';
        }

        if (str_contains($option, 'virtual_patches')) {
            return sprintf('Updated active virtual exploit shields (%d rule definition%s altered).', $count, $count === 1 ? '' : 's');
        }
        if (str_contains($option, 'micro_waf_status')) {
            return 'Standalone Pre-Boot Micro-WAF script recompiled into wp-content/micro-waf.php to enforce active rules, IP blocklists, and CAF policies.';
        }
        if (str_contains($option, 'ip_reputation_log')) {
            return 'Updated threat risk scores and behavioral evaluation cache for client IP addresses.';
        }
        if (str_contains($option, 'blocked_ips_meta')) {
            return 'Synchronized expiration timestamps and strike counters for blocked IP addresses.';
        }
        if (str_contains($option, 'self_defense_last_audit')) {
            return 'Automated background audit verified plugin file hashes and manifests against tampering.';
        }
        if (str_contains($option, 'wizard_completed')) {
            return 'Completed initial security onboarding setup wizard and applied baseline hardening.';
        }
        if (str_contains($option, 'site_archetype')) {
            $arch = is_string($diff['wcpscan_site_archetype']['new'] ?? null) ? $diff['wcpscan_site_archetype']['new'] : 'Standard';
            return sprintf('Configured security scanner posture for site profile "%s".', ucfirst($arch));
        }
        if (str_contains($option, 'server_security_options')) {
            return 'Updated server armor security directives for .htaccess / Nginx.';
        }
        if (str_contains($option, 'waf_whitelisted_ips')) {
            return sprintf('Updated trusted IP allowlist (%d IP address%s permitted to bypass WAF inspection).', $count, $count === 1 ? '' : 'es');
        }
        if (str_contains($option, 'waf_settings')) {
            return sprintf('Updated Web Application Firewall inspection parameters (%d setting%s: %s).', $count, $count === 1 ? '' : 's', $keys_summary);
        }
        if (str_contains($option, 'notification_settings')) {
            return sprintf('Updated security alert delivery channels and email notifications (%d setting%s).', $count, $count === 1 ? '' : 's');
        }
        if (str_contains($option, 'whitelist')) {
            return sprintf('Modified false positive suppression rules (%d rule%s adjusted: %s).', $count, $count === 1 ? '' : 's', $keys_summary);
        }
        if (str_contains($option, 'cloudflare')) {
            return sprintf('Synchronized Cloudflare Edge configuration (%d setting%s: %s).', $count, $count === 1 ? '' : 's', $keys_summary);
        }
        if (str_contains($option, 'settings')) {
            return sprintf('Updated plugin security parameters (%d setting%s: %s).', $count, $count === 1 ? '' : 's', $keys_summary);
        }

        return sprintf('Configuration adjusted for %s (%d parameter%s: %s).', str_replace('wcpscan_', '', $option), $count, $count === 1 ? '' : 's', $keys_summary);
    }
}
