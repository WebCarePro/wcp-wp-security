<?php
namespace WcpScanner\System;

use WcpScanner\System\ActivityLogs\ActivityCanonicalizer;
use WcpScanner\System\ActivityLogs\ActivityEventSchema;
use WcpScanner\System\ActivityLogs\ActivityHashChain;
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

            // Step 4: Write WAL pending journal transaction
            $journal_payload = [
                'envelope'       => $envelope,
                'h'              => $record_hash,
                'seq'            => $next_seq,
                'status'         => 'pending',
                'target_segment' => $target_segment,
                'timestamp'      => time(),
            ];
            $journal_json = ActivityStorage::PHP_HEADER_STUB . json_encode($journal_payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            @file_put_contents(ActivityStorage::get_journal_path(), $journal_json, LOCK_EX);

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

            // Step 6: Commit new chain state
            ActivityStorage::write_chain_state($next_seq, $record_hash, $target_segment);

            // Step 7: Clear journal transaction
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
     * Read records with cursor pagination and filters.
     *
     * @param array $args ['cursor' => string, 'limit' => int, 'category' => string, 'actor_type' => string, 'severity' => string, 'search' => string]
     * @return array ['records' => array, 'next_cursor' => ?string, 'total_read' => int]
     */
    public static function query_records(array $args = []): array {
        $limit = isset($args['limit']) ? min(100, max(1, (int) $args['limit'])) : 50;
        $category = !empty($args['category']) ? sanitize_key($args['category']) : null;
        $actor_type = !empty($args['actor_type']) ? sanitize_key($args['actor_type']) : null;
        $severity = !empty($args['severity']) ? sanitize_key($args['severity']) : null;
        $search = !empty($args['search']) ? strtolower(sanitize_text_field($args['search'])) : null;

        $dir = ActivityStorage::get_log_dir();
        $files = glob($dir . '/activity-*-*.json.php');
        if (empty($files)) {
            return ['next_cursor' => null, 'records' => [], 'total_read' => 0];
        }

        // Sort descending to read newest records first
        rsort($files);

        $matched_records = [];
        $total_examined = 0;

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

                $total_examined++;

                try {
                    $record = ActivityHashChain::decrypt_envelope($envelope);
                } catch (\Throwable $e) {
                    continue;
                }

                // Filter Category
                if ($category && ($record['category'] ?? '') !== $category) {
                    continue;
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

                $matched_records[] = $record;
                if (count($matched_records) >= $limit) {
                    break 2;
                }
            }
        }

        return [
            'next_cursor' => null, // Cursor pagination will be refined in Phase 3
            'records'     => $matched_records,
            'total_read'  => count($matched_records),
        ];
    }

    /**
     * Run full cryptographic verification across active partitions and Checkpoint Ledger.
     *
     * @return array Verification report.
     */
    public static function verify_integrity(): array {
        // Step 1: Reconcile any lingering WAL state
        ActivityRecovery::reconcile_wal();

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

        // If checkpoints exist, verify checkpoint chain
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
}
