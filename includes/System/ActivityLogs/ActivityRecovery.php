<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Crash Recovery & Forensic Tail Inspection Coordinator.
 *
 * Responsibilities:
 * 1. Reconcile Write-Ahead Log (.journal.json.php) against active segment tails on startup.
 * 2. Detect damaged, malformed, or incomplete trailing records without silently truncating them.
 * 3. Quarantine damaged fragments with SHA-256 dumps into .forensic-quarantine/.
 * 4. Transition system into explicit recovery_required / degraded states when evidence is found.
 */
class ActivityRecovery {

    /**
     * Get absolute path to the forensic quarantine directory.
     *
     * @return string
     */
    public static function get_quarantine_dir(): string {
        $dir = ActivityStorage::get_log_dir() . '/.forensic-quarantine';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            @file_put_contents($dir . '/index.php', "<?php\nexit;\n");
            @file_put_contents($dir . '/.htaccess', "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n");
        }
        return $dir;
    }

    /**
     * Reconcile WAL journal and inspect storage consistency.
     *
     * @return array Status array with ['reconciled' => bool, 'action' => string, 'error' => ?string]
     */
    public static function reconcile_wal(): array {
        $journal_path = ActivityStorage::get_journal_path();
        if (!file_exists($journal_path)) {
            return ['reconciled' => true, 'action' => 'none', 'error' => null];
        }

        $raw = @file_get_contents($journal_path);
        if (empty($raw)) {
            wp_delete_file($journal_path);
            return ['reconciled' => true, 'action' => 'empty_journal_cleared', 'error' => null];
        }

        // Strip PHP stub
        if (strpos($raw, ActivityStorage::PHP_HEADER_STUB) === 0) {
            $raw = substr($raw, strlen(ActivityStorage::PHP_HEADER_STUB));
        }

        $journal = json_decode($raw, true);
        if (!is_array($journal) || empty($journal['status'])) {
            wp_delete_file($journal_path);
            return ['reconciled' => true, 'action' => 'malformed_journal_cleared', 'error' => null];
        }

        // If journal transaction was already marked committed, clean it up
        if ($journal['status'] === 'committed') {
            wp_delete_file($journal_path);
            return ['reconciled' => true, 'action' => 'committed_journal_cleared', 'error' => null];
        }

        // Handle PENDING WAL transaction
        if ($journal['status'] === 'pending') {
            $seq = (int) ($journal['seq'] ?? 0);
            $h = (string) ($journal['h'] ?? '');
            $target_segment = (string) ($journal['target_segment'] ?? '');
            $envelope = $journal['envelope'] ?? [];

            if (empty($target_segment) || empty($envelope)) {
                wp_delete_file($journal_path);
                return ['reconciled' => false, 'action' => 'invalid_pending_journal_discarded', 'error' => 'Pending journal missing envelope or target segment'];
            }

            $segment_path = ActivityStorage::get_log_dir() . '/' . $target_segment;
            $tail_line = self::read_last_line($segment_path);

            // Case A: Partition tail contains the exact matching pending envelope (write succeeded before crash)
            $expected_json = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (trim($tail_line) === trim($expected_json)) {
                // Update chain state to commit the write
                ActivityStorage::write_chain_state($seq, $h, $target_segment);
                wp_delete_file($journal_path);
                return [
                    'action'     => 'pending_transaction_committed',
                    'error'      => null,
                    'reconciled' => true,
                ];
            }

            // Case B: Partition tail is damaged or partially written
            if (!empty($tail_line) && !self::is_valid_json_envelope($tail_line)) {
                self::quarantine_damaged_tail($segment_path, $tail_line, 'Interrupted write mismatch with pending WAL');
                wp_delete_file($journal_path);
                return [
                    'action'     => 'damaged_tail_quarantined',
                    'error'      => 'Incomplete partition tail detected and quarantined',
                    'reconciled' => false,
                ];
            }

            // Case C: Partition tail does not have the record (append failed before reaching disk)
            wp_delete_file($journal_path);
            return [
                'action'     => 'pending_transaction_rolled_back',
                'error'      => null,
                'reconciled' => true,
            ];
        }

        return ['reconciled' => true, 'action' => 'none', 'error' => null];
    }

    /**
     * Read the last non-empty line of a partition file.
     *
     * @param string $file_path
     * @return string
     */
    public static function read_last_line(string $file_path): string {
        if (!file_exists($file_path)) {
            return '';
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($file_path, 'rb');
        if (!$fp) {
            return '';
        }

        $pos = -1;
        $line = '';
        $char = '';

        @fseek($fp, $pos, SEEK_END);
        $char = @fgetc($fp);

        // Scan backward past trailing newlines
        while ($char === "\r" || $char === "\n") {
            $pos--;
            if (@fseek($fp, $pos, SEEK_END) === -1) {
                break;
            }
            $char = @fgetc($fp);
        }

        // Read backward until start of line
        while ($char !== false && $char !== "\n" && $char !== "\r") {
            $line = $char . $line;
            $pos--;
            if (@fseek($fp, $pos, SEEK_END) === -1) {
                break;
            }
            $char = @fgetc($fp);
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);
        return trim($line);
    }

    /**
     * Check if a string is a valid activity envelope JSON object.
     *
     * @param string $line
     * @return bool
     */
    public static function is_valid_json_envelope(string $line): bool {
        if (empty($line) || strpos($line, '<?php') === 0) {
            return false;
        }
        $data = json_decode($line, true);
        return is_array($data) && isset($data['v'], $data['k_ver'], $data['seq'], $data['event_id'], $data['c'], $data['h']);
    }

    /**
     * Quarantine damaged trailing bytes to the evidence folder.
     *
     * @param string $file_path
     * @param string $damaged_bytes
     * @param string $reason
     * @return string Quarantined dump path.
     */
    public static function quarantine_damaged_tail(string $file_path, string $damaged_bytes, string $reason): string {
        $q_dir = self::get_quarantine_dir();
        $timestamp = gmdate('Ymd_His');
        $file_base = sanitize_file_name(basename($file_path));
        $dump_file = sprintf('%s/%s_%s.dump', $q_dir, $timestamp, $file_base);

        $dump_data = [
            'damaged_bytes_b64' => base64_encode($damaged_bytes),
            'damaged_hash'      => hash('sha256', $damaged_bytes),
            'detected_at_utc'   => gmdate('Y-m-d\TH:i:s\Z'),
            'original_file'     => $file_base,
            'reason'            => $reason,
        ];

        @file_put_contents($dump_file, ActivityStorage::PHP_HEADER_STUB . json_encode($dump_data, JSON_PRETTY_PRINT));
        return $dump_file;
    }
}
