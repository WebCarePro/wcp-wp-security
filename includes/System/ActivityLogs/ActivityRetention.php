<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Retention Policy & Hash-Chained Checkpoint Ledger Engine.
 *
 * Implements:
 * 1. Strict 7-day UTC minimum immutability (deletions within last 7 days are strictly forbidden).
 * 2. Entire partition-level pruning (individual record deletion is barred to preserve chain integrity).
 * 3. Chained Checkpoint Ledger (.checkpoints.json.php):
 *    H_{chk,m} = SHA256( H_{chk,m-1} || CanonicalCheckpoint_m ).
 * 4. Audit trail emission for every retention pruning event.
 */
class ActivityRetention {

    const MINIMUM_IMMUTABILITY_DAYS = 7;

    /**
     * Get path to checkpoint ledger file.
     *
     * @return string
     */
    public static function get_checkpoint_path(): string {
        return ActivityStorage::get_log_dir() . '/.checkpoints.json.php';
    }

    /**
     * Get stable checkpoint genesis hash (H_{chk,0}).
     *
     * @return string
     */
    public static function get_checkpoint_genesis_hash(): string {
        $install_hash = get_option('wcpscan_install_hash', 'wcp_default_seed');
        return hash('sha256', 'WCP_CHECKPOINT_GENESIS::' . $install_hash);
    }

    /**
     * Read all recorded checkpoints in chronological sequence.
     *
     * @return array List of checkpoint entries.
     */
    public static function read_checkpoints(): array {
        $path = self::get_checkpoint_path();
        if (!file_exists($path)) {
            return [];
        }

        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (empty($lines)) {
            return [];
        }

        $checkpoints = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '<?php') === 0) {
                continue;
            }
            $entry = json_decode($line, true);
            if (is_array($entry) && isset($entry['checkpoint_id'], $entry['checkpoint_hash'])) {
                $checkpoints[] = $entry;
            }
        }

        return $checkpoints;
    }

    /**
     * Get configured retention policy in days.
     * (Defaults to 30 days; minimum enforced is 7 days).
     *
     * @return int Days (0 = Forever / no auto-prune).
     */
    public static function get_retention_days(): int {
        $settings = function_exists('get_option') ? get_option('wcpscan_activity_log_settings', []) : [];
        $days = isset($settings['retention_days']) ? (int) $settings['retention_days'] : 30;
        if ($days === 0) {
            return 0; // Forever
        }
        return max(self::MINIMUM_IMMUTABILITY_DAYS, $days);
    }

    /**
     * Check if a partition date is eligible for retention pruning.
     * Partitions within 7 days of UTC now are ALWAYS strictly immutable.
     *
     * @param string $partition_date YYYY-MM-DD
     * @return bool True if eligible for pruning.
     */
    public static function is_partition_eligible_for_prune(string $partition_date): bool {
        $configured_days = self::get_retention_days();
        if ($configured_days === 0) {
            return false; // Forever retention configured
        }

        $effective_days = max(self::MINIMUM_IMMUTABILITY_DAYS, $configured_days);
        $date_ts = strtotime($partition_date . ' 23:59:59 UTC');
        if ($date_ts === false) {
            return false;
        }

        $cutoff_ts = time() - ($effective_days * 86400);
        return $date_ts < $cutoff_ts;
    }

    /**
     * Prune expired partitions that satisfy the retention policy, compiling
     * a chained checkpoint for each deleted partition file.
     *
     * @return array Results array.
     */
    public static function prune_expired_partitions(): array {
        $dir = ActivityStorage::get_log_dir();
        $pattern = $dir . '/activity-*-*.json.php';
        $files = glob($pattern);
        if (empty($files)) {
            return ['pruned_count' => 0, 'files' => []];
        }

        sort($files);
        $pruned_files = [];

        foreach ($files as $file_path) {
            $filename = basename($file_path);
            if (preg_match('/activity-(\d{4}-\d{2}-\d{2})-\d{3}\.json\.php$/', $filename, $m)) {
                $partition_date = $m[1];
                if (self::is_partition_eligible_for_prune($partition_date)) {
                    $result = self::prune_single_partition($file_path, $filename);
                    if ($result) {
                        $pruned_files[] = $filename;
                    }
                }
            }
        }

        return [
            'files'        => $pruned_files,
            'pruned_count' => count($pruned_files),
        ];
    }

    /**
     * Compile checkpoint for a single partition and delete the file.
     *
     * @param string $file_path
     * @param string $filename
     * @return bool
     */
    private static function prune_single_partition(string $file_path, string $filename): bool {
        $lines = @file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (empty($lines)) {
            return wp_delete_file($file_path);
        }

        $first_seq = null;
        $last_seq = null;
        $first_prev_hash = null;
        $closing_hash = null;
        $record_count = 0;

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '<?php') === 0) {
                continue;
            }
            $env = json_decode($line, true);
            if (is_array($env) && isset($env['seq'], $env['h'])) {
                if ($first_seq === null) {
                    $first_seq = (int) $env['seq'];
                    // Read decrypted or inner prev_hash if possible
                    try {
                        $decrypted = ActivityHashChain::decrypt_envelope($env);
                        $first_prev_hash = (string) ($decrypted['prev_hash'] ?? '');
                    } catch (\Throwable $e) {
                        $first_prev_hash = 'unknown_corrupted';
                    }
                }
                $last_seq = (int) $env['seq'];
                $closing_hash = (string) $env['h'];
                $record_count++;
            }
        }

        // If partition had valid records, commit checkpoint before deleting
        if ($record_count > 0 && $first_seq !== null && $last_seq !== null) {
            self::append_checkpoint([
                'closing_hash'          => (string) $closing_hash,
                'first_prev_hash'       => (string) $first_prev_hash,
                'first_seq'             => (int) $first_seq,
                'last_seq'              => (int) $last_seq,
                'partition_file'        => (string) $filename,
                'pruned_at_utc'         => gmdate('Y-m-d\TH:i:s\Z'),
                'pruned_by_actor'       => [
                    'identifier' => 'wcpscan_daily_maintenance',
                    'type'       => 'system',
                ],
                'record_count'          => (int) $record_count,
                'retention_policy_days' => self::get_retention_days(),
                'v'                     => 1,
            ]);
        }

        // Delete file using WordPress filesystem wrapper
        return wp_delete_file($file_path);
    }

    /**
     * Append a new cryptographically chained checkpoint to .checkpoints.json.php.
     *
     * @param array $checkpoint_payload
     * @return bool
     */
    public static function append_checkpoint(array $checkpoint_payload): bool {
        $existing = self::read_checkpoints();
        $prev_chk_hash = !empty($existing) ? end($existing)['checkpoint_hash'] : self::get_checkpoint_genesis_hash();
        $chk_seq = count($existing) + 1;

        $checkpoint_payload['checkpoint_id'] = 'chk_' . wp_generate_password(16, false, false);
        $checkpoint_payload['checkpoint_seq'] = $chk_seq;
        $checkpoint_payload['previous_checkpoint_hash'] = $prev_chk_hash;

        // Compute canonical checkpoint hash
        ksort($checkpoint_payload, SORT_STRING);
        $json = json_encode($checkpoint_payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $chk_hash = hash('sha256', $prev_chk_hash . $json);
        $checkpoint_payload['checkpoint_hash'] = $chk_hash;

        // Append line to checkpoints file
        $path = self::get_checkpoint_path();
        $is_new = !file_exists($path);
        $line = json_encode($checkpoint_payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";

        // Direct file operations are required for atomic append and flock advisory locking
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($path, 'ab');
        if (!$fp) {
            return false;
        }

        flock($fp, LOCK_EX);
        if ($is_new) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($fp, ActivityStorage::PHP_HEADER_STUB);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
        fwrite($fp, $line);
        fflush($fp);
        flock($fp, LOCK_UN);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);

        return true;
    }
}
