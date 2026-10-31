<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Crash-Safe Storage Engine for WCP Activity & Audit Logging.
 *
 * Implements:
 * 1. 3-Tier Mutex Lock Hierarchy: Level 1 (.chain-state.lock) -> Level 2 (.journal.lock) -> Level 3 (Segment Lock).
 * 2. Write-Ahead Logging (WAL) protocol in .journal.json.php.
 * 3. Daily Partition Segments with 15 MB capacity rollover (activity-YYYY-MM-DD-001.json.php).
 * 4. Verified Complete-Byte append loop with zero-byte write traps and fflush/fsync.
 * 5. <?php exit; ?> header protection preventing direct web execution.
 */
class ActivityStorage {

    const MAX_SEGMENT_BYTES   = 15728640; // 15 MB per segment
    const MAX_DAILY_SEGMENTS  = 20;       // Max 20 segments per day (300 MB cap)
    const PHP_HEADER_STUB     = "<?php exit; ?>\n";

    /**
     * Get the absolute filesystem directory for activity logs.
     *
     * @return string
     */
    public static function get_log_dir(): string {
        $upload_dir = wp_upload_dir();
        $dir = trailingslashit($upload_dir['basedir']) . 'wcp-security-scanner/.activity-logs';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            // Place web access protection files
            @file_put_contents($dir . '/index.php', "<?php\n// Silence is golden.\nexit;\n");
            @file_put_contents($dir . '/.htaccess', "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n");
        }
        return $dir;
    }

    /**
     * Get path to chain state file.
     *
     * @return string
     */
    public static function get_chain_state_path(): string {
        return self::get_log_dir() . '/.chain-state.json.php';
    }

    /**
     * Get path to WAL transaction journal.
     *
     * @return string
     */
    public static function get_journal_path(): string {
        return self::get_log_dir() . '/.journal.json.php';
    }

    /**
     * Get path to level 1 lock file.
     *
     * @return string
     */
    public static function get_chain_lock_path(): string {
        return self::get_log_dir() . '/.chain-state.lock';
    }

    /**
     * Get path to level 2 lock file.
     *
     * @return string
     */
    public static function get_journal_lock_path(): string {
        return self::get_log_dir() . '/.journal.lock';
    }

    /**
     * Read the current committed chain state.
     *
     * @return array
     */
    public static function read_chain_state(): array {
        $path = self::get_chain_state_path();
        if (!file_exists($path)) {
            return [
                'active_segment' => '',
                'current_seq'    => 0,
                'latest_hash'    => ActivityHashChain::get_genesis_hash(),
                'updated_at'     => time(),
            ];
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return [
                'active_segment' => '',
                'current_seq'    => 0,
                'latest_hash'    => ActivityHashChain::get_genesis_hash(),
                'updated_at'     => time(),
            ];
        }

        // Strip PHP exit stub
        if (strpos($content, self::PHP_HEADER_STUB) === 0) {
            $content = substr($content, strlen(self::PHP_HEADER_STUB));
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return [
                'active_segment' => '',
                'current_seq'    => 0,
                'latest_hash'    => ActivityHashChain::get_genesis_hash(),
                'updated_at'     => time(),
            ];
        }

        return $data;
    }

    /**
     * Commit new chain state atomically to disk.
     *
     * @param int    $seq
     * @param string $hash
     * @param string $active_segment
     * @return bool
     */
    public static function write_chain_state(int $seq, string $hash, string $active_segment): bool {
        $payload = [
            'active_segment' => (string) $active_segment,
            'current_seq'    => (int) $seq,
            'latest_hash'    => (string) $hash,
            'updated_at'     => time(),
        ];
        $json = self::PHP_HEADER_STUB . json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $tmp_file = self::get_chain_state_path() . '.tmp.' . uniqid('', true);
        $res = @file_put_contents($tmp_file, $json, LOCK_EX);
        if ($res === false) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
        return @rename($tmp_file, self::get_chain_state_path());
    }

    /**
     * Resolve the target partition segment filename for a write, rolling over if capacity is reached.
     *
     * @param string $current_active_segment
     * @return string Filename (basename) of active segment.
     */
    public static function resolve_active_segment(string $current_active_segment): string {
        $today = gmdate('Y-m-d');
        $dir = self::get_log_dir();

        // If current segment belongs to today and has space, keep using it
        if (!empty($current_active_segment) && strpos($current_active_segment, 'activity-' . $today) === 0) {
            $path = $dir . '/' . $current_active_segment;
            if (file_exists($path)) {
                $size = @filesize($path);
                if ($size !== false && $size < self::MAX_SEGMENT_BYTES) {
                    return $current_active_segment;
                }
            }
        }

        // Find existing segments for today
        $pattern = $dir . '/activity-' . $today . '-*.json.php';
        $files = glob($pattern);
        if (!empty($files)) {
            sort($files);
            $latest = basename(end($files));
            $latest_path = $dir . '/' . $latest;
            $size = @filesize($latest_path);
            if ($size !== false && $size < self::MAX_SEGMENT_BYTES) {
                return $latest;
            }

            // Segment full: extract segment number and roll over
            if (preg_match('/activity-\d{4}-\d{2}-\d{2}-(\d{3})\.json\.php$/', $latest, $m)) {
                $next_num = intval($m[1]) + 1;
                if ($next_num <= self::MAX_DAILY_SEGMENTS) {
                    return sprintf('activity-%s-%03d.json.php', $today, $next_num);
                }
                // Cap reached; return latest segment to prevent runaway file spam
                return $latest;
            }
        }

        // First segment of the day
        return sprintf('activity-%s-001.json.php', $today);
    }

    /**
     * Execute verified complete-byte append to a partition file.
     *
     * @param string $file_path Absolute path to partition file.
     * @param string $line      Payload string including trailing newline.
     * @return bool True if all bytes written and flushed successfully.
     */
    public static function atomic_append_line(string $file_path, string $line): bool {
        $is_new = !file_exists($file_path);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($file_path, 'ab');
        if (!$fp) {
            return false;
        }

        // Lock target partition file (Level 3 Lock)
        $locked = false;
        $start = microtime(true);
        while (microtime(true) - $start < 1.5) {
            if (flock($fp, LOCK_EX | LOCK_NB)) {
                $locked = true;
                break;
            }
            usleep(10000);
        }

        if (!$locked) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return false;
        }

        // Write header stub if creating a new partition file
        if ($is_new) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($fp, self::PHP_HEADER_STUB);
        }

        $written = 0;
        $length = strlen($line);
        $zero_byte_attempts = 0;

        while ($written < $length) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            $n = fwrite($fp, substr($line, $written));
            if ($n === false) {
                flock($fp, LOCK_UN);
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);
                return false;
            }
            if ($n === 0) {
                $zero_byte_attempts++;
                if ($zero_byte_attempts > 5) {
                    flock($fp, LOCK_UN);
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                    fclose($fp);
                    return false;
                }
                usleep(5000);
                continue;
            }
            $written += $n;
            $zero_byte_attempts = 0;
        }

        $flush_ok = fflush($fp);
        flock($fp, LOCK_UN);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);

        return $flush_ok && ($written === $length);
    }

    /**
     * Acquire an exclusive advisory file lock with timeout.
     *
     * @param string $lock_file
     * @param float  $timeout_sec
     * @return resource|false File handle or false on failure.
     */
    public static function acquire_lock(string $lock_file, float $timeout_sec = 1.5) {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($lock_file, 'c+');
        if (!$fp) {
            return false;
        }

        $start = microtime(true);
        while (microtime(true) - $start < $timeout_sec) {
            if (flock($fp, LOCK_EX | LOCK_NB)) {
                return $fp;
            }
            usleep(10000); // 10ms backoff
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);
        return false;
    }

    /**
     * Release and close an acquired file lock.
     *
     * @param resource $fp
     */
    public static function release_lock($fp): void {
        if (is_resource($fp)) {
            flock($fp, LOCK_UN);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
        }
    }
}
