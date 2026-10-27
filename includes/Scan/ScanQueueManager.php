<?php
namespace WcpScanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * High-performance, zero-allocation streaming session queue manager.
 * Stores large file lists in temporary session stream files on disk
 * using cursor offsets, with seamless fallback to transients.
 */
class ScanQueueManager {

    const SESSIONS_DIR_NAME = 'wcp-security-scanner/scan-sessions';
    const QUEUE_FILE_NAME = 'queue.txt';
    const META_FILE_NAME = 'meta.json';
    const TRANSIENT_QUEUE_PREFIX = 'wcpscan_scan_queue_';
    const TRANSIENT_META_PREFIX = 'wcpscan_queue_meta_';

    /**
     * Get or create the base sessions directory.
     * Ensures .htaccess and index.php protection.
     *
     * @return string|false Absolute path to base sessions dir, or false if not writable
     */
    public static function get_base_sessions_dir() {
        $upload_dir = wp_upload_dir();
        if (!empty($upload_dir['error']) || empty($upload_dir['basedir'])) {
            return false;
        }

        $base = wp_normalize_path(untrailingslashit($upload_dir['basedir']) . '/' . self::SESSIONS_DIR_NAME);
        if (!is_dir($base)) {
            if (!wp_mkdir_p($base)) {
                return false;
            }
        }

        if (!wp_is_writable($base)) {
            return false;
        }

        self::protect_directory($base);

        return $base;
    }

    /**
     * Get or create the session directory for a specific scan ID.
     *
     * @param int|string $scan_id
     * @param bool $create
     * @return string|false
     */
    public static function get_session_dir($scan_id, bool $create = false) {
        $base = self::get_base_sessions_dir();
        if (!$base) {
            return false;
        }

        $clean_id = (int) $scan_id;
        if ($clean_id <= 0) {
            return false;
        }

        $dir = $base . '/' . $clean_id;

        if ($create && !is_dir($dir)) {
            if (!wp_mkdir_p($dir)) {
                return false;
            }
            self::protect_directory($dir);
        }

        return is_dir($dir) ? $dir : ($create ? false : false);
    }

    /**
     * Protect directory with .htaccess and empty index.php.
     *
     * @param string $dir
     */
    public static function protect_directory(string $dir): void {
        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }

        $htaccess = $dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($htaccess, $rules);
        }
    }

    /**
     * Initialize the scan queue for a scan session.
     * Streams scannable files from given directories directly to disk (or transient fallback).
     *
     * @param int|string $scan_id
     * @param array $paths Array of directory paths to scan
     * @param int $file_limit Optional file limit
     * @return int Total files enqueued
     */
    public static function init_queue($scan_id, array $paths, int $file_limit = 0): int {
        // Clean up any stale sessions older than 2 hours first
        self::cleanup_expired_sessions(7200);

        $session_dir = self::get_session_dir($scan_id, true);
        $use_disk = ($session_dir !== false && wp_is_writable($session_dir));

        $total_files = 0;
        $unique_paths = array_unique($paths);

        if ($use_disk) {
            $queue_file = $session_dir . '/' . self::QUEUE_FILE_NAME;
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $fp = @fopen($queue_file, 'wb');

            if ($fp) {
                // Stream files directly into file with zero RAM accumulation
                foreach ($unique_paths as $path) {
                    if (!is_dir($path)) {
                        continue;
                    }
                    $remaining_limit = $file_limit > 0 ? max(0, $file_limit - $total_files) : 0;
                    if ($file_limit > 0 && $remaining_limit <= 0) {
                        break;
                    }

                    \WcpScanner\Scanner\Engine::stream_scannable_files($path, function ($filepath) use ($fp, &$total_files) {
                        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                        fwrite($fp, $filepath . "\n");
                        $total_files++;
                    }, $remaining_limit);
                }

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
                fclose($fp);

                $meta = [
                    'scan_id'         => (int) $scan_id,
                    'storage_mode'    => 'disk',
                    'total_files'     => $total_files,
                    'processed_count' => 0,
                    'cursor_offset'   => 0,
                    'created_at'      => time(),
                ];
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                @file_put_contents($session_dir . '/' . self::META_FILE_NAME, wp_json_encode($meta));

                return $total_files;
            }
        }

        // Fallback: transient queue
        $all_files = [];
        foreach ($unique_paths as $path) {
            if (!is_dir($path)) {
                continue;
            }
            $remaining_limit = $file_limit > 0 ? max(0, $file_limit - count($all_files)) : 0;
            if ($file_limit > 0 && $remaining_limit <= 0) {
                break;
            }
            $all_files = array_merge($all_files, \WcpScanner\Scanner\Engine::get_scannable_files($path, $remaining_limit));
        }

        $total_files = count($all_files);
        set_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id, $all_files, HOUR_IN_SECONDS);
        set_transient(self::TRANSIENT_META_PREFIX . $scan_id, [
            'scan_id'         => (int) $scan_id,
            'storage_mode'    => 'transient',
            'total_files'     => $total_files,
            'processed_count' => 0,
            'created_at'      => time(),
        ], HOUR_IN_SECONDS);

        return $total_files;
    }

    /**
     * Get the next batch of files to process.
     *
     * @param int|string $scan_id
     * @param int $batch_size
     * @return array Array with ['files', 'line_bytes', 'remaining', 'total', 'storage_mode']
     */
    public static function get_batch($scan_id, int $batch_size = 50): array {
        $meta = self::get_meta($scan_id);
        if (!$meta) {
            // Check legacy transient fallback
            $legacy_queue = get_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
            if (is_array($legacy_queue)) {
                $files = array_slice($legacy_queue, 0, $batch_size);
                return [
                    'files'        => $files,
                    'line_bytes'   => [],
                    'remaining'    => count($legacy_queue),
                    'total'        => count($legacy_queue),
                    'storage_mode' => 'transient',
                ];
            }
            return [
                'files'        => [],
                'line_bytes'   => [],
                'remaining'    => 0,
                'total'        => 0,
                'storage_mode' => 'none',
            ];
        }

        if (($meta['storage_mode'] ?? 'disk') === 'disk') {
            $session_dir = self::get_session_dir($scan_id);
            if (!$session_dir) {
                return ['files' => [], 'line_bytes' => [], 'remaining' => 0, 'total' => 0, 'storage_mode' => 'none'];
            }

            $queue_file = $session_dir . '/' . self::QUEUE_FILE_NAME;
            if (!file_exists($queue_file)) {
                return ['files' => [], 'line_bytes' => [], 'remaining' => 0, 'total' => 0, 'storage_mode' => 'none'];
            }

            $cursor = (int) ($meta['cursor_offset'] ?? 0);
            $total = (int) ($meta['total_files'] ?? 0);
            $processed = (int) ($meta['processed_count'] ?? 0);
            $remaining = max(0, $total - $processed);

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
            $fp = @fopen($queue_file, 'rb');
            if (!$fp) {
                return ['files' => [], 'line_bytes' => [], 'remaining' => 0, 'total' => 0, 'storage_mode' => 'none'];
            }

            if ($cursor > 0) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fseek
                fseek($fp, $cursor);
            }

            $files = [];
            $line_bytes = [];

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_feof
            while (!feof($fp) && count($files) < $batch_size) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fgets
                $line = fgets($fp);
                if ($line === false) {
                    break;
                }
                $bytes = strlen($line);
                $trimmed = trim($line);
                if ($trimmed !== '') {
                    $files[] = $trimmed;
                    $line_bytes[] = $bytes;
                }
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);

            return [
                'files'        => $files,
                'line_bytes'   => $line_bytes,
                'remaining'    => $remaining,
                'total'        => $total,
                'storage_mode' => 'disk',
            ];
        }

        // Transient mode
        $queue = get_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
        if (!is_array($queue)) {
            return ['files' => [], 'line_bytes' => [], 'remaining' => 0, 'total' => 0, 'storage_mode' => 'transient'];
        }

        $files = array_slice($queue, 0, $batch_size);
        return [
            'files'        => $files,
            'line_bytes'   => [],
            'remaining'    => count($queue),
            'total'        => (int) ($meta['total_files'] ?? count($queue)),
            'storage_mode' => 'transient',
        ];
    }

    /**
     * Advance the queue cursor after processing a batch.
     *
     * @param int|string $scan_id
     * @param int $processed_count Number of files actually processed
     * @param int $bytes_consumed Byte count consumed in disk mode
     * @return int Remaining count
     */
    public static function advance($scan_id, int $processed_count, int $bytes_consumed = 0): int {
        $meta = self::get_meta($scan_id);
        if (!$meta) {
            // Legacy transient fallback
            $queue = get_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
            if (is_array($queue)) {
                array_splice($queue, 0, $processed_count);
                if (empty($queue)) {
                    delete_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
                    return 0;
                }
                set_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id, $queue, HOUR_IN_SECONDS);
                return count($queue);
            }
            return 0;
        }

        if (($meta['storage_mode'] ?? 'disk') === 'disk') {
            $session_dir = self::get_session_dir($scan_id);
            if (!$session_dir) {
                return 0;
            }

            $meta['cursor_offset'] = (int) ($meta['cursor_offset'] ?? 0) + $bytes_consumed;
            $meta['processed_count'] = (int) ($meta['processed_count'] ?? 0) + $processed_count;
            $total = (int) ($meta['total_files'] ?? 0);
            $remaining = max(0, $total - $meta['processed_count']);

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($session_dir . '/' . self::META_FILE_NAME, wp_json_encode($meta));

            if ($remaining === 0) {
                self::cleanup($scan_id);
            }

            return $remaining;
        }

        // Transient mode
        $queue = get_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
        if (is_array($queue)) {
            array_splice($queue, 0, $processed_count);
            $remaining = count($queue);
            if ($remaining === 0) {
                self::cleanup($scan_id);
                return 0;
            }
            set_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id, $queue, HOUR_IN_SECONDS);
            $meta['processed_count'] = (int) ($meta['processed_count'] ?? 0) + $processed_count;
            set_transient(self::TRANSIENT_META_PREFIX . $scan_id, $meta, HOUR_IN_SECONDS);
            return $remaining;
        }

        return 0;
    }

    /**
     * Get remaining file count for a scan.
     *
     * @param int|string $scan_id
     * @return int
     */
    public static function get_remaining_count($scan_id): int {
        $meta = self::get_meta($scan_id);
        if ($meta) {
            if (($meta['storage_mode'] ?? 'disk') === 'disk') {
                $total = (int) ($meta['total_files'] ?? 0);
                $processed = (int) ($meta['processed_count'] ?? 0);
                return max(0, $total - $processed);
            }
        }

        $queue = get_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
        return is_array($queue) ? count($queue) : 0;
    }

    /**
     * Check if a scan queue exists.
     *
     * @param int|string $scan_id
     * @return bool
     */
    public static function has_queue($scan_id): bool {
        $meta = self::get_meta($scan_id);
        if ($meta) {
            $total = (int) ($meta['total_files'] ?? 0);
            $processed = (int) ($meta['processed_count'] ?? 0);
            return ($total > $processed);
        }

        $queue = get_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
        return is_array($queue) && !empty($queue);
    }

    /**
     * Read metadata for a scan queue.
     *
     * @param int|string $scan_id
     * @return array|null
     */
    public static function get_meta($scan_id): ?array {
        $session_dir = self::get_session_dir($scan_id);
        if ($session_dir && file_exists($session_dir . '/' . self::META_FILE_NAME)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_get_contents
            $raw = @file_get_contents($session_dir . '/' . self::META_FILE_NAME);
            if ($raw) {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    return $decoded;
                }
            }
        }

        $transient_meta = get_transient(self::TRANSIENT_META_PREFIX . $scan_id);
        if (is_array($transient_meta)) {
            return $transient_meta;
        }

        return null;
    }

    /**
     * Clean up session files and transients for a scan.
     *
     * @param int|string $scan_id
     */
    public static function cleanup($scan_id): void {
        delete_transient(self::TRANSIENT_QUEUE_PREFIX . $scan_id);
        delete_transient(self::TRANSIENT_META_PREFIX . $scan_id);

        $session_dir = self::get_session_dir($scan_id);
        if ($session_dir && is_dir($session_dir)) {
            self::recursive_delete_directory($session_dir);
        }
    }

    /**
     * Clean up expired sessions older than max age.
     *
     * @param int $max_age Age in seconds (default 7200 = 2 hours)
     * @return int Number of sessions cleaned
     */
    public static function cleanup_expired_sessions(int $max_age = 7200): int {
        $base = self::get_base_sessions_dir();
        if (!$base || !is_dir($base)) {
            return 0;
        }

        $cleaned = 0;
        $now = time();

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_scandir
        $entries = @scandir($base);
        if (!is_array($entries)) {
            return 0;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === '.htaccess' || $entry === 'index.php') {
                continue;
            }
            $dir = $base . '/' . $entry;
            if (is_dir($dir)) {
                $mtime = @filemtime($dir);
                if ($mtime && ($now - $mtime) > $max_age) {
                    self::recursive_delete_directory($dir);
                    $cleaned++;
                }
            }
        }

        return $cleaned;
    }

    /**
     * Recursively delete a directory and its contents.
     *
     * @param string $dir
     */
    private static function recursive_delete_directory(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_scandir
        $items = @scandir($dir);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path)) {
                self::recursive_delete_directory($path);
            } else {
                wp_delete_file($path);
            }
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
        @rmdir($dir);
    }
}
