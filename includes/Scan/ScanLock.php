<?php
namespace WCP\Scanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

class ScanLock {

    const LOCK_OPTION = 'wcp_active_scan_lock';
    const LOCK_TIMEOUT_SECONDS = 300; // 5 minutes timeout for auto recovery

    /**
     * Attempt to acquire a scan lock.
     *
     * @param int $scan_id
     * @return bool True if acquired, false if another scan is actively locked.
     */
    public static function acquire($scan_id) {
        $existing = get_option(self::LOCK_OPTION);

        if ($existing && is_array($existing)) {
            $locked_time = $existing['time'] ?? 0;
            // If lock is active and hasn't timed out, reject concurrent scan
            if ((time() - $locked_time) < self::LOCK_TIMEOUT_SECONDS && $existing['scan_id'] !== $scan_id) {
                return false;
            }
        }

        update_option(self::LOCK_OPTION, [
            'scan_id' => $scan_id,
            'time'    => time(),
        ]);

        return true;
    }

    /**
     * Refresh the lock heartbeat to indicate the scan is still actively processing.
     *
     * @param int $scan_id
     */
    public static function heartbeat($scan_id) {
        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing) && ($existing['scan_id'] ?? 0) === $scan_id) {
            update_option(self::LOCK_OPTION, [
                'scan_id' => $scan_id,
                'time'    => time(),
            ]);
        }
    }

    /**
     * Release the scan lock.
     *
     * @param int|null $scan_id
     */
    public static function release($scan_id = null) {
        if ($scan_id === null) {
            delete_option(self::LOCK_OPTION);
            return;
        }

        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing) && ($existing['scan_id'] ?? 0) === $scan_id) {
            delete_option(self::LOCK_OPTION);
        }
    }

    /**
     * Check if a scan is currently running and locked.
     *
     * @return int|null Scan ID if locked, or null.
     */
    public static function get_locked_scan_id() {
        $existing = get_option(self::LOCK_OPTION);
        if ($existing && is_array($existing)) {
            $locked_time = $existing['time'] ?? 0;
            if ((time() - $locked_time) < self::LOCK_TIMEOUT_SECONDS) {
                return (int) $existing['scan_id'];
            }
        }
        return null;
    }
}
