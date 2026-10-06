<?php
namespace WCP\Scanner\Resource;

if (!defined('ABSPATH')) {
    exit;
}

class ResourceMonitor {
    
    /**
     * Maximum allowed memory usage percentage (0-100).
     */
    private $max_memory_percent;

    /**
     * Maximum allowed execution time in seconds per batch.
     */
    private $max_time_seconds;

    private $start_time;

    public function __construct($max_memory_percent = 80, $max_time_seconds = 20) {
        $this->max_memory_percent = $max_memory_percent;
        $this->max_time_seconds = $max_time_seconds;
        $this->start_time = microtime(true);
    }

    /**
     * Check if the process is approaching resource limits.
     *
     * @return bool True if we need to pause and save state.
     */
    public function is_nearing_limits() {
        if ($this->get_memory_usage_percent() >= $this->max_memory_percent) {
            return true;
        }

        if ($this->get_execution_time() >= $this->max_time_seconds) {
            return true;
        }

        return false;
    }

    private function get_memory_usage_percent() {
        $memory_limit = ini_get('memory_limit');
        if (preg_match('/^(\d+)(.)$/', $memory_limit, $matches)) {
            if ($matches[2] == 'M') {
                $memory_limit = $matches[1] * 1024 * 1024;
            } else if ($matches[2] == 'K') {
                $memory_limit = $matches[1] * 1024;
            } else if ($matches[2] == 'G') {
                $memory_limit = $matches[1] * 1024 * 1024 * 1024;
            }
        } else {
            $memory_limit = (int)$memory_limit;
        }

        if ($memory_limit <= 0) {
            return 0; // Unlimited or unparseable
        }

        $used_memory = memory_get_usage();
        return ($used_memory / $memory_limit) * 100;
    }

    private function get_execution_time() {
        return microtime(true) - $this->start_time;
    }
}
