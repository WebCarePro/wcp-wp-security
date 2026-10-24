<?php
namespace WcpScanner\Resource;

if (!defined('ABSPATH')) {
    exit;
}

class ResourceMonitor {
    
    /**
     * Maximum allowed memory usage percentage (0-100). Default safe ceiling is 65-70%.
     */
    private $max_memory_percent;

    /**
     * Maximum allowed execution time in seconds per batch.
     */
    private $max_time_seconds;

    private $start_time;
    private $files_processed_in_cycle = 0;
    private $throttle_delay_us = 0;
    private $last_status_reason = 'Optimal memory headroom';
    private $mode = 'balanced';

    public function __construct($max_memory_percent = 70, $max_time_seconds = 18, $mode = 'balanced') {
        // Enforce user setting override if present
        $configured_envelope = 70;
        if (class_exists('\\WcpScanner\\System\\SettingsManager')) {
            $saved_envelope = \WcpScanner\System\SettingsManager::get('scan_memory_safety_envelope', 'balanced');
            if ($saved_envelope === 'strict') {
                $configured_envelope = 60;
            } elseif ($saved_envelope === 'performance') {
                $configured_envelope = 80;
            } else {
                $configured_envelope = 70;
            }
        }

        $this->max_memory_percent = min((int) $max_memory_percent, $configured_envelope);
        $this->max_time_seconds   = $max_time_seconds;
        $this->mode               = $mode;
        $this->start_time         = microtime(true);
        $this->evaluate_environment();
    }

    /**
     * Evaluate system memory and load to set pacing and batch limits.
     */
    private function evaluate_environment() {
        $mem_percent = $this->get_memory_usage_percent();
        $free_mem_mb = $this->get_free_memory_mb();

        // 1. Check OS available memory if on Linux
        $os_low_ram = false;
        if (is_readable('/proc/meminfo')) {
            $meminfo = @file_get_contents('/proc/meminfo');
            if ($meminfo && preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $meminfo, $m)) {
                $avail_mb = ((int) $m[1]) / 1024;
                if ($avail_mb < 80) { // Less than 80MB left on entire server
                    $os_low_ram = true;
                }
            }
        }

        // 2. Dynamic Pacing based on Memory Safety Envelope
        if ($mem_percent >= $this->max_memory_percent || $os_low_ram) {
            $this->throttle_delay_us = 60000; // 60ms pause per file
            $this->last_status_reason = 'Visitor RAM Protection: Approaching memory safe ceiling (' . round($mem_percent, 1) . '%)';
        } elseif ($mem_percent >= ($this->max_memory_percent - 15)) {
            $this->throttle_delay_us = 25000; // 25ms pause per file
            $this->last_status_reason = 'Adaptive Throttle: Pacing batch to preserve visitor headroom (' . round($mem_percent, 1) . '%)';
        } else {
            // Check CPU load
            if (function_exists('sys_getloadavg')) {
                $load = @sys_getloadavg();
                $cores = $this->get_cpu_cores();
                if (is_array($load) && isset($load[0]) && $cores > 0 && ($load[0] / $cores) > 1.2) {
                    $this->throttle_delay_us = 35000;
                    $this->last_status_reason = 'Visitor CPU Shield: High server load detected, pacing execution';
                    return;
                }
            }
            $this->throttle_delay_us = 0;
            $this->last_status_reason = 'Turbo Throughput: Spacious memory & CPU headroom (' . round($mem_percent, 1) . '%)';
        }
    }

    /**
     * Dynamically recommend an intelligent batch size (e.g. 5 to 150 files)
     * based on current free memory headroom and server pressure.
     *
     * @param int $default_requested_batch
     * @return int
     */
    public function get_adaptive_batch_size(int $default_requested_batch = 50): int {
        $mem_percent = $this->get_memory_usage_percent();
        $headroom_pct = max(0, $this->max_memory_percent - $mem_percent);
        $free_mem_mb = $this->get_free_memory_mb();

        // 1. Critical memory pressure: shrink to minimum safe batch
        if ($headroom_pct <= 8 || $free_mem_mb < 60) {
            return max(5, (int) round($default_requested_batch * 0.25)); // 5-10 files
        }

        // 2. Moderate memory pressure: half batch size
        if ($headroom_pct <= 18 || $free_mem_mb < 120) {
            return max(10, (int) round($default_requested_batch * 0.50)); // 15-25 files
        }

        // 3. Super Turbo: Abundant memory headroom (>500MB free and plenty of % headroom)
        if ($free_mem_mb >= 500 && $headroom_pct >= 35) {
            // Turbo scale: up to 120 - 150 files per batch
            return min(150, max($default_requested_batch * 3, 120));
        }

        // 4. Turbo: Healthy headroom (>250MB free)
        if ($free_mem_mb >= 250 && $headroom_pct >= 25) {
            // High scale: up to 80 - 100 files per batch
            return min(100, max($default_requested_batch * 2, 80));
        }

        // 5. Standard baseline
        return $default_requested_batch;
    }

    /**
     * Throttle execution slightly if needed to keep CPU and memory breathing for visitors.
     * Checks if process is nearing safety limit.
     *
     * @return bool True if we need to yield/pause the batch and save state.
     */
    public function throttle_and_check(): bool {
        $this->files_processed_in_cycle++;

        // Inject breathing micro-sleep if throttled
        if ($this->throttle_delay_us > 0) {
            usleep($this->throttle_delay_us);
        }

        // Proactive garbage collection every 12 files
        if ($this->files_processed_in_cycle % 12 === 0) {
            if (function_exists('gc_collect_cycles')) {
                gc_collect_cycles();
            }
        }

        return $this->is_nearing_limits();
    }

    /**
     * Check if the process is approaching resource limits.
     *
     * @return bool True if we need to pause and save state.
     */
    public function is_nearing_limits() {
        if ($this->get_memory_usage_percent() >= $this->max_memory_percent) {
            $this->last_status_reason = 'Yielding: Reached memory ceiling (' . $this->max_memory_percent . '% max safe)';
            return true;
        }

        if ($this->get_execution_time() >= $this->max_time_seconds) {
            $this->last_status_reason = 'Yielding: Reached batch execution time budget (' . $this->max_time_seconds . 's)';
            return true;
        }

        return false;
    }

    /**
     * Get real-time governor diagnostics payload for API telemetry and UI progress bar.
     *
     * @return array
     */
    public function get_telemetry_payload(): array {
        $mem_pct = round($this->get_memory_usage_percent(), 1);
        $status_label = 'turbo';
        if ($this->throttle_delay_us >= 50000) {
            $status_label = 'critical_safe';
        } elseif ($this->throttle_delay_us > 0) {
            $status_label = 'throttled_safe';
        }

        return [
            'mode'                 => $this->mode,
            'status'               => $status_label,
            'reason'               => $this->last_status_reason,
            'max_safe_percent'     => $this->max_memory_percent,
            'current_memory_pct'   => $mem_pct,
            'memory_free_mb'       => round($this->get_free_memory_mb(), 1),
            'throttle_delay_ms'    => round($this->throttle_delay_us / 1000, 1),
            'execution_time_sec'   => round($this->get_execution_time(), 2),
        ];
    }

    public function get_memory_usage_percent() {
        $memory_limit = ini_get('memory_limit');
        if (preg_match('/^(\d+)(.)$/i', $memory_limit, $matches)) {
            $unit = strtoupper($matches[2]);
            if ($unit === 'M') {
                $memory_limit = $matches[1] * 1024 * 1024;
            } else if ($unit === 'K') {
                $memory_limit = $matches[1] * 1024;
            } else if ($unit === 'G') {
                $memory_limit = $matches[1] * 1024 * 1024 * 1024;
            }
        } else {
            $memory_limit = (int)$memory_limit;
        }

        if ($memory_limit <= 0) {
            // Unlimited: calculate against physical total memory if possible, or fallback to 1GB base
            return 15.0;
        }

        $used_memory = memory_get_usage(true);
        return ($used_memory / $memory_limit) * 100;
    }

    public function get_free_memory_mb(): float {
        $memory_limit = ini_get('memory_limit');
        $limit_bytes = 256 * 1024 * 1024;
        if ($memory_limit === '-1') {
            return 9999.0;
        } elseif (preg_match('/^(\d+)(.)$/i', $memory_limit, $matches)) {
            $unit = strtoupper($matches[2]);
            $val = (int)$matches[1];
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }
        $used_bytes = memory_get_usage(true);
        return max(0.0, ($limit_bytes - $used_bytes) / (1024 * 1024));
    }

    private function get_execution_time() {
        return microtime(true) - $this->start_time;
    }

    private function get_cpu_cores(): int {
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            return (int) $win_cores;
        }
        if (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                return max(1, substr_count($cpuinfo, 'processor'));
            }
        }
        return 2;
    }
}
