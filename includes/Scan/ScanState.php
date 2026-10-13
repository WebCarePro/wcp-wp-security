<?php
namespace WCP\Scanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

class ScanState {

    const OPTION_PREFIX = 'wcp_scan_state_';

    private string $scan_id;
    private string $engine;
    private int $offset;
    private array $meta;
    private array $cursor;
    private string $status;
    private array $progress;
    private bool $abort_requested;
    private int $memory_peak;

    public function __construct($scan_id, $engine = 'filesystem', $offset = 0, $meta = []) {
        $this->scan_id = (string) $scan_id;
        $this->engine = (string) $engine;
        $this->offset = (int) $offset;
        $this->meta = is_array($meta) ? $meta : [];

        $this->cursor = $this->meta['cursor'] ?? [
            'phase'     => 'plugins',
            'dir_stack' => [],
            'last_file' => null,
        ];
        $this->status = $this->meta['status'] ?? 'queued';
        $this->progress = $this->meta['progress'] ?? [
            'files_scanned'   => $this->offset,
            'files_total_est' => 0,
            'issues_found'    => 0,
            'started_at'      => time(),
            'updated_at'      => time(),
        ];
        $this->abort_requested = !empty($this->meta['abort_requested']);
        $this->memory_peak = (int) ($this->meta['memory_peak'] ?? 0);
    }

    public static function load($scan_id): self {
        $data = get_transient(self::OPTION_PREFIX . $scan_id);
        if ($data && is_array($data)) {
            $instance = new self(
                $scan_id,
                $data['engine'] ?? 'filesystem',
                $data['offset'] ?? 0,
                $data['meta'] ?? []
            );
            if (isset($data['cursor'])) {
                $instance->set_cursor($data['cursor']);
            }
            if (isset($data['status'])) {
                $instance->set_status($data['status']);
            }
            if (isset($data['progress'])) {
                $instance->progress = $data['progress'];
            }
            if (isset($data['abort_requested'])) {
                $instance->abort_requested = (bool) $data['abort_requested'];
            }
            if (isset($data['memory_peak'])) {
                $instance->memory_peak = (int) $data['memory_peak'];
            }
            return $instance;
        }

        return new self($scan_id);
    }

    public function save(): void {
        $this->progress['updated_at'] = time();
        $this->meta['cursor'] = $this->cursor;
        $this->meta['status'] = $this->status;
        $this->meta['progress'] = $this->progress;
        $this->meta['abort_requested'] = $this->abort_requested;
        $this->meta['memory_peak'] = $this->memory_peak;

        set_transient(self::OPTION_PREFIX . $this->scan_id, [
            'engine'          => $this->engine,
            'offset'          => $this->offset,
            'meta'            => $this->meta,
            'cursor'          => $this->cursor,
            'status'          => $this->status,
            'progress'        => $this->progress,
            'abort_requested' => $this->abort_requested,
            'memory_peak'     => $this->memory_peak,
        ], 2 * HOUR_IN_SECONDS);
    }

    public function get_scan_id(): string {
        return $this->scan_id;
    }

    public function get_engine(): string {
        return $this->engine;
    }

    public function set_engine(string $engine): void {
        $this->engine = $engine;
    }

    public function get_offset(): int {
        return $this->offset;
    }

    public function set_offset(int $offset): void {
        $this->offset = $offset;
        $this->progress['files_scanned'] = $offset;
    }

    public function get_meta(): array {
        return $this->meta;
    }

    public function set_meta_key(string $key, $value): void {
        $this->meta[$key] = $value;
    }

    public function get_cursor(): array {
        return $this->cursor;
    }

    public function set_cursor(array $cursor): void {
        $this->cursor = $cursor;
    }

    public function get_status(): string {
        return $this->status;
    }

    public function set_status(string $status): void {
        $this->status = $status;
    }

    public function increment_scanned(int $count = 1): void {
        $this->offset += $count;
        $this->progress['files_scanned'] = ($this->progress['files_scanned'] ?? 0) + $count;
    }

    public function add_issues(int $count): void {
        $this->progress['issues_found'] = ($this->progress['issues_found'] ?? 0) + $count;
    }

    public function request_abort(): void {
        $this->abort_requested = true;
        $this->status = 'aborting';
    }

    public function is_abort_requested(): bool {
        return $this->abort_requested || $this->status === 'aborting';
    }

    public function set_memory_peak(int $bytes): void {
        $this->memory_peak = max($this->memory_peak, $bytes);
    }

    public function get_memory_peak(): int {
        return $this->memory_peak;
    }

    public function to_array(): array {
        return [
            'scan_id'         => $this->scan_id,
            'engine'          => $this->engine,
            'offset'          => $this->offset,
            'cursor'          => $this->cursor,
            'status'          => $this->status,
            'progress'        => $this->progress,
            'abort_requested' => $this->abort_requested,
            'memory_peak'     => $this->memory_peak,
        ];
    }
}
