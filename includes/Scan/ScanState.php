<?php
namespace WCP\Scanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

class ScanState {
    
    private $scan_id;
    private $engine;
    private $offset;
    private $meta;

    public function __construct($scan_id, $engine = 'filesystem', $offset = 0, $meta = []) {
        $this->scan_id = $scan_id;
        $this->engine = $engine;
        $this->offset = $offset;
        $this->meta = $meta;
    }

    public function get_scan_id() {
        return $this->scan_id;
    }

    public function get_engine() {
        return $this->engine;
    }

    public function get_offset() {
        return $this->offset;
    }

    public function get_meta() {
        return $this->meta;
    }

    public function set_engine($engine) {
        $this->engine = $engine;
    }

    public function set_offset($offset) {
        $this->offset = $offset;
    }

    public function set_meta_key($key, $value) {
        $this->meta[$key] = $value;
    }

    /**
     * Save the current state to the database so it can be resumed later.
     */
    public function save() {
        // Implementation will be done when hooking this up to the REST API endpoints
        // Currently, we just structure the object for passing around.
        set_transient('wcp_scan_state_' . $this->scan_id, [
            'engine' => $this->engine,
            'offset' => $this->offset,
            'meta'   => $this->meta
        ], HOUR_IN_SECONDS);
    }

    public static function load($scan_id) {
        $data = get_transient('wcp_scan_state_' . $scan_id);
        if ($data) {
            return new self($scan_id, $data['engine'], $data['offset'], $data['meta']);
        }
        return new self($scan_id);
    }
}
