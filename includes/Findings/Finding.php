<?php
namespace WCP\Scanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

class Finding {
    public $engine;
    public $type;
    public $severity;
    public $confidence;
    public $file_path;
    public $line_number;
    public $code_snippet;
    public $evidence;
    public $description;

    public function __construct($data = []) {
        $this->engine = $data['engine'] ?? 'unknown';
        $this->type = $data['type'] ?? 'unknown';
        $this->severity = $data['severity'] ?? 'medium';
        $this->confidence = $data['confidence'] ?? 100;
        $this->file_path = $data['file_path'] ?? '';
        $this->line_number = $data['line_number'] ?? null;
        $this->code_snippet = $data['code_snippet'] ?? null;
        $this->evidence = $data['evidence'] ?? null;
        $this->description = $data['description'] ?? '';
    }

    public function to_array() {
        return [
            'engine' => $this->engine,
            'type' => $this->type,
            'severity' => $this->severity,
            'confidence' => $this->confidence,
            'file_path' => $this->file_path,
            'line_number' => $this->line_number,
            'code_snippet' => $this->code_snippet,
            'evidence' => $this->evidence,
            'description' => $this->description,
        ];
    }
}
