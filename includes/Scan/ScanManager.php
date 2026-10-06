<?php
namespace WCP\Scanner\Scan;

use WCP\Scanner\Resource\ResourceMonitor;
use WCP\Scanner\Filesystem\DirectoryWalker;
use WCP\Scanner\Filesystem\FileScanner;

if (!defined('ABSPATH')) {
    exit;
}

class ScanManager {
    
    private $directory_walker;
    private $file_scanner;

    public function __construct() {
        $this->directory_walker = new DirectoryWalker();
        $this->file_scanner = new FileScanner();
    }

    /**
     * Run a batch of the filesystem scan.
     *
     * @param string $scan_id
     * @param int $batch_size
     * @return array Result array containing status, offset, findings, etc.
     */
    public function run_filesystem_batch($scan_id, $batch_size = 100) {
        $state = ScanState::load($scan_id);
        
        // Dynamically adjust batch size if memory is an issue (mock implementation for now)
        $monitor = new ResourceMonitor(80, 20); // 80% memory max, 20s max

        $root_dir = ABSPATH;
        $offset = $state->get_offset();
        
        $files = $this->directory_walker->get_batch($root_dir, $batch_size, $offset);
        
        $findings = [];
        $files_scanned = 0;

        foreach ($files as $file) {
            if ($monitor->is_nearing_limits()) {
                break; // Stop processing this batch early to save state
            }

            $file_findings = $this->file_scanner->scan_file($file, $scan_id);
            $findings = array_merge($findings, $file_findings);
            
            $files_scanned++;
        }

        // Update state
        $new_offset = $offset + $files_scanned;
        $state->set_offset($new_offset);
        $state->save();

        $is_complete = count($files) === 0 || count($files) < $batch_size && $files_scanned === count($files);

        return [
            'scan_id' => $scan_id,
            'engine' => 'filesystem',
            'files_scanned_in_batch' => $files_scanned,
            'total_scanned_so_far' => $new_offset,
            'is_complete' => $is_complete,
            'findings' => array_map(function($f) { return $f->to_array(); }, $findings)
        ];
    }
}
