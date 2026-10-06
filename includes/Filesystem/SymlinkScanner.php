<?php
namespace WCP\Scanner\Filesystem;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class SymlinkScanner {
    
    public function scan($file_path, $scan_id) {
        if (is_link($file_path)) {
            $target = readlink($file_path);
            
            return new Finding([
                'engine'      => 'filesystem',
                'type'        => 'symlink_detected',
                'severity'    => 'low',
                'confidence'  => 100,
                'file_path'   => $file_path,
                'description' => "Symbolic link detected pointing to: $target",
                'evidence'    => "Target: $target"
            ]);
        }
        
        return null;
    }
}
