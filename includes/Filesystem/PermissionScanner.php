<?php
namespace WCP\Scanner\Filesystem;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class PermissionScanner {
    
    public function scan($file_path, FileMetadata $metadata, $scan_id) {
        if ($metadata->permissions === '0777' || $metadata->permissions === '0666') {
            
            $severity = 'medium';
            // Config files with 777 are critical
            if (strpos($file_path, 'wp-config.php') !== false || strpos($file_path, '.htaccess') !== false) {
                $severity = 'high';
            }

            return new Finding([
                'engine'      => 'filesystem',
                'type'        => 'unsafe_permissions',
                'severity'    => $severity,
                'confidence'  => 100,
                'file_path'   => $file_path,
                'description' => "Unsafe file permissions detected: {$metadata->permissions}",
                'evidence'    => "Permissions: {$metadata->permissions}"
            ]);
        }
        
        return null;
    }
}
