<?php
namespace WCP\Scanner\Filesystem;

if (!defined('ABSPATH')) {
    exit;
}

class FileMetadata {
    
    public $size;
    public $mtime;
    public $ctime;
    public $atime;
    public $permissions;
    public $owner;
    public $group;
    public $is_symlink;
    public $is_readable;

    public function __construct($file_path) {
        if (file_exists($file_path)) {
            $this->size = filesize($file_path);
            $this->mtime = filemtime($file_path);
            $this->ctime = filectime($file_path);
            $this->atime = fileatime($file_path);
            $this->permissions = substr(sprintf('%o', fileperms($file_path)), -4);
            $this->is_symlink = is_link($file_path);
            $this->is_readable = is_readable($file_path);
            
            if (function_exists('posix_getpwuid')) {
                $owner_info = @posix_getpwuid(fileowner($file_path));
                $this->owner = $owner_info ? $owner_info['name'] : fileowner($file_path);
            }
        }
    }
}
