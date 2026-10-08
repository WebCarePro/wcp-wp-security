<?php
namespace WCP\Scanner\Backup;

if (!defined('ABSPATH')) {
    exit;
}

class DatabaseBackup {

    private $backup_dir;

    public function __construct() {
        $primary = WP_CONTENT_DIR . '/wcp-backups';
        $this->backup_dir = $primary;
        $this->ensure_directory();

        // If primary location in wp-content is not writable by web server user, fallback to uploads
        if (!is_writable($this->backup_dir)) {
            $uploads = wp_upload_dir();
            if (!empty($uploads['basedir'])) {
                $fallback = untrailingslashit($uploads['basedir']) . '/wcp-backups';
                $this->backup_dir = $fallback;
                $this->ensure_directory();
            }
        }
    }

    /**
     * Ensure the backup directory exists and is strictly blocked from public web access.
     */
    private function ensure_directory() {
        if (!is_dir($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
            @chmod($this->backup_dir, 0775);
        }

        if (is_dir($this->backup_dir) && !is_writable($this->backup_dir)) {
            @chmod($this->backup_dir, 0775);
        }

        // Lock with .htaccess
        $htaccess = $this->backup_dir . '/.htaccess';
        if (!file_exists($htaccess) && is_writable($this->backup_dir)) {
            $rules = "# Block all public access to database backups\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
            @file_put_contents($htaccess, $rules);
        }

        // Lock with index.php
        $index = $this->backup_dir . '/index.php';
        if (!file_exists($index) && is_writable($this->backup_dir)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\nexit;\n");
        }
    }

    /**
     * Generate a fast, memory-safe database backup dump.
     *
     * @return array ['success' => bool, 'filename' => string, 'size_mb' => float, 'message' => string]
     */
    public function create_backup() {
        global $wpdb;

        @set_time_limit(300);
        $date_str = gmdate('Y-m-d_H-i-s');
        $use_gzip = function_exists('gzopen');
        $ext = $use_gzip ? 'sql.gz' : 'sql';
        $filename = "db_backup_{$date_str}_" . wp_generate_password(8, false) . ".{$ext}";
        $filepath = $this->backup_dir . '/' . $filename;

        $fp = $use_gzip ? @gzopen($filepath, 'w9') : @fopen($filepath, 'w');
        if (!$fp) {
            return ['success' => false, 'message' => 'Failed to create backup file in vault directory. Check permissions.'];
        }

        $write_fn = function ($str) use ($fp, $use_gzip) {
            if ($use_gzip) {
                gzwrite($fp, $str);
            } else {
                fwrite($fp, $str);
            }
        };

        // Header
        $write_fn("-- ============================================================\n");
        $write_fn("-- WCP Security Scanner - Database Backup\n");
        $write_fn("-- Date: " . current_time('mysql') . "\n");
        $write_fn("-- WordPress Version: " . get_bloginfo('version') . "\n");
        $write_fn("-- Host: " . DB_HOST . " | Database: " . DB_NAME . "\n");
        $write_fn("-- ============================================================\n\n");
        $write_fn("SET FOREIGN_KEY_CHECKS = 0;\nSET NAMES utf8mb4;\n\n");

        $tables = $wpdb->get_col("SHOW TABLES");
        if (empty($tables)) {
            if ($use_gzip) gzclose($fp); else fclose($fp);
            @unlink($filepath);
            return ['success' => false, 'message' => 'No tables found to back up.'];
        }

        foreach ($tables as $table) {
            // Drop & Create Table Structure
            $write_fn("-- Structure for table `{$table}`\n");
            $write_fn("DROP TABLE IF EXISTS `{$table}`;\n");
            $create_res = $wpdb->get_row("SHOW CREATE TABLE `{$table}`", ARRAY_A);
            if (isset($create_res['Create Table'])) {
                $write_fn($create_res['Create Table'] . ";\n\n");
            }

            // Dump data in chunks of 500 rows to keep memory footprint minimal
            $total_rows = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table}`");
            if ($total_rows === 0) {
                continue;
            }

            $write_fn("-- Dumping data for `{$table}` ({$total_rows} rows)\n");
            $batch_size = 500;
            $offset = 0;

            while ($offset < $total_rows) {
                $rows = $wpdb->get_results(
                    $wpdb->prepare("SELECT * FROM `{$table}` LIMIT %d OFFSET %d", $batch_size, $offset),
                    ARRAY_A
                );

                if (empty($rows)) {
                    break;
                }

                foreach ($rows as $row) {
                    $cols = array_map(function ($col) { return "`{$col}`"; }, array_keys($row));
                    $values = array_map(function ($val) use ($wpdb) {
                        if ($val === null) return 'NULL';
                        return "'" . esc_sql($val) . "'";
                    }, array_values($row));

                    $sql = "INSERT INTO `{$table}` (" . implode(', ', $cols) . ") VALUES (" . implode(', ', $values) . ");\n";
                    $write_fn($sql);
                }

                $offset += count($rows);
            }

            $write_fn("\n");
        }

        $write_fn("SET FOREIGN_KEY_CHECKS = 1;\n");
        $write_fn("-- Dump completed on " . current_time('mysql') . "\n");

        if ($use_gzip) {
            gzclose($fp);
        } else {
            fclose($fp);
        }

        $size = filesize($filepath);
        $size_mb = round($size / (1024 * 1024), 2);

        return [
            'success'  => true,
            'filename' => $filename,
            'size_mb'  => $size_mb,
            'created'  => current_time('mysql'),
            'message'  => "Database backup created successfully ({$size_mb} MB)."
        ];
    }

    /**
     * List all database backups stored in the secure vault.
     *
     * @return array
     */
    /**
     * List all database backups stored in the secure vault.
     *
     * @return array
     */
    public function list_backups() {
        $backups = [];
        $dirs = array_filter(array_unique([
            $this->backup_dir,
            WP_CONTENT_DIR . '/wcp-backups',
            (function_exists('wp_upload_dir') ? untrailingslashit(wp_upload_dir()['basedir']) . '/wcp-backups' : '')
        ]));

        $seen = [];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $files = @scandir($dir, SCANDIR_SORT_DESCENDING);
            if (!$files) {
                continue;
            }

            foreach ($files as $file) {
                if ($file === '.' || $file === '..' || $file === '.htaccess' || $file === 'index.php') {
                    continue;
                }
                if (isset($seen[$file])) {
                    continue;
                }

                $path = $dir . '/' . $file;
                if (is_file($path)) {
                    $seen[$file] = true;
                    $size = @filesize($path) ?: 0;
                    $mtime = @filemtime($path) ?: time();
                    $backups[] = [
                        'filename'   => $file,
                        'size_mb'    => round($size / (1024 * 1024), 2),
                        'size_bytes' => $size,
                        'created'    => gmdate('Y-m-d H:i:s', $mtime),
                        'timestamp'  => $mtime,
                    ];
                }
            }
        }

        usort($backups, function ($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });

        return $backups;
    }

    /**
     * Delete a backup file.
     *
     * @param string $filename
     * @return bool
     */
    public function delete_backup($filename) {
        $path = $this->get_backup_path($filename);
        if ($path && file_exists($path) && is_file($path)) {
            return @unlink($path);
        }
        return false;
    }

    /**
     * Get path for downloading a backup.
     *
     * @param string $filename
     * @return string|null
     */
    public function get_backup_path($filename) {
        $basename = basename($filename);
        $dirs = array_filter(array_unique([
            $this->backup_dir,
            WP_CONTENT_DIR . '/wcp-backups',
            (function_exists('wp_upload_dir') ? untrailingslashit(wp_upload_dir()['basedir']) . '/wcp-backups' : '')
        ]));

        foreach ($dirs as $dir) {
            $path = $dir . '/' . $basename;
            if (file_exists($path) && is_file($path)) {
                return $path;
            }
        }
        return null;
    }
}
