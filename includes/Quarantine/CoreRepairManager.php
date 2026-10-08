<?php
namespace WCP\Scanner\Quarantine;

if (!defined('ABSPATH')) {
    exit;
}

class CoreRepairManager {

    /**
     * Safely repair a compromised WordPress core file by downloading a pristine version
     * from the official WordPress.org Subversion repository.
     *
     * @param string $file_path Absolute path to the core file
     * @return array ['success' => bool, 'message' => string]
     */
    public function repair_core_file($file_path) {
        $real_path = realpath($file_path);
        
        // If file doesn't exist, we can still try to restore it if we know where it should be
        if (!$real_path) {
            $real_path = str_replace('\\', '/', $file_path);
        }

        $real_root = str_replace('\\', '/', ABSPATH);
        $normalized_path = str_replace('\\', '/', $real_path);

        // Security check: Must reside within WordPress installation root
        if (strpos($normalized_path, $real_root) !== 0) {
            return ['success' => false, 'message' => 'Security violation: File resides outside ABSPATH.'];
        }

        // Calculate relative path inside ABSPATH
        $relative_path = ltrim(substr($normalized_path, strlen($real_root)), '/');

        // Prevent repairing non-core directories (wp-content)
        if (strpos($relative_path, 'wp-content/') === 0) {
            return ['success' => false, 'message' => 'Cannot repair files inside wp-content directory.'];
        }

        // Prevent repairing configuration files (these are unique per site)
        if ($relative_path === 'wp-config.php' || $relative_path === '.htaccess') {
            return ['success' => false, 'message' => 'Cannot overwrite site-specific configuration files (wp-config.php or .htaccess). Manual surgical repair required.'];
        }

        global $wp_version;
        // Construct the official WordPress SVN raw URL for the exact version
        $svn_url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}";

        $response = wp_remote_get($svn_url, ['timeout' => 30]);

        if (is_wp_error($response)) {
            return ['success' => false, 'message' => 'Failed to connect to WordPress.org SVN repository: ' . $response->get_error_message()];
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            return ['success' => false, 'message' => "WordPress.org returned HTTP $status_code. File might not exist in this core version."];
        }

        $pristine_content = wp_remote_retrieve_body($response);
        if (empty($pristine_content)) {
            return ['success' => false, 'message' => 'Downloaded pristine file was empty. Aborting repair.'];
        }

        // Backup the infected file before overwriting (just in case)
        if (file_exists($real_path)) {
            $backup_path = $real_path . '.wcp_infected_bak';
            @rename($real_path, $backup_path);
        }

        // Write the pristine content
        $result = @file_put_contents($real_path, $pristine_content);

        if ($result !== false) {
            return ['success' => true, 'message' => "File {$relative_path} has been successfully repaired and restored to its original factory state."];
        } else {
            // Restore backup if write failed
            if (isset($backup_path) && file_exists($backup_path)) {
                @rename($backup_path, $real_path);
            }
            return ['success' => false, 'message' => 'Failed to write pristine file to disk. Check directory permissions.'];
        }
    }
}
