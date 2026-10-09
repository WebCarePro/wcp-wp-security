<?php
namespace WCP\Scanner\Quarantine;

if (!defined('ABSPATH')) {
    exit;
}

class CoreRepairManager {

    /**
     * Provide safe instructions to repair a core file through official WordPress channels.
     * WordPress.org guidelines prohibit plugins from directly writing or modifying files in core directories.
     *
     * @param string $file_path Absolute path to the core file
     * @return array ['success' => bool, 'message' => string, 'redirect_url' => string]
     */
    public function repair_core_file($file_path) {
        $update_url = admin_url('update-core.php');
        
        return [
            'success'      => false,
            'message'      => sprintf(
                /* translators: %s: URL to WordPress Updates screen */
                __('Direct modification of WordPress core files by plugins is restricted for security. To safely restore pristine WordPress core files, navigate to Dashboard &rarr; Updates (%s) and click "Re-install version", or execute "wp core download --force" via WP-CLI.', 'wcp-security-scanner'),
                esc_url($update_url)
            ),
            'redirect_url' => esc_url($update_url)
        ];
    }
}
