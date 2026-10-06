<?php
namespace WCP\Scanner\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class CoreChecksum {
    /**
     * Verify WordPress Core files against the official WordPress API checksums.
     *
     * @return array List of issues found (modified or missing files)
     */
    public static function verify() {
        global $wp_version, $wp_local_package;

        $locale = !empty($wp_local_package) ? $wp_local_package : get_locale();
        $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";

        $response = wp_remote_get($api_url, ['timeout' => 15]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Fallback to default en_US if localized version is unavailable
            $fallback_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale=en_US";
            $response = wp_remote_get($fallback_url, ['timeout' => 15]);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                return [];
            }
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (empty($body['checksums']) || !is_array($body['checksums'])) {
            return [];
        }

        $issues = [];
        $abspath = untrailingslashit(ABSPATH);

        foreach ($body['checksums'] as $file => $checksum) {
            // Skip wp-content as it is customized
            if (strpos($file, 'wp-content') === 0) {
                continue;
            }

            $filepath = $abspath . '/' . $file;

            if (!file_exists($filepath)) {
                $issues[] = [
                    'type'        => 'core_missing',
                    'severity'    => 'medium',
                    'file_path'   => $file,
                    'line_number' => 0,
                    'code_snippet'=> '',
                    'description' => "Official WordPress core file is missing: {$file}",
                ];
                continue;
            }

            $local_hash = md5_file($filepath);
            if ($local_hash !== $checksum) {
                $issues[] = [
                    'type'        => 'core_modified',
                    'severity'    => 'critical',
                    'file_path'   => $file,
                    'line_number' => 0,
                    'code_snippet'=> '',
                    'description' => "WordPress core file has been modified or tampered with: {$file}",
                ];
            }
        }

        return $issues;
    }
}
