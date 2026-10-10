<?php
namespace WCP\Scanner\Integrity;

if (!defined('ABSPATH')) {
    exit;
}

class ChecksumProvider {
    
    /**
     * Fetch core checksums for the current WordPress version.
     *
     * @return array|null Array of file => hash, or null on failure.
     */
    public function get_core_checksums() {
        global $wp_version, $wp_local_package;

        $locale = empty($wp_local_package) ? 'en_US' : $wp_local_package;
        $version = $wp_version;
        
        // Strip out extra version info for alpha/beta
        $version = preg_replace('/-.*$/', '', $version);

        $cache_key = "wcp_core_chk_{$version}_{$locale}";
        $cached = get_transient($cache_key);
        if ($cached !== false && is_array($cached)) {
            return $cached;
        }

        $url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}";
        
        $response = wp_remote_get($url, ['timeout' => 15]);
        
        if (is_wp_error($response)) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['checksums']) && is_array($data['checksums'])) {
            set_transient($cache_key, $data['checksums'], 12 * HOUR_IN_SECONDS);
            return $data['checksums'];
        }

        return null;
    }

    /**
     * Fetch checksums for a specific plugin.
     *
     * @param string $plugin_slug e.g., 'akismet'
     * @param string $version
     * @return array|null
     */
    public function get_plugin_checksums($plugin_slug, $version) {
        $cache_key = "wcp_plugin_chk_{$plugin_slug}_{$version}";
        $cached = get_transient($cache_key);
        if ($cached !== false && is_array($cached)) {
            return $cached;
        }

        $url = "https://downloads.wordpress.org/plugin-checksums/{$plugin_slug}/{$version}.json";
        
        $response = wp_remote_get($url, ['timeout' => 10]);
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['files']) && is_array($data['files'])) {
            // Reformat to match core checksums (file => hash)
            $checksums = [];
            foreach ($data['files'] as $file => $info) {
                if (isset($info['md5'])) {
                    $checksums[$file] = $info['md5']; // WP.org uses MD5 for plugins generally, or sha256. 
                }
            }
            if (!empty($checksums)) {
                set_transient($cache_key, $checksums, 12 * HOUR_IN_SECONDS);
            }
            return $checksums;
        }

        return null;
    }

    /**
     * Fetch checksums for an official theme.
     *
     * @param string $theme_slug e.g., 'twentytwentyfour', 'hello-elementor'
     * @param string $version
     * @return array|null Array of relative_file => hash/bool
     */
    public function get_theme_checksums($theme_slug, $version) {
        $cache_key = "wcp_theme_chk_{$theme_slug}_{$version}";
        $cached = get_transient($cache_key);
        if ($cached !== false && is_array($cached)) {
            return $cached;
        }

        // 1. Check if it's a bundled default theme in core checksums
        $core_checksums = $this->get_core_checksums();
        if ($core_checksums) {
            $prefix = "wp-content/themes/{$theme_slug}/";
            $theme_files = [];
            foreach ($core_checksums as $file => $hash) {
                if (strpos($file, $prefix) === 0) {
                    $rel = substr($file, strlen($prefix));
                    $theme_files[$rel] = $hash;
                }
            }
            if (!empty($theme_files)) {
                set_transient($cache_key, $theme_files, DAY_IN_SECONDS);
                return $theme_files;
            }
        }

        // 2. Fetch theme zip from WordPress.org to extract manifest
        $url = "https://downloads.wordpress.org/theme/{$theme_slug}.{$version}.zip";
        $response = wp_remote_head($url, ['timeout' => 5]);
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null; // Not an official WP.org theme or version unavailable
        }

        if (class_exists('\ZipArchive')) {
            if (!function_exists('download_url')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
            }
            $tmp_file = download_url($url, 15);
            if (!is_wp_error($tmp_file)) {
                $zip = new \ZipArchive();
                if ($zip->open($tmp_file) === true) {
                    $manifest = [];
                    $zip_prefix = "{$theme_slug}/";
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $stat = $zip->statIndex($i);
                        $entry_name = $stat['name'];
                        if (substr($entry_name, -1) === '/') {
                            continue; // Skip directories
                        }
                        if (strpos($entry_name, $zip_prefix) === 0) {
                            $rel_name = substr($entry_name, strlen($zip_prefix));
                            $stream = $zip->getStream($entry_name);
                            if ($stream) {
                                $manifest[$rel_name] = md5(stream_get_contents($stream));
                                fclose($stream);
                            } else {
                                $manifest[$rel_name] = true;
                            }
                        }
                    }
                    $zip->close();
                    @unlink($tmp_file);
                    if (!empty($manifest)) {
                        set_transient($cache_key, $manifest, DAY_IN_SECONDS);
                        return $manifest;
                    }
                }
                @unlink($tmp_file);
            }
        }

        return null;
    }
}
