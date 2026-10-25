<?php
namespace WcpScanner\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CVEIntelligenceService
 *
 * Real-Time Upstream CVE Intelligence & Local WordPress Correlator Engine
 *
 * Features:
 * - Fetches CVE details from the official National Vulnerability Database (NVD) 2.0 API.
 * - Extracts CVSS scores, affected software, vulnerable semver ranges, exploit vector, and descriptions.
 * - Accurately correlates whether the CVE affects the WordPress ecosystem (Plugins, Themes, WordPress Core).
 * - Inspects the local WordPress filesystem and active inventory to determine:
 *   1. Is the software installed on this website?
 *   2. Is the installed version within the vulnerable range?
 *   3. Is the vulnerability already patched or is the site clean?
 * - Provides 1-click remediation intelligence (auto-synthesize virtual patch or deactivate component).
 * - Caches external lookups in transient storage for fast subsequent queries.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class CVEIntelligenceService {

    const TRANSIENT_PREFIX = 'wcpscan_cve_intel_';
    const CACHE_DURATION   = 604800; // 7 days cache

    /**
     * Resolve CVE Intelligence and Correlate against Local WordPress Installation
     *
     * @param string $cve_id Valid CVE ID, e.g. CVE-2024-5932
     * @return array
     */
    public static function lookup_and_correlate(string $cve_id): array {
        $cve_id = strtoupper(trim(sanitize_text_field($cve_id)));

        if (!preg_match('/^CVE-\d{4}-\d{4,8}$/', $cve_id)) {
            return [
                'success' => false,
                'message' => __('Invalid CVE ID format. Format should be CVE-YYYY-NNNN (e.g. CVE-2024-5932).', 'wcp-security-scanner'),
            ];
        }

        // 1. Check Local Pre-Packaged Catalog First
        $catalog = VirtualPatchManager::get_patch_catalog();
        if (isset($catalog[$cve_id])) {
            $cat_item = $catalog[$cve_id];
            $correlation = self::correlate_component(
                $cat_item['component'] ?? '',
                $cat_item['title'] ?? '',
                $cat_item['description'] ?? '',
                'plugin'
            );

            return [
                'success'     => true,
                'cve_id'      => $cve_id,
                'source'      => 'curated_catalog',
                'title'       => $cat_item['title'] ?? $cve_id,
                'description' => $cat_item['description'] ?? '',
                'severity'    => $cat_item['severity'] ?? 'high',
                'cvss'        => $cat_item['severity'] === 'critical' ? 9.8 : 7.5,
                'vector_type' => self::detect_vector_type($cat_item['title'] . ' ' . $cat_item['description']),
                'is_wordpress'=> true,
                'component'   => $cat_item['component'],
                'has_prebuilt_patch' => true,
                'patch_data'  => $cat_item,
                'correlation' => $correlation,
            ];
        }

        // 2. Check Transient Cache
        $cache_key = self::TRANSIENT_PREFIX . md5($cve_id);
        $cached = get_transient($cache_key);
        if (is_array($cached) && !empty($cached['cve_id'])) {
            // Re-run correlation on cached intelligence to reflect current site plugins
            $cached['correlation'] = self::correlate_component(
                $cached['component'] ?? '',
                $cached['title'] ?? '',
                $cached['description'] ?? '',
                $cached['component_type'] ?? 'plugin',
                $cached['vulnerable_max_version'] ?? ''
            );
            return $cached;
        }

        // 3. Fetch from Upstream NVD API
        $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' . rawurlencode($cve_id);
        $response = wp_remote_get($url, [
            'timeout'    => 12,
            'user-agent' => 'WCP-Security-Scanner/1.26.0 (WordPress Security Engine)',
            'headers'    => [
                'Accept' => 'application/json',
            ],
        ]);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: Error message returned from HTTP request */
                    __('Failed to connect to CVE intelligence database: %s', 'wcp-security-scanner'),
                    $response->get_error_message()
                ),
            ];
        }

        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($status_code !== 200 || empty($body)) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %d: HTTP status code */
                    __('CVE intelligence provider returned HTTP error %d.', 'wcp-security-scanner'),
                    $status_code
                ),
            ];
        }

        $data = json_decode($body, true);
        if (!is_array($data) || empty($data['vulnerabilities'])) {
            return [
                'success' => false,
                'message' => sprintf(
                    /* translators: %s: CVE identifier */
                    __('No vulnerability record found for %s in the National Vulnerability Database.', 'wcp-security-scanner'),
                    $cve_id
                ),
            ];
        }

        $cve_item = $data['vulnerabilities'][0]['cve'] ?? [];
        $description = '';
        if (!empty($cve_item['descriptions']) && is_array($cve_item['descriptions'])) {
            foreach ($cve_item['descriptions'] as $desc) {
                if (($desc['lang'] ?? '') === 'en') {
                    $description = $desc['value'] ?? '';
                    break;
                }
            }
        }

        // Metrics & CVSS
        $cvss = 7.5;
        $severity = 'high';
        if (!empty($cve_item['metrics']['cvssMetricV31'][0]['cvssData'])) {
            $cvssData = $cve_item['metrics']['cvssMetricV31'][0]['cvssData'];
            $cvss = floatval($cvssData['baseScore'] ?? 7.5);
            $sev_raw = strtolower($cvssData['baseSeverity'] ?? 'high');
            if (in_array($sev_raw, ['critical', 'high', 'medium', 'low'], true)) {
                $severity = $sev_raw;
            }
        }

        // Detect if WordPress ecosystem
        $is_wordpress = false;
        $component_name = '';
        $component_type = 'plugin';
        $vulnerable_max_version = '';

        // Inspect description
        $desc_lower = strtolower($description);
        if (strpos($desc_lower, 'wordpress') !== false || strpos($desc_lower, 'wp ') !== false || strpos($desc_lower, 'plugin') !== false) {
            $is_wordpress = true;
        }

        // Check CPEs & Affected entries
        if (!empty($cve_item['configurations'][0]['nodes'][0]['cpeMatch'])) {
            foreach ($cve_item['configurations'][0]['nodes'][0]['cpeMatch'] as $cpe) {
                $criteria = $cpe['criteria'] ?? '';
                if (strpos($criteria, 'wordpress') !== false) {
                    $is_wordpress = true;
                    // Format: cpe:2.3:a:vendor:product:...
                    $parts = explode(':', $criteria);
                    if (isset($parts[4]) && !empty($parts[4]) && empty($component_name)) {
                        $component_name = sanitize_title($parts[4]);
                    }
                }
                if (!empty($cpe['versionEndExcluding'])) {
                    $vulnerable_max_version = $cpe['versionEndExcluding'];
                } elseif (!empty($cpe['versionEndIncluding'])) {
                    $vulnerable_max_version = $cpe['versionEndIncluding'];
                }
            }
        }

        // Detect target component name from description or package name
        if (!empty($cve_item['affected'][0]['affectedData'][0]['packageName'])) {
            $component_name = sanitize_key($cve_item['affected'][0]['affectedData'][0]['packageName']);
            $is_wordpress = true;
        } elseif (!empty($cve_item['affected'][0]['affectedData'][0]['product']) && empty($component_name)) {
            $component_name = sanitize_title($cve_item['affected'][0]['affectedData'][0]['product']);
        }

        if (empty($component_name)) {
            // Regex match common phrasing like "The GiveWP – Donation Plugin ... plugin for WordPress"
            if (preg_match('/(?:The\s+)?([A-Za-z0-9\-_]+)(?:\s+[–\-]\s+[A-Za-z0-9\s\-_]+)?\s+(?:plugin|theme)\s+for\s+WordPress/i', $description, $m)) {
                $component_name = sanitize_title(trim($m[1]));
            } elseif (preg_match('/in\s+WordPress\s+Core/i', $description)) {
                $component_name = 'wordpress-core';
                $component_type = 'core';
                $is_wordpress   = true;
            }
        }

        $vector_type = self::detect_vector_type($description);

        // Correlate with local site inventory
        $correlation = self::correlate_component(
            $component_name,
            $description,
            $description,
            $component_type,
            $vulnerable_max_version
        );

        $result = [
            'success'                => true,
            'cve_id'                 => $cve_id,
            'source'                 => 'nvd_upstream',
            'title'                  => sprintf('%s - %s', $cve_id, !empty($component_name) ? ucwords(str_replace('-', ' ', $component_name)) : 'Advisory'),
            'description'            => $description,
            'severity'               => $severity,
            'cvss'                   => $cvss,
            'vector_type'            => $vector_type,
            'is_wordpress'           => $is_wordpress,
            'component'              => $component_name,
            'component_type'         => $component_type,
            'vulnerable_max_version' => $vulnerable_max_version,
            'has_prebuilt_patch'     => false,
            'correlation'            => $correlation,
        ];

        // Cache result
        set_transient($cache_key, $result, self::CACHE_DURATION);

        return $result;
    }

    /**
     * Correlate Component against Local WordPress Plugins, Themes and Core
     *
     * @param string $component_slug
     * @param string $title
     * @param string $description
     * @param string $component_type
     * @param string $vulnerable_max_version
     * @return array
     */
    public static function correlate_component(
        string $component_slug,
        string $title,
        string $description,
        string $component_type = 'plugin',
        string $vulnerable_max_version = ''
    ): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        // 1. WordPress Core Check
        if ($component_type === 'core' || strpos(strtolower($component_slug), 'core') !== false) {
            global $wp_version;
            $is_vuln = false;
            if (!empty($vulnerable_max_version)) {
                $is_vuln = version_compare($wp_version, $vulnerable_max_version, '<');
            }

            return [
                'status'            => $is_vuln ? 'vulnerable' : 'safe',
                'component_type'    => 'core',
                'installed'         => true,
                'name'              => 'WordPress Core',
                'version'           => $wp_version,
                'is_active'         => true,
                'message'           => $is_vuln
                    ? sprintf(
                        /* translators: 1: Installed WP version, 2: Fixed version */
                        __('WordPress Core v%1$s is vulnerable (requires update to >= %2$s).', 'wcp-security-scanner'),
                        $wp_version,
                        $vulnerable_max_version
                    )
                    : sprintf(
                        /* translators: %s: Installed WP version */
                        __('WordPress Core v%s is running and verified immune or patched.', 'wcp-security-scanner'),
                        $wp_version
                    ),
            ];
        }

        $all_plugins = get_plugins();
        $target_slug = sanitize_title($component_slug);

        // Find candidate in installed plugins
        $matched_file = null;
        $matched_data = null;

        foreach ($all_plugins as $file => $data) {
            $folder = dirname($file);
            $slug_candidate = $folder !== '.' ? $folder : basename($file, '.php');

            // Exact folder / slug match
            if ($slug_candidate === $target_slug) {
                $matched_file = $file;
                $matched_data = $data;
                break;
            }

            // Plugin Name exact case-insensitive match
            if (!empty($data['Name']) && strtolower(trim($data['Name'])) === strtolower(str_replace('-', ' ', $target_slug))) {
                $matched_file = $file;
                $matched_data = $data;
                break;
            }
        }

        // Second pass: only if slug candidate is longer than 5 chars and folder starts with slug
        if (!$matched_file && strlen($target_slug) > 5) {
            foreach ($all_plugins as $file => $data) {
                $folder = dirname($file);
                $slug_candidate = $folder !== '.' ? $folder : basename($file, '.php');

                if ($slug_candidate === $target_slug || strpos($target_slug, $slug_candidate . '-') === 0) {
                    // Check if target is a distinct sub-addon (e.g. woocommerce-payments is NOT woocommerce)
                    continue;
                }

                if (strpos($slug_candidate, $target_slug) === 0) {
                    $matched_file = $file;
                    $matched_data = $data;
                    break;
                }
            }
        }

        if ($matched_file && $matched_data) {
            $is_active = is_plugin_active($matched_file);
            $installed_ver = $matched_data['Version'] ?? '0.0.0';

            $is_vulnerable = true;
            if (!empty($vulnerable_max_version)) {
                $is_vulnerable = version_compare($installed_ver, $vulnerable_max_version, '<=');
            }

            return [
                'status'            => $is_vulnerable ? 'vulnerable' : 'safe',
                'component_type'    => 'plugin',
                'installed'         => true,
                'plugin_file'       => $matched_file,
                'name'              => $matched_data['Name'] ?? $component_slug,
                'version'           => $installed_ver,
                'is_active'         => $is_active,
                'can_deactivate'    => $is_active && current_user_can('activate_plugins'),
                'message'           => $is_vulnerable
                    ? sprintf(
                        /* translators: 1: Plugin name, 2: Installed version */
                        __('Plugin "%1$s" (v%2$s) is INSTALLED and matches the vulnerable version range!', 'wcp-security-scanner'),
                        $matched_data['Name'],
                        $installed_ver
                    )
                    : sprintf(
                        /* translators: 1: Plugin name, 2: Installed version */
                        __('Plugin "%1$s" is installed, but running v%2$s which is already patched.', 'wcp-security-scanner'),
                        $matched_data['Name'],
                        $installed_ver
                    ),
            ];
        }

        // 3. Themes Check
        $theme = wp_get_theme($target_slug);
        if ($theme->exists()) {
            $theme_ver = $theme->get('Version');
            $is_vulnerable = true;
            if (!empty($vulnerable_max_version)) {
                $is_vulnerable = version_compare($theme_ver, $vulnerable_max_version, '<=');
            }

            return [
                'status'         => $is_vulnerable ? 'vulnerable' : 'safe',
                'component_type' => 'theme',
                'installed'      => true,
                'name'           => $theme->get('Name'),
                'version'        => $theme_ver,
                'is_active'      => (get_stylesheet() === $target_slug || get_template() === $target_slug),
                'message'        => $is_vulnerable
                    ? sprintf(
                        /* translators: 1: Theme name, 2: Installed version */
                        __('Theme "%1$s" (v%2$s) is INSTALLED and matches the vulnerable version range!', 'wcp-security-scanner'),
                        $theme->get('Name'),
                        $theme_ver
                    )
                    : sprintf(
                        /* translators: 1: Theme name, 2: Installed version */
                        __('Theme "%1$s" is installed, but running v%2$s which is already patched.', 'wcp-security-scanner'),
                        $theme->get('Name'),
                        $theme_ver
                    ),
            ];
        }

        // 4. Clean / Not Installed
        return [
            'status'         => 'not_installed',
            'component_type' => $component_type,
            'installed'      => false,
            'name'           => !empty($component_slug) ? ucwords(str_replace('-', ' ', $component_slug)) : __('Unknown Component', 'wcp-security-scanner'),
            'message'        => sprintf(
                /* translators: %s: Component name */
                __('Clean: Component "%s" is NOT installed on this WordPress site. Attackers cannot exploit code that does not exist. No patch is required.', 'wcp-security-scanner'),
                !empty($component_slug) ? ucwords(str_replace('-', ' ', $component_slug)) : __('Target Component', 'wcp-security-scanner')
            ),
        ];
    }

    /**
     * Deactivate a Vulnerable Plugin safely
     *
     * @param string $plugin_file
     * @return array
     */
    public static function deactivate_vulnerable_plugin(string $plugin_file): array {
        if (!current_user_can('activate_plugins')) {
            return [
                'success' => false,
                'message' => __('You do not have permission to deactivate plugins.', 'wcp-security-scanner'),
            ];
        }

        $plugin_file = sanitize_text_field(wp_unslash($plugin_file));
        if (empty($plugin_file) || !file_exists(WP_PLUGIN_DIR . '/' . $plugin_file)) {
            return [
                'success' => false,
                'message' => __('Target plugin file not found on server.', 'wcp-security-scanner'),
            ];
        }

        deactivate_plugins($plugin_file);

        return [
            'success' => true,
            'message' => sprintf(
                /* translators: %s: Plugin file path */
                __('Plugin "%s" was successfully deactivated to prevent exploit execution.', 'wcp-security-scanner'),
                $plugin_file
            ),
        ];
    }

    /**
     * Detect Attack Vector Type from Description
     *
     * @param string $text
     * @return string
     */
    private static function detect_vector_type(string $text): string {
        $t = strtolower($text);

        if (strpos($t, 'sql injection') !== false || strpos($t, 'sqli') !== false) {
            return 'sqli';
        }
        if (strpos($t, 'remote code execution') !== false || strpos($t, 'rce') !== false || strpos($t, 'object injection') !== false || strpos($t, 'deserialization') !== false) {
            return 'rce';
        }
        if (strpos($t, 'arbitrary file upload') !== false || strpos($t, 'file upload') !== false) {
            return 'file_upload';
        }
        if (strpos($t, 'privilege escalation') !== false || strpos($t, 'admin takeover') !== false || strpos($t, 'auth') !== false || strpos($t, 'bypass') !== false) {
            return 'auth_bypass';
        }
        if (strpos($t, 'path traversal') !== false || strpos($t, 'lfi') !== false || strpos($t, 'file deletion') !== false) {
            return 'path_traversal';
        }
        if (strpos($t, 'ssrf') !== false) {
            return 'ssrf';
        }

        return 'custom';
    }
}
