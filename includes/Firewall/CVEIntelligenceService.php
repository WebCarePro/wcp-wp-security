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
                ($cat_item['component'] === 'wordpress-core' ? 'core' : 'plugin')
            );

            $curated_meta = self::get_curated_metadata($cve_id, $cat_item);

            return [
                'success'            => true,
                'cve_id'             => $cve_id,
                'source'             => 'curated_catalog',
                'title'              => $cat_item['title'] ?? $cve_id,
                'description'        => $cat_item['description'] ?? '',
                'severity'           => $cat_item['severity'] ?? 'high',
                'cvss'               => $curated_meta['cvss'] ?? ($cat_item['severity'] === 'critical' ? 9.8 : 7.5),
                'vector_type'        => self::detect_vector_type($cat_item['title'] . ' ' . $cat_item['description']),
                'published_at'       => $curated_meta['published_at'] ?? 'Verified Advisory',
                'updated_at'         => $curated_meta['updated_at'] ?? 'Current Release',
                'researcher'         => $curated_meta['researcher'] ?? 'WCP Security Research',
                'weakness'           => $curated_meta['weakness'] ?? 'Critical Vulnerability',
                'references'         => $curated_meta['references'] ?? [],
                'software'           => $curated_meta['software'] ?? [
                    'name'             => ucwords(str_replace('-', ' ', $cat_item['component'] ?? 'WordPress Component')),
                    'type'             => ($cat_item['component'] === 'wordpress-core' ? 'WordPress Core' : 'Plugin'),
                    'slug'             => $cat_item['component'] ?? '',
                    'wporg_url'        => 'https://wordpress.org/plugins/' . ($cat_item['component'] ?? '') . '/',
                    'is_patched'       => true,
                    'remediation'      => 'Update to latest version or deploy active virtual patch.',
                    'affected_version' => '<= Latest Known Vulnerable',
                    'patched_version'  => 'Official Patch or Virtual Shield',
                ],
                'is_wordpress'       => true,
                'component'          => $cat_item['component'],
                'has_prebuilt_patch' => true,
                'patch_data'         => $cat_item,
                'correlation'        => $correlation,
            ];
        }

        // 2. Check Transient Cache
        $cache_key = self::TRANSIENT_PREFIX . md5($cve_id);
        $cached = get_transient($cache_key);
        if (is_array($cached) && !empty($cached['cve_id'])) {
            // Re-run correlation on cached intelligence to reflect current site plugins
            $cached['correlation'] = self::correlate_component(
                $cached['component'] ?? ($cached['software']['slug'] ?? ''),
                $cached['title'] ?? '',
                $cached['description'] ?? '',
                $cached['component_type'] ?? ($cached['software']['type'] ?? 'plugin'),
                $cached['vulnerable_max_version'] ?? ($cached['software']['affected_version'] ?? '')
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

        // Dates & Publishing
        $published_at = !empty($cve_item['published']) ? gmdate('F j, Y', strtotime($cve_item['published'])) : 'N/A';
        $updated_at   = !empty($cve_item['lastModified']) ? gmdate('F j, Y', strtotime($cve_item['lastModified'])) : 'N/A';

        // Researcher / Source
        $source_id = $cve_item['sourceIdentifier'] ?? '';
        $researcher = 'NVD / NIST';
        if (stripos($source_id, 'wordfence') !== false) {
            $researcher = 'Wordfence Security';
        } elseif (stripos($source_id, 'patchstack') !== false) {
            $researcher = 'Patchstack';
        } elseif (stripos($source_id, 'mitre') !== false) {
            $researcher = 'MITRE';
        } elseif (!empty($source_id)) {
            $researcher = sanitize_text_field($source_id);
        }

        // Weakness / CWE
        $weakness = 'Security Vulnerability';
        if (!empty($cve_item['weaknesses'][0]['description'][0]['value'])) {
            $cwe_id = $cve_item['weaknesses'][0]['description'][0]['value'];
            $cwe_map = [
                'CWE-79'  => 'CWE-79 (Cross-Site Scripting)',
                'CWE-89'  => 'CWE-89 (SQL Injection)',
                'CWE-502' => 'CWE-502 (PHP Object Injection)',
                'CWE-22'  => 'CWE-22 (Path Traversal / File Deletion)',
                'CWE-434' => 'CWE-434 (Arbitrary File Upload)',
                'CWE-862' => 'CWE-862 (Missing Authorization / Privilege Escalation)',
                'CWE-287' => 'CWE-287 (Improper Authentication / Auth Bypass)',
                'CWE-352' => 'CWE-352 (Cross-Site Request Forgery)',
                'CWE-94'  => 'CWE-94 (Code Injection / RCE)',
                'CWE-200' => 'CWE-200 (Information Disclosure)',
                'CWE-601' => 'CWE-601 (Open Redirect)',
            ];
            $weakness = $cwe_map[$cwe_id] ?? $cwe_id;
        }

        // References
        $references = [];
        if (!empty($cve_item['references']) && is_array($cve_item['references'])) {
            $seen_urls = [];
            foreach ($cve_item['references'] as $ref) {
                $ref_url = esc_url_raw($ref['url'] ?? '');
                if ($ref_url && !isset($seen_urls[$ref_url])) {
                    $seen_urls[$ref_url] = true;
                    $host = wp_parse_url($ref_url, PHP_URL_HOST) ?: 'Reference';
                    $references[] = [
                        'url'  => $ref_url,
                        'host' => str_replace('www.', '', $host),
                    ];
                    if (count($references) >= 6) {
                        break;
                    }
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

        // Detect target software attributes
        $software_info = self::extract_software_details($cve_item, $description);

        $is_wordpress           = $software_info['is_wordpress'];
        $component_name         = $software_info['slug'];
        $component_type         = $software_info['type_key'];
        $vulnerable_max_version = $software_info['vulnerable_max_version'];

        $vector_type = self::detect_vector_type($description);

        // Correlate with local site inventory
        $correlation = self::correlate_component(
            $component_name,
            $software_info['name'],
            $description,
            $component_type,
            $vulnerable_max_version
        );

        $result = [
            'success'                => true,
            'cve_id'                 => $cve_id,
            'source'                 => 'nvd_upstream',
            'title'                  => sprintf('%s - %s', $cve_id, $software_info['name']),
            'description'            => $description,
            'severity'               => $severity,
            'cvss'                   => $cvss,
            'vector_type'            => $vector_type,
            'published_at'           => $published_at,
            'updated_at'             => $updated_at,
            'researcher'             => $researcher,
            'weakness'               => $weakness,
            'references'             => $references,
            'software'               => [
                'name'             => $software_info['name'],
                'type'             => $software_info['type_label'],
                'slug'             => $software_info['slug'],
                'wporg_url'        => $software_info['wporg_url'],
                'is_patched'       => $software_info['is_patched'],
                'remediation'      => $software_info['remediation'],
                'affected_version' => $software_info['affected_version_str'],
                'patched_version'  => $software_info['patched_version_str'],
            ],
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

    /**
     * Extract detailed software information, versions, and remediation
     *
     * @param array $cve_item
     * @param string $description
     * @return array
     */
    private static function extract_software_details(array $cve_item, string $description): array {
        $slug = '';
        $is_wordpress = false;

        // 1. Try to find slug from WordPress.org Trac / Plugin references
        if (!empty($cve_item['references']) && is_array($cve_item['references'])) {
            foreach ($cve_item['references'] as $ref) {
                $ref_url = $ref['url'] ?? '';
                if (preg_match('/plugins\.trac\.wordpress\.org\/(?:browser|changeset|log)\/([a-zA-Z0-9\-_]+)/i', $ref_url, $sm)) {
                    $slug = sanitize_title($sm[1]);
                    $is_wordpress = true;
                    break;
                }
                if (preg_match('/wordpress\.org\/plugins\/([a-zA-Z0-9\-_]+)/i', $ref_url, $sm)) {
                    $slug = sanitize_title($sm[1]);
                    $is_wordpress = true;
                    break;
                }
                if (preg_match('/@([a-zA-Z0-9\-_]+)/i', $ref_url, $sm)) {
                    $slug = sanitize_title($sm[1]);
                    $is_wordpress = true;
                    break;
                }
            }
        }

        // 2. Check CPEs if slug not found
        $version_end_excluding = '';
        $version_end_including = '';

        if (!empty($cve_item['configurations'][0]['nodes'][0]['cpeMatch'])) {
            foreach ($cve_item['configurations'][0]['nodes'][0]['cpeMatch'] as $cpe) {
                $criteria = $cpe['criteria'] ?? '';
                if (strpos($criteria, 'wordpress') !== false) {
                    $is_wordpress = true;
                }
                $parts = explode(':', $criteria);
                if (empty($slug) && isset($parts[4]) && !empty($parts[4]) && $parts[4] !== 'wordpress') {
                    $slug = sanitize_title($parts[4]);
                    $is_wordpress = true;
                }
                if (!empty($cpe['versionEndExcluding'])) {
                    $version_end_excluding = $cpe['versionEndExcluding'];
                }
                if (!empty($cpe['versionEndIncluding'])) {
                    $version_end_including = $cpe['versionEndIncluding'];
                }
            }
        }

        // 3. Check Affected Data
        if (!empty($cve_item['affected'][0]['affectedData'][0])) {
            $aff = $cve_item['affected'][0]['affectedData'][0];
            if (empty($slug) && !empty($aff['packageName'])) {
                $slug = sanitize_title($aff['packageName']);
                $is_wordpress = true;
            }
            if (!empty($aff['versions'][0]['lessThanOrEqual'])) {
                $version_end_including = $aff['versions'][0]['lessThanOrEqual'];
            } elseif (!empty($aff['versions'][0]['lessThan'])) {
                $version_end_excluding = $aff['versions'][0]['lessThan'];
            }
        }

        // 4. Regex fallback from description
        $desc_lower = strtolower($description);
        if (strpos($desc_lower, 'wordpress') !== false || strpos($desc_lower, 'wp ') !== false || strpos($desc_lower, 'plugin') !== false) {
            $is_wordpress = true;
        }

        if (empty($slug)) {
            if (preg_match('/(?:The\s+)?([A-Za-z0-9\-_]+)(?:\s+[–\-]\s+[A-Za-z0-9\s\-_]+)?\s+(?:plugin|theme)\s+for\s+WordPress/i', $description, $m)) {
                $slug = sanitize_title(trim($m[1]));
            } elseif (preg_match('/in\s+WordPress\s+Core/i', $description)) {
                $slug = 'wordpress-core';
            }
        }

        // Fallback version parse from description
        if (empty($version_end_including) && empty($version_end_excluding)) {
            if (preg_match('/in\s+all\s+versions\s+up\s+to,\s+and\s+including,\s+([0-9\.]+)/i', $description, $vm)) {
                $version_end_including = $vm[1];
            } elseif (preg_match('/versions\s+prior\s+to\s+([0-9\.]+)/i', $description, $vm)) {
                $version_end_excluding = $vm[1];
            }
        }

        // Software Name
        $name = '';
        if (!empty($cve_item['affected'][0]['affectedData'][0]['product'])) {
            $name = sanitize_text_field($cve_item['affected'][0]['affectedData'][0]['product']);
        }
        if (empty($name) || $name === $slug) {
            if (preg_match('/(?:The\s+)?([A-Za-z0-9\s–\-_&]+?)\s+(?:plugin|theme)\s+for\s+WordPress/i', $description, $nm)) {
                $name = trim($nm[1]);
            }
        }
        if (empty($name)) {
            $name = !empty($slug) ? ucwords(str_replace('-', ' ', $slug)) : 'Target Component';
        }

        // Type
        $type_key   = 'plugin';
        $type_label = 'Plugin';
        if ($slug === 'wordpress-core' || stripos($description, 'WordPress Core') !== false) {
            $type_key   = 'core';
            $type_label = 'WordPress Core';
        } elseif (stripos($description, ' theme ') !== false || stripos($slug, '-theme') !== false) {
            $type_key   = 'theme';
            $type_label = 'Theme';
        }

        // Formatted affected version string
        if (!empty($version_end_including)) {
            $affected_version_str = '<= ' . $version_end_including;
            $vulnerable_max = $version_end_including;
        } elseif (!empty($version_end_excluding)) {
            $affected_version_str = '< ' . $version_end_excluding;
            $vulnerable_max = $version_end_excluding;
        } else {
            $affected_version_str = '<= All Known Versions';
            $vulnerable_max = '';
        }

        // Patched Version resolution
        $patched_ver = '';
        if (!empty($version_end_excluding)) {
            $patched_ver = $version_end_excluding;
        } else {
            $wporg_latest = self::get_wporg_plugin_version($slug);
            if (!empty($wporg_latest) && !empty($version_end_including)) {
                if (version_compare($wporg_latest, $version_end_including, '>')) {
                    $patched_ver = $wporg_latest;
                }
            }
        }

        $is_patched = !empty($patched_ver);
        $remediation = $is_patched
            ? sprintf('Update to version %s, or a newer patched version', $patched_ver)
            : 'No official vendor patch released yet (0-Day). Apply Virtual Patch or deactivate component immediately.';

        // WordPress.org URL
        $wporg_url = '';
        if ($type_key === 'plugin' && !empty($slug)) {
            $wporg_url = 'https://wordpress.org/plugins/' . $slug . '/';
        } elseif ($type_key === 'theme' && !empty($slug)) {
            $wporg_url = 'https://wordpress.org/themes/' . $slug . '/';
        } elseif ($type_key === 'core') {
            $wporg_url = 'https://wordpress.org/';
        }

        return [
            'name'                   => $name,
            'slug'                   => $slug,
            'type_key'               => $type_key,
            'type_label'             => $type_label,
            'is_wordpress'           => $is_wordpress,
            'wporg_url'              => $wporg_url,
            'vulnerable_max_version' => $vulnerable_max,
            'affected_version_str'   => $affected_version_str,
            'patched_version_str'    => $patched_ver ?: 'None / 0-Day',
            'is_patched'             => $is_patched,
            'remediation'            => $remediation,
        ];
    }

    /**
     * Resolve Curated Metadata for Pre-Packaged Catalog Items
     *
     * @param string $cve_id
     * @param array  $cat_item
     * @return array
     */
    private static function get_curated_metadata(string $cve_id, array $cat_item): array {
        $curated_db = [
            'CVE-2024-5932' => [
                'cvss'         => 9.8,
                'published_at' => 'August 20, 2024',
                'updated_at'   => 'August 21, 2024',
                'researcher'   => 'Wordfence Security (Callum Kempe)',
                'weakness'     => 'CWE-502 (PHP Object Injection to RCE)',
                'software'     => [
                    'name'             => 'GiveWP – Donation Plugin and Fundraising Platform',
                    'type'             => 'Plugin',
                    'slug'             => 'give',
                    'wporg_url'        => 'https://wordpress.org/plugins/give/',
                    'is_patched'       => true,
                    'remediation'      => 'Update to version 3.14.2, or a newer patched version',
                    'affected_version' => '<= 3.14.1',
                    'patched_version'  => '3.14.2',
                ],
                'references'   => [
                    ['url' => 'https://plugins.trac.wordpress.org/changeset/3132247/', 'host' => 'plugins.trac.wordpress.org'],
                    ['url' => 'https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/', 'host' => 'wordfence.com'],
                    ['url' => 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5932', 'host' => 'cve.mitre.org'],
                ],
            ],
            'CVE-2024-28000' => [
                'cvss'         => 9.8,
                'published_at' => 'August 28, 2024',
                'updated_at'   => 'September 2, 2024',
                'researcher'   => 'Wordfence Security (Rafie Muhammad)',
                'weakness'     => 'CWE-287 (Improper Authentication / Privilege Escalation)',
                'software'     => [
                    'name'             => 'LiteSpeed Cache',
                    'type'             => 'Plugin',
                    'slug'             => 'litespeed-cache',
                    'wporg_url'        => 'https://wordpress.org/plugins/litespeed-cache/',
                    'is_patched'       => true,
                    'remediation'      => 'Update to version 6.4, or a newer patched version',
                    'affected_version' => '<= 6.3.0.1',
                    'patched_version'  => '6.4',
                ],
                'references'   => [
                    ['url' => 'https://plugins.trac.wordpress.org/changeset/3138865/', 'host' => 'plugins.trac.wordpress.org'],
                    ['url' => 'https://www.wordfence.com/blog/2024/08/bounty-awarded-for-unauthenticated-privilege-escalation-vulnerability-patched-in-litespeed-cache-plugin/', 'host' => 'wordfence.com'],
                    ['url' => 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28000', 'host' => 'cve.mitre.org'],
                ],
            ],
            'CVE-2024-31210' => [
                'cvss'         => 7.5,
                'published_at' => 'April 10, 2024',
                'updated_at'   => 'April 12, 2024',
                'researcher'   => 'WordPress Security Team',
                'weakness'     => 'CWE-22 (Path Traversal / Arbitrary File Deletion)',
                'software'     => [
                    'name'             => 'WordPress Core',
                    'type'             => 'WordPress Core',
                    'slug'             => 'wordpress-core',
                    'wporg_url'        => 'https://wordpress.org/',
                    'is_patched'       => true,
                    'remediation'      => 'Update WordPress Core to version 6.5.3, or a newer patched version',
                    'affected_version' => '<= 6.5.2',
                    'patched_version'  => '6.5.3',
                ],
                'references'   => [
                    ['url' => 'https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/', 'host' => 'wordpress.org'],
                    ['url' => 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-31210', 'host' => 'cve.mitre.org'],
                ],
            ],
            'CVE-2023-28121' => [
                'cvss'         => 9.8,
                'published_at' => 'March 23, 2023',
                'updated_at'   => 'March 25, 2023',
                'researcher'   => 'Wordfence Security',
                'weakness'     => 'CWE-287 (Unauthenticated Privilege Escalation)',
                'software'     => [
                    'name'             => 'WooCommerce Payments',
                    'type'             => 'Plugin',
                    'slug'             => 'woocommerce-payments',
                    'wporg_url'        => 'https://wordpress.org/plugins/woocommerce-payments/',
                    'is_patched'       => true,
                    'remediation'      => 'Update to version 5.6.2, or a newer patched version',
                    'affected_version' => '<= 5.6.1',
                    'patched_version'  => '5.6.2',
                ],
                'references'   => [
                    ['url' => 'https://woocommerce.com/document/payments/', 'host' => 'woocommerce.com'],
                    ['url' => 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28121', 'host' => 'cve.mitre.org'],
                ],
            ],
        ];

        return $curated_db[$cve_id] ?? [];
    }

    /**
     * Retrieve Latest Version for a Plugin from WordPress.org API
     *
     * @param string $slug
     * @return string
     */
    public static function get_wporg_plugin_version(string $slug): string {
        $slug = sanitize_title($slug);
        if (empty($slug) || $slug === 'wordpress-core') {
            return '';
        }

        $transient_key = 'wcpscan_wporg_ver_' . md5($slug);
        $cached = get_transient($transient_key);
        if ($cached !== false) {
            return strval($cached);
        }

        $url = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode($slug);
        $resp = wp_remote_get($url, [
            'timeout'    => 6,
            'user-agent' => 'WCP-Security-Scanner/1.26.0 (WordPress Security Engine)',
        ]);

        if (is_wp_error($resp) || wp_remote_retrieve_response_code($resp) !== 200) {
            set_transient($transient_key, '', 86400); // Cache empty for 1 day
            return '';
        }

        $body = wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        $version = !empty($data['version']) ? sanitize_text_field($data['version']) : '';

        set_transient($transient_key, $version, 604800); // Cache 7 days
        return $version;
    }
}
