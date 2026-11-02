<?php
namespace WcpScanner\Advisor;

if (!defined('ABSPATH')) {
    exit;
}

use WcpScanner\Firewall\FirewallEngine;

/**
 * SiteCapabilityProfiler
 *
 * Fast, 0ms-network local profiler that inspects active plugins, active/parent themes,
 * and proxy topology to produce a rich, evidence-backed capability bag.
 *
 * @package WcpScanner\Advisor
 * @author Mir Alamin (WebCare Pro)
 */
class SiteCapabilityProfiler {

    /**
     * Known ecosystem dictionary mapping plugin file fragments to capability keys.
     */
    private const KNOWN_ECOSYSTEMS = [
        'commerce' => [
            'woocommerce/woocommerce.php'     => 'WooCommerce',
            'easy-digital-downloads/'         => 'Easy Digital Downloads',
            'surecart/'                       => 'SureCart',
            'wp-e-commerce/'                  => 'WP eCommerce',
        ],
        'forms' => [
            'contact-form-7/'                 => 'Contact Form 7',
            'wpforms/'                        => 'WPForms',
            'wpforms-lite/'                   => 'WPForms Lite',
            'gravityforms/'                   => 'Gravity Forms',
            'fluentform/'                     => 'Fluent Forms',
            'formidable/'                     => 'Formidable Forms',
            'ninja-forms/'                    => 'Ninja Forms',
            'forminator/'                     => 'Forminator',
        ],
        'builder' => [
            'elementor/'                      => 'Elementor Website Builder',
            'elementor-pro/'                  => 'Elementor Pro',
            'beaver-builder-lite-version/'    => 'Beaver Builder',
            'bb-plugin/'                      => 'Beaver Builder Pro',
            'oxygen/'                         => 'Oxygen Builder',
            'bricks/'                         => 'Bricks Builder',
        ],
        'membership' => [
            'memberpress/'                    => 'MemberPress',
            'paid-memberships-pro/'           => 'Paid Memberships Pro',
            'restrict-content-pro/'           => 'Restrict Content Pro',
            'armember/'                       => 'ARMember',
            'ultimate-member/'                => 'Ultimate Member',
            's2member/'                       => 's2Member',
            'buddypress/'                     => 'BuddyPress',
            'bbpress/'                        => 'bbPress',
        ],
        'lms' => [
            'sfwd-lms/'                       => 'LearnDash LMS',
            'lifterlms/'                      => 'LifterLMS',
            'tutor/'                          => 'Tutor LMS',
            'learnpress/'                     => 'LearnPress',
            'masterstudy-lms-learning-management-system/' => 'MasterStudy LMS',
            'sensei-lms/'                     => 'Sensei LMS',
        ],
    ];

    /**
     * Recognized commercial / premium theme vendor signatures.
     */
    private const KNOWN_THEME_VENDORS = [
        'divi'          => 'Elegant Themes (Divi)',
        'extra'         => 'Elegant Themes (Extra)',
        'astra'         => 'Brainstorm Force (Astra)',
        'kadence'       => 'Kadence WP',
        'generatepress' => 'GeneratePress',
        'avada'         => 'ThemeFusion (Avada)',
        'flatsome'      => 'UX-Themes (Flatsome)',
        'enfold'        => 'Kriesi (Enfold)',
        'betheme'       => 'Muffin Group (Betheme)',
        'woodmart'      => 'XTemos (WoodMart)',
        'oceanwp'       => 'OceanWP',
        'genesis'       => 'StudioPress (Genesis Framework)',
        'salient'       => 'ThemeNectar (Salient)',
        'uncode'        => 'Undsgn (Uncode)',
        'bridge'        => 'Qode Interactive (Bridge)',
        'x'             => 'Themeco (X Theme)',
        'pro'           => 'Themeco (Pro)',
    ];

    /**
     * Profile the site and return capabilities with evidence and proxy telemetry.
     *
     * @return array
     */
    public static function profile(): array {
        $active_plugins = self::get_active_plugins();
        $theme_info     = self::get_theme_info();
        $capabilities   = self::detect_capabilities($active_plugins, $theme_info);
        $proxy_status   = self::inspect_proxy_status();

        return [
            'capabilities'   => $capabilities,
            'theme'          => $theme_info,
            'active_plugins' => $active_plugins,
            'proxy'          => $proxy_status,
            'profiled_at'    => gmdate('Y-m-d H:i:s'),
        ];
    }

    /**
     * Get active plugin basenames across single and multisite installs.
     *
     * @return array Array of plugin basenames (e.g. ['woocommerce/woocommerce.php', ...])
     */
    private static function get_active_plugins(): array {
        $active = (array) get_option('active_plugins', []);

        if (is_multisite()) {
            $network_active = (array) get_site_option('active_sitewide_plugins', []);
            $active = array_unique(array_merge($active, array_keys($network_active)));
        }

        return array_values(array_filter($active));
    }

    /**
     * Inspect active theme, parent theme, and origin classification.
     *
     * @return array
     */
    private static function get_theme_info(): array {
        $theme = wp_get_theme();
        if (!$theme->exists()) {
            return [
                'name'           => 'Unknown',
                'slug'           => 'unknown',
                'version'        => '1.0.0',
                'is_child'       => false,
                'parent_name'    => null,
                'parent_slug'    => null,
                'classification' => 'unknown',
                'vendor_label'   => null,
            ];
        }

        $stylesheet   = $theme->get_stylesheet();
        $template     = $theme->get_template();
        $is_child     = $stylesheet !== $template;
        $parent_theme = $is_child ? $theme->parent() : null;
        $parent_slug  = $parent_theme ? $parent_theme->get_stylesheet() : null;
        $parent_name  = $parent_theme ? $parent_theme->get('Name') : null;

        // Origin classification heuristics
        $theme_slug_lower = strtolower($template ?: $stylesheet);
        $theme_name_lower = strtolower($theme->get('Name') ?: '');
        $theme_uri_lower  = strtolower((string) $theme->get('ThemeURI'));
        $author_lower     = strtolower((string) $theme->get('Author'));

        $vendor_label   = null;
        $classification = 'wp_org_or_bespoke';

        // Check recognized premium vendor signatures
        foreach (self::KNOWN_THEME_VENDORS as $vendor_slug => $label) {
            if (
                $theme_slug_lower === $vendor_slug ||
                strpos($theme_slug_lower, $vendor_slug) === 0 ||
                strpos($theme_name_lower, $vendor_slug) !== false
            ) {
                $classification = 'recognized_commercial';
                $vendor_label   = $label;
                break;
            }
        }

        if (!$vendor_label) {
            if (preg_match('/\b(themeforest|envato|elegantthemes|studiopress|wpvoyager|woocommerce)\b/i', $theme_uri_lower . ' ' . $author_lower)) {
                $classification = 'recognized_commercial';
                $vendor_label   = 'Commercial Ecosystem';
            } elseif ($is_child) {
                $classification = 'custom_child_theme';
            } else {
                // If it starts with standard default themes (twentytwenty...)
                if (strpos($theme_slug_lower, 'twenty') === 0) {
                    $classification = 'official_core_theme';
                    $vendor_label   = 'WordPress Core Default';
                } else {
                    $classification = 'bespoke_or_directory';
                }
            }
        }

        return [
            'name'           => (string) $theme->get('Name'),
            'slug'           => $stylesheet,
            'version'        => (string) $theme->get('Version'),
            'is_child'       => $is_child,
            'parent_name'    => $parent_name,
            'parent_slug'    => $parent_slug,
            'classification' => $classification,
            'vendor_label'   => $vendor_label,
            'author'         => (string) $theme->get('Author'),
        ];
    }

    /**
     * Detect site capabilities from active plugins and theme.
     *
     * @param array $active_plugins
     * @param array $theme_info
     * @return array
     */
    private static function detect_capabilities(array $active_plugins, array $theme_info): array {
        $capabilities = [
            'commerce'   => [
                'detected'   => false,
                'evidence'   => [],
                'confidence' => 'none',
            ],
            'forms'      => [
                'detected'   => false,
                'evidence'   => [],
                'confidence' => 'none',
            ],
            'builder'    => [
                'detected'   => false,
                'evidence'   => [],
                'confidence' => 'none',
            ],
            'membership' => [
                'detected'   => false,
                'evidence'   => [],
                'confidence' => 'none',
            ],
            'lms'        => [
                'detected'   => false,
                'evidence'   => [],
                'confidence' => 'none',
            ],
        ];

        // 1. Scan active plugins against known ecosystems
        foreach ($active_plugins as $plugin) {
            foreach (self::KNOWN_ECOSYSTEMS as $cap => $patterns) {
                foreach ($patterns as $pattern => $label) {
                    if (strpos($plugin, $pattern) !== false || $plugin === $pattern) {
                        $capabilities[$cap]['detected']   = true;
                        $capabilities[$cap]['evidence'][] = [
                            'type'   => 'plugin',
                            'slug'   => $plugin,
                            'name'   => $label,
                        ];
                        $capabilities[$cap]['confidence'] = 'high';
                    }
                }
            }
        }

        // 2. Check theme for builder integration (e.g. Divi is both theme and builder)
        $theme_slug = strtolower($theme_info['parent_slug'] ?: $theme_info['slug']);
        if (in_array($theme_slug, ['divi', 'extra', 'bricks'], true)) {
            $capabilities['builder']['detected']   = true;
            $capabilities['builder']['evidence'][] = [
                'type' => 'theme',
                'slug' => $theme_slug,
                'name' => $theme_info['name'],
            ];
            $capabilities['builder']['confidence'] = 'high';
        }

        // 3. Functional runtime sanity checks
        if (class_exists('WooCommerce')) {
            $capabilities['commerce']['detected']   = true;
            $capabilities['commerce']['confidence'] = 'high';
            // Verify if public checkout is ready
            $capabilities['commerce']['checkout_ready'] = function_exists('wc_get_page_id') && wc_get_page_id('checkout') > 0;
        }

        return $capabilities;
    }

    /**
     * Inspect proxy topology to protect IP velocity throttles from locking out all visitors.
     *
     * @return array
     */
    private static function inspect_proxy_status(): array {
        $has_cf_header    = !empty($_SERVER['HTTP_CF_CONNECTING_IP']);
        $has_xff_header   = !empty($_SERVER['HTTP_X_FORWARDED_FOR']);
        $raw_remote_addr  = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        
        // Check if FirewallEngine trusted proxy resolution is active
        $is_trusted_proxy = class_exists(FirewallEngine::class) ? FirewallEngine::is_trusted_proxy($raw_remote_addr) : false;
        
        // Flag warning if edge headers are present but REMOTE_ADDR is untrusted private/carrier IP
        $proxy_warning = false;
        $proxy_notes   = 'Direct connection or properly validated proxy.';

        if (($has_cf_header || $has_xff_header) && !$is_trusted_proxy) {
            // Edge header detected, but REMOTE_ADDR is not registered as a trusted proxy
            $proxy_warning = true;
            $proxy_notes   = 'Reverse proxy or CDN header detected, but connecting IP is not in trusted proxy subnet. Velocity rate limiters should be configured carefully.';
        }

        return [
            'has_edge_headers' => ($has_cf_header || $has_xff_header),
            'cf_header'        => $has_cf_header,
            'xff_header'       => $has_xff_header,
            'is_trusted_proxy' => $is_trusted_proxy,
            'proxy_warning'    => $proxy_warning,
            'notes'            => $proxy_notes,
        ];
    }
}
