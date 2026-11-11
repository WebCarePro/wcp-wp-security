<?php
/**
 * Component Integrity & Supply-Chain Verifier
 *
 * Verifies official WordPress.org origin, release checksum manifests,
 * self-defense SHA-256 manifests, and known commercial vendor plugins/themes/addons
 * for every component and PHP file analyzed by Modular Intelligence Firewall.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Modular
 */

namespace WebCareProScanner\Firewall\Modular;

use WebCareProScanner\Integrity\ChecksumProvider;
use WebCareProScanner\Integrity\KnownVendorManifest;
use WebCareProScanner\Security\PluginSelfDefense;

if (!defined('ABSPATH')) {
    exit;
}

class ComponentIntegrityVerifier {

    /**
     * In-memory cache of component verification results per request.
     *
     * @var array
     */
    private static $component_cache = [];

    /**
     * In-memory cache of individual file forensic verifications per request.
     *
     * @var array
     */
    private static $file_cache = [];

    /**
     * Known commercial / trusted WordPress plugin & addon ecosystems.
     * Maps slug prefix / exact slug to vendor metadata and official update/author domains.
     *
     * @var array
     */
    private const KNOWN_PLUGIN_VENDORS = [
        'woocommerce'          => ['vendor' => 'Automattic / WooCommerce', 'domains' => ['woocommerce.com', 'automattic.com']],
        'jetpack'              => ['vendor' => 'Automattic', 'domains' => ['jetpack.com', 'automattic.com']],
        'akismet'              => ['vendor' => 'Automattic', 'domains' => ['akismet.com', 'automattic.com']],
        'elementor'            => ['vendor' => 'Elementor', 'domains' => ['elementor.com']],
        'essential-addons'     => ['vendor' => 'WPDeveloper', 'domains' => ['essential-addons.com', 'wpdeveloper.com']],
        'happy-elementor'      => ['vendor' => 'weDevs / HappyMonster', 'domains' => ['happyaddons.com', 'wedevs.com']],
        'jet-'                 => ['vendor' => 'Crocoblock (JetPlugins)', 'domains' => ['crocoblock.com']],
        'crocoblock'           => ['vendor' => 'Crocoblock', 'domains' => ['crocoblock.com']],
        'gravityforms'         => ['vendor' => 'Rocketgenius (Gravity Forms)', 'domains' => ['gravityforms.com']],
        'wpforms'              => ['vendor' => 'Awesome Motive (WPForms)', 'domains' => ['wpforms.com']],
        'wp-mail-smtp'         => ['vendor' => 'Awesome Motive (WP Mail SMTP)', 'domains' => ['wpmailsmtp.com']],
        'monsterinsights'      => ['vendor' => 'Awesome Motive (MonsterInsights)', 'domains' => ['monsterinsights.com']],
        'all-in-one-seo'       => ['vendor' => 'Awesome Motive (AIOSEO)', 'domains' => ['aioseo.com']],
        'aioseo'               => ['vendor' => 'Awesome Motive (AIOSEO)', 'domains' => ['aioseo.com']],
        'seedprod'             => ['vendor' => 'Awesome Motive (SeedProd)', 'domains' => ['seedprod.com']],
        'optinmonster'         => ['vendor' => 'Awesome Motive (OptinMonster)', 'domains' => ['optinmonster.com']],
        'fluentform'           => ['vendor' => 'WPManageNinja (Fluent Forms)', 'domains' => ['fluentforms.com', 'wpmanageninja.com']],
        'fluent-crm'           => ['vendor' => 'WPManageNinja (FluentCRM)', 'domains' => ['fluentcrm.com', 'wpmanageninja.com']],
        'fluent-smtp'          => ['vendor' => 'WPManageNinja (FluentSMTP)', 'domains' => ['fluentsmtp.com', 'wpmanageninja.com']],
        'fluent-'              => ['vendor' => 'WPManageNinja (Fluent Suite)', 'domains' => ['wpmanageninja.com']],
        'ninja-tables'         => ['vendor' => 'WPManageNinja', 'domains' => ['wpmanageninja.com']],
        'advanced-custom-fields' => ['vendor' => 'WP Engine (ACF)', 'domains' => ['advancedcustomfields.com', 'wpengine.com']],
        'acf-'                 => ['vendor' => 'WP Engine / ACF Addons', 'domains' => ['advancedcustomfields.com']],
        'wp-migrate-db'        => ['vendor' => 'WP Engine (Delicious Brains)', 'domains' => ['deliciousbrains.com', 'wpengine.com']],
        'wp-rocket'            => ['vendor' => 'WP Media (WP Rocket)', 'domains' => ['wp-rocket.me', 'wpmedia.co']],
        'imagify'              => ['vendor' => 'WP Media (Imagify)', 'domains' => ['imagify.io', 'wpmedia.co']],
        'wordpress-seo'        => ['vendor' => 'Yoast', 'domains' => ['yoast.com']],
        'yoast-'               => ['vendor' => 'Yoast', 'domains' => ['yoast.com']],
        'seo-by-rank-math'     => ['vendor' => 'Rank Math', 'domains' => ['rankmath.com']],
        'post-smtp'            => ['vendor' => 'Post SMTP / Saad Iqbal', 'domains' => ['postmansmtp.com', 'wpexperts.io']],
        'postman-smtp'         => ['vendor' => 'Post SMTP', 'domains' => ['postmansmtp.com']],
        'updraftplus'          => ['vendor' => 'TeamUpdraft', 'domains' => ['updraftplus.com', 'teamupdraft.com']],
        'wp-optimize'          => ['vendor' => 'TeamUpdraft', 'domains' => ['getwpo.com', 'updraftplus.com']],
        'litespeed-cache'      => ['vendor' => 'LiteSpeed Technologies', 'domains' => ['litespeedtech.com']],
        'perfmatters'          => ['vendor' => 'forgemedia (Perfmatters)', 'domains' => ['perfmatters.io']],
        'flying-press'         => ['vendor' => 'FlyingPress', 'domains' => ['flyingpress.com']],
        'sfwd-lms'             => ['vendor' => 'LearnDash / StellarWP', 'domains' => ['learndash.com', 'stellarwp.com']],
        'learndash'            => ['vendor' => 'LearnDash / StellarWP', 'domains' => ['learndash.com', 'stellarwp.com']],
        'uncanny'              => ['vendor' => 'Uncanny Owl', 'domains' => ['uncannyowl.com']],
        'tin-canny'            => ['vendor' => 'Uncanny Owl', 'domains' => ['uncannyowl.com']],
        'ulgm'                 => ['vendor' => 'Uncanny Owl', 'domains' => ['uncannyowl.com']],
        'gravityflow'          => ['vendor' => 'Gravity Flow (CosmicGiant)', 'domains' => ['gravityflow.io', 'cosmicgiant.com']],
        'gamipress'            => ['vendor' => 'GamiPress', 'domains' => ['gamipress.com']],
        'elementskit'          => ['vendor' => 'Wpmet (ElementsKit)', 'domains' => ['wpmet.com']],
        'host-webfonts-local'  => ['vendor' => 'Daan.dev (OMGF)', 'domains' => ['daan.dev', 'ffwp.nl']],
        'omgf'                 => ['vendor' => 'Daan.dev (OMGF)', 'domains' => ['daan.dev', 'ffwp.nl']],
        'all-in-one-wp-migration' => ['vendor' => 'ServMask', 'domains' => ['servmask.com']],
        'profile-builder'      => ['vendor' => 'Cozmoslabs', 'domains' => ['cozmoslabs.com']],
        'edubin'               => ['vendor' => 'PixelCurve (Edubin)', 'domains' => ['thepixelcurve.com']],
        'memberpress'          => ['vendor' => 'Caseproof (MemberPress)', 'domains' => ['memberpress.com']],
        'lifterlms'            => ['vendor' => 'LifterLMS', 'domains' => ['lifterlms.com']],
        'paid-memberships-pro' => ['vendor' => 'Stranger Studios (PMPro)', 'domains' => ['paidmembershipspro.com']],
        'restrict-content'     => ['vendor' => 'StellarWP (Restrict Content)', 'domains' => ['restrictcontentpro.com', 'stellarwp.com']],
        'tutor'                => ['vendor' => 'Themeum (Tutor LMS)', 'domains' => ['themeum.com']],
        'sitepress-multilingual' => ['vendor' => 'OnTheGoSystems (WPML)', 'domains' => ['wpml.org']],
        'wpml-'                => ['vendor' => 'OnTheGoSystems (WPML)', 'domains' => ['wpml.org']],
        'polylang'             => ['vendor' => 'WP SYNTEX (Polylang)', 'domains' => ['polylang.pro']],
        'easy-digital-downloads' => ['vendor' => 'Awesome Motive (EDD)', 'domains' => ['easydigitaldownloads.com']],
        'edd-'                 => ['vendor' => 'Awesome Motive (EDD Addons)', 'domains' => ['easydigitaldownloads.com']],
        'surecart'             => ['vendor' => 'SureCart', 'domains' => ['surecart.com']],
        'astra-'               => ['vendor' => 'Brainstorm Force (Astra)', 'domains' => ['wpastra.com', 'brainstormforce.com']],
        'ultimate-addons'      => ['vendor' => 'Brainstorm Force', 'domains' => ['ultimateelementor.com', 'brainstormforce.com']],
        'kadence-'             => ['vendor' => 'StellarWP (Kadence WP)', 'domains' => ['kadencewp.com', 'stellarwp.com']],
        'gp-premium'           => ['vendor' => 'GeneratePress', 'domains' => ['generatepress.com']],
        'generateblocks'       => ['vendor' => 'GeneratePress (GenerateBlocks)', 'domains' => ['generateblocks.com']],
        'ocean-extra'          => ['vendor' => 'OceanWP', 'domains' => ['oceanwp.org']],
        'fusion-builder'       => ['vendor' => 'ThemeFusion (Avada)', 'domains' => ['avada.com', 'theme-fusion.com']],
        'fusion-core'          => ['vendor' => 'ThemeFusion (Avada)', 'domains' => ['avada.com', 'theme-fusion.com']],
        'js_composer'          => ['vendor' => 'WPBakery', 'domains' => ['wpbakery.com']],
        'greenshift'           => ['vendor' => 'Wpsoul (GreenShift)', 'domains' => ['greenshiftwp.com', 'wpsoul.com']],
        'advanced-google-recaptcha' => ['vendor' => 'WebFactory Ltd', 'domains' => ['webfactoryltd.com', 'getwpcaptcha.com']],
        'blocksy-companion'    => ['vendor' => 'CreativeThemes (Blocksy)', 'domains' => ['creativethemes.com']],
        'revslider'            => ['vendor' => 'ThemePunch (Slider Revolution)', 'domains' => ['sliderrevolution.com', 'themepunch.com']],
        'bb-plugin'            => ['vendor' => 'Beaver Builder', 'domains' => ['wpbeaverbuilder.com']],
        'beaver-builder'       => ['vendor' => 'Beaver Builder', 'domains' => ['wpbeaverbuilder.com']],
        'oxygen'               => ['vendor' => 'Soflyy (Oxygen Builder)', 'domains' => ['oxygenbuilder.com']],
        'mainwp-child'         => ['vendor' => 'MainWP', 'domains' => ['mainwp.com']],
        'worker'               => ['vendor' => 'ManageWP (GoDaddy)', 'domains' => ['managewp.com']],
        'yith-'                => ['vendor' => 'YITH Commercial Addons', 'domains' => ['yithemes.com']],
        'plugin-check'         => ['vendor' => 'WordPress.org Plugin Review Team', 'domains' => []],
        'hello-dolly'          => ['vendor' => 'WordPress.org Core (Matt Mullenweg)', 'domains' => []],
        'hello'                => ['vendor' => 'WordPress.org Core (Matt Mullenweg)', 'domains' => []],
        'wordfence'            => ['vendor' => 'Defiant (Wordfence)', 'domains' => ['wordfence.com']],
        'better-wp-security'   => ['vendor' => 'StellarWP (Solid Security)', 'domains' => ['solidwp.com']],
        'ithemes-security'     => ['vendor' => 'StellarWP (Solid Security)', 'domains' => ['solidwp.com']],
        'cloudflare'           => ['vendor' => 'Cloudflare', 'domains' => []],
        'formidable'           => ['vendor' => 'Strategy11 (Formidable)', 'domains' => ['formidableforms.com']],
        'ninja-forms'          => ['vendor' => 'Saturday Drive (Ninja Forms)', 'domains' => ['ninjaforms.com']],
        'contact-form-7'       => ['vendor' => 'Rock Lobster (Takayuki Miyoshi)', 'domains' => ['contactform7.com']],
        'complianz-'           => ['vendor' => 'Really Simple Plugins (Complianz)', 'domains' => ['complianz.io']],
        'really-simple-ssl'    => ['vendor' => 'Really Simple Plugins', 'domains' => ['really-simple-ssl.com']],
        'mailchimp-for-wp'     => ['vendor' => 'ibericode (MC4WP)', 'domains' => ['mc4wp.com']],
        'redirection'          => ['vendor' => 'John Godley (Redirection)', 'domains' => ['redirection.me']],
        'ai-engine'            => ['vendor' => 'Meow Apps (Jordy Meow)', 'domains' => ['meowapps.com']],
        'envato-market'        => ['vendor' => 'Envato', 'domains' => ['envato.com']],
        'kirki'                => ['vendor' => 'Themeum (Kirki)', 'domains' => ['kirki.org', 'themeum.com']],
        'premium-addons'       => ['vendor' => 'Leap13 (Premium Addons)', 'domains' => ['premiumaddons.com', 'leap13.com']],
        'dk-pdf'               => ['vendor' => 'Dinamiko', 'domains' => ['dinamiko.com']],
        'peters-login-redirect' => ['vendor' => 'LoginWP', 'domains' => ['loginwp.com']],
        'users-customers-import-export' => ['vendor' => 'WebToffee', 'domains' => ['webtoffee.com']],
        'checkout-field-editor' => ['vendor' => 'ThemeHigh', 'domains' => ['themehigh.com']],
        'private-message-for-learndash' => ['vendor' => 'WisdmLabs (LearnDash Addon)', 'domains' => ['wisdmlabs.com', 'learndash.com']],
        'webcare-pro-security' => ['vendor' => 'WebCare Pro (Mir Alamin)', 'domains' => []],
    ];

    /**
     * Known commercial & official theme ecosystems.
     *
     * @var array
     */
    private const KNOWN_THEME_VENDORS = [
        'divi'          => ['vendor' => 'Elegant Themes (Divi)', 'domains' => ['elegantthemes.com']],
        'extra'         => ['vendor' => 'Elegant Themes (Extra)', 'domains' => ['elegantthemes.com']],
        'astra'         => ['vendor' => 'Brainstorm Force (Astra)', 'domains' => ['wpastra.com']],
        'kadence'       => ['vendor' => 'StellarWP (Kadence)', 'domains' => ['kadencewp.com']],
        'generatepress' => ['vendor' => 'GeneratePress', 'domains' => ['generatepress.com']],
        'oceanwp'       => ['vendor' => 'OceanWP', 'domains' => ['oceanwp.org']],
        'avada'         => ['vendor' => 'ThemeFusion (Avada)', 'domains' => ['avada.com']],
        'flatsome'      => ['vendor' => 'UX-Themes (Flatsome)', 'domains' => ['uxthemes.com']],
        'woodmart'      => ['vendor' => 'XTemos (WoodMart)', 'domains' => ['xtemos.com']],
        'enfold'        => ['vendor' => 'Kriesi (Enfold)', 'domains' => ['kriesi.at']],
        'betheme'       => ['vendor' => 'Muffin Group (Betheme)', 'domains' => ['muffingroup.com']],
        'bricks'        => ['vendor' => 'Bricks Builder', 'domains' => ['bricksbuilder.io']],
        'hello-elementor' => ['vendor' => 'Elementor', 'domains' => ['elementor.com']],
        'neve'          => ['vendor' => 'ThemeIsle (Neve)', 'domains' => ['themeisle.com']],
        'blocksy'       => ['vendor' => 'CreativeThemes (Blocksy)', 'domains' => ['creativethemes.com']],
        'genesis'       => ['vendor' => 'StudioPress (Genesis)', 'domains' => ['studiopress.com']],
        'salient'       => ['vendor' => 'ThemeNectar (Salient)', 'domains' => ['themenectar.com']],
        'edubin'        => ['vendor' => 'PixelCurve (Edubin)', 'domains' => ['thepixelcurve.com']],
    ];

    /**
     * Verify origin, official repository membership, known vendor match,
     * and cryptographic checksums for a discovered component.
     *
     * @param array $comp         Component descriptor from discover_all_components().
     * @param bool  $deep_verify  If true, performs network checksum fetch (if uncached) & file sampling.
     * @return array Enriched attestation metadata to merge into component record.
     */
    public static function verify_component(array $comp, bool $deep_verify = false): array {
        $type    = $comp['type'] ?? 'plugin';
        $slug    = $comp['slug'] ?? '';
        $version = trim(preg_replace('/^v/i', '', (string) ($comp['version'] ?? '')));
        $cache_key = "{$type}:{$slug}:{$version}:" . ($deep_verify ? '1' : '0');

        if (isset(self::$component_cache[$cache_key])) {
            return self::$component_cache[$cache_key];
        }

        // Gather metadata headers (URI, Author, UpdateURI, Update transient)
        $meta = self::extract_component_headers($comp);

        $result = [
            'origin_type'       => 'custom_unmanaged',
            'origin_label'      => __('Custom / Unmanaged Extension', 'webcare-pro-security'),
            'is_official_wporg' => false,
            'is_known_vendor'   => false,
            'vendor_name'       => null,
            'vendor_evidence'   => null,
            'trust_tier'        => 'unverified_custom',
            'checksum_status'   => 'not_available',
            'checksum_verified' => false,
            'checksum_source'   => null,
            'checksum_summary'  => [
                'manifest_total'  => 0,
                'files_checked'   => 0,
                'authentic_count' => 0,
                'modified_count'  => 0,
                'unknown_count'   => 0,
                'modified_files'  => [],
                'unknown_files'   => [],
            ],
            'update_available'  => $meta['update_available'],
            'latest_version'    => $meta['latest_version'],
            'plugin_uri'        => $meta['plugin_uri'],
            'author_uri'        => $meta['author_uri'],
            'update_uri'        => $meta['update_uri'],
            'canonical_slug'    => $meta['canonical_slug'],
        ];

        // 1. Self Plugin Check (WebCare Pro Security & Firewall)
        if ($type === 'plugin' && $slug === 'webcare-pro-security') {
            $result = array_merge($result, self::verify_self_plugin($deep_verify));
            self::$component_cache[$cache_key] = $result;
            return $result;
        }

        // 2. MU-Plugins / Drop-ins
        if ($type === 'mu_plugin') {
            $result['origin_type']  = 'mu_plugin_system';
            $result['origin_label'] = __('Must-Use Drop-in / Host MU-Plugin', 'webcare-pro-security');
            $result['trust_tier']   = 'system_mu_plugin';
            self::$component_cache[$cache_key] = $result;
            return $result;
        }

        // 3. Check Known Vendor Catalog (Plugins/Addons or Themes + URI domains, including parent theme inheritance for child themes)
        $vendor_match = self::match_known_vendor($type, $slug, $comp['name'] ?? '', $meta);
        if (!$vendor_match && $type === 'theme' && function_exists('wp_get_theme')) {
            $theme_obj = wp_get_theme($slug);
            $parent_slug = $theme_obj->exists() ? (string) $theme_obj->get_template() : '';
            if ($parent_slug !== '' && $parent_slug !== $slug) {
                $parent_match = self::match_known_vendor('theme', $parent_slug, $parent_slug, $meta);
                if ($parent_match) {
                    $vendor_match = [
                        'vendor'   => $parent_match['vendor'],
                        'evidence' => sprintf('Inherited from trusted parent theme "%s"', $parent_slug),
                    ];
                }
            }
        }
        if ($vendor_match) {
            $result['is_known_vendor'] = true;
            $result['vendor_name']     = $vendor_match['vendor'];
            $result['vendor_evidence'] = $vendor_match['evidence'];
        }

        // 4. Check Official WordPress.org Repository + Checksum Verification
        if ($type === 'plugin') {
            $wporg_check = self::verify_official_wporg_plugin($comp, $meta, $deep_verify);
            $result = array_merge($result, $wporg_check);
        } elseif ($type === 'theme') {
            $theme_check = self::verify_official_wporg_theme($comp, $meta, $deep_verify);
            $result = array_merge($result, $theme_check);
        }

        // 5. Determine Final Origin Type & Trust Tier
        if ($result['is_official_wporg']) {
            if (empty($result['vendor_name']) && !empty($comp['author'])) {
                $clean_author = trim(sanitize_text_field(wp_strip_all_tags((string) $comp['author'])));
                if ($clean_author !== '') {
                    $result['vendor_name'] = $clean_author;
                }
            }

            if ($result['checksum_status'] === 'modified_files_detected' || $result['checksum_status'] === 'unknown_files_detected') {
                $result['origin_type']  = 'official_wporg';
                $result['origin_label'] = __('WordPress.org Official (Integrity Alert)', 'webcare-pro-security');
                $result['trust_tier']   = 'tamper_alert';
            } elseif ($result['checksum_verified']) {
                $result['origin_type']  = 'official_wporg';
                $result['origin_label'] = __('WordPress.org Official (Checksum Verified)', 'webcare-pro-security');
                $result['trust_tier']   = 'verified_official';
            } else {
                $result['origin_type']  = 'official_wporg';
                $result['origin_label'] = __('WordPress.org Directory Listed', 'webcare-pro-security');
                $result['trust_tier']   = 'verified_official';
            }
        } elseif (!empty($comp['is_child'])) {
            $result['origin_type']  = 'child_theme';
            $result['origin_label'] = __('Child Theme (Custom Override)', 'webcare-pro-security');
            $result['trust_tier']   = $result['is_known_vendor'] ? 'trusted_vendor' : 'custom_child';
        } elseif ($result['is_known_vendor']) {
            $result['origin_type']  = 'known_vendor';
            $result['origin_label'] = sprintf(
                /* translators: %s: vendor name */
                __('Trusted Vendor (%s)', 'webcare-pro-security'),
                $result['vendor_name']
            );
            $result['trust_tier']   = 'trusted_vendor';
        }

        self::$component_cache[$cache_key] = $result;
        return $result;
    }

    /**
     * Compute cryptographic hashes and official checksum verification status for a single PHP file.
     *
     * @param string $file_path      Absolute path or relative path from wp-content / ABSPATH.
     * @param array  $component_meta Optional component metadata for context.
     * @return array File forensic attributes (file_sha256, file_md5, file_size, file_mtime, checksum_status, expected_checksum, known_vendor_lib).
     */
    public static function verify_file_forensics(string $file_path, array $component_meta = []): array {
        $resolved = self::resolve_absolute_path($file_path);
        if (!$resolved || !file_exists($resolved) || !is_readable($resolved)) {
            return [
                'file_exists'         => false,
                'file_sha256'         => null,
                'file_md5'            => null,
                'file_size'           => 0,
                'file_mtime'          => null,
                'checksum_status'     => 'missing',
                'expected_checksum'   => null,
                'known_vendor_lib'    => null,
                'is_official_verified'=> false,
            ];
        }

        $cache_key = $resolved;
        if (isset(self::$file_cache[$cache_key])) {
            return self::$file_cache[$cache_key];
        }

        $sha256 = @hash_file('sha256', $resolved) ?: null;
        $md5    = @md5_file($resolved) ?: null;
        $size   = @filesize($resolved) ?: 0;
        $mtime  = @filemtime($resolved) ?: 0;

        $checksum_status      = 'unmanaged_custom';
        $expected_checksum    = null;
        $known_vendor_lib     = null;
        $is_official_verified = false;

        $norm_path = wp_normalize_path($resolved);

        // 1. Check Self-Defense Manifest if inside webcare-pro-security
        $self_base = wp_normalize_path(rtrim(WEBCAREPROSCAN_PATH, '/\\') . '/');
        if (str_starts_with($norm_path, $self_base)) {
            $rel = ltrim(substr($norm_path, strlen($self_base)), '/');
            $manifest = class_exists('\\WebCareProScanner\\Security\\PluginSelfDefense')
                ? PluginSelfDefense::get_baseline_manifest()
                : [];
            if (!empty($manifest)) {
                if (isset($manifest[$rel])) {
                    $exp = is_array($manifest[$rel]) ? ($manifest[$rel]['sha256'] ?? '') : (string) $manifest[$rel];
                    $expected_checksum = $exp;
                    if ($sha256 === $exp) {
                        $checksum_status      = 'self_verified';
                        $is_official_verified = true;
                    } else {
                        $checksum_status = 'self_modified';
                    }
                } else {
                    $checksum_status = 'self_untracked';
                }
            }
        } elseif (defined('WP_PLUGIN_DIR') && str_starts_with($norm_path, wp_normalize_path(rtrim(WP_PLUGIN_DIR, '/\\') . '/'))) {
            // 2. Check Official WordPress.org Plugin Checksums
            if (class_exists('\\WebCareProScanner\\Integrity\\ChecksumProvider')) {
                $chk = ChecksumProvider::verify_plugin_file($resolved);
                $st  = $chk['status'] ?? 'unmanaged';
                if ($st === 'authentic') {
                    $checksum_status      = 'authentic';
                    $expected_checksum    = $md5;
                    $is_official_verified = true;
                } elseif ($st === 'modified') {
                    $checksum_status   = 'modified';
                    $expected_checksum = $chk['expected'] ?? null;
                } elseif ($st === 'unknown') {
                    $checksum_status = 'unknown_in_official';
                } elseif ($st === 'ignored') {
                    $checksum_status      = 'ignored_official_runtime';
                    $is_official_verified = true;
                }
            }
        } elseif (function_exists('get_theme_root') && str_starts_with($norm_path, wp_normalize_path(rtrim(get_theme_root(), '/\\') . '/'))) {
            // 3. Check Official WordPress.org Theme Checksums (only if cached or core theme to stay non-blocking)
            $rel_theme = ltrim(substr($norm_path, strlen(wp_normalize_path(rtrim(get_theme_root(), '/\\') . '/'))), '/');
            $parts     = explode('/', $rel_theme, 2);
            $t_slug    = $parts[0] ?? '';
            $t_ver     = $component_meta['version'] ?? ChecksumProvider::get_installed_theme_version($t_slug);
            $has_cached_theme_manifest = false;
            if (!empty($t_slug) && !empty($t_ver)) {
                $cached = get_transient("webcareproscan_theme_chk_v3_" . sanitize_title($t_slug) . "_" . trim(preg_replace('/^v/i', '', (string) $t_ver)));
                $has_cached_theme_manifest = is_array($cached);
            }
            if ($has_cached_theme_manifest || str_starts_with(strtolower($t_slug), 'twenty')) {
                $chk = ChecksumProvider::verify_theme_file($resolved);
                $st  = $chk['status'] ?? 'unmanaged';
                if ($st === 'authentic') {
                    $checksum_status      = 'authentic';
                    $expected_checksum    = $md5;
                    $is_official_verified = true;
                } elseif ($st === 'modified') {
                    $checksum_status   = 'modified';
                    $expected_checksum = $chk['expected'] ?? null;
                } elseif ($st === 'unknown') {
                    $checksum_status = 'unknown_in_official';
                }
            }
        }

        // 4. Cross-check KnownVendorManifest (128-bit SHA-256 vendor library fingerprints)
        if (!$is_official_verified && class_exists('\\WebCareProScanner\\Integrity\\KnownVendorManifest')) {
            $vendor_lib = KnownVendorManifest::match_known_hash($resolved);
            if ($vendor_lib) {
                $known_vendor_lib     = $vendor_lib['library'] . ' (' . $vendor_lib['file'] . ')';
                $checksum_status      = ($checksum_status === 'modified' || $checksum_status === 'unknown_in_official')
                    ? $checksum_status
                    : 'known_vendor_hash_match';
                $is_official_verified = ($checksum_status === 'known_vendor_hash_match');
            }
        }

        // Fallback label for commercial/known vendor extensions lacking public WP.org checksums
        if ($checksum_status === 'unmanaged_custom' && !empty($component_meta['is_known_vendor'])) {
            $checksum_status = 'known_vendor_unchecksummed';
        }

        $res = [
            'file_exists'          => true,
            'file_sha256'          => $sha256,
            'file_md5'             => $md5,
            'file_size'            => $size,
            'file_mtime'           => $mtime ? gmdate('c', $mtime) : null,
            'checksum_status'      => $checksum_status,
            'expected_checksum'    => $expected_checksum,
            'known_vendor_lib'     => $known_vendor_lib,
            'is_official_verified' => $is_official_verified,
        ];

        self::$file_cache[$cache_key] = $res;
        return $res;
    }

    /**
     * Extract WordPress header URIs & update transient status for a component.
     */
    private static function extract_component_headers(array $comp): array {
        $type = $comp['type'] ?? 'plugin';
        $slug = $comp['slug'] ?? '';
        $file = $comp['file'] ?? '';

        $out = [
            'canonical_slug'   => $slug,
            'plugin_uri'       => '',
            'author_uri'       => '',
            'update_uri'       => '',
            'text_domain'      => '',
            'update_available' => false,
            'latest_version'   => null,
            'listed_on_wporg'  => false,
        ];

        if ($type === 'plugin') {
            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $all = function_exists('get_plugins') ? get_plugins() : [];
            $data = (!empty($file) && isset($all[$file])) ? $all[$file] : null;
            if ($data === null && !empty($slug)) {
                foreach ($all as $pf => $pd) {
                    if (dirname($pf) === $slug || basename($pf, '.php') === $slug) {
                        $file = $pf;
                        $data = $pd;
                        break;
                    }
                }
            }

            if ($data) {
                $out['plugin_uri']  = (string) ($data['PluginURI'] ?? '');
                $out['author_uri']  = (string) ($data['AuthorURI'] ?? '');
                $out['update_uri']  = (string) ($data['UpdateURI'] ?? '');
                $out['text_domain'] = (string) ($data['TextDomain'] ?? '');
            }

            $update_plugins = get_site_transient('update_plugins');
            if ($file && is_object($update_plugins)) {
                if (!empty($update_plugins->no_update[$file])) {
                    $entry = $update_plugins->no_update[$file];
                    if (!empty($entry->slug)) {
                        $out['canonical_slug'] = $entry->slug;
                    }
                    if (!empty($entry->url) && str_contains((string) $entry->url, 'wordpress.org/plugins/')) {
                        $out['listed_on_wporg'] = true;
                    }
                } elseif (!empty($update_plugins->response[$file])) {
                    $entry = $update_plugins->response[$file];
                    $out['update_available'] = true;
                    $out['latest_version']   = $entry->new_version ?? null;
                    if (!empty($entry->slug)) {
                        $out['canonical_slug'] = $entry->slug;
                    }
                    if (!empty($entry->url) && str_contains((string) $entry->url, 'wordpress.org/plugins/')) {
                        $out['listed_on_wporg'] = true;
                    }
                }
            }
        } elseif ($type === 'theme' && function_exists('wp_get_theme')) {
            $theme = wp_get_theme($slug);
            if ($theme->exists()) {
                $out['plugin_uri']  = (string) $theme->get('ThemeURI');
                $out['author_uri']  = (string) $theme->get('AuthorURI');
                $out['update_uri']  = (string) $theme->get('UpdateURI');
                $out['text_domain'] = (string) $theme->get('TextDomain');
            }

            $update_themes = get_site_transient('update_themes');
            if (is_object($update_themes)) {
                if (!empty($update_themes->no_update[$slug])) {
                    $entry = $update_themes->no_update[$slug];
                    if (!empty($entry['url']) && str_contains((string) $entry['url'], 'wordpress.org/themes/')) {
                        $out['listed_on_wporg'] = true;
                    }
                } elseif (!empty($update_themes->response[$slug])) {
                    $entry = $update_themes->response[$slug];
                    $out['update_available'] = true;
                    $out['latest_version']   = $entry['new_version'] ?? null;
                    if (!empty($entry['url']) && str_contains((string) $entry['url'], 'wordpress.org/themes/')) {
                        $out['listed_on_wporg'] = true;
                    }
                }
            }
        }

        return $out;
    }

    /**
     * Match component slug, title, or header URIs against known trusted vendor registries.
     */
    private static function match_known_vendor(string $type, string $slug, string $name, array $meta): ?array {
        $slug_lower = strtolower($slug);
        $name_lower = strtolower($name);
        $uris = strtolower($meta['plugin_uri'] . ' ' . $meta['author_uri'] . ' ' . $meta['update_uri']);

        $catalog = ($type === 'theme') ? self::KNOWN_THEME_VENDORS : self::KNOWN_PLUGIN_VENDORS;

        foreach ($catalog as $pattern => $info) {
            $prefix_match = str_ends_with($pattern, '-')
                ? str_starts_with($slug_lower, $pattern)
                : ($slug_lower === $pattern || str_starts_with($slug_lower, $pattern . '-') || str_starts_with($slug_lower, $pattern . '_'));

            if ($prefix_match) {
                return [
                    'vendor'   => $info['vendor'],
                    'evidence' => sprintf('Matched verified vendor slug pattern "%s"', $pattern),
                ];
            }

            foreach ($info['domains'] as $domain) {
                if ($domain !== '' && str_contains($uris, strtolower($domain))) {
                    return [
                        'vendor'   => $info['vendor'],
                        'evidence' => sprintf('Verified header URI domain "%s"', $domain),
                    ];
                }
            }
        }

        // Generic official core theme detection
        if ($type === 'theme' && preg_match('/^twenty(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|nineteen|twenty|twentyone|twentytwo|twentythree|twentyfour|twentyfive|twentysix)/i', $slug_lower)) {
            return [
                'vendor'   => 'WordPress.org Core Theme Team',
                'evidence' => 'Official WordPress default theme',
            ];
        }

        // Check name fallback for well-known suites
        if (str_contains($name_lower, 'woocommerce') && str_contains($uris, 'woo')) {
            return [
                'vendor'   => 'Automattic / WooCommerce Ecosystem',
                'evidence' => 'WooCommerce addon header signature',
            ];
        }

        return null;
    }

    /**
     * Verify WebCare Pro Security & Firewall against its embedded SHA-256 plugin-manifest.json.
     */
    private static function verify_self_plugin(bool $deep_verify): array {
        $manifest = class_exists('\\WebCareProScanner\\Security\\PluginSelfDefense')
            ? PluginSelfDefense::get_baseline_manifest()
            : [];

        $total    = count($manifest);
        $checked  = 0;
        $authentic = 0;
        $modified = [];

        if ($deep_verify && !empty($manifest)) {
            $base = wp_normalize_path(rtrim(WEBCAREPROSCAN_PATH, '/\\') . '/');
            foreach ($manifest as $rel => $meta) {
                if ($checked >= 250) {
                    break;
                }
                $expected = is_array($meta) ? ($meta['sha256'] ?? '') : (string) $meta;
                $abs = $base . ltrim($rel, '/');
                $checked++;
                if (!file_exists($abs)) {
                    $modified[] = ['file' => $rel, 'status' => 'missing'];
                    continue;
                }
                $actual = @hash_file('sha256', $abs);
                if ($actual === $expected) {
                    $authentic++;
                } else {
                    $modified[] = ['file' => $rel, 'status' => 'modified', 'expected' => $expected, 'actual' => $actual];
                }
            }
        } else {
            // Lightweight main entrypoint check when not running deep verification
            $main_rel = 'webcare-pro-security.php';
            if (isset($manifest[$main_rel])) {
                $exp = is_array($manifest[$main_rel]) ? ($manifest[$main_rel]['sha256'] ?? '') : (string) $manifest[$main_rel];
                $checked = 1;
                $act = @hash_file('sha256', WEBCAREPROSCAN_PATH . $main_rel);
                if ($act === $exp) {
                    $authentic = 1;
                } else {
                    $modified[] = ['file' => $main_rel, 'status' => 'modified', 'expected' => $exp, 'actual' => $act];
                }
            }
        }

        $clean = empty($modified) && $total > 0;
        return [
            'origin_type'       => 'self_official',
            'origin_label'      => $clean ? __('WebCare Pro (SHA-256 Self-Verified)', 'webcare-pro-security') : __('WebCare Pro (Manifest Mismatch)', 'webcare-pro-security'),
            'is_official_wporg' => false,
            'is_known_vendor'   => true,
            'vendor_name'       => 'WebCare Pro (Mir Alamin)',
            'vendor_evidence'   => 'Verified against signed plugin-manifest.json SHA-256 baseline',
            'trust_tier'        => $clean ? 'verified_official' : 'tamper_alert',
            'checksum_status'   => $clean ? 'verified_clean' : 'modified_files_detected',
            'checksum_verified' => $clean,
            'checksum_source'   => 'plugin-manifest.json (SHA-256)',
            'checksum_summary'  => [
                'manifest_total'  => $total,
                'files_checked'   => $checked,
                'authentic_count' => $authentic,
                'modified_count'  => count($modified),
                'unknown_count'   => 0,
                'modified_files'  => array_slice($modified, 0, 20),
                'unknown_files'   => [],
            ],
        ];
    }

    /**
     * Verify plugin against WordPress.org plugin-checksums API (and verify PHP files).
     */
    private static function verify_official_wporg_plugin(array $comp, array $meta, bool $deep_verify): array {
        $slug    = $meta['canonical_slug'] ?: ($comp['slug'] ?? '');
        $version = trim(preg_replace('/^v/i', '', (string) ($comp['version'] ?? '')));
        $folder  = $comp['slug'] ?? '';

        $provider  = new ChecksumProvider();
        $checksums = null;

        // Check transient first if non-deep, or fetch live if deep / listed
        $cache_key_primary = 'webcareproscan_plugin_chk_' . sanitize_title($slug) . '_' . $version;
        $cached_val = get_transient($cache_key_primary);

        if ($deep_verify || $cached_val === false) {
            $checksums = $provider->get_plugin_checksums($slug, $version);
            if (!$checksums && !empty($folder) && $folder !== $slug) {
                $checksums = $provider->get_plugin_checksums($folder, $version);
                if ($checksums) {
                    $slug = $folder;
                }
            }
            if (!$checksums && !empty($meta['text_domain']) && $meta['text_domain'] !== $slug) {
                $checksums = $provider->get_plugin_checksums($meta['text_domain'], $version);
                if ($checksums) {
                    $slug = $meta['text_domain'];
                }
            }
        } elseif (is_array($cached_val)) {
            $checksums = $cached_val;
        }

        if (empty($checksums) || !is_array($checksums)) {
            return [
                'is_official_wporg' => !empty($meta['listed_on_wporg']),
                'checksum_status'   => 'not_available',
                'checksum_verified' => false,
                'checksum_source'   => null,
            ];
        }

        // Checksum manifest found on WordPress.org -> official repository plugin!
        $component_dir = !empty($comp['path']) ? $comp['path'] : (WP_PLUGIN_DIR . '/' . $folder);
        $is_single_file = !is_dir($component_dir) && file_exists(WP_PLUGIN_DIR . '/' . ($comp['file'] ?? $folder . '.php'));

        $checked   = 0;
        $authentic = 0;
        $modified  = [];
        $unknown   = [];

        // Verify key files (all PHP files in manifest up to cap for responsive performance)
        $max_check = $deep_verify ? 300 : 25;
        $main_file = $is_single_file ? basename($comp['file'] ?? $folder . '.php') : '';

        foreach ($checksums as $rel_file => $expected_hash) {
            if ($checked >= $max_check) {
                break;
            }
            if ($is_single_file && $rel_file !== $main_file) {
                continue;
            }
            // Prioritize verifying PHP scripts for speed
            if (!str_ends_with(strtolower($rel_file), '.php') && $checked > 10) {
                continue;
            }

            $abs = $is_single_file ? (WP_PLUGIN_DIR . '/' . $rel_file) : (rtrim($component_dir, '/\\') . '/' . $rel_file);
            if (!file_exists($abs)) {
                continue;
            }
            $checked++;

            if ($is_single_file) {
                $matched = self::matches_expected_checksum($abs, $expected_hash);
                if (!$matched) {
                    // Fallback: WordPress core ships single-file plugins (e.g. hello.php) under api.wordpress.org/core/checksums
                    $core_chk = $provider->get_core_checksums();
                    if (is_array($core_chk) && isset($core_chk['wp-content/plugins/' . $rel_file])) {
                        $matched = self::matches_expected_checksum($abs, $core_chk['wp-content/plugins/' . $rel_file]);
                    }
                }
                if ($matched) {
                    $authentic++;
                } else {
                    $modified[] = [
                        'file'     => $rel_file,
                        'expected' => is_array($expected_hash) ? (string) ($expected_hash['hash'] ?? implode(', ', $expected_hash)) : (string) $expected_hash,
                        'actual'   => (string) @md5_file($abs),
                    ];
                }
                continue;
            }

            $res = ChecksumProvider::verify_plugin_file($abs);
            if (($res['status'] ?? '') === 'authentic') {
                $authentic++;
            } elseif (($res['status'] ?? '') === 'modified') {
                $modified[] = [
                    'file'     => $rel_file,
                    'expected' => $res['expected'] ?? '',
                    'actual'   => $res['actual'] ?? '',
                ];
            }
        }

        // Scan for unknown PHP files in directory when deep verifying
        if ($deep_verify && !$is_single_file && is_dir($component_dir)) {
            try {
                $it = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($component_dir, \RecursiveDirectoryIterator::SKIP_DOTS)
                );
                $scanned_extra = 0;
                foreach ($it as $item) {
                    if ($scanned_extra > 500) {
                        break;
                    }
                    if (!$item->isFile() || strtolower($item->getExtension()) !== 'php') {
                        continue;
                    }
                    $scanned_extra++;
                    $abs_p = wp_normalize_path($item->getPathname());
                    $rel_p = ltrim(substr($abs_p, strlen(wp_normalize_path(rtrim($component_dir, '/\\') . '/'))), '/');
                    if (!isset($checksums[$rel_p])) {
                        $unknown[] = $rel_p;
                    }
                }
            } catch (\Throwable $e) {
                // Non-fatal filesystem iteration notice
            }
        }

        $status = 'verified_clean';
        $verified = true;
        if (!empty($modified)) {
            $status   = 'modified_files_detected';
            $verified = false;
        } elseif (!empty($unknown)) {
            $status   = 'unknown_files_detected';
            $verified = false;
        }

        return [
            'is_official_wporg' => true,
            'checksum_status'   => $status,
            'checksum_verified' => $verified,
            'checksum_source'   => "downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json",
            'checksum_summary'  => [
                'manifest_total'  => count($checksums),
                'files_checked'   => $checked,
                'authentic_count' => $authentic,
                'modified_count'  => count($modified),
                'unknown_count'   => count($unknown),
                'modified_files'  => array_slice($modified, 0, 20),
                'unknown_files'   => array_slice($unknown, 0, 20),
            ],
        ];
    }

    /**
     * Verify theme against WordPress.org theme zip / core checksums manifest.
     */
    private static function verify_official_wporg_theme(array $comp, array $meta, bool $deep_verify): array {
        $slug    = $comp['slug'] ?? '';
        $version = trim(preg_replace('/^v/i', '', (string) ($comp['version'] ?? '')));

        $cache_key     = 'webcareproscan_theme_chk_v3_' . sanitize_title($slug) . '_' . $version;
        $cached        = get_transient($cache_key);
        $is_core_theme = str_starts_with(strtolower($slug), 'twenty');
        $provider      = new ChecksumProvider();
        $checksums     = null;
        $source        = "downloads.wordpress.org/theme/{$slug}.{$version}.zip";

        // Core default themes shipped with WordPress (e.g. twentytwentyfive): check WordPress core checksums first
        if ($is_core_theme) {
            $core_chk = $provider->get_core_checksums();
            if (is_array($core_chk)) {
                $prefix      = "wp-content/themes/{$slug}/";
                $core_subset = [];
                foreach ($core_chk as $file => $hash) {
                    if (str_starts_with($file, $prefix)) {
                        $core_subset[substr($file, strlen($prefix))] = $hash;
                    }
                }
                if (!empty($core_subset)) {
                    $checksums = $core_subset;
                    $source    = 'api.wordpress.org/core/checksums';
                }
            }
        }

        if ($checksums === null) {
            if (is_array($cached)) {
                $checksums = $cached;
            } elseif ($deep_verify || $is_core_theme) {
                $checksums = $provider->get_theme_checksums($slug, $version);
            }
        }

        if (empty($checksums) || !is_array($checksums)) {
            return [
                'is_official_wporg' => !empty($meta['listed_on_wporg']) || $is_core_theme,
                'checksum_status'   => 'not_available',
                'checksum_verified' => false,
                'checksum_source'   => null,
            ];
        }

        $theme_dir = $comp['path'] ?? (function_exists('get_theme_root') ? get_theme_root() . '/' . $slug : '');
        $checked   = 0;
        $authentic = 0;
        $modified  = [];
        $unknown   = [];

        $max_check = $deep_verify ? 200 : 25;
        foreach ($checksums as $rel_file => $expected_hash) {
            if ($checked >= $max_check) {
                break;
            }
            if (!str_ends_with(strtolower($rel_file), '.php') && $rel_file !== 'style.css' && $checked > 10) {
                continue;
            }
            $abs = rtrim($theme_dir, '/\\') . '/' . $rel_file;
            if (!file_exists($abs)) {
                continue;
            }
            $checked++;

            if (self::matches_expected_checksum($abs, $expected_hash)) {
                $authentic++;
            } else {
                $res = ChecksumProvider::verify_theme_file($abs);
                if (($res['status'] ?? '') === 'authentic') {
                    $authentic++;
                } else {
                    $modified[] = [
                        'file'     => $rel_file,
                        'expected' => is_string($expected_hash) ? $expected_hash : ($res['expected'] ?? ''),
                        'actual'   => (string) @md5_file($abs),
                    ];
                }
            }
        }

        $status   = empty($modified) ? 'verified_clean' : 'modified_files_detected';
        $verified = empty($modified);

        return [
            'is_official_wporg' => true,
            'checksum_status'   => $status,
            'checksum_verified' => $verified,
            'checksum_source'   => $source,
            'checksum_summary'  => [
                'manifest_total'  => count($checksums),
                'files_checked'   => $checked,
                'authentic_count' => $authentic,
                'modified_count'  => count($modified),
                'unknown_count'   => count($unknown),
                'modified_files'  => array_slice($modified, 0, 20),
                'unknown_files'   => [],
            ],
        ];
    }

    /**
     * Shared checksum matcher supporting MD5 strings, arrays of valid MD5s, SHA-256 specs, and CRLF->LF normalization.
     */
    private static function matches_expected_checksum(string $abs_path, $expected): bool {
        if ($expected === true) {
            return true;
        }
        if (!file_exists($abs_path) || !is_readable($abs_path)) {
            return false;
        }

        if (is_array($expected) && ($expected['algo'] ?? '') === 'sha256') {
            $sha = @hash_file('sha256', $abs_path);
            return $sha !== false && in_array($sha, (array) ($expected['hash'] ?? []), true);
        }

        $valid_md5s = is_array($expected) ? array_map('strval', (array) ($expected['md5'] ?? $expected['hash'] ?? $expected)) : [(string) $expected];
        $actual_md5 = @md5_file($abs_path);
        if ($actual_md5 !== false && in_array($actual_md5, $valid_md5s, true)) {
            return true;
        }

        $raw = @file_get_contents($abs_path);
        if ($raw !== false) {
            $norm_md5 = md5(str_replace("\r\n", "\n", $raw));
            if (in_array($norm_md5, $valid_md5s, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Safely resolve relative wp-content or absolute file path into verified disk path.
     */
    public static function resolve_absolute_path(string $file_path): ?string {
        $file_path = wp_normalize_path(trim($file_path));
        if ($file_path === '' || str_contains($file_path, '..') || str_contains($file_path, "\0")) {
            return null;
        }

        $candidates = [
            $file_path,
            wp_normalize_path(WP_CONTENT_DIR) . '/' . ltrim($file_path, '/'),
            wp_normalize_path(ABSPATH) . '/' . ltrim($file_path, '/'),
        ];

        $abspath_norm    = wp_normalize_path(ABSPATH);
        $wp_content_norm = wp_normalize_path(WP_CONTENT_DIR);

        foreach ($candidates as $cand) {
            $norm = wp_normalize_path($cand);
            if (file_exists($norm) && is_file($norm)) {
                if (str_starts_with($norm, $wp_content_norm) || str_starts_with($norm, $abspath_norm)) {
                    return $norm;
                }
            }
        }

        return null;
    }
}
