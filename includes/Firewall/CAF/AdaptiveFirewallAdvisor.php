<?php
declare(strict_types=1);

namespace WcpScanner\Firewall\CAF;

use WcpScanner\Advisor\SiteCapabilityProfiler;
use WcpScanner\Firewall\VirtualPatchManager;
use WcpScanner\Firewall\MicroWafCompiler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AdaptiveFirewallAdvisor
 *
 * Core engine of the Context-Adaptive Firewall (CAF) & StackGuard.
 * Inspects WordPress site anatomy via StackSnapshot, cross-references active/inactive
 * plugins, evaluates version-scoped virtual patches, and recommends/applies optimized WAF profiles.
 *
 * @package WcpScanner\Firewall\CAF
 * @author  Mir Alamin (WebCare Pro)
 */
final class AdaptiveFirewallAdvisor {

	public const OPTION_STACK_SNAPSHOT = 'wcp_caf_stack_snapshot';
	public const OPTION_ACTIVE_PROFILE  = 'wcp_caf_active_profile';
	public const OPTION_DORMANT_LOCK    = 'wcp_caf_lock_dormant_surface';

	public const PROFILE_ECOMMERCE_HARDENED = 'ecommerce_hardened';
	public const PROFILE_CORPORATE_BROCHURE = 'corporate_brochure';
	public const PROFILE_MEMBERSHIP_LMS     = 'membership_lms';
	public const PROFILE_CPANEL_SHARED      = 'cpanel_shared_saver';
	public const PROFILE_HIGH_SECURITY      = 'high_security_paranoid';
	public const PROFILE_BALANCED           = 'balanced';

	/**
	 * Build or retrieve the cached StackSnapshot.
	 *
	 * @param bool $force_refresh
	 * @return StackSnapshot
	 */
	public function get_stack_snapshot( bool $force_refresh = false ): StackSnapshot {
		if ( ! $force_refresh ) {
			$cached = get_option( self::OPTION_STACK_SNAPSHOT );
			if ( is_array( $cached ) && ! empty( $cached['snapshot_hash'] ) ) {
				return StackSnapshot::from_array( $cached );
			}
		}

		return $this->capture_stack_snapshot();
	}

	/**
	 * Deeply capture and fingerprint the full WordPress site anatomy.
	 *
	 * @return StackSnapshot
	 */
	public function capture_stack_snapshot(): StackSnapshot {
		global $wp_version;

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$all_plugins = function_exists( 'get_plugins' ) ? get_plugins() : [];
		$active_plugin_files = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$active_network = (array) get_site_option( 'active_sitewide_plugins', [] );
			$active_plugin_files = array_unique( array_merge( $active_plugin_files, array_keys( $active_network ) ) );
		}

		$active_plugins = [];
		$inactive_plugins = [];
		$detected_ecosystems = [];

		foreach ( $all_plugins as $file => $meta ) {
			$slug = dirname( $file );
			if ( '.' === $slug || '' === $slug ) {
				$slug = sanitize_title( pathinfo( $file, PATHINFO_FILENAME ) );
			}

			$item = [
				'slug'    => $slug,
				'file'    => $file,
				'name'    => $meta['Name'] ?? $slug,
				'version' => $meta['Version'] ?? '0.0.0',
			];

			if ( in_array( $file, $active_plugin_files, true ) ) {
				$active_plugins[ $slug ] = $item;

				// Eco system detection tags
				if ( 'woocommerce' === $slug || str_contains( $file, 'woocommerce' ) ) {
					$detected_ecosystems[] = 'woocommerce';
				} elseif ( 'elementor' === $slug || 'elementor-pro' === $slug ) {
					$detected_ecosystems[] = 'elementor';
				} elseif ( 'divi-builder' === $slug ) {
					$detected_ecosystems[] = 'divi';
				} elseif ( in_array( $slug, [ 'gravityforms', 'wpforms-lite', 'wpforms', 'contact-form-7', 'fluentform' ], true ) ) {
					$detected_ecosystems[] = 'forms';
				} elseif ( in_array( $slug, [ 'sfwd-lms', 'learndash', 'memberpress', 'lifterlms', 'buddyboss-platform' ], true ) ) {
					$detected_ecosystems[] = 'lms_membership';
				} elseif ( 'fluent-crm' === $slug ) {
					$detected_ecosystems[] = 'fluent-crm';
				}
			} else {
				$inactive_plugins[ $slug ] = $item;
			}
		}

		// Themes audit
		$current_theme = wp_get_theme();
		$active_themes = [
			'active' => [
				'slug'    => $current_theme->get_stylesheet(),
				'name'    => $current_theme->get( 'Name' ),
				'version' => $current_theme->get( 'Version' ) ?: '0.0.0',
			],
			'parent' => null,
		];

		if ( $current_theme->parent() ) {
			$parent = $current_theme->parent();
			$active_themes['parent'] = [
				'slug'    => $parent->get_stylesheet(),
				'name'    => $parent->get( 'Name' ),
				'version' => $parent->get( 'Version' ) ?: '0.0.0',
			];
		}

		$all_themes = function_exists( 'wp_get_themes' ) ? wp_get_themes() : [];
		$inactive_themes = [];
		foreach ( $all_themes as $slug => $theme_obj ) {
			if ( $slug !== $current_theme->get_stylesheet() && ( ! $current_theme->parent() || $slug !== $current_theme->parent()->get_stylesheet() ) ) {
				$inactive_themes[ $slug ] = $theme_obj->get( 'Version' ) ?: '0.0.0';
			}
		}

		// REST Namespaces
		$rest_namespaces = [];
		if ( function_exists( 'rest_get_server' ) ) {
			$rest_server = rest_get_server();
			if ( $rest_server ) {
				$rest_namespaces = array_values( array_unique( $rest_server->get_namespaces() ) );
			}
		}
		if ( empty( $rest_namespaces ) ) {
			$rest_namespaces = [ 'wp/v2', 'oembed/1.0' ];
		}

		$detected_ecosystems = array_values( array_unique( $detected_ecosystems ) );

		// Generate canonical fingerprint hash
		$canonical_data = [
			'wp'       => $wp_version ?? '7.0',
			'php'      => PHP_VERSION,
			'plugins'  => array_keys( $active_plugins ),
			'dormant'  => array_keys( $inactive_plugins ),
			'theme'    => $active_themes['active']['slug'],
		];
		$snapshot_hash = hash( 'sha256', (string) wp_json_encode( $canonical_data ) );

		$snapshot = new StackSnapshot(
			(string) ( $wp_version ?? '7.0' ),
			PHP_VERSION,
			$active_plugins,
			$inactive_plugins,
			$active_themes,
			$inactive_themes,
			$rest_namespaces,
			$detected_ecosystems,
			time(),
			$snapshot_hash
		);

		update_option( self::OPTION_STACK_SNAPSHOT, $snapshot->to_array(), false );

		return $snapshot;
	}

	/**
	 * Recommend the optimal smart protection profile based on stack anatomy.
	 *
	 * @param StackSnapshot $snapshot
	 * @return string
	 */
	public function recommend_profile( StackSnapshot $snapshot ): string {
		$ecosystems = $snapshot->detected_ecosystems;
		$active_slugs = array_keys( $snapshot->active_plugins );

		if ( in_array( 'woocommerce', $ecosystems, true ) || in_array( 'woocommerce', $active_slugs, true ) ) {
			return self::PROFILE_ECOMMERCE_HARDENED;
		}

		if ( in_array( 'lms_membership', $ecosystems, true ) || in_array( 'memberpress', $active_slugs, true ) || in_array( 'sfwd-lms', $active_slugs, true ) ) {
			return self::PROFILE_MEMBERSHIP_LMS;
		}

		// Detect low memory / shared cPanel hosting
		$memory_limit = ini_get( 'memory_limit' );
		$is_low_resource = false;
		if ( $memory_limit && preg_match( '/^(\d+)(M|G)?$/i', $memory_limit, $matches ) ) {
			$val = (int) $matches[1];
			if ( ( isset( $matches[2] ) && strtoupper( $matches[2] ) === 'M' && $val <= 128 ) || ( ! isset( $matches[2] ) && $val <= 134217728 ) ) {
				$is_low_resource = true;
			}
		}

		if ( $is_low_resource || isset( $_SERVER['CPANEL'] ) || @file_exists( '/proc/lve/list' ) ) {
			return self::PROFILE_CPANEL_SHARED;
		}

		if ( in_array( 'elementor', $ecosystems, true ) || in_array( 'divi', $ecosystems, true ) ) {
			return self::PROFILE_CORPORATE_BROCHURE;
		}

		return self::PROFILE_BALANCED;
	}

	/**
	 * Generate the complete recommendation matrix for the UI and compiler.
	 *
	 * @param StackSnapshot|null $snapshot
	 * @return array<string, mixed>
	 */
	public function get_recommendations_matrix( ?StackSnapshot $snapshot = null ): array {
		if ( null === $snapshot ) {
			$snapshot = $this->get_stack_snapshot();
		}

		$recommended_profile = $this->recommend_profile( $snapshot );
		$current_profile = get_option( self::OPTION_ACTIVE_PROFILE, $recommended_profile );
		$lock_dormant = (bool) get_option( self::OPTION_DORMANT_LOCK, true );

		// 1. Conflict avoidance exemptions
		$conflict_engine = new ConflictAvoidanceEngine();
		$conflict_exemptions = $conflict_engine->get_exemptions_for_stack( $snapshot );

		// 2. Dormant surface map
		$dormant_plugins = array_keys( $snapshot->inactive_plugins );
		$dormant_themes  = array_keys( $snapshot->inactive_themes );

		// 3. Stack-Scoped Virtual Patches
		$must_enable_patches = [];
		$all_patches = class_exists( VirtualPatchManager::class ) ? ( VirtualPatchManager::get_patch_catalog() ?: [] ) : [];

		foreach ( $all_patches as $patch_id => $patch ) {
			$target = $patch['target'] ?? '';
			$cve    = $patch['cve'] ?? $patch_id;

			// If target matches an installed active plugin
			if ( isset( $snapshot->active_plugins[ $target ] ) ) {
				$installed_ver = $snapshot->active_plugins[ $target ]['version'];
				$fixed_in = $patch['fixed_in'] ?? null;

				if ( $fixed_in && version_compare( (string) $installed_ver, (string) $fixed_in, '<' ) ) {
					$must_enable_patches[] = [
						'id'          => $patch_id,
						'cve'         => $cve,
						'target'      => $target,
						'version'     => $installed_ver,
						'fixed_in'    => $fixed_in,
						'description' => $patch['description'] ?? '',
						'priority'    => 'CRITICAL',
					];
				}
			}
		}

		// Calculate residual risk score (0-100)
		$risk_score = 10; // Baseline
		$risk_score += min( 40, count( $must_enable_patches ) * 15 );
		if ( ! $lock_dormant && ! empty( $dormant_plugins ) ) {
			$risk_score += min( 25, count( $dormant_plugins ) * 3 );
		}
		$risk_score = min( 100, $risk_score );

		return [
			'recommended_profile'    => $recommended_profile,
			'current_profile'        => $current_profile,
			'lock_dormant_surface'   => $lock_dormant,
			'dormant_plugin_count'   => count( $dormant_plugins ),
			'dormant_theme_count'    => count( $dormant_themes ),
			'dormant_plugins'        => $dormant_plugins,
			'dormant_themes'         => $dormant_themes,
			'must_enable_patches'    => $must_enable_patches,
			'conflict_exemptions'    => $conflict_exemptions,
			'residual_risk_score'    => $risk_score,
			'generated_at'           => $snapshot->generated_at,
			'snapshot_hash'          => $snapshot->snapshot_hash,
		];
	}

	/**
	 * Apply an advisory profile and trigger MicroWaf re-compilation.
	 *
	 * @param string $profile_id
	 * @param bool   $lock_dormant
	 * @return array<string, mixed>
	 */
	public function apply_profile( string $profile_id, bool $lock_dormant = true ): array {
		$valid_profiles = [
			self::PROFILE_ECOMMERCE_HARDENED,
			self::PROFILE_CORPORATE_BROCHURE,
			self::PROFILE_MEMBERSHIP_LMS,
			self::PROFILE_CPANEL_SHARED,
			self::PROFILE_HIGH_SECURITY,
			self::PROFILE_BALANCED,
		];

		if ( ! in_array( $profile_id, $valid_profiles, true ) ) {
			$profile_id = self::PROFILE_BALANCED;
		}

		update_option( self::OPTION_ACTIVE_PROFILE, $profile_id );
		update_option( self::OPTION_DORMANT_LOCK, $lock_dormant );

		// Regenerate snapshot
		$snapshot = $this->capture_stack_snapshot();

		// Compile into MicroWaf rules
		$compile_success = false;
		if ( class_exists( MicroWafCompiler::class ) ) {
			$compile_success = MicroWafCompiler::compile_script();
		}

		return [
			'success'         => $compile_success,
			'profile_id'      => $profile_id,
			'lock_dormant'    => $lock_dormant,
			'snapshot_hash'   => $snapshot->snapshot_hash,
			'recommendations' => $this->get_recommendations_matrix( $snapshot ),
		];
	}

	/**
	 * Register lifecycle hooks for automatic stack re-profiling and WAF compilation.
	 */
	public static function register_lifecycle_hooks(): void {
		$handler = static function () {
			$advisor = new self();
			$snapshot = $advisor->capture_stack_snapshot();
			if ( class_exists( MicroWafCompiler::class ) ) {
				MicroWafCompiler::compile_script();
			}
		};

		add_action( 'activated_plugin', $handler, 999 );
		add_action( 'deactivated_plugin', $handler, 999 );
		add_action( 'switch_theme', $handler, 999 );
		add_action( 'upgrader_process_complete', $handler, 999 );
	}
}
