<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

use WebCareProScanner\Advisor\SiteCapabilityProfiler;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Firewall\MicroWafCompiler;

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
 * @package WebCareProScanner\Firewall\CAF
 * @author  Mir Alamin (WebCare Pro)
 */
final class AdaptiveFirewallAdvisor {

	public const OPTION_STACK_SNAPSHOT = 'webcare_caf_stack_snapshot';
	public const OPTION_ACTIVE_PROFILE  = 'webcare_caf_active_profile';
	public const OPTION_DORMANT_LOCK    = 'webcare_caf_lock_dormant_surface';

	public const PROFILE_ECOMMERCE_HARDENED = 'ecommerce_hardened';
	public const PROFILE_CORPORATE_BROCHURE = 'corporate_brochure';
	public const PROFILE_MEMBERSHIP_LMS     = 'membership_lms';
	public const PROFILE_CPANEL_SHARED      = 'cpanel_shared_saver';
	public const PROFILE_HIGH_SECURITY      = 'high_security_paranoid';
	public const PROFILE_BALANCED           = 'balanced';

	private static ?array $runtime_ecosystems = null;
	private static ?array $runtime_active_slugs = null;
	private static ?array $runtime_profile_rules = null;

	/**
	 * Fast O(1) check if a specific ecosystem ('woocommerce', 'commerce', 'lms_membership', 'page_builder', 'elementor', 'divi', 'forms') is active on this site.
	 *
	 * @param string $ecosystem
	 * @return bool
	 */
	public static function has_ecosystem( string $ecosystem ): bool {
		if ( self::$runtime_ecosystems === null ) {
			$cached = get_option( self::OPTION_STACK_SNAPSHOT, [] );
			if ( is_array( $cached ) && isset( $cached['detected_ecosystems'] ) && is_array( $cached['detected_ecosystems'] ) ) {
				self::$runtime_ecosystems = $cached['detected_ecosystems'];
			} else {
				// Lightweight fallback before first snapshot is saved
				$active = (array) get_option( 'active_plugins', [] );
				$active_str = implode( ' ', $active );
				$eco = [];
				if ( str_contains( $active_str, 'woocommerce' ) ) {
					$eco[] = 'woocommerce';
					$eco[] = 'commerce';
				}
				if ( preg_match( '/(?:easy-digital-downloads|surecart|fluent-cart|give|wp-easycart)/i', $active_str ) ) {
					$eco[] = 'commerce';
				}
				if ( preg_match( '/(?:learndash|sfwd-lms|memberpress|lifterlms|simple-membership|ultimate-member)/i', $active_str ) ) {
					$eco[] = 'lms_membership';
				}
				if ( preg_match( '/(?:elementor|divi-builder|bricks|beaver-builder|bb-plugin|js_composer)/i', $active_str ) ) {
					$eco[] = 'page_builder';
				}
				if ( preg_match( '/(?:post-smtp|postman|wp-mail-smtp|fluent-smtp|easy-wp-smtp|smtp-mailer|suremails|wp-offload-ses|mailgun|sendgrid|sparkpost|mailin|brevo|postmark|zoho-mail)/i', $active_str ) ) {
					$eco[] = 'email_smtp';
				}
				self::$runtime_ecosystems = $eco;
			}
		}
		return in_array( $ecosystem, self::$runtime_ecosystems, true );
	}

	/**
	 * Fast O(1) check if a plugin slug is currently installed and active.
	 *
	 * @param string $slug
	 * @return bool
	 */
	public static function is_plugin_slug_active( string $slug ): bool {
		if ( self::$runtime_active_slugs === null ) {
			$cached = get_option( self::OPTION_STACK_SNAPSHOT, [] );
			if ( is_array( $cached ) && ! empty( $cached['active_plugins'] ) && is_array( $cached['active_plugins'] ) ) {
				self::$runtime_active_slugs = array_keys( $cached['active_plugins'] );
			} else {
				$active = (array) get_option( 'active_plugins', [] );
				self::$runtime_active_slugs = array_map( static fn( $f ) => dirname( (string) $f ), $active );
			}
		}
		return in_array( $slug, self::$runtime_active_slugs, true );
	}

	/**
	 * Retrieve the active CAF profile's rule map in O(1) time.
	 *
	 * @return array
	 */
	public static function get_active_profile_rules(): array {
		if ( self::$runtime_profile_rules === null ) {
			$profile_id = (string) get_option( self::OPTION_ACTIVE_PROFILE, '' );
			if ( $profile_id === '' ) {
				$profile_id = self::has_ecosystem( 'woocommerce' ) ? self::PROFILE_ECOMMERCE_HARDENED : self::PROFILE_BALANCED;
			}
			$profile = ProfileManager::get_profile( $profile_id );
			self::$runtime_profile_rules = is_array( $profile['rules'] ?? null ) ? $profile['rules'] : [];
		}
		return self::$runtime_profile_rules;
	}

	/**
	 * Reset in-memory cached helpers when stack changes.
	 */
	public static function reset_runtime_cache(): void {
		self::$runtime_ecosystems    = null;
		self::$runtime_active_slugs  = null;
		self::$runtime_profile_rules = null;
	}

	/**
	 * Get full overview data for UI views and API consumers.
	 *
	 * @return array<string, mixed>
	 */
	public function get_overview(): array {
		$snapshot = $this->get_stack_snapshot();
		$matrix   = $this->get_recommendations_matrix( $snapshot );

		$killswitch_file = defined( 'WP_CONTENT_DIR' ) ? ( WP_CONTENT_DIR . '/uploads/webcare-pro-security/.killswitch' ) : '';
		$is_killed = ( defined( 'WEBCARE_CAF_DISABLE_PRELOAD' ) && WEBCARE_CAF_DISABLE_PRELOAD ) || ( $killswitch_file && file_exists( $killswitch_file ) );

		return [
			'success'              => true,
			'snapshot'             => $snapshot->to_array(),
			'recommendations'      => $matrix,
			'is_killswitch_active' => $is_killed,
			'active_profile'       => $matrix['current_profile'] ?? self::PROFILE_BALANCED,
			'residual_risk_score'  => $matrix['residual_risk_score'] ?? 10,
		];
	}

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
					$detected_ecosystems[] = 'commerce';
				} elseif ( in_array( $slug, [ 'easy-digital-downloads', 'easy-digital-downloads-pro' ], true ) ) {
					$detected_ecosystems[] = 'edd';
					$detected_ecosystems[] = 'commerce';
				} elseif ( 'surecart' === $slug ) {
					$detected_ecosystems[] = 'surecart';
					$detected_ecosystems[] = 'commerce';
				} elseif ( in_array( $slug, [ 'fluent-cart', 'fluent-cart-pro' ], true ) ) {
					$detected_ecosystems[] = 'fluentcart';
					$detected_ecosystems[] = 'commerce';
				} elseif ( in_array( $slug, [ 'give', 'wp-easycart' ], true ) ) {
					$detected_ecosystems[] = 'commerce';
				} elseif ( in_array( $slug, [ 'elementor', 'elementor-pro' ], true ) ) {
					$detected_ecosystems[] = 'elementor';
					$detected_ecosystems[] = 'page_builder';
				} elseif ( 'divi-builder' === $slug ) {
					$detected_ecosystems[] = 'divi';
					$detected_ecosystems[] = 'page_builder';
				} elseif ( in_array( $slug, [ 'bricks', 'beaver-builder-lite-version', 'bb-plugin', 'js_composer' ], true ) ) {
					$detected_ecosystems[] = 'page_builder';
				} elseif ( in_array( $slug, [ 'gravityforms', 'wpforms-lite', 'wpforms', 'contact-form-7', 'fluentform', 'ninja-forms', 'formidable' ], true ) ) {
					$detected_ecosystems[] = 'forms';
				} elseif ( in_array( $slug, [ 'sfwd-lms', 'learndash', 'memberpress', 'lifterlms', 'buddyboss-platform', 'simple-membership', 'ultimate-member', 'paid-memberships-pro', 'restrict-content-pro' ], true ) ) {
					$detected_ecosystems[] = 'lms_membership';
				} elseif ( 'fluent-crm' === $slug ) {
					$detected_ecosystems[] = 'fluent-crm';
				} elseif ( in_array( $slug, [ 'post-smtp', 'wp-mail-smtp', 'wp-mail-smtp-pro', 'fluent-smtp', 'easy-wp-smtp', 'smtp-mailer', 'suremails', 'wp-offload-ses', 'mailgun', 'sendgrid-email-delivery-simplified', 'sparkpost', 'mailin', 'brevo-mail', 'postmark-approved-wordpress-plugin', 'zoho-mail' ], true ) || str_contains( $file, 'postman-smtp' ) || str_contains( $slug, 'smtp' ) ) {
					$detected_ecosystems[] = 'email_smtp';
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

		// Theme ecosystem detection (Divi, Bricks, etc.)
		$active_theme_slug = strtolower( (string) ( $active_themes['active']['slug'] ?? '' ) );
		$parent_theme_slug = strtolower( (string) ( $active_themes['parent']['slug'] ?? '' ) );
		if ( in_array( 'divi', [ $active_theme_slug, $parent_theme_slug ], true ) ) {
			$detected_ecosystems[] = 'divi';
			$detected_ecosystems[] = 'page_builder';
		} elseif ( in_array( 'bricks', [ $active_theme_slug, $parent_theme_slug ], true ) ) {
			$detected_ecosystems[] = 'bricks';
			$detected_ecosystems[] = 'page_builder';
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
		self::reset_runtime_cache();

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
			$target = $patch['component'] ?? ($patch['target'] ?? '');
			$cve    = $patch['cve_id'] ?? ($patch['cve'] ?? $patch_id);

			// If target matches an installed active plugin
			if ( ! empty( $target ) && isset( $snapshot->active_plugins[ $target ] ) ) {
				$installed_ver = $snapshot->active_plugins[ $target ]['version'];
				$fixed_in = $patch['fixed_in'] ?? null;

				// If no specific fixed_in version is set, any version is vulnerable until patched
				if ( ! $fixed_in || version_compare( (string) $installed_ver, (string) $fixed_in, '<' ) ) {
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
	 * When the E-Commerce Hardened profile is activated, Smart Shields
	 * (waf_ecommerce_safe_mode) are automatically enabled to prevent
	 * false-positives on checkout, cart, and payment webhook endpoints.
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

		// --- Profile-Specific Auto-Enable Logic ---
		$auto_enabled = [];

		if ( self::PROFILE_ECOMMERCE_HARDENED === $profile_id ) {
			$settings = get_option( 'webcareproscan_settings', [] );
			$changed  = false;

			// Auto-enable 1: Smart Shields & Verified Integrations (False-Positive Prevention)
			if ( empty( $settings['waf_ecommerce_safe_mode'] ) ) {
				$settings['waf_ecommerce_safe_mode'] = true;
				$auto_enabled[]                      = 'Smart Shields & Verified Integrations (E-Commerce, Membership & Payment Webhook Shield)';
				$changed                             = true;
			}

			// Auto-enable 2: Targeted Endpoint & User-Agent Bypass Rules
			// Inject default WooCommerce + payment gateway bypass rules if the list is currently empty.
			$existing_rules_raw = $settings['waf_targeted_allowlist_rules'] ?? '[]';
			$existing_rules     = is_array( $existing_rules_raw )
				? $existing_rules_raw
				: (array) json_decode( (string) $existing_rules_raw, true );

			if ( empty( $existing_rules ) ) {
				$default_bypass_rules = self::get_ecommerce_default_bypass_rules();
				$settings['waf_targeted_allowlist_rules'] = wp_json_encode( $default_bypass_rules );
				$auto_enabled[] = 'Targeted Endpoint & User-Agent Bypass Rules (pre-loaded WooCommerce REST, Stripe & PayPal webhook bypass rules)';
				$changed        = true;
			}

			if ( $changed ) {
				update_option( 'webcareproscan_settings', $settings, false );
			}
		}

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
			'auto_enabled'    => $auto_enabled,
			'recommendations' => $this->get_recommendations_matrix( $snapshot ),
		];
	}

	/**
	 * Default bypass rule definitions injected when E-Commerce Hardened profile is applied
	 * and no Targeted Allowlist rules have been configured yet.
	 *
	 * Covers: WooCommerce REST API, Stripe webhooks, and PayPal IPN.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function get_ecommerce_default_bypass_rules(): array {
		return [
			[
				'id'               => 'webcare_auto_woo_rest',
				'name'             => 'WooCommerce REST API (Auto)',
				'enabled'          => true,
				'user_agents'      => [],
				'endpoints'        => [ '/wp-json/wc/v3/*', '/wp-json/wc/v2/*', '/wp-json/wc-analytics/*' ],
				'ip_addresses'     => [],
				'hostnames'        => [],
				'asns'             => [],
				'required_headers' => [],
				'methods'          => [ 'GET', 'POST', 'PUT', 'DELETE' ],
				'log_payload'      => true,
				'description'      => 'Auto-added by E-Commerce Hardened CAF profile. Allows WooCommerce REST API v2/v3 and analytics endpoints to function without WAF interference.',
			],
			[
				'id'               => 'webcare_auto_stripe_webhook',
				'name'             => 'Stripe Webhook (Auto)',
				'enabled'          => true,
				'user_agents'      => [ 'Stripe/1.0 (+https://stripe.com/docs/webhooks)' ],
				'endpoints'        => [ '/wc-api/WC_Stripe*', '/wp-json/wc/v3/payment_gateways*', '/?wc-api=wc_stripe*' ],
				'ip_addresses'     => [
					'3.18.12.63/32',
					'3.130.192.231/32',
					'13.235.14.237/32',
					'13.235.122.149/32',
					'18.211.135.69/32',
					'35.154.171.200/32',
					'52.15.183.38/32',
					'54.187.174.169/32',
					'54.187.205.235/32',
					'54.187.216.72/32',
					'54.241.31.99/32',
					'54.241.31.102/32',
					'54.241.34.107/32',
				],
				'hostnames'        => [ 'stripe.com', 'hooks.stripe.com' ],
				'asns'             => [],
				'required_headers' => [ 'Stripe-Signature' ],
				'methods'          => [ 'POST' ],
				'log_payload'      => true,
				'description'      => 'Auto-added by E-Commerce Hardened CAF profile. Permits Stripe payment webhooks via official IPs and Stripe-Signature header verification.',
			],
			[
				'id'               => 'webcare_auto_paypal_ipn',
				'name'             => 'PayPal IPN & Webhooks (Auto)',
				'enabled'          => true,
				'user_agents'      => [ 'PayPal/IPN*', 'Java/*' ],
				'endpoints'        => [ '/wc-api/WC_Paypal*', '/wc-api/wc_paypal*', '/?wc-api=WC_PayPal*', '/wp-json/wc/v3/payment_gateways*' ],
				'ip_addresses'     => [
					'173.0.80.0/20',
					'66.211.168.0/22',
					'64.4.240.0/21',
					'64.4.248.0/22',
					'185.177.189.0/24',
					'3.253.0.0/16',
					'52.212.0.0/15',
				],
				'hostnames'        => [ 'paypal.com', 'ipnpb.paypal.com', 'ipnpb.sandbox.paypal.com' ],
				'asns'             => [ 'AS17012' ],
				'required_headers' => [],
				'methods'          => [ 'POST' ],
				'log_payload'      => true,
				'description'      => 'Auto-added by E-Commerce Hardened CAF profile. Permits PayPal IPN and webhook callbacks from official PayPal IP ranges (AS17012).',
			],
		];
	}

	/**
	 * Register lifecycle hooks for automatic stack re-profiling, WAF compilation, and Cloudflare Edge synchronization.
	 */
	public static function register_lifecycle_hooks(): void {
		$handler = static function () {
			$advisor = new self();
			$advisor->capture_stack_snapshot();
			if ( class_exists( MicroWafCompiler::class ) ) {
				MicroWafCompiler::compile_script();
			}
			self::schedule_edge_auto_sync();
		};

		add_action( 'activated_plugin', $handler, 999 );
		add_action( 'deactivated_plugin', $handler, 999 );
		add_action( 'switch_theme', $handler, 999 );
		add_action( 'upgrader_process_complete', $handler, 999 );
		add_action( 'webcareproscan_settings_updated', $handler, 999 );

		// Register single-event background cron hook for non-blocking edge sync
		if ( class_exists( '\\WebCareProScanner\\System\\Cron\\CronControlCenter' ) ) {
			add_action(
				'webcare_cf_auto_sync_edge_cron',
				static function () {
					\WebCareProScanner\System\Cron\CronControlCenter::invoke_task_handler( 'webcare_cf_auto_sync_edge_cron', 'wp_cron' );
				}
			);
		} else {
			add_action( 'webcare_cf_auto_sync_edge_cron', [ __CLASS__, 'execute_edge_auto_sync' ] );
		}
	}

	/**
	 * Schedule non-blocking asynchronous Cloudflare Edge rule synchronization.
	 */
	public static function schedule_edge_auto_sync(): void {
		$settings = \WebCareProScanner\System\SettingsManager::get_settings();
		$token = $settings['cloudflare_api_token'] ?? '';
		$zone_id = $settings['cloudflare_zone_id'] ?? '';

		if ( empty( $token ) || empty( $zone_id ) ) {
			return;
		}

		$auto_sync = get_option( 'webcare_cf_auto_sync_edge', true );
		if ( ! $auto_sync ) {
			return;
		}

		if ( ! wp_next_scheduled( 'webcare_cf_auto_sync_edge_cron' ) ) {
			wp_schedule_single_event( time() + 5, 'webcare_cf_auto_sync_edge_cron' );
		}
	}

	/**
	 * Background execution worker for Cloudflare Edge rule synchronization.
	 */
	public static function execute_edge_auto_sync(): void {
		$settings = \WebCareProScanner\System\SettingsManager::get_settings();
		$token = $settings['cloudflare_api_token'] ?? '';
		$zone_id = $settings['cloudflare_zone_id'] ?? '';

		if ( empty( $token ) || empty( $zone_id ) || ! class_exists( CloudflareSlotOptimizer::class ) ) {
			return;
		}

		$optimizer = new CloudflareSlotOptimizer();
		$breaker = class_exists( OriginLoadCircuitBreaker::class ) ? new OriginLoadCircuitBreaker() : null;
		$origin_survival = $breaker ? $breaker->is_survival_mode_active() : false;

		$optimizer->deploy_to_cloudflare( $zone_id, null, [], $origin_survival );

		update_option( 'webcare_cf_last_auto_sync_time', time(), false );
	}
}
