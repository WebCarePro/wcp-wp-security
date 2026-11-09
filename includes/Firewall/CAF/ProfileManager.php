<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * ProfileManager
 *
 * Defines and manages Context-Adaptive Firewall (CAF) smart protection profiles,
 * sensitivities, rate limit thresholds, and environmental adaptions.
 *
 * @package WebCareProScanner\Firewall\CAF
 * @author  Mir Alamin (WebCare Pro)
 */
final class ProfileManager {

	public const PROFILE_ECOMMERCE_HARDENED = 'ecommerce_hardened';
	public const PROFILE_CORPORATE_BROCHURE = 'corporate_brochure';
	public const PROFILE_MEMBERSHIP_LMS     = 'membership_lms';
	public const PROFILE_CPANEL_SHARED      = 'cpanel_shared_saver';
	public const PROFILE_HIGH_SECURITY      = 'high_security_paranoid';
	public const PROFILE_BALANCED           = 'balanced';

	/**
	 * Retrieve all available smart profiles with full capability definitions.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function get_all_profiles(): array {
		return [
			self::PROFILE_ECOMMERCE_HARDENED => [
				'id'          => self::PROFILE_ECOMMERCE_HARDENED,
				'name'        => 'E-Commerce Hardened (WooCommerce / Store Shield)',
				'description' => 'Optimized for stores: zero friction for active cart sessions, strict carding velocity guards, coupon brute-force suppression, and aggressive checkout protection.',
				'icon'        => 'shopping-bag',
				'color'       => '#10b981',
				'sensitivity' => 'high',
				'rules'       => [
					'lock_dormant_surface'     => true,
					'checkout_velocity_guard'  => true,
					'coupon_anti_enumeration'  => true,
					'cart_flooding_defense'    => true,
					'price_scraping_guard'     => true,
					'strict_sqli_rce'          => true,
				],
			],
			self::PROFILE_CORPORATE_BROCHURE => [
				'id'          => self::PROFILE_CORPORATE_BROCHURE,
				'name'        => 'Corporate & Lead Gen (Page Builder Shield)',
				'description' => 'Seamless compatibility for visual page builders (Elementor, Divi) and forms with heavy lockdown on unauthenticated REST and XML-RPC.',
				'icon'        => 'layers',
				'color'       => '#6366f1',
				'sensitivity' => 'medium',
				'rules'       => [
					'lock_dormant_surface'     => true,
					'elementor_divi_safe_pass' => true,
					'form_upload_sanitization' => true,
					'xmlrpc_hard_drop'         => true,
					'strict_sqli_rce'          => true,
				],
			],
			self::PROFILE_MEMBERSHIP_LMS => [
				'id'          => self::PROFILE_MEMBERSHIP_LMS,
				'name'        => 'Membership & LMS (Student Portal Protection)',
				'description' => 'Preserves student dashboard navigation and quizzes while rigorously enforcing credential stuffing defense, session anomaly guards, and user privilege shields.',
				'icon'        => 'users',
				'color'       => '#8b5cf6',
				'sensitivity' => 'high',
				'rules'       => [
					'lock_dormant_surface'     => true,
					'auth_credential_stuffing' => true,
					'usermeta_privilege_guard' => true,
					'session_concurrency_lock' => true,
					'strict_sqli_rce'          => true,
				],
			],
			self::PROFILE_CPANEL_SHARED => [
				'id'          => self::PROFILE_CPANEL_SHARED,
				'name'        => 'cPanel & Shared Host Saver (Resource Preserver)',
				'description' => 'Preempts CloudLinux 508 Resource Limit crashes by prioritizing early edge/preload drops, throttling aggressive search queries, and reducing origin CPU.',
				'icon'        => 'cpu',
				'color'       => '#f59e0b',
				'sensitivity' => 'extreme_early_drop',
				'rules'       => [
					'lock_dormant_surface'     => true,
					'search_query_velocity'    => true,
					'edge_offload_priority'    => true,
					'static_asset_drop'        => true,
					'strict_sqli_rce'          => true,
				],
			],
			self::PROFILE_HIGH_SECURITY => [
				'id'          => self::PROFILE_HIGH_SECURITY,
				'name'        => 'Paranoid Lockdown (Maximum Security Posture)',
				'description' => 'Zero-tolerance enforcement across all boundaries: aggressive rate limits, strict bot challenges, complete dormant lockdown, and immediate CIDR aggregation.',
				'icon'        => 'lock',
				'color'       => '#ef4444',
				'sensitivity' => 'maximum',
				'rules'       => [
					'lock_dormant_surface'     => true,
					'h2_header_sequencing'     => true,
					'pow_challenge_enforced'   => true,
					'strict_virtual_patches'   => true,
					'strict_sqli_rce'          => true,
				],
			],
			self::PROFILE_BALANCED => [
				'id'          => self::PROFILE_BALANCED,
				'name'        => 'Balanced General Defense (Universal Compatibility)',
				'description' => 'Default safe profile suited for blogs, standard content websites, and multi-purpose installations.',
				'icon'        => 'shield',
				'color'       => '#3b82f6',
				'sensitivity' => 'standard',
				'rules'       => [
					'lock_dormant_surface'     => true,
					'standard_sqli_rce_drop'   => true,
					'fail2ban_logging'         => true,
				],
			],
		];
	}

	/**
	 * Get configuration for a specific profile.
	 *
	 * @param string $profile_id
	 * @return array<string, mixed>
	 */
	public static function get_profile( string $profile_id ): array {
		$profiles = self::get_all_profiles();
		return $profiles[ $profile_id ] ?? $profiles[ self::PROFILE_BALANCED ];
	}
}
