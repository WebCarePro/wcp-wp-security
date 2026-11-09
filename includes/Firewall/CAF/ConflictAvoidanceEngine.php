<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * ConflictAvoidanceEngine
 *
 * Evaluates active components within a StackSnapshot and synthesizes deterministic,
 * context-bound exemptions for high-friction plugins (WooCommerce, Elementor, Divi, Forms, FluentCRM).
 *
 * @package WebCareProScanner\Firewall\CAF
 * @author  Mir Alamin (WebCare Pro)
 */
final class ConflictAvoidanceEngine {

	/**
	 * Build scoped parameter and route exemptions for the detected stack.
	 *
	 * @param StackSnapshot $snapshot
	 * @return array<string, mixed>
	 */
	public function get_exemptions_for_stack( StackSnapshot $snapshot ): array {
		$exemptions = [
			'woocommerce_ajax_actions' => [],
			'editor_exempt_actions'    => [],
			'form_submit_routes'       => [],
			'rest_exempt_namespaces'   => [],
			'scoped_rules'             => [],
		];

		$active_slugs = array_keys( $snapshot->active_plugins );

		// 1. WooCommerce safe-pass rules
		if ( in_array( 'woocommerce', $active_slugs, true ) || in_array( 'woocommerce', $snapshot->detected_ecosystems, true ) ) {
			$exemptions['woocommerce_ajax_actions'] = [
				'update_order_review',
				'checkout',
				'add_to_cart',
				'get_refreshed_fragments',
				'ppc-sdk-v6-client-token',
				'ppc_create_order',
				'ppc_approve_order',
				'wc_stripe_create_order',
			];

			$exemptions['scoped_rules'][] = [
				'context'     => 'woocommerce',
				'route'       => '/?wc-ajax=',
				'description' => 'Exempt WooCommerce cart and checkout AJAX endpoints from generic serialized payload flags with JSON error formatting.',
			];
		}

		// 2. Elementor & Elementor Pro
		if ( in_array( 'elementor', $active_slugs, true ) || in_array( 'elementor-pro', $active_slugs, true ) || in_array( 'elementor', $snapshot->detected_ecosystems, true ) ) {
			$exemptions['editor_exempt_actions'][] = 'elementor_ajax';
			$exemptions['rest_exempt_namespaces'][] = 'elementor/v1';

			$exemptions['scoped_rules'][] = [
				'context'     => 'elementor',
				'route'       => 'action=elementor_ajax',
				'capability'  => 'edit_posts',
				'description' => 'Exempt authenticated editor AJAX saves and style schemas from generic CSS/SVG inline regex triggers.',
			];
		}

		// 3. Divi Builder / Divi Theme
		if ( in_array( 'divi-builder', $active_slugs, true ) || ( isset( $snapshot->active_themes['active']['slug'] ) && strtolower( (string) $snapshot->active_themes['active']['slug'] ) === 'divi' ) || in_array( 'divi', $snapshot->detected_ecosystems, true ) ) {
			$exemptions['editor_exempt_actions'][] = 'et_fb_ajax_save';
			$exemptions['editor_exempt_actions'][] = 'et_fb_retrieve_builder_data';

			$exemptions['scoped_rules'][] = [
				'context'     => 'divi',
				'route'       => 'action=et_fb_ajax_save',
				'capability'  => 'edit_posts',
				'description' => 'Exempt Divi front-end visual builder saves and shortcode attributes for authenticated editors.',
			];
		}

		// 4. Form Plugins (Gravity Forms, WPForms, Contact Form 7, Fluent Forms)
		$form_plugins = [
			'gravityforms'   => 'wp-json/gf/v2/forms/',
			'wpforms-lite'   => 'action=wpforms_submit',
			'wpforms'        => 'action=wpforms_submit',
			'contact-form-7' => 'wp-json/contact-form-7/v1/contact-forms/',
			'fluentform'     => 'action=fluentform_submit',
		];

		foreach ( $form_plugins as $plugin_slug => $target_endpoint ) {
			if ( in_array( $plugin_slug, $active_slugs, true ) ) {
				$exemptions['form_submit_routes'][] = [
					'plugin'   => $plugin_slug,
					'endpoint' => $target_endpoint,
				];
			}
		}

		// 5. FluentCRM
		if ( in_array( 'fluent-crm', $active_slugs, true ) ) {
			$exemptions['rest_exempt_namespaces'][] = 'fluent-crm/v2';
			$exemptions['scoped_rules'][] = [
				'context'     => 'fluentcrm',
				'route'       => '/wp-json/fluent-crm/',
				'capability'  => 'manage_options',
				'description' => 'Exempt email campaign HTML bodies from generic XSS filters for verified administrative users.',
			];
		}

		return $exemptions;
	}
}
