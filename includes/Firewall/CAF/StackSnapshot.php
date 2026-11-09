<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\CAF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * StackSnapshot
 *
 * Immutable Value Object / DTO representing the fingerprinted state of the WordPress installation,
 * including active/inactive plugins, active/inactive themes, registered REST namespaces, and detected ecosystems.
 *
 * @package WebCareProScanner\Firewall\CAF
 * @author  Mir Alamin (WebCare Pro)
 */
final class StackSnapshot {

	/**
	 * @param string               $wp_version
	 * @param string               $php_version
	 * @param array<string, array> $active_plugins   [slug => ['version' => string, 'file' => string, 'name' => string]]
	 * @param array<string, array> $inactive_plugins [slug => ['version' => string, 'file' => string, 'name' => string]]
	 * @param array<string, mixed> $active_themes    ['active' => [slug, version], 'parent' => [slug, version]|null]
	 * @param array<string, string> $inactive_themes  [slug => version]
	 * @param array<string>        $rest_namespaces  Registered REST route namespaces
	 * @param array<string>        $detected_ecosystems ['woocommerce', 'elementor', ...]
	 * @param int                  $generated_at     Unix timestamp
	 * @param string               $snapshot_hash    SHA-256 fingerprint
	 */
	public function __construct(
		public readonly string $wp_version,
		public readonly string $php_version,
		public readonly array $active_plugins,
		public readonly array $inactive_plugins,
		public readonly array $active_themes,
		public readonly array $inactive_themes,
		public readonly array $rest_namespaces,
		public readonly array $detected_ecosystems,
		public readonly int $generated_at,
		public readonly string $snapshot_hash
	) {}

	/**
	 * Convert the StackSnapshot into a serializable array.
	 *
	 * @return array<string, mixed>
	 */
	public function to_array(): array {
		return [
			'wp_version'          => $this->wp_version,
			'php_version'         => $this->php_version,
			'active_plugins'      => $this->active_plugins,
			'inactive_plugins'    => $this->inactive_plugins,
			'active_themes'       => $this->active_themes,
			'inactive_themes'     => $this->inactive_themes,
			'rest_namespaces'     => $this->rest_namespaces,
			'detected_ecosystems' => $this->detected_ecosystems,
			'generated_at'        => $this->generated_at,
			'snapshot_hash'       => $this->snapshot_hash,
		];
	}

	/**
	 * Instantiate a StackSnapshot from a serialized array.
	 *
	 * @param array<string, mixed> $data
	 * @return self
	 */
	public static function from_array( array $data ): self {
		return new self(
			(string) ( $data['wp_version'] ?? '' ),
			(string) ( $data['php_version'] ?? '' ),
			(array) ( $data['active_plugins'] ?? [] ),
			(array) ( $data['inactive_plugins'] ?? [] ),
			(array) ( $data['active_themes'] ?? [] ),
			(array) ( $data['inactive_themes'] ?? [] ),
			(array) ( $data['rest_namespaces'] ?? [] ),
			(array) ( $data['detected_ecosystems'] ?? [] ),
			(int) ( $data['generated_at'] ?? time() ),
			(string) ( $data['snapshot_hash'] ?? '' )
		);
	}
}
