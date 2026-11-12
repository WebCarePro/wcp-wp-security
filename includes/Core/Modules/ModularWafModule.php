<?php
namespace WebCareProScanner\Core\Modules;

use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Reference module adapter registering Modular Intelligence WAF & Visual Rule Studio.
 */
class ModularWafModule implements SecurityModuleInterface, WafEvaluatorInterface {

    public function get_id(): string {
        return 'modular-waf';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Modular Behavioral WAF & Visual Rule Studio', 'webcare-pro-security'),
            'description' => __('Autonomous AST-synthesized firewall rules paired with the Cloudflare-style Visual Condition & Wirefilter Studio.', 'webcare-pro-security'),
            'category'    => 'waf',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf',
            'badge'       => 'Core WAF',
        ];
    }

    public function is_applicable(): bool {
        return class_exists(ModularFirewallSynthesizer::class);
    }

    public function boot(): void {
        // Booted directly in early plugins_loaded WAF dispatch path for zero overhead.
    }

    public function get_settings_schema(): array {
        return [];
    }

    public function get_rest_routes(): array {
        return [];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [];
    }

    public function compile_preload_ast(): array {
        return ModularFirewallSynthesizer::get_compiled_preload_rules();
    }

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        return null;
    }
}
