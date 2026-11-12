<?php
namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Optional WAF pipeline contract implemented by security modules capable of pre-boot
 * Micro-WAF compilation and/or plugins_loaded runtime request evaluation.
 */
interface WafEvaluatorInterface {

    /**
     * Export stateless rules compilable into micro-waf-compiled.php for pre-boot execution.
     *
     * @return array<string, mixed>
     */
    public function compile_preload_ast(): array;

    /**
     * Evaluate an incoming request at plugins_loaded runtime.
     *
     * @param RequestContext $ctx
     * @return WafVerdict|null Return null if request does not violate or match module policy.
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict;
}
