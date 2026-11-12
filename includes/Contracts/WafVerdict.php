<?php
namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Structured WAF evaluation verdict returned by pluggable WafEvaluatorInterface modules.
 */
class WafVerdict {

    /** @var string One of allow|monitor|challenge_pow|rate_limit|block|block_and_ban */
    public string $action = 'monitor';

    /** @var string Rule identifier (e.g. WAF-AI-AGENT-KILLCHAIN) */
    public string $ruleId = '';

    /** @var string Human-readable security reason */
    public string $reason = '';

    /** @var string Category label for incident logging */
    public string $category = 'Next-Gen Threat Defense';

    /** @var string Severity level (low|medium|high|critical) */
    public string $severity = 'high';

    /** @var int HTTP response status code */
    public int $statusCode = 403;

    /** @var int Ban TTL in seconds when action enforces or escalates a ban */
    public int $banTtl = 86400;

    /** @var bool Whether to sync offender IP to Cloudflare Edge */
    public bool $syncCloudflare = false;

    /** @var string[] Rule IDs exempted when action === 'allow' */
    public array $exemptRules = [];

    /**
     * Construct a verdict object cleanly.
     *
     * @param string $action
     * @param string $ruleId
     * @param string $reason
     * @param array<string, mixed> $meta
     */
    public function __construct(string $action, string $ruleId, string $reason, array $meta = []) {
        $this->action         = $action;
        $this->ruleId         = $ruleId;
        $this->reason         = $reason;
        $this->category       = (string) ($meta['category'] ?? $this->category);
        $this->severity       = (string) ($meta['severity'] ?? $this->severity);
        $this->statusCode     = (int) ($meta['status_code'] ?? ($action === 'rate_limit' ? 429 : 403));
        $this->banTtl         = (int) ($meta['ban_ttl'] ?? 86400);
        $this->syncCloudflare = !empty($meta['sync_cloudflare']);
        $this->exemptRules    = isset($meta['exempt_rules']) && is_array($meta['exempt_rules']) ? $meta['exempt_rules'] : [];
    }
}
