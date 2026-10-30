<?php
namespace WcpScanner\Security;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PromptInjectionGuard
 *
 * WordPress 7.0+ AI Client & Prompt-Injection Guard.
 * Inspects incoming untrusted inputs (comments, reviews, order notes, contact form fields, REST input)
 * destined for LLM prompts, MCP tools, or AI processing.
 * Detects adversarial prompt overrides, jailbreaks, hidden Unicode tag characters, and environment extraction attacks.
 */
class PromptInjectionGuard {

    const OPTION_SETTINGS = 'wcpscan_prompt_guard_settings';
    const OPTION_CATCHES  = 'wcpscan_prompt_guard_catches';

    /**
     * Common adversarial LLM jailbreak and system prompt override expressions.
     */
    const PROMPT_OVERRIDE_PATTERNS = [
        'ignore_instructions'   => '/(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|directives|commands|rules)/i',
        'system_override'       => '/(?:system\s+(?:prompt\s+)?override|override\s+system\s+directives)/i',
        'dan_jailbreak'         => '/(?:you\s+are\s+now\s+(?:in\s+)?(?:dan|developer\s+mode|unfiltered|jailbroken|an\s+unrestricted\s+ai))/i',
        'bypass_safety'         => '/(?:bypass|disable|ignore)\s+all\s+(?:safety|content|ethical)\s+(?:filters|protocols|guidelines|policies)/i',
        'reveal_prompt'         => '/(?:output|print|reveal|display|leak)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|pre-prompt|context\s+window)/i',
        'hypothetical_override' => '/(?:in\s+this\s+hypothetical\s+scenario,\s+you\s+have\s+no\s+rules|act\s+as\s+if\s+you\s+have\s+no\s+restrictions)/i',
    ];

    /**
     * Environment extraction and WordPress configuration exfiltration patterns.
     */
    const SECRET_LEAK_PATTERNS = [
        'wp_config_leak'   => '/(?:wp-config\.php|DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)/i',
        'printenv'         => '/(?:printenv|getenv\(|get_defined_vars|phpinfo\(\))/i',
        'etc_passwd'       => '/(?:\/etc\/passwd|\/etc\/shadow|\.env\.local)/i',
    ];

    /**
     * Initialize Prompt Injection Guard.
     */
    public static function init() {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        // Hook into comments to inspect for prompt injection attacks
        if (!empty($settings['inspect_comments'])) {
            add_filter('preprocess_comment', [__CLASS__, 'inspect_incoming_comment']);
        }
    }

    /**
     * Get settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'               => true,
            'inspect_comments'      => true,
            'block_prompt_override' => true,
            'block_unicode_tags'    => true,
            'block_secret_leaks'    => true,
            'action'                => 'moderate', // 'moderate' (hold for review), 'sanitize', or 'block'
        ];
        $saved = get_option(self::OPTION_SETTINGS, []);
        return is_array($saved) ? array_merge($defaults, $saved) : $defaults;
    }

    /**
     * Update settings.
     *
     * @param array $settings
     * @return bool
     */
    public static function update_settings(array $settings): bool {
        $current = self::get_settings();
        $updated = [
            'enabled'               => !empty($settings['enabled']),
            'inspect_comments'      => !empty($settings['inspect_comments']),
            'block_prompt_override' => !empty($settings['block_prompt_override']),
            'block_unicode_tags'    => !empty($settings['block_unicode_tags']),
            'block_secret_leaks'    => !empty($settings['block_secret_leaks']),
            'action'                => in_array($settings['action'] ?? '', ['block', 'sanitize', 'moderate'], true) ? $settings['action'] : 'moderate',
        ];
        return update_option(self::OPTION_SETTINGS, array_merge($current, $updated), false);
    }

    /**
     * Inspect comment submission for prompt injection attacks.
     *
     * @param array $commentdata
     * @return array
     */
    public static function inspect_incoming_comment(array $commentdata): array {
        $text = $commentdata['comment_content'] ?? '';
        $author = $commentdata['comment_author'] ?? '';
        $full_probe = $author . ' ' . $text;

        $analysis = self::inspect_prompt($full_probe, 'wordpress_comment');

        if (!$analysis['is_safe']) {
            $settings = self::get_settings();
            self::record_catch('comment', $analysis['findings'], $analysis['risk_score'], $settings['action']);

            // Sanitize invisible unicode tag smuggling characters if detected
            if (!empty($analysis['has_unicode_tags'])) {
                $commentdata['comment_content'] = $analysis['cleaned_text'];
            }

            if ($settings['action'] === 'block') {
                wp_die(
                    esc_html__('Submission rejected: Potential prompt injection or adversarial instruction detected.', 'wcp-security-scanner'),
                    esc_html__('Prompt Injection Blocked', 'wcp-security-scanner'),
                    ['response' => 403, 'back_link' => true]
                );
            } elseif ($settings['action'] === 'moderate') {
                // Route comment to WordPress moderation hold queue rather than breaking user experience with 403
                $commentdata['comment_approved'] = 0;
            }
        }

        return $commentdata;
    }

    /**
     * Deep inspection of any prompt text destined for LLM inference or agent tools.
     *
     * @param string $text
     * @param string $context
     * @return array
     */
    public static function inspect_prompt(string $text, string $context = 'generic'): array {
        $findings = [];
        $score = 0;
        $has_override = false;
        $has_unicode_tags = false;
        $has_secret_leak = false;

        // 1. Invisible Unicode Tag Characters Check (U+E0000 - U+E007F)
        if (preg_match('/[\x{E0000}-\x{E007F}]/u', $text)) {
            $has_unicode_tags = true;
            $score += 70;
            $findings[] = 'Invisible Unicode tag characters detected (adversarial prompt smuggling).';
        }

        // 2. Prompt Override & Jailbreak Patterns Check
        foreach (self::PROMPT_OVERRIDE_PATTERNS as $name => $pattern) {
            if (preg_match($pattern, $text, $m)) {
                $has_override = true;
                $score += 80;
                $findings[] = sprintf('Adversarial prompt override signature matched: "%s".', substr($m[0], 0, 70));
                break;
            }
        }

        // 3. Secret Leak / Environment Extraction Check
        // In public comment contexts, require an explicit extraction verb (print/dump/reveal/cat)
        // to prevent false positives when visitors legitimately discuss wp-config.php or WordPress settings.
        foreach (self::SECRET_LEAK_PATTERNS as $name => $pattern) {
            if (preg_match($pattern, $text, $m)) {
                if ($context === 'wordpress_comment') {
                    $has_extraction_intent = (bool) preg_match('/(?:reveal|leak|print|display|dump|extract|output|cat|show|get)\s+.*(?:wp-config|DB_|AUTH_|KEY|passwd|getenv|printenv)/i', $text);
                    if (!$has_extraction_intent) {
                        continue; // Benign technical discussion in WordPress comment
                    }
                }
                $has_secret_leak = true;
                $score += 85;
                $findings[] = sprintf('Targeted credential or environment extraction attempt detected: "%s".', $m[0]);
                break;
            }
        }

        // Sanitize out invisible tags
        $cleaned = preg_replace('/[\x{E0000}-\x{E007F}]/u', '', $text);

        $is_safe = ($score === 0);

        return [
            'is_safe'          => $is_safe,
            'risk_score'       => min(100, $score),
            'has_override'     => $has_override,
            'has_unicode_tags' => $has_unicode_tags,
            'has_secret_leak'  => $has_secret_leak,
            'findings'         => $findings,
            'cleaned_text'     => $cleaned,
            'context'          => $context,
        ];
    }

    /**
     * Record prompt injection interception event.
     */
    private static function record_catch(string $source, array $findings, int $score, string $action) {
        $catches = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            $catches = [];
        }

        $raw_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
        $ip = filter_var($raw_ip, FILTER_VALIDATE_IP) ? $raw_ip : '127.0.0.1';

        $event = [
            'id'         => 'pi_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(3)),
            'source'     => sanitize_key($source),
            'ip'         => $ip,
            'score'      => $score,
            'findings'   => array_map('sanitize_text_field', $findings),
            'action'     => $action,
            'timestamp'  => current_time('mysql'),
        ];

        array_unshift($catches, $event);
        if (count($catches) > 100) {
            $catches = array_slice($catches, 0, 100);
        }
        update_option(self::OPTION_CATCHES, $catches, false);

        if (class_exists('\\WcpScanner\\Firewall\\WafFileLogger')) {
            WafFileLogger::log_incident([
                'ip'              => $ip,
                'category'        => 'prompt_injection_guard',
                'rule_id'         => 'wcp_ai_prompt_injection',
                'reason'          => implode(' | ', $findings),
                'action'          => ($action === 'block') ? 'block' : 'sanitize',
                'http_status'     => ($action === 'block') ? 403 : 200,
                'request_uri'     => isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '',
                'request_method'  => 'POST',
                'user_agent'      => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            ]);
        }

        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('ai_defense_prompt_injection', [
                'severity' => 'critical',
                /* translators: 1: source channel, 2: findings summary */
                'message'  => sprintf(__('AI Prompt Injection / Adversarial Jailbreak intercepted in %1$s: %2$s', 'wcp-security-scanner'), $source, implode(', ', $findings)),
                'details'  => [
                    'Source Channel'   => $source,
                    'Interception IP'  => $ip,
                    'Adversarial Findings' => implode(' | ', $findings),
                    'Risk Score'       => $score . '/100',
                    'Enforced Action'  => strtoupper($action),
                ],
            ]);
        }
    }

    /**
     * Get telemetry status.
     *
     * @return array
     */
    public static function get_status(): array {
        $settings = self::get_settings();
        $catches  = get_option(self::OPTION_CATCHES, []);
        if (!is_array($catches)) {
            $catches = [];
        }

        return [
            'enabled'         => !empty($settings['enabled']),
            'settings'        => $settings,
            'total_catches'   => count($catches),
            'recent_catches'  => array_slice($catches, 0, 25),
        ];
    }
}
