<?php
namespace WcpScanner\Security;

use WcpScanner\System\AuditLogger;
use WcpScanner\Firewall\WafFileLogger;
use WcpScanner\Notifications\NotificationDispatcher;
use WcpScanner\System\WcpActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PromptInjectionGuard
 *
 * Pillar 3: Inbound AI Prompt-Injection & Indirect Jailbreak Firewall:
 * 1. Multi-Pipeline Ingestion Shield: Hooks WordPress comments, WooCommerce checkout order notes,
 *    product reviews, post/page content submissions, and user profile descriptions.
 * 2. Invisible Unicode Tag & Steganography Stripper: Neutralizes high-order ASCII tag bytes
 *    (U+E0000–U+E007F), zero-width characters, and bidirectional control characters.
 * 3. LLM Architecture Delimiter Quarantine: Defeats instruction boundary escapes targeting
 *    ChatML (<|im_start|>), Llama/Mistral ([INST], <|start_header_id|>), and turn-markers (### System:).
 * 4. Model Context Protocol (MCP) Tool-Call Canary: Prevents attackers from tricking AI agents
 *    and background LLMs into executing privileged WordPress tools (user_create, delete_user, options_update).
 * 5. Multi-Mode Enforcement: Supports surgical sanitization (transparent cleaning), moderation quarantine,
 *    and strict 403 request blocking.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class PromptInjectionGuard {

    const OPTION_SETTINGS = 'wcpscan_prompt_guard_settings';
    const OPTION_CATCHES  = 'wcpscan_prompt_guard_catches';

    /**
     * Regex matching invisible Unicode Tag characters (U+E0000-U+E007F), zero-width characters,
     * word joiners, and bidirectional text overrides used for covert prompt injection smuggling.
     */
    const UNICODE_TAG_REGEX = '/[\x{E0000}-\x{E007F}\x{200B}-\x{200D}\x{FEFF}\x{2060}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /**
     * Common adversarial LLM jailbreak and system prompt override expressions.
     */
    const PROMPT_OVERRIDE_PATTERNS = [
        'ignore_instructions'   => '/(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|earlier)\s+(?:instructions|prompts|directives|commands|rules|context)/i',
        'system_override'       => '/(?:system\s+(?:prompt\s+)?override|override\s+system\s+(?:directives|rules|prompts))/i',
        'dan_jailbreak'         => '/(?:you\s+are\s+now\s+(?:in\s+)?(?:dan|developer\s+mode|unfiltered|jailbroken|an\s+unrestricted\s+ai|chaos\s+mode))/i',
        'bypass_safety'         => '/(?:bypass|disable|ignore|deactivate)\s+all\s+(?:safety|content|ethical|moderation)\s+(?:filters|protocols|guidelines|policies)/i',
        'reveal_prompt'         => '/(?:output|print|reveal|display|leak|dump)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|pre-prompt|context\s+window|hidden\s+rules)/i',
        'hypothetical_override' => '/(?:in\s+this\s+hypothetical\s+scenario,\s+you\s+have\s+no\s+rules|act\s+as\s+if\s+you\s+have\s+no\s+restrictions|pretend\s+you\s+are\s+an\s+evil)/i',
        'embedded_comment'      => '/(?:\/\*|<!--|\/\/|#)\s*(?:system|admin|root|instruction|directive|developer)\s*:\s*(?:ignore|whitelist|allow|bypass|override|execute)/i',
    ];

    /**
     * LLM model token boundaries and instruction delimiters.
     */
    const LLM_DELIMITER_PATTERNS = [
        'chatml_delimiters'   => '/(?:<\|im_start\|>|<\|im_end\|>|<\|im_sep\|>)/i',
        'llama_inst_tokens'   => '/(?:\[INST\]|\[\/INST\])/i',
        'llama_header_tokens' => '/(?:<\|begin_of_text\|>|<\|start_header_id\|>|<\|end_header_id\|>|<\|eot_id\|>)/i',
        'turn_directive_tags' => '/(?:###\s*(?:System|Human|Assistant|Instruction|Input|Response)\s*:)/i',
        'anthropic_turn_tags' => '/(?:(?:^|\n)\s*(?:Human|Assistant)\s*:\s*)/i',
    ];

    /**
     * Model Context Protocol (MCP) tool-call spoofing and execution injection patterns.
     */
    const MCP_TOOL_CALL_PATTERNS = [
        'tool_invocation'      => '/(?:call\s+tool|execute\s+tool|use_tool|tool_call|function_call|mcp_tool)\s*[:=]\s*["\']?([a-z0-9_\-]+)/i',
        'privileged_functions' => '/(?:user_create|delete_user|promote_user|wp_options_update|activate_plugin|export_database|grant_elevation)\s*\(/i',
    ];

    /**
     * Environment extraction and WordPress configuration exfiltration patterns.
     */
    const SECRET_LEAK_PATTERNS = [
        'wp_config_leak'   => '/(?:wp-config\.php|DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)/i',
        'printenv'         => '/(?:printenv|getenv\(|get_defined_vars|phpinfo\(\))/i',
        'etc_passwd'       => '/(?:\/etc\/passwd|\/etc\/shadow|\.env\.local|\.env)/i',
    ];

    /**
     * Initialize Prompt Injection Guard hooks.
     */
    public static function init(): void {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        // 1. Comments & Product Reviews
        if (!empty($settings['inspect_comments'])) {
            add_filter('preprocess_comment', [__CLASS__, 'inspect_incoming_comment'], 10, 1);
        }

        // 2. WooCommerce Checkout Order Notes
        if (!empty($settings['inspect_woocommerce'])) {
            add_action('woocommerce_checkout_create_order', [__CLASS__, 'inspect_woocommerce_order'], 10, 2);
            add_filter('woocommerce_new_order_data', [__CLASS__, 'filter_woocommerce_order_data'], 10, 1);
        }

        // 3. Post & Page Content (REST, XML-RPC, and Editor Submissions)
        if (!empty($settings['inspect_posts'])) {
            add_filter('wp_insert_post_data', [__CLASS__, 'inspect_incoming_post_data'], 10, 2);
        }

        // 4. User Bio & Profile Descriptions
        if (!empty($settings['inspect_user_bios'])) {
            add_filter('pre_user_description', [__CLASS__, 'inspect_user_description'], 10, 1);
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
            'inspect_woocommerce'   => true,
            'inspect_posts'         => true,
            'inspect_user_bios'     => true,
            'block_prompt_override' => true,
            'block_unicode_tags'    => true,
            'block_llm_delimiters'  => true,
            'block_mcp_tool_calls'  => true,
            'block_secret_leaks'    => true,
            'action'                => 'sanitize', // 'sanitize' (clean and pass), 'moderate' (hold for review), 'block' (reject 403)
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
            'inspect_woocommerce'   => !empty($settings['inspect_woocommerce']),
            'inspect_posts'         => !empty($settings['inspect_posts']),
            'inspect_user_bios'     => !empty($settings['inspect_user_bios']),
            'block_prompt_override' => !empty($settings['block_prompt_override']),
            'block_unicode_tags'    => !empty($settings['block_unicode_tags']),
            'block_llm_delimiters'  => !empty($settings['block_llm_delimiters']),
            'block_mcp_tool_calls'  => !empty($settings['block_mcp_tool_calls']),
            'block_secret_leaks'    => !empty($settings['block_secret_leaks']),
            'action'                => in_array($settings['action'] ?? '', ['block', 'sanitize', 'moderate'], true) ? $settings['action'] : 'sanitize',
        ];
        $final = array_merge($current, $updated);
        $res = update_option(self::OPTION_SETTINGS, $final, false);

        if (class_exists(WcpActivityLogger::class)) {
            WcpActivityLogger::log(
                'prompt_injection_settings_updated',
                'firewall',
                'info',
                [
                    'settings'    => $final,
                    'description' => 'Updated Inbound AI Prompt Injection & Indirect Jailbreak Firewall settings.',
                ]
            );
        }

        return $res;
    }

    /**
     * Deep inspection of any prompt text destined for LLM inference, order summaries, or agent tools.
     *
     * @param string $text Raw incoming text
     * @param string $context Calling context (e.g. 'wordpress_comment', 'woocommerce_order_note', 'post_content')
     * @return array
     */
    public static function inspect_prompt(string $text, string $context = 'generic'): array {
        $settings = self::get_settings();
        $findings = [];
        $score    = 0;
        $has_override     = false;
        $has_unicode_tags = false;
        $has_delimiters   = false;
        $has_mcp_call     = false;
        $has_secret_leak  = false;

        // 1. Invisible Unicode Tag Characters & Bidi Control Smuggling
        if (!empty($settings['block_unicode_tags']) && preg_match(self::UNICODE_TAG_REGEX, $text)) {
            $has_unicode_tags = true;
            $score += 75;
            $findings[] = __('Invisible Unicode tag plane (U+E0000–U+E007F), zero-width, or bidi control characters detected (stealth prompt smuggling).', 'wcp-security-scanner');
        }

        // 2. Prompt Override & Jailbreak Patterns Check
        if (!empty($settings['block_prompt_override'])) {
            foreach (self::PROMPT_OVERRIDE_PATTERNS as $name => $pattern) {
                if (preg_match($pattern, $text, $m)) {
                    $has_override = true;
                    $score += 85;
                    $findings[] = sprintf(
                        /* translators: %s: matched pattern */
                        __('Adversarial prompt override directive detected: "%s".', 'wcp-security-scanner'),
                        substr($m[0], 0, 70)
                    );
                    break;
                }
            }
        }

        // 3. LLM Architecture Delimiters (ChatML, Llama, Turn Directives)
        if (!empty($settings['block_llm_delimiters'])) {
            foreach (self::LLM_DELIMITER_PATTERNS as $d_name => $d_pattern) {
                if (preg_match($d_pattern, $text, $dm)) {
                    $has_delimiters = true;
                    $score += 80;
                    $findings[] = sprintf(
                        /* translators: %s: matched delimiter */
                        __('LLM architecture instruction delimiter matched: "%s".', 'wcp-security-scanner'),
                        substr($dm[0], 0, 50)
                    );
                    break;
                }
            }
        }

        // 4. MCP Tool-Call Canary & Function Call Spoofing
        if (!empty($settings['block_mcp_tool_calls'])) {
            foreach (self::MCP_TOOL_CALL_PATTERNS as $t_name => $t_pattern) {
                if (preg_match($t_pattern, $text, $tm)) {
                    $has_mcp_call = true;
                    $score += 90;
                    $findings[] = sprintf(
                        /* translators: %s: tool invocation */
                        __('Unauthorized AI agent MCP tool-call directive detected: "%s".', 'wcp-security-scanner'),
                        substr($tm[0], 0, 60)
                    );
                    break;
                }
            }
        }

        // 5. Secret Leak / Environment Extraction Check
        if (!empty($settings['block_secret_leaks'])) {
            foreach (self::SECRET_LEAK_PATTERNS as $s_name => $s_pattern) {
                if (preg_match($s_pattern, $text, $sm)) {
                    // In public comment/content contexts, require an explicit extraction verb
                    if (in_array($context, ['wordpress_comment', 'post_content'], true)) {
                        $has_extraction_intent = (bool) preg_match('/(?:reveal|leak|print|display|dump|extract|output|cat|show|get)\s+.*(?:wp-config|DB_|AUTH_|KEY|passwd|getenv|printenv)/i', $text);
                        if (!$has_extraction_intent) {
                            continue;
                        }
                    }
                    $has_secret_leak = true;
                    $score += 85;
                    $findings[] = sprintf(
                        /* translators: %s: targeted secret */
                        __('Targeted credential or server environment extraction attempt detected: "%s".', 'wcp-security-scanner'),
                        $sm[0]
                    );
                    break;
                }
            }
        }

        // Clean text: strip invisible unicode tag planes, zero-width chars, and neutralize delimiters
        $cleaned = (string) preg_replace(self::UNICODE_TAG_REGEX, '', $text);

        // Neutralize LLM delimiters into HTML entities so LLM parsers do not evaluate them as tokens
        $cleaned = str_replace(
            ['<|im_start|>', '<|im_end|>', '<|im_sep|>', '<|begin_of_text|>', '<|start_header_id|>', '<|end_header_id|>', '<|eot_id|>', '[INST]', '[/INST]'],
            ['&lt;|im_start|&gt;', '&lt;|im_end|&gt;', '&lt;|im_sep|&gt;', '&lt;|begin_of_text|&gt;', '&lt;|start_header_id|&gt;', '&lt;|end_header_id|&gt;', '&lt;|eot_id|&gt;', '&#91;INST&#93;', '&#91;/INST&#93;'],
            $cleaned
        );

        $is_safe = ($score === 0);

        return [
            'is_safe'          => $is_safe,
            'risk_score'       => min(100, $score),
            'has_override'     => $has_override,
            'has_unicode_tags' => $has_unicode_tags,
            'has_delimiters'   => $has_delimiters,
            'has_mcp_call'     => $has_mcp_call,
            'has_secret_leak'  => $has_secret_leak,
            'findings'         => $findings,
            'cleaned_text'     => $cleaned,
            'context'          => $context,
        ];
    }

    /**
     * Inspect comment submission for prompt injection attacks.
     *
     * @param array $commentdata
     * @return array
     */
    public static function inspect_incoming_comment(array $commentdata): array {
        $text   = $commentdata['comment_content'] ?? '';
        $author = $commentdata['comment_author'] ?? '';
        $probe  = $author . ' ' . $text;

        $analysis = self::inspect_prompt($probe, 'wordpress_comment');

        if (!$analysis['is_safe']) {
            $settings = self::get_settings();
            self::record_catch('wordpress_comment', $analysis['findings'], $analysis['risk_score'], $settings['action']);

            if ($settings['action'] === 'block') {
                wp_die(
                    '<h1>' . esc_html__('Submission Rejected', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('WCP Prompt Injection Guard: Your comment contains disallowed adversarial directives or instruction tokens.', 'wcp-security-scanner') . '</p>',
                    esc_html__('Prompt Injection Blocked', 'wcp-security-scanner'),
                    ['response' => 403, 'back_link' => true]
                );
            } elseif ($settings['action'] === 'sanitize') {
                $commentdata['comment_content'] = $analysis['cleaned_text'];
            } elseif ($settings['action'] === 'moderate') {
                $commentdata['comment_approved'] = 0;
            }
        }

        return $commentdata;
    }

    /**
     * Inspect WooCommerce checkout customer note.
     *
     * @param \WC_Order $order
     * @param array     $data
     * @return void
     */
    public static function inspect_woocommerce_order($order, array $data): void {
        if (!$order instanceof \WC_Order) {
            return;
        }

        $customer_note = $order->get_customer_note();
        if (empty($customer_note)) {
            return;
        }

        $analysis = self::inspect_prompt($customer_note, 'woocommerce_order_note');

        if (!$analysis['is_safe']) {
            $settings = self::get_settings();
            self::record_catch('woocommerce_order_note', $analysis['findings'], $analysis['risk_score'], $settings['action']);

            if ($settings['action'] === 'block') {
                throw new \Exception(
                    esc_html__('Your order note contains invalid characters or disallowed AI directives. Please remove it to proceed with checkout.', 'wcp-security-scanner')
                );
            } else {
                // Sanitize customer note to prevent LLM indirect prompt injection
                $order->set_customer_note($analysis['cleaned_text']);
                // Add private administrative note to the order for store owner visibility
                $order->add_order_note(
                    sprintf(
                        /* translators: %s: threat findings */
                        __('WCP Security Sentinel: Sanitized potential indirect AI prompt injection from customer order note: %s. Delimiters and invisible Unicode tags neutralized.', 'wcp-security-scanner'),
                        implode(', ', $analysis['findings'])
                    ),
                    false
                );
            }
        }
    }

    /**
     * Filter WooCommerce new order data array before order creation.
     *
     * @param array $data
     * @return array
     */
    public static function filter_woocommerce_order_data(array $data): array {
        if (!empty($data['customer_note'])) {
            $analysis = self::inspect_prompt($data['customer_note'], 'woocommerce_order_note');
            if (!$analysis['is_safe']) {
                $settings = self::get_settings();
                if ($settings['action'] === 'sanitize') {
                    $data['customer_note'] = $analysis['cleaned_text'];
                }
            }
        }
        return $data;
    }

    /**
     * Inspect post/page content submissions before database persistence.
     *
     * @param array $data Cleaned post data
     * @param array $postarr Raw post array
     * @return array
     */
    public static function inspect_incoming_post_data(array $data, array $postarr): array {
        // Skip administrative users with manage_options to allow legitimate technical writing
        if (current_user_can('manage_options')) {
            return $data;
        }

        $content = $data['post_content'] ?? '';
        $title   = $data['post_title'] ?? '';
        $probe   = $title . ' ' . $content;

        if (empty($probe) || strlen($probe) < 10) {
            return $data;
        }

        $analysis = self::inspect_prompt($probe, 'post_content');

        if (!$analysis['is_safe']) {
            $settings = self::get_settings();
            self::record_catch('post_content', $analysis['findings'], $analysis['risk_score'], $settings['action']);

            if ($settings['action'] === 'block') {
                wp_die(
                    '<h1>' . esc_html__('Content Rejected', 'wcp-security-scanner') . '</h1>' .
                    '<p>' . esc_html__('WCP Prompt Injection Guard: Inbound content contains adversarial prompt injection directives.', 'wcp-security-scanner') . '</p>',
                    esc_html__('Content Blocked', 'wcp-security-scanner'),
                    ['response' => 403, 'back_link' => true]
                );
            } elseif ($settings['action'] === 'sanitize') {
                $data['post_content'] = $analysis['cleaned_text'];
            } elseif ($settings['action'] === 'moderate') {
                // Force post into pending review status
                $data['post_status'] = 'pending';
            }
        }

        return $data;
    }

    /**
     * Inspect user bio/description on profile updates.
     *
     * @param string $description
     * @return string
     */
    public static function inspect_user_description(string $description): string {
        if (empty($description)) {
            return $description;
        }

        $analysis = self::inspect_prompt($description, 'user_description');

        if (!$analysis['is_safe']) {
            $settings = self::get_settings();
            self::record_catch('user_description', $analysis['findings'], $analysis['risk_score'], $settings['action']);

            if ($settings['action'] === 'block' && !current_user_can('manage_options')) {
                wp_die(
                    esc_html__('Profile description rejected: Contains disallowed adversarial prompt tokens.', 'wcp-security-scanner'),
                    esc_html__('Profile Update Blocked', 'wcp-security-scanner'),
                    ['response' => 403, 'back_link' => true]
                );
            }

            return $analysis['cleaned_text'];
        }

        return $description;
    }

    /**
     * Record prompt injection interception event in audit history and notify.
     *
     * @param string $source
     * @param array  $findings
     * @param int    $score
     * @param string $action
     * @return void
     */
    private static function record_catch(string $source, array $findings, int $score, string $action): void {
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

        if (class_exists(WafFileLogger::class)) {
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

        if (class_exists(WcpActivityLogger::class)) {
            WcpActivityLogger::log(
                'ai_prompt_injection_intercepted',
                'firewall',
                'warning',
                [
                    'source'   => $source,
                    'ip'       => $ip,
                    'score'    => $score,
                    'action'   => $action,
                    'findings' => $findings,
                    'description' => sprintf(
                        'AI Prompt Injection intercepted in %s from IP %s. Action enforced: %s.',
                        $source,
                        $ip,
                        strtoupper($action)
                    ),
                ]
            );
        }

        if (class_exists(NotificationDispatcher::class)) {
            NotificationDispatcher::trigger('ai_defense_prompt_injection', [
                'severity' => 'critical',
                'source'   => $source,
                'ip'       => $ip,
                'findings' => implode(' | ', $findings),
                'score'    => $score . '/100',
                'action'   => strtoupper($action),
                'timestamp'=> current_time('mysql'),
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
