<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class AIService {
    /**
     * Test connection to selected AI Provider
     */
    public static function test_connection(string $provider, string $api_key, string $model): array {
        if ($provider === 'wp_ai_connect') {
            try {
                $status = self::get_ai_connect_status();
                if (!$status['is_available']) {
                    return [
                        'success' => false,
                        'error'   => __('No active WordPress Native AI Connect client or plugin detected. You can install a compatible AI plugin like AI Engine or configure an API key below.', 'wcp-security-scanner'),
                        'provider'=> 'wp_ai_connect',
                    ];
                }

                $prompt = 'Ping test. Reply with OK.';
                // Ultra-fast 6-second ping test for immediate feedback
                $response = self::call_native_ai_connect('You are an AI diagnostic tester.', $prompt, 0.1, 16, 6);
                return [
                    'success' => true,
                    'message' => sprintf(
                        /* translators: %s: AI engine name */
                        __('WordPress Native AI Connect verified successfully (%s)!', 'wcp-security-scanner'),
                        $status['engine_name']
                    ),
                    'provider'=> 'wp_ai_connect',
                    'model'   => $status['engine_slug'],
                    'preview' => trim(substr($response, 0, 100)),
                ];
            } catch (\Throwable $e) {
                $status = self::get_ai_connect_status();
                if ($status['is_available']) {
                    return [
                        'success' => true,
                        'message' => sprintf(
                            /* translators: %s: AI engine name */
                            __('WordPress AI subsystem detected (%s) and ready for threat forensics.', 'wcp-security-scanner'),
                            $status['engine_name']
                        ),
                        'provider'=> 'wp_ai_connect',
                        'model'   => $status['engine_slug'],
                        'preview' => $status['details'],
                    ];
                }
                return [
                    'success' => false,
                    'error'   => $e->getMessage(),
                    'provider'=> 'wp_ai_connect',
                ];
            }
        }

        if (empty($api_key)) {
            $status = self::get_ai_connect_status();
            if ($status['is_available']) {
                return self::test_connection('wp_ai_connect', '', $model);
            }
            return ['success' => false, 'error' => __('API key is required.', 'wcp-security-scanner')];
        }

        $prompt = 'Ping test. Reply with OK.';

        try {
            // Ultra-fast 6-second ping test for immediate feedback
            $response = self::call_provider($provider, $api_key, $model, 'You are an AI diagnostic tester.', $prompt, 0.1, 16, 6);
            return [
                'success' => true,
                'message' => __('AI connection established successfully!', 'wcp-security-scanner'),
                'provider'=> $provider,
                'model'   => $model,
                'preview' => trim(substr($response, 0, 100)),
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error'   => $e->getMessage(),
                'provider'=> $provider,
            ];
        }
    }

    /**
     * Analyze suspicious code or file snippet using AI
     */
    public static function analyze_code(array $data): array {
        $settings = SettingsManager::get_settings();
        $provider = $data['provider'] ?? ($settings['ai_provider'] ?? 'openai');

        $api_key = '';
        $model = '';
        if ($provider === 'gemini') {
            $api_key = !empty($data['api_key']) ? $data['api_key'] : ($settings['gemini_api_key'] ?? '');
            $model = !empty($data['model']) ? $data['model'] : ($settings['gemini_model'] ?? 'gemini-3.8-flash');
        } elseif ($provider === 'claude') {
            $api_key = !empty($data['api_key']) ? $data['api_key'] : ($settings['claude_api_key'] ?? '');
            $model = !empty($data['model']) ? $data['model'] : ($settings['claude_model'] ?? 'claude-sonnet-5-5');
        } elseif ($provider === 'wp_ai_connect') {
            $api_key = '';
            $model = 'wp-native-ai';
        } else {
            $provider = 'openai';
            $api_key = !empty($data['api_key']) ? $data['api_key'] : ($settings['openai_api_key'] ?? '');
            $model = !empty($data['model']) ? $data['model'] : ($settings['openai_model'] ?? 'gpt-6.1-sol');
        }

        $ai_status = self::get_ai_connect_status();

        if (empty($api_key) && $provider !== 'wp_ai_connect') {
            if ($ai_status['is_available']) {
                $provider = 'wp_ai_connect';
                $model = $ai_status['engine_slug'];
            } else {
                // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
                throw new \Exception(esc_html__('AI Provider API key is missing. Please configure it in Security Scanner Settings or connect WordPress Native AI Connect.', 'wcp-security-scanner'));
            }
        }

        $code = $data['code'] ?? '';
        $file_path = $data['file_path'] ?? 'unknown_file.php';
        $threat_type = $data['threat_type'] ?? 'Suspicious Code / Malicious Function';
        $flagged_line = $data['line_number'] ?? null;

        if (empty($code)) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception(esc_html__('No code snippet provided for AI forensic analysis.', 'wcp-security-scanner'));
        }

        // Limit code sent to avoid excessive token costs
        if (strlen($code) > 8000) {
            $code = substr($code, 0, 8000) . "\n...[truncated for token limit]...";
        }

        $system_prompt = "You are an elite WordPress Cybersecurity Forensic Specialist. Your audience includes non-technical website owners who need crystal-clear, plain-English explanations without confusing jargon, as well as developers who need exact forensic details. Always be concise, direct, and reassuring when code is benign, and clear about risks when code is suspicious or malicious.";

        $user_prompt = "Analyze the following WordPress code snippet for security threats:\n\n" .
            "File Context: {$file_path}\n" .
            "Detected Vector: {$threat_type}\n" .
            ($flagged_line ? "Flagged Line: {$flagged_line}\n" : "") .
            "Code:\n```php\n{$code}\n```\n\n" .
            "Format your forensic report clearly into the following structured sections:\n\n" .
            "### 1. Executive Summary for Non-Technical Site Owners\n" .
            "In 2-3 plain-English sentences, explain exactly what was found, whether the site is in immediate danger, and whether the site owner needs to panic or take action.\n\n" .
            "### 2. Threat Assessment & Risk Severity\n" .
            "- **Threat Verdict**: **Malicious** | **Suspicious** | **Safe / False Positive** | **Legitimate**\n" .
            "- **Risk Severity**: **Critical** | **High** | **Medium** | **Low** | **Clean**\n" .
            "- **Reasoning**: Plain explanation of why this verdict was reached.\n\n" .
            "### 3. What the Code Does (Line-by-Line Breakdown)\n" .
            "Explain what the code does step-by-step in simple language. Specifically wrap any detected code snippets, functions, or injected strings (e.g. `#nice`, `eval()`, `functions.php`) and line numbers (e.g. `line 11`, `lines 1-10`) in backticks so they can be highlighted in red.\n\n" .
            "### 4. De-obfuscation & Decoded Payload\n" .
            "If the code uses base64, rot13, eval, gzip, hex, or chr obfuscation, show the completely decoded plain-text payload. If not obfuscated, state 'None - Plain PHP code'.\n\n" .
            "### 5. Actionable Remediation Steps\n" .
            "Provide numbered, foolproof steps for the site owner to safely fix, clean, or whitelist this file.";

        $temperature = floatval($settings['ai_temperature'] ?? 0.2);
        $max_tokens = 1200; // Efficient token usage for code forensics

        if ($provider === 'wp_ai_connect') {
            $analysis = self::call_native_ai_connect($system_prompt, $user_prompt, $temperature, $max_tokens);
            return [
                'success'   => true,
                'provider'  => 'wp_ai_connect',
                'model'     => $ai_status['engine_name'],
                'analysis'  => $analysis,
                'timestamp' => current_time('mysql'),
            ];
        }

        $analysis = self::call_provider($provider, $api_key, $model, $system_prompt, $user_prompt, $temperature, $max_tokens);

        return [
            'success'   => true,
            'provider'  => $provider,
            'model'     => $model,
            'analysis'  => $analysis,
            'timestamp' => current_time('mysql'),
        ];
    }

    /**
     * Get detailed detection status of WordPress Native AI Connect or compatible AI plugins.
     */
    public static function get_ai_connect_status(): array {
        $recommended_plugin = [
            'name'        => 'AI Engine: Chatbots, Generators, Assistants & AI Connect',
            'slug'        => 'ai-engine',
            'author'      => 'Jordy Meow',
            'install_url' => admin_url('plugin-install.php?s=ai-engine&tab=search&type=term'),
            'description' => __('The leading WordPress AI connector with 80,000+ active installs. Connects your WordPress site to OpenAI, Gemini, Claude, and local LLMs natively with unified APIs.', 'wcp-security-scanner'),
        ];

        $connectors_url = admin_url('options-connectors.php');
        $has_connectors_api = function_exists('wp_get_connectors') || function_exists('wp_ai_client_prompt') || class_exists('\\WordPress\\AI\\Main') || function_exists('\\WordPress\\AI\\get_ai_service');

        // Check active connectors configured in WordPress options-connectors.php
        $active_connectors = [];
        if (function_exists('wp_get_connectors')) {
            foreach (wp_get_connectors() as $cid => $cdata) {
                $isActive = is_callable($cdata['plugin']['is_active'] ?? null) ? $cdata['plugin']['is_active']() : false;
                $hasKey = !empty(get_option("connectors_ai_{$cid}_api_key"));
                if ($isActive || $hasKey) {
                    $active_connectors[] = $cdata['name'] ?? ucfirst($cid);
                }
            }
        }
        if (empty($active_connectors) && function_exists('\\WordPress\\AI\\get_ai_connectors')) {
            $conns = \WordPress\AI\get_ai_connectors(false);
            foreach ($conns as $cid => $cdata) {
                $hasKey = !empty(get_option("connectors_ai_{$cid}_api_key"));
                if ($hasKey) {
                    $active_connectors[] = $cdata['name'] ?? ucfirst($cid);
                }
            }
        }
        if (empty($active_connectors)) {
            if (!empty(get_option('connectors_ai_google_api_key'))) $active_connectors[] = 'Google Gemini';
            if (!empty(get_option('connectors_ai_openai_api_key'))) $active_connectors[] = 'OpenAI ChatGPT';
            if (!empty(get_option('connectors_ai_anthropic_api_key'))) $active_connectors[] = 'Anthropic Claude';
        }

        // 1. Check WordPress Native Connectors API (options-connectors.php)
        if ($has_connectors_api && !empty($active_connectors)) {
            return [
                'is_available'        => true,
                'engine_name'         => 'WordPress Native AI Connectors (' . implode(', ', $active_connectors) . ')',
                'engine_slug'         => 'wp_connectors',
                'detected_via'        => 'WordPress Core Connectors API (options-connectors.php)',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => true,
                'active_connectors'   => $active_connectors,
                'details'             => sprintf(
                    /* translators: %s: Comma-separated list of active connectors */
                    __('WordPress Native AI Connect is active with %s configured! You can manage or add connectors anytime at Settings → Connectors (options-connectors.php). WCP Security Scanner is 100%% compatible and seamlessly executes code de-obfuscation and threat forensics directly through your WordPress AI infrastructure.', 'wcp-security-scanner'),
                    implode(', ', $active_connectors)
                ),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 2. Check WordPress Core AI Client (WP 7.0+)
        if (function_exists('wp_ai_client') || class_exists('\\WP_AI_Client') || class_exists('\\WordPress\\AI\\Client')) {
            return [
                'is_available'        => true,
                'engine_name'         => 'WordPress Core AI Client',
                'engine_slug'         => 'wp_core_ai',
                'detected_via'        => 'wp_ai_client() core function',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => __('WordPress native Core AI Client is active and connected. WCP Security Scanner can seamlessly run zero-key forensics through your WordPress AI infrastructure.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 3. Check WordPress Abilities API
        if (function_exists('wp_ai_run_ability') || function_exists('wp_register_ai_ability')) {
            return [
                'is_available'        => true,
                'engine_name'         => 'WordPress AI Abilities System',
                'engine_slug'         => 'wp_abilities',
                'detected_via'        => 'wp_ai_run_ability() Core Abilities API',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => __('WordPress AI Abilities runtime detected. WCP Security Scanner can dispatch suspicious file forensics directly through registered site abilities.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 4. Check AI Engine (Meow Apps)
        if (class_exists('\\Meow_MWAI_Core') || function_exists('mwai_ai_query') || class_exists('\\Meow_MWAI_Query_Text')) {
            return [
                'is_available'        => true,
                'engine_name'         => 'AI Engine (by Meow Apps)',
                'engine_slug'         => 'ai_engine',
                'detected_via'        => 'Meow_MWAI_Core plugin runtime',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => __('AI Engine plugin is active on your site. WCP Security Scanner is 100% compatible and will route malware de-obfuscation and code analysis through your AI Engine models.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 5. Check WP AI Connect / AI Connect plugins
        if (class_exists('WP_AI_Connect') || defined('WP_AI_CONNECT_VERSION') || function_exists('wp_ai_connect')) {
            return [
                'is_available'        => true,
                'engine_name'         => 'WP AI Connect Plugin',
                'engine_slug'         => 'wp_ai_connect',
                'detected_via'        => 'WP_AI_Connect plugin class',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => __('WP AI Connect plugin detected on your site. WCP Security Scanner is fully compatible and will route threat forensics through your connected models.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 6. Check Jetpack AI
        if (class_exists('Automattic\\Jetpack\\AI\\Client') || class_exists('Jetpack_AI') || function_exists('jetpack_ai_post')) {
            return [
                'is_available'        => true,
                'engine_name'         => 'Jetpack AI Subsystem',
                'engine_slug'         => 'jetpack_ai',
                'detected_via'        => 'Jetpack AI Client',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => __('Jetpack AI subsystem detected. WCP Security Scanner is compatible with your Jetpack AI connected services.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 7. Check Active Filters or Extensible Hooks
        if (has_filter('wcpscan_ai_analyze_code') || has_filter('wp_ai_prompt')) {
            return [
                'is_available'        => true,
                'engine_name'         => 'Custom WordPress AI Hook Bridge',
                'engine_slug'         => 'wp_custom_hook',
                'detected_via'        => 'Active wcpscan_ai_analyze_code / wp_ai_prompt filter hook',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => __('A custom WordPress AI connector filter is registered on this site. WCP Security Scanner will dispatch code forensics directly through your custom AI pipeline.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 8. Check wp-config / Environment Defined AI Keys
        $env_keys = [];
        if (defined('OPENAI_API_KEY') && constant('OPENAI_API_KEY')) $env_keys[] = 'OpenAI';
        if (defined('GEMINI_API_KEY') && constant('GEMINI_API_KEY')) $env_keys[] = 'Gemini';
        if (defined('ANTHROPIC_API_KEY') && constant('ANTHROPIC_API_KEY')) $env_keys[] = 'Anthropic Claude';
        if (!empty($env_keys)) {
            return [
                'is_available'        => true,
                'engine_name'         => 'WordPress Environment AI Credentials',
                'engine_slug'         => 'env_credentials',
                'detected_via'        => implode(', ', $env_keys) . ' constant(s) in wp-config.php',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => $has_connectors_api,
                'details'             => sprintf(
                    /* translators: %s: Comma-separated list of environment constants */
                    __('Pre-configured AI keys (%s) detected in your WordPress environment constants. WCP Security Scanner can seamlessly leverage these credentials without extra setup.', 'wcp-security-scanner'),
                    implode(', ', $env_keys)
                ),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // 9. Check if options-connectors.php exists but has no keys yet
        if ($has_connectors_api) {
            return [
                'is_available'        => false,
                'engine_name'         => 'WordPress Native AI Connectors',
                'engine_slug'         => 'wp_connectors_empty',
                'detected_via'        => 'WordPress Core Connectors API (options-connectors.php)',
                'connectors_url'      => $connectors_url,
                'has_connectors_page' => true,
                'details'             => __('WordPress Native AI Connectors (options-connectors.php) is available on your site, but no AI credentials are saved yet. You can configure Google Gemini, OpenAI, or Claude in WordPress.', 'wcp-security-scanner'),
                'recommended_plugin'  => $recommended_plugin,
            ];
        }

        // None detected: Provide recommendation
        return [
            'is_available'        => false,
            'engine_name'         => 'None Detected',
            'engine_slug'         => 'none',
            'detected_via'        => 'none',
            'connectors_url'      => $connectors_url,
            'has_connectors_page' => false,
            'details'             => __('No WordPress Native AI Connect or AI connector plugin is currently active on this WordPress site.', 'wcp-security-scanner'),
            'recommended_plugin'  => $recommended_plugin,
        ];
    }

    /**
     * Check if WordPress Core AI Client (introduced in WordPress 7.0+) is available.
     */
    public static function has_core_ai_client(): bool {
        $status = self::get_ai_connect_status();
        return $status['is_available'];
    }

    /**
     * Universal Native AI Connect bridge for WordPress.
     * Compatible with WordPress Core AI Client (wp_ai_client_prompt), options-connectors.php credentials,
     * AI Engine (Meow Apps), WP AI Connect, custom AI filter hooks, and environment credentials.
     */
    public static function call_native_ai_connect(string $system, string $user, float $temp = 0.2, int $max_tokens = 1200, int $timeout = 45): string {
        // 1. Allow third-party plugins to intercept directly via filter
        $filtered = apply_filters('wcpscan_ai_analyze_code', null, [
            'system'      => $system,
            'prompt'      => $user,
            'temperature' => $temp,
            'max_tokens'  => $max_tokens,
            'timeout'     => $timeout,
        ]);
        if (!empty($filtered) && is_string($filtered)) {
            return $filtered;
        }

        // 2. Direct connector credentials configured in WordPress options-connectors.php
        // These provide instant, reliable execution using the credentials stored by WordPress Connectors admin screen.
        // We prioritize high-speed flash models to avoid alpha core AI client rate-limiting or slow retry loops.
        $google_conn_key = get_option('connectors_ai_google_api_key');
        if (!empty($google_conn_key) && is_string($google_conn_key)) {
            try {
                return self::call_gemini($google_conn_key, 'gemini-3.5-flash-lite', $system, $user, $temp, $max_tokens, $timeout);
            } catch (\Throwable $e) {
                try {
                    return self::call_gemini($google_conn_key, 'gemini-3.8-flash', $system, $user, $temp, $max_tokens, $timeout);
                } catch (\Throwable $e2) {
                    // Continue down fallback chain
                }
            }
        }
        $openai_conn_key = get_option('connectors_ai_openai_api_key');
        if (!empty($openai_conn_key) && is_string($openai_conn_key)) {
            try {
                return self::call_openai($openai_conn_key, 'gpt-6.1-sol', $system, $user, $temp, $max_tokens, $timeout);
            } catch (\Throwable $e) {
                // Continue down fallback chain
            }
        }
        $anthropic_conn_key = get_option('connectors_ai_anthropic_api_key');
        if (!empty($anthropic_conn_key) && is_string($anthropic_conn_key)) {
            try {
                return self::call_claude($anthropic_conn_key, 'claude-sonnet-5-5', $system, $user, $temp, $max_tokens, $timeout);
            } catch (\Throwable $e) {
                // Continue down fallback chain
            }
        }

        // 3. Check WordPress Core AI Client Prompt Builder (wp_ai_client_prompt() in WP 7.0+)
        if (function_exists('wp_ai_client_prompt')) {
            try {
                $full_prompt = "{$system}\n\n{$user}";
                $prompt_builder = wp_ai_client_prompt($full_prompt);
                if ($prompt_builder && method_exists($prompt_builder, 'generate_text')) {
                    $result = $prompt_builder->generate_text();
                    if (!is_wp_error($result) && !empty($result) && is_string($result)) {
                        return $result;
                    }
                }
            } catch (\Throwable $e) {
                // Continue down fallback chain
            }
        }

        // 4. Check WordPress Core AI Client (wp_ai_client())
        if (function_exists('wp_ai_client')) {
            try {
                $client = wp_ai_client();
                if ($client) {
                    if (method_exists($client, 'prompt')) {
                        $result = $client->prompt($user, [
                            'system_instruction' => $system,
                            'temperature'        => $temp,
                            'max_tokens'         => $max_tokens,
                        ]);
                        if (!empty($result)) {
                            return is_string($result) ? $result : ($result['text'] ?? $result['content'] ?? '');
                        }
                    } elseif (method_exists($client, 'complete')) {
                        $result = $client->complete($user, [
                            'system'      => $system,
                            'temperature' => $temp,
                            'max_tokens'  => $max_tokens,
                        ]);
                        if (!empty($result)) {
                            return is_string($result) ? $result : ($result['text'] ?? $result['content'] ?? '');
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Continue down fallback chain
            }
        }

        // 3. Check WordPress Abilities API (wp_ai_run_ability())
        if (function_exists('wp_ai_run_ability')) {
            try {
                $result = wp_ai_run_ability('generate-text', [
                    'prompt' => $user,
                    'system' => $system,
                ]);
                if (!empty($result) && is_string($result)) {
                    return $result;
                }
            } catch (\Throwable $e) {
                // Continue down fallback chain
            }
        }

        // 4. Check AI Engine (by Meow Apps)
        if (class_exists('\\Meow_MWAI_Core')) {
            try {
                if (class_exists('\\Meow_MWAI_Query_Text')) {
                    $query = new \Meow_MWAI_Query_Text($user);
                    if (method_exists($query, 'set_instructions')) {
                        $query->set_instructions($system);
                    } elseif (property_exists($query, 'instructions')) {
                        $query->instructions = $system;
                    }
                    if (property_exists($query, 'maxTokens')) {
                        $query->maxTokens = $max_tokens;
                    }
                    if (property_exists($query, 'temperature')) {
                        $query->temperature = $temp;
                    }
                    $mwai = \Meow_MWAI_Core::instance();
                    if ($mwai && method_exists($mwai, 'run_query')) {
                        $reply = $mwai->run_query($query);
                        if (!empty($reply) && isset($reply->result)) {
                            return (string) $reply->result;
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Continue down fallback chain
            }
        }

        // 5. Generic WordPress AI prompt filter (used by various plugins)
        $prompt_filtered = apply_filters('wp_ai_prompt', null, $user, $system);
        if (!empty($prompt_filtered) && is_string($prompt_filtered)) {
            return $prompt_filtered;
        }

        // 6. Inherit keys from AI Engine options if stored in DB
        $mwai_options = get_option('mwai_options', []);
        if (is_array($mwai_options)) {
            $mwai_openai = $mwai_options['openai_apiKey'] ?? ($mwai_options['openaiApiKey'] ?? '');
            if (!empty($mwai_openai)) {
                return self::call_openai($mwai_openai, 'gpt-6.1-sol', $system, $user, $temp, $max_tokens);
            }
            $mwai_anthropic = $mwai_options['anthropic_apiKey'] ?? ($mwai_options['anthropicApiKey'] ?? '');
            if (!empty($mwai_anthropic)) {
                return self::call_claude($mwai_anthropic, 'claude-sonnet-5-5', $system, $user, $temp, $max_tokens);
            }
        }

        // 7. Inherit keys from wp-config / environment constants
        if (defined('OPENAI_API_KEY') && constant('OPENAI_API_KEY')) {
            return self::call_openai(constant('OPENAI_API_KEY'), 'gpt-6.1-sol', $system, $user, $temp, $max_tokens);
        }
        if (defined('GEMINI_API_KEY') && constant('GEMINI_API_KEY')) {
            return self::call_gemini(constant('GEMINI_API_KEY'), 'gemini-3.8-flash', $system, $user, $temp, $max_tokens);
        }
        if (defined('ANTHROPIC_API_KEY') && constant('ANTHROPIC_API_KEY')) {
            return self::call_claude(constant('ANTHROPIC_API_KEY'), 'claude-sonnet-5-5', $system, $user, $temp, $max_tokens);
        }

        throw new \Exception(esc_html__('WordPress Native AI Connect is not yet configured or did not return a response. Please ensure your WordPress AI connector plugin is active and has credentials configured.', 'wcp-security-scanner'));
    }

    /**
     * Dispatch API call to selected AI provider (with Native AI Connect compatibility)
     */
    private static function call_provider(string $provider, string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200, int $timeout = 45): string {
        if ($provider === 'wp_ai_connect') {
            return self::call_native_ai_connect($system, $user, $temp, $max_tokens, $timeout);
        }

        // If site runs WordPress Native AI Connect or Core AI Client and no custom key is provided, prefer Native AI Connect
        if (empty($api_key)) {
            $status = self::get_ai_connect_status();
            if ($status['is_available']) {
                return self::call_native_ai_connect($system, $user, $temp, $max_tokens, $timeout);
            }
        }

        if ($provider === 'gemini') {
            return self::call_gemini($api_key, $model, $system, $user, $temp, $max_tokens, $timeout);
        } elseif ($provider === 'claude') {
            return self::call_claude($api_key, $model, $system, $user, $temp, $max_tokens, $timeout);
        } else {
            return self::call_openai($api_key, $model, $system, $user, $temp, $max_tokens, $timeout);
        }
    }

    /**
     * OpenAI API Implementation (GPT-6 series, GPT-6.1 Sol, GPT-6 Astra, etc.)
     */
    private static function call_openai(string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200, int $timeout = 45): string {
        $url = 'https://api.openai.com/v1/chat/completions';

        $body = [
            'model'       => $model ?: 'gpt-6.1-sol',
            'temperature' => $temp,
            'max_tokens'  => $max_tokens,
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user', 'content' => $user],
            ],
        ];

        @set_time_limit(max(60, $timeout + 30));

        $response = wp_remote_post($url, [
            'timeout' => $timeout,
            'headers' => [
                'Authorization' => 'Bearer ' . $api_key,
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode($body),
        ]);

        if (is_wp_error($response)) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception('OpenAI Request Failed: ' . esc_html($response->get_error_message()));
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw = wp_remote_retrieve_body($response);
        $data = json_decode($raw, true);

        if ($code !== 200) {
            $err = $data['error']['message'] ?? "HTTP error {$code}";
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception('OpenAI Error: ' . esc_html($err));
        }

        return $data['choices'][0]['message']['content'] ?? '';
    }

    /**
     * Google Gemini API Implementation (Gemini 3.5 Flash Lite, Gemini 3.8 Flash, etc.)
     */
    private static function call_gemini(string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200, int $timeout = 45): string {
        $model_name = $model ?: 'gemini-3.5-flash-lite';
        $url = "https://generativelanguage.googleapis.com/v1beta/models/{$model_name}:generateContent";

        $body = [
            'system_instruction' => [
                'parts' => [['text' => $system]],
            ],
            'contents' => [
                [
                    'role'  => 'user',
                    'parts' => [['text' => $user]],
                ]
            ],
            'generationConfig' => [
                'temperature'     => $temp,
                'maxOutputTokens' => $max_tokens,
            ]
        ];

        @set_time_limit(max(60, $timeout + 30));

        $response = wp_remote_post($url, [
            'timeout' => $timeout,
            'headers' => [
                'Content-Type'   => 'application/json',
                'x-goog-api-key' => $api_key,
            ],
            'body'    => wp_json_encode($body),
        ]);

        if (is_wp_error($response)) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception('Gemini Request Failed: ' . esc_html($response->get_error_message()));
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw = wp_remote_retrieve_body($response);
        $data = json_decode($raw, true);

        if ($code !== 200) {
            $err = $data['error']['message'] ?? "HTTP error {$code}";

            // Automatic resilient fallback: if the primary model is busy/overloaded or deprecating, try gemini-3.5-flash-lite
            if ($model_name !== 'gemini-3.5-flash-lite' && (stripos($err, 'high demand') !== false || stripos($err, 'overloaded') !== false || stripos($err, 'Resource has been exhausted') !== false || stripos($err, 'no longer available') !== false)) {
                return self::call_gemini($api_key, 'gemini-3.5-flash-lite', $system, $user, $temp, $max_tokens, $timeout);
            }

            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception('Google Gemini Error: ' . esc_html($err));
        }

        return $data['candidates'][0]['content']['parts'][0]['text'] ?? '';
    }

    /**
     * Anthropic Claude API Implementation (Claude Sonnet 5.5, Claude Opus 5.5, Claude Haiku 5.5, etc.)
     */
    private static function call_claude(string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200, int $timeout = 45): string {
        $url = 'https://api.anthropic.com/v1/messages';

        $body = [
            'model'      => $model ?: 'claude-sonnet-5-5',
            'max_tokens' => min(2048, $max_tokens),
            'temperature'=> $temp,
            'system'     => $system,
            'messages'   => [
                ['role' => 'user', 'content' => $user],
            ],
        ];

        @set_time_limit(max(60, $timeout + 30));

        $response = wp_remote_post($url, [
            'timeout' => $timeout,
            'headers' => [
                'x-api-key'         => $api_key,
                'anthropic-version' => '2023-06-01',
                'Content-Type'      => 'application/json',
            ],
            'body'    => wp_json_encode($body),
        ]);

        if (is_wp_error($response)) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception('Claude Request Failed: ' . esc_html($response->get_error_message()));
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw = wp_remote_retrieve_body($response);
        $data = json_decode($raw, true);

        if ($code !== 200) {
            $err = $data['error']['message'] ?? "HTTP error {$code}";
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \Exception('Anthropic Claude Error: ' . esc_html($err));
        }

        return $data['content'][0]['text'] ?? '';
    }

    /**
     * Get available model registry for all providers
     */
    public static function get_available_models(): array {
        $transient_key = 'wcpscan_ai_models_catalog';
        $cached = get_transient($transient_key);
        if ($cached && is_array($cached)) {
            return $cached;
        }

        return self::get_default_models_catalog();
    }

    /**
     * Built-in fallback catalog of tested, high-performance models
     */
    public static function get_default_models_catalog(): array {
        return [
            'gemini' => [
                'current_default' => 'gemini-3.5-flash-lite',
                'models' => [
                    [
                        'id'          => 'gemini-3.5-flash-lite',
                        'name'        => 'Gemini 3.5 Flash-Lite',
                        'badge'       => '3.5 Lite (Low Token)',
                        'description' => 'Fast, Ultra-Low Token & Resilient Code Forensic Engine',
                        'is_default'  => true,
                    ],
                    [
                        'id'          => 'gemini-3.1-flash-lite',
                        'name'        => 'Gemini 3.1 Flash-Lite',
                        'badge'       => '3.1 Lite',
                        'description' => 'High-Speed Efficient Forensic Agent',
                        'is_default'  => false,
                    ],
                    [
                        'id'          => 'gemini-3.8-flash',
                        'name'        => 'Gemini 3.8 Flash',
                        'badge'       => '3.8 Flash',
                        'description' => 'High-Intelligence Full Flagship Agent',
                        'is_default'  => false,
                    ],
                ],
            ],
            'openai' => [
                'current_default' => 'gpt-6.1-sol',
                'models' => [
                    [
                        'id'          => 'gpt-6.1-sol',
                        'name'        => 'GPT-6.1 Sol',
                        'badge'       => 'GPT-6.1 Sol',
                        'description' => 'Latest Balanced Default - Optimal Code Forensics & Speed',
                        'is_default'  => true,
                    ],
                    [
                        'id'          => 'gpt-6-astra',
                        'name'        => 'GPT-6 Astra',
                        'badge'       => 'GPT-6 Astra',
                        'description' => 'Flagship Frontier Model - Deep De-obfuscation & Autonomous Reasoning',
                        'is_default'  => false,
                    ],
                    [
                        'id'          => 'gpt-6-luna',
                        'name'        => 'GPT-6 Luna',
                        'badge'       => 'GPT-6 Luna',
                        'description' => 'Ultra-Fast Lightweight Model for High Volume Checks',
                        'is_default'  => false,
                    ],
                ],
            ],
            'claude' => [
                'current_default' => 'claude-sonnet-5-5',
                'models' => [
                    [
                        'id'          => 'claude-sonnet-5-5',
                        'name'        => 'Claude Sonnet 5.5',
                        'badge'       => 'Sonnet 5.5',
                        'description' => 'Latest Default - Superior Code Analysis & Security Insights',
                        'is_default'  => true,
                    ],
                    [
                        'id'          => 'claude-opus-5-5',
                        'name'        => 'Claude Opus 5.5',
                        'badge'       => 'Opus 5.5',
                        'description' => 'Flagship Powerhouse for Complex Cryptographic Audits',
                        'is_default'  => false,
                    ],
                    [
                        'id'          => 'claude-haiku-5-5',
                        'name'        => 'Claude Haiku 5.5',
                        'badge'       => 'Haiku 5.5',
                        'description' => 'Ultra-Low Latency Response for Quick File Checks',
                        'is_default'  => false,
                    ],
                ],
            ],
        ];
    }

    /**
     * Query provider APIs / registry for new agent versions and update catalog
     * Optionally automatically upgrades active settings to the newly detected flagship default
     */
    public static function check_and_update_models(bool $auto_upgrade_active_settings = true): array {
        $settings = SettingsManager::get_settings();
        $catalog = self::get_default_models_catalog();
        $discovered = [];

        // 1. Check Gemini Models via API if key is available
        $gemini_key = $settings['gemini_api_key'] ?? '';
        if (!empty($gemini_key)) {
            try {
                $url = "https://generativelanguage.googleapis.com/v1beta/models?key=" . urlencode($gemini_key);
                $resp = wp_remote_get($url, ['timeout' => 15]);
                if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
                    $json = json_decode(wp_remote_retrieve_body($resp), true);
                    if (!empty($json['models']) && is_array($json['models'])) {
                        $found_models = [];
                        foreach ($json['models'] as $m) {
                            $name = str_replace('models/', '', $m['name'] ?? '');
                            // Only include text/content generation models
                            if (!empty($m['supportedGenerationMethods']) && in_array('generateContent', $m['supportedGenerationMethods'], true)) {
                                if (stripos($name, 'gemini') !== false) {
                                    $found_models[] = $name;
                                }
                            }
                        }

                        if (!empty($found_models)) {
                            // Sort to detect if a higher version exists (e.g. 3.9, 4.0, etc.)
                            usort($found_models, 'version_compare');
                            $latest_detected = end($found_models);

                            // Format into catalog
                            $formatted = [];
                            foreach (array_reverse($found_models) as $mId) {
                                if (count($formatted) >= 6) break; // Limit dropdown clutter
                                $is_top = ($mId === $latest_detected);
                                $formatted[] = [
                                    'id'          => $mId,
                                    'name'        => ucwords(str_replace(['-', '_'], ' ', $mId)),
                                    'badge'       => ucwords(str_replace(['gemini-', '_'], '', $mId)),
                                    'description' => $is_top ? 'Latest Detected Agent Version' : 'Available Gemini Model',
                                    'is_default'  => $is_top,
                                ];
                            }
                            if (!empty($formatted)) {
                                $catalog['gemini']['models'] = $formatted;
                                $catalog['gemini']['current_default'] = $latest_detected;
                                $discovered['gemini'] = $latest_detected;
                            }
                        }
                    }
                }
            } catch (\Exception $e) {
                // Keep default catalog on network failure
            }
        }

        // 2. Check OpenAI Models via API if key is available
        $openai_key = $settings['openai_api_key'] ?? '';
        if (!empty($openai_key)) {
            try {
                $url = 'https://api.openai.com/v1/models';
                $resp = wp_remote_get($url, [
                    'timeout' => 15,
                    'headers' => ['Authorization' => 'Bearer ' . $openai_key],
                ]);
                if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
                    $json = json_decode(wp_remote_retrieve_body($resp), true);
                    if (!empty($json['data']) && is_array($json['data'])) {
                        $found_gpt = [];
                        foreach ($json['data'] as $m) {
                            $id = $m['id'] ?? '';
                            if (preg_match('/^(gpt-[5-9]|gpt-6\.)/i', $id)) {
                                $found_gpt[] = $id;
                            }
                        }
                        if (!empty($found_gpt)) {
                            $latest_gpt = in_array('gpt-6.1-sol', $found_gpt, true) ? 'gpt-6.1-sol' : end($found_gpt);
                            $discovered['openai'] = $latest_gpt;
                        }
                    }
                }
            } catch (\Exception $e) {
                // Keep default
            }
        }

        // Cache catalog for 24 hours
        set_transient('wcpscan_ai_models_catalog', $catalog, 24 * HOUR_IN_SECONDS);

        // Auto-upgrade user settings to latest defaults if requested and newer version exists
        if ($auto_upgrade_active_settings) {
            $updated_settings = [];
            if (!empty($catalog['gemini']['current_default']) && $settings['gemini_model'] !== $catalog['gemini']['current_default']) {
                $updated_settings['gemini_model'] = $catalog['gemini']['current_default'];
            }
            if (!empty($catalog['openai']['current_default']) && $settings['openai_model'] !== $catalog['openai']['current_default']) {
                $updated_settings['openai_model'] = $catalog['openai']['current_default'];
            }
            if (!empty($catalog['claude']['current_default']) && $settings['claude_model'] !== $catalog['claude']['current_default']) {
                $updated_settings['claude_model'] = $catalog['claude']['current_default'];
            }

            if (!empty($updated_settings)) {
                SettingsManager::save_settings($updated_settings);
            }
        }

        return [
            'success'     => true,
            'message'     => __('AI Agent models updated to the latest available releases.', 'wcp-security-scanner'),
            'catalog'     => $catalog,
            'discovered'  => $discovered,
            'updated_at'  => current_time('mysql'),
        ];
    }
}
