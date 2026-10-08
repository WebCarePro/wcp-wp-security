<?php
namespace WCP\Scanner\System;

if (!defined('ABSPATH')) {
    exit;
}

class AIService {
    /**
     * Test connection to selected AI Provider
     */
    public static function test_connection(string $provider, string $api_key, string $model): array {
        if (empty($api_key)) {
            return ['success' => false, 'error' => __('API key is required.', 'wcp-wp-scanner')];
        }

        $prompt = 'Ping test. Reply with OK.';

        try {
            $response = self::call_provider($provider, $api_key, $model, 'You are an AI diagnostic tester.', $prompt, 0.1, 16);
            return [
                'success' => true,
                'message' => __('AI connection established successfully!', 'wcp-wp-scanner'),
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
        } else {
            $provider = 'openai';
            $api_key = !empty($data['api_key']) ? $data['api_key'] : ($settings['openai_api_key'] ?? '');
            $model = !empty($data['model']) ? $data['model'] : ($settings['openai_model'] ?? 'gpt-6.1-sol');
        }

        if (empty($api_key)) {
            throw new \Exception(__('AI Provider API key is missing. Please configure it in Security Scanner Settings.', 'wcp-wp-scanner'));
        }

        $code = $data['code'] ?? '';
        $file_path = $data['file_path'] ?? 'unknown_file.php';
        $threat_type = $data['threat_type'] ?? 'Suspicious Code / Malicious Function';
        $flagged_line = $data['line_number'] ?? null;

        if (empty($code)) {
            throw new \Exception(__('No code snippet provided for AI forensic analysis.', 'wcp-wp-scanner'));
        }

        // Limit code sent to avoid excessive token costs
        if (strlen($code) > 8000) {
            $code = substr($code, 0, 8000) . "\n...[truncated for token limit]...";
        }

        $system_prompt = "You are an elite WordPress Cybersecurity Forensic Specialist. Your task is to analyze code flagged by the WCP Security Scanner, assess threat probability, de-obfuscate hidden malware, evaluate security risks, and provide actionable remediation.";

        $user_prompt = "Analyze the following WordPress code snippet for security threats:\n\n" .
            "File Context: {$file_path}\n" .
            "Detected Vector: {$threat_type}\n" .
            ($flagged_line ? "Flagged Line: {$flagged_line}\n" : "") .
            "Code:\n```php\n{$code}\n```\n\n" .
            "Please provide a structured analysis with:\n" .
            "1. **Threat Assessment**: (Malicious, Suspicious, Safe / False Positive, or Legitimate)\n" .
            "2. **Risk Severity**: (Critical, High, Medium, Low, Clean)\n" .
            "3. **What the Code Does**: Plain English breakdown of intent and mechanics\n" .
            "4. **De-obfuscation / Payload Decoded**: (If obfuscated with base64, eval, rot13, chr, decode the underlying payload)\n" .
            "5. **Remediation Recommendation**: Specific steps for the developer/site owner to fix or clean this safely.";

        $temperature = floatval($settings['ai_temperature'] ?? 0.2);
        $max_tokens = 1200; // Efficient token usage for code forensics
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
     * Dispatch API call to selected AI provider
     */
    private static function call_provider(string $provider, string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200): string {
        if ($provider === 'gemini') {
            return self::call_gemini($api_key, $model, $system, $user, $temp, $max_tokens);
        } elseif ($provider === 'claude') {
            return self::call_claude($api_key, $model, $system, $user, $temp, $max_tokens);
        } else {
            return self::call_openai($api_key, $model, $system, $user, $temp, $max_tokens);
        }
    }

    /**
     * OpenAI API Implementation (GPT-6 series, GPT-6.1 Sol, GPT-6 Astra, etc.)
     */
    private static function call_openai(string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200): string {
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

        @set_time_limit(120);

        $response = wp_remote_post($url, [
            'timeout' => 90,
            'headers' => [
                'Authorization' => 'Bearer ' . $api_key,
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode($body),
        ]);

        if (is_wp_error($response)) {
            throw new \Exception('OpenAI Request Failed: ' . $response->get_error_message());
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw = wp_remote_retrieve_body($response);
        $data = json_decode($raw, true);

        if ($code !== 200) {
            $err = $data['error']['message'] ?? "HTTP error {$code}";
            throw new \Exception('OpenAI Error: ' . $err);
        }

        return $data['choices'][0]['message']['content'] ?? '';
    }

    /**
     * Google Gemini API Implementation (Gemini 3.5 Flash Lite, Gemini 3.8 Flash, etc.)
     */
    private static function call_gemini(string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200): string {
        $model_name = $model ?: 'gemini-3.5-flash-lite';
        $url = "https://generativelanguage.googleapis.com/v1beta/models/{$model_name}:generateContent?key=" . urlencode($api_key);

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

        @set_time_limit(120);

        $response = wp_remote_post($url, [
            'timeout' => 90,
            'headers' => ['Content-Type' => 'application/json'],
            'body'    => wp_json_encode($body),
        ]);

        if (is_wp_error($response)) {
            throw new \Exception('Gemini Request Failed: ' . $response->get_error_message());
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw = wp_remote_retrieve_body($response);
        $data = json_decode($raw, true);

        if ($code !== 200) {
            $err = $data['error']['message'] ?? "HTTP error {$code}";

            // Automatic resilient fallback: if the primary model is busy/overloaded or deprecating, try gemini-3.5-flash-lite
            if ($model_name !== 'gemini-3.5-flash-lite' && (stripos($err, 'high demand') !== false || stripos($err, 'overloaded') !== false || stripos($err, 'Resource has been exhausted') !== false || stripos($err, 'no longer available') !== false)) {
                return self::call_gemini($api_key, 'gemini-3.5-flash-lite', $system, $user, $temp, $max_tokens);
            }

            throw new \Exception('Google Gemini Error: ' . $err);
        }

        return $data['candidates'][0]['content']['parts'][0]['text'] ?? '';
    }

    /**
     * Anthropic Claude API Implementation (Claude Sonnet 5.5, Claude Opus 5.5, Claude Haiku 5.5, etc.)
     */
    private static function call_claude(string $api_key, string $model, string $system, string $user, float $temp, int $max_tokens = 1200): string {
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

        @set_time_limit(120);

        $response = wp_remote_post($url, [
            'timeout' => 90,
            'headers' => [
                'x-api-key'         => $api_key,
                'anthropic-version' => '2023-06-01',
                'Content-Type'      => 'application/json',
            ],
            'body'    => wp_json_encode($body),
        ]);

        if (is_wp_error($response)) {
            throw new \Exception('Claude Request Failed: ' . $response->get_error_message());
        }

        $code = wp_remote_retrieve_response_code($response);
        $raw = wp_remote_retrieve_body($response);
        $data = json_decode($raw, true);

        if ($code !== 200) {
            $err = $data['error']['message'] ?? "HTTP error {$code}";
            throw new \Exception('Anthropic Claude Error: ' . $err);
        }

        return $data['content'][0]['text'] ?? '';
    }

    /**
     * Get available model registry for all providers
     */
    public static function get_available_models(): array {
        $transient_key = 'wcp_scanner_ai_models_catalog';
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
        set_transient('wcp_scanner_ai_models_catalog', $catalog, 24 * HOUR_IN_SECONDS);

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
            'message'     => __('AI Agent models updated to the latest available releases.', 'wcp-wp-scanner'),
            'catalog'     => $catalog,
            'discovered'  => $discovered,
            'updated_at'  => current_time('mysql'),
        ];
    }
}
