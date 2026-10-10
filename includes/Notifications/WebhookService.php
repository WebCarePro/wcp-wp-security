<?php
namespace WCP\Scanner\Notifications;

use WCP\Scanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * DevSecOps Chat Webhook Service
 *
 * Dispatches real-time security alerts to team collaboration channels
 * on Slack (Block Kit) and Discord (Rich Embeds).
 */
class WebhookService {

    const COLOR_CRITICAL = '#dc2626'; // 14428198
    const COLOR_WARNING  = '#f59e0b'; // 16096779
    const COLOR_SUCCESS  = '#10b981'; // 1096065
    const COLOR_INFO     = '#0284c7'; // 164999

    /**
     * Dispatch a test alert to verify webhook integration
     */
    public static function send_test(string $platform, ?string $custom_url = null): array {
        $settings = SettingsManager::get_settings();
        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) ?: 'WordPress';
        $site_url  = get_site_url();
        $dashboard_url = admin_url('admin.php?page=wcp-security-scanner');

        if ($platform === 'slack') {
            $url = !empty($custom_url) ? trim($custom_url) : ($settings['slack_webhook_url'] ?? '');
            if (empty($url)) {
                return ['success' => false, 'code' => 400, 'message' => __('No Slack Webhook URL provided.', 'wcp-security-scanner')];
            }

            $payload = [
                'text' => "🧪 [TEST] WCP Security Scanner alert for {$site_name}",
                'attachments' => [
                    [
                        'color' => self::COLOR_SUCCESS,
                        'blocks' => [
                            [
                                'type' => 'header',
                                'text' => ['type' => 'plain_text', 'text' => '🧪 WCP Security Webhook Test', 'emoji' => true]
                            ],
                            [
                                'type' => 'section',
                                'text' => [
                                    'type' => 'mrkdwn',
                                    'text' => "*Site:* <{$site_url}|{$site_name}>\n*Status:* Webhook delivery test successful!\n*Security Engine:* WCP Security Scanner v1.5.0"
                                ]
                            ],
                            [
                                'type' => 'actions',
                                'elements' => [
                                    [
                                        'type' => 'button',
                                        'text' => ['type' => 'plain_text', 'text' => 'Open Security Dashboard'],
                                        'url' => $dashboard_url,
                                        'style' => 'primary'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ];

            return self::post_webhook($url, $payload, 'Slack');

        } elseif ($platform === 'discord') {
            $url = !empty($custom_url) ? trim($custom_url) : ($settings['discord_webhook_url'] ?? '');
            if (empty($url)) {
                return ['success' => false, 'code' => 400, 'message' => __('No Discord Webhook URL provided.', 'wcp-security-scanner')];
            }

            $payload = [
                'username' => 'WCP Security Bot',
                'embeds' => [
                    [
                        'title' => '🧪 WCP Security Webhook Test',
                        'description' => "Real-time security alert integration with **{$site_name}** is operational.",
                        'url' => $dashboard_url,
                        'color' => 1096065, // Emerald green
                        'fields' => [
                            ['name' => 'Site URL', 'value' => $site_url, 'inline' => true],
                            ['name' => 'Engine Version', 'value' => 'v1.5.0', 'inline' => true],
                            ['name' => 'Status', 'value' => 'Connected & Ready', 'inline' => true],
                        ],
                        'footer' => ['text' => 'WebCare Pro DevSecOps Security Hub'],
                        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                    ]
                ]
            ];

            return self::post_webhook($url, $payload, 'Discord');
        }

        return ['success' => false, 'code' => 400, 'message' => __('Unsupported platform.', 'wcp-security-scanner')];
    }

    /**
     * Dispatch Scan Completion Alert to Slack & Discord
     */
    public static function send_scan_alert(int $scan_id, int $total_issues, int $risk_score, string $target, array $issues = []) {
        $settings = SettingsManager::get_settings();
        $has_slack   = !empty($settings['slack_enabled']) && !empty($settings['slack_webhook_url']);
        $has_discord = !empty($settings['discord_enabled']) && !empty($settings['discord_webhook_url']);

        if (!$has_slack && !$has_discord) {
            return;
        }

        $critical_count = 0;
        $high_count     = 0;
        foreach ($issues as $iss) {
            if (($iss['severity'] ?? '') === 'critical') $critical_count++;
            elseif (($iss['severity'] ?? '') === 'high') $high_count++;
        }

        $notify_on_critical = !empty($settings['webhook_notify_on_critical']);
        $notify_on_finish   = !empty($settings['webhook_notify_on_scan_finish']);

        if (!$notify_on_finish && (!($notify_on_critical && ($critical_count > 0 || $high_count > 0)))) {
            return;
        }

        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) ?: 'WordPress';
        $site_url  = get_site_url();
        $dashboard_url = admin_url('admin.php?page=wcp-security-scanner');

        $is_danger = ($critical_count > 0 || $high_count > 0);
        $color_hex = $is_danger ? self::COLOR_CRITICAL : ($total_issues > 0 ? self::COLOR_WARNING : self::COLOR_SUCCESS);
        $color_int = $is_danger ? 14428198 : ($total_issues > 0 ? 16096779 : 1096065);
        $status_emoji = $is_danger ? '🚨' : ($total_issues > 0 ? '⚠️' : '✅');

        // 1. Dispatch Slack
        if ($has_slack) {
            $slack_fields = [
                ['type' => 'mrkdwn', 'text' => "*Risk Score:*\n{$risk_score}/100"],
                ['type' => 'mrkdwn', 'text' => "*Total Findings:*\n{$total_issues}"],
                ['type' => 'mrkdwn', 'text' => "*Critical Threats:*\n{$critical_count}"],
                ['type' => 'mrkdwn', 'text' => "*High Warnings:*\n{$high_count}"],
            ];

            $slack_payload = [
                'text' => "{$status_emoji} Security Scan #{$scan_id} finished on {$site_name} ({$total_issues} findings)",
                'attachments' => [
                    [
                        'color' => $color_hex,
                        'blocks' => [
                            [
                                'type' => 'header',
                                'text' => ['type' => 'plain_text', 'text' => "{$status_emoji} WCP Security Scan Report", 'emoji' => true]
                            ],
                            [
                                'type' => 'section',
                                'text' => [
                                    'type' => 'mrkdwn',
                                    'text' => "*Site:* <{$site_url}|{$site_name}>\n*Target:* `{$target}` | *Scan ID:* `#{$scan_id}`"
                                ]
                            ],
                            [
                                'type' => 'section',
                                'fields' => $slack_fields
                            ],
                            [
                                'type' => 'actions',
                                'elements' => [
                                    [
                                        'type' => 'button',
                                        'text' => ['type' => 'plain_text', 'text' => 'Review Findings & Auto-Cure'],
                                        'url' => $dashboard_url,
                                        'style' => $is_danger ? 'danger' : 'primary'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ];

            self::post_webhook($settings['slack_webhook_url'], $slack_payload, 'Slack');
        }

        // 2. Dispatch Discord
        if ($has_discord) {
            $discord_payload = [
                'username' => 'WCP Security Bot',
                'embeds' => [
                    [
                        'title' => "{$status_emoji} Security Scan #{$scan_id} Completed",
                        'description' => "Audit concluded on **{$site_name}** with **{$total_issues}** findings recorded.",
                        'url' => $dashboard_url,
                        'color' => $color_int,
                        'fields' => [
                            ['name' => 'Risk Score', 'value' => "{$risk_score}/100", 'inline' => true],
                            ['name' => 'Critical', 'value' => (string) $critical_count, 'inline' => true],
                            ['name' => 'High', 'value' => (string) $high_count, 'inline' => true],
                            ['name' => 'Target Mode', 'value' => $target, 'inline' => true],
                            ['name' => 'Site URL', 'value' => $site_url, 'inline' => true],
                        ],
                        'footer' => ['text' => 'WebCare Pro Security Scanner'],
                        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                    ]
                ]
            ];

            self::post_webhook($settings['discord_webhook_url'], $discord_payload, 'Discord');
        }
    }

    /**
     * Dispatch File Integrity Monitoring (FIM) Alert
     */
    public static function send_fim_alert(array $changed_files) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['webhook_notify_on_fim'])) {
            return;
        }

        $has_slack   = !empty($settings['slack_enabled']) && !empty($settings['slack_webhook_url']);
        $has_discord = !empty($settings['discord_enabled']) && !empty($settings['discord_webhook_url']);

        if (!$has_slack && !$has_discord) {
            return;
        }

        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) ?: 'WordPress';
        $site_url  = get_site_url();
        $fim_url   = admin_url('admin.php?page=wcp-scanner-fim');
        $count     = count($changed_files);

        $sample_paths = array_slice(array_map(function ($f) {
            return '`' . basename($f['relative_path'] ?? $f['file_path'] ?? '') . '`';
        }, $changed_files), 0, 4);
        $sample_str = implode(', ', $sample_paths);

        if ($has_slack) {
            $slack_payload = [
                'text' => "⚠️ [FIM Alert] {$count} modified files detected on {$site_name}",
                'attachments' => [
                    [
                        'color' => self::COLOR_WARNING,
                        'blocks' => [
                            [
                                'type' => 'header',
                                'text' => ['type' => 'plain_text', 'text' => '⚠️ File Integrity Monitor Warning', 'emoji' => true]
                            ],
                            [
                                'type' => 'section',
                                'text' => [
                                    'type' => 'mrkdwn',
                                    'text' => "*Site:* <{$site_url}|{$site_name}>\n*Modified Files:* {$count}\n*Recent Changes:* {$sample_str}"
                                ]
                            ],
                            [
                                'type' => 'actions',
                                'elements' => [
                                    [
                                        'type' => 'button',
                                        'text' => ['type' => 'plain_text', 'text' => 'Inspect Code Diff (FIM)'],
                                        'url' => $fim_url,
                                        'style' => 'primary'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ];
            self::post_webhook($settings['slack_webhook_url'], $slack_payload, 'Slack');
        }

        if ($has_discord) {
            $discord_payload = [
                'username' => 'WCP FIM Monitor',
                'embeds' => [
                    [
                        'title' => '⚠️ File Integrity Changes Detected',
                        'description' => "FIM flagged **{$count}** unexpected filesystem modifications on **{$site_name}**.\nSample: {$sample_str}",
                        'url' => $fim_url,
                        'color' => 16096779,
                        'fields' => [
                            ['name' => 'Modified Count', 'value' => (string) $count, 'inline' => true],
                            ['name' => 'Site', 'value' => $site_name, 'inline' => true],
                        ],
                        'footer' => ['text' => 'WCP File Integrity Monitoring'],
                        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                    ]
                ]
            ];
            self::post_webhook($settings['discord_webhook_url'], $discord_payload, 'Discord');
        }
    }

    /**
     * Dispatch High-Severity WAF Lite Attack Interception Alert
     */
    public static function send_waf_alert(array $incident) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['webhook_notify_on_waf_block'])) {
            return;
        }

        // Rate-limit WAF webhooks to at most 1 per 60 seconds to avoid spamming team channels during DDoS/floods
        $rate_key = 'wcp_waf_webhook_rate_limit';
        if (get_transient($rate_key)) {
            return;
        }
        set_transient($rate_key, 1, 60);

        $has_slack   = !empty($settings['slack_enabled']) && !empty($settings['slack_webhook_url']);
        $has_discord = !empty($settings['discord_enabled']) && !empty($settings['discord_webhook_url']);

        if (!$has_slack && !$has_discord) {
            return;
        }

        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) ?: 'WordPress';
        $site_url  = get_site_url();
        $waf_url   = admin_url('admin.php?page=wcp-scanner-firewall');

        $category = $incident['category'] ?? 'Exploit Probe';
        $rule     = $incident['name'] ?? 'WAF Rule';
        $ip       = $incident['ip_address'] ?? 'unknown';

        if ($has_slack) {
            $slack_payload = [
                'text' => "🛡️ [WAF Block] Attack intercepted from {$ip} on {$site_name}",
                'attachments' => [
                    [
                        'color' => self::COLOR_CRITICAL,
                        'blocks' => [
                            [
                                'type' => 'header',
                                'text' => ['type' => 'plain_text', 'text' => '🛡️ WAF Lite Attack Blocked', 'emoji' => true]
                            ],
                            [
                                'type' => 'section',
                                'text' => [
                                    'type' => 'mrkdwn',
                                    'text' => "*Site:* <{$site_url}|{$site_name}>\n*Attacker IP:* `{$ip}`\n*Category:* *{$category}*\n*Rule:* `{$rule}`"
                                ]
                            ],
                            [
                                'type' => 'actions',
                                'elements' => [
                                    [
                                        'type' => 'button',
                                        'text' => ['type' => 'plain_text', 'text' => 'View Live Incident Stream'],
                                        'url' => $waf_url,
                                        'style' => 'danger'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ];
            self::post_webhook($settings['slack_webhook_url'], $slack_payload, 'Slack');
        }

        if ($has_discord) {
            $discord_payload = [
                'username' => 'WCP Firewall Bot',
                'embeds' => [
                    [
                        'title' => '🛡️ WAF Lite Attack Intercepted',
                        'description' => "Malicious HTTP probe rejected before reaching WordPress core.",
                        'url' => $waf_url,
                        'color' => 14428198,
                        'fields' => [
                            ['name' => 'Attacker IP', 'value' => $ip, 'inline' => true],
                            ['name' => 'Category', 'value' => $category, 'inline' => true],
                            ['name' => 'Rule', 'value' => $rule, 'inline' => true],
                        ],
                        'footer' => ['text' => 'WCP Web Application Firewall'],
                        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                    ]
                ]
            ];
            self::post_webhook($settings['discord_webhook_url'], $discord_payload, 'Discord');
        }
    }

    /**
     * Send HTTP POST to webhook endpoint
     */
    private static function post_webhook(string $url, array $payload, string $platform_name): array {
        $response = wp_remote_post($url, [
            'timeout'     => 8,
            'blocking'    => true,
            'headers'     => ['Content-Type' => 'application/json'],
            'body'        => wp_json_encode($payload),
            'data_format' => 'body',
        ]);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'code'    => 500,
                'message' => sprintf(__('%s delivery error: %s', 'wcp-security-scanner'), $platform_name, $response->get_error_message()),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 200 && $code < 300) {
            return [
                'success' => true,
                'code'    => $code,
                'message' => sprintf(__('%s alert delivered successfully (HTTP %d).', 'wcp-security-scanner'), $platform_name, $code),
            ];
        }

        $body = wp_remote_retrieve_body($response);
        return [
            'success' => false,
            'code'    => $code,
            'message' => sprintf(__('%s returned HTTP %d: %s', 'wcp-security-scanner'), $platform_name, $code, substr($body, 0, 120)),
        ];
    }
}
