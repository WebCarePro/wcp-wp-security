<?php
namespace WebCareProScanner\Identity;

use WebCareProScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AiAgentInventoryScanner
 *
 * Third-Party AI & MCP Plugin Governance and Secret Vaulting.
 * Discovers unauthenticated or misconfigured AI connectors and exposed MCP endpoints.
 * Audits wp_options for plaintext AI/LLM credentials and migrates them into SecretVault (AES-256-GCM).
 */
class AiAgentInventoryScanner {

    private const SUSPICIOUS_OPTION_PATTERNS = [
        '/openai[_-]?key/i',
        '/anthropic[_-]?key/i',
        '/gemini[_-]?key/i',
        '/mcp[_-]?token/i',
        '/ai[_-]?secret/i',
        '/llm[_-]?auth/i',
    ];

    /**
     * Scan WordPress database and REST inventory for AI/MCP agents and unencrypted keys.
     *
     * @return array<string, mixed>
     */
    public function scan_ai_inventory(): array {
        global $wpdb;

        $findings = [];
        $unencrypted_keys = [];

        // 1. Audit wp_options for plaintext AI/LLM/MCP secrets
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $options = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options} 
             WHERE option_name LIKE '%ai_%' 
             OR option_name LIKE '%mcp_%' 
             OR option_name LIKE '%openai%' 
             OR option_name LIKE '%anthropic%' 
             LIMIT 200",
            ARRAY_A
        );

        if (is_array($options)) {
            foreach ($options as $opt) {
                $name  = $opt['option_name'];
                $value = (string) $opt['option_value'];

                foreach (self::SUSPICIOUS_OPTION_PATTERNS as $pattern) {
                    if (preg_match($pattern, $name) && $value !== '' && !str_starts_with($value, 'wcp_gcm:') && !str_starts_with($value, 'wcp_enc_')) {
                        $unencrypted_keys[] = [
                            'option_name' => $name,
                            'length'      => strlen($value),
                        ];
                        break;
                    }
                }
            }
        }

        if (!empty($unencrypted_keys)) {
            $findings[] = [
                'type'           => 'ai_inventory_plaintext_secrets',
                'severity'       => 'high',
                'count'          => count($unencrypted_keys),
                'details'        => $unencrypted_keys,
                'recommendation' => 'Migrate plaintext AI keys into the WCP Secret Vault (AES-256-GCM).',
            ];
        }

        // 2. Audit exposed MCP / AI REST endpoints
        if (function_exists('rest_get_server')) {
            $server = rest_get_server();
            if ($server && method_exists($server, 'get_routes')) {
                $rest_routes = $server->get_routes();
                $exposed_mcp = [];

                foreach ($rest_routes as $route => $handlers) {
                    if (preg_match('#/(?:mcp|ai|llm|agent)/#i', $route)) {
                        $requires_auth = true;
                        if (is_array($handlers)) {
                            foreach ($handlers as $handler) {
                                if (empty($handler['permission_callback'])) {
                                    $requires_auth = false;
                                    break;
                                }
                            }
                        }

                        if (!$requires_auth) {
                            $exposed_mcp[] = $route;
                        }
                    }
                }

                if (!empty($exposed_mcp)) {
                    $findings[] = [
                        'type'     => 'ai_inventory_unauthenticated_mcp_route',
                        'severity' => 'critical',
                        'routes'   => $exposed_mcp,
                        'reason'   => 'Exposed AI/MCP REST route lacks an explicit permission callback.',
                    ];
                }
            }
        }

        return [
            'scanned_at' => time(),
            'findings'   => $findings,
        ];
    }

    /**
     * Automatically vault discovered plaintext keys.
     *
     * @return int Count of migrated keys
     */
    public function migrate_keys_to_vault(): int {
        global $wpdb;
        $migrated = 0;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $options = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options} 
             WHERE option_name LIKE '%ai_%' 
             OR option_name LIKE '%mcp_%' 
             OR option_name LIKE '%openai%'",
            ARRAY_A
        );

        if (is_array($options)) {
            foreach ($options as $opt) {
                $name  = $opt['option_name'];
                $value = (string) $opt['option_value'];

                if ($value !== '' && !str_starts_with($value, 'wcp_gcm:') && !str_starts_with($value, 'wcp_enc_') && strlen($value) > 15) {
                    $encrypted = SecretVault::encrypt_secret($value);
                    if ($encrypted) {
                        update_option($name, $encrypted, false);
                        $migrated++;
                    }
                }
            }
        }

        return $migrated;
    }
}
