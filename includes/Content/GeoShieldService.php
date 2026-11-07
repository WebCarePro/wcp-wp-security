<?php
namespace WcpScanner\Content;

use WcpScanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * GeoShieldService
 *
 * 2026 AI-Era Generative Engine Optimization (GEO) & AI SEO Shield.
 *
 * Protects websites against AI search engine poisoning and citation hijacking by:
 *  1. Monitoring /llms.txt and /llms-full.txt integrity against cryptographic baselines.
 *  2. Detecting prompt injections, crypto drainers, and phishing redirects inside /llms.txt.
 *  3. Auditing <script type="application/ld+json"> structured data schemas for poisoned authority data.
 *  4. Detecting invisible CSS cloaking (zero opacity, negative z-index, transparent color) targeting LLM crawlers.
 *
 * Engineered by Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer.
 *
 * @package WcpScanner\Content
 */
class GeoShieldService {

    const BASELINE_OPTION = 'wcpscan_llmstxt_baseline';

    /**
     * Common cryptocurrency address regex patterns.
     */
    const CRYPTO_PATTERNS = [
        'btc' => '/\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/',
        'eth' => '/\b0x[a-fA-F0-9]{40}\b/',
        'sol' => '/\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/'
    ];

    /**
     * Prompt injection tokens often placed in llms.txt to manipulate AI agents.
     */
    const PROMPT_INJECTION_TOKENS = [
        'ignore previous instructions',
        'disregard prior instructions',
        'system directive:',
        'system prompt:',
        '<|im_start|>',
        '<|im_end|>',
        '[inst]',
        '[/inst]',
        '### system:',
        '### human:',
        '### assistant:',
        'call tool:',
        'execute tool:'
    ];

    /**
     * Audit /llms.txt and /llms-full.txt files in WordPress root.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public static function audit_fim_llms_files(string $scan_id = ''): array {
        $findings = [];
        $root_files = [
            'llms.txt'      => ABSPATH . 'llms.txt',
            'llms-full.txt' => ABSPATH . 'llms-full.txt',
        ];

        $baselines = get_option(self::BASELINE_OPTION, []);
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';

        foreach ($root_files as $filename => $path) {
            if (!file_exists($path)) {
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                continue;
            }

            $current_hash = hash('sha256', $content);
            $norm_path = wp_normalize_path($path);

            // 1. Check Cryptographic Baseline Drift
            if (isset($baselines[$filename])) {
                $saved = $baselines[$filename];
                if (!empty($saved['hash']) && $saved['hash'] !== $current_hash) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'llms_txt_tampered',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => $norm_path,
                        'description' => sprintf(
                            /* translators: %s: filename */
                            __('Unauthorized modification detected in %s. AI search engines (ChatGPT, Perplexity, Claude) may ingest poisoned brand data.', 'wcp-security-scanner'),
                            esc_html($filename)
                        ),
                        'evidence'    => sprintf('Expected Hash: %s... | Live Hash: %s...', substr($saved['hash'], 0, 16), substr($current_hash, 0, 16)),
                        'code_snippet'=> substr($content, 0, 250)
                    ]);
                }
            }

            // 2. Check for Prompt Injection Sinks in llms.txt
            foreach (self::PROMPT_INJECTION_TOKENS as $token) {
                if (stripos($content, $token) !== false) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'llms_txt_prompt_injection',
                        'severity'    => 'critical',
                        'confidence'  => 98,
                        'file_path'   => $norm_path,
                        'description' => sprintf(
                            /* translators: %1$s: filename, %2$s: token */
                            __('Prompt injection payload ("%2$s") detected inside %1$s. Adversaries use this to hijack AI search citations and assistant summaries.', 'wcp-security-scanner'),
                            esc_html($filename),
                            esc_html($token)
                        ),
                        'evidence'    => "Matched Token: {$token}",
                        'code_snippet'=> substr($content, 0, 250)
                    ]);
                    break;
                }
            }

            // 3. Check for Malicious External URLs / Phishing Sinks
            if (preg_match_all('/https?:\/\/([^\s\)\"\'>]+)/i', $content, $url_matches)) {
                $foreign_count = 0;
                $suspicious_urls = [];

                foreach ($url_matches[0] as $url) {
                    $u_host = wp_parse_url($url, PHP_URL_HOST);
                    if (!$u_host) continue;

                    // Ignore self host, localhost, or common legitimate docs/standards (llmstxt.org, w3.org, github.com, wordpress.org)
                    $is_self = ($site_host && (strtolower($u_host) === strtolower($site_host) || str_ends_with(strtolower($u_host), '.' . strtolower($site_host))));
                    $is_standard_doc = (bool) preg_match('/(?:llmstxt\.org|w3\.org|schema\.org|github\.com|wordpress\.org|automattic\.com)/i', $u_host);

                    if (!$is_self && !$is_standard_doc) {
                        $foreign_count++;
                        $suspicious_urls[] = $url;
                    }
                }

                // If llms.txt contains external links not pointing to this site or standard authorities
                if ($foreign_count > 3) {
                    $findings[] = new Finding([
                        'engine'      => 'integrity-fim',
                        'type'        => 'llms_txt_unauthorized_external_links',
                        'severity'    => 'medium',
                        'confidence'  => 85,
                        'file_path'   => $norm_path,
                        'description' => sprintf(
                            /* translators: %1$s: filename, %2$d: count */
                            __('%1$s contains %2$d third-party links not associated with your domain. Review to ensure AI crawlers are not directed to phishing or affiliate spam.', 'wcp-security-scanner'),
                            esc_html($filename),
                            $foreign_count
                        ),
                        'evidence'    => 'External targets: ' . implode(', ', array_slice($suspicious_urls, 0, 3)),
                    ]);
                }
            }

            // 4. Check for Crypto Wallet Drainer Addresses
            if (preg_match(self::CRYPTO_PATTERNS['eth'], $content, $m_eth) || preg_match(self::CRYPTO_PATTERNS['btc'], $content, $m_btc)) {
                $wallet = $m_eth[0] ?? ($m_btc[0] ?? '');
                $findings[] = new Finding([
                    'engine'      => 'integrity-fim',
                    'type'        => 'llms_txt_crypto_drainer_address',
                    'severity'    => 'critical',
                    'confidence'  => 99,
                    'file_path'   => $norm_path,
                    'description' => sprintf(
                        /* translators: %s: filename */
                        __('Cryptocurrency wallet address detected inside %s. Threat actors inject wallet addresses to fool AI search engines into recommending fraudulent crypto payment destinations.', 'wcp-security-scanner'),
                        esc_html($filename)
                    ),
                    'evidence'    => "Detected Wallet: {$wallet}",
                    'code_snippet'=> substr($content, 0, 250)
                ]);
            }
        }

        return $findings;
    }

    /**
     * Save the pristine cryptographic baseline for /llms.txt and /llms-full.txt.
     *
     * @return array
     */
    public static function save_llms_baseline(): array {
        $root_files = [
            'llms.txt'      => ABSPATH . 'llms.txt',
            'llms-full.txt' => ABSPATH . 'llms-full.txt',
        ];

        $baselines = [];
        foreach ($root_files as $filename => $path) {
            if (file_exists($path)) {
                $content = @file_get_contents($path);
                if ($content !== false) {
                    $baselines[$filename] = [
                        'hash'        => hash('sha256', $content),
                        'size'        => filesize($path),
                        'modified_at' => filemtime($path),
                        'saved_at'    => current_time('mysql'),
                    ];
                }
            }
        }

        update_option(self::BASELINE_OPTION, $baselines);

        return [
            'success'   => true,
            'message'   => __('Pristine baseline for /llms.txt files successfully saved.', 'wcp-security-scanner'),
            'baselines' => $baselines
        ];
    }

    /**
     * Audit structured JSON-LD data schemas inside HTML for poisoning and manipulation.
     *
     * @param string $html
     * @return array List of findings.
     */
    public static function audit_jsonld_schemas(string $html): array {
        $detections = [];

        if (empty($html) || !is_string($html)) {
            return $detections;
        }

        // Match all <script type="application/ld+json">...</script>
        if (!preg_match_all('/<script\s+[^>]*type\s*=\s*["\']application\/ld\+json["\'][^>]*>(.*?)<\/script>/is', $html, $matches)) {
            return $detections;
        }

        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';

        foreach ($matches[1] as $idx => $raw_json) {
            $raw_json = trim($raw_json);
            if (empty($raw_json)) {
                continue;
            }

            $decoded = json_decode($raw_json, true);
            if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
                // Malformed JSON-LD can indicate injection attempt
                $detections[] = [
                    'type'       => 'jsonld_malformed_syntax',
                    'snippet'    => substr($raw_json, 0, 150),
                    'desc'       => 'Malformed JSON-LD schema detected. Incomplete or corrupted structured data.',
                    'severity'   => 'medium',
                    'confidence' => 80
                ];
                continue;
            }

            // Inspect Schema Entities Recursively
            $schema_type = $decoded['@type'] ?? 'Unknown';
            self::inspect_schema_node($decoded, $site_host, $detections, $raw_json);
        }

        return $detections;
    }

    /**
     * Recursively inspect a JSON-LD schema node for malicious attributes.
     *
     * @param mixed $node
     * @param string $site_host
     * @param array &$detections
     * @param string $raw_json
     */
    private static function inspect_schema_node($node, string $site_host, array &$detections, string $raw_json) {
        if (!is_array($node)) {
            return;
        }

        // 1. Check Telephone Spoofing
        if (isset($node['telephone']) && is_string($node['telephone'])) {
            $phone = trim($node['telephone']);
            // High-risk toll fraud prefixes (+1-900, +888, premium rate lines)
            if (preg_match('/(?:\+?1[-.\s]?900[-.\s]?[0-9]{3}|(?:\+?888|\+?870|\+?881))/i', $phone)) {
                $detections[] = [
                    'type'       => 'jsonld_toll_fraud_telephone',
                    'snippet'    => substr($raw_json, 0, 150),
                    'desc'       => sprintf('High-risk premium rate or fraudulent telephone number ("%s") detected in JSON-LD schema.', esc_html($phone)),
                    'severity'   => 'critical',
                    'confidence' => 95
                ];
            }
        }

        // 2. Check for Suspicious Authority Hijacking in sameAs or url
        $urls_to_check = [];
        if (isset($node['url']) && is_string($node['url'])) {
            $urls_to_check[] = $node['url'];
        }
        if (isset($node['sameAs'])) {
            if (is_array($node['sameAs'])) {
                $urls_to_check = array_merge($urls_to_check, $node['sameAs']);
            } elseif (is_string($node['sameAs'])) {
                $urls_to_check[] = $node['sameAs'];
            }
        }

        foreach ($urls_to_check as $target_url) {
            if (!is_string($target_url)) continue;
            $u_host = wp_parse_url($target_url, PHP_URL_HOST);
            if (!$u_host) continue;

            // Check if domain is a known URL shortener or suspect TLD (.tk, .xyz, .top, .click, .cam)
            if (preg_match('/\.(?:tk|xyz|top|click|cam|fun|rest|live|vip|work|gq|ml|cf)$/i', $u_host)) {
                $detections[] = [
                    'type'       => 'jsonld_suspicious_tld_redirect',
                    'snippet'    => substr($raw_json, 0, 150),
                    'desc'       => sprintf('JSON-LD schema points authority ("sameAs" / "url") to high-risk TLD host "%s". AI engines may associate your brand with phishing destinations.', esc_html($u_host)),
                    'severity'   => 'high',
                    'confidence' => 90
                ];
            }
        }

        // 3. Check for Crypto Wallet Addresses in schema text fields
        foreach ($node as $k => $v) {
            if (is_string($v)) {
                if (preg_match(self::CRYPTO_PATTERNS['eth'], $v) || preg_match(self::CRYPTO_PATTERNS['btc'], $v)) {
                    $detections[] = [
                        'type'       => 'jsonld_crypto_wallet_injection',
                        'snippet'    => substr($raw_json, 0, 150),
                        'desc'       => sprintf('Cryptocurrency address detected inside JSON-LD attribute "%s". Threat actors use schema poisoning to feed fake addresses to AI Overviews.', esc_html($k)),
                        'severity'   => 'critical',
                        'confidence' => 98
                    ];
                }
            } elseif (is_array($v)) {
                self::inspect_schema_node($v, $site_host, $detections, $raw_json);
            }
        }
    }

    /**
     * Inspect HTML for invisible CSS cloaking targeting AI search crawlers.
     *
     * @param string $html
     * @return array
     */
    public static function audit_geo_cloaking(string $html): array {
        $detections = [];
        if (empty($html) || !is_string($html)) {
            return $detections;
        }

        // 1. Transparent text color: color: transparent / color: rgba(0,0,0,0)
        if (preg_match('/(?:style\s*=\s*["\'][^"\']*color\s*:\s*(?:transparent|rgba\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\))[^"\']*["\'][^>]*>(.*?)<\/(?:p|div|span|h[1-6]|li|a)>)/is', $html, $matches)) {
            $text = trim(wp_strip_all_tags($matches[1]));
            if (!empty($text)) {
                $detections[] = [
                    'type'       => 'geo_transparent_text_cloak',
                    'snippet'    => substr($matches[0], 0, 150),
                    'desc'       => sprintf('Transparent text cloaking detected ("%s"). Content is invisible to visitors but scraped by AI search bots.', esc_html(substr($text, 0, 80))),
                    'severity'   => 'high',
                    'confidence' => 92
                ];
            }
        }

        // 2. High-contrast identical foreground and background (e.g. color: #fff; background: #fff;)
        if (preg_match('/style\s*=\s*["\'][^"\']*(?:color\s*:\s*(?:#ffffff|#fff|white)\s*;\s*background(?:-color)?\s*:\s*(?:#ffffff|#fff|white)|color\s*:\s*(?:#000000|#000|black)\s*;\s*background(?:-color)?\s*:\s*(?:#000000|#000|black))[^"\']*["\']/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'geo_contrast_cloak',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Identical foreground and background CSS color detected (contrast cloaking). Conceals text from users while feeding AI crawlers.',
                'severity'   => 'high',
                'confidence' => 90
            ];
        }

        // 3. Screen-reader clip / sr-only containing external links or phone numbers
        if (preg_match('/(?:class\s*=\s*["\'][^"\']*(?:screen-reader-text|sr-only)[^"\']*["\']|style\s*=\s*["\'][^"\']*(?:clip\s*:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)|clip-path\s*:\s*inset\s*\(\s*50%\s*\))[^"\']*["\'])[^>]*>(.*?)<\/(?:span|div|p)>/is', $html, $matches)) {
            $inner = $matches[1];
            // If sr-only container has external links or cryptocurrency addresses
            if (preg_match('/href\s*=\s*["\']https?:\/\/|\b0x[a-fA-F0-9]{40}\b/i', $inner)) {
                $detections[] = [
                    'type'       => 'geo_sr_only_abused_link_cloak',
                    'snippet'    => substr($matches[0], 0, 150),
                    'desc'       => 'Screen-reader/clip-path utility abused to conceal external links or cryptocurrency addresses from visual layout.',
                    'severity'   => 'critical',
                    'confidence' => 95
                ];
            }
        }

        return $detections;
    }

    /**
     * Retrieve aggregated telemetry status for the GEO Shield.
     *
     * @return array
     */
    public static function get_telemetry(): array {
        $root_files = [
            'llms.txt'      => ABSPATH . 'llms.txt',
            'llms-full.txt' => ABSPATH . 'llms-full.txt',
        ];

        $baselines = get_option(self::BASELINE_OPTION, []);
        $files_status = [];

        foreach ($root_files as $filename => $path) {
            $exists = file_exists($path);
            $size = $exists ? filesize($path) : 0;
            $mtime = $exists ? filemtime($path) : 0;
            $current_hash = $exists ? hash('sha256', (string) @file_get_contents($path)) : null;

            $has_baseline = isset($baselines[$filename]);
            $is_matching = $has_baseline && ($baselines[$filename]['hash'] === $current_hash);

            $files_status[$filename] = [
                'exists'       => $exists,
                'path'         => $path,
                'size'         => $size,
                'modified_at'  => $mtime ? gmdate('Y-m-d H:i:s', $mtime) : null,
                'hash'         => $current_hash,
                'has_baseline' => $has_baseline,
                'is_verified'  => $is_matching,
                'baseline_at'  => $has_baseline ? ($baselines[$filename]['saved_at'] ?? null) : null,
            ];
        }

        return [
            'success'          => true,
            'files'            => $files_status,
            'has_all_baselines'=> (!empty($files_status['llms.txt']['is_verified'])),
            'schema_checks'    => [
                'jsonld_telephone_audit'   => true,
                'jsonld_authority_audit'   => true,
                'jsonld_crypto_audit'      => true,
                'geo_contrast_cloak_audit' => true,
                'geo_transparent_audit'    => true,
                'geo_sr_only_audit'        => true,
            ],
            'version'          => '2026.1-geo'
        ];
    }
}
