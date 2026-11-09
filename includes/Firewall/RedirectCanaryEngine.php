<?php
/**
 * RedirectCanaryEngine
 *
 * Synthetic Out-of-Band Canary, Differential Cloaking Watchdog & Database URL Sentinel.
 * Executes 5 specialized multi-vector probes (Search Engine, Mobile UA, AI Search, Admin Gatekeeper, Baseline)
 * with differential DOM inspection, Web3 RPC C2 detection, ClickFix analysis, and Strict 3-Condition Auto-Heal.
 *
 * @package WebCareProScanner\Firewall
 * @author  Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer
 */

namespace WebCareProScanner\Firewall;

use WebCareProScanner\Security\SecretVault;
use WebCareProScanner\Notifications\NotificationDispatcher;
use WebCareProScanner\System\WcpActivityLogger;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

final class RedirectCanaryEngine {

    public const STATE_OPTION        = 'webcareproscan_redirect_canary_state';
    public const BASELINE_OPTION     = 'webcareproscan_canonical_host_baseline';
    public const LAST_REPORT_OPTION  = 'webcareproscan_redirect_canary_last_report';
    public const AUTO_HEAL_OPTION    = 'webcareproscan_redirect_auto_heal_enabled';
    public const HMAC_HEADER         = 'X-WCP-Canary-Signature';

    /**
     * User-Agent Strings for Probing.
     */
    private const UA_DESKTOP = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
    private const UA_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const UA_MOBILE_IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
    private const UA_AI_SEARCHBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)';

    /**
     * Run the scheduled 15-minute background canary audit.
     *
     * @return array Comprehensive canary report.
     */
    public static function run_scheduled_canary(): array {
        // Ensure baseline is calibrated on first run
        self::ensure_baseline_calibrated();

        // 1. Execute all 5 specialized synthetic probes
        $probes_report = self::execute_probes();

        // 2. Audit Database siteurl & home integrity
        $db_report = self::verify_database_core_urls();

        // Merge findings
        $findings = array_merge($probes_report['findings'], $db_report['findings']);
        $is_hostile = $probes_report['is_hostile'] || $db_report['is_hostile'];
        $max_score  = max($probes_report['max_score'], $db_report['score']);

        $report = [
            'timestamp'       => time(),
            'timestamp_gmt'   => gmdate('Y-m-d H:i:s'),
            'is_hostile'      => $is_hostile,
            'max_score'       => $max_score,
            'severity'        => $is_hostile ? ($max_score >= 80 ? 'critical' : 'high') : 'clean',
            'probes'          => $probes_report['probes'],
            'database_urls'   => $db_report,
            'findings'        => $findings,
            'auto_healed'     => false,
            'auto_heal_info'  => null,
        ];

        // 3. Evaluate Strict 3-Condition Auto-Heal Formula
        $report = self::evaluate_and_auto_heal($report);

        // 4. State-Transition Deduplicated Out-of-Band Alerts
        self::handle_state_transitions($report);

        // 5. Persist last execution report for REST API & UI Cockpit
        update_option(self::LAST_REPORT_OPTION, $report, false);

        return $report;
    }

    /**
     * Execute all 5 specialized synthetic canary probes.
     *
     * @return array Detailed probes report.
     */
    public static function execute_probes(): array {
        $findings   = [];
        $max_score  = 0;
        $is_hostile = false;

        $canonical_hosts = HtaccessShield::get_canonical_hosts();
        $target_home     = home_url('/');
        $admin_target    = admin_url('/');

        // -------------------------------------------------------------
        // Probe A: Baseline Desktop Direct (Clean Room Control)
        // -------------------------------------------------------------
        $probe_a = self::dispatch_probe(
            'probe_a',
            'Baseline Desktop Direct',
            $target_home,
            self::UA_DESKTOP,
            null
        );

        $baseline_scripts = [];
        if (!empty($probe_a['body'])) {
            $probe_a_body = self::inspect_canary_html_body($probe_a['body'], []);
            $baseline_scripts = $probe_a_body['script_hosts'];
            if (!empty($probe_a_body['findings'])) {
                foreach ($probe_a_body['findings'] as $f) {
                    $findings[] = array_merge($f, ['probe' => 'probe_a']);
                    $max_score  = max($max_score, $f['score']);
                    $is_hostile = true;
                }
            }
        }

        if ($probe_a['is_redirect']) {
            $dest_host = $probe_a['redirect_host'];
            if (HtaccessShield::is_external_target($probe_a['redirect_url'], $canonical_hosts)) {
                $score      = 95;
                $max_score  = max($max_score, $score);
                $is_hostile = true;
                $findings[] = [
                    'probe'       => 'probe_a',
                    'type'        => 'direct_external_redirect',
                    'score'       => $score,
                    'severity'    => 'critical',
                    'target_url'  => $probe_a['redirect_url'],
                    'target_host' => $dest_host,
                    'description' => sprintf(
                        /* translators: %s: external destination URL */
                        __('Baseline Probe A: Homepage immediately redirected direct desktop visitors to external host "%s".', 'webcare-pro-security'),
                        $probe_a['redirect_url']
                    ),
                ];
            }
        }

        // -------------------------------------------------------------
        // Probe B: Search Engine Cloaking Trap (Googlebot + Google Referer)
        // -------------------------------------------------------------
        $probe_b = self::dispatch_probe(
            'probe_b',
            'Search Engine Cloaking Trap',
            $target_home,
            self::UA_GOOGLEBOT,
            'https://www.google.com/'
        );

        if ($probe_b['is_redirect'] && HtaccessShield::is_external_target($probe_b['redirect_url'], $canonical_hosts)) {
            $score      = 100;
            $max_score  = max($max_score, $score);
            $is_hostile = true;
            $findings[] = [
                'probe'       => 'probe_b',
                'type'        => 'search_engine_cloaked_redirect',
                'score'       => $score,
                'severity'    => 'critical',
                'target_url'  => $probe_b['redirect_url'],
                'target_host' => $probe_b['redirect_host'],
                'description' => sprintf(
                    /* translators: 1: target URL, 2: referer */
                    __('Search Engine Cloak Detected: Probe B was redirected to "%1$s" when arriving from "%2$s" with Googlebot User-Agent.', 'webcare-pro-security'),
                    $probe_b['redirect_url'],
                    'https://www.google.com/'
                ),
            ];
        } elseif (!empty($probe_b['body'])) {
            $probe_b_body = self::inspect_canary_html_body($probe_b['body'], $baseline_scripts);
            if (!empty($probe_b_body['findings'])) {
                foreach ($probe_b_body['findings'] as $f) {
                    $findings[] = array_merge($f, ['probe' => 'probe_b']);
                    $max_score  = max($max_score, $f['score']);
                    $is_hostile = true;
                }
            }
        }

        // -------------------------------------------------------------
        // Probe C: Mobile Traffic Trap (iPhone Safari + Google Referer)
        // -------------------------------------------------------------
        $probe_c = self::dispatch_probe(
            'probe_c',
            'Mobile Traffic Trap',
            $target_home,
            self::UA_MOBILE_IPHONE,
            'https://www.google.com/'
        );

        if ($probe_c['is_redirect'] && HtaccessShield::is_external_target($probe_c['redirect_url'], $canonical_hosts)) {
            $score      = 100;
            $max_score  = max($max_score, $score);
            $is_hostile = true;
            $findings[] = [
                'probe'       => 'probe_c',
                'type'        => 'mobile_traffic_cloaked_redirect',
                'score'       => $score,
                'severity'    => 'critical',
                'target_url'  => $probe_c['redirect_url'],
                'target_host' => $probe_c['redirect_host'],
                'description' => sprintf(
                    /* translators: 1: target URL, 2: referer */
                    __('Mobile Cloak Detected: Probe C was redirected to "%1$s" for mobile iPhone visitors referred by Google.', 'webcare-pro-security'),
                    $probe_c['redirect_url'],
                    'https://www.google.com/'
                ),
            ];
        } elseif (!empty($probe_c['body'])) {
            $probe_c_body = self::inspect_canary_html_body($probe_c['body'], $baseline_scripts);
            if (!empty($probe_c_body['findings'])) {
                foreach ($probe_c_body['findings'] as $f) {
                    $findings[] = array_merge($f, ['probe' => 'probe_c']);
                    $max_score  = max($max_score, $f['score']);
                    $is_hostile = true;
                }
            }
        }

        // -------------------------------------------------------------
        // Probe D: Admin Gatekeeper (/wp-admin/ Access & Login Hijacking)
        // -------------------------------------------------------------
        $probe_d = self::dispatch_probe(
            'probe_d',
            'Admin Gatekeeper',
            $admin_target,
            self::UA_DESKTOP,
            null
        );

        if ($probe_d['is_redirect']) {
            $target_url = $probe_d['redirect_url'];
            $dest_host  = $probe_d['redirect_host'];

            // Normal WordPress behavior: 302 from /wp-admin/ to wp-login.php on SAME host is 100% CLEAN
            $is_internal_auth = false;
            foreach ($canonical_hosts as $can_host) {
                if ($dest_host === $can_host || str_ends_with($dest_host, '.' . $can_host)) {
                    $is_internal_auth = true;
                    break;
                }
            }

            if (!$is_internal_auth && HtaccessShield::is_external_target($target_url, $canonical_hosts)) {
                $score      = 100;
                $max_score  = max($max_score, $score);
                $is_hostile = true;
                $findings[] = [
                    'probe'       => 'probe_d',
                    'type'        => 'admin_area_hijacked_redirect',
                    'score'       => $score,
                    'severity'    => 'critical',
                    'target_url'  => $target_url,
                    'target_host' => $dest_host,
                    'description' => sprintf(
                        /* translators: %s: external host */
                        __('Critical Admin Hijack: Probe D discovered /wp-admin/ redirects administrators out-of-band to external host "%s".', 'webcare-pro-security'),
                        $dest_host
                    ),
                ];
            }
        }

        // -------------------------------------------------------------
        // Probe E: 2026 AI Search & LLM Citation Cloaking Trap
        // -------------------------------------------------------------
        $probe_e = self::dispatch_probe(
            'probe_e',
            'AI Search Referer Trap',
            $target_home,
            self::UA_AI_SEARCHBOT,
            'https://chatgpt.com/'
        );

        if ($probe_e['is_redirect'] && HtaccessShield::is_external_target($probe_e['redirect_url'], $canonical_hosts)) {
            $score      = 95;
            $max_score  = max($max_score, $score);
            $is_hostile = true;
            $findings[] = [
                'probe'       => 'probe_e',
                'type'        => 'ai_search_cloaked_redirect',
                'score'       => $score,
                'severity'    => 'critical',
                'target_url'  => $probe_e['redirect_url'],
                'target_host' => $probe_e['redirect_host'],
                'description' => sprintf(
                    /* translators: 1: target URL, 2: referer */
                    __('AI Search Cloak Detected: Probe E was redirected to "%1$s" when referred by ChatGPT/Perplexity AI search engines.', 'webcare-pro-security'),
                    $probe_e['redirect_url'],
                    'https://chatgpt.com/'
                ),
            ];
        } elseif (!empty($probe_e['body'])) {
            $probe_e_body = self::inspect_canary_html_body($probe_e['body'], $baseline_scripts);
            if (!empty($probe_e_body['findings'])) {
                foreach ($probe_e_body['findings'] as $f) {
                    $findings[] = array_merge($f, ['probe' => 'probe_e']);
                    $max_score  = max($max_score, $f['score']);
                    $is_hostile = true;
                }
            }
        }

        return [
            'is_hostile' => $is_hostile,
            'max_score'  => $max_score,
            'probes'     => [
                'probe_a' => $probe_a,
                'probe_b' => $probe_b,
                'probe_c' => $probe_c,
                'probe_d' => $probe_d,
                'probe_e' => $probe_e,
            ],
            'findings'   => $findings,
        ];
    }

    /**
     * Dispatch a single HTTP probe request with simulated residential IP and HMAC header.
     *
     * @param string      $id Probe identifier.
     * @param string      $name Human-readable probe title.
     * @param string      $url Target URL.
     * @param string      $user_agent User-Agent string.
     * @param string|null $referer Optional HTTP Referer header.
     * @return array Standardized probe response telemetry.
     */
    private static function dispatch_probe(string $id, string $name, string $url, string $user_agent, ?string $referer): array {
        // Simulated residential public IP pool to bypass 127.0.0.1 / server-IP cloaking gates
        $simulated_ip = '198.51.100.' . wp_rand(11, 240);

        // Internal HMAC verification header so WCP firewall engine recognizes internal probe
        $hmac_sig = hash_hmac('sha256', 'wcp-canary-probe', SecretVault::get_key());

        $headers = [
            'User-Agent'             => $user_agent,
            'X-Forwarded-For'        => $simulated_ip,
            'X-Real-IP'              => $simulated_ip,
            self::HMAC_HEADER        => $hmac_sig,
            'Accept'                 => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language'        => 'en-US,en;q=0.9',
            'Cache-Control'          => 'no-cache',
            'Pragma'                 => 'no-cache',
        ];

        if (!empty($referer)) {
            $headers['Referer'] = $referer;
        }

        $args = [
            'timeout'     => 8,
            'redirection' => 0, // Strict non-following: captures 3xx Location header
            'sslverify'   => false,
            'headers'     => $headers,
        ];

        $start_time = microtime(true);
        $response   = wp_remote_get($url, $args);
        $duration   = round((microtime(true) - $start_time) * 1000, 2);

        if (is_wp_error($response)) {
            return [
                'id'            => $id,
                'name'          => $name,
                'url'           => $url,
                'status_code'   => 0,
                'is_redirect'   => false,
                'redirect_url'  => '',
                'redirect_host' => '',
                'latency_ms'    => $duration,
                'error'         => $response->get_error_message(),
                'body'          => '',
            ];
        }

        $status_code  = (int) wp_remote_retrieve_response_code($response);
        $location_hdr = (string) wp_remote_retrieve_header($response, 'location');
        $body         = (string) wp_remote_retrieve_body($response);

        $is_redirect   = ($status_code >= 300 && $status_code < 400 && !empty($location_hdr));
        $redirect_host = $is_redirect ? (string) wp_parse_url($location_hdr, PHP_URL_HOST) : '';

        return [
            'id'            => $id,
            'name'          => $name,
            'url'           => $url,
            'status_code'   => $status_code,
            'is_redirect'   => $is_redirect,
            'redirect_url'  => $location_hdr,
            'redirect_host' => $redirect_host,
            'latency_ms'    => $duration,
            'error'         => '',
            'body'          => $body,
        ];
    }

    /**
     * Inspect Canary HTML Body for HTTP 200 OK Cloaking & Web3 C2 Signatures.
     *
     * @param string $html Response HTML markup.
     * @param array  $baseline_script_hosts Array of script hosts discovered in Baseline Probe A.
     * @return array Telemetry and any detected security findings.
     */
    public static function inspect_canary_html_body(string $html, array $baseline_script_hosts = []): array {
        $findings     = [];
        $script_hosts = [];
        $canonical    = HtaccessShield::get_canonical_hosts();

        if (trim($html) === '') {
            return [
                'script_hosts' => [],
                'findings'     => [],
            ];
        }

        // 1. Detect <meta http-equiv="refresh" content="...;url=https://external.com">
        if (preg_match('/<meta\s+[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+\s*;\s*url=([^"\'>\s]+)/i', $html, $m_meta)) {
            $dest = $m_meta[1];
            if (HtaccessShield::is_external_target($dest, $canonical)) {
                $target_host = wp_parse_url($dest, PHP_URL_HOST);
                $findings[]  = [
                    'type'        => 'meta_refresh_redirect',
                    'score'       => 95,
                    'severity'    => 'critical',
                    'evidence'    => substr($m_meta[0], 0, 150),
                    'target_url'  => $dest,
                    'target_host' => $target_host,
                    'description' => sprintf(
                        /* translators: %s: destination URL */
                        __('Client-side <meta http-equiv="refresh"> redirect hijacking visitors to external host "%s".', 'webcare-pro-security'),
                        $dest
                    ),
                ];
            }
        }

        // 2. Detect <base href="https://external.com/"> hijacking
        if (preg_match('/<base\s+[^>]*href=["\'](https?:\/\/[^"\'>\s]+)/i', $html, $m_base)) {
            $base_url = $m_base[1];
            if (HtaccessShield::is_external_target($base_url, $canonical)) {
                $target_host = wp_parse_url($base_url, PHP_URL_HOST);
                $findings[]  = [
                    'type'        => 'base_href_hijack',
                    'score'       => 90,
                    'severity'    => 'high',
                    'evidence'    => substr($m_base[0], 0, 120),
                    'target_url'  => $base_url,
                    'target_host' => $target_host,
                    'description' => sprintf(
                        /* translators: %s: external base URL */
                        __('Poisoned <base href> directive redirecting all relative asset and link queries to external host "%s".', 'webcare-pro-security'),
                        $base_url
                    ),
                ];
            }
        }

        // 3. Extract all <script src="..."> tags and track hosts
        if (preg_match_all('/<script\s+[^>]*src=["\']([^"\']+)["\']/i', $html, $m_scripts)) {
            foreach ($m_scripts[1] as $src) {
                $s_host = wp_parse_url($src, PHP_URL_HOST);
                if (!empty($s_host)) {
                    $s_host_low     = strtolower($s_host);
                    $script_hosts[] = $s_host_low;

                    // Differential comparison: If baseline exists and this external script was absent in Probe A
                    if (!empty($baseline_script_hosts) && !in_array($s_host_low, $baseline_script_hosts, true)) {
                        if (HtaccessShield::is_external_target($src, $canonical)) {
                            $findings[] = [
                                'type'        => 'cloaked_script_injection',
                                'score'       => 95,
                                'severity'    => 'critical',
                                'target_url'  => $src,
                                'target_host' => $s_host_low,
                                // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Forensic scanner evidence string representation, not an enqueued script.
                                'evidence'    => '<' . 'script src="' . esc_url($src) . '">',
                                'description' => sprintf(
                                    /* translators: 1: external domain, 2: script URL */
                                    __('Cloaked Script Injection: External script from "%1$s" was delivered exclusively to cloaked probes (%2$s).', 'webcare-pro-security'),
                                    $s_host_low,
                                    substr($src, 0, 100)
                                ),
                            ];
                        }
                    }
                }
            }
        }

        // 4. Scan inline <script> blocks for Web3 C2, ClickFix, and eval/atob patterns
        if (preg_match_all('/<script(?![^>]*src=)[^>]*>(.*?)<\/script>/is', $html, $m_inline)) {
            foreach ($m_inline[1] as $inline_code) {
                // Web3 RPC Resolver
                if (preg_match('/(?:eth_call|bsc-dataseed|polygon-rpc|binance\.org|ankr\.com\/bsc|web3\.eth\.call)/i', $inline_code) &&
                    preg_match('/(?:createElement\s*\(\s*["\']script["\']|document\.write|eval\s*\(|Function\s*\()/i', $inline_code)) {
                    $findings[] = [
                        'type'        => 'web3_smart_contract_c2_loader',
                        'score'       => 100,
                        'severity'    => 'critical',
                        'evidence'    => substr(trim($inline_code), 0, 160),
                        'description' => __('Web3 Blockchain RPC C2 Resolver: Discovered dynamic script loader resolving command & control payloads via public blockchain RPCs.', 'webcare-pro-security'),
                    ];
                }

                // ClickFix / Fake Turnstile Clipboard Hijacking
                if (preg_match('/(?:navigator\.clipboard\.writeText|execCommand\s*\(\s*["\']copy["\'])/i', $inline_code) &&
                    preg_match('/(?:powershell|mshta|Invoke-Expression|iex\s*\(|cmd\.exe|-EncodedCommand|curl\s+https?:)/i', $inline_code)) {
                    $findings[] = [
                        'type'        => 'clickfix_clipboard_hijack',
                        'score'       => 100,
                        'severity'    => 'critical',
                        'evidence'    => substr(trim($inline_code), 0, 160),
                        'description' => __('ClickFix Clipboard Hijacking: Discovered fake verification/Turnstile payload attempting to copy malicious shell execution commands into the visitor clipboard.', 'webcare-pro-security'),
                    ];
                }

                // Rogue Service Worker Registration
                if (preg_match('/navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']/i', $inline_code, $m_sw)) {
                    $sw_path = $m_sw[1];
                    if (HtaccessShield::is_external_target($sw_path, $canonical) || str_contains($sw_path, 'worker.js')) {
                        $findings[] = [
                            'type'        => 'rogue_service_worker_registered',
                            'score'       => 90,
                            'severity'    => 'high',
                            'evidence'    => substr($m_sw[0], 0, 120),
                            'description' => sprintf(
                                /* translators: %s: worker path */
                                __('Suspicious Service Worker Registration: Injected script registers service worker "%s" capable of persistent client-side traffic redirection.', 'webcare-pro-security'),
                                $sw_path
                            ),
                        ];
                    }
                }
            }
        }

        return [
            'script_hosts' => array_values(array_unique($script_hosts)),
            'findings'     => $findings,
        ];
    }

    /**
     * Audit Database siteurl & home integrity directly against encrypted baseline.
     * Bypasses object cache to prevent cache-poisoning blindness.
     *
     * @return array Database core URLs report.
     */
    public static function verify_database_core_urls(): array {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name IN ('siteurl', 'home')"
        );

        $current_siteurl = '';
        $current_home    = '';

        if (!empty($rows)) {
            foreach ($rows as $r) {
                if ($r->option_name === 'siteurl') {
                    $current_siteurl = (string) $r->option_value;
                } elseif ($r->option_name === 'home') {
                    $current_home = (string) $r->option_value;
                }
            }
        }

        $baseline = self::get_baseline_hosts();
        $findings = [];
        $is_hostile = false;

        if (!empty($baseline['home_host'])) {
            $cur_home_host = wp_parse_url($current_home, PHP_URL_HOST);
            if (!empty($cur_home_host) && !self::matches_baseline_host($cur_home_host, $baseline['home_host'])) {
                $is_hostile = true;
                $findings[] = [
                    'type'        => 'database_home_url_hijacking',
                    'score'       => 100,
                    'severity'    => 'critical',
                    'option_name' => 'home',
                    'current_val' => $current_home,
                    'baseline_val'=> $baseline['home_url'],
                    'description' => sprintf(
                        /* translators: 1: current hijacked home url, 2: baseline home url */
                        __('Database Core URL Hijack: The "home" option in wp_options was tampered to point to foreign domain "%1$s" (Baseline: "%2$s").', 'webcare-pro-security'),
                        $current_home,
                        $baseline['home_url']
                    ),
                ];
            }
        }

        if (!empty($baseline['site_host'])) {
            $cur_site_host = wp_parse_url($current_siteurl, PHP_URL_HOST);
            if (!empty($cur_site_host) && !self::matches_baseline_host($cur_site_host, $baseline['site_host'])) {
                $is_hostile = true;
                $findings[] = [
                    'type'        => 'database_siteurl_hijacking',
                    'score'       => 100,
                    'severity'    => 'critical',
                    'option_name' => 'siteurl',
                    'current_val' => $current_siteurl,
                    'baseline_val'=> $baseline['site_url'],
                    'description' => sprintf(
                        /* translators: 1: current hijacked siteurl, 2: baseline siteurl */
                        __('Database Core URL Hijack: The "siteurl" option in wp_options was tampered to point to foreign domain "%1$s" (Baseline: "%2$s").', 'webcare-pro-security'),
                        $current_siteurl,
                        $baseline['site_url']
                    ),
                ];
            }
        }

        return [
            'is_hostile'      => $is_hostile,
            'score'           => $is_hostile ? 100 : 0,
            'current_home'    => $current_home,
            'current_siteurl' => $current_siteurl,
            'baseline'        => $baseline,
            'findings'        => $findings,
        ];
    }

    /**
     * Check if a hostname matches baseline (accounting for www / non-www).
     *
     * @param string $host Current host.
     * @param string $base Baseline host.
     * @return bool True if matching.
     */
    private static function matches_baseline_host(string $host, string $base): bool {
        $h_clean = ltrim(strtolower($host), 'w.');
        $b_clean = ltrim(strtolower($base), 'w.');
        return ($h_clean === $b_clean);
    }

    /**
     * Calibrate and cryptographically sign the canonical baseline host in SecretVault.
     *
     * @return array Baseline metadata.
     */
    public static function calibrate_baseline_hosts(): array {
        $home_url = home_url('/');
        $site_url = site_url('/');

        $baseline = [
            'calibrated_at'     => time(),
            'calibrated_at_gmt' => gmdate('Y-m-d H:i:s'),
            'home_url'          => $home_url,
            'home_host'         => (string) wp_parse_url($home_url, PHP_URL_HOST),
            'site_url'          => $site_url,
            'site_host'         => (string) wp_parse_url($site_url, PHP_URL_HOST),
        ];

        $enc = SecretVault::encrypt((string) wp_json_encode($baseline));
        update_option(self::BASELINE_OPTION, $enc, false);

        return $baseline;
    }

    /**
     * Ensure baseline exists; if not, initialize calibration.
     *
     * @return void
     */
    private static function ensure_baseline_calibrated(): void {
        $existing = get_option(self::BASELINE_OPTION, '');
        if (empty($existing)) {
            self::calibrate_baseline_hosts();
        }
    }

    /**
     * Retrieve decrypted baseline hosts from SecretVault.
     *
     * @return array
     */
    public static function get_baseline_hosts(): array {
        $raw = get_option(self::BASELINE_OPTION, '');
        if (empty($raw) || !is_string($raw)) {
            return [];
        }

        $dec = SecretVault::decrypt($raw);
        if (empty($dec)) {
            return [];
        }

        $data = json_decode($dec, true);
        return is_array($data) ? $data : [];
    }

    /**
     * 1-Click Database Core URL Restoration: Restores siteurl and home back to baseline.
     *
     * @return array Result array.
     */
    public static function restore_database_core_urls(): array {
        $baseline = self::get_baseline_hosts();
        if (empty($baseline['home_url']) || empty($baseline['site_url'])) {
            return [
                'success' => false,
                'message' => __('No verified cryptographic baseline exists to restore core URLs.', 'webcare-pro-security'),
            ];
        }

        global $wpdb;

        // Direct DB update to bypass poisoned in-memory filters
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($wpdb->options, ['option_value' => $baseline['home_url']], ['option_name' => 'home']);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($wpdb->options, ['option_value' => $baseline['site_url']], ['option_name' => 'siteurl']);

        // Invalidate WordPress options caches
        wp_cache_delete('home', 'options');
        wp_cache_delete('siteurl', 'options');
        wp_cache_delete('alloptions', 'options');

        if (class_exists('\\WebCareProScanner\\System\\WcpActivityLogger')) {
            WcpActivityLogger::log('database_core_urls_healed', 'database', 'critical', [
                'restored_home'    => $baseline['home_url'],
                'restored_siteurl' => $baseline['site_url'],
            ]);
        }

        return [
            'success'          => true,
            'message'          => __('Database "siteurl" and "home" options successfully restored from signed baseline.', 'webcare-pro-security'),
            'restored_home'    => $baseline['home_url'],
            'restored_siteurl' => $baseline['site_url'],
        ];
    }

    /**
     * Evaluate and execute the Strict 3-Condition Auto-Heal Formula.
     *
     * @param array $report Active canary execution report.
     * @return array Enriched report.
     */
    public static function evaluate_and_auto_heal(array $report): array {
        if (!$report['is_hostile']) {
            return $report;
        }

        // Condition 1: Canary probe confirmed hostile redirect / cloaking (already verified true)

        // Read current .htaccess content
        $htaccess_path = ABSPATH . '.htaccess';
        $ht_content    = file_exists($htaccess_path) ? (string) @file_get_contents($htaccess_path) : '';
        $ht_analysis   = HtaccessShield::analyze_htaccess_content($ht_content);

        // Condition 2: Live .htaccess contains matching hostile pattern
        $ht_is_hostile = $ht_analysis['is_hostile'];

        // Condition 3: Outside 5-minute flush grace window
        $is_in_grace_window = HtaccessShield::is_within_flush_grace_window();

        // Check if auto-heal is enabled (enabled by default)
        $auto_heal_enabled = (bool) get_option(self::AUTO_HEAL_OPTION, true);

        // Auto-heal condition evaluation
        if ($auto_heal_enabled && $ht_is_hostile && !$is_in_grace_window) {
            // Restore from Vault Snapshot #1
            $restore_res = HtaccessVaultManager::restore_snapshot(1);
            if ($restore_res['success']) {
                $report['auto_healed']    = true;
                $report['auto_heal_info'] = [
                    'status'    => 'success',
                    'action'    => 'restored_from_vault_snapshot_1',
                    'sha256'    => $restore_res['sha256'] ?? '',
                    'timestamp' => time(),
                ];
            } else {
                $report['auto_heal_info'] = [
                    'status'  => 'failed',
                    'message' => $restore_res['message'],
                ];
            }
        } elseif (!$ht_is_hostile) {
            // Canary is hostile but .htaccess is clean! DO NOT touch .htaccess.
            // Attributed to Nginx / server block, database URL tampering, or runtime drop-in.
            $report['auto_heal_info'] = [
                'status'      => 'skipped_clean_htaccess',
                'reason'      => 'Canary detected redirect but .htaccess is verified clean. Pointing remediation to database/Nginx/hooks.',
                'attribution' => !empty($report['database_urls']['is_hostile']) ? 'database_url_hijacking' : 'server_nginx_or_dropin',
            ];
        } elseif ($is_in_grace_window) {
            $report['auto_heal_info'] = [
                'status' => 'held_in_grace_window',
                'reason' => 'Legitimate plugin flush grace window is currently active (within 5 minutes).',
            ];
        }

        return $report;
    }

    /**
     * Handle state-transition deduplicated alert dispatch.
     * Fires alerts ONLY when transitioning clean -> hostile or hostile -> clean.
     *
     * @param array $report Active report.
     * @return void
     */
    private static function handle_state_transitions(array $report): array {
        $state = get_option(self::STATE_OPTION, [
            'status'          => 'clean',
            'last_transition' => time(),
            'last_target'     => '',
        ]);

        $prev_status = $state['status'] ?? 'clean';
        $new_status  = $report['is_hostile'] ? 'hostile' : 'clean';

        $first_finding = !empty($report['findings'][0]) ? $report['findings'][0] : [];
        $target_url    = $first_finding['target_url'] ?? '';
        $desc          = $first_finding['description'] ?? 'Zero-day redirect hack detected by canary probe.';

        // Transition 1: Clean -> Hostile (NEW ATTACK DETECTED)
        if ($prev_status === 'clean' && $new_status === 'hostile') {
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                NotificationDispatcher::trigger('redirect_hack_detected', [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        /* translators: %s: incident description */
                        __('Redirect Hack Detected by WCP Synthetic Canary: %s', 'webcare-pro-security'),
                        $desc
                    ),
                    'details'  => [
                        'Threat Type'     => $first_finding['type'] ?? 'redirect_hijack',
                        'Target Host'     => $first_finding['target_host'] ?? 'External',
                        'Target URL'      => substr($target_url, 0, 120),
                        'Auto-Heal State' => !empty($report['auto_healed']) ? 'Auto-Restored from Vault #1' : 'Awaiting Administrator Action',
                        'Triggered Probe' => strtoupper($first_finding['probe'] ?? 'SYSTEM'),
                    ],
                ]);
            }

            $state['status']          = 'hostile';
            $state['last_transition' ]= time();
            $state['last_target']     = $target_url;
            update_option(self::STATE_OPTION, $state, false);
            return $state;
        }

        // Transition 2: Hostile -> Clean (ATTACK REMEDIATED & RECOVERED)
        if ($prev_status === 'hostile' && $new_status === 'clean') {
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                NotificationDispatcher::trigger('redirect_hack_auto_healed', [
                    'severity' => 'info',
                    'message'  => __('Redirect Incident Recovered: All 5 synthetic canary probes and core database URLs have verified normal clean status.', 'webcare-pro-security'),
                    'details'  => [
                        'Recovery Status' => 'All Probes Clean (HTTP 200 / Legitimate Canonical)',
                        'Remediated At'   => gmdate('Y-m-d H:i:s') . ' UTC',
                    ],
                ]);
            }

            $state['status']          = 'clean';
            $state['last_transition'] = time();
            $state['last_target']     = '';
            update_option(self::STATE_OPTION, $state, false);
            return $state;
        }

        // In-State Update: Hostile -> Hostile with a new target destination
        if ($prev_status === 'hostile' && $new_status === 'hostile') {
            if (!empty($target_url) && $target_url !== ($state['last_target'] ?? '')) {
                $state['last_target'] = $target_url;
                update_option(self::STATE_OPTION, $state, false);
            }
        }

        return $state;
    }
}
