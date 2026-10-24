<?php
namespace WcpScanner\WordPress;

use WcpScanner\Findings\Finding;
use WcpScanner\Malware\HeuristicEngine;
use WcpScanner\Filesystem\PathValidator;
use WcpScanner\Remediation\RemediationManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PersistenceScanner
 *
 * Comprehensive Self-Healing & Multi-Persistence Malware Hunter for WordPress:
 * 1. Must-Use Plugins (mu-plugins) AST Token Analysis & Stealth Loaders
 * 2. Standard & Rogue PHP Drop-Ins in wp-content/ (db.php, object-cache.php, etc.)
 * 3. Database Autoloaded Malicious Payloads, Transients & EtherHiding Anchors
 * 4. Orphan & Rogue Scheduled wp-cron Tasks
 * 5. Resurrection Sentinel: Detects when remediated files are re-created by hidden loops
 * 6. 1-Click Surgical Neutralization & Safety Rollback Vault
 */
class PersistenceScanner {

    private $heuristic_engine;

    // Standard recognized WordPress drop-in files
    private $recognized_dropins = [
        'advanced-cache.php'   => 'Advanced caching engine',
        'object-cache.php'     => 'External object cache',
        'db.php'               => 'Custom database class',
        'db-error.php'         => 'Custom database error template',
        'sunrise.php'          => 'Multisite domain mapping',
        'blog-deleted.php'     => 'Custom blog deleted template',
        'blog-inactive.php'    => 'Custom blog inactive template',
        'blog-suspended.php'   => 'Custom blog suspended template',
        'maintenance.php'      => 'Custom maintenance page',
        'php-error.php'        => 'Custom PHP error template',
        'fatal-error-handler.php' => 'Fatal error handler',
        'index.php'            => 'Directory browsing placeholder',
    ];

    public function __construct() {
        $this->heuristic_engine = new HeuristicEngine();
    }

    /**
     * Calculate Shannon Entropy on a string to identify encrypted/obfuscated binary payloads.
     *
     * @param string $string
     * @return float
     */
    public static function calculate_shannon_entropy(string $string): float {
        $len = strlen($string);
        if ($len === 0) {
            return 0.0;
        }
        $freq = count_chars($string, 1);
        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    /**
     * Inspect persistence locations during standard background/manual scans.
     * Returns standard Finding objects for the scanner findings table.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];
        $audit = $this->audit_full();

        // 1. Convert MU-Plugin issues to Findings
        foreach ($audit['mu_plugins'] as $mu) {
            if ($mu['status'] === 'malicious') {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-persistence',
                    'type'        => 'malicious_mu_plugin',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => $mu['path'],
                    /* translators: 1: filename, 2: threat summary */
                    'description' => sprintf(
                        __('Malicious Must-Use (MU) plugin detected: %1$s. %2$s', 'wcp-security-scanner'),
                        $mu['filename'],
                        $mu['threat_summary']
                    ),
                    'evidence'    => $mu['evidence'] ?? ('File: ' . $mu['filename']),
                    'code_snippet'=> $mu['snippet'] ?? null,
                ]);
            } elseif ($mu['status'] === 'warning') {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-persistence',
                    'type'        => 'mu_plugin_warning',
                    'severity'    => 'medium',
                    'confidence'  => 85,
                    'file_path'   => $mu['path'],
                    /* translators: %s: filename */
                    'description' => sprintf(
                        __('Must-Use plugin "%s" contains suspicious code or hidden includes.', 'wcp-security-scanner'),
                        $mu['filename']
                    ),
                    'evidence'    => $mu['threat_summary'],
                ]);
            }
        }

        // 2. Convert Drop-In issues to Findings
        foreach ($audit['dropins'] as $drop) {
            if ($drop['is_unexpected']) {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-persistence',
                    'type'        => 'unexpected_wp_content_file',
                    'severity'    => 'high',
                    'confidence'  => 90,
                    'file_path'   => $drop['path'],
                    /* translators: %s: filename */
                    'description' => sprintf(
                        __('Unexpected PHP file directly in wp-content/ root: "%s". Common webshell or malware drop location.', 'wcp-security-scanner'),
                        $drop['filename']
                    ),
                    'evidence'    => 'File: ' . $drop['filename'],
                ]);
            } elseif ($drop['status'] === 'malicious') {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-persistence',
                    'type'        => 'malicious_dropin',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => $drop['path'],
                    /* translators: 1: filename, 2: threat summary */
                    'description' => sprintf(
                        __('Malicious PHP drop-in detected: %1$s. %2$s', 'wcp-security-scanner'),
                        $drop['filename'],
                        $drop['threat_summary']
                    ),
                    'evidence'    => $drop['evidence'] ?? ('Drop-in: ' . $drop['filename']),
                    'code_snippet'=> $drop['snippet'] ?? null,
                ]);
            } elseif ($drop['status'] === 'unauthorized') {
                $findings[] = new Finding([
                    'engine'      => 'wordpress-persistence',
                    'type'        => 'unauthorized_dropin',
                    'severity'    => 'medium',
                    'confidence'  => 85,
                    'file_path'   => $drop['path'],
                    /* translators: %s: filename */
                    'description' => sprintf(
                        __('Drop-in file "%s" is active, but no matching caching/database plugin was detected in active plugins.', 'wcp-security-scanner'),
                        $drop['filename']
                    ),
                    'evidence'    => 'Drop-in: ' . $drop['filename'],
                ]);
            }
        }

        // 3. Convert Autoload & Transient Database Anchors to Findings
        foreach ($audit['autoload_options'] as $opt) {
            $findings[] = new Finding([
                'engine'      => 'database-persistence',
                'type'        => 'db_autoload_malware_anchor',
                'severity'    => $opt['severity'] ?? 'critical',
                'confidence'  => 95,
                'file_path'   => 'wp_options:' . $opt['option_name'],
                /* translators: 1: option name, 2: reason */
                'description' => sprintf(
                    __('Database persistence anchor in autoloaded option "%1$s": %2$s', 'wcp-security-scanner'),
                    $opt['option_name'],
                    $opt['reason']
                ),
                'evidence'    => 'Option: ' . $opt['option_name'] . ' (Size: ' . $opt['size_formatted'] . ')',
                'code_snippet'=> $opt['snippet'] ?? null,
            ]);
        }

        // 4. Convert Rogue Cron Tasks to Findings
        foreach ($audit['cron_tasks'] as $cron) {
            if ($cron['severity'] === 'critical' || $cron['severity'] === 'high') {
                $findings[] = new Finding([
                    'engine'      => 'system-cron',
                    'type'        => 'malicious_cron_hook',
                    'severity'    => $cron['severity'],
                    'confidence'  => 90,
                    'file_path'   => 'cron:hook:' . $cron['hook'],
                    /* translators: 1: cron hook name, 2: reason */
                    'description' => sprintf(
                        __('Suspicious scheduled cron task "%1$s": %2$s', 'wcp-security-scanner'),
                        $cron['hook'],
                        $cron['reason']
                    ),
                    'evidence'    => 'Hook: ' . $cron['hook'] . ' | Next run: ' . $cron['next_run_human'],
                ]);
            }
        }

        // 5. Convert Resurrection / Self-Healing Loops to Findings
        foreach ($audit['resurrections'] as $res) {
            $findings[] = new Finding([
                'engine'      => 'self-healing-loop',
                'type'        => 'self_healing_malware_resurrection',
                'severity'    => 'critical',
                'confidence'  => 99,
                'file_path'   => $res['file_path'],
                /* translators: 1: original action, 2: timeline */
                'description' => sprintf(
                    __('Self-Healing Malware Loop Detected! File was previously neutralized via WCP (%1$s), but was resurrected/re-injected %2$s.', 'wcp-security-scanner'),
                    $res['original_action'],
                    $res['timeline_human']
                ),
                'evidence'    => sprintf(
                    'Neutralized: %s | Re-infected: %s (%s later)',
                    $res['remediated_at'],
                    $res['current_mtime_human'],
                    $res['diff_human']
                ),
            ]);
        }

        return $findings;
    }

    /**
     * Deep Audit of all 4 Persistence Vectors.
     * Returns a rich, structured payload for live dashboard cards, forensic inspection, and 1-click remediation.
     *
     * @return array
     */
    public function audit_full(): array {
        $mu_plugins = $this->audit_mu_plugins();
        $dropins = $this->audit_dropins();
        $autoload_options = $this->audit_database_autoload();
        $cron_tasks = $this->audit_cron_tasks();
        $resurrections = $this->audit_resurrections();

        $insecure_mu = 0;
        foreach ($mu_plugins as $m) {
            if ($m['status'] === 'malicious' || $m['status'] === 'warning') {
                $insecure_mu++;
            }
        }

        $insecure_dropins = 0;
        foreach ($dropins as $d) {
            if ($d['status'] === 'malicious' || $d['status'] === 'unauthorized' || $d['is_unexpected']) {
                $insecure_dropins++;
            }
        }

        $insecure_crons = 0;
        foreach ($cron_tasks as $c) {
            if ($c['severity'] === 'critical' || $c['severity'] === 'high') {
                $insecure_crons++;
            }
        }

        $total_threats = $insecure_mu + $insecure_dropins + count($autoload_options) + $insecure_crons + count($resurrections);

        return [
            'success'                 => true,
            'is_healthy'              => ($total_threats === 0),
            'total_threats'           => $total_threats,
            'kpis' => [
                'mu_plugins_count'    => count($mu_plugins),
                'mu_threats_count'    => $insecure_mu,
                'dropins_count'       => count($dropins),
                'dropin_threats_count'=> $insecure_dropins,
                'autoload_threats'    => count($autoload_options),
                'cron_threats_count'  => $insecure_crons,
                'resurrections_count' => count($resurrections),
            ],
            'mu_plugins'              => $mu_plugins,
            'dropins'                 => $dropins,
            'autoload_options'        => $autoload_options,
            'cron_tasks'              => $cron_tasks,
            'resurrections'           => $resurrections,
        ];
    }

    /**
     * Vector 1: Audit Must-Use Plugins (mu-plugins)
     */
    private function audit_mu_plugins(): array {
        $results = [];
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        if (!is_dir($mu_dir)) {
            return $results;
        }

        $files = glob($mu_dir . '/*.php') ?: [];
        foreach ($files as $file) {
            $filename = basename($file);
            $content = @file_get_contents($file) ?: '';
            $fsize = @filesize($file) ?: 0;
            $mtime = @filemtime($file) ?: 0;

            $status = 'clean';
            $threat_summary = '';
            $evidence = '';
            $snippet = '';

            // Run AST token analysis
            $ast = $this->analyze_php_tokens($content);
            if ($ast['is_malicious']) {
                $status = 'malicious';
                $threat_summary = $ast['reason'];
                $snippet = $ast['snippet'];
                $evidence = $ast['evidence'];
            } elseif ($ast['is_suspicious']) {
                $status = 'warning';
                $threat_summary = $ast['reason'];
                $snippet = $ast['snippet'];
                $evidence = $ast['evidence'];
            } else {
                // Run heuristic detector as second pass
                $heuristics = $this->heuristic_engine->scan_file($file, 'audit_' . time());
                if (!empty($heuristics)) {
                    $first = reset($heuristics);
                    $status = 'malicious';
                    $threat_summary = $first->description;
                    $snippet = $first->code_snippet;
                    $evidence = $first->evidence;
                }
            }

            $results[] = [
                'filename'       => $filename,
                'path'           => wp_normalize_path($file),
                'relative_path'  => 'wp-content/mu-plugins/' . $filename,
                'size'           => $fsize,
                'size_formatted' => size_format($fsize),
                'mtime'          => $mtime,
                'modified_human' => human_time_diff($mtime, time()) . ' ago',
                'status'         => $status,
                'threat_summary' => $threat_summary ?: __('Legitimate Must-Use plugin.', 'wcp-security-scanner'),
                'snippet'        => $snippet,
                'evidence'       => $evidence,
            ];
        }

        return $results;
    }

    /**
     * Vector 2: Audit Drop-Ins & wp-content Loose Files
     */
    private function audit_dropins(): array {
        $results = [];
        $wp_content_files = glob(WP_CONTENT_DIR . '/*.php') ?: [];

        // Check active caching & db plugins to verify legitimate drop-in ownership
        $active_plugins = (array) get_option('active_plugins', []);
        $active_plugins_str = strtolower(implode(' ', $active_plugins));

        $has_caching_plugin = (
            strpos($active_plugins_str, 'redis') !== false ||
            strpos($active_plugins_str, 'memcached') !== false ||
            strpos($active_plugins_str, 'litespeed') !== false ||
            strpos($active_plugins_str, 'w3-total-cache') !== false ||
            strpos($active_plugins_str, 'wp-super-cache') !== false ||
            strpos($active_plugins_str, 'wp-rocket') !== false
        );

        $has_db_plugin = (
            strpos($active_plugins_str, 'query-monitor') !== false ||
            strpos($active_plugins_str, 'ludicrousdb') !== false ||
            strpos($active_plugins_str, 'hyperdb') !== false
        );

        foreach ($wp_content_files as $file) {
            $filename = basename($file);
            $content = @file_get_contents($file) ?: '';
            $fsize = @filesize($file) ?: 0;
            $mtime = @filemtime($file) ?: 0;

            $is_recognized = isset($this->recognized_dropins[$filename]);
            $is_unexpected = !$is_recognized;
            $status = 'clean';
            $threat_summary = '';
            $snippet = '';
            $evidence = '';

            if ($is_unexpected) {
                $status = 'malicious';
                $threat_summary = __('Unexpected PHP file located in wp-content root. High probability of webshell drop.', 'wcp-security-scanner');
            }

            // AST Token Check
            $ast = $this->analyze_php_tokens($content);
            if ($ast['is_malicious']) {
                $status = 'malicious';
                $threat_summary = $ast['reason'];
                $snippet = $ast['snippet'];
                $evidence = $ast['evidence'];
            } elseif ($ast['is_suspicious'] && $status !== 'malicious') {
                $status = 'warning';
                $threat_summary = $ast['reason'];
                $snippet = $ast['snippet'];
                $evidence = $ast['evidence'];
            }

            // Verify legitimate plugin backing
            if ($status === 'clean') {
                if ($filename === 'object-cache.php' && !$has_caching_plugin) {
                    $status = 'unauthorized';
                    $threat_summary = __('object-cache.php is present, but no active Redis, Memcached, or Object Cache plugin is enabled.', 'wcp-security-scanner');
                } elseif ($filename === 'db.php' && !$has_db_plugin) {
                    $status = 'unauthorized';
                    $threat_summary = __('db.php drop-in is present, but Query Monitor, LudicrousDB, or HyperDB are not enabled in active plugins.', 'wcp-security-scanner');
                } elseif ($filename === 'advanced-cache.php' && !defined('WP_CACHE') && !$has_caching_plugin) {
                    $status = 'unauthorized';
                    $threat_summary = __('advanced-cache.php is present, but WP_CACHE is not enabled in wp-config.php and no caching plugin is active.', 'wcp-security-scanner');
                }
            }

            $results[] = [
                'filename'       => $filename,
                'path'           => wp_normalize_path($file),
                'relative_path'  => 'wp-content/' . $filename,
                'purpose'        => $this->recognized_dropins[$filename] ?? __('Unrecognized loose file', 'wcp-security-scanner'),
                'is_unexpected'  => $is_unexpected,
                'size'           => $fsize,
                'size_formatted' => size_format($fsize),
                'mtime'          => $mtime,
                'modified_human' => human_time_diff($mtime, time()) . ' ago',
                'status'         => $status,
                'threat_summary' => $threat_summary ?: __('Standard WordPress Drop-in.', 'wcp-security-scanner'),
                'snippet'        => $snippet,
                'evidence'       => $evidence,
            ];
        }

        return $results;
    }

    /**
     * Vector 3: Audit Database Autoload & Transient Persistence Anchors
     */
    private function audit_database_autoload(): array {
        global $wpdb;
        $flagged = [];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            "SELECT option_id, option_name, option_value FROM {$wpdb->options} 
             WHERE autoload IN ('yes', 'on', 'true') 
                OR option_name LIKE '_transient_%' 
                OR option_name LIKE '_site_transient_%'
             ORDER BY option_id DESC 
             LIMIT 400",
            ARRAY_A
        ) ?: [];

        foreach ($rows as $row) {
            $name = $row['option_name'];
            $val = $row['option_value'];
            if (empty($val) || !is_string($val)) {
                continue;
            }

            // Skip WCP's own internal analysis, FIM diffs, and security caches
            if (strpos($name, 'wcp_') !== false || strpos($name, 'wcpscan_') !== false) {
                continue;
            }

            $len = strlen($val);
            if ($len < 20) {
                continue;
            }

            $reason = '';
            $severity = 'critical';
            $snippet = '';

            // 1. Direct PHP executable tags inside database option
            if (preg_match('/<\?(php|=|xml)/i', $val)) {
                $reason = __('Embedded PHP executable tag found inside database option value.', 'wcp-security-scanner');
                $snippet = substr($val, 0, 160);
            }
            // 2. Evaluators inside option string
            elseif (preg_match('/(@?eval\s*\(|@?assert\s*\(|@?create_function\s*\(|@?passthru\s*\(|@?system\s*\()/i', $val)) {
                $reason = __('Direct dynamic evaluator execution construct detected in option value.', 'wcp-security-scanner');
                $snippet = substr($val, 0, 160);
            }
            // 3. EtherHiding / Balada Web3 IPFS C2 injection patterns
            elseif (preg_match('/(eth\.limo|ipfs\.io|cloudflare-ipfs\.com|rentry\.co|pastebin\.com\/raw\/|bsc-dataseed)/i', $val)) {
                $reason = __('EtherHiding or decentralized Web3/IPFS C2 payload URL detected in database option.', 'wcp-security-scanner');
                $snippet = substr($val, 0, 160);
            }
            // 4. Obfuscated Base64 script injection in options
            elseif (preg_match('/<script[^>]*>[\s\S]*?(eval\s*\(|atob\s*\(|String\.fromCharCode)[\s\S]*?<\/script>/i', $val)) {
                $reason = __('Obfuscated client-side JavaScript execution payload stored in database option.', 'wcp-security-scanner');
                $snippet = substr($val, 0, 160);
            }
            // 5. High-Entropy Base64 / Hex blob check on large string fields
            elseif ($len > 180 && !is_serialized($val)) {
                // Check if continuous block of alphanumeric characters has high entropy
                if (preg_match('/[a-zA-Z0-9\/+=]{150,}/', $val, $matches)) {
                    $entropy = self::calculate_shannon_entropy($matches[0]);
                    if ($entropy > 5.3) {
                        $decoded = @base64_decode($matches[0], true);
                        if ($decoded && (strpos($decoded, '<?php') !== false || strpos($decoded, 'eval') !== false || strpos($decoded, 'curl') !== false)) {
                            /* translators: %.2f: entropy score */
                            $reason = sprintf(__('High-entropy base64 blob (Entropy: %.2f) decoding to executable PHP/C2 instructions.', 'wcp-security-scanner'), $entropy);
                            $snippet = substr($matches[0], 0, 120) . '...';
                        }
                    }
                }
            }

            if (!empty($reason)) {
                $flagged[] = [
                    'option_id'      => (int) $row['option_id'],
                    'option_name'    => $name,
                    'size'           => $len,
                    'size_formatted' => size_format($len),
                    'severity'       => $severity,
                    'reason'         => $reason,
                    'snippet'        => $snippet,
                ];
            }
        }

        return $flagged;
    }

    /**
     * Vector 4: Audit Scheduled wp-cron Tasks
     */
    private function audit_cron_tasks(): array {
        $flagged = [];
        $cron_array = _get_cron_array();
        if (empty($cron_array) || !is_array($cron_array)) {
            return $flagged;
        }

        global $wp_filter;

        $core_safe_hooks = [
            'wp_version_check',
            'wp_update_plugins',
            'wp_update_themes',
            'recovery_mode_clean_expired_keys',
            'wp_scheduled_delete',
            'delete_expired_transients',
            'wp_privacy_delete_old_export_files',
            'wp_https_detection',
            'wp_site_health_scheduled_check',
            'wcpscan_scheduled_scan_event',
        ];

        $now = time();

        foreach ($cron_array as $timestamp => $hooks) {
            if (!is_array($hooks)) {
                continue;
            }

            foreach ($hooks as $hook => $schedules) {
                if (in_array($hook, $core_safe_hooks, true)) {
                    continue;
                }

                $has_callback = isset($wp_filter[$hook]);
                $severity = 'info';
                $reason = '';

                // 1. Orphan cron hook: Scheduled to run repeatedly, but callback function no longer exists
                if (!$has_callback) {
                    // Check if hook name looks generated or suspicious (hex hash or random chars)
                    if (preg_match('/^[a-f0-9]{16,64}$/i', $hook) || preg_match('/(temp|cache_check|update_sys|wpc_[0-9a-f]{6,})/i', $hook)) {
                        $severity = 'high';
                        $reason = __('Orphaned cron hook with suspicious generated name and no active callback function in WordPress.', 'wcp-security-scanner');
                    }
                } else {
                    // 2. Hook exists - inspect callback functions for rogue closures or file locations
                    $callbacks = $wp_filter[$hook]->callbacks ?? [];
                    foreach ($callbacks as $priority => $handlers) {
                        foreach ($handlers as $id => $handler) {
                            $func = $handler['function'] ?? null;
                            if ($func instanceof \Closure) {
                                try {
                                    $ref = new \ReflectionFunction($func);
                                    $file = wp_normalize_path($ref->getFileName() ?: '');
                                    if (strpos($file, '/wp-content/uploads/') !== false || strpos($file, '/tmp/') !== false) {
                                        $severity = 'critical';
                                        /* translators: %s: file basename */
                                        $reason = sprintf(__('Cron hook executes an anonymous Closure defined inside uploads or temp directory: %s', 'wcp-security-scanner'), basename($file));
                                    }
                                } catch (\Throwable $e) {
                                    // pass
                                }
                            }
                        }
                    }
                }

                if (!empty($reason)) {
                    $next_run_sec = max(0, $timestamp - $now);
                    $flagged[] = [
                        'hook'            => $hook,
                        'timestamp'       => $timestamp,
                        'next_run_human'  => human_time_diff($now, $timestamp) . ($timestamp > $now ? ' from now' : ' ago'),
                        'has_callback'    => $has_callback,
                        'severity'        => $severity,
                        'reason'          => $reason,
                    ];
                }
            }
        }

        return $flagged;
    }

    /**
     * Vector 5: Audit Resurrection Sentinel (Self-Healing Loop Tracker)
     */
    private function audit_resurrections(): array {
        $resurrections = [];
        $backups = get_option('wcpscan_remediation_backups', []);
        if (empty($backups) || !is_array($backups)) {
            return $resurrections;
        }

        $now = time();

        foreach ($backups as $id => $record) {
            $orig_path = $record['original_path'] ?? '';
            $created_at = $record['created_at'] ?? '';
            $action_type = $record['action_type'] ?? '';

            if (empty($orig_path) || empty($created_at)) {
                continue;
            }

            $created_time = strtotime($created_at);
            if (!$created_time || ($now - $created_time) > (14 * DAY_IN_SECONDS)) {
                // Monitor for 14 days after remediation
                continue;
            }

            if (file_exists($orig_path)) {
                $mtime = @filemtime($orig_path);

                // If file was stripped or restored, but was edited again AFTER remediation timestamp
                if ($mtime && $mtime > ($created_time + 10)) {
                    $content = @file_get_contents($orig_path) ?: '';
                    $ast = $this->analyze_php_tokens($content);

                    if ($ast['is_malicious'] || $ast['is_suspicious']) {
                        $diff = $mtime - $created_time;
                        $resurrections[] = [
                            'backup_id'            => $id,
                            'file_path'            => wp_normalize_path($orig_path),
                            'filename'             => basename($orig_path),
                            'original_action'      => $action_type,
                            'remediated_at'        => $created_at,
                            'current_mtime'        => $mtime,
                            'current_mtime_human'  => gmdate('Y-m-d H:i:s', $mtime) . ' UTC',
                            'timeline_human'       => human_time_diff($created_time, $mtime) . ' after cleanup',
                            'diff_human'           => human_time_diff($created_time, $mtime),
                            'threat_reason'        => $ast['reason'],
                        ];
                    }
                }
            }
        }

        return $resurrections;
    }

    /**
     * Parse PHP tokens to detect malicious constructs, stealth include wrappers, and backdoors.
     *
     * @param string $content
     * @return array
     */
    private function analyze_php_tokens(string $content): array {
        $result = [
            'is_malicious'  => false,
            'is_suspicious' => false,
            'reason'        => '',
            'snippet'       => '',
            'evidence'      => '',
        ];

        if (empty($content) || !function_exists('token_get_all')) {
            return $result;
        }

        try {
            $tokens = @token_get_all($content);
        } catch (\ParseError $e) {
            return $result;
        }

        $dangerous_funcs = ['eval', 'assert', 'passthru', 'system', 'exec', 'shell_exec', 'proc_open', 'popen'];
        $obfuscation_funcs = ['base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'convert_uudecode'];

        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $tok = $tokens[$i];

            if (is_array($tok)) {
                $type = $tok[0];
                $str = strtolower($tok[1]);

                // 1. eval / assert execution
                if ($type === T_EVAL || ($type === T_STRING && in_array($str, $dangerous_funcs, true))) {
                    // Check next non-whitespace tokens to see what is evaluated
                    $next_code = '';
                    for ($j = $i + 1; $j < min($count, $i + 15); $j++) {
                        $ntok = $tokens[$j];
                        $next_code .= is_array($ntok) ? $ntok[1] : $ntok;
                    }

                    if (preg_match('/(base64_decode|gzinflate|gzuncompress|\$_POST|\$_GET|\$_REQUEST|\$GLOBALS)/i', $next_code)) {
                        $result['is_malicious'] = true;
                        /* translators: %s: function name */
                        $result['reason'] = sprintf(__('Critical Backdoor: %s executing dynamic encoded payload.', 'wcp-security-scanner'), strtoupper($str));
                        $result['snippet'] = substr($tok[1] . $next_code, 0, 140);
                        $result['evidence'] = "Construct: {$tok[1]}";
                        return $result;
                    }

                    $result['is_suspicious'] = true;
                    /* translators: %s: function name */
                    $result['reason'] = sprintf(__('Suspicious dynamic function call: %s()', 'wcp-security-scanner'), $tok[1]);
                    $result['snippet'] = substr($tok[1] . $next_code, 0, 100);
                }

                // 2. Stealth include/require pointing to uploads, cache, or temp
                if ($type === T_INCLUDE || $type === T_INCLUDE_ONCE || $type === T_REQUIRE || $type === T_REQUIRE_ONCE) {
                    $next_code = '';
                    for ($j = $i + 1; $j < min($count, $i + 25); $j++) {
                        $ntok = $tokens[$j];
                        $next_code .= is_array($ntok) ? $ntok[1] : $ntok;
                    }

                    if (preg_match('/(uploads|cache|tmp|\.ico|\.png|\.jpg|\.txt|\.css|\.woff)/i', $next_code)) {
                        $result['is_malicious'] = true;
                        $result['reason'] = __('Stealth Loader: Drop-in or MU-plugin includes a hidden payload from uploads, cache, or disguised image file.', 'wcp-security-scanner');
                        $result['snippet'] = substr($tok[1] . ' ' . $next_code, 0, 140);
                        $result['evidence'] = "Stealth include: {$next_code}";
                        return $result;
                    }
                }

                // 3. EtherHiding / Web3 Decentralized C2 pattern
                if ($type === T_CONSTANT_ENCAPSED_STRING) {
                    if (preg_match('/(eth\.limo|ipfs\.io|cloudflare-ipfs\.com|rentry\.co|pastebin\.com\/raw\/|bsc-dataseed)/i', $tok[1])) {
                        $result['is_malicious'] = true;
                        $result['reason'] = __('EtherHiding / Decentralized Web3 C2 endpoint detected in string literal.', 'wcp-security-scanner');
                        $result['snippet'] = substr($tok[1], 0, 120);
                        $result['evidence'] = "C2 URL: {$tok[1]}";
                        return $result;
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Surgically neutralize an individual persistence finding.
     *
     * @param string $type dropin | mu_plugin | autoload_option | cron_hook | resurrected_file
     * @param string $id Target identifier (path, option_name, or cron hook name)
     * @return array
     */
    public function neutralize_item(string $type, string $id): array {
        switch ($type) {
            case 'dropin':
            case 'mu_plugin':
            case 'resurrected_file':
                $file = realpath($id);
                if (!$file && file_exists(ABSPATH . ltrim($id, '/\\'))) {
                    $file = realpath(ABSPATH . ltrim($id, '/\\'));
                }
                if (!$file || !file_exists($file)) {
                    return ['success' => false, 'message' => __('Target file not found on disk.', 'wcp-security-scanner')];
                }
                if (!PathValidator::is_inside_root($file, ABSPATH)) {
                    return ['success' => false, 'message' => __('Security restriction: File is outside WordPress root.', 'wcp-security-scanner')];
                }

                // Generate encrypted vault backup first
                $remediation = new RemediationManager();
                $backup = $remediation->create_file_backup($file, 'persistence_neutralize');
                if (!$backup['success']) {
                    return ['success' => false, 'message' => __('Could not generate encrypted safety backup. Neutralization aborted.', 'wcp-security-scanner')];
                }

                // Delete or rename file
                $quarantined_name = $file . '.wcp-quarantined-' . time();
                if (@rename($file, $quarantined_name) || wp_delete_file($file)) {
                    return [
                        'success'   => true,
                        /* translators: %s: file basename */
                        'message'   => sprintf(__('Persistence anchor "%s" neutralized. Encrypted safety backup created.', 'wcp-security-scanner'), basename($file)),
                        'backup_id' => $backup['backup_id'],
                    ];
                }
                return ['success' => false, 'message' => __('Filesystem write permission denied. Could not remove file.', 'wcp-security-scanner')];

            case 'autoload_option':
                global $wpdb;
                $opt_name = sanitize_text_field($id);
                // Backup option value to backups option
                $val = get_option($opt_name);
                $backups = get_option('wcpscan_remediation_backups', []);
                $b_id = 'opt_' . substr(md5($opt_name . time()), 0, 12);
                $backups[$b_id] = [
                    'id'            => $b_id,
                    'original_path' => 'wp_options:' . $opt_name,
                    'backup_file'   => $opt_name,
                    'action_type'   => 'db_autoload_cleaned',
                    'created_at'    => current_time('mysql'),
                    'size'          => is_string($val) ? strlen($val) : 0,
                    'backup_data'   => $val,
                ];
                update_option('wcpscan_remediation_backups', $backups, false);

                delete_option($opt_name);
                delete_site_option($opt_name);

                return [
                    'success'   => true,
                    /* translators: %s: option name */
                    'message'   => sprintf(__('Malicious autoload option "%s" deleted from database. Snapshot saved to vault.', 'wcp-security-scanner'), $opt_name),
                    'backup_id' => $b_id,
                ];

            case 'cron_hook':
                $hook = sanitize_text_field($id);
                $cleared = wp_clear_scheduled_hook($hook);
                return [
                    'success' => true,
                    /* translators: %s: cron hook name */
                    'message' => sprintf(__('Scheduled cron hook "%s" cleared from WordPress crontab.', 'wcp-security-scanner'), $hook),
                    'cleared' => $cleared,
                ];

            default:
                return ['success' => false, 'message' => __('Invalid persistence item type.', 'wcp-security-scanner')];
        }
    }

    /**
     * 1-Click Mass Neutralization: Purges all confirmed malicious persistence anchors.
     *
     * @return array
     */
    public function neutralize_all(): array {
        $audit = $this->audit_full();
        $cleaned = 0;
        $failed = 0;
        $details = [];

        // 1. Drop-ins
        foreach ($audit['dropins'] as $d) {
            if ($d['status'] === 'malicious' || $d['is_unexpected']) {
                $res = $this->neutralize_item('dropin', $d['path']);
                if ($res['success']) {
                    $cleaned++;
                    $details[] = "Purged Drop-in: {$d['filename']}";
                } else {
                    $failed++;
                }
            }
        }

        // 2. MU-Plugins
        foreach ($audit['mu_plugins'] as $m) {
            if ($m['status'] === 'malicious') {
                $res = $this->neutralize_item('mu_plugin', $m['path']);
                if ($res['success']) {
                    $cleaned++;
                    $details[] = "Purged MU-Plugin: {$m['filename']}";
                } else {
                    $failed++;
                }
            }
        }

        // 3. Database Autoload Options
        foreach ($audit['autoload_options'] as $o) {
            $res = $this->neutralize_item('autoload_option', $o['option_name']);
            if ($res['success']) {
                $cleaned++;
                $details[] = "Deleted Option: {$o['option_name']}";
            } else {
                $failed++;
            }
        }

        // 4. Rogue Cron Hooks
        foreach ($audit['cron_tasks'] as $c) {
            if ($c['severity'] === 'critical' || $c['severity'] === 'high') {
                $res = $this->neutralize_item('cron_hook', $c['hook']);
                if ($res['success']) {
                    $cleaned++;
                    $details[] = "Cleared Cron: {$c['hook']}";
                } else {
                    $failed++;
                }
            }
        }

        // 5. Resurrected Files
        foreach ($audit['resurrections'] as $r) {
            $res = $this->neutralize_item('resurrected_file', $r['file_path']);
            if ($res['success']) {
                $cleaned++;
                $details[] = "Re-neutralized: {$r['filename']}";
            } else {
                $failed++;
            }
        }

        return [
            'success'        => true,
            /* translators: 1: number of cleaned anchors, 2: number of failed anchors */
            'message'        => sprintf(
                __('Persistence Neutralization Complete: Cleaned %1$d anchors, %2$d failed. Safety snapshots saved to vault.', 'wcp-security-scanner'),
                $cleaned,
                $failed
            ),
            'cleaned_count'  => $cleaned,
            'failed_count'   => $failed,
            'details'        => $details,
        ];
    }
}
