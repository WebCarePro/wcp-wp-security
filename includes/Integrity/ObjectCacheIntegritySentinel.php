<?php
namespace WcpScanner\Integrity;

use WcpScanner\Notifications\NotificationDispatcher;
use WcpScanner\System\WcpActivityLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ObjectCacheIntegritySentinel
 *
 * Pillar 2: In-Memory Object-Cache (Redis / Memcached / APCu) Poisoning Sentinel:
 * 1. RAM vs Disk Differential Auditor: Compares options fetched from live in-memory object cache
 *    (wp_cache_get / wp_load_alloptions) against direct, unbuffered MySQL queries on wp_options.
 * 2. Critical Option Sentinel: Protects high-value vectors (siteurl, home, active_plugins, default_role,
 *    users_can_register) from stealth socket injections or SSRF overwrites.
 * 3. Serialized Closure & Payload Sink Detector: Identifies injected PHP closures, dynamic callbacks,
 *    or malicious redirect sinks persisting strictly in Redis/Memcached RAM.
 * 4. 1-Click Surgical Resynchronization: Purges poisoned cache keys, flushes Redis/Memcached,
 *    resynchronizes memory from MySQL truth, and invalidates OPcache.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class ObjectCacheIntegritySentinel {

    const OPTION_LAST_AUDIT = 'wcpscan_object_cache_last_audit';
    const OPTION_AUTO_HEAL   = 'wcpscan_object_cache_auto_heal';

    /**
     * Critical security-sensitive WordPress options to verify individually.
     */
    private const CRITICAL_KEYS = [
        'siteurl'             => 'Site Address (URL)',
        'home'                => 'Home Address (URL)',
        'active_plugins'      => 'Active Plugins List',
        'default_role'        => 'Default User Registration Role',
        'users_can_register'  => 'User Registration Policy',
        'template'            => 'Active Parent Theme',
        'stylesheet'          => 'Active Child Theme',
    ];

    /**
     * Initialize sentinel hooks
     */
    public static function init(): void {
        // Sentinel is invoked by OptionScanner, scheduled health check, and REST API routes
    }

    /**
     * Inspect live object cache environment and backend details.
     *
     * @return array
     */
    public static function get_cache_environment(): array {
        $dropin_path   = WP_CONTENT_DIR . '/object-cache.php';
        $dropin_exists = file_exists($dropin_path);
        $ext_cache     = function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache();
        $backend_name  = 'Internal WordPress Memory (WP_Object_Cache)';
        $driver        = 'memory';
        $dropin_meta   = null;

        if ($dropin_exists) {
            $dropin_size  = filesize($dropin_path);
            $dropin_mtime = filemtime($dropin_path);
            // Read first 2KB for driver identification
            $header_content = (string) @file_get_contents($dropin_path, false, null, 0, 2048);

            if (stripos($header_content, 'redis') !== false || class_exists('RedisObjectCache') || class_exists('Redis')) {
                $backend_name = 'Redis Object Cache';
                $driver       = 'redis';
            } elseif (stripos($header_content, 'memcached') !== false || class_exists('Memcached') || class_exists('Memcache')) {
                $backend_name = 'Memcached Object Cache';
                $driver       = 'memcached';
            } elseif (stripos($header_content, 'apcu') !== false || function_exists('apcu_fetch')) {
                $backend_name = 'APCu In-Memory Cache';
                $driver       = 'apcu';
            } elseif (stripos($header_content, 'litespeed') !== false || defined('LSCWP_V')) {
                $backend_name = 'LiteSpeed Cache Object Cache';
                $driver       = 'litespeed';
            } else {
                $backend_name = 'Custom Drop-in Object Cache';
                $driver       = 'custom';
            }

            $dropin_meta = [
                'path'          => $dropin_path,
                'size'          => $dropin_size,
                'mtime'         => $dropin_mtime,
                'mtime_human'   => human_time_diff($dropin_mtime, time()) . ' ' . __('ago', 'wcp-security-scanner'),
            ];
        }

        return [
            'is_external_cache' => $ext_cache,
            'dropin_exists'     => $dropin_exists,
            'backend_name'      => $backend_name,
            'driver'            => $driver,
            'dropin_meta'       => $dropin_meta,
            'opcache_active'    => function_exists('opcache_get_status') && !empty(opcache_get_status(false)['opcache_enabled']),
        ];
    }

    /**
     * Perform deep differential audit comparing RAM Object Cache against MySQL Database truth.
     *
     * @return array
     */
    public static function audit_ram_vs_disk(): array {
        global $wpdb;

        $env = self::get_cache_environment();
        $divergences = [];
        $critical_issues = [];
        $suspicious_sinks = [];

        // 1. Direct MySQL Query (Bypassing Object Cache & Query Buffers)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $raw_db_options = $wpdb->get_results(
            "SELECT option_name, option_value FROM `{$wpdb->options}` WHERE autoload IN ('yes', 'on', 'auto')"
        );

        $db_autoload_map = [];
        if (!empty($raw_db_options)) {
            foreach ($raw_db_options as $row) {
                $db_autoload_map[$row->option_name] = $row->option_value;
            }
        }

        // 2. Fetch live alloptions from In-Memory Object Cache
        $ram_alloptions = wp_cache_get('alloptions', 'options');
        $alloptions_cached = is_array($ram_alloptions);

        if ($alloptions_cached) {
            // A. Check for ghost keys in RAM that do NOT exist in DB autoload
            foreach ($ram_alloptions as $ram_key => $ram_val) {
                if (!isset($db_autoload_map[$ram_key])) {
                    // Ignore known transient runtime keys
                    if (str_starts_with($ram_key, '_transient_') || str_starts_with($ram_key, '_site_transient_')) {
                        continue;
                    }

                    $divergences[] = [
                        'type'        => 'ghost_key_in_ram',
                        'option_name' => $ram_key,
                        'db_value'    => null,
                        'ram_value'   => is_scalar($ram_val) ? (string) $ram_val : wp_json_encode($ram_val),
                        'severity'    => in_array($ram_key, array_keys(self::CRITICAL_KEYS), true) ? 'critical' : 'high',
                        'message'     => sprintf(
                            /* translators: %s: option key */
                            __('Ghost option "%s" exists in RAM Object Cache but is completely absent from MySQL database.', 'wcp-security-scanner'),
                            $ram_key
                        ),
                    ];
                }
            }

            // B. Compare value parity for common keys
            foreach ($db_autoload_map as $db_key => $db_val) {
                if (!isset($ram_alloptions[$db_key])) {
                    // Key in DB autoload is missing from RAM
                    $divergences[] = [
                        'type'        => 'missing_from_ram',
                        'option_name' => $db_key,
                        'db_value'    => $db_val,
                        'ram_value'   => null,
                        'severity'    => in_array($db_key, array_keys(self::CRITICAL_KEYS), true) ? 'critical' : 'medium',
                        'message'     => sprintf(
                            /* translators: %s: option key */
                            __('Autoloaded option "%s" in MySQL database is missing from RAM Object Cache.', 'wcp-security-scanner'),
                            $db_key
                        ),
                    ];
                    continue;
                }

                $ram_val = $ram_alloptions[$db_key];

                // Normalize both representations for strict parity comparison
                $normalized_db  = self::normalize_value($db_val);
                $normalized_ram = self::normalize_value($ram_val);

                if ($normalized_db !== $normalized_ram) {
                    $is_critical = in_array($db_key, array_keys(self::CRITICAL_KEYS), true);

                    $divergences[] = [
                        'type'        => 'value_mismatch',
                        'option_name' => $db_key,
                        'db_value'    => is_scalar($normalized_db) ? (string) $normalized_db : wp_json_encode($normalized_db),
                        'ram_value'   => is_scalar($normalized_ram) ? (string) $normalized_ram : wp_json_encode($normalized_ram),
                        'severity'    => $is_critical ? 'critical' : 'high',
                        'message'     => sprintf(
                            /* translators: %s: option key */
                            __('Value divergence in "%s": Live RAM value does not match MySQL database truth.', 'wcp-security-scanner'),
                            $db_key
                        ),
                    ];
                }
            }
        }

        // 3. Deep Verification of Critical Security Keys Individually
        foreach (self::CRITICAL_KEYS as $crit_key => $crit_label) {
            // Fetch direct raw value from MySQL
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $db_raw = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT option_value FROM `{$wpdb->options}` WHERE option_name = %s LIMIT 1",
                    $crit_key
                )
            );

            // Fetch live RAM value directly from object cache
            $ram_cached = wp_cache_get($crit_key, 'options');

            // If not directly cached under individual key, check alloptions
            if ($ram_cached === false && isset($ram_alloptions[$crit_key])) {
                $ram_cached = $ram_alloptions[$crit_key];
            }

            // If both are present, compare normalized values
            if ($db_raw !== null && $ram_cached !== false) {
                $norm_db  = self::normalize_value($db_raw);
                $norm_ram = self::normalize_value($ram_cached);

                if ($norm_db !== $norm_ram) {
                    $crit_item = [
                        'option_name'  => $crit_key,
                        'label'        => $crit_label,
                        'db_value'     => is_scalar($norm_db) ? (string) $norm_db : wp_json_encode($norm_db),
                        'ram_value'    => is_scalar($norm_ram) ? (string) $norm_ram : wp_json_encode($norm_ram),
                        'divergence'   => 'critical_option_poisoning',
                    ];

                    // Specific threat forensics
                    if (in_array($crit_key, ['siteurl', 'home'], true)) {
                        $crit_item['threat_type'] = 'in_memory_redirect_hijack';
                        $crit_item['forensics']   = sprintf(
                            'Object Cache Hijacking: RAM "%s" points to "%s", while MySQL is "%s". Attackers are executing fileless traffic redirection via Redis/Memcached RAM.',
                            $crit_key,
                            (string) $norm_ram,
                            (string) $norm_db
                        );
                    } elseif ($crit_key === 'active_plugins') {
                        $crit_item['threat_type'] = 'in_memory_plugin_injection';
                        $db_plugins  = is_array($norm_db) ? $norm_db : [];
                        $ram_plugins = is_array($norm_ram) ? $norm_ram : [];
                        $injected    = array_diff($ram_plugins, $db_plugins);
                        $crit_item['forensics']   = sprintf(
                            'Fileless Plugin Injection: Object Cache loads active plugins %s that do NOT exist in MySQL database active_plugins.',
                            wp_json_encode(array_values($injected))
                        );
                    } elseif ($crit_key === 'default_role' && $norm_ram === 'administrator') {
                        $crit_item['threat_type'] = 'in_memory_privilege_escalation';
                        $crit_item['forensics']   = 'Privilege Escalation: RAM object cache forces default_role to "administrator", making all new registrations auto-admins.';
                    } else {
                        $crit_item['threat_type'] = 'critical_value_divergence';
                        $crit_item['forensics']   = "Critical option {$crit_key} has diverged between live memory cache and MySQL storage.";
                    }

                    $critical_issues[] = $crit_item;
                }
            }
        }

        // 4. Scan RAM Options for Serialized PHP Closures & Execution Sinks
        if ($alloptions_cached && is_array($ram_alloptions)) {
            foreach ($ram_alloptions as $opt_k => $opt_v) {
                $serialized_repr = is_scalar($opt_v) ? (string) $opt_v : serialize($opt_v);

                // Detect serialized closures
                if (stripos($serialized_repr, 'Closure') !== false || stripos($serialized_repr, 'SerializableClosure') !== false) {
                    $suspicious_sinks[] = [
                        'option_name' => $opt_k,
                        'sink_type'   => 'serialized_closure',
                        'snippet'     => substr($serialized_repr, 0, 150),
                        'message'     => sprintf('Serialized PHP closure detected in RAM cache option "%s". High risk of fileless RCE persistence.', $opt_k),
                    ];
                }

                // Detect embedded shell execution sinks
                if (preg_match('/\b(eval|passthru|shell_exec|system|exec|assert)\s*\(/i', $serialized_repr, $sink_match)) {
                    $suspicious_sinks[] = [
                        'option_name' => $opt_k,
                        'sink_type'   => 'command_execution_sink',
                        'snippet'     => $sink_match[0],
                        'message'     => sprintf('Dynamic execution function "%s" detected in RAM cache option "%s".', $sink_match[0], $opt_k),
                    ];
                }
            }
        }

        // 5. Cryptographic Parity Hashes
        ksort($db_autoload_map);
        $db_canonical_str = wp_json_encode($db_autoload_map);
        $db_hash = hash('sha256', (string) $db_canonical_str);

        $ram_hash = null;
        if ($alloptions_cached && is_array($ram_alloptions)) {
            ksort($ram_alloptions);
            $ram_canonical_str = wp_json_encode($ram_alloptions);
            $ram_hash = hash('sha256', (string) $ram_canonical_str);
        }

        $is_poisoned = !empty($critical_issues) || !empty($suspicious_sinks);
        $is_warning  = !$is_poisoned && !empty($divergences);
        $is_clean    = !$is_poisoned && !$is_warning;

        $report = [
            'status'                 => $is_poisoned ? 'poisoned' : ($is_warning ? 'diverged' : 'clean'),
            'parity_score'           => $is_clean ? 100 : ($is_poisoned ? 0 : max(10, 100 - (count($divergences) * 5))),
            'environment'            => $env,
            'db_autoload_count'      => count($db_autoload_map),
            'ram_options_count'      => $alloptions_cached ? count($ram_alloptions) : null,
            'alloptions_cached'      => $alloptions_cached,
            'db_hash'                => $db_hash,
            'ram_hash'               => $ram_hash,
            'hash_parity'            => ($ram_hash !== null && $db_hash === $ram_hash),
            'critical_issues'        => $critical_issues,
            'divergences'            => $divergences,
            'suspicious_sinks'       => $suspicious_sinks,
            'scanned_at'             => current_time('mysql'),
            'scanned_timestamp'      => time(),
        ];

        // Cache last audit result
        update_option(self::OPTION_LAST_AUDIT, $report, false);

        // If active poisoning detected, trigger notifications and activity log
        if ($is_poisoned) {
            self::dispatch_poisoning_alert($report);

            // Automated Auto-Heal: If critical navigation poisoning (siteurl, home, active_plugins) is detected,
            // immediately purge poisoned keys and resynchronize from MySQL truth to stop visitor hijacking
            $auto_heal_enabled = (bool) get_option(self::OPTION_AUTO_HEAL, 1);
            if ($auto_heal_enabled) {
                $critical_key_names = array_column($report['critical_issues'], 'option_name');
                if (in_array('siteurl', $critical_key_names, true) || in_array('home', $critical_key_names, true) || in_array('active_plugins', $critical_key_names, true)) {
                    self::resynchronize_and_flush();
                    $report['auto_healed']          = true;
                    $report['auto_heal_timestamp']  = time();

                    if (class_exists(WcpActivityLogger::class)) {
                        WcpActivityLogger::log(
                            'object_cache_auto_healed',
                            'integrity',
                            'warning',
                            [
                                'backend'     => $report['environment']['backend_name'],
                                'remediated'  => $critical_key_names,
                                'description' => sprintf(
                                    /* translators: %s: backend name */
                                    __('Automatic remediation: In-memory cache poisoning on critical navigation keys was instantly neutralized and resynchronized from MySQL on %s.', 'wcp-security-scanner'),
                                    $report['environment']['backend_name']
                                ),
                            ]
                        );
                    }
                }
            }
        }

        return $report;
    }

    /**
     * Retrieve sentinel settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        return [
            'auto_heal_critical_poisoning' => (bool) get_option(self::OPTION_AUTO_HEAL, 1),
        ];
    }

    /**
     * Update sentinel settings.
     *
     * @param array $params
     * @return array
     */
    public static function update_settings(array $params): array {
        if (isset($params['auto_heal_critical_poisoning'])) {
            update_option(self::OPTION_AUTO_HEAL, !empty($params['auto_heal_critical_poisoning']) ? 1 : 0, false);
        }
        return self::get_settings();
    }

    /**
     * Dispatch out-of-band alert when in-memory cache poisoning is detected.
     *
     * @param array $report Audit report
     * @return void
     */
    private static function dispatch_poisoning_alert(array $report): void {
        $critical_count = count($report['critical_issues']);
        $first_threat   = $report['critical_issues'][0]['forensics'] ?? 'In-memory option tampering detected.';

        if (class_exists(WcpActivityLogger::class)) {
            WcpActivityLogger::log(
                'object_cache_poisoning_detected',
                'integrity',
                'critical',
                [
                    'critical_count' => $critical_count,
                    'backend'        => $report['environment']['backend_name'],
                    'first_threat'   => $first_threat,
                    'critical_keys'  => array_column($report['critical_issues'], 'option_name'),
                    'description'    => sprintf(
                        'CRITICAL: In-Memory Object Cache Poisoning detected on %s! %s',
                        $report['environment']['backend_name'],
                        $first_threat
                    ),
                ]
            );
        }

        if (class_exists(NotificationDispatcher::class)) {
            NotificationDispatcher::trigger('object_cache_poisoning_detected', [
                'backend'        => $report['environment']['backend_name'],
                'critical_count' => $critical_count,
                'forensics'      => $first_threat,
                'timestamp'      => current_time('mysql'),
            ]);
        }
    }

    /**
     * Surgical 1-Click Flush & Resynchronization:
     * Purges live object cache, clears alloptions, reloads from clean MySQL, and resets OPcache.
     *
     * @return array
     */
    public static function resynchronize_and_flush(): array {
        $before_env = self::get_cache_environment();

        // 1. Flush complete external object cache (Redis / Memcached / APCu)
        $flushed = false;
        if (function_exists('wp_cache_flush')) {
            $flushed = (bool) wp_cache_flush();
        }

        // 2. Explicitly delete individual critical keys from cache
        if (function_exists('wp_cache_delete')) {
            wp_cache_delete('alloptions', 'options');
            foreach (array_keys(self::CRITICAL_KEYS) as $key) {
                wp_cache_delete($key, 'options');
            }
        }

        // 3. Force re-prime of alloptions from clean MySQL database
        if (function_exists('wp_load_alloptions')) {
            wp_load_alloptions(true);
        }

        // 4. Invalidate OPcache if active
        $opcache_reset = false;
        if (function_exists('opcache_reset')) {
            $opcache_reset = (bool) @opcache_reset();
        }

        // 5. Re-run differential audit to verify recovery
        $post_audit = self::audit_ram_vs_disk();

        if (class_exists(WcpActivityLogger::class)) {
            WcpActivityLogger::log(
                'object_cache_resynchronized',
                'integrity',
                'notice',
                [
                    'backend'         => $before_env['backend_name'],
                    'cache_flushed'   => $flushed,
                    'opcache_reset'   => $opcache_reset,
                    'recovery_status' => $post_audit['status'],
                    'post_parity'     => $post_audit['parity_score'],
                    'description'     => sprintf(
                        'Object Cache purged and resynchronized from MySQL truth on %s. Post-audit status: %s (Parity: %d%%).',
                        $before_env['backend_name'],
                        strtoupper($post_audit['status']),
                        $post_audit['parity_score']
                    ),
                ]
            );
        }

        return [
            'success'       => true,
            'message'       => __('In-Memory Object Cache successfully flushed and resynchronized from MySQL database truth.', 'wcp-security-scanner'),
            'flushed'       => $flushed,
            'opcache_reset' => $opcache_reset,
            'audit'         => $post_audit,
        ];
    }

    /**
     * Normalize values for accurate parity comparison across string/serialized formats.
     *
     * @param mixed $val
     * @return mixed
     */
    private static function normalize_value($val) {
        if (is_string($val)) {
            $val = maybe_unserialize($val);
        }
        if (is_object($val) || is_array($val)) {
            $decoded = json_decode((string) wp_json_encode($val), true);
            if ($decoded !== null || $val === null || $val === []) {
                return $decoded;
            }
        }
        return $val;
    }
}
