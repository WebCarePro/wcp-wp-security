<?php
namespace WcpScanner\Integrity;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * BehavioralBaselineEngine
 *
 * Captures an autonomous known-good baseline snapshot of critical WordPress execution vectors:
 * - High-risk hook callback signatures & densities
 * - Active crontab event schedule registry
 * - Drop-ins & Must-Use (MU) plugin filesystem presence and hashes
 * - High-entropy (> 5.2 Shannon) PHP file distribution
 *
 * Provides fast real-time deviation auditing to catch covert persistence and backdoor implants.
 */
class BehavioralBaselineEngine {

    const OPTION_KEY = 'wcpscan_behavioral_baseline';

    /**
     * Critical WordPress filter & action hooks to monitor for covert tampering.
     */
    const CRITICAL_HOOKS = [
        'init',
        'wp_loaded',
        'template_redirect',
        'shutdown',
        'admin_init',
        'wp_authenticate',
        'authenticate',
        'login_init',
        'wp_login',
        'user_register',
        'set_current_user',
        'pre_get_posts',
        'rest_api_init',
        'plugins_loaded',
        'wp_head',
        'wp_footer',
    ];

    /**
     * Standard WordPress drop-in filenames in WP_CONTENT_DIR.
     */
    const STANDARD_DROPINS = [
        'advanced-cache.php',
        'db.php',
        'db-error.php',
        'install.php',
        'maintenance.php',
        'object-cache.php',
        'sunrise.php',
        'blog-deleted.php',
        'blog-inactive.php',
        'blog-suspended.php',
    ];

    /**
     * Retrieve the stored baseline snapshot.
     *
     * @return array|null
     */
    public static function get_baseline(): ?array {
        $data = get_option(self::OPTION_KEY, null);
        return is_array($data) ? $data : null;
    }

    /**
     * Calibrate and store a new clean baseline snapshot of current site behavior.
     *
     * @return array
     */
    public static function calibrate(): array {
        global $wp_version;

        $user = wp_get_current_user();
        $author = ($user && $user->exists()) ? $user->user_login : 'admin';

        $snapshot = [
            'calibrated_at'        => current_time('mysql'),
            'timestamp'            => time(),
            'calibrated_by'        => $author,
            'wp_version'           => $wp_version ?: 'unknown',
            'php_version'          => PHP_VERSION,
            'active_plugins_count' => count(get_option('active_plugins', [])),
            'active_theme'         => get_stylesheet(),
            'hooks'                => self::capture_hook_registry(),
            'cron'                 => self::capture_cron_registry(),
            'dropins'              => self::capture_dropins_registry(),
            'high_entropy'         => self::capture_high_entropy_index(),
        ];

        update_option(self::OPTION_KEY, $snapshot, false);

        return [
            'success'   => true,
            'message'   => __('Behavioral baseline successfully calibrated.', 'wcp-security-scanner'),
            'baseline'  => $snapshot,
            'stats'     => [
                'tracked_hooks'        => count($snapshot['hooks']),
                'total_callbacks'      => array_sum(array_column($snapshot['hooks'], 'callback_count')),
                'scheduled_crons'      => count($snapshot['cron']),
                'active_dropins'       => count(array_filter($snapshot['dropins'], fn($d) => $d['exists'])),
                'high_entropy_count'   => count($snapshot['high_entropy']),
            ],
        ];
    }

    /**
     * Perform a real-time deviation audit comparing live state against stored baseline.
     *
     * @return array
     */
    public static function audit_baseline(): array {
        $baseline = self::get_baseline();
        if (!$baseline) {
            return [
                'success'    => false,
                'calibrated' => false,
                'message'    => __('No behavioral baseline calibrated yet. Calibrate the system to enable deviation auditing.', 'wcp-security-scanner'),
                'deviations' => [],
                'score'      => null,
            ];
        }

        $live_hooks        = self::capture_hook_registry();
        $live_cron         = self::capture_cron_registry();
        $live_dropins      = self::capture_dropins_registry();
        $live_high_entropy = self::capture_high_entropy_index();

        $deviations = [];
        $penalty = 0;

        // 1. Audit Hook Infiltration & Callback Deviations
        foreach (self::CRITICAL_HOOKS as $hook) {
            $base_info = $baseline['hooks'][$hook] ?? null;
            $live_info = $live_hooks[$hook] ?? null;

            if (!$base_info || !$live_info) {
                continue;
            }

            // Check signature changes
            if ($base_info['signature_hash'] !== $live_info['signature_hash']) {
                $base_cbs = $base_info['callbacks'] ?? [];
                $live_cbs = $live_info['callbacks'] ?? [];

                $added_callbacks = array_diff($live_cbs, $base_cbs);
                $removed_callbacks = array_diff($base_cbs, $live_cbs);

                if (!empty($added_callbacks)) {
                    $sev = in_array($hook, ['wp_authenticate', 'authenticate', 'login_init', 'init']) ? 'critical' : 'high';
                    $penalty += ($sev === 'critical' ? 25 : 15);

                    $deviations[] = [
                        'category'    => 'hooks',
                        'hook'        => $hook,
                        'severity'    => $sev,
                        'title'       => sprintf(__('Unauthorized Callback Injected into %s', 'wcp-security-scanner'), $hook),
                        'description' => sprintf(__('%d unexpected callback(s) registered on hook "%s" since baseline calibration.', 'wcp-security-scanner'), count($added_callbacks), $hook),
                        'added'       => array_values($added_callbacks),
                        'removed'     => array_values($removed_callbacks),
                        'recommendation' => __('Inspect the callback origin. If legitimate developer changes were made, re-calibrate the baseline.', 'wcp-security-scanner'),
                    ];
                }
            }
        }

        // 2. Audit Cron Schedule Injections
        $base_crons = array_column($baseline['cron'] ?? [], 'hook');
        $live_crons = array_column($live_cron, 'hook');

        $new_crons = array_diff($live_crons, $base_crons);
        if (!empty($new_crons)) {
            $penalty += (count($new_crons) * 10);
            foreach ($new_crons as $cron_hook) {
                $deviations[] = [
                    'category'    => 'cron',
                    'hook'        => $cron_hook,
                    'severity'    => 'high',
                    'title'       => sprintf(__('Rogue Scheduled Cron Event: %s', 'wcp-security-scanner'), $cron_hook),
                    'description' => sprintf(__('New background cron task "%s" was registered after baseline was established.', 'wcp-security-scanner'), $cron_hook),
                    'recommendation' => __('Verify if this cron task belongs to an authorized plugin. Malicious plugins often schedule recurring persistence jobs.', 'wcp-security-scanner'),
                ];
            }
        }

        // 3. Audit Drop-In & MU-Plugin Deviations
        foreach ($live_dropins as $name => $live_drop) {
            $base_drop = $baseline['dropins'][$name] ?? null;

            // Newly introduced drop-in file
            if ($live_drop['exists'] && (!$base_drop || !$base_drop['exists'])) {
                $penalty += 30;
                $deviations[] = [
                    'category'    => 'dropins',
                    'target'      => $live_drop['path'],
                    'severity'    => 'critical',
                    'title'       => sprintf(__('New Drop-In Implant Detected: %s', 'wcp-security-scanner'), $name),
                    'description' => sprintf(__('The drop-in file "%s" was created after baseline calibration. Drop-ins execute before plugins load and are a prime backdoor vector.', 'wcp-security-scanner'), $name),
                    'recommendation' => __('Inspect file contents immediately. Quarantine if unrecognized.', 'wcp-security-scanner'),
                ];
            }
            // Modified drop-in file hash
            elseif ($live_drop['exists'] && $base_drop && $base_drop['exists'] && $live_drop['hash'] !== $base_drop['hash']) {
                $penalty += 25;
                $deviations[] = [
                    'category'    => 'dropins',
                    'target'      => $live_drop['path'],
                    'severity'    => 'critical',
                    'title'       => sprintf(__('Drop-In File Modified: %s', 'wcp-security-scanner'), $name),
                    'description' => sprintf(__('The cryptographic SHA-256 hash of drop-in "%s" changed from baseline.', 'wcp-security-scanner'), $name),
                    'recommendation' => __('Review diff to ensure caching or object-cache drop-ins were not backdoored.', 'wcp-security-scanner'),
                ];
            }
        }

        // 4. Audit High-Entropy File Injections
        $base_entropy_files = array_column($baseline['high_entropy'] ?? [], 'hash', 'file');
        foreach ($live_high_entropy as $item) {
            $file = $item['file'];
            $live_hash = $item['hash'];

            if (!isset($base_entropy_files[$file])) {
                $penalty += 20;
                $deviations[] = [
                    'category'    => 'entropy',
                    'target'      => $file,
                    'severity'    => 'high',
                    'entropy'     => $item['entropy'],
                    'title'       => sprintf(__('New High-Entropy PHP File Detected: %s', 'wcp-security-scanner'), basename($file)),
                    'description' => sprintf(__('File has Shannon entropy score of %0.2f (obfuscated or encrypted code typical of web shells). Not present in baseline.', 'wcp-security-scanner'), $item['entropy']),
                    'recommendation' => __('Inspect code snippet for eval, base64_decode, or gzinflate obfuscation.', 'wcp-security-scanner'),
                ];
            } elseif ($base_entropy_files[$file] !== $live_hash) {
                $penalty += 15;
                $deviations[] = [
                    'category'    => 'entropy',
                    'target'      => $file,
                    'severity'    => 'high',
                    'entropy'     => $item['entropy'],
                    'title'       => sprintf(__('High-Entropy File Modified: %s', 'wcp-security-scanner'), basename($file)),
                    'description' => sprintf(__('Cryptographic hash changed for high-entropy PHP file %s.', 'wcp-security-scanner'), basename($file)),
                    'recommendation' => __('Review changes to ensure file was not re-injected with malicious payload.', 'wcp-security-scanner'),
                ];
            }
        }

        $health_score = max(0, 100 - $penalty);
        $status = 'clean';
        if ($health_score < 70) {
            $status = 'compromised';
        } elseif ($health_score < 95) {
            $status = 'warning';
        }

        return [
            'success'          => true,
            'calibrated'       => true,
            'calibrated_at'    => $baseline['calibrated_at'],
            'audited_at'       => current_time('mysql'),
            'status'           => $status,
            'health_score'     => $health_score,
            'deviations_count' => count($deviations),
            'deviations'       => $deviations,
            'baseline_metrics' => [
                'tracked_hooks'   => count($baseline['hooks'] ?? []),
                'crons_count'     => count($baseline['cron'] ?? []),
                'dropins_count'   => count(array_filter($baseline['dropins'] ?? [], fn($d) => !empty($d['exists']))),
                'entropy_count'   => count($baseline['high_entropy'] ?? []),
            ],
            'live_metrics'     => [
                'tracked_hooks'   => count($live_hooks),
                'crons_count'     => count($live_cron),
                'dropins_count'   => count(array_filter($live_dropins, fn($d) => !empty($d['exists']))),
                'entropy_count'   => count($live_high_entropy),
            ],
        ];
    }

    /**
     * Capture callback signatures across critical hooks.
     *
     * @return array
     */
    private static function capture_hook_registry(): array {
        global $wp_filter;

        $registry = [];

        foreach (self::CRITICAL_HOOKS as $hook_name) {
            $hook_obj = $wp_filter[$hook_name] ?? null;
            $callbacks = [];

            if ($hook_obj && is_object($hook_obj) && isset($hook_obj->callbacks)) {
                foreach ($hook_obj->callbacks as $priority => $functions) {
                    foreach ($functions as $func_key => $func_data) {
                        $name = self::format_callback_name($func_data['function'] ?? $func_key);
                        $callbacks[] = "p{$priority}:" . $name;
                    }
                }
            } elseif (is_array($hook_obj)) {
                foreach ($hook_obj as $priority => $functions) {
                    if (is_array($functions)) {
                        foreach ($functions as $func_key => $func_data) {
                            $name = self::format_callback_name($func_data['function'] ?? $func_key);
                            $callbacks[] = "p{$priority}:" . $name;
                        }
                    }
                }
            }

            sort($callbacks);
            $sig_hash = hash('sha256', implode('|', $callbacks));

            $registry[$hook_name] = [
                'hook'            => $hook_name,
                'callback_count'  => count($callbacks),
                'signature_hash'  => $sig_hash,
                'callbacks'       => $callbacks,
            ];
        }

        return $registry;
    }

    /**
     * Capture cron schedule array.
     *
     * @return array
     */
    private static function capture_cron_registry(): array {
        $cron_array = _get_cron_array();
        if (!is_array($cron_array)) {
            $cron_array = get_option('cron', []);
        }

        $flat = [];
        if (is_array($cron_array)) {
            foreach ($cron_array as $timestamp => $hooks) {
                if (!is_array($hooks)) continue;
                foreach ($hooks as $hook => $events) {
                    if (!is_array($events)) continue;
                    foreach ($events as $event_key => $event_data) {
                        $flat[] = [
                            'hook'      => (string) $hook,
                            'schedule'  => $event_data['schedule'] ?? 'once',
                            'interval'  => $event_data['interval'] ?? 0,
                            'args_hash' => hash('sha256', serialize($event_data['args'] ?? [])),
                        ];
                    }
                }
            }
        }

        // Deduplicate by hook name
        $unique = [];
        foreach ($flat as $item) {
            $unique[$item['hook']] = $item;
        }

        return array_values($unique);
    }

    /**
     * Inspect and hash all drop-ins and MU-plugins.
     *
     * @return array
     */
    private static function capture_dropins_registry(): array {
        $dropins = [];
        $content_dir = wp_normalize_path(WP_CONTENT_DIR);

        foreach (self::STANDARD_DROPINS as $filename) {
            $path = $content_dir . '/' . $filename;
            $exists = file_exists($path) && is_file($path);

            $dropins[$filename] = [
                'name'   => $filename,
                'path'   => 'wp-content/' . $filename,
                'exists' => $exists,
                'size'   => $exists ? @filesize($path) : 0,
                'hash'   => $exists ? hash_file('sha256', $path) : null,
            ];
        }

        // Also inspect Must-Use plugins directory
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? wp_normalize_path(WPMU_PLUGIN_DIR) : $content_dir . '/mu-plugins';
        if (is_dir($mu_dir)) {
            $mu_files = @scandir($mu_dir) ?: [];
            foreach ($mu_files as $f) {
                if ($f === '.' || $f === '..' || !str_ends_with(strtolower($f), '.php')) {
                    continue;
                }
                $path = $mu_dir . '/' . $f;
                $dropins['mu:' . $f] = [
                    'name'   => 'mu-plugins/' . $f,
                    'path'   => 'wp-content/mu-plugins/' . $f,
                    'exists' => true,
                    'size'   => @filesize($path) ?: 0,
                    'hash'   => hash_file('sha256', $path),
                ];
            }
        }

        return $dropins;
    }

    /**
     * Calculate high-entropy PHP files in sensitive directories.
     *
     * @return array
     */
    private static function capture_high_entropy_index(): array {
        $results = [];

        $targets = [
            ABSPATH,
            WP_CONTENT_DIR,
            defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (WP_CONTENT_DIR . '/mu-plugins'),
        ];

        foreach ($targets as $dir) {
            if (!is_dir($dir)) continue;

            $items = @scandir($dir) ?: [];
            foreach ($items as $item) {
                if ($item === '.' || $item === '..' || !str_ends_with(strtolower($item), '.php')) {
                    continue;
                }
                $path = wp_normalize_path($dir . '/' . $item);
                if (!is_file($path) || @filesize($path) > (1024 * 1024)) { // Limit to 1MB
                    continue;
                }

                $content = @file_get_contents($path);
                if ($content === false || strlen($content) < 200) {
                    continue;
                }

                $entropy = self::calculate_shannon_entropy($content);
                // Flag files with Shannon entropy >= 5.2 (highly packed or obfuscated)
                if ($entropy >= 5.20) {
                    $rel_path = ltrim(str_replace(wp_normalize_path(ABSPATH), '', $path), '/');
                    $results[] = [
                        'file'    => $rel_path,
                        'entropy' => round($entropy, 2),
                        'hash'    => hash_file('sha256', $path),
                        'size'    => strlen($content),
                    ];
                }
            }
        }

        return $results;
    }

    /**
     * Compute Shannon entropy for a given string: H = -sum(p * log2(p)).
     *
     * @param string $str
     * @return float
     */
    public static function calculate_shannon_entropy(string $str): float {
        $len = strlen($str);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = count_chars($str, 1);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    /**
     * Format a callable into a readable string identifier.
     *
     * @param mixed $callback
     * @return string
     */
    private static function format_callback_name($callback): string {
        if (is_string($callback)) {
            return $callback;
        }

        if (is_array($callback)) {
            $class = is_object($callback[0]) ? get_class($callback[0]) : (string) $callback[0];
            $method = (string) ($callback[1] ?? 'unknown');
            return $class . '::' . $method;
        }

        if (is_object($callback)) {
            if ($callback instanceof \Closure) {
                return 'Closure';
            }
            return get_class($callback);
        }

        return 'unknown_callable';
    }
}
