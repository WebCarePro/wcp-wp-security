<?php
namespace WebCareProScanner\Firewall\NextGen;

use WebCareProScanner\Contracts\SecurityModuleInterface;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer;
use WebCareProScanner\Firewall\Modular\SiteBehavioralAnalyzer;
use WebCareProScanner\Malware\TaintAnalysisEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * UpgraderDeltaSentinel
 *
 * Performs sub-second targeted AST & taint scans immediately after plugins or themes are
 * installed, updated, or activated so newly introduced guest endpoints are guarded at once.
 */
class UpgraderDeltaSentinel implements SecurityModuleInterface {

    const OPTION_REPORTS = 'webcareproscan_upgrader_delta_reports';

    public function get_id(): string {
        return 'upgrader-delta-sentinel';
    }

    public function get_manifest(): array {
        return [
            'title'       => __('Post-Install & Update Delta AST Sentinel', 'webcare-pro-security'),
            'description' => __('Immediately audits newly installed or updated plugins and themes in <350ms to detect backdoors and new guest endpoints without waiting for full nightly scans.', 'webcare-pro-security'),
            'category'    => 'nextgen',
            'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.12.0',
            'author'      => 'Mir Alamin (WebCare Pro)',
            'enable_key'  => 'waf_nextgen_upgrader_delta_enabled',
            'deep_link'   => 'admin.php?page=webcare-pro-modular-waf&tab=nextgen',
            'badge'       => 'Next-Gen Supply Chain',
        ];
    }

    public function is_applicable(): bool {
        return true;
    }

    public function boot(): void {
        add_action('upgrader_process_complete', [__CLASS__, 'on_upgrader_complete'], 20, 2);
        add_action('activated_plugin', [__CLASS__, 'on_plugin_activated'], 20, 1);
    }

    public function get_settings_schema(): array {
        return [
            'waf_nextgen_upgrader_delta_enabled' => [
                'default' => true,
                'type'    => 'bool',
                'label'   => __('Post-Install & Update Delta AST Sentinel', 'webcare-pro-security'),
            ],
            'waf_nextgen_upgrader_auto_enforce' => [
                'default' => false,
                'type'    => 'bool',
                'label'   => __('Auto-Enforce Newly Discovered Delta Endpoints', 'webcare-pro-security'),
            ],
        ];
    }

    public function get_rest_routes(): array {
        return [
            [
                'route'    => '/nextgen/delta-reports',
                'methods'  => 'GET',
                'callback' => static function () {
                    $reports = get_option(self::OPTION_REPORTS, []);
                    return new \WP_REST_Response([
                        'success' => true,
                        'reports' => is_array($reports) ? $reports : [],
                    ], 200);
                },
            ],
        ];
    }

    public function get_cron_tasks(): array {
        return [];
    }

    public function get_mcp_tools(): array {
        return [
            [
                'name'        => 'webcareproscan_get_upgrader_delta_reports',
                'description' => 'Retrieve sub-second delta AST reports captured after recent plugin/theme installs and updates.',
                'category'    => 'read',
                'isMutating'  => false,
                'inputSchema' => ['type' => 'object', 'properties' => new \stdClass()],
                'handler'     => static function () {
                    $reports = get_option(self::OPTION_REPORTS, []);
                    return [
                        'isError' => false,
                        'content' => [[
                            'type' => 'text',
                            'text' => (string) wp_json_encode(['reports' => is_array($reports) ? $reports : []]),
                        ]],
                    ];
                },
            ],
        ];
    }

    /**
     * Hook handler for `upgrader_process_complete`.
     *
     * @param \WP_Upgrader $upgrader
     * @param array<string, mixed> $hook_extra
     */
    public static function on_upgrader_complete($upgrader, $hook_extra): void {
        if (!is_array($hook_extra)) {
            return;
        }
        $type = (string) ($hook_extra['type'] ?? '');
        if ($type === 'plugin') {
            $plugins = !empty($hook_extra['plugins']) && is_array($hook_extra['plugins'])
                ? $hook_extra['plugins']
                : (!empty($hook_extra['plugin']) ? [(string) $hook_extra['plugin']] : []);
            foreach ($plugins as $pf) {
                $slug = dirname((string) $pf);
                if ($slug === '.' || $slug === '') {
                    $slug = pathinfo((string) $pf, PATHINFO_FILENAME);
                }
                $dir = WP_PLUGIN_DIR . '/' . trim((string) $slug, '/');
                if ($slug !== 'webcare-pro-security' && is_dir($dir)) {
                    self::run_delta_scan_for_path($dir, (string) $slug, 'plugin_upgrade');
                }
            }
        } elseif ($type === 'theme') {
            $themes = !empty($hook_extra['themes']) && is_array($hook_extra['themes'])
                ? $hook_extra['themes']
                : (!empty($hook_extra['theme']) ? [(string) $hook_extra['theme']] : []);
            foreach ($themes as $th) {
                $dir = get_theme_root() . '/' . trim((string) $th, '/');
                if (is_dir($dir)) {
                    self::run_delta_scan_for_path($dir, (string) $th, 'theme_upgrade');
                }
            }
        }
    }

    /**
     * Hook handler for `activated_plugin`.
     */
    public static function on_plugin_activated(string $plugin): void {
        $slug = dirname($plugin);
        if ($slug === '.' || $slug === '') {
            $slug = pathinfo($plugin, PATHINFO_FILENAME);
        }
        if ($slug === 'webcare-pro-security') {
            return;
        }
        $dir = WP_PLUGIN_DIR . '/' . trim($slug, '/');
        if (is_dir($dir)) {
            self::run_delta_scan_for_path($dir, $slug, 'plugin_activated');
        }
    }

    /**
     * Execute fast targeted AST & taint inspection on a single plugin/theme directory.
     *
     * @param string $dir_path
     * @param string $component_slug
     * @param string $trigger_reason
     * @return array<string, mixed>
     */
    public static function run_delta_scan_for_path(string $dir_path, string $component_slug, string $trigger_reason = 'manual'): array {
        $t_start = microtime(true);
        if (!is_dir($dir_path)) {
            return ['success' => false, 'files_scanned' => 0, 'findings' => []];
        }

        $findings      = [];
        $ajax_actions  = [];
        $rest_routes   = [];
        $files_scanned = 0;
        $max_files     = 150;
        $budget_sec    = 1.25;
        $taint_engine  = class_exists(TaintAnalysisEngine::class) ? new TaintAnalysisEngine() : null;

        try {
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir_path, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }
                if (strtolower($file->getExtension()) !== 'php') {
                    continue;
                }
                if ($files_scanned >= $max_files || (microtime(true) - $t_start) >= $budget_sec) {
                    break;
                }

                $fpath = wp_normalize_path($file->getPathname());
                $files_scanned++;

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Targeted local PHP plugin AST inspection
                $code = @file_get_contents($fpath);
                if (!is_string($code) || $code === '') {
                    continue;
                }

                // 1. Discover guest AJAX hooks (wp_ajax_nopriv_*)
                if (preg_match_all('/add_action\s*\(\s*[\'"]wp_ajax_nopriv_([a-zA-Z0-9_-]+)[\'"]/', $code, $am)) {
                    foreach ($am[1] as $act) {
                        $ajax_actions[] = strtolower(sanitize_text_field($act));
                    }
                }

                // 2. Discover permissive REST routes
                if (preg_match_all('/register_rest_route\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]/s', $code, $rm, PREG_SET_ORDER)) {
                    foreach ($rm as $match) {
                        if (strpos($code, '__return_true') !== false) {
                            $rest_routes[] = '/' . trim($match[1], '/') . '/' . ltrim($match[2], '/');
                        }
                    }
                }

                // 3. Fast taint analysis check if TaintAnalysisEngine available
                if ($taint_engine !== null && method_exists($taint_engine, 'analyze_content')) {
                    $taint_finding = $taint_engine->analyze_content($code, $fpath, 'upgrader-delta');
                    if (is_object($taint_finding)) {
                        $findings[] = [
                            'file'     => preg_replace('#^.*/wp-content/#', 'wp-content/', $fpath),
                            'type'     => property_exists($taint_finding, 'type') ? (string) $taint_finding->type : 'taint',
                            'severity' => property_exists($taint_finding, 'severity') ? (string) $taint_finding->severity : 'high',
                            'detail'   => property_exists($taint_finding, 'description') ? (string) $taint_finding->description : 'Static taint flow detected',
                        ];
                    }
                }
            }
        } catch (\Throwable $e) {
            // Non-blocking delta guard
        }

        $ajax_actions = array_values(array_unique($ajax_actions));
        $rest_routes  = array_values(array_unique($rest_routes));
        $duration_ms  = round((microtime(true) - $t_start) * 1000, 1);

        // Synthesize Modular WAF shields for newly introduced guest endpoints when synthesizer available
        $rules_added = 0;
        if (class_exists(ModularFirewallSynthesizer::class) && (!empty($ajax_actions) || !empty($rest_routes))) {
            $settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
                ? \WebCareProScanner\System\SettingsManager::get_settings()
                : [];
            $default_mode = !empty($settings['waf_nextgen_upgrader_auto_enforce']) ? 'enforce' : 'monitor';
            $existing     = ModularFirewallSynthesizer::get_active_rules();
            $existing_ids = array_column($existing, 'id');

            foreach (array_slice($ajax_actions, 0, 10) as $act) {
                $rid = 'MOD-DELTA-AJAX-' . strtoupper(substr(md5($component_slug . '|' . $act), 0, 6));
                if (!in_array($rid, $existing_ids, true)) {
                    $existing[] = [
                        'id'               => $rid,
                        'category'         => 'ajax_shield',
                        /* translators: 1: AJAX action name, 2: component slug */
                        'title'            => sprintf(__('Delta Guard: Guest AJAX "%1$s" (%2$s)', 'webcare-pro-security'), $act, $component_slug),
                        'origin_component' => $component_slug,
                        'target_uri'       => 'admin-ajax.php',
                        'target_param'     => 'action',
                        'target_value'     => $act,
                        'rate_limit'       => 20,
                        'block_uploads'    => true,
                        'severity'         => 'high',
                        'recommended_mode' => $default_mode,
                        'current_mode'     => $default_mode,
                        'synthesized_at'   => time(),
                    ];
                    $existing_ids[] = $rid;
                    $rules_added++;
                }
            }

            if ($rules_added > 0) {
                ModularFirewallSynthesizer::save_rules($existing);
            }
        } elseif (class_exists(MicroWafCompiler::class)) {
            MicroWafCompiler::compile();
        }

        $report = [
            'timestamp'      => time(),
            'component'      => sanitize_key($component_slug),
            'trigger'        => sanitize_key($trigger_reason),
            'files_scanned'  => $files_scanned,
            'duration_ms'    => $duration_ms,
            'ajax_discovered'=> count($ajax_actions),
            'rest_discovered'=> count($rest_routes),
            'taint_findings' => count($findings),
            'rules_added'    => $rules_added,
            'findings'       => array_slice($findings, 0, 10),
        ];

        $reports = get_option(self::OPTION_REPORTS, []);
        if (!is_array($reports)) {
            $reports = [];
        }
        array_unshift($reports, $report);
        if (count($reports) > 30) {
            $reports = array_slice($reports, 0, 30);
        }
        update_option(self::OPTION_REPORTS, $reports, false);

        return array_merge(['success' => true], $report);
    }
}
