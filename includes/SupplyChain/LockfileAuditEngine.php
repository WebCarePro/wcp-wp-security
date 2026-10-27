<?php
namespace WcpScanner\SupplyChain;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LockfileAuditEngine
 *
 * Offline Software Supply-Chain & Dependency Lockfile Auditor.
 * Recursively discovers composer.lock and package-lock.json files across active
 * plugins and themes, auditing third-party dependencies against bundled CVE advisories
 * and supply-chain tampering vectors without requiring Composer, Node.js, or npm.
 */
class LockfileAuditEngine {

    const CACHE_OPTION = 'wcpscan_lockfile_audit_cache';

    /**
     * Known vulnerability advisory database (offline signature feed).
     */
    const KNOWN_ADVISORIES = [
        'composer' => [
            'phpunit/phpunit' => [
                'cve'         => 'CVE-2017-9841',
                'severity'    => 'critical',
                'affected'    => '<= 4.8.27 || >= 5.0.0, <= 5.6.2',
                'fixed_in'    => '4.8.28, 5.6.3',
                'description' => 'Unauthenticated arbitrary PHP code execution via public eval-stdin.php test runner endpoint.',
            ],
            'guzzlehttp/guzzle' => [
                'cve'         => 'CVE-2022-31090',
                'severity'    => 'high',
                'affected'    => '< 6.5.8 || >= 7.0.0, < 7.4.5',
                'fixed_in'    => '6.5.8, 7.4.5',
                'description' => 'Authorization and Cookie header leakage across cross-domain redirects.',
            ],
            'dompdf/dompdf' => [
                'cve'         => 'CVE-2022-28368',
                'severity'    => 'critical',
                'affected'    => '< 2.0.0',
                'fixed_in'    => '2.0.0',
                'description' => 'Remote code execution and arbitrary file disclosure via untrusted CSS and SVG font rendering.',
            ],
            'monolog/monolog' => [
                'cve'         => 'CVE-2021-39249',
                'severity'    => 'high',
                'affected'    => '< 2.3.0',
                'fixed_in'    => '2.3.0',
                'description' => 'Command injection vulnerability in SyslogUdpHandler via malformed log messages.',
            ],
            'symfony/http-foundation' => [
                'cve'         => 'CVE-2020-15094',
                'severity'    => 'medium',
                'affected'    => '< 4.4.11 || >= 5.0.0, < 5.1.3',
                'fixed_in'    => '4.4.11, 5.1.3',
                'description' => 'Reverse proxy IP header spoofing allowing unauthorized client IP bypass.',
            ],
            'twig/twig' => [
                'cve'         => 'CVE-2022-39261',
                'severity'    => 'high',
                'affected'    => '< 2.15.3 || >= 3.0.0, < 3.4.3',
                'fixed_in'    => '2.15.3, 3.4.3',
                'description' => 'Template path traversal allowing unauthorized file disclosure in file system loaders.',
            ],
        ],
        'npm' => [
            'lodash' => [
                'cve'         => 'CVE-2021-23337',
                'severity'    => 'high',
                'affected'    => '< 4.17.21',
                'fixed_in'    => '4.17.21',
                'description' => 'Prototype pollution and remote command injection in template function.',
            ],
            'axios' => [
                'cve'         => 'CVE-2020-28168',
                'severity'    => 'high',
                'affected'    => '< 0.21.1',
                'fixed_in'    => '0.21.1',
                'description' => 'Server-Side Request Forgery (SSRF) and proxy header bypass.',
            ],
            'tar' => [
                'cve'         => 'CVE-2021-37701',
                'severity'    => 'high',
                'affected'    => '< 6.1.9',
                'fixed_in'    => '6.1.9',
                'description' => 'Arbitrary file creation and overwrite through symlink directory traversal.',
            ],
            'minimist' => [
                'cve'         => 'CVE-2021-44906',
                'severity'    => 'medium',
                'affected'    => '< 1.2.6',
                'fixed_in'    => '1.2.6',
                'description' => 'Prototype pollution via constructor and proto argument parameters.',
            ],
            'moment' => [
                'cve'         => 'CVE-2022-31129',
                'severity'    => 'medium',
                'affected'    => '< 2.29.4',
                'fixed_in'    => '2.29.4',
                'description' => 'Regular Expression Denial of Service (ReDoS) in date format parser.',
            ],
        ],
    ];

    /**
     * Run full offline scan across plugins and themes.
     *
     * @param bool $force_refresh
     * @return array
     */
    public static function run_audit(bool $force_refresh = false): array {
        if (!$force_refresh) {
            $cached = get_transient(self::CACHE_OPTION);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $discovered = self::find_lockfiles();
        $lockfiles_summary = [];
        $vulnerabilities = [];
        $anomalies = [];
        $total_packages = 0;

        foreach ($discovered as $file_info) {
            $parsed = self::parse_lockfile($file_info['path'], $file_info['ecosystem']);
            $packages = $parsed['packages'] ?? [];
            $total_packages += count($packages);

            $file_vulns = [];
            $file_anomalies = [];

            // Audit each dependency package
            foreach ($packages as $pkg) {
                $name = strtolower($pkg['name']);
                $version = ltrim($pkg['version'] ?? '', 'v');
                $ecosystem = $file_info['ecosystem'];

                // Check advisory database
                if (isset(self::KNOWN_ADVISORIES[$ecosystem][$name])) {
                    $advisory = self::KNOWN_ADVISORIES[$ecosystem][$name];
                    if (self::is_version_vulnerable($version, $advisory['affected'])) {
                        $vuln_entry = [
                            'package'     => $name,
                            'installed'   => $version,
                            'fixed_in'    => $advisory['fixed_in'],
                            'cve'         => $advisory['cve'],
                            'severity'    => $advisory['severity'],
                            'description' => $advisory['description'],
                            'ecosystem'   => $ecosystem,
                            'lockfile'    => $file_info['rel_path'],
                            'plugin_slug' => $file_info['plugin_slug'],
                        ];
                        $vulnerabilities[] = $vuln_entry;
                        $file_vulns[] = $vuln_entry;
                    }
                }

                // Check for insecure sources (HTTP or plain git)
                $source_url = $pkg['source_url'] ?? '';
                if (!empty($source_url) && (str_starts_with($source_url, 'http://') || str_starts_with($source_url, 'git://'))) {
                    $anom = [
                        'type'        => 'insecure_transport',
                        'package'     => $name,
                        'source'      => $source_url,
                        'severity'    => 'medium',
                        'description' => 'Package fetched over unencrypted transport protocol (HTTP/git://).',
                        'lockfile'    => $file_info['rel_path'],
                    ];
                    $anomalies[] = $anom;
                    $file_anomalies[] = $anom;
                }

                // Check for unpinned git commits/dev-master
                if (str_starts_with($version, 'dev-') || str_contains($version, 'x-dev')) {
                    $anom = [
                        'type'        => 'unpinned_branch',
                        'package'     => $name,
                        'source'      => $version,
                        'severity'    => 'low',
                        'description' => 'Package pinned to mutable development branch instead of tagged immutable release.',
                        'lockfile'    => $file_info['rel_path'],
                    ];
                    $anomalies[] = $anom;
                    $file_anomalies[] = $anom;
                }
            }

            // Check for dangerous lifecycle scripts in npm lockfiles
            if (!empty($parsed['suspicious_scripts'])) {
                foreach ($parsed['suspicious_scripts'] as $script_info) {
                    $anomalies[] = [
                        'type'        => 'suspicious_lifecycle_script',
                        'package'     => $script_info['package'],
                        'source'      => $script_info['command'],
                        'severity'    => 'high',
                        'description' => 'NPM package defines dangerous preinstall/postinstall shell execution hook.',
                        'lockfile'    => $file_info['rel_path'],
                    ];
                }
            }

            $lockfiles_summary[] = [
                'rel_path'         => $file_info['rel_path'],
                'ecosystem'        => $file_info['ecosystem'],
                'plugin_slug'      => $file_info['plugin_slug'],
                'total_packages'   => count($packages),
                'vulnerabilities'  => count($file_vulns),
                'anomalies'        => count($file_anomalies),
                'filesize'         => @filesize($file_info['path']) ?: 0,
            ];
        }

        $crit_count = count(array_filter($vulnerabilities, fn($v) => $v['severity'] === 'critical'));
        $high_count = count(array_filter($vulnerabilities, fn($v) => $v['severity'] === 'high'));
        $med_count = count(array_filter($vulnerabilities, fn($v) => $v['severity'] === 'medium'));

        $report = [
            'success'          => true,
            'scanned_at'       => current_time('mysql'),
            'total_lockfiles'  => count($discovered),
            'total_packages'   => $total_packages,
            'summary'          => [
                'critical' => $crit_count,
                'high'     => $high_count,
                'medium'   => $med_count,
                'clean'    => count($vulnerabilities) === 0 && count($anomalies) === 0,
            ],
            'lockfiles'        => $lockfiles_summary,
            'vulnerabilities'  => $vulnerabilities,
            'anomalies'        => $anomalies,
        ];

        set_transient(self::CACHE_OPTION, $report, 12 * HOUR_IN_SECONDS);

        return $report;
    }

    /**
     * Find lockfiles across plugins and themes.
     *
     * @return array
     */
    public static function find_lockfiles(): array {
        $targets = [
            'plugins' => WP_PLUGIN_DIR,
            'themes'  => get_theme_root(),
        ];

        $discovered = [];
        $filenames = [
            'composer.lock'     => 'composer',
            'package-lock.json' => 'npm',
        ];

        foreach ($targets as $base_dir) {
            if (!is_dir($base_dir)) {
                continue;
            }

            try {
                $dir_iter = new \RecursiveDirectoryIterator($base_dir, \RecursiveDirectoryIterator::SKIP_DOTS);
                $filter = new \RecursiveCallbackFilterIterator($dir_iter, function ($current) {
                    if ($current->isDir()) {
                        $name = $current->getFilename();
                        // Skip internal node_modules and vendor directories to avoid redundant nested lockfiles
                        if (in_array($name, ['.git', '.svn', 'node_modules', 'cache', 'wcp-security-scanner'], true)) {
                            return false;
                        }
                    }
                    return true;
                });

                $iterator = new \RecursiveIteratorIterator($filter, \RecursiveIteratorIterator::SELF_FIRST);

                foreach ($iterator as $item) {
                    if ($item->isFile()) {
                        $name = $item->getFilename();
                        if (isset($filenames[$name])) {
                            $path = wp_normalize_path($item->getPathname());
                            // Self-Exclusion: Skip scanner's own lockfiles
                            if (str_contains($path, '/plugins/wcp-security-scanner/')) {
                                continue;
                            }

                            $rel = ltrim(str_replace(wp_normalize_path(ABSPATH), '', $path), '/');
                            $parts = explode('/', $rel);
                            $slug = $parts[2] ?? basename(dirname($path));

                            $discovered[] = [
                                'path'        => $path,
                                'rel_path'    => $rel,
                                'filename'    => $name,
                                'ecosystem'   => $filenames[$name],
                                'plugin_slug' => $slug,
                            ];
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Ignore directory iteration errors on restricted hosts
            }
        }

        return $discovered;
    }

    /**
     * Parse lockfile contents into normalized package structures.
     *
     * @param string $path
     * @param string $ecosystem
     * @return array
     */
    private static function parse_lockfile(string $path, string $ecosystem): array {
        if (!file_exists($path) || !is_readable($path)) {
            return ['packages' => [], 'suspicious_scripts' => []];
        }

        $raw = @file_get_contents($path);
        if (!$raw) {
            return ['packages' => [], 'suspicious_scripts' => []];
        }

        $json = json_decode($raw, true);
        if (!is_array($json)) {
            return ['packages' => [], 'suspicious_scripts' => []];
        }

        $packages = [];
        $suspicious_scripts = [];

        if ($ecosystem === 'composer') {
            $pkg_list = array_merge($json['packages'] ?? [], $json['packages-dev'] ?? []);
            foreach ($pkg_list as $p) {
                if (empty($p['name'])) {
                    continue;
                }
                $packages[] = [
                    'name'       => $p['name'],
                    'version'    => $p['version'] ?? '',
                    'source_url' => $p['source']['url'] ?? '',
                ];
            }
        } elseif ($ecosystem === 'npm') {
            // NPM v2/v3 package-lock.json uses "packages" object
            if (isset($json['packages']) && is_array($json['packages'])) {
                foreach ($json['packages'] as $pkg_path => $p) {
                    if (empty($pkg_path)) {
                        continue; // Root project definition
                    }
                    $name = $p['name'] ?? basename($pkg_path);
                    $version = $p['version'] ?? '';
                    $packages[] = [
                        'name'       => $name,
                        'version'    => $version,
                        'source_url' => $p['resolved'] ?? '',
                    ];

                    // Check for dangerous lifecycle scripts
                    if (!empty($p['scripts']) && is_array($p['scripts'])) {
                        foreach (['preinstall', 'postinstall'] as $hook) {
                            if (!empty($p['scripts'][$hook])) {
                                $cmd = (string) $p['scripts'][$hook];
                                if (preg_match('/(?:curl|wget|bash|sh\s+-c|python|node\s+-e)/i', $cmd)) {
                                    $suspicious_scripts[] = [
                                        'package' => $name,
                                        'hook'    => $hook,
                                        'command' => $cmd,
                                    ];
                                }
                            }
                        }
                    }
                }
            } elseif (isset($json['dependencies']) && is_array($json['dependencies'])) {
                // Legacy NPM v1 format
                foreach ($json['dependencies'] as $name => $p) {
                    $packages[] = [
                        'name'       => $name,
                        'version'    => $p['version'] ?? '',
                        'source_url' => $p['resolved'] ?? '',
                    ];
                }
            }
        }

        return [
            'packages'           => $packages,
            'suspicious_scripts' => $suspicious_scripts,
        ];
    }

    /**
     * SemVer range evaluation helper.
     *
     * @param string $installed
     * @param string $range_spec e.g. "<= 4.8.27 || >= 5.0.0, <= 5.6.2"
     * @return bool
     */
    private static function is_version_vulnerable(string $installed, string $range_spec): bool {
        if (empty($installed)) {
            return false;
        }

        // Clean any metadata suffix (e.g. 1.2.3+build)
        $clean_inst = explode('+', $installed)[0];
        $clean_inst = explode('-', $clean_inst)[0];

        $clauses = explode('||', $range_spec);

        foreach ($clauses as $clause) {
            $sub_conditions = explode(',', $clause);
            $all_met = true;

            foreach ($sub_conditions as $cond) {
                $cond = trim($cond);
                if (preg_match('/^(<=|>=|<|>|==|=)\s*(.+)$/', $cond, $m)) {
                    $op = $m[1] === '=' ? '==' : $m[1];
                    $target_ver = trim($m[2]);

                    if (!version_compare($clean_inst, $target_ver, $op)) {
                        $all_met = false;
                        break;
                    }
                }
            }

            if ($all_met) {
                return true;
            }
        }

        return false;
    }
}
