<?php
namespace WcpScanner\Scan;

use WcpScanner\Resource\ResourceMonitor;
use WcpScanner\Filesystem\DirectoryWalker;
use WcpScanner\Filesystem\FileScanner;
use WcpScanner\Findings\FindingsRepository;

if (!defined('ABSPATH')) {
    exit;
}

class ScanManager {

    private DirectoryWalker $directory_walker;
    private FileScanner $file_scanner;
    private FindingsRepository $repository;

    public function __construct() {
        $this->directory_walker = new DirectoryWalker();
        $this->file_scanner = new FileScanner();
        $this->repository = new FindingsRepository();
    }

    /**
     * Run a streaming batch of the filesystem scan with hierarchical cursor,
     * memory guardrails, abort safety, and bulk persistence.
     *
     * @param string|int $scan_id
     * @param int $batch_size
     * @return array
     */
    public function run_filesystem_batch($scan_id, $batch_size = 25): array {
        $scan_id_str = (string) $scan_id;
        $state = ScanState::load($scan_id_str);
        $monitor = new ResourceMonitor(75, 18); // 75% memory ceiling, 18s execution limit

        // Abort requested check before starting chunk
        if ($state->is_abort_requested()) {
            $state->set_status('aborted');
            $state->save();
            return $this->build_response($state, [], 0, true);
        }

        if ($state->get_status() === 'queued') {
            $state->set_status('running');
        }

        $cursor = $state->get_cursor();
        $current_phase = $cursor['phase'] ?? 'plugins';
        $root_dir = $this->phase_root($current_phase);

        $batch = $this->directory_walker->get_batch($root_dir, $cursor, $batch_size);
        $files = $batch['files'] ?? [];
        $new_cursor = $batch['cursor'] ?? $cursor;
        $exhausted = !empty($batch['exhausted']);

        $findings = [];
        $file_rows = [];
        $issue_rows = [];
        $files_scanned = 0;

        foreach ($files as $file) {
            // Guardrail checks before each file
            if ($monitor->is_nearing_limits() || $state->is_abort_requested()) {
                break;
            }

            $file_findings = $this->file_scanner->scan_file($file, $scan_id_str);
            $has_unignored_threat = false;

            if (!empty($file_findings)) {
                foreach ($file_findings as $finding) {
                    $item = method_exists($finding, 'to_array') ? $finding->to_array() : (array) $finding;
                    if (class_exists('\\WcpScanner\\Findings\\WhitelistManager')) {
                        $matched_rule = \WcpScanner\Findings\WhitelistManager::match_finding($item);
                        if ($matched_rule !== null) {
                            $item['status'] = 'ignored';
                            $item['whitelisted'] = true;
                            $item['whitelist_rule'] = $matched_rule;
                        } else {
                            $item['status'] = 'open';
                            $has_unignored_threat = true;
                        }
                    } else {
                        $item['status'] = 'open';
                        $has_unignored_threat = true;
                    }
                    $findings[] = $item;
                    $issue_rows[] = $item;
                }
            }

            $file_rows[] = [
                'file_path' => $file,
                'file_size' => @filesize($file) ?: 0,
                'status'    => $has_unignored_threat ? 'threat' : 'clean',
            ];

            $files_scanned++;

            // Memory hygiene: force GC every 10 files
            if ($files_scanned % 10 === 0) {
                if (function_exists('gc_collect_cycles')) {
                    gc_collect_cycles();
                }
            }
        }

        // Multi-row bulk persistence
        if (!empty($file_rows)) {
            $this->repository->persist_batch((int) $scan_id, $file_rows, $issue_rows);
        }

        // Update progress & cursor
        $open_issues_count = 0;
        foreach ($issue_rows as $ir) {
            if (($ir['status'] ?? 'open') === 'open') {
                $open_issues_count++;
            }
        }

        $state->increment_scanned($files_scanned);
        $state->add_issues($open_issues_count);
        $state->set_cursor($new_cursor);
        $state->set_memory_peak(memory_get_peak_usage(true));

        // Phase progression
        $is_complete = false;
        if ($exhausted && $files_scanned < $batch_size) {
            $next_phase = $this->next_phase($current_phase);
            if ($next_phase === null) {
                $state->set_status('completed');
                $is_complete = true;
            } else {
                $state->set_cursor([
                    'phase'     => $next_phase,
                    'dir_stack' => [],
                    'last_file' => null,
                ]);
            }
        }

        $state->save();

        return $this->build_response($state, $findings, $files_scanned, $is_complete);
    }

    private function build_response(ScanState $state, array $findings, int $files_scanned, bool $is_complete): array {
        return [
            'scan_id'                => $state->get_scan_id(),
            'engine'                 => 'filesystem',
            'status'                 => $state->get_status(),
            'cursor'                 => $state->get_cursor(),
            'files_scanned_in_batch' => $files_scanned,
            'total_scanned_so_far'   => $state->get_offset(),
            'is_complete'            => $is_complete,
            'memory_peak_mb'         => round($state->get_memory_peak() / 1024 / 1024, 2),
            'findings'               => array_map(function ($f) {
                return method_exists($f, 'to_array') ? $f->to_array() : (array) $f;
            }, $findings),
        ];
    }

    private function phase_root(string $phase): string {
        $uploads = wp_upload_dir();
        return match ($phase) {
            'plugins'  => WP_PLUGIN_DIR,
            'themes'   => get_theme_root(),
            'mu'       => WPMU_PLUGIN_DIR,
            'uploads'  => untrailingslashit($uploads['basedir']),
            'core'     => ABSPATH,
            default    => ABSPATH,
        };
    }

    private function next_phase(string $current): ?string {
        $order = ['plugins', 'themes', 'mu', 'core', 'uploads'];
        $idx = array_search($current, $order, true);
        if ($idx === false || !isset($order[$idx + 1])) {
            return null;
        }
        return $order[$idx + 1];
    }
}
