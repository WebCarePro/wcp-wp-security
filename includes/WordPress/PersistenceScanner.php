<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Malware\HeuristicEngine;

if (!defined('ABSPATH')) {
    exit;
}

class PersistenceScanner {

    private $heuristic_engine;

    // Standard recognized WordPress drop-in files
    private $recognized_dropins = [
        'advanced-cache.php',
        'object-cache.php',
        'db.php',
        'db-error.php',
        'sunrise.php',
        'blog-deleted.php',
        'blog-inactive.php',
        'blog-suspended.php',
        'maintenance.php',
        'php-error.php',
        'fatal-error-handler.php',
        'index.php'
    ];

    public function __construct() {
        $this->heuristic_engine = new HeuristicEngine();
    }

    /**
     * Inspect persistence locations: mu-plugins, drop-ins, and loose PHP files in wp-content.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];

        // 1. Audit mu-plugins directory
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        if (is_dir($mu_dir)) {
            $mu_files = glob($mu_dir . '/*.php');
            if (!empty($mu_files)) {
                foreach ($mu_files as $file) {
                    $heuristics = $this->heuristic_engine->scan_file($file, $scan_id);
                    if (!empty($heuristics)) {
                        $findings = array_merge($findings, $heuristics);
                    } else {
                        // MU-plugins execute automatically before regular plugins - flag for review
                        $findings[] = new Finding([
                            'engine'      => 'wordpress-persistence',
                            'type'        => 'mu_plugin_detected',
                            'severity'    => 'info',
                            'confidence'  => 100,
                            'file_path'   => $file,
                            'description' => 'Must-Use (MU) plugin detected. MU-plugins execute automatically on every request without activation.',
                            'evidence'    => 'File: ' . basename($file)
                        ]);
                    }
                }
            }
        }

        // 2. Audit loose PHP files in wp-content root (common malware drop location)
        $wp_content_files = glob(WP_CONTENT_DIR . '/*.php');
        if (!empty($wp_content_files)) {
            foreach ($wp_content_files as $file) {
                $filename = basename($file);

                if (!in_array($filename, $this->recognized_dropins)) {
                    // Loose, unstandardized PHP file in wp-content root
                    $findings[] = new Finding([
                        'engine'      => 'wordpress-persistence',
                        'type'        => 'unexpected_wp_content_file',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => $file,
                        'description' => "Unexpected PHP file directly in wp-content/ root: '{$filename}'. Common webshell or malware persistence drop location.",
                        'evidence'    => "File: {$filename}"
                    ]);
                }

                // Run malware heuristic check on any loose file or drop-in
                $heuristics = $this->heuristic_engine->scan_file($file, $scan_id);
                if (!empty($heuristics)) {
                    $findings = array_merge($findings, $heuristics);
                }
            }
        }

        return $findings;
    }
}
