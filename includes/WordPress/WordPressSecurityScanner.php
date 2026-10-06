<?php
namespace WCP\Scanner\WordPress;

use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Resource\ResourceMonitor;

if (!defined('ABSPATH')) {
    exit;
}

class WordPressSecurityScanner {

    private $user_scanner;
    private $persistence_scanner;
    private $config_scanner;
    private $cron_scanner;

    public function __construct() {
        $this->user_scanner = new UserScanner();
        $this->persistence_scanner = new PersistenceScanner();
        $this->config_scanner = new ConfigScanner();
        $this->cron_scanner = new CronScanner();
    }

    /**
     * Run all WordPress security & persistence audits.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];
        $monitor = new ResourceMonitor(80, 20);

        // 1. Audit Users & Capabilities
        if (!$monitor->is_nearing_limits()) {
            $user_findings = $this->user_scanner->scan($scan_id);
            $findings = array_merge($findings, $user_findings);
        }

        // 2. Audit Persistence (mu-plugins, drop-ins, loose files)
        if (!$monitor->is_nearing_limits()) {
            $persist_findings = $this->persistence_scanner->scan($scan_id);
            $findings = array_merge($findings, $persist_findings);
        }

        // 3. Audit Configuration (wp-config, .htaccess, ini)
        if (!$monitor->is_nearing_limits()) {
            $config_findings = $this->config_scanner->scan($scan_id);
            $findings = array_merge($findings, $config_findings);
        }

        // 4. Audit Scheduled Cron Jobs
        if (!$monitor->is_nearing_limits()) {
            $cron_findings = $this->cron_scanner->scan($scan_id);
            $findings = array_merge($findings, $cron_findings);
        }

        return $findings;
    }
}
