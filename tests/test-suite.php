<?php
/**
 * Automated Verification & Hardening Test Suite for WCP Security Scanner
 */

if (!isset($_SERVER['HTTP_HOST'])) {
    $_SERVER['HTTP_HOST'] = 'localhost';
}
require_once '/var/www/html/wp-load.php';
while (ob_get_level() > 0) {
    ob_end_flush();
}

use WCP\Scanner\Malware\HeuristicEngine;
use WCP\Scanner\Malware\WebshellDetector;
use WCP\Scanner\Malware\ObfuscationDetector;
use WCP\Scanner\Database\SerializedDataScanner;
use WCP\Scanner\Findings\CorrelationEngine;
use WCP\Scanner\Findings\RiskScorer;
use WCP\Scanner\Findings\Finding;
use WCP\Scanner\Quarantine\QuarantineManager;
use WCP\Scanner\Scan\ScanLock;
use WCP\Scanner\Integrity\CoreIntegrity;
use WCP\Scanner\Integrity\PluginIntegrity;
use WCP\Scanner\Integrity\ThemeIntegrity;

$passed = 0;
$failed = 0;

function assert_test($condition, $name) {
    global $passed, $failed;
    if ($condition) {
        echo "[PASS] $name\n";
        $passed++;
    } else {
        echo "[FAIL] $name\n";
        $failed++;
    }
}

echo "=== WCP Security Scanner Automated Test Suite ===\n\n";

// 1. Webshell Detection Test
$webshell_detector = new WebshellDetector();
$malicious_payload = '<?php eval($_POST["cmd"]); ?>';
$ws_hit = $webshell_detector->scan('/dummy/shell.php', $malicious_payload, '1');
assert_test($ws_hit !== null && $ws_hit->severity === 'critical', 'Webshell Detector catches eval($_POST["cmd"])');

// 2. Obfuscation Detection Test
$obf_detector = new ObfuscationDetector();
$obf_payload = '<?php $x = str_rot13(base64_decode(gzinflate("H4sICA..."))); ' . str_repeat('chr(101).', 30) . ' ?>';
$obf_hit = $obf_detector->scan('/dummy/obf.php', $obf_payload, '1');
assert_test($obf_hit !== null && $obf_hit->confidence >= 60, 'Obfuscation Detector catches high-density string manipulation');

// 3. Serialized Data Safe Parser Test (No Object Execution)
$ser_scanner = new SerializedDataScanner();
$serialized_str = serialize(['nested' => 'safe_string', 'payload' => '<script>alert(1)</script>']);
$extracted = $ser_scanner->extract_strings_safely($serialized_str);
assert_test(in_array('<script>alert(1)</script>', $extracted), 'SerializedDataScanner safely extracts nested payload strings');

// 4. Correlation Engine Compound Elevation Test
$corr_engine = new CorrelationEngine();
$findings_to_correlate = [
    new Finding([
        'engine' => 'integrity-core',
        'type' => 'modified_core_file',
        'severity' => 'high',
        'file_path' => 'wp-includes/sample.php'
    ]),
    new Finding([
        'engine' => 'malware-webshell',
        'type' => 'webshell_pattern',
        'severity' => 'critical',
        'file_path' => 'wp-includes/sample.php'
    ])
];
$correlated = $corr_engine->correlate($findings_to_correlate);
$elevated = false;
foreach ($correlated as $c) {
    if ($c->confidence >= 99 && strpos($c->evidence, 'Multi-Engine Correlation Alert') !== false) {
        $elevated = true;
    }
}
assert_test($elevated, 'CorrelationEngine elevates compound threats across Integrity + Malware engines');

// 5. Risk Scorer Calculation Test
$scorer = new RiskScorer();
$summary = $scorer->calculate([
    ['severity' => 'critical', 'confidence' => 100],
    ['severity' => 'high', 'confidence' => 90],
    ['severity' => 'medium', 'confidence' => 80]
]);
assert_test($summary['score'] >= 50 && isset($summary['counts']['critical']), 'RiskScorer calculates normalized score and counts');

// 6. Scan Lock Concurrency Test
$lock_acquired = ScanLock::acquire(999);
$second_lock = ScanLock::acquire(1000);
ScanLock::release(999);
assert_test($lock_acquired === true && $second_lock === false, 'ScanLock prevents concurrent overlapping scans');

// 7. Quarantine Manager Test
$test_file = ABSPATH . 'test_quarantine_fixture.php';
file_put_contents($test_file, '<?php echo "evil"; ?>');
$qm = new QuarantineManager();
$q_res = $qm->quarantine_file($test_file, 1, null);
assert_test($q_res['success'] === true && !file_exists($test_file), 'QuarantineManager moves file out of ABSPATH into vault');

if ($q_res['success']) {
    $restore_res = $qm->restore_file($q_res['quarantine_id']);
    assert_test($restore_res['success'] === true && file_exists($test_file), 'QuarantineManager safely restores file to original location');
    @unlink($test_file);
}

// 8. System Critical File Quarantine Protection Shield
$wp_config_path = ABSPATH . 'wp-config.php';
$block_res = $qm->quarantine_file($wp_config_path, 1, null);
assert_test($block_res['success'] === false && strpos($block_res['message'], 'Action Blocked') !== false, 'QuarantineManager strictly shields critical system files (wp-config.php) from being quarantined');

// 9. Unknown/Foreign File in wp-admin or wp-includes Detection Test
$rogue_file = ABSPATH . 'wp-admin/unrecognized_rogue_payload.php';
file_put_contents($rogue_file, '<?php echo "rogue"; ?>');
$core_integrity = new CoreIntegrity();
$core_findings = $core_integrity->verify('1');
$found_rogue = false;
foreach ($core_findings as $cf) {
    if ($cf->type === 'unknown_core_file' && strpos($cf->file_path, 'unrecognized_rogue_payload.php') !== false) {
        $found_rogue = true;
        break;
    }
}
@unlink($rogue_file);
assert_test($found_rogue === true, 'CoreIntegrity detects unrecognized/foreign files in wp-admin or wp-includes');

// 10. Unknown/Foreign File in Official Plugin Detection Test (any extension)
$rogue_plugin_file = WP_PLUGIN_DIR . '/elementor/unauthorized_plugin_payload.ico';
file_put_contents($rogue_plugin_file, 'hidden_payload_data');
$plugin_integrity = new PluginIntegrity();
$plugin_findings = $plugin_integrity->verify('1');
$found_plugin_rogue = false;
foreach ($plugin_findings as $pf) {
    if ($pf->type === 'unknown_plugin_file' && strpos($pf->file_path, 'unauthorized_plugin_payload.ico') !== false) {
        $found_plugin_rogue = true;
        break;
    }
}
@unlink($rogue_plugin_file);
assert_test($found_plugin_rogue === true, 'PluginIntegrity detects unrecognized/foreign files inside official plugins regardless of extension');

// 11. Unknown/Foreign File in Official Theme Detection Test (any extension)
$rogue_theme_file = WP_CONTENT_DIR . '/themes/twentytwentyfour/unauthorized_theme_payload.txt';
file_put_contents($rogue_theme_file, 'hidden_theme_payload');
$theme_integrity = new ThemeIntegrity();
$theme_findings = $theme_integrity->verify('1');
$found_theme_rogue = false;
foreach ($theme_findings as $tf) {
    if ($tf->type === 'unknown_theme_file' && strpos($tf->file_path, 'unauthorized_theme_payload.txt') !== false) {
        $found_theme_rogue = true;
        break;
    }
}
@unlink($rogue_theme_file);
assert_test($found_theme_rogue === true, 'ThemeIntegrity detects unrecognized/foreign files inside official themes regardless of extension');

// 12. Server Information Inspection Test
use WCP\Scanner\System\ServerInfo;
$info = ServerInfo::get_info();
assert_test(isset($info['php']['version']) && isset($info['database']['version']) && isset($info['permissions']['wp-config.php']), 'ServerInfo compiles PHP runtime, MySQL stats, and security file permissions');

// 13. Database Backup Vault & SQL Dump Engine Test
use WCP\Scanner\Backup\DatabaseBackup;
$db_backup = new DatabaseBackup();
$backup_res = $db_backup->create_backup();
assert_test($backup_res['success'] === true && !empty($backup_res['filename']), 'DatabaseBackup creates compressed SQL dump in secure vault');

$backups_list = $db_backup->list_backups();
$found_backup = false;
foreach ($backups_list as $b) {
    if ($b['filename'] === $backup_res['filename']) {
        $found_backup = true;
        break;
    }
}
assert_test($found_backup === true, 'DatabaseBackup lists generated backups in vault');

// Verify vault .htaccess security lockdown
$vault_htaccess = WP_CONTENT_DIR . '/wcp-backups/.htaccess';
assert_test(file_exists($vault_htaccess) && strpos(file_get_contents($vault_htaccess), 'Require all denied') !== false, 'DatabaseBackup vault is locked down with Apache access denial');

// Clean up test backup
$deleted_backup = $db_backup->delete_backup($backup_res['filename']);
assert_test($deleted_backup === true, 'DatabaseBackup cleanly deletes backup from vault');

// 14. User Security & Password Dictionary Check Test
use WCP\Scanner\WordPress\UserScanner;
$user_scanner = new UserScanner();
$user_findings = $user_scanner->scan('1', true);
assert_test(is_array($user_findings), 'UserScanner performs administrator password strength and enumeration audit');

// 15. WordPress Updates & Outdated Software Audit Test
use WCP\Scanner\WordPress\UpdateScanner;
$update_scanner = new UpdateScanner();
$update_findings = $update_scanner->scan('1');
assert_test(is_array($update_findings), 'UpdateScanner inspects WordPress core, plugins, and themes for updates');

// 16. Uploads Executables & Suspicious Files Detection Test (.php, .sh, double extension)
use WCP\Scanner\Filesystem\UploadsScanner;
$uploads_dir = WP_CONTENT_DIR . '/uploads';
if (!is_dir($uploads_dir)) {
    @mkdir($uploads_dir, 0775, true);
}
$test_php = $uploads_dir . '/rogue_payload.php';
$test_sh  = $uploads_dir . '/malicious_runner.sh';
$test_dbl = $uploads_dir . '/avatar.png.php';

@file_put_contents($test_php, '<?php echo "evil"; ?>');
@file_put_contents($test_sh, "#!/bin/bash\necho \"root\"");
@file_put_contents($test_dbl, '<?php passthru("id"); ?>');

$uploads_scanner = new UploadsScanner();
$uploads_findings = $uploads_scanner->scan('1');

$detected_php = false;
$detected_sh  = false;
$detected_dbl = false;

foreach ($uploads_findings as $uf) {
    if (strpos($uf->file_path, 'rogue_payload.php') !== false && $uf->type === 'executable_in_uploads') {
        $detected_php = true;
    }
    if (strpos($uf->file_path, 'malicious_runner.sh') !== false && $uf->type === 'executable_in_uploads') {
        $detected_sh = true;
    }
    if (strpos($uf->file_path, 'avatar.png.php') !== false) {
        $detected_dbl = true;
    }
}

@unlink($test_php);
@unlink($test_sh);
@unlink($test_dbl);

assert_test($detected_php && $detected_sh && $detected_dbl, 'UploadsScanner detects forbidden .php, .sh, and double extension files in wp-content/uploads');

echo "\nSummary: $passed Passed, $failed Failed\n";
exit($failed === 0 ? 0 : 1);

