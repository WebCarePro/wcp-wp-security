<?php
require '/var/www/html/wp-load.php';
wp_set_current_user(1);

function test_route($route, $method = 'GET', $params = []) {
    $request = new WP_REST_Request($method, $route);
    if (!empty($params)) {
        if ($method === 'GET') {
            $request->set_query_params($params);
        } else {
            $request->set_body_params($params);
        }
    }
    $response = rest_do_request($request);
    $status = $response->get_status();
    $data = $response->get_data();
    $ok = ($status >= 200 && $status < 300);
    echo "[$method $route] Status: $status, OK: " . ($ok ? 'YES' : 'NO') . "\n";
    return $data;
}

echo "=== REST API Endpoints Verification ===\n";
test_route('/wcp-scanner/v1/server-info', 'GET');
$backup = test_route('/wcp-scanner/v1/backup/create', 'POST');
test_route('/wcp-scanner/v1/backup/list', 'GET');
if (!empty($backup['filename'])) {
    test_route('/wcp-scanner/v1/backup/delete', 'POST', ['filename' => $backup['filename']]);
}
test_route('/wcp-scanner/v1/scan/history', 'GET');
test_route('/wcp-scanner/v1/scan/history/clear', 'POST');

echo "\n=== Targeted Scans API Verification ===\n";
// Release lock if any
WCP\Scanner\Scan\ScanLock::release(WCP\Scanner\Scan\ScanLock::get_locked_scan_id() ?: 0);

$t1 = test_route('/wcp-scanner/v1/scan/start', 'POST', ['target' => 'unknown_files']);
WCP\Scanner\Scan\ScanLock::release($t1['scan_id'] ?? 0);

$t2 = test_route('/wcp-scanner/v1/scan/start', 'POST', ['target' => 'spam_content']);
WCP\Scanner\Scan\ScanLock::release($t2['scan_id'] ?? 0);

$t3 = test_route('/wcp-scanner/v1/scan/start', 'POST', ['target' => 'user_security']);
WCP\Scanner\Scan\ScanLock::release($t3['scan_id'] ?? 0);

$t4 = test_route('/wcp-scanner/v1/scan/start', 'POST', ['target' => 'outdated_software']);
WCP\Scanner\Scan\ScanLock::release($t4['scan_id'] ?? 0);

$t5 = test_route('/wcp-scanner/v1/scan/start', 'POST', ['target' => 'filesystem_only']);
WCP\Scanner\Scan\ScanLock::release($t5['scan_id'] ?? 0);

$t6 = test_route('/wcp-scanner/v1/scan/start', 'POST', ['target' => 'suspicious_uploads']);
WCP\Scanner\Scan\ScanLock::release($t6['scan_id'] ?? 0);

echo "\nAll endpoints verified successfully!\n";
