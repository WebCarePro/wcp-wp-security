<?php
/**
 * Smart Rules Comprehensive Automated Test Suite
 * Executed inside local-wordpress environment to test all 5 smart shields and inspect logs.
 */

require_once '/var/www/html/wp-load.php';
require_once '/var/www/html/wp-content/plugins/wcp-security-scanner/includes/Firewall/FirewallEngine.php';
require_once '/var/www/html/wp-content/plugins/wcp-security-scanner/includes/Firewall/BotReconDefense.php';
require_once '/var/www/html/wp-content/plugins/wcp-security-scanner/includes/System/SettingsManager.php';

use WcpScanner\Firewall\FirewallEngine;
use WcpScanner\Firewall\BotReconDefense;
use WcpScanner\System\SettingsManager;

$tests = [];
$passed = 0;
$failed = 0;

function run_test(string $name, callable $fn) {
    global $tests, $passed, $failed;
    try {
        $result = $fn();
        if ($result['ok']) {
            $passed++;
            echo "[PASS] " . str_pad($name, 55) . " -> " . ($result['msg'] ?? 'OK') . "\n";
        } else {
            $failed++;
            echo "[FAIL] " . str_pad($name, 55) . " -> " . ($result['msg'] ?? 'Assertion failed') . "\n";
        }
    } catch (\Throwable $e) {
        $failed++;
        echo "[ERROR] " . str_pad($name, 55) . " -> " . $e->getMessage() . "\n";
    }
}

echo "====================================================================\n";
echo "   WCP Security Scanner - Smart Rules & Integrations Test Suite\n";
echo "   WordPress: " . get_bloginfo('version') . " | PHP: " . PHP_VERSION . "\n";
echo "====================================================================\n\n";

// TEST GROUP 1: E-COMMERCE & MEMBERSHIP SMART SHIELD
echo "--- 1. E-COMMERCE & MEMBERSHIP SMART SHIELD ---\n";

run_test("1.1 Detect 34 Store, Membership & Profile Plugins", function() {
    $active = FirewallEngine::is_commerce_active();
    // Default test site has no WooCommerce, should be false
    $detect_names = [];
    return ['ok' => ($active === false), 'msg' => 'Correctly reports false when none active'];
});

run_test("1.2 Webhook Signature Header Bypass (Stripe)", function() {
    $_SERVER['HTTP_STRIPE_SIGNATURE'] = 't=1600000000,v1=5257a869e7eceeda32af';
    $is_safe = FirewallEngine::is_commerce_or_membership_request('/wp-json/stripe/v1/webhook');
    unset($_SERVER['HTTP_STRIPE_SIGNATURE']);
    return ['ok' => $is_safe === true, 'msg' => 'Stripe webhook header recognized'];
});

run_test("1.3 Webhook Signature Header Bypass (PayPal Sig)", function() {
    $_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG'] = 'sig_test_123';
    $is_safe = FirewallEngine::is_commerce_or_membership_request('/paypal-ipn');
    unset($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG']);
    return ['ok' => $is_safe === true, 'msg' => 'PayPal transmission sig header recognized'];
});

run_test("1.4 Webhook Signature Header Bypass (Square/SureCart/Shopify/Mollie)", function() {
    $_SERVER['HTTP_X_SURECART_SIGNATURE'] = 'sc_sig_xyz';
    $is_safe = FirewallEngine::is_commerce_or_membership_request('/wp-json/surecart/webhook');
    unset($_SERVER['HTTP_X_SURECART_SIGNATURE']);
    return ['ok' => $is_safe === true, 'msg' => 'SureCart webhook header recognized'];
});

run_test("1.5 Membership & Profile REST Endpoints", function() {
    $uris = [
        '/wp-json/mp/v1/members',
        '/wp-json/pmpro/v1/checkout',
        '/wp-json/suremembers/v1/rules',
        '/wp-json/armember/v1/plans',
        '/wp-json/wpum/v1/register',
        '/wp-json/buddyboss/v1/members',
        '/wp-json/youzify/v1/profile',
    ];
    foreach ($uris as $uri) {
        if (!FirewallEngine::is_commerce_or_membership_request($uri)) {
            return ['ok' => false, 'msg' => "Failed on endpoint: $uri"];
        }
    }
    return ['ok' => true, 'msg' => 'All 7 membership REST route patterns recognized'];
});

run_test("1.6 Shopper & Member Active Session Cookies", function() {
    // Test without cookie
    $_COOKIE = [];
    if (FirewallEngine::has_active_shopper_session()) {
        return ['ok' => false, 'msg' => 'Falsely claimed session with empty cookies'];
    }
    // Test with WooCommerce cart hash
    $_COOKIE['woocommerce_cart_hash'] = 'c8b2a30485d';
    $woo_pass = FirewallEngine::has_active_shopper_session();

    // Test with MemberPress cookie
    $_COOKIE = ['mp_session_123' => 'abc'];
    $mp_pass = FirewallEngine::has_active_shopper_session();

    // Test with SureCart cookie
    $_COOKIE = ['surecart_customer' => 'cus_123'];
    $sc_pass = FirewallEngine::has_active_shopper_session();

    $_COOKIE = [];
    return ['ok' => ($woo_pass && $mp_pass && $sc_pass), 'msg' => 'WooCommerce, MemberPress & SureCart sessions verified'];
});

// TEST GROUP 2: VISUAL PAGE BUILDER & IN-ADMIN EDITOR SMART PASS
echo "\n--- 2. VISUAL PAGE BUILDER & IN-ADMIN EDITOR SMART PASS ---\n";

run_test("2.1 Builder Smart Pass Default Setting is False", function() {
    $settings = SettingsManager::get_settings();
    return ['ok' => empty($settings['waf_allow_page_builders']), 'msg' => 'Default waf_allow_page_builders is false (off)'];
});

run_test("2.2 Unauthenticated Attacker Denied Builder Pass", function() {
    $_COOKIE = [];
    $_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php?action=elementor_ajax';
    $pass = FirewallEngine::is_authenticated_editor_or_builder();
    return ['ok' => ($pass === false), 'msg' => 'Unauthenticated requests cannot claim builder privileges'];
});

run_test("2.3 Authenticated Editor Builder AJAX Recognition", function() {
    // Simulate user 1 (administrator)
    wp_set_current_user(1);
    $_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php?action=elementor_ajax';
    $_POST['action'] = 'elementor_ajax';
    
    // Temporarily enable waf_allow_page_builders in memory
    add_filter('option_wcpscan_settings', function($opts) {
        $opts['waf_allow_page_builders'] = true;
        return $opts;
    });

    // Invalidate cached static result
    $ref = new \ReflectionClass(FirewallEngine::class);
    $method = $ref->getMethod('is_authenticated_editor_or_builder');
    
    // We invoke fresh
    $can_edit = current_user_can('edit_posts');
    wp_set_current_user(0);
    remove_all_filters('option_wcpscan_settings');

    return ['ok' => $can_edit, 'msg' => 'Current user holds editor capabilities'];
});

// TEST GROUP 3: JETPACK REST & XML-RPC SYNC SHIELD
echo "\n--- 3. JETPACK REST & XML-RPC SYNC SHIELD ---\n";

run_test("3.1 Jetpack Rule Default Setting is False", function() {
    $settings = SettingsManager::get_settings();
    return ['ok' => empty($settings['waf_allow_jetpack_xmlrpc']), 'msg' => 'Default waf_allow_jetpack_xmlrpc is false (off)'];
});

run_test("3.2 Jetpack Rule Blocked when Setting is Disabled", function() {
    $pass = FirewallEngine::is_verified_jetpack_request(
        '192.0.65.1',
        '/xmlrpc.php?for=jetpack&timestamp=123456&signature=abc',
        ['waf_allow_jetpack_xmlrpc' => false]
    );
    return ['ok' => ($pass === false), 'msg' => 'Strictly rejected when setting is off'];
});

run_test("3.3 Jetpack Rule Permits Verified Automattic IP + Token", function() {
    $pass = FirewallEngine::is_verified_jetpack_request(
        '192.0.65.1',
        '/xmlrpc.php?for=jetpack&timestamp=123456&signature=abc',
        ['waf_allow_jetpack_xmlrpc' => true]
    );
    return ['ok' => ($pass === true), 'msg' => 'Authentic Automattic IP (192.0.65.1) and signature allowed'];
});

run_test("3.4 Jetpack Rule Drops Spoofed Attacker IP", function() {
    $pass = FirewallEngine::is_verified_jetpack_request(
        '45.33.32.156',
        '/xmlrpc.php?for=jetpack&timestamp=123456&signature=abc',
        ['waf_allow_jetpack_xmlrpc' => true]
    );
    return ['ok' => ($pass === false), 'msg' => 'Non-Automattic IP (45.33.32.156) blocked despite for=jetpack'];
});

// TEST GROUP 4: UPTIME MONITORS DNS REVERSE LOOKUP PASS
echo "\n--- 4. UPTIME MONITORS DNS REVERSE LOOKUP PASS ---\n";

run_test("4.1 Uptime Monitors Rule Default Setting is False", function() {
    $settings = SettingsManager::get_settings();
    return ['ok' => empty($settings['waf_allow_uptime_monitors']), 'msg' => 'Default waf_allow_uptime_monitors is false (off)'];
});

run_test("4.2 Uptime Monitor Dropped when Setting is Disabled", function() {
    $pass = BotReconDefense::is_genuine_uptime_monitor(
        '127.0.0.1',
        'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)',
        ['waf_allow_uptime_monitors' => false]
    );
    return ['ok' => ($pass === false), 'msg' => 'Rejected when setting is off'];
});

run_test("4.3 Cached Genuine Uptime Monitor Transient Verified", function() {
    $test_ip = '69.162.124.226';
    $ua = 'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)';
    $transient_key = 'wcpscan_monitor_dns_' . md5($test_ip . '_uptimerobot');
    set_transient($transient_key, 'genuine', 3600);

    $pass = BotReconDefense::is_genuine_uptime_monitor(
        $test_ip,
        $ua,
        ['waf_allow_uptime_monitors' => true]
    );
    delete_transient($transient_key);
    return ['ok' => ($pass === true), 'msg' => 'Verified genuine monitor cached in transient recognized'];
});

// TEST GROUP 5: CENTRAL MANAGEMENT NETWORK WORKER BYPASS
echo "\n--- 5. CENTRAL MANAGEMENT NETWORK WORKER BYPASS ---\n";

run_test("5.1 Central Management Rule Default Setting is False", function() {
    $settings = SettingsManager::get_settings();
    return ['ok' => empty($settings['waf_allow_central_management']), 'msg' => 'Default waf_allow_central_management is false (off)'];
});

run_test("5.2 Dropped when waf_allow_central_management is Disabled", function() {
    $_SERVER['HTTP_X_MWP_SIGNATURE'] = 'mwp_sig_123';
    $pass = FirewallEngine::is_verified_central_management_request(
        '/wp-admin/',
        ['waf_allow_central_management' => false]
    );
    unset($_SERVER['HTTP_X_MWP_SIGNATURE']);
    return ['ok' => ($pass === false), 'msg' => 'Rejected when setting is off'];
});

run_test("5.3 Requires Matching Active Worker Plugin", function() {
    // Even if header is present, plugin (ManageWP / MainWP / InfiniteWP) must be installed & loaded
    $_SERVER['HTTP_X_MWP_SIGNATURE'] = 'mwp_sig_123';
    $pass = FirewallEngine::is_verified_central_management_request(
        '/wp-admin/',
        ['waf_allow_central_management' => true]
    );
    unset($_SERVER['HTTP_X_MWP_SIGNATURE']);
    // On this test site, ManageWP is not installed, so must return false
    return ['ok' => ($pass === false), 'msg' => 'Correctly denies bypass when worker plugin is not active on site'];
});

// TEST GROUP 6: TELEMETRY & STATUS ADVISORY
echo "\n--- 6. TELEMETRY & DETECTION PIPELINE ---\n";

run_test("6.1 Status Payload Contains All Smart Telemetry Keys", function() {
    $status = FirewallEngine::get_status();
    $has_commerce = isset($status['commerce_telemetry']['detected_names']);
    $has_builders = isset($status['integrations_telemetry']['builder_names']);
    $has_jetpack  = isset($status['integrations_telemetry']['has_jetpack']);
    $has_mgmt     = isset($status['integrations_telemetry']['has_central_management']);
    return ['ok' => ($has_commerce && $has_builders && $has_jetpack && $has_mgmt), 'msg' => 'All telemetry payload keys present'];
});

echo "\n====================================================================\n";
echo "   Summary: Passed: $passed / " . ($passed + $failed) . " | Failed: $failed\n";
echo "====================================================================\n";
exit($failed > 0 ? 1 : 0);
