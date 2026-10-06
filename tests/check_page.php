<?php
require_once '/var/www/html/wp-load.php';
wp_set_current_user(1);

$_GET['page'] = 'wcp-security-scanner';

$hook = 'toplevel_page_wcp-security-scanner';
WCP\Scanner\Admin\AdminMenu::enqueue_assets($hook);

ob_start();
WCP\Scanner\Admin\AdminMenu::render_app_container();
$container = ob_get_clean();

echo "Container: " . $container . "\n";
echo "Script enqueued: " . (wp_script_is('wcp-scanner-app', 'enqueued') ? 'YES' : 'NO') . "\n";
echo "Style enqueued: " . (wp_style_is('wcp-scanner-style', 'enqueued') ? 'YES' : 'NO') . "\n";

global $wp_scripts;
if (isset($wp_scripts->registered['wcp-scanner-app'])) {
    echo "Dependencies: " . implode(', ', $wp_scripts->registered['wcp-scanner-app']->deps) . "\n";
    echo "Source URL: " . $wp_scripts->registered['wcp-scanner-app']->src . "\n";
}
