<?php
require_once '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/admin.php';

$hook = add_menu_page('Test', 'Test', 'manage_options', 'wcp-security-scanner', 'dummy');
echo "Hook suffix: " . $hook . "\n";
