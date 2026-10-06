<?php
require '/var/www/html/wp-load.php';

echo "Running backup test as user: " . (function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : get_current_user()) . "\n";

$backup = new WCP\Scanner\Backup\DatabaseBackup();
$res = $backup->create_backup();
print_r($res);

$list = $backup->list_backups();
echo "Total backups in vault: " . count($list) . "\n";

if (!empty($res['filename'])) {
    $deleted = $backup->delete_backup($res['filename']);
    echo "Deleted test backup: " . ($deleted ? "YES" : "NO") . "\n";
}
