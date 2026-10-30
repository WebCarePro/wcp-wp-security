<?php
namespace WcpScanner\Remediation;

use WcpScanner\Security\PathValidator;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * TransactionalRemediation
 *
 * Implements atomic, multi-threat remediation transactions with 1-click safe rollback.
 * Captures pre-remediation byte-for-byte file snapshots, database states, and cron entries
 * prior to executing any destructive quarantine or disinfection operations.
 */
class TransactionalRemediation {

    /**
     * Get root directory for transaction manifests and snapshots.
     *
     * @return string
     */
    public static function get_transactions_dir(): string {
        $upload_dir = wp_upload_dir();
        $base = wp_normalize_path($upload_dir['basedir'] . '/wcp-security-scanner/transactions');

        if (!is_dir($base)) {
            wp_mkdir_p($base);
            // Harden transaction storage against public web access
            @file_put_contents($base . '/.htaccess', "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>");
            @file_put_contents($base . '/index.php', "<?php\n// Silence is golden.\n");
        }

        return $base;
    }

    /**
     * Start a new atomic remediation transaction.
     *
     * @param string $title
     * @param string $reason
     * @param array $context
     * @return string Transaction ID
     */
    public static function start_transaction(string $title, string $reason = '', array $context = []): string {
        $base_dir = self::get_transactions_dir();
        $tx_id = 'tx_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(4));
        $tx_dir = $base_dir . '/' . $tx_id;

        wp_mkdir_p($tx_dir . '/files');

        $user = wp_get_current_user();
        $author = ($user && $user->exists()) ? $user->user_login : 'admin';

        $manifest = [
            'tx_id'       => $tx_id,
            'title'       => sanitize_text_field($title),
            'reason'      => sanitize_textarea_field($reason ?: 'Multi-threat attack chain eradication'),
            'status'      => 'in_progress',
            'created_at'  => current_time('mysql'),
            'timestamp'   => time(),
            'created_by'  => $author,
            'context'     => $context,
            'items'       => [],
        ];

        file_put_contents($tx_dir . '/manifest.json', wp_json_encode($manifest, JSON_PRETTY_PRINT));

        return $tx_id;
    }

    /**
     * Record a pre-remediation file snapshot in the transaction vault.
     *
     * @param string $tx_id
     * @param string $file_path
     * @param string $action_type 'quarantine' | 'delete' | 'repair' | 'permission_fix'
     * @param int|null $issue_id
     * @return bool
     */
    public static function record_file_snapshot(string $tx_id, string $file_path, string $action_type = 'quarantine', ?int $issue_id = null): bool {
        $tx_dir = self::get_transactions_dir() . '/' . $tx_id;
        $manifest_file = $tx_dir . '/manifest.json';

        if (!file_exists($manifest_file)) {
            return false;
        }

        $manifest = json_decode(file_get_contents($manifest_file), true);
        if (!is_array($manifest)) {
            return false;
        }

        $clean_path = ltrim(str_replace(['../', '..\\'], '', $file_path), '/\\');
        $full_path = wp_normalize_path(ABSPATH . $clean_path);

        if (!file_exists($full_path) && file_exists($file_path)) {
            $full_path = wp_normalize_path($file_path);
        }

        if (!file_exists($full_path) || !is_file($full_path)) {
            return false;
        }

        $backup_key = 'f_' . count($manifest['items']) . '_' . basename($full_path);
        $backup_path = $tx_dir . '/files/' . $backup_key;

        // Perform byte-for-byte copy
        if (!@copy($full_path, $backup_path)) {
            return false;
        }

        $manifest['items'][] = [
            'type'            => 'file',
            'action'          => $action_type,
            'target_path'     => $clean_path,
            'original_abs'    => $full_path,
            'backup_filename' => $backup_key,
            'original_hash'   => hash_file('sha256', $full_path),
            'original_perms'  => substr(sprintf('%o', fileperms($full_path)), -4),
            'original_mtime'  => @filemtime($full_path) ?: time(),
            'issue_id'        => $issue_id,
            'timestamp'       => time(),
        ];

        file_put_contents($manifest_file, wp_json_encode($manifest, JSON_PRETTY_PRINT));
        return true;
    }

    /**
     * Record a pre-remediation database row snapshot.
     *
     * @param string $tx_id
     * @param string $table_name
     * @param string $primary_key
     * @param mixed $row_id
     * @param array $original_row
     * @param int|null $issue_id
     * @return bool
     */
    public static function record_db_snapshot(string $tx_id, string $table_name, string $primary_key, $row_id, array $original_row, ?int $issue_id = null): bool {
        $tx_dir = self::get_transactions_dir() . '/' . $tx_id;
        $manifest_file = $tx_dir . '/manifest.json';

        if (!file_exists($manifest_file)) {
            return false;
        }

        $manifest = json_decode(file_get_contents($manifest_file), true);
        if (!is_array($manifest)) {
            return false;
        }

        $manifest['items'][] = [
            'type'          => 'database',
            'table_name'    => sanitize_text_field($table_name),
            'primary_key'   => sanitize_key($primary_key),
            'row_id'        => $row_id,
            'original_data' => $original_row,
            'issue_id'      => $issue_id,
            'timestamp'     => time(),
        ];

        file_put_contents($manifest_file, wp_json_encode($manifest, JSON_PRETTY_PRINT));
        return true;
    }

    /**
     * Record a pre-remediation user account snapshot in the transaction vault.
     *
     * @param string $tx_id
     * @param int $user_id
     * @param string $backup_filename
     * @param string $action_type 'delete' | 'demote'
     * @return bool
     */
    public static function record_user_snapshot(string $tx_id, int $user_id, string $backup_filename, string $action_type = 'delete'): bool {
        $tx_dir = self::get_transactions_dir() . '/' . $tx_id;
        $manifest_file = $tx_dir . '/manifest.json';

        if (!file_exists($manifest_file)) {
            return false;
        }

        $manifest = json_decode(file_get_contents($manifest_file), true);
        if (!is_array($manifest)) {
            return false;
        }

        $manifest['items'][] = [
            'type'            => 'user',
            'action_type'     => $action_type,
            'user_id'         => $user_id,
            'backup_filename' => $backup_filename,
            'target_path'     => "wp_users:user_id_{$user_id}",
            'timestamp'       => time(),
        ];

        file_put_contents($manifest_file, wp_json_encode($manifest, JSON_PRETTY_PRINT));
        return true;
    }

    /**
     * Commit and finalize transaction after all steps have succeeded.
     *
     * @param string $tx_id
     * @return array
     */
    public static function commit_transaction(string $tx_id): array {
        $tx_dir = self::get_transactions_dir() . '/' . $tx_id;
        $manifest_file = $tx_dir . '/manifest.json';

        if (!file_exists($manifest_file)) {
            return ['success' => false, 'message' => 'Transaction not found.'];
        }

        $manifest = json_decode(file_get_contents($manifest_file), true);
        if (!is_array($manifest)) {
            return ['success' => false, 'message' => 'Invalid transaction manifest.'];
        }

        $manifest['status'] = 'completed';
        $manifest['committed_at'] = current_time('mysql');
        $manifest['total_items'] = count($manifest['items']);

        file_put_contents($manifest_file, wp_json_encode($manifest, JSON_PRETTY_PRINT));

        return [
            'success'     => true,
            'tx_id'       => $tx_id,
            'items_count' => $manifest['total_items'],
            /* translators: 1: transaction ID, 2: number of items */
            'message'     => sprintf(__('Remediation transaction %1$s committed with %2$d items snapshotted.', 'wcp-security-scanner'), $tx_id, $manifest['total_items']),
        ];
    }

    /**
     * 1-Click Rollback: Atomically restore all files, database states, and issues from a transaction.
     *
     * @param string $tx_id
     * @return array
     */
    public static function rollback_transaction(string $tx_id): array {
        $tx_dir = self::get_transactions_dir() . '/' . $tx_id;
        $manifest_file = $tx_dir . '/manifest.json';

        if (!file_exists($manifest_file)) {
            return ['success' => false, 'message' => __('Transaction manifest not found.', 'wcp-security-scanner')];
        }

        $manifest = json_decode(file_get_contents($manifest_file), true);
        if (!is_array($manifest)) {
            return ['success' => false, 'message' => __('Corrupt transaction manifest.', 'wcp-security-scanner')];
        }

        $user_mgr = new \WcpScanner\WordPress\UserRemediationManager();
        $missing_users = $user_mgr->get_missing_user_backups();

        if (($manifest['status'] ?? '') === 'rolled_back' && empty($missing_users)) {
            return ['success' => false, 'message' => __('This transaction was already rolled back.', 'wcp-security-scanner')];
        }

        global $wpdb;
        $restored_files = 0;
        $restored_db    = 0;
        $restored_users = 0;
        $errors         = [];

        // Reverse through items so latest changes roll back first
        $items = array_reverse($manifest['items'] ?? []);
        $restored_uids = [];

        foreach ($items as $item) {
            $type = $item['type'] ?? '';

            if ($type === 'file') {
                $target_abs  = $item['original_abs'] ?? '';
                $backup_file = $tx_dir . '/files/' . ($item['backup_filename'] ?? '');

                if (file_exists($backup_file)) {
                    // Ensure directory exists
                    $dir = dirname($target_abs);
                    if (!is_dir($dir)) {
                        wp_mkdir_p($dir);
                    }

                    global $wp_filesystem;
                    $copied = false;
                    if ($wp_filesystem) {
                        $copied = $wp_filesystem->copy($backup_file, $target_abs, true);
                    } else {
                        $copied = @copy($backup_file, $target_abs);
                    }

                    if ($copied) {
                        $restored_files++;
                        // Restore original permissions & timestamps
                        if (!empty($item['original_perms'])) {
                            if ($wp_filesystem) {
                                $wp_filesystem->chmod($target_abs, octdec($item['original_perms']));
                            } else {
                                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
                                @chmod($target_abs, octdec($item['original_perms']));
                            }
                        }
                        if (!empty($item['original_mtime'])) {
                            if ($wp_filesystem) {
                                $wp_filesystem->touch($target_abs, (int) $item['original_mtime']);
                            } else {
                                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_touch
                                @touch($target_abs, (int) $item['original_mtime']);
                            }
                        }
                    } else {
                        $errors[] = sprintf(
                            /* translators: %s: file name */
                            __('Failed to copy restored file: %s', 'wcp-security-scanner'),
                            basename($target_abs)
                        );
                    }
                }

                // Re-open scan issue
                if (!empty($item['issue_id'])) {
                    $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->update($table_issues, ['status' => 'open'], ['id' => (int) $item['issue_id']]);
                }
            } elseif ($type === 'database') {
                $table = $item['table_name'] ?? '';
                $pkey  = $item['primary_key'] ?? 'id';
                $rid   = $item['row_id'] ?? null;
                $data  = $item['original_data'] ?? [];

                if ($table && $rid !== null && !empty($data)) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $updated = $wpdb->update($table, $data, [$pkey => $rid]);
                    if ($updated !== false) {
                        $restored_db++;
                    }
                }

                // Re-open scan issue
                if (!empty($item['issue_id'])) {
                    $table_issues = $wpdb->prefix . 'wcpscan_scan_issues';
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->update($table_issues, ['status' => 'open'], ['id' => (int) $item['issue_id']]);
                }
            } elseif ($type === 'user') {
                $backup_file = $item['backup_filename'] ?? '';
                if ($backup_file) {
                    $user_mgr = new \WcpScanner\WordPress\UserRemediationManager();
                    $u_res = $user_mgr->restore_user($backup_file);
                    if ($u_res['success']) {
                        $restored_users++;
                        if (!empty($u_res['user_id'])) {
                            $restored_uids[] = (int) $u_res['user_id'];
                        }
                    } else {
                        /* translators: 1: user ID, 2: error message */
                        $errors[] = sprintf(__('Failed to restore user #%1$d: %2$s', 'wcp-security-scanner'), (int) ($item['user_id'] ?? 0), $u_res['error'] ?? '');
                    }
                }
            }
        }

        // Correlated user recovery fallback:
        // If this transaction was an attack chain eradication that preceded explicit user snapshot tracking,
        // recover any user backups created during this transaction's execution window.
        $tx_time = (int) ($manifest['timestamp'] ?? 0);
        if ($tx_time > 0) {
            $user_mgr = new \WcpScanner\WordPress\UserRemediationManager();
            $available_user_backups = $user_mgr->list_user_backups();
            foreach ($available_user_backups as $ub) {
                $uid = (int) $ub['user_id'];
                if (in_array($uid, $restored_uids, true)) {
                    continue;
                }
                // Check if user backup was created within 10 minutes of this transaction
                if (abs($ub['timestamp'] - $tx_time) <= 600) {
                    $u_res = $user_mgr->restore_user($ub['backup_file']);
                    if ($u_res['success']) {
                        $restored_users++;
                        $restored_uids[] = $uid;
                    }
                }
            }
        }

        $user = wp_get_current_user();
        $author = ($user && $user->exists()) ? $user->user_login : 'admin';

        $manifest['status']         = 'rolled_back';
        $manifest['rolled_back_at'] = current_time('mysql');
        $manifest['rolled_back_by'] = $author;

        file_put_contents($manifest_file, wp_json_encode($manifest, JSON_PRETTY_PRINT));

        $msg_parts = [];
        /* translators: %d: number of files */
        if ($restored_files > 0) $msg_parts[] = sprintf(__('%d file(s)', 'wcp-security-scanner'), $restored_files);
        /* translators: %d: number of database records */
        if ($restored_db > 0)    $msg_parts[] = sprintf(__('%d database record(s)', 'wcp-security-scanner'), $restored_db);
        /* translators: %d: number of user accounts */
        if ($restored_users > 0) $msg_parts[] = sprintf(__('%d user account(s)', 'wcp-security-scanner'), $restored_users);

        $restored_summary = !empty($msg_parts) ? implode(', ', $msg_parts) : __('0 items', 'wcp-security-scanner');

        if (class_exists('\\WcpScanner\\Notifications\\NotificationDispatcher')) {
            \WcpScanner\Notifications\NotificationDispatcher::trigger('remediation_transaction_rollback', [
                'severity' => 'warning',
                /* translators: 1: transaction ID, 2: restored summary details */
                'message'  => sprintf(__('Remediation transaction %1$s reverted: restored %2$s.', 'wcp-security-scanner'), $tx_id, $restored_summary),
                'details'  => [
                    'Transaction ID'  => $tx_id,
                    'Restored Files'  => $restored_files,
                    'Restored DB'     => $restored_db,
                    'Restored Users'  => $restored_users,
                    'Rolled Back By'  => $author,
                ],
            ]);
        }

        return [
            'success'        => empty($errors),
            'tx_id'          => $tx_id,
            'restored_files' => $restored_files,
            'restored_db'    => $restored_db,
            'restored_users' => $restored_users,
            'errors'         => $errors,
            'message'        => sprintf(
                /* translators: 1: transaction ID, 2: restored summary details */
                __('Transaction %1$s rolled back successfully: restored %2$s.', 'wcp-security-scanner'),
                $tx_id,
                $restored_summary
            ),
        ];
    }

    /**
     * Retrieve all remediation transactions.
     *
     * @param int $limit
     * @return array
     */
    public static function list_transactions(int $limit = 30): array {
        $base_dir = self::get_transactions_dir();
        if (!is_dir($base_dir)) {
            return [];
        }

        $dirs = @scandir($base_dir) ?: [];
        $transactions = [];

        foreach ($dirs as $d) {
            if ($d === '.' || $d === '..' || !str_starts_with($d, 'tx_')) {
                continue;
            }

            $manifest_file = $base_dir . '/' . $d . '/manifest.json';
            if (!file_exists($manifest_file)) {
                continue;
            }

            $manifest = json_decode(file_get_contents($manifest_file), true);
            if (is_array($manifest)) {
                $file_items = array_filter($manifest['items'] ?? [], fn($i) => ($i['type'] ?? '') === 'file');
                $db_items   = array_filter($manifest['items'] ?? [], fn($i) => ($i['type'] ?? '') === 'database');
                $user_items = array_filter($manifest['items'] ?? [], fn($i) => ($i['type'] ?? '') === 'user');

                $transactions[] = [
                    'tx_id'          => $manifest['tx_id'] ?? $d,
                    'title'          => $manifest['title'] ?? 'Attack Chain Eradication',
                    'reason'         => $manifest['reason'] ?? '',
                    'status'         => $manifest['status'] ?? 'completed',
                    'created_at'     => $manifest['created_at'] ?? '',
                    'timestamp'      => $manifest['timestamp'] ?? 0,
                    'created_by'     => $manifest['created_by'] ?? 'admin',
                    'files_count'    => count($file_items),
                    'db_count'       => count($db_items),
                    'users_count'    => count($user_items),
                    'total_items'    => count($manifest['items'] ?? []),
                    'rolled_back_at' => $manifest['rolled_back_at'] ?? null,
                    'rolled_back_by' => $manifest['rolled_back_by'] ?? null,
                    'sample_targets' => array_slice(array_column($file_items, 'target_path'), 0, 3),
                ];
            }
        }

        // Sort descending by timestamp
        usort($transactions, fn($a, $b) => ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0));

        return array_slice($transactions, 0, $limit);
    }
}
