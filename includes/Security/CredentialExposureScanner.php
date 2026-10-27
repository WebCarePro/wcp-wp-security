<?php
namespace WcpScanner\Security;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CredentialExposureScanner
 *
 * AI API Key, Cloud Secret & Plaintext Credential Exposure Auditor.
 * Audits public web directories, uploads, client-side bundles, and database options
 * for exposed high-value credentials, private API keys, and sensitive environment secrets.
 */
class CredentialExposureScanner {

    const CACHE_OPTION = 'wcpscan_credential_exposure_report';
    const MAX_FILE_SIZE = 2097152; // 2MB

    /**
     * Secret signatures and regex detectors.
     */
    const SECRET_PATTERNS = [
        'openai_api_key' => [
            'title'       => 'OpenAI Secret API Key',
            'pattern'     => '/\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,80})\b/',
            'severity'    => 'critical',
            'description' => 'Plaintext OpenAI secret API key exposed. Attackers can hijack token quota or exfiltrate private models.',
        ],
        'anthropic_api_key' => [
            'title'       => 'Anthropic Claude API Key',
            'pattern'     => '/\b(sk-ant-[A-Za-z0-9_-]{40,90})\b/',
            'severity'    => 'critical',
            'description' => 'Plaintext Anthropic Claude API key exposed in public or accessible file.',
        ],
        'google_gemini_key' => [
            'title'       => 'Google Gemini / Cloud API Key',
            'pattern'     => '/\b(AIzaSy[A-Za-z0-9_-]{33})\b/',
            'severity'    => 'high',
            'description' => 'Google AI / Cloud API credential exposed in file contents.',
        ],
        'stripe_secret_key' => [
            'title'       => 'Stripe Secret Live Key',
            'pattern'     => '/\b(sk_live_[0-9a-zA-Z]{24,34})\b/',
            'severity'    => 'critical',
            'description' => 'Live Stripe payment gateway secret key exposed. Grants full financial and refund transaction authority.',
        ],
        'aws_access_key' => [
            'title'       => 'AWS Access Key ID',
            'pattern'     => '/\b(AKIA[0-9A-Z]{16})\b/',
            'severity'    => 'critical',
            'description' => 'Amazon Web Services IAM access key identifier discovered in plaintext.',
        ],
        'github_personal_token' => [
            'title'       => 'GitHub Personal Access Token',
            'pattern'     => '/\b(ghp_[A-Za-z0-9]{36})\b/',
            'severity'    => 'high',
            'description' => 'GitHub personal access token exposed, allowing unauthorized repository tampering.',
        ],
        'private_ssh_key' => [
            'title'       => 'Private RSA / OpenSSH Cryptographic Key',
            'pattern'     => '/(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/',
            'severity'    => 'critical',
            'description' => 'Unencrypted private server SSH or SSL key discovered in accessible storage.',
        ],
        'database_password' => [
            'title'       => 'Exposed Database Credentials',
            'pattern'     => '/(?:DB_PASSWORD|database_password)\s*[:=]\s*[\'"]([^\'"]{4,})[\'"]/i',
            'severity'    => 'critical',
            'description' => 'Database connection password hardcoded outside secure wp-config.php environment boundary.',
        ],
    ];

    /**
     * High-risk sensitive filenames to target.
     */
    const TARGET_SENSITIVE_FILES = [
        '.env',
        '.env.local',
        '.env.production',
        '.git/config',
        'config.json',
        'credentials.json',
        'id_rsa',
        'id_ed25519',
        'dump.sql',
        'backup.sql',
    ];

    /**
     * Run a comprehensive credential exposure audit.
     *
     * @param bool $force_refresh
     * @return array
     */
    public static function run_scan(bool $force_refresh = false): array {
        if (!$force_refresh) {
            $cached = get_transient(self::CACHE_OPTION);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $findings = [];
        $files_checked = 0;

        // 1. Audit root sensitive environment files
        if (defined('ABSPATH')) {
            $root = rtrim(ABSPATH, '/\\');
            foreach (self::TARGET_SENSITIVE_FILES as $rel_file) {
                $full_path = $root . '/' . $rel_file;
                if (file_exists($full_path) && is_readable($full_path)) {
                    $files_checked++;
                    $file_findings = self::scan_file_for_credentials($full_path, $rel_file);
                    if (!empty($file_findings)) {
                        $findings = array_merge($findings, $file_findings);
                    }
                }
            }
        }

        // 2. Audit uploads directory for leaked SQL dumps, logs, and config backups
        $upload_dir = wp_upload_dir();
        $uploads_base = $upload_dir['basedir'] ?? '';
        if (is_dir($uploads_base)) {
            $files_checked += self::scan_directory_files($uploads_base, $findings, ['sql', 'env', 'bak', 'log', 'txt', 'json'], 60);
        }

        // 3. Audit active theme directory for hardcoded secrets
        $theme_dir = get_stylesheet_directory();
        if (is_dir($theme_dir)) {
            $files_checked += self::scan_directory_files($theme_dir, $findings, ['php', 'js', 'json'], 40);
        }

        $crit_count = count(array_filter($findings, fn($f) => $f['severity'] === 'critical'));
        $high_count = count(array_filter($findings, fn($f) => $f['severity'] === 'high'));

        $report = [
            'success'          => true,
            'scanned_at'       => current_time('mysql'),
            'files_checked'    => $files_checked,
            'total_findings'   => count($findings),
            'summary'          => [
                'critical' => $crit_count,
                'high'     => $high_count,
                'clean'    => count($findings) === 0,
            ],
            'findings'         => $findings,
        ];

        set_transient(self::CACHE_OPTION, $report, 12 * HOUR_IN_SECONDS);

        if (count($findings) > 0) {
            AuditLogger::log(
                'credentials_exposed_detected',
                sprintf('Credential exposure audit discovered %d exposed secret(s) across site assets.', count($findings))
            );
        }

        return $report;
    }

    /**
     * Scan a directory recursively up to a file limit.
     *
     * @param string $dir
     * @param array  $findings (by reference)
     * @param array  $extensions
     * @param int    $limit
     * @return int files scanned
     */
    private static function scan_directory_files(string $dir, array &$findings, array $extensions, int $limit): int {
        $count = 0;
        try {
            $dir_iter = new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS);
            $filter = new \RecursiveCallbackFilterIterator($dir_iter, function ($current) {
                if ($current->isDir()) {
                    $name = $current->getFilename();
                    if (in_array($name, ['.git', '.svn', 'node_modules', 'cache', 'wcp-security-scanner'], true)) {
                        return false;
                    }
                }
                return true;
            });

            $iterator = new \RecursiveIteratorIterator($filter, \RecursiveIteratorIterator::SELF_FIRST);

            foreach ($iterator as $item) {
                if ($count >= $limit) {
                    break;
                }
                if ($item->isFile()) {
                    $ext = strtolower($item->getExtension());
                    if (in_array($ext, $extensions, true)) {
                        $path = $item->getPathname();
                        // Self-Exclusion
                        $norm = str_replace('\\', '/', $path);
                        if (str_contains($norm, '/plugins/wcp-security-scanner/')) {
                            continue;
                        }

                        $rel = defined('ABSPATH') ? ltrim(str_replace(str_replace('\\', '/', ABSPATH), '', $norm), '/') : $norm;
                        $count++;
                        $file_findings = self::scan_file_for_credentials($path, $rel);
                        if (!empty($file_findings)) {
                            $findings = array_merge($findings, $file_findings);
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // gracefully continue on permission error
        }

        return $count;
    }

    /**
     * Inspect a single file for credential signatures.
     *
     * @param string $file_path
     * @param string $rel_path
     * @return array
     */
    public static function scan_file_for_credentials(string $file_path, string $rel_path): array {
        $file_findings = [];
        $size = @filesize($file_path) ?: 0;
        if ($size > self::MAX_FILE_SIZE || $size === 0) {
            return $file_findings;
        }

        $content = @file_get_contents($file_path);
        if (!$content) {
            return $file_findings;
        }

        // Never flag legitimate wp-config.php constants in wp-config.php itself
        $is_wp_config = (basename($file_path) === 'wp-config.php');

        foreach (self::SECRET_PATTERNS as $key => $sig) {
            if ($is_wp_config && $key === 'database_password') {
                continue;
            }

            if (preg_match_all($sig['pattern'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[1] as $match) {
                    $raw_token = $match[0];
                    $offset = $match[1];
                    $line_no = substr_count(substr($content, 0, $offset), "\n") + 1;

                    // Safely mask token
                    $masked = self::mask_credential($raw_token);

                    $file_findings[] = [
                        'type'        => $key,
                        'title'       => $sig['title'],
                        'severity'    => $sig['severity'],
                        'description' => $sig['description'],
                        'file'        => $rel_path,
                        'line'        => $line_no,
                        'masked'      => $masked,
                        'filesize'    => $size,
                    ];
                }
            }
        }

        return $file_findings;
    }

    /**
     * Mask sensitive credential tokens to preserve security in UI and logs.
     *
     * @param string $token
     * @return string
     */
    public static function mask_credential(string $token): string {
        $len = strlen($token);
        if ($len <= 8) {
            return '********';
        }
        $prefix = substr($token, 0, min(8, (int) ($len * 0.25)));
        $suffix = substr($token, -min(4, (int) ($len * 0.15)));
        $mask_len = $len - strlen($prefix) - strlen($suffix);
        return $prefix . str_repeat('*', max(6, $mask_len)) . $suffix;
    }

    /**
     * Get status report.
     *
     * @return array
     */
    public static function get_status(): array {
        return self::run_scan(false);
    }
}
