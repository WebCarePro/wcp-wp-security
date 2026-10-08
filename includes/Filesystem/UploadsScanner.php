<?php
namespace WCP\Scanner\Filesystem;

use WCP\Scanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class UploadsScanner {

    /**
     * Dangerous executable and script extensions prohibited in media uploads.
     */
    private $executable_extensions = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc', 'hphp', 'pht',
        'sh', 'bash', 'zsh', 'ksh', 'csh', 'pl', 'cgi', 'py', 'rb',
        'exe', 'bat', 'cmd', 'com', 'bin', 'elf', 'so', 'dll', 'vbs', 'wsf', 'scr',
        'jsp', 'asp', 'aspx'
    ];

    /**
     * Scan the WordPress uploads directory for any scripts or suspicious files.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];

        $upload_dir_info = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
        $uploads_path = !empty($upload_dir_info['basedir']) ? $upload_dir_info['basedir'] : WP_CONTENT_DIR . '/uploads';

        if (!is_dir($uploads_path)) {
            return $findings;
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($uploads_path, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            $normalized_uploads = str_replace('\\', '/', rtrim($uploads_path, '/\\') . '/');

            foreach ($iterator as $item) {
                if (!$item->isFile()) {
                    continue;
                }

                $real_path = $item->getPathname();
                $normalized_path = str_replace('\\', '/', $real_path);
                $rel_path = str_replace($normalized_uploads, '', $normalized_path);
                $basename = $item->getBasename();
                $lower_name = strtolower($basename);
                $ext = strtolower($item->getExtension());

                // 1. Direct prohibited executable / shell extension
                if (in_array($ext, $this->executable_extensions, true)) {
                    $snippet = $this->extract_preview_snippet($real_path);
                    $findings[] = new Finding([
                        'engine'       => 'uploads-scanner',
                        'type'         => 'executable_in_uploads',
                        'severity'     => 'critical',
                        'confidence'   => 100,
                        'file_path'    => $real_path,
                        'code_snippet' => $snippet,
                        'description'  => "Dangerous executable script (.{$ext}) found inside WordPress uploads directory: {$rel_path}",
                        'evidence'     => "File extension '.{$ext}' is strictly forbidden in the media library."
                    ]);
                    continue;
                }

                // 2. Dangerous server overrides (.htaccess / web.config in uploads)
                if ($lower_name === '.htaccess' || $lower_name === 'web.config') {
                    $content = @file_get_contents($real_path, false, null, 0, 1024) ?: '';
                    // Allow .htaccess only if it restricts execution, otherwise flag as high risk
                    $is_protective = (stripos($content, 'deny from all') !== false || stripos($content, 'require all denied') !== false);
                    if (!$is_protective) {
                        $findings[] = new Finding([
                            'engine'       => 'uploads-scanner',
                            'type'         => 'server_override_in_uploads',
                            'severity'     => 'high',
                            'confidence'   => 95,
                            'file_path'    => $real_path,
                            'code_snippet' => substr($content, 0, 250),
                            'description'  => "Server configuration file '{$basename}' found inside uploads folder. Often used by attackers to override PHP execution restrictions.",
                            'evidence'     => "Found {$basename} with potential execution override in {$rel_path}"
                        ]);
                    }
                    continue;
                }

                // 3. Double extension check (e.g. image.php.jpg, photo.jpg.php, document.pdf.sh)
                if (preg_match('/\.(php[0-9]?|phtml|phar|sh|bash|cgi|pl|py|exe)\.([a-z0-9]+)$/i', $lower_name, $m)) {
                    $snippet = $this->extract_preview_snippet($real_path);
                    $findings[] = new Finding([
                        'engine'       => 'uploads-scanner',
                        'type'         => 'double_extension_in_uploads',
                        'severity'     => 'critical',
                        'confidence'   => 100,
                        'file_path'    => $real_path,
                        'code_snippet' => $snippet,
                        'description'  => "Disguised double-extension file found inside uploads: {$basename}. May bypass media validation on vulnerable web servers.",
                        'evidence'     => "Embedded script extension '.{$m[1]}' disguised with secondary extension '.{$m[2]}'"
                    ]);
                    continue;
                }

                // 4. Disguised PHP code inside non-PHP files (polyglot webshells in jpg/png/gif/txt)
                $media_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'txt', 'pdf', 'doc', 'docx'];
                if (in_array($ext, $media_extensions, true)) {
                    $header_bytes = @file_get_contents($real_path, false, null, 0, 2048);
                    if ($header_bytes !== false) {
                        if (preg_match('/<\?php|<\?=\s*|eval\s*\(|base64_decode\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(/i', $header_bytes)) {
                            $findings[] = new Finding([
                                'engine'       => 'uploads-scanner',
                                'type'         => 'disguised_php_in_uploads',
                                'severity'     => 'critical',
                                'confidence'   => 98,
                                'file_path'    => $real_path,
                                'code_snippet' => substr($header_bytes, 0, 200),
                                'description'  => "Media file {$basename} in uploads contains embedded active PHP code or shell execution tokens.",
                                'evidence'     => "Found active PHP execution tokens inside a .{$ext} file."
                            ]);
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            // Suppress media inspection exceptions silently
        }

        return $findings;
    }

    /**
     * Safely read a small text snippet from file for findings reporting.
     *
     * @param string $path
     * @return string|null
     */
    private function extract_preview_snippet($path) {
        $content = @file_get_contents($path, false, null, 0, 300);
        if ($content === false) {
            return null;
        }
        return substr($content, 0, 300);
    }
}
