<?php
namespace WcpScanner\Filesystem;

use WcpScanner\Findings\Finding;

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
     * Common image and media extensions subject to deep forensic inspection.
     */
    private $image_extensions = [
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg', 'svgz', 'tiff', 'tif', 'avif'
    ];

    /**
     * Document and other non-executable media extensions.
     */
    private $document_extensions = [
        'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'
    ];

    /**
     * Scan the WordPress uploads directory for any scripts or suspicious files.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];

        $upload_dir_info = wp_upload_dir();
        $uploads_path = !empty($upload_dir_info['basedir']) ? $upload_dir_info['basedir'] : '';

        if (empty($uploads_path) || !is_dir($uploads_path)) {
            return $findings;
        }

        try {
            $flags = \FilesystemIterator::KEY_AS_PATHNAME | \FilesystemIterator::CURRENT_AS_FILEINFO | \FilesystemIterator::SKIP_DOTS;
            $dir_iterator = new \RecursiveDirectoryIterator($uploads_path, $flags);
            $iterator = new \RecursiveIteratorIterator(
                $dir_iterator,
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD // Silently skip unreadable subdirectories without crashing
            );

            $normalized_uploads = str_replace('\\', '/', rtrim($uploads_path, '/\\') . '/');
            $files_inspected = 0;
            $max_files_limit = 5000; // Safeguard against runaway memory/execution time in enormous media libraries
            $monitor = new \WcpScanner\Resource\ResourceMonitor(70, 20, 'balanced');

            foreach ($iterator as $item) {
                // Adaptive breathing & memory headroom check before each file
                if ($monitor->throttle_and_check()) {
                    break;
                }

                try {
                    if (!$item->isFile()) {
                        continue;
                    }
                } catch (\Throwable $e) {
                    continue;
                }

                $files_inspected++;
                if ($files_inspected > $max_files_limit) {
                    break;
                }

                $real_path = $item->getPathname();
                $normalized_path = str_replace('\\', '/', $real_path);

                // Exclude plugin's internal secure storage (quarantine, logs, backups, fim-vault, etc.) and common cache directories
                if (preg_match('#/(wcp-security-scanner|wcp-scanner-quarantine|wcp-vault|wcp-waf|wcp-quarantine|node_modules|\.git|updraft|wfcache)/#i', $normalized_path)) {
                    continue;
                }

                // Check user configured excluded paths
                if (\WcpScanner\System\SettingsManager::is_path_excluded($normalized_path)) {
                    continue;
                }

                $rel_path = str_replace($normalized_uploads, '', $normalized_path);
                $basename = $item->getBasename();
                $lower_name = strtolower($basename);
                $ext = strtolower($item->getExtension());
                $file_size = (int) @$item->getSize();

                // 1. Direct prohibited executable / shell extension
                if (in_array($ext, $this->executable_extensions, true)) {
                    // Check if harmless WordPress directory listing prevention placeholder
                    if (($lower_name === 'index.php' || $lower_name === 'index.html' || $lower_name === 'index.htm') && \WcpScanner\System\SettingsManager::is_safe_directory_index($real_path)) {
                        continue;
                    }

                    // Check if legitimate, verified plugin cache (e.g. MailPoet Twig template cache) with 0 malware indicators
                    if (\WcpScanner\System\SettingsManager::is_legitimate_uploads_cache_file($real_path)) {
                        continue;
                    }

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
                    $content = @file_get_contents($real_path, false, null, 0, 2048) ?: '';
                    // Legitimate security plugins (Forminator, WooCommerce, WPForms) place protective .htaccess files
                    // to prevent PHP execution (e.g. php_flag engine off, Options -ExecCGI, Deny from all, RemoveHandler).
                    // Flag ONLY if it actually overrides/enables PHP execution for media/non-php files or drops backdoors.
                    $is_malicious_override = (bool) preg_match('/(AddType|AddHandler|SetHandler)\s+application\/x-httpd-php|\b(auto_prepend_file|auto_append_file)\b|php_flag\s+engine\s+(?:on|1)/i', $content);
                    $is_protective = (
                        stripos($content, 'deny from all') !== false ||
                        stripos($content, 'require all denied') !== false ||
                        stripos($content, 'php_flag engine off') !== false ||
                        stripos($content, 'Options -ExecCGI') !== false ||
                        stripos($content, 'Options -Indexes') !== false ||
                        stripos($content, 'RemoveHandler') !== false ||
                        stripos($content, 'SetHandler default-handler') !== false
                    );

                    if ($is_malicious_override || !$is_protective) {
                        $findings[] = new Finding([
                            'engine'       => 'uploads-scanner',
                            'type'         => 'server_override_in_uploads',
                            'severity'     => 'high',
                            'confidence'   => 95,
                            'file_path'    => $real_path,
                            'code_snippet' => self::sanitize_utf8(substr($content, 0, 250)),
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

                // 4. Binary Executable Magic Bytes Spoofing (e.g. Windows PE or Linux ELF disguised as an image)
                if (in_array($ext, $this->image_extensions, true) || in_array($ext, $this->document_extensions, true)) {
                    $magic_finding = $this->check_binary_magic_bytes($real_path, $basename, $ext, $rel_path);
                    if ($magic_finding) {
                        $findings[] = $magic_finding;
                        continue;
                    }
                }

                // 5. SVG Image Security Audit (XSS, JavaScript, embedded PHP)
                if ($ext === 'svg' || $ext === 'svgz') {
                    $svg_finding = $this->check_svg_file($real_path, $basename, $rel_path, $file_size);
                    if ($svg_finding) {
                        $findings[] = $svg_finding;
                        continue;
                    }
                }

                // 6. Deep Forensic Inspection for Disguised PHP Code / Image Polyglots
                if (in_array($ext, $this->image_extensions, true) || in_array($ext, $this->document_extensions, true)) {
                    $polyglot_finding = $this->check_embedded_php_payload($real_path, $basename, $ext, $rel_path, $file_size);
                    if ($polyglot_finding) {
                        $findings[] = $polyglot_finding;
                        continue;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Suppress media inspection exceptions silently and return collected findings
        }

        return $findings;
    }

    /**
     * Checks if a media/image file is actually a raw compiled binary executable.
     */
    private function check_binary_magic_bytes($real_path, $basename, $ext, $rel_path) {
        $header = @file_get_contents($real_path, false, null, 0, 16);
        if ($header === false || strlen($header) < 2) {
            return null;
        }

        // Windows PE executable (MZ header)
        if (substr($header, 0, 2) === "MZ") {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => 'Magic Header: MZ (Windows PE Executable / DLL)',
                'description'  => "Binary executable disguised as media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Windows PE executable signature 'MZ' but uses '.{$ext}' extension."
            ]);
        }

        // Linux ELF binary executable (\x7FELF)
        if (substr($header, 0, 4) === "\x7fELF") {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => 'Magic Header: 7F 45 4C 46 (\x7fELF Linux Executable / Shared Object)',
                'description'  => "Linux ELF binary executable disguised as media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Linux ELF binary signature '\\x7fELF' but uses '.{$ext}' extension."
            ]);
        }

        // macOS Mach-O binaries (\xCA\xFE\xBA\xBE, \xCF\xFA\xED\xFE, \xCE\xFA\xED\xFE)
        $macho_signatures = ["\xca\xfe\xba\xbe", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe"];
        if (in_array(substr($header, 0, 4), $macho_signatures, true)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => 'Magic Header: Mach-O Binary Executable',
                'description'  => "Mach-O binary executable disguised as media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Mach-O binary signature but uses '.{$ext}' extension."
            ]);
        }

        // Shell script shebang in an image file (e.g. #!/bin/bash, #!/bin/sh, #!/usr/bin/env)
        if (substr($header, 0, 2) === '#!' && preg_match('/^#!\s*\/(bin|usr)/i', $header)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => trim($header),
                'description'  => "Shell script shebang discovered in media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Unix shell script shebang '#!' but uses '.{$ext}' extension."
            ]);
        }

        return null;
    }

    /**
     * Inspects SVG vector image files for embedded XSS scripts and malicious executable handlers.
     */
    private function check_svg_file($real_path, $basename, $rel_path, $file_size) {
        if ($file_size > 2 * 1024 * 1024) { // Limit to 2MB
            return null;
        }

        $content = @file_get_contents($real_path);
        if ($content === false || empty($content)) {
            return null;
        }

        // Decompress if svgz (gzipped SVG)
        if (substr($content, 0, 2) === "\x1f\x8b" && function_exists('gzdecode')) {
            $decompressed = @gzdecode($content);
            if ($decompressed !== false) {
                $content = $decompressed;
            }
        }

        // Check for embedded active PHP
        if (preg_match('/(<\?php|<\?=\s*)/i', $content, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'disguised_php_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => $this->extract_context_snippet($content, $m[0]),
                'description'  => "SVG image '{$basename}' contains active PHP execution code tags.",
                'evidence'     => "Embedded PHP opening tag '{$m[0]}' found inside SVG XML structure."
            ]);
        }

        // Check for script tags in SVG content
        if (preg_match('/<script\b[^>]*>/i', $content, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 98,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains executable script element leading to Stored Cross-Site Scripting (XSS).",
                'evidence'     => "Found active script element in SVG vector image file."
            ]);
        }

        // Check for javascript: URI in href, src, xlink:href
        if (preg_match('/(?:href|src|xlink:href)\s*=\s*[\'"]\s*javascript:[^\'"]+/i', $content, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 95,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains javascript: pseudo-protocol handler.",
                'evidence'     => "Found 'javascript:' payload in SVG attribute."
            ]);
        }

        // Check for inline event handlers: onload=, onerror=, onmouseover=, onclick=
        if (preg_match('/\b(onload|onerror|onclick|onmouseover|onfocus|onblur)\s*=\s*[\'"][^\'"]+/i', $content, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'high',
                'confidence'   => 92,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains inline DOM event handler ({$m[1]}).",
                'evidence'     => "Found active inline DOM event handler '{$m[0]}' in SVG file."
            ]);
        }

        // Check for dangerous remote embedding tags: <foreignObject>, <iframe>, <embed>, <object>
        if (preg_match('/<(foreignObject|iframe|embed|object)\b[^>]*>/i', $content, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'high',
                'confidence'   => 90,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains HTML embedding tag (<{$m[1]}>).",
                'evidence'     => "Found '<{$m[1]}>' container inside SVG vector graphic."
            ]);
        }

        return null;
    }

    /**
     * Inspects media and image files for embedded or trailing PHP code polyglots.
     */
    private function check_embedded_php_payload($real_path, $basename, $ext, $rel_path, $file_size) {
        // Skip files > 10MB to maintain scanner speed and prevent memory issues
        if ($file_size > 10 * 1024 * 1024) {
            return null;
        }

        // True PHP polyglot webshells in images MUST contain a valid PHP opening tag with executable tokens.
        // Plain binary sequences in compressed PNG/WebP/JPEG can accidentally contain ASCII bytes for words like 'eval('
        // but can never execute in PHP without opening PHP tags (<?php or <?=).
        $php_pattern = '/<\?(?:php\s+[\s\S]{0,500}?(?:eval|assert|system|passthru|shell_exec|exec|base64_decode|\$_[A-Z]+|\$[a-zA-Z0-9_]+)|\=\s*[\s\S]{0,200}?(?:eval|assert|\$_[A-Z]+|\$[a-zA-Z0-9_]+))/i';

        // 1. Read header up to 8KB (covers image headers, EXIF Comment, IPTC, and head polyglots)
        $header = @file_get_contents($real_path, false, null, 0, 8192);
        if ($header === false || empty($header)) {
            return null;
        }

        $detected_pattern = null;
        $snippet = '';

        if (preg_match($php_pattern, $header, $m)) {
            $detected_pattern = $m[0];
            $snippet = $this->extract_context_snippet($header, $m[0]);
        }

        // 2. If file is larger than 8KB, check trailing 8KB (where attackers append webshells after JPEG \xFF\xD9 or PNG IEND)
        if (!$detected_pattern && $file_size > 8192) {
            $tail_offset = max(0, $file_size - 8192);
            $tail = @file_get_contents($real_path, false, null, $tail_offset, 8192);
            if ($tail !== false && preg_match($php_pattern, $tail, $m)) {
                $detected_pattern = $m[0];
                $snippet = $this->extract_context_snippet($tail, $m[0]);
            }
        }

        // 3. Masquerading full PHP script disguised with media extension (starts with <?php)
        if (!$detected_pattern && $file_size <= 128 * 1024) {
            if (preg_match('/^\s*<\?php/i', $header, $m)) {
                $detected_pattern = $m[0];
                $snippet = $this->extract_context_snippet($header, $m[0]);
            }
        }

        if ($detected_pattern) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'disguised_php_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 98,
                'file_path'    => $real_path,
                'code_snippet' => $snippet,
                'description'  => "Media file {$basename} in uploads contains embedded active PHP code or shell execution tokens.",
                'evidence'     => "Found active PHP execution token '{$detected_pattern}' inside .{$ext} media file."
            ]);
        }

        return null;
    }

    /**
     * Extracts a clean contextual snippet surrounding a pattern match.
     */
    private function extract_context_snippet($content, $match) {
        $pos = strpos($content, $match);
        if ($pos === false) {
            return self::sanitize_utf8(substr($content, 0, 200));
        }
        $start = max(0, $pos - 40);
        $length = min(strlen($content) - $start, 200);
        return self::sanitize_utf8(substr($content, $start, $length));
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
        return self::sanitize_utf8(substr($content, 0, 300));
    }

    /**
     * Sanitize any binary or malformed string into valid UTF-8 for JSON encoding and REST responses.
     *
     * @param mixed $input
     * @return string
     */
    public static function sanitize_utf8($input): string {
        if (!is_string($input) || $input === '') {
            return '';
        }

        // Convert non-printable bytes or invalid characters to UTF-8
        if (function_exists('mb_convert_encoding')) {
            $cleaned = mb_convert_encoding($input, 'UTF-8', 'UTF-8');
        } elseif (function_exists('iconv')) {
            $cleaned = @iconv('UTF-8', 'UTF-8//IGNORE', $input);
        } else {
            $cleaned = $input;
        }

        // Strip non-printable binary control codes except standard tabs/newlines
        $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', ' ', (string) $cleaned);

        return trim((string) $cleaned);
    }
}
