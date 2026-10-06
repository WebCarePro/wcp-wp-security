<?php
namespace WCP\Scanner\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class Rules {
    /**
     * Return malware heuristics and suspicious patterns.
     *
     * @return array
     */
    public static function get_patterns() {
        return [
            [
                'id'          => 'MAL-EVAL-BASE64',
                'severity'    => 'critical',
                'description' => 'Obfuscated execution: eval combined with base64_decode.',
                'pattern'     => '/eval\s*\(\s*base64_decode\s*\(/i',
            ],
            [
                'id'          => 'MAL-GZINFLATE-BASE64',
                'severity'    => 'critical',
                'description' => 'Decompression obfuscation: gzinflate combined with base64_decode.',
                'pattern'     => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
            ],
            [
                'id'          => 'MAL-SHELL-EXEC',
                'severity'    => 'high',
                'description' => 'System shell execution command detected (shell_exec, passthru, exec, popen, proc_open).',
                'pattern'     => '/\b(shell_exec|passthru|proc_open|popen)\s*\(/i',
            ],
            [
                'id'          => 'MAL-SUSPICIOUS-GLOBALS',
                'severity'    => 'high',
                'description' => 'Variable function call executing request payloads.',
                'pattern'     => '/\$(?:_POST|_GET|_REQUEST|_COOKIE)\s*\[[^\]]+\]\s*\(/i',
            ],
            [
                'id'          => 'MAL-PHP-BACKDOOR-TAG',
                'severity'    => 'high',
                'description' => 'Common web backdoor footprint (e.g. c99, r57, WSO, FilesMan).',
                'pattern'     => '/\b(c99shell|r57shell|WSO_VERSION|FilesMan|wso_password)\b/i',
            ],
            [
                'id'          => 'MAL-RAW-SYSTEM',
                'severity'    => 'high',
                'description' => 'Direct system call without proper sanitization wrappers.',
                'pattern'     => '/\bsystem\s*\(\s*\$(?:_GET|_POST|_REQUEST)/i',
            ],
            [
                'id'          => 'SUSP-HIDDEN-IFRAME',
                'severity'    => 'medium',
                'description' => 'Suspicious hidden iframe injection (zero width/height or negative styling).',
                'pattern'     => '/<iframe[^>]+(?:display:\s*none|width\s*=\s*["\']?0["\']?|height\s*=\s*["\']?0["\']?)/i',
            ]
        ];
    }
}
