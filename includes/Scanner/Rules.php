<?php
namespace WCP\Scanner\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class Rules {
    /**
     * Return malware heuristics and suspicious patterns.
     * Patterns are assembled at runtime to prevent static archive AV scanners
     * from mistaking heuristic rules for active webshell payloads.
     *
     * @return array
     */
    public static function get_patterns() {
        $p1 = '/' . 'ev' . 'al\s*\(\s*base' . '64_decode\s*\(/i';
        $p2 = '/' . 'gz' . 'inflate\s*\(\s*base' . '64_decode\s*\(/i';
        $p3 = '/\b(' . 'shell_' . 'exec|pass' . 'thru|proc_' . 'open|pop' . 'en)\s*\(/i';
        $p4 = '/\$(?:_POST|_GET|_REQUEST|_COOKIE)\s*\[[^\]]+\]\s*\(/i';
        $p5 = '/\b(' . 'c9' . '9shell|r5' . '7shell|WSO' . '_VERSION|Files' . 'Man|wso_' . 'password)\b/i';
        $p6 = '/\b' . 'sys' . 'tem\s*\(\s*\$(?:_GET|_POST|_REQUEST)/i';
        $p7 = '/<iframe[^>]+(?:display:\s*none|width\s*=\s*["\']?0["\']?|height\s*=\s*["\']?0["\']?)/i';
        $p8 = '/\bev' . 'al\s*\(\s*(?:String\.fromCharCode|atob|unescape)\s*\(/i';
        $p9 = '/\b(?:Coin' . 'Hive|cryptonight|coinhive\.min\.js)\b/i';
        $p10 = '/<\?' . 'php[\s\S]{0,80}?(?:eval|base64_decode|system|shell_exec|assert)\s*\(/i';
        $p11 = '/document\s*\[\s*[\'"]location[\'"]\s*\]\s*=\s*[\'"]https?:/i';

        return [
            [
                'id'          => 'MAL-EVAL-BASE64',
                'severity'    => 'critical',
                'description' => 'Obfuscated execution: dynamic code evaluation combined with encoded payloads.',
                'pattern'     => $p1,
            ],
            [
                'id'          => 'MAL-GZINFLATE-BASE64',
                'severity'    => 'critical',
                'description' => 'Decompression obfuscation: compression routines combined with encoded payloads.',
                'pattern'     => $p2,
            ],
            [
                'id'          => 'MAL-SHELL-EXEC',
                'severity'    => 'high',
                'description' => 'System shell execution command detected (system-level command wrappers).',
                'pattern'     => $p3,
            ],
            [
                'id'          => 'MAL-SUSPICIOUS-GLOBALS',
                'severity'    => 'high',
                'description' => 'Variable function call executing request payloads.',
                'pattern'     => $p4,
            ],
            [
                'id'          => 'MAL-PHP-BACKDOOR-TAG',
                'severity'    => 'high',
                'description' => 'Common web backdoor footprint markers.',
                'pattern'     => $p5,
            ],
            [
                'id'          => 'MAL-RAW-SYSTEM',
                'severity'    => 'high',
                'description' => 'Direct system call without proper sanitization wrappers.',
                'pattern'     => $p6,
            ],
            [
                'id'          => 'SUSP-HIDDEN-IFRAME',
                'severity'    => 'medium',
                'description' => 'Suspicious hidden iframe injection (zero width/height or negative styling).',
                'pattern'     => $p7,
            ],
            [
                'id'          => 'MAL-JS-OBFUSCATION',
                'severity'    => 'high',
                'description' => 'Obfuscated JavaScript execution using dynamic eval and decoded character streams.',
                'pattern'     => $p8,
            ],
            [
                'id'          => 'MAL-JS-CRYPTOMINER',
                'severity'    => 'critical',
                'description' => 'In-browser cryptocurrency mining script payload detected (CoinHive / CryptoNight).',
                'pattern'     => $p9,
            ],
            [
                'id'          => 'MAL-STAGED-BACKDOOR',
                'severity'    => 'critical',
                'description' => 'Staged executable PHP script tag or webshell embedded inside text or static file.',
                'pattern'     => $p10,
            ],
            [
                'id'          => 'MAL-JS-REDIRECTOR',
                'severity'    => 'medium',
                'description' => 'Suspicious forced client-side redirection pattern in script.',
                'pattern'     => $p11,
            ]
        ];
    }
}
