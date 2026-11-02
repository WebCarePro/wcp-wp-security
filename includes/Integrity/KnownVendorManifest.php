<?php
namespace WcpScanner\Integrity;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * High-Speed 128-bit Truncated SHA-256 Micro-Manifest for Known Noisy Upstream Vendor Libraries.
 *
 * Contains 16-byte (32-hex) truncated SHA-256 digests of official, unmodified third-party
 * vendor files from common open-source libraries (phpseclib, mpdf, action-scheduler,
 * requests, datatables, tcpdf, minify).
 *
 * Memory footprint: ~12 KB.
 * Collision resistance: 2^128 (cryptographically collision-free).
 */
class KnownVendorManifest {

    /**
     * Map of 32-character hex prefixes (128-bit truncated SHA-256) of authentic upstream library releases.
     * Format: 'truncated_128bit_sha256' => ['library' => string, 'file' => string]
     *
     * @var array<string, array{library: string, file: string}>
     */
    private static $known_good_hashes = [
        // UpdraftPlus phpseclib 3.x / 2.x
        '48f36d11d38ed092410a5e5b8e9069d5' => ['library' => 'phpseclib', 'file' => 'Net/SSH2.php'],
        'fe7740d4552d04443ef230a1bf840333' => ['library' => 'phpseclib', 'file' => 'Crypt/Common/SymmetricKey.php'],
        'd6b79e709877c17fbb80b72183e9eaee' => ['library' => 'phpseclib', 'file' => 'Common/Functions/Strings.php'],

        // mPDF upstream releases
        '138cf43a64aaebf3972466fc74cb96eb' => ['library' => 'mpdf/mpdf', 'file' => 'src/Mpdf.php'],
        'ac35b6bc97b9bba14c6d6783d3127926' => ['library' => 'mpdf/mpdf', 'file' => 'src/Image/ImageProcessor.php'],
        'f2d21bb6846b2742ddb12489c6dce80b' => ['library' => 'mpdf/mpdf', 'file' => 'src/Mpdf.php (scoped)'],
        '62ce693d3de500ee947022e11894a4e1' => ['library' => 'mpdf/mpdf', 'file' => 'src/Image/ImageProcessor.php (scoped)'],

        // Requests library (rmccue/requests)
        'd5c69c8a2522861f6ca79d67ae4b8be9' => ['library' => 'rmccue/requests', 'file' => 'src/Requests.php'],
        '9c145236c9f246ee2aa4e3ff3db6ea8d' => ['library' => 'rmccue/requests', 'file' => 'src/Requests.php (v2.0.4)'],

        // WooCommerce Subscriptions & ActionScheduler
        'b4e9dc52fe3fa5e4b1bd0fa16f3f3590' => ['library' => 'woocommerce/subscriptions-core', 'file' => 'class-wc-subscriptions-upgrader.php'],
        '3b9d3922b620f85a218fe0bcf2e77b69' => ['library' => 'woocommerce/action-scheduler', 'file' => 'ActionScheduler_Abstract_ListTable.php'],
        'd0d797f7cf566e64c3c3a4d467793d58' => ['library' => 'woocommerce/action-scheduler', 'file' => 'ActionScheduler_Abstract_ListTable.php'],

        // MatthiasMullie / Minify JS
        'b85beb86d9f07f79435b809a4d80a138' => ['library' => 'matthiasmullie/minify', 'file' => 'JS.php'],

        // DataTables vendor distribution
        '209a341af4d5e205ab38474dcbb0b555' => ['library' => 'datatables.net', 'file' => 'datatables.min.js'],

        // Gravity Forms official build assets
        '79d7416a759b6189cb3ab5b5378a7caa' => ['library' => 'gravityforms', 'file' => 'assets/js/dist/admin-components.min.js'],
        'f6fd4615da04317356eec687ab65c786' => ['library' => 'gravityforms', 'file' => 'assets/js/dist/admin-components.min.js'],

        // Source maps & build artifacts
        '42534331b90ab33ea20504e0e010a30b' => ['library' => 'stellarwp/harbor', 'file' => 'index.js.map'],
    ];

    /**
     * Check if a file matches a known clean upstream vendor hash.
     * Uses 128-bit truncated SHA-256 (first 32 hex chars / 16 bytes) for O(1) matching.
     *
     * @param string $file_path Absolute path to the file.
     * @param string|null $content Optional file contents if already read into memory.
     * @return array|null Returns array metadata ['library' => string, 'file' => string] if matched, null otherwise.
     */
    public static function match_known_hash(string $file_path, ?string $content = null): ?array {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return null;
        }

        // Fast path: compute sha256 prefix of raw file
        $raw_sha256 = hash_file('sha256', $file_path);
        if ($raw_sha256) {
            $prefix128 = substr($raw_sha256, 0, 32);
            if (isset(self::$known_good_hashes[$prefix128])) {
                return self::$known_good_hashes[$prefix128];
            }
        }

        // Line ending normalization check (CRLF vs LF)
        if ($content === null) {
            $content = @file_get_contents($file_path);
        }

        if ($content !== false && strlen($content) > 0) {
            $lf_content = str_replace("\r\n", "\n", $content);
            $lf_prefix128 = substr(hash('sha256', $lf_content), 0, 32);
            if (isset(self::$known_good_hashes[$lf_prefix128])) {
                return self::$known_good_hashes[$lf_prefix128];
            }
        }

        return null;
    }

    /**
     * Add or update verified known-good hashes dynamically (e.g. from upstream sync or manifest updates).
     *
     * @param string $prefix128 32-char hex string (128-bit truncated SHA-256).
     * @param string $library Library name.
     * @param string $file Relative file name.
     */
    public static function register_known_hash(string $prefix128, string $library, string $file): void {
        self::$known_good_hashes[strtolower(trim($prefix128))] = [
            'library' => $library,
            'file'    => $file,
        ];
    }
}
