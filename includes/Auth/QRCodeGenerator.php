<?php
namespace WcpScanner\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Lightweight, self-contained Pure-PHP QR Code (Model 2) SVG Generator.
 *
 * Implements ISO/IEC 18004 Model 2 QR Code Byte Mode with Reed-Solomon Error Correction.
 * Generates standards-compliant SVG data URIs locally with ZERO external API calls,
 * keeping TOTP two-factor provisioning secrets strictly private on the host server.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class QRCodeGenerator {

    // Galois field 256 tables
    private static array $exp = [];
    private static array $log = [];
    private static bool $gf_init = false;

    // Alignment pattern locations for versions 1 to 10
    private static array $alignment_patterns = [
        1 => [],
        2 => [6, 18],
        3 => [6, 22],
        4 => [6, 26],
        5 => [6, 30],
        6 => [6, 34],
        7 => [6, 22, 38],
        8 => [6, 24, 42],
        9 => [6, 26, 46],
        10 => [6, 28, 50],
    ];

    // Capacity (data codewords) and EC codewords for Level M (Medium error correction)
    // [total_codewords, ec_codewords_per_block, num_blocks_g1, data_per_block_g1, num_blocks_g2, data_per_block_g2]
    private static array $version_specs_m = [
        1 => [26, 10, 1, 16, 0, 0],
        2 => [44, 16, 1, 28, 0, 0],
        3 => [70, 26, 1, 44, 0, 0],
        4 => [100, 18, 2, 32, 0, 0],
        5 => [134, 24, 2, 43, 0, 0],
        6 => [172, 16, 4, 27, 0, 0],
        7 => [196, 18, 4, 31, 0, 0],
        8 => [242, 22, 2, 38, 2, 39],
        9 => [292, 22, 3, 36, 2, 37],
        10 => [346, 26, 4, 43, 1, 44],
    ];

    private static function init_gf(): void {
        if (self::$gf_init) {
            return;
        }
        self::$exp = array_fill(0, 512, 0);
        self::$log = array_fill(0, 256, 0);
        $x = 1;
        for ($i = 0; $i < 255; $i++) {
            self::$exp[$i] = $x;
            self::$log[$x] = $i;
            $x <<= 1;
            if ($x & 0x100) {
                $x ^= 0x11d; // Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
            }
        }
        for ($i = 255; $i < 512; $i++) {
            self::$exp[$i] = self::$exp[$i - 255];
        }
        self::$gf_init = true;
    }

    private static function gf_mul(int $x, int $y): int {
        if ($x === 0 || $y === 0) {
            return 0;
        }
        return self::$exp[self::$log[$x] + self::$log[$y]];
    }

    private static function rs_generator_poly(int $degree): array {
        $poly = [1];
        for ($i = 0; $i < $degree; $i++) {
            $next = [1, self::$exp[$i]];
            $res = array_fill(0, count($poly) + 1, 0);
            for ($j = 0; $j < count($poly); $j++) {
                for ($k = 0; $k < count($next); $k++) {
                    $res[$j + $k] ^= self::gf_mul($poly[$j], $next[$k]);
                }
            }
            $poly = $res;
        }
        return $poly;
    }

    private static function rs_encode(array $data, int $degree): array {
        $gen = self::rs_generator_poly($degree);
        $info = array_merge($data, array_fill(0, $degree, 0));
        for ($i = 0; $i < count($data); $i++) {
            $coef = $info[$i];
            if ($coef !== 0) {
                for ($j = 0; $j < count($gen); $j++) {
                    $info[$i + $j] ^= self::gf_mul($gen[$j], $coef);
                }
            }
        }
        return array_slice($info, count($data));
    }

    public static function generate_svg(string $text, int $size = 200, int $margin = 4): string {
        self::init_gf();
        $raw_bytes = array_values(unpack('C*', $text));
        $len = count($raw_bytes);

        // Pick smallest Version in Level M that can hold $len bytes
        $ver = null;
        $spec = null;
        for ($v = 1; $v <= 10; $v++) {
            $s = self::$version_specs_m[$v];
            $cap = ($s[2] * $s[3]) + ($s[4] * $s[5]);
            if ($len + 3 <= $cap) {
                $ver = $v;
                $spec = $s;
                break;
            }
        }

        if ($ver === null) {
            throw new \InvalidArgumentException('Text too long for built-in QR generator');
        }

        $total_data = ($spec[2] * $spec[3]) + ($spec[4] * $spec[5]);

        // Construct bit stream: Mode (0100) + Character Count (8 bits) + Data bytes
        $bits = '0100'; // 8-bit byte mode
        $bits .= sprintf('%08b', $len);
        foreach ($raw_bytes as $b) {
            $bits .= sprintf('%08b', $b);
        }

        // Terminator: up to 4 zeroes
        $needed_bits = $total_data * 8;
        $term_len = min(4, $needed_bits - strlen($bits));
        if ($term_len > 0) {
            $bits .= str_repeat('0', $term_len);
        }

        // Pad to byte boundary
        if (strlen($bits) % 8 !== 0) {
            $bits .= str_repeat('0', 8 - (strlen($bits) % 8));
        }

        // Pad bytes
        $pad_bytes = ['11101100', '00010001'];
        $p_idx = 0;
        while (strlen($bits) < $needed_bits) {
            $bits .= $pad_bytes[$p_idx % 2];
            $p_idx++;
        }

        // Convert bit stream to data codewords
        $codewords = [];
        for ($i = 0; $i < strlen($bits); $i += 8) {
            $codewords[] = bindec(substr($bits, $i, 8));
        }

        // Partition into blocks & calculate EC
        $ec_len = $spec[1];
        $blocks_data = [];
        $blocks_ec = [];
        $offset = 0;

        for ($b = 0; $b < $spec[2]; $b++) {
            $d = array_slice($codewords, $offset, $spec[3]);
            $offset += $spec[3];
            $blocks_data[] = $d;
            $blocks_ec[] = self::rs_encode($d, $ec_len);
        }
        for ($b = 0; $b < $spec[4]; $b++) {
            $d = array_slice($codewords, $offset, $spec[5]);
            $offset += $spec[5];
            $blocks_data[] = $d;
            $blocks_ec[] = self::rs_encode($d, $ec_len);
        }

        // Interleave data codewords
        $final_stream = [];
        $max_data_len = max($spec[3], $spec[5]);
        for ($i = 0; $i < $max_data_len; $i++) {
            foreach ($blocks_data as $bd) {
                if ($i < count($bd)) {
                    $final_stream[] = $bd[$i];
                }
            }
        }

        // Interleave EC codewords
        for ($i = 0; $i < $ec_len; $i++) {
            foreach ($blocks_ec as $be) {
                $final_stream[] = $be[$i];
            }
        }

        // Add remainder bits if any
        $remainder_bits = [1 => 0, 2 => 7, 3 => 7, 4 => 7, 5 => 7, 6 => 7, 7 => 0, 8 => 0, 9 => 0, 10 => 0][$ver];
        $final_bits = '';
        foreach ($final_stream as $byte) {
            $final_bits .= sprintf('%08b', $byte);
        }
        $final_bits .= str_repeat('0', $remainder_bits);

        // Matrix construction
        $dim = 17 + 4 * $ver;
        $matrix = array_fill(0, $dim, array_fill(0, $dim, null));
        $reserved = array_fill(0, $dim, array_fill(0, $dim, false));

        // 1. Finder patterns
        self::place_finder(0, 0, $matrix, $reserved);
        self::place_finder($dim - 7, 0, $matrix, $reserved);
        self::place_finder(0, $dim - 7, $matrix, $reserved);

        // 2. Alignment patterns
        $align_coords = self::$alignment_patterns[$ver];
        $align_positions = [];
        foreach ($align_coords as $r) {
            foreach ($align_coords as $c) {
                if (($r <= 8 && $c <= 8) || ($r <= 8 && $c >= $dim - 8) || ($r >= $dim - 8 && $c <= 8)) {
                    continue;
                }
                $align_positions[] = [$r, $c];
            }
        }
        foreach ($align_positions as [$r, $c]) {
            self::place_alignment($r, $c, $matrix, $reserved);
        }

        // 3. Timing patterns
        for ($i = 8; $i < $dim - 8; $i++) {
            $bit = ($i % 2 === 0) ? 1 : 0;
            if (!$reserved[6][$i]) {
                $matrix[6][$i] = $bit;
                $reserved[6][$i] = true;
            }
            if (!$reserved[$i][6]) {
                $matrix[$i][6] = $bit;
                $reserved[$i][6] = true;
            }
        }

        // 4. Dark module
        $matrix[$dim - 8][8] = 1;
        $reserved[$dim - 8][8] = true;

        // 5. Reserve format information areas
        for ($i = 0; $i < 9; $i++) {
            $reserved[8][$i] = true;
            $reserved[$i][8] = true;
        }
        for ($i = $dim - 8; $i < $dim; $i++) {
            $reserved[8][$i] = true;
            $reserved[$i][8] = true;
        }

        // 6. Place data bits in zig-zag
        $bit_idx = 0;
        $bit_total = strlen($final_bits);
        $col = $dim - 1;
        $up = true;

        while ($col > 0) {
            if ($col === 6) {
                $col--;
            }
            $rows = $up ? range($dim - 1, 0, -1) : range(0, $dim - 1);
            foreach ($rows as $row) {
                foreach ([$col, $col - 1] as $c) {
                    if (!$reserved[$row][$c]) {
                        $val = ($bit_idx < $bit_total) ? (int)$final_bits[$bit_idx++] : 0;
                        if (($row + $c) % 2 === 0) {
                            $val ^= 1;
                        }
                        $matrix[$row][$c] = $val;
                    }
                }
            }
            $up = !$up;
            $col -= 2;
        }

        // 7. Write Format Information
        $format_bits = self::get_format_bits(0, 0); // Level M, Mask 0
        self::place_format_bits($format_bits, $matrix);

        // Generate SVG
        $full_dim = $dim + (2 * $margin);
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $full_dim . ' ' . $full_dim . '" width="' . $size . '" height="' . $size . '" shape-rendering="crispEdges">';
        $svg .= '<rect width="100%" height="100%" fill="#ffffff"/>';
        $path_data = '';
        for ($r = 0; $r < $dim; $r++) {
            for ($c = 0; $c < $dim; $c++) {
                if ($matrix[$r][$c] === 1) {
                    $x = $c + $margin;
                    $y = $r + $margin;
                    $path_data .= "M{$x},{$y}h1v1h-1z ";
                }
            }
        }
        $svg .= '<path d="' . rtrim($path_data) . '" fill="#000000"/>';
        $svg .= '</svg>';

        return $svg;
    }

    public static function get_data_uri(string $text, int $size = 200): string {
        $svg = self::generate_svg($text, $size);
        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }

    private static function place_finder(int $top, int $left, array &$matrix, array &$reserved): void {
        for ($r = -1; $r <= 7; $r++) {
            for ($c = -1; $c <= 7; $c++) {
                $row = $top + $r;
                $col = $left + $c;
                if ($row < 0 || $row >= count($matrix) || $col < 0 || $col >= count($matrix)) {
                    continue;
                }
                $is_black = (
                    ($r >= 0 && $r <= 6 && ($c === 0 || $c === 6)) ||
                    ($c >= 0 && $c <= 6 && ($r === 0 || $r === 6)) ||
                    ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4)
                );
                $matrix[$row][$col] = $is_black ? 1 : 0;
                $reserved[$row][$col] = true;
            }
        }
    }

    private static function place_alignment(int $center_r, int $center_c, array &$matrix, array &$reserved): void {
        for ($r = -2; $r <= 2; $r++) {
            for ($c = -2; $c <= 2; $c++) {
                $row = $center_r + $r;
                $col = $center_c + $c;
                $is_black = ($r === -2 || $r === 2 || $c === -2 || $c === 2 || ($r === 0 && $c === 0));
                $matrix[$row][$col] = $is_black ? 1 : 0;
                $reserved[$row][$col] = true;
            }
        }
    }

    private static function get_format_bits(int $ec_level_bits, int $mask): int {
        $data = ($ec_level_bits << 3) | $mask;
        $d = $data << 10;
        $poly = 0x537;
        for ($i = 4; $i >= 0; $i--) {
            if ($d & (1 << ($i + 10))) {
                $d ^= ($poly << $i);
            }
        }
        $format = ($data << 10) | $d;
        return $format ^ 0x5412;
    }

    private static function place_format_bits(int $bits, array &$matrix): void {
        $dim = count($matrix);
        $coords_top_left = [
            [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5],
            [8, 7], [8, 8], [7, 8],
            [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
        ];

        $coords_split = [
            [$dim - 1, 8], [$dim - 2, 8], [$dim - 3, 8], [$dim - 4, 8],
            [$dim - 5, 8], [$dim - 6, 8], [$dim - 7, 8],
            [8, $dim - 8], [8, $dim - 7], [8, $dim - 6], [8, $dim - 5],
            [8, $dim - 4], [8, $dim - 3], [8, $dim - 2], [8, $dim - 1]
        ];

        for ($i = 0; $i < 15; $i++) {
            $bit = ($bits >> $i) & 1;
            [$r1, $c1] = $coords_top_left[$i];
            $matrix[$r1][$c1] = $bit;

            [$r2, $c2] = $coords_split[$i];
            $matrix[$r2][$c2] = $bit;
        }
    }
}
