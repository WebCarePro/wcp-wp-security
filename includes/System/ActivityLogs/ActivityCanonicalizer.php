<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Strict canonicalizer for WCP Activity & Audit Log payloads.
 *
 * Enforces:
 * 1. Prohibition of floating-point values (throws \InvalidArgumentException).
 * 2. Strict distinction between empty associative objects (cast to stdClass) and sequential lists (array_values).
 * 3. Deep recursive key sorting (SORT_STRING) at all nested levels.
 * 4. Deterministic UTF-8 normalization without silent data mutation during verification.
 * 5. Deterministic canonical JSON serialization.
 */
class ActivityCanonicalizer {

    /**
     * Recursively canonicalize payload data.
     *
     * @param mixed $data Raw data structure.
     * @param bool  $is_verification True if verifying stored payload, false if creating a new event.
     * @return mixed Canonical structure ready for json_encode.
     * @throws \InvalidArgumentException If floating-point values or invalid types are encountered.
     */
    public static function canonicalize($data, bool $is_verification = false) {
        if (is_float($data)) {
            throw new \InvalidArgumentException('Floating-point numbers are strictly prohibited in canonical event payloads. Use integer microseconds or fixed-point strings.');
        }

        if (is_null($data) || is_bool($data) || is_int($data)) {
            return $data;
        }

        if (is_string($data)) {
            if ($is_verification) {
                // In verification mode, do not mutate invalid UTF-8 bytes; verify exact validity
                if (function_exists('mb_check_encoding') && !mb_check_encoding($data, 'UTF-8')) {
                    throw new \InvalidArgumentException('Stored event string contains invalid UTF-8 bytes; verification aborted.');
                }
                return $data;
            }

            // In event creation mode, ensure string is valid UTF-8
            if (function_exists('mb_convert_encoding')) {
                return mb_convert_encoding($data, 'UTF-8', 'UTF-8');
            }
            return $data;
        }

        if (is_object($data)) {
            $data = (array) $data;
            // Empty object remains empty stdClass
            if (empty($data)) {
                return new \stdClass();
            }
            return self::canonicalize_associative($data, $is_verification);
        }

        if (is_array($data)) {
            if (empty($data)) {
                // Preserved as sequential empty array []
                return [];
            }

            if (self::is_associative($data)) {
                return self::canonicalize_associative($data, $is_verification);
            }

            // Sequential list: canonicalize elements and ensure sequential re-indexing
            $canonical_list = [];
            foreach ($data as $item) {
                $canonical_list[] = self::canonicalize($item, $is_verification);
            }
            return array_values($canonical_list);
        }

        // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
        throw new \InvalidArgumentException('Unsupported data type in canonical event payload: ' . gettype($data));
    }

    /**
     * Canonicalize an associative array: recursively sort keys and format children.
     *
     * @param array $array
     * @param bool  $is_verification
     * @return \stdClass
     */
    private static function canonicalize_associative(array $array, bool $is_verification): \stdClass {
        ksort($array, SORT_STRING);
        $obj = new \stdClass();
        foreach ($array as $key => $val) {
            $string_key = (string) $key;
            $obj->{$string_key} = self::canonicalize($val, $is_verification);
        }
        return $obj;
    }

    /**
     * Check if an array is associative (dictionary) or sequential (list).
     *
     * @param array $array
     * @return bool
     */
    public static function is_associative(array $array): bool {
        if (empty($array)) {
            return false;
        }
        $expected = 0;
        foreach ($array as $key => $value) {
            if ($key !== $expected) {
                return true;
            }
            $expected++;
        }
        return false;
    }

    /**
     * Produce deterministic canonical JSON string.
     *
     * @param mixed $data
     * @param bool  $is_verification
     * @return string
     * @throws \RuntimeException If JSON encoding fails.
     */
    public static function to_json($data, bool $is_verification = false): string {
        $canonical = self::canonicalize($data, $is_verification);
        $json = json_encode($canonical, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
            throw new \RuntimeException('JSON encoding failed during canonicalization: ' . json_last_error_msg());
        }
        return $json;
    }
}
