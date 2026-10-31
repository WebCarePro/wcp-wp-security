<?php
namespace WcpScanner\System\ActivityLogs;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Universal Sensitive Data Redactor for WCP Activity & Audit Logging.
 *
 * Traverses nested structures, diffs, exceptions, and configuration values,
 * applying key-blacklist masks and regex pattern detection to redact:
 * - API keys, tokens, bearer headers, nonces, and passwords.
 * - Database credentials, salt constants, and private keys.
 * - Replaces matches with deterministic "[REDACTED_SECRET::prefix_hash]".
 */
class ActivityRedactor {

    /**
     * Key name patterns that must always have their values redacted.
     */
    private static array $sensitive_key_patterns = [
        'password',
        'passwd',
        'secret',
        'api_key',
        'apikey',
        'token',
        'access_token',
        'refresh_token',
        'auth_token',
        'bearer',
        'nonce',
        'wp_nonce',
        'private_key',
        'privkey',
        'credential',
        'license',
        'cookie',
        'session_id',
        'cf_token',
        'cf_key',
        'openai_api_key',
        'gemini_api_key',
        'anthropic_api_key',
        'webhook_url',
        'db_password',
    ];

    /**
     * Value regex patterns to detect raw secret strings even if key name is generic.
     */
    private static array $secret_value_regexes = [
        '/^Bearer\s+[A-Za-z0-9\-_\.=]+/i',                         // Bearer tokens
        '/^sk-[a-zA-Z0-9_\-]{20,}/',                                 // OpenAI keys
        '/^AIzaSy[a-zA-Z0-9_\-]{30,}/',                             // Google API keys
        '/^AKIA[0-9A-Z]{16}/',                                      // AWS Access Keys
        '/-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----/s',    // Private cryptographic keys
    ];

    /**
     * Redact all sensitive fields in an arbitrary data structure.
     *
     * @param mixed $data
     * @param int   $depth Recursion safety counter.
     * @return mixed
     */
    public static function redact($data, int $depth = 0) {
        if ($depth > 12) {
            return '[MAX_REDACTION_DEPTH_EXCEEDED]';
        }

        if (is_null($data) || is_bool($data) || is_int($data) || is_float($data)) {
            return $data;
        }

        if (is_string($data)) {
            return self::redact_string_value($data);
        }

        if (is_object($data)) {
            $array = (array) $data;
            $redacted_array = self::redact_array($array, $depth + 1);
            return (object) $redacted_array;
        }

        if (is_array($data)) {
            return self::redact_array($data, $depth + 1);
        }

        return $data;
    }

    /**
     * Redact array keys and values.
     *
     * @param array $array
     * @param int   $depth
     * @return array
     */
    private static function redact_array(array $array, int $depth): array {
        $result = [];
        foreach ($array as $key => $value) {
            $string_key = (string) $key;
            if (self::is_sensitive_key($string_key)) {
                $result[$key] = self::mask_secret($value);
            } else {
                $result[$key] = self::redact($value, $depth);
            }
        }
        return $result;
    }

    /**
     * Check if an array or object key represents sensitive data.
     *
     * @param string $key
     * @return bool
     */
    public static function is_sensitive_key(string $key): bool {
        $normalized = strtolower(str_replace(['-', '_', '.'], '', $key));
        foreach (self::$sensitive_key_patterns as $pattern) {
            $clean_pattern = str_replace(['-', '_', '.'], '', $pattern);
            if (strpos($normalized, $clean_pattern) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Redact a string value if it matches secret regexes or contains query-string secrets.
     *
     * @param string $value
     * @return string
     */
    private static function redact_string_value(string $value): string {
        if (strlen($value) === 0) {
            return $value;
        }

        // Check secret value patterns
        foreach (self::$secret_value_regexes as $regex) {
            if (preg_match($regex, $value)) {
                return self::mask_secret($value);
            }
        }

        // Check if value is a URL with sensitive query parameters (e.g. ?api_key=xxx or ?token=yyy)
        if (strpos($value, '://') !== false && strpos($value, '?') !== false) {
            $parts = wp_parse_url($value);
            if (!empty($parts['query'])) {
                parse_str($parts['query'], $query_params);
                $query_modified = false;
                foreach ($query_params as $q_key => $q_val) {
                    if (self::is_sensitive_key((string) $q_key)) {
                        $query_params[$q_key] = self::mask_secret($q_val);
                        $query_modified = true;
                    }
                }
                if ($query_modified) {
                    $parts['query'] = http_build_query($query_params);
                    return self::unparse_url($parts);
                }
            }
        }

        return $value;
    }

    /**
     * Generate deterministic secret mask with prefix hash.
     *
     * @param mixed $value
     * @return string
     */
    public static function mask_secret($value): string {
        if (empty($value)) {
            return '[REDACTED_EMPTY]';
        }
        $str = is_scalar($value) ? (string) $value : serialize($value);
        $hash = substr(hash('sha256', 'WCP_REDACT_' . $str), 0, 6);
        return '[REDACTED_SECRET::' . $hash . ']';
    }

    /**
     * Reconstruct a URL from parse_url parts.
     *
     * @param array $parsed_url
     * @return string
     */
    private static function unparse_url(array $parsed_url): string {
        $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
        $host     = isset($parsed_url['host']) ? $parsed_url['host'] : '';
        $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
        $user     = isset($parsed_url['user']) ? $parsed_url['user'] : '';
        $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = isset($parsed_url['path']) ? $parsed_url['path'] : '';
        $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
        $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
        return "$scheme$user$pass$host$port$path$query$fragment";
    }
}
