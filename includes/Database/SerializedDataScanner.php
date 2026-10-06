<?php
namespace WCP\Scanner\Database;

if (!defined('ABSPATH')) {
    exit;
}

class SerializedDataScanner {

    /**
     * Check if a string appears to be serialized PHP data.
     *
     * @param mixed $data
     * @return bool
     */
    public static function is_serialized($data) {
        if (!is_string($data)) {
            return false;
        }
        $data = trim($data);
        if ('N;' === $data) {
            return true;
        }
        if (strlen($data) < 4 || ':' !== $data[1]) {
            return false;
        }
        $last = substr($data, -1);
        if (';' !== $last && '}' !== $last) {
            return false;
        }
        $token = $data[0];
        switch ($token) {
            case 's':
                if ('"' !== substr($data, -2, 1)) {
                    return false;
                }
            case 'a':
            case 'O':
            case 'b':
            case 'i':
            case 'd':
                return (bool) preg_match("/^{$token}:[0-9]+:/s", $data);
        }
        return false;
    }

    /**
     * Safely extract all strings from a serialized data string without executing arbitrary class constructors.
     *
     * @param string $data
     * @return array List of string values extracted
     */
    public function extract_strings_safely($data) {
        $extracted = [];

        if (!is_string($data)) {
            return $extracted;
        }

        // Strategy 1: Safe unserialize with allowed_classes => false
        if (self::is_serialized($data)) {
            $unserialized = @unserialize($data, ['allowed_classes' => false]);
            if ($unserialized !== false || $data === 'b:0;') {
                $this->collect_strings_recursive($unserialized, $extracted);
                return $extracted;
            }
        }

        // Strategy 2: If JSON, safely decode
        $json = json_decode($data, true);
        if (is_array($json)) {
            $this->collect_strings_recursive($json, $extracted);
            return $extracted;
        }

        // Strategy 3: Fallback regex to extract string literals from corrupted or custom serialized strings
        if (preg_match_all('/s:\d+:"(.*?)";/s', $data, $matches)) {
            foreach ($matches[1] as $str) {
                $extracted[] = $str;
                // Check if nested serialized string
                if (self::is_serialized($str)) {
                    $nested = $this->extract_strings_safely($str);
                    $extracted = array_merge($extracted, $nested);
                }
            }
        } else {
            $extracted[] = $data;
        }

        return array_unique($extracted);
    }

    /**
     * Recursively collect strings from arrays or stdClass.
     *
     * @param mixed $node
     * @param array $collector
     */
    private function collect_strings_recursive($node, &$collector) {
        if (is_string($node)) {
            $collector[] = $node;
            // Check for nested serialized or JSON string
            if (self::is_serialized($node) || (strlen($node) > 2 && ($node[0] === '{' || $node[0] === '['))) {
                $nested = $this->extract_strings_safely($node);
                $collector = array_merge($collector, $nested);
            }
        } elseif (is_array($node) || is_object($node)) {
            foreach ((array)$node as $val) {
                $this->collect_strings_recursive($val, $collector);
            }
        }
    }
}
