<?php
namespace WebCareProScanner\Database;

if (!defined('ABSPATH')) {
    exit;
}

class SerializedDataScanner {

    /**
     * Explicitly allowed commerce & scheduling classes in database records.
     */
    private const ALLOWED_COMMERCE_CLASSES = [
        'WC_Cart',
        'WC_Customer',
        'WC_Product',
        'WC_Product_Simple',
        'WC_Product_Variable',
        'WC_Product_Variation',
        'WC_Order_Item_Product',
        'WC_Tax',
        'WC_DateTime',
        'ActionScheduler_SimpleSchedule',
        'ActionScheduler_IntervalSchedule',
        'ActionScheduler_CronSchedule',
        'ActionScheduler_NullSchedule',
        'DateTime',
        'DateTimeImmutable',
        'DateTimeZone',
        'stdClass',
    ];

    /**
     * Known POP-chain gadget classes across popular Composer packages.
     */
    private const KNOWN_GADGET_PATTERNS = '/^(?:GuzzleHttp\\\\|Monolog\\\\|Symfony\\\\|Illuminate\\\\|PhpOption\\\\|Faker\\\\|Swift_|PendingBroadcast)/i';

    /**
     * Check if a class is an explicitly allowed benign commerce or schedule value object.
     *
     * @param string $class_name
     * @return bool
     */
    public static function is_allowed_commerce_class(string $class_name): bool {
        $clean_class = ltrim($class_name, '\\');
        return in_array($clean_class, self::ALLOWED_COMMERCE_CLASSES, true);
    }

    /**
     * Inspect a serialized payload for dangerous POP gadgets or unauthorized objects without calling unserialize().
     *
     * @param string $payload Raw database value.
     * @return array<string, mixed>|null Finding array if malicious, null if clean.
     */
    public function inspect_serialized_string(string $payload): ?array {
        if (strpos($payload, 'O:') === false && strpos($payload, 'C:') === false) {
            return null;
        }

        if (!preg_match_all('/(?:O|C):[+-]?\d+:"([^"]+)"/i', $payload, $matches)) {
            return null;
        }

        foreach ($matches[1] as $class_name) {
            $clean_class = ltrim($class_name, '\\');

            if (preg_match(self::KNOWN_GADGET_PATTERNS, $clean_class)) {
                return [
                    'type'     => 'serialized_pop_gadget',
                    'severity' => 'critical',
                    'class'    => $clean_class,
                    'reason'   => sprintf('Known PHP Object Injection gadget class (%s) detected.', $clean_class),
                ];
            }

            if (!self::is_allowed_commerce_class($clean_class)) {
                return [
                    'type'     => 'serialized_unexpected_object',
                    'severity' => 'high',
                    'class'    => $clean_class,
                    'reason'   => sprintf('Unauthorized serialized class (%s) found in stateful storage.', $clean_class),
                ];
            }
        }

        return null;
    }

    /**
     * Safely unserialize a database string without instantiating arbitrary PHP object classes.
     *
     * @param mixed $data Candidate serialized value.
     * @return mixed Unserialized scalars/arrays (objects become __PHP_Incomplete_Class safely) or original value.
     */
    public static function safe_unserialize($data) {
        if (self::is_serialized($data)) {
            // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- Safely disallows class instantiation via allowed_classes => false during security scans.
            return @unserialize(trim((string) $data), ['allowed_classes' => false]);
        }
        return $data;
    }

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
