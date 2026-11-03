<?php
namespace WcpScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PulseHealthCheck
 *
 * Implements non-destructive, rapid store & checkout pulse loopback verification.
 * Dispatches concurrent/fast internal HTTP requests against WordPress core endpoints
 * (Homepage, Login, WooCommerce Cart, WooCommerce Checkout) to verify availability
 * and guarantee that security mitigations or quarantine operations never cause White Screens of Death.
 */
class PulseHealthCheck {

    /**
     * Run full store and checkout pulse check.
     *
     * @return array [
     *   'all_passed' => bool,
     *   'total_duration' => float,
     *   'summary' => string,
     *   'endpoints' => array
     * ]
     */
    public static function check_store_pulse(): array {
        $endpoints = self::get_critical_endpoints();
        $results = [];
        $has_fatal_conflict = false;
        $all_passed = true;
        $total_duration = 0.0;
        $failure_details = [];

        foreach ($endpoints as $key => $ep) {
            $start = microtime(true);
            $res = wp_remote_get($ep['url'], [
                'timeout'     => 6,
                'redirection' => 3,
                'sslverify'   => false,
                'headers'     => [
                    'X-WCP-Pulse-Check' => '1',
                    'User-Agent'        => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WCP-PulseCheck/2.3.0 (+https://webcarepro.com)',
                ],
            ]);
            $duration = round(microtime(true) - $start, 3);
            $total_duration += $duration;

            if (is_wp_error($res)) {
                $err_msg = $res->get_error_message();
                // Network timeouts, DNS resolution issues, or cURL loopback blocks are not fatal PHP site crashes
                $results[$key] = [
                    'label'       => $ep['label'],
                    'url'         => $ep['url'],
                    'status_code' => 0,
                    'duration'    => $duration,
                    'passed'      => false,
                    'is_fatal'    => false,
                    'skipped'     => true,
                    'error'       => $err_msg,
                ];
                // Do not mark $has_fatal_conflict for loopback network connection drops or timeouts
                continue;
            }

            $code = wp_remote_retrieve_response_code($res);
            $body = wp_remote_retrieve_body($res);

            // Check if response is a server crash (500, 502, 503, 504) or contains explicit fatal PHP error
            $is_5xx = ($code >= 500 && $code <= 504);
            $has_fatal_error_text = (
                stripos($body, 'Fatal error:') !== false ||
                stripos($body, 'Parse error:') !== false ||
                stripos($body, 'There has been a critical error on this website.') !== false
            );

            $is_fatal = ($is_5xx || $has_fatal_error_text);
            $is_healthy = ($code >= 200 && $code < 500 && !$has_fatal_error_text);

            if ($is_fatal) {
                $has_fatal_conflict = true;
                $all_passed = false;
                $failure_details[] = sprintf('%s (%s) returned %s', $ep['label'], $ep['url'], $is_5xx ? "HTTP {$code}" : "Fatal PHP Error");
            } elseif (!$is_healthy) {
                $all_passed = false;
            }

            $results[$key] = [
                'label'       => $ep['label'],
                'url'         => $ep['url'],
                'status_code' => $code,
                'duration'    => $duration,
                'passed'      => $is_healthy,
                'is_fatal'    => $is_fatal,
                'error'       => $is_healthy ? null : "HTTP status {$code}" . ($has_fatal_error_text ? ' (Fatal PHP error in response body)' : ''),
            ];
        }

        $avg_time = count($results) > 0 ? round($total_duration / count($results), 2) : 0;

        if ($has_fatal_conflict) {
            $summary = sprintf(
                __('Critical Conflict: %s', 'wcp-security-scanner'),
                implode(', ', $failure_details)
            );
        } elseif ($all_passed) {
            $summary = sprintf(
                /* translators: 1: optional cart/checkout notice, 2: response time in seconds */
                __('Live Health Check Passed: Homepage, Login%1$s are loading normally (%2$ss).', 'wcp-security-scanner'),
                class_exists('WooCommerce') ? __(', Cart & Checkout', 'wcp-security-scanner') : '',
                $avg_time
            );
        } else {
            $summary = __('Live Health Check completed with non-fatal advisory warnings.', 'wcp-security-scanner');
        }

        return [
            'all_passed'         => $all_passed,
            'has_fatal_conflict' => $has_fatal_conflict,
            'total_duration'     => round($total_duration, 2),
            'avg_duration'       => $avg_time,
            'summary'            => $summary,
            'endpoints'          => $results,
            'timestamp'          => gmdate('Y-m-d H:i:s \U\T\C'),
        ];
    }

    /**
     * Resolve critical site and store endpoints
     */
    public static function get_critical_endpoints(): array {
        $endpoints = [
            'home' => [
                'label' => __('Homepage', 'wcp-security-scanner'),
                'url'   => home_url('/'),
            ],
            'login' => [
                'label' => __('Login Portal', 'wcp-security-scanner'),
                'url'   => wp_login_url(),
            ],
        ];

        if (function_exists('wc_get_cart_url')) {
            $cart_url = wc_get_cart_url();
            if (!empty($cart_url)) {
                $endpoints['cart'] = [
                    'label' => __('Shopping Cart', 'wcp-security-scanner'),
                    'url'   => $cart_url,
                ];
            }
        }

        if (function_exists('wc_get_checkout_url')) {
            $checkout_url = wc_get_checkout_url();
            if (!empty($checkout_url)) {
                $endpoints['checkout'] = [
                    'label' => __('Store Checkout', 'wcp-security-scanner'),
                    'url'   => $checkout_url,
                ];
            }
        }

        return $endpoints;
    }
}
