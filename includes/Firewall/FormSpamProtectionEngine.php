<?php
namespace WcpScanner\Firewall;

use WcpScanner\Security\SecretVault;
use WcpScanner\Security\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Universal Smart Form Armor & Anti-Spam Defense Engine.
 *
 * Provides enterprise-grade, zero-friction protection against automated browsers,
 * headless scraping bots, and high-velocity spam floods across all form ecosystems:
 * - Elementor Pro Forms
 * - Contact Form 7 (CF7)
 * - WPForms (Lite & Pro)
 * - Fluent Forms
 * - Gravity Forms
 * - Formidable Forms
 * - Ninja Forms
 * - WooCommerce Customer Reviews & Account Registration
 * - WordPress Native Comments
 */
class FormSpamProtectionEngine {

    const OPTION_STATS = 'wcpscan_form_spam_stats';
    const TRANSIENT_IP_FLOOD = 'wcpscan_form_flood_';
    const HONEYPOT_SESSION_SALT = 'wcpscan_hp_salt';

    /**
     * Common high-confidence spam dictionary patterns.
     */
    const SPAM_PATTERNS = [
        '/\b(crypto(currency)?\s+trading|bitcoin\s+(investment|profit|doubler)|binance\s+signals)\b/i',
        '/\b(whatsapp\s+trading\s+group|telegram\s+signals\s+channel|forex\s+guaranteed)\b/i',
        '/\b(seo\s+backlinks\s+package|first\s+page\s+of\s+google|guest\s+post\s+service)\b/i',
        '/\b(viagra|cialis|levitra|phentermine|tramadol|casino\s+online|slot\s+gacor)\b/i',
        '/\b(hack(ing)?\s+service|darkweb|ddos\s+service)\b/i',
        '/\[url=[^\]]+\]/i', // BBCode spam syntax
        '/<a\s+[^>]*href=[\'"][^\'"]*[\'"][^>]*>/i', // Raw HTML anchors disguised in plain message boxes
    ];

    /**
     * Initialize form anti-spam hooks across all WordPress form providers.
     */
    public static function init(): void {
        $settings = self::get_settings();
        if (empty($settings['form_spam_protection_enabled'])) {
            return;
        }

        // 1. Frontend Asset Enqueue (Micro-script for dynamic cryptographic time-gate & human entropy)
        add_action('wp_enqueue_scripts', [__CLASS__, 'enqueue_frontend_armor']);
        add_action('login_enqueue_scripts', [__CLASS__, 'enqueue_frontend_armor']);

        // 2. Elementor Pro Forms Interception
        add_action('elementor_pro/forms/validation', [__CLASS__, 'validate_elementor_form'], 10, 2);

        // 3. Contact Form 7 Interception
        add_filter('wpcf7_validate', [__CLASS__, 'validate_cf7_form'], 10, 2);

        // 4. WPForms Interception
        add_filter('wpforms_process_before_filter', [__CLASS__, 'validate_wpforms_form'], 10, 2);

        // 5. Fluent Forms Interception
        add_filter('fluentform/before_insert_submission', [__CLASS__, 'validate_fluent_form'], 10, 3);

        // 6. Gravity Forms Interception
        add_filter('gform_validation', [__CLASS__, 'validate_gravity_form'], 10, 1);

        // 7. Formidable Forms Interception
        add_filter('frm_validate_entry', [__CLASS__, 'validate_formidable_form'], 10, 2);

        // 8. Ninja Forms Interception
        add_filter('ninja_forms_submit_data', [__CLASS__, 'validate_ninja_form'], 10, 1);

        // 9. WordPress Native Comments & WooCommerce Reviews
        add_filter('preprocess_comment', [__CLASS__, 'validate_comment_submission'], 1, 1);

        // 10. WooCommerce Registration Errors
        add_filter('woocommerce_process_registration_errors', [__CLASS__, 'validate_woo_registration'], 10, 4);
    }

    /**
     * Get Form Spam Protection configuration settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        if (class_exists('\\WcpScanner\\System\\SettingsManager')) {
            $main_settings = \WcpScanner\System\SettingsManager::get_settings();
        } else {
            $main_settings = [];
        }

        return [
            'form_spam_protection_enabled' => !empty($main_settings['form_spam_protection_enabled']),
            'form_block_headless_browsers' => !empty($main_settings['form_block_headless_browsers'] ?? true),
            'form_honeypot_enabled'        => !empty($main_settings['form_honeypot_enabled'] ?? true),
            'form_speed_gate_enabled'      => !empty($main_settings['form_speed_gate_enabled'] ?? true),
            'form_min_interaction_seconds' => (int) ($main_settings['form_min_interaction_seconds'] ?? 2),
            'form_flood_limit_enabled'     => !empty($main_settings['form_flood_limit_enabled'] ?? true),
            'form_max_submits_per_window'  => (int) ($main_settings['form_max_submits_per_window'] ?? 5),
            'form_flood_window_minutes'    => (int) ($main_settings['form_flood_window_minutes'] ?? 10),
            'form_content_filtering'       => !empty($main_settings['form_content_filtering'] ?? true),
            'form_max_urls_allowed'        => (int) ($main_settings['form_max_urls_allowed'] ?? 2),
        ];
    }

    /**
     * Get dynamic polymorphic honeypot field name.
     * Generates a stable key for the current session/date without revealing predictable names.
     *
     * @return string
     */
    public static function get_honeypot_field_name(): string {
        $salt = get_option(self::HONEYPOT_SESSION_SALT);
        if (!$salt || strlen($salt) < 16) {
            $salt = wp_generate_password(24, false);
            update_option(self::HONEYPOT_SESSION_SALT, $salt, false);
        }
        return 'wcp_hp_' . substr(hash_hmac('sha256', gmdate('Ymd') . '|' . $salt, 'wcp_form_salt'), 0, 8);
    }

    /**
     * Generate an encrypted cryptographic time-gate token.
     *
     * @return string
     */
    public static function generate_time_gate_token(): string {
        $data = time() . '|' . self::get_client_ip();
        if (class_exists('\\WcpScanner\\Security\\SecretVault')) {
            return SecretVault::encrypt($data);
        }
        return base64_encode($data);
    }

    /**
     * Enqueue the lightweight frontend Form Armor micro-script.
     */
    public static function enqueue_frontend_armor(): void {
        $settings = self::get_settings();
        if (empty($settings['form_spam_protection_enabled'])) {
            return;
        }

        $hp_name = self::get_honeypot_field_name();
        $token   = self::generate_time_gate_token();

        $config = [
            'hpName' => $hp_name,
            'token'  => $token,
            'gate'   => $settings['form_speed_gate_enabled'],
        ];

        // Inline script to avoid an extra render-blocking HTTP request
        $js = self::get_inline_armor_script($config);
        wp_register_script('wcp-form-armor', false, [], WCPSCAN_VERSION, true);
        wp_enqueue_script('wcp-form-armor');
        wp_add_inline_script('wcp-form-armor', $js);
    }

    /**
     * Generates the zero-dependency client-side human telemetry and injection script.
     *
     * @param array $config
     * @return string
     */
    private static function get_inline_armor_script(array $config): string {
        $json = wp_json_encode($config);
        return <<<JS
(function(){
  if (window.__wcpFormArmorActive) return;
  window.__wcpFormArmorActive = true;
  var cfg = {$json};
  var startTime = Date.now();
  var entropy = 0;

  function countEntropy() { entropy++; }
  window.addEventListener('mousemove', countEntropy, {passive: true, once: false});
  window.addEventListener('touchstart', countEntropy, {passive: true, once: false});
  window.addEventListener('keydown', countEntropy, {passive: true, once: false});
  window.addEventListener('scroll', countEntropy, {passive: true, once: false});

  function injectArmor(form) {
    if (form.getAttribute('data-wcp-armored')) return;
    form.setAttribute('data-wcp-armored', '1');

    // 1. Dynamic Polymorphic Honeypot (Accessible, off-screen, invisible to humans)
    var hpWrap = document.createElement('div');
    hpWrap.style.cssText = 'position:absolute!important;left:-9999px!important;top:-9999px!important;opacity:0!important;height:0!important;width:0!important;overflow:hidden!important;pointer-events:none!important;';
    hpWrap.setAttribute('aria-hidden', 'true');
    hpWrap.setAttribute('tabindex', '-1');

    var hpInput = document.createElement('input');
    hpInput.type = 'text';
    hpInput.name = cfg.hpName;
    hpInput.value = '';
    hpInput.autocomplete = 'off';
    hpInput.tabIndex = -1;
    hpWrap.appendChild(hpInput);
    form.appendChild(hpWrap);

    // 2. Cryptographic Time-Gate & Entropy Field
    var tokenInput = document.createElement('input');
    tokenInput.type = 'hidden';
    tokenInput.name = 'wcp_time_gate';
    tokenInput.value = cfg.token;
    form.appendChild(tokenInput);

    var entropyInput = document.createElement('input');
    entropyInput.type = 'hidden';
    entropyInput.name = 'wcp_human_telemetry';
    form.appendChild(entropyInput);

    form.addEventListener('submit', function() {
      var isWebDriver = navigator.webdriver === true || !!window.callPhantom || !!window._phantom || !!window.__nightmare;
      var clientTimeDelta = Math.floor((Date.now() - startTime) / 1000);
      var payload = {
        webdriver: isWebDriver,
        entropy: entropy,
        delta: clientTimeDelta,
        screen: [window.screen.width, window.screen.height].join('x')
      };
      try {
        entropyInput.value = btoa(JSON.stringify(payload));
      } catch(e) {
        entropyInput.value = 'fallback';
      }
    });
  }

  function scanForms() {
    var forms = document.querySelectorAll('form');
    for (var i = 0; i < forms.length; i++) {
      injectArmor(forms[i]);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanForms);
  } else {
    scanForms();
  }
  // Re-scan periodically for dynamically loaded modal forms (Elementor popups, AJAX forms)
  setInterval(scanForms, 2500);
})();
JS;
    }

    /**
     * Inspect incoming submission data against all active defense tiers.
     *
     * @param array  $request_data Combined $_POST / request parameters
     * @param string $form_source  Name of the submitting engine (e.g. 'Elementor', 'CF7')
     * @return true|\WP_Error
     */
    public static function evaluate_submission(array $request_data, string $form_source = 'General') {
        $settings = self::get_settings();
        if (empty($settings['form_spam_protection_enabled'])) {
            return true;
        }

        $client_ip = self::get_client_ip();

        // Tier 0: Authenticated Administrators are immune from anti-spam friction
        if (function_exists('current_user_can') && current_user_can('manage_options')) {
            return true;
        }

        // Tier 1: Dynamic Polymorphic Honeypot Verification
        if (!empty($settings['form_honeypot_enabled'])) {
            $hp_name = self::get_honeypot_field_name();
            if (isset($request_data[$hp_name]) && trim((string) $request_data[$hp_name]) !== '') {
                self::record_spam_drop('honeypot_tripped', $form_source, $client_ip);
                return new \WP_Error('wcp_spam_honeypot', __('Spam submission rejected. Automated bot decoy triggered.', 'wcp-security-scanner'));
            }
        }

        // Tier 2: Headless Browser & Automated Tool Fingerprinting
        if (!empty($settings['form_block_headless_browsers']) && isset($request_data['wcp_human_telemetry'])) {
            $raw_telemetry = sanitize_text_field(wp_unslash($request_data['wcp_human_telemetry']));
            if ($raw_telemetry !== '') {
                $decoded = json_decode(base64_decode($raw_telemetry), true);
                if (is_array($decoded)) {
                    // Check explicit navigator.webdriver driver flag
                    if (!empty($decoded['webdriver'])) {
                        self::record_spam_drop('headless_webdriver_detected', $form_source, $client_ip);
                        return new \WP_Error('wcp_spam_webdriver', __('Automated browser software detected. Submission denied.', 'wcp-security-scanner'));
                    }
                    // Check zero-entropy bot submissions (clicked submit without any mouse or touch interaction)
                    if (isset($decoded['entropy']) && (int) $decoded['entropy'] === 0 && isset($decoded['delta']) && (int) $decoded['delta'] < 2) {
                        self::record_spam_drop('zero_entropy_automation', $form_source, $client_ip);
                        return new \WP_Error('wcp_spam_zero_entropy', __('Automated form interaction detected.', 'wcp-security-scanner'));
                    }
                }
            }
        }

        // Tier 3: Cryptographic Speed-Gate & Timing Verification
        if (!empty($settings['form_speed_gate_enabled']) && isset($request_data['wcp_time_gate'])) {
            $raw_token = sanitize_text_field(wp_unslash($request_data['wcp_time_gate']));
            $decrypted = false;

            if (class_exists('\\WcpScanner\\Security\\SecretVault')) {
                $decrypted = SecretVault::decrypt($raw_token);
            }
            if (!$decrypted) {
                $decrypted = base64_decode($raw_token);
            }

            if ($decrypted && strpos($decrypted, '|') !== false) {
                list($timestamp_str, $token_ip) = explode('|', $decrypted, 2);
                $rendered_at = (int) $timestamp_str;
                $elapsed = time() - $rendered_at;
                $min_seconds = max(1, $settings['form_min_interaction_seconds']);

                // Submitted faster than human threshold (< min_seconds)
                if ($elapsed < $min_seconds) {
                    self::record_spam_drop('speed_gate_too_fast', $form_source, $client_ip);
                    return new \WP_Error('wcp_spam_speed_gate', __('Submission was completed too quickly for a human visitor. Please take a moment and try again.', 'wcp-security-scanner'));
                }

                // Stale token (> 2 hours / 7200s) indicating cached scraper replay
                if ($elapsed > 7200) {
                    self::record_spam_drop('stale_replay_token', $form_source, $client_ip);
                    return new \WP_Error('wcp_spam_stale_token', __('Form session has expired. Please refresh the page and resubmit.', 'wcp-security-scanner'));
                }
            }
        }

        // Tier 4: High-Velocity Form Flooding Limiter
        if (!empty($settings['form_flood_limit_enabled'])) {
            $max_submits = max(2, $settings['form_max_submits_per_window']);
            $window_secs = max(60, $settings['form_flood_window_minutes'] * 60);
            $transient_key = self::TRANSIENT_IP_FLOOD . md5($client_ip);

            $current_count = (int) get_transient($transient_key);
            if ($current_count >= $max_submits) {
                self::record_spam_drop('ip_flood_exceeded', $form_source, $client_ip);
                return new \WP_Error('wcp_spam_flood_limited', __('Too many submissions from your connection. Please wait several minutes before trying again.', 'wcp-security-scanner'));
            }

            // Increment flood counter
            set_transient($transient_key, $current_count + 1, $window_secs);
        }

        // Tier 5: Semantic Content & Keyword Heuristics
        if (!empty($settings['form_content_filtering'])) {
            $content_text = self::extract_plain_text($request_data);

            // Check URL count limit
            $url_count = preg_match_all('/https?:\/\/[^\s]+/i', $content_text);
            $max_urls = max(1, $settings['form_max_urls_allowed']);
            if ($url_count > $max_urls) {
                self::record_spam_drop('excessive_links_detected', $form_source, $client_ip);
                return new \WP_Error('wcp_spam_excessive_links', __('Your message contains too many links. Please remove excessive URLs before sending.', 'wcp-security-scanner'));
            }

            // Check spam dictionary patterns
            foreach (self::SPAM_PATTERNS as $pattern) {
                if (preg_match($pattern, $content_text)) {
                    self::record_spam_drop('spam_keyword_matched', $form_source, $client_ip);
                    return new \WP_Error('wcp_spam_keyword', __('Submission contained disallowed promotional or prohibited keywords.', 'wcp-security-scanner'));
                }
            }
        }

        return true;
    }

    /**
     * Intercept Elementor Pro Form submissions.
     *
     * @param \ElementorPro\Modules\Forms\Classes\Form_Record $record
     * @param \ElementorPro\Modules\Forms\Classes\Ajax_Handler $ajax_handler
     */
    public static function validate_elementor_form($record, $ajax_handler): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early WAF validation
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'Elementor Pro Forms');

        if (is_wp_error($check)) {
            $ajax_handler->add_error_message($check->get_error_message());
        }
    }

    /**
     * Intercept Contact Form 7 submissions.
     *
     * @param \WPCF7_Validation $result
     * @param \WPCF7_ContactForm $tag
     * @return \WPCF7_Validation
     */
    public static function validate_cf7_form($result, $tag) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'Contact Form 7');

        if (is_wp_error($check)) {
            $result->invalidate($tag, $check->get_error_message());
        }
        return $result;
    }

    /**
     * Intercept WPForms submissions.
     *
     * @param array $entry
     * @param array $form_data
     * @return array
     */
    public static function validate_wpforms_form($entry, $form_data) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'WPForms');

        if (is_wp_error($check)) {
            wpforms()->process->errors[$form_data['id']]['header'] = $check->get_error_message();
        }
        return $entry;
    }

    /**
     * Intercept Fluent Forms submissions.
     *
     * @param array $insert_data
     * @param array $custom_data
     * @param object $form
     * @return array
     */
    public static function validate_fluent_form($insert_data, $custom_data, $form) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'Fluent Forms');

        if (is_wp_error($check)) {
            wp_send_json_error([
                'errors' => [$check->get_error_message()]
            ], 400);
        }
        return $insert_data;
    }

    /**
     * Intercept Gravity Forms submissions.
     *
     * @param array $validation_result
     * @return array
     */
    public static function validate_gravity_form($validation_result) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'Gravity Forms');

        if (is_wp_error($check)) {
            $validation_result['is_valid'] = false;
            $form = $validation_result['form'] ?? [];
            if (!empty($form['fields'])) {
                $form['fields'][0]->failed_validation = true;
                $form['fields'][0]->validation_message = $check->get_error_message();
                $validation_result['form'] = $form;
            }
        }
        return $validation_result;
    }

    /**
     * Intercept Formidable Forms submissions.
     *
     * @param array $errors
     * @param array $values
     * @return array
     */
    public static function validate_formidable_form($errors, $values) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'Formidable Forms');

        if (is_wp_error($check)) {
            $errors['wcp_form_spam'] = $check->get_error_message();
        }
        return $errors;
    }

    /**
     * Intercept Ninja Forms submissions.
     *
     * @param array $form_data
     * @return array
     */
    public static function validate_ninja_form($form_data) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'Ninja Forms');

        if (is_wp_error($check)) {
            $form_data['errors']['form']['wcp_spam'] = $check->get_error_message();
        }
        return $form_data;
    }

    /**
     * Intercept WordPress comments and WooCommerce reviews.
     *
     * @param array $commentdata
     * @return array
     */
    public static function validate_comment_submission($commentdata) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'WordPress Comments / Reviews');

        if (is_wp_error($check)) {
            wp_die(
                esc_html($check->get_error_message()),
                esc_html__('Comment Submission Blocked', 'wcp-security-scanner'),
                ['response' => 403, 'back_link' => true]
            );
        }
        return $commentdata;
    }

    /**
     * Intercept WooCommerce customer registration attempts.
     *
     * @param \WP_Error $errors
     * @param string $username
     * @param string $password
     * @param string $email
     * @return \WP_Error
     */
    public static function validate_woo_registration($errors, $username, $password, $email) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $data = !empty($_POST) ? wp_unslash($_POST) : [];
        $check = self::evaluate_submission($data, 'WooCommerce Registration');

        if (is_wp_error($check)) {
            $errors->add('wcp_spam_reg', $check->get_error_message());
        }
        return $errors;
    }

    /**
     * Records a neutralized spam attempt in persistent statistics.
     *
     * @param string $reason
     * @param string $engine
     * @param string $ip
     */
    private static function record_spam_drop(string $reason, string $engine, string $ip): void {
        $stats = get_option(self::OPTION_STATS, [
            'total_blocked' => 0,
            'breakdown'     => [],
            'recent'        => []
        ]);

        if (!is_array($stats)) {
            $stats = ['total_blocked' => 0, 'breakdown' => [], 'recent' => []];
        }

        $stats['total_blocked'] = ($stats['total_blocked'] ?? 0) + 1;
        $stats['breakdown'][$reason] = ($stats['breakdown'][$reason] ?? 0) + 1;

        $entry = [
            'timestamp' => current_time('mysql'),
            'reason'    => $reason,
            'engine'    => $engine,
            'ip'        => $ip,
        ];

        if (!isset($stats['recent']) || !is_array($stats['recent'])) {
            $stats['recent'] = [];
        }

        array_unshift($stats['recent'], $entry);
        if (count($stats['recent']) > 50) {
            $stats['recent'] = array_slice($stats['recent'], 0, 50);
        }

        update_option(self::OPTION_STATS, $stats, false);

        if (class_exists('\\WcpScanner\\Security\\AuditLogger')) {
            AuditLogger::log('form_spam_neutralized', sprintf('Neutralized %s form spam from IP %s. Vector: %s', $engine, $ip, $reason));
        }
    }

    /**
     * Retrieves persistent Form Spam telemetry and statistics.
     *
     * @return array
     */
    public static function get_stats(): array {
        $stats = get_option(self::OPTION_STATS, [
            'total_blocked' => 0,
            'breakdown'     => [],
            'recent'        => []
        ]);
        return is_array($stats) ? $stats : ['total_blocked' => 0, 'breakdown' => [], 'recent' => []];
    }

    /**
     * Helper to extract plain text string representation from recursive request parameters.
     *
     * @param array $data
     * @return string
     */
    private static function extract_plain_text(array $data): string {
        $parts = [];
        array_walk_recursive($data, function ($value) use (&$parts) {
            if (is_scalar($value)) {
                $parts[] = (string) $value;
            }
        });
        return implode(' ', $parts);
    }

    /**
     * Safely resolve client IP address.
     *
     * @return string
     */
    private static function get_client_ip(): string {
        if (class_exists('\\WcpScanner\\Firewall\\FirewallEngine')) {
            return FirewallEngine::get_client_ip();
        }
        $raw = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
        return filter_var($raw, FILTER_VALIDATE_IP) ? $raw : '127.0.0.1';
    }
}
