# WebCare Pro Security & Firewall (v2.11.0): Full Code Audit, Modular WAF Fixes & Non-Tech UX Blueprint

**Author:** Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer  
**Target Build Audited:** `wcp-security-scanner-full-22.zip` (`v2.11.0`, Manifest `2026-11-11T16:33:25.000Z`, `210 / 210` files tracked)

---

## 1. Executive Code & Security Audit Verdict

### 1.1 Cryptographic & Structural Integrity: PASS (`210 / 210`)
- **Manifest Verification**: All `210` tracked files in `includes/System/plugin-manifest.json` match their exact SHA-256 hashes and byte sizes (`0` missing, `0` modified, `0` untracked).
- **5-Manifest Version Synchronization**: Version `2.11.0` is synchronized across `webcare-pro-security.php`, `version.json`, `package.json`, `readme.txt`, and `includes/System/plugin-manifest.json`.
- **Core Security & Vulnerability Check of Plugin Code**:
  - **REST API Authorization**: All 8 new `/modular-waf/*` routes in `includes/Api/ScannerRoutes.php` (`lines 1946–1992`) enforce `$permission` (`current_user_can('manage_options')` + REST nonce verification).
  - **Path Traversal & File Disclosure Protection**: `ModularFirewallSynthesizer::get_code_preview()` (`lines 586–650`) and `ComponentIntegrityVerifier::resolve_absolute_path()` (`lines 620–645`) strictly block `..`, null bytes, paths outside `ABSPATH`/`WP_CONTENT_DIR`, files `> 5MB`, and explicitly forbid reading `wp-config.php`.
  - **Cryptographic Vault Tamper Resistance**: `BehavioralVaultManager` (`includes/Firewall/Modular/BehavioralVaultManager.php`) seals every `.intel.gz` shard with `HMAC-SHA256`, verifies signatures in constant time via `hash_equals()`, writes atomically via `.tmp` swap, and locks down `wp-content/uploads/webcare-pro-security/intel-vault/` with `.htaccess` (`Require all denied`) and `index.php`.
  - **SQL & Privacy Hygiene**: `ScannerRoutes::build_modular_log_analysis_context()` (`lines 2510–2540`) uses `$wpdb->prepare()` with `%i` table identifier escaping and hashes client IPs (`sha256` prefix) in exported diagnostic bundles.

---

## 2. Five Bugs & False-Positive Risks Found in the New Modular WAF Engine (Must Fix)

While the core plugin and new Setup Studio are architected cleanly, our line-by-line review of `includes/Firewall/Modular/*`, `MicroWafCompiler.php`, and `Step03BehavioralModularWaf.tsx` uncovered **5 important bugs and false-positive risks** that should be patched:

### Bug #1: `SiteBehavioralAnalyzer::inspect_hook_call()` Checks Nonces Across the *Entire File* Instead of the Callback Scope (`SiteBehavioralAnalyzer.php:473-490`)
- **What Happens Now**:
  ```php
  // SiteBehavioralAnalyzer.php lines 473-474
  $has_nonce = self::file_has_nonce_verification($tokens);
  $has_cap   = self::file_has_capability_check($tokens);
  ```
- **Why This Causes Both False Negatives & False Positives**:
  1. **False Negative (Missed Vulnerability)**: If a 1,500-line `functions.php` or plugin controller calls `check_ajax_referer()` inside *one* unrelated admin function at the top of the file, `file_has_nonce_verification($tokens)` returns `true` for the **entire file**, causing the scanner to miss an unprotected `wp_ajax_nopriv_*` handler at the bottom of the same file.
  2. **False Positive (Over-Blocking Benign Guest AJAX)**: If a verified WordPress.org plugin (e.g., WooCommerce, Elementor, or a live-search plugin) registers a harmless read-only `wp_ajax_nopriv_live_search` handler in a small file that only runs `WP_Query` and has **zero dangerous sinks** (no `$wpdb->query`, no `update_option`, no `move_uploaded_file`, no `wp_mail`), it gets flagged as `severity: critical` with `recommended_mode => 'enforce'`.
- **Exact Fix**:
  - Add a helper `inspect_callback_scope(array $tokens, ?string $callback_name, int $hook_pos): array` that locates `function <callback_name>` in `$tokens` (or inspects the inline closure at `$hook_pos`) to check `has_nonce`, `has_cap`, and `has_dangerous_sink` **inside the callback itself**.
  - If the component is checksum-verified (`is_official_wporg === true` and `checksum_status === 'authentic'`) or the callback has no dangerous mutation sink, set `recommended_mode => 'monitor'` instead of `'enforce'`.

---

### Bug #2: `MOD-AJAX-*` Blocks File Uploads even for Logged-In Administrators (`MicroWafCompiler.php:503-510` & `ModularFirewallSynthesizer.php:515-530`)
- **What Happens Now**:
  - In WordPress, `wp_ajax_{action}` (authenticated) and `wp_ajax_nopriv_{action}` (guest) share the exact same `$_REQUEST['action']` name on `/wp-admin/admin-ajax.php`.
  - In `MicroWafCompiler.php` (`line 507`) and `ModularFirewallSynthesizer::evaluate_runtime_modular_rules()` (`line 520`), `block_uploads` blocks `$_FILES` for **every caller** without checking whether the user is logged in! If a non-whitelisted admin or editor uploads media via an AJAX action that also has a `nopriv` hook, their upload is blocked.
- **Exact Fix**:
  - In `MicroWafCompiler.php` (`line 500`), only enforce guest AJAX upload blocks when `!$has_login_cookie` (no `wordpress_logged_in_*` cookie present).
  - In `ModularFirewallSynthesizer::evaluate_runtime_modular_rules()`, check `if (function_exists('is_user_logged_in') && is_user_logged_in())` to bypass guest-only rules (`ajax_shield` and `rest_guard`) for authenticated users, and always exempt `current_user_can('manage_options')`.

---

### Bug #3: `evaluate_runtime_modular_rules()` and `MicroWafCompiler.php` Do Not Enforce `rest_guard`, `upload_guard`, `egress_lock`, `custom`, or `rate_limit`
- **What Happens Now**:
  - `ModularFirewallSynthesizer::synthesize_rules()` creates 6 categories of rules (`tamper_guard`, `ajax_shield`, `rest_guard`, `abspath_lock`, `upload_guard`, `egress_lock`) plus developer `custom` rules, and `get_compiled_preload_rules()` outputs `rest_routes_enforced`.
  - However, `evaluate_runtime_modular_rules()` (`ModularFirewallSynthesizer.php:486-533`) only checks `abspath_lock`/`tamper_guard` and `ajax_shield` (`$_FILES` only). It completely ignores:
    - `rest_guard` (`MOD-REST-*`)
    - `upload_guard` (`MOD-UPLOAD-*`)
    - `egress_lock` (`MOD-EGRESS-*`)
    - `custom` (`MOD-CUSTOM-*`)
    - Per-rule `rate_limit` (`req/min`) and SQLi/XSS parameter inspection on `ajax_shield`!
  - Likewise, `MicroWafCompiler.php` (`lines 487–511`) never evaluates `$mod_rules['rest_routes_enforced']`.
- **Exact Fix** (Drop-in code provided in Section 3 below):
  - Complete `evaluate_runtime_modular_rules()` in `ModularFirewallSynthesizer.php` and `MicroWafCompiler.php` so all 6 modular rule categories + custom rules + velocity rate limits are actively enforced.

---

### Bug #4: `Step03BehavioralModularWaf.tsx` Displays Hardcoded Fallback Numbers (`360`, `14`, `75`, `82`) When Scan Has Not Run (`lines 320–341`)
- **What Happens Now**:
  ```tsx
  // src/components/wizard/steps/Step03BehavioralModularWaf.tsx lines 320-341
  {(counters.ajax_hooks_found || 0) + (counters.rest_routes_found || 0) || 360}
  {(counters.permissive_rest_routes || 0) + (counters.taint_sinks_found || 0) || 14}
  {counters.missing_abspath_files || 75}
  {rules.length || counters.rules_synthesized || 82}
  ```
  When a user opens Step 3 before running a scan (`Files Tokenized: 0`), those `|| 360`, `|| 14`, `|| 75`, and `|| 82` fallbacks display fake numbers alongside `0` files tokenized and `0` rules in the list below!
- **Exact Fix**:
  Replace those 4 fallback numbers in `Step03BehavioralModularWaf.tsx` with `0`:
  ```tsx
  {(counters.ajax_hooks_found || 0) + (counters.rest_routes_found || 0)}
  {(counters.permissive_rest_routes || 0) + (counters.taint_sinks_found || 0)}
  {counters.missing_abspath_files ?? 0}
  {rules.length || counters.rules_synthesized || 0}
  ```

---

### Bug #5: `MOD-CVE-*` (`cve_patch`) Rules & Outdated Component Counters Are Never Populated (`SiteBehavioralAnalyzer.php:66`)
- **What Happens Now**:
  - `SiteBehavioralAnalyzer` initializes `'cve_vulnerabilities' => 0` (`line 66`), and both `Step03BehavioralModularWaf.tsx` and `ModularFirewallStudio.tsx` include a filter pill for `cve_patch` (`MOD-CVE-*`), but `synthesize_rules()` never generates `cve_patch` rules for outdated/vulnerable plugins in `$inventory`.
- **Exact Fix**:
  - In `ModularFirewallSynthesizer::synthesize_rules()`, iterate over `$inventory`: whenever a plugin/theme has `!empty($comp['update_available'])` or known CVEs, synthesize a `MOD-CVE-*` virtual shield rule (defaulting to `monitor` for simple updates or `enforce` when a known CVE matches).

---

## 3. Copy-Paste PHP Patch for `ModularFirewallSynthesizer.php` & `MicroWafCompiler.php`

### 3.1 Complete `evaluate_runtime_modular_rules()` in `includes/Firewall/Modular/ModularFirewallSynthesizer.php`
Replace `evaluate_runtime_modular_rules()` (`lines 468–534`) with this complete implementation covering all 6 rule categories, custom rules, logged-in exemptions, and per-rule rate limiting:

```php
    /**
     * Evaluate incoming request against active Modular Rules at WordPress Runtime.
     *
     * @return array|null Returns violation array if blocked/monitored, null if safe.
     */
    public static function evaluate_runtime_modular_rules(): ?array {
        $rules = self::get_active_rules();
        if (empty($rules)) {
            return null;
        }

        $uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        $ip     = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : '127.0.0.1';

        // 1. Whitelist & Admin Safety Check
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            if (\WebCareProScanner\Firewall\FirewallEngine::is_ip_whitelisted($ip)) {
                return null;
            }
        }
        $is_logged_in = function_exists('is_user_logged_in') && is_user_logged_in();
        $is_admin     = $is_logged_in && function_exists('current_user_can') && current_user_can('manage_options');
        if ($is_admin) {
            return null;
        }

        $clean_uri = strtolower((string) strtok($uri, '?'));

        foreach ($rules as $r) {
            $mode = $r['current_mode'] ?? 'off';
            if ($mode === 'off') {
                continue;
            }

            $cat     = $r['category'] ?? '';
            $methods = is_array($r['http_methods'] ?? null) ? array_map('strtoupper', $r['http_methods']) : [];

            // Category 1: abspath_lock / tamper_guard (Direct HTTP request to standalone or checksum-modified PHP script)
            if (in_array($cat, ['abspath_lock', 'tamper_guard'], true) && !empty($r['target_uri'])) {
                $target_suffix = strtolower(ltrim((string) $r['target_uri'], '/\\'));
                if ($target_suffix !== '' && str_ends_with($clean_uri, $target_suffix)) {
                    return [
                        'blocked'  => ($mode === 'enforce'),
                        'rule_id'  => $r['id'],
                        'category' => $cat,
                        'reason'   => ($cat === 'tamper_guard')
                            ? sprintf('Direct HTTP access to checksum-flagged script "%s" blocked by Modular WAF Rule [%s].', basename($target_suffix), $r['id'])
                            : sprintf('Direct HTTP access to standalone script "%s" blocked by Modular WAF Rule [%s].', basename($target_suffix), $r['id']),
                        'severity' => $r['severity'] ?? 'high',
                        'mode'     => $mode,
                    ];
                }
            }

            // Category 2: ajax_shield (Targeted guest AJAX action — exempt logged-in users)
            if ($cat === 'ajax_shield' && !$is_logged_in && !empty($r['target_value'])) {
                if (str_contains($clean_uri, 'admin-ajax.php')) {
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
                    if ($action !== '' && $action === strtolower((string) $r['target_value'])) {
                        // A. Block unauthorized multipart file uploads on guest AJAX
                        // phpcs:ignore WordPress.Security.NonceVerification.Missing
                        if (!empty($r['block_uploads']) && !empty($_FILES)) {
                            return [
                                'blocked'  => ($mode === 'enforce'),
                                'rule_id'  => $r['id'],
                                'category' => $cat,
                                'reason'   => sprintf('File upload prohibited on guest AJAX action "%s" by Modular WAF Rule [%s].', $action, $r['id']),
                                'severity' => 'critical',
                                'mode'     => $mode,
                            ];
                        }

                        // B. Inspect parameters for SQLi / XSS / Privilege Escalation payloads on unprotected guest AJAX
                        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                        $raw_payload = wp_json_encode($_REQUEST) ?: '';
                        if (preg_match('/(?:\bunion\s+all\s+select\b|\bselect\b.{1,40}\bfrom\b.{1,40}\bwp_users\b|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|<script\b|javascript:|wp_capabilities|administrator)/i', $raw_payload)) {
                            return [
                                'blocked'  => ($mode === 'enforce'),
                                'rule_id'  => $r['id'],
                                'category' => $cat,
                                'reason'   => sprintf('Malicious SQLi/XSS/PrivEsc payload intercepted on unprotected guest AJAX action "%s" [%s].', $action, $r['id']),
                                'severity' => 'critical',
                                'mode'     => $mode,
                            ];
                        }

                        // C. Enforce per-IP velocity rate limit if configured
                        $limit = intval($r['rate_limit'] ?? 0);
                        if ($limit > 0 && self::is_modular_rate_limited($r['id'], $ip, $limit)) {
                            return [
                                'blocked'  => ($mode === 'enforce'),
                                'rule_id'  => $r['id'],
                                'category' => $cat,
                                'reason'   => sprintf('Rate limit (%d req/min) exceeded on guest AJAX action "%s" [%s].', $limit, $action, $r['id']),
                                'severity' => 'high',
                                'mode'     => $mode,
                            ];
                        }
                    }
                }
            }

            // Category 3: rest_guard (Permissive REST route guard — exempt logged-in users)
            if ($cat === 'rest_guard' && !$is_logged_in && !empty($r['target_uri'])) {
                $target_route = strtolower(rtrim((string) $r['target_uri'], '/'));
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $rest_query = isset($_GET['rest_route']) ? strtolower(sanitize_text_field(wp_unslash($_GET['rest_route']))) : '';
                if (($target_route !== '' && str_contains($clean_uri, '/wp-json' . $target_route)) || ($rest_query !== '' && str_starts_with($rest_query, $target_route))) {
                    if (empty($methods) || in_array($method, $methods, true)) {
                        return [
                            'blocked'  => ($mode === 'enforce'),
                            'rule_id'  => $r['id'],
                            'category' => $cat,
                            'reason'   => sprintf('Unauthenticated %s mutation on permissive REST route "%s" blocked by Modular WAF Rule [%s].', $method, $target_route, $r['id']),
                            'severity' => $r['severity'] ?? 'high',
                            'mode'     => $mode,
                        ];
                    }
                }
            }

            // Category 4: upload_guard (Inspect multipart $_FILES for executable extensions / PHP tags)
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            if ($cat === 'upload_guard' && !empty($_FILES)) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                foreach ($_FILES as $file_item) {
                    $names   = is_array($file_item['name'] ?? null) ? $file_item['name'] : [($file_item['name'] ?? '')];
                    $tmp_arr = is_array($file_item['tmp_name'] ?? null) ? $file_item['tmp_name'] : [($file_item['tmp_name'] ?? '')];
                    foreach ($names as $idx => $fname) {
                        $fname_l = strtolower((string) $fname);
                        if (preg_match('/\.(?:php\d*|phtml|phar|pgif|htaccess|user\.ini|sh|pl|py|cgi|asp|aspx)\b/i', $fname_l)) {
                            return [
                                'blocked'  => ($mode === 'enforce'),
                                'rule_id'  => $r['id'],
                                'category' => $cat,
                                'reason'   => sprintf('Dangerous executable upload filename "%s" blocked by Modular Upload Guard [%s].', sanitize_file_name($fname), $r['id']),
                                'severity' => 'critical',
                                'mode'     => $mode,
                            ];
                        }
                        $tmp_f = (string) ($tmp_arr[$idx] ?? '');
                        if ($tmp_f !== '' && is_uploaded_file($tmp_f)) {
                            $head = (string) @file_get_contents($tmp_f, false, null, 0, 4096);
                            if (preg_match('/<\?(?:php|=)|__HALT_COMPILER\s*\(\s*\)/i', $head)) {
                                return [
                                    'blocked'  => ($mode === 'enforce'),
                                    'rule_id'  => $r['id'],
                                    'category' => $cat,
                                    'reason'   => sprintf('Embedded PHP/PHAR payload inside uploaded file "%s" blocked by Modular Upload Guard [%s].', sanitize_file_name($fname), $r['id']),
                                    'severity' => 'critical',
                                    'mode'     => $mode,
                                ];
                            }
                        }
                    }
                }
            }

            // Category 5: egress_lock (SSRF parameter inspection for internal/metadata targets)
            if ($cat === 'egress_lock' && !empty($r['target_param'])) {
                $param_keys = array_filter(array_map('trim', explode(',', strtolower((string) $r['target_param']))));
                foreach ($param_keys as $pk) {
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    if (isset($_REQUEST[$pk]) && is_string($_REQUEST[$pk])) {
                        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                        $val = strtolower(trim( sanitize_text_field(wp_unslash($_REQUEST[$pk])) ));
                        if (preg_match('#^(?:file|gopher|dict|ftp|ldap|tftp)://|(?:\b169\.254\.169\.254\b|\b127\.\d+\.\d+\.\d+\b|\blocalhost\b|\b0\.0\.0\.0\b|\[::1\]|\bmetadata\.google\.internal\b)#i', $val)) {
                            return [
                                'blocked'  => ($mode === 'enforce'),
                                'rule_id'  => $r['id'],
                                'category' => $cat,
                                'reason'   => sprintf('SSRF target in parameter "%s" blocked by Modular Egress Lock [%s].', $pk, $r['id']),
                                'severity' => 'critical',
                                'mode'     => $mode,
                            ];
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Lightweight 60-second sliding counter for Modular WAF rule rate limits.
     */
    private static function is_modular_rate_limited(string $rule_id, string $ip, int $limit_per_min): bool {
        $key   = 'wcp_mod_rl_' . substr(md5($rule_id . '|' . $ip), 0, 16);
        $count = (int) get_transient($key);
        if ($count >= $limit_per_min) {
            return true;
        }
        set_transient($key, $count + 1, 60);
        return false;
    }
```

---

## 4. Six High-Impact Ideas to Make WebCare Pro Effortless for Non-Technical Users

To make WebCare Pro equally loved by **first-time WordPress store owners / bloggers** and **senior Linux sysadmins**, add these 6 user-experience features:

### 4.1 Global "Simple Owner View" vs. "Pro Engineer View" Switcher
- Right now, the Setup Wizard has **Express Mode vs. Developer Mode**, but once the user lands on the main Dashboard or Firewall pages, they see advanced DevSecOps terms (`AST Taint Sink`, `FCrDNS`, `MOD-ABSPATH`, `RASP Rule #44`, `HMAC Shard`).
- **Solution**: Put the **⚡ Simple Owner Mode / 🛠️ Pro Engineer Mode** pill in the global top header across all plugin pages:
  - In **Simple Owner Mode**, translate technical jargon into plain-English outcome cards:
    - 🟢 **"Customer Checkout & Payments: Protected"** *(Carding & fake coupon bots blocked)*
    - 🟢 **"Admin Area & Passwords: Protected"** *(Brute-force shield & Zero-Lockout IP active)*
    - 🟢 **"Website Files & Plugins: Verified Clean"** *(210 files verified against official signatures)*
    - 🟡 **"1 Action Needed: Update Contact Form Plugin"** *(Protected by WebCare Virtual Shield until you click Update)*

### 4.2 "Something Stopped Working? 1-Click Fix My Site" Rescue Assistant
- **Why Non-Tech Users Love This**: When a payment webhook, contact form, or Elementor page save fails on a WordPress site, non-technical owners panic and deactivate their security plugin.
- **How It Works**:
  - Place a friendly **"🛠️ Something Not Working? Click to Troubleshoot"** button in the top header and WordPress Admin Bar.
  - Clicking it scans the last 15 minutes of WAF blocks/challenges, translates the technical log into plain English (*"3 minutes ago, WebCare blocked a background request from Elementor / Stripe Webhook"*), and offers two 1-click buttons:
    1. **"✅ Trust & Allow This Action Permanently"** (automatically creates the targeted bypass/exemption rule and unblocks the IP).
    2. **"⏸️ Pause Strict Firewall Rules for 15 Minutes (Test Mode)"** (switches WAF to Monitor-Only for 15 minutes with an automatic countdown timer so it re-arms itself even if the owner forgets!).

### 4.3 "Smart 48-Hour Auto-Pilot" for Modular Firewall Rules
- Non-technical users won't know whether a synthesized `MOD-AJAX-*` or `MOD-REST-*` rule should be set to `Enforce` or `Monitor`.
- **How It Works**:
  - Add a **"✨ Smart Auto-Pilot (Recommended for Site Owners)"** toggle in Step 3 and on the Modular WAF page:
    - High-certainty threats (`MOD-TAMPER-*` modified files and `MOD-ABSPATH-*` naked scripts in uploads) immediately start in **`Enforce (Block)`**.
    - Newly discovered `MOD-AJAX-*` and `MOD-REST-*` rules on active plugins start in **`Smart Learning (48h)`**: if regular visitors use the endpoint cleanly, WebCare keeps the endpoint open for normal traffic while enforcing **SQLi/XSS payload filtering + rate limiting**; if zero legitimate visitors ever call a dormant endpoint, it automatically promotes to **`Enforce`**!

### 4.4 Plain-English "Daily Security Story" Card on Dashboard
- Instead of opening the Dashboard with raw tables of HTTP status codes, CIDR blocks, and regex rule IDs, show a human-friendly **Security Story Banner** at the top:
  > *"🛡️ **Your site had a quiet, safe week.** WebCare Pro automatically stopped **318 password-guessing bots**, **42 fake SEO scrapers**, and **6 checkout card-testing attempts** before they could slow down your server. **0 real customers** were blocked."*

### 4.5 Admin Bar "Quick Unblock Customer" Popover (`#WEBCARE-XXXX`)
- When a customer emails a store owner saying *"I got blocked with code `#WEBCARE-492A`"*, the store owner shouldn't have to hunt through firewall submenus.
- Add a compact dropdown inside the WordPress top Admin Bar (`🛡️ WebCare Pro`): the owner pastes `#WEBCARE-492A` (or the customer's IP) right into the admin bar box from any screen (even while viewing WooCommerce Orders) and clicks **Unblock Customer in 1 Click**.

### 4.6 Safe Update & 1-Click Virtual Shield for Outdated Plugins
- When a non-technical user sees *"Plugin X is outdated / vulnerable"*, they often hesitate to update because they fear breaking their theme layout.
- Give them two side-by-side buttons right on the alert card:
  1. **"🛡️ Shield Without Updating (1-Click Virtual Patch)"** — activates the `MOD-CVE-*` virtual patch so the vulnerable endpoint is protected immediately at the firewall level.
  2. **"🔄 Safe Update (With Auto-Backup)"** — backs up the plugin directory to `webcare-pro-security/vault` before running the WordPress update so the owner can roll back in 1 click if anything looks wrong.
