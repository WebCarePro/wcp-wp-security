# WCP Security Scanner (v2.6.0) — Complete Security, Bug Fix & Production-Readiness Roadmap

This engineering specification provides exact file paths, method names, line numbers, root-cause analyses, and drop-in PHP code replacements for every critical bug, security vulnerability, firewall rule bypass, false positive, and production-readiness gap identified in **WCP Security Scanner v2.6.0**.

## Phase 1: P0 Showstopping Bugs & Security Vulnerabilities (Immediate Fixes)

These 12 issues currently break core functionality (2FA login, Guest AJAX, WooCommerce Blocks Checkout, Virtual Patching, Session Hijack Protection, Deobfuscation, Apache 2.4 compatibility) or introduce critical security risks (Stored XSS in `wp-admin`, JIT Admin privilege escalation).

### 1.1 Fix 100% Broken 2FA Challenge Screen (`includes/Auth/TwoFactorAuth.php`)

* **Target**: `TwoFactorAuth::render_2fa_challenge_screen()` (lines 1080–1085)
* **Root Cause**: `sanitize_key()` lowercases `'POST'` into `'post'`, causing `$request_method === 'POST'` to always evaluate to `false`. Users redirected to the fallback 2FA challenge screen can never submit their TOTP or backup code.
* **Before (lines 1081–1082)**:
```php
$request_method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : '';
if ($request_method === 'POST' && isset($_POST['wcpscan_2fa_code'])) {
```
* **After**:
```php
$request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : '';
if ($request_method === 'POST' && isset($_POST['wcpscan_2fa_code'])) {
```

### 1.2 Fix 100% Broken Guest AJAX Whitelist in Preload Micro-WAF (`includes/Firewall/MicroWafCompiler.php`)

* **Target**: `MicroWafCompiler::compile_caf_data_artifact()` (lines 515–523) and `MicroWafCompiler::generate_standalone_code()` (lines 330–345)
* **Root Cause**:
  1. `strlen('wp_ajax_nopriv_')` is `15`, not `16`. Calling `substr($hook_name, 16)` strips the first character off every registered guest AJAX action (e.g., `wpforms_submit` becomes `pforms_submit`), causing `WAF-CAF-DORMANT-AJAX-ACTION` in `micro-waf-compiled.php` to block 100% of third-party guest AJAX actions with HTTP 403.
  2. Many plugins conditionally register `wp_ajax_nopriv_*` hooks inside `if (wp_doing_ajax())`, which are not present in `$wp_filter` when `compile_caf_data_artifact()` runs during admin settings saves or cron jobs.
* **Before (`compile_caf_data_artifact()`, lines 517–521)**:
```php
foreach (array_keys($wp_filter) as $hook_name) {
    if (is_string($hook_name) && str_starts_with($hook_name, 'wp_ajax_nopriv_')) {
        $allowed_nopriv_actions[] = substr($hook_name, 16);
    }
}
```
* **After (`compile_caf_data_artifact()`, lines 517–521)**:
```php
foreach (array_keys($wp_filter) as $hook_name) {
    if (is_string($hook_name) && str_starts_with($hook_name, 'wp_ajax_nopriv_')) {
        $allowed_nopriv_actions[] = substr($hook_name, 15);
    }
}
```
* **Additional Fix in `generate_standalone_code()` (lines 330–345)**:
  Ensure `WAF-CAF-DORMANT-AJAX-ACTION` only blocks known dormant/deactivated plugin prefixes or logs in monitor mode rather than hard-blocking every unknown `admin-ajax.php` action at the `auto_prepend_file` layer before WordPress loads plugins that use `wp_doing_ajax()`.

### 1.3 Fix Preload Micro-WAF Blocking 3-Segment REST Namespaces (`includes/Firewall/MicroWafCompiler.php`)

* **Target**: `MicroWafCompiler::generate_standalone_code()` (lines 313–328)
* **Root Cause**: The compiled Micro-WAF only extracts 1-segment (`$segments[0]`) or 2-segment (`$segments[0] . '/' . $segments[1]`) REST prefixes to compare against `$active_namespaces`. WooCommerce Store API registers `wc/store/v1` (3 segments), so `$prefix_candidate` (`wc/store`) is not found in `$active_namespaces`, causing `WAF-CAF-DORMANT-REST-NAMESPACE` to block all WooCommerce Blocks Cart & Checkout requests with HTTP 403.
* **Before (lines 313–328)**:
```php
$segments = explode('/', $rest_route);
$prefix_candidate = $segments[0] ?? '';
if (isset($segments[1]) && $segments[1] !== '') {
    $prefix_candidate = $segments[0] . '/' . $segments[1];
}
$active_namespaces = $caf_data['active_rest_namespaces'] ?? [];
if ($prefix_candidate !== '' && !empty($active_namespaces)) {
    if (!in_array($prefix_candidate, $active_namespaces, true) && !in_array($segments[0], $active_namespaces, true)) {
        wcp_micro_waf_block('WAF-CAF-DORMANT-REST-NAMESPACE', 'Request to unregistered REST namespace: ' . $prefix_candidate, $client_ip, $request_uri, $caf_learning);
    }
}
```
* **After**:
```php
$active_namespaces = $caf_data['active_rest_namespaces'] ?? [];
if ($rest_route !== '' && !empty($active_namespaces)) {
    $namespace_matched = false;
    foreach ($active_namespaces as $ns) {
        $ns_clean = trim((string) $ns, '/');
        if ($ns_clean !== '' && ($rest_route === $ns_clean || strpos($rest_route, $ns_clean . '/') === 0)) {
            $namespace_matched = true;
            break;
        }
    }
    if (!$namespace_matched) {
        wcp_micro_waf_block('WAF-CAF-DORMANT-REST-NAMESPACE', 'Request to unregistered REST namespace: ' . $rest_route, $client_ip, $request_uri, $caf_learning);
    }
}
```

### 1.4 Fix 100% Broken `POST` Inspection in `VirtualPatchManager` (`includes/Firewall/VirtualPatchManager.php`)

* **Target**: `VirtualPatchManager::evaluate_request()` (lines 364–384)
* **Root Cause**: `$method` is sanitized via `sanitize_key()`, which returns lowercase `'post'`. Consequently, `if ($method === 'POST')` at line 369 is always `false` (`php://input` is never read) and `in_array($method, $rule['methods'], true)` at line 381 against `['POST']` is always `false` (`VPATCH-FILE-UPLOAD` and all POST virtual patches never trigger).
* **Before (lines 364–384)**:
```php
$method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
$query  = isset($_SERVER['QUERY_STRING']) ? rawurldecode(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';

// Inspect raw body safely (limited to first 64KB for performance)
$raw_body = '';
if ($method === 'POST') {
    $raw_body = (string) @file_get_contents('php://input', false, null, 0, 65536);
}
```
* **After**:
```php
$method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
$query  = isset($_SERVER['QUERY_STRING']) ? rawurldecode(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';

// Inspect raw body safely (limited to first 64KB for performance)
$raw_body = '';
if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
    $raw_body = (string) @file_get_contents('php://input', false, null, 0, 65536);
}
```
* **Also normalize rule methods at line 381**:
```php
$allowed_methods = array_map('strtoupper', (array) $rule['methods']);
if (!empty($allowed_methods) && !in_array('*', $allowed_methods, true) && !in_array($method, $allowed_methods, true)) {
    continue;
}
```

### 1.5 Fix Stored XSS via `<script>` Breakout in `CrashGuard` (`includes/System/CrashGuard.php`)

* **Target**: `CrashGuard::render_admin_notice()` (line 497)
* **Root Cause**: `$incident` contains attacker-controlled request URIs, `$_GET`/`$_POST` values, and source code lines (`code_snippet`), and is echoed inside `<script type="application/json" id="wcp-crashguard-json-dossier">` with `JSON_UNESCAPED_SLASHES`. Any payload containing `</script><script>...` breaks out of the `<script>` tag and executes arbitrary JavaScript in `wp-admin`.
* **Before (line 497)**:
```php
<script type="application/json" id="wcp-crashguard-json-dossier"><?php echo wp_json_encode($incident, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES); ?></script>
```
* **After**:
```php
<script type="application/json" id="wcp-crashguard-json-dossier"><?php echo wp_json_encode($incident, JSON_PRETTY_PRINT | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?></script>
```

### 1.6 Fix Single-Fault Global WAF Kill-Switch in `CrashGuard` (`includes/System/CrashGuard.php`)

* **Target**: `CrashGuard::engage_safe_mode_from_throwable()` (lines 293–305) and `CrashGuard::run_guarded()` (lines 125–155)
* **Root Cause**: Any single uncaught `Throwable` inside any plugin subsystem immediately sets `update_option('wcpscan_circuit_breaker_safe_mode', true, true)`. On every subsequent request, `CrashGuard::run_guarded()` skips `Plugin::get_instance()`, completely disabling the WAF, 2FA, and Login Hardening site-wide until an admin manually resets Safe Mode.
* **Required Fix**:
  1. Require at least `3` fatal crashes within a `60`-second sliding window before engaging Safe Mode, AND auto-expire Safe Mode after 15 minutes (`wcpscan_circuit_breaker_safe_mode_until`) rather than permanently disabling security.
  2. Even when Safe Mode is engaged for non-critical modules (like AI Service or Scanner), keep `FirewallEngine`, `TwoFactorAuth`, and `LoginHardening` active unless the crash trace explicitly originated inside that specific file.

### 1.7 Fix JIT Ephemeral Admin & Support Tech Sandbox Escape (`includes/Auth/WcpJitMuGuardian.php` & `includes/Plugin.php`)

* **Target**: `WcpJitMuGuardian::intercept_unauthorized_rest_actions()` (lines 257–306) and `Plugin::deactivate()` (lines 603–634)
* **Root Cause**:
  1. A restricted JIT Admin or Temporary Support Technician (`wcp_temp_tech`) is not blocked from calling `/wcp-scanner/v1/identity/jit-elevate` (re-elevating themselves for 7 days), `/wcp-scanner/v1/auth/admin-2fa/disable` (disabling the primary owner's 2FA), `/wcp-scanner/v1/backup/create` & `/backup/download` (downloading full database dumps), `/wcp-scanner/v1/database/` (modifying `wp_users`), or `/wcp-scanner/v1/file/view` (reading `wp-config.php`).
  2. `wp-content/mu-plugins/wcp-jit-guardian.php` is never deleted in `Plugin::deactivate()` or default `uninstall.php`.
* **After (`WcpJitMuGuardian::intercept_unauthorized_rest_actions()`, lines 267–298)**:
```php
$blocked_scanner_routes = [
    '/wcp-scanner/v1/quarantine/delete',
    '/wcp-scanner/v1/file/delete',
    '/wcp-scanner/v1/file/view',
    '/wcp-scanner/v1/file/fix-permissions',
    '/wcp-scanner/v1/remediation/execute',
    '/wcp-scanner/v1/remediation/auto-clean',
    '/wcp-scanner/v1/users/remediate',
    '/wcp-scanner/v1/settings',
    '/wcp-scanner/v1/firewall/reset',
    '/wcp-scanner/v1/identity/jit-elevate',
    '/wcp-scanner/v1/identity/jit-revoke',
    '/wcp-scanner/v1/identity/temp-link',
    '/wcp-scanner/v1/auth/admin-2fa',
    '/wcp-scanner/v1/backup',
    '/wcp-scanner/v1/database',
    '/wcp-scanner/v1/encryption',
];
```
* **Also add cleanup in `Plugin::deactivate()` and `uninstall.php`**:
```php
$mu_guardian = defined('WPMU_plugin_dir') ? WPMU_PLUGIN_DIR . '/wcp-jit-guardian.php' : WP_CONTENT_DIR . '/mu-plugins/wcp-jit-guardian.php';
if (file_exists($mu_guardian)) {
    @unlink($mu_guardian);
}
```

### 1.8 Fix Dead Deobfuscation Pass & Zip-Bomb DoS (`includes/Malware/DeobfuscationEngine.php`)

* **Target**: `DeobfuscationEngine::safely_unpack()` (lines 104–145)
* **Root Cause**:
  1. Step 1 decodes `base64_decode('...')` and replaces the matched string in `$content` with raw binary compressed bytes *before* Step 2 searches for `gzinflate(base64_decode('...'))`. Because the inner `base64_decode('...')` was already mutated by Step 1, Step 2's regex can never match!
  2. `@gzinflate($decoded)` and `@gzuncompress($decoded)` have no `$max_length` limit, allowing a small zip-bomb payload to exhaust PHP memory during a scan.
* **After (`DeobfuscationEngine::safely_unpack()`, lines 104–145)**:
```php
// 1. Nested gzinflate/gzuncompress/gzdecode + base64_decode (MUST run BEFORE standalone base64_decode)
if (preg_match_all('/(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*base64_decode\s*\(\s*[\'"]([a-zA-Z0-9+\/=]+)[\'"]\s*\)\s*\)/i', $content, $matches)) {
    foreach ($matches[0] as $idx => $full_match) {
        $b64_str = $matches[1][$idx];
        $decoded = @base64_decode($b64_str, true);
        if ($decoded !== false) {
            $uncompressed = @gzinflate($decoded, 524288);
            if ($uncompressed === false) {
                $uncompressed = @gzuncompress($decoded, 524288);
            }
            if ($uncompressed === false && function_exists('gzdecode')) {
                $uncompressed = @gzdecode($decoded, 524288);
            }
            if ($uncompressed !== false && strlen($uncompressed) <= 524288) {
                $content = str_replace($full_match, $uncompressed, $content);
                $layers_peeled++;
            }
        }
    }
}

// 2. Direct base64_decode('...') extraction (only replace when decoded payload is printable ASCII/UTF-8)
if (preg_match_all('/base64_decode\s*\(\s*[\'"]([a-zA-Z0-9+\/=\s]{20,})[\'"]\s*\)/i', $content, $matches)) {
    foreach ($matches[0] as $idx => $full_match) {
        $b64_str = $matches[1][$idx];
        $decoded = @base64_decode(preg_replace('/\s+/', '', $b64_str), true);
        if ($decoded !== false && strlen($decoded) > 4 && strlen($decoded) <= 524288 && preg_match('/^[\x09\x0A\x0D\x20-\x7E]+$/', $decoded)) {
            $content = str_replace($full_match, $decoded, $content);
            $layers_peeled++;
        }
    }
}
```

### 1.9 Fix Session Sentinel Fatal `TypeError`, Undefined `$support_link_meta`, and Metadata Overwrite (`includes/Auth/SessionSentinel.php`)

* **Target**:
  1. `SessionSentinel::inspect_active_session()` (line 260): Passes `$decoded` (which is `null` if JSON decoding fails or has not run) into `self::is_ip_match_or_subnet($anchored_ip, $current_ip, $strict_ip, $decoded)` where parameter 4 is typed `array $decoded_meta = []`, throwing a `TypeError` that silently aborts session hijack enforcement.
  2. `SessionSentinel::anchor_session()` (lines 539–557): Overwrites existing session anchor metadata without preserving `auth_type` and `auth_label` set during login.
  3. `SessionSentinel::get_active_sessions()` (line 868): References undefined variable `$support_link_meta`.
* **Fixes**:
  * **Line 260**: Change `$decoded` to `is_array($decoded ?? null) ? $decoded : []`.
  * **Lines 539–557 (`anchor_session`)**: Read existing `get_user_meta($user_id, self::META_PREFIX . $verifier, true)` first, decode it, and preserve `$existing['auth_type'] ?? 'password'` and `$existing['auth_label'] ?? 'Password'`.
  * **Line 848 (`get_active_sessions`)**: Initialize `$support_link_meta = null;` at the top of the `foreach ($tokens as $verifier => $token_data)` loop.

### 1.10 Fix Apache 2.4 HTTP 500 Crash, REST API `PUT`/`DELETE` Block & `.zip` Download Block (`includes/Firewall/ServerSecurityEngine.php` & `includes/Remediation/TransactionalRemediation.php`)

* **Target**: `ServerSecurityEngine::generate_apache_rules()` (lines 185–249), `ServerSecurityEngine::generate_nginx_rules()` (lines 257–311), `ServerSecurityEngine::verify_rule_enforcement()` (lines 515–560), and `TransactionalRemediation::get_transactions_dir()` (line 31)
* **Root Cause**:
  1. Bare `Order Allow,Deny` / `Deny from all` outside `<IfModule !mod_authz_core.c>` causes an immediate **HTTP 500 Internal Server Error** on Apache 2.4 servers where `mod_access_compat` is disabled.
  2. `<LimitExcept GET POST HEAD>` (Apache) and `if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }` (Nginx) block `PUT`, `PATCH`, `DELETE`, and `OPTIONS`, breaking the WordPress REST API, Gutenberg editor, and WooCommerce REST integrations.
  3. `<FilesMatch "\.(sql|bak|tar|gz|zip|ini|sh)$">` blocks all legitimate `.zip` downloads across the entire website.
  4. `verify_rule_enforcement()` treats `404 Not Found` on non-existent probe URLs (`readme.html`, `/wp-content/uploads/wcp-test-probe.php`) as `"Enforced (Protected)"`, reporting false verification success on Nginx.
* **Fixes**:
  * Wrap all legacy `Order Allow,Deny` / `Deny from all` blocks in `<IfModule !mod_authz_core.c> ... </IfModule>` alongside `<IfModule mod_authz_core.c> Require all denied </IfModule>` in both `ServerSecurityEngine.php` and `TransactionalRemediation.php`.
  * Change `<LimitExcept GET POST HEAD>` to `<LimitExcept GET POST HEAD OPTIONS PUT PATCH DELETE>` (and `^(GET|POST|HEAD|OPTIONS|PUT|PATCH|DELETE)$` in Nginx).
  * Remove `zip` from the root `FilesMatch` rule (`\.(sql|bak|tar|gz|ini|sh|env)$`).
  * In `verify_rule_enforcement()`, only mark a rule `"enforced"` when the HTTP status is `403` (or create and remove a temporary probe file inside `uploads/wcp-security-scanner/` to test PHP execution blocking accurately).

### 1.11 Fix Unregistered Cron Interval in `CloudflareIpListSynchronizer` (`includes/Firewall/CAF/CloudflareIpListSynchronizer.php`)

* **Target**: `CloudflareIpListSynchronizer::register_cron()` (line 406)
* **Root Cause**: Uses `'wcp_every_five_minutes'`, which is never registered in WordPress's `cron_schedules` filter (`Scheduler.php` registers `'wcp_15min'`). As a result, `wp_schedule_event()` fails and Cloudflare IP sync never runs.
* **Fix**: Register `'wcp_every_five_minutes'` (`['interval' => 300, 'display' => 'Every 5 Minutes (WCP Security)']`) in `Scheduler::add_cron_intervals()` or change line 406 to `'wcp_15min'`.

### 1.12 Remove Raw JSX Comments from PHP HTML Output (`includes/Admin/AdminMenu.php`)

* **Target**: `AdminMenu::render_plugins_uninstall_modal()` (lines 817, 830, 868, 875)
* **Root Cause**: Literal JSX comments `{/* Header */}`, `{/* Body Content */}`, `{/* Option 1: Keep Data */}`, and `{/* Option 2: Delete Everything */}` are inside raw HTML output on `wp-admin/plugins.php` and render visibly to users.
* **Fix**: Remove those four `{/* ... */}` lines or convert them to PHP comments `<?php // ... ?>`.

## Phase 2: Firewall & WAF Rule Fixes (`includes/Firewall/*`)

### 2.1 Lock Down `FirewallEngine::is_authenticated_editor_or_builder()` (Lines 513–648)

* **Flaws**:
  1. Grants complete WAF rule bypass (`evaluate_rules()`) to any user with `edit_posts` (which includes low-privilege Contributors and Authors) without verifying any WordPress nonce (`_wpnonce` or `HTTP_X_WP_NONCE`).
  2. Whitelists `/wp-json/wp/v2/` and `/wp-json/elementor/` and builder query strings (`?et_fb=1`, `?fl_builder=1`, `?ct_builder=true`, `?bricks=run`, `?vc_editable=true`) for any `edit_posts` user even without a valid REST/Admin nonce, enabling CSRF-based WAF bypasses and privilege escalation by Contributors.
* **Required Fix**:
  1. Change the capability requirement from `current_user_can('edit_posts')` to `current_user_can('unfiltered_html')` (which restricts the bypass to Administrators and Editors on single-site installs and Super Admins on Multisite).
  2. Require a valid nonce check on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`): verify either `wp_verify_nonce($_SERVER['HTTP_X_WP_NONCE'], 'wp_rest')` for REST requests or a valid admin/builder nonce before skipping `evaluate_rules()`.

### 2.2 Eliminate the 256 KB Payload Padding Bypass & Decode JSON `\uXXXX` Escapes (`FirewallEngine::evaluate_rules()`, Lines 1658–1689)

* **Flaws**:
  1. Line 1663 (`if (!empty($raw_input) && strlen($raw_input) < 262144)`) completely skips inspecting `php://input` when an attacker pads the request body to `>= 256 KB`.
  2. `evaluate_rules()` does not decode JSON Unicode escapes (`\u0055NION \u0053ELECT` or `\u003cscript\u003e`), allowing attackers to bypass all WAF regexes on `/wp-json/` endpoints while `WP_REST_Request` automatically decodes the JSON.
* **Before (lines 1660–1672)**:
```php
if ($request_method === 'POST' || $request_method === 'PUT' || $request_method === 'PATCH') {
    $raw_input = @file_get_contents('php://input');
    if (!empty($raw_input) && strlen($raw_input) < 262144) { // 256KB safety limit
        $payloads[] = rawurldecode($raw_input);
    }
}
```
* **After**:
```php
if (in_array($request_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
    // Read first 256KB and last 64KB so padding >256KB cannot bypass inspection
    $raw_head = (string) @file_get_contents('php://input', false, null, 0, 262144);
    if ($raw_head !== '') {
        $normalized_body = rawurldecode($raw_head);
        // Decode JSON \uXXXX escapes so REST JSON payloads cannot evade SQLi/XSS regexes
        if (strpos($normalized_body, '\\u') !== false) {
            $normalized_body = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function ($m) {
                return html_entity_decode('&#x' . $m[1] . ';', ENT_QUOTES, 'UTF-8');
            }, $normalized_body);
        }
        $payloads[] = $normalized_body;
    }
    $content_len = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
    if ($content_len > 262144) {
        $raw_tail = (string) @file_get_contents('php://input', false, null, max(0, $content_len - 65536), 65536);
        if ($raw_tail !== '') {
            $payloads[] = rawurldecode($raw_tail);
        }
    }
}
```

### 2.3 Fix URL Whitelist Root `/` Wipeout & Prefix Collision (`FirewallEngine.php`, Lines 4695–4715 & 4790–4805)

* **Target**: `FirewallEngine::is_url_whitelisted()` (line 4703) and `FirewallEngine::match_targeted_allowlist_rule()` (line 4796)
* **Root Cause**: `strpos($path, rtrim($allowed_clean, '/')) === 0` turns `/` into `''` (`rtrim('/', '/') === ''`), and `strpos($path, '') === 0` is `true` for every URL in PHP! Furthermore, whitelisting `/api` unintentionally matches `/api-exploit`.
* **Before (line 4703)**:
```php
if ($path === $allowed_clean || strpos($path, rtrim($allowed_clean, '/')) === 0) {
    return true;
}
```
* **After**:
```php
$trimmed = rtrim($allowed_clean, '/');
if ($path === $allowed_clean || ($trimmed !== '' && ($path === $trimmed || strpos($path, $trimmed . '/') === 0))) {
    return true;
}
```
*(Apply the identical boundary check at line 4796 in `match_targeted_allowlist_rule()`.)*

### 2.4 Fix Spoofable Webhook Headers & Shopper Session Cookies (`FirewallEngine.php`, Lines 2240–2422)

* **Target**: `FirewallEngine::is_commerce_or_membership_request()` and `FirewallEngine::has_active_shopper_session()`
* **Root Cause**: Any attacker sending `Cookie: woocommerce_items_in_cart=1` or `Stripe-Signature: 1` is treated as a verified commerce webhook or active shopper, bypassing Rule #34 (URI/Query/POST flood protection), Rule #37 (Guest REST Mutation Guard), Empty User-Agent/Referer POST blocking, and 404 rate limiting.
* **Required Fix**:
  1. In `is_commerce_or_membership_request()`, only honor `HTTP_STRIPE_SIGNATURE`, `HTTP_X_WC_WEBHOOK_SIGNATURE`, or `HTTP_PAYPAL_TRANSMISSION_ID` when `$uri` matches an actual webhook endpoint (`wc-api=`, `/wp-json/wc`, `/wp-json/stripe`, etc.), never on arbitrary URLs.
  2. In `has_active_shopper_session()`, remove `woocommerce_items_in_cart` and `woocommerce_cart_hash` (which are static, unauthenticated client-set cookies) and only check `wp_woocommerce_session_` with a valid format (`explode('||', $cookie_val)` having 4 parts and non-expired timestamp), and do **not** exempt shopper cookies from Rule #34 (URI/POST flood) or 404 scanner rate limiting.

### 2.5 Upgrade WAF Signatures in `FirewallEngine::evaluate_rules()` & `MicroWafCompiler`

| Rule ID & Location | Flaw to Fix | Updated Pattern / Logic |
|---|---|---|
| **Rule #1: Directory Traversal & LFI** (`FirewallEngine.php`, lines 1690–1696) | Misses `phar://`, `zip://`, `data://`, `expect://`, `glob://`, and `wp-config.php`. | Add `/(?:phar\|zip\|data\|expect\|glob):\/\/\|wp-config(?:-sample)?\.php/i` to the LFI array. |
| **Rule #2: SQL Injection** (`FirewallEngine.php`, lines 1699–1708) | 1) Missing `/s` (`PCRE_DOTALL`) modifier allows `UNION/*\n*/SELECT` bypass.<br>2) `/*!50000SELECT*/` bypasses `\bselect\b` because `0` and `S` are both `\w`.<br>3) `sleep\|benchmark` requires literal digits, bypassed by `SLEEP(1+1)` or `SLEEP(0x05)`. | 1) Add `/is` modifier to all SQLi regexes.<br>2) Replace MySQL versioned comment pattern with `/\/\*![0-9]*\s*(?:select\|union\|insert\|update\|delete\|drop\|alter\|sleep\|benchmark)/is`.<br>3) Change time-based blind SQLi pattern to `/\b(?:sleep\|pg_sleep)\s*\(\s*[^)]+\)\|\bbenchmark\s*\(\s*[0-9]+\s*,/is` and add `/\b(?:gtid_subset\|gtid_subtract\|extractvalue\|updatexml)\s*\(/is`. |
| **Rule #3: PHP Code Injection** (`FirewallEngine.php`, line 1724) | `/\b(?:system\|passthru\|shell_exec\|proc_open\|popen\|pcntl_exec)\s*\(/i` triggers false positives on normal English text like `"operating system (Windows)"`. | Keep `/\b(?:passthru\|shell_exec\|proc_open\|popen\|pcntl_exec\|posix_mkfifo\|posix_setuid)\s*\(/i` strict, and require PHP syntax context for `system`: `/(?:;\s*\|\|\s*\|\$\w+\s*=\s*\|\.\s*\|<\?(?:php)?\s+.*)system\s*\(\s*['"\$\w]/is`. |
| **Rule #3.5: Object Stream Injection** (`FirewallEngine.php`, line 1739) | Hardcoded always-on with no toggle in `$settings`. | Wrap in `if (!isset($settings['waf_block_object_injection']) \|\| !empty($settings['waf_block_object_injection']))`. |
| **Rule #4: XSS** (`FirewallEngine.php`, lines 1750–1756) | 1) `/javascript\s*:\s*[a-z0-9_]+/i` is bypassed by `javascript://%0aalert(1)` or `javascript:/*x*/alert(1)`.<br>2) Event handler regex only checks 8 events. | 1) Strip ASCII control chars (`[\x00-\x20]+`) before matching `/(?:javascript\|vbscript\|data\s*:\s*text\/html)\s*:/i`.<br>2) Expand event handler regex to `/\bon(?:error\|load\|mouseover\|mouseenter\|mouseleave\|click\|dblclick\|auxclick\|contextmenu\|focus\|blur\|pointerenter\|pointerover\|pointerdown\|toggle\|beforetoggle\|animationstart\|animationend\|animationiteration\|transitionend\|begin\|pageshow\|pagehide\|input\|invalid\|submit\|reset\|wheel\|drag\|drop\|copy\|cut\|paste)\s*=\s*[^\s>]+/i`. |
| **Rule #8: Malicious File Upload** (`FirewallEngine::inspect_uploaded_file()`, lines 5080–5375) | 1) `$prohibited_exts` misses `htaccess`, `ini`, `pht`, `pgif`, `inc`, `shtml`.<br>2) SVG XSS misses `<animate` and `<set`.<br>3) Polyglot check only reads the first 8,192 bytes, missing PHP code at the end of images >8 KB. | 1) Add `'htaccess', 'ini', 'pht', 'pgif', 'inc', 'shtml'` to `$prohibited_exts` and block filenames matching `/^\.(?:htaccess\|htpasswd\|user\.ini)$/i`.<br>2) Add `<animate` and `<set` to SVG inspection.<br>3) Read both first 8,192 bytes and last 8,192 bytes (`$size > 8192 ? @file_get_contents($tmp_name, false, null, $size - 8192, 8192) : ''`). |
| **Rule #32: Host Header Injection** (`FirewallEngine::validate_host_headers()`, line 6258) | Only checks the first item in comma-separated `X-Forwarded-Host` (`explode(',', $fwd_raw)[0]`). | Loop over every comma-separated host in `HTTP_X_FORWARDED_HOST` and reject any segment that fails validation or contains `@`. |
| **Rule #37: Guest REST Mutation Guard** (`FirewallEngine::inspect_guest_rest_dispatch()`, lines 6799–6950) | Never blocks even when `waf_guest_rest_policy === 'block'` (always returns `$result`), and includes `/wcp-scanner/` in `$safe_prefixes`. | Remove `/wcp-scanner/` from `$safe_prefixes` (only allow `/wcp-scanner/v1/auth/webauthn/assertion/`), and when `$policy === 'block'`, call `self::log_incident($rule_triggered, 'blocked')` and `return new \WP_Error('wcp_waf_rest_blocked', 'Unauthorized guest REST mutation blocked by WCP Firewall.', ['status' => 403]);`. |
| **IP Unban Substring Bug** (`FirewallEngine::remove_blocked_ip()`, line 3972) | `strpos($line, $ip) !== false` causes unblocking `192.168.1.1` to also delete `192.168.1.100` and `192.168.1.1/24`. | Extract the IP token before any `#` or whitespace (`$entry_ip = trim(preg_split('/[\s#]+/', $line)[0] ?? '');`) and compare `$entry_ip === $ip`. |

### 2.6 Fix Bot Spoofing Auto-Unban & HTTP/2 Client Blocking (`includes/Firewall/BotReconDefense.php`)

* **Target**: `BotReconDefense::verify_search_bot_reverse_dns()` (lines 176–260) and `BotReconDefense::check_http2_pseudo_header_anomaly()` (lines 413–420)
* **Root Cause**:
  1. `OFFICIAL_BOT_CIDRS` includes broad Google Cloud/Services (`74.125.0.0/16`, `172.217.0.0/16`, `2607:f8b0::/32`) and Microsoft Azure (`2603:1030::/32`) CIDRs, and `verify_search_bot_reverse_dns()` checks `is_search_bot_in_official_cidrs()` **before** reverse DNS PTR verification. Even worse, lines 201–205 call `FirewallEngine::remove_blocked_ip($ip)` automatically! Any attacker on an Azure VM or Google IP sending `User-Agent: bingbot` or `Googlebot` is marked `'genuine'` and automatically unbanned from `waf_blocked_ips`.
  2. `check_http2_pseudo_header_anomaly()` unconditionally blocks `curl`, `python`, and `Go-http-client` over HTTP/2 with no setting toggle.
* **Required Fix**:
  1. Always require verified forward-confirmed reverse DNS (`gethostbyaddr($ip)` ending in `.googlebot.com`, `.google.com`, `.search.msn.com`, etc. + `gethostbyname($hostname) === $ip`) as the primary verification step. Only fall back to strict crawler-only CIDRs (`66.249.64.0/19`, `157.55.39.0/24`, `207.46.13.0/24`, `40.77.167.0/24`) when DNS times out—remove `74.125.0.0/16`, `172.217.0.0/16`, `2607:f8b0::/32`, and `2603:1030::/32` from `OFFICIAL_BOT_CIDRS`.
  2. Gate `check_http2_pseudo_header_anomaly()` behind `!empty($settings['waf_block_http2_fingerprint_mismatch'])` (default `false` or score-based rather than instant 403 block).

### 2.7 Fix Outbound Egress Firewall Octal/Shortened IP SSRF Bypass & DNS Latency (`includes/Firewall/OutboundEgressFirewall.php`)

* **Target**: `OutboundEgressFirewall::resolve_and_inspect_host_ips()` (lines 202–264)
* **Root Cause**:
  1. Octal IPs (`0177.0.0.1`, `0251.0376.0251.0376`) and shorthand IPs (`127.1`, `2130706433`) fail `filter_var($host, FILTER_VALIDATE_IP)` and fail `dns_get_record()`, returning `threat = 'unresolvable_host'`. In the default `'monitor'` mode, `unresolvable_host` is not blocked (only `loopback_ssrf`, `cloud_metadata_ssrf`, and `private_network_ssrf` are hard-blocked in monitor mode at line 153), allowing cURL to connect directly to `127.0.0.1` or `169.254.169.254`!
  2. `dns_get_record($host, DNS_A | DNS_AAAA)` runs synchronously without caching on every `wp_remote_get()` / `wp_remote_post()` request, adding DNS latency even to approved hosts like `api.wordpress.org`.
* **Required Fix**:
  1. Before calling `filter_var($host, FILTER_VALIDATE_IP)`, check if `$host` consists solely of digits, dots, or hex/octal prefixes (`/^[0-9a-fA-FxX.]+$/`). If so, normalize via `ip2long($host)` -> `long2ip()` (or if `ip2long($host) === false`, immediately return `['safe' => false, 'threat' => 'loopback_ssrf', 'reason' => 'Malformed/Octal IP literal blocked']`).
  2. Skip `resolve_and_inspect_host_ips()` for hardcoded `DEFAULT_APPROVED_HOSTS` (`api.wordpress.org`, `downloads.wordpress.org`, etc.), and cache DNS resolution results for other hosts in a 5-minute transient or static in-memory array per request.

### 2.8 Make `FormSpamProtectionEngine` Cache-Safe & Enforce Required Fields (`includes/Firewall/FormSpamProtectionEngine.php`)

* **Target**: `FormSpamProtectionEngine::inspect_submission()` (lines 147–225) and `FormSpamProtectionEngine::log_spam_block()` (line 353)
* **Root Cause**:
  1. Line 175 rejects form submissions when `$elapsed > 7200` (2 hours). On sites with full-page caching (WP Rocket, LiteSpeed, Cloudflare), cached pages serve a `wcp_time_gate` token older than 2 hours, blocking 100% of legitimate users submitting comments or forms on cached pages.
  2. Lines 162 and 189 only validate `wcp_time_gate` and `wcp_human_telemetry` if `isset($request_data[...])`, allowing any bot that simply omits those fields from `$_POST` to bypass Tier 2 and Tier 3 checks completely.
  3. Line 353 calls non-existent class `\WcpScanner\Security\AuditLogger` instead of `\WcpScanner\System\AuditLogger`.
* **Required Fix**:
  1. Fix class reference at line 353 to `\WcpScanner\System\AuditLogger`.
  2. Increase the token max age from `7200` (2 hours) to `172800` (48 hours) or stamp the token dynamically via lightweight client-side JS on form focus so full-page caches never break submissions.
  3. Require `wcp_time_gate` on protected form submissions (if `!isset($request_data['wcp_time_gate'])` on a public comment/registration POST, treat as failed time-gate rather than passing).

## Phase 3: Database, Backup, Quarantine & Scanner Fixes

### 3.1 Fix Database Backup Row Truncation & Unencrypted `0775` Storage (`includes/Backup/DatabaseBackup.php`)

* **Target**: `DatabaseBackup::get_backup_dir()` (line 41) and `DatabaseBackup::process_step()` (line 599)
* **Root Cause**:
  1. Line 41 sets `@chmod($dir, 0775)` (world/group-writable on shared hosts) and stores unencrypted `.sql.gz` database dumps inside `wp-content/uploads/wcp-security-scanner/.db-backups/`. On Nginx servers (which ignore `.htaccess`), anyone who discovers or guesses the filename or accesses directory listings can download the database.
  2. Line 599 checks `if ($rows_count < $batch_limit || $state['current_row_offset'] >= $table_meta['total_rows'])`. Because `$table_meta['total_rows']` was snapshotted when the backup started, if rows are inserted into a busy table (`wp_options`, `wp_postmeta`, `wp_wc_orders`) while the backup is running, `$state['current_row_offset'] >= $table_meta['total_rows']` becomes `true` while more rows still exist—silently truncating the end of the table!
* **Required Fix**:
  1. Change `@chmod($dir, 0775)` to `@chmod($dir, 0750)`, add `web.config`, and append a 32-character cryptographic random suffix (`bin2hex(random_bytes(16))`) to every backup filename or encrypt the archive with `SecretVault`.
  2. At line 599, change the table completion check to strictly `if ($rows_count < $batch_limit)` so pagination continues until the query returns fewer rows than `$batch_limit`.

### 3.2 Restrict Table Scope & Encrypt Snapshots in `DatabaseRemediationManager` (`includes/Database/DatabaseRemediationManager.php`)

* **Target**: `DatabaseRemediationManager::get_row_details()`, `delete_row()`, `disable_autoload()`, `clean_row_content()` (lines 149–265)
* **Root Cause**: Accepts arbitrary `$table_name` without verifying that it belongs to `$wpdb->prefix`, and allows deleting or modifying the primary Administrator account in `wp_users` / `wp_usermeta`.
* **Required Fix**:
  1. Enforce `strpos($table_name, $wpdb->prefix) === 0` in `validate_identifier()` or at the start of every public method.
  2. Block `delete_row()` and `clean_row_content()` on `$wpdb->users` and `$wpdb->usermeta` when the target row belongs to the current user or the primary administrator (`user_id === 1` or `get_current_user_id()`).

### 3.3 Fix Multibyte Filename Stripping & Large-File Memory Exhaustion in `QuarantineManager` (`includes/Quarantine/QuarantineManager.php`)

* **Target**: `QuarantineManager::validate_safe_file_path()` (line 97) and `QuarantineManager::quarantine_file()` (line 162)
* **Root Cause**:
  1. Line 97 strips all non-ASCII characters via `preg_replace('/[^a-zA-Z0-9_\-\.\/\\\\ :]/', '', $file_path)`, breaking quarantine/view/delete operations on files with UTF-8/multibyte characters in their path.
  2. Line 162 loads the entire file into RAM with `file_get_contents($full_path)` and `openssl_encrypt()`, crashing PHP (`Allowed memory size exhausted`) if a user quarantines a large file (>32 MB).
* **Required Fix**:
  1. Replace the ASCII-only regex in `validate_safe_file_path()` with `PathValidator::validate_within_root($file_path, ABSPATH)`.
  2. Cap in-memory `openssl_encrypt()` at 20 MB (`filesize($full_path) <= 20971520`); for files larger than 20 MB, move the file directly into the locked quarantine vault (`@rename($full_path, $vault_path)`) with `chmod($vault_path, 0400)` and record `'encrypted' => false` in the manifest.

## Phase 4: High-Traffic Performance & Production-Readiness Improvements

### 4.1 Stop Writing High-Frequency WAF State to `wp_options`

* **Files Affected**:
  * `includes/Firewall/FirewallEngine.php` (`waf_blocked_ips`, `wcpscan_waf_learning_Queue`)
  * `includes/Firewall/AdaptiveRateLimiter.php` (transients per IP/bucket)
  * `includes/Firewall/CAF/ThreatScoreTracker.php` (`wcp_caf_threat_scores`)
  * `includes/Firewall/CAF/OriginLoadCircuitBreaker.php`
* **Problem**: Updating `wp_options` or database-backed transients on every blocked request or rate-limit hit causes severe MySQL row-lock contention on `wp_options` during a DDoS or brute-force attack.
* **Solution**:
  1. Ensure `wp_options` keys that change frequently (`wcpscan_waf_learning_Queue`, `wcp_caf_threat_scores`, `wcpscan_security_posture_history`) are saved with `$autoload = 'no'` (`false`).
  2. Route IP block lookups and rate-limit counters through `wp_cache_get()` / `wp_cache_set()` (when an external object cache like Redis/Memcached is present) or an atomic file-backed cache inside `wp-content/wcp-waf-rules/` before falling back to the custom `wp_wcp_firewall_blocks` table.

### 4.2 Convert Low-Confidence WAF Signatures from Instant-Block to Cumulative Threat Scoring

* **Files Affected**: `includes/Firewall/FirewallEngine.php`, `includes/Firewall/CAF/ThreatScoreTracker.php`
* **Problem**: Rules that match ambiguous patterns (such as single SQL keywords without syntax operators, generic HTTP client User-Agents, or missing `Referer` headers) cause false positives when configured to hard-block on the first hit.
* **Solution**:
  1. Classify every WAF rule into either **Tier A (Deterministic Exploit — Immediate 403 Block)** (e.g., `UNION SELECT`, `<?php`, `php://filter`, `.htaccess` upload, SSRF loopback) or **Tier B (Anomaly / Heuristic — Add +25 to +50 Threat Score via `ThreatScoreTracker::record_signal()`)**.
  2. Only trigger a 403 block for Tier B anomalies when the client IP's cumulative threat score crosses the threshold (e.g., `>= 100`).

### 4.3 Regenerate Integrity Manifest (`includes/System/plugin-manifest.json`)

* **Final Build Step**:
  After applying all code changes in Phases 1–4, regenerate `includes/System/plugin-manifest.json` so that `PluginSelfDefense` and the File Integrity Scanner compute matching SHA-256 hashes for all modified PHP files:
```bash
php -r '
$manifest = json_decode(file_get_contents("includes/System/plugin-manifest.json"), true);
foreach (array_keys($manifest["files"]) as $rel_path) {
    if (file_exists($rel_path)) {
        $manifest["files"][$rel_path] = hash_file("sha256", $rel_path);
    }
}
$manifest["generated_at"] = gmdate("Y-m-d\TH:i:s\Z");
file_put_contents("includes/System/plugin-manifest.json", json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
'
```

## Phase 5: Final 5 Edge-Case Polish Fixes (Post-v2.7.0 Verification)

After verifying the v2.7.0 build, apply these 5 final adjustments and re-run your zip packaging script so the updated PHP files and `plugin-manifest.json` are bundled into the new `.zip` archive:

### 5.1 Block Octal (`0177.0.0.1`), Hex (`0x7f.1`), and Shorthand (`127.1`) IPv4 Literals in Monitor Mode (`includes/Firewall/OutboundEgressFirewall.php`)

* **Target**: `OutboundEgressFirewall::evaluate_ssrf_destination()` (lines 472–478)
* **Why**: PHP 8's `ip2long()` returns `false` on octal (`0177.0.0.1`), hex (`0x7f.1`), and shorthand (`127.1`) IPv4 strings, which causes them to fall through to `unresolvable_host` (not blocked in default `'monitor'` mode) while libcurl resolves them to `127.0.0.1` or `169.254.169.254`.
* **Before (lines 472–478)**:
```php
// Normalize shorthand or octal/hex IPv4 representations (e.g. 0177.0.0.1, 127.1, 0x7f.1)
if (preg_match('/^[0-9a-fA-FxX.]+$/', $clean_host) && strpos($clean_host, '.') !== false) {
    $parsed_long = ip2long($clean_host);
    if ($parsed_long !== false) {
        $clean_host = long2ip($parsed_long);
    }
}
```
* **After**:
```php
// Normalize or hard-block shorthand/octal/hex IPv4 representations (e.g. 0177.0.0.1, 127.1, 0x7f.1)
if (preg_match('/^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){1,3}$/i', $clean_host)) {
    if (filter_var($clean_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return [
            'threat' => 'ssrf_loopback',
            'reason' => 'Non-standard octal, hex, or shorthand IPv4 literal blocked to prevent SSRF bypass.',
        ];
    }
}
```

### 5.2 Remove Redundant CIDR Calls That Skip Reverse DNS & User-Agent Checks (`includes/Firewall/FirewallEngine.php`)

* **Target**: `FirewallEngine.php` at lines 747–750, 1468–1471, and 3973–3976
* **Why**: `BotReconDefense::is_genuine_search_engine($client_ip, $ua)` already performs Forward-Confirmed Reverse DNS (FCrDNS) first and uses `is_search_bot_in_official_cidrs()` only as a fallback when `$ua` matches a search bot. Calling `|| BotReconDefense::is_search_bot_in_official_cidrs(...)` directly in `FirewallEngine.php` bypasses both the User-Agent check and FCrDNS check.
* **Before (lines 747–750 & 1468–1471)**:
```php
$is_legit_crawler = BotReconDefense::is_genuine_search_engine($client_ip, $ua) ||
    BotReconDefense::is_search_bot_in_official_cidrs($client_ip, 'googlebot') ||
    BotReconDefense::is_search_bot_in_official_cidrs($client_ip, 'bingbot');
```
* **After**:
```php
$is_legit_crawler = BotReconDefense::is_genuine_search_engine($client_ip, $ua);
```
*(Apply the same change at lines 3973–3976 inside `FirewallEngine::add_blocked_ip()`.)*

### 5.3 Avoid Hard-Blocking Legitimate `curl` / `python` Webhook & API Clients Over HTTP/2 (`includes/Firewall/FirewallEngine.php`)

* **Target**: `FirewallEngine.php` (lines 853–872)
* **Why**: `BotReconDefense::check_http2_pseudo_header_anomaly()` flags any `curl`, `python`, or `go-http-client` User-Agent over HTTP/2 as `script_http2_signature`, and line 870 immediately triggers a 403 block (`self::handle_rule_violation(...)`) before checking if the request is a legitimate webhook or API client.
* **Before (lines 853–872)**:
```php
if (class_exists('\\WcpScanner\\Firewall\\BotReconDefense')) {
    $h2_anomaly = \WcpScanner\Firewall\BotReconDefense::check_http2_pseudo_header_anomaly();
    if ($h2_anomaly !== null) {
        // Record threat score increment for header anomaly (+15)
        if (class_exists('\\WcpScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            \WcpScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, 'header_anomaly', 15.0);
        }

        $rule_triggered = [
            'id'          => 'BOT-H2-HEADER-ANOMALY',
            'name'        => 'HTTP/2 Header / Client-Hint Anomaly',
            'category'    => 'Protocol Anomaly Defense',
            'description' => $h2_anomaly['description'],
            'match_type'  => 'Header Anomaly',
            'match_value' => $h2_anomaly['anomaly'],
            'payload'     => "Client IP: {$client_ip} URI: {$request_uri}",
        ];
        self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
    }
}
```
* **After**:
```php
if (class_exists('\\WcpScanner\\Firewall\\BotReconDefense')) {
    $h2_anomaly = \WcpScanner\Firewall\BotReconDefense::check_http2_pseudo_header_anomaly();
    if ($h2_anomaly !== null) {
        // Record threat score increment for header anomaly (+15)
        if (class_exists('\\WcpScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            \WcpScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, 'header_anomaly', 15.0);
        }

        // Only hard-block malformed uppercase HTTP/2 pseudo-headers (or when strict HTTP/2 blocking is explicitly enabled)
        if (($h2_anomaly['anomaly'] ?? '') === 'uppercase_pseudo_header' || !empty($settings['waf_block_http2_anomalies'])) {
            $rule_triggered = [
                'id'          => 'BOT-H2-HEADER-ANOMALY',
                'name'        => 'HTTP/2 Header / Client-Hint Anomaly',
                'category'    => 'Protocol Anomaly Defense',
                'description' => $h2_anomaly['description'],
                'match_type'  => 'Header Anomaly',
                'match_value' => $h2_anomaly['anomaly'],
                'payload'     => "Client IP: {$client_ip} URI: {$request_uri}",
            ];
            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
        }
    }
}
```

### 5.4 Stream-Restore Large Quarantined Files (`>20 MB`) Without Memory Exhaustion (`includes/Quarantine/QuarantineManager.php`)

* **Target**: `QuarantineManager::restore_file()` (lines 339–369)
* **Why**: `quarantine_file()` now streams files `>20 MB` directly to disk after the `$guard_header`, but `restore_file()` still calls `file_get_contents($source_path)` in memory, which will hit PHP's memory limit when restoring a `>20 MB` file.
* **Before (lines 339–369)**:
```php
// Read vault file and extract payload
$vault_raw = @file_get_contents($source_path);
if ($vault_raw === false) {
    return ['success' => false, 'message' => 'Failed to read vault file for restoration.'];
}
...
if (!\WcpScanner\Filesystem\PathValidator::safe_atomic_write($dest_path, $clean_data, ABSPATH, $perms)) {
    return ['success' => false, 'message' => 'Failed to safely restore file to original location. Check directory permissions.'];
}
```
* **After**:
```php
$perms = !empty($record['file_perms']) ? octdec($record['file_perms']) : 0644;
$halt_marker = "__halt_compiler(); ?>\n";
$vault_size = (int) @filesize($source_path);

if ($vault_size > 20971520) {
    // Stream-restore large unencrypted vault files (>20MB) without loading into RAM
    $src_fp = @fopen($source_path, 'rb');
    if (!$src_fp) {
        return ['success' => false, 'message' => 'Failed to open large vault file for restoration.'];
    }
    $header_chunk = (string) fread($src_fp, 256);
    $pos = strpos($header_chunk, '__halt_compiler(); ?>');
    $offset = ($pos !== false) ? ($pos + strlen('__halt_compiler(); ?>')) : 0;
    if ($offset > 0 && isset($header_chunk[$offset]) && $header_chunk[$offset] === "\r") {
        $offset++;
    }
    if ($offset > 0 && isset($header_chunk[$offset]) && $header_chunk[$offset] === "\n") {
        $offset++;
    }
    fseek($src_fp, $offset);
    $dst_fp = @fopen($dest_path, 'wb');
    if (!$dst_fp) {
        fclose($src_fp);
        return ['success' => false, 'message' => 'Failed to open destination file for restoration.'];
    }
    stream_copy_to_stream($src_fp, $dst_fp);
    fclose($src_fp);
    fclose($dst_fp);
    @chmod($dest_path, $perms);
} else {
    // Read vault file and extract payload
    $vault_raw = @file_get_contents($source_path);
    if ($vault_raw === false) {
        return ['success' => false, 'message' => 'Failed to read vault file for restoration.'];
    }

    $payload = $vault_raw;
    $pos = strpos($vault_raw, '__halt_compiler(); ?>');
    if ($pos !== false) {
        $payload = ltrim(substr($vault_raw, $pos + strlen('__halt_compiler(); ?>')), "\r\n");
    }

    // Decrypt ciphertext if encrypted
    if (\WcpScanner\Security\SecretVault::is_encrypted($payload)) {
        $decrypted = \WcpScanner\Security\SecretVault::decrypt($payload);
        if ($decrypted === false) {
            return ['success' => false, 'message' => 'Cryptographic decryption failed: Invalid vault key or corrupted vault ciphertext.'];
        }
        $clean_data = $decrypted;
    } else {
        $clean_data = $payload;
    }

    if (!\WcpScanner\Filesystem\PathValidator::safe_atomic_write($dest_path, $clean_data, ABSPATH, $perms)) {
        return ['success' => false, 'message' => 'Failed to safely restore file to original location. Check directory permissions.'];
    }
}
```

### 5.5 Always Remove `wcp-jit-guardian.php` MU-Plugin on Uninstall (`uninstall.php`)

* **Target**: `uninstall.php` (lines 94 and 195–200)
* **Why**: Currently, `wp_delete_file($wcpscan_mu_file)` is inside `if ($wcpscan_delete_data)` (lines 195–200). If a user uninstalls the plugin with the default "Retain Data" option, `wcp-jit-guardian.php` is left behind in `wp-content/mu-plugins/`.
* **Fix**: Move lines 195–200 above `if ($wcpscan_delete_data)` (immediately after `ServerSecurityEngine::remove_rules()` at line 93) so the MU-plugin is always removed upon uninstallation.
