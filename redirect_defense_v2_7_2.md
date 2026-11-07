# Zero-Day Redirect Hack Defense & .htaccess Armor Architecture (v2.7.2)

**Author:** Mir Alamin (WebCare Pro) — Senior Linux SysAdmin & WordPress Security Engineer  
**Date:** 2026-11-07  
**Engine Version Target:** 2.7.2  
**Review Integration:** Grok Operational Review + Argon 2026 AI-Era Threat Hardening Incorporated  

## 1. Executive Summary: 2026 Real-World Threat Model

Redirect hacks in 2026 (Balada Injector, ClearFake, SocGholish, Angel Drainer, Keitaro TDS, Pharmacy/Casino SEO & AI-Search Cloaking, and ClickFix overlays) operate across five distinct layers of the WordPress stack simultaneously:

1. **Layer 1 — Pre-PHP Web Server (`.htaccess` / LiteSpeed / Nginx):** Conditional `RewriteCond` cloaking targeting search engines, AI crawlers, and mobile visitors, or catch-all `301/302` redirects that also break `wp-cron.php`.
2. **Layer 2 — Database & Bootstrap (`siteurl` / `home`, `db.php`, `object-cache.php`, `mu-plugins`):** Poisoned core URLs or early `header('Location: ...')` traps executing before standard plugins load.
3. **Layer 3 — Runtime PHP Hook & Output Buffer Hijacking:** Malicious closures hooked into `template_redirect`, `wp_redirect`, `wp_head`, `wp_footer`, or `ob_start()` that conditionally redirect guests or inject script loaders only for specific referrers and residential IPs.
4. **Layer 4 — Client-Side HTTP `200 OK` Cloaking & Web3/Serverless C2 Loaders:** Over 80% of 2026 redirect attacks return `HTTP 200 OK` (no `3xx` header) and trigger redirects in the browser via `<meta http-equiv="refresh">`, `<base href>`, dynamic `<script>` creation, or JSON-RPC calls to public blockchains (`eth_call` on BNB Smart Chain / Polygon) and serverless workers (`*.workers.dev`, `*.pages.dev`, `*.vercel.app`, IPFS).
5. **Layer 5 — Browser Persistence & Social Engineering (Service Workers & ClickFix):** Registering rogue browser Service Workers (`navigator.serviceWorker.register`) that keep hijacking returning visitors even after the server is cleaned, or displaying fake Cloudflare Turnstile / Chrome update modals (`ClickFix`) that hijack the clipboard (`navigator.clipboard.writeText`).

This architecture defeats all five layers **without breaking legitimate SEO plugins (Yoast, Rank Math, Redirection), page builders (Elementor, Divi), e-commerce payment gateways (WooCommerce, Stripe, PayPal), cache managers (WP Rocket, LiteSpeed, W3TC), or domain migrations.**

## 2. Locked-In Operational Specifications

| # | Principle | Hardened Specification |
|---|---|---|
| **1** | **Strict 3-Condition Auto-Heal Formula** | Automatic `.htaccess` restoration executes **ONLY IF ALL THREE CONDITIONS ARE MET**:<br>1. Canary probe (or Preload Micro-WAF check) confirms a hostile external redirect or cloaked payload.<br>2. Live `.htaccess` contains a matching hostile pattern (external target + cloaking condition or catch-all rewrite).<br>3. No verified admin/plugin rewrite flush (`flush_rewrite_rules` transient) occurred within a 5-minute grace window.<br>*(If the canary is hostile but `.htaccess` is clean, the engine does NOT touch `.htaccess`; it alerts immediately and attributes the redirect to Nginx, database `siteurl`/`home`, or a PHP hook/drop-in.)* |
| **2** | **Preload Micro-WAF Anti-Deadlock Watchdog** | A catch-all `.htaccess` redirect (`RewriteRule ^.*$ https://spam.xyz [R=302,L]`) breaks `wp-cron.php` loopback requests, which would otherwise deadlock scheduled canary crons. To prevent deadlock, `micro-waf-compiled.php` (`auto_prepend_file`) performs an O(1) `filemtime()` check on `ABSPATH . '.htaccess'` during any PHP execution and triggers immediate semantic verification and vault auto-heal if `.htaccess` was tampered with outside a legitimate flush window. |
| **3** | **HTTP `200 OK` Differential DOM Comparison** | Canary probes do **not** stop at checking `3xx` `Location` headers. On `HTTP 200 OK` responses, `RedirectCanaryEngine` compares the `<head>`, `<script src="...">`, `<meta http-equiv="refresh">`, and `<base href>` elements of **Probe A (Baseline Admin/Direct View)** against **Probes B, C, and E (Googlebot, Mobile, and AI Search Referrers)**. Any external script domain or redirect tag present in Probes B/C/E but absent in Probe A is flagged as a **Cloaked Injection**. |
| **4** | **Simulated Residential IP Forwarding for Self-Probes** | Malware frequently bypasses `127.0.0.1` and datacenter ASNs (`$_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']`). Canary self-probes send a randomized public residential test IP via `X-Forwarded-For` accompanied by a short-lived internal HMAC header (`X-WCP-Canary-Signature`) so `FirewallEngine` honors the probe while third-party malware sees an external visitor IP. |
| **5** | **Canary Edge-Case Immunity** | * **Admin Probe D:** A `302 Found` from `/wp-admin/` to `wp-login.php` on the same host is verified as **CLEAN**.<br>* Canonical `http → https` and `www ↔ non-www` redirects matching `home_url()` or `site_url()` hostnames are verified as **CLEAN**.<br>* Network timeouts or `cURL` errors are logged as connectivity warnings, **NEVER** flagged as redirect hacks. |
| **6** | **Inside-Block Semantic Scoring** | Vendor markers (`# BEGIN WordPress`, `# BEGIN LSCACHE`, `# BEGIN WP Rocket`) are **never** treated as a blind whitelist. Rules injected inside `# BEGIN WordPress` undergo full directive-level semantic scoring. |
| **7** | **Dual-Medium Rolling Vault (`.vault/` + Encrypted DB)** | The last 5 verified-clean `.htaccess` snapshots are stored both on disk (`wp-content/uploads/wcp-security-scanner/.vault/.htaccess.vault.1..5` with `0600` permissions and Apache/LiteSpeed deny rules) **AND** encrypted via `SecretVault` inside the database (`wcpscan_htaccess_vault_ mirrored`). If a resident PHP shell deletes `.vault/` on disk, restoration seamlessly falls back to the encrypted database snapshot. |
| **8** | **Runtime `wp_redirect` Call-Stack Firewall** | Hooks `wp_redirect` at priority `999999` on front-end guest requests. If PHP code attempts to redirect an unauthenticated visitor to an unapproved external domain (excluding Stripe, PayPal, WooCommerce gateways, OAuth providers, and whitelisted domains), the redirect is blocked in real time and `debug_backtrace()` records the exact offending PHP file and line number. |
| **9** | **Service Worker Eviction (`Clear-Site-Data`)** | When an active redirect or rogue Service Worker (`navigator.serviceWorker.register`) is remediated, the plugin can optionally emit `Clear-Site-Data: "cache", "storage"` headers for 24 hours on front-end responses so returning visitors' browsers automatically purge poisoned caches and rogue Service Workers. |
| **10** | **State-Transition Deduplication** | Background canaries run every 15 minutes (`wcp_15min`). Out-of-band alerts (Discord, Slack, Email) fire strictly on state transitions (`Clean → Hostile` and `Hostile → Recovered`) to prevent alert fatigue. |

## 3. The 5 Core Pillars: Technical Implementation Blueprint

### Pillar 1: Synthetic External Canary & Differential Cloaking Watchdog (`includes/Firewall/RedirectCanaryEngine.php`)

1. **Five Specialized Canary Probes (`redirection => 0`, `timeout => 8`):**
   * **Probe A (Baseline Desktop Direct):** Requests `home_url('/')` with standard Desktop User-Agent and no `Referer`. Establishes the baseline status code and baseline `<script src>` / `<meta>` inventory.
   * **Probe B (Search Engine Cloaking Trap):** Requests `home_url('/')` with `Referer: https://www.google.com/` and Googlebot/Desktop User-Agent + simulated residential IP.
   * **Probe C (Mobile Traffic Trap):** Requests `home_url('/')` with `Referer: https://www.google.com/` and iPhone/Android Mobile User-Agent (`Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)...`).
   * **Probe D (Admin Gatekeeper):** Requests `wp_login_url()` and `admin_url()` to verify login accessibility and ensure `Location` headers never point to an external phishing or spam host.
   * **Probe E (2026 AI Search / LLM Referrer Trap):** Requests `home_url('/')` with `Referer: https://chatgpt.com/` and `https://www.perplexity.ai/` (plus `OAI-SearchBot` User-Agent check) to detect 2026 AI-citation cloaking.
2. **Header & Body Inspection Pipeline:**
   * **3xx Header Check:** Extracts `Location` header on `301`, `302`, `303`, `307`, `308`. Parses target host via `wp_parse_url()` and compares against `home_url()` and `site_url()` hosts.
   * **200 OK Body Check (`inspect_canary_html_body()`):**
     * Detects `<meta\s+http-equiv=["']?refresh["']?\s+content=["']?\d+\s*;\s*url=([^"'>\s]+)` pointing to external hosts.
     * Detects `<base\s+href=["']https?:\/\/([^"'>\/]+)` pointing to external hosts.
     * Extracts all `<script[^>]+src=["']([^"']+)["']` URLs in Probes B, C, and E and diffs them against Probe A. If an external script domain appears **only** when `Referer` is Google/ChatGPT or on Mobile UA, flags `cloaked_script_injection`.
     * Scans inline `<script>` blocks in Probes B, C, and E for Web3 RPC C2 resolvers (`eth_call`, `bsc-dataseed`, `polygon-rpc`) and `window.location.replace` / `eval(atob(...))`.
3. **Database `siteurl` & `home` Integrity Correlation:**
   * Queries `SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name IN ('siteurl', 'home')` directly (bypassing object cache).
   * Compares against the signed baseline host stored in `SecretVault` (`wcpscan_canonical_host_baseline`). If `siteurl` or `home` was altered to a foreign domain, flags `database_url_hijacking` and provides 1-click restoration to the baseline domain.

### Pillar 2: Semantic `.htaccess` Classifier & Runtime Redirect Shield (`includes/Firewall/HtaccessShield.php`)

1. **Flush Grace Window Tracking:**
   * Hooks `flush_rewrite_rules_hard` and `activated_plugin` / `deactivated_plugin` to set a 5-minute signed transient (`wcpscan_htaccess_flush_grace`) and automatically snapshots the newly generated `.htaccess` if it passes semantic scanning.
2. **Directive-Grouping Semantic Classifier (`analyze_htaccess_content(string $content)`):**
   * Parses `.htaccess` line-by-line (ignoring `# BEGIN ...` / `# END ...` wrapper labels as trust boundaries) while grouping contiguous `RewriteCond` directives with their governing `RewriteRule`:
     * **Clean (Score 0):** `RewriteRule ^index\.php$ - [L]`, internal relative rewrites, same-host HTTPS/www canonical redirects, `ExpiresByType`, `Header set`, `AddOutputFilterByType`, and WCP's own `# BEGIN WCP_SECURITY_RULES` block.
     * **High / Critical (Score 80–100):**
       * `RewriteCond %{HTTP_REFERER} .*(google|bing|yahoo|yandex|duckduckgo|chatgpt|perplexity).*` paired with an external `RewriteRule` or `RedirectMatch`.
       * `RewriteCond %{HTTP_USER_AGENT} .*(android|iphone|ipad|mobile|googlebot|bingbot).*` paired with an external `RewriteRule`.
       * Catch-all `RewriteRule` or `RedirectMatch` (`^\.*$`, `^/?$`, `\.php$`) pointing to an external `https?://` host.
       * Rogue handler injection (`AddHandler application/x-httpd-php .jpg .png .ico`, `SetHandler application/x-httpd-php`, or unauthorized `auto_prepend_file` pointing outside WCP's own `micro-waf-compiled.php`).
3. **Runtime PHP Redirect Firewall (`inspect_runtime_redirect(string $location, int $status)`):**
   * Hooked via `add_filter('wp_redirect', [__CLASS__, 'inspect_runtime_redirect'], 999999, 2)`.
   * On unauthenticated front-end requests (`!is_user_logged_in()` and `!is_admin()`), validates the target host of `$location`:
     * Allows same-host redirects, relative paths, and approved commerce/auth domains (`checkout.stripe.com`, `www.paypal.com`, `accounts.google.com`, `login.microsoftonline.com`, plus any domain in `waf_redirect_allowlist` or active Redirection plugin tables).
     * If an unapproved external redirect is attempted during a guest page load, captures `debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15)` to identify the exact plugin, theme, or drop-in file/line, logs a critical `WAF-RUNTIME-REDIRECT-HIJACK` event, and neutralizes the redirect back to `home_url('/')` (when enforcement is enabled).

### Pillar 3: Dual-Medium Rolling Vault & Break-Glass Recovery (`includes/Firewall/HtaccessVaultManager.php`)

1. **5-Version Rolling Vault (Disk + Encrypted DB):**
   * Stores up to 5 deduplicated, verified-clean `.htaccess` versions (only pushing a new version when the SHA-256 hash of a clean `.htaccess` changes):
     * Disk path: `wp-content/uploads/wcp-security-scanner/.vault/.htaccess.vault.{1..5}.php` (wrapped with `<?php http_response_code(403); exit; __halt_compiler(); ?>` + AES-256-GCM encrypted payload via `SecretVault`, permissions `0600`).
     * Database mirror: Stored in `wp_options` (`wcpscan_htaccess_vault_snapshots`, `autoload = false`) so snapshots survive even if an attacker deletes the `.vault/` directory on disk.
2. **Atomic Restore + File Permission Lock + Cache Purge (`restore_snapshot(int $version = 1)`):**
   * Verifies target snapshot passes `HtaccessShield::analyze_htaccess_content()` before writing.
   * Restores `ABSPATH . '.htaccess'` atomically via `PathValidator::safe_atomic_write()`.
   * If opt-in `.htaccess` Read-Only Lock is enabled, applies `chmod(ABSPATH . '.htaccess', 0444)`.
   * **Automated Full-Page Cache Invalidation (`purge_all_site_caches()`):**
     * WP Rocket: `if (function_exists('rocket_clean_domain')) { rocket_clean_domain(); }`
     * LiteSpeed Cache: `do_action('litespeed_purge_all');`
     * W3 Total Cache: `if (function_exists('w3tc_flush_all')) { w3tc_flush_all(); }`
     * WP Super Cache: `if (function_exists('wp_cache_clear_cache')) { wp_cache_clear_cache(); }`
     * WP Fastest Cache / Autoptimize / SiteGround (`sg_cachepress_purge_cache`) / WordPress Object Cache (`wp_cache_flush()`).
     * Sets a 24-hour transient `wcpscan_emit_clear_site_data` to send `Clear-Site-Data: "cache"` on front-end HTML responses if a rogue Service Worker or cached JS redirect was remediated.
3. **WP-CLI Break-Glass Command (`wp wcp htaccess`):**
   * Registers WP-CLI commands when `defined('WP_CLI') && WP_CLI`:
     * `wp wcp htaccess status` — Runs live semantic scan + canary probe and prints table of findings.
     * `wp wcp htaccess vault` — Lists all 5 rolling snapshots with timestamp, SHA-256, byte size, and clean status.
     * `wp wcp htaccess restore [--version=<1-5>]` — Restores `.htaccess` from disk or DB vault and flushes all caches.

### Pillar 4: Full-Stack 2026 JS, Web3, ClickFix & Drop-In Redirect Scanner (`includes/Malware/JavaScriptSecurityScanner.php` & `includes/WordPress/PersistenceScanner.php`)

1. **2026 Client-Side JS & Web3 C2 Signatures (`JavaScriptSecurityScanner.php`):**
   * **Referrer/UA Cloaked Redirect Sinks:** Requires `External Host/Dynamic Sink` + (`document.referrer` check for `google|bing|yahoo|chatgpt|perplexity` OR mobile `navigator.userAgent` check OR `localStorage`/`sessionStorage`/`document.cookie` once-per-session gate).
   * **Web3 Blockchain Smart-Contract C2 Resolvers (ClearFake / Balada 2026):** Detects `eth_call`, `bsc-dataseed`, `binance.org`, `polygon-rpc.com`, `ankr.com/bsc`, or `web3.eth.call` combined with dynamic script injection (`createElement('script')`, `document.write`, `eval`, `Function(`).
   * **ClickFix / Fake Turnstile Clipboard Hijacking:** Detects `navigator.clipboard.writeText` or `document.execCommand('copy')` paired with shell execution strings (`powershell`, `mshta`, `Invoke-Expression`, `iex(`, `cmd.exe`, `-EncodedCommand`, `curl `).
   * **Rogue Service Worker Registration:** Detects `navigator.serviceWorker.register(` pointing to non-whitelisted scripts or scripts containing `Response.redirect` / external `fetch()` hijacking.
2. **HTML & Database Content Scanner (`ContentScanner.php` / `DatabaseScanner.php`):**
   * Scans `wp_posts.post_content`, `wp_postmeta` (`_elementor_data`), and `wp_options` widget/header/footer snippets for external `<meta http-equiv="refresh">`, external `<base href="...">`, and hidden `<iframe src="...">` zero-pixel traps.
3. **Early Drop-In & MU-Plugin Redirect Trap Auditor (`PersistenceScanner.php`):**
   * Audits `wp-content/db.php`, `wp-content/object-cache.php`, `wp-content/advanced-cache.php`, `wp-content/sunrise.php`, and `wp-content/mu-plugins/*.php` for `header('Location:` / `wp_redirect(` calls, `ob_start(` output buffer injectors, and remote C2 `wp_remote_get` / `curl_exec` redirect fetchers.

### Pillar 5: Out-of-Band Incident Dispatch (`includes/Notifications/NotificationDispatcher.php`)

1. **Dedicated Event Type (`redirect_hack_detected` & `redirect_hack_auto_healed`):**
   * Dispatches rich alerts via Discord (Red `#DC2626` embed on detection, Green `#10B981` embed on auto-heal), Slack Block Kit, and Email.
   * Includes:
     * **Triggered Probe(s):** e.g., `Probe B (Google Referer Cloak)` & `Probe E (AI Search Referer)`.
     * **Malicious Destination URL:** Full external redirect URL or injected script source.
     * **Root-Cause Attribution:** `.htaccess RewriteRule (Line 14)`, `Database siteurl Tampering`, or `Runtime wp_redirect() in wp-content/themes/.../functions.php:42`.
     * **Auto-Heal Status:** Whether `.htaccess` was automatically restored from Vault Snapshot #1 and site caches were purged.
2. **State-Transition Deduplication (`wcpscan_redirect_canary_state`):**
   * Tracks `status` (`clean` vs. `hostile`) and `last_target_hash`. Fires notifications immediately when transitioning `clean → hostile` or `hostile → clean`, suppressing duplicate alerts on consecutive 15-minute crons while the state remains unchanged.

## 4. Acceptance Test Matrix (v2.7.2 Verification Suite)

| Test # | Scenario | Expected Result |
|---|---|---|
| **1** | Clean site with WP Rocket / LiteSpeed / Yoast / Rank Math `.htaccess` rules | All 5 Canary Probes return clean; `HtaccessShield` scores `0`; `0` alerts fired. |
| **2** | Global `.htaccess` 301/302 redirect to external spam domain (breaking `wp-cron.php`) | Preload Micro-WAF (`micro-waf-compiled.php`) or Canary Probe A/D detects external redirect + `.htaccess` tampering; auto-heals from Vault #1 and purges caches. |
| **3** | Cloaked Google `Referer` + Mobile User-Agent `.htaccess` redirect | Probe A is clean (`200`), Probes B & C catch external `302`; flagged as Critical Search Engine Cloaking; auto-heal restores `.htaccess`. |
| **4** | Cloaked AI Search (`Referer: https://chatgpt.com/`) redirect | Probe E detects external redirect or injected script; flagged as AI-Search Cloaking. |
| **5** | HTTP `200 OK` PHP/JS cloaking (injects `<script src="https://evil.xyz/ldr.js">` only for Google Referer) | Differential DOM comparison between Probe A and Probe B catches the extra external `<script>` tag even though HTTP status is `200 OK`. |
| **6** | Standard `http → https` and `www` canonical redirects | Matched against `home_url()` / `site_url()` host; verified **CLEAN**. |
| **7** | Database `siteurl` / `home` modified to foreign domain | Canary Probe A + DB Option Sentinel attributes attack to `database_url_hijacking` without falsely overwriting `.htaccess`. |
| **8** | Unauthenticated `/wp-admin/` redirecting to local `wp-login.php` | Recognized as standard WordPress auth redirect on same host; verified **CLEAN**. |
| **9** | Hostile `RewriteRule` injected *inside* `# BEGIN WordPress` block | `HtaccessShield` inspects inside vendor comment markers and flags the external redirect. |
| **10** | Legitimate plugin (`Redirection` / `Yoast`) updates `.htaccess` during admin save | 5-minute flush grace transient is active and semantic classifier finds no cloaked malware; new clean snapshot is pushed to Vault #1. |
| **11** | Resident malware deletes `.vault/` files on disk and poisons `.htaccess` | `HtaccessVaultManager` seamlessly restores `.htaccess` from the encrypted database mirror in `SecretVault`. |
| **12** | Malicious code in `functions.php` calls `wp_redirect('https://drainer.xyz')` for guests | Runtime `wp_redirect` firewall blocks the redirect, logs `functions.php` line number via `debug_backtrace()`, and returns visitor safely to `home_url()`. |
| **13** | Web3 `eth_call` smart-contract loader or ClickFix `navigator.clipboard.writeText` in JS | `JavaScriptSecurityScanner` flags the file/post with Critical severity. |
| **14** | Execution of `wp wcp htaccess restore` or 1-Click Admin Restore | Atomic file write restores `.htaccess`, flushes WP Rocket/LiteSpeed/W3TC caches, and dispatches `Hostile → Recovered` notification. |

## 5. Phased Implementation Roadmap for Antigravity (v2.7.2)

### Phase 1: `HtaccessVaultManager.php` & `HtaccessShield.php` (Core Armor & Vault)
1. Create `includes/Firewall/HtaccessVaultManager.php`:
   * Implement 5-version rolling vault stored in `wp-content/uploads/wcp-security-scanner/.vault/` (`0600` perms, `<?php exit; __halt_compiler(); ?>` header + `SecretVault::encrypt()`) **plus** encrypted database fallback in `wp_options` (`wcpscan_htaccess_vault_snapshots`, `autoload = false`).
   * Implement `snapshot_current_if_clean()`, `restore_snapshot($version = 1)`, `purge_all_site_caches()`, and WP-CLI command registration (`wp wcp htaccess status|vault|restore`).
2. Create `includes/Firewall/HtaccessShield.php`:
   * Implement directive-grouping semantic parser `analyze_htaccess_content($raw_htaccess)` that pairs `RewriteCond` + `RewriteRule`, inspects inside `# BEGIN WordPress`, and scores hostile external redirects, referrer/UA cloaks, and rogue `AddHandler`/`SetHandler`/`auto_prepend_file` directives.
   * Implement runtime `wp_redirect` filter (`inspect_runtime_redirect($location, $status)`) with `debug_backtrace()` attribution and commerce/OAuth allowlist.
3. Add Preload `.htaccess` Mtime/Hash Watchdog in `includes/Firewall/MicroWafCompiler.php` so global `.htaccess` redirects are detected even if `wp-cron.php` is blocked.

### Phase 2: `RedirectCanaryEngine.php` & Out-of-Band Alerts
1. Create `includes/Firewall/RedirectCanaryEngine.php`:
   * Implement Probes A (Desktop Direct), B (Googlebot/Google Referer), C (Mobile iPhone/Android + Google Referer), D (Admin/Login Gatekeeper), and E (AI Search `chatgpt.com` / `perplexity.ai` Referer).
   * Implement both `3xx` `Location` header validation AND `200 OK` Differential DOM Comparison (comparing `<script src>`, `<meta http-equiv="refresh">`, and `<base href>` between Probe A and Probes B/C/E).
   * Implement Database `siteurl` / `home` baseline comparison and 1-click recovery.
   * Implement the **Strict 3-Condition Auto-Heal Formula** (Canary hostile + `.htaccess` semantic match + outside 5-minute flush grace window → auto-restore from `HtaccessVaultManager` + `purge_all_site_caches()`).
2. Wire state-transition notifications (`redirect_hack_detected` and `redirect_hack_auto_healed`) into `NotificationDispatcher.php` (Discord, Slack, Email) and schedule on `wcp_15min` in `Scheduler.php`.

### Phase 3: 2026 Full-Stack JS, Web3, ClickFix & Drop-In Signatures
1. Upgrade `includes/Malware/JavaScriptSecurityScanner.php`:
   * Add signatures for Web3 blockchain RPC resolvers (`eth_call`, `bsc-dataseed`, `polygon-rpc`), ClickFix clipboard hijacking (`navigator.clipboard.writeText` + PowerShell/mshta/curl), rogue Service Workers (`navigator.serviceWorker.register`), and referrer-cloaked DOM redirects.
2. Upgrade `includes/WordPress/PersistenceScanner.php` & `includes/Content/ContentScanner.php`:
   * Add checks for early `header('Location: ...')` and `ob_start()` redirectors in `db.php`, `object-cache.php`, `advanced-cache.php`, and `mu-plugins/`, plus `<base href>` and `<meta http-equiv="refresh">` in database content.

### Phase 4: REST API Endpoints & React Cockpit UI
1. Register REST endpoints in `includes/Api/ScannerRoutes.php`:
   * `GET /wcp-scanner/v1/firewall/redirect-shield/status` (live canary status, `.htaccess` semantic score, `siteurl`/`home` baseline status, and vault snapshot list).
   * `POST /wcp-scanner/v1/firewall/redirect-shield/probe` (run on-demand 5-vector canary probe).
   * `POST /wcp-scanner/v1/firewall/redirect-shield/restore` (restore `.htaccess` from selected vault snapshot #1–#5 and purge caches).
   * `POST /wcp-scanner/v1/firewall/redirect-shield/lock` (toggle `.htaccess` read-only `0444` lock and auto-heal mode).
2. Build the React UI panel in the Firewall / Server Armor tab with visual `.htaccess` diff viewer, 5-probe canary simulator, and 1-click Vault Restore.

### Phase 5: Manifest Sync & Packaging (v2.7.2)
1. Bump version to `2.7.2` across `wcp-wp-scanner.php`, `readme.txt`, `package.json`, `README.md`, `version.json`, and `changelog.txt`.
2. Run `npm run build` and `npm run package` to regenerate `includes/System/plugin-manifest.json` with updated SHA-256 hashes and byte sizes.

## 6. Grok Implementation Guardrails & Method-Level Interface Stubs

To ensure zero regressions during implementation, Antigravity must adhere to these 5 operational guardrails noted in the final peer review:

1. **Preload Mtime Caching (Zero Per-Request Parse Overhead):**
   * In `micro-waf-compiled.php`, **never** read or regex-parse `.htaccess` on every HTTP request.
   * Compare `filemtime(ABSPATH . '.htaccess')` against the integer `$expected_htaccess_mtime` compiled into `caf-data.php` (or cached in APCu `wcp_htaccess_mtime`). Only read and evaluate `.htaccess` when `filemtime()` differs from the compiled baseline!
2. **Settings-Driven `wp_redirect` Allowlist (Commerce, OAuth & SSO Safe):**
   * `HtaccessShield::inspect_runtime_redirect()` must merge a default trusted domain list (`checkout.stripe.com`, `hooks.stripe.com`, `paypal.com`, `sandbox.paypal.com`, `accounts.google.com`, `login.microsoftonline.com`, `appleid.apple.com`, `auth0.com`, `okta.com`, `squareup.com`, `mollie.com`, `surecart.com`, `paddle.com`, `lemonsqueezy.com`) with the user-configurable `SettingsManager::get('waf_redirect_allowlist')` array and any domains registered in active redirection plugins (`wp_redirection_items`, `rank_math_redirections`, `wpseo_redirects`).
3. **`Clear-Site-Data` Scope (`"cache"` Only by Default):**
   * When emitting `Clear-Site-Data` after remediating a redirect incident, emit `Clear-Site-Data: "cache"` (and only include `"storage"` if a rogue Service Worker was explicitly detected and the admin opted in), so logged-in administrators and shoppers do not lose session cookies or local cart state.
4. **Unified Vault Path (`wp-content/uploads/wcp-security-scanner/.vault/`):**
   * Standardize on `wp_upload_dir()['basedir'] . '/wcp-security-scanner/.vault'` across all classes (consistent with `.quarantine`, `.db-backups`, and `.remediation`), hardened with `.htaccess` (`<IfModule !mod_authz_core.c>` + `<IfModule mod_authz_core.c>`), `index.php`, `0600` file permissions, `<?php http_response_code(403); exit; __halt_compiler(); ?>` guard header, and `SecretVault::encrypt()` AEAD payload + `wp_options` encrypted database mirror.
5. **Sub-Phased Delivery Gate (Tests 2, 3, 5, 7, 11, 12):**
   * Implement and verify in three sequential commits:
     * **Step 1A:** `HtaccessVaultManager` (Dual-medium vault + WP-CLI `wp wcp htaccess` + cache purge) + Preload `filemtime()` watchdog.
     * **Step 1B:** `HtaccessShield` (Directive-paired semantic classifier + runtime `wp_redirect` firewall with allowlist & backtrace).
     * **Step 2:** `RedirectCanaryEngine` (5 probes + HTTP `200 OK` DOM diffing + `siteurl`/`home` sentinel + OOB state-transition alerts).

### Reference Class & Method Signatures

```php
namespace WcpScanner\Firewall;

final class HtaccessVaultManager {
    public const OPTION_DB_MIRROR = 'wcpscan_htaccess_vault_snapshots';
    public const MAX_SNAPSHOTS    = 5;

    public static function get_vault_dir(): string;
    public static function snapshot_current_if_clean(string $reason = 'auto'): array;
    public static function list_snapshots(): array;
    public static function restore_snapshot(int $version = 1): array;
    public static function purge_all_site_caches(): void;
    public static function set_readonly_lock(bool $locked): bool;
}

final class HtaccessShield {
    public const FLUSH_GRACE_TRANSIENT = 'wcpscan_htaccess_flush_grace';

    public static function init(): void;
    public static function mark_legitimate_flush_window(int $ttl = 300): void;
    public static function is_within_flush_grace_window(): bool;
    public static function analyze_htaccess_content(string $content): array;
    public static function inspect_runtime_redirect(string $location, int $status): string;
    public static function get_approved_redirect_hosts(): array;
}

final class RedirectCanaryEngine {
    public const STATE_OPTION = 'wcpscan_redirect_canary_state';

    public static function run_scheduled_canary(): array;
    public static function execute_probes(): array;
    public static function inspect_canary_html_body(string $html, array $baseline_scripts): array;
    public static function verify_database_core_urls(): array;
    public static function evaluate_and_auto_heal(array $canary_report): array;
}
```
