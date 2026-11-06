# WCP Security Scanner — Master Remediation Plan

This document details the comprehensive, multi-phase technical remediation plan for WCP Security Scanner (v2.6.0+), addressing all 16 critical security vulnerabilities, 22 fatal PHP 8.3 / White Screen of Death (WSOD) runtime bugs, WAF payload inspection sanitization flaws, and severe per-request database performance bottlenecks identified in the system audit (`bug-fix.md`).

---

## Executive Summary of Remediation Phases

| Phase | Core Objective | Primary Files / Components | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Fatal PHP 8.3 / Crash Fixes & WSOD Remediation** | `FirewallEngine.php`, `uninstall.php`, `wcp-wp-scanner.php`, `CloudflareIpListSynchronizer.php`, `VirtualPatchManager.php`, `QRCodeGenerator.php`, `IncidentReportEngine.php`, `CAF/*.php`, `RemediationManager.php`, `AttackChainEngine.php`, `PersistenceScanner.php`, `SystemReadinessChecker.php` | **Completed** |
| **Phase 2** | **Core WAF Integrity & Bypass Remediation** | `FirewallEngine.php`, `HoneyTokenEngine.php`, `MicroWafCompiler.php`, `VirtualPatchManager.php`, `AttackSimulationEngine.php`, `WafFileLogger.php`, `AdaptiveRateLimiter.php`, `BotReconDefense.php` | **Completed** |
| **Phase 3** | **Identity, Auth, Storage & Secrets Hardening** | `WebAuthnManager.php`, `TwoFactorAuth.php`, `MCPAgentService.php`, `WcpJitMuGuardian.php`, `TransactionalRemediation.php`, `DatabaseBackup.php`, `DatabaseRemediationManager.php`, `OutboundEgressFirewall.php`, `LocalSnapshotManager.php` | **Completed** |
| **Phase 4** | **Scanner Accuracy & Per-Request Performance** | `Plugin.php`, `AdaptiveRateLimiter.php`, `LearningModeEngine.php`, `WcpJitMuGuardian.php`, `DirectoryWalker.php`, `KnownMalwareManifest.php`, `KnownHashDetector.php`, `Malware/*` | **Completed** |
| **Phase 5** | **Comprehensive Build, Docker QA, Packaging & Sync** | `npm run build`, `npm run package`, version sync (`2.6.0`), Docker deployment (`test1`), git push | **Completed** |

---

## Phase 1: Fatal PHP 8.3 Runtime & Crash Fixes

### 1.1 Unconditional `exit;` in `FirewallEngine.php`
- **Root Cause**: `FirewallEngine.php` contains ~24 unconditional `exit;` statements immediately following `self::handle_rule_violation(...)` (e.g. lines 856, 893, 907, 931, 960, 978, 1020, 1034, 1048, 1068, etc.).
- **Impact**: When the WAF is in Learning Mode, Monitor Mode, or when an IP is whitelisted, `handle_rule_violation()` records telemetry and intentionally returns without issuing a 403 block. The trailing `exit;` halts execution immediately with an empty HTTP 200 White Screen of Death (WSOD).
- **Remediation**: Remove every trailing unconditional `exit;` following `self::handle_rule_violation()`. `handle_rule_violation()` itself handles terminating execution with a 403 / 423 status and block template when blocking is actually warranted.

### 1.2 Plugin Deactivation & `uninstall.php` Cleanliness
- **Root Cause**: If the Micro-WAF was compiled and prepended via `.user.ini` or `php.ini`, deactivating or deleting the plugin leaves `auto_prepend_file` pointing to non-existent plugin paths, crashing the entire WordPress site. Furthermore, `uninstall.php` ran `DELETE FROM wp_options WHERE option_name LIKE 'wcp_%'`, which deletes unrelated third-party plugins with the `wcp_` prefix.
- **Remediation**:
  1. In `uninstall.php`: Always call `MicroWafCompiler::uninstall_preload()` and `ServerSecurityEngine::remove_rules()`.
  2. Narrow database option cleanup strictly to `option_name LIKE 'wcpscan_%'`.
  3. In `wcp-wp-scanner.php`: Register a deactivation hook (`register_deactivation_hook`) that executes `MicroWafCompiler::uninstall_preload()` and cleans active rules.

### 1.3 PHP 8.3 Fatal Call Sites, Visibility & Namespace Incompatibilities
- **`CloudflareIpListSynchronizer::queue_ip_ban()`**:
  - File: `includes/Firewall/CAF/CloudflareIpListSynchronizer.php:88`
  - Issue: Declared as an instance method (`public function queue_ip_ban`) but invoked statically in `ThreatScoreTracker.php:127`.
  - Fix: Change method signature to `public static function queue_ip_ban(string $ip, string $reason = 'WCP WAF Threat', int $ttl = 86400): void`.
- **`VirtualPatchManager::deploy_to_cloudflare_edge()` & `remove_from_cloudflare_edge()`**:
  - File: `includes/Firewall/VirtualPatchManager.php`
  - Issue: Declared as `private static`, but called externally by `VirtualPatchSynthesizer.php`.
  - Fix: Change visibility to `public static`.
- **`QRCodeGenerator.php`**:
  - File: `includes/Auth/QRCodeGenerator.php`
  - Issue: Helper methods called statically on PHP 8.3 while defined non-statically.
  - Fix: Add `static` modifier to all static helper methods.
- **`GhostRouteTrap::check_lostpassword_submission()`**:
  - File: `includes/Firewall/GhostRouteTrap.php`
  - Issue: Undefined variable `$client_ip` causes PHP 8.2+ deprecation / notice and blocks legitimate password reset workflows.
  - Fix: Define `$client_ip = FirewallEngine::get_client_ip();` prior to evaluation.
- **`HoneyTokenEngine::add_blocked_ip()` Argument Reversal**:
  - File: `includes/Firewall/HoneyTokenEngine.php`
  - Issue: Arguments passed to `add_blocked_ip($ip, $reason, $duration)` are inverted, passing reason where IP is expected, triggering `TypeError`.
  - Fix: Correct argument order to match method definition.
- **`GhostRouteTrap` Missing Cloudflare Method**:
  - File: `includes/Firewall/GhostRouteTrap.php`
  - Issue: Calls non-existent `CloudflareService::add_to_ip_list()`.
  - Fix: Replace call with `CloudflareService::block_ip($ip, $reason, 86400)`.
- **`CloudflareService::disconnect()` & `PolicyRegistry` Missing Settings Methods**:
  - File: `includes/Services/CloudflareService.php` & `includes/Policy/PolicyRegistry.php`
  - Issue: Calls `SettingsManager::update_settings()` (actual: `save_settings()`) and `SettingsManager::get_default_settings()` (actual: `get_defaults()`).
  - Fix: Update call sites to valid existing methods.
- **`NotificationDispatcher::is_event_enabled()`**:
  - File: `includes/Notifications/NotificationDispatcher.php` & `includes/System/Scheduler.php`
  - Issue: `Scheduler.php` calls `NotificationDispatcher::is_event_enabled()`, which does not exist.
  - Fix: Add `public static function is_event_enabled(string $event): bool` to `NotificationDispatcher`.
- **Namespace Corrections**:
  - In `includes/Remediation/TransactionalRemediation.php`: Change `use WcpScanner\Security\PathValidator;` to `use WcpScanner\Filesystem\PathValidator;`.
  - In `includes/Firewall/FormSpamProtectionEngine.php`: Change `use WcpScanner\Security\AuditLogger;` to `use WcpScanner\System\AuditLogger;`.
- **`RemediationManager::create_file_backup()` Visibility**:
  - File: `includes/Remediation/RemediationManager.php:927`
  - Issue: Declared `private`, causing fatal errors when called from `AttackChainEngine.php` and `PersistenceScanner.php`.
  - Fix: Change visibility to `public`.
- **`AttackChainEngine::assign_role()`**:
  - File: `includes/Forensics/AttackChainEngine.php:764`
  - Issue: Calls non-existent `$user_mgr->assign_role()`.
  - Fix: Change to `$user_mgr->assign_default_role()`.
- **`PersistenceScanner::analyze_php_tokens()` Signature**:
  - File: `includes/Scanner/PersistenceScanner.php`
  - Issue: Uses undefined `$file_path` inside `analyze_php_tokens(string $content)`.
  - Fix: Add optional `$file_path = ''` parameter: `analyze_php_tokens(string $content, string $file_path = '')`.
- **`SystemReadinessChecker` Non-Existent WordPress Version**:
  - File: `includes/System/SystemReadinessChecker.php`
  - Issue: Sets `MIN_WP_VERSION` and `RECOMMENDED_WP` to `7.0.0` and `7.2.0`, causing environmental failures on current WordPress 6.x.
  - Fix: Set `MIN_WP_VERSION` to `'6.2'` and `RECOMMENDED_WP` to `'6.7'`.
- **`MCPAgentService.php` Missing Method Routing**:
  - File: `includes/AI/MCPAgentService.php`
  - Issue: Calls undefined stub methods (`get_site_health`, `detect_drift`, `apply_virtual_patch`, `remove_virtual_patch`).
  - Fix: Map these calls to live services (`SystemReadinessChecker`, `FimDriftDetector`, `VirtualPatchManager`).

### 1.4 IncidentReportEngine Method Name Mismatches
- **File**: `includes/Reports/IncidentReportEngine.php` (lines 85, 94, 103)
- **Fixes**:
  - `AttackChainEngine::correlate_chains()` $\rightarrow$ `(new AttackChainEngine())->audit_attack_chains()`
  - `PersistenceScanner::audit()` $\rightarrow$ `(new PersistenceScanner())->audit_full()`
  - `VirtualPatchManager::get_catalog()` $\rightarrow$ `VirtualPatchManager::get_patch_catalog()`

### 1.5 Broken CAF Array Keys
- **`LearningModeEngine.php:214`**: Reads `$logs['items']` instead of `$logs['logs']` from `WafFileLogger::query_logs()`. Fix array index to `$logs['logs'] ?? []`.
- **`OriginLoadCircuitBreaker.php:56`**: Reads `$stats['actions']['blocked']` instead of `$stats['blocked_24h']`. Fix array index to `$stats['blocked_24h'] ?? 0`.
- **`AdaptiveFirewallAdvisor.php:255–265`**: Expects `$patch['target']` and `$patch['fixed_in']`. Align keys with `VirtualPatchManager::get_patch_catalog()` schema (`vulnerability`, `component`, etc.).

### 1.6 Dead Cloudflare Auto-Sync in `FirewallEngine::log_incident()`
- **File**: `includes/Firewall/FirewallEngine.php` (lines 3015–3020)
- **Issue**: Compares `$ip !== $current_client_ip` where both are initialized via `self::get_client_ip()`. The condition is always false, completely disabling Cloudflare edge blocking.
- **Fix**: Replace condition with `if (!self::is_current_request_admin_authenticated())` so malicious IPs are pushed to Cloudflare while protecting active administrators.

---

## Phase 2: Core WAF Integrity & Bypass Remediation

### Current Progress Matrix:
| Fix / Item | Status | Details |
| :--- | :--- | :--- |
| **HoneyTokenEngine IP Spoofing** | **Completed** | Now delegates to `FirewallEngine::get_client_ip()` exclusively. |
| **MicroWafCompiler Cloudflare Spoofing** | **Completed** | Generated code strictly verifies `REMOTE_ADDR` matches Cloudflare CIDRs before trusting `HTTP_CF_CONNECTING_IP`. |
| **MicroWaf `.htaccess` Protection** | **Completed** | Replaced `Allow from all` with `Require all denied` / `Deny from all`. |
| **fail2ban Log CRLF Injection** | **Completed** | Strips `\r` and `\n` from URI and method prior to appending to `fail2ban.log`. |
| **`is_trusted_proxy()` Verification** | **Completed** | Local / private IP addresses only trusted if `WCP_TRUST_LOCAL_PROXY` is explicitly defined. |
| **Central Management WAF Bypass** | **Completed** | Removed early return bypass; requests now undergo full inspection rules. |
| **Drill Token Log Blackout** | **Completed** | Both `FirewallEngine::log_incident()` and `WafFileLogger::log_incident()` enforce `AttackSimulationEngine::verify_drill_token()`. |
| **Virtual Patch E-Commerce Skip** | **Completed** | Blanket early-return on cart/checkout removed, allowing CVE virtual patches to protect WooCommerce & donation endpoints. |
| **`evaluate_rules()` Payload Stripping** | **Completed** | Removed `sanitize_text_field()`; added multi-pass `rawurldecode()` on raw URI/query string. |
| **BotRecon `Sec-CH-UA` Hard-Block** | **Completed** | Missing Client-Hints no longer blocks privacy browsers (Brave, Tor, Firefox). |
| **AdaptiveRateLimiter Admin Throttling** | **Completed** | Accurately identifies authenticated administrators at `plugins_loaded: 0`. |
| **Stop Unsetting Commerce POST Fields** | **Completed** | Full POST payloads are inspected for SQLi/XSS/RCE regardless of cart or form state. |
| **Inspect Cookies / User-Agent / Referer** | **Completed** | `$_COOKIE`, `$_SERVER['HTTP_USER_AGENT']`, and `$_SERVER['HTTP_REFERER']` are actively inspected in `evaluate_rules()`. |
| **Harden SQLi/XSS/PHP/Traversal Regexes** | **Completed** | Patched evasions (`UNION/**/SELECT`, `UNION(SELECT)`, `onpointerenter`, SVG vectors, `<?=`, `assert()`, double URL encoding `%252e%252e%252f`). |
| **Sensitive-File Probe Iterative Decode** | **Completed** | Multi-pass URL decoding in `FirewallEngine` reliably catches `/%2eenv` and `/%252eenv`. |

### 2.1 Client IP Resolution & Proxy Spoofing Hardening
- **`HoneyTokenEngine.php`**: Remove raw inspection of `HTTP_CF_CONNECTING_IP` / `X-Forwarded-For`. Delegate exclusively to `FirewallEngine::get_client_ip()`.
- **`MicroWafCompiler.php`**:
  - Before trusting `HTTP_CF_CONNECTING_IP`, verify that `REMOTE_ADDR` belongs to official Cloudflare CIDR blocks (both IPv4 and IPv6).
  - Sanitize carriage returns (`\r`) and line feeds (`\n`) in `fail2ban.log` to prevent CRLF log injection.
  - In compiled directory `.htaccess`: Replace `Allow from all` with `Require all denied` / `Deny from all`.
- **`FirewallEngine::is_trusted_proxy()`**: Disallow arbitrary local loopback spoofing unless the server is explicitly configured behind a validated upstream reverse proxy.

### 2.2 Elimination of Central Management & Drill Token Bypasses
- **Central Management Bypass**: Remove the blanket unauthenticated bypass in `FirewallEngine::is_verified_central_management_request()`. Require HMAC-SHA256 signature verification over timestamp and request body using the stored API secret.
- **Drill Token Log Suppression**:
  - Stop allowing arbitrary unauthenticated GET parameters (`?wcp_drill_token=1`) to suppress incident logging.
  - Require token validation through `AttackSimulationEngine::verify_drill_token($token)`.

### 2.3 E-Commerce Cart & Stripe Bypass Removal
- **Files**: `includes/Firewall/FirewallEngine.php` & `includes/Firewall/VirtualPatchManager.php`
- **Issue**: Attackers injecting `Cookie: woocommerce_items_in_cart=1` or `Stripe-Signature` headers triggered a "Safe Mode" bypass that unset POST fields prior to inspection and skipped virtual patches.
- **Remediation**:
  1. Remove blanket exclusion of requests containing cart cookies or webhook headers.
  2. Inspect all requests across all endpoints regardless of cart status.
  3. For genuine webhooks, verify cryptographic webhook signatures prior to exempting from specific generic rules, while never unsetting raw POST payload buffers.

### 2.4 WAF Payload Normalization (Elimination of Destructive Sanitization)
- **Files**: `FirewallEngine::evaluate_rules()`, `check_sensitive_file_probes()`, and `VirtualPatchManager::extract_request_context()`
- **Issue**: The firewall invoked `sanitize_text_field()` on incoming request parameters prior to regex evaluation. `sanitize_text_field()` strips `<tag>` constructs and decodes/normalizes forward slashes (`%2f`), allowing path traversal (`..%2f..%2f`) and cross-site scripting attacks to bypass inspection undetected.
- **Remediation**:
  1. Inspect raw, unstripped input payloads.
  2. Apply recursive multi-pass `rawurldecode()` and Unicode normalization so obfuscated payloads (`%252e%252e%252f`, `UNION/**/SELECT`, `<?=`, `assert()`) are fully detected.
  3. Ensure `$user_agent`, `Referer`, and `$_COOKIE` are evaluated in `evaluate_rules()`.
  4. Expand inspectable payload buffer size beyond 128 KB for critical inspection points.
- **Rate Limiting & Bot Heuristics**:
  - In `AdaptiveRateLimiter.php`: Correctly detect logged-in administrators at `plugins_loaded: 0` using auth cookies so scan batches and REST API tasks are not throttled.
  - In `BotReconDefense.php`: Remove the mandatory requirement for `Sec-CH-UA` headers that falsely flagged Brave browser, privacy-focused clients, and search engine crawlers.

---

## Phase 3: Identity, Auth, Storage & Secrets Hardening

### Current Progress Matrix:
| Fix / Item | Status | Details |
| :--- | :--- | :--- |
| **Passkey RP ID & Origin Validation** | **Completed** | Registration and assertion enforce `origin` against `home_url()` and `rpIdHash` against `sha256(rpId)`. |
| **Passkey Open Redirect / DOM XSS** | **Completed** | `redirect_to` is strictly validated using `wp_validate_redirect()` server-side; client script uses sanitized target. |
| **Passkey User Enumeration Removal** | **Completed** | `/auth/webauthn/login-options` maintains empty `allowCredentials`, supporting resident keys without leaking user existence. |
| **2FA Verification Rate-Limiting** | **Completed** | Enforces max 5 attempts per `pending_key` session transient before immediate session termination with HTTP 429. |
| **TOTP Replay Cache** | **Completed** | Verified TOTP timeslot is cached for 90s to prevent token replay attacks during drift window. |
| **2FA Recovery Code Length** | **Completed** | Changed input `maxlength="6"` to `maxlength="12"` with `inputmode="text"` to allow 8- and 9-char backup codes. |
| **2FA Dashboard Guard & Redirection** | **Completed** | Fixed redirect target to `wcp-scanner-auth` avoiding redirect loops; gates authenticated dashboard access. |
| **MCP AI Copilot Token Separation** | **Completed** | `confirmation_token` stripped from client-visible responses and staged action listings; approvals require admin session. |
| **JIT Privilege Escalation Defense** | **Completed** | In `WcpJitMuGuardian.php`, checked `$is_jit` in all REST, AJAX, settings, and user tampering interceptors. |
| **MU Guardian Runtime Gating** | **Completed** | `ensure_installed()` optimized to run only during admin sessions or when active JIT/support users exist. |
| **Transactional File Snapshots** | **Completed** | Relocated storage to dot-prefixed `.remediation/transactions`, sanitized `$tx_id` against traversal. |
| **WAF Logs & Database Backup Storage** | **Completed** | Relocated to `.waf-logs` and `.db-backups`, added `http_response_code(403); exit;` guards. |
| **Outbound Egress SSRF Hardening** | **Completed** | Patched expanded IPv6 loopback (`0:0:0:0:0:0:0:1`, `::1`, `::ffff:x.x.x.x`, `fe80::/10`). |
| **Local Snapshot Manager CLI/Cron** | **Completed** | Relocated storage to `.snapshots`, allowed restoration from WP-CLI / background auto-cure crons. |
| **Database Backup Placeholder Fix** | **Completed** | Added `$wpdb->remove_placeholder_escape()` to prevent serialized PHP data corruption in SQL exports. |

### 3.1 WebAuthn Security (`WebAuthnManager.php`)
- **Origin & RP ID Hash Verification**: Verify that the client data JSON `origin` strictly matches the site's origin (`home_url()`) and that `rpIdHash` matches `hash('sha256', parse_url(home_url(), PHP_URL_HOST), true)`.
- **Redirect Validation**: Use `wp_validate_redirect()` on `redirect_to` parameters to prevent open redirects and DOM-based XSS.
- **User Enumeration**: Restrict the `login-options` REST endpoint from disclosing registered authenticators and user existence to unauthenticated callers.

### 3.2 Two-Factor Authentication (`TwoFactorAuth.php`)
- **Rate-Limiting & Replay Cache**: Enforce per-IP and per-user rate limiting on 2FA code verification, and record recently consumed TOTP timestamps in a transient replay cache to prevent code replay.
- **Input Length**: Change the input element's `maxlength="6"` to `maxlength="12"` to accommodate standard 8- and 9-character alphanumeric backup codes.
- **Dashboard Guard**: Ensure users with pending 2FA sessions cannot bypass authentication by accessing admin AJAX or REST endpoints directly.

### 3.3 AI Copilot Token Separation (`MCPAgentService.php`)
- **Token Leakage**: Stop returning the destructive action `confirmation_token` directly in the LLM response payload.
- **Remediation**: Store pending confirmation tokens strictly in server-side session state and require explicit authorization by an authenticated administrator session.

### 3.4 JIT Privilege Escalation Defense (`WcpJitMuGuardian.php`)
- Update the 4 MU-guardian enforcement methods to check `$is_jit` alongside `$is_support` so ephemeral Just-In-Time administrator roles cannot bypass security restrictions or linger past expiration.

### 3.5 Storage, Backups & Directory Protection
- **`TransactionalRemediation.php`**: Eliminate storage of raw `.php` files in `/uploads/`. Store file snapshots inside a dot-prefixed directory (`.remediation/`), append direct `<?php exit; ?>` headers, and encrypt snapshot contents with `SecretVault`. Enforce strict path traversal validation on `$tx_id`.
- **`WafFileLogger.php`, `DatabaseBackup.php`, `DatabaseRemediationManager.php`**:
  - Migrate all log and backup directories to dot-prefixed paths (`.logs/`, `.backups/`).
  - Add `index.php` and `.htaccess` deny rules.
  - Wrap database export files (`.sql.gz`) with encryption and prevent directory indexing on Nginx.
- **`OutboundEgressFirewall.php`**: Block SSRF bypasses targeting expanded IPv6 loopback addresses (`0:0:0:0:0:0:0:1`, `::1`, `::ffff:127.0.0.1`) and internal cloud metadata service endpoints.
- **`LocalSnapshotManager.php`**: Ensure `restore_file_from_snapshot()` operates smoothly when triggered by background auto-cure crons or WP-CLI by checking `defined('WP_CLI')` or system context when `current_user_can('manage_options')` is not available.

---

## Phase 4: Scanner Accuracy & Per-Request Performance Optimization

### 4.1 Scanner Accuracy & Scope Corrections
- **Global Test & Doc Exclusions**:
  - Remove blanket `/tests/` and `/docs/` path exclusions from `FileScanner.php`, `Scanner/Engine.php`, and `Malware/*`.
  - Restrict exclusions strictly to the plugin's own vendor directory (`/wp-content/plugins/wcp-security-scanner/vendor/`).
- **`DirectoryWalker.php` Batch Traversal**: Fix directory cursor tracking so batch scans do not terminate prematurely after completing the first subdirectory.
- **Known Hash Manifests**: Replace placeholder sequential hashes in `KnownMalwareManifest.php` and remove false-positive benign hashes (such as `md5("123456")`) from `KnownHashDetector.php`.
- **Database Backup Placeholder Fix**:
  - File: `includes/Backup/DatabaseBackup.php:275`
  - In WordPress 6.2+, `esc_sql()` replaces `%` characters with placeholder strings. Wrap SQL exports with `$wpdb->remove_placeholder_escape(esc_sql((string) $val))` to prevent permanent corruption of serialized PHP options and URLs.

### 4.2 Per-Request Database & CPU Performance Optimization
- **Eliminate `SHOW TABLES` on Every Request (`includes/Plugin.php:28–30`)**:
  - Check `get_option('wcpscan_db_version') === WCPSCAN_DB_VERSION` first (cached in-memory via `alloptions`).
  - Only execute `SHOW TABLES LIKE ...` queries when the version option is missing or outdated.
- **Eliminate Per-Request `wp_options` Transient Writes**:
  - In `FirewallEngine.php:690`: Only write `wcpscan_active_visitor_traffic_15s` if `!get_transient('wcpscan_active_visitor_traffic_15s')`.
  - In `AdaptiveRateLimiter.php:188`: Avoid per-request transient database writes for rate-limit counters when external object caching is not available.
- **Throttle Learning Mode Option Updates (`LearningModeEngine.php:224`)**:
  - Gate `LearningModeEngine::observe_request()` so it executes strictly when `$settings['waf_mode'] === 'learning'`.
  - Do not call `update_option(self::PROFILES_OPTION, $profiles)` on every request for graduated routes when no new parameters are discovered.
- **MU-Guardian File Read & Hashing Optimization (`WcpJitMuGuardian.php:48–65`)**:
  - Restrict `WcpJitMuGuardian::ensure_installed()` so it only runs during administrative requests or when active ephemeral/support users exist, eliminating double disk reads and SHA-256 file hashing on every visitor hit.

---

## Phase 5: Verification, Packaging & Deployment

1. **Linting & Code Quality**:
   - Run `php -l` across all modified PHP files to guarantee zero syntax or compilation errors.
2. **Frontend & Asset Build**:
   - Run `npm run build` to compile production assets.
3. **Local Docker Deployment**:
   - Deploy compiled assets and modified PHP files to the local Docker WordPress environment (`test1` at `/var/www/html/wp-content/plugins/wcp-security-scanner/`).
   - Reset permissions: `docker exec test1 chown -R www-data:www-data /var/www/html`.
4. **Distribution Packaging & Version Sync**:
   - Sync version number across `wcp-wp-scanner.php`, `readme.txt`, `package.json`, `README.md`, `version.json`, and `changelog.txt`.
   - Run `npm run package` to compile `wcp-security-scanner.zip` and generate the cryptographic manifest.
5. **Git Push**:
   - Verify with `git status` that no test or temporary files are tracked.
   - Commit and push to GitHub repository (`git push origin main`).
