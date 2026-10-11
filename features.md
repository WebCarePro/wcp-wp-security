# WCP Security Scanner — Extended Features & Architecture Catalog

**WCP Security Scanner** is an enterprise-grade, memory-efficient WordPress security, malware detection, forensic auditing, and edge defense plugin engineered by **[Mir Alamin](https://www.upwork.com/freelancers/~0162afa9a578170c67)** ([WebCare Pro](https://webcarespro.com)).

Built with a modern **React 18 + TypeScript** administrative single-page dashboard and memory-safe **PHP 8.3+ streaming engines**, the plugin provides comprehensive threat prevention, runtime defense, and forensic remediation without degrading server performance.

---

## Table of Contents

1. [Next-Gen Cyber Command Center & Threat Dashboard](#1-next-gen-cyber-command-center--threat-dashboard)
2. [Multi-Vector Security & Deep Malware Detection Engine](#2-multi-vector-security--deep-malware-detection-engine)
3. [Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer](#3-real-time-file-integrity-monitoring-fim--visual-code-diff-viewer)
4. [1-Click Auto-Cure & Surgical Remediation Engine](#4-1-click-auto-cure--surgical-remediation-engine)
5. [Secure Quarantine Vault & Isolation Architecture](#5-secure-quarantine-vault--isolation-architecture)
6. [Software Intelligence & Curated CVE Advisory Database](#6-software-intelligence--curated-cve-advisory-database)
7. [Living-off-the-Land (LotL) Runtime Hook Infiltration Sentinel](#7-living-off-the-land-lotl-runtime-hook-infiltration-sentinel)
8. [Database Micro-Anomaly & Rogue Administrator Trap](#8-database-micro-anomaly--rogue-administrator-trap)
9. [Web Application Firewall (WAF Lite) & Virtual Patching](#9-web-application-firewall-waf-lite--virtual-patching)
10. [Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)](#10-cloudflare-edge-defense--zero-resource-waf-100-free-plan)
11. [Community Threat Intelligence & Botnet IP Blacklists](#11-community-threat-intelligence--botnet-ip-blacklists)
12. [Active Session Sentinel & Anti-Hijack Defense](#12-active-session-sentinel--anti-hijack-defense)
13. [Multi-Factor Authentication (2FA) & Login Hardening](#13-multi-factor-authentication-2fa--login-hardening)
14. [Enterprise HTTP Security Headers & 1-Click Site Hardening](#14-enterprise-http-security-headers--1-click-site-hardening)
15. [Bot Recon Defense & AI Scraper Shield](#15-bot-recon-defense--ai-scraper-shield)
16. [Multi-Provider AI Code Forensics](#16-multi-provider-ai-code-forensics)
17. [DevSecOps Chat & Enterprise Automation Webhooks](#17-devsecops-chat--enterprise-automation-webhooks)
18. [Cryptographic Secret Vault (AES-256-CBC at Rest)](#18-cryptographic-secret-vault-aes-256-cbc-at-rest)
19. [On-Demand Database Backup Vault (`.sql.gz`)](#19-on-demand-database-backup-vault-sqlgz)
20. [High-Precision Microsecond Telemetry & Diagnostics](#20-high-precision-microsecond-telemetry--diagnostics)
21. [Data Privacy, Safety Policies & Clean Uninstall Lifecycle](#21-data-privacy-safety-policies--clean-uninstall-lifecycle)

---

## 1. Next-Gen Cyber Command Center & Threat Dashboard

- **High-Precision SVG Security Health Meter:** Circular dynamic vector meter displaying site security score (0–100%) with reactive color accents (emerald `#10b981`, blue `#38bdf8`, amber `#f59e0b`, rose `#ef4444`) and letter grades (`A+`, `A`, `B`, `C`, `D`, `F`).
- **Interactive Threat Metric Cubes:** High-contrast summary widgets grouping active threats into 3 primary vectors:
  - *Critical Exploits & Backdoors:* High-severity webshells, injection droppers, and active Trojans.
  - *File Integrity & Code Drift:* Modified WordPress core files, altered plugins, tampered themes, and rogue uploads.
  - *Software Vulnerabilities & CVE Advisories:* Outdated components with documented vulnerabilities and available patches.
  - Includes instant 1-click category filtering to immediately isolate specific threat vectors in the findings table.
- **Audit Command Center Console:**
  - Fast single-click execution controls: **Full Deep Audit** (entire tree) vs **Fast Audit** (plugins & themes only).
  - Live engine telemetry indicators displaying the active subsystem currently running (e.g., Core Integrity, Heuristic Scanner, CVE Scanner, LotL Hook Sentinel).
  - Dual-layer animated scan progress bar with percentage tracking, scanned file counter, and instant stop controls.
- **Interactive Findings Hub:**
  - Modern alternating zebra row styling with severity-tinted accent borders (rose for Critical, warm orange for High, amber for Medium, sky blue for Low/Info).
  - Quick filter pills: All Issues, Critical & High, File Integrity (FIM), Software CVEs, Database/Spam, and User Accounts.
  - Monotonic finding index numbers (`#1`, `#2`, ...) and rounded monospace path breadcrumbs with 1-click clipboard copy.
  - Real-time instant text search across file paths, finding descriptions, threat signatures, and CVE titles.
  - Severity selector dropdown and direct sorting controls.

---

## 2. Multi-Vector Security & Deep Malware Detection Engine

- **Deep Heuristic PHP Code Analysis:** Scans files line-by-line for webshells, backdoors, Trojan droppers, and command execution stubs.
  - Detects multi-layer obfuscation patterns: nested `eval()`, `base64_decode()`, `gzinflate()`, `str_rot13()`, `rawurldecode()`, and `chr()` concatenation.
  - Analyzes dynamic variable function calls (e.g., `$$var()`, `$f = 'sys'.'tem'; $f()`).
  - Detects hexadecimal and octal string encodings used to conceal exploit payloads.
  - Detects spoofed image/GIF/PDF file headers containing executable PHP tags (e.g., `GIF89a; <?php`).
  - Runtime signature fragmentation: dynamically constructs signatures in memory to prevent antivirus false-positives on the scanner itself.
- **WordPress Core Cryptographic Integrity Engine:**
  - Directly queries the official WordPress.org Checksum API for the installed WordPress release.
  - Validates MD5 checksums for every file in `wp-admin`, `wp-includes`, and root directories.
  - Pinpoints modified, injected, tampered, or missing official core files.
- **Uploads Executable & Script Shield:**
  - Recursively audits `wp-content/uploads/` for prohibited script extensions: `.php`, `.phtml`, `.phps`, `.php5`, `.php7`, `.sh`, `.py`, `.pl`, `.cgi`, `.exe`.
  - Catches disguised double extensions (e.g., `invoice.jpg.php`, `logo.png.phtml`).
  - Detects rogue `.htaccess` files inside upload folders overriding execution rules.
  - Automatically identifies and allows legitimate directory index protection files (`index.php` with silent return).
- **Database Threat & Content Injection Scanner:**
  - Scans `wp_posts`, `wp_options`, `wp_users`, and `wp_comments` for stored malicious code.
  - Detects Stored Cross-Site Scripting (Stored XSS) in post content and comments.
  - Identifies malicious `<iframe>` tags, external obfuscated `<script>` includes, and pharmaceutical SEO spam doorways.
  - Flags unauthorized hidden admin user records created directly via SQL.
- **Crontab & Scheduled Task Auditing:**
  - Audits Linux server-level crontab files (`/var/spool/cron`, `crontab -l`) for rogue persistence jobs.
  - Audits WordPress virtual `wp-cron` hooks in `wp_options:cron` for suspicious callbacks, piped curl/wget downloads, and orphaned hooks.
- **User Account & Privilege Security:**
  - Detects weak administrator usernames (`admin`, `administrator`).
  - Identifies dormant administrator accounts with months of inactivity.
  - Flags newly spawned administrator accounts created outside standard administrative workflows.
- **Server Configuration Hardening Safeguards:**
  - Verifies file permissions for `wp-config.php` (recommends `0400` or `0440`) and `.htaccess` (`0444` or `0644`).
  - Audits `WP_DEBUG`, `WP_DEBUG_LOG`, and `WP_DEBUG_DISPLAY` settings to prevent sensitive error disclosure.
  - Validates server protection against public HTTP access to `.env`, `.git`, `.user.ini`, `php.ini`, and database dumps.

---

## 3. Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer

- **Filesystem Change Tracker:** Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
- **Custom & Premium Component Recognition:** Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to eliminate false alarms.
- **Git-Style Visual Code Diff Viewer Modal (`VisualDiffModal.tsx`):**
  - Pure PHP Myers/Longest Common Subsequence (LCS) visual diffing algorithm.
  - Compares modified server files against official WordPress.org release mirrors line-by-line.
  - High-visibility color highlighting: green for additions, red for deletions, dark slate for context lines.
  - Displays change statistics: total lines, additions, deletions, and total modifications.
  - Displays direct link to the official WordPress.org source file.
  - Overlay modal rendered with ultra-high z-index (`9999999`) above all WordPress admin bars with 1-click clipboard copy.

---

## 4. 1-Click Auto-Cure & Surgical Remediation Engine

- **1-Click WordPress Core Auto-Cure (`restore_official_core_file`):**
  - Allows repairing tampered core files in `wp-admin`, `wp-includes`, and root directories directly to official WordPress.org release code.
  - Automatically fetches the bit-for-bit clean copy matching the exact site WordPress version (`$wp_version`) from the official WordPress.org Subversion repository or official GitHub mirror.
  - Protected configuration boundary: strictly protects `wp-config.php`, `.htaccess`, and `.user.ini` from template overwrite.
  - Automatically takes a pre-restoration safety snapshot in the local backup vault before writing to disk.
  - Performs atomic disk replacement, clears PHP OPcache (`opcache_invalidate`), and updates the database scan records to `repaired`.
- **1-Click Plugin & Theme Auto-Cure (`restore_official_plugin_file`, `restore_official_theme_file`):**
  - Restores altered or infected plugin and theme files back to clean, official release copies directly from WordPress.org.
  - Automatically creates pre-restoration safety backups in the local vault.
- **1-Click Webshell Stripping (`strip_prepended_malware`):**
  - Surgically removes injected malware wrappers, obfuscated `eval()` blocks, and backdoor headers from legitimate files.
  - Preserves legitimate plugin/theme logic intact.
  - Uses PHP tokenizer (`token_get_all`) to validate PHP syntax integrity before saving.
  - Automatically creates a pre-strip safety backup in the local vault.
- **1-Click Scheduled Cron Hook Remediation (`remediate_delete_cron_hook`):**
  - Safely unschedules and purges orphaned or malicious cron hooks (`orphaned_cron_hook`, `malicious_cron_hook_name`) directly from `wp_options:cron` via `wp_clear_scheduled_hook()`.
  - Enforces safety boundaries to protect critical core cron tasks (`wp_version_check`, `wp_update_plugins`, `wp_scheduled_delete`).
- **Real-Time State Synchronization:**
  - Upon running any Auto-Cure remediation, matching scan issues are instantly marked as `repaired`.
  - The findings table immediately updates to display a green **`Issue Solved & Restored`** badge, and all mitigation buttons (`Diff`, `View`, `Quarantine`, `Ignore`) disappear.

---

## 5. Secure Quarantine Vault & Isolation Architecture

- **Safe Cryptographic Isolation (`quarantine_file`):**
  - Safely isolates malicious or unrecognized files out of web-accessible paths and into a protected vault folder (`wp-content/uploads/wcp-security-scanner/quarantine/`).
  - Guards the vault directory with Apache/LiteSpeed `.htaccess` (`Require all denied`) and silent PHP index files to block web execution.
  - Preserves original file permissions, modification timestamps, original relative path, and SHA-256 cryptographic hashes in `wp_wcp_quarantine`.
- **Intelligent Quarantine Eligibility Safeguards:**
  - Enforces strict boundary checks (`canQuarantineIssue`): prevents quarantining critical configuration files (`wp-config.php`, `.htaccess`, `wp-settings.php`, `wp-load.php`) to eliminate site crashes.
  - Excludes modified official files (`modified_core_file`, `modified_plugin_file`, `injected_wp_config`): official files must be restored/repaired via Auto-Cure rather than removed.
  - Restricts the Quarantine action strictly to verified alien, rogue, and unknown files (`unknown_core_file`, `unknown_plugin_file`, `disguised_php_in_uploads`, standalone webshells).
- **Quarantine Vault Hub (`QuarantineTab`):**
  - Responsive table with horizontal overflow support and alternating zebra row shading.
  - Displays original path, quarantine filename, isolation date, file size, and SHA-256 hash with 1-click clipboard copy.
  - **1-Click Instant Restoration:** Restores the quarantined file back to its exact original path and permissions.
  - **1-Click Permanent Deletion:** Permanently purges the isolated file from disk and deletes the vault record.

---

## 6. Software Intelligence & Curated CVE Advisory Database

- **Curated CVE Advisory Database:** Scans installed WordPress core, active/inactive plugins, and themes against an offline-resilient vulnerability database.
- **Granular Vulnerability Metadata:**
  - Displays official Common Vulnerabilities and Exposures identifiers (e.g., `CVE-2024-XXXX`).
  - Standardized Common Vulnerability Scoring System (CVSS) risk ratings (0.0 to 10.0) with severity badges: Critical, High, Medium, Low.
  - Identifies affected version ranges, patched release versions, and vulnerability types (SQLi, XSS, RCE, CSRF, Auth Bypass).
  - Provides direct clickable links to official NIST National Vulnerability Database (NVD) advisories.
- **Interactive Vulnerabilities Management Hub:**
  - Component filtering by Core, Plugins, and Themes.
  - Status filtering by Vulnerable, Outdated, and Clean.
  - Direct 1-click update action links to native WordPress update screens (`update-core.php`).
  - Detailed CVE forensic breakdown modal.

---

## 7. Living-off-the-Land (LotL) Runtime Hook Infiltration Sentinel

- **Active Runtime Memory Hook Audit:** Uses PHP Reflection to inspect active runtime hook callbacks registered in `$wp_filter` across sensitive WordPress lifecycle actions:
  - `authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`.
- **Anonymous Closure & Credential Sniffer Detection:** Flags anonymous `Closure` functions attached to authentication hooks that may intercept plaintext user credentials during login.
- **External Rootkit & Uploads Hook Traps:**
  - Detects callbacks originating outside the WordPress root (e.g., server-level `auto_prepend_file` rootkits or PHP-FPM pool injections).
  - Detects callbacks originating from `wp-content/uploads/` (webshell runtime hooks).
- **Dangerous Native Function Registration Defense:** Detects dangerous native PHP execution functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`, `exec`, `popen`) attached directly as WordPress filter callbacks.

---

## 8. Database Micro-Anomaly & Rogue Administrator Trap

- **Stealth User Infiltration Detection:** Cross-references `wp_users` with `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL queries that bypass standard `user_register` hooks.
- **Ghost & Orphaned Capability Hunting:** Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap:** Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe:** Recursively audits `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden inside transients or autoloaded options.

---

## 9. Web Application Firewall (WAF Lite) & Virtual Patching

- **Real-Time Request Filtering:** Inspects incoming HTTP payloads at `plugins_loaded` (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
- **Attack Vector Shields:**
  - *SQL Injection (SQLi):* Blocks `UNION SELECT`, `information_schema`, `benchmark()`, `sleep()`, and stacked queries.
  - *Cross-Site Scripting (XSS):* Blocks `<script>`, `javascript:`, and malicious event handlers (`onload`, `onerror`).
  - *Path Traversal & Local File Inclusion (LFI):* Blocks `../`, `/etc/passwd`, `win.ini`, and `php://filter` streams.
  - *PHP Code Injection:* Blocks `<?php`, `eval()`, `base64_decode()`, and `system()` inside query strings and request bodies.
  - *XML-RPC Exploitation:* Blocks unauthenticated pingback and brute-force spray targeting `/xmlrpc.php`.
- **Smart Cloudflare & Coexistence:**
  - Decodes real visitor IPs from `HTTP_CF_CONNECTING_IP` with Cloudflare proxy range validation.
  - Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.
- **Live Incidents Stream & Controls:**
  - Real-time blocked attack table displaying attacking IP, country, blocked vector, requested URI, and incident timestamp.
  - 1-click IP whitelisting to unblock trusted administrators.
  - Learning Mode toggle (audit-only logging without blocking) and individual rule switches.
  - Custom dark-themed 403 Forbidden screen displaying incident reference IDs.

---

## 10. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)

- **Zero-Resource Perimeter Threat Interception:** Blocks malicious bots and automated exploit probes at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
- **1-Click Free Plan Cloudflare Edge Rules Deployment (5 Compound Rules):**
  1. *WordPress Core & Sensitive System Armor:* Combines `/xmlrpc.php`, `wp-config.php`, `.env`, `.git`, `.user.ini`, `debug.log`, and package manifests into a single perimeter rule.
  2. *Webshell & Direct Script Execution Trap:* Blocks direct script execution across both `wp-content/uploads/` and `wp-content/upgrade/`.
  3. *Path Traversal & Code Injection Edge Shield:* Blocks LFI/RFI `../`, `/etc/passwd`, `base64_decode`, `eval`, and null byte injections directly at the edge.
  4. *Recon & Username Harvesting Shield:* Blocks `?author=` query scrapers and REST API user enumeration.
  5. *Login Portal Threat Defense:* Deploys non-intrusive Cloudflare Turnstile / Managed Challenge for automated bots targeting `wp-login.php`.
- **Cloudflare Free Rate Limiter:** Deploys an edge rate limiter on `wp-login.php` (10 requests / 10s per IP) to mitigate brute-force attacks with zero server resource consumption.
- **Bi-Directional WAF Auto-Ban Sync:** Automatically synchronizes locally detected high-threat attack IPs to Cloudflare Edge IP Access Rules.
- **1-Click Global CDN Cache Purge:** Instant edge cache purge directly from the WordPress administration panel.

---

## 11. Community Threat Intelligence & Botnet IP Blacklists

- **Community Botnet IP Blacklists:** Automatically synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL.
- **Sub-Millisecond In-Memory Subnet Matching:** Performs static in-memory $O(1)$ hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
- **Zero-Day CVE Feed & Site Correlation:** Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes, displaying status badges (`Installed — Vulnerable`, `Installed — Patched`, `Global Virtual Shield`).
- **IP Reputation Diagnostic Tool:** Built-in checker to test client or visitor IPs against the active threat database.

---

## 12. Active Session Sentinel & Anti-Hijack Defense

- **Administrative Session Telemetry:** Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Strict IP Lock & Anti-Replay:** Automatically detects and revokes hijacked sessions if client IP shifts during an active login.
- **Single Concurrent Session Policy:** Enforces single-session policies by invalidating older sessions when an administrator logs in from a new machine.
- **Configurable Idle Inactivity Revocation:** Automatically logs out abandoned admin sessions after configurable periods (default: 120m).
- **1-Click Remote Termination:** Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

---

## 13. Multi-Factor Authentication (2FA) & Login Hardening

- **Pure PHP RFC 6238 TOTP Engine:** Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
- **Native `wp-login.php` Interception:** Displays a responsive, branded two-factor verification challenge screen supporting rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
- **AES-256-CBC Encrypted User Secrets:** Encrypts user TOTP secrets (`_wcp_2fa_secret`) at rest in `wp_usermeta` via the Secret Vault.
- **Brute Force Rate-Limiter:** Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.

---

## 14. Enterprise HTTP Security Headers & 1-Click Site Hardening

- **Enterprise Security Headers Dispatcher:** Injects `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock:** Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense:** Blocks author archive scraping (`/?author=1`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`). Strips WordPress version meta tags and asset query strings (`?ver=`).
- **Sensitive System File Probe Shield:** Returns 403 Forbidden on requests attempting to access `.env`, `.git`, `.htaccess`, `.sql`, `composer.json`, and backup archives.
- **1-Click Hardening Presets:** Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (`A+`, `A`, `B`, `C`).

---

## 15. Bot Recon Defense & AI Scraper Shield

- **Fake Search Engine Crawler Defense:** Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
- **AI Content Scraper & Harvester Shield:** Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) at the WAF level.
- **Dynamic Virtual `robots.txt` Injection:** Automatically generates and injects standard AI bot Disallow directives into virtual `robots.txt`.

---

## 16. Multi-Provider AI Code Forensics

- **Supported AI Forensic Providers:**
  - **Google Gemini:** Gemini 3.8 Flash, 2.5 Flash, 1.5 Pro.
  - **OpenAI:** GPT-6.1 Sol, GPT-4o, GPT-4o-mini.
  - **Anthropic Claude:** Claude Sonnet 5.5, Claude 3.7 Sonnet, Claude 3.5 Haiku.
- **WordPress 7.0+ Core AI Client Bridge:** Automatically detects and leverages WordPress 7.0+ native `wp_ai_client()` site-level AI credentials for zero-configuration AI forensics.
- **1-Click AI Code Forensics Modal:**
  - Decodes multi-layer obfuscated scripts in seconds.
  - Assesses threat confidence rating (0–100%) and explains exploit mechanics.
  - Generates surgical clean code patches to eliminate malicious functionality without breaking legitimate logic.

---

## 17. DevSecOps Chat & Enterprise Automation Webhooks

- **Multi-Channel Chat Webhook Notifications:**
  - **Slack:** Rich Block Kit formatting with color-coded threat cards, direct finding links, and severity badges.
  - **Discord:** Structured Embed cards with real-time incident metadata.
- **Automated DevSecOps Ticket Dispatch:**
  - **ClickUp:** Automatically creates tasks in designated ClickUp lists with priority tags and incident forensics.
  - **Asana:** Automatically creates project tasks with forensic notes.
- **Generic Automation Webhook (Zapier, Make.com, n8n):**
  - Dispatches structured REST JSON event payloads to custom SIEM endpoints and automation pipelines.
- **Flood Protection Safeguards:** Built-in 60-second rate-limiting prevents channel notification spamming during brute-force or DDoS storms.
- **Live Webhook Testing API:** 1-click test buttons in Settings to verify webhook URL configuration instantly.

---

## 18. Cryptographic Secret Vault (AES-256-CBC at Rest)

- **Military-Grade AES-256-CBC Encryption:** All sensitive third-party API credentials, webhook endpoints, and infrastructure tokens are encrypted at rest before being saved to `wp_options`:
  - Slack webhooks, Discord webhooks, ClickUp webhooks, Asana webhooks, Generic automation URLs (Zapier, Make, n8n).
  - Cloudflare API Bearer Tokens and Cloudflare Zone IDs.
  - OpenAI API keys, Google Gemini API keys, and Anthropic Claude API keys.
  - Two-Factor Authentication (2FA) TOTP user secrets.
- **Dynamic 256-bit Key Derivation & Random IVs:**
  - Each secret is encrypted with a cryptographically secure, randomized 16-byte initialization vector (`random_bytes(16)`).
  - Keys derived using SHA-256 hashes of WordPress secret salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`).
- **Zero Plaintext Database Exposure:** Database backups, SQL dumps, staging exports, and unauthorized database access reveal only ciphertexts prefixed with `wcp_enc:`.
- **Transparent In-Memory Decryption:** Decrypts credentials on the fly in memory only when executing authorized API requests, ensuring zero performance penalty.
- **UI Password Masking:** Administrative interfaces mask secrets with bullet placeholders (`••••••••`) and provide 1-click show/hide toggles.

---

## 19. On-Demand Database Backup Vault (`.sql.gz`)

- **1-Click Compressed Database Vault:** Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression.
- **Secure File Storage:** Stored in protected vault directory guarded by `.htaccess` with direct secure browser downloads.
- **Index Metadata:** Tracks backup filename, creation timestamp, and file size.

---

## 20. High-Precision Microsecond Telemetry & Diagnostics

- **Microsecond Scan Duration Tracking:**
  - Database schema upgraded with `started_at` (`datetime(3)`), `completed_at` (`datetime(3)`), and `duration_ms` (`int(11)`).
  - Captures exact microtime at scan initialization and completion in WordPress local timezone without timestamp truncation.
  - Timezone-aware execution tracking eliminating server clock and site timezone drift.
- **Real-Time Environment Diagnostics:** Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`), MySQL collation, database size, and OS architecture.
- **Scan Logs & History:** Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

---

## 21. Data Privacy, Safety Policies & Clean Uninstall Lifecycle

- **Non-Destructive Operations:** All Auto-Cure, Quarantine, and Remediation operations create automated pre-action safety snapshots in the local backup vault before modifying files on disk.
- **Zero Tracking or Telemetry:** The plugin does NOT track, collect, store, or sell any personal data, analytics, or browsing habits.
- **100% On-Premise Execution:** Scans, heuristic checks, file integrity monitoring, brute-force defenses, 2FA generation, and firewall evaluation run 100% locally within your PHP environment.
- **Clean 5-Table Database Purge on Uninstall (`uninstall.php`):** When "Auto-Remove All Data on Uninstall" is active (default), deleting the plugin automatically drops all 5 custom database tables (`wp_wcp_scans`, `wp_wcp_scan_issues`, `wp_wcp_scan_files`, `wp_wcp_quarantine`, `wp_wcp_firewall_logs`), deletes options/transients, clears crons, and purges the upload storage folder.

---

## 👨‍💻 Author & Engineering

**WCP Security Scanner** is designed and engineered by **Mir Alamin** ([WebCare Pro](https://webcarespro.com)):
- **Upwork:** [Mir Alamin on Upwork](https://www.upwork.com/freelancers/~0162afa9a578170c67) — Top Rated Plus Freelancer, 100% Job Success Score
- **Website:** [https://webcarespro.com](https://webcarespro.com)
- **Direct Email:** [hello@webcarespro.com](mailto:hello@webcarespro.com)
- **WhatsApp:** [+880 1322 691090](https://wa.me/8801322691090)
