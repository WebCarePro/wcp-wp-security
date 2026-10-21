# WCP Security Scanner — Extended Features & Architecture Catalog

**WCP Security Scanner** is an enterprise-grade, memory-efficient WordPress security, malware detection, forensic auditing, and edge defense plugin engineered by **[Mir Alamin](https://www.upwork.com/freelancers/~0162afa9a578170c67)** ([WebCare Pro](https://webcarespro.com)).

Built with a high-performance **React 18 + TypeScript** administrative single-page dashboard and memory-safe **PHP 8.3+ streaming engines**, the plugin provides comprehensive threat prevention, runtime defense, cryptographic isolation, and forensic remediation without degrading server performance.

---

## Table of Contents

1. [Next-Gen Cyber Command Center & Threat Dashboard](#1-next-gen-cyber-command-center--threat-dashboard)
2. [Multi-Vector Security & Deep Malware Detection Engine](#2-multi-vector-security--deep-malware-detection-engine)
3. [Targeted Single-Purpose Security Audits & Auto-Scroll Workflow](#3-targeted-single-purpose-security-audits--auto-scroll-workflow)
4. [Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer](#4-real-time-file-integrity-monitoring-fim--visual-code-diff-viewer)
5. [1-Click Auto-Cure & Surgical Remediation Engine](#5-1-click-auto-cure--surgical-remediation-engine)
6. [Secure Quarantine Vault & Isolation Architecture](#6-secure-quarantine-vault--isolation-architecture)
7. [Software Intelligence & Curated CVE Advisory Database](#7-software-intelligence--curated-cve-advisory-database)
8. [Living-off-the-Land (LotL) Runtime Hook Infiltration Sentinel](#8-living-off-the-land-lotl-runtime-hook-infiltration-sentinel)
9. [Database Micro-Anomaly & Rogue Administrator Trap](#9-database-micro-anomaly--rogue-administrator-trap)
10. [Web Application Firewall (WAF Lite) & Virtual Patching](#10-web-application-firewall-waf-lite--virtual-patching)
11. [Dedicated WAF Incident Logs, Threat Intelligence & Attack Forensics](#11-dedicated-waf-incident-logs-threat-intelligence--attack-forensics)
12. [Smart 404 Scanner Rate-Limiter & Reconnaissance Shield](#12-smart-404-scanner-rate-limiter--reconnaissance-shield)
13. [Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)](#13-cloudflare-edge-defense--zero-resource-waf-100-free-plan)
14. [Community Threat Intelligence & Botnet IP Blacklists](#14-community-threat-intelligence--botnet-ip-blacklists)
15. [Active Session Sentinel & Anti-Hijack Defense](#15-active-session-sentinel--anti-hijack-defense)
16. [Inline Expandable User Session Forensics & Real IP Tracking](#16-inline-expandable-user-session-forensics--real-ip-tracking)
17. [Multi-Factor Authentication (2FA) & Login Hardening](#17-multi-factor-authentication-2fa--login-hardening)
18. [Dedicated Notification Center & Granular 32+ Event Alert Matrix](#18-dedicated-notification-center--granular-32-event-alert-matrix)
19. [Enterprise HTTP Security Headers & 1-Click Site Hardening](#19-enterprise-http-security-headers--1-click-site-hardening)
20. [Bot Recon Defense & AI Scraper Shield](#20-bot-recon-defense--ai-scraper-shield)
21. [Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude)](#21-multi-provider-ai-code-forensics-chatgpt-gemini-claude)
22. [Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation)](#22-model-context-protocol-mcp-agentic-surface-ai-secops-automation)
23. [Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation)](#23-cryptographic-secret-vault-pure-aes-256-gcm-aead--two-phase-key-rotation)
24. [Unified WCP Vault Console (4 Consolidated Isolation & Recovery Facilities)](#24-unified-wcp-vault-console-4-consolidated-isolation--recovery-facilities)
25. [On-Demand Database Backup Vault (`.sql.gz`)](#25-on-demand-database-backup-vault-sqlgz)
26. [High-Precision Microsecond Telemetry & Diagnostics](#26-high-precision-microsecond-telemetry--diagnostics)
27. [Behavioral Baseline & Attack Chain Correlation](#27-behavioral-baseline--attack-chain-correlation)
28. [Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking](#28-frictionless-1-click-mark-safe--ignore-ux-with-sha-256-hash-locking)
29. [Data Privacy, Safety Policies & Clean Uninstall Lifecycle](#29-data-privacy-safety-policies--clean-uninstall-lifecycle)
30. [Dual-Theme Design System (High-Contrast White Mode & Dark Obsidian)](#30-dual-theme-design-system-high-contrast-white-mode--dark-obsidian)

---

## 1. Next-Gen Cyber Command Center & Threat Dashboard

- **High-Precision SVG Security Health Meter:** Circular dynamic vector meter displaying site security score (0–100%) with reactive color accents (emerald `#10b981`, sky blue `#38bdf8`, amber `#f59e0b`, rose `#ef4444`) and letter grades (`A+`, `A`, `B`, `C`, `D`, `F`).
- **Interactive Threat Metric Cubes:** High-contrast summary widgets grouping active threats into 3 primary vectors:
  - *Critical Exploits & Backdoors:* High-severity webshells, injection droppers, and active Trojans.
  - *File Integrity & Code Drift:* Modified WordPress core files, altered plugins, tampered themes, and rogue uploads.
  - *Software Vulnerabilities & CVE Advisories:* Outdated components with documented vulnerabilities and available patches.
  - Includes instant 1-click category filtering to immediately isolate specific threat vectors in the findings table.
- **Audit Command Center Console:**
  - Fast single-click execution controls: **Full Deep Audit** (entire filesystem and database) vs **Fast Audit** (plugins & themes only).
  - Live engine telemetry indicators displaying the active subsystem currently running (e.g., Core Integrity, Heuristic Scanner, CVE Scanner, LotL Hook Sentinel).
  - Dual-layer animated scan progress bar with percentage tracking, scanned file counter, active file paths, and instant cancellation controls.
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
- **Hierarchical Resumable Cursor Engine:**
  - Replaces slow numeric offset pagination with an opaque two-level hierarchical cursor (`phase`, `dir_stack`, `last_file`).
  - Completely eliminates $O(N^2)$ filesystem re-traversal overhead on large sites by resuming directory traversal directly at the last processed file.
  - Excludes non-essential and heavy trees (`.git`, `node_modules`, `vendor`, `cache`, `wfcache`, `updraft`, `.vault`, `.backups`, `.logs`) without recursion.
  - Fast-path filtering skips harmless static media while strictly inspecting executables and disguised double extensions (`shell.jpg.php`).
  - Bounded incremental memory footprint: limits batch heap overhead to ~15–25MB per chunk with cycle-safe non-symlink traversal, operating comfortably within standard 128MB–256MB hosting limits.
- **High-Throughput Findings Bulk Ingestion Layer:**
  - Persists file audit and finding records using prepared multi-row SQL statements (`bulk_insert_files`, `bulk_insert_issues`) via `FindingsRepository`.
  - Chunks queries at 80 rows per statement to stay safely beneath MySQL `max_allowed_packet` while avoiding table locks.
  - Safe null parameter binding via `prepare_with_nulls` prevents SQL syntax corruption.
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

## 3. Targeted Single-Purpose Security Audits & Auto-Scroll Workflow

- **7 Dedicated Rapid Audit Modules:**
  1. *Database Injections:* Instant check on `wp_posts`, `wp_options`, and `wp_comments` for SQL-injected scripts, SEO spam, and hidden redirect doors.
  2. *Uploads Quarantine Audit:* Fast-scan of `wp-content/uploads` isolating rogue executable PHP and disguised scripts.
  3. *Theme Integrity Deep Scan:* Targeted integrity verification across all installed themes.
  4. *Plugin Vulnerabilities Audit:* Isolated scan of all active and inactive plugins against known CVE advisories.
  5. *Core Checksums Audit:* Immediate verification of WordPress core files against official WordPress.org cryptographic hashes.
  6. *Privilege Escalation Check:* Rapid detection of ghost superusers, rogue administrator accounts, and orphaned user capabilities.
  7. *Runtime Hook Infiltration (LotL):* In-memory inspection of `$wp_filter` for suspicious closures and unauthorized authentication listeners.
- **Automatic Smooth Viewport Auto-Scroll:** When any targeted audit completes, the UI smoothly auto-scrolls the viewport directly to the Targeted Audit Results section (`scrollMarginTop: 24px`), presenting findings and risk scores immediately without requiring manual page scrolling.

---

## 4. Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer

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

## 5. 1-Click Auto-Cure & Surgical Remediation Engine

- **1-Click WordPress Core Auto-Cure (`restore_official_core_file`):**
  - Repairs tampered core files in `wp-admin`, `wp-includes`, and root directories directly to official WordPress.org release code.
  - Automatically fetches the bit-for-bit clean copy matching the exact site WordPress version (`$wp_version`) from the official WordPress.org Subversion repository or official GitHub mirror.
  - Strictly protects `wp-config.php`, `.htaccess`, and `.user.ini` from template overwrite.
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

## 6. Secure Quarantine Vault & Isolation Architecture

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

## 7. Software Intelligence & Curated CVE Advisory Database

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

## 8. Living-off-the-Land (LotL) Runtime Hook Infiltration Sentinel

- **Active Runtime Memory Hook Audit:** Uses PHP Reflection to inspect active runtime hook callbacks registered in `$wp_filter` across sensitive WordPress lifecycle actions:
  - `authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`.
- **Anonymous Closure & Credential Sniffer Detection:** Flags anonymous `Closure` functions attached to authentication hooks that may intercept plaintext user credentials during login.
- **External Rootkit & Uploads Hook Traps:**
  - Detects callbacks originating outside the WordPress root (e.g., server-level `auto_prepend_file` rootkits or PHP-FPM pool injections).
  - Detects callbacks originating from `wp-content/uploads/` (webshell runtime hooks).
- **Dangerous Native Function Registration Defense:** Detects dangerous native PHP execution functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`, `exec`, `popen`) attached directly as WordPress filter callbacks.

---

## 9. Database Micro-Anomaly & Rogue Administrator Trap

- **Stealth User Infiltration Detection:** Cross-references `wp_users` with `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL queries that bypass standard `user_register` hooks.
- **Ghost & Orphaned Capability Hunting:** Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap:** Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe:** Recursively audits `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden inside transients or autoloaded options.

---

## 10. Web Application Firewall (WAF Lite) & Virtual Patching

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

## 11. Dedicated WAF Incident Logs, Threat Intelligence & Attack Forensics

- **Full Forensic Analytics Center (`wcp-scanner-waf-logs`):**
  - Real-time threat telemetry featuring 4 primary KPI cards: Total Incursions Blocked, 24h Attack Surge, Distinct Hostile IPs, and Simulation Mode hits.
  - Top Attack Vectors breakdown with proportional visual percentage distribution bars.
  - Frequent Hostile Offender IP Directory with hit counts, last active timestamps, and 1-click Filter/Block controls.
- **Multi-Field Real-Time Forensic Search:**
  - Search across IP addresses, target URIs, malicious payload signatures, and User-Agents simultaneously.
  - Granular filters by Category (SQLi, XSS, Path Traversal, Bot Probes, 404 Rate-Limit, Virtual Patch), Action (Blocked vs Simulated), HTTP Method (GET, POST, PUT, DELETE), and Page Size (10, 25, 50, 100).
- **Expandable In-Depth Incident Accordion:**
  - Inspect trigger rule descriptions, raw browser User-Agents, and syntax-highlighted malicious payload excerpts.
  - 1-click incident payload export to JSON for external SIEM analysis.
- **1-Click Perimeter Mitigation & Export:**
  - 1-click Block IP (instantly appends to local WAF blocklist) and 1-click Allow IP directly from incident rows.
  - Export filtered incident datasets as CSV (`.csv`), JSON (`.json`), or printable forensic reports (`window.print()`).

---

## 12. Smart 404 Scanner Rate-Limiter & Reconnaissance Shield

- **Automated 404 Fuzzing & Exploit Lockouts:**
  - Intercepts hostile automated fuzzers and vulnerability scanners probing for non-existent backdoor scripts (`shell.php`, `adminer.php`, `c99.php`).
  - Enforces automated temporary lockouts when requests exceed configurable probe thresholds (default 10 probes within 60s trigger a 30-minute block).
- **DNS-Verified Search Engine Exemption:**
  - Validates genuine search engine bots (Googlebot, Bingbot, DuckDuckBot, Yandex, Baidu, Yahoo) using dual Reverse DNS (PTR) + Forward DNS (A/AAAA) confirmation with 24-hour transient caching.
  - Completely exempts verified crawlers from 404 lockouts, preventing SEO penalties and crawler disruptions.
- **Static Asset & Media Exclusion:**
  - Missing static assets (`.jpg`, `.png`, `.webp`, `.svg`, `.css`, `.js`, `.ico`, `.woff`, `.pdf`) are excluded from 404 failure tallies, preventing accidental false-positive lockouts for legitimate human visitors loading broken theme assets.
- **High-Risk Reconnaissance Acceleration:**
  - Probes targeting high-risk backdoor signatures (`.env`, `.git`, `.bak`, `wp-config.php.bak`, `shell.php`, `.sql`) increment the rate-limiting counter by 3x to instantly quarantine active penetration attempts.

---

## 13. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)

- **Zero-Resource Perimeter Threat Interception:** Blocks malicious bots and automated exploit probes at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
- **3 High-Density Master Compound Rules (100% Free Plan Compatible):**
  1. *Rule 1: Master Perimeter & Sensitive File Armor:* Blocks `/xmlrpc.php`, script execution in `wp-content/uploads/` and `wp-content/upgrade/`, sensitive dotfiles (`.env`, `.git`, `.user.ini`), debug logs, and backup files in 1 consolidated Block rule.
  2. *Rule 2: LFI/RFI Directory Traversal & Reconnaissance Shield:* Terminates directory traversal (`../`, `etc/passwd`), code execution wrappers (`base64_decode`, `eval`), author harvesting (`?author=`), and unauthenticated REST API user enumeration.
  3. *Rule 3: Login Portal Automated Bot Defense:* Challenges automated bots targeting `wp-login.php`, custom membership slugs, and WooCommerce account endpoints with Cloudflare Turnstile / Managed Challenge.
- **Cloudflare Free Quota Optimization:** Consolidating into 3 master compound rules consumes only 3 of Cloudflare's 5 free custom rule slots (leaving 40% free for custom rules).
- **Individual Single-Rule Push & Remove:** Push, update, or remove individual Cloudflare edge rules independently via REST API (`/cloudflare/deploy-single-rule`) without redeploying entire rulesets.
- **Cloudflare Edge Rate Limiting on `/wp-login.php`:** Deploys an edge rate limiter calibrated for the Cloudflare Free Tier (60s window, 5 request threshold, 10s mitigation cooldown) with zero server resource usage.
- **Bi-Directional WAF Auto-Ban Sync:** Automatically synchronizes locally detected high-threat attack IPs to Cloudflare Edge IP Access Rules.
- **1-Click Global CDN Cache Purge:** Instant edge cache purge directly from the WordPress administration panel.

---

## 14. Community Threat Intelligence & Botnet IP Blacklists

- **Community Botnet IP Blacklists:** Automatically synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL.
- **Sub-Millisecond In-Memory Subnet Matching:** Performs static in-memory $O(1)$ hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
- **Zero-Day CVE Feed & Site Correlation:** Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes, displaying status badges (`Installed — Vulnerable`, `Installed — Patched`, `Global Virtual Shield`).
- **IP Reputation Diagnostic Tool:** Built-in checker to test client or visitor IPs against the active threat database.

---

## 15. Active Session Sentinel & Anti-Hijack Defense

- **Administrative Session Telemetry:** Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Dual-Device Concurrency Control:** Enforces flexible session policies (strictly 1 Desktop + 1 Mobile maximum per administrator).
- **1-Click Remote Termination:** Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

---

## 16. Inline Expandable User Session Forensics & Real IP Tracking

- **In-Table Forensic Accordion:** Expands comprehensive session forensics directly beneath administrator rows in the Active Administrator Sessions directory table (`Hide Forensics` / `Forensics`), completely eliminating viewport modal overlap.
- **Strict Origin Login IP Preservation:** Inspects the user's authentic decrypted login IP recorded at authentication time (`$data['ip']`), preventing Cloudflare Anycast edge proxies or viewer reverse proxy IPs from colliding with or overwriting remote administrator IPs.
- **Fallback Session Integrity:** Preserves authentic origin IP telemetry across all core session token iterations and password reset audit trails.

---

## 17. Multi-Factor Authentication (2FA) & Login Hardening

- **Pure PHP RFC 6238 TOTP Engine:** Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
- **Native `wp-login.php` Interception:** Displays a responsive, branded two-factor verification challenge screen supporting rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
- **AES-256-GCM AEAD Encrypted User Secrets:** Encrypts user TOTP secrets (`_wcp_2fa_secret`) at rest in `wp_usermeta` via the Secret Vault with 128-bit authentication integrity tags and transparent in-memory runtime decryption.
- **Brute Force Rate-Limiter:** Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.
- **Administrator 2FA Governance & Policy Enforcement:**
  - View all administrator accounts with their profile avatars, 2FA status, and compliance state.
  - 1-click Emergency Unlock & Disable 2FA for locked-out administrators.
  - 1-click Credential Reset & QR Code Delivery Modal for remote enrollment.
  - Mandatory 2FA Enforcement Policies: Force Immediately, Grace Period Countdown, or Remind on Next Login.
  - Emergency Backup Codes (`.txt`) Download Guard with auto-download prior to activation.
  - Post-setup Backup Code Regeneration with real-time remaining code counters.

---

## 18. Dedicated Notification Center & Granular 32+ Event Alert Matrix

- **Dedicated Administrative Notification Hub (`wcp-scanner-notifications`):** Full-page notification operations hub accessible via direct deep-link from Settings, Firewall, and email footers.
- **32+ Granular Security Events Across 8 Categories:**
  1. *Core Scans & Threats:* Scheduled complete, manual complete, targeted complete, critical/high threats found, auto-quarantined threats, execution timeout.
  2. *Plugin Self-Defense:* Anti-tamper file mismatch, host-deleted files, unauthorized deactivation, uninstallation.
  3. *Cloudflare & WAF Defense:* Firewall rules deployed/removed, attack block surges, virtual patch exploits intercepted, .htaccess/Nginx hardening updates.
  4. *Authentication & Access Security:* 2FA enabled/disabled, admin password changed/reset, brute-force IP lockouts, Cloudflare edge IP auto-bans, session IP shift/hijack, rogue admin creation/privilege escalation.
  5. *File Integrity Monitoring:* FIM core file modifications, plugin/theme tampering, suspicious PHP scripts in uploads, Auto-Cure restorations, baseline snapshot updates.
  6. *Vulnerabilities & CVE Feeds:* Core unpatched CVEs, plugin/theme vulnerability advisories, abandoned plugins, threat intel sync.
  7. *Database Backups & Vault:* Backup completed, backup failed, database restored, quarantine restored to filesystem, quarantine purged.
  8. *DevSecOps & AI Forensics:* Webhook channel toggled, webhook delivery HTTP failures, AI forensics engine status, MCP agent surface status.
- **Independent Dual-Channel Matrix:** Independent toggle switches for Email (`wp_mail`) and DevSecOps Webhooks (Slack, Discord, ClickUp, Asana, Generic JSON) per event.
- **Granular Default Baseline:** By default, only two critical high-priority events are activated ("Plugin Deactivated" and "Critical / High Threats Detected"), while all other 30+ events remain cleanly silenced until customized.
- **Executive Obsidian Email Template:** Branded obsidian styling (`#0b1120`), glowing priority badges, client IP/device metadata detection, and Schema.org (`SecurityIncident`) JSON-LD structured data for LLM inbox summarization.
- **1-Click Test Delivery:** Test buttons on each event trigger live test payloads via `/notifications/test-event`.

---

## 19. Enterprise HTTP Security Headers & 1-Click Site Hardening

- **Enterprise Security Headers Dispatcher:** Injects `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock:** Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense:** Blocks author archive scraping (`/?author=1`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`). Strips WordPress version meta tags and asset query strings (`?ver=`).
- **Sensitive System File Probe Shield:** Returns 403 Forbidden on requests attempting to access `.env`, `.git`, `.htaccess`, `.sql`, `composer.json`, and backup archives.
- **1-Click Hardening Presets:** Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (`A+`, `A`, `B`, `C`).

---

## 20. Bot Recon Defense & AI Scraper Shield

- **Fake Search Engine Crawler Defense:** Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
- **AI Content Scraper & Harvester Shield:** Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) at the WAF level.
- **Dynamic Virtual `robots.txt` Injection:** Automatically generates and injects standard AI bot Disallow directives into virtual `robots.txt`.

---

## 21. Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude)

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

## 22. Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation)

- **Native JSON-RPC 2.0 Agentic Integration:** Bridges external AI coding agents (Claude Desktop, Cursor IDE, Antigravity, custom LLM agents) with WordPress security operations over standard JSON-RPC 2.0 and Bearer token authentication.
- **7 First-Class SecOps Tools:**
  - `wcp_get_site_health`: Retrieve dynamic health score (0–100%), letter grade, and active threat counts *(Read-Only)*.
  - `wcp_list_findings`: Query active, quarantined, repaired, or ignored findings with pagination and severity filters *(Read-Only)*.
  - `wcp_get_finding_detail`: Inspect specific vulnerability metadata, Myers code diffs, and forensic evidence *(Read-Only)*.
  - `wcp_list_quarantined_files`: Enumerate isolated files with SHA-256 hashes and original paths *(Read-Only)*.
  - `wcp_get_waf_stats`: Inspect firewall block statistics, rule hits, and top malicious IP addresses *(Read-Only)*.
  - `wcp_trigger_scan`: Launch asynchronous background security audits or synchronous fast checks *(Mutating)*.
  - `wcp_whitelist_finding`: Suppress false-positives with automated SHA-256 cryptographic hash-locking *(Mutating)*.
- **Granular Permission Scopes:** Enforce **Read-Only (Observation)** mode to allow AI agents to safely inspect and diagnose without write privileges, or **Full Remediation (Read + Write)** for automated incident response.
- **Sliding-Window Rate Limiting:** Per-token rate limiter configurable from 30 to 300 requests/minute to protect origin servers from agentic query floods.
- **Persistent Ring-Buffer Execution Audit Trail:** Logs every incoming MCP agent call with timestamp, tool name, client IP, payload preview, execution time, and response status in a persistent 150-event ring buffer (`wcpscan_mcp_audit_log`).
- **1-Click Ready Client Configs:** Ready-to-copy JSON configuration snippets formatted specifically for Cursor (`cursor_mcp.json`) and Claude Desktop (`claude_desktop_config.json`).

---

## 23. Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation)

- **Pure AES-256-GCM Authenticated Encryption (AEAD):** All sensitive third-party API credentials, webhook endpoints, and infrastructure tokens are encrypted at rest before being saved to `wp_options`:
  - Slack webhooks, Discord webhooks, ClickUp webhooks, Asana webhooks, Generic automation URLs (Zapier, Make, n8n).
  - Cloudflare API Bearer Tokens and Cloudflare Zone IDs.
  - OpenAI API keys, Google Gemini API keys, and Anthropic Claude API keys.
  - Two-Factor Authentication (2FA) TOTP user secrets (`_wcp_2fa_secret`).
- **Cryptographic Tamper-Proofing & Integrity Tags:**
  - Encrypts payloads using AES-256-GCM with 128-bit authentication tags and randomized 12-byte initialization vectors (`random_bytes(12)`).
  - Completely eliminates ciphertext malleability, bit-flipping vulnerabilities, and CBC padding oracle attacks by cryptographically verifying ciphertext integrity prior to decryption.
  - Enforces strict fail-closed security: corrupted or tampered records fail decryption immediately by throwing `\RuntimeException`, preventing execution on tainted credentials.
- **Two-Phase Commit Key Rotation Orchestrator (`VaultRotator`):**
  - Robust state machine (`idle` → `preparing` → `migrating` → `verifying` → `committed`) manages zero-downtime key rotation.
  - Dual-key background decrypt fallback: enables background requests, webhooks, and REST calls to decrypt using transitional old key material while key rotation is actively in flight.
  - Ephemeral sealed key envelopes: transitional keys are sealed in-memory using `sodium_crypto_secretbox` (with AES-256-GCM fallback), storing cipher payloads and session-tied ephemeral keys in short-lived transients to prevent raw key exposure in `wp_options` or persistent caches.
  - Pre-rotation single-row serialized backup & rollback: captures pre-migration encrypted secrets into an isolated snapshot (`wcp_vault_backup_{id}`) with atomic rollback (`VaultRotator::rollback()`) if verification detects any decryption discrepancy.
  - Idempotent & resumable batch re-encryption with 32-byte binary key detection.
- **Dynamic 256-bit Key Derivation:**
  - Priority derivation: `WCP_VAULT_KEY` environment variable &rarr; `WCP_VAULT_KEY` constant in `wp-config.php` &rarr; SHA-256 hash of 4 WordPress core salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`, `SECURE_AUTH_SALT`).
  - Supports 64-character hexadecimal keys representing raw 32-byte binary keys.
- **Zero Plaintext Database Exposure:** Database backups, SQL dumps, staging exports, and unauthorized database access reveal only ciphertexts prefixed with `wcp_gcm:`.
- **Transparent In-Memory Decryption:** Decrypts credentials on the fly in memory only when executing authorized API requests or dispatching webhooks, ensuring zero performance penalty.
- **UI Password Masking:** Administrative interfaces mask secrets with bullet placeholders (`••••••••`) and provide 1-click show/hide toggles.

---

## 24. Unified WCP Vault Console (4 Consolidated Isolation & Recovery Facilities)

- **Centralized Security Vault Page (`wcp-vault`):** Seamlessly consolidates all site isolation, backup, and encryption primitives into a single high-performance interface with live telemetry and direct deep-linking.
- **Facility 1 — File Quarantine Isolation Vault:** View, inspect, restore, or permanently purge quarantined rogue scripts and backdoors preserved with SHA-256 integrity hashes in `.htaccess`-protected storage.
- **Facility 2 — Database Snapshot & Point-in-Time Recovery Vault:** Create on-demand Gzip-compressed `.sql.gz` database snapshots, inspect byte-accurate archive sizes, and download for offsite disaster recovery.
- **Facility 3 — Pre-Cure Safety Rollback & Remediation Vault:** Inspect safety diffs and restore modified files prior to Auto-Cure or webshell stripping actions.
- **Facility 4 — Secret & Cryptographic Key Vault:** Real-time health metrics of the AES-256-GCM AEAD encryption subsystem, including self-healing dual-key decryption fallback, stale rotation lock recovery, and 1-click diagnostic reset.

---

## 25. On-Demand Database Backup Vault (`.sql.gz`)

- **1-Click Compressed Database Vault:** Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression.
- **Secure File Storage:** Stored in protected vault directory guarded by `.htaccess` with direct secure browser downloads.
- **Index Metadata:** Tracks backup filename, creation timestamp, and file size.

---

## 26. High-Precision Microsecond Telemetry & Diagnostics

- **Microsecond Scan Duration Tracking:**
  - Database schema upgraded with `started_at` (`datetime(3)`), `completed_at` (`datetime(3)`), and `duration_ms` (`int(11)`).
  - Captures exact microtime at scan initialization and completion in WordPress local timezone without timestamp truncation.
  - Timezone-aware execution tracking eliminating server clock and site timezone drift.
- **Real-Time Environment Diagnostics:** Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`), MySQL collation, database size, and OS architecture.
- **Scan Logs & History:** Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

---

## 27. Behavioral Baseline & Attack Chain Correlation

- **Behavioral Drift Detection:** Tracks alterations in critical site metadata, administrator counts, PHP execution options, and file counts against historic baselines.
- **Attack Chain Timeline:** Correlates disparate security events (failed login brute-force → backdoor upload → cron modification) into a unified chronological breach narrative with estimated blast radius scoring.

---

## 28. Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking

- **1-Click Intelligent Suppression:** Instantly suppress known false-positives with a single click. Automatically computes SHA-256 cryptographic checksums of the target file to lock the rule to that exact file version, with a 90-day auto-review safety period.
- **Collapsible Power-User Drawer:** Advanced controls to customize rule match types (Exact SHA-256 Hash vs File Path vs Pattern Signature), adjust expiration periods (30 days, 90 days, 1 year, or Permanent), and log administrative audit rationale.
- **Segmented Findings Status Filtering:** Instantly toggle between **Active Threats**, **Whitelisted / Ignored**, and **All Findings** with dynamic count badges, keeping active security views clean and actionable.

---

## 29. Data Privacy, Safety Policies & Clean Uninstall Lifecycle

- **Non-Destructive Operations:** All Auto-Cure, Quarantine, and Remediation operations create automated pre-action safety snapshots in the local backup vault before modifying files on disk.
- **Zero Tracking or Telemetry:** The plugin does NOT track, collect, store, or sell any personal data, analytics, or browsing habits.
- **100% On-Premise Execution:** Scans, heuristic checks, file integrity monitoring, brute-force defenses, 2FA generation, and firewall evaluation run 100% locally within your PHP environment.
- **Clean 6-Table Database Purge on Uninstall (`uninstall.php`):** When "Auto-Remove All Data on Uninstall" is active (default), deleting the plugin automatically drops all 6 custom database tables (`wcpscan_scans`, `wcpscan_scan_issues`, `wcpscan_scan_files`, `wcpscan_quarantine`, `wcpscan_firewall_logs`, `wcpscan_login_history`), purges user meta, clears transients, deletes options, removes crons, and purges the upload storage folder.

---

## 30. Dual-Theme Design System (High-Contrast White Mode & Dark Obsidian)

- **Flawless White (Light) Mode Parity:** Custom semantic token architecture (`var(--wcp-bg-panel)`, `var(--wcp-text-primary)`, `var(--wcp-border)`) guarantees maximum readability, deep contrast, and crisp table borders (`#ffffff`, `#f8fafc`, `#e2e8f0`, `#0f172a`), eliminating washed-out text or unreadable badges.
- **Midnight Obsidian Dark Mode:** Cyberpunk-inspired deep midnight palette (`#090d16` canvas, `#0f172a` cards, `#1e293b` borders) with vibrant neon accents and glowing status indicators.
- **1-Click Theme Switcher:** Instant toggle between White Mode and Dark Mode saved in local storage.

---

## 👨‍💻 Author & Engineering

**WCP Security Scanner** is designed and engineered by **Mir Alamin** ([WebCare Pro](https://webcarespro.com)):
- **Upwork:** [Mir Alamin on Upwork](https://www.upwork.com/freelancers/~0162afa9a578170c67) — Top Rated Plus Freelancer, 100% Job Success Score
- **Website:** [https://webcarespro.com](https://webcarespro.com)
- **Direct Email:** [hello@webcarespro.com](mailto:hello@webcarespro.com)
- **WhatsApp:** [+880 1322 691090](https://wa.me/8801322691090)
