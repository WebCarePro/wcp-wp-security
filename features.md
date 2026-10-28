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
18. [WebAuthn Passwordless Biometric Login & Native Windows Hello Ceremony](#18-webauthn-passwordless-biometric-login--native-windows-hello-ceremony)
19. [Dedicated Notification Center & Granular 32+ Event Alert Matrix](#19-dedicated-notification-center--granular-32-event-alert-matrix)
20. [Enterprise HTTP Security Headers & 1-Click Site Hardening](#20-enterprise-http-security-headers--1-click-site-hardening)
21. [1-Click WP_DEBUG & Sensitive Configuration Remediation Engine](#21-1-click-wp_debug--sensitive-configuration-remediation-engine)
22. [Bot Recon Defense & AI Scraper Shield](#22-bot-recon-defense--ai-scraper-shield)
23. [Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude)](#23-multi-provider-ai-code-forensics-chatgpt-gemini-claude)
24. [Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation)](#24-model-context-protocol-mcp-agentic-surface-ai-secops-automation)
25. [Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation)](#25-cryptographic-secret-vault-pure-aes-256-gcm-aead--two-phase-key-rotation)
26. [Unified WCP Vault Console (4 Consolidated Isolation & Recovery Facilities)](#26-unified-wcp-vault-console-4-consolidated-isolation--recovery-facilities)
27. [On-Demand Database Backup Vault (`.sql.gz`)](#27-on-demand-database-backup-vault-sqlgz)
28. [High-Precision Microsecond Telemetry & Diagnostics](#28-high-precision-microsecond-telemetry--diagnostics)
29. [Behavioral Baseline & Attack Chain Correlation](#29-behavioral-baseline--attack-chain-correlation)
30. [Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking](#30-frictionless-1-click-mark-safe--ignore-ux-with-sha-256-hash-locking)
31. [Zero-Trust Must-Use (MU) Guardian & Sandboxed Temporary Support Access](#31-zero-trust-must-use-mu-guardian--sandboxed-temporary-support-access)
32. [Preload Micro-WAF & Early Execution Engine (Linux Fail2ban & CrowdSec Syslog)](#32-preload-micro-waf--early-execution-engine-linux-fail2ban--crowdsec-syslog)
33. [JavaScript Threat Intelligence, Magecart Payment Skimmer & Beacon Detector](#33-javascript-threat-intelligence-magecart-payment-skimmer--beacon-detector)
34. [Third-Party Script Inventory & Frontend Hostname Drift Sentinel](#34-third-party-script-inventory--frontend-hostname-drift-sentinel)
35. [Offline Dependency Lockfile (Composer & npm) Supply-Chain Auditor](#35-offline-dependency-lockfile-composer--npm-supply-chain-auditor)
36. [2026 AI Threat Defense, Prompt-Injection Guard & Decoy Ghost Route Traps](#36-2026-ai-threat-defense-prompt-injection-guard--decoy-ghost-route-traps)
37. [Outbound AI & SSRF Egress Firewall (Cloud Metadata & Exfiltration Shield)](#37-outbound-ai--ssrf-egress-firewall-cloud-metadata--exfiltration-shield)
38. [Plaintext Credential Exposure & Secret Leak Scanner (.env, Git, Keys)](#38-plaintext-credential-exposure--secret-leak-scanner-env-git-keys)
39. [REST API & Public AJAX Attack Surface Inventory & User Enumeration Guard](#39-rest-api--public-ajax-attack-surface-inventory--user-enumeration-guard)
40. [72-Hour Post-Remediation Reinfection Watchdog & Surveillance Vault](#40-72-hour-post-remediation-reinfection-watchdog--surveillance-vault)
41. ["Time-Machine" Local File & Bespoke Asset Snapshot Baseline Engine](#41-time-machine-local-file--bespoke-asset-snapshot-baseline-engine)
42. [Automated Blacklist, Domain Reputation & DNSBL Early-Warning Sentinel](#42-automated-blacklist-domain-reputation--dnsbl-early-warning-sentinel)
43. [Unified 5-Tier Threat Correlation Engine & Attack Kill-Chain Forensics](#43-unified-5-tier-threat-correlation-engine--attack-kill-chain-forensics)
44. [1-Click Panic Button Emergency Site Lockdown & Containment Protocol](#44-1-click-panic-button-emergency-site-lockdown--containment-protocol)
45. [Global Command Center & All Modules Mega-Menu (Ctrl+K Navigation)](#45-global-command-center--all-modules-mega-menu-ctrlk-navigation)
46. [Zero-Allocation Streaming Session Queue & Microsecond Disk Cursor](#46-zero-allocation-streaming-session-queue--microsecond-disk-cursor)
47. [Host Antivirus Immunity & Heuristic Engine Resilience (CPGuard / Imunify360 Bypass Defense)](#47-host-antivirus-immunity--heuristic-engine-resilience-cpguard--imunify360-bypass-defense)
48. [Data Privacy, Safety Policies & Clean Uninstall Lifecycle](#48-data-privacy-safety-policies--clean-uninstall-lifecycle)
49. [CrashGuard Zero-Downtime Circuit Breaker & Safe Mode Self-Preservation](#49-crashguard-zero-downtime-circuit-breaker--safe-mode-self-preservation)
50. [Pre-Install Supply-Chain Gatekeeper & Update Risk Advisor](#50-pre-install-supply-chain-gatekeeper--update-risk-advisor)
51. [Zero-SQL Partitioned WAF Incident Filesystem Engine](#51-zero-sql-partitioned-waf-incident-filesystem-engine)
52. [Enterprise Granular Notification Center & DevSecOps Webhooks](#52-enterprise-granular-notification-center--devsecops-webhooks)
53. [Turbo Scan Engine Optimization, In-Memory Caching & Bulk Ingestion](#53-turbo-scan-engine-optimization-in-memory-caching--bulk-ingestion)

---

## 1. Next-Gen Cyber Command Center & Threat Dashboard

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Think of this as the digital cockpit and dashboard for your website's health. In a single glance, you see a clear letter grade (from **A+** down to **F**) and a percentage score showing exactly how safe your website is right now. If there are any urgent issues—like hacked files, outdated plugins, or suspicious accounts—they are highlighted in bold, colorful summary cards. You don't have to navigate through endless menus; one click on any card immediately filters the exact list of issues so you can solve them in seconds.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
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

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Hackers frequently hide malicious code inside normal-looking images, fake plugins, or deeply nested folders. Our Deep Malware Detection Engine acts like an advanced airport X-ray scanner for your server. It reads through every file, checking for hacker tools, hidden backdoors, disguised file extensions (like a harmful script disguised as a photo), and sneaky database injections. It runs smoothly in small batches in the background so your site visitors never experience any slowdowns.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
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
  - Bounded incremental memory footprint: limits batch heap overhead to ~15–25MB per chunk with cycle-safe non-symlink traversal, operating comfortably within standard 128MB–256MB hosting limits.
- **High-Throughput Findings Bulk Ingestion Layer:**
  - Persists file audit and finding records using prepared multi-row SQL statements (`bulk_insert_files`, `bulk_insert_issues`) via `FindingsRepository`.
  - Chunks queries at 80 rows per statement to stay safely beneath MySQL `max_allowed_packet` while avoiding table locks.
  - Safe null parameter binding via `prepare_with_nulls` prevents SQL syntax corruption.
- **Crontab & Scheduled Task Auditing:**
  - Audits Linux server-level crontab files (`/var/spool/cron`, `crontab -l`) for rogue persistence jobs.
  - Audits WordPress virtual `wp-cron` hooks in `wp_options:cron` for suspicious callbacks, piped curl/wget downloads, and orphaned hooks.

---

## 3. Targeted Single-Purpose Security Audits & Auto-Scroll Workflow

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Sometimes you don't need a full 10-minute scan of your entire server; you just want to check one specific thing, like "Are my uploads clean?" or "Are any of my plugins vulnerable right now?". With Targeted Audits, you click one button, the plugin scans that exact area in 3 to 10 seconds, and your screen smoothly glides down directly to the results so you see the answers instantly without searching.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **7 Dedicated Rapid Audit Modules:**
  1. *Database Injections Audit:* Inspects `wp_posts` and `wp_options` for stored XSS, spam redirects, and rogue iframes.
  2. *Uploads Quarantine Audit:* Scans `wp-content/uploads/` exclusively for executable scripts and double extensions.
  3. *Theme Integrity Deep Scan:* Verifies active and installed theme template files for backdoor injections.
  4. *Plugin Vulnerabilities Audit:* Audits active and inactive plugins against known CVE records.
  5. *Core Checksums Audit:* Fast API checksum verification across all WordPress root, `wp-admin`, and `wp-includes` files.
  6. *Privilege Escalation Check:* Identifies rogue administrative accounts and capability mismatches in `wp_usermeta`.
  7. *Runtime Hook Infiltration (LotL):* Inspects active memory filters for anonymous closure sniffers.
- **Automatic Smooth Viewport Auto-Scroll:** When any targeted audit completes, the UI smoothly auto-scrolls the browser viewport directly to the Targeted Audit Results section (`scrollMarginTop: 24px`), presenting findings and risk scores immediately without requiring manual page scrolling.

---

## 4. Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
If a hacker or rogue script secretly changes a single line of code in WordPress or one of your plugins, it can be almost impossible to notice. File Integrity Monitoring acts as your site's permanent security guard. It knows what official, clean WordPress files look like. If any file has been altered, it shows you a clear visual comparison: lines in red show what was removed, and lines in green show what was added, just like a Word document change-tracker.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Filesystem Change Tracker:** Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
- **Custom & Premium Component Recognition:** Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to prevent false alarms.
- **In-Page Visual Code Diff Viewer Modal (`VisualDiffModal.tsx`):** Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org release mirrors line-by-line with side-by-side additions and deletions.

---

## 5. 1-Click Auto-Cure & Surgical Remediation Engine

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Finding malware is only half the battle—fixing it without breaking your website is the hard part. Auto-Cure gives you a 1-click "Fix It" button. If an official WordPress or plugin file was infected, it automatically fetches a brand-new, clean copy straight from the official WordPress repository and swaps it in. Before changing anything, it saves a safe backup copy first, so you can always undo the change with one click if needed.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **1-Click WordPress Core Auto-Cure:** Restores tampered core files inside `wp-admin`, `wp-includes`, and root directories back to official pristine WordPress.org release code matching the exact site WordPress version, without re-installing all of WordPress.
- **1-Click Plugin & Theme Auto-Cure:** Restores altered or infected plugin and theme files back to authentic, bit-for-bit verified copies fetched directly from WordPress.org release mirrors.
- **1-Click Webshell Stripping:** Surgically neutralizes malicious code headers, obfuscated `eval()`/`base64` wrappers, and backdoor includes while preserving legitimate file code with tokenizer syntax validation.
- **1-Click Scheduled Cron Hook Remediation:** Safely unschedules and purges orphaned or malicious cron hooks directly from `wp_options:cron` via `wp_clear_scheduled_hook()`.
- **Auto-Cure Safety Backups & Rollback Vault:** Creates timestamped safety backups in a secure directory before every remediation action, enabling instant rollback if needed.
- **Real-Time State Synchronization:** As soon as an issue is cured, the findings table updates to display an `Issue Solved & Restored` status badge and transitions mitigation actions automatically.

---

## 6. Secure Quarantine Vault & Isolation Architecture

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When dangerous hacker files or alien scripts are found, you shouldn't just leave them sitting there, but deleting them immediately might be risky if you aren't sure what they are. The Quarantine Vault works like a hospital isolation ward: it locks the infected file inside a secure, encrypted folder where it cannot run, spread, or execute. You can inspect it safely, and either restore it if it's harmless or permanently delete it forever.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Safe Cryptographic Isolation:** Safely isolates infected or unknown files into a protected, `.htaccess`-guarded directory outside executable paths. Preserves original file permissions, timestamps, and SHA-256 cryptographic hashes in `wp_wcp_quarantine`.
- **Intelligent Quarantine Eligibility Safeguards:** Enforces strict boundary checks (`canQuarantineIssue`): prevents quarantining critical configuration files (`wp-config.php`, `.htaccess`, `wp-settings.php`, `wp-load.php`) to eliminate site crashes. Restricts quarantine strictly to alien and rogue files.
- **Quarantine Vault Hub (`QuarantineTab`):** Responsive table with horizontal overflow support, displaying original path, quarantine filename, isolation date, file size, and SHA-256 hash, with 1-click instant file restoration and permanent vault deletion.

---

## 7. Software Intelligence & Curated CVE Advisory Database

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Most website hacks don't happen because someone guessed your password; they happen because an old plugin had a known security flaw (called a CVE). This feature checks all your installed plugins and themes against a live database of known security vulnerabilities. It tells you in plain language: "Plugin X has a critical flaw that allows hackers to view your database. Please update it to version 2.1 or newer immediately," along with a direct button to update it.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Curated CVE Advisory Database:** Scans installed WordPress core, active/inactive plugins, and themes against an offline-resilient vulnerability database.
- **Granular Vulnerability Metadata:** Displays official Common Vulnerabilities and Exposures identifiers (e.g., `CVE-2024-XXXX`), standardized CVSS risk ratings (0.0 to 10.0), affected versions, patched versions, and direct links to official NIST NVD advisories.
- **Interactive Vulnerabilities Management Hub:** Filter by component type (Core, Plugins, Themes) or status (Vulnerable, Outdated, Clean). Includes 1-click update links to native WordPress update screens (`update-core.php`) and a detailed CVE forensic breakdown modal.

---

## 8. Living-off-the-Land (LotL) Runtime Hook Infiltration Sentinel

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Advanced hackers often don't save files on your disk. Instead, they inject malicious instructions directly into your server's active memory while WordPress is running. This allows them to secretly capture passwords whenever an administrator logs in. The Runtime Sentinel acts like a memory detective, scanning WordPress's internal memory hooks for any hidden, anonymous code listening to your login screens.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Active Runtime Memory Hook Audit:** Uses PHP Reflection to inspect active runtime hook callbacks registered in `$wp_filter` across sensitive WordPress lifecycle actions: `authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`.
- **Anonymous Closure & Credential Sniffer Detection:** Flags anonymous `Closure` functions attached to sensitive authentication hooks that could steal passwords.
- **External Rootkit & Uploads Hook Traps:** Detects hook callbacks originating outside WordPress root (server-level `auto_prepend_file` rootkits or PHP-FPM pool injections) and callbacks executing inside `wp-content/uploads/` (webshell callbacks).
- **Dangerous Native Function Registration Defense:** Detects dangerous native PHP functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`) attached directly as WordPress filter callbacks.

---

## 9. Database Micro-Anomaly & Rogue Administrator Trap

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Sometimes attackers secretly add a brand-new administrator account directly into your database behind your back, without WordPress ever sending you an email notification. This feature checks your database records every day, uncovering ghost admin accounts, hidden users with super-powers, or malicious code stored inside website options or blog posts.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Stealth User Infiltration Detection:** Audits `wp_users` against `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
- **Ghost & Orphaned Capability Hunting:** Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap:** Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe:** Recursively audits `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden in transients.

---

## 10. Web Application Firewall (WAF Lite) & Virtual Patching

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
A Web Application Firewall (WAF) is like a digital security guard standing at your website's front door. Before any visitor or automated bot is allowed to view your pages, the firewall inspects what they are sending. If someone tries to inject malicious computer code, steal your database, or break into your files, the firewall blocks them immediately with a "403 Forbidden" screen, keeping your site safe.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Real-Time Request Filtering:** Inspects incoming HTTP payloads at `plugins_loaded` (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
- **Attack Vector Shields:** Blocks SQL Injections (`UNION SELECT`, `information_schema`, `benchmark`), Cross-Site Scripting (XSS scripts/handlers), Path Traversal & LFI (`/etc/passwd`, `php://filter`), PHP code tag injections (`<?php`, `eval`, `base64_decode`, `system`), and XML-RPC exploitation.
- **Smart Shields & Verified Integrations Control Center:**
  - *Dedicated Reactive Whitelist Controls:* All smart rules are default **OFF** (zero unnecessary bypass surface). Automatically fingerprints active environments and renders intelligent recommendation banners.
  - *Targeted Allowlist Engine:* Combines User-Agent wildcard signatures, Target Endpoints, HTTP methods, verified IP/CIDR subnets, Reverse DNS domain validation with forward confirm (`rDNS`), Autonomous System Numbers (`ASN`), and Required Security/HMAC Signature Headers (`X-Shopify-Hmac-Sha256`, `Stripe-Signature`, `X-Square-Hmacsha256-Signature`).
  - *32 Verified Integration Presets:* Pre-engineered templates across E-Commerce, Payments, Shipping, Marketing & CRM, Membership & LMS, and Automation with 1-click batch setup.
  - *E-Commerce & Membership Smart Shield (34 Plugins):* Covers WooCommerce, Easy Digital Downloads, SureCart, GiveWP, MemberPress, Restrict Content Pro, ARMember, BuddyBoss, and more.
  - *Shopper & Member Cart Session Immunity:* Protects shoppers with active cart cookies against 404 lockouts while shopping.
  - *Visual Page Builder & Editor Smart Pass (20 Builders):* Natively recognizes Elementor, Divi, Beaver, Bricks, Breakdance, Oxygen, WPBakery, Avada, and Gutenberg FSE, validating capabilities to prevent false-positive blocks.
  - *Automattic Jetpack Sync Shield:* Enables verified Jetpack syncs hitting `xmlrpc.php` with official Automattic CIDR validation.
  - *Central WordPress Management Worker Pass:* Authenticates ManageWP, MainWP, and InfiniteWP sweeps when worker plugins are active.

---

## 11. Dedicated WAF Incident Logs, Threat Intelligence & Attack Forensics

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When attacks are blocked, this screen shows you full forensic proof of what happened. You can see the attacker's IP address, what country they came from, what malicious code they tried to inject, and the exact time it happened. You can search the logs easily or download clean reports to show your hosting company or IT director.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Full-Page Forensic Analytics Hub (`admin.php?page=wcp-scanner-waf-logs`):** Deep-linked directly from Firewall header actions and navigation bar.
- **Real-Time KPI Threat Metrics:** 4 live KPI cards displaying Total Incursions Blocked, 24h Attack Surge, Distinct Attack IPs, and Simulation/Learning Mode hits.
- **Threat Vector & Offender Analytics Grid:** Top Attack Vectors breakdown with proportional percentage bars and Frequent Offending Hostile IP Directory with hit counts and 1-click Filter/Block actions.
- **Multi-Field Forensic Search:** Real-time search across IP addresses, target URIs, malicious payload signatures, and User-Agents, combined with category, action, and HTTP method filters.
- **Expandable Forensic Deep-Dive Accordion:** Per-incident inspection view displaying rule trigger descriptions, raw User-Agent fingerprints, and syntax-highlighted malicious payload excerpts with 1-click JSON export.
- **Export & Forensics Reporting:** Download filtered incident records as CSV (`.csv`), raw JSON (`.json`), or formatted printable audit reports (`window.print()`).

---

## 12. Smart 404 Scanner Rate-Limiter & Reconnaissance Shield

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When automated hacker bots attack a WordPress website, they usually test hundreds of random web addresses (like `yoursite.com/secret.php` or `yoursite.com/admin-login.php`) within a few seconds looking for vulnerabilities. This feature catches them in the act: if an unknown bot causes multiple "Page Not Found" (404) errors in a short period, it locks them out automatically. Real human visitors and search engines like Google are never affected.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Automated 404 Scanner Lockouts:** Automatically isolates fuzzing and vulnerability scanning bots that trigger repetitive 404 errors across WordPress installations (default 10 probes in 60s trigger a 30-minute block).
- **DNS-Verified Search Engine Exemption:** Genuine search engines (Googlebot, Bingbot, DuckDuckBot, Yandex, Baidu, Yahoo) verified via Reverse DNS (PTR) + Forward DNS (A/AAAA) confirmation with 24h caching are strictly exempted to prevent search engine indexing drops or SEO penalties.
- **Static Asset & Media Exclusion:** Missing static assets (`.jpg`, `.png`, `.webp`, `.svg`, `.css`, `.js`, `.ico`, `.woff`, `.pdf`) are ignored from 404 tallies, completely preventing false-positive lockouts for legitimate human visitors.
- **High-Risk Reconnaissance Acceleration:** High-threat backdoor and sensitive file probes (`.env`, `.git`, `.bak`, `wp-config.php.bak`, `shell.php`, database dumps) advance the counter by 3 to swiftly isolate active exploit scanners.

---

## 13. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
If your website gets hit by a massive flood of hacker traffic, it can overwhelm your hosting server and make your site go down. Cloudflare is a free service that stands between the internet and your server. Our plugin gives you pre-made, 1-click security rules designed for Cloudflare's 100% free plan. It stops attacks in the cloud—before they ever reach your server—saving your server memory and bandwidth completely.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Zero-Resource Threat Interception:** Blocks malicious bots and automated exploits at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
- **3 Master Compound Rules (Free Plan Calibrated):**
  1. *Rule 1: Master Perimeter & Sensitive File Armor:* Blocks `/xmlrpc.php`, script execution in uploads/upgrade trees, sensitive dotfiles (`.env`, `.git`), and backup files in 1 unified Block rule.
  2. *Rule 2: LFI/RFI Directory Traversal & Reconnaissance Shield:* Terminates directory traversal (`../`, `etc/passwd`), code execution wrappers, `?author=` harvesting, and REST user scraping.
  3. *Rule 3: Intelligent Cloudflare Managed Challenge & Rate Limiting:* Challenges high-frequency automated scrapers and bad ASN traffic.
- **1-Click Sync & Cloudflare API Integration:** Synchronizes edge IP blocklists and firewall rules directly via Cloudflare API v4 tokens without requiring manual Cloudflare dashboard navigation.

---

## 14. Community Threat Intelligence & Botnet IP Blacklists

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Every day, thousands of malicious computers around the world are used to launch coordinated attacks against WordPress websites. Community Threat Intelligence allows your website to stay ahead of them. It downloads verified lists of known criminal and botnet IP addresses and blocks them before they even try to touch your site.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Automated Threat Feed Aggregation:** Periodically synchronizes verified malicious IP lists from leading cybersecurity feeds (including Spamhaus, FireHOL, Emerging Threats, and abuse.ch).
- **In-Memory Subnet Matching:** Evaluates incoming client IPs against compressed CIDR subnet lookup tables in RAM, executing in microseconds.
- **Custom Whitelist & Override Rules:** Allows administrators to permanently exempt trusted developer, office, or VPN IP addresses from community bans.

---

## 15. Active Session Sentinel & Anti-Hijack Defense

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
If a hacker steals an administrator's browser cookie (through a malicious browser extension or unsecured Wi-Fi), they could browse your WordPress dashboard without knowing your password. Active Session Sentinel monitors all logged-in administrator sessions. It shows you what device they are on, whether they used a secure Passkey or 2FA, their IP location, and gives you a 1-click button to immediately kick out any session that looks suspicious.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Multi-Factor & Passkey Authentication Tracking:** Enriched session token metadata with real-time authentication method detection (`passkey`, `2fa`, `magic_link`, `password`), device categorization (Desktop/Mobile/Tablet), idle activity formatting, and session lifespan countdowns.
- **High-Contrast Sentinel Metrics Bar:** Summary metrics strip displaying total active administrator sessions, Passkey Verified sessions, 2FA TOTP Protected sessions, Magic Support Links, and single-factor Password Only sessions.
- **Real-Time Risk & Sandboxing Notice Strips:** Contextual warning and info banners for single-factor administrator sessions, network IP shifts (ISP dynamic roaming), and Zero-Trust sandboxed temporary support technician sessions.
- **1-Click Remote Session Destruction:** Allows administrators to instantly terminate individual suspicious sessions or purge all remote sessions in one click via `wp_destroy_other_sessions()`.

---

## 16. Inline Expandable User Session Forensics & Real IP Tracking

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Ever wonder who is currently logged into your site and where they are connecting from? This feature provides an interactive, expandable view under every user account. You can click on any active session to see their browser type, operating system, last activity timestamp, and whether their IP address has changed since they logged in.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Inline Forensic Drawer (`.wcp-waf-expanded-row`):** Deep inspection accordion rendering full user session records, user-agent fingerprints, session duration, and expiration counters.
- **Accurate Real-IP Resolution:** Resolves real visitor IPs behind CDNs and reverse proxies (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`) with strict trusted proxy validation to prevent header spoofing.
- **Session IP Roaming Telemetry:** Highlights when a session switches IP addresses mid-lifecycle, alerting administrators to potential cookie hijacking or ISP mobile cell tower shifts.

---

## 17. Multi-Factor Authentication (2FA) & Login Hardening

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Passwords alone are no longer enough to protect your business. Multi-Factor Authentication (2FA) adds a second layer of security: when logging in, you simply enter a temporary 6-digit code from your phone's authenticator app (like Google Authenticator or 1Password). Even if a hacker steals your password, they cannot log into your website without this code.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Pure RFC 6238 TOTP Engine:** Implements native Time-Based One-Time Passwords without external third-party cloud services or API dependencies.
- **Encrypted Secret Storage:** All user 2FA secrets are encrypted at rest inside `wp_usermeta` using AES-256-GCM AEAD encryption.
- **QR Code Onboarding:** Renders client-side vector QR codes compatible with Google Authenticator, Microsoft Authenticator, 1Password, Authy, and Apple Keychain.
- **Cryptographic Emergency Recovery Codes:** Generates single-use hashed backup recovery codes for account access if a user loses their phone.
- **Brute-Force Protection:** Automatically locks user accounts after 5 consecutive incorrect TOTP code attempts.

---

## 18. WebAuthn Passwordless Biometric Login & Native Windows Hello Ceremony

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Imagine logging into your WordPress website the exact same way you unlock your smartphone: with your fingerprint, Face ID, or a Windows Hello PIN—with zero passwords to remember or type. WebAuthn allows you to register your computer or security key (like a YubiKey). When you visit your login page, you just tap "Sign in with Passkey", touch your sensor or enter your PIN, and you are logged in instantly. It is 100% immune to phishing.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Complete Native WebAuthn Ceremony (`WebAuthnManager.php`):** Implements the official W3C WebAuthn Level 3 protocol directly inside WordPress core login lifecycle (`wp-login.php`).
- **Native Windows Hello & Biometric Integration:** Connects the "Sign in with Passkey / Biometrics" login button to an asynchronous assertion handler hooked on `login_footer`. It fetches cryptographic challenge options from `/wcp-scanner/v1/auth/webauthn/login-options`, triggers `navigator.credentials.get()`, and launches the native platform authenticator (Windows Hello PIN/Fingerprint, Apple Touch ID/Face ID, Android Biometrics, or USB FIDO2 security keys).
- **Zero-Password Phishing Resistance:** Validates cryptographic client data JSON and authenticator signatures against public keys stored in `wp_usermeta` with replay-resistant counter verification.
- **Frictionless Session Cookie Issuance:** Upon successful verification at `/auth/webauthn/login-verify`, generates secure WordPress authentication cookies and automatically redirects the user into the admin dashboard.

---

## 19. Dedicated Notification Center & Granular 32+ Event Alert Matrix

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When something important happens—like malware is detected, a new administrator is created, or an attack is blocked—you need to know right away. The Notification Center lets you choose exactly how you want to be notified: by Email, Slack, Discord, Microsoft Teams, or custom webhooks. You have complete control over which alerts you receive, so your inbox is never spammed with unimportant messages.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Granular 32+ Security Event Matrix:** Configurable alerts across Critical Malware Findings, Core File Alterations, Rogue Admin Account Injections, Brute-Force Lockouts, WAF Incursions, 2FA Status Changes, Database Injections, and Temporary Support Access Events.
- **Multi-Channel Dispatch Engine:** Native integrations for transactional Email (`wp_mail`), Slack incoming webhooks, Discord webhooks, Telegram bot alerts, Microsoft Teams, and Generic JSON Webhooks (Zapier, Make, n8n).
- **Asynchronous Non-Blocking Delivery:** Batches and queues outgoing notifications via background cron jobs to prevent slowing down admin page loads or user checkout flows.
- **Payload Formatting & Rate-Limiting:** Formats messages with rich markdown, status embeds, and severity colors, with automatic deduplication rate-limiting to prevent alert storms during active attacks.

---

## 20. Enterprise HTTP Security Headers & 1-Click Site Hardening

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Web browsers have built-in security features that can protect your visitors from malicious scripts and clickjacking—if your website tells them to turn those features on. This feature adds industry-standard security instructions (called HTTP Headers) to your website with a single toggle. It prevents other websites from secretly embedding your pages in invisible frames and stops browsers from running dangerous, unverified scripts.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Enterprise Security Header Suite:**
  - `Content-Security-Policy (CSP)`: Configurable policy rules to restrict script execution origins and prevent XSS.
  - `X-Frame-Options: SAMEORIGIN`: Prevents clickjacking and unauthorized iframe embedding.
  - `X-Content-Type-Options: nosniff`: Enforces strict MIME-type sniffing defense.
  - `Strict-Transport-Security (HSTS)`: Enforces HTTPS connections with customizable max-age and preload directives.
  - `Referrer-Policy: strict-origin-when-cross-origin`: Protects sensitive URL query parameters from leaking to external referrers.
  - `Permissions-Policy`: Restricts browser hardware APIs (geolocation, camera, microphone) from unauthorized third-party scripts.
- **1-Click XML-RPC & User Enumeration Hardening:** Disables `/xmlrpc.php` and blocks author scanning queries (`/?author=1`) to prevent brute-force attacks and username discovery.

---

## 21. 1-Click WP_DEBUG & Sensitive Configuration Remediation Engine

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When web developers build or fix a website, they often turn on a developer setting called `WP_DEBUG`. If this setting is accidentally left turned on on a live website, it can display private technical details (like database errors, server file paths, and passwords) right on the screen for anyone to see. Our plugin checks for this issue and gives you a 1-click button that automatically and safely turns off debug mode without you needing to edit any code files.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Automated Configuration Remediation (`RemediationManager::disable_wp_debug`):** Safely parses and updates `wp-config.php` via REST endpoint `/remediation/disable-wp-debug`.
- **Atomic File Alteration with Syntax Tokenizer Validation:** Uses PHP's native `token_get_all()` parser to safely locate and update `WP_DEBUG`, `WP_DEBUG_LOG`, and `WP_DEBUG_DISPLAY` constants to `false` without syntax corruption.
- **Pre-Remediation Vault Backup:** Captures an encrypted safety backup snapshot of `wp-config.php` into the WCP Vault prior to modification.
- **OPcache Invalidation:** Immediately calls `opcache_invalidate()` on `wp-config.php` to guarantee the changes take effect immediately across all PHP worker processes.

---

## 22. Bot Recon Defense & AI Scraper Shield

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Unwanted bots, web scrapers, and aggressive AI crawlers constantly browse your website to steal your content, scrape your product prices, or search for weaknesses. This shield detects these automated bots and stops them. Crucially, it is smart enough to recognize genuine search engines like Google and Bing, ensuring that your real search engine rankings and traffic are always protected.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Behavioral Bot Detection:** Identifies headless browsers, automated Python/Go HTTP libraries, and known scraping signatures.
- **Cryptographic DNS Verification for Search Engines:** Verifies search engine crawlers (Googlebot, Bingbot, Yandex, Baidu, DuckDuckBot) using two-way Reverse DNS (PTR) + Forward DNS (A/AAAA) lookup with 24-hour transient caching.
- **Configurable AI Scraper Blocking:** 1-click toggles to block commercial AI training crawlers (GPTBot, ClaudeBot, CCBot, PerplexityBot, Bytespider) via header responses and virtual `robots.txt` disallow rules.

---

## 23. Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When the scanner finds suspicious code, you might not know whether it is safe or harmful. AI Code Forensics allows you to ask top AI models (OpenAI ChatGPT, Google Gemini, or Anthropic Claude) to analyze the suspicious code for you. The AI reviews the code in seconds and explains in simple English: "This code is a dangerous backdoor that lets attackers upload files to your server," along with recommended action steps.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Direct Multi-Provider SDK Integration (`AIService.php`):** Supports direct REST communication with OpenAI (`gpt-4o`, `gpt-4o-mini`), Google Gemini (`gemini-1.5-pro`, `gemini-1.5-flash`), and Anthropic Claude (`claude-3-5-sonnet`).
- **Encrypted Key Storage:** All third-party AI API keys are encrypted at rest using AES-256-GCM AEAD encryption inside the Secret Vault.
- **Privacy & Code Redaction:** Automatically scrubs database credentials, site URLs, salts, and private user information before sending code snippets to AI analysis endpoints.
- **Structured Threat Output:** Formats AI forensic responses with vulnerability summaries, exploit severity scores, potential impact analysis, and exact remediation instructions.

---

## 24. Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Model Context Protocol (MCP) is the cutting-edge standard that allows modern AI developer assistants (like Claude Desktop or Cursor) to safely connect to your website. If you work with an AI assistant, it can run scans, check security status, or review logs on your website directly through a secure, permission-controlled channel.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Official MCP JSON-RPC 2.0 Compliance (`MCPAgentService.php`):** Implements an agentic server endpoint at `/wp-json/wcp-scanner/v1/mcp` accepting JSON-RPC 2.0 tool discovery and execution requests.
- **Full Tool Suite:** Exposes structured security tools: `wcp_get_security_posture`, `wcp_list_findings`, `wcp_trigger_scan`, `wcp_quarantine_file`, and `wcp_whitelist_finding`.
- **Strict Read-Only Default Governance:** Defaults `mcp_permission_scope` to `'read_only'`, strictly forbidding mutating operations (quarantine, file edits, user changes) unless an administrator explicitly elevates permissions in settings.
- **Sliding-Window Rate Limiting & Ring-Buffer Audit:** Per-token rate-limiter (30–300 req/min) and persistent 150-event ring-buffer execution log (`wcpscan_mcp_audit_log`) recording tool calls, timestamps, client IPs, and durations.

---

## 25. Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Most WordPress plugins save your third-party API keys, webhook addresses, and passwords in plain text inside your database. If anyone gets access to a database backup, all your private keys are exposed. Our Cryptographic Secret Vault locks all your sensitive keys using the exact same military-grade encryption used by global banks (AES-256-GCM). Even if someone steals your entire database, they cannot read your secrets.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Pure AES-256-GCM Authenticated Encryption (AEAD):** Encrypts all sensitive credentials (webhooks, Cloudflare tokens, AI keys, 2FA TOTP secrets) before writing to `wp_options`.
- **128-bit Integrity Authentication Tags & Random IVs:** Generates unique 12-byte initialization vectors (`random_bytes(12)`) per record with 128-bit authentication tags, eliminating ciphertext malleability and CBC padding oracle vulnerabilities.
- **Strict Fail-Closed Decryption:** Tampered or corrupted ciphertexts fail immediately with `\RuntimeException`, preventing execution on tainted credentials.
- **Two-Phase Commit Key Rotation Orchestrator (`VaultRotator`):** Zero-downtime state machine (`idle` → `preparing` → `migrating` → `verifying` → `committed`) with dual-key background decrypt fallback and atomic snapshot rollbacks (`wcp_vault_backup_{id}`).
- **Dynamic 256-bit Key Derivation:** Prioritizes server environment variable `WCP_VAULT_KEY` &rarr; `WCP_VAULT_KEY` constant in `wp-config.php` &rarr; SHA-256 hash of core WordPress salts.

---

## 26. Unified WCP Vault Console (4 Consolidated Isolation & Recovery Facilities)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
The WCP Vault Console is a centralized emergency center that brings together all your backups, quarantined files, and encryption controls in one clean interface. If you ever need to restore a quarantined file, download a database backup, or undo an auto-cure repair, you can do it all right here with one click.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Centralized Security Vault Page (`wcp-vault`):** Unified administrative console consolidating 4 security facilities with real-time status telemetry and deep-linking:
  - *Facility 1 — File Quarantine Isolation Vault:* Inspect, restore, or permanently purge quarantined threats.
  - *Facility 2 — Database Snapshot & Point-in-Time Recovery Vault:* On-demand Gzip-compressed `.sql.gz` database dumps.
  - *Facility 3 — Pre-Cure Safety Rollback & Remediation Vault:* Inspect safety diffs and restore modified files prior to remediation.
  - *Facility 4 — Secret & Cryptographic Key Vault:* AES-256-GCM encryption health metrics, key rotation, and diagnostic resets.

---

## 27. On-Demand Database Backup Vault (`.sql.gz`)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Before making major updates or cleaning up malware, you should always back up your database. This feature gives you a 1-click button to create an instant, compressed database backup file (`.sql.gz`). It is stored securely on your server where strangers cannot download it, and you can download a copy to your computer whenever you want.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **1-Click Compressed Database Vault:** Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression.
- **Secure File Storage:** Stored in protected vault directory guarded by `.htaccess` and `index.php` with direct secure browser streaming downloads.
- **Index Metadata:** Tracks backup filename, creation timestamp, byte-accurate file size, and SHA-256 integrity hash.

---

## 28. High-Precision Microsecond Telemetry & Diagnostics

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Have you ever wondered how much server memory a security plugin is using or how long a scan took? Our diagnostics page gives you exact, transparent numbers: scan duration down to the millisecond, PHP memory usage, server software versions, and a complete history of past scans so you can verify that your server is running fast and healthy.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Microsecond Scan Duration Tracking:** Database schema upgraded with `started_at` (`datetime(3)`), `completed_at` (`datetime(3)`), and `duration_ms` (`int(11)`), capturing exact microtime without timestamp truncation.
- **Real-Time Environment Diagnostics:** Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`), MySQL collation, database size, and OS architecture.
- **Scan Logs & History:** Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

---

## 29. Behavioral Baseline & Attack Chain Correlation

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Hackers rarely launch an attack in a single step. Typically, they start with a failed login, upload a hidden backdoor, and then schedule a rogue task to keep their access. Attack Chain Correlation connects these separate clues like a detective solving a case, showing you a clear timeline of how the attack started and what areas were affected.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Behavioral Drift Detection:** Tracks alterations in critical site metadata, administrator counts, PHP execution options, and file counts against historic baselines.
- **Attack Chain Timeline:** Correlates disparate security events (failed login brute-force → backdoor upload → cron modification) into a unified chronological breach narrative with estimated blast radius scoring.

---

## 30. Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Sometimes a custom script that you or your developer wrote gets flagged by the scanner as suspicious, even though you know it is safe. With one click, you can mark it as safe. What makes our system special is that it remembers the exact cryptographic fingerprint of that file: if a hacker ever secretly changes or infects that file later, the plugin will immediately notice and alert you again.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **1-Click Intelligent Suppression:** Instantly suppress known false-positives with a single click. Automatically computes SHA-256 cryptographic checksums of the target file to lock the rule to that exact file version, with a 90-day auto-review safety period.
- **Collapsible Power-User Drawer:** Advanced controls to customize rule match types (Exact SHA-256 Hash vs File Path vs Pattern Signature), adjust expiration periods (30 days, 90 days, 1 year, or Permanent), and log administrative audit rationale.
- **Segmented Findings Status Filtering:** Instantly toggle between **Active Threats**, **Whitelisted / Ignored**, and **All Findings** with dynamic count badges.

---

## 31. Zero-Trust Must-Use (MU) Guardian & Sandboxed Temporary Support Access

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When you hire an external freelance developer or theme support agent to fix an issue on your website, you often have to give them administrator access. But what if they accidentally deactivate your security plugin, install a dangerous plugin, or edit your database? Our Zero-Trust Support Access allows you to generate a temporary, expiring "magic link" for the technician. While they work, our Must-Use Guardian locks down the doors: they cannot disable WCP Security Scanner, cannot see your secret API keys, cannot install unapproved plugins, and cannot edit other administrator accounts. When their time is up, their access vanishes automatically.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Inviolable Must-Use Guardian (`WcpJitMuGuardian.php`):** Deployed as an infallible Must-Use plugin (`wp-content/mu-plugins/wcp-jit-guardian.php`) executing at earliest bootstrap (`muplugins_loaded`) that cannot be deactivated or deleted via the WordPress admin UI.
- **Inviolable Anti-Tamper Shield:** Strictly prohibits temporary support technicians and JIT administrators from deactivating, deleting, or modifying WCP Security Scanner, immediately aborting attempts with a 403 Forbidden intercept.
- **Anti-Sub-Account & Delegation Lockdown:** Strictly prohibits temporary technicians from creating new temporary support accounts, inspecting active magic login links, or revoking existing credentials, shutting down privilege escalation vectors.
- **Plugin & Theme Installation Lockdown:** Intercepts `plugin-install.php`, `theme-install.php`, `update.php` package uploads, core REST endpoints (`/wp/v2/plugins`, `/wp/v2/themes`), and AJAX installer actions (`install-plugin`, `upload-plugin`, `install-theme`, `upload-theme`).
- **Database & Core Options Protection:** Blocks direct navigation to `wp-admin/options.php` with an immediate 403 exit, restricts `options-*.php` core settings screens, filters `pre_update_option` on critical options (`siteurl`, `home`, `admin_email`, `active_plugins`, `wcpscan_*`), and rejects database row modification endpoints (`/database/*`, `/remediation/*`).
- **Anti-Account Hijacking & Persistence Defense:** Hooks `wp_pre_insert_user_data` to forbid temporary technicians from modifying other user accounts or changing their own username, email, or password to establish unauthorized persistence.
- **Secret Vault Redaction:** Redacts sensitive API tokens (Cloudflare, AI keys, MCP tokens, webhooks, SMTP credentials) in `/settings` responses for temporary sessions.
- **Plugin Settings Read-Only Enforcement:** Forbids settings reset (`/settings/reset`), import (`/settings/import`), and configuration updates, rendering a locked "Reset Defaults (Locked)" button with a Lock icon and contextual Zero-Trust session notices in `SettingsPage.tsx`.
- **Configurable Zero-Trust Sandboxing Shields:** Added granular policy toggles in `TemporarySupportAccessCard.tsx` covering plugin deactivation, package installation, file editors, user administration, secret vault, database/options protection, tools/exports restriction, forensic remediation lock, and settings lock.
- **Infallible Auto-Termination:** On every request, expired sessions are pruned and active user tokens destroyed; if WCP Security Scanner is ever deactivated, all temporary support sessions are instantly revoked.

---

## 32. Preload Micro-WAF & Early Execution Engine (Linux Fail2ban & CrowdSec Syslog)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Normally, WordPress plugins only run after WordPress loads its core files and connects to your database. But what if a massive attack is hitting your site? Loading WordPress on every attack attempt can slow down your entire server. The Preload Micro-WAF runs at the very first millisecond of PHP execution—before WordPress boots and before MySQL is contacted. It drops malicious attacks instantly with almost zero server load, and writes the attacker's IP to a log file so your server firewall (Fail2ban or CrowdSec) can ban them permanently.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Zero-Dependency Standalone Runtime (`MicroWafCompiler.php`):** Compiles WAF rules to OPcache-shared static PHP arrays (`micro-waf-compiled.php`), intercepting malicious requests in PHP's early request lifecycle via `auto_prepend_file` before WordPress core boots or database connections initialize.
- **Linux Fail2ban & CrowdSec Integration:** Automatically formats and appends early dropped requests to a standardized append-only syslog (`wp-content/uploads/wcp-security-scanner/waf-logs/fail2ban.log`), enabling instant kernel/network-level blocking via Linux Fail2ban jails and CrowdSec parsers.
- **Automatic Environment Detection & Safe Installer:** Detects server environment (PHP-FPM `.user.ini` vs Apache/LiteSpeed `.htaccess`) and safely injects/uninstalls `auto_prepend_file` directives with delimited marker comments.
- **Preload Micro-WAF Host Prepend Chaining:** Automatically detects pre-existing `auto_prepend_file` scripts (e.g. Wordfence or hosting runtime scripts) and chains execution so third-party tools are not clobbered or disabled.
- **Fail-Safe Architecture:** Features emergency query bypass tokens (`wcp_waf_bypass`) and `WCP_DISABLE_MICRO_WAF` constant support to prevent lockout scenarios.
- **Dedicated Preload Micro-WAF UI Cockpit:** High-contrast telemetry card in the Server Security tab (`ServerSecurityTab.tsx`) for 1-click Micro-WAF compilation, installation, detachment, OPcache memory status, and an interactive Linux Fail2ban / CrowdSec live syslog viewer.

---

## 33. JavaScript Threat Intelligence, Magecart Payment Skimmer & Beacon Detector

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
One of the most dangerous threats in e-commerce today is called a "Magecart" or credit card skimmer. Hackers inject a tiny, invisible piece of JavaScript into your checkout page that secretly copies your customers' credit card numbers and sends them to a hacker server while the customer is paying. Our JavaScript Scanner inspects all script files across your plugins and themes to detect payment skimmers, hidden crypto-currency miners, and unauthorized data-theft beacons.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Dedicated Client-Side Malware Engine (`JavaScriptSecurityScanner.php`):** Inspects static `.js` files across plugins, active themes, and root assets for client-side attack vectors without executing untrusted scripts.
- **Magecart Payment Skimmer Detection:** Detects event listeners (`addEventListener`, `attachEvent`, jQuery `.on`) interrogating credit card, CVV, expiry, billing fields, or input selectors correlated with network exfiltration calls (`fetch()`, `sendBeacon()`, `new Image()`, `XMLHttpRequest`).
- **Stealth Image Beacon & Webhook Exfiltration:** Flags unauthorized exfiltration pipelines utilizing dynamic image source mutations (`new Image().src = ... + btoa(...)`) and hardcoded exfiltration webhooks (Discord, Telegram bots, Pastebin API, Transfer.sh).
- **Heavy Obfuscation & Crypto-Miner Unpacking:** Targets Dean Edwards packers (`eval(function(p,a,c,k,e,d)...)`), JavaScript Obfuscator hex-encoded array rotation loops (`_0x...`), and browser-based cryptocurrency miners (`CoinHive`, `Cryptonight`, `WasmMiner`).
- **Core Integrity Checksum Bypass:** Automatically verifies `.js` files against official WordPress core checksums to eliminate false positives on core distribution scripts.

---

## 34. Third-Party Script Inventory & Frontend Hostname Drift Sentinel

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Websites often use external scripts for analytics, chat widgets, and ads. But if a plugin you use gets compromised, an attacker could load a malicious script from an unknown foreign website onto your checkout or login pages. This monitor keeps an inventory of all external domains that load scripts on your site. If an unexpected new domain suddenly appears, the plugin triggers an immediate alert so you can inspect it.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Passive Frontend Enqueue Telemetry (`ScriptInventoryMonitor.php`):** Intercepts `wp_print_footer_scripts` to monitor all dynamically enqueued scripts rendered on frontend requests across plugins and themes.
- **Sensitive Page Context Awareness:** Flags whether scripts are executing in sensitive transaction boundaries (WooCommerce checkout, cart, my-account, and WordPress login).
- **Hostname Baseline Calibration & Drift Alerting:** Allows administrators to calibrate an approved third-party domain baseline; any uncalibrated third-party hostname dynamically injected on the site generates an immediate high/critical drift alert and forensic audit log entry.

---

## 35. Offline Dependency Lockfile (Composer & npm) Supply-Chain Auditor

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Modern WordPress plugins are built using dozens of underlying code libraries (called packages or dependencies). If one of those libraries has a known vulnerability, your whole site can be at risk even if the plugin author didn't realize it. Our Supply-Chain Auditor inspects the library manifests (`composer.lock` and `package-lock.json`) inside all your plugins and warns you if any third-party library has a known security flaw—completely offline, without needing any complex developer tools installed on your server.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Offline SemVer Parser (`LockfileAuditEngine.php`):** Scans the entire WordPress installation for bundled `composer.lock` and `package-lock.json` manifests without requiring external Node.js, npm, or Composer binaries on production servers.
- **Bundled Security Advisory Database:** Compares resolved package versions against bundled high-profile CVE signatures (including PHPUnit RCE CVE-2017-9841, Guzzle SSRF CVE-2022-31090, Dompdf RCE CVE-2023-28849, Monolog Syslog injection CVE-2020-15094, Lodash prototype pollution CVE-2021-23337, and Axios SSRF CVE-2020-28168).
- **Manifest Anomaly & Transport Inspection:** Automatically detects insecure unencrypted transport protocols (`http://` or `git://`) and unpinned branch dependencies (`dev-master`).
- **Interactive Supply-Chain Cockpit (`SbomSupplyChainCard.tsx`):** Displays discovered lockfiles, checked packages tally, active CVE advisories, severity badges, anomaly tables, and 1-click on-demand manual audit triggers.

---

## 36. 2026 AI Threat Defense, Prompt-Injection Guard & Decoy Ghost Route Traps

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
As hackers begin using automated AI bots to probe websites, they look for hidden weaknesses or try to trick AI chat features into revealing private passwords. We protect your site with clever "Decoy Traps": invisible links and fake web addresses that real human visitors never see. If an automated hacker bot tries to explore these fake doors, the trap snaps shut: the bot is immediately blocked and banned before it can touch any of your real content.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Autonomous AI Pentest Bot & Decoy Canary Trap (`GhostRouteTrap.php`):** Injects invisible canary link tags into `wp_footer` and `login_footer` and provisions phantom REST honeypot routes (`/wcp-internal/v1/telemetry-debug`, `/wcp-core/v1/system-env`, `/wcp-admin/v1/database-dump`). Autonomous scrapers and aggressive vulnerability scanners accessing canaries are instantly intercepted with 403 Forbidden, tarpitted with artificial latency, blocked at client IP, and synchronized with Cloudflare Edge IP Lists.
- **Search Engine & Uptime Monitor Crawler Immunity:** Hardened with reverse-DNS crawler verification (`BotReconDefense::is_genuine_search_engine()`) so legitimate search engine bots (Googlebot, Bingbot, etc.) are never banned or pushed to Cloudflare Edge. Emitted `X-Robots-Tag: noindex, nofollow, noarchive` and virtual `robots.txt` disallow directives on canary routes.
- **WordPress 7.0+ AI Client & Prompt-Injection Guard (`PromptInjectionGuard.php`):** Proactively inspects user comments and incoming prompt vectors destined for LLM tools against prompt override attacks, DAN jailbreak patterns, secret extraction attempts (`.env`, `DB_PASSWORD`), and invisible Unicode tag character smuggling (`\x{E0000}`–`\x{E007F}`). Comments with detected prompt injections default to WordPress moderation hold (`comment_approved = 0`) instead of breaking user experience.

---

## 37. Outbound AI & SSRF Egress Firewall (Cloud Metadata & Exfiltration Shield)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
When malware infects a website, its first goal is usually to "phone home" to the hacker's server to send away your database or download more viruses. Most firewalls only inspect traffic coming into your site; our Outbound Egress Firewall also inspects traffic leaving your site. If a rogue plugin tries to send stolen data to an unauthorized destination (like a Telegram bot or cloud metadata address), the outbound request is instantly stopped.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Outbound HTTP Client Interception (`OutboundEgressFirewall.php`):** Hooks `pre_http_request` with deep stack backtrace inspection to identify calling plugins or themes before network socket dispatch.
- **Cloud Metadata & Private Network Shield:** Blocks Server-Side Request Forgery (SSRF) attempts targeting cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean, Oracle Cloud `169.254.169.254`, `127.0.0.1`, and private LAN CIDRs `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Data Exfiltration Conduit Blocking:** Terminates unauthorized outbound connections to known attacker exfiltration conduits (Discord webhooks, Telegram bots, Pastebin, Transfer.sh).
- **Pre-Approved WordPress Ecosystem APIs:** Pre-approves essential WordPress ecosystem APIs (WooCommerce Connect, Stripe, PayPal, transactional mailers SendGrid/Mailgun/Postmark/Brevo, Google Services, and GitHub updates) to eliminate false exfiltration triggers in monitor and enforce modes.

---

## 38. Plaintext Credential Exposure & Secret Leak Scanner (.env, Git, Keys)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Developers frequently create temporary configuration files (like `.env`, backup database dumps, or GitHub settings) that contain real passwords and API keys. If these files are left in your public website folder, anyone who knows their name can download them and read your passwords. This scanner searches your public folders for any exposed secret files and alerts you immediately so you can delete or protect them.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Automated Root & Uploads Audit (`CredentialExposureScanner.php`):** Rapidly audits root directory dotfiles (`.env`, `.git/config`), uploads folder, and active theme assets for hardcoded or exposed production secrets.
- **Secret Signature Coverage:** Scans for OpenAI API keys (`sk-proj-...`), Anthropic Claude keys, Google Gemini keys, Stripe Live secret keys (`sk_live_...`), AWS Access Key IDs (`AKIA...`), GitHub Personal Access Tokens (`ghp_...`), and private SSH / RSA keys (`BEGIN RSA PRIVATE KEY`).
- **Safe Administrative Masking:** Safely redacts and masks all discovered keys in administrative reports (e.g. `sk-proj-********...Ab3d`) to prevent secondary credential leakage in UI screenshots or support logs.

---

## 39. REST API & Public AJAX Attack Surface Inventory & User Enumeration Guard

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
WordPress has built-in web endpoints (the REST API and AJAX) that allow plugins to talk to other apps. However, poorly coded plugins sometimes leave these endpoints open to the public without checking who is calling them. This feature creates a complete visual inventory of every single public endpoint on your website. It highlights any endpoint that can modify data without a password and gives you a 1-click button to block attackers from scanning your list of usernames.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Automated Surface Discovery (`RestApiInventory.php`):** Automatically catalogs and maps all registered WordPress REST API endpoints and public unauthenticated AJAX actions (`wp_ajax_nopriv_*`).
- **Write Vector Identification:** Flags unauthenticated mutating endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) across third-party namespaces that could represent unauthorized backdoor endpoints or vulnerable form handlers.
- **1-Click User Enumeration Defense:** Automatically intercepts and terminates requests targeting `/wp/v2/users` or `/?rest_route=/wp/v2/users` for unauthenticated visitors, returning an empty array or 403 Forbidden to prevent username harvesting for brute-force attacks.

---

## 40. 72-Hour Post-Remediation Reinfection Watchdog & Surveillance Vault

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Have you ever cleaned malware from a WordPress site, only for the exact same hacked file to reappear a few hours later? That happens because malware often leaves behind a hidden "resurrection dropper" or cron job. The Reinfection Watchdog keeps active 24/7 surveillance over any file you cleaned or quarantined for 72 full hours. If a deleted backdoor tries to resurrect itself, the watchdog immediately grabs it, locks it in the quarantine vault, and alerts you instantly.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Automated Surveillance Enlistment (`ReinfectionWatchdog.php`):** Automatically registers quarantined or remediated threat files into high-frequency surveillance tracking (`wcpscan_reinfection_watchdog` option) hooked into `wcpscan_file_quarantined`.
- **Hourly Automated Cron Verification:** Runs an hourly cron `wcpscan_reinfection_hourly_check` continuously monitoring remediated paths across a 72-hour threat window, verifying whether deleted backdoors reappear or disinfected files undergo hash drift.
- **Zero-Breakage Persistence Vault:** Quarantines resurrected files immediately into the secure vault without resorting to rigid directory permission freezes (`chmod 0555`), guaranteeing that legitimate media uploads and caching engines continue working smoothly.
- **Interactive Watchdog Console:** Provides administrators with 1-click manual verification triggers, active watch lists, reinfection incident logs, and resolution management.

---

## 41. "Time-Machine" Local File & Bespoke Asset Snapshot Baseline Engine

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Official plugins from WordPress.org can easily be checked against official copies. But what about custom-built themes, private client plugins, or paid premium extensions that aren't on WordPress.org? The "Time-Machine" Baseline Engine lets you take a snapshot of your custom code when you know it is clean. If someone later tampers with your theme or injects malicious code, you can view the exact differences side-by-side and restore your clean files with one click.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Bespoke Asset Baseline Archives (`LocalSnapshotManager.php`):** Captures compressed, read-only baseline snapshots (`.gz`) of custom client themes, bespoke plugins, and premium extensions stored in hardened directory `wp-content/uploads/wcp-security-scanner/snapshots/` protected by `.htaccess` and `index.php`.
- **Visual Myers Diff Inspection:** Calculates side-by-side file comparisons with diff metrics (lines added/removed/modified) and content previews against verified snapshots to detect tampering, supply-chain adulteration, or unauthorized edits.
- **1-Click Atomic Restoration:** Supports 1-click atomic restoration of modified or injected files back to clean baseline state using native WordPress filesystem abstractions with fallback handling.

---

## 42. Automated Blacklist, Domain Reputation & DNSBL Early-Warning Sentinel

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
If a website gets hacked, it can end up on global spam blacklists or have its Google search rankings destroyed before the owner even notices. The Domain Reputation Sentinel runs an automatic check every day. It checks your domain against major security blacklists, checks your SSL security certificate so it doesn't expire by surprise, and audits your email security records (SPF and DMARC) to keep your emails out of the spam folder.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Daily Automated Reputation Audit (`DomainReputationMonitor.php`):** Runs daily cron `wcpscan_domain_reputation_daily_check` auditing site domain reputation, SSL certificate health, email authentication records, and DNSBL listings.
- **SSL Certificate Expiration & Peer Verification:** Inspects TLS peer certificate validity, subject alternative names (SANs), and calculates exact days remaining before expiration.
- **DNSBL Multi-List Querying:** Queries leading spam and reputation blacklists (Spamhaus Zen/DBL, Barracuda, SpamCop, SURBL) to alert administrators before domain blacklisting impacts traffic or search engine rankings.
- **Email Hygiene & Authentication Records:** Audits domain SPF (`v=spf1`) and DMARC (`_dmarc`) DNS records to identify spoofing vulnerabilities and email deliverability risks.

---

## 43. Unified 5-Tier Threat Correlation Engine & Attack Kill-Chain Forensics

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Security logs can be confusing when there are thousands of lines of data. The Threat Correlation Engine organizes all your security data into 5 clear tiers: from basic facts (like an IP address that visited your site) all the way up to an Attack Story (explaining how someone tried to brute-force a login, upload a file, and edit your database). This gives you a crystal-clear understanding of what happened and how to fix it.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **5-Tier Telemetry Hierarchy (`CorrelationEngine.php`):** Synthesizes disparate signals across Filesystem, Database, WAF, Identity, and Network into 5 structured intelligence tiers:
  - *Tier 1 — Concrete Observed Facts:* Raw file modifications, 404 spikes, blocked IPs, failed logins.
  - *Tier 2 — Contextualized Threat Indicators:* Known webshell signatures, suspicious file extensions in uploads.
  - *Tier 3 — Multi-Signal Temporal Correlations:* Correlated signals occurring within identical time windows from identical IPs.
  - *Tier 4 — Attack Kill-Chain Hypotheses:* Coordinated attack sequences (Brute-Force &rarr; Backdoor Injection &rarr; Persistence).
  - *Tier 5 — Actionable Containment Outcomes:* 1-click surgical containment recommendations with blast radius scoring.
- **Interactive Telemetry Navigator (`ThreatCorrelationHierarchyCard.tsx`):** High-contrast interactive correlation console under Forensics with filter chips, kill-chain timeline visualizations, and 1-click remediation actions.

---

## 44. 1-Click Panic Button Emergency Site Lockdown & Containment Protocol

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
If your website is under an active, aggressive cyberattack or DDoS flood, you don't have time to configure complex settings. The red "Panic Button" in the top header is your digital emergency brake. With a single click, it locks down your site: it turns on Cloudflare Under-Attack defense to challenge all traffic in the cloud, freezes outbound connections to stop hackers from stealing data, and creates an instant backup of recent files so you have full evidence for investigation.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **1-Click Header Panic Button (`EmergencyContainmentManager.php`):** Prominently integrated into the top global header navigation bar for instant emergency incident containment.
- **Cloudflare Under-Attack Offload:** Synchronizes containment activation directly to Cloudflare Free-Tier API tokens, activating Under-Attack Mode / Turnstile challenge pages to deflect volumetric DDoS and automated bots at the global edge.
- **Outbound HTTP Egress Freeze:** Integrates with `OutboundEgressFirewall` to intercept and drop all external HTTP requests originating from core, plugins, or themes to prevent attacker reverse shells, C2 beaconing, or data exfiltration during active containment.
- **Automatic 72-Hour Forensic Snapshot:** Captures an immediate compressed baseline archive of all files modified in the preceding 72 hours before lockdown to preserve volatile incident evidence.

---

## 45. Global Command Center & All Modules Mega-Menu (Ctrl+K Navigation)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
With dozens of powerful security features, you want navigation to be effortless. You can click the "All Modules" menu or press `Ctrl + K` (or `Cmd + K` on a Mac) on your keyboard at any time. A sleek command center pops up instantly, letting you type what you are looking for (like "firewall", "quarantine", or "backups") and jump straight to that feature in a fraction of a second.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Comprehensive Navigation Matrix (`MegaMenuModal.tsx`):** Categorizes all 13 core security pillars (Scanner, Vulnerabilities, Hardening, WAF, Edge, Backups, Supply Chain, File Integrity, Identity, Audit, Server, Live Traffic, System Config).
- **Instant Search & Direct Sub-Tab Jumps:** Real-time filter input and keyboard shortcut triggers (`Ctrl+K` / `Cmd+K`) for rapid module hopping and deep sub-tab switching.
- **WCAG AAA Theme-Adaptive Visuals:** Fully styled and tuned for WCAG AAA contrast across both High-Contrast Light/White Mode and Obsidian Dark Mode.

---

## 46. Zero-Allocation Streaming Session Queue & Microsecond Disk Cursor

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Many WordPress security plugins crash or slow down websites because they try to load lists of 50,000 files into your server's memory all at once. Our Zero-Allocation Streaming Queue stores the scanning list directly on disk in a private, protected session file. The scanner moves through the file in tiny, lightning-fast batches, using less than 2 megabytes of RAM regardless of how huge your website is.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Ephemeral Stream Queue Storage (`ScanQueueManager.php`):** Eliminates massive PHP array memory allocations and MySQL `wp_options` transient bloat by streaming discovered files directly into private line-delimited session files (`wp-content/uploads/wcp-security-scanner/scan-sessions/{scan_id}/queue.txt`) protected by `.htaccess` and `index.php`.
- **Instant Microsecond Batch Seeking:** Replaces expensive `unserialize()` and `array_splice()` operations with O(1) atomic `fseek()` cursor offsets and byte tracking, reducing batch retrieval latency from seconds to <5ms on 50,000+ file sites.
- **Constant-Memory Recursive Directory Traversal:** Utilizes `RecursiveIteratorIterator` to pipe file paths directly to the disk stream writer callback without accumulating memory, maintaining flat ~2MB RAM consumption regardless of website size.
- **Automated Ephemeral Cleanup:** Automatic lifecycle cleanup for completed or aborted scans and stale sessions older than 2 hours.

---

## 47. Host Antivirus Immunity & Heuristic Engine Resilience (CPGuard / Imunify360 Bypass Defense)

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Web hosting companies run server-level antivirus tools (like Imunify360 or CPGuard). Paradoxically, when a security plugin includes samples of malware signatures to search for, the host antivirus sometimes mistakes the security plugin itself for a virus and deletes parts of it! Our engine uses "Dynamic Token Assembly" to build its search patterns in memory only when needed, ensuring hosting antivirus tools never mistakenly quarantine your scanner.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Dynamic Runtime Token Assembly:** Completely eliminated static decompressor and unpacker signatures (such as raw gzinflate/base64_decode pairings, static rot13 character maps, and hex escape patterns) that triggered aggressive false-positive quarantine by server-level security daemons like CPGuard, Imunify360, and ClamAV.
- **Fault-Tolerant Engine Instantiation:** Hardened `HeuristicEngine` and `FileScanner` with file existence verification and defensive exception boundaries, guaranteeing that if any sub-detector is ever quarantined or blocked by third-party hosting tools, the scanner continues its audit gracefully without throwing a fatal 500 batch error.

---

## 48. Data Privacy, Safety Policies & Clean Uninstall Lifecycle

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Your privacy is sacred. WCP Security Scanner runs 100% locally on your own server. It never sends your visitor data, files, or browsing habits to any outside servers or third parties. Furthermore, if you ever decide to uninstall the plugin, it completely cleans up after itself—removing all custom database tables, settings, and temporary files so your website remains completely clean and clutter-free.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Non-Destructive Operations:** All Auto-Cure, Quarantine, and Remediation operations create automated pre-action safety snapshots in the local backup vault before modifying files on disk.
- **Zero Tracking or Telemetry:** The plugin does NOT track, collect, store, or sell any personal data, analytics, or browsing habits.
- **100% On-Premise Execution:** Scans, heuristic checks, file integrity monitoring, brute-force defenses, 2FA generation, and firewall evaluation run 100% locally within your PHP environment.
- **Clean 6-Table Database Purge on Uninstall (`uninstall.php`):** When "Auto-Remove All Data on Uninstall" is active (default), deleting the plugin automatically drops all 6 custom database tables (`wcpscan_scans`, `wcpscan_scan_issues`, `wcpscan_scan_files`, `wcpscan_quarantine`, `wcpscan_firewall_logs`, `wcpscan_login_history`), purges user meta, clears transients, deletes options, removes crons, and purges upload storage folders.

---
## 49. CrashGuard Zero-Downtime Circuit Breaker & Safe Mode Self-Preservation

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Security tools must never be the reason your website crashes or shows "There has been a critical error on this website". CrashGuard is a built-in safety net and circuit breaker engineered by Mir Alamin. If any unexpected PHP error, memory spike, or third-party conflict ever occurs inside the plugin, CrashGuard instantly isolates the issue into "Safe Mode". Your website, store, themes, and admin dashboard remain 100% online and accessible while a helpful recovery notice appears in your admin area with 1-click self-healing.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Top-Level Bootstrap Guard (`CrashGuard::shield_bootstrap()`):** Wraps all heavy plugin initialization, WAF hooks, and routing controllers inside an early defensive `try/catch (\Throwable $e)` envelope.
- **Early Scoped Shutdown Interceptor (`CrashGuard::handle_fatal_shutdown()`):** Registers a shutdown handler before heavy includes load. Catches low-level fatal errors (`E_ERROR`, `E_PARSE`, `E_CORE_ERROR`, `E_COMPILE_ERROR`), verifies whether the offending file resides within the plugin directory (`str_starts_with`), and activates Safe Mode without crashing the host PHP execution pool.
- **Sliding-Window Multi-Strike Circuit Breaker:** Employs a sliding-window strike limiter requiring 3 consecutive fatal crashes within a 5-minute (300-second) window before triggering safe deactivation, preventing transient server glitches from disabling security indefinitely.
- **Micro-WAF Preload Shield:** Includes a standalone defensive `try/catch` guard directly inside compiled `auto_prepend_file` templates (`MicroWafCompiler.php`), guaranteeing early pre-WordPress inspection never aborts the request before core boots.
- **Zero-Friction 1-Click Recovery:** Sticky admin notice displays file, line, and timestamp incident forensics with 1-click incident clearing (`wcpscan_reset_crashguard`) and safe deactivation routes.

---

## 50. Pre-Install Supply-Chain Gatekeeper & Update Risk Advisor

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Many WordPress hacks happen when an otherwise legitimate plugin you already use gets compromised or bought out and pushes a malicious update. The Pre-Install Gatekeeper acts like a customs inspector: whenever an update is downloaded, it unpacks and inspects the new code in an isolated sandbox *before* it overwrites your live files. If suspicious backdoors or malicious payloads are found, the update is blocked, your live site is protected, and you receive an immediate alert.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Upgrader Pipeline Interception (`UpdateGatekeeperEngine.php`):** Hooks into WordPress native `upgrader_source_selection` and `upgrader_pre_install` filters to quarantine extracted update archives before filesystem replacement.
- **Shift-Left Heuristic Static Analysis:** Recursively inspects unpacked files against AST-level heuristics (`eval`, variable function execution, hex obfuscation, base64 payloads, socket connects, unauthorized administrative user creation).
- **Automated Pre-Update Snapshots & Instant Rollback:** Creates an isolated, timestamped snapshot of the existing plugin directory in the WCP Vault prior to applying any update. If an update exhibits post-installation anomalies, a single click restores the verified snapshot.
- **Multi-Attribute Threat Scoring:** Computes a composite risk score (0-100) per update. Updates exceeding the critical risk threshold (Score >= 70) are rejected with a detailed `WP_Error` and recorded in security audit logs.

---

## 51. Zero-SQL Partitioned WAF Incident Filesystem Engine

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Under high-volume bot attacks or brute-force scans, writing thousands of incident logs into your WordPress database can quickly slow down or crash your server. WCP Security Scanner includes a Zero-SQL Filesystem Logging Engine that writes blocked attacks into lightweight, daily compressed log files on your server. This gives you detailed forensic logs with zero database load.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **High-Performance Filesystem Appending (`WafFileLogger.php`):** Blocked HTTP requests and WAF telemetry are streamed directly to partitioned daily JSON Lines logs (`wp-content/uploads/wcp-scanner-quarantine/waf-logs/waf-YYYY-MM-DD.json.gz` or `.log`) using atomic append operations (`LOCK_EX`).
- **Zero Database Load Under Attack:** Deflects thousands of malicious probes, SQL injection fuzzers, and botnet scrapers without issuing single `INSERT` or `UPDATE` queries to MySQL/MariaDB.
- **Fail2ban & CrowdSec Native Ingestion:** Generates standardized syslog-compatible records directly ingestible by host-level intrusion prevention engines (`fail2ban`, `crowdsec`, `auditd`).
- **Automated Retention & Microsecond Retrieval:** Automatically purges logs beyond the administrator's configured retention window (default 30 days) and streams forensic views directly into the WAF Incident Logs UI.

---

## 52. Enterprise Granular Notification Center & DevSecOps Webhooks

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Stay informed about critical security events in real time without being spammed. The Notification Center lets you choose exactly which events trigger alerts—from blocked botnet attacks and rogue admin creation to FIDO2 passkey enrollment—and choose how you want to be notified (Email, Slack, Discord, ClickUp, Asana, or custom webhooks).

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **Granular 59-Event Security Catalog (`NotificationDispatcher.php`):** Dispatches structured alerts across 10 security categories: Malware Findings, File Integrity (FIM), WAF Incidents, Supply-Chain & SBOM, Authentication & Sessions, WebAuthn Passkeys, System Forensics, Secrets Vault, and Emergency Containment.
- **Multi-Channel Dispatch Matrix:** Independent toggles per event for WordPress Core Email (`wp_mail`), Slack Incoming Webhooks, Discord Webhook Embeds, ClickUp Automation API, Asana Task API, and Generic DevSecOps JSON Webhooks (Zapier, Make, n8n).
- **Cryptographic Webhook Secret Isolation:** All webhook URLs and channel API keys are encrypted at rest with AES-256-GCM authenticated encryption in the WCP Vault.
- **Interactive UI with Instant Search & Test Triggers:** Dedicated full-page notification console (`?page=wcp-scanner-notifications`) featuring category filtering, live channel status indicators, and 1-click test dispatches.

---

## 53. Turbo Scan Engine Optimization, In-Memory Caching & Bulk Ingestion

### 💡 Plain-English Overview (For Everyone & Non-Tech Users)
Scanning tens of thousands of files on a busy WordPress website can often cause server timeouts or high CPU usage. The Turbo Scan Engine optimizes the file inspection pipeline to achieve blazing-fast speeds (over 300 files per second) while using minimal server memory, ensuring complete site audits finish in seconds without interrupting your visitors.

### ⚙️ Deep Technical Details & Architecture (For Developers & Engineers)
- **In-Memory & Negative Checksum Caching (`ChecksumProvider.php`):** Caches official WordPress.org checksums in static PHP runtime memory (`self::$plugin_checksums_memory`, `self::$theme_checksums_memory`) and caches 404/not_found responses for 6 hours as negative transients. Completely eliminates redundant, blocking HTTP calls to downloads.wordpress.org for custom, proprietary, or unmanaged plugins.
- **Non-Production & Test Suite Pruning (`Engine.php`):** Automatically excludes developer test folders (`tests/`, `spec/`, `phpunit/`, `.github/`, `docs/`, `fixtures/`, `.vscode/`) and non-executable documentation files (`.txt`) from the scannable queue, cutting unnecessary file inspection by up to 80%.
- **High-Throughput Atomic Bulk SQL Ingestion (`ScannerRoutes.php`):** Replaces single-row `INSERT` queries with batched multi-row SQL insertion during file queue staging, increasing ingestion throughput from 1.6 files/sec to over 320 files/sec.
- **Adaptive Execution Budget & Heartbeat Guard:** Microsecond resource governor yields batch execution at safe time thresholds (18 seconds per batch) while pulsing lock heartbeats, preventing PHP timeout crashes on shared and enterprise hosting alike.

---


## 👨‍💻 Author & Engineering

**WCP Security Scanner** is designed and engineered by **Mir Alamin** ([WebCare Pro](https://webcarespro.com)):
- **Upwork:** [Mir Alamin on Upwork](https://www.upwork.com/freelancers/~0162afa9a578170c67) — Top Rated Plus Freelancer, 100% Job Success Score
- **Website:** [https://webcarespro.com](https://webcarespro.com)
- **Direct Email:** [hello@webcarespro.com](mailto:hello@webcarespro.com)
- **WhatsApp:** [+880 1322 691090](https://wa.me/8801322691090)
