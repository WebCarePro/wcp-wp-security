# WCP Security Scanner

<p align="center">
  <img src="https://webcarespro.com/icon-192.png" alt="WebCare Pro Logo" width="180" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>Enterprise-Grade WordPress Malware Detection, Web Application Firewall (WAF), Core Integrity Auditing & Forensic Threat Intelligence</strong>
</p>

<p align="center">
  <a href="https://wordpress.org/"><img src="https://img.shields.io/badge/WordPress-7.0%2B-blue.svg?logo=wordpress" alt="WordPress Version"/></a>
  <a href="https://www.php.net/"><img src="https://img.shields.io/badge/PHP-8.3%2B-777BB4.svg?logo=php" alt="PHP Version"/></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB.svg?logo=react" alt="React 18"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-GPLv2%2B-green.svg" alt="License"/></a>
  <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67"><img src="https://img.shields.io/badge/Upwork-Top%20Rated%20Plus%20★%20100%25%20JSS-14A800.svg?logo=upwork" alt="Upwork Top Rated Plus"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Release-v1.29.0-orange.svg" alt="Release Version"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Status-Public%20Beta%20%7C%20Active%20Dev-blue?style=flat&logo=git" alt="Status"/></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy%20%26%20Disclosure-blue.svg?logo=securityscorecard" alt="Security Policy"/></a>
  <a href="#22-model-context-protocol-mcp-agentic-surface-ai-secops-automation"><img src="https://img.shields.io/badge/Agentic-Model%20Context%20Protocol%20(MCP)-purple.svg?logo=anthropic" alt="MCP Ready"/></a>
  <a href="#-featured-spotlight-cryptographic-secret-vault--database-encryption-at-rest"><img src="https://img.shields.io/badge/Security-AES--256--GCM%20AEAD%20Vault-blueviolet.svg?logo=securityscorecard&logoColor=white" alt="Cryptographic Secret Vault"/></a>
</p>

---

## 🛡️ Overview

**WCP Security Scanner** is a modern, high-performance WordPress security, malware detection, and forensic auditing plugin engineered by **[Mir Alamin](https://www.upwork.com/freelancers/~0162afa9a578170c67)** ([WebCare Pro](https://webcarespro.com)). 

> [!NOTE]
> **Active Engineering & Senior Architecture (v1.29.0)**  
> WCP Security Scanner is actively developed and battle-tested by solo engineer **Mir Alamin**. Rapid architectural upgrades, engine hardening, and new security primitives are released continuously.

Unlike heavy, bloated security plugins that degrade server performance with background overhead, WCP Security Scanner combines **memory-safe PHP batch auditing engines** with a responsive **React 18 single-page administrative dashboard**. It provides deep insight into your file system, WordPress core integrity, plugin and theme source code, database tables, cron jobs, active administrative sessions, runtime memory hooks, and server configurations—giving developers, sysadmins, and site owners complete visibility and control over their WordPress security posture.

---

## 🔐 Featured Spotlight: Cryptographic Secret Vault & Database Encryption at Rest

> [!IMPORTANT]
> **Zero Plaintext Credentials in Database or SQL Backups with Authenticated AEAD Encryption.**  
> Unlike typical WordPress security plugins that store third-party API keys and incoming webhooks as raw plaintext inside `wp_options`, WCP Security Scanner implements a dedicated **Enterprise AES-256-GCM Authenticated Cryptographic Secret Vault**. Every webhook URL, Cloudflare API token, AI key, and 2FA user secret is encrypted at rest using modern Authenticated Encryption with Associated Data (AEAD), 128-bit integrity authentication tags, randomized 12-byte initialization vectors (`random_bytes(12)`), and dynamic 256-bit key derivation with optional server-level `WCP_VAULT_KEY` environment isolation.

### 🛡️ How the Cryptographic Secret Vault Protects Your Infrastructure:

| Security Dimension | Standard WordPress Plugins | WCP Security Scanner Vault |
|:---|:---|:---|
| **Database Storage (`wp_options`)** | ❌ Plaintext strings visible to anyone with database access | ✅ **AES-256-GCM Authenticated Ciphertext** (`wcp_gcm:...`) |
| **Tamper & Bit-Flip Resistance** | ❌ None (or vulnerable to CBC padding oracle attacks) | ✅ **128-bit Cryptographic Authentication Tag** (tampering rejected immediately) |
| **SQL Dumps & Database Backups** | ❌ Secrets exposed in plain text if backup files are compromised | ✅ **Completely unreadable encrypted strings** |
| **phpMyAdmin & SQLi Exposure** | ❌ Scraped easily via unauthorized database queries | ✅ **Zero plaintext credential leakage** |
| **Encryption Keys & Salting** | ❌ Static hardcoded strings or unencrypted options | ✅ **Derived from WP Salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`) or dedicated `WCP_VAULT_KEY`** |
| **Key Isolation (DevOps)** | ❌ Tied solely to database or webroot | ✅ **Supports isolated `WCP_VAULT_KEY` in server environment outside webroot** |
| **Initialization Vectors (IV)** | ❌ Static or reused IV vectors | ✅ **Cryptographically random 12-byte IV generated per record** |
| **Decryption Lifecycle** | ❌ Persisted in plain text on memory or disk | ✅ **Transient in-memory decryption ONLY during active API/webhook calls** |
| **Admin UI Visibility** | ❌ Plaintext input fields or visible strings | ✅ **Auto-masked bullet placeholders (`••••••••`) with 1-click eye toggle** |

---

## 🌟 Comprehensive Feature Catalog (53 Specialized Security Engines & Subsystems)

> 💡 **For Complete In-Depth Documentation & Plain-English Guides:** Read the comprehensive [features.md](file:///c:/Users/My-PC-03/Documents/test/wcp-wp-scanner/features.md) catalog for dual-level breakdowns (plain-English for site owners + deep engineering architecture for developers).

### 1. Next-Gen Cyber Command Center & Threat Dashboard
- **High-Precision SVG Security Health Meter**: Circular dynamic vector meter displaying site security score (0–100%) with reactive color accents (emerald `#10b981`, sky blue `#38bdf8`, amber `#f59e0b`, rose `#ef4444`) and live letter grades (`A+`, `A`, `B`, `C`, `D`, `F`).
- **Interactive Threat Metric Cubes**: High-contrast summary widgets grouping active threats into 3 primary vectors: Critical Exploits & Backdoors, File Integrity & Code Drift, and Software Vulnerabilities & CVE Advisories, with instant 1-click category filtering.
- **Audit Command Center Console**: Fast single-click execution controls (Full Deep Audit vs Fast Audit), live engine telemetry indicators, dual-layer animated scan progress bar, and instant cancellation controls.
- **Interactive Findings Hub**: Modern alternating zebra row styling with severity-tinted accent borders, quick filter pills, monospace path breadcrumbs with 1-click clipboard copy, and real-time instant text search.

### 2. Multi-Vector Security & Deep Malware Scanning
- **Deep Heuristic PHP Code Analysis**: Scans for webshells, backdoors, Trojan droppers, and remote access tools. Detects obfuscation patterns including nested decode wrappers, decompression routines, dynamic variable functions, hex/octal encodings, and malicious file header spoofs.
- **WordPress Core Cryptographic Integrity Engine**: Validates core files against official WordPress.org cryptographic MD5 checksum APIs. Pinpoints modified, injected, tampered, or missing core files in `wp-admin`, `wp-includes`, and root directories.
- **Uploads Executable & Script Shield**: Recursively audits `wp-content/uploads/` for prohibited script extensions (`.php`, `.phtml`, `.phps`, `.sh`, `.py`, `.pl`), disguised double-extensions (`shell.jpg.php`), and rogue `.htaccess` execution overrides.
- **Database Threat & Content Injection Scanner**: Deeply inspects `wp_posts`, `wp_options`, `wp_users`, and `wp_comments` for stored cross-site scripting (Stored XSS), malicious iframes, pharmaceutical spam links, hidden redirect doorways, and unauthorized admin user records.
- **Hierarchical Resumable Cursor Engine**: Replaces slow numeric offset pagination with an opaque two-level hierarchical cursor (`phase`, `dir_stack`, `last_file`), completely eliminating $O(N^2)$ filesystem re-traversals on large WordPress sites with bounded ~15–25MB batch heap delta and cycle-safe non-symlink traversal.
- **High-Throughput Findings Bulk Ingestion**: Persists file audit and finding records using prepared multi-row SQL batches (`bulk_insert_files`, `bulk_insert_issues`) capped at 80 rows per statement via `FindingsRepository`, staying safely under MySQL `max_allowed_packet` with safe null parameter binding and zero table lock contention.
- **Crontab & Scheduled Task Auditing**: Audits both Linux server-level crontab files (`/var/spool/cron`, `crontab -l`) and WordPress virtual `wp-cron` hooks for unauthorized piped downloads (`curl | bash`, `wget | sh`), reverse shells, and persistence callbacks.
- **User Account & Privilege Security**: Identifies weak administrator passwords, dormant superuser accounts, and suspicious newly created administrator accounts.

### 3. Targeted Single-Purpose Security Audits & Auto-Scroll Workflow
- **7 Dedicated Rapid Audit Modules**: Database Injections, Uploads Quarantine Audit, Theme Integrity Deep Scan, Plugin Vulnerabilities Audit, Core Checksums Audit, Privilege Escalation Check, and Runtime Hook Infiltration (LotL).
- **Automatic Smooth Viewport Auto-Scroll**: When any targeted audit completes, the UI smoothly auto-scrolls the viewport directly to the Targeted Audit Results section (`scrollMarginTop: 24px`), presenting findings and risk scores immediately without requiring manual page scrolling.

### 4. Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer
- **Filesystem Change Tracker**: Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
- **Custom & Premium Component Recognition**: Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to prevent false alarms.
- **In-Page Visual Code Diff Viewer Modal (`VisualDiffModal.tsx`)**: Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org release mirrors line-by-line with side-by-side additions and deletions.

### 5. 1-Click Auto-Cure & Surgical Remediation Engine
- **1-Click WordPress Core Auto-Cure**: Restores tampered core files inside `wp-admin`, `wp-includes`, and root directories back to official pristine WordPress.org release code matching the exact site WordPress version, without re-installing all of WordPress.
- **1-Click Plugin & Theme Auto-Cure**: Restores altered or infected plugin and theme files back to authentic, bit-for-bit verified copies fetched directly from WordPress.org release mirrors.
- **1-Click Webshell Stripping**: Surgically neutralizes malicious code headers, obfuscated `eval()`/`base64` wrappers, and backdoor includes while preserving legitimate file code with tokenizer syntax validation.
- **1-Click Scheduled Cron Hook Remediation**: Safely unschedules and purges orphaned or malicious cron hooks directly from `wp_options:cron` via `wp_clear_scheduled_hook()`.
- **Auto-Cure Safety Backups & Rollback Vault**: Creates timestamped safety backups in a secure directory before every remediation action, enabling instant rollback if needed.
- **Real-Time State Synchronization**: As soon as an issue is cured, the findings table updates to display an `Issue Solved & Restored` status badge and transitions mitigation actions automatically.

### 6. Secure Quarantine Vault & Isolation Architecture
- **Safe Cryptographic Isolation**: Safely isolates infected or unknown files into a protected, `.htaccess`-guarded directory outside executable paths. Preserves original file permissions, timestamps, and SHA-256 cryptographic hashes in `wp_wcp_quarantine`.
- **Intelligent Quarantine Eligibility Safeguards**: Enforces strict boundaries to prevent quarantining critical configuration files (`wp-config.php`, `.htaccess`, `index.php`) and modified official components, ensuring isolation is strictly reserved for rogue and unknown alien files.
- **Quarantine Vault Hub**: Responsive table with horizontal overflow support, 1-click instant file restoration, and permanent vault deletion.

### 7. Software Intelligence & Curated CVE Advisory Database
- **Curated CVE Advisory Database**: Scans installed WordPress core, active/inactive plugins, and themes against an offline-resilient vulnerability database.
- **Granular Vulnerability Metadata**: View CVSS risk scores, severity badges (Critical, High, Medium, Low), affected versions, patched versions, and official NIST NVD reference advisories.
- **Interactive Vulnerabilities Dashboard**: Filter by component type (Core, Plugins, Themes) or status (Vulnerable, Outdated, Clean). Includes 1-click update links to native WordPress update screens and an in-depth CVE forensic breakdown modal.

### 8. Living-off-the-Land (LotL) Runtime Hook Infiltration Sentinel
- **Active Runtime Memory Hook Audit**: Uses reflection to inspect active runtime hook callbacks registered in `$wp_filter` across high-risk lifecycle actions (`authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`).
- **Anonymous Closure & Credential Sniffer Detection**: Flags anonymous `Closure` functions attached to sensitive authentication and login hooks that could steal passwords.
- **External Rootkit & Uploads Hook Traps**: Detects hook callbacks originating outside WordPress root (server-level `auto_prepend_file` rootkits or PHP-FPM pool injections) and callbacks executing inside `wp-content/uploads/` (webshell callbacks).
- **Dangerous Native Function Registration Defense**: Detects dangerous native PHP functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`) attached directly as WordPress filter callbacks.

### 9. Database Micro-Anomaly & Rogue Administrator Trap
- **Stealth User Infiltration Detection**: Audits `wp_users` against `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
- **Ghost & Orphaned Capability Hunting**: Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap**: Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe**: Recursively scans `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden in transient names.

### 10. Web Application Firewall (WAF Lite) & Virtual Patching
- **Real-Time Request Filtering**: Inspects incoming HTTP payloads at `plugins_loaded` (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
- **Attack Vector Shields**: Blocks SQL Injections (`UNION SELECT`, `information_schema`, `benchmark`), Cross-Site Scripting (XSS scripts/handlers), Path Traversal & LFI (`/etc/passwd`, `php://filter`), PHP code tag injections (`<?php`, `eval`, `base64_decode`, `system`), and XML-RPC exploitation.
- **Smart Shields & 32 Verified Integrations**: Comprehensive allowlist rules for WooCommerce, Stripe, PayPal, Elementor, Divi, Gutenberg, Jetpack, ManageWP, and 30+ other tools.
- **Smart Cloudflare & Coexistence**: Decodes visitor Real-IP from `HTTP_CF_CONNECTING_IP` with Cloudflare proxy range validation. Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.

### 11. Dedicated WAF Incident Logs, Threat Intelligence & Attack Forensics
- **Full-Page Forensic Analytics Hub (`admin.php?page=wcp-scanner-waf-logs`)**: Deep-linked directly from Firewall header actions and navigation bar.
- **Real-Time KPI Threat Metrics**: 4 live KPI cards displaying Total Incursions Blocked, 24h Attack Surge, Distinct Attack IPs, and Simulation/Learning Mode hits.
- **Threat Vector & Offender Analytics Grid**: Top Attack Vectors breakdown with proportional percentage bars and Frequent Offending Hostile IP Directory with hit counts, last seen timestamps, and 1-click Filter/Block actions.
- **Multi-Field Forensic Search & Export**: Real-time search across IP addresses, target URIs, malicious payload signatures, and User-Agents, with CSV, JSON, and printable report downloads.

### 12. Smart 404 Scanner Rate-Limiter & Reconnaissance Shield
- **Automated 404 Scanner Lockouts**: Automatically isolates fuzzing and vulnerability scanning bots that trigger repetitive 404 errors across WordPress installations (default 10 probes in 60s trigger a 30-minute block).
- **DNS-Verified Search Engine Exemption**: Genuine search engines (Googlebot, Bingbot, DuckDuckBot, Yandex, Baidu, Yahoo) verified via Reverse DNS (PTR) + Forward DNS (A/AAAA) confirmation with 24h caching are strictly exempted.
- **Static Asset & Media Exclusion**: Missing static assets (`.jpg`, `.png`, `.webp`, `.svg`, `.css`, `.js`, `.ico`, `.woff`, `.pdf`) are ignored from 404 tallies to prevent human visitor lockouts.
- **High-Risk Reconnaissance Acceleration**: High-threat backdoor and sensitive file probes (`.env`, `.git`, `.bak`, `wp-config.php.bak`, `shell.php`, database dumps) advance the counter by 3 to swiftly isolate active exploit scanners.

### 13. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)
- **Zero-Resource Threat Interception**: Blocks malicious bots and automated exploits at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
- **3 Master Compound Rules (Free Plan Calibrated)**: Master Perimeter Armor, LFI/RFI Directory Traversal Shield, and Login Portal Bot Defense.
- **Single-Rule Push & Remove (`/cloudflare/deploy-single-rule`)**: Push, update, or remove individual Cloudflare edge rules independently without touching other rules.
- **Cloudflare Free Rate Limiter & Auto-Ban Sync**: Edge rate limiting on `/wp-login.php` with bi-directional syncing of locally detected attack IPs to Cloudflare Edge IP Access Rules.

### 14. Community Threat Intelligence & Botnet IP Blacklists
- **Community Botnet IP Blacklists**: Synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL with static in-memory $O(1)$ hash map and CIDR subnet matching (<0.05ms).
- **Zero-Day CVE Feed & Site Correlation**: Real-time zero-day vulnerability definitions correlated with installed WordPress Core, plugins, and themes.

### 15. Active Session Sentinel & Access Control
- **Active Administrative Session Inspector**: Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Dual-Device Concurrency Control**: Enforces flexible session policies (strictly 1 Desktop + 1 Mobile maximum per administrator).
- **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

### 16. Inline Expandable User Session Forensics & Real IP Tracking
- **In-Table Forensic Accordion**: Clicking an administrator row expands the forensic audit panel in place (`Hide Forensics` / `Forensics`), completely eliminating viewport modal overlap.
- **Strict Decrypted Origin IP Fidelity**: Inspects the authentic user's decrypted login IP recorded at authentication time (`$data['ip']`), preventing Cloudflare Anycast edge proxies from colliding with remote administrator IPs.

### 17. Multi-Factor Authentication (2FA) & Login Hardening
- **Pure PHP RFC 6238 TOTP Engine**: Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
- **Native `wp-login.php` Interception**: Displays a responsive, branded two-factor verification challenge screen supporting rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
- **AES-256-GCM AEAD Encrypted User Secrets**: Encrypts user TOTP secrets (`_wcp_2fa_secret`) at rest in `wp_usermeta` via the Secret Vault with 128-bit authentication integrity tags.

### 18. WebAuthn Passwordless Biometric Login & Native Windows Hello Ceremony
- **Complete Native WebAuthn Ceremony (`WebAuthnManager.php`)**: Implements the official W3C WebAuthn Level 3 protocol directly inside the WordPress core login lifecycle (`wp-login.php`).
- **Native Windows Hello & Biometric Integration**: Supports platform authenticators (Windows Hello PIN/Fingerprint, Apple Touch ID/Face ID, Android Biometrics, and USB FIDO2 security keys) for instant, 100% phishing-immune login.

### 19. Dedicated Notification Center & Granular 32+ Event Alert Matrix
- **Dedicated Administrative Notification Hub (`admin.php?page=wcp-scanner-notifications`)**: Full-page notification operations hub accessible via direct deep-link.
- **32+ Granular Security Events Across 8 Categories**: Core Scans & Threats, Plugin Self-Defense, Cloudflare & WAF Defense, Authentication & Access Security, File Integrity Monitoring, Vulnerabilities & CVE Feeds, Database Backups & Vault, and DevSecOps & AI Forensics.
- **Independent Dual-Channel Matrix**: Independent toggle switches for Email (`wp_mail`) and DevSecOps Webhooks (Slack, Discord, ClickUp, Asana, Generic JSON) per event.

### 20. Enterprise HTTP Security Headers & 1-Click Site Hardening
- **Enterprise Security Headers Dispatcher**: Injects `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock**: Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense**: Blocks author archive scraping (`/?author=1`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`).

### 21. 1-Click WP_DEBUG & Sensitive Configuration Remediation Engine
- **Automated Configuration Remediation (`RemediationManager::disable_wp_debug`)**: Safely parses and updates `wp-config.php` via REST endpoint `/remediation/disable-wp-debug`.
- **Atomic File Alteration with Syntax Tokenizer Validation**: Uses PHP's native `token_get_all()` parser to safely turn off `WP_DEBUG`, `WP_DEBUG_LOG`, and `WP_DEBUG_DISPLAY` constants without syntax corruption.

### 22. Bot Recon Defense & AI Scraper Shield
- **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching.
- **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) with virtual `robots.txt` disallows.

### 23. Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude)
- **Supported AI Forensic Providers**: Google Gemini, OpenAI, and Anthropic Claude.
- **1-Click AI Code Forensics Modal**: Decodes obfuscated scripts in seconds, assesses threat confidence (0–100%), explains exploit mechanics, and generates surgical clean code patches.

### 24. Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation)
- **Native JSON-RPC 2.0 Agentic Integration**: Bridges external AI coding agents (Claude Desktop, Cursor IDE, Antigravity) with WordPress security operations over standard JSON-RPC 2.0.
- **Granular Permission Scopes & Rate Limiting**: Enforce Read-Only or Full Remediation mode with per-token rate-limiting and persistent 150-event ring-buffer execution logging (`wcpscan_mcp_audit_log`).

### 25. Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation)
- **Pure AES-256-GCM Authenticated Encryption (AEAD)**: Encrypts all sensitive credentials (webhooks, Cloudflare tokens, AI keys, 2FA TOTP secrets) before writing to `wp_options`.
- **Two-Phase Commit Key Rotation Orchestrator (`VaultRotator`)**: Zero-downtime state machine with dual-key background decrypt fallback and atomic snapshot rollbacks.

### 26. Unified WCP Vault Console (4 Consolidated Isolation & Recovery Facilities)
- **Centralized Security Vault Page (`wcp-vault`)**: Consolidates File Quarantine, Database Snapshots, Pre-Cure Safety Rollbacks, and Secret Vault metrics into one unified screen.

### 27. On-Demand Database Backup Vault (`.sql.gz`)
- **1-Click Compressed Database Vault**: Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression, size metadata indexing, and secure browser downloads.

### 28. High-Precision Microsecond Telemetry & Diagnostics
- **Microsecond Scan Duration Tracking**: Database schema upgraded with `started_at` (`datetime(3)`), `completed_at` (`datetime(3)`), and `duration_ms` (`int(11)`) for millisecond accuracy.
- **Real-Time Environment Diagnostics**: Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions, MySQL collation, and historical audit logs.

### 29. Behavioral Baseline & Attack Chain Correlation
- **Behavioral Drift Detection**: Tracks alterations in critical site metadata, administrator counts, PHP execution options, and file counts against historic baselines.
- **Attack Chain Timeline**: Correlates disparate security events into a unified chronological breach narrative with estimated blast radius scoring.

### 30. Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking
- **1-Click Intelligent Suppression**: Instantly suppress known false-positives with automated SHA-256 cryptographic checksum locking and customizable expiration windows (30 days, 90 days, 1 year, or Permanent).

### 31. Zero-Trust Must-Use (MU) Guardian & Sandboxed Temporary Support Access
- **Inviolable Must-Use Guardian (`WcpJitMuGuardian.php`)**: Deployed as an infallible Must-Use plugin (`wp-content/mu-plugins/wcp-jit-guardian.php`) executing at earliest bootstrap (`muplugins_loaded`) that cannot be deactivated or deleted via the WordPress admin UI.
- **Granular Sandboxing Shields**: Strictly forbids temporary technicians from modifying security settings, deactivating plugins, installing unapproved packages, editing files, or viewing decrypted secrets.

### 32. Preload Micro-WAF & Early Execution Engine (Linux Fail2ban & CrowdSec Syslog)
- **Zero-Dependency Standalone Runtime (`MicroWafCompiler.php`)**: Compiles WAF rules to OPcache-shared static PHP arrays (`micro-waf-compiled.php`), intercepting malicious requests via `auto_prepend_file` before WordPress core boots or database connections initialize.
- **Linux Fail2ban & CrowdSec Integration**: Automatically appends early dropped requests to a standardized append-only syslog for instant kernel/network-level blocking.

### 33. JavaScript Threat Intelligence, Magecart Payment Skimmer & Beacon Detector
- **Dedicated Client-Side Malware Engine (`JavaScriptSecurityScanner.php`)**: Inspects static `.js` files for Magecart payment skimmers, event listeners listening to credit card fields, and unauthorized data-theft beacons (`fetch()`, `sendBeacon()`, `new Image()`).

### 34. Third-Party Script Inventory & Frontend Hostname Drift Sentinel
- **Passive Frontend Enqueue Telemetry (`ScriptInventoryMonitor.php`)**: Monitors dynamically enqueued scripts across checkout and sensitive transaction boundaries, alerting on unexpected third-party domain drift.

### 35. Offline Dependency Lockfile (Composer & npm) Supply-Chain Auditor
- **Offline SemVer Parser (`LockfileAuditEngine.php`)**: Scans `composer.lock` and `package-lock.json` manifests against bundled high-profile CVE signatures completely offline, without requiring npm or Composer on the server.

### 36. 2026 AI Threat Defense, Prompt-Injection Guard & Decoy Ghost Route Traps
- **Autonomous AI Pentest Bot & Decoy Canary Trap (`GhostRouteTrap.php`)**: Injects invisible canary link tags and phantom REST honeypot routes to immediately catch, tarpit, and block aggressive AI scrapers and vulnerability scanners.
- **WordPress 7.0+ AI Client & Prompt-Injection Guard (`PromptInjectionGuard.php`)**: Inspects incoming prompt vectors and comments against prompt override attacks, DAN jailbreak patterns, and invisible Unicode tag smuggling.

### 37. Outbound AI & SSRF Egress Firewall (Cloud Metadata & Exfiltration Shield)
- **Outbound HTTP Client Interception (`OutboundEgressFirewall.php`)**: Hooks `pre_http_request` with stack backtrace inspection to block SSRF targeting cloud metadata (`169.254.169.254`, private LAN CIDRs) and data exfiltration pipelines.

### 38. Plaintext Credential Exposure & Secret Leak Scanner (.env, Git, Keys)
- **Automated Root & Uploads Audit (`CredentialExposureScanner.php`)**: Rapidly scans public folders for exposed `.env` files, `.git/config`, OpenAI keys, Stripe secret keys, AWS keys, and private SSH keys, with safe administrative masking.

### 39. REST API & Public AJAX Attack Surface Inventory & User Enumeration Guard
- **Automated Surface Discovery (`RestApiInventory.php`)**: Maps all registered WordPress REST API endpoints and public unauthenticated AJAX actions, highlighting mutating write endpoints.
- **1-Click User Enumeration Defense**: Intercepts unauthenticated queries targeting `/wp/v2/users` to prevent username harvesting.

### 40. 72-Hour Post-Remediation Reinfection Watchdog & Surveillance Vault
- **Automated Surveillance Enlistment (`ReinfectionWatchdog.php`)**: Maintains hourly automated surveillance over remediated paths across a 72-hour threat window, instantly locking resurrected backdoors into the quarantine vault.

### 41. "Time-Machine" Local File & Bespoke Asset Snapshot Baseline Engine
- **Bespoke Asset Baseline Archives (`LocalSnapshotManager.php`)**: Captures compressed, read-only baseline snapshots (`.gz`) of custom client themes and bespoke plugins for visual Myers diff inspection and 1-click atomic restoration.

### 42. Automated Blacklist, Domain Reputation & DNSBL Early-Warning Sentinel
- **Daily Automated Reputation Audit (`DomainReputationMonitor.php`)**: Continuously audits site domain reputation across leading DNSBL blacklists, verifies TLS/SSL certificate expiration countdowns, and validates SPF/DMARC email authentication records.

### 43. Unified 5-Tier Threat Correlation Engine & Attack Kill-Chain Forensics
- **5-Tier Telemetry Hierarchy (`CorrelationEngine.php`)**: Synthesizes disparate signals into 5 structured intelligence tiers (Observed Facts &rarr; Threat Indicators &rarr; Temporal Correlations &rarr; Kill-Chain Hypotheses &rarr; Actionable Containment Outcomes).

### 44. 1-Click Panic Button Emergency Site Lockdown & Containment Protocol
- **1-Click Header Panic Button (`EmergencyContainmentManager.php`)**: Instantly locks down the site by activating Cloudflare Under-Attack defense, freezing outbound HTTP egress, and capturing a 72-hour forensic snapshot.

### 45. Global Command Center & All Modules Mega-Menu (Ctrl+K Navigation)
- **Comprehensive Navigation Matrix (`MegaMenuModal.tsx`)**: Categorizes all 13 core security pillars with real-time text filtering and `Ctrl+K` keyboard shortcuts for instant module hopping.

### 46. Zero-Allocation Streaming Session Queue & Microsecond Disk Cursor
- **Ephemeral Stream Queue Storage (`ScanQueueManager.php`)**: Streams discovered files directly into private line-delimited session files on disk, maintaining flat ~2MB RAM consumption regardless of website size.

### 47. Host Antivirus Immunity & Heuristic Engine Resilience (CPGuard / Imunify360 Bypass Defense)
- **Dynamic Runtime Token Assembly**: Assembles malware detection patterns in memory to prevent false-positive quarantines of the security scanner by server-level security daemons like CPGuard, Imunify360, and ClamAV.

### 48. Data Privacy, Safety Policies & Clean Uninstall Lifecycle
- **100% On-Premise Execution & Clean Database Purge**: Zero tracking, zero telemetry, non-destructive safety backups before any file edit, and clean 6-table database dropping on uninstall (`uninstall.php`).

---
### 49. CrashGuard Zero-Downtime Circuit Breaker & Safe Mode Self-Preservation
- **Guarded Plugin Initialization & Fail-Closed Resilience**: Top-level bootstrap `try/catch` shield, scoped early shutdown fatal error interception (`CrashGuard.php`), 3-strike sliding-window loop protection, standalone Micro-WAF try/catch shield (`MicroWafCompiler.php`), and 1-click self-healing Safe Mode recovery preventing WSOD downtime.

### 50. Pre-Install Supply-Chain Gatekeeper & Update Risk Advisor
- **Shift-Left Upgrader Archive Static Analysis**: Intercepts extracted plugin and theme update archives before filesystem replacement (`UpdateGatekeeperEngine.php`), performs AST heuristic security audits, generates pre-update WCP Vault rollback snapshots, and blocks hostile supply-chain updates.

### 51. Zero-SQL Partitioned WAF Incident Filesystem Engine
- **High-Throughput Filesystem Incident Telemetry**: Streams blocked attack telemetry and Layer 7 incidents directly to partitioned daily JSON Lines logs (`WafFileLogger.php`) with atomic appending (`LOCK_EX`), eliminating MySQL database overhead under high-volume botnet attacks with Fail2ban and CrowdSec native ingestion.

### 52. Enterprise Granular Notification Center & DevSecOps Webhooks
- **59-Event Security Alert Matrix & Webhook Integrations**: Full-page interactive notification center (`?page=wcp-scanner-notifications`) with granular event toggles across 10 security categories and independent channels for Email, Slack, Discord, ClickUp, Asana, and custom DevSecOps webhooks with AES-256-GCM encrypted secrets.

### 53. Turbo Scan Engine Optimization, In-Memory Caching & Bulk Ingestion
- **320+ Files/Sec Audit Throughput**: In-memory WordPress.org checksum caching with negative transient caches (`ChecksumProvider.php`), automatic test suite and vendor sample directory exclusions (`Engine.php`), and multi-row batched atomic SQL staging (`ScannerRoutes.php`) delivering lightning-fast, zero-overhead malware scans.

---


## ⚖️ Architectural Comparison at a Glance (as of Oct 2026)

Security plugins solve overlapping problems through different architectures. This practical orientation highlights primary engineering models and operational trade-offs:

| Dimension | **WCP Security Scanner** | **Wordfence** | **Sucuri Platform** | **Patchstack** |
| :--- | :--- | :--- | :--- | :--- |
| **Model** | **On-Server Suite**: Streaming Scan, WAF, Identity, Secret Vault, 4-Mirror Auto-Cure | **On-Server Suite**: Endpoint WAF + Signature Scanner + Login Hardening | **Cloud WAF/CDN** + Monitoring + Managed Human Response | **Vulnerability Intel & Rapid Virtual Patching** |
| **Key Strength** | **Ultra-low RAM (~15-25MB batch delta)**, AES-256-GCM Vault, MCP AI agent governance, zero telemetry | Huge install base + proprietary threat research lab | Cloud edge blocking + managed malware cleanup retainers | Industry-fastest CVE intelligence & virtual patch loop |
| **Trade-off** | Independent solo-vendor velocity; no 24/7 global SOC; uses origin CPU/RAM | Can be resource-heavy; free threat feed delayed ~30 days; database table bloat | Premium cost; DNS/proxy dependency; free plugin is limited | Not a complete malware scanner, cleaner, or traditional WAF |

> **Honest Architectural Positioning**: WCP Security Scanner is not designed to replace globally distributed Anycast DDoS scrubbing networks (like Cloudflare Enterprise) or 24/7 human research SOCs. It is purpose-built for SysAdmins, developers, and store operators who demand deep on-server control, strict zero-telemetry privacy, and non-destructive surgical remediation.
>
> 📖 **Read the comprehensive, balanced ecosystem comparison and technical breakdown:**  
> [https://webcarespro.com/blog/post/wcp-wordpress-security-scanner](https://webcarespro.com/blog/post/wcp-wordpress-security-scanner)

---

## 🏢 About WebCare Pro & Mir Alamin

**[WebCare Pro](https://webcarespro.com)** is an enterprise web and Linux server engineering practice founded in 2013 by **Mir Alamin**. I help businesses worldwide build, secure, optimize, and manage high-performance websites and servers.

- **12+ Years Enterprise Experience**: Senior Linux SysAdmin and Web Architecture background across high-traffic digital infrastructures.
- **Direct Senior Engineering**: Every architecture, server migration, malware cleanup, and speed optimization is personally designed and handled—**zero junior contractor outsourcing**.
- **100% Proven Track Record**: Over 680 successfully completed client projects with a flawless **100% Job Success Score** on Upwork and 5-star ratings worldwide.
- **15-Minute Emergency SLA**: Rapid diagnostic triage when servers crash, gateways timeout, or websites suffer critical malware attacks.

### Specialized Professional Services:
1. **[Website Hack Recovery & Security](https://webcarespro.com/services/website-hack-recovery-security)** — Rapid malware eradication, backdoor cleanup, Google blacklist delisting, and WAF configuration.
2. **[Website Speed Optimization](https://webcarespro.com/services/website-speed-optimization)** — Sub-100ms TTFB tuning, Redis object caching, asset deferral, and 100/100 Core Web Vitals.
3. **[Linux Server Administration](https://webcarespro.com/services/server-administration-management)** — Nginx, Apache, LiteSpeed, PHP-FPM, Docker, MySQL replication, security hardening, and Cloudflare enterprise routing.
4. **[WordPress Maintenance & Core Care](https://webcarespro.com/services/wordpress-maintenance-service)** — 24/7 uptime monitoring, offsite encrypted backups, vulnerability patching, and staging testing.

---

## 🚀 Quick Start & Installation

### Requirements:
- **WordPress Version:** 7.0 or higher (Fully tested on WP 7.0 and 7.1)
- **PHP Version:** 8.3 or higher
- **MySQL / MariaDB:** 5.7+ / 10.3+
- **PHP Extensions:** `OpenSSL`, `cURL`, `sodium`, `json`, `mbstring`, `zip`

### Installation Steps:
1. Download `wcp-security-scanner.zip` from releases or build directly from source.
2. Navigate to **Plugins > Add New > Upload Plugin** in your WordPress administration panel.
3. Select `wcp-security-scanner.zip` and click **Install Now**.
4. Click **Activate Plugin**.
5. Access your new cyber command center by clicking **WCP Security** in your WordPress sidebar.

### Building from Source:
```bash
# Clone the repository
git clone https://github.com/WebCarePro/wcp-wp-security.git
cd wcp-wp-security

# Install dependencies
npm install

# Compile the production React build
npm run build

# Package the clean release zip for WordPress.org
npm run package
```

---

## 🔒 Security & WordPress.org Directory Compliance

WCP Security Scanner is strictly developed in adherence to the **WordPress.org Plugin Guidelines**:
- **Non-Destructive Core Policy**: Does not blindly delete or modify core files. When core files are flagged as tampered, administrators can use 1-click Auto-Cure to restore clean, bit-for-bit official copies directly from WordPress.org with automated pre-restoration rollback backups, or leverage official WordPress update workflows (`update-core.php`) and WP-CLI (`wp core download --force`).
- **Protected File Storage**: Quarantine vaults, audit logs, and compressed database backups are stored exclusively within `wp-content/uploads/wcp-security-scanner/`, guarded by Apache/LiteSpeed `.htaccess` (`Require all denied`) and silent PHP index files.
- **Directory Traversal Defense**: All quarantine, file inspection, and backup operations enforce strict path normalization and trailing-slash boundary checks against `ABSPATH`.
- **Transparent Third-Party Services**: External API calls (official WordPress.org Checksum API, community threat feeds, and optional AI providers) are fully documented with explicit triggers, payload descriptions, and links to Terms of Service and Privacy Policies.

---

## 📬 Connect Directly with Mir Alamin

Have questions, need an emergency malware cleanup, or want to hire a certified Senior Linux SysAdmin for your website? Connect with me directly:

<p align="center">
  <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67">
    <img src="https://img.shields.io/badge/Upwork-Hire%20on%20Upwork%20(Top%20Rated%20Plus)-14A800?style=for-the-badge&logo=upwork&logoColor=white" alt="Hire Mir Alamin on Upwork"/>
  </a>
  <a href="https://webcarespro.com/">
    <img src="https://img.shields.io/badge/Website-webcarespro.com-0284C7?style=for-the-badge&logo=googlechrome&logoColor=white" alt="WebCare Pro Website"/>
  </a>
  <a href="https://wa.me/8801322691090">
    <img src="https://img.shields.io/badge/WhatsApp-Chat%20Now-25D366?style=for-the-badge&logo=whatsapp&logoColor=white" alt="WhatsApp Direct Chat"/>
  </a>
  <a href="https://teams.live.com/l/invite/FEAI60zv48mwbIKhA?v=g1">
    <img src="https://img.shields.io/badge/Microsoft%20Teams-Live%20Meeting-6264A7?style=for-the-badge&logo=microsoftteams&logoColor=white" alt="Microsoft Teams Meeting"/>
  </a>
  <a href="mailto:hello@webcarespro.com">
    <img src="https://img.shields.io/badge/Email-hello%40webcarespro.com-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Direct Email"/>
  </a>
</p>

### Direct Contact Channels:
- 🌟 **Upwork Profile:** [Mir Alamin — Top Rated Plus Freelancer (100% Job Success Score)](https://www.upwork.com/freelancers/~0162afa9a578170c67)
- 🌐 **Official Website:** [https://webcarespro.com](https://webcarespro.com)
- 🚨 **Emergency Triage & Consultations:** [https://webcarespro.com/contact](https://webcarespro.com/contact)
- 💬 **WhatsApp / Direct Line:** [+880 1322 691090](https://wa.me/8801322691090)
- 👥 **Microsoft Teams:** [Connect on MS Teams](https://teams.live.com/l/invite/FEAI60zv48mwbIKhA?v=g1)
- 📧 **Direct Email:** [hello@webcarespro.com](mailto:hello@webcarespro.com)
- 🐙 **GitHub Organization:** [https://github.com/WebCarePro](https://github.com/WebCarePro)
- 📦 **Repository:** [https://github.com/WebCarePro/wcp-wp-security](https://github.com/WebCarePro/wcp-wp-security)

---

## 🔒 Privacy, Zero Telemetry & Data Protection Guarantee

- **Zero Tracking or Analytics:** WCP Security Scanner does NOT track, collect, store, or sell any personal data, analytics, or browsing habits from your WordPress website, its visitors, or its administrators.
- **No Sensitive Data Transmission:** The plugin operates entirely on your local server. It does NOT transmit sensitive credentials, passwords, database records, client data, or private files to any third-party server or external cloud.
- **100% On-Premise Execution:** Core scans, heuristic engines, File Integrity Monitoring (FIM), brute-force defenses, RFC 6238 TOTP 2FA generation, and firewall evaluations run 100% locally within your PHP environment.
- **Explicit Administrator Integrations Only:** External connections (WordPress.org checksums, threat intelligence feeds, Cloudflare edge sync, AI forensic assistance, or Slack/Discord webhooks) only execute when explicitly configured or initiated by the site administrator, transmitting only non-sensitive diagnostic parameters strictly necessary for the requested feature.

---

## 📄 License & Attribution

- **License:** Open source under the terms of the [GNU General Public License v2.0 or later (GPL-2.0-or-later)](https://www.gnu.org/licenses/gpl-2.0.html).
- **Author & Copyright:** © 2013–2026 **Mir Alamin** / **[WebCare Pro](https://webcarespro.com)**. All rights reserved.
