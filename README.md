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
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Release-v1.23.0-orange.svg" alt="Release Version"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Status-Public%20Beta%20%7C%20Active%20Dev-blue?style=flat&logo=git" alt="Status"/></a>
  <a href="#22-model-context-protocol-mcp-agentic-surface-ai-secops-automation"><img src="https://img.shields.io/badge/Agentic-Model%20Context%20Protocol%20(MCP)-purple.svg?logo=anthropic" alt="MCP Ready"/></a>
  <a href="#-featured-spotlight-cryptographic-secret-vault--database-encryption-at-rest"><img src="https://img.shields.io/badge/Security-AES--256--GCM%20AEAD%20Vault-blueviolet.svg?logo=securityscorecard&logoColor=white" alt="Cryptographic Secret Vault"/></a>
</p>

---

## 🛡️ Overview

**WCP Security Scanner** is a modern, high-performance WordPress security, malware detection, and forensic auditing plugin engineered by **[Mir Alamin](https://www.upwork.com/freelancers/~0162afa9a578170c67)** ([WebCare Pro](https://webcarespro.com)). 

> [!NOTE]
> **Active Engineering & Senior Architecture (v1.22.0)**  
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

## 🌟 Comprehensive Feature Catalog (30 Specialized Security Engines)

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
- **Server Configuration Hardening Safeguards**: Checks permissions for `wp-config.php` and `.htaccess`, audits `WP_DEBUG` exposure flags, and validates protection against public access to `.env`, `.git`, `.user.ini`, and database dumps.

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
- **Smart Cloudflare & Coexistence**: Decodes visitor Real-IP from `HTTP_CF_CONNECTING_IP` with Cloudflare proxy range validation. Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.
- **Live Incidents Stream & Controls**: Real-time blocked attack table, 1-click IP whitelisting, Learning Mode toggle (audit-only logging), and individual rule toggles. Custom dark-themed 403 Forbidden screen with incident reference IDs.

### 11. Dedicated WAF Incident Logs, Threat Intelligence & Attack Forensics
- **Full-Page Forensic Analytics Hub (`admin.php?page=wcp-scanner-waf-logs`)**: Deep-linked directly from Firewall header actions and navigation bar.
- **Real-Time KPI Threat Metrics**: 4 live KPI cards displaying Total Incursions Blocked, 24h Attack Surge, Distinct Attack IPs, and Simulation/Learning Mode hits.
- **Threat Vector & Offender Analytics Grid**: Top Attack Vectors breakdown with proportional percentage bars and Frequent Offending Hostile IP Directory with hit counts, last seen timestamps, and 1-click Filter/Block actions.
- **Multi-Field Forensic Search**: Real-time search across IP addresses, target URIs, malicious payload signatures, and User-Agents, combined with category, action, and HTTP method filters.
- **Expandable Forensic Deep-Dive Accordion**: Per-incident inspection view displaying rule trigger descriptions, raw User-Agent fingerprints, and syntax-highlighted malicious payload excerpts with 1-click JSON export.
- **Export & Forensics Reporting**: Download filtered incident records as CSV (`.csv`), raw JSON (`.json`), or formatted printable audit reports (`window.print()`).

### 12. Smart 404 Scanner Rate-Limiter & Reconnaissance Shield
- **Automated 404 Scanner Lockouts**: Automatically isolates fuzzing and vulnerability scanning bots that trigger repetitive 404 errors across WordPress installations (default 10 probes in 60s trigger a 30-minute block).
- **DNS-Verified Search Engine Exemption**: Genuine search engines (Googlebot, Bingbot, DuckDuckBot, Yandex, Baidu, Yahoo) verified via Reverse DNS (PTR) + Forward DNS (A/AAAA) confirmation with 24h caching are strictly exempted to prevent search engine indexing drops or SEO penalties.
- **Static Asset & Media Exclusion**: Missing static assets (`.jpg`, `.png`, `.webp`, `.svg`, `.css`, `.js`, `.ico`, `.woff`, `.pdf`) are ignored from 404 tallies, completely preventing false-positive lockouts for legitimate human visitors.
- **High-Risk Reconnaissance Acceleration**: High-threat backdoor and sensitive file probes (`.env`, `.git`, `.bak`, `wp-config.php.bak`, `shell.php`, database dumps) advance the counter by 3 to swiftly isolate active exploit scanners.

### 13. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan)
- **Zero-Resource Threat Interception**: Blocks malicious bots and automated exploits at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
- **3 Master Compound Rules (Free Plan Calibrated)**:
  1. *Rule 1: Master Perimeter & Sensitive File Armor:* Blocks `/xmlrpc.php`, script execution in uploads/upgrade trees, sensitive dotfiles (`.env`, `.git`), and backup files in 1 unified Block rule.
  2. *Rule 2: LFI/RFI Directory Traversal & Reconnaissance Shield:* Terminates directory traversal (`../`, `etc/passwd`), code execution wrappers, `?author=` harvesting, and REST user scraping.
  3. *Rule 3: Login Portal Automated Bot Defense:* Challenges automated bots targeting `wp-login.php`, membership portals, and WooCommerce account endpoints with Cloudflare Turnstile / Managed Challenge.
- **Single-Rule Push & Remove (`/cloudflare/deploy-single-rule`)**: Push, update, or remove individual Cloudflare edge rules independently without touching or redeploying other rules.
- **Cloudflare Free Rate Limiter**: Deploys edge rate limiting on `/wp-login.php` (5 requests / 60s per IP, 10s mitigation cooldown) to mitigate brute-force attacks with zero server resource consumption.
- **Bi-Directional WAF Auto-Ban Sync**: Automatically syncs locally detected high-threat attack IPs to Cloudflare Edge IP Access Rules.
- **1-Click CDN Cache Purge**: Instant global edge cache purge directly from the WordPress administration panel.

### 14. Community Threat Intelligence & Botnet IP Blacklists
- **Community Botnet IP Blacklists**: Synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL. Performs static in-memory $O(1)$ hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
- **Zero-Day CVE Feed & Site Correlation**: Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes, displaying status badges (`Installed — Vulnerable`, `Installed — Patched`, `Global Virtual Shield`).
- **IP Reputation Diagnostic Tool**: Built-in checker to test client or visitor IPs against the active threat database.

### 15. Active Session Sentinel & Access Control
- **Active Administrative Session Inspector**: Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Dual-Device Concurrency Control**: Enforces flexible session policies (strictly 1 Desktop + 1 Mobile maximum per administrator).
- **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

### 16. Inline Expandable User Session Forensics & Real IP Tracking
- **In-Table Forensic Accordion**: Clicking an administrator row expands the forensic audit panel in place (`Hide Forensics` / `Forensics`), completely eliminating viewport modal overlap with admin top bars.
- **Strict Decrypted Origin IP Fidelity**: Inspects the authentic user's decrypted login IP recorded at authentication time (`$data['ip']`), preventing Cloudflare Anycast edge proxies or viewer reverse proxy IPs from colliding with or overwriting remote administrator IPs.
- **Fallback Session Integrity**: Preserves authentic origin IP telemetry across all core session token iterations and password reset audit trails.

### 17. Multi-Factor Authentication (2FA) & Login Hardening
- **Pure PHP RFC 6238 TOTP Engine**: Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
- **Native `wp-login.php` Interception**: Displays a responsive, branded two-factor verification challenge screen supporting rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
- **AES-256-GCM AEAD Encrypted User Secrets**: Encrypts user TOTP secrets (`_wcp_2fa_secret`) at rest in `wp_usermeta` via the Secret Vault with 128-bit authentication integrity tags and transparent in-memory runtime decryption.
- **Brute Force Rate-Limiter**: Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.
- **Administrator 2FA Governance & Policy Enforcement**:
  - View all administrator accounts with their profile avatars, 2FA status, and compliance state.
  - 1-click Emergency Unlock & Disable 2FA for locked-out administrators.
  - 1-click Credential Reset & QR Code Delivery Modal for remote enrollment.
  - Mandatory 2FA Enforcement Policies: Force Immediately, Grace Period Countdown, or Remind on Next Login.
  - Emergency Backup Codes (`.txt`) Download Guard with auto-download prior to activation.
  - Post-setup Backup Code Regeneration with real-time remaining code counters.

### 18. Dedicated Notification Center & Granular 32+ Event Alert Matrix
- **Dedicated Administrative Notification Hub (`admin.php?page=wcp-scanner-notifications`)**: Full-page notification operations hub accessible via direct deep-link from Settings, Firewall, and email footers.
- **32+ Granular Security Events Across 8 Categories**: Core Scans & Threats, Plugin Self-Defense, Cloudflare & WAF Defense, Authentication & Access Security, File Integrity Monitoring, Vulnerabilities & CVE Feeds, Database Backups & Vault, and DevSecOps & AI Forensics.
- **Independent Dual-Channel Matrix**: Independent toggle switches for Email (`wp_mail`) and DevSecOps Webhooks (Slack, Discord, ClickUp, Asana, Generic JSON) per event.
- **Granular Default Baseline**: By default, only two critical high-priority events are activated ("Plugin Deactivated" and "Critical / High Threats Detected"), while all other 30+ events remain cleanly silenced until customized.
- **Executive Obsidian Email Template**: Branded obsidian styling (`#0b1120`), glowing priority badges, client IP/device metadata detection, and Schema.org (`SecurityIncident`) JSON-LD structured data for LLM inbox summarization.
- **1-Click Test Delivery**: Test buttons on each event trigger live test payloads via `/notifications/test-event`.

### 19. Enterprise HTTP Security Headers & 1-Click Site Hardening
- **Enterprise Security Headers Dispatcher**: Injects `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock**: Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense**: Blocks author archive scraping (`/?author=1`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`). Strips WordPress version meta tags and asset query strings (`?ver=`).
- **Sensitive System File Probe Shield**: Returns 403 Forbidden on requests attempting to access `.env`, `.git`, `.htaccess`, `.sql`, `composer.json`, and backup archives.
- **1-Click Hardening Presets**: Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (`A+`, `A`, `B`, `C`).

### 20. Bot Recon Defense & AI Scraper Shield
- **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
- **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) at the WAF level.
- **Dynamic Virtual `robots.txt` Injection**: Automatically generates and injects standard AI bot Disallow directives into virtual `robots.txt`.

### 21. Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude)
- **Supported AI Forensic Providers**: Google Gemini (3.8 Flash, 2.5 Flash, 1.5 Pro), OpenAI (GPT-6.1 Sol, GPT-4o, GPT-4o-mini), and Anthropic Claude (Sonnet 5.5, 3.7 Sonnet, 3.5 Haiku).
- **WordPress 7.0+ Core AI Client Bridge**: Automatically detects and leverages WordPress 7.0+ native `wp_ai_client()` site-level AI credentials for zero-configuration AI forensics.
- **1-Click AI Code Forensics Modal**: Decodes obfuscated scripts in seconds, assesses threat confidence (0–100%), explains exploit mechanics, and generates surgical clean code patches.

### 22. Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation)
- **Native JSON-RPC 2.0 Agentic Integration**: Bridges external AI coding agents (Claude Desktop, Cursor IDE, Antigravity, custom LLM agents) with WordPress security operations over standard JSON-RPC 2.0 and Bearer token authentication.
- **7 First-Class SecOps Tools**: `wcp_get_site_health`, `wcp_list_findings`, `wcp_get_finding_detail`, `wcp_list_quarantined_files`, `wcp_get_waf_stats`, `wcp_trigger_scan`, and `wcp_whitelist_finding`.
- **Granular Permission Scopes**: Enforce **Read-Only (Observation)** mode to allow AI agents to safely inspect and diagnose without write privileges, or **Full Remediation (Read + Write)** for automated incident response.
- **Sliding-Window Rate Limiting**: Per-token rate limiter configurable from 30 to 300 requests/minute to protect origin servers from agentic query floods.
- **Persistent Ring-Buffer Execution Audit Trail**: Logs every incoming MCP agent call with timestamp, tool name, client IP, payload preview, execution time, and response status in a persistent 150-event ring buffer (`wcpscan_mcp_audit_log`).
- **1-Click Ready Client Configs**: Ready-to-copy JSON configuration snippets formatted specifically for Cursor (`cursor_mcp.json`) and Claude Desktop (`claude_desktop_config.json`).

### 23. Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation)
- **Pure AES-256-GCM Authenticated Encryption (AEAD)**: All sensitive third-party API credentials, webhook endpoints, and infrastructure tokens are encrypted at rest before being saved to `wp_options`.
- **128-bit Cryptographic Authentication Tags**: Cryptographically verifies ciphertext integrity prior to decryption, completely preventing bit-flipping vulnerabilities and CBC padding oracle attacks.
- **Two-Phase Commit Key Rotation Orchestrator (`VaultRotator`)**: Robust state machine (`idle` → `preparing` → `migrating` → `verifying` → `committed`) manages zero-downtime key rotation with dual-key background decrypt fallback and atomic snapshot rollbacks.
- **Dynamic 256-bit Key Derivation**: Derives keys from `WCP_VAULT_KEY` environment variables, `wp-config.php` constants, or cryptographic SHA-256 hashes of 4 WordPress core salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`, `SECURE_AUTH_SALT`).

### 24. Unified WCP Vault Console (4 Consolidated Isolation & Recovery Facilities)
- **Centralized Security Vault Page (`wcp-vault`)**: Consolidates all site isolation, backup, and encryption primitives into a single high-performance interface with live telemetry and direct deep-linking.
- **Facility 1 — File Quarantine Isolation Vault**: View, inspect, restore, or permanently purge quarantined rogue scripts and backdoors preserved with SHA-256 integrity hashes in `.htaccess`-protected storage.
- **Facility 2 — Database Snapshot & Point-in-Time Recovery Vault**: Create on-demand Gzip-compressed `.sql.gz` database snapshots, inspect byte-accurate archive sizes, and download for offsite disaster recovery.
- **Facility 3 — Pre-Cure Safety Rollback & Remediation Vault**: Inspect safety diffs and restore modified files prior to Auto-Cure or webshell stripping actions.
- **Facility 4 — Secret & Cryptographic Key Vault**: Real-time health metrics of the AES-256-GCM AEAD encryption subsystem, including self-healing dual-key decryption fallback, stale rotation lock recovery, and 1-click diagnostic reset.

### 25. On-Demand Database Backup Vault (`.sql.gz`)
- **1-Click Database Backup Vault**: Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression, size metadata indexing, and secure browser downloads.
- **Secure File Storage**: Guarded by Apache/LiteSpeed `.htaccess` (`Require all denied`) and silent PHP index files.

### 26. High-Precision Microsecond Telemetry & Diagnostics
- **Microsecond Scan Duration Tracking**: Database schema upgraded with `started_at` (`datetime(3)`), `completed_at` (`datetime(3)`), and `duration_ms` (`int(11)`) columns to guarantee sub-second and millisecond tracking across all scan types.
- **Timezone-Aware Accuracy**: Replaced timezone-clashing server queries with WordPress `wp_timezone()` arithmetic, eliminating drift between server clocks and site timezones.
- **Real-Time Environment Diagnostics**: Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`), MySQL collation, database size, and OS architecture.
- **Historical Audit Logs**: Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

### 27. Behavioral Baseline & Attack Chain Correlation
- **Behavioral Drift Detection**: Tracks alterations in critical site metadata, administrator counts, PHP execution options, and file counts against historic baselines.
- **Attack Chain Timeline**: Correlates disparate security events (failed login brute-force → backdoor upload → cron modification) into a unified chronological breach narrative with estimated blast radius scoring.

### 28. Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking
- **1-Click Intelligent Suppression**: Instantly suppress known false-positives with a single click. Automatically computes SHA-256 cryptographic checksums of the target file to lock the rule to that exact file version, with a 90-day auto-review safety period.
- **Collapsible Power-User Drawer**: Advanced controls to customize rule match types (Exact SHA-256 Hash vs File Path vs Pattern Signature), adjust expiration periods (30 days, 90 days, 1 year, or Permanent), and log administrative audit rationale.
- **Segmented Findings Status Filtering**: Instantly toggle between **Active Threats**, **Whitelisted / Ignored**, and **All Findings** with dynamic count badges, keeping active security views clean and actionable.

### 29. Data Privacy, Non-Destructive Operations & Clean Uninstall Lifecycle
- **Automated Pre-Action Safety Backups**: Every Auto-Cure, Quarantine, and Remediation action creates an automated safety snapshot in the local vault before modifying files.
- **Zero Tracking or Analytics**: The plugin does NOT track, collect, store, or sell any personal data, analytics, or browsing habits.
- **100% On-Premise Execution**: Core scans, heuristic checks, file integrity monitoring, brute-force defenses, 2FA generation, and firewall evaluation run 100% locally within your PHP environment.
- **Clean 6-Table Database Purge on Uninstall (`uninstall.php`)**: When "Auto-Remove All Data on Uninstall" is active (default), deleting the plugin automatically drops all 6 custom database tables (`wcpscan_scans`, `wcpscan_scan_issues`, `wcpscan_scan_files`, `wcpscan_quarantine`, `wcpscan_firewall_logs`, `wcpscan_login_history`), purges user meta, clears transients, deletes options, removes crons, and safely purges the upload storage folder.

### 30. Dual-Theme Design System (High-Contrast White Mode & Dark Obsidian)
- **Flawless White (Light) Mode Parity**: Custom semantic token architecture (`var(--wcp-bg-panel)`, `var(--wcp-text-primary)`, `var(--wcp-border)`) guarantees maximum readability, deep contrast, and crisp table borders (`#ffffff`, `#f8fafc`, `#e2e8f0`, `#0f172a`), eliminating washed-out text or unreadable badges.
- **Midnight Obsidian Dark Mode**: Cyberpunk-inspired deep midnight palette (`#090d16` canvas, `#0f172a` cards, `#1e293b` borders) with vibrant neon accents and glowing status indicators.
- **1-Click Theme Switcher**: Instant toggle between White Mode and Dark Mode saved in local storage.

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
