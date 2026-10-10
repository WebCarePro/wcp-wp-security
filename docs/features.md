# WCP Security Scanner - Comprehensive Features & Architecture

An enterprise-grade, lightweight WordPress security, malware detection, integrity auditing, active firewall, session sentinel, and site forensic scanner built with a modern React admin interface and high-performance, memory-safe PHP auditing engines.

---

## 🏗️ Architecture & Core Design Principles

- **Decoupled Architecture:** High-performance PHP REST API backend adhering to WordPress Core security standards, paired with a modern React 18 & TypeScript single-page application (SPA) administrative dashboard.
- **Zero Runtime Bloat:** Production builds compiled strictly into native WordPress JavaScript/CSS bundles (`build/index.js`), completely free of runtime `node_modules` dependencies on client servers.
- **Memory-Safe Batch Processing:** File inspection and heuristic scanning run in chunked batches (configurable from 25 to 200 files per cycle) with memory overrides and execution timeouts to guarantee zero server crashes even on resource-constrained shared hosting environments.
- **Strict WordPress.org Directory Compliance:**
  - **Non-destructive core protection:** Never overwrites or deletes core WordPress files directly; routes repairs through native WordPress update mechanisms.
  - **Safe, isolated data storage:** Audit logs, quarantine vaults, and compressed database backups reside inside `wp-content/uploads/wcp-security-scanner/` guarded by `.htaccess` (`Require all denied`) and silent `index.php` gatekeepers.
  - **Directory traversal boundary enforcement:** Strict path normalization with trailing separators guarantees all quarantine operations stay within legitimate site boundaries.
  - **Clean lifecycle uninstall:** Complete database table and file system cleanup via standard `uninstall.php`.

---

## 🚀 Complete Production Features (v1.5.0 Release)

### 1. Multi-Vector Security & Malware Scanning Engine
- **Heuristic PHP Code Analysis**:
  - Scans for webshells, backdoors, Trojan droppers, and remote access tools (including variants of c99, r57, b374k, WSO, and China Chopper).
  - Detects complex obfuscation layers: `eval(base64_decode())`, nested `gzinflate()`, `str_rot13()`, dynamic variable functions (`$func()`), hexadecimal/octal encodings, and malicious file header tricks (GIF89a webshell headers).
  - Suspicious function call profiling: identifies unapproved invocations of `shell_exec`, `passthru`, `system`, `proc_open`, `popen`, and `curl_exec`.
- **WordPress Core Cryptographic Integrity Scanner**:
  - Live cryptographic MD5 checksum validation against the official WordPress.org Core API for `wp-admin`, `wp-includes`, and root files.
  - Identifies tampered core files, injected bootstrap code (`index.php`, `wp-blog-header.php`), missing core files, and rogue foreign scripts placed inside system directories.
- **Plugin & Theme Integrity Verification**:
  - Deep-audits active and inactive themes and plugins for unauthorized file modifications, rogue entry points, injected spam doorways, and orphaned scripts.
- **Uploads Executable & Script Shield**:
  - Recursively audits the entire `wp-content/uploads/` directory for prohibited script execution vectors.
  - Detects hidden script extensions (`.php`, `.phtml`, `.php5`, `.phps`, `.sh`, `.py`, `.pl`, `.cgi`).
  - Identifies disguised double-extension bypasses (e.g., `avatar.jpg.php`, `invoice.pdf.phtml`).
  - Detects unauthorized `.htaccess` files placed inside upload folders designed to re-enable PHP execution.
- **Database Threat & Content Injection Scanner**:
  - Deep scanning across `wp_posts`, `wp_options`, `wp_users`, and `wp_comments`.
  - Scans for stored cross-site scripting (Stored XSS), malicious external `<script>` tags, hidden `<iframe>` embeds, and phishing redirects.
  - Detects pharmaceutical spam links, hidden keyword stuffing, base64-encoded post content, and unauthorized admin user records in `wp_users`.
- **Crontab & Scheduled Task Auditing**:
  - **Linux System Crontab Audit**: Inspects system cron tabs (`crontab -l`, `/var/spool/cron`, `/etc/cron.*`) for unauthorized `curl | bash`, `wget | sh` piped commands, reverse shells, and persistence scripts.
  - **WordPress Virtual WP-Cron Audit**: Analyzes all registered WordPress virtual cron hooks for suspicious callbacks, anomalous recurrence intervals, and orphaned plugin cron tasks.
- **User Accounts & Privilege Security**:
  - Audits administrator accounts for weak configurations, default usernames (`admin`, `administrator`), dormant superusers, and suspicious newly spawned administrator accounts.
- **Server Configuration & Hardening Safeguards**:
  - Audits `wp-config.php` and `.htaccess` file permissions (ensuring `0644` or `0600` flags).
  - Checks PHP debug exposure flags (`WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY`).
  - Validates protections preventing public HTTP access to sensitive files (`.env`, `.git`, `.user.ini`, `.sql` dumps, and backup archives).

---

### 2. Software Intelligence & Vulnerability Management (CVE Engine)
- **Curated CVE Advisory Database**:
  - Audits installed WordPress Core, plugins, and active/inactive themes against an offline-resilient, curated CVE vulnerability database.
  - Full vulnerability metadata: CVSS risk scores, severity badges (Critical, High, Medium, Low), affected versions, fixed-in patched versions, and official NIST NVD advisory links.
- **Dedicated "Vulnerabilities & Updates" Dashboard**:
  - Status filters: View All, Vulnerable Components (CVEs), Outdated Only, or Clean & Up-to-Date.
  - Component type filters: WordPress Core, Installed Plugins, Installed Themes.
  - Quick action links: Direct 1-click update action links to native WordPress core update workflows.
  - Interactive CVE Forensic Modal: Explains specific exploit vectors, attack types (RCE, SQLi, Auth Bypass, XSS), and recommended mitigation steps.

---

### 3. Threat Forensics, Code Inspection & Quarantine Vault
- **Interactive Dark-Theme Code Viewer Modal**:
  - In-browser code inspection modal (`#090d16` modern terminal palette) with line numbering, syntax highlighting, and text search/filtering.
  - Automatic scroll-to-line highlight immediately focusing on the exact line and snippet flagged by the heuristic engine.
- **Post & Database Content Inspector**:
  - Dedicated inspector modal for database post/page threats.
  - Displays post metadata (ID, title, author, post status, modified date), raw threat snippet previews, direct WordPress block editor links, and live post permalinks.
- **Secure Quarantine Vault**:
  - Isolates flagged malicious files into a secure, protected quarantine directory (`wp-content/uploads/wcp-security-scanner/quarantine/`) guarded by `.htaccess` execution denial.
  - Stores SHA-256 cryptographic hashes, original filesystem permissions, and timestamp metadata.
  - Instant 1-click safe file restoration back to original directory or permanent unrecoverable deletion.

---

### 4. Database Vault & Environmental Diagnostics
- **One-Click Database Backup Vault**:
  - Instant on-demand database backup creation with automatic Gzip compression (`.sql.gz` or uncompressed `.sql`).
  - Vault management interface: displays backup creation date, uncompressed size, compressed archive size, and 1-click secure download.
- **Server & PHP Environment Diagnostics**:
  - Real-time diagnostic breakdown: PHP version, memory limit, max execution time, SAPI interface, active security extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`).
  - Database status: MySQL version, character set collation, and total database size.
  - Operating system architecture and filesystem directory permission status (`wp-content`, `uploads`, root).
- **Historical Audit Logs**:
  - Detailed chronological log of past scans with durations, total files audited, risk scores, and granular issue categorization.
  - Searchable log viewer with quick log purge actions.

---

### 5. Settings, Automation & AI Forensics Hub
- **Automated Scheduled Scans Engine**:
  - Recurring scan frequencies powered by WP-Cron: **Hourly**, **Twice Daily**, **Daily**, or **Once Weekly**.
  - Off-peak execution scheduling: Configure precise execution times (HH:MM server time) to run intensive scans during low-traffic periods.
  - Configurable scan scope: Select between Quick Plugins & Themes scan, Deep Full-Site audit, Core Integrity verification, or Uploads audit.
- **Real-Time Email Security Alerts**:
  - Instant HTML email alerts dispatched immediately upon detection of High or Critical severity threats and zero-day CVE advisories.
  - Configurable minimum severity thresholds (Critical Only, High & Critical, All Findings).
  - Customizable alert recipient email addresses.
- **AI Intelligence Integration & Threat Forensics**:
  - Multi-provider AI engine support:
    - **Google Gemini** (Gemini 3.8 Flash, Gemini 2.5 Flash, Gemini 1.5 Pro).
    - **OpenAI** (GPT-6.1 Sol, GPT-6 Astra, GPT-4o, GPT-4o-mini).
    - **Anthropic Claude** (Claude Sonnet 5.5, Claude 3.7 Sonnet, Claude 3.5 Sonnet).
  - **WordPress 7.0+ Core AI Client Bridge**:
    - Automatically detects and leverages WordPress 7.0+ native `wp_ai_client()` site-level AI credentials for zero-configuration AI forensics.
  - **1-Click AI Code Forensics Modal**:
    - Decodes obfuscated scripts in seconds, determines whether suspicious code is legitimate or malicious, calculates confidence scores, and generates surgical remediation patches.
- **Engine Performance & Developer Safeguards**:
  - Configurable batch sizes (25 to 200 files/batch).
  - Temporary memory overrides (256 MB, 512 MB, 1024 MB).
  - Heuristic file size thresholds and custom path/pattern exclusions.
- **Settings Import & Export**:
  - 1-click JSON configuration export and import for seamless fleet replication.
- **Data Privacy & Clean Uninstall Lifecycle**:
  - Standard WordPress `uninstall.php` automatically drops all 5 database tables (`wp_wcp_scans`, `wp_wcp_scan_issues`, `wp_wcp_scan_files`, `wp_wcp_quarantine`, `wp_wcp_firewall_logs`), deletes options/transients, and purges secure uploads.

---

### 6. Web Application Firewall (WAF Lite) & Virtual Patching
- **Early Request Inspection**: Runs at `plugins_loaded` (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
- **Virtual Patching Engine**: Proactive rule-based shielding against known CVE exploits before official plugin patches are available.
- **Malicious Payload Inspection**: Blocks SQL Injection (`UNION SELECT`, `benchmark`, `information_schema`), Cross-Site Scripting (`<script>`, handlers), Path Traversal (`../`, `php://filter`), PHP script tags (`<?php`, `eval`), and XML-RPC exploitation.
- **Smart Cloudflare & Coexistence**: Automatic Real-IP extraction from `HTTP_CF_CONNECTING_IP` with proxy validation. Coexistence negotiation with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode.
- **Branded Dark 403 Screen**: Responsive dark block screen with unique incident tracking IDs and real-time blocked incident streams.

---

### 7. Real-Time File Integrity Monitoring (FIM) & Code Diff Viewer
- **Filesystem Modification Tracker**: Audits files modified or added within customizable timeframes (24h, 48h, 7d, 30d) across Core, Plugins, Themes, and Uploads.
- **Custom & Premium Component Recognition**: Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to eliminate false-positive alarms.
- **Visual Code Diff Viewer**: Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org SVN release mirrors.

---

### 8. One-Click Malware Remediation / Auto-Cure Engine
- **Automated Webshell Stripping**: 1-click surgical neutralization of prepended malware headers while preserving legitimate code integrity with PHP tokenizer syntax validation.
- **Automated Clean Restoration**: Replaces infected or tampered files with fresh, bit-for-bit verified copies fetched directly from official WordPress.org repositories.
- **Safety Backups & Rollback Vault**: Automated timestamped backups before all remediation actions with 1-click instant rollback.

---

### 9. Cloud Threat Intelligence & Community Botnet IP Blacklists
- **Live CVE Feed & Site Correlation**: Real-time synchronization of critical WordPress vulnerability catalogs with severity badges. Cross-examines zero-day definitions against installed components with status badges (`Installed — Vulnerable`, `Installed — Patched`, `Global Virtual Shield`).
- **Malicious IP & Botnet Blacklists**: Live synchronization with global malicious IP databases (Blocklist.de, FireHOL, Ipsum) with high-speed in-memory O(1) hash map and CIDR bitwise matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
- **IP Reputation Diagnostic Tool**: Built-in checker to test client or visitor IPs against the active threat database.

---

### 10. Multi-Factor Authentication (2FA) & Login Hardening
- **Time-Based One-Time Password (TOTP) 2FA**: Native RFC 6238 TOTP engine (Google Authenticator, Authy, 1Password) with single-use emergency backup recovery codes.
- **Brute Force Defense**: IP-based failed login attempt tracking with automated temporary lockouts and countdown notices.
- **Native wp-login.php Interception**: Displays a responsive, branded two-factor verification challenge screen.

---

### 11. HTTP Security Headers Engine & 1-Click Site Hardening
- **Enterprise Security Headers**: Dispatches `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock**: Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense**: Blocks author archive scraping (`/?author=1`, `/?author=admin`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`). Strips WordPress version meta tags and asset query strings (`?ver=`).
- **Sensitive System File Probe Shield**: Returns 403 Forbidden on requests attempting to access `.env`, `.git`, `.htaccess`, `.sql`, `composer.json`, and backup archives.
- **1-Click Hardening Presets**: Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (A+, A, B, C).

---

### 12. Active Session Sentinel & Anti-Hijack Defense
- **Administrative Session Telemetry**: Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Strict IP Lock & Cookie Replay Defense**: Detects and revokes hijacked sessions if client IP shifts during an active login.
- **Single Concurrent Session Policy**: Invalidate prior sessions when logging in from a new machine to prevent credential sharing or undetected parallel access.
- **Configurable Idle Inactivity Revocation**: Automatically logs out abandoned admin sessions after configurable periods (default: 120m).
- **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

---

### 13. Database Micro-Anomaly & Rogue Administrator Trap
- **Stealth User Infiltration Detection**: Audits `wp_users` against `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
- **Ghost & Orphaned Capability Hunting**: Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap**: Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe**: Recursively scans `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden in transient names.

---

### 14. Bot Recon Defense & AI Scraper Shield
- **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
- **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) at the WAF level.
- **Dynamic Virtual robots.txt Injection**: Automatically generates and injects standard AI bot Disallow directives into virtual `robots.txt`.

---

### 15. Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
- **Active Runtime Memory Hook Audit**: Uses reflection to inspect active runtime hook callbacks registered in `$wp_filter` across high-risk lifecycle actions (`authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`).
- **Anonymous Closure & Credential Sniffer Detection**: Flags anonymous `Closure` functions attached to sensitive authentication and login hooks that could steal passwords.
- **External Rootkit & Uploads Hook Traps**: Detects hook callbacks originating outside WordPress root (`auto_prepend_file` or system rootkits) and callbacks executing inside `wp-content/uploads/` (webshell callbacks).
- **Dangerous Native Function Registration Defense**: Detects dangerous native PHP functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`) attached directly as WordPress filter callbacks.

---

### 16. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n)
- **Real-Time Security Notifications**: Delivers rich Block Kit (Slack) and Embed (Discord) alert cards when critical vulnerabilities are found, files are altered, or attacks are blocked.
- **Automated DevSecOps Ticket Dispatch**: Automatically converts security threats, malware discoveries, and FIM file changes into actionable task tickets in ClickUp and Asana with priority flags, tags, and direct dashboard URLs.
- **Custom Enterprise Automation Webhook**: Dispatches structured REST JSON payloads to Zapier, Make.com, n8n, or custom SIEM pipelines to automate incident response workflows.
- **Attack Flood Protection**: Built-in 60-second rate-limiting prevents channel notification spamming during brute-force or DDoS storms.
- **Live Webhook Testing API**: 1-click test buttons inside Scanner Settings to verify webhook URL configuration instantly with real-time delivery status feedback.

---

### 17. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan Compatible)
- **Zero-Resource Threat Interception**: Stops automated attacks at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
- **1-Click Free Plan Cloudflare Edge Rules Deployment**:
  - *XML-RPC & Amplification Shield*: Drops pingback and brute force spray targeting `/xmlrpc.php` at the edge.
  - *Sensitive Files & Dotfiles Armor*: Rejects probes for `wp-config.php`, `.env`, `.git`, `composer.json`, and database dumps before disk access.
  - *Uploads Directory Webshell Trap*: Direct edge block on HTTP execution of scripts (`.php`, `.sh`, `.py`, `.exe`) in `wp-content/uploads/`.
  - *Author Enumeration Recon Shield*: Prevents username harvesting via `?author=1` and `/wp-json/wp/v2/users`.
  - *Login Portal Threat Defense*: Deploys non-intrusive Cloudflare Turnstile / Managed Challenge for automated bots targeting `wp-login.php`.
- **Cloudflare Free Rate Limiting Integration**: Deploys an edge rate limiter on `wp-login.php` (10 requests / 10s per IP) to neutralize credential stuffing.
- **Bi-Directional WAF Auto-Ban Sync**: When WCP Local WAF detects high-threat attacks (SQL injection, webshell uploads, directory traversal), it automatically pushes the attacking IP to Cloudflare Edge IP Access Rules.
- **1-Click CDN Cache Purge**: Instant global edge cache purge from WordPress admin with zero latency.

---

### 18. Cryptographic Secret Vault & Database Encryption at Rest
- **Military-Grade AES-256-CBC Encryption**: All sensitive third-party API tokens and infrastructure credentials (Cloudflare API Bearer Tokens, Cloudflare Zone IDs, OpenAI API keys, Google Gemini API keys, Anthropic Claude API keys) are encrypted using AES-256-CBC with `OPENSSL_RAW_DATA` before being saved to `wp_options` under `wcp_scanner_settings`.
- **Dynamic 256-bit Key Derivation**: Encryption keys are dynamically derived via SHA-256 using site-specific WordPress secret salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`), ensuring ciphertexts cannot be decrypted outside the host site.
- **Per-Record Cryptographic Initialization Vectors**: Every encryption call utilizes a unique, cryptographically random 16-byte initialization vector (`random_bytes(16)`), meaning the exact same secret produces a completely different ciphertext on each save.
- **Zero Plaintext Database Exposure**: Database backups, `.sql.gz` snapshots, staging migrations, and unauthorized database access (via SQLi or compromised phpMyAdmin) reveal only ciphertext strings prefixed with `wcp_enc:`.
- **Transparent In-Memory Decryption**: `SettingsManager::get()` and `SettingsManager::get_settings()` transparently decrypt credentials in memory during authorized runtime API calls with zero database or hook overhead.
- **UI Password Masking & Visibility Controls**: Administrative interfaces display credentials masked as bullets (`••••••••`) by default, backed by interactive Show/Hide eye toggles and a verified `✓ Encrypted in Vault` badge.

---

### 19. Privacy, Zero Telemetry & Data Sovereignty Architecture
- **Cryptographic Encryption at Rest for All Sensitive Data**: All API keys, tokens, and sensitive integration credentials are encrypted using AES-256-CBC with cryptographically random IVs before database writes. They are never saved in plain text.
- **Zero Remote Tracking & Telemetry**: The plugin collects zero analytics, visitor metrics, browsing activity, or server telemetry.
- **No Sensitive Data Exfiltration**: Never transmits passwords, database records, client data, wp-config credentials, or sensitive files to external servers or cloud services.
- **100% On-Premise Core Processing**: All scanning algorithms, heuristic analyzers, file integrity checks, brute force defenders, 2FA cryptographic calculations, and firewall rules operate locally within your WordPress PHP and MySQL runtime.
- **Explicit Administrator Consent for APIs**: External APIs (such as WordPress.org checksums, public threat feeds, optional AI analysis, Cloudflare edge controls, or webhook alerts) only connect when explicitly enabled and initiated by the administrator.

