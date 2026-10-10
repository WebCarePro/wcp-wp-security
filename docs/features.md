# WCP Security Scanner - Comprehensive Features & Roadmap

An enterprise-grade, lightweight WordPress security, malware detection, integrity auditing, and site forensic scanner built with a modern React admin interface and high-performance, memory-safe PHP auditing engines.

---

## 🏗️ Architecture & Core Design Principles

- **Decoupled Architecture:** High-performance PHP REST API backend adhering to WordPress Core security standards, paired with a modern React 18 & TypeScript single-page application (SPA) administrative dashboard.
- **Zero Runtime Bloat:** Production builds compiled strictly into native WordPress JavaScript/CSS bundles (`build/index.js`), completely free of runtime `node_modules` dependencies on client servers.
- **Memory-Safe Batch Processing:** File inspection and heuristic scanning run in chunked batches (configurable from 25 to 200 files per cycle) with memory overrides and execution timeouts to guarantee zero server crashes even on resource-constrained shared hosting environments.
- **Strict WordPress.org Directory Compliance:**
  - Non-destructive core protection: Never overwrites or deletes core WordPress files directly; routes repairs through native WordPress update mechanisms.
  - Safe, isolated data storage: Audit logs, quarantine vaults, and compressed database backups reside inside `wp-content/uploads/wcp-security-scanner/` guarded by `.htaccess` (`Require all denied`) and silent `index.php` gatekeepers.
  - Directory traversal boundary enforcement: Strict path normalization with trailing separators guarantees all quarantine operations stay within legitimate site boundaries.
  - Clean lifecycle uninstall: Complete database table and file system cleanup via standard `uninstall.php`.

---

## 🚀 Current Production Features (Available in v1.4.1)

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

### 5. Settings, Automation & AI Forensics Hub (v1.4.0+)
- **Automated Scheduled Scans Engine**:
  - Recurring scan frequencies powered by WP-Cron: **Hourly**, **Twice Daily**, **Daily**, or **Once Weekly**.
  - Off-peak execution scheduling: Configure precise execution times (HH:MM server time) to run intensive scans during low-traffic periods.
  - Configurable scan scope: Select between Quick Plugins & Themes scan, Deep Full-Site audit, Core Integrity verification, or Uploads audit.
- **Real-Time Email Security Alerts**:
  - Instant HTML email alerts dispatched immediately upon detection of High or Critical severity threats and zero-day CVE advisories.
  - Configurable minimum severity thresholds (Critical Only, High & Critical, All Findings).
  - Customizable alert recipient email addresses (supports single or comma-separated administrator lists).
  - Scan completion summary reports and periodic security digests.
- **AI Intelligence Integration & Threat Forensics**:
  - Multi-provider AI engine support:
    - **Google Gemini** (Gemini 3.8 Flash, Gemini 2.5 Flash, Gemini 1.5 Pro).
    - **OpenAI** (GPT-6.1 Sol, GPT-6 Astra, GPT-4o, GPT-4o-mini).
    - **Anthropic Claude** (Claude Sonnet 5.5, Claude 3.7 Sonnet, Claude 3.5 Sonnet).
  - **WordPress 7.0+ Core AI Client Bridge**:
    - Automatically detects and leverages WordPress 7.0+ native `wp_ai_client()` site-level AI credentials, providing zero-configuration out-of-the-box AI forensics while maintaining backward compatibility with direct API keys.
  - **1-Click AI Code Forensics Modal**:
    - Decodes obfuscated scripts in seconds, determines whether suspicious code is legitimate or malicious, calculates confidence scores, and generates surgical remediation patches.
  - **Live Connection Testing**:
    - 1-click "Test AI Connection" ping verifying API key validity and provider responsiveness before saving.
  - **Dynamic Model Catalog Updates**:
    - Auto-fetches current AI model catalogs and specs directly from providers.
- **Engine Performance & Developer Safeguards**:
  - **Configurable Batch Sizes**: 25 files/batch (shared hosting), 50 files/batch (standard), 100 files/batch (VPS), or 200 files/batch (turbo).
  - **Temporary Memory Overrides**: 256 MB, 512 MB, or 1024 MB temporary allocations during active scans.
  - **Heuristic File Size Thresholds**: Configurable maximum file size (KB) for regex parsing to prevent memory exhaustion on giant media or log files.
  - **Custom Path & File Exclusions**: Rule-based exclusion list supporting custom paths and directory glob patterns (e.g., `wp-content/cache/*`, `node_modules/*`).
  - **Security Tweaks**: 1-click toggles to hide WordPress Generator version tags and block public access to sensitive files (`.env`, `.git`, `.sql`).
- **Settings Import & Export**:
  - 1-click JSON configuration export to easily replicate uniform security profiles across multi-site agency portfolios.
  - 1-click JSON import with strict validation and error handling.
  - Safe "Reset to Factory Defaults" button with confirmation state.
- **Data Privacy & Clean Uninstall Lifecycle**:
  - Standard WordPress `uninstall.php` compliance.
  - **Auto-Remove All Data on Uninstall** (enabled by default): Automatically drops all 4 custom database tables (`wp_wcp_scans`, `wp_wcp_scan_issues`, `wp_wcp_scan_files`, `wp_wcp_quarantine`), deletes options, clears crons, and removes the `uploads/wcp-security-scanner/` directory upon plugin deletion.
  - High discoverability across the Settings UI:
    - Dedicated **"Data & Cleanup"** tab with itemized asset purge breakdown and WordPress lifecycle safety documentation.
    - Inline toggle card inside the **"Engine & Hardening"** tab.
    - Quick-status badge in the Settings page top header.

---

## 🚀 Implemented Features (v1.5.0 Release)

### 1. Web Application Firewall (WAF) Lite & Virtual Patching
- **Virtual Patching Engine**: Proactive rule-based shielding against known CVE exploits before third-party plugin authors release official patches.
- **Malicious Payload Inspection**: Real-time filtering of incoming `GET` and `POST` request parameters for SQL injection signatures (`UNION SELECT`), Cross-Site Scripting (`<script>`, inline handlers), path traversal attempts (`../`), and PHP opening tags (`<?php`).
- **Smart Cloudflare & Coexistence**: Automatic Cloudflare Real-IP extraction from `HTTP_CF_CONNECTING_IP` with proxy validation. Coexistence negotiation with Wordfence, Sucuri, and Solid Security.

### 2. Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer
- **Filesystem Modification Tracker**: Background monitor flagging files modified or added within customizable timeframes (24h, 48h, 7d, 30d) across Core, Plugins, Themes, and Uploads.
- **Visual Code Diff Viewer**: Git-style side-by-side and unified visual diffs comparing altered files against official WordPress.org SVN release mirrors.

### 3. One-Click Malware Remediation / Auto-Cure
- **Automated Webshell Stripping**: 1-click automated neutralization of prepended malware headers while preserving legitimate code integrity with PHP syntax validation.
- **Automated Clean Restoration**: Replaces infected or tampered files with fresh, bit-for-bit verified copies fetched directly from official WordPress.org repositories.
- **Safety Backups & Rollback Vault**: Automated timestamped backups before all remediation actions with 1-click instant rollback.

### 4. Cloud Threat Intelligence & Community Blacklists
- **Live CVE Feed Synchronization**: Real-time synchronization of critical WordPress vulnerability catalogs with severity badges and virtual patching rules.
- **Malicious IP & Botnet Blacklists**: Live synchronization with active global malicious IP databases (Blocklist.de, FireHOL, Ipsum) with high-speed O(1) hash map and CIDR bitwise memory matching to auto-drop botnet requests at the firewall layer.

### 5. Multi-Factor Authentication & Login Hardening
- **Time-Based One-Time Password (TOTP) 2FA**: Native RFC 6238 TOTP engine (Google Authenticator, Authy, 1Password) with single-use emergency backup recovery codes.
- **Brute Force Defense**: IP-based failed login attempt tracking with automated temporary lockouts and countdown notices.

### 6. DevSecOps Chat Webhook Integrations
- **Slack & Discord Webhook Alerts**: Real-time rich notifications dispatched to team communication channels for critical vulnerability discoveries, unauthorized file integrity modifications, and WAF blocked attacks with built-in attack flood rate-limiting.
