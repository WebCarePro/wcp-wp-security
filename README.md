# WCP Security Scanner

<p align="center">
  <img src="https://webcarespro.com/icon-192.png" alt="WebCare Pro Logo" width="180" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>Enterprise-Grade WordPress Malware Detection, Web Application Firewall (WAF), Core Integrity Auditing & Forensic Threat Intelligence</strong>
</p>

<p align="center">
  <a href="https://wordpress.org/"><img src="https://img.shields.io/badge/WordPress-6.2%2B-blue.svg?logo=wordpress" alt="WordPress Version"/></a>
  <a href="https://www.php.net/"><img src="https://img.shields.io/badge/PHP-8.3%2B-777BB4.svg?logo=php" alt="PHP Version"/></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB.svg?logo=react" alt="React 18"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-GPLv2%2B-green.svg" alt="License"/></a>
  <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67"><img src="https://img.shields.io/badge/Upwork-Top%20Rated%20Plus%20★%20100%25%20JSS-14A800.svg?logo=upwork" alt="Upwork Top Rated Plus"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Release-v1.12.0-orange.svg" alt="Release Version"/></a>
  <a href="#-featured-spotlight-cryptographic-secret-vault--database-encryption-at-rest"><img src="https://img.shields.io/badge/Security-AES--256--CBC%20Vault%20Encrypted-blueviolet.svg?logo=securityscorecard&logoColor=white" alt="Cryptographic Secret Vault"/></a>
</p>

---

## 🛡️ Overview

**WCP Security Scanner** is a modern, high-performance WordPress security, malware detection, and forensic auditing plugin engineered by **[Mir Alamin](https://www.upwork.com/freelancers/~0162afa9a578170c67)** ([WebCare Pro](https://webcarespro.com)). 

Unlike heavy, bloated security plugins that degrade server performance with background overhead, WCP Security Scanner combines **memory-safe PHP batch auditing engines** with a responsive **React 18 single-page administrative dashboard**. It provides deep insight into your file system, WordPress core integrity, plugin and theme source code, database tables, cron jobs, active administrative sessions, runtime memory hooks, and server configurations—giving developers, sysadmins, and site owners complete visibility and control over their WordPress security posture.

---

## 🔐 Featured Spotlight: Cryptographic Secret Vault & Database Encryption at Rest

> [!IMPORTANT]
> **Zero Plaintext Credentials in Database or SQL Backups.**  
> Unlike typical WordPress security plugins that store third-party API keys and incoming webhooks as raw plaintext inside `wp_options`, WCP Security Scanner implements a dedicated **Military-Grade AES-256-CBC Cryptographic Secret Vault**. Every webhook URL, Cloudflare API token, AI key, and 2FA user secret is encrypted at rest using dynamic 256-bit key derivation and per-record randomized 16-byte initialization vectors (`random_bytes(16)`).

### 🛡️ How the Cryptographic Secret Vault Protects Your Infrastructure:

| Security Dimension | Standard WordPress Plugins | WCP Security Scanner Vault |
|:---|:---|:---|
| **Database Storage (`wp_options`)** | ❌ Plaintext strings visible to anyone with database access | ✅ **AES-256-CBC Encrypted Ciphertext** (`wcp_enc:...`) |
| **SQL Dumps & Database Backups** | ❌ Secrets exposed in plain text if backup files are compromised | ✅ **Completely unreadable encrypted strings** |
| **phpMyAdmin & SQLi Exposure** | ❌ Scraped easily via unauthorized database queries | ✅ **Zero plaintext credential leakage** |
| **Encryption Keys & Salting** | ❌ Static hardcoded strings or unencrypted options | ✅ **Derived from WP Salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`)** |
| **Initialization Vectors (IV)** | ❌ Static or reused IV vectors | ✅ **Cryptographically random 16-byte IV generated per record** |
| **Decryption Lifecycle** | ❌ Persisted in plain text on memory or disk | ✅ **Transient in-memory decryption ONLY during active API/webhook calls** |
| **Admin UI Visibility** | ❌ Plaintext input fields or visible strings | ✅ **Auto-masked bullet placeholders (`••••••••`) with 1-click eye toggle** |

---

## 🌟 Comprehensive Feature Catalog (21 Specialized Security Engines)

### 1. Next-Gen Cyber Command Center & Threat Dashboard
- **High-Precision SVG Security Health Meter**: Circular dynamic vector meter displaying site security score (0–100%) with reactive color accents (emerald `#10b981`, blue `#38bdf8`, amber `#f59e0b`, rose `#ef4444`) and letter grades (`A+`, `A`, `B`, `C`, `D`, `F`).
- **Interactive Threat Metric Cubes**: High-contrast summary widgets grouping active threats into 3 primary vectors:
  - *Critical Exploits & Backdoors*: High-severity webshells, injection droppers, and active Trojans.
  - *File Integrity & Code Drift*: Modified WordPress core files, altered plugins, tampered themes, and rogue uploads.
  - *Software Vulnerabilities & CVE Advisories*: Outdated components with documented vulnerabilities and available patches.
  - Includes instant 1-click category filtering to immediately isolate specific threat vectors in the findings table.
- **Audit Command Center Console**: Fast single-click execution controls (Full Deep Audit vs Fast Audit), live engine telemetry indicators, dual-layer animated scan progress bar, and instant stop controls.
- **Interactive Findings Hub**: Modern alternating zebra row styling with severity-tinted accent borders, quick filter pills, monospace path breadcrumbs with 1-click clipboard copy, and real-time instant text search.

### 2. Multi-Vector Security & Deep Malware Scanning
- **Deep Heuristic PHP Code Analysis**: Scans for webshells, backdoors, Trojan droppers, and remote access tools. Detects obfuscation patterns including nested decode wrappers, decompression routines, dynamic variable functions, hex/octal encodings, and malicious file header spoofs.
- **WordPress Core Cryptographic Integrity Engine**: Validates core files against official WordPress.org cryptographic MD5 checksum APIs. Pinpoints modified, injected, tampered, or missing core files in `wp-admin`, `wp-includes`, and root directories.
- **Uploads Executable & Script Shield**: Recursively audits `wp-content/uploads/` for prohibited script extensions (`.php`, `.phtml`, `.phps`, `.sh`, `.py`, `.pl`), disguised double-extensions (`shell.jpg.php`), and rogue `.htaccess` execution overrides.
- **Database Threat & Content Injection Scanner**: Deeply inspects `wp_posts`, `wp_options`, `wp_users`, and `wp_comments` for stored cross-site scripting (Stored XSS), malicious iframes, pharmaceutical spam links, hidden redirect doorways, and unauthorized admin user records.
- **Crontab & Scheduled Task Auditing**: Audits both Linux server-level crontab files (`/var/spool/cron`, `crontab -l`) and WordPress virtual `wp-cron` hooks for unauthorized piped downloads (`curl | bash`, `wget | sh`), reverse shells, and persistence callbacks.
- **User Account & Privilege Security**: Identifies weak administrator passwords, dormant superuser accounts, and suspicious newly created administrator accounts.
- **Server Configuration Hardening Safeguards**: Checks permissions for `wp-config.php` and `.htaccess`, audits `WP_DEBUG` exposure flags, and validates protection against public access to `.env`, `.git`, `.user.ini`, and database dumps.

### 3. Real-Time File Integrity Monitoring (FIM) & Visual Code Diff Viewer
- **Filesystem Change Tracker**: Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
- **Custom & Premium Component Recognition**: Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to prevent false alarms.
- **In-Page Visual Code Diff Viewer Modal (`VisualDiffModal.tsx`)**: Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org release mirrors line-by-line with side-by-side additions and deletions.

### 4. 1-Click Auto-Cure & Surgical Remediation Engine
- **1-Click WordPress Core Auto-Cure**: Restores tampered core files inside `wp-admin`, `wp-includes`, and root directories back to official pristine WordPress.org release code matching the exact site WordPress version, without re-installing all of WordPress.
- **1-Click Plugin & Theme Auto-Cure**: Restores altered or infected plugin and theme files back to authentic, bit-for-bit verified copies fetched directly from WordPress.org release mirrors.
- **1-Click Webshell Stripping**: Surgically neutralizes malicious code headers, obfuscated `eval()`/`base64` wrappers, and backdoor includes while preserving legitimate file code with tokenizer syntax validation.
- **1-Click Scheduled Cron Hook Remediation**: Safely unschedules and purges orphaned or malicious cron hooks (`orphaned_cron_hook`, `malicious_cron_hook_name`) directly from `wp_options:cron` via `wp_clear_scheduled_hook()`.
- **Auto-Cure Safety Backups & Rollback Vault**: Creates timestamped safety backups in a secure directory before every remediation action, enabling instant rollback if needed.
- **Real-Time State Synchronization**: As soon as an issue is cured, the findings table updates to display an `Issue Solved & Restored` status badge and transitions mitigation actions automatically.

### 5. Secure Quarantine Vault & Isolation Architecture
- **Safe Cryptographic Isolation**: Safely isolates infected or unknown files into a protected, `.htaccess`-guarded directory outside executable paths. Preserves original file permissions, timestamps, and SHA-256 cryptographic hashes in `wp_wcp_quarantine`.
- **Intelligent Quarantine Eligibility Safeguards**: Enforces strict boundaries to prevent quarantining critical configuration files (`wp-config.php`, `.htaccess`, `index.php`) and modified official components, ensuring isolation is strictly reserved for rogue and unknown alien files.
- **Quarantine Vault Hub**: Responsive table with horizontal overflow support, 1-click instant file restoration, and permanent vault deletion.

### 6. Software Intelligence & Curated CVE Advisory Database
- **Curated CVE Advisory Database**: Scans installed WordPress core, plugins, and active/inactive themes against an offline-resilient vulnerability database.
- **Granular Vulnerability Metadata**: View CVSS risk scores, severity badges (Critical, High, Medium, Low), affected versions, patched versions, and official NIST NVD reference advisories.
- **Interactive Vulnerabilities Dashboard**: Filter by component type (Core, Plugins, Themes) or status (Vulnerable, Outdated, Clean) with 1-click update links to native WordPress update screens.

### 7. Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
- **Active Runtime Memory Hook Audit**: Uses reflection to inspect active runtime hook callbacks registered in `$wp_filter` across high-risk lifecycle actions (`authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`).
- **Anonymous Closure & Credential Sniffer Detection**: Flags anonymous `Closure` functions attached to sensitive authentication and login hooks that could steal passwords.
- **External Rootkit & Uploads Hook Traps**: Detects hook callbacks originating outside WordPress root (`auto_prepend_file` or system rootkits) and callbacks executing inside `wp-content/uploads/` (webshell callbacks).
- **Dangerous Native Function Registration Defense**: Detects dangerous native PHP functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`) attached directly as WordPress filter callbacks.

### 8. Database Micro-Anomaly & Rogue Administrator Trap
- **Stealth User Infiltration Detection**: Audits `wp_users` against `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
- **Ghost & Orphaned Capability Hunting**: Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap**: Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe**: Recursively scans `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden in transient names.

### 9. Web Application Firewall (WAF Lite) & Virtual Patching
- **Real-Time Request Filtering**: Inspects incoming HTTP payloads at `plugins_loaded` (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
- **Attack Vector Shields**: Blocks SQL Injections (`UNION SELECT`, `information_schema`, `benchmark`), Cross-Site Scripting (XSS scripts and handlers), Path Traversal & LFI (`/etc/passwd`, `php://filter`), PHP code tag injections (`<?php`, `eval`, `base64_decode`, `system`), and XML-RPC exploitation.
- **Smart Cloudflare & Coexistence**: Decodes visitor Real-IP from `HTTP_CF_CONNECTING_IP` with Cloudflare proxy range validation. Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.
- **Live Incidents Stream & Controls**: Real-time blocked attack table, 1-click IP whitelisting, Learning Mode toggle (audit-only logging), and individual rule toggles. Custom dark-themed 403 Forbidden screen with incident reference IDs.

### 10. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan Compatible)
- **Zero-Resource Threat Interception**: Blocks malicious requests at Cloudflare's Global Anycast Edge before requests ever reach your origin server or boot WordPress PHP/MySQL.
- **1-Click Free Plan Cloudflare Edge Rules Deployment (5 Compound Rules)**:
  1. *WordPress Core & Sensitive System Armor*: Combines `/xmlrpc.php`, `wp-config.php`, `.env`, `.git`, `.user.ini`, `debug.log`, and package manifests.
  2. *Webshell & Direct Script Execution Trap*: Blocks direct script execution across both `wp-content/uploads/` and `wp-content/upgrade/`.
  3. *Path Traversal & Code Injection Edge Shield*: Blocks LFI/RFI `../`, `/etc/passwd`, `base64_decode`, `eval`, and null byte injections.
  4. *Recon & Username Harvesting Shield*: Blocks `?author=` query scrapers and REST API user enumeration.
  5. *Login Portal Threat Defense*: Deploys Cloudflare Turnstile / Managed Challenge for automated bots targeting `wp-login.php`.
- **Cloudflare Free Rate Limiting Integration**: Deploys an edge rate limiter on `wp-login.php` (10 requests / 10s per IP) to neutralize credential stuffing.
- **Bi-Directional WAF Auto-Ban Sync**: Automatically syncs locally detected high-threat attack IPs to Cloudflare Edge IP Access Rules.
- **1-Click CDN Cache Purge**: Instant global edge cache purge from WordPress admin with zero latency.

### 11. Cloud Threat Intelligence & Botnet Feeds
- **Community Botnet IP Blacklists**: Synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL.
- **Sub-Millisecond In-Memory Subnet Matching**: Performs static in-memory $O(1)$ hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
- **Zero-Day CVE Feed & Site Correlation**: Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes.
- **IP Reputation Diagnostic Tool**: Built-in checker to test client or visitor IPs against the active threat database.

### 12. Active Session Sentinel & Anti-Hijack Defense
- **Administrative Session Telemetry**: Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Strict IP Lock & Anti-Replay**: Detects and revokes hijacked sessions if client IP shifts during an active login.
- **Single Concurrent Session Policy**: Invalidate prior sessions when logging in from a new machine to prevent credential sharing or undetected parallel access.
- **Configurable Idle Inactivity Revocation**: Automatically logs out abandoned admin sessions after configurable periods (default: 120m).
- **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

### 13. Multi-Factor Authentication (2FA) & Login Hardening
- **Pure PHP RFC 6238 TOTP Engine**: Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
- **Native wp-login.php Interception**: Displays a responsive, branded two-factor verification challenge screen with support for rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
- **AES-256-CBC Encrypted User Secrets**: Encrypts user TOTP secrets (`_wcp_2fa_secret`) at rest in `wp_usermeta` via the Secret Vault.
- **Brute Force Rate-Limiter**: Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.

### 14. HTTP Security Headers Engine & 1-Click Site Hardening
- **Enterprise Security Headers Dispatcher**: Injects `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock**: Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense**: Blocks author archive scraping (`/?author=1`, `/?author=admin`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`). Strips WordPress version meta tags and asset query strings (`?ver=`).
- **Sensitive System File Probe Shield**: Returns 403 Forbidden on requests attempting to access `.env`, `.git`, `.htaccess`, `.sql`, `composer.json`, and backup archives.
- **1-Click Hardening Presets**: Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (`A+`, `A`, `B`, `C`).

### 15. Bot Recon Defense & AI Scraper Shield
- **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
- **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) at the WAF level.
- **Dynamic Virtual robots.txt Injection**: Automatically generates and injects standard AI bot Disallow directives into virtual `robots.txt`.

### 16. Multi-Provider AI Code Forensics
- **Supported AI Forensic Providers**:
  - **Google Gemini**: Gemini 3.8 Flash, 2.5 Flash, 1.5 Pro.
  - **OpenAI**: GPT-6.1 Sol, GPT-4o, GPT-4o-mini.
  - **Anthropic Claude**: Claude Sonnet 5.5, Claude 3.7 Sonnet, Claude 3.5 Haiku.
- **WordPress 7.0+ Core AI Client Bridge**: Automatically detects and leverages WordPress 7.0+ native `wp_ai_client()` site-level AI credentials for zero-configuration AI forensics.
- **1-Click AI Code Forensics Modal**: Decodes obfuscated scripts in seconds, determines whether code is safe or malicious, assesses threat confidence, and generates clean surgical remediation patches.

### 17. DevSecOps Chat & Enterprise Automation Webhooks
- **Real-Time Security Notifications**: Delivers rich Block Kit (Slack) and Embed (Discord) alert cards when critical vulnerabilities are found, files are altered, or attacks are blocked.
- **Automated DevSecOps Ticket Dispatch**: Automatically converts security threats, malware discoveries, and FIM file changes into actionable task tickets in ClickUp and Asana with priority flags, tags, and direct dashboard URLs.
- **Custom Enterprise Automation Webhook**: Dispatches structured REST JSON payloads to Zapier, Make.com, n8n, or custom SIEM pipelines to automate incident response workflows.
- **Attack Flood Protection**: Built-in 60-second rate-limiting prevents channel notification spamming during brute-force or DDoS storms.
- **Live Webhook Testing API**: 1-click test buttons inside Scanner Settings to verify webhook URL configuration instantly with real-time delivery status feedback.

### 18. 🔐 Cryptographic Secret Vault & Database Encryption at Rest *(Key Security Architecture)*

> **Enterprise-Grade Protection for All API Credentials, Webhook Endpoints & 2FA Secrets**

- **Military-Grade AES-256-CBC Encryption**: All third-party API credentials, webhook endpoints, and sensitive infrastructure tokens—including Slack incoming webhooks, Discord channel webhooks, ClickUp automation webhooks, Asana task webhooks, Generic automation URLs (Zapier, Make.com, n8n), Cloudflare API Bearer Tokens, Cloudflare Zone IDs, OpenAI API keys, Google Gemini API keys, and Anthropic Claude API keys—are encrypted at rest before being saved to the WordPress database (`wp_options` under option key `wcp_scanner_settings`).
- **Dynamic 256-bit Key Derivation & Random IVs**: Each secret is encrypted with a cryptographically secure, randomized 16-byte initialization vector (`random_bytes(16)`), derived using a SHA-256 hash of WordPress secret salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`). Identical tokens produce completely different ciphertexts upon every save.
- **Zero Plaintext Database Exposure**: Database backups, `.sql` dumps, staging exports, and unauthorized database access reveal only ciphertext strings prefixed with `wcp_enc:`.
- **Transparent In-Memory Decryption**: Decrypts credentials on the fly in memory only when executing authorized API requests or dispatching webhook security alerts, ensuring zero performance penalty and 100% backend transparency.
- **Encrypted 2FA User Secrets at Rest**: TOTP base32 user secrets (`_wcp_2fa_secret`) stored in `wp_usermeta` are automatically encrypted with AES-256-CBC via `SecretVault` with seamless transparent runtime decryption.
- **Interface Password Masking & Visibility Toggles**: All sensitive credentials in administrative panels default to masked bullet placeholders (`••••••••`) with one-click show/hide eye toggles and a verified `✓ Encrypted in Vault` indicator badge.

### 19. On-Demand Database Backup Vault (`.sql.gz`)
- **One-Click Database Backup Vault**: Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression, size metadata indexing, and secure browser downloads.
- **Secure File Storage**: Guarded by Apache/LiteSpeed `.htaccess` (`Require all denied`) and silent PHP index files.

### 20. High-Precision Microsecond Telemetry & Diagnostics
- **Microsecond Scan Duration Tracking**: Database schema upgraded with `started_at` (`datetime(3)`), `completed_at` (`datetime(3)`), and `duration_ms` (`int(11)`) columns to guarantee sub-second and millisecond tracking across all scan types.
- **Timezone-Aware Accuracy**: Replaced timezone-clashing server queries with WordPress `wp_timezone()` arithmetic, eliminating drift between server clocks and site timezones.
- **Real-Time Environment Diagnostics**: Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`), MySQL collation, database size, and OS architecture.
- **Historical Audit Logs**: Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

### 21. Data Privacy, Non-Destructive Operations & Clean Uninstall Lifecycle
- **Automated Pre-Action Safety Backups**: Every Auto-Cure, Quarantine, and Remediation action creates an automated safety snapshot in the local vault before modifying files.
- **Zero Tracking or Analytics**: The plugin does NOT track, collect, store, or sell any personal data, analytics, or browsing habits.
- **100% On-Premise Execution**: Core scans, heuristic checks, file integrity monitoring, brute-force defenses, 2FA generation, and firewall evaluation run 100% locally within your PHP environment.
- **Clean 5-Table Database Purge on Uninstall (`uninstall.php`)**: When "Auto-Remove All Data on Uninstall" is active (default), deleting the plugin automatically drops all 5 custom database tables (`wp_wcp_scans`, `wp_wcp_scan_issues`, `wp_wcp_scan_files`, `wp_wcp_quarantine`, `wp_wcp_firewall_logs`), deletes options/transients, clears crons, and purges the upload storage folder.

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
3. **[Managed Server Administration](https://webcarespro.com/services/managed-server-administration)** — Full Linux root VPS & dedicated server management, Nginx/LiteSpeed tuning, CSF/UFW firewalls, and 24/7 health monitoring.
4. **[Expert Web Maintenance](https://webcarespro.com/services/expert-web-maintenance)** — Proactive round-the-clock uptime monitoring, safe staging updates, automated offsite cloud backups, and regular database audits.
5. **[Zero-Downtime Website Transfers](https://webcarespro.com/services/website-transfer)** — Flawless server migrations with live WooCommerce order delta synchronization and DNS staging.
6. **[Server & Web Troubleshooting](https://webcarespro.com/services/website-server-troubleshooting)** — Emergency triage for HTTP 500, 502 Bad Gateway, 504 Timeouts, and White Screen of Death (backed by my *No Fix, No Fee* policy).
7. **[Domain & DNS Setup](https://webcarespro.com/services/domain-dns-setup)** — Enterprise Cloudflare Edge caching, Bot Fight Mode, and SPF/DKIM/DMARC records for in-box email deliverability.
8. **[Web Hosting Management](https://webcarespro.com/services/website-hosting-maintenance)** — Comprehensive care for cPanel, Plesk, and shared hosting control panels.
9. **[White-Label Agency Support](https://webcarespro.com/services/white-label-agency-support)** — Dedicated, invisible behind-the-scenes Linux sysadmin partner for digital agencies with NDA protection.
10. **[AI-Ready Web Development](https://webcarespro.com/services/seo-website-development)** — High-performance Next.js and React architectures engineered for 100/100 Core Web Vitals and WebMCP discovery.

---

## 💻 Tech Stack & Requirements

| Component | Specification |
|:---|:---|
| **PHP Version** | PHP 8.3 or higher |
| **WordPress Version** | WordPress 7.0 or higher (compatible with 7.1+) |
| **Database** | MySQL 8.0+ or MariaDB 10.4+ |
| **Frontend Framework** | React 18, TypeScript, `@wordpress/scripts`, Lucide Icons |
| **Styling** | Clean Vanilla CSS & Modern Responsive Flexbox/Grid |
| **API Layer** | WordPress REST API (`/wp-json/wcp-scanner/v1/`) |
| **Security Standards** | Nonce verification, `current_user_can('manage_options')`, input sanitization, output escaping, prepared SQL queries |

---

## 📦 Installation & Setup

### Method 1: WordPress Admin Upload
1. Download the release archive `wcp-security-scanner.zip`.
2. In your WordPress admin dashboard, navigate to **Plugins &rarr; Add New Plugin &rarr; Upload Plugin**.
3. Select `wcp-security-scanner.zip` and click **Install Now**.
4. Click **Activate Plugin**.
5. Navigate to **Security Scanner** in your admin sidebar to begin your first audit.

### Method 2: Manual / Composer Installation
```bash
# Clone repository into your WordPress plugins directory
cd wp-content/plugins/
git clone https://github.com/WebCarePro/wcp-wp-security.git wcp-security-scanner

# Activate via WP-CLI
wp plugin activate wcp-security-scanner
```

### Method 3: Building from Source
If you are developing or customizing the React dashboard:
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
