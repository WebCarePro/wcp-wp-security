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
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Release-v1.5.0-orange.svg" alt="Release Version"/></a>
</p>

---

## 🛡️ Overview

**WCP Security Scanner** is a modern, high-performance WordPress security, malware detection, and forensic auditing plugin engineered by **[WebCare Pro](https://webcarespro.com)**. 

Unlike heavy, bloated security plugins that degrade server performance with background overhead, WCP Security Scanner combines **memory-safe PHP batch auditing engines** with a responsive **React 18 single-page administrative dashboard**. It provides deep insight into your file system, WordPress core integrity, plugin and theme source code, database tables, cron jobs, active administrative sessions, runtime memory hooks, and server configurations—giving developers, sysadmins, and agency site owners complete visibility and control over their WordPress security posture.

---

## 🌟 Comprehensive Feature Catalog (18 Modern Security Engines)

### 1. Multi-Vector Security & Malware Scanning
- **Deep Heuristic PHP Code Analysis**: Scans for webshells, backdoors, Trojan droppers, and remote access tools (variants of c99, r57, b374k, WSO, China Chopper). Detects obfuscation patterns including nested `eval(base64_decode())`, `gzinflate()`, `str_rot13()`, dynamic variable functions, hex/octal encodings, and malicious file header spoofs.
- **WordPress Core Cryptographic Integrity Engine**: Validates core files against official WordPress.org cryptographic MD5 checksum APIs. Pinpoints modified, injected, tampered, or missing core files in `wp-admin`, `wp-includes`, and root directories.
- **Uploads Executable & Script Shield**: Recursively audits `wp-content/uploads/` for prohibited script extensions (`.php`, `.phtml`, `.phps`, `.sh`, `.py`, `.pl`), disguised double-extensions (`shell.jpg.php`), and rogue `.htaccess` execution overrides.
- **Database Threat & Content Injection Scanner**: Deeply inspects `wp_posts`, `wp_options`, `wp_users`, and `wp_comments` for stored cross-site scripting (Stored XSS), malicious iframes, pharmaceutical spam links, hidden redirect doorways, and unauthorized admin user records.
- **Crontab & Scheduled Task Auditing**: Audits both Linux server-level crontab files (`/var/spool/cron`, `crontab -l`) and WordPress virtual `wp-cron` hooks for unauthorized piped downloads (`curl | bash`, `wget | sh`), reverse shells, and persistence callbacks.
- **User Account & Privilege Security**: Identifies weak administrator passwords, dormant superuser accounts, and suspicious newly created administrator accounts.
- **Server Configuration Hardening**: Checks permissions for `wp-config.php` and `.htaccess`, verifies `WP_DEBUG` exposure flags, and audits protection against public access to `.env`, `.git`, `.user.ini`, and database dumps.

### 2. Software Intelligence & CVE Vulnerability Engine
- **Curated CVE Advisory Database**: Scans installed WordPress core, plugins, and active/inactive themes against an offline-resilient vulnerability database.
- **Granular Vulnerability Metadata**: View CVSS risk scores, severity badges (Critical, High, Medium, Low), affected versions, patched versions, and official NIST NVD reference advisories.
- **Interactive Vulnerabilities Dashboard**: Filter by component type (Core, Plugins, Themes) or status (Vulnerable, Outdated, Clean). Includes 1-click update links to native WordPress update screens and an in-depth CVE forensic breakdown modal.

### 3. Threat Forensics, Code Viewer & Quarantine Vault
- **In-Browser Dark-Theme Code Inspector**: Built-in Monaco/terminal-style viewer (`#090d16`) with line numbering, syntax highlighting, search/filtering, and automatic scroll-to-line highlight on flagged threat snippets.
- **Database Content Inspector**: Dedicated modal for inspecting database post/page threats, showing post metadata, snippet preview, direct editor links, and live post permalinks.
- **Secure Quarantine Vault**: Safely isolates infected files into a protected, `.htaccess`-guarded directory. Preserves original file permissions, timestamps, and SHA-256 cryptographic hashes, with 1-click instant restoration or permanent deletion.

### 4. Database Vault & System Diagnostics
- **One-Click Database Backup Vault**: Creates instant on-demand database dumps with automatic `.sql.gz` Gzip compression, size metadata indexing, and secure browser downloads.
- **Real-Time Environment Diagnostics**: Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (`cURL`, `OpenSSL`, `sodium`, `Zip`), MySQL collation, database size, and OS architecture.
- **Historical Audit Logs**: Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

### 5. Settings, Automation & AI Forensics
- **Automated Scheduled Scans**: Run hands-free recurring scans via WP-Cron on an **Hourly**, **Twice Daily**, **Daily**, or **Weekly** schedule, with configurable off-peak execution times (HH:MM server time) and selectable scan depth.
- **Instant Email Security Alerts**: Dispatches HTML email alerts on detection of Critical or High severity threats or CVE advisories, with configurable recipient lists and severity thresholds.
- **AI Intelligence Integration**:
  - Connect your choice of state-of-the-art AI forensic engines: **Google Gemini** (Gemini 3.8 Flash, 2.5 Flash), **OpenAI** (GPT-6.1 Sol, GPT-4o), or **Anthropic Claude** (Claude Sonnet 5.5, Claude 3.7 Sonnet).
  - **WordPress 7.0+ Core AI Client Bridge**: Automatically detects and leverages WordPress 7.0+ native `wp_ai_client()` site-level AI credentials for zero-configuration AI forensics.
  - **1-Click AI Code Forensics Modal**: Decodes obfuscated scripts in seconds, determines whether code is safe or malicious, assesses threat confidence, and generates clean surgical remediation patches.
- **Performance & Developer Safeguards**: Configurable scan batch sizes (25 to 200 files/batch), memory limit overrides (256 MB to 1024 MB), heuristic file size thresholds, custom path exclusions (e.g., `wp-content/cache/*`), safe directory index (`index.php`) auto-exclusion in uploads, and 1-click generator tag hiding.
- **Settings Import & Export**: 1-click JSON export and import for seamless fleet deployment across multi-site agency portfolios, plus factory reset safeguards.
- **Clean Uninstall & Data Privacy**: Standard `uninstall.php` lifecycle script. When **Auto-Remove All Data on Uninstall** is active (default), deleting the plugin automatically drops all 5 custom database tables (`wp_wcp_scans`, `wp_wcp_scan_issues`, `wp_wcp_scan_files`, `wp_wcp_quarantine`, `wp_wcp_firewall_logs`), deletes options/transients, clears crons, and purges the upload storage folder.

### 6. Web Application Firewall (WAF Lite) & Virtual Patching
- **Real-Time Request Filtering**: Inspects incoming HTTP payloads at `plugins_loaded` (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
- **Attack Vector Shields**: Blocks SQL Injections (`UNION SELECT`, `information_schema`, `benchmark`), Cross-Site Scripting (XSS scripts and handlers), Path Traversal & LFI (`/etc/passwd`, `php://filter`), PHP code tag injections (`<?php`, `eval`, `base64_decode`, `system`), and XML-RPC exploitation.
- **Smart Cloudflare & Third-Party Coexistence**: Decodes visitor Real-IP from `HTTP_CF_CONNECTING_IP` with Cloudflare proxy range validation. Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.
- **Live Incidents Stream & Controls**: Real-time blocked attack table, 1-click IP whitelisting, Learning Mode toggle (audit-only logging), and individual rule toggles. Custom dark-themed 403 Forbidden screen with incident reference IDs.

### 7. Real-Time File Integrity Monitoring (FIM) & Code Diff Viewer
- **Filesystem Change Tracker**: Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
- **Custom & Premium Component Recognition**: Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to prevent false-positive alarms.
- **Bit-for-Bit Visual Code Diff Viewer**: Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org release mirrors with side-by-side and unified views.

### 8. One-Click Malware Remediation & Auto-Cure Engine
- **Automated Webshell Stripping**: 1-click surgical neutralization of malicious code headers, obfuscated base64/eval wrappers, and backdoor includes while preserving legitimate file code. Includes tokenizer syntax validation before writing.
- **Official WordPress.org Restoration**: 1-click replacement of infected or tampered plugin/theme files with authentic, bit-for-bit verified copies fetched directly from official release mirrors.
- **Auto-Cure Safety Backups & Rollback Vault**: Creates timestamped safety backups in a secure directory before every remediation action, enabling instant 1-click restoration if needed.

### 9. Cloud Threat Intelligence & Botnet Feeds
- **Community Botnet IP Blacklists**: Synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL. Performs static in-memory O(1) hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
- **Zero-Day CVE Feed & Site Correlation**: Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes, displaying status badges (`Installed — Vulnerable`, `Installed — Patched`, `Global Virtual Shield`) and filter controls.
- **IP Reputation Diagnostic Tool**: Built-in checker to test client or visitor IPs against the active threat database.

### 10. Multi-Factor Authentication (2FA) & Login Hardening
- **Pure PHP RFC 6238 TOTP Engine**: Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
- **Native wp-login.php Interception**: Displays a responsive, branded two-factor verification challenge screen with support for rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
- **Brute Force Rate-Limiter**: Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.

### 11. HTTP Security Headers Engine & 1-Click Site Hardening
- **Enterprise Security Headers Dispatcher**: Injects `Strict-Transport-Security` (HSTS with preload), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` (CSP Lite).
- **Runtime PHP File Editor Lock**: Defines `DISALLOW_FILE_EDIT` at runtime to prevent attackers from editing plugin/theme files through `wp-admin`.
- **User Enumeration & Reconnaissance Defense**: Blocks author archive scraping (`/?author=1`, `/?author=admin`) and removes user listings from unauthenticated REST API queries (`/wp/v2/users`). Strips WordPress version meta tags and asset query strings (`?ver=`).
- **Sensitive System File Probe Shield**: Returns 403 Forbidden on requests attempting to access `.env`, `.git`, `.htaccess`, `.sql`, `composer.json`, and backup archives.
- **1-Click Hardening Presets**: Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (A+, A, B, C).

### 12. Active Session Sentinel & Anti-Hijack Defense
- **Administrative Session Telemetry**: Real-time tracking of active user logins via `\WP_Session_Tokens` with IP address, browser, OS, and timestamp telemetry.
- **Strict IP Lock & Cookie Replay Defense**: Detects and revokes hijacked sessions if client IP shifts during an active login.
- **Single Concurrent Session Policy**: Invalidate prior sessions when logging in from a new machine to prevent credential sharing or undetected parallel access.
- **Configurable Idle Inactivity Revocation**: Automatically logs out abandoned admin sessions after configurable periods (default: 120m).
- **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

### 13. Database Micro-Anomaly & Rogue Administrator Trap
- **Stealth User Infiltration Detection**: Audits `wp_users` against `wp_usermeta` to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
- **Ghost & Orphaned Capability Hunting**: Uncovers orphaned capability rows in `wp_usermeta` pointing to non-existent user IDs left behind by malware droppers.
- **Privilege Escalation Trap**: Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
- **Database Rootkit & Transient Probe**: Recursively scans `wp_options` for obfuscated execution payloads (`eval`, `base64_decode`, `gzinflate`) hidden in transient names.

### 14. Bot Recon Defense & AI Scraper Shield
- **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
- **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (`GPTBot`, `CCBot`, `Bytespider`, `ClaudeBot`, `PerplexityBot`, `Diffbot`, `Cohere-ai`) at the WAF level.
- **Dynamic Virtual robots.txt Injection**: Automatically generates and injects standard AI bot Disallow directives into virtual `robots.txt`.

### 15. Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
- **Active Runtime Memory Hook Audit**: Uses reflection to inspect active runtime hook callbacks registered in `$wp_filter` across high-risk lifecycle actions (`authenticate`, `wp_authenticate`, `template_redirect`, `wp_head`, `wp_footer`, `user_register`, `xmlrpc_call`, `rest_pre_serve_request`).
- **Anonymous Closure & Credential Sniffer Detection**: Flags anonymous `Closure` functions attached to sensitive authentication and login hooks that could steal passwords.
- **External Rootkit & Uploads Hook Traps**: Detects hook callbacks originating outside WordPress root (`auto_prepend_file` or system rootkits) and callbacks executing inside `wp-content/uploads/` (webshell callbacks).
- **Dangerous Native Function Registration Defense**: Detects dangerous native PHP functions (`eval`, `assert`, `shell_exec`, `system`, `passthru`) attached directly as WordPress filter callbacks.

### 16. DevSecOps Chat & Automation Webhooks (Slack, Discord, ClickUp, Asana, Zapier, Make, n8n)
- **Real-Time Security Notifications**: Delivers rich Block Kit (Slack) and Embed (Discord) alert cards when critical vulnerabilities are found, files are altered, or attacks are blocked.
- **Automated DevSecOps Ticket Dispatch**: Automatically converts security threats, malware discoveries, and FIM file changes into actionable task tickets in ClickUp and Asana with priority flags, tags, and direct dashboard URLs.
- **Custom Enterprise Automation Webhook**: Dispatches structured REST JSON payloads to Zapier, Make.com, n8n, or custom SIEM pipelines to automate incident response workflows.
- **Attack Flood Protection**: Built-in 60-second rate-limiting prevents channel notification spamming during brute-force or DDoS storms.
- **Live Webhook Testing API**: 1-click test buttons inside Scanner Settings to verify webhook URL configuration instantly with real-time delivery status feedback.

### 17. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan Compatible)
- **Zero-Resource Threat Interception**: Blocks malicious requests at Cloudflare's Global Anycast Edge before requests ever reach your origin server or boot WordPress PHP/MySQL.
- **1-Click Free Plan Cloudflare Edge Rules Deployment**:
  - *XML-RPC & Amplification Shield*: Drops pingback and brute-force spray targeting `/xmlrpc.php` at the edge.
  - *Sensitive Files & Dotfiles Armor*: Rejects probes for `wp-config.php`, `.env`, `.git`, `composer.json`, and database dumps before disk access.
  - *Uploads Directory Webshell Trap*: Direct edge block on HTTP execution of scripts (`.php`, `.sh`, `.py`, `.exe`) in `wp-content/uploads/`.
  - *Author Enumeration Recon Shield*: Prevents username harvesting via `?author=1` and `/wp-json/wp/v2/users`.
  - *Login Portal Threat Defense*: Deploys non-intrusive Cloudflare Turnstile / Managed Challenge for automated bots targeting `wp-login.php`.
- **Cloudflare Free Rate Limiting Integration**: Deploys an edge rate limiter on `wp-login.php` (10 requests / 10s per IP) to neutralize credential stuffing.
- **Bi-Directional WAF Auto-Ban Sync**: When WCP Local WAF detects high-threat attacks (SQL injection, webshell uploads, directory traversal), it automatically pushes the attacking IP to Cloudflare Edge IP Access Rules.
- **1-Click CDN Cache Purge**: Instant global edge cache purge from WordPress admin with zero latency.

### 18. Cryptographic Secret Vault & Database Encryption at Rest
- **Military-Grade AES-256-CBC Algorithm**: All third-party API credentials, secret tokens, and sensitive infrastructure parameters—including Cloudflare API Bearer Tokens, Cloudflare Zone IDs, OpenAI API keys, Google Gemini API keys, and Anthropic Claude API keys—are encrypted at rest before being saved to the WordPress database (`wp_options` under option key `wcp_scanner_settings`).
- **Dynamic 256-bit Key Derivation & Random IVs**: Each secret is encrypted with a cryptographically secure, randomized 16-byte initialization vector (`random_bytes(16)`), derived using a SHA-256 hash of WordPress secret salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`). Identical tokens produce completely different ciphertexts upon every save.
- **Zero Plaintext Database Exposure**: Database backups, `.sql` dumps, staging exports, and unauthorized database access (SQLi, phpMyAdmin compromises) reveal only ciphertext strings prefixed with `wcp_enc:`, eliminating credential leakage.
- **Transparent In-Memory Decryption**: Decrypts credentials on the fly in memory only when executing authorized API requests (`CloudflareService`, `AIService`), ensuring zero performance penalty and 100% backend transparency.
- **Interface Password Masking & Visibility Toggles**: All sensitive credentials in administrative panels default to masked bullet placeholders (`••••••••`) with one-click `Show`/`Hide` eye toggles and a verified `✓ Encrypted in Vault` badge.

---

## 🏢 About WebCare Pro

**[WebCare Pro](https://webcarespro.com)** is an enterprise web and Linux server engineering firm founded in 2013 by **Mir Alamin**. We help businesses worldwide build, secure, optimize, and manage high-performance websites and servers.

- **12+ Years Enterprise Experience**: Senior Linux SysAdmin and Web Architecture background across high-traffic digital infrastructures.
- **Direct Senior Engineering**: Every architecture, server migration, malware cleanup, and speed optimization is personally designed and supervised—**zero junior contractor outsourcing**.
- **100% Proven Track Record**: Over 680 successfully completed client projects with a flawless **100% Job Success Score** on Upwork and 5-star ratings worldwide.
- **15-Minute Emergency SLA**: Rapid diagnostic triage when servers crash, gateways timeout, or websites suffer critical malware attacks.

### Specialized Professional Services:
1. **[Website Hack Recovery & Security](https://webcarespro.com/services/website-hack-recovery-security)** — Rapid malware eradication, backdoor cleanup, Google blacklist delisting, and WAF configuration.
2. **[Website Speed Optimization](https://webcarespro.com/services/website-speed-optimization)** — Sub-100ms TTFB tuning, Redis object caching, asset deferral, and 100/100 Core Web Vitals.
3. **[Managed Server Administration](https://webcarespro.com/services/managed-server-administration)** — Full Linux root VPS & dedicated server management, Nginx/LiteSpeed tuning, CSF/UFW firewalls, and 24/7 health monitoring.
4. **[Expert Web Maintenance](https://webcarespro.com/services/expert-web-maintenance)** — Proactive round-the-clock uptime monitoring, safe staging updates, automated offsite cloud backups, and regular database audits.
5. **[Zero-Downtime Website Transfers](https://webcarespro.com/services/website-transfer)** — Flawless server migrations with live WooCommerce order delta synchronization and DNS staging.
6. **[Server & Web Troubleshooting](https://webcarespro.com/services/website-server-troubleshooting)** — Emergency triage for HTTP 500, 502 Bad Gateway, 504 Timeouts, and White Screen of Death (backed by our *No Fix, No Fee* policy).
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
- **Non-Destructive Core Policy**: Does not modify, overwrite, or delete core WordPress files directly. When core files are flagged as tampered, administrators are guided to use official WordPress update workflows (`update-core.php`) or WP-CLI (`wp core download --force`).
- **Protected File Storage**: Quarantine vaults, audit logs, and compressed database backups are stored exclusively within `wp-content/uploads/wcp-security-scanner/`, guarded by Apache/LiteSpeed `.htaccess` (`Require all denied`) and silent PHP index files.
- **Directory Traversal Defense**: All quarantine, file inspection, and backup operations enforce strict path normalization and trailing-slash boundary checks against `ABSPATH`.
- **Transparent Third-Party Services**: External API calls (official WordPress.org Checksum API, community threat feeds, and optional AI providers) are fully documented with explicit triggers, payload descriptions, and links to Terms of Service and Privacy Policies.

---

## 📬 Connect & Hire WebCare Pro

Have questions, need an emergency malware cleanup, or want to hire a certified Senior Linux SysAdmin for your website? Connect with us directly:

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
