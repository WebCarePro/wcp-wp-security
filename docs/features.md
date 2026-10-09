# WCP WP Security Scanner - Features & Roadmap

An enterprise-grade, lightweight WordPress security, malware detection, integrity auditing, and site forensic scanner built with a modern React admin interface and high-performance PHP auditing engines.

---

## 🚀 Current Features (Available in v1.3.0)

### 1. Multi-Vector Security & Malware Scanning
- **Heuristic PHP Code Analysis**: Scans for webshells, backdoors, obfuscated payloads (`eval(base64_decode())`, `str_rot13`, `gzinflate`, dynamic variable functions, hex/octal encodings).
- **Filesystem Scanner**: High-speed batch processing engine with memory safety guards, scannable file limits, and lock controls to prevent overlapping scans.
- **WordPress Core Integrity Scanner**: Cryptographic MD5 checksum verification against the official WordPress.org release API (`wp-admin`, `wp-includes`, root entry points). Detects tampered, injected, modified, or missing core files.
- **Plugin & Theme Integrity Verification**: Checks plugin/theme source trees for rogue entry points, unauthorized modifications, and unknown standalone scripts.
- **Uploads Executables Audit**: Dedicated scanner recursively checking `wp-content/uploads/` for prohibited script extensions (`.php`, `.phtml`, `.phps`, `.sh`, `.py`, `.pl`), disguised double-extensions (`shell.jpg.php`), and rogue `.htaccess` overrides.
- **Database Threat Scanner**: Deep inspection of `wp_posts`, `wp_options`, `wp_users`, and comments for SQL injections, stored XSS scripts, malicious iframes, spam redirections, hidden pharmaceutical spam links, and eval payloads.
- **Crontab & Scheduled Tasks Audit**: Dual audit of server-level Linux crontab (`crontab -l`, `/var/spool/cron`) and WordPress virtual `wp-cron` jobs, detecting unauthorized curl/wget piped executions, reverse shells, base64 pipes, and anomalous recurring jobs.
- **User Accounts & Privilege Security**: Identifies administrative accounts without two-factor protection, weak passwords, dormant admin privileges, and suspicious newly spawned administrator accounts.
- **Web Server & Configuration Hardening**: Validates `wp-config.php`, `.htaccess`, directory permissions (`0755` / `0644`), security headers, debug flags (`WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY`), and sensitive file access prevention.

### 2. Vulnerabilities & Software Intelligence (CVE Engine)
- **Automated CVE Advisory Mapping**: Audits installed WordPress Core, plugins, and active/inactive themes against an offline-resilient, curated CVE vulnerability database (CVSS scores, severity badges, affected versions, fixed-in versions, NIST NVD advisory links).
- **Dedicated "Vulnerabilities & Updates" Page**:
  - Filterable by status (All, Vulnerable with CVEs, Outdated Only, Clean & Up-to-Date).
  - Component type filters (Core, Plugins, Themes).
  - Direct 1-click update action links to native WordPress update workflows.
  - Interactive CVE Forensic Modal with detailed vulnerability breakdown, remediation advice, and official CVE links.

### 3. Threat Forensics & Code Inspection
- **Interactive Source Code Viewer Modal**: Built-in dark-themed code viewer (`#090d16`) with line numbering, syntax highlighting, search/filtering, and automatic scroll-to-line threat highlight.
- **Post & Database Content Inspector**: Dedicated modal for inspecting database post/page threats, showing post metadata, threat snippet preview, direct editor links, and live post permalinks.
- **Quarantine Manager**: Safe isolation of malicious files into protected quarantine storage (`.htaccess` denied), preserving file permissions and SHA256 hashes, with instant 1-click restore or permanent deletion.

### 4. Database Vault & System Environment
- **Database Backup Engine**: 1-click on-demand database backup creation with automatic `.sql.gz` / `.sql` compression, metadata indexing, instant secure download, and backup management.
- **Server & Environment Diagnostics**: Real-time PHP environment diagnostics (PHP memory limit, execution time, SAPI, active extensions like cURL, OpenSSL, sodium, Zip), MySQL version & size, OS architecture, and filesystem permissions checker.
- **Audit Logs & Historical Reporting**: Complete history of past scans with duration, file counts, risk scores, findings breakdown, and log cleaning options.
- **Dedicated "About WebCare Pro & Services" Hub**: Quick access to certified WordPress security, speed optimization, server administration, and emergency hack cleanup services.

---

## 🔮 Future Roadmap & Planned Features

### 1. Settings & Automation Hub (Immediate Next Feature - v1.4.0)
- **Automated Scheduled Scans**:
  - Configurable frequency: Daily, Twice Daily, Weekly, or Monthly automated scans via WP-Cron / Server Cron.
  - Scan depth selection (Quick Plugins & Themes scan vs. Deep Full-Site audit).
  - Automatic off-peak execution (e.g., run scans at 02:00 AM server time).
- **Email Security Notifications & Alerts**:
  - Instant alert emails whenever high or critical severity malware/CVEs are detected.
  - Customizable alert recipient email addresses.
  - Daily or weekly executive security digest summaries.
  - Optional notification on scheduled backup completion or scan failures.
- **AI Intelligence Integration (Google Gemini / OpenAI ChatGPT / Anthropic Claude)**:
  - Multi-provider API Key configuration with latest defaults (Google Gemini 3.8 Flash, OpenAI GPT-6.1 Sol / GPT-6 Astra, Anthropic Claude Sonnet 5.5).
  - **AI Suspicious Code Forensic Analysis**: 1-click AI analysis inside the Code Inspection Modal to explain obfuscated scripts, evaluate whether code is safe or malicious, assess threat level, and generate clean remediation patches.
  - **AI Database Content De-obfuscation**: Decodes concealed base64/hex spam redirects in posts and explains malicious payloads in plain English.
  - Configurable custom AI prompt templates and model temperature settings.
- **Settings Import & Export**:
  - 1-click Export settings to clean JSON configuration file.
  - 1-click Import settings with schema validation to deploy uniform security configurations across multi-site agency fleets.
  - "Reset to Factory Defaults" safeguard with confirmation modal.
- **Advanced Developer & Webmaster Options**:
  - **File & Directory Exclusion Lists**: Custom ignore patterns (e.g., `wp-content/cache/*`, `node_modules/*`, large media directories).
  - **Scan Performance Throttling**: Configurable batch file sizes (e.g., 25, 50, 100 files/batch) and CPU pause intervals to prevent timeouts on shared hosting.
  - **Custom File Extension Rules**: Ability to add custom file extensions for heuristic inspection (`.inc`, `.tpl`, `.module`).
  - **High-Risk File Watcher**: Automated alerts if critical bootstrap files (`index.php`, `wp-config.php`, `.htaccess`) are modified.

### 2. Next-Gen Security & Defense Enhancements
- **Web Application Firewall (WAF) Lite**:
  - Virtual patching against known CVE exploits before plugin authors release updates.
  - Block malicious query parameters (`base64_`, `UNION SELECT`, `<?php`, `../` directory traversal).
  - Rate limiting on `xmlrpc.php` and `wp-login.php` to prevent brute force attacks.
- **Real-Time File Integrity Monitoring (FIM)**:
  - Background daemon or cron tracking file modifications within the last 24 hours.
  - Visual git-style diffs showing exact code additions and modifications in altered core or plugin files.
- **Automatic Malware Remediation / Auto-Clean**:
  - 1-click auto-cure for common injections: stripping `eval(base64_decode())` headers, removing known webshell payloads, and re-downloading clean core/plugin files directly from official WordPress.org repositories.
- **Cloud Threat Intelligence Feed**:
  - Live synchronization with remote threat feeds for zero-day CVE definitions and known malicious IP blacklists.
- **Two-Factor Authentication (2FA) & Login Hardening**:
  - TOTP 2FA (Google Authenticator / Authy) for administrator and editor roles.
  - Login URL masking / custom login slug.
- **Slack & Discord Webhook Alerts**:
  - Real-time webhook notifications pushed to agency DevSecOps chat channels on critical security events.
