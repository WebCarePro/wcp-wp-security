# WCP Security Scanner

<p align="center">
  <img src="https://webcarespro.com/wp-content/uploads/2024/02/webcarepro-logo.png" alt="WebCare Pro Logo" width="180" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>Enterprise-Grade WordPress Malware Detection, Core Integrity Auditing & Forensic Threat Intelligence</strong>
</p>

<p align="center">
  <a href="https://wordpress.org/"><img src="https://img.shields.io/badge/WordPress-7.0%2B-blue.svg?logo=wordpress" alt="WordPress Version"/></a>
  <a href="https://www.php.net/"><img src="https://img.shields.io/badge/PHP-8.3%2B-777BB4.svg?logo=php" alt="PHP Version"/></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB.svg?logo=react" alt="React 18"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-GPLv2%2B-green.svg" alt="License"/></a>
  <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67"><img src="https://img.shields.io/badge/Upwork-Top%20Rated%20Plus%20★%20100%25%20JSS-14A800.svg?logo=upwork" alt="Upwork Top Rated Plus"/></a>
  <a href="https://github.com/WebCarePro/wcp-wp-security"><img src="https://img.shields.io/badge/Release-v1.4.1-orange.svg" alt="Release Version"/></a>
</p>

---

## 🛡️ Overview

**WCP Security Scanner** is a modern, high-performance WordPress security, malware detection, and forensic auditing plugin engineered by **[WebCare Pro](https://webcarespro.com)**. 

Unlike heavy, bloated security plugins that degrade server performance with background overhead, WCP Security Scanner combines **memory-safe PHP batch auditing engines** with a responsive **React 18 single-page administrative dashboard**. It provides deep insight into your file system, WordPress core integrity, plugin and theme source code, database tables, cron jobs, and server configurations—giving developers, sysadmins, and agency site owners complete visibility and control over their WordPress security posture.

---

## 🌟 Key Features

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
- **Performance & Developer Safeguards**: Configurable scan batch sizes (25 to 200 files/batch), memory limit overrides (256 MB to 1024 MB), heuristic file size thresholds, custom path exclusions (e.g., `wp-content/cache/*`), and 1-click generator tag hiding.
- **Settings Import & Export**: 1-click JSON export and import for seamless fleet deployment across multi-site agency portfolios, plus factory reset safeguards.
- **Clean Uninstall & Data Privacy**: Standard `uninstall.php` lifecycle script. When **Auto-Remove All Data on Uninstall** is active (default), deleting the plugin automatically drops all 4 custom tables (`wp_wcp_scans`, `wp_wcp_scan_issues`, `wp_wcp_scan_files`, `wp_wcp_quarantine`), removes options/transients, clears crons, and purges the upload storage folder.

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
- **Transparent Third-Party Services**: External API calls (official WordPress.org Checksum API and optional AI providers) are fully documented with explicit triggers, payload descriptions, and links to Terms of Service and Privacy Policies.

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

## 📄 License & Attribution

- **License:** Open source under the terms of the [GNU General Public License v2.0 or later (GPL-2.0-or-later)](https://www.gnu.org/licenses/gpl-2.0.html).
- **Author & Copyright:** © 2013–2026 **Mir Alamin** / **[WebCare Pro](https://webcarespro.com)**. All rights reserved.
