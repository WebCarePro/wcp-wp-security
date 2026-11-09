# WebCare Pro Security & Firewall

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
  <a href="https://github.com/WebCarePro/webcare-pro-security/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-GPLv2%2B-green.svg" alt="License"/></a>
  <a href="https://www.upwork.com/freelancers/~0162afa9a578170c67"><img src="https://img.shields.io/badge/Upwork-Top%20Rated%20Plus%20★%20100%25%20JSS-14A800.svg?logo=upwork" alt="Upwork Top Rated Plus"/></a>
  <a href="https://github.com/WebCarePro/webcare-pro-security"><img src="https://img.shields.io/badge/Release-v2.10.0-orange.svg" alt="Release Version"/></a>
  <a href="https://github.com/WebCarePro/webcare-pro-security"><img src="https://img.shields.io/badge/Status-Public%20Beta%20%7C%20Active%20Dev-blue?style=flat&logo=git" alt="Status"/></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy%20%26%20Disclosure-blue.svg?logo=securityscorecard" alt="Security Policy"/></a>
  <a href="#22-model-context-protocol-mcp-agentic-surface-ai-secops-automation"><img src="https://img.shields.io/badge/Agentic-Model%20Context%20Protocol%20(MCP)-purple.svg?logo=anthropic" alt="MCP Ready"/></a>
  <a href="#-featured-spotlight-cryptographic-secret-vault--database-encryption-at-rest"><img src="https://img.shields.io/badge/Security-AES--256--GCM%20AEAD%20Vault-blueviolet.svg?logo=securityscorecard&logoColor=white" alt="Cryptographic Secret Vault"/></a>
</p>

---

## 🛡️ Overview

**WebCare Pro Security & Firewall** is a modern, high-performance WordPress security, malware detection, and forensic auditing plugin engineered by **[Mir Alamin](https://www.upwork.com/freelancers/~0162afa9a578170c67)** ([WebCare Pro](https://webcarespro.com)). 

> [!NOTE]
> **Active Engineering & Senior Architecture (v2.9.0)**  
> WebCare Pro Security & Firewall is actively developed and battle-tested by solo engineer **Mir Alamin**. Rapid architectural upgrades, engine hardening, and new security primitives are released continuously.

Unlike heavy, bloated security plugins that degrade server performance with background overhead, WebCare Pro Security & Firewall combines **memory-safe PHP batch auditing engines** with a responsive **React 18 single-page administrative dashboard**. It provides deep insight into your file system, WordPress core integrity, plugin and theme source code, database tables, cron jobs, active administrative sessions, runtime memory hooks, and server configurations—giving developers, sysadmins, and site owners complete visibility and control over their WordPress security posture.

---

## 🔐 Featured Spotlight: Cryptographic Secret Vault & Database Encryption at Rest

> [!IMPORTANT]
> **Zero Plaintext Credentials in Database or SQL Backups with Authenticated AEAD Encryption.**  
> Unlike typical WordPress security plugins that store third-party API keys and incoming webhooks as raw plaintext inside `wp_options`, WebCare Pro Security & Firewall implements a dedicated **Enterprise AES-256-GCM Authenticated Cryptographic Secret Vault**. Every webhook URL, Cloudflare API token, AI key, and 2FA user secret is encrypted at rest using modern Authenticated Encryption with Associated Data (AEAD), 128-bit integrity authentication tags, randomized 12-byte initialization vectors (`random_bytes(12)`), and dynamic 256-bit key derivation with optional server-level `WEBCARE_VAULT_KEY` environment isolation.

### 🛡️ How the Cryptographic Secret Vault Protects Your Infrastructure:

| Security Dimension | Standard WordPress Plugins | WebCare Pro Security Vault |
|:---|:---|:---|
| **Database Storage (`wp_options`)** | ❌ Plaintext strings visible to anyone with database access | ✅ **AES-256-GCM Authenticated Ciphertext** (`webcare_gcm:...`) |
| **Tamper & Bit-Flip Resistance** | ❌ None (or vulnerable to CBC padding oracle attacks) | ✅ **128-bit Cryptographic Authentication Tag** (tampering rejected immediately) |
| **SQL Dumps & Database Backups** | ❌ Secrets exposed in plain text if backup files are compromised | ✅ **Completely unreadable encrypted strings** |
| **phpMyAdmin & SQLi Exposure** | ❌ Scraped easily via unauthorized database queries | ✅ **Zero plaintext credential leakage** |
| **Encryption Keys & Salting** | ❌ Static hardcoded strings or unencrypted options | ✅ **Derived from WP Salts (`AUTH_KEY`, `AUTH_SALT`, `SECURE_AUTH_KEY`) or dedicated `WEBCARE_VAULT_KEY`** |
| **Key Isolation (DevOps)** | ❌ Tied solely to database or webroot | ✅ **Supports isolated `WEBCARE_VAULT_KEY` in server environment outside webroot** |
| **Initialization Vectors (IV)** | ❌ Static or reused IV vectors | ✅ **Cryptographically random 12-byte IV generated per record** |
| **Decryption Lifecycle** | ❌ Persisted in plain text on memory or disk | ✅ **Transient in-memory decryption ONLY during active API/webhook calls** |
| **Admin UI Visibility** | ❌ Plaintext input fields or visible strings | ✅ **Auto-masked bullet placeholders (`••••••••`) with 1-click eye toggle** |

---

## 🌟 Top Core Features & Architectural Highlights

WebCare Pro Security & Firewall combines lightweight, memory-efficient PHP 8.3+ streaming engines with a modern React 18 single-page cockpit. While the plugin contains **87 specialized subsystems** (documented exhaustively in [features.md](features.md)), these 9 core pillars represent the heart of its enterprise defense model:

### 1. 📊 Executive Cyber Command Center & React 18 SOC Cockpit
- **Dynamic Security Health Score:** High-precision circular SVG meter displaying your live security posture (0–100%) and letter grade (A+ through F).
- **3-Pillar Threat Metrics:** Real-time summary cubes categorizing threats into Critical Exploits, Code Drift/FIM, and Software CVEs with 1-click filtering.
- **Dual Interface Modes:** Seamlessly switch between **Essential Mode** (streamlined, distraction-free protection for site owners) and **Advanced SOC Mode** (deep telemetry, AST dumps, and MCP controls for sysadmins).

### 2. ⚡ Ultra-Fast Streaming Malware Detection Engine (320+ Files/Sec)
- **Hierarchical Resumable Cursor:** O(1) disk queue traversal eliminating $O(N^2)$ filesystem loops on large sites, maintaining flat ~15–25MB batch RAM usage.
- **Source-to-Sink AST Taint Flow Analyzer:** Token-level dataflow tracking (`token_get_all()`) that traces untrusted input from sources to execution sinks, catching 2026 AI-crafted polymorphic webshells that evade static signatures.
- **Cryptographic Core Integrity:** Bit-for-bit validation against official WordPress.org MD5 checksum APIs for WordPress Core, themes, and plugins.

### 3. 🛡️ Context-Adaptive Firewall (CAF 2.0) & ThreatScore First-Hit Shield
- **Stack-Aware Dynamic Gating:** Automatically fingerprints your active plugins. E-commerce rules sleep on simple blogs, and page-builder rules sleep when builders are absent—zero unnecessary CPU overhead.
- **Deterministic First-Hit Banning:** Critical exploits (SQL Injection, Code Injection, Path Traversal) trigger an immediate 85-point violation and 24-hour hard ban on hit #1.
- **Pre-Calibrated Allowlist Library:** 33+ verified enterprise integrations (WooCommerce, Stripe, PayPal, Jetpack, Gutenberg, CRM webhooks) with zero false-positives.

### 4. ☁️ Instant Zero-Latency Cloudflare Edge Defense (100% Free Plan)
- **Edge Threat Interception:** Neutralizes automated botnets at Cloudflare’s Global Anycast Edge before requests ever reach your origin server or consume PHP workers.
- **Zero-Latency Post-Response Push:** Flushes HTTP 403 responses to attackers instantly via `fastcgi_finish_request()` and offloads the attacker's IP to Cloudflare Edge in the background.
- **Bi-Directional Unban Sync:** Unbanning an IP locally in WordPress immediately purges matching Zone IP Access Rules and Account IP Lists on Cloudflare Edge.

### 5. 🩹 1-Click Auto-Cure, Surgical Remediation & Rollback Vault
- **Official Release Mirrors:** Surgically restores altered core, plugin, and theme files back to clean, official WordPress.org code without reinstalling WordPress.
- **Non-Destructive Webshell Stripping:** Neutralizes obfuscated code blocks and malicious headers while preserving legitimate file customizations with tokenizer syntax verification.
- **Pre-Cure Safety Snapshots:** Generates timestamped Gzip backups in the WebCare Vault before any file remediation, enabling instant 1-click rollbacks.

### 6. 🔐 Enterprise Cryptographic Secret Vault (AES-256-GCM AEAD)
- **Zero Plaintext Credentials in Database:** All API tokens (Cloudflare, AI keys, webhooks, 2FA secrets) are encrypted at rest with military-grade AES-256-GCM AEAD encryption.
- **Tamper-Evident Authentication Tags:** 128-bit authentication tags and unique 12-byte initialization vectors per record protect against bit-flipping and database dumps.
- **Two-Phase Key Rotation:** Zero-downtime state machine for rotating master encryption keys with isolated `WEBCARE_VAULT_KEY` server environment variable support.

### 7. 🤖 2026 AI-Era Threat Defense & Autonomous Ghost Canaries
- **Ghost Admin Canary User Tripwire:** Provisions a dormant, invisible `webcare_canary_admin` in `wp_users` with an impossible password hash to catch database dump leaks.
- **Database Honey-Tokens:** Decoy options (`_webcareproscan_canary_*`) with fake API keys instantly ban any SQL-injection intruder who attempts to read them.
- **AI Prompt-Injection & Jailbreak Guard:** Strips invisible Unicode steganography and ChatML/LLaMA delimiter escapes from comments, reviews, and WooCommerce order notes.
- **AI SEO & GEO Shield:** Monitors `/llms.txt` feeds against cryptographic baselines and detects transparent CSS text cloaking and JSON-LD schema toll-fraud.

### 8. 🔑 Zero-Trust Identity, WebAuthn Biometrics & Step-Up 2FA
- **W3C WebAuthn Passwordless Ceremony:** Native Windows Hello, Apple Touch ID/Face ID, Android Biometrics, and FIDO2 USB keys for 100% phishing-immune login.
- **Pure PHP RFC 6238 TOTP 2FA:** High-security HMAC-SHA-512 and SHA-1 two-factor authentication compatible with Google Authenticator, 1Password, and YubiKey.
- **REST Application Password Shield:** Mandatory Step-Up 2FA on `authorize-application.php` blocks 1-click token consent phishing traps.

### 9. 🧠 Model Context Protocol (MCP) Agentic AI SecOps Automation
- **Native JSON-RPC 2.0 Surface:** Securely connect external AI developer agents (Claude Desktop, Cursor IDE, Antigravity) directly to WordPress security operations.
- **Encrypted Bearer Authentication:** Secure AEAD-encrypted tokens, strict read-only default permissions, configurable rate limits, and an immutable 150-event ring-buffer execution log.

---

> [!TIP]
> ### 📖 Looking for the Complete 87-Engine Catalog?
> WebCare Pro Security & Firewall includes over **87 specialized security engines, behavioral monitors, and forensic subsystems**.
> 
> 👉 **[Explore the Complete Features & Architecture Catalog in `features.md`](features.md)** for exhaustive dual-level documentation (plain-English summaries for site owners + deep technical architecture for systems engineers).
---

## ⚖️ Architectural Comparison at a Glance (as of Oct 2026)

Security plugins solve overlapping problems through different architectures. This practical orientation highlights primary engineering models and operational trade-offs:

| Dimension | **WebCare Pro Security & Firewall** | **Wordfence** | **Sucuri Platform** | **Patchstack** |
| :--- | :--- | :--- | :--- | :--- |
| **Model** | **On-Server Suite**: Streaming Scan, WAF, Identity, Secret Vault, 4-Mirror Auto-Cure | **On-Server Suite**: Endpoint WAF + Signature Scanner + Login Hardening | **Cloud WAF/CDN** + Monitoring + Managed Human Response | **Vulnerability Intel & Rapid Virtual Patching** |
| **Key Strength** | **Ultra-low RAM (~15-25MB batch delta)**, AES-256-GCM Vault, MCP AI agent governance, zero telemetry | Huge install base + proprietary threat research lab | Cloud edge blocking + managed malware cleanup retainers | Industry-fastest CVE intelligence & virtual patch loop |
| **Trade-off** | Independent solo-vendor velocity; no 24/7 global SOC; uses origin CPU/RAM | Can be resource-heavy; free threat feed delayed ~30 days; database table bloat | Premium cost; DNS/proxy dependency; free plugin is limited | Not a complete malware scanner, cleaner, or traditional WAF |

> **Honest Architectural Positioning**: WebCare Pro Security & Firewall is not designed to replace globally distributed Anycast DDoS scrubbing networks (like Cloudflare Enterprise) or 24/7 human research SOCs. It is purpose-built for SysAdmins, developers, and store operators who demand deep on-server control, strict zero-telemetry privacy, and non-destructive surgical remediation.
>
> 📖 **Read the comprehensive, balanced ecosystem comparison and technical breakdown:**  
> [https://webcarespro.com/blog/post/webcare-wordpress-security-scanner](https://webcarespro.com/blog/post/webcare-wordpress-security-scanner)

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
1. Download `webcare-pro-security.zip` from releases or build directly from source.
2. Navigate to **Plugins > Add New > Upload Plugin** in your WordPress administration panel.
3. Select `webcare-pro-security.zip` and click **Install Now**.
4. Click **Activate Plugin**.
5. Access your new cyber command center by clicking **WebCare Pro** in your WordPress sidebar.

### Building from Source:
```bash
# Clone the repository
git clone https://github.com/WebCarePro/webcare-pro-security.git
cd webcare-pro-security

# Install dependencies
npm install

# Compile the production React build
npm run build

# Package the clean release zip for WordPress.org
npm run package
```

---

## 🆘 Locked Out? How to Unblock Yourself Immediately

If your IP address gets temporarily blocked by login rate-limiting, honeypot traps, or strict firewall inspection rules, you can instantly restore access without breaking your site using any of these 4 failsafe methods:

### Method 1: Emergency `wp-config.php` Whitelist Override (Fastest & Recommended)
Add this single line near the top of your `wp-config.php` file (above the `/* That's all, stop editing! */` comment) with your public IP address:

```php
define('WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP', '203.0.113.1');
```

> [!TIP]
> You can also specify multiple comma-separated IP addresses or CIDR subnets:
> `define('WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP', '203.0.113.1, 198.51.100.0/24');`  
> This override executes with zero database dependencies and grants an instantaneous, zero-delay bypass across all WAF rules and login hardening checks.

### Method 2: Emergency Firewall Bypass Constant
If you need to temporarily disable all WAF inspection rules without deactivating or deleting the plugin:

```php
define('WEBCAREPROSCAN_DISABLE_WAF', true);
```

### Method 3: Reset Login Lockouts via WP-CLI
If you have SSH/terminal access to your server, flush active login brute-force lockouts with a single command:

```bash
wp option delete webcareproscan_login_lockouts
```

### Method 4: Clear Lockout via Database (phpMyAdmin / MySQL)
Open phpMyAdmin or your MySQL client, navigate to your site's `wp_options` table, search for the option named `webcareproscan_login_lockouts`, and delete or empty that row. Access is immediately restored upon next page reload.

---

## 🔒 Security & WordPress.org Directory Compliance

WebCare Pro Security & Firewall is strictly developed in adherence to the **WordPress.org Plugin Guidelines**:
- **Non-Destructive Core Policy**: Does not blindly delete or modify core files. When core files are flagged as tampered, administrators can use 1-click Auto-Cure to restore clean, bit-for-bit official copies directly from WordPress.org with automated pre-restoration rollback backups, or leverage official WordPress update workflows (`update-core.php`) and WP-CLI (`wp core download --force`).
- **Protected File Storage**: Quarantine vaults, audit logs, and compressed database backups are stored exclusively within `wp-content/uploads/webcare-pro-security/`, guarded by Apache/LiteSpeed `.htaccess` (`Require all denied`) and silent PHP index files.
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
- 📦 **Repository:** [https://github.com/WebCarePro/webcare-pro-security](https://github.com/WebCarePro/webcare-pro-security)

---

## 🔒 Privacy, Zero Telemetry & Data Protection Guarantee

- **Zero Tracking or Analytics:** WebCare Pro Security & Firewall does NOT track, collect, store, or sell any personal data, analytics, or browsing habits from your WordPress website, its visitors, or its administrators.
- **No Sensitive Data Transmission:** The plugin operates entirely on your local server. It does NOT transmit sensitive credentials, passwords, database records, client data, or private files to any third-party server or external cloud.
- **100% On-Premise Execution:** Core scans, heuristic engines, File Integrity Monitoring (FIM), brute-force defenses, RFC 6238 TOTP 2FA generation, and firewall evaluations run 100% locally within your PHP environment.
- **Explicit Administrator Integrations Only:** External connections (WordPress.org checksums, threat intelligence feeds, Cloudflare edge sync, AI forensic assistance, or Slack/Discord webhooks) only execute when explicitly configured or initiated by the site administrator, transmitting only non-sensitive diagnostic parameters strictly necessary for the requested feature.

---

## 📄 License & Attribution

- **License:** Open source under the terms of the [GNU General Public License v2.0 or later (GPL-2.0-or-later)](https://www.gnu.org/licenses/gpl-2.0.html).
- **Author & Copyright:** © 2013–2026 **Mir Alamin** / **[WebCare Pro](https://webcarespro.com)**. All rights reserved.
