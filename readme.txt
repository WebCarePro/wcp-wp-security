=== WCP Security Scanner ===
Contributors: miralamin
Donate link: https://webcarespro.com
Tags: security, malware, scanner, integrity, antivirus
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Professional security & malware scanner with core integrity checks, heuristic threat analysis, automated scheduling, and modern React dashboard.

== Description ==

WCP Security Scanner gives you enterprise-grade malware detection, core integrity auditing, and threat forensics inside an intuitive, modern React single-page dashboard. Engineered by WebCare Pro for high-performance sites, it provides deep visibility across your file system, WordPress core files, plugins, themes, database tables, cron jobs, and server configurations—without the performance bloat of traditional security tools.

= Multi-Vector Security & Malware Scanning =
* **Deep Heuristic PHP Code Analysis**: Scans for webshells, backdoors, Trojan droppers, and remote access tools (c99, r57, b374k, WSO, China Chopper). Detects obfuscated code patterns including nested eval(base64_decode()), gzinflate(), str_rot13(), dynamic variable functions, hex/octal encodings, and spoofed file headers.
* **WordPress Core Cryptographic Integrity Engine**: Validates core files against official WordPress.org cryptographic MD5 checksum APIs. Pinpoints modified, injected, tampered, or missing core files in wp-admin, wp-includes, and root directories.
* **Uploads Executable & Script Shield**: Recursively audits wp-content/uploads/ for prohibited script extensions (.php, .phtml, .phps, .sh, .py, .pl), disguised double-extensions (shell.jpg.php), and rogue .htaccess overrides.
* **Database Threat & Content Injection Scanner**: Deeply inspects wp_posts, wp_options, wp_users, and wp_comments for stored cross-site scripting (Stored XSS), malicious iframes, pharmaceutical spam links, hidden redirect doorways, and unauthorized admin user records.
* **Crontab & Scheduled Task Auditing**: Audits both Linux server-level crontab files (/var/spool/cron, crontab -l) and WordPress virtual wp-cron hooks for unauthorized piped downloads (curl | bash, wget | sh), reverse shells, and persistence callbacks.
* **User Account & Privilege Security**: Identifies weak administrator configurations, dormant superusers, and suspicious newly spawned administrator accounts.
* **Server Configuration & Hardening Safeguards**: Validates permissions for wp-config.php and .htaccess, audits WP_DEBUG exposure flags, and blocks public HTTP access to .env, .git, .user.ini, and database dumps.

= Software Intelligence & CVE Vulnerability Engine =
* **Curated CVE Advisory Database**: Scans installed WordPress core, plugins, and active/inactive themes against an offline-resilient vulnerability database.
* **Granular Vulnerability Metadata**: View CVSS risk scores, severity badges (Critical, High, Medium, Low), affected versions, patched versions, and official NIST NVD reference advisories.
* **Interactive Vulnerabilities Dashboard**: Filter by component type (Core, Plugins, Themes) or status (Vulnerable, Outdated, Clean). Includes 1-click update links to native WordPress update screens and an in-depth CVE forensic breakdown modal.

= Threat Forensics, Code Viewer & Quarantine Vault =
* **In-Browser Dark-Theme Code Inspector**: Built-in Monaco/terminal-style viewer (#090d16) with line numbering, syntax highlighting, search/filtering, and automatic scroll-to-line highlight on flagged threat snippets.
* **Database Content Inspector**: Dedicated modal for inspecting database post/page threats, showing post metadata, snippet preview, direct editor links, and live post permalinks.
* **Secure Quarantine Vault**: Safely isolates infected files into a protected, .htaccess-guarded directory. Preserves original file permissions, timestamps, and SHA-256 cryptographic hashes, with 1-click instant restoration or permanent deletion.

= Database Vault & System Diagnostics =
* **One-Click Database Backup Vault**: Creates instant on-demand database dumps with automatic .sql.gz Gzip compression, size metadata indexing, and secure browser downloads.
* **Real-Time Environment Diagnostics**: Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (cURL, OpenSSL, sodium, Zip), MySQL collation, database size, and OS architecture.
* **Historical Audit Logs**: Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

= Settings, Automation & AI Forensics =
* **Automated Scheduled Scans**: Run hands-free recurring scans via WP-Cron on an Hourly, Twice Daily, Daily, or Weekly schedule, with configurable off-peak execution times (HH:MM server time) and selectable scan depth.
* **Instant Email Security Alerts**: Dispatches HTML email alerts on detection of Critical or High severity threats or CVE advisories, with configurable recipient lists and severity thresholds.
* **Multi-Provider AI Intelligence**: Integrated forensic analysis with Google Gemini (Gemini 3.8 Flash), OpenAI (GPT-6.1 Sol, GPT-4o), and Anthropic Claude (Claude Sonnet 5.5).
* **WordPress 7.0+ Core AI Client Bridge**: Automatically detects and leverages WordPress 7.0+ native wp_ai_client() site-level AI credentials for zero-configuration AI forensics.
* **1-Click AI Code Forensics Modal**: Decodes obfuscated scripts in seconds, determines whether code is safe or malicious, assesses threat confidence, and generates clean surgical remediation patches.
* **Performance & Developer Safeguards**: Configurable scan batch sizes (25 to 200 files/batch), memory limit overrides (256 MB to 1024 MB), heuristic file size thresholds, custom path exclusions (e.g., wp-content/cache/*), and 1-click generator tag hiding.
* **Settings Import & Export**: 1-click JSON export and import for seamless fleet deployment across multi-site agency portfolios, plus factory reset safeguards.
* **Clean Uninstall & Data Privacy**: Standard uninstall.php lifecycle script. When Auto-Remove All Data on Uninstall is active (default), deleting the plugin automatically drops all 4 custom tables (wp_wcp_scans, wp_wcp_scan_issues, wp_wcp_scan_files, wp_wcp_quarantine), removes options/transients, clears crons, and purges the upload storage folder.

= Author =
* **Author**: Mir Alamin
* **Upwork**: [Mir Alamin on Upwork](https://www.upwork.com/freelancers/~0162afa9a578170c67) (Top Rated Plus Freelancer, 100% Job Success Score)
* **Website**: [WebCare Pro](https://webcarespro.com)

= About WebCare Pro =
WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux & cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—we keep your online presence fast, secure, and always available. Founded in 2013 by Mir Alamin, WebCare Pro has delivered over 680+ client projects with 100% verified 5-star success.

== Installation ==

1. Upload the `wcp-security-scanner` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Security Scanner** in the WordPress admin sidebar.
4. Click **Start Scan Now** to analyze your site.

== External Services ==

This plugin connects to external services to provide file integrity verification and optional AI-assisted code forensic analysis:

1. WordPress.org API
* Service: Official WordPress.org API (https://api.wordpress.org and https://downloads.wordpress.org).
* Purpose: Verifies core WordPress file checksums and installed plugin checksums to detect modified, backdoored, or tampered files.
* Data Sent: WordPress version, locale, and public plugin slugs/versions being audited. No private user data, code, or personal information is transmitted.
* When: Triggered when the user initiates a Core Integrity or Plugin Integrity scan, or during an automated scheduled scan.
* Terms of Service: https://wordpress.org/about/terms/
* Privacy Policy: https://wordpress.org/about/privacy/

2. Google Gemini API (Google AI)
* Service: Google Generative AI API (https://generativelanguage.googleapis.com).
* Purpose: Provides optional AI-assisted forensic code analysis and de-obfuscation for detected suspicious code snippets.
* Data Sent: Only the specific flagged code snippet, relative file path, and detected threat signature when explicitly requested by the administrator via the "Analyze with AI" modal.
* When: Only on-demand when the administrator inputs their own Google Gemini API key and clicks "Analyze with AI" or tests API connectivity.
* Terms of Service: https://ai.google.dev/terms
* Privacy Policy: https://policies.google.com/privacy

3. OpenAI API
* Service: OpenAI API (https://api.openai.com).
* Purpose: Provides optional AI-assisted forensic code analysis and de-obfuscation for detected suspicious code snippets.
* Data Sent: Only the specific flagged code snippet, relative file path, and detected threat signature when explicitly requested by the administrator via the "Analyze with AI" modal.
* When: Only on-demand when the administrator inputs their own OpenAI API key and clicks "Analyze with AI" or tests API connectivity.
* Terms of Service: https://openai.com/policies/terms-of-use/
* Privacy Policy: https://openai.com/policies/privacy-policy/

4. Anthropic Claude API
* Service: Anthropic API (https://api.anthropic.com).
* Purpose: Provides optional AI-assisted forensic code analysis and de-obfuscation for detected suspicious code snippets.
* Data Sent: Only the specific flagged code snippet, relative file path, and detected threat signature when explicitly requested by the administrator via the "Analyze with AI" modal.
* When: Only on-demand when the administrator inputs their own Anthropic API key and clicks "Analyze with AI" or tests API connectivity.
* Terms of Service: https://www.anthropic.com/legal/consumer-terms
* Privacy Policy: https://www.anthropic.com/legal/privacy

== Source Code & Build ==

This plugin is open-source under GPLv2 or later. Non-minified React and JavaScript source files are included directly in the `src/` directory.

The public source repository is hosted on GitHub:
https://github.com/webcarepro/wcp-wp-security

To compile the React admin application from source:
1. Ensure Node.js 18+ and npm are installed.
2. In the plugin root, run `npm install`.
3. Run `npm run build` to generate the production bundle in `build/index.js`.
