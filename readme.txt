=== WCP Security Scanner ===
Contributors: miralamin
Donate link: https://webcarespro.com
Tags: security, malware, scanner, integrity, firewall, 2fa
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Professional security & malware scanner with core integrity checks, heuristic threat analysis, automated scheduling, and modern React dashboard.

== Description ==

WCP Security Scanner gives you enterprise-grade malware detection, core integrity auditing, web application firewalling (WAF), session sentinel, rogue admin detection, and threat forensics inside an intuitive, modern React single-page dashboard. Engineered by WebCare Pro for high-performance sites, it provides deep visibility across your file system, WordPress core files, plugins, themes, database tables, cron jobs, active sessions, runtime hooks, and server configurations—without the performance bloat of traditional security tools.

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
* **Clean Uninstall & Data Privacy**: Standard uninstall.php lifecycle script. When Auto-Remove All Data on Uninstall is active (default), deleting the plugin automatically drops all 5 custom tables (wp_wcp_scans, wp_wcp_scan_issues, wp_wcp_scan_files, wp_wcp_quarantine, wp_wcp_firewall_logs), removes options/transients, clears crons, and purges the upload storage folder.

= Web Application Firewall (WAF Lite) & Virtual Patching =
* **Real-Time Request Filtering**: Inspects incoming HTTP payloads at plugins_loaded (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
* **Attack Vector Shields**: Blocks SQL Injections (UNION SELECT, information_schema, benchmark), Cross-Site Scripting (XSS scripts/handlers), Path Traversal & LFI (/etc/passwd, php://filter), PHP code tag injections (<?php, eval, base64_decode, system), and XML-RPC exploitation.
* **Smart Cloudflare & Coexistence**: Decodes visitor Real-IP from HTTP_CF_CONNECTING_IP with Cloudflare proxy range validation. Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.
* **Live Incidents Stream & Controls**: Real-time blocked attack table, 1-click IP whitelisting, Learning Mode toggle (audit-only logging), and individual rule toggles. Custom dark-themed 403 Forbidden screen with incident reference IDs.

= Real-Time File Integrity Monitoring (FIM) & Code Diff Viewer =
* **Filesystem Change Tracker**: Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
* **Custom & Premium Component Recognition**: Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to prevent false-positive alarms.
* **Bit-for-Bit Visual Code Diff Viewer**: Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org release mirrors with side-by-side and unified views.

= One-Click Malware Remediation & Auto-Cure Engine =
* **Automated Webshell Stripping**: 1-click surgical neutralization of malicious code headers, obfuscated base64/eval wrappers, and backdoor includes while preserving legitimate file code with tokenizer syntax validation.
* **Official WordPress.org Restoration**: 1-click replacement of infected or tampered plugin/theme files with authentic, bit-for-bit verified copies fetched directly from official release mirrors.
* **Auto-Cure Safety Backups & Rollback Vault**: Creates timestamped safety backups in a secure directory before every remediation action, enabling instant 1-click restoration if needed.

= Cloud Threat Intelligence & Botnet Feeds =
* **Community Botnet IP Blacklists**: Synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL. Performs static in-memory O(1) hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
* **Zero-Day CVE Feed & Site Correlation**: Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes, displaying status badges (Installed - Vulnerable, Installed - Patched, Global Virtual Shield) and filter controls.
* **IP Reputation Diagnostic Tool**: Built-in checker to test client or visitor IPs against the active threat database.

= Multi-Factor Authentication (2FA) & Login Hardening =
* **Pure PHP RFC 6238 TOTP Engine**: Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
* **Native wp-login.php Interception**: Displays a responsive, branded two-factor verification challenge screen with support for rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
* **Brute Force Rate-Limiter**: Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.

= HTTP Security Headers & Site Hardening =
* **Enterprise Security Headers Dispatcher**: Injects HSTS (with optional preload), X-Frame-Options (DENY/SAMEORIGIN), X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy, and Content-Security-Policy (CSP Lite).
* **Runtime PHP Editor Lock**: Defuses file editor exploits by locking theme and plugin code editing at runtime via DISALLOW_FILE_EDIT.
* **Reconnaissance & User Enumeration Defense**: Blocks author archive scraping (/?author=1) and strips sensitive user endpoints from public REST API queries. Strips WordPress version meta tags and enqueued asset query strings (?ver=).
* **Sensitive File HTTP Probe Shield**: Returns 403 Forbidden on incoming requests attempting to read .env, .git, .htaccess, .sql, and composer.json.
* **1-Click Hardening Presets**: Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (A+, A, B, C).

= Session Sentinel & Anti-Hijack Defense =
* **Active Administrative Session Inspector**: Real-time tracking of active user logins via WP_Session_Tokens with IP address, browser, OS, and timestamp telemetry.
* **Strict IP Lock & Anti-Replay**: Automatically detects and revokes hijacked sessions if client IP shifts during an active login.
* **Concurrent Login Block**: Enforces single-session policies by invalidating older sessions when an administrator logs in from a new machine.
* **Configurable Idle Inactivity Revocation**: Automatically logs out abandoned admin sessions after configurable periods (default: 120m).
* **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

= Database Micro-Anomaly & Rogue Administrator Trap =
* **Stealth User Infiltration Detection**: Audits wp_users against wp_usermeta to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
* **Ghost & Orphaned Capability Hunting**: Uncovers orphaned capability rows in wp_usermeta pointing to non-existent user IDs left behind by malware droppers.
* **Privilege Escalation Trap**: Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
* **Database Rootkit & Transient Probe**: Recursively scans wp_options for obfuscated execution payloads (eval, base64_decode, gzinflate) hidden in transient names.

= Bot Recon Defense & AI Scraper Shield =
* **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
* **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (GPTBot, CCBot, Bytespider, ClaudeBot, PerplexityBot, Diffbot) at the WAF level.
* **Dynamic Virtual robots.txt Injection**: Automatically generates and injects standard AI bot Disallow directives into virtual robots.txt.

= Living-off-the-Land (LotL) Native Hook Infiltration Sentinel =
* **Active Runtime Memory Hook Audit**: Uses reflection to inspect active runtime hook callbacks registered in $wp_filter across high-risk lifecycle actions (authenticate, wp_authenticate, template_redirect, wp_head, wp_footer, user_register, xmlrpc_call).
* **Anonymous Closure & Credential Sniffer Detection**: Flags anonymous Closure functions attached to sensitive authentication and login hooks that could steal passwords.
* **External Rootkit & Uploads Hook Traps**: Detects hook callbacks originating outside WordPress root (auto_prepend_file or system rootkits) and callbacks executing inside wp-content/uploads/ (webshell callbacks).
* **Dangerous Native Function Registration Defense**: Detects dangerous native PHP functions (eval, assert, shell_exec, system, passthru) attached directly as WordPress filter callbacks.

= DevSecOps Chat Webhooks (Slack & Discord) =
* **Real-Time Security Notifications**: Delivers rich Block Kit (Slack) and Embed (Discord) alert cards when critical vulnerabilities are found, files are altered, or attacks are blocked.
* **Attack Flood Protection**: Built-in 60-second rate-limiting prevents channel notification spamming during brute-force or DDoS storms.
* **Live Webhook Testing API**: 1-click test button inside Scanner Settings to verify webhook URL configuration instantly.

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

5. Community Botnet & Threat Intelligence Feeds
* Service: Blocklist.de (https://lists.blocklist.de) and Stamparm Ipsum (https://raw.githubusercontent.com/stamparm/ipsum).
* Purpose: Downloads publicly aggregated lists of known malicious botnet and brute-force IP addresses for firewall perimeter protection.
* Data Sent: No user, site, or visitor data is transmitted. Only public plain-text threat lists are downloaded via standard HTTP GET.
* When: Synchronized bi-daily (every 12 hours) via WP-Cron or when the administrator clicks "Sync Threat Intel Now".
* Terms of Service: https://www.blocklist.de/en/tos.html
* Privacy Policy: https://www.blocklist.de/en/privacy.html

6. Slack Webhook API (Optional)
* Service: Slack Technologies (https://hooks.slack.com).
* Purpose: Sends optional security incident notifications (critical malware discoveries, WAF blocks) to the administrator's designated Slack channel.
* Data Sent: Alert notification message, site name, threat severity, and incident timestamp.
* When: Triggered only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://slack.com/terms-of-service
* Privacy Policy: https://slack.com/privacy-policy

7. Discord Webhook API (Optional)
* Service: Discord Inc. (https://discord.com/api/webhooks).
* Purpose: Sends optional security incident notifications to the administrator's designated Discord channel.
* Data Sent: Alert notification embed card, site name, threat severity, and incident timestamp.
* When: Triggered only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://discord.com/terms
* Privacy Policy: https://discord.com/privacy

== Source Code & Build ==

This plugin is open-source under GPLv2 or later. Non-minified React and JavaScript source files are included directly in the `src/` directory.

The public source repository is hosted on GitHub:
https://github.com/webcarepro/wcp-wp-security

To compile the React admin application from source:
1. Ensure Node.js 18+ and npm are installed.
2. In the plugin root, run `npm install`.
3. Run `npm run build` to generate the production bundle in `build/index.js`.

== Changelog ==

= 1.5.0 =
* Added Web Application Firewall (WAF Lite) with real-time early request filtering, virtual patching, and custom 403 Forbidden screen.
* Added Real-Time File Integrity Monitoring (FIM) with pure PHP Myers/LCS visual code diff viewer against WordPress.org SVN release mirrors.
* Added One-Click Malware Remediation / Auto-Cure Engine with webshell stripping, official WordPress.org restoration, and automatic rollback safety backups.
* Added Cloud Threat Intelligence & Community Botnet IP Blacklists with zero-day CVE site correlation and O(1) in-memory subnet matching.
* Added Multi-Factor Authentication (2FA) with RFC 6238 TOTP engine, emergency recovery codes, and brute-force login hardening.
* Added HTTP Security Headers Engine & 1-Click Hardening with HSTS, X-Frame-Options, CSP Lite, user enumeration defense, and sensitive file probe shield.
* Added Active Session Sentinel with strict IP locking, concurrent login prevention, and remote session revocation.
* Added Database Micro-Anomaly & Rogue Administrator Trap for stealth SQL user injections, ghost capabilities, and transient rootkits.
* Added Bot Recon Defense & AI Scraper Shield with reverse DNS search crawler verification and dynamic robots.txt injection.
* Added Living-off-the-Land (LotL) Native Hook Infiltration Sentinel auditing runtime $wp_filter for closures and malicious memory callbacks.
* Added DevSecOps Chat Webhooks for real-time Slack and Discord security notifications.
* Added automatic detection and exclusion for harmless directory protection index.php files in uploads and custom/premium components in FIM.
* Added clean 5-table database purge on plugin uninstall (uninstall.php).
* Redesigned Scanner Settings with modern segmented pill navigation and animated toggle switches.
