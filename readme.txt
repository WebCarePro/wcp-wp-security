=== WCP Security Scanner ===
Contributors: miralamin
Donate link: https://webcarespro.com
Tags: security, malware, ai-security, firewall, 2fa
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.24.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security, malware detection, web application firewall (WAF), core integrity auditing, and threat intelligence.

== Description ==

WCP Security Scanner gives you enterprise-grade malware detection, core integrity auditing, web application firewalling (WAF), session sentinel, rogue admin detection, and threat forensics inside an intuitive, modern React 18 single-page dashboard. Engineered by Mir Alamin (WebCare Pro) for high-performance WordPress sites, it provides deep visibility across your file system, WordPress core files, plugins, themes, database tables, cron jobs, active sessions, runtime hooks, and server configurations—without the performance bloat of traditional security tools.

= 1. Next-Gen Cyber Command Center & Threat Dashboard =
* **High-Precision SVG Security Health Meter**: Circular dynamic vector meter displaying site security score (0–100%) with reactive color accents (emerald #10b981, sky blue #38bdf8, amber #f59e0b, rose #ef4444) and live letter grades (A+, A, B, C, D, F).
* **Interactive Threat Metric Cubes**: High-contrast summary widgets grouping active threats into 3 primary vectors: Critical Exploits & Backdoors, File Integrity & Code Drift, and Software Vulnerabilities & CVE Advisories, with instant 1-click category filtering.
* **Audit Command Center Console**: Fast single-click execution controls (Full Deep Audit vs Fast Audit), live engine telemetry indicators, dual-layer animated scan progress bar, and instant cancellation controls.
* **Interactive Findings Hub**: Modern alternating zebra row styling with severity-tinted accent borders, quick filter pills, monospace path breadcrumbs with 1-click clipboard copy, and real-time instant text search.

= 2. Multi-Vector Security & Deep Malware Scanning =
* **Deep Heuristic PHP Code Analysis**: Scans for webshells, backdoors, Trojan droppers, and remote access tools. Detects obfuscation patterns including nested decode wrappers, decompression routines, dynamic variable functions, hex/octal encodings, and malicious file header spoofs.
* **WordPress Core Cryptographic Integrity Engine**: Validates core files against official WordPress.org cryptographic MD5 checksum APIs. Pinpoints modified, injected, tampered, or missing core files in wp-admin, wp-includes, and root directories.
* **Uploads Executable & Script Shield**: Recursively audits wp-content/uploads/ for prohibited script extensions (.php, .phtml, .phps, .sh, .py, .pl), disguised double-extensions (shell.jpg.php), and rogue .htaccess execution overrides.
* **Database Threat & Content Injection Scanner**: Deeply inspects wp_posts, wp_options, wp_users, and wp_comments for stored cross-site scripting (Stored XSS), malicious iframes, pharmaceutical spam links, hidden redirect doorways, and unauthorized admin user records.
* **Hierarchical Resumable Cursor Engine**: Replaces slow numeric offset pagination with an opaque two-level hierarchical cursor, completely eliminating O(N^2) filesystem re-traversals on large WordPress sites with bounded ~15–25MB batch heap delta and cycle-safe non-symlink traversal.
* **High-Throughput Findings Bulk Ingestion**: Persists file audit and finding records using prepared multi-row SQL batches capped at 80 rows per statement via FindingsRepository, staying safely under MySQL max_allowed_packet with safe null parameter binding and zero table lock contention.
* **Crontab & Scheduled Task Auditing**: Audits both Linux server-level crontab files (/var/spool/cron, crontab -l) and WordPress virtual wp-cron hooks for unauthorized piped downloads (curl | bash, wget | sh), reverse shells, and persistence callbacks.
* **User Account & Privilege Security**: Identifies weak administrator configurations, dormant superusers, and suspicious newly spawned administrator accounts.
* **Server Configuration & Hardening Safeguards**: Validates permissions for wp-config.php and .htaccess, audits WP_DEBUG exposure flags, and blocks public HTTP access to .env, .git, .user.ini, and database dumps.

= 3. Targeted Single-Purpose Security Audits & Auto-Scroll =
* **7 Dedicated Rapid Audit Modules**: Database Injections, Uploads Quarantine Audit, Theme Integrity Deep Scan, Plugin Vulnerabilities Audit, Core Checksums Audit, Privilege Escalation Check, and Runtime Hook Infiltration (LotL).
* **Automatic Smooth Viewport Auto-Scroll**: When any targeted audit completes, the UI smoothly auto-scrolls the viewport directly to the Targeted Audit Results section (scrollMarginTop: 24px), presenting findings and risk scores immediately.

= 4. Real-Time File Integrity Monitoring (FIM) & Code Diff Viewer =
* **Filesystem Change Tracker**: Monitors WordPress Core, active Plugins, Themes, and Uploads directories with customizable historical audit windows (24h, 48h, 7d, 30d).
* **Custom & Premium Component Recognition**: Automatically identifies custom or commercial plugins/themes not hosted on WordPress.org, excluding them from repository baseline checks to prevent false-positive alarms.
* **In-Page Visual Code Diff Viewer Modal**: Pure PHP Myers/LCS visual diff engine comparing modified server files against official WordPress.org release mirrors line-by-line with side-by-side additions and deletions.

= 5. 1-Click Auto-Cure & Surgical Remediation Engine =
* **1-Click WordPress Core Auto-Cure**: Restores tampered core files inside wp-admin, wp-includes, and root directories back to official pristine WordPress.org release code matching the exact site WordPress version, without re-installing all of WordPress.
* **1-Click Plugin & Theme Auto-Cure**: Restores altered or infected plugin and theme files back to authentic, bit-for-bit verified copies fetched directly from WordPress.org release mirrors.
* **1-Click Webshell Stripping**: Surgically neutralizes malicious code headers, obfuscated eval()/base64 wrappers, and backdoor includes while preserving legitimate file code with tokenizer syntax validation.
* **1-Click Scheduled Cron Hook Remediation**: Safely unschedules and purges orphaned or malicious cron hooks directly from wp_options:cron via wp_clear_scheduled_hook().
* **Auto-Cure Safety Backups & Rollback Vault**: Creates timestamped safety backups in a secure directory before every remediation action, enabling instant rollback if needed.
* **Real-Time State Synchronization**: As soon as an issue is cured, the findings table updates to display an Issue Solved & Restored status badge and transitions mitigation actions automatically.

= 6. Secure Quarantine Vault & Isolation Architecture =
* **Safe Cryptographic Isolation**: Safely isolates infected or unknown files into a protected, .htaccess-guarded directory outside executable paths. Preserves original file permissions, timestamps, and SHA-256 cryptographic hashes in wp_wcp_quarantine.
* **Intelligent Quarantine Eligibility Safeguards**: Enforces strict boundaries to prevent quarantining critical configuration files (wp-config.php, .htaccess, index.php) and modified official components, ensuring isolation is strictly reserved for rogue and unknown alien files.
* **Quarantine Vault Hub**: Responsive table with horizontal overflow support, 1-click instant file restoration, and permanent vault deletion.

= 7. Software Intelligence & Curated CVE Advisory Database =
* **Curated CVE Advisory Database**: Scans installed WordPress core, plugins, and active/inactive themes against an offline-resilient vulnerability database.
* **Granular Vulnerability Metadata**: View CVSS risk scores, severity badges (Critical, High, Medium, Low), affected versions, patched versions, and official NIST NVD reference advisories.
* **Interactive Vulnerabilities Dashboard**: Filter by component type (Core, Plugins, Themes) or status (Vulnerable, Outdated, Clean). Includes 1-click update links to native WordPress update screens and an in-depth CVE forensic breakdown modal.

= 8. Living-off-the-Land (LotL) Native Hook Infiltration Sentinel =
* **Active Runtime Memory Hook Audit**: Uses reflection to inspect active runtime hook callbacks registered in $wp_filter across high-risk lifecycle actions (authenticate, wp_authenticate, template_redirect, wp_head, wp_footer, user_register, xmlrpc_call, rest_pre_serve_request).
* **Anonymous Closure & Credential Sniffer Detection**: Flags anonymous Closure functions attached to sensitive authentication and login hooks that could steal passwords.
* **External Rootkit & Uploads Hook Traps**: Detects hook callbacks originating outside WordPress root (auto_prepend_file or system rootkits) and callbacks executing inside wp-content/uploads/ (webshell callbacks).
* **Dangerous Native Function Registration Defense**: Detects dangerous native PHP functions (eval, assert, shell_exec, system, passthru) attached directly as WordPress filter callbacks.

= 9. Database Micro-Anomaly & Rogue Administrator Trap =
* **Stealth User Infiltration Detection**: Audits wp_users against wp_usermeta to catch zombie administrator accounts inserted directly via SQL that bypass standard WordPress registration hooks.
* **Ghost & Orphaned Capability Hunting**: Uncovers orphaned capability rows in wp_usermeta pointing to non-existent user IDs left behind by malware droppers.
* **Privilege Escalation Trap**: Catches privilege inconsistencies where administrator capabilities do not match standard user level 10.
* **Database Rootkit & Transient Probe**: Recursively scans wp_options for obfuscated execution payloads (eval, base64_decode, gzinflate) hidden in transient names.

= 10. Web Application Firewall (WAF Lite) & Virtual Patching =
* **Real-Time Request Filtering**: Inspects incoming HTTP payloads at plugins_loaded (priority 0) with sub-millisecond evaluation before core WordPress queries execute.
* **Attack Vector Shields**: Blocks SQL Injections (UNION SELECT, information_schema, benchmark), Cross-Site Scripting (XSS scripts/handlers), Path Traversal & LFI (/etc/passwd, php://filter), PHP code tag injections (<?php, eval, base64_decode, system), and XML-RPC exploitation.
* **Smart Cloudflare & Coexistence**: Decodes visitor Real-IP from HTTP_CF_CONNECTING_IP with Cloudflare proxy range validation. Auto-negotiates with Wordfence, Sucuri, and Solid Security into Complementary Virtual Patching mode without hook conflicts.
* **Live Incidents Stream & Controls**: Real-time blocked attack table, 1-click IP whitelisting, Learning Mode toggle (audit-only logging), and individual rule toggles. Custom dark-themed 403 Forbidden screen with incident reference IDs.

= 11. Dedicated WAF Incident Logs & Threat Intelligence =
* **Dedicated Submenu & Edge Route**: Full-page WAF logs forensics view accessible directly via direct link and deep-linked from Firewall header actions and navigation bar.
* **Real-Time Telemetry & Threat Metrics**: 4 live KPI cards (Total Incursions Blocked, 24h Attack Surge, Distinct Attack IPs, Simulation/Learning mode hits).
* **Threat Vector & Offender Analytics Grid**: Top Attack Vectors breakdown with proportional percentage bars and Frequent Offending Hostile IP Directory with hit counts, last seen timestamps, and 1-click Filter/Block actions.
* **Multi-Field Search & Forensic Filtering**: Real-time search across IP addresses, target URIs, malicious payload signatures, and User-Agents, combined with category, action, and HTTP method filters.
* **Expandable Forensic Deep-Dive Accordion**: Per-incident inspection view displaying rule trigger descriptions, raw User-Agent fingerprints, and syntax-highlighted malicious payload excerpts with 1-click JSON export.
* **Export & Forensics Reporting**: Integrated export tools to download filtered incident records as CSV (.csv), raw JSON (.json), or formatted printable audit reports (window.print()).

= 12. Smart 404 Scanner Rate-Limiter & Reconnaissance Shield =
* **Automated 404 Scanner Lockouts**: Automated temporary lockout mitigation against fuzzing and vulnerability scanning bots that trigger repetitive 404 errors across WordPress installations (default 10 probes in 60s trigger 30-minute block).
* **DNS-Verified Search Engine Exemption**: Genuine search engines (Googlebot, Bingbot, DuckDuckBot, Yandex, Baidu, Yahoo) verified via Reverse DNS (PTR) + Forward DNS (A/AAAA) confirmation with 24h caching are strictly exempted to prevent search engine indexing drops or SEO penalties.
* **Static Asset & Media Exclusion**: Missing static assets (.jpg, .png, .webp, .svg, .css, .js, .ico, .woff, .pdf) are ignored from 404 tallies, completely preventing false-positive lockouts for legitimate human visitors.
* **High-Risk Reconnaissance Acceleration**: High-threat backdoor and sensitive file probes (.env, .git, .bak, wp-config.php.bak, shell.php, database dumps) advance the counter by 3 to swiftly isolate active exploit scanners.

= 13. Cloudflare Edge Defense & Zero-Resource WAF (100% Free Plan Compatible) =
* **Zero-Resource Threat Interception**: Blocks malicious bots and automated exploits at Cloudflare's Global Anycast Edge before requests ever reach your origin server or consume PHP and MySQL resources.
* **3 Master Compound Rules (Free Plan Calibrated)**: Consolidates edge defense into 3 high-impact master compound rules: Rule 1 (Master Perimeter & Sensitive File Armor), Rule 2 (LFI/RFI Directory Traversal & Reconnaissance Shield), and Rule 3 (Login Portal Automated Bot Defense), leaving 2 custom rule slots (40% of quota) free.
* **Individual Single-Rule Push & Remove**: Push, update, or remove individual Cloudflare edge rules independently via REST API (/cloudflare/deploy-single-rule) without redeploying entire rulesets.
* **Cloudflare Free Rate Limiter**: Deploys edge rate limiting on /wp-login.php (5 requests / 60s per IP, 10s mitigation cooldown) to mitigate brute-force attacks with zero server resource consumption.
* **Bi-Directional WAF Auto-Ban Sync**: Automatically syncs locally detected high-threat attack IPs to Cloudflare Edge IP Access Rules.
* **1-Click CDN Cache Purge**: Instant global edge cache purge directly from the WordPress administration panel.

= 14. Cloud Threat Intelligence & Botnet Feeds =
* **Community Botnet IP Blacklists**: Synchronizes active botnet nodes and brute-force scanner pools from Blocklist.de, Stamparm Ipsum, and FireHOL. Performs static in-memory O(1) hash map and CIDR subnet matching (<0.05ms) to auto-drop botnet traffic at the perimeter.
* **Zero-Day CVE Feed & Site Correlation**: Real-time zero-day vulnerability definitions with WAF virtual patching. Automatically correlates CVEs with installed WordPress Core, plugins, and themes, displaying status badges (Installed - Vulnerable, Installed - Patched, Global Virtual Shield).
* **IP Reputation Diagnostic Tool**: Built-in checker to test client or visitor IPs against the active threat database.

= 15. Active Session Sentinel & Access Control =
* **Active Administrative Session Inspector**: Real-time tracking of active user logins via WP_Session_Tokens with IP address, browser, OS, and timestamp telemetry.
* **Dual-Device Concurrency Control**: Enforces flexible session policies (1 Desktop + 1 Mobile maximum per administrator).
* **1-Click Remote Termination**: Remotely terminate individual compromised sessions or revoke all other sessions with 1-click.

= 16. Inline Expandable User Session Forensics & Real IP Tracking =
* **In-Table Forensic Accordion**: Clicking an administrator row expands the forensic audit panel in place (Hide Forensics / Forensics), completely eliminating viewport modal overlap with admin top bars.
* **Strict Decrypted Origin IP Fidelity**: Inspects the authentic user's decrypted login IP recorded at authentication time ($data['ip']), preventing Cloudflare Anycast edge proxies or viewer reverse proxy IPs from colliding with or overwriting remote administrator IPs.
* **Fallback Session Integrity**: Preserves authentic origin IP telemetry across all core session token iterations and password reset audit trails.

= 17. Multi-Factor Authentication (2FA) & Login Hardening =
* **Pure PHP RFC 6238 TOTP Engine**: Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator without external libraries.
* **Native wp-login.php Interception**: Displays a responsive, branded two-factor verification challenge screen with support for rotating 6-digit TOTP codes and single-use emergency backup recovery codes.
* **AES-256-GCM AEAD Encrypted User Secrets**: Encrypts user TOTP secrets (_wcp_2fa_secret) at rest in wp_usermeta via the Secret Vault with 128-bit authentication integrity tags and transparent in-memory runtime decryption.
* **Brute Force Rate-Limiter**: Tracks failed login attempts per client IP with configurable thresholds and temporary lockout durations with countdown notices.
* **Administrator 2FA Governance & Policy Enforcement**: View all administrator accounts with avatars, 2FA status, and compliance state. Includes 1-click Emergency Unlock & Disable 2FA, 1-click Credential Reset & QR Code Delivery Modal, mandatory 2FA enforcement policies, emergency backup codes (.txt) auto-download guard, and post-setup code regeneration.

= 18. Dedicated Notification Center & Granular 32+ Event Alert Matrix =
* **Dedicated Administrative Notification Hub**: Full-page notification operations hub accessible via direct deep-link from Settings, Firewall, and email footers.
* **32+ Granular Security Events Across 8 Categories**: Core Scans & Threats, Plugin Self-Defense, Cloudflare & WAF Defense, Authentication & Access Security, File Integrity Monitoring, Vulnerabilities & CVE Feeds, Database Backups & Vault, and DevSecOps & AI Forensics.
* **Independent Dual-Channel Matrix**: Independent toggle switches for Email (wp_mail) and DevSecOps Webhooks (Slack, Discord, ClickUp, Asana, Generic JSON) per event.
* **Granular Default Baseline**: By default, only two critical high-priority events are activated ("Plugin Deactivated" and "Critical / High Threats Detected"), while all other 30+ events remain cleanly silenced until customized.
* **Executive Obsidian Email Template**: Branded obsidian styling (#0b1120), glowing priority badges, client IP/device metadata detection, and Schema.org (SecurityIncident) JSON-LD structured data for LLM inbox summarization.
* **1-Click Test Delivery**: Interactive test buttons on each event trigger live test payloads via /notifications/test-event.

= 19. HTTP Security Headers & Site Hardening =
* **Enterprise Security Headers Dispatcher**: Injects HSTS (with optional preload), X-Frame-Options (DENY/SAMEORIGIN), X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy, and Content-Security-Policy (CSP Lite).
* **Runtime PHP Editor Lock**: Defuses file editor exploits by locking theme and plugin code editing at runtime via DISALLOW_FILE_EDIT.
* **Reconnaissance & User Enumeration Defense**: Blocks author archive scraping (/?author=1) and strips sensitive user endpoints from public REST API queries. Strips WordPress version meta tags and enqueued asset query strings (?ver=).
* **Sensitive System File Probe Shield**: Returns 403 Forbidden on requests attempting to access .env, .git, .htaccess, .sql, composer.json, and backup archives.
* **1-Click Hardening Presets**: Instant "Apply Recommended A+ Hardening" preset in Settings with live grade assessment badge (A+, A, B, C).

= 20. Bot Recon Defense & AI Scraper Shield =
* **Fake Search Engine Crawler Defense**: Verifies claimed Googlebot, Bingbot, Slurp, and DuckDuckBot User-Agents via reverse DNS (PTR) and forward DNS (A/AAAA) lookups with 24-hour transient caching to block spoofed reconnaissance probes.
* **AI Content Scraper & Harvester Shield**: Intercepts aggressive AI model scrapers (GPTBot, CCBot, Bytespider, ClaudeBot, PerplexityBot, Diffbot, Cohere-ai) at the WAF level.
* **Dynamic Virtual robots.txt Injection**: Automatically generates and injects standard AI bot Disallow directives into virtual robots.txt.

= 21. Multi-Provider AI Code Forensics (ChatGPT, Gemini, Claude) =
* **Supported AI Forensic Providers**: Google Gemini (3.8 Flash, 2.5 Flash, 1.5 Pro), OpenAI (GPT-6.1 Sol, GPT-4o, GPT-4o-mini), and Anthropic Claude (Sonnet 5.5, 3.7 Sonnet, 3.5 Haiku).
* **WordPress 7.0+ Core AI Client Bridge**: Automatically detects and leverages WordPress 7.0+ native wp_ai_client() site-level AI credentials for zero-configuration AI forensics.
* **1-Click AI Code Forensics Modal**: Decodes obfuscated scripts in seconds, assesses threat confidence (0–100%), explains exploit mechanics, and generates surgical clean code patches.

= 22. Model Context Protocol (MCP) Agentic Surface (AI SecOps Automation) =
* **Native JSON-RPC 2.0 Agentic Integration**: Bridges external AI coding agents (Claude Desktop, Cursor IDE, Antigravity, custom LLM agents) with WordPress security operations over standard JSON-RPC 2.0 and Bearer token authentication.
* **7 First-Class SecOps Tools**: wcp_get_site_health, wcp_list_findings, wcp_get_finding_detail, wcp_list_quarantined_files, wcp_get_waf_stats, wcp_trigger_scan, and wcp_whitelist_finding.
* **Granular Permission Scopes**: Enforce Read-Only (Observation) mode to allow AI agents to safely inspect and diagnose without write privileges, or Full Remediation (Read + Write) for automated incident response.
* **Sliding-Window Rate Limiting & Ring-Buffer Audit**: Per-token rate limiter configurable from 30 to 300 requests/minute and persistent 150-event ring-buffer execution audit trail.

= 23. Cryptographic Secret Vault (Pure AES-256-GCM AEAD & Two-Phase Key Rotation) =
* **Pure AES-256-GCM Authenticated Encryption (AEAD)**: All sensitive third-party API credentials, webhook endpoints, and infrastructure tokens are encrypted at rest before being saved to wp_options.
* **128-bit Cryptographic Authentication Tags**: Cryptographically verifies ciphertext integrity prior to decryption, completely preventing bit-flipping vulnerabilities and CBC padding oracle attacks.
* **Two-Phase Commit Key Rotation Orchestrator (VaultRotator)**: Robust state machine (idle -> preparing -> migrating -> verifying -> committed) manages zero-downtime key rotation with dual-key background decrypt fallback and atomic snapshot rollbacks.
* **Dynamic 256-bit Key Derivation**: Derives keys from WCP_VAULT_KEY environment variables, wp-config.php constants, or cryptographic SHA-256 hashes of 4 WordPress core salts (AUTH_KEY, AUTH_SALT, SECURE_AUTH_KEY, SECURE_AUTH_SALT).

= 24. Unified WCP Vault Console (4 Consolidated Facilities) =
* **Centralized Security Vault Page (wcp-vault)**: Consolidates all site isolation, backup, and encryption primitives into a single high-performance interface with live telemetry and direct deep-linking.
* **Facility 1 — File Quarantine Isolation Vault**: View, inspect, restore, or permanently purge quarantined rogue scripts and backdoors preserved with SHA-256 integrity hashes in .htaccess-protected storage.
* **Facility 2 — Database Snapshot & Point-in-Time Recovery Vault**: Create on-demand Gzip-compressed .sql.gz database snapshots, inspect byte-accurate archive sizes, and download for offsite disaster recovery.
* **Facility 3 — Pre-Cure Safety Rollback & Remediation Vault**: Inspect safety diffs and restore modified files prior to Auto-Cure or webshell stripping actions.
* **Facility 4 — Secret & Cryptographic Key Vault**: Real-time health metrics of the AES-256-GCM AEAD encryption subsystem, including self-healing dual-key decryption fallback, stale rotation lock recovery, and 1-click diagnostic reset.

= 25. On-Demand Database Backup Vault (.sql.gz) =
* **1-Click Database Backup Vault**: Creates instant on-demand database dumps with automatic .sql.gz Gzip compression, size metadata indexing, and secure browser downloads.
* **Secure File Storage**: Guarded by Apache/LiteSpeed .htaccess (Require all denied) and silent PHP index files.

= 26. High-Precision Microsecond Telemetry & Diagnostics =
* **Microsecond Scan Duration Tracking**: Database schema upgraded with started_at (datetime(3)), completed_at (datetime(3)), and duration_ms (int(11)) columns to guarantee sub-second and millisecond tracking across all scan types.
* **Timezone-Aware Accuracy**: Replaced timezone-clashing server queries with WordPress wp_timezone() arithmetic, eliminating drift between server clocks and site timezones.
* **Real-Time Environment Diagnostics**: Live diagnostics for PHP memory limit, execution time, SAPI interface, active extensions (cURL, OpenSSL, sodium, Zip), MySQL collation, database size, and OS architecture.
* **Historical Audit Logs**: Complete chronological history of past scans with durations, scanned file counts, risk scores, and granular issue categorization.

= 27. Behavioral Baseline & Attack Chain Correlation =
* **Behavioral Drift Detection**: Tracks alterations in critical site metadata, administrator counts, PHP execution options, and file counts against historic baselines.
* **Attack Chain Timeline**: Correlates disparate security events (failed login brute-force -> backdoor upload -> cron modification) into a unified chronological breach narrative with estimated blast radius scoring.

= 28. Frictionless 1-Click "Mark Safe / Ignore" UX with SHA-256 Hash-Locking =
* **1-Click Intelligent Suppression**: Instantly suppress known false-positives with a single click. Automatically computes SHA-256 cryptographic checksums of the target file to lock the rule to that exact file version, with a 90-day auto-review safety period.
* **Collapsible Power-User Drawer**: Advanced controls to customize rule match types (Exact SHA-256 Hash vs File Path vs Pattern Signature), adjust expiration periods (30 days, 90 days, 1 year, or Permanent), and log administrative audit rationale.
* **Segmented Findings Status Filtering**: Instantly toggle between Active Threats, Whitelisted / Ignored, and All Findings with dynamic count badges, keeping active security views clean and actionable.

= 29. Data Privacy, Non-Destructive Operations & Clean Uninstall Lifecycle =
* **Automated Pre-Action Safety Backups**: Every Auto-Cure, Quarantine, and Remediation action creates an automated safety snapshot in the local vault before modifying files.
* **Zero Tracking or Analytics**: The plugin does NOT track, collect, store, or sell any personal data, analytics, or browsing habits.
* **100% On-Premise Execution**: Core scans, heuristic checks, file integrity monitoring, brute-force defenses, 2FA generation, and firewall evaluation run 100% locally within your PHP environment.
* **Clean 6-Table Database Purge on Uninstall (uninstall.php)**: When "Auto-Remove All Data on Uninstall" is active (default), deleting the plugin automatically drops all 6 custom database tables (wcpscan_scans, wcpscan_scan_issues, wcpscan_scan_files, wcpscan_quarantine, wcpscan_firewall_logs, wcpscan_login_history), purges user meta, clears transients, deletes options, removes crons, and safely purges the upload storage folder.

= 30. Dual-Theme Design System (High-Contrast White Mode & Dark Obsidian) =
* **Flawless White (Light) Mode Parity**: Custom semantic token architecture guarantees maximum readability, deep contrast, and crisp table borders (#ffffff, #f8fafc, #e2e8f0, #0f172a), eliminating washed-out text or unreadable badges.
* **Midnight Obsidian Dark Mode**: Cyberpunk-inspired deep midnight palette (#090d16 canvas, #0f172a cards, #1e293b borders) with vibrant neon accents and glowing status indicators.
* **1-Click Theme Switcher**: Instant toggle between White Mode and Dark Mode saved in local storage.

== Installation ==

1. Upload the `wcp-security-scanner` folder to the `/wp-content/plugins/` directory, or install directly through the WordPress plugins dashboard.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Access your new cyber command center by clicking **WCP Security** in the admin sidebar.
4. Run your first Deep Audit from the Cyber Command Center.

== Frequently Asked Questions ==

= Does WCP Security Scanner slow down my website? =
No. The scanner is built with a memory-safe batching engine that processes files in non-blocking chunks with zero impact on frontend visitors. The frontend admin interface runs on modern React 18 and only executes within the WordPress admin dashboard.

= What makes the Cryptographic Secret Vault different from other plugins? =
Standard WordPress plugins store sensitive credentials like webhook URLs and Cloudflare tokens in plaintext inside `wp_options`. WCP Security Scanner encrypts all sensitive data at rest using pure AES-256-GCM AEAD encryption with 128-bit integrity tags. If your database is exported or leaked, attackers see only ciphertext.

= Can I use Cloudflare Free Plan with this plugin? =
Yes! WCP Security Scanner provides 100% Free Plan compatible Cloudflare integration. It deploys 3 master compound rules, leaving 2 custom rule slots free for user rules, plus edge rate limiting and bi-directional auto-ban synchronization.

= Does this plugin phone home or collect telemetry? =
No. WCP Security Scanner contains zero tracking, zero telemetry, and zero analytics. All scans and security checks execute 100% locally on your server.

== External Services ==

This plugin can optionally connect to the following external third-party services to enhance security, provide checksum verification, and support optional AI forensics:

1. WordPress.org Checksum API
* Service: WordPress Foundation (https://api.wordpress.org/core/checksums/1.0/).
* Purpose: Compares installed WordPress Core files against official release checksums to detect modified or malicious core files.
* Data Sent: WordPress version string, locale, and site URL.
* When: Triggered when running Core Integrity checks or starting a Full Deep Audit.
* Terms of Service: https://wordpress.org/about/privacy/
* Privacy Policy: https://wordpress.org/about/privacy/

2. WordPress.org Subversion Repository & Release Mirrors
* Service: WordPress Foundation (https://plugins.svn.wordpress.org, https://themes.svn.wordpress.org).
* Purpose: Fetches clean, authentic source code copies of official plugins and themes for visual diffing (FIM) and 1-Click Auto-Cure.
* Data Sent: Plugin/theme slug, file path, and version number.
* When: Only when an administrator opens the Visual Diff Viewer or executes 1-Click Auto-Cure.
* Terms of Service: https://wordpress.org/about/privacy/
* Privacy Policy: https://wordpress.org/about/privacy/

3. Blocklist.de & FireHOL Threat Intelligence Feeds
* Service: Blocklist.de (https://www.blocklist.de) and FireHOL (https://iplists.firehol.org).
* Purpose: Synchronizes known hostile botnet IPs, brute-force scanners, and malicious probe nodes to populate the local WAF threat database.
* Data Sent: None (outbound GET request to download public IP lists).
* When: Triggered on-demand when clicking "Sync Threat Feeds" or during scheduled background threat intelligence refreshes.
* Blocklist.de Terms: https://www.blocklist.de/en/tos.html
* Blocklist.de Privacy: https://www.blocklist.de/en/privacy.html

4. OpenAI API (Optional)
* Service: OpenAI, LLC (https://api.openai.com).
* Purpose: AI code analysis of suspicious code snippets.
* Data Sent: Code snippet, file path, threat signature, and administrator query.
* When: Only on-demand when the administrator inputs their own OpenAI API key and clicks "Analyze with AI".
* Terms of Service: https://openai.com/policies/terms-of-use
* Privacy Policy: https://openai.com/policies/privacy-policy

5. Google Gemini API (Optional)
* Service: Google LLC (https://generativelanguage.googleapis.com).
* Purpose: AI code analysis of suspicious code snippets.
* Data Sent: Code snippet, file path, threat signature, and administrator query.
* When: Only on-demand when the administrator inputs their own Gemini API key and clicks "Analyze with AI".
* Terms of Service: https://ai.google.dev/terms
* Privacy Policy: https://policies.google.com/privacy

6. Anthropic Claude API (Optional)
* Service: Anthropic, PBC (https://api.anthropic.com).
* Purpose: AI code analysis of suspicious code snippets.
* Data Sent: Code snippet, file path, threat signature, and administrator query.
* When: Only on-demand when the administrator inputs their own Anthropic API key and clicks "Analyze with AI".
* Terms of Service: https://www.anthropic.com/legal/consumer-terms
* Privacy Policy: https://www.anthropic.com/legal/privacy

7. Slack Webhook API (Optional)
* Service: Slack Technologies (https://hooks.slack.com).
* Purpose: Sends optional security incident notifications to the administrator's designated Slack channel.
* Data Sent: Alert notification message, site name, threat severity, and incident timestamp.
* When: Triggered only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://slack.com/terms-of-service
* Privacy Policy: https://slack.com/privacy-policy

8. Discord Webhook API (Optional)
* Service: Discord Inc. (https://discord.com/api/webhooks).
* Purpose: Sends optional security incident notifications to the administrator's designated Discord channel.
* Data Sent: Alert notification embed card, site name, threat severity, and incident timestamp.
* When: Triggered only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://discord.com/terms
* Privacy Policy: https://discord.com/privacy

9. ClickUp Automation API (Optional)
* Service: ClickUp (https://clickup.com).
* Purpose: Creates automated DevSecOps tasks on critical security threats.
* Data Sent: Task name, description with site name, risk score, findings count, and incident timestamp.
* When: Only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://clickup.com/terms
* Privacy Policy: https://clickup.com/privacy

10. Asana API & Automations (Optional)
* Service: Asana Inc. (https://asana.com).
* Purpose: Creates automated project management tasks on security findings.
* Data Sent: Task title, forensic notes, site name, risk score, and incident timestamp.
* When: Only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://asana.com/terms
* Privacy Policy: https://asana.com/privacy

11. Generic Automation Webhooks (Zapier, Make.com, n8n) (Optional)
* Service: User-specified automation endpoints.
* Purpose: Dispatches structured JSON event payloads to trigger custom enterprise DevSecOps automation workflows.
* Data Sent: JSON event payload with event type, site name, site URL, risk score, issue count, and timestamp.
* When: Only if configured and enabled by the administrator in Scanner Settings.

12. Cloudflare API v4 (Optional)
* Service: Cloudflare Inc. (https://api.cloudflare.com/client/v4).
* Purpose: Deploys edge WAF rules, wp-login rate limiting, and IP access block rules to Cloudflare CDN, and purges edge cache.
* Data Sent: Zone ID, WAF ruleset configurations, and blocked malicious IP addresses when explicitly initiated or configured for auto-sync.
* When: Only when the administrator enters their Cloudflare API Token and Zone ID in the Cloudflare Edge Defense tab.
* Terms of Service: https://www.cloudflare.com/terms/
* Privacy Policy: https://www.cloudflare.com/privacypolicy/

== Source Code & Build ==

This plugin is open-source under GPLv2 or later. Non-minified React and JavaScript source files are included directly in the `src/` directory.

The public source repository is hosted on GitHub:
https://github.com/webcarepro/wcp-wp-security

To compile the React admin application from source:
1. Ensure Node.js 18+ and npm are installed.
2. In the plugin root, run `npm install`.
3. Run `npm run build` to generate the production bundle in `build/index.js`.
4. Run `npm run package` to compile and package the release zip.

== Changelog ==

= 1.22.0 =
* Targeted Scan Auto-Scroll: UI smoothly auto-scrolls down to findings on targeted audit completion.
* Admin Menu Declutter: Removed WAF Logs and Notifications from the side menu (registered with parent_slug null for direct route fidelity) and restored 4 core menus on top header bar.
* Contextual Hyperlinks: Embedded direct links to WAF Logs in Firewall header/subtabs and Notification Center in Settings header/toolbar.
* Documentation Overhaul: Comprehensive rewrite of readme.txt, README.md, and features.md covering all 30 security engines.

= 1.21.0 =
* Smart 404 Scanner Rate-Limiter: Automated lockouts for 404 fuzzing scanners with reverse DNS verified search crawler exemption and static media exclusion.
* Dedicated WAF Incident Logs & Threat Intelligence: Full-page WAF forensics center with 4 live KPI cards, Top Vectors breakdown, Frequent Offender directory, real-time search, and JSON/CSV/Print export.
* Inline Expandable User Session Forensics: Replaced fixed-overlay modal with seamless expandable table rows preserving authentic decrypted origin login IPs across reverse proxies and Cloudflare Anycast.
* Dedicated Notification Center: Full-page alert matrix with 32+ granular security events across 8 categories with independent Email and DevSecOps webhook switches.

= 1.17.0 =
* Resolved WordPress.org Plugin Review feedback for security, coding standards, and namespace compliance.
* Upgraded plugin prefix and namespaces to `WcpScanner\` (namespaces), `WCPSCAN_*` (constants), and `wcpscan_*` (database tables, options, transients, and cron hooks) meeting the 4+ character uniqueness guideline.
* Replaced third-party QR code API dependency with built-in, 100% on-premise pure-PHP SVG QR Code generator (`QRCodeGenerator`) for Two-Factor Authentication (TOTP), keeping user secrets completely local.
* Enqueued administrative brand styling via `admin_enqueue_scripts` with `wp_register_style`, `wp_enqueue_style`, and `wp_add_inline_style`, removing direct `<style>` tag echoes.
* Replaced custom inline CSS block rendering in WAF Lite with WordPress core `wp_die()`.
* Enhanced input sanitization, escaping, and validation across all `$_SERVER`, `$_GET`, `$_POST`, and `$_COOKIE` variables in Firewall and Session Sentinel engines.
* Standardized directory location references across backup, remediation, quarantine, and scanning engines using canonical `wp_upload_dir()['basedir']`, `WP_PLUGIN_DIR`, `WPMU_PLUGIN_DIR`, `get_theme_root()`, and `ABSPATH . WPINC`.
