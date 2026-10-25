=== WCP Security Scanner ===
Contributors: miralamin
Donate link: https://webcarespro.com
Tags: security, malware, ai-security, firewall, 2fa
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.25.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security, malware detection, web application firewall (WAF), core integrity auditing, and threat intelligence.

== Description ==

WCP Security Scanner gives you enterprise-grade malware detection, core integrity auditing, web application firewalling (WAF), session sentinel, rogue admin detection, and threat forensics inside an intuitive, modern React 18 single-page dashboard. Engineered by Mir Alamin (WebCare Pro) for high-performance WordPress sites, it provides deep visibility across your file system, WordPress core files, plugins, themes, database tables, cron jobs, active sessions, runtime hooks, and server configurations—without the performance bloat of traditional security tools.

Key highlights:
* **Deep Malware & Heuristic Scanner**: Scans PHP files, uploads, and database for webshells, backdoors, obfuscated injections, and rogue admin accounts.
* **WordPress Core & Plugin Integrity**: Cryptographic validation against official WordPress.org checksums with 1-click Auto-Cure.
* **Proactive Web Application Firewall (WAF)**: Zero-overhead request filtering, virtual patching, 404 rate-limiting, and Cloudflare Edge synchronization.
* **Zero Bloat & Memory-Safe Architecture**: Hierarchical cursors and adaptive resource governor preserve visitor headroom.
* **Pure AES-256-GCM Cryptographic Vault**: Encrypts sensitive secrets and TOTP 2FA keys at rest.
* **100% On-Premise & Privacy First**: Zero third-party telemetry, zero external tracking, and zero data collection.

== Screenshots ==

1. Cyber Command Center & Threat Dashboard with dynamic SVG Security Health Meter and 1-click audit console.
2. Multi-Vector Deep Malware Scanner showing real-time file inspection, heuristic detection, and issue classification.
3. Proactive Web Application Firewall (WAF) rule matrix with Layer 7 protection and real-time incident blocking.
4. Cloudflare Edge Defense dashboard showing Anycast edge sync, rate limiting, and automated IP ban integration.
5. In-Page Visual Code Diff Viewer Modal comparing altered files directly against pristine WordPress.org mirrors.
6. Session Sentinel & Live Device Manager providing real-time origin IP inspection and remote session revocation.

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

= 1.25.0 =
* Intelligent Prohibited Installation Armor: Added multi-stage WP Upgrader pipeline inspection (`upgrader_source_selection`) and deep archive stream sampling (`stream_get_contents`) to prevent upload or installation of phpMyAdmin, Adminer, and standalone File Manager web shells.
* Full Dark Mode & High-Contrast Design Hardening: Synchronized all elevated surface and semantic status tokens (`--wcp-bg-surface-elevated`) across the settings hub, GitHub continuous updates, rollback vault tables, and Cloudflare telemetry.
* WordPress.org Plugin Check Standards Remediation: Resolved all direct database query and file operation warnings across subsystems down to 0 actionable errors.
* Sensitive File Probe Hardening: Upgraded `SecurityHeadersEngine` with multi-layer URL decoding to neutralize hex-encoded directory traversal and system probe evasion.

= 1.24.0 =
* Smart Shields & Verified Integrations Control Center: Granular reactive on/off switches for 5 intelligent false-positive bypasses with automatic environment detection and 1-click recommendation banners.
* 34-Plugin E-Commerce & Membership Smart Shield: Expansive support for WooCommerce, EDD, SureCart, GiveWP, MemberPress, PMPro, Restrict Content Pro, SureMembers, ARMember, BuddyBoss, Youzify, and 23 others with cryptographic webhook signature authentication and active shopper session immunity.
* 20-Visual Builder & Block Design Smart Pass: Verified session protection for Elementor, Divi, Beaver, Bricks, Breakdance, Oxygen, SeedProd, Brizy, Thrive Architect, WPBakery, Visual Composer, Themify, SiteOrigin, Droip, Live Composer, WP Site Editor FSE, GenerateBlocks, Kadence, Spectra, and Avada Fusion Builder.
* Automattic Jetpack & Uptime Monitors Defense: Strict CIDR validation for Jetpack syncs and 24-hour cached reverse DNS (PTR) verification for UptimeRobot, Pingdom, StatusCake, and BetterUptime.
* Central Management Worker Pass: Verified worker authentication for ManageWP, MainWP, and InfiniteWP.
* Automated Test Suites & Live WAF Verification: Built and executed automated unit and live HTTP test suites (`test_smart_rules_suite.php`, `test_live_http_rules.js`) against Docker environment, auto-provisioning `incident_id` in `wp_wcpscan_firewall_logs` via database schema version 1.10.0.

= 1.23.0 =
* UI Design System Theme Hardening: Codified dual-mode design tokens across Firewall controls, WAF Logs, and Filesystem Forensics in both Dark Obsidian and High-Contrast White Mode.
* Unmanaged & Proprietary Component UX: Eliminated false-positive "Auto-Cure" triggers on custom/proprietary plugins, transitioning them to distinct informational badges.
* Defensive Deactivation Trigger: Protected deactivation hooks with defensive exception wrappers preventing third-party mailer plugin fatal errors from interrupting deactivation.

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
