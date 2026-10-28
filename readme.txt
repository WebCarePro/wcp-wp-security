=== WCP Security Scanner ===
Contributors: miralamin
Donate link: https://webcarespro.com
Tags: security, malware, ai-security, firewall, 2fa
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.29.0
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

= 1.29.0 =
* WordPress.org Plugin Check & I18n Compliance.
* WordPress Admin Sidebar Authentic Logo SVG Embedding.
* Small Laptop & Medium Screen Responsive Navigation.
* Scanner Engine Turbo Optimization & Integrity Checksum Caching.

= 1.28.0 =
* CrashGuard Enterprise Hardening & Micro-WAF Preload Isolation.
* CrashGuard Zero-Downtime Circuit Breaker.
* Granular Security Events & Notification Center Expansion.
* Unique Deep-Linking URLs & Mega-Menu Module Expansion.
* Database Credentials & Secret Salt Redaction in File Inspection Modal.
* Intelligent Developer Debug Remediation & wp-config.php Production Lockdown.
* In-Page Confirmation Dialog & Visual Layout Fix for Disable Debugging.
* Live Incident Stream Timezone Precision Fix.
* WAF Rule Verification, Targeted Bypass Testing & Core Bug Fixes.
* Firewall & Edge Protection UI Modernization.
* Zero-Breakage Production Stabilization & False Positive Elimination.
* Zero-Trust Must-Use Guardian & Sandboxed Temporary Support Access.
* Canonical Plugin Slug Standardization & Legacy Slug Elimination.
* 1-Click WP_DEBUG Remediation Engine.
* Active Sessions Sentinel & Multi-Factor Telemetry Cockpit.
* WebAuthn Login Page Passkey Ceremony Integration.
* Strict Official Integrity & Rogue/Unknown File Detection.
* Host Antivirus Immunity & Heuristic Engine Resilience.
* Global Command Center & All Modules Mega-Menu.
* Preload Micro-WAF & Early Execution Engine.
* Strict Anti-Spoofing Allowlist Hardening.
* Autonomous MCP Governance Hardening.
* Manifest Uniformity & Automated Verification.
* Zero-Allocation Streaming Session Queue & Scanning Engine Modernization.
* Advanced Stealth Malware & Webshell Heuristic Detectors.
* JavaScript Threat Intelligence & First-Party Malware Detection.
* Third-Party Client Script & Hostname Drift Monitor.
* Offline Dependency Lockfile & Supply-Chain Auditor.
* Interactive Supply-Chain UI Subtabs.
* 2026 AI Threat Defense, MCP Governance & Decoy Ghost Routes.
* 72-Hour Post-Remediation Reinfection Watchdog.
* "Time-Machine" Local File & Snapshot Baseline Engine.
* Automated Blacklist & Domain Reputation Early-Warning Sentinel.
* Deep Server Pre-loader & System Crontab Audits.
* Unified Threat Correlation Engine.
* Enhanced 1-Click Panic Button Emergency Containment Protocol.
* Autonomous System Number & TLS Fingerprint Session Binding.
* Native Dependency-Free W3C WebAuthn Biometric Passkeys.
* Scoped Time-Bombed Emergency Support Access.
* 10-Vector Non-Destructive Attack Simulation Engine.
* Caddy v2 Security Directives & Perimeter Verification Suite.

= 1.27.0 =
* Zero-SQL Daily Partitioned Filesystem WAF Incident Logging Engine.
* Granular Developer Freedom for Uninstallation Cleanup.
* Scan Report Findings High-Performance Client Pagination.
* Scan Report Email Threat Priority Ranking & Customizable Findings Limit.
* Scan Home & Dashboard Findings Virtual Pagination.
* Smart Form Plugin Shield & Zero False-Positive Compatibility Engine.

= 1.26.0 =
* Cloudflare Edge WAF Credentials Banner Visual Highlighting.
* Universal System-Wide UTC/GMT Immutable Timestamps.
* Image Asset Interactive Viewer & Binary Malware Forensic Validation.
* WordPress.org Plugin Check Complete Compliance Refactoring & Fresh Architecture.
* WordPress Root Folder Unknown File, Dotfile & Dot-Directory Deep Scanning.
* Server Origin IP & Cloudflare Edge REST Rule 2 Self-Blocking Immunity.
* Cloudflare Edge Banned IP List & Reason Forensic Modal.
* Supply-Chain Install Risk Advisor Syntax Fix.
* Just-In-Time Ephemeral Privilege Elevation Hardening & Anti-Tamper Shield.
* Just-In-Time Ephemeral Elevation Candidate User Population Fix.
* Unified Single Storage Directory Architecture under `wp-content/uploads/wcp-security-scanner/`.
* False-Positive Immunity for Schema.org JSON-LD & Structured Data Islands.
* Self-Exclusion & Immunity for Plugin Internal Telemetry, Forensic Tables & Quarantine Vault.
* Real-Time CVE Intelligence & Local Site Inventory Correlator Engine.
* Safe Data Retention by Default & Interactive Uninstall Confirmation Modal.
* Behavioral WAF & Bot Traps Settings Persistence & UI Synchronization Fix.

= 1.25.0 =
* WordPress Plugin Check Clean Verification & Hardening.
* Dark Mode High-Contrast Preset & Detected Badge Styling.
* False-Positive Immunity for Hostname & TLD Validators.
* Architectural Ecosystem Comparison & Honest Limitations.
* PHP 8.4 Compatibility & Admin Screen Title Normalization.
* Targeted User-Agent, Endpoint & IP Granular Firewall Allowlist Rules.
* Navigation Architecture Modernization & Two-Tier Command Hub.
* WordPress.org Plugin Guidelines & Plugin Check Compliance Hardening.
* Multi-Region Timezone Architecture & Date/Timestamp Hardening.
* Next-Gen Pillar 5: Continuous Threat Intel Network & Automated Virtual Patching Ecosystem.
* Next-Gen Pillar 4: Zero-Trust Identity, Session Forensics & Credential Leak Armor.
* Next-Gen Pillar 3: Behavioral WAF & Anti-Automated Abuse.
* Next-Gen Pillar 2: Supply-Chain Defense & Update Gatekeeper.
* Next-Gen Pillar 1: AI-Era Defense, Attack Simulation & Autonomous Incident Containment.
* Intelligent phpMyAdmin & File Manager Prohibited Installation Armor.
* WordPress.org Plugin Check Standards Remediation.
* Sensitive System File Probe URL-Decode Hardening.
* Main Plugin Cleanliness & Constant Streamlining.
* WordPress.org Submission Compliance Phase 1.
* WordPress.org Submission Compliance Phase 2.
* WordPress.org Submission Compliance Phase 3.
* WordPress.org Submission Compliance Phase 4.

= 1.24.0 =
* Automattic Jetpack Smart Pass & Verified Crawler Defense Architecture.

= 1.23.0 =
* Plugin Deactivation Resiliency & 3rd-Party Mailer Shield.
* UI Design System Documentation & Anti-Pattern Specifications.
* Finding Details Expand White Screen Elimination & Error Boundary Hardening.
* Proprietary & Unmanaged Component UI Remediation Accuracy.
* Core Integrity Scanner False-Positive Elimination for Hardened Docs.
* Incident ID Search & Forensic Telemetry Tracking.
* Administrator Bulk Operations & WP-Admin DoS Exemption.
* Redirection Plugins & 404 Scanner Rate Limiter Compatibility Shield.
* WAF Incident Logs & Threat Intelligence Customization Suite.
* Comprehensive Firewall Rule Verification & Lifecycle Hardening.
* High-Impact WAF Rule Expansion Suite.
* Firewall Rules & Controls Complete Rebuild & Granular Architecture.
* Virtual Patch & Core Administrative False-Positive Elimination.
* Intelligent E-Commerce, Membership & Cart Smart Shield.
* Cloudflare Edge Virtual Patching Class Loading Fix.
* Firewall Rule State Persistence & Partial-Save Sanitization Hardening.
* Role Enforced Password Policy Defaults.
* Virtual Patch Interception & WAF Forensic Logging Suite.
* Cloudflare Edge Rule ID Persistence & Admin Self-Ban Shield.
* Cloudflare Edge Integration & Firewall Page Experience Suite.
* phpMyAdmin & File Manager Prohibited Installation and Upload Hardening Suite.
* Advanced API, Protocol & Abuse Defense Suite — Rules #29 to #34.
* Cloudflare Edge Firewall Block Events & Vault Cache Integration.

= 1.22.0 =
* Comprehensive Documentation Overhaul.
* Targeted Scan Auto-Scroll & Workflow Enhancements.
* Enhanced Web Application Firewall Rules & Identity Perimeter Protection.
* Admin Submenu Declutter & Deep-Link Navigation Architecture.
* Cloudflare Free Rate Limiting Counting Window Calibration.
* Timezone-Aware Timestamp Synchronization & Relative Time Fix.
* Firewall Toggle State Synchronization & Operating Mode Persistence.
* Cloudflare Edge Master Rule 4: Deep SQL Injection & Database Armor.
* GitHub Direct Plugin Updates, Rollback Engine & Zero-Trust Cloud Self-Healing.

= 1.21.0 =
* Smart 404 Scanner Rate-Limiter & Reconnaissance Shield.
* Dedicated WAF Incident Logs & Threat Intelligence Page.
* Inline Expandable User Session Forensics.
* User Session Forensics Authentic Login IP Preservation.
* Dedicated Notification Center & Granular Per-Event Alert Matrix.
* Core Security & Architecture Hardening from Grok Code Review.
* Scan Progress & Real-Time Resource HUD White/Light Mode Visual Upgrade.
* Attack Timeline & Correlation Engine White/Light Mode Visual Upgrade:- Strict IP Lock Setting Complete Removal.
* Executive PDF Audit Report Footer Refinement.
* Website CDN Edge IP & Cloudflare Detection Hardening.
* Cloudflare Free Plan 3 Master Compound Rules & Individual Single-Rule Push.
* Cloudflare Free Plan Rate Limiting & Dual-Tier Brute Force Armor.
* Cloudflare WAF Expression Hardening & Leading Slash Removal.
* Unknown & Rogue Files Extended Details Remediation: Quarantine & Delete Options.
* Modified Official Files Auto-Cure & View File Restoration.
* Login Hardening IP Whitelist Scope Fix.
* Multi-Factor Authentication & Login Security: URL Subtab Deep-Linking & Administrator Governance.
* Subsequent Scan DOM Reconciliation & Blank White Page Fix.

= 1.20.0 =
* Login Security User Session Forensics & IP Shift Tracking.
* Universal Dropdown Menu Indicators.
* Server & Host Infrastructure Telemetry Cockpit on Firewall Page.
* Shared Hosting CPGuard False-Positive Immunity & Release Clean Packaging.
* Plugin Self-Defense & Anti-Tamper Attestation Engine.
* Resilient Cloudflare Service Class Loading & Shared Hosting Hardening.
* Scan Logs Inspection Telemetry Font Sizing Refinement & Numerical Aggregation Fix.

= 1.19.0 =
* UI/UX update.

= 1.18.0 =
* Architecture-Aware Visitor IP Detection & Environment Intelligence.
* Separate Custom Scan & Targeted Scan Naming & Target Name Attribution in Scan Logs.
* Dashboard Custom Scan Engine Options Suite & Wordfence-Style Checklist.
* Complete Settings Page Rebuild & Dedicated Model Context Protocol Suite.
* Global 100% Full-Width WordPress Layout Expansion.
* WordPress Native AI Connect Universal Bridge & Intelligent Detection.
* Frictionless 1-Click "Mark Safe / Ignore" UX & Finding Status Segmentation.
* Documentation & Linux System Hardening.
* REST Telemetry Hardening, Cryptographic Rollback Verification & Database Lifecycle Integrity.
* Codebase Streamlining & Legacy Compatibility Pruning.
* WordPress.org Official Review Audit & Compliance Hardening.
* Pre-Flight System Readiness & Compatibility Gate.
* 3D Aesthetic First-Time Welcome Modal & Non-Technical Onboarding Rebuild.
* False-Positive Whitelist & Finding Reopen Lifecycle Fix.
* Dedicated "Scan" Tab in Main Navigation & Admin Menu.

= 1.17.0 =
* Dedicated WCP Vault & Top Navigation Suite.
* Attack Chain Engine & User Privilege Escalation Overhaul.
* WordPress.org Official Plugin Review Compliance & Architectural Hardening.

= 1.16.0 =
* Multi-Vector Reverse Proxy SSL / HTTPS Detection & Server Environment Audit.

= 1.15.0 =
* Real-Time Progress & Telemetry Engine for One-Click Database Backup Vault.
* Phase 4: Executive Incident Response & Client Security PDF/JSON Report.
* Phase 3: Automated Two-Tier Virtual Patching Engine.
* Phase 2: Attack-Chain & Behavioral Anomaly Correlation Engine.
* Phase 1: Self-Healing & Multi-Persistence Malware Hunter.
* Dedicated Tabs for File Integrity Monitoring & Filesystem Permissions.
* Compliant Root & Shared Hosting Directory Permission Recognition.
* Filesystem Permissions & Ownership Auditor with 1-Click Mass Hardening.

= 1.14.0 =
* Official Verified Website Logo Branding & Plugin Action Links.
* Directory Browsing Prevention & Safe Index Placeholder Recognition.
* Filesystem Forensics & One-Click Permission Remediation for Unsafe Permissions.
* Real-Time Integrity Auto-Reconciliation for Restored Files.
* Theme Integrity Detail Expansion & Forensics Fault-Tolerance Fix.
* Dashboard Comprehensive Scan Filtering & Targeted Scan Separation.
* Full-System Queue Discovery & Artificial 3000 File Limit Removal.
* Filesystem & Directory Storage Breakdown on Server Info.
* Malware Scanning Expansion for Non-PHP Assets.
* Premium & Third-Party Plugin Upstream Changelog Integration.
* Official WordPress.org Repository Classification & Latest Upstream Changelog Viewer.
* Current Authenticated Administrator Protection & Direct Password Change Remediation.
* Database Record Forensics, Auto-Backup Quarantine & Surgical Remediation.
* WordPress Comment Threat Forensics & Native Moderation Architecture.
* Theme Integrity Version Reconciliation & Pristine Baseline Detection.
* Real-Time Audit Telemetry, Memory & CPU Consumption HUD.
* Deep Technical Telemetry & SysAdmin Diagnostics Across All Report Exports.
* User Accounts, Roles & Capability Forensics & Surgical Remediation Architecture.
* Active Scan Safeguards & Log Purging Self-Healing Architecture.
* Custom & Premium Themes/Plugins Forensics, Changelog Modal & Finding Details Fix.

= 1.13.0 =
* Real-World Production Scan Calibration & False-Positive Elimination.
* Two-Phase Commit Vault Key Rotation Orchestrator.
* Hierarchical Resumable Cursor & Constant-Memory Filesystem Traversal.
* Phased Streaming Scan Pipeline & Real OS Memory Ceilings.
* Multi-Row Prepared Statement Database Persistence Layer.
* Enterprise AES-256-GCM Authenticated Cryptographic Secret Vault Upgrade.
* Multi-Format Scan Results Export.
* Official Plugin & Theme File Modification Detection & Full Scan Pipeline Hardening.
* Quarantine Vault & Sensitive Storage Cryptographic Hardening.
* Path Boundary Hardening & Sibling-Directory Prefix Confusion Elimination.
* Strict Trusted Proxy Verification & Client IP Spoofing Prevention.
* Dedicated Quarantine Vault Page & Admin Sidebar Navigation.

= 1.12.0 =
* Complete Dashboard Rebuild & Next-Gen Cyber Command Center.
* Finding Table Modern Zebra Shading & Visual Hierarchy Rebuild.
* Cron Hook & Database Option Non-File Categorization & Action Boundary Fix.
* Visual Code Diff In-Page Modal Opening Fix & Resilient API Fallback.
* High-Precision Microsecond & Millisecond Scan Execution Duration Tracking.
* Plugin Integrity Self-Exclusion & Multi-Engine Deduplication Safeguards.
* In-Page Visual Code Diff Modal on Dashboard & Inspection Reports.
* Multi-Layer Finding Deduplication & Concurrency Lock Resolution.
* Unknown & Rogue File FIM Action Boundary Correction.
* 1-Click Scheduled Cron Hook Removal & Database Deletion.
* Rogue & Unknown File Quarantine in Core Directories & Vault Purge.
* Auto-Cure Remediation Resolution & Solved Issue State Synchronization.
* Quarantine Button Exclusion for Protected & Modified Official Files.
* Quarantine Vault Table Format & Action Button Overflow Fix.
* 1-Click Single-File WordPress Core Auto-Cure & Pristine WP.org Restoration.
* Dynamic Security Health Score & Remediated Threat Resolution.
* Comprehensive Documentation & Extended 21-Engine Architecture Catalog.
* CVEs & Warnings Threat Cube & Category Filter Synchronization.
* WordPress Core Compatibility Header Standardization.

= 1.5.1 =
* Automated Sensitive Credential & Webhook Masking on Settings Save & Reveal.
* Two-Step "Reset Defaults" Confirmation Modal Safeguard.
* Encrypted Two-Factor Authentication User Secrets at Rest.
* Consolidated & Strengthened Cloudflare Free Plan Custom WAF Edge Rules.
* VirusTotal & Antivirus Heuristic False-Positive Elimination.
* Scheduled Background Scan Architecture & Reliability Overhaul.
* Scan Logs Execution Origin Tracking.
* Schedule Scan Diagnostics: WordPress Time, GMT Time & Live Relative Countdown.
* Custom Scheduled Start Time & Background Scan Progress Tracking.
* Live Dashboard & Scanner UI Monitoring for Scheduled Background Scans.
* Optimized "Scan Logs & History" with Deep-Link URL State & Auto-Scroll.

= 1.5.0 =
* Built Web Application Firewall & Virtual Patching Engine.
* Built Real-Time File Integrity Monitoring & Visual Code Diff Viewer.
* Built One-Click Malware Remediation & Auto-Cure Engine.
* Built Cloud Threat Intelligence & Community Blacklists Synchronization.
* Built Multi-Factor Authentication & Login Hardening Engine.
* Built DevSecOps Chat & Automation Webhooks.
* Built Dedicated "Support & Socials" Hub Under Scanner Settings.
* WordPress.org Official Plugin Review Compliance & Hardening.
* Cleaned Dashboard Top Menu Navigation & Streamlined Standalone Views.
* Redesigned and Modernized Scanner Settings Page.
* Fixed File Integrity Monitoring Scope Filter Stats Persistence.
* Added Custom & Premium Component Recognition & Automatic Exclusion to FIM.
* Added Automatic Safe Directory Index Protection & Custom Exclusion Engine for Uploads.
* Fixed Cloud Threat Intelligence Live Sync and Enhanced Site Vulnerability Correlation.
* Fixed Header Refresh Button Responsiveness & Visual Feedback.
* Built HTTP Security Headers Engine & 1-Click Site Hardening.
* Built Session Hijack Defense & Concurrent Admin Session Sentinel.
* Built Database Micro-Anomaly & Rogue Administrator Trap.
* Built Bot Recon Defense & AI Scraper Shield.
* Built Living-off-the-Land Native Hook Infiltration Sentinel.
* Expanded Comprehensive Plugin Documentation across `readme.txt`, `README.md`, and `docs/features.md`.
* Resolved Targeted Scan JSON Response Errors.
* Built Cloudflare Edge Defense & Zero-Resource WAF.
* Resolved Fresh Installation FIM Baseline False-Positives.
* Enhanced Dashboard UX & Scan Results Professionalism.
* Modernized Scan Logs & Audit History Interface.
* Built 2FA "Remember Trusted Device for 7 Days" Engine & Management Suite.
* Enhanced Cloudflare Edge Defense Integration & 1-Click Token Pre-Configuration.
* Enhanced Active Sessions Sentinel & Current Session UX.
* Enhanced File Integrity Monitoring & Config Diff Viewer Security.
* Encrypted Cloudflare Credentials, Webhook URLs & AI Tokens at Rest via AES-256-CBC SecretVault.
* Resilient Cloudflare Service Loader & Host Scanner Quarantine Hardening.
* Interactive "Reset Defaults" Safeguard Modal.
* Repackaged production-ready WordPress.org release zip `wcp-security-scanner.zip`..

= 1.4.0 =
* Created Comprehensive Documentation `features.md`.
* Added Dedicated "Scanner Settings & Automation" Page & Submenu.
* Automated Scheduled Scanning Engine.
* Email Security Notifications & Incident Alerts.
* Multi-Provider AI Cybersecurity Intelligence Integration.
* Settings Import & Export Engine.
* Scanner Performance & Developer Hardening Options.
* Redesigned "Scan Logs & History" UI & Formatting.
* WordPress.org Submission & Plugin Check Hardening.
* Advanced File System Malware Detection.
* Comprehensive Database Malware Scanning.
* Professional Remediation & User Audit Logging.
* Dynamic Plugin Version Engine Badge.
* Expanded Automated Test Suite.

= 1.3.0 =
* Added Dedicated "About Us & Services" Sub-Page.
* Added Source File Code Inspection Popup Window & Modal.
* Added Post & Page Malware / Spam Inspection & Direct WordPress Editor Navigation.
* Modernized and Enhanced Interface.
* Added Outdated WordPress Core, Themes & Plugins Detection with Known CVE References.
* Added Dedicated "Vulnerabilities & Updates" Sub-Page.
* Added Official vs. Premium/Custom Provenance & Unknown Foreign File Detection to Vulnerabilities Page.

= 1.2.0 =
* Bumped plugin and package version to 1.2.0..
* Implemented Dedicated Sub-Pages & Tabs Navigation.
* Registered new submenus in AdminMenu.php with synchronized initialTab state for direct deep linking..
* Built REST API routes for /server-info, /backup/create, /backup/list, /backup/delete, /backup/download, /scan/history, and /scan/history/{id}..
* Updated wcp_scans database table migration to include scan_target tracking with dbDelta and alter-table fallback..
* Added Quarantine Shield: strictly blocked quarantining of critical WordPress bootstrap files in QuarantineManager.php..
* Added Reverse Integrity Reconciliation: detected unrecognized/foreign files in CoreIntegrity.php, PluginIntegrity.php, and ThemeIntegrity.php regardless of extension..
* Calibrated Malware Heuristics and SerializedDataScanner to prevent false positives on transients, embeds, and scanner self-code..
* Expanded automated test suite in test-suite.php to 19 passing unit & integration checks..
* Dynamic Browser URL Synchronization: Connected tab navigation to HTML5 History pushState and popstate event listeners so clicking Dashboard, Targeted Scans, Scan Logs, Database Backup Vault, and Server Info updates the browser URL and synchronizes WordPress sidebar menu active highlights without reloading..
* Implemented Clear Scan Logs Feature: Added REST API route /scan/history/clear and UI button in Scan Logs & History tab to purge historical scan runs, and cleared all old test scan logs from database..
* Hardened Database Backup Vault Permissions & Fallback: Added automatic 0775 permission enforcement and automatic fallback to wp-content/uploads/wcp-backups/ if the primary directory lacks write permissions for the web server user. Updated list, delete, and download handlers to cross-search all vault storage locations seamlessly..
* Added Targeted Scan Option - Uploads Executables & Suspicious Files Audit.
* Initialized Git repository tracking and configured .gitignore to exclude non-plugin environment files and frontend source build files leaving only production plugin files in repository..
* Implemented Animated Real-Time Progress Bar for Targeted Scans.
* Added Targeted Scans for Crontab / Persistence Audit & WordPress Core Integrity.
* Hardened REST API Communication & Scan Resilience.
* Implemented Persistent Running Scan State & Auto-Resumption on Page Refresh.
