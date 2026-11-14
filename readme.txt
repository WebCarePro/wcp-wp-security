=== WebCare Pro Security & Firewall ===
Contributors: miralamin
Tags: security, malware, ai-security, firewall, 2fa
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 2.14.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security, malware detection, web application firewall (WAF), core integrity auditing, and threat intelligence.

== Description ==

WebCare Pro Security & Firewall gives you enterprise-grade malware detection, core integrity auditing, web application firewalling (WAF), session sentinel, rogue admin detection, and threat forensics inside an intuitive, modern React 18 single-page dashboard. Engineered by Mir Alamin (WebCare Pro) for high-performance WordPress sites, it provides deep visibility across your file system, WordPress core files, plugins, themes, database tables, cron jobs, active sessions, runtime hooks, and server configurations—without the performance bloat of traditional security tools.

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

1. Upload the `webcare-pro-security` folder to the `/wp-content/plugins/` directory, or install directly through the WordPress plugins dashboard.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Access your new cyber command center by clicking **WebCare Pro** in the admin sidebar.
4. Run your first Deep Audit from the Cyber Command Center.

== Frequently Asked Questions ==

= Does WebCare Pro Security & Firewall slow down my website? =
No. The scanner is built with a memory-safe batching engine that processes files in non-blocking chunks with zero impact on frontend visitors. The frontend admin interface runs on modern React 18 and only executes within the WordPress admin dashboard.

= What makes the Cryptographic Secret Vault different from other plugins? =
Standard WordPress plugins store sensitive credentials like webhook URLs and Cloudflare tokens in plaintext inside `wp_options`. WebCare Pro Security & Firewall encrypts all sensitive data at rest using pure AES-256-GCM AEAD encryption with 128-bit integrity tags. If your database is exported or leaked, attackers see only ciphertext.

= Can I use Cloudflare Free Plan with this plugin? =
Yes! WebCare Pro Security & Firewall provides 100% Free Plan compatible Cloudflare integration. It deploys 4 master compound rules, leaving 1 custom rule slot 100% free for site owner rules, plus edge rate limiting and bi-directional auto-ban synchronization.

= Does this plugin phone home or collect telemetry? =
No. WebCare Pro Security & Firewall contains zero tracking, zero telemetry, and zero analytics. All scans and security checks execute 100% locally on your server.

= What if I get locked out? How do I unblock myself? =
If your IP address gets temporarily blocked by login rate-limiting, honeypot traps, or firewall rules, you can immediately restore access using any of these simple methods:

1. Emergency wp-config.php Whitelist (Fastest & Recommended):
Add this single line to your wp-config.php file (above the "/* That's all, stop editing! */" line) with your public IP address:
define('WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP', '203.0.113.1');
This grants an instantaneous, zero-delay bypass across all WAF and login hardening checks even if the database is inaccessible.

2. Emergency Firewall Bypass:
To temporarily disable all WAF inspection rules without deactivating the plugin:
define('WEBCAREPROSCAN_DISABLE_WAF', true);

3. Reset Login Lockouts via WP-CLI:
If you have SSH/terminal access, simply run:
wp option delete webcareproscan_login_lockouts

4. Database / phpMyAdmin:
In your database tool, browse the wp_options table and delete the option named webcareproscan_login_lockouts.

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

13. Have I Been Pwned API (HIBP)
* Service: Troy Hunt / Have I Been Pwned (https://api.pwnedpasswords.com).
* Purpose: Verifies whether user-submitted passwords or administrator accounts have been compromised in known global data breaches using k-Anonymity mathematical privacy model.
* Data Sent: Only the first 5 characters of the SHA-1 hash of the password (k-Anonymity prefix). The full password or hash is never transmitted over the network.
* When: Triggered during password audits or administrator login checks when HIBP Breach Shield is enabled.
* Terms of Service: https://haveibeenpwned.com/Terms
* Privacy Policy: https://haveibeenpwned.com/Privacy

14. NIST National Vulnerability Database (NVD)
* Service: National Institute of Standards and Technology (NIST) (https://services.nvd.nist.gov).
* Purpose: Queries official CVE vulnerability descriptions and severity metrics for detected WordPress core, theme, and plugin vulnerabilities.
* Data Sent: CVE identification string (e.g. CVE-2023-XXXX). No user or website data is sent.
* When: Triggered on-demand when inspecting CVE threat details in the Vulnerabilities tab.
* Terms of Service: https://www.nist.gov/oism/terms-use
* Privacy Policy: https://www.nist.gov/privacy-policy

15. Stamparm Ipsum & Threat Intelligence Feeds
* Service: Stamparm Ipsum Project (https://raw.githubusercontent.com/stamparm/ipsum).
* Purpose: Downloads curated feeds of suspicious IP addresses and known malicious scanners to update the local firewall blocklist.
* Data Sent: None (outbound GET request to download public IP lists).
* When: Triggered on-demand or during scheduled threat intelligence sync when enabled by administrator.
* Terms of Service: https://github.com/stamparm/ipsum/blob/master/README.md
* Privacy Policy: https://github.com/stamparm/ipsum

16. GitHub Content Delivery (Official WordPress Core Fallback & Integrity Attestation)
* Service: GitHub, Inc. / Microsoft Corporation (https://raw.githubusercontent.com).
* Purpose: Retrieves authentic, unmodified WordPress core release sources as an authoritative fallback when SVN is unavailable during administrator-initiated core remediation, and checks plugin self-defense integrity attestation.
* Data Sent: None (outbound GET request to fetch public WordPress core release files).
* When: Triggered only when an administrator explicitly initiates core file remediation or integrity checks.
* Terms of Service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
* Privacy Policy: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement

== Source Code & Build ==

This plugin is open-source under GPLv2 or later. Non-minified React and JavaScript source files are included directly in the `src/` directory.

The public source repository is hosted on GitHub:
https://github.com/webcarepro/webcare-pro-security

To compile the React admin application from source:
1. Ensure Node.js 18+ and npm are installed.
2. In the plugin root, run `npm install`.
3. Run `npm run build` to generate the production bundle in `build/index.js`.
4. Run `npm run package` to compile and package the release zip.

== Changelog ==

= 2.14.0 =
* Bounded Streaming Request-Body Inspection & Unredacted Password Analysis: Replaced head/tail truncation with 64KB chunked streaming inspection up to a 4MB ceiling with 8KB rolling overlap, eliminated password field omissions from mandatory exploit checks while preserving heuristic masking, added strict regex end-anchoring on REST authoring routes, and made WAF configuration redaction strictly route-schema aware.
* Unredacted Mandatory Exploit Inspection & Write-Only Builder Privilege Gating: Ensured 100% unredacted payload inspection across all mandatory exploit signatures (SQLi, RCE, LFI, Object Injection, SSRF), introduced schema-aware heuristic masking for WAF configuration writes, and restricted builder/author exemptions strictly to verified state-changing write operations (POST, PUT, PATCH) with valid nonces.
* Deep Security & Integrity Remediation (WCP-01 through WCP-10): Atomic DB-first quarantine to prevent data loss; verified large stream copies (>20MB) with byte count and SHA-256 checks; safe restoration of unknown files in wp-admin and wp-includes without overwriting core checksums; mandatory 14-day WebCare Vault safety backups prior to rogue file deletion; protected core and plugin directories from rogue deletion; gated Cloudflare GeoIP/ASN headers behind trusted proxy validation; hardened SSRF loopback protections; comprehensive vault rotation across all API keys and disk archives; recursive prompt injection telemetry sanitization; transactional remediation path containment; WebAuthn user verification and strict origin validation with registration parity; and active plugin/theme quarantine containment.
* Four-Boundary Model Context Protocol (MCP) Runtime Security Hardening: Boundary 1 untrusted-data taint tracking (120s transient marker); Boundary 2 scoped token authorization ceilings (read_only, safe_operator, staged_proposer); Boundary 3 taint-aware dynamic risk escalation in preflight guardrails; and Boundary 4 interactive WordPress administrator approval enforcement rejecting Bearer token calls.
* Custom Firewall Rules Rebranding & AI Assistant Enhancements: Renamed Visual Rule Studio to Custom Firewall Rules across navigation, routes, and compiler logs; updated hero workflow to collapsed-by-default with 1-click plain English prompts and site-aware Markdown generation for non-technical users.

= 2.13.0 =
* Context-Aware Instant Scan & Targeted Audit Mitigation Actions Overhaul: Eliminated irrelevant action buttons on unrecognized and unknown files (e.g. "Repair Core", "Repair Plugin", "Repair Theme", "Code Diff (FIM)", and "Strip Webshell" erroneously displayed on unknown_core_file findings like test.txt in WordPress root).
* Formulated strict semantic classification predicates across all scanner interfaces: isUnknownFile strictly displays "Quarantine", "Delete Rogue File", and "View File"; isChecksumsUnavailable identifies unmanaged or custom components without official WP.org SVN checksums; isModifiedFile and isFimEligible restrict "Repair Core/Plugin/Theme" and "Visual Code Diff (FIM)" exclusively to verified modified official WordPress.org releases (excluding wp-config.php and unknown files); isInjectedWrapper restricts "Auto-Cure: Strip Webshell" exclusively to legitimate existing files where malware wrappers were prepended or injected; and isUser/isCron/isHook isolate non-file entities with dedicated context actions.
* Rogue File Deletion Safeguard: Added 14-day WebCare Quarantine Vault automatic backup safety confirmation dialog before permanently deleting any rogue or untracked file via handleDeleteRogueFile().
* Upstream Comparison Verification: Added fallback is_official_compared guard in VisualDiffModal for core and theme comparisons to prevent offering restoration when no upstream baseline exists.

= 2.12.0 =
* Plugin Check (PCP) Sandbox Authentication & RASP Hardening: Added original-table auth cookie verification (`get_original_table_prefix()`, `is_plugin_check_db_sandbox()`, `validate_cookie_against_original_tables()`), fixed `AUTH_COOKIE` scheme lookup, increased RASP stack inspection depth to 40 frames, and skipped seeding HoneyToken canary users/options inside temporary `*_pc_` compliance test sandboxes while keeping unauthenticated referer/action spoofing strictly blocked.
* REST API & AJAX Attack Surface & Modular WAF False-Positive Tuning: Fixed Reflection handler ownership for inherited background queue subclasses, separated Core REST discovery indexes and Storefront/internal-guarded routes from unguarded write risks, added AST callback guard and read-only sink inspection across named and inline closures, scoped `$wpdb` SQL sink checks strictly to argument `#1` (ignoring `$wpdb->prefix`/cast-safe table concatenation), stripped duplicate REST slashes, excluded Composer `vendor-prefixed`/`lib/packages` bundles, fixed string-interpolation (`T_CURLY_OPEN`/`${}`) depth and top-level helper/guard detection in ABSPATH and fixed-host SSRF checks, skipped dynamic concatenated hook names, preserved slashes in namespaced AJAX actions, added child-theme vendor inheritance and expanded known vendor identification, and calibrated Modular WAF Monitor vs Enforce recommendations on verified/read-only endpoints, upload handlers, and outbound HTTP checks.
* Modular WAF Live AST Scan Telemetry, Background Continuation & Pause/Resume Controls: Upgraded `SiteBehavioralAnalyzer`, `Scheduler`, `ScannerRoutes`, and the Modular Intelligence Firewall Studio (plus Setup Studio Step 3) with active execution time tracking (`active_elapsed_ms`) and EMA speed smoothing (`ema_files_per_sec`) so closed-browser idle gaps never distort elapsed duration or ETA, added automatic WP-Cron background step continuation (`webcareproscan_modular_ast_step`), raised batch throughput (400 files per request), and added Pause, Resume, and Cancel endpoints and controls across Light and Dark modes alongside dynamic version badges.
* Edge-Case Security Audit Hardening: Enforced `realpath()` and `PathValidator` symlink boundary checks in `get_code_preview()`, replaced `maybe_unserialize()` with class-safe `SerializedDataScanner::safe_unserialize()` across DB/cache scanners, routed `MCPAgentService` through `FirewallEngine::get_client_ip()`, enforced same-origin `Referer` host validation on Rule #36 cart/checkout heuristics, restricted RASP `debug_backtrace` checks to authenticated administrators under `WordPress\Plugin_Check\`, and added custom trusted reverse-proxy CIDR resolution and IPv6-safe matching in `MicroWafCompiler`.
* Centralized Cron & Scheduled Tasks Control Center: Added `CronRegistry`, `CronExecutionLogger`, `CronControlCenter`, `CronRoutes` (`/cron-manager/*`), database table `webcareproscan_cron_logs`, and the dedicated `Cron & Scheduled Tasks Control Center` console (`webcare-pro-cron-manager`) unifying all 15 plugin cron hooks and background workers with bidirectional settings/notification/Setup Studio synchronization, enable/disable switches (with safety-locked expiration timers), custom recurrence controls, manual "Run Now" triggers, and filterable execution history logs across Light and Dark modes.
* Custom Modular Rule (MOD-CUSTOM-*) Pre-Boot Compilation & Auto-Ban Sync: Enabled first-hit immediate blocking (`immediate_block` / `rate_limit = 0`) for custom Modular WAF rules across both WordPress runtime and compiled `< 0.1ms` pre-boot `.waf-preload.php`, with full `ban_ttl` and `sync_cloudflare` propagation into `FirewallEngine::add_blocked_ip()` and Cloudflare Edge IP ban synchronization.

= 2.11.0 =
* Production WAF Telemetry Learnings & False-Positive Hardening: Immunized standard RFC 8615 well-known endpoints (/.well-known/related-website-set.json, assetlinks.json, apple-app-site-association, acme-challenge, security.txt) from 404 attack counters, eliminating false-positive lockouts on modern mobile browsers.
* Synthetic Performance Audit Tool Immunity: Added recognition for read-only synthetic audit runners (WebPageTest PTST/, Chrome-Lighthouse, Google-PageSpeed, GTmetrix, SpeedCurve, PingdomTMS) to exempt speed test bots from 404 rate-limiting during automated site diagnostics.
* WooCommerce High-Traffic Production Hardening: Resolved customer IP addresses directly from $order records on asynchronous payment webhooks (Stripe, PayPal, Mollie, Klarna, 3DS) to safeguard payment gateways from carding lockouts, deduplicated checkout failure tracking, enforced Store API block checkout security, and tuned coupon velocity to 8 attempts with active cart session leniency (up to 12 attempts).
* Context-Aware Customer Order Notes & Complex Passwords: Required HTML tag context and JavaScript assignment markers for XSS regex checks, preventing false alarms on benign checkout notes (e.g. "leave on back porch") and masking sensitive password strings.
* Cloudflare Edge Rule 1 & Jetpack Smart Pass: Stripped /xmlrpc.php from Cloudflare Edge Rule 1 to route XML-RPC traffic to origin where verified Automattic Jetpack Smart Pass (192.0.64.0/18, 198.181.116.0/22) operates smoothly while blocking unauthorized brute-force attempts.
* Plugin Check (PCP) Test Harness Immunity: Immunized Runtime RASP hooks against test runner sandboxes (wp_pc_ / wpm3_pc_) and ensured administrative referers and actions never trigger privilege alerts or self-IP bans during compliance audits.

= 2.10.0 =
* 2026 Advanced Smart Rules Suite (Rules #48–#54): Implemented specialized defense primitives across MicroWafCompiler and FirewallEngine.
* Smart Rule #48: Normalized ?rest_route= query parameter routing and blocked unauthenticated HTTP method overrides (_method=DELETE, X-HTTP-Method-Override).
* Smart Rule #49: Trapped authentication and password-reset PHP array type-confusion injections (user_login[]=, pwd[]=, key[]=) to prevent PHP 8+ TypeError crashes.
* Smart Rule #50: Intercepted unauthenticated admin-ajax / REST shortcode parse requests and serialized callable gadgets (["System", "exec"]) targeting builder RCE chains.
* Smart Rule #51: Protected WordPress 7.0+ Interactivity API directives (data-wp-init, data-wp-watch) against prototype pollution and sanitized block bindings targeting sensitive meta keys.
* Smart Rule #52: Deep-packet inspection intercepting forged Stripe-Signature or PayPal-Transmission-Sig webhooks from public IPs outside official gateway CIDRs/ASNs.
* Smart Rule #53: Sensitive log and configuration exfiltration shield (/wc-logs/, php_errorlog, .env.*, auth.json, Range: bytes= probes) with instant 1st-hit 24h bans.
* Smart Rule #54: In-memory gzdecode() decompression on gzipped .svgz images prior to sanitization, escalating malicious polyglot and webshell uploads to immediate 24h bans.
* Cloudflare Real-Time Auto-Ban Sync Persistence: Out-of-the-box auto-sync enablement with live UI state synchronization between Settings and Firewall views.
* Structured 240-Character Forensic Cloudflare Notes: Formatted rich edge ban notes preserving incident ID, rule name, HTTP method, and TTL expiration.
* Recursive Upload Flattening: Safe recursive normalization (depth <= 4, count <= 50) of nested multi-dimensional $_FILES form arrays with pre-flight inspection.

= 2.9.0 =
* Context-Adaptive Firewall (CAF 2.0): Fingerprints active plugins to put irrelevant rules to sleep (e.g., e-commerce rules sleep on standard blogs, page-builder rules sleep when builders are absent), minimizing CPU overhead.
* ThreatScore First-Hit Critical Exploit Banning: Deterministic exploits (SQL Injection, PHP Code Injection, Path Traversal) trigger an immediate 85-point violation and 24-hour hard ban on hit #1, offloading IPs to Cloudflare Edge in zero visitor latency via fastcgi_finish_request().
* Cloudflare Edge "4 + 1" Smart Consolidation: Consolidates enterprise edge defense into 4 master compound rules on Cloudflare Free Plan, leaving 1 custom rule slot 100% free for site owner rules.
* Zero-Day Redirect Hack Defense & .htaccess Vault Armor: 5-vector synthetic canary probes (Mobile, Googlebot, External Referer) detecting cloaked redirects, paired with a 5-version rolling .htaccess rollback vault.
* Next-Gen Cryptographic Self-Defense: Real-time SHA-256 integrity audits against an embedded 204-file cryptographic manifest, detecting modified, missing, or rogue files with 1-click self-repair.

= 2.4.0 =
* AI/MCP Agent Governance & Plaintext Key Vaulting (AiAgentInventoryScanner.php, SecretVault.php): Discovers autonomous agents, LLM integrations, and MCP tools across active plugins, registered REST namespaces, and option keys. Automatically flags exposed REST routes missing authorization callbacks and migrates plaintext API secrets (OpenAI, Anthropic, Gemini, MCP) into AES-256-GCM AEAD encrypted storage.
* Zero-Quarantine Surgical In-File Remediation (FimVaultManager.php, TransactionalRemediation.php): Captures compressed gzip pristine baselines inside a hardened, directory-listing-protected vault. Surgically restores altered core and plugin files back to their pristine baseline with pre-repair snapshots and loopback CrashGuard health check probes that roll back changes instantly if fatal errors or HTTP 500 status codes occur.
* WooCommerce & ActionScheduler Keyset Cursor Pagination (CronPersistenceScanner.php): Replaces table-locking OFFSET and full scans with non-locking primary key cursor pagination (WHERE action_id > %d ORDER BY action_id ASC LIMIT 250) on wp_actionscheduler_actions, eliminating InnoDB lock contention and checkout slowdowns during high-volume store traffic.
* Class-Aware Serialized Object & POP-Chain Validation (SerializedDataScanner.php): Zero-unserialize static class inspections validating against white-listed WooCommerce and ActionScheduler domain classes while flagging dangerous PHP Object Injection gadget chains (Guzzle, Monolog, Symfony, Illuminate).
* Pre-Install Package Security Audit & Atomic Upgrade Window (UpdateGatekeeperEngine.php, FirewallEngine.php): Staging archive audit inspecting unzipped directories for zip-slip path traversals, external directory symlinks, and obfuscated webshell markers before installation. Places 180s atomic upgrade locks blocking unauthenticated external probes to upgrade.php and plugin directories during updates.
* In-Memory Closure Reflection & Gadget Callback Sentinel (HookInfiltrationSentinel.php): Audits critical runtime hooks (authenticate, init, template_redirect, wp_authenticate) using ReflectionFunction on anonymous Closures to detect fileless eval()'d code, writable directory bindings, and dangerous array reflection/gadget callbacks.
* Outbound Egress DNS Pinning & TOCTOU Rebinding Elimination (OutboundEgressFirewall.php): Single-pass DNS resolution across A and AAAA records, evaluating IPs against private, loopback, unique-local, and cloud metadata ranges. Pins verified destination IPs into cURL transports via CURLOPT_RESOLVE, permanently defeating Time-of-Check to Time-of-Use DNS rebinding SSRF attacks.
* REST API Batch-Route & Method-Override Normalization (FirewallEngine.php, RestApiInventory.php): Recursive inspection engine for /wp-json/wp/v2/batch payloads, unpacking query parameters and canonicalizing _method query and X-HTTP-Method-Override headers to neutralize smuggled unauthenticated exploits (CVE-2026-63030 and CVE-2026-60137).
* Deterministic MCP Capability Sandboxing (MCPAgentService.php): Hardened Model Context Protocol agent tool execution by enforcing strict deterministic sandboxing on all state-mutating actions, requiring HMAC-signed cryptographic confirmation tokens and human administrative authentication.
* Advanced Adversarial Prompt Injection Isolation (PromptInjectionGuard.php): Neutralizes zero-width spaces, bidirectional override controls, invisible Unicode tag smuggler characters, and embedded comment directives.
* Active Canary Honeytokens & Signed Webhook Decoys (HoneyTokenEngine.php): Realistic decoy .env generation with HMAC-signed canary callback tokens, automatically quarantining external C2 probes and LLM recon scrapers.
* Stateless WebCrypto SHA-256 Proof-of-Work (BotReconDefense.php): Zero-dependency browser verification requiring clients to solve a 16-bit leading zero SHA-256 challenge via native crypto.subtle.digest in ~70ms, halting automated headless and AI scrapers.

= 2.1.0 =
* Cryptographic Plugin Activity & Tamper-Evident Forensic Audit Ledger with unbroken SHA-256 hash chains and AES-256-GCM envelope encryption.
* Write-Ahead Logging (WAL) state machine with crash recovery and forensic journal quarantine.
* Model Context Protocol (MCP) agent token encryption in SecretVault with authenticated REST permissions.
* Strict fail-closed WebAuthn cryptographic assertion verification (openssl_verify) supporting SPKI PEM and COSE key extraction.
* Monotonic authenticator signature counter verification (sign_count) to detect cloned passkeys.
* Timing-safe indexed WebAuthn credential lookup resolving O(1) user identification.
* Anti-enumeration resident key challenge generation preventing account presence leakage.
* Fail-closed SecretVault key derivation removing weak fallback seeds.
* Next-Gen WAF Track B: Guest admin-ajax.php / admin-post.php and REST action matrix guard (Rules #36 and #37) with O(1) WooCommerce and form allowlists.
* Interactive tables for Blocked and Whitelisted IPs replacing multi-line textareas with live subnet validation.
* Active Lockouts & Central Blocklist modal redesign featuring expandable recent attack payload drawers and live countdown timers.
* SHA-512 8-digit TOTP cryptographic algorithm support with dynamic inline SVG QR code provisioning.
* Unified WAF incident stream routing for Supply-Chain Gatekeeper update and install intercepts.
* Full WordPress.org Plugin Check (PCP) compliance in QRCodeGenerator.php with 100% clean passes.
* Expanded forensic Activity Log exports up to 5,000 records in streaming CSV and JSON.

= 1.31.0 =
* Web Application Firewall (WAF) Attack Counters & Accurate Daily Partition Aggregation.
* Zero-SQL WAF incident daily JSON Lines storage with atomic appending.
* Pre-Install Supply-Chain Gatekeeper & Update Risk Advisor AST heuristic inspection.
* CrashGuard zero-downtime circuit breaker and safe mode self-healing recovery.
* Enterprise 59-event notification center matrix across email and webhooks.

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
* Granular Rule-Scoped & Category-Scoped IP Allowlisting & In-Place Policy Management.
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
* 12-Step Protection Setup & Calibration Onboarding Wizard with Live Server Audit.
* Cloudflare Edge 1-Click API Token Generator & Automatic Zone ID Detection.
* Consolidated Single-Line Firewall Navigation & Advanced Tools Dropdown.
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
* Unified Single Storage Directory Architecture under `wp-content/uploads/webcare-pro-security/`.
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
