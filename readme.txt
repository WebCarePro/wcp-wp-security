=== WCP Security Scanner ===
Contributors: miralamin
Donate link: https://webcarespro.com
Tags: security, malware, scanner, integrity, antivirus
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Professional security & malware scanner with core integrity checks, heuristic threat analysis, automated scheduling, and modern React dashboard.

== Description ==

WCP Security Scanner gives you enterprise-grade malware detection and WordPress core integrity checks inside an intuitive, modern React single-page dashboard.

= Features =
* **WordPress Core Integrity Audit**: Matches your core files against official WordPress.org cryptographic checksums to detect tampered or backdoored files.
* **Malware & Heuristic Engine**: Scans themes and plugins for suspicious patterns like `eval(base64_decode())`, webshell signatures, backdoor functions, and remote shell executions.
* **Automated Scheduled Scanning**: Background WP-Cron scheduler with customizable frequencies (Hourly, Twice Daily, Daily, Weekly) and off-peak execution times.
* **Email Security Notifications**: Real-time incident reports with configurable severity thresholds sent directly to administrator inboxes.
* **Multi-Provider AI Intelligence**: Integrated forensic analysis with Google Gemini, OpenAI ChatGPT, and Anthropic Claude for instant malicious code de-obfuscation and remediation guidance.
* **Chunk-based Asynchronous Scanning**: Avoids PHP timeouts or memory limits by dividing scan jobs into intelligent batches.
* **One-Click Database Backup Vault**: Create compressed SQL dumps before remediation with secure access-denied storage.
* **Modern SPA Interface**: Built with WordPress React components and Lucide icons for real-time progress and reporting.

= Author =
* **Author**: Mir Alamin
* **Website**: [WebCare Pro](https://webcarespro.com)

= About WebCare Pro =
WebCare Pro helps businesses build, secure, optimize, and manage high-performance websites and servers. From Linux & cloud infrastructure to blazing-fast performance, website security, migrations, Cloudflare, DNS, managed hosting, and modern web development—we keep your online presence fast, secure, and always available.

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
