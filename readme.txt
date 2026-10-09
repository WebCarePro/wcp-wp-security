=== WCP WP Security Scanner ===
Contributors: wcpteam, miralamin
Donate link: https://webcarespro.com
Tags: security, malware, scanner, integrity, antivirus
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Professional WordPress Security & Malware Scanner by Mir Alamin with Core File Integrity, Heuristic Threat Analysis, Automated Scheduling, AI Forensic Intelligence, and Modern React Dashboard.

== Description ==

WCP WP Security Scanner gives you enterprise-grade malware detection and WordPress core integrity checks inside an intuitive, modern React single-page dashboard.

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
