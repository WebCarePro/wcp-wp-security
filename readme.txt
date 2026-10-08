=== WCP WP Security Scanner ===
Contributors: wcpteam
Tags: security, malware, scanner, integrity, antivirus
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Professional WordPress Security & Malware Scanner with Core File Integrity, Heuristic Threat Analysis, and Modern React Dashboard.

== Description ==

WCP WP Security Scanner gives you enterprise-grade malware detection and WordPress core integrity checks inside an intuitive, modern React single-page dashboard.

= Features =
* **WordPress Core Integrity Audit**: Matches your core files against official WordPress.org cryptographic checksums to detect tampered or backdoored files.
* **Malware & Heuristic Engine**: Scans themes and plugins for suspicious patterns like `eval(base64_decode())`, webshell signatures, backdoor functions, and remote shell executions.
* **Chunk-based Asynchronous Scanning**: Avoids PHP timeouts or memory limits by dividing scan jobs into intelligent batches.
* **Modern SPA Interface**: Built with WordPress React components and Lucide icons for real-time progress and reporting.

== Installation ==

1. Upload the `wcp-wp-scanner` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Security Scanner** in the WordPress admin sidebar.
4. Click **Start Scan Now** to analyze your site.
