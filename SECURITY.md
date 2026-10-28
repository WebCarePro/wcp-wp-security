# Security Policy & Vulnerability Disclosure

**WCP Security Scanner** is designed, engineered, and maintained by **Mir Alamin** ([WebCare Pro](https://webcarespro.com)), an individual solo Linux SysAdmin and Senior WordPress Security Engineer. 

Security integrity and responsible disclosure are paramount. If you discover a security vulnerability or potential risk within this plugin or its runtime engines, please follow this policy to report it responsibly.

---

## Supported Versions

Only the latest release version on the active `main` branch receives active security patches and hotfixes.

| Version | Supported | Status |
|:---|:---:|:---|
| **1.29.x** (Current) | ✅ Yes | Active Security Maintenance |
| < 1.29.0 | ❌ No | Deprecated — Please upgrade to the latest release |

---

## Reporting a Vulnerability

> [!IMPORTANT]
> **Please do NOT report security vulnerabilities via public GitHub issues, discussions, or community forums.**  
> Public disclosure before an investigation and patch can put active production sites at risk.

To report a vulnerability directly and privately to Mir Alamin:

1. **Email:** Send full technical details to **`security@webcarespro.com`** (or directly via **`miralamin.dev@gmail.com`**).
2. **Subject Line:** `[Vulnerability Report] WCP Security Scanner - <Brief Description>`
3. **Report Contents:**
   - Detailed description of the vulnerability and its potential impact.
   - Exact steps or proof-of-concept (PoC) code to reproduce the issue in a standard environment.
   - Affected file(s), function(s), or REST API endpoint(s).
   - WordPress and PHP version used during testing.
   - Any suggested remediations or virtual patches (if available).

---

## Responsible Disclosure & Response SLA

As an independent solo security engineer, I treat valid security disclosures with the highest priority:

- **Initial Acknowledgment:** Within **24 to 48 hours** of receiving your report.
- **Triage & Validation:** Within **3 business days** to verify reproducibility and scope the blast radius.
- **Remediation & Patch Release:** Critical vulnerabilities are patched, tested, and published to GitHub within **5 to 7 business days** (or sooner depending on severity).
- **Public Disclosure / Advisory:** Coordinated with the reporter after a patched release is published and available for users to update.

---

## Defensive Architecture & Safety Principles

WCP Security Scanner is engineered with defensive architectural principles to minimize attack surfaces:

1. **CrashGuard Circuit Breaker (`CrashGuard.php`):** Unhandled internal errors, TypeErrors, or fatal exceptions are trapped in an early Safe Mode envelope, preventing host fatal crashes or administrative lockouts.
2. **Pure Cryptographic Secret Vault (`CryptoVault.php`):** All sensitive webhook credentials, Cloudflare API tokens, and 2FA secrets are encrypted at rest using AES-256-GCM AEAD encryption with randomized 12-byte IVs. Plaintext secrets are never stored in `wp_options` or written into SQL backups.
3. **Preload Micro-WAF Protection (`MicroWafCompiler.php`):** Standalone early request inspection runs before WordPress core boots with independent `try/catch` isolation, guaranteeing zero interference with standard PHP processing.
4. **100% On-Premise Privacy:** No tracking, telemetry, or external phone-home mechanisms. All security telemetry remains 100% on the client server.

---

## Recognition & Attribution

Responsible researchers and community engineers who report verified vulnerabilities will be gratefully credited in the release notes (`changelog.txt`), `README.md`, and official GitHub releases.

Thank you for helping keep the WordPress ecosystem safe and secure!
