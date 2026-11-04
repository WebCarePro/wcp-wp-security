<?php
/**
 * Context-Adaptive Firewall (CAF) Standalone Admin Page View
 *
 * Dedicated standalone interface providing full control over:
 * - CAF StackGuard Archetype & Profiles (Phase 1)
 * - Cloudflare Free-Plan Edge Slot Optimizer & Survival Mode (Phase 2)
 * - Behavioral Intelligence, Proof-of-Work (PoW) & Dynamic Rate Limiting (Phase 3)
 *
 * Preserves the Scan Page UI 100% untouched by executing as an independent view.
 * Fully integrates with the WCP Executive Design System (Light & Dark Theme adaptive).
 *
 * @package WcpScanner\Admin
 * @author  Mir Alamin (WebCare Pro)
 */

namespace WcpScanner\Admin;

if (!defined('ABSPATH')) {
    exit;
}

$advisor = new \WcpScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
$overview = $advisor->get_overview();

$snapshot        = $overview['snapshot'] ?? [];
$recommendations = $overview['recommendations'] ?? [];
$active_profile  = $overview['active_profile'] ?? 'balanced';
$risk_score      = $overview['residual_risk_score'] ?? 10;
$is_killed       = !empty($overview['is_killswitch_active']);

$profiles = [
    [
        'id'    => 'ecommerce_hardened',
        'name'  => __('E-Commerce Hardened', 'wcp-security-scanner'),
        'color' => '#10b981',
        'badge' => __('High Conversion & Safe Cart', 'wcp-security-scanner'),
        'desc'  => __('WooCommerce, EDD & SureCart. Zero checkout friction, serialized cart fragment safe-pass, and strict login brute-force defense.', 'wcp-security-scanner'),
    ],
    [
        'id'    => 'corporate_brochure',
        'name'  => __('Corporate / Brochure', 'wcp-security-scanner'),
        'color' => '#0284c7',
        'badge' => __('Page-Builder Protected', 'wcp-security-scanner'),
        'desc'  => __('Elementor, Divi & Contact Forms. Relaxed page-builder styling saves for authenticated editors; blocks external probe vectors.', 'wcp-security-scanner'),
    ],
    [
        'id'    => 'membership_lms',
        'name'  => __('Membership & LMS', 'wcp-security-scanner'),
        'color' => '#8b5cf6',
        'badge' => __('High Throughput', 'wcp-security-scanner'),
        'desc'  => __('MemberPress, LearnDash & BuddyBoss. Anti-credential stuffing, concurrent session armor, and high video/progress throughput.', 'wcp-security-scanner'),
    ],
    [
        'id'    => 'cpanel_shared_saver',
        'name'  => __('cPanel / Shared Saver', 'wcp-security-scanner'),
        'color' => '#f59e0b',
        'badge' => __('Zero CloudLinux LVE Overload', 'wcp-security-scanner'),
        'desc'  => __('Low-resource / CloudLinux hosting. Minimizes PHP worker wakeups with ultra-lean fast-path preload execution.', 'wcp-security-scanner'),
    ],
    [
        'id'    => 'high_security_paranoid',
        'name'  => __('High-Security / Paranoid', 'wcp-security-scanner'),
        'color' => '#ef4444',
        'badge' => __('Zero-Trust Perimeter', 'wcp-security-scanner'),
        'desc'  => __('Zero-trust defense mode. Enforces strict zero-tolerance perimeter filters, early honeytokens, and aggressive probe lockouts.', 'wcp-security-scanner'),
    ],
    [
        'id'    => 'balanced',
        'name'  => __('Balanced (Default)', 'wcp-security-scanner'),
        'color' => '#6366f1',
        'badge' => __('Universal Standard', 'wcp-security-scanner'),
        'desc'  => __('Adaptive default profile. Standard brute-force filters, crawler verification, and automatic virtual patch compilation.', 'wcp-security-scanner'),
    ],
];

// Cloudflare Status (Phase 2)
$cf_settings = \WcpScanner\System\SettingsManager::get_settings();
$cf_zone_id  = $cf_settings['cloudflare_zone_id'] ?? '';
$cf_configured = !empty($cf_settings['cloudflare_api_token']) && !empty($cf_zone_id);

$cf_optimizer = class_exists('\\WcpScanner\\Firewall\\CAF\\CloudflareSlotOptimizer') ? new \WcpScanner\Firewall\CAF\CloudflareSlotOptimizer() : null;
$cf_breaker   = class_exists('\\WcpScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker') ? new \WcpScanner\Firewall\CAF\OriginLoadCircuitBreaker() : null;

$cf_pending_queue = get_option(\WcpScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
$cf_pending_count = is_array($cf_pending_queue) ? count($cf_pending_queue) : 0;
$cf_breaker_state = $cf_breaker ? $cf_breaker->get_state() : [];

$cf_status = [
    'configured'              => $cf_configured,
    'pending_ban_queue_size'  => $cf_pending_count,
    'circuit_breaker_active'  => !empty($cf_breaker_state['active']),
];

// Threat Score & Behavioral Metrics (Phase 3)
$threat_telemetry = class_exists('\\WcpScanner\\Firewall\\CAF\\ThreatScoreTracker')
    ? \WcpScanner\Firewall\CAF\ThreatScoreTracker::get_telemetry()
    : [];

$threat_summary = [
    'total_tracked_ips'     => $threat_telemetry['total_tracked_ips'] ?? 0,
    'pow_challenges_active' => $threat_telemetry['pow_active_count'] ?? 0,
];

$rest_url = esc_url_raw(rest_url('wcp-scanner/v1'));
$rest_nonce = wp_create_nonce('wp_rest');
$logo_url = defined('WCPSCAN_URL') ? WCPSCAN_URL . 'assets/webcare-original-logo-3d.jpg' : '';
$version  = defined('WCPSCAN_VERSION') ? WCPSCAN_VERSION : '2.4.0';
?>

<div class="wcp-page-container wcp-theme-light" id="wcp-caf-root">

    <!-- FLOATING NOTICE BANNER -->
    <div id="wcp-caf-notice" style="display: none; position: sticky; top: 32px; z-index: 9999; margin-bottom: 16px; padding: 12px 18px; border-radius: 10px; box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.15); font-size: 13px; font-weight: 600;"></div>

    <!-- MAIN TWO-TIER EXECUTIVE HEADER -->
    <header class="header-bar wcp-two-tier-header">
        <div class="wcp-header-tier-top">
            <div class="brand-section">
                <div class="brand-logo-wrap" style="overflow: hidden; border-radius: 12px; border: 1.5px solid rgba(56, 189, 248, 0.45); box-shadow: 0 4px 14px rgba(6, 182, 212, 0.35); display: flex; align-items: center; justify-content: center; width: 44px; height: 44px;">
                    <?php if (!empty($logo_url)): ?>
                        <img src="<?php echo esc_url($logo_url); ?>" alt="WebCare Pro Logo" class="brand-3d-logo-img" style="width: 100%; height: 100%; object-fit: cover;" />
                    <?php else: ?>
                        <span style="font-size: 22px;">🛡️</span>
                    <?php endif; ?>
                </div>
                <div>
                    <div class="brand-title">
                        WebCare<span class="highlight">Pro</span> Security
                    </div>
                    <div class="brand-subtitle">
                        <span class="pulse-dot"></span>
                        <?php
                        /* translators: %s: current plugin version string */
                        printf(esc_html__('Context-Adaptive Perimeter Defense & StackGuard • v%s', 'wcp-security-scanner'), esc_html($version));
                        ?>
                    </div>
                </div>
            </div>

            <div class="wcp-header-actions" style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <button type="button" id="wcp-theme-toggle-btn" class="wcp-theme-toggle-btn" title="Toggle Light / Dark Mode">
                    <span id="wcp-theme-toggle-icon">🌙</span>
                    <span id="wcp-theme-toggle-text">Dark Mode</span>
                </button>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-firewall')); ?>" class="wcp-btn wcp-btn-secondary" style="font-size: 13px; padding: 7px 14px; text-decoration: none; display: inline-flex; align-items: center; gap: 6px;">
                    ← <?php esc_html_e('WAF Rules', 'wcp-security-scanner'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-scan')); ?>" class="wcp-btn wcp-btn-secondary" style="font-size: 13px; padding: 7px 14px; text-decoration: none; display: inline-flex; align-items: center; gap: 6px;">
                    🔍 <?php esc_html_e('Scanner', 'wcp-security-scanner'); ?>
                </a>
            </div>
        </div>

        <div class="wcp-header-tier-bottom">
            <nav class="nav-tabs" style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-security-scanner')); ?>" class="nav-tab-btn" style="text-decoration: none;">
                    📊 <?php esc_html_e('Dashboard', 'wcp-security-scanner'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-scan')); ?>" class="nav-tab-btn" style="text-decoration: none;">
                    🔍 <?php esc_html_e('Scanner', 'wcp-security-scanner'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-firewall')); ?>" class="nav-tab-btn" style="text-decoration: none;">
                    🛡️ <?php esc_html_e('Firewall (WAF Lite)', 'wcp-security-scanner'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-caf')); ?>" class="nav-tab-btn active" style="text-decoration: none;">
                    ⚡ <?php esc_html_e('Adaptive Firewall (CAF)', 'wcp-security-scanner'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-auth')); ?>" class="nav-tab-btn" style="text-decoration: none;">
                    🔐 <?php esc_html_e('Identity & 2FA', 'wcp-security-scanner'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wcp-scanner-settings')); ?>" class="nav-tab-btn" style="text-decoration: none;">
                    ⚙️ <?php esc_html_e('Settings', 'wcp-security-scanner'); ?>
                </a>
            </nav>
        </div>
    </header>

    <!-- FIREWALL HERO BANNER -->
    <div class="wcp-firewall-hero">
        <div style="display: flex; align-items: center; gap: 14px;">
            <div class="wcp-firewall-hero-icon">
                <span style="font-size: 24px;">⚡</span>
            </div>
            <div>
                <h1 class="wcp-firewall-hero-title">
                    <?php esc_html_e('Context-Adaptive Firewall (CAF) & StackGuard', 'wcp-security-scanner'); ?>
                </h1>
                <p class="wcp-firewall-hero-desc">
                    <?php esc_html_e('Zero-friction intelligent perimeter: stack anatomy inspection, Cloudflare 3-slot edge offload, and behavioral velocity defenses.', 'wcp-security-scanner'); ?>
                </p>
            </div>
        </div>

        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
            <button type="button" id="wcp-caf-reprofile-btn" class="wcp-btn wcp-btn-secondary" style="font-size: 13px; font-weight: 600; padding: 8px 16px; cursor: pointer;">
                🔄 <?php esc_html_e('Re-Profile Stack', 'wcp-security-scanner'); ?>
            </button>
            <button type="button" id="wcp-caf-killswitch-btn" class="wcp-btn" style="font-size: 13px; font-weight: 600; padding: 8px 16px; cursor: pointer; <?php echo $is_killed ? 'background: #dc2626; color: #ffffff;' : 'background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%); color: #ffffff;'; ?>">
                ⚡ <?php echo $is_killed ? esc_html__('Preload Bypassed (Click to Enable)', 'wcp-security-scanner') : esc_html__('Preload WAF Active', 'wcp-security-scanner'); ?>
            </button>
        </div>
    </div>

    <!-- 4 KPI ANATOMY STAT CARDS -->
    <div class="wcp-firewall-kpi-grid">
        <div class="wcp-firewall-kpi-card">
            <div class="wcp-firewall-kpi-label">
                <span><?php esc_html_e('WordPress & PHP Environment', 'wcp-security-scanner'); ?></span>
                <span style="width: 8px; height: 8px; border-radius: 50%; background: #0284c7; display: inline-block;"></span>
            </div>
            <div class="wcp-firewall-kpi-val" style="font-size: 18px; margin-top: 6px;">
                WP v<?php echo esc_html($snapshot['wp_version'] ?? '7.x'); ?> • PHP <?php echo esc_html($snapshot['php_version'] ?? '8.x'); ?>
            </div>
            <span class="wcp-firewall-kpi-sub">
                <?php
                /* translators: %1$d: active plugin count, %2$s: active theme slug */
                printf(esc_html__('%1$d Active Plugins • Theme: %2$s', 'wcp-security-scanner'), count($snapshot['active_plugins'] ?? []), esc_html($snapshot['active_themes']['active']['slug'] ?? 'Active'));
                ?>
            </span>
        </div>

        <div class="wcp-firewall-kpi-card">
            <div class="wcp-firewall-kpi-label">
                <span><?php esc_html_e('Dormant Attack Surface', 'wcp-security-scanner'); ?></span>
                <span style="width: 8px; height: 8px; border-radius: 50%; background: <?php echo !empty($recommendations['lock_dormant_surface']) ? '#10b981' : '#f59e0b'; ?>; display: inline-block;"></span>
            </div>
            <div class="wcp-firewall-kpi-val" style="font-size: 18px; margin-top: 6px; color: <?php echo !empty($recommendations['lock_dormant_surface']) ? '#10b981' : '#f59e0b'; ?>;">
                <?php echo esc_html((string)($recommendations['dormant_plugin_count'] ?? 0)); ?> <?php esc_html_e('Inactive Plugins', 'wcp-security-scanner'); ?>
            </div>
            <span class="wcp-firewall-kpi-sub">
                <?php echo !empty($recommendations['lock_dormant_surface']) ? esc_html__('🔒 Locked down at early preload runtime', 'wcp-security-scanner') : esc_html__('⚠️ Direct plugin probe surface exposed', 'wcp-security-scanner'); ?>
            </span>
        </div>

        <div class="wcp-firewall-kpi-card">
            <div class="wcp-firewall-kpi-label">
                <span><?php esc_html_e('Conflict Avoidance Shields', 'wcp-security-scanner'); ?></span>
                <span style="width: 8px; height: 8px; border-radius: 50%; background: #10b981; display: inline-block;"></span>
            </div>
            <div class="wcp-firewall-kpi-val" style="font-size: 18px; margin-top: 6px; color: #0284c7;">
                <?php echo esc_html((string)count($recommendations['conflict_exemptions']['scoped_rules'] ?? [])); ?> <?php esc_html_e('Context Safe-Passes', 'wcp-security-scanner'); ?>
            </div>
            <span class="wcp-firewall-kpi-sub">
                <?php esc_html_e('Zero false-positive e-commerce & page-builder saves', 'wcp-security-scanner'); ?>
            </span>
        </div>

        <div class="wcp-firewall-kpi-card">
            <div class="wcp-firewall-kpi-label">
                <span><?php esc_html_e('Residual Risk Posture', 'wcp-security-scanner'); ?></span>
                <span style="width: 8px; height: 8px; border-radius: 50%; background: <?php echo $risk_score > 50 ? '#dc2626' : '#10b981'; ?>; display: inline-block;"></span>
            </div>
            <div class="wcp-firewall-kpi-val" style="font-size: 18px; margin-top: 6px; color: <?php echo $risk_score > 50 ? '#dc2626' : '#10b981'; ?>;">
                <?php echo esc_html((string)$risk_score); ?> / 100
            </div>
            <span class="wcp-firewall-kpi-sub">
                <?php echo $risk_score <= 20 ? esc_html__('Optimal Hardened Defense Posture', 'wcp-security-scanner') : esc_html__('Hardening recommendations pending', 'wcp-security-scanner'); ?>
            </span>
        </div>
    </div>

    <!-- MAIN TWO-COLUMN SPLIT: PROFILES (LEFT) + CLOUDFLARE EDGE & BEHAVIORAL (RIGHT) -->
    <div style="display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(420px, 1.75fr); gap: 24px; align-items: start;">

        <!-- LEFT COLUMN: SMART PROTECTION PROFILES (PHASE 1) -->
        <div class="wcp-firewall-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--wcp-border, #e2e8f0); padding-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                <div>
                    <h3 class="wcp-firewall-section-title" style="margin: 0 0 4px 0; font-size: 16px;">
                        🛡️ <?php esc_html_e('Smart Protection Profiles (Phase 1)', 'wcp-security-scanner'); ?>
                    </h3>
                    <p class="wcp-firewall-section-desc" style="margin: 0; font-size: 12.5px;">
                        <?php esc_html_e('Compile tailored O(1) early-rejection rules matching your site archetype.', 'wcp-security-scanner'); ?>
                    </p>
                </div>
                <span class="wcp-badge-info" style="font-size: 11px;">
                    <?php esc_html_e('Auto-Detected:', 'wcp-security-scanner'); ?> <?php echo esc_html($recommendations['recommended_profile'] ?? 'balanced'); ?>
                </span>
            </div>

            <div style="display: flex; flex-direction: column; gap: 12px;">
                <?php foreach ($profiles as $p):
                    $is_current = ($active_profile === $p['id']);
                    $is_rec = (($recommendations['recommended_profile'] ?? '') === $p['id']);
                ?>
                <div class="wcp-firewall-rule-card" style="padding: 14px 16px; <?php echo $is_current ? 'border: 2px solid #4f46e5; box-shadow: 0 0 12px rgba(79, 70, 229, 0.15);' : ''; ?>">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: <?php echo esc_attr($p['color']); ?>;"></span>
                            <strong style="font-size: 14px;"><?php echo esc_html($p['name']); ?></strong>
                            <?php if ($is_rec): ?>
                                <span class="wcp-badge-clean" style="font-size: 10px; padding: 2px 6px;">
                                    <?php esc_html_e('RECOMMENDED', 'wcp-security-scanner'); ?>
                                </span>
                            <?php endif; ?>
                        </div>
                        <span class="wcp-badge-neutral" style="font-size: 11px;"><?php echo esc_html($p['badge']); ?></span>
                    </div>

                    <p style="font-size: 12px; margin: 0 0 10px 0; line-height: 1.5; opacity: 0.85;">
                        <?php echo esc_html($p['desc']); ?>
                    </p>

                    <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 8px; border-top: 1px solid var(--wcp-border, #e2e8f0);">
                        <span style="font-size: 11.5px; font-weight: 600;" class="<?php echo $is_current ? 'wcp-badge-clean' : 'wcp-badge-neutral'; ?>">
                            <?php echo $is_current ? esc_html__('● Active Profile', 'wcp-security-scanner') : esc_html__('○ Inactive', 'wcp-security-scanner'); ?>
                        </span>
                        <button type="button" class="wcp-apply-profile-btn wcp-firewall-rule-save-btn <?php echo $is_current ? 'is-saved' : ''; ?>" data-profile="<?php echo esc_attr($p['id']); ?>" <?php disabled($is_current); ?>>
                            <?php echo $is_current ? esc_html__('✓ Active', 'wcp-security-scanner') : esc_html__('Apply & Compile', 'wcp-security-scanner'); ?>
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- RIGHT COLUMN: CLOUDFLARE EDGE (PHASE 2) & BEHAVIORAL COCKPIT (PHASE 3) -->
        <div style="display: flex; flex-direction: column; gap: 24px;">

            <!-- CLOUDFLARE FREE-PLAN EDGE DEFENSE (PHASE 2) -->
            <div class="wcp-firewall-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--wcp-border, #e2e8f0); padding-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <h3 class="wcp-firewall-section-title" style="margin: 0 0 4px 0; font-size: 16px;">
                            ☁️ <?php esc_html_e('Cloudflare Free-Plan 3-Slot Edge Offload (Phase 2)', 'wcp-security-scanner'); ?>
                        </h3>
                        <p class="wcp-firewall-section-desc" style="margin: 0; font-size: 12.5px;">
                            <?php esc_html_e('Packs defense rules into Cloudflare free edge slots to save PHP workers.', 'wcp-security-scanner'); ?>
                        </p>
                    </div>
                    <span class="<?php echo !empty($cf_status['configured']) ? 'wcp-badge-clean' : 'wcp-badge-critical'; ?>" style="font-size: 11px;">
                        <?php echo !empty($cf_status['configured']) ? esc_html__('● Edge Connected', 'wcp-security-scanner') : esc_html__('○ Not Configured', 'wcp-security-scanner'); ?>
                    </span>
                </div>

                <!-- 3-Slot Edge Matrix Cards -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px;">
                    <div class="wcp-firewall-inset-box" style="padding: 12px 14px;">
                        <span class="wcp-badge-critical" style="font-size: 10px; margin-bottom: 4px; display: inline-block;">
                            <?php esc_html_e('Slot 1: Hard Drop', 'wcp-security-scanner'); ?>
                        </span>
                        <div style="font-size: 13px; font-weight: 700; margin: 4px 0;">Dormant & Scanners</div>
                        <div style="font-size: 11px; opacity: 0.8; line-height: 1.4;">Instant HTTP 403 block for known bot scanners & inactive plugin probes.</div>
                    </div>

                    <div class="wcp-firewall-inset-box" style="padding: 12px 14px;">
                        <span class="wcp-badge-warn" style="font-size: 10px; margin-bottom: 4px; display: inline-block;">
                            <?php esc_html_e('Slot 2: Managed Challenge', 'wcp-security-scanner'); ?>
                        </span>
                        <div style="font-size: 13px; font-weight: 700; margin: 4px 0;">Auth & Velocity Pacing</div>
                        <div style="font-size: 11px; opacity: 0.8; line-height: 1.4;">Managed Challenge on wp-login.php & abnormal authorization bursts.</div>
                    </div>

                    <div class="wcp-firewall-inset-box" style="padding: 12px 14px;">
                        <span class="wcp-badge-purple" style="font-size: 10px; margin-bottom: 4px; display: inline-block;">
                            <?php esc_html_e('Slot 3: Virtual Patches', 'wcp-security-scanner'); ?>
                        </span>
                        <div style="font-size: 13px; font-weight: 700; margin: 4px 0;">CVE Wirefilter Mitigations</div>
                        <div style="font-size: 11px; opacity: 0.8; line-height: 1.4;">Byte-packed wirefilter expressions neutralizing active plugin 0-days.</div>
                    </div>
                </div>

                <!-- Ban Queue & Origin Survival Controls Strip -->
                <div class="wcp-firewall-section-group" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <div style="font-size: 13px; font-weight: 700;">
                            <?php esc_html_e('Origin Survival Mode & Async Ban Queue', 'wcp-security-scanner'); ?>
                        </div>
                        <div style="font-size: 11.5px; opacity: 0.8; margin-top: 2px;">
                            <?php
                            /* translators: %d: pending queued IP count */
                            printf(esc_html__('Ban queue: %d pending IPs • Subnet aggregation active (/24 & /64)', 'wcp-security-scanner'), (int)($cf_status['pending_ban_queue_size'] ?? 0));
                            ?>
                        </div>
                    </div>

                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <button type="button" id="wcp-caf-sync-cf-btn" class="wcp-btn wcp-btn-secondary" style="font-size: 12px; padding: 6px 12px; cursor: pointer;">
                            ☁️ <?php esc_html_e('Sync Edge Now', 'wcp-security-scanner'); ?>
                        </button>
                        <button type="button" id="wcp-caf-circuit-breaker-btn" class="wcp-btn <?php echo !empty($cf_status['circuit_breaker_active']) ? 'wcp-btn-danger' : 'wcp-btn-secondary'; ?>" style="font-size: 12px; padding: 6px 12px; cursor: pointer;">
                            🚨 <?php echo !empty($cf_status['circuit_breaker_active']) ? esc_html__('De-escalate Survival Mode', 'wcp-security-scanner') : esc_html__('Trip Survival Mode', 'wcp-security-scanner'); ?>
                        </button>
                    </div>
                </div>
            </div>

            <!-- BEHAVIORAL INTELLIGENCE & STATELESS POW (PHASE 3) -->
            <div class="wcp-firewall-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--wcp-border, #e2e8f0); padding-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <h3 class="wcp-firewall-section-title" style="margin: 0 0 4px 0; font-size: 16px;">
                            🧠 <?php esc_html_e('Behavioral Intelligence & Proof-of-Work (Phase 3)', 'wcp-security-scanner'); ?>
                        </h3>
                        <p class="wcp-firewall-section-desc" style="margin: 0; font-size: 12.5px;">
                            <?php esc_html_e('Exponential threat score decay, WebCrypto SHA-256 client puzzles, and 5-bucket rate limiting.', 'wcp-security-scanner'); ?>
                        </p>
                    </div>
                    <span class="wcp-badge-clean" style="font-size: 11px;">
                        <?php esc_html_e('Active Velocity Tracking', 'wcp-security-scanner'); ?>
                    </span>
                </div>

                <!-- 5 Sliding-Window Velocity Buckets -->
                <div style="margin-bottom: 18px;">
                    <div style="font-size: 12px; font-weight: 700; margin-bottom: 8px; opacity: 0.9;">
                        <?php esc_html_e('5 Multi-Bucket Velocity Classification (WooCommerce Safe-Pass)', 'wcp-security-scanner'); ?>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px;">
                        <div class="wcp-firewall-inset-box" style="padding: 10px 12px;">
                            <strong style="display: block; font-size: 12px; margin-bottom: 2px;">Auth Bucket</strong>
                            <span style="font-size: 11px; opacity: 0.75;">wp-login & XML-RPC</span>
                        </div>
                        <div class="wcp-firewall-inset-box" style="padding: 10px 12px;">
                            <strong style="display: block; font-size: 12px; margin-bottom: 2px; color: #10b981;">Checkout Bucket</strong>
                            <span style="font-size: 11px; opacity: 0.75;">Carding defense</span>
                        </div>
                        <div class="wcp-firewall-inset-box" style="padding: 10px 12px;">
                            <strong style="display: block; font-size: 12px; margin-bottom: 2px; color: #0284c7;">Cart AJAX</strong>
                            <span style="font-size: 11px; opacity: 0.75;">Zero buyer friction</span>
                        </div>
                        <div class="wcp-firewall-inset-box" style="padding: 10px 12px;">
                            <strong style="display: block; font-size: 12px; margin-bottom: 2px; color: #7c3aed;">REST Write</strong>
                            <span style="font-size: 11px; opacity: 0.75;">POST /wp-json bounds</span>
                        </div>
                        <div class="wcp-firewall-inset-box" style="padding: 10px 12px;">
                            <strong style="display: block; font-size: 12px; margin-bottom: 2px; color: #ea580c;">Search Probe</strong>
                            <span style="font-size: 11px; opacity: 0.75;">Crawler DoS pacing</span>
                        </div>
                    </div>
                </div>

                <!-- Threat Score Escalation Policy & PoW Issue Strip -->
                <div class="wcp-firewall-section-group" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <div style="font-size: 13px; font-weight: 700;">
                            <?php esc_html_e('Tracked IP Escalation Levels', 'wcp-security-scanner'); ?>
                        </div>
                        <div style="font-size: 11.5px; opacity: 0.8; margin-top: 2px;">
                            <?php
                            /* translators: %1$d: elevated threat IP count, %2$d: PoW challenged count */
                            printf(esc_html__('%1$d IPs tracked • T ≥ 40 invokes WebCrypto PoW (%2$d active) • T ≥ 85 hard ban', 'wcp-security-scanner'), (int)($threat_summary['total_tracked_ips'] ?? 0), (int)($threat_summary['pow_challenges_active'] ?? 0));
                            ?>
                        </div>
                    </div>

                    <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                        <input type="text" id="wcp-caf-pow-ip" class="wcp-firewall-input" placeholder="IP Address..." style="width: 130px; padding: 4px 10px; font-size: 12px; height: 32px;" />
                        <button type="button" id="wcp-caf-toggle-pow-btn" class="wcp-btn wcp-btn-secondary" style="font-size: 12px; padding: 6px 12px; height: 32px; cursor: pointer;">
                            🧩 <?php esc_html_e('Issue PoW', 'wcp-security-scanner'); ?>
                        </button>
                    </div>
                </div>
            </div>

        </div>

    </div>

</div>

<!-- THEME CONTROLLER & INLINE ACTION LOGIC -->
<script type="text/javascript">
(function() {
    const rootUrl = '<?php echo esc_url($rest_url); ?>';
    const nonce   = '<?php echo esc_js($rest_nonce); ?>';

    // 1. Theme Synchronization (Matches main plugin theme stored in wcp_theme_mode)
    const rootContainer = document.getElementById('wcp-caf-root');
    const themeBtn      = document.getElementById('wcp-theme-toggle-btn');
    const themeIcon     = document.getElementById('wcp-theme-toggle-icon');
    const themeText     = document.getElementById('wcp-theme-toggle-text');

    function applyTheme(mode) {
        if (!rootContainer) return;
        if (mode === 'dark') {
            rootContainer.classList.remove('wcp-theme-light');
            rootContainer.classList.add('wcp-theme-dark');
            document.body.classList.remove('wcp-theme-light');
            document.body.classList.add('wcp-theme-dark');
            document.documentElement.setAttribute('data-theme', 'dark');
            if (themeIcon) themeIcon.innerText = '☀️';
            if (themeText) themeText.innerText = 'White Mode';
        } else {
            rootContainer.classList.remove('wcp-theme-dark');
            rootContainer.classList.add('wcp-theme-light');
            document.body.classList.remove('wcp-theme-dark');
            document.body.classList.add('wcp-theme-light');
            document.documentElement.setAttribute('data-theme', 'light');
            if (themeIcon) themeIcon.innerText = '🌙';
            if (themeText) themeText.innerText = 'Dark Mode';
        }
    }

    // Initialize theme from localStorage
    let currentTheme = 'light';
    try {
        const stored = localStorage.getItem('wcp_theme_mode');
        if (stored === 'dark' || stored === 'light') {
            currentTheme = stored;
        }
    } catch(e) {}
    applyTheme(currentTheme);

    if (themeBtn) {
        themeBtn.addEventListener('click', function() {
            currentTheme = (currentTheme === 'dark') ? 'light' : 'dark';
            try {
                localStorage.setItem('wcp_theme_mode', currentTheme);
            } catch(e) {}
            applyTheme(currentTheme);
        });
    }

    // 2. Notification Helper
    function showNotice(type, msg) {
        const box = document.getElementById('wcp-caf-notice');
        if (!box) return;
        box.style.display = 'block';
        box.style.background = (type === 'success') ? '#ecfdf5' : '#fef2f2';
        box.style.color = (type === 'success') ? '#047857' : '#dc2626';
        box.style.border = '1px solid ' + ((type === 'success') ? '#a7f3d0' : '#fecaca');
        box.innerText = msg;
        setTimeout(() => { box.style.display = 'none'; }, 6000);
    }

    // 3. Apply Protection Profile
    document.querySelectorAll('.wcp-apply-profile-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const pid = this.getAttribute('data-profile');
            this.disabled = true;
            this.innerText = 'Compiling...';

            fetch(rootUrl + '/caf/apply-profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': nonce },
                body: JSON.stringify({ profile_id: pid, lock_dormant_surface: true })
            })
            .then(r => r.json())
            .then(data => {
                if (data && data.success) {
                    showNotice('success', data.message || 'Profile applied and Micro-WAF recompiled!');
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    showNotice('error', data.message || 'Failed to apply profile.');
                    btn.disabled = false;
                    btn.innerText = 'Apply & Compile';
                }
            })
            .catch(err => {
                showNotice('error', err.message || 'Network error.');
                btn.disabled = false;
                btn.innerText = 'Apply & Compile';
            });
        });
    });

    // 4. Re-Profile Stack
    const reprofileBtn = document.getElementById('wcp-caf-reprofile-btn');
    if (reprofileBtn) {
        reprofileBtn.addEventListener('click', function() {
            this.disabled = true;
            this.innerText = 'Re-profiling...';
            fetch(rootUrl + '/caf/reprofile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': nonce }
            })
            .then(r => r.json())
            .then(data => {
                showNotice('success', 'Stack snapshot refreshed & CAF rules recompiled!');
                setTimeout(() => window.location.reload(), 1000);
            })
            .catch(err => {
                showNotice('error', err.message || 'Error refreshing stack.');
                this.disabled = false;
                this.innerText = '🔄 Re-Profile Stack';
            });
        });
    }

    // 5. Toggle Preload Killswitch
    const killswitchBtn = document.getElementById('wcp-caf-killswitch-btn');
    if (killswitchBtn) {
        killswitchBtn.addEventListener('click', function() {
            this.disabled = true;
            const isKilled = <?php echo $is_killed ? 'true' : 'false'; ?>;
            fetch(rootUrl + '/caf/killswitch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': nonce },
                body: JSON.stringify({ killswitch: !isKilled })
            })
            .then(r => r.json())
            .then(data => {
                showNotice('success', data.message || 'Killswitch state updated.');
                setTimeout(() => window.location.reload(), 1000);
            })
            .catch(err => {
                showNotice('error', err.message || 'Error toggling killswitch.');
                this.disabled = false;
            });
        });
    }

    // 6. Sync Cloudflare Edge
    const syncCfBtn = document.getElementById('wcp-caf-sync-cf-btn');
    if (syncCfBtn) {
        syncCfBtn.addEventListener('click', function() {
            this.disabled = true;
            this.innerText = 'Syncing...';
            fetch(rootUrl + '/caf/sync-cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': nonce }
            })
            .then(r => r.json())
            .then(data => {
                showNotice('success', data.message || 'Cloudflare edge synchronized!');
                setTimeout(() => window.location.reload(), 1200);
            })
            .catch(err => {
                showNotice('error', err.message || 'Error syncing Cloudflare.');
                this.disabled = false;
                this.innerText = '☁️ Sync Edge Now';
            });
        });
    }

    // 7. Toggle Origin Survival Mode
    const circuitBtn = document.getElementById('wcp-caf-circuit-breaker-btn');
    if (circuitBtn) {
        circuitBtn.addEventListener('click', function() {
            this.disabled = true;
            fetch(rootUrl + '/caf/toggle-circuit-breaker', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': nonce },
                body: JSON.stringify({ active: <?php echo !empty($cf_status['circuit_breaker_active']) ? 'false' : 'true'; ?> })
            })
            .then(r => r.json())
            .then(data => {
                showNotice('success', data.message || 'Survival mode updated.');
                setTimeout(() => window.location.reload(), 1000);
            })
            .catch(err => {
                showNotice('error', err.message || 'Error updating survival mode.');
                this.disabled = false;
            });
        });
    }

    // 8. Issue Proof-of-Work Challenge
    const powBtn = document.getElementById('wcp-caf-toggle-pow-btn');
    const powIpInput = document.getElementById('wcp-caf-pow-ip');
    if (powBtn && powIpInput) {
        powBtn.addEventListener('click', function() {
            const ip = powIpInput.value.trim();
            if (!ip) {
                alert('Please enter an IP address to issue a Proof-of-Work challenge.');
                return;
            }
            this.disabled = true;
            fetch(rootUrl + '/caf/toggle-pow-challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': nonce },
                body: JSON.stringify({ ip: ip, enable: true, reason: 'Administrator Cockpit Enforcement' })
            })
            .then(r => r.json())
            .then(data => {
                showNotice('success', data.message || 'PoW challenge enforced for ' + ip);
                powIpInput.value = '';
                this.disabled = false;
            })
            .catch(err => {
                showNotice('error', err.message || 'Error issuing PoW challenge.');
                this.disabled = false;
            });
        });
    }
})();
</script>
