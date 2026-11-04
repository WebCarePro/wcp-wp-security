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
 *
 * @package WcpScanner\Admin
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

// Cloudflare Status
$cf_status = \WcpScanner\Firewall\CAF\CloudflareSlotOptimizer::get_status();

// Threat Score & Behavioral Metrics
$threat_summary = \WcpScanner\Firewall\CAF\ThreatScoreTracker::get_threat_summary();

$rest_url = esc_url_raw(rest_url('wcp-scanner/v1'));
$rest_nonce = wp_create_nonce('wp_rest');
?>
<div class="wrap wcp-caf-standalone-wrap" style="max-width: 1300px; margin: 20px auto 40px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">

    <!-- TOP HERO BANNER -->
    <div style="background: linear-gradient(135deg, #090d16 0%, #0f172a 100%); border: 1px solid #1e293b; border-radius: 16px; padding: 28px 32px; color: #ffffff; margin-bottom: 24px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 20px;">
            <div style="max-width: 780px;">
                <div style="display: inline-flex; align-items: center; gap: 8px; padding: 4px 12px; border-radius: 999px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); color: #818cf8; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">
                    <span style="display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #10b981;"></span>
                    <?php esc_html_e('Next-Gen Adaptive Perimeter Security (CAF)', 'wcp-security-scanner'); ?>
                </div>
                <h1 style="font-size: 26px; font-weight: 800; color: #ffffff; margin: 0 0 8px 0; line-height: 1.2;">
                    <?php esc_html_e('Context-Adaptive Firewall (CAF) & StackGuard Cockpit', 'wcp-security-scanner'); ?>
                </h1>
                <p style="font-size: 14px; color: #94a3b8; line-height: 1.6; margin: 0;">
                    <?php esc_html_e('Deeply inspects active WordPress components, dormant attack surfaces, and visitor velocity to generate zero-friction edge rules and early pre-boot defense.', 'wcp-security-scanner'); ?>
                </p>
            </div>

            <!-- Action Buttons -->
            <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                <button type="button" id="wcp-caf-reprofile-btn" class="button" style="background: #1e293b; border: 1px solid #334155; color: #f1f5f9; padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;">
                    🔄 <?php esc_html_e('Re-Profile Stack', 'wcp-security-scanner'); ?>
                </button>
                <button type="button" id="wcp-caf-killswitch-btn" class="button" style="background: <?php echo $is_killed ? '#dc2626' : '#334155'; ?>; border: 1px solid <?php echo $is_killed ? '#b91c1c' : '#475569'; ?>; color: #ffffff; padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;">
                    ⚡ <?php echo $is_killed ? esc_html__('Preload Bypassed (Click to Enable)', 'wcp-security-scanner') : esc_html__('Preload WAF Active', 'wcp-security-scanner'); ?>
                </button>
            </div>
        </div>

        <!-- Notification Bar -->
        <div id="wcp-caf-notice" style="display: none; margin-top: 16px; padding: 10px 16px; border-radius: 8px; font-size: 13px; font-weight: 600;"></div>
    </div>

    <!-- 4 ANATOMY STAT CARDS -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px;">
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">
                <?php esc_html_e('WordPress & PHP Environment', 'wcp-security-scanner'); ?>
            </div>
            <div style="font-size: 18px; font-weight: 800; color: #0f172a;">
                WP v<?php echo esc_html($snapshot['wp_version'] ?? '7.x'); ?> • PHP <?php echo esc_html($snapshot['php_version'] ?? '8.x'); ?>
            </div>
            <div style="font-size: 12px; color: #475569; margin-top: 4px;">
                <?php
                /* translators: %1$d: active plugin count, %2$s: active theme slug */
                printf(esc_html__('%1$d Active Plugins • Theme: %2$s', 'wcp-security-scanner'), count($snapshot['active_plugins'] ?? []), esc_html($snapshot['active_themes']['active']['slug'] ?? 'Active'));
                ?>
            </div>
        </div>

        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">
                <?php esc_html_e('Dormant Attack Surface', 'wcp-security-scanner'); ?>
            </div>
            <div style="font-size: 18px; font-weight: 800; color: <?php echo !empty($recommendations['lock_dormant_surface']) ? '#10b981' : '#f59e0b'; ?>;">
                <?php echo esc_html((string)($recommendations['dormant_plugin_count'] ?? 0)); ?> <?php esc_html_e('Inactive Plugins', 'wcp-security-scanner'); ?>
            </div>
            <div style="font-size: 12px; color: #475569; margin-top: 4px;">
                <?php echo !empty($recommendations['lock_dormant_surface']) ? esc_html__('🔒 Locked down at early preload runtime', 'wcp-security-scanner') : esc_html__('⚠️ Direct plugin execution open', 'wcp-security-scanner'); ?>
            </div>
        </div>

        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">
                <?php esc_html_e('Conflict Avoidance Shields', 'wcp-security-scanner'); ?>
            </div>
            <div style="font-size: 18px; font-weight: 800; color: #0284c7;">
                <?php echo esc_html((string)count($recommendations['conflict_exemptions']['scoped_rules'] ?? [])); ?> <?php esc_html_e('Context Safe-Passes', 'wcp-security-scanner'); ?>
            </div>
            <div style="font-size: 12px; color: #475569; margin-top: 4px;">
                <?php esc_html_e('Zero false-positive e-commerce & builder saves', 'wcp-security-scanner'); ?>
            </div>
        </div>

        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">
                <?php esc_html_e('Residual Risk Posture', 'wcp-security-scanner'); ?>
            </div>
            <div style="font-size: 18px; font-weight: 800; color: <?php echo $risk_score > 50 ? '#ef4444' : '#10b981'; ?>;">
                <?php echo esc_html((string)$risk_score); ?> / 100
            </div>
            <div style="font-size: 12px; color: #475569; margin-top: 4px;">
                <?php echo $risk_score <= 20 ? esc_html__('Optimal Hardened Defense Posture', 'wcp-security-scanner') : esc_html__('Additional hardening recommended', 'wcp-security-scanner'); ?>
            </div>
        </div>
    </div>

    <!-- MAIN TWO-COLUMN SPLIT: PROFILES (LEFT) + CLOUDFLARE EDGE & BEHAVIORAL (RIGHT) -->
    <div style="display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(420px, 1.65fr); gap: 24px; align-items: start;">

        <!-- LEFT COLUMN: SMART PROTECTION PROFILES (PHASE 1) -->
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px;">
                <div>
                    <h2 style="font-size: 17px; font-weight: 800; color: #0f172a; margin: 0 0 4px 0;">
                        🛡️ <?php esc_html_e('Smart Protection Profiles (Phase 1)', 'wcp-security-scanner'); ?>
                    </h2>
                    <p style="font-size: 12.5px; color: #64748b; margin: 0;">
                        <?php esc_html_e('Compile tailored O(1) early-rejection rules matching your site archetype.', 'wcp-security-scanner'); ?>
                    </p>
                </div>
                <span style="font-size: 12px; color: #64748b;">
                    <?php esc_html_e('Auto-Detected:', 'wcp-security-scanner'); ?> <strong style="color: #4f46e5;"><?php echo esc_html($recommendations['recommended_profile'] ?? 'balanced'); ?></strong>
                </span>
            </div>

            <div style="display: flex; flex-direction: column; gap: 12px;">
                <?php foreach ($profiles as $p):
                    $is_current = ($active_profile === $p['id']);
                    $is_rec = (($recommendations['recommended_profile'] ?? '') === $p['id']);
                ?>
                <div style="border: <?php echo $is_current ? '2px solid #4f46e5' : '1px solid #e2e8f0'; ?>; border-radius: 10px; padding: 14px 16px; background: <?php echo $is_current ? '#f5f3ff' : '#ffffff'; ?>; display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: <?php echo esc_attr($p['color']); ?>;"></span>
                            <strong style="font-size: 14px; color: #0f172a;"><?php echo esc_html($p['name']); ?></strong>
                            <?php if ($is_rec): ?>
                                <span style="background: #ecfdf5; color: #047857; font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px; border: 1px solid #a7f3d0;">
                                    <?php esc_html_e('RECOMMENDED', 'wcp-security-scanner'); ?>
                                </span>
                            <?php endif; ?>
                        </div>
                        <span style="font-size: 11px; font-weight: 600; color: #64748b;"><?php echo esc_html($p['badge']); ?></span>
                    </div>

                    <p style="font-size: 12px; color: #475569; margin: 0; line-height: 1.4;">
                        <?php echo esc_html($p['desc']); ?>
                    </p>

                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; padding-top: 8px; border-top: 1px solid rgba(0,0,0,0.05);">
                        <span style="font-size: 11px; font-weight: 600; color: <?php echo $is_current ? '#4f46e5' : '#94a3b8'; ?>;">
                            <?php echo $is_current ? esc_html__('● Active Profile', 'wcp-security-scanner') : esc_html__('Inactive', 'wcp-security-scanner'); ?>
                        </span>
                        <button type="button" class="wcp-apply-profile-btn button" data-profile="<?php echo esc_attr($p['id']); ?>" <?php disabled($is_current); ?> style="font-size: 11px; padding: 3px 12px; height: 28px; line-height: 20px;">
                            <?php echo $is_current ? esc_html__('Active', 'wcp-security-scanner') : esc_html__('Apply & Compile', 'wcp-security-scanner'); ?>
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- RIGHT COLUMN: CLOUDFLARE EDGE (PHASE 2) & BEHAVIORAL COCKPIT (PHASE 3) -->
        <div style="display: flex; flex-direction: column; gap: 24px;">

            <!-- CLOUDFLARE FREE-PLAN EDGE DEFENSE (PHASE 2) -->
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px;">
                    <div>
                        <h2 style="font-size: 17px; font-weight: 800; color: #0f172a; margin: 0 0 4px 0;">
                            ☁️ <?php esc_html_e('Cloudflare Free-Plan 3-Slot Edge Offload (Phase 2)', 'wcp-security-scanner'); ?>
                        </h2>
                        <p style="font-size: 12.5px; color: #64748b; margin: 0;">
                            <?php esc_html_e('Stops scans and brute-force at the edge before hitting cPanel/PHP workers.', 'wcp-security-scanner'); ?>
                        </p>
                    </div>
                    <span style="padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; background: <?php echo !empty($cf_status['configured']) ? '#ecfdf5' : '#fef2f2'; ?>; color: <?php echo !empty($cf_status['configured']) ? '#047857' : '#dc2626'; ?>;">
                        <?php echo !empty($cf_status['configured']) ? esc_html__('● Connected', 'wcp-security-scanner') : esc_html__('○ Not Configured', 'wcp-security-scanner'); ?>
                    </span>
                </div>

                <!-- Slots Visualization -->
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px;">
                    <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #f8fafc;">
                        <div style="font-size: 11px; font-weight: 700; color: #dc2626; text-transform: uppercase;">Slot 1: Hard Drop</div>
                        <div style="font-size: 13px; font-weight: 700; color: #0f172a; margin: 4px 0;">Dormant & Attackers</div>
                        <div style="font-size: 11px; color: #64748b;">Instant HTTP 403 block for known scanners & bad subnets.</div>
                    </div>
                    <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #f8fafc;">
                        <div style="font-size: 11px; font-weight: 700; color: #d97706; text-transform: uppercase;">Slot 2: Challenge</div>
                        <div style="font-size: 13px; font-weight: 700; color: #0f172a; margin: 4px 0;">Bot & Brute Pacing</div>
                        <div style="font-size: 11px; color: #64748b;">Managed Challenge on wp-login & suspicious auth queries.</div>
                    </div>
                    <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #f8fafc;">
                        <div style="font-size: 11px; font-weight: 700; color: #4f46e5; text-transform: uppercase;">Slot 3: Virtual Patches</div>
                        <div style="font-size: 13px; font-weight: 700; color: #0f172a; margin: 4px 0;">0-Day Mitigation</div>
                        <div style="font-size: 11px; color: #64748b;">Wirefilter byte-packed rules blocking known CVE exploits.</div>
                    </div>
                </div>

                <!-- Async Ban Queue & Survival Mode Controls -->
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <div style="font-size: 13px; font-weight: 700; color: #0f172a;">
                            <?php esc_html_e('Origin Survival Mode & Async Ban Queue', 'wcp-security-scanner'); ?>
                        </div>
                        <div style="font-size: 11.5px; color: #64748b;">
                            <?php
                            /* translators: %d: pending queued IP count */
                            printf(esc_html__('Ban queue: %d pending IPs • Subnet aggregation active (/24 & /64)', 'wcp-security-scanner'), (int)($cf_status['pending_ban_queue_size'] ?? 0));
                            ?>
                        </div>
                    </div>

                    <div style="display: flex; gap: 8px;">
                        <button type="button" id="wcp-caf-sync-cf-btn" class="button" style="font-size: 12px;">
                            ☁️ <?php esc_html_e('Sync Edge Now', 'wcp-security-scanner'); ?>
                        </button>
                        <button type="button" id="wcp-caf-circuit-breaker-btn" class="button" style="font-size: 12px; background: <?php echo !empty($cf_status['circuit_breaker_active']) ? '#fef2f2' : '#ffffff'; ?>; color: <?php echo !empty($cf_status['circuit_breaker_active']) ? '#dc2626' : '#334155'; ?>;">
                            🚨 <?php echo !empty($cf_status['circuit_breaker_active']) ? esc_html__('De-escalate Survival Mode', 'wcp-security-scanner') : esc_html__('Trip Survival Mode', 'wcp-security-scanner'); ?>
                        </button>
                    </div>
                </div>
            </div>

            <!-- BEHAVIORAL INTELLIGENCE & STATELESS POW (PHASE 3) -->
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px;">
                    <div>
                        <h2 style="font-size: 17px; font-weight: 800; color: #0f172a; margin: 0 0 4px 0;">
                            🧠 <?php esc_html_e('Behavioral Intelligence & Proof-of-Work (Phase 3)', 'wcp-security-scanner'); ?>
                        </h2>
                        <p style="font-size: 12.5px; color: #64748b; margin: 0;">
                            <?php esc_html_e('Exponential threat score decay, WebCrypto SHA-256 client puzzles, and 5-bucket rate limiting.', 'wcp-security-scanner'); ?>
                        </p>
                    </div>
                    <span style="font-size: 11px; font-weight: 700; color: #10b981; background: #ecfdf5; padding: 3px 8px; border-radius: 4px;">
                        <?php esc_html_e('Active Velocity Tracking', 'wcp-security-scanner'); ?>
                    </span>
                </div>

                <!-- 5 Sliding-Window Velocity Buckets -->
                <div style="margin-bottom: 18px;">
                    <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 8px;">
                        <?php esc_html_e('5 Multi-Bucket Velocity Classification (WooCommerce Safe-Pass)', 'wcp-security-scanner'); ?>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px;">
                        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 11px;">
                            <strong style="display: block; color: #0f172a;">Auth Bucket</strong>
                            <span style="color: #64748b;">wp-login & XML-RPC</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 11px;">
                            <strong style="display: block; color: #10b981;">Checkout Bucket</strong>
                            <span style="color: #64748b;">Carding prevention</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 11px;">
                            <strong style="display: block; color: #0284c7;">Cart AJAX</strong>
                            <span style="color: #64748b;">Zero buyer friction</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 11px;">
                            <strong style="display: block; color: #7c3aed;">REST Write</strong>
                            <span style="color: #64748b;">POST /wp-json abuse</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 11px;">
                            <strong style="display: block; color: #ea580c;">Search Probe</strong>
                            <span style="color: #64748b;">Crawler DoS bounds</span>
                        </div>
                    </div>
                </div>

                <!-- Proof-of-Work & Threat Score Escalation Summary -->
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <div style="font-size: 13px; font-weight: 700; color: #0f172a;">
                            <?php esc_html_e('Tracked IP Escalation Levels', 'wcp-security-scanner'); ?>
                        </div>
                        <div style="font-size: 11.5px; color: #64748b;">
                            <?php
                            /* translators: %1$d: elevated threat IP count, %2$d: PoW challenged count */
                            printf(esc_html__('%1$d IPs tracked • T ≥ 40 invokes WebCrypto PoW (%2$d challenged) • T ≥ 85 hard ban', 'wcp-security-scanner'), (int)($threat_summary['total_tracked_ips'] ?? 0), (int)($threat_summary['pow_challenges_active'] ?? 0));
                            ?>
                        </div>
                    </div>

                    <div style="display: flex; gap: 8px; align-items: center;">
                        <input type="text" id="wcp-caf-pow-ip" placeholder="Target IP..." style="height: 28px; font-size: 12px; padding: 2px 8px; width: 120px;" />
                        <button type="button" id="wcp-caf-toggle-pow-btn" class="button" style="font-size: 12px;">
                            🧩 <?php esc_html_e('Issue PoW', 'wcp-security-scanner'); ?>
                        </button>
                    </div>
                </div>
            </div>

        </div>

    </div>

</div>

<!-- INLINE CONTROLLER JAVASCRIPT FOR DYNAMIC ACTIONS -->
<script type="text/javascript">
(function() {
    const rootUrl = '<?php echo esc_url($rest_url); ?>';
    const nonce   = '<?php echo esc_js($rest_nonce); ?>';

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

    // Apply Profile
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
                    showNotice('success', data.message || 'Profile applied and WAF recompiled!');
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

    // Re-Profile Stack
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

    // Toggle Killswitch
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

    // Sync Cloudflare
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

    // Toggle Circuit Breaker
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

    // Issue PoW
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
