import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  ShieldCheck,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Loader2,
  Info,
  ChevronRight,
  Layers,
  ShoppingBag,
  FileText,
  Lock,
  Cpu,
  RefreshCw,
  Power
} from 'lucide-react';

interface CafAdvisorPanelProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onSettingsUpdated?: () => void;
}

export const CafAdvisorPanel: React.FC<CafAdvisorPanelProps> = ({ apiRequest, onSettingsUpdated }) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [applyingProfile, setApplyingProfile] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [togglingKillswitch, setTogglingKillswitch] = useState<boolean>(false);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string; autoEnabled?: string[] } | null>(null);

  const loadCafOverview = async () => {
    try {
      setLoading(true);
      const res = await apiRequest({ path: '/caf/overview', method: 'GET' });
      if (res && res.success) {
        setData(res);
      }
    } catch (err: any) {
      console.error('Failed to load CAF overview:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCafOverview();
  }, []);

  const handleApplyProfile = async (profileId: string) => {
    try {
      setApplyingProfile(profileId);
      setNotice(null);
      const res = await apiRequest({
        path: '/caf/apply-profile',
        method: 'POST',
        data: { profile_id: profileId, lock_dormant_surface: true }
      });

      if (res && res.success) {
        const autoEnabled: string[] = res.auto_enabled || [];
        let msg = res.message || `Profile "${profileId}" applied and WAF recompiled!`;
        if (autoEnabled.length > 0) {
          msg += ` Auto-enabled: ${autoEnabled.join(', ')}.`;
        }
        setNotice({
          type: 'success',
          message: msg,
          autoEnabled,
        });
        await loadCafOverview();
        if (onSettingsUpdated) {
          onSettingsUpdated();
        }
      } else {
        setNotice({ type: 'error', message: res?.message || 'Failed to apply CAF profile.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Error communicating with CAF API.' });
    } finally {
      setApplyingProfile(null);
    }
  };

  const handleReprofile = async () => {
    try {
      setRefreshing(true);
      setNotice(null);
      const res = await apiRequest({ path: '/caf/reprofile', method: 'POST' });
      if (res && res.success) {
        setNotice({ type: 'success', message: 'Stack snapshot refreshed & CAF rules recompiled!' });
        await loadCafOverview();
        if (onSettingsUpdated) {
          onSettingsUpdated();
        }
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Error refreshing stack.' });
    } finally {
      setRefreshing(false);
    }
  };

  const handleToggleKillswitch = async () => {
    try {
      setTogglingKillswitch(true);
      setNotice(null);
      const newState = !data?.is_killswitch_active;
      const res = await apiRequest({
        path: '/caf/killswitch',
        method: 'POST',
        data: { killswitch: newState }
      });
      if (res && res.success) {
        setNotice({ type: 'success', message: res.message });
        await loadCafOverview();
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Error toggling killswitch.' });
    } finally {
      setTogglingKillswitch(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="webcare-card webcare-firewall-card" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Loader2 className="webcare-spin" size={20} color="#0284c7" />
        <span style={{ fontSize: '14px', color: 'var(--webcare-text-secondary, #475569)' }}>Analyzing WordPress stack anatomy &amp; CAF Advisor...</span>
      </div>
    );
  }

  const snapshot = data?.snapshot || {};
  const recs = data?.recommendations || {};
  const activeProfile = data?.active_profile || 'balanced';
  const riskScore = data?.residual_risk_score ?? 10;
  const isKilled = !!data?.is_killswitch_active;

  const profiles = [
    {
      id: 'ecommerce_hardened',
      name: 'E-Commerce Hardened',
      icon: <ShoppingBag size={18} color="#10b981" />,
      desc: 'WooCommerce, EDD & SureCart. Zero checkout friction, serialized cart fragment safe-pass, and strict login brute-force defense.',
    },
    {
      id: 'corporate_brochure',
      name: 'Corporate / Brochure',
      icon: <FileText size={18} color="#0284c7" />,
      desc: 'Elementor, Divi & Contact Forms. Relaxed page-builder styling saves for authenticated editors; blocks external probe vectors.',
    },
    {
      id: 'membership_lms',
      name: 'Membership & LMS',
      icon: <Layers size={18} color="#8b5cf6" />,
      desc: 'MemberPress, LearnDash & BuddyBoss. Anti-credential stuffing, concurrent session armor, and high video/progress throughput.',
    },
    {
      id: 'cpanel_shared_saver',
      name: 'cPanel / Shared Saver',
      icon: <Cpu size={18} color="#f59e0b" />,
      desc: 'Low-resource / CloudLinux LVE hosting. Minimizes PHP worker wakeups with ultra-lean fast-path preload execution.',
    },
    {
      id: 'high_security_paranoid',
      name: 'High-Security / Paranoid',
      icon: <Lock size={18} color="#ef4444" />,
      desc: 'Zero-trust defense mode. Enforces strict zero-tolerance perimeter filters, early honeytokens, and aggressive probe lockouts.',
    },
    {
      id: 'balanced',
      name: 'Balanced (Default)',
      icon: <ShieldCheck size={18} color="#6366f1" />,
      desc: 'Adaptive default profile. Standard brute-force filters, crawler verification, and automatic virtual patch compilation.',
    },
  ];

  return (
    <div className="webcare-card webcare-firewall-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', borderBottom: '1px solid var(--webcare-border, #e2e8f0)', paddingBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ display: 'inline-flex', padding: '6px', borderRadius: '8px', background: 'rgba(2, 132, 199, 0.1)', color: '#0284c7' }}>
              <Sparkles size={20} />
            </span>
            <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)' }}>
              Context-Adaptive Firewall (CAF) &amp; StackGuard Engine
            </h3>
            <span className="webcare-badge-pill webcare-badge-info" style={{ fontSize: '11px', textTransform: 'uppercase' }}>
              Phase 1 Active
            </span>
          </div>
          <p style={{ margin: '6px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
            Deeply inspects installed plugins, themes, and REST routes to synthesize hyper-tailored, zero-friction firewall rules.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            type="button"
            className="webcare-btn webcare-btn-secondary"
            onClick={handleReprofile}
            disabled={refreshing}
            style={{ fontSize: '12px', padding: '6px 12px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={14} className={refreshing ? 'webcare-spin' : ''} />
            {refreshing ? 'Re-profiling...' : 'Re-Profile Stack'}
          </button>

          <button
            type="button"
            className={`webcare-btn ${isKilled ? 'webcare-btn-danger' : 'webcare-btn-secondary'}`}
            onClick={handleToggleKillswitch}
            disabled={togglingKillswitch}
            title={isKilled ? 'Preload WAF is bypassed. Click to reactivate.' : 'Emergency Killswitch: Bypass preload WAF instantly.'}
            style={{ fontSize: '12px', padding: '6px 12px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Power size={14} />
            {isKilled ? 'Preload Bypassed (Click to Enable)' : 'Preload Active'}
          </button>
        </div>
      </div>

      {notice && (
        <div
          className={`webcare-alert ${notice.type === 'success' ? 'webcare-alert-success' : 'webcare-alert-danger'}`}
          style={{ padding: '10px 14px', borderRadius: '6px', fontSize: '13px' }}
        >
          <div style={{ fontWeight: 600, marginBottom: (notice as any).autoEnabled?.length > 0 ? '6px' : 0 }}>
            {notice.message.split(' Auto-enabled:')[0]}
          </div>
          {(notice as any).autoEnabled?.length > 0 && (
            <div style={{ marginTop: '6px', padding: '8px 10px', background: 'rgba(16, 185, 129, 0.08)', borderRadius: '5px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#059669', textTransform: 'uppercase', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                <CheckCircle2 size={12} /> Auto-Enabled on Firewall Rules &amp; Controls:
              </div>
              <ul style={{ margin: '0', padding: '0 0 0 16px', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                {(notice as any).autoEnabled.map((item: string, idx: number) => (
                  <li key={idx} style={{ marginBottom: '2px' }}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Anatomy Summary Cockpit */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div className="webcare-firewall-rule-card" style={{ padding: '14px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>WordPress &amp; PHP Stack</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)', marginTop: '4px' }}>
            WP v{snapshot.wp_version || '7.1'} • PHP {snapshot.php_version || '8.3'}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
            {Object.keys(snapshot.active_plugins || {}).length} Active Plugins • Theme: {snapshot.active_themes?.active?.slug || 'Active'}
          </div>
        </div>

        <div className="webcare-firewall-rule-card" style={{ padding: '14px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Dormant Attack Surface</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: recs.lock_dormant_surface ? '#10b981' : '#f59e0b', marginTop: '4px' }}>
            {recs.dormant_plugin_count || 0} Deactivated Plugins
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
            {recs.lock_dormant_surface ? '🔒 Locked down at WAF layer' : '⚠️ Unprotected direct access'}
          </div>
        </div>

        <div className="webcare-firewall-rule-card" style={{ padding: '14px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Conflict Avoidance Shields</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#0284c7', marginTop: '4px' }}>
            {recs.conflict_exemptions?.scoped_rules?.length || 0} Context Safe-Passes
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
            Zero false-positive e-commerce &amp; builder saves
          </div>
        </div>

        <div className="webcare-firewall-rule-card" style={{ padding: '14px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase' }}>Residual Risk Score</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: riskScore > 50 ? '#ef4444' : '#10b981', marginTop: '4px' }}>
            {riskScore} / 100
          </div>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
            {riskScore <= 20 ? 'Optimal Protection Posture' : 'Hardening recommended'}
          </div>
        </div>
      </div>

      {/* Smart Protection Profiles */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-heading, #0f172a)' }}>
            Smart Protection Profiles
          </h4>
          <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
            Recommended: <strong style={{ color: '#0284c7' }}>{profiles.find(p => p.id === recs.recommended_profile)?.name || 'E-Commerce Hardened'}</strong>
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
          {profiles.map((p) => {
            const isCurrent = activeProfile === p.id;
            const isRec = recs.recommended_profile === p.id;
            const isApplying = applyingProfile === p.id;

            return (
              <div
                key={p.id}
                className="webcare-firewall-rule-card"
                style={{
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  border: isCurrent ? '2px solid #0284c7' : '1px solid var(--webcare-border, #e2e8f0)',
                  background: isCurrent ? 'var(--webcare-bg-surface-elevated, rgba(2, 132, 199, 0.04))' : undefined
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {p.icon}
                      <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--webcare-text-heading, #0f172a)' }}>
                        {p.name}
                      </span>
                    </div>
                    {isRec && (
                      <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px' }}>
                        Recommended
                      </span>
                    )}
                  </div>
                  <p style={{ margin: '8px 0 14px', fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4 }}>
                    {p.desc}
                  </p>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--webcare-border, #e2e8f0)', paddingTop: '10px', marginTop: 'auto' }}>
                  <span style={{ fontSize: '11px', fontWeight: 600, color: isCurrent ? '#0284c7' : 'var(--webcare-text-muted, #64748b)' }}>
                    {isCurrent ? '● Active Profile' : 'Inactive'}
                  </span>

                  <button
                    type="button"
                    className={`webcare-btn ${isCurrent ? 'webcare-btn-secondary' : 'webcare-btn-primary'}`}
                    disabled={isCurrent || isApplying}
                    onClick={() => handleApplyProfile(p.id)}
                    style={{ fontSize: '11px', padding: '4px 10px', borderRadius: '4px' }}
                  >
                    {isApplying ? 'Compiling...' : isCurrent ? 'Applied' : 'Apply & Compile'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
