import React, { useState, useEffect } from 'react';
import {
  Cloud,
  Cpu,
  Zap,
  Activity,
  Layers,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Loader2,
  AlertTriangle,
  Lock,
  ArrowRight,
  Database
} from 'lucide-react';

interface CloudflareStatusResponse {
  configured: boolean;
  zone_id: string;
  token_scope: 'account' | 'zone' | 'none';
  slot_usage: {
    total_quota: number;
    user_rules: number;
    wcp_rules: number;
    available_slots: number;
    free_unallocated: number;
  };
  existing_rules: Array<{
    id: string;
    description: string;
    action: string;
    enabled: boolean;
    bytes: number;
    is_wcp: boolean;
  }>;
  pending_ban_queue_size: number;
  circuit_breaker: {
    active: boolean;
    engaged_at: number | null;
    reason: string;
    escalation: string;
    stress: {
      cpu_load: number;
      cpu_threshold: number;
      probe_velocity_per_min: number;
      velocity_threshold: number;
      is_stressed: boolean;
      memory_usage_bytes?: number;
    };
    auto_managed: boolean;
  };
}

interface CloudflareSlotVisualizerProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const CloudflareSlotVisualizer: React.FC<CloudflareSlotVisualizerProps> = ({ apiRequest }) => {
  const [data, setData] = useState<CloudflareStatusResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [togglingSurvival, setTogglingSurvival] = useState(false);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({ path: '/caf/cloudflare-status', method: 'GET' });
      setData(res);
    } catch (err: any) {
      console.error('Failed to fetch Cloudflare CAF status', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleSyncNow = async () => {
    setSyncing(true);
    setNotice(null);
    try {
      const res = await apiRequest({ path: '/caf/sync-cloudflare', method: 'POST' });
      if (res.success) {
        setNotice({ type: 'success', message: res.message || 'Cloudflare Edge synchronized successfully.' });
        fetchStatus();
      } else {
        setNotice({ type: 'error', message: res.message || 'Failed to sync Cloudflare Edge.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Synchronization failed.' });
    } finally {
      setSyncing(false);
    }
  };

  const handleToggleSurvival = async (enable: boolean) => {
    setTogglingSurvival(true);
    setNotice(null);
    try {
      const res = await apiRequest({
        path: '/caf/toggle-circuit-breaker',
        method: 'POST',
        data: {
          enable,
          reason: enable ? 'Administrator Manual Origin Survival Trigger' : 'Administrator Reset'
        }
      });
      if (res.success) {
        setNotice({ type: 'success', message: res.message });
        fetchStatus();
      } else {
        setNotice({ type: 'error', message: res.message || 'Action failed.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Failed to update Origin Survival mode.' });
    } finally {
      setTogglingSurvival(false);
    }
  };

  if (!data?.configured) {
    return null; // Only render when Cloudflare is configured
  }

  const { slot_usage, token_scope, pending_ban_queue_size, circuit_breaker } = data;
  const totalSlots = 5;
  const userSlots = slot_usage?.user_rules || 0;
  const wcpSlots = slot_usage?.wcp_rules || 0;
  const unallocatedSlots = Math.max(0, totalSlots - (userSlots + wcpSlots));

  const slotsArray = [];
  for (let i = 0; i < userSlots; i++) {
    slotsArray.push({ type: 'user', label: 'User Custom Rule', color: '#64748b' });
  }
  for (let i = 0; i < wcpSlots; i++) {
    slotsArray.push({ type: 'wcp', label: `WCP Slot #${i + 1}`, color: '#ea580c' });
  }
  for (let i = 0; i < unallocatedSlots; i++) {
    slotsArray.push({ type: 'free', label: 'Free Slot', color: '#10b981' });
  }

  const stress = circuit_breaker?.stress;
  const isSurvivalActive = !!circuit_breaker?.active;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
      {/* Top Banner Notice */}
      {notice && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: notice.type === 'success' ? '#ecfdf5' : '#fef2f2',
            border: notice.type === 'success' ? '1px solid #a7f3d0' : '1px solid #fecaca',
            color: notice.type === 'success' ? '#065f46' : '#991b1b',
          }}
        >
          <span>{notice.message}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '14px', color: 'inherit' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Cloudflare Free-Plan 5-Slot Optimizer Visualizer Card */}
      <div className="wcp-firewall-section-group" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Layers size={18} color="#ea580c" />
              <h4 className="wcp-firewall-section-title" style={{ margin: 0, fontSize: '16px' }}>
                Cloudflare Free-Plan 5-Slot Optimizer (CAF Phase 2)
              </h4>
              <span className="wcp-badge-pill" style={{ background: 'rgba(234, 88, 12, 0.1)', color: '#ea580c', border: '1px solid rgba(234, 88, 12, 0.3)' }}>
                Wirefilter &lt; 4,000 Bytes
              </span>
            </div>
            <p className="wcp-firewall-section-desc" style={{ marginTop: '4px', marginBottom: 0 }}>
              Non-destructive rule packer. Automatically reserves your custom Cloudflare rules while claiming up to 3 slots for Dormant Lockdown, Managed Challenges, and StackGuard Virtual Patches.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              type="button"
              className="wcp-btn"
              onClick={handleSyncNow}
              disabled={syncing || loading}
              style={{
                background: '#ea580c',
                color: '#fff',
                border: 'none',
                padding: '7px 16px',
                fontSize: '12px',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                borderRadius: '6px',
                cursor: (syncing || loading) ? 'not-allowed' : 'pointer'
              }}
            >
              {syncing ? <Loader2 size={13} className="wcp-spin" /> : <RefreshCw size={13} />}
              Sync Slots &amp; Ban Queue Now
            </button>
          </div>
        </div>

        {/* 5-Slot Visual Bar */}
        <div style={{ marginBottom: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '8px', color: 'var(--wcp-text-muted, #64748b)' }}>
            <span>
              <strong>{userSlots}</strong> User Defined • <strong>{wcpSlots}</strong> WCP Managed • <strong>{unallocatedSlots}</strong> Available
            </span>
            <span>
              API Token Scope:{' '}
              <strong style={{ color: token_scope === 'account' ? '#10b981' : token_scope === 'zone' ? '#38bdf8' : '#ef4444' }}>
                {token_scope === 'account' ? 'Account Custom Lists (10,000 items)' : token_scope === 'zone' ? 'Zone Access Rules (Fallback)' : 'Unverified'}
              </strong>
            </span>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(5, 1fr)',
              gap: '8px',
              background: 'var(--wcp-bg-deep, #090d16)',
              padding: '8px',
              borderRadius: '8px',
              border: '1px solid var(--wcp-border-standard, #1e293b)'
            }}
          >
            {slotsArray.map((slot, idx) => (
              <div
                key={idx}
                style={{
                  background: slot.type === 'wcp' ? 'rgba(234, 88, 12, 0.16)' : slot.type === 'user' ? 'rgba(100, 116, 139, 0.16)' : 'rgba(16, 185, 129, 0.16)',
                  border: `1px solid ${slot.type === 'wcp' ? 'rgba(234, 88, 12, 0.4)' : slot.type === 'user' ? 'rgba(100, 116, 139, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
                  borderRadius: '6px',
                  padding: '10px 12px',
                  textAlign: 'center'
                }}
              >
                <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: slot.color, fontWeight: 700 }}>
                  Slot #{idx + 1}
                </div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginTop: '2px' }}>
                  {slot.label}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Expression Byte Breakdown Table */}
        {data.existing_rules && data.existing_rules.length > 0 && (
          <div style={{ overflowX: 'auto' }}>
            <table className="wcp-waf-table" style={{ width: '100%', fontSize: '12px' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '8px 12px' }}>Rule Description</th>
                  <th style={{ textAlign: 'center', padding: '8px 12px', width: '120px' }}>Action</th>
                  <th style={{ textAlign: 'center', padding: '8px 12px', width: '120px' }}>Expression Size</th>
                  <th style={{ textAlign: 'center', padding: '8px 12px', width: '100px' }}>Type</th>
                </tr>
              </thead>
              <tbody>
                {data.existing_rules.map((rule, idx) => (
                  <tr key={idx}>
                    <td style={{ padding: '8px 12px' }}>
                      <strong>{rule.description}</strong>
                    </td>
                    <td style={{ textAlign: 'center', padding: '8px 12px' }}>
                      <span className={`wcp-badge-pill ${rule.action === 'block' ? 'wcp-badge-danger' : 'wcp-badge-warning'}`}>
                        {rule.action}
                      </span>
                    </td>
                    <td style={{ textAlign: 'center', padding: '8px 12px' }}>
                      <span style={{ color: rule.bytes > 3800 ? '#ea580c' : 'inherit' }}>
                        {rule.bytes} / 4,000 B
                      </span>
                    </td>
                    <td style={{ textAlign: 'center', padding: '8px 12px' }}>
                      <span className={rule.is_wcp ? 'wcp-badge-pill wcp-badge-info' : 'wcp-badge-pill'}>
                        {rule.is_wcp ? 'WCP' : 'User'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Origin Survival Mode (Circuit Breaker) Card */}
      <div className="wcp-firewall-section-group" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Cpu size={18} color={isSurvivalActive ? '#ef4444' : '#10b981'} />
              <h4 className="wcp-firewall-section-title" style={{ margin: 0, fontSize: '16px' }}>
                Origin Survival Mode (cPanel &amp; Shared Hosting Circuit Breaker)
              </h4>
              <span
                className={`wcp-badge-pill ${isSurvivalActive ? 'wcp-badge-danger' : 'wcp-badge-clean'}`}
                style={{ fontWeight: 700 }}
              >
                {isSurvivalActive ? 'SURVIVAL MODE ENGAGED' : 'NORMAL BASELINE'}
              </span>
            </div>
            <p className="wcp-firewall-section-desc" style={{ marginTop: '4px', marginBottom: 0 }}>
              Protects shared hosting and cPanel accounts against 508 Resource Limit crashes. Automatically offloads CPU load to Cloudflare Edge during bot surges or DDoS attacks.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              type="button"
              className="wcp-btn"
              onClick={() => handleToggleSurvival(!isSurvivalActive)}
              disabled={togglingSurvival}
              style={{
                background: isSurvivalActive ? '#10b981' : '#dc2626',
                color: '#fff',
                border: 'none',
                padding: '7px 16px',
                fontSize: '12px',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                borderRadius: '6px',
                cursor: togglingSurvival ? 'not-allowed' : 'pointer'
              }}
            >
              {togglingSurvival ? <Loader2 size={13} className="wcp-spin" /> : isSurvivalActive ? <ShieldCheck size={13} /> : <ShieldAlert size={13} />}
              {isSurvivalActive ? 'Disengage Survival Mode' : 'Test / Force Survival Mode'}
            </button>
          </div>
        </div>

        {/* Live Telemetry Indicators */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginTop: '12px' }}>
          <div className="wcp-firewall-inset-box" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--wcp-text-muted, #64748b)' }}>
              Origin CPU Load (1m Avg)
            </div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: (stress?.cpu_load || 0) >= (stress?.cpu_threshold || 4.0) ? '#ef4444' : 'var(--wcp-text-primary, #0f172a)', marginTop: '4px' }}>
              {stress?.cpu_load ?? '0.00'} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>/ {stress?.cpu_threshold ?? 4.0} limit</span>
            </div>
          </div>

          <div className="wcp-firewall-inset-box" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--wcp-text-muted, #64748b)' }}>
              Probe Velocity (403/404)
            </div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: (stress?.probe_velocity_per_min || 0) >= (stress?.velocity_threshold || 120) ? '#ef4444' : 'var(--wcp-text-primary, #0f172a)', marginTop: '4px' }}>
              {stress?.probe_velocity_per_min ?? 0} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>req / min</span>
            </div>
          </div>

          <div className="wcp-firewall-inset-box" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--wcp-text-muted, #64748b)' }}>
              Async Ban Queue Size
            </div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: pending_ban_queue_size > 0 ? '#ea580c' : 'var(--wcp-text-primary, #0f172a)', marginTop: '4px' }}>
              {pending_ban_queue_size} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>pending /24 merge</span>
            </div>
          </div>
        </div>

        {isSurvivalActive && (
          <div style={{ marginTop: '14px', padding: '12px 16px', borderRadius: '6px', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#ef4444', fontSize: '12px' }}>
            <strong>Active Escalation:</strong> Cloudflare Edge is currently challenging unauthenticated queries, aggressive search scraping, and login routes. Automatic deescalation will trigger once origin load remains under normal thresholds for 10 consecutive minutes.
          </div>
        )}
      </div>
    </div>
  );
};
