import React, { useState, useEffect } from 'react';
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Lock,
  Cpu,
  RefreshCw,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Search,
  ShoppingBag,
  Key,
  Globe
} from 'lucide-react';

interface BehavioralStatusResponse {
  rate_limiter: {
    settings: {
      enabled: boolean;
      limit_auth: number;
      window_auth: number;
      limit_checkout: number;
      window_checkout: number;
      limit_search: number;
      window_search: number;
      limit_api: number;
      window_api: number;
      limit_global: number;
      window_global: number;
      retry_after_seconds: number;
      escalate_to_ban: boolean;
    };
    total_throttled: number;
    total_throttled_requests: number;
    active_tracked_ips: number;
    by_bucket: {
      auth: number;
      checkout: number;
      search: number;
      api: number;
      global: number;
    };
  };
  learning_observations: Array<{
    id: string;
    rule_id: string;
    rule_name: string;
    rule_category: string;
    ip: string;
    method: string;
    uri: string;
    clean_route: string;
    payload_sample: string;
    is_logged_in: boolean;
    observed_at: number;
    status: string;
  }>;
  observation_count: number;
  synthesized_exemptions: Array<{
    id: string;
    source_id: string;
    route: string;
    rule_id: string;
    rule_category: string;
    param_key: string;
    capability: string;
    description: string;
    created_at: number;
    status: string;
  }>;
  exemption_count: number;
  pow_enforced_ips: Array<{
    ip: string;
    enforced_at: number;
    reason: string;
  }>;
}

interface CafBehavioralCockpitProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const CafBehavioralCockpit: React.FC<CafBehavioralCockpitProps> = ({ apiRequest }) => {
  const [data, setData] = useState<BehavioralStatusResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [synthesizingId, setSynthesizingId] = useState<string | null>(null);
  const [powIpInput, setPowIpInput] = useState('');
  const [togglingPow, setTogglingPow] = useState(false);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({ path: '/caf/behavioral-status', method: 'GET' });
      setData(res);
    } catch (err: any) {
      console.error('Failed to fetch CAF behavioral status', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleSynthesizeExemption = async (findingId: string) => {
    setSynthesizingId(findingId);
    setNotice(null);
    try {
      const res = await apiRequest({
        path: '/caf/create-exemption',
        method: 'POST',
        data: { finding_id: findingId }
      });
      if (res.success) {
        setNotice({ type: 'success', message: res.message });
        fetchStatus();
      } else {
        setNotice({ type: 'error', message: res.message || 'Failed to synthesize exemption.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Error communicating with exemption API.' });
    } finally {
      setSynthesizingId(null);
    }
  };

  const handleTogglePow = async (ip: string, enable: boolean) => {
    setTogglingPow(true);
    setNotice(null);
    try {
      const res = await apiRequest({
        path: '/caf/toggle-pow-challenge',
        method: 'POST',
        data: { ip, enable, reason: 'Administrator Cockpit Enforcement' }
      });
      if (res.success) {
        setNotice({ type: 'success', message: res.message });
        if (enable) setPowIpInput('');
        fetchStatus();
      } else {
        setNotice({ type: 'error', message: res.message || 'Action failed.' });
      }
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Error toggling PoW challenge.' });
    } finally {
      setTogglingPow(false);
    }
  };

  if (loading && !data) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '24px', justifyContent: 'center' }}>
        <Loader2 size={18} className="wcp-spin" />
        <span style={{ fontSize: '13px', color: 'var(--wcp-text-muted, #64748b)' }}>Loading Behavioral Intelligence Engine...</span>
      </div>
    );
  }

  const rl = data?.rate_limiter;
  const buckets = rl?.by_bucket || { auth: 0, checkout: 0, search: 0, api: 0, global: 0 };
  const settings = rl?.settings;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', marginBottom: '24px' }}>
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

      {/* 4 Action-Type Velocity Buckets Grid */}
      <div className="wcp-firewall-section-group" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Zap size={18} color="#4f46e5" />
              <h4 className="wcp-firewall-section-title" style={{ margin: 0, fontSize: '16px' }}>
                Multi-Bucket Stateful Velocity Monitor (CAF Phase 3)
              </h4>
              <span className="wcp-badge-pill wcp-badge-clean">
                Sliding-Window Non-Locking
              </span>
            </div>
            <p className="wcp-firewall-section-desc" style={{ marginTop: '4px', marginBottom: 0 }}>
              Independent token budgets tailored for authentication, e-commerce checkout, search queries, and standard REST requests.
            </p>
          </div>

          <button
            type="button"
            className="wcp-btn wcp-firewall-rule-card"
            onClick={fetchStatus}
            disabled={loading}
            style={{
              padding: '6px 14px',
              fontSize: '12px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            {loading ? <Loader2 size={13} className="wcp-spin" /> : <RefreshCw size={13} />}
            Refresh Velocity
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '12px' }}>
          {/* Auth Bucket */}
          <div className="wcp-firewall-inset-box" style={{ padding: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', color: '#ea580c' }}>
                <Key size={14} /> Authentication
              </span>
              <span className="wcp-badge-pill" style={{ fontSize: '11px' }}>
                {settings?.limit_auth || 5} req / {settings?.window_auth ? `${settings.window_auth}s` : '5m'}
              </span>
            </div>
            <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
              {buckets.auth} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>throttles today</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '4px' }}>
              Protects wp-login.php, xmlrpc.php, and jwt-auth
            </div>
          </div>

          {/* Checkout Bucket */}
          <div className="wcp-firewall-inset-box" style={{ padding: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
                <ShoppingBag size={14} /> E-Commerce Checkout
              </span>
              <span className="wcp-badge-pill" style={{ fontSize: '11px' }}>
                {settings?.limit_checkout || 8} req / min
              </span>
            </div>
            <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
              {buckets.checkout} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>throttles today</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '4px' }}>
              Structured JSON errors to protect active carts
            </div>
          </div>

          {/* Search Bucket */}
          <div className="wcp-firewall-inset-box" style={{ padding: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', color: '#38bdf8' }}>
                <Search size={14} /> Search Queries
              </span>
              <span className="wcp-badge-pill" style={{ fontSize: '11px' }}>
                {settings?.limit_search || 25} req / min
              </span>
            </div>
            <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
              {buckets.search} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>throttles today</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '4px' }}>
              Terminates database exhaustion DoS loops
            </div>
          </div>

          {/* API Bucket */}
          <div className="wcp-firewall-inset-box" style={{ padding: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', color: '#818cf8' }}>
                <Globe size={14} /> REST API Endpoints
              </span>
              <span className="wcp-badge-pill" style={{ fontSize: '11px' }}>
                {settings?.limit_api || 60} req / min
              </span>
            </div>
            <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
              {buckets.api} <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--wcp-text-muted, #64748b)' }}>throttles today</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '4px' }}>
              Burst allowance for unauthenticated endpoints
            </div>
          </div>
        </div>
      </div>

      {/* Stateless WebCrypto PoW & HTTP/2 Sentinel Card */}
      <div className="wcp-firewall-section-group" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Cpu size={18} color="#10b981" />
              <h4 className="wcp-firewall-section-title" style={{ margin: 0, fontSize: '16px' }}>
                Stateless WebCrypto Proof-of-Work (PoW) &amp; HTTP/2 Fingerprint Sentinel
              </h4>
              <span className="wcp-badge-pill wcp-badge-info">
                Zero External JS CDN
              </span>
            </div>
            <p className="wcp-firewall-section-desc" style={{ marginTop: '4px', marginBottom: 0 }}>
              Halts headless Python, Go, and LLM scrapers via native in-browser <code>crypto.subtle.digest</code> SHA-256 challenges (~70ms) and terminates HTTP/2 pseudo-header sequencing anomalies.
            </p>
          </div>
        </div>

        {/* Manual Suspicious IP Challenge Enforcer */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginTop: '10px' }}>
          <input
            type="text"
            className="wcp-input"
            placeholder="Enter suspicious IP to challenge (e.g. 198.51.100.22)..."
            value={powIpInput}
            onChange={(e) => setPowIpInput(e.target.value)}
            style={{ minWidth: '320px', fontSize: '13px', padding: '8px 12px' }}
          />
          <button
            type="button"
            className="wcp-btn"
            disabled={!powIpInput.trim() || togglingPow}
            onClick={() => handleTogglePow(powIpInput.trim(), true)}
            style={{
              background: '#4f46e5',
              color: '#fff',
              border: 'none',
              padding: '8px 16px',
              fontSize: '12px',
              fontWeight: 600,
              borderRadius: '6px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              cursor: (!powIpInput.trim() || togglingPow) ? 'not-allowed' : 'pointer'
            }}
          >
            {togglingPow ? <Loader2 size={13} className="wcp-spin" /> : <Lock size={13} />}
            Enforce WebCrypto PoW
          </button>
        </div>

        {/* Active Enforced IPs */}
        {data?.pow_enforced_ips && data.pow_enforced_ips.length > 0 && (
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--wcp-text-primary, #0f172a)' }}>
              Manually Challenged IPs ({data.pow_enforced_ips.length}):
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {data.pow_enforced_ips.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '4px 10px',
                    borderRadius: '4px',
                    background: 'rgba(79, 70, 229, 0.1)',
                    border: '1px solid rgba(79, 70, 229, 0.3)',
                    fontSize: '12px'
                  }}
                >
                  <code>{item.ip}</code>
                  <button
                    type="button"
                    onClick={() => handleTogglePow(item.ip, false)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', fontSize: '12px', padding: 0 }}
                    title="Remove PoW Challenge"
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 1-Click Exemption Synthesis & Learning Mode Observations Card */}
      <div className="wcp-firewall-section-group" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldCheck size={18} color="#10b981" />
              <h4 className="wcp-firewall-section-title" style={{ margin: 0, fontSize: '16px' }}>
                1-Click False-Positive Exemption Synthesizer (CAF Feedback Loop)
              </h4>
              <span className="wcp-badge-pill wcp-badge-clean">
                {data?.exemption_count || 0} Active Safe-Passes
              </span>
            </div>
            <p className="wcp-firewall-section-desc" style={{ marginTop: '4px', marginBottom: 0 }}>
              Surgically softens firewall rules for verified plugins and administrative sessions without lowering global perimeter protection.
            </p>
          </div>
        </div>

        {/* Learning Mode Observations List */}
        {data?.learning_observations && data.learning_observations.length > 0 ? (
          <div style={{ overflowX: 'auto', marginTop: '12px' }}>
            <table className="wcp-waf-table" style={{ width: '100%', fontSize: '12px' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '8px 12px' }}>Observed Target &amp; Route</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px' }}>Rule Triggered</th>
                  <th style={{ textAlign: 'center', padding: '8px 12px', width: '100px' }}>Auth Status</th>
                  <th style={{ textAlign: 'center', padding: '8px 12px', width: '140px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {data.learning_observations.map((obs, idx) => (
                  <tr key={idx}>
                    <td style={{ padding: '8px 12px' }}>
                      <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>{obs.clean_route}</strong>
                      <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                        Method: {obs.method} • IP: <code>{obs.ip}</code>
                      </div>
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span className="wcp-badge-pill wcp-badge-warning">{obs.rule_id}</span>
                      <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                        {obs.rule_name}
                      </div>
                    </td>
                    <td style={{ textAlign: 'center', padding: '8px 12px' }}>
                      <span className={obs.is_logged_in ? 'wcp-badge-pill wcp-badge-clean' : 'wcp-badge-pill'}>
                        {obs.is_logged_in ? 'Logged In' : 'Guest'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'center', padding: '8px 12px' }}>
                      {obs.status === 'synthesized' ? (
                        <span className="wcp-badge-pill wcp-badge-clean" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          <CheckCircle2 size={12} /> Synthesized
                        </span>
                      ) : (
                        <button
                          type="button"
                          className="wcp-btn"
                          disabled={synthesizingId === obs.id}
                          onClick={() => handleSynthesizeExemption(obs.id)}
                          style={{
                            background: '#10b981',
                            color: '#fff',
                            border: 'none',
                            padding: '4px 10px',
                            fontSize: '11px',
                            fontWeight: 600,
                            borderRadius: '4px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}
                        >
                          {synthesizingId === obs.id ? <Loader2 size={11} className="wcp-spin" /> : <ShieldCheck size={11} />}
                          1-Click Soften
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '16px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)', fontSize: '13px' }}>
            No recent false-positive learning observations recorded. When anomalous traffic occurs or you click &quot;Soften Rule&quot; from a blocked incident log, surgical exemptions appear here.
          </div>
        )}
      </div>
    </div>
  );
};
