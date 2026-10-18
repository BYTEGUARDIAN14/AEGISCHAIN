import { 
  CheckCircle2, 
  XCircle, 
  Shield, 
  ShieldAlert, 
  Lock, 
  Check, 
  Zap, 
  Activity, 
  Play 
} from 'lucide-react';
import { type Decision, INITIAL_DECISIONS } from '../types';

interface OverviewTabProps {
  onSelectDecision: (d: Decision) => void;
  onOpenSimulator: () => void;
}

export const OverviewTab = ({ onSelectDecision, onOpenSimulator }: OverviewTabProps) => {
  return (
    <main className="space-y-6" id="view-overview">
      {/* KPI Stat Cards */}
      <section className="stats-grid" aria-label="Key Performance Indicators">
        <div className="glass-panel kpi-card kpi-card-emerald">
          <div className="kpi-header">
            <span className="kpi-title">Workloads Admitted</span>
            <div className="kpi-icon" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}>
              <CheckCircle2 size={18} />
            </div>
          </div>
          <div className="kpi-value" style={{ color: '#34d399' }}>24</div>
          <span className="kpi-subtitle">
            <Lock size={12} className="text-emerald-400" /> SLSA L3 + Signed with Fulcio OIDC
          </span>
        </div>

        <div className="glass-panel kpi-card kpi-card-rose">
          <div className="kpi-header">
            <span className="kpi-title">Supply Chain Attacks Blocked</span>
            <div className="kpi-icon" style={{ background: 'rgba(244, 63, 94, 0.15)', color: '#fb7185' }}>
              <XCircle size={18} />
            </div>
          </div>
          <div className="kpi-value" style={{ color: '#fb7185' }}>14</div>
          <span className="kpi-subtitle">
            <ShieldAlert size={12} className="text-rose-400" /> 14 of 14 Attack Lab Scenarios Thwarted
          </span>
        </div>

        <div className="glass-panel kpi-card kpi-card-cyan">
          <div className="kpi-header">
            <span className="kpi-title">Mean Trust Score</span>
            <div className="kpi-icon" style={{ background: 'rgba(6, 182, 212, 0.15)', color: '#38bdf8' }}>
              <Shield size={18} />
            </div>
          </div>
          <div className="kpi-value" style={{ color: '#38bdf8' }}>
            96.8 <span style={{ fontSize: '14px', fontWeight: 'normal', color: 'var(--text-muted)' }}>/ 100</span>
          </div>
          <span className="kpi-subtitle">
            <Check size={12} className="text-cyan-400" /> Across 8 OPA Rego v1 Policies
          </span>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Admission Webhook Latency</span>
            <div className="kpi-icon" style={{ background: 'rgba(139, 92, 246, 0.15)', color: '#a78bfa' }}>
              <Zap size={18} />
            </div>
          </div>
          <div className="kpi-value" style={{ color: '#a78bfa' }}>0.70 <span style={{ fontSize: '14px', fontWeight: 'normal', color: 'var(--text-muted)' }}>ms</span></div>
          <span className="kpi-subtitle">
            <Activity size={12} className="text-purple-400" /> Benchmarked p95 Admission Overhead
          </span>
        </div>
      </section>

      {/* Activity Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        <section className="glass-panel" style={{ padding: '22px', gridColumn: 'span 2' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '16px', fontWeight: '700', color: 'var(--text-primary)' }}>
                Recent Admission Reviews
              </h2>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Real-time cryptographic verdicts verified at Kubernetes API ingress
              </p>
            </div>
            <button 
              className="btn-ghost-sm"
              onClick={onOpenSimulator}
            >
              <Play size={12} /> Test New Workload
            </button>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Decision ID</th>
                  <th>Workload Image</th>
                  <th>Namespace</th>
                  <th>Verdict</th>
                  <th>Trust Score</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {INITIAL_DECISIONS.map((d) => (
                  <tr 
                    key={d.id} 
                    className="table-row-interactive"
                    onClick={() => onSelectDecision(d)}
                  >
                    <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>
                      {d.id}
                    </td>
                    <td className="mono-text" style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {d.image}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>
                        {d.namespace} ({d.mode})
                      </span>
                    </td>
                    <td>
                      <span className={`pill ${d.verdict === 'allow' ? 'pill-allow' : 'pill-deny'}`}>
                        {d.verdict}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{d.trustScore}</span>
                      <span style={{ color: 'var(--text-muted)' }}> / 100</span>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{d.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Namespaces Policy Status */}
        <section className="glass-panel" style={{ padding: '22px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h2 style={{ fontSize: '16px', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '4px' }}>
              Namespace Guardrails
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Per-namespace fail-closed gating policies
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(10, 15, 26, 0.7)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: '600', fontSize: '13px' }}>prod</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Zero-trust mission critical</div>
                </div>
                <span className="pill pill-deny">ENFORCE (FAIL-CLOSED)</span>
              </div>

              <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(10, 15, 26, 0.7)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: '600', fontSize: '13px' }}>staging</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Pre-release integration</div>
                </div>
                <span className="pill pill-audit">AUDIT (OBSERVABLE)</span>
              </div>

              <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(10, 15, 26, 0.7)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: '600', fontSize: '13px' }}>default</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Unmanaged workloads</div>
                </div>
                <span className="pill pill-deny">ENFORCE (FAIL-CLOSED)</span>
              </div>

              <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(10, 15, 26, 0.4)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: '600', fontSize: '13px', color: 'var(--text-muted)' }}>kube-system</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Kube control plane</div>
                </div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>EXCLUDED</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--border-subtle)', fontSize: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Emergency Break-Glass:</span>
            <span className="mono-text" style={{ color: '#34d399', fontWeight: '600' }}>STANDBY (Max 2h)</span>
          </div>
        </section>
      </div>

      {/* STRIDE Security Architecture Overview */}
      <section className="glass-panel" style={{ padding: '22px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '4px' }}>
          STRIDE Supply Chain Threat Matrix
        </h2>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
          Comprehensive supply chain threat model defenses implemented in AegisChain
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
          <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(14, 20, 34, 0.8)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: '700', color: '#38bdf8' }}>Spoofing</span>
              <span className="pill pill-allow" style={{ fontSize: '9px' }}>MITIGATED</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Sigstore Cosign keyless signatures bound to Fulcio OIDC ephemeral certificates.
            </p>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(14, 20, 34, 0.8)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: '700', color: '#38bdf8' }}>Tampering</span>
              <span className="pill pill-allow" style={{ fontSize: '9px' }}>MITIGATED</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              SLSA Build Level 3 hermetic builders with bit-for-bit digest verification.
            </p>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(14, 20, 34, 0.8)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: '700', color: '#38bdf8' }}>Repudiation</span>
              <span className="pill pill-allow" style={{ fontSize: '9px' }}>MITIGATED</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Append-only hash-chained ledger anchoring every decision with cryptographic proof.
            </p>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(14, 20, 34, 0.8)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: '700', color: '#38bdf8' }}>Info Disclosure</span>
              <span className="pill pill-allow" style={{ fontSize: '9px' }}>MITIGATED</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              TLS 1.3 mTLS client certs and zero secrets stored in container layers or logs.
            </p>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(14, 20, 34, 0.8)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: '700', color: '#38bdf8' }}>Denial of Service</span>
              <span className="pill pill-allow" style={{ fontSize: '9px' }}>MITIGATED</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Concurrent resolver with 5s context timeout and bounded memory footprint.
            </p>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(14, 20, 34, 0.8)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: '700', color: '#38bdf8' }}>Elevation</span>
              <span className="pill pill-allow" style={{ fontSize: '9px' }}>MITIGATED</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Hardened security context: non-root 65532, drop ALL capabilities, read-only rootfs.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
};
