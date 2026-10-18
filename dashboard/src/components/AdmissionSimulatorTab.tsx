import { 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Lock, 
  Play, 
  RefreshCw 
} from 'lucide-react';

interface AdmissionSimulatorTabProps {
  simPreset: 'clean' | 'tampered-layer' | 'unsigned' | 'typosquat' | 'cve-vex' | 'expired-exemption';
  onPresetChange: (p: 'clean' | 'tampered-layer' | 'unsigned' | 'typosquat' | 'cve-vex' | 'expired-exemption') => void;
  simNamespace: 'prod' | 'staging';
  onNamespaceChange: (n: 'prod' | 'staging') => void;
  simulating: boolean;
  simResult: any | null;
  onRunSimulation: () => void;
}

export const AdmissionSimulatorTab = ({
  simPreset,
  onPresetChange,
  simNamespace,
  onNamespaceChange,
  simulating,
  simResult,
  onRunSimulation,
}: AdmissionSimulatorTabProps) => {
  return (
    <main className="space-y-6" id="view-simulator">
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>
            Interactive Admission Simulator & Policy Sandbox
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Simulate validating admission webhook reviews against the embedded OPA Rego v1 trust engine
          </p>
        </div>

        {/* Presets */}
        <div style={{ marginBottom: '16px' }}>
          <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)', display: 'block', marginBottom: '8px' }}>
            Select Test Scenario Preset:
          </span>
          <div className="preset-chips">
            <button 
              id="preset-clean"
              className={`chip-btn ${simPreset === 'clean' ? 'active' : ''}`}
              onClick={() => onPresetChange('clean')}
            >
              <CheckCircle2 size={12} className="text-emerald-400" /> Clean SLSA L3 Artifact (sample-app:v1.0.0)
            </button>
            <button 
              id="preset-tampered"
              className={`chip-btn ${simPreset === 'tampered-layer' ? 'active' : ''}`}
              onClick={() => onPresetChange('tampered-layer')}
            >
              <XCircle size={12} className="text-rose-400" /> Scenario 03: Tampered Image Layer
            </button>
            <button 
              id="preset-unsigned"
              className={`chip-btn ${simPreset === 'unsigned' ? 'active' : ''}`}
              onClick={() => onPresetChange('unsigned')}
            >
              <XCircle size={12} className="text-rose-400" /> Scenario 02: Unsigned Image
            </button>
            <button 
              id="preset-typosquat"
              className={`chip-btn ${simPreset === 'typosquat' ? 'active' : ''}`}
              onClick={() => onPresetChange('typosquat')}
            >
              <AlertTriangle size={12} className="text-amber-400" /> Scenario 09: Malicious Typosquat (crossenv)
            </button>
            <button 
              id="preset-vex"
              className={`chip-btn ${simPreset === 'cve-vex' ? 'active' : ''}`}
              onClick={() => onPresetChange('cve-vex')}
            >
              <Lock size={12} className="text-cyan-400" /> Scenario 04: CISA KEV + Signed OpenVEX Waiver
            </button>
            <button 
              id="preset-expired"
              className={`chip-btn ${simPreset === 'expired-exemption' ? 'active' : ''}`}
              onClick={() => onPresetChange('expired-exemption')}
            >
              <AlertTriangle size={12} className="text-rose-400" /> Scenario 07: Expired Policy Exemption
            </button>
          </div>
        </div>

        {/* Target Options */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', marginBottom: '20px' }}>
          <div>
            <label style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
              Target Kubernetes Namespace:
            </label>
            <select 
              value={simNamespace}
              onChange={(e: any) => onNamespaceChange(e.target.value)}
              style={{ width: '100%', background: 'rgba(14, 19, 32, 0.9)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '12px', fontSize: '13px', outline: 'none' }}
            >
              <option value="prod">prod (Mode: Enforce, Fail-Closed)</option>
              <option value="staging">staging (Mode: Audit, Observable)</option>
            </select>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button 
              id="btn-run-simulation"
              className="btn-primary" 
              onClick={onRunSimulation}
              disabled={simulating}
              style={{ width: '100%', justifyContent: 'center' }}
            >
              {simulating ? (
                <>
                  <RefreshCw size={16} className="animate-spin" /> Evaluating Rego Policies...
                </>
              ) : (
                <>
                  <Play size={16} /> Execute Admission Evaluation
                </>
              )}
            </button>
          </div>
        </div>

        {/* Simulation Results Output */}
        {simResult && (
          <div style={{ marginTop: '24px', padding: '24px', borderRadius: '14px', background: 'rgba(10, 16, 28, 0.95)', border: simResult.verdict === 'allow' ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(244, 63, 94, 0.4)', boxShadow: 'var(--shadow-lg)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  ADMISSION CERTIFICATE: {simResult.certificateId} &bull; EVALUATION TIME: {simResult.latency}
                </span>
                <h3 style={{ fontSize: '20px', fontWeight: '800', fontFamily: 'var(--font-display)', color: simResult.verdict === 'allow' ? '#34d399' : '#fb7185', marginTop: '2px' }}>
                  {simResult.verdict === 'allow' ? 'ADMISSION PERMITTED (ALLOW)' : 'ADMISSION BLOCKED (DENY)'}
                </h3>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Trust Score</div>
                  <div style={{ fontSize: '24px', fontWeight: '800', fontFamily: 'var(--font-display)', color: simResult.score >= 70 ? '#34d399' : '#fb7185' }}>
                    {simResult.score} <span style={{ fontSize: '13px', fontWeight: 'normal', color: 'var(--text-muted)' }}>/ 100</span>
                  </div>
                </div>
              </div>
            </div>

            {simResult.reason && (
              <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(244, 63, 94, 0.12)', border: '1px solid rgba(244, 63, 94, 0.3)', marginBottom: '18px', fontSize: '13px' }}>
                <div style={{ color: '#fb7185', fontWeight: '700', marginBottom: '4px' }}>
                  Violation: {simResult.failedRule}
                </div>
                <div style={{ color: 'var(--text-secondary)', marginBottom: '6px' }}>{simResult.reason}</div>
                <div style={{ color: '#34d399', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>Remediation: {simResult.remediation}</div>
              </div>
            )}

            {/* Step-by-step Rule Breakdown */}
            <h4 style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '10px', letterSpacing: '0.5px' }}>
              Rego Rule Evaluation Log
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {simResult.rules.map((r: any, idx: number) => (
                <div 
                  key={idx}
                  style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(6, 10, 18, 0.7)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {r.status === 'pass' ? (
                      <CheckCircle2 size={16} className="text-emerald-400" />
                    ) : (
                      <XCircle size={16} className="text-rose-400" />
                    )}
                    <span className="mono-text" style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{r.name}</span>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>&bull; {r.desc}</span>
                  </div>
                  <span className={`pill ${r.status === 'pass' ? 'pill-allow' : 'pill-deny'}`}>
                    {r.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </main>
  );
};
