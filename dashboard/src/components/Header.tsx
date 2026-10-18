import { Shield, Play, RefreshCw } from 'lucide-react';

interface HeaderProps {
  onOpenSimulator: () => void;
  onVerifyLedger: () => void;
}

export const Header = ({ onOpenSimulator, onVerifyLedger }: HeaderProps) => {
  return (
    <header className="header-bar glass-panel">
      <div className="brand-section">
        <div className="brand-logo" aria-hidden="true">
          <Shield size={24} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="brand-title">AEGISCHAIN</h1>
            <span className="brand-badge">TRUST PLATFORM</span>
            <span className="pill pill-allow" style={{ fontSize: '10px' }}>PROD READY</span>
          </div>
          <p className="brand-subtitle">
            Software Supply Chain Trust Engine & Admission Controller
          </p>
        </div>
      </div>

      <div className="status-badges">
        <div className="badge-item" id="badge-cluster-status">
          <span className="indicator-dot dot-pulse-emerald"></span>
          <span>Cluster: <strong>kind-aegischain</strong></span>
        </div>
        <div className="badge-item" id="badge-ledger-status">
          <span className="indicator-dot dot-cyan"></span>
          <span>Ledger: <strong>Hash Chained</strong></span>
        </div>
        <div className="badge-item" id="badge-policy-mode">
          <span className="indicator-dot dot-purple"></span>
          <span>Mode: <strong>Enforce (prod)</strong></span>
        </div>

        <div className="header-actions">
          <button 
            id="header-btn-simulate"
            className="btn-ghost-sm"
            onClick={onOpenSimulator}
            title="Launch admission simulator"
          >
            <Play size={13} className="text-cyan-400" />
            <span>Simulate</span>
          </button>
          <button 
            id="header-btn-verify-ledger"
            className="btn-ghost-sm"
            onClick={onVerifyLedger}
            title="Verify ledger chain"
          >
            <RefreshCw size={13} className="text-emerald-400" />
            <span>Verify Chain</span>
          </button>
        </div>
      </div>
    </header>
  );
};
