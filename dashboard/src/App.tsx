import { useState } from 'react';
import { 
  Activity, 
  Workflow, 
  Database, 
  Sliders, 
  ShieldAlert, 
  FileText,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info
} from 'lucide-react';
import './App.css';
import { 
  type Decision, 
  type ProvenanceNodeData, 
  type ToastNotification, 
  type LedgerBlock, 
  INITIAL_DECISIONS, 
  PROVENANCE_FLOW, 
  INITIAL_LEDGER_BLOCKS, 
  calculatePackageRisk 
} from './types';
import { Header } from './components/Header';
import { OverviewTab } from './components/OverviewTab';
import { ProvenanceGraphTab } from './components/ProvenanceGraphTab';
import { DecisionLedgerTab } from './components/DecisionLedgerTab';
import { AdmissionSimulatorTab } from './components/AdmissionSimulatorTab';
import { DependencyRiskTab } from './components/DependencyRiskTab';
import { PolicyWaiversTab } from './components/PolicyWaiversTab';

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'decisions' | 'simulator' | 'risk' | 'policies'>('overview');
  const [selectedNode, setSelectedNode] = useState<ProvenanceNodeData>(PROVENANCE_FLOW[5]);
  const [selectedDecision, setSelectedDecision] = useState<Decision | null>(INITIAL_DECISIONS[0]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Search and filters for decisions
  const [searchQuery, setSearchQuery] = useState('');
  const [namespaceFilter, setNamespaceFilter] = useState<'all' | 'prod' | 'staging'>('all');
  const [verdictFilter, setVerdictFilter] = useState<'all' | 'allow' | 'deny'>('all');

  // Ledger state & interactive tamper sandbox
  const [ledgerBlocks, setLedgerBlocks] = useState<LedgerBlock[]>(INITIAL_LEDGER_BLOCKS);
  const [ledgerTampered, setLedgerTampered] = useState(false);

  // Simulator state
  const [simPreset, setSimPreset] = useState<'clean' | 'tampered-layer' | 'unsigned' | 'typosquat' | 'cve-vex' | 'expired-exemption'>('clean');
  const [simNamespace, setSimNamespace] = useState<'prod' | 'staging'>('prod');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<any | null>(null);

  // Live Dependency Risk Scorer State initialized directly without setState inside useEffect
  const [pkgSearch, setPkgSearch] = useState('crossenv');
  const [pkgResult, setPkgResult] = useState(() => calculatePackageRisk('crossenv'));

  // Toasts
  const [toasts, setToasts] = useState<ToastNotification[]>([]);

  const showToast = (type: ToastNotification['type'], message: string) => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    showToast('info', 'Copied cryptographic digest to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleTamperLedger = () => {
    setLedgerBlocks(prev => {
      const copy = [...prev];
      copy[1] = {
        ...copy[1],
        verdict: 'deny',
        tampered: true
      };
      return copy;
    });
    setLedgerTampered(true);
    showToast('error', 'CRYPTOGRAPHIC ALARM: Block #1 hash mismatch! Merkle chain verification failed.');
  };

  const handleRestoreLedger = () => {
    setLedgerBlocks(INITIAL_LEDGER_BLOCKS);
    setLedgerTampered(false);
    showToast('success', 'Ledger restored. SHA-256 hash continuity verified across all blocks.');
  };

  const runSimulation = () => {
    setSimulating(true);
    setSimResult(null);

    setTimeout(() => {
      setSimulating(false);
      if (simPreset === 'clean') {
        setSimResult({
          verdict: 'allow',
          score: 100,
          latency: '0.68ms',
          certificateId: 'CERT-2026-PASS-091',
          rules: [
            { name: 'signature_required', status: 'pass', desc: 'Valid Sigstore Cosign signature via Fulcio OIDC' },
            { name: 'provenance_required', status: 'pass', desc: 'SLSA Build Level 3 provenance generator verified' },
            { name: 'sbom_required', status: 'pass', desc: 'CycloneDX SBOM attestation verified (48 packages)' },
            { name: 'vulnerability_gate', status: 'pass', desc: 'Zero unmitigated critical vulnerabilities' },
            { name: 'base_image_allowlist', status: 'pass', desc: 'Approved Google Distroless base image' },
            { name: 'dependency_risk_gate', status: 'pass', desc: 'Package dependency threat score: 0/100' },
            { name: 'freshness', status: 'pass', desc: 'Build timestamp within 30 days freshness window' },
            { name: 'privileged_workload_extra_scrutiny', status: 'pass', desc: 'Non-root container with dropped capabilities' }
          ]
        });
        showToast('success', 'Admission Request Allowed (100/100 Trust Score)');
      } else if (simPreset === 'tampered-layer') {
        setSimResult({
          verdict: 'deny',
          score: 15,
          latency: '0.72ms',
          certificateId: 'CERT-2026-DENY-LAYER-03',
          failedRule: 'provenance_required',
          reason: 'Calculated layer digest does not match SLSA Build L3 signed attestation (Scenario 03 Attack)',
          remediation: 'Rebuild container through authorized hermetic GitHub Actions builder workflow',
          rules: [
            { name: 'signature_required', status: 'pass', desc: 'Cosign keyless signature valid' },
            { name: 'provenance_required', status: 'fail', desc: 'Subject artifact digest mismatch with in-toto predicate' },
            { name: 'vulnerability_gate', status: 'pass', desc: 'Vulnerability scan matches' }
          ]
        });
        showToast('error', 'Admission Request Denied: Layer Tampering Detected');
      } else if (simPreset === 'unsigned') {
        setSimResult({
          verdict: 'deny',
          score: 40,
          latency: '0.54ms',
          certificateId: 'CERT-2026-DENY-SIG-02',
          failedRule: 'signature_required',
          reason: 'No cryptographic signatures found matching authorized Fulcio root certificate identity',
          remediation: 'Run "cosign sign --yes <image>" within authorized CI/CD pipeline',
          rules: [
            { name: 'signature_required', status: 'fail', desc: 'Signature missing or unverified' },
            { name: 'provenance_required', status: 'fail', desc: 'No provenance attestation' }
          ]
        });
        showToast('error', 'Admission Request Denied: Missing Keyless Signature');
      } else if (simPreset === 'typosquat') {
        setSimResult({
          verdict: 'deny',
          score: 25,
          latency: '1.02ms',
          certificateId: 'CERT-2026-DENY-RISK-09',
          failedRule: 'dependency_risk_gate',
          reason: 'Malicious dependency detected: crossenv (OSV MAL-2017-001 credential exfiltration)',
          remediation: 'Remove malicious package and replace with legitimate cross-env',
          rules: [
            { name: 'signature_required', status: 'pass', desc: 'Valid signature' },
            { name: 'dependency_risk_gate', status: 'fail', desc: 'Package threat score: 100/100 (Threshold: 65)' }
          ]
        });
        showToast('error', 'Admission Request Denied: Malicious Dependency Detected');
      } else if (simPreset === 'cve-vex') {
        setSimResult({
          verdict: 'allow',
          score: 95,
          latency: '0.84ms',
          certificateId: 'CERT-2026-ALLOW-VEX-04',
          rules: [
            { name: 'signature_required', status: 'pass', desc: 'Valid Sigstore Cosign signature' },
            { name: 'provenance_required', status: 'pass', desc: 'SLSA L3 Provenance verified' },
            { name: 'vulnerability_gate', status: 'pass', desc: 'CVE-2023-44487 justified via signed OpenVEX (not_affected)' }
          ]
        });
        showToast('success', 'Admission Request Allowed: Mitigated via Signed OpenVEX');
      } else {
        setSimResult({
          verdict: 'deny',
          score: 55,
          latency: '0.62ms',
          certificateId: 'CERT-2026-DENY-EXEMPT-07',
          failedRule: 'policy_exemption_expired',
          reason: 'Waiver EX-2026-OLD expired on 2026-09-01; admission gate strictly enforces expiration',
          remediation: 'Submit updated exemption review with architectural remediation commitment',
          rules: [
            { name: 'signature_required', status: 'pass', desc: 'Signature valid' },
            { name: 'policy_exemption_expired', status: 'fail', desc: 'Expired platform waiver' }
          ]
        });
        showToast('error', 'Admission Request Denied: Expired Policy Exemption');
      }
    }, 450);
  };

  const filteredDecisions = INITIAL_DECISIONS.filter(d => {
    const matchesSearch = d.id.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          d.image.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          d.digest.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesNamespace = namespaceFilter === 'all' || d.namespace === namespaceFilter;
    const matchesVerdict = verdictFilter === 'all' || d.verdict === verdictFilter;
    return matchesSearch && matchesNamespace && matchesVerdict;
  });

  return (
    <div className="app-container">
      {/* Toast notifications */}
      <div className="toast-container" aria-live="polite">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            {t.type === 'success' && <CheckCircle2 size={18} className="text-emerald-400" />}
            {t.type === 'error' && <XCircle size={18} className="text-rose-400" />}
            {t.type === 'warning' && <AlertTriangle size={18} className="text-amber-400" />}
            {t.type === 'info' && <Info size={18} className="text-cyan-400" />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>

      {/* Header bar */}
      <Header 
        onOpenSimulator={() => setActiveTab('simulator')}
        onVerifyLedger={() => {
          setActiveTab('decisions');
          handleRestoreLedger();
        }}
      />

      {/* Navigation tabs */}
      <nav className="nav-tabs" role="tablist">
        <button 
          id="tab-overview"
          role="tab"
          aria-selected={activeTab === 'overview'}
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <Activity size={16} /> Overview
        </button>
        <button 
          id="tab-graph"
          role="tab"
          aria-selected={activeTab === 'graph'}
          className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
          onClick={() => setActiveTab('graph')}
        >
          <Workflow size={16} /> Provenance Graph
        </button>
        <button 
          id="tab-decisions"
          role="tab"
          aria-selected={activeTab === 'decisions'}
          className={`tab-btn ${activeTab === 'decisions' ? 'active' : ''}`}
          onClick={() => setActiveTab('decisions')}
        >
          <Database size={16} /> Decision Ledger
          {ledgerTampered && <span className="tab-badge bg-rose-500 text-white">TAMPER ALARM</span>}
        </button>
        <button 
          id="tab-simulator"
          role="tab"
          aria-selected={activeTab === 'simulator'}
          className={`tab-btn ${activeTab === 'simulator' ? 'active' : ''}`}
          onClick={() => setActiveTab('simulator')}
        >
          <Sliders size={16} /> Admission Simulator
          <span className="tab-badge bg-cyan-500/20 text-cyan-300">INTERACTIVE</span>
        </button>
        <button 
          id="tab-risk"
          role="tab"
          aria-selected={activeTab === 'risk'}
          className={`tab-btn ${activeTab === 'risk' ? 'active' : ''}`}
          onClick={() => setActiveTab('risk')}
        >
          <ShieldAlert size={16} /> Dependency Risk Scorer
        </button>
        <button 
          id="tab-policies"
          role="tab"
          aria-selected={activeTab === 'policies'}
          className={`tab-btn ${activeTab === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveTab('policies')}
        >
          <FileText size={16} /> Policy & Waivers
        </button>
      </nav>

      {/* Dynamic Tab Views */}
      {activeTab === 'overview' && (
        <OverviewTab 
          onSelectDecision={(d) => {
            setSelectedDecision(d);
            setActiveTab('decisions');
          }}
          onOpenSimulator={() => setActiveTab('simulator')}
        />
      )}

      {activeTab === 'graph' && (
        <ProvenanceGraphTab 
          selectedNode={selectedNode}
          onSelectNode={setSelectedNode}
          copiedId={copiedId}
          onCopyJson={copyToClipboard}
        />
      )}

      {activeTab === 'decisions' && (
        <DecisionLedgerTab 
          ledgerBlocks={ledgerBlocks}
          ledgerTampered={ledgerTampered}
          onTamperLedger={handleTamperLedger}
          onRestoreLedger={handleRestoreLedger}
          onVerifyProof={() => {
            if (ledgerTampered) {
              showToast('error', 'Chain verification failed: Block #1 hash mismatch');
            } else {
              showToast('success', 'Chain verified: Merkle root matches genesis proof');
            }
          }}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          namespaceFilter={namespaceFilter}
          onNamespaceFilterChange={setNamespaceFilter}
          verdictFilter={verdictFilter}
          onVerdictFilterChange={setVerdictFilter}
          filteredDecisions={filteredDecisions}
          selectedDecision={selectedDecision}
          onSelectDecision={setSelectedDecision}
        />
      )}

      {activeTab === 'simulator' && (
        <AdmissionSimulatorTab 
          simPreset={simPreset}
          onPresetChange={setSimPreset}
          simNamespace={simNamespace}
          onNamespaceChange={setSimNamespace}
          simulating={simulating}
          simResult={simResult}
          onRunSimulation={runSimulation}
        />
      )}

      {activeTab === 'risk' && (
        <DependencyRiskTab 
          pkgSearch={pkgSearch}
          onPkgSearchChange={setPkgSearch}
          pkgResult={pkgResult}
          onEvaluatePkg={(name) => {
            setPkgSearch(name);
            setPkgResult(calculatePackageRisk(name));
          }}
        />
      )}

      {activeTab === 'policies' && (
        <PolicyWaiversTab />
      )}

      {/* Footer */}
      <footer style={{ marginTop: '32px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px', color: 'var(--text-muted)', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          AegisChain Trust Platform &bull; Built to Google SLSA, Sigstore & Microsoft DevSecOps Standards
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          <span>Version: <strong>1.0.0</strong></span>
          <span>Engine: <strong>OPA v0.69.0</strong></span>
          <span>Cosign: <strong>v3.7.0</strong></span>
        </div>
      </footer>
    </div>
  );
}
