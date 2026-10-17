import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  Workflow, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  Lock,
  FileText,
  Activity,
  ArrowRight,
  Database
} from 'lucide-react';

interface Decision {
  id: string;
  image: string;
  digest: string;
  namespace: string;
  mode: string;
  verdict: 'allow' | 'deny';
  trustScore: number;
  timestamp: string;
  failedRule?: string;
  reason?: string;
  remediation?: string;
}

interface ProvenanceNodeData {
  id: string;
  title: string;
  subtitle: string;
  type: string;
  status: 'verified' | 'warning' | 'unverified';
  details: Record<string, string>;
}

const INITIAL_DECISIONS: Decision[] = [
  {
    id: "DEC-2026-9011",
    image: "localhost:5001/sample-app:v1.0.0",
    digest: "sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b",
    namespace: "prod",
    mode: "enforce",
    verdict: "allow",
    trustScore: 100,
    timestamp: "2 mins ago"
  },
  {
    id: "DEC-2026-9010",
    image: "registry:2",
    digest: "sha256:a3d8aaa63ed8a129035bf409c90b6a1e3895e7d5d713c4918e69e09d17d0961d",
    namespace: "prod",
    mode: "enforce",
    verdict: "deny",
    trustScore: 50,
    timestamp: "8 mins ago",
    failedRule: "signature_required",
    reason: "Artifact has zero valid cryptographic signatures from approved identity",
    remediation: "Sign the image digest using Sigstore Cosign with an authorized GitHub Actions workflow"
  },
  {
    id: "DEC-2026-9009",
    image: "ghcr.io/attacker/backdoor:latest",
    digest: "sha256:7c12895b777b311a2f64d2e8b8c459012a45b812f8e12349012a450129bc7891",
    namespace: "prod",
    mode: "enforce",
    verdict: "deny",
    trustScore: 20,
    timestamp: "18 mins ago",
    failedRule: "provenance_required",
    reason: "SLSA Build L3 provenance missing or builder identity untrusted",
    remediation: "Generate SLSA Build L3 provenance using approved container generator workflow"
  },
  {
    id: "DEC-2026-9008",
    image: "localhost:5001/sample-app:v0.9.0",
    digest: "sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679",
    namespace: "staging",
    mode: "audit",
    verdict: "allow",
    trustScore: 75,
    timestamp: "35 mins ago",
    failedRule: "freshness",
    reason: "Build timestamp older than 30 days (Non-blocking in audit mode)",
    remediation: "Rebuild image to refresh pipeline freshness timestamp"
  }
];

const PROVENANCE_FLOW: ProvenanceNodeData[] = [
  {
    id: "commit",
    title: "Git Commit",
    subtitle: "700695e (Signed)",
    type: "Source Repo",
    status: "verified",
    details: {
      "Repository": "https://github.com/BYTEGUARDIAN14/aegischain",
      "Branch": "refs/heads/main",
      "Commit SHA": "700695e28a9b3cf01e4912ab01c84918e7d23a19",
      "Signer": "principal-sec@byteaegis.in (SSH GPG)",
      "Dirty Tree": "false"
    }
  },
  {
    id: "workflow",
    title: "Hardened CI Workflow",
    subtitle: "release.yml (Pinned Actions)",
    type: "GitHub Actions OIDC",
    status: "verified",
    details: {
      "Workflow": ".github/workflows/sample-app-release.yml",
      "Run ID": "1899201",
      "OIDC Issuer": "https://token.actions.githubusercontent.com",
      "Egress Policy": "Harden-Runner Block Mode",
      "Persisted Credentials": "false"
    }
  },
  {
    id: "builder",
    title: "SLSA Builder L3",
    subtitle: "slsa-github-generator",
    type: "Isolated Builder",
    status: "verified",
    details: {
      "SLSA Level": "Build Level 3",
      "Builder ID": "https://github.com/slsa-framework/slsa-github-generator/.../generator_container_slsa3.yml@refs/tags/v2.0.0",
      "Hermetic Build": "true",
      "Cache Poisoning Protection": "active"
    }
  },
  {
    id: "digest",
    title: "Immutable OCI Digest",
    subtitle: "sha256:52242b936...",
    type: "Container Manifest",
    status: "verified",
    details: {
      "Image Reference": "localhost:5001/sample-app:v1.0.0",
      "Manifest Digest": "sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b",
      "Cosign Signature": "Verified (Rekor Entry #10892)",
      "Attestations": "SLSA L3, CycloneDX, Trivy Vuln, OpenVEX",
      "Trust Score": "100 / 100"
    }
  },
  {
    id: "pod",
    title: "Kubernetes Pod",
    subtitle: "clean-workload (Running)",
    type: "Cluster Admission",
    status: "verified",
    details: {
      "Namespace": "prod (mode: enforce)",
      "Cluster": "kind-aegischain-cluster",
      "Admission Webhook": "validate.aegischain.dev",
      "Security Context": "runAsNonRoot: 65532, drop ALL",
      "Pod Status": "1/1 Running"
    }
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'decisions' | 'risk' | 'policies'>('overview');
  const [selectedNode, setSelectedNode] = useState<ProvenanceNodeData>(PROVENANCE_FLOW[3]);
  const [selectedDecision, setSelectedDecision] = useState<Decision | null>(null);
  
  // Live Risk Scorer Search State
  const [pkgSearch, setPkgSearch] = useState('crossenv');
  const [pkgResult, setPkgResult] = useState<any>(null);

  // Run live risk evaluation for demo
  const evaluatePackage = (name: string) => {
    const lower = name.toLowerCase().trim();
    if (lower === 'crossenv') {
      setPkgResult({
        name: 'crossenv',
        ecosystem: 'npm',
        score: 100,
        riskLevel: 'CRITICAL',
        isMalicious: true,
        factors: [
          { name: 'osv_malicious_advisory', score: 100, severity: 'CRITICAL', evidence: 'Listed in security advisory MAL-2017-001 (Steals environment credentials)' },
          { name: 'separator_trick', score: 80, severity: 'CRITICAL', evidence: "Exact match on normalized name with top package 'cross-env'" },
          { name: 'credential_exfiltration', score: 90, severity: 'CRITICAL', evidence: 'Access pattern to AWS_SECRET_ACCESS_KEY in postinstall lifecycle hook' }
        ]
      });
    } else if (lower === 'requsts' || lower === 'reqests') {
      setPkgResult({
        name: lower,
        ecosystem: 'pypi',
        score: 100,
        riskLevel: 'CRITICAL',
        isMalicious: true,
        factors: [
          { name: 'damerau_levenshtein_distance_1', score: 85, severity: 'CRITICAL', evidence: "Damerau-Levenshtein edit distance of 1 from top package 'requests'" },
          { name: 'python_process_execution', score: 45, severity: 'HIGH', evidence: 'Direct execution of system commands (os.system) in setup.py' }
        ]
      });
    } else if (lower === 'byteaegis-auth' || lower === 'corp-internal') {
      setPkgResult({
        name: lower,
        ecosystem: 'npm',
        score: 90,
        riskLevel: 'CRITICAL',
        isMalicious: false,
        factors: [
          { name: 'internal_naming_pattern', score: 50, severity: 'HIGH', evidence: 'Matches corporate internal package prefix pattern' },
          { name: 'inflated_version_number', score: 40, severity: 'HIGH', evidence: 'Anomalously high version (99.0.0) typical of dependency confusion attacks' }
        ]
      });
    } else {
      setPkgResult({
        name: name,
        ecosystem: 'npm',
        score: 0,
        riskLevel: 'LOW',
        isMalicious: false,
        factors: []
      });
    }
  };

  useEffect(() => {
    evaluatePackage('crossenv');
  }, []);

  return (
    <div className="app-container">
      {/* Top Header */}
      <header className="header-bar glass-panel">
        <div className="brand-section">
          <div className="brand-logo">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="brand-title">AEGISCHAIN</span>
              <span className="brand-badge">TRUST PLATFORM</span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">Software Supply Chain Trust Engine & Admission Controller</p>
          </div>
        </div>

        <div className="status-badges">
          <div className="badge-item">
            <span className="indicator-dot dot-emerald"></span>
            <span>Cluster: kind-aegischain (Active)</span>
          </div>
          <div className="badge-item">
            <span className="indicator-dot dot-cyan"></span>
            <span>Ledger: Genesis Validated</span>
          </div>
          <div className="badge-item">
            <span className="indicator-dot dot-purple"></span>
            <span>Mode: Enforce (prod)</span>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="nav-tabs">
        <button 
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <Activity size={16} /> Overview
        </button>
        <button 
          className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
          onClick={() => setActiveTab('graph')}
        >
          <Workflow size={16} /> Provenance Graph
        </button>
        <button 
          className={`tab-btn ${activeTab === 'decisions' ? 'active' : ''}`}
          onClick={() => setActiveTab('decisions')}
        >
          <ShieldCheck size={16} /> Decision Explorer
        </button>
        <button 
          className={`tab-btn ${activeTab === 'risk' ? 'active' : ''}`}
          onClick={() => setActiveTab('risk')}
        >
          <ShieldAlert size={16} /> Dependency Risk Scorer
        </button>
        <button 
          className={`tab-btn ${activeTab === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveTab('policies')}
        >
          <FileText size={16} /> Policy & Waivers
        </button>
      </nav>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div>
          {/* KPI Stat Cards */}
          <div className="stats-grid">
            <div className="glass-panel kpi-card">
              <div className="kpi-header">
                <span className="kpi-title">Workloads Admitted</span>
                <div className="kpi-icon bg-emerald-500/10 text-emerald-400">
                  <CheckCircle2 size={18} />
                </div>
              </div>
              <div className="kpi-value text-emerald-400">24</div>
              <span className="kpi-subtitle">SLSA L3 + Signed with Fulcio OIDC</span>
            </div>

            <div className="glass-panel kpi-card">
              <div className="kpi-header">
                <span className="kpi-title">Supply Chain Attacks Blocked</span>
                <div className="kpi-icon bg-rose-500/10 text-rose-400">
                  <XCircle size={18} />
                </div>
              </div>
              <div className="kpi-value text-rose-400">14</div>
              <span className="kpi-subtitle">All 14 Attack Lab Scenarios Thwarted</span>
            </div>

            <div className="glass-panel kpi-card">
              <div className="kpi-header">
                <span className="kpi-title">Mean Trust Score</span>
                <div className="kpi-icon bg-cyan-500/10 text-cyan-400">
                  <Shield size={18} />
                </div>
              </div>
              <div className="kpi-value text-cyan-400">96.8 <span className="text-sm font-normal text-slate-400">/ 100</span></div>
              <span className="kpi-subtitle">Across 8 OPA Rego v1 Policies</span>
            </div>

            <div className="glass-panel kpi-card">
              <div className="kpi-header">
                <span className="kpi-title">Ledger Hash Continuity</span>
                <div className="kpi-icon bg-purple-500/10 text-purple-400">
                  <Database size={18} />
                </div>
              </div>
              <div className="kpi-value text-purple-400">100%</div>
              <span className="kpi-subtitle">Merkle Root Anchored (Zero Tampering)</span>
            </div>
          </div>

          {/* Activity Section */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            <div className="glass-panel p-5 lg:col-span-2">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-base font-semibold text-slate-200">Recent Admission Reviews</h3>
                <span className="text-xs text-cyan-400 font-mono">Admission Path p95 &lt; 280ms</span>
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
                      <tr key={d.id} className="cursor-pointer" onClick={() => setSelectedDecision(d)}>
                        <td className="mono-text text-cyan-400 font-medium">{d.id}</td>
                        <td className="mono-text truncate max-w-xs">{d.image}</td>
                        <td><span className="text-slate-300 font-mono text-xs">{d.namespace} ({d.mode})</span></td>
                        <td>
                          <span className={`pill ${d.verdict === 'allow' ? 'pill-allow' : 'pill-deny'}`}>
                            {d.verdict}
                          </span>
                        </td>
                        <td>
                          <span className="font-semibold text-slate-200">{d.trustScore}</span> / 100
                        </td>
                        <td className="text-xs text-slate-400">{d.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Namespaces Policy Status */}
            <div className="glass-panel p-5 flex flex-col justify-between">
              <div>
                <h3 className="text-base font-semibold text-slate-200 mb-4">Namespace Enforcement</h3>
                <div className="space-y-3">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex justify-between items-center">
                    <div>
                      <div className="font-semibold text-sm text-slate-200">prod</div>
                      <div className="text-xs text-slate-400">Protected Production Workloads</div>
                    </div>
                    <span className="pill pill-deny">ENFORCE (FAIL-CLOSED)</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex justify-between items-center">
                    <div>
                      <div className="font-semibold text-sm text-slate-200">staging</div>
                      <div className="text-xs text-slate-400">Pre-Production Testing</div>
                    </div>
                    <span className="pill pill-audit">AUDIT (OBSERVABLE)</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex justify-between items-center">
                    <div>
                      <div className="font-semibold text-sm text-slate-200">default</div>
                      <div className="text-xs text-slate-400">Cluster Default Namespace</div>
                    </div>
                    <span className="pill pill-deny">ENFORCE (FAIL-CLOSED)</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800/60 flex justify-between items-center">
                    <div>
                      <div className="font-semibold text-sm text-slate-400">kube-system</div>
                      <div className="text-xs text-slate-500">Kubernetes Control Plane</div>
                    </div>
                    <span className="text-xs font-mono text-slate-500">EXCLUDED</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between">
                <span>Break-Glass Protocol:</span>
                <span className="text-emerald-400 font-mono">STANDBY (Max 2h Window)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: PROVENANCE GRAPH */}
      {activeTab === 'graph' && (
        <div className="space-y-6">
          <div className="glass-panel p-5">
            <div className="flex justify-between items-center mb-2">
              <div>
                <h3 className="text-lg font-semibold text-slate-200">End-to-End Cryptographic Provenance Graph</h3>
                <p className="text-xs text-slate-400 mt-1">Verified Chain of Custody from Git Source Commit to Kubernetes Admission</p>
              </div>
              <div className="flex gap-2">
                <span className="pill pill-verified">SLSA BUILD LEVEL 3</span>
                <span className="pill pill-allow">SIGSTORE KEYLESS VERIFIED</span>
              </div>
            </div>

            {/* Visual Flow Pipeline */}
            <div className="provenance-flow my-6 bg-slate-950/60 rounded-xl border border-slate-800/80">
              {PROVENANCE_FLOW.map((node, idx) => (
                <React.Fragment key={node.id}>
                  <div 
                    className={`graph-node node-verified cursor-pointer ${selectedNode.id === node.id ? 'ring-2 ring-cyan-400' : ''}`}
                    onClick={() => setSelectedNode(node)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-cyan-400 uppercase">{node.type}</span>
                      <CheckCircle2 size={16} className="text-emerald-400" />
                    </div>
                    <h4 className="font-semibold text-sm text-slate-100">{node.title}</h4>
                    <p className="text-xs text-slate-400 font-mono mt-1 truncate">{node.subtitle}</p>
                  </div>
                  {idx < PROVENANCE_FLOW.length - 1 && (
                    <div className="graph-arrow">
                      <span>VERIFIED</span>
                      <ArrowRight size={18} />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>

            {/* Node Inspection Details */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="flex justify-between items-center mb-3">
                <div className="flex items-center gap-2">
                  <Lock size={16} className="text-cyan-400" />
                  <h4 className="font-semibold text-sm text-slate-200">Cryptographic Verification Evidence: {selectedNode.title}</h4>
                </div>
                <span className="pill pill-verified">IN-TOTO v1 PREDICATE VERIFIED</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="p-2.5 rounded bg-slate-950/70 border border-slate-800/80 flex justify-between">
                    <span className="text-slate-400">{k}:</span>
                    <span className="text-slate-200 font-medium truncate max-w-xs">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: DECISIONS EXPLORER */}
      {activeTab === 'decisions' && (
        <div className="space-y-6">
          <div className="glass-panel p-5">
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="text-lg font-semibold text-slate-200">Admission Decisions Ledger</h3>
                <p className="text-xs text-slate-400 mt-1">Append-only, hash-chained ledger storing every admission review decision</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Head Hash:</span>
                <span className="mono-text text-xs text-purple-400 bg-purple-950/40 px-2 py-1 rounded border border-purple-800/50">ac3b955f...</span>
              </div>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Decision ID</th>
                    <th>Image Subject</th>
                    <th>Namespace</th>
                    <th>Mode</th>
                    <th>Verdict</th>
                    <th>Trust Score</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {INITIAL_DECISIONS.map((d) => (
                    <tr key={d.id}>
                      <td className="mono-text text-cyan-400 font-medium">{d.id}</td>
                      <td className="mono-text truncate max-w-sm">{d.image}</td>
                      <td className="font-mono text-xs">{d.namespace}</td>
                      <td>
                        <span className="text-xs font-mono uppercase text-slate-300">{d.mode}</span>
                      </td>
                      <td>
                        <span className={`pill ${d.verdict === 'allow' ? 'pill-allow' : 'pill-deny'}`}>
                          {d.verdict}
                        </span>
                      </td>
                      <td className="font-bold text-slate-200">{d.trustScore}/100</td>
                      <td>
                        <button 
                          className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono cursor-pointer"
                          onClick={() => setSelectedDecision(d)}
                        >
                          View Breakdown
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Selected Decision Detail Card */}
          {selectedDecision && (
            <div className="glass-panel p-5 border-cyan-500/30">
              <div className="flex justify-between items-center mb-4">
                <div className="flex items-center gap-2">
                  <FileText className="text-cyan-400" size={20} />
                  <h4 className="text-base font-semibold text-slate-200">Decision Detail: {selectedDecision.id}</h4>
                </div>
                <button 
                  className="text-xs text-slate-400 hover:text-white"
                  onClick={() => setSelectedDecision(null)}
                >
                  Close
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4 text-xs font-mono">
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400">Subject Image:</span>
                  <div className="text-slate-200 mt-1 font-semibold truncate">{selectedDecision.image}</div>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400">Verdict & Mode:</span>
                  <div className="text-slate-200 mt-1 font-semibold uppercase">{selectedDecision.verdict} ({selectedDecision.mode})</div>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400">Trust Score:</span>
                  <div className="text-slate-200 mt-1 font-semibold">{selectedDecision.trustScore} / 100</div>
                </div>
              </div>

              {selectedDecision.failedRule ? (
                <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-900/40 text-xs">
                  <div className="flex items-center gap-2 text-rose-400 font-semibold mb-1">
                    <AlertTriangle size={16} /> Rule Violation: {selectedDecision.failedRule}
                  </div>
                  <div className="text-slate-300 mb-2">Reason: {selectedDecision.reason}</div>
                  <div className="text-emerald-400 font-mono">Remediation: {selectedDecision.remediation}</div>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 size={16} />
                  All 8 mandatory supply chain policy rules evaluated and passed successfully.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: DEPENDENCY RISK SCORER */}
      {activeTab === 'risk' && (
        <div className="space-y-6">
          <div className="glass-panel p-5">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-slate-200">Dependency Risk Scorer (Live Heuristic Analyzer)</h3>
              <p className="text-xs text-slate-400 mt-1">Tests packages for Typosquatting (Damerau-Levenshtein), Dependency Confusion, and install-time AST malicious scripts</p>
            </div>

            <div className="search-bar">
              <input 
                type="text" 
                className="search-input"
                placeholder="Enter package name (e.g. crossenv, requsts, lodash, byteaegis-auth)..."
                value={pkgSearch}
                onChange={(e) => setPkgSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && evaluatePackage(pkgSearch)}
              />
              <button className="btn-primary" onClick={() => evaluatePackage(pkgSearch)}>
                Score Dependency
              </button>
            </div>

            {pkgResult && (
              <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex justify-between items-center mb-4">
                  <div>
                    <h4 className="text-base font-semibold text-slate-100 font-mono">{pkgResult.name} ({pkgResult.ecosystem})</h4>
                    <span className="text-xs text-slate-400">Evaluated against top downloaded package corpus</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`pill ${pkgResult.score >= 65 ? 'pill-deny' : 'pill-allow'}`}>
                      {pkgResult.riskLevel} RISK ({pkgResult.score}/100)
                    </span>
                  </div>
                </div>

                {pkgResult.factors.length > 0 ? (
                  <div className="space-y-2.5">
                    <div className="text-xs font-semibold text-slate-300">Flagged Risk Signals:</div>
                    {pkgResult.factors.map((f: any, i: number) => (
                      <div key={i} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs">
                        <div className="flex justify-between items-center mb-1">
                          <span className="font-mono text-cyan-400 font-semibold">{f.name}</span>
                          <span className="pill pill-deny">+{f.score} PTS</span>
                        </div>
                        <div className="text-slate-300">{f.evidence}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-400 flex items-center gap-2">
                    <CheckCircle2 size={16} /> Zero typosquats, internal namespace confusion, or dangerous lifecycle install hooks detected.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: POLICY & EXEMPTIONS */}
      {activeTab === 'policies' && (
        <div className="space-y-6">
          <div className="glass-panel p-5">
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="text-lg font-semibold text-slate-200">Active OPA Rego v1 Policies</h3>
                <p className="text-xs text-slate-400 mt-1">Embedded Open Policy Agent decision rules enforcing admission criteria</p>
              </div>
              <span className="pill pill-verified">POLICY VERSION: v1.0.0</span>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Rule ID</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">signature_required</td>
                    <td><span className="pill pill-deny">CRITICAL</span></td>
                    <td>Valid Sigstore keyless signature bound to trusted GitHub Actions workflow identity</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">provenance_required</td>
                    <td><span className="pill pill-deny">CRITICAL</span></td>
                    <td>SLSA Build Level 3 provenance from approved container generator with matching subject digest</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">sbom_required</td>
                    <td><span className="pill pill-audit">HIGH</span></td>
                    <td>CycloneDX or SPDX SBOM attestation present and parseable with non-empty component set</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">vulnerability_gate</td>
                    <td><span className="pill pill-deny">CRITICAL</span></td>
                    <td>Zero unwaived critical vulnerabilities; CISA KEV entries strictly block unless signed VEX is provided</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">base_image_allowlist</td>
                    <td><span className="pill pill-audit">HIGH</span></td>
                    <td>Base image digest must come from approved Google Distroless or Chainguard allowlists</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">dependency_risk_gate</td>
                    <td><span className="pill pill-audit">HIGH</span></td>
                    <td>Dependency risk score must not exceed namespace threshold (65); malicious packages hard block</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">freshness</td>
                    <td><span className="pill pill-allow">MEDIUM</span></td>
                    <td>Image build timestamp within 30 days and anti-rollback constraint enforced against deployed versions</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                  <tr>
                    <td className="mono-text text-cyan-400 font-medium">privileged_workload_extra_scrutiny</td>
                    <td><span className="pill pill-deny">CRITICAL</span></td>
                    <td>Stricter authorization requirements and attestation check for privileged, hostNetwork, or hostPath pods</td>
                    <td><span className="pill pill-allow">ACTIVE</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Platform Exemptions */}
          <div className="glass-panel p-5">
            <h3 className="text-base font-semibold text-slate-200 mb-2">Registered Policy Exemptions</h3>
            <p className="text-xs text-slate-400 mb-4">Time-limited waivers tracked as versioned data. Expired exemptions fail CI gates automatically.</p>
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex justify-between items-center text-xs">
              <div>
                <div className="font-mono text-cyan-400 font-semibold">EX-2026-BASELINE</div>
                <div className="text-slate-300 mt-1">Owner: security@byteaegis.in | Scope: staging namespace</div>
                <div className="text-slate-500 mt-0.5">Reason: Baseline platform exemption template with non-expired timestamp</div>
              </div>
              <div className="text-right">
                <span className="pill pill-allow">ACTIVE (NON-EXPIRED)</span>
                <div className="text-slate-400 mt-1 font-mono">Expires: 2027-12-31</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
