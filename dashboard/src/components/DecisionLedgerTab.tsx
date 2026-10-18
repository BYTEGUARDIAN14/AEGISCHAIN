import { AlertTriangle, RefreshCw, Lock, FileText, ChevronRight, CheckCircle2 } from 'lucide-react';
import { type Decision, type LedgerBlock } from '../types';

interface DecisionLedgerTabProps {
  ledgerBlocks: LedgerBlock[];
  ledgerTampered: boolean;
  onTamperLedger: () => void;
  onRestoreLedger: () => void;
  onVerifyProof: () => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  namespaceFilter: 'all' | 'prod' | 'staging';
  onNamespaceFilterChange: (n: 'all' | 'prod' | 'staging') => void;
  verdictFilter: 'all' | 'allow' | 'deny';
  onVerdictFilterChange: (v: 'all' | 'allow' | 'deny') => void;
  filteredDecisions: Decision[];
  selectedDecision: Decision | null;
  onSelectDecision: (d: Decision | null) => void;
}

export const DecisionLedgerTab = ({
  ledgerBlocks,
  ledgerTampered,
  onTamperLedger,
  onRestoreLedger,
  onVerifyProof,
  searchQuery,
  onSearchChange,
  namespaceFilter,
  onNamespaceFilterChange,
  verdictFilter,
  onVerdictFilterChange,
  filteredDecisions,
  selectedDecision,
  onSelectDecision,
}: DecisionLedgerTabProps) => {
  return (
    <main className="space-y-6" id="view-decisions">
      {/* Ledger Tamper Alert Banner */}
      {ledgerTampered && (
        <div style={{ padding: '16px 20px', borderRadius: '12px', background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.5)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <AlertTriangle size={24} className="text-rose-400" />
            <div>
              <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#fb7185' }}>
                CRYPTOGRAPHIC CHAIN CORRUPTION DETECTED
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                Record #1 verdict was tampered without recomputing SHA-256 hash chain. Merkle root proof mismatch.
              </p>
            </div>
          </div>
          <button 
            id="btn-restore-ledger"
            className="btn-primary" 
            onClick={onRestoreLedger}
            style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
          >
            <RefreshCw size={14} /> Restore Clean Ledger
          </button>
        </div>
      )}

      {/* Interactive Ledger Block Chain Visualizer */}
      <section className="glass-panel" style={{ padding: '22px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>
              Cryptographic Ledger Hash Chain Inspector
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Append-only decision ledger where each entry cryptographically commits to the SHA-256 digest of the previous record
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button 
              id="btn-tamper-ledger"
              className="btn-danger"
              onClick={onTamperLedger}
              disabled={ledgerTampered}
            >
              <AlertTriangle size={14} /> Simulate Ledger Tamper
            </button>
            <button 
              id="btn-verify-proof"
              className="btn-secondary"
              onClick={onVerifyProof}
            >
              <Lock size={14} /> Verify Chain Proof
            </button>
          </div>
        </div>

        {/* Block Chain Cards */}
        <div className="ledger-chain-view">
          {ledgerBlocks.map((b) => (
            <div 
              key={b.index} 
              className={`ledger-block-item ${b.tampered ? 'tampered' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ width: '38px', height: '38px', borderRadius: '8px', background: b.tampered ? 'rgba(244, 63, 94, 0.2)' : 'rgba(6, 182, 212, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'var(--font-mono)', fontWeight: '700', color: b.tampered ? '#f87171' : '#38bdf8' }}>
                  #{b.index}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="mono-text" style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{b.decisionId}</span>
                    <span className={`pill ${b.verdict === 'allow' ? 'pill-allow' : 'pill-deny'}`}>
                      {b.verdict}
                    </span>
                    {b.tampered && <span className="pill pill-deny">TAMPERED</span>}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                    {b.image} &bull; {b.timestamp}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  PREV: {b.prevHash.substring(0, 16)}...
                </div>
                <div style={{ fontSize: '11px', color: b.tampered ? '#f87171' : 'var(--color-cyan)', fontFamily: 'var(--font-mono)', fontWeight: '600' }}>
                  HASH: {b.hash.substring(0, 24)}...
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Decisions Table with Filtering */}
      <section className="glass-panel" style={{ padding: '22px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>
              Admission Decisions Explorer
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Filterable query engine across all recorded webhook evaluations
            </p>
          </div>

          {/* Filters */}
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <input 
              type="text" 
              placeholder="Search image or digest..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="search-input"
              style={{ minWidth: '220px', padding: '8px 14px', fontSize: '12px' }}
            />
            <select 
              value={namespaceFilter}
              onChange={(e: any) => onNamespaceFilterChange(e.target.value)}
              style={{ background: 'rgba(14, 19, 32, 0.9)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '8px 12px', fontSize: '12px', outline: 'none' }}
            >
              <option value="all">All Namespaces</option>
              <option value="prod">prod</option>
              <option value="staging">staging</option>
            </select>
            <select 
              value={verdictFilter}
              onChange={(e: any) => onVerdictFilterChange(e.target.value)}
              style={{ background: 'rgba(14, 19, 32, 0.9)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '8px 12px', fontSize: '12px', outline: 'none' }}
            >
              <option value="all">All Verdicts</option>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
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
              {filteredDecisions.map((d) => (
                <tr key={d.id} className="table-row-interactive" onClick={() => onSelectDecision(d)}>
                  <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>{d.id}</td>
                  <td className="mono-text" style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {d.image}
                  </td>
                  <td className="mono-text">{d.namespace}</td>
                  <td>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                      {d.mode}
                    </span>
                  </td>
                  <td>
                    <span className={`pill ${d.verdict === 'allow' ? 'pill-allow' : 'pill-deny'}`}>
                      {d.verdict}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{d.trustScore}</span> / 100
                  </td>
                  <td>
                    <button 
                      className="btn-ghost-sm"
                      style={{ padding: '4px 8px', fontSize: '11px' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectDecision(d);
                      }}
                    >
                      Breakdown <ChevronRight size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Selected Decision Detail Card */}
        {selectedDecision && (
          <div style={{ marginTop: '20px', padding: '20px', borderRadius: '12px', background: 'rgba(10, 16, 28, 0.95)', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FileText className="text-cyan-400" size={18} />
                <h3 style={{ fontSize: '15px', fontWeight: '700', color: 'var(--text-primary)' }}>
                  Decision Detail: {selectedDecision.id}
                </h3>
              </div>
              <span className={`pill ${selectedDecision.verdict === 'allow' ? 'pill-allow' : 'pill-deny'}`}>
                VERDICT: {selectedDecision.verdict} ({selectedDecision.mode})
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px', marginBottom: '16px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              <div style={{ padding: '10px 14px', background: 'rgba(6, 10, 18, 0.7)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>Image Subject:</div>
                <div style={{ color: 'var(--text-primary)', fontWeight: '600', marginTop: '2px', wordBreak: 'break-all' }}>
                  {selectedDecision.image}
                </div>
              </div>
              <div style={{ padding: '10px 14px', background: 'rgba(6, 10, 18, 0.7)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>Digest:</div>
                <div style={{ color: 'var(--text-primary)', fontWeight: '600', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {selectedDecision.digest}
                </div>
              </div>
              <div style={{ padding: '10px 14px', background: 'rgba(6, 10, 18, 0.7)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>Trust Score:</div>
                <div style={{ color: selectedDecision.trustScore >= 70 ? '#34d399' : '#fb7185', fontWeight: '700', fontSize: '16px', marginTop: '2px' }}>
                  {selectedDecision.trustScore} / 100
                </div>
              </div>
            </div>

            {selectedDecision.failedRule ? (
              <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(244, 63, 94, 0.12)', border: '1px solid rgba(244, 63, 94, 0.35)', fontSize: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#fb7185', fontWeight: '700', marginBottom: '4px' }}>
                  <AlertTriangle size={16} /> Rule Violation: {selectedDecision.failedRule}
                </div>
                <div style={{ color: 'var(--text-secondary)', marginBottom: '8px' }}>
                  <strong>Reason:</strong> {selectedDecision.reason}
                </div>
                <div style={{ color: '#34d399', fontFamily: 'var(--font-mono)' }}>
                  <strong>Remediation:</strong> {selectedDecision.remediation}
                </div>
              </div>
            ) : (
              <div style={{ padding: '14px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', fontSize: '12px', color: '#34d399', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} />
                All 8 mandatory supply chain policy rules evaluated and passed successfully. Zero exemptions required.
              </div>
            )}
          </div>
        )}
      </section>
    </main>
  );
};
