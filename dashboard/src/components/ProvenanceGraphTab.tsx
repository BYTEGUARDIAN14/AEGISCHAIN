import { Fragment } from 'react';
import { CheckCircle2, Lock, ArrowRight, Code2, Copy, Check } from 'lucide-react';
import { type ProvenanceNodeData, PROVENANCE_FLOW } from '../types';

interface ProvenanceGraphTabProps {
  selectedNode: ProvenanceNodeData;
  onSelectNode: (node: ProvenanceNodeData) => void;
  copiedId: string | null;
  onCopyJson: (json: string, id: string) => void;
}

export const ProvenanceGraphTab = ({
  selectedNode,
  onSelectNode,
  copiedId,
  onCopyJson,
}: ProvenanceGraphTabProps) => {
  return (
    <main className="space-y-6" id="view-graph">
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>
              End-to-End Cryptographic Provenance Graph
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Verified Chain of Custody from Git Source Commit to Kubernetes Admission
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="pill pill-verified">SLSA BUILD LEVEL 3</span>
            <span className="pill pill-allow">SIGSTORE KEYLESS VERIFIED</span>
            <span className="pill pill-purple">IN-TOTO v1</span>
          </div>
        </div>

        {/* Visual Flow Pipeline */}
        <div className="provenance-flow-container my-6" style={{ background: 'rgba(6, 10, 18, 0.7)', borderRadius: '14px', border: '1px solid var(--border-subtle)' }}>
          <div className="provenance-flow">
            {PROVENANCE_FLOW.map((node, idx) => (
              <Fragment key={node.id}>
                <div 
                  id={`node-${node.id}`}
                  className={`graph-node node-verified ${selectedNode.id === node.id ? 'node-active' : ''}`}
                  onClick={() => onSelectNode(node)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)', textTransform: 'uppercase' }}>
                      {node.type}
                    </span>
                    <CheckCircle2 size={16} className="text-emerald-400" />
                  </div>
                  <h3 style={{ fontWeight: '700', fontSize: '14px', color: 'var(--text-primary)' }}>
                    {node.title}
                  </h3>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {node.subtitle}
                  </p>
                </div>
                {idx < PROVENANCE_FLOW.length - 1 && (
                  <div className="graph-arrow" aria-hidden="true">
                    <span>VERIFIED</span>
                    <ArrowRight size={16} />
                  </div>
                )}
              </Fragment>
            ))}
          </div>
        </div>

        {/* Node Inspection Details */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '18px' }}>
          <div style={{ padding: '18px', borderRadius: '12px', background: 'rgba(12, 17, 30, 0.9)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Lock size={16} className="text-cyan-400" />
                <h3 style={{ fontWeight: '700', fontSize: '14px', color: 'var(--text-primary)' }}>
                  Verification Claims: {selectedNode.title}
                </h3>
              </div>
              <span className="pill pill-allow" style={{ fontSize: '10px' }}>CRYPTOGRAPHIC PROOF OK</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              {Object.entries(selectedNode.details).map(([k, v]) => (
                <div key={k} style={{ padding: '8px 12px', borderRadius: '6px', background: 'rgba(6, 10, 18, 0.7)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>{k}:</span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: '600', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '65%' }}>
                    {v}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Raw JSON in-toto attestation payload preview */}
          <div style={{ padding: '18px', borderRadius: '12px', background: 'rgba(12, 17, 30, 0.9)', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Code2 size={16} className="text-purple-400" />
                <span style={{ fontWeight: '700', fontSize: '13px', color: 'var(--text-primary)' }}>
                  Raw In-Toto Statement Payload
                </span>
              </div>
              {selectedNode.rawJson && (
                <button 
                  className="btn-ghost-sm"
                  onClick={() => onCopyJson(selectedNode.rawJson || '', selectedNode.id)}
                >
                  {copiedId === selectedNode.id ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  <span>Copy JSON</span>
                </button>
              )}
            </div>

            <pre style={{ flex: 1, margin: 0, padding: '12px', borderRadius: '8px', background: '#05070d', border: '1px solid var(--border-subtle)', color: '#a5b4fc', fontFamily: 'var(--font-mono)', fontSize: '11px', overflowX: 'auto', lineHeight: '1.5' }}>
              {selectedNode.rawJson || '// No raw JSON available for this step'}
            </pre>
          </div>
        </div>
      </section>
    </main>
  );
};
