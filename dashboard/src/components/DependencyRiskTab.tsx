import { Search, CheckCircle2, Code2 } from 'lucide-react';
import { type PackageRiskResult } from '../types';

interface DependencyRiskTabProps {
  pkgSearch: string;
  onPkgSearchChange: (name: string) => void;
  pkgResult: PackageRiskResult | null;
  onEvaluatePkg: (name: string) => void;
}

export const DependencyRiskTab = ({
  pkgSearch,
  onPkgSearchChange,
  pkgResult,
  onEvaluatePkg,
}: DependencyRiskTabProps) => {
  return (
    <main className="space-y-6" id="view-risk">
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ marginBottom: '18px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>
            Dependency Risk Scorer (Heuristic AST Analyzer)
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Detects typosquatting via Damerau-Levenshtein, corporate namespace dependency confusion, and install-time AST malicious scripts
          </p>
        </div>

        {/* Presets */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)', alignSelf: 'center', marginRight: '4px' }}>Presets:</span>
          <button className="chip-btn" onClick={() => onEvaluatePkg('crossenv')}>crossenv (Malicious)</button>
          <button className="chip-btn" onClick={() => onEvaluatePkg('requsts')}>requsts (Typosquat)</button>
          <button className="chip-btn" onClick={() => onEvaluatePkg('byteaegis-auth')}>byteaegis-auth (Confusion)</button>
          <button className="chip-btn" onClick={() => onEvaluatePkg('requests')}>requests (Clean)</button>
          <button className="chip-btn" onClick={() => onEvaluatePkg('colorama')}>colorama (Clean)</button>
        </div>

        <div className="search-bar">
          <input 
            id="input-pkg-search"
            type="text" 
            className="search-input"
            placeholder="Enter dependency package name (e.g. crossenv, requsts, lodash, byteaegis-auth)..."
            value={pkgSearch}
            onChange={(e) => onPkgSearchChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                onEvaluatePkg(pkgSearch);
              }
            }}
          />
          <button 
            id="btn-score-pkg"
            className="btn-primary" 
            onClick={() => onEvaluatePkg(pkgSearch)}
          >
            <Search size={16} /> Score Package
          </button>
        </div>

        {/* Risk Scorer Result Card */}
        {pkgResult && (
          <div style={{ marginTop: '20px', padding: '22px', borderRadius: '14px', background: 'rgba(12, 17, 30, 0.95)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                  {pkgResult.name} <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>({pkgResult.ecosystem})</span>
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Corpus: Top 5,000 PyPI & npm packages + OSV Advisory Catalog
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Level</div>
                  <span className={`pill ${pkgResult.score >= 65 ? 'pill-deny' : 'pill-allow'}`} style={{ fontSize: '13px', padding: '4px 12px' }}>
                    {pkgResult.riskLevel} ({pkgResult.score} / 100)
                  </span>
                </div>
              </div>
            </div>

            {/* Factors List */}
            {pkgResult.factors.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '20px' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Flagged Heuristic Threat Vectors:
                </div>
                {pkgResult.factors.map((f, i) => (
                  <div key={i} style={{ padding: '12px 16px', borderRadius: '10px', background: 'rgba(6, 10, 18, 0.7)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '700' }}>{f.name}</span>
                      <span className="pill pill-deny">+{f.score} PTS ({f.severity})</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{f.evidence}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '16px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', color: '#34d399', display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', fontSize: '13px' }}>
                <CheckCircle2 size={18} />
                Zero typosquatting, corporate namespace confusion, or suspicious install-time lifecycle hooks detected. Clean bill of health.
              </div>
            )}

            {/* AST Code Snippet Inspector */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                <Code2 size={16} className="text-cyan-400" />
                <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Abstract Syntax Tree (AST) Inspection Snippet:
                </span>
              </div>
              <pre style={{ margin: 0, padding: '14px', borderRadius: '8px', background: '#05070d', border: '1px solid var(--border-subtle)', color: '#38bdf8', fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: '1.5', overflowX: 'auto' }}>
                {pkgResult.astSnippet}
              </pre>
            </div>
          </div>
        )}
      </section>
    </main>
  );
};
