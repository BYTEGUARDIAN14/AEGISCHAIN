import { Code2 } from 'lucide-react';

export const PolicyWaiversTab = () => {
  return (
    <main className="space-y-6" id="view-policies">
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>
              Active OPA Rego v1 Policies
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Embedded Open Policy Agent decision rules enforcing admission criteria
            </p>
          </div>
          <span className="pill pill-verified">POLICY VERSION: v1.0.0 (97.4% TEST COVERAGE)</span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Severity</th>
                <th>Enforcement Action</th>
                <th>Description</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>signature_required</td>
                <td><span className="pill pill-deny">CRITICAL</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>Valid Sigstore keyless signature bound to trusted GitHub Actions workflow identity</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>provenance_required</td>
                <td><span className="pill pill-deny">CRITICAL</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>SLSA Build Level 3 provenance from approved container generator with matching subject digest</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>sbom_required</td>
                <td><span className="pill pill-audit">HIGH</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>CycloneDX or SPDX SBOM attestation present and parseable with non-empty component set</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>vulnerability_gate</td>
                <td><span className="pill pill-deny">CRITICAL</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>Zero unwaived critical vulnerabilities; CISA KEV entries strictly block unless signed VEX is provided</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>base_image_allowlist</td>
                <td><span className="pill pill-audit">HIGH</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>Base image digest must come from approved Google Distroless or Chainguard allowlists</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>dependency_risk_gate</td>
                <td><span className="pill pill-audit">HIGH</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>Dependency risk score must not exceed namespace threshold (65); malicious packages hard block</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>freshness</td>
                <td><span className="pill pill-allow">MEDIUM</span></td>
                <td><span className="mono-text">AUDIT_FAIL</span></td>
                <td>Image build timestamp within 30 days and anti-rollback constraint enforced against deployed versions</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
              <tr>
                <td className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '600' }}>privileged_workload_extra_scrutiny</td>
                <td><span className="pill pill-deny">CRITICAL</span></td>
                <td><span className="mono-text">FAIL_CLOSED</span></td>
                <td>Stricter authorization requirements and attestation check for privileged, hostNetwork, or hostPath pods</td>
                <td><span className="pill pill-allow">ACTIVE</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Embedded Rego Code Viewer Preview */}
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <Code2 size={18} className="text-cyan-400" />
          <h3 style={{ fontSize: '15px', fontWeight: '700', color: 'var(--text-primary)' }}>
            Production OPA Rego v1 Source Code Sample: policies/rego/signature_required.rego
          </h3>
        </div>
        <pre className="rego-code-box">
          <span className="rego-comment"># AegisChain OPA Rego v1 Policy: signature_required</span>{'\n'}
          <span className="rego-keyword">package</span> <span className="rego-pkg">aegischain.policy.signature_required</span>{'\n\n'}
          <span className="rego-keyword">import</span> rego.v1{'\n\n'}
          <span className="rego-keyword">default</span> allow := <span className="rego-keyword">false</span>{'\n\n'}
          allow <span className="rego-keyword">if</span> {'{'}{'\n'}
          {'  '}<span className="rego-comment"># Rule evaluates verified Cosign signatures bound to Rekor</span>{'\n'}
          {'  count(input.signatures) > 0'}{'\n'}
          {'  some sig in input.signatures'}{'\n'}
          {'  sig.verified == true'}{'\n'}
          {'  sig.rekor_log_id != ""'}{'\n'}
          {'}'}{'\n\n'}
          deny <span className="rego-keyword">contains</span> msg <span className="rego-keyword">if</span> {'{'}{'\n'}
          {'  not allow'}{'\n'}
          {'  msg := "Artifact has zero valid cryptographic signatures from approved identity"'}{'\n'}
          {'}'}
        </pre>
      </section>

      {/* Platform Exemptions */}
      <section className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '4px' }}>
          Registered Policy Exemptions & Waivers
        </h3>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
          Time-limited waivers tracked as versioned data. Expired exemptions fail CI gates automatically.
        </p>

        <div style={{ padding: '16px', borderRadius: '10px', background: 'rgba(10, 15, 26, 0.7)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="mono-text" style={{ color: 'var(--color-cyan)', fontWeight: '700', fontSize: '13px' }}>
                EX-2026-BASELINE
              </span>
              <span className="pill pill-allow">ACTIVE (NON-EXPIRED)</span>
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '12px', marginTop: '4px' }}>
              Owner: security@byteaegis.in &bull; Scope: staging namespace
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '2px' }}>
              Reason: Baseline platform exemption template with non-expired timestamp
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Expiration Date</div>
            <div className="mono-text" style={{ color: '#34d399', fontWeight: '700' }}>2027-12-31T23:59:59Z</div>
          </div>
        </div>
      </section>
    </main>
  );
};
