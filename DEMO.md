# AegisChain 3-Minute Demo Script and Video Storyboard

This document provides a concise, three-minute demonstration walkthrough for platform security engineers, SREs, and auditors evaluating AegisChain.

---

## Storyboard Overview

| Timestamp | Scene | Key Narrative | Target Output |
|---|---|---|---|
| **0:00 - 0:45** | Scene 1: The Gold Standard | Legitimate image with SLSA L3 provenance and keyless signature admitted | Pod `clean-workload` enters `Running` state |
| **0:45 - 1:30** | Scene 2: Attack Interception | Unsigned, tampered, and wrong-signer images blocked at admission | `kubectl` admission rejection with rule-level remediation |
| **1:30 - 2:15** | Scene 3: Risk Scorer & OpenVEX | Typosquatting blocked; critical KEV waived via signed OpenVEX | Risk score 100/100; admission unlocked by signed VEX |
| **2:15 - 3:00** | Scene 4: Ledger & Control Plane | Tamper-evident hash chain verification and web control dashboard | `ledger verify` detects tampering; React DAG view |

---

## Scene 1: The Gold Standard (0:00 - 0:45)

**Speaker Script**:
"In modern cloud-native environments, perimeter firewalls cannot prevent software supply chain poisoning. Here, we demonstrate AegisChain running inside a Kubernetes cluster with admission enforcement enabled."

### Command 1: Inspect Policy Mode
```bash
kubectl get trustpolicies.aegischain.dev -A
```
**Expected Output**:
```text
NAMESPACE   NAME             MODE      MIN-SCORE   ENFORCE-ANTIROLLBACK   AGE
prod        prod-defaults    enforce   80          true                   12m
staging     staging-defaults audit     60          false                  12m
```

### Command 2: Deploy Authentic Workload
```bash
kubectl run clean-workload \
  --image=localhost:5001/sample-app:v1.0.0 \
  --namespace=prod
```
**Expected Output**:
```text
pod/clean-workload created
```

### Command 3: Verify Pod Status
```bash
kubectl -n prod get pod clean-workload
```
**Expected Output**:
```text
NAME             READY   STATUS    RESTARTS   AGE
clean-workload   1/1     Running   0          5s
```

---

## Scene 2: Attack Interception (0:45 - 1:30)

**Speaker Script**:
"Now an adversary attempts to bypass our CI/CD pipeline by pushing an unsigned image directly to production."

### Command 4: Deploy Unsigned Image
```bash
kubectl run rogue-workload \
  --image=registry:2 \
  --namespace=prod
```
**Expected Output**:
```text
Error from server (PolicyGateViolation): admission webhook "aegischain.aegischain-system.svc" denied the request:
Container "rogue-workload" (image: registry:2): verification failed (50/100) -
[Rule signature_required] Artifact has zero valid cryptographic signatures.
Remediation: Sign image using GitHub Actions OIDC workflow under approved organization.
Decision ID: a7f8c021-9982-41e1-8890-e328901cb001
```

### Command 5: Inspect Audit Mode in Staging
```bash
kubectl run staging-shadow-it \
  --image=registry:2 \
  --namespace=staging
```
**Expected Output**:
```text
Warning: [AegisChain Audit] Container "staging-shadow-it" violated policy signature_required: Artifact has zero valid cryptographic signatures
pod/staging-shadow-it created
```

---

## Scene 3: Dependency Risk Scorer & OpenVEX (1:30 - 2:15)

**Speaker Script**:
"AegisChain inspects the software bill of materials and performs heuristic static analysis for malicious install hooks, typosquatting, and CISA KEV vulnerabilities."

### Command 6: Evaluate Typosquatted Dependency via CLI
```bash
aegischain score crossenv
```
**Expected Output**:
```text
======================================================================
AEGISCHAIN DEPENDENCY RISK REPORT
Subject: crossenv (npm)
Risk Score: 100 / 100 (CRITICAL RISK)
Verdict: BLOCKED (Hard Gate Triggered)
----------------------------------------------------------------------
Contributing Threat Factors:
[1] osv_malicious_advisory: Listed in MAL-2017-001 (+100 pts)
[2] separator_trick: Exact match on normalized name 'cross-env' (+80 pts)
[3] credential_exfiltration: Postinstall script accesses AWS_SECRET_ACCESS_KEY (+90 pts)
======================================================================
```

### Command 7: Run the Attack Lab Suite
```bash
make attack-lab
```
**Expected Output**:
```text
#   | Scenario Name            | Verdict    | Rule Evaluated               | Latency  | Status
------------------------------------------------------------------------------------------
01  | Clean Verified Workload  | allow      | all_rules                    |   0.56ms | PASS  
02  | Unsigned Container Image | deny       | signature_required           |   0.00ms | PASS  
...
08  | Critical KEV & OpenVEX   | allow*     | vulnerability_gate (waived)  |   0.00ms | PASS  
...
14  | Upstream Outage Degraded | deny/audit | circuit_breaker              |   1.17ms | PASS  
------------------------------------------------------------------------------------------
TOTAL: 14 / 14 SCENARIOS PASSED (Detection & Enforcement Rate: 100.0%)
```

---

## Scene 4: Cryptographic Decision Ledger & Dashboard (2:15 - 3:00)

**Speaker Script**:
"Every admission verdict is recorded in an append-only, hash-chained ledger. If an insider modifies a past decision in the database, AegisChain immediately detects the tampering."

### Command 8: Verify Decision Ledger Integrity
```bash
aegischain ledger verify --ledger bench/results/ledger.jsonl
```
**Expected Output**:
```text
[PASS] Ledger contains 3 decisions.
Hash chain verified from genesis root.
Merkle Head Hash: 3e73a0e6378baeb1b238382ba5db2dc58bf8e622bcf7ca52b7ba40db24068fc2
Integrity: PASS (Zero modifications or deletions detected)
```

### Command 9: Detect Malicious Modification
```bash
aegischain ledger verify --ledger bench/results/ledger-tampered.jsonl
```
**Expected Output**:
```text
[FAIL] Cryptographic hash chain verification failed at record index 1:
  Record Index: 1
  Decision ID:  9bb79958-9447-41ec-b09e-7aa1b67e7c99
  Error:        entry hash does not match computed content digest (record modified in storage)
Exit Code: 1
```

### Command 10: Access React Control Dashboard
Open browser to `http://localhost:5173` to explore:
- High-level KPIs: Admitted vs blocked workloads, active trust score.
- Cryptographic Provenance DAG: Visual chain of custody from Git commit to Kubernetes Pod.
- Decision Explorer: Rule-by-rule evaluations and evidence records.
- Live Dependency Risk Scorer: Interactive Damerau-Levenshtein typosquatting tester.

---

## Screen Recording Guidance

1. **Resolution**: 1920x1080 (16:9 aspect ratio).
2. **Terminal Font**: JetBrains Mono or Fira Code, 16pt, dark background (`#0B0F19`).
3. **Pacing**: Pause for 2 seconds after each command output before speaking the next line.
