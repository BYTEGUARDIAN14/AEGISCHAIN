# AegisChain Operations and Incident Response Runbook

## 1. Routine Platform Operations

### Verifying Cluster Health
```bash
kubectl -n aegischain-system get pods -l app=aegischain
kubectl -n aegischain-system logs -l app=aegischain -c trust-engine --tail=100
```

### Checking Ledger Integrity
Execute an append-only hash chain integrity check:
```bash
aegischain ledger verify --endpoint https://aegischain.aegischain-system.svc.cluster.local:8443
```
Expected output:
```
[PASS] Ledger contains 1,482 decisions. Hash chain verified from genesis root. Zero tampering detected.
```

## 2. Emergency Break-Glass Procedure

If a critical business outage occurs due to webhook network isolation, and emergency pods must be scheduled in an enforced namespace, use the signed break-glass token:

1. Generate emergency token signed by designated Break-Glass Key:
   ```bash
   aegischain break-glass generate \
     --namespace prod \
     --workload payment-processor \
     --duration 1h \
     --reason "INC-8891: Resolving critical payment gateway outage" \
     --key /etc/aegischain/break-glass.key
   ```
2. Annotate the deployment manifest:
   ```yaml
   metadata:
     annotations:
       aegischain.dev/break-glass-token: "<TOKEN>"
   ```
3. Apply the workload. The admission controller validates the token signature and expiration, admits the workload, and writes a high-priority audit entry to the ledger.

## 3. Incident Response: Compromised Signing Identity

If a GitHub repository or CI workflow signing key/identity is reported compromised:

1. **Immediate Revocation**: Update `policies/data/revocations.json` with the compromised identity or certificate serial number:
   ```json
   {
     "revocations": [
       {
         "type": "certificate_identity",
         "value": "https://github.com/compromised-org/compromised-repo/.github/workflows/build.yml@refs/heads/main",
         "revoked_at": "2026-10-17T13:00:00Z",
         "reason": "CI token exfiltration in runner environment"
       }
     ]
   }
   ```
2. **Hot-Reload Policy Bundle**:
   ```bash
   aegischain policy reload --namespace prod
   ```
3. **Invalidate Trust Engine Cache**:
   The engine immediately invalidates all cached decisions for workloads matching the revoked identity.
4. **Identify Affected Workloads**:
   ```bash
   aegischain query --identity "https://github.com/compromised-org/compromised-repo/*" --since 7d
   ```

## 4. Key and Trust Root Rotation

### Fulcio CA Root or TUF Root Rotation
When updating the trusted Sigstore root:
1. Update `policies/data/trusted_roots.json`.
2. Run `aegischain policy test` in CI to ensure all positive test vectors still evaluate cleanly.
3. Deploy the updated Helm values to the admission controller:
   ```bash
   helm upgrade aegischain deploy/helm/aegischain -n aegischain-system -f production-values.yaml
   ```
