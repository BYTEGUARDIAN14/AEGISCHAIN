$ErrorActionPreference = "Stop"

Write-Host ">>> [AegisChain] Deploying Admission Webhook to kind cluster..." -ForegroundColor Cyan

# 1. Apply CRD
kubectl apply -f deploy/helm/aegischain/crds/trustpolicy.yaml

# 2. Create namespaces & base deployment manifests
kubectl apply -f deploy/manifests/webhook-deploy.yaml

# 3. Create or replace TLS Secret in aegischain-system
$certBytes = [System.IO.File]::ReadAllBytes("deploy/certs/tls.crt")
$keyBytes = [System.IO.File]::ReadAllBytes("deploy/certs/tls.key")
$certB64 = [Convert]::ToBase64String($certBytes)
$keyB64 = [Convert]::ToBase64String($keyBytes)

$secretYaml = @"
apiVersion: v1
kind: Secret
metadata:
  name: aegischain-webhook-tls
  namespace: aegischain-system
type: kubernetes.io/tls
data:
  tls.crt: $certB64
  tls.key: $keyB64
"@

$secretYaml | kubectl apply -f -

# 4. Wait for Webhook Deployment to be Ready
Write-Host "Waiting for aegischain-admission-webhook deployment to roll out..."
kubectl rollout restart deployment/aegischain-admission-webhook -n aegischain-system
kubectl rollout status deployment/aegischain-admission-webhook -n aegischain-system --timeout=60s

# 5. Apply ValidatingWebhookConfiguration with CA Bundle
$webhookConfigYaml = @"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: aegischain-admission-webhook
webhooks:
  - name: validate.aegischain.dev
    admissionReviewVersions:
      - v1
    sideEffects: None
    timeoutSeconds: 5
    failurePolicy: Fail
    clientConfig:
      service:
        name: aegischain-admission-webhook
        namespace: aegischain-system
        path: /validate
        port: 443
      caBundle: $certB64
    rules:
      - operations:
          - CREATE
          - UPDATE
        apiGroups:
          - ""
        apiVersions:
          - v1
        resources:
          - pods
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
            - kube-system
            - kube-public
            - kube-node-lease
            - aegischain-system
            - local-path-storage
"@

$webhookConfigYaml | kubectl apply -f -

# 6. Apply TrustPolicy CRDs for prod and staging
$prodPolicyYaml = @"
apiVersion: aegischain.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: prod-strict-policy
  namespace: prod
spec:
  mode: enforce
  requireSignatures: true
  allowedIdentities:
    - "^https://github.com/BYTEGUARDIAN14/.*"
  requireProvenance: true
  trustedBuilders:
    - "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
  requireSBOM: true
  maxVulnerabilitySeverity: CRITICAL
  blockKEV: true
  maxDependencyRiskScore: 65
  antiRollback: true
"@

$prodPolicyYaml | kubectl apply -f -

Write-Host ">>> [AegisChain] Admission Webhook successfully deployed and active in kind cluster!" -ForegroundColor Green
kubectl get pods -n aegischain-system -o wide
