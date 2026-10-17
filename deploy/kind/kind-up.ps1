$ErrorActionPreference = "Continue"

$ClusterName = "aegischain-cluster"
$RegName = "aegis-registry"
$RegPort = 5001

Write-Host ">>> [AegisChain] Bootstrapping local OCI registry and kind cluster..." -ForegroundColor Cyan

# 1. Create registry container unless it already exists
$regExisting = docker ps -a --filter "name=^/${RegName}$" --format "{{.Names}}"
if (-not $regExisting) {
    Write-Host "Starting local registry container '$RegName' on port $RegPort..."
    docker run -d --restart=always -p "127.0.0.1:${RegPort}:5000" --network bridge --name $RegName registry:2 | Out-Null
} else {
    $regRunning = docker ps --filter "name=^/${RegName}$" --format "{{.Names}}"
    if (-not $regRunning) {
        Write-Host "Starting stopped registry container '$RegName'..."
        docker start $RegName | Out-Null
    } else {
        Write-Host "Local registry '$RegName' is already running on port $RegPort."
    }
}

# 2. Check if kind cluster already exists
$clusters = kind get clusters 2>$null
if ($clusters -notcontains $ClusterName) {
    Write-Host "Creating kind cluster '$ClusterName'..."
    kind create cluster --name $ClusterName --config deploy/kind/kind-config.yaml
} else {
    Write-Host "Kind cluster '$ClusterName' already exists. Switching context..."
    kubectl config use-context "kind-$ClusterName" | Out-Null
}

# 3. Add registry config to containerd inside kind control-plane
$regDir = "/etc/containerd/certs.d/localhost:${RegPort}"
$hostsToml = @"
server = "http://${RegName}:5000"

[host."http://${RegName}:5000"]
  capabilities = ["pull", "resolve", "push"]
  skip_verify = true
"@

docker exec "${ClusterName}-control-plane" mkdir -p $regDir 2>$null
$bytes = [System.Text.Encoding]::UTF8.GetBytes($hostsToml)
$base64 = [Convert]::ToBase64String($bytes)
docker exec "${ClusterName}-control-plane" sh -c "echo $base64 | base64 -d > ${regDir}/hosts.toml" 2>$null

# 4. Connect registry to kind network if not already connected
$netInspect = docker network inspect kind -f '{{range .Containers}}{{.Name}} {{end}}' 2>$null
if ($netInspect -notmatch $RegName) {
    docker network connect kind $RegName 2>$null | Out-Null
}

# 5. Document local registry in ConfigMap as per KEP-1755
$configMapYaml = @"
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${RegPort}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
"@
$configMapYaml | kubectl apply -f - | Out-Null

Write-Host ">>> [AegisChain] Cluster and local registry successfully configured!" -ForegroundColor Green
kubectl cluster-info
kubectl get nodes -o wide
