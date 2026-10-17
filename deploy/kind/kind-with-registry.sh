#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

CLUSTER_NAME="aegischain-cluster"
reg_name='aegis-registry'
reg_port='5001'

# 1. Create registry container unless it already exists
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker rm -f "${reg_name}" 2>/dev/null || true
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --network bridge --name "${reg_name}" \
    registry:2
fi

# 2. Create kind cluster with containerd registry config dir enabled
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
  kind create cluster --name "${CLUSTER_NAME}" --config deploy/kind/kind-config.yaml
else
  kubectl config use-context "kind-${CLUSTER_NAME}"
fi

# 3. Add registry config to containerd inside kind control plane
REGISTRY_DIR="/etc/containerd/certs.d/localhost:${reg_port}"
docker exec "${CLUSTER_NAME}-control-plane" mkdir -p "${REGISTRY_DIR}"
cat <<EOF | docker exec -i "${CLUSTER_NAME}-control-plane" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
server = "http://${reg_name}:5000"

[host."http://${reg_name}:5000"]
  capabilities = ["pull", "resolve", "push"]
  skip_verify = true
EOF

# 4. Connect the registry to the cluster network if not already connected
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  docker network connect "kind" "${reg_name}"
fi

# 5. Document the local registry
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

echo ">>> [AegisChain] Kind cluster and local registry are ready."
