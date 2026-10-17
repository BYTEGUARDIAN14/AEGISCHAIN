package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestAdmissionServer(t *testing.T) *AdmissionServer {
	ctx := context.Background()
	tempDir := t.TempDir()

	certFile := filepath.Join(tempDir, "tls.crt")
	keyFile := filepath.Join(tempDir, "tls.key")
	_, err := GenerateSelfSignedCert(certFile, keyFile)
	require.NoError(t, err)

	cfg := Config{
		Port:              "8443",
		TLSCertFile:       certFile,
		TLSKeyFile:        keyFile,
		PoliciesDir:       filepath.Join("..", "..", "policies"),
		DataDir:           filepath.Join("..", "..", "policies", "data"),
		PublicKeyPath:     filepath.Join("..", "..", "deploy", "keys", "cosign.pub"),
		EnforceNamespaces: []string{"prod", "default"},
		AuditNamespaces:   []string{"staging", "dev"},
		DefaultMode:       "enforce",
		Timeout:           5 * time.Second,
	}

	server, err := NewAdmissionServer(ctx, cfg)
	require.NoError(t, err)
	return server
}

func TestHealthAndReadyProbes(t *testing.T) {
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Test /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"healthy"`)

	// Test /readyz
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"ready"`)
}

func TestExcludedNamespaceAutoAdmit(t *testing.T) {
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	reviewReq := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       "test-uid-system",
			Namespace: "kube-system",
			Kind:      GroupVersionKind{Kind: "Pod"},
			Object:    json.RawMessage(`{"metadata":{"name":"core-dns"},"spec":{"containers":[{"name":"dns","image":"unverified-image:latest"}]}}`),
		},
	}
	body, _ := json.Marshal(reviewReq)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp AdmissionReview
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Response.Allowed)
}

func TestBreakGlassAuthorization(t *testing.T) {
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	now := time.Now().UTC()
	validExpiry := now.Add(1 * time.Hour).Format(time.RFC3339)
	expiredDate := now.Add(-1 * time.Hour).Format(time.RFC3339)
	overLimitExpiry := now.Add(3 * time.Hour).Format(time.RFC3339)

	t.Run("Valid emergency break glass token is admitted with warning", func(t *testing.T) {
		podJSON := `{
			"metadata": {
				"name": "emergency-pod",
				"namespace": "prod",
				"annotations": {
					"aegischain.dev/break-glass": "true",
					"aegischain.dev/break-glass-token": "EMERGENCY_SEC_AUTH_TOKEN_778899",
					"aegischain.dev/break-glass-approver": "sec-ops@byteaegis.in",
					"aegischain.dev/break-glass-reason": "Production outage incident INC-9901",
					"aegischain.dev/break-glass-expires": "` + validExpiry + `"
				}
			},
			"spec": {
				"containers": [{"name": "hotfix", "image": "registry:2"}]
			}
		}`

		reviewReq := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       "test-break-glass-valid",
				Namespace: "prod",
				Kind:      GroupVersionKind{Kind: "Pod"},
				Object:    json.RawMessage(podJSON),
			},
		}

		body, _ := json.Marshal(reviewReq)
		req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp AdmissionReview
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Response.Allowed)
		require.NotEmpty(t, resp.Response.Warnings)
		assert.Contains(t, resp.Response.Warnings[0], "[BREAK-GLASS]")
	})

	t.Run("Expired break glass token is rejected in enforce mode", func(t *testing.T) {
		podJSON := `{
			"metadata": {
				"name": "expired-pod",
				"namespace": "prod",
				"annotations": {
					"aegischain.dev/break-glass": "true",
					"aegischain.dev/break-glass-token": "EMERGENCY_SEC_AUTH_TOKEN_778899",
					"aegischain.dev/break-glass-approver": "sec-ops@byteaegis.in",
					"aegischain.dev/break-glass-reason": "Expired hotfix",
					"aegischain.dev/break-glass-expires": "` + expiredDate + `"
				}
			},
			"spec": {
				"containers": [{"name": "hotfix", "image": "registry:2"}]
			}
		}`

		reviewReq := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       "test-break-glass-expired",
				Namespace: "prod",
				Kind:      GroupVersionKind{Kind: "Pod"},
				Object:    json.RawMessage(podJSON),
			},
		}

		body, _ := json.Marshal(reviewReq)
		req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp AdmissionReview
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Response.Allowed)
		assert.Contains(t, resp.Response.Status.Message, "AegisChain Policy Enforce Denial")
	})

	t.Run("Break glass token exceeding 2 hour max window is rejected", func(t *testing.T) {
		bg := parseBreakGlass(map[string]string{
			"aegischain.dev/break-glass":         "true",
			"aegischain.dev/break-glass-token":   "EMERGENCY_SEC_AUTH_TOKEN_778899",
			"aegischain.dev/break-glass-approver": "sec@byteaegis.in",
			"aegischain.dev/break-glass-reason":   "Long waiver",
			"aegischain.dev/break-glass-expires":  overLimitExpiry,
		})
		assert.False(t, server.validateBreakGlass(bg))
	})
}

func TestAuditVsEnforceMode(t *testing.T) {
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	podJSON := `{
		"metadata": {"name": "app-workload"},
		"spec": {
			"containers": [{"name": "app", "image": "registry:2"}]
		}
	}`

	// 1. In 'staging' namespace (audit mode): policy violation generates warning but allows
	t.Run("Audit mode allows with warning", func(t *testing.T) {
		reviewReq := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       "audit-uid-1",
				Namespace: "staging",
				Kind:      GroupVersionKind{Kind: "Pod"},
				Object:    json.RawMessage(podJSON),
			},
		}
		body, _ := json.Marshal(reviewReq)
		req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp AdmissionReview
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Response.Allowed)
		require.NotEmpty(t, resp.Response.Warnings)
		assert.Contains(t, resp.Response.Warnings[0], "[AUDIT WARNING]")
	})

	// 2. In 'prod' namespace (enforce mode): policy violation blocks admission
	t.Run("Enforce mode denies unsigned container", func(t *testing.T) {
		reviewReq := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       "enforce-uid-1",
				Namespace: "prod",
				Kind:      GroupVersionKind{Kind: "Pod"},
				Object:    json.RawMessage(podJSON),
			},
		}
		body, _ := json.Marshal(reviewReq)
		req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp AdmissionReview
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Response.Allowed)
		assert.Equal(t, int32(403), resp.Response.Status.Code)
		assert.Contains(t, resp.Response.Status.Message, "Policy Enforce Denial")
	})
}

func TestMutatingWebhookEndpoint(t *testing.T) {
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	podJSON := `{
		"metadata": {"name": "app-workload", "namespace": "prod"},
		"spec": {
			"containers": [{"name": "app", "image": "localhost:5001/sample-app:v1.0.0"}]
		}
	}`

	reviewReq := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       "mutate-uid-1",
			Namespace: "prod",
			Kind:      GroupVersionKind{Kind: "Pod"},
			Object:    json.RawMessage(podJSON),
		},
	}
	body, _ := json.Marshal(reviewReq)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp AdmissionReview
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Response.Allowed)
	if resp.Response.Patch != nil {
		assert.Equal(t, "JSONPatch", resp.Response.PatchType)
		assert.Contains(t, string(resp.Response.Patch), "aegischain.dev~1verified-by")
	}
}

func TestSelfSignedCertGeneration(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "tls.crt")
	keyFile := filepath.Join(tempDir, "tls.key")

	pemData, err := GenerateSelfSignedCert(certFile, keyFile)
	require.NoError(t, err)
	assert.NotEmpty(t, pemData)

	_, err = os.Stat(certFile)
	assert.NoError(t, err)
	_, err = os.Stat(keyFile)
	assert.NoError(t, err)
}
