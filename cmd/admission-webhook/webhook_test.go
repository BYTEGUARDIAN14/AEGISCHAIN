package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteaegis/aegischain/internal/ledger"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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

func TestAdmitThenRevokeDigestDenial(t *testing.T) {
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	targetDigest := "sha256:a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123"
	imageRef := "localhost:5001/app@" + targetDigest

	// 1. Seed valid admission in evaluation cache with policy version and key fingerprint
	cacheKey := fmt.Sprintf("%s:%s:%s:%s", "prod", targetDigest, server.policyVersion, server.trustedKeyFingerprint)
	server.cacheEvaluation(cacheKey, "allow", 100, []ledger.RuleResult{
		{ID: "signature_required", Result: "pass"},
	}, nil)

	// Send initial AdmissionReview -> MUST BE ADMITTED
	podJSON := fmt.Sprintf(`{
		"metadata": {"name": "revocation-workload", "namespace": "prod"},
		"spec": {
			"containers": [{"name": "app", "image": %q}]
		}
	}`, imageRef)

	reviewReq := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       "admit-req-001",
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
	assert.True(t, resp.Response.Allowed, "Expected image to be initially admitted from cache")

	// 2. Revoke the digest and flush cache
	server.RevokeDigest(targetDigest)

	// Verify cache key was flushed
	server.evaluationCacheMu.RLock()
	_, inCache := server.evaluationCache[cacheKey]
	server.evaluationCacheMu.RUnlock()
	assert.False(t, inCache, "Expected revoked digest to be flushed from evaluation cache")
	assert.True(t, server.resolver.IsRevoked(targetDigest), "Expected digest to be flagged as revoked in resolver")

	// 3. Send subsequent AdmissionReview for same revoked digest -> MUST BE DENIED
	reqRevoked := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rrRevoked := httptest.NewRecorder()
	mux.ServeHTTP(rrRevoked, reqRevoked)

	assert.Equal(t, http.StatusOK, rrRevoked.Code)
	var respRevoked AdmissionReview
	err = json.Unmarshal(rrRevoked.Body.Bytes(), &respRevoked)
	require.NoError(t, err)
	assert.False(t, respRevoked.Response.Allowed, "Expected revoked digest to be denied admission")
	assert.Equal(t, int32(403), respRevoked.Response.Status.Code)
	assert.Contains(t, respRevoked.Response.Status.Message, "revocation_check")
}

func TestMutatingWebhookPreventsTagRetargetPoisoning(t *testing.T) {
	// Start local in-memory registry
	regHandler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	regListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer regListener.Close()

	regServer := &http.Server{Handler: regHandler}
	go func() { _ = regServer.Serve(regListener) }()

	regAddr := regListener.Addr().String()
	imgTagRef := fmt.Sprintf("%s/secure-workload:v1.0.0", regAddr)

	// Step 1: Push legitimate image A
	refA, err := name.ParseReference(imgTagRef, name.Insecure)
	require.NoError(t, err)
	imgA, _ := random.Image(512, 1)
	err = remote.Write(refA, imgA)
	require.NoError(t, err)
	descA, err := remote.Head(refA)
	require.NoError(t, err)
	digestA := descA.Digest.String()

	// Step 2: Submit Pod referencing mutable tag to /mutate
	server := setupTestAdmissionServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	podJSON := fmt.Sprintf(`{
		"metadata": {"name": "app-workload", "namespace": "prod"},
		"spec": {
			"containers": [{"name": "app", "image": %q}]
		}
	}`, imgTagRef)

	reviewReq := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       "mutate-test-01",
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
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Response.Allowed)
	require.NotNil(t, resp.Response.Patch)

	var patches []JSONPatchOperation
	err = json.Unmarshal(resp.Response.Patch, &patches)
	require.NoError(t, err)

	// Find image replacement patch
	var mutatedImage string
	for _, p := range patches {
		if p.Path == "/spec/containers/0/image" && p.Op == "replace" {
			mutatedImage = p.Value.(string)
		}
	}
	expectedPinnedImage := fmt.Sprintf("%s/secure-workload@%s", regAddr, digestA)
	assert.Equal(t, expectedPinnedImage, mutatedImage, "Mutating webhook must pin tag to exact immutable digest")

	// Step 3: Attacker retargets the mutable tag in registry to malicious image B
	imgB, _ := random.Image(2048, 2)
	err = remote.Write(refA, imgB)
	require.NoError(t, err)
	descB, err := remote.Head(refA)
	require.NoError(t, err)
	digestB := descB.Digest.String()
	require.NotEqual(t, digestA, digestB, "Registry tag must have drifted to new digest")

	// Step 4: Prove that the mutated Pod spec CANNOT be poisoned by the retargeted tag
	// Any node resolving the mutated image reference still pulls digestA, ignoring retargeted tag
	mutatedRef, err := name.ParseReference(mutatedImage, name.Insecure)
	require.NoError(t, err)
	descMutated, err := remote.Head(mutatedRef)
	require.NoError(t, err)
	assert.Equal(t, digestA, descMutated.Digest.String(), "Mutated pod must pull digest A, immune to retargeted tag")
	assert.NotEqual(t, digestB, descMutated.Digest.String(), "Mutated pod cannot pull poisoned digest B")
}

func TestDSSEInProcessAttestationVerification(t *testing.T) {
	// 1. Generate trusted keypair
	trustedPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	trustedPub := &trustedPriv.PublicKey

	// Generate untrusted/attacker keypair
	attackerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// 2. Build in-toto statement payload
	payloadType := "application/vnd.in-toto+json"
	statementJSON := []byte(`{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "app", "digest": {"sha256": "1122334455667788990011223344556677889900112233445566778899001122"}}],
		"predicateType": "https://cyclonedx.org/schema",
		"predicate": {"bomFormat": "CycloneDX", "specVersion": "1.4"}
	}`)

	// 3. Compute DSSE Pre-Authentication Encoding (PAE)
	pae := dssePAE(payloadType, statementJSON)
	h := sha256.Sum256(pae)

	// 4. Sign PAE with trusted key
	sigBytes, err := ecdsa.SignASN1(rand.Reader, trustedPriv, h[:])
	require.NoError(t, err)

	// 5. Construct valid DSSEEnvelope
	validEnvelope := DSSEEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(statementJSON),
	}
	validEnvelope.Signatures = []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{
		{KeyID: "", Sig: base64.StdEncoding.EncodeToString(sigBytes)},
	}

	// 6. Test In-Process Verification of Valid Envelope
	decodedPayload, err := base64.StdEncoding.DecodeString(validEnvelope.Payload)
	require.NoError(t, err)
	decodedSig, err := base64.StdEncoding.DecodeString(validEnvelope.Signatures[0].Sig)
	require.NoError(t, err)

	verifyPAE := dssePAE(validEnvelope.PayloadType, decodedPayload)
	verifyH := sha256.Sum256(verifyPAE)
	assert.True(t, ecdsa.VerifyASN1(trustedPub, verifyH[:], decodedSig), "Valid DSSE envelope MUST pass cryptographic verification")

	// 7. Test In-Process Rejection of Tampered Payload
	tamperedJSON := bytes.ReplaceAll(statementJSON, []byte("CycloneDX"), []byte("MaliciousBOM"))
	tamperedPAE := dssePAE(validEnvelope.PayloadType, tamperedJSON)
	tamperedH := sha256.Sum256(tamperedPAE)
	assert.False(t, ecdsa.VerifyASN1(trustedPub, tamperedH[:], decodedSig), "Tampered DSSE payload MUST fail cryptographic verification")

	// 8. Test In-Process Rejection of Attacker Signature (Wrong Key)
	attackerSigBytes, err := ecdsa.SignASN1(rand.Reader, attackerPriv, h[:])
	require.NoError(t, err)
	assert.False(t, ecdsa.VerifyASN1(trustedPub, h[:], attackerSigBytes), "Attacker-signed DSSE envelope MUST fail verification against trusted key")

	// 9. Test In-Process Rejection of Corrupted Signature
	corruptedSig := make([]byte, len(sigBytes))
	copy(corruptedSig, sigBytes)
	corruptedSig[len(corruptedSig)-1] ^= 0xFF
	assert.False(t, ecdsa.VerifyASN1(trustedPub, h[:], corruptedSig), "Corrupted signature bytes MUST fail verification")
}

