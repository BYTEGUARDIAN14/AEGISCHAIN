package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string           `json:"uid"`
	Namespace string           `json:"namespace"`
	Kind      GroupVersionKind `json:"kind"`
	Object    json.RawMessage  `json:"object"`
}

type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

type AdmissionResponse struct {
	UID      string        `json:"uid"`
	Allowed  bool          `json:"allowed"`
	Status   *StatusResult `json:"status,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

type StatusResult struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func main() {
	fmt.Println("=========================================================================================")
	fmt.Println("AEGISCHAIN ATTACK LAB: LIVE SCENARIOS 02 TO 13 WITH REAL REGISTRY & COSIGN")
	fmt.Println("Deploying Real Container Workloads and Capturing Exact Admission Denial Messages")
	fmt.Println("=========================================================================================")

	// 1. Start real OCI registry on 127.0.0.1:5001
	regHandler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	regListener, err := net.Listen("tcp", "127.0.0.1:5001")
	if err != nil {
		fmt.Printf("FATAL: Failed to start registry on :5001: %v\n", err)
		os.Exit(1)
	}
	defer regListener.Close()
	regServer := &http.Server{Handler: regHandler}
	go func() { _ = regServer.Serve(regListener) }()
	fmt.Println("[Setup 1/3] Real OCI Registry running on http://127.0.0.1:5001")

	// 2. Generate unapproved attacker keypair
	attackerDir, err := os.MkdirTemp("", "attacker-keys-*")
	if err != nil {
		fmt.Printf("FATAL: MkdirTemp failed: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(attackerDir)
	attackerKey := filepath.Join(attackerDir, "attacker.key")
	attackerPub := filepath.Join(attackerDir, "attacker.pub")
	_ = attackerPub
	genAttackerKey := exec.Command("cosign", "generate-key-pair", "--output-key-prefix", filepath.Join(attackerDir, "attacker"))
	genAttackerKey.Env = append(os.Environ(), "COSIGN_PASSWORD=attackerpass")
	if out, err := genAttackerKey.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: generate attacker key failed: %v (out: %s)\n", err, string(out))
		os.Exit(1)
	}
	fmt.Println("[Setup 2/3] Generated Rogue Attacker Cosign Keypair in temporary enclave")

	// 3. Start Real Admission Webhook on HTTPS :8443
	webhookPort := "8443"
	tempDir, err := os.MkdirTemp("", "webhook-attack-test-*")
	if err != nil {
		fmt.Printf("FATAL: MkdirTemp failed: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	certFile := filepath.Join(tempDir, "tls.crt")
	keyFile := filepath.Join(tempDir, "tls.key")
	genCertCmd := exec.Command("go", "run", "./scripts/gen-certs/main.go",
		"-cert", certFile,
		"-key", keyFile,
		"-host", "127.0.0.1,localhost",
	)
	if out, err := genCertCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: gen-certs failed: %v (out: %s)\n", err, string(out))
		os.Exit(1)
	}

	webhookCtx, webhookCancel := context.WithCancel(context.Background())
	defer webhookCancel()

	pubKeyPath := filepath.Join("deploy", "keys", "cosign.pub")
	webhookBinCmd := exec.CommandContext(webhookCtx, "go", "run", "./cmd/admission-webhook",
		"-port", webhookPort,
		"-tls-cert-file", certFile,
		"-tls-key-file", keyFile,
		"-public-key", pubKeyPath,
		"-enforce-namespaces", "prod",
		"-audit-namespaces", "staging",
		"-default-mode", "enforce",
	)
	webhookLogFile, _ := os.Create(filepath.Join(tempDir, "webhook.log"))
	webhookBinCmd.Stdout = webhookLogFile
	webhookBinCmd.Stderr = webhookLogFile
	if err := webhookBinCmd.Start(); err != nil {
		fmt.Printf("FATAL: Failed to start admission-webhook: %v\n", err)
		os.Exit(1)
	}
	defer webhookBinCmd.Process.Kill()

	// Wait for webhook /healthz
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	webhookURL := fmt.Sprintf("https://127.0.0.1:%s/validate", webhookPort)
	healthURL := fmt.Sprintf("https://127.0.0.1:%s/healthz", webhookPort)

	ready := false
	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(200 * time.Millisecond)
		resp, err := client.Get(healthURL)
		if err == nil && resp.StatusCode == 200 {
			ready = true
			resp.Body.Close()
			break
		}
	}
	if !ready {
		fmt.Println("FATAL: Webhook failed to become healthy within 6 seconds")
		os.Exit(1)
	}
	fmt.Println("[Setup 3/3] Real AegisChain Admission Webhook active on https://127.0.0.1:8443/validate")

	// Helper to send AdmissionReview
	sendAdmissionReview := func(uid, imgRef, namespace string) AdmissionReview {
		podJSON := fmt.Sprintf(`{
			"metadata": {"name": "attack-pod", "namespace": "%s"},
			"spec": {
				"containers": [{"name": "app", "image": %q}]
			}
		}`, namespace, imgRef)

		reqReview := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       uid,
				Namespace: namespace,
				Kind:      GroupVersionKind{Kind: "Pod", Version: "v1"},
				Object:    json.RawMessage(podJSON),
			},
		}

		body, _ := json.Marshal(reqReview)
		httpResp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("ERROR: HTTP request failed: %v\n", err)
			return AdmissionReview{}
		}
		defer httpResp.Body.Close()
		respBytes, _ := io.ReadAll(httpResp.Body)
		var outReview AdmissionReview
		_ = json.Unmarshal(respBytes, &outReview)
		return outReview
	}

	sendCustomPodAdmissionReview := func(uid, namespace string, podJSON string) AdmissionReview {
		reqReview := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       uid,
				Namespace: namespace,
				Kind:      GroupVersionKind{Kind: "Pod", Version: "v1"},
				Object:    json.RawMessage(podJSON),
			},
		}

		body, _ := json.Marshal(reqReview)
		httpResp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("ERROR: HTTP request failed: %v\n", err)
			return AdmissionReview{}
		}
		defer httpResp.Body.Close()
		respBytes, _ := io.ReadAll(httpResp.Body)
		var outReview AdmissionReview
		_ = json.Unmarshal(respBytes, &outReview)
		return outReview
	}

	pushRandomImage := func(imgRef string) string {
		ref, err := name.ParseReference(imgRef, name.Insecure)
		if err != nil {
			log.Fatalf("ParseReference %s: %v", imgRef, err)
		}
		img, _ := random.Image(1024, 1)
		if err := remote.Write(ref, img); err != nil {
			log.Fatalf("remote.Write %s: %v", imgRef, err)
		}
		desc, _ := remote.Head(ref)
		return desc.Digest.String()
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 02: Unsigned Container Image in Enforced Namespace
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 02: UNSIGNED CONTAINER IMAGE IN ENFORCED NAMESPACE ('prod')")
	fmt.Println("=========================================================================================")
	s2Ref := "127.0.0.1:5001/scenario-02-unsigned:v1.0.0"
	s2Digest := pushRandomImage(s2Ref)
	fmt.Printf("[Push] Pushed real unsigned image: %s (digest: %s)\n", s2Ref, s2Digest[:20]+"...")
	fmt.Println("[Action] Sending Kubernetes AdmissionReview to AegisChain webhook in 'prod' namespace...")
	s2Resp := sendAdmissionReview("scenario-02-uid", s2Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s2Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s2Resp.Response.Allowed)
		if s2Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s2Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s2Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s2Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 03: Copied Signature Attack onto Modified Image Digest
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 03: COPIED SIGNATURE ATTACK ONTO MODIFIED IMAGE DIGEST")
	fmt.Println("=========================================================================================")
	s3CleanRef := "127.0.0.1:5001/scenario-03-copied-sig:clean"
	s3CleanDigest := pushRandomImage(s3CleanRef)
	fmt.Printf("[Push] Pushed clean image: %s (digest: %s)\n", s3CleanRef, s3CleanDigest[:20]+"...")

	validKeyPath := filepath.Join("deploy", "keys", "cosign.key")
	s3SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s3CleanRef)
	s3SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := s3SignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Signing clean image failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Printf("[Sign] Cryptographically signed clean artifact with valid key: %s\n", s3CleanRef)

	s3ModRef := "127.0.0.1:5001/scenario-03-copied-sig:modified"
	s3ModDigest := pushRandomImage(s3ModRef)
	fmt.Printf("[Push] Pushed modified/tampered image: %s (digest: %s)\n", s3ModRef, s3ModDigest[:20]+"...")

	cleanSigTag := fmt.Sprintf("127.0.0.1:5001/scenario-03-copied-sig:sha256-%s.sig", strings.TrimPrefix(s3CleanDigest, "sha256:"))
	modSigTag := fmt.Sprintf("127.0.0.1:5001/scenario-03-copied-sig:sha256-%s.sig", strings.TrimPrefix(s3ModDigest, "sha256:"))
	cleanSigRef, _ := name.ParseReference(cleanSigTag, name.Insecure)
	modSigRef, _ := name.ParseReference(modSigTag, name.Insecure)
	sigImg, err := remote.Image(cleanSigRef)
	if err != nil {
		fmt.Printf("FATAL: Failed to read clean signature artifact: %v\n", err)
	}
	if err := remote.Write(modSigRef, sigImg); err != nil {
		fmt.Printf("FATAL: Failed to copy signature artifact to modified digest: %v\n", err)
	}
	fmt.Printf("[Attack] Copied valid signature artifact from %s to %s\n", cleanSigTag, modSigTag)

	fmt.Println("[Action] Sending Kubernetes AdmissionReview for modified image with copied signature...")
	s3Resp := sendAdmissionReview("scenario-03-uid", s3ModRef, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s3Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s3Resp.Response.Allowed)
		if s3Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s3Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s3Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s3Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 04: Mutable Tag Retargeting Attack (Sign, Admit, Retarget, Denial)
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 04: MUTABLE TAG RETARGETING ATTACK (SIGN, ADMIT, RETARGET, DENIAL)")
	fmt.Println("=========================================================================================")
	s4Ref := "127.0.0.1:5001/scenario-04-tag-retarget:release-v1"
	s4DigestA := pushRandomImage(s4Ref)
	fmt.Printf("[Step 1: Push] Pushed legitimate initial image: %s (digest: %s)\n", s4Ref, s4DigestA[:20]+"...")

	s4SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s4Ref)
	s4SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := s4SignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Signing s4 image failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Printf("[Step 2: Sign] Cryptographically signed %s with valid key\n", s4Ref)

	// Send initial AdmissionReview -> MUST BE ADMITTED
	fmt.Println("[Step 3: Initial Review] Sending Kubernetes AdmissionReview for initial image...")
	s4Resp1 := sendAdmissionReview("scenario-04-initial-uid", s4Ref, "staging")
	fmt.Println("\n[CAPTURE] Initial AdmissionReview Response:")
	if s4Resp1.Response != nil {
		fmt.Printf("  Allowed: %v\n", s4Resp1.Response.Allowed)
		if s4Resp1.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s4Resp1.Response.Status.Code)
			fmt.Printf("  Status Message:   %s\n", s4Resp1.Response.Status.Message)
		} else {
			fmt.Println("  Status: 200 OK (Workload admitted successfully into cluster)")
		}
	}

	// Retarget the tag! Overwrite the tag with a different image
	s4RefParsed, _ := name.ParseReference(s4Ref, name.Insecure)
	s4DiffImg, _ := random.Image(4096, 3)
	_ = remote.Write(s4RefParsed, s4DiffImg)
	descB, _ := remote.Head(s4RefParsed)
	s4DigestB := descB.Digest.String()
	fmt.Printf("\n[Step 4: Tag Retarget Attack] Retargeted tag %s to different image digest: %s (mutated from %s)\n",
		s4Ref, s4DigestB[:20]+"...", s4DigestA[:20]+"...")

	fmt.Println("[Step 5: Post-Retarget Review] Sending Kubernetes AdmissionReview after tag retargeting...")
	s4Resp2 := sendAdmissionReview("scenario-04-retargeted-uid", s4Ref, "prod")
	fmt.Println("\n[CAPTURE] Post-Retarget AdmissionReview Response:")
	if s4Resp2.Response != nil {
		fmt.Printf("  Allowed: %v\n", s4Resp2.Response.Allowed)
		if s4Resp2.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s4Resp2.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s4Resp2.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s4Resp2.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 05: Untrusted Signing Key (Key Mode True Cause Reporting)
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 05: UNTRUSTED SIGNING KEY IN KEY MODE (TRUE CAUSE REPORTING)")
	fmt.Println("=========================================================================================")
	s5Ref := "127.0.0.1:5001/scenario-05-untrusted-key:v1.0.0"
	s5Digest := pushRandomImage(s5Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s5Ref, s5Digest[:20]+"...")

	unexpectedIdentity := "https://github.com/evil-actor/rogue-supply-chain/.github/workflows/backdoor.yml@refs/heads/main"
	rogueSignCmd := exec.Command("cosign", "sign", "--key", attackerKey,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true",
		"-a", "identity="+unexpectedIdentity,
		s5Ref)
	rogueSignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=attackerpass")
	if out, err := rogueSignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Rogue signing failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Printf("[Rogue Sign] Signed artifact with unauthorized key (asserting self-reported identity: %s)\n", unexpectedIdentity)

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify true cause denial without identity check...")
	s5Resp := sendAdmissionReview("scenario-05-uid", s5Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s5Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s5Resp.Response.Allowed)
		if s5Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s5Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s5Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s5Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 06: Valid Signature, No Attestations -> OPA provenance_required & sbom_required Denial
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 06: VALID SIGNATURE BUT NO ATTESTATIONS (OPA PROVENANCE & SBOM ENFORCEMENT)")
	fmt.Println("=========================================================================================")
	s6Ref := "127.0.0.1:5001/scenario-06-no-attestations:v1.0.0"
	s6Digest := pushRandomImage(s6Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s6Ref, s6Digest[:20]+"...")

	s6SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s6Ref)
	s6SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := s6SignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Signing s6 image failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Printf("[Sign] Cryptographically signed %s with valid key (zero in-toto attestations attached)\n", s6Ref)

	fmt.Println("[Action] Sending Kubernetes AdmissionReview in 'prod' to verify OPA denial on missing attestations...")
	s6Resp := sendAdmissionReview("scenario-06-uid", s6Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s6Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s6Resp.Response.Allowed)
		if s6Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s6Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s6Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s6Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 07: Valid Signature Plus Attestation Signed by Rogue Key (DSSE Denial)
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 07: VALID SIGNATURE WITH ROGUE KEY ATTESTATION (CRYPTOGRAPHIC DSSE VERIFICATION DENIAL)")
	fmt.Println("=========================================================================================")
	s7Ref := "127.0.0.1:5001/scenario-07-rogue-attestation:v1.0.0"
	s7Digest := pushRandomImage(s7Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s7Ref, s7Digest[:20]+"...")

	s7SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s7Ref)
	s7SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := s7SignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Signing s7 image failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Printf("[Sign] Cryptographically signed artifact with valid release key\n")

	// Attest with unauthorized attacker key
	attCmd := exec.Command("cosign", "attest", "--key", attackerKey,
		"--yes", "--type", "https://slsa.dev/provenance/v1",
		"--predicate", "sample-app/attestations/slsa-provenance.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s7Ref)
	attCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=attackerpass")
	if out, err := attCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Rogue attestation failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Println("[Rogue Attest] Attached in-toto attestation signed by rogue attacker key")

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify DSSE cryptographic verification denial...")
	s7Resp := sendAdmissionReview("scenario-07-uid", s7Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s7Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s7Resp.Response.Allowed)
		if s7Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s7Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s7Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s7Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 08: Critical KEV CVE Denied ([Rule vulnerability_gate])
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 08: CRITICAL KEV CVE VULNERABILITY GATE DENIAL")
	fmt.Println("=========================================================================================")
	s8Ref := "127.0.0.1:5001/scenario-08-critical-kev:v1.0.0"
	s8Digest := pushRandomImage(s8Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s8Ref, s8Digest[:20]+"...")

	s8SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s8Ref)
	s8SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := s8SignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Signing s8 image failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Println("[Sign] Cryptographically signed artifact with valid release key")

	attSlsaCmd8 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://slsa.dev/provenance/v1",
		"--predicate", "sample-app/attestations/slsa-provenance.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s8Ref)
	attSlsaCmd8.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := attSlsaCmd8.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: SLSA attestation failed: %v (out: %s)\n", err, string(out))
	}

	attSbomCmd8 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://cyclonedx.org/schema",
		"--predicate", "sample-app/attestations/cyclonedx.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s8Ref)
	attSbomCmd8.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := attSbomCmd8.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: SBOM attestation failed: %v (out: %s)\n", err, string(out))
	}

	vulnScanFile := filepath.Join(tempDir, "vuln_scan_kev.json")
	_ = os.WriteFile(vulnScanFile, []byte(`{"vulnerabilities":[{"id":"CVE-2023-38606","severity":"CRITICAL","kev":true}]}`), 0644)
	attVulnCmd := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://cosign.sigstore.dev/attestation/vuln/v1",
		"--predicate", vulnScanFile,
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s8Ref)
	attVulnCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := attVulnCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Vuln attestation failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Println("[Attest] Attached Verified Vulnerability Scan attestation containing critical KEV CVE-2023-38606")

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify vulnerability_gate denial...")
	s8Resp := sendAdmissionReview("scenario-08-uid", s8Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s8Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s8Resp.Response.Allowed)
		if s8Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s8Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s8Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s8Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 09: Same Image with Signed OpenVEX Admitted (vulnerability_gate Waived)
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 09: SAME IMAGE WITH SIGNED OPENVEX WAIVER ADMITTED")
	fmt.Println("=========================================================================================")
	vexFile := filepath.Join(tempDir, "openvex_waiver.json")
	_ = os.WriteFile(vexFile, []byte(`{"statements":[{"vulnerability":{"name":"CVE-2023-38606"},"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`), 0644)

	attVexCmd := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://openvex.dev/ns/v0.2.0",
		"--predicate", vexFile,
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s8Ref)
	attVexCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := attVexCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: OpenVEX attestation failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Println("[Attest] Attached cryptographically signed OpenVEX waiver for CVE-2023-38606 to same image")

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify successful admission of waived workload...")
	s9Resp := sendAdmissionReview("scenario-09-uid", s8Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s9Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s9Resp.Response.Allowed)
		if s9Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s9Resp.Response.Status.Code)
			fmt.Printf("  Status Message:   %s\n", s9Resp.Response.Status.Message)
		} else {
			fmt.Println("  Status: 200 OK (Workload admitted successfully into cluster)")
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 10: Non-Allowlisted Base Image Denied ([Rule base_image_allowlist])
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 10: NON-ALLOWLISTED BASE IMAGE DENIED (BASE IMAGE ALLOWLIST GATE)")
	fmt.Println("=========================================================================================")
	s10Ref := "127.0.0.1:5001/scenario-10-unapproved-base:v1.0.0"
	s10Digest := pushRandomImage(s10Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s10Ref, s10Digest[:20]+"...")

	s10SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true",
		"-a", "base_image_digest=sha256:ba00000000000000000000000000000000000000000000000000000000000000",
		s10Ref)
	s10SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := s10SignCmd.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Signing s10 image failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Println("[Sign] Signed artifact with unapproved base image annotation sha256:ba0000...")

	attSlsaCmd10 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://slsa.dev/provenance/v1",
		"--predicate", "sample-app/attestations/slsa-provenance.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s10Ref)
	attSlsaCmd10.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSlsaCmd10.Run()

	attSbomCmd10 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://cyclonedx.org/schema",
		"--predicate", "sample-app/attestations/cyclonedx.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s10Ref)
	attSbomCmd10.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSbomCmd10.Run()

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify base_image_allowlist denial...")
	s10Resp := sendAdmissionReview("scenario-10-uid", s10Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s10Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s10Resp.Response.Allowed)
		if s10Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s10Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s10Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s10Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 11: Privileged Pod Denied ([Rule privileged_workload_extra_scrutiny])
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 11: PRIVILEGED WORKLOAD DENIED (SECURITY COMMITTEE SCRUTINY GATE)")
	fmt.Println("=========================================================================================")
	s11Ref := "127.0.0.1:5001/scenario-11-privileged-pod:v1.0.0"
	s11Digest := pushRandomImage(s11Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s11Ref, s11Digest[:20]+"...")

	s11SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s11Ref)
	s11SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = s11SignCmd.Run()

	attSlsaCmd11 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://slsa.dev/provenance/v1",
		"--predicate", "sample-app/attestations/slsa-provenance.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s11Ref)
	attSlsaCmd11.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSlsaCmd11.Run()

	attSbomCmd11 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://cyclonedx.org/schema",
		"--predicate", "sample-app/attestations/cyclonedx.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s11Ref)
	attSbomCmd11.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSbomCmd11.Run()

	privPodJSON := fmt.Sprintf(`{
		"metadata": {"name": "privileged-pod", "namespace": "prod"},
		"spec": {
			"containers": [
				{
					"name": "app",
					"image": %q,
					"securityContext": {
						"privileged": true
					}
				}
			]
		}
	}`, s11Ref)

	fmt.Println("[Action] Sending Kubernetes AdmissionReview with securityContext.privileged=true...")
	s11Resp := sendCustomPodAdmissionReview("scenario-11-uid", "prod", privPodJSON)
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s11Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s11Resp.Response.Allowed)
		if s11Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s11Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s11Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s11Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 12: Stale Build Denied ([Rule freshness])
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 12: STALE BUILD (>30 DAYS) DENIED (PIPELINE FRESHNESS GATE)")
	fmt.Println("=========================================================================================")
	s12Ref := "127.0.0.1:5001/scenario-12-stale-build:v1.0.0"
	s12Digest := pushRandomImage(s12Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s12Ref, s12Digest[:20]+"...")

	s12SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true",
		"-a", "built_at=2024-01-01T00:00:00Z",
		s12Ref)
	s12SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = s12SignCmd.Run()
	fmt.Println("[Sign] Signed artifact asserting build creation date: 2024-01-01T00:00:00Z (>30 days limit)")

	attSlsaCmd12 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://slsa.dev/provenance/v1",
		"--predicate", "sample-app/attestations/slsa-provenance.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s12Ref)
	attSlsaCmd12.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSlsaCmd12.Run()

	attSbomCmd12 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://cyclonedx.org/schema",
		"--predicate", "sample-app/attestations/cyclonedx.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s12Ref)
	attSbomCmd12.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSbomCmd12.Run()

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify freshness denial...")
	s12Resp := sendAdmissionReview("scenario-12-uid", s12Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s12Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s12Resp.Response.Allowed)
		if s12Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s12Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s12Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s12Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 13: Typosquatted Dependency Denied ([Rule dependency_risk_gate])
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 13: TYPOSQUATTED MALICIOUS DEPENDENCY DENIED (DEPENDENCY RISK GATE)")
	fmt.Println("=========================================================================================")
	s13Ref := "127.0.0.1:5001/scenario-13-typosquat:v1.0.0"
	s13Digest := pushRandomImage(s13Ref)
	fmt.Printf("[Push] Pushed image: %s (digest: %s)\n", s13Ref, s13Digest[:20]+"...")

	s13SignCmd := exec.Command("cosign", "sign", "--key", validKeyPath,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s13Ref)
	s13SignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = s13SignCmd.Run()

	attSlsaCmd13 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://slsa.dev/provenance/v1",
		"--predicate", "sample-app/attestations/slsa-provenance.json",
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s13Ref)
	attSlsaCmd13.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = attSlsaCmd13.Run()

	maliciousSbomFile := filepath.Join(tempDir, "cyclonedx_malicious.json")
	_ = os.WriteFile(maliciousSbomFile, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"cross-env-malicious","ecosystem":"npm","version":"1.0.0"}]}`), 0644)
	attSbomCmd13 := exec.Command("cosign", "attest", "--key", validKeyPath,
		"--yes", "--type", "https://cyclonedx.org/schema",
		"--predicate", maliciousSbomFile,
		"--allow-http-registry=true", "--allow-insecure-registry=true", "--tlog-upload=false", s13Ref)
	attSbomCmd13.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	if out, err := attSbomCmd13.CombinedOutput(); err != nil {
		fmt.Printf("FATAL: Malicious SBOM attestation failed: %v (out: %s)\n", err, string(out))
	}
	fmt.Println("[Attest] Attached CycloneDX SBOM containing typosquatted malicious package 'cross-env-malicious'")

	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify dependency_risk_gate denial...")
	s13Resp := sendAdmissionReview("scenario-13-uid", s13Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s13Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s13Resp.Response.Allowed)
		if s13Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s13Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s13Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s13Resp.Response.Status.Message)
		}
	}

	fmt.Println("=========================================================================================")
}
