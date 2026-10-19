package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// AdmissionReview mirrors Kubernetes admission.k8s.io/v1
type AdmissionReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Request    *AdmissionRequest `json:"request,omitempty"`
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
	UID     string        `json:"uid"`
	Allowed bool          `json:"allowed"`
	Status  *StatusResult `json:"status,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
}

type StatusResult struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func main() {
	fmt.Println("=========================================================================================")
	fmt.Println("AEGISCHAIN LIVE ADMISSION BENCHMARK (REAL WEBHOOK + REAL REGISTRY + REAL COSIGN)")
	fmt.Println("=========================================================================================")

	// 1. Start real OCI registry on 127.0.0.1:5001
	regHandler := registry.New()
	regListener, err := net.Listen("tcp", "127.0.0.1:5001")
	if err != nil {
		fmt.Printf("FATAL: Failed to start registry listener on :5001: %v\n", err)
		os.Exit(1)
	}
	defer regListener.Close()

	regServer := &http.Server{Handler: regHandler}
	go func() {
		if err := regServer.Serve(regListener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Registry server error: %v\n", err)
		}
	}()
	fmt.Printf("[1/5] Real OCI Registry running on http://%s\n", regListener.Addr().String())

	// 2. Push a real image to the registry
	imgRef := "127.0.0.1:5001/live-workload:v1.0.0"
	ref, err := name.ParseReference(imgRef, name.Insecure)
	if err != nil {
		fmt.Printf("FATAL: Failed to parse image ref: %v\n", err)
		os.Exit(1)
	}

	// Create a real container image with a random layer
	img, err := random.Image(1024, 1)
	if err != nil {
		img = empty.Image
	}
	if err := remote.Write(ref, img); err != nil {
		fmt.Printf("FATAL: Failed to push real image to registry: %v\n", err)
		os.Exit(1)
	}
	desc, _ := remote.Head(ref)
	imgDigest := desc.Digest.String()
	fmt.Printf("[2/5] Real Container Image pushed: %s (digest: %s)\n", imgRef, imgDigest[:19]+"...")

	// 3. Sign the image using real Cosign CLI and deploy/keys/cosign.key
	keyPath := filepath.Join("deploy", "keys", "cosign.key")
	pubKeyPath := filepath.Join("deploy", "keys", "cosign.pub")
	fmt.Printf("[3/5] Executing real Cosign CLI signing using key: %s\n", keyPath)
	cmd := exec.Command("cosign", "sign",
		"--key", keyPath,
		"--yes",
		"--allow-http-registry=true",
		"--allow-insecure-registry=true",
		"--tlog-upload=false",
		imgRef,
	)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	cosignOut, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("FATAL: Cosign signing failed: %v\nOutput: %s\n", err, string(cosignOut))
		os.Exit(1)
	}
	fmt.Println("      Cosign signing succeeded! Cryptographic .sig OCI artifact pushed to registry.")

	// Also attach real in-toto attestations to the image in the registry
	attestations := []struct {
		predType string
		file     string
	}{
		{"https://cyclonedx.org/schema", "sample-app/attestations/cyclonedx.json"},
		{"https://cosign.sigstore.dev/attestation/vuln/v1", "sample-app/attestations/trivy-scan.json"},
		{"https://openvex.dev/ns/v0.2.0", "sample-app/attestations/openvex.json"},
		{"https://slsa.dev/provenance/v1", "sample-app/attestations/slsa-provenance.json"},
	}

	for _, att := range attestations {
		attCmd := exec.Command("cosign", "attest",
			"--key", keyPath,
			"--yes",
			"--type", att.predType,
			"--predicate", att.file,
			"--allow-http-registry=true",
			"--allow-insecure-registry=true",
			"--tlog-upload=false",
			imgRef,
		)
		attCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
		if attOut, err := attCmd.CombinedOutput(); err != nil {
			fmt.Printf("      Warning: Attestation %s failed: %v (out: %s)\n", att.predType, err, string(attOut))
		} else {
			fmt.Printf("      Attached in-toto attestation: %s\n", att.predType)
		}
	}

	// Verify that the .sig exists in the registry using cosign verify
	verifyCmd := exec.Command("cosign", "verify",
		"--key", pubKeyPath,
		"--allow-http-registry=true",
		"--allow-insecure-registry=true",
		"--insecure-ignore-tlog=true",
		imgRef,
	)
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("FATAL: Cosign verification failed: %v\nOutput: %s\n", err, string(verifyOut))
		os.Exit(1)
	}
	fmt.Println("      Verified signature presence via Cosign CLI against registry.")

	// 4. Start Real Admission Webhook on HTTPS :8443
	webhookPort := "8443"
	tempDir, err := os.MkdirTemp("", "webhook-test-*")
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

	webhookBinCmd := exec.CommandContext(webhookCtx, "go", "run", "./cmd/admission-webhook",
		"-port", webhookPort,
		"-tls-cert-file", certFile,
		"-tls-key-file", keyFile,
		"-public-key", pubKeyPath,
		"-enforce-namespaces", "prod",
		"-audit-namespaces", "staging",
		"-default-mode", "enforce",
	)
	webhookBinCmd.Stdout = os.Stdout
	webhookBinCmd.Stderr = os.Stderr
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
	fmt.Printf("[4/5] Real AegisChain Admission Webhook running at %s\n", webhookURL)

	// 5. Send Real AdmissionReview Requests and Benchmark Cold vs Warm
	fmt.Println("\n[5/5] Executing Real AdmissionReview HTTP/TLS Requests...")

	makeReviewRequest := func(uid, imageRef, namespace string) AdmissionReview {
		podJSON := fmt.Sprintf(`{
			"metadata": {"name": "benchmark-workload", "namespace": "%s"},
			"spec": {
				"containers": [{"name": "app", "image": "%s"}]
			}
		}`, namespace, imageRef)

		return AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       uid,
				Namespace: namespace,
				Kind:      GroupVersionKind{Kind: "Pod", Version: "v1"},
				Object:    json.RawMessage(podJSON),
			},
		}
	}

	sendReview := func(req AdmissionReview) (AdmissionReview, float64, error) {
		body, _ := json.Marshal(req)
		t0 := time.Now()
		httpResp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
		durationMs := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			return AdmissionReview{}, durationMs, err
		}
		defer httpResp.Body.Close()

		respBody, _ := io.ReadAll(httpResp.Body)
		var revResp AdmissionReview
		if err := json.Unmarshal(respBody, &revResp); err != nil {
			return AdmissionReview{}, durationMs, fmt.Errorf("decode error: %w (body: %s)", err, string(respBody))
		}
		return revResp, durationMs, nil
	}

	// COLD REQUEST
	coldReq := makeReviewRequest("cold-req-001", imgRef, "prod")
	coldResp, coldMs, err := sendReview(coldReq)
	if err != nil {
		fmt.Printf("Cold request error: %v\n", err)
	}

	fmt.Println("\n-----------------------------------------------------------------------------------------")
	fmt.Printf("COLD REQUEST ADMISSION LATENCY: %.2f ms\n", coldMs)
	if coldResp.Response != nil {
		fmt.Printf("  Allowed:  %v\n", coldResp.Response.Allowed)
		if coldResp.Response.Status != nil {
			fmt.Printf("  Status:   %s\n", coldResp.Response.Status.Message)
		}
	}

	// WARM REQUESTS (5 iterations)
	warmDurations := make([]float64, 5)
	for i := 0; i < 5; i++ {
		warmReq := makeReviewRequest(fmt.Sprintf("warm-req-%03d", i+1), imgRef, "prod")
		warmResp, warmMs, err := sendReview(warmReq)
		if err != nil {
			fmt.Printf("Warm request %d error: %v\n", i+1, err)
		}
		warmDurations[i] = warmMs
		if i == 0 && warmResp.Response != nil {
			fmt.Printf("WARM REQUEST ADMISSION LATENCY (sample 1): %.2f ms\n", warmMs)
			fmt.Printf("  Allowed:  %v\n", warmResp.Response.Allowed)
		}
	}

	var warmSum float64
	for _, d := range warmDurations {
		warmSum += d
	}
	avgWarm := warmSum / float64(len(warmDurations))
	fmt.Printf("WARM REQUESTS AVERAGE LATENCY (5 samples):  %.2f ms\n", avgWarm)
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Printf("RATIO (Cold / Warm): %.2fx\n", coldMs/avgWarm)
	if coldMs > avgWarm {
		fmt.Printf("EMPIRICAL RESULT: Cold (%.2f ms) is SLOWER than Warm (%.2f ms) as expected!\n", coldMs, avgWarm)
		fmt.Println("Reason: Cold must establish TLS, execute remote registry HEAD, and invoke Cosign verify subprocess.")
		fmt.Println("        Warm hits in-memory resolver digest cache and verifier report cache, bypassing all I/O.")
	} else {
		fmt.Printf("Cold is not slower: Cold=%.2fms, Warm=%.2fms\n", coldMs, avgWarm)
	}
	fmt.Println("=========================================================================================")
}
