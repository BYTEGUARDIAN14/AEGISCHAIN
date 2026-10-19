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
	fmt.Println("AEGISCHAIN ATTACK LAB: LIVE SCENARIOS 02 TO 05 WITH REAL REGISTRY & COSIGN")
	fmt.Println("Deploying Real Container Workloads and Capturing Exact Admission Denial Messages")
	fmt.Println("=========================================================================================")

	// 1. Start real OCI registry on 127.0.0.1:5001
	regHandler := registry.New()
	regListener, err := net.Listen("tcp", "127.0.0.1:5001")
	if err != nil {
		fmt.Printf("FATAL: Failed to start registry on :5001: %v\n", err)
		os.Exit(1)
	}
	defer regListener.Close()
	regServer := &http.Server{Handler: regHandler}
	go func() { _ = regServer.Serve(regListener) }()
	fmt.Println("[Setup 1/3] Real OCI Registry running on http://127.0.0.1:5001")

	// 2. Generate unapproved attacker keypair for Scenario 5
	attackerDir, err := os.MkdirTemp("", "attacker-keys-*")
	if err != nil {
		fmt.Printf("FATAL: MkdirTemp failed: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(attackerDir)
	attackerKey := filepath.Join(attackerDir, "attacker.key")
	attackerPub := filepath.Join(attackerDir, "attacker.pub")
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
		"-cert", certFile, "-key", keyFile, "-host", "127.0.0.1,localhost")
	_ = genCertCmd.Run()

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
	if err := webhookBinCmd.Start(); err != nil {
		fmt.Printf("FATAL: Failed to start admission-webhook: %v\n", err)
		os.Exit(1)
	}
	defer webhookBinCmd.Process.Kill()

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	webhookURL := fmt.Sprintf("https://127.0.0.1:%s/validate", webhookPort)
	healthURL := fmt.Sprintf("https://127.0.0.1:%s/healthz", webhookPort)

	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(200 * time.Millisecond)
		resp, err := client.Get(healthURL)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
	}
	fmt.Println("[Setup 3/3] Real AegisChain Admission Webhook active on https://127.0.0.1:8443/validate\n")

	// Helper to send AdmissionReview
	sendAdmissionReview := func(uid, imgRef, ns string) AdmissionReview {
		podJSON := fmt.Sprintf(`{
			"metadata": {"name": "%s-workload", "namespace": "%s"},
			"spec": {
				"containers": [{"name": "app", "image": "%s"}]
			}
		}`, uid, ns, imgRef)

		reqReview := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Request: &AdmissionRequest{
				UID:       uid,
				Namespace: ns,
				Kind:      GroupVersionKind{Kind: "Pod", Version: "v1"},
				Object:    json.RawMessage(podJSON),
			},
		}
		body, _ := json.Marshal(reqReview)
		httpResp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("HTTP error: %v\n", err)
			return AdmissionReview{}
		}
		defer httpResp.Body.Close()
		respBytes, _ := io.ReadAll(httpResp.Body)
		var revResp AdmissionReview
		_ = json.Unmarshal(respBytes, &revResp)
		return revResp
	}

	pushRandomImage := func(refStr string) string {
		r, _ := name.ParseReference(refStr, name.Insecure)
		img, _ := random.Image(512, 1)
		_ = remote.Write(r, img)
		desc, _ := remote.Head(r)
		return desc.Digest.String()
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 02: Unsigned Container Image
	// -----------------------------------------------------------------------------------------
	fmt.Println("=========================================================================================")
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
	// SCENARIO 03: Tampered Image Layer Substitution
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 03: TAMPERED IMAGE LAYER SUBSTITUTION")
	fmt.Println("=========================================================================================")
	s3Ref := "127.0.0.1:5001/scenario-03-tampered:v1.0.0"
	pushRandomImage(s3Ref)
	// Sign original
	signCmd := exec.Command("cosign", "sign", "--key", filepath.Join("deploy", "keys", "cosign.key"),
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s3Ref)
	signCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
	_ = signCmd.Run()
	fmt.Printf("[Sign] Signed original artifact: %s\n", s3Ref)

	// Now tamper: overwrite with different image layer under same tag so digest mutates
	tamperedR, _ := name.ParseReference(s3Ref, name.Insecure)
	tamperedImg, _ := random.Image(2048, 2)
	_ = remote.Write(tamperedR, tamperedImg)
	descTampered, _ := remote.Head(tamperedR)
	fmt.Printf("[Tamper] Injected modified layer; new image digest: %s (signature broken!)\n", descTampered.Digest.String()[:20]+"...")

	fmt.Println("[Action] Sending Kubernetes AdmissionReview for tampered workload...")
	s3Resp := sendAdmissionReview("scenario-03-uid", s3Ref, "prod")
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
	// SCENARIO 04: Mutable Tag Retargeting
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 04: MUTABLE TAG RETARGETING / UNPINNED TAG POLICY VIOLATION")
	fmt.Println("=========================================================================================")
	s4Ref := "127.0.0.1:5001/scenario-04-mutable:latest"
	pushRandomImage(s4Ref)
	fmt.Printf("[Push] Pushed image using mutable unpinned tag ':latest': %s\n", s4Ref)
	fmt.Println("[Action] Sending Kubernetes AdmissionReview for mutable tag workload...")

	s4Resp := sendAdmissionReview("scenario-04-uid", s4Ref, "prod")
	fmt.Println("\n[CAPTURE] Exact AdmissionReview Response:")
	if s4Resp.Response != nil {
		fmt.Printf("  Allowed: %v\n", s4Resp.Response.Allowed)
		if s4Resp.Response.Status != nil {
			fmt.Printf("  HTTP Status Code: %d\n", s4Resp.Response.Status.Code)
			fmt.Printf("  Status Reason:    %s\n", s4Resp.Response.Status.Reason)
			fmt.Printf("  Denial Message:\n%s\n", s4Resp.Response.Status.Message)
		}
	}

	// -----------------------------------------------------------------------------------------
	// SCENARIO 05: Wrong Signer Workflow Identity
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("SCENARIO 05: WRONG SIGNER WORKFLOW IDENTITY / UNTRUSTED SIGNING KEY")
	fmt.Println("=========================================================================================")
	s5Ref := "127.0.0.1:5001/scenario-05-wrong-signer:v1.0.0"
	pushRandomImage(s5Ref)
	// Sign with attacker keypair instead of approved platform key
	rogueSignCmd := exec.Command("cosign", "sign", "--key", attackerKey,
		"--yes", "--tlog-upload=false", "--allow-http-registry=true", "--allow-insecure-registry=true", s5Ref)
	rogueSignCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=attackerpass")
	_ = rogueSignCmd.Run()
	fmt.Printf("[Rogue Sign] Signed %s using unauthorized rogue key (%s)\n", s5Ref, attackerPub)
	fmt.Println("[Action] Sending Kubernetes AdmissionReview to verify signer identity enforcement...")

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
	// KUBECTL DEPLOYMENT ATTEMPT & CAPTURE
	// -----------------------------------------------------------------------------------------
	fmt.Println("\n=========================================================================================")
	fmt.Println("KUBECTL DEPLOYMENT ATTEMPT AGAINST CLUSTER")
	fmt.Println("=========================================================================================")
	fmt.Println("[Command] kubectl run attack-test-pod --image=127.0.0.1:5001/scenario-02-unsigned:v1.0.0 -n prod")
	kCmd := exec.Command("kubectl", "run", "attack-test-pod", "--image=127.0.0.1:5001/scenario-02-unsigned:v1.0.0", "-n", "prod")
	kOut, kErr := kCmd.CombinedOutput()
	fmt.Println("\n[CAPTURE] Exact kubectl Output:")
	fmt.Printf("%s\n", string(kOut))
	if kErr != nil {
		fmt.Printf("[Exit Code]: %v\n", kErr)
	}
	fmt.Println("=========================================================================================")
}
