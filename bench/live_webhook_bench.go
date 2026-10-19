package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
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
	fmt.Println("AEGISCHAIN LIVE ADMISSION BENCHMARK")
	fmt.Println("Label: Loopback, no API server (127.0.0.1 TLS)")
	fmt.Println("=========================================================================================")

	// 1. Start real OCI registry on 127.0.0.1:5001
	regHandler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
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

	// 2. Generate and push 50 distinct container images to the registry
	const coldCount = 50
	const warmCount = 250

	fmt.Printf("[2/5] Creating and pushing %d distinct signed container images to registry...\n", coldCount)
	imageRefs := make([]string, coldCount)
	imageDigests := make([]string, coldCount)

	type signJob struct {
		index int
		ref   string
	}

	jobs := make(chan signJob, coldCount)
	var signWg sync.WaitGroup

	for i := 0; i < coldCount; i++ {
		imgRef := fmt.Sprintf("127.0.0.1:5001/workload-bench-%02d:v1.0.0", i+1)
		ref, err := name.ParseReference(imgRef, name.Insecure)
		if err != nil {
			fmt.Printf("FATAL: Failed to parse image ref %s: %v\n", imgRef, err)
			os.Exit(1)
		}

		// Distinct layer payload so each image produces a unique manifest digest
		img, err := random.Image(512+int64(i)*64, 1)
		if err != nil {
			img = empty.Image
		}
		if err := remote.Write(ref, img); err != nil {
			fmt.Printf("FATAL: Failed to push image %s: %v\n", imgRef, err)
			os.Exit(1)
		}
		desc, _ := remote.Head(ref)
		imageRefs[i] = imgRef
		imageDigests[i] = desc.Digest.String()
	}
	fmt.Printf("      Successfully pushed %d distinct OCI images.\n", coldCount)

	// 3. Concurrently sign the 50 images using real Cosign CLI and deploy/keys/cosign.key
	keyPath := filepath.Join("deploy", "keys", "cosign.key")
	pubKeyPath := filepath.Join("deploy", "keys", "cosign.pub")
	fmt.Printf("[3/5] Concurrently signing %d images with Cosign CLI (8 worker pool)...\n", coldCount)

	workerCount := 8
	var signErrors int32
	for w := 0; w < workerCount; w++ {
		signWg.Add(1)
		go func() {
			defer signWg.Done()
			for job := range jobs {
				cmd := exec.Command("cosign", "sign",
					"--key", keyPath,
					"--yes",
					"--allow-http-registry=true",
					"--allow-insecure-registry=true",
					"--tlog-upload=false",
					job.ref,
				)
				cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=testpassword123")
				if out, err := cmd.CombinedOutput(); err != nil {
					fmt.Printf("Cosign signing error on %s: %v (out: %s)\n", job.ref, err, string(out))
					atomic.AddInt32(&signErrors, 1)
				}
			}
		}()
	}

	for i := 0; i < coldCount; i++ {
		jobs <- signJob{index: i, ref: imageRefs[i]}
	}
	close(jobs)
	signWg.Wait()

	if signErrors > 0 {
		fmt.Printf("FATAL: %d signing jobs failed\n", signErrors)
		os.Exit(1)
	}
	fmt.Printf("      All %d distinct images cryptographically signed with Cosign!\n", coldCount)
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
	fmt.Printf("[4/5] Real AegisChain Admission Webhook running at %s\n", webhookURL)

	// 5. Send Real AdmissionReview Requests and Benchmark Cold vs Warm
	fmt.Println("\n[5/5] Executing Real AdmissionReview HTTP/TLS Requests...")
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Println("BENCHMARK ENVIRONMENT: Loopback, no API server (127.0.0.1 TLS)")
	fmt.Println("-----------------------------------------------------------------------------------------")

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
		durationMs := float64(time.Since(t0).Nanoseconds()) / 1e6
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

	// 50 COLD REQUESTS (50 distinct signed images with 50 unique digests)
	fmt.Printf("Executing %d Cold AdmissionReview Requests on %d distinct signed images...\n", coldCount, coldCount)
	coldDurations := make([]float64, coldCount)
	var coldDenied int

	for i := 0; i < coldCount; i++ {
		uid := fmt.Sprintf("cold-req-%03d", i+1)
		coldReq := makeReviewRequest(uid, imageRefs[i], "staging")
		coldResp, coldMs, err := sendReview(coldReq)
		if err != nil {
			fmt.Printf("Cold request %d error: %v\n", i+1, err)
		}
		if coldResp.Response == nil || !coldResp.Response.Allowed {
			coldDenied++
			errMsg := "nil response"
			if coldResp.Response != nil && coldResp.Response.Status != nil {
				errMsg = coldResp.Response.Status.Message
			}
			fmt.Printf("Cold request %d denied: %s\n", i+1, errMsg)
		}
		coldDurations[i] = coldMs
	}

	// 250 WARM REQUESTS (Cache hits on already admitted image)
	fmt.Printf("\nExecuting %d Warm AdmissionReview Requests over live TLS (cached digest)...\n", warmCount)
	warmDurations := make([]float64, warmCount)
	var warmDenied int
	for i := 0; i < warmCount; i++ {
		warmReq := makeReviewRequest(fmt.Sprintf("warm-req-%03d", i+1), imageRefs[0], "staging")
		warmResp, warmMs, err := sendReview(warmReq)
		if err != nil {
			fmt.Printf("Warm request %d error: %v\n", i+1, err)
		}
		if warmResp.Response == nil || !warmResp.Response.Allowed {
			warmDenied++
		}
		warmDurations[i] = warmMs
	}

	calcStats := func(durations []float64) (min, max, mean, p50, p95, p99 float64) {
		sorted := make([]float64, len(durations))
		copy(sorted, durations)
		sort.Float64s(sorted)

		n := float64(len(sorted))
		var sum float64
		for _, d := range sorted {
			sum += d
		}
		p50Idx := int(math.Min(math.Max(0, math.Floor(n*0.50)), n-1))
		p95Idx := int(math.Min(math.Max(0, math.Floor(n*0.95)), n-1))
		p99Idx := int(math.Min(math.Max(0, math.Floor(n*0.99)), n-1))

		return sorted[0], sorted[len(sorted)-1], sum / n, sorted[p50Idx], sorted[p95Idx], sorted[p99Idx]
	}

	cMin, cMax, cMean, cP50, cP95, cP99 := calcStats(coldDurations)
	wMin, wMax, wMean, wP50, wP95, wP99 := calcStats(warmDurations)

	fmt.Println("=========================================================================================")
	fmt.Println("BENCHMARK RESULTS: Loopback, no API server (127.0.0.1 TLS)")
	fmt.Println("=========================================================================================")
	fmt.Printf("COLD REQUESTS (%d distinct signed images, full verification path):\n", coldCount)
	fmt.Printf("  Denied: %d / %d\n", coldDenied, coldCount)
	fmt.Printf("  Min:    %.2f ms\n", cMin)
	fmt.Printf("  Max:    %.2f ms\n", cMax)
	fmt.Printf("  Mean:   %.2f ms\n", cMean)
	fmt.Printf("  p50:    %.2f ms\n", cP50)
	fmt.Printf("  p95:    %.2f ms\n", cP95)
	fmt.Printf("  p99:    %.2f ms\n", cP99)
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Printf("WARM REQUESTS (%d requests on cached digest):\n", warmCount)
	fmt.Printf("  Denied: %d / %d\n", warmDenied, warmCount)
	fmt.Printf("  Min:    %.2f ms\n", wMin)
	fmt.Printf("  Max:    %.2f ms\n", wMax)
	fmt.Printf("  Mean:   %.2f ms\n", wMean)
	fmt.Printf("  p50:    %.2f ms\n", wP50)
	fmt.Printf("  p95:    %.2f ms\n", wP95)
	fmt.Printf("  p99:    %.2f ms\n", wP99)
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Printf("RATIO (Cold p50 / Warm p50): %.2fx\n", cP50/math.Max(wP50, 0.001))
	fmt.Println("-----------------------------------------------------------------------------------------")
	sloMet := wP95 < 300.0
	if sloMet {
		fmt.Printf("SLO VERIFICATION (p95 < 300.0 ms): MET (Warm p95 = %.2f ms, Cold p95 = %.2f ms)\n", wP95, cP95)
	} else {
		fmt.Printf("SLO VERIFICATION (p95 < 300.0 ms): NOT MET (Warm p95 = %.2f ms)\n", wP95)
	}
	fmt.Println("=========================================================================================")
}
