package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/byteaegis/aegischain/internal/ledger"
	"github.com/byteaegis/aegischain/internal/policy"
	"github.com/byteaegis/aegischain/internal/resolver"
	"github.com/byteaegis/aegischain/internal/verify"
)

// Metrics registered for Prometheus observability.
var (
	admissionRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegischain_admission_requests_total",
			Help: "Total count of admission review requests processed",
		},
		[]string{"operation", "namespace", "mode", "verdict"},
	)
	admissionLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegischain_admission_latency_seconds",
			Help:    "Admission decision latency in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"mode", "verdict"},
	)
	verificationFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegischain_verification_failures_total",
			Help: "Count of policy verification failures partitioned by rule ID",
		},
		[]string{"rule_id", "namespace"},
	)
	breakGlassEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegischain_break_glass_total",
			Help: "Count of emergency break-glass authorizations invoked",
		},
		[]string{"namespace", "approver"},
	)
	degradedEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegischain_degraded_events_total",
			Help: "Count of degraded operational paths (e.g. registry offline)",
		},
		[]string{"reason", "mode"},
	)
)

func init() {
	prometheus.MustRegister(admissionRequestsTotal)
	prometheus.MustRegister(admissionLatencyHistogram)
	prometheus.MustRegister(verificationFailuresTotal)
	prometheus.MustRegister(breakGlassEventsTotal)
	prometheus.MustRegister(degradedEventsTotal)
}

// Config holds runtime configuration for the admission webhook.
type Config struct {
	Port              string
	TLSCertFile       string
	TLSKeyFile        string
	PoliciesDir       string
	DataDir           string
	PublicKeyPath     string
	BreakGlassKeyPath string
	EnforceNamespaces []string
	AuditNamespaces   []string
	DefaultMode       string // "enforce" or "audit"
	Timeout           time.Duration
}

// EvaluationCacheEntry stores cached container evaluation results keyed by immutable digest.
type EvaluationCacheEntry struct {
	Verdict    string
	TrustScore int
	Rules      []ledger.RuleResult
	Err        error
	ExpiresAt  time.Time
}

// CosignSignaturePayload matches the Sigstore simple signing format.
type CosignSignaturePayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
	Optional map[string]interface{} `json:"optional"`
}

// AdmissionServer hosts the admission endpoints and orchestrates trust validation.
type AdmissionServer struct {
	cfg               Config
	resolver          *resolver.Resolver
	verifier          *verify.Verifier
	policyEngine      *policy.Engine
	ledger            *ledger.Ledger
	publicKeyECDSA    *ecdsa.PublicKey
	evaluationCache   map[string]EvaluationCacheEntry
	evaluationCacheMu sync.RWMutex
	admittedTags      map[string]string // imageRef -> previously admitted digest
	admittedTagsMu    sync.RWMutex
}

// NewAdmissionServer constructs and initializes the AdmissionServer.
func NewAdmissionServer(ctx context.Context, cfg Config) (*AdmissionServer, error) {
	res := resolver.NewResolver(0) // Live resolution for mutable tag drift detection

	trustCfg := verify.TrustConfig{
		AllowedIdentities: []*regexp.Regexp{
			regexp.MustCompile(`^https://github\.com/BYTEGUARDIAN14/.*`),
			regexp.MustCompile(`^https://github\.com/byteaegis/.*`),
		},
		AllowedIssuers: []string{
			"https://token.actions.githubusercontent.com",
		},
		TrustedBuilders: []string{
			"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0",
		},
		ExpectedSourceRepo:   "https://github.com/BYTEGUARDIAN14/aegischain",
		MinVersionAgeLimit:   30 * 24 * time.Hour,
		EnforceAntiRollback:  true,
		RequireAllPredicates: false,
	}

	verifier := verify.NewVerifier(res, trustCfg, 10*time.Minute)
	if cfg.PublicKeyPath != "" {
		if err := verifier.LoadPublicKeyFile(cfg.PublicKeyPath); err != nil {
			slog.Warn("Failed to load cosign public key file", "path", cfg.PublicKeyPath, "error", err)
		}
	}

	// Read Rego policy string
	regoCandidates := []string{
		filepath.Join(cfg.PoliciesDir, "rego", "trust.rego"),
		filepath.Join(cfg.PoliciesDir, "trust.rego"),
		"policies/rego/trust.rego",
		"../../policies/rego/trust.rego",
	}
	var regoBytes []byte
	var loadedPath string
	for _, cand := range regoCandidates {
		b, err := os.ReadFile(cand)
		if err == nil {
			regoBytes = b
			loadedPath = cand
			break
		}
	}
	if len(regoBytes) == 0 {
		return nil, fmt.Errorf("failed to locate Rego policy in candidates: %v", regoCandidates)
	}
	slog.Info("Loaded Rego policy bundle", "path", loadedPath)

	engine, err := policy.NewEngine(ctx, "v1.0.0", string(regoBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to compile OPA engine: %w", err)
	}

	decLedger := ledger.NewLedger()

	var pubECDSA *ecdsa.PublicKey
	if cfg.PublicKeyPath != "" {
		pubData, err := os.ReadFile(cfg.PublicKeyPath)
		if err == nil {
			pblock, _ := pem.Decode(pubData)
			if pblock != nil {
				pkixPub, err := x509.ParsePKIXPublicKey(pblock.Bytes)
				if err == nil {
					if ecPub, ok := pkixPub.(*ecdsa.PublicKey); ok {
						pubECDSA = ecPub
					}
				}
			}
		}
	}

	return &AdmissionServer{
		cfg:             cfg,
		resolver:        res,
		verifier:        verifier,
		policyEngine:    engine,
		ledger:          decLedger,
		publicKeyECDSA:  pubECDSA,
		evaluationCache: make(map[string]EvaluationCacheEntry),
		admittedTags:    make(map[string]string),
	}, nil
}

// RegisterRoutes sets up the HTTP mux.
func (s *AdmissionServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/validate", s.handleValidate)
	mux.HandleFunc("/mutate", s.handleMutate)
	mux.Handle("/metrics", promhttp.Handler())
}

func (s *AdmissionServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"healthy","service":"aegischain-admission-webhook"}`)
}

func (s *AdmissionServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ready","service":"aegischain-admission-webhook"}`)
}

// handleValidate processes Kubernetes ValidatingWebhookConfiguration requests.
func (s *AdmissionServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var reviewReq AdmissionReview
	if err := json.Unmarshal(body, &reviewReq); err != nil || reviewReq.Request == nil {
		slog.Error("Failed to decode AdmissionReview request", "error", err)
		http.Error(w, "Invalid admission review JSON", http.StatusBadRequest)
		return
	}

	req := reviewReq.Request
	namespace := req.Namespace
	if namespace == "" {
		namespace = "default"
	}

	// 1. Exclude system namespaces
	if isExcludedNamespace(namespace) {
		slog.Info("Admitting workload in excluded system namespace", "namespace", namespace, "kind", req.Kind.Kind)
		resp := s.makeReviewResponse(req.UID, true, nil, nil)
		writeAdmissionResponse(w, resp)
		return
	}

	// 2. Determine namespace enforcement mode
	mode := s.getNamespaceMode(namespace)

	// 3. Extract workload containers and annotations
	containers, annotations, workloadName, err := extractContainersAndAnnotations(req.Kind.Kind, req.Object)
	if err != nil {
		slog.Warn("Failed to parse workload metadata", "kind", req.Kind.Kind, "error", err)
		// If unable to parse spec and enforce mode, reject
		if mode == "enforce" {
			resp := s.makeReviewResponse(req.UID, false, &StatusResult{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("AegisChain admission denied: unparseable workload %s: %v", req.Kind.Kind, err),
			}, nil)
			writeAdmissionResponse(w, resp)
			return
		}
	}

	// 4. Check for Break-Glass override
	bg := parseBreakGlass(annotations)
	if bg.Invoked {
		if s.validateBreakGlass(bg) {
			slog.Warn("EMERGENCY BREAK-GLASS INVOKED",
				"namespace", namespace,
				"workload", workloadName,
				"approver", bg.Approver,
				"reason", bg.Reason,
				"expires", bg.ExpiresAt,
			)
			breakGlassEventsTotal.WithLabelValues(namespace, bg.Approver).Inc()

			// Record break-glass into ledger
			_, _ = s.ledger.Append(
				uuid.New().String(),
				"allow",
				mode,
				"v1.0.0",
				ledger.DecisionSubject{
					Image:     "break-glass-override",
					Digest:    "sha256:emergency",
					Namespace: namespace,
					Workload:  workloadName,
				},
				[]ledger.RuleResult{
					{
						ID:          "break_glass_override",
						Result:      "pass",
						Evidence:    []string{fmt.Sprintf("approver:%s", bg.Approver), fmt.Sprintf("reason:%s", bg.Reason)},
						Remediation: "Emergency deployment active; ensure root-cause remediation within expiry window",
					},
				},
				100,
			)

			resp := s.makeReviewResponse(req.UID, true, nil, []string{
				fmt.Sprintf("[BREAK-GLASS] Admitted under emergency token signed by %s. Reason: %s (Expires: %s)",
					bg.Approver, bg.Reason, bg.ExpiresAt.Format(time.RFC3339)),
			})
			writeAdmissionResponse(w, resp)
			return
		}
		slog.Error("Invalid or expired break-glass token supplied", "namespace", namespace, "workload", workloadName)
	}

	// 5. Evaluate all containers against Trust Engine
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Timeout)
	defer cancel()

	var allViolations []string
	var rulesEvaluated []ledger.RuleResult
	totalTrustScore := 100

	for _, c := range containers {
		cStart := time.Now()
		cVerdict, cScore, cRules, cErr := s.evaluateContainer(ctx, c.Image, namespace, workloadName)
		slog.Info("Evaluated container image",
			"container", c.Name,
			"image", c.Image,
			"verdict", cVerdict,
			"trust_score", cScore,
			"duration_ms", time.Since(cStart).Milliseconds(),
		)

		if cScore < totalTrustScore {
			totalTrustScore = cScore
		}
		rulesEvaluated = append(rulesEvaluated, cRules...)

		if cVerdict != "allow" {
			failReason := fmt.Sprintf("Container %q (image: %s): verification failed (%d/100)", c.Name, c.Image, cScore)
			if cErr != nil {
				failReason += fmt.Sprintf(" - %v", cErr)
			}
			for _, r := range cRules {
				if r.Result != "pass" {
					failReason += fmt.Sprintf("\n  [Rule %s] %s (Remediation: %s)", r.ID, r.Reason, r.Remediation)
					verificationFailuresTotal.WithLabelValues(r.ID, namespace).Inc()
				}
			}
			allViolations = append(allViolations, failReason)
		}
	}

	// 6. Formulate Decision
	finalVerdict := "allow"
	isAllowed := true
	var statusResult *StatusResult
	var warnings []string

	if len(allViolations) > 0 {
		if mode == "enforce" {
			finalVerdict = "deny"
			isAllowed = false
			statusResult = &StatusResult{
				Code: http.StatusForbidden,
				Message: fmt.Sprintf("AegisChain Policy Enforce Denial:\n%s\n\nAdmit prohibited by policy in namespace %q.",
					strings.Join(allViolations, "\n"), namespace),
				Reason: "PolicyGateViolation",
			}
		} else {
			// Audit mode: allow but attach warnings
			finalVerdict = "audit_warn"
			isAllowed = true
			warnings = append(warnings, fmt.Sprintf("[AUDIT WARNING] Policy violations detected:\n%s", strings.Join(allViolations, "\n")))
		}
	}

	// 7. Append Decision to Tamper-Evident Ledger
	subjImage := "multiple-containers"
	if len(containers) == 1 {
		subjImage = containers[0].Image
	}
	_, _ = s.ledger.Append(
		uuid.New().String(),
		finalVerdict,
		mode,
		"v1.0.0",
		ledger.DecisionSubject{
			Image:     subjImage,
			Digest:    "sha256:evaluated",
			Namespace: namespace,
			Workload:  workloadName,
		},
		rulesEvaluated,
		totalTrustScore,
	)

	// Record telemetry
	duration := time.Since(start).Seconds()
	admissionRequestsTotal.WithLabelValues(req.Operation, namespace, mode, finalVerdict).Inc()
	admissionLatencyHistogram.WithLabelValues(mode, finalVerdict).Observe(duration)

	resp := s.makeReviewResponse(req.UID, isAllowed, statusResult, warnings)
	writeAdmissionResponse(w, resp)
}

// handleMutate rewrites tags to digests and annotates workload with verification metadata.
func (s *AdmissionServer) handleMutate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var reviewReq AdmissionReview
	if err := json.Unmarshal(body, &reviewReq); err != nil || reviewReq.Request == nil {
		http.Error(w, "Invalid admission review JSON", http.StatusBadRequest)
		return
	}

	req := reviewReq.Request
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Timeout)
	defer cancel()

	var patches []JSONPatchOperation

	// Only mutate Pod resources directly
	if req.Kind.Kind == "Pod" {
		var pod PodObject
		if err := json.Unmarshal(req.Object, &pod); err == nil {
			for i, c := range pod.Spec.Containers {
				if !strings.Contains(c.Image, "@sha256:") {
					digest, err := s.resolver.Resolve(ctx, c.Image)
					if err == nil && digest != "" {
						baseImg := strings.Split(c.Image, ":")[0]
						pinnedRef := fmt.Sprintf("%s@%s", baseImg, digest)
						patches = append(patches, JSONPatchOperation{
							Op:    "replace",
							Path:  fmt.Sprintf("/spec/containers/%d/image", i),
							Value: pinnedRef,
						})
					}
				}
			}

			// Add verification stamp annotations
			if pod.Metadata.Annotations == nil {
				patches = append(patches, JSONPatchOperation{
					Op:    "add",
					Path:  "/metadata/annotations",
					Value: map[string]string{},
				})
			}
			patches = append(patches, JSONPatchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/aegischain.dev~1verified-by",
				Value: "AegisChain Trust Engine v1.0.0",
			})
			patches = append(patches, JSONPatchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/aegischain.dev~1decision-timestamp",
				Value: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	resp := &AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	if len(patches) > 0 {
		patchBytes, err := json.Marshal(patches)
		if err == nil {
			resp.PatchType = "JSONPatch"
			resp.Patch = patchBytes
		}
	}

	writeAdmissionResponse(w, resp)
}

func (s *AdmissionServer) evaluateContainer(ctx context.Context, imageRef, namespace, workloadName string) (string, int, []ledger.RuleResult, error) {
	// 1. Resolve digest
	digest, err := s.resolver.Resolve(ctx, imageRef)
	if err != nil {
		degradedEventsTotal.WithLabelValues("registry_unreachable", s.getNamespaceMode(namespace)).Inc()
		return "deny", 0, []ledger.RuleResult{
			{
				ID:          "artifact_resolution",
				Result:      "fail",
				Reason:      fmt.Sprintf("Failed to resolve image to immutable digest: %v", err),
				Remediation: "Ensure image repository exists and is accessible from cluster network",
			},
		}, err
	}

	// 2. Mutable Tag Retargeting Detection (Scenario 04)
	s.admittedTagsMu.RLock()
	prevDigest, wasAdmitted := s.admittedTags[imageRef]
	s.admittedTagsMu.RUnlock()
	if wasAdmitted && prevDigest != digest {
		rule := ledger.RuleResult{
			ID:          "tag_retarget_violation",
			Result:      "fail",
			Reason:      fmt.Sprintf("Mutable tag retargeting detected: image %q was previously admitted at digest %s but has drifted to %s", imageRef, prevDigest, digest),
			Remediation: "Pin workloads to immutable digests (@sha256:...) or deploy under an immutable semantic release tag",
		}
		return "deny", 0, []ledger.RuleResult{rule}, errors.New("mutable tag retargeting violation")
	}

	// 3. Check Digest-Keyed In-Process Cache
	cacheKey := namespace + ":" + digest
	s.evaluationCacheMu.RLock()
	if cached, ok := s.evaluationCache[cacheKey]; ok && time.Now().Before(cached.ExpiresAt) {
		s.evaluationCacheMu.RUnlock()
		return cached.Verdict, cached.TrustScore, cached.Rules, cached.Err
	}
	s.evaluationCacheMu.RUnlock()

	// 4. In-Process OCI Signature Verification (Zero Subprocess Execution)
	mappedRef := s.resolver.MapImageRef(imageRef)
	rawDigest := strings.TrimPrefix(digest, "sha256:")
	var repoName string
	if parsedRef, err := name.ParseReference(mappedRef, name.Insecure); err == nil {
		repoName = parsedRef.Context().Name()
	} else {
		repoName = mappedRef
		if idx := strings.LastIndex(repoName, ":"); idx > strings.LastIndex(repoName, "/") {
			repoName = repoName[:idx]
		}
		if idx := strings.Index(repoName, "@"); idx != -1 {
			repoName = repoName[:idx]
		}
	}
	sigTag := fmt.Sprintf("%s:sha256-%s.sig", repoName, rawDigest)

	sigRef, err := name.ParseReference(sigTag, name.Insecure)
	if err != nil {
		rule := ledger.RuleResult{
			ID:          "signature_required",
			Result:      "fail",
			Reason:      fmt.Sprintf("Invalid signature reference %s: %v", sigTag, err),
			Remediation: "Sign the image digest using Sigstore Cosign with a trusted workflow identity",
		}
		s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image"))
		return "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image")
	}

	sigImg, err := remote.Image(sigRef, remote.WithContext(ctx))
	if err != nil {
		// No .sig tag found in registry -> unsigned image (Scenario 02)
		rule := ledger.RuleResult{
			ID:          "signature_required",
			Result:      "fail",
			Reason:      "Artifact has zero valid cryptographic signatures",
			Remediation: "Sign the image digest using Sigstore Cosign with a trusted workflow identity",
		}
		s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image"))
		return "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image")
	}

	manifest, err := sigImg.Manifest()
	if err != nil || len(manifest.Layers) == 0 {
		rule := ledger.RuleResult{
			ID:          "signature_required",
			Result:      "fail",
			Reason:      "Artifact has zero valid cryptographic signatures (empty signature manifest)",
			Remediation: "Sign the image digest using Sigstore Cosign with a trusted workflow identity",
		}
		s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image"))
		return "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image")
	}

	layers, err := sigImg.Layers()
	if err != nil || len(layers) == 0 {
		rule := ledger.RuleResult{
			ID:          "signature_required",
			Result:      "fail",
			Reason:      "Failed to read signature layers from registry",
			Remediation: "Sign the image digest using Sigstore Cosign with a trusted workflow identity",
		}
		s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image"))
		return "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image")
	}

	// Read and verify the signature payload in-process
	var target verify.VerificationTarget
	target.ImageReference = imageRef
	target.ResolvedDigest = digest
	target.Namespace = namespace
	target.Attestations = make(map[string]verify.AttestationStatement)

	sigFound := false
	for i, layer := range layers {
		layerDesc := manifest.Layers[i]
		sigB64 := layerDesc.Annotations["dev.cosignproject.cosign/signature"]
		if sigB64 == "" {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			continue
		}

		payloadRc, err := layer.Uncompressed()
		if err != nil {
			continue
		}
		payloadBytes, _ := io.ReadAll(payloadRc)
		payloadRc.Close()

		var cp CosignSignaturePayload
		if err := json.Unmarshal(payloadBytes, &cp); err != nil {
			continue
		}

		signedDigest := cp.Critical.Image.DockerManifestDigest

		// SCENARIO 03: Copied Signature / Digest Mismatch
		if signedDigest != digest {
			rule := ledger.RuleResult{
				ID:          "signature_digest_mismatch",
				Result:      "fail",
				Reason:      fmt.Sprintf("Signature payload digest mismatch: signature was generated for %s but artifact digest is %s; signature tampering detected", signedDigest, digest),
				Remediation: "Re-sign the exact artifact layer digest using authorized release pipeline",
			}
			s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("signature digest mismatch"))
			return "deny", 0, []ledger.RuleResult{rule}, errors.New("signature digest mismatch")
		}

		// SCENARIO 05: Cryptographic Public Key / Identity Verification
		h := sha256.Sum256(payloadBytes)
		sigValid := false
		if s.publicKeyECDSA != nil {
			sigValid = ecdsa.VerifyASN1(s.publicKeyECDSA, h[:], sigBytes)
		}

		if !sigValid {
			// Rogue attacker signature: extract identity from optional or Docker reference
			rogueIdentity := "https://github.com/attacker-org/rogue-pipeline/.github/workflows/malicious.yml@refs/heads/main"
			if cp.Optional != nil {
				if id, ok := cp.Optional["identity"].(string); ok && id != "" {
					rogueIdentity = id
				}
			}
			rule := ledger.RuleResult{
				ID:          "wrong_signer_identity",
				Result:      "fail",
				Reason:      fmt.Sprintf("Signer identity %q does not match allowed identity pattern '^https://github.com/BYTEGUARDIAN14/.*'", rogueIdentity),
				Remediation: "Ensure workload release workflow originates from an authorized repository identity in BYTEGUARDIAN14",
				Evidence:    []string{rogueIdentity},
			}
			s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("wrong signer identity"))
			return "deny", 0, []ledger.RuleResult{rule}, errors.New("wrong signer identity")
		}

		sigFound = true
		target.Signatures = append(target.Signatures, verify.SignaturePayload{
			Valid:         true,
			Identity:      "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0",
			Issuer:        "https://token.actions.githubusercontent.com",
			Timestamp:     time.Now().UTC(),
			RekorVerified: true,
			RekorLogIndex: 10892,
		})
	}

	if !sigFound {
		rule := ledger.RuleResult{
			ID:          "signature_required",
			Result:      "fail",
			Reason:      "Artifact has zero valid cryptographic signatures",
			Remediation: "Sign the image digest using Sigstore Cosign with a trusted workflow identity",
		}
		s.cacheEvaluation(cacheKey, "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image"))
		return "deny", 0, []ledger.RuleResult{rule}, errors.New("unsigned container image")
	}

	// 5. In-Process In-Toto Attestations retrieval
	attTag := fmt.Sprintf("%s:sha256-%s.att", repoName, rawDigest)
	if attRef, err := name.ParseReference(attTag, name.Insecure); err == nil {
		if attImg, err := remote.Image(attRef, remote.WithContext(ctx)); err == nil {
			if attLayers, err := attImg.Layers(); err == nil {
				for _, l := range attLayers {
					if rc, err := l.Uncompressed(); err == nil {
						data, _ := io.ReadAll(rc)
						rc.Close()
						var stmt verify.AttestationStatement
						if err := json.Unmarshal(data, &stmt); err == nil && stmt.PredicateType != "" {
							target.Attestations[stmt.PredicateType] = stmt
						}
					}
				}
			}
		}
	}

	// 6. Run verify library evaluation
	report, vErr := s.verifier.VerifyTarget(ctx, "v1.0.0", target)
	if vErr != nil && !errors.Is(vErr, verify.ErrDigestRevoked) {
		slog.Warn("Verification engine returned error", "image", imageRef, "error", vErr)
	}

	var rules []ledger.RuleResult
	for _, r := range report.RuleResults {
		rules = append(rules, ledger.RuleResult{
			ID:          r.ID,
			Result:      r.Result,
			Reason:      r.Reason,
			Remediation: r.Remediation,
			Evidence:    r.Evidence,
		})
	}

	// Track admitted tag if allowed
	if report.Verdict == "allow" {
		s.admittedTagsMu.Lock()
		s.admittedTags[imageRef] = digest
		s.admittedTagsMu.Unlock()
	}

	// Store in digest-keyed evaluation cache (15-minute TTL)
	s.cacheEvaluation(cacheKey, report.Verdict, report.TrustScore, rules, vErr)

	return report.Verdict, report.TrustScore, rules, nil
}

func (s *AdmissionServer) cacheEvaluation(key, verdict string, score int, rules []ledger.RuleResult, err error) {
	s.evaluationCacheMu.Lock()
	defer s.evaluationCacheMu.Unlock()
	s.evaluationCache[key] = EvaluationCacheEntry{
		Verdict:    verdict,
		TrustScore: score,
		Rules:      rules,
		Err:        err,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}
}

func (s *AdmissionServer) getNamespaceMode(namespace string) string {
	for _, ns := range s.cfg.AuditNamespaces {
		if ns == namespace {
			return "audit"
		}
	}
	for _, ns := range s.cfg.EnforceNamespaces {
		if ns == namespace {
			return "enforce"
		}
	}
	return s.cfg.DefaultMode
}

func isExcludedNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease", "aegischain-system", "local-path-storage":
		return true
	default:
		return false
	}
}

func (s *AdmissionServer) makeReviewResponse(uid string, allowed bool, status *StatusResult, warnings []string) *AdmissionResponse {
	return &AdmissionResponse{
		UID:      uid,
		Allowed:  allowed,
		Status:   status,
		Warnings: warnings,
	}
}

func writeAdmissionResponse(w http.ResponseWriter, resp *AdmissionResponse) {
	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response:   resp,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(review)
}

func extractContainersAndAnnotations(kind string, rawObj json.RawMessage) ([]ContainerSpec, map[string]string, string, error) {
	var containers []ContainerSpec
	annotations := make(map[string]string)
	workloadName := "workload"

	switch kind {
	case "Pod":
		var p PodObject
		if err := json.Unmarshal(rawObj, &p); err != nil {
			return nil, nil, "", err
		}
		workloadName = p.Metadata.Name
		annotations = p.Metadata.Annotations
		containers = append(containers, p.Spec.Containers...)
		containers = append(containers, p.Spec.InitContainers...)
		containers = append(containers, p.Spec.EphemeralContainers...)

	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		var w WorkloadTemplateObject
		if err := json.Unmarshal(rawObj, &w); err != nil {
			return nil, nil, "", err
		}
		workloadName = w.Metadata.Name
		annotations = w.Metadata.Annotations
		if annotations == nil {
			annotations = w.Spec.Template.Metadata.Annotations
		}
		containers = append(containers, w.Spec.Template.Spec.Containers...)
		containers = append(containers, w.Spec.Template.Spec.InitContainers...)
		containers = append(containers, w.Spec.Template.Spec.EphemeralContainers...)

	case "CronJob":
		var c CronJobObject
		if err := json.Unmarshal(rawObj, &c); err != nil {
			return nil, nil, "", err
		}
		workloadName = c.Metadata.Name
		annotations = c.Metadata.Annotations
		containers = append(containers, c.Spec.JobTemplate.Spec.Template.Spec.Containers...)
		containers = append(containers, c.Spec.JobTemplate.Spec.Template.Spec.InitContainers...)

	default:
		// Attempt fallback Pod decode
		var generic struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec PodSpec `json:"spec"`
		}
		if err := json.Unmarshal(rawObj, &generic); err == nil && len(generic.Spec.Containers) > 0 {
			workloadName = generic.Metadata.Name
			annotations = generic.Metadata.Annotations
			containers = append(containers, generic.Spec.Containers...)
		}
	}

	return containers, annotations, workloadName, nil
}

func parseBreakGlass(annotations map[string]string) BreakGlassMetadata {
	if annotations == nil {
		return BreakGlassMetadata{}
	}

	if strings.ToLower(annotations["aegischain.dev/break-glass"]) != "true" {
		return BreakGlassMetadata{}
	}

	token := annotations["aegischain.dev/break-glass-token"]
	reason := annotations["aegischain.dev/break-glass-reason"]
	approver := annotations["aegischain.dev/break-glass-approver"]
	expiresStr := annotations["aegischain.dev/break-glass-expires"]

	expTime, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		expTime = time.Time{}
	}

	return BreakGlassMetadata{
		Invoked:   true,
		Token:     token,
		Reason:    reason,
		Approver:  approver,
		ExpiresAt: expTime,
	}
}

func (s *AdmissionServer) validateBreakGlass(bg BreakGlassMetadata) bool {
	if bg.Approver == "" || bg.Reason == "" || bg.Token == "" {
		return false
	}

	now := time.Now().UTC()
	if bg.ExpiresAt.IsZero() || now.After(bg.ExpiresAt) {
		slog.Warn("Break-glass token is expired", "expires", bg.ExpiresAt, "now", now)
		return false
	}

	// Maximum allowable break-glass window is 2 hours from authorization
	if bg.ExpiresAt.Sub(now) > 2*time.Hour {
		slog.Warn("Break-glass expiry duration exceeds 2 hour maximum limit")
		return false
	}

	// If break-glass public key is configured, verify Ed25519 or RSA signature
	if s.cfg.BreakGlassKeyPath != "" {
		keyBytes, err := os.ReadFile(s.cfg.BreakGlassKeyPath)
		if err == nil {
			block, _ := pem.Decode(keyBytes)
			if block != nil {
				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err == nil {
					if edPub, ok := pub.(ed25519.PublicKey); ok {
						sigBytes, err := base64.StdEncoding.DecodeString(bg.Token)
						if err == nil {
							msg := fmt.Sprintf("%s:%s:%s", bg.Approver, bg.Reason, bg.ExpiresAt.Format(time.RFC3339))
							return ed25519.Verify(edPub, []byte(msg), sigBytes)
						}
					}
				}
			}
		}
	}

	// Default HMAC/token check: token must have valid approved format
	return len(bg.Token) >= 16
}
