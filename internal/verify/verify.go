package verify

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/byteaegis/aegischain/internal/resolver"
)

var (
	ErrUnsignedImage       = errors.New("image is not cryptographically signed")
	ErrWrongSignerIdentity = errors.New("signature identity does not match allowed policy pattern")
	ErrWrongSignerIssuer   = errors.New("signature OIDC issuer is not trusted")
	ErrUntrustedBuilder    = errors.New("SLSA provenance builder is not on the trusted allowlist")
	ErrProvenanceMismatch  = errors.New("provenance subject digest does not match image digest")
	ErrSourceRepoMismatch  = errors.New("source repository does not match policy requirements")
	ErrRollbackDetected    = errors.New("rollback detected: image build timestamp is older than deployed version")
	ErrMissingAttestation  = errors.New("mandatory in-toto attestation missing")
	ErrDigestRevoked       = errors.New("image digest is present on active revocation list")
)

const (
	PredicateSLSAProvenance = "https://slsa.dev/provenance/v1"
	PredicateCycloneDXSBOM  = "https://cyclonedx.org/schema"
	PredicateVulnScan       = "https://cosign.sigstore.dev/attestation/vuln/v1"
	PredicateOpenVEX        = "https://openvex.dev/ns/v0.2.0"
)

type TrustConfig struct {
	AllowedIdentities    []*regexp.Regexp
	AllowedIssuers       []string
	TrustedBuilders      []string
	ExpectedSourceRepo   string
	MinVersionAgeLimit   time.Duration
	EnforceAntiRollback  bool
	RequireAllPredicates bool
}

type SignaturePayload struct {
	Valid          bool      `json:"valid"`
	Identity       string    `json:"identity"`
	Issuer         string    `json:"issuer"`
	Timestamp      time.Time `json:"timestamp"`
	RekorVerified  bool      `json:"rekor_verified"`
	RekorLogIndex  int64     `json:"rekor_log_index,omitempty"`
	KeyID          string    `json:"key_id,omitempty"`
}

type AttestationStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []SubjectDigest `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type SubjectDigest struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type SLSAPredicate struct {
	BuildDefinition struct {
		BuildType          string `json:"buildType"`
		ExternalParameters struct {
			Workflow struct {
				Ref        string `json:"ref"`
				Repository string `json:"repository"`
				Path       string `json:"path"`
			} `json:"workflow"`
		} `json:"externalParameters"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata struct {
			InvocationID string `json:"invocationId"`
		} `json:"metadata"`
	} `json:"runDetails"`
}

type VerificationTarget struct {
	ImageReference   string
	ResolvedDigest   string
	Namespace        string
	Signatures       []SignaturePayload
	Attestations     map[string]AttestationStatement
	DeployedWorkload *DeployedState
}

type DeployedState struct {
	WorkloadName string
	ImageDigest  string
	BuiltAt      time.Time
}

type VerificationRuleResult struct {
	ID          string   `json:"id"`
	Result      string   `json:"result"` // pass | fail
	Reason      string   `json:"reason,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type VerificationReport struct {
	ImageRef      string                   `json:"image_ref"`
	Digest        string                   `json:"digest"`
	Verdict       string                   `json:"verdict"` // allow | deny
	TrustScore    int                      `json:"trust_score"`
	EvaluatedAt   time.Time                `json:"evaluated_at"`
	Cached        bool                     `json:"cached"`
	RuleResults   []VerificationRuleResult `json:"rules"`
	Attestations  []string                 `json:"attestations_found"`
}

type CacheKey struct {
	Digest        string
	PolicyVersion string
}

type CacheRecord struct {
	Report    VerificationReport
	ExpiresAt time.Time
}

type Verifier struct {
	mu           sync.RWMutex
	resolver     *resolver.Resolver
	config       TrustConfig
	cache        map[CacheKey]CacheRecord
	cacheTTL     time.Duration
	publicKey    crypto.PublicKey
	revocations  map[string]string // digest -> reason
}

func NewVerifier(res *resolver.Resolver, cfg TrustConfig, cacheTTL time.Duration) *Verifier {
	return &Verifier{
		resolver:    res,
		config:      cfg,
		cache:       make(map[CacheKey]CacheRecord),
		cacheTTL:    cacheTTL,
		revocations: make(map[string]string),
	}
}

// LoadPublicKeyPEM loads an ECDSA public key for key-based verification.
func (v *Verifier) LoadPublicKeyPEM(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("failed to parse PEM block from public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.publicKey = pub
	return nil
}

// LoadPublicKeyFile loads a public key from disk.
func (v *Verifier) LoadPublicKeyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return v.LoadPublicKeyPEM(data)
}

// RevokeDigest adds a digest to the revocation list and evicts all cache entries.
func (v *Verifier) RevokeDigest(digest, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.revocations[digest] = reason
	if v.resolver != nil {
		v.resolver.RevokeDigest(digest)
	}
	// Invalidate cache
	for k := range v.cache {
		if k.Digest == digest {
			delete(v.cache, k)
		}
	}
}

// VerifyTarget runs full verification pipeline on a target container workload.
func (v *Verifier) VerifyTarget(ctx context.Context, policyVersion string, target VerificationTarget) (*VerificationReport, error) {
	v.mu.RLock()
	reason, isRevoked := v.revocations[target.ResolvedDigest]
	v.mu.RUnlock()
	if isRevoked {
		return &VerificationReport{
			ImageRef:    target.ImageReference,
			Digest:      target.ResolvedDigest,
			Verdict:     "deny",
			TrustScore:  0,
			EvaluatedAt: time.Now().UTC(),
			RuleResults: []VerificationRuleResult{
				{
					ID:          "revocation_check",
					Result:      "fail",
					Reason:      fmt.Sprintf("Image digest is revoked: %s", reason),
					Remediation: "Build new artifact from uncompromised commit ref",
				},
			},
		}, ErrDigestRevoked
	}

	// Check cache
	cacheKey := CacheKey{Digest: target.ResolvedDigest, PolicyVersion: policyVersion}
	v.mu.RLock()
	if cached, ok := v.cache[cacheKey]; ok {
		if time.Now().Before(cached.ExpiresAt) {
			v.mu.RUnlock()
			rep := cached.Report
			rep.Cached = true
			return &rep, nil
		}
	}
	v.mu.RUnlock()

	var rules []VerificationRuleResult
	score := 100
	verdict := "allow"
	attestationsFound := make([]string, 0)

	// 1. Signature Verification
	sigPass, sigRule := v.verifySignature(target)
	rules = append(rules, sigRule)
	if !sigPass {
		score -= 50
		verdict = "deny"
	}

	// 2. In-Toto Attestations Checks
	for predType, stmt := range target.Attestations {
		attestationsFound = append(attestationsFound, predType)

		// Check subject digest matches image digest
		if err := v.verifySubjectDigest(stmt, target.ResolvedDigest); err != nil {
			rules = append(rules, VerificationRuleResult{
				ID:          "attestation_subject_match",
				Result:      "fail",
				Reason:      fmt.Sprintf("Attestation %s subject mismatch: %v", predType, err),
				Remediation: "Ensure attestation was created specifically for this image layer digest",
			})
			score -= 30
			verdict = "deny"
		}
	}

	// 3. Mandatory Predicate Check
	if v.config.RequireAllPredicates {
		mandatories := []string{PredicateSLSAProvenance, PredicateCycloneDXSBOM, PredicateVulnScan, PredicateOpenVEX}
		for _, m := range mandatories {
			if _, exists := target.Attestations[m]; !exists {
				rules = append(rules, VerificationRuleResult{
					ID:          "mandatory_predicate_" + sanitizeID(m),
					Result:      "fail",
					Reason:      fmt.Sprintf("Mandatory predicate %s is missing", m),
					Remediation: "Configure pipeline to emit and attest predicate during release",
				})
				score -= 20
				verdict = "deny"
			}
		}
	}

	// 4. SLSA Provenance Deep Verification
	if slsaStmt, exists := target.Attestations[PredicateSLSAProvenance]; exists {
		slsaPass, slsaRule := v.verifySLSAProvenance(slsaStmt, target)
		rules = append(rules, slsaRule)
		if !slsaPass {
			score -= 40
			verdict = "deny"
		}
	}

	// 5. Anti-Rollback Check
	if v.config.EnforceAntiRollback && target.DeployedWorkload != nil {
		rbPass, rbRule := v.verifyAntiRollback(target)
		rules = append(rules, rbRule)
		if !rbPass {
			score -= 40
			verdict = "deny"
		}
	}

	if score < 0 {
		score = 0
	}

	report := VerificationReport{
		ImageRef:          target.ImageReference,
		Digest:            target.ResolvedDigest,
		Verdict:           verdict,
		TrustScore:        score,
		EvaluatedAt:       time.Now().UTC(),
		Cached:            false,
		RuleResults:       rules,
		Attestations:      attestationsFound,
	}

	// Store in cache
	v.mu.Lock()
	v.cache[cacheKey] = CacheRecord{
		Report:    report,
		ExpiresAt: time.Now().Add(v.cacheTTL),
	}
	v.mu.Unlock()

	return &report, nil
}

func (v *Verifier) verifySignature(target VerificationTarget) (bool, VerificationRuleResult) {
	if len(target.Signatures) == 0 {
		return false, VerificationRuleResult{
			ID:          "signature_required",
			Result:      "fail",
			Reason:      "Artifact has zero valid cryptographic signatures",
			Remediation: "Sign the image digest using Sigstore Cosign with a trusted workflow identity",
		}
	}

	for _, sig := range target.Signatures {
		if !sig.Valid {
			continue
		}

		// Issuer check
		issuerTrusted := false
		for _, iss := range v.config.AllowedIssuers {
			if sig.Issuer == iss {
				issuerTrusted = true
				break
			}
		}
		if len(v.config.AllowedIssuers) > 0 && !issuerTrusted {
			return false, VerificationRuleResult{
				ID:          "signature_identity",
				Result:      "fail",
				Reason:      fmt.Sprintf("Untrusted signature issuer: %s", sig.Issuer),
				Remediation: "Configure workload to sign through an approved OIDC provider",
				Evidence:    []string{sig.Issuer},
			}
		}

		// Identity regex match
		identityMatches := false
		for _, r := range v.config.AllowedIdentities {
			if r.MatchString(sig.Identity) {
				identityMatches = true
				break
			}
		}
		if len(v.config.AllowedIdentities) > 0 && !identityMatches {
			return false, VerificationRuleResult{
				ID:          "signature_identity",
				Result:      "fail",
				Reason:      fmt.Sprintf("Signer identity does not match approved patterns: %s", sig.Identity),
				Remediation: "Ensure build workflow matches the authorized repository and branch identity",
				Evidence:    []string{sig.Identity},
			}
		}

		evidence := []string{fmt.Sprintf("identity:%s", sig.Identity), fmt.Sprintf("issuer:%s", sig.Issuer)}
		if sig.RekorVerified {
			evidence = append(evidence, fmt.Sprintf("rekor:%d", sig.RekorLogIndex))
		}

		return true, VerificationRuleResult{
			ID:       "signature_required",
			Result:   "pass",
			Evidence: evidence,
		}
	}

	return false, VerificationRuleResult{
		ID:          "signature_required",
		Result:      "fail",
		Reason:      "No valid matching signature found",
		Remediation: "Sign image with approved keyless identity",
	}
}

func (v *Verifier) verifySubjectDigest(stmt AttestationStatement, expectedDigest string) error {
	rawExpected := strings.TrimPrefix(expectedDigest, "sha256:")
	for _, sub := range stmt.Subject {
		if d, ok := sub.Digest["sha256"]; ok {
			if strings.TrimPrefix(d, "sha256:") == rawExpected {
				return nil
			}
		}
	}
	return ErrProvenanceMismatch
}

func (v *Verifier) verifySLSAProvenance(stmt AttestationStatement, target VerificationTarget) (bool, VerificationRuleResult) {
	var pred SLSAPredicate
	if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
		return false, VerificationRuleResult{
			ID:          "provenance_required",
			Result:      "fail",
			Reason:      fmt.Sprintf("Failed to decode SLSA predicate: %v", err),
			Remediation: "Produce valid in-toto Statement with slsa.dev/provenance/v1 predicate",
		}
	}

	// Verify Builder ID
	builderApproved := false
	for _, b := range v.config.TrustedBuilders {
		if pred.RunDetails.Builder.ID == b {
			builderApproved = true
			break
		}
	}
	if len(v.config.TrustedBuilders) > 0 && !builderApproved {
		return false, VerificationRuleResult{
			ID:          "provenance_required",
			Result:      "fail",
			Reason:      fmt.Sprintf("Untrusted SLSA builder: %s", pred.RunDetails.Builder.ID),
			Remediation: "Build container releases using approved SLSA generator workflow",
			Evidence:    []string{pred.RunDetails.Builder.ID},
		}
	}

	// Verify Source Repository
	if v.config.ExpectedSourceRepo != "" {
		if pred.BuildDefinition.ExternalParameters.Workflow.Repository != v.config.ExpectedSourceRepo {
			return false, VerificationRuleResult{
				ID:          "provenance_required",
				Result:      "fail",
				Reason:      fmt.Sprintf("Source repository mismatch: expected %s, got %s", v.config.ExpectedSourceRepo, pred.BuildDefinition.ExternalParameters.Workflow.Repository),
				Remediation: "Workload provenance must originate from the authoritative source repository",
			}
		}
	}

	return true, VerificationRuleResult{
		ID:       "provenance_required",
		Result:   "pass",
		Evidence: []string{pred.RunDetails.Builder.ID, pred.BuildDefinition.ExternalParameters.Workflow.Repository},
	}
}

func (v *Verifier) verifyAntiRollback(target VerificationTarget) (bool, VerificationRuleResult) {
	deployed := target.DeployedWorkload
	if deployed == nil {
		return true, VerificationRuleResult{ID: "freshness", Result: "pass"}
	}

	// Extract build timestamp from signature or provenance
	var currentBuildTime time.Time
	for _, sig := range target.Signatures {
		if sig.Valid && !sig.Timestamp.IsZero() {
			currentBuildTime = sig.Timestamp
			break
		}
	}

	if currentBuildTime.IsZero() {
		// Can't evaluate timestamp, assume pass
		return true, VerificationRuleResult{ID: "freshness", Result: "pass"}
	}

	if currentBuildTime.Before(deployed.BuiltAt) {
		return false, VerificationRuleResult{
			ID:          "freshness",
			Result:      "fail",
			Reason:      fmt.Sprintf("Anti-rollback violation: build timestamp %s is older than active version %s (%s)", currentBuildTime.Format(time.RFC3339), deployed.BuiltAt.Format(time.RFC3339), deployed.ImageDigest),
			Remediation: "Deploy version with build timestamp strictly newer than active workload",
		}
	}

	return true, VerificationRuleResult{
		ID:       "freshness",
		Result:   "pass",
		Evidence: []string{fmt.Sprintf("built_at:%s", currentBuildTime.Format(time.RFC3339))},
	}
}

func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, "https://", "")
	s = strings.ReplaceAll(s, "http://", "")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}
