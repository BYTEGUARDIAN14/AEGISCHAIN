package verify

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleSLSAPredicate(digest, builderID, repo string) json.RawMessage {
	slsa := map[string]any{
		"buildDefinition": map[string]any{
			"buildType": "https://actions.github.com/buildtypes/workflow/v1",
			"externalParameters": map[string]any{
				"workflow": map[string]any{
					"ref":        "refs/heads/main",
					"repository": repo,
					"path":       ".github/workflows/release.yml",
				},
			},
		},
		"runDetails": map[string]any{
			"builder": map[string]any{
				"id": builderID,
			},
		},
	}
	bytes, _ := json.Marshal(slsa)
	return bytes
}

func sampleAttestationStatement(predType, digest string, predicate json.RawMessage) AttestationStatement {
	return AttestationStatement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: predType,
		Subject: []SubjectDigest{
			{
				Name: "pkg:oci/sample-app",
				Digest: map[string]string{
					"sha256": digest,
				},
			},
		},
		Predicate: predicate,
	}
}

func getStandardConfig() TrustConfig {
	return TrustConfig{
		AllowedIdentities: []*regexp.Regexp{
			regexp.MustCompile(`^https://github\.com/BYTEGUARDIAN14/aegischain/.*`),
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
		RequireAllPredicates: true,
	}
}

func TestVerifyGoodImage(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	slsaPred := sampleSLSAPredicate(digest, cfg.TrustedBuilders[0], cfg.ExpectedSourceRepo)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: digest,
		Namespace:      "prod",
		Signatures: []SignaturePayload{
			{
				Valid:         true,
				Identity:      "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0",
				Issuer:        "https://token.actions.githubusercontent.com",
				Timestamp:     time.Now().UTC(),
				RekorVerified: true,
				RekorLogIndex: 88721,
			},
		},
		Attestations: map[string]AttestationStatement{
			PredicateSLSAProvenance: sampleAttestationStatement(PredicateSLSAProvenance, digest, slsaPred),
			PredicateCycloneDXSBOM:  sampleAttestationStatement(PredicateCycloneDXSBOM, digest, json.RawMessage(`{}`)),
			PredicateVulnScan:       sampleAttestationStatement(PredicateVulnScan, digest, json.RawMessage(`{}`)),
			PredicateOpenVEX:        sampleAttestationStatement(PredicateOpenVEX, digest, json.RawMessage(`{}`)),
		},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "allow", report.Verdict)
	assert.Equal(t, 100, report.TrustScore)
	assert.False(t, report.Cached)

	// Second execution should return cached report
	cachedReport, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "allow", cachedReport.Verdict)
	assert.True(t, cachedReport.Cached)
}

func TestVerifyUnsignedImage(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Namespace:      "prod",
		Signatures:     []SignaturePayload{},
		Attestations:   map[string]AttestationStatement{},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "deny", report.Verdict)
	assert.Less(t, report.TrustScore, 50)
	assert.Equal(t, "fail", report.RuleResults[0].Result)
}

func TestVerifyWrongSignerIdentity(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Namespace:      "prod",
		Signatures: []SignaturePayload{
			{
				Valid:     true,
				Identity:  "https://github.com/attacker-org/malicious-repo/.github/workflows/attack.yml@refs/heads/main",
				Issuer:    "https://token.actions.githubusercontent.com",
				Timestamp: time.Now().UTC(),
			},
		},
		Attestations: map[string]AttestationStatement{},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "deny", report.Verdict)
	assert.Equal(t, "fail", report.RuleResults[0].Result)
	assert.Contains(t, report.RuleResults[0].Reason, "Signer identity does not match")
}

func TestVerifyWrongSignerIssuer(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		Namespace:      "prod",
		Signatures: []SignaturePayload{
			{
				Valid:     true,
				Identity:  "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0",
				Issuer:    "https://untrusted-oidc-issuer.example.com",
				Timestamp: time.Now().UTC(),
			},
		},
		Attestations: map[string]AttestationStatement{},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "deny", report.Verdict)
	assert.Contains(t, report.RuleResults[0].Reason, "Untrusted signature issuer")
}

func TestVerifyUntrustedBuilder(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	digest := "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	untrustedBuilder := "https://github.com/rogue-builder/unverified-builder@v1"
	slsaPred := sampleSLSAPredicate(digest, untrustedBuilder, cfg.ExpectedSourceRepo)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: digest,
		Namespace:      "prod",
		Signatures: []SignaturePayload{
			{
				Valid:     true,
				Identity:  "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0",
				Issuer:    "https://token.actions.githubusercontent.com",
				Timestamp: time.Now().UTC(),
			},
		},
		Attestations: map[string]AttestationStatement{
			PredicateSLSAProvenance: sampleAttestationStatement(PredicateSLSAProvenance, digest, slsaPred),
		},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "deny", report.Verdict)

	foundBuilderFailure := false
	for _, r := range report.RuleResults {
		if r.ID == "provenance_required" && r.Result == "fail" {
			foundBuilderFailure = true
			assert.Contains(t, r.Reason, "Untrusted SLSA builder")
		}
	}
	assert.True(t, foundBuilderFailure)
}

func TestVerifyProvenanceDigestMismatch(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	imageDigest := "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	differentDigest := "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	slsaPred := sampleSLSAPredicate(differentDigest, cfg.TrustedBuilders[0], cfg.ExpectedSourceRepo)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: imageDigest,
		Namespace:      "prod",
		Signatures: []SignaturePayload{
			{
				Valid:     true,
				Identity:  "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0",
				Issuer:    "https://token.actions.githubusercontent.com",
				Timestamp: time.Now().UTC(),
			},
		},
		Attestations: map[string]AttestationStatement{
			// Attestation declares differentDigest as subject
			PredicateSLSAProvenance: sampleAttestationStatement(PredicateSLSAProvenance, differentDigest, slsaPred),
		},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "deny", report.Verdict)

	foundMismatch := false
	for _, r := range report.RuleResults {
		if r.ID == "attestation_subject_match" && r.Result == "fail" {
			foundMismatch = true
		}
	}
	assert.True(t, foundMismatch)
}

func TestVerifyRollbackAttack(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	now := time.Now().UTC()
	deployedBuiltAt := now.Add(-1 * time.Hour)
	olderCandidateBuiltAt := now.Add(-5 * time.Hour) // Older than deployed!

	digest := "sha256:8888888888888888888888888888888888888888888888888888888888888888"
	slsaPred := sampleSLSAPredicate(digest, cfg.TrustedBuilders[0], cfg.ExpectedSourceRepo)

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v0.9.0",
		ResolvedDigest: digest,
		Namespace:      "prod",
		Signatures: []SignaturePayload{
			{
				Valid:     true,
				Identity:  "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v0.9.0",
				Issuer:    "https://token.actions.githubusercontent.com",
				Timestamp: olderCandidateBuiltAt,
			},
		},
		Attestations: map[string]AttestationStatement{
			PredicateSLSAProvenance: sampleAttestationStatement(PredicateSLSAProvenance, digest, slsaPred),
		},
		DeployedWorkload: &DeployedState{
			WorkloadName: "sample-app-deployment",
			ImageDigest:  "sha256:9999999999999999999999999999999999999999999999999999999999999999",
			BuiltAt:      deployedBuiltAt,
		},
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	require.NoError(t, err)
	assert.Equal(t, "deny", report.Verdict)

	foundRollback := false
	for _, r := range report.RuleResults {
		if r.ID == "freshness" && r.Result == "fail" {
			foundRollback = true
			assert.Contains(t, r.Reason, "Anti-rollback violation")
		}
	}
	assert.True(t, foundRollback)
}

func TestVerifyRevokedDigest(t *testing.T) {
	ctx := context.Background()
	cfg := getStandardConfig()
	verifier := NewVerifier(nil, cfg, 5*time.Minute)

	revokedDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifier.RevokeDigest(revokedDigest, "Signing identity key exfiltration disclosed in advisory SEC-01")

	target := VerificationTarget{
		ImageReference: "localhost:5001/sample-app:v1.0.0",
		ResolvedDigest: revokedDigest,
		Namespace:      "prod",
	}

	report, err := verifier.VerifyTarget(ctx, "policy-v1", target)
	assert.ErrorIs(t, err, ErrDigestRevoked)
	assert.Equal(t, "deny", report.Verdict)
	assert.Equal(t, "fail", report.RuleResults[0].Result)
	assert.Contains(t, report.RuleResults[0].Reason, "Image digest is revoked")
}
