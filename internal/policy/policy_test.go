package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleRego = `
package aegischain.trust

import rego.v1

default decision = {
	"verdict": "deny",
	"mode": "enforce",
	"trust_score": 0,
	"rules": [
		{
			"id": "signature_required",
			"result": "fail",
			"reason": "Missing or invalid cryptographic signature"
		}
	]
}

decision = {
	"verdict": "allow",
	"mode": "enforce",
	"trust_score": 100,
	"rules": [
		{
			"id": "signature_required",
			"result": "pass",
			"evidence": ["rekor:12345"]
		}
	]
} if {
	input.signature.valid == true
}
`

const updatedRego = `
package aegischain.trust

import rego.v1

default decision = {
	"verdict": "allow",
	"mode": "audit",
	"trust_score": 85,
	"rules": []
}
`

func TestEngineEvaluateAllow(t *testing.T) {
	ctx := context.Background()
	engine, err := NewEngine(ctx, "sha256:testversion", sampleRego)
	require.NoError(t, err)

	input := map[string]any{
		"signature": map[string]any{
			"valid": true,
		},
	}

	resp, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.Equal(t, "allow", resp.Verdict)
	assert.Equal(t, 100, resp.TrustScore)
	assert.Equal(t, "sha256:testversion", resp.PolicyVersion)
	assert.Equal(t, "pass", resp.Rules[0].Result)
}

func TestEngineEvaluateDeny(t *testing.T) {
	ctx := context.Background()
	engine, err := NewEngine(ctx, "sha256:testversion", sampleRego)
	require.NoError(t, err)

	input := map[string]any{
		"signature": map[string]any{
			"valid": false,
		},
	}

	resp, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.Equal(t, "deny", resp.Verdict)
	assert.Equal(t, 0, resp.TrustScore)
	assert.Equal(t, "fail", resp.Rules[0].Result)
}

func TestEngineEmptyInput(t *testing.T) {
	ctx := context.Background()
	engine, err := NewEngine(ctx, "sha256:testversion", sampleRego)
	require.NoError(t, err)

	_, err = engine.Evaluate(ctx, nil)
	assert.ErrorIs(t, err, ErrEmptyInput)
}

func TestEngineHotReload(t *testing.T) {
	ctx := context.Background()
	engine, err := NewEngine(ctx, "v1.0.0", sampleRego)
	require.NoError(t, err)

	err = engine.HotReload(ctx, "v1.1.0", updatedRego)
	require.NoError(t, err)

	resp, err := engine.Evaluate(ctx, map[string]any{"dummy": true})
	require.NoError(t, err)
	assert.Equal(t, "audit", resp.Mode)
	assert.Equal(t, "v1.1.0", resp.PolicyVersion)
}

func TestEngineCompilationFailure(t *testing.T) {
	ctx := context.Background()
	_, err := NewEngine(ctx, "v1.0.0", "invalid rego syntax ::: ???")
	assert.ErrorIs(t, err, ErrCompilationFailed)
}

func TestExemptionsValidation(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	exemptions := []Exemption{
		{
			ID:        "EX-VALID",
			Owner:     "sec@byteaegis.in",
			Reason:    "Active waiver",
			ExpiresAt: "2027-01-01T00:00:00Z",
		},
		{
			ID:        "EX-EXPIRED",
			Owner:     "dev@byteaegis.in",
			Reason:    "Old waiver",
			ExpiresAt: "2026-01-01T00:00:00Z",
		},
		{
			ID:        "EX-BAD-DATE",
			Owner:     "dev@byteaegis.in",
			Reason:    "Bad date",
			ExpiresAt: "invalid-date",
		},
		{
			ID:     "EX-NO-DATE",
			Owner  : "dev@byteaegis.in",
			Reason: "No date",
		},
	}

	expired := ValidateExemptions(exemptions, now)
	require.Len(t, expired, 3)
	assert.Equal(t, "EX-EXPIRED", expired[0].ID)
	assert.Contains(t, expired[0].Error(), "expired on 2026-01-01")
	assert.Equal(t, "EX-BAD-DATE", expired[1].ID)
	assert.Equal(t, "EX-NO-DATE", expired[2].ID)
}

func TestVerifyExemptionsDirectory(t *testing.T) {
	tempDir := t.TempDir()
	validContent := `{
		"exemptions": [
			{
				"id": "EX-TEST-1",
				"owner": "sec@byteaegis.in",
				"reason": "Test waiver",
				"expires_at": "2028-01-01T00:00:00Z"
			}
		]
	}`
	err := os.WriteFile(filepath.Join(tempDir, "exemptions.json"), []byte(validContent), 0600)
	require.NoError(t, err)

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	all, expired, err := VerifyExemptionsDirectory(tempDir, now)
	require.NoError(t, err)
	assert.Len(t, all, 1)
	assert.Empty(t, expired)

	// Now add an expired exemption
	expiredContent := `{
		"exemptions": [
			{
				"id": "EX-EXPIRED-TEST",
				"owner": "sec@byteaegis.in",
				"reason": "Expired waiver",
				"expires_at": "2025-01-01T00:00:00Z"
			}
		]
	}`
	err = os.WriteFile(filepath.Join(tempDir, "expired.json"), []byte(expiredContent), 0600)
	require.NoError(t, err)

	all, expired, err = VerifyExemptionsDirectory(tempDir, now)
	require.NoError(t, err)
	assert.Len(t, all, 2)
	assert.Len(t, expired, 1)
	assert.Equal(t, "EX-EXPIRED-TEST", expired[0].ID)
}

func TestVerifyProductionExemptionsFile(t *testing.T) {
	exemptions, err := LoadExemptions(filepath.Join("..", "..", "policies", "data", "exemptions.json"))
	require.NoError(t, err)
	assert.NotEmpty(t, exemptions)

	now := time.Now().UTC()
	expired := ValidateExemptions(exemptions, now)
	assert.Empty(t, expired, "production exemptions should not contain expired entries")
}
