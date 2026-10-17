package policy

import (
	"context"
	"testing"

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
