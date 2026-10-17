package risk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientScorePackageAndSBOM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/score/package", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)

		score := 0
		isMal := false
		if req["name"] == "crossenv" {
			score = 100
			isMal = true
		}

		resp := PackageScore{
			Name:        req["name"],
			Ecosystem:   req["ecosystem"],
			Score:       score,
			RiskLevel:   "LOW",
			IsMalicious: isMal,
		}
		if isMal {
			resp.RiskLevel = "CRITICAL"
			resp.HardGateTriggered = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/score/sbom", func(w http.ResponseWriter, r *http.Request) {
		resp := SBOMResult{
			OverallRiskScore:     10,
			RiskThreshold:        65,
			HasMaliciousPackages: false,
			Verdict:              "allow",
			ComponentCount:       2,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, 2*time.Second)
	ctx := context.Background()

	// 1. Clean package
	cleanScore, err := client.ScorePackage(ctx, "react", "npm", "18.0.0")
	require.NoError(t, err)
	assert.Equal(t, 0, cleanScore.Score)
	assert.False(t, cleanScore.IsMalicious)

	// 2. Malicious package
	malScore, err := client.ScorePackage(ctx, "crossenv", "npm", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, 100, malScore.Score)

	// 2b. Cache hit (cached score should return without HTTP call)
	cachedScore, err := client.ScorePackage(ctx, "crossenv", "npm", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, 100, cachedScore.Score)
	assert.True(t, malScore.IsMalicious)

	// 3. SBOM score
	sbomRes, err := client.ScoreSBOM(ctx, []Component{{Name: "react", Ecosystem: "npm"}}, "prod", 65)
	require.NoError(t, err)
	assert.Equal(t, "allow", sbomRes.Verdict)
	assert.Equal(t, 10, sbomRes.OverallRiskScore)
}

func TestClientCircuitBreaker(t *testing.T) {
	// Connect to non-existent port to force failures
	client := NewClient("http://127.0.0.1:59999", 50*time.Millisecond)
	client.failureThreshold = 2
	client.cooldownDuration = 500 * time.Millisecond
	ctx := context.Background()

	// Failure 1
	_, err := client.ScorePackage(ctx, "react", "npm", "1.0.0")
	assert.ErrorIs(t, err, ErrServiceUnavailable)

	// Failure 2 -> should trip circuit breaker
	_, err = client.ScorePackage(ctx, "react", "npm", "1.0.0")
	assert.ErrorIs(t, err, ErrServiceUnavailable)

	// Attempt 3 -> immediately blocked by circuit breaker without network call
	_, err = client.ScorePackage(ctx, "react", "npm", "1.0.0")
	assert.ErrorIs(t, err, ErrCircuitBreakerOpen)
}
