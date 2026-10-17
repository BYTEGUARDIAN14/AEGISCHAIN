package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	ErrServiceUnavailable = errors.New("risk scorer service is unavailable")
	ErrCircuitBreakerOpen = errors.New("risk scorer circuit breaker is open")
)

type Component struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Version   string `json:"version,omitempty"`
}

type RiskFactor struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	ScoreDelta  int    `json:"score_delta"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation,omitempty"`
}

type PackageScore struct {
	Name              string       `json:"name"`
	Ecosystem         string       `json:"ecosystem"`
	Version           string       `json:"version"`
	Score             int          `json:"score"`
	RiskLevel         string       `json:"risk_level"`
	IsMalicious       bool         `json:"is_malicious"`
	HardGateTriggered bool         `json:"hard_gate_triggered"`
	Factors           []RiskFactor `json:"factors"`
}

type SBOMResult struct {
	OverallRiskScore     int            `json:"overall_risk_score"`
	RiskThreshold        int            `json:"risk_threshold"`
	HasMaliciousPackages bool           `json:"has_malicious_packages"`
	Verdict              string         `json:"verdict"` // allow | deny
	ComponentCount       int            `json:"component_count"`
	FlaggedPackagesCount int            `json:"flagged_packages_count"`
	FlaggedPackages      []PackageScore `json:"flagged_packages"`
	EvaluatedPackages    []PackageScore `json:"evaluated_packages"`
}

type Client struct {
	baseURL            string
	httpClient         *http.Client
	mu                 sync.RWMutex
	circuitOpen        bool
	lastFailure        time.Time
	failureCount       int
	failureThreshold   int
	cooldownDuration   time.Duration
	cache              map[string]PackageScore
	cacheTTL           time.Duration
}

func NewClient(baseURL string, timeout time.Duration) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:8088"
	}
	return &Client{
		baseURL:          baseURL,
		httpClient:       &http.Client{Timeout: timeout},
		failureThreshold: 3,
		cooldownDuration: 30 * time.Second,
		cache:            make(map[string]PackageScore),
		cacheTTL:         10 * time.Minute,
	}
}

// ScorePackage queries the risk scorer service for a single package.
func (c *Client) ScorePackage(ctx context.Context, name, ecosystem, version string) (*PackageScore, error) {
	c.mu.RLock()
	if c.circuitOpen {
		if time.Since(c.lastFailure) < c.cooldownDuration {
			c.mu.RUnlock()
			return nil, ErrCircuitBreakerOpen
		}
		// Try half-open probe
	}
	cacheKey := fmt.Sprintf("%s:%s", ecosystem, name)
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.RUnlock()
		return &cached, nil
	}
	c.mu.RUnlock()

	reqBody, _ := json.Marshal(map[string]string{
		"name":      name,
		"ecosystem": ecosystem,
		"version":   version,
	})

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/score/package", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("%w: %v", ErrServiceUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		return nil, fmt.Errorf("%w: HTTP status %d", ErrServiceUnavailable, resp.StatusCode)
	}

	var score PackageScore
	if err := json.NewDecoder(resp.Body).Decode(&score); err != nil {
		return nil, fmt.Errorf("failed to decode risk score response: %w", err)
	}

	c.recordSuccess(cacheKey, score)
	return &score, nil
}

// ScoreSBOM evaluates a set of dependencies from an SBOM against platform risk thresholds.
func (c *Client) ScoreSBOM(ctx context.Context, components []Component, namespace string, threshold int) (*SBOMResult, error) {
	c.mu.RLock()
	if c.circuitOpen && time.Since(c.lastFailure) < c.cooldownDuration {
		c.mu.RUnlock()
		return nil, ErrCircuitBreakerOpen
	}
	c.mu.RUnlock()

	payload := map[string]any{
		"components":     components,
		"namespace":      namespace,
		"risk_threshold": threshold,
	}
	body, _ := json.Marshal(payload)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/score/sbom", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("%w: %v", ErrServiceUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		return nil, fmt.Errorf("%w: HTTP status %d", ErrServiceUnavailable, resp.StatusCode)
	}

	var result SBOMResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode SBOM risk result: %w", err)
	}

	c.mu.Lock()
	c.circuitOpen = false
	c.failureCount = 0
	c.mu.Unlock()

	return &result, nil
}

func (c *Client) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastFailure = time.Now()
	c.failureCount++
	if c.failureCount >= c.failureThreshold {
		c.circuitOpen = true
	}
}

func (c *Client) recordSuccess(cacheKey string, score PackageScore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.circuitOpen = false
	c.failureCount = 0
	c.cache[cacheKey] = score
}
