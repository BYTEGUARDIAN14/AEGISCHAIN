package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

var (
	ErrCompilationFailed = errors.New("rego policy compilation failed")
	ErrEvaluationFailed  = errors.New("rego policy evaluation failed")
	ErrEmptyInput        = errors.New("input for policy evaluation cannot be empty")
)

type RuleEvaluation struct {
	ID          string   `json:"id"`
	Result      string   `json:"result"` // pass | fail
	Reason      string   `json:"reason,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type EvaluationResponse struct {
	Verdict       string           `json:"verdict"` // allow | deny
	Mode          string           `json:"mode"`    // audit | enforce
	PolicyVersion string           `json:"policy_version"`
	TrustScore    int              `json:"trust_score"`
	Rules         []RuleEvaluation `json:"rules"`
}

type Engine struct {
	mu            sync.RWMutex
	policyVersion string
	query         rego.PreparedEvalQuery
}

// NewEngine compiles raw Rego policy string into an in-memory prepared query.
func NewEngine(ctx context.Context, policyVersion, regoModule string) (*Engine, error) {
	e := &Engine{
		policyVersion: policyVersion,
	}
	if err := e.load(ctx, policyVersion, regoModule); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) load(ctx context.Context, policyVersion, regoModule string) error {
	r := rego.New(
		rego.Query("data.aegischain.trust.decision"),
		rego.Module("trust.rego", regoModule),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCompilationFailed, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.policyVersion = policyVersion
	e.query = pq
	return nil
}

// HotReload updates the running policy bundle in memory.
func (e *Engine) HotReload(ctx context.Context, policyVersion, regoModule string) error {
	return e.load(ctx, policyVersion, regoModule)
}

// Evaluate runs the embedded OPA query against arbitrary input payload.
func (e *Engine) Evaluate(ctx context.Context, input any) (*EvaluationResponse, error) {
	if input == nil {
		return nil, ErrEmptyInput
	}

	e.mu.RLock()
	pq := e.query
	policyVer := e.policyVersion
	e.mu.RUnlock()

	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvaluationFailed, err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("%w: empty expression result from rego query", ErrEvaluationFailed)
	}

	rawResult := rs[0].Expressions[0].Value
	bytes, err := json.Marshal(rawResult)
	if err != nil {
		return nil, fmt.Errorf("failed to encode rego output: %w", err)
	}

	var resp EvaluationResponse
	if err := json.Unmarshal(bytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode rego evaluation into response: %w", err)
	}

	resp.PolicyVersion = policyVer
	return &resp, nil
}
