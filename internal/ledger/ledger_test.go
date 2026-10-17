package ledger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLedgerAppendAndVerify(t *testing.T) {
	l := NewLedger()

	sub1 := DecisionSubject{
		Image:     "ghcr.io/byteaegis/sample-app:v1.0.0",
		Digest:    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Namespace: "prod",
		Workload:  "sample-deployment",
	}

	rules1 := []RuleResult{
		{ID: "signature_required", Result: "pass", Evidence: []string{"rekor:9981"}},
		{ID: "provenance_required", Result: "pass", Evidence: []string{"slsa:builder-l3"}},
	}

	rec1, err := l.Append("dec-001", "allow", "enforce", "v1.0.0", sub1, rules1, 95)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), rec1.Index)
	assert.Equal(t, GenesisHash, rec1.PrevHash)

	sub2 := DecisionSubject{
		Image:     "ghcr.io/byteaegis/sample-app:v1.0.1",
		Digest:    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Namespace: "prod",
		Workload:  "sample-deployment",
	}

	rules2 := []RuleResult{
		{ID: "signature_required", Result: "fail", Reason: "Unsigned image"},
	}

	rec2, err := l.Append("dec-002", "deny", "enforce", "v1.0.0", sub2, rules2, 10)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), rec2.Index)
	assert.Equal(t, rec1.Hash, rec2.PrevHash)

	// Verify intact ledger
	err = l.Verify()
	assert.NoError(t, err)
	assert.Equal(t, 2, len(l.Entries()))
}

func TestLedgerDetectsTampering(t *testing.T) {
	l := NewLedger()

	for i := 0; i < 5; i++ {
		sub := DecisionSubject{
			Image:     "ghcr.io/byteaegis/sample-app",
			Digest:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			Namespace: "prod",
			Workload:  "worker",
		}
		_, err := l.Append("dec", "allow", "enforce", "v1.0.0", sub, nil, 90)
		require.NoError(t, err)
	}

	// Verify initially clean
	require.NoError(t, l.Verify())

	// Maliciously tamper with entry 2 in storage
	l.TamperForTesting(2, "deny")

	// Ledger verification must detect corruption
	err := l.Verify()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEntryHashInvalid)
	assert.Contains(t, err.Error(), "index 2")
}

func TestLedgerRejectsEmptySubject(t *testing.T) {
	l := NewLedger()
	_, err := l.Append("dec-bad", "allow", "enforce", "v1.0.0", DecisionSubject{}, nil, 100)
	assert.ErrorIs(t, err, ErrEmptySubject)
}
