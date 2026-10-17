package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	ErrEmptySubject     = errors.New("subject cannot be empty")
	ErrTamperDetected   = errors.New("cryptographic ledger tampering detected")
	ErrBrokenSequence   = errors.New("broken index sequence in ledger")
	ErrInvalidPrevHash  = errors.New("previous hash mismatch")
	ErrEntryHashInvalid = errors.New("entry hash does not match computed content digest")
)

type DecisionSubject struct {
	Image     string `json:"image"`
	Digest    string `json:"digest"`
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
}

type RuleResult struct {
	ID          string   `json:"id"`
	Result      string   `json:"result"` // pass | fail
	Reason      string   `json:"reason,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type DecisionRecord struct {
	Index         uint64          `json:"index"`
	DecisionID    string          `json:"decision_id"`
	Verdict       string          `json:"verdict"` // allow | deny
	Mode          string          `json:"mode"`    // audit | enforce
	PolicyVersion string          `json:"policy_version"`
	Subject       DecisionSubject `json:"subject"`
	Rules         []RuleResult    `json:"rules"`
	TrustScore    int             `json:"trust_score"`
	Timestamp     string          `json:"timestamp"`
	PrevHash      string          `json:"prev_hash"`
	Hash          string          `json:"hash"`
}

type Ledger struct {
	mu      sync.RWMutex
	entries []DecisionRecord
}

func NewLedger() *Ledger {
	return &Ledger{
		entries: make([]DecisionRecord, 0),
	}
}

// ComputeEntryHash calculates SHA256(prev_hash || CanonicalJSON(entry_without_hash)).
func ComputeEntryHash(rec DecisionRecord) (string, error) {
	// Create canonical payload copy with blank hash
	payloadCopy := rec
	payloadCopy.Hash = ""

	data, err := json.Marshal(payloadCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal decision for hashing: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(rec.PrevHash))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Append adds a decision record to the hash-chained ledger.
func (l *Ledger) Append(decisionID, verdict, mode, policyVersion string, subject DecisionSubject, rules []RuleResult, trustScore int) (*DecisionRecord, error) {
	if subject.Image == "" || subject.Digest == "" {
		return nil, ErrEmptySubject
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var prevHash string
	var nextIndex uint64

	if len(l.entries) == 0 {
		prevHash = GenesisHash
		nextIndex = 0
	} else {
		lastEntry := l.entries[len(l.entries)-1]
		prevHash = lastEntry.Hash
		nextIndex = lastEntry.Index + 1
	}

	rec := DecisionRecord{
		Index:         nextIndex,
		DecisionID:    decisionID,
		Verdict:       verdict,
		Mode:          mode,
		PolicyVersion: policyVersion,
		Subject:       subject,
		Rules:         rules,
		TrustScore:    trustScore,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		PrevHash:      prevHash,
	}

	hash, err := ComputeEntryHash(rec)
	if err != nil {
		return nil, err
	}
	rec.Hash = hash

	l.entries = append(l.entries, rec)
	return &rec, nil
}

// Verify iterates through the full ledger verifying hash-chain continuity and authenticity.
func (l *Ledger) Verify() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	expectedPrev := GenesisHash
	for i := uint64(0); i < uint64(len(l.entries)); i++ {
		entry := l.entries[i]
		if entry.Index != i {
			return fmt.Errorf("%w at index %d (expected %d, got %d)", ErrBrokenSequence, i, i, entry.Index)
		}

		if entry.PrevHash != expectedPrev {
			return fmt.Errorf("%w at index %d (expected prev %s, got %s)", ErrInvalidPrevHash, i, expectedPrev, entry.PrevHash)
		}

		computedHash, err := ComputeEntryHash(entry)
		if err != nil {
			return fmt.Errorf("error computing hash at index %d: %w", i, err)
		}

		if entry.Hash != computedHash {
			return fmt.Errorf("%w at index %d (content modified, expected hash %s, got %s)", ErrEntryHashInvalid, i, computedHash, entry.Hash)
		}

		expectedPrev = entry.Hash
	}

	return nil
}

// Entries returns a copy of all records.
func (l *Ledger) Entries() []DecisionRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	res := make([]DecisionRecord, len(l.entries))
	copy(res, l.entries)
	return res
}

// TamperForTesting allows unit tests to deliberately tamper with a record.
func (l *Ledger) TamperForTesting(index int, newVerdict string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < len(l.entries) {
		l.entries[index].Verdict = newVerdict
	}
}
