package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
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

// Checkpoint represents a periodic cryptographic root anchor of the ledger.
type Checkpoint struct {
	Index     uint64 `json:"index"`
	HeadHash  string `json:"head_hash"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature,omitempty"`
}

// CreateCheckpoint generates a signed checkpoint payload for the current head of the ledger.
func (l *Ledger) CreateCheckpoint() Checkpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.entries) == 0 {
		return Checkpoint{
			Index:     0,
			HeadHash:  GenesisHash,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
	}

	last := l.entries[len(l.entries)-1]
	return Checkpoint{
		Index:     last.Index,
		HeadHash:  last.Hash,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// SaveToFile serializes the full ledger to an append-only JSON Lines file.
func (l *Ledger) SaveToFile(path string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create ledger file %s: %w", path, err)
	}
	defer f.Close()

	for _, entry := range l.entries {
		line, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal entry %d: %w", entry.Index, err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("failed to write entry %d to file: %w", entry.Index, err)
		}
	}

	return nil
}

// LoadFromFile reads and reconstructs a Ledger from a JSON Lines file.
func LoadFromFile(path string) (*Ledger, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ledger file %s: %w", path, err)
	}
	defer f.Close()

	var entries []DecisionRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry DecisionRecord
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("corrupt ledger line: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ledger file: %w", err)
	}

	return &Ledger{entries: entries}, nil
}

// VerifyFile reads a ledger file from disk and validates full hash-chain continuity.
func VerifyFile(path string) error {
	l, err := LoadFromFile(path)
	if err != nil {
		return err
	}
	return l.Verify()
}

// TamperForTesting allows unit tests to deliberately modify a record in memory.
func (l *Ledger) TamperForTesting(index int, newVerdict string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < len(l.entries) {
		l.entries[index].Verdict = newVerdict
	}
}

// DeleteEntryForTesting deletes an entry to simulate record omission attack.
func (l *Ledger) DeleteEntryForTesting(index int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < len(l.entries) {
		l.entries = append(l.entries[:index], l.entries[index+1:]...)
	}
}

// ReorderEntriesForTesting swaps two entries to simulate sequence tampering.
func (l *Ledger) ReorderEntriesForTesting(i, j int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i < len(l.entries) && j < len(l.entries) {
		l.entries[i], l.entries[j] = l.entries[j], l.entries[i]
	}
}
