package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/byteaegis/aegischain/internal/ledger"
)

func main() {
	outDir := filepath.Join("bench", "results")
	_ = os.MkdirAll(outDir, 0755)

	cleanPath := filepath.Join(outDir, "ledger.jsonl")
	tamperedPath := filepath.Join(outDir, "ledger-tampered.jsonl")

	l := ledger.NewLedger()
	subjects := []string{
		"localhost:5001/sample-app:v1.0.0",
		"localhost:5001/sample-app:v1.0.1",
		"localhost:5001/sample-app:v1.0.2",
	}

	for i, s := range subjects {
		sub := ledger.DecisionSubject{
			Image:     s,
			Digest:    fmt.Sprintf("sha256:%064d", i+1),
			Namespace: "prod",
			Workload:  "sample-deployment",
		}
		rules := []ledger.RuleResult{
			{ID: "signature_required", Result: "pass", Evidence: []string{"rekor:entry"}},
		}
		_, err := l.Append(fmt.Sprintf("dec-%d", i), "allow", "enforce", "v1.0.0", sub, rules, 100)
		if err != nil {
			panic(err)
		}
	}

	// 1. Save clean ledger
	if err := l.SaveToFile(cleanPath); err != nil {
		panic(err)
	}
	fmt.Printf("Created clean ledger with %d entries at %s\n", len(l.Entries()), cleanPath)

	// 2. Tamper with record 1 and save tampered ledger
	l.TamperForTesting(1, "deny") // Modify verdict without recomputing hash chain
	if err := l.SaveToFile(tamperedPath); err != nil {
		panic(err)
	}
	fmt.Printf("Created tampered ledger at %s\n", tamperedPath)
}
