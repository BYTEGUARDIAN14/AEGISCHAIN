package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExemptionScope defines the target boundaries for a policy exemption.
type ExemptionScope struct {
	Namespace string `json:"namespace,omitempty"`
	Image     string `json:"image,omitempty"`
	Rule      string `json:"rule,omitempty"`
	CVE       string `json:"cve,omitempty"`
}

// Exemption represents an approved, temporary deviation from platform policy.
// Policy exemptions are data, not code: each exemption has an owner, reason,
// scope, and a strict RFC3339 expiry date. Expired exemptions fail CI gates.
type Exemption struct {
	ID        string         `json:"id"`
	Owner     string         `json:"owner"`
	Reason    string         `json:"reason"`
	ExpiresAt string         `json:"expires_at"`
	CVE       string         `json:"cve,omitempty"`
	Scope     ExemptionScope `json:"scope,omitempty"`
}

// ExemptionsContainer models the standard exemptions.json file layout.
type ExemptionsContainer struct {
	Exemptions []Exemption `json:"exemptions"`
}

// ExpiredExemptionError records an exemption that has passed its expiration timestamp.
type ExpiredExemptionError struct {
	ID        string
	Owner     string
	ExpiresAt time.Time
	Reason    string
}

func (e ExpiredExemptionError) Error() string {
	return fmt.Sprintf("exemption %s (owner: %s) expired on %s: %s",
		e.ID, e.Owner, e.ExpiresAt.Format(time.RFC3339), e.Reason)
}

// LoadExemptions reads and parses an exemptions JSON file.
func LoadExemptions(path string) ([]Exemption, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read exemptions file %s: %w", path, err)
	}

	var container ExemptionsContainer
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to parse exemptions JSON from %s: %w", path, err)
	}

	return container.Exemptions, nil
}

// ValidateExemptions checks a slice of exemptions against the evaluation timestamp.
// Returns a slice of ExpiredExemptionError for any expired items.
func ValidateExemptions(exemptions []Exemption, now time.Time) []ExpiredExemptionError {
	var expired []ExpiredExemptionError

	for _, ex := range exemptions {
		if strings.TrimSpace(ex.ExpiresAt) == "" {
			expired = append(expired, ExpiredExemptionError{
				ID:        ex.ID,
				Owner:     ex.Owner,
				ExpiresAt: time.Time{},
				Reason:    "missing or empty expires_at timestamp",
			})
			continue
		}

		t, err := time.Parse(time.RFC3339, ex.ExpiresAt)
		if err != nil {
			expired = append(expired, ExpiredExemptionError{
				ID:        ex.ID,
				Owner:     ex.Owner,
				ExpiresAt: time.Time{},
				Reason:    fmt.Sprintf("invalid RFC3339 expires_at format %q: %v", ex.ExpiresAt, err),
			})
			continue
		}

		if now.After(t) {
			expired = append(expired, ExpiredExemptionError{
				ID:        ex.ID,
				Owner:     ex.Owner,
				ExpiresAt: t,
				Reason:    ex.Reason,
			})
		}
	}

	return expired
}

// VerifyExemptionsDirectory scans a directory (such as policies/data) for any JSON files
// containing exemptions and verifies none have expired.
func VerifyExemptionsDirectory(dir string, now time.Time) ([]Exemption, []ExpiredExemptionError, error) {
	var allExemptions []Exemption
	var allExpired []ExpiredExemptionError

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		var container ExemptionsContainer
		if err := json.Unmarshal(data, &container); err == nil && len(container.Exemptions) > 0 {
			allExemptions = append(allExemptions, container.Exemptions...)
			expired := ValidateExemptions(container.Exemptions, now)
			allExpired = append(allExpired, expired...)
		}
	}

	return allExemptions, allExpired, nil
}
