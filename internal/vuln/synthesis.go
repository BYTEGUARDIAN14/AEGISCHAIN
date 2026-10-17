package vuln

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Known CISA KEV sample catalog for fast in-memory lookup.
var cisaKEVCatalog = map[string]struct{}{
	"CVE-2021-44228": {}, // Log4j
	"CVE-2022-22965": {}, // Spring4Shell
	"CVE-2023-38606": {}, // WebKit
	"CVE-2023-4863":  {}, // libwebp
	"CVE-2024-21626": {}, // runc breakout
	"CVE-2024-3094":  {}, // XZ Utils backdoor
	"CVE-2026-3199":  {}, // AegisChain demo KEV fixture
}

// Synthesizer merges and normalizes multi-scanner vulnerability reports with signed OpenVEX statements.
type Synthesizer struct {
	knownKEV       map[string]struct{}
	trustedSigners []string
}

// NewSynthesizer creates an initialized Synthesizer instance.
func NewSynthesizer(trustedSigners []string) *Synthesizer {
	kevMap := make(map[string]struct{}, len(cisaKEVCatalog))
	for k, v := range cisaKEVCatalog {
		kevMap[k] = v
	}
	return &Synthesizer{
		knownKEV:       kevMap,
		trustedSigners: trustedSigners,
	}
}

// RegisterKEV adds a CVE identifier to the active KEV catalog.
func (s *Synthesizer) RegisterKEV(cveID string) {
	s.knownKEV[cveID] = struct{}{}
}

// Synthesize correlates findings across scanners and applies signed OpenVEX waivers.
func (s *Synthesizer) Synthesize(findingsByScanner map[string][]VulnerabilityFinding, vexDocs []OpenVEXDocument) (*VulnSynthesisResult, error) {
	mergedMap := make(map[string]*VulnerabilityFinding)
	var disagreements int

	// 1. Correlate findings across scanners
	for scanner, findings := range findingsByScanner {
		for _, f := range findings {
			key := fmt.Sprintf("%s:%s", f.ID, f.Package)
			if existing, ok := mergedMap[key]; ok {
				// Record scanner participation
				if !containsString(existing.ReportingScanners, scanner) {
					existing.ReportingScanners = append(existing.ReportingScanners, scanner)
				}
				// If severities disagree, elevate to higher severity and count disagreement
				if existing.Severity != f.Severity {
					disagreements++
					if severityWeight(f.Severity) > severityWeight(existing.Severity) {
						existing.Severity = f.Severity
					}
				}
				// Merge fixed version
				if existing.FixedVersion == "" && f.FixedVersion != "" {
					existing.FixedVersion = f.FixedVersion
				}
			} else {
				findingCopy := f
				findingCopy.ReportingScanners = []string{scanner}
				// Check KEV membership
				if _, isKEV := s.knownKEV[f.ID]; isKEV {
					findingCopy.KEV = true
				}
				mergedMap[key] = &findingCopy
			}
		}
	}

	var unifiedFindings []VulnerabilityFinding
	for _, f := range mergedMap {
		unifiedFindings = append(unifiedFindings, *f)
	}

	// 2. Merge OpenVEX statements
	waivedFindings, unsignedWarnings := s.applyOpenVEX(unifiedFindings, vexDocs)

	// Sort findings deterministically (by severity descending, then ID)
	sort.Slice(waivedFindings, func(i, j int) bool {
		if severityWeight(waivedFindings[i].Severity) != severityWeight(waivedFindings[j].Severity) {
			return severityWeight(waivedFindings[i].Severity) > severityWeight(waivedFindings[j].Severity)
		}
		return waivedFindings[i].ID < waivedFindings[j].ID
	})

	// 3. Aggregate counts and formulate admission recommendation
	result := &VulnSynthesisResult{
		Timestamp:            time.Now().UTC(),
		TotalVulnerabilities: len(waivedFindings),
		ScannerDisagreements: disagreements,
		UnsignedVEXWarnings:  unsignedWarnings,
		AllFindings:          waivedFindings,
	}

	for _, f := range waivedFindings {
		if f.Waived {
			result.WaivedCount++
			continue
		}

		switch f.Severity {
		case "CRITICAL":
			result.CriticalCount++
			result.UnwaivedCriticals = append(result.UnwaivedCriticals, f)
		case "HIGH":
			result.HighCount++
		case "MEDIUM":
			result.MediumCount++
		case "LOW":
			result.LowCount++
		}

		if f.KEV {
			result.KEVCount++
			result.UnwaivedKEV = append(result.UnwaivedKEV, f)
		}
	}

	// Workload is admissible if zero unwaived criticals and zero unwaived KEV
	result.Admissible = (result.CriticalCount == 0 && result.KEVCount == 0)

	return result, nil
}

// applyOpenVEX parses OpenVEX documents, enforces signature validity, and waives affected findings.
func (s *Synthesizer) applyOpenVEX(findings []VulnerabilityFinding, vexDocs []OpenVEXDocument) ([]VulnerabilityFinding, []string) {
	var unsignedWarnings []string
	waivers := make(map[string]OpenVEXStatement)

	for _, doc := range vexDocs {
		// Enforce signed requirement
		if !doc.Signed {
			msg := fmt.Sprintf("Unsigned OpenVEX document %s from author %q ignored per security policy", doc.ID, doc.Author)
			unsignedWarnings = append(unsignedWarnings, msg)
			continue
		}

		// Enforce trusted signer identity if configured
		if len(s.trustedSigners) > 0 && doc.SignerIdentity != "" {
			if !s.isTrustedSigner(doc.SignerIdentity) {
				msg := fmt.Sprintf("OpenVEX document %s signed by untrusted identity %q ignored", doc.ID, doc.SignerIdentity)
				unsignedWarnings = append(unsignedWarnings, msg)
				continue
			}
		}

		for _, stmt := range doc.Statements {
			if stmt.Status == "not_affected" || stmt.Status == "fixed" {
				waivers[stmt.Vulnerability] = stmt
			}
		}
	}

	// Apply waivers to matching findings
	res := make([]VulnerabilityFinding, len(findings))
	for i, f := range findings {
		res[i] = f
		if stmt, ok := waivers[f.ID]; ok {
			res[i].Waived = true
			res[i].WaiverReason = stmt.Status
			res[i].WaiverJustification = fmt.Sprintf("Justification: %s. Impact: %s", stmt.Justification, stmt.ImpactStatement)
		}
	}

	return res, unsignedWarnings
}

func (s *Synthesizer) isTrustedSigner(identity string) bool {
	for _, trusted := range s.trustedSigners {
		if strings.HasPrefix(identity, trusted) || identity == trusted {
			return true
		}
	}
	return false
}

// ParseTrivyJSON extracts findings from Trivy vulnerability output.
func ParseTrivyJSON(data []byte) ([]VulnerabilityFinding, error) {
	var report struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				PkgName         string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion    string `json:"FixedVersion"`
				Severity        string `json:"Severity"`
				Title           string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse Trivy JSON: %w", err)
	}

	var findings []VulnerabilityFinding
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			findings = append(findings, VulnerabilityFinding{
				ID:                    v.VulnerabilityID,
				Package:               v.PkgName,
				InstalledVersion:      v.InstalledVersion,
				FixedVersion:          v.FixedVersion,
				Severity:              normalizeSeverity(v.Severity),
				PrimarySource:         "trivy",
				ReachabilityPrecision: PrecisionPackage,
				Reachable:             true,
				Description:           v.Title,
			})
		}
	}

	return findings, nil
}

// ParseGrypeJSON extracts findings from Grype vulnerability output.
func ParseGrypeJSON(data []byte) ([]VulnerabilityFinding, error) {
	var report struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse Grype JSON: %w", err)
	}

	var findings []VulnerabilityFinding
	for _, m := range report.Matches {
		fixed := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixed = m.Vulnerability.Fix.Versions[0]
		}
		findings = append(findings, VulnerabilityFinding{
			ID:                    m.Vulnerability.ID,
			Package:               m.Artifact.Name,
			InstalledVersion:      m.Artifact.Version,
			FixedVersion:          fixed,
			Severity:              normalizeSeverity(m.Vulnerability.Severity),
			PrimarySource:         "grype",
			ReachabilityPrecision: PrecisionPackage,
			Reachable:             true,
			Description:           m.Vulnerability.Description,
		})
	}

	return findings, nil
}

func normalizeSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func severityWeight(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
