package vuln

import (
	"encoding/json"
	"time"
)

// ReachabilityPrecision specifies the certainty of vulnerability reachability.
type ReachabilityPrecision string

const (
	PrecisionSymbol  ReachabilityPrecision = "symbol"
	PrecisionPackage ReachabilityPrecision = "package"
	PrecisionUnknown ReachabilityPrecision = "unknown"
)

// VulnerabilityFinding represents a unified security advisory from Trivy, Grype, or OSV.
type VulnerabilityFinding struct {
	ID                    string                `json:"id"`
	Package               string                `json:"package"`
	InstalledVersion      string                `json:"installed_version"`
	FixedVersion          string                `json:"fixed_version,omitempty"`
	Severity              string                `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	PrimarySource         string                `json:"primary_source"` // trivy, grype, osv
	ReportingScanners     []string              `json:"reporting_scanners"`
	KEV                   bool                  `json:"kev"`
	EPSSScore             float64               `json:"epss_score,omitempty"`
	ReachabilityPrecision ReachabilityPrecision `json:"reachability_precision"`
	Reachable             bool                  `json:"reachable"`
	Description           string                `json:"description,omitempty"`
	Waived                bool                  `json:"waived"`
	WaiverReason          string                `json:"waiver_reason,omitempty"`
	WaiverJustification   string                `json:"waiver_justification,omitempty"`
}

// OpenVEXStatement models an individual statement in an OpenVEX document.
type OpenVEXStatement struct {
	Vulnerability   string   `json:"vulnerability"`
	Status          string   `json:"status"` // not_affected, fixed, under_investigation, affected
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impact_statement,omitempty"`
	ActionStatement string   `json:"action_statement,omitempty"`
	Products        []string `json:"products,omitempty"`
	Timestamp       string   `json:"timestamp,omitempty"`
}

// OpenVEXDocument models a standard OpenVEX v0.2.0 document.
type OpenVEXDocument struct {
	Context     string             `json:"@context"`
	ID          string             `json:"@id"`
	Author      string             `json:"author"`
	Role        string             `json:"role"`
	Timestamp   string             `json:"timestamp"`
	Version     int                `json:"version"`
	Tooling     string             `json:"tooling,omitempty"`
	Statements  []OpenVEXStatement `json:"statements"`
	Signed      bool               `json:"signed"`
	SignerIdentity string          `json:"signer_identity,omitempty"`
}

// ScannerReport models raw output ingested from container security scanners.
type ScannerReport struct {
	Scanner string
	Data    json.RawMessage
}

// VulnSynthesisResult provides policy-facing summarized vulnerability metrics.
type VulnSynthesisResult struct {
	Timestamp            time.Time              `json:"timestamp"`
	TotalVulnerabilities int                    `json:"total_vulnerabilities"`
	CriticalCount        int                    `json:"critical_count"`
	HighCount            int                    `json:"high_count"`
	MediumCount          int                    `json:"medium_count"`
	LowCount             int                    `json:"low_count"`
	KEVCount             int                    `json:"kev_count"`
	WaivedCount          int                    `json:"waived_count"`
	ScannerDisagreements int                    `json:"scanner_disagreements"`
	Admissible           bool                   `json:"admissible"`
	UnwaivedCriticals    []VulnerabilityFinding `json:"unwaived_criticals"`
	UnwaivedKEV          []VulnerabilityFinding `json:"unwaived_kev"`
	AllFindings          []VulnerabilityFinding `json:"all_findings"`
	UnsignedVEXWarnings  []string               `json:"unsigned_vex_warnings,omitempty"`
}
