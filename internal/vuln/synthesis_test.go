package vuln

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleTrivyJSON = `{
  "Results": [
    {
      "Target": "sample-app:v1.0.0",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-3199",
          "PkgName": "golang.org/x/crypto",
          "InstalledVersion": "v0.1.0",
          "FixedVersion": "v0.2.0",
          "Severity": "CRITICAL",
          "Title": "Cryptographic signature bypass vulnerability"
        },
        {
          "VulnerabilityID": "CVE-2026-1001",
          "PkgName": "libssl",
          "InstalledVersion": "1.1.1",
          "FixedVersion": "1.1.2",
          "Severity": "HIGH",
          "Title": "Buffer overflow in SSL handshake"
        }
      ]
    }
  ]
}`

const sampleGrypeJSON = `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2026-3199",
        "severity": "CRITICAL",
        "description": "Cryptographic signature bypass vulnerability",
        "fix": {
          "versions": ["v0.2.0"]
        }
      },
      "artifact": {
        "name": "golang.org/x/crypto",
        "version": "v0.1.0"
      }
    },
    {
      "vulnerability": {
        "id": "CVE-2026-1001",
        "severity": "MEDIUM",
        "description": "Buffer overflow in SSL handshake",
        "fix": {
          "versions": ["1.1.2"]
        }
      },
      "artifact": {
        "name": "libssl",
        "version": "1.1.1"
      }
    }
  ]
}`

func TestParseTrivyAndGrype(t *testing.T) {
	trivyFindings, err := ParseTrivyJSON([]byte(sampleTrivyJSON))
	require.NoError(t, err)
	assert.Len(t, trivyFindings, 2)
	assert.Equal(t, "CVE-2026-3199", trivyFindings[0].ID)
	assert.Equal(t, "CRITICAL", trivyFindings[0].Severity)

	grypeFindings, err := ParseGrypeJSON([]byte(sampleGrypeJSON))
	require.NoError(t, err)
	assert.Len(t, grypeFindings, 2)
	assert.Equal(t, "CVE-2026-3199", grypeFindings[0].ID)
	assert.Equal(t, "CRITICAL", grypeFindings[0].Severity)
}

func TestMultiScannerSynthesisAndDisagreement(t *testing.T) {
	trivyFindings, _ := ParseTrivyJSON([]byte(sampleTrivyJSON))
	grypeFindings, _ := ParseGrypeJSON([]byte(sampleGrypeJSON))

	synth := NewSynthesizer([]string{"https://github.com/BYTEGUARDIAN14/"})

	findingsMap := map[string][]VulnerabilityFinding{
		"trivy": trivyFindings,
		"grype": grypeFindings,
	}

	res, err := synth.Synthesize(findingsMap, nil)
	require.NoError(t, err)

	assert.Equal(t, 2, res.TotalVulnerabilities)
	// Trivy rated CVE-2026-1001 as HIGH, Grype rated it MEDIUM -> disagreement detected
	assert.Equal(t, 1, res.ScannerDisagreements)
	assert.Equal(t, 1, res.CriticalCount)
	assert.Equal(t, 1, res.KEVCount)
	assert.False(t, res.Admissible, "KEV critical vulnerability must block workload admission")
}

func TestSignedOpenVEXWaiver(t *testing.T) {
	trivyFindings, _ := ParseTrivyJSON([]byte(sampleTrivyJSON))

	synth := NewSynthesizer([]string{"https://github.com/BYTEGUARDIAN14/"})
	findingsMap := map[string][]VulnerabilityFinding{
		"trivy": trivyFindings,
	}

	t.Run("Signed VEX waives KEV critical and admits workload", func(t *testing.T) {
		signedVEX := []OpenVEXDocument{
			{
				Context:        "https://openvex.dev/ns/v0.2.0",
				ID:             "https://byteaegis.in/vex/2026-001",
				Author:         "sec-team@byteaegis.in",
				Role:           "Security Operations",
				Signed:         true,
				SignerIdentity: "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml",
				Statements: []OpenVEXStatement{
					{
						Vulnerability:   "CVE-2026-3199",
						Status:          "not_affected",
						Justification:   "vulnerable_code_not_in_execute_path",
						ImpactStatement: "Cryptographic algorithm is disabled via build tags and uncallable.",
					},
					{
						Vulnerability:   "CVE-2026-1001",
						Status:          "not_affected",
						Justification:   "inline_mitigations_already_exist",
						ImpactStatement: "Container runs with dropped network privileges.",
					},
				},
			},
		}

		res, err := synth.Synthesize(findingsMap, signedVEX)
		require.NoError(t, err)

		assert.Equal(t, 2, res.TotalVulnerabilities)
		assert.Equal(t, 2, res.WaivedCount)
		assert.Equal(t, 0, res.CriticalCount, "Waived critical should not count towards block threshold")
		assert.Equal(t, 0, res.KEVCount, "Waived KEV should not count towards block threshold")
		assert.True(t, res.Admissible, "Workload must be admitted when all criticals are waived via signed VEX")
		assert.Empty(t, res.UnsignedVEXWarnings)
	})

	t.Run("Unsigned VEX statement is ignored and fails policy", func(t *testing.T) {
		unsignedVEX := []OpenVEXDocument{
			{
				Context: "https://openvex.dev/ns/v0.2.0",
				ID:      "https://attacker.com/vex/fake",
				Author:  "attacker@malicious.com",
				Signed:  false, // UNSIGNED
				Statements: []OpenVEXStatement{
					{
						Vulnerability: "CVE-2026-3199",
						Status:        "not_affected",
					},
				},
			},
		}

		res, err := synth.Synthesize(findingsMap, unsignedVEX)
		require.NoError(t, err)

		assert.Equal(t, 0, res.WaivedCount)
		assert.Equal(t, 1, res.CriticalCount)
		assert.False(t, res.Admissible, "Unsigned VEX must not waive vulnerabilities")
		require.NotEmpty(t, res.UnsignedVEXWarnings)
		assert.Contains(t, res.UnsignedVEXWarnings[0], "Unsigned OpenVEX document")
	})

	t.Run("Untrusted signer identity is ignored and fails policy", func(t *testing.T) {
		untrustedSignerVEX := []OpenVEXDocument{
			{
				Context:        "https://openvex.dev/ns/v0.2.0",
				ID:             "https://untrusted.com/vex",
				Author:         "external@vendor.com",
				Signed:         true,
				SignerIdentity: "https://github.com/untrusted-org/workflow",
				Statements: []OpenVEXStatement{
					{
						Vulnerability: "CVE-2026-3199",
						Status:        "not_affected",
					},
				},
			},
		}

		res, err := synth.Synthesize(findingsMap, untrustedSignerVEX)
		require.NoError(t, err)

		assert.Equal(t, 0, res.WaivedCount)
		assert.Equal(t, 1, res.CriticalCount)
		assert.False(t, res.Admissible)
		require.NotEmpty(t, res.UnsignedVEXWarnings)
		assert.Contains(t, res.UnsignedVEXWarnings[0], "untrusted identity")
	})
}
