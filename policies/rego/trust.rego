package aegischain.trust

import rego.v1

# Default decision structure
default decision = {
	"verdict": "deny",
	"mode": "enforce",
	"policy_version": "v1.0.0",
	"trust_score": 0,
	"rules": [
		{
			"id": "policy_evaluation",
			"result": "fail",
			"reason": "Default deny triggered: input failed mandatory policy rules",
			"remediation": "Review rule-by-rule evaluation results"
		}
	]
}

# Decision calculation
decision = {
	"verdict": final_verdict,
	"mode": mode,
	"policy_version": "v1.0.0",
	"trust_score": trust_score,
	"rules": rule_results
} if {
	mode := object.get(input, "mode", "enforce")
	rule_results := [
		rule_signature_required,
		rule_provenance_required,
		rule_sbom_required,
		rule_vulnerability_gate,
		rule_base_image_allowlist,
		rule_dependency_risk_gate,
		rule_freshness,
		rule_privileged_workload_extra_scrutiny
	]
	
	failed_rules := [r | some r in rule_results; r.result == "fail"]
	final_verdict := determine_verdict(failed_rules)
	trust_score := max([0, 100 - (count(failed_rules) * 20)])
}

determine_verdict(failed) := "allow" if {
	count(failed) == 0
} else := "deny"

# Rule 1: signature_required
rule_signature_required = {
	"id": "signature_required",
	"result": "pass",
	"evidence": [sprintf("mode:%s", [object.get(input.signature, "mode", "keyless")])]
} if {
	is_valid_signature
} else = {
	"id": "signature_required",
	"result": "fail",
	"reason": "Valid signature from trusted key or identity not found",
	"remediation": "Sign image using authorized release keys or GitHub Actions OIDC workflow under approved organization"
}

is_valid_signature if {
	input.signature.valid == true
	object.get(input.signature, "mode", "keyless") == "key"
}

is_valid_signature if {
	input.signature.valid == true
	object.get(input.signature, "mode", "keyless") != "key"
	input.signature.issuer == "https://token.actions.githubusercontent.com"
	regex.match("^https://github.com/BYTEGUARDIAN14/.*", input.signature.identity)
}

# Rule 2: provenance_required
rule_provenance_required = {
	"id": "provenance_required",
	"result": "pass",
	"evidence": [input.provenance.builder_id, input.provenance.source_repo]
} if {
	input.provenance.present == true
	input.provenance.builder_id == "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
	input.provenance.source_repo == "https://github.com/BYTEGUARDIAN14/aegischain"
	input.provenance.subject_digest == input.subject.digest
} else = {
	"id": "provenance_required",
	"result": "fail",
	"reason": "SLSA Build L3 provenance missing or builder/source mismatch",
	"remediation": "Generate SLSA Build L3 provenance using slsa-github-generator from main branch"
}

# Rule 3: sbom_required
rule_sbom_required = {
	"id": "sbom_required",
	"result": "pass",
	"evidence": [sprintf("components:%d", [input.sbom.component_count])]
} if {
	input.sbom.present == true
	input.sbom.component_count >= 1
} else = {
	"id": "sbom_required",
	"result": "fail",
	"reason": "CycloneDX or SPDX SBOM attestation missing or empty",
	"remediation": "Generate and attest CycloneDX JSON SBOM via Syft"
}

# Rule 4: vulnerability_gate
rule_vulnerability_gate = {
	"id": "vulnerability_gate",
	"result": "pass",
	"evidence": [sprintf("unwaived_critical:%d", [count(unwaived_criticals)])]
} if {
	count(unwaived_criticals) == 0
	count(kev_vulnerabilities) == 0
} else = {
	"id": "vulnerability_gate",
	"result": "fail",
	"reason": sprintf("Unwaived critical vulnerabilities (%d) or active KEV listed (%d)", [count(unwaived_criticals), count(kev_vulnerabilities)]),
	"remediation": "Upgrade vulnerable components or publish a cryptographically signed OpenVEX not_affected waiver"
}

unwaived_criticals := [v |
	some v in object.get(input, "vulnerabilities", [])
	v.severity == "CRITICAL"
	not has_valid_vex(v.id)
	not is_exempt(v.id)
]

kev_vulnerabilities := [v |
	some v in object.get(input, "vulnerabilities", [])
	v.kev == true
	not has_valid_vex(v.id)
	not is_exempt(v.id)
]

has_valid_vex(cve) if {
	some vex in object.get(input, "vex_statements", [])
	vex.cve == cve
	vex.status in ["not_affected", "fixed"]
	vex.signed == true
}

is_exempt(cve) if {
	some ex in data.exemptions
	ex.cve == cve
	time.now_ns() < time.parse_rfc3339_ns(ex.expires_at)
}

# Rule 5: base_image_allowlist
rule_base_image_allowlist = {
	"id": "base_image_allowlist",
	"result": "pass",
	"evidence": [input.base_image.digest]
} if {
	is_approved_base_image(input.base_image.digest)
} else = {
	"id": "base_image_allowlist",
	"result": "fail",
	"reason": sprintf("Base image digest %s is not on the platform allowlist", [object.get(input.base_image, "digest", "unknown")]),
	"remediation": "Rebase workload onto approved Google Distroless or Chainguard base image"
}

is_approved_base_image(d) if {
	d in [
		"sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3",
		"sha256:6ec5aa99dc33c56d5b79dc1a68b6a14704a4fa8b9152b84d08891ad85ec2d1da",
		"sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679"
	]
}

is_approved_base_image(d) if {
	d in data.allowed_digests
}

# Rule 6: dependency_risk_gate
rule_dependency_risk_gate = {
	"id": "dependency_risk_gate",
	"result": "pass",
	"evidence": [sprintf("risk_score:%d", [input.risk.score])]
} if {
	input.risk.score <= object.get(input.risk, "threshold", 65)
	input.risk.has_malicious_packages == false
} else = {
	"id": "dependency_risk_gate",
	"result": "fail",
	"reason": sprintf("Dependency risk score (%d) exceeds threshold (65) or contains malicious packages", [input.risk.score]),
	"remediation": "Audit flagged dependencies for typosquatting, obfuscation, or suspicious postinstall scripts"
}

# Rule 7: freshness
rule_freshness = {
	"id": "freshness",
	"result": "pass",
	"evidence": [sprintf("build_age_hours:%.1f", [build_age_hours])]
} if {
	build_age_hours <= 720 # 30 days max
	input.freshness.rollback == false
} else = {
	"id": "freshness",
	"result": "fail",
	"reason": "Image exceeds 30-day build age limit or violates anti-rollback constraint",
	"remediation": "Rebuild container image from latest source to refresh pipeline freshness"
}

build_age_hours := (time.now_ns() - time.parse_rfc3339_ns(object.get(input.freshness, "built_at", "2020-01-01T00:00:00Z"))) / 3600000000000

# Rule 8: privileged_workload_extra_scrutiny
rule_privileged_workload_extra_scrutiny = {
	"id": "privileged_workload_extra_scrutiny",
	"result": "pass",
	"evidence": ["non-privileged"]
} if {
	input.workload.privileged == false
	input.workload.host_network == false
	input.workload.host_path == false
} else = {
	"id": "privileged_workload_extra_scrutiny",
	"result": "pass",
	"evidence": ["approved_privileged_exception"]
} if {
	input.workload.security_exception_attestation == true
	input.risk.score <= 20
} else = {
	"id": "privileged_workload_extra_scrutiny",
	"result": "fail",
	"reason": "Privileged container, hostNetwork, or hostPath requested without security committee approval",
	"remediation": "Remove privileged flags or obtain signed security exception attestation"
}
