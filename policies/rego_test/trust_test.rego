package aegischain.trust_test

import rego.v1
import data.aegischain.trust

base_input := {
	"mode": "enforce",
	"subject": {
		"image": "localhost:5001/sample-app:v1.0.0",
		"digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	},
	"signature": {
		"valid": true,
		"issuer": "https://token.actions.githubusercontent.com",
		"identity": "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0"
	},
	"provenance": {
		"present": true,
		"builder_id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0",
		"source_repo": "https://github.com/BYTEGUARDIAN14/aegischain",
		"subject_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	},
	"sbom": {
		"present": true,
		"component_count": 42
	},
	"vulnerabilities": [],
	"base_image": {
		"digest": "sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3"
	},
	"risk": {
		"score": 15,
		"threshold": 65,
		"has_malicious_packages": false
	},
	"freshness": {
		"built_at": "2026-10-17T12:00:00Z",
		"rollback": false
	},
	"workload": {
		"privileged": false,
		"host_network": false,
		"host_path": false
	}
}

test_all_rules_pass_on_clean_input if {
	res := trust.decision with input as base_input
	res.verdict == "allow"
	res.trust_score == 100
}

test_rule_1_signature_missing if {
	inp := object.union(base_input, {
		"signature": {
			"valid": false,
			"issuer": "https://token.actions.githubusercontent.com",
			"identity": "none"
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_1_wrong_identity if {
	inp := object.union(base_input, {
		"signature": {
			"valid": true,
			"issuer": "https://token.actions.githubusercontent.com",
			"identity": "https://github.com/attacker-org/malicious"
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_2_provenance_builder_mismatch if {
	inp := object.union(base_input, {
		"provenance": {
			"present": true,
			"builder_id": "https://github.com/untrusted/builder",
			"source_repo": "https://github.com/BYTEGUARDIAN14/aegischain",
			"subject_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_2_provenance_digest_mismatch if {
	inp := object.union(base_input, {
		"provenance": {
			"present": true,
			"builder_id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0",
			"source_repo": "https://github.com/BYTEGUARDIAN14/aegischain",
			"subject_digest": "sha256:different"
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_3_sbom_missing if {
	inp := object.union(base_input, {
		"sbom": {
			"present": false,
			"component_count": 0
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_4_vulnerability_critical_blocks if {
	inp := object.union(base_input, {
		"vulnerabilities": [{"id": "CVE-2026-1234", "severity": "CRITICAL", "kev": false}]
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_4_critical_admitted_with_valid_vex if {
	inp := object.union(base_input, {
		"vulnerabilities": [{"id": "CVE-2026-1234", "severity": "CRITICAL", "kev": false}],
		"vex_statements": [{"cve": "CVE-2026-1234", "status": "not_affected", "signed": true}]
	})
	res := trust.decision with input as inp
	res.verdict == "allow"
}

test_rule_4_kev_blocks_without_vex if {
	inp := object.union(base_input, {
		"vulnerabilities": [{"id": "CVE-2026-5555", "severity": "HIGH", "kev": true}]
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_5_base_image_swap_denied if {
	inp := object.union(base_input, {
		"base_image": {"digest": "sha256:unapproved_base_image_digest"}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_6_dependency_risk_score_exceeded if {
	inp := object.union(base_input, {
		"risk": {
			"score": 85,
			"threshold": 65,
			"has_malicious_packages": false
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_6_malicious_dependency_hard_gate if {
	inp := object.union(base_input, {
		"risk": {
			"score": 20,
			"threshold": 65,
			"has_malicious_packages": true
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_7_rollback_attack_denied if {
	inp := object.union(base_input, {
		"freshness": {
			"built_at": "2026-10-17T12:00:00Z",
			"rollback": true
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_8_privileged_workload_without_approval_denied if {
	inp := object.union(base_input, {
		"workload": {
			"privileged": true,
			"host_network": false,
			"host_path": false
		}
	})
	res := trust.decision with input as inp
	res.verdict == "deny"
}

test_rule_8_privileged_workload_with_approval_allowed if {
	inp := object.union(base_input, {
		"workload": {
			"privileged": true,
			"host_network": false,
			"host_path": false,
			"security_exception_attestation": true
		},
		"risk": {
			"score": 10,
			"threshold": 65,
			"has_malicious_packages": false
		}
	})
	res := trust.decision with input as inp
	res.verdict == "allow"
}
