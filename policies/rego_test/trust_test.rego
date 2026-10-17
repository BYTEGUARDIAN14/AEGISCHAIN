package aegischain.trust_test

import rego.v1
import data.aegischain.trust

test_decision_allow_valid_signature if {
	inp := {
		"mode": "enforce",
		"signature": {
			"valid": true,
			"issuer": "https://token.actions.githubusercontent.com",
			"identity": "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0"
		}
	}
	res := trust.decision with input as inp
	res.verdict == "allow"
	res.trust_score == 100
}

test_decision_deny_invalid_signature if {
	inp := {
		"mode": "enforce",
		"signature": {
			"valid": false,
			"issuer": "https://token.actions.githubusercontent.com",
			"identity": "https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0"
		}
	}
	res := trust.decision with input as inp
	res.verdict == "deny"
	res.trust_score == 0
}

test_decision_deny_untrusted_identity if {
	inp := {
		"mode": "enforce",
		"signature": {
			"valid": true,
			"issuer": "https://token.actions.githubusercontent.com",
			"identity": "https://github.com/attacker-org/malicious-repo/.github/workflows/attack.yml@refs/heads/main"
		}
	}
	res := trust.decision with input as inp
	res.verdict == "deny"
}
