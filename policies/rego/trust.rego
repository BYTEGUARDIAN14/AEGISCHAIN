package aegischain.trust

import rego.v1

# Default decision when inputs fail validation
default decision = {
	"verdict": "deny",
	"mode": "enforce",
	"trust_score": 0,
	"rules": [
		{
			"id": "signature_required",
			"result": "fail",
			"reason": "Image lacks verifiable cryptographic signature or trust identity",
			"remediation": "Sign image using trusted GitHub Actions keyless workflow with Fulcio"
		}
	]
}

# Allow when image signature is valid and issued by trusted authority
decision = {
	"verdict": "allow",
	"mode": object.get(input, "mode", "enforce"),
	"trust_score": 100,
	"rules": [
		{
			"id": "signature_required",
			"result": "pass",
			"evidence": [sprintf("identity:%s", [input.signature.identity])]
		}
	]
} if {
	input.signature.valid == true
	input.signature.issuer == "https://token.actions.githubusercontent.com"
	startswith(input.signature.identity, "https://github.com/BYTEGUARDIAN14/")
}
