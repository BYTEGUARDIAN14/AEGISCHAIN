import urllib.request
import json
import sys

ACTIONS = [
    ("actions/checkout", "actions/checkout", "11bd71901bbe5b1630ceea73d27597364c9af683"),
    ("actions/setup-go", "actions/setup-go", "41dfa10bad2bb2ae585af6ee5bb4d7d973ad74ed"),
    ("actions/upload-artifact", "actions/upload-artifact", "b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882"),
    ("ossf/scorecard-action", "ossf/scorecard-action", "fa7117db83c52d787ae5a89f350999701505d78e"),
    ("github/codeql-action", "github/codeql-action", "df409f7d9260372bd5f19e5b04e83cb3c43714ae"),
    ("step-security/harden-runner", "step-security/harden-runner", "4d991eb9b905ef189e4c376166672c3f2f230481"),
    ("docker/setup-buildx-action", "docker/setup-buildx-action", "c47758b77c9736f4b2ef4073d4d51994fabfe349"),
    ("docker/login-action", "docker/login-action", "9780b0c442fbb1117ed29e0efdff1e18412f7567"),
    ("docker/build-push-action", "docker/build-push-action", "4f58ea79222b3b9dc2c8bbdd6debcef730109a75"),
    ("sigstore/cosign-installer", "sigstore/cosign-installer", "dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da"),
    ("anchore/sbom-action", "anchore/sbom-action", "f325610c9f50a54015d37c8d16cb3b0e2c8f4de0"),
    ("aquasecurity/trivy-action", "aquasecurity/trivy-action", "6e7b7d1fd3e4fef0c5fa8cce1229c54b2c9bd0d8"),
    ("golangci/golangci-lint-action", "golangci/golangci-lint-action", "971e284b6050e8a5849b72094c50ab08da042db8"),
    ("open-policy-agent/setup-opa", "open-policy-agent/setup-opa", "34a30e8a924d1b03ce2cf7abe97250bbb1f332b5"),
]

def main():
    print(f"VERIFYING {len(ACTIONS)} GITHUB ACTION COMMIT SHAS VIA GITHUB REST API:")
    print("=" * 80)
    all_ok = True
    for name, repo, sha in ACTIONS:
        url = f"https://api.github.com/repos/{repo}/commits/{sha}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "AegisChain-Audit/1.0",
            "Accept": "application/vnd.github.v3+json"
        })
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.getcode()
                data = json.loads(resp.read().decode())
                commit_author = data.get("commit", {}).get("author", {}).get("name", "unknown")
                commit_date = data.get("commit", {}).get("author", {}).get("date", "unknown")
                commit_msg = data.get("commit", {}).get("message", "").splitlines()[0]
                resolved_sha = data.get("sha", "")
                
                print(f"[HTTP {status}] {repo} @ {sha[:12]}")
                print(f"  Resolved SHA: {resolved_sha}")
                print(f"  Author/Date:  {commit_author} on {commit_date}")
                print(f"  Message:      {commit_msg[:60]}")
                print()
        except urllib.error.HTTPError as e:
            print(f"[HTTP {e.code}] FAILED {repo} @ {sha}: {e.reason}")
            all_ok = False
        except Exception as e:
            print(f"[ERROR] {repo} @ {sha}: {e}")
            all_ok = False
            
    print("=" * 80)
    if all_ok:
        print(f"RESULT: ALL {len(ACTIONS)} ACTION SHAS RESOLVED SUCCESSFULLY (HTTP 200).")
    else:
        print("RESULT: FAILED TO RESOLVE SOME SHAS.")
        sys.exit(1)

if __name__ == '__main__':
    main()
