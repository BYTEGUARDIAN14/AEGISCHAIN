# Scenario 11: Unapproved Base Image Substitution

## Real-World Incident Context
Mirrors container baseline compromises where developers swap hardened minimal base images (e.g. Google Distroless or Chainguard) for generic distribution images (e.g. unpinned `node:alpine` or `ubuntu:latest`) containing dozens of unnecessary utilities, shells, and package managers that expand the attack surface.

## Attack Vector / Evaluation
A developer or pull request modifies the Dockerfile base image layer from the approved pinned Google Distroless digest to an arbitrary unapproved base image digest (`sha256:unapproved...`).

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `40 / 100`
- **Failing Rule**: `base_image_allowlist`
- **Reason**: `Base image digest is not on the platform allowlist`
- **Remediation**: `Rebase workload onto approved Google Distroless or Chainguard base image`
