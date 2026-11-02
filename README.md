# Northfleet bundle format (`.nfb`)

**Status: draft.** This document is published for review and verification purposes. Normative language may change until the 1.0 tag of this repository. The format schema documented is `schemaVersion: 1.0.0`; the spec's own Revisions section records every correction.

The text here is published from the copy maintained alongside Northfleet's implementation and is refreshed at each release, so the two never differ.

## What this is

The open specification for the Northfleet bundle format: the wire and at-rest format that moves a complete Kubernetes deployment from a connected build environment to an air-gapped target cluster, with a verifiable signature chain and tamper-evident structure.

The spec is public for one reason: anyone receiving a Northfleet bundle should be able to verify it with stock tooling, without installing or trusting any Northfleet software. For a bare-key bundle signed with Ed25519 or ECDSA P-256, or with ECDSA P-384 from cosign v3.1.4, `tar(1)`, `jq(1)`, `sha256sum(1)` and cosign are sufficient; the spec gives OpenSSL commands for a P-384 bundle with any cosign release, and says what a cert-chain bundle needs. An accreditor can audit the trust path from this document alone.

See [`BUNDLE-FORMAT.md`](BUNDLE-FORMAT.md) for the specification.

## Quick verification example

With cosign v3, package the detached signature as a Sigstore bundle, then verify it:

```sh
cosign bundle create \
  --artifact <bundleId>/manifest.json \
  --signature <bundleId>/manifest.json.sig \
  --key operator.pub \
  --ignore-tlog \
  --out manifest.sigstore.json
cosign verify-blob \
  --bundle manifest.sigstore.json \
  --key operator.pub \
  --insecure-ignore-tlog \
  <bundleId>/manifest.json
```

`operator.pub` is the operator's public key, obtained over a channel you trust, never from the bundle. The `--ignore-tlog` and `--insecure-ignore-tlog` flags reflect the air-gapped threat model: bundles are deliberately not registered in a public transparency log. The spec's Signing section gives the cosign v2 form, what these commands do and do not check, and the OpenSSL commands for P-384.

## What this repository is not

This repository contains the format specification only. The implementation that produces and applies bundles is proprietary, with source access available to design partners and accreditors under NDA. For the product, see [northfleetsecurity.ca](https://northfleetsecurity.ca).

## Versioning

`schemaVersion` follows semantic versioning. Patch bumps are editorial. Minor bumps are additive and backward-compatible. Major bumps are breaking and coordinated out of band. The policy is normative in the spec.

## License

Spec text copyright 2026 Northfleet Security Ltd. Licensed under the [Apache License 2.0](LICENSE).

## Feedback

Issues and corrections are welcome via the issue tracker. Questions about the product belong at [northfleetsecurity.ca](https://northfleetsecurity.ca), not here.
