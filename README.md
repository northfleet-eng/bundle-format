# Northfleet bundle format (`.nfb`)

**Status: draft.** This document is published for review and verification purposes. Normative language may change until the 1.0 tag of this repository. The format schema documented is `schemaVersion: 1.0.0`.

## What this is

The open specification for the Northfleet bundle format: the wire and at-rest format that moves a complete Kubernetes deployment from a connected build environment to an air-gapped target cluster, with a verifiable signature chain and tamper-evident structure.

The spec is public for one reason: anyone receiving a Northfleet bundle should be able to verify it with stock tooling, without installing or trusting any Northfleet software. `tar(1)`, `jq(1)`, and `cosign verify-blob` are sufficient. An accreditor can audit the trust path from this document alone.

See [`BUNDLE-FORMAT.md`](BUNDLE-FORMAT.md) for the specification.

## Quick verification example

```sh
cosign verify-blob \
  --key operator.pub \
  --signature <bundleId>/manifest.json.sig \
  --insecure-ignore-tlog \
  <bundleId>/manifest.json
```

(The `--insecure-ignore-tlog` flag reflects the air-gapped threat model: bundles are deliberately not registered in a public transparency log. See the spec's signing section.)

## What this repository is not

This repository contains the format specification only. The implementation that produces and applies bundles is proprietary, with source access available to design partners and accreditors under NDA. For the product, see [northfleetsecurity.ca](https://northfleetsecurity.ca).

## Versioning

`schemaVersion` follows semantic versioning. Patch bumps are editorial. Minor bumps are additive and backward-compatible. Major bumps are breaking and coordinated out of band. The policy is normative in the spec.

## License

Spec text copyright 2026 Brian Irish. Licensed under the [Apache License 2.0](LICENSE).

## Feedback

Issues and corrections are welcome via the issue tracker. Questions about the product belong at [northfleetsecurity.ca](https://northfleetsecurity.ca), not here.
