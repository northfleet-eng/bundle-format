# Northfleet Bundle Format (`.nfb`)

**Schema version:** 1.0.0 · **Document status:** Draft (normative language may change until the 1.0 tag of this repository)

A `.nfb` file is the wire and at-rest format Northfleet uses to move a complete
Kubernetes deployment from a connected build environment to an air-gapped
target cluster. It is designed to be:

- **Self-describing.** A single top-level `manifest.json` enumerates every
  artifact in the bundle and its content hash.
- **Inspectable with stock tools.** `tar(1)`, `jq(1)`, `cosign verify-blob`
  are sufficient to validate a bundle without installing any
  Northfleet-specific software.
- **Reproducible.** The bytes that get signed are deterministic.
- **Forward-compatible.** `schemaVersion` gates additive evolution.

This document is the authoritative spec. Northfleet's implementation is a
consumer of this spec, not its source of truth.

---

## Container

The `.nfb` file is an **uncompressed POSIX tar archive** (`ustar`). Image layers
are already gzip-compressed inside the OCI layout, so wrapping the outer
archive in gzip burns CPU on a 5 GB bundle for a near-zero size win and breaks
seek-based inspection.

The archive contains a single top-level directory whose name is the bundle's
UUIDv7. This avoids tar bombs on extraction and gives an obvious foreign-key
between filesystem and `manifest.json`.

```
01900000-0000-7000-8000-000000000000/
├── manifest.json                 # canonical JCS-encoded bundle manifest
├── manifest.json.sig             # detached signature over manifest.json
├── manifest.json.cert            # signing cert + intermediates (PEM, leaf first); absent if bundle was signed with a bare key
├── attestations/
├── manifests/
├── images/
├── sboms/
├── revocation/
│   └── crl.pem                   # optional signed CRL from the operator CA
└── policy/
```

Only `manifest.json` is required in every bundle; current producers populate
`manifest.json` and `manifests/`. The remaining directories are reserved and
MUST NOT appear unless populated.

## `manifest.json`

`manifest.json` is the only file that must exist in every bundle. Every other
file is referenced from it by relative path and SHA-256 digest.

### Canonical encoding

The bytes of `manifest.json` are produced by:

1. Marshalling the in-memory manifest to JSON.
2. Re-encoding through **RFC 8785 JSON Canonicalization Scheme (JCS)**:
   - keys sorted lexicographically by UTF-16 code unit,
   - no insignificant whitespace,
   - numbers in their shortest round-trip form,
   - strings using minimal escaping.
3. Writing the resulting bytes verbatim into the archive.

Step 2 is what makes the signature stable across producers, languages, and
encoder versions. Verifiers MUST canonicalize before computing the signature
verification target.

### Schema (v1.0.0)

```json
{
  "schemaVersion": "1.0.0",
  "bundleId": "01900000-0000-7000-8000-000000000000",
  "createdAt": "2026-05-05T14:30:00Z",
  "createdBy": "alice@northfleet.example",
  "classification": "PROTECTED-B",
  "target": {
    "cluster": "ground-systems-staging",
    "namespace": "ground-staging",
    "application": "telemetry-pipeline",
    "kubernetesVersion": ">=1.29.0"
  },
  "contents": {
    "manifests": [
      { "path": "manifests/deployment.yaml", "sha256": "…" }
    ],
    "images": [],
    "sboms": []
  },
  "previousBundleId": null
}
```

Field-by-field:

| Field | Required | Type | Notes |
|---|---|---|---|
| `schemaVersion` | yes | string | Semantic version of this spec. Current producers MUST emit `"1.0.0"`. |
| `bundleId` | yes | string | UUIDv7 (RFC 9562). Time-ordered, monotonic, 128 bits. |
| `createdAt` | yes | string | RFC 3339 UTC, millisecond precision. |
| `createdBy` | yes | string | Operator identity. In bare-key mode, a producer-configured string; in cert-chain mode, the subject of the signing certificate. |
| `classification` | yes | string | Free-form. Recommended values: `UNCLASSIFIED`, `PROTECTED-A`, `PROTECTED-B`, `SECRET`. |
| `target` | yes | object | See below. Identifies the deployment target for replay-detection scoping. |
| `target.cluster` | yes | string | Cluster name. |
| `target.namespace` | yes | string | Namespace the bundle applies to. |
| `target.application` | yes | string | Application identifier within the namespace. |
| `target.kubernetesVersion` | no | string | Semver constraint. Advisory. |
| `contents.manifests` | yes | array | Each entry has `path` (relative to bundle root) and `sha256` (lowercase hex of file contents). |
| `contents.images` | yes | array | Empty in current producer output. Schema preserved for forward compatibility. |
| `contents.sboms` | yes | array | Empty in current producer output. |
| `attestations` | no | object | Optional; see Attestations. |
| `policy` | no | string | Reserved. |
| `previousBundleId` | yes | string \| null | UUIDv7 of the previous bundle applied to the same `target`, or `null` for first-apply. |
| `signingAlgorithm` | no | string | Advisory: SC-13 policy ID of the algorithm used to sign `manifest.json` (e.g. `ed25519`, `ecdsa-p256-sha256`). Verifiers MUST NOT consult this field for security decisions; the signature is self-describing via the operator public key's PKIX OID. Absent in unsigned bundles. |

### Bundle continuity (`previousBundleId`)

Replay detection is **per deployment target**, not per cluster. The chain key
is the tuple `(target.cluster, target.namespace, target.application)`.

The high-side stores, for each chain key, the most recently applied
`bundleId`. A new bundle is accepted only if its `previousBundleId` matches the
stored value, or is `null` and the operator explicitly acknowledges a
first apply.

This lets one cluster receive bundles for many independent applications
without their replay state interfering.

## Signing chain

A bundle may be signed in one of two modes:

### Bare-key mode

`manifest.json.sig` is verified directly against an operator public key
delivered out-of-band. No `manifest.json.cert` is present. Suitable for
demonstrations and CI; not acceptable for any accredited deployment.

### Cert-chain mode

`manifest.json.cert` is present and contains, in order:

1. The leaf signing certificate (PEM `CERTIFICATE` block).
2. Zero or more intermediate certificates (PEM `CERTIFICATE` blocks).

The root CA is **never** included in the sidecar -- the verifier supplies it
from its own trust store.

Verifier algorithm:

1. Parse `manifest.json.cert` into leaf + intermediates.
2. Verify the leaf chains to a configured trust root using standard X.509
   path validation (purely local; no OCSP or CRL fetch).
3. If `revocation/crl.pem` is present, verify its signature against the
   trust root, enforce the verifier's configured maximum CRL age against the
   CRL's `thisUpdate` field, and check the leaf cert's serial is not in the
   revoked list. A stale CRL is a hard failure.
4. Extract the leaf's public key and verify `manifest.json.sig` against the
   canonical `manifest.json` bytes via an algorithm-aware verification path.

A verifier MAY operate in a strict mode that rejects bundles lacking
`revocation/crl.pem`.

A verifier MUST NOT be configured with both a bare public key and a trust
root; the two modes are mutually exclusive.

### CRL freshness

CRLs in air-gapped environments cannot be auto-fetched. The verifier accepts
a CRL only if `now - CRL.thisUpdate` does not exceed the verifier's configured
maximum CRL age (RECOMMENDED default: 720 hours = 30 days). Operators who
require tighter windows (typically per classification) configure the
verifier accordingly.

## Signing

`manifest.json.sig` is a detached signature produced by signing the canonical
bytes of `manifest.json` with the operator's local key.

For the current schema:

- Algorithm: Ed25519.
- Private key: PKCS#8 PEM.
- Public key: PKIX PEM (`-----BEGIN PUBLIC KEY-----`).
- Signature: base64 (StdEncoding) of the raw 64-byte Ed25519 signature
  over the JCS-canonical bytes of `manifest.json`. Bytes-identical to
  `cosign sign-blob` output.
- Trust roots: file-based. No dependency on a public certificate authority
  or a publicly reachable transparency log.

### Verifying with stock cosign

```sh
cosign verify-blob \
  --key cosign.pub \
  --signature <bundleId>/manifest.json.sig \
  --insecure-ignore-tlog \
  <bundleId>/manifest.json
```

The `--insecure-ignore-tlog` flag is required because Northfleet bundles
are produced for air-gapped deployment and are not registered in the
public Rekor transparency log. Cosign's "insecure" warning here is a
misnomer for this threat model: the format deliberately does not depend
on a publicly reachable log.

Public Fulcio and Rekor are explicitly out of scope: a bundle is built to
cross into a disconnected classified environment, and the format does not
depend on any publicly reachable service.

Future revisions may add hardware-backed signing (PKCS#11, TPM) and optional
private transparency logging. Such additions will be additive, minor-version
changes.

## Attestations

### SLSA provenance (v1.0)

A bundle MAY include, in its `attestations/` directory, a DSSE-signed SLSA
Provenance v1.0 statement covering the canonical `manifest.json`. The
provenance MAY also carry a **source claim** identifying the repository,
ref, and commit the bundle was built from. The claim populates two fields
per the SLSA v1.0 request/resolved split:
`buildDefinition.externalParameters.source = {"uri": "<source-uri>", "ref": "<source-ref>"}` (the operator's
build-from request) and a `buildDefinition.resolvedDependencies` entry
`{"name": "source", "uri": "git+<source-uri>@<source-ref>", "digest": {"gitCommit": "<source-commit>"}}`
(the immutable resolved commit, using the in-toto `gitCommit` digest-set type).
This representation is what `slsa-verifier` and stock SLSA-aware consumers expect,
and the attestation can be verified with `cosign verify-blob` or `slsa-verifier`
against the operator public key without Northfleet tooling.

The source claim is **operator-asserted (SLSA Build L1)** -- it is as
trustworthy as the signing key. A CI-signed, non-falsifiable variant
(SLSA Build L2+) is planned and will re-sign the same fields.
Implementations do not re-derive or compare a source tree hash; the binding
is via commit/ref identifiers combined with the DSSE envelope signature.
Verifiers MAY enforce expected source URI and commit values; a mismatch is
a verification failure. Implementations that provide an audited override
for verification failures record the override and its justification in the
audit log.

## Audit log linkage

Producers and appliers record bundle operations in an append-only,
hash-chained audit log; entries reference `bundleId`. The audit log format
is specified separately and is out of scope for this document.

## Versioning policy

`schemaVersion` follows semver:

- Patch bumps: editorial / non-normative changes to this document only.
- Minor bumps: additive changes (new optional fields, new reserved
  directories). Existing v1.x bundles MUST remain valid against any future v1.y
  spec.
- Major bumps: breaking changes. Producers and verifiers must agree on the
  major version out of band.

Current producers emit and consume `schemaVersion: "1.0.0"` exclusively.

## Reserved field names

The following top-level keys are reserved in `manifest.json` and MUST NOT be
used by third-party extensions:

`schemaVersion`, `bundleId`, `createdAt`, `createdBy`, `classification`,
`target`, `contents`, `attestations`, `policy`, `previousBundleId`,
`signingAlgorithm`, `signatures`.

Extensions MAY use a `x-` prefix for experimental keys. These keys are
ignored by verifiers but preserved through the canonicalization round-trip.
