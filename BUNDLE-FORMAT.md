# Northfleet Bundle Format (`.nfb`), v1.0.0

A `.nfb` file is the wire and at-rest format Northfleet uses to move a complete
Kubernetes deployment from a connected build environment to an air-gapped
target cluster. It is designed to be:

- **Self-describing.** A single top-level `manifest.json` lists the bundle's
  manifests, images, SBOMs and policy with their content hashes.
- **Inspectable with stock tools.** `tar(1)`, `jq(1)`, `sha256sum(1)` and
  `cosign verify-blob` are sufficient to validate a bare-key bundle signed
  with Ed25519 or ECDSA P-256, without installing any Northfleet-specific
  software. A P-384 signature needs a verifier that hashes with SHA-384 (see
  Signing), and a cert-chain bundle's certificates need an X.509 path
  validator.
- **Canonical.** The bytes that get signed are the RFC 8785 (JCS) encoding of
  the manifest, so every producer encodes one manifest the same way.
- **Forward-compatible.** `schemaVersion` gates additive evolution.

This document is the authoritative spec. nfctl, Northfleet's implementation,
is a consumer of this spec, not its source of truth.

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
│   └── crl.pem                   # optional CRL from the CA that issued the signing certificate
└── policy/
```

The directories other than `manifests/` are optional and MUST NOT appear
unless populated.

## `manifest.json`

`manifest.json` is the only file that must exist in every bundle. The
manifests, the SBOMs, the policy file and each image's OCI manifest blob are
referenced from it by relative path and SHA-256 digest. The signature,
certificate and CRL sidecars, the provenance envelope (named in
`attestations.slsaProvenance`, and carrying its own DSSE signature) and the
rest of the OCI layout under `images/` are not hashed in it.

### Canonical encoding

The bytes of `manifest.json` are produced by:

1. Marshalling the in-memory manifest to JSON.
2. Re-encoding through **RFC 8785 JSON Canonicalization Scheme (JCS)**:
   - keys sorted lexicographically by UTF-16 code unit,
   - no insignificant whitespace,
   - numbers in their shortest round-trip form,
   - strings using minimal escaping.
3. Writing the resulting bytes verbatim into the archive.

Step 2 is what makes the signature stable across producers, languages, and Go
encoder versions. The signature covers the bytes of `manifest.json` exactly as
stored in the archive. Verifiers MUST check the signature over those bytes, as
`cosign verify-blob` does over the extracted file, and MUST NOT re-encode or
re-canonicalize them first. For a conforming bundle the stored bytes already
are the JCS encoding; for any other bundle, canonicalizing first would accept
bytes the producer did not sign.

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
| `schemaVersion` | yes | string | Semantic version of this spec. Producers of this version MUST emit `"1.0.0"`. |
| `bundleId` | yes | string | UUIDv7 (RFC 9562). Time-ordered, monotonic, 128 bits. |
| `createdAt` | yes | string | RFC 3339 UTC, millisecond precision. |
| `createdBy` | yes | string | Operator identity as the producer declares it. It is covered by the signature but not derived from or checked against any certificate; verifiers MUST NOT treat it as an authenticated identity. |
| `classification` | yes | string | Free-form. Recommended values: `UNCLASSIFIED`, `PROTECTED-A`, `PROTECTED-B`, `SECRET`. Compared as an exact, case-sensitive string. |
| `target` | yes | object | See below. Identifies the deployment target for replay-detection scoping. |
| `target.cluster` | yes | string | Cluster name. |
| `target.namespace` | yes | string | Namespace the bundle applies to. |
| `target.application` | yes | string | Application identifier within the namespace. |
| `target.kubernetesVersion` | no | string | Semver constraint. Advisory: `bundle inspect` shows it; apply does not parse or check it. |
| `contents.manifests` | yes | array | Each entry has `path` (relative to bundle root) and `sha256` (lowercase hex of file contents). |
| `contents.images` | yes | array | Each entry has `reference` (the image reference as the manifests name it), `digest` (`sha256:` plus the lowercase hex SHA-256 of the image's OCI manifest blob) and `ociLayoutPath` (the bundle-relative path of that blob, under `images/`). Empty when the bundle carries no images. |
| `contents.sboms` | yes | array | Each entry has `imageRef`, `path` and `sha256`. Empty when the bundle carries no SBOMs. |
| `contents.policy` | no | object | `path` and `sha256` (lowercase hex) of the embedded Rego policy file. This entry is what binds the file: a producer that sets `policy` MUST set `contents.policy` with the same `path`. The policy calls only the OPA builtins its consumer allows and declares no METADATA schemas. nfctl allows a fixed list of builtins, documented with nfctl, none of which reads anything but its arguments and the policy itself (no network, host, clock, randomness or cryptography builtins); it will not embed a policy that calls another builtin or declares METADATA schemas, and with `--verify-policy` fails the policy check of a bundle whose policy does. |
| `attestations` | no | object | `slsaProvenance`: bundle-relative path of the SLSA Provenance v1.0 DSSE envelope. Present when the bundle carries one. |
| `policy` | no | string | Bundle-relative path of the embedded Rego policy file (`policy/verification.rego`). Informational; `contents.policy` binds the file. |
| `previousBundleId` | yes | string \| null | UUIDv7 of the previous bundle applied to the same `target`, or `null` for first-apply. |
| `signingAlgorithm` | no | string | Advisory: SC-13 policy ID of the algorithm used to sign `manifest.json` (e.g. `ed25519`, `ecdsa-p256-sha256`). Verifiers MUST NOT consult this field for security decisions; the signature is self-describing via the operator public key's PKIX OID. Absent in unsigned bundles. |

### Bundle continuity (`previousBundleId`)

Replay detection is **per deployment target**, not per cluster. The chain key
is the tuple `(target.cluster, target.namespace, target.application)`.

The high-side stores, for each chain key, the most recently applied
`bundleId`. A new bundle is accepted only if its `previousBundleId` matches the
stored value (or is `null` and the operator passes `--first-apply`).

This lets one cluster receive bundles for many independent applications
without their replay state interfering.

## Signing chain

A bundle may be signed in one of two modes:

### Bare-key mode

`manifest.json.sig` is verified directly against an operator public key
delivered out-of-band (verifier flag: `--public-key operator.pub`). No
`manifest.json.cert` is present. Acceptable for non-classified demos and
CI; not acceptable for any accredited deployment.

### Cert-chain mode

`manifest.json.cert` is present and contains, in order:

1. The leaf signing certificate (PEM `CERTIFICATE` block).
2. Zero or more intermediate certificates (PEM `CERTIFICATE` blocks).

The root CA is **never** included in the sidecar -- the verifier supplies it
via `--trust-root` from its own trust store.

Verifier algorithm:

1. Parse `manifest.json.cert` into leaf + intermediates.
2. Verify that the leaf chains to a configured trust anchor through the
   intermediates, with the code-signing extended key usage. The check is
   local: no OCSP or CRL fetch. Certificates in the sidecar that are not in
   the verified chain carry no weight in any later step.
3. If `revocation/crl.pem` is present, it MUST hold exactly one PEM `X509
   CRL` block, with nothing but whitespace before or after it (a malformed
   block included), and the verifier MUST refuse the bundle unless all of
   these hold:
   - The CRL was issued and signed by the certificate that issued the leaf
     in a chain verified in step 2: its issuer name equals that
     certificate's subject, its authority key identifier, when both are
     present, equals that certificate's subject key identifier, and its
     signature verifies with that certificate's key. When the verified
     chains hold more than one certificate for the leaf's issuer
     (cross-certification), the CRL MUST pass against one of them. No other
     certificate, in the sidecar or among the trust anchors, is a CRL
     issuer.
   - The CRL's signature algorithm is not based on SHA-1 or MD5.
   - The CRL is a complete CRL covering the leaf. A verifier MUST refuse a
     delta CRL, a CRL whose issuingDistributionPoint limits its scope so
     that it does not cover the leaf (only CA certificates, only attribute
     certificates, only some reasons, an indirect CRL, only user
     certificates when the leaf is a CA, or distribution points the leaf
     does not name), and a CRL or CRL entry carrying a critical extension
     it does not process (RFC 5280 §5.2, §5.3). A verifier MUST also
     refuse the CRL when the leaf's cRLDistributionPoints extension limits
     a distribution point to some reasons or names a cRLIssuer: a single
     CRL is then not complete for the leaf.
   - `thisUpdate` is not ahead of the verifier's clock by more than its
     clock-skew allowance (nfctl: 24 hours), `nextUpdate`, when present,
     is not in the past, and `now - thisUpdate` is within the verifier's
     configured maximum CRL age (nfctl: `--max-crl-age`, default 720h).
   - The leaf's serial number is not listed.

   If the leaf is itself a trust anchor (a verified chain is the leaf
   alone), no CRL applies: a verifier MUST refuse such a bundle if the
   bundle carries a CRL or the verifier requires one.
4. Verify `manifest.json.sig` over the stored `manifest.json` bytes with the
   leaf's public key, using the algorithm the key's type selects (see
   Signing).

A verifier configured to require a CRL (nfctl: `--require-crl`) MUST reject
bundles that lack `revocation/crl.pem`. Only the leaf is checked for
revocation; this specification defines no revocation check of intermediate
certificates.

Setting `--trust-root` and `--public-key` simultaneously is a configuration error.

### CRL freshness

CRLs in air-gapped environments cannot be auto-fetched. The verifier accepts
a CRL only from `thisUpdate`, less the clock-skew allowance, to `nextUpdate`,
and within the verifier's configured maximum CRL age (nfctl: `--max-crl-age`, default 720h =
30 days, as a positive whole number of days such as `7d` or a positive Go
duration such as `168h`).

`revocation/crl.pem` is not covered by the manifest signature: the bundle's
producer, or anyone who handles the bundle, chooses which CRL it carries. A
revocation therefore reaches the verifier only in a CRL issued after it:
until every CRL the issuer published before the revocation is past its
`nextUpdate` or older than the maximum CRL age, whoever handles the bundle
can ship one of those, and a verifier that does not require a CRL accepts a
bundle with none. This format defines no way for the verifier to supply a
CRL of its own.

## Signing

`manifest.json.sig` is a detached signature produced by signing the canonical
bytes of `manifest.json` with the operator's key.

The default key, the one `nfctl init keygen` writes:

- Algorithm: Ed25519.
- Private key: PKCS#8 PEM, unencrypted (nfctl does not encrypt key files at rest).
- Public key: PKIX PEM (`-----BEGIN PUBLIC KEY-----`).
- Signature: base64 (StdEncoding) of the raw 64-byte Ed25519 signature
  over the JCS-canonical bytes of `manifest.json`. Bytes-identical to
  `cosign sign-blob` output.
- Trust roots: file-based. No Fulcio, no Rekor, no public transparency log.

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
misnomer for this threat model: we deliberately do not depend on a
publicly reachable log.

Other signing keys are ECDSA P-256 and P-384. The signature is base64
(StdEncoding) of the ASN.1 DER `ECDSA-Sig-Value` over the SHA-256 (P-256) or
SHA-384 (P-384) digest of the `manifest.json` bytes. The public key's type
and curve select the algorithm; the signature carries no algorithm
identifier. No other key types are defined. `cosign verify-blob --key`
(v3.1.3) verifies Ed25519 and P-256 signatures but not P-384 ones, because it
hashes with SHA-256.

A key may be held on hardware; the signature format does not change. There
is no transparency-log entry for a bundle signature, public or private.

Public Fulcio + Rekor are explicitly out of scope: a bundle is built to cross
into a classified facility, where no public transparency log can be reached,
so verification must not depend on one.

## Attestations

### SLSA provenance (v1.0)

When `bundle create --provenance` is used, the bundle's `attestations/` directory
contains a DSSE-signed SLSA Provenance v1.0 statement covering the canonical
`manifest.json`. The provenance MAY also carry a **source claim**, added with
`--source-uri <repo> [--source-ref <ref>] --source-commit <sha>`. The claim
populates two fields per the SLSA v1.0 request/resolved split:
`buildDefinition.externalParameters.source = {"uri": "<source-uri>", "ref": "<source-ref>"}` (the operator's
build-from request) and a `buildDefinition.resolvedDependencies` entry
`{"name": "source", "uri": "git+<source-uri>@<source-ref>", "digest": {"gitCommit": "<source-commit>"}}`
(the immutable resolved commit, using the in-toto `gitCommit` digest-set type).
This representation is what `slsa-verifier` and stock SLSA-aware consumers expect,
and the attestation can be verified with `cosign verify-blob` or `slsa-verifier`
against the operator public key without Northfleet tooling.

The source claim is **operator-asserted (SLSA Build L1)**: it is as trustworthy
as the signing key. nfctl produces no CI-signed bundle provenance. nfctl does
**not** re-derive or compare a source tree hash; the
binding is via commit/ref identifiers combined with the DSSE envelope signature.
Verifiers enforce the claim with `--expect-source-uri` / `--expect-source-commit`;
a mismatch is a hard failure that rides the apply-time enforcement gate and is
break-glassable with an audited justification.

## Audit log linkage

nfctl's audit log records the `bundleId` of every bundle it creates, verifies
or applies. The log's format is not part of this specification.

## Versioning policy

`schemaVersion` changes only when the bundle format changes, following semver:

- Minor bumps: additive changes (new optional fields, new reserved
  directories). Existing v1.x bundles MUST remain valid against any future v1.y
  spec, except as a dated security correction under Revisions states.
- Major bumps: breaking changes. Producers and verifiers must agree on the
  major version out of band.

Corrections to this document that do not change what a conforming producer
writes are listed under Revisions, dated, and leave `schemaVersion`
unchanged. A correction can make a verifier stricter; its entry says which
bundles it affects.

`nfctl` produces and consumes `schemaVersion: "1.0.0"` exclusively.

## Reserved field names

The following top-level keys are reserved in `manifest.json` and MUST NOT be
used by third-party extensions:

`schemaVersion`, `bundleId`, `createdAt`, `createdBy`, `classification`,
`target`, `contents`, `attestations`, `policy`, `previousBundleId`,
`signingAlgorithm`, `signatures`.

Extensions MAY use a `x-` prefix for experimental keys. These keys are
ignored by verifiers but preserved through the canonicalization round-trip.

## Revisions

- **2026-09-28. Correction, schemaVersion unchanged (`1.0.0`).** Earlier
  text said verifiers MUST canonicalize `manifest.json` before checking its
  signature. The signature has always covered the stored bytes, which
  conforming producers write in JCS form, and nfctl has always checked it
  over them. Verifiers must check the stored bytes (Canonical encoding). No
  bundle a conforming producer wrote is affected.
- **2026-09-28. Correction (security), schemaVersion unchanged (`1.0.0`).**
  Earlier text said a CRL's signature is verified against the trust root. A
  CRL is accepted only from the certificate that issued the leaf in the
  verified chain (Cert-chain mode, step 3). A bundle whose CRL comes from
  any other issuer, including the trust anchor's CRL for an
  intermediate-issued leaf, which the earlier text allowed and nfctl v0.4.0
  accepted, now fails verification.
- **2026-09-28. Correction (security), schemaVersion unchanged (`1.0.0`).**
  Earlier text did not require the CRL to be complete or current. A
  verifier refuses a delta CRL, a CRL whose issuing distribution point does
  not cover the leaf, a CRL or entry with an unprocessed critical extension,
  a CRL past its `nextUpdate` or dated ahead of the clock, a SHA-1 or MD5
  CRL signature, a CRL file with more than one PEM block or with anything
  else before its block, a CRL for a leaf whose CRL distribution points
  limit reasons or name a cRLIssuer, and any CRL, or a required CRL, for a
  leaf that is itself a trust anchor (Cert-chain mode, step 3). Bundles carrying such a CRL, which nfctl v0.4.0 accepted, now
  fail verification.
