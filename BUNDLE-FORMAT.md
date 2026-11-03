# Northfleet Bundle Format (`.nfb`), v1.0.0

A `.nfb` file is the wire and at-rest format Northfleet uses to move a complete
Kubernetes deployment from a connected build environment to an air-gapped
target cluster. It is designed to be:

- **Self-describing.** A single top-level `manifest.json` lists the bundle's
  manifests, images, SBOMs and policy with their content hashes.
- **Inspectable with stock tools.** Given the operator's public key from a
  trusted channel, `tar(1)`, `jq(1)`, `sha256sum(1)` and cosign are
  sufficient to validate a bare-key bundle signed with Ed25519 or ECDSA
  P-256, provenance included, and, from cosign v3.1.4, one signed with
  ECDSA P-384; the same tools with `openssl(1)` in place of cosign validate
  a P-384 bundle with any cosign release. None of it needs
  Northfleet-specific software (see Signing and Attestations). A cert-chain
  bundle's certificates need an X.509 path validator.
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
| `contents.manifests` | yes | array | Each entry has `path` and `sha256` (lowercase hex of file contents). `path` is `manifests/` followed by a file name that ends in `.yaml` or `.yml` and contains no `/`, `\` or NUL: a manifest is a file directly under `manifests/`. Verifiers MUST refuse a bundle that lists any other manifest path. Nested directories are reserved for a later format version. |
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
`manifest.json.cert` is present. The signature shows that the bundle was
signed with the key the verifier holds. The signer's identity is the
manifest's `createdBy`, as the producer declares it: in this mode it is
declared, not authenticated. A deployment that requires an authenticated
individual signer uses cert-chain mode.

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

`operator.pub` below is the operator's public key, obtained from the
operator over a channel the verifier trusts, never from the bundle. These
commands are for bare-key bundles: a key taken from a bundle's
`manifest.json.cert` proves nothing until that certificate is validated to a
trust anchor the verifier holds (Cert-chain mode).

With cosign v3 (tested with v3.1.4), package the detached signature as a
Sigstore bundle, then verify it:

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

`cosign bundle create` only packages the signature; it checks nothing.
`cosign verify-blob` checks the signature over the stored `manifest.json`
bytes and prints `Verified OK`. Neither command needs network access. The
files `manifest.json` lists are then checked against its hashes with
`sha256sum(1)`.

The `--ignore-tlog` and `--insecure-ignore-tlog` flags are required because
Northfleet bundles are not recorded in the public Rekor transparency log,
which an air-gapped site cannot reach; without them, cosign goes to the
network. Cosign's warning is accurate: without a log, cosign checks only
that the key signed these bytes. It gives no evidence of when they were
signed and no public record in which a signature made with a stolen key
would show up, and a key is retired only by no longer distributing it.
These commands also do not check the replay order (`previousBundleId`) or,
in cert-chain mode, the certificate chain and CRL.

cosign v2 (tested with v2.6.5) needs a Sigstore trusted root to verify a
Sigstore bundle, and fetches one over the network. Without network access,
use the detached-signature form instead, which cosign v2 accepts and cosign
v3 deprecates. Offline, cosign v2 first warns that it could not fetch
`trusted_root.json` from the TUF repository, then verifies:

```sh
cosign verify-blob \
  --key operator.pub \
  --signature <bundleId>/manifest.json.sig \
  --insecure-ignore-tlog \
  <bundleId>/manifest.json
```

Other signing keys are ECDSA P-256 and P-384. The signature is base64
(StdEncoding) of the ASN.1 DER `ECDSA-Sig-Value` over the SHA-256 (P-256) or
SHA-384 (P-384) digest of the `manifest.json` bytes. The public key's type
and curve select the algorithm; the signature carries no algorithm
identifier. No other key types are defined. The cosign commands above
verify Ed25519 and P-256 signatures, and P-384 ones from cosign v3.1.4,
which hashes with the key's own hash. Earlier releases hash with SHA-256
whatever the key, unless given `--signature-digest-algorithm`, which cosign
v3 deprecates, so they refuse a P-384 signature. OpenSSL verifies a P-384
signature with any cosign release or none: decode it from base64, then
check it over the stored bytes.

```sh
openssl base64 -d -A -in <bundleId>/manifest.json.sig -out manifest.sig.der
openssl dgst -sha384 -verify operator.pub -signature manifest.sig.der \
  <bundleId>/manifest.json
```

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

The envelope is verifiable against the operator public key without Northfleet
tooling. As in Signing, `operator.pub` comes from the operator over a trusted
channel, never from the bundle. With cosign v3 (tested with v3.1.4) and an
Ed25519 or P-256 key, wrap the envelope (at the path
`attestations.slsaProvenance` names; nfctl writes
`attestations/slsa-provenance.intoto.jsonl`) as a Sigstore bundle, keeping only
each signature's `sig`, then verify it. DSSE signs only the payload type and
the payload, so `keyid` is an unsigned hint and dropping it changes nothing
that is verified. cosign v3 does not accept the signature while nfctl's
`keyid` is present, as it is not the key ID cosign derives from the key.

```sh
jq '{mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
     verificationMaterial: {publicKey: {hint: ""}},
     dsseEnvelope: {payload, payloadType, signatures: [.signatures[] | {sig}]}}' \
  <bundleId>/attestations/slsa-provenance.intoto.jsonl > provenance.sigstore.json
cosign verify-blob-attestation \
  --bundle provenance.sigstore.json \
  --key operator.pub \
  --type slsaprovenance1 \
  --insecure-ignore-tlog \
  <bundleId>/manifest.json
```

`cosign verify-blob-attestation` checks the DSSE signature, the predicate type
and that the statement's subject digest is the SHA-256 of the stored
`manifest.json`, and prints `Verified OK`. It needs no network access. It
does not check the source claim against anything: compare it with the source
you expect by reading it.

```sh
jq -r .payload <bundleId>/attestations/slsa-provenance.intoto.jsonl | base64 -d \
  | jq '.predicate.buildDefinition | {externalParameters, resolvedDependencies}'
```

cosign v2 (tested with v2.6.5) verifies the envelope itself without network
access, after the same TUF warning as for the manifest signature:

```sh
cosign verify-blob-attestation \
  --key operator.pub \
  --signature <bundleId>/attestations/slsa-provenance.intoto.jsonl \
  --type slsaprovenance1 \
  --insecure-ignore-tlog \
  <bundleId>/manifest.json
```

As with the manifest signature, the cosign commands above verify a P-384
envelope, which is signed over SHA-384, from cosign v3.1.4; earlier
releases refuse it. OpenSSL verifies it with any release: rebuild
the DSSE pre-authentication encoding (PAE) of the payload, check the
signature over it, then check the statement's predicate type and subject.
The last command prints `true`.

```sh
env=<bundleId>/attestations/slsa-provenance.intoto.jsonl
jq -j .payload "$env" | openssl base64 -d -A -out payload.json
type=$(jq -r .payloadType "$env")
printf 'DSSEv1 %d %s %d ' "${#type}" "$type" "$(wc -c < payload.json | tr -d ' ')" > pae.bin
cat payload.json >> pae.bin
jq -j '.signatures[0].sig' "$env" | openssl base64 -d -A -out envelope.sig.der
openssl dgst -sha384 -verify operator.pub -signature envelope.sig.der pae.bin
jq -e --arg d "$(openssl dgst -sha256 -r <bundleId>/manifest.json | cut -d' ' -f1)" \
  '.predicateType == "https://slsa.dev/provenance/v1" and .subject[0].digest.sha256 == $d' \
  payload.json
```

`slsa-verifier` does not verify this provenance: it verifies provenance only
against the signing identities of the builders it knows, and cannot be given
the operator public key for it (its one public-key option, `verify-vsa`, is
for verification summary attestations).

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

A verifier reads the format versions it implements and refuses a bundle of
any other version, a later 1.y included, saying that a verifier for that
version is needed. It never reads a later version by skipping what it does
not know, since a later version may add something a verifier must check. A
producer writes the earliest version that describes the bundle, so a
bundle that uses no later feature can be read by every 1.x verifier.

`nfctl` produces and consumes `schemaVersion: "1.0.0"` exclusively.

## Reserved field names

The following top-level keys are reserved in `manifest.json` and MUST NOT be
used by third-party extensions:

`schemaVersion`, `bundleId`, `createdAt`, `createdBy`, `classification`,
`target`, `contents`, `attestations`, `policy`, `previousBundleId`,
`signingAlgorithm`, `signatures`.

Within `attestations`, two names are reserved for later format versions:
`buildProvenance`, for SLSA provenance signed by a build platform rather
than the operator (SLSA Build L3), and `inTotoLinks`, for in-toto link
metadata. `slsaProvenance` names the operator-signed envelope in every 1.x
version.

A key this spec does not define, at the top level or inside any object,
makes the manifest invalid, and verifiers MUST refuse the bundle. This
includes a reserved name the version does not define, such as
`signatures` or `attestations.inTotoLinks` in 1.0.0. The exception is an
experimental key: extensions MAY use keys starting with `x-`, at any
level. These keys, and anything under them, are ignored by verifiers but
preserved through the canonicalization round-trip.

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
- **2026-09-30. Correction, schemaVersion unchanged (`1.0.0`).** Earlier text
  said the SLSA provenance envelope can be verified against the operator public
  key with `cosign verify-blob` or `slsa-verifier`. `cosign verify-blob` does not
  accept the envelope as stored, and `slsa-verifier` verifies provenance only
  against the signing identities of the builders it knows, not against an
  operator key. Attestations now gives stock commands that verify it: cosign
  for an Ed25519 or P-256 key, OpenSSL for a P-384 key. No bundle is affected,
  and what a verifier checks does not change.
- **2026-11-02. Correction, schemaVersion unchanged (`1.0.0`).** Earlier
  text said the cosign commands do not verify a P-384 signature or
  provenance envelope. From cosign v3.1.4 they do, since `verify-blob` hashes
  with the key's own hash; earlier releases still refuse them, and the
  OpenSSL commands work with any release. No bundle is affected, and what a
  verifier checks does not change.
- **2026-11-02. Correction (security), schemaVersion unchanged (`1.0.0`).**
  Earlier text let a manifest entry's `path` be any bundle-relative path, so
  a bundle could list a file in a nested directory, the embedded policy or
  an SBOM as a Kubernetes manifest for the consumer to apply. A manifest
  path is now a `.yaml` or `.yml` file directly under `manifests/`, and a
  verifier refuses any other. nfctl's `bundle create` has only ever written
  such paths, except for a manifest whose file name contains a backslash;
  a bundle listing another path, which nfctl v0.5.1 and earlier verified,
  now fails verification.
- **2026-11-02. Correction (security), schemaVersion unchanged (`1.0.0`).**
  Earlier text did not say what a verifier does with a manifest key this
  spec does not define, or with a later 1.y `schemaVersion`. A key the spec
  does not define, other than an `x-` key, now makes the manifest invalid,
  and a verifier refuses a version it does not implement rather than read
  it by skipping unknown keys (Versioning policy, Reserved field names).
  `attestations.inTotoLinks` is reserved. nfctl has never written such a
  key; a bundle carrying one, which nfctl v0.5.1 and earlier verified while
  ignoring it, now fails verification.
- **2026-11-02. Correction, schemaVersion unchanged (`1.0.0`).**
  `attestations.buildProvenance` is reserved for provenance a build
  platform signs (SLSA Build L3), so it never shares a field with the
  operator-signed `slsaProvenance`, and a verifier judges each against its
  own trust input. No bundle is affected.
- **2026-11-02. Correction, schemaVersion unchanged (`1.0.0`).** Earlier
  text said bare-key mode is not acceptable for any accredited deployment.
  Whether a signing arrangement is acceptable for a deployment is the
  deploying organization's and its assessor's decision. Bare-key mode now
  says what it establishes and what it does not: the key, not an
  authenticated signer. No bundle is affected, and what a verifier checks
  does not change.
