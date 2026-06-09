# 0001. Pinned trust anchor; unpinned vault is read-only

* Status: Accepted
* Deciders: Paul Clark
* Date: 2026

## Context

A `.pqsm` manifest carries a `signer-public-key` field and a signature
over the manifest body. A naive verifier would say "the manifest is
trustworthy iff its signature verifies under the embedded signer key."
That is **self-attestation**: any attacker who can author and sign a
manifest produces something that passes this check, and the verifier
has no basis to distinguish a legitimate manifest from a forged one
just because it is internally consistent.

We need an out-of-band anchor of trust.

## Decision

`PqSqliteVault` takes the trusted signer public key in its constructor.
Every operation — including read paths — refuses manifests whose
`signer-public-key` does not equal that pin, byte-for-byte.

A second, deliberately-ugly factory (`PqSqliteVault.CreateUnpinned`)
returns a vault that accepts any internally-consistent manifest. It is
**read-only**: every mutating operation throws. It exists so inspection
tooling can decode an arbitrary `.pqsm` without lying about its trust
posture. The naming ("unpinned"), the static factory call site, and the
documented limitations are all chosen to make accidental production use
implausible.

Mutating operations also prove that the supplied signing private key
corresponds to the pin, via a random-challenge sign/verify, before
re-signing. This closes the trust-anchor swap (`A6` in the threat
model).

## Consequences

**Positive:**
- Manifest substitution by an attacker is detected at the trust
  boundary, not deeper in the parser where it could be racy or
  bypassable.
- Applications get a "this database is mine" guarantee for the cost of
  shipping one public key with the binary, the way a root certificate
  is shipped.
- The unpinned escape hatch is honest about what it is, instead of
  pretending the manifest's embedded signer is meaningful trust.

**Negative:**
- Applications cannot rotate the *trust anchor* without rewriting it
  in the binary. This is deliberate: rotating the anchor would defeat
  its purpose. A future ADR could specify a managed trust-rotation
  protocol if needed.
- There is no "list of trusted signers" — only one. Multi-signer
  authority models are deferred to post-1.0 (see `docs/ROADMAP.md`).

## Revisiting

This decision would have to be reopened if either:
- A concrete deployment scenario requires multi-signer authority
  (multiple devices, each authorised to mint manifests) and the
  workaround of one shared signer is unacceptable.
- A safe, deterministic trust-anchor rotation protocol exists that
  does not move the substitution risk back into the manifest.

## Related

- [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) §3 (trust anchors), A3
  (manifest substitution), A6 (trust-anchor swap via re-sign).
- [`docs/SPEC.md`](../SPEC.md) §7 (signing and database binding).
