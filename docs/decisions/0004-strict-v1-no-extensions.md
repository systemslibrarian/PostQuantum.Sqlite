# 0004. Strict v1 manifest parser; no extension mechanism

* Status: Accepted
* Deciders: Paul Clark
* Date: 2026

## Context

Wire formats traditionally trade off two properties:

- **Forward compatibility.** A v1 parser silently ignores unknown
  fields so v2 writers can add things without breaking v1 readers.
- **Strictness.** A v1 parser rejects anything it did not write,
  refusing to be a hospitality engine for malicious or
  malformed input.

For a *security* manifest the second matters far more than the first.
A liberal parser has been the substrate for parser-confusion attacks
in JWT, X.509, PKCS#7, CBOR, ASN.1, BSON, COSE, and every other
format whose maintainers underestimated the cost of leniency.

## Decision

The v1 `.pqsm` parser is **strict**:

- Canonical CBOR only — definite lengths, sorted unique map keys,
  trailing bytes rejected.
- Whitelisted field keys — unknown top-level or recipient fields are
  hard rejections, not "unknown extension."
- Exact-length fields are enforced byte-for-byte against the declared
  algorithm.
- Variable-length fields have explicit upper bounds.
- Duplicate recipient fingerprints are rejected.
- `version` is `1`; any other value is rejected.

There is **no extension mechanism in v1**. Future fields require
a new `version` field value (v2) and a new spec section describing
the migration. Existing v1 readers MUST refuse v2 manifests rather
than silently strip the new fields.

## Consequences

**Positive:**
- Anything the parser accepts, we authored. Every parser-confusion
  attack class is excluded by construction.
- A reviewer reading `docs/SPEC.md` knows what the parser does to
  every input bit; there is no "the parser is forgiving in the
  following circumstances" footnote.
- Independent implementations can be tested against an explicit
  rejection corpus and there is no ambiguity about which rejections
  are required.

**Negative:**
- Forward compatibility is zero. Adding any field, including a
  field that v1 readers could safely ignore, requires a v2.
- We have to design the v2 transition deliberately (with at least
  one round-trip test against pre-1.0 vectors before cutting).

## Revisiting

This is a load-bearing structural choice. It will not be revisited
without a v2 manifest, and a v2 manifest is itself an explicit
decision (which would land here as ADR 0005).

## Related

- [`docs/SPEC.md`](../SPEC.md) §2 (encoding), §3 (top-level structure),
  §4 (recipient entry).
- [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) A7 (malicious manifest
  input).
- [`tests/PostQuantum.Sqlite.Tests/HardeningTests.cs`](../../tests/PostQuantum.Sqlite.Tests/HardeningTests.cs)
  — the rejection corpus this decision is enforced against.
