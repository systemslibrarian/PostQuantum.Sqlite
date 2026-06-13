# Roadmap

The headline question is **what has to be true before this package
ships 1.0**, and what is deliberately deferred.

## Working principle

Pre-1.0 the manifest format and the public API can change. After 1.0
they cannot, except behind a new manifest `version` field (with a
documented migration) or in a 2.0. That makes the 1.0 cut a one-way
door, so the criteria below are conservative.

## 1.0 criteria

A 1.0 release requires every item below to be true. Anything still
red blocks the cut.

### Format and API stability
- [ ] `docs/SPEC.md` frozen for v1 — no field renames, no field
      additions, no relaxation of strict parsing.
- [ ] `PublicAPI.Shipped.txt` reflects the surface we are willing to
      support, with no churn for ≥ one release cycle.
- [ ] Backwards-compat tests exist for `.pqsm` files produced by every
      shipped pre-1.0 version.

### External assurance
- [ ] An independent security review of the frozen 1.0 candidate is
      complete; report and disposition of findings published.
- [ ] Fuzzing campaign over `PqSqlCipherManifest.Deserialize` and the
      manifest state machine has run continuously for ≥ 1 CPU-month
      with no unresolved findings; corpus committed.
- [ ] Property-based tests cover wrap/unwrap, sign/verify, manifest
      roundtrip, recipient set operations, and rotation invariants.

### Interoperability
- [ ] Test vectors (positive and negative) cover every normative
      requirement in `docs/SPEC.md`, with explicit "MUST reject"
      cases for each parser rejection rule.
- [ ] At least one independent implementation has validated against
      the vectors; failures triaged and either fixed or specced.

### Release trust
- [ ] Release workflow signs tags and (where the distribution channel
      supports it) packages.
- [ ] Build provenance attestation published for every release artifact.
- [ ] SBOM published per release.
- [ ] Reproducibility documented and verified by a third party at
      least once before tag-cut.

### Platform proof
- [ ] CI proves Linux (with OpenSSL ≥ 3.5), Windows, and macOS.
- [ ] Performance benchmarks for create / open / add-recipient /
      rotate / revoke published for at least two database sizes.
- [ ] Fault-injection coverage for pending-manifest recovery and
      partial filesystem failures.

### Operator guidance
- [ ] Deployment guide for: out-of-band revision tracking, signer key
      custody, backup/restore as a (db, sidecar) unit, incident
      response for compromised recipients.
- [ ] "When NOT to use this" section in the README.
- [ ] At least one sample beyond `QuickStart` showing a realistic
      multi-device or break-glass scenario.

## Explicitly out of scope for 1.0

These are sometimes-requested but will not block 1.0:
- A custom SQLCipher fork or SQLCipher-replacement.
- Generic PQC abstractions beyond what `IKemAlgorithm` /
  `ISignatureAlgorithm` / `IPasswordKdf` already provide.
- Key-management service features. (See `PostQuantum.KeyManagement`.)
- Schema-aware encryption beyond the page-level SQLCipher guarantees.

## Candidates for post-1.0

- X-Wing hybrid KEM as a built-in (today possible via `IKemAlgorithm`).
- Argon2id as a built-in `IPasswordKdf` (today possible via the
  interface; no managed Argon2 dependency in core).
- Multi-sidecar / multi-signer authority models.
- Manifest format v2 (only if v1 cannot express something we genuinely
  need; the bar is high).

## How this document changes

This roadmap is updated when criteria are met or scope changes. PRs that
flip a checkbox should link the evidence (issue, PR, audit report,
benchmark file). Adding or removing criteria requires a maintainer
decision recorded in `docs/decisions/`.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
