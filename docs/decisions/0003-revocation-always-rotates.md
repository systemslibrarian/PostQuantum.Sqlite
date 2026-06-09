# 0003. Revocation always rotates the DEK

* Status: Accepted
* Deciders: Paul Clark
* Date: 2026

## Context

Removing a recipient from the manifest can be done two ways:

1. **Remove only.** Drop the entry, re-sign, write. The database file
   is untouched; the DEK is unchanged.
2. **Remove and rotate.** Drop the entry, generate a new DEK,
   `sqlite3_rekey` every page, re-wrap to the surviving recipients,
   re-sign.

Option 1 is faster and simpler. It is also a lie.

## Decision

The public API offers **only the second option**:
`RemoveRecipientAndRotate`. There is no `RemoveRecipient` that omits
the rotation.

## Consequences

**Positive:**
- A removed recipient who cached the old DEK loses access. Without
  rotation, "revocation" only means "removed from the manifest" — the
  attacker still has the page-encryption key.
- A removed recipient who kept a copy of the old `.pqsm` cannot use
  it: the salt-binding still holds, but the DEK their old entry
  unwraps now decrypts nothing (the pages were re-keyed).
- The API teaches the right mental model. Most "is revocation
  working?" mistakes happen when developers reach for a fast
  remove-without-rotate and forget that the DEK is still the same.

**Negative:**
- Revocation is `O(database size)` rather than `O(1)`. Documented in
  `docs/ROADMAP.md` as a performance characteristic we will
  benchmark and publish before 1.0.
- A buggy or interrupted rotation could brick the database; we own
  that risk via the pending-manifest crash-recovery protocol (`A10`).

## Revisiting

Reopen if a credible deployment scenario requires
remove-without-rotate AND has an externally-tracked story for the
removed recipient's residual DEK access. Even then, the rotated
variant remains the default; the new API would have to be
deliberately ugly the way `CreateUnpinned` is.

## Related

- [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) A9 (revoked-recipient
  retention), A10 (crash during rotation).
- [`docs/SPEC.md`](../SPEC.md) §9 (atomic writes and crash-safe
  rotation).
- ADR [0001](0001-pinned-trust-anchor.md) (mutations also require
  proving the signing key matches the pin).
