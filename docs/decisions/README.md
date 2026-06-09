# Architectural Decision Records

Decisions that future readers, contributors, and reviewers will likely
question. Each record explains the choice, the alternatives we
considered, and what would have to change to revisit it.

Format: [MADR](https://adr.github.io/madr/) lite.

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-pinned-trust-anchor.md) | Pinned trust anchor; unpinned vault is read-only | Accepted |
| [0002](0002-sidecar-manifest-not-in-band.md) | Sidecar `.pqsm` manifest, not in-band | Accepted |
| [0003](0003-revocation-always-rotates.md) | Revocation always rotates the DEK | Accepted |
| [0004](0004-strict-v1-no-extensions.md) | Strict v1 parser; no extension mechanism | Accepted |

## When to write a new ADR

If your PR makes a choice that:

- A reasonable reviewer might argue with on grounds of taste,
- Has long-term API or wire-format consequences,
- Trades one risk against another in a way the diff cannot explain,

…then write an ADR. Number it sequentially, link it from this index, and
reference it from `CHANGELOG.md` if user-visible.

When NOT to write an ADR: implementation details, bug fixes, and
straightforward changes that the spec, threat model, or existing ADRs
already cover.
