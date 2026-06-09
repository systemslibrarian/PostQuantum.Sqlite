# 0002. Sidecar `.pqsm` manifest, not in-band

* Status: Accepted
* Deciders: Paul Clark
* Date: 2026

## Context

The wrapped-DEK manifest can live in one of two places:

1. **In-band**: a reserved table or page inside the SQLCipher database
   itself, decrypted along with everything else.
2. **Sidecar**: a separate `.pqsm` file living next to the `.db`.

Both options are workable; the choice has secondary consequences for
substitution resistance, observability, and ecosystem fit.

## Decision

The manifest is a **sidecar** file, `database.db.pqsm`, with the
format defined in `docs/SPEC.md`.

To prevent the substitution attack a separable sidecar would otherwise
enable (drop the sidecar from database A on top of database B, both
encrypted to the same recipient: open succeeds, you read someone
else's data), the manifest is **bound to the SQLCipher salt** — the
first 16 bytes of the database file, written by SQLCipher in
plaintext at creation, preserved across `sqlite3_rekey`. The salt is
part of the signed payload; a verifier reads it from the actual
database file and refuses a manifest whose `database-salt` does not
match (threat-model A4).

## Consequences

**Positive:**
- Matches the existing `.pqfe` precedent in `PostQuantum.FileFormat`.
  Tooling generalises.
- A pre-keying step can read the manifest *before* opening SQLCipher,
  which means trust-pin checks, algorithm-id checks, and signature
  verification all happen before any DEK material is materialised.
- Inspection tooling can read the manifest without ever needing the
  database key.
- Manifest rewrites (adding a recipient, rotating, etc.) do not
  rewrite the database file. Sharing scales without re-encrypting
  pages.

**Negative:**
- Two-file operational unit: backup and restore must move them
  together. Documented in `docs/THREAT-MODEL.md` §5.5.
- The salt-binding mechanism is a load-bearing detail that does not
  exist in the in-band alternative. We cover it in the spec, but it
  is one more thing a reader has to understand.

## Revisiting

Reopen if SQLCipher's salt handling changes (e.g., a future SQLCipher
version that allows salt rotation independent of `sqlite3_rekey`).
The binding mechanism would have to be re-derived; the sidecar choice
itself probably still holds.

## Related

- [`docs/SPEC.md`](../SPEC.md) §1 (overview), §7 (database binding).
- [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) A4 (manifest transplant),
  §5.5 (denial of service via sidecar deletion).
