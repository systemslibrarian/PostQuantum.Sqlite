# Operations Guide

How to deploy, maintain, and respond to incidents in a system built on
`PostQuantum.SqlCipher.Vault`. The package gives you safe primitives; this
document is the part that decides whether they stay safe in
production.

## 1. Pre-flight: things that MUST be true before you deploy

- [ ] Your application constructs `PqSqlCipherVault` with a **pinned**
      trust anchor (see ADR [0001](decisions/0001-pinned-trust-anchor.md)).
      `PqSqlCipherVault.CreateUnpinned()` MUST NOT appear in any
      production code path. Add a test that fails the build if it does.
- [ ] You have a documented place where the **signer private key**
      lives — HSM, OS keystore, KMS, or `PostQuantum.KeyManagement`.
      Plain config files, environment variables, and committed
      secrets are all wrong answers.
- [ ] You have a documented place where the **out-of-band revision
      counter** is persisted (§3 below) — and the application
      consults it on `Open`.
- [ ] You have a backup procedure that treats `<db>.db` and
      `<db>.db.pqsm` as a **single unit** (§4 below). Restoring one
      without the other yields an unopenable database; restoring an
      old pair is a rollback an attacker can exploit.
- [ ] You have documented who responds to a suspected key compromise,
      and how (§6 below).

## 2. Signer key custody

The signer private key is the trust anchor for every database your
application touches. Whoever holds it can mint manifests that your
application will trust unconditionally.

### Where it should live

| Option | Notes |
|---|---|
| HSM / TPM | First choice when available. Key never leaves the device. |
| OS keystore (Windows DPAPI, macOS Keychain, Linux Secret Service) | Acceptable for single-machine deployments. |
| Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) | First choice for fleet deployments. Key access is audited. |
| [`PostQuantum.KeyManagement`](https://github.com/systemslibrarian/PostQuantum.KeyManagement) | Designed as a peer package to this one. |

### Where it MUST NOT live

- Plain config files committed to source control.
- Environment variables on shared / multi-tenant infrastructure.
- Files inside the application's installed package (anyone with read
  access to the install can extract it).

### Operational practice

- Restrict who can read the signer private key to the smallest
  possible audience. For most deployments this is one or two
  operators, not the application's runtime user.
- Audit access. If your custody layer doesn't produce audit logs,
  fix that layer first; don't paper over it here.
- Rotating the signer key requires updating the pinned trust anchor
  in every consumer of the package, then re-signing every manifest
  under the new key. There is no fast path. Build that procedure
  before you need it.

## 3. Out-of-band revision tracking (rollback detection)

The signed monotonic `Revision` counter on every manifest is the only
way an application can tell an old, validly-signed manifest from a
fresh one. The library cannot do this itself — both files live on
the same filesystem an attacker may control.

### The protocol

1. After every mutating call (`Create`, `AddRecipient`,
   `AddPassphraseRecipient`, `RotateDek`, `RemoveRecipientAndRotate`),
   read `PqSqlCipherManifest.Load(dbPath).Revision` and persist it
   somewhere the attacker cannot rewind.
2. On every `Open`, pass that persisted value as
   `expectedMinimumRevision`. The vault refuses any manifest below
   that floor.

### Where the counter should live

| Option | Notes |
|---|---|
| Server-side record per device | Strongest. Attacker would have to compromise the server too. |
| HSM/TPM-sealed value | Strong on single-device deployments. |
| App config in a file the user runs as administrator and the application runs unprivileged | Acceptable but enforce file ACLs. |

### Pitfalls

- The counter is **only** rollback detection; it does not detect a
  current attacker. An attacker who controls both files AND your
  out-of-band store can roll back undetected. The threat model
  (§5.1 of `THREAT-MODEL.md`) is honest about this.
- A counter that gets reset on application reinstall is worthless.
  Persist it through the same mechanism you persist user data, not
  application state.

## 4. Backup and restore

`<db>.db` and `<db>.db.pqsm` are **one unit**. Treat them like a
relational backup of a database + its transaction log:

- Back them up in a single atomic operation.
- Restore them together.
- Verify after restore by calling `vault.Open(...)` with the
  recipient key and the recorded `expectedMinimumRevision`. If
  `Open` succeeds AND the manifest revision is at least the
  recorded value, the restore is consistent.

### A note on `.pending`

If `<db>.db.pqsm.pending` exists on disk during backup, **include it
too**. It's the crash-recovery anchor for an interrupted rotation
(see SPEC §9). A backup that drops it can leave the database
unopenable.

A backup that includes both `.pqsm` and `.pqsm.pending` is safe:
restore will trigger the recovery flow on the next `Open` and
promote the pending manifest if appropriate.

## 5. Recipient lifecycle

### Onboarding a new device

1. Generate an ML-KEM-768 keypair on the new device (the private key
   never leaves the device).
2. Ship the public (encapsulation) key to a device that already has
   write authority.
3. That device calls `vault.AddRecipient(...)` with the new public key.
4. Record the new manifest revision.

### Retiring a device

1. Call `vault.RemoveRecipientAndRotate(...)` from an authorised
   device.
   The DEK is rotated automatically — see ADR
   [0003](decisions/0003-revocation-always-rotates.md) for why
   removal without rotation is unsafe.
2. Record the new manifest revision.
3. Re-add any passphrase recipients (they are dropped by rotation
   per SPEC §9).

### Break-glass passphrase

Passphrase recipients are the weakest path by construction
(THREAT-MODEL §5.4). Use them as a **last-resort recovery** path,
not as primary access:

- Generate a long random passphrase (≥ 80 bits of entropy). Print it
  on paper and store it physically.
- Pair it with a strong KDF — see the `IPasswordKdf` interface; prefer
  Argon2id over the PBKDF2 default in production.
- Re-add the passphrase recipient after every rotation that drops it.

## 6. Incident response

### Compromised recipient key

A recipient's device is lost or its private key is suspected stolen.

1. From any other authorised device, call
   `vault.RemoveRecipientAndRotate(...)` with the compromised
   recipient's fingerprint. The DEK is rotated; the compromised
   key can no longer decrypt the live database.
2. Record the new manifest revision.
3. The compromised key may still decrypt **historical backups** that
   predate the rotation. Decide if those need to be re-encrypted
   under the new DEK; if yes, restore each old backup, re-key the
   database with the new DEK (round-trip through SQLCipher), and
   re-store.

### Compromised signer (trust anchor) private key

The signer private key is the trust anchor. Compromise is a
**critical** incident.

1. Immediately rotate the signer keypair and update the pinned trust
   anchor in every consumer of the package.
2. Re-sign every active manifest under the new signer.
3. Audit every manifest issued during the window the old signer was
   compromised. Any recipient added during that window is suspect.
4. Inform downstream consumers; their cached "this database is
   trustworthy" assumption was based on the now-compromised key.

There is no automated recovery path for a signer compromise. Build
the procedure before you need it.

### Suspected manifest tampering

If `vault.Open` throws with a signature-verification or
trust-anchor-pin error, the manifest has been altered or substituted.

1. Do not "fix it up" in place — preserve the bad manifest as
   evidence.
2. Restore the last known-good `(db, sidecar)` pair from backup.
3. Open with `expectedMinimumRevision` set to your last recorded
   value; if even the backup is below that floor, the rollback
   predates your last good backup and you need to investigate
   further.

### Suspected page-level database tampering

Page-level tampering is detected by SQLCipher's per-page HMAC — `Open`
will surface it as a key-check failure. The mitigation is the same as
manifest tampering: restore from backup.

## 7. Metrics worth tracking

Operations get easier when you can answer the questions below from
metrics, not by reading logs after an incident.

| Metric | Why |
|---|---|
| Number of recipients per database | A growing count without a corresponding offboarding flow is a slow leak of authority. |
| Manifest revision lag (out-of-band counter vs on-disk) | Should always be zero. A non-zero value means a write happened that wasn't recorded out-of-band — investigate. |
| Time-since-last-rotation | Long-lived DEKs amplify the cost of any compromise. Decide a rotation cadence and alert when it's exceeded. |
| `Open` failures by reason (signature, trust-pin, key-check, revision) | Each reason has a different incident response. Separate them in your dashboards. |
| Backup recency for both `.db` and `.pqsm` | If they diverge, your atomic-pair invariant has slipped. |

## 8. Things that look like features but are footguns

- **Lowering PBKDF2 iterations because passphrase recovery feels
  slow.** The iteration count is the only thing standing between an
  attacker with the sidecar and the DEK. Don't.
- **Caching the DEK across processes.** The library never does this;
  `Pooling=False` is set on the SQLCipher connection string for the
  same reason (ADR
  [0001](decisions/0001-pinned-trust-anchor.md) refs Push A's
  pooling fix). If you build your own cache, you are reintroducing
  the same bug.
- **Using the unpinned vault "just for inspection" in production
  code.** It is deliberately ugly because production code is
  exactly where it must not appear.
- **Sharing one signer key across many applications.** Every
  application that pins it implicitly trusts every other. Use
  per-application signers.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
