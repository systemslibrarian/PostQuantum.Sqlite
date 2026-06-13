# PostQuantum.SqlCipher.Vault Threat Model

Status: living document. If an attack works and isn't listed here, that is a
reportable bug (see SECURITY.md) — either in the code or in this document.

## 1. The one-sentence scope statement

> SQLCipher encrypts the database pages. PostQuantum.SqlCipher.Vault protects the
> database **key lifecycle**: recipient sharing, post-quantum key wrapping,
> manifest signing, revocation, and rotation.

This package does not replace, modify, or strengthen SQLCipher's AES-256
page encryption, which is already quantum-resistant (Grover's algorithm
reduces AES-256 to ~128 effective bits — still infeasible). The quantum
threat (Shor's algorithm) applies to the **asymmetric** layer — how keys are
wrapped, shared, and signed — and that, plus the classical key-management
problem, is the layer this package owns.

## 2. Assets

| Asset | Where it lives | Protection |
|---|---|---|
| DEK (32-byte raw database key) | wrapped in manifest entries; transiently in process memory | ML-KEM-768 → HKDF-SHA256 → AES-256-GCM; zeroized after use |
| Database contents | `.db` file | SQLCipher (out of scope) |
| Key authority (who may share/revoke/rotate) | manifest signature + trust anchor | ML-DSA-65 + constructor-pinned signer key |
| Recipient set | manifest | signed; mutations require the trust anchor's private key |
| Signing private key | caller's key store | **out of scope** — its compromise defeats the authority layer |
| Recipient decapsulation keys | callers' key stores | **out of scope** — each one's compromise exposes the DEK to that holder |

## 3. Trust anchors

1. **The pinned signer public key** — supplied to the `PqSqlCipherVault`
   constructor and distributed with the application like a root certificate.
   Every operation refuses manifests signed by any other key. The unpinned
   escape hatch is read-only and intended for inspection tooling.
2. **The SQLCipher salt** — first 16 bytes of the database file, plaintext,
   written once at creation, preserved by `sqlite3_rekey`. Binds each
   manifest to exactly one database file.

## 4. Adversaries and attacks — in scope

| # | Attack | Defense |
|---|---|---|
| A1 | **Harvest-now-decrypt-later**: record wrapped DEKs today, decrypt with a future quantum computer | DEK wrapping uses ML-KEM-768 (FIPS 203); no RSA/ECDH anywhere in the lifecycle |
| A2 | **Manifest tampering** (modify recipients, swap wrapped keys) | ML-DSA-65 signature over the canonical payload; any bit flip fails verification |
| A3 | **Manifest substitution** (attacker-authored manifest, self-signed) | Trust pinning: signer key compared byte-for-byte against the constructor anchor. Self-attestation is never sufficient |
| A4 | **Manifest transplant** (valid manifest from database A presented with database B) | Salt binding: signed `database-salt` must equal the file's actual first 16 bytes |
| A5 | **Wrapped-DEK transplant** (move a wrapped entry between manifests or recipients) | AES-GCM AAD = salt ‖ fingerprint; tag verification fails on any move |
| A6 | **Trust-anchor swap via re-sign** (trick a mutating operation into re-signing under a different key) | Mutations prove the supplied private key corresponds to the pin (random-challenge sign/verify) before re-signing |
| A7 | **Malicious manifest input** (unknown fields, duplicates, type confusion, length abuse, non-canonical encoding, trailing data) | Strict whitelist parser; all are hard rejections; variable fields bounded (DoS) |
| A8 | **Algorithm confusion** (declare a different KEM/signature/KDF than the verifier expects) | Algorithm ids are signed, checked against the vault's configuration, and lengths are enforced per-algorithm; passphrase opens refuse KDF-id mismatches |
| A9 | **Revoked-recipient retention** (removed recipient kept the old DEK or old manifest) | Revocation always rotates: `sqlite3_rekey` rewrites every page under a fresh DEK; the old DEK becomes useless |
| A10 | **Crash during rotation** (DB rekeyed but manifest stale → lockout) | Pending-manifest protocol: post-rotation manifest durably written before rekey; readers recover and promote it; stale pendings cleaned up |
| A11 | **Rollback** (replay an older validly-signed manifest + matching DB copy, e.g. resurrecting a revoked recipient) | Signed monotonic revision counter + `expectedMinimumRevision`. **Detection requires out-of-band revision tracking — see §5.1** |

## 5. Explicit limitations — residual risk

Honesty about residual exposure is part of the security design.

### 5.1 Rollback without out-of-band state
A signature proves authenticity, not freshness. An attacker with write access
to both files can restore an older, internally-valid (manifest, database)
pair. The revision counter makes this *detectable* — but only if the
application stores the last known revision somewhere the attacker cannot
roll back (app config, registry, KMS metadata, server). Without that,
rollback is **undetectable by design** in any sidecar-file scheme.

### 5.2 Key material in process memory
DEKs, KEKs, and shared secrets are zeroized after use. Keys are applied via
the native `sqlite3_key`/`sqlite3_rekey` entry points using a zeroable byte
buffer — never an immutable managed string (a `PRAGMA key = "x'…'"` command
string would pin the hex key in managed memory until GC, unzeroizable).
Residual exposure remains: SQLCipher necessarily retains derived key
material internally while a connection is open, and the .NET GC may copy
arrays before zeroization. **An attacker with code execution or memory-dump
capability on the host while the database is open is out of scope.**

### 5.3 Metadata
File sizes, recipient count, recipient fingerprints, algorithm identifiers,
and the revision counter are visible to anyone who can read the sidecar.
Fingerprints are stable identifiers and can be correlated across databases.

### 5.4 Passphrase recipients
The weakest path by construction: strength is bounded by the passphrase.
The PBKDF2-SHA512 default (600k iterations) is a BCL-only convenience;
production passphrase recipients SHOULD use a memory-hard KDF (Argon2id)
via `IPasswordKdf`. Passphrases gain nothing from the PQ layer — document
them to users as break-glass recovery, not primary access.

### 5.5 Denial of service
Deleting or corrupting the sidecar (or the database) makes the database
unopenable. That is what backups are for; the package bounds parsing costs
but cannot prevent file deletion.

### 5.6 Side channels
Default algorithm implementations delegate to the .NET 10 BCL (ML-KEM,
ML-DSA, AES-GCM, HKDF). Constant-time behavior is inherited from, and
bounded by, the BCL and SQLCipher implementations.

## 6. Deployment requirements (what the application MUST do)

1. **Pin the signer.** Construct `PqSqlCipherVault` with the trusted signer
   public key, distributed with the application. Never use the unpinned
   vault on a production data path.
2. **Protect the signing private key** — HSM, OS keystore, or
   PostQuantum.KeyManagement. Its compromise transfers full key authority.
3. **Track the revision out-of-band** and pass `expectedMinimumRevision`
   to `Open` if rollback matters for your threat model.
4. **Back up database and sidecar together** — they are a unit.
5. **Re-add passphrase recipients after rotation** — they are dropped by
   design (the library never stores passphrases).

---

*Soli Deo Gloria — 1 Corinthians 10:31*
