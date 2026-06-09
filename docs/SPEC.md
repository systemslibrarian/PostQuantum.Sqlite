# PostQuantum.Sqlite Manifest Specification (`.pqsm`), Version 1

Status: **Draft** (pre-1.0 — the format may change until the package reaches 1.0.0)

This document specifies the `.pqsm` sidecar manifest format precisely enough
for an independent implementation. Normative keywords MUST / MUST NOT /
SHOULD follow RFC 2119.

## 1. Overview

A `.pqsm` manifest accompanies a SQLCipher-encrypted SQLite database file:

```
mydata.db        SQLCipher database (AES-256, raw 32-byte DEK)
mydata.db.pqsm   manifest: per-recipient wrapped copies of the DEK,
                 signed, salt-bound, revision-counted
```

The manifest answers exactly one question: **who may obtain the DEK, and on
whose authority.** It does not participate in page encryption.

## 2. Encoding

The manifest is a single CBOR (RFC 8949) document in **canonical encoding**:

- Definite lengths only. Indefinite-length items MUST be rejected.
- Map keys MUST be sorted per canonical CBOR ordering and MUST be unique.
- Parsers MUST reject trailing bytes after the document.
- Parsers MUST operate as a **whitelist**: unknown fields, duplicate fields,
  wrong CBOR types, and out-of-spec lengths are hard failures. Version 1 has
  no extension mechanism by design.

## 3. Top-level structure

A CBOR map with **exactly 7 entries (unsigned form) or 8 entries (signed
form)**, integer keys:

| Key | Name | CBOR type | Constraint |
|---|---|---|---|
| 1 | `version` | uint | MUST be `1` |
| 2 | `kem-algorithm-id` | tstr | length 1..64, e.g. `"ML-KEM-768"` |
| 3 | `signature-algorithm-id` | tstr | length 1..64, e.g. `"ML-DSA-65"` |
| 4 | `database-salt` | bstr | exactly 16 bytes |
| 5 | `recipients` | array | 1..1024 recipient maps (§4) |
| 6 | `signer-public-key` | bstr | exact public-key length of the declared signature algorithm (ML-DSA-65: 1952) |
| 7 | `revision` | uint | ≥ 1; monotonic, incremented on every mutation |
| 8 | `signature` | bstr | exact signature length of the declared algorithm (ML-DSA-65: 3309); present only in the signed form |

`database-salt` is the SQLCipher salt: the first 16 bytes of the database
file, which SQLCipher stores in plaintext. It binds the manifest to exactly
one database file (§7).

Verifiers MUST additionally check `signer-public-key` and per-recipient KEM
ciphertext lengths against the *declared* algorithms, and MUST refuse
manifests whose declared algorithms differ from the verifier's configuration.

## 4. Recipient entry

A CBOR map with integer keys. **KEM recipients have exactly keys 1–5;
passphrase recipients have exactly keys 1–7.** Any other combination MUST be
rejected.

| Key | Name | CBOR type | Constraint |
|---|---|---|---|
| 1 | `type` | uint | `1` = KEM, `2` = passphrase; all other values rejected |
| 2 | `fingerprint` | bstr | exactly 16 bytes (§5) |
| 3 | `kem-ciphertext` / `kdf-salt` | bstr | KEM: exact ciphertext length of the declared KEM (ML-KEM-768: 1088). Passphrase: exactly 32 bytes |
| 4 | `nonce` | bstr | exactly 12 bytes (AES-GCM) |
| 5 | `wrapped-dek` | bstr | exactly 48 bytes: 32-byte AES-GCM ciphertext ‖ 16-byte tag |
| 6 | `kdf-id` | tstr | length 1..64, e.g. `"PBKDF2-SHA512"`, `"Argon2id"` (passphrase only) |
| 7 | `kdf-parameters` | bstr | length 1..1024; KDF-specific CBOR. A KDF with no parameters MUST encode an empty CBOR map (`0xA0`) (passphrase only) |

Duplicate recipient fingerprints within one manifest MUST be rejected.

## 5. Fingerprints

```
fingerprint = SHA-256(input)[0..16)
```

- KEM recipients: `input` = the recipient's encapsulation (public) key bytes.
- Passphrase recipients: `input` = the 32-byte `kdf-salt`.

Fingerprints identify recipients; they are NOT sufficient to re-wrap a DEK
(re-encapsulation requires the full encapsulation key).

## 6. Key derivation and DEK wrapping

The DEK is 32 random bytes, used as the SQLCipher **raw key**.

KEM shared secrets and password-KDF outputs are never used directly as AES
keys. The key-encryption key (KEK) is:

```
KEK = HKDF-SHA256(
    ikm  = KEM shared secret            (KEM recipients)
           | password-KDF output         (passphrase recipients),
    salt = database-salt (16 bytes),
    L    = 32,
    info = "PostQuantum.Sqlite/kek" || 0x00
           || version as int32 big-endian || 0x00
           || algorithm-id (UTF-8)        || 0x00
           || fingerprint (16 bytes)
)
```

where `algorithm-id` is the KEM algorithm id (key 2) for KEM recipients and
the `kdf-id` (recipient key 6) for passphrase recipients.

The DEK is wrapped with AES-256-GCM:

```
wrapped-dek = AES-256-GCM-Encrypt(
    key   = KEK,
    nonce = 12 random bytes (recipient key 4),
    aad   = database-salt || fingerprint,
    pt    = DEK
)  // output: ciphertext (32) || tag (16)
```

The AAD prevents transplanting a wrapped DEK between databases or between
recipients: any such move fails tag verification.

## 7. Signing and database binding

The **signed payload** is the canonical CBOR encoding of the top-level map
containing exactly keys 1–7 (i.e. the manifest without its signature entry).
The signature (key 8) is computed over those bytes with the declared
signature algorithm.

Verification MUST, in order:

1. Strict-parse the manifest (§2–§4).
2. Enforce declared algorithm ids match the verifier's configuration.
3. Enforce algorithm-exact lengths (signer key, signature, KEM ciphertexts).
4. **Trust pinning:** compare `signer-public-key` byte-for-byte against the
   verifier's pinned trust anchor. A manifest MUST NOT be trusted merely
   because it verifies under its own embedded key — that is self-attestation.
   (Unpinned verification is permissible only for inspection tooling.)
5. Read the first 16 bytes of the database file and compare with
   `database-salt`. Mismatch = manifest substitution; reject.
6. Verify the signature over the signed payload.

## 8. Revision counter and rollback

`revision` starts at 1 and MUST be incremented by every mutation (recipient
add, rotation, revocation). It is covered by the signature.

A signature proves authenticity, not freshness: an attacker with filesystem
access can restore an older validly-signed manifest together with the
matching older database. **Rollback is undetectable without out-of-band
state.** Applications requiring rollback detection MUST track the last known
revision externally and reject manifests with a lower value.

## 9. Atomic writes and crash-safe rotation

All manifest writes MUST be atomic: write to a temporary file in the same
directory, flush to durable storage, then rename over the target.

DEK rotation (which re-encrypts every database page via `sqlite3_rekey`)
MUST follow this protocol:

```
1. Build and sign the post-rotation manifest (revision + 1, new DEK
   wrapped to surviving recipients).
2. Durably write it to <db>.pqsm.pending.
3. Rekey the database (old DEK -> new DEK). On failure: delete the
   pending file; the primary manifest still matches the database.
4. Atomically rename <db>.pqsm.pending over <db>.pqsm.
```

Readers MUST implement recovery: if the primary manifest's DEK fails the
database key check and a pending manifest exists, verify and try the pending
manifest; on success, promote it (atomic rename). If the primary succeeds
while a pending file exists, the pending file is stale (crash before step 3)
and MUST be deleted. `sqlite3_rekey` preserves the file salt, so the binding
value (§7) is stable across rotation.

Passphrase entries cannot be re-wrapped during rotation (the KDF requires
the passphrase, which implementations rightly never store); they are dropped
and MUST be re-added explicitly.

## 10. Default algorithms (version 1)

| Role | Algorithm | Reference |
|---|---|---|
| KEM | ML-KEM-768 | FIPS 203 |
| Signature | ML-DSA-65 | FIPS 204 |
| KEK derivation | HKDF-SHA256 | RFC 5869 |
| DEK wrap | AES-256-GCM | SP 800-38D |
| Passphrase KDF (default) | PBKDF2-HMAC-SHA512 | SP 800-132 |
| Page encryption (out of scope) | SQLCipher AES-256-CBC + HMAC | SQLCipher docs |

Other algorithms (e.g. X-Wing hybrid KEM, Argon2id) may be used; the manifest
records their identifiers and verifiers refuse mismatches.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
