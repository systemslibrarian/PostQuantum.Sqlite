# PostQuantum.Sqlite

**Post-quantum key management for SQLCipher SQLite databases.**

> SQLCipher protects the database pages.
> PostQuantum.Sqlite protects the database **key lifecycle**:
> ML-KEM recipient wrapping, ML-DSA manifest signing, signer pinning,
> safe sharing, revocation, rotation, and recovery.
>
> This package does not replace SQLCipher. It adds a signed, post-quantum
> recipient manifest around it.

## "SQLCipher already encrypts my database. Why do I need this?"

Because **SQLCipher has one key and no opinion about who holds it.** The
moment you have two devices, two people, a break-glass recovery path, or a
revocation event, you are hand-rolling key management — and that is where
encrypted-database projects actually get hurt. This package gives you:

- **Sharing** — wrap the database key to multiple recipients, each under
  their own ML-KEM-768 key pair; adding a recipient never rewrites the DB.
- **Authority** — an ML-DSA-65–signed manifest, pinned to one trusted signer
  key, decides who the recipients are. Tampering, substitution, and
  self-signed manifests fail loudly.
- **Revocation that means it** — removing a recipient always rotates the
  key and re-encrypts every page; the old key becomes useless.
- **Recovery** — crash-safe rotation, atomic manifest writes, optional
  break-glass passphrase recipients, rollback detection hooks.

And the quantum part: AES-256 page encryption is already quantum-resistant
(Grover only halves it), but any RSA/ECDH key wrapping is fully broken by
Shor — and *harvest-now-decrypt-later* means wrapped keys captured today are
decrypted retroactively. This package's key lifecycle uses ML-KEM-768
(FIPS 203) and ML-DSA-65 (FIPS 204) from the .NET 10 BCL, with
HKDF-SHA256–separated wrapping keys. The key management is the reason to
install it today; the post-quantum layer is why it stays installed.

## Two different layers — be precise about which one you're trusting

| Layer | What protects it | Quantum status |
|---|---|---|
| **Page encryption** (every byte in the `.db` file) | SQLCipher: AES-256-CBC + per-page HMAC | ✅ Already resistant (Grover-only) — *not changed by this package* |
| **DEK wrapping** | **ML-KEM-768** → **HKDF-SHA256** → AES-256-GCM | ✅ Provided by this package |
| **Multi-recipient sharing** | One wrapped-DEK manifest entry per recipient | ✅ Provided by this package |
| **Key authority** | **ML-DSA-65** signature + **constructor-pinned signer** | ✅ Provided by this package |
| **Passphrase recovery** | PBKDF2-SHA512 default / pluggable Argon2id → HKDF | ➖ Symmetric break-glass path |

## Architecture

```
mydata.db        ← SQLCipher database, AES-256, random 32-byte DEK
mydata.db.pqsm   ← strict canonical-CBOR manifest (sidecar):
                     • DEK wrapped per recipient: ML-KEM-768 → HKDF-SHA256 KEK → AES-256-GCM
                     • bound to the DB via its SQLCipher salt (anti-substitution)
                     • monotonic signed revision counter (rollback detection hook)
                     • signed with ML-DSA-65, pinned to ONE trusted signer
```

Full format details: [`docs/SPEC.md`](docs/SPEC.md).
Full security analysis: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Quick start

```csharp
using PostQuantum.Sqlite;
using PostQuantum.Sqlite.Algorithms;

var (aliceEk, aliceDk) = MlKem768Kem.GenerateKeyPair();
var (signPk, signSk)   = MlDsa65Signer.GenerateKeyPair();

// The vault is constructed around ONE trusted signer key — the trust
// anchor, distributed with your application like a root certificate.
var vault = new PqSqliteVault(trustedSignerPublicKey: signPk);

// Create — random DEK, wrapped to Alice, manifest signed at revision 1
using var conn = vault.Create("mydata.db", new[] { new KemRecipient(aliceEk) }, signSk);

// Open — verifies signature, trust pin, and database binding automatically
using var conn2 = vault.Open("mydata.db", aliceDk, aliceEk);

// Share — manifest-only (atomic replace); the database file is not rewritten
vault.AddRecipient("mydata.db", new KemRecipient(bobEk), aliceDk, aliceEk, signSk);

// Revoke — removes the entry AND rotates the DEK (crash-safe rekey)
vault.RemoveRecipientAndRotate("mydata.db", bobFingerprint, aliceDk, aliceEk, signSk);
```

## Trust model — pinning is not optional

- **The constructor takes the trust anchor.** Every operation — reads
  included — refuses manifests signed by any other key. A manifest is never
  trusted merely because it verifies under its own embedded signer; that is
  self-attestation, and any attacker-authored manifest has it too.
- **Mutations prove key correspondence.** Before re-signing, the supplied
  signing private key is proven (random-challenge sign/verify) to match the
  pinned anchor — a wrong key cannot silently change the trust root.
- **`PqSqliteVault.CreateUnpinned()` exists and is deliberately ugly.** It
  is read-only (all mutating operations throw), accepts any
  internally-consistent manifest, and is intended for inspection tooling
  only. If it appears on a production data path, that is a bug in your
  application.

## Threat model — explicit limitations

The full analysis lives in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md);
the honest summary:

- **Rollback** of both files to an older validly-signed state is
  *undetectable without out-of-band state*. The signed monotonic `Revision`
  counter is the detection hook: track it externally and pass
  `expectedMinimumRevision` to `Open`.
- **Memory:** DEKs/KEKs/secrets are zeroized and keys are applied via native
  `sqlite3_key` with a zeroable buffer (never an immutable hex string), but
  SQLCipher retains internal key material while a connection is open, and
  the GC may copy arrays. Memory-dump attackers are out of scope.
- **Metadata** (recipient count, fingerprints, algorithm ids, revision) is
  visible in the sidecar.
- **Passphrases** are the weakest path; prefer an Argon2id `IPasswordKdf`
  over the PBKDF2 default, and treat them as break-glass recovery.

## Maturity

This package has **not** received an independent security audit, fuzzing
campaign, or formal review. It implements NIST-final algorithms (FIPS
203/204) via the .NET 10 BCL and follows the engineering practices in
`docs/SPEC.md`, with 25 tests covering malicious-input and crash-recovery
cases — but "carefully engineered" and "audited" are different claims, and
you should know which one you're getting. Suitable for evaluation,
prototypes, side projects, and applications whose threat model tolerates
that maturity level.

## Design decisions (and their reasoning)

- **Sidecar manifest, not in-band** — matches the `.pqfe` precedent
  (PostQuantum.FileFormat); the salt binding closes the substitution gap a
  separable sidecar would otherwise open.
- **Sign the manifest + salt, not the database content** — runtime page
  integrity is SQLCipher's per-page HMAC job; the manifest signature
  protects the *key authority* layer.
- **Revocation always rotates** — removal without rotation is security
  theater, so the API doesn't offer it.
- **Strict v1 parser, no extensions** — a security manifest format must
  never be forgiving about input it didn't write. Extensions can come in v2.
- **Pluggable algorithms with declared sizes** — `IKemAlgorithm` /
  `ISignatureAlgorithm` expose exact sizes so every field is
  length-validated *before* any cryptography runs. X-Wing hybrid drops in
  via `IKemAlgorithm`; the manifest records the id and the vault refuses
  mismatches.

## Building

```bash
dotnet build PostQuantum.Sqlite.sln
dotnet test
dotnet pack src/PostQuantum.Sqlite -c Release
```

Requires the .NET 10 SDK (LTS; BCL ML-KEM / ML-DSA). Native SQLCipher is
supplied by `SQLitePCLRaw.bundle_e_sqlcipher` — no system install needed.

## License

MIT — see [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
