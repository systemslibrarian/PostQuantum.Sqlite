# PostQuantum.SqlCipher.Vault

**Post-quantum key management for SQLCipher SQLite databases.**

> SQLCipher protects the database pages.
> PostQuantum.SqlCipher.Vault protects the database **key lifecycle**:
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
Conformance test vectors for independent implementations: [`docs/test-vectors.md`](docs/test-vectors.md).
Fuzzing infrastructure: [`fuzz/README.md`](fuzz/README.md).
Performance benchmarks: [`bench/README.md`](bench/README.md).

## Quick start

```csharp
using PostQuantum.SqlCipher.Vault;
using PostQuantum.SqlCipher.Vault.Algorithms;

var (aliceEk, aliceDk) = MlKem768Kem.GenerateKeyPair();
var (signPk, signSk)   = MlDsa65Signer.GenerateKeyPair();

// The vault is constructed around ONE trusted signer key — the trust
// anchor, distributed with your application like a root certificate.
var vault = new PqSqlCipherVault(trustedSignerPublicKey: signPk);

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
- **`PqSqlCipherVault.CreateUnpinned()` exists and is deliberately ugly.** It
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

## When NOT to use this

Not every application benefits from a post-quantum signed key
manifest. Skip this package if any of these apply:

- **You don't share the database.** A single-process desktop app
  whose one user holds the only key is not the use case this
  package was built for. Plain SQLCipher with the user's passphrase
  is enough; the manifest adds operational complexity for no
  authority gain.
- **Access control already lives somewhere else.** If your app is a
  web server fronting a SQLite database and authorisation runs at
  the HTTP layer, the manifest's recipient-set is a parallel
  authority model you have to keep in sync with the primary one.
  Two sources of truth for who can read what is a foot-gun.
- **Your threat model genuinely tolerates RSA/ECDH key wrapping.**
  Harvest-now-decrypt-later only matters if (a) an attacker can
  capture wrapped keys today and (b) the wrapped keys protect data
  that's still sensitive when a capable quantum computer arrives.
  Short-lived session caches don't qualify.
- **You need a key-management service**, not a key-lifecycle library.
  See [`PostQuantum.KeyManagement`](https://github.com/systemslibrarian/PostQuantum.KeyManagement);
  this package is a deliberately narrow piece of that picture.
- **You're targeting macOS only.** .NET 10 on Darwin does not yet
  implement ML-KEM (see the [platform support](#platform-support)
  matrix). The library will refuse to construct a vault at runtime.
  Wait for upstream support before designing it in.
- **You can't tolerate the deployment requirements** in
  [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — particularly
  out-of-band revision tracking and pinned-signer trust custody.
  Those requirements are load-bearing; the package is not
  meaningfully useful without them.

If you read the list and none of it applies, this is the right tool.

## Operations

[`docs/OPERATIONS.md`](docs/OPERATIONS.md) is the deployment guide:
signer custody, out-of-band revision tracking, backup/restore as a
single unit, recipient lifecycle, and incident response for
compromised keys and tampered manifests. Read it before you ship.

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
dotnet build PostQuantum.SqlCipher.Vault.sln
dotnet test
dotnet pack src/PostQuantum.SqlCipher.Vault -c Release
```

Requires the .NET 10 SDK (LTS; BCL ML-KEM / ML-DSA). Native SQLCipher is
supplied by `SQLitePCLRaw.bundle_e_sqlcipher` — no system install needed.

Releases are reproducible from source and ship a signed build-provenance
attestation. See [`docs/REPRODUCIBLE-BUILDS.md`](docs/REPRODUCIBLE-BUILDS.md)
for the verification recipe.

## Platform support

| Platform | Status |
|---|---|
| Windows (CNG / SymCrypt) | ✅ Works on .NET 10.0.300+; CI covers `windows-latest`. |
| Linux | ✅ Requires **OpenSSL ≥ 3.5** — FIPS 203 / 204 support landed there. Ubuntu 24.04 LTS ships 3.0.x, so you must install 3.5+ side-by-side and put it on `LD_LIBRARY_PATH`. CI builds 3.5 from source on `ubuntu-latest`; the workflow in `.github/workflows/ci.yml` is a copy-pasteable recipe. |
| macOS | ❌ **Not currently runnable.** .NET 10's macOS build delegates `System.Security.Cryptography` to Apple's Security framework rather than to OpenSSL, and Security framework does not yet implement ML-KEM / ML-DSA. `MLKem.IsSupported` returns `false` on Darwin regardless of which OpenSSL is installed. We track this as a hard blocker; macOS will return to CI when either Apple ships FIPS 203/204 in Security framework or .NET adds an explicit OpenSSL fallback on Darwin. |

The dependency is upstream of this package: .NET 10's BCL `MLKem` / `MLDsa`
classes throw `PlatformNotSupportedException` when the underlying provider
can't find FIPS 203 / 204 — there is no way for a managed library to
polyfill that.

## License

MIT — see [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
