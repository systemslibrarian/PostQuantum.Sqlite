# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `global.json` pinning the .NET 10.0.300 SDK with `rollForward: latestFeature`.
- `Directory.Build.props` with shared properties (TFM, Nullable,
  ImplicitUsings, `EnforceCodeStyleInBuild`, deterministic build).
- `.editorconfig` with C# style baseline (file-scoped namespaces,
  `_camelCase` private fields, sorted usings).
- GitHub Actions CI workflow (`.github/workflows/ci.yml`) that builds and
  tests on `windows-latest` and `ubuntu-latest`, builds OpenSSL 3.5 from
  source on Linux (cached) so .NET 10 ML-KEM/ML-DSA work, uploads `trx`
  test results, and packs the NuGet artifact.
- SourceLink + symbol package (`.snupkg`) generation for the NuGet package.
- README "Platform support" section documenting the OpenSSL 3.5
  requirement on Linux and macOS.
- `CHANGELOG.md` (this file).

### Changed
- `QuickStart` sample now walks every headline feature end-to-end
  (create, share, open as second party, passphrase break-glass,
  scheduled DEK rotation, revocation with auto-rotation, rollback
  detection), runs against a temp directory with cleanup so re-runs
  are idempotent, and narrates each step.
- `KemRecipient.Fingerprint` is now cached on first access instead of
  recomputing SHA-256 on every reference.
- `Pbkdf2PasswordKdf.DeriveKey` encodes the passphrase directly to a
  zeroable byte buffer; the previous `passphrase.ToArray()` route
  allocated a `char[]` copy that the GC could never zero.

### Fixed
- `SqlCipherInterop.OpenWithRawKey` appends `Pooling=False` to the
  connection string. The default Microsoft.Data.Sqlite pooling kept the
  SQLCipher-keyed handle alive after `Dispose()`, blocking all tests
  with file-share violations on Windows AND opening a security gap
  where the next pool consumer would inherit a pre-authenticated
  database belonging to a different caller.
- `SqlCipherInterop.ReadDatabaseSalt` opens with
  `FileShare.ReadWrite | Delete` so the salt read works while the
  just-created `SqliteConnection` still holds the file on Windows.
- Added missing `<param>` XML doc tags on the `PqSqliteVault`
  constructor and `Open` overloads (the build was failing CS1573
  under `TreatWarningsAsErrors` + `GenerateDocumentationFile`).

## [0.1.0] - Initial baseline

Initial source drop:

- `PqSqliteVault` with create / open / share / revoke-and-rotate /
  rotate flows.
- ML-KEM-768 + ML-DSA-65 defaults; pluggable `IKemAlgorithm`,
  `ISignatureAlgorithm`, and `IPasswordKdf` for X-Wing, hybrid,
  Argon2id, etc.
- Strict v1 canonical-CBOR `.pqsm` manifest with signed salt binding
  and monotonic revision counter.
- Crash-safe rotation via `.pqsm.pending` recovery.
- Passphrase recipients with PBKDF2-SHA512 default and
  Argon2id-pluggable KDF.
- 25 tests covering happy paths, malicious CBOR, crash recovery,
  trust pinning, and rollback detection.

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.Sqlite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/systemslibrarian/PostQuantum.Sqlite/releases/tag/v0.1.0
