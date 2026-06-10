# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI matrix now includes `macos-latest` alongside Ubuntu and Windows.
  Uses the same OpenSSL 3.5 source-build recipe (cached) adapted to
  macOS lib paths and `DYLD_LIBRARY_PATH`/`DYLD_FALLBACK_LIBRARY_PATH`.
  README platform matrix promoted macOS from ⚠️ to ✅.

### Added
- `fuzz/PostQuantum.Sqlite.Fuzz/` — a SharpFuzz (2.2.0) AFL harness
  pointed at `PqSqliteManifest.Deserialize` with a round-trip identity
  check on accepted inputs. `PqSqliteException` is treated as a
  rejection success; any other exception is a finding.
- `fuzz/corpus/` seeded from the official test vectors so a fresh
  campaign has both positive and adversarial starting points without
  any setup.
- `fuzz/README.md` with the one-time setup (SharpFuzz.CommandLine
  tool install + instrumentation), the AFL launch command, and the
  triage flow for moving a crash into the negative test-vector
  corpus once a fix lands.
- `.gitignore` now keeps `fuzz/findings/` and the instrumented bin
  out of the repo while explicitly including `fuzz/corpus/**`
  (the seed corpus is shipped intentionally).

### Added
- Official test-vector corpus under
  `tests/PostQuantum.Sqlite.Tests/Vectors/`:
  - One positive vector (`kem-single-recipient`) with the bytes of
    `.pqsm`, recipient encap/decap keys, signer public key, database
    salt, and the expected unwrapped DEK — enough for an independent
    implementation to validate end-to-end (parse, signature verify,
    fingerprint match, decapsulate, HKDF-KEK, AES-GCM unwrap).
  - Six negative vectors covering the spec's mandatory parser
    rejections: unknown top-level field, duplicate recipient key,
    non-canonical ordering, trailing bytes, truncated nonce, wrong
    salt length.
  - `manifest.json` index keyed by name with `expectedErrorContains`
    substrings for each negative case.
- `tests/PostQuantum.Sqlite.Tests/VectorTests.cs` runs the corpus
  every CI build, so any divergence between code and shipped vectors
  fails CI immediately. A skipped `VectorGenerator` lives alongside
  for maintainer regeneration.
- `docs/test-vectors.md` documents the corpus layout, the eight-step
  positive conformance procedure, and the rejection rules each
  negative vector exercises — the spec piece that lets an outsider
  build a compatible implementation.
- README now links the test-vectors doc next to the spec and threat
  model.

### Added (continued)
- `Microsoft.CodeAnalysis.PublicApiAnalyzers` with a snapshot of the
  current public surface in `PublicAPI.Shipped.txt` (119 entries).
  Any unintentional public-API change now fails the build (RS0016 /
  RS0017); intentional changes land in `PublicAPI.Unshipped.txt` and
  graduate at release time.
- XML documentation comments on every public type, constant, field,
  property, and method that was missing one (47 unique members), so
  the suppression of CS1591 can be removed and the generated XML
  docs are useful to NuGet consumers.

### Changed
- The library csproj no longer suppresses CS1591 ("missing XML
  comment"). Every public surface is now documented or fails CI.

- Tag-triggered release workflow (`.github/workflows/release.yml`)
  that verifies the tag matches `<Version>` in the csproj, runs the
  full vuln-audit + build + test + reproducible pack, computes
  SHA-256 over the artifacts, attests build provenance via
  `actions/attest-build-provenance`, extracts release notes from the
  matching `CHANGELOG.md` section, and publishes a GitHub Release
  with the `.nupkg`, `.snupkg`, and `SHA256SUMS.txt` attached.
  NuGet publish is intentionally out-of-band (see RELEASE-CHECKLIST).
- `docs/REPRODUCIBLE-BUILDS.md` documenting how a third party rebuilds
  a tagged release from source and verifies both the SHA-256 and the
  build-provenance attestation. README links it from the Building
  section.
- Dependabot config (`.github/dependabot.yml`) watching GitHub Actions
  and the two NuGet csproj roots on a weekly cadence, with grouped
  updates for analyzers and the xUnit runner.
- CodeQL workflow (`.github/workflows/codeql.yml`) running the
  `security-and-quality` query pack against C# on push, PR, and a
  weekly cron.
- CI now gates on `dotnet list package --vulnerable --include-transitive`,
  so any known-CVE direct or transitive NuGet dependency fails the build
  the next time CI runs.
- Maintainer ops package: `CONTRIBUTING.md`, `.github/CODEOWNERS`,
  bug-report and feature-request issue templates with security-advisory
  link in `config.yml`, pull-request template, `docs/RELEASE-CHECKLIST.md`,
  `docs/ROADMAP.md` (explicit 1.0 criteria), and ADRs 0001–0004 covering
  the pinned trust anchor, sidecar manifest, revocation-always-rotates,
  and strict-v1-no-extensions design decisions.
- CI workflow exports `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` so the
  upcoming 2026-06-16 Node.js 24 default flip doesn't change behavior
  underneath us.
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
