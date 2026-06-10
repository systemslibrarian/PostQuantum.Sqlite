# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-09

First release. The package, the documentation that proves it works,
and the infrastructure that proves a release is what it claims to be.

### Added — library

- `PqSqliteVault` with the full key-lifecycle surface: `Create`,
  `Open`, `AddRecipient`, `AddPassphraseRecipient`, `RotateDek`,
  `RemoveRecipientAndRotate`, and the deliberately-ugly
  `CreateUnpinned` read-only escape hatch.
- ML-KEM-768 + ML-DSA-65 defaults via the .NET 10 BCL; pluggable
  `IKemAlgorithm`, `ISignatureAlgorithm`, and `IPasswordKdf` so
  X-Wing hybrid KEM, Argon2id, and similar can drop in without
  touching the library.
- Strict v1 canonical-CBOR `.pqsm` manifest with signed
  database-salt binding, monotonic revision counter, and per-
  algorithm length enforcement.
- Crash-safe rotation via `.pqsm.pending` write-promote protocol
  with recovery on the next `Open`.
- Passphrase recipients with a PBKDF2-SHA512 default (600k
  iterations) and pluggable KDF for Argon2id et al.
- `KemRecipient.Fingerprint` cached on first access instead of
  recomputing SHA-256 on every reference.
- `Pbkdf2PasswordKdf.DeriveKey` encodes the passphrase directly to a
  zeroable byte buffer; no non-zeroable `char[]` copy.

### Added — assurance

- 36 tests in `PostQuantum.Sqlite.Tests` covering happy paths,
  tampering, salt-binding, trust-pinning, mismatched signing keys,
  malicious CBOR (unknown fields, duplicates, wrong lengths,
  non-canonical encoding, trailing bytes), crash-safe rotation
  recovery, mismatched KDF rejection, rollback detection, four new
  fault-injection scenarios (corrupted pending, both-corrupted,
  cross-DB pending substitution, leftover tmp files), and a
  data-driven vector runner.
- Official test-vector corpus under
  `tests/PostQuantum.Sqlite.Tests/Vectors/`: one positive vector
  (full reader pipeline byte-for-byte) plus six negative vectors,
  one per mandatory parser-rejection rule, with `manifest.json`
  describing each. `docs/test-vectors.md` is the conformance recipe
  for independent implementations.
- `fuzz/PostQuantum.Sqlite.Fuzz/` SharpFuzz harness over
  `PqSqliteManifest.Deserialize` with a round-trip identity check
  on accepted inputs. Seed corpus bootstrapped from the test
  vectors. `fuzz/README.md` covers setup, AFL launch, and triage.
- `bench/PostQuantum.Sqlite.Bench/` BenchmarkDotNet suite covering
  the headline operations at three database sizes so the linear
  cost of `sqlite3_rekey` is visible alongside the constant-time
  crypto cost.

### Added — documentation

- `docs/SPEC.md` — normative manifest format (canonical CBOR,
  whitelist fields, exact-length enforcement, sign-and-bind
  protocol).
- `docs/THREAT-MODEL.md` — assets, trust anchors, in-scope attacks
  (A1–A11), and explicit residual-risk section.
- `docs/OPERATIONS.md` — deployment and incident-response guide
  (pre-flight, signer custody, out-of-band revision tracking,
  backup/restore as a unit, recipient lifecycle, four incident
  runbooks, footguns to avoid).
- `docs/REPRODUCIBLE-BUILDS.md` — how a third party rebuilds a tag
  from source and verifies SHA-256 + build-provenance attestation.
- `docs/test-vectors.md` — interop corpus layout, the eight-step
  positive conformance procedure, and rule-to-vector mapping.
- `docs/RELEASE-CHECKLIST.md` — human steps the release workflow
  can't do.
- `docs/ROADMAP.md` — explicit 1.0 criteria across format/API
  stability, external assurance, interoperability, release trust,
  platform proof, and operator guidance.
- `docs/decisions/` — ADRs 0001 (pinned trust anchor), 0002
  (sidecar manifest), 0003 (revocation always rotates), 0004
  (strict v1, no extensions).
- README "Quick start", "Trust model", "Threat model", "Platform
  support", "Building", "When NOT to use this", "Operations",
  "Maturity", and "Design decisions" sections; links to every
  doc above.

### Added — supply-chain trust

- `global.json` pinning .NET 10.0.300 SDK.
- `Directory.Build.props` with shared TFM/LangVersion/Nullable/
  ImplicitUsings/AnalysisLevel/EnforceCodeStyleInBuild/Deterministic
  properties.
- `.editorconfig` C# style baseline (file-scoped namespaces,
  `_camelCase` private fields, sorted usings).
- `.github/workflows/ci.yml` — restore, build, test, pack on
  `ubuntu-latest` and `windows-latest`. Linux builds OpenSSL 3.5
  from source (cached) because .NET 10's BCL ML-KEM/ML-DSA require
  FIPS 203/204 support that landed in OpenSSL 3.5. Opt-in to
  Node.js 24 actions via `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`.
  Vulnerable-package audit (`dotnet list package --vulnerable
  --include-transitive`) gates the build.
- `.github/workflows/codeql.yml` — CodeQL `security-and-quality`
  query pack on push, PR, and weekly cron.
- `.github/workflows/release.yml` — tag-triggered. Verifies tag
  matches csproj `<Version>`, runs the full vuln-audit + build +
  test + reproducible pack, computes SHA-256, attests build
  provenance via `actions/attest-build-provenance` (OIDC-signed
  in-toto attestation), extracts release notes from the matching
  CHANGELOG section, and publishes a GitHub Release with .nupkg,
  .snupkg, and SHA256SUMS.txt attached. NuGet publish is
  intentionally out-of-band.
- `.github/dependabot.yml` weekly NuGet + GitHub Actions updates
  with grouped analyzers / test-runner bumps.
- SourceLink (`Microsoft.SourceLink.GitHub`) + symbol package
  (`.snupkg`) on the library NuGet.
- `Microsoft.CodeAnalysis.PublicApiAnalyzers` with the current
  public surface snapshotted in `PublicAPI.Shipped.txt` (119
  entries). Public-API drift fails CI.

### Added — maintainer ops

- `CONTRIBUTING.md` with scope rules, style baseline, and PR
  expectations tied to threat model + spec.
- `.github/CODEOWNERS` requiring explicit review on spec, threat
  model, security policy, manifest/vault source, and workflows.
- Issue templates (bug, feature) with security-advisory link;
  pull-request template requiring threat-model and compatibility
  sections.

### Changed

- `SqlCipherInterop.OpenWithRawKey` appends `Pooling=False` to the
  connection string. Default Microsoft.Data.Sqlite pooling kept
  the SQLCipher-keyed handle alive after `Dispose()`, blocking
  tests with file-share violations on Windows AND opening a
  security gap where the next pool consumer would inherit a
  pre-authenticated database.
- `SqlCipherInterop.ReadDatabaseSalt` opens with
  `FileShare.ReadWrite | Delete` so the salt read works while the
  just-created `SqliteConnection` still holds the file on Windows.
- Library csproj no longer suppresses CS1591; every public surface
  carries XML docs (47 previously-undocumented members
  documented).
- `samples/QuickStart` walks the entire headline arc (create,
  share, second-party open, passphrase break-glass, scheduled
  rotation, revocation, rollback detection) against a temp dir
  that cleans itself up.

### Fixed

- `PqSqliteVault` constructor and `Open` overload XML docs added
  the missing `<param>` tags (build was failing CS1573 under
  TreatWarningsAsErrors + GenerateDocumentationFile).

### Security

- Trust pinning via constructor anchor; mutating operations prove
  the supplied signing key corresponds to the pin before re-signing
  (random-challenge sign/verify).
- Manifest salt-binding: signed `database-salt` is checked
  byte-for-byte against the file's actual first 16 bytes on every
  read. Manifest transplant fails.
- Wrapped-DEK AAD = `salt || fingerprint`; transplanting a wrapped
  entry between manifests or recipients fails GCM tag verification.
- Strict v1 parser with whitelist fields, exact-length enforcement,
  bounded variable-length fields, and explicit duplicate-fingerprint
  rejection. No extension mechanism by design.

### Known limitations

- macOS is not currently runnable. .NET 10's macOS build delegates
  `System.Security.Cryptography` to Apple's Security framework, not
  OpenSSL; Security framework does not yet implement ML-KEM /
  ML-DSA. The README platform matrix calls this out explicitly.
- Rollback without out-of-band state is undetectable by design (a
  sidecar-file scheme cannot enforce freshness). The signed
  monotonic `Revision` counter is the detection hook; applications
  must persist it externally and pass `expectedMinimumRevision`
  to `Open`.
- This package has NOT received an independent security audit or a
  sustained fuzzing campaign — see `docs/ROADMAP.md` for the 1.0
  criteria around external assurance.

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.Sqlite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/systemslibrarian/PostQuantum.Sqlite/releases/tag/v0.1.0
