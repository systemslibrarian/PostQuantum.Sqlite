# Contributing

Thank you for considering a contribution. This is a small, focused
security library; the bar is high and the rules are few.

## Before you start

**Security vulnerabilities:** **do not open a public issue.** Follow
[`SECURITY.md`](SECURITY.md) — report privately via GitHub Security
Advisories.

**Anything else:** open an issue first if you intend to send a non-trivial
PR. Bugs and security-adjacent observations are welcome unconditionally;
new features need a "is this in scope?" conversation before code.

## Scope rules of thumb

This package owns one thing: the **key lifecycle** around SQLCipher.
Recipient sharing, ML-KEM wrapping, ML-DSA-signed manifests, revocation,
rotation, and recovery. It is deliberately not:

- A SQLCipher replacement, wrapper, or fork.
- A general-purpose PQC abstraction layer.
- A key-management service. (See `PostQuantum.KeyManagement` for that.)

If you are unsure whether something is in scope, open an issue and ask.

## What "good" looks like

| Trait | What it means here |
|---|---|
| Strict by default | Parsing, lengths, algorithm ids, and trust pinning all reject on mismatch. We do not "be lenient" about anything we did not produce. |
| Honest about residual risk | If your change moves a guarantee, update [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) in the same PR. Code and threat model stay in sync. |
| Reasoned, not exhaustive | New tests should exercise *failure modes that matter* — tampering, transplant, crash recovery, malicious input — not just "happy path with another value." |
| Specced before extended | New manifest fields, new recipient types, and any wire-format change must land in [`docs/SPEC.md`](docs/SPEC.md) first, with negative cases. |

## Local development

```bash
dotnet restore PostQuantum.Sqlite.sln
dotnet build PostQuantum.Sqlite.sln -c Release
dotnet test PostQuantum.Sqlite.sln -c Release
dotnet run --project samples/QuickStart -c Release
```

Requirements:

- .NET 10 SDK as pinned in [`global.json`](global.json).
- Linux/macOS: OpenSSL ≥ 3.5 (FIPS 203/204 provider). See "Platform
  support" in [`README.md`](README.md) — the CI workflow at
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml) is a
  copy-pasteable recipe.

The library treats `TreatWarningsAsErrors=true` and
`GenerateDocumentationFile=true` as load-bearing. If you touch the public
surface, you will be writing `<param>`/`<returns>` tags.

## Pull requests

Keep PRs focused. One commit per logical change is preferred; squash on
merge is fine. A PR should explain:

- **What** changed (briefly — the diff already says this).
- **Why** the change was needed (the motivation that does not survive in
  the diff).
- **Threat-model implications**, if any. If none: say so explicitly.
- **Test coverage** for new behavior and (for security-relevant changes)
  for the failure mode the change defends against.

If your PR touches the manifest format, it must update
[`docs/SPEC.md`](docs/SPEC.md) and [`CHANGELOG.md`](CHANGELOG.md), and
include a test vector showing a parser must reject the bad input.

## Style

Style is enforced by [`.editorconfig`](.editorconfig) and code analysis
(`EnforceCodeStyleInBuild=true`). Run `dotnet format` if your editor
hasn't already.

## License

By contributing you agree your changes are licensed under the
[MIT license](LICENSE) that covers the rest of the project.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
