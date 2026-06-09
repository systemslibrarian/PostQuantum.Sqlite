<!--
Thanks for the PR.

Security vulnerabilities go through GitHub Security Advisories, not PRs.
If this PR is a vulnerability fix coordinated under an advisory, link it
in the description and request review privately.
-->

## What

<!-- One-paragraph description. The diff says what; this says why-this-shape. -->

## Why

<!-- The motivation that does NOT survive in the diff. What incident, requirement,
     or design choice forced this change? -->

## Threat-model implications

<!-- Required. Pick one and write a sentence per the case that applies:
     - "None." (and explain briefly why you're confident)
     - "Updates docs/THREAT-MODEL.md to record …"
     - "Closes attack Ax from docs/THREAT-MODEL.md by …" -->

## Compatibility

<!-- Required for any change to:
       - Public API surface (src/PostQuantum.Sqlite/Abstractions, PqSqliteVault, PqSqliteManifest)
       - Manifest format or signed payload
       - Wire-level behavior (atomic writes, pending recovery, salt binding)
     If none: "None — internal change." -->

## Test coverage

<!-- New behavior → at least one happy-path test. Security-relevant change →
     at least one negative test that exercises the failure mode you defend against. -->

## Checklist

- [ ] `dotnet build -c Release`: 0 warnings, 0 errors.
- [ ] `dotnet test -c Release`: all passing.
- [ ] For manifest changes: `docs/SPEC.md` updated and at least one negative test vector added.
- [ ] For threat-model changes: `docs/THREAT-MODEL.md` updated.
- [ ] For user-visible changes: `CHANGELOG.md` updated under `[Unreleased]`.
- [ ] Public API additions/removals reflected in `PublicAPI.Unshipped.txt`.
