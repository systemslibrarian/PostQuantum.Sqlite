# Release Checklist

Pre-1.0 releases are cut from `main` after the checklist below clears. The
release workflow (`.github/workflows/release.yml`, triggered by a `v*` tag)
handles the mechanical steps; this checklist captures the human ones.

## Pre-flight

- [ ] `main` is green on CI (Windows and Linux) for the candidate SHA.
- [ ] No open security advisories awaiting fix-in-this-release.
- [ ] `CHANGELOG.md` `[Unreleased]` section reflects every user-visible
      change since the last tag and is dated today.
- [ ] `Version` in `src/PostQuantum.SqlCipher.Vault/PostQuantum.SqlCipher.Vault.csproj`
      matches the tag to be pushed.
- [ ] `PublicAPI.Unshipped.txt` is empty (everything moved to `Shipped.txt`).
- [ ] `docs/SPEC.md` version line matches the manifest version this
      package writes, and no `version` bump landed since the last release
      without a documented migration note.
- [ ] `docs/THREAT-MODEL.md` reflects current code (no "TODO before
      release" markers).

## Cut the release

- [ ] Update `CHANGELOG.md`: rename `[Unreleased]` to the new version
      with today's date; add a new empty `[Unreleased]` section at the top
      for the next cycle.
- [ ] Commit the changelog/version bump on `main`; PR through CI.
- [ ] Tag the resulting merge commit: `git tag v<version>` with a signed
      tag (`-s`) when possible; push the tag.
- [ ] The `release.yml` workflow runs:
      build → test → pack (reproducible) → attest build provenance →
      create GitHub Release with notes pulled from the new CHANGELOG
      section → attach `.nupkg` + `.snupkg` artifacts.

## After the release

- [ ] Verify the GitHub Release page shows the build provenance
      attestation and both artifact files.
- [ ] Verify the NuGet feed shows the new version (and SourceLink is
      walkable from a sample debugger session).
- [ ] Compute and publish the SHA-256 of the `.nupkg` in the release notes
      (the workflow does this automatically; sanity-check it).
- [ ] Close the milestone, if any.
- [ ] Open follow-up issues for anything intentionally deferred.

## Hot-fix releases

Hot-fix releases for the latest minor only (pre-1.0: latest version only —
see `SECURITY.md`). Same checklist; cherry-pick from `main` onto a
`release/v<x.y>` branch if `main` has already moved on.

## When NOT to cut a release

- The change introduces a manifest-format break and the migration story
  hasn't been written.
- A vulnerability fix is in flight and dropping a release without it
  would push users onto a known-bad version for a longer window.
- Public API churn has not yet been ratified in `PublicAPI.Shipped.txt`.
