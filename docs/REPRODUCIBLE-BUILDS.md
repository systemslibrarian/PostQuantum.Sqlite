# Reproducible Builds

A third party should be able to rebuild any released `PostQuantum.SqlCipher.Vault`
NuGet package from the source at the tagged commit and get a byte-equal
artifact (modulo timestamps embedded by NuGet itself, which we normalise
below). This document is how.

## What we do

The library project sets:

```xml
<Deterministic>true</Deterministic>
<ContinuousIntegrationBuild Condition="'$(GITHUB_ACTIONS)' == 'true'">true</ContinuousIntegrationBuild>
```

`Deterministic=true` normalises embedded PDB paths, GUIDs, and MVIDs.
`ContinuousIntegrationBuild=true` (set automatically in CI, and pinned
explicitly by both `ci.yml` and `release.yml`) makes the compiler embed
relative repo paths instead of absolute build-machine paths.

SourceLink (`Microsoft.SourceLink.GitHub`) embeds a GitHub URL plus the
exact commit SHA in the PDB so that anyone with the `.nupkg` can step
into the source from a debugger without a side-loaded checkout — and
the embedded SHA proves which source revision was built.

## Verifying a release

The recipe below assumes you have the .NET SDK pinned in
[`global.json`](../global.json), and on Linux/macOS, OpenSSL ≥ 3.5
available (FIPS 203/204 provider). See README "Platform support".

```bash
# 1. Pick a tag.
VERSION=0.1.0
TAG=v${VERSION}

# 2. Clone the repo at exactly that tag.
git clone --depth 1 --branch "$TAG" https://github.com/systemslibrarian/PostQuantum.SqlCipher.Vault
cd PostQuantum.SqlCipher.Vault

# 3. Restore and build under the same flags CI uses.
dotnet restore PostQuantum.SqlCipher.Vault.sln
dotnet build PostQuantum.SqlCipher.Vault.sln -c Release --no-restore \
    -p:ContinuousIntegrationBuild=true

# 4. Pack reproducibly.
dotnet pack src/PostQuantum.SqlCipher.Vault/PostQuantum.SqlCipher.Vault.csproj \
    -c Release --no-build -p:ContinuousIntegrationBuild=true \
    --output artifacts

# 5. Compute the SHA-256 and compare against the value in the GitHub Release notes.
sha256sum "artifacts/PostQuantum.SqlCipher.Vault.${VERSION}.nupkg"
```

The GitHub Release page for the tag publishes the SHA-256 we computed at
release time (under "SHA-256") alongside a build-provenance attestation.

## Verifying the provenance attestation

The release workflow signs an in-toto attestation that this commit, on
this workflow, built that artifact. Verify with the GitHub CLI:

```bash
gh attestation verify "artifacts/PostQuantum.SqlCipher.Vault.${VERSION}.nupkg" \
    --owner systemslibrarian
```

A successful verification proves:
- The artifact bytes match what GitHub's signing service signed.
- The workflow that built it is the one in the `.github/workflows/`
  directory at the tagged commit.
- The build ran in the GitHub Actions infrastructure under the
  expected job identity.

## Things that legitimately differ

- **Package timestamps.** `dotnet pack` records the pack time in the
  `.nuspec`. The included content (DLL, PDB, README, license, etc.) is
  byte-stable; the outer ZIP timestamps are not. To compare the
  payloads directly, expand the `.nupkg` (it is a ZIP) and hash the
  contained files.
- **Symbol package (`.snupkg`).** Same caveat. Stable content,
  unstable ZIP metadata.
- **Different SDK feature versions.** `global.json` uses
  `rollForward: latestFeature`, so a future SDK in the same major.minor
  band may be picked up. For exact reproduction, install the SDK
  version in the `version` field literally.

If you reproduce the build and the **contents** differ in any way that
is not on the list above, please open an issue — that is a
reproducibility bug we want to fix.

## Why this matters

The release workflow that produces the artifact runs on hosted
infrastructure. The attestation proves an artifact came from a specific
workflow + commit; the reproducible build proves the *commit itself*
produces that artifact. Together they let a third party trust the
release without trusting the maintainer's local machine.
