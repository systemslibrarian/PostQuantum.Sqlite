# Fuzzing PostQuantum.Sqlite

The [`PostQuantum.Sqlite.Fuzz`](PostQuantum.Sqlite.Fuzz/) project is a
SharpFuzz harness pointed at `PqSqliteManifest.Deserialize` — the strict
CBOR parser every reader, signer, and verifier funnels untrusted bytes
through.

A `PqSqliteException` is a **success** signal (parser rejected
malformed input). Any other exception or crash is a real finding.

## Requirements

- Linux (afl-fuzz works best here).
- `afl-fuzz` (Debian/Ubuntu: `sudo apt install afl++`).
- .NET 10 SDK as pinned by `global.json`.
- OpenSSL ≥ 3.5 on `LD_LIBRARY_PATH` (same constraint as the rest of
  the repo on Linux — see the README "Platform support" section).

## One-time setup

```bash
# Install the SharpFuzz instrumentation CLI globally.
dotnet tool install --global SharpFuzz.CommandLine

# Build the harness.
dotnet build fuzz/PostQuantum.Sqlite.Fuzz -c Release

# Instrument the assemblies SharpFuzz needs to track for coverage.
# We instrument the library DLL — the harness DLL doesn't need it.
sharpfuzz fuzz/PostQuantum.Sqlite.Fuzz/bin/Release/net10.0/PostQuantum.Sqlite.dll
```

The first `sharpfuzz` invocation rewrites the IL of the library DLL in
place. To revert, rebuild.

## Running a campaign

```bash
afl-fuzz \
    -i fuzz/corpus \
    -o fuzz/findings \
    -- dotnet fuzz/PostQuantum.Sqlite.Fuzz/bin/Release/net10.0/PostQuantum.Sqlite.Fuzz.dll
```

The seed corpus in `fuzz/corpus/` is bootstrapped from the official
test vectors — one positive manifest and the six committed negative
cases. New corpus inputs that AFL discovers go into `fuzz/findings/`
(gitignored).

A useful first benchmark: leave the campaign running overnight. Even a
small CPU budget (a few hours on one core) usually surfaces the first
class of bugs.

## Triaging findings

When AFL finds a crash, it writes the input bytes to
`fuzz/findings/default/crashes/`. Reproduce locally:

```bash
dotnet run -c Release \
    --project fuzz/PostQuantum.Sqlite.Fuzz \
    < fuzz/findings/default/crashes/<crash-id>
```

If the harness exits cleanly, you have a flake. Otherwise, the stack
trace identifies the rule the parser should have enforced. Add the
crashing bytes to the negative corpus
([`docs/test-vectors.md`](../docs/test-vectors.md)) with the rule it
exercises, fix the parser, and re-run the campaign.

## CI integration (deferred)

This repository ships the infrastructure but does NOT yet run
continuous fuzzing in CI. The `docs/ROADMAP.md` 1.0 criteria require a
sustained campaign (≥ 1 CPU-month with no unresolved findings) before
the format is frozen; that runs on dedicated infrastructure, not on
the per-PR runner.

A short smoke-fuzz step (e.g. 60s per PR) is a reasonable interim — add
it to `.github/workflows/ci.yml` when there is a maintained AFL toolchain
on the runner image.

## See also

- [`docs/SPEC.md`](../docs/SPEC.md) — the parser's rejection rules.
- [`docs/test-vectors.md`](../docs/test-vectors.md) — the curated
  negative corpus that started as fuzz findings or hand-derived rule
  exercises.
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — 1.0 fuzzing criteria.
