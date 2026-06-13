# Benchmarks

[BenchmarkDotNet](https://benchmarkdotnet.org/) suite covering the headline
operations of `PqSqlCipherVault`. Lives outside `PostQuantum.SqlCipher.Vault.sln` so
the main CI build stays fast; run it explicitly when you care about
performance numbers.

## What is measured

| Benchmark | What it captures |
|---|---|
| `Create` | Random DEK, ML-KEM-768 encapsulation, HKDF-SHA256 KEK, AES-GCM wrap, ML-DSA-65 sign, atomic manifest write, SQLCipher database creation. |
| `Open` | Strict manifest parse, signature verify, salt-binding check, KEM decapsulate, HKDF-SHA256, AES-GCM unwrap, SQLCipher key check. |
| `AddRecipient` | Manifest-only mutation: encapsulate to the new recipient, re-sign, atomic replace. No database rewrite. |
| `RotateDek` | Generates a new DEK, durably writes pending manifest, `sqlite3_rekey` (rewrites every page), atomic promote. Linear in DB size. |
| `RemoveRecipientAndRotate` | `AddRecipient` then `RemoveRecipientAndRotate`. Combined cost of revocation. |

Each benchmark runs at three database sizes (`Rows` = 0, 1_000, 10_000)
so the linear cost of `sqlite3_rekey` over real pages is visible
alongside the constant-time crypto cost.

## Running

```bash
# All benchmarks (long; ~10 min depending on CPU).
dotnet run -c Release --project bench/PostQuantum.SqlCipher.Vault.Bench

# Subset by filter.
dotnet run -c Release --project bench/PostQuantum.SqlCipher.Vault.Bench -- --filter "*Create*"
dotnet run -c Release --project bench/PostQuantum.SqlCipher.Vault.Bench -- --filter "*Rotate*"

# List available benchmarks without running them.
dotnet run -c Release --project bench/PostQuantum.SqlCipher.Vault.Bench -- --list flat
```

Output (markdown table + memory diagnoser) lands in
`bench/PostQuantum.SqlCipher.Vault.Bench/BenchmarkDotNet.Artifacts/results/`.

## Methodology notes

- `[ShortRunJob]` keeps the suite under ~10 minutes for fast iteration.
  For numbers worth publishing, switch to the default job
  (longer warmup + measurement) by editing `VaultBenchmarks.cs`.
- KEM and signature keypair generation runs once in `[GlobalSetup]` so
  the randomized cost doesn't leak into per-iteration measurements.
- Each iteration writes to a fresh temp DB and cleans up afterwards,
  so the OS page cache state is the only confound.
- `[MemoryDiagnoser]` reports allocations per op — useful for spotting
  regressions where a refactor introduces a defensive copy.

## When to re-run

- Before a release if any code path in `PqSqlCipherVault` or
  `PqSqlCipherManifest` changed.
- When considering an algorithm swap (e.g. X-Wing hybrid KEM via
  `IKemAlgorithm`, Argon2id via `IPasswordKdf`).
- After upgrading `Microsoft.Data.Sqlite` or
  `SQLitePCLRaw.bundle_e_sqlcipher` — both can shift the cost basis
  meaningfully.

## Publishing benchmark results

The 1.0 criteria in `docs/ROADMAP.md` require performance numbers to be
published before release. The intended deliverable is a
`docs/PERFORMANCE.md` with results from a documented hardware and SDK
configuration; this is operational follow-up, not part of every CI run.
