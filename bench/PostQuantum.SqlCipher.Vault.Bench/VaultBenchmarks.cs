using BenchmarkDotNet.Attributes;
using Microsoft.Data.Sqlite;
using PostQuantum.SqlCipher.Vault;
using PostQuantum.SqlCipher.Vault.Algorithms;

namespace PostQuantum.SqlCipher.Vault.Bench;

[MemoryDiagnoser]
[ShortRunJob]
public class VaultBenchmarks
{
    private byte[] _aliceEk;
    private byte[] _aliceDk;
    private byte[] _signPk;
    private byte[] _signSk;
    private PqSqlCipherVault _vault;
    private string _workDir;
    private string _dbPath;

    /// <summary>
    /// Pre-populated row count for the database used by Open / Rotate / Revoke
    /// benchmarks. Captures the linear cost of `sqlite3_rekey` over real pages.
    /// </summary>
    [Params(0, 1_000, 10_000)]
    public int Rows;

    [GlobalSetup]
    public void GlobalSetup()
    {
        // KEM and signature key generation is randomized but stable across
        // iterations once captured here.
        (_aliceEk, _aliceDk) = MlKem768Kem.GenerateKeyPair();
        (_signPk,  _signSk)  = MlDsa65Signer.GenerateKeyPair();
        _vault = new PqSqlCipherVault(_signPk);
        _workDir = Directory.CreateTempSubdirectory("pqsqlite-bench").FullName;
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        try { Directory.Delete(_workDir, recursive: true); } catch { /* best effort */ }
    }

    [IterationSetup(Target = nameof(Create))]
    public void IterationSetup_Create()
    {
        _dbPath = Path.Combine(_workDir, "bench-" + Guid.NewGuid().ToString("N") + ".db");
    }

    [IterationCleanup(Target = nameof(Create))]
    public void IterationCleanup_Create()
    {
        TryDelete(_dbPath);
        TryDelete(PqSqlCipherManifest.SidecarPathFor(_dbPath));
    }

    [Benchmark(Description = "Create empty DB + signed manifest")]
    public void Create()
    {
        using var conn = _vault.Create(_dbPath, new[] { new KemRecipient(_aliceEk) }, _signSk);
    }

    // ── Benchmarks that need a pre-populated DB ───────────────────────────

    [IterationSetup(Targets = new[] {
        nameof(Open),
        nameof(AddRecipient),
        nameof(RotateDek),
        nameof(RemoveRecipientAndRotate),
    })]
    public void IterationSetup_Existing()
    {
        _dbPath = Path.Combine(_workDir, "bench-" + Guid.NewGuid().ToString("N") + ".db");
        using var conn = _vault.Create(_dbPath, new[] { new KemRecipient(_aliceEk) }, _signSk);
        if (Rows > 0) PopulateRows(conn, Rows);
    }

    [IterationCleanup(Targets = new[] {
        nameof(Open),
        nameof(AddRecipient),
        nameof(RotateDek),
        nameof(RemoveRecipientAndRotate),
    })]
    public void IterationCleanup_Existing()
    {
        TryDelete(_dbPath);
        TryDelete(PqSqlCipherManifest.SidecarPathFor(_dbPath));
        TryDelete(PqSqlCipherManifest.PendingSidecarPathFor(_dbPath));
    }

    [Benchmark(Description = "Open existing DB by recipient key")]
    public void Open()
    {
        using var conn = _vault.Open(_dbPath, _aliceDk, _aliceEk);
    }

    [Benchmark(Description = "AddRecipient (manifest-only)")]
    public void AddRecipient()
    {
        var (bobEk, _) = MlKem768Kem.GenerateKeyPair();
        _vault.AddRecipient(_dbPath, new KemRecipient(bobEk), _aliceDk, _aliceEk, _signSk);
    }

    [Benchmark(Description = "RotateDek (sqlite3_rekey + sign)")]
    public void RotateDek()
    {
        _vault.RotateDek(_dbPath, _aliceDk, _aliceEk, _signSk);
    }

    [Benchmark(Description = "RemoveRecipientAndRotate (rewrite all pages)")]
    public void RemoveRecipientAndRotate()
    {
        var (bobEk, _) = MlKem768Kem.GenerateKeyPair();
        _vault.AddRecipient(_dbPath, new KemRecipient(bobEk), _aliceDk, _aliceEk, _signSk);
        _vault.RemoveRecipientAndRotate(_dbPath, new KemRecipient(bobEk).Fingerprint,
                                        _aliceDk, _aliceEk, _signSk);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static void PopulateRows(SqliteConnection conn, int rows)
    {
        using var tx = conn.BeginTransaction();
        using (var ddl = conn.CreateCommand())
        {
            ddl.CommandText = "CREATE TABLE IF NOT EXISTS bench (id INTEGER PRIMARY KEY, payload BLOB);";
            ddl.ExecuteNonQuery();
        }
        using var insert = conn.CreateCommand();
        insert.CommandText = "INSERT INTO bench (payload) VALUES (zeroblob(512));";
        for (int i = 0; i < rows; i++) insert.ExecuteNonQuery();
        tx.Commit();
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best effort */ }
    }
}
