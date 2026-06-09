using Microsoft.Data.Sqlite;
using PostQuantum.Sqlite;
using PostQuantum.Sqlite.Algorithms;
using Xunit;

namespace PostQuantum.Sqlite.Tests;

public class VaultLifecycleTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("pqsqlite-tests").FullName;
    private string DbPath => Path.Combine(_dir, "test.db");

    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ } }

    private static (byte[] ek, byte[] dk) Kem() => MlKem768Kem.GenerateKeyPair();
    private static (byte[] pk, byte[] sk) Sig() => MlDsa65Signer.GenerateKeyPair();

    [Fact]
    public void Create_Then_Open_RoundTrips_Data()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);

        using (var conn = vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk))
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT); INSERT INTO notes (body) VALUES ('soli deo gloria');";
            cmd.ExecuteNonQuery();
        }

        using var reopened = vault.Open(DbPath, dk, ek);
        using var query = reopened.CreateCommand();
        query.CommandText = "SELECT body FROM notes WHERE id = 1;";
        Assert.Equal("soli deo gloria", (string)query.ExecuteScalar()!);
    }

    [Fact]
    public void Open_With_NonRecipient_Key_Fails()
    {
        var (ek, _) = Kem();
        var (strangerEk, strangerDk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        Assert.Throws<PqSqliteException>(() => vault.Open(DbPath, strangerDk, strangerEk));
    }

    [Fact]
    public void Tampered_Manifest_Is_Rejected()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);
        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        string sidecar = PqSqliteManifest.SidecarPathFor(DbPath);
        byte[] bytes = File.ReadAllBytes(sidecar);
        bytes[^20] ^= 0xFF;
        File.WriteAllBytes(sidecar, bytes);

        Assert.Throws<PqSqliteException>(() => vault.Open(DbPath, dk, ek));
    }

    [Fact]
    public void Manifest_ReSigned_By_Untrusted_Key_Is_Rejected_By_Pinned_Vault()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var (evilPk, evilSk) = Sig();
        var vault = new PqSqliteVault(pk);
        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        var manifest = PqSqliteManifest.Load(DbPath);
        var forged = new PqSqliteManifest
        {
            KemAlgorithmId = manifest.KemAlgorithmId,
            SignatureAlgorithmId = manifest.SignatureAlgorithmId,
            DatabaseSalt = manifest.DatabaseSalt,
            SignerPublicKey = evilPk,
        };
        forged.Revision = manifest.Revision;
        forged.Recipients.AddRange(manifest.Recipients);
        forged.Sign(new MlDsa65Signer(), evilSk);
        forged.Save(DbPath);

        var ex = Assert.Throws<PqSqliteException>(() => vault.Open(DbPath, dk, ek));
        Assert.Contains("pinned trust anchor", ex.Message);
    }

    [Fact]
    public void Manifest_From_Other_Database_Is_Rejected()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);

        string dbA = Path.Combine(_dir, "a.db");
        string dbB = Path.Combine(_dir, "b.db");
        vault.Create(dbA, new[] { new KemRecipient(ek) }, sk).Dispose();
        vault.Create(dbB, new[] { new KemRecipient(ek) }, sk).Dispose();

        File.Copy(PqSqliteManifest.SidecarPathFor(dbA), PqSqliteManifest.SidecarPathFor(dbB), overwrite: true);

        var ex = Assert.Throws<PqSqliteException>(() => vault.Open(dbB, dk, ek));
        Assert.Contains("salt mismatch", ex.Message);
    }

    [Fact]
    public void AddRecipient_Allows_Second_Party_To_Open_And_Bumps_Revision()
    {
        var (ek1, dk1) = Kem();
        var (ek2, dk2) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek1) }, sk).Dispose();
        Assert.Equal(1, PqSqliteManifest.Load(DbPath).Revision);

        vault.AddRecipient(DbPath, new KemRecipient(ek2), dk1, ek1, sk);
        Assert.Equal(2, PqSqliteManifest.Load(DbPath).Revision);

        using var conn = vault.Open(DbPath, dk2, ek2);
        Assert.Equal(System.Data.ConnectionState.Open, conn.State);
    }

    [Fact]
    public void RemoveRecipientAndRotate_Locks_Out_Removed_Recipient()
    {
        var (ek1, dk1) = Kem();
        var (ek2, dk2) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek1), new KemRecipient(ek2) }, sk).Dispose();

        var fp2 = new KemRecipient(ek2).Fingerprint;
        vault.RemoveRecipientAndRotate(DbPath, fp2, dk1, ek1, sk);

        vault.Open(DbPath, dk1, ek1).Dispose();
        Assert.Throws<PqSqliteException>(() => vault.Open(DbPath, dk2, ek2));
        Assert.False(File.Exists(PqSqliteManifest.PendingSidecarPathFor(DbPath)));
    }

    [Fact]
    public void Passphrase_Recipient_Can_Open()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqliteVault(pk);
        var fastKdf = new Pbkdf2PasswordKdf(iterations: 10_000); // low iterations for test speed

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();
        vault.AddPassphraseRecipient(DbPath, "correct horse battery staple", dk, ek, sk, kdf: fastKdf);

        using var conn = vault.OpenWithPassphrase(DbPath, "correct horse battery staple", kdf: fastKdf);
        Assert.Equal(System.Data.ConnectionState.Open, conn.State);

        Assert.Throws<PqSqliteException>(() => vault.OpenWithPassphrase(DbPath, "wrong passphrase", kdf: fastKdf));
    }

    [Fact]
    public void Manifest_Cbor_RoundTrip_Is_Lossless()
    {
        var (ek, _) = Kem();
        var (pk, sk) = Sig();

        var manifest = new PqSqliteManifest
        {
            KemAlgorithmId = "ML-KEM-768",
            SignatureAlgorithmId = "ML-DSA-65",
            DatabaseSalt = new byte[16],
            SignerPublicKey = pk,
        };
        manifest.Recipients.Add(new RecipientEntry
        {
            Type = RecipientType.Kem,
            Fingerprint = PqSqliteManifest.FingerprintOf(ek),
            KemCiphertextOrSalt = new byte[1088],
            Nonce = new byte[12],
            WrappedDek = new byte[48],
        });
        manifest.Sign(new MlDsa65Signer(), sk);

        var roundTripped = PqSqliteManifest.Deserialize(manifest.Serialize());
        Assert.Equal(manifest.Serialize(), roundTripped.Serialize());
        roundTripped.Verify(new MlDsa65Signer(), new byte[16]); // does not throw
    }
}
