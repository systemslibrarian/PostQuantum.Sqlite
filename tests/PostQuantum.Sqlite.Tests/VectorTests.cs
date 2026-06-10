using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.Sqlite;
using PostQuantum.Sqlite.Algorithms;
using Xunit;

namespace PostQuantum.Sqlite.Tests;

/// <summary>
/// Validates the committed test-vector corpus under <c>Vectors/</c>:
///
///   - Positive vectors round-trip end to end: parse, find recipient by
///     fingerprint, decapsulate, derive KEK, unwrap DEK, verify signature.
///     The unwrapped DEK MUST equal the committed expected.dek.
///
///   - Negative vectors MUST be rejected by the parser with a message
///     containing the expected substring.
///
/// Independent <c>.pqsm</c> implementations should run the same assertions
/// against the same files; see <c>docs/test-vectors.md</c>.
/// </summary>
public sealed class VectorTests
{
    private static readonly string VectorsRoot =
        Path.Combine(AppContext.BaseDirectory, "Vectors");

    public static IEnumerable<object[]> PositiveCases() => LoadManifest("positive");

    public static IEnumerable<object[]> NegativeCases() => LoadManifest("negative");

    [Theory]
    [MemberData(nameof(PositiveCases))]
    public void Positive_Vector_RoundTrips(string vectorName)
    {
        var doc = LoadDoc();
        var entry = doc.RootElement.GetProperty("positive")
            .EnumerateArray().Single(e => e.GetProperty("name").GetString() == vectorName);

        byte[] pqsm = ReadVector(entry.GetProperty("path").GetString()!);
        byte[] encapKey = ReadVector(entry.GetProperty("recipientEncapsulationKey").GetString()!);
        byte[] decapKey = ReadVector(entry.GetProperty("recipientDecapsulationKey").GetString()!);
        byte[] signerPk = ReadVector(entry.GetProperty("signerPublicKey").GetString()!);
        byte[] salt = ReadVector(entry.GetProperty("databaseSalt").GetString()!);
        byte[] expectedDek = ReadVector(entry.GetProperty("expectedDek").GetString()!);

        var manifest = PqSqliteManifest.Deserialize(pqsm);

        Assert.Equal("ML-KEM-768", manifest.KemAlgorithmId);
        Assert.Equal("ML-DSA-65", manifest.SignatureAlgorithmId);
        Assert.Equal(salt, manifest.DatabaseSalt);
        Assert.Equal(signerPk, manifest.SignerPublicKey);

        // Verify the signature using the committed signer public key.
        manifest.Verify(new MlDsa65Signer(), salt);

        // Find the recipient entry by fingerprint, decapsulate, derive KEK,
        // unwrap the DEK — the full reader pipeline an independent
        // implementation must reproduce.
        byte[] fingerprint = PqSqliteManifest.FingerprintOf(encapKey);
        var rec = manifest.FindByFingerprint(fingerprint);
        Assert.NotNull(rec);
        Assert.Equal(RecipientType.Kem, rec!.Type);

        var kem = new MlKem768Kem();
        byte[] sharedSecret = kem.Decapsulate(decapKey, rec.KemCiphertextOrSalt);

        byte[] info = BuildKekInfo(manifest.Version, kem.AlgorithmId, fingerprint);
        byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, salt, info);

        byte[] aad = new byte[salt.Length + fingerprint.Length];
        salt.CopyTo(aad, 0);
        fingerprint.CopyTo(aad, salt.Length);

        byte[] dek = new byte[32];
        using (var gcm = new AesGcm(kek, 16))
            gcm.Decrypt(rec.Nonce, rec.WrappedDek.AsSpan(0, 32), rec.WrappedDek.AsSpan(32, 16), dek, aad);

        Assert.Equal(expectedDek, dek);
    }

    [Theory]
    [MemberData(nameof(NegativeCases))]
    public void Negative_Vector_Is_Rejected(string vectorName)
    {
        var doc = LoadDoc();
        var entry = doc.RootElement.GetProperty("negative")
            .EnumerateArray().Single(e => e.GetProperty("name").GetString() == vectorName);

        byte[] pqsm = ReadVector(entry.GetProperty("path").GetString()!);
        string expected = entry.GetProperty("expectedErrorContains").GetString()!;

        var ex = Assert.Throws<PqSqliteException>(() => PqSqliteManifest.Deserialize(pqsm));
        Assert.Contains(expected, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<object[]> LoadManifest(string section)
    {
        using var doc = LoadDoc();
        foreach (var e in doc.RootElement.GetProperty(section).EnumerateArray())
            yield return new object[] { e.GetProperty("name").GetString()! };
    }

    private static JsonDocument LoadDoc() =>
        JsonDocument.Parse(File.ReadAllBytes(Path.Combine(VectorsRoot, "manifest.json")));

    private static byte[] ReadVector(string relative) =>
        File.ReadAllBytes(Path.Combine(VectorsRoot, relative.Replace('/', Path.DirectorySeparatorChar)));

    private static byte[] BuildKekInfo(int version, string algorithmId, byte[] fingerprint)
    {
        ReadOnlySpan<byte> label = "PostQuantum.Sqlite/kek"u8;
        byte[] algId = System.Text.Encoding.UTF8.GetBytes(algorithmId);
        byte[] info = new byte[label.Length + 1 + 4 + 1 + algId.Length + 1 + fingerprint.Length];
        int off = 0;
        label.CopyTo(info.AsSpan(off)); off += label.Length;
        info[off++] = 0x00;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(info.AsSpan(off, 4), version); off += 4;
        info[off++] = 0x00;
        algId.CopyTo(info, off); off += algId.Length;
        info[off++] = 0x00;
        fingerprint.CopyTo(info, off);
        return info;
    }
}
