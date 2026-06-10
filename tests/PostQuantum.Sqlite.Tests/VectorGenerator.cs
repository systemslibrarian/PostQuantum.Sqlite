using System.Formats.Cbor;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using PostQuantum.Sqlite;
using PostQuantum.Sqlite.Algorithms;
using Xunit;

namespace PostQuantum.Sqlite.Tests;

/// <summary>
/// Regenerates the test-vector corpus under <c>Vectors/</c>. Intentionally
/// marked Skip; remove the Skip locally to regenerate, commit the binary
/// outputs, then put the Skip back. The shipped vectors are the source of
/// truth — independent implementations validate against the committed bytes.
/// </summary>
public sealed class VectorGenerator
{
    [Fact(Skip = "Vector generator. Remove Skip locally and rerun to regenerate the committed corpus.")]
    public void Regenerate()
    {
        string vectorsDir = ResolveVectorsDir();
        if (Directory.Exists(vectorsDir)) Directory.Delete(vectorsDir, recursive: true);
        Directory.CreateDirectory(Path.Combine(vectorsDir, "positive", "kem-single-recipient"));
        Directory.CreateDirectory(Path.Combine(vectorsDir, "negative"));

        var positive = new[] { EmitPositiveKemSingleRecipient(vectorsDir) };
        var negative = EmitNegativeCorpus(vectorsDir);

        var manifest = new
        {
            version = 1,
            description = "Official PostQuantum.Sqlite test vectors. See docs/test-vectors.md.",
            positive,
            negative,
        };
        File.WriteAllText(
            Path.Combine(vectorsDir, "manifest.json"),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static object EmitPositiveKemSingleRecipient(string vectorsDir)
    {
        string dir = Path.Combine(vectorsDir, "positive", "kem-single-recipient");
        string tempDb = Path.Combine(Path.GetTempPath(), "pqsqlite-vector-" + Guid.NewGuid().ToString("N") + ".db");

        var (ek, dk) = MlKem768Kem.GenerateKeyPair();
        var (signPk, signSk) = MlDsa65Signer.GenerateKeyPair();
        var vault = new PqSqliteVault(signPk);
        try
        {
            using (SqliteConnection _ = vault.Create(tempDb, new[] { new KemRecipient(ek) }, signSk))
            {
                // intentionally empty: vector exercises the manifest, not the DB schema.
            }

            File.Copy(PqSqliteManifest.SidecarPathFor(tempDb), Path.Combine(dir, "input.pqsm"), overwrite: true);
            File.WriteAllBytes(Path.Combine(dir, "recipient.encap.key"), ek);
            File.WriteAllBytes(Path.Combine(dir, "recipient.decap.key"), dk);
            File.WriteAllBytes(Path.Combine(dir, "signer.public.key"), signPk);

            // The DEK is held internally by Create(); for vector consumers we
            // re-derive it by opening the manifest as a known recipient.
            byte[] dek = ExtractDek(tempDb, dk, ek);
            File.WriteAllBytes(Path.Combine(dir, "expected.dek"), dek);

            byte[] salt = new byte[16];
            using (var fs = new FileStream(tempDb, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                fs.ReadExactly(salt);
            File.WriteAllBytes(Path.Combine(dir, "database.salt"), salt);
        }
        finally
        {
            TryDelete(tempDb);
            TryDelete(PqSqliteManifest.SidecarPathFor(tempDb));
        }

        return new
        {
            name = "kem-single-recipient",
            path = "positive/kem-single-recipient/input.pqsm",
            description = "Minimal well-formed manifest: one ML-KEM-768 recipient, ML-DSA-65 signed, revision 1.",
            recipientEncapsulationKey = "positive/kem-single-recipient/recipient.encap.key",
            recipientDecapsulationKey = "positive/kem-single-recipient/recipient.decap.key",
            signerPublicKey = "positive/kem-single-recipient/signer.public.key",
            databaseSalt = "positive/kem-single-recipient/database.salt",
            expectedDek = "positive/kem-single-recipient/expected.dek",
        };
    }

    private static byte[] ExtractDek(string dbPath, byte[] dk, byte[] ek)
    {
        // The vault doesn't expose the DEK directly. Re-run the unwrap path
        // by recovering through the manifest using the recipient key, then
        // read sqlite_master to prove it works; we surface the DEK bytes by
        // borrowing the same Internal helpers the vault uses.
        var manifest = PqSqliteManifest.Load(dbPath);
        var entry = manifest.FindByFingerprint(PqSqliteManifest.FingerprintOf(ek))
            ?? throw new InvalidOperationException("manifest missing recipient entry");

        var kem = new MlKem768Kem();
        byte[] sharedSecret = kem.Decapsulate(dk, entry.KemCiphertextOrSalt);

        byte[] info = BuildKekInfo(manifest.Version, kem.AlgorithmId, entry.Fingerprint);
        byte[] kek = System.Security.Cryptography.HKDF.DeriveKey(
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            sharedSecret, 32, manifest.DatabaseSalt, info);

        byte[] aad = new byte[manifest.DatabaseSalt.Length + entry.Fingerprint.Length];
        manifest.DatabaseSalt.CopyTo(aad, 0);
        entry.Fingerprint.CopyTo(aad, manifest.DatabaseSalt.Length);

        byte[] dek = new byte[32];
        using var gcm = new System.Security.Cryptography.AesGcm(kek, 16);
        gcm.Decrypt(entry.Nonce, entry.WrappedDek.AsSpan(0, 32), entry.WrappedDek.AsSpan(32, 16), dek, aad);
        return dek;
    }

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

    private static object[] EmitNegativeCorpus(string vectorsDir)
    {
        string dir = Path.Combine(vectorsDir, "negative");

        var cases = new (string name, string description, string expected, Func<byte[]> craft)[]
        {
            ("unknown-toplevel-field.pqsm",
             "Adds top-level field 99 with a string value. Strict parser rejects unknown fields.",
             "unknown field",
             () => CraftLaxManifest(extraTopLevelKey: 99)),
            ("duplicate-recipient-field.pqsm",
             "Recipient map has duplicate key 1 (type) — rejected by canonical CBOR uniqueness enforcement before the application's explicit duplicate-key check runs.",
             "malformed",
             () => CraftDuplicateRecipientKey()),
            ("truncated-nonce.pqsm",
             "Recipient nonce is 11 bytes instead of 12. Length is enforced exactly.",
             "AES-GCM nonce",
             () => CraftLaxManifest(nonceLength: 11)),
            ("wrong-salt-length.pqsm",
             "Top-level database-salt is 15 bytes instead of 16.",
             "database salt",
             () => CraftLaxManifest(saltLength: 15)),
            ("noncanonical-order.pqsm",
             "Top-level map keys are not sorted (canonical CBOR violated).",
             "malformed",
             () => CraftLaxManifest(unsortedTopLevelKeys: true)),
            ("trailing-bytes.pqsm",
             "Valid manifest with one extra 0x00 byte appended. Parser must reject trailing data.",
             "trailing bytes",
             () => CraftLaxManifest().Concat(new byte[] { 0x00 }).ToArray()),
        };

        var emitted = new List<object>();
        foreach (var c in cases)
        {
            byte[] bytes = c.craft();
            File.WriteAllBytes(Path.Combine(dir, c.name), bytes);
            emitted.Add(new
            {
                name = Path.GetFileNameWithoutExtension(c.name),
                path = "negative/" + c.name,
                description = c.description,
                expectedErrorContains = c.expected,
            });
        }
        return emitted.ToArray();
    }

    // Recipient with exactly 5 fields but key 1 appears twice and key 2 is
    // missing. Trips the explicit "duplicate field" check in ReadRecipient,
    // not the field-count check.
    private static byte[] CraftDuplicateRecipientKey()
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(7);
        w.WriteInt32(1); w.WriteInt32(1);
        w.WriteInt32(2); w.WriteTextString("ML-KEM-768");
        w.WriteInt32(3); w.WriteTextString("ML-DSA-65");
        w.WriteInt32(4); w.WriteByteString(new byte[16]);
        w.WriteInt32(5);
        w.WriteStartArray(1);
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(1);                 // type
        w.WriteInt32(1); w.WriteInt32(1);                 // duplicate type — invalid
        w.WriteInt32(3); w.WriteByteString(new byte[1088]);
        w.WriteInt32(4); w.WriteByteString(new byte[12]);
        w.WriteInt32(5); w.WriteByteString(new byte[48]);
        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteInt32(6); w.WriteByteString(new byte[1952]);
        w.WriteInt32(7); w.WriteInt64(1);
        w.WriteEndMap();
        return w.Encode();
    }

    // Mirrors HardeningTests.CraftManifestCbor — kept here so the test code
    // and the vector generator do not drift.
    private static byte[] CraftLaxManifest(
        int? extraTopLevelKey = null,
        bool duplicateRecipientField = false,
        int nonceLength = 12,
        int saltLength = 16,
        bool unsortedTopLevelKeys = false)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        int topCount = 7 + (extraTopLevelKey is null ? 0 : 1);
        w.WriteStartMap(topCount);

        if (unsortedTopLevelKeys)
        {
            w.WriteInt32(2); w.WriteTextString("ML-KEM-768");
            w.WriteInt32(1); w.WriteInt32(1);
        }
        else
        {
            w.WriteInt32(1); w.WriteInt32(1);
            w.WriteInt32(2); w.WriteTextString("ML-KEM-768");
        }
        w.WriteInt32(3); w.WriteTextString("ML-DSA-65");
        w.WriteInt32(4); w.WriteByteString(new byte[saltLength]);

        w.WriteInt32(5);
        w.WriteStartArray(1);
        int recipientCount = 5 + (duplicateRecipientField ? 1 : 0);
        w.WriteStartMap(recipientCount);
        w.WriteInt32(1); w.WriteInt32(1);
        if (duplicateRecipientField) { w.WriteInt32(1); w.WriteInt32(1); }
        w.WriteInt32(2); w.WriteByteString(new byte[16]);
        w.WriteInt32(3); w.WriteByteString(new byte[1088]);
        w.WriteInt32(4); w.WriteByteString(new byte[nonceLength]);
        w.WriteInt32(5); w.WriteByteString(new byte[48]);
        w.WriteEndMap();
        w.WriteEndArray();

        w.WriteInt32(6); w.WriteByteString(new byte[1952]);
        w.WriteInt32(7); w.WriteInt64(1);
        if (extraTopLevelKey is int extra) { w.WriteInt32(extra); w.WriteTextString("injected"); }
        w.WriteEndMap();
        return w.Encode();
    }

    private static string ResolveVectorsDir()
    {
        // Walk up from the test binary's directory to the project's source
        // directory so regeneration writes to the committed location.
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(current.FullName, "PostQuantum.Sqlite.Tests.csproj");
            if (File.Exists(candidate)) return Path.Combine(current.FullName, "Vectors");
            current = current.Parent;
        }
        throw new InvalidOperationException("Could not locate the test project source directory.");
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best effort */ }
    }
}
