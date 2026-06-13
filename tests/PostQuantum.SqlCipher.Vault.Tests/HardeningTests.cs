using System.Formats.Cbor;
using PostQuantum.SqlCipher.Vault;
using PostQuantum.SqlCipher.Vault.Abstractions;
using PostQuantum.SqlCipher.Vault.Algorithms;
using Xunit;

namespace PostQuantum.SqlCipher.Vault.Tests;

public class HardeningTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("pqsqlite-hardening").FullName;
    private string DbPath => Path.Combine(_dir, "test.db");

    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ } }

    private static (byte[] ek, byte[] dk) Kem() => MlKem768Kem.GenerateKeyPair();
    private static (byte[] pk, byte[] sk) Sig() => MlDsa65Signer.GenerateKeyPair();

    // ── Trust anchor enforcement ──────────────────────────────────────────

    [Fact]
    public void Unpinned_Vault_Refuses_All_Mutating_Operations()
    {
        var (ek, dk) = Kem();
        var (ek2, _) = Kem();
        var (pk, sk) = Sig();

        // Set up a database with a properly pinned vault first.
        new PqSqlCipherVault(pk).Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        var unpinned = PqSqlCipherVault.CreateUnpinned();
        Assert.False(unpinned.IsPinned);

        Assert.Throws<PqSqlCipherException>(() => unpinned.Create(Path.Combine(_dir, "x.db"), new[] { new KemRecipient(ek) }, sk));
        Assert.Throws<PqSqlCipherException>(() => unpinned.AddRecipient(DbPath, new KemRecipient(ek2), dk, ek, sk));
        Assert.Throws<PqSqlCipherException>(() => unpinned.AddPassphraseRecipient(DbPath, "pw", dk, ek, sk));
        Assert.Throws<PqSqlCipherException>(() => unpinned.RotateDek(DbPath, dk, ek, sk));
        Assert.Throws<PqSqlCipherException>(() => unpinned.RemoveRecipientAndRotate(DbPath, new KemRecipient(ek2).Fingerprint, dk, ek, sk));
    }

    [Fact]
    public void Unpinned_Vault_Can_Read_But_Accepts_Any_Signer()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var (evilPk, evilSk) = Sig();

        new PqSqlCipherVault(pk).Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Attacker re-signs under their own key.
        var manifest = PqSqlCipherManifest.Load(DbPath);
        var forged = new PqSqlCipherManifest
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

        // The pinned vault refuses; the unpinned vault demonstrates the
        // documented risk: self-attestation passes without a trust anchor.
        Assert.Throws<PqSqlCipherException>(() => new PqSqlCipherVault(pk).Open(DbPath, dk, ek));
        PqSqlCipherVault.CreateUnpinned().Open(DbPath, dk, ek).Dispose();
    }

    [Fact]
    public void Constructor_Rejects_Wrong_Length_Trust_Anchor() =>
        Assert.Throws<PqSqlCipherException>(() => new PqSqlCipherVault(new byte[16]));

    [Fact]
    public void Mutating_Operation_Rejects_Manifest_Signed_By_Untrusted_Key()
    {
        var (ek, dk) = Kem();
        var (ek2, _) = Kem();
        var (pk, sk) = Sig();
        var (evilPk, evilSk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        var manifest = PqSqlCipherManifest.Load(DbPath);
        var forged = new PqSqlCipherManifest
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

        // The forged manifest verifies under its OWN embedded key — but the
        // vault pins the legitimate signer and must refuse.
        var ex = Assert.Throws<PqSqlCipherException>(() =>
            vault.AddRecipient(DbPath, new KemRecipient(ek2), dk, ek, sk));
        Assert.Contains("pinned trust anchor", ex.Message);
    }

    [Fact]
    public void Mutating_Operation_Rejects_Mismatched_Signing_Keypair()
    {
        var (ek, dk) = Kem();
        var (ek2, _) = Kem();
        var (pk, sk) = Sig();
        var (_, otherSk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Trust anchor is correct, but the private key handed in doesn't match it.
        var ex = Assert.Throws<PqSqlCipherException>(() =>
            vault.AddRecipient(DbPath, new KemRecipient(ek2), dk, ek, otherSk));
        Assert.Contains("does not correspond", ex.Message);
    }

    // ── Malicious CBOR ────────────────────────────────────────────────────

    /// <summary>
    /// Crafts manifest CBOR with a Lax writer so we can produce structures the
    /// canonical writer would refuse: unknown fields, duplicate fields,
    /// unsorted keys, out-of-spec lengths.
    /// </summary>
    private static byte[] CraftManifestCbor(
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
        w.WriteInt32(1); w.WriteInt32(1); // type = Kem
        if (duplicateRecipientField)
        {
            w.WriteInt32(1); w.WriteInt32(1); // duplicate type field
        }
        w.WriteInt32(2); w.WriteByteString(new byte[16]);   // fingerprint
        w.WriteInt32(3); w.WriteByteString(new byte[1088]); // KEM ciphertext
        w.WriteInt32(4); w.WriteByteString(new byte[nonceLength]);
        w.WriteInt32(5); w.WriteByteString(new byte[48]);   // wrapped DEK
        w.WriteEndMap();
        w.WriteEndArray();

        w.WriteInt32(6); w.WriteByteString(new byte[1952]); // signer pk
        w.WriteInt32(7); w.WriteInt64(1);                   // revision
        if (extraTopLevelKey is int extra)
        {
            w.WriteInt32(extra); w.WriteTextString("injected");
        }
        w.WriteEndMap();
        return w.Encode();
    }

    [Fact]
    public void Wellformed_Crafted_Manifest_Parses()
    {
        var manifest = PqSqlCipherManifest.Deserialize(CraftManifestCbor());
        Assert.Equal("ML-KEM-768", manifest.KemAlgorithmId);
        Assert.Single(manifest.Recipients);
    }

    [Fact]
    public void Unknown_TopLevel_Field_Is_Rejected() =>
        Assert.Throws<PqSqlCipherException>(() => PqSqlCipherManifest.Deserialize(CraftManifestCbor(extraTopLevelKey: 99)));

    [Fact]
    public void Duplicate_Recipient_Field_Is_Rejected() =>
        Assert.Throws<PqSqlCipherException>(() => PqSqlCipherManifest.Deserialize(CraftManifestCbor(duplicateRecipientField: true)));

    [Fact]
    public void Truncated_Nonce_Is_Rejected() =>
        Assert.Throws<PqSqlCipherException>(() => PqSqlCipherManifest.Deserialize(CraftManifestCbor(nonceLength: 11)));

    [Fact]
    public void Wrong_Salt_Length_Is_Rejected() =>
        Assert.Throws<PqSqlCipherException>(() => PqSqlCipherManifest.Deserialize(CraftManifestCbor(saltLength: 15)));

    [Fact]
    public void NonCanonical_Key_Order_Is_Rejected() =>
        Assert.Throws<PqSqlCipherException>(() => PqSqlCipherManifest.Deserialize(CraftManifestCbor(unsortedTopLevelKeys: true)));

    [Fact]
    public void Trailing_Bytes_Are_Rejected()
    {
        byte[] valid = CraftManifestCbor();
        byte[] padded = valid.Concat(new byte[] { 0x00 }).ToArray();
        Assert.Throws<PqSqlCipherException>(() => PqSqlCipherManifest.Deserialize(padded));
    }

    // ── Crash-safe rotation ───────────────────────────────────────────────

    [Fact]
    public void Stale_Primary_After_Rotation_Crash_Is_Recovered_Via_Pending()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        // M1/D1 state, then a completed rotation to M2/D2.
        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();
        byte[] m1 = File.ReadAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath));
        vault.RotateDek(DbPath, dk, ek, sk);
        byte[] m2 = File.ReadAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath));

        // Simulate crash-after-rekey-before-promote: DB is at D2, primary
        // sidecar rolled back to stale M1, M2 sits as pending.
        File.WriteAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath), m1);
        File.WriteAllBytes(PqSqlCipherManifest.PendingSidecarPathFor(DbPath), m2);

        // Open must recover via the pending manifest and promote it.
        vault.Open(DbPath, dk, ek).Dispose();
        Assert.False(File.Exists(PqSqlCipherManifest.PendingSidecarPathFor(DbPath)));
        Assert.Equal(m2, File.ReadAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath)));
    }

    [Fact]
    public void Stale_Pending_Before_Rekey_Is_Cleaned_Up()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Simulate crash-after-pending-write-before-rekey: DB still at D1,
        // primary M1 is correct, a pending file exists but was never applied.
        File.Copy(PqSqlCipherManifest.SidecarPathFor(DbPath), PqSqlCipherManifest.PendingSidecarPathFor(DbPath));

        vault.Open(DbPath, dk, ek).Dispose();
        Assert.False(File.Exists(PqSqlCipherManifest.PendingSidecarPathFor(DbPath)));
    }

    // ── KDF enforcement ───────────────────────────────────────────────────

    private sealed class RenamedKdf : IPasswordKdf
    {
        private readonly Pbkdf2PasswordKdf _inner = new(iterations: 10_000);
        public string KdfId => "Argon2id"; // pretends to be a different KDF
        public byte[] SerializeParameters() => _inner.SerializeParameters();
        public byte[] DeriveKey(ReadOnlySpan<char> p, ReadOnlySpan<byte> s, ReadOnlySpan<byte> sp) => _inner.DeriveKey(p, s, sp);
    }

    [Fact]
    public void Passphrase_Open_Refuses_Mismatched_KdfId()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();
        vault.AddPassphraseRecipient(DbPath, "hunter2hunter2", dk, ek, sk, kdf: new RenamedKdf());

        // Entry is recorded as "Argon2id"; opening with the PBKDF2 default must refuse
        // to derive rather than silently producing garbage with the wrong KDF.
        var ex = Assert.Throws<PqSqlCipherException>(() =>
            vault.OpenWithPassphrase(DbPath, "hunter2hunter2", kdf: new Pbkdf2PasswordKdf(iterations: 10_000)));
        Assert.Contains("mismatched KDF", ex.Message);

        // And the matching KDF works.
        vault.OpenWithPassphrase(DbPath, "hunter2hunter2", kdf: new RenamedKdf()).Dispose();
    }

    // ── Fault injection: corrupt sidecars + leftover artefacts ────────────

    [Fact]
    public void Corrupted_Pending_Is_Cleaned_Up_When_Primary_Succeeds()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Simulate "rotation aborted mid-AtomicWrite": a malformed file sits
        // at the .pending path. Open MUST succeed off the primary AND delete
        // the corrupt pending so it can't bite a future call.
        File.WriteAllBytes(PqSqlCipherManifest.PendingSidecarPathFor(DbPath),
            new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });

        vault.Open(DbPath, dk, ek).Dispose();
        Assert.False(File.Exists(PqSqlCipherManifest.PendingSidecarPathFor(DbPath)));
    }

    [Fact]
    public void Both_Primary_And_Pending_Corrupted_Fails_Cleanly()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Both sidecars unparseable. Open MUST surface a PqSqlCipherException
        // (no NRE, no IndexOutOfRange, no CborContentException leaking out).
        File.WriteAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath), new byte[] { 0x00 });
        File.WriteAllBytes(PqSqlCipherManifest.PendingSidecarPathFor(DbPath), new byte[] { 0x00 });

        var ex = Assert.Throws<PqSqlCipherException>(() => vault.Open(DbPath, dk, ek));
        Assert.Contains("Could not resolve", ex.Message, StringComparison.OrdinalIgnoreCase);
        // The inner cause must surface the actual parse failure, not be lost.
        Assert.IsType<PqSqlCipherException>(ex.InnerException);
        Assert.Contains("malformed", ex.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Pending_From_Different_Database_Is_Rejected_Via_Salt_Binding()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        string dbA = Path.Combine(_dir, "a.db");
        string dbB = Path.Combine(_dir, "b.db");
        vault.Create(dbA, new[] { new KemRecipient(ek) }, sk).Dispose();
        vault.Create(dbB, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Attacker drops a valid manifest from a DIFFERENT database into b's
        // .pending slot. Even if b's primary somehow failed, the cross-DB
        // pending must be rejected via salt binding, not silently promoted.
        File.Copy(PqSqlCipherManifest.SidecarPathFor(dbA),
                  PqSqlCipherManifest.PendingSidecarPathFor(dbB), overwrite: true);

        // Corrupt b's primary to force the recovery path to consider the pending.
        byte[] primary = File.ReadAllBytes(PqSqlCipherManifest.SidecarPathFor(dbB));
        primary[^20] ^= 0xFF;
        File.WriteAllBytes(PqSqlCipherManifest.SidecarPathFor(dbB), primary);

        Assert.Throws<PqSqlCipherException>(() => vault.Open(dbB, dk, ek));
        // The pending sidecar should still be present — it was authentic for
        // dbA, just not for dbB. We must not silently delete legitimate state
        // belonging to another database that lives in the wrong directory.
        Assert.True(File.Exists(PqSqlCipherManifest.PendingSidecarPathFor(dbB)));
    }

    [Fact]
    public void Leftover_Tmp_Files_Are_Inert()
    {
        var (ek, dk) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek) }, sk).Dispose();

        // Simulate a previous crash mid-AtomicWrite leaving a stray .tmp.
        // The next write picks a fresh GUID-suffixed tmp so collisions are
        // impossible; verify Open and a mutating op both still work and the
        // stray file is left untouched (it is not our responsibility to GC
        // arbitrary files in the user's directory).
        string strayTmp = PqSqlCipherManifest.SidecarPathFor(DbPath) + ".deadbeef.tmp";
        File.WriteAllBytes(strayTmp, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        vault.Open(DbPath, dk, ek).Dispose();

        var (ek2, _) = Kem();
        vault.AddRecipient(DbPath, new KemRecipient(ek2), dk, ek, sk);

        Assert.True(File.Exists(strayTmp));
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, File.ReadAllBytes(strayTmp));
    }

    // ── Rollback detection ────────────────────────────────────────────────

    [Fact]
    public void Rollback_To_Older_Revision_Is_Detected_When_Minimum_Pinned()
    {
        var (ek1, dk1) = Kem();
        var (ek2, dk2) = Kem();
        var (pk, sk) = Sig();
        var vault = new PqSqlCipherVault(pk);

        vault.Create(DbPath, new[] { new KemRecipient(ek1), new KemRecipient(ek2) }, sk).Dispose();
        byte[] oldManifest = File.ReadAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath));
        byte[] oldDb = File.ReadAllBytes(DbPath);

        // Revoke recipient 2 (revision bumps via rotation).
        vault.RemoveRecipientAndRotate(DbPath, new KemRecipient(ek2).Fingerprint, dk1, ek1, sk);
        long newRevision = PqSqlCipherManifest.Load(DbPath).Revision;
        Assert.True(newRevision > 1);

        // Attacker rolls back BOTH the database and the manifest to the
        // pre-revocation state. Both are authentic — signature passes.
        File.WriteAllBytes(DbPath, oldDb);
        File.WriteAllBytes(PqSqlCipherManifest.SidecarPathFor(DbPath), oldManifest);

        // Without a pinned minimum the rollback is undetectable by design...
        vault.Open(DbPath, dk2, ek2).Dispose();

        // ...but an application tracking the revision out-of-band catches it.
        var ex = Assert.Throws<PqSqlCipherException>(() =>
            vault.Open(DbPath, dk2, ek2, expectedMinimumRevision: newRevision));
        Assert.Contains("rollback", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
