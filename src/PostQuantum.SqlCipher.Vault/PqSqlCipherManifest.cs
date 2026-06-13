using System.Formats.Cbor;
using System.Security.Cryptography;
using PostQuantum.SqlCipher.Vault.Abstractions;

namespace PostQuantum.SqlCipher.Vault;

/// <summary>Wire-level recipient kind. The integer value is the on-disk encoding.</summary>
public enum RecipientType : int
{
    /// <summary>Key-encapsulation recipient (e.g. ML-KEM-768). Wire value <c>1</c>.</summary>
    Kem = 1,
    /// <summary>Passphrase recipient with a KDF-derived intermediate key. Wire value <c>2</c>.</summary>
    Passphrase = 2,
}

/// <summary>One wrapped copy of the DEK, addressed to a single recipient.</summary>
public sealed class RecipientEntry
{
    /// <summary>KEM or passphrase. Determines which CBOR fields are required.</summary>
    public required RecipientType Type { get; init; }

    /// <summary>SHA-256 of the recipient's encapsulation key (KEM) or of the KDF salt (passphrase), first 16 bytes.</summary>
    public required byte[] Fingerprint { get; init; }

    /// <summary>KEM ciphertext (KEM recipients) or KDF salt (passphrase recipients).</summary>
    public required byte[] KemCiphertextOrSalt { get; init; }

    /// <summary>AES-256-GCM nonce used to wrap the DEK (12 bytes).</summary>
    public required byte[] Nonce { get; init; }

    /// <summary>DEK wrapped under the per-recipient KEK: 32-byte ciphertext || 16-byte GCM tag.</summary>
    public required byte[] WrappedDek { get; init; }

    /// <summary>KDF identifier (passphrase recipients only).</summary>
    public string? KdfId { get; init; }

    /// <summary>Serialized KDF parameters as canonical CBOR; null for KEM recipients.</summary>
    public byte[]? KdfParameters { get; init; }
}

/// <summary>
/// The .pqsm sidecar manifest: canonical CBOR, ML-DSA-65 signed, bound to its
/// database file via the SQLCipher salt (first 16 plaintext bytes of the file),
/// with a monotonic revision counter for application-level rollback detection.
///
/// Parsing is STRICT for version 1: unknown fields, duplicate fields, wrong
/// types, non-canonical encoding, indefinite lengths, and out-of-spec field
/// lengths are all hard rejections. A security manifest format must never be
/// forgiving about input it did not produce.
/// </summary>
public sealed class PqSqlCipherManifest
{
    /// <summary>The current manifest format version. Strict-equality check at parse time.</summary>
    public const int CurrentVersion = 1;
    /// <summary>Sidecar file extension appended to the database path (<c>.pqsm</c>).</summary>
    public const string SidecarExtension = ".pqsm";

    // ── Fixed field lengths (version 1) ───────────────────────────────────
    /// <summary>SQLCipher file-salt length in bytes (16).</summary>
    public const int SaltLength = 16;            // SQLCipher file salt
    /// <summary>Truncated-SHA-256 fingerprint length in bytes (16).</summary>
    public const int FingerprintLength = 16;     // SHA-256 truncated
    /// <summary>AES-GCM nonce length in bytes (12).</summary>
    public const int NonceLength = 12;           // AES-GCM
    /// <summary>Wrapped-DEK length in bytes (48 = 32-byte ciphertext + 16-byte tag).</summary>
    public const int WrappedDekLength = 48;      // 32-byte DEK + 16-byte tag
    /// <summary>KDF salt length for passphrase recipients (32 bytes).</summary>
    public const int PassphraseSaltLength = 32;  // KDF salt for passphrase recipients

    // ── Structural bounds (DoS hardening; exact sizes enforced later
    //    against the configured algorithms in PqSqlCipherVault) ───────────────
    private const int MaxAlgorithmIdLength = 64;
    private const int MaxKdfIdLength = 64;
    private const int MaxKdfParametersLength = 1024;
    private const int MaxVariableFieldLength = 16384; // KEM ct, signer pk, signature upper bound
    private const int MaxRecipients = 1024;

    // ── CBOR map keys, version 1. Top level: 1..7 unsigned, 8 signed. ─────
    private const int KeyVersion = 1;
    private const int KeyKemAlg = 2;
    private const int KeySigAlg = 3;
    private const int KeySalt = 4;
    private const int KeyRecipients = 5;
    private const int KeySignerPk = 6;
    private const int KeyRevision = 7;
    private const int KeySignature = 8;

    private const int RKeyType = 1;
    private const int RKeyFingerprint = 2;
    private const int RKeyCtOrSalt = 3;
    private const int RKeyNonce = 4;
    private const int RKeyWrappedDek = 5;
    private const int RKeyKdfId = 6;
    private const int RKeyKdfParams = 7;

    /// <summary>Manifest format version. Always equal to <see cref="CurrentVersion"/> for a freshly-constructed manifest.</summary>
    public int Version { get; private set; } = CurrentVersion;

    /// <summary>The KEM algorithm identifier (e.g. <c>"ML-KEM-768"</c>) recorded in the manifest.</summary>
    public required string KemAlgorithmId { get; init; }

    /// <summary>The signature algorithm identifier (e.g. <c>"ML-DSA-65"</c>) recorded in the manifest.</summary>
    public required string SignatureAlgorithmId { get; init; }

    /// <summary>SQLCipher salt — first 16 bytes of the database file. Binds manifest to DB.</summary>
    public required byte[] DatabaseSalt { get; init; }

    /// <summary>Wrapped-DEK entries, one per recipient. Order is significant for canonical CBOR re-encoding.</summary>
    public List<RecipientEntry> Recipients { get; } = new();

    /// <summary>Public key of the signer that produced <see cref="Signature"/>; checked against the vault's trust anchor at verify time.</summary>
    public required byte[] SignerPublicKey { get; init; }

    /// <summary>
    /// Monotonic revision, starting at 1, incremented on every mutation and
    /// covered by the signature. The manifest format cannot prevent rollback
    /// (an attacker replaying an older validly-signed manifest + matching DB
    /// copy); applications that need rollback detection must track the last
    /// known revision out-of-band and pass it to PqSqlCipherVault.Open.
    /// </summary>
    public long Revision { get; set; } = 1;

    /// <summary>Detached signature over the canonical CBOR of fields 1–7. <see langword="null"/> until <see cref="Sign"/> runs.</summary>
    public byte[]? Signature { get; private set; }

    // ── Signing ────────────────────────────────────────────────────────────

    /// <summary>Canonical CBOR bytes of everything except the signature — the signed payload.</summary>
    public byte[] GetSignedPayload()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteBody(writer, includeSignature: false);
        return writer.Encode();
    }

    /// <summary>Compute and store a signature over <see cref="GetSignedPayload"/> using the supplied signer and private key.</summary>
    public void Sign(ISignatureAlgorithm signer, ReadOnlySpan<byte> signingPrivateKey)
    {
        if (signer.AlgorithmId != SignatureAlgorithmId)
            throw new PqSqlCipherException($"Signer is {signer.AlgorithmId} but manifest declares {SignatureAlgorithmId}.");
        Signature = signer.Sign(signingPrivateKey, GetSignedPayload());
    }

    /// <summary>Verify the manifest signature and its binding to the database salt. Throws on failure.</summary>
    public void Verify(ISignatureAlgorithm verifier, ReadOnlySpan<byte> actualDatabaseSalt)
    {
        if (Signature is null)
            throw new PqSqlCipherException("Manifest is unsigned.");
        if (verifier.AlgorithmId != SignatureAlgorithmId)
            throw new PqSqlCipherException($"Manifest declares signature algorithm '{SignatureAlgorithmId}' but verifier is '{verifier.AlgorithmId}'.");
        if (SignerPublicKey.Length != verifier.PublicKeySizeInBytes)
            throw new PqSqlCipherException("Signer public key has invalid length for the declared algorithm.");
        if (Signature.Length != verifier.SignatureSizeInBytes)
            throw new PqSqlCipherException("Signature has invalid length for the declared algorithm.");
        if (!actualDatabaseSalt.SequenceEqual(DatabaseSalt))
            throw new PqSqlCipherException("Manifest does not belong to this database file (salt mismatch). Possible substitution.");
        if (!verifier.Verify(SignerPublicKey, GetSignedPayload(), Signature))
            throw new PqSqlCipherException("Manifest signature verification FAILED. The manifest has been tampered with or re-signed by an untrusted key.");
    }

    // ── Recipient lookup ──────────────────────────────────────────────────

    /// <summary>Linear-scan lookup of a recipient entry by its 16-byte fingerprint. Returns <see langword="null"/> if no entry matches.</summary>
    public RecipientEntry? FindByFingerprint(ReadOnlySpan<byte> fingerprint)
    {
        foreach (var r in Recipients)
            if (fingerprint.SequenceEqual(r.Fingerprint)) return r;
        return null;
    }

    /// <summary>SHA-256 of <paramref name="keyMaterial"/> truncated to <see cref="FingerprintLength"/> bytes — the manifest's fingerprint construction.</summary>
    public static byte[] FingerprintOf(ReadOnlySpan<byte> keyMaterial) =>
        SHA256.HashData(keyMaterial)[..FingerprintLength];

    // ── CBOR serialization ────────────────────────────────────────────────

    /// <summary>Serialize the manifest (including signature if present) to canonical CBOR.</summary>
    public byte[] Serialize()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteBody(writer, includeSignature: true);
        return writer.Encode();
    }

    private void WriteBody(CborWriter writer, bool includeSignature)
    {
        bool signed = includeSignature && Signature is not null;
        writer.WriteStartMap(signed ? 8 : 7);

        writer.WriteInt32(KeyVersion);    writer.WriteInt32(Version);
        writer.WriteInt32(KeyKemAlg);     writer.WriteTextString(KemAlgorithmId);
        writer.WriteInt32(KeySigAlg);     writer.WriteTextString(SignatureAlgorithmId);
        writer.WriteInt32(KeySalt);       writer.WriteByteString(DatabaseSalt);

        writer.WriteInt32(KeyRecipients);
        writer.WriteStartArray(Recipients.Count);
        foreach (var r in Recipients)
        {
            bool hasKdf = r.Type == RecipientType.Passphrase;
            writer.WriteStartMap(hasKdf ? 7 : 5);
            writer.WriteInt32(RKeyType);        writer.WriteInt32((int)r.Type);
            writer.WriteInt32(RKeyFingerprint); writer.WriteByteString(r.Fingerprint);
            writer.WriteInt32(RKeyCtOrSalt);    writer.WriteByteString(r.KemCiphertextOrSalt);
            writer.WriteInt32(RKeyNonce);       writer.WriteByteString(r.Nonce);
            writer.WriteInt32(RKeyWrappedDek);  writer.WriteByteString(r.WrappedDek);
            if (hasKdf)
            {
                writer.WriteInt32(RKeyKdfId);     writer.WriteTextString(r.KdfId ?? throw new PqSqlCipherException("Passphrase recipient missing KdfId."));
                writer.WriteInt32(RKeyKdfParams); writer.WriteByteString(r.KdfParameters ?? Array.Empty<byte>());
            }
            writer.WriteEndMap();
        }
        writer.WriteEndArray();

        writer.WriteInt32(KeySignerPk);  writer.WriteByteString(SignerPublicKey);
        writer.WriteInt32(KeyRevision);  writer.WriteInt64(Revision);

        if (signed)
        {
            writer.WriteInt32(KeySignature); writer.WriteByteString(Signature!);
        }

        writer.WriteEndMap();
    }

    /// <summary>
    /// Strict v1 parser. Canonical conformance (definite lengths, sorted unique
    /// map keys), exhaustive key whitelisting, duplicate detection, type
    /// enforcement (wrong CBOR major types throw from the reader), exact
    /// lengths for fixed-size fields, and hard upper bounds on variable fields.
    /// </summary>
    public static PqSqlCipherManifest Deserialize(byte[] cbor)
    {
        ArgumentNullException.ThrowIfNull(cbor);
        try
        {
            return DeserializeCore(cbor);
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new PqSqlCipherException("Manifest is malformed (strict CBOR validation failed).", ex);
        }
    }

    private static PqSqlCipherManifest DeserializeCore(byte[] cbor)
    {
        var reader = new CborReader(cbor, CborConformanceMode.Canonical);
        int? mapCountNullable = reader.ReadStartMap();
        if (mapCountNullable is not (7 or 8))
            throw new PqSqlCipherException($"Manifest: expected 7 (unsigned) or 8 (signed) top-level fields, got {mapCountNullable?.ToString() ?? "indefinite"}.");
        int mapCount = mapCountNullable.Value;

        var seen = new HashSet<int>();
        int version = 0;
        long revision = -1;
        string? kemId = null, sigId = null;
        byte[]? salt = null, signerPk = null, signature = null;
        List<RecipientEntry>? recipients = null;

        for (int i = 0; i < mapCount; i++)
        {
            int key = reader.ReadInt32();
            if (!seen.Add(key))
                throw new PqSqlCipherException($"Manifest: duplicate field {key}.");

            switch (key)
            {
                case KeyVersion:
                    version = reader.ReadInt32();
                    break;
                case KeyKemAlg:
                    kemId = ReadBoundedText(reader, MaxAlgorithmIdLength, "KEM algorithm id");
                    break;
                case KeySigAlg:
                    sigId = ReadBoundedText(reader, MaxAlgorithmIdLength, "signature algorithm id");
                    break;
                case KeySalt:
                    salt = ReadExactBytes(reader, SaltLength, "database salt");
                    break;
                case KeyRecipients:
                    recipients = ReadRecipients(reader);
                    break;
                case KeySignerPk:
                    signerPk = ReadBoundedBytes(reader, MaxVariableFieldLength, "signer public key");
                    break;
                case KeyRevision:
                    revision = reader.ReadInt64();
                    break;
                case KeySignature:
                    signature = ReadBoundedBytes(reader, MaxVariableFieldLength, "signature");
                    break;
                default:
                    throw new PqSqlCipherException($"Manifest: unknown field {key} is not permitted in version {CurrentVersion}.");
            }
        }
        reader.ReadEndMap();
        if (reader.BytesRemaining != 0)
            throw new PqSqlCipherException("Manifest: trailing bytes after CBOR document.");

        if (version != CurrentVersion)
            throw new PqSqlCipherException($"Unsupported manifest version {version}.");
        if (kemId is null || sigId is null || salt is null || signerPk is null || recipients is null)
            throw new PqSqlCipherException("Manifest is missing required fields.");
        if (revision < 1)
            throw new PqSqlCipherException("Manifest: revision must be present and >= 1.");
        if (mapCount == 8 && signature is null)
            throw new PqSqlCipherException("Manifest: 8 fields present but no signature field.");

        var manifest = new PqSqlCipherManifest
        {
            KemAlgorithmId = kemId,
            SignatureAlgorithmId = sigId,
            DatabaseSalt = salt,
            SignerPublicKey = signerPk,
        };
        manifest.Version = version;
        manifest.Revision = revision;
        manifest.Recipients.AddRange(recipients);
        manifest.Signature = signature;
        return manifest;
    }

    private static List<RecipientEntry> ReadRecipients(CborReader reader)
    {
        int count = (int)(reader.ReadStartArray()
            ?? throw new PqSqlCipherException("Manifest: indefinite-length recipient array not allowed."));
        if (count is < 1 or > MaxRecipients)
            throw new PqSqlCipherException($"Manifest: recipient count {count} outside accepted range 1..{MaxRecipients}.");

        var list = new List<RecipientEntry>(count);
        for (int i = 0; i < count; i++)
            list.Add(ReadRecipient(reader));
        reader.ReadEndArray();

        // Reject duplicate fingerprints — ambiguous recipient resolution is an attack surface.
        for (int i = 0; i < list.Count; i++)
            for (int j = i + 1; j < list.Count; j++)
                if (list[i].Fingerprint.AsSpan().SequenceEqual(list[j].Fingerprint))
                    throw new PqSqlCipherException("Manifest: duplicate recipient fingerprint.");
        return list;
    }

    private static RecipientEntry ReadRecipient(CborReader reader)
    {
        int? mapCountNullable = reader.ReadStartMap();
        if (mapCountNullable is not (5 or 7))
            throw new PqSqlCipherException($"Recipient: expected 5 (KEM) or 7 (passphrase) fields, got {mapCountNullable?.ToString() ?? "indefinite"}.");
        int mapCount = mapCountNullable.Value;

        var seen = new HashSet<int>();
        int type = 0;
        byte[]? fp = null, ctOrSalt = null, nonce = null, wrapped = null, kdfParams = null;
        string? kdfId = null;

        for (int i = 0; i < mapCount; i++)
        {
            int key = reader.ReadInt32();
            if (!seen.Add(key))
                throw new PqSqlCipherException($"Recipient: duplicate field {key}.");

            switch (key)
            {
                case RKeyType:        type = reader.ReadInt32(); break;
                case RKeyFingerprint: fp = ReadExactBytes(reader, FingerprintLength, "recipient fingerprint"); break;
                case RKeyCtOrSalt:    ctOrSalt = ReadBoundedBytes(reader, MaxVariableFieldLength, "KEM ciphertext / KDF salt"); break;
                case RKeyNonce:       nonce = ReadExactBytes(reader, NonceLength, "AES-GCM nonce"); break;
                case RKeyWrappedDek:  wrapped = ReadExactBytes(reader, WrappedDekLength, "wrapped DEK"); break;
                case RKeyKdfId:       kdfId = ReadBoundedText(reader, MaxKdfIdLength, "KDF id"); break;
                case RKeyKdfParams:   kdfParams = ReadBoundedBytes(reader, MaxKdfParametersLength, "KDF parameters"); break;
                default:
                    throw new PqSqlCipherException($"Recipient: unknown field {key} is not permitted in version {CurrentVersion}.");
            }
        }
        reader.ReadEndMap();

        if (fp is null || ctOrSalt is null || nonce is null || wrapped is null)
            throw new PqSqlCipherException("Recipient entry is missing required fields.");

        switch ((RecipientType)type)
        {
            case RecipientType.Kem:
                if (mapCount != 5 || kdfId is not null || kdfParams is not null)
                    throw new PqSqlCipherException("KEM recipient must have exactly fields 1-5 and no KDF fields.");
                break;
            case RecipientType.Passphrase:
                if (mapCount != 7 || kdfId is null || kdfParams is null)
                    throw new PqSqlCipherException("Passphrase recipient must have exactly fields 1-7 including KDF id and parameters.");
                if (ctOrSalt.Length != PassphraseSaltLength)
                    throw new PqSqlCipherException($"Passphrase recipient KDF salt must be exactly {PassphraseSaltLength} bytes.");
                break;
            default:
                throw new PqSqlCipherException($"Recipient: unknown type {type}.");
        }

        return new RecipientEntry
        {
            Type = (RecipientType)type,
            Fingerprint = fp,
            KemCiphertextOrSalt = ctOrSalt,
            Nonce = nonce,
            WrappedDek = wrapped,
            KdfId = kdfId,
            KdfParameters = kdfParams,
        };
    }

    private static byte[] ReadExactBytes(CborReader reader, int expectedLength, string fieldName)
    {
        byte[] value = reader.ReadByteString();
        if (value.Length != expectedLength)
            throw new PqSqlCipherException($"Manifest: {fieldName} must be exactly {expectedLength} bytes, got {value.Length}.");
        return value;
    }

    private static byte[] ReadBoundedBytes(CborReader reader, int maxLength, string fieldName)
    {
        byte[] value = reader.ReadByteString();
        if (value.Length is 0 || value.Length > maxLength)
            throw new PqSqlCipherException($"Manifest: {fieldName} length {value.Length} outside accepted range 1..{maxLength}.");
        return value;
    }

    private static string ReadBoundedText(CborReader reader, int maxLength, string fieldName)
    {
        string value = reader.ReadTextString();
        if (value.Length is 0 || value.Length > maxLength)
            throw new PqSqlCipherException($"Manifest: {fieldName} length outside accepted range 1..{maxLength}.");
        return value;
    }

    // ── File I/O (atomic) ─────────────────────────────────────────────────

    /// <summary>Return the primary sidecar path for <paramref name="databasePath"/> (<c>&lt;db&gt;.pqsm</c>).</summary>
    public static string SidecarPathFor(string databasePath) => databasePath + SidecarExtension;

    /// <summary>Pending manifest written BEFORE a DEK rotation rekeys the database — the crash-recovery anchor.</summary>
    public static string PendingSidecarPathFor(string databasePath) => databasePath + SidecarExtension + ".pending";

    /// <summary>Atomic write: temp file in the same directory, flushed to disk, then renamed over the target.</summary>
    public void Save(string databasePath) =>
        AtomicWrite(SidecarPathFor(databasePath), Serialize());

    /// <summary>Atomic write of the manifest to the <c>.pending</c> sidecar — the first phase of crash-safe rotation.</summary>
    public void SaveAsPending(string databasePath) =>
        AtomicWrite(PendingSidecarPathFor(databasePath), Serialize());

    internal static void AtomicWrite(string path, byte[] bytes)
    {
        string tmp = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best effort */ }
            throw;
        }
    }

    /// <summary>Load the primary sidecar for <paramref name="databasePath"/> and strict-parse it. Does NOT verify the signature; use a vault for that.</summary>
    public static PqSqlCipherManifest Load(string databasePath) =>
        LoadFromSidecar(SidecarPathFor(databasePath));

    /// <summary>Load and strict-parse a manifest from an arbitrary sidecar path. Does NOT verify the signature.</summary>
    public static PqSqlCipherManifest LoadFromSidecar(string sidecarPath)
    {
        if (!File.Exists(sidecarPath))
            throw new PqSqlCipherException($"Manifest sidecar not found: {sidecarPath}");
        return Deserialize(File.ReadAllBytes(sidecarPath));
    }
}

/// <summary>The exception type all PostQuantum.SqlCipher.Vault operations surface for trust-pin, parse, crypto, and I/O failures.</summary>
public sealed class PqSqlCipherException : Exception
{
    /// <summary>Construct an exception with a human-readable message.</summary>
    public PqSqlCipherException(string message) : base(message) { }

    /// <summary>Construct an exception wrapping an inner cause.</summary>
    public PqSqlCipherException(string message, Exception inner) : base(message, inner) { }
}
