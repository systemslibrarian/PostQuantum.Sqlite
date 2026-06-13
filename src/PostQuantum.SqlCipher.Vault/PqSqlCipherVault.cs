using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using PostQuantum.SqlCipher.Vault.Abstractions;
using PostQuantum.SqlCipher.Vault.Algorithms;
using PostQuantum.SqlCipher.Vault.Internal;

namespace PostQuantum.SqlCipher.Vault;

/// <summary>A KEM recipient to whom the DEK should be wrapped.</summary>
public sealed record KemRecipient(byte[] EncapsulationKey)
{
    private byte[]? _fingerprint;

    /// <summary>SHA-256 of the encapsulation key truncated to 16 bytes; cached on first access.</summary>
    public byte[] Fingerprint => _fingerprint ??= PqSqlCipherManifest.FingerprintOf(EncapsulationKey);
}

/// <summary>
/// Post-quantum key lifecycle around a SQLCipher-encrypted SQLite database.
///
/// Threat model (read this): SQLCipher's AES-256 page encryption is already
/// quantum-resistant (Grover halves it to ~128 effective bits — still safe).
/// What this class makes quantum-resistant is the KEY LIFECYCLE:
///   • Wrapping  — DEK keyed under ML-KEM-768 + HKDF-SHA256, not RSA/ECDH
///   • Sharing   — multi-recipient manifest entries, each PQ-encapsulated
///   • Signing   — manifest integrity under ML-DSA-65, not ECDSA
///
/// TRUST MODEL: the vault is constructed around ONE trusted signer public
/// key — the trust anchor, distributed with your application like a root
/// certificate. Every operation refuses manifests signed by any other key.
/// A manifest is never trusted merely because it verifies under its own
/// embedded key; that is self-attestation, not authority.
///
/// The unpinned escape hatch (<see cref="CreateUnpinned"/>) permits READ
/// operations only, accepts any internally-consistent manifest, and exists
/// for tooling/inspection scenarios. Mutating operations on an unpinned
/// vault always throw.
/// </summary>
public sealed class PqSqlCipherVault
{
    private readonly IKemAlgorithm _kem;
    private readonly ISignatureAlgorithm _signer;
    private readonly byte[]? _trustedSignerPublicKey;

    /// <summary>
    /// Construct a vault pinned to a trusted signer public key. All operations
    /// — including reads — refuse manifests signed by any other key.
    /// </summary>
    /// <param name="trustedSignerPublicKey">
    /// The ML-DSA-65 (or configured algorithm) public key of the sole
    /// authority allowed to sign manifests for the databases this vault
    /// touches. Distribute it with your application like a root certificate.
    /// </param>
    /// <param name="kem">KEM algorithm to use; defaults to ML-KEM-768.</param>
    /// <param name="signer">Signature algorithm to use; defaults to ML-DSA-65.</param>
    public PqSqlCipherVault(byte[] trustedSignerPublicKey, IKemAlgorithm? kem = null, ISignatureAlgorithm? signer = null)
    {
        ArgumentNullException.ThrowIfNull(trustedSignerPublicKey);
        _kem = kem ?? new MlKem768Kem();
        _signer = signer ?? new MlDsa65Signer();
        if (trustedSignerPublicKey.Length != _signer.PublicKeySizeInBytes)
            throw new PqSqlCipherException(
                $"Trusted signer public key length {trustedSignerPublicKey.Length} does not match {_signer.AlgorithmId} ({_signer.PublicKeySizeInBytes} bytes).");
        _trustedSignerPublicKey = trustedSignerPublicKey;
    }

    private PqSqlCipherVault(IKemAlgorithm? kem, ISignatureAlgorithm? signer)
    {
        _kem = kem ?? new MlKem768Kem();
        _signer = signer ?? new MlDsa65Signer();
        _trustedSignerPublicKey = null;
    }

    /// <summary>
    /// DELIBERATELY UNSAFE construction: no trust anchor. The returned vault
    /// can Open databases whose manifests verify under their own embedded
    /// signer key — which any attacker-authored manifest also does. Read
    /// operations only; all mutating operations throw. Intended for
    /// inspection tooling, never for production data paths.
    /// </summary>
    public static PqSqlCipherVault CreateUnpinned(IKemAlgorithm? kem = null, ISignatureAlgorithm? signer = null) =>
        new(kem, signer);

    /// <summary>True when this vault enforces a pinned trust anchor.</summary>
    public bool IsPinned => _trustedSignerPublicKey is not null;

    // ── Create ────────────────────────────────────────────────────────────

    /// <summary>
    /// Create a new SQLCipher database with a random 256-bit DEK, wrap that DEK
    /// to each recipient under the KEM (via HKDF-derived KEKs), and write a
    /// signed .pqsm manifest at revision 1. The manifest's signer is the
    /// vault's pinned trust anchor; the supplied private key must correspond
    /// to it. Returns an open connection (caller disposes).
    /// </summary>
    public SqliteConnection Create(
        string databasePath,
        IEnumerable<KemRecipient> recipients,
        byte[] signingPrivateKey)
    {
        byte[] signerPublicKey = RequirePinned("Create");
        VerifySigningKeyMatchesPin(signingPrivateKey);

        if (File.Exists(databasePath))
            throw new PqSqlCipherException($"Database already exists: {databasePath}");

        var recipientList = recipients.ToList();
        if (recipientList.Count == 0)
            throw new PqSqlCipherException("At least one recipient is required — otherwise nobody can ever open this database.");

        byte[] dek = RandomNumberGenerator.GetBytes(AesGcmKeyWrap.DekSize);
        SqliteConnection? conn = null;
        try
        {
            // 1. Create the encrypted database (writes header + salt to disk).
            conn = SqlCipherInterop.OpenWithRawKey(databasePath, dek);
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "CREATE TABLE IF NOT EXISTS __pq_sqlite_meta (k TEXT PRIMARY KEY, v TEXT);" +
                                  "INSERT OR REPLACE INTO __pq_sqlite_meta VALUES ('created_utc', datetime('now'));";
                cmd.ExecuteNonQuery();
            }

            // 2. Read the salt SQLCipher just wrote — the manifest binding value.
            byte[] salt = SqlCipherInterop.ReadDatabaseSalt(databasePath);

            // 3. Build, sign, and atomically save the manifest.
            var manifest = new PqSqlCipherManifest
            {
                KemAlgorithmId = _kem.AlgorithmId,
                SignatureAlgorithmId = _signer.AlgorithmId,
                DatabaseSalt = salt,
                SignerPublicKey = signerPublicKey,
            };
            foreach (var r in recipientList)
                manifest.Recipients.Add(WrapForRecipient(r, dek, salt));

            manifest.Sign(_signer, signingPrivateKey);
            manifest.Save(databasePath);

            return conn;
        }
        catch
        {
            conn?.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    // ── Open ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Verify the manifest (signature + trust pin + database binding +
    /// algorithm ids), decapsulate, derive the KEK via HKDF, unwrap the DEK,
    /// and return an open, key-verified connection. If the primary manifest
    /// fails its key check and a .pending manifest from an interrupted
    /// rotation exists, the pending manifest is tried and promoted on
    /// success (crash recovery).
    /// </summary>
    /// <param name="databasePath">Path to the SQLCipher database file.</param>
    /// <param name="decapsulationKey">Caller's KEM private (decapsulation) key.</param>
    /// <param name="encapsulationKey">Caller's KEM public (encapsulation) key, used to select the matching manifest entry.</param>
    /// <param name="expectedMinimumRevision">
    /// Optional rollback detection: rejects manifests whose revision is below
    /// the application's last known revision (track it out-of-band).
    /// </param>
    public SqliteConnection Open(
        string databasePath,
        byte[] decapsulationKey,
        byte[] encapsulationKey,
        long? expectedMinimumRevision = null)
    {
        var (manifest, dek) = ResolveManifestAndDek(databasePath, decapsulationKey, encapsulationKey);
        try
        {
            CheckRevision(manifest, expectedMinimumRevision);
            return OpenAndVerify(databasePath, dek);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>Open using a passphrase recipient entry. Only entries matching the supplied KDF's KdfId are attempted.</summary>
    public SqliteConnection OpenWithPassphrase(
        string databasePath,
        ReadOnlySpan<char> passphrase,
        IPasswordKdf? kdf = null,
        long? expectedMinimumRevision = null)
    {
        kdf ??= new Pbkdf2PasswordKdf();

        foreach (string sidecar in CandidateSidecars(databasePath))
        {
            PqSqlCipherManifest manifest;
            try { manifest = LoadAndVerify(databasePath, sidecar); }
            catch (PqSqlCipherException) when (sidecar != PqSqlCipherManifest.SidecarPathFor(databasePath)) { continue; }

            var passphraseEntries = manifest.Recipients.Where(r => r.Type == RecipientType.Passphrase).ToList();
            if (passphraseEntries.Count == 0)
                throw new PqSqlCipherException("Manifest has no passphrase recipients.");

            var matching = passphraseEntries.Where(r => r.KdfId == kdf.KdfId).ToList();
            if (matching.Count == 0)
                throw new PqSqlCipherException(
                    $"No passphrase entry uses KDF '{kdf.KdfId}'. Manifest entries use: {string.Join(", ", passphraseEntries.Select(r => r.KdfId).Distinct())}. " +
                    "Refusing to derive with a mismatched KDF.");

            foreach (var entry in matching)
            {
                byte[] derived = kdf.DeriveKey(passphrase, entry.KemCiphertextOrSalt, entry.KdfParameters ?? Array.Empty<byte>());
                byte[] kek = KekDerivation.DeriveKek(derived, manifest.DatabaseSalt, manifest.Version, kdf.KdfId, entry.Fingerprint);
                CryptographicOperations.ZeroMemory(derived);
                try
                {
                    byte[] dek = AesGcmKeyWrap.Unwrap(kek, entry.Nonce, entry.WrappedDek, manifest.DatabaseSalt, entry.Fingerprint);
                    try
                    {
                        CheckRevision(manifest, expectedMinimumRevision);
                        var conn = OpenAndVerify(databasePath, dek);
                        PromoteIfPending(databasePath, sidecar);
                        return conn;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(dek);
                    }
                }
                catch (PqSqlCipherException)
                {
                    // Wrong passphrase for this entry, or stale manifest; keep trying.
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }
        }
        throw new PqSqlCipherException("Passphrase did not unwrap any matching recipient entry.");
    }

    // ── Recipient management (manifest-only; cheap) ───────────────────────

    /// <summary>
    /// Wrap the DEK to a new KEM recipient. Requires an existing recipient's
    /// keys and the signing private key corresponding to the vault's pinned
    /// trust anchor. Touches only the manifest (atomic replace).
    /// </summary>
    public void AddRecipient(
        string databasePath,
        KemRecipient newRecipient,
        byte[] existingDecapsulationKey,
        byte[] existingEncapsulationKey,
        byte[] signingPrivateKey)
    {
        RequirePinned("AddRecipient");
        VerifySigningKeyMatchesPin(signingPrivateKey);
        ValidateEncapsulationKey(newRecipient.EncapsulationKey);

        var (manifest, dek) = ResolveManifestAndDek(databasePath, existingDecapsulationKey, existingEncapsulationKey);
        try
        {
            if (manifest.FindByFingerprint(newRecipient.Fingerprint) is not null)
                throw new PqSqlCipherException("Recipient already present in manifest.");

            manifest.Recipients.Add(WrapForRecipient(newRecipient, dek, manifest.DatabaseSalt));
            manifest.Revision++;
            manifest.Sign(_signer, signingPrivateKey);
            manifest.Save(databasePath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>Add a passphrase recipient (e.g. break-glass recovery). Same trust rules as AddRecipient.</summary>
    public void AddPassphraseRecipient(
        string databasePath,
        ReadOnlySpan<char> passphrase,
        byte[] existingDecapsulationKey,
        byte[] existingEncapsulationKey,
        byte[] signingPrivateKey,
        IPasswordKdf? kdf = null)
    {
        kdf ??= new Pbkdf2PasswordKdf();
        RequirePinned("AddPassphraseRecipient");
        VerifySigningKeyMatchesPin(signingPrivateKey);

        var (manifest, dek) = ResolveManifestAndDek(databasePath, existingDecapsulationKey, existingEncapsulationKey);
        try
        {
            byte[] salt = RandomNumberGenerator.GetBytes(PqSqlCipherManifest.PassphraseSaltLength);
            byte[] fingerprint = PqSqlCipherManifest.FingerprintOf(salt);
            byte[] kdfParams = kdf.SerializeParameters();
            if (kdfParams.Length == 0)
                throw new PqSqlCipherException(
                    "KDF parameters must be non-empty. A KDF with no parameters should serialize an empty CBOR map (0xA0).");
            byte[] derived = kdf.DeriveKey(passphrase, salt, kdfParams);
            byte[] kek = KekDerivation.DeriveKek(derived, manifest.DatabaseSalt, manifest.Version, kdf.KdfId, fingerprint);
            CryptographicOperations.ZeroMemory(derived);
            try
            {
                var (nonce, wrapped) = AesGcmKeyWrap.Wrap(kek, dek, manifest.DatabaseSalt, fingerprint);
                manifest.Recipients.Add(new RecipientEntry
                {
                    Type = RecipientType.Passphrase,
                    Fingerprint = fingerprint,
                    KemCiphertextOrSalt = salt,
                    Nonce = nonce,
                    WrappedDek = wrapped,
                    KdfId = kdf.KdfId,
                    KdfParameters = kdfParams,
                });
                manifest.Revision++;
                manifest.Sign(_signer, signingPrivateKey);
                manifest.Save(databasePath);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>
    /// Remove a recipient's manifest entry, then ROTATE THE DEK. Removal without
    /// rotation is security theater: the removed recipient may have cached the
    /// old DEK or kept a copy of the old manifest.
    /// </summary>
    public void RemoveRecipientAndRotate(
        string databasePath,
        byte[] removeFingerprint,
        byte[] authorizedDecapsulationKey,
        byte[] authorizedEncapsulationKey,
        byte[] signingPrivateKey,
        IEnumerable<KemRecipient>? remainingRecipients = null)
    {
        RequirePinned("RemoveRecipientAndRotate");
        VerifySigningKeyMatchesPin(signingPrivateKey);

        var (manifest, oldDek) = ResolveManifestAndDek(databasePath, authorizedDecapsulationKey, authorizedEncapsulationKey);
        try
        {
            if (manifest.FindByFingerprint(removeFingerprint) is null)
                throw new PqSqlCipherException("Fingerprint not found in manifest.");

            byte[] authorizedFp = PqSqlCipherManifest.FingerprintOf(authorizedEncapsulationKey);
            if (authorizedFp.AsSpan().SequenceEqual(removeFingerprint))
                throw new PqSqlCipherException("The authorizing key cannot remove itself.");

            var rewrap = (remainingRecipients ?? Enumerable.Empty<KemRecipient>())
                .Where(r => !r.Fingerprint.AsSpan().SequenceEqual(removeFingerprint));

            RotateDekCore(databasePath, manifest, oldDek, authorizedEncapsulationKey, signingPrivateKey, rewrap);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldDek);
        }
    }

    /// <summary>
    /// Rotate the DEK (compromise response / scheduled rotation). Because
    /// re-encapsulation requires each recipient's PUBLIC key — fingerprints in
    /// the manifest are not enough — pass the encapsulation keys of every
    /// recipient who should survive the rotation. The authorizing recipient is
    /// always re-added. Passphrase entries cannot be re-wrapped without the
    /// passphrase and must be re-added explicitly via AddPassphraseRecipient.
    ///
    /// Crash safety: the new manifest is durably written as a .pending sidecar
    /// BEFORE the database is rekeyed, then atomically promoted afterwards.
    /// A crash at any point leaves the database openable: either the primary
    /// manifest still matches (rekey hadn't happened) or Open recovers via
    /// the pending manifest and promotes it.
    /// </summary>
    public void RotateDek(
        string databasePath,
        byte[] authorizedDecapsulationKey,
        byte[] authorizedEncapsulationKey,
        byte[] signingPrivateKey,
        IEnumerable<KemRecipient>? rewrapRecipients = null)
    {
        RequirePinned("RotateDek");
        VerifySigningKeyMatchesPin(signingPrivateKey);

        var (manifest, oldDek) = ResolveManifestAndDek(databasePath, authorizedDecapsulationKey, authorizedEncapsulationKey);
        try
        {
            RotateDekCore(databasePath, manifest, oldDek, authorizedEncapsulationKey, signingPrivateKey,
                          rewrapRecipients ?? Enumerable.Empty<KemRecipient>());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldDek);
        }
    }

    // ── Internals ─────────────────────────────────────────────────────────

    private void RotateDekCore(
        string databasePath,
        PqSqlCipherManifest current,
        byte[] oldDek,
        byte[] authorizedEncapsulationKey,
        byte[] signingPrivateKey,
        IEnumerable<KemRecipient> rewrapRecipients)
    {
        byte[] newDek = RandomNumberGenerator.GetBytes(AesGcmKeyWrap.DekSize);
        try
        {
            // 1. Build + sign the post-rotation manifest. sqlite3_rekey preserves
            //    the file salt, so the binding value carries over.
            var next = new PqSqlCipherManifest
            {
                KemAlgorithmId = current.KemAlgorithmId,
                SignatureAlgorithmId = current.SignatureAlgorithmId,
                DatabaseSalt = current.DatabaseSalt,
                SignerPublicKey = current.SignerPublicKey,
            };
            next.Revision = current.Revision + 1;

            var self = new KemRecipient(authorizedEncapsulationKey);
            next.Recipients.Add(WrapForRecipient(self, newDek, next.DatabaseSalt));
            foreach (var recipient in rewrapRecipients)
            {
                ValidateEncapsulationKey(recipient.EncapsulationKey);
                if (next.FindByFingerprint(recipient.Fingerprint) is not null) continue; // skip self/dupes
                next.Recipients.Add(WrapForRecipient(recipient, newDek, next.DatabaseSalt));
            }
            next.Sign(_signer, signingPrivateKey);

            // 2. Durably persist the pending manifest BEFORE touching the database.
            next.SaveAsPending(databasePath);

            // 3. Rekey the database. If this throws, the pending file is removed
            //    and the primary manifest still matches the (un-rekeyed) DB.
            try
            {
                using var conn = SqlCipherInterop.OpenWithRawKey(databasePath, oldDek);
                SqlCipherInterop.VerifyKeyWorks(conn);
                SqlCipherInterop.Rekey(conn, newDek);
            }
            catch
            {
                TryDelete(PqSqlCipherManifest.PendingSidecarPathFor(databasePath));
                throw;
            }

            // 4. Promote: atomic replace of primary with pending. A crash between
            //    3 and 4 is recovered by Open's pending-manifest fallback.
            PromotePending(databasePath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(newDek);
        }
    }

    /// <summary>
    /// Resolve the live manifest and recover the DEK, with crash recovery:
    /// try the primary sidecar first, proving the DEK against the actual
    /// database; if that fails and a pending sidecar exists, try it and
    /// promote it on success. Stale pending files (rotation crashed before
    /// rekey) are cleaned up when the primary proves correct.
    /// </summary>
    private (PqSqlCipherManifest Manifest, byte[] Dek) ResolveManifestAndDek(
        string databasePath, byte[] decapsulationKey, byte[] encapsulationKey)
    {
        if (!File.Exists(databasePath))
            throw new PqSqlCipherException($"Database not found: {databasePath}");

        string primaryPath = PqSqlCipherManifest.SidecarPathFor(databasePath);
        string pendingPath = PqSqlCipherManifest.PendingSidecarPathFor(databasePath);
        PqSqlCipherException? primaryFailure = null;

        foreach (string sidecar in CandidateSidecars(databasePath))
        {
            bool isPrimary = sidecar == primaryPath;
            try
            {
                var manifest = LoadAndVerify(databasePath, sidecar);
                byte[] dek = RecoverDek(manifest, decapsulationKey, encapsulationKey);
                try
                {
                    using var probe = SqlCipherInterop.OpenWithRawKey(databasePath, dek);
                    SqlCipherInterop.VerifyKeyWorks(probe);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(dek);
                    throw;
                }

                if (isPrimary)
                    TryDelete(pendingPath);          // rotation crashed before rekey — pending is stale
                else
                    PromotePending(databasePath);    // rotation crashed after rekey — pending is live

                return (manifest, dek);
            }
            catch (PqSqlCipherException ex)
            {
                if (isPrimary) primaryFailure = ex;
                if (!File.Exists(pendingPath)) throw;
                // fall through to the pending candidate
            }
        }

        throw new PqSqlCipherException(
            "Could not resolve a working manifest: primary failed and pending manifest (if any) also failed.",
            primaryFailure ?? new PqSqlCipherException("No candidate sidecars."));
    }

    private static IEnumerable<string> CandidateSidecars(string databasePath)
    {
        yield return PqSqlCipherManifest.SidecarPathFor(databasePath);
        string pending = PqSqlCipherManifest.PendingSidecarPathFor(databasePath);
        if (File.Exists(pending)) yield return pending;
    }

    private static void PromotePending(string databasePath)
    {
        string pending = PqSqlCipherManifest.PendingSidecarPathFor(databasePath);
        if (File.Exists(pending))
            File.Move(pending, PqSqlCipherManifest.SidecarPathFor(databasePath), overwrite: true);
    }

    private static void PromoteIfPending(string databasePath, string sidecarUsed)
    {
        if (sidecarUsed == PqSqlCipherManifest.PendingSidecarPathFor(databasePath))
            PromotePending(databasePath);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best effort */ }
    }

    private static SqliteConnection OpenAndVerify(string databasePath, byte[] dek)
    {
        var conn = SqlCipherInterop.OpenWithRawKey(databasePath, dek);
        try
        {
            SqlCipherInterop.VerifyKeyWorks(conn);
            return conn;
        }
        catch
        {
            conn.Dispose();
            throw;
        }
    }

    private static void CheckRevision(PqSqlCipherManifest manifest, long? expectedMinimumRevision)
    {
        if (expectedMinimumRevision is long min && manifest.Revision < min)
            throw new PqSqlCipherException(
                $"Manifest revision {manifest.Revision} is below the expected minimum {min}. " +
                "Possible rollback attack: an older validly-signed manifest may have been substituted.");
    }

    /// <summary>Mutations require a trust anchor. There is deliberately no way around this.</summary>
    private byte[] RequirePinned(string operation) =>
        _trustedSignerPublicKey
        ?? throw new PqSqlCipherException(
            $"{operation} requires a pinned trust anchor. Construct the vault with the trusted signer " +
            "public key: new PqSqlCipherVault(trustedSignerPublicKey). Unpinned vaults are read-only by design.");

    /// <summary>Prove the signing private key corresponds to the pinned trust anchor before re-signing anything.</summary>
    private void VerifySigningKeyMatchesPin(byte[] signingPrivateKey)
    {
        byte[] pin = _trustedSignerPublicKey!;
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] sig = _signer.Sign(signingPrivateKey, challenge);
        if (!_signer.Verify(pin, challenge, sig))
            throw new PqSqlCipherException(
                "Signing private key does not correspond to the pinned trust anchor. " +
                "Refusing to re-sign — this would either fail trust pinning later or silently change the trust anchor.");
    }

    private void ValidateEncapsulationKey(byte[] encapsulationKey)
    {
        if (encapsulationKey.Length != _kem.EncapsulationKeySizeInBytes)
            throw new PqSqlCipherException(
                $"Encapsulation key length {encapsulationKey.Length} does not match {_kem.AlgorithmId} ({_kem.EncapsulationKeySizeInBytes} bytes).");
    }

    private RecipientEntry WrapForRecipient(KemRecipient recipient, byte[] dek, byte[] databaseSalt)
    {
        ValidateEncapsulationKey(recipient.EncapsulationKey);
        var (ciphertext, sharedSecret) = _kem.Encapsulate(recipient.EncapsulationKey);
        byte[] fingerprint = recipient.Fingerprint;
        byte[] kek = KekDerivation.DeriveKek(sharedSecret, databaseSalt, PqSqlCipherManifest.CurrentVersion, _kem.AlgorithmId, fingerprint);
        CryptographicOperations.ZeroMemory(sharedSecret);
        try
        {
            var (nonce, wrapped) = AesGcmKeyWrap.Wrap(kek, dek, databaseSalt, fingerprint);
            return new RecipientEntry
            {
                Type = RecipientType.Kem,
                Fingerprint = fingerprint,
                KemCiphertextOrSalt = ciphertext,
                Nonce = nonce,
                WrappedDek = wrapped,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private byte[] RecoverDek(PqSqlCipherManifest manifest, byte[] decapsulationKey, byte[] encapsulationKey)
    {
        byte[] fingerprint = PqSqlCipherManifest.FingerprintOf(encapsulationKey);
        var entry = manifest.FindByFingerprint(fingerprint)
            ?? throw new PqSqlCipherException("This key is not a recipient of this database.");
        if (entry.Type != RecipientType.Kem)
            throw new PqSqlCipherException("Manifest entry for this fingerprint is not a KEM recipient.");
        if (entry.KemCiphertextOrSalt.Length != _kem.CiphertextSizeInBytes)
            throw new PqSqlCipherException($"KEM ciphertext length does not match {_kem.AlgorithmId}.");

        byte[] sharedSecret = _kem.Decapsulate(decapsulationKey, entry.KemCiphertextOrSalt);
        byte[] kek = KekDerivation.DeriveKek(sharedSecret, manifest.DatabaseSalt, manifest.Version, _kem.AlgorithmId, fingerprint);
        CryptographicOperations.ZeroMemory(sharedSecret);
        try
        {
            return AesGcmKeyWrap.Unwrap(kek, entry.Nonce, entry.WrappedDek, manifest.DatabaseSalt, fingerprint);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// Load a manifest from a specific sidecar and verify: strict parse,
    /// algorithm id enforcement (KEM and signature), per-algorithm length
    /// enforcement, trust-anchor pinning (when the vault is pinned), salt
    /// binding, and signature.
    /// </summary>
    private PqSqlCipherManifest LoadAndVerify(string databasePath, string sidecarPath)
    {
        var manifest = PqSqlCipherManifest.LoadFromSidecar(sidecarPath);

        if (manifest.KemAlgorithmId != _kem.AlgorithmId)
            throw new PqSqlCipherException($"Manifest uses KEM '{manifest.KemAlgorithmId}' but this vault is configured for '{_kem.AlgorithmId}'.");
        if (manifest.SignatureAlgorithmId != _signer.AlgorithmId)
            throw new PqSqlCipherException($"Manifest uses signature algorithm '{manifest.SignatureAlgorithmId}' but this vault is configured for '{_signer.AlgorithmId}'.");

        foreach (var r in manifest.Recipients.Where(r => r.Type == RecipientType.Kem))
            if (r.KemCiphertextOrSalt.Length != _kem.CiphertextSizeInBytes)
                throw new PqSqlCipherException($"Manifest contains a KEM ciphertext whose length does not match {_kem.AlgorithmId}.");

        if (_trustedSignerPublicKey is not null &&
            !_trustedSignerPublicKey.AsSpan().SequenceEqual(manifest.SignerPublicKey))
            throw new PqSqlCipherException("Manifest signer public key does not match the pinned trust anchor.");

        byte[] actualSalt = SqlCipherInterop.ReadDatabaseSalt(databasePath);
        manifest.Verify(_signer, actualSalt);
        return manifest;
    }
}
