using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace PostQuantum.SqlCipher.Vault.Internal;

/// <summary>
/// HKDF-SHA256 domain-separated KEK derivation. KEM shared secrets (and
/// passphrase-KDF outputs) are never used directly as AES keys: the KEK is
/// bound to the protocol label, manifest version, database salt, algorithm
/// identifier, and recipient fingerprint, so a shared secret reused in any
/// other context derives an unrelated key.
/// </summary>
internal static class KekDerivation
{
    // Frozen wire-format constant — do NOT change with package renames.
    // This label is mixed into the HKDF info for every wrapped DEK, so altering
    // it would re-derive a different KEK and make every existing on-disk vault
    // (and the v1 test vectors) un-openable. The original package name is
    // retained here deliberately for backward compatibility.
    private const string Label = "PostQuantum.Sqlite/kek";

    public static byte[] DeriveKek(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> databaseSalt,
        int manifestVersion,
        string algorithmId,
        ReadOnlySpan<byte> recipientFingerprint)
    {
        byte[] algIdBytes = Encoding.UTF8.GetBytes(algorithmId);

        // info = label || 0x00 || version (4 bytes BE) || 0x00 || algId || 0x00 || fingerprint
        byte[] labelBytes = Encoding.UTF8.GetBytes(Label);
        byte[] info = new byte[labelBytes.Length + 1 + 4 + 1 + algIdBytes.Length + 1 + recipientFingerprint.Length];
        int offset = 0;
        labelBytes.CopyTo(info, offset); offset += labelBytes.Length;
        info[offset++] = 0x00;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(info.AsSpan(offset, 4), manifestVersion); offset += 4;
        info[offset++] = 0x00;
        algIdBytes.CopyTo(info, offset); offset += algIdBytes.Length;
        info[offset++] = 0x00;
        recipientFingerprint.CopyTo(info.AsSpan(offset));

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial.ToArray(), 32, salt: databaseSalt.ToArray(), info: info);
    }
}

/// <summary>
/// AES-256-GCM wrap/unwrap of the 32-byte DEK. The AAD binds each wrapped copy
/// to (database salt || recipient fingerprint) so a wrapped DEK can't be
/// transplanted between manifests or recipients without detection.
/// </summary>
internal static class AesGcmKeyWrap
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int DekSize = 32;

    public static (byte[] Nonce, byte[] WrappedDek) Wrap(
        ReadOnlySpan<byte> kek, ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> databaseSalt, ReadOnlySpan<byte> recipientFingerprint)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] output = new byte[dek.Length + TagSize];

        using var gcm = new AesGcm(kek, TagSize);
        gcm.Encrypt(nonce, dek, output.AsSpan(0, dek.Length), output.AsSpan(dek.Length, TagSize),
                    BuildAad(databaseSalt, recipientFingerprint));
        return (nonce, output);
    }

    public static byte[] Unwrap(
        ReadOnlySpan<byte> kek, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> wrappedDek,
        ReadOnlySpan<byte> databaseSalt, ReadOnlySpan<byte> recipientFingerprint)
    {
        if (wrappedDek.Length != DekSize + TagSize)
            throw new PqSqlCipherException("Wrapped DEK has unexpected length.");

        byte[] dek = new byte[DekSize];
        using var gcm = new AesGcm(kek, TagSize);
        try
        {
            gcm.Decrypt(nonce, wrappedDek[..DekSize], wrappedDek[DekSize..], dek,
                        BuildAad(databaseSalt, recipientFingerprint));
        }
        catch (AuthenticationTagMismatchException ex)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new PqSqlCipherException(
                "DEK unwrap failed (GCM tag mismatch). Wrong key, or wrapped DEK was tampered with or transplanted.", ex);
        }
        return dek;
    }

    private static byte[] BuildAad(ReadOnlySpan<byte> databaseSalt, ReadOnlySpan<byte> fingerprint)
    {
        byte[] aad = new byte[databaseSalt.Length + fingerprint.Length];
        databaseSalt.CopyTo(aad);
        fingerprint.CopyTo(aad.AsSpan(databaseSalt.Length));
        return aad;
    }
}

/// <summary>
/// SQLCipher interop. Keys are applied through the native sqlite3_key /
/// sqlite3_rekey entry points with the raw-key spec ("x'HEX'") built in a
/// zeroable byte buffer — never materialized as an immutable managed string
/// (PRAGMA command text would pin the hex key in managed memory until GC,
/// and strings can never be zeroed). SQLCipher itself necessarily retains
/// key material internally while the connection is open; see README threat
/// model for residual exposure.
/// </summary>
internal static class SqlCipherInterop
{
    public const int SaltSize = 16;

    static SqlCipherInterop() => SQLitePCL.Batteries_V2.Init();

    /// <summary>Open a connection and apply the raw 32-byte DEK via the native key API.</summary>
    public static SqliteConnection OpenWithRawKey(string databasePath, ReadOnlySpan<byte> dek)
    {
        // Pooling=False: a pooled SQLCipher connection would retain the DEK in
        // the cached native handle and hand a pre-authenticated database to the
        // next pool consumer. Also lets Dispose() actually release the file lock.
        var conn = new SqliteConnection($"Data Source={databasePath};Pooling=False");
        conn.Open();
        try
        {
            ApplyKey(conn, dek, rekey: false);
            return conn;
        }
        catch
        {
            conn.Dispose();
            throw;
        }
    }

    /// <summary>Re-encrypt every page under a new raw DEK (sqlite3_rekey). Expensive; full DB rewrite.</summary>
    public static void Rekey(SqliteConnection openConnection, ReadOnlySpan<byte> newDek) =>
        ApplyKey(openConnection, newDek, rekey: true);

    private static void ApplyKey(SqliteConnection conn, ReadOnlySpan<byte> dek, bool rekey)
    {
        if (dek.Length != AesGcmKeyWrap.DekSize)
            throw new PqSqlCipherException("DEK must be exactly 32 bytes.");

        byte[] keySpec = BuildRawKeySpec(dek); // ASCII bytes of x'HEX' — zeroed below
        try
        {
            var handle = conn.Handle
                ?? throw new PqSqlCipherException("Connection has no native handle (is it open?).");
            int rc = rekey
                ? SQLitePCL.raw.sqlite3_rekey(handle, keySpec)
                : SQLitePCL.raw.sqlite3_key(handle, keySpec);
            if (rc != SQLitePCL.raw.SQLITE_OK)
                throw new PqSqlCipherException($"sqlite3_{(rekey ? "rekey" : "key")} failed with result code {rc}.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keySpec);
        }
    }

    /// <summary>Build the SQLCipher raw-key spec x'HEX' as ASCII bytes without any intermediate string.</summary>
    private static byte[] BuildRawKeySpec(ReadOnlySpan<byte> dek)
    {
        ReadOnlySpan<byte> hex = "0123456789ABCDEF"u8;
        byte[] spec = new byte[3 + dek.Length * 2];
        spec[0] = (byte)'x';
        spec[1] = (byte)'\'';
        for (int i = 0; i < dek.Length; i++)
        {
            spec[2 + 2 * i] = hex[dek[i] >> 4];
            spec[3 + 2 * i] = hex[dek[i] & 0xF];
        }
        spec[^1] = (byte)'\'';
        return spec;
    }

    /// <summary>Throws unless the key actually decrypts the database (forces a header read).</summary>
    public static void VerifyKeyWorks(SqliteConnection openConnection)
    {
        try
        {
            using var cmd = openConnection.CreateCommand();
            cmd.CommandText = "SELECT count(*) FROM sqlite_master;";
            cmd.ExecuteScalar();
        }
        catch (SqliteException ex)
        {
            throw new PqSqlCipherException("Database key check failed — wrong DEK or file is not a SQLCipher database.", ex);
        }
    }

    /// <summary>
    /// Read the SQLCipher salt: the first 16 bytes of the database file, stored
    /// in plaintext. This is the binding value between database and manifest.
    /// </summary>
    public static byte[] ReadDatabaseSalt(string databasePath)
    {
        // FileShare.ReadWrite | Delete: an open SqliteConnection holds the
        // file on Windows; without share flags File.OpenRead returns
        // "in use by another process" even though SQLite permits shared reads.
        using var fs = new FileStream(
            databasePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        byte[] salt = new byte[SaltSize];
        fs.ReadExactly(salt);
        return salt;
    }
}
