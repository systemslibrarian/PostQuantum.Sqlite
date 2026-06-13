using System.Formats.Cbor;
using System.Security.Cryptography;
using PostQuantum.SqlCipher.Vault.Abstractions;

namespace PostQuantum.SqlCipher.Vault.Algorithms;

/// <summary>
/// ML-KEM-768 (FIPS 203) over the .NET 10 BCL.
/// NOTE: verify exact BCL method shapes against your installed SDK —
/// the PQC surface moved between .NET 10 previews and RTM. The intent
/// of each call is documented inline so adjustments are mechanical.
/// </summary>
public sealed class MlKem768Kem : IKemAlgorithm
{
    /// <inheritdoc />
    public string AlgorithmId => "ML-KEM-768";

    /// <inheritdoc />
    public int CiphertextSizeInBytes => MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;          // 1088
    /// <inheritdoc />
    public int EncapsulationKeySizeInBytes => MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes; // 1184

    /// <inheritdoc />
    public (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> encapsulationKey)
    {
        using MLKem kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKey);
        byte[] ciphertext = new byte[MLKemAlgorithm.MLKem768.CiphertextSizeInBytes];
        byte[] sharedSecret = new byte[MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes];
        kem.Encapsulate(ciphertext, sharedSecret);
        return (ciphertext, sharedSecret);
    }

    /// <inheritdoc />
    public byte[] Decapsulate(ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext)
    {
        using MLKem kem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, decapsulationKey);
        byte[] sharedSecret = new byte[MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes];
        kem.Decapsulate(ciphertext, sharedSecret);
        return sharedSecret;
    }

    /// <summary>Convenience: generate a fresh ML-KEM-768 key pair (encapsulation key, decapsulation key).</summary>
    public static (byte[] EncapsulationKey, byte[] DecapsulationKey) GenerateKeyPair()
    {
        using MLKem kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        return (kem.ExportEncapsulationKey(), kem.ExportDecapsulationKey());
    }
}

/// <summary>ML-DSA-65 (FIPS 204) over the .NET 10 BCL.</summary>
public sealed class MlDsa65Signer : ISignatureAlgorithm
{
    /// <inheritdoc />
    public string AlgorithmId => "ML-DSA-65";

    /// <inheritdoc />
    public int PublicKeySizeInBytes => MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes;  // 1952
    /// <inheritdoc />
    public int SignatureSizeInBytes => MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes;  // 3309

    /// <inheritdoc />
    public byte[] Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        using MLDsa dsa = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privateKey);
        byte[] signature = new byte[MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes];
        dsa.SignData(data, signature);
        return signature;
    }

    /// <inheritdoc />
    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using MLDsa dsa = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);
        return dsa.VerifyData(data, signature);
    }

    /// <summary>Convenience: generate a fresh ML-DSA-65 key pair (public key, private key).</summary>
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
        using MLDsa dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        return (dsa.ExportMLDsaPublicKey(), dsa.ExportMLDsaPrivateKey());
    }
}

/// <summary>
/// PBKDF2-SHA512 password KDF — the BCL-only default so the core package has
/// zero non-Microsoft dependencies. For production passphrase recipients,
/// prefer an Argon2id adapter (memory-hardness matters against GPU/ASIC attack).
/// </summary>
public sealed class Pbkdf2PasswordKdf : IPasswordKdf
{
    /// <summary>Default PBKDF2-SHA512 iteration count (OWASP-style guidance, 2025).</summary>
    public const int DefaultIterations = 600_000;
    private const int MinIterations = 1_000;
    private const int MaxIterations = 100_000_000;

    private readonly int _iterations;

    /// <summary>Construct a PBKDF2-SHA512 KDF with a custom iteration count (1_000–100_000_000).</summary>
    public Pbkdf2PasswordKdf(int iterations = DefaultIterations)
    {
        if (iterations is < MinIterations or > MaxIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        _iterations = iterations;
    }

    /// <inheritdoc />
    public string KdfId => "PBKDF2-SHA512";

    /// <inheritdoc />
    public byte[] SerializeParameters()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("iterations");
        writer.WriteInt32(_iterations);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <inheritdoc />
    public byte[] DeriveKey(ReadOnlySpan<char> passphrase, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> serializedParameters)
    {
        int iterations = _iterations;
        if (!serializedParameters.IsEmpty)
        {
            var reader = new CborReader(serializedParameters.ToArray(), CborConformanceMode.Canonical);
            reader.ReadStartMap();
            string key = reader.ReadTextString();
            if (key != "iterations")
                throw new PqSqlCipherException($"Unknown PBKDF2 parameter '{key}'.");
            iterations = reader.ReadInt32();
            reader.ReadEndMap();
            if (reader.BytesRemaining != 0)
                throw new PqSqlCipherException("Trailing bytes after PBKDF2 parameters.");
            if (iterations is < MinIterations or > MaxIterations)
                throw new PqSqlCipherException($"PBKDF2 iteration count {iterations} outside accepted range.");
        }

        // Encode chars directly to a zeroable byte buffer. passphrase.ToArray()
        // would allocate a char[] copy that the GC can never zero.
        int byteCount = System.Text.Encoding.UTF8.GetByteCount(passphrase);
        byte[] passphraseBytes = new byte[byteCount];
        try
        {
            System.Text.Encoding.UTF8.GetBytes(passphrase, passphraseBytes);
            return Rfc2898DeriveBytes.Pbkdf2(passphraseBytes, salt, iterations, HashAlgorithmName.SHA512, 32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }
}
