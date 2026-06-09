namespace PostQuantum.Sqlite.Abstractions;

/// <summary>
/// Key encapsulation mechanism abstraction. The default implementation is
/// ML-KEM-768 via the .NET 10 BCL. Swap in X-Wing (ML-KEM-768 + X25519 hybrid)
/// by implementing this interface over your X-Wing primitive.
/// </summary>
public interface IKemAlgorithm
{
    /// <summary>Algorithm identifier stored in the manifest (e.g. "ML-KEM-768", "X-Wing").</summary>
    string AlgorithmId { get; }

    /// <summary>Exact KEM ciphertext length — used to validate manifest entries before any crypto runs.</summary>
    int CiphertextSizeInBytes { get; }

    /// <summary>Exact encapsulation (public) key length.</summary>
    int EncapsulationKeySizeInBytes { get; }

    /// <summary>Encapsulate to a recipient's public (encapsulation) key.</summary>
    /// <returns>The KEM ciphertext and the raw shared secret (NOT used directly as a KEK — see KekDerivation).</returns>
    (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> encapsulationKey);

    /// <summary>Decapsulate using the recipient's private (decapsulation) key.</summary>
    byte[] Decapsulate(ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext);
}

/// <summary>Signature abstraction. Default is ML-DSA-65 via the .NET 10 BCL.</summary>
public interface ISignatureAlgorithm
{
    /// <summary>Algorithm identifier stored in the manifest (e.g. "ML-DSA-65").</summary>
    string AlgorithmId { get; }

    /// <summary>Exact public key length — used to validate the manifest before verification.</summary>
    int PublicKeySizeInBytes { get; }

    /// <summary>Exact signature length — used to validate the manifest before verification.</summary>
    int SignatureSizeInBytes { get; }

    byte[] Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data);

    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}

/// <summary>
/// Password-based KDF abstraction for the passphrase recipient type.
/// Default is PBKDF2-SHA512 (BCL-only). Strongly consider substituting an
/// Argon2id implementation (e.g. Argon2id.PasswordHasher) in production.
/// </summary>
public interface IPasswordKdf
{
    /// <summary>KDF identifier stored in the manifest (e.g. "PBKDF2-SHA512", "Argon2id").</summary>
    string KdfId { get; }

    /// <summary>Serialized parameters (CBOR map bytes) needed to re-derive the key.</summary>
    byte[] SerializeParameters();

    /// <summary>Derive a 32-byte intermediate key from a passphrase (HKDF domain separation is applied on top).</summary>
    byte[] DeriveKey(ReadOnlySpan<char> passphrase, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> serializedParameters);
}
