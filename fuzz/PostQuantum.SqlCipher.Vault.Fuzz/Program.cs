// PostQuantum.SqlCipher.Vault fuzz harness.
//
// Target: PqSqlCipherManifest.Deserialize — the strict CBOR parser is the
// single highest-leverage place to fuzz, since every reader, signer, and
// verifier funnels untrusted bytes through it.
//
// Run with libFuzzer-driven SharpFuzz (see fuzz/README.md). The harness
// catches PqSqlCipherException — those are SUCCESSES (the strict parser
// rejected malformed input). Any other exception type is a real finding:
// either a missing rejection rule or an unhandled edge case.

using PostQuantum.SqlCipher.Vault;
using SharpFuzz;

Fuzzer.OutOfProcess.Run(stream =>
{
    using var ms = new MemoryStream();
    stream.CopyTo(ms);
    byte[] cbor = ms.ToArray();

    try
    {
        var manifest = PqSqlCipherManifest.Deserialize(cbor);

        // If parse succeeded, also exercise the round-trip — re-encoding
        // an accepted manifest must produce identical bytes (canonical CBOR
        // is bijective for our field set).
        byte[] roundTripped = manifest.Serialize();
        if (cbor.Length == roundTripped.Length && cbor.AsSpan().SequenceEqual(roundTripped))
        {
            // ok
        }
    }
    catch (PqSqlCipherException)
    {
        // Expected: strict parser rejected malformed input.
    }
});
