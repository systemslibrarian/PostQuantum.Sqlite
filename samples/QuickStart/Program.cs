using PostQuantum.Sqlite;
using PostQuantum.Sqlite.Algorithms;

// 1. Generate keys (in production these come from PostQuantum.KeyManagement / your key store)
var (aliceEk, aliceDk) = MlKem768Kem.GenerateKeyPair();   // ML-KEM-768 encaps/decaps keys
var (signPk, signSk)  = MlDsa65Signer.GenerateKeyPair();  // ML-DSA-65 manifest signing keys

// 2. The vault is constructed around the trust anchor — the ONE signer key
//    allowed to authorize recipients for this application's databases.
var vault = new PqSqliteVault(trustedSignerPublicKey: signPk);

// 3. Create an encrypted database wrapped to Alice (manifest revision 1)
using (var conn = vault.Create("prayers.db", new[] { new KemRecipient(aliceEk) }, signSk))
{
    using var cmd = conn.CreateCommand();
    cmd.CommandText = """
        CREATE TABLE requests (id INTEGER PRIMARY KEY, request TEXT, created TEXT DEFAULT (datetime('now')));
        INSERT INTO requests (request) VALUES ('Wisdom for the Analyst III interview');
        """;
    cmd.ExecuteNonQuery();
}

// 4. Share with Bob — manifest-only; signed by the pinned trust anchor
var (bobEk, bobDk) = MlKem768Kem.GenerateKeyPair();
vault.AddRecipient("prayers.db", new KemRecipient(bobEk), aliceDk, aliceEk, signSk);

// 5. Bob opens with his own key — signature, pin, and DB binding verified automatically
using (var conn = vault.Open("prayers.db", bobDk, bobEk))
{
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT request FROM requests;";
    Console.WriteLine($"Bob reads: {cmd.ExecuteScalar()}");
}

// 6. Revoke Bob — removes his entry AND rotates the DEK (crash-safe rekey)
vault.RemoveRecipientAndRotate("prayers.db", new KemRecipient(bobEk).Fingerprint, aliceDk, aliceEk, signSk);
long revision = PqSqliteManifest.Load("prayers.db").Revision;
Console.WriteLine($"Bob revoked; DEK rotated. Manifest at revision {revision} — store this out-of-band for rollback detection.");
