// QuickStart: walk through every headline feature of PostQuantum.SqlCipher.Vault
// end-to-end against a real SQLCipher database.
//
//   1. Create a database wrapped to Alice
//   2. Share with Bob (manifest-only; no DB rewrite)
//   3. Bob opens with his own key
//   4. Add a passphrase break-glass recipient
//   5. Rotate the DEK (scheduled rotation)
//   6. Revoke Bob (DEK rotates again; old DEK becomes useless)
//   7. Detect a rollback using the signed monotonic revision counter
//
// The sample runs against a fresh temp directory so it is idempotent — you
// can run it any number of times in a row without cleaning up state.

using PostQuantum.SqlCipher.Vault;
using PostQuantum.SqlCipher.Vault.Algorithms;

string workDir = Directory.CreateTempSubdirectory("pqsqlite-quickstart").FullName;
string dbPath  = Path.Combine(workDir, "prayers.db");

try
{
    // ── Generate keys (in production these live in your key store) ─────────
    var (aliceEk, aliceDk) = MlKem768Kem.GenerateKeyPair();
    var (signPk,  signSk)  = MlDsa65Signer.GenerateKeyPair();

    // The vault is constructed around ONE trusted signer key — the trust
    // anchor, distributed with your application like a root certificate.
    var vault = new PqSqlCipherVault(trustedSignerPublicKey: signPk);

    Console.WriteLine($"Working directory: {workDir}");

    // ── 1. Create the database (revision 1) ────────────────────────────────
    using (var conn = vault.Create(dbPath, [new KemRecipient(aliceEk)], signSk))
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE requests (id INTEGER PRIMARY KEY, request TEXT,
                                   created TEXT DEFAULT (datetime('now')));
            INSERT INTO requests (request) VALUES
                ('Wisdom for the Analyst III interview');
            """;
        cmd.ExecuteNonQuery();
    }
    Console.WriteLine($"  1. Created {Path.GetFileName(dbPath)}, wrapped to Alice (revision {PqSqlCipherManifest.Load(dbPath).Revision}).");

    // ── 2. Share with Bob (manifest-only; no DB rewrite) ───────────────────
    var (bobEk, bobDk) = MlKem768Kem.GenerateKeyPair();
    vault.AddRecipient(dbPath, new KemRecipient(bobEk), aliceDk, aliceEk, signSk);
    Console.WriteLine($"  2. Shared with Bob (revision {PqSqlCipherManifest.Load(dbPath).Revision}).");

    // ── 3. Bob opens with his own key ──────────────────────────────────────
    using (var conn = vault.Open(dbPath, bobDk, bobEk))
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT request FROM requests LIMIT 1;";
        Console.WriteLine($"  3. Bob reads: \"{cmd.ExecuteScalar()}\"");
    }

    // ── 4. Add a passphrase break-glass recipient ──────────────────────────
    //
    // PBKDF2 default uses 600k iterations for production. The sample drops
    // it to 50k purely for demo speed — DO NOT do this in real code.
    var demoKdf = new Pbkdf2PasswordKdf(iterations: 50_000);
    vault.AddPassphraseRecipient(dbPath, "correct horse battery staple",
                                 aliceDk, aliceEk, signSk, kdf: demoKdf);
    Console.WriteLine($"  4. Added passphrase recipient (revision {PqSqlCipherManifest.Load(dbPath).Revision}).");

    using (var conn = vault.OpenWithPassphrase(dbPath, "correct horse battery staple", kdf: demoKdf))
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT count(*) FROM requests;";
        Console.WriteLine($"     break-glass open OK ({cmd.ExecuteScalar()} row).");
    }

    // ── 5. Scheduled DEK rotation (rewrites every page) ────────────────────
    //
    // Snapshot the revision BEFORE rotation so we can demonstrate rollback
    // detection in step 7. In a real system, applications persist this
    // out-of-band (app config, registry, KMS metadata, server side).
    long preRotationRevision = PqSqlCipherManifest.Load(dbPath).Revision;
    // RotateDek requires the encapsulation key of every recipient who should
    // survive the rotation — fingerprints in the manifest are not enough,
    // because re-encapsulation needs the full public key. Pass Bob explicitly
    // so step 6 has something to revoke.
    vault.RotateDek(dbPath, aliceDk, aliceEk, signSk,
                    rewrapRecipients: [new KemRecipient(bobEk)]);
    Console.WriteLine($"  5. Rotated DEK (revision {PqSqlCipherManifest.Load(dbPath).Revision}). " +
                      "Passphrase entries are dropped by design — re-add if needed.");
    vault.AddPassphraseRecipient(dbPath, "correct horse battery staple",
                                 aliceDk, aliceEk, signSk, kdf: demoKdf);

    // ── 6. Revoke Bob — removal ALWAYS rotates the DEK ─────────────────────
    vault.RemoveRecipientAndRotate(dbPath, new KemRecipient(bobEk).Fingerprint,
                                   aliceDk, aliceEk, signSk);
    long postRevocationRevision = PqSqlCipherManifest.Load(dbPath).Revision;
    Console.WriteLine($"  6. Revoked Bob (revision {postRevocationRevision}). " +
                      "Bob's cached DEK is now useless.");

    try
    {
        vault.Open(dbPath, bobDk, bobEk).Dispose();
        Console.WriteLine("     UNEXPECTED: Bob still opens — this should never happen.");
    }
    catch (PqSqlCipherException)
    {
        Console.WriteLine("     Bob's revoked key correctly fails to open.");
    }

    // ── 7. Rollback detection ──────────────────────────────────────────────
    //
    // An attacker with filesystem access can restore an older validly-signed
    // (manifest, database) pair — a rollback that resurrects Bob's access.
    // The signed monotonic revision counter is the detection HOOK; the
    // application must compare it against the value it tracked out-of-band.
    vault.AddPassphraseRecipient(dbPath, "extra recipient just to bump revision",
                                 aliceDk, aliceEk, signSk, kdf: demoKdf);
    long currentRevision = PqSqlCipherManifest.Load(dbPath).Revision;

    // No minimum pinned → opens fine, regardless of which past revision is on disk:
    vault.Open(dbPath, aliceDk, aliceEk).Dispose();

    // With expectedMinimumRevision pinned, any rolled-back state is rejected:
    try
    {
        vault.Open(dbPath, aliceDk, aliceEk, expectedMinimumRevision: currentRevision + 1).Dispose();
        Console.WriteLine("  7. UNEXPECTED: rollback check did not fire.");
    }
    catch (PqSqlCipherException ex) when (ex.Message.Contains("rollback", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"  7. expectedMinimumRevision={currentRevision + 1} correctly rejects revision {currentRevision} as rollback.");
    }

    Console.WriteLine();
    Console.WriteLine($"Final state: manifest revision {currentRevision}, " +
                      $"started before rotation at {preRotationRevision}. " +
                      "Track the latest revision out-of-band to keep rollback detectable.");
}
finally
{
    try { Directory.Delete(workDir, recursive: true); } catch { /* best effort */ }
}
