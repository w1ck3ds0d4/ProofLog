using Microsoft.Data.Sqlite;
using ProofLog;

// A 30-second tour of ProofLog: append a few audit events, verify the chain, then
// have an "attacker" rewrite history in the raw database and watch verification
// catch it at exactly the altered record.

var path = Path.Combine(Path.GetTempPath(), $"prooflog-demo-{Guid.NewGuid():N}.db");
Console.WriteLine($"ProofLog demo   (db: {path})\n");

using (var log = new SqliteProofLog(path))
{
    log.Append(new AuditEntry { Actor = "alice", Action = "user.login", Resource = "session/abc" });
    log.Append(new AuditEntry { Actor = "alice", Action = "config.update", Resource = "policy/aml-v3", Data = "{\"limit\":5000}" });
    log.Append(new AuditEntry { Actor = "bob", Action = "payout.approve", Resource = "payout/42", Data = "{\"amount\":1500}" });
    log.Append(new AuditEntry { Actor = "bob", Action = "user.logout", Resource = "session/def" });

    Console.WriteLine("Appended chain:");
    foreach (var r in log.Read())
        Console.WriteLine($"  #{r.Seq}  {r.At:u}  {r.Actor,-6} {r.Action,-16} {r.Hash[..12]}...");

    var v = log.Verify();
    Console.WriteLine($"\nVerify: {(v.Ok ? $"INTACT [OK]  ({v.Verified} records)" : "TAMPERED [FAIL]")}");
    Console.WriteLine($"Head (anchor this externally to also catch truncation): {log.Head()}");

    File.WriteAllText("evidence.json", Evidence.ToJson(log));
    Console.WriteLine("Wrote evidence.json - a self-verifying export an auditor can replay.");
}

Console.WriteLine("\n--- Attacker edits record #3 in the database: payout 1500 -> 999999 ---");
using (var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
{
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "UPDATE ProofRecords SET Data = '{\"amount\":999999}' WHERE Seq = 3;";
    cmd.ExecuteNonQuery();
}

using (var log = new SqliteProofLog(path))
{
    var v = log.Verify();
    Console.WriteLine(v.Ok
        ? "Verify: INTACT [OK]   <-- this should never print"
        : $"Verify: TAMPERED [FAIL]   at record #{v.BrokenAtSeq} - {v.Reason}");
}

try { File.Delete(path); } catch { /* best effort */ }

// --- Asymmetric signing (v0.3): the auditor verifies with only the public key ---
Console.WriteLine("\n--- Asymmetric signing: you sign with the private key, the auditor verifies with the public key ---");
var signedPath = Path.Combine(Path.GetTempPath(), $"prooflog-demo-ec-{Guid.NewGuid():N}.db");
using (var signer = EcdsaProofSigner.Create())
{
    var publicKey = signer.ExportPublicKey();

    using (var log = new SqliteProofLog(signedPath, signer))
    {
        log.Append(new AuditEntry { Actor = "alice", Action = "payout.approve", Resource = "payout/77", Data = "{\"amount\":2500}" });
        log.Append(new AuditEntry { Actor = "bob", Action = "config.update", Resource = "policy/aml-v4" });
    }
    Console.WriteLine($"Signed 2 records with a private key. Public key (share this): {publicKey[..24]}...");

    // The auditor holds ONLY the public key.
    using var auditor = EcdsaProofSigner.FromPublicKey(publicKey);
    using var review = new SqliteProofLog(signedPath, auditor);
    var av = review.Verify();
    Console.WriteLine($"Auditor verify (public key only): {(av.Ok ? $"INTACT [OK] ({av.Verified} records)" : "FAIL")}");
    try { review.Append(new AuditEntry { Actor = "mallory", Action = "payout.approve" }); }
    catch (InvalidOperationException) { Console.WriteLine("Auditor tried to append with the public key -> rejected (verify-only). Cannot forge."); }
}
try { File.Delete(signedPath); } catch { /* best effort */ }

Console.WriteLine("\nEdit the history, and verification fails at exactly the altered record. That's ProofLog.");
