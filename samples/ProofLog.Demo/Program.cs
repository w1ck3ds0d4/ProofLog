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
Console.WriteLine("\nEdit the history, and verification fails at exactly the altered record. That's ProofLog.");
