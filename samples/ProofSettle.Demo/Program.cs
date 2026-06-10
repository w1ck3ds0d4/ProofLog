using System.Globalization;
using Microsoft.Data.Sqlite;
using ProofLog;

// ProofSettle - the settlement-evidence wedge, demonstrated on ProofLog.
//
// The pitch: an operator's own database is not an independent witness. When a player
// disputes "you voided my winning market", the operator's mutable logs can't *prove*
// how the market resolved against its stated rules - they could have been edited.
//
// ProofSettle records each resolution as an append-only, ECDSA-signed, hash-chained
// entry: who resolved which market, to which outcome, against which stated source.
// It NEVER moves money or holds keys - the operator's PAM settles and calls this to
// log it. Here we settle three mock markets, export an MGA-profiled evidence bundle a
// regulator can verify with only the public key, then tamper with one record in the
// raw database and watch verification fail at exactly that record.

var path = Path.Combine(Path.GetTempPath(), $"proofsettle-demo-{Guid.NewGuid():N}.db");
Console.WriteLine($"ProofSettle demo   (ledger: {path})\n");

// The operator keeps the PRIVATE key; the MGA / a player verifies with the PUBLIC key.
using var signer = EcdsaProofSigner.Create();
var publicKey = signer.ExportPublicKey();

var markets = new (string Id, string Question, string SourceRule, string Outcome, string Resolver)[]
{
    ("MKT-1041", "Will Malta host the 2027 iGaming Summit?", "Official MGA / SiGMA announcement", "YES", "ops.alice"),
    ("MKT-1042", "EUR/USD above 1.10 at 2026-06-30 close?", "ECB reference rate, 2026-06-30", "NO", "ops.bob"),
    ("MKT-1043", "Goatz weekly active users above 50k?", "Internal analytics snapshot, signed by the data lead", "YES", "ops.alice"),
};

Console.WriteLine("Settling markets (manual 4-eyes mode) and recording a signed resolution proof for each:\n");
using (var ledger = new SqliteProofLog(path, signer))
{
    foreach (var m in markets)
    {
        // The PAM would move the money here. ProofSettle only records HOW it resolved.
        var data = $"{{\"market\":\"{m.Id}\",\"outcome\":\"{m.Outcome}\",\"sourceRule\":\"{m.SourceRule}\"}}";
        var rec = ledger.Append(new AuditEntry
        {
            Actor = m.Resolver,
            Action = "market.resolve",
            Resource = m.Id,
            Data = data,
        });
        Console.WriteLine($"  {m.Id}  ->  {m.Outcome,-3}  resolved by {m.Resolver}  (seq #{rec.Seq}, signed {rec.Hash[..12]}...)");
    }

    Console.WriteLine($"\nLedger head (anchor): {ledger.Head()}");
    Console.WriteLine($"Verify (operator):    {(ledger.Verify().Ok ? "INTACT [OK]" : "TAMPERED [FAIL]")}");

    // The artifact handed to the MGA or a disputing player: an MGA-profiled, self-verifying bundle.
    var bundle = Evidence.ToJson(ledger, RegulatorProfiles.MgaGaming);
    File.WriteAllText("settlement-evidence.json", bundle);
    Console.WriteLine("Wrote settlement-evidence.json (MGA-profiled, signed, independently verifiable).");
}

// The whole point: an INDEPENDENT party verifies with only the public key - no trust in
// the operator required, and they cannot forge a record.
Console.WriteLine("\n--- A player disputes MKT-1041. They verify the trail with only the public key ---");
using (var auditor = EcdsaProofSigner.FromPublicKey(publicKey))
using (var review = new SqliteProofLog(path, auditor))
{
    var v = review.Verify();
    Console.WriteLine($"Independent verify (public key only): {(v.Ok ? $"INTACT [OK] ({v.Verified} resolutions)" : "FAIL")}");
}

// Now the operator quietly edits the database to flip a losing market to a win.
Console.WriteLine("\n--- Operator edits the database: flip MKT-1042 from NO to YES ---");
using (var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
{
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "UPDATE ProofRecords SET Data = $d WHERE Resource = 'MKT-1042';";
    cmd.Parameters.AddWithValue("$d", "{\"market\":\"MKT-1042\",\"outcome\":\"YES\",\"sourceRule\":\"ECB reference rate, 2026-06-30\"}");
    cmd.ExecuteNonQuery();
}

using (var auditor = EcdsaProofSigner.FromPublicKey(publicKey))
using (var review = new SqliteProofLog(path, auditor))
{
    var v = review.Verify();
    Console.WriteLine(v.Ok
        ? "Independent verify: INTACT [OK]   <-- this must never print"
        : $"Independent verify: TAMPERED [FAIL]   at resolution #{v.BrokenAtSeq} - {v.Reason}");
}

try { File.Delete(path); } catch { /* best effort */ }
Console.WriteLine("\nThe operator's own logs cannot do this. That independence is ProofSettle.");
