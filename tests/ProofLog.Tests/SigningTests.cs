using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using ProofLog;
using Xunit;

namespace ProofLog.Tests;

// Keyed signing (v0.2) closes the one gap a bare hash chain has: an attacker with
// full database write access can rewrite the WHOLE chain (recomputing every hash)
// and a plain Verify() passes. With an HMAC signing key they can't, because they
// can't forge a valid MAC without the key.
public class SigningTests : IDisposable
{
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("super-secret-signing-key-v1");
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"prooflog-sig-{Guid.NewGuid():N}.db");

    private static AuditEntry E(string action, string? data = null) => new() { Actor = "alice", Action = action, Data = data };

    [Fact]
    public void Unsigned_records_have_no_mac()
    {
        var log = new InMemoryProofLog();
        Assert.Equal("", log.Append(E("a")).Mac);
        Assert.True(log.Verify().Ok);
    }

    [Fact]
    public void Signed_records_carry_a_mac_and_verify()
    {
        var log = new InMemoryProofLog(signingKey: Key);
        var r = log.Append(E("a"));
        Assert.NotEqual("", r.Mac);
        Assert.True(log.Verify().Ok);
    }

    [Fact]
    public void Signed_log_persists_and_reverifies_after_reopen()
    {
        using (var log = new SqliteProofLog(_path, signingKey: Key))
        {
            log.Append(E("login"));
            log.Append(E("payout", "{\"amt\":100}"));
        }
        using var reopened = new SqliteProofLog(_path, signingKey: Key);
        Assert.True(reopened.Verify().Ok);
        Assert.Equal(2, reopened.Count());
    }

    [Fact]
    public void Verifying_with_the_wrong_key_fails()
    {
        using (var log = new SqliteProofLog(_path, signingKey: Key)) log.Append(E("a"));
        using var wrong = new SqliteProofLog(_path, signingKey: Encoding.UTF8.GetBytes("attacker-key"));
        var v = wrong.Verify();
        Assert.False(v.Ok);
        Assert.Contains("MAC", v.Reason);
    }

    [Fact]
    public void Unsigned_log_does_NOT_catch_a_full_rewrite()
    {
        // Baseline: this is the gap signing closes. Forge the data AND recompute the
        // hash correctly; a plain (unsigned) chain still verifies.
        using (var log = new SqliteProofLog(_path)) { log.Append(E("a")); log.Append(E("payout", "{\"amt\":100}")); }
        ForgeRecord2DataAndHash("{\"amt\":999999}", signWithKey: null);
        using var reopened = new SqliteProofLog(_path);
        Assert.True(reopened.Verify().Ok);   // undetected without a key
    }

    [Fact]
    public void Signed_log_catches_a_full_rewrite()
    {
        using (var log = new SqliteProofLog(_path, signingKey: Key)) { log.Append(E("a")); log.Append(E("payout", "{\"amt\":100}")); }
        // Same forge as above (data + correct hash); the attacker even signs with
        // their own key - but they don't have the real key.
        ForgeRecord2DataAndHash("{\"amt\":999999}", signWithKey: Encoding.UTF8.GetBytes("attacker-key"));
        using var reopened = new SqliteProofLog(_path, signingKey: Key);
        var v = reopened.Verify();
        Assert.False(v.Ok);
        Assert.Equal(2, v.BrokenAtSeq);
        Assert.Contains("MAC", v.Reason);
    }

    // Rewrite record #2's data and recompute its (public) hash correctly, optionally
    // signing with a key the verifier does not trust.
    private void ForgeRecord2DataAndHash(string forgedData, byte[]? signWithKey)
    {
        using var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _path }.ToString());
        c.Open();
        string at, prev, actor, action;
        using (var read = c.CreateCommand())
        {
            read.CommandText = "SELECT At, PrevHash, Actor, Action FROM ProofRecords WHERE Seq = 2;";
            using var rr = read.ExecuteReader();
            rr.Read();
            at = rr.GetString(0); prev = rr.GetString(1); actor = rr.GetString(2); action = rr.GetString(3);
        }
        var forgedHash = Hashing.ComputeHash(prev, 2,
            DateTimeOffset.Parse(at, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            actor, action, null, forgedData);
        var forgedMac = signWithKey is null ? "" : Hashing.ComputeMac(signWithKey, forgedHash);
        using var upd = c.CreateCommand();
        upd.CommandText = "UPDATE ProofRecords SET Data = $d, Hash = $h, Mac = $m WHERE Seq = 2;";
        upd.Parameters.AddWithValue("$d", forgedData);
        upd.Parameters.AddWithValue("$h", forgedHash);
        upd.Parameters.AddWithValue("$m", forgedMac);
        upd.ExecuteNonQuery();
    }

    public void Dispose() { try { if (File.Exists(_path)) File.Delete(_path); } catch { } }
}
