using Microsoft.Data.Sqlite;
using ProofLog;
using Xunit;

namespace ProofLog.Tests;

// These prove the whole point: once written, history can't be altered without Verify
// catching it. We tamper with the raw SQLite file (the strongest attacker model: full
// DB write access) and confirm the chain detects every kind of change.
public class TamperTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"prooflog-{Guid.NewGuid():N}.db");

    private void Seed(int n = 4)
    {
        using var log = new SqliteProofLog(_path);
        for (var i = 0; i < n; i++)
            log.Append(new AuditEntry { Actor = "alice", Action = $"action{i}", Resource = "acct/1" });
    }

    private void Raw(string sql)
    {
        using var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _path }.ToString());
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    [Fact]
    public void Modifying_a_field_is_detected()
    {
        Seed();
        Raw("UPDATE ProofRecords SET Action = 'tampered' WHERE Seq = 2;");
        using var log = new SqliteProofLog(_path);
        var v = log.Verify();
        Assert.False(v.Ok);
        Assert.Equal(2, v.BrokenAtSeq);
        Assert.Contains("modified", v.Reason);
    }

    [Fact]
    public void Overwriting_a_stored_hash_is_detected()
    {
        Seed();
        Raw("UPDATE ProofRecords SET Hash = 'deadbeef' WHERE Seq = 2;");
        using var log = new SqliteProofLog(_path);
        var v = log.Verify();
        Assert.False(v.Ok);
        Assert.Equal(2, v.BrokenAtSeq);
    }

    [Fact]
    public void Deleting_a_record_is_detected()
    {
        Seed();
        Raw("DELETE FROM ProofRecords WHERE Seq = 2;");
        using var log = new SqliteProofLog(_path);
        var v = log.Verify();
        Assert.False(v.Ok);
        Assert.Equal(3, v.BrokenAtSeq); // the gap surfaces at the next record
        Assert.Contains("sequence", v.Reason);
    }

    [Fact]
    public void Reparenting_a_record_is_detected()
    {
        Seed();
        // Point record 3 at the genesis hash (as if rewriting its parent).
        Raw($"UPDATE ProofRecords SET PrevHash = '{Hashing.Genesis}' WHERE Seq = 3;");
        using var log = new SqliteProofLog(_path);
        var v = log.Verify();
        Assert.False(v.Ok);
        Assert.Equal(3, v.BrokenAtSeq);
    }

    [Fact]
    public void Tail_truncation_is_internally_consistent_so_head_must_be_anchored()
    {
        // Honest threat-model test: deleting the LAST record leaves a chain that is
        // still internally valid. That is why Head() is exposed - anchor it externally
        // (publish/notarize) to also detect truncation.
        string headBefore;
        using (var log = new SqliteProofLog(_path))
        {
            for (var i = 0; i < 4; i++) log.Append(new AuditEntry { Actor = "a", Action = $"x{i}" });
            headBefore = log.Head();
        }
        Raw("DELETE FROM ProofRecords WHERE Seq = 4;");
        using var reopened = new SqliteProofLog(_path);
        Assert.True(reopened.Verify().Ok);                 // internally consistent...
        Assert.NotEqual(headBefore, reopened.Head());       // ...but the anchored head changed
    }

    public void Dispose()
    {
        try { if (File.Exists(_path)) File.Delete(_path); } catch { /* best effort */ }
    }
}
