using ProofLog;
using Xunit;

namespace ProofLog.Tests;

public class ChainTests
{
    private static AuditEntry Entry(string action) => new() { Actor = "alice", Action = action, Resource = "acct/1", Data = "{}" };

    [Fact]
    public void Append_assigns_contiguous_seq_and_chains_prev_hash()
    {
        var log = new InMemoryProofLog();
        var r1 = log.Append(Entry("a"));
        var r2 = log.Append(Entry("b"));
        var r3 = log.Append(Entry("c"));

        Assert.Equal(1, r1.Seq);
        Assert.Equal(2, r2.Seq);
        Assert.Equal(3, r3.Seq);
        Assert.Equal(Hashing.Genesis, r1.PrevHash);
        Assert.Equal(r1.Hash, r2.PrevHash);
        Assert.Equal(r2.Hash, r3.PrevHash);
        Assert.Equal(r3.Hash, log.Head());
        Assert.Equal(3, log.Count());
    }

    [Fact]
    public void Append_requires_actor()
    {
        var log = new InMemoryProofLog();
        Assert.Throws<ArgumentException>(() => log.Append(new AuditEntry { Actor = "", Action = "x" }));
    }

    [Fact]
    public void Append_requires_action()
    {
        var log = new InMemoryProofLog();
        Assert.Throws<ArgumentException>(() => log.Append(new AuditEntry { Actor = "a", Action = "" }));
    }

    [Fact]
    public void Fresh_log_verifies()
    {
        var log = new InMemoryProofLog();
        for (var i = 0; i < 25; i++) log.Append(Entry($"a{i}"));
        var v = log.Verify();
        Assert.True(v.Ok);
        Assert.Equal(25, v.Verified);
        Assert.Null(v.BrokenAtSeq);
    }

    [Fact]
    public void Empty_log_verifies()
    {
        var v = new InMemoryProofLog().Verify();
        Assert.True(v.Ok);
        Assert.Equal(0, v.Verified);
    }

    [Fact]
    public void Read_range_honours_from_and_limit()
    {
        var log = new InMemoryProofLog();
        for (var i = 0; i < 10; i++) log.Append(Entry($"a{i}"));
        var page = log.Read(fromSeq: 4, limit: 3);
        Assert.Equal(new long[] { 4, 5, 6 }, page.Select(r => r.Seq).ToArray());
    }

    [Fact]
    public void Same_clock_and_inputs_produce_identical_hashes()
    {
        var fixedAt = new DateTimeOffset(2026, 6, 8, 12, 0, 0, TimeSpan.Zero);
        var a = new InMemoryProofLog(() => fixedAt);
        var b = new InMemoryProofLog(() => fixedAt);
        for (var i = 0; i < 5; i++) { a.Append(Entry($"a{i}")); b.Append(Entry($"a{i}")); }
        Assert.Equal(a.Head(), b.Head());
        Assert.Equal(a.Read().Select(r => r.Hash), b.Read().Select(r => r.Hash));
    }

    [Fact]
    public void Sqlite_and_inmemory_stores_produce_identical_hashes()
    {
        var fixedAt = new DateTimeOffset(2026, 6, 8, 12, 0, 0, TimeSpan.Zero);
        var mem = new InMemoryProofLog(() => fixedAt);
        using var sql = new SqliteProofLog(":memory:", () => fixedAt);
        for (var i = 0; i < 5; i++) { mem.Append(Entry($"a{i}")); sql.Append(Entry($"a{i}")); }
        Assert.Equal(mem.Head(), sql.Head());
        Assert.Equal(mem.Read().Select(r => r.Hash), sql.Read().Select(r => r.Hash));
        Assert.True(sql.Verify().Ok);
    }
}
