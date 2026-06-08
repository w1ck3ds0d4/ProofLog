using System.Text.Json;
using ProofLog;
using Xunit;

namespace ProofLog.Tests;

public class EvidenceTests
{
    [Fact]
    public void Export_is_valid_json_with_head_count_and_verification()
    {
        var log = new InMemoryProofLog();
        for (var i = 0; i < 3; i++) log.Append(new AuditEntry { Actor = "alice", Action = $"a{i}" });

        var json = Evidence.ToJson(log);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal(3, root.GetProperty("count").GetInt64());
        Assert.Equal(log.Head(), root.GetProperty("head").GetString());
        Assert.True(root.GetProperty("verification").GetProperty("ok").GetBoolean());
        Assert.Equal(3, root.GetProperty("records").GetArrayLength());
    }

    [Fact]
    public void Evidence_bundle_can_be_independently_reverified_from_records()
    {
        // An auditor with only the exported records can replay the chain themselves.
        var log = new InMemoryProofLog();
        for (var i = 0; i < 6; i++) log.Append(new AuditEntry { Actor = "svc", Action = $"e{i}", Resource = "r", Data = "{\"k\":1}" });

        var bundle = Evidence.Build(log);
        var prev = Hashing.Genesis;
        long seq = 1;
        foreach (var r in bundle.Records)
        {
            Assert.Equal(seq, r.Seq);
            Assert.Equal(prev, r.PrevHash);
            Assert.Equal(Hashing.ComputeHash(r.PrevHash, r.Seq, r.At, r.Actor, r.Action, r.Resource, r.Data), r.Hash);
            prev = r.Hash;
            seq++;
        }
        Assert.Equal(bundle.Head, prev);
        Assert.True(bundle.Verification.Ok);
    }
}
