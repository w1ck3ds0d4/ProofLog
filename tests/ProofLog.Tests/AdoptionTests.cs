using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ProofLog;
using Xunit;

namespace ProofLog.Tests;

public class AdoptionTests
{
    [Fact]
    public void AddProofLog_registers_a_working_singleton()
    {
        using var sp = new ServiceCollection().AddProofLog(":memory:").BuildServiceProvider();
        var log = sp.GetRequiredService<IProofLog>();
        log.Append("alice", "login");
        Assert.Equal(1, log.Count());
        Assert.True(log.Verify().Ok);
        Assert.Same(log, sp.GetRequiredService<IProofLog>());   // singleton
    }

    [Fact]
    public void Convenience_append_overload_sets_fields()
    {
        var log = new InMemoryProofLog();
        var r = log.Append("bob", "payout.approve", "payout/42", "{\"amt\":100}");
        Assert.Equal("bob", r.Actor);
        Assert.Equal("payout.approve", r.Action);
        Assert.Equal("payout/42", r.Resource);
        Assert.Equal("{\"amt\":100}", r.Data);
    }

    [Fact]
    public void Logger_audit_extension_records_and_returns_the_entry()
    {
        var log = new InMemoryProofLog();
        var r = NullLogger.Instance.Audit(log, "svc", "config.update", "policy/aml");
        Assert.Equal(1, log.Count());
        Assert.Equal("config.update", r.Action);
        Assert.True(log.Verify().Ok);
    }
}
