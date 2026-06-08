using Microsoft.Extensions.Logging;

namespace ProofLog;

/// <summary>Ergonomic helpers so appending an audit record is a single call.</summary>
public static class ProofLogExtensions
{
    /// <summary>Append an entry without constructing an <see cref="AuditEntry"/>.</summary>
    public static ProofRecord Append(this IProofLog log, string actor, string action, string? resource = null, string? data = null) =>
        log.Append(new AuditEntry { Actor = actor, Action = action, Resource = resource, Data = data });

    /// <summary>Record a tamper-evident audit entry AND emit it through your normal
    /// <see cref="ILogger"/> pipeline in one call - observability and evidence together.</summary>
    public static ProofRecord Audit(this ILogger logger, IProofLog log, string actor, string action, string? resource = null, string? data = null)
    {
        var record = log.Append(actor, action, resource, data);
        logger.LogInformation("audit #{Seq} {Actor} {Action} {Resource}", record.Seq, actor, action, resource ?? "-");
        return record;
    }
}
