using Microsoft.Extensions.Logging;

namespace ProofLog;

/// <summary>Ergonomic helpers so appending an audit record is a single call.</summary>
public static class ProofLogExtensions
{
    /// <summary>Append an entry without constructing an <see cref="AuditEntry"/>.</summary>
    public static ProofRecord Append(this IProofLog log, string actor, string action, string? resource = null, string? data = null) =>
        log.Append(new AuditEntry { Actor = actor, Action = action, Resource = resource, Data = data });

    /// <summary>Verify the chain AND that its head matches a previously anchored value.
    /// This closes the truncation gap: if records were deleted from the end (or appended)
    /// since you last recorded <paramref name="expectedHead"/>, the heads won't match.
    /// Store the head somewhere the attacker can't reach (publish it, send it to a second
    /// system) and call this with it.</summary>
    public static VerificationResult Verify(this IProofLog log, string expectedHead)
    {
        var v = log.Verify();
        if (!v.Ok) return v;
        if (!string.Equals(log.Head(), expectedHead, StringComparison.OrdinalIgnoreCase))
            return VerificationResult.Broken(v.Verified, v.Verified, "head does not match the anchored value (records were truncated or appended since it was recorded)");
        return v;
    }

    /// <summary>Record a tamper-evident audit entry AND emit it through your normal
    /// <see cref="ILogger"/> pipeline in one call - observability and evidence together.</summary>
    public static ProofRecord Audit(this ILogger logger, IProofLog log, string actor, string action, string? resource = null, string? data = null)
    {
        var record = log.Append(actor, action, resource, data);
        logger.LogInformation("audit #{Seq} {Actor} {Action} {Resource}", record.Seq, actor, action, resource ?? "-");
        return record;
    }
}
