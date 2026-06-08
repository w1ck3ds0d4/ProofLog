namespace ProofLog;

/// <summary>
/// An event to append to the log: <b>who</b> did <b>what</b>, optionally to which
/// resource, with optional structured detail. The log stamps the time and chains it.
/// </summary>
/// <remarks>
/// <see cref="Actor"/> is required - ProofLog is identity-bound, so every record
/// carries the actor and that actor is part of the hash chain. You cannot later
/// alter who did something without breaking the chain.
/// </remarks>
public sealed record AuditEntry
{
    /// <summary>The identity that performed the action (user id, service name, key id). Required.</summary>
    public required string Actor { get; init; }

    /// <summary>What happened (e.g. "user.login", "config.update", "payout.approve"). Required.</summary>
    public required string Action { get; init; }

    /// <summary>The resource acted upon, if any (e.g. "account/42", "policy/aml-v3").</summary>
    public string? Resource { get; init; }

    /// <summary>Optional structured detail, typically a small JSON document.</summary>
    public string? Data { get; init; }
}
