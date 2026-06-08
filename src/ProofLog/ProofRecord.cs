namespace ProofLog;

/// <summary>
/// A committed, hash-chained log record. <see cref="Hash"/> is the SHA-256 over the
/// previous record's hash plus this record's canonical fields, so any change to
/// history (edit, insert, delete, reorder) breaks the chain from that point on.
/// </summary>
public sealed record ProofRecord
{
    /// <summary>1-based, contiguous sequence number.</summary>
    public long Seq { get; init; }

    /// <summary>When the record was appended (UTC).</summary>
    public DateTimeOffset At { get; init; }

    /// <summary>Who performed the action (identity-bound).</summary>
    public string Actor { get; init; } = "";

    /// <summary>What happened.</summary>
    public string Action { get; init; } = "";

    /// <summary>The resource acted upon, if any.</summary>
    public string? Resource { get; init; }

    /// <summary>Optional structured detail.</summary>
    public string? Data { get; init; }

    /// <summary>The hash of the previous record (or the genesis hash for the first record).</summary>
    public string PrevHash { get; init; } = "";

    /// <summary>This record's hash = SHA-256(PrevHash + canonical fields), lower-case hex.</summary>
    public string Hash { get; init; } = "";
}
