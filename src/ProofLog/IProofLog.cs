namespace ProofLog;

/// <summary>A tamper-evident, identity-bound, hash-chained audit log.</summary>
public interface IProofLog
{
    /// <summary>Append an entry and return the committed, chained record.</summary>
    /// <exception cref="System.ArgumentException">If the entry has no actor or action.</exception>
    ProofRecord Append(AuditEntry entry);

    /// <summary>Read records in sequence order, starting at <paramref name="fromSeq"/>.</summary>
    IReadOnlyList<ProofRecord> Read(long fromSeq = 1, int? limit = null);

    /// <summary>The latest record's hash (the chain head). Anchor it externally
    /// (publish, notarize, send to a second system) to also detect truncation.</summary>
    string Head();

    /// <summary>The number of records in the log.</summary>
    long Count();

    /// <summary>Recompute the entire chain and report the first break, if any.</summary>
    VerificationResult Verify();
}
