namespace ProofLog;

/// <summary>
/// The outcome of verifying the chain. When <see cref="Ok"/> is <c>false</c>,
/// <see cref="BrokenAtSeq"/> is the first record where tampering was detected and
/// <see cref="Reason"/> explains how.
/// </summary>
public sealed record VerificationResult(bool Ok, long Verified, long? BrokenAtSeq, string? Reason)
{
    /// <summary>A clean chain: every record verified.</summary>
    public static VerificationResult Valid(long verified) => new(true, verified, null, null);

    /// <summary>Tampering detected at <paramref name="seq"/>.</summary>
    public static VerificationResult Broken(long verified, long seq, string reason) => new(false, verified, seq, reason);
}
