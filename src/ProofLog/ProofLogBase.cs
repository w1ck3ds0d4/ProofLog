namespace ProofLog;

/// <summary>
/// Shared append + verify logic for any storage backend. Subclasses only implement
/// the persistence primitives; the chaining, identity check, and verification live
/// here so every store behaves identically.
/// </summary>
public abstract class ProofLogBase : IProofLog
{
    private readonly object _gate = new();
    private readonly IProofSigner? _signer;

    /// <param name="signingKey">Optional HMAC key. When set, every record is signed and
    /// <see cref="Verify"/> also checks the signature, so a full-chain rewrite without the
    /// key is detected. Shorthand for <c>new HmacProofSigner(signingKey)</c>.</param>
    protected ProofLogBase(byte[]? signingKey = null)
        => _signer = signingKey is null ? null : new HmacProofSigner(signingKey);

    /// <param name="signer">Optional signer. <see cref="HmacProofSigner"/> for symmetric
    /// signing, or <see cref="EcdsaProofSigner"/> for asymmetric signing where an auditor
    /// can verify with only the public key. When the signer is verify-only
    /// (<see cref="IProofSigner.CanSign"/> is false), <see cref="Append"/> throws - a
    /// public key can check the trail but not extend it.</param>
    protected ProofLogBase(IProofSigner? signer) => _signer = signer;

    /// <inheritdoc />
    public ProofRecord Append(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (string.IsNullOrEmpty(entry.Actor)) throw new ArgumentException("Actor is required - ProofLog is identity-bound.", nameof(entry));
        if (string.IsNullOrEmpty(entry.Action)) throw new ArgumentException("Action is required.", nameof(entry));
        if (_signer is { CanSign: false }) throw new InvalidOperationException($"This log was opened with a verify-only {_signer.Algorithm} signer (public key). It can verify the trail but cannot append - open it with the signing key to record evidence.");

        // Serialize appends so the chain stays linear and prev-hash never races.
        lock (_gate)
        {
            var last = GetLast();
            var seq = (last?.Seq ?? 0) + 1;
            var prev = last?.Hash ?? Hashing.Genesis;
            var at = UtcNow();
            var hash = Hashing.ComputeHash(prev, seq, at, entry.Actor, entry.Action, entry.Resource, entry.Data);
            var mac = _signer is null ? "" : _signer.Sign(hash);

            var record = new ProofRecord
            {
                Seq = seq,
                At = at,
                Actor = entry.Actor,
                Action = entry.Action,
                Resource = entry.Resource,
                Data = entry.Data,
                PrevHash = prev,
                Hash = hash,
                Mac = mac,
            };
            Persist(record);
            return record;
        }
    }

    /// <inheritdoc />
    public VerificationResult Verify()
    {
        long expectedSeq = 1;
        var expectedPrev = Hashing.Genesis;
        long verified = 0;

        foreach (var r in ReadAll())
        {
            if (r.Seq != expectedSeq)
                return VerificationResult.Broken(verified, r.Seq, $"sequence break: expected {expectedSeq}, found {r.Seq} (record inserted or removed)");

            if (r.PrevHash != expectedPrev)
                return VerificationResult.Broken(verified, r.Seq, "previous-hash mismatch (record inserted, removed, or reordered)");

            var recomputed = Hashing.ComputeHash(r.PrevHash, r.Seq, r.At, r.Actor, r.Action, r.Resource, r.Data);
            if (recomputed != r.Hash)
                return VerificationResult.Broken(verified, r.Seq, "content hash mismatch (record was modified)");

            if (_signer is not null && !_signer.Verify(r.Hash, r.Mac))
                return VerificationResult.Broken(verified, r.Seq, $"signature ({_signer.Algorithm}) mismatch - record was not produced with this signing key");

            expectedSeq++;
            expectedPrev = r.Hash;
            verified++;
        }

        return VerificationResult.Valid(verified);
    }

    /// <inheritdoc />
    public string Head() => GetLast()?.Hash ?? Hashing.Genesis;

    /// <inheritdoc />
    public long Count() => CountCore();

    /// <inheritdoc />
    public IReadOnlyList<ProofRecord> Read(long fromSeq = 1, int? limit = null) => ReadRange(fromSeq, limit);

    /// <summary>The clock used for timestamps; overridable for deterministic tests.</summary>
    protected virtual DateTimeOffset UtcNow() => DateTimeOffset.UtcNow;

    // ---- storage primitives ----
    /// <summary>The most recently appended record, or null if the log is empty.</summary>
    protected abstract ProofRecord? GetLast();

    /// <summary>Persist a freshly chained record.</summary>
    protected abstract void Persist(ProofRecord record);

    /// <summary>Every record, in ascending sequence order.</summary>
    protected abstract IEnumerable<ProofRecord> ReadAll();

    /// <summary>Records from <paramref name="fromSeq"/> onward, ascending, optionally capped.</summary>
    protected abstract IReadOnlyList<ProofRecord> ReadRange(long fromSeq, int? limit);

    /// <summary>The number of records.</summary>
    protected abstract long CountCore();
}
