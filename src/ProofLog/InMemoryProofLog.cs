namespace ProofLog;

/// <summary>
/// An in-memory ProofLog - useful for tests, embedding, and as the simplest example
/// of the storage contract. Not durable: the chain lives only as long as the object.
/// </summary>
public sealed class InMemoryProofLog : ProofLogBase
{
    private readonly List<ProofRecord> _records = new();
    private readonly Func<DateTimeOffset>? _clock;

    /// <summary>Create an optionally fixed-clock log (pass <paramref name="clock"/> for
    /// deterministic timestamps).</summary>
    public InMemoryProofLog(Func<DateTimeOffset>? clock = null) => _clock = clock;

    /// <inheritdoc />
    protected override DateTimeOffset UtcNow() => _clock?.Invoke() ?? base.UtcNow();

    /// <inheritdoc />
    protected override ProofRecord? GetLast() => _records.Count == 0 ? null : _records[^1];

    /// <inheritdoc />
    protected override void Persist(ProofRecord record) => _records.Add(record);

    /// <inheritdoc />
    protected override IEnumerable<ProofRecord> ReadAll() => _records;

    /// <inheritdoc />
    protected override IReadOnlyList<ProofRecord> ReadRange(long fromSeq, int? limit)
    {
        var query = _records.Where(r => r.Seq >= fromSeq);
        if (limit is { } n) query = query.Take(n);
        return query.ToList();
    }

    /// <inheritdoc />
    protected override long CountCore() => _records.Count;
}
