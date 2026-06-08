using System.Globalization;
using Microsoft.Data.Sqlite;

namespace ProofLog;

/// <summary>
/// A durable ProofLog backed by SQLite. Pass a file path (created if missing) or a
/// full connection string. Keeps one connection open for the lifetime of the object.
/// </summary>
public sealed class SqliteProofLog : ProofLogBase, IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly Func<DateTimeOffset>? _clock;

    /// <summary>Open (or create) a ProofLog at <paramref name="pathOrConnectionString"/>.
    /// A bare path becomes <c>Data Source=path</c>; use <c>":memory:"</c> for an
    /// in-process database that lives as long as this object. Pass <paramref name="clock"/>
    /// for deterministic timestamps (tests).</summary>
    public SqliteProofLog(string pathOrConnectionString, Func<DateTimeOffset>? clock = null, byte[]? signingKey = null)
        : base(signingKey) => _clock = Init(pathOrConnectionString, clock, out _conn);

    /// <summary>Open (or create) a ProofLog signed with an explicit signer - e.g. an
    /// <see cref="EcdsaProofSigner"/> for asymmetric signing so an auditor can verify
    /// the trail with only the public key. A verify-only signer can read but not append.</summary>
    public SqliteProofLog(string pathOrConnectionString, IProofSigner? signer, Func<DateTimeOffset>? clock = null)
        : base(signer) => _clock = Init(pathOrConnectionString, clock, out _conn);

    private static Func<DateTimeOffset>? Init(string pathOrConnectionString, Func<DateTimeOffset>? clock, out SqliteConnection conn)
    {
        var cs = pathOrConnectionString.Contains('=', StringComparison.Ordinal)
            ? pathOrConnectionString
            : new SqliteConnectionStringBuilder { DataSource = pathOrConnectionString }.ToString();
        conn = new SqliteConnection(cs);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS ProofRecords (
                Seq      INTEGER PRIMARY KEY,
                At       TEXT NOT NULL,
                Actor    TEXT NOT NULL,
                Action   TEXT NOT NULL,
                Resource TEXT,
                Data     TEXT,
                PrevHash TEXT NOT NULL,
                Hash     TEXT NOT NULL,
                Mac      TEXT NOT NULL DEFAULT ''
            );
            """;
        cmd.ExecuteNonQuery();

        // Add the Mac column to databases created before v0.2 (idempotent).
        try { using var alter = conn.CreateCommand(); alter.CommandText = "ALTER TABLE ProofRecords ADD COLUMN Mac TEXT NOT NULL DEFAULT '';"; alter.ExecuteNonQuery(); }
        catch (SqliteException) { /* column already exists */ }
        return clock;
    }

    /// <inheritdoc />
    protected override DateTimeOffset UtcNow() => _clock?.Invoke() ?? base.UtcNow();

    /// <inheritdoc />
    protected override ProofRecord? GetLast()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT Seq, At, Actor, Action, Resource, Data, PrevHash, Hash, Mac FROM ProofRecords ORDER BY Seq DESC LIMIT 1;";
        using var r = cmd.ExecuteReader();
        return r.Read() ? Map(r) : null;
    }

    /// <inheritdoc />
    protected override void Persist(ProofRecord record)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO ProofRecords (Seq, At, Actor, Action, Resource, Data, PrevHash, Hash, Mac) " +
            "VALUES ($seq, $at, $actor, $action, $resource, $data, $prev, $hash, $mac);";
        cmd.Parameters.AddWithValue("$seq", record.Seq);
        cmd.Parameters.AddWithValue("$at", record.At.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$actor", record.Actor);
        cmd.Parameters.AddWithValue("$action", record.Action);
        cmd.Parameters.AddWithValue("$resource", (object?)record.Resource ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$data", (object?)record.Data ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$prev", record.PrevHash);
        cmd.Parameters.AddWithValue("$hash", record.Hash);
        cmd.Parameters.AddWithValue("$mac", record.Mac);
        cmd.ExecuteNonQuery();
    }

    /// <inheritdoc />
    protected override IEnumerable<ProofRecord> ReadAll()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT Seq, At, Actor, Action, Resource, Data, PrevHash, Hash, Mac FROM ProofRecords ORDER BY Seq ASC;";
        using var r = cmd.ExecuteReader();
        while (r.Read()) yield return Map(r);
    }

    /// <inheritdoc />
    protected override IReadOnlyList<ProofRecord> ReadRange(long fromSeq, int? limit)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT Seq, At, Actor, Action, Resource, Data, PrevHash, Hash, Mac FROM ProofRecords WHERE Seq >= $from ORDER BY Seq ASC" + (limit is null ? ";" : " LIMIT $limit;");
        cmd.Parameters.AddWithValue("$from", fromSeq);
        if (limit is { } n) cmd.Parameters.AddWithValue("$limit", n);
        using var r = cmd.ExecuteReader();
        var list = new List<ProofRecord>();
        while (r.Read()) list.Add(Map(r));
        return list;
    }

    /// <inheritdoc />
    protected override long CountCore()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM ProofRecords;";
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    private static ProofRecord Map(SqliteDataReader r) => new()
    {
        Seq = r.GetInt64(0),
        At = DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
        Actor = r.GetString(2),
        Action = r.GetString(3),
        Resource = r.IsDBNull(4) ? null : r.GetString(4),
        Data = r.IsDBNull(5) ? null : r.GetString(5),
        PrevHash = r.GetString(6),
        Hash = r.GetString(7),
        Mac = r.IsDBNull(8) ? "" : r.GetString(8),
    };

    /// <summary>Close the underlying connection.</summary>
    public void Dispose() => _conn.Dispose();
}
