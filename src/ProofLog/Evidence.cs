using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProofLog;

/// <summary>A one-call, self-verifying evidence bundle: the full chain plus its head
/// hash and a fresh verification statement. Hand this to an auditor; they can replay
/// the hashes from the records alone and confirm <see cref="Verification"/>.</summary>
public sealed record EvidenceBundle(
    DateTimeOffset GeneratedAt,
    long Count,
    string Head,
    VerificationResult Verification,
    IReadOnlyList<ProofRecord> Records);

/// <summary>Regulator-ready evidence export. v0.1 emits a portable JSON bundle; later
/// versions add named profiles (CRA / DORA / NIS2 / EU AI Act Article 12).</summary>
public static class Evidence
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Build an evidence bundle for the whole log (records + head + verification).</summary>
    public static EvidenceBundle Build(IProofLog log, DateTimeOffset? generatedAt = null)
    {
        ArgumentNullException.ThrowIfNull(log);
        var records = log.Read();
        return new EvidenceBundle(
            generatedAt ?? DateTimeOffset.UtcNow,
            log.Count(),
            log.Head(),
            log.Verify(),
            records);
    }

    /// <summary>Export the whole log as a portable, self-verifying JSON document.</summary>
    public static string ToJson(IProofLog log, DateTimeOffset? generatedAt = null)
        => JsonSerializer.Serialize(Build(log, generatedAt), Options);
}
