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

/// <summary>A profiled evidence bundle: a plain bundle plus the regulator profile it
/// speaks to, whether the records are signed, and the compliance disclaimer. Hand this
/// to an auditor to say "this trail addresses <em>this</em> obligation, and here is the
/// integrity proof."</summary>
public sealed record ProfiledEvidenceBundle(
    RegulatorProfile Profile,
    bool Signed,
    string Disclaimer,
    DateTimeOffset GeneratedAt,
    long Count,
    string Head,
    VerificationResult Verification,
    IReadOnlyList<ProofRecord> Records);

/// <summary>Regulator-ready evidence export: a portable, self-verifying JSON bundle,
/// optionally tagged with a named profile (CRA / DORA / NIS2 / EU AI Act) that maps the
/// obligation to ProofLog's properties.</summary>
public static class Evidence
{
    /// <summary>The standing disclaimer attached to profiled exports.</summary>
    public const string ComplianceDisclaimer =
        "ProofLog provides a tamper-evident, identity-bound record-keeping mechanism. This export documents the integrity of the recorded events; it does not by itself constitute or guarantee regulatory compliance, and it is not legal advice.";

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

    /// <summary>Build an evidence bundle tagged with a regulator profile. The
    /// <c>Signed</c> flag is true when the records carry a signature (a non-empty MAC).</summary>
    public static ProfiledEvidenceBundle BuildProfiled(IProofLog log, RegulatorProfile profile, DateTimeOffset? generatedAt = null)
    {
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(profile);
        var b = Build(log, generatedAt);
        var signed = b.Records.Count > 0 && b.Records.All(r => !string.IsNullOrEmpty(r.Mac));
        return new ProfiledEvidenceBundle(
            profile, signed, ComplianceDisclaimer,
            b.GeneratedAt, b.Count, b.Head, b.Verification, b.Records);
    }

    /// <summary>Build a profiled bundle by profile key (case-insensitive), e.g. <c>"cra"</c>.</summary>
    public static ProfiledEvidenceBundle BuildProfiled(IProofLog log, string profileKey, DateTimeOffset? generatedAt = null)
        => BuildProfiled(log, RegulatorProfiles.ByKey(profileKey), generatedAt);

    /// <summary>Export the whole log as a portable, self-verifying JSON document.</summary>
    public static string ToJson(IProofLog log, DateTimeOffset? generatedAt = null)
        => JsonSerializer.Serialize(Build(log, generatedAt), Options);

    /// <summary>Export the log as a JSON document tagged with a regulator profile.</summary>
    public static string ToJson(IProofLog log, RegulatorProfile profile, DateTimeOffset? generatedAt = null)
        => JsonSerializer.Serialize(BuildProfiled(log, profile, generatedAt), Options);

    /// <summary>Export the log as a JSON document tagged with a regulator profile, by key.</summary>
    public static string ToJson(IProofLog log, string profileKey, DateTimeOffset? generatedAt = null)
        => JsonSerializer.Serialize(BuildProfiled(log, profileKey, generatedAt), Options);
}
