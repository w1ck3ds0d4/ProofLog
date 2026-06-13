namespace ProofLog;

/// <summary>
/// One requirement of a regulation's record-keeping obligation, paired with the
/// ProofLog property that helps satisfy it. This is a mapping, not a compliance
/// claim - it documents how a tamper-evident log supports the obligation.
/// </summary>
public sealed record ControlMapping(string Requirement, string HowProofLogHelps);

/// <summary>
/// A named regulator profile: the framework, the specific record-keeping / logging
/// obligation, and how ProofLog's properties (append-only, identity-bound, time-stamped,
/// hash-chained, optionally signed) map onto it. Attach one to an evidence export so the
/// bundle states which obligation it speaks to.
/// </summary>
public sealed record RegulatorProfile(
    string Key,
    string Framework,
    string Reference,
    string Obligation,
    IReadOnlyList<ControlMapping> Mappings);

/// <summary>
/// The built-in regulator profiles. Each summarises a record-keeping / logging duty and
/// maps it to ProofLog. These are engineering aids, not legal advice - see
/// <see cref="Evidence.ComplianceDisclaimer"/>.
/// </summary>
public static class RegulatorProfiles
{
    /// <summary>EU Cyber Resilience Act - vulnerability handling and technical documentation.</summary>
    public static readonly RegulatorProfile Cra = new(
        "cra",
        "EU Cyber Resilience Act",
        "Regulation (EU) 2024/2847 - Annex I Part II (vulnerability handling) and Article 13 (technical documentation)",
        "Manufacturers must handle vulnerabilities throughout the support period and keep records of the security-relevant processes that back the technical documentation.",
        new[]
        {
            new ControlMapping(
                "Record how vulnerabilities are identified, triaged, and remediated",
                "Each triage and remediation decision is an append-only, time-stamped, attributable record - the trail behind the Annex VII technical file."),
            new ControlMapping(
                "Demonstrate the records were not altered after the fact",
                "The hash chain detects any edit, reorder, insertion, or deletion; with signing, even a full rewrite by someone without the key is caught."),
            new ControlMapping(
                "Evidence the timeline of incident handling and reporting (Article 14)",
                "Every event carries a UTC timestamp bound into its hash, so the recorded 24h / 72h / 14-day sequence is tamper-evident: the timeline cannot be quietly rewritten after the fact."),
        });

    /// <summary>EU Digital Operational Resilience Act - ICT incident management and audit trail.</summary>
    public static readonly RegulatorProfile Dora = new(
        "dora",
        "EU Digital Operational Resilience Act (DORA)",
        "Regulation (EU) 2022/2554 - Articles 17-19 (ICT-related incident management, classification, and reporting)",
        "Financial entities must log and classify ICT-related incidents and keep an auditable record of the ICT risk-management process.",
        new[]
        {
            new ControlMapping(
                "Maintain records of the ICT incident lifecycle (detection, classification, response)",
                "The incident lifecycle is captured as an ordered, attributable, append-only chain - who did what, when."),
            new ControlMapping(
                "Provide auditors and competent authorities with reliable, unaltered records",
                "Anyone can replay the public hash rule to confirm integrity; an asymmetric public key lets an auditor verify without being able to forge."),
            new ControlMapping(
                "Support the major-incident reporting timeline",
                "Timestamps are bound into each record's hash, evidencing when each step occurred."),
        });

    /// <summary>EU NIS2 Directive - cybersecurity risk-management measures and incident records.</summary>
    public static readonly RegulatorProfile Nis2 = new(
        "nis2",
        "EU NIS2 Directive",
        "Directive (EU) 2022/2555 - Article 21 (risk-management measures, incl. logging) and Article 23 (incident reporting)",
        "Essential and important entities must apply cybersecurity risk-management measures - including logging and incident handling - and report significant incidents with supporting evidence.",
        new[]
        {
            new ControlMapping(
                "Show that risk-management measures and security events were logged",
                "Security-relevant actions are recorded append-only with the actor that performed them."),
            new ControlMapping(
                "Provide tamper-evident records when reporting a significant incident",
                "The hash chain (and optional signature) makes after-the-fact alteration detectable, so the reported timeline holds up."),
            new ControlMapping(
                "Attribute actions to identities",
                "ProofLog refuses a record without an actor - every entry is identity-bound by construction."),
        });

    /// <summary>EU AI Act - automatic record-keeping (logging) for high-risk AI systems.</summary>
    public static readonly RegulatorProfile EuAiAct = new(
        "eu-ai-act",
        "EU Artificial Intelligence Act",
        "Regulation (EU) 2024/1689 - Article 12 (record-keeping) and Article 19 (automatically generated logs)",
        "High-risk AI systems must automatically record events (logs) over their lifetime to ensure a level of traceability appropriate to their intended purpose.",
        new[]
        {
            new ControlMapping(
                "Automatically record events over the system's lifetime",
                "ProofLog is an append-only event log designed to be written to continuously from the system itself."),
            new ControlMapping(
                "Ensure traceability of the system's functioning",
                "Each event is ordered, time-stamped, and attributable, and the chain proves no event was removed or reordered."),
            new ControlMapping(
                "Keep the logs under the provider's control and unaltered",
                "Tamper-evidence (and optional signing) demonstrates the retained logs are the ones the system produced."),
        });

    /// <summary>Malta Gaming Authority - player-gaming record-keeping and dispute traceability.</summary>
    public static readonly RegulatorProfile MgaGaming = new(
        "mga-gaming",
        "Malta Gaming Authority (B2C gaming)",
        "MGA Gaming Authorisations and Compliance Directive + the Player Protection Directive - record-keeping of gaming transactions and the handling of player disputes / complaints",
        "Licensees must keep complete, retrievable records of gaming transactions and game / market outcomes, and be able to evidence to the Authority and to players how a contested outcome was resolved.",
        new[]
        {
            new ControlMapping(
                "Keep complete, retrievable records of game / market outcomes and settlements",
                "Every settlement decision is an append-only, time-stamped, attributable record, retrievable and exportable on demand."),
            new ControlMapping(
                "Evidence how a contested or voided outcome was resolved against its stated rules",
                "The resolution record binds the market's stated source rule, the outcome, and the resolver identity into a signed entry an operator's own mutable logs cannot independently attest."),
            new ControlMapping(
                "Demonstrate the records were not altered after a dispute arose",
                "The hash chain detects any edit, reorder, or deletion; an ECDSA signature lets the Authority or a player verify the record without being able to forge it."),
        });

    /// <summary>ISO/IEC 27037 + 27043 - digital evidence handling and chain of custody.</summary>
    public static readonly RegulatorProfile DigitalEvidence = new(
        "digital-evidence",
        "ISO/IEC 27037 + 27043 (digital evidence and investigation)",
        "ISO/IEC 27037:2012 (identification, collection, acquisition and preservation of digital evidence) and ISO/IEC 27043:2015 (incident investigation principles and processes)",
        "Digital evidence must be handled so it can be relied upon: its origin authenticated, its integrity provable, its chain of custody documented and unbroken, and its handling auditable, repeatable, and reproducible by an independent party.",
        new[]
        {
            new ControlMapping(
                "Maintain an unbroken, documented chain of custody - who handled the evidence, when, and what was done",
                "Each handling action (collection, acquisition, transfer, analysis) is an append-only, identity-bound, time-stamped record; the hash chain proves no step was inserted, removed, or reordered, so custody is continuous and attributable."),
            new ControlMapping(
                "Prove evidence integrity - that an artifact was not altered after collection",
                "The artifact's hash is bound into the SHA-256 chain at the moment of collection; any later edit fails verification at exactly that record. With ECDSA signing, even a full rewrite by someone without the private key is caught."),
            new ControlMapping(
                "Authenticate the origin of the evidence so it can be attributed",
                "ProofLog refuses a record without an actor, and an ECDSA signature ties the trail to a private key the collector controls - origin is authenticated, not merely asserted."),
            new ControlMapping(
                "Let an independent party verify without trusting the holder (auditability, repeatability, reproducibility)",
                "The canonicalization rule is public and the export is self-contained, so a court, opposing expert, or auditor can replay the chain and, with only the public key, verify every signature without being able to forge or extend the trail."),
        });

    private static readonly RegulatorProfile[] _all = { Cra, Dora, Nis2, EuAiAct, MgaGaming, DigitalEvidence };

    /// <summary>All built-in profiles.</summary>
    public static IReadOnlyList<RegulatorProfile> All => _all;

    /// <summary>Look up a profile by its key (case-insensitive), e.g. <c>"cra"</c>, <c>"dora"</c>,
    /// <c>"nis2"</c>, <c>"eu-ai-act"</c>, <c>"mga-gaming"</c>, <c>"digital-evidence"</c>. Throws <see cref="ArgumentException"/> if unknown.</summary>
    public static RegulatorProfile ByKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return TryByKey(key, out var p)
            ? p
            : throw new ArgumentException($"Unknown regulator profile '{key}'. Known: {string.Join(", ", _all.Select(x => x.Key))}.", nameof(key));
    }

    /// <summary>Try to look up a profile by its key (case-insensitive).</summary>
    public static bool TryByKey(string key, out RegulatorProfile profile)
    {
        foreach (var p in _all)
        {
            if (string.Equals(p.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                profile = p;
                return true;
            }
        }
        profile = null!;
        return false;
    }
}
