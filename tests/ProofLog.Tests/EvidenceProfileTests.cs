using System.Text;
using ProofLog;
using Xunit;

namespace ProofLog.Tests;

// Regulator profiles tag an evidence export with the obligation it speaks to (CRA /
// DORA / NIS2 / EU AI Act) and map that obligation onto ProofLog's properties - turning
// a generic bundle into "this trail addresses this requirement, here is the integrity proof".
public class EvidenceProfileTests
{
    private static AuditEntry E(string action, string? data = null) => new() { Actor = "alice", Action = action, Data = data };

    [Fact]
    public void All_profiles_are_well_formed()
    {
        Assert.Equal(5, RegulatorProfiles.All.Count);
        foreach (var p in RegulatorProfiles.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(p.Key));
            Assert.False(string.IsNullOrWhiteSpace(p.Framework));
            Assert.False(string.IsNullOrWhiteSpace(p.Reference));
            Assert.False(string.IsNullOrWhiteSpace(p.Obligation));
            Assert.NotEmpty(p.Mappings);
            Assert.All(p.Mappings, m =>
            {
                Assert.False(string.IsNullOrWhiteSpace(m.Requirement));
                Assert.False(string.IsNullOrWhiteSpace(m.HowProofLogHelps));
            });
        }
    }

    [Theory]
    [InlineData("cra", "EU Cyber Resilience Act")]
    [InlineData("CRA", "EU Cyber Resilience Act")]
    [InlineData("dora", "EU Digital Operational Resilience Act (DORA)")]
    [InlineData("nis2", "EU NIS2 Directive")]
    [InlineData("eu-ai-act", "EU Artificial Intelligence Act")]
    [InlineData("EU-AI-ACT", "EU Artificial Intelligence Act")]
    [InlineData("mga-gaming", "Malta Gaming Authority (B2C gaming)")]
    public void ByKey_is_case_insensitive(string key, string framework)
    {
        Assert.Equal(framework, RegulatorProfiles.ByKey(key).Framework);
        Assert.True(RegulatorProfiles.TryByKey(key, out var p));
        Assert.Equal(framework, p.Framework);
    }

    [Fact]
    public void ByKey_throws_on_an_unknown_key()
    {
        var ex = Assert.Throws<ArgumentException>(() => RegulatorProfiles.ByKey("gdpr"));
        Assert.Contains("Unknown regulator profile", ex.Message);
        Assert.False(RegulatorProfiles.TryByKey("gdpr", out _));
    }

    [Fact]
    public void BuildProfiled_tags_the_profile_and_verifies()
    {
        var log = new InMemoryProofLog();
        log.Append(E("vuln.triage", "{\"cve\":\"CVE-2025-1\"}"));
        log.Append(E("patch.release"));

        var bundle = Evidence.BuildProfiled(log, RegulatorProfiles.Cra);
        Assert.Equal("cra", bundle.Profile.Key);
        Assert.True(bundle.Verification.Ok);
        Assert.Equal(2, bundle.Count);
        Assert.False(bundle.Signed);                              // unsigned log
        Assert.Equal(Evidence.ComplianceDisclaimer, bundle.Disclaimer);
    }

    [Fact]
    public void BuildProfiled_reports_signed_when_records_carry_a_signature()
    {
        using var signer = EcdsaProofSigner.Create();
        var log = new InMemoryProofLog(signer);
        log.Append(E("incident.detect"));
        log.Append(E("incident.report"));

        var bundle = Evidence.BuildProfiled(log, "dora");
        Assert.True(bundle.Signed);
        Assert.Equal("dora", bundle.Profile.Key);
    }

    [Fact]
    public void Empty_log_is_not_marked_signed()
    {
        var bundle = Evidence.BuildProfiled(new InMemoryProofLog(), RegulatorProfiles.Nis2);
        Assert.Equal(0, bundle.Count);
        Assert.False(bundle.Signed);
        Assert.True(bundle.Verification.Ok);
    }

    [Fact]
    public void Profiled_json_carries_framework_reference_disclaimer_and_records()
    {
        var key = Encoding.UTF8.GetBytes("k");
        var log = new InMemoryProofLog(signingKey: key);
        log.Append(E("model.deploy", "{\"version\":\"1.2\"}"));

        var json = Evidence.ToJson(log, RegulatorProfiles.EuAiAct);
        Assert.Contains("EU Artificial Intelligence Act", json);
        Assert.Contains("Regulation (EU) 2024/1689", json);
        Assert.Contains("not legal advice", json);
        Assert.Contains("model.deploy", json);
        Assert.Contains("\"signed\": true", json);                // camelCase, signed
        Assert.Contains("\"key\": \"eu-ai-act\"", json);
    }

    [Fact]
    public void Profiled_json_by_key_matches_by_profile()
    {
        var fixedAt = new DateTimeOffset(2026, 6, 8, 12, 0, 0, TimeSpan.Zero);
        var log = new InMemoryProofLog();
        log.Append(E("a"));

        var byKey = Evidence.ToJson(log, "nis2", fixedAt);
        var byProfile = Evidence.ToJson(log, RegulatorProfiles.Nis2, fixedAt);
        Assert.Equal(byProfile, byKey);
    }
}
