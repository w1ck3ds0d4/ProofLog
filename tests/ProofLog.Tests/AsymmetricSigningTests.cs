using System.Globalization;
using Microsoft.Data.Sqlite;
using ProofLog;
using Xunit;

namespace ProofLog.Tests;

// Asymmetric signing (v0.3) goes one step beyond HMAC: you can hand an auditor the
// PUBLIC key so they independently verify the chain was produced by your private key -
// and they still cannot forge a record. That is what an evidence store handed to a
// regulator actually needs (verifiable, but not forgeable by the verifier).
public class AsymmetricSigningTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"prooflog-ec-{Guid.NewGuid():N}.db");

    private static AuditEntry E(string action, string? data = null) => new() { Actor = "alice", Action = action, Data = data };

    [Fact]
    public void Ecdsa_signed_records_carry_a_signature_and_verify()
    {
        using var signer = EcdsaProofSigner.Create();
        var log = new InMemoryProofLog(signer);
        var r = log.Append(E("login"));
        Assert.NotEqual("", r.Mac);
        Assert.Equal("ECDSA-P256-SHA256", signer.Algorithm);
        Assert.True(log.Verify().Ok);
    }

    [Fact]
    public void Auditor_with_only_the_public_key_can_verify()
    {
        string publicKey;
        using (var signer = EcdsaProofSigner.Create())
        {
            publicKey = signer.ExportPublicKey();
            using var log = new SqliteProofLog(_path, signer);
            log.Append(E("login"));
            log.Append(E("payout", "{\"amt\":100}"));
        }

        // The auditor reopens with ONLY the public key - no private key in sight.
        using var verifyOnly = EcdsaProofSigner.FromPublicKey(publicKey);
        Assert.False(verifyOnly.CanSign);
        using var reopened = new SqliteProofLog(_path, verifyOnly);
        var v = reopened.Verify();
        Assert.True(v.Ok);
        Assert.Equal(2, v.Verified);
    }

    [Fact]
    public void A_verify_only_log_cannot_append()
    {
        string publicKey;
        using (var signer = EcdsaProofSigner.Create())
        {
            publicKey = signer.ExportPublicKey();
            using var log = new SqliteProofLog(_path, signer);
            log.Append(E("login"));
        }

        using var verifyOnly = EcdsaProofSigner.FromPublicKey(publicKey);
        using var reopened = new SqliteProofLog(_path, verifyOnly);
        // A public key can check the trail but must not be able to extend it.
        var ex = Assert.Throws<InvalidOperationException>(() => reopened.Append(E("sneaky")));
        Assert.Contains("verify-only", ex.Message);
    }

    [Fact]
    public void A_different_keypair_does_not_verify_the_chain()
    {
        using (var signer = EcdsaProofSigner.Create())
        using (var log = new SqliteProofLog(_path, signer))
            log.Append(E("login"));

        // An auditor handed the WRONG public key must reject the chain.
        using var wrong = EcdsaProofSigner.Create();
        using var reopened = new SqliteProofLog(_path, EcdsaProofSigner.FromPublicKey(wrong.ExportPublicKey()));
        var v = reopened.Verify();
        Assert.False(v.Ok);
        Assert.Contains("ECDSA", v.Reason);
    }

    [Fact]
    public void Asymmetric_log_catches_a_full_rewrite_without_the_private_key()
    {
        string publicKey;
        using (var signer = EcdsaProofSigner.Create())
        {
            publicKey = signer.ExportPublicKey();
            using var log = new SqliteProofLog(_path, signer);
            log.Append(E("a"));
            log.Append(E("payout", "{\"amt\":100}"));
        }

        // An attacker with full DB write access forges record #2, recomputes the public
        // hash correctly, and signs with their OWN freshly-generated key. Without the real
        // private key, the auditor's public-key verification rejects it.
        using (var attacker = EcdsaProofSigner.Create())
            ForgeRecord2(_path, "{\"amt\":999999}", attacker);

        using var reopened = new SqliteProofLog(_path, EcdsaProofSigner.FromPublicKey(publicKey));
        var v = reopened.Verify();
        Assert.False(v.Ok);
        Assert.Equal(2, v.BrokenAtSeq);
        Assert.Contains("ECDSA", v.Reason);
    }

    [Fact]
    public void Private_key_round_trips_so_a_log_can_be_reopened_to_append()
    {
        string privateKey;
        using (var signer = EcdsaProofSigner.Create())
        {
            privateKey = signer.ExportPrivateKey();
            using var log = new SqliteProofLog(_path, signer);
            log.Append(E("a"));
        }

        // Reopen with the exported private key and append more - the chain stays valid.
        using var reloaded = EcdsaProofSigner.FromPrivateKey(privateKey);
        Assert.True(reloaded.CanSign);
        using var reopened = new SqliteProofLog(_path, reloaded);
        reopened.Append(E("b"));
        var v = reopened.Verify();
        Assert.True(v.Ok);
        Assert.Equal(2, v.Verified);
    }

    [Fact]
    public void Verify_only_signer_refuses_to_export_a_private_key()
    {
        using var signer = EcdsaProofSigner.Create();
        using var verifyOnly = EcdsaProofSigner.FromPublicKey(signer.ExportPublicKey());
        Assert.Throws<InvalidOperationException>(() => verifyOnly.ExportPrivateKey());
    }

    // Rewrite record #2's data, recompute its public hash, and re-sign with the given
    // (attacker) signer - the worst case a DB-write attacker can do.
    private static void ForgeRecord2(string path, string forgedData, IProofSigner attacker)
    {
        using var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        c.Open();
        string at, prev, actor, action;
        using (var read = c.CreateCommand())
        {
            read.CommandText = "SELECT At, PrevHash, Actor, Action FROM ProofRecords WHERE Seq = 2;";
            using var rr = read.ExecuteReader();
            rr.Read();
            at = rr.GetString(0); prev = rr.GetString(1); actor = rr.GetString(2); action = rr.GetString(3);
        }
        var forgedHash = Hashing.ComputeHash(prev, 2,
            DateTimeOffset.Parse(at, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            actor, action, null, forgedData);
        using var upd = c.CreateCommand();
        upd.CommandText = "UPDATE ProofRecords SET Data = $d, Hash = $h, Mac = $m WHERE Seq = 2;";
        upd.Parameters.AddWithValue("$d", forgedData);
        upd.Parameters.AddWithValue("$h", forgedHash);
        upd.Parameters.AddWithValue("$m", attacker.Sign(forgedHash));
        upd.ExecuteNonQuery();
    }

    public void Dispose() { try { if (File.Exists(_path)) File.Delete(_path); } catch { } }
}
