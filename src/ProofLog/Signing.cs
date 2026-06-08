using System.Security.Cryptography;
using System.Text;

namespace ProofLog;

/// <summary>
/// Signs and verifies a record's hash. Two implementations ship:
/// <see cref="HmacProofSigner"/> (symmetric: the verifier holds the same secret) and
/// <see cref="EcdsaProofSigner"/> (asymmetric: a third party can verify with only the
/// public key, and so cannot forge). The signature is stored in
/// <see cref="ProofRecord.Mac"/>.
/// </summary>
/// <remarks>
/// Symmetric signing closes the full-rewrite gap (an attacker with database write
/// access can recompute every public hash, but not a valid MAC without the key).
/// Asymmetric signing goes one step further: you can hand an auditor the public key
/// so they can independently verify the chain was produced by your private key, and
/// they still cannot forge a record - which is what an evidence store handed to a
/// regulator actually needs.
/// </remarks>
public interface IProofSigner
{
    /// <summary>A short identifier for the algorithm, e.g. <c>HMAC-SHA256</c> or <c>ECDSA-P256-SHA256</c>.</summary>
    string Algorithm { get; }

    /// <summary>Whether this signer can produce signatures (it holds the secret/private key).
    /// A verify-only signer (public key only) returns <c>false</c> and throws from <see cref="Sign"/>.</summary>
    bool CanSign { get; }

    /// <summary>Sign a record's hash (lower-case hex), returning the signature as lower-case hex.</summary>
    string Sign(string hashHex);

    /// <summary>Verify a record's hash against its stored signature. Never throws on a malformed
    /// signature - it returns <c>false</c>.</summary>
    bool Verify(string hashHex, string signature);
}

/// <summary>
/// Symmetric HMAC-SHA-256 signing (the v0.2 behaviour). The same key both signs and
/// verifies, so anyone who can verify can also forge - fine when you control both
/// ends, but hand an auditor an asymmetric public key instead when they should be able
/// to verify without being able to forge.
/// </summary>
public sealed class HmacProofSigner : IProofSigner
{
    private readonly byte[] _key;

    /// <summary>Create an HMAC signer from a secret key.</summary>
    /// <param name="key">The shared secret. Keep it out of the database the log lives in.</param>
    public HmacProofSigner(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length == 0) throw new ArgumentException("Signing key must not be empty.", nameof(key));
        _key = (byte[])key.Clone();
    }

    /// <inheritdoc />
    public string Algorithm => "HMAC-SHA256";

    /// <inheritdoc />
    public bool CanSign => true;

    /// <inheritdoc />
    public string Sign(string hashHex) => Hashing.ComputeMac(_key, hashHex);

    /// <inheritdoc />
    public bool Verify(string hashHex, string signature)
    {
        var expected = Encoding.ASCII.GetBytes(Sign(hashHex));
        var actual = Encoding.ASCII.GetBytes(signature ?? "");
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}

/// <summary>
/// Asymmetric ECDSA (NIST P-256, SHA-256) signing. The private-key holder appends and
/// signs; anyone with the public key can verify the chain was produced by that key and
/// cannot forge a record. Built on the .NET BCL (<see cref="ECDsa"/>) - no extra
/// dependency. Keys export as base64 (SPKI public / PKCS#8 private) so you can publish
/// the public key with the dossier and keep the private key in a vault.
/// </summary>
public sealed class EcdsaProofSigner : IProofSigner, IDisposable
{
    private readonly ECDsa _ecdsa;
    private readonly bool _canSign;

    private EcdsaProofSigner(ECDsa ecdsa, bool canSign)
    {
        _ecdsa = ecdsa;
        _canSign = canSign;
    }

    /// <inheritdoc />
    public string Algorithm => "ECDSA-P256-SHA256";

    /// <inheritdoc />
    public bool CanSign => _canSign;

    /// <summary>Generate a fresh P-256 keypair. Export the keys before disposing if you
    /// need to reopen or share the log.</summary>
    public static EcdsaProofSigner Create() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256), canSign: true);

    /// <summary>Load a signer from a base64 PKCS#8 private key (can sign and verify).</summary>
    public static EcdsaProofSigner FromPrivateKey(string base64Pkcs8)
    {
        ArgumentNullException.ThrowIfNull(base64Pkcs8);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(base64Pkcs8), out _);
        return new EcdsaProofSigner(ecdsa, canSign: true);
    }

    /// <summary>Load a verify-only signer from a base64 SubjectPublicKeyInfo public key.
    /// This is what you give an auditor: it can verify the chain but cannot sign.</summary>
    public static EcdsaProofSigner FromPublicKey(string base64Spki)
    {
        ArgumentNullException.ThrowIfNull(base64Spki);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(base64Spki), out _);
        return new EcdsaProofSigner(ecdsa, canSign: false);
    }

    /// <summary>Export the public key as base64 SubjectPublicKeyInfo - safe to publish
    /// alongside the evidence so anyone can verify it.</summary>
    public string ExportPublicKey() => Convert.ToBase64String(_ecdsa.ExportSubjectPublicKeyInfo());

    /// <summary>Export the private key as base64 PKCS#8 - keep this secret.</summary>
    public string ExportPrivateKey()
    {
        if (!_canSign) throw new InvalidOperationException("This signer has only a public key; there is no private key to export.");
        return Convert.ToBase64String(_ecdsa.ExportPkcs8PrivateKey());
    }

    /// <inheritdoc />
    public string Sign(string hashHex)
    {
        if (!_canSign)
            throw new InvalidOperationException("This signer has only a public key; it can verify but not sign. Open the log with a private key to append.");
        var sig = _ecdsa.SignData(Encoding.UTF8.GetBytes(hashHex), HashAlgorithmName.SHA256);
        return Convert.ToHexString(sig).ToLowerInvariant();
    }

    /// <inheritdoc />
    public bool Verify(string hashHex, string signature)
    {
        if (string.IsNullOrEmpty(signature)) return false;
        try
        {
            return _ecdsa.VerifyData(Encoding.UTF8.GetBytes(hashHex), Convert.FromHexString(signature), HashAlgorithmName.SHA256);
        }
        catch (FormatException)
        {
            return false; // signature was not valid hex
        }
    }

    /// <summary>Release the underlying key handle.</summary>
    public void Dispose() => _ecdsa.Dispose();
}
