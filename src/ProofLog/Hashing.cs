using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ProofLog;

/// <summary>
/// Deterministic canonicalization + SHA-256 hashing of a record.
/// </summary>
/// <remarks>
/// Each field is written length-prefixed (a 4-byte big-endian length, then UTF-8
/// bytes) so concatenation is unambiguous: there is no separator a value could
/// contain to forge an equivalent encoding (e.g. <c>"ab"+"c"</c> can never collide
/// with <c>"a"+"bc"</c>). The previous hash, sequence, and timestamp are part of the
/// input, so editing, reordering, inserting, or deleting a record changes its hash.
/// </remarks>
public static class Hashing
{
    /// <summary>The previous-hash used for the very first record (64 hex zeros).</summary>
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>Compute a record's hash (lower-case hex) from its canonical fields.</summary>
    public static string ComputeHash(string prevHash, long seq, DateTimeOffset at, string actor, string action, string? resource, string? data)
    {
        using var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(ih, prevHash);
        Append(ih, seq.ToString(CultureInfo.InvariantCulture));
        Append(ih, at.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture));
        Append(ih, actor);
        Append(ih, action);
        Append(ih, resource ?? "");
        Append(ih, data ?? "");
        return Convert.ToHexString(ih.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>HMAC-SHA-256 of a record's hash with the signing key (lower-case hex).</summary>
    public static string ComputeMac(byte[] key, string hashHex) =>
        Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(hashHex))).ToLowerInvariant();

    private static void Append(IncrementalHash ih, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, bytes.Length);
        ih.AppendData(len);
        ih.AppendData(bytes);
    }
}
