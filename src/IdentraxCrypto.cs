using System.Security.Cryptography;
using System.Text;

namespace Identrax;

/// <summary>
/// Cryptographic helpers mirroring the platform exactly. Must reproduce
/// api-spec/examples/crypto_vectors.json (pinned by the test project).
/// Ed25519 verification uses NSec-free .NET: System.Security.Cryptography
/// gained Ed25519 in .NET 8 via the new AsymmetricAlgorithm; we use the
/// SHA-256 and HMAC come from the BCL; Ed25519 verification uses
/// BouncyCastle (the BCL has no Ed25519 in net8.0).
/// </summary>
public static class IdentraxCrypto
{
    public static string Sha256Hex(byte[] input) =>
        Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();

    /// <summary>The platform's stored/lookup form of a NIN.</summary>
    public static string NinHash(string nin) =>
        Sha256Hex(Encoding.UTF8.GetBytes(nin.Trim()));

    private static byte[] Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }

    /// <summary>Verify a base64url Ed25519 signature over a UTF-8 message.</summary>
    public static bool Ed25519Verify(string publicKeyB64Url, string message, string signatureB64Url)
    {
        try
        {
            var publicKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(
                Base64UrlDecode(publicKeyB64Url), 0);
            var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            verifier.Init(false, publicKey);
            var msg = Encoding.UTF8.GetBytes(message);
            verifier.BlockUpdate(msg, 0, msg.Length);
            return verifier.VerifySignature(Base64UrlDecode(signatureB64Url));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validate an X-Webhook-Signature header (<c>t=&lt;ts&gt;,v1=&lt;hex&gt;</c>):
    /// HMAC-SHA256 over "{t}.{body}", timestamp-bounded against replay.
    /// </summary>
    public static bool VerifyWebhookSignature(
        string secret, string header, string body, long nowUnix, long toleranceSecs = 300)
    {
        long? timestamp = null;
        string? signature = null;
        foreach (var part in header.Split(','))
        {
            var idx = part.IndexOf('=');
            if (idx < 0) continue;
            var key = part[..idx];
            var value = part[(idx + 1)..];
            if (key == "t")
            {
                if (!long.TryParse(value, out var parsed)) return false;
                timestamp = parsed;
            }
            else if (key == "v1") signature = value;
        }
        if (timestamp is null || signature is null) return false;
        if (Math.Abs(nowUnix - timestamp.Value) > toleranceSecs) return false;

        var expected = Convert.ToHexString(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(secret),
                Encoding.UTF8.GetBytes($"{timestamp}.{body}")))
            .ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signature));
    }
}
