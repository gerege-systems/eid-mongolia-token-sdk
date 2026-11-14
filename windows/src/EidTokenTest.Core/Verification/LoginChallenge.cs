using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace EidTokenTest.Core.Verification;

/// Challenge binding, version 1. The relying party issues a challenge of EXACTLY 32 random bytes; the token's AUTH
/// key signs
///
///     SHA-256( UTF-8("eID-TOKEN-LOGIN-V1") ‖ UTF-8(origin) ‖ challenge )
///
/// where origin is the relying party's own host name (<see cref="Origin"/>). The same AUTH key also serves other
/// login protocols with their own prefixes: a client that signed arbitrary server-supplied bytes could be used to
/// relay a login to another site, so both the prefix and the origin are part of what is signed.
public static class LoginChallenge
{
    public const int Length = 32;
    public const string Context = "eID-TOKEN-LOGIN-V1";

    /// The origin field's default in the test apps.
    public const string DefaultOrigin = "test.example";

    /// 32 fresh random bytes.
    public static byte[] NewChallenge() => RandomNumberGenerator.GetBytes(Length);

    public static bool IsValidLength(byte[] challenge) => challenge is { Length: Length };

    /// The 32-byte digest the client hands to C_Sign (CKM_ECDSA does not hash). Throws
    /// <see cref="ArgumentException"/> when <paramref name="challenge"/> is not exactly 32 bytes or
    /// <paramref name="origin"/> is not a valid origin — then nothing may be signed.
    public static byte[] DigestToSign(string origin, byte[] challenge)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(challenge);
        if (!IsValidLength(challenge)) throw new ArgumentException(LengthMessage(challenge.Length), nameof(challenge));
        if (!Origin.IsValid(origin)) throw new ArgumentException(Origin.InvalidReason, nameof(origin));
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(Encoding.UTF8.GetBytes(Context));
        sha.AppendData(Encoding.UTF8.GetBytes(origin));
        sha.AppendData(challenge);
        return sha.GetHashAndReset();
    }

    internal static string LengthMessage(int length) =>
        "Challenge " + length.ToString(CultureInfo.InvariantCulture) + " байт (яг 32 байт байх ёстой)";
}
