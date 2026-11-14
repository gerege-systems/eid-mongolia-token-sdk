using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Core.Tokens;

/// The eID objects on the token are found by CKA_ID (CKA_LABEL repeats it for people). During a certificate renewal
/// the new pair can sit under the staged IDs for a while. The CKA_ID only FINDS the object — whether the certificate
/// may log in is decided by the verifier (<see cref="LoginVerifier.AuthProfileProblem"/>). The same IDs on macOS.
public static class EidKeyId
{
    public static readonly byte[] Auth = [0x45, 0x49, 0x44, 0x01];          // "eID AUTH"
    public static readonly byte[] Sign = [0x45, 0x49, 0x44, 0x02];          // "eID SIGN"
    public static readonly byte[] StagedAuth = [0x45, 0x49, 0x44, 0x11];    // "eID AUTH (new)"
    public static readonly byte[] StagedSign = [0x45, 0x49, 0x44, 0x12];    // "eID SIGN (new)"

    public static CertificateKind KindOf(byte[] id)
    {
        ArgumentNullException.ThrowIfNull(id);
        if (id.AsSpan().SequenceEqual(Auth) || id.AsSpan().SequenceEqual(StagedAuth)) return CertificateKind.Auth;
        if (id.AsSpan().SequenceEqual(Sign) || id.AsSpan().SequenceEqual(StagedSign)) return CertificateKind.Sign;
        return CertificateKind.Other;
    }
}

public enum CertificateKind
{
    /// The login certificate (AUTH).
    Auth,
    /// The signature certificate (SIGN) — never used for login.
    Sign,
    Other,
}

/// One row of «Гэрчилгээ» (no PIN needed): type by CKA_ID, holder, subject serialNumber, issuer, serial, validity.
public sealed record CertificateView(CertificateKind Kind, string KeyIdHex, string SubjectName, string? SubjectSerial,
                                     string Issuer, string SerialHex, DateTimeOffset? NotBefore, DateTimeOffset? NotAfter,
                                     byte[] KeyId, byte[] Der)
{
    public string KindLabel => Label(Kind);

    /// "AUTH" / "SIGN" / "OTHER" — the command-line tool's JSON (the same values on macOS).
    public string KindCode => Kind switch
    {
        CertificateKind.Auth => "AUTH",
        CertificateKind.Sign => "SIGN",
        _ => "OTHER",
    };

    public static string Label(CertificateKind kind) => kind switch
    {
        CertificateKind.Auth => "Нэвтрэх",
        CertificateKind.Sign => "Гарын үсэг",
        _ => "Бусад",
    };

    public static CertificateView Describe(TokenCertificateObject obj)
    {
        ArgumentNullException.ThrowIfNull(obj);
        var kind = EidKeyId.KindOf(obj.Id);
        var idHex = Convert.ToHexString(obj.Id).ToLowerInvariant();
        try
        {
            using var cert = new X509Certificate2(obj.Der);
            var serials = Der.AttributeValues(cert.SubjectName.RawData, Der.SerialNumberAttribute);
            return new CertificateView(kind, idHex, Der.DisplayName(cert.SubjectName.RawData),
                serials.Count > 0 ? serials[0] : null, Der.DisplayName(cert.IssuerName.RawData), Der.SerialHex(cert),
                Der.NotBefore(cert), Der.NotAfter(cert), obj.Id, obj.Der);
        }
        catch (CryptographicException)
        {
            return new CertificateView(kind, idHex, string.IsNullOrEmpty(obj.Label) ? "—" : obj.Label, null, "—", "—",
                null, null, obj.Id, obj.Der);
        }
    }
}

/// The login flow the test app and the command-line tool share: pick the AUTH certificate, bind a fresh challenge to
/// the origin, ONE C_Login + C_Sign on the token, then the verifier's five checks. The same flow on macOS.
public static class TokenLogin
{
    public const string NoEidCertificates = "eID гэрчилгээ олдсонгүй";
    public const string NoAuthCertificate = "Токен дээр нэвтрэх (AUTH) гэрчилгээ алга";

    /// Any certificate under an eID CKA_ID (AUTH or SIGN, primary or staged).
    public static bool HasEidCertificates(IEnumerable<TokenCertificateObject> certificates) =>
        certificates.Any(c => EidKeyId.KindOf(c.Id) != CertificateKind.Other);

    /// The AUTH certificate: CKA_ID 45494401, else the staged 45494411.
    public static TokenCertificateObject? AuthCertificate(IReadOnlyList<TokenCertificateObject> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        return certificates.FirstOrDefault(c => c.Id.AsSpan().SequenceEqual(EidKeyId.Auth))
               ?? certificates.FirstOrDefault(c => c.Id.AsSpan().SequenceEqual(EidKeyId.StagedAuth));
    }

    /// One login attempt on the token in <paramref name="slotId"/>. The PIN state gate is the caller's (the app asks
    /// before the final try, the command-line tool refuses it). Exactly one C_Login; nothing is retried. Never throws.
    public static async Task<LoginReport> RunAsync(ITokenSource source, ulong slotId, string origin, string pin,
                                                   LoginVerifier verifier, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(verifier);
        if (!Origin.IsValid(origin)) return LoginReport.NotStarted(Origin.InvalidReason);
        IReadOnlyList<TokenCertificateObject> certificates;
        try
        {
            certificates = await Task.Run(() => source.ReadCertificates(slotId), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return LoginReport.NotStarted(ex.Message);
        }
        if (!HasEidCertificates(certificates)) return LoginReport.NotStarted(NoEidCertificates);
        if (AuthCertificate(certificates) is not { } auth) return LoginReport.NotStarted(NoAuthCertificate);
        return await verifier.RunAsync(origin, LoginChallenge.NewChallenge(), auth.Der,
            (digest, token) => Task.Run(() => source.SignDigest(slotId, auth.Id, digest, pin), token), ct).ConfigureAwait(false);
    }
}
