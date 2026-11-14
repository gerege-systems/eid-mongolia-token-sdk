using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace EidTokenTest.Core.Verification;

/// The relying party's whole decision, made locally — no call to any eID service; the only network traffic is OCSP and
/// CRL at the URLs inside the certificates. The five checks, in this order (the same on macOS):
///
///  1. «Challenge-ийн гарын үсэг» — the digest of (<see cref="LoginChallenge"/>, origin) signed by the AUTH key
///     (CKM_ECDSA, P-256, raw r‖s), verified with the AUTH certificate's public key;
///  2. «Гэрчилгээний гинж» — path to the bundled root only, issued directly by the pinned 04
///     (<see cref="TrustAnchors.IssuingCa"/>), the AUTH profile (<see cref="AuthProfileProblem"/>), and 04 itself not
///     revoked (OCSP / CRL against 03);
///  3. «Хүчинтэй хугацаа» — every certificate of the path, both ends inclusive;
///  4. «OCSP» — the AUTH certificate at its AIA URL, echoed nonce REQUIRED;
///  5. «CRL» — the AUTH certificate at its CDP URL.
///
/// Fail closed: logged in only when all five pass. <see cref="VerifyAsync"/> and <see cref="RunAsync"/> never throw —
/// not for bad input either (null, empty or garbage certificate, wrong-length challenge, invalid origin): every
/// network / IO / parsing exception and every rejected input becomes a result row («шалгаж чадсангүй» or ✗).
public sealed class LoginVerifier
{
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private static readonly byte[] P256Parameters = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// The order n of P-256 (big-endian): signature scalars must be 1 ≤ r, s ≤ n − 1.
    internal static readonly byte[] P256Order =
    [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ];

    private readonly TrustAnchors _trust;
    private readonly IRevocationTransport _transport;
    private readonly Func<DateTimeOffset> _now;

    public LoginVerifier(TrustAnchors trust, IRevocationTransport transport, Func<DateTimeOffset>? now = null)
    {
        _trust = trust;
        _transport = transport;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    internal const string UnreadableCertificate = "AUTH гэрчилгээг уншиж чадсангүй (нэг DER гэрчилгээ биш)";

    /// Invalid origin → wrong-length challenge → certificate that is not one strict DER certificate:
    /// <see cref="LoginReport.InputRejected"/> (signature ✗, the rest «шалгаж чадсангүй», no network, nothing signed);
    /// null = go on with <paramref name="certificate"/> loaded (caller disposes). The same order on macOS.
    private static LoginReport? RejectInput(string? origin, byte[]? challenge, byte[]? der, out X509Certificate2 certificate)
    {
        certificate = null!;
        if (!Origin.IsValid(origin)) return LoginReport.InputRejected(Origin.InvalidReason);
        if (challenge is null || !LoginChallenge.IsValidLength(challenge))
            return LoginReport.InputRejected(LoginChallenge.LengthMessage(challenge?.Length ?? 0));
        if (!Der.TryLoadCertificate(der, out certificate)) return LoginReport.InputRejected(UnreadableCertificate);
        return null;
    }

    /// The test apps' whole login: origin, challenge (exactly 32 bytes), certificate and key type are checked BEFORE
    /// anything is signed (the same rejection as <see cref="VerifyAsync"/>); then <paramref name="signDigest"/> is
    /// called ONCE with the digest (C_Login + C_Sign on the token). An exception from it makes the signature row
    /// «шалгаж чадсангүй» with its message; the other checks still run.
    public async Task<LoginReport> RunAsync(string origin, byte[] challenge, byte[] authCertificateDer,
                                            Func<byte[], CancellationToken, Task<byte[]>> signDigest,
                                            CancellationToken ct = default)
    {
        if (RejectInput(origin, challenge, authCertificateDer, out var certificate) is { } rejected) return rejected;
        using (certificate)
        {
            CheckResult signature;
            if (!IsP256(certificate))
            {
                signature = CheckResult.Fail(CheckNames.Signature, "AUTH гэрчилгээний түлхүүр EC P-256 биш");
            }
            else
            {
                try
                {
                    var raw = await signDigest(LoginChallenge.DigestToSign(origin, challenge), ct).ConfigureAwait(false);
                    signature = SignatureCheck(certificate, origin, challenge, raw ?? []);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    signature = CheckResult.Unknown(CheckNames.Signature, ex.Message);
                }
            }
            return await CheckAllAsync(certificate, signature, ct).ConfigureAwait(false);
        }
    }

    /// The relying party's decision from what the client sent back: <paramref name="origin"/> is the relying party's
    /// own host name — a constant from its configuration, never taken from the request — and
    /// <paramref name="challenge"/> the 32 bytes it issued; the signed digest is computed here.
    public async Task<LoginReport> VerifyAsync(string origin, byte[] challenge, byte[] signature, byte[] authCertificateDer,
                                               CancellationToken ct = default)
    {
        if (RejectInput(origin, challenge, authCertificateDer, out var certificate) is { } rejected) return rejected;
        using (certificate)
        {
            return await CheckAllAsync(certificate, SignatureCheck(certificate, origin, challenge, signature ?? []), ct)
                .ConfigureAwait(false);
        }
    }

    private async Task<LoginReport> CheckAllAsync(X509Certificate2 certificate, CheckResult signature, CancellationToken ct)
    {
        var chainCertificates = new List<X509Certificate2>();
        try
        {
            var now = _now();
            var chain = Chain(certificate, now, chainCertificates);
            if (chain.State == CheckState.Pass)
                chain = await WithIssuingCaRevocationAsync(chain, chainCertificates, now, ct).ConfigureAwait(false);
            var validity = Validity(certificate, chainCertificates, now);
            var issuer = _trust.IssuerOf(certificate);
            var ocsp = await OcspAsync(certificate, issuer, nonceRequired: true, now, ct).ConfigureAwait(false);
            var crl = await CrlAsync(certificate, issuer, now, ct).ConfigureAwait(false);
            var serials = Der.AttributeValues(certificate.SubjectName.RawData, Der.SerialNumberAttribute);
            return new LoginReport([signature, chain, validity, ocsp, crl], Der.DisplayName(certificate.SubjectName.RawData))
            {
                HolderSerialNumber = serials.Count == 1 ? serials[0] : null,
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return LoginReport.NotStarted("Шалгалтыг гүйцээж чадсангүй (" + ex.GetType().Name + ")");
        }
        finally
        {
            foreach (var c in chainCertificates) c.Dispose();
        }
    }

    /// «Challenge-ийн гарын үсэг»: P-256 AUTH key only; raw r‖s of exactly 64 bytes with 1 ≤ r, s &lt; n, verified over
    /// the digest computed HERE from (origin, challenge) — never over a caller-supplied digest.
    internal static CheckResult SignatureCheck(X509Certificate2 certificate, string origin, byte[] challenge, byte[] signature)
    {
        const string name = CheckNames.Signature;
        if (!LoginChallenge.IsValidLength(challenge)) return CheckResult.Fail(name, LoginChallenge.LengthMessage(challenge.Length));
        if (!Origin.IsValid(origin)) return CheckResult.Fail(name, Origin.InvalidReason);
        if (!IsP256(certificate)) return CheckResult.Fail(name, "AUTH гэрчилгээний түлхүүр EC P-256 биш");
        if (signature.Length != 64)
            return CheckResult.Fail(name, "Гарын үсгийн урт " + signature.Length.ToString(CultureInfo.InvariantCulture)
                                          + " байт (r‖s 64 байт хүлээсэн)");
        if (!IsValidScalar(signature.AsSpan(0, 32)) || !IsValidScalar(signature.AsSpan(32, 32)))
            return CheckResult.Fail(name, "Гарын үсгийн r эсвэл s хүчингүй (0 эсвэл ≥ n)");
        var digest = LoginChallenge.DigestToSign(origin, challenge);
        bool ok;
        try
        {
            using var key = certificate.GetECDsaPublicKey();
            ok = key is not null && key.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            ok = false;
        }
        return ok
            ? CheckResult.Pass(name, "ECDSA P-256 / SHA-256 (" + LoginChallenge.Context + ", origin " + origin + ")")
            : CheckResult.Fail(name, "Гарын үсэг AUTH гэрчилгээний түлхүүртэй таарахгүй");
    }

    /// subjectPublicKeyInfo is id-ecPublicKey on the named curve P-256.
    internal static bool IsP256(X509Certificate2 certificate) =>
        certificate.PublicKey.Oid.Value == EcPublicKeyOid
        && certificate.PublicKey.EncodedParameters.RawData.AsSpan().SequenceEqual(P256Parameters);

    /// 1 ≤ x ≤ n − 1 for a 32-byte big-endian scalar.
    internal static bool IsValidScalar(ReadOnlySpan<byte> x) =>
        x.Length == 32 && x.IndexOfAnyExcept((byte)0) >= 0 && x.SequenceCompareTo(P256Order) < 0;

    /// The token AUTH certificate profile, identical on macOS and Windows: KeyUsage present with EXACTLY
    /// {digitalSignature}; ExtendedKeyUsage present and containing clientAuth; exactly one subject serialNumber,
    /// starting with `PNOMN-`. A missing extension fails. null = the profile holds.
    public static string? AuthProfileProblem(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var bits = Der.KeyUsageBits(certificate);
        if (bits is null) return "AUTH профайл: KeyUsage өргөтгөл алга";
        if (bits.Count != 1 || !bits.Contains(0)) return "AUTH профайл: KeyUsage нь зөвхөн digitalSignature байх ёстой";
        var eku = Der.ExtendedKeyUsage(certificate);
        if (eku is null) return "AUTH профайл: ExtendedKeyUsage өргөтгөл алга";
        if (!eku.Contains(Der.ClientAuthEku)) return "AUTH профайл: ExtendedKeyUsage-д clientAuth алга";
        var serials = Der.AttributeValues(certificate.SubjectName.RawData, Der.SerialNumberAttribute);
        if (serials.Count != 1 || !serials[0].StartsWith("PNOMN-", StringComparison.Ordinal))
            return "AUTH профайл: subject serialNumber нь PNOMN- угтвартай ганц утга байх ёстой";
        return null;
    }

    /// «Гэрчилгээний гинж» — the same decision, in the same order, as `ChainCheck.chain` on macOS:
    ///
    ///  1. the CA path above the AUTH certificate is taken from the bundled certificates only, starting at the PINNED
    ///     04 (<see cref="TrustAnchors.CaPath"/>): each CA on it must be within its validity period (an expired CA fails
    ///     HERE) and the path must reach a bundled root;
    ///  2. X509Chain evaluates the AUTH certificate against the bundled roots only (CustomRootTrust), no downloads, no
    ///     revocation (checks 4 and 5 and the issuing CA's own revocation below), at the same instant and with the same
    ///     time rule as macOS (every certificate of the platform's path valid then). .NET cannot keep Windows from also
    ///     looking at intermediates in the machine's CA store, so the platform's path may run through another copy of
    ///     04 (same subject and key): the platform then checks the AUTH certificate's signature with that copy's
    ///     (identical) key and applies that copy's constraints. The path is accepted only when
    ///  3. element [1] of the platform's path has the SAME subject AND the SAME public key as the pinned 04. From here
    ///     on only the pinned 04 is used: the validity / path check from trust/ (1), issuer identification
    ///     (<see cref="TrustAnchors.IssuerOf"/>) and the OCSP / CRL verification;
    ///  4. the AUTH profile (<see cref="AuthProfileProblem"/>).
    ///
    /// <paramref name="cas"/> receives copies of the pinned path (pinned 04 DER first, root last; caller disposes) —
    /// what the validity check and the issuing CA's revocation check use. Everything is judged at
    /// <paramref name="now"/> clamped into the AUTH certificate's validity period, so that an expired AUTH certificate
    /// is reported by the validity check, not here.
    internal CheckResult Chain(X509Certificate2 certificate, DateTimeOffset now, List<X509Certificate2> cas)
    {
        const string name = CheckNames.Chain;
        if (_trust.Roots.Count == 0) return CheckResult.Unknown(name, "Итгэлийн үндэс (trust anchor) апп-д алга");
        if (_trust.IssuingCa is not { } pinned) return CheckResult.Unknown(name, "Олгогч CA (04) апп-д алга");
        var notTrusted = CheckResult.Fail(name, "Итгэмжлэгдсэн үндэс хүртэл гинж баталгаажсангүй");

        var from = Der.NotBefore(certificate);
        var to = Der.NotAfter(certificate);
        var at = now < from ? from : now > to ? to : now;
        var path = _trust.CaPath(pinned);
        if (path.FirstOrDefault(c => !Der.IsValidAt(c, at)) is { } expired)
            return CheckResult.Fail(name, ExpiredCaReason(Der.DisplayName(expired.SubjectName.RawData)));
        if (!_trust.Roots.Any(r => r.RawData.AsSpan().SequenceEqual(path[^1].RawData))) return notTrusted;

        using var chain = new X509Chain();
        var policy = chain.ChainPolicy;
        policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        policy.CustomTrustStore.AddRange(_trust.Roots.ToArray());
        policy.ExtraStore.AddRange(_trust.Intermediates.ToArray());
        policy.RevocationMode = X509RevocationMode.NoCheck;           // OCSP and CRL: below and checks 4 and 5
        policy.DisableCertificateDownloads = true;
        // Time validity is checked like Security.framework does on macOS; only the legacy "nested validity" rule
        // (which macOS does not apply) is ignored.
        policy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeNested;
        // At the AUTH certificate's last second OpenSSL (.NET on Linux) already treats it as expired (notAfter
        // exclusive) while Windows and macOS do not: the platform evaluates one second earlier then, on every platform.
        // The time rules themselves are this code's (step 1 above and the validity check), unchanged.
        policy.VerificationTime = PlatformInstant(at, from, to).UtcDateTime;
        policy.VerificationTimeIgnored = false;

        var built = chain.Build(certificate);
        var elements = chain.ChainElements.Cast<X509ChainElement>().Select(e => e.Certificate).ToList();
        if (!built || elements.Count < 2 || !elements[0].RawData.AsSpan().SequenceEqual(certificate.RawData)
            || !_trust.Roots.Any(r => r.RawData.AsSpan().SequenceEqual(elements[^1].RawData)))
            return notTrusted;
        if (!elements[1].SubjectName.RawData.AsSpan().SequenceEqual(pinned.SubjectName.RawData)
            || !SubjectPublicKeyInfo(elements[1]).AsSpan().SequenceEqual(SubjectPublicKeyInfo(pinned)))
            return CheckResult.Fail(name, "Гэрчилгээг eID Mongolia Issuing CA (04) шууд олгоогүй");

        foreach (var ca in path) cas.Add(X509CertificateLoader.LoadCertificate(ca.RawData));
        if (AuthProfileProblem(certificate) is { } problem) return CheckResult.Fail(name, problem);
        var names = new[] { certificate }.Concat(cas).Select(c => Der.DisplayName(c.SubjectName.RawData));
        return CheckResult.Pass(name, string.Join(" → ", names));
    }

    /// The instant the platform evaluates the path at: <paramref name="at"/>, or one second before the AUTH
    /// certificate's notAfter when <paramref name="at"/> is that very second (the same rule on macOS).
    internal static DateTimeOffset PlatformInstant(DateTimeOffset at, DateTimeOffset notBefore, DateTimeOffset notAfter) =>
        at >= notAfter && notAfter.AddSeconds(-1) >= notBefore ? notAfter.AddSeconds(-1) : at;

    /// «Гинжний гэрчилгээ (‹нэр›) хүчинтэй хугацаанаас гадуур» — the same text in the chain and validity rows.
    internal static string ExpiredCaReason(string name) => "Гинжний гэрчилгээ (" + name + ") хүчинтэй хугацаанаас гадуур";

    private static byte[] SubjectPublicKeyInfo(X509Certificate2 certificate) => certificate.PublicKey.ExportSubjectPublicKeyInfo();

    /// «Гэрчилгээний гинж» also covers the issuing CA (<paramref name="cas"/>[0]) not being revoked: the same OCSP and
    /// CRL code against ITS issuer (<paramref name="cas"/>[1]), at the URLs in the CA certificate. The OCSP nonce is
    /// optional here (the CA-level answers are pre-signed). A CA certificate with neither AIA nor CDP → «шалгаж
    /// чадсангүй»; with only one of them, that one decides.
    private async Task<CheckResult> WithIssuingCaRevocationAsync(CheckResult chain, IReadOnlyList<X509Certificate2> cas,
                                                                 DateTimeOffset now, CancellationToken ct)
    {
        if (cas.Count < 2) return CheckResult.Unknown(CheckNames.Chain, "Олгогч CA-ийн дээд CA гинжид алга");
        var ca = cas[0];
        var parent = cas[1];
        var caName = Der.DisplayName(ca.SubjectName.RawData);
        var hasOcsp = Der.OcspUris(ca).Count > 0;
        var hasCrl = Der.CrlUris(ca).Count > 0;
        if (!hasOcsp && !hasCrl)
            return CheckResult.Unknown(CheckNames.Chain,
                "Олгогч CA (" + caName + ")-ийн гэрчилгээнд AIA ч CDP ч алга — цуцлалтыг шалгаж чадсангүй");
        var parts = new List<CheckResult>();
        var missing = new List<string>();
        if (hasOcsp) parts.Add(await OcspAsync(ca, parent, nonceRequired: false, now, ct).ConfigureAwait(false));
        else missing.Add("OCSP: AIA алга");
        if (hasCrl) parts.Add(await CrlAsync(ca, parent, now, ct).ConfigureAwait(false));
        else missing.Add("CRL: CDP алга");

        var bad = parts.FirstOrDefault(p => p.State == CheckState.Fail) ?? parts.FirstOrDefault(p => p.State == CheckState.Unknown);
        if (bad is not null) return new CheckResult(CheckNames.Chain, bad.State, "Олгогч CA (" + caName + ") — " + bad.Name + ": " + bad.Reason);
        var summary = parts.Select(p => p.Name + " ✓").Concat(missing);
        return CheckResult.Pass(CheckNames.Chain, chain.Reason + "; олгогч CA цуцлагдаагүй (" + string.Join(", ", summary) + ")");
    }

    /// Every certificate of the path within its validity period at <paramref name="now"/> (notBefore ≤ now ≤ notAfter).
    internal static CheckResult Validity(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> cas, DateTimeOffset now)
    {
        const string name = CheckNames.Validity;
        var from = Der.NotBefore(certificate);
        var to = Der.NotAfter(certificate);
        if (now < from) return CheckResult.Fail(name, "Гэрчилгээ " + DisplayDate.Format(from) + "-аас хүчинтэй болно");
        if (now > to) return CheckResult.Fail(name, "Гэрчилгээний хугацаа " + DisplayDate.Format(to) + "-нд дууссан");
        var ca = cas.FirstOrDefault(c => !Der.IsValidAt(c, now));
        if (ca is not null)
            return CheckResult.Fail(name, ExpiredCaReason(Der.DisplayName(ca.SubjectName.RawData)));
        return CheckResult.Pass(name, DisplayDate.Format(from) + " – " + DisplayDate.Format(to));
    }

    /// OCSP for <paramref name="certificate"/> against <paramref name="issuer"/> at the certificate's AIA URLs (the
    /// AUTH certificate or the issuing CA). Any exception from the transport → «шалгаж чадсангүй».
    private async Task<CheckResult> OcspAsync(X509Certificate2 certificate, X509Certificate2? issuer, bool nonceRequired,
                                              DateTimeOffset now, CancellationToken ct)
    {
        if (issuer is null) return CheckResult.Unknown(CheckNames.Ocsp, "Олгогч CA (04) апп-д алга");
        var urls = Der.OcspUris(certificate);
        if (urls.Count == 0) return CheckResult.Unknown(CheckNames.Ocsp, "Гэрчилгээнд OCSP хаяг (AIA) алга");
        var request = Ocsp.CreateRequest(certificate, issuer, out var nonce);
        var lastHost = string.Empty;
        foreach (var url in urls)
        {
            byte[] response;
            try
            {
                response = await _transport.PostOcspAsync(url, request, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                lastHost = url.Host;
                continue;
            }
            return Ocsp.Evaluate(response, certificate, issuer, nonce, nonceRequired, now);
        }
        return CheckResult.Unknown(CheckNames.Ocsp, "OCSP руу холбогдож чадсангүй (" + lastHost + ")");
    }

    /// CRL for <paramref name="certificate"/> against <paramref name="issuer"/> at the certificate's CDP URLs. Any
    /// exception from the transport → «шалгаж чадсангүй».
    private async Task<CheckResult> CrlAsync(X509Certificate2 certificate, X509Certificate2? issuer, DateTimeOffset now,
                                             CancellationToken ct)
    {
        if (issuer is null) return CheckResult.Unknown(CheckNames.Crl, "Олгогч CA (04) апп-д алга");
        var urls = Der.CrlUris(certificate);
        if (urls.Count == 0) return CheckResult.Unknown(CheckNames.Crl, "Гэрчилгээнд CRL хаяг (CDP) алга");
        var lastHost = string.Empty;
        foreach (var url in urls)
        {
            byte[] crl;
            try
            {
                crl = await _transport.GetCrlAsync(url, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                lastHost = url.Host;
                continue;
            }
            return Crl.Evaluate(crl, certificate, issuer, now);
        }
        return CheckResult.Unknown(CheckNames.Crl, "CRL татаж чадсангүй (" + lastHost + ")");
    }
}
