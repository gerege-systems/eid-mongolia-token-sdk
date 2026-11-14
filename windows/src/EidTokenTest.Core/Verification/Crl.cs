using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace EidTokenTest.Core.Verification;

/// RFC 5280 CRL check for one certificate. Pure — the download is the caller's (<see cref="IRevocationTransport"/>).
/// The list must be issued and signed by the CA that issued the certificate, carry nextUpdate, be current (5 min
/// clock skew on thisUpdate and nextUpdate), be a full CRL without an issuingDistributionPoint or unknown critical
/// extensions, and not list the certificate's serial.
///
/// Order (the same on macOS): structure → issuer → signature → CRL extensions → nextUpdate present → thisUpdate in the
/// future → stale → entries (entry extensions, then the serial). Never throws.
public static class Crl
{
    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0);

    /// CRL extensions understood here: authorityKeyIdentifier, cRLNumber.
    private static readonly string[] KnownCrlExtensions = ["2.5.29.35", "2.5.29.20"];

    /// CRL entry extensions understood here: reasonCode, invalidityDate.
    private static readonly string[] KnownEntryExtensions = ["2.5.29.21", "2.5.29.24"];

    public static CheckResult Evaluate(byte[] crlDer, X509Certificate2 certificate, X509Certificate2 issuer, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(crlDer);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        const string name = CheckNames.Crl;
        var malformed = CheckResult.Fail(name, "CRL задрахгүй байна");
        try
        {
            var (tbs, algorithm, signature) = Der.ReadSigned(crlDer, out var rest);
            rest.ThrowIfNotEmpty();
            var list = new AsnReader(tbs, AsnEncodingRules.DER).ReadSequence();
            if (list.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)) list.ReadIntegerBytes();       // version v2
            if (list.ReadSequence().ReadObjectIdentifier() != algorithm) return malformed;            // signature
            var crlIssuer = list.ReadEncodedValue();
            var thisUpdate = Der.ReadTime(list);
            DateTimeOffset? nextUpdate = list.HasData && Der.IsTime(list.PeekTag()) ? Der.ReadTime(list) : null;
            AsnReader? revoked = null;
            if (list.HasData && list.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) revoked = list.ReadSequence();
            AsnReader? extensions = null;
            if (list.HasData && Der.IsContext(list.PeekTag(), 0))
            {
                var wrapper = list.ReadSequence(Context0);
                extensions = wrapper.ReadSequence();
                wrapper.ThrowIfNotEmpty();
            }
            list.ThrowIfNotEmpty();

            if (!crlIssuer.Span.SequenceEqual(issuer.SubjectName.RawData)
                || !crlIssuer.Span.SequenceEqual(certificate.IssuerName.RawData))
                return CheckResult.Fail(name, "CRL-ийг энэ гэрчилгээний олгогч гаргаагүй");
            switch (Der.Verify(tbs.Span, algorithm, signature, issuer))
            {
                case null: return CheckResult.Unknown(name, "CRL-ийн гарын үсгийн алгоритм дэмжигдээгүй");
                case false: return CheckResult.Fail(name, "CRL-ийн гарын үсэг олгогчийн түлхүүртэй таарахгүй");
            }
            var problem = extensions is null ? null : Der.CrlExtensionProblem(extensions, KnownCrlExtensions);
            if (problem is not null) return CheckResult.Unknown(name, problem);
            if (nextUpdate is not { } next)
                return CheckResult.Unknown(name, "CRL-д nextUpdate алга — шинэ эсэхийг тогтоох боломжгүй");
            var window = "thisUpdate " + DisplayDate.Format(thisUpdate) + ", nextUpdate " + DisplayDate.Format(next);
            if (Freshness.IsFuture(thisUpdate, now)) return CheckResult.Fail(name, "CRL ирээдүйн огноотой (" + window + ")");
            if (Freshness.IsStale(thisUpdate, next, now)) return CheckResult.Fail(name, "CRL хуучирсан (" + window + ")");

            if (revoked is not null)
            {
                var serial = Normalize(certificate.SerialNumberBytes.Span);
                while (revoked.HasData)
                {
                    // revokedCertificate { userCertificate, revocationDate, crlEntryExtensions OPTIONAL }
                    var entry = revoked.ReadSequence();
                    var number = entry.ReadIntegerBytes();
                    var at = Der.ReadTime(entry);
                    if (entry.HasData)
                    {
                        var entryProblem = Der.CrlExtensionProblem(entry.ReadSequence(), KnownEntryExtensions);
                        entry.ThrowIfNotEmpty();
                        if (entryProblem is not null) return CheckResult.Unknown(name, entryProblem);
                    }
                    if (Normalize(number.Span).SequenceEqual(serial))
                        return CheckResult.Fail(name, "Гэрчилгээ CRL-д цуцлагдсан (" + DisplayDate.Format(at) + ")");
                }
            }
            return CheckResult.Pass(name, "Жагсаалтад байхгүй (" + window + ")");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return malformed;
        }
    }

    /// INTEGER content without redundant leading zero bytes — the form serials are compared in.
    private static ReadOnlySpan<byte> Normalize(ReadOnlySpan<byte> value)
    {
        var start = 0;
        while (start < value.Length - 1 && value[start] == 0) start++;
        return value[start..];
    }
}
