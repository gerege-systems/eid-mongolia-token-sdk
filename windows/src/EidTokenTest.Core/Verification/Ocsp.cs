using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EidTokenTest.Core.Verification;

/// RFC 6960 OCSP for one certificate: building the request and judging the response. Pure — the HTTP exchange is the
/// caller's (<see cref="IRevocationTransport"/>). The same code checks the AUTH certificate (issuer 04, nonce
/// REQUIRED) and the issuing CA certificate itself (issuer 03, nonce optional — those answers are pre-signed and
/// carry no nonce).
public static class Ocsp
{
    internal const string NonceOid = "1.3.6.1.5.5.7.48.1.2";
    internal const string BasicResponseOid = "1.3.6.1.5.5.7.48.1.1";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag Context1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag Context2 = new(TagClass.ContextSpecific, 2);

    /// `OCSPRequest` for <paramref name="certificate"/> (CertID with SHA-256) with a fresh 32-byte nonce (RFC 8954).
    public static byte[] CreateRequest(X509Certificate2 certificate, X509Certificate2 issuer, out byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        nonce = RandomNumberGenerator.GetBytes(32);
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())                                    // OCSPRequest
        {
            using (w.PushSequence())                                // TBSRequest
            {
                using (w.PushSequence())                            // requestList
                using (w.PushSequence())                            // Request
                {
                    WriteCertId(w, Der.Sha256, certificate, issuer);
                }
                using (w.PushSequence(Context2))                    // requestExtensions [2] EXPLICIT
                using (w.PushSequence())                            // Extensions
                using (w.PushSequence())                            // Extension
                {
                    w.WriteObjectIdentifier(NonceOid);
                    w.WriteOctetString(NonceValue(nonce));
                }
            }
        }
        return w.Encode();
    }

    /// The nonce extension's extnValue: the nonce as a DER OCTET STRING (RFC 8954).
    internal static byte[] NonceValue(byte[] nonce)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteOctetString(nonce);
        return w.Encode();
    }

    internal static void WriteCertId(AsnWriter w, string hashAlgorithm, X509Certificate2 certificate, X509Certificate2 issuer)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(hashAlgorithm);
                w.WriteNull();
            }
            w.WriteOctetString(Der.Hash(hashAlgorithm, issuer.SubjectName.RawData));
            w.WriteOctetString(Der.KeyHash(hashAlgorithm, issuer));
            w.WriteInteger(certificate.SerialNumberBytes.Span);
        }
    }

    /// Judges a DER `OCSPResponse` for <paramref name="certificate"/> issued by <paramref name="issuer"/>.
    /// <paramref name="expectedNonce"/> = what the request carried; <paramref name="nonceRequired"/>: the response MUST
    /// echo it (AUTH certificate), otherwise an echoed nonce must still match.
    ///
    /// Order (the same on macOS): responseStatus → response type → structure → signer (the issuer, or a delegated
    /// responder: issued by the issuer, id-kp-OCSPSigning, valid now) → signature → nonce → the SingleResponse for
    /// this CertID: revoked → thisUpdate in the future → stale → unknown → good. Never throws.
    public static CheckResult Evaluate(byte[] responseDer, X509Certificate2 certificate, X509Certificate2 issuer,
                                       byte[]? expectedNonce, bool nonceRequired, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(responseDer);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        const string name = CheckNames.Ocsp;
        var malformed = CheckResult.Fail(name, "OCSP хариу задрахгүй байна");
        var embedded = new List<X509Certificate2>();
        try
        {
            var outer = new AsnReader(responseDer, AsnEncodingRules.DER);
            var top = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var status = top.ReadEnumeratedBytes().Span;
            if (status.Length != 1) return malformed;
            if (status[0] != 0)
                return CheckResult.Unknown(name, "OCSP responder амжилтгүй хариу өгсөн (responseStatus " +
                                                 status[0].ToString(CultureInfo.InvariantCulture) + ")");
            if (!top.HasData) return malformed;
            var bytes = top.ReadSequence(Context0).ReadSequence();
            top.ThrowIfNotEmpty();
            var type = bytes.ReadObjectIdentifier();
            var basicDer = bytes.ReadOctetString();
            bytes.ThrowIfNotEmpty();
            if (type != BasicResponseOid) return CheckResult.Unknown(name, "OCSP хариуны төрөл дэмжигдээгүй");

            var (tbs, algorithm, signature) = Der.ReadSigned(basicDer, out var rest);
            if (rest.HasData)
            {
                var certs = rest.ReadSequence(Context0).ReadSequence();
                while (certs.HasData)
                {
                    // Strict DER, one certificate each — never handed to a loader that also takes PEM / PKCS#7 / PFX.
                    if (!Der.TryLoadCertificate(certs.ReadEncodedValue().ToArray(), out var responder)) return malformed;
                    embedded.Add(responder);
                }
            }
            rest.ThrowIfNotEmpty();

            var data = new AsnReader(tbs, AsnEncodingRules.DER).ReadSequence();
            if (data.HasData && Der.IsContext(data.PeekTag(), 0)) data.ReadSequence(Context0);           // version
            byte[]? responderName = null, responderKeyHash = null;
            var idTag = data.PeekTag();
            if (Der.IsContext(idTag, 1)) responderName = data.ReadSequence(Context1).ReadEncodedValue().ToArray();
            else if (Der.IsContext(idTag, 2)) responderKeyHash = data.ReadSequence(Context2).ReadOctetString();
            else return malformed;
            Der.ReadTime(data);                                                                            // producedAt
            var responses = data.ReadSequence();
            byte[]? echoedNonce = null;
            if (data.HasData) echoedNonce = FindExtension(data.ReadSequence(Context1), NonceOid);
            data.ThrowIfNotEmpty();

            // Who signed: the issuer itself, or a delegated responder certificate carried in the response.
            var signer = new[] { issuer }.Concat(embedded).FirstOrDefault(c =>
                responderKeyHash is not null
                    ? Der.KeyHash(Der.Sha1, c).AsSpan().SequenceEqual(responderKeyHash)
                    : c.SubjectName.RawData.AsSpan().SequenceEqual(responderName!));
            if (signer is null) return CheckResult.Fail(name, "OCSP хариуг хэн зурсан нь тодорхойгүй (responderID таарахгүй)");
            if (!signer.RawData.AsSpan().SequenceEqual(issuer.RawData))
            {
                if (!Der.IsSignedBy(signer, issuer))
                    return CheckResult.Fail(name, "OCSP responder-ийн гэрчилгээг энэ гэрчилгээний олгогч олгоогүй");
                if (!Der.HasEku(signer, Der.OcspSigningEku))
                    return CheckResult.Fail(name, "OCSP responder-ийн гэрчилгээнд id-kp-OCSPSigning алга");
                if (!Der.IsValidAt(signer, now))
                    return CheckResult.Fail(name, "OCSP responder-ийн гэрчилгээ хүчинтэй хугацаанаас гадуур");
            }
            switch (Der.Verify(tbs.Span, algorithm, signature, signer))
            {
                case null: return CheckResult.Unknown(name, "OCSP хариуны гарын үсгийн алгоритм дэмжигдээгүй");
                case false: return CheckResult.Fail(name, "OCSP хариуны гарын үсэг буруу");
            }

            if (echoedNonce is not null)
            {
                if (expectedNonce is null
                    || !(echoedNonce.AsSpan().SequenceEqual(NonceValue(expectedNonce)) || echoedNonce.AsSpan().SequenceEqual(expectedNonce)))
                    return CheckResult.Fail(name, "OCSP хариуны nonce манай хүсэлтийнхтэй таарахгүй");
            }
            else if (nonceRequired)
            {
                return CheckResult.Fail(name, "OCSP хариунд nonce алга (AUTH гэрчилгээнд заавал)");
            }

            // The SingleResponse for this certificate. Entries whose CertID is about another certificate — or cannot be
            // read as a CertID at all — are skipped; the matching entry must be well-formed, otherwise ✗ (the same
            // rule on macOS).
            while (responses.HasData)
            {
                var entry = responses.ReadEncodedValue();
                if (!IsEntryFor(entry, certificate, issuer)) continue;
                var single = new AsnReader(entry, AsnEncodingRules.DER).ReadSequence();
                single.ReadSequence();                                                   // certID (matched above)
                var statusTag = single.PeekTag();
                DateTimeOffset? revokedAt = null;
                int state;
                if (Der.IsContext(statusTag, 0)) { single.ReadNull(Context0); state = 0; }
                else if (Der.IsContext(statusTag, 1))
                {
                    var info = single.ReadSequence(Context1);                           // RevokedInfo
                    revokedAt = Der.ReadTime(info);
                    if (info.HasData)
                    {
                        var reason = info.ReadSequence(Context0);                       // revocationReason [0] EXPLICIT
                        reason.ReadEnumeratedBytes();
                        reason.ThrowIfNotEmpty();
                    }
                    info.ThrowIfNotEmpty();
                    state = 1;
                }
                else if (Der.IsContext(statusTag, 2)) { single.ReadNull(Context2); state = 2; }
                else return malformed;
                var thisUpdate = Der.ReadTime(single);
                DateTimeOffset? nextUpdate = null;
                if (single.HasData && Der.IsContext(single.PeekTag(), 0))
                {
                    var next = single.ReadSequence(Context0);
                    nextUpdate = Der.ReadTime(next);
                    next.ThrowIfNotEmpty();
                }
                if (single.HasData && Der.IsContext(single.PeekTag(), 1))
                {
                    var wrapper = single.ReadSequence(Context1);                        // singleExtensions
                    ReadExtensions(wrapper.ReadSequence());
                    wrapper.ThrowIfNotEmpty();
                }
                single.ThrowIfNotEmpty();
                var window = "thisUpdate " + DisplayDate.Format(thisUpdate)
                             + (nextUpdate is { } n ? ", nextUpdate " + DisplayDate.Format(n) : string.Empty);

                if (state == 1)                                                  // revoked: cancellation never expires
                    return CheckResult.Fail(name, "Гэрчилгээ цуцлагдсан (" + DisplayDate.Format(revokedAt!.Value) + ")");
                if (Freshness.IsFuture(thisUpdate, now))
                    return CheckResult.Fail(name, "OCSP хариу ирээдүйн огноотой (" + window + ")");
                if (Freshness.IsStale(thisUpdate, nextUpdate, now))
                    return CheckResult.Fail(name, "OCSP хариу хуучирсан (" + window + ")");
                if (state == 2) return CheckResult.Fail(name, "OCSP: unknown — responder энэ гэрчилгээг танихгүй");
                return CheckResult.Pass(name, "good (" + window + ")");
            }
            return CheckResult.Fail(name, "OCSP хариунд энэ гэрчилгээний төлөв алга (CertID таарахгүй)");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return malformed;
        }
        finally
        {
            foreach (var c in embedded) c.Dispose();
        }
    }

    /// <paramref name="entry"/> is a SEQUENCE starting with a well-formed CertID for <paramref name="certificate"/>
    /// issued by <paramref name="issuer"/>. Anything else — another certificate, or no readable CertID — is false (the
    /// entry is skipped).
    private static bool IsEntryFor(ReadOnlyMemory<byte> entry, X509Certificate2 certificate, X509Certificate2 issuer)
    {
        try
        {
            return CertIdMatches(new AsnReader(entry, AsnEncodingRules.DER).ReadSequence().ReadSequence(), certificate, issuer);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            return false;
        }
    }

    /// CertID { AlgorithmIdentifier, OCTET STRING, OCTET STRING, INTEGER } with SHA-1 or SHA-256 (the responder may
    /// answer in either). Throws on a malformed CertID.
    internal static bool CertIdMatches(AsnReader certId, X509Certificate2 certificate, X509Certificate2 issuer)
    {
        var hashAlgorithm = certId.ReadSequence().ReadObjectIdentifier();
        var nameHash = certId.ReadOctetString();
        var keyHash = certId.ReadOctetString();
        var serial = certId.ReadIntegerBytes();
        certId.ThrowIfNotEmpty();
        if (hashAlgorithm is not (Der.Sha1 or Der.Sha256)) return false;
        return nameHash.AsSpan().SequenceEqual(Der.Hash(hashAlgorithm, issuer.SubjectName.RawData))
               && keyHash.AsSpan().SequenceEqual(Der.KeyHash(hashAlgorithm, issuer))
               && serial.Span.SequenceEqual(certificate.SerialNumberBytes.Span);
    }

    /// extnValue of the extension <paramref name="oid"/> in an `Extensions` wrapper reader, or null.
    private static byte[]? FindExtension(AsnReader wrapper, string oid)
    {
        var extensions = wrapper.ReadSequence();
        wrapper.ThrowIfNotEmpty();
        return ReadExtensions(extensions).Where(e => e.Oid == oid).Select(e => e.Value).FirstOrDefault();
    }

    /// `Extensions ::= SEQUENCE OF Extension { extnID, critical BOOLEAN DEFAULT FALSE (DER: 0xFF / 0x00), extnValue }`;
    /// throws when malformed.
    private static List<(string Oid, byte[] Value)> ReadExtensions(AsnReader extensions)
    {
        var output = new List<(string, byte[])>();
        while (extensions.HasData)
        {
            var ext = extensions.ReadSequence();
            var id = ext.ReadObjectIdentifier();
            if (ext.HasData && ext.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean)) ext.ReadBoolean();
            var value = ext.ReadOctetString();
            ext.ThrowIfNotEmpty();
            output.Add((id, value));
        }
        return output;
    }
}
