using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

public sealed class OcspTests
{
    private static readonly DateTimeOffset Now = TestPki.Now;

    private static CheckResult Eval(byte[] response, X509Certificate2 leaf, X509Certificate2 issuer, byte[]? nonce = null,
                                    bool required = false) =>
        Ocsp.Evaluate(response, leaf, issuer, nonce, required, Now);

    /// One encoded CertID (SHA-1) for <paramref name="subject"/> issued by <paramref name="issuer"/>.
    private static byte[] CertId(X509Certificate2 subject, X509Certificate2 issuer)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        Ocsp.WriteCertId(w, Der.Sha1, subject, issuer);
        return w.Encode();
    }

    private static byte[] Sequence(params byte[][] parts)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var part in parts) w.WriteEncodedValue(part);
        }
        return w.Encode();
    }

    private static byte[] GeneralizedTime(DateTimeOffset at)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteGeneralizedTime(at, omitFractionalSeconds: true);
        return w.Encode();
    }

    [Fact]
    public void RequestCarriesTheCertIdAndANonce()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var request = Ocsp.CreateRequest(leaf, pki.Issuing, out var nonce);

        var tbs = new AsnReader(request, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        var certId = tbs.ReadSequence().ReadSequence().ReadSequence();
        Assert.True(Ocsp.CertIdMatches(certId, leaf, pki.Issuing));
        Assert.Equal(Ocsp.NonceValue(nonce), TestPki.NonceExtValue(request));
        Assert.Equal(32, nonce.Length);
    }

    [Fact]
    public void GoodResponseSignedByTheIssuerPasses()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var nonce = new byte[] { 1, 2, 3 };
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            Ocsp.NonceValue(nonce));
        Assert.Equal(CheckState.Pass, Eval(response, leaf, pki.Issuing, nonce, required: true).State);
        var raw = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1), nonce);
        Assert.Equal(CheckState.Pass, Eval(raw, leaf, pki.Issuing, nonce, required: true).State);      // echoed raw
    }

    /// AUTH certificate: the echoed nonce is REQUIRED.
    [Fact]
    public void MissingNonceFailsWhenRequired()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            certIdHash: Der.Sha256);
        Reason.Assert(Eval(response, leaf, pki.Issuing, [9, 9], required: true), CheckState.Fail,
            "OCSP хариунд nonce алга (AUTH гэрчилгээнд заавал)");
    }

    /// Issuing-CA check (pre-signed answers): the nonce is optional, but an echoed one must still match.
    [Fact]
    public void NonceOptionalForTheIssuingCa()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var none = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1));
        Assert.Equal(CheckState.Pass, Eval(none, leaf, pki.Issuing, [9, 9], required: false).State);
        var other = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            Ocsp.NonceValue([1, 2, 3]));
        Reason.Assert(Eval(other, leaf, pki.Issuing, [4, 5, 6], required: false), CheckState.Fail,
            "OCSP хариуны nonce манай хүсэлтийнхтэй таарахгүй");
    }

    [Fact]
    public void DelegatedResponderNeedsOcspSigning()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var responder = TestPki.CreateResponder(pki.Issuing, ocspSigning: true);
        using var notResponder = TestPki.CreateResponder(pki.Issuing, ocspSigning: false);

        var ok = TestPki.OcspResponse(leaf, pki.Issuing, responder, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true);
        Assert.Equal(CheckState.Pass, Eval(ok, leaf, pki.Issuing).State);

        var bad = TestPki.OcspResponse(leaf, pki.Issuing, notResponder, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true);
        Reason.Assert(Eval(bad, leaf, pki.Issuing), CheckState.Fail, "OCSP responder-ийн гэрчилгээнд id-kp-OCSPSigning алга");
    }

    [Fact]
    public void ResponderNotIssuedByTheCaFails()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create("OTHER");
        using var leaf = pki.CreateLeaf();
        using var foreign = TestPki.CreateResponder(other.Issuing, ocspSigning: true);
        var response = TestPki.OcspResponse(leaf, pki.Issuing, foreign, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true);
        Reason.Assert(Eval(response, leaf, pki.Issuing), CheckState.Fail,
            "OCSP responder-ийн гэрчилгээг энэ гэрчилгээний олгогч олгоогүй");
    }

    [Fact]
    public void ExpiredOrNotYetValidResponderFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var expired = TestPki.CreateResponder(pki.Issuing, ocspSigning: true, from: Now.AddDays(-30), to: Now.AddDays(-1));
        using var notYet = TestPki.CreateResponder(pki.Issuing, ocspSigning: true, from: Now.AddDays(1), to: Now.AddDays(30));
        const string outside = "OCSP responder-ийн гэрчилгээ хүчинтэй хугацаанаас гадуур";
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, expired, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true),
            leaf, pki.Issuing), CheckState.Fail, outside);
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, notYet, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true),
            leaf, pki.Issuing), CheckState.Fail, outside);
    }

    [Fact]
    public void UnknownSignerFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var stranger = TestPki.CreateResponder(pki.Issuing, ocspSigning: true);
        // Signed by a responder whose certificate is not in the response.
        var response = TestPki.OcspResponse(leaf, pki.Issuing, stranger, 0, Now.AddMinutes(-1), Now.AddHours(1));
        Reason.Assert(Eval(response, leaf, pki.Issuing), CheckState.Fail,
            "OCSP хариуг хэн зурсан нь тодорхойгүй (responderID таарахгүй)");
    }

    [Theory]
    [InlineData(1, "Гэрчилгээ цуцлагдсан (")]
    [InlineData(2, "OCSP: unknown — responder энэ гэрчилгээг танихгүй")]
    public void RevokedOrUnknownStatusFails(int status, string reason)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, status, Now.AddMinutes(-1), Now.AddHours(1));
        Reason.Assert(Eval(response, leaf, pki.Issuing), CheckState.Fail, reason);
    }

    /// Order: revoked is reported before freshness, freshness before unknown (the same on macOS).
    [Fact]
    public void StatusAndFreshnessOrder()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var staleRevoked = Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 1, Now.AddDays(-3), Now.AddDays(-2)),
            leaf, pki.Issuing);
        Reason.Assert(staleRevoked, CheckState.Fail, "Гэрчилгээ цуцлагдсан");
        var staleUnknown = Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 2, Now.AddDays(-3), Now.AddDays(-2)),
            leaf, pki.Issuing);
        Reason.Assert(staleUnknown, CheckState.Fail, "OCSP хариу хуучирсан");
    }

    [Fact]
    public void StaleOrFutureResponsesFail()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddDays(-2), Now.AddDays(-1)),
            leaf, pki.Issuing), CheckState.Fail, "OCSP хариу хуучирсан");
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddHours(1), Now.AddHours(2)),
            leaf, pki.Issuing), CheckState.Fail, "OCSP хариу ирээдүйн огноотой");
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddHours(-2), null),
            leaf, pki.Issuing), CheckState.Fail, "OCSP хариу хуучирсан");
        Assert.Equal(CheckState.Pass, Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-10), null),
            leaf, pki.Issuing).State);
    }

    [Fact]
    public void FiveMinutesClockSkewOnBothEndsInclusive()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        CheckResult At(DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate) =>
            Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, thisUpdate, nextUpdate), leaf, pki.Issuing);
        Assert.Equal(CheckState.Pass, At(Now.AddMinutes(2), Now.AddHours(1)).State);
        Assert.Equal(CheckState.Pass, At(Now.AddMinutes(5), Now.AddHours(1)).State);
        Reason.Assert(At(Now.AddMinutes(5).AddSeconds(1), Now.AddHours(1)), CheckState.Fail, "OCSP хариу ирээдүйн огноотой");
        Assert.Equal(CheckState.Pass, At(Now.AddHours(-1), Now.AddMinutes(-2)).State);
        Assert.Equal(CheckState.Pass, At(Now.AddHours(-1), Now.AddMinutes(-5)).State);
        Reason.Assert(At(Now.AddHours(-1), Now.AddMinutes(-5).AddSeconds(-1)), CheckState.Fail, "OCSP хариу хуучирсан");
    }

    [Fact]
    public void NonceMismatchFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            Ocsp.NonceValue([1, 2, 3]));
        Reason.Assert(Eval(response, leaf, pki.Issuing, [4, 5, 6], required: true), CheckState.Fail,
            "OCSP хариуны nonce манай хүсэлтийнхтэй таарахгүй");
    }

    [Fact]
    public void AnswerForAnotherCertificateFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var other = pki.CreateLeaf();
        var response = TestPki.OcspResponse(other, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1));
        Reason.Assert(Eval(response, leaf, pki.Issuing), CheckState.Fail, Reason.CertIdMismatch);
    }

    /// B: entries about other certificates — even malformed ones — are skipped; the matching entry decides.
    [Fact]
    public void OtherEntriesAreSkippedEvenWhenMalformed()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var other = pki.CreateLeaf();
        byte[] good = [0x80, 0x00];
        var otherEntry = Sequence(CertId(other, pki.Issuing), good, GeneralizedTime(Now.AddMinutes(-1)));
        var garbage = Sequence(new byte[] { 0x02, 0x01, 0x05 });                                          // no CertID at all
        var brokenCertId = Sequence(Sequence(Sequence([0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A], [0x05, 0x00]),
                                             [0x02, 0x01, 0x01]), good);
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            otherSingles: [garbage, brokenCertId, otherEntry]);
        var result = Eval(response, leaf, pki.Issuing);
        Assert.Equal(CheckState.Pass, result.State);
    }

    /// B: a malformed entry for THIS certificate is ✗.
    [Fact]
    public void MalformedMatchingEntryFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            singleSuffix: [0x02, 0x01, 0x01]), leaf, pki.Issuing), CheckState.Fail, Reason.OcspMalformed);    // trailing element
        var goodWithContent = Sequence(CertId(leaf, pki.Issuing), [0x80, 0x01, 0x00], GeneralizedTime(Now.AddMinutes(-1)));
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            otherSingles: [goodWithContent]), leaf, pki.Issuing), CheckState.Fail, Reason.OcspMalformed);
        var revokedNoTime = Sequence(CertId(leaf, pki.Issuing), [0xA1, 0x00], GeneralizedTime(Now.AddMinutes(-1)));
        Reason.Assert(Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            otherSingles: [revokedNoTime]), leaf, pki.Issuing), CheckState.Fail, Reason.OcspMalformed);
    }

    [Fact]
    public void ResponderErrorIsUnknownButGarbageFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        byte[] internalError = [0x30, 0x03, 0x0A, 0x01, 0x02];
        Reason.Assert(Eval(internalError, leaf, pki.Issuing), CheckState.Unknown,
            "OCSP responder амжилтгүй хариу өгсөн (responseStatus 2)");
        Reason.Assert(Eval([0x01, 0x02, 0x03], leaf, pki.Issuing), CheckState.Fail, Reason.OcspMalformed);
        Reason.Assert(Eval([0x30, 0x00], leaf, pki.Issuing), CheckState.Fail, Reason.OcspMalformed);
        Reason.Assert(Eval([0x30, 0x81, 0x03, 0x0A, 0x01, 0x00], leaf, pki.Issuing), CheckState.Fail,
            Reason.OcspMalformed);                                                                     // non-minimal length
    }
}
