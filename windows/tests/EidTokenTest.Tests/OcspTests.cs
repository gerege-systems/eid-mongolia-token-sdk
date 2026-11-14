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
        var result = Eval(response, leaf, pki.Issuing, [9, 9], required: true);
        Assert.Equal(CheckState.Fail, result.State);
        Assert.Contains("nonce", result.Reason, StringComparison.Ordinal);
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
        Assert.Equal(CheckState.Fail, Eval(other, leaf, pki.Issuing, [4, 5, 6], required: false).State);
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
        Assert.Equal(CheckState.Fail, Eval(bad, leaf, pki.Issuing).State);
    }

    [Fact]
    public void ResponderNotIssuedByTheCaFails()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create("OTHER");
        using var leaf = pki.CreateLeaf();
        using var foreign = TestPki.CreateResponder(other.Issuing, ocspSigning: true);
        var response = TestPki.OcspResponse(leaf, pki.Issuing, foreign, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true);
        var result = Eval(response, leaf, pki.Issuing);
        Assert.Equal(CheckState.Fail, result.State);
        Assert.Contains("олгоогүй", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ExpiredOrNotYetValidResponderFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var expired = TestPki.CreateResponder(pki.Issuing, ocspSigning: true, from: Now.AddDays(-30), to: Now.AddDays(-1));
        using var notYet = TestPki.CreateResponder(pki.Issuing, ocspSigning: true, from: Now.AddDays(1), to: Now.AddDays(30));
        var e = Eval(TestPki.OcspResponse(leaf, pki.Issuing, expired, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true),
            leaf, pki.Issuing);
        Assert.Equal(CheckState.Fail, e.State);
        Assert.Contains("хүчинтэй хугацаанаас гадуур", e.Reason, StringComparison.Ordinal);
        Assert.Equal(CheckState.Fail,
            Eval(TestPki.OcspResponse(leaf, pki.Issuing, notYet, 0, Now.AddMinutes(-1), Now.AddHours(1), embedSigner: true),
                leaf, pki.Issuing).State);
    }

    [Fact]
    public void UnknownSignerFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var stranger = TestPki.CreateResponder(pki.Issuing, ocspSigning: true);
        // Signed by a responder whose certificate is not in the response.
        var response = TestPki.OcspResponse(leaf, pki.Issuing, stranger, 0, Now.AddMinutes(-1), Now.AddHours(1));
        Assert.Equal(CheckState.Fail, Eval(response, leaf, pki.Issuing).State);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void RevokedOrUnknownStatusFails(int status)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, status, Now.AddMinutes(-1), Now.AddHours(1));
        Assert.Equal(CheckState.Fail, Eval(response, leaf, pki.Issuing).State);
    }

    /// Order: revoked is reported before freshness, freshness before unknown (the same on macOS).
    [Fact]
    public void StatusAndFreshnessOrder()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var staleRevoked = Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 1, Now.AddDays(-3), Now.AddDays(-2)),
            leaf, pki.Issuing);
        Assert.StartsWith("Гэрчилгээ цуцлагдсан", staleRevoked.Reason, StringComparison.Ordinal);
        var staleUnknown = Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 2, Now.AddDays(-3), Now.AddDays(-2)),
            leaf, pki.Issuing);
        Assert.StartsWith("OCSP хариу хуучирсан", staleUnknown.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void StaleOrFutureResponsesFail()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.Equal(CheckState.Fail, Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddDays(-2), Now.AddDays(-1)),
            leaf, pki.Issuing).State);
        Assert.Equal(CheckState.Fail, Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddHours(1), Now.AddHours(2)),
            leaf, pki.Issuing).State);
        Assert.Equal(CheckState.Fail, Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddHours(-2), null),
            leaf, pki.Issuing).State);
        Assert.Equal(CheckState.Pass, Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-10), null),
            leaf, pki.Issuing).State);
    }

    [Fact]
    public void FiveMinutesClockSkewOnBothEndsInclusive()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        CheckState At(DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate) =>
            Eval(TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, thisUpdate, nextUpdate), leaf, pki.Issuing).State;
        Assert.Equal(CheckState.Pass, At(Now.AddMinutes(2), Now.AddHours(1)));
        Assert.Equal(CheckState.Pass, At(Now.AddMinutes(5), Now.AddHours(1)));
        Assert.Equal(CheckState.Fail, At(Now.AddMinutes(5).AddSeconds(1), Now.AddHours(1)));
        Assert.Equal(CheckState.Pass, At(Now.AddHours(-1), Now.AddMinutes(-2)));
        Assert.Equal(CheckState.Pass, At(Now.AddHours(-1), Now.AddMinutes(-5)));
        Assert.Equal(CheckState.Fail, At(Now.AddHours(-1), Now.AddMinutes(-5).AddSeconds(-1)));
    }

    [Fact]
    public void NonceMismatchFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var response = TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1),
            Ocsp.NonceValue([1, 2, 3]));
        Assert.Equal(CheckState.Fail, Eval(response, leaf, pki.Issuing, [4, 5, 6], required: true).State);
    }

    [Fact]
    public void AnswerForAnotherCertificateFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var other = pki.CreateLeaf();
        var response = TestPki.OcspResponse(other, pki.Issuing, pki.Issuing, 0, Now.AddMinutes(-1), Now.AddHours(1));
        Assert.Equal(CheckState.Fail, Eval(response, leaf, pki.Issuing).State);
    }

    [Fact]
    public void ResponderErrorIsUnknownButGarbageFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        byte[] internalError = [0x30, 0x03, 0x0A, 0x01, 0x02];
        Assert.Equal(CheckState.Unknown, Eval(internalError, leaf, pki.Issuing).State);
        Assert.Equal(CheckState.Fail, Eval([0x01, 0x02, 0x03], leaf, pki.Issuing).State);
        Assert.Equal(CheckState.Fail, Eval([0x30, 0x00], leaf, pki.Issuing).State);
        Assert.Equal(CheckState.Fail, Eval([0x30, 0x81, 0x03, 0x0A, 0x01, 0x00], leaf, pki.Issuing).State);   // non-minimal length
    }
}
