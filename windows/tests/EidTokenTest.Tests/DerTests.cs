using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

/// untrusted certificate bytes are accepted only as ONE strict DER certificate (the same rules as on macOS).
public sealed class DerTests
{
    /// Inputs that a lenient loader would take as a certificate, or that are not DER; null = no bytes at all.
    internal static IEnumerable<(string Name, byte[]? Bytes)> NonCertificates(TestPki pki, X509Certificate2 leaf)
    {
        var pem = "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(leaf.RawData, Base64FormattingOptions.InsertLineBreaks)
                  + "\n-----END CERTIFICATE-----\n";
        yield return ("PEM", Encoding.ASCII.GetBytes(pem));
        yield return ("PKCS#7", new X509Certificate2Collection(TestPki.PublicOnly(leaf)).Export(X509ContentType.Pkcs7)!);
        using var publicOnly = TestPki.PublicOnly(leaf);
        yield return ("PFX", publicOnly.Export(X509ContentType.Pfx, "test"));
        yield return ("trailing byte", [.. leaf.RawData, 0x00]);
        yield return ("two certificates", [.. leaf.RawData, .. pki.Issuing.RawData]);
        yield return ("empty", []);
        yield return ("null", null);
        yield return ("30 February", ImpossibleDate(leaf));
        yield return ("BOOLEAN 0x01", NonDerBoolean(pki.Issuing));
        // The KeyUsage extension's OID 2.5.29.15 with a non-minimal first sub-identifier (0x80 …).
        yield return ("non-minimal OID", TestPki.ReplaceFirst(leaf.RawData, [0x06, 0x03, 0x55, 0x1D, 0x0F], [0x06, 0x03, 0x80, 0x1D, 0x0F]));
    }

    /// The leaf's notBefore (UTCTime) rewritten to 30 February.
    internal static byte[] ImpossibleDate(X509Certificate2 leaf)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteUtcTime(new DateTimeOffset(leaf.NotBefore.ToUniversalTime(), TimeSpan.Zero));
        return TestPki.ReplaceFirst(leaf.RawData, w.Encode(), TestPki.Tlv(0x17, "260230120000Z"u8.ToArray()));
    }

    /// A critical BOOLEAN 0xFF rewritten to 0x01 (BER TRUE, not DER).
    internal static byte[] NonDerBoolean(X509Certificate2 ca) =>
        TestPki.ReplaceFirst(ca.RawData, [0x01, 0x01, 0xFF], [0x01, 0x01, 0x01]);

    [Fact]
    public void OneStrictDerCertificateIsAccepted()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.True(Der.IsStrictCertificate(leaf.RawData));
        Assert.True(Der.IsStrictCertificate(pki.Issuing.RawData));
        Assert.True(Der.TryLoadCertificate(leaf.RawData, out var loaded));
        using (loaded)
        {
            Assert.Equal(leaf.RawData, loaded.RawData);
        }
    }

    [Fact]
    public void PemPkcs7PfxTrailingBytesEmptyAndNonDerAreRefused()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        foreach (var (name, bytes) in NonCertificates(pki, leaf))
        {
            Assert.False(Der.IsStrictCertificate(bytes ?? Array.Empty<byte>()), name);
            Assert.False(Der.TryLoadCertificate(bytes, out _), name);
        }
    }

    /// The bundled trust certificates are strict DER themselves (they pass the same gate).
    [Fact]
    public void BundledCertificatesAreStrictDer()
    {
        var trust = TrustAnchors.Bundled();
        foreach (var c in trust.Roots.Concat(trust.Intermediates)) Assert.True(Der.IsStrictCertificate(c.RawData), c.Subject);
    }

    /// An OCSP response that embeds a responder "certificate" which is not strict DER is unreadable (✗).
    [Fact]
    public void NonDerResponderCertificateMakesTheOcspResponseUnreadable()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var responder = TestPki.CreateResponder(pki.Issuing, ocspSigning: true);
        var response = TestPki.OcspResponse(leaf, pki.Issuing, responder, 0, TestPki.Now.AddMinutes(-1), TestPki.Now.AddHours(1),
            embedSigner: true);
        Assert.Equal(CheckState.Pass, Ocsp.Evaluate(response, leaf, pki.Issuing, null, false, TestPki.Now).State);
        // The responder's critical KeyUsage BOOLEAN 0xFF → 0x01 inside the embedded certificate.
        var pattern = NonDerBooleanPattern(responder);
        var replaced = (byte[])pattern.Clone();
        replaced[^1] = 0x01;
        var tampered = TestPki.ReplaceFirst(response, pattern, replaced);
        Reason.Assert(Ocsp.Evaluate(tampered, leaf, pki.Issuing, null, false, TestPki.Now), CheckState.Fail, Reason.OcspMalformed);
    }

    /// The bytes of the responder certificate's first `01 01 FF` — located inside the embedded copy in the response.
    private static byte[] NonDerBooleanPattern(X509Certificate2 responder)
    {
        var raw = responder.RawData;
        var at = raw.AsSpan().IndexOf(new byte[] { 0x01, 0x01, 0xFF });
        Assert.True(at >= 8);
        return raw.AsSpan(at - 8, 11).ToArray();                       // 8 bytes of context make it unique in the response
    }
}
