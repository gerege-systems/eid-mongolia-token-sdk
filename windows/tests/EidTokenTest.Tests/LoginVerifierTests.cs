using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

public sealed class LoginVerifierTests
{
    private static readonly DateTimeOffset Now = TestPki.Now;
    private static readonly byte[] Challenge = Enumerable.Repeat((byte)1, 32).ToArray();

    /// Responders that answer like the real ones: leaf by the issuing CA with the request's nonce echoed, issuing CA by
    /// its own issuer, pre-signed (no nonce).
    private static FakeTransport Online(TestPki pki, X509Certificate2 leaf, int status = 0, IEnumerable<X509Certificate2>? revoked = null)
    {
        var transport = new FakeTransport();
        transport.Ocsp[TestPki.OcspUrl] = request => TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, status,
            Now.AddMinutes(-1), Now.AddHours(1), TestPki.NonceExtValue(request));
        transport.Crls[TestPki.CrlUrl] = TestPki.Crl(pki.Issuing, revoked ?? Array.Empty<X509Certificate2>(), Now.AddHours(-1), Now.AddDays(1));
        transport.Ocsp[TestPki.CaOcspUrl] = _ => TestPki.OcspResponse(pki.Issuing, pki.Intermediate, pki.Intermediate, 0,
            Now.AddMinutes(-1), Now.AddHours(1));
        transport.Crls[TestPki.CaCrlUrl] = TestPki.Crl(pki.Intermediate, Array.Empty<X509Certificate2>(), Now.AddHours(-1), Now.AddDays(1));
        return transport;
    }

    private static Task<LoginReport> Run(TestPki pki, FakeTransport transport, X509Certificate2 certificate,
                                         X509Certificate2? signer = null, TrustAnchors? trust = null) =>
        new LoginVerifier(trust ?? pki.Trust, transport, () => Now)
            .RunAsync(TestPki.Origin, Challenge, certificate.RawData, TestPki.Signer(signer ?? certificate));

    private static CheckResult Row(LoginReport report, string name) => report.Checks.Single(c => c.Name == name);

    [Fact]
    public async Task AllChecksPassLogsIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        var report = await Run(pki, transport, leaf);

        Assert.All(report.Checks, c => Assert.Equal(CheckState.Pass, c.State));
        Assert.Equal(CheckNames.All, report.Checks.Select(c => c.Name));
        Assert.True(report.LoggedIn);
        Assert.Equal("Нэвтэрлээ: TEST ONLY Citizen", report.Summary);
        Assert.Contains("олгогч CA цуцлагдаагүй", Row(report, CheckNames.Chain).Reason, StringComparison.Ordinal);
        Assert.Equal(new[] { TestPki.CaOcspUrl, TestPki.CaCrlUrl, TestPki.OcspUrl, TestPki.CrlUrl },
                     transport.Requested.Select(u => u.AbsoluteUri));
    }

    [Fact]
    public async Task RelyingPartyVerifyAcceptsTheBoundSignature()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now)
            .VerifyAsync(TestPki.Origin, Challenge, TestPki.Sign(leaf, TestPki.Origin, Challenge), leaf.RawData);
        Assert.True(report.LoggedIn, report.Summary);
    }

    [Fact]
    public void DigestIsTheBoundConstruction()
    {
        var digest = LoginChallenge.DigestToSign("rp.example", Challenge);
        byte[] message = [.. "eID-TOKEN-LOGIN-V1"u8.ToArray(), .. "rp.example"u8.ToArray(), .. Challenge];
        Assert.Equal(SHA256.HashData(message), digest);
        Assert.NotEqual(SHA256.HashData(Challenge), digest);
        Assert.Equal("test.example", LoginChallenge.DefaultOrigin);
        Assert.Equal(32, LoginChallenge.NewChallenge().Length);
    }

    /// The signature is otherwise valid (over the bound digest of that very challenge): only the length fails it.
    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public async Task ChallengeNotExactly32BytesIsRejectedBeforeSigning(int length)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var challenge = Enumerable.Repeat((byte)9, length).ToArray();
        var signed = false;
        var report = await new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now).RunAsync(TestPki.Origin, challenge,
            leaf.RawData, (_, _) => { signed = true; return Task.FromResult(new byte[64]); });
        Assert.False(signed);
        Assert.False(report.LoggedIn);
        Assert.Throws<ArgumentException>(() => LoginChallenge.DigestToSign(TestPki.Origin, challenge));

        var validSignature = TestPki.Sign(leaf, TestPki.Origin, challenge);
        var verified = await new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now)
            .VerifyAsync(TestPki.Origin, challenge, validSignature, leaf.RawData);
        Assert.Equal(CheckState.Fail, Row(verified, CheckNames.Signature).State);
        Assert.StartsWith("Challenge " + length, Row(verified, CheckNames.Signature).Reason, StringComparison.Ordinal);
        Assert.False(verified.LoggedIn);
    }

    [Theory]
    [InlineData("")]
    [InlineData("https://rp.test.invalid")]
    [InlineData("RP.test.invalid")]
    [InlineData("rp.test.invalid:443")]
    [InlineData("rp.test.invalid/login")]
    [InlineData("rp.test.invalid.")]
    public async Task InvalidOriginStopsBeforeSigningAndVerifying(string origin)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        var signed = false;
        var run = await new LoginVerifier(pki.Trust, transport, () => Now).RunAsync(origin, Challenge, leaf.RawData,
            (_, _) => { signed = true; return Task.FromResult(new byte[64]); });
        Assert.False(signed);
        Assert.Equal(Origin.InvalidReason, run.StopReason);
        var verify = await new LoginVerifier(pki.Trust, transport, () => Now)
            .VerifyAsync(origin, Challenge, TestPki.Sign(leaf, origin, Challenge), leaf.RawData);
        Assert.False(verify.LoggedIn);
        Assert.Empty(transport.Requested);
    }

    [Fact]
    public async Task BareSha256OfTheChallengeFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now)
            .VerifyAsync(TestPki.Origin, Challenge, TestPki.SignBare(leaf, Challenge), leaf.RawData);
        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Signature).State);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task SignatureForAnotherOriginFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var verifier = new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now);
        var otherOrigin = await verifier.VerifyAsync(TestPki.Origin, Challenge,
            TestPki.Sign(leaf, "other.test.invalid", Challenge), leaf.RawData);
        Assert.Equal(CheckState.Fail, Row(otherOrigin, CheckNames.Signature).State);
        Assert.False(otherOrigin.LoggedIn);
    }

    [Fact]
    public void ZeroOrOutOfRangeScalarsAndNonRawSignaturesFail()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var good = TestPki.Sign(leaf, TestPki.Origin, Challenge);
        Assert.Equal(CheckState.Pass, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, good).State);

        var zeroR = (byte[])good.Clone();
        Array.Clear(zeroR, 0, 32);
        var zeroS = (byte[])good.Clone();
        Array.Clear(zeroS, 32, 32);
        byte[] rIsN = [.. LoginVerifier.P256Order, .. good.AsSpan(32).ToArray()];
        Assert.Equal(CheckState.Fail, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, zeroR).State);
        Assert.Equal(CheckState.Fail, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, zeroS).State);
        Assert.Equal(CheckState.Fail, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, rIsN).State);

        using var key = leaf.GetECDsaPrivateKey()!;
        var der = key.SignHash(LoginChallenge.DigestToSign(TestPki.Origin, Challenge), DSASignatureFormat.Rfc3279DerSequence);
        Assert.Equal(CheckState.Fail, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, der).State);
        Assert.Equal(CheckState.Fail, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, good[..63]).State);
        var tampered = (byte[])good.Clone();
        tampered[10] ^= 0x01;
        Assert.Equal(CheckState.Fail, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, tampered).State);

        Assert.False(LoginVerifier.IsValidScalar(new byte[32]));
        Assert.False(LoginVerifier.IsValidScalar(LoginVerifier.P256Order));
        Assert.True(LoginVerifier.IsValidScalar([.. new byte[31], 1]));
    }

    [Fact]
    public async Task OfflineMeansNotLoggedIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await Run(pki, new FakeTransport { Offline = true }, leaf);

        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Ocsp).State);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Crl).State);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Chain).State);      // issuing CA revocation unreachable
        Assert.Equal("шалгаж чадсангүй", Row(report, CheckNames.Ocsp).Mark);
        Assert.False(report.LoggedIn);
        Assert.StartsWith("Нэвтэрч чадсангүй: ", report.Summary, StringComparison.Ordinal);
    }

    /// Every network / IO exception from the transport — including an IOException in the middle of the body, a
    /// timeout, or anything unexpected — becomes «шалгаж чадсангүй»; nothing escapes the verify call.
    [Theory]
    [InlineData("io")]
    [InlineData("timeout")]
    [InlineData("socket")]
    [InlineData("other")]
    public async Task EveryTransportExceptionIsUnknown(string kind)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        transport.Ocsp.Remove(TestPki.OcspUrl);
        transport.Crls.Remove(TestPki.CrlUrl);
        transport.Failure = () => kind switch
        {
            "io" => new IOException("The response ended prematurely."),
            "timeout" => new TaskCanceledException("timeout"),
            "socket" => new System.Net.Sockets.SocketException(10054),
            _ => new InvalidOperationException("unexpected"),
        };
        var report = await Run(pki, transport, leaf);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Ocsp).State);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Crl).State);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task MissingNonceOnTheAuthOcspIsNotLoggedIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        transport.Ocsp[TestPki.OcspUrl] = _ => TestPki.OcspResponse(leaf, pki.Issuing, pki.Issuing, 0,
            Now.AddMinutes(-1), Now.AddHours(1));
        var report = await Run(pki, transport, leaf);
        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Ocsp).State);
        Assert.Contains("nonce", Row(report, CheckNames.Ocsp).Reason, StringComparison.Ordinal);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task RevokedCertificateIsNotLoggedIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await Run(pki, Online(pki, leaf, status: 1, revoked: [leaf]), leaf);

        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Ocsp).State);
        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Crl).State);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task RevokedIssuingCaIsNotLoggedIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();

        var byOcsp = Online(pki, leaf);
        byOcsp.Ocsp[TestPki.CaOcspUrl] = _ => TestPki.OcspResponse(pki.Issuing, pki.Intermediate, pki.Intermediate, 1,
            Now.AddMinutes(-1), Now.AddHours(1));
        var ocspReport = await Run(pki, byOcsp, leaf);
        Assert.Equal(CheckState.Fail, Row(ocspReport, CheckNames.Chain).State);
        Assert.False(ocspReport.LoggedIn);

        var byCrl = Online(pki, leaf);
        byCrl.Crls[TestPki.CaCrlUrl] = TestPki.Crl(pki.Intermediate, [pki.Issuing], Now.AddHours(-1), Now.AddDays(1));
        var crlReport = await Run(pki, byCrl, leaf);
        Assert.Equal(CheckState.Fail, Row(crlReport, CheckNames.Chain).State);
        Assert.False(crlReport.LoggedIn);

        var unreachable = Online(pki, leaf);
        unreachable.Crls.Remove(TestPki.CaCrlUrl);
        var offline = await Run(pki, unreachable, leaf);
        Assert.Equal(CheckState.Unknown, Row(offline, CheckNames.Chain).State);
        Assert.False(offline.LoggedIn);
    }

    /// Neither AIA nor CDP on the issuing CA: its revocation cannot be checked — not "not applicable".
    [Fact]
    public async Task IssuingCaWithoutAiaAndCdpCannotBeChecked()
    {
        using var pki = TestPki.Create(caOcsp: false, caCrl: false);
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        var report = await Run(pki, transport, leaf);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Chain).State);
        Assert.False(report.LoggedIn);
        Assert.Equal(new[] { TestPki.OcspUrl, TestPki.CrlUrl }, transport.Requested.Select(u => u.AbsoluteUri));
    }

    /// Only one of them: that one decides.
    [Fact]
    public async Task IssuingCaWithOnlyCdp()
    {
        using var pki = TestPki.Create(caOcsp: false);
        using var leaf = pki.CreateLeaf();
        var report = await Run(pki, Online(pki, leaf), leaf);
        Assert.True(report.LoggedIn, report.Summary);
        Assert.Contains("OCSP: AIA алга", Row(report, CheckNames.Chain).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SignatureByAnotherKeyFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var other = pki.CreateLeaf();
        var report = await Run(pki, Online(pki, leaf), leaf, signer: other);

        Assert.Equal(CheckState.Fail, report.Checks[0].State);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task SignerErrorIsReportedAndNotLoggedIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now).RunAsync(TestPki.Origin, Challenge,
            leaf.RawData, (_, _) => throw new TokenLoginException(TokenLoginError.PinIncorrect));

        Assert.Equal(CheckState.Unknown, report.Checks[0].State);
        Assert.Equal("PIN буруу", report.Checks[0].Reason);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task CertificateWithoutRevocationUrlsCannotLogIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(withUrls: false);
        var transport = Online(pki, leaf);
        var report = await Run(pki, transport, leaf);

        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Ocsp).State);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Crl).State);
        Assert.DoesNotContain(transport.Requested, u => u.AbsoluteUri is TestPki.OcspUrl or TestPki.CrlUrl);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task CertificateFromAnotherPkiFailsTheChain()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create("OTHER");
        using var leaf = other.CreateLeaf();
        var report = await Run(pki, Online(other, leaf), leaf);

        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Chain).State);
        // Not issued by the pinned issuing CA: OCSP / CRL cannot be judged against it.
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Ocsp).State);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public void ChainMustEndAtTheBundledRootThroughTheIssuingCa()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var verifier = new LoginVerifier(pki.Trust, new FakeTransport(), () => Now);

        var cas = new List<X509Certificate2>();
        var ok = verifier.Chain(leaf, Now, cas);
        Assert.Equal(CheckState.Pass, ok.State);
        Assert.Contains("TEST ONLY Root CA", ok.Reason, StringComparison.Ordinal);
        Assert.Equal(4, cas.Count);
    }

    [Fact]
    public void EndEntityIssuedDirectlyByANonIssuingCaFails()
    {
        using var pki = TestPki.Create();
        using var fromNational = pki.CreateLeaf(issuer: pki.National);           // ≙ 02
        using var fromIntermediate = pki.CreateLeaf(issuer: pki.Intermediate);   // ≙ 03
        var verifier = new LoginVerifier(pki.Trust, new FakeTransport(), () => Now);
        Assert.Equal(CheckState.Fail, verifier.Chain(fromNational, Now, []).State);
        Assert.Equal(CheckState.Fail, verifier.Chain(fromIntermediate, Now, []).State);
    }

    /// ≙05 issues relying-party mTLS certificates with clientAuth: even with digitalSignature + clientAuth + PNOMN- and
    /// 05 in the bundled set, only the pinned 04 may issue an AUTH certificate.
    [Fact]
    public async Task CertificateFromTheOrganizationCaIsRejected()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(issuer: pki.Organization);
        var report = await Run(pki, Online(pki, leaf), leaf, trust: pki.TrustWith(withOrganization: true));
        Assert.Equal(CheckState.Pass, Row(report, CheckNames.Signature).State);
        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Chain).State);
        Assert.Contains("(04)", Row(report, CheckNames.Chain).Reason, StringComparison.Ordinal);
        Assert.Equal(CheckState.Unknown, Row(report, CheckNames.Ocsp).State);
        Assert.False(report.LoggedIn);
    }

    /// The SIGN fixture carries clientAuth and PNOMN-: nonRepudiation alone disqualifies it.
    [Fact]
    public async Task SignAndOcspResponderCertificatesAreNotAuth()
    {
        using var pki = TestPki.Create();
        using var sign = pki.CreateLeaf(auth: false);
        using var responder = TestPki.CreateResponder(pki.Issuing, ocspSigning: true);
        Assert.Contains("1.3.6.1.5.5.7.3.2", sign.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single()
            .EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value));

        var signReport = await Run(pki, Online(pki, sign), sign);
        Assert.Equal(CheckState.Fail, Row(signReport, CheckNames.Chain).State);
        Assert.Contains("KeyUsage", Row(signReport, CheckNames.Chain).Reason, StringComparison.Ordinal);
        Assert.False(signReport.LoggedIn);

        var responderReport = await Run(pki, Online(pki, responder), responder);
        Assert.Equal(CheckState.Pass, Row(responderReport, CheckNames.Signature).State);
        Assert.Equal(CheckState.Fail, Row(responderReport, CheckNames.Chain).State);
        Assert.False(responderReport.LoggedIn);
    }

    [Fact]
    public void AuthProfileRule()
    {
        using var pki = TestPki.Create();
        using var good = pki.CreateLeaf();
        using var noKeyUsage = pki.CreateLeaf(keyUsage: false);
        using var noEku = pki.CreateLeaf(eku: false);
        using var extraBit = pki.CreateLeaf(usage: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        using var noClientAuth = pki.CreateLeaf(ekus: ["1.3.6.1.5.5.7.3.4"]);
        using var otherPrefix = pki.CreateLeaf(serialNumber: "NTRMN-TEST0001");
        using var noSerial = pki.CreateLeaf(serialNumber: null);
        var verifier = new LoginVerifier(pki.Trust, new FakeTransport(), () => Now);

        Assert.Null(LoginVerifier.AuthProfileProblem(good));
        foreach (var bad in new[] { noKeyUsage, noEku, extraBit, noClientAuth, otherPrefix, noSerial })
        {
            Assert.NotNull(LoginVerifier.AuthProfileProblem(bad));
            Assert.Equal(CheckState.Fail, verifier.Chain(bad, Now, []).State);
        }
        Assert.Contains("serialNumber", LoginVerifier.AuthProfileProblem(noSerial), StringComparison.Ordinal);
    }

    [Fact]
    public void ChainWithoutTrustAnchorsOrIssuingCaCannotBeChecked()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.Equal(CheckState.Unknown,
            new LoginVerifier(new TrustAnchors([], [], null), new FakeTransport(), () => Now).Chain(leaf, Now, []).State);
        var noIssuing = new TrustAnchors([TestPki.PublicOnly(pki.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate)], TestPki.PublicOnly(pki.Issuing));
        Assert.Null(noIssuing.IssuingCa);
        Assert.Equal(CheckState.Unknown, new LoginVerifier(noIssuing, new FakeTransport(), () => Now).Chain(leaf, Now, []).State);
    }

    [Fact]
    public async Task ExpiredCertificateFailsValidityButStillBuildsTheChain()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(from: Now.AddDays(-300), to: Now.AddDays(-1));
        var report = await Run(pki, Online(pki, leaf), leaf);

        Assert.Equal(CheckState.Pass, Row(report, CheckNames.Chain).State);
        Assert.Equal(CheckState.Fail, Row(report, CheckNames.Validity).State);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public void NotYetValidCertificateFailsValidity()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(from: Now.AddDays(1), to: Now.AddDays(30));
        Assert.Equal(CheckState.Fail, LoginVerifier.Validity(leaf, [], Now).State);
    }

    /// notAfter is inclusive: valid AT notAfter, expired one second later.
    [Fact]
    public void NotAfterBoundaryIsInclusive()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(from: Now.AddDays(-1), to: Now.AddMinutes(1));
        var notAfter = new DateTimeOffset(leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        Assert.Equal(CheckState.Pass, LoginVerifier.Validity(leaf, [], notAfter).State);
        Assert.Equal(CheckState.Fail, LoginVerifier.Validity(leaf, [], notAfter.AddSeconds(1)).State);
    }

    [Fact]
    public async Task UnreadableCertificateStopsBeforeSigning()
    {
        var signed = false;
        var report = await new LoginVerifier(new TrustAnchors([], [], null), new FakeTransport(), () => Now)
            .RunAsync(TestPki.Origin, Challenge, [0x30, 0x00], (_, _) => { signed = true; return Task.FromResult(Array.Empty<byte>()); });
        Assert.False(signed);
        Assert.False(report.LoggedIn);
        Assert.StartsWith("Нэвтэрч чадсангүй: ", report.Summary, StringComparison.Ordinal);
    }
}
