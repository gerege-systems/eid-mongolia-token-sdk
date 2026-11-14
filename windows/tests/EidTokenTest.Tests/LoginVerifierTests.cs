using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

/// Reason texts shared by the negative tests (the same texts on macOS).
internal static class Reason
{
    public const string NotTrusted = "Итгэмжлэгдсэн үндэс хүртэл гинж баталгаажсангүй";
    public const string Not04 = "Гэрчилгээг eID Mongolia Issuing CA (04) шууд олгоогүй";
    public const string KeyUsageMissing = "AUTH профайл: KeyUsage өргөтгөл алга";
    public const string KeyUsageOnly = "AUTH профайл: KeyUsage нь зөвхөн digitalSignature байх ёстой";
    public const string EkuMissing = "AUTH профайл: ExtendedKeyUsage өргөтгөл алга";
    public const string NoClientAuth = "AUTH профайл: ExtendedKeyUsage-д clientAuth алга";
    public const string SerialNumber = "AUTH профайл: subject serialNumber нь PNOMN- угтвартай ганц утга байх ёстой";
    public const string WrongKey = "Гарын үсэг AUTH гэрчилгээний түлхүүртэй таарахгүй";
    public const string Unreadable = "AUTH гэрчилгээг уншиж чадсангүй";
    public const string NoIssuingCa = "Олгогч CA (04) апп-д алга";
    public const string OcspMalformed = "OCSP хариу задрахгүй байна";
    public const string CrlMalformed = "CRL задрахгүй байна";
    public const string CertIdMismatch = "OCSP хариунд энэ гэрчилгээний төлөв алга (CertID таарахгүй)";

    /// A negative result: its state AND its reason (prefix — dates and names follow some reasons).
    public static void Assert(CheckResult result, CheckState state, string reasonPrefix)
    {
        Xunit.Assert.Equal(state, result.State);
        Xunit.Assert.StartsWith(reasonPrefix, result.Reason, StringComparison.Ordinal);
    }
}

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

    /// The rejected-input report: signature ✗ with <paramref name="reason"/>, every other row «шалгаж чадсангүй».
    private static void AssertRejected(LoginReport report, string reason)
    {
        Assert.Equal(CheckNames.All, report.Checks.Select(c => c.Name));
        Reason.Assert(report.Checks[0], CheckState.Fail, reason);
        foreach (var check in report.Checks.Skip(1)) Reason.Assert(check, CheckState.Unknown, LoginReport.NotRunReason);
        Assert.False(report.LoggedIn);
        Assert.Null(report.SubjectSerialNumber);
    }

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
        Assert.Equal("TEST ONLY Citizen", report.SubjectName);
        Assert.Equal(TestPki.SubjectSerial, report.SubjectSerialNumber);
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
        Assert.Equal(TestPki.SubjectSerial, report.SubjectSerialNumber);
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

    /// The signature is otherwise valid (over the bound digest of that very challenge): only the length fails it —
    /// before anything is signed, and without any network request.
    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public async Task ChallengeNotExactly32BytesIsRejectedWithoutSigningOrNetwork(int length)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var challenge = Enumerable.Repeat((byte)9, length).ToArray();
        var expected = "Challenge " + length + " байт (яг 32 байт байх ёстой)";
        var signed = false;
        var transport = Online(pki, leaf);
        var run = await new LoginVerifier(pki.Trust, transport, () => Now).RunAsync(TestPki.Origin, challenge,
            leaf.RawData, (_, _) => { signed = true; return Task.FromResult(new byte[64]); });
        Assert.False(signed);
        AssertRejected(run, expected);
        Assert.Throws<ArgumentException>(() => LoginChallenge.DigestToSign(TestPki.Origin, challenge));

        var validSignature = TestPki.Sign(leaf, TestPki.Origin, challenge);
        var verified = await new LoginVerifier(pki.Trust, transport, () => Now)
            .VerifyAsync(TestPki.Origin, challenge, validSignature, leaf.RawData);
        AssertRejected(verified, expected);
        Assert.Empty(transport.Requested);
    }

    [Theory]
    [InlineData("")]
    [InlineData("https://rp.test.invalid")]
    [InlineData("RP.test.invalid")]
    [InlineData("rp.test.invalid:443")]
    [InlineData("rp.test.invalid/login")]
    [InlineData("rp.test.invalid.")]
    public async Task InvalidOriginIsRejectedWithoutSigningOrNetwork(string origin)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        var signed = false;
        var run = await new LoginVerifier(pki.Trust, transport, () => Now).RunAsync(origin, Challenge, leaf.RawData,
            (_, _) => { signed = true; return Task.FromResult(new byte[64]); });
        Assert.False(signed);
        AssertRejected(run, Origin.InvalidReason);
        var verify = await new LoginVerifier(pki.Trust, transport, () => Now)
            .VerifyAsync(origin, Challenge, TestPki.Sign(leaf, origin, Challenge), leaf.RawData);
        AssertRejected(verify, Origin.InvalidReason);
        Assert.Empty(transport.Requested);
    }

    /// anything but one strict DER certificate — PEM, PKCS#7, PFX, trailing bytes, empty, null, a non-DER
    /// BOOLEAN, an impossible date — is signature ✗ with no network request; nothing throws.
    [Fact]
    public async Task NonCertificateInputIsRejectedWithoutNetworkAndNeverThrows()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var transport = Online(pki, leaf);
        var verifier = new LoginVerifier(pki.Trust, transport, () => Now);
        var signature = TestPki.Sign(leaf, TestPki.Origin, Challenge);
        foreach (var (name, bytes) in DerTests.NonCertificates(pki, leaf))
        {
            Assert.False(Der.IsStrictCertificate(bytes ?? Array.Empty<byte>()), name);
            AssertRejected(await verifier.VerifyAsync(TestPki.Origin, Challenge, signature, bytes!), Reason.Unreadable);
            var signed = false;
            AssertRejected(await verifier.RunAsync(TestPki.Origin, Challenge, bytes!,
                (_, _) => { signed = true; return Task.FromResult(signature); }), Reason.Unreadable);
            Assert.False(signed, name);
        }
        Assert.Empty(transport.Requested);
        // Null challenge / signature / signer: rows, not exceptions.
        AssertRejected(await verifier.VerifyAsync(TestPki.Origin, null!, signature, leaf.RawData), "Challenge 0 байт");
        Reason.Assert((await verifier.VerifyAsync(TestPki.Origin, Challenge, null!, leaf.RawData)).Checks[0], CheckState.Fail,
            "Гарын үсгийн урт 0 байт");
        Assert.Equal(CheckState.Unknown, (await verifier.RunAsync(TestPki.Origin, Challenge, leaf.RawData, null!)).Checks[0].State);
    }

    [Fact]
    public async Task BareSha256OfTheChallengeFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now)
            .VerifyAsync(TestPki.Origin, Challenge, TestPki.SignBare(leaf, Challenge), leaf.RawData);
        Reason.Assert(Row(report, CheckNames.Signature), CheckState.Fail, Reason.WrongKey);
        Assert.False(report.LoggedIn);
        Assert.Null(report.SubjectSerialNumber);
    }

    [Fact]
    public async Task SignatureForAnotherOriginFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var verifier = new LoginVerifier(pki.Trust, Online(pki, leaf), () => Now);
        var otherOrigin = await verifier.VerifyAsync(TestPki.Origin, Challenge,
            TestPki.Sign(leaf, "other.test.invalid", Challenge), leaf.RawData);
        Reason.Assert(Row(otherOrigin, CheckNames.Signature), CheckState.Fail, Reason.WrongKey);
        Assert.False(otherOrigin.LoggedIn);
    }

    [Fact]
    public void ZeroOrOutOfRangeScalarsAndNonRawSignaturesFail()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var good = TestPki.Sign(leaf, TestPki.Origin, Challenge);
        Assert.Equal(CheckState.Pass, LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, good).State);

        const string scalar = "Гарын үсгийн r эсвэл s хүчингүй (0 эсвэл ≥ n)";
        var zeroR = (byte[])good.Clone();
        Array.Clear(zeroR, 0, 32);
        var zeroS = (byte[])good.Clone();
        Array.Clear(zeroS, 32, 32);
        byte[] rIsN = [.. LoginVerifier.P256Order, .. good.AsSpan(32).ToArray()];
        Reason.Assert(LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, zeroR), CheckState.Fail, scalar);
        Reason.Assert(LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, zeroS), CheckState.Fail, scalar);
        Reason.Assert(LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, rIsN), CheckState.Fail, scalar);

        using var key = leaf.GetECDsaPrivateKey()!;
        var der = key.SignHash(LoginChallenge.DigestToSign(TestPki.Origin, Challenge), DSASignatureFormat.Rfc3279DerSequence);
        Reason.Assert(LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, der), CheckState.Fail,
            "Гарын үсгийн урт " + der.Length + " байт");
        Reason.Assert(LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, good[..63]), CheckState.Fail,
            "Гарын үсгийн урт 63 байт");
        var tampered = (byte[])good.Clone();
        tampered[10] ^= 0x01;
        Reason.Assert(LoginVerifier.SignatureCheck(leaf, TestPki.Origin, Challenge, tampered), CheckState.Fail, Reason.WrongKey);

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

        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Unknown, "OCSP руу холбогдож чадсангүй (ocsp.test.invalid)");
        Reason.Assert(Row(report, CheckNames.Crl), CheckState.Unknown, "CRL татаж чадсангүй (crl.test.invalid)");
        Reason.Assert(Row(report, CheckNames.Chain), CheckState.Unknown,       // issuing CA revocation unreachable
            "Олгогч CA (TEST ONLY Issuing CA) — OCSP: OCSP руу холбогдож чадсангүй");
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
        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Unknown, "OCSP руу холбогдож чадсангүй (ocsp.test.invalid)");
        Reason.Assert(Row(report, CheckNames.Crl), CheckState.Unknown, "CRL татаж чадсангүй (crl.test.invalid)");
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
        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Fail, "OCSP хариунд nonce алга (AUTH гэрчилгээнд заавал)");
        Assert.False(report.LoggedIn);
        Assert.Null(report.SubjectSerialNumber);
    }

    [Fact]
    public async Task RevokedCertificateIsNotLoggedIn()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var report = await Run(pki, Online(pki, leaf, status: 1, revoked: [leaf]), leaf);

        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Fail, "Гэрчилгээ цуцлагдсан (");
        Reason.Assert(Row(report, CheckNames.Crl), CheckState.Fail, "Гэрчилгээ CRL-д цуцлагдсан (");
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
        Reason.Assert(Row(ocspReport, CheckNames.Chain), CheckState.Fail,
            "Олгогч CA (TEST ONLY Issuing CA) — OCSP: Гэрчилгээ цуцлагдсан");
        Assert.False(ocspReport.LoggedIn);

        var byCrl = Online(pki, leaf);
        byCrl.Crls[TestPki.CaCrlUrl] = TestPki.Crl(pki.Intermediate, [pki.Issuing], Now.AddHours(-1), Now.AddDays(1));
        var crlReport = await Run(pki, byCrl, leaf);
        Reason.Assert(Row(crlReport, CheckNames.Chain), CheckState.Fail,
            "Олгогч CA (TEST ONLY Issuing CA) — CRL: Гэрчилгээ CRL-д цуцлагдсан");
        Assert.False(crlReport.LoggedIn);

        var unreachable = Online(pki, leaf);
        unreachable.Crls.Remove(TestPki.CaCrlUrl);
        var offline = await Run(pki, unreachable, leaf);
        Reason.Assert(Row(offline, CheckNames.Chain), CheckState.Unknown,
            "Олгогч CA (TEST ONLY Issuing CA) — CRL: CRL татаж чадсангүй");
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
        Reason.Assert(Row(report, CheckNames.Chain), CheckState.Unknown,
            "Олгогч CA (TEST ONLY Issuing CA)-ийн гэрчилгээнд AIA ч CDP ч алга");
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

        Reason.Assert(report.Checks[0], CheckState.Fail, Reason.WrongKey);
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

        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Unknown, "Гэрчилгээнд OCSP хаяг (AIA) алга");
        Reason.Assert(Row(report, CheckNames.Crl), CheckState.Unknown, "Гэрчилгээнд CRL хаяг (CDP) алга");
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

        Reason.Assert(Row(report, CheckNames.Chain), CheckState.Fail, Reason.NotTrusted);
        // Not issued by the pinned issuing CA: OCSP / CRL cannot be judged against it.
        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Unknown, Reason.NoIssuingCa);
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
        Assert.Equal(new[] { pki.Issuing.RawData, pki.Intermediate.RawData, pki.National.RawData, pki.Root.RawData },
                     cas.Select(c => c.RawData));
    }

    [Fact]
    public void ForeignRootOrMissingIntermediateFails()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create("OTHER");
        using var leaf = pki.CreateLeaf();
        var foreignRoot = new TrustAnchors([TestPki.PublicOnly(other.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate), TestPki.PublicOnly(pki.Issuing)],
            TestPki.PublicOnly(pki.Issuing));
        Reason.Assert(new LoginVerifier(foreignRoot, new FakeTransport(), () => Now).Chain(leaf, Now, []), CheckState.Fail,
            Reason.NotTrusted);
        var missing = new TrustAnchors([TestPki.PublicOnly(pki.Root)], [TestPki.PublicOnly(pki.Issuing)],
            TestPki.PublicOnly(pki.Issuing));
        Reason.Assert(new LoginVerifier(missing, new FakeTransport(), () => Now).Chain(leaf, Now, []), CheckState.Fail,
            Reason.NotTrusted);
    }

    [Fact]
    public void EndEntityIssuedDirectlyByANonIssuingCaFails()
    {
        using var pki = TestPki.Create();
        using var fromNational = pki.CreateLeaf(issuer: pki.National);           // ≙ 02
        using var fromIntermediate = pki.CreateLeaf(issuer: pki.Intermediate);   // ≙ 03
        using var fromRoot = pki.CreateLeaf(issuer: pki.Root);                   // ≙ 01
        var verifier = new LoginVerifier(pki.Trust, new FakeTransport(), () => Now);
        Reason.Assert(verifier.Chain(fromNational, Now, []), CheckState.Fail, Reason.Not04);
        Reason.Assert(verifier.Chain(fromIntermediate, Now, []), CheckState.Fail, Reason.Not04);
        Reason.Assert(verifier.Chain(fromRoot, Now, []), CheckState.Fail, Reason.Not04);
    }

    /// The REAL 04 is pinned; an impostor CA with the same subject but another key, chained under the same root,
    /// issues the AUTH certificate: the issuer pin rejects it (and OCSP / CRL have no issuer for it).
    [Fact]
    public void SameSubjectDifferentKeyIssuerIsRejected()
    {
        using var pki = TestPki.Create();
        using var impostor = pki.IssuingCopy(sameKey: false, to: Now.AddYears(2));     // covers the leaf's validity
        using var leaf = pki.CreateLeaf(issuer: impostor);
        var trust = new TrustAnchors([TestPki.PublicOnly(pki.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate), TestPki.PublicOnly(pki.Issuing),
             TestPki.PublicOnly(impostor)], TestPki.PublicOnly(pki.Issuing));
        Reason.Assert(new LoginVerifier(trust, new FakeTransport(), () => Now).Chain(leaf, Now, []), CheckState.Fail, Reason.Not04);
        Assert.Null(trust.IssuerOf(leaf));
    }

    /// The pinned 04 has expired while a valid copy with the same subject and key exists: the chain row fails —
    /// validity is judged on the pinned certificate, a copy does not stand in for it.
    [Fact]
    public void ExpiredPinned04WithValidSameKeyCopyFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var expiredPinned = pki.IssuingCopy(sameKey: true, from: Now.AddDays(-400), to: Now.AddDays(-1));
        var trust = new TrustAnchors([TestPki.PublicOnly(pki.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate), TestPki.PublicOnly(expiredPinned),
             TestPki.PublicOnly(pki.Issuing)], TestPki.PublicOnly(expiredPinned));
        Reason.Assert(new LoginVerifier(trust, new FakeTransport(), () => Now).Chain(leaf, Now, []), CheckState.Fail,
            "Гинжний гэрчилгээ (TEST ONLY Issuing CA) хүчинтэй хугацаанаас гадуур");
    }

    /// another copy of 04 (same subject and key, different DER) among the candidates is neither used nor a reason
    /// to refuse: the path passes and carries the PINNED 04 DER.
    [Fact]
    public void LegacyCopyOf04IsNeitherUsedNorRefused()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var legacy = pki.IssuingCopy(sameKey: true);
        Assert.NotEqual(legacy.RawData, pki.Issuing.RawData);
        var trust = new TrustAnchors([TestPki.PublicOnly(pki.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate), TestPki.PublicOnly(legacy),
             TestPki.PublicOnly(pki.Issuing)], TestPki.PublicOnly(pki.Issuing));
        var cas = new List<X509Certificate2>();
        var result = new LoginVerifier(trust, new FakeTransport(), () => Now).Chain(leaf, Now, cas);
        Assert.Equal(CheckState.Pass, result.State);
        Assert.Equal(pki.Issuing.RawData, cas[0].RawData);
        Assert.Equal(4, cas.Count);
    }

    /// an expired CA in the path fails the CHAIN row (the same on macOS).
    [Fact]
    public async Task ExpiredIntermediateFailsTheChain()
    {
        using var pki = TestPki.Create(intermediateTo: Now.AddDays(-1));
        using var leaf = pki.CreateLeaf();
        const string expected = "Гинжний гэрчилгээ (TEST ONLY Intermediate CA) хүчинтэй хугацаанаас гадуур";
        Reason.Assert(new LoginVerifier(pki.Trust, new FakeTransport(), () => Now).Chain(leaf, Now, []), CheckState.Fail, expected);
        var report = await Run(pki, Online(pki, leaf), leaf);
        Reason.Assert(Row(report, CheckNames.Chain), CheckState.Fail, expected);
        Assert.False(report.LoggedIn);
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
        Reason.Assert(Row(report, CheckNames.Chain), CheckState.Fail, Reason.Not04);
        Reason.Assert(Row(report, CheckNames.Ocsp), CheckState.Unknown, Reason.NoIssuingCa);
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
        Reason.Assert(Row(signReport, CheckNames.Chain), CheckState.Fail, Reason.KeyUsageOnly);
        Assert.False(signReport.LoggedIn);

        var responderReport = await Run(pki, Online(pki, responder), responder);
        Assert.Equal(CheckState.Pass, Row(responderReport, CheckNames.Signature).State);
        Reason.Assert(Row(responderReport, CheckNames.Chain), CheckState.Fail, Reason.NoClientAuth);
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
        foreach (var (bad, reason) in new[]
                 {
                     (noKeyUsage, Reason.KeyUsageMissing), (noEku, Reason.EkuMissing), (extraBit, Reason.KeyUsageOnly),
                     (noClientAuth, Reason.NoClientAuth), (otherPrefix, Reason.SerialNumber), (noSerial, Reason.SerialNumber),
                 })
        {
            Assert.Equal(reason, LoginVerifier.AuthProfileProblem(bad));
            Reason.Assert(verifier.Chain(bad, Now, []), CheckState.Fail, reason);
        }
    }

    [Fact]
    public void ChainWithoutTrustAnchorsOrIssuingCaCannotBeChecked()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Reason.Assert(new LoginVerifier(new TrustAnchors([], [], null), new FakeTransport(), () => Now).Chain(leaf, Now, []),
            CheckState.Unknown, "Итгэлийн үндэс (trust anchor) апп-д алга");
        var noIssuing = new TrustAnchors([TestPki.PublicOnly(pki.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate)], TestPki.PublicOnly(pki.Issuing));
        Assert.Null(noIssuing.IssuingCa);
        Reason.Assert(new LoginVerifier(noIssuing, new FakeTransport(), () => Now).Chain(leaf, Now, []), CheckState.Unknown,
            Reason.NoIssuingCa);
    }

    [Fact]
    public async Task ExpiredCertificateFailsValidityButStillBuildsTheChain()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(from: Now.AddDays(-300), to: Now.AddDays(-1));
        var report = await Run(pki, Online(pki, leaf), leaf);

        Assert.Equal(CheckState.Pass, Row(report, CheckNames.Chain).State);
        Reason.Assert(Row(report, CheckNames.Validity), CheckState.Fail, "Гэрчилгээний хугацаа ");
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public void NotYetValidCertificateFailsValidity()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(from: Now.AddDays(1), to: Now.AddDays(30));
        var result = LoginVerifier.Validity(leaf, [], Now);
        Reason.Assert(result, CheckState.Fail, "Гэрчилгээ ");
        Assert.EndsWith("-аас хүчинтэй болно", result.Reason, StringComparison.Ordinal);
    }

    /// notAfter is inclusive: valid AT notAfter, expired one second later.
    [Fact]
    public void NotAfterBoundaryIsInclusive()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf(from: Now.AddDays(-1), to: Now.AddMinutes(1));
        var notAfter = new DateTimeOffset(leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        Assert.Equal(CheckState.Pass, LoginVerifier.Validity(leaf, [], notAfter).State);
        Reason.Assert(LoginVerifier.Validity(leaf, [], notAfter.AddSeconds(1)), CheckState.Fail, "Гэрчилгээний хугацаа ");
    }

    [Fact]
    public async Task UnreadableCertificateStopsBeforeSigning()
    {
        var signed = false;
        var report = await new LoginVerifier(new TrustAnchors([], [], null), new FakeTransport(), () => Now)
            .RunAsync(TestPki.Origin, Challenge, [0x30, 0x00], (_, _) => { signed = true; return Task.FromResult(Array.Empty<byte>()); });
        Assert.False(signed);
        AssertRejected(report, Reason.Unreadable);
        Assert.StartsWith("Нэвтэрч чадсангүй: " + CheckNames.Signature + " — " + Reason.Unreadable, report.Summary,
            StringComparison.Ordinal);
    }
}
