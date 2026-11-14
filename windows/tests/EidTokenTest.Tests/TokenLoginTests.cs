using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

public sealed class TokenLoginTests
{
    private static readonly byte[] Garbage = [0x30, 0x00];

    [Fact]
    public void KindFollowsTheCkaId()
    {
        Assert.Equal(CertificateKind.Auth, EidKeyId.KindOf(EidKeyId.Auth));
        Assert.Equal(CertificateKind.Auth, EidKeyId.KindOf(EidKeyId.StagedAuth));
        Assert.Equal(CertificateKind.Sign, EidKeyId.KindOf(EidKeyId.Sign));
        Assert.Equal(CertificateKind.Sign, EidKeyId.KindOf(EidKeyId.StagedSign));
        Assert.Equal(CertificateKind.Other, EidKeyId.KindOf([0x01]));
        Assert.Equal("Нэвтрэх", CertificateView.Label(CertificateKind.Auth));
        Assert.Equal("Гарын үсэг", CertificateView.Label(CertificateKind.Sign));
    }

    [Fact]
    public void DescribeShowsSubjectSerialIssuerAndHexSerial()
    {
        using var pki = TestPki.Create();
        using var auth = pki.CreateLeaf();
        var view = CertificateView.Describe(new TokenCertificateObject(EidKeyId.Auth, "eID AUTH", auth.RawData));

        Assert.Equal(CertificateKind.Auth, view.Kind);
        Assert.Equal("AUTH", view.KindCode);
        Assert.Equal("45494401", view.KeyIdHex);
        Assert.Equal("TEST ONLY Citizen", view.SubjectName);
        Assert.Equal(TestPki.SubjectSerial, view.SubjectSerial);
        Assert.Equal("TEST ONLY Issuing CA", view.Issuer);
        Assert.Equal(auth.SerialNumber.TrimStart('0'), view.SerialHex.TrimStart('0'));
        Assert.NotNull(view.NotBefore);
        Assert.NotNull(view.NotAfter);
        Assert.Equal("—", CertificateView.Describe(new TokenCertificateObject([0x01], string.Empty, Garbage)).Issuer);
    }

    [Fact]
    public void AuthCertificateIsThePrimaryElseTheStagedOne()
    {
        var staged = new TokenCertificateObject(EidKeyId.StagedAuth, string.Empty, [1]);
        var primary = new TokenCertificateObject(EidKeyId.Auth, string.Empty, [2]);
        var sign = new TokenCertificateObject(EidKeyId.Sign, string.Empty, [3]);
        Assert.Same(primary, TokenLogin.AuthCertificate([staged, sign, primary]));
        Assert.Same(staged, TokenLogin.AuthCertificate([sign, staged]));
        Assert.Null(TokenLogin.AuthCertificate([sign]));
        Assert.True(TokenLogin.HasEidCertificates([sign]));
        Assert.False(TokenLogin.HasEidCertificates([new TokenCertificateObject([0x01], string.Empty, [4])]));
    }

    [Fact]
    public async Task NoEidCertificateStopsBeforeCLogin()
    {
        var source = new FakeTokenSource { Certificates = [new TokenCertificateObject([0x01], "other", Garbage)] };
        using var pki = TestPki.Create();
        var report = await TokenLogin.RunAsync(source, 0, TestPki.Origin, "1234",
            new LoginVerifier(pki.Trust, new FakeTransport(), () => TestPki.Now));
        Assert.Equal(TokenLogin.NoEidCertificates, report.StopReason);
        Assert.Equal(0, source.SignCalls);
        Assert.False(report.LoggedIn);
    }

    [Fact]
    public async Task OneSignCallPerLogin()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var source = new FakeTokenSource { Certificates = [new TokenCertificateObject(EidKeyId.Auth, "eID AUTH", leaf.RawData)] };
        var report = await TokenLogin.RunAsync(source, 0, TestPki.Origin, "1234",
            new LoginVerifier(pki.Trust, new FakeTransport(), () => TestPki.Now));
        Assert.Equal(1, source.SignCalls);
        Assert.Equal("PIN буруу", report.Checks[0].Reason);
        Assert.False(report.LoggedIn);
    }
}

/// A token that never touches hardware: SignDigest always refuses (wrong PIN) and counts the calls.
internal sealed class FakeTokenSource : ITokenSource
{
    public List<TokenSummary> Tokens { get; set; } = [];
    public List<TokenCertificateObject> Certificates { get; set; } = [];
    public int SignCalls { get; private set; }

    public IReadOnlyList<TokenSummary> ListTokens() => Tokens;

    public IReadOnlyList<TokenCertificateObject> ReadCertificates(ulong slotId) => Certificates;

    public byte[] SignDigest(ulong slotId, byte[] keyId, byte[] digest, string pin)
    {
        SignCalls++;
        throw new TokenLoginException(TokenLoginError.PinIncorrect);
    }
}
