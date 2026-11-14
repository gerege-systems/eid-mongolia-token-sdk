using EidTokenTest.Core.Tokens;
using Net.Pkcs11Interop.Common;
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
        var report = await TokenLogin.RunAsync(source, "S1", TestPki.Origin, "1234",
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
        var report = await TokenLogin.RunAsync(source, "S1", TestPki.Origin, "1234",
            new LoginVerifier(pki.Trust, new FakeTransport(), () => TestPki.Now));
        Assert.Equal(1, source.SignCalls);
        Assert.Equal("PIN буруу", report.Checks[0].Reason);
        Assert.False(report.LoggedIn);
        Assert.Equal(new[] { "S1" }, source.SignedSerials);          // the token is addressed by serial, not by a slot ID
    }

    /// L4: a token swapped in the same slot before signing is not found by its serial — refused before C_Login.
    [Fact]
    public void TokenSwappedInTheSlotIsNotFoundBySerial()
    {
        var before = new[] { new FakeSlot(1, "S1"), new FakeSlot(2, "S2") };
        Assert.Same(before[0], Pkcs11TokenReader.SlotWithSerial(before, s => s.Serial, "S1"));
        var swapped = new[] { new FakeSlot(1, "S9"), new FakeSlot(2, "S2") };               // another token in slot 1
        Assert.Null(Pkcs11TokenReader.SlotWithSerial(swapped, s => s.Serial, "S1"));
        var moved = new[] { new FakeSlot(1, "S9"), new FakeSlot(3, "S1   ") };              // S1 now in slot 3 (padded)
        Assert.Same(moved[1], Pkcs11TokenReader.SlotWithSerial(moved, s => s.Serial, "S1"));
        var removed = new[] { new FakeSlot(1, null, removed: true), new FakeSlot(2, "S1") };
        Assert.Same(removed[1], Pkcs11TokenReader.SlotWithSerial(removed, s => s.Serial, "S1"));
        Assert.False(Pkcs11TokenReader.IsSameToken("S9", "S1"));
        Assert.True(Pkcs11TokenReader.IsSameToken("S1\0\0  ", "S1"));
        Assert.False(Pkcs11TokenReader.IsSameToken("", ""));
    }

    /// B: CKR_USER_ALREADY_LOGGED_IN is a login this reader did not make — refused, the same as on macOS.
    [Fact]
    public void UserAlreadyLoggedInIsRefused()
    {
        var error = Pkcs11TokenReader.MapError(CKR.CKR_USER_ALREADY_LOGGED_IN);
        Assert.Equal(TokenLoginError.AlreadyLoggedIn, error.Error);
        Assert.Equal("Токенд өөр session нэвтэрсэн байна — энэ оролдлого гарын үсэг зурахгүй", error.Message);
        Assert.Equal(TokenLoginError.PinIncorrect, Pkcs11TokenReader.MapError(CKR.CKR_PIN_INCORRECT).Error);
    }

    private sealed class FakeSlot(ulong id, string? serial, bool removed = false)
    {
        public ulong Id { get; } = id;

        public string? Serial => removed
            ? throw new Pkcs11Exception("C_GetTokenInfo", CKR.CKR_TOKEN_NOT_PRESENT)
            : serial;
    }
}

/// A token that never touches hardware: SignDigest always refuses (wrong PIN) and counts the calls.
internal sealed class FakeTokenSource : ITokenSource
{
    public List<TokenSummary> Tokens { get; set; } = [];
    public List<TokenCertificateObject> Certificates { get; set; } = [];
    public int SignCalls { get; private set; }
    public List<string> SignedSerials { get; } = [];

    public IReadOnlyList<TokenSummary> ListTokens() => Tokens;

    public IReadOnlyList<TokenCertificateObject> ReadCertificates(string serial) => Certificates;

    public byte[] SignDigest(string serial, byte[] keyId, byte[] digest, string pin)
    {
        SignCalls++;
        SignedSerials.Add(serial);
        throw new TokenLoginException(TokenLoginError.PinIncorrect);
    }
}
