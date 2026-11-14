using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

public sealed class CrlTests
{
    private static readonly DateTimeOffset Now = TestPki.Now;

    [Fact]
    public void CurrentCrlWithoutTheSerialPasses()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var someoneElse = pki.CreateLeaf();
        var crl = TestPki.Crl(pki.Issuing, [someoneElse], Now.AddHours(-1), Now.AddDays(1));
        Assert.Equal(CheckState.Pass, Crl.Evaluate(crl, leaf, pki.Issuing, Now).State);
    }

    [Fact]
    public void ListedSerialFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.Crl(pki.Issuing, [leaf], Now.AddHours(-1), Now.AddDays(1));
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Fail, "Гэрчилгээ CRL-д цуцлагдсан (");
    }

    [Fact]
    public void CrlPastNextUpdateFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.Crl(pki.Issuing, [], Now.AddDays(-10), Now.AddDays(-1));
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Fail, "CRL хуучирсан");
    }

    [Fact]
    public void CrlSignedByAnotherKeyUnderTheSameNameFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        using var impostor = TestPki.CreateCa("TEST ONLY Issuing CA", pki.Intermediate, Now.AddDays(-10), Now.AddYears(1), 0);
        var crl = TestPki.Crl(impostor, [], Now.AddHours(-1), Now.AddDays(1));
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Fail,
            "CRL-ийн гарын үсэг олгогчийн түлхүүртэй таарахгүй");
    }

    [Fact]
    public void CrlOfAnotherCaFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.Crl(pki.Intermediate, [], Now.AddHours(-1), Now.AddDays(1));
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Fail, "CRL-ийг энэ гэрчилгээний олгогч гаргаагүй");
    }

    [Fact]
    public void GarbageFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Reason.Assert(Crl.Evaluate([0x30, 0x01, 0x00], leaf, pki.Issuing, Now), CheckState.Fail, Reason.CrlMalformed);
    }

    [Fact]
    public void HandWrittenCrlIsReadLikeTheBuilderOne()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.Equal(CheckState.Pass, Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), Now.AddDays(1)), leaf, pki.Issuing, Now).State);
        Reason.Assert(Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), Now.AddDays(1), [leaf]), leaf, pki.Issuing, Now),
            CheckState.Fail, "Гэрчилгээ CRL-д цуцлагдсан (");
    }

    [Fact]
    public void CrlWithoutNextUpdateCannotBeChecked()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), null);
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Unknown, "CRL-д nextUpdate алга");
    }

    [Theory]
    [InlineData("2.5.29.27", true, "Delta CRL дэмжигдээгүй")]                                  // deltaCRLIndicator
    [InlineData("2.5.29.28", true, "issuingDistributionPoint-той CRL дэмжигдээгүй")]          // issuingDistributionPoint
    [InlineData("2.5.29.28", false, "issuingDistributionPoint-той CRL дэмжигдээгүй")]
    [InlineData("1.3.6.1.4.1.311.99", true, "CRL-д үл мэдэгдэх critical өргөтгөл байна")]     // unknown, critical
    public void DeltaIdpOrUnknownCriticalExtensionCannotBeUsed(string oid, bool critical, string reason)
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), Now.AddDays(1), extensionOid: oid, critical: critical);
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Unknown, reason);
    }

    /// A critical flag that is not DER (0x01 instead of 0xFF) makes the CRL unreadable (the same on macOS). The CRL is
    /// re-signed after the edit, so only the encoding is wrong.
    [Fact]
    public void NonDerBooleanFails()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), Now.AddDays(1), extensionOid: "2.5.29.20", critical: true,
            booleanByte: 0x01);
        Reason.Assert(Crl.Evaluate(crl, leaf, pki.Issuing, Now), CheckState.Fail, Reason.CrlMalformed);
    }

    [Fact]
    public void UnknownNonCriticalExtensionIsIgnored()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var crl = TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), Now.AddDays(1), extensionOid: "1.3.6.1.4.1.311.99", critical: false);
        Assert.Equal(CheckState.Pass, Crl.Evaluate(crl, leaf, pki.Issuing, Now).State);
    }

    [Fact]
    public void FiveMinutesClockSkewOnBothEnds()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.Equal(CheckState.Pass,
            Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddMinutes(2), Now.AddDays(1)), leaf, pki.Issuing, Now).State);
        Assert.Equal(CheckState.Pass,
            Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddDays(-1), Now.AddMinutes(-2)), leaf, pki.Issuing, Now).State);
        Reason.Assert(Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddMinutes(10), Now.AddDays(1)), leaf, pki.Issuing, Now),
            CheckState.Fail, "CRL ирээдүйн огноотой");
        Reason.Assert(Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddDays(-1), Now.AddMinutes(-10)), leaf, pki.Issuing, Now),
            CheckState.Fail, "CRL хуучирсан");
    }

    [Fact]
    public void GeneralizedTimeIsAcceptedLikeUtcTime()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.Equal(CheckState.Pass,
            Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddHours(-1), Now.AddDays(1), generalized: true), leaf, pki.Issuing, Now).State);
    }

    [Fact]
    public void NextUpdateBoundaryIsInclusive()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        Assert.Equal(CheckState.Pass,
            Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddDays(-1), Now.AddMinutes(-5)), leaf, pki.Issuing, Now).State);
        Reason.Assert(Crl.Evaluate(TestPki.RawCrl(pki.Issuing, Now.AddDays(-1), Now.AddMinutes(-5).AddSeconds(-1)), leaf,
            pki.Issuing, Now), CheckState.Fail, "CRL хуучирсан");
    }
}
