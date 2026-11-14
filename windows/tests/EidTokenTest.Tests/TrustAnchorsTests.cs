using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

/// The bundled trust material (offline: signatures only, no network).
public sealed class TrustAnchorsTests
{
    /// SHA-256 of each bundled DER certificate (also listed in README.md).
    private static readonly string[] Fingerprints =
    [
        "cbe7f3fe1f048037c215da321e58caa4f363de9e54bbc442a3bfd62fad834482", // 01 Mongolian National Root CA
        "9423640dd74561d1af1ea8a093860bda7df5b5620bb617921395dc0d1a1f980d", // 02 Mongolian National Issuing CA
        "56f3d1ca7f282287619773905aa0cd7a427d4f95dc0ed7b6733963a89bc31237", // 03 Gerege Issuing CA
        "87b8db6862abde5e4a07a10c2c696afe5cb6aea072b9f3f9755e73ce79f546fc", // 04 eID Mongolia Issuing CA
    ];

    [Fact]
    public void BundledCertificatesAreExactlyThePublishedChain()
    {
        var trust = TrustAnchors.Bundled();
        var all = trust.Roots.Concat(trust.Intermediates).Select(TrustAnchors.Sha256Hex).Order(StringComparer.Ordinal);
        Assert.Equal(Fingerprints.Order(StringComparer.Ordinal), all);
    }

    [Fact]
    public void RootByFolderAndThePinnedIssuingCa()
    {
        var trust = TrustAnchors.Bundled();
        Assert.Single(trust.Roots);
        Assert.Equal(Fingerprints[0], TrustAnchors.Sha256Hex(trust.Roots[0]));
        Assert.Equal(3, trust.Intermediates.Count);
        Assert.NotNull(trust.IssuingCa);
        Assert.Equal(TrustAnchors.IssuingCaSha256, TrustAnchors.Sha256Hex(trust.IssuingCa!));
        Assert.Contains("eID Mongolia Issuing CA", trust.IssuingCa!.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryCertificateIsSignedByItsBundledParent()
    {
        var trust = TrustAnchors.Bundled();
        var all = trust.Roots.Concat(trust.Intermediates).ToList();
        Assert.True(Der.IsSignedBy(trust.Roots[0], trust.Roots[0]));
        foreach (var ca in trust.Intermediates)
            Assert.Contains(all, parent => !ReferenceEquals(parent, ca) && Der.IsSignedBy(ca, parent));
    }

    [Fact]
    public void IssuingCaMustBeOneOfTheIntermediates()
    {
        using var pki = TestPki.Create();
        Assert.NotNull(pki.Trust.IssuingCa);
        Assert.Null(new TrustAnchors([TestPki.PublicOnly(pki.Root)], [], TestPki.PublicOnly(pki.Issuing)).IssuingCa);
    }

    /// A trust file that is not one strict DER certificate stops loading with an error naming the file (the same on
    /// macOS) — never silently skipped.
    [Fact]
    public void BrokenTrustFileFailsLoudly()
    {
        using var pki = TestPki.Create();
        static string Pem(byte[] der) =>
            "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
        Assert.Single(TrustAnchors.ParsePem(Pem(pki.Root.RawData), "anchors/root.pem"));
        foreach (var (text, reason) in new[]
                 {
                     ("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n", "not valid base64"),
                     ("-----BEGIN CERTIFICATE-----\n", "unclosed"),
                     ("no certificate here", "no certificate"),
                     (Pem([.. pki.Issuing.RawData, 0x00]), "not one strict DER certificate"),
                     (Pem(DerTests.NonDerBoolean(pki.Root)), "not one strict DER certificate"),
                 })
        {
            var error = Assert.Throws<InvalidOperationException>(() => TrustAnchors.ParsePem(text, "intermediates/bad.pem"));
            Assert.StartsWith("intermediates/bad.pem", error.Message, StringComparison.Ordinal);
            Assert.Contains(reason, error.Message, StringComparison.Ordinal);
        }
    }

    /// the public constructor enforces the 04 pin — a test CA can only be injected through the internal one.
    [Fact]
    public void PublicConstructorEnforcesThePin()
    {
        using var pki = TestPki.Create();
        var withTestCa = new TrustAnchors([TestPki.PublicOnly(pki.Root)],
            [TestPki.PublicOnly(pki.National), TestPki.PublicOnly(pki.Intermediate), TestPki.PublicOnly(pki.Issuing)]);
        Assert.Null(withTestCa.IssuingCa);
        var bundled = TrustAnchors.Bundled();
        var rebuilt = new TrustAnchors(bundled.Roots, bundled.Intermediates);
        Assert.NotNull(rebuilt.IssuingCa);
        Assert.Equal(TrustAnchors.IssuingCaSha256, TrustAnchors.Sha256Hex(rebuilt.IssuingCa!));
        Assert.DoesNotContain(typeof(TrustAnchors).GetConstructors(), c => c.GetParameters().Length != 2);
    }
}
