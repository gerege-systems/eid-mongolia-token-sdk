using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EidTokenTest.Core.Verification;

/// The certificates a login is checked against, from the repository's `trust/` folder — embedded in this assembly,
/// never read from or written to a Windows certificate store. `anchors/` are the roots (the only trust anchors),
/// `intermediates/` the CAs between; root or intermediate is decided by the folder, never by looking at the
/// certificate (the same rule as on macOS):
///
///     Mongolian National Root CA                 trust/anchors/01-…
///       └─ Mongolian National Issuing CA         trust/intermediates/02-…
///            └─ Gerege Issuing CA                trust/intermediates/03-…
///                 └─ eID Mongolia Issuing CA     trust/intermediates/04-…   ← issues the token AUTH certificates
///
/// <see cref="IssuingCa"/> is the ONE CA allowed to issue an AUTH certificate directly: 04, pinned by the SHA-256 of
/// its DER (<see cref="IssuingCaSha256"/>). A certificate issued by any other CA under the same root — e.g. a
/// relying-party mTLS certificate with clientAuth from another eID CA — does not pass.
public sealed class TrustAnchors
{
    /// SHA-256 of `trust/intermediates/04-eid-mongolia-issuing-ca.pem` (DER), lowercase hex.
    public const string IssuingCaSha256 = "87b8db6862abde5e4a07a10c2c696afe5cb6aea072b9f3f9755e73ce79f546fc";

    /// <paramref name="issuingCa"/> must be one of <paramref name="intermediates"/> (byte for byte), otherwise it is
    /// dropped.
    public TrustAnchors(IEnumerable<X509Certificate2> roots, IEnumerable<X509Certificate2> intermediates,
                        X509Certificate2? issuingCa)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(intermediates);
        Roots = roots.ToList();
        Intermediates = intermediates.ToList();
        IssuingCa = issuingCa is null
            ? null
            : Intermediates.FirstOrDefault(c => c.RawData.AsSpan().SequenceEqual(issuingCa.RawData));
    }

    public IReadOnlyList<X509Certificate2> Roots { get; }
    public IReadOnlyList<X509Certificate2> Intermediates { get; }

    /// Null when the pinned issuing CA is not among <see cref="Intermediates"/>.
    public X509Certificate2? IssuingCa { get; }

    /// The certificates bundled with this build (`trust/anchors/*.pem`, `trust/intermediates/*.pem` resources); the
    /// issuing CA is the intermediate whose SHA-256 is <see cref="IssuingCaSha256"/>.
    public static TrustAnchors Bundled()
    {
        var roots = Load("trust/anchors/");
        var intermediates = Load("trust/intermediates/");
        return new TrustAnchors(roots, intermediates, intermediates.FirstOrDefault(c => Sha256Hex(c) == IssuingCaSha256));
    }

    public static string Sha256Hex(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();

    private static List<X509Certificate2> Load(string prefix)
    {
        var assembly = typeof(TrustAnchors).Assembly;
        var certificates = new List<X509Certificate2>();
        foreach (var name in assembly.GetManifestResourceNames()
                     .Where(n => n.StartsWith(prefix, StringComparison.Ordinal) && n.EndsWith(".pem", StringComparison.Ordinal))
                     .Order(StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            var collection = new X509Certificate2Collection();
            collection.ImportFromPem(reader.ReadToEnd());
            certificates.AddRange(collection);
        }
        return certificates;
    }

    /// The pinned issuing CA when it issued and signed <paramref name="certificate"/>, or null — the CA its OCSP / CRL
    /// answers must come from.
    public X509Certificate2? IssuerOf(X509Certificate2 certificate) =>
        IssuingCa is not null && Der.IsSignedBy(certificate, IssuingCa) ? IssuingCa : null;
}
