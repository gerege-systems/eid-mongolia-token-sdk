using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    /// The issuing CA is the intermediate whose SHA-256 is <see cref="IssuingCaSha256"/> — the pin cannot be replaced
    /// from outside this assembly. Every certificate must be one strict DER certificate
    /// (<see cref="Der.IsStrictCertificate"/>); anything else throws <see cref="ArgumentException"/> — a broken trust
    /// set is never silently ignored (the same on macOS).
    public TrustAnchors(IEnumerable<X509Certificate2> roots, IEnumerable<X509Certificate2> intermediates)
        : this(Strict(roots, nameof(roots)), Strict(intermediates, nameof(intermediates)), pinned: true)
    {
    }

    private TrustAnchors(List<X509Certificate2> roots, List<X509Certificate2> intermediates, bool pinned)
        : this(roots, intermediates, pinned ? intermediates.FirstOrDefault(c => Sha256Hex(c) == IssuingCaSha256) : null)
    {
    }

    private static List<X509Certificate2> Strict(IEnumerable<X509Certificate2> certificates, string name)
    {
        ArgumentNullException.ThrowIfNull(certificates, name);
        var list = certificates.ToList();
        for (var i = 0; i < list.Count; i++)
        {
            if (!Der.IsStrictCertificate(list[i].RawData))
                throw new ArgumentException("trust/: certificate #" + (i + 1) + " is not one strict DER certificate", name);
        }
        return list;
    }

    /// Tests only (internal): another issuing CA. <paramref name="issuingCa"/> must be one of
    /// <paramref name="intermediates"/> (byte for byte), otherwise it is dropped.
    internal TrustAnchors(IEnumerable<X509Certificate2> roots, IEnumerable<X509Certificate2> intermediates,
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
    /// issuing CA is the intermediate whose SHA-256 is <see cref="IssuingCaSha256"/>. A resource that holds no
    /// certificate, a PEM block that is not valid base64, or anything that is not one strict DER certificate throws
    /// <see cref="InvalidOperationException"/> naming the file (the same rule as `TrustStore.load` on macOS).
    public static TrustAnchors Bundled()
    {
        return new TrustAnchors(Load("trust/anchors/"), Load("trust/intermediates/"));
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
            foreach (var der in ParsePem(reader.ReadToEnd(), name)) certificates.Add(X509CertificateLoader.LoadCertificate(der));
        }
        return certificates;
    }

    /// The CERTIFICATE blocks of a PEM file, each one strict DER certificate; throws <see cref="InvalidOperationException"/>
    /// naming <paramref name="name"/> otherwise (no block, unclosed block, bad base64, not strict DER).
    internal static List<byte[]> ParsePem(string text, string name)
    {
        const string begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----";
        var output = new List<byte[]>();
        var at = text.IndexOf(begin, StringComparison.Ordinal);
        while (at >= 0)
        {
            var start = at + begin.Length;
            var stop = text.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0) throw new InvalidOperationException(name + ": unclosed CERTIFICATE block");
            byte[] der;
            try
            {
                der = Convert.FromBase64String(text[start..stop]);
            }
            catch (FormatException)
            {
                throw new InvalidOperationException(name + ": a CERTIFICATE block is not valid base64");
            }
            if (!Der.IsStrictCertificate(der)) throw new InvalidOperationException(name + " is not one strict DER certificate");
            output.Add(der);
            at = text.IndexOf(begin, stop + end.Length, StringComparison.Ordinal);
        }
        if (output.Count == 0) throw new InvalidOperationException(name + ": no certificate");
        return output;
    }

    /// The pinned issuing CA when it issued and signed <paramref name="certificate"/>, or null — the CA its OCSP / CRL
    /// answers must come from.
    public X509Certificate2? IssuerOf(X509Certificate2 certificate) =>
        IssuingCa is not null && Der.IsSignedBy(certificate, IssuingCa) ? IssuingCa : null;

    /// The CA path from <paramref name="start"/> upwards through THESE certificates only (subject = issuer name AND
    /// signature), ending at a root when one is reached. Never looks at a Windows store or the network.
    internal IReadOnlyList<X509Certificate2> CaPath(X509Certificate2 start)
    {
        var pool = Intermediates.Concat(Roots).ToList();
        var path = new List<X509Certificate2> { start };
        while (path.Count <= pool.Count && !Roots.Any(r => r.RawData.AsSpan().SequenceEqual(path[^1].RawData)))
        {
            var current = path[^1];
            var parent = pool.FirstOrDefault(p => !path.Any(q => q.RawData.AsSpan().SequenceEqual(p.RawData))
                                                  && Der.IsSignedBy(current, p));
            if (parent is null) break;
            path.Add(parent);
        }
        return path;
    }
}
