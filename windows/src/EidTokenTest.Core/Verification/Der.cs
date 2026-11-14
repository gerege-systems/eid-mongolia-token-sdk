using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EidTokenTest.Core.Verification;

/// Small DER helpers shared by the certificate, CRL and OCSP checks (System.Formats.Asn1 only). Every reader uses
/// <see cref="AsnEncodingRules.DER"/>: definite, minimal lengths — the same strictness as on macOS.
internal static class Der
{
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string ClientAuthEku = "1.3.6.1.5.5.7.3.2";
    public const string OcspSigningEku = "1.3.6.1.5.5.7.3.9";
    public const string SerialNumberAttribute = "2.5.4.5";
    public const string DeltaCrlIndicator = "2.5.29.27";
    public const string IssuingDistributionPoint = "2.5.29.28";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag Context3 = new(TagClass.ContextSpecific, 3);

    /// Exactly one DER `Certificate` SEQUENCE spanning all of <paramref name="der"/> — no PEM, no PKCS#7, no PFX, no
    /// trailing bytes. The same structure rules as `ParsedCertificate(der:)` on macOS: definite minimal lengths, minimal
    /// INTEGER serial, DER BOOLEAN (0xFF / 0x00), DER times of real dates, unused-bits 0 in the signature and key, and
    /// nothing in TBSCertificate after subjectPublicKeyInfo but [1], [2], [3] in that order. Never throws.
    public static bool IsStrictCertificate(ReadOnlyMemory<byte> der)
    {
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.DER);
            var certificate = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var tbs = certificate.ReadSequence();
            certificate.ReadSequence().ReadObjectIdentifier();                       // signatureAlgorithm
            certificate.ReadBitString(out var unused);
            if (unused != 0) return false;
            certificate.ThrowIfNotEmpty();

            if (tbs.HasData && IsContext(tbs.PeekTag(), 0)) tbs.ReadSequence(Context0);  // [0] version
            tbs.ReadIntegerBytes();                                                    // serialNumber (DER: minimal)
            tbs.ReadSequence();                                                        // signature
            tbs.ReadSequence();                                                        // issuer
            var validity = tbs.ReadSequence();
            ReadTime(validity);
            ReadTime(validity);
            validity.ThrowIfNotEmpty();
            tbs.ReadSequence();                                                        // subject
            var spki = tbs.ReadSequence();
            spki.ReadSequence();
            spki.ReadBitString(out var keyUnused);
            if (keyUnused != 0) return false;
            spki.ThrowIfNotEmpty();
            foreach (var number in new[] { 1, 2 })                                     // issuer/subjectUniqueID
            {
                if (tbs.HasData && IsContext(tbs.PeekTag(), number)) tbs.ReadEncodedValue();
            }
            if (tbs.HasData && IsContext(tbs.PeekTag(), 3))
            {
                var wrapper = tbs.ReadSequence(Context3);
                var extensions = wrapper.ReadSequence();
                wrapper.ThrowIfNotEmpty();
                while (extensions.HasData)
                {
                    var extension = extensions.ReadSequence();
                    extension.ReadObjectIdentifier();
                    if (extension.HasData && extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                        extension.ReadBoolean();                                       // DER: 0xFF / 0x00 only
                    extension.ReadOctetString();
                    extension.ThrowIfNotEmpty();
                }
            }
            tbs.ThrowIfNotEmpty();
            return true;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    /// Loads untrusted certificate bytes: only after <see cref="IsStrictCertificate"/> accepted them, and only through
    /// the plain-certificate loader. False (nothing loaded) for anything else.
    public static bool TryLoadCertificate(byte[]? der, out X509Certificate2 certificate)
    {
        certificate = null!;
        if (der is null || !IsStrictCertificate(der)) return false;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(der);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// `SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING }` — Certificate, CertificateList and BasicOCSPResponse all
    /// start like this. Trailing elements (OCSP `certs`) stay in <paramref name="rest"/>.
    public static (ReadOnlyMemory<byte> Tbs, string Algorithm, byte[] Signature) ReadSigned(
        ReadOnlyMemory<byte> der, out AsnReader rest)
    {
        var outer = new AsnReader(der, AsnEncodingRules.DER);
        rest = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        var tbs = rest.ReadEncodedValue();
        var algorithm = rest.ReadSequence().ReadObjectIdentifier();
        var signature = rest.ReadBitString(out var unused);
        if (unused != 0) throw new CryptographicException("Signature BIT STRING has unused bits.");
        return (tbs, algorithm, signature);
    }

    /// Verifies <paramref name="signature"/> over <paramref name="tbs"/> with <paramref name="signer"/>'s public key.
    /// RSA PKCS#1 v1.5 and ECDSA with SHA-256/384/512. true / false = verified / not; null = the algorithm (or the
    /// signer's key type) is not supported here — «шалгаж чадсангүй», never a pass.
    public static bool? Verify(ReadOnlySpan<byte> tbs, string algorithm, byte[] signature, X509Certificate2 signer)
    {
        HashAlgorithmName hash;
        bool ec;
        switch (algorithm)
        {
            case "1.2.840.113549.1.1.11": hash = HashAlgorithmName.SHA256; ec = false; break;
            case "1.2.840.113549.1.1.12": hash = HashAlgorithmName.SHA384; ec = false; break;
            case "1.2.840.113549.1.1.13": hash = HashAlgorithmName.SHA512; ec = false; break;
            case "1.2.840.10045.4.3.2": hash = HashAlgorithmName.SHA256; ec = true; break;
            case "1.2.840.10045.4.3.3": hash = HashAlgorithmName.SHA384; ec = true; break;
            case "1.2.840.10045.4.3.4": hash = HashAlgorithmName.SHA512; ec = true; break;
            default: return null;
        }
        try
        {
            if (ec)
            {
                using var key = signer.GetECDsaPublicKey();
                return key is null ? null : key.VerifyData(tbs, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
            }
            using var rsa = signer.GetRSAPublicKey();
            return rsa is null ? null : rsa.VerifyData(tbs, signature, hash, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <paramref name="certificate"/> names <paramref name="issuer"/> as its issuer and carries its signature.
    public static bool IsSignedBy(X509Certificate2 certificate, X509Certificate2 issuer)
    {
        if (!certificate.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData)) return false;
        try
        {
            var (tbs, algorithm, signature) = ReadSigned(certificate.RawData, out _);
            return Verify(tbs.Span, algorithm, signature, issuer) == true;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            return false;
        }
    }

    /// X.509 `Time ::= CHOICE { utcTime, generalTime }` — both accepted everywhere (certificates, CRLs, OCSP).
    public static DateTimeOffset ReadTime(AsnReader reader) =>
        reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();

    public static bool IsTime(Asn1Tag tag) =>
        tag.HasSameClassAndValue(Asn1Tag.UtcTime) || tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    public static bool IsContext(Asn1Tag tag, int number) =>
        tag.TagClass == TagClass.ContextSpecific && tag.TagValue == number;

    public static byte[] Hash(string algorithm, ReadOnlySpan<byte> data) => algorithm switch
    {
        Sha1 => SHA1.HashData(data),
        Sha256 => SHA256.HashData(data),
        _ => throw new CryptographicException("Unsupported hash " + algorithm),
    };

    /// RFC 6960 `issuerKeyHash` / ResponderID `byKey`: the hash of the subjectPublicKey BIT STRING value.
    public static byte[] KeyHash(string algorithm, X509Certificate2 certificate) =>
        Hash(algorithm, certificate.PublicKey.EncodedKeyValue.RawData);

    /// Notbefore / notAfter as UTC instants.
    public static DateTimeOffset NotBefore(X509Certificate2 c) => new(c.NotBefore.ToUniversalTime(), TimeSpan.Zero);
    public static DateTimeOffset NotAfter(X509Certificate2 c) => new(c.NotAfter.ToUniversalTime(), TimeSpan.Zero);

    /// notBefore ≤ now ≤ notAfter (both ends inclusive).
    public static bool IsValidAt(X509Certificate2 c, DateTimeOffset now) => NotBefore(c) <= now && now <= NotAfter(c);

    /// The KeyUsage bits that are set (0 = digitalSignature, 1 = nonRepudiation, …, 8 = decipherOnly); null when the
    /// extension is absent or malformed.
    public static IReadOnlySet<int>? KeyUsageBits(X509Certificate2 certificate)
    {
        var ext = certificate.Extensions["2.5.29.15"];
        if (ext is null) return null;
        try
        {
            var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
            var bytes = reader.ReadBitString(out var unused);
            reader.ThrowIfNotEmpty();
            var set = new HashSet<int>();
            for (var i = 0; i < bytes.Length; i++)
            {
                var usable = i == bytes.Length - 1 ? 8 - unused : 8;
                for (var bit = 0; bit < usable; bit++)
                {
                    if ((bytes[i] & (0x80 >> bit)) != 0) set.Add(i * 8 + bit);
                }
            }
            return set;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// Extended key usage OIDs; null when the extension is absent or malformed.
    public static IReadOnlyList<string>? ExtendedKeyUsage(X509Certificate2 certificate)
    {
        var ext = certificate.Extensions["2.5.29.37"];
        if (ext is null) return null;
        try
        {
            var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
            var list = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            var output = new List<string>();
            while (list.HasData) output.Add(list.ReadObjectIdentifier());
            return output;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    public static bool HasEku(X509Certificate2 certificate, string oid) =>
        ExtendedKeyUsage(certificate)?.Contains(oid) == true;

    /// The attributes of an X.509 Name (subject or issuer) in certificate order; null when malformed.
    public static IReadOnlyList<(string Oid, string Value)>? NameAttributes(ReadOnlyMemory<byte> rawName)
    {
        try
        {
            var reader = new AsnReader(rawName, AsnEncodingRules.DER);
            var rdns = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            var output = new List<(string, string)>();
            while (rdns.HasData)
            {
                var set = rdns.ReadSetOf(skipSortOrderValidation: true);
                while (set.HasData)
                {
                    var atv = set.ReadSequence();
                    var oid = atv.ReadObjectIdentifier();
                    output.Add((oid, AttributeString(atv.ReadEncodedValue().Span)));
                    atv.ThrowIfNotEmpty();
                }
            }
            return output;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// UTF8String, PrintableString, IA5String … as UTF-8; BMPString as UTF-16BE; TeletexString as Latin-1.
    private static string AttributeString(ReadOnlySpan<byte> encoded)
    {
        var tag = encoded[0];
        AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out var offset, out var length, out _);
        var content = encoded.Slice(offset, length);
        return tag switch
        {
            0x1E => Encoding.BigEndianUnicode.GetString(content),
            0x14 => Encoding.Latin1.GetString(content),
            _ => Encoding.UTF8.GetString(content),
        };
    }

    /// CN, else «givenName surname», else the whole name — the same rule on macOS.
    public static string DisplayName(ReadOnlyMemory<byte> rawName)
    {
        var attributes = NameAttributes(rawName);
        if (attributes is null) return "—";
        string? First(string oid) => attributes.Where(a => a.Oid == oid).Select(a => a.Value).FirstOrDefault();
        var cn = First("2.5.4.3");
        if (!string.IsNullOrEmpty(cn)) return cn;
        var parts = new[] { First("2.5.4.42"), First("2.5.4.4") }.Where(p => !string.IsNullOrEmpty(p)).ToList();
        if (parts.Count > 0) return string.Join(" ", parts);
        var dn = string.Join(", ", attributes.Select(a => ShortName(a.Oid) + "=" + a.Value));
        return dn.Length == 0 ? "—" : dn;
    }

    public static IReadOnlyList<string> AttributeValues(ReadOnlyMemory<byte> rawName, string oid) =>
        NameAttributes(rawName)?.Where(a => a.Oid == oid).Select(a => a.Value).ToList() ?? [];

    private static string ShortName(string oid) => oid switch
    {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.42" => "G",
        _ => oid,
    };

    /// Serial as uppercase hex, leading zero bytes removed (the same form as on macOS).
    public static string SerialHex(X509Certificate2 certificate)
    {
        var bytes = certificate.SerialNumberBytes.Span;          // big-endian, as encoded
        var start = 0;
        while (start < bytes.Length - 1 && bytes[start] == 0) start++;
        return Convert.ToHexString(bytes[start..]);
    }

    /// Why a CRL (or CRL entry) with these `Extensions` cannot be used — «шалгаж чадсангүй»; null = usable. A delta
    /// CRL, an issuingDistributionPoint, or any critical extension not in <paramref name="known"/>. Malformed input
    /// throws <see cref="AsnContentException"/>.
    public static string? CrlExtensionProblem(AsnReader extensions, IReadOnlyCollection<string> known)
    {
        string? problem = null;
        while (extensions.HasData)
        {
            var ext = extensions.ReadSequence();
            var oid = ext.ReadObjectIdentifier();
            var critical = ext.HasData && ext.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && ext.ReadBoolean();
            ext.ReadOctetString();
            ext.ThrowIfNotEmpty();
            problem ??= oid switch
            {
                DeltaCrlIndicator => "Delta CRL дэмжигдээгүй (бүтэн CRL шаардлагатай)",
                IssuingDistributionPoint => "issuingDistributionPoint-той CRL дэмжигдээгүй",
                _ when critical && !known.Contains(oid) => "CRL-д үл мэдэгдэх critical өргөтгөл байна",
                _ => null,
            };
        }
        return problem;
    }

    /// The OCSP URIs of the Authority Information Access extension (http/https only).
    public static IReadOnlyList<Uri> OcspUris(X509Certificate2 certificate)
    {
        var ext = certificate.Extensions["1.3.6.1.5.5.7.1.1"];
        if (ext is null) return [];
        try
        {
            var aia = new X509AuthorityInformationAccessExtension(ext.RawData, ext.Critical);
            return HttpUris(aia.EnumerateOcspUris());
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            return [];
        }
    }

    /// The full-name URIs of the CRL Distribution Points extension (2.5.29.31, http/https only).
    public static IReadOnlyList<Uri> CrlUris(X509Certificate2 certificate)
    {
        var ext = certificate.Extensions["2.5.29.31"];
        if (ext is null) return [];
        var uris = new List<string>();
        try
        {
            var points = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
            while (points.HasData)
            {
                var point = points.ReadSequence();
                if (!point.HasData || !IsContext(point.PeekTag(), 0)) continue;
                var name = point.ReadSequence(Context0);                     // DistributionPointName (CHOICE)
                if (!name.HasData || !IsContext(name.PeekTag(), 0)) continue;
                var fullName = name.ReadSequence(Context0);                  // fullName [0] GeneralNames
                while (fullName.HasData)
                {
                    var tag = fullName.PeekTag();
                    if (IsContext(tag, 6) && !tag.IsConstructed)
                        uris.Add(fullName.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6)));
                    else
                        fullName.ReadEncodedValue();
                }
            }
        }
        catch (AsnContentException)
        {
            return [];
        }
        return HttpUris(uris);
    }

    private static IReadOnlyList<Uri> HttpUris(IEnumerable<string> values) =>
        values.Select(v => Uri.TryCreate(v, UriKind.Absolute, out var u) ? u : null)
            .Where(u => u is not null && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
            .Select(u => u!)
            .ToList();
}
