using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

/// A throw-away PKI generated per test: root (≙01) → national (≙02) → intermediate (≙03) → issuing CA (≙04) → leaf, plus
/// a sibling CA (≙05) under the intermediate, all ECDSA P-256. The URLs use the reserved `.invalid` TLD and are only ever
/// answered by <see cref="FakeTransport"/>.
internal sealed class TestPki : IDisposable
{
    public const string OcspUrl = "http://ocsp.test.invalid/ocsp";
    public const string CrlUrl = "http://crl.test.invalid/crl/issuing";
    public const string CaOcspUrl = "http://ocsp-ca.test.invalid/ocsp";
    public const string CaCrlUrl = "http://crl-ca.test.invalid/crl/ca";
    public const string SubjectSerial = "PNOMN-AA00000000";
    public const string Origin = "rp.test.invalid";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag Context1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag Context2 = new(TagClass.ContextSpecific, 2);

    private TestPki(X509Certificate2 root, X509Certificate2 national, X509Certificate2 intermediate, X509Certificate2 issuing,
                    X509Certificate2 organization)
    {
        Root = root;
        National = national;
        Intermediate = intermediate;
        Issuing = issuing;
        Organization = organization;
    }

    /// Whole seconds (certificate times have second precision).
    public static DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    public X509Certificate2 Root { get; }
    public X509Certificate2 National { get; }
    public X509Certificate2 Intermediate { get; }
    public X509Certificate2 Issuing { get; }
    /// ≙05: issues relying-party certificates with clientAuth — never AUTH certificates.
    public X509Certificate2 Organization { get; }

    /// The bundled set: root, 02, 03, 04 (the pinned issuing CA). <paramref name="withOrganization"/> also bundles ≙05.
    public TrustAnchors TrustWith(bool withOrganization)
    {
        var issuing = PublicOnly(Issuing);
        var intermediates = new List<X509Certificate2> { PublicOnly(National), PublicOnly(Intermediate), issuing };
        if (withOrganization) intermediates.Add(PublicOnly(Organization));
        return new TrustAnchors([PublicOnly(Root)], intermediates, issuing);
    }

    public TrustAnchors Trust => TrustWith(false);

    /// <paramref name="caOcsp"/> / <paramref name="caCrl"/>: the issuing CA carries AIA (OCSP) / CDP like the real 04.
    /// <paramref name="intermediateTo"/>: the intermediate CA's (≙03) notAfter (default: in four years).
    public static TestPki Create(string name = "TEST ONLY", bool caOcsp = true, bool caCrl = true,
                                 DateTimeOffset? intermediateTo = null)
    {
        var root = CreateCa(name + " Root CA", null, Now.AddYears(-1), Now.AddYears(5), pathLength: null);
        var national = CreateCa(name + " National Issuing CA", root, Now.AddDays(-365), Now.AddYears(5), pathLength: null);
        var intermediate = CreateCa(name + " Intermediate CA", national, Now.AddDays(-360), intermediateTo ?? Now.AddYears(4),
            pathLength: null);
        var issuing = CreateCa(name + " Issuing CA", intermediate, Now.AddDays(-350), Now.AddYears(3), pathLength: 0,
            ocspUrl: caOcsp ? CaOcspUrl : null, crlUrl: caCrl ? CaCrlUrl : null);
        var organization = CreateCa(name + " Organization Issuing CA", intermediate, Now.AddDays(-350), Now.AddYears(3),
            pathLength: 0, ocspUrl: CaOcspUrl, crlUrl: CaCrlUrl);
        return new TestPki(root, national, intermediate, issuing, organization);
    }

    /// <paramref name="key"/>: the CA's key (default: a new one) — the same key gives another copy of an existing CA.
    public static X509Certificate2 CreateCa(string commonName, X509Certificate2? issuer, DateTimeOffset from, DateTimeOffset to,
                                            int? pathLength, string? ocspUrl = null, string? crlUrl = null, ECDsa? key = null)
    {
        using var ownKey = key is null ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
        key ??= ownKey!;
        var request = new CertificateRequest("CN=" + commonName + ", C=MN", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, pathLength is not null, pathLength ?? 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
        var ski = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        request.CertificateExtensions.Add(ski);
        if (ocspUrl is not null) request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([ocspUrl], null));
        if (crlUrl is not null) request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([crlUrl]));
        if (issuer is null)
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(ski));
            return request.CreateSelfSigned(from, to);
        }
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        // Signed with the issuer's key directly: unlike Create(issuerCertificate, …) this does not refuse a validity
        // period outside the issuer's (needed for the expired-intermediate fixture).
        using var issuerKey = issuer.GetECDsaPrivateKey()!;
        using var cert = request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey), from, to, RandomSerial());
        return cert.CopyWithPrivateKey(key);
    }

    /// An eID-like end-entity certificate. AUTH = digitalSignature + EKU clientAuth + emailProtection + serialNumber
    /// `PNOMN-…` (the token AUTH profile); <paramref name="auth"/> false = the SIGN key usage (digitalSignature +
    /// nonRepudiation) with the SAME clientAuth EKU and serialNumber, so only nonRepudiation tells it apart.
    /// <paramref name="keyUsage"/> / <paramref name="eku"/> false = that extension is absent; <paramref name="usage"/>
    /// overrides the key usage bits; <paramref name="ekus"/> overrides the EKU list; <paramref name="serialNumber"/>
    /// null = no subject serialNumber.
    public X509Certificate2 CreateLeaf(bool auth = true, DateTimeOffset? from = null, DateTimeOffset? to = null,
                                       X509Certificate2? issuer = null, bool withUrls = true, string? ocspUrl = null,
                                       bool keyUsage = true, bool eku = true, X509KeyUsageFlags? usage = null,
                                       string[]? ekus = null, string? serialNumber = SubjectSerial)
    {
        issuer ??= Issuing;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var name = new X500DistinguishedNameBuilder();
        name.AddCountryOrRegion("MN");
        if (serialNumber is not null) name.Add("2.5.4.5", serialNumber, UniversalTagNumber.PrintableString);
        name.AddCommonName("TEST ONLY Citizen");
        var request = new CertificateRequest(name.Build(), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        if (keyUsage)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usage
                ?? (auth ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation), true));
        }
        if (eku)
        {
            var oids = new OidCollection();
            foreach (var oid in ekus ?? ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"]) oids.Add(new Oid(oid));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        }
        if (withUrls)
        {
            request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([ocspUrl ?? OcspUrl], null));
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUrl]));
        }
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        using var cert = request.Create(issuer, from ?? Now.AddDays(-1), to ?? Now.AddDays(365), RandomSerial());
        return cert.CopyWithPrivateKey(key);
    }

    /// Another certificate of the issuing CA's (≙04) subject, issued by ≙03: <paramref name="sameKey"/> = the same key
    /// (a re-issued / legacy copy: same subject and key, different DER), otherwise a new key (same name, other key).
    public X509Certificate2 IssuingCopy(bool sameKey)
    {
        using var key = sameKey ? Issuing.GetECDsaPrivateKey()! : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return CreateCa(Issuing.GetNameInfo(X509NameType.SimpleName, false), Intermediate, Now.AddDays(-100), Now.AddDays(100), 0,
            CaOcspUrl, CaCrlUrl, key);
    }

    /// A delegated OCSP responder certificate issued by <paramref name="issuer"/>.
    public static X509Certificate2 CreateResponder(X509Certificate2 issuer, bool ocspSigning, DateTimeOffset? from = null,
                                                   DateTimeOffset? to = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=TEST ONLY OCSP Responder, C=MN", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        if (ocspSigning)
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.9") }, false));
        }
        using var cert = request.Create(issuer, from ?? Now.AddDays(-1), to ?? Now.AddDays(30), RandomSerial());
        return cert.CopyWithPrivateKey(key);
    }

    /// What CKM_ECDSA on the token does: sign the 32-byte digest it is given, raw r‖s.
    public static Func<byte[], CancellationToken, Task<byte[]>> Signer(X509Certificate2 leaf) => (digest, _) =>
    {
        using var key = leaf.GetECDsaPrivateKey()!;
        return Task.FromResult(key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    };

    /// Raw r‖s over SHA-256("eID-TOKEN-LOGIN-V1" ‖ origin ‖ challenge) — computed here, independently of
    /// <see cref="LoginChallenge"/>.
    public static byte[] Sign(X509Certificate2 leaf, string origin, byte[] challenge)
    {
        byte[] message = [.. Encoding.UTF8.GetBytes("eID-TOKEN-LOGIN-V1"), .. Encoding.UTF8.GetBytes(origin), .. challenge];
        return SignDigest(leaf, SHA256.HashData(message));
    }

    /// The old, unbound construction: raw r‖s over SHA-256(challenge) alone.
    public static byte[] SignBare(X509Certificate2 leaf, byte[] challenge) => SignDigest(leaf, SHA256.HashData(challenge));

    private static byte[] SignDigest(X509Certificate2 leaf, byte[] digest)
    {
        using var key = leaf.GetECDsaPrivateKey()!;
        return key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// A CRL written by hand (the framework's builder always sets nextUpdate): optional nextUpdate, revoked entries,
    /// and one extra CRL extension (content NULL).
    public static byte[] RawCrl(X509Certificate2 issuer, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate,
                                IEnumerable<X509Certificate2>? revoked = null, string? extensionOid = null, bool critical = true,
                                bool generalized = false, byte booleanByte = 0xFF)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(1);
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.2.840.10045.4.3.2");
            }
            w.WriteEncodedValue(issuer.SubjectName.RawData);
            if (generalized) w.WriteGeneralizedTime(thisUpdate, omitFractionalSeconds: true);
            else w.WriteUtcTime(thisUpdate);
            if (nextUpdate is { } next)
            {
                if (generalized) w.WriteGeneralizedTime(next, omitFractionalSeconds: true);
                else w.WriteUtcTime(next);
            }
            var entries = revoked?.ToList() ?? new List<X509Certificate2>();
            if (entries.Count > 0)
            {
                using (w.PushSequence())
                {
                    foreach (var c in entries)
                    {
                        using (w.PushSequence())
                        {
                            w.WriteInteger(c.SerialNumberBytes.Span);
                            w.WriteUtcTime(thisUpdate.AddHours(-1));
                        }
                    }
                }
            }
            if (extensionOid is not null)
            {
                using (w.PushSequence(Context0))
                using (w.PushSequence())
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(extensionOid);
                    if (critical) w.WriteEncodedValue(new byte[] { 0x01, 0x01, booleanByte });
                    w.WriteOctetString([0x05, 0x00]);
                }
            }
        }
        var tbs = w.Encode();
        using var key = issuer.GetECDsaPrivateKey()!;
        var signature = key.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var outer = new AsnWriter(AsnEncodingRules.DER);
        using (outer.PushSequence())
        {
            outer.WriteEncodedValue(tbs);
            using (outer.PushSequence())
            {
                outer.WriteObjectIdentifier("1.2.840.10045.4.3.2");
            }
            outer.WriteBitString(signature);
        }
        return outer.Encode();
    }

    public static byte[] Crl(X509Certificate2 issuer, IEnumerable<X509Certificate2> revoked, DateTimeOffset thisUpdate,
                             DateTimeOffset nextUpdate)
    {
        var builder = new CertificateRevocationListBuilder();
        foreach (var c in revoked) builder.AddEntry(c, thisUpdate.AddHours(-1));
        return builder.Build(issuer, BigInteger.One, nextUpdate, HashAlgorithmName.SHA256, thisUpdate: thisUpdate);
    }

    /// A DER OCSPResponse (successful, BasicOCSPResponse) built like the CA's responder does: responderID byKey.
    /// <paramref name="status"/>: 0 good, 1 revoked, 2 unknown.
    public static byte[] OcspResponse(X509Certificate2 subject, X509Certificate2 issuer, X509Certificate2 signer, int status,
                                      DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate, byte[]? nonceExtValue = null,
                                      bool embedSigner = false, string certIdHash = Der.Sha1,
                                      IEnumerable<byte[]>? otherSingles = null, byte[]? singleSuffix = null)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())                                                   // ResponseData
        {
            using (w.PushSequence(Context2))
            {
                w.WriteOctetString(Der.KeyHash(Der.Sha1, signer));
            }
            w.WriteGeneralizedTime(thisUpdate, omitFractionalSeconds: true);       // producedAt
            using (w.PushSequence())                                               // responses
            {
            foreach (var other in otherSingles ?? []) w.WriteEncodedValue(other);  // entries before ours
            using (w.PushSequence())                                               // SingleResponse
            {
                Ocsp.WriteCertId(w, certIdHash, subject, issuer);
                switch (status)
                {
                    case 0:
                        w.WriteNull(Context0);
                        break;
                    case 1:
                        using (w.PushSequence(Context1))
                        {
                            w.WriteGeneralizedTime(thisUpdate.AddDays(-1), omitFractionalSeconds: true);
                        }
                        break;
                    default:
                        w.WriteNull(Context2);
                        break;
                }
                w.WriteGeneralizedTime(thisUpdate, omitFractionalSeconds: true);
                if (nextUpdate is { } next)
                {
                    using (w.PushSequence(Context0))
                    {
                        w.WriteGeneralizedTime(next, omitFractionalSeconds: true);
                    }
                }
                if (singleSuffix is not null) w.WriteEncodedValue(singleSuffix);
            }
            }
            if (nonceExtValue is not null)
            {
                using (w.PushSequence(Context1))
                using (w.PushSequence())
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(Ocsp.NonceOid);
                    w.WriteOctetString(nonceExtValue);
                }
            }
        }
        var tbs = w.Encode();
        using var key = signer.GetECDsaPrivateKey()!;
        var signature = key.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var basic = new AsnWriter(AsnEncodingRules.DER);
        using (basic.PushSequence())
        {
            basic.WriteEncodedValue(tbs);
            using (basic.PushSequence())
            {
                basic.WriteObjectIdentifier("1.2.840.10045.4.3.2");
            }
            basic.WriteBitString(signature);
            if (embedSigner)
            {
                using (basic.PushSequence(Context0))
                using (basic.PushSequence())
                {
                    basic.WriteEncodedValue(signer.RawData);
                }
            }
        }

        var response = new AsnWriter(AsnEncodingRules.DER);
        using (response.PushSequence())
        {
            response.WriteEncodedValue(new byte[] { 0x0A, 0x01, 0x00 });          // successful
            using (response.PushSequence(Context0))
            using (response.PushSequence())
            {
                response.WriteObjectIdentifier(Ocsp.BasicResponseOid);
                response.WriteOctetString(basic.Encode());
            }
        }
        return response.Encode();
    }

    /// The nonce extension value of an OCSPRequest (what a responder echoes), or null.
    public static byte[]? NonceExtValue(byte[] request)
    {
        var tbs = new AsnReader(request, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        tbs.ReadSequence();                                                       // requestList
        if (!tbs.HasData) return null;
        var extensions = tbs.ReadSequence(Context2).ReadSequence();
        while (extensions.HasData)
        {
            var ext = extensions.ReadSequence();
            if (ext.ReadObjectIdentifier() == Ocsp.NonceOid) return ext.ReadOctetString();
        }
        return null;
    }

    public static X509Certificate2 PublicOnly(X509Certificate2 c) => X509CertificateLoader.LoadCertificate(c.RawData);

    /// <paramref name="der"/> with the first occurrence of <paramref name="old"/> replaced by <paramref name="new"/>
    /// (the same length, so every DER length stays valid).
    public static byte[] ReplaceFirst(byte[] der, byte[] old, byte[] @new)
    {
        Assert.Equal(old.Length, @new.Length);
        var at = der.AsSpan().IndexOf(old);
        Assert.True(at >= 0, "pattern not found");
        var copy = (byte[])der.Clone();
        @new.CopyTo(copy, at);
        return copy;
    }

    /// One encoded TLV.
    public static byte[] Tlv(byte tag, byte[] content)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteOctetString(content);
        var encoded = w.Encode();
        encoded[0] = tag;
        return encoded;
    }

    private static byte[] RandomSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x01);
        return serial;
    }

    public void Dispose()
    {
        Root.Dispose();
        National.Dispose();
        Intermediate.Dispose();
        Issuing.Dispose();
        Organization.Dispose();
    }
}

/// The only "network" the tests have: answers by URL; anything not set up is "offline".
internal sealed class FakeTransport : IRevocationTransport
{
    public Dictionary<string, Func<byte[], byte[]>> Ocsp { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, byte[]> Crls { get; } = new(StringComparer.Ordinal);
    public bool Offline { get; set; }
    /// What an unknown URL throws (default: HttpRequestException "offline").
    public Func<Exception> Failure { get; set; } = () => new HttpRequestException("offline");
    public List<Uri> Requested { get; } = [];

    public Task<byte[]> PostOcspAsync(Uri url, byte[] request, CancellationToken ct)
    {
        Requested.Add(url);
        if (Offline || !Ocsp.TryGetValue(url.AbsoluteUri, out var answer)) throw Failure();
        return Task.FromResult(answer(request));
    }

    public Task<byte[]> GetCrlAsync(Uri url, CancellationToken ct)
    {
        Requested.Add(url);
        if (Offline || !Crls.TryGetValue(url.AbsoluteUri, out var crl)) throw Failure();
        return Task.FromResult(crl);
    }
}
