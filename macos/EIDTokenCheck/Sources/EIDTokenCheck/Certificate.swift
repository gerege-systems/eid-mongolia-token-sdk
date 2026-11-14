import CryptoKit
import Foundation
import Security

/// The parts of an X.509 certificate the login checks need (RFC 5280). Parsing only — every
/// decision is made by the checks that use it.
public struct ParsedCertificate: Sendable, Equatable {
    public struct Extension: Sendable, Equatable {
        public let oid: [UInt8]
        public let critical: Bool
        /// extnValue content (the DER inside the OCTET STRING).
        public let value: [UInt8]
    }

    public let der: [UInt8]
    /// Raw TBSCertificate — the signed bytes.
    public let tbs: [UInt8]
    public let signatureAlgorithm: [UInt8]
    public let signature: [UInt8]
    /// INTEGER content as encoded.
    public let serial: [UInt8]
    /// Raw issuer / subject Name (full TLV) — compared byte for byte.
    public let issuer: [UInt8]
    public let subject: [UInt8]
    public let notBefore: Date
    public let notAfter: Date
    public let subjectPublicKeyInfo: [UInt8]
    /// subjectPublicKey BIT STRING content (RFC 6960 issuerKeyHash / ResponderID.byKey input).
    public let subjectPublicKey: [UInt8]
    public let extensions: [Extension]

    /// Exactly one DER `Certificate` SEQUENCE spanning all of `der` — no PEM, no PKCS#7, no PFX, no trailing bytes;
    /// otherwise nil. The same structure rules as `Der.IsStrictCertificate` on Windows: definite minimal lengths,
    /// minimal INTEGER serial, DER BOOLEAN (0xFF / 0x00), DER times of real dates, unused-bits 0 in the signature and
    /// key, and nothing in TBSCertificate after subjectPublicKeyInfo but [1], [2], [3] in that order.
    public init?(der: [UInt8]) {
        guard let cert = DER.single(der), cert.tag == DER.Tag.sequence,
              let top = cert.children, top.count == 3, top[0].tag == DER.Tag.sequence,
              let algorithm = DER.algorithmOID(top[1]), let signature = DER.bitStringBytes(top[2]),
              var parts = top[0].children else { return nil }
        if parts.first?.tag == DER.Tag.context(0) { parts.removeFirst() }          // [0] version
        guard parts.count >= 6, parts[0].tag == DER.Tag.integer, DER.isMinimalInteger(parts[0].value),
              parts[1].tag == DER.Tag.sequence, parts[2].tag == DER.Tag.sequence,
              parts[3].tag == DER.Tag.sequence, let validity = parts[3].children, validity.count == 2,
              let notBefore = DER.time(validity[0]), let notAfter = DER.time(validity[1]),
              parts[4].tag == DER.Tag.sequence, parts[5].tag == DER.Tag.sequence,
              let spki = parts[5].children, spki.count == 2, spki[0].tag == DER.Tag.sequence,
              let key = DER.bitStringBytes(spki[1]) else { return nil }
        // issuerUniqueID [1], subjectUniqueID [2], extensions [3] — each optional, in this order, nothing else.
        var optional = Array(parts.dropFirst(6))
        for number: UInt8 in [1, 2] where optional.first.map({ $0.tag & 0x1F == number && $0.tag & 0xC0 == 0x80 }) == true {
            optional.removeFirst()
        }
        var extensions: [Extension] = []
        if let block = optional.first, block.tag == DER.Tag.context(3) {
            optional.removeFirst()
            guard let inner = block.children, inner.count == 1, inner[0].tag == DER.Tag.sequence,
                  let list = inner[0].children else { return nil }
            for item in list {
                guard item.tag == DER.Tag.sequence, let f = item.children, (2...3).contains(f.count),
                      f[0].tag == DER.Tag.oid, DER.isValidOID(f[0].value), let value = f.last,
                      value.tag == DER.Tag.octetString else { return nil }
                var critical = false
                if f.count == 3 {
                    guard let flag = DER.boolean(f[1]) else { return nil }
                    critical = flag
                }
                extensions.append(Extension(oid: f[0].value, critical: critical, value: value.value))
            }
        }
        guard optional.isEmpty else { return nil }
        self.der = der
        self.tbs = top[0].raw
        self.signatureAlgorithm = algorithm
        self.signature = signature
        self.serial = parts[0].value
        self.issuer = parts[2].raw
        self.subject = parts[4].raw
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.subjectPublicKeyInfo = parts[5].raw
        self.subjectPublicKey = key
        self.extensions = extensions
    }

    public func extensionValue(_ oid: [UInt8]) -> [UInt8]? { extensions.first { $0.oid == oid }?.value }

    /// Serial as uppercase hex, leading zero bytes removed.
    public var serialHex: String { DER.normalizedInteger(serial).map { String(format: "%02X", $0) }.joined() }

    public var subjectName: X509Name? { X509Name.parse(subject) }
    public var issuerName: X509Name? { X509Name.parse(issuer) }

    /// OCSP responder URLs from Authority Information Access (id-ad-ocsp, http/https only).
    public var ocspURLs: [URL] {
        guard let value = extensionValue(OID.authorityInfoAccess), let seq = DER.single(value),
              let descriptions = seq.children else { return [] }
        return descriptions.compactMap { d -> URL? in
            guard let f = d.children, f.count == 2, f[0].tag == DER.Tag.oid, f[0].value == OID.accessMethodOCSP else {
                return nil
            }
            return Self.uri(f[1])
        }
    }

    /// CRL URLs from CRL Distribution Points (fullName URIs, http/https only).
    public var crlURLs: [URL] {
        guard let value = extensionValue(OID.crlDistributionPoints), let seq = DER.single(value),
              let points = seq.children else { return [] }
        var out: [URL] = []
        for point in points {
            // DistributionPoint { distributionPoint [0] { fullName [0] GeneralNames } }
            guard let dp = point.children?.first(where: { $0.tag == DER.Tag.context(0) }),
                  let fullName = dp.children?.first(where: { $0.tag == DER.Tag.context(0) }),
                  let names = fullName.children else { continue }
            out += names.compactMap(Self.uri)
        }
        return out
    }

    /// Extended key usage OIDs; nil when the extension is absent or malformed.
    public var extendedKeyUsage: [[UInt8]]? {
        guard let value = extensionValue(OID.extendedKeyUsage), let seq = DER.single(value),
              seq.tag == DER.Tag.sequence, let list = seq.children else { return nil }
        return list.filter { $0.tag == DER.Tag.oid }.map(\.value)
    }

    /// The KeyUsage bits that are set (0 = digitalSignature, 1 = nonRepudiation, …, 8 = decipherOnly); nil when the
    /// extension is absent or malformed.
    public var keyUsageBits: Set<Int>? {
        guard let value = extensionValue(OID.keyUsage), let bits = DER.single(value), bits.tag == DER.Tag.bitString,
              let unused = bits.value.first, unused <= 7, bits.value.count >= 2 || unused == 0 else { return nil }
        let bytes = Array(bits.value.dropFirst())
        var set = Set<Int>()
        for (i, byte) in bytes.enumerated() {
            let usable = i == bytes.count - 1 ? 8 - Int(unused) : 8
            for bit in 0..<usable where byte & (0x80 >> UInt8(bit)) != 0 { set.insert(i * 8 + bit) }
        }
        return set
    }

    /// subjectPublicKeyInfo is id-ecPublicKey on the named curve P-256 (prime256v1).
    public var isP256Key: Bool {
        guard let spki = DER.single(subjectPublicKeyInfo)?.children, spki.count == 2,
              let algorithm = spki[0].children, algorithm.count == 2,
              algorithm[0].tag == DER.Tag.oid, algorithm[1].tag == DER.Tag.oid else { return false }
        return algorithm[0].value == OID.ecPublicKey && algorithm[1].value == OID.prime256v1
    }

    /// The certificate's public key (RSA or EC) through Security.framework.
    public var publicKey: SecKey? {
        guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else { return nil }
        return SecCertificateCopyKey(cert)
    }

    /// true / false = signature of this certificate checked with `issuer`'s key; nil = could not be
    /// checked (unsupported algorithm or unusable key).
    public func isSigned(by issuer: ParsedCertificate) -> Bool? {
        guard let key = issuer.publicKey else { return nil }
        return SignatureVerifier.verify(message: tbs, signature: signature, algorithm: signatureAlgorithm, key: key)
    }

    /// notBefore ≤ date ≤ notAfter (both ends inclusive).
    public func isValid(at date: Date) -> Bool { notBefore <= date && date <= notAfter }

    /// GeneralName uniformResourceIdentifier ([6], 0x86) with an http/https scheme.
    static func uri(_ node: DERNode) -> URL? {
        guard node.tag == 0x86, let text = String(bytes: node.value, encoding: .ascii),
              let url = URL(string: text), let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https", url.host != nil else { return nil }
        return url
    }
}

/// An X.509 Name (subject or issuer): its attributes in certificate order.
public struct X509Name: Sendable, Equatable {
    public struct Attribute: Sendable, Equatable {
        public let oid: [UInt8]
        public let value: String
    }

    public let attributes: [Attribute]

    /// nil when `raw` is not a well-formed Name.
    public static func parse(_ raw: [UInt8]) -> X509Name? {
        guard let name = DER.single(raw), name.tag == DER.Tag.sequence, let rdns = name.children else { return nil }
        var out: [Attribute] = []
        for rdn in rdns {
            guard rdn.tag == DER.Tag.set, let atvs = rdn.children else { return nil }
            for atv in atvs {
                guard atv.tag == DER.Tag.sequence, let kv = atv.children, kv.count == 2, kv[0].tag == DER.Tag.oid else {
                    return nil
                }
                out.append(Attribute(oid: kv[0].value, value: string(kv[1])))
            }
        }
        return X509Name(attributes: out)
    }

    public func values(_ oid: [UInt8]) -> [String] { attributes.filter { $0.oid == oid }.map(\.value) }
    public func first(_ oid: [UInt8]) -> String? { values(oid).first }

    /// CN, else «givenName surname», else the whole name.
    public var displayName: String {
        if let cn = first(OID.commonName), !cn.isEmpty { return cn }
        let parts = [first(OID.givenName), first(OID.surname)].compactMap { $0 }.filter { !$0.isEmpty }
        if !parts.isEmpty { return parts.joined(separator: " ") }
        return distinguishedName.isEmpty ? "—" : distinguishedName
    }

    /// `SERIALNUMBER=…, G=…, SN=…, C=MN` in certificate order (unknown types as dotted OIDs).
    public var distinguishedName: String {
        attributes.map { "\(Self.shortName($0.oid))=\($0.value)" }.joined(separator: ", ")
    }

    static func shortName(_ oid: [UInt8]) -> String {
        switch oid {
        case OID.commonName: return "CN"
        case OID.surname: return "SN"
        case OID.serialNumber: return "SERIALNUMBER"
        case OID.country: return "C"
        case OID.organization: return "O"
        case OID.organizationalUnit: return "OU"
        case OID.givenName: return "G"
        default: return dotted(oid)
        }
    }

    static func dotted(_ oid: [UInt8]) -> String {
        guard let first = oid.first else { return "" }
        var parts = [Int(first) / 40, Int(first) % 40]
        var acc = 0
        for b in oid.dropFirst() {
            acc = acc << 7 | Int(b & 0x7F)
            if b & 0x80 == 0 { parts.append(acc); acc = 0 }
        }
        return parts.map(String.init).joined(separator: ".")
    }

    static func string(_ node: DERNode) -> String {
        switch node.tag {
        case DER.Tag.bmpString:                                          // UTF-16BE
            var units: [UInt16] = []
            var i = 0
            while i + 1 < node.value.count { units.append(UInt16(node.value[i]) << 8 | UInt16(node.value[i + 1])); i += 2 }
            return String(decoding: units, as: UTF16.self)
        case DER.Tag.teletexString:
            return String(bytes: node.value, encoding: .isoLatin1) ?? ""
        default:
            return String(decoding: node.value, as: UTF8.self)
        }
    }
}

/// Signature algorithm OIDs → Security.framework verification.
public enum SignatureVerifier {
    public static func algorithm(for oid: [UInt8]) -> SecKeyAlgorithm? {
        switch oid {
        case OID.sha256WithRSA: return .rsaSignatureMessagePKCS1v15SHA256
        case OID.sha384WithRSA: return .rsaSignatureMessagePKCS1v15SHA384
        case OID.sha512WithRSA: return .rsaSignatureMessagePKCS1v15SHA512
        case OID.ecdsaWithSHA256: return .ecdsaSignatureMessageX962SHA256
        case OID.ecdsaWithSHA384: return .ecdsaSignatureMessageX962SHA384
        case OID.ecdsaWithSHA512: return .ecdsaSignatureMessageX962SHA512
        default: return nil
        }
    }

    /// true / false = verified / not; nil = algorithm not supported here (or not usable with `key`).
    public static func verify(message: [UInt8], signature: [UInt8], algorithm oid: [UInt8], key: SecKey) -> Bool? {
        guard let algorithm = algorithm(for: oid), SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            return nil
        }
        return SecKeyVerifySignature(key, algorithm, Data(message) as CFData, Data(signature) as CFData, nil)
    }

    /// ECDSA P-256 over a 32-byte digest: raw r‖s (64 bytes) with the uncompressed point `04‖X‖Y`. Internal: the
    /// login digest is always computed by `LoginChallenge` from (origin, challenge) — never taken from a caller.
    static func verifyP256(point: [UInt8], digest: [UInt8], rawSignature: [UInt8]) -> Bool {
        guard point.count == 65, point.first == 0x04, digest.count == 32, rawSignature.count == 64,
              let der = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature).derRepresentation else {
            return false
        }
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                           kSecAttrKeyClass: kSecAttrKeyClassPublic,
                                           kSecAttrKeySizeInBits: 256]
        guard let key = SecKeyCreateWithData(Data(point) as CFData, attributes as CFDictionary, nil) else { return false }
        return SecKeyVerifySignature(key, .ecdsaSignatureDigestX962SHA256, Data(digest) as CFData, der as CFData, nil)
    }
}
