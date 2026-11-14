import CryptoKit
import Foundation
import Security

/// Trust material the login check relies on, from the public certificates in `trust/`: `anchors/` are the roots
/// (the only trust anchors), `intermediates/` the CAs between. Root or intermediate is decided by the folder, never
/// by looking at the certificate. Nothing is downloaded — an empty store makes the chain check «шалгаж чадсангүй».
///
/// `issuingCA` is the ONE CA allowed to issue an AUTH certificate directly: eID Mongolia Issuing CA (04), pinned by
/// the SHA-256 of its DER (`issuingCASHA256`). A certificate issued by any other CA under the same root — e.g. a
/// relying-party mTLS certificate with clientAuth from another eID CA — does not pass.
public struct TrustStore: Sendable, Equatable {
    /// SHA-256 of `trust/intermediates/04-eid-mongolia-issuing-ca.pem` (DER), lowercase hex.
    public static let issuingCASHA256 = "87b8db6862abde5e4a07a10c2c696afe5cb6aea072b9f3f9755e73ce79f546fc"

    public let anchors: [[UInt8]]
    public let intermediates: [[UInt8]]
    /// nil when the pinned issuing CA is not among `intermediates`.
    public let issuingCA: [UInt8]?

    /// `issuingCA` must be one of `intermediates` (byte for byte), otherwise it is dropped.
    public init(anchors: [[UInt8]], intermediates: [[UInt8]], issuingCA: [UInt8]?) {
        let usableIntermediates = intermediates.filter { ParsedCertificate(der: $0) != nil }
        self.anchors = anchors.filter { ParsedCertificate(der: $0) != nil }
        self.intermediates = usableIntermediates
        self.issuingCA = issuingCA.flatMap { ca in usableIntermediates.contains(ca) ? ca : nil }
    }

    /// `<directory>/anchors/*` and `<directory>/intermediates/*` (.pem, .cer, .crt, .der); the issuing CA is the
    /// intermediate whose SHA-256 is `issuingCASHA256`. Missing or unreadable files are skipped.
    public static func load(directory: URL) -> TrustStore {
        func read(_ sub: String) -> [[UInt8]] {
            let dir = directory.appendingPathComponent(sub, isDirectory: true)
            let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
            return files
                .filter { ["pem", "cer", "crt", "der"].contains($0.pathExtension.lowercased()) }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
                .flatMap { url in (try? Data(contentsOf: url)).map(certificates(in:)) ?? [] }
        }
        let intermediates = read("intermediates")
        return TrustStore(anchors: read("anchors"), intermediates: intermediates,
                          issuingCA: intermediates.first { sha256Hex($0) == issuingCASHA256 })
    }

    public static func sha256Hex(_ der: [UInt8]) -> String {
        SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }

    /// PEM (one or more CERTIFICATE blocks) or a single DER certificate.
    public static func certificates(in data: Data) -> [[UInt8]] {
        let begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----"
        guard let text = String(data: data, encoding: .utf8), text.contains(begin) else { return [[UInt8](data)] }
        return text.components(separatedBy: begin).dropFirst().compactMap { block in
            guard let stop = block.range(of: end) else { return nil }
            let base64 = block[..<stop.lowerBound].filter { !$0.isWhitespace }
            return Data(base64Encoded: String(base64)).map { [UInt8]($0) }
        }
    }

    /// The pinned issuing CA when it issued `cert` (subject = issuer name AND its key verifies the signature).
    public func issuingCA(of cert: ParsedCertificate) -> ParsedCertificate? {
        guard let der = issuingCA, let ca = ParsedCertificate(der: der),
              ca.subject == cert.issuer, cert.isSigned(by: ca) == true else { return nil }
        return ca
    }
}

/// «Гэрчилгээний гинж» and «Хүчинтэй хугацаа».
public enum ChainCheck {
    /// Path from `leaf` to one of the store's anchors (Security.framework, basic X.509 policy, ONLY the bundled
    /// anchors — never the system trust store — no network fetch); the path's element [1] is the pinned issuing CA
    /// (04); and the AUTH profile (`authProfileProblem`). The issuing CA's own revocation is added by
    /// `LoginVerifier` (it needs the network).
    ///
    /// The path is evaluated at `now` clamped into the leaf's validity period so that an expired certificate is
    /// reported by the validity check, not here. Returns the built chain (leaf first).
    public static func chain(leaf: ParsedCertificate, trust: TrustStore,
                             now: Date) -> (result: CheckResult, chain: [ParsedCertificate]) {
        guard !trust.anchors.isEmpty else {
            return (CheckResult(.chain, .unavailable, "Итгэлийн үндэс (trust anchor) апп-д алга"), [leaf])
        }
        guard let issuingCA = trust.issuingCA else {
            return (CheckResult(.chain, .unavailable, "Олгогч CA (04) апп-д алга"), [leaf])
        }
        guard let leafRef = SecCertificateCreateWithData(nil, Data(leaf.der) as CFData) else {
            return (CheckResult(.chain, .failed, "AUTH гэрчилгээг уншиж чадсангүй"), [leaf])
        }
        let anchors = trust.anchors.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        let intermediates = trust.intermediates.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        var trustRef: SecTrust?
        guard SecTrustCreateWithCertificates(([leafRef] + intermediates) as CFArray, SecPolicyCreateBasicX509(),
                                             &trustRef) == errSecSuccess, let secTrust = trustRef,
              SecTrustSetAnchorCertificates(secTrust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(secTrust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(secTrust, false) == errSecSuccess else {
            return (CheckResult(.chain, .unavailable, "Гинж шалгах орчныг үүсгэж чадсангүй"), [leaf])
        }
        let at = min(max(now, leaf.notBefore), leaf.notAfter)
        SecTrustSetVerifyDate(secTrust, at as CFDate)
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(secTrust, &error)
        let built = ((SecTrustCopyCertificateChain(secTrust) as? [SecCertificate]) ?? [])
            .compactMap { ParsedCertificate(der: [UInt8](SecCertificateCopyData($0) as Data)) }
        let chain = built.isEmpty ? [leaf] : built
        guard trusted, chain.count >= 2, chain[0].der == leaf.der, let root = chain.last,
              trust.anchors.contains(root.der) else {
            return (CheckResult(.chain, .failed, "Итгэмжлэгдсэн үндэс хүртэл гинж баталгаажсангүй"), chain)
        }
        guard chain[1].der == issuingCA else {
            return (CheckResult(.chain, .failed, "Гэрчилгээг eID Mongolia Issuing CA (04) шууд олгоогүй"), chain)
        }
        if let problem = authProfileProblem(leaf) {
            return (CheckResult(.chain, .failed, problem), chain)
        }
        let names = chain.map { $0.subjectName?.displayName ?? "—" }
        return (CheckResult(.chain, .passed, names.joined(separator: " → ")), chain)
    }

    /// The token AUTH certificate profile, identical on macOS and Windows: KeyUsage present with EXACTLY
    /// {digitalSignature}; ExtendedKeyUsage present and containing clientAuth; exactly one subject serialNumber,
    /// starting with `PNOMN-`. A missing extension fails. nil = the profile holds.
    public static func authProfileProblem(_ cert: ParsedCertificate) -> String? {
        guard let bits = cert.keyUsageBits else { return "AUTH профайл: KeyUsage өргөтгөл алга" }
        guard bits == [0] else { return "AUTH профайл: KeyUsage нь зөвхөн digitalSignature байх ёстой" }
        guard let eku = cert.extendedKeyUsage else { return "AUTH профайл: ExtendedKeyUsage өргөтгөл алга" }
        guard eku.contains(OID.ekuClientAuth) else { return "AUTH профайл: ExtendedKeyUsage-д clientAuth алга" }
        let serials = cert.subjectName?.values(OID.serialNumber) ?? []
        guard serials.count == 1, serials[0].hasPrefix("PNOMN-") else {
            return "AUTH профайл: subject serialNumber нь PNOMN- угтвартай ганц утга байх ёстой"
        }
        return nil
    }

    /// Every certificate of the chain is within its validity period at `now` (notBefore ≤ now ≤ notAfter).
    public static func validity(chain: [ParsedCertificate], now: Date) -> CheckResult {
        guard let leaf = chain.first else { return CheckResult(.validity, .unavailable, "Гэрчилгээ алга") }
        if now < leaf.notBefore {
            return CheckResult(.validity, .failed, "Гэрчилгээ \(DisplayDate.string(leaf.notBefore))-аас хүчинтэй болно")
        }
        if now > leaf.notAfter {
            return CheckResult(.validity, .failed, "Гэрчилгээний хугацаа \(DisplayDate.string(leaf.notAfter))-нд дууссан")
        }
        if let ca = chain.dropFirst().first(where: { !$0.isValid(at: now) }) {
            return CheckResult(.validity, .failed,
                               "Гинжний гэрчилгээ (\(ca.subjectName?.displayName ?? "—")) хүчинтэй хугацаанаас гадуур")
        }
        return CheckResult(.validity, .passed,
                           "\(DisplayDate.string(leaf.notBefore)) – \(DisplayDate.string(leaf.notAfter))")
    }
}
