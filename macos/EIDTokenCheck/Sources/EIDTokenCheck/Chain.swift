import CryptoKit
import Foundation
import Security

/// A certificate file in `trust/` (or a certificate given to `TrustStore`) is not one strict DER certificate.
public enum TrustStoreError: Error, Equatable, LocalizedError {
    case notACertificate(String)

    public var errorDescription: String? {
        switch self {
        case .notACertificate(let what): return "trust/: \(what) нь нэг хатуу DER гэрчилгээ биш"
        }
    }
}

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

    /// The issuing CA is the intermediate whose SHA-256 is `issuingCASHA256` — the pin cannot be replaced from
    /// outside this module. Every certificate must be one strict DER certificate (`ParsedCertificate`); anything else
    /// throws — a broken trust folder is never silently ignored (the same on Windows).
    public init(anchors: [[UInt8]], intermediates: [[UInt8]]) throws {
        for (i, der) in (anchors + intermediates).enumerated() where ParsedCertificate(der: der) == nil {
            throw TrustStoreError.notACertificate("certificate #\(i + 1)")
        }
        self.init(anchors: anchors, intermediates: intermediates,
                  issuingCA: intermediates.first { Self.sha256Hex($0) == Self.issuingCASHA256 })
    }

    /// Tests only (internal): another issuing CA. It must be one of `intermediates` (byte for byte), otherwise it is
    /// dropped.
    init(anchors: [[UInt8]], intermediates: [[UInt8]], issuingCA: [UInt8]?) {
        let usableIntermediates = intermediates.filter { ParsedCertificate(der: $0) != nil }
        self.anchors = anchors.filter { ParsedCertificate(der: $0) != nil }
        self.intermediates = usableIntermediates
        self.issuingCA = issuingCA.flatMap { ca in usableIntermediates.contains(ca) ? ca : nil }
    }

    /// `<directory>/anchors/*` and `<directory>/intermediates/*` (.pem, .cer, .crt, .der; other files are not
    /// read); the issuing CA is the intermediate whose SHA-256 is `issuingCASHA256`. A missing folder gives an empty
    /// list (the chain check then reports it); a certificate file that cannot be read, holds no certificate, or holds
    /// anything that is not one strict DER certificate throws `TrustStoreError` naming the file.
    public static func load(directory: URL) throws -> TrustStore {
        func read(_ sub: String) throws -> [[UInt8]] {
            let dir = directory.appendingPathComponent(sub, isDirectory: true)
            let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
            var out: [[UInt8]] = []
            for url in files.filter({ ["pem", "cer", "crt", "der"].contains($0.pathExtension.lowercased()) })
                .sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                let name = "\(sub)/\(url.lastPathComponent)"
                guard let data = try? Data(contentsOf: url) else { throw TrustStoreError.notACertificate(name) }
                let found = certificates(in: data)
                guard let found, !found.isEmpty, found.allSatisfy({ ParsedCertificate(der: $0) != nil }) else {
                    throw TrustStoreError.notACertificate(name)
                }
                out += found
            }
            return out
        }
        return try TrustStore(anchors: read("anchors"), intermediates: read("intermediates"))
    }

    public static func sha256Hex(_ der: [UInt8]) -> String {
        SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }

    /// PEM (one or more CERTIFICATE blocks) or a single DER certificate; nil when a PEM block is not valid base64 or
    /// is not closed.
    public static func certificates(in data: Data) -> [[UInt8]]? {
        let begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----"
        guard let text = String(data: data, encoding: .utf8), text.contains(begin) else { return [[UInt8](data)] }
        var out: [[UInt8]] = []
        for block in text.components(separatedBy: begin).dropFirst() {
            guard let stop = block.range(of: end) else { return nil }
            let base64 = block[..<stop.lowerBound].filter { !$0.isWhitespace }
            guard let der = Data(base64Encoded: String(base64)) else { return nil }
            out.append([UInt8](der))
        }
        return out
    }

    /// The pinned issuing CA when it issued `cert` (subject = issuer name AND its key verifies the signature).
    public func issuingCA(of cert: ParsedCertificate) -> ParsedCertificate? {
        guard let der = issuingCA, let ca = ParsedCertificate(der: der),
              ca.subject == cert.issuer, cert.isSigned(by: ca) == true else { return nil }
        return ca
    }

    /// The CA path from `start` upwards through THIS store only (subject = issuer name AND signature), ending at an
    /// anchor when one is reached. Never looks at a keychain or the network.
    func caPath(from start: ParsedCertificate) -> [ParsedCertificate] {
        let pool = (intermediates + anchors).compactMap { ParsedCertificate(der: $0) }
        var path = [start]
        while let current = path.last, !anchors.contains(current.der), path.count <= pool.count {
            guard let parent = pool.first(where: {
                $0.subject == current.issuer && !path.contains($0) && current.isSigned(by: $0) == true
            }) else { break }
            path.append(parent)
        }
        return path
    }
}

/// «Гэрчилгээний гинж» and «Хүчинтэй хугацаа».
public enum ChainCheck {
    /// The same decision, in the same order, as `LoginVerifier.Chain` on Windows:
    ///
    ///  1. the CA path above the AUTH certificate is taken from `trust/` only, starting at the PINNED 04: each CA on
    ///     it must be within its validity period (an expired CA fails HERE) and the path must reach a bundled anchor;
    ///  2. Security.framework evaluates the AUTH certificate (basic X.509 policy, ONLY the bundled anchors — never the
    ///     system trust store — no network fetch), every certificate of its path valid at the instant below (the same
    ///     time rule as Windows). macOS has no way to keep it from also looking at keychain intermediates
    ///     (`SecTrustSetKeychains` has been a no-op since 10.12), so the platform's path may run through another copy
    ///     of 04 (same subject and key): it then checks the AUTH certificate's signature with that copy's (identical)
    ///     key and applies that copy's constraints. The path is accepted only when
    ///  3. element [1] of the platform's path has the SAME subject AND the SAME public key as the pinned 04. From here
    ///     on only the pinned 04 is used: the validity / path check from `trust/` (1), issuer identification
    ///     (`TrustStore.issuingCA(of:)`) and the OCSP / CRL verification;
    ///  4. the AUTH profile (`authProfileProblem`).
    ///
    /// The returned chain is the AUTH certificate followed by the pinned path (pinned 04 DER first) — what the
    /// validity check and the issuing CA's revocation check use. The issuing CA's own revocation is added by
    /// `LoginVerifier` (it needs the network). Everything is judged at `now` clamped into the AUTH certificate's
    /// validity period, so that an expired AUTH certificate is reported by the validity check, not here.
    public static func chain(leaf: ParsedCertificate, trust: TrustStore,
                             now: Date) -> (result: CheckResult, chain: [ParsedCertificate]) {
        guard !trust.anchors.isEmpty else {
            return (CheckResult(.chain, .unavailable, "Итгэлийн үндэс (trust anchor) апп-д алга"), [leaf])
        }
        guard let pinnedDER = trust.issuingCA, let pinned = ParsedCertificate(der: pinnedDER) else {
            return (CheckResult(.chain, .unavailable, "Олгогч CA (04) апп-д алга"), [leaf])
        }
        let notTrusted = CheckResult(.chain, .failed, "Итгэмжлэгдсэн үндэс хүртэл гинж баталгаажсангүй")
        let at = min(max(now, leaf.notBefore), leaf.notAfter)
        let cas = trust.caPath(from: pinned)
        if let ca = cas.first(where: { !$0.isValid(at: at) }) {
            return (CheckResult(.chain, .failed, expiredCAReason(ca.subjectName?.displayName ?? "—")), [leaf])
        }
        guard let top = cas.last, trust.anchors.contains(top.der) else { return (notTrusted, [leaf]) }

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
        // The same instant as on Windows / Linux: one second before notAfter when `at` is that very second (OpenSSL
        // treats notAfter as exclusive). The time rules themselves are this code's (step 1 and the validity check).
        SecTrustSetVerifyDate(secTrust, platformInstant(at, notBefore: leaf.notBefore, notAfter: leaf.notAfter) as CFDate)
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(secTrust, &error)
        let built = ((SecTrustCopyCertificateChain(secTrust) as? [SecCertificate]) ?? [])
            .compactMap { ParsedCertificate(der: [UInt8](SecCertificateCopyData($0) as Data)) }
        guard trusted, built.count >= 2, built[0].der == leaf.der, let root = built.last,
              trust.anchors.contains(root.der) else {
            return (notTrusted, [leaf])
        }
        guard built[1].subject == pinned.subject, built[1].subjectPublicKeyInfo == pinned.subjectPublicKeyInfo else {
            return (CheckResult(.chain, .failed, "Гэрчилгээг eID Mongolia Issuing CA (04) шууд олгоогүй"), [leaf])
        }
        let chain = [leaf] + cas
        if let problem = authProfileProblem(leaf) {
            return (CheckResult(.chain, .failed, problem), chain)
        }
        let names = chain.map { $0.subjectName?.displayName ?? "—" }
        return (CheckResult(.chain, .passed, names.joined(separator: " → ")), chain)
    }

    /// The instant the platform evaluates the path at: `at`, or one second before the AUTH certificate's notAfter
    /// when `at` is that very second (the same rule on Windows / Linux).
    static func platformInstant(_ at: Date, notBefore: Date, notAfter: Date) -> Date {
        at >= notAfter && notAfter - 1 >= notBefore ? notAfter - 1 : at
    }

    /// «Гинжний гэрчилгээ (‹нэр›) хүчинтэй хугацаанаас гадуур» — the same text in the chain and validity rows.
    static func expiredCAReason(_ name: String) -> String { "Гинжний гэрчилгээ (\(name)) хүчинтэй хугацаанаас гадуур" }

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
            return CheckResult(.validity, .failed, expiredCAReason(ca.subjectName?.displayName ?? "—"))
        }
        return CheckResult(.validity, .passed,
                           "\(DisplayDate.string(leaf.notBefore)) – \(DisplayDate.string(leaf.notAfter))")
    }
}
