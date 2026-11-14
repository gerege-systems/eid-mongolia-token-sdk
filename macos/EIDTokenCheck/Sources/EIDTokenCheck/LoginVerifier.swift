import CryptoKit
import Foundation
import Security

/// Challenge binding, version 1. The relying party issues a challenge of EXACTLY 32 random bytes; the token's AUTH
/// key signs
///
///     SHA-256( UTF-8("eID-TOKEN-LOGIN-V1") ‖ UTF-8(origin) ‖ challenge )
///
/// where `origin` is the relying party's own host name (`Origin`). The same AUTH key also serves other login
/// protocols with their own prefixes: a client that signed arbitrary server-supplied bytes could be used to relay a
/// login to another site, so both the prefix and the origin are part of what is signed.
public enum LoginChallenge {
    public static let length = 32
    public static let context = "eID-TOKEN-LOGIN-V1"
    /// The origin field's default in the test apps.
    public static let defaultOrigin = "test.example"

    /// 32 fresh random bytes; nil only when the system random generator fails.
    public static func random() -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: length)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        return bytes
    }

    /// The 32-byte digest the client hands to C_Sign (CKM_ECDSA does not hash). nil when `challenge` is not exactly
    /// 32 bytes or `origin` is not a valid origin (`Origin.isValid`) — then nothing may be signed.
    public static func digestToSign(origin: String, challenge: [UInt8]) -> [UInt8]? {
        guard challenge.count == length, Origin.isValid(origin) else { return nil }
        var hasher = SHA256()
        hasher.update(data: Data(context.utf8))
        hasher.update(data: Data(origin.utf8))
        hasher.update(data: Data(challenge))
        return Array(hasher.finalize())
    }

    static func lengthReason(_ count: Int) -> String { "Challenge \(count) байт (яг \(length) байт байх ёстой)" }

    /// «Challenge-ийн гарын үсэг»: P-256 AUTH key only; raw r‖s of exactly 64 bytes with 1 ≤ r, s < n, verified
    /// over the digest computed HERE from (origin, challenge) — never over a caller-supplied digest.
    static func checkSignature(origin: String, challenge: [UInt8], rawSignature: [UInt8],
                               certificate: ParsedCertificate) -> CheckResult {
        guard challenge.count == length else { return CheckResult(.signature, .failed, lengthReason(challenge.count)) }
        guard let digest = digestToSign(origin: origin, challenge: challenge) else {
            return CheckResult(.signature, .failed, Origin.invalidReason)
        }
        guard certificate.isP256Key else {
            return CheckResult(.signature, .failed, "AUTH гэрчилгээний түлхүүр EC P-256 биш")
        }
        guard rawSignature.count == 64 else {
            return CheckResult(.signature, .failed, "Гарын үсгийн урт \(rawSignature.count) байт (r‖s 64 байт хүлээсэн)")
        }
        guard P256Scalar.isValid(rawSignature[0..<32]), P256Scalar.isValid(rawSignature[32..<64]) else {
            return CheckResult(.signature, .failed, "Гарын үсгийн r эсвэл s хүчингүй (0 эсвэл ≥ n)")
        }
        guard SignatureVerifier.verifyP256(point: certificate.subjectPublicKey, digest: digest, rawSignature: rawSignature) else {
            return CheckResult(.signature, .failed, "Гарын үсэг AUTH гэрчилгээний түлхүүртэй таарахгүй")
        }
        return CheckResult(.signature, .passed, "ECDSA P-256 / SHA-256 (\(context), origin \(origin))")
    }
}

/// ECDSA P-256 signature scalars: 1 ≤ x ≤ n − 1 (32-byte big-endian).
enum P256Scalar {
    static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]

    static func isValid(_ x: ArraySlice<UInt8>) -> Bool {
        guard x.count == 32, x.contains(where: { $0 != 0 }) else { return false }
        return Array(x).lexicographicallyPrecedes(order)
    }
}

/// The relying party's whole decision, made locally — no call to any eID service; the only network traffic is OCSP
/// and CRL at the URLs inside the certificates. The five checks, in this order:
///
///  1. «Challenge-ийн гарын үсэг» — `LoginChallenge.checkSignature`;
///  2. «Гэрчилгээний гинж» — path to the bundled root, issued directly by the pinned 04, AUTH profile, and 04 itself
///     not revoked (OCSP / CRL against 03);
///  3. «Хүчинтэй хугацаа» — every certificate of the path, both ends inclusive;
///  4. «OCSP» — the AUTH certificate at its AIA URL, echoed nonce REQUIRED;
///  5. «CRL» — the AUTH certificate at its CDP URL.
///
/// Fail closed: logged in only when all five pass. Nothing here throws.
public struct LoginVerifier: Sendable {
    public let trust: TrustStore
    public let fetcher: any RevocationFetcher

    public init(trust: TrustStore, fetcher: any RevocationFetcher) {
        self.trust = trust
        self.fetcher = fetcher
    }

    /// The relying party's decision from what the client sent back. `origin` is the relying party's own host name,
    /// `challenge` the 32 bytes it issued; the signed digest is computed here.
    public func verify(origin: String, challenge: [UInt8], signature: [UInt8], certificate: [UInt8],
                       now: Date = Date()) async -> LoginReport {
        guard Origin.isValid(origin) else { return .notStarted(Origin.invalidReason) }
        guard let leaf = ParsedCertificate(der: certificate) else { return .notStarted("AUTH гэрчилгээг уншиж чадсангүй") }
        let signatureCheck = LoginChallenge.checkSignature(origin: origin, challenge: challenge, rawSignature: signature,
                                                           certificate: leaf)
        return await checkAll(leaf: leaf, signature: signatureCheck, now: now)
    }

    /// The test apps' whole login: origin, challenge (exactly 32 bytes), certificate and key type are checked BEFORE
    /// anything is signed; then `sign` is called ONCE with the digest (C_Login + C_Sign on the token). An error from
    /// `sign` makes the signature row «шалгаж чадсангүй» with the error's text; the other checks still run.
    public func run(origin: String, challenge: [UInt8], certificate: [UInt8], now: Date = Date(),
                    sign: ([UInt8]) async throws -> [UInt8]) async -> LoginReport {
        guard Origin.isValid(origin) else { return .notStarted(Origin.invalidReason) }
        guard challenge.count == LoginChallenge.length else { return .notStarted(LoginChallenge.lengthReason(challenge.count)) }
        guard let leaf = ParsedCertificate(der: certificate) else { return .notStarted("AUTH гэрчилгээг уншиж чадсангүй") }
        let signatureCheck: CheckResult
        if !leaf.isP256Key {
            signatureCheck = CheckResult(.signature, .failed, "AUTH гэрчилгээний түлхүүр EC P-256 биш")
        } else if let digest = LoginChallenge.digestToSign(origin: origin, challenge: challenge) {
            do {
                let raw = try await sign(digest)
                signatureCheck = LoginChallenge.checkSignature(origin: origin, challenge: challenge, rawSignature: raw,
                                                               certificate: leaf)
            } catch {
                signatureCheck = CheckResult(.signature, .unavailable, error.localizedDescription)
            }
        } else {
            return .notStarted(Origin.invalidReason)
        }
        return await checkAll(leaf: leaf, signature: signatureCheck, now: now)
    }

    private func checkAll(leaf: ParsedCertificate, signature: CheckResult, now: Date) async -> LoginReport {
        var checks = [signature]
        let chain = ChainCheck.chain(leaf: leaf, trust: trust, now: now)
        checks.append(await withIssuingCARevocation(chain, now: now))
        checks.append(ChainCheck.validity(chain: chain.chain, now: now))
        let issuer = trust.issuingCA(of: leaf)
        checks.append(await ocsp(leaf: leaf, issuer: issuer, nonceRequired: true, now: now))
        checks.append(await crl(leaf: leaf, issuer: issuer, now: now))
        return LoginReport(checks: checks, subjectName: leaf.subjectName?.displayName ?? "—")
    }

    /// «Гэрчилгээний гинж» also covers the issuing CA (chain element [1]) not being revoked: the same OCSP and CRL
    /// code against ITS issuer (element [2]), at the URLs in the CA certificate. The OCSP nonce is optional here (the
    /// CA-level answers are pre-signed). A CA certificate with neither AIA nor CDP → «шалгаж чадсангүй»; with only
    /// one of them, that one decides.
    func withIssuingCARevocation(_ chain: (result: CheckResult, chain: [ParsedCertificate]),
                                 now: Date) async -> CheckResult {
        guard chain.result.status == .passed else { return chain.result }
        guard chain.chain.count >= 3 else {
            return CheckResult(.chain, .unavailable, "Олгогч CA-ийн дээд CA гинжид алга")
        }
        let ca = chain.chain[1], parent = chain.chain[2]
        let caName = ca.subjectName?.displayName ?? "—"
        if ca.ocspURLs.isEmpty && ca.crlURLs.isEmpty {
            return CheckResult(.chain, .unavailable,
                               "Олгогч CA (\(caName))-ийн гэрчилгээнд AIA ч CDP ч алга — цуцлалтыг шалгаж чадсангүй")
        }
        var parts: [CheckResult] = []
        var missing: [String] = []
        if ca.ocspURLs.isEmpty { missing.append("OCSP: AIA алга") } else {
            parts.append(await ocsp(leaf: ca, issuer: parent, nonceRequired: false, now: now))
        }
        if ca.crlURLs.isEmpty { missing.append("CRL: CDP алга") } else {
            parts.append(await crl(leaf: ca, issuer: parent, now: now))
        }
        if let bad = parts.first(where: { $0.status == .failed }) ?? parts.first(where: { $0.status == .unavailable }) {
            return CheckResult(.chain, bad.status, "Олгогч CA (\(caName)) — \(bad.kind.title): \(bad.reason)")
        }
        let summary = parts.map { "\($0.kind.title) ✓" } + missing
        return CheckResult(.chain, .passed,
                           chain.result.reason + "; олгогч CA цуцлагдаагүй (" + summary.joined(separator: ", ") + ")")
    }

    /// OCSP for `leaf` against `issuer` at the AIA URLs of `leaf` (the AUTH certificate or the issuing CA).
    func ocsp(leaf: ParsedCertificate, issuer: ParsedCertificate?, nonceRequired: Bool, now: Date) async -> CheckResult {
        guard let issuer else { return CheckResult(.ocsp, .unavailable, "Олгогч CA (04) апп-д алга") }
        let urls = leaf.ocspURLs
        guard !urls.isEmpty else { return CheckResult(.ocsp, .unavailable, "Гэрчилгээнд OCSP хаяг (AIA) алга") }
        guard let nonce = OCSPCheck.newNonce() else {
            return CheckResult(.ocsp, .unavailable, "Санамсаргүй nonce үүсгэж чадсангүй")
        }
        let body = Data(OCSPCheck.request(leaf: leaf, issuer: issuer, nonce: nonce))
        var lastHost = ""
        for url in urls {
            do {
                let data = try await fetcher.fetch(RevocationRequest(url: url, body: body, contentType: OCSPCheck.contentType,
                                                                     accept: OCSPCheck.accept))
                return OCSPCheck.evaluate(response: [UInt8](data), leaf: leaf, issuer: issuer, nonce: nonce,
                                          nonceRequired: nonceRequired, now: now)
            } catch {
                lastHost = url.host ?? url.absoluteString
            }
        }
        return CheckResult(.ocsp, .unavailable, "OCSP руу холбогдож чадсангүй (\(lastHost))")
    }

    /// CRL for `leaf` against `issuer` at the CDP URLs of `leaf`.
    func crl(leaf: ParsedCertificate, issuer: ParsedCertificate?, now: Date) async -> CheckResult {
        guard let issuer else { return CheckResult(.crl, .unavailable, "Олгогч CA (04) апп-д алга") }
        let urls = leaf.crlURLs
        guard !urls.isEmpty else { return CheckResult(.crl, .unavailable, "Гэрчилгээнд CRL хаяг (CDP) алга") }
        var lastHost = ""
        for url in urls {
            do {
                let data = try await fetcher.fetch(RevocationRequest(url: url, body: nil, contentType: nil,
                                                                     accept: CRLCheck.accept))
                return CRLCheck.evaluate(crl: [UInt8](data), leaf: leaf, issuer: issuer, now: now)
            } catch {
                lastHost = url.host ?? url.absoluteString
            }
        }
        return CheckResult(.crl, .unavailable, "CRL татаж чадсангүй (\(lastHost))")
    }
}
