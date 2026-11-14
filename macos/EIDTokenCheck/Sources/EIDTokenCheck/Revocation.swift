import CryptoKit
import Foundation
import Security

// MARK: - OCSP (RFC 6960)

/// «OCSP»: request for one certificate, then the response decision. The responder URL comes from the
/// certificate's own AIA; the response must be signed by the issuing CA itself or by a responder certificate that
/// the same CA issued for OCSP signing (id-kp-OCSPSigning, within its validity period). The same code checks the
/// AUTH certificate (issuer 04, nonce REQUIRED) and the issuing CA certificate itself (issuer 03, nonce optional —
/// those answers are pre-signed and carry no nonce).
public enum OCSPCheck {
    public static let contentType = "application/ocsp-request"
    public static let accept = "application/ocsp-response"
    public static let nonceLength = 32

    /// A fresh 32-byte nonce; nil only when the system random generator fails.
    public static func newNonce() -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: nonceLength)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        return bytes
    }

    /// DER OCSPRequest for one certificate (CertID with SHA-256) with the nonce extension (RFC 8954):
    /// OCSPRequest { TBSRequest { requestList { Request { CertID } }, requestExtensions [2] { nonce } } }.
    public static func request(leaf: ParsedCertificate, issuer: ParsedCertificate, nonce: [UInt8]) -> [UInt8] {
        let request = DER.tlv(DER.Tag.sequence, certID(leaf: leaf, issuer: issuer))
        let requestList = DER.tlv(DER.Tag.sequence, request)
        let nonceExtension = DER.tlv(DER.Tag.sequence, DER.tlv(DER.Tag.oid, OID.ocspNonce) + DER.tlv(DER.Tag.octetString, nonceValue(nonce)))
        let extensions = DER.tlv(DER.Tag.context(2), DER.tlv(DER.Tag.sequence, nonceExtension))
        let tbsRequest = DER.tlv(DER.Tag.sequence, requestList + extensions)
        return DER.tlv(DER.Tag.sequence, tbsRequest)
    }

    /// The nonce extension's extnValue: the nonce as a DER OCTET STRING.
    static func nonceValue(_ nonce: [UInt8]) -> [UInt8] { DER.tlv(DER.Tag.octetString, nonce) }

    /// CertID { hashAlgorithm sha256, issuerNameHash, issuerKeyHash, serialNumber }.
    public static func certID(leaf: ParsedCertificate, issuer: ParsedCertificate) -> [UInt8] {
        let algorithm = DER.tlv(DER.Tag.sequence, DER.tlv(DER.Tag.oid, OID.sha256) + [DER.Tag.null, 0x00])
        return DER.tlv(DER.Tag.sequence,
                       algorithm
                       + DER.tlv(DER.Tag.octetString, hash(OID.sha256, issuer.subject) ?? [])
                       + DER.tlv(DER.Tag.octetString, hash(OID.sha256, issuer.subjectPublicKey) ?? [])
                       + DER.tlv(DER.Tag.integer, leaf.serial))
    }

    /// CertID hashes: SHA-1 or SHA-256 only; anything else never matches.
    static func hash(_ algorithm: [UInt8], _ data: [UInt8]) -> [UInt8]? {
        switch algorithm {
        case OID.sha1: return Array(Insecure.SHA1.hash(data: data))
        case OID.sha256: return Array(SHA256.hash(data: data))
        default: return nil
        }
    }

    /// Decision on a DER OCSPResponse for `leaf` (issued by `issuer`) at `now`. `nonce` = what the request carried.
    /// `nonceRequired`: the response MUST echo it (AUTH certificate); otherwise an echoed nonce must still match.
    ///
    /// Order (the same on Windows): responseStatus → response type → structure → signer (issuer or delegated
    /// responder: issued by the issuer, id-kp-OCSPSigning, valid now) → signature → nonce → the SingleResponse for
    /// this CertID: revoked → thisUpdate in the future → stale → unknown → good.
    public static func evaluate(response: [UInt8], leaf: ParsedCertificate, issuer: ParsedCertificate,
                                nonce: [UInt8]?, nonceRequired: Bool, now: Date) -> CheckResult {
        func fail(_ s: String) -> CheckResult { CheckResult(.ocsp, .failed, s) }
        func unavailable(_ s: String) -> CheckResult { CheckResult(.ocsp, .unavailable, s) }
        let malformed = fail("OCSP хариу задрахгүй байна")

        // OCSPResponse { responseStatus ENUMERATED, responseBytes [0] EXPLICIT { responseType, response } }
        guard let outer = DER.single(response), outer.tag == DER.Tag.sequence, let top = outer.children,
              let status = top.first, status.tag == DER.Tag.enumerated, status.value.count == 1 else { return malformed }
        guard status.value == [0] else {
            return unavailable("OCSP responder амжилтгүй хариу өгсөн (responseStatus \(status.value[0]))")
        }
        guard top.count == 2, top[1].tag == DER.Tag.context(0), let wrapped = top[1].children, wrapped.count == 1,
              let rb = wrapped[0].children, rb.count == 2, rb[0].tag == DER.Tag.oid, rb[1].tag == DER.Tag.octetString else {
            return malformed
        }
        guard rb[0].value == OID.ocspBasicResponse else { return unavailable("OCSP хариуны төрөл дэмжигдээгүй") }

        // BasicOCSPResponse { tbsResponseData, signatureAlgorithm, signature, certs [0] EXPLICIT OPTIONAL }
        guard let basic = DER.single(rb[1].value), basic.tag == DER.Tag.sequence, let b = basic.children,
              b.count == 3 || b.count == 4, b[0].tag == DER.Tag.sequence, let sigAlg = DER.algorithmOID(b[1]),
              let signature = DER.bitStringBytes(b[2]), var data = b[0].children else {
            return malformed
        }
        var embedded: [ParsedCertificate] = []
        if b.count == 4 {
            guard b[3].tag == DER.Tag.context(0), let certs = b[3].children?.first?.children else { return malformed }
            for cert in certs {
                guard let parsed = ParsedCertificate(der: cert.raw) else { return malformed }
                embedded.append(parsed)
            }
        }

        // ResponseData { version [0] OPTIONAL, responderID, producedAt, responses, extensions [1] OPTIONAL }
        if data.first?.tag == DER.Tag.context(0) { data.removeFirst() }
        guard data.count == 3 || data.count == 4, DER.isTime(data[1].tag), DER.time(data[1]) != nil,
              data[2].tag == DER.Tag.sequence, let singles = data[2].children else {
            return malformed
        }
        var echoedNonce: [UInt8]?
        if data.count == 4 {
            guard data[3].tag == DER.Tag.context(1), let list = data[3].children?.first?.children,
                  let headers = Extensions.parse(list) else { return malformed }
            echoedNonce = headers.first { $0.oid == OID.ocspNonce }?.value
        }

        // Who signed it.
        guard let signer = responder(data[0], candidates: [issuer] + embedded) else {
            return fail("OCSP хариуг хэн зурсан нь тодорхойгүй (responderID таарахгүй)")
        }
        if signer != issuer {
            guard signer.issuer == issuer.subject, signer.isSigned(by: issuer) == true else {
                return fail("OCSP responder-ийн гэрчилгээг энэ гэрчилгээний олгогч олгоогүй")
            }
            guard signer.extendedKeyUsage?.contains(OID.ekuOCSPSigning) == true else {
                return fail("OCSP responder-ийн гэрчилгээнд id-kp-OCSPSigning алга")
            }
            guard signer.isValid(at: now) else {
                return fail("OCSP responder-ийн гэрчилгээ хүчинтэй хугацаанаас гадуур")
            }
        }
        guard let key = signer.publicKey else { return unavailable("OCSP хариуны гарын үсгийн алгоритм дэмжигдээгүй") }
        switch SignatureVerifier.verify(message: b[0].raw, signature: signature, algorithm: sigAlg, key: key) {
        case .none: return unavailable("OCSP хариуны гарын үсгийн алгоритм дэмжигдээгүй")
        case .some(false): return fail("OCSP хариуны гарын үсэг буруу")
        case .some(true): break
        }

        if let echoedNonce {
            guard let nonce, echoedNonce == nonceValue(nonce) || echoedNonce == nonce else {
                return fail("OCSP хариуны nonce манай хүсэлтийнхтэй таарахгүй")
            }
        } else if nonceRequired {
            return fail("OCSP хариунд nonce алга (AUTH гэрчилгээнд заавал)")
        }

        // The SingleResponse for this certificate (same serial AND same issuer hashes, SHA-1 or SHA-256).
        let serial = DER.normalizedInteger(leaf.serial)
        for single in singles {
            guard let s = single.children, s.count >= 3, let certID = s[0].children, certID.count == 4,
                  let hashAlg = DER.algorithmOID(certID[0]), certID[3].tag == DER.Tag.integer,
                  DER.normalizedInteger(certID[3].value) == serial else { continue }
            guard let nameHash = hash(hashAlg, issuer.subject), let keyHash = hash(hashAlg, issuer.subjectPublicKey),
                  certID[1].value == nameHash, certID[2].value == keyHash else { continue }
            guard let thisUpdate = DER.time(s[2]) else { return malformed }
            var nextUpdate: Date?
            if s.count >= 4, s[3].tag == DER.Tag.context(0) {
                guard let n = s[3].children?.first.flatMap(DER.time) else { return malformed }
                nextUpdate = n
            }
            let window = "thisUpdate \(DisplayDate.string(thisUpdate))"
                + (nextUpdate.map { ", nextUpdate \(DisplayDate.string($0))" } ?? "")
            if s[1].tag == 0xA1 {                                        // revoked: cancellation never expires
                let at = s[1].children?.first.flatMap(DER.time).map { " (\(DisplayDate.string($0)))" } ?? ""
                return fail("Гэрчилгээ цуцлагдсан" + at)
            }
            guard s[1].tag == 0x80 || s[1].tag == 0x82 else { return malformed }
            if Freshness.isFuture(thisUpdate: thisUpdate, now: now) {
                return fail("OCSP хариу ирээдүйн огноотой (\(window))")
            }
            if Freshness.isStale(thisUpdate: thisUpdate, nextUpdate: nextUpdate, now: now) {
                return fail("OCSP хариу хуучирсан (\(window))")
            }
            if s[1].tag == 0x82 { return fail("OCSP: unknown — responder энэ гэрчилгээг танихгүй") }
            return CheckResult(.ocsp, .passed, "good (\(window))")
        }
        return fail("OCSP хариунд энэ гэрчилгээний төлөв алга (CertID таарахгүй)")
    }

    /// The candidate named by ResponderID: byName [1] = subject Name, byKey [2] = SHA-1 of the key.
    static func responder(_ id: DERNode, candidates: [ParsedCertificate]) -> ParsedCertificate? {
        switch id.tag {
        case DER.Tag.context(1):
            guard let name = id.children?.first else { return nil }
            return candidates.first { $0.subject == name.raw }
        case DER.Tag.context(2):
            guard let keyHash = id.children?.first, keyHash.tag == DER.Tag.octetString else { return nil }
            return candidates.first { hash(OID.sha1, $0.subjectPublicKey) == keyHash.value }
        default:
            return nil
        }
    }
}

// MARK: - Extensions

/// `Extensions ::= SEQUENCE OF Extension { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
enum Extensions {
    struct Header {
        let oid: [UInt8]
        let critical: Bool
        let value: [UInt8]
    }

    /// nil when malformed.
    static func parse(_ list: [DERNode]) -> [Header]? {
        var out: [Header] = []
        for item in list {
            guard item.tag == DER.Tag.sequence, let f = item.children, (2...3).contains(f.count), f[0].tag == DER.Tag.oid,
                  f.last?.tag == DER.Tag.octetString else { return nil }
            var critical = false
            if f.count == 3 {
                guard f[1].tag == DER.Tag.boolean, f[1].value.count == 1 else { return nil }
                critical = f[1].value[0] != 0
            }
            out.append(Header(oid: f[0].value, critical: critical, value: f[f.count - 1].value))
        }
        return out
    }

    /// Why a CRL (or CRL entry) with these extensions cannot be used — «шалгаж чадсангүй»; nil = usable.
    /// A delta CRL, an issuingDistributionPoint, or any critical extension not in `known`.
    static func crlProblem(_ headers: [Header], known: [[UInt8]]) -> String? {
        for h in headers {
            if h.oid == OID.deltaCRLIndicator { return "Delta CRL дэмжигдээгүй (бүтэн CRL шаардлагатай)" }
            if h.oid == OID.issuingDistributionPoint { return "issuingDistributionPoint-той CRL дэмжигдээгүй" }
            if h.critical && !known.contains(h.oid) { return "CRL-д үл мэдэгдэх critical өргөтгөл байна" }
        }
        return nil
    }
}

// MARK: - CRL (RFC 5280 §5)

/// «CRL»: the list from the certificate's own CDP must be issued and signed by the same CA that issued the
/// certificate, carry nextUpdate, be current (5 min skew), be a full CRL without an issuingDistributionPoint or
/// unknown critical extensions, and not list the certificate's serial.
///
/// Order (the same on Windows): structure → issuer → signature → CRL extensions → nextUpdate present →
/// thisUpdate in the future → stale → entries (entry extensions, then the serial).
public enum CRLCheck {
    public static let accept = "application/pkix-crl"

    static let knownCRLExtensions = [OID.authorityKeyIdentifier, OID.crlNumber]
    static let knownEntryExtensions = [OID.reasonCode, OID.invalidityDate]

    public static func evaluate(crl: [UInt8], leaf: ParsedCertificate, issuer: ParsedCertificate,
                                now: Date) -> CheckResult {
        func fail(_ s: String) -> CheckResult { CheckResult(.crl, .failed, s) }
        func unavailable(_ s: String) -> CheckResult { CheckResult(.crl, .unavailable, s) }
        let malformed = fail("CRL задрахгүй байна")

        // CertificateList { tbsCertList, signatureAlgorithm, signatureValue }
        guard let list = DER.single(crl), list.tag == DER.Tag.sequence, let top = list.children, top.count == 3,
              top[0].tag == DER.Tag.sequence, let sigAlg = DER.algorithmOID(top[1]),
              let signature = DER.bitStringBytes(top[2]), var parts = top[0].children else {
            return malformed
        }
        // TBSCertList { version OPTIONAL, signature, issuer, thisUpdate, nextUpdate OPTIONAL,
        //               revokedCertificates OPTIONAL, crlExtensions [0] OPTIONAL }
        if parts.first?.tag == DER.Tag.integer { parts.removeFirst() }
        guard parts.count >= 3, DER.algorithmOID(parts[0]) == sigAlg, parts[1].tag == DER.Tag.sequence,
              let thisUpdate = DER.time(parts[2]) else { return malformed }
        var i = 3
        var nextUpdate: Date?
        if i < parts.count, DER.isTime(parts[i].tag) {
            guard let n = DER.time(parts[i]) else { return malformed }
            nextUpdate = n
            i += 1
        }
        var revoked: [DERNode] = []
        if i < parts.count, parts[i].tag == DER.Tag.sequence {
            guard let entries = parts[i].children else { return malformed }
            revoked = entries
            i += 1
        }
        var extensions: [Extensions.Header] = []
        if i < parts.count, parts[i].tag == DER.Tag.context(0) {
            guard let wrapped = parts[i].children, wrapped.count == 1, wrapped[0].tag == DER.Tag.sequence,
                  let items = wrapped[0].children, let headers = Extensions.parse(items) else { return malformed }
            extensions = headers
            i += 1
        }
        guard i == parts.count else { return malformed }

        guard parts[1].raw == issuer.subject, parts[1].raw == leaf.issuer else {
            return fail("CRL-ийг энэ гэрчилгээний олгогч гаргаагүй")
        }
        guard let key = issuer.publicKey else { return unavailable("CRL-ийн гарын үсгийн алгоритм дэмжигдээгүй") }
        switch SignatureVerifier.verify(message: top[0].raw, signature: signature, algorithm: sigAlg, key: key) {
        case .none: return unavailable("CRL-ийн гарын үсгийн алгоритм дэмжигдээгүй")
        case .some(false): return fail("CRL-ийн гарын үсэг олгогчийн түлхүүртэй таарахгүй")
        case .some(true): break
        }
        if let problem = Extensions.crlProblem(extensions, known: knownCRLExtensions) { return unavailable(problem) }
        guard let next = nextUpdate else { return unavailable("CRL-д nextUpdate алга — шинэ эсэхийг тогтоох боломжгүй") }
        let window = "thisUpdate \(DisplayDate.string(thisUpdate)), nextUpdate \(DisplayDate.string(next))"
        if Freshness.isFuture(thisUpdate: thisUpdate, now: now) { return fail("CRL ирээдүйн огноотой (\(window))") }
        if Freshness.isStale(thisUpdate: thisUpdate, nextUpdate: next, now: now) { return fail("CRL хуучирсан (\(window))") }

        let serial = DER.normalizedInteger(leaf.serial)
        for entry in revoked {
            // revokedCertificate { userCertificate, revocationDate, crlEntryExtensions OPTIONAL }
            guard entry.tag == DER.Tag.sequence, let fields = entry.children, (2...3).contains(fields.count),
                  fields[0].tag == DER.Tag.integer, let at = DER.time(fields[1]) else { return malformed }
            if fields.count == 3 {
                guard fields[2].tag == DER.Tag.sequence, let items = fields[2].children,
                      let headers = Extensions.parse(items) else { return malformed }
                if let problem = Extensions.crlProblem(headers, known: knownEntryExtensions) { return unavailable(problem) }
            }
            if DER.normalizedInteger(fields[0].value) == serial {
                return fail("Гэрчилгээ CRL-д цуцлагдсан (\(DisplayDate.string(at)))")
            }
        }
        return CheckResult(.crl, .passed, "Жагсаалтад байхгүй (\(window))")
    }
}

// MARK: - Fetching

public struct RevocationRequest: Sendable, Equatable {
    public let url: URL
    /// POST body (OCSP); nil = GET (CRL).
    public let body: Data?
    public let contentType: String?
    public let accept: String

    public init(url: URL, body: Data?, contentType: String?, accept: String) {
        self.url = url
        self.body = body
        self.contentType = contentType
        self.accept = accept
    }
}

/// Network access for OCSP/CRL — injected so tests never reach a real endpoint. Any error thrown here becomes
/// «шалгаж чадсангүй» in the check.
public protocol RevocationFetcher: Sendable {
    func fetch(_ request: RevocationRequest) async throws -> Data
}

public enum RevocationFetchError: LocalizedError, Equatable {
    case unsupportedURL
    case httpStatus(Int)
    case tooLarge
    case timedOut

    public var errorDescription: String? {
        switch self {
        case .unsupportedURL: return "зөвхөн http/https хаяг зөвшөөрөгдөнө"
        case .httpStatus(let code): return "HTTP \(code)"
        case .tooLarge: return "хариу хэт том"
        case .timedOut: return "хугацаа хэтэрсэн"
        }
    }
}

/// URLSession, ephemeral (no cookies/cache): redirects are not followed (a 3xx is not 200 → error), 10 s for the
/// WHOLE exchange (connection, headers and body), at most 8 MiB counted while reading, HTTP 200 only.
public struct URLSessionRevocationFetcher: RevocationFetcher {
    public static let defaultMaxBytes = 8 << 20
    public static let defaultTimeout: TimeInterval = 10

    let maxBytes: Int
    let timeout: TimeInterval

    public init() { self.init(maxBytes: Self.defaultMaxBytes, timeout: Self.defaultTimeout) }

    /// Smaller limits for tests.
    init(maxBytes: Int, timeout: TimeInterval) {
        self.maxBytes = maxBytes
        self.timeout = timeout
    }

    public func fetch(_ r: RevocationRequest) async throws -> Data {
        guard let scheme = r.url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw RevocationFetchError.unsupportedURL
        }
        let timeout = self.timeout
        // The total deadline is enforced here as well as by URLSession's resource timeout: whichever comes first.
        return try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask { try await self.exchange(r) }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw RevocationFetchError.timedOut
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw RevocationFetchError.timedOut }
            return first
        }
    }

    private func exchange(_ r: RevocationRequest) async throws -> Data {
        var request = URLRequest(url: r.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = r.body == nil ? "GET" : "POST"
        request.httpBody = r.body
        if let contentType = r.contentType { request.setValue(contentType, forHTTPHeaderField: "Content-Type") }
        request.setValue(r.accept, forHTTPHeaderField: "Accept")
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout          // total, not idle
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw RevocationFetchError.httpStatus(code) }
        guard response.expectedContentLength <= Int64(maxBytes) else { throw RevocationFetchError.tooLarge }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maxBytes else { throw RevocationFetchError.tooLarge }
            data.append(byte)
        }
        return data
    }
}

/// Refuses every redirect: the task then completes with the 3xx response itself.
final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}
