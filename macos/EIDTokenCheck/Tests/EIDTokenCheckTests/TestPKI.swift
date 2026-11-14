import CryptoKit
import Foundation
import Network
@testable import EIDTokenCheck

/// DER writers for fixtures (tests only).
enum E {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { DER.tlv(tag, content) }
    static func seq(_ parts: [UInt8]...) -> [UInt8] { tlv(0x30, parts.flatMap { $0 }) }
    static func set(_ parts: [UInt8]...) -> [UInt8] { tlv(0x31, parts.flatMap { $0 }) }
    static func oid(_ bytes: [UInt8]) -> [UInt8] { tlv(0x06, bytes) }
    static func int(_ bytes: [UInt8]) -> [UInt8] { tlv(0x02, (bytes.first ?? 0) & 0x80 != 0 ? [0] + bytes : bytes) }
    static func octet(_ bytes: [UInt8]) -> [UInt8] { tlv(0x04, bytes) }
    static func bits(_ bytes: [UInt8]) -> [UInt8] { tlv(0x03, [0] + bytes) }
    static func ctx(_ n: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0xA0 | n, content) }
    static func utf8(_ s: String) -> [UInt8] { tlv(0x0C, Array(s.utf8)) }
    static func printable(_ s: String) -> [UInt8] { tlv(0x13, Array(s.utf8)) }
    static let null: [UInt8] = [0x05, 0x00]
    static let ecdsaSHA256 = seq(oid(OID.ecdsaWithSHA256))

    static func time(_ format: String, _ date: Date) -> [UInt8] {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = format
        return Array(f.string(from: date).utf8)
    }
    static func utc(_ date: Date) -> [UInt8] { tlv(0x17, time("yyMMddHHmmss'Z'", date)) }
    static func gtime(_ date: Date) -> [UInt8] { tlv(0x18, time("yyyyMMddHHmmss'Z'", date)) }

    static func name(cn: String? = nil, serialNumber: String? = nil, given: String? = nil, surname: String? = nil) -> [UInt8] {
        var rdns = set(seq(oid([0x55, 0x04, 0x06]), printable("MN")))
        if let serialNumber { rdns += set(seq(oid([0x55, 0x04, 0x05]), printable(serialNumber))) }
        if let given { rdns += set(seq(oid([0x55, 0x04, 0x2A]), utf8(given))) }
        if let surname { rdns += set(seq(oid([0x55, 0x04, 0x04]), utf8(surname))) }
        if let cn { rdns += set(seq(oid([0x55, 0x04, 0x03]), utf8(cn))) }
        return tlv(0x30, rdns)
    }

    static func ext(_ id: [UInt8], critical: Bool = false, _ value: [UInt8]) -> [UInt8] {
        critical ? seq(oid(id), tlv(0x01, [0xFF]), octet(value)) : seq(oid(id), octet(value))
    }
}

/// A key + name + serial + certificate.
struct TestEntity: @unchecked Sendable {
    let key: P256.Signing.PrivateKey
    let name: [UInt8]
    let serial: [UInt8]
    let der: [UInt8]
    var parsed: ParsedCertificate { ParsedCertificate(der: der)! }
    var keyBits: [UInt8] { Array(key.publicKey.x963Representation) }
}

enum TestPKI {
    static func sign(_ data: [UInt8], _ key: P256.Signing.PrivateKey) -> [UInt8] {
        Array(try! key.signature(for: Data(data)).derRepresentation)
    }

    static func ski(_ key: P256.Signing.PublicKey) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: key.x963Representation))
    }

    /// X.509 v3 certificate signed with ecdsa-with-SHA256.
    static func certificate(serial: [UInt8], subject: [UInt8], key: P256.Signing.PublicKey,
                            issuer: [UInt8], issuerKey: P256.Signing.PrivateKey,
                            notBefore: Date, notAfter: Date, extensions: [[UInt8]]) -> [UInt8] {
        let exts = extensions + [E.ext([0x55, 0x1D, 0x0E], E.octet(ski(key))),
                                 E.ext([0x55, 0x1D, 0x23], E.seq(E.tlv(0x80, ski(issuerKey.publicKey))))]
        let tbs = E.seq(E.ctx(0, E.int([2])), E.int(serial), E.ecdsaSHA256, issuer,
                        E.seq(E.utc(notBefore), E.utc(notAfter)), subject, Array(key.derRepresentation),
                        E.ctx(3, E.tlv(0x30, exts.flatMap { $0 })))
        return E.seq(tbs, E.ecdsaSHA256, E.bits(sign(tbs, issuerKey)))
    }

    static let caBasicConstraints = E.ext(OID.basicConstraints, critical: true, E.seq(E.tlv(0x01, [0xFF])))
    static let caKeyUsage = E.ext(OID.keyUsage, critical: true, E.tlv(0x03, [0x01, 0x06]))      // keyCertSign, cRLSign
    /// AUTH: digitalSignature only.
    static let authKeyUsage = E.ext(OID.keyUsage, critical: true, E.tlv(0x03, [0x07, 0x80]))
    /// SIGN: digitalSignature + nonRepudiation.
    static let signKeyUsage = E.ext(OID.keyUsage, critical: true, E.tlv(0x03, [0x06, 0xC0]))
    /// digitalSignature + keyEncipherment (an extra bit).
    static let authPlusKeyEnciphermentKeyUsage = E.ext(OID.keyUsage, critical: true, E.tlv(0x03, [0x05, 0xA0]))
    static func eku(_ oids: [UInt8]...) -> [UInt8] {
        E.ext(OID.extendedKeyUsage, E.tlv(0x30, oids.flatMap { E.oid($0) }))
    }
    static func aia(ocsp url: URL) -> [UInt8] {
        E.ext(OID.authorityInfoAccess, E.seq(E.seq(E.oid(OID.accessMethodOCSP), E.tlv(0x86, Array(url.absoluteString.utf8)))))
    }
    static func cdp(_ url: URL) -> [UInt8] {
        E.ext(OID.crlDistributionPoints, E.seq(E.seq(E.ctx(0, E.ctx(0, E.tlv(0x86, Array(url.absoluteString.utf8)))))))
    }
}

/// Root (≙01) → national (≙02) → intermediate (≙03) → issuing CA (≙04) → AUTH leaf, plus a sibling CA (≙05) under
/// the intermediate and a delegated OCSP responder of the issuing CA. Hosts are `.invalid`: nothing here can ever
/// reach a real OCSP/CRL endpoint.
struct Fixture: @unchecked Sendable {
    static let ocspURL = URL(string: "http://ocsp.test.invalid/ocsp")!
    static let crlURL = URL(string: "http://crl.test.invalid/crl")!
    static let caOCSPURL = URL(string: "http://ocsp-ca.test.invalid/ocsp")!
    static let caCRLURL = URL(string: "http://crl-ca.test.invalid/ca")!
    static let origin = "rp.test.invalid"
    static let day: TimeInterval = 86_400
    static let leafSerial: [UInt8] = [0xA1, 0xB2, 0xC3]

    enum Level { case root, national, intermediate, ca, org }

    let now: Date
    let root: TestEntity
    let national: TestEntity
    let intermediate: TestEntity
    let ca: TestEntity
    let org: TestEntity
    let leaf: TestEntity
    let responder: TestEntity

    /// `leafKeyUsage` / `leafEKU` nil = the extension is absent; `leafSerialNumber` nil = no subject serialNumber.
    /// `caOCSP` / `caCRL`: the issuing CA carries AIA / CDP.
    init(leafNotBefore: Date? = nil, leafNotAfter: Date? = nil,
         leafKeyUsage: [UInt8]? = TestPKI.authKeyUsage, leafEKU: [UInt8]? = TestPKI.eku(OID.ekuClientAuth, OID.ekuEmailProtection),
         leafSerialNumber: String? = "PNOMN-TEST0001", leafIssuer: Level = .ca,
         responderEKU: Bool = true, responderNotBefore: Date? = nil, responderNotAfter: Date? = nil,
         caOCSP: Bool = true, caCRL: Bool = true) {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        self.now = now
        func makeCA(_ cn: String, serial: UInt8, issuer: TestEntity?, extra: [[UInt8]] = []) -> TestEntity {
            let key = P256.Signing.PrivateKey()
            let name = E.name(cn: cn)
            return TestEntity(key: key, name: name, serial: [serial], der: TestPKI.certificate(
                serial: [serial], subject: name, key: key.publicKey, issuer: issuer?.name ?? name,
                issuerKey: issuer?.key ?? key, notBefore: now - 365 * Self.day, notAfter: now + 3650 * Self.day,
                extensions: [TestPKI.caBasicConstraints, TestPKI.caKeyUsage] + extra))
        }
        let root = makeCA("TEST ONLY Root CA", serial: 0x01, issuer: nil)
        let national = makeCA("TEST ONLY National Issuing CA", serial: 0x02, issuer: root)
        let intermediate = makeCA("TEST ONLY Intermediate CA", serial: 0x03, issuer: national)
        let caURLs = (caOCSP ? [TestPKI.aia(ocsp: Self.caOCSPURL)] : []) + (caCRL ? [TestPKI.cdp(Self.caCRLURL)] : [])
        let ca = makeCA("TEST ONLY Issuing CA", serial: 0x04, issuer: intermediate, extra: caURLs)
        let org = makeCA("TEST ONLY Organization Issuing CA", serial: 0x05, issuer: intermediate,
                         extra: [TestPKI.aia(ocsp: Self.caOCSPURL), TestPKI.cdp(Self.caCRLURL)])
        self.root = root
        self.national = national
        self.intermediate = intermediate
        self.ca = ca
        self.org = org

        let leafParent: TestEntity
        switch leafIssuer {
        case .root: leafParent = root
        case .national: leafParent = national
        case .intermediate: leafParent = intermediate
        case .ca: leafParent = ca
        case .org: leafParent = org
        }
        let leafKey = P256.Signing.PrivateKey(), responderKey = P256.Signing.PrivateKey()
        let leafName = E.name(serialNumber: leafSerialNumber, given: "Тест", surname: "Хэрэглэгч")
        leaf = TestEntity(key: leafKey, name: leafName, serial: Self.leafSerial, der: TestPKI.certificate(
            serial: Self.leafSerial, subject: leafName, key: leafKey.publicKey, issuer: leafParent.name,
            issuerKey: leafParent.key,
            notBefore: leafNotBefore ?? now - 10 * Self.day, notAfter: leafNotAfter ?? now + 355 * Self.day,
            extensions: [leafKeyUsage, leafEKU].compactMap { $0 }
                + [TestPKI.aia(ocsp: Self.ocspURL), TestPKI.cdp(Self.crlURL)]))
        let responderName = E.name(cn: "TEST ONLY OCSP Responder")
        responder = TestEntity(key: responderKey, name: responderName, serial: [0x06], der: TestPKI.certificate(
            serial: [0x06], subject: responderName, key: responderKey.publicKey, issuer: ca.name,
            issuerKey: ca.key, notBefore: responderNotBefore ?? now - Self.day,
            notAfter: responderNotAfter ?? now + 30 * Self.day,
            extensions: [TestPKI.authKeyUsage] + (responderEKU ? [TestPKI.eku(OID.ekuOCSPSigning)] : [])))
    }

    /// The bundled set: root, 02, 03, 04 (the pinned issuing CA). `withOrg` also bundles the sibling CA (≙05).
    func trust(withOrg: Bool = false) -> TrustStore {
        TrustStore(anchors: [root.der], intermediates: [national.der, intermediate.der, ca.der] + (withOrg ? [org.der] : []),
                   issuingCA: ca.der)
    }

    var trust: TrustStore { trust() }

    /// CertID built independently of the code under test (default: the leaf, issued by the issuing CA).
    func certID(sha1: Bool = false, serial: [UInt8]? = nil, issuerName: [UInt8]? = nil,
                subject: TestEntity? = nil, issuer: TestEntity? = nil) -> [UInt8] {
        func h(_ d: [UInt8]) -> [UInt8] { sha1 ? Array(Insecure.SHA1.hash(data: d)) : Array(SHA256.hash(data: d)) }
        let issuer = issuer ?? ca
        return E.seq(E.seq(E.oid(sha1 ? OID.sha1 : OID.sha256), E.null),
                     E.octet(h(issuerName ?? issuer.name)), E.octet(h(issuer.keyBits)),
                     E.int(serial ?? (subject ?? leaf).serial))
    }

    enum Status { case good, revoked(Date), unknown }

    /// DER OCSPResponse about `subject` (default leaf) from `issuer` (default issuing CA). `signer` nil = the issuer
    /// signs (no embedded certificate). `nonceExt` = the extnValue of a responseExtensions nonce.
    func ocsp(status: Status = .good, thisUpdate: Date? = nil, nextUpdate: Date?? = .none,
              signer: TestEntity? = nil, embedSigner: Bool = true, certID: [UInt8]? = nil,
              tamper: Bool = false, responseStatus: UInt8 = 0, nonceExt: [UInt8]? = nil,
              subject: TestEntity? = nil, issuer: TestEntity? = nil) -> [UInt8] {
        if responseStatus != 0 { return E.seq(E.tlv(0x0A, [responseStatus])) }
        let key = signer?.key ?? (issuer ?? ca).key
        let statusDER: [UInt8]
        switch status {
        case .good: statusDER = [0x80, 0x00]
        case .revoked(let at): statusDER = E.ctx(1, E.gtime(at))
        case .unknown: statusDER = [0x82, 0x00]
        }
        let next: Date? = nextUpdate ?? (now + 3600)
        var single = (certID ?? self.certID(subject: subject, issuer: issuer)) + statusDER + E.gtime(thisUpdate ?? now - 60)
        if let next { single += E.ctx(0, E.gtime(next)) }
        var data = E.ctx(2, E.octet(TestPKI.ski(key.publicKey))) + E.gtime(now) + E.seq(E.tlv(0x30, single))
        if let nonceExt { data += E.ctx(1, E.seq(E.seq(E.oid(OID.ocspNonce), E.octet(nonceExt)))) }
        let tbs = E.tlv(0x30, data)
        let signature = TestPKI.sign(tamper ? tbs + [0x00] : tbs, key)
        var basic = tbs + E.ecdsaSHA256 + E.bits(signature)
        if let signer, embedSigner { basic += E.ctx(0, E.seq(signer.der)) }
        return E.seq(E.tlv(0x0A, [0]),
                     E.ctx(0, E.seq(E.oid(OID.ocspBasicResponse), E.octet(E.tlv(0x30, basic)))))
    }

    /// The nonce extension value (extnValue) of a DER OCSPRequest — what a responder echoes; nil when absent.
    static func nonceExtValue(request: [UInt8]) -> [UInt8]? {
        guard let tbs = DER.single(request)?.children?.first?.children, tbs.count == 2,
              let exts = tbs[1].children?.first?.children else { return nil }
        for ext in exts {
            guard let f = ext.children, f.count == 2, f[0].value == OID.ocspNonce else { continue }
            return f[1].value
        }
        return nil
    }

    static let deltaCRLExtension = E.ext(OID.deltaCRLIndicator, critical: true, E.int([5]))
    static let issuingDistributionPointExtension = E.ext(OID.issuingDistributionPoint, critical: true, E.seq())
    static let unknownCriticalExtension = E.ext([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x63], critical: true, E.null)

    /// DER CRL (v2) from `issuer` (default the issuing CA). `signerKey` nil = the issuer's key. `generalized` =
    /// thisUpdate / nextUpdate as GeneralizedTime instead of UTCTime.
    func crl(revoked: [[UInt8]] = [], thisUpdate: Date? = nil, nextUpdate: Date?? = .none,
             issuerName: [UInt8]? = nil, signerKey: P256.Signing.PrivateKey? = nil, extensions: [[UInt8]] = [],
             issuer: TestEntity? = nil, generalized: Bool = false) -> [UInt8] {
        let issuer = issuer ?? ca
        let time: (Date) -> [UInt8] = generalized ? E.gtime : E.utc
        var tbs = E.int([1]) + E.ecdsaSHA256 + (issuerName ?? issuer.name) + time(thisUpdate ?? now - 600)
        let next: Date? = nextUpdate ?? (now + 3600)
        if let next { tbs += time(next) }
        if !revoked.isEmpty {
            tbs += E.tlv(0x30, revoked.flatMap { E.seq(E.int($0), E.utc(now - Self.day)) })
        }
        if !extensions.isEmpty { tbs += E.ctx(0, E.tlv(0x30, extensions.flatMap { $0 })) }
        let tbsDER = E.tlv(0x30, tbs)
        return E.seq(tbsDER, E.ecdsaSHA256, E.bits(TestPKI.sign(tbsDER, signerKey ?? issuer.key)))
    }

    typealias Answer = @Sendable (RevocationRequest) -> [UInt8]

    /// Every endpoint answering "good / not listed": the leaf's OCSP (delegated responder) echoes the request's
    /// nonce, the issuing CA's OCSP answers pre-signed (no nonce).
    func answers() -> [URL: Answer] {
        let f = self
        return [Self.caOCSPURL: { _ in f.ocsp(subject: f.ca, issuer: f.intermediate) },
                Self.caCRLURL: { _ in f.crl(issuer: f.intermediate) },
                Self.ocspURL: { r in f.ocsp(signer: f.responder, nonceExt: Self.nonceExtValue(request: [UInt8](r.body ?? Data()))) },
                Self.crlURL: { _ in f.crl() }]
    }

    /// Raw r‖s by the leaf key over SHA-256("eID-TOKEN-LOGIN-V1" ‖ origin ‖ challenge) — computed here,
    /// independently of `LoginChallenge` — what CKM_ECDSA on the token returns.
    func tokenSignature(origin: String = Fixture.origin, challenge: [UInt8], key: P256.Signing.PrivateKey? = nil) -> [UInt8] {
        Self.signRaw(origin: origin, challenge: challenge, key: key ?? leaf.key)
    }

    static func signRaw(origin: String, challenge: [UInt8], key: P256.Signing.PrivateKey) -> [UInt8] {
        var hasher = SHA256()
        hasher.update(data: Data("eID-TOKEN-LOGIN-V1".utf8))
        hasher.update(data: Data(origin.utf8))
        hasher.update(data: Data(challenge))
        return Array(try! key.signature(for: hasher.finalize()).rawRepresentation)
    }

    /// The old, unbound construction: raw r‖s over SHA-256(challenge) alone.
    func bareSignature(challenge: [UInt8]) -> [UInt8] {
        Array(try! leaf.key.signature(for: SHA256.hash(data: challenge)).rawRepresentation)
    }
}

/// Answers from fixtures by URL; records every request; refuses any host that is not a `.invalid` test host.
/// `failure` = what an unknown URL throws (default: offline).
actor StubFetcher: RevocationFetcher {
    enum Failure: Error { case offline, unexpectedHost(String) }
    private(set) var requests: [RevocationRequest] = []
    let answers: [URL: Fixture.Answer]
    let failure: (any Error)?

    init(_ answers: [URL: Fixture.Answer], failure: (any Error)? = nil) {
        self.answers = answers
        self.failure = failure
    }

    func fetch(_ request: RevocationRequest) async throws -> Data {
        requests.append(request)
        guard let host = request.url.host, host.hasSuffix(".invalid") else {
            throw Failure.unexpectedHost(request.url.absoluteString)
        }
        guard let answer = answers[request.url] else { throw failure ?? Failure.offline }
        return Data(answer(request))
    }
}

/// Runs `body` once, whichever callback gets there first.
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func run(_ body: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { body() }
    }
}

/// HTTP/1.1 on the loopback interface only (tests only). Every request gets the chunks `answer(requestLine)` returns,
/// each after its delay, and then the connection is closed. Records the request lines.
final class LoopbackHTTPServer: @unchecked Sendable {
    struct Chunk: Sendable {
        let data: Data
        let delay: TimeInterval

        init(_ text: String, delay: TimeInterval = 0) {
            self.data = Data(text.utf8)
            self.delay = delay
        }

        init(bytes: Data, delay: TimeInterval = 0) {
            self.data = bytes
            self.delay = delay
        }
    }

    private let listener: NWListener
    private let queue = DispatchQueue(label: "eid-token-check.loopback-http")
    private let lock = NSLock()
    private var lines: [String] = []
    private(set) var port: UInt16 = 0

    var requestLines: [String] {
        lock.lock()
        defer { lock.unlock() }
        return lines
    }

    init(answer: @escaping @Sendable (String) -> [Chunk]) async throws {
        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .loopback
        let listener = try NWListener(using: parameters, on: .any)
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            connection.start(queue: self.queue)
            self.receive(connection, buffer: Data(), answer: answer)
        }
        let queue = self.queue
        port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            let once = Once()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: once.run { continuation.resume(returning: listener.port?.rawValue ?? 0) }
                case .failed(let error): once.run { continuation.resume(throwing: error) }
                case .cancelled: once.run { continuation.resume(throwing: CancellationError()) }
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    convenience init(text: @escaping @Sendable (String) -> String) async throws {
        try await self.init(answer: { [Chunk(text($0))] })
    }

    func stop() { listener.cancel() }

    private func receive(_ connection: NWConnection, buffer: Data, answer: @escaping @Sendable (String) -> [Chunk]) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { connection.cancel(); return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buffer[..<end.lowerBound], as: UTF8.self)
                let line = head.components(separatedBy: "\r\n").first ?? ""
                self.record(line)
                self.send(answer(line)[...], on: connection)
            } else if isComplete || error != nil {
                connection.cancel()
            } else {
                self.receive(connection, buffer: buffer, answer: answer)
            }
        }
    }

    private func send(_ chunks: ArraySlice<Chunk>, on connection: NWConnection) {
        guard let chunk = chunks.first else { connection.cancel(); return }
        queue.asyncAfter(deadline: .now() + chunk.delay) { [weak self] in
            connection.send(content: chunk.data, completion: .contentProcessed { error in
                guard error == nil else { connection.cancel(); return }
                self?.send(chunks.dropFirst(), on: connection)
            })
        }
    }

    private func record(_ line: String) {
        lock.lock()
        lines.append(line)
        lock.unlock()
    }
}

/// The repository's `trust/` folder (tests read the shipped certificates; no network).
enum RepoTrust {
    static var directory: URL {
        URL(fileURLWithPath: #filePath)                 // macos/EIDTokenCheck/Tests/EIDTokenCheckTests/TestPKI.swift
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("trust", isDirectory: true)
    }
}
