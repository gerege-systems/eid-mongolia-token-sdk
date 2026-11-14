import CryptoKit
import XCTest
@testable import EIDTokenCheck

final class DERTests: XCTestCase {
    func testParsesLeafFields() throws {
        let f = Fixture()
        let leaf = try XCTUnwrap(ParsedCertificate(der: f.leaf.der))
        XCTAssertEqual(leaf.serialHex, "A1B2C3")
        XCTAssertEqual(leaf.issuer, f.ca.name)
        XCTAssertEqual(leaf.subject, f.leaf.name)
        XCTAssertEqual(leaf.ocspURLs, [Fixture.ocspURL])
        XCTAssertEqual(leaf.crlURLs, [Fixture.crlURL])
        XCTAssertEqual(leaf.extendedKeyUsage, [OID.ekuClientAuth, OID.ekuEmailProtection])
        XCTAssertEqual(leaf.keyUsageBits, [0])
        XCTAssertEqual(leaf.subjectName?.first(OID.serialNumber), "PNOMN-TEST0001")
        XCTAssertEqual(leaf.subjectName?.displayName, "Тест Хэрэглэгч")
        XCTAssertTrue(leaf.isP256Key)
        XCTAssertEqual(leaf.isSigned(by: f.ca.parsed), true)
        XCTAssertEqual(leaf.isSigned(by: f.root.parsed), false)
    }

    func testRejectsGarbageAndNonMinimalLengths() {
        XCTAssertNil(ParsedCertificate(der: []))
        XCTAssertNil(ParsedCertificate(der: [0x30, 0x82, 0xFF]))
        XCTAssertNil(ParsedCertificate(der: Fixture().leaf.der + [0x00]))
        XCTAssertNil(DER.elements([0x30, 0x80, 0x00, 0x00]))                          // indefinite length
        XCTAssertNotNil(DER.single([0x04, 0x03, 0x01, 0x02, 0x03]))
        XCTAssertNil(DER.single([0x04, 0x81, 0x03, 0x01, 0x02, 0x03]))                // long form for a short length
        let body = [UInt8](repeating: 0x11, count: 0x80)
        XCTAssertNotNil(DER.single([0x04, 0x81, 0x80] + body))
        XCTAssertNil(DER.single([0x04, 0x82, 0x00, 0x80] + body))                     // leading zero length byte
    }

    func testTimeParsingUTCAndGeneralized() throws {
        let utc = try XCTUnwrap(DER.time(DERNode(tag: 0x17, raw: [], value: Array("491231235959Z".utf8))))
        let utc19 = try XCTUnwrap(DER.time(DERNode(tag: 0x17, raw: [], value: Array("500101000000Z".utf8))))
        let gen = try XCTUnwrap(DER.time(DERNode(tag: 0x18, raw: [], value: Array("20261114120000.123Z".utf8))))
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        XCTAssertEqual(cal.component(.year, from: utc), 2049)
        XCTAssertEqual(cal.component(.year, from: utc19), 1950)
        let parts = cal.dateComponents([.year, .month, .day, .hour], from: gen)
        XCTAssertEqual([parts.year, parts.month, parts.day, parts.hour], [2026, 11, 14, 12])
        XCTAssertNil(DER.time(DERNode(tag: 0x17, raw: [], value: Array("261314000000Z".utf8))))
    }

    func testKeyUsageBits() {
        XCTAssertEqual(Fixture(leafKeyUsage: TestPKI.signKeyUsage).leaf.parsed.keyUsageBits, [0, 1])
        XCTAssertEqual(Fixture(leafKeyUsage: TestPKI.authPlusKeyEnciphermentKeyUsage).leaf.parsed.keyUsageBits, [0, 2])
        XCTAssertNil(Fixture(leafKeyUsage: nil).leaf.parsed.keyUsageBits)
    }
}

final class OriginTests: XCTestCase {
    func testValidOrigins() {
        for origin in ["test.example", "login.example.mn", "a", "xn--80aa0b.mn", "rp-1.test.invalid",
                       String(repeating: "a.", count: 126) + "a"] {
            XCTAssertTrue(Origin.isValid(origin), origin)
        }
    }

    func testInvalidOrigins() {
        let tooLong = String(repeating: "a.", count: 126) + "ab"                      // 254 characters
        for origin in ["", "Login.example.mn", "https://login.example.mn", "login.example.mn:443",
                       "login.example.mn/path", "login.example.mn.", "логин.mn", "-a.mn", "a-.mn", "a..mn",
                       ".a.mn", "a b.mn", String(repeating: "a", count: 64) + ".mn", tooLong, "a_b.mn"] {
            XCTAssertFalse(Origin.isValid(origin), origin)
        }
        XCTAssertNil(LoginChallenge.digestToSign(origin: "Login.example.mn", challenge: [UInt8](repeating: 1, count: 32)))
    }
}

final class SignatureTests: XCTestCase {
    private let challenge = [UInt8](repeating: 7, count: 32)

    private func check(_ f: Fixture, origin: String = Fixture.origin, challenge: [UInt8]? = nil,
                       _ signature: [UInt8]) -> CheckResult {
        LoginChallenge.checkSignature(origin: origin, challenge: challenge ?? self.challenge, rawSignature: signature,
                                      certificate: f.leaf.parsed)
    }

    func testDigestIsTheBoundConstruction() throws {
        var hasher = SHA256()
        hasher.update(data: Data("eID-TOKEN-LOGIN-V1".utf8))
        hasher.update(data: Data("rp.example".utf8))
        hasher.update(data: Data(challenge))
        XCTAssertEqual(LoginChallenge.digestToSign(origin: "rp.example", challenge: challenge), Array(hasher.finalize()))
        XCTAssertNotEqual(LoginChallenge.digestToSign(origin: "rp.example", challenge: challenge),
                          Array(SHA256.hash(data: challenge)))
        XCTAssertEqual(LoginChallenge.defaultOrigin, "test.example")
    }

    func testValidSignature() {
        let f = Fixture()
        XCTAssertEqual(check(f, f.tokenSignature(challenge: challenge)).status, .passed)
    }

    /// The signature is otherwise valid (over the bound digest of that very challenge): only the length fails it.
    func testChallengeMustBeExactly32Bytes() {
        let f = Fixture()
        for length in [0, 31, 33, 64] {
            let c = [UInt8](repeating: 9, count: length)
            XCTAssertNil(LoginChallenge.digestToSign(origin: Fixture.origin, challenge: c))   // nothing to sign
            let r = check(f, challenge: c, f.tokenSignature(challenge: c))
            XCTAssertEqual(r.status, .failed, "length \(length)")
            XCTAssertTrue(r.reason.hasPrefix("Challenge \(length) байт"), r.reason)
        }
    }

    func testBareSHA256OfChallengeFails() {
        let f = Fixture()
        XCTAssertEqual(check(f, f.bareSignature(challenge: challenge)).status, .failed)
    }

    func testOtherOriginFails() {
        let f = Fixture()
        XCTAssertEqual(check(f, f.tokenSignature(origin: "other.test.invalid", challenge: challenge)).status, .failed)
        XCTAssertEqual(check(f, origin: "other.test.invalid", f.tokenSignature(challenge: challenge)).status, .failed)
    }

    func testOtherKeyOrOtherChallengeOrLengthFails() {
        let f = Fixture()
        let good = f.tokenSignature(challenge: challenge)
        XCTAssertEqual(check(f, f.tokenSignature(challenge: [UInt8](repeating: 8, count: 32))).status, .failed)
        XCTAssertEqual(check(f, f.tokenSignature(challenge: challenge, key: P256.Signing.PrivateKey())).status, .failed)
        XCTAssertEqual(check(f, Array(good.prefix(63))).status, .failed)
        XCTAssertEqual(check(f, good + [0]).status, .failed)
        let der = Array(try! f.leaf.key.signature(for: Data()).derRepresentation)        // DER is not accepted
        XCTAssertEqual(check(f, der).status, .failed)
    }

    func testZeroOrOutOfRangeScalarsFail() {
        let f = Fixture()
        let good = f.tokenSignature(challenge: challenge)
        let zeroR = [UInt8](repeating: 0, count: 32) + good[32...]
        let zeroS = Array(good[..<32]) + [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(check(f, zeroR).status, .failed)
        XCTAssertEqual(check(f, zeroS).status, .failed)
        XCTAssertEqual(check(f, P256Scalar.order + Array(good[32...])).status, .failed)
        XCTAssertFalse(P256Scalar.isValid([UInt8](repeating: 0, count: 32)[...]))
        XCTAssertFalse(P256Scalar.isValid(P256Scalar.order[...]))
        XCTAssertTrue(P256Scalar.isValid(([UInt8](repeating: 0, count: 31) + [1])[...]))
    }

    func testRandomChallengeIsFresh() throws {
        let a = try XCTUnwrap(LoginChallenge.random()), b = try XCTUnwrap(LoginChallenge.random())
        XCTAssertEqual(a.count, 32)
        XCTAssertNotEqual(a, b)
    }
}

final class ChainTests: XCTestCase {
    private func chain(_ f: Fixture, trust: TrustStore? = nil, leaf: TestEntity? = nil) -> CheckResult {
        ChainCheck.chain(leaf: (leaf ?? f.leaf).parsed, trust: trust ?? f.trust, now: f.now).result
    }

    func testChainToBundledAnchor() {
        let f = Fixture()
        let r = ChainCheck.chain(leaf: f.leaf.parsed, trust: f.trust, now: f.now)
        XCTAssertEqual(r.result.status, .passed, r.result.reason)
        XCTAssertEqual(r.chain.map(\.der), [f.leaf.der, f.ca.der, f.intermediate.der, f.national.der, f.root.der])
        XCTAssertEqual(ChainCheck.validity(chain: r.chain, now: f.now).status, .passed)
    }

    func testForeignRootIsRejected() {
        let f = Fixture(), other = Fixture()
        let trust = TrustStore(anchors: [other.root.der], intermediates: [f.national.der, f.intermediate.der, f.ca.der],
                               issuingCA: f.ca.der)
        XCTAssertEqual(chain(f, trust: trust).status, .failed)
    }

    func testMissingIntermediateIsRejected() {
        let f = Fixture()
        XCTAssertEqual(chain(f, trust: TrustStore(anchors: [f.root.der], intermediates: [f.ca.der], issuingCA: f.ca.der)).status,
                       .failed)
    }

    func testNoAnchorsOrNoIssuingCACannotBeChecked() {
        let f = Fixture()
        XCTAssertEqual(chain(f, trust: TrustStore(anchors: [], intermediates: [f.ca.der], issuingCA: f.ca.der)).status,
                       .unavailable)
        XCTAssertEqual(chain(f, trust: TrustStore(anchors: [f.root.der], intermediates: [f.national.der, f.intermediate.der],
                                                  issuingCA: f.ca.der)).status, .unavailable)
    }

    func testEndEntityFromANonIssuingCAIsRejected() {
        for level in [Fixture.Level.national, .intermediate, .root] {          // ≙ 02, 03, 01
            let f = Fixture(leafIssuer: level)
            XCTAssertEqual(chain(f).status, .failed, "\(level)")
        }
    }

    /// ≙05 issues relying-party mTLS certificates with clientAuth: even with digitalSignature + clientAuth +
    /// PNOMN- and 05 in the bundled set, only the pinned 04 may issue an AUTH certificate.
    func testCertificateFromTheOrganizationCAIsRejected() {
        let f = Fixture(leafIssuer: .org)
        let r = chain(f, trust: f.trust(withOrg: true))
        XCTAssertEqual(r.status, .failed)
        XCTAssertTrue(r.reason.contains("(04)"), r.reason)
    }

    /// nonRepudiation alone disqualifies: the SIGN fixture carries clientAuth and PNOMN-.
    func testSignCertificateIsNotAuth() {
        let f = Fixture(leafKeyUsage: TestPKI.signKeyUsage)
        let r = chain(f)
        XCTAssertEqual(r.status, .failed)
        XCTAssertTrue(r.reason.contains("KeyUsage"), r.reason)
    }

    func testKeyUsageWithAnExtraBitIsNotAuth() {
        let f = Fixture(leafKeyUsage: TestPKI.authPlusKeyEnciphermentKeyUsage)
        XCTAssertEqual(chain(f).status, .failed)
    }

    func testSerialNumberMustStartWithPNOMN() {
        XCTAssertEqual(chain(Fixture(leafSerialNumber: "NTRMN-TEST0001")).status, .failed)
        XCTAssertEqual(chain(Fixture(leafSerialNumber: "RP-TEST0001")).status, .failed)
        let none = chain(Fixture(leafSerialNumber: nil))
        XCTAssertEqual(none.status, .failed)
        XCTAssertTrue(none.reason.contains("serialNumber"), none.reason)
    }

    func testOCSPResponderCertificateIsNotAuth() {
        let f = Fixture()
        XCTAssertEqual(chain(f, leaf: f.responder).status, .failed)
    }

    func testMissingKeyUsageOrEKUFails() {
        XCTAssertEqual(chain(Fixture(leafKeyUsage: nil)).status, .failed)
        XCTAssertEqual(chain(Fixture(leafEKU: nil)).status, .failed)
        XCTAssertEqual(chain(Fixture(leafEKU: TestPKI.eku(OID.ekuEmailProtection))).status, .failed)
    }

    func testExpiredLeafFailsValidityNotChain() {
        let now = Date()
        let f = Fixture(leafNotBefore: now - 400 * Fixture.day, leafNotAfter: now - Fixture.day)
        let r = ChainCheck.chain(leaf: f.leaf.parsed, trust: f.trust, now: f.now)
        XCTAssertEqual(r.result.status, .passed, r.result.reason)
        XCTAssertEqual(ChainCheck.validity(chain: r.chain, now: f.now).status, .failed)
        let notYet = Fixture(leafNotBefore: now + Fixture.day, leafNotAfter: now + 30 * Fixture.day)
        XCTAssertEqual(ChainCheck.validity(chain: [notYet.leaf.parsed], now: notYet.now).status, .failed)
    }

    /// notAfter is inclusive: valid AT notAfter, expired one second later.
    func testNotAfterBoundaryIsInclusive() {
        let probe = Fixture()
        let f = Fixture(leafNotBefore: probe.now - Fixture.day, leafNotAfter: probe.now + 60)
        let notAfter = f.leaf.parsed.notAfter
        XCTAssertEqual(ChainCheck.validity(chain: [f.leaf.parsed], now: notAfter).status, .passed)
        XCTAssertEqual(ChainCheck.validity(chain: [f.leaf.parsed], now: notAfter + 1).status, .failed)
    }

    func testTrustStoreLoadsByFolderAndPinsTheIssuingCA() throws {
        let f = Fixture()
        func pem(_ der: [UInt8]) -> String {
            "-----BEGIN CERTIFICATE-----\n" + Data(der).base64EncodedString(options: .lineLength64Characters)
                + "\n-----END CERTIFICATE-----\n"
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("eid-trust-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("anchors"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("intermediates"), withIntermediateDirectories: true)
        try pem(f.root.der).write(to: dir.appendingPathComponent("anchors/root.pem"), atomically: true, encoding: .utf8)
        try Data(f.national.der).write(to: dir.appendingPathComponent("intermediates/02.cer"))
        try pem(f.intermediate.der).write(to: dir.appendingPathComponent("intermediates/03.pem"), atomically: true, encoding: .utf8)
        try Data(f.ca.der).write(to: dir.appendingPathComponent("intermediates/04.der"))
        try "not a certificate".write(to: dir.appendingPathComponent("intermediates/readme.txt"), atomically: true, encoding: .utf8)
        let store = TrustStore.load(directory: dir)
        XCTAssertEqual(store.anchors, [f.root.der])
        XCTAssertEqual(store.intermediates, [f.national.der, f.intermediate.der, f.ca.der])
        XCTAssertNil(store.issuingCA)                     // the test CA is not the pinned 04
        XCTAssertNil(TrustStore(anchors: [], intermediates: [], issuingCA: f.ca.der).issuingCA)
        XCTAssertEqual(f.trust.issuingCA(of: f.leaf.parsed)?.der, f.ca.der)
        XCTAssertNil(f.trust.issuingCA(of: f.ca.parsed))
    }

    /// The shipped trust/ folder: one root, 02, 03, 04; 04 is the pinned issuing CA; every certificate is signed by
    /// its bundled parent (signatures only, no network).
    func testShippedTrustFolder() throws {
        let store = TrustStore.load(directory: RepoTrust.directory)
        let all = (store.anchors + store.intermediates).map(TrustStore.sha256Hex).sorted()
        XCTAssertEqual(all, [
            "56f3d1ca7f282287619773905aa0cd7a427d4f95dc0ed7b6733963a89bc31237",     // 03 Gerege Issuing CA
            "87b8db6862abde5e4a07a10c2c696afe5cb6aea072b9f3f9755e73ce79f546fc",     // 04 eID Mongolia Issuing CA
            "9423640dd74561d1af1ea8a093860bda7df5b5620bb617921395dc0d1a1f980d",     // 02 Mongolian National Issuing CA
            "cbe7f3fe1f048037c215da321e58caa4f363de9e54bbc442a3bfd62fad834482",     // 01 Mongolian National Root CA
        ])
        XCTAssertEqual(store.anchors.count, 1)
        let issuing = try XCTUnwrap(store.issuingCA)
        XCTAssertEqual(TrustStore.sha256Hex(issuing), TrustStore.issuingCASHA256)
        let parsed = (store.anchors + store.intermediates).compactMap { ParsedCertificate(der: $0) }
        for cert in parsed where !store.anchors.contains(cert.der) {
            XCTAssertTrue(parsed.contains { $0.der != cert.der && cert.isSigned(by: $0) == true },
                          cert.subjectName?.displayName ?? "?")
        }
    }
}

final class OCSPTests: XCTestCase {
    private func eval(_ f: Fixture, _ response: [UInt8], nonce: [UInt8]? = nil, required: Bool = false) -> CheckResult {
        OCSPCheck.evaluate(response: response, leaf: f.leaf.parsed, issuer: f.ca.parsed, nonce: nonce,
                           nonceRequired: required, now: f.now)
    }

    func testDelegatedResponderGood() {
        let f = Fixture()
        let r = eval(f, f.ocsp(signer: f.responder))
        XCTAssertEqual(r.status, .passed, r.reason)
    }

    func testIssuerSignedGoodWithSHA1CertID() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.ocsp(certID: f.certID(sha1: true))).status, .passed)
    }

    func testCertIDHashMustBeSHA1OrSHA256() {
        let f = Fixture()
        let sha384: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]
        let id = E.seq(E.seq(E.oid(sha384), E.null), E.octet(Array(SHA384.hash(data: f.ca.name))),
                       E.octet(Array(SHA384.hash(data: f.ca.keyBits))), E.int(Fixture.leafSerial))
        XCTAssertEqual(eval(f, f.ocsp(certID: id)).status, .failed)
    }

    func testRequestCarriesCertIDAndNonce() {
        let f = Fixture()
        let nonce = [UInt8](repeating: 0x5A, count: 32)
        XCTAssertEqual(OCSPCheck.certID(leaf: f.leaf.parsed, issuer: f.ca.parsed), f.certID())
        let request = OCSPCheck.request(leaf: f.leaf.parsed, issuer: f.ca.parsed, nonce: nonce)
        let nonceExtension = E.seq(E.oid(OID.ocspNonce), E.octet(E.octet(nonce)))
        XCTAssertEqual(request, E.seq(E.seq(E.seq(E.seq(f.certID())), E.ctx(2, E.seq(nonceExtension)))))
        XCTAssertEqual(Fixture.nonceExtValue(request: request), E.octet(nonce))
        XCTAssertEqual(OCSPCheck.newNonce()?.count, 32)
    }

    /// AUTH certificate: the echoed nonce is REQUIRED and must match.
    func testNonceRequiredForAuth() {
        let f = Fixture()
        let nonce = [UInt8](repeating: 0x11, count: 32), other = [UInt8](repeating: 0x22, count: 32)
        XCTAssertEqual(eval(f, f.ocsp(nonceExt: E.octet(nonce)), nonce: nonce, required: true).status, .passed)
        XCTAssertEqual(eval(f, f.ocsp(nonceExt: nonce), nonce: nonce, required: true).status, .passed)     // echoed raw
        let missing = eval(f, f.ocsp(), nonce: nonce, required: true)
        XCTAssertEqual(missing.status, .failed)
        XCTAssertTrue(missing.reason.contains("nonce"), missing.reason)
        XCTAssertEqual(eval(f, f.ocsp(nonceExt: E.octet(other)), nonce: nonce, required: true).status, .failed)
    }

    /// Issuing-CA check (pre-signed answers): the nonce is optional, but an echoed one must still match.
    func testNonceOptionalForTheIssuingCA() {
        let f = Fixture()
        let nonce = [UInt8](repeating: 0x11, count: 32), other = [UInt8](repeating: 0x22, count: 32)
        XCTAssertEqual(eval(f, f.ocsp(), nonce: nonce, required: false).status, .passed)
        XCTAssertEqual(eval(f, f.ocsp(nonceExt: E.octet(other)), nonce: nonce, required: false).status, .failed)
    }

    func testRevokedAndUnknownFail() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.ocsp(status: .revoked(f.now - 3600), signer: f.responder)).status, .failed)
        XCTAssertEqual(eval(f, f.ocsp(status: .unknown, signer: f.responder)).status, .failed)
    }

    /// Order: revoked is reported before freshness, freshness before unknown (the same on Windows).
    func testStatusAndFreshnessOrder() {
        let f = Fixture()
        let staleRevoked = eval(f, f.ocsp(status: .revoked(f.now - 3 * Fixture.day), thisUpdate: f.now - 3 * Fixture.day,
                                          nextUpdate: f.now - 2 * Fixture.day))
        XCTAssertTrue(staleRevoked.reason.hasPrefix("Гэрчилгээ цуцлагдсан"), staleRevoked.reason)
        let staleUnknown = eval(f, f.ocsp(status: .unknown, thisUpdate: f.now - 3 * Fixture.day, nextUpdate: f.now - 2 * Fixture.day))
        XCTAssertTrue(staleUnknown.reason.hasPrefix("OCSP хариу хуучирсан"), staleUnknown.reason)
    }

    func testBadSignatureFails() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.ocsp(signer: f.responder, tamper: true)).status, .failed)
    }

    func testResponderMustBeAuthorised() {
        // Responder certificate without id-kp-OCSPSigning.
        let f = Fixture(responderEKU: false)
        XCTAssertEqual(eval(f, f.ocsp(signer: f.responder)).status, .failed)
        // Responder certificate not embedded: unknown signer.
        XCTAssertEqual(eval(f, f.ocsp(signer: f.responder, embedSigner: false)).status, .failed)
    }

    func testResponderIssuedByAnotherCAFails() {
        let f = Fixture(), other = Fixture()
        let r = eval(f, f.ocsp(signer: other.responder))
        XCTAssertEqual(r.status, .failed)
        XCTAssertTrue(r.reason.contains("олгоогүй"), r.reason)
    }

    func testExpiredOrNotYetValidResponderFails() {
        let probe = Fixture()
        let expired = Fixture(responderNotBefore: probe.now - 30 * Fixture.day, responderNotAfter: probe.now - Fixture.day)
        let r = eval(expired, expired.ocsp(signer: expired.responder))
        XCTAssertEqual(r.status, .failed)
        XCTAssertTrue(r.reason.contains("хүчинтэй хугацаанаас гадуур"), r.reason)
        let notYet = Fixture(responderNotBefore: probe.now + Fixture.day, responderNotAfter: probe.now + 30 * Fixture.day)
        XCTAssertEqual(eval(notYet, notYet.ocsp(signer: notYet.responder)).status, .failed)
    }

    func testFreshnessWindow() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 3 * Fixture.day, nextUpdate: f.now - Fixture.day)).status, .failed)
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now + 3600)).status, .failed)
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now + 120)).status, .passed)                         // skew
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: f.now - 120)).status, .passed)  // skew
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: f.now - 300)).status, .passed)  // inclusive
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: f.now - 301)).status, .failed)
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 2 * 3600, nextUpdate: .some(nil))).status, .failed)
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: .some(nil))).status, .passed)
    }

    func testResponseForAnotherCertificateFails() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.ocsp(certID: f.certID(serial: [0x05]))).status, .failed)
        XCTAssertEqual(eval(f, f.ocsp(certID: f.certID(issuerName: f.root.name))).status, .failed)
    }

    func testResponderErrorCannotBeCheckedButGarbageFails() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.ocsp(responseStatus: 3)).status, .unavailable)          // tryLater
        XCTAssertEqual(eval(f, [0x30, 0x00]).status, .failed)
        XCTAssertEqual(eval(f, [0x01, 0x02, 0x03]).status, .failed)
    }
}

final class CRLTests: XCTestCase {
    private func eval(_ f: Fixture, _ crl: [UInt8]) -> CheckResult {
        CRLCheck.evaluate(crl: crl, leaf: f.leaf.parsed, issuer: f.ca.parsed, now: f.now)
    }

    func testNotListedPasses() {
        let f = Fixture()
        let r = eval(f, f.crl(revoked: [[0x05], [0x06]]))
        XCTAssertEqual(r.status, .passed, r.reason)
        XCTAssertEqual(eval(f, f.crl()).status, .passed)
        XCTAssertEqual(eval(f, f.crl(generalized: true)).status, .passed)               // GeneralizedTime
    }

    func testListedFails() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.crl(revoked: [[0x05], Fixture.leafSerial])).status, .failed)
    }

    func testWrongSignerOrIssuerFails() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.crl(signerKey: f.root.key)).status, .failed)
        XCTAssertEqual(eval(f, f.crl(issuerName: f.root.name, signerKey: f.root.key)).status, .failed)
    }

    func testFreshnessWindow() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now - 3 * Fixture.day, nextUpdate: f.now - Fixture.day)).status, .failed)
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now + 3600)).status, .failed)
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now - Fixture.day, nextUpdate: f.now - 120)).status, .passed)   // skew
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now - Fixture.day, nextUpdate: f.now - 300)).status, .passed)   // inclusive
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now - Fixture.day, nextUpdate: f.now - 301)).status, .failed)
    }

    func testMissingNextUpdateCannotBeChecked() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.crl(nextUpdate: .some(nil))).status, .unavailable)
    }

    func testDeltaIDPOrUnknownCriticalExtensionCannotBeUsed() {
        let f = Fixture()
        XCTAssertEqual(eval(f, f.crl(extensions: [Fixture.deltaCRLExtension])).status, .unavailable)
        XCTAssertEqual(eval(f, f.crl(extensions: [Fixture.issuingDistributionPointExtension])).status, .unavailable)
        XCTAssertEqual(eval(f, f.crl(extensions: [Fixture.unknownCriticalExtension])).status, .unavailable)
        let crlNumber = E.ext(OID.crlNumber, E.int([7]))
        XCTAssertEqual(eval(f, f.crl(extensions: [crlNumber])).status, .passed)
    }

    func testGarbageFails() {
        let f = Fixture()
        XCTAssertEqual(eval(f, [0x30, 0x01, 0x00]).status, .failed)
    }
}

final class LoginVerifierTests: XCTestCase {
    private let challenge = [UInt8](repeating: 1, count: 32)

    private func verify(_ f: Fixture, answers: [URL: Fixture.Answer]? = nil, trust: TrustStore? = nil,
                        certificate: [UInt8]? = nil, signature: [UInt8]? = nil, origin: String = Fixture.origin,
                        failure: (any Error)? = nil) async -> (LoginReport, StubFetcher) {
        let stub = StubFetcher(answers ?? f.answers(), failure: failure)
        let report = await LoginVerifier(trust: trust ?? f.trust, fetcher: stub)
            .verify(origin: origin, challenge: challenge,
                    signature: signature ?? f.tokenSignature(challenge: challenge),
                    certificate: certificate ?? f.leaf.der, now: f.now)
        return (report, stub)
    }

    private func status(_ report: LoginReport, _ kind: CheckKind) -> CheckStatus? {
        report.checks.first { $0.kind == kind }?.status
    }

    func testAllChecksPassOnlyWithTestEndpoints() async {
        let f = Fixture()
        let (report, stub) = await verify(f)
        XCTAssertEqual(report.checks.map(\.kind), CheckKind.allCases)
        XCTAssertTrue(report.loggedIn, report.failureReason ?? "")
        XCTAssertEqual(report.summary, "Нэвтэрлээ: Тест Хэрэглэгч")
        let requests = await stub.requests
        XCTAssertEqual(requests.map(\.url), [Fixture.caOCSPURL, Fixture.caCRLURL, Fixture.ocspURL, Fixture.crlURL])
        XCTAssertEqual(requests[2].contentType, "application/ocsp-request")
        XCTAssertNotNil(requests[2].body)
        XCTAssertNil(requests[3].body)
        XCTAssertTrue(report.checks[1].reason.contains("олгогч CA цуцлагдаагүй"), report.checks[1].reason)
    }

    func testInvalidOriginStopsBeforeAnyCheck() async {
        let f = Fixture()
        let (report, stub) = await verify(f, origin: "https://rp.test.invalid")
        XCTAssertFalse(report.loggedIn)
        XCTAssertEqual(report.stopReason, Origin.invalidReason)
        let requests = await stub.requests
        XCTAssertTrue(requests.isEmpty)
    }

    func testMissingNonceOnTheAuthOCSPIsNotLoggedIn() async {
        let f = Fixture()
        var answers = f.answers()
        answers[Fixture.ocspURL] = { _ in f.ocsp(signer: f.responder) }
        let (report, _) = await verify(f, answers: answers)
        XCTAssertEqual(status(report, .ocsp), .failed)
        XCTAssertFalse(report.loggedIn)
    }

    func testNetworkFailureFailsClosed() async {
        let f = Fixture()
        var answers = f.answers()
        answers[Fixture.ocspURL] = nil
        let (report, _) = await verify(f, answers: answers)
        XCTAssertEqual(status(report, .ocsp), .unavailable)
        XCTAssertFalse(report.loggedIn)
        XCTAssertTrue(report.failureReason?.hasPrefix("OCSP —") == true, report.failureReason ?? "")
    }

    /// A connection lost in the middle of the body is «шалгаж чадсангүй», never a crash or a pass.
    func testIOErrorMidBodyIsUnavailable() async {
        let f = Fixture()
        var answers = f.answers()
        answers[Fixture.crlURL] = nil
        let (report, _) = await verify(f, answers: answers, failure: URLError(.networkConnectionLost))
        XCTAssertEqual(status(report, .crl), .unavailable)
        XCTAssertFalse(report.loggedIn)
    }

    func testWrongSignatureIsNotLoggedIn() async {
        let f = Fixture()
        let (report, _) = await verify(f, signature: f.tokenSignature(challenge: challenge, key: P256.Signing.PrivateKey()))
        XCTAssertEqual(report.checks.first?.status, .failed)
        XCTAssertFalse(report.loggedIn)
    }

    func testOldConstructionAndOtherOriginAreNotLoggedIn() async {
        let f = Fixture()
        let (bare, _) = await verify(f, signature: f.bareSignature(challenge: challenge))
        XCTAssertEqual(bare.checks.first?.status, .failed)
        XCTAssertFalse(bare.loggedIn)
        let (otherOrigin, _) = await verify(f, signature: f.tokenSignature(origin: "other.test.invalid", challenge: challenge))
        XCTAssertEqual(otherOrigin.checks.first?.status, .failed)
        XCTAssertFalse(otherOrigin.loggedIn)
    }

    func testSignOrgAndResponderCertificatesAreNotLoggedIn() async {
        let sign = Fixture(leafKeyUsage: TestPKI.signKeyUsage)
        let (signReport, _) = await verify(sign)
        XCTAssertEqual(status(signReport, .chain), .failed)
        XCTAssertFalse(signReport.loggedIn)

        let org = Fixture(leafIssuer: .org)
        let (orgReport, _) = await verify(org, trust: org.trust(withOrg: true))
        XCTAssertEqual(status(orgReport, .signature), .passed)
        XCTAssertEqual(status(orgReport, .chain), .failed)
        XCTAssertEqual(status(orgReport, .ocsp), .unavailable)                 // not issued by the pinned 04
        XCTAssertFalse(orgReport.loggedIn)

        let f = Fixture()
        let responderSignature = Fixture.signRaw(origin: Fixture.origin, challenge: challenge, key: f.responder.key)
        let (responderReport, _) = await verify(f, certificate: f.responder.der, signature: responderSignature)
        XCTAssertEqual(status(responderReport, .signature), .passed)
        XCTAssertEqual(status(responderReport, .chain), .failed)
        XCTAssertFalse(responderReport.loggedIn)
    }

    func testRevokedIssuingCAIsNotLoggedIn() async {
        let f = Fixture()
        var byOCSP = f.answers()
        byOCSP[Fixture.caOCSPURL] = { _ in f.ocsp(status: .revoked(f.now - 3600), subject: f.ca, issuer: f.intermediate) }
        let (ocspReport, _) = await verify(f, answers: byOCSP)
        XCTAssertEqual(status(ocspReport, .chain), .failed)
        XCTAssertFalse(ocspReport.loggedIn)

        var byCRL = f.answers()
        byCRL[Fixture.caCRLURL] = { _ in f.crl(revoked: [f.ca.serial], issuer: f.intermediate) }
        let (crlReport, _) = await verify(f, answers: byCRL)
        XCTAssertEqual(status(crlReport, .chain), .failed)
        XCTAssertFalse(crlReport.loggedIn)

        var unreachable = f.answers()
        unreachable[Fixture.caCRLURL] = nil
        let (offline, _) = await verify(f, answers: unreachable)
        XCTAssertEqual(status(offline, .chain), .unavailable)
        XCTAssertFalse(offline.loggedIn)
    }

    /// Neither AIA nor CDP on the issuing CA: its revocation cannot be checked — not "not applicable".
    func testIssuingCAWithoutAIAAndCDPCannotBeChecked() async {
        let f = Fixture(caOCSP: false, caCRL: false)
        let (report, stub) = await verify(f)
        XCTAssertEqual(status(report, .chain), .unavailable)
        XCTAssertFalse(report.loggedIn)
        let requests = await stub.requests
        XCTAssertEqual(requests.map(\.url), [Fixture.ocspURL, Fixture.crlURL])
    }

    /// Only one of them: that one decides.
    func testIssuingCAWithOnlyCDP() async {
        let f = Fixture(caOCSP: false)
        let (report, _) = await verify(f)
        XCTAssertTrue(report.loggedIn, report.failureReason ?? "")
        XCTAssertTrue(report.checks[1].reason.contains("OCSP: AIA алга"), report.checks[1].reason)
    }

    func testUnknownIssuerCannotCheckRevocation() async {
        let f = Fixture()
        let (report, stub) = await verify(f, trust: TrustStore(anchors: [f.root.der], intermediates: [], issuingCA: nil))
        XCTAssertEqual(report.checks.filter { $0.kind == .ocsp || $0.kind == .crl }.map(\.status), [.unavailable, .unavailable])
        XCTAssertFalse(report.loggedIn)
        let requests = await stub.requests
        XCTAssertTrue(requests.isEmpty)
    }

    func testRunSignsOnceAfterThePreconditions() async {
        let f = Fixture()
        let verifier = LoginVerifier(trust: f.trust, fetcher: StubFetcher(f.answers()))
        var calls = 0
        let report = await verifier.run(origin: Fixture.origin, challenge: challenge, certificate: f.leaf.der, now: f.now) { digest in
            calls += 1
            return Array(try f.leaf.key.signature(for: Data(digest)).rawRepresentation)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(status(report, .signature), .failed)        // signature(for: Data) hashes again: wrong digest
        var refused = 0
        let short = await verifier.run(origin: Fixture.origin, challenge: [1, 2, 3], certificate: f.leaf.der, now: f.now) { _ in
            refused += 1
            return []
        }
        let badOrigin = await verifier.run(origin: "RP.test", challenge: challenge, certificate: f.leaf.der, now: f.now) { _ in
            refused += 1
            return []
        }
        XCTAssertEqual(refused, 0)
        XCTAssertFalse(short.loggedIn)
        XCTAssertFalse(badOrigin.loggedIn)
    }

    func testSignerErrorIsUnavailable() async {
        struct Refused: LocalizedError { var errorDescription: String? { "PIN буруу" } }
        let f = Fixture()
        let verifier = LoginVerifier(trust: f.trust, fetcher: StubFetcher(f.answers()))
        let report = await verifier.run(origin: Fixture.origin, challenge: challenge, certificate: f.leaf.der, now: f.now) { _ in
            throw Refused()
        }
        XCTAssertEqual(report.checks.first?.status, .unavailable)
        XCTAssertEqual(report.checks.first?.reason, "PIN буруу")
        XCTAssertFalse(report.loggedIn)
    }

    func testFreshnessRule() {
        let now = Date()
        XCTAssertFalse(Freshness.isStale(thisUpdate: now - 3 * Fixture.day, nextUpdate: now + Fixture.day, now: now))
        XCTAssertFalse(Freshness.isStale(thisUpdate: now - 3000, nextUpdate: nil, now: now))
        XCTAssertTrue(Freshness.isStale(thisUpdate: now - 3700, nextUpdate: nil, now: now))
        XCTAssertTrue(Freshness.isFuture(thisUpdate: now + 600, now: now))
        XCTAssertFalse(Freshness.isFuture(thisUpdate: now + 300, now: now))
        XCTAssertTrue(Freshness.isStale(thisUpdate: now - 3600, nextUpdate: now - 600, now: now))
        XCTAssertFalse(Freshness.isStale(thisUpdate: now - 3600, nextUpdate: now - 300, now: now))
    }
}

final class FetcherTests: XCTestCase {
    private func fetch(_ server: LoopbackHTTPServer, maxBytes: Int = URLSessionRevocationFetcher.defaultMaxBytes,
                       timeout: TimeInterval = 10) async throws -> Data {
        let url = try XCTUnwrap(URL(string: "http://127.0.0.1:\(server.port)/crl"))
        return try await URLSessionRevocationFetcher(maxBytes: maxBytes, timeout: timeout)
            .fetch(RevocationRequest(url: url, body: nil, contentType: nil, accept: CRLCheck.accept))
    }

    func testPlainAnswer() async throws {
        let server = try await LoopbackHTTPServer(text: { _ in "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" })
        defer { server.stop() }
        let data = try await fetch(server)
        XCTAssertEqual(data, Data("ok".utf8))
    }

    func testRedirectIsNotFollowed() async throws {
        let server = try await LoopbackHTTPServer(text: { line in
            line.hasPrefix("GET /moved ")
                ? "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                : "HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        })
        defer { server.stop() }
        do {
            _ = try await fetch(server)
            XCTFail("the redirect was followed")
        } catch {
            XCTAssertEqual(error as? RevocationFetchError, .httpStatus(302))
        }
        XCTAssertEqual(server.requestLines, ["GET /crl HTTP/1.1"])
    }

    /// The size cap is counted while reading (no Content-Length announced).
    func testSizeCap() async throws {
        let body = String(repeating: "x", count: 4096)
        let server = try await LoopbackHTTPServer(text: { _ in "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body })
        defer { server.stop() }
        do {
            _ = try await fetch(server, maxBytes: 1024)
            XCTFail("over the size cap")
        } catch {
            XCTAssertEqual(error as? RevocationFetchError, .tooLarge)
        }
    }

    /// Content-Length over the cap: refused (before or while reading the body — either way `tooLarge`).
    func testAnnouncedLengthOverTheCap() async throws {
        let server = try await LoopbackHTTPServer(answer: { _ in
            [LoopbackHTTPServer.Chunk("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n"
                                      + String(repeating: "x", count: 5000))]
        })
        defer { server.stop() }
        do {
            _ = try await fetch(server, maxBytes: 1024)
            XCTFail("over the size cap")
        } catch {
            XCTAssertEqual(error as? RevocationFetchError, .tooLarge)
        }
    }

    /// The deadline covers the whole exchange: a body that keeps trickling in is cut off.
    func testTotalTimeout() async throws {
        let server = try await LoopbackHTTPServer(answer: { _ in
            [LoopbackHTTPServer.Chunk("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")]
                + (0..<20).map { _ in LoopbackHTTPServer.Chunk("x", delay: 0.3) }
        })
        defer { server.stop() }
        let started = Date()
        do {
            _ = try await fetch(server, timeout: 1)
            XCTFail("the deadline was not enforced")
        } catch {
            XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        }
    }

    /// The connection drops in the middle of the body: an error (→ «шалгаж чадсангүй»), never partial data.
    func testIOErrorMidBody() async throws {
        let server = try await LoopbackHTTPServer(text: { _ in
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n" + String(repeating: "x", count: 10)
        })
        defer { server.stop() }
        do {
            let data = try await fetch(server)
            XCTFail("partial body returned (\(data.count) bytes)")
        } catch {}
    }

    func testOnlyHTTPURLs() async {
        do {
            _ = try await URLSessionRevocationFetcher().fetch(
                RevocationRequest(url: URL(string: "file:///etc/hosts")!, body: nil, contentType: nil, accept: CRLCheck.accept))
            XCTFail("file URL fetched")
        } catch {
            XCTAssertEqual(error as? RevocationFetchError, .unsupportedURL)
        }
    }
}
