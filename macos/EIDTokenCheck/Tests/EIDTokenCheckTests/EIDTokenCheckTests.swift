import CryptoKit
import XCTest
@testable import EIDTokenCheck

/// A negative result: its status AND its reason (prefix — dates and names follow some reasons).
func assertCheck(_ r: CheckResult, _ status: CheckStatus, _ reasonPrefix: String,
                 file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertEqual(r.status, status, r.reason, file: file, line: line)
    XCTAssertTrue(r.reason.hasPrefix(reasonPrefix), "«\(r.reason)» does not start with «\(reasonPrefix)»", file: file, line: line)
}

enum Reason {
    static let notTrusted = "Итгэмжлэгдсэн үндэс хүртэл гинж баталгаажсангүй"
    static let not04 = "Гэрчилгээг eID Mongolia Issuing CA (04) шууд олгоогүй"
    static let keyUsageMissing = "AUTH профайл: KeyUsage өргөтгөл алга"
    static let keyUsageOnly = "AUTH профайл: KeyUsage нь зөвхөн digitalSignature байх ёстой"
    static let ekuMissing = "AUTH профайл: ExtendedKeyUsage өргөтгөл алга"
    static let noClientAuth = "AUTH профайл: ExtendedKeyUsage-д clientAuth алга"
    static let serialNumber = "AUTH профайл: subject serialNumber нь PNOMN- угтвартай ганц утга байх ёстой"
    static let wrongKey = "Гарын үсэг AUTH гэрчилгээний түлхүүртэй таарахгүй"
    static let ocspMalformed = "OCSP хариу задрахгүй байна"
    static let crlMalformed = "CRL задрахгүй байна"
    static let unknownSigner = "OCSP хариуг хэн зурсан нь тодорхойгүй (responderID таарахгүй)"
    static let certIDMismatch = "OCSP хариунд энэ гэрчилгээний төлөв алга (CertID таарахгүй)"
}

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
        XCTAssertNil(ParsedCertificate(der: [0x30, 0x00]))
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

    /// Dates that do not exist, and non-DER time forms, are rejected (the same on Windows).
    func testImpossibleDatesAndNonDERTimesAreRejected() {
        func utc(_ s: String) -> Date? { DER.time(DERNode(tag: 0x17, raw: [], value: Array(s.utf8))) }
        func gen(_ s: String) -> Date? { DER.time(DERNode(tag: 0x18, raw: [], value: Array(s.utf8))) }
        XCTAssertNil(utc("260230120000Z"))                     // 30 February
        XCTAssertNil(utc("250229120000Z"))                     // 29 February, not a leap year
        XCTAssertNotNil(utc("240229120000Z"))                  // 29 February 2024
        XCTAssertNil(utc("260431120000Z"))                     // 31 April
        XCTAssertNil(utc("261231235960Z"))                     // second 60
        XCTAssertNil(utc("2612312359Z"))                       // no seconds
        XCTAssertNil(utc("261231235959+0000"))                 // not Z
        XCTAssertNil(gen("20261114120000.120Z"))               // trailing zero in the fraction
        XCTAssertNil(gen("20261114120000.Z"))                  // empty fraction
        XCTAssertNil(gen("20261114120000,1Z"))                 // comma
    }

    func testOIDEncoding() {
        XCTAssertTrue(DER.isValidOID(OID.keyUsage))
        XCTAssertTrue(DER.isValidOID(OID.ecdsaWithSHA256))
        XCTAssertFalse(DER.isValidOID([]))
        XCTAssertFalse(DER.isValidOID([0x55, 0x1D, 0x8F]))              // last byte continues
        XCTAssertFalse(DER.isValidOID([0x55, 0x80, 0x1D]))              // sub-identifier starts with 0x80
        XCTAssertFalse(DER.isValidOID([0x80, 0x01]))
    }

    func testDERBooleanAndInteger() {
        XCTAssertEqual(DER.boolean(DERNode(tag: 0x01, raw: [], value: [0xFF])), true)
        XCTAssertEqual(DER.boolean(DERNode(tag: 0x01, raw: [], value: [0x00])), false)
        XCTAssertNil(DER.boolean(DERNode(tag: 0x01, raw: [], value: [0x01])))
        XCTAssertNil(DER.boolean(DERNode(tag: 0x01, raw: [], value: [0xFF, 0x00])))
        XCTAssertTrue(DER.isMinimalInteger([0x00, 0x80]))
        XCTAssertFalse(DER.isMinimalInteger([0x00, 0x7F]))
        XCTAssertFalse(DER.isMinimalInteger([0xFF, 0x80]))
        XCTAssertFalse(DER.isMinimalInteger([]))
    }

    /// Only one strict DER certificate is accepted: PEM, PKCS#7, PFX, trailing bytes, empty input, a BOOLEAN that
    /// is not 0xFF / 0x00, or a date that does not exist → nil (and ✗ in the verifier, below).
    func testOnlyOneStrictDERCertificate() {
        let f = Fixture()
        XCTAssertNotNil(ParsedCertificate(der: f.leaf.der))
        for (name, bytes) in Self.nonCertificates(f) {
            XCTAssertNil(ParsedCertificate(der: bytes), name)
        }
    }

    /// Inputs that a lenient loader would accept as a certificate, or that are not DER.
    static func nonCertificates(_ f: Fixture) -> [(String, [UInt8])] {
        let pem = "-----BEGIN CERTIFICATE-----\n" + Data(f.leaf.der).base64EncodedString(options: .lineLength64Characters)
            + "\n-----END CERTIFICATE-----\n"
        let signedData: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]
        let data: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]
        let pkcs7 = E.seq(E.oid(signedData), E.ctx(0, E.seq(E.int([1]), E.tlv(0x31, []), E.seq(E.oid(data)),
                                                             E.ctx(0, f.leaf.der), E.tlv(0x31, []))))
        let pfx = E.seq(E.int([3]), E.seq(E.oid(data), E.ctx(0, E.octet(E.seq(f.leaf.der)))))
        // The leaf's notBefore (UTCTime) rewritten to 30 February; the CA's critical BOOLEAN 0xFF rewritten to 0x01.
        let notBefore = E.utc(f.leaf.parsed.notBefore)
        let impossible = replacingFirst(notBefore, with: E.tlv(0x17, Array("260230120000Z".utf8)), in: f.leaf.der)
        let booleanOne = replacingFirst([0x01, 0x01, 0xFF], with: [0x01, 0x01, 0x01], in: f.ca.der)
        // The KeyUsage extension's OID 2.5.29.15 with a non-minimal first sub-identifier (0x80 …).
        let badOID = replacingFirst([0x06, 0x03, 0x55, 0x1D, 0x0F], with: [0x06, 0x03, 0x80, 0x1D, 0x0F], in: f.leaf.der)
        return [("PEM", Array(pem.utf8)), ("PKCS#7", pkcs7), ("PFX", pfx), ("trailing byte", f.leaf.der + [0x00]),
                ("two certificates", f.leaf.der + f.ca.der), ("empty", []), ("30 February", impossible),
                ("BOOLEAN 0x01", booleanOne), ("non-minimal OID", badOID)]
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

    /// no public API verifies a caller-supplied digest (compile-time: `SignatureVerifier.verifyP256` is internal;
    /// only the (origin, challenge) path exists for callers).
    func testDigestIsAlwaysComputedHere() {
        let f = Fixture()
        let digest = Array(SHA256.hash(data: challenge))
        let overDigest = Array(try! f.leaf.key.signature(for: SHA256.hash(data: challenge)).rawRepresentation)
        XCTAssertTrue(SignatureVerifier.verifyP256(point: f.leaf.parsed.subjectPublicKey, digest: digest, rawSignature: overDigest))
        assertCheck(check(f, overDigest), .failed, Reason.wrongKey)
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
        assertCheck(check(f, f.bareSignature(challenge: challenge)), .failed, Reason.wrongKey)
    }

    func testOtherOriginFails() {
        let f = Fixture()
        assertCheck(check(f, f.tokenSignature(origin: "other.test.invalid", challenge: challenge)), .failed, Reason.wrongKey)
        assertCheck(check(f, origin: "other.test.invalid", f.tokenSignature(challenge: challenge)), .failed, Reason.wrongKey)
        assertCheck(check(f, origin: "Other.test.invalid", f.tokenSignature(challenge: challenge)), .failed, Origin.invalidReason)
    }

    func testOtherKeyOrOtherChallengeOrLengthFails() {
        let f = Fixture()
        let good = f.tokenSignature(challenge: challenge)
        assertCheck(check(f, f.tokenSignature(challenge: [UInt8](repeating: 8, count: 32))), .failed, Reason.wrongKey)
        assertCheck(check(f, f.tokenSignature(challenge: challenge, key: P256.Signing.PrivateKey())), .failed, Reason.wrongKey)
        assertCheck(check(f, Array(good.prefix(63))), .failed, "Гарын үсгийн урт 63 байт")
        assertCheck(check(f, good + [0]), .failed, "Гарын үсгийн урт 65 байт")
        let der = Array(try! f.leaf.key.signature(for: Data()).derRepresentation)        // DER is not accepted
        assertCheck(check(f, der), .failed, "Гарын үсгийн урт \(der.count) байт")
    }

    func testZeroOrOutOfRangeScalarsFail() {
        let f = Fixture()
        let good = f.tokenSignature(challenge: challenge)
        let zeroR = [UInt8](repeating: 0, count: 32) + good[32...]
        let zeroS = Array(good[..<32]) + [UInt8](repeating: 0, count: 32)
        let scalar = "Гарын үсгийн r эсвэл s хүчингүй (0 эсвэл ≥ n)"
        assertCheck(check(f, zeroR), .failed, scalar)
        assertCheck(check(f, zeroS), .failed, scalar)
        assertCheck(check(f, P256Scalar.order + Array(good[32...])), .failed, scalar)
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
        assertCheck(chain(f, trust: trust), .failed, Reason.notTrusted)
    }

    func testMissingIntermediateIsRejected() {
        let f = Fixture()
        assertCheck(chain(f, trust: TrustStore(anchors: [f.root.der], intermediates: [f.ca.der], issuingCA: f.ca.der)),
                    .failed, Reason.notTrusted)
    }

    func testNoAnchorsOrNoIssuingCACannotBeChecked() {
        let f = Fixture()
        assertCheck(chain(f, trust: TrustStore(anchors: [], intermediates: [f.ca.der], issuingCA: f.ca.der)),
                    .unavailable, "Итгэлийн үндэс (trust anchor) апп-д алга")
        assertCheck(chain(f, trust: TrustStore(anchors: [f.root.der], intermediates: [f.national.der, f.intermediate.der],
                                               issuingCA: f.ca.der)), .unavailable, "Олгогч CA (04) апп-д алга")
    }

    func testEndEntityFromANonIssuingCAIsRejected() {
        for level in [Fixture.Level.national, .intermediate, .root] {          // ≙ 02, 03, 01
            let f = Fixture(leafIssuer: level)
            assertCheck(chain(f), .failed, Reason.not04)
        }
    }

    /// The REAL 04 is pinned; an impostor CA with the same subject but another key, chained under the same root,
    /// issues the AUTH certificate: the issuer pin rejects it (and OCSP / CRL have no issuer for it).
    func testSameSubjectDifferentKeyIssuerIsRejected() {
        let f = Fixture()
        let impostor = f.issuingCACopy(sameKey: false)
        let leaf = f.authLeaf(issuedBy: impostor)
        let trust = TrustStore(anchors: [f.root.der], intermediates: [f.national.der, f.intermediate.der, f.ca.der, impostor.der],
                               issuingCA: f.ca.der)
        let r = ChainCheck.chain(leaf: leaf.parsed, trust: trust, now: f.now)
        assertCheck(r.result, .failed, Reason.not04)
        XCTAssertNil(trust.issuingCA(of: leaf.parsed))
    }

    /// The pinned 04 has expired while a valid copy with the same subject and key exists: the chain row fails —
    /// validity is judged on the pinned certificate, a copy does not stand in for it.
    func testExpiredPinned04WithValidSameKeyCopyFails() {
        let f = Fixture()
        let expiredPinned = f.issuingCACopy(sameKey: true, serial: 0x45, notBefore: f.now - 400 * Fixture.day,
                                            notAfter: f.now - Fixture.day)
        let trust = TrustStore(anchors: [f.root.der],
                               intermediates: [f.national.der, f.intermediate.der, expiredPinned.der, f.ca.der],
                               issuingCA: expiredPinned.der)
        assertCheck(ChainCheck.chain(leaf: f.leaf.parsed, trust: trust, now: f.now).result, .failed,
                    "Гинжний гэрчилгээ (TEST ONLY Issuing CA) хүчинтэй хугацаанаас гадуур")
    }

    /// another copy of 04 (same subject and key, different DER) among the candidates is neither used nor a
    /// reason to refuse: the path passes and carries the PINNED 04 DER.
    func testLegacyCopyOf04IsNeitherUsedNorRefused() {
        let f = Fixture()
        let legacy = f.issuingCACopy(sameKey: true)
        XCTAssertNotEqual(legacy.der, f.ca.der)
        let trust = TrustStore(anchors: [f.root.der], intermediates: [f.national.der, f.intermediate.der, legacy.der, f.ca.der],
                               issuingCA: f.ca.der)
        let r = ChainCheck.chain(leaf: f.leaf.parsed, trust: trust, now: f.now)
        XCTAssertEqual(r.result.status, .passed, r.result.reason)
        XCTAssertEqual(r.chain.map(\.der), [f.leaf.der, f.ca.der, f.intermediate.der, f.national.der, f.root.der])
    }

    /// an expired CA in the path fails the CHAIN row (the same on Windows).
    func testExpiredIntermediateFailsTheChain() {
        let probe = Fixture()
        let f = Fixture(intermediateNotAfter: probe.now - Fixture.day)
        assertCheck(chain(f), .failed, "Гинжний гэрчилгээ (TEST ONLY Intermediate CA) хүчинтэй хугацаанаас гадуур")
    }

    /// ≙05 issues relying-party mTLS certificates with clientAuth: even with digitalSignature + clientAuth +
    /// PNOMN- and 05 in the bundled set, only the pinned 04 may issue an AUTH certificate.
    func testCertificateFromTheOrganizationCAIsRejected() {
        let f = Fixture(leafIssuer: .org)
        let r = chain(f, trust: f.trust(withOrg: true))
        assertCheck(r, .failed, Reason.not04)
    }

    /// nonRepudiation alone disqualifies: the SIGN fixture carries clientAuth and PNOMN-.
    func testSignCertificateIsNotAuth() {
        let f = Fixture(leafKeyUsage: TestPKI.signKeyUsage)
        assertCheck(chain(f), .failed, Reason.keyUsageOnly)
    }

    func testKeyUsageWithAnExtraBitIsNotAuth() {
        let f = Fixture(leafKeyUsage: TestPKI.authPlusKeyEnciphermentKeyUsage)
        assertCheck(chain(f), .failed, Reason.keyUsageOnly)
    }

    func testSerialNumberMustStartWithPNOMN() {
        assertCheck(chain(Fixture(leafSerialNumber: "NTRMN-TEST0001")), .failed, Reason.serialNumber)
        assertCheck(chain(Fixture(leafSerialNumber: "RP-TEST0001")), .failed, Reason.serialNumber)
        assertCheck(chain(Fixture(leafSerialNumber: nil)), .failed, Reason.serialNumber)
    }

    func testOCSPResponderCertificateIsNotAuth() {
        let f = Fixture()
        assertCheck(chain(f, leaf: f.responder), .failed, Reason.noClientAuth)
    }

    func testMissingKeyUsageOrEKUFails() {
        assertCheck(chain(Fixture(leafKeyUsage: nil)), .failed, Reason.keyUsageMissing)
        assertCheck(chain(Fixture(leafEKU: nil)), .failed, Reason.ekuMissing)
        assertCheck(chain(Fixture(leafEKU: TestPKI.eku(OID.ekuEmailProtection))), .failed, Reason.noClientAuth)
    }

    func testExpiredLeafFailsValidityNotChain() {
        let now = Date()
        let f = Fixture(leafNotBefore: now - 400 * Fixture.day, leafNotAfter: now - Fixture.day)
        let r = ChainCheck.chain(leaf: f.leaf.parsed, trust: f.trust, now: f.now)
        XCTAssertEqual(r.result.status, .passed, r.result.reason)
        assertCheck(ChainCheck.validity(chain: r.chain, now: f.now), .failed, "Гэрчилгээний хугацаа ")
        let notYet = Fixture(leafNotBefore: now + Fixture.day, leafNotAfter: now + 30 * Fixture.day)
        let early = ChainCheck.validity(chain: [notYet.leaf.parsed], now: notYet.now)
        assertCheck(early, .failed, "Гэрчилгээ ")
        XCTAssertTrue(early.reason.hasSuffix("-аас хүчинтэй болно"), early.reason)
    }

    /// notAfter is inclusive: valid AT notAfter, expired one second later.
    func testNotAfterBoundaryIsInclusive() {
        let probe = Fixture()
        let f = Fixture(leafNotBefore: probe.now - Fixture.day, leafNotAfter: probe.now + 60)
        let notAfter = f.leaf.parsed.notAfter
        XCTAssertEqual(ChainCheck.validity(chain: [f.leaf.parsed], now: notAfter).status, .passed)
        assertCheck(ChainCheck.validity(chain: [f.leaf.parsed], now: notAfter + 1), .failed, "Гэрчилгээний хугацаа ")
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
        let store = try TrustStore.load(directory: dir)
        XCTAssertEqual(store.anchors, [f.root.der])
        XCTAssertEqual(store.intermediates, [f.national.der, f.intermediate.der, f.ca.der])
        XCTAssertNil(store.issuingCA)                     // the test CA is not the pinned 04
        XCTAssertNil(TrustStore(anchors: [], intermediates: [], issuingCA: f.ca.der).issuingCA)
        // the public initializer enforces the pin — a test CA can only be injected through the internal one.
        XCTAssertNil(try TrustStore(anchors: [f.root.der], intermediates: [f.national.der, f.intermediate.der, f.ca.der]).issuingCA)
        XCTAssertEqual(f.trust.issuingCA(of: f.leaf.parsed)?.der, f.ca.der)
        XCTAssertNil(f.trust.issuingCA(of: f.ca.parsed))
    }

    /// A certificate file in trust/ that is not one strict DER certificate stops loading with an error naming the file
    /// (the same on Windows) — never silently skipped. Also the public initializer.
    func testBrokenTrustFolderFailsLoudly() throws {
        let f = Fixture()
        let cases: [(String, Data)] = [
            ("intermediates/bad.pem", Data("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n".utf8)),
            ("intermediates/empty.pem", Data("-----BEGIN CERTIFICATE-----\n".utf8)),
            ("intermediates/trailing.der", Data(f.ca.der + [0x00])),
            ("anchors/boolean.cer", Data(replacingFirst([0x01, 0x01, 0xFF], with: [0x01, 0x01, 0x01], in: f.root.der))),
        ]
        for (path, data) in cases {
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("eid-trust-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: dir) }
            try FileManager.default.createDirectory(at: dir.appendingPathComponent("anchors"), withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: dir.appendingPathComponent("intermediates"), withIntermediateDirectories: true)
            if !path.hasPrefix("anchors/") { try Data(f.root.der).write(to: dir.appendingPathComponent("anchors/root.der")) }
            try data.write(to: dir.appendingPathComponent(path))
            XCTAssertThrowsError(try TrustStore.load(directory: dir), path) { error in
                XCTAssertEqual(error as? TrustStoreError, .notACertificate(path))
            }
        }
        XCTAssertThrowsError(try TrustStore(anchors: [f.root.der], intermediates: [f.ca.der + [0x00]]))
    }

    /// The shipped trust/ folder: one root, 02, 03, 04; 04 is the pinned issuing CA; every certificate is signed by
    /// its bundled parent (signatures only, no network).
    func testShippedTrustFolder() throws {
        let store = try TrustStore.load(directory: RepoTrust.directory)
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
        XCTAssertEqual(try TrustStore(anchors: store.anchors, intermediates: store.intermediates).issuingCA, issuing)
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
        assertCheck(eval(f, f.ocsp(certID: id)), .failed, Reason.certIDMismatch)
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
        assertCheck(eval(f, f.ocsp(), nonce: nonce, required: true), .failed, "OCSP хариунд nonce алга (AUTH гэрчилгээнд заавал)")
        assertCheck(eval(f, f.ocsp(nonceExt: E.octet(other)), nonce: nonce, required: true), .failed,
                    "OCSP хариуны nonce манай хүсэлтийнхтэй таарахгүй")
    }

    /// Issuing-CA check (pre-signed answers): the nonce is optional, but an echoed one must still match.
    func testNonceOptionalForTheIssuingCA() {
        let f = Fixture()
        let nonce = [UInt8](repeating: 0x11, count: 32), other = [UInt8](repeating: 0x22, count: 32)
        XCTAssertEqual(eval(f, f.ocsp(), nonce: nonce, required: false).status, .passed)
        assertCheck(eval(f, f.ocsp(nonceExt: E.octet(other)), nonce: nonce, required: false), .failed,
                    "OCSP хариуны nonce манай хүсэлтийнхтэй таарахгүй")
    }

    func testRevokedAndUnknownFail() {
        let f = Fixture()
        assertCheck(eval(f, f.ocsp(status: .revoked(f.now - 3600), signer: f.responder)), .failed, "Гэрчилгээ цуцлагдсан (")
        assertCheck(eval(f, f.ocsp(status: .unknown, signer: f.responder)), .failed,
                    "OCSP: unknown — responder энэ гэрчилгээг танихгүй")
    }

    /// Order: revoked is reported before freshness, freshness before unknown (the same on Windows).
    func testStatusAndFreshnessOrder() {
        let f = Fixture()
        let staleRevoked = eval(f, f.ocsp(status: .revoked(f.now - 3 * Fixture.day), thisUpdate: f.now - 3 * Fixture.day,
                                          nextUpdate: f.now - 2 * Fixture.day))
        assertCheck(staleRevoked, .failed, "Гэрчилгээ цуцлагдсан")
        let staleUnknown = eval(f, f.ocsp(status: .unknown, thisUpdate: f.now - 3 * Fixture.day, nextUpdate: f.now - 2 * Fixture.day))
        assertCheck(staleUnknown, .failed, "OCSP хариу хуучирсан")
    }

    func testBadSignatureFails() {
        let f = Fixture()
        assertCheck(eval(f, f.ocsp(signer: f.responder, tamper: true)), .failed, "OCSP хариуны гарын үсэг буруу")
    }

    func testResponderMustBeAuthorised() {
        // Responder certificate without id-kp-OCSPSigning.
        let f = Fixture(responderEKU: false)
        assertCheck(eval(f, f.ocsp(signer: f.responder)), .failed, "OCSP responder-ийн гэрчилгээнд id-kp-OCSPSigning алга")
        // Responder certificate not embedded: unknown signer.
        assertCheck(eval(f, f.ocsp(signer: f.responder, embedSigner: false)), .failed, Reason.unknownSigner)
    }

    func testResponderIssuedByAnotherCAFails() {
        let f = Fixture(), other = Fixture()
        assertCheck(eval(f, f.ocsp(signer: other.responder)), .failed,
                    "OCSP responder-ийн гэрчилгээг энэ гэрчилгээний олгогч олгоогүй")
    }

    func testExpiredOrNotYetValidResponderFails() {
        let probe = Fixture()
        let expired = Fixture(responderNotBefore: probe.now - 30 * Fixture.day, responderNotAfter: probe.now - Fixture.day)
        let outside = "OCSP responder-ийн гэрчилгээ хүчинтэй хугацаанаас гадуур"
        assertCheck(eval(expired, expired.ocsp(signer: expired.responder)), .failed, outside)
        let notYet = Fixture(responderNotBefore: probe.now + Fixture.day, responderNotAfter: probe.now + 30 * Fixture.day)
        assertCheck(eval(notYet, notYet.ocsp(signer: notYet.responder)), .failed, outside)
    }

    func testFreshnessWindow() {
        let f = Fixture()
        assertCheck(eval(f, f.ocsp(thisUpdate: f.now - 3 * Fixture.day, nextUpdate: f.now - Fixture.day)), .failed,
                    "OCSP хариу хуучирсан")
        assertCheck(eval(f, f.ocsp(thisUpdate: f.now + 3600)), .failed, "OCSP хариу ирээдүйн огноотой")
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now + 120)).status, .passed)                         // skew
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: f.now - 120)).status, .passed)  // skew
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: f.now - 300)).status, .passed)  // inclusive
        assertCheck(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: f.now - 301)), .failed, "OCSP хариу хуучирсан")
        assertCheck(eval(f, f.ocsp(thisUpdate: f.now - 2 * 3600, nextUpdate: .some(nil))), .failed, "OCSP хариу хуучирсан")
        XCTAssertEqual(eval(f, f.ocsp(thisUpdate: f.now - 600, nextUpdate: .some(nil))).status, .passed)
    }

    func testResponseForAnotherCertificateFails() {
        let f = Fixture()
        assertCheck(eval(f, f.ocsp(certID: f.certID(serial: [0x05]))), .failed, Reason.certIDMismatch)
        assertCheck(eval(f, f.ocsp(certID: f.certID(issuerName: f.root.name))), .failed, Reason.certIDMismatch)
    }

    /// entries about other certificates — even malformed ones — are skipped; the matching entry decides.
    func testOtherEntriesAreSkippedEvenWhenMalformed() {
        let f = Fixture()
        let other = E.seq(f.certID(serial: [0x05]), [0x80, 0x00], E.gtime(f.now - 60))
        let garbage = E.seq(E.int([5]))                                            // no CertID at all
        let brokenCertID = E.seq(E.seq(E.seq(E.oid(OID.sha256), E.null), E.int([1])), [0x80, 0x00])
        let r = eval(f, f.ocsp(otherSingles: [garbage, brokenCertID, other]))
        XCTAssertEqual(r.status, .passed, r.reason)
    }

    /// a malformed entry for THIS certificate is ✗.
    func testMalformedMatchingEntryFails() {
        let f = Fixture()
        assertCheck(eval(f, f.ocsp(singleSuffix: E.int([1]))), .failed, Reason.ocspMalformed)        // trailing element
        let goodWithContent = f.certID() + [0x80, 0x01, 0x00] + E.gtime(f.now - 60)                 // good [0] not empty
        assertCheck(eval(f, f.ocsp(otherSingles: [E.tlv(0x30, goodWithContent)], singleSuffix: E.int([1]))), .failed,
                    Reason.ocspMalformed)
        let revokedNoTime = E.tlv(0x30, f.certID() + E.ctx(1, []) + E.gtime(f.now - 60))
        assertCheck(eval(f, f.ocsp(otherSingles: [revokedNoTime])), .failed, Reason.ocspMalformed)
    }

    func testResponderErrorCannotBeCheckedButGarbageFails() {
        let f = Fixture()
        assertCheck(eval(f, f.ocsp(responseStatus: 3)), .unavailable, "OCSP responder амжилтгүй хариу өгсөн (responseStatus 3)")
        assertCheck(eval(f, [0x30, 0x00]), .failed, Reason.ocspMalformed)
        assertCheck(eval(f, [0x01, 0x02, 0x03]), .failed, Reason.ocspMalformed)
        assertCheck(eval(f, [0x30, 0x81, 0x03, 0x0A, 0x01, 0x00]), .failed, Reason.ocspMalformed)   // non-minimal length
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
        assertCheck(eval(f, f.crl(revoked: [[0x05], Fixture.leafSerial])), .failed, "Гэрчилгээ CRL-д цуцлагдсан (")
    }

    func testWrongSignerOrIssuerFails() {
        let f = Fixture()
        assertCheck(eval(f, f.crl(signerKey: f.root.key)), .failed, "CRL-ийн гарын үсэг олгогчийн түлхүүртэй таарахгүй")
        assertCheck(eval(f, f.crl(issuerName: f.root.name, signerKey: f.root.key)), .failed,
                    "CRL-ийг энэ гэрчилгээний олгогч гаргаагүй")
    }

    func testFreshnessWindow() {
        let f = Fixture()
        assertCheck(eval(f, f.crl(thisUpdate: f.now - 3 * Fixture.day, nextUpdate: f.now - Fixture.day)), .failed, "CRL хуучирсан")
        assertCheck(eval(f, f.crl(thisUpdate: f.now + 3600)), .failed, "CRL ирээдүйн огноотой")
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now - Fixture.day, nextUpdate: f.now - 120)).status, .passed)   // skew
        XCTAssertEqual(eval(f, f.crl(thisUpdate: f.now - Fixture.day, nextUpdate: f.now - 300)).status, .passed)   // inclusive
        assertCheck(eval(f, f.crl(thisUpdate: f.now - Fixture.day, nextUpdate: f.now - 301)), .failed, "CRL хуучирсан")
    }

    func testMissingNextUpdateCannotBeChecked() {
        let f = Fixture()
        assertCheck(eval(f, f.crl(nextUpdate: .some(nil))), .unavailable, "CRL-д nextUpdate алга")
    }

    func testDeltaIDPOrUnknownCriticalExtensionCannotBeUsed() {
        let f = Fixture()
        assertCheck(eval(f, f.crl(extensions: [Fixture.deltaCRLExtension])), .unavailable, "Delta CRL дэмжигдээгүй")
        assertCheck(eval(f, f.crl(extensions: [Fixture.issuingDistributionPointExtension])), .unavailable,
                    "issuingDistributionPoint-той CRL дэмжигдээгүй")
        assertCheck(eval(f, f.crl(extensions: [Fixture.unknownCriticalExtension])), .unavailable,
                    "CRL-д үл мэдэгдэх critical өргөтгөл байна")
        let crlNumber = E.ext(OID.crlNumber, E.int([7]))
        XCTAssertEqual(eval(f, f.crl(extensions: [crlNumber])).status, .passed)
    }

    /// A critical flag that is not DER (0x01 instead of 0xFF) makes the CRL unreadable (the same on Windows).
    func testNonDERBooleanFails() {
        let f = Fixture()
        let bad = E.seq(E.oid(OID.crlNumber), E.tlv(0x01, [0x01]), E.octet(E.int([7])))
        assertCheck(eval(f, f.crl(extensions: [bad])), .failed, Reason.crlMalformed)
    }

    func testGarbageFails() {
        let f = Fixture()
        assertCheck(eval(f, [0x30, 0x01, 0x00]), .failed, Reason.crlMalformed)
    }
}

final class LoginVerifierTests: XCTestCase {
    private let challenge = [UInt8](repeating: 1, count: 32)

    private func verify(_ f: Fixture, answers: [URL: Fixture.Answer]? = nil, trust: TrustStore? = nil,
                        certificate: [UInt8]? = nil, signature: [UInt8]? = nil, origin: String = Fixture.origin,
                        challenge: [UInt8]? = nil, failure: (any Error)? = nil) async -> (LoginReport, StubFetcher) {
        let stub = StubFetcher(answers ?? f.answers(), failure: failure)
        let challenge = challenge ?? self.challenge
        let report = await LoginVerifier(trust: trust ?? f.trust, fetcher: stub)
            .verify(origin: origin, challenge: challenge,
                    signature: signature ?? f.tokenSignature(challenge: challenge),
                    certificate: certificate ?? f.leaf.der, now: f.now)
        return (report, stub)
    }

    private func row(_ report: LoginReport, _ kind: CheckKind) -> CheckResult {
        report.checks.first { $0.kind == kind } ?? CheckResult(kind, .unavailable, "row missing")
    }

    /// The rejected-input report: signature ✗ with `reason`, every other row «шалгаж чадсангүй», not logged in.
    private func assertRejected(_ report: LoginReport, _ reason: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(report.checks.map(\.kind), CheckKind.allCases, file: file, line: line)
        assertCheck(row(report, .signature), .failed, reason, file: file, line: line)
        for check in report.checks.dropFirst() {
            assertCheck(check, .unavailable, LoginReport.notRunReason, file: file, line: line)
        }
        XCTAssertFalse(report.loggedIn, file: file, line: line)
        XCTAssertNil(report.subjectSerialNumber, file: file, line: line)
    }

    func testAllChecksPassOnlyWithTestEndpoints() async {
        let f = Fixture()
        let (report, stub) = await verify(f)
        XCTAssertEqual(report.checks.map(\.kind), CheckKind.allCases)
        XCTAssertTrue(report.loggedIn, report.failureReason ?? "")
        XCTAssertEqual(report.summary, "Нэвтэрлээ: Тест Хэрэглэгч")
        XCTAssertEqual(report.subjectName, "Тест Хэрэглэгч")
        XCTAssertEqual(report.subjectSerialNumber, "PNOMN-TEST0001")
        let requests = await stub.requests
        XCTAssertEqual(requests.map(\.url), [Fixture.caOCSPURL, Fixture.caCRLURL, Fixture.ocspURL, Fixture.crlURL])
        XCTAssertEqual(requests[2].contentType, "application/ocsp-request")
        XCTAssertNotNil(requests[2].body)
        XCTAssertNil(requests[3].body)
        XCTAssertTrue(report.checks[1].reason.contains("олгогч CA цуцлагдаагүй"), report.checks[1].reason)
    }

    func testInvalidOriginIsRejectedWithoutNetwork() async {
        let f = Fixture()
        let (report, stub) = await verify(f, origin: "https://rp.test.invalid")
        assertRejected(report, Origin.invalidReason)
        let requests = await stub.requests
        XCTAssertTrue(requests.isEmpty)
    }

    /// a challenge that is not exactly 32 bytes — even with a valid signature over it — is signature ✗, the
    /// rest «шалгаж чадсангүй», and NO network request.
    func testWrongLengthChallengeMakesNoNetworkRequest() async {
        let f = Fixture()
        for length in [0, 31, 33, 64] {
            let (report, stub) = await verify(f, challenge: [UInt8](repeating: 9, count: length))
            assertRejected(report, "Challenge \(length) байт (яг 32 байт байх ёстой)")
            let requests = await stub.requests
            XCTAssertTrue(requests.isEmpty, "length \(length)")
        }
    }

    /// anything but one strict DER certificate → signature ✗, no network.
    func testNonCertificateInputIsRejectedWithoutNetwork() async {
        let f = Fixture()
        for (name, bytes) in DERTests.nonCertificates(f) {
            let (report, stub) = await verify(f, certificate: bytes)
            assertRejected(report, "AUTH гэрчилгээг уншиж чадсангүй")
            let requests = await stub.requests
            XCTAssertTrue(requests.isEmpty, name)
        }
    }

    func testMissingNonceOnTheAuthOCSPIsNotLoggedIn() async {
        let f = Fixture()
        var answers = f.answers()
        answers[Fixture.ocspURL] = { _ in f.ocsp(signer: f.responder) }
        let (report, _) = await verify(f, answers: answers)
        assertCheck(row(report, .ocsp), .failed, "OCSP хариунд nonce алга (AUTH гэрчилгээнд заавал)")
        XCTAssertFalse(report.loggedIn)
        XCTAssertNil(report.subjectSerialNumber)
    }

    func testNetworkFailureFailsClosed() async {
        let f = Fixture()
        var answers = f.answers()
        answers[Fixture.ocspURL] = nil
        let (report, _) = await verify(f, answers: answers)
        assertCheck(row(report, .ocsp), .unavailable, "OCSP руу холбогдож чадсангүй (ocsp.test.invalid)")
        XCTAssertFalse(report.loggedIn)
        XCTAssertTrue(report.failureReason?.hasPrefix("OCSP —") == true, report.failureReason ?? "")
    }

    /// A connection lost in the middle of the body is «шалгаж чадсангүй», never a crash or a pass.
    func testIOErrorMidBodyIsUnavailable() async {
        let f = Fixture()
        var answers = f.answers()
        answers[Fixture.crlURL] = nil
        let (report, _) = await verify(f, answers: answers, failure: URLError(.networkConnectionLost))
        assertCheck(row(report, .crl), .unavailable, "CRL татаж чадсангүй (crl.test.invalid)")
        XCTAssertFalse(report.loggedIn)
    }

    func testWrongSignatureIsNotLoggedIn() async {
        let f = Fixture()
        let (report, _) = await verify(f, signature: f.tokenSignature(challenge: challenge, key: P256.Signing.PrivateKey()))
        assertCheck(row(report, .signature), .failed, Reason.wrongKey)
        XCTAssertFalse(report.loggedIn)
    }

    func testOldConstructionAndOtherOriginAreNotLoggedIn() async {
        let f = Fixture()
        let (bare, _) = await verify(f, signature: f.bareSignature(challenge: challenge))
        assertCheck(row(bare, .signature), .failed, Reason.wrongKey)
        XCTAssertFalse(bare.loggedIn)
        let (otherOrigin, _) = await verify(f, signature: f.tokenSignature(origin: "other.test.invalid", challenge: challenge))
        assertCheck(row(otherOrigin, .signature), .failed, Reason.wrongKey)
        XCTAssertFalse(otherOrigin.loggedIn)
    }

    func testSignOrgAndResponderCertificatesAreNotLoggedIn() async {
        let sign = Fixture(leafKeyUsage: TestPKI.signKeyUsage)
        let (signReport, _) = await verify(sign)
        assertCheck(row(signReport, .chain), .failed, Reason.keyUsageOnly)
        XCTAssertFalse(signReport.loggedIn)

        let org = Fixture(leafIssuer: .org)
        let (orgReport, _) = await verify(org, trust: org.trust(withOrg: true))
        XCTAssertEqual(row(orgReport, .signature).status, .passed)
        assertCheck(row(orgReport, .chain), .failed, Reason.not04)
        assertCheck(row(orgReport, .ocsp), .unavailable, "Олгогч CA (04) апп-д алга")    // not issued by the pinned 04
        XCTAssertFalse(orgReport.loggedIn)

        let f = Fixture()
        let responderSignature = Fixture.signRaw(origin: Fixture.origin, challenge: challenge, key: f.responder.key)
        let (responderReport, _) = await verify(f, certificate: f.responder.der, signature: responderSignature)
        XCTAssertEqual(row(responderReport, .signature).status, .passed)
        assertCheck(row(responderReport, .chain), .failed, Reason.noClientAuth)
        XCTAssertFalse(responderReport.loggedIn)
    }

    func testRevokedIssuingCAIsNotLoggedIn() async {
        let f = Fixture()
        var byOCSP = f.answers()
        byOCSP[Fixture.caOCSPURL] = { _ in f.ocsp(status: .revoked(f.now - 3600), subject: f.ca, issuer: f.intermediate) }
        let (ocspReport, _) = await verify(f, answers: byOCSP)
        assertCheck(row(ocspReport, .chain), .failed, "Олгогч CA (TEST ONLY Issuing CA) — OCSP: Гэрчилгээ цуцлагдсан")
        XCTAssertFalse(ocspReport.loggedIn)

        var byCRL = f.answers()
        byCRL[Fixture.caCRLURL] = { _ in f.crl(revoked: [f.ca.serial], issuer: f.intermediate) }
        let (crlReport, _) = await verify(f, answers: byCRL)
        assertCheck(row(crlReport, .chain), .failed, "Олгогч CA (TEST ONLY Issuing CA) — CRL: Гэрчилгээ CRL-д цуцлагдсан")
        XCTAssertFalse(crlReport.loggedIn)

        var unreachable = f.answers()
        unreachable[Fixture.caCRLURL] = nil
        let (offline, _) = await verify(f, answers: unreachable)
        assertCheck(row(offline, .chain), .unavailable, "Олгогч CA (TEST ONLY Issuing CA) — CRL: CRL татаж чадсангүй")
        XCTAssertFalse(offline.loggedIn)
    }

    /// Neither AIA nor CDP on the issuing CA: its revocation cannot be checked — not "not applicable".
    func testIssuingCAWithoutAIAAndCDPCannotBeChecked() async {
        let f = Fixture(caOCSP: false, caCRL: false)
        let (report, stub) = await verify(f)
        assertCheck(row(report, .chain), .unavailable, "Олгогч CA (TEST ONLY Issuing CA)-ийн гэрчилгээнд AIA ч CDP ч алга")
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

    /// an expired CA in the path fails the chain row in the full login as well.
    func testExpiredIntermediateIsNotLoggedIn() async {
        let probe = Fixture()
        let f = Fixture(intermediateNotAfter: probe.now - Fixture.day)
        let (report, _) = await verify(f)
        assertCheck(row(report, .chain), .failed, "Гинжний гэрчилгээ (TEST ONLY Intermediate CA) хүчинтэй хугацаанаас гадуур")
        XCTAssertFalse(report.loggedIn)
    }

    func testUnknownIssuerCannotCheckRevocation() async {
        let f = Fixture()
        let (report, stub) = await verify(f, trust: try! TrustStore(anchors: [f.root.der], intermediates: []))
        assertCheck(row(report, .chain), .unavailable, "Олгогч CA (04) апп-д алга")
        assertCheck(row(report, .ocsp), .unavailable, "Олгогч CA (04) апп-д алга")
        assertCheck(row(report, .crl), .unavailable, "Олгогч CA (04) апп-д алга")
        XCTAssertFalse(report.loggedIn)
        let requests = await stub.requests
        XCTAssertTrue(requests.isEmpty)
    }

    func testRunSignsOnceAfterThePreconditions() async {
        let f = Fixture()
        let stub = StubFetcher(f.answers())
        let verifier = LoginVerifier(trust: f.trust, fetcher: stub)
        var calls = 0
        let report = await verifier.run(origin: Fixture.origin, challenge: challenge, certificate: f.leaf.der, now: f.now) { digest in
            calls += 1
            return Array(try f.leaf.key.signature(for: Data(digest)).rawRepresentation)
        }
        XCTAssertEqual(calls, 1)
        assertCheck(row(report, .signature), .failed, Reason.wrongKey)   // signature(for: Data) hashes again: wrong digest
        let before = await stub.requests.count
        var refused = 0
        let short = await verifier.run(origin: Fixture.origin, challenge: [1, 2, 3], certificate: f.leaf.der, now: f.now) { _ in
            refused += 1
            return []
        }
        let badOrigin = await verifier.run(origin: "RP.test", challenge: challenge, certificate: f.leaf.der, now: f.now) { _ in
            refused += 1
            return []
        }
        let badCertificate = await verifier.run(origin: Fixture.origin, challenge: challenge, certificate: f.leaf.der + [0],
                                                now: f.now) { _ in
            refused += 1
            return []
        }
        XCTAssertEqual(refused, 0)
        assertRejected(short, "Challenge 3 байт (яг 32 байт байх ёстой)")
        assertRejected(badOrigin, Origin.invalidReason)
        assertRejected(badCertificate, "AUTH гэрчилгээг уншиж чадсангүй")
        let after = await stub.requests.count
        XCTAssertEqual(before, after)
    }

    func testSignerErrorIsUnavailable() async {
        struct Refused: LocalizedError { var errorDescription: String? { "PIN буруу" } }
        let f = Fixture()
        let verifier = LoginVerifier(trust: f.trust, fetcher: StubFetcher(f.answers()))
        let report = await verifier.run(origin: Fixture.origin, challenge: challenge, certificate: f.leaf.der, now: f.now) { _ in
            throw Refused()
        }
        assertCheck(row(report, .signature), .unavailable, "PIN буруу")
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
