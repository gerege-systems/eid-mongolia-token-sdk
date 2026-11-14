import EIDTokenCheck
import XCTest
@testable import EIDTokenCLI
@testable import EIDTokenReader

/// A token that never touches hardware. Records every signDigest call.
final class FakeSource: TokenSource {
    var tokenList: [TokenInfo]
    var certificateList: [TokenCertificate]
    private(set) var signCalls = 0

    init(tokens: [TokenInfo], certificates: [TokenCertificate] = []) {
        tokenList = tokens
        certificateList = certificates
    }

    func tokens() throws -> [TokenInfo] { tokenList }
    func certificates(serial: String) throws -> [TokenCertificate] { certificateList }
    func signDigest(serial: String, keyID: [UInt8], digest: [UInt8], pin: String) throws -> [UInt8] {
        signCalls += 1
        throw TokenError.pinIncorrect
    }
}

struct FakePIN: PinInput {
    var isTerminal = false
    var pin: String? = "1234"
    func readPIN() -> String? { pin }
}

final class Output {
    var out: [String] = []
    var err: [String] = []
}

final class ArgumentTests: XCTestCase {
    func testListing() {
        XCTAssertEqual(CLIArguments.parse(["--module", "/m.so"]), .run(CLIOptions(modulePath: "/m.so")))
        XCTAssertEqual(CLIArguments.parse(["--module", "/m.so", "--serial", "S1", "--json"]),
                       .run(CLIOptions(modulePath: "/m.so", serial: "S1", json: true)))
        XCTAssertEqual(CLIArguments.parse(["--help"]), .help)
    }

    func testLogin() {
        XCTAssertEqual(CLIArguments.parse(["--module", "/m.so", "--serial", "S1", "--origin", "rp.example.mn", "--login"]),
                       .run(CLIOptions(modulePath: "/m.so", serial: "S1", origin: "rp.example.mn", login: true)))
    }

    func testLoginWithoutSerialIsRefused() {
        XCTAssertEqual(CLIArguments.parse(["--module", "/m.so", "--login"]), .usage(CLIArguments.serialRequired))
    }

    func testPINOnTheCommandLineIsRefused() {
        for args in [["--module", "/m.so", "--serial", "S1", "--login", "--pin", "1234"],
                     ["--module", "/m.so", "--serial", "S1", "--login", "--pin=1234"],
                     ["--module", "/m.so", "--PIN", "1234"]] {
            XCTAssertEqual(CLIArguments.parse(args), .usage(CLIArguments.pinOnCommandLine), "\(args)")
        }
    }

    func testOtherUsageErrors() {
        let cases: [([String], String)] = [
            ([], "--module <opensc-pkcs11 зам> заавал"), (["--serial", "S1"], "--module <opensc-pkcs11 зам> заавал"),
            (["--module"], "--module-ийн утга (модулийн зам) алга"),
            (["--module", "/m.so", "extra"], CLIArguments.unknownArgument),
            (["--module", "/m.so", "--bogus"], CLIArguments.unknownArgument),
            (["--module", "/m.so", "--module", "/n.so"], "--module давхар өгөгдсөн"),
            (["--module", "/m.so", "--origin", "https://rp.example.mn"], Origin.invalidReason),
            (["--module", "/m.so", "--origin", "RP.example.mn"], Origin.invalidReason),
            (["--module", "/m.so", "--origin", "rp.example.mn:443"], Origin.invalidReason),
            (["--module", "/m.so", "--serial"], "--serial-ийн утга алга"),
        ]
        for (args, reason) in cases {
            XCTAssertEqual(CLIArguments.parse(args), .usage(reason), "\(args)")
        }
    }

    /// an unknown or positional argument is never printed back (it may be a PIN typed in the wrong place).
    func testUnknownArgumentIsNotEchoed() {
        XCTAssertEqual(CLIArguments.parse(["--module", "/m.so", "--serial", "S1", "--login", "482913"]),
                       .usage(CLIArguments.unknownArgument))
        XCTAssertFalse(CLIArguments.unknownArgument.contains("482913"))
    }
}

final class RefusalTests: XCTestCase {
    static let flagsOK: UInt = TokenInfo.CKF_TOKEN_INITIALIZED | TokenInfo.CKF_USER_PIN_INITIALIZED

    private func token(_ flags: UInt = RefusalTests.flagsOK, serial: String = "S1") -> TokenInfo {
        TokenInfo(slot: 0, label: "eID", manufacturer: "OpenSC", model: "PKCS#15", serial: serial, flags: flags)
    }

    private func run(_ args: [String], source: FakeSource?, pin: FakePIN = FakePIN()) async -> (Int32, Output) {
        let output = Output()
        let verifier = LoginVerifier(trust: try! TrustStore(anchors: [], intermediates: []), fetcher: NoNetwork())
        let cli = CLI(openSource: { path in
            guard let source else { throw TokenError.moduleLoad("PKCS#11 модуль олдсонгүй: \(path)") }
            return source
        }, verifier: verifier, pinInput: pin, out: { output.out.append($0) }, err: { output.err.append($0) })
        return (await cli.run(args), output)
    }

    func testUsageErrorsExit2() async {
        let (noSerial, noSerialOutput) = await run(["--module", "/m.so", "--login"], source: FakeSource(tokens: [token()]))
        XCTAssertEqual(noSerial, ExitCode.usage)
        XCTAssertEqual(noSerialOutput.err.first, "eid-token-check: \(CLIArguments.serialRequired)")
        let (pinArg, pinOutput) = await run(["--module", "/m.so", "--serial", "S1", "--login", "--pin", "1"],
                                            source: FakeSource(tokens: [token()]))
        XCTAssertEqual(pinArg, ExitCode.usage)
        XCTAssertEqual(pinOutput.err.first, "eid-token-check: \(CLIArguments.pinOnCommandLine)")
    }

    /// a PIN typed as a positional argument is not printed — not on stdout, not on stderr, not in JSON.
    func testPositionalPINIsNeverPrinted() async {
        for json in [false, true] {
            let source = FakeSource(tokens: [token()])
            let args = ["--module", "/m.so", "--serial", "S1", "--login", "482913"] + (json ? ["--json"] : [])
            let (code, output) = await run(args, source: source)
            XCTAssertEqual(code, ExitCode.usage)
            XCTAssertEqual(source.signCalls, 0)
            XCTAssertFalse((output.out + output.err).joined().contains("482913"), "\(output.out) \(output.err)")
            XCTAssertTrue((output.out + output.err).joined().contains(CLIArguments.unknownArgument))
        }
    }

    /// CKR_USER_ALREADY_LOGGED_IN is a login this reader did not make — refused, the same as on Windows.
    func testUserAlreadyLoggedInIsRefused() {
        XCTAssertEqual(TokenError.from("C_Login", PKCS11Module.CKR_USER_ALREADY_LOGGED_IN), .alreadyLoggedIn)
        XCTAssertEqual(TokenError.alreadyLoggedIn.errorDescription,
                       "Токенд өөр session нэвтэрсэн байна — энэ оролдлого гарын үсэг зурахгүй")
        XCTAssertEqual(TokenError.from("C_Login", PKCS11Module.CKR_PIN_INCORRECT), .pinIncorrect)
    }

    func testPINFromATerminalIsRefused() async {
        let source = FakeSource(tokens: [token()])
        let (code, output) = await run(["--module", "/m.so", "--serial", "S1", "--login"], source: source,
                                       pin: FakePIN(isTerminal: true))
        XCTAssertEqual(code, ExitCode.usage)
        XCTAssertEqual(source.signCalls, 0)
        XCTAssertEqual(output.err.first, "eid-token-check: \(CLI.stdinIsTerminal)")
    }

    func testFinalTryAndLockedAreRefusedWithoutCLogin() async {
        for flags in [Self.flagsOK | TokenInfo.CKF_USER_PIN_FINAL_TRY, Self.flagsOK | TokenInfo.CKF_USER_PIN_LOCKED] {
            let source = FakeSource(tokens: [token(flags)])
            let (code, output) = await run(["--module", "/m.so", "--serial", "S1", "--login"], source: source)
            XCTAssertEqual(code, ExitCode.failed)
            XCTAssertEqual(source.signCalls, 0)
            let expected = flags & TokenInfo.CKF_USER_PIN_LOCKED != 0
                ? PinPolicy.message(.locked) ?? "" : CLI.finalTryRefused
            XCTAssertEqual(output.err.first, "eid-token-check: \(expected)")
        }
    }

    func testEmptyStdinIsAUsageError() async {
        let source = FakeSource(tokens: [token()])
        let (code, output) = await run(["--module", "/m.so", "--serial", "S1", "--login"], source: source, pin: FakePIN(pin: nil))
        XCTAssertEqual(code, ExitCode.usage)
        XCTAssertEqual(source.signCalls, 0)
        XCTAssertEqual(output.err.first, "eid-token-check: \(CLI.noPIN)")
    }

    func testModuleErrorAndMissingTokenExit3() async {
        let (module, moduleOutput) = await run(["--module", "/missing.so"], source: nil)
        XCTAssertEqual(module, ExitCode.noToken)
        XCTAssertEqual(moduleOutput.err.first, "eid-token-check: PKCS#11 модуль олдсонгүй: /missing.so")
        let (none, noneOutput) = await run(["--module", "/m.so"], source: FakeSource(tokens: []))
        XCTAssertEqual(none, ExitCode.noToken)
        XCTAssertEqual(noneOutput.err.first, "eid-token-check: \(CLI.noToken)")
        let (otherSerial, otherOutput) = await run(["--module", "/m.so", "--serial", "S9", "--login"],
                                                   source: FakeSource(tokens: [token()]))
        XCTAssertEqual(otherSerial, ExitCode.noToken)
        XCTAssertEqual(otherOutput.err.first, "eid-token-check: \(CLI.noToken): S9")
    }

    func testNoEIDCertificates() async {
        let other = TokenCertificate(keyID: [0x01], label: "other", der: [0x30, 0x00])
        let (list, listOutput) = await run(["--module", "/m.so"], source: FakeSource(tokens: [token()], certificates: [other]))
        XCTAssertEqual(list, ExitCode.ok)
        XCTAssertTrue(listOutput.out.contains { $0.contains(TokenLogin.noEIDCertificates) }, "\(listOutput.out)")

        let source = FakeSource(tokens: [token()], certificates: [other])
        let (login, loginOutput) = await run(["--module", "/m.so", "--serial", "S1", "--login"], source: source)
        XCTAssertEqual(login, ExitCode.failed)
        XCTAssertEqual(source.signCalls, 0)
        XCTAssertTrue(loginOutput.out.last?.contains(TokenLogin.noEIDCertificates) == true, "\(loginOutput.out)")
    }

    func testJSONListing() async throws {
        let (code, output) = await run(["--module", "/m.so", "--json"],
                                       source: FakeSource(tokens: [token(Self.flagsOK | TokenInfo.CKF_USER_PIN_COUNT_LOW)]))
        XCTAssertEqual(code, ExitCode.ok)
        XCTAssertEqual(output.out.count, 1)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(output.out[0].utf8)) as? [String: Any])
        let tokens = try XCTUnwrap(object["tokens"] as? [[String: Any]])
        XCTAssertEqual(tokens.first?["serial"] as? String, "S1")
        let pin = try XCTUnwrap(tokens.first?["pin"] as? [String: Bool])
        XCTAssertEqual(pin, ["countLow": true, "finalTry": false, "locked": false])
        XCTAssertEqual(tokens.first?["note"] as? String, TokenLogin.noEIDCertificates)
    }

    func testJSONUsageError() async throws {
        let (code, output) = await run(["--module", "/m.so", "--login", "--json"], source: FakeSource(tokens: [token()]))
        XCTAssertEqual(code, ExitCode.usage)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(output.out[0].utf8)) as? [String: Any])
        XCTAssertEqual(object["error"] as? String, CLIArguments.serialRequired)
    }

    func testAuthCertificateSelection() {
        let staged = TokenCertificate(keyID: EIDKeyID.stagedAuth, label: "", der: [1])
        let primary = TokenCertificate(keyID: EIDKeyID.auth, label: "", der: [2])
        let sign = TokenCertificate(keyID: EIDKeyID.sign, label: "", der: [3])
        XCTAssertEqual(TokenLogin.authCertificate([staged, sign, primary]), primary)
        XCTAssertEqual(TokenLogin.authCertificate([sign, staged]), staged)
        XCTAssertNil(TokenLogin.authCertificate([sign]))
        XCTAssertTrue(TokenLogin.hasEIDCertificates([sign]))
        XCTAssertEqual(CertificateSummary.make(sign).kind, .sign)
    }
}

/// The CLI tests never reach a network.
struct NoNetwork: RevocationFetcher {
    struct Offline: Error {}
    func fetch(_ request: RevocationRequest) async throws -> Data { throw Offline() }
}
