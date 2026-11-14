import EIDTokenCheck
import EIDTokenReader
import Foundation

/// The command-line tool: the same reader (`TokenReader`), login flow (`TokenLogin`) and verifier (`LoginVerifier`)
/// as the test app — no second implementation. Human-readable lines by default, one JSON object with `--json`.
public struct CLI {
    let openSource: (String) throws -> TokenSource
    let verifier: LoginVerifier
    let pinInput: PinInput
    let out: (String) -> Void
    let err: (String) -> Void

    public init(openSource: @escaping (String) throws -> TokenSource, verifier: LoginVerifier, pinInput: PinInput,
                out: @escaping (String) -> Void, err: @escaping (String) -> Void) {
        self.openSource = openSource
        self.verifier = verifier
        self.pinInput = pinInput
        self.out = out
        self.err = err
    }

    public static let finalTryRefused =
        "Токен PIN-ий сүүлийн оролдлого дээр байна — command-line хэрэгсэл нэвтрэх оролдлого хийхгүй"
    public static let stdinIsTerminal = "PIN-ийг stdin-ээр (pipe эсвэл файл) дамжуулна — терминалаас уншихгүй"
    public static let noPIN = "stdin-ээс PIN уншигдсангүй"
    public static let noToken = "Токен олдсонгүй"

    public func run(_ arguments: [String]) async -> Int32 {
        let options: CLIOptions
        switch CLIArguments.parse(arguments) {
        case .help:
            out(CLIArguments.usageText)
            return ExitCode.ok
        case .usage(let reason):
            emitError(reason, json: arguments.contains("--json"))
            err(CLIArguments.usageText)
            return ExitCode.usage
        case .run(let parsed):
            options = parsed
        }
        if options.login && pinInput.isTerminal {
            emitError(Self.stdinIsTerminal, json: options.json)
            return ExitCode.usage
        }

        let source: TokenSource
        let tokens: [TokenInfo]
        do {
            source = try openSource(options.modulePath)
            tokens = try source.tokens()
        } catch {
            emitError(error.localizedDescription, json: options.json)
            return ExitCode.noToken
        }
        let selected = options.serial.map { serial in tokens.filter { $0.serial == serial } } ?? tokens
        guard !selected.isEmpty else {
            emitError(options.serial.map { "\(Self.noToken): \($0)" } ?? Self.noToken, json: options.json)
            return ExitCode.noToken
        }
        if options.login, let token = selected.first {
            return await login(token: token, source: source, options: options)
        }
        return list(selected, source: source, json: options.json)
    }

    // MARK: Listing

    private func list(_ tokens: [TokenInfo], source: TokenSource, json: Bool) -> Int32 {
        var code = ExitCode.ok
        var entries: [TokenOutput] = []
        for token in tokens {
            var entry = TokenOutput(token)
            if !token.isInitialized {
                entry.note = "Токен форматлагдаагүй (PKCS#15 бүтэцгүй)"
            } else {
                do {
                    let certificates = try source.certificates(serial: token.serial)
                    entry.certificates = certificates.map { CertificateOutput(CertificateSummary.make($0)) }
                    if !TokenLogin.hasEIDCertificates(certificates) { entry.note = TokenLogin.noEIDCertificates }
                } catch {
                    entry.error = "Гэрчилгээ уншиж чадсангүй: \(error.localizedDescription)"
                    code = ExitCode.failed
                }
            }
            entries.append(entry)
        }
        if json {
            out(Self.encode(ListOutput(tokens: entries)))
            return code
        }
        for entry in entries {
            out("Токен: \(entry.label.isEmpty ? "(нэргүй)" : entry.label) — серийн дугаар \(entry.serial), загвар \(dash(entry.model))")
            out("  PIN: count-low=\(yesNo(entry.pin.countLow)), final-try=\(yesNo(entry.pin.finalTry)), locked=\(yesNo(entry.pin.locked))")
            for c in entry.certificates {
                out("  [\(c.type)] \(c.subject)")
                out("    CKA_ID \(c.keyId) · serialNumber \(dash(c.serialNumber)) · олгогч \(c.issuer)")
                out("    серийн дугаар \(c.serial) · хүчинтэй \(dash(c.notBefore)) – \(dash(c.notAfter))")
            }
            if let note = entry.note { out("  \(note)") }
            if let error = entry.error { out("  \(error)") }
        }
        return code
    }

    // MARK: Login

    private func login(token: TokenInfo, source: TokenSource, options: CLIOptions) async -> Int32 {
        switch PinPolicy.gate(token.pinState) {
        case .blocked:
            emitError(PinPolicy.message(token.pinState) ?? "PIN ашиглах боломжгүй", json: options.json)
            return ExitCode.failed
        case .confirmFinalTry:
            emitError(Self.finalTryRefused, json: options.json)
            return ExitCode.failed
        case .allowed:
            break
        }
        guard let pin = pinInput.readPIN() else {
            emitError(Self.noPIN, json: options.json)
            return ExitCode.usage
        }
        let report = await TokenLogin.run(source: source, serial: token.serial, origin: options.origin, pin: pin,
                                          verifier: verifier)
        if options.json {
            out(Self.encode(LoginOutput(serial: token.serial, origin: options.origin, report: report)))
        } else {
            for check in report.checks {
                out("\(check.kind.title): \(check.status.mark) — \(check.reason)")
            }
            out(report.summary)
        }
        return report.loggedIn ? ExitCode.ok : ExitCode.failed
    }

    // MARK: Output

    private func emitError(_ message: String, json: Bool) {
        if json { out(Self.encode(ErrorOutput(error: message))) } else { err("eid-token-check: \(message)") }
    }

    private func yesNo(_ value: Bool) -> String { value ? "yes" : "no" }
    private func dash(_ value: String?) -> String { (value ?? "").isEmpty ? "—" : value! }

    static func encode<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    static func iso(_ date: Date?) -> String? {
        guard let date else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: date)
    }
}

// MARK: - JSON shapes (the same field names on Windows)

struct PinOutput: Encodable, Equatable {
    let countLow: Bool
    let finalTry: Bool
    let locked: Bool
}

struct CertificateOutput: Encodable, Equatable {
    let type: String
    let keyId: String
    let subject: String
    let serialNumber: String?
    let issuer: String
    let serial: String
    let notBefore: String?
    let notAfter: String?

    init(_ s: CertificateSummary) {
        type = s.kind.rawValue
        keyId = s.keyIDHex
        subject = s.subjectName
        serialNumber = s.subjectSerialNumber
        issuer = s.issuerName
        serial = s.serialHex
        notBefore = CLI.iso(s.notBefore)
        notAfter = CLI.iso(s.notAfter)
    }
}

struct TokenOutput: Encodable, Equatable {
    let label: String
    let serial: String
    let model: String
    let manufacturer: String
    let initialized: Bool
    let pin: PinOutput
    var certificates: [CertificateOutput] = []
    var note: String?
    var error: String?

    init(_ t: TokenInfo) {
        label = t.label
        serial = t.serial
        model = t.model
        manufacturer = t.manufacturer
        initialized = t.isInitialized
        pin = PinOutput(countLow: t.pinCountLow, finalTry: t.pinFinalTry, locked: t.pinLocked)
    }
}

struct ListOutput: Encodable {
    let tokens: [TokenOutput]
}

struct CheckOutput: Encodable {
    let name: String
    let status: String
    let mark: String
    let reason: String
}

struct LoginOutput: Encodable {
    let serial: String
    let origin: String
    let loggedIn: Bool
    let summary: String
    let checks: [CheckOutput]

    init(serial: String, origin: String, report: LoginReport) {
        self.serial = serial
        self.origin = origin
        loggedIn = report.loggedIn
        summary = report.summary
        checks = report.checks.map {
            CheckOutput(name: $0.kind.title, status: $0.status.rawValue, mark: $0.status.mark, reason: $0.reason)
        }
    }
}

struct ErrorOutput: Encodable {
    let error: String
}
