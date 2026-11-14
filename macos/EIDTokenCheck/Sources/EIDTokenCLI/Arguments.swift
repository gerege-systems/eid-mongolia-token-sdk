import EIDTokenCheck
import Foundation

/// `eid-token-check --module <path> [--serial <serial>] [--origin <host>] [--login] [--json]` — the same options
/// and rules on Windows (`eid-token-check.exe`).
public struct CLIOptions: Equatable, Sendable {
    public var modulePath: String
    public var serial: String?
    public var origin: String
    public var login: Bool
    public var json: Bool

    public init(modulePath: String, serial: String? = nil, origin: String = LoginChallenge.defaultOrigin,
                login: Bool = false, json: Bool = false) {
        self.modulePath = modulePath
        self.serial = serial
        self.origin = origin
        self.login = login
        self.json = json
    }
}

public enum ParseResult: Equatable, Sendable {
    case run(CLIOptions)
    case help
    /// Usage error (exit code 2) with a one-line reason.
    case usage(String)
}

/// Process exit codes, the same on macOS and Windows.
public enum ExitCode {
    /// The listing worked / logged in.
    public static let ok: Int32 = 0
    /// A check failed, not logged in, or the token refused (PIN state, PIN, no eID certificate).
    public static let failed: Int32 = 1
    /// Usage error.
    public static let usage: Int32 = 2
    /// No token (none present / serial not found) or the module could not be loaded.
    public static let noToken: Int32 = 3
}

public enum CLIArguments {
    public static let usageText = """
    eid-token-check — eID токеныг ЗӨВХӨН уншиж шалгах command-line хэрэгсэл

      eid-token-check --module <opensc-pkcs11 зам> [--serial <токены серийн дугаар>] [--json]
          токенууд ба гэрчилгээнүүдийг жагсаана (PIN шаардахгүй)
      eid-token-check --module <зам> --serial <серийн дугаар> [--origin <host>] --login [--json] < pin.txt
          нэг удаа C_Login хийж нэвтрэх таван шалгалтыг хийнэ; PIN-ийг ЗӨВХӨН stdin-ээр (pipe/файл)

    Exit code: 0 амжилттай · 1 шалгалт унасан / нэвтрээгүй · 2 буруу хэрэглээ · 3 токен алга / модуль ачаалагдсангүй
    """

    public static let pinOnCommandLine = "PIN-ийг командын мөрөөр өгөхгүй — stdin-ээр (pipe эсвэл файл) дамжуулна"
    public static let serialRequired = "--login-д --serial заавал (PIN оруулах токеныг тодорхой заана)"
    /// Never echoes the argument itself: it may be a PIN typed in the wrong place.
    public static let unknownArgument = "Үл мэдэгдэх аргумент (утгыг нь хэвлэхгүй) — --help-ийг үзнэ үү"

    public static func parse(_ arguments: [String]) -> ParseResult {
        var modulePath: String?
        var serial: String?
        var origin: String?
        var login = false
        var json = false
        var i = 0
        func value() -> String? {
            guard i + 1 < arguments.count, !arguments[i + 1].hasPrefix("--") else { return nil }
            i += 1
            return arguments[i]
        }
        while i < arguments.count {
            let arg = arguments[i]
            if arg.lowercased().hasPrefix("--pin") || arg.lowercased() == "-p" { return .usage(pinOnCommandLine) }
            switch arg {
            case "--help", "-h":
                return .help
            case "--module":
                guard modulePath == nil else { return .usage("--module давхар өгөгдсөн") }
                guard let v = value(), !v.isEmpty else { return .usage("--module-ийн утга (модулийн зам) алга") }
                modulePath = v
            case "--serial":
                guard serial == nil else { return .usage("--serial давхар өгөгдсөн") }
                guard let v = value(), !v.isEmpty else { return .usage("--serial-ийн утга алга") }
                serial = v
            case "--origin":
                guard origin == nil else { return .usage("--origin давхар өгөгдсөн") }
                guard let v = value() else { return .usage("--origin-ий утга алга") }
                origin = v
            case "--login":
                guard !login else { return .usage("--login давхар өгөгдсөн") }
                login = true
            case "--json":
                guard !json else { return .usage("--json давхар өгөгдсөн") }
                json = true
            default:
                return .usage(unknownArgument)
            }
            i += 1
        }
        guard let modulePath else { return .usage("--module <opensc-pkcs11 зам> заавал") }
        let resolvedOrigin = origin ?? LoginChallenge.defaultOrigin
        guard Origin.isValid(resolvedOrigin) else { return .usage(Origin.invalidReason) }
        if login && serial == nil { return .usage(serialRequired) }
        return .run(CLIOptions(modulePath: modulePath, serial: serial, origin: resolvedOrigin, login: login, json: json))
    }
}

/// Where the PIN comes from: redirected standard input only.
public protocol PinInput {
    /// Standard input is an interactive terminal — then the PIN is NOT read (refused).
    var isTerminal: Bool { get }
    /// The first line (without CR/LF); nil when there is none.
    func readPIN() -> String?
}

public struct StandardInputPIN: PinInput {
    public init() {}

    public var isTerminal: Bool { isatty(STDIN_FILENO) == 1 }

    /// Reads up to the first newline (at most 256 bytes); never echoes.
    public func readPIN() -> String? {
        var bytes: [UInt8] = []
        var byte: UInt8 = 0
        while bytes.count <= 256, read(STDIN_FILENO, &byte, 1) == 1 {
            if byte == 0x0A { break }
            bytes.append(byte)
        }
        defer { for i in bytes.indices { bytes[i] = 0 } }
        if bytes.last == 0x0D { bytes.removeLast() }
        guard !bytes.isEmpty, bytes.count <= 256 else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }
}
