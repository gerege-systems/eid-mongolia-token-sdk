import Foundation

/// A connected token as `C_GetTokenInfo` reports it.
public struct TokenInfo: Sendable, Equatable {
    public static let CKF_USER_PIN_INITIALIZED: UInt = 0x0000_0008
    public static let CKF_TOKEN_INITIALIZED: UInt = 0x0000_0400
    public static let CKF_USER_PIN_COUNT_LOW: UInt = 0x0001_0000
    public static let CKF_USER_PIN_FINAL_TRY: UInt = 0x0002_0000
    public static let CKF_USER_PIN_LOCKED: UInt = 0x0004_0000

    public let slot: UInt
    public let label: String
    public let manufacturer: String
    public let model: String
    /// Trimmed `serialNumber` — how a token is told apart when several are plugged in.
    public let serial: String
    public let flags: UInt

    public init(slot: UInt, label: String, manufacturer: String, model: String, serial: String, flags: UInt) {
        self.slot = slot
        self.label = label
        self.manufacturer = manufacturer
        self.model = model
        self.serial = serial
        self.flags = flags
    }

    /// PKCS#15 structure exists (CKF_TOKEN_INITIALIZED).
    public var isInitialized: Bool { flags & Self.CKF_TOKEN_INITIALIZED != 0 }
    public var pinCountLow: Bool { flags & Self.CKF_USER_PIN_COUNT_LOW != 0 }
    public var pinFinalTry: Bool { flags & Self.CKF_USER_PIN_FINAL_TRY != 0 }
    public var pinLocked: Bool { flags & Self.CKF_USER_PIN_LOCKED != 0 }

    public var pinState: PinState {
        PinPolicy.state(userPinInitialized: flags & Self.CKF_USER_PIN_INITIALIZED != 0, locked: pinLocked,
                        finalTry: pinFinalTry, countLow: pinCountLow)
    }
}

/// One certificate object on the token (public: read without the PIN).
public struct TokenCertificate: Sendable, Equatable {
    public let keyID: [UInt8]
    public let label: String
    public let der: [UInt8]

    public init(keyID: [UInt8], label: String, der: [UInt8]) {
        self.keyID = keyID
        self.label = label
        self.der = der
    }
}

/// The user PIN counter as the PKCS#11 token flags tell it (PKCS#11 has no exact count).
public enum PinState: String, Sendable, Equatable {
    case ok, countLow, finalTry, locked, notInitialized
}

public enum PinGate: Sendable, Equatable {
    case allowed
    /// The final try: the app asks for explicit confirmation; the command-line tool refuses.
    case confirmFinalTry
    /// No C_Login at all.
    case blocked
}

/// What a login may do for a PIN state — decided BEFORE C_Login, which spends a try. Same rule on Windows.
public enum PinPolicy {
    public static func state(userPinInitialized: Bool, locked: Bool, finalTry: Bool, countLow: Bool) -> PinState {
        if !userPinInitialized { return .notInitialized }
        if locked { return .locked }
        if finalTry { return .finalTry }
        if countLow { return .countLow }
        return .ok
    }

    public static func gate(_ state: PinState) -> PinGate {
        switch state {
        case .locked, .notInitialized: return .blocked
        case .finalTry: return .confirmFinalTry
        case .ok, .countLow: return .allowed
        }
    }

    /// One line for the user; nil = nothing to say.
    public static func message(_ state: PinState) -> String? {
        switch state {
        case .locked: return "PIN түгжигдсэн тул нэвтрэх тест хийх боломжгүй."
        case .notInitialized: return "Токены PIN тохируулагдаагүй тул нэвтрэх тест хийх боломжгүй."
        case .finalTry: return "Анхаар: PIN-ий сүүлийн оролдлого. Буруу оруулбал токен түгжигдэнэ."
        case .countLow: return "PIN-ийг өмнө нь буруу оруулсан байна — оролдлого цөөн үлдсэн."
        case .ok: return nil
        }
    }
}

/// Token access failures. `errorDescription` is the one-line Mongolian reason (the same texts as on Windows).
public enum TokenError: LocalizedError, Equatable {
    case moduleLoad(String)
    case tokenNotFound
    case pinIncorrect
    case pinLocked
    case pinLength
    case keyNotFound
    case pkcs11(String, UInt)

    public var errorDescription: String? {
        switch self {
        case .moduleLoad(let message): return message
        case .tokenNotFound: return "Токен салгагдсан эсвэл олдсонгүй"
        case .pinIncorrect: return "PIN буруу"
        case .pinLocked: return "PIN түгжигдсэн"
        case .pinLength: return "PIN-ий урт буруу"
        case .keyNotFound: return "Токен дээр AUTH гэрчилгээтэй таарах хувийн түлхүүр алга"
        case .pkcs11(let function, let rv): return String(format: "Токен гарын үсэг зурж чадсангүй (%@ CKR=0x%08lX)", function, rv)
        }
    }

    static func from(_ function: String, _ rv: UInt) -> TokenError {
        switch rv {
        case PKCS11Module.CKR_PIN_INCORRECT: return .pinIncorrect
        case PKCS11Module.CKR_PIN_LOCKED: return .pinLocked
        case PKCS11Module.CKR_PIN_LEN_RANGE: return .pinLength
        case PKCS11Module.CKR_TOKEN_NOT_PRESENT, PKCS11Module.CKR_DEVICE_REMOVED, PKCS11Module.CKR_SLOT_ID_INVALID:
            return .tokenNotFound
        default: return .pkcs11(function, rv)
        }
    }
}

/// What the login flow and the command-line tool need from a token (the real one: `TokenReader`).
public protocol TokenSource {
    func tokens() throws -> [TokenInfo]
    func certificates(serial: String) throws -> [TokenCertificate]
    /// Exactly one C_Login (CKU_USER) in a read-only session, then C_Sign (CKM_ECDSA) over the 32-byte `digest` with
    /// the private key whose CKA_ID is `keyID` → raw r‖s. No retry, no context-specific login.
    func signDigest(serial: String, keyID: [UInt8], digest: [UInt8], pin: String) throws -> [UInt8]
}

/// READ-ONLY access to eID tokens through the standard OpenSC PKCS#11 module (`opensc-pkcs11.so`):
///
///  - every session is opened WITHOUT CKF_RW_SESSION;
///  - certificates are public objects: read without C_Login;
///  - the PIN is used for exactly one C_Login per `signDigest` call (no automatic retry), only to sign a digest with
///    the AUTH key; its bytes are wiped afterwards; it is never logged or stored;
///  - nothing is created, changed or deleted on the token — the functions that could are not even loaded.
///
/// Every call runs C_Initialize … C_Finalize; a token is always picked by its serial, never "the first slot".
/// Not thread-safe: call from one thread / actor at a time.
public final class TokenReader: TokenSource {
    private let module: PKCS11Module

    /// Loads the module. Throws `TokenError.moduleLoad`.
    public init(modulePath: String) throws {
        module = try PKCS11Module(path: modulePath)
    }

    public func tokens() throws -> [TokenInfo] {
        try module.withLibrary {
            try module.slots().compactMap { try? module.tokenInfo(slot: $0) }      // removed meanwhile: not listed
        }
    }

    public func tokenInfo(serial: String) throws -> TokenInfo {
        try module.withLibrary { try find(serial) }
    }

    public func certificates(serial: String) throws -> [TokenCertificate] {
        try module.withLibrary {
            let token = try find(serial)
            return try module.withSession(slot: token.slot) { session in
                try module.find(session: session, objectClass: PKCS11Module.CKO_CERTIFICATE).compactMap { object in
                    guard let der = module.attribute(session: session, object: object, type: PKCS11Module.CKA_VALUE),
                          !der.isEmpty else { return nil }
                    let id = module.attribute(session: session, object: object, type: PKCS11Module.CKA_ID) ?? []
                    let label = module.attribute(session: session, object: object, type: PKCS11Module.CKA_LABEL)
                        .map { String(decoding: $0, as: UTF8.self).trimmingCharacters(in: .whitespaces) } ?? ""
                    return TokenCertificate(keyID: id, label: label, der: der)
                }
            }
        }
    }

    public func signDigest(serial: String, keyID: [UInt8], digest: [UInt8], pin: String) throws -> [UInt8] {
        guard digest.count == 32 else { throw TokenError.pkcs11("C_Sign", 0) }
        return try module.withLibrary {
            let token = try find(serial)
            // Never spend a try on a locked token (callers check too; the flags may have changed since).
            if token.pinLocked { throw TokenError.pinLocked }
            return try module.withSession(slot: token.slot) { session in
                var pinBytes = Array(pin.utf8)
                defer { for i in pinBytes.indices { pinBytes[i] = 0 } }
                let rv = pinBytes.withUnsafeBufferPointer {
                    module.login(session, PKCS11Module.CKU_USER, $0.baseAddress, PKCS11Module.CK_ULONG($0.count))
                }
                guard rv == PKCS11Module.CKR_OK || rv == PKCS11Module.CKR_USER_ALREADY_LOGGED_IN else {
                    throw TokenError.from("C_Login", rv)
                }
                defer { _ = module.logout(session) }
                guard let key = try module.find(session: session, objectClass: PKCS11Module.CKO_PRIVATE_KEY,
                                                id: keyID, max: 1).first else { throw TokenError.keyNotFound }
                return try module.signECDSA(session: session, key: key, digest: digest)
            }
        }
    }

    private func find(_ serial: String) throws -> TokenInfo {
        for slot in try module.slots() {
            if let info = try? module.tokenInfo(slot: slot), info.serial == serial { return info }
        }
        throw TokenError.tokenNotFound
    }
}

/// OpenSC reads its configuration from `OPENSC_CONF`; without it, it would read the path compiled into the module
/// (or an OpenSC installed on the same computer). A minimal private config (defaults only, nothing secret) is
/// written once per process. Call before the module is loaded. A value the user already set is kept.
public enum OpenSCConfig {
    public static func isolate() {
        if let set = ProcessInfo.processInfo.environment["OPENSC_CONF"], !set.isEmpty { return }
        guard let path = try? configPath.get() else { return }
        setenv("OPENSC_CONF", path, 1)
    }

    private static let configPath: Result<String, Error> = Result {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("eid-token-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let file = dir.appendingPathComponent("opensc.conf")
        try "app default {\n    debug = 0;\n}\n".write(to: file, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return file.path
    }
}
