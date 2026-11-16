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
    /// C_Login answered CKR_USER_ALREADY_LOGGED_IN: some other session of this process is logged in to the token.
    /// This reader never logs in twice, so it refuses instead of signing on a login it did not make.
    case alreadyLoggedIn
    case pkcs11(String, UInt)

    public var errorDescription: String? {
        switch self {
        case .moduleLoad(let message): return message
        case .tokenNotFound: return "Токен салгагдсан эсвэл олдсонгүй"
        case .pinIncorrect: return "PIN буруу"
        case .pinLocked: return "PIN түгжигдсэн"
        case .pinLength: return "PIN-ий урт буруу"
        case .keyNotFound: return "Токен дээр AUTH гэрчилгээтэй таарах хувийн түлхүүр алга"
        case .alreadyLoggedIn: return "Токенд өөр session нэвтэрсэн байна — энэ оролдлого гарын үсэг зурахгүй"
        case .pkcs11(let function, let rv): return String(format: "Токен гарын үсэг зурж чадсангүй (%@ CKR=0x%08lX)", function, rv)
        }
    }

    static func from(_ function: String, _ rv: UInt) -> TokenError {
        switch rv {
        case PKCS11Module.CKR_PIN_INCORRECT: return .pinIncorrect
        case PKCS11Module.CKR_PIN_LOCKED: return .pinLocked
        case PKCS11Module.CKR_PIN_LEN_RANGE: return .pinLength
        case PKCS11Module.CKR_USER_ALREADY_LOGGED_IN: return .alreadyLoggedIn
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
                // Only our own C_Login counts: CKR_USER_ALREADY_LOGGED_IN means a login this call did not make
                // (this session is fresh) — refused, the same as on Windows.
                guard rv == PKCS11Module.CKR_OK else { throw TokenError.from("C_Login", rv) }
                defer { _ = module.logout(session) }
                guard let key = try module.find(session: session, objectClass: PKCS11Module.CKO_PRIVATE_KEY,
                                                id: keyID, max: 1).first else { throw TokenError.keyNotFound }
                return try module.signECDSA(session: session, key: key, digest: digest)
            }
        }
    }

    /// The token whose serial is `serial` right now; an empty serial never selects a token (the same on Windows).
    private func find(_ serial: String) throws -> TokenInfo {
        guard !serial.isEmpty else { throw TokenError.tokenNotFound }
        for slot in try module.slots() {
            if let info = try? module.tokenInfo(slot: slot), info.serial == serial { return info }
        }
        throw TokenError.tokenNotFound
    }
}

/// OpenSC reads its configuration from `OPENSC_CONF`; without it, it would read the path compiled into the module
/// (or an OpenSC installed on the same computer). A minimal private config (defaults only, nothing secret) is
/// written once per process. Call before the module is loaded. A value the user already set is kept.
///
/// The folder lives as long as the process: it is removed at normal exit (`atexit`; each module call has run its
/// C_Finalize by then). Folders of runs that crashed are swept at the next start once they are 7 days old; a running
/// process refreshes its folder's modification time on every module call, so a live process is never swept.
public enum OpenSCConfig {
    public static func isolate() {
        if let set = ProcessInfo.processInfo.environment["OPENSC_CONF"], !set.isEmpty { return }
        guard let path = try? configPath.get() else { return }
        setenv("OPENSC_CONF", path, 1)
    }

    static let directoryPrefix = "eid-token-test-"
    static let configName = "opensc.conf"
    /// A folder not touched for this long belongs to a process that is gone.
    static let staleAge: TimeInterval = 7 * 24 * 60 * 60

    private static var ownDirectory: URL?

    /// Sweeps old folders, creates this process's folder and arranges its removal at exit.
    private static let configPath: Result<String, Error> = Result {
        let root = FileManager.default.temporaryDirectory
        sweepStale(in: root, olderThan: staleAge, now: Date())
        let dir = try createConfigDirectory(in: root)
        ownDirectory = dir
        atexit { OpenSCConfig.removeOwnDirectory() }
        return dir.appendingPathComponent(configName).path
    }

    /// `<root>/eid-token-test-<uuid>/opensc.conf` (0700 / 0600).
    static func createConfigDirectory(in root: URL) throws -> URL {
        let dir = root.appendingPathComponent(directoryPrefix + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let file = dir.appendingPathComponent(configName)
        try "app default {\n    debug = 0;\n}\n".write(to: file, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return dir
    }

    /// Removes the folder this process created, if any. Best effort: never throws.
    static func removeOwnDirectory() {
        guard let dir = ownDirectory else { return }
        ownDirectory = nil
        removeConfigDirectory(dir)
    }

    /// Refreshes the modification time of this process's folder (cheap), so another instance's sweep skips it.
    static func touch() {
        if let dir = ownDirectory { touch(dir) }
    }

    static func touch(_ dir: URL) {
        _ = utimes(dir.path, nil)
    }

    /// Removes `dir` only when it is a real folder (not a symlink) holding nothing but a regular `opensc.conf`
    /// (not a symlink, not a folder); otherwise nothing is changed. Never recursive and never follows a link: the
    /// folder is opened with O_NOFOLLOW, the file is checked with fstatat(AT_SYMLINK_NOFOLLOW) and removed with
    /// unlinkat(…, 0) (cannot remove a folder), the folder with unlinkat(AT_REMOVEDIR) (fails if anything is left).
    /// Never throws. Returns whether the folder was removed.
    @discardableResult
    static func removeConfigDirectory(_ dir: URL) -> Bool {
        let name = dir.lastPathComponent
        let parentFd = open(dir.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY)
        guard parentFd >= 0 else { return false }
        defer { close(parentFd) }
        let fd = openat(parentFd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)   // a symlink fails with ELOOP
        guard fd >= 0 else { return false }
        defer { close(fd) }
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path), names.count <= 1 else {
            return false
        }
        if let only = names.first {
            var st = stat()
            guard only == configName, fstatat(fd, configName, &st, AT_SYMLINK_NOFOLLOW) == 0,
                  st.st_mode & S_IFMT == S_IFREG, unlinkat(fd, configName, 0) == 0 else { return false }
        }
        return unlinkat(parentFd, name, AT_REMOVEDIR) == 0
    }

    /// Deletes `<root>/eid-token-test-<UUID>` folders (the exact name `createConfigDirectory` makes) last modified at
    /// least `age` seconds before `now` that hold only the expected `opensc.conf`. Only directly inside `root`;
    /// symlinks and anything unexpected are left alone. Best effort: never throws.
    static func sweepStale(in root: URL, olderThan age: TimeInterval, now: Date) {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root.path) else { return }
        for name in names where name.hasPrefix(directoryPrefix) {
            let id = String(name.dropFirst(directoryPrefix.count))
            guard UUID(uuidString: id)?.uuidString == id else { continue }
            let dir = root.appendingPathComponent(name, isDirectory: true)
            var st = stat()
            guard lstat(dir.path, &st) == 0, st.st_mode & S_IFMT == S_IFDIR,
                  now.timeIntervalSince1970 - TimeInterval(st.st_mtimespec.tv_sec) >= age else { continue }
            removeConfigDirectory(dir)
        }
    }
}
