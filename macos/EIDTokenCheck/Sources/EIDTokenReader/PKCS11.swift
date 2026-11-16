import Foundation

/// The PKCS#11 v2.20 subset a relying party needs to READ an eID token and sign ONE login digest with its AUTH key —
/// nothing that creates, changes or deletes anything on the token is even resolved from the module:
///
///     C_Initialize, C_Finalize, C_GetSlotList, C_GetTokenInfo, C_OpenSession (never CKF_RW_SESSION),
///     C_CloseSession, C_Login (CKU_USER), C_Logout, C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal,
///     C_GetAttributeValue, C_SignInit (CKM_ECDSA), C_Sign
///
/// 64-bit macOS layout: CK_ULONG = 64 bit, structures naturally aligned.
final class PKCS11Module {
    typealias CK_RV = UInt
    typealias CK_ULONG = UInt

    static let CKR_OK: CK_RV = 0x0000_0000
    static let CKR_SLOT_ID_INVALID: CK_RV = 0x0000_0003
    static let CKR_DEVICE_REMOVED: CK_RV = 0x0000_0032
    static let CKR_PIN_INCORRECT: CK_RV = 0x0000_00A0
    static let CKR_PIN_LEN_RANGE: CK_RV = 0x0000_00A2
    static let CKR_PIN_LOCKED: CK_RV = 0x0000_00A4
    static let CKR_TOKEN_NOT_PRESENT: CK_RV = 0x0000_00E0
    static let CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x0000_0100
    static let CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x0000_0191

    static let CKF_SERIAL_SESSION: CK_ULONG = 0x0000_0004
    static let CKU_USER: CK_ULONG = 1
    static let CKM_ECDSA: CK_ULONG = 0x0000_1041
    static let CKO_CERTIFICATE: CK_ULONG = 1
    static let CKO_PRIVATE_KEY: CK_ULONG = 3
    static let CKA_CLASS: CK_ULONG = 0x0000_0000
    static let CKA_LABEL: CK_ULONG = 0x0000_0003
    static let CKA_VALUE: CK_ULONG = 0x0000_0011
    static let CKA_ID: CK_ULONG = 0x0000_0102

    struct CK_ATTRIBUTE {
        var type: CK_ULONG
        var pValue: UnsafeMutableRawPointer?
        var ulValueLen: CK_ULONG
    }

    struct CK_MECHANISM {
        var mechanism: CK_ULONG
        var pParameter: UnsafeMutableRawPointer?
        var ulParameterLen: CK_ULONG
    }

    typealias FnInitialize = @convention(c) (UnsafeMutableRawPointer?) -> CK_RV
    typealias FnFinalize = @convention(c) (UnsafeMutableRawPointer?) -> CK_RV
    typealias FnGetSlotList = @convention(c) (UInt8, UnsafeMutablePointer<CK_ULONG>?, UnsafeMutablePointer<CK_ULONG>) -> CK_RV
    typealias FnGetTokenInfo = @convention(c) (CK_ULONG, UnsafeMutableRawPointer) -> CK_RV
    typealias FnOpenSession = @convention(c) (CK_ULONG, CK_ULONG, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?,
                                              UnsafeMutablePointer<CK_ULONG>) -> CK_RV
    typealias FnCloseSession = @convention(c) (CK_ULONG) -> CK_RV
    typealias FnLogin = @convention(c) (CK_ULONG, CK_ULONG, UnsafePointer<UInt8>?, CK_ULONG) -> CK_RV
    typealias FnLogout = @convention(c) (CK_ULONG) -> CK_RV
    typealias FnFindObjectsInit = @convention(c) (CK_ULONG, UnsafeMutableRawPointer?, CK_ULONG) -> CK_RV
    typealias FnFindObjects = @convention(c) (CK_ULONG, UnsafeMutablePointer<CK_ULONG>?, CK_ULONG,
                                              UnsafeMutablePointer<CK_ULONG>) -> CK_RV
    typealias FnFindObjectsFinal = @convention(c) (CK_ULONG) -> CK_RV
    typealias FnGetAttributeValue = @convention(c) (CK_ULONG, CK_ULONG, UnsafeMutableRawPointer?, CK_ULONG) -> CK_RV
    typealias FnSignInit = @convention(c) (CK_ULONG, UnsafeMutableRawPointer, CK_ULONG) -> CK_RV
    typealias FnSign = @convention(c) (CK_ULONG, UnsafePointer<UInt8>?, CK_ULONG, UnsafeMutablePointer<UInt8>?,
                                       UnsafeMutablePointer<CK_ULONG>) -> CK_RV

    private let handle: UnsafeMutableRawPointer
    let initialize: FnInitialize
    let finalize: FnFinalize
    let getSlotList: FnGetSlotList
    let getTokenInfo: FnGetTokenInfo
    let openSession: FnOpenSession
    let closeSession: FnCloseSession
    let login: FnLogin
    let logout: FnLogout
    let findObjectsInit: FnFindObjectsInit
    let findObjects: FnFindObjects
    let findObjectsFinal: FnFindObjectsFinal
    let getAttributeValue: FnGetAttributeValue
    let signInit: FnSignInit
    let sign: FnSign

    /// dlopen + dlsym. Throws `TokenError.moduleLoad`.
    init(path: String) throws {
        guard FileManager.default.fileExists(atPath: path) else {
            throw TokenError.moduleLoad("PKCS#11 модуль олдсонгүй: \(path)")
        }
        guard let handle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            let reason = dlerror().map { String(cString: $0) } ?? "dlopen"
            throw TokenError.moduleLoad("PKCS#11 модулийг ачаалж чадсангүй (\(reason))")
        }
        func resolve<T>(_ name: String, _: T.Type) throws -> T {
            guard let symbol = dlsym(handle, name) else {
                dlclose(handle)
                throw TokenError.moduleLoad("PKCS#11 модульд \(name) алга")
            }
            return unsafeBitCast(symbol, to: T.self)
        }
        initialize = try resolve("C_Initialize", FnInitialize.self)
        finalize = try resolve("C_Finalize", FnFinalize.self)
        getSlotList = try resolve("C_GetSlotList", FnGetSlotList.self)
        getTokenInfo = try resolve("C_GetTokenInfo", FnGetTokenInfo.self)
        openSession = try resolve("C_OpenSession", FnOpenSession.self)
        closeSession = try resolve("C_CloseSession", FnCloseSession.self)
        login = try resolve("C_Login", FnLogin.self)
        logout = try resolve("C_Logout", FnLogout.self)
        findObjectsInit = try resolve("C_FindObjectsInit", FnFindObjectsInit.self)
        findObjects = try resolve("C_FindObjects", FnFindObjects.self)
        findObjectsFinal = try resolve("C_FindObjectsFinal", FnFindObjectsFinal.self)
        getAttributeValue = try resolve("C_GetAttributeValue", FnGetAttributeValue.self)
        signInit = try resolve("C_SignInit", FnSignInit.self)
        sign = try resolve("C_Sign", FnSign.self)
        self.handle = handle
    }

    deinit { dlclose(handle) }

    // MARK: Helpers

    /// C_Initialize → body → C_Finalize: OpenSC sees tokens plugged in since the last call.
    func withLibrary<T>(_ body: () throws -> T) throws -> T {
        OpenSCConfig.touch()   // OpenSC reads its config here; keep the folder from looking abandoned
        let rv = initialize(nil)
        guard rv == Self.CKR_OK || rv == Self.CKR_CRYPTOKI_ALREADY_INITIALIZED else {
            throw TokenError.pkcs11("C_Initialize", rv)
        }
        defer { _ = finalize(nil) }
        return try body()
    }

    func slots() throws -> [CK_ULONG] {
        var count: CK_ULONG = 0
        var rv = getSlotList(1, nil, &count)
        guard rv == Self.CKR_OK else { throw TokenError.pkcs11("C_GetSlotList", rv) }
        guard count > 0 else { return [] }
        var slots = [CK_ULONG](repeating: 0, count: Int(count))
        rv = slots.withUnsafeMutableBufferPointer { getSlotList(1, $0.baseAddress, &count) }
        guard rv == Self.CKR_OK else { throw TokenError.pkcs11("C_GetSlotList", rv) }
        return Array(slots.prefix(Int(count)))
    }

    /// CK_TOKEN_INFO (208 bytes on 64-bit): label[32] manufacturerID[32] model[16] serialNumber[16] flags …
    func tokenInfo(slot: CK_ULONG) throws -> TokenInfo {
        var raw = [UInt8](repeating: 0, count: 208)
        let rv = raw.withUnsafeMutableBytes { getTokenInfo(slot, $0.baseAddress!) }
        guard rv == Self.CKR_OK else { throw TokenError.pkcs11("C_GetTokenInfo", rv) }
        func text(_ range: Range<Int>) -> String {
            String(decoding: raw[range], as: UTF8.self).trimmingCharacters(in: CharacterSet(charactersIn: " \0"))
        }
        let flags = raw[96..<104].withUnsafeBytes { $0.loadUnaligned(as: UInt.self) }
        return TokenInfo(slot: slot, label: text(0..<32), manufacturer: text(32..<64), model: text(64..<80),
                         serial: text(80..<96), flags: flags)
    }

    /// A read-only session (CKF_SERIAL_SESSION only).
    func withSession<T>(slot: CK_ULONG, _ body: (CK_ULONG) throws -> T) throws -> T {
        var session: CK_ULONG = 0
        let rv = openSession(slot, Self.CKF_SERIAL_SESSION, nil, nil, &session)
        guard rv == Self.CKR_OK else { throw TokenError.from("C_OpenSession", rv) }
        defer { _ = closeSession(session) }
        return try body(session)
    }

    func find(session: CK_ULONG, objectClass: CK_ULONG, id: [UInt8]? = nil, max: Int = 64) throws -> [CK_ULONG] {
        var classValue = objectClass
        var idBytes = id ?? []
        return try withUnsafeMutableBytes(of: &classValue) { classPtr in
            try idBytes.withUnsafeMutableBytes { idPtr in
                var template = [CK_ATTRIBUTE(type: Self.CKA_CLASS, pValue: classPtr.baseAddress,
                                             ulValueLen: CK_ULONG(classPtr.count))]
                if id != nil {
                    template.append(CK_ATTRIBUTE(type: Self.CKA_ID, pValue: idPtr.baseAddress, ulValueLen: CK_ULONG(idPtr.count)))
                }
                let rvInit = template.withUnsafeMutableBufferPointer {
                    findObjectsInit(session, UnsafeMutableRawPointer($0.baseAddress), CK_ULONG($0.count))
                }
                guard rvInit == Self.CKR_OK else { throw TokenError.from("C_FindObjectsInit", rvInit) }
                defer { _ = findObjectsFinal(session) }
                var handles = [CK_ULONG](repeating: 0, count: max)
                var found: CK_ULONG = 0
                let rv = handles.withUnsafeMutableBufferPointer { findObjects(session, $0.baseAddress, CK_ULONG($0.count), &found) }
                guard rv == Self.CKR_OK else { throw TokenError.from("C_FindObjects", rv) }
                return Array(handles.prefix(Int(found)))
            }
        }
    }

    /// A variable-length attribute (length probe, then the value); nil when unreadable.
    func attribute(session: CK_ULONG, object: CK_ULONG, type: CK_ULONG) -> [UInt8]? {
        var probe = CK_ATTRIBUTE(type: type, pValue: nil, ulValueLen: 0)
        let rv1 = withUnsafeMutablePointer(to: &probe) { getAttributeValue(session, object, UnsafeMutableRawPointer($0), 1) }
        guard rv1 == Self.CKR_OK, probe.ulValueLen < 65_536 else { return nil }
        let size = Int(probe.ulValueLen)
        if size == 0 { return [] }
        var buffer = [UInt8](repeating: 0, count: size)
        let rv2 = buffer.withUnsafeMutableBytes { bytes -> CK_RV in
            var attribute = CK_ATTRIBUTE(type: type, pValue: bytes.baseAddress, ulValueLen: CK_ULONG(size))
            return withUnsafeMutablePointer(to: &attribute) { getAttributeValue(session, object, UnsafeMutableRawPointer($0), 1) }
        }
        return rv2 == Self.CKR_OK ? buffer : nil
    }

    /// C_SignInit(CKM_ECDSA) + C_Sign over `digest` → raw r‖s.
    func signECDSA(session: CK_ULONG, key: CK_ULONG, digest: [UInt8]) throws -> [UInt8] {
        var mechanism = CK_MECHANISM(mechanism: Self.CKM_ECDSA, pParameter: nil, ulParameterLen: 0)
        let rvInit = withUnsafeMutablePointer(to: &mechanism) { signInit(session, UnsafeMutableRawPointer($0), key) }
        guard rvInit == Self.CKR_OK else { throw TokenError.from("C_SignInit", rvInit) }
        var length: CK_ULONG = 0
        let rv1 = digest.withUnsafeBufferPointer { sign(session, $0.baseAddress, CK_ULONG($0.count), nil, &length) }
        guard rv1 == Self.CKR_OK, length > 0, length <= 512 else { throw TokenError.from("C_Sign", rv1) }
        var signature = [UInt8](repeating: 0, count: Int(length))
        let rv2 = digest.withUnsafeBufferPointer { d in
            signature.withUnsafeMutableBufferPointer { sign(session, d.baseAddress, CK_ULONG(d.count), $0.baseAddress, &length) }
        }
        guard rv2 == Self.CKR_OK else { throw TokenError.from("C_Sign", rv2) }
        return Array(signature.prefix(Int(length)))
    }
}
