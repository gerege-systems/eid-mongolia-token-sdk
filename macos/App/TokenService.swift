import EIDTokenCheck
import EIDTokenReader
import Foundation
import Security

/// One connected token as the window shows it — read WITHOUT the PIN (public objects only).
struct TokenEntry: Identifiable, Sendable {
    var id: String { info.serial }
    var info: TokenInfo
    var certificates: [CertificateSummary]
    /// Any certificate under an eID CKA_ID (AUTH / SIGN).
    var hasEIDCertificates: Bool
    /// Why the certificates could not be read (nil = read fine).
    var readError: String?

    var hasAuthCertificate: Bool { certificates.contains { $0.kind == .auth } }
}

/// The app's token access: the shared `TokenReader` (EIDTokenReader) over the module bundled in
/// `Contents/Frameworks/opensc-pkcs11.so`, and the shared `TokenLogin` flow — the same code the command-line tool
/// runs. One actor = one operation at a time (OpenSC's C_Initialize / C_Finalize are process-wide).
actor TokenService {
    enum ServiceError: LocalizedError {
        case moduleMissing
        case moduleNotTrusted

        var errorDescription: String? {
            switch self {
            case .moduleMissing: return "PKCS#11 модуль (opensc-pkcs11.so) апп-д багтаагүй байна."
            case .moduleNotTrusted: return "PKCS#11 модулийн гарын үсэг аппын гарын үсэгтэй таарахгүй байна."
            }
        }
    }

    private var reader: TokenReader?

    /// The bundled module, loaded once: it must sit inside this app's Contents/Frameworks, and (Release builds) the
    /// app's signature seal — nested code included — must be intact, so a replaced module is never loaded.
    private func source() throws -> TokenReader {
        if let reader { return reader }
        let frameworks = Bundle.main.bundleURL.appendingPathComponent("Contents/Frameworks", isDirectory: true)
            .resolvingSymlinksInPath()
        let module = frameworks.appendingPathComponent("opensc-pkcs11.so").resolvingSymlinksInPath()
        guard module.path.hasPrefix(frameworks.path + "/"), FileManager.default.fileExists(atPath: module.path) else {
            throw ServiceError.moduleMissing
        }
        #if !DEBUG
        guard Self.bundleSealIsValid() else { throw ServiceError.moduleNotTrusted }
        #endif
        OpenSCConfig.isolate()
        let reader = try TokenReader(modulePath: module.path)
        self.reader = reader
        return reader
    }

    private static func bundleSealIsValid() -> Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess, let code else {
            return false
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckNestedCode | kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        return SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess
    }

    /// Every present token with its certificates (public objects, no PIN).
    func scan() throws -> [TokenEntry] {
        let reader = try source()
        return try reader.tokens().map { info in
            guard info.isInitialized else {
                return TokenEntry(info: info, certificates: [], hasEIDCertificates: false, readError: nil)
            }
            do {
                let certificates = try reader.certificates(serial: info.serial)
                return TokenEntry(info: info, certificates: certificates.map(CertificateSummary.make),
                                  hasEIDCertificates: TokenLogin.hasEIDCertificates(certificates), readError: nil)
            } catch {
                return TokenEntry(info: info, certificates: [], hasEIDCertificates: false,
                                  readError: error.localizedDescription)
            }
        }
    }

    /// Fresh C_GetTokenInfo of one token (PIN flags right before C_Login).
    func tokenInfo(serial: String) throws -> TokenInfo {
        try source().tokenInfo(serial: serial)
    }

    /// One login attempt (`TokenLogin.run`): exactly one C_Login, no retry. The PIN is passed through only.
    func login(serial: String, origin: String, pin: String, verifier: LoginVerifier) async -> LoginReport {
        do {
            let reader = try source()
            return await TokenLogin.run(source: reader, serial: serial, origin: origin, pin: pin, verifier: verifier)
        } catch {
            return .notStarted(error.localizedDescription)
        }
    }
}
