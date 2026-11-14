import EIDTokenCheck
import Foundation

/// The eID objects on the token are found by CKA_ID (CKA_LABEL repeats it for people). During a certificate renewal
/// the new pair can sit under the staged IDs for a while. The CKA_ID only FINDS the object — whether the certificate
/// may log in is decided by the verifier (`ChainCheck.authProfileProblem`).
public enum EIDKeyID {
    public enum Role: String, Sendable { case auth, sign }

    public static let auth: [UInt8] = [0x45, 0x49, 0x44, 0x01]          // "eID AUTH"
    public static let sign: [UInt8] = [0x45, 0x49, 0x44, 0x02]          // "eID SIGN"
    public static let stagedAuth: [UInt8] = [0x45, 0x49, 0x44, 0x11]    // "eID AUTH (new)"
    public static let stagedSign: [UInt8] = [0x45, 0x49, 0x44, 0x12]    // "eID SIGN (new)"

    public static func role(of id: [UInt8]) -> Role? {
        if id == auth || id == stagedAuth { return .auth }
        if id == sign || id == stagedSign { return .sign }
        return nil
    }
}

/// One row of «Гэрчилгээ» (no PIN needed): type by CKA_ID, holder, subject serialNumber, issuer, serial, validity.
public struct CertificateSummary: Sendable, Equatable, Identifiable {
    public enum Kind: String, Sendable, Equatable {
        case auth = "AUTH", sign = "SIGN", other = "OTHER"

        public var title: String {
            switch self {
            case .auth: return "Нэвтрэх"
            case .sign: return "Гарын үсэг"
            case .other: return "Бусад"
            }
        }
    }

    public var id: String { keyIDHex + ":" + serialHex }
    public let kind: Kind
    public let keyIDHex: String
    public let subjectName: String
    /// Subject serialNumber attribute (e.g. `PNOMN-…`).
    public let subjectSerialNumber: String?
    public let issuerName: String
    /// Certificate serial, uppercase hex.
    public let serialHex: String
    public let notBefore: Date?
    public let notAfter: Date?

    public static func make(_ certificate: TokenCertificate) -> CertificateSummary {
        let kind: Kind
        switch EIDKeyID.role(of: certificate.keyID) {
        case .auth?: kind = .auth
        case .sign?: kind = .sign
        case nil: kind = .other
        }
        let idHex = certificate.keyID.map { String(format: "%02x", $0) }.joined()
        guard let parsed = ParsedCertificate(der: certificate.der) else {
            return CertificateSummary(kind: kind, keyIDHex: idHex,
                                      subjectName: certificate.label.isEmpty ? "—" : certificate.label,
                                      subjectSerialNumber: nil, issuerName: "—", serialHex: "—", notBefore: nil, notAfter: nil)
        }
        return CertificateSummary(kind: kind, keyIDHex: idHex, subjectName: parsed.subjectName?.displayName ?? "—",
                                  subjectSerialNumber: parsed.subjectName?.first(OID.serialNumber),
                                  issuerName: parsed.issuerName?.displayName ?? "—", serialHex: parsed.serialHex,
                                  notBefore: parsed.notBefore, notAfter: parsed.notAfter)
    }
}

/// The login flow the test app and the command-line tool share: pick the AUTH certificate, bind a fresh challenge to
/// the origin, ONE C_Login + C_Sign on the token, then the verifier's five checks.
public enum TokenLogin {
    public static let noEIDCertificates = "eID гэрчилгээ олдсонгүй"
    public static let noAuthCertificate = "Токен дээр нэвтрэх (AUTH) гэрчилгээ алга"

    /// Any certificate under an eID CKA_ID (AUTH or SIGN, primary or staged).
    public static func hasEIDCertificates(_ certificates: [TokenCertificate]) -> Bool {
        certificates.contains { EIDKeyID.role(of: $0.keyID) != nil }
    }

    /// The AUTH certificate: CKA_ID 45494401, else the staged 45494411.
    public static func authCertificate(_ certificates: [TokenCertificate]) -> TokenCertificate? {
        certificates.first { $0.keyID == EIDKeyID.auth } ?? certificates.first { $0.keyID == EIDKeyID.stagedAuth }
    }

    /// One login attempt on the token `serial`. The PIN state gate is the caller's (the app asks before the final try,
    /// the command-line tool refuses it). Exactly one C_Login; nothing is retried.
    public static func run(source: TokenSource, serial: String, origin: String, pin: String,
                           verifier: LoginVerifier, now: Date = Date()) async -> LoginReport {
        guard Origin.isValid(origin) else { return .notStarted(Origin.invalidReason) }
        let certificates: [TokenCertificate]
        do {
            certificates = try source.certificates(serial: serial)
        } catch {
            return .notStarted(error.localizedDescription)
        }
        guard hasEIDCertificates(certificates) else { return .notStarted(noEIDCertificates) }
        guard let auth = authCertificate(certificates) else { return .notStarted(noAuthCertificate) }
        guard let challenge = LoginChallenge.random() else { return .notStarted("Санамсаргүй challenge үүсгэж чадсангүй") }
        return await verifier.run(origin: origin, challenge: challenge, certificate: auth.der, now: now) { digest in
            try source.signDigest(serial: serial, keyID: auth.keyID, digest: digest, pin: pin)
        }
    }
}
