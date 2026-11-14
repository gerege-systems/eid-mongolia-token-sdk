import Foundation

/// The five login checks, in display order. Titles are the labels both platforms (macOS and Windows) use.
public enum CheckKind: Int, Sendable, CaseIterable {
    case signature, chain, validity, ocsp, crl

    public var title: String {
        switch self {
        case .signature: return "Challenge-ийн гарын үсэг"
        case .chain: return "Гэрчилгээний гинж"
        case .validity: return "Хүчинтэй хугацаа"
        case .ocsp: return "OCSP"
        case .crl: return "CRL"
        }
    }
}

public enum CheckStatus: String, Sendable, Equatable {
    /// ✓
    case passed = "pass"
    /// ✗ — checked, and the answer is no.
    case failed = "fail"
    /// «шалгаж чадсангүй» — could not be performed (network, missing data, unsupported). Fails closed.
    case unavailable = "unknown"

    /// ✓ / ✗ / «шалгаж чадсангүй» — the same marks on macOS and Windows.
    public var mark: String {
        switch self {
        case .passed: return "✓"
        case .failed: return "✗"
        case .unavailable: return "шалгаж чадсангүй"
        }
    }
}

public struct CheckResult: Sendable, Equatable {
    public let kind: CheckKind
    public let status: CheckStatus
    /// One line, Mongolian.
    public let reason: String

    public init(_ kind: CheckKind, _ status: CheckStatus, _ reason: String) {
        self.kind = kind
        self.status = status
        self.reason = reason
    }
}

/// Outcome of one login test. Logged in ONLY when every check passed — a check that failed or could
/// not be performed (e.g. OCSP unreachable) means not logged in.
public struct LoginReport: Sendable, Equatable {
    public let checks: [CheckResult]
    /// Certificate holder (display only).
    public let subjectName: String
    /// Set when the test stopped before the checks could run (invalid origin, unreadable certificate, …).
    public let stopReason: String?

    public init(checks: [CheckResult], subjectName: String, stopReason: String? = nil) {
        self.checks = checks
        self.subjectName = subjectName
        self.stopReason = stopReason
    }

    /// Every row «шалгаж чадсангүй» with `reason`; not logged in.
    public static func notStarted(_ reason: String) -> LoginReport {
        LoginReport(checks: CheckKind.allCases.map { CheckResult($0, .unavailable, reason) }, subjectName: "",
                    stopReason: reason)
    }

    public var loggedIn: Bool {
        stopReason == nil && checks.map(\.kind) == CheckKind.allCases && checks.allSatisfy { $0.status == .passed }
    }

    /// The first check that did not pass, as «<title> — <reason>»; nil when logged in.
    public var failureReason: String? {
        if loggedIn { return nil }
        if let stopReason { return stopReason }
        guard let first = checks.first(where: { $0.status != .passed }) else { return "шалгалт дутуу" }
        return "\(first.kind.title) — \(first.reason)"
    }

    /// «Нэвтэрлээ: <нэр>» or «Нэвтэрч чадсангүй: <шалтгаан>» — the same line on both platforms.
    public var summary: String {
        loggedIn ? "Нэвтэрлээ: \(subjectName)" : "Нэвтэрч чадсангүй: \(failureReason ?? "")"
    }
}

/// Freshness of a revocation answer (OCSP SingleResponse or CRL), the same on macOS and Windows: thisUpdate not in
/// the future and nextUpdate not passed, with 5 min clock skew on both (both bounds inclusive); without nextUpdate
/// (OCSP only — a CRL must carry one) thisUpdate is at most 1 h old.
public enum Freshness {
    public static let clockSkew: TimeInterval = 5 * 60
    public static let maxAgeWithoutNextUpdate: TimeInterval = 60 * 60

    /// thisUpdate > now + 5 min.
    public static func isFuture(thisUpdate: Date, now: Date) -> Bool {
        thisUpdate > now.addingTimeInterval(clockSkew)
    }

    /// nextUpdate < now − 5 min; without nextUpdate: thisUpdate < now − 1 h.
    public static func isStale(thisUpdate: Date, nextUpdate: Date?, now: Date) -> Bool {
        if let next = nextUpdate { return next < now.addingTimeInterval(-clockSkew) }
        return thisUpdate < now.addingTimeInterval(-maxAgeWithoutNextUpdate)
    }
}

/// Dates in check reasons and the certificate list: local time, `yyyy-MM-dd HH:mm`.
public enum DisplayDate {
    public static func string(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f.string(from: date)
    }
}

/// The relying party's origin bound into the signed digest: its own host name as lowercase ASCII (an IDN in its
/// A-label / punycode form), dot-separated labels of 1–63 characters from `a–z`, `0–9` and `-` (not at either end
/// of a label), at most 253 characters — no scheme, no port, no path, no trailing dot. Anything else is rejected
/// before anything is signed or verified.
public enum Origin {
    public static let maxLength = 253
    public static let invalidReason =
        "Origin буруу: жижиг үсгийн ASCII host нэр байх ёстой (scheme, порт, зам, төгсгөлийн цэггүй, ≤ 253 тэмдэгт)"

    public static func isValid(_ origin: String) -> Bool {
        let bytes = Array(origin.utf8)
        guard !bytes.isEmpty, bytes.count <= maxLength else { return false }
        let labels = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        for label in labels {
            guard (1...63).contains(label.count), label.first != UInt8(ascii: "-"), label.last != UInt8(ascii: "-")
            else { return false }
            for c in label {
                let ok = (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z"))
                    || (c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9")) || c == UInt8(ascii: "-")
                if !ok { return false }
            }
        }
        return true
    }
}
