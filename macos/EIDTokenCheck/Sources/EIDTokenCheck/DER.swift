import Foundation

/// One DER element: definite length, single-byte tag.
public struct DERNode: Equatable, Sendable {
    public let tag: UInt8
    /// The whole TLV (tag, length, content).
    public let raw: [UInt8]
    /// The content octets.
    public let value: [UInt8]

    /// The elements inside the content (nil when it is not well-formed DER).
    public var children: [DERNode]? { DER.elements(value) }
}

/// Minimal DER reader/writer — enough for X.509 certificates, CRLs and OCSP (RFC 5280 / RFC 6960).
/// Strict DER lengths: definite form only, minimal encoding (a length below 128 in long form, or a long form with a
/// leading zero byte, is rejected). Malformed input yields nil; nothing here traps on attacker-controlled bytes.
public enum DER {
    public enum Tag {
        public static let boolean: UInt8 = 0x01
        public static let integer: UInt8 = 0x02
        public static let bitString: UInt8 = 0x03
        public static let octetString: UInt8 = 0x04
        public static let null: UInt8 = 0x05
        public static let oid: UInt8 = 0x06
        public static let enumerated: UInt8 = 0x0A
        public static let utf8String: UInt8 = 0x0C
        public static let printableString: UInt8 = 0x13
        public static let teletexString: UInt8 = 0x14
        public static let ia5String: UInt8 = 0x16
        public static let utcTime: UInt8 = 0x17
        public static let generalizedTime: UInt8 = 0x18
        public static let bmpString: UInt8 = 0x1E
        public static let sequence: UInt8 = 0x30
        public static let set: UInt8 = 0x31
        /// `[n]` constructed context-specific tag (0xA0 | n).
        public static func context(_ n: UInt8) -> UInt8 { 0xA0 | n }
    }

    /// Exactly one element spanning all of `bytes`.
    public static func single(_ bytes: [UInt8]) -> DERNode? {
        guard let e = element(bytes, at: 0), e.next == bytes.count else { return nil }
        return e.node
    }

    /// All consecutive elements of `bytes` (empty input → empty list); nil when malformed.
    public static func elements(_ bytes: [UInt8]) -> [DERNode]? {
        var out: [DERNode] = []
        var i = 0
        while i < bytes.count {
            guard let e = element(bytes, at: i) else { return nil }
            out.append(e.node)
            i = e.next
        }
        return out
    }

    static func element(_ b: [UInt8], at start: Int) -> (node: DERNode, next: Int)? {
        guard start >= 0, start + 2 <= b.count else { return nil }
        let tag = b[start]
        guard tag & 0x1F != 0x1F else { return nil }                 // high-tag-number form: not used here
        var length = Int(b[start + 1])
        var header = 2
        if length & 0x80 != 0 {
            let n = length & 0x7F
            guard (1...4).contains(n), start + 2 + n <= b.count else { return nil }   // 0x80 = indefinite: not DER
            guard b[start + 2] != 0 else { return nil }                                // non-minimal: leading zero
            length = 0
            for k in 0..<n { length = length << 8 | Int(b[start + 2 + k]) }
            guard length >= 0x80 else { return nil }                                   // non-minimal: fits short form
            header += n
        }
        let end = start + header + length
        guard length >= 0, end <= b.count else { return nil }
        return (DERNode(tag: tag, raw: Array(b[start..<end]), value: Array(b[(start + header)..<end])), end)
    }

    // MARK: Values

    /// OID content bytes of an AlgorithmIdentifier SEQUENCE (a valid DER OID, `isValidOID`).
    public static func algorithmOID(_ node: DERNode) -> [UInt8]? {
        guard node.tag == Tag.sequence, let first = node.children?.first, first.tag == Tag.oid,
              isValidOID(first.value) else { return nil }
        return first.value
    }

    /// DER OBJECT IDENTIFIER content, the same rule as the Windows reader: at least one byte, every sub-identifier in
    /// minimal base-128 (it does not start with 0x80) and the last byte without the continuation bit.
    public static func isValidOID(_ value: [UInt8]) -> Bool {
        guard let last = value.last, last & 0x80 == 0 else { return false }
        var startOfSubidentifier = true
        for byte in value {
            if startOfSubidentifier && byte == 0x80 { return false }
            startOfSubidentifier = byte & 0x80 == 0
        }
        return true
    }

    /// BIT STRING content without the unused-bits byte (only whole-byte strings: signatures, keys).
    public static func bitStringBytes(_ node: DERNode) -> [UInt8]? {
        guard node.tag == Tag.bitString, node.value.first == 0 else { return nil }
        return Array(node.value.dropFirst())
    }

    /// INTEGER content with redundant leading zero bytes removed — the form serials are compared in.
    public static func normalizedInteger(_ bytes: [UInt8]) -> [UInt8] {
        var b = bytes[...]
        while b.count > 1 && b.first == 0 { b = b.dropFirst() }
        return Array(b)
    }

    /// X.509 `Time`: UTCTime or GeneralizedTime (UTC, `Z`). UTCTime YY ≥ 50 → 19YY (RFC 5280 §4.1.2.5.1).
    /// DER form only, the same as on Windows: UTCTime `YYMMDDHHMMSSZ`; GeneralizedTime `YYYYMMDDHHMMSS[.f…]Z` (a
    /// fraction has at least one digit and no trailing zero; it is ignored). A date that does not exist (month 13,
    /// 30 February, 31 April, second 60 …) is rejected.
    public static func time(_ node: DERNode) -> Date? {
        guard let text = String(bytes: node.value, encoding: .ascii), text.hasSuffix("Z") else { return nil }
        var digits = String(text.dropLast())
        if node.tag == Tag.generalizedTime, let dot = digits.firstIndex(of: ".") {
            let fraction = digits[digits.index(after: dot)...]
            guard !fraction.isEmpty, fraction.allSatisfy({ $0.isASCII && $0.isNumber }), fraction.last != "0" else {
                return nil
            }
            digits = String(digits[..<dot])                          // fractional seconds: ignored
        }
        guard digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        let year: Int
        let rest: [Character]
        switch node.tag {
        case Tag.utcTime:
            guard digits.count == 12, let yy = Int(digits.prefix(2)) else { return nil }
            year = yy >= 50 ? 1900 + yy : 2000 + yy
            rest = Array(digits.dropFirst(2))
        case Tag.generalizedTime:
            guard digits.count == 14, let y = Int(digits.prefix(4)) else { return nil }
            year = y
            rest = Array(digits.dropFirst(4))
        default:
            return nil
        }
        guard rest.count == 10 else { return nil }
        func field(_ i: Int) -> Int { Int(String(rest[i..<(i + 2)])) ?? -1 }
        let month = field(0), day = field(2), hour = field(4), minute = field(6), second = field(8)
        guard year >= 1, (1...12).contains(month), (1...daysIn(month: month, year: year)).contains(day),
              (0...23).contains(hour), (0...59).contains(minute), (0...59).contains(second) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? calendar.timeZone
        return calendar.date(from: DateComponents(year: year, month: month, day: day,
                                                  hour: hour, minute: minute, second: second))
    }

    static func daysIn(month: Int, year: Int) -> Int {
        switch month {
        case 2: return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 ? 29 : 28
        case 4, 6, 9, 11: return 30
        default: return 31
        }
    }

    public static func isTime(_ tag: UInt8) -> Bool { tag == Tag.utcTime || tag == Tag.generalizedTime }

    /// DER BOOLEAN: one content byte, 0xFF (TRUE) or 0x00 (FALSE); any other encoding (e.g. 0x01 for TRUE) is not
    /// DER and yields nil — the same rule as on Windows.
    public static func boolean(_ node: DERNode) -> Bool? {
        guard node.tag == Tag.boolean, node.value.count == 1 else { return nil }
        switch node.value[0] {
        case 0xFF: return true
        case 0x00: return false
        default: return nil
        }
    }

    /// DER INTEGER content: at least one byte, minimal two's-complement (no redundant leading 0x00 / 0xFF).
    public static func isMinimalInteger(_ value: [UInt8]) -> Bool {
        guard let first = value.first else { return false }
        guard value.count > 1 else { return true }
        let second = value[1]
        if first == 0x00 && second & 0x80 == 0 { return false }
        if first == 0xFF && second & 0x80 != 0 { return false }
        return true
    }

    // MARK: Writing

    /// Tag + definite (minimal) length + content.
    public static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        let n = content.count
        if n < 0x80 {
            out.append(UInt8(n))
        } else {
            var lengthBytes: [UInt8] = []
            var v = n
            while v > 0 { lengthBytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
            out.append(0x80 | UInt8(lengthBytes.count))
            out += lengthBytes
        }
        return out + content
    }
}

/// Object identifiers used here (DER content bytes, without tag/length).
public enum OID {
    // Signature algorithms
    public static let sha256WithRSA: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
    public static let sha384WithRSA: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C]
    public static let sha512WithRSA: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D]
    public static let ecdsaWithSHA256: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
    public static let ecdsaWithSHA384: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]
    public static let ecdsaWithSHA512: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]
    // Hashes (OCSP CertID: SHA-1 or SHA-256 only)
    public static let sha1: [UInt8] = [0x2B, 0x0E, 0x03, 0x02, 0x1A]
    public static let sha256: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    // Public keys
    public static let ecPublicKey: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
    public static let prime256v1: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    // Name attributes
    public static let commonName: [UInt8] = [0x55, 0x04, 0x03]
    public static let surname: [UInt8] = [0x55, 0x04, 0x04]
    public static let serialNumber: [UInt8] = [0x55, 0x04, 0x05]
    public static let country: [UInt8] = [0x55, 0x04, 0x06]
    public static let organization: [UInt8] = [0x55, 0x04, 0x0A]
    public static let organizationalUnit: [UInt8] = [0x55, 0x04, 0x0B]
    public static let givenName: [UInt8] = [0x55, 0x04, 0x2A]
    // Certificate extensions
    public static let keyUsage: [UInt8] = [0x55, 0x1D, 0x0F]
    public static let basicConstraints: [UInt8] = [0x55, 0x1D, 0x13]
    public static let crlDistributionPoints: [UInt8] = [0x55, 0x1D, 0x1F]
    public static let extendedKeyUsage: [UInt8] = [0x55, 0x1D, 0x25]
    public static let authorityKeyIdentifier: [UInt8] = [0x55, 0x1D, 0x23]
    public static let authorityInfoAccess: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]
    // CRL and CRL entry extensions
    public static let crlNumber: [UInt8] = [0x55, 0x1D, 0x14]
    public static let reasonCode: [UInt8] = [0x55, 0x1D, 0x15]
    public static let invalidityDate: [UInt8] = [0x55, 0x1D, 0x18]
    public static let deltaCRLIndicator: [UInt8] = [0x55, 0x1D, 0x1B]
    public static let issuingDistributionPoint: [UInt8] = [0x55, 0x1D, 0x1C]
    // OCSP
    public static let accessMethodOCSP: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]
    public static let ocspBasicResponse: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
    public static let ocspNonce: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]
    // Extended key usages
    public static let ekuClientAuth: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]
    public static let ekuEmailProtection: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04]
    public static let ekuOCSPSigning: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]
}
