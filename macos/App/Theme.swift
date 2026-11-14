import AppKit
import SwiftUI

// The test app's look: one accent (Brand500 / Brand300), status colours only for status, 1 px strokes,
// no gradients or shadows.

extension Color {
    static let eidAccent = dynamic("3A6DFF", "84A8FF")
    static let eidAccentStrong = dynamic("1D47B3", "B3CCFF")
    static let eidAccentSubtle = dynamic("D8E6FF", "0A2466")
    static let eidSuccess = dynamic("107C10", "6FCF6F")
    static let eidWarning = dynamic("9D5D00", "E8B66A")
    static let eidDanger = dynamic("BA1A1A", "FFB4AB")
    static let eidCardBackground = Color(nsColor: NSColor.dynamic(light: .white, dark: NSColor(hex: "1F1F23")))
    static let eidCardStroke = dynamic("E5E7EB", "34343A")
    static let eidSurface = dynamic("F9F9FC", "0B0E12")
    static let eidMuted = dynamic("6B7280", "9CA3AF")
    static let backgroundSecondary = dynamic("F1F5F9", "111827")
    static let textPrimary = dynamic("0F172A", "F8FAFC")
    static let bannerErrorBG = dynamic("FEE2E2", "450A0A")
    static let bannerErrorBorder = dynamic("FCA5A5", "991B1B")
    static let bannerErrorText = dynamic("7F1D1D", "FECACA")
    static let bannerErrorIcon = dynamic("B91C1C", "F87171")
    /// Text on a filled accent/status background.
    static let onFill = Color(nsColor: NSColor.dynamic(light: .white, dark: NSColor(hex: "0B0E12")))

    private static func dynamic(_ light: String, _ dark: String) -> Color {
        Color(nsColor: NSColor.dynamic(light: NSColor(hex: light), dark: NSColor(hex: dark)))
    }
}

extension NSColor {
    static func dynamic(light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .vibrantDark]) != nil ? dark : light }
    }

    convenience init(hex: String) {
        var value: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&value)
        self.init(srgbRed: CGFloat((value >> 16) & 0xFF) / 255, green: CGFloat((value >> 8) & 0xFF) / 255,
                  blue: CGFloat(value & 0xFF) / 255, alpha: 1)
    }
}

extension Font {
    static let eidPageTitle = Font.system(size: 20, weight: .semibold)
    static let eidSectionTitle = Font.system(size: 17, weight: .semibold)
    static let eidBody = Font.system(size: 14)
    static let eidLabel = Font.system(size: 12)
    static let eidMonoSmall = Font.system(size: 12, design: .monospaced)
}

enum Space {
    static let xs: CGFloat = 4
    static let sm: CGFloat = 8
    static let md: CGFloat = 12
    static let lg: CGFloat = 16
    static let xl: CGFloat = 24
}

enum Radius {
    static let md: CGFloat = 8
    static let lg: CGFloat = 12
}

extension View {
    /// AppCard: card background, 1 px stroke, 12 pt corners, 24 pt padding.
    func appCard() -> some View {
        frame(maxWidth: .infinity, alignment: .leading)
            .padding(Space.xl)
            .background(Color.eidCardBackground)
            .clipShape(RoundedRectangle(cornerRadius: Radius.lg, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.lg, style: .continuous).strokeBorder(Color.eidCardStroke, lineWidth: 1))
    }

    /// Nested row inside a card.
    func rowBox(selected: Bool = false) -> some View {
        padding(.horizontal, 14)
            .padding(.vertical, Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.backgroundSecondary)
            .clipShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                .strokeBorder(selected ? Color.eidAccent : Color.eidCardStroke, lineWidth: selected ? 1.5 : 1))
    }

    func sectionTitleStyle() -> some View { font(.eidSectionTitle).foregroundStyle(Color.textPrimary) }

    func labelStyle() -> some View {
        font(.eidLabel).foregroundStyle(Color.eidMuted).fixedSize(horizontal: false, vertical: true)
    }
}

struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { Content(configuration: configuration) }

    private struct Content: View {
        let configuration: Configuration
        @Environment(\.isEnabled) private var isEnabled

        var body: some View {
            configuration.label
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Color.onFill)
                .padding(.horizontal, 18)
                .frame(height: 34)
                .background(configuration.isPressed ? Color.eidAccentStrong : Color.eidAccent)
                .clipShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
                .opacity(isEnabled ? 1 : 0.45)
        }
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { Content(configuration: configuration) }

    private struct Content: View {
        let configuration: Configuration
        @Environment(\.isEnabled) private var isEnabled

        var body: some View {
            configuration.label
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color.textPrimary)
                .padding(.horizontal, 14)
                .frame(height: 30)
                .background(configuration.isPressed ? Color.backgroundSecondary : Color.eidCardBackground)
                .clipShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous).strokeBorder(Color.eidCardStroke, lineWidth: 1))
                .opacity(isEnabled ? 1 : 0.45)
        }
    }
}

/// Solid status pill.
struct StatusPill: View {
    enum Variant { case ok, warn, bad, neutral }
    let text: String
    let variant: Variant

    var body: some View {
        Text(text)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(Color.onFill)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(fill)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private var fill: Color {
        switch variant {
        case .ok: return .eidSuccess
        case .warn: return .eidWarning
        case .bad: return .eidDanger
        case .neutral: return .eidMuted
        }
    }
}

/// Accent-subtle badge (certificate type).
struct AccentBadge: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(Color.eidAccent)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Color.eidAccentSubtle)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

/// Inline banner: error / warning / info.
struct InlineBanner: View {
    enum Variant { case error, warning, info }
    let text: String
    let variant: Variant

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: variant == .info ? "info.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(icon)
            Text(text)
                .font(.eidBody)
                .foregroundStyle(variant == .error ? Color.bannerErrorText : Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, 10)
        .background(background)
        .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous).strokeBorder(border, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
    }

    private var icon: Color {
        switch variant {
        case .error: return .bannerErrorIcon
        case .warning: return .eidWarning
        case .info: return .eidAccent
        }
    }

    private var background: Color {
        switch variant {
        case .error: return .bannerErrorBG
        case .warning: return Color.eidWarning.opacity(0.10)
        case .info: return .eidAccentSubtle
        }
    }

    private var border: Color {
        switch variant {
        case .error: return .bannerErrorBorder
        case .warning: return Color.eidWarning.opacity(0.4)
        case .info: return Color.eidAccent.opacity(0.35)
        }
    }
}
