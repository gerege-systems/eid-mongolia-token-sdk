import EIDTokenCheck
import EIDTokenReader
import SwiftUI

@main
struct EIDTokenTestApp: App {
    var body: some Scene {
        Window("eID Token Test", id: "main") {
            ContentView()
        }
        .windowResizability(.contentMinSize)
    }
}

/// One window, three sections in a list: «Токен», «Гэрчилгээ», «Нэвтрэх тест».
struct ContentView: View {
    @StateObject private var model = AppModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                VStack(alignment: .leading, spacing: Space.xs) {
                    Text("eID Token Test").font(.eidPageTitle).foregroundStyle(Color.textPrimary)
                    Text("Зөвхөн уншина: токен форматлах, түлхүүр үүсгэх, гэрчилгээ бичих, PIN солих үйлдэл энэ апп-д байхгүй.")
                        .labelStyle()
                }
                TokenSection(model: model)
                CertificateSection(model: model)
                LoginSection(model: model)
            }
            .padding(Space.xl)
            .frame(maxWidth: 860, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color.eidSurface)
        .frame(minWidth: 640, minHeight: 640)
        .task { await model.refresh() }
    }
}

// MARK: - «Токен»

private struct TokenSection: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            HStack {
                Text("Токен").sectionTitleStyle()
                Spacer()
                Button { Task { await model.refresh() } } label: {
                    Label("Дахин унших", systemImage: "arrow.clockwise")
                }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(model.isLoading || model.isRunning)
            }
            switch model.listState {
            case .loading:
                HStack(spacing: Space.sm) {
                    ProgressView().controlSize(.small)
                    Text("Токен уншиж байна…").labelStyle()
                }
            case .failed(let message):
                InlineBanner(text: "PKCS#11 модулийг ачаалж чадсангүй: \(message)", variant: .error)
            case .loaded where model.tokens.isEmpty:
                EmptyLine(icon: "key.horizontal", text: "Токен олдсонгүй")
            case .loaded:
                ForEach(model.tokens) { token in
                    TokenRow(token: token, selected: token.info.serial == model.selectedSerial) {
                        model.select(token.info.serial)
                    }
                }
            }
        }
        .appCard()
    }
}

private struct TokenRow: View {
    let token: TokenEntry
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.md) {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(Color.eidAccent)
                    .frame(width: 36, height: 36)
                    .background(Color.eidAccentSubtle)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(token.info.label.isEmpty ? "Нэргүй токен" : token.info.label)
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(Color.textPrimary)
                    Text("Серийн дугаар \(token.info.serial) · Загвар \(token.info.model.isEmpty ? "—" : token.info.model)")
                        .labelStyle().lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: 0)
                pinPill
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 18))
                    .foregroundStyle(selected ? Color.eidAccent : Color.eidMuted.opacity(0.6))
            }
            .rowBox(selected: selected)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    @ViewBuilder private var pinPill: some View {
        if !token.info.isInitialized {
            StatusPill(text: "Форматлагдаагүй", variant: .neutral)
        } else if token.info.pinLocked {
            StatusPill(text: "PIN түгжигдсэн", variant: .bad)
        } else if token.info.pinFinalTry {
            StatusPill(text: "PIN: сүүлийн оролдлого", variant: .bad)
        } else if token.info.pinCountLow {
            StatusPill(text: "PIN-ий оролдлого цөөн үлдсэн", variant: .warn)
        }
    }
}

// MARK: - «Гэрчилгээ»

private struct CertificateSection: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            Text("Гэрчилгээ").sectionTitleStyle()
            if model.isLoading {
                Text("Токен уншиж байна…").labelStyle()
            } else if let token = model.selected {
                if let error = token.readError {
                    InlineBanner(text: "Гэрчилгээ уншиж чадсангүй: \(error)", variant: .error)
                } else if !token.info.isInitialized {
                    EmptyLine(icon: "doc.badge.ellipsis", text: "Токен форматлагдаагүй (PKCS#15 бүтэцгүй)")
                } else {
                    ForEach(token.certificates) { CertificateRow(certificate: $0) }
                    if !token.hasEIDCertificates {
                        EmptyLine(icon: "doc", text: TokenLogin.noEIDCertificates)
                    }
                }
            } else {
                EmptyLine(icon: "key.horizontal", text: "Токен сонгоогүй байна")
            }
        }
        .appCard()
    }
}

private struct CertificateRow: View {
    let certificate: CertificateSummary

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(spacing: Space.sm) {
                AccentBadge(text: certificate.kind.title)
                Text(certificate.subjectName)
                    .font(.system(size: 14, weight: .semibold)).foregroundStyle(Color.textPrimary)
                    .textSelection(.enabled)
            }
            Grid(alignment: .leading, horizontalSpacing: Space.lg, verticalSpacing: Space.xs) {
                field("Эзэмшигч", certificate.subjectName)
                field("serialNumber", certificate.subjectSerialNumber ?? "—")
                field("Олгогч", certificate.issuerName)
                field("Серийн дугаар", certificate.serialHex, mono: true)
                field("Хүчинтэй", "\(certificate.notBefore.map(DisplayDate.string) ?? "—") – \(certificate.notAfter.map(DisplayDate.string) ?? "—")")
            }
        }
        .rowBox()
    }

    private func field(_ name: String, _ value: String, mono: Bool = false) -> some View {
        GridRow {
            Text(name).labelStyle()
            Text(value)
                .font(mono ? .eidMonoSmall : .eidLabel)
                .foregroundStyle(Color.textPrimary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - «Нэвтрэх тест»

private struct LoginSection: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            Text("Нэвтрэх тест").sectionTitleStyle()
            Text("AUTH түлхүүрээр 32 байт санамсаргүй challenge-д (origin-той холбож) гарын үсэг зуруулаад гарын үсэг, гэрчилгээний гинж, хүчинтэй хугацаа, OCSP, CRL-ийг энэ компьютер дээр шалгана.")
                .labelStyle()
            if let reason = model.loginBlockReason, !model.isLoading {
                InlineBanner(text: reason, variant: model.selected?.info.pinLocked == true ? .error : .info)
            } else if model.selected?.info.pinFinalTry == true {
                InlineBanner(text: "PIN-ий сүүлийн оролдлого үлдсэн. Буруу оруулбал токен түгжигдэнэ.", variant: .warning)
            } else if model.selected?.info.pinCountLow == true {
                InlineBanner(text: "PIN-ийг өмнө нь буруу оруулсан байна — оролдлого цөөн үлдсэн.", variant: .warning)
            }
            HStack(spacing: Space.sm) {
                Text("Origin").labelStyle()
                TextField("танай системийн host нэр", text: $model.origin)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                    .disabled(model.isRunning)
            }
            if let problem = model.originProblem {
                Text(problem).labelStyle()
            }
            HStack(spacing: Space.sm) {
                SecureField("PIN", text: $model.pin)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 220)
                    .disabled(model.loginBlockReason != nil || model.isRunning)
                    .onSubmit { model.loginTapped() }
                Button("Нэвтрэх") { model.loginTapped() }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(!model.canLogin)
            }
            result
        }
        .appCard()
        .confirmationDialog("PIN-ий сүүлийн оролдлого", isPresented: $model.confirmFinalTry, titleVisibility: .visible) {
            Button("Үргэлжлүүлэх", role: .destructive) { model.finalTryConfirmed() }
            Button("Болих", role: .cancel) { model.finalTryCancelled() }
        } message: {
            Text("Токен PIN-ий сүүлийн оролдлого үлдсэн гэж мэдэгдэж байна. Буруу PIN оруулбал токен түгжигдэж, энэ апп түүнийг тайлж чадахгүй.")
        }
    }

    @ViewBuilder private var result: some View {
        switch model.login {
        case .idle:
            EmptyView()
        case .running:
            HStack(spacing: Space.sm) {
                ProgressView().controlSize(.small)
                Text("Шалгаж байна…").labelStyle()
            }
        case .error(let message):
            InlineBanner(text: "Нэвтэрч чадсангүй: \(message)", variant: .error)
        case .done(let report):
            VStack(alignment: .leading, spacing: Space.sm) {
                ForEach(report.checks, id: \.kind) { CheckRow(check: $0) }
                Divider().padding(.vertical, Space.xs)
                if report.loggedIn {
                    Label(report.summary, systemImage: "checkmark.seal.fill")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Color.eidSuccess)
                } else {
                    Label(report.summary, systemImage: "xmark.seal.fill")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Color.eidDanger)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .rowBox()
        }
    }
}

private struct CheckRow: View {
    let check: CheckResult

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
            Image(systemName: icon).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: Space.sm) {
                    Text(check.kind.title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.textPrimary)
                    Text(check.status.mark).font(.system(size: 13, weight: .semibold)).foregroundStyle(color)
                }
                Text(check.reason).labelStyle().lineLimit(2).textSelection(.enabled)
            }
        }
    }

    private var icon: String {
        switch check.status {
        case .passed: return "checkmark.circle.fill"
        case .failed: return "xmark.circle.fill"
        case .unavailable: return "questionmark.circle.fill"
        }
    }

    private var color: Color {
        switch check.status {
        case .passed: return .eidSuccess
        case .failed: return .eidDanger
        case .unavailable: return .eidWarning
        }
    }
}

private struct EmptyLine: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: Space.sm) {
            Image(systemName: icon).foregroundStyle(Color.eidMuted)
            Text(text).font(.eidBody).foregroundStyle(Color.eidMuted)
        }
        .padding(.vertical, Space.xs)
    }
}
