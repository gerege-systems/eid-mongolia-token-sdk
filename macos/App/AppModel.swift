import EIDTokenCheck
import EIDTokenReader
import Foundation

/// Window state. The PIN lives only in `pin` while typed: it is copied once into the login call and the field is
/// cleared at that moment; it is never logged, stored or kept after the attempt.
@MainActor
final class AppModel: ObservableObject {
    enum ListState: Equatable { case loading, loaded, failed(String) }
    enum LoginState { case idle, running, done(LoginReport), error(String) }

    @Published private(set) var listState: ListState = .loading
    @Published private(set) var tokens: [TokenEntry] = []
    @Published var selectedSerial: String?
    @Published var pin = ""
    /// The relying party's host name bound into the signed digest (`LoginChallenge`, `Origin`).
    @Published var origin = LoginChallenge.defaultOrigin
    @Published private(set) var login: LoginState = .idle
    /// The token reports the PIN's final try: «Нэвтрэх» first asks for explicit confirmation.
    @Published var confirmFinalTry = false

    private let service = TokenService()
    /// A broken bundled trust folder stops the app loudly (log + crash report) — never a login against partial trust.
    private let verifier: LoginVerifier = {
        do {
            let trust = try TrustStore.load(directory: Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/trust"))
            return LoginVerifier(trust: trust, fetcher: URLSessionRevocationFetcher())
        } catch {
            StartupLog.write("trust folder failed to load: \(error.localizedDescription)")
            fatalError(error.localizedDescription)
        }
    }()

    var selected: TokenEntry? { tokens.first { $0.info.serial == selectedSerial } }
    var isLoading: Bool { listState == .loading }
    var isRunning: Bool { if case .running = login { return true } else { return false } }

    /// Why «Нэвтрэх» is disabled for the selected token (nil = it can be used).
    var loginBlockReason: String? {
        guard let token = selected else { return "Токен сонгоогүй байна." }
        if !token.info.isInitialized { return "Токен форматлагдаагүй (PKCS#15 бүтэцгүй)." }
        if PinPolicy.gate(token.info.pinState) == .blocked { return PinPolicy.message(token.info.pinState) }
        if !token.hasEIDCertificates { return TokenLogin.noEIDCertificates + "." }
        if !token.hasAuthCertificate { return TokenLogin.noAuthCertificate + "." }
        return nil
    }

    var trimmedOrigin: String { origin.trimmingCharacters(in: .whitespacesAndNewlines) }

    /// The origin field holds a valid origin (`Origin.isValid`) — otherwise nothing is signed.
    var originProblem: String? { Origin.isValid(trimmedOrigin) ? nil : Origin.invalidReason }

    var canLogin: Bool {
        loginBlockReason == nil && originProblem == nil && !pin.isEmpty && !isRunning && !isLoading
    }

    func refresh() async {
        guard !isRunning else { return }
        listState = .loading
        login = .idle
        do {
            let found = try await service.scan()
            tokens = found
            if !found.contains(where: { $0.info.serial == selectedSerial }) { selectedSerial = found.first?.info.serial }
            listState = .loaded
        } catch {
            tokens = []
            selectedSerial = nil
            listState = .failed(error.localizedDescription)
        }
    }

    func select(_ serial: String) {
        guard !isRunning, serial != selectedSerial else { return }
        selectedSerial = serial
        pin = ""
        login = .idle
    }

    /// Reads the token flags first: locked → refused; final try → confirmation; otherwise C_Login.
    func loginTapped() {
        guard canLogin, let serial = selectedSerial else { return }
        login = .running
        Task {
            do {
                let info = try await service.tokenInfo(serial: serial)
                update(info)
                switch PinPolicy.gate(info.pinState) {
                case .blocked:
                    pin = ""
                    login = .error(PinPolicy.message(info.pinState) ?? "PIN ашиглах боломжгүй.")
                case .confirmFinalTry:
                    login = .idle
                    confirmFinalTry = true
                case .allowed:
                    await runLogin(serial: serial)
                }
            } catch {
                pin = ""
                login = .error(error.localizedDescription)
            }
        }
    }

    func finalTryConfirmed() {
        guard let serial = selectedSerial, !pin.isEmpty, originProblem == nil else { return }
        login = .running
        Task { await runLogin(serial: serial) }
    }

    func finalTryCancelled() {
        pin = ""
    }

    /// One attempt = one C_Login; nothing is retried (`TokenLogin.run`, shared with the command-line tool).
    private func runLogin(serial: String) async {
        let entered = pin
        pin = ""
        login = .done(await service.login(serial: serial, origin: trimmedOrigin, pin: entered, verifier: verifier))
        // A wrong PIN changes the counters: show the new state.
        if let info = try? await service.tokenInfo(serial: serial) { update(info) }
    }

    private func update(_ info: TokenInfo) {
        guard let i = tokens.firstIndex(where: { $0.info.serial == info.serial }) else { return }
        tokens[i].info = info
    }
}
