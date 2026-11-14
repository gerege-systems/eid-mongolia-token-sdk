import EIDTokenCheck
import EIDTokenCLI
import EIDTokenReader
import Foundation

// eid-token-check: lists eID tokens and their certificates, or (--login) runs one login test — the same reader,
// login flow and verifier as the «eID Token Test» app. Trust certificates: the `trust/` folder next to this binary.
OpenSCConfig.isolate()
let executable = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])).resolvingSymlinksInPath()
let trust = TrustStore.load(directory: executable.deletingLastPathComponent().appendingPathComponent("trust"))
let cli = CLI(openSource: { try TokenReader(modulePath: $0) },
              verifier: LoginVerifier(trust: trust, fetcher: URLSessionRevocationFetcher()),
              pinInput: StandardInputPIN(),
              out: { print($0) },
              err: { FileHandle.standardError.write(Data(($0 + "\n").utf8)) })
exit(await cli.run(Array(CommandLine.arguments.dropFirst())))
