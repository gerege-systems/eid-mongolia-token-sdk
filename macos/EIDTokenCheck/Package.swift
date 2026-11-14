// swift-tools-version: 5.9
import PackageDescription

// eID token login check for macOS.
//
//   EIDTokenCheck   — the verifier (challenge signature, chain, validity, OCSP, CRL). Foundation, Security and
//                     CryptoKit only; copy Sources/EIDTokenCheck/ into your own code as one folder.
//   EIDTokenReader  — READ-ONLY PKCS#11 access through opensc-pkcs11 (list tokens, read certificates, one C_Login
//                     + C_Sign with the AUTH key) and the login flow shared by the app and the command-line tool.
//   EIDTokenCLI     — the command-line tool's logic (arguments, refusal rules, output).
//   eid-token-check — the command-line executable.
//
// Unit tests generate every certificate, CRL and OCSP response themselves: no network, no token.
let package = Package(
    name: "EIDTokenCheck",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "EIDTokenCheck", targets: ["EIDTokenCheck"]),
        .library(name: "EIDTokenReader", targets: ["EIDTokenReader"]),
        .executable(name: "eid-token-check", targets: ["eid-token-check"])
    ],
    targets: [
        .target(name: "EIDTokenCheck", path: "Sources/EIDTokenCheck"),
        .target(name: "EIDTokenReader", dependencies: ["EIDTokenCheck"], path: "Sources/EIDTokenReader"),
        .target(name: "EIDTokenCLI", dependencies: ["EIDTokenCheck", "EIDTokenReader"], path: "Sources/EIDTokenCLI"),
        .executableTarget(name: "eid-token-check", dependencies: ["EIDTokenCLI", "EIDTokenReader", "EIDTokenCheck"], path: "Sources/eid-token-check"),
        .testTarget(name: "EIDTokenCheckTests", dependencies: ["EIDTokenCheck"], path: "Tests/EIDTokenCheckTests"),
        .testTarget(name: "EIDTokenCLITests", dependencies: ["EIDTokenCLI", "EIDTokenReader", "EIDTokenCheck"],
                    path: "Tests/EIDTokenCLITests")
    ]
)
