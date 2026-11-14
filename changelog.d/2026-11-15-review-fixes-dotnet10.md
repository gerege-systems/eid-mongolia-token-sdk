# 2026-11-15 — review fixes, .NET 10

- **What (verifier, both platforms, same order and reasons):**
  - Untrusted certificate bytes are accepted only as ONE strict DER certificate (no PEM / PKCS#7 / PFX / trailing
    bytes); DER BOOLEAN 0xFF / 0x00 only, minimal INTEGER serial, impossible dates rejected (Windows:
    `Der.IsStrictCertificate` before `X509CertificateLoader`; macOS: `ParsedCertificate`).
  - Chain: the CA path above the AUTH certificate is taken from `trust/` only, starting at the pinned 04; an expired CA
    fails the chain row; the platform path is accepted when element [1] has the pinned 04's subject AND public key, and
    the pinned 04 DER is used for every later check (another copy of 04 in a keychain / CA store is neither used nor a
    reason to refuse).
  - Invalid origin, wrong-length challenge or unreadable certificate: signature ✗, the other rows «шалгаж чадсангүй»,
    no network request, nothing signed — `VerifyAsync` / `RunAsync` / `verify` / `run` never throw.
  - OCSP: entries about other certificates (even malformed) are skipped; a malformed matching entry is ✗.
  - The 04 pin is enforced by the public trust-store constructors; injecting another CA is internal (tests).
  - Swift: the digest-taking P-256 verify is internal.
  - Login report exposes the verified subject serialNumber (`SubjectSerialNumber` / `subjectSerialNumber`, only when
    logged in).
- **What (reader / CLI):** Windows re-finds the token by serial at every step (a token swapped in the slot is refused
  before C_Login); `CKR_USER_ALREADY_LOGGED_IN` is refused on both platforms; the command-line tool never echoes an
  unknown / positional argument.
- **What (repo):** MIT `LICENSE` for the SDK's own code (OpenSC / OpenSSL keep their licences); `ci` now runs changelog,
  macOS and Windows in one workflow and `gate` passes only when all three succeeded (a skipped platform job fails it);
  `release.yml` builds both platforms on a `v*` tag and attaches the zips + `SHA256SUMS` to the GitHub Release.
- **What (.NET 10):** `windows/` targets .NET 10 (`global.json` 10.0.400, latestFeature); Windows App SDK 2.6.5,
  Windows SDK BuildTools 10.0.28000.2957, Microsoft.NET.Test.Sdk 18.12.0, xunit 2.9.3, xunit.runner.visualstudio 3.1.5;
  Pkcs11Interop unchanged (5.2.0). `EidTokenTest.Core` builds without implicit usings.
- **What (Windows app, blank window):** the published unpackaged WinUI 3 app opened with an empty content area; its
  publish folder had no compiled XAML (`*.xbf`) although the build output has them (`App.xbf`, `MainWindow.xbf`,
  `eid-token-test.pri`). The App project now copies every `*.pri` / `*.xbf` of the build output into the publish
  folder (and the app PRI as `resources.pri`, the name MRT Core looks for first). Startup errors are no longer silent: written to stderr and
  `eid-token-test.log`, shown in a code-built error window or a message box; the main page writes
  `main page loaded`. CI: UI smoke test of the published app through UI Automation (headings, «Дахин унших»,
  «Токен олдсонгүй»; screenshot + log on failure), a static check of `resources.pri` / `App.xbf` / `MainWindow.xbf`,
  a pixel check of the app's own window (PrintWindow with full content after waking the display: >= 50 colours, the
  page surface colour present, no colour over 90 %; the window PNG is always kept as the `ui-smoke-windows` artifact),
  and a macOS launch check (the app stays up; the same marker is required when the runner has a GUI session — the
  current macOS runner runs as a launchd daemon, so there only start + stay up is checked, with a warning).
- **What (release / CI hardening):** release artifacts are built ONLY on GitHub-hosted runners (macos-15,
  windows-latest; `release: true` hard-codes them) at the exact tagged commit; macOS builds OpenSC, OpenSSL and
  XcodeGen from SHA-256-pinned sources in fresh folders (missing build tools from Homebrew on that image only).
  `release.yml` runs only by hand from main with an existing tag on main, re-checks on the remote that the tag still
  points at the built commit before creating the release and before uploading, never overwrites a release that has
  files, and lists both zips' SHA-256 in the release text. Pull request builds may run on the self-hosted macOS runner;
  that runner is not a trust boundary — its per-event cache is checked on every use (XcodeGen archive hash, OpenSC
  output manifest), which detects accidental corruption only, and nothing from it is released. `ci` has a manual
  `macos_release_dry_run` input that runs the release build path without publishing. No `.pdb` in the Windows
  package; the UI smoke screenshot shows only the app's window (GitHub-hosted runners only); the .NET tests also run
  on Linux (`verifier-linux`, required by `gate`).
- **What (alignment):** a broken `trust/` file stops loading with an error on both platforms; macOS checks OID encoding
  like Windows; an empty token serial never selects a token on macOS either; the Windows chain evaluation checks time
  validity like macOS.
- **README:** origin is a server constant (never from request headers), licence, pin / chain rules, rejected-input row,
  shared transport sample, Swift = Apple platforms (ATS exception), Releases instead of PR artifacts, macOS
  quarantine before the first run and the «eid-token-check хариу өгөхгүй гацсан» entry.
- **Verified:** PR CI (unit tests on both platforms, app and CLI builds, package contents). The release workflow runs
  only on a tag — not exercised by the PR.
- **Open:** no code signing / notarization; no installers.
