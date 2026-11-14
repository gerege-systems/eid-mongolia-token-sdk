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
- **README:** origin is a server constant (never from request headers), licence, pin / chain rules, rejected-input row,
  shared transport sample, Swift = Apple platforms (ATS exception), Releases instead of PR artifacts, macOS
  quarantine before the first run and the «eid-token-check хариу өгөхгүй гацсан» entry.
- **Verified:** PR CI (unit tests on both platforms, app and CLI builds, package contents). The release workflow runs
  only on a tag — not exercised by the PR.
- **Open:** no code signing / notarization; no installers.
