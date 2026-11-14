# eID Token Test — Windows

Бүрэн гарын авлага (нэвтрэлтийн дүрэм, модуль ашиглах, command-line хэрэгсэл, алдаа засах, лиценз) нь репогийн үндсэн
[`README.md`](../README.md)-д (zip-д `README.md`). Энэ файл зөвхөн Windows-ийн багцын бүтэц ба эх кодын байршлыг заана.

## Zip (`eid-token-test-windows-x64.zip`, GitHub Releases)

| Зам | Юу вэ |
|---|---|
| `eid-token-test.exe` (+ `*.dll`, `*.pri`) | WinUI 3 тест апп, self-contained (.NET 10 + Windows App SDK), x64 |
| `opensc\opensc-pkcs11.dll`, `opensc\COPYING`, `opensc\OPENSSL-LICENSE.txt` | OpenSC 0.26.1 PKCS#11 модуль ба лиценз |
| `eid-token-check\eid-token-check.exe` (+ runtime) | Command-line хэрэгсэл, self-contained (win-x64) |
| `eid-token-check\opensc-pkcs11.dll`, `COPYING`, `OPENSSL-LICENSE.txt` | Ижил модуль, хэрэгслийн хажууд |
| `README.md`, `README-windows.md`, `trust\` | Гарын авлага, энэ файл, итгэлийн гэрчилгээнүүд |

## Эх код

| Зам | Агуулга |
|---|---|
| `src/EidTokenTest.Core/Verification/` | Шалгагч (verifier) — зөвхөн .NET-ийн суурь сан; өөрийн серверт бүтнээр нь хуулна |
| `src/EidTokenTest.Core/Tokens/` | READ-ONLY PKCS#11 (Pkcs11Interop), нэвтрэх урсгал (`TokenLogin`) — апп ба CLI хоёулаа ашиглана |
| `src/EidTokenTest.App/` | WinUI 3 цонх |
| `src/EidTokenTest.Cli/` | `eid-token-check.exe` |
| `tests/EidTokenTest.Tests/` | Unit тест (бүх гэрчилгээ, CRL, OCSP-ийг тест дотор үүсгэнэ; сүлжээ, токен хэрэглэхгүй) |
| `third_party/opensc/` | `opensc-pkcs11.dll`-ийн эх сурвалж, SHA-256 ([README](third_party/opensc/README.md)) |
