# eID Token Test — Windows

## Хурдан эхлэх

1. Татна: <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-windows-x64.zip>
   (ногоон «Code → Download ZIP» биш — тэр нь зөвхөн эх код, exe-гүй).
2. **Задлахаас ӨМНӨ:** zip дээр баруун товч → Properties → «Unblock»-ийг чагтлах → OK.
3. Zip дээр баруун товч → Extract All → `eid-token-test-windows-x64` хавтас үүснэ; түүнийг нээ — дотор нь **ижил нэртэй**
   хавтас дахин бий, түүнийг ч нээ (`<задалсан газар>\eid-token-test-windows-x64\eid-token-test-windows-x64\`).
4. `eid-token-test.exe` дээр давхар дарна (хажууд нь олон `.dll` — «Type» нь «Application» файл).
5. «Unblock»-ийг алгассан бол «Open File - Security Warning» гарна → Run. Оронд нь «Windows protected your PC» гарч ч
   болно → More info → Run anyway.

Дэлгэрэнгүй: браузераар —
[Windows A](https://github.com/gerege-systems/eid-mongolia-token-sdk/blob/main/README.md#windows-a-браузераар-татах),
PowerShell-ээр —
[Windows B](https://github.com/gerege-systems/eid-mongolia-token-sdk/blob/main/README.md#windows-b-powershell-ээр-татах)
(zip дотор ижил гарын авлага нь хажуудах `README.md`-ийн §3).

Бүрэн гарын авлага (нэвтрэлтийн дүрэм, модуль ашиглах, command-line хэрэгсэл, алдаа засах, лиценз) нь репогийн үндсэн
[`README.md`](https://github.com/gerege-systems/eid-mongolia-token-sdk/blob/main/README.md)-д (zip дотор хажуудах
`README.md`). Энэ файл Windows-ийн хурдан эхлэл, багцын бүтэц ба эх кодын байршлыг заана.

## Zip (`eid-token-test-windows-x64.zip`, GitHub Releases)

Замууд нь `eid-token-test.exe`-тэй хавтастай харьцангуй: zip доторх `eid-token-test-windows-x64\`; Extract All-аар
задалбал `<задалсан газар>\eid-token-test-windows-x64\eid-token-test-windows-x64\`.

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
