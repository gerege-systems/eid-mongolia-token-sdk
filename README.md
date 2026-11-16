# eID Mongolia token SDK

eID USB токеноос (ePass2003, PKCS#15, OpenSC) гэрчилгээ уншиж, хэрэглэгчийг токеноор **нэвтрүүлэх** гуравдагч талын
системд зориулсан багц: стандарт OpenSC PKCS#11 module, энэ гарын авлага, эх кодтой хоёр **зөвхөн унших** тест апп
(macOS, Windows) ба `eid-token-check` command-line хэрэгсэл. Шалгалтыг та өөрийн серверт өөрөө хийнэ — eID-ийн аль
нэг API руу хандахгүй; сүлжээний цорын ганц хандалт нь гэрчилгээнд заасан OCSP / CRL хаяг.

**Хамрах хүрээ — зөвхөн нэвтрэлт:** токеноос гэрчилгээ унших, AUTH түлхүүрээр challenge-д гарын үсэг зуруулах,
серверт шалгах. Энд **байхгүй**: SIGN түлхүүрээр баримт зурах, токен форматлах, түлхүүр үүсгэх, гэрчилгээ бичих, PIN
солих / тайлах. `pkcs15-init` болон OpenSC-ийн бусад хэрэгсэл, profile файл багцад ороогүй; session бүр
`CKF_RW_SESSION`-гүй; нэг оролдлого = яг нэг `C_Login`.

## Суулгах — аль замаар вэ

> **Анхаар:** GitHub-ийн ногоон **«Code → Download ZIP»** товч зөвхөн **эх код** өгнө (`windows\` дотор `.sln`, `src`,
> `tests` …) — дотор нь бэлэн апп, exe **байхгүй**. Бэлэн апп **Releases** хуудсанд байна.

- Releases (сүүлийн хувилбар): <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest>
- Windows: <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-windows-x64.zip>
- macOS: <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-macos.zip>
- Checksum: <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/SHA256SUMS>

| Та | Дагах хэсэг |
|---|---|
| Windows, браузераар татна (энгийн хэрэглэгч) | [Windows A](#windows-a-браузераар-татах) |
| Windows, PowerShell ашиглана | [Windows B](#windows-b-powershell-ээр-татах) |
| macOS (санал болгох) | [macOS A](#macos-a-terminal-аар-татах) |
| macOS, браузераар татсан | [macOS B](#macos-b-браузераар-татах) |
| Эх кодоос өөрөө бүтээнэ | [Windows C](#windows-c-эх-кодоос-бүтээх), [macOS C](#macos-c-эх-кодоос-бүтээх) → §4 |
| Зөвхөн command-line хэрэгсэл | [Command-line хэрэгсэл](#command-line-хэрэгсэл-суулгах-шаардлагагүй) |
| Өөрийн системд токеноор нэвтрэлт нэмнэ | [§5](#5-module-ийг-өөрийн-апп-д-ашиглах), [§6](#6-сервер-дээрх-нэвтрэлтийн-шалгалт-норматив) |

## Агуулга

1. [Энэ юу вэ](#eid-mongolia-token-sdk) · [Суулгах — аль замаар вэ](#суулгах--аль-замаар-вэ)
2. [Репогийн бүтэц](#2-репогийн-бүтэц)
3. [Хурдан эхлэх](#3-хурдан-эхлэх) — [Windows A](#windows-a-браузераар-татах) ·
   [Windows B](#windows-b-powershell-ээр-татах) · [Windows C](#windows-c-эх-кодоос-бүтээх) ·
   [macOS A](#macos-a-terminal-аар-татах) · [macOS B](#macos-b-браузераар-татах) · [macOS C](#macos-c-эх-кодоос-бүтээх) ·
   [Command-line хэрэгсэл](#command-line-хэрэгсэл-суулгах-шаардлагагүй) ·
   [Шаардлага ба бичдэг файлууд](#шаардлага-ба-бичдэг-файлууд) · [Татсан файлыг шалгах](#татсан-файлыг-шалгах)
4. [Эх кодоос бүтээх](#4-эх-кодоос-бүтээх)
5. [Module-ийг өөрийн апп-д ашиглах](#5-module-ийг-өөрийн-апп-д-ашиглах)
6. [Сервер дээрх нэвтрэлтийн шалгалт (норматив)](#6-сервер-дээрх-нэвтрэлтийн-шалгалт-норматив)
7. [Command-line хэрэгсэл `eid-token-check`](#7-command-line-хэрэгсэл-eid-token-check)
8. [Алдаа засах](#8-алдаа-засах)
9. [Лиценз ба хязгаарлалт](#9-лиценз-ба-хязгаарлалт)

## 2. Репогийн бүтэц

```
README.md                    энэ гарын авлага
LICENSE                      MIT — SDK-ийн өөрийн код (§9)
trust/
  anchors/01-…pem            Mongolian National Root CA — цорын ганц итгэлийн үндэс
  intermediates/02-…pem      Mongolian National Issuing CA
  intermediates/03-…pem      Gerege Issuing CA
  intermediates/04-…pem      eID Mongolia Issuing CA — токены AUTH гэрчилгээг олгогч (pin хийгдсэн)
macos/
  App/                       SwiftUI тест апп «eID Token Test»
  EIDTokenCheck/             Swift package: шалгагч (EIDTokenCheck), PKCS#11 уншигч (EIDTokenReader), CLI, тест
  project.yml                XcodeGen төсөл
  scripts/                   OpenSC 0.26.1 модулийг эх кодоос бүтээх / апп-д багцлах (зөвхөн модуль)
  README.md                  macOS zip-ийн бүтэц
windows/
  src/EidTokenTest.Core/     Verification/ — шалгагч; Tokens/ — PKCS#11 уншигч (Pkcs11Interop), нэвтрэх урсгал
  src/EidTokenTest.App/      WinUI 3 тест апп «eID Token Test»
  src/EidTokenTest.Cli/      eid-token-check.exe
  tests/EidTokenTest.Tests/  unit тест
  third_party/opensc/        opensc-pkcs11.dll (OpenSC 0.26.1 x64), COPYING, OPENSSL-LICENSE.txt, эх сурвалж + SHA-256
  README.md                  Windows zip-ийн бүтэц
changelog.d/                 өөрчлөлтийн фрагментууд
.github/workflows/           ci (changelog + macos + windows + verifier-linux → gate), release (гараар: main + tag →
                             GitHub Release, зөвхөн GitHub-hosted runner);
                             token-sdk-macos / token-sdk-windows — хоёулаа ашигладаг build алхмууд
```

Шалгагч платформ бүрд **нэг хавтас**, апп / UI-аас хамааралгүй — өөрийн серверт бүтнээр нь хуулна:
macOS `macos/EIDTokenCheck/Sources/EIDTokenCheck/` (Foundation, Security, CryptoKit л), Windows
`windows/src/EidTokenTest.Core/Verification/` (.NET 10-ийн суурь сан л; файл бүр өөрийн `using`-тэй, апп / CLI
төслөөс хамааралгүй). Хоёулаа §6-ийн дүрмийг ижил дараалал, ижил шалтгааны бичвэрээр хэрэгжүүлнэ. Swift шалгагч нь
Apple-ийн платформын код (Security.framework) — сервер дээр C# шалгагчийг ашигла, эсвэл §6-г өөрийн хэл дээр
хэрэгжүүл (§6.8).

## 3. Хурдан эхлэх

Бэлэн апп **GitHub Releases**-д: <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest>
(`eid-token-test-windows-x64.zip`, `eid-token-test-macos.zip`, `SHA256SUMS`). Доорх зам бүр бие даасан — өөрийн
компьютер, дассан аргадаа тохирох **нэгийг** л дага. GitHub-ийн «Code → Download ZIP» зөвхөн эх код өгнө (C зам, §4).

### Windows A: браузераар татах

**Шаардлага:** Windows 10 1809 ба түүнээс хойш эсвэл Windows 11, x64; суулгалт шаардахгүй
([дэлгэрэнгүй](#шаардлага-ба-бичдэг-файлууд)).

1. Браузераар татна:
   <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-windows-x64.zip>
   (эсвэл [Releases](https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest) хуудасны «Assets» хэсгээс
   `eid-token-test-windows-x64.zip`). Ногоон «Code → Download ZIP» **биш**.
2. **Задлахаас ӨМНӨ:** татсан zip дээр баруун товч → **Properties** → доод хэсгийн **«Unblock»**-ийг чагтална → **OK**.
   PowerShell-ээр: `Unblock-File .\eid-token-test-windows-x64.zip`. Unblock хийсэн zip-ээс задалсан файлд
   Mark-of-the-Web байхгүй тул анхааруулгын цонх гарахгүй.
3. Zip дээр баруун товч → **Extract All…** → **Extract**. `eid-token-test-windows-x64` нэртэй хавтас үүснэ.
4. Тэр хавтсыг нээ — дотор нь **ижил нэртэй** `eid-token-test-windows-x64` хавтас дахин бий, түүнийг ч нээ. Exe-ийн зам:
   `<задалсан газар>\eid-token-test-windows-x64\eid-token-test-windows-x64\eid-token-test.exe`.
5. `eid-token-test.exe` дээр давхар дарна. Хажууд нь олон `.dll` файл байгаа — нэрээр эрэмбэл, эсвэл «Type» нь
   «Application» файлыг ол.
6. «Unblock»-ийг алгассан бол «Open File - Security Warning» («The publisher could not be verified») цонх гарна →
   **Run**. Оронд нь «Windows protected your PC» (SmartScreen) цонх гарч ч болно → **More info** → **Run anyway**.
   (Exe code-signing гарын үсэггүй.)

**Амжилттай бол:** «eID Token Test» цонх гурван хэсэгтэй нээгдэнэ ([доор](#цонхны-гурван-хэсэг-хоёр-платформд-ижил));
exe-ийн хажуудах `eid-token-test.log`-д `main page loaded` мөр бичигдэнэ.

**Түгээмэл саад:**

- Exe олдохгүй, zip дотор зөвхөн `.sln`, `src`, `tests` байна → эх кодын архив («Code → Download ZIP») татсан байна;
  1-р алхмын холбоосоор дахин тат.
- «Unblock»-ийг алгассан → апп эхлэхээсээ өмнө дээрх анхааруулгын цонхонд хариулт хүлээнэ; хариулах хүртэл апп
  **эхлэхгүй**. Дэлгэц харагдахгүй үед (ssh, дэлгэцгүй алсын холболт) чимээгүй гацсан мэт харагдана. Аль хэдийн
  задалсан бол тэр хавтсанд PowerShell-ээр: `Get-ChildItem -Recurse | Unblock-File`.

### Windows B: PowerShell-ээр татах

**Шаардлага:** Windows A-тай ижил; Windows PowerShell 5.1 (Windows-д суусан) хангалттай.

`curl.exe`-ээр татсан файлд Mark-of-the-Web тавигддаггүй тул «Unblock» алхам хэрэггүй. **`curl.exe`** гэж бүтнээр нь
бич — Windows PowerShell-д `curl` нь `Invoke-WebRequest`-ийн alias.

1. Zip ба `SHA256SUMS`-ийг татна:

   ```powershell
   cd $HOME\Downloads
   curl.exe -fLO https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-windows-x64.zip
   curl.exe -fLO https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/SHA256SUMS
   ```

2. Checksum тулгана — **`True`** хэвлэх ёстой (`False` бол задлахгүй, дахин тат):

   ```powershell
   (Get-FileHash .\eid-token-test-windows-x64.zip -Algorithm SHA256).Hash -eq ((Select-String -Path .\SHA256SUMS -Pattern 'windows-x64\.zip').Line -split '\s+')[0]
   ```

3. Задална: `Expand-Archive .\eid-token-test-windows-x64.zip -DestinationPath .`
4. Апп нээнэ: `Start-Process .\eid-token-test-windows-x64\eid-token-test.exe`

**Амжилттай бол:** 2-р алхам `True`; Windows A-тай ижил цонх нээгдэнэ.

**Түгээмэл саад:** `curl`-ыг `.exe`-гүй бичвэл `Invoke-WebRequest` ажиллаж `-fLO` параметрийг танихгүй алдаа гарна →
`curl.exe`. Өмнө нь задалсан `eid-token-test-windows-x64` хавтас байвал `Expand-Archive` алдаа өгнө — хуучин хавтсыг
устга эсвэл `-Force` нэм.

### Windows C: эх кодоос бүтээх

**Шаардлага:** .NET 10 SDK. Энд л эх код хэрэгтэй: «Code → Download ZIP» эсвэл
`git clone https://github.com/gerege-systems/eid-mongolia-token-sdk.git`. Алхмууд: [§4 Windows](#4-эх-кодоос-бүтээх).

### macOS A: Terminal-аар татах

**Шаардлага:** macOS 14 ба түүнээс хойш, Apple Silicon эсвэл Intel ([дэлгэрэнгүй](#шаардлага-ба-бичдэг-файлууд)).

**Санал болгож буй зам.** `curl`-аар татсан файлд macOS «quarantine» тэмдэг тавьдаггүй тул Gatekeeper-ийн анхааруулга
гарахгүй, нэмэлт алхам хэрэггүй.

1. Terminal нээнэ (Applications → Utilities → Terminal).
2. Дараах мөрүүдийг ажиллуулна:

   ```bash
   cd ~/Downloads
   curl -fLO https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-macos.zip
   curl -fLO https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/SHA256SUMS
   shasum -a 256 -c SHA256SUMS --ignore-missing      # eid-token-test-macos.zip: OK
   unzip -q eid-token-test-macos.zip
   open "eid-token-test-macos/eID Token Test.app"
   ```

**Амжилттай бол:** `eid-token-test-macos.zip: OK` мөр хэвлэгдэж, «eID Token Test» цонх нээгдэнэ.

**Түгээмэл саад:** `shasum` `OK` биш мөр хэвлэвэл файл бүтэн татагдаагүй — задлахгүй, дахин тат.

### macOS B: браузераар татах

**Шаардлага:** macOS A-тай ижил; Terminal-д нэг команд ажиллуулна.

**Гарын үсэг:** энэ build-үүд **ad-hoc** гарын үсэгтэй, Apple-аар **notarize хийгдээгүй**. Браузераар татсан zip
«quarantine» тэмдэгтэй тул Gatekeeper анхны нээлт дээр зогсооно. Эх кодоос өөрөө бүтээвэл (§4) энэ асуудал гарахгүй.

1. Браузераар татна:
   <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest/download/eid-token-test-macos.zip>.
2. **Анхны нээлтээс ӨМНӨ** quarantine-ийг арилга — zip дээр (задлахаас өмнө) эсвэл задалсан **бүх хавтас** дээр (апп,
   `eid-token-check`, модулийн файлууд бүгд). Terminal-д:

   ```bash
   cd ~/Downloads
   xattr -dr com.apple.quarantine eid-token-test-macos.zip      # эсвэл: xattr -dr com.apple.quarantine eid-token-test-macos/
   ```

   quarantine тавьдаггүй хэрэгслээр (`curl`, `gh release download`) татсан файлд энэ алхам хэрэггүй.
3. Finder-т zip дээр давхар дарж задална → `eid-token-test-macos` хавтас.
4. `eid-token-test-macos/eID Token Test.app`-ийг нээнэ.

**Амжилттай бол:** «eID Token Test» цонх анхааруулгагүй нээгдэнэ.

**Түгээмэл саад:** Quarantine-тэй хэвээр нээвэл: апп «Not Opened / Apple could not verify …» цонх гаргана → System
Settings → Privacy & Security → «Open Anyway». `eid-token-check`-ийн процесс тэр цонхонд хариулах хүртэл `main`-аас ӨМНӨ
зогсоно — ssh / дэлгэцгүй үед чимээгүй гацсан мэт харагдана (§8 «eid-token-check хариу өгөхгүй гацсан»).

### macOS C: эх кодоос бүтээх

**Шаардлага:** Xcode 16+, XcodeGen 2.45.4. Энд л эх код хэрэгтэй: «Code → Download ZIP» эсвэл
`git clone https://github.com/gerege-systems/eid-mongolia-token-sdk.git`. Алхмууд: [§4 macOS](#4-эх-кодоос-бүтээх).

### Command-line хэрэгсэл: суулгах шаардлагагүй

`eid-token-check` тусад нь суулгахгүй — хоёр zip-д апптай хамт ирнэ. Дээрх A эсвэл B замаар zip-ээ авч задлаад
тэр хавтсаас ажиллуулна ([§7](#7-command-line-хэрэгсэл-eid-token-check)):

- Windows: `eid-token-test.exe`-тэй нэг хавтсанд байгаа `eid-token-check\` хавтас —
  `eid-token-check\eid-token-check.exe` (хажуудаа `opensc-pkcs11.dll`). Windows B-ээр задалсан бол
  `.\eid-token-test-windows-x64\eid-token-check\eid-token-check.exe`; Windows A-аар (Extract All) задалсан бол
  `eid-token-test-windows-x64\` нэг түвшин нэмэгдэнэ:
  `<задалсан газар>\eid-token-test-windows-x64\eid-token-test-windows-x64\eid-token-check\eid-token-check.exe`;
- macOS: `eid-token-test-macos/eid-token-check/eid-token-check` (хажуудаа `opensc-pkcs11.so`, `libopensc.12.dylib`,
  `trust/`).

### Шаардлага ба бичдэг файлууд

**macOS**

- **Шаардлага:** macOS 14 ба түүнээс хойш, Apple Silicon эсвэл Intel (апп, модуль, CLI нь universal). Нэмэлт драйвер,
  OpenSC суулгах шаардлагагүй — модуль апп дотор (`Contents/Frameworks/`); токеныг macOS-ийн PC/SC-ээр уншина.
- **Бичдэг файлууд:** апп систем, keychain-д юу ч бичихгүй; түр хавтсанд OpenSC-ийн жижиг тохиргооны файл, эхлэх бүрд
  `~/Library/Logs/eid-token-test.log`-д эхлэлийн мөр (`main page loaded` эсвэл эхлэлийн алдаа; PIN, гэрчилгээ хэзээ ч
  биш). `EID_TOKEN_TEST_LOG` орчны хувьсагчаар өөр зам заана.

**Windows**

- **Шаардлага:** Windows 10 1809 (17763) ба түүнээс хойш эсвэл Windows 11, **x64**. Суулгалт шаардахгүй
  (self-contained: .NET 10 ба Windows App SDK хавтас дотроо). Smart Card service (`SCardSvr`) ажиллаж байх ёстой
  (анхдагчаар асаалттай). Апп Windows-ийн гэрчилгээний санд юу ч суулгахгүй, registry бичихгүй.
- **Бичдэг файлууд:** апп эсвэл `eid-token-check` ажиллах бүрд `%TEMP%\eid-token-test-<guid>\opensc.conf` (OpenSC-ийн
  ≈31 байт тохиргооны файл) үүсгэнэ; эдгээр хавтас автоматаар **устахгүй**, устгахад аюулгүй. Апп эхлэх бүрд
  `eid-token-test.log` — exe-ийн хажууд, тэр хавтас бичигдэхгүй бол `%TEMP%`-д (эхлэлийн мөр `main page loaded` эсвэл
  эхлэлийн алдаа; PIN, гэрчилгээ хэзээ ч биш; `EID_TOKEN_TEST_LOG`-оор өөр зам заана).

### Татсан файлыг шалгах

Release бүрт хоёр zip ба `SHA256SUMS` хавсаргагдана (хоёр zip-ийн SHA-256 нь release-ийн тайлбарт ч бий). Тулгах
команд: macOS — `shasum -a 256 -c SHA256SUMS --ignore-missing` ([macOS A](#macos-a-terminal-аар-татах)), Windows —
PowerShell `Get-FileHash` ([Windows B](#windows-b-powershell-ээр-татах), 2-р алхам). Checksum нь зөвхөн **татсан файл
бүтэн, өөрчлөгдөөгүйг** (release хуудастай таарч буйг) харуулна — хэн бүтээснийг батлахгүй (build-үүд code-signing-гүй).
Release-ийн файлууд зөвхөн **GitHub-hosted** runner (macos-15, windows-latest) дээр, `main` дээрх tag-ийн яг тэр
commit-оос, CI-тэй ижил алхмаар (unit тест орно) бүтээгдэнэ; macOS-ийн OpenSC, OpenSSL, XcodeGen-ийг SHA-256-аар
бэхэлсэн эх сурвалжаас шинээр бүтээнэ. PR-ийн build-үүд self-hosted runner дээр явж болох ч тэр нь итгэлийн хил биш —
тэдгээрээс юу ч release-д орохгүй.

### Цонхны гурван хэсэг (хоёр платформд ижил)

1. **Токен** — залгаатай токенууд: label, серийн дугаар, загвар; PIN-ий төлөв (оролдлого цөөн / сүүлийн оролдлого /
   түгжигдсэн). Токен залгасан / салгасны дараа «Дахин унших».
2. **Гэрчилгээ** — сонгосон токены гэрчилгээнүүд PIN-гүйгээр: төрөл («Нэвтрэх» = AUTH, «Гарын үсэг» = SIGN — `CKA_ID`-аар),
   эзэмшигч, subject `serialNumber`, олгогч, серийн дугаар (hex), хүчинтэй хугацаа. eID-ийн `CKA_ID`-тай гэрчилгээ
   алга бол «eID гэрчилгээ олдсонгүй» гэж харуулж, нэвтрэх тестийг хаана.
3. **Нэвтрэх тест** — «Origin» (анхдагч `test.example`; танай host нэр, §6.1-ийн дүрмээр) ба PIN оруулаад «Нэвтрэх»:
   32 байт санамсаргүй challenge → digest → AUTH түлхүүрээр `CKM_ECDSA` (нэг `C_Login`) → §6-ийн таван шалгалт:
   «Challenge-ийн гарын үсэг», «Гэрчилгээний гинж», «Хүчинтэй хугацаа», «OCSP», «CRL» — тус бүр ✓ / ✗ /
   «шалгаж чадсангүй» ба нэг мөр шалтгаан.

**Амжилттай тест:** таван мөр бүгд ✓, доор нь «Нэвтэрлээ: ‹эзэмшигчийн нэр›». Гинжний мөрийн шалтгаанд
`‹нэр› → eID Mongolia Issuing CA → Gerege Issuing CA → Mongolian National Issuing CA → Mongolian National Root CA;
олгогч CA цуцлагдаагүй (OCSP ✓, CRL ✓)` гэх мэт бичигдэнэ. Аль нэг мөр ✓ биш бол «Нэвтэрч чадсангүй: ‹шалгалт› —
‹шалтгаан›». Сүлжээгүй бол OCSP / CRL «шалгаж чадсангүй» тул **нэвтрэхгүй** (fail closed).

PIN: зөвхөн тухайн нэг `C_Login`-д ашиглагдаад санах ойгоос арилна; лог, файлд бичигдэхгүй. Сүүлийн оролдлого дээр апп
тусад нь баталгаажуулалт асууна; түгжигдсэн бол «Нэвтрэх» идэвхгүй. Буруу PIN-д дахин автоматаар оролдохгүй.

## 4. Эх кодоос бүтээх

Энд эх код хэрэгтэй: GitHub-ийн «Code → Download ZIP» эсвэл
`git clone https://github.com/gerege-systems/eid-mongolia-token-sdk.git` (Releases-ийн zip-д эх код байхгүй).
CI-ийн workflow-ууд яг эдгээр командыг ажиллуулна (`.github/workflows/`).

### macOS (Xcode 16+, XcodeGen 2.45.4)

```bash
cd macos
bash scripts/build_opensc.sh                 # OpenSC 0.26.1 + OpenSSL 3.5.9 (эх код, SHA-256-аар бэхэлсэн) → macos/.opensc/
xcodegen generate
(cd EIDTokenCheck && swift test --parallel)  # unit тест
xcodebuild -project EIDTokenTest.xcodeproj -scheme EIDTokenTest -configuration Release \
  -destination 'generic/platform=macOS' CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM= build
(cd EIDTokenCheck && swift build -c release --product eid-token-check --arch arm64 --arch x86_64)
```

Xcode-ийн «Bundle OpenSC» алхам (`scripts/bundle_opensc.sh`) модулийг `Contents/Frameworks/`-д хуулж аппын
identity-гээр гарын үсэг зурна; OpenSC мод өөр газар бол `OPENSC_PREFIX`-ээр заана. CLI-г ажиллуулахдаа
`opensc-pkcs11.so`, `libopensc.12.dylib`-ийг (аппын `Contents/Frameworks/`-ээс) ба `trust/` хавтсыг
`eid-token-check`-ийн хажууд тавина.

### Windows (.NET 10 SDK — `windows/global.json`: 10.0.400 feature band ба түүнээс хойш)

```powershell
cd windows
dotnet test tests/EidTokenTest.Tests/EidTokenTest.Tests.csproj -c Release
dotnet publish src/EidTokenTest.App/EidTokenTest.App.csproj -c Release -p:Platform=x64 -o out
dotnet publish src/EidTokenTest.Cli/EidTokenTest.Cli.csproj -c Release -r win-x64 --self-contained true -o out\eid-token-check
```

`opensc-pkcs11.dll` (`third_party/opensc/`) апп-ийн `opensc\` дэд хавтсанд, CLI-ийн хажууд автоматаар хуулагдана.

### Release (maintainer)

1. Release хийх commit `main` дээр байна; түүн дээр tag тавина: `git tag v0.3.0 <commit> && git push origin v0.3.0`.
2. GitHub → Actions → **release** → «Run workflow»: branch **main**, `tag` = `v0.3.0`.
3. Workflow tag main дээр байгааг шалгаад тэр commit-ийг GitHub-hosted runner-ууд дээр бүтээж, хоёр zip + `SHA256SUMS`-ийг
   Release-д хавсаргана. Tag-ийг дундаас нь өөр commit руу шилжүүлбэл юу ч нийтлэхгүй; файлтай release-ийг дахин бичихгүй.
4. CI-ийн macOS release замыг нийтлэхгүйгээр шалгах: Actions → **ci** → «Run workflow», `macos_release_dry_run` ✓.

## 5. Module-ийг өөрийн апп-д ашиглах

Токен нь стандарт PKCS#15 бүтэцтэй тул стандарт **OpenSC PKCS#11 module**-ээр уншигдана; тусгай wrapper сан хэрэггүй.

### 5.1 Тараах файлууд

| Платформ | Файл | Тэмдэглэл |
|---|---|---|
| Windows | `opensc-pkcs11.dll` | OpenSC 0.26.1 албан ёсны release-ийн DLL, өөрчлөлтгүй, SHA-256 `6c1eb3705a477fbec73cf007b6f868c77cb8a58b902fab9f6d884570c9c4e68e`. Зөвхөн Windows-ийн системийн DLL-ээс хамаарна. **Зөвхөн 64-bit процесс** ачаална. |
| macOS | `opensc-pkcs11.so` + `libopensc.12.dylib` | `opensc-pkcs11.so` нь `libopensc.12.dylib`-ийг `@loader_path`-аас ачаална — **хоёуланг нэг хавтсанд**. OpenSSL static. Universal, macOS 14+. |

Хоёуланд `COPYING` (LGPL-2.1) ба OpenSSL-ийн лицензийг хамт тараана (§9).

### 5.2 Ачаалах

- Модулийг ачаалахаас **өмнө** `OPENSC_CONF` орчны хувьсагчийг өөрийн жижиг тохиргооны файл руу заа — эс бөгөөс
  module-д суусан анхдагч зам эсвэл тухайн компьютерт суусан өөр OpenSC-ийн тохиргоо уншигдана. Модуль үүнийг
  ачаалагдах үедээ уншина. Хангалттай агуулга:

  ```
  app default {
      debug = 0;
  }
  ```

- Стандарт PKCS#11 v2.20 урсгал: `C_GetFunctionList` / `C_Initialize` → `C_GetSlotList(CK_TRUE)` → `C_GetTokenInfo` →
  `C_OpenSession(CKF_SERIAL_SESSION)` (**`CKF_RW_SESSION`-гүй**).
- Хэд хэдэн токен залгаатай байж болно: токеныг `C_GetTokenInfo`-ийн `serialNumber`-ээр (хоосон зайг хассан) ялга,
  «эхний slot»-ыг бүү сонго.

### 5.3 Токен дээрх объектууд

Токенд **нэг AUTH** (нэвтрэх) ба **нэг SIGN** (гарын үсэг) түлхүүрийн хос байна. Объектыг **`CKA_ID`-аар** ол
(`CKA_LABEL` нь ижил утгыг хүнд уншигдахаар давтана). `CKA_ID` зөвхөн объектыг олох арга — гэрчилгээ нэвтрэлтэд
тохирох эсэхийг сервер §6.2-оор **заавал** шалгана.

| Үүрэг | `CKA_ID` (hex) | `CKA_LABEL` | Объектууд |
|---|---|---|---|
| AUTH — нэвтрэх | `45 49 44 01` | `eID AUTH` | private key, public key, X.509 certificate |
| SIGN — гарын үсэг | `45 49 44 02` | `eID SIGN` | private key, public key, X.509 certificate — **нэвтрэлтэд бүү ашигла** |

Гэрчилгээ сунгах явцад шинэ хос түр хугацаанд `45 49 44 11` (`eID AUTH (new)`) / `45 49 44 12` (`eID SIGN (new)`) ID-тай
байж болно. Дүрэм (тест аппуудынх): AUTH гэрчилгээ = `…01`-тэй гэрчилгээ, байхгүй бол `…11`-тэй; хувийн түлхүүрийг
**ижил `CKA_ID`-аар** хайна. Эдгээр `CKA_ID`-тай гэрчилгээ огт байхгүй бол «eID гэрчилгээ олдсонгүй».

- Гэрчилгээ (`CKO_CERTIFICATE`, `CKA_VALUE` = DER) нь нийтийн объект — PIN шаардахгүй уншина.
- Private key нь `CKA_SENSITIVE = TRUE`, `CKA_EXTRACTABLE = FALSE` — токеноос гарахгүй.

### 5.4 Түлхүүр, механизм, PIN

| | |
|---|---|
| Түлхүүрийн төрөл | EC **P-256** (secp256r1, `1.2.840.10045.3.1.7`) |
| Механизм | **`CKM_ECDSA`** (`0x00001041`) |
| `C_Sign`-ийн оролт | 32 байт **SHA-256 digest** — module өөрөө hash хийхгүй |
| `C_Sign`-ийн гаралт | **raw `r‖s`, 64 байт** (r 32 ‖ s 32, big-endian) — DER биш |

DER (`ECDSA-Sig-Value`) шаарддаг сан (Java `SHA256withECDSA`, OpenSSL `EVP_DigestVerify`)-д хөрвүүл, эсвэл IEEE P1363
хэлбэрийг шууд хүлээн авдаг горимыг ашигла (Java `SHA256withECDSAinP1363Format`, Node.js `dsaEncoding: 'ieee-p1363'`,
.NET `DSASignatureFormat.IeeeP1363FixedFieldConcatenation`).

- Токен **нэг хэрэглэгчийн PIN** (`CKU_USER`) ба PUK-тэй. PIN-ий урт: `C_GetTokenInfo`-ийн `ulMinPinLen` / `ulMaxPinLen`.
- AUTH түлхүүр: session-д нэг удаа `C_Login(CKU_USER, PIN)` → `C_SignInit(CKM_ECDSA)` → `C_Sign` → `C_Logout`.
- `C_Login`-оос өмнө `C_GetTokenInfo`-ийн flag-ийг уншиж хэрэглэгчид анхааруул: `CKF_USER_PIN_COUNT_LOW` (`0x00010000`)
  — оролдлого цөөн; `CKF_USER_PIN_FINAL_TRY` (`0x00020000`) — сүүлийн оролдлого (тодорхой баталгаажуулалт ав);
  `CKF_USER_PIN_LOCKED` (`0x00040000`) — түгжигдсэн, `C_Login` бүү дууд.
- Нэг нэвтрэх оролдлого = **нэг** `C_Login`. Буруу PIN-ий дараа автоматаар дахин бүү оролд.
- `C_Login` нь `CKR_USER_ALREADY_LOGGED_IN` буцаавал (тухайн session-д та өөрөө нэвтрээгүй — өөр session нэвтэрсэн):
  нэвтэрсэн гэж бүү тооц, гарын үсэг бүү зур — татгалз. Тест аппууд хоёр платформд ингэж татгалзана.
- Гарын үсэг зурахын өмнө токеныг **serial-аар дахин** ол (slot ID-г санаж бүү ашигла): тэр slot-д өөр токен залгагдсан
  бол `C_Login`-оос өмнө татгалз; хоосон serial-аар токен бүү сонго. Тест аппууд хоёр платформд ингэнэ.
- PIN-ийг лог, файл, санах ойд үлдээхгүй; ашигласны дараа устга. PIN тайлах (PUK) энэ багцын хүрээнд биш — түгжигдсэн
  токены эзэмшигч токен олгосон байгууллагад хандана.

### 5.5 Challenge-д гарын үсэг зуруулах

Клиент серверээс 32 байт challenge авч, **өөрийн мэдэх** серверийн host нэрээр (`origin`, §6.1) digest тооцоод AUTH
түлхүүрээр зурна; `r‖s` ба AUTH гэрчилгээг (DER) сервер рүү буцаана:

```
digest = SHA-256( "eID-TOKEN-LOGIN-V1" ‖ origin ‖ challenge )
```

**C# (Pkcs11Interop 5.2.0)** — `windows/src/EidTokenTest.Core/Tokens/Pkcs11TokenReader.cs`-аас:

```csharp
var factories = new Pkcs11InteropFactories();
using var library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, modulePath, AppType.MultiThreaded);
var slot = library.GetSlotList(SlotsType.WithTokenPresent)
    .First(s => s.GetTokenInfo().SerialNumber.Trim(' ', '\0') == serial);
using var session = slot.OpenSession(SessionType.ReadOnly);              // CKF_RW_SESSION-гүй
var attrs = session.Factories.ObjectAttributeFactory;
byte[] authId = [0x45, 0x49, 0x44, 0x01];
var cert = session.FindAllObjects([attrs.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE), attrs.Create(CKA.CKA_ID, authId)])[0];
var certificateDer = session.GetAttributeValue(cert, [CKA.CKA_VALUE])[0].GetValueAsByteArray();   // PIN-гүй
var digest = LoginChallenge.DigestToSign(origin, challenge);              // Verification/LoginChallenge.cs
session.Login(CKU.CKU_USER, pinBytes);                                    // яг нэг удаа
try
{
    var key = session.FindAllObjects([attrs.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), attrs.Create(CKA.CKA_ID, authId)])[0];
    var rs = session.Sign(session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA), key, digest);   // r‖s, 64 байт
}
finally
{
    session.Logout();
    CryptographicOperations.ZeroMemory(pinBytes);
}
```

**Swift** — `macos/EIDTokenCheck/Sources/EIDTokenReader/` (`TokenReader`, `TokenLogin`)-аас:

```swift
OpenSCConfig.isolate()                                              // OPENSC_CONF, модулийг ачаалахаас өмнө
let reader = try TokenReader(modulePath: modulePath)               // dlopen opensc-pkcs11.so
let certificates = try reader.certificates(serial: serial)         // PIN-гүй, read-only session
guard let auth = TokenLogin.authCertificate(certificates),         // CKA_ID 45494401 (эсвэл 45494411)
      let challenge = challengeFromServer,
      let digest = LoginChallenge.digestToSign(origin: origin, challenge: challenge) else { return }
let rs = try reader.signDigest(serial: serial, keyID: auth.keyID, digest: digest, pin: pin)   // нэг C_Login + C_Sign
// rs (64 байт) ба auth.der-ийг сервер рүү илгээнэ
```

Java (SunPKCS11), Python (python-pkcs11 / PyKCS11), Go (miekg/pkcs11), C/C++ гэх мэт аль ч PKCS#11 binding ижил дарааллаар
ажиллана: модулийг ачаалах → serial-аар slot сонгох → read-only session → `CKA_ID`-аар гэрчилгээ → нэг `C_Login` →
`CKM_ECDSA`-аар digest зурах.

## 6. Сервер дээрх нэвтрэлтийн шалгалт (норматив)

```
Сервер                                        Клиент (PKCS#11)
  challenge = ЯГ 32 санамсаргүй байт   ──►    challenge 32 байт биш бол зогсоно (гарын үсэг зурахгүй)
  (нэг удаагийн, богино хугацаатай,           digest = SHA-256( "eID-TOKEN-LOGIN-V1" ‖ origin ‖ challenge )
   session-д холбогдсон)                      C_Login(CKU_USER, PIN)            — нэг удаа
                                              C_Sign(AUTH key, CKM_ECDSA, digest) → r‖s (64 байт)
                                       ◄──    r‖s + AUTH гэрчилгээ (DER, токеноос)
  доорх 6.1–6.6-г бүгдийг шалгана
```

Сервер **бүх** шалгалтыг хийнэ. Аль нэг нь бүтэлгүйтвэл (✗) ЭСВЭЛ хийгдэж чадаагүй бол («шалгаж чадсангүй») —
**нэвтрүүлэхгүй** (fail closed). Шалгагчийн код (`LoginVerifier`) хоёр платформд эдгээрийг энэ дарааллаар хийнэ:
challenge-ийн гарын үсэг → гинж (олгогч CA-ийн цуцлалтыг оруулаад) → хүчинтэй хугацаа → OCSP → CRL.

Ерөнхий дүрэм: DER **хатуу** (definite, хамгийн богино урт — урт кодчилол илүүдэлтэй бол ✗; BOOLEAN нь яг нэг байт
`0xFF` / `0x00`; INTEGER хамгийн богино хэлбэр; байхгүй огноо — 2-р сарын 30, 4-р сарын 31, 60 дахь секунд — ✗);
клиентээс ирсэн AUTH гэрчилгээ нь **яг нэг DER `Certificate`** (PEM, PKCS#7, PFX, ард илүү байт, хоосон → ✗; PEM /
PKCS#7 / PFX-ийг хүлээж авдаг ачаалагч руу шалгахаас өмнө бүү өг); X.509 `Time` нь UTCTime ба GeneralizedTime
хоёуланг хүлээн авна; хугацааны хил хоёр талдаа **оролцоотой** (`notBefore ≤ одоо ≤ notAfter`,
`nextUpdate ≥ одоо − 5 мин`, `thisUpdate ≤ одоо + 5 мин`).

### 6.1 Origin ба challenge-ийн гарын үсэг

- `"eID-TOKEN-LOGIN-V1"` — 18 байт ASCII тогтмол угтвар, төгсгөлийн тэг байтгүй. `‖` — байтуудыг дараалан залгана
  (урт, тусгаарлагчгүй; challenge үргэлж 32 байт тул задрал нэг утгатай).
- **`origin`** — танай (relying party-ийн) **өөрийн host нэр**. Шалгагч үүнийг гарын үсэг зурах / шалгахаас **өмнө**
  баталгаажуулна; таарахгүй бол юу ч хийхгүй: хоосон биш; **жижиг үсгийн ASCII** (IDN бол A-label / punycode,
  `xn--…`); цэгээр тусгаарлагдсан label бүр 1–63 тэмдэгт, `a–z`, `0–9`, `-` (label-ийн эхэнд, төгсгөлд `-` биш);
  нийт ≤ 253 тэмдэгт; **scheme, порт, зам, төгсгөлийн цэг байхгүй** (`login.example.mn` ✓; `https://login.example.mn`,
  `login.example.mn:443`, `login.example.mn/`, `Login.example.mn`, `login.example.mn.` ✗). Клиент `origin`-ийг серверээс
  авсан утгаар биш, өөрийн мэдэх хаягаар тавина.
- **Сервер дээрх `origin` бол серверийн тохиргооны ТОГТМОЛ** — хүсэлтээс (`Host`, `X-Forwarded-Host`, `Origin`,
  `Referer` толгой, биеийн талбар) **хэзээ ч** бүү ав. Хүсэлтээс авбал халдагч өөр сайтын нэрээр зурагдсан гарын үсгийг
  тэр сайтын нэрийг толгойд тавиад танай сервер рүү дамжуулж (relay) танай сайтад нэвтэрч чадна — `origin`-ийн холбоос
  утгагүй болно.
- Challenge-ийг та өөрөө үүсгэсэн, **яг 32 байт**, ашиглагдаагүй, хугацаа нь дуусаагүй байна. Digest-ийг **та өөрөө**
  өөрийн `origin` ба challenge-аас тооцно — клиентээс digest хүлээн авч бүү шалга.
- AUTH гэрчилгээний түлхүүр **EC P-256** (`id-ecPublicKey`, `prime256v1`); өөр төрөл → ✗.
- Гарын үсэг **raw `r‖s`, яг 64 байт**, `1 ≤ r, s ≤ n − 1` (n — P-256-ийн эрэмбэ); DER хэлбэр, өөр урт, `r` эсвэл
  `s` = 0 → ✗. Дараа нь AUTH гэрчилгээний нийтийн түлхүүрээр digest дээр ECDSA-аар шалгана.

**Яагаад challenge-ийг шууд зуруулахгүй вэ.** Нэг AUTH түлхүүрийг өөр нэвтрэх протоколууд (өөр угтвартай) мөн ашигладаг.
Серверээс ирсэн дурын байтыг шууд зурдаг клиентийг ашиглан халдагч өөр сайтын challenge-ийг танай клиентээр зуруулж,
тэр сайтад нэвтэрч (relay) чадна. Угтвар нь гарын үсгийг энэ протоколд, `origin` нь танай сайтад холбодог.

### 6.2 Гэрчилгээний гинж ба AUTH профайл

AUTH гэрчилгээнээс `trust/anchors/` дахь үндэс хүртэлх замыг шалга (гарын үсэг, нэр, CA basicConstraints, pathLen),
зөвхөн `trust/` дахь гэрчилгээгээр — системийн итгэлийн санг бүү ашигла. Үндэс эсвэл завсрын CA гэдгийг **хавтсаар**
(`anchors/` / `intermediates/`) шийднэ:

```
Mongolian National Root CA                  trust/anchors/01-…        (цорын ганц итгэлийн үндэс)
  └─ Mongolian National Issuing CA          trust/intermediates/02-…
       └─ Gerege Issuing CA                 trust/intermediates/03-…
            └─ eID Mongolia Issuing CA      trust/intermediates/04-…  (pin)
                 └─ AUTH гэрчилгээ (токен)
```

| Файл | SHA-256 (DER) |
|---|---|
| `anchors/01-mongolian-national-root-ca.pem` | `cbe7f3fe1f048037c215da321e58caa4f363de9e54bbc442a3bfd62fad834482` |
| `intermediates/02-mongolian-national-issuing-ca-mddc.pem` | `9423640dd74561d1af1ea8a093860bda7df5b5620bb617921395dc0d1a1f980d` |
| `intermediates/03-gerege-issuing-ca.pem` | `56f3d1ca7f282287619773905aa0cd7a427d4f95dc0ed7b6733963a89bc31237` |
| `intermediates/04-eid-mongolia-issuing-ca.pem` | `87b8db6862abde5e4a07a10c2c696afe5cb6aea072b9f3f9755e73ce79f546fc` |

Дараах бүгд **заавал**:

1. **Шууд олгогч нь зөвхөн 04 (pin).** Pin нь `04` файлын DER-ийн SHA-256 (`87b8db68…46fc`). Бүтээсэн замын [1]
   элемент (AUTH гэрчилгээний шууд олгогч) нь pin хийсэн 04-тэй **ижил subject БА ижил нийтийн түлхүүртэй** байна;
   үгүй бол → ✗. Платформын зам бүтээгч (macOS keychain, Windows-ийн CA store) 04-ийн өөр хуулбарыг (ижил subject +
   түлхүүр, өөр DER) замдаа оруулж болно — тэгвэл платформ AUTH гэрчилгээний гарын үсгийг тэр хуулбарын (ижил) түлхүүрээр
   шалгаж, тэр хуулбарын хязгаарлалтыг (basicConstraints, pathLen …) хэрэглэнэ; платформын замын гэрчилгээ бүр тухайн
   агшинд хүчинтэй байх ёстой (хоёр платформд ижил). Үүнээс хойш код зөвхөн `trust/` дахь pin хийсэн 04-ийг ашиглана:
   `trust/`-ээс авсан замын шалгалт ба хугацаа (доор), олгогчийг тодорхойлох, OCSP / CRL-ийг шалгах. Ижил нэртэй өөр
   түлхүүртэй CA → ✗. Ижил үндэс
   доорх өөр CA-ийн олгосон гэрчилгээ → ✗ — үүнд clientAuth-тэй relying party mTLS гэрчилгээ олгодог eID Mongolia
   **Organization** Issuing CA (05) ч орно; 05 нь `trust/`-д байхгүй, нэвтрэлтэд хэзээ ч тэнцэхгүй. 02 эсвэл 03-ын
   шууд олгосон гэрчилгээ → ✗.

   04-өөс дээших CA-ийн замыг (04 → 03 → 02 → 01) зөвхөн `trust/`-ээс (нэр + гарын үсгээр) авна; замын CA бүр
   хүчинтэй хугацаандаа байна, үгүй бол **гинж ✗** («Гинжний гэрчилгээ (‹нэр›) хүчинтэй хугацаанаас гадуур»). macOS
   (`SecTrustSetKeychains` 10.12-оос хойш нөлөөгүй) ба .NET (Windows-ийн CA store-ийг хасах тохиргоогүй) аль аль нь
   завсрын CA-г зөвхөн өгсөн гэрчилгээнээс хайхыг хязгаарлаж чадахгүй тул энэ дүрмийг кодоороо хэрэгжүүлнэ; сүлжээнээс
   (AIA) завсрын CA татахыг хоёуланд нь унтраасан.

   `trust/`-ийн файл (эсвэл `TrustAnchors` / `TrustStore`-д өгсөн гэрчилгээ) яг нэг хатуу DER гэрчилгээ биш бол ачаалах
   үед **алдаа** (файлын нэртэй) — чимээгүй алгасахгүй: .NET `TrustAnchors.Bundled()` / `new TrustAnchors(…)` →
   exception, Swift `TrustStore.load` / `TrustStore(anchors:intermediates:)` → `throw`; тест аппууд эхлэхдээ зогсоно,
   `eid-token-check` exit 1.
2. **AUTH профайл** (токены AUTH гэрчилгээний CA профайл: KeyUsage зөвхөн digitalSignature, EKU clientAuth +
   emailProtection, subject `serialNumber` = `PNOMN-…`):
   - KeyUsage өргөтгөл **байгаа** ба **яг {digitalSignature}** — өөр ямар ч бит (nonRepudiation, keyEncipherment …) → ✗;
   - ExtendedKeyUsage өргөтгөл **байгаа** ба **clientAuth** (`1.3.6.1.5.5.7.3.2`)-тэй (бусад EKU байж болно);
   - subject-д **яг нэг** `serialNumber` (`2.5.4.5`) атрибут, **`PNOMN-`**-ээр эхэлнэ;
   - аль нэг өргөтгөл / атрибут байхгүй бол → ✗.

   Ингэснээр SIGN гэрчилгээ (nonRepudiation), OCSP responder-ийн гэрчилгээ (clientAuth-гүй), байгууллага / relying
   party-ийн гэрчилгээ нэвтрэлтэд орохгүй.
3. **Олгогч CA (04) цуцлагдаагүй.** 04-ийн гэрчилгээ өөрөө цуцлагдаагүйг AUTH гэрчилгээнийхтэй ижил OCSP (§6.4) ба
   CRL (§6.5) кодоор, түүний олгогч `03`-ын эсрэг, **04-ийн гэрчилгээнд заасан** AIA / CDP хаягаар шалгана. 04-д AIA
   ба CDP хоёулаа бий. Хоёулаа байхгүй бол → «шалгаж чадсангүй» (хаяг зохиож бүү ол; «хамаарахгүй» гэж тооцохгүй).
   Зөвхөн нэг нь байвал тэр нэг нь шийднэ. Энэ шалгалтад OCSP nonce **заавал биш** (§6.4).

AUTH гэрчилгээний OCSP / CRL-ийн олгогчийг (§6.4, §6.5) зөвхөн pin хийсэн 04-өөс авна.

### 6.3 Хүчинтэй хугацаа

Одоогийн цаг AUTH гэрчилгээний `notBefore ≤ одоо ≤ notAfter` дотор (хоёр хил оролцоотой: `notAfter`-ийн яг тэр
секундэд хүчинтэй, дараагийн секундэд хүчингүй); үгүй бол энэ мөр ✗. Замын CA-ийн хугацааг гинжний мөр шалгана (§6.2;
AUTH гэрчилгээ хугацаа дууссан бол гинжийг түүний хүчинтэй хугацааны төгсгөлийн агшинд үнэлнэ).

### 6.4 OCSP

- Хаяг: **гэрчилгээний өөрийн** Authority Information Access (`id-ad-ocsp`) — хаягийг кодонд бүү хатуу бич.
- Хүсэлт: RFC 6960, `POST`, `Content-Type: application/ocsp-request`, CertID SHA-256, **32 байт санамсаргүй nonce**
  (`id-pkix-ocsp-nonce`, RFC 8954; extnValue = nonce-ийн OCTET STRING).
- **Nonce:** AUTH гэрчилгээний хариунд nonce **заавал** буцаж ирэх ба илгээсэнтэй таарна (extnValue нь OCTET
  STRING(nonce) эсвэл түүхий nonce); байхгүй эсвэл зөрвөл → ✗. Олгогч CA (04)-г 03-ын эсрэг шалгахад nonce **заавал
  биш** — CA түвшний хариуг урьдчилан гарын үсэг зурж бэлтгэдэг тул nonce буцаадаггүй; гэхдээ буцаасан бол таарах ёстой.
- CertID-ийн hash **зөвхөн SHA-1 эсвэл SHA-256**; CertID (hash алгоритм + issuerNameHash + issuerKeyHash + serial)
  таны гэрчилгээнийх биш бол → ✗.
- Хариуны гарын үсэг: олгогч CA өөрөө, ЭСВЭЛ хариунд шингэсэн **responder гэрчилгээ**, нөхцөл нь:
  `responderID` (byKey / byName) түүнтэй таарна; **шалгаж буй гэрчилгээг олгосон CA-ийн** олгосон (нэр + гарын үсэг);
  ExtendedKeyUsage-д `id-kp-OCSPSigning` (`1.3.6.1.5.5.7.3.9`); **хүчинтэй хугацаандаа** (хил оролцоотой). Responder
  гэрчилгээний өөрийнх нь цуцлалтыг шалгахгүй (`id-pkix-ocsp-nocheck`-ийн утга: богино хугацаатай responder
  гэрчилгээг олгогч CA шууд итгэмжилдэг).
- `responses` дотор: CertID нь өөр гэрчилгээнийх эсвэл CertID болж уншигдахгүй бичлэгийг **алгасна**; энэ гэрчилгээний
  бичлэг (эхнийх) нь бүтэн, хатуу DER байна (certStatus, thisUpdate, `[0]` nextUpdate, `[1]` өргөтгөл — өөр юу ч
  үгүй), үгүй бол → ✗. Хариунд шингэсэн responder гэрчилгээ бүр мөн яг нэг DER гэрчилгээ байна, үгүй бол → ✗.
- Шийдвэрийн дараалал (хоёр платформд ижил, шалтгаан ч ижил): responseStatus → хариуны төрөл → бүтэц → гарын үсэг
  зурсан гэрчилгээ → гарын үсэг → nonce → энэ CertID-ийн SingleResponse: `revoked` → ✗ (цуцлалт хугацаа дуусдаггүй);
  `thisUpdate > одоо + 5 мин` → ✗; хуучирсан (`nextUpdate < одоо − 5 мин`, `nextUpdate` байхгүй бол
  `thisUpdate < одоо − 1 цаг`) → ✗; `unknown` → ✗; `good` → ✓.

### 6.5 CRL

- Хаяг: **гэрчилгээний өөрийн** CRL Distribution Points (fullName URI).
- CRL-ийн `issuer` = гэрчилгээний `issuer` = олгогч CA-ийн subject; гарын үсэг олгогч CA-ийн түлхүүрээр баталгаажна.
- Delta CRL (`deltaCRLIndicator`), `issuingDistributionPoint`-той CRL, эсвэл CRL / бичлэгт үл мэдэгдэх **critical**
  өргөтгөл → «шалгаж чадсангүй». Мэдэгдэх өргөтгөл: CRL — `authorityKeyIdentifier`, `cRLNumber`; бичлэг —
  `reasonCode`, `invalidityDate`.
- `nextUpdate` **заавал**; байхгүй бол → «шалгаж чадсангүй».
- Шинэлэг: `thisUpdate ≤ одоо + 5 мин`, `nextUpdate ≥ одоо − 5 мин`; эс бөгөөс → ✗.
- Гэрчилгээний serial жагсаалтад **байхгүй**; байвал → ✗.
- Дараалал: бүтэц → issuer → гарын үсэг → CRL өргөтгөл → `nextUpdate` → ирээдүйн огноо → хуучирсан → бичлэгүүд.
- CRL-ийг `nextUpdate` хүртэл cache хийж болно (тест аппууд cache хийдэггүй).

### 6.6 Хэрэглэгчийг таних

Хэрэглэгчийг нэрээр биш subject-ийн **`serialNumber`**-аар (ETSI EN 319 412-1 semantics identifier, `PNOMN-…`) тань —
гэхдээ **зөвхөн** §6.2-ын 1–2 (шууд олгогч нь pin хийсэн 04, AUTH профайл) ба бусад бүх шалгалт ✓ болсны **дараа**.
Шалгагчийн тайлан үүнийг шууд өгнө: .NET `report.SubjectSerialNumber`, Swift `report.subjectSerialNumber` — нэвтэрсэн
(`LoggedIn` / `loggedIn`) үед л утгатай, бусад үед `null` / `nil`; эзэмшигчийн нэр `SubjectName` / `subjectName` (зөвхөн
харуулах). Гэрчилгээг дахин задлах шаардлагагүй.
Олгогчийг pin хийхгүйгээр `serialNumber`-т итгэвэл ижил үндэс доорх өөр CA-ийн (жишээ нь relying party-ийн) гэрчилгээ
дурын `PNOMN-…` утгыг агуулж чадна.

### 6.7 Үр дүн ба татах дүрэм

| Нөхцөл | Үр дүн |
|---|---|
| `origin` §6.1-ийн дүрмийг зөрчсөн; challenge яг 32 байт биш; AUTH гэрчилгээ яг нэг хатуу DER гэрчилгээ биш (сервер ба тест апп хоёуланд ижил; тест апп гарын үсэг зурахгүй) | «Challenge-ийн гарын үсэг» ✗ (шалтгаантай), бусад мөр «шалгаж чадсангүй» (`Шалгаагүй — оролт буруу`), **сүлжээнд нэг ч хүсэлт явуулахгүй**, нэвтрээгүй |
| Итгэлийн үндэс эсвэл pin хийсэн 04 апп-д алга; гинжийн орчныг үүсгэж чадаагүй | «шалгаж чадсангүй» |
| 04-д AIA ч CDP ч алга; 04-ийн OCSP / CRL «шалгаж чадсангүй» | гинж «шалгаж чадсангүй» |
| `trust/`-ийн замын CA (04, 03, 02, 01) хугацаанаас гадуур; зам `trust/`-ийн үндэс хүртэл хүрэхгүй; [1] нь 04-ийн subject + түлхүүртэй таарахгүй | гинж ✗ |
| AUTH гэрчилгээ 04-өөр олгогдоогүй тул OCSP / CRL-ийн олгогч алга; гэрчилгээнд AIA эсвэл CDP алга | «шалгаж чадсангүй» |
| Сүлжээ: холбогдож чадаагүй, HTTP ≠ 200 (redirect орно), 10 секундээс хэтэрсэн, 8 MiB-ээс том, бие дундаа тасарсан (IO алдаа) | «шалгаж чадсангүй» |
| OCSP `responseStatus` ≠ 0, хариуны төрөл BasicOCSPResponse биш; OCSP / CRL-ийн гарын үсгийн алгоритм дэмжигдээгүй | «шалгаж чадсангүй» |
| CRL-д `nextUpdate` алга, delta / IDP / үл мэдэгдэх critical өргөтгөл (CRL эсвэл бичлэг) | «шалгаж чадсангүй» |
| Тест апп: токен татгалзсан (PIN буруу, түгжигдсэн, түлхүүр алга, токен салсан) | гарын үсгийн мөр «шалгаж чадсангүй» |
| Гарын үсэг буруу; шууд олгогч 04 биш; AUTH профайл зөрсөн; AUTH гэрчилгээ хугацаанаас гадуур | ✗ |
| Задрахгүй (malformed / DER биш) хариу эсвэл CRL (энэ гэрчилгээний SingleResponse эвдэрхий, шингэсэн responder гэрчилгээ DER биш орно); буруу гарын үсэг; responderID таарахгүй; responder гэрчилгээ буруу CA-ийнх, OCSPSigning-гүй, хугацаанаас гадуур; nonce алга (AUTH) эсвэл зөрсөн; CertID таарахгүй; `revoked` / `unknown`; хуучирсан / ирээдүйн огноотой; CRL буруу олгогчийнх; serial жагсаалтад | ✗ |

Хоёулаа **нэвтрээгүй** гэсэн үг. OCSP хариу ба CRL-ийг HTTP-ээр татахдаа: redirect-ийг **дагахгүй** (3xx бол алдаа);
нийт хугацаа **10 секунд** (холболт, толгой, бие бүгд); хэмжээ **8 MiB** хүртэл — уншиж байхдаа тоолж, хэтэрмэгц
зогсооно; зөвхөн **HTTP 200**; cookie, cache-гүй. AIA / CDP хаяг нь `http://` (хариу гарын үсгээр баталгаажна;
http нь зөвхөн тээвэр) — firewall / proxy `ocsp.eidmongolia.mn`, `crl.eidmongolia.mn` руу 80 портыг зөвшөөрнө.

### 6.8 Шалгагчийг өөрийн серверт ашиглах

- **.NET (сервер дээр санал болгох):** `windows/src/EidTokenTest.Core/Verification/` хавтсыг бүтнээр нь хуулна — .NET
  10-ийн суурь сан л, файл бүр өөрийн `using`-тэй (`ImplicitUsings`-ээс хамаарахгүй), апп / CLI / `Tokens/`-оос
  хамааралгүй. `TrustAnchors.Bundled()` нь `trust/anchors/*.pem`, `trust/intermediates/*.pem` нэртэй embedded resource
  уншина (`EidTokenTest.Core.csproj`-ийн `EmbeddedResource`-ийг дагана), эсвэл
  `new TrustAnchors(roots, intermediates)`-аар `trust/`-ийн гэрчилгээг өөрөө өгнө — 04-ийг SHA-256 pin-ээр нь
  (`TrustAnchors.IssuingCaSha256`) энэ байгуулагч өөрөө сонгоно; өөр олгогч CA өгөх public зам байхгүй. Шалгагч
  Windows-оос гадна Linux дээр ч ажиллана — CI түүний unit тестийг `ubuntu-24.04` дээр ч ажиллуулдаг.
  `LoginVerifier` ба `HttpRevocationTransport`-ийг (дотроо нэг `HttpClient`) апп эхлэхэд **нэг удаа** үүсгээд бүх
  хүсэлтэд хуваалцана — хүсэлт бүрд шинээр бүү үүсгэ:

  ```csharp
  // эхлэхэд нэг удаа (singleton)
  static readonly HttpRevocationTransport Transport = new();
  static readonly LoginVerifier Verifier = new(TrustAnchors.Bundled(), Transport);
  const string Origin = "login.example.mn";            // ТОГТМОЛ, тохиргооноос — хүсэлтээс биш (§6.1)

  // нэвтрэх хүсэлт бүрд
  var report = await Verifier.VerifyAsync(Origin, challenge, signatureRs, authCertificateDer);   // хэзээ ч throw хийхгүй
  if (report.LoggedIn) { var user = report.SubjectSerialNumber; /* PNOMN-…, §6.6 */ }
  ```

- **Swift:** `macos/EIDTokenCheck/Sources/EIDTokenCheck/` нь **Apple-ийн платформын** код (Foundation, Security.framework,
  CryptoKit) — macOS / iOS апп дотор ашиглана; Linux сервер дээр ажиллахгүй (сервер дээр C# шалгагчийг ашигла, эсвэл
  §6-ийн дүрмийг өөрийн хэл дээр хэрэгжүүл). Апп-д шингээхдээ OCSP / CRL хаяг нь энгийн `http://` тул App Transport
  Security-ийн exception (`NSAppTransportSecurity` → `NSExceptionDomains`: `ocsp.eidmongolia.mn`, `crl.eidmongolia.mn`,
  `NSExceptionAllowsInsecureHTTPLoads`) шаардлагатай — эс бөгөөс OCSP / CRL «шалгаж чадсангүй». `TrustStore.load` ба
  `TrustStore(anchors:intermediates:)` нь 04-ийг pin-ээр нь өөрөө сонгоно (хоёулаа `throws`).

  ```swift
  // эхлэхэд нэг удаа
  let verifier = LoginVerifier(trust: try TrustStore.load(directory: trustDirectory), fetcher: URLSessionRevocationFetcher())
  let origin = "login.example.mn"                      // ТОГТМОЛ (§6.1)

  // нэвтрэх бүрд
  let report = await verifier.verify(origin: origin, challenge: challenge, signature: signatureRs, certificate: authCertificateDer)
  if report.loggedIn, let user = report.subjectSerialNumber { /* PNOMN-…, §6.6 */ }
  ```

- Бусад хэл: §6.1–6.7-г шууд хэрэгжүүлнэ; хоёр шалгагчийн unit тест (`macos/EIDTokenCheck/Tests/`,
  `windows/tests/EidTokenTest.Tests/`) нь тохиолдол бүрийн жишээ (шалтгааны бичвэрийг ч шалгадаг).

## 7. Command-line хэрэгсэл `eid-token-check`

Апптай **ижил** уншигч, нэвтрэх урсгал, шалгагчийн кодоор ажиллана (GUI-гүй машин дээр, жишээ нь алсаас токентой
компьютерт шалгах). macOS: zip-ийн `eid-token-check/eid-token-check` (хажуудаа `opensc-pkcs11.so`, `libopensc.12.dylib`,
`trust/`); Windows: `eid-token-test.exe`-тэй нэг хавтсанд байгаа `eid-token-check\eid-token-check.exe` (хажуудаа
`opensc-pkcs11.dll`; итгэлийн гэрчилгээ exe-д шингэсэн; бүтэн зам —
[Command-line хэрэгсэл](#command-line-хэрэгсэл-суулгах-шаардлагагүй)).

```
eid-token-check --module <opensc-pkcs11 зам> [--serial <токены серийн дугаар>] [--json]
eid-token-check --module <зам> --serial <серийн дугаар> [--origin <host>] --login [--json] < pin.txt
```

- `--login`-гүй: токенууд (label, серийн дугаар, загвар, PIN flag: count-low / final-try / locked) ба гэрчилгээ бүр
  (төрөл, `CKA_ID`, subject, `serialNumber`, олгогч, серийн дугаар, хүчинтэй хугацаа) — PIN шаардахгүй. eID гэрчилгээгүй
  токенд «eID гэрчилгээ олдсонгүй».
- `--login`: `--serial` **заавал**; PIN-ийг **зөвхөн** redirect хийсэн stdin-ээс уншина (эхний мөр) — командын мөр,
  орчны хувьсагчаар хүлээн авахгүй (`--pin` → буруу хэрэглээ), stdin терминал бол татгалзана, PIN-ийг хэвлэхгүй.
  Токен сүүлийн оролдлого дээр эсвэл түгжигдсэн бол `C_Login` хийхгүй татгалзана. Яг нэг `C_Login`, дараа нь таван
  мөр (GUI-тэй ижил нэр, шалтгаан) ба «Нэвтэрлээ: …» / «Нэвтэрч чадсангүй: …».
- `--origin` анхдагч `test.example`; §6.1-ийн дүрмээр шалгана.
- Үл мэдэгдэх эсвэл байрлалын аргументыг (жишээ нь андуурч бичсэн PIN) **буцааж хэвлэхгүй** — ерөнхий «Үл мэдэгдэх
  аргумент» алдаа (exit 2).
- `--json`: нэг JSON объект (`tokens[]` / `checks[]`, `loggedIn`, `summary` / `error`), талбарын нэр хоёр платформд ижил.
- `--help` (`-h`): хэрэглээг хэвлэнэ, exit 0. Аргументгүй ажиллуулбал хэрэглээг хэвлээд exit 2.
- Гаралт UTF-8. Windows-ийн консолд монгол бичвэр эвдэрч харагдвал: cmd — `chcp 65001`, PowerShell —
  `[Console]::OutputEncoding = [Text.Encoding]::UTF8`.

| Exit code | Утга |
|---|---|
| `0` | жагсаалт амжилттай / нэвтэрсэн |
| `1` | шалгалт унасан, нэвтрээгүй, эсвэл токен татгалзсан (PIN-ий төлөв, eID гэрчилгээ алга, гэрчилгээ уншиж чадаагүй); `trust/` эвдэрхий |
| `2` | буруу хэрэглээ (`--serial`-гүй `--login`, `--pin`, үл мэдэгдэх аргумент, буруу `--origin`, stdin терминал, хоосон PIN …) |
| `3` | токен алга (эсвэл тэр serial-тай токен алга) эсвэл модуль ачаалагдсангүй |

Жишээ (macOS / Linux shell; Windows PowerShell-д `Get-Content pin.txt | .\eid-token-check.exe …`):

```bash
./eid-token-check --module ./opensc-pkcs11.so
./eid-token-check --module ./opensc-pkcs11.so --serial 0123456789ABCDEF --origin login.example.mn --login --json < pin.txt
```

Windows (PowerShell): `eid-token-test.exe`-тэй нэг хавтсанд байгаа `eid-token-check\` хавтаснаас. Доорх `cd` нь
Windows B-ээр задалсан хавтаснаас; Windows A-аар (Extract All) задалсан бол `eid-token-test-windows-x64\` нэг түвшин
нэмэгдэнэ (`cd .\eid-token-test-windows-x64\eid-token-test-windows-x64\eid-token-check`).

```powershell
cd .\eid-token-test-windows-x64\eid-token-check
.\eid-token-check.exe --help
.\eid-token-check.exe --module .\opensc-pkcs11.dll            # токен ба гэрчилгээнүүд, exit 0
.\eid-token-check.exe --module .\opensc-pkcs11.dll --json
Get-Content pin.txt | .\eid-token-check.exe --module .\opensc-pkcs11.dll --serial 0123456789ABCDEF --origin login.example.mn --login --json
```

## 8. Алдаа засах

| Шинж тэмдэг | Шалтгаан / хийх зүйл |
|---|---|
| exe олдохгүй / zip дотор зөвхөн `.sln`, `src`, `tests` байна | Эх кодын архив (GitHub-ийн «Code → Download ZIP») татсан байна — бэлэн апп тэнд байхгүй. Releases-ээс ав: <https://github.com/gerege-systems/eid-mongolia-token-sdk/releases/latest> ([Суулгах — аль замаар вэ](#суулгах--аль-замаар-вэ)). |
| Windows: апп эхлэхгүй, чимээгүй гацсан мэт | «Unblock»-гүй задалсан файл: Windows анхааруулгын цонхонд («Open File - Security Warning» эсвэл «Windows protected your PC») хариулт хүлээж байна, хариулах хүртэл апп эхлэхгүй; дэлгэц харагдахгүй үед (ssh, дэлгэцгүй алсын холболт) цонх харагдахгүй. Дэлгэц дээрх цонхонд хариул, эсвэл тэр хавтсанд `Get-ChildItem -Recurse \| Unblock-File` ([Windows A](#windows-a-браузераар-татах)). |
| «Токен олдсонгүй» / exit 3 | Токен USB-д залгаатай эсэх; өөр програм токеныг онцгой (exclusive) эзэмшиж байвал хаагаад «Дахин унших». Windows: Smart Card service (`SCardSvr`) асаалттай эсэх. `--serial`-ийн утга жагсаалтынхтай яг таарах эсэх. |
| PKCS#11 модулийг ачаалж чадсангүй / exit 3 | Зам зөв эсэх; macOS: `libopensc.12.dylib` `opensc-pkcs11.so`-тэй нэг хавтсанд байх; quarantine ([§3 macOS B](#macos-b-браузераар-татах) — анхны ажиллуулалтаас өмнө). Windows: **32-bit процесс** x64 модулийг ачаалж чадахгүй — танай програм 64-bit байх ёстой. |
| eid-token-check хариу өгөхгүй гацсан (macOS) | Татсан (quarantine-тэй) ad-hoc build-ийг анх ажиллуулахад Gatekeeper процессыг `main`-аас ӨМНӨ барьж, Mac-ийн дэлгэц дээр «Apple could not verify …» цонхонд хариулахыг хүлээнэ — ssh / дэлгэцгүй үед чимээгүй гацсан мэт. Гацсаны дараа quarantine арилгах нь тэр процессыг суллахгүй. Засах: Mac-ийн дэлгэц дээрх цонхыг хаах (эсвэл гацсан процессыг зогсоох) → zip-ийг дахин задлах → `xattr -dr com.apple.quarantine <zip эсвэл задалсан хавтас>` → дахин ажиллуулах. Эсвэл `curl` / `gh release download`-оор татах, эсвэл эх кодоос бүтээх (§4). |
| Аппын цонх хоосон эсвэл «эхэлж чадсангүй» алдааны цонх | Апп эхлэх үеийн алдааг дэлгэцэнд (алдааны цонх эсвэл message box) ба лог файлд бичнэ: Windows — `eid-token-test.exe`-ийн хажуудах `eid-token-test.log` (хавтас бичигдэхгүй бол `%TEMP%`), macOS — `~/Library/Logs/eid-token-test.log` (`EID_TOKEN_TEST_LOG`-оор өөр зам заана). Амжилттай эхэлбэл `main page loaded` мөр бичигдэнэ. Windows: zip-ийг бүтнээр нь задал (`resources.pri`, `*.xbf` файлууд exe-ийн хажууд байх ёстой). |
| Windows: цонх гарсан ч дотор нь цагаан / хоосон (алсын / дэлгэцгүй компьютер) | Дэлгэц унтарсан (power off) үед Windows цонхны агуулгыг дэлгэц сэрэх хүртэл зурдаггүй — аппын алдаа биш. Дэлгэцийг сэрээ (эсвэл алсын сессээр холбогд); лог дахь `main page loaded` мөр апп хэвийн ачаалсныг харуулна. |
| Апп «Not Opened» / «Apple could not verify …» (macOS) | Ad-hoc, notarize хийгдээгүй build. System Settings → Privacy & Security → «Open Anyway», эсвэл анхны нээлтээс өмнө quarantine арилга ([§3 macOS B](#macos-b-браузераар-татах)). |
| «eID гэрчилгээ олдсонгүй» | Токенд eID-ийн `CKA_ID`-тай (`45494401/02/11/12`) гэрчилгээ алга — өөр байгууллагын токен, эсвэл гэрчилгээ олгогдоогүй токен. Токен олгосон байгууллагад хандана. |
| «Токен форматлагдаагүй (PKCS#15 бүтэцгүй)» | Хоосон токен; энэ багц форматлахгүй. |
| PIN: оролдлого цөөн | Өмнө нь буруу PIN оруулсан; анхааралтай оруул. |
| PIN: сүүлийн оролдлого | Апп тусад нь баталгаажуулна; CLI татгалзана (exit 1). Буруу оруулбал токен түгжигдэнэ. |
| PIN түгжигдсэн | `C_Login` хийхгүй. PUK-аар тайлах нь энэ багцын хүрээнд биш — токен олгосон байгууллагад хандана. |
| OCSP / CRL «шалгаж чадсангүй» | Сүлжээ: `ocsp.eidmongolia.mn`, `crl.eidmongolia.mn` руу HTTP (80) нээлттэй эсэх, proxy, 10 секундийн хязгаар. Fail closed тул нэвтрэхгүй — энэ нь зөв үйлдэл. |
| Гинж ✗ «… (04) шууд олгоогүй» | Гэрчилгээ eID Mongolia Issuing CA-аас олгогдоогүй (жишээ нь байгууллагын / relying party-ийн гэрчилгээ) — нэвтрэлтэд тэнцэхгүй. |
| Гинж ✗ «AUTH профайл: …» | SIGN гэрчилгээ эсвэл AUTH бус гэрчилгээ сонгогдсон; `CKA_ID 45494401`-ийг ашигла. |
| «Origin буруу …» | §6.1: жижиг үсэг, scheme / порт / замгүй host нэр. |

## 9. Лиценз ба хязгаарлалт

### Лиценз

- **Энэ SDK-ийн өөрийн код** (шалгагч, уншигч, тест аппууд, `eid-token-check`, скрипт, гарын авлага) — **MIT License**,
  Copyright (c) 2026 Gerege Systems LLC (`LICENSE`). Өөрийн бүтээгдэхүүндээ хуулж, өөрчилж ашиглаж болно; `LICENSE`-ийн
  бичвэрийг хадгална. Хамт тараагдах OpenSC ба OpenSSL нь доорх **өөрсдийн** лицензтэй хэвээр — MIT тэдэнд хамаарахгүй.
- **OpenSC** (<https://github.com/OpenSC/OpenSC>) — **GNU LGPL-2.1**. PKCS#11 module-ийг динамикаар ачаалж (`dlopen` /
  `LoadLibrary`) ашигладаг тул танай програм LGPL-ийн дагуу өөр (жишээ нь өөрөө бүтээсэн) хувилбараар сольж болохуйц
  байна. Module-ийг тараахдаа `COPYING`-ийг хамт тараана. Эх код: <https://github.com/OpenSC/OpenSC/releases/tag/0.26.1>.
  macOS-ийн module-ийг upstream эх кодоос өөрчлөлтгүйгээр бүтээдэг (`macos/scripts/build_opensc.sh`); Windows-ийн DLL нь
  OpenSC 0.26.1-ийн албан ёсны release-ийн файл (`windows/third_party/opensc/README.md`).
- **OpenSSL** — macOS-ийн module-д **OpenSSL 3.5.9** static-аар холбогдсон (Apache License 2.0); Windows-ийн DLL
  **OpenSSL 1.1**-ийг агуулна (OpenSSL License + SSLeay License). Бичвэр: macOS zip-ийн `licenses/`, Windows-ийн
  `opensc\OPENSSL-LICENSE.txt` ба `eid-token-check\OPENSSL-LICENSE.txt`.

### Хязгаарлалт

- Зөвхөн нэвтрэлт: SIGN түлхүүрээр баримт зурах, токен форматлах, түлхүүр үүсгэх, гэрчилгээ бичих, PIN солих / тайлах
  энэ багцад байхгүй.
- Тест аппууд code-signing / notarization-гүй (macOS ad-hoc, Windows гарын үсэггүй); суулгагчгүй. Production-д тест
  аппыг биш, шалгагчийн кодыг өөрийн системд ашиглана.
- Windows module зөвхөн **x64** (32-bit процесс ачаалахгүй); macOS 14+.
- OCSP / CRL `http://`-ээр (гарын үсгээр баталгаажна); responder гэрчилгээний өөрийн цуцлалтыг шалгахгүй (§6.4);
  тест аппууд CRL cache хийхгүй — нэвтрэх бүрд татна.
- CI нь unit тест, build, багцын агуулгыг шалгана; бодит токентой шалгалтыг (USB) CI хийхгүй.
