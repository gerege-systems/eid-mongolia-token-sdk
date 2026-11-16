# Release-ийн хувилбар tag-аас; түр хавтсыг цэвэрлэдэг болгосон

- **Юу:** (1) `release.yml` tag-аас `v`-г хасаж хувилбар гаргаад (`x.y.z` эсвэл `x.y.z-pre` загвараар шалгана) хоёр
  платформын бүтээлтэд дамжуулна. Windows: `-p:Version`, `InformationalVersion` = tag, `AssemblyVersion`, `FileVersion` =
  `x.y.z.0` (pre-release дагавар тоон 4 хэсэгт орохгүй тул); нийтлэхийн өмнө `eid-token-test.dll`, `eid-token-check.dll`-ийн
  хувилбарыг tag-тай тулгаж зөрвөл унана. macOS: `xcodebuild MARKETING_VERSION=<хувилбар>`, `Info.plist`-ийн
  `CFBundleShortVersionString` = `$(MARKETING_VERSION)`, бүтээсний дараа plist-ийг tag-тай тулгана. Хөгжүүлэлтийн
  анхдагч хувилбар платформ бүрд нэг газар: `windows/Directory.Build.props`, `macos/project.yml`. Апп `starting <хувилбар>`
  мөрөндөө одоо `AssemblyInformationalVersion`-ийг (tag-тай ижил) бичнэ. (2) `eid-token-test-<guid>` түр хавтсыг процесс
  хэвийн дуусахад устгана (Windows: `ProcessExit`, macOS: `atexit`), мөн эхлэхдээ 24 цагаас хуучирсан, нэр нь яг загвартай,
  зөвхөн `opensc.conf` агуулсан хавтсыг (symlink / reparse point-ыг дагахгүй, зөвхөн temp-ийн шууд хүүхэд) устгана. Бүгд
  best effort: алдаа гарвал шалгалтыг унагахгүй.
- **Яагаад:** v0.1.0 release `starting 0.2.0.0` гэж лог бичсэн (төслийн файлд 0.2.0 хатуу бичигдсэн байсан); Windows-ийн
  тест PC дээр 52 түр хавтас үлдсэн.
- **Хаана:** `.github/workflows/{release,token-sdk-windows,token-sdk-macos,ci}.yml`, `windows/Directory.Build.props`,
  `windows/src/EidTokenTest.Core/Tokens/OpenScModule.cs`, `windows/src/EidTokenTest.App/{StartupLog,App.xaml}.cs`,
  `macos/project.yml`, `macos/EIDTokenCheck/Sources/EIDTokenReader/TokenReader.swift`, `README.md` (§3 «Бичдэг файлууд»,
  Release). Тест: `windows/tests/EidTokenTest.Tests/OpenScModuleTests.cs`,
  `macos/EIDTokenCheck/Tests/EIDTokenCLITests/OpenSCConfigTests.swift`.
- **Хэрхэн шалгасан:** локалд юу ч ажиллуулаагүй; PR-ийн CI-ийн Windows ба macOS job-ууд хоёр платформын шинэ unit
  тестийг ажиллуулна.
- **Үлдсэн:** release workflow-ийн хувилбарын шалгалт жинхэнэ release хийх хүртэл Windows дээр ажиллаагүй (PR-аар
  ажиллуулах зам байхгүй); macOS-ийнхыг `ci` → «Run workflow» → `macos_release_dry_run` (`0.0.0-dry-run.1`)-ээр шалгаж
  болно. macOS-ийн `eid-token-check` хувилбар хэвлэдэггүй тул зөвхөн аппын plist шалгагдана.
