# README: macOS-д Terminal-аар татах замыг үндсэн болгосон

- **Юу:** §3 macOS-ийн эхэнд `curl`-аар татах → SHA-256 тулгах → задлах → нээх 6 мөр команд нэмсэн
  (`releases/latest/download/…` тогтмол хаяг). Браузераар татах + `xattr` алхам нөөц зам болж үлдсэн.
- **Яагаад:** багц Developer ID-гүй (ad-hoc), notarize хийгдээгүй. `curl`-аар татсан файлд quarantine тавигддаггүй тул
  Gatekeeper-ийн анхааруулга гарахгүй — сертификатгүйгээр интеграторт саадгүй эхлэх зам.
- **Хаана:** `README.md` §3.
- **Хэрхэн шалгасан:** 2026-11-15 v0.1.0 zip-ийг `curl -L`-ээр татаж (quarantine тэмдэггүй), hash тулгаж, CLI ба GUI-г
  ажиллуулсан; `shasum -a 256 -c SHA256SUMS --ignore-missing` → `OK`, exit 0.
- **Үлдсэн:** Developer ID + notarization (Account Holder сертификат үүсгэсний дараа).
