# OpenSC 0.26.1 — Windows x64 PKCS#11 module

| Файл | Эх сурвалж | SHA-256 |
|---|---|---|
| `x64/opensc-pkcs11.dll` | OpenSC 0.26.1-ийн албан ёсны release `OpenSC-0.26.1_win64.msi` → `OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll`, өөрчлөлтгүй | `6c1eb3705a477fbec73cf007b6f868c77cb8a58b902fab9f6d884570c9c4e68e` |
| `COPYING` | `opensc-0.26.1.tar.gz` — GNU LGPL-2.1 | — |
| `OPENSSL-LICENSE.txt` | OpenSSL 1.1.1 (`OpenSSL_1_1_1w/LICENSE`) — release-ийн DLL OpenSSL 1.1-ийг статикаар агуулна | — |

- MSI: <https://github.com/OpenSC/OpenSC/releases/download/0.26.1/OpenSC-0.26.1_win64.msi>,
  SHA-256 `bb2a47bd7a87617f38828c17eb7129a40fe27fe6656781882f2924fc2c9cf96e`. DLL нь OpenSC төслийн Authenticode гарын
  үсэгтэй (Windows дээр `Get-AuthenticodeSignature`-аар шалгана).
- Эх код: <https://github.com/OpenSC/OpenSC/releases/tag/0.26.1> (`opensc-0.26.1.tar.gz`, SHA-256
  `f16291a031d86e570394762e9f35eaf2fcbc2337a49910f3feae42d54e1688cb`).
- Хамаарал: зөвхөн Windows-ийн системийн DLL (CRT статик) — VC++ redistributable шаардахгүй. Зөвхөн 64-bit процесс
  ачаална.
- Зөвхөн PKCS#11 модуль: OpenSC-ийн хэрэгслүүд (`pkcs15-init.exe` г.м.), `opensc.dll`, profile файлууд энд БАЙХГҮЙ.
- CI (`token-sdk-windows`) багц бүрд DLL-ийн SHA-256-г дээрх утгатай тулгана.
