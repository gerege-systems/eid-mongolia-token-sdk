# eID Token Test — macOS

Бүрэн гарын авлага (нэвтрэлтийн дүрэм, модуль ашиглах, command-line хэрэгсэл, алдаа засах, лиценз) нь репогийн үндсэн
[`README.md`](../README.md)-д (zip-д `README.md`). Энэ файл зөвхөн macOS-ийн багцын бүтэц ба эх кодын байршлыг заана.

## Zip (`eid-token-test-macos.zip`)

| Зам | Юу вэ |
|---|---|
| `eID Token Test.app` | SwiftUI тест апп (universal, macOS 14+); модуль `Contents/Frameworks/`-д |
| `eid-token-check/eid-token-check` | Command-line хэрэгсэл (universal) |
| `eid-token-check/opensc-pkcs11.so`, `libopensc.12.dylib`, `trust/` | Хэрэгслийн хажуудах модуль ба итгэлийн гэрчилгээ |
| `README.md`, `trust/`, `licenses/` | Гарын авлага, итгэлийн гэрчилгээ, OpenSC / OpenSSL лиценз |

## Эх код

| Зам | Агуулга |
|---|---|
| `EIDTokenCheck/Sources/EIDTokenCheck/` | Шалгагч (verifier) — Foundation, Security, CryptoKit л; өөрийн кодонд бүтнээр нь хуулна |
| `EIDTokenCheck/Sources/EIDTokenReader/` | READ-ONLY PKCS#11 (`dlopen`), нэвтрэх урсгал (`TokenLogin`) — апп ба CLI хоёулаа ашиглана |
| `EIDTokenCheck/Sources/EIDTokenCLI/`, `Sources/eid-token-check/` | Command-line хэрэгсэл |
| `EIDTokenCheck/Tests/` | Unit тест (сүлжээ, токен хэрэглэхгүй) |
| `App/` | SwiftUI цонх |
| `project.yml` | XcodeGen төсөл |
| `scripts/build_opensc.sh`, `scripts/bundle_opensc.sh` | OpenSC 0.26.1 модулийг эх кодоос бүтээх, апп-д багцлах (зөвхөн модуль) |
