# Windows шалгагч: параметргүй нийтийн түлхүүртэй гэрчилгээнд null шалгалт

- **Юу:** `LoginVerifier.IsP256` нь `PublicKey.EncodedParameters` хоосон (null) байж болохыг тооцдог болсон —
  ийм гэрчилгээг P-256 биш гэж үзнэ.
- **Яагаад:** release build-ийн хөрвүүлэгчийн анхааруулга (possible null dereference). id-ecPublicKey OID-тэй ч
  параметргүй гэрчилгээ ирвэл null dereference гарч, ерөнхий catch-д баригдахын оронд шууд «P-256 биш» гэж
  татгалзах нь зөв.
- **Хаана:** `windows/src/EidTokenTest.Core/Verification/LoginVerifier.cs`.
- **Хэрхэн шалгасан:** PR-ийн CI (Windows, Linux шалгагчийн тест).
- **Үлдсэн:** үгүй.
