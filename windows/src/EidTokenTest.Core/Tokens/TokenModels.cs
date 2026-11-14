using System;
using System.Collections.Generic;

namespace EidTokenTest.Core.Tokens;

/// A connected token as `C_GetTokenInfo` reports it.
public sealed record TokenSummary(ulong SlotId, string Label, string Serial, string Model, string Manufacturer,
                                  bool Initialized, bool PinCountLow, bool PinFinalTry, bool PinLocked, PinState Pin);

/// One certificate object on the token (public: read without the PIN).
public sealed record TokenCertificateObject(byte[] Id, string Label, byte[] Der);

/// What the login flow and the command-line tool need from a token (the real one: <see cref="Pkcs11TokenReader"/>). A
/// token is always addressed by its serial number (C_GetTokenInfo, trimmed) and looked up again on every call — never
/// by a slot ID remembered from an earlier call. The same on macOS.
public interface ITokenSource
{
    IReadOnlyList<TokenSummary> ListTokens();

    IReadOnlyList<TokenCertificateObject> ReadCertificates(string serial);

    /// Exactly one C_Login (CKU_USER) in a read-only session of the token whose serial is <paramref name="serial"/>
    /// right now, then C_Sign (CKM_ECDSA) over the 32-byte <paramref name="digest"/> with the private key whose CKA_ID
    /// is <paramref name="keyId"/> → raw r‖s. No retry, no context-specific login. Throws
    /// <see cref="TokenLoginException"/>.
    byte[] SignDigest(string serial, byte[] keyId, byte[] digest, string pin);
}

/// The user PIN counter as the PKCS#11 token flags tell it (no exact count in PKCS#11).
public enum PinState
{
    Ok,
    /// CKF_USER_PIN_COUNT_LOW: a wrong PIN has been entered since the last successful login.
    CountLow,
    /// CKF_USER_PIN_FINAL_TRY: one more wrong PIN locks the token.
    FinalTry,
    /// CKF_USER_PIN_LOCKED.
    Locked,
    /// CKF_USER_PIN_INITIALIZED is not set.
    NotInitialized,
}

public enum PinGate
{
    Allowed,
    /// The final try: the app asks for explicit confirmation; the command-line tool refuses.
    ConfirmFinalTry,
    /// No C_Login at all.
    Blocked,
}

/// What a login may do for a PIN state — decided BEFORE C_Login, which spends a try. The same rule on macOS.
public static class PinPolicy
{
    public static PinState FromFlags(bool userPinInitialized, bool locked, bool finalTry, bool countLow) =>
        !userPinInitialized ? PinState.NotInitialized
        : locked ? PinState.Locked
        : finalTry ? PinState.FinalTry
        : countLow ? PinState.CountLow
        : PinState.Ok;

    public static PinGate Gate(PinState state) => state switch
    {
        PinState.Locked or PinState.NotInitialized => PinGate.Blocked,
        PinState.FinalTry => PinGate.ConfirmFinalTry,
        _ => PinGate.Allowed,
    };

    /// One line for the user; null = nothing to say.
    public static string? Message(PinState state) => state switch
    {
        PinState.Locked => "PIN түгжигдсэн тул нэвтрэх тест хийх боломжгүй.",
        PinState.NotInitialized => "Токены PIN тохируулагдаагүй тул нэвтрэх тест хийх боломжгүй.",
        PinState.FinalTry => "Анхаар: PIN-ий сүүлийн оролдлого. Буруу оруулбал токен түгжигдэнэ.",
        PinState.CountLow => "PIN-ийг өмнө нь буруу оруулсан байна — оролдлого цөөн үлдсэн.",
        _ => null,
    };
}

public enum TokenLoginError
{
    PinIncorrect,
    PinLocked,
    PinLength,
    KeyNotFound,
    TokenNotFound,
    /// C_Login answered CKR_USER_ALREADY_LOGGED_IN: some other session of this process is logged in to the token. This
    /// reader never logs in twice, so it refuses instead of signing on a login it did not make (the same on macOS).
    AlreadyLoggedIn,
    Pkcs11,
}

/// The token refused the login / signature. <see cref="Exception.Message"/> is the one-line Mongolian reason (the same
/// texts as on macOS).
public sealed class TokenLoginException : Exception
{
    public TokenLoginException(TokenLoginError error, string? detail = null)
        : base(MessageFor(error, detail))
    {
        Error = error;
    }

    public TokenLoginException()
        : this(TokenLoginError.Pkcs11)
    {
    }

    public TokenLoginException(string message)
        : base(message)
    {
        Error = TokenLoginError.Pkcs11;
    }

    public TokenLoginException(string message, Exception innerException)
        : base(message, innerException)
    {
        Error = TokenLoginError.Pkcs11;
    }

    public TokenLoginError Error { get; }

    public static string MessageFor(TokenLoginError error, string? detail = null) => error switch
    {
        TokenLoginError.PinIncorrect => "PIN буруу",
        TokenLoginError.PinLocked => "PIN түгжигдсэн",
        TokenLoginError.PinLength => "PIN-ий урт буруу",
        TokenLoginError.KeyNotFound => "Токен дээр AUTH гэрчилгээтэй таарах хувийн түлхүүр алга",
        TokenLoginError.TokenNotFound => "Токен салгагдсан эсвэл олдсонгүй",
        TokenLoginError.AlreadyLoggedIn => "Токенд өөр session нэвтэрсэн байна — энэ оролдлого гарын үсэг зурахгүй",
        _ => "Токен гарын үсэг зурж чадсангүй" + (string.IsNullOrEmpty(detail) ? string.Empty : " (" + detail + ")"),
    };
}

/// `opensc-pkcs11.dll` is missing or could not be loaded / initialised.
public sealed class TokenModuleException : Exception
{
    public TokenModuleException()
    {
    }

    public TokenModuleException(string message)
        : base(message)
    {
    }

    public TokenModuleException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
