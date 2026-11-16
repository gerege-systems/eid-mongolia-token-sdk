using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace EidTokenTest.Core.Tokens;

/// READ-ONLY access to eID tokens through the standard OpenSC PKCS#11 module (`opensc-pkcs11.dll`), Pkcs11Interop
/// high-level API. What a relying party needs, and nothing more:
///
///  - every session is opened WITHOUT CKF_RW_SESSION (`SessionType.ReadOnly`);
///  - certificates are public objects: read without C_Login;
///  - the PIN is used for exactly one C_Login per test (no automatic retry), only to sign a digest with the
///    AUTH key, and is wiped from memory afterwards; it is never logged or stored;
///  - nothing is created, changed or deleted on the token (no C_CreateObject / C_SetAttributeValue /
///    C_DestroyObject / C_GenerateKeyPair / C_InitToken / C_InitPIN / C_SetPIN anywhere in this class).
///
/// A token is always addressed by its serial number and looked up again (C_GetSlotList + C_GetTokenInfo) on every call —
/// never by a slot ID remembered from an earlier call: a token swapped in the same slot is refused before C_Login.
/// All calls are serialised; call them off the UI thread.
public sealed class Pkcs11TokenReader : ITokenSource, IDisposable
{
    private readonly object _gate = new();
    private readonly IPkcs11Library _library;
    private bool _disposed;

    private Pkcs11TokenReader(IPkcs11Library library) => _library = library;

    /// Tests only: a reader over an already loaded (or fake) PKCS#11 library.
    internal static Pkcs11TokenReader ForLibrary(IPkcs11Library library) => new(library);

    /// Loads and initialises the module (C_Initialize). Throws <see cref="TokenModuleException"/>.
    public static Pkcs11TokenReader Load(string modulePath)
    {
        OpenScModule.Touch();   // the config folder is in use: another instance's sweep must skip it
        if (!File.Exists(modulePath))
            throw new TokenModuleException("PKCS#11 модуль олдсонгүй: " + modulePath);
        try
        {
            var factories = new Pkcs11InteropFactories();
            var library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, modulePath, AppType.MultiThreaded);
            return new Pkcs11TokenReader(library);
        }
        catch (Exception ex) when (ex is Pkcs11Exception or DllNotFoundException or BadImageFormatException
                                       or UnmanagedException or EntryPointNotFoundException)
        {
            throw new TokenModuleException("PKCS#11 модулийг ачаалж чадсангүй (" + ex.Message + ")", ex);
        }
    }

    /// Slots with a token present (C_GetSlotList(CK_TRUE) + C_GetTokenInfo).
    public IReadOnlyList<TokenSummary> ListTokens()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var output = new List<TokenSummary>();
            foreach (var slot in _library.GetSlotList(SlotsType.WithTokenPresent))
            {
                try
                {
                    var info = slot.GetTokenInfo();
                    var f = info.TokenFlags;
                    output.Add(new TokenSummary(slot.SlotId, Clean(info.Label), Clean(info.SerialNumber), Clean(info.Model),
                        Clean(info.ManufacturerId), f.TokenInitialized, f.UserPinCountLow, f.UserPinFinalTry, f.UserPinLocked,
                        PinStateOf(info)));
                }
                catch (Pkcs11Exception)
                {
                    // removed between C_GetSlotList and C_GetTokenInfo: not listed
                }
            }
            return output;
        }
    }

    /// The PIN flags right now (re-read before every login).
    public PinState ReadPinState(string serial)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return PinStateOf(FindSlot(serial).GetTokenInfo());
        }
    }

    /// Every CKO_CERTIFICATE object (CKA_ID, CKA_LABEL, CKA_VALUE) — read-only session, no login.
    public IReadOnlyList<TokenCertificateObject> ReadCertificates(string serial)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var session = FindSlot(serial).OpenSession(SessionType.ReadOnly);
            var handles = session.FindAllObjects(new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            });
            var output = new List<TokenCertificateObject>();
            foreach (var handle in handles)
            {
                var attributes = session.GetAttributeValue(handle, new List<CKA> { CKA.CKA_ID, CKA.CKA_LABEL, CKA.CKA_VALUE });
                var der = attributes[2].CannotBeRead ? null : attributes[2].GetValueAsByteArray();
                if (der is not { Length: > 0 }) continue;
                byte[] id = attributes[0].CannotBeRead ? Array.Empty<byte>() : attributes[0].GetValueAsByteArray() ?? Array.Empty<byte>();
                var label = attributes[1].CannotBeRead ? string.Empty : attributes[1].GetValueAsString() ?? string.Empty;
                output.Add(new TokenCertificateObject(id, label.Trim(), der));
            }
            return output;
        }
    }

    /// C_Login(CKU_USER) once in a read-only session of the token whose serial is <paramref name="serial"/> right now,
    /// then C_Sign with CKM_ECDSA over the 32-byte <paramref name="digest"/> using the private key whose CKA_ID is
    /// <paramref name="keyId"/>; C_Logout. Exactly one C_Login per call: no context-specific login, no retry. Returns
    /// raw r‖s. Throws <see cref="TokenLoginException"/>.
    public byte[] SignDigest(string serial, byte[] keyId, byte[] digest, string pin)
    {
        ArgumentNullException.ThrowIfNull(serial);
        ArgumentNullException.ThrowIfNull(keyId);
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentNullException.ThrowIfNull(pin);
        if (digest.Length != 32) throw new ArgumentException("SHA-256 digest expected.", nameof(digest));
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ISlot slot;
            try
            {
                slot = FindSlot(serial);
            }
            catch (Pkcs11Exception)
            {
                throw new TokenLoginException(TokenLoginError.TokenNotFound);
            }
            var pinBytes = Encoding.UTF8.GetBytes(pin);
            try
            {
                var info = slot.GetTokenInfo();
                // The token in that slot must still be the one asked for: swapped meanwhile → refused before C_Login.
                if (!IsSameToken(info.SerialNumber, serial)) throw new TokenLoginException(TokenLoginError.TokenNotFound);
                // Never spend a try on a locked token (the UI checks too; the flags may have changed since).
                if (PinStateOf(info) == PinState.Locked) throw new TokenLoginException(TokenLoginError.PinLocked);
                using var session = slot.OpenSession(SessionType.ReadOnly);
                // Only our own C_Login counts: CKR_USER_ALREADY_LOGGED_IN (a login this call did not make — the session
                // is fresh) is refused by MapError, the same as on macOS.
                session.Login(CKU.CKU_USER, pinBytes);
                try
                {
                    var keys = session.FindAllObjects(new List<IObjectAttribute>
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
                    });
                    if (keys.Count == 0) throw new TokenLoginException(TokenLoginError.KeyNotFound);
                    var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA);
                    return session.Sign(mechanism, keys[0], digest);
                }
                finally
                {
                    try { session.Logout(); } catch (Pkcs11Exception) { /* session closes anyway */ }
                }
            }
            catch (Pkcs11Exception ex)
            {
                throw MapError(ex.RV);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pinBytes);
            }
        }
    }

    /// A PKCS#11 return value from C_Login / C_Sign as the one-line reason (the same texts as on macOS).
    internal static TokenLoginException MapError(CKR rv) => rv switch
    {
        CKR.CKR_PIN_INCORRECT => new TokenLoginException(TokenLoginError.PinIncorrect),
        CKR.CKR_PIN_LOCKED => new TokenLoginException(TokenLoginError.PinLocked),
        CKR.CKR_PIN_LEN_RANGE => new TokenLoginException(TokenLoginError.PinLength),
        CKR.CKR_USER_ALREADY_LOGGED_IN => new TokenLoginException(TokenLoginError.AlreadyLoggedIn),
        CKR.CKR_TOKEN_NOT_PRESENT or CKR.CKR_DEVICE_REMOVED or CKR.CKR_SLOT_ID_INVALID
            => new TokenLoginException(TokenLoginError.TokenNotFound),
        _ => new TokenLoginException(TokenLoginError.Pkcs11, rv.ToString()),
    };

    /// The slot that holds the token <paramref name="serial"/> right now.
    private ISlot FindSlot(string serial) =>
        SlotWithSerial(_library.GetSlotList(SlotsType.WithTokenPresent), s => s.GetTokenInfo().SerialNumber, serial)
        ?? throw new Pkcs11Exception("C_GetSlotList", CKR.CKR_TOKEN_NOT_PRESENT);

    /// The first slot whose token reports <paramref name="serial"/> (trimmed) now; a slot whose token cannot be read
    /// (removed meanwhile) is skipped. Never "the slot it was in before".
    internal static TSlot? SlotWithSerial<TSlot>(IEnumerable<TSlot> slots, Func<TSlot, string?> serialOf, string serial)
        where TSlot : class
    {
        foreach (var slot in slots)
        {
            string? reported;
            try
            {
                reported = serialOf(slot);
            }
            catch (Pkcs11Exception)
            {
                continue;
            }
            if (IsSameToken(reported, serial)) return slot;
        }
        return null;
    }

    /// The serial C_GetTokenInfo reports (blank-padded) is <paramref name="serial"/>.
    internal static bool IsSameToken(string? reported, string serial) =>
        serial.Length > 0 && Clean(reported) == serial;

    private static PinState PinStateOf(ITokenInfo info)
    {
        var f = info.TokenFlags;
        return PinPolicy.FromFlags(f.UserPinInitialized, f.UserPinLocked, f.UserPinFinalTry, f.UserPinCountLow);
    }

    private static string Clean(string? value) => (value ?? string.Empty).Trim(' ', '\0');

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _library.Dispose();                                            // C_Finalize
        }
    }
}
