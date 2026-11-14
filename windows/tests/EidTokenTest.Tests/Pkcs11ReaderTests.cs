using System.Reflection;
using EidTokenTest.Core.Tokens;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace EidTokenTest.Tests;

/// The real <see cref="Pkcs11TokenReader"/> over a fake PKCS#11 library (no module, no token): the refusals happen
/// BEFORE C_Login / C_Sign.
public sealed class Pkcs11ReaderTests
{
    private static readonly byte[] Digest = new byte[32];

    /// A token in slot 1 whose C_GetTokenInfo answers <paramref name="serials"/> one after the other (the last one
    /// repeats), and a session whose C_Login answers <paramref name="loginResult"/>.
    private static (Pkcs11TokenReader Reader, Fake<ISession> Session, Fake<ISlot> Slot) Reader(string[] serials, CKR loginResult)
    {
        var call = 0;
        var flags = Fake<ITokenFlags>.Create((m, _) => m.Name == "get_UserPinInitialized" ? true : Default(m)).Proxy;
        var (session, sessionFake) = Fake<ISession>.Create((m, _) =>
        {
            if (m.Name == "Login" && loginResult != CKR.CKR_OK) throw new Pkcs11Exception("C_Login", loginResult);
            return Default(m);
        });
        var (slot, slotFake) = Fake<ISlot>.Create((m, _) => m.Name switch
        {
            "GetTokenInfo" => Fake<ITokenInfo>.Create((info, _) => info.Name switch
            {
                "get_SerialNumber" => serials[Math.Min(call++, serials.Length - 1)],
                "get_TokenFlags" => (object)flags,
                _ => Default(info),
            }).Proxy,
            "OpenSession" => (object)session,
            _ => Default(m),
        });
        var library = Fake<IPkcs11Library>.Create((m, _) =>
            m.Name == "GetSlotList" ? (object)new List<ISlot> { slot } : Default(m)).Proxy;
        return (Pkcs11TokenReader.ForLibrary(library), sessionFake, slotFake);
    }

    private static object? Default(MethodInfo method) =>
        method.ReturnType.IsValueType && method.ReturnType != typeof(void) ? Activator.CreateInstance(method.ReturnType) : null;

    /// The token in the slot is swapped between the lookup by serial and the re-check right before C_Login: refused,
    /// no session is opened, so neither C_Login nor C_Sign can run.
    [Fact]
    public void TokenSwappedBeforeLoginNeverReachesCLoginOrCSign()
    {
        var (reader, session, slot) = Reader(["S1", "S9"], CKR.CKR_OK);
        var error = Assert.Throws<TokenLoginException>(() => reader.SignDigest("S1", EidKeyId.Auth, Digest, "1234"));
        Assert.Equal(TokenLoginError.TokenNotFound, error.Error);
        Assert.DoesNotContain("OpenSession", slot.Calls);
        Assert.Empty(session.Calls);
    }

    /// C_Login answers CKR_USER_ALREADY_LOGGED_IN (a login this call did not make): refused — no C_Sign, no C_Logout
    /// of somebody else's login.
    [Fact]
    public void UserAlreadyLoggedInNeverReachesCSign()
    {
        var (reader, session, _) = Reader(["S1"], CKR.CKR_USER_ALREADY_LOGGED_IN);
        var error = Assert.Throws<TokenLoginException>(() => reader.SignDigest("S1", EidKeyId.Auth, Digest, "1234"));
        Assert.Equal(TokenLoginError.AlreadyLoggedIn, error.Error);
        Assert.Equal(1, session.Calls.Count(c => c == "Login"));
        Assert.DoesNotContain("Sign", session.Calls);
        Assert.DoesNotContain("Logout", session.Calls);
        Assert.DoesNotContain("FindAllObjects", session.Calls);
    }

    /// An empty serial never selects a token (a token reporting an empty serial included).
    [Fact]
    public void EmptySerialIsRefused()
    {
        var (reader, session, _) = Reader([""], CKR.CKR_OK);
        Assert.Equal(TokenLoginError.TokenNotFound,
            Assert.Throws<TokenLoginException>(() => reader.SignDigest("", EidKeyId.Auth, Digest, "1234")).Error);
        Assert.Empty(session.Calls);
    }
}

/// A recording fake for any interface (System.Reflection.DispatchProxy): every call is answered by the handler.
public class Fake<T> : DispatchProxy where T : class
{
    private Func<MethodInfo, object?[]?, object?> _handler = (_, _) => null;

    public List<string> Calls { get; } = [];

    public static (T Proxy, Fake<T> Fake) Create(Func<MethodInfo, object?[]?, object?> handler)
    {
        var proxy = DispatchProxy.Create<T, Fake<T>>();
        var fake = (Fake<T>)(object)proxy;
        fake._handler = handler;
        return (proxy, fake);
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        ArgumentNullException.ThrowIfNull(targetMethod);
        Calls.Add(targetMethod.Name);
        return _handler(targetMethod, args);
    }
}
