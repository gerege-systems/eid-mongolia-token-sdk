using EidTokenTest.Core.Verification;

namespace EidTokenTest.Cli;

/// `eid-token-check --module &lt;path&gt; [--serial &lt;serial&gt;] [--origin &lt;host&gt;] [--login] [--json]` — the same
/// options and rules on macOS.
public sealed record CliOptions(string ModulePath, string? Serial = null, string Origin = LoginChallenge.DefaultOrigin,
                                bool Login = false, bool Json = false);

/// Run, help, or a usage error (exit code 2) with a one-line reason.
public sealed record ParseResult(CliOptions? Options, bool Help, string? UsageError)
{
    public static ParseResult Run(CliOptions options) => new(options, false, null);
    public static ParseResult ShowHelp() => new(null, true, null);
    public static ParseResult Usage(string reason) => new(null, false, reason);
}

/// Process exit codes, the same on Windows and macOS.
public static class ExitCode
{
    /// The listing worked / logged in.
    public const int Ok = 0;
    /// A check failed, not logged in, or the token refused (PIN state, PIN, no eID certificate).
    public const int Failed = 1;
    /// Usage error.
    public const int Usage = 2;
    /// No token (none present / serial not found) or the module could not be loaded.
    public const int NoToken = 3;
}

public static class CliArguments
{
    public const string UsageText = """
        eid-token-check — eID токеныг ЗӨВХӨН уншиж шалгах command-line хэрэгсэл

          eid-token-check --module <opensc-pkcs11 зам> [--serial <токены серийн дугаар>] [--json]
              токенууд ба гэрчилгээнүүдийг жагсаана (PIN шаардахгүй)
          eid-token-check --module <зам> --serial <серийн дугаар> [--origin <host>] --login [--json] < pin.txt
              нэг удаа C_Login хийж нэвтрэх таван шалгалтыг хийнэ; PIN-ийг ЗӨВХӨН stdin-ээр (pipe/файл)

        Exit code: 0 амжилттай · 1 шалгалт унасан / нэвтрээгүй · 2 буруу хэрэглээ · 3 токен алга / модуль ачаалагдсангүй
        """;

    public const string PinOnCommandLine = "PIN-ийг командын мөрөөр өгөхгүй — stdin-ээр (pipe эсвэл файл) дамжуулна";
    public const string SerialRequired = "--login-д --serial заавал (PIN оруулах токеныг тодорхой заана)";

    /// Never echoes the argument itself: it may be a PIN typed in the wrong place.
    public const string UnknownArgument = "Үл мэдэгдэх аргумент (утгыг нь хэвлэхгүй) — --help-ийг үзнэ үү";

    public static ParseResult Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        string? modulePath = null, serial = null, origin = null;
        var login = false;
        var json = false;
        var i = 0;
        string? Value()
        {
            if (i + 1 >= arguments.Count || arguments[i + 1].StartsWith("--", StringComparison.Ordinal)) return null;
            i++;
            return arguments[i];
        }
        while (i < arguments.Count)
        {
            var arg = arguments[i];
            if (arg.StartsWith("--pin", StringComparison.OrdinalIgnoreCase) || string.Equals(arg, "-p", StringComparison.OrdinalIgnoreCase))
                return ParseResult.Usage(PinOnCommandLine);
            switch (arg)
            {
                case "--help" or "-h":
                    return ParseResult.ShowHelp();
                case "--module":
                    if (modulePath is not null) return ParseResult.Usage("--module давхар өгөгдсөн");
                    if (Value() is not { Length: > 0 } m) return ParseResult.Usage("--module-ийн утга (модулийн зам) алга");
                    modulePath = m;
                    break;
                case "--serial":
                    if (serial is not null) return ParseResult.Usage("--serial давхар өгөгдсөн");
                    if (Value() is not { Length: > 0 } s) return ParseResult.Usage("--serial-ийн утга алга");
                    serial = s;
                    break;
                case "--origin":
                    if (origin is not null) return ParseResult.Usage("--origin давхар өгөгдсөн");
                    if (Value() is not { } o) return ParseResult.Usage("--origin-ий утга алга");
                    origin = o;
                    break;
                case "--login":
                    if (login) return ParseResult.Usage("--login давхар өгөгдсөн");
                    login = true;
                    break;
                case "--json":
                    if (json) return ParseResult.Usage("--json давхар өгөгдсөн");
                    json = true;
                    break;
                default:
                    return ParseResult.Usage(UnknownArgument);
            }
            i++;
        }
        if (modulePath is null) return ParseResult.Usage("--module <opensc-pkcs11 зам> заавал");
        var resolvedOrigin = origin ?? LoginChallenge.DefaultOrigin;
        if (!Core.Verification.Origin.IsValid(resolvedOrigin)) return ParseResult.Usage(Core.Verification.Origin.InvalidReason);
        if (login && serial is null) return ParseResult.Usage(SerialRequired);
        return ParseResult.Run(new CliOptions(modulePath, serial, resolvedOrigin, login, json));
    }
}

/// Where the PIN comes from: redirected standard input only.
public interface IPinInput
{
    /// Standard input is an interactive console — then the PIN is NOT read (refused).
    bool IsTerminal { get; }

    /// The first line (without CR/LF); null when there is none.
    string? ReadPin();
}

public sealed class StandardInputPin : IPinInput
{
    public bool IsTerminal => !Console.IsInputRedirected;

    /// Reads up to the first newline (at most 256 bytes) from the raw stdin stream; never echoes.
    public string? ReadPin()
    {
        using var stdin = Console.OpenStandardInput();
        var bytes = new List<byte>();
        int b;
        while (bytes.Count <= 256 && (b = stdin.ReadByte()) >= 0)
        {
            if (b == '\n') break;
            bytes.Add((byte)b);
        }
        if (bytes.Count > 0 && bytes[^1] == '\r') bytes.RemoveAt(bytes.Count - 1);
        if (bytes.Count is 0 or > 256) return null;
        var array = bytes.ToArray();
        try
        {
            return System.Text.Encoding.UTF8.GetString(array);
        }
        finally
        {
            Array.Clear(array);
            bytes.Clear();
        }
    }
}
