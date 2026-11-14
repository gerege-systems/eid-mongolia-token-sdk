using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Cli;

/// The command-line tool: the same reader (<see cref="Pkcs11TokenReader"/>), login flow (<see cref="TokenLogin"/>) and
/// verifier (<see cref="LoginVerifier"/>) as the test app — no second implementation. Human-readable lines by
/// default, one JSON object with `--json` (the same field names on macOS).
public sealed class CliRunner
{
    public const string FinalTryRefused =
        "Токен PIN-ий сүүлийн оролдлого дээр байна — command-line хэрэгсэл нэвтрэх оролдлого хийхгүй";
    public const string StdinIsTerminal = "PIN-ийг stdin-ээр (pipe эсвэл файл) дамжуулна — терминалаас уншихгүй";
    public const string NoPin = "stdin-ээс PIN уншигдсангүй";
    public const string NoToken = "Токен олдсонгүй";

    private readonly Func<string, ITokenSource> _openSource;
    private readonly LoginVerifier _verifier;
    private readonly IPinInput _pinInput;
    private readonly TextWriter _out;
    private readonly TextWriter _err;

    public CliRunner(Func<string, ITokenSource> openSource, LoginVerifier verifier, IPinInput pinInput, TextWriter output,
                     TextWriter error)
    {
        _openSource = openSource;
        _verifier = verifier;
        _pinInput = pinInput;
        _out = output;
        _err = error;
    }

    public async Task<int> RunAsync(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var parsed = CliArguments.Parse(arguments);
        if (parsed.Help)
        {
            _out.WriteLine(CliArguments.UsageText);
            return ExitCode.Ok;
        }
        if (parsed.Options is not { } options)
        {
            EmitError(parsed.UsageError ?? "usage", arguments.Contains("--json"));
            _err.WriteLine(CliArguments.UsageText);
            return ExitCode.Usage;
        }
        if (options.Login && _pinInput.IsTerminal)
        {
            EmitError(StdinIsTerminal, options.Json);
            return ExitCode.Usage;
        }

        ITokenSource source;
        IReadOnlyList<TokenSummary> tokens;
        try
        {
            source = _openSource(options.ModulePath);
            tokens = source.ListTokens();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            EmitError(ex.Message, options.Json);
            return ExitCode.NoToken;
        }
        var selected = options.Serial is null ? tokens : tokens.Where(t => t.Serial == options.Serial).ToList();
        if (selected.Count == 0)
        {
            EmitError(options.Serial is null ? NoToken : NoToken + ": " + options.Serial, options.Json);
            return ExitCode.NoToken;
        }
        return options.Login
            ? await LoginAsync(selected[0], source, options).ConfigureAwait(false)
            : List(selected, source, options.Json);
    }

    // Listing

    private int List(IReadOnlyList<TokenSummary> tokens, ITokenSource source, bool json)
    {
        var code = ExitCode.Ok;
        var entries = new List<TokenEntry>();
        foreach (var token in tokens)
        {
            var entry = new TokenEntry(token);
            if (!token.Initialized)
            {
                entry.Note = "Токен форматлагдаагүй (PKCS#15 бүтэцгүй)";
            }
            else
            {
                try
                {
                    var certificates = source.ReadCertificates(token.Serial);
                    entry.Certificates.AddRange(certificates.Select(CertificateView.Describe));
                    if (!TokenLogin.HasEidCertificates(certificates)) entry.Note = TokenLogin.NoEidCertificates;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    entry.Error = "Гэрчилгээ уншиж чадсангүй: " + ex.Message;
                    code = ExitCode.Failed;
                }
            }
            entries.Add(entry);
        }
        if (json)
        {
            _out.WriteLine(Json(w =>
            {
                w.WriteStartArray("tokens");
                foreach (var e in entries) e.Write(w);
                w.WriteEndArray();
            }));
            return code;
        }
        foreach (var e in entries)
        {
            var t = e.Token;
            _out.WriteLine("Токен: " + (t.Label.Length == 0 ? "(нэргүй)" : t.Label) + " — серийн дугаар " + t.Serial
                           + ", загвар " + Dash(t.Model));
            _out.WriteLine("  PIN: count-low=" + YesNo(t.PinCountLow) + ", final-try=" + YesNo(t.PinFinalTry) + ", locked="
                           + YesNo(t.PinLocked));
            foreach (var c in e.Certificates)
            {
                _out.WriteLine("  [" + c.KindCode + "] " + c.SubjectName);
                _out.WriteLine("    CKA_ID " + c.KeyIdHex + " · serialNumber " + Dash(c.SubjectSerial) + " · олгогч " + c.Issuer);
                _out.WriteLine("    серийн дугаар " + c.SerialHex + " · хүчинтэй " + Dash(Iso(c.NotBefore)) + " – " + Dash(Iso(c.NotAfter)));
            }
            if (e.Note is not null) _out.WriteLine("  " + e.Note);
            if (e.Error is not null) _out.WriteLine("  " + e.Error);
        }
        return code;
    }

    // Login

    private async Task<int> LoginAsync(TokenSummary token, ITokenSource source, CliOptions options)
    {
        switch (PinPolicy.Gate(token.Pin))
        {
            case PinGate.Blocked:
                EmitError(PinPolicy.Message(token.Pin) ?? "PIN ашиглах боломжгүй", options.Json);
                return ExitCode.Failed;
            case PinGate.ConfirmFinalTry:
                EmitError(FinalTryRefused, options.Json);
                return ExitCode.Failed;
        }
        if (_pinInput.ReadPin() is not { } pin)
        {
            EmitError(NoPin, options.Json);
            return ExitCode.Usage;
        }
        var report = await TokenLogin.RunAsync(source, token.Serial, options.Origin, pin, _verifier).ConfigureAwait(false);
        if (options.Json)
        {
            _out.WriteLine(Json(w =>
            {
                w.WriteStartArray("checks");
                foreach (var c in report.Checks)
                {
                    w.WriteStartObject();
                    w.WriteString("mark", c.Mark);
                    w.WriteString("name", c.Name);
                    w.WriteString("reason", c.Reason);
                    w.WriteString("status", c.Status);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteBoolean("loggedIn", report.LoggedIn);
                w.WriteString("origin", options.Origin);
                w.WriteString("serial", token.Serial);
                w.WriteString("summary", report.Summary);
            }));
        }
        else
        {
            foreach (var c in report.Checks) _out.WriteLine(c.Name + ": " + c.Mark + " — " + c.Reason);
            _out.WriteLine(report.Summary);
        }
        return report.LoggedIn ? ExitCode.Ok : ExitCode.Failed;
    }

    // Output

    private void EmitError(string message, bool json)
    {
        if (json) _out.WriteLine(Json(w => w.WriteString("error", message)));
        else _err.WriteLine("eid-token-check: " + message);
    }

    private static string YesNo(bool value) => value ? "yes" : "no";

    private static string Dash(string? value) => string.IsNullOrEmpty(value) ? "—" : value;

    internal static string? Iso(DateTimeOffset? at) =>
        at?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// One JSON object; keys written in sorted order (as on macOS); Cyrillic kept readable.
    private static string Json(Action<Utf8JsonWriter> body)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private sealed class TokenEntry(TokenSummary token)
    {
        public TokenSummary Token { get; } = token;
        public List<CertificateView> Certificates { get; } = [];
        public string? Note { get; set; }
        public string? Error { get; set; }

        public void Write(Utf8JsonWriter w)
        {
            w.WriteStartObject();
            w.WriteStartArray("certificates");
            foreach (var c in Certificates)
            {
                w.WriteStartObject();
                w.WriteString("issuer", c.Issuer);
                w.WriteString("keyId", c.KeyIdHex);
                if (Iso(c.NotAfter) is { } notAfter) w.WriteString("notAfter", notAfter);
                if (Iso(c.NotBefore) is { } notBefore) w.WriteString("notBefore", notBefore);
                w.WriteString("serial", c.SerialHex);
                if (c.SubjectSerial is not null) w.WriteString("serialNumber", c.SubjectSerial);
                w.WriteString("subject", c.SubjectName);
                w.WriteString("type", c.KindCode);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            if (Error is not null) w.WriteString("error", Error);
            w.WriteBoolean("initialized", Token.Initialized);
            w.WriteString("label", Token.Label);
            w.WriteString("manufacturer", Token.Manufacturer);
            w.WriteString("model", Token.Model);
            if (Note is not null) w.WriteString("note", Note);
            w.WriteStartObject("pin");
            w.WriteBoolean("countLow", Token.PinCountLow);
            w.WriteBoolean("finalTry", Token.PinFinalTry);
            w.WriteBoolean("locked", Token.PinLocked);
            w.WriteEndObject();
            w.WriteString("serial", Token.Serial);
            w.WriteEndObject();
        }
    }
}
