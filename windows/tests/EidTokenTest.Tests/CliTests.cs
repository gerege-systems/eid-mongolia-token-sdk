using System.Text.Json;
using EidTokenTest.Cli;
using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

public sealed class CliArgumentTests
{
    [Fact]
    public void Listing()
    {
        Assert.Equal(new CliOptions("m.dll"), CliArguments.Parse(["--module", "m.dll"]).Options);
        Assert.Equal(new CliOptions("m.dll", "S1", Json: true), CliArguments.Parse(["--module", "m.dll", "--serial", "S1", "--json"]).Options);
        Assert.True(CliArguments.Parse(["--help"]).Help);
    }

    [Fact]
    public void Login()
    {
        Assert.Equal(new CliOptions("m.dll", "S1", "rp.example.mn", Login: true),
            CliArguments.Parse(["--module", "m.dll", "--serial", "S1", "--origin", "rp.example.mn", "--login"]).Options);
    }

    [Fact]
    public void LoginWithoutSerialIsRefused() =>
        Assert.Equal(CliArguments.SerialRequired, CliArguments.Parse(["--module", "m.dll", "--login"]).UsageError);

    [Theory]
    [InlineData("--pin", "1234")]
    [InlineData("--pin=1234", null)]
    [InlineData("--PIN", "1234")]
    public void PinOnTheCommandLineIsRefused(string option, string? value)
    {
        var args = new List<string> { "--module", "m.dll", "--serial", "S1", "--login", option };
        if (value is not null) args.Add(value);
        Assert.Equal(CliArguments.PinOnCommandLine, CliArguments.Parse(args).UsageError);
    }

    /// Arguments separated by single spaces.
    [Theory]
    [InlineData("")]
    [InlineData("--serial S1")]
    [InlineData("--module")]
    [InlineData("--module m.dll extra")]
    [InlineData("--module m.dll --bogus")]
    [InlineData("--module m.dll --module n.dll")]
    [InlineData("--module m.dll --origin https://rp.example.mn")]
    [InlineData("--module m.dll --origin RP.example.mn")]
    [InlineData("--module m.dll --origin rp.example.mn:443")]
    [InlineData("--module m.dll --serial")]
    public void OtherUsageErrors(string line) =>
        Assert.NotNull(CliArguments.Parse(line.Length == 0 ? [] : line.Split(' ')).UsageError);
}

public sealed class CliRefusalTests
{
    private sealed class FakePin(bool terminal = false, string? pin = "1234") : IPinInput
    {
        public bool IsTerminal => terminal;
        public string? ReadPin() => pin;
    }

    private static TokenSummary Token(bool finalTry = false, bool locked = false, bool countLow = false, string serial = "S1") =>
        new(0, "eID", serial, "PKCS#15", "OpenSC", true, countLow, finalTry, locked,
            PinPolicy.FromFlags(true, locked, finalTry, countLow));

    private static async Task<(int Code, string Out, string Err)> Run(string[] args, FakeTokenSource? source, IPinInput? pin = null)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        using var pki = TestPki.Create();
        var runner = new CliRunner(path => source ?? throw new TokenModuleException("PKCS#11 модуль олдсонгүй: " + path),
            new LoginVerifier(pki.Trust, new FakeTransport(), () => TestPki.Now), pin ?? new FakePin(), output, error);
        var code = await runner.RunAsync(args);
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public async Task UsageErrorsExit2()
    {
        var source = new FakeTokenSource { Tokens = [Token()] };
        Assert.Equal(ExitCode.Usage, (await Run(["--module", "m.dll", "--login"], source)).Code);
        Assert.Equal(ExitCode.Usage, (await Run(["--module", "m.dll", "--serial", "S1", "--login", "--pin", "1"], source)).Code);
        Assert.Equal(0, source.SignCalls);
    }

    [Fact]
    public async Task PinFromATerminalIsRefused()
    {
        var source = new FakeTokenSource { Tokens = [Token()] };
        var (code, _, err) = await Run(["--module", "m.dll", "--serial", "S1", "--login"], source, new FakePin(terminal: true));
        Assert.Equal(ExitCode.Usage, code);
        Assert.Contains("stdin", err, StringComparison.Ordinal);
        Assert.Equal(0, source.SignCalls);
    }

    [Fact]
    public async Task FinalTryAndLockedAreRefusedWithoutCLogin()
    {
        foreach (var token in new[] { Token(finalTry: true), Token(locked: true) })
        {
            var source = new FakeTokenSource { Tokens = [token] };
            var (code, _, _) = await Run(["--module", "m.dll", "--serial", "S1", "--login"], source);
            Assert.Equal(ExitCode.Failed, code);
            Assert.Equal(0, source.SignCalls);
        }
    }

    [Fact]
    public async Task EmptyStdinIsAUsageError()
    {
        var source = new FakeTokenSource { Tokens = [Token()] };
        var (code, _, _) = await Run(["--module", "m.dll", "--serial", "S1", "--login"], source, new FakePin(pin: null));
        Assert.Equal(ExitCode.Usage, code);
        Assert.Equal(0, source.SignCalls);
    }

    [Fact]
    public async Task ModuleErrorAndMissingTokenExit3()
    {
        Assert.Equal(ExitCode.NoToken, (await Run(["--module", "missing.dll"], null)).Code);
        Assert.Equal(ExitCode.NoToken, (await Run(["--module", "m.dll"], new FakeTokenSource())).Code);
        Assert.Equal(ExitCode.NoToken,
            (await Run(["--module", "m.dll", "--serial", "S9", "--login"], new FakeTokenSource { Tokens = [Token()] })).Code);
    }

    [Fact]
    public async Task NoEidCertificates()
    {
        var other = new TokenCertificateObject([0x01], "other", [0x30, 0x00]);
        var (listCode, listOut, _) = await Run(["--module", "m.dll"],
            new FakeTokenSource { Tokens = [Token()], Certificates = [other] });
        Assert.Equal(ExitCode.Ok, listCode);
        Assert.Contains(TokenLogin.NoEidCertificates, listOut, StringComparison.Ordinal);

        var source = new FakeTokenSource { Tokens = [Token()], Certificates = [other] };
        var (loginCode, loginOut, _) = await Run(["--module", "m.dll", "--serial", "S1", "--login"], source);
        Assert.Equal(ExitCode.Failed, loginCode);
        Assert.Equal(0, source.SignCalls);
        Assert.Contains("Нэвтэрч чадсангүй: " + TokenLogin.NoEidCertificates, loginOut, StringComparison.Ordinal);
    }

    [Fact]
    public async Task JsonListing()
    {
        var (code, output, _) = await Run(["--module", "m.dll", "--json"], new FakeTokenSource { Tokens = [Token(countLow: true)] });
        Assert.Equal(ExitCode.Ok, code);
        using var doc = JsonDocument.Parse(output);
        var token = doc.RootElement.GetProperty("tokens")[0];
        Assert.Equal("S1", token.GetProperty("serial").GetString());
        Assert.True(token.GetProperty("pin").GetProperty("countLow").GetBoolean());
        Assert.False(token.GetProperty("pin").GetProperty("finalTry").GetBoolean());
        Assert.False(token.GetProperty("pin").GetProperty("locked").GetBoolean());
        Assert.Equal(TokenLogin.NoEidCertificates, token.GetProperty("note").GetString());
    }

    [Fact]
    public async Task JsonUsageError()
    {
        var (code, output, _) = await Run(["--module", "m.dll", "--login", "--json"], new FakeTokenSource { Tokens = [Token()] });
        Assert.Equal(ExitCode.Usage, code);
        using var doc = JsonDocument.Parse(output);
        Assert.Equal(CliArguments.SerialRequired, doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task JsonLoginReport()
    {
        using var pki = TestPki.Create();
        using var leaf = pki.CreateLeaf();
        var source = new FakeTokenSource
        {
            Tokens = [Token()],
            Certificates = [new TokenCertificateObject(EidKeyId.Auth, "eID AUTH", leaf.RawData)],
        };
        var (code, output, _) = await Run(["--module", "m.dll", "--serial", "S1", "--login", "--json"], source);
        Assert.Equal(ExitCode.Failed, code);
        Assert.Equal(1, source.SignCalls);
        using var doc = JsonDocument.Parse(output);
        Assert.False(doc.RootElement.GetProperty("loggedIn").GetBoolean());
        Assert.Equal(CheckNames.All, doc.RootElement.GetProperty("checks").EnumerateArray().Select(c => c.GetProperty("name").GetString()));
        Assert.Equal("unknown", doc.RootElement.GetProperty("checks")[0].GetProperty("status").GetString());
    }
}

public sealed class OriginTests
{
    [Theory]
    [InlineData("test.example")]
    [InlineData("login.example.mn")]
    [InlineData("a")]
    [InlineData("xn--80aa0b.mn")]
    [InlineData("rp-1.test.invalid")]
    public void Valid(string origin) => Assert.True(Origin.IsValid(origin));

    [Theory]
    [InlineData("")]
    [InlineData("Login.example.mn")]
    [InlineData("https://login.example.mn")]
    [InlineData("login.example.mn:443")]
    [InlineData("login.example.mn/path")]
    [InlineData("login.example.mn.")]
    [InlineData("логин.mn")]
    [InlineData("-a.mn")]
    [InlineData("a-.mn")]
    [InlineData("a..mn")]
    [InlineData(".a.mn")]
    [InlineData("a b.mn")]
    [InlineData("a_b.mn")]
    public void Invalid(string origin) => Assert.False(Origin.IsValid(origin));

    [Fact]
    public void LengthLimits()
    {
        Assert.True(Origin.IsValid(string.Concat(Enumerable.Repeat("a.", 126)) + "a"));        // 253
        Assert.False(Origin.IsValid(string.Concat(Enumerable.Repeat("a.", 126)) + "ab"));      // 254
        Assert.False(Origin.IsValid(new string('a', 64) + ".mn"));                               // label > 63
    }
}
