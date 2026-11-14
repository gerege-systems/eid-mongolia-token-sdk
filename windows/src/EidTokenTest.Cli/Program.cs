using System.Text;
using EidTokenTest.Cli;
using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

// eid-token-check.exe: lists eID tokens and their certificates, or (--login) runs one login test — the same reader,
// login flow and verifier as the «eID Token Test» app. Trust certificates are embedded (EidTokenTest.Core).
Console.OutputEncoding = Encoding.UTF8;
OpenScModule.IsolateConfig();                     // before opensc-pkcs11.dll is loaded (it reads OPENSC_CONF once)
TrustAnchors trust;
try
{
    trust = TrustAnchors.Bundled();
}
catch (InvalidOperationException ex)
{
    // A broken embedded trust set stops the tool loudly — never a check against partial trust.
    Console.Error.WriteLine("eid-token-check: " + ex.Message);
    return ExitCode.Failed;
}
using var transport = new HttpRevocationTransport();
var readers = new List<Pkcs11TokenReader>();
try
{
    var runner = new CliRunner(path =>
        {
            var reader = Pkcs11TokenReader.Load(path);
            readers.Add(reader);
            return reader;
        },
        new LoginVerifier(trust, transport), new StandardInputPin(), Console.Out, Console.Error);
    return await runner.RunAsync(args);
}
finally
{
    foreach (var reader in readers) reader.Dispose();
}
