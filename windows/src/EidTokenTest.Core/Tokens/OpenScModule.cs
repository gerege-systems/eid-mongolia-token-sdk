using System;
using System.IO;
using System.Text;

namespace EidTokenTest.Core.Tokens;

/// Where the bundled module sits and how it is isolated from an OpenSC installed on the same computer.
public static class OpenScModule
{
    /// `opensc\opensc-pkcs11.dll` next to the exe.
    public static string BundledPath => Path.Combine(AppContext.BaseDirectory, "opensc", "opensc-pkcs11.dll");

    /// Points `OPENSC_CONF` at a minimal config of our own unless the user already set it (e.g. to turn on
    /// OpenSC debug logging). Must run BEFORE the module is first loaded: opensc-pkcs11.dll links the C runtime
    /// statically and reads the environment copied at load time. Without it, an installed OpenSC's registry
    /// config (Program Files) would be read by our copy of the module.
    public static void IsolateConfig()
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OPENSC_CONF"))) return;
        var dir = Path.Combine(Path.GetTempPath(), "eid-token-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "opensc.conf");
        File.WriteAllText(file, "app default {\n    debug = 0;\n}\n", new UTF8Encoding(false));
        Environment.SetEnvironmentVariable("OPENSC_CONF", file);
    }
}
