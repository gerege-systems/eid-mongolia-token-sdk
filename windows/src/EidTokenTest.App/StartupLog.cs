using System.Runtime.InteropServices;
using System.Text;

namespace EidTokenTest.App;

/// Startup diagnostics — never a silent blank window. One line per event, UTF-8, to standard error and to
/// `eid-token-test.log` next to the exe (or the path in `EID_TOKEN_TEST_LOG`; falls back to the temp folder when the
/// exe's folder is read-only). Only startup events and errors are written — never a PIN or certificate content.
/// The CI smoke test waits for <see cref="MainPageLoaded"/>; the macOS app writes the same marker.
internal static class StartupLog
{
    /// Written once, when the main window's content has been loaded and laid out.
    public const string MainPageLoaded = "main page loaded";

    private static readonly object Gate = new();

    public static string FilePath { get; } = ResolvePath();

    public static void Write(string message)
    {
        var line = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture)
                   + " " + message.Replace('\r', ' ').Replace('\n', ' ');
        lock (Gate)
        {
            try
            {
                Console.Error.WriteLine(line);
            }
            catch (IOException)
            {
                // no stderr attached (WinExe started from Explorer)
            }
            try
            {
                File.AppendAllText(FilePath, line + Environment.NewLine, new UTF8Encoding(false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // the log is best effort; the error is also shown on screen
            }
        }
    }

    /// A Win32 message box: works even when no XAML could be loaded at all.
    public static void ShowFatal(string text) =>
        _ = MessageBoxW(IntPtr.Zero, text, "eID Token Test", 0x00000010 /* MB_ICONERROR */);

    private static string ResolvePath()
    {
        var configured = Environment.GetEnvironmentVariable("EID_TOKEN_TEST_LOG");
        if (!string.IsNullOrWhiteSpace(configured)) return configured;
        var next = Path.Combine(AppContext.BaseDirectory, "eid-token-test.log");
        try
        {
            using (new FileStream(next, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            {
            }
            return next;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Path.Combine(Path.GetTempPath(), "eid-token-test.log");
        }
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr owner, string text, string caption, uint type);
}
