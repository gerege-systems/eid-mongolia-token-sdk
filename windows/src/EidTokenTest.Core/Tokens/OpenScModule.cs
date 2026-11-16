using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace EidTokenTest.Core.Tokens;

/// Where the bundled module sits and how it is isolated from an OpenSC installed on the same computer.
public static class OpenScModule
{
    private const string DirPrefix = "eid-token-test-";
    private const string ConfName = "opensc.conf";
    private const string ConfText = "app default {\n    debug = 0;\n}\n";

    /// Exactly what <see cref="CreateConfigDir"/> makes: the prefix and a 32-digit lowercase hex GUID.
    private static readonly Regex DirName = new("^eid-token-test-[0-9a-f]{32}$", RegexOptions.CultureInvariant);

    /// A folder not touched for this long belongs to a process that is gone.
    internal static readonly TimeSpan StaleAge = TimeSpan.FromDays(7);

    private static readonly object Gate = new();
    private static string? _ownDir;

    /// `opensc\opensc-pkcs11.dll` next to the exe.
    public static string BundledPath => Path.Combine(AppContext.BaseDirectory, "opensc", "opensc-pkcs11.dll");

    /// Points `OPENSC_CONF` at a minimal config of our own unless the user already set it (e.g. to turn on
    /// OpenSC debug logging). Must run BEFORE the module is first loaded: opensc-pkcs11.dll links the C runtime
    /// statically and reads the environment copied at load time. Without it, an installed OpenSC's registry
    /// config (Program Files) would be read by our copy of the module.
    ///
    /// The folder is removed when the process exits normally (by then the readers are disposed, i.e. C_Finalize has
    /// run). Folders of runs that crashed are swept at the next start once they are older than 7 days; a running
    /// process refreshes its folder's time on every <see cref="Touch()"/> (each module load), so it is never swept.
    /// The sweep and the exit cleanup are housekeeping and can never stop the start; creating the config is not
    /// housekeeping and still throws.
    public static void IsolateConfig()
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OPENSC_CONF"))) return;
        var root = Path.GetTempPath();
        SweepStale(root, StaleAge, DateTime.UtcNow);   // never throws
        var dir = CreateConfigDir(root);
        lock (Gate) _ownDir = dir;
        AppDomain.CurrentDomain.ProcessExit += (_, _) => RemoveOwnDir();   // RemoveOwnDir never throws
        Environment.SetEnvironmentVariable("OPENSC_CONF", Path.Combine(dir, ConfName));
    }

    /// Creates `<root>\eid-token-test-<guid>\opensc.conf` and returns the folder.
    internal static string CreateConfigDir(string root)
    {
        var dir = Path.Combine(root, DirPrefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, ConfName), ConfText, new UTF8Encoding(false));
        return dir;
    }

    /// Refreshes the folder's time (cheap), so another instance's sweep skips it. Best effort: never throws.
    public static void Touch()
    {
        string? dir;
        lock (Gate) dir = _ownDir;
        if (dir is not null) Touch(dir);
    }

    internal static void Touch(string dir)
    {
        try
        {
            Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow);
        }
        catch (Exception)
        {
            // housekeeping: whatever goes wrong here must never fail a login check
        }
    }

    /// Removes the folder this process created, if any. Best effort: never throws.
    internal static void RemoveOwnDir()
    {
        string? dir;
        lock (Gate)
        {
            dir = _ownDir;
            _ownDir = null;
        }
        if (dir is not null) RemoveConfigDir(dir);   // never throws
    }

    /// Deletes `dir` only when it holds nothing but a regular `opensc.conf` and is not a link. Never recursive;
    /// never throws. Returns whether the folder was removed.
    internal static bool RemoveConfigDir(string dir)
    {
        try
        {
            var info = new DirectoryInfo(dir);
            if (!info.Exists || IsLink(info)) return false;
            var entries = info.GetFileSystemInfos();
            if (entries.Length > 1) return false;
            if (entries.Length == 1)
            {
                var only = entries[0];
                if (only.Name != ConfName || only is DirectoryInfo || IsLink(only)) return false;
                only.Delete();
            }
            info.Delete(false);
            return true;
        }
        catch (Exception)
        {
            // cleanup is best effort: a folder that cannot be inspected or removed is left behind, nothing more
            return false;
        }
    }

    /// Deletes `<root>\eid-token-test-<32 hex>` folders last written more than `maxAge` ago that hold only the
    /// expected `opensc.conf`. Folders only directly inside `root`; links and anything unexpected are left alone.
    /// Best effort: never throws.
    internal static void SweepStale(string root, TimeSpan maxAge, DateTime nowUtc)
    {
        try
        {
            foreach (var candidate in new DirectoryInfo(root).EnumerateDirectories(DirPrefix + "*"))
            {
                try
                {
                    if (!DirName.IsMatch(candidate.Name) || IsLink(candidate)) continue;
                    if (nowUtc - candidate.LastWriteTimeUtc < maxAge) continue;
                    RemoveConfigDir(candidate.FullName);
                }
                catch (Exception)
                {
                    // one folder that cannot be inspected does not stop the sweep
                }
            }
        }
        catch (Exception)
        {
            // the sweep is housekeeping (an unreadable or invalid temp root included); it never fails a start
        }
    }

    private static bool IsLink(FileSystemInfo info) => info.Attributes.HasFlag(FileAttributes.ReparsePoint);
}
