using EidTokenTest.Core.Tokens;

namespace EidTokenTest.Tests;

public sealed class OpenScModuleTests : IDisposable
{
    private static readonly TimeSpan Max = OpenScModule.StaleAge;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "eid-token-test-unit-" + Guid.NewGuid().ToString("N"));

    public OpenScModuleTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    /// A created config folder, optionally renamed, last written `age` ago (set last, after any change inside).
    private string AgedDir(string? name = null, TimeSpan? age = null, Action<string>? change = null)
    {
        var dir = OpenScModule.CreateConfigDir(_root);
        if (name is not null)
        {
            var renamed = Path.Combine(_root, name);
            Directory.Move(dir, renamed);
            dir = renamed;
        }
        change?.Invoke(dir);
        Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow - (age ?? TimeSpan.FromDays(10)));
        return dir;
    }

    [Fact]
    public void CreatedDirHoldsOnlyTheConfigAndIsRemovedByCleanup()
    {
        var dir = OpenScModule.CreateConfigDir(_root);
        Assert.Equal(["opensc.conf"], Directory.GetFileSystemEntries(dir).Select(p => Path.GetFileName(p)).ToArray());
        Assert.Matches("^eid-token-test-[0-9a-f]{32}$", Path.GetFileName(dir));

        Assert.True(OpenScModule.RemoveConfigDir(dir));
        Assert.False(Directory.Exists(dir));
        Assert.False(OpenScModule.RemoveConfigDir(dir)); // already gone: no exception
    }

    [Fact]
    public void CleanupLeavesADirWithAnUnexpectedFile()
    {
        var dir = OpenScModule.CreateConfigDir(_root);
        File.WriteAllText(Path.Combine(dir, "notes.txt"), "x");
        Assert.False(OpenScModule.RemoveConfigDir(dir));
        Assert.True(File.Exists(Path.Combine(dir, "opensc.conf")));
        Assert.True(File.Exists(Path.Combine(dir, "notes.txt")));
    }

    [Fact]
    public void SweepRemovesOldMatchingDirs()
    {
        var old = AgedDir();
        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);
        Assert.False(Directory.Exists(old));
    }

    [Fact]
    public void SweepLeavesRecentDirs()
    {
        var recent = AgedDir(age: TimeSpan.FromHours(1));
        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);
        Assert.True(Directory.Exists(recent));
    }

    [Fact]
    public void SweepLeavesDirsWithUnexpectedContent()
    {
        var extraFile = AgedDir(change: d => File.WriteAllText(Path.Combine(d, "other.txt"), "x"));
        var wrongName = AgedDir(change: d => File.Move(Path.Combine(d, "opensc.conf"), Path.Combine(d, "other.conf")));
        var confIsDir = AgedDir(change: d =>
        {
            File.Delete(Path.Combine(d, "opensc.conf"));
            Directory.CreateDirectory(Path.Combine(d, "opensc.conf"));
        });

        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);

        Assert.True(Directory.Exists(extraFile));
        Assert.True(Directory.Exists(wrongName));
        Assert.True(Directory.Exists(confIsDir));
    }

    [Fact]
    public void SweepLeavesDirsWhoseNameDoesNotMatchExactly()
    {
        var shortGuid = AgedDir("eid-token-test-abc123");
        var upper = AgedDir("eid-token-test-" + new string('A', 32));
        var suffixed = AgedDir("eid-token-test-" + new string('a', 32) + "-x");

        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);

        Assert.True(Directory.Exists(shortGuid));
        Assert.True(Directory.Exists(upper));
        Assert.True(Directory.Exists(suffixed));
    }

    [Fact]
    public void SweepOfAMissingRootDoesNotThrow() =>
        OpenScModule.SweepStale(Path.Combine(_root, "missing"), Max, DateTime.UtcNow);

    [Fact]
    public void SweepThresholdIsSevenDays()
    {
        Assert.Equal(TimeSpan.FromDays(7), OpenScModule.StaleAge);
        var dir = AgedDir(age: TimeSpan.FromDays(6));
        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);
        Assert.True(Directory.Exists(dir));
        Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow - TimeSpan.FromDays(8));
        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public void TouchKeepsALiveDirFromBeingSwept()
    {
        var dir = AgedDir(age: TimeSpan.FromDays(10));
        OpenScModule.Touch(dir);
        OpenScModule.SweepStale(_root, Max, DateTime.UtcNow);
        Assert.True(Directory.Exists(dir));
    }

    [Fact]
    public void HousekeepingNeverThrowsOnAnInvalidRoot()
    {
        var bad = "bad\0root";
        OpenScModule.SweepStale(bad, Max, DateTime.UtcNow);
        Assert.False(OpenScModule.RemoveConfigDir(bad));
        OpenScModule.Touch(bad);
    }

    [Fact]
    public void SweepDoesNotFollowAJunctionNamedLikeAStaleDir()
    {
        if (!OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_root, "real-target");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "opensc.conf"), "x");
        var link = Path.Combine(_root, "eid-token-test-" + new string('a', 32));
        var mk = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        })!;
        mk.WaitForExit();
        Assert.Equal(0, mk.ExitCode);
        try
        {
            // 8 days later the junction would count as stale if it were taken for a plain folder.
            OpenScModule.SweepStale(_root, Max, DateTime.UtcNow + TimeSpan.FromDays(8));
            Assert.True(File.Exists(Path.Combine(target, "opensc.conf")));
            Assert.True(Directory.Exists(link));
        }
        finally
        {
            Directory.Delete(link, recursive: false);   // removes the junction only, never the target's content
        }
    }
}
