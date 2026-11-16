using EidTokenTest.Core.Tokens;

namespace EidTokenTest.Tests;

public sealed class OpenScModuleTests : IDisposable
{
    private static readonly TimeSpan Day = TimeSpan.FromHours(24);

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
        Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow - (age ?? TimeSpan.FromDays(3)));
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
        OpenScModule.SweepStale(_root, Day, DateTime.UtcNow);
        Assert.False(Directory.Exists(old));
    }

    [Fact]
    public void SweepLeavesRecentDirs()
    {
        var recent = AgedDir(age: TimeSpan.FromHours(1));
        OpenScModule.SweepStale(_root, Day, DateTime.UtcNow);
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

        OpenScModule.SweepStale(_root, Day, DateTime.UtcNow);

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

        OpenScModule.SweepStale(_root, Day, DateTime.UtcNow);

        Assert.True(Directory.Exists(shortGuid));
        Assert.True(Directory.Exists(upper));
        Assert.True(Directory.Exists(suffixed));
    }

    [Fact]
    public void SweepOfAMissingRootDoesNotThrow() =>
        OpenScModule.SweepStale(Path.Combine(_root, "missing"), Day, DateTime.UtcNow);
}
