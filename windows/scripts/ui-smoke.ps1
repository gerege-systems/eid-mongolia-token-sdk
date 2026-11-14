# UI smoke test of the PUBLISHED "eID Token Test" (CI, Windows PowerShell 5.1, needs an interactive desktop):
#
#   1. copy the published folder to a clean folder and start eid-token-test.exe from there;
#   2. wait for the main window and for the "main page loaded" line in eid-token-test.log (written by the app after the
#      first layout of its main page);
#   3. UI Automation: the three section headings (token / certificates / login test), the reload button and the
#      empty state "no token found" (no token on a CI machine) must be there;
#   4. pixels: the UI Automation tree and the log line exist even when no frame was ever presented, so the display is
#      kept awake, the app's own window is captured with PrintWindow(PW_RENDERFULLCONTENT) (PrintWindow(..., 0) is
#      always white for WinUI) and its client area must hold >= 50 distinct colours, the page surface colour
#      (#F9F9FC light / #0B0E12 dark, from App.xaml, by the user's app theme) and no colour on more than 90 % of it;
#      that window-only PNG is always written to -OutDir (ui-smoke-window.png);
#   5. on failure: also the UI Automation tree, the app log and stderr go to -OutDir.
#
# The process is always stopped by its own PID. Non-ASCII texts are written as \u escapes so the file reads the same
# under any code page.
param(
    [Parameter(Mandatory = $true)] [string] $AppDir,
    [Parameter(Mandatory = $true)] [string] $OutDir,
    [int] $TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms, System.Drawing
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

public static class EidWindowPixels
{
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] static extern bool ClientToScreen(IntPtr hwnd, ref POINT point);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll")] static extern uint SetThreadExecutionState(uint flags);

    // ES_CONTINUOUS | ES_DISPLAY_REQUIRED, then WM_SYSCOMMAND / SC_MONITORPOWER / -1 (on) to every top-level window.
    public static void KeepDisplayOn()
    {
        SetThreadExecutionState(0x80000000u | 0x00000002u);
        PostMessage(new IntPtr(0xFFFF), 0x0112, new IntPtr(0xF170), new IntPtr(-1));
    }

    // The whole window as the compositor renders it (PW_RENDERFULLCONTENT = 0x2).
    public static Bitmap Capture(IntPtr hwnd)
    {
        RECT r;
        GetWindowRect(hwnd, out r);
        Bitmap bitmap = new Bitmap(Math.Max(1, r.Right - r.Left), Math.Max(1, r.Bottom - r.Top), PixelFormat.Format32bppArgb);
        using (Graphics g = Graphics.FromImage(bitmap))
        {
            IntPtr hdc = g.GetHdc();
            try { PrintWindow(hwnd, hdc, 0x2); } finally { g.ReleaseHdc(hdc); }
        }
        return bitmap;
    }

    // The client area (below the title bar) inside a Capture() bitmap.
    public static Rectangle ClientArea(IntPtr hwnd)
    {
        RECT w, c;
        GetWindowRect(hwnd, out w);
        GetClientRect(hwnd, out c);
        POINT origin = new POINT();
        ClientToScreen(hwnd, ref origin);
        return new Rectangle(origin.X - w.Left, origin.Y - w.Top, c.Right - c.Left, c.Bottom - c.Top);
    }

    // { distinct colours, share of the most frequent colour, pixels with exactly `expected` (opaque RGB) }.
    public static double[] Measure(Bitmap bitmap, Rectangle area, int expectedRgb)
    {
        area.Intersect(new Rectangle(0, 0, bitmap.Width, bitmap.Height));
        if (area.Width <= 0 || area.Height <= 0) return new double[] { 0, 1, 0 };
        BitmapData data = bitmap.LockBits(area, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
        Dictionary<int, int> counts = new Dictionary<int, int>();
        int[] row = new int[area.Width];
        try
        {
            for (int y = 0; y < area.Height; y++)
            {
                Marshal.Copy(new IntPtr(data.Scan0.ToInt64() + (long)y * data.Stride), row, 0, area.Width);
                for (int x = 0; x < area.Width; x++)
                {
                    int rgb = row[x] & 0x00FFFFFF;
                    int n;
                    counts.TryGetValue(rgb, out n);
                    counts[rgb] = n + 1;
                }
            }
        }
        finally { bitmap.UnlockBits(data); }
        int top = 0;
        foreach (int n in counts.Values) if (n > top) top = n;
        int expected;
        counts.TryGetValue(expectedRgb & 0x00FFFFFF, out expected);
        return new double[] { counts.Count, (double)top / ((double)area.Width * area.Height), expected };
    }
}
'@

function U([string] $escaped) { [regex]::Unescape($escaped) }
$expected = @(
    (U '\u0422\u043e\u043a\u0435\u043d'),  # section heading 1
    (U '\u0413\u044d\u0440\u0447\u0438\u043b\u0433\u044d\u044d'),  # section heading 2
    (U '\u041d\u044d\u0432\u0442\u0440\u044d\u0445 \u0442\u0435\u0441\u0442'),  # section heading 3
    (U '\u0414\u0430\u0445\u0438\u043d \u0443\u043d\u0448\u0438\u0445'),  # reload button
    (U '\u0422\u043e\u043a\u0435\u043d \u043e\u043b\u0434\u0441\u043e\u043d\u0433\u04af\u0439')  # empty state: no token
)
$marker = 'main page loaded'

New-Item -ItemType Directory -Force $OutDir | Out-Null
$work = Join-Path $env:RUNNER_TEMP 'ui-smoke'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
Copy-Item $AppDir $work -Recurse
$exe = Join-Path $work 'eid-token-test.exe'
$log = Join-Path $work 'eid-token-test.log'
$stderr = Join-Path $OutDir 'eid-token-test.stderr.txt'
$stdout = Join-Path $OutDir 'eid-token-test.stdout.txt'

function Save-Evidence([System.Diagnostics.Process] $process) {
    # A screenshot of the app's OWN window only (never the desktop), and only on a GitHub-hosted runner.
    try {
        if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
            Write-Host "screenshot skipped (runner environment '$($env:RUNNER_ENVIRONMENT)')"
        } elseif ($process -and -not $process.HasExited -and $process.MainWindowHandle -ne [IntPtr]::Zero) {
            $bitmap = [EidWindowPixels]::Capture($process.MainWindowHandle)
            $bitmap.Save((Join-Path $OutDir 'ui-smoke-window.png'), [System.Drawing.Imaging.ImageFormat]::Png)
            $bitmap.Dispose()
        } else {
            Write-Host "screenshot skipped (no app window)"
        }
    } catch { Write-Host "screenshot failed: $_" }
    if (Test-Path $log) { Copy-Item $log (Join-Path $OutDir 'eid-token-test.log') }
    try {
        if ($process -and -not $process.HasExited -and $process.MainWindowHandle -ne [IntPtr]::Zero) {
            $root = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
            $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
            $lines = foreach ($e in $all) { $e.Current.ControlType.ProgrammaticName + "`t" + $e.Current.Name }
            [System.IO.File]::WriteAllLines((Join-Path $OutDir 'uia-tree.txt'), [string[]]$lines, (New-Object System.Text.UTF8Encoding $false))
        }
    } catch { Write-Host "UI Automation dump failed: $_" }
}

function Find-ByName($root, [string] $name) {
    $condition = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty), $name
    $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}

$process = $null
$failed = $null
try {
    $process = Start-Process -FilePath $exe -WorkingDirectory $work -PassThru `
        -RedirectStandardError $stderr -RedirectStandardOutput $stdout
    Write-Host "started eid-token-test.exe, PID $($process.Id)"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ($true) {
        $process.Refresh()
        if ($process.HasExited) { throw "the app exited (code $($process.ExitCode)) before showing its window" }
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) { break }
        if ((Get-Date) -gt $deadline) { throw "no main window after $TimeoutSeconds s" }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "main window: $($process.MainWindowTitle)"

    while (-not ((Test-Path $log) -and (Select-String -Path $log -SimpleMatch $marker -Quiet))) {
        $process.Refresh()
        if ($process.HasExited) { throw "the app exited (code $($process.ExitCode)) before '$marker'" }
        if ((Get-Date) -gt $deadline) { throw "no '$marker' in eid-token-test.log after $TimeoutSeconds s" }
        Start-Sleep -Milliseconds 500
    }
    Write-Host (Select-String -Path $log -SimpleMatch $marker | Select-Object -First 1).Line

    $root = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
    $missing = @($expected)
    while ($missing.Count -gt 0) {
        $missing = @($missing | Where-Object { -not (Find-ByName $root $_) })
        if ($missing.Count -eq 0) { break }
        $process.Refresh()
        if ($process.HasExited) { throw "the app exited (code $($process.ExitCode))" }
        if ((Get-Date) -gt $deadline) { throw ("not found by UI Automation: " + ($missing -join ' | ')) }
        Start-Sleep -Seconds 1
    }
    Write-Host "UI Automation: all $($expected.Count) texts found"

    # Pixels: a frame was really presented. Light / dark page surface from App.xaml, by the user's app theme.
    [EidWindowPixels]::KeepDisplayOn()
    Start-Sleep -Seconds 3
    $light = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction SilentlyContinue).AppsUseLightTheme
    $surface = if ($light -eq 0) { 0x0B0E12 } else { 0xF9F9FC }
    $hwnd = $process.MainWindowHandle
    $bitmap = [EidWindowPixels]::Capture($hwnd)
    try {
        $bitmap.Save((Join-Path $OutDir 'ui-smoke-window.png'), [System.Drawing.Imaging.ImageFormat]::Png)
        $area = [EidWindowPixels]::ClientArea($hwnd)
        $m = [EidWindowPixels]::Measure($bitmap, $area, $surface)
    } finally { $bitmap.Dispose() }
    $distinct = [int]$m[0]; $topShare = [double]$m[1]; $surfacePixels = [int]$m[2]
    $summary = "client area $($area.Width)x$($area.Height): $distinct distinct colours, top colour {0:P1}, surface #{1:X6} on $surfacePixels pixels (theme: {2})" -f $topShare, $surface, $(if ($light -eq 0) { 'dark' } else { 'light' })
    Write-Host "pixels: $summary"
    if ($distinct -lt 50 -or $topShare -gt 0.90 -or $surfacePixels -eq 0) {
        throw "the window content was not rendered: $summary (need >= 50 colours, top colour <= 90 %, surface colour present)"
    }
    $process.Refresh()
    if ($process.HasExited) { throw "the app exited (code $($process.ExitCode))" }
    Write-Host "ui smoke OK"
}
catch {
    $failed = "$_"
    Write-Host "::error::UI smoke test failed: $failed"
    Save-Evidence $process
    if (Test-Path $log) { Get-Content $log -Encoding UTF8 | Write-Host }
}
finally {
    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}
if ($failed) { exit 1 }
