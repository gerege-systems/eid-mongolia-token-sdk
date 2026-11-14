# UI smoke test of the PUBLISHED "eID Token Test" (CI, Windows PowerShell 5.1, needs an interactive desktop):
#
#   1. copy the published folder to a clean folder and start eid-token-test.exe from there;
#   2. wait for the main window and for the "main page loaded" line in eid-token-test.log (written by the app after the
#      first layout of its main page);
#   3. UI Automation: the three section headings (token / certificates / login test), the reload button and the
#      empty state "no token found" (no token on a CI machine) must be there;
#   4. on failure: a screenshot of the app's own window (GitHub-hosted runners only), the UI Automation tree, the
#      app log and stderr go to -OutDir.
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
            $rect = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle).Current.BoundingRectangle
            if ($rect.Width -gt 0 -and $rect.Height -gt 0) {
                $bitmap = New-Object System.Drawing.Bitmap ([int]$rect.Width), ([int]$rect.Height)
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen([int]$rect.X, [int]$rect.Y, 0, 0, $bitmap.Size)
                $bitmap.Save((Join-Path $OutDir 'ui-smoke-window.png'), [System.Drawing.Imaging.ImageFormat]::Png)
                $graphics.Dispose(); $bitmap.Dispose()
            }
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
