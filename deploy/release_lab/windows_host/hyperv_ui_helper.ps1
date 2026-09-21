[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('capture','confirm','launch-app')] [string] $Action,
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [string] $CaseId,
    [Parameter(Mandatory = $true)] [guid] $VmId,
    [string] $OutputPath = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\ui-evidence.json",
    [string] $ScreenshotPath = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\ui-screenshot.png",
    [string] $ExpectedVersion = ""
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$' -or $CaseId -notmatch '^(thin-clean|thin-upgrade|thin-reinstall|outer-clean|outer-upgrade|outer-reinstall|outer-interactive)$') { throw 'RunId or CaseId is invalid' }
$explorer = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1)
if ($explorer.Count -ne 1) { throw 'logged-in guest explorer session is missing' }
$owner = (Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop)
$markerPath = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\run-marker.txt"
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'guest run marker is missing' }
$markerLines = @(Get-Content -LiteralPath $markerPath)
if ($markerLines -notcontains "amnezia-release-lab:${RunId}:windows-x64" -or $markerLines -notcontains "backend=hyperv" -or $markerLines -notcontains "case_id=$CaseId" -or $markerLines -notcontains "vm_id=$($VmId.ToString())") { throw 'guest run marker does not bind this run/profile/case/VM' }
$currentSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
if ([int]$explorer[0].SessionId -ne $currentSessionId) { throw 'Explorer session does not match the current guest process session' }
if (-not ('UiNative' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class UiNative {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public MOUSEKEYBDHARDWAREINPUT data; }
  [StructLayout(LayoutKind.Explicit)] public struct MOUSEKEYBDHARDWAREINPUT { [FieldOffset(0)] public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int command);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
  public static bool Enter() { var a=new INPUT[2]; a[0].type=1; a[0].data.ki.wVk=0x0D; a[1].type=1; a[1].data.ki.wVk=0x0D; a[1].data.ki.dwFlags=2; return SendInput(2,a,Marshal.SizeOf(typeof(INPUT)))==2; }
}
'@
}
if ($Action -eq 'confirm' -and -not [UiNative]::Enter()) { throw 'guest SendInput confirmation failed' }
$appEvidence = $null
if ($Action -eq 'launch-app') {
    if ($ExpectedVersion -notmatch '^[0-9]+(\.[0-9]+){2,3}$') { throw 'launch-app requires an expected installed version' }
    $appPath = 'C:\Program Files\AmneziaVPN\AmneziaVPN.exe'
    if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) { throw 'installed AmneziaVPN executable is missing' }
    $componentsPath = 'C:\Program Files\AmneziaVPN\components.xml'
    if (-not (Test-Path -LiteralPath $componentsPath -PathType Leaf) -or [IO.File]::ReadAllText($componentsPath) -notmatch "<Version>\s*$([regex]::Escape($ExpectedVersion))\s*</Version>") { throw 'installed AmneziaVPN version differs from the planned version' }
    $existing = @(Get-CimInstance Win32_Process -Filter "Name='AmneziaVPN.exe'" -ErrorAction SilentlyContinue | Where-Object { [string]$_.ExecutablePath -eq $appPath })
    if ($existing.Count -ne 0) { throw 'an installed AmneziaVPN process already exists before the owned launch' }
    $startedAt = [DateTime]::UtcNow
    $app = Start-Process -FilePath $appPath -PassThru
    $deadline = (Get-Date).AddSeconds(90); $rect = New-Object UiNative+RECT; $visible = $false
    do {
        Start-Sleep -Milliseconds 500
        try { $app.Refresh() } catch {}
        if (-not $app.HasExited -and $app.MainWindowHandle -ne [IntPtr]::Zero -and [UiNative]::IsWindowVisible($app.MainWindowHandle) -and [UiNative]::GetWindowRect($app.MainWindowHandle, [ref]$rect) -and $rect.Right -gt $rect.Left -and $rect.Bottom -gt $rect.Top) { $visible = $true; break }
    } while ((Get-Date) -lt $deadline -and -not $app.HasExited)
    if (-not $visible) { if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue }; throw 'owned AmneziaVPN launch did not expose a visible main window before deadline' }
    [void][UiNative]::ShowWindow($app.MainWindowHandle, 9)
    [void][UiNative]::BringWindowToTop($app.MainWindowHandle)
    if (-not [UiNative]::SetForegroundWindow($app.MainWindowHandle)) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue; throw 'owned AmneziaVPN window could not be brought to the foreground' }
    Start-Sleep -Seconds 2
    $app.Refresh(); if ($app.MainWindowHandle -eq [IntPtr]::Zero -or -not [UiNative]::IsWindowVisible($app.MainWindowHandle) -or -not [UiNative]::GetWindowRect($app.MainWindowHandle, [ref]$rect)) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue; throw 'owned AmneziaVPN window lost visibility before capture' }
    $actual = Get-CimInstance Win32_Process -Filter "ProcessId=$($app.Id)" -ErrorAction Stop
    if ([string]$actual.ExecutablePath -ne $appPath -or [int]$actual.SessionId -ne $currentSessionId) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue; throw 'owned AmneziaVPN process path/session binding differs' }
    $appEvidence = [ordered]@{ pid=[int]$app.Id; start_time=$app.StartTime.ToUniversalTime().ToString('o'); launched_after=$startedAt.ToString('o'); path=$appPath; sha256=(Get-FileHash -LiteralPath $appPath -Algorithm SHA256).Hash.ToLowerInvariant(); version=$ExpectedVersion; session_id=$currentSessionId; window_handle=[int64]$app.MainWindowHandle; window_title=[string]$app.MainWindowTitle; window_rect=[ordered]@{left=$rect.Left;top=$rect.Top;right=$rect.Right;bottom=$rect.Bottom}; visible=$true }
}
Add-Type -AssemblyName System.Drawing
$bitmap = New-Object Drawing.Bitmap 1280,720
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try { $graphics.CopyFromScreen(0,0,0,0,$bitmap.Size); $bitmap.Save($ScreenshotPath,[Drawing.Imaging.ImageFormat]::Png) } finally { $graphics.Dispose(); $bitmap.Dispose() }
if ($null -ne $appEvidence) {
    $captured = [Drawing.Bitmap]::FromFile($ScreenshotPath)
    try {
        $colors = New-Object 'System.Collections.Generic.HashSet[int]'; $nonDark=0; $samples=0
        $left=[Math]::Max(0,[int]$appEvidence.window_rect.left);$top=[Math]::Max(0,[int]$appEvidence.window_rect.top);$right=[Math]::Min($captured.Width,[int]$appEvidence.window_rect.right);$bottom=[Math]::Min($captured.Height,[int]$appEvidence.window_rect.bottom)
        for($y=$top;$y-lt$bottom;$y+=8){for($x=$left;$x-lt$right;$x+=8){$pixel=$captured.GetPixel($x,$y);[void]$colors.Add($pixel.ToArgb());if(($pixel.R+$pixel.G+$pixel.B)-gt60){$nonDark++};$samples++}}
        $appEvidence.render_samples=$samples;$appEvidence.distinct_colors=$colors.Count;$appEvidence.non_dark_samples=$nonDark
        $appEvidence.render_diagnostic_pass=[bool]($samples-ge100-and$colors.Count-ge20-and$nonDark-ge[math]::Ceiling($samples*0.05))
    } finally { $captured.Dispose() }
}
$evidence = [ordered]@{ schema=1; run_id=$RunId; profile='windows-x64'; case_id=$CaseId; vm_id=$VmId.ToString(); interactive_token=[bool]([Environment]::UserInteractive -and ([int]$explorer[0].SessionId -eq $currentSessionId)); session_id=[int]$explorer[0].SessionId; current_process_session_id=$currentSessionId; explorer_pid=[int]$explorer[0].ProcessId; explorer_owner=[string]$owner.User; explorer_domain=[string]$owner.Domain; screenshot_path=$ScreenshotPath; screenshot_sha256=(Get-FileHash -LiteralPath $ScreenshotPath -Algorithm SHA256).Hash.ToLowerInvariant(); action=$Action; app=$appEvidence; observed_at=[DateTime]::UtcNow.ToString('o') }
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$evidence | ConvertTo-Json -Compress
if ($null -ne $appEvidence) {
    $owned = Get-Process -Id ([int]$appEvidence.pid) -ErrorAction SilentlyContinue
    if ($null -ne $owned -and $owned.StartTime.ToUniversalTime().ToString('o') -eq [string]$appEvidence.start_time -and $owned.Path -eq [string]$appEvidence.path) { Stop-Process -Id $owned.Id -Force -ErrorAction Stop }
}
