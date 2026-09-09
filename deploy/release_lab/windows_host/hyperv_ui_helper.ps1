[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('capture','confirm')] [string] $Action,
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [guid] $VmId,
    [string] $OutputPath = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\ui-evidence.json",
    [string] $ScreenshotPath = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\ui-screenshot.png"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { throw 'RunId is invalid' }
$explorer = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1)
if ($explorer.Count -ne 1) { throw 'logged-in guest explorer session is missing' }
$owner = (Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop)
$markerPath = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\run-marker.txt"
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'guest run marker is missing' }
$markerLines = @(Get-Content -LiteralPath $markerPath)
if ($markerLines -notcontains "amnezia-release-lab:${RunId}:windows-x64" -or $markerLines -notcontains "backend=hyperv" -or $markerLines -notcontains "vm_id=$($VmId.ToString())") { throw 'guest run marker does not bind this run/profile/VM' }
$currentSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
if ([int]$explorer[0].SessionId -ne $currentSessionId) { throw 'Explorer session does not match the current guest process session' }
if (-not ('UiNative' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class UiNative {
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public MOUSEKEYBDHARDWAREINPUT data; }
  [StructLayout(LayoutKind.Explicit)] public struct MOUSEKEYBDHARDWAREINPUT { [FieldOffset(0)] public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
  public static bool Enter() { var a=new INPUT[2]; a[0].type=1; a[0].data.ki.wVk=0x0D; a[1].type=1; a[1].data.ki.wVk=0x0D; a[1].data.ki.dwFlags=2; return SendInput(2,a,Marshal.SizeOf(typeof(INPUT)))==2; }
}
'@
}
if ($Action -eq 'confirm' -and -not [UiNative]::Enter()) { throw 'guest SendInput confirmation failed' }
Add-Type -AssemblyName System.Drawing
$bitmap = New-Object Drawing.Bitmap 1280,720
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try { $graphics.CopyFromScreen(0,0,0,0,$bitmap.Size); $bitmap.Save($ScreenshotPath,[Drawing.Imaging.ImageFormat]::Png) } finally { $graphics.Dispose(); $bitmap.Dispose() }
$evidence = [ordered]@{ schema=1; run_id=$RunId; profile='windows-x64'; vm_id=$VmId.ToString(); interactive_token=[bool]([Environment]::UserInteractive -and ([int]$explorer[0].SessionId -eq $currentSessionId)); session_id=[int]$explorer[0].SessionId; current_process_session_id=$currentSessionId; explorer_pid=[int]$explorer[0].ProcessId; explorer_owner=[string]$owner.User; explorer_domain=[string]$owner.Domain; screenshot_path=$ScreenshotPath; screenshot_sha256=(Get-FileHash -LiteralPath $ScreenshotPath -Algorithm SHA256).Hash.ToLowerInvariant(); action=$Action; observed_at=[DateTime]::UtcNow.ToString('o') }
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$evidence | ConvertTo-Json -Compress
