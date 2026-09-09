[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [string] $CaseId,
    [Parameter(Mandatory = $true)] [string] $GuestRoot,
    [Parameter(Mandatory = $true)] [string] $ArtifactPath,
    [Parameter(Mandatory = $true)] [string] $ArtifactSha256,
    [Parameter(Mandatory = $true)] [string] $PendingPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
function Fail([string] $Message) { throw "hyperv-interactive-launcher: $Message" }
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$' -or $CaseId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'run/case identity is invalid' }
$markerPath = Join-Path $GuestRoot 'run-marker.txt'
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { Fail 'guest case marker is missing' }
$markerLines = @(Get-Content -LiteralPath $markerPath)
if ($markerLines -notcontains "amnezia-release-lab:${RunId}:windows-x64" -or $markerLines -notcontains "backend=hyperv" -or $markerLines -notcontains "case_id=$CaseId") { Fail 'guest case marker binding mismatch' }
if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) { Fail 'interactive artifact is missing' }
$artifactHash = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($artifactHash -ne $ArtifactSha256.ToLowerInvariant()) { Fail 'interactive artifact hash differs from the planned hash' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$explorer = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1)
if ($explorer.Count -ne 1 -or [int]$explorer[0].SessionId -ne [System.Diagnostics.Process]::GetCurrentProcess().SessionId) { Fail 'limited launcher is not bound to the current interactive guest session' }
$procInfo = @(Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop)[0]
$request = [ordered]@{
    schema = 1; run_id = $RunId; case_id = $CaseId; profile = 'windows-x64'; state = 'waiting';
    artifact_sha256 = $artifactHash; launcher_path = $MyInvocation.MyCommand.Path; launcher_sha256 = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash.ToLowerInvariant();
    launcher_pid = [int]$PID; launcher_start_time = [string]$procInfo.CreationDate; launcher_session_id = [int][System.Diagnostics.Process]::GetCurrentProcess().SessionId;
    launcher_user = [string]$identity.Name; launcher_user_sid = [string]$identity.User.Value; installer_pid = $null; created_at = [DateTime]::UtcNow.ToString('o')
}
$tmp = "$PendingPath.tmp"; $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $PendingPath -Force
$process = Start-Process -FilePath $ArtifactPath -ArgumentList @('--accept-messages','--accept-licenses','--confirm-command','install','AmneziaSelfHostedUpdate=true') -PassThru -WindowStyle Normal
$request.installer_pid = [int]$process.Id; $request.state = 'waiting'; $tmp = "$PendingPath.tmp"; $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $PendingPath -Force
$request | ConvertTo-Json -Compress
