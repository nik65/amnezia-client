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
Import-Module Microsoft.PowerShell.Utility -Force -ErrorAction Stop
function Fail([string] $Message) { throw "hyperv-interactive-launcher: $Message" }

function Write-LaunchFailurePending([string] $Path, [object] $Request, [Management.Automation.ErrorRecord] $Failure) {
    $exception=$Failure.Exception; $nativeCode=$null; $cursor=$exception
    for($depth=0;$depth-lt8-and$null-ne$cursor;$depth++) {
        if($cursor-is[ComponentModel.Win32Exception]){$nativeCode=[int]$cursor.NativeErrorCode;break}
        $cursor=$cursor.InnerException
    }
    $type=[string]$exception.GetType().FullName
    if($type.Length-gt256){$type=$type.Substring(0,256)}
    $message=[string]$exception.Message
    if($message.Length-gt512){$message=$message.Substring(0,512)}
    $Request['state']='launch-failed';$Request['installer_pid']=$null;$Request['exit_code']=$null
    $Request['completed_at']=[DateTime]::UtcNow.ToString('o')
    $Request['launch_error']=[ordered]@{stage='Start-Process';error_type=$type;native_error_code=$nativeCode;hresult=[int]$exception.HResult;message=$message}
    $temporary=$Path+'.launch-failure-'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        $bytes=(New-Object Text.UTF8Encoding($true)).GetBytes(($Request|ConvertTo-Json -Depth 8))
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        # Pending was already written before Start-Process. Replace requires it
        # still to exist and atomically preserves its DACL; no overwrite fallback.
        [IO.File]::Replace($temporary,$Path,[NullString]::Value)
    } finally {
        if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
    }
}
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
    artifact_sha256 = $artifactHash; artifact_path = [IO.Path]::GetFullPath($ArtifactPath); launcher_path = $MyInvocation.MyCommand.Path; launcher_sha256 = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash.ToLowerInvariant();
    launcher_pid = [int]$PID; launcher_start_time = [string]$procInfo.CreationDate; launcher_session_id = [int][System.Diagnostics.Process]::GetCurrentProcess().SessionId;
    launcher_user = [string]$identity.Name; launcher_user_sid = [string]$identity.User.Value; installer_pid = $null; created_at = [DateTime]::UtcNow.ToString('o')
}
$tmp = "$PendingPath.tmp"; $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $PendingPath -Force
try {
    $process = Start-Process -FilePath $ArtifactPath -ArgumentList @('--accept-messages','--accept-licenses','--confirm-command','install','AmneziaSelfHostedUpdate=true') -PassThru -WindowStyle Normal -ErrorAction Stop
} catch {
    $launchFailure=$_
    try { Write-LaunchFailurePending $PendingPath $request $launchFailure }
    catch { [Console]::Error.WriteLine('launcher failure receipt could not be persisted: '+$_.Exception.GetType().FullName) }
    throw $launchFailure
}
$request.installer_pid = [int]$process.Id; $request.installer_start_time = [string]$process.StartTime.ToUniversalTime().ToString('o'); $request.state = 'running'; $tmp = "$PendingPath.tmp"; $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $PendingPath -Force
$completed = $process.WaitForExit(900000)
if (-not $completed) {
    $request.state = 'timeout'; $request.exit_code = $null; $request.completed_at = [DateTime]::UtcNow.ToString('o'); $tmp = "$PendingPath.tmp"; $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $PendingPath -Force
    Fail 'interactive installer exceeded the bounded 15 minute timeout'
}
$request.state = 'completed'; $request.exit_code = [int]$process.ExitCode; $request.completed_at = [DateTime]::UtcNow.ToString('o'); $tmp = "$PendingPath.tmp"; $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $PendingPath -Force
if ([int]$process.ExitCode -ne 0) { Fail "interactive installer exited with $($process.ExitCode)" }
$request | ConvertTo-Json -Compress
