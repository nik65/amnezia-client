[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('plan','probe','smoke','stop')]
    [string] $Action,
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [string] $CaseId,
    [Parameter(Mandatory = $true)] [guid] $VmId,
    [Parameter(Mandatory = $true)] [string] $ChildRecordPath,
    [Parameter(Mandatory = $true)] [string] $ServerRecordPath,
    [Parameter(Mandatory = $true)] [string] $SupervisorPath,
    [Parameter(Mandatory = $true)] [string] $RelayPath,
    [string] $HostKeyPinPath,
    [string] $ServerRequestLogPath,
    [string] $AttemptNonce,
    [string] $RunRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\runs',
    [switch] $EnableLive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SshServiceGuid = '{5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}'
$HttpServiceGuid = '{6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42}'
$SshRelayPort = 22222
$HttpRelayPort = 17865
$LinuxSshPort = 22
$HttpPath = '/healthz'
$StopEventName = "Local\AmneziaReleaseLabRelayStop_${RunId}_${CaseId}"

function Fail([string] $Message) { throw "hyperv-relay-smoke: $Message" }
function Full([string] $Path) { [IO.Path]::GetFullPath($Path) }
function Read-Json([string] $Path) { if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "record is missing: $Path" }; Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
function Assert-Id([string] $Value, [string] $Label) { if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail "$Label is not bounded" } }
function Assert-ExactGuid([guid] $Value) {
    $text = $Value.ToString('B')
    $forbidden = @([guid]::Empty, [guid]'00000000-0000-0000-0000-000000000000')
    if ($forbidden -contains $Value) { Fail 'VM ID is empty' }
    if ($text -eq '{ffffffff-ffff-ffff-ffff-ffffffffffff}') { Fail 'VM ID wildcard is forbidden' }
}
function Assert-OwnedPath([string] $Path, [string] $Label) {
    $root = (Full $RunRoot).TrimEnd('\') + '\'
    $full = Full $Path
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the owned run root" }
    return $full
}
function Assert-RecordIdentity($Record, [string] $Label) {
    foreach ($name in @('run_id','case_id','vm_id','parent_sha256')) { if (-not $Record.PSObject.Properties[$name]) { Fail "$Label lacks $name" } }
    if ([string]$Record.run_id -ne $RunId -or [string]$Record.case_id -ne $CaseId -or [string]$Record.vm_id -ne $VmId.ToString('B')) { Fail "$Label identity mismatch" }
    if ([string]$Record.parent_sha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail "$Label parent hash is not SHA-256" }
}
function Assert-ChildRecord($Record) {
    Assert-RecordIdentity $Record 'child record'
    foreach ($name in @('qmp_socket','qga_socket','marker','process_pid','process_uuid')) { if (-not $Record.PSObject.Properties[$name]) { Fail "child record lacks $name" } }
    if ([int64]$Record.process_pid -le 0 -or [string]$Record.process_uuid -notmatch '^[0-9a-fA-F-]{36}$') { Fail 'child process identity is invalid' }
    if ([string]$Record.marker -ne "amnezia-release-lab:${RunId}:windows-x64") { Fail 'child marker is not bound to run/profile' }
}
function Assert-ServerRecord($Record) {
    if (-not $Record.PSObject.Properties['run_id'] -or [string]$Record.run_id -ne $RunId) { Fail 'server record run identity mismatch' }
    if (-not $Record.PSObject.Properties['profile'] -or [string]$Record.profile -ne 'server-router') { Fail 'server record is not server-router' }
    if (-not $Record.PSObject.Properties['qmp_socket'] -or -not $Record.PSObject.Properties['qga_socket']) { Fail 'server record lacks QMP/QGA binding' }
    if ([string]$Record.http_guest_port -ne '17865' -or [string]$Record.ssh_guest_port -ne '22' -or [string]$Record.host_bind -ne '127.0.0.1') { Fail 'server record fixed endpoint mapping mismatch' }
}
function Invoke-BoundedHttpNonce([string] $Nonce) {
    if ($Nonce -notmatch '^[A-Za-z0-9._-]{16,128}$') { Fail 'attempt nonce is invalid' }
    $encodedRun = [Uri]::EscapeDataString($RunId)
    $encodedNonce = [Uri]::EscapeDataString($Nonce)
    $uri = "http://127.0.0.1:${HttpRelayPort}${HttpPath}?run_id=${encodedRun}&nonce=${encodedNonce}"
    $request = [Net.HttpWebRequest]::Create($uri); $request.Method = 'GET'; $request.Timeout = 5000; $request.ReadWriteTimeout = 5000
    $response = $request.GetResponse(); try {
        $reader = New-Object IO.StreamReader($response.GetResponseStream()); try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $bodyRecord = $body | ConvertFrom-Json
        if ([int]$response.StatusCode -ne 200 -or [string]$bodyRecord.run_id -ne $RunId) { Fail 'HTTP nonce response identity mismatch' }
        if ([string]::IsNullOrWhiteSpace($ServerRequestLogPath) -or -not (Test-Path -LiteralPath $ServerRequestLogPath -PathType Leaf)) { Fail 'server request-log evidence is missing' }
        $records = @((Get-Content -LiteralPath $ServerRequestLogPath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }))
        if (@($records | Where-Object { [string]$_.run_id -eq $RunId -and [string]$_.attempt_nonce -eq $Nonce -and [string]$_.path -match [regex]::Escape($Nonce) }).Count -eq 0) { Fail 'server request-log lacks exact run/nonce health request' }
        return [ordered]@{ passed = $true; endpoint = $uri; status = 200; run_id = $RunId; attempt_nonce = $Nonce; record_count = $records.Count }
    } finally { $response.Dispose() }
}
function Invoke-SshBannerAndPin([string] $PinPath) {
    if ([string]::IsNullOrWhiteSpace($PinPath) -or -not (Test-Path -LiteralPath $PinPath -PathType Leaf)) { Fail 'SSH host-key pin file is missing' }
    $pin = Full $PinPath
    $pinHash = (Get-FileHash -LiteralPath $pin -Algorithm SHA256).Hash.ToLowerInvariant()
    $client = New-Object Net.Sockets.TcpClient; $client.ReceiveTimeout = 5000; $client.SendTimeout = 5000
    try {
        $client.Connect('127.0.0.1', $SshRelayPort); $stream = $client.GetStream(); $bytes = New-Object byte[] 512; $count = $stream.Read($bytes, 0, $bytes.Length)
        $banner = [Text.Encoding]::ASCII.GetString($bytes, 0, $count).Split("`n")[0].Trim("`r")
        if ($banner -notmatch '^SSH-2\.0-') { Fail 'SSH banner is not a production SSH banner' }
    } finally { $client.Dispose() }
    $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue; if ($null -eq $ssh) { Fail 'OpenSSH client is unavailable for host-key pin proof' }
    $sshArgs = '-vv -o BatchMode=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="' + $pin + '" -o ConnectTimeout=5 -p ' + $SshRelayPort + ' lab@127.0.0.1 -N'
    $startInfo = [Diagnostics.ProcessStartInfo]::new(); $startInfo.FileName = $ssh.Source; $startInfo.Arguments = $sshArgs; $startInfo.UseShellExecute = $false; $startInfo.CreateNoWindow = $true; $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $startInfo; [void]$process.Start()
    $timedOut = -not $process.WaitForExit(6000)
    if ($timedOut) { $process.Kill(); $process.WaitForExit() }
    $diagnostic = $process.StandardError.ReadToEnd()
    $pinLine = @(Get-Content -LiteralPath $pin | Where-Object { $_ -match '^\[127\.0\.0\.1\]:22222 ssh-ed25519 ' }) | Select-Object -First 1
    $keyscan = @(ssh-keyscan.exe -T 5 -p $SshRelayPort 127.0.0.1 2>$null | Where-Object { $_ -match '^\[127\.0\.0\.1\]:22222 ssh-ed25519 ' }) | Select-Object -First 1
    $pinFileBound = -not [string]::IsNullOrWhiteSpace($pinLine)
    $pinAccepted = $pinFileBound -and -not [string]::IsNullOrWhiteSpace($keyscan) -and (($pinLine -split '\s+')[2] -eq ($keyscan -split '\s+')[2])
    [ordered]@{ passed = ($pinAccepted -and ($process.ExitCode -eq 0 -or $process.ExitCode -eq 255 -or $timedOut)); banner = $banner; host_key_pin_sha256 = $pinHash; host_key_pin_accepted = $pinAccepted; host_key_pin_file_bound = $pinFileBound; endpoint = "127.0.0.1:$SshRelayPort"; exit_code = $process.ExitCode; timed_out = $timedOut; diagnostic = ($diagnostic -split "`r?`n" | Where-Object { $_ -match 'known and matches|REMOTE HOST|Permission denied|Server host key' }) }
}

Assert-Id $RunId 'run id'; Assert-Id $CaseId 'case id'; Assert-ExactGuid $VmId
$childPath = Assert-OwnedPath $ChildRecordPath 'child record'; $serverPath = Assert-OwnedPath $ServerRecordPath 'server record';
$child = Read-Json $childPath; $server = Read-Json $serverPath; Assert-ChildRecord $child; Assert-ServerRecord $server
if ($Action -eq 'plan') {
    [ordered]@{ schema = 1; action = 'plan'; run_id = $RunId; case_id = $CaseId; vm_id = $VmId.ToString('B'); parent_sha256 = [string]$child.parent_sha256; child_qmp = [string]$child.qmp_socket; child_qga = [string]$child.qga_socket; stop_event = $StopEventName; ssh = [ordered]@{ service_guid = $SshServiceGuid; host_port = $SshRelayPort; guest_port = $SshRelayPort; server_guest_port = $LinuxSshPort }; http = [ordered]@{ service_guid = $HttpServiceGuid; host_port = $HttpRelayPort; guest_port = $HttpRelayPort; path = $HttpPath }; host_network_mutation = $false; live = $false } | ConvertTo-Json -Depth 10 -Compress
    exit 0
}
if (-not $EnableLive) { Fail 'probe/smoke/stop require explicit live authorization' }
if ($Action -eq 'probe' -or $Action -eq 'smoke') {
    if ([string]::IsNullOrWhiteSpace($AttemptNonce)) { Fail 'probe requires an owned attempt nonce' }
    $sshResult = Invoke-SshBannerAndPin $HostKeyPinPath; $httpResult = Invoke-BoundedHttpNonce $AttemptNonce
    [ordered]@{ schema = 1; action = $Action; run_id = $RunId; case_id = $CaseId; vm_id = $VmId.ToString('B'); parent_sha256 = [string]$child.parent_sha256; child_process_pid = [int64]$child.process_pid; child_process_uuid = [string]$child.process_uuid; marker = [string]$child.marker; ssh = $sshResult; http = $httpResult; transport = 'AF_HYPERV-owned-relay'; host_network_mutation = $false; passed = ($sshResult.passed -and $httpResult.passed) } | ConvertTo-Json -Depth 10 -Compress
    exit 0
}
if ($Action -eq 'stop') { Fail 'stop is performed by the owned supervisor --stop interface; this adapter does not issue arbitrary process commands' }
