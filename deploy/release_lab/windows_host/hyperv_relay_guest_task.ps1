[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('start','stop','probe')] [string] $Action,
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [string] $CaseId,
    [ValidateSet('ssh','http')] [string] $Channel = 'http',
    [Parameter(Mandatory = $true)] [guid] $VmId,
    [Parameter(Mandatory = $true)] [string] $SupervisorPath,
    [Parameter(Mandatory = $true)] [string] $RelayPath,
    [Parameter(Mandatory = $true)] [string] $OwnershipFile,
    [Parameter(Mandatory = $true)] [string] $ReceiptPath,
    [Parameter(Mandatory = $true)] [string] $HelperSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$TaskName = "AmneziaReleaseLab-Relay-${RunId}-${CaseId}-${Channel}"
$StopEventName = "Local\AmneziaReleaseLabRelayStop_${RunId}_${CaseId}"
function Fail([string] $Message) { throw "hyperv-relay-guest-task: $Message" }
function Assert-Id([string] $Value, [string] $Label) { if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail "$Label is invalid" } }
if ($VmId -eq [guid]::Empty -or $VmId.ToString('B') -eq '{ffffffff-ffff-ffff-ffff-ffffffffffff}') { Fail 'VM ID is not exact and owned' }
Assert-Id $RunId 'run id'; Assert-Id $CaseId 'case id'
if (-not (Test-Path -LiteralPath $SupervisorPath -PathType Leaf) -or -not (Test-Path -LiteralPath $RelayPath -PathType Leaf)) { Fail 'relay binaries are missing' }
if ($HelperSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'helper hash is invalid' }

if ($Action -eq 'start') {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Fail 'owned relay task already exists' }
    $arguments = "--relay-exe `"$RelayPath`" --mode guest --channel $Channel --vm-id $($VmId.ToString('B')) --run-id $RunId --case-id $CaseId --ownership-file `"$OwnershipFile`" --receipt-path `"$ReceiptPath`" --helper-sha256 $HelperSha256 --ready-timeout-ms 15000"
    $taskAction = New-ScheduledTaskAction -Execute $SupervisorPath -Argument $arguments
    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Description "Owned Amnezia AF_HYPERV relay $RunId/$CaseId" | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    [ordered]@{ action = 'start'; task = $TaskName; run_id = $RunId; case_id = $CaseId; vm_id = $VmId.ToString('B'); stop_event = $StopEventName; host_network_mutation = $false } | ConvertTo-Json -Compress
    exit 0
}
if ($Action -eq 'stop') {
    $stopArgs = "--stop --run-id $RunId --case-id $CaseId --ownership-file `"$OwnershipFile`""
    $stop = Start-Process -FilePath $SupervisorPath -ArgumentList $stopArgs -Wait -PassThru -WindowStyle Hidden
    if ($stop.ExitCode -ne 0) { Fail "owned relay stop failed with exit $($stop.ExitCode)" }
    $deadline = (Get-Date).AddSeconds(15)
    do { Start-Sleep -Milliseconds 250; $last = if (Test-Path -LiteralPath $ReceiptPath) { (Get-Content -LiteralPath $ReceiptPath | Select-Object -Last 1) } else { '' } } while ($last -notin @('state=stopped','state=failed') -and (Get-Date) -lt $deadline)
    if ($last -notin @('state=stopped','state=failed')) { Fail 'relay terminal receipt was not observed' }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    [ordered]@{ action = 'stop'; task = $TaskName; run_id = $RunId; case_id = $CaseId; terminal_state = $last; host_network_mutation = $false } | ConvertTo-Json -Compress
    exit 0
}
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$receipt = if (Test-Path -LiteralPath $ReceiptPath) { Get-Content -LiteralPath $ReceiptPath | Select-Object -Last 1 } else { '' }
if ($null -eq $task -or $receipt -notin @('state=running','state=stopped','state=failed')) { Fail 'guest relay task/receipt readback is incomplete' }
[ordered]@{ action = 'probe'; task = $TaskName; task_state = [string]$task.State; run_id = $RunId; case_id = $CaseId; vm_id = $VmId.ToString('B'); terminal_state = $receipt; host_network_mutation = $false } | ConvertTo-Json -Compress
