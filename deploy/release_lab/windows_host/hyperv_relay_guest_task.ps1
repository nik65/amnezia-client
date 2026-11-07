[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('start','stop','probe')] [string] $Action,
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [string] $CaseId,
    [ValidateSet('guest','host','guest-worker')] [string] $Mode = 'guest',
    [string] $SourceSha256,
    [string] $StopAttempt,
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

function Read-OwnedRelayRecord([string]$Path) {
    try{$item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop}catch{throw "relay record '$Path' unavailable: $($_.CategoryInfo.Category)/$($_.FullyQualifiedErrorId)"}
    if($item.PSIsContainer -or $item.Length -gt 65536 -or $item.Length -lt 1){throw 'relay record size/type differs'}
    $cursor=$item
    while($null-ne$cursor){if(($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'relay record traverses reparse point'};if($cursor-is[IO.FileInfo]){$cursor=$cursor.Directory}else{$cursor=$cursor.Parent}}
    $record=@{}
    $lines=@(Get-Content -LiteralPath $Path -TotalCount 129 -ErrorAction Stop)
    if($lines.Count-gt128){throw 'relay record line bound exceeded'}
    foreach($line in $lines){
        if($line.Length-gt4096){throw 'relay record line size exceeded'}
        if($line-notmatch '^([a-z_0-9]+)=(.*)$'){throw 'relay record wire differs'}
        $key=$Matches[1];$value=$Matches[2]
        if($record.ContainsKey($key)-and$key-ne'state'){throw 'duplicate relay identity field'}
        if($key-eq'state'-and$value-eq'failed'){throw 'relay failed terminal state'}
        $record[$key]=$value
    }
    return $record
}
function Test-OwnedRelayStopped([string]$Mode,[string]$Channel,[string]$Id,[string]$Case,[guid]$Vm,[string]$Hash,[string]$Lease,[string]$Receipt,[string]$Supervisor,[string]$Relay) {
    if($Mode-notin@('host','guest')-or$Channel-notin@('ssh','http')-or$Id-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'-or$Case-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'-or$Hash-notmatch'^[a-fA-F0-9]{64}$'-or$Vm-eq[guid]::Empty-or$Vm.ToString('B')-eq'{ffffffff-ffff-ffff-ffff-ffffffffffff}'){throw 'relay stop identity invalid'}
    $root=if($Mode-eq'host'){"C:\ProgramData\AmneziaReleaseLab\hyperv\runs\$Id\relay"}else{"C:\ProgramData\AmneziaLab\runs\$Id\windows-x64\$Case\relay"}
    $stem=if($Mode-eq'host'){"host-$Channel"}else{$Channel}
    if([IO.Path]::GetFullPath($Lease)-ine"$root\$stem.lease"-or[IO.Path]::GetFullPath($Receipt)-ine"$root\$stem.receipt"){throw 'relay stop paths differ'}
    if((Get-FileHash -LiteralPath $Relay -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$Hash.ToLowerInvariant()){throw 'relay binary hash differs'}
    $leaseRecord=Read-OwnedRelayRecord $Lease;$receiptRecord=Read-OwnedRelayRecord $Receipt
    $event="Local\AmneziaReleaseLabRelayStop_${Id}_${Case}"
    foreach($r in @($leaseRecord,$receiptRecord)){
        foreach($pair in @(@('schema','1'),@('run_id',$Id),@('case_id',$Case),@('vm_id',$Vm.ToString('B')),@('helper_sha256',$Hash.ToLowerInvariant()),@('stop_event',$event))){if(-not$r.ContainsKey($pair[0])-or$r[$pair[0]]-cne$pair[1]){throw 'relay lease/receipt identity differs'}}
    }
    $guid=if($Channel-eq'ssh'){'{5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}'}else{'{6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42}'}
    if($leaseRecord.state-cne'relay-authorized'-or$receiptRecord.mode-cne$Mode-or$receiptRecord.channel-cne$Channel-or$receiptRecord.service_guid-cne$guid-or$receiptRecord.state-notin@('running','stopped')){throw 'relay channel or terminal identity differs'}
    foreach($field in @('parent_pid','parent_start')){if($leaseRecord[$field]-notmatch'^[1-9][0-9]*$'-or$leaseRecord[$field]-cne$receiptRecord[$field]){throw 'relay parent binding differs'}}
    $absent=$true
    foreach($tuple in @(@('parent_pid','parent_start',$Supervisor),@('relay_pid','relay_start',$Relay))){
        $pidText=$receiptRecord[$tuple[0]];$startText=$receiptRecord[$tuple[1]]
        if($pidText-notmatch'^[1-9][0-9]*$'-or$startText-notmatch'^[1-9][0-9]*$'){throw 'relay PID/start invalid'}
        $number=[uint32]::Parse($pidText);$expectedStart=[uint64]::Parse($startText)
        $processes=@(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$number" -ErrorAction Stop)
        if($processes.Count-gt1){throw 'relay PID query ambiguous'}
        if($processes.Count-eq1){
            if($Mode-eq'guest'-and$processes[0].SessionId-ne0){throw 'guest relay process is outside SYSTEM session zero'}
            try{$process=Get-Process -Id $number -ErrorAction Stop}catch{
                # A relay can exit after CIM observed it. Only a genuine not-found
                # error plus a fresh successful empty CIM query proves that race.
                if($_.CategoryInfo.Category-ne[Management.Automation.ErrorCategory]::ObjectNotFound-or($_.FullyQualifiedErrorId-split',')[0]-ne'NoProcessFoundForGivenId'){throw}
                $fresh=@(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$number" -ErrorAction Stop)
                if($fresh.Count-ne0){throw 'relay PID remains present after process not-found'}
                continue
            }
            if([string]$processes[0].ExecutablePath-ine[IO.Path]::GetFullPath($tuple[2])-or[uint64]$process.StartTime.ToUniversalTime().ToFileTimeUtc()-ne$expectedStart){throw 'relay PID was reused or foreign'}
            $absent=$false
        }
    }
    return ($receiptRecord.state-ceq'stopped'-and$absent)
}
function Invoke-OwnedRelayStop([string]$Mode,[string]$Channel,[string]$Id,[string]$Case,[guid]$Vm,[string]$Hash,[string]$Lease,[string]$Receipt,[string]$Supervisor,[string]$Relay) {
    if(Test-OwnedRelayStopped $Mode $Channel $Id $Case $Vm $Hash $Lease $Receipt $Supervisor $Relay){return}
    $arguments=@('--stop','--run-id',$Id,'--case-id',$Case,'--ownership-file',$Lease)
    $options=@{FilePath=$Supervisor;ArgumentList=$arguments;WindowStyle='Hidden';Wait=$true;PassThru=$true}
    if($Mode-eq'host'){$options.Verb='RunAs'}
    $stop=Start-Process @options
    if($stop.ExitCode-notin@(0,70)){throw "owned relay stop failed with exit $($stop.ExitCode)"}
    for($attempt=0;$attempt-lt60;$attempt++){
        if(Test-OwnedRelayStopped $Mode $Channel $Id $Case $Vm $Hash $Lease $Receipt $Supervisor $Relay){return}
        Start-Sleep -Milliseconds 250
    }
    throw 'owned relay stopped receipt and PID absence were not proven'
}

function Write-RelayStopResult([string]$Path,[object]$Value) {
    $parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($Path)) -Force -ErrorAction Stop
    for($item=$parent;$null-ne$item;$item=$item.Parent){if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'stop result path traverses reparse point'}}
    if(Test-Path -LiteralPath $Path){throw 'stop result already exists'}
    $json=$Value|ConvertTo-Json -Compress
    if([Text.Encoding]::UTF8.GetByteCount($json)-gt8192){throw 'stop result exceeds bound'}
    $temporary=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    New-Item -ItemType File -Path $temporary -ErrorAction Stop|Out-Null
    $item=Get-Item -LiteralPath $temporary -Force -ErrorAction Stop
    if($item.PSIsContainer-or$item.Length-ne0-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'stop result temporary file identity differs'}
    Set-Content -LiteralPath $temporary -Encoding Byte -Value ([Text.Encoding]::UTF8.GetBytes($json)) -ErrorAction Stop
    Move-Item -LiteralPath $temporary -Destination $Path -ErrorAction Stop
}
function Invoke-GuestRelayStopWorker {
    if($SourceSha256-notmatch'^[a-fA-F0-9]{64}$'-or(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$SourceSha256.ToLowerInvariant()){Fail 'guest stop worker source hash differs'}
    $attempt=[guid]::NewGuid().ToString('N');$workerName="AmneziaReleaseLab-RelayStop-$attempt"
    $root="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay";$resultPath=Join-Path $root "$Channel.stop-$attempt.json"
    $literal={param([string]$v) "'"+$v.Replace("'","''")+"'"}
    $task=&$literal $PSCommandPath;$pin=&$literal $SourceSha256.ToLowerInvariant()
    $command="`$ErrorActionPreference='Stop';if((Get-FileHash -LiteralPath $task -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$pin){throw 'guest stop worker source hash differs'};& $task -Action stop -Mode guest-worker"
    foreach($pair in @(@('RunId',$RunId),@('CaseId',$CaseId),@('Channel',$Channel),@('VmId',$VmId.ToString('B')),@('SupervisorPath',$SupervisorPath),@('RelayPath',$RelayPath),@('OwnershipFile',$OwnershipFile),@('ReceiptPath',$ReceiptPath),@('HelperSha256',$HelperSha256),@('SourceSha256',$SourceSha256),@('StopAttempt',$attempt))){$command+=' -'+$pair[0]+' '+(&$literal ([string]$pair[1]))}
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command));$executable=Join-Path $PSHOME 'powershell.exe';$arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
    $action=New-ScheduledTaskAction -Execute $executable -Argument $arguments
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # On-demand only: no second timer trigger can create another worker.
    Register-ScheduledTask -TaskName $workerName -Action $action -Principal $principal -Description "Owned relay stop $RunId/$CaseId/$Channel/$attempt" -ErrorAction Stop|Out-Null
    Start-ScheduledTask -TaskName $workerName -ErrorAction Stop
    $ready=$false
    for($attemptIndex=0;$attemptIndex-lt120;$attemptIndex++){if(Test-Path -LiteralPath $resultPath -PathType Leaf){$ready=$true;break};Start-Sleep -Milliseconds 250}
    if(-not$ready){Fail 'SYSTEM relay stop worker did not produce its fresh result'}
    $item=Get-Item -LiteralPath $resultPath -Force -ErrorAction Stop
    if($item.PSIsContainer-or$item.Length-lt1-or$item.Length-gt8192-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){Fail 'SYSTEM relay stop result type or bound differs'}
    $answer=(Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)
    if($answer-isnot[pscustomobject]-or$answer.schema-ne1-or$answer.run_id-cne$RunId-or$answer.case_id-cne$CaseId-or$answer.channel-cne$Channel-or$answer.vm_id-cne$VmId.ToString('B')-or$answer.attempt-cne$attempt-or$answer.source_sha256-cne$SourceSha256.ToLowerInvariant()-or$answer.session_id-ne0-or$answer.stopped-isnot[bool]-or-not$answer.stopped){Fail 'SYSTEM relay stop worker result lacks exact stopped proof'}
    if(-not(Test-OwnedRelayStopped 'guest' $Channel $RunId $CaseId $VmId $HelperSha256 $OwnershipFile $ReceiptPath $SupervisorPath $RelayPath)){Fail 'SYSTEM relay worker result lacks independent stopped and PID absence proof'}
    $registered=Get-ScheduledTask -TaskName $workerName -ErrorAction Stop;$actions=@($registered.Actions)
    if($registered.TaskName-cne$workerName-or$actions.Count-ne1-or[string]$actions[0].Execute-ine$executable-or[string]$actions[0].Arguments-cne$arguments-or[string]$registered.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or[string]$registered.Principal.LogonType-ne'ServiceAccount'-or[string]$registered.Principal.RunLevel-ne'Highest'){Fail 'SYSTEM relay stop worker task identity differs'}
    Unregister-ScheduledTask -TaskName $workerName -Confirm:$false -ErrorAction Stop
}

function Get-RelayStopSessionId { return (Get-Process -Id $PID -ErrorAction Stop).SessionId }
if($Mode-eq'host'){
    if($Action-ne'stop'-or$SourceSha256-notmatch'^[a-fA-F0-9]{64}$'-or(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$SourceSha256.ToLowerInvariant()){Fail 'host relay stop task source/action binding differs'}
    Invoke-OwnedRelayStop 'host' $Channel $RunId $CaseId $VmId $HelperSha256 $OwnershipFile $ReceiptPath $SupervisorPath $RelayPath
    exit 0
}
if($Mode-eq'guest-worker'){
    if($Action-ne'stop'-or$StopAttempt-notmatch'^[0-9a-f]{32}$'-or$SourceSha256-notmatch'^[a-fA-F0-9]{64}$'-or(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$SourceSha256.ToLowerInvariant()){Fail 'SYSTEM relay stop source/action binding differs'}
    $sessionId=Get-RelayStopSessionId
    $result=[ordered]@{schema=1;run_id=$RunId;case_id=$CaseId;channel=$Channel;vm_id=$VmId.ToString('B');attempt=$StopAttempt;source_sha256=$SourceSha256.ToLowerInvariant();session_id=$sessionId;stopped=$false}
    $root="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay";$resultPath=Join-Path $root "$Channel.stop-$StopAttempt.json"
    try{
        if($sessionId-ne0){Fail 'SYSTEM relay stop worker is outside session zero'}
        Invoke-OwnedRelayStop 'guest' $Channel $RunId $CaseId $VmId $HelperSha256 $OwnershipFile $ReceiptPath $SupervisorPath $RelayPath
        $result.stopped=$true
    }catch{$result.error_type=$_.Exception.GetType().FullName;$message=[string]$_.Exception.Message;$result.error=$message.Substring(0,[Math]::Min(2048,$message.Length));Write-RelayStopResult $resultPath $result;throw}
    Write-RelayStopResult $resultPath $result
    exit 0
}
function Wait-OwnedGuestRelayReady([string]$ExpectedArguments) {
    $diagnosticPath=Join-Path (Split-Path -Parent $ReceiptPath) "startup-$Channel.json"
    $diagnostic=[ordered]@{run_id=$RunId;case_id=$CaseId;vm_id=$VmId.ToString('B');channel=$Channel;task=$TaskName;calling_session_id=[int](Get-Process -Id $PID -ErrorAction Stop).SessionId;ready=$false;observed_at='';task_state='';last_task_result=$null;records_present=$false;processes=@();error=''}
    try {
        for($attempt=0;$attempt-lt120;$attempt++) {
            $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
            $diagnostic.observed_at=[DateTime]::UtcNow.ToString('o');$diagnostic.task_state=[string]$task.State;$diagnostic.last_task_result=[long]$info.LastTaskResult
            $actions=@($task.Actions)
            if($task.TaskName-cne$TaskName-or$actions.Count-ne1-or[string]$actions[0].Execute-ine$SupervisorPath-or[string]$actions[0].Arguments-cne$ExpectedArguments-or[string]$task.Principal.UserId-notin@('SYSTEM','S-1-5-18')){throw 'guest relay startup scheduled task identity differs'}
            if([long]$info.LastTaskResult-notin@(0,267009,267011)){throw "guest relay startup task failed: $($info.LastTaskResult)"}
            $diagnostic.records_present=(Test-Path -LiteralPath $OwnershipFile -PathType Leaf)-and(Test-Path -LiteralPath $ReceiptPath -PathType Leaf)
            if($diagnostic.records_present) {
                [void](Test-OwnedRelayStopped 'guest' $Channel $RunId $CaseId $VmId $HelperSha256 $OwnershipFile $ReceiptPath $SupervisorPath $RelayPath)
                $receipt=Read-OwnedRelayRecord $ReceiptPath
                if($receipt.state-cne'running'){throw 'guest relay startup receipt is not running'}
                $processes=@()
                foreach($role in @('parent','relay')) {
                    $id=[int]$receipt[($role+'_pid')];$actual=@(Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction Stop)
                    if($actual.Count-ne1-or[int]$actual[0].SessionId-ne0){throw 'guest relay startup requires verified SYSTEM session zero helpers'}
                    $sid=Invoke-CimMethod -InputObject $actual[0] -MethodName GetOwnerSid -ErrorAction Stop
                    if($sid.ReturnValue-ne0-or[string]$sid.Sid-cne'S-1-5-18'){throw 'guest relay startup helper owner differs'}
                    $processes+=@{role=$role;pid=$id;session_id=[int]$actual[0].SessionId;owner_sid=[string]$sid.Sid;start_filetime=[string]$receipt[($role+'_start')];path=[string]$actual[0].ExecutablePath}
                }
                if([string]$task.State-cne'Running'){throw 'guest relay task is not running after helper readiness'}
                $diagnostic.processes=$processes;$diagnostic.ready=$true
                [IO.File]::WriteAllText($diagnosticPath,($diagnostic|ConvertTo-Json -Depth 8 -Compress),(New-Object Text.UTF8Encoding($false)))
                return $diagnostic
            }
            Start-Sleep -Milliseconds 250
        }
        throw 'guest relay startup timed out before owned lease/receipt readiness'
    } catch {
        $diagnostic.error=[string]$_.Exception.Message
        try{[IO.File]::WriteAllText($diagnosticPath,($diagnostic|ConvertTo-Json -Depth 8 -Compress),(New-Object Text.UTF8Encoding($false)))}catch{}
        throw
    }
}

if ($Action -eq 'start') {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Fail 'owned relay task already exists' }
    $arguments = "--relay-exe `"$RelayPath`" --mode guest --channel $Channel --vm-id $($VmId.ToString('B')) --run-id $RunId --case-id $CaseId --ownership-file `"$OwnershipFile`" --receipt-path `"$ReceiptPath`" --helper-sha256 $HelperSha256 --ready-timeout-ms 15000"
    $taskAction = New-ScheduledTaskAction -Execute $SupervisorPath -Argument $arguments
    # Start this owned helper only on demand; no delayed duplicate launch.
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Principal $taskPrincipal -Description "Owned Amnezia AF_HYPERV relay $RunId/$CaseId" | Out-Null
    Start-ScheduledTask -TaskName $TaskName | Out-Null
    $readiness=Wait-OwnedGuestRelayReady $arguments
    [ordered]@{ action = 'start'; task = $TaskName; run_id = $RunId; case_id = $CaseId; vm_id = $VmId.ToString('B'); stop_event = $StopEventName; ready=$true; readiness=$readiness; host_network_mutation = $false } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}
if ($Action -eq 'stop') {
    $existingTask=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if($null-ne$existingTask){
        $expectedArguments="--relay-exe `"$RelayPath`" --mode guest --channel $Channel --vm-id $($VmId.ToString('B')) --run-id $RunId --case-id $CaseId --ownership-file `"$OwnershipFile`" --receipt-path `"$ReceiptPath`" --helper-sha256 $HelperSha256 --ready-timeout-ms 15000"
        $actions=@($existingTask.Actions)
        if($existingTask.TaskName-cne$TaskName-or$actions.Count-ne1-or[string]$actions[0].Execute-ine$SupervisorPath-or[string]$actions[0].Arguments-cne$expectedArguments){Fail 'scheduled relay task identity differs'}
    }
    Invoke-GuestRelayStopWorker
    $last='state=stopped'
    if($null-ne$existingTask){Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop}
    [ordered]@{ action = 'stop'; task = $TaskName; run_id = $RunId; case_id = $CaseId; terminal_state = $last; host_network_mutation = $false } | ConvertTo-Json -Compress
    exit 0
}
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$receipt = if (Test-Path -LiteralPath $ReceiptPath) { Get-Content -LiteralPath $ReceiptPath | Select-Object -Last 1 } else { '' }
if ($null -eq $task -or $receipt -notin @('state=running','state=stopped','state=failed')) { Fail 'guest relay task/receipt readback is incomplete' }
[ordered]@{ action = 'probe'; task = $TaskName; task_state = [string]$task.State; run_id = $RunId; case_id = $CaseId; vm_id = $VmId.ToString('B'); terminal_state = $receipt; host_network_mutation = $false } | ConvertTo-Json -Compress
