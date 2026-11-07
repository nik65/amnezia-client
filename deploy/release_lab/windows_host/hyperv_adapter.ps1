[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('plan','status','create-child','start','stop','probe','precondition','prepare-interactive','stage','run','collect','diagnose-bootstrap-root','reset','ui-observe','ui-confirm','export-ui','app-window','seed-profile','relays-start','relays-stop','publish','netstack-fixture','native-tests')]
    [string] $Action,
    [string] $RunId,
    [string] $CaseId = 'control',
    [ValidateSet('windows-x64')]
    [string] $Profile = 'windows-x64',
    [string] $ParentRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64',
    [string] $RunsRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\runs',
    [string] $FixtureManifestPath,
    [string] $FixtureManifestSha256,
    [string] $ArtifactPath,
    [string] $ArtifactSha256,
    [int64] $ArtifactSize = -1,
    [ValidateSet('baseline-thin','candidate-thin','baseline-outer','candidate-outer')]
    [string] $Stage,
    [ValidateSet('probe','reinstall','update','service-health','interactive-start','interactive-status','interactive-collect')]
    [string] $GuestAction,
    [string] $ExpectedSha256,
    [ValidateSet('baseline','candidate')]
    [string] $ExpectedArtifactRole,
    [string] $ExpectedVersion,
    [string] $BaselineVersion,
    [string] $CandidateVersion,
    [string] $RunnerPath,
    [string] $RunnerSha256,
    [string] $UiHelperPath,
    [string] $UiHelperSha256,
    [string] $LauncherPath,
    [string] $LauncherSha256,
    [string] $SeedHelperPath,
    [string] $SeedHelperSha256,
    [string] $SeedHost,
    [string] $SeedUser,
    [int] $SeedPort = -1,
    [string] $SeedFingerprint,
    [string] $AttemptNonce,
    [string] $ChildVmId,
    [string] $RelayHelperPath,
    [string] $RelaySupervisorPath,
    [string] $RelayGuestTaskPath,
    [string] $RelayGuestTaskSha256,
    [string] $RelayHelperSha256,
    [int] $ExpectedConsentPid = -1,
    [string] $ExpectedConsentStartTime,
    [int] $ExpectedConsentSessionId = -1,
    [string] $ExpectedArtifactSha256,
    [string] $ExpectedScreenshotSha256,
    [string] $ScreenshotGuestPath,
    [string] $TokenEvidencePath,
    [string] $NativeManifestPath,
    [string] $NativeManifestSha256,
    [string] $NativeHelperPath,
    [string] $NativeHelperSha256,
    [string] $NativeCapturePath,
    [string] $NativeCaptureSha256,
    [switch] $CredentialStdin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module Microsoft.PowerShell.Utility -Force -ErrorAction Stop

function New-UiCapturePaths([string] $GuestRoot, [string] $Phase) {
    if ($Phase -notin @('probe','reinstall','update','service-health','interactive-start','interactive-status','interactive-collect')) { throw 'capture phase is invalid' }
    $captureId = '{0}-{1}' -f $Phase,([Guid]::NewGuid().ToString('N'))
    return @{ evidence = (Join-Path $GuestRoot "ui-evidence-$captureId.json"); screenshot = (Join-Path $GuestRoot "ui-screenshot-$captureId.png") }
}
function Fail([string] $Message) { throw "hyperv-adapter: $Message" }
function Full([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Fail 'path is empty' }
    return [IO.Path]::GetFullPath($Path.TrimEnd('\'))
}
function Assert-Contained([string] $Path, [string] $Root, [string] $Label) {
    $full = Full $Path; $rootFull = Full $Root
    if ($full -ine $rootFull -and -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the owned root" }
    $cursor = New-Object IO.DirectoryInfo($full)
    while ($null -ne $cursor -and $cursor.FullName.Length -ge $rootFull.Length) {
        if (Test-Path -LiteralPath $cursor.FullName) {
            $item = Get-Item -LiteralPath $cursor.FullName -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label has a reparse-point ancestor" }
        }
        if ($cursor.FullName -ieq $rootFull) { break }
        $cursor = $cursor.Parent
    }
    return $full
}
function Assert-NoReparse([string] $Path, [string] $Label) {
    $full = Full $Path
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label is a reparse point" }
    $cursor = if ($item.PSIsContainer) { [IO.DirectoryInfo]$item.FullName } else { $item.Directory }
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label has a reparse-point ancestor" }
        $cursor = $cursor.Parent
    }
    return $item
}
function Assert-Directory([string] $Path, [string] $Label) {
    $full = Full $Path
    $allowed = Full 'C:\ProgramData\AmneziaReleaseLab\hyperv'
    if ($full -ine $allowed -and -not $full.StartsWith($allowed + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the Hyper-V lab root" }
    if (Test-Path -LiteralPath $full) {
        if (-not (Test-Path -LiteralPath $full -PathType Container)) { Fail "$Label is not a directory" }
        Assert-NoReparse $full $Label | Out-Null
    }
    return $full
}
function Sha([string] $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
function Test-HyperVOnState([object] $Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Enum] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) { return ([int64]$Value -eq 0) }
    return ([string]$Value -ieq 'On')
}
function Read-Json([string] $Path, [string] $Label) {
    Assert-NoReparse $Path $Label | Out-Null
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { Fail "$Label is invalid JSON" }
}
function Write-JsonNoClobber([string] $Path, [object] $Value) {
    if (Test-Path -LiteralPath $Path) { Fail "refusing to overwrite $Path" }
    $parent = Split-Path -Parent (Full $Path)
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Get-Parent([string] $Root) {
    $root = Assert-Directory $Root 'parent root'
    $markerPath = Join-Path $root '.owned-vm.json'
    $marker = Read-Json $markerPath 'sealed parent marker'
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or $marker.profile -ne 'windows-x64' -or $marker.sealed -ne $true -or $marker.state -ne 'sealed') { Fail 'parent marker is not a sealed Hyper-V windows-x64 baseline' }
    try { $parentVm = @(Get-VM -Id ([guid]$marker.vm_id) -ErrorAction Stop); if ($parentVm.Count -ne 1) { Fail 'parent VM ID did not resolve uniquely' } } catch { Fail 'sealed parent VM is unavailable' }
    if ([string]$parentVm[0].State -ne 'Off') { Fail 'sealed parent VM must remain Off; refusing to boot or mutate the golden' }
    $vhd = Assert-Contained ([string]$marker.vhdx) $root 'sealed parent VHDX'
    $vhdItem = Assert-NoReparse $vhd 'sealed parent VHDX'
    $current = Sha $vhd
    if ($current -ne ([string]$marker.vhdx_sha256).ToLowerInvariant()) { Fail 'sealed parent VHDX hash differs from marker' }
    $info = Get-VHD -Path $vhd -ErrorAction Stop
    if (-not [string]::IsNullOrWhiteSpace([string]$info.ParentPath) -or [int64]$info.Size -ne 137438953472) { Fail 'sealed parent VHDX is not self-contained 128 GiB' }
    return [ordered]@{ marker = $marker; vm = $parentVm[0]; vhdx = $vhd; sha256 = $current; size = [int64]$vhdItem.Length }
}
function ChildRoot([string] $Root, [string] $Id) {
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is invalid' }
    $runs = Assert-Directory $Root 'runs root'
    return Assert-Directory (Join-Path (Join-Path $runs $Id) 'windows-x64') 'child run root'
}
function Assert-CaseId([string] $Id) {
    if ($Id -notmatch '^(control|thin-clean|thin-upgrade|thin-reinstall|outer-clean|outer-upgrade|outer-reinstall|outer-interactive|publisher-clean)$') { Fail 'CaseId is not an allowlisted Hyper-V matrix case' }
    return $Id
}
function CaseRoot([string] $Root, [string] $Id, [string] $Case) {
    Assert-CaseId $Case | Out-Null
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is invalid' }
    $base = Join-Path (Join-Path (Join-Path (Assert-Directory $Root 'runs root') $Id) 'windows-x64') 'cases'
    return Assert-Directory (Join-Path $base $Case) 'case root'
}
function Expected-ChildName([string] $Id, [string] $Case) {
    $bytes = [Text.Encoding]::UTF8.GetBytes("$Id|$Case")
    $hash = ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes))).Replace('-','').ToLowerInvariant().Substring(0,12)
    $slug = ($Id -replace '[^A-Za-z0-9._-]','_'); if ($slug.Length -gt 32) { $slug = $slug.Substring(0,32) }
    $name = "AmneziaLab-$slug-$Case-$hash"; if ($name.Length -gt 80) { $name = $name.Substring(0,80) }
    return $name
}
function Read-Child([string] $Root, [string] $Id, [string] $ParentRoot, [string] $Case) {
    $childRoot = CaseRoot $Root $Id $Case
    $markerPath = Join-Path $childRoot '.owned-child.json'
    $marker = Read-Json $markerPath 'owned child marker'
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or $marker.profile -ne 'windows-x64' -or [string]$marker.run_id -ne $Id -or [string]$marker.case_id -ne $Case) { Fail 'owned child marker identity mismatch' }
    try { $vm = @(Get-VM -Id ([guid]$marker.vm_id) -ErrorAction Stop); if ($vm.Count -ne 1) { Fail 'owned child VM ID did not resolve uniquely' } } catch { Fail 'owned child VM is unavailable' }
    $parent = Get-Parent $ParentRoot
    if ([string]$marker.parent_sha256 -ne $parent.sha256 -or [string]$marker.parent_vhdx -ine $parent.vhdx -or [string]$marker.parent_vm_id -ne [string]$parent.vm.Id) { Fail 'owned child parent binding differs from sealed baseline' }
    $configuration = Verify-ChildConfig ([ordered]@{ root = $childRoot; marker = $marker; vm = $vm[0]; parent = $parent })
    return [ordered]@{ root = $childRoot; marker = $marker; vm = $vm[0]; parent = $parent; configuration = $configuration }
}
function Get-CredentialFromStdin {
    if (-not $CredentialStdin) { Fail 'PowerShell Direct actions require -CredentialStdin' }
    $plain = [Console]::In.ReadToEnd().TrimEnd("`r", "`n")
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -gt 512) { Fail 'runtime guest credential is missing or too long' }
    $secure = New-Object System.Security.SecureString
    foreach ($character in $plain.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return [PSCredential]::new('.\labadmin', $secure)
}
function Get-PlainCredential([PSCredential] $Credential) {
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
function New-Session([object] $Child) {
    $credential = Get-CredentialFromStdin
    return New-PSSession -VMId ([guid]$Child.vm.Id) -Credential $credential -ErrorAction Stop
}
function Get-MsvmKeyboardMetadata([string] $VmId) {
    $class = Get-CimClass -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction Stop
    $methodObjects = @($class.CimClassMethods)
    $methods = @($methodObjects | ForEach-Object { [string]$_.Name })
    $parameters = @($methodObjects | ForEach-Object { [ordered]@{ name=[string]$_.Name; parameters=@($_.Parameters | ForEach-Object { [string]$_.Name }) } })
    $instances = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction SilentlyContinue)
    return [ordered]@{ class_name='Msvm_Keyboard'; vm_id=$VmId; methods=$methods; method_parameters=$parameters; instance_count=$instances.Count; type_key_supported=($methods -contains 'TypeKey' -and $methods -contains 'PressKey' -and $methods -contains 'ReleaseKey') }
}
function Get-GuestConsentProof([object] $Child, [object] $Session) {
    $guestRoot="C:\ProgramData\AmneziaLab\runs\$($Child.marker.run_id)\windows-x64\$($Child.marker.case_id)"; $marker=Join-Path $guestRoot 'run-marker.txt'
    $expectedArtifact = $ExpectedArtifactSha256.ToLowerInvariant()
    $childVmId = [string]$Child.vm.Id
    return Invoke-Command -Session $Session -ScriptBlock {
        param($marker,$runId,$caseId,$vmId,$expectedPid,$expectedStart,$expectedSession,$expectedArtifact)
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'guest marker missing for UI observation' }
        $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${runId}:windows-x64" -or $lines -notcontains "case_id=$caseId" -or $lines -notcontains "vm_id=$vmId"){throw 'guest UI marker binding mismatch'}
        $requestPath=Join-Path (Split-Path -Parent $marker) 'pending-installer.json'
        $request=$null;$pendingText=$null
        try {
            if(-not(Test-Path -LiteralPath $requestPath -PathType Leaf)){throw 'guest pending installer request is missing'}
            $pendingItem=Get-Item -LiteralPath $requestPath -Force
            if($pendingItem.PSIsContainer-or($pendingItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or$pendingItem.Length-gt65536){throw 'guest pending installer request bounds/type differ'}
            $pendingText=Get-Content -LiteralPath $requestPath -Raw
            if($pendingText.Length-gt65536){throw 'guest pending installer request text exceeds bound'}
            $request=$pendingText|ConvertFrom-Json
            if([string]$request.state -notin @('waiting','running') -or [string]$request.run_id -ne $runId -or [string]$request.case_id -ne $caseId -or ([string]$request.artifact_sha256 -ne $expectedArtifact)){throw 'guest pending installer request is not bound to this artifact/case'}
        } catch {
            $pendingFailure=$_
            try {
                function Pending-Field($value,[string]$name,[int]$limit=128){
                    if($null-eq$value-or$null-eq$value.PSObject.Properties[$name]){return ''}
                    $text=[string]$value.PSObject.Properties[$name].Value
                    if($text.Length-gt$limit){return $text.Substring(0,$limit)};return $text
                }
                $selected=[ordered]@{}
                foreach($name in @('state','run_id','case_id','artifact_sha256','created_at','completed_at','launcher_pid','launcher_session_id','installer_pid','exit_code')){$selected[$name]=Pending-Field $request $name}
                $launch=$null;if($null-ne$request-and$request.PSObject.Properties['launch_error']){$launch=$request.launch_error}
                $selected['launch_error_type']=Pending-Field $launch 'error_type';$selected['launch_native_error_code']=Pending-Field $launch 'native_error_code';$selected['launch_hresult']=Pending-Field $launch 'hresult'
                $selected['launch_error_stage']=Pending-Field $launch 'stage'
                $selected['launch_error_message']=Pending-Field $launch 'message' 512
                $guard=[ordered]@{schema=1;kind='guest-pending-installer-guard';failure_type=$pendingFailure.Exception.GetType().FullName;state_ready=($selected.state-in@('waiting','running'));run_matches=($selected.run_id-eq$runId);case_matches=($selected.case_id-eq$caseId);artifact_matches=($selected.artifact_sha256-eq$expectedArtifact);observed=$selected;private_archive_only=$true}
                # ErrorDetails travels in the original PowerShell error record; lab.hyperv_call archives host stderr privately.
                # Never include paths, arbitrary JSON/error messages, argv or credentials.
                $bounded=$guard|ConvertTo-Json -Depth 4 -Compress
                # Private existing Start-Process text only. Escaping/UTF8 may
                # expand512chars; trim message in at most16 bounded steps.
                for($trim=0;$trim-lt16-and($bounded.Length-gt4096-or[Text.Encoding]::UTF8.GetByteCount($bounded)-gt4096)-and$selected.launch_error_message.Length-gt0;$trim++){
                    $selected.launch_error_message=$selected.launch_error_message.Substring(0,[Math]::Max(0,$selected.launch_error_message.Length-32))
                    $bounded=$guard|ConvertTo-Json -Depth 4 -Compress
                }
                if($bounded.Length-le4096-and[Text.Encoding]::UTF8.GetByteCount($bounded)-le4096){$pendingFailure.ErrorDetails=[Management.Automation.ErrorDetails]::new('guest pending installer guard failed; amnezia-pending-guard '+$bounded)}
            } catch { }
            throw $pendingFailure
        }
        $consent=@(Get-CimInstance Win32_Process -Filter "Name='consent.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 -and $_.ExecutablePath -and ([IO.Path]::GetFullPath([string]$_.ExecutablePath) -ieq (Join-Path $env:SystemRoot 'System32\consent.exe')) })
        if($consent.Count -ne 1){throw 'System32 consent.exe is not observed in the expected guest session'}
        $p=$consent[0]; $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        $sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
        if([string]$sid.Sid -ne 'S-1-5-18'){throw 'consent.exe is not running as SYSTEM'}
        if([int]$p.ProcessId -eq [int]$request.launcher_pid -or [int]$p.SessionId -ne [int]$request.launcher_session_id){throw 'consent.exe is not a distinct process bound to the pending installer session'}
        $launcher=@(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$request.launcher_pid)" -ErrorAction SilentlyContinue)
        if($launcher.Count -ne 1 -or [string]$launcher[0].CommandLine -notlike "*$([string]$request.launcher_path)*" -or [string]$launcher[0].CreationDate -ne [string]$request.launcher_start_time -or [int]$launcher[0].SessionId -ne [int]$request.launcher_session_id){throw 'limited launcher process is not bound to the pending installer request'}
        $launcherSid=Invoke-CimMethod -InputObject $launcher[0] -MethodName GetOwnerSid -ErrorAction Stop
        if([string]$launcherSid.Sid -eq 'S-1-5-18'){throw 'limited launcher unexpectedly runs as SYSTEM'}
        $installerPid=0; $installerPath=''
        if($request.PSObject.Properties['installer_pid'] -and [int]$request.installer_pid -gt 0){
            $installer=@(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$request.installer_pid)" -ErrorAction SilentlyContinue)
            if($installer.Count -ne 1 -or [IO.Path]::GetFullPath([string]$installer[0].ExecutablePath) -ine [IO.Path]::GetFullPath([string]$request.artifact_path)){throw 'installer process is not bound to the requested artifact'}
            $installerPid=[int]$installer[0].ProcessId; $installerPath=[string]$installer[0].ExecutablePath
        }
        if($expectedPid -ge 0 -and [int]$p.ProcessId -ne $expectedPid){throw 'consent PID changed'}
        if($expectedStart -and [string]$p.CreationDate -ne $expectedStart){throw 'consent start time changed'}
        if($expectedSession -ge 0 -and [int]$p.SessionId -ne $expectedSession){throw 'consent session changed'}
        [ordered]@{ run_id=$runId; case_id=$caseId; vm_id=$vmId; request_state=[string]$request.state; process_id=[int]$p.ProcessId; creation_time=[string]$p.CreationDate; session_id=[int]$p.SessionId; owner_user=[string]$owner.User; owner_sid=[string]$sid.Sid; consent_path=[string]$p.ExecutablePath; launcher_pid=[int]$request.launcher_pid; launcher_start_time=[string]$request.launcher_start_time; launcher_session_id=[int]$request.launcher_session_id; launcher_sid=[string]$launcherSid.Sid; installer_pid=$installerPid; installer_path=$installerPath; installer_start_time=if($request.PSObject.Properties['installer_start_time']){[string]$request.installer_start_time}else{''}; expected_consent=$true; interactive_token=$false }
    } -ArgumentList $marker,$Child.marker.run_id,$Child.marker.case_id,$childVmId,$ExpectedConsentPid,$ExpectedConsentStartTime,$ExpectedConsentSessionId,$expectedArtifact
}
function Get-OwnedConsentConsole([object] $Child, [object] $Session, [object] $Before) {
    if($AttemptNonce -notmatch '^[0-9a-f]{32}$'){Fail 'console capture requires the controller attempt nonce'}
    $vmId=[string]$Child.vm.Id
    $systems=@(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter "Name='$vmId'" -ErrorAction Stop)
    if($systems.Count-ne 1){Fail 'console VM binding is ambiguous'}
    $settings=@(Get-CimAssociatedInstance -InputObject $systems[0] -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData -ErrorAction Stop | Where-Object {[string]$_.VirtualSystemType-ceq 'Microsoft:Hyper-V:System:Realized' -and [string]$_.VirtualSystemIdentifier-ieq $vmId})
    $services=@(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_VirtualSystemManagementService -ErrorAction Stop)
    if($settings.Count-ne 1 -or $services.Count-ne 1){Fail 'current owned console settings/service are ambiguous'}
    $started=[DateTime]::UtcNow.ToString('o')
    $width=1280;$height=720
    $capture=Invoke-CimMethod -InputObject $services[0] -MethodName GetVirtualSystemThumbnailImage -Arguments @{TargetSystem=$settings[0];WidthPixels=[uint16]$width;HeightPixels=[uint16]$height} -ErrorAction Stop
    if([int]$capture.ReturnValue-ne 0){Fail "console thumbnail provider did not complete synchronously: $([int]$capture.ReturnValue)"}
    [byte[]]$providerRaw=$capture.ImageData
    $methodClass=Get-CimClass -Namespace 'root\virtualization\v2' -ClassName Msvm_VirtualSystemManagementService -ErrorAction Stop
    $imageParameter=$methodClass.CimClassMethods['GetVirtualSystemThumbnailImage'].Parameters['ImageData']
    $octetQualifier=$imageParameter.Qualifiers['OctetString']
    if($null-eq$octetQualifier-or$octetQualifier.Value-isnot[bool]-or$octetQualifier.Value-ne$true){Fail 'provider ImageData OctetString qualifier is not proven'}
    $expectedSize=$width*$height*2
    $payloadOffset=0
    if($providerRaw.Length-eq$expectedSize){[byte[]]$pixels=$providerRaw;$providerEncoding='raw-rgb565le'}
    elseif($providerRaw.Length-eq($expectedSize+4)){
        [uint32]$frameLength=([uint32]$providerRaw[0]-shl24)-bor([uint32]$providerRaw[1]-shl16)-bor([uint32]$providerRaw[2]-shl8)-bor[uint32]$providerRaw[3]
        if($frameLength-ne$providerRaw.Length){Fail 'CIM OctetString total-length prefix differs'}
        $payloadOffset=4;$providerEncoding='cim-octet-string-rgb565le'
        [byte[]]$pixels=New-Object byte[] $expectedSize
        [Array]::Copy($providerRaw,4,$pixels,0,$expectedSize)
    }else{Fail 'console thumbnail is not exact RGB565 or length-framed CIM OctetString'}
    $after=Get-GuestConsentProof $Child $Session
    foreach($key in @('run_id','case_id','vm_id','process_id','creation_time','session_id','owner_sid','consent_path','launcher_pid','launcher_start_time','launcher_session_id','launcher_sid')){
        if([string]$Before.$key-cne [string]$after.$key){Fail 'consent changed during console capture'}
    }
    $evidenceRoot=Join-Path $Child.root 'evidence';[void](Assert-Contained $evidenceRoot $Child.root 'console evidence')
    New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
    $path=Join-Path $evidenceRoot "consent-console-$AttemptNonce-$([Guid]::NewGuid().ToString('N')).rgb565"
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($pixels,0,$pixels.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $providerPath=Join-Path $evidenceRoot "consent-provider-$AttemptNonce-$([Guid]::NewGuid().ToString('N')).octets"
    $providerStream=[IO.File]::Open($providerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$providerStream.Write($providerRaw,0,$providerRaw.Length);$providerStream.Flush($true)}finally{$providerStream.Dispose()}
    return [ordered]@{provider_raw_file_name=[IO.Path]::GetFileName($providerPath);provider_raw_sha256=(Sha $providerPath);provider_raw_size=$providerRaw.Length;provider_encoding=$providerEncoding;provider_payload_offset=$payloadOffset;provider_octet_string_qualifier=$true;method='Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage';format='rgb565le';vm_id=$vmId;settings_vm_id=[string]$settings[0].VirtualSystemIdentifier;settings_virtual_system_type=[string]$settings[0].VirtualSystemType;artifact_sha256=$ExpectedArtifactSha256.ToLowerInvariant();width=$width;height=$height;host_path=$path;sha256=(Sha $path);size=$pixels.Length;started_at=$started;completed_at=[DateTime]::UtcNow.ToString('o');consent_after=$after}
}
function Assert-FixedChildMemory([object] $Memory) {
    if ($null -eq $Memory) { Fail 'child VM memory readback is missing' }
    foreach ($field in @('DynamicMemoryEnabled','Startup')) {
        if (-not $Memory.PSObject.Properties[$field] -or $null -eq $Memory.$field) { Fail 'child VM memory readback is incomplete' }
    }
    if ($Memory.DynamicMemoryEnabled -isnot [bool] -or $Memory.DynamicMemoryEnabled -or ($Memory.Startup -isnot [long] -and $Memory.Startup -isnot [uint64]) -or [int64]$Memory.Startup -ne 8589934592) { Fail 'child VM memory is not fixed at 8 GiB' }
}
function Verify-ChildConfig([object] $Child) {
    $vm = @(Get-VM -Id ([guid]$Child.vm.Id) -ErrorAction Stop)[0]
    if ([string]$vm.Id -ne [string]$Child.marker.vm_id -or [string]$vm.Name -ne [string]$Child.marker.vm_name -or [int]$vm.Generation -ne 2 -or [int]$vm.ProcessorCount -ne 4 -or [int64]$vm.MemoryStartup -ne 8589934592) { Fail 'child VM configuration readback mismatch' }
    # Cleanup retains every ownership check while accepting historical memory settings.
    $fixedMemory = $null
    if ($Action -notin @('reset','stop','relays-stop')) { $fixedMemory = Get-VMMemory -VM $vm -ErrorAction Stop; Assert-FixedChildMemory $fixedMemory }
    $expectedConfigurationLocation = Join-Path (Join-Path $Child.root 'vm') ([string]$vm.Name)
    if (-not $vm.PSObject.Properties['ConfigurationLocation'] -or [string]::IsNullOrWhiteSpace([string]$vm.ConfigurationLocation) -or [string]$vm.ConfigurationLocation.TrimEnd('\') -ine $expectedConfigurationLocation.TrimEnd('\')) { Fail "child VM configuration location is missing or differs from owned case root (actual='$([string]$vm.ConfigurationLocation)', expected='$expectedConfigurationLocation')" }
    if (-not $vm.PSObject.Properties['AutomaticCheckpointsEnabled']) { Fail 'child automatic checkpoints state is missing' }
    if ([bool]$vm.AutomaticCheckpointsEnabled) { Fail 'child automatic checkpoints are enabled' }
    $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop); if ($adapters.Count -ne 0) { Fail 'child VM has a network adapter' }
    $firmware = Get-VMFirmware -VM $vm -ErrorAction Stop
    if (-not (Test-HyperVOnState $firmware.SecureBoot) -or [string]$firmware.SecureBootTemplate -ne 'MicrosoftWindows') { Fail 'child Secure Boot readback mismatch' }
    $security = Get-VMSecurity -VM $vm -ErrorAction Stop
    if (-not $security.TpmEnabled) { Fail 'child vTPM is disabled' }
    $disk = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop); if ($disk.Count -ne 1) { Fail 'child must have exactly one disk' }
    $diskPath = Assert-Contained ([string]$disk[0].Path) $Child.root 'child VHDX'
    if ($diskPath -ine [string]$Child.marker.child_vhdx) { Fail 'child disk path differs from marker' }
    $info = Get-VHD -Path $diskPath -ErrorAction Stop
    if ([string]$info.ParentPath -ine [string]$Child.marker.parent_vhdx -or [string]$info.VhdType -ine 'Differencing') { Fail 'child VHDX parent/type readback mismatch' }
    $dvds = @(Get-VMDvdDrive -VM $vm -ErrorAction Stop); if ($dvds.Count -ne 0) { Fail 'child VM has attached DVD media' }
    $keyProtector = Get-VMKeyProtector -VM $vm -ErrorAction Stop
    $keyPresent = if ($keyProtector -is [byte[]]) { $keyProtector.Length -gt 0 } elseif ($keyProtector.PSObject.Properties['KeyProtector']) { $null -ne $keyProtector.KeyProtector } else { $false }
    if (-not $keyPresent) { Fail 'child vTPM key protector is missing' }
    $firstBoot = @($firmware.BootOrder | Where-Object { $null -ne $_.Device -and -not [string]::IsNullOrWhiteSpace([string]$_.Device.Id) }) | Select-Object -First 1
    if ($null -eq $firstBoot -or $null -eq $firstBoot.Device -or [string]$firstBoot.Device.Id -ne [string]$disk[0].Id) { Fail 'child first boot device is not the owned VHDX' }
    return [ordered]@{ vm_id = [string]$vm.Id; state = [string]$vm.State; generation = [int]$vm.Generation; processors = [int]$vm.ProcessorCount; memory_bytes = [int64]$vm.MemoryStartup; fixed_memory_readback = $(if ($null -ne $fixedMemory) { [ordered]@{ dynamic_memory_enabled = [bool]$fixedMemory.DynamicMemoryEnabled; startup_bytes = [int64]$fixedMemory.Startup } } else { $null }); network_adapter_count = $adapters.Count; secure_boot = (Test-HyperVOnState $firmware.SecureBoot); secure_boot_template = [string]$firmware.SecureBootTemplate; vtp_enabled = [bool]$security.TpmEnabled; key_protector_present = $keyPresent; dvd_count = $dvds.Count; first_boot_device_id = [string]$firstBoot.Device.Id; child_vhdx = $diskPath; parent_vhdx = [string]$info.ParentPath; vhd_type = [string]$info.VhdType }
}
function Get-ChildWorkerIdentity([object] $Vm) {
    $vmId = [string]$Vm.Id
    $systems = @(Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='$vmId'" -ErrorAction SilentlyContinue)
    if ($systems.Count -ne 1 -or [int]$systems[0].ProcessID -le 0) { Fail 'owned Hyper-V VM metadata did not expose one worker PID' }
    $workers = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$systems[0].ProcessID)" -ErrorAction SilentlyContinue)
    if ($workers.Count -ne 1 -or [string]$workers[0].Name -ine 'vmwp.exe') { Fail 'owned Hyper-V VM metadata worker PID is not vmwp.exe' }
    return [ordered]@{ process_pid=[int]$systems[0].ProcessID; process_uuid=$vmId; process_start_time=[string]$workers[0].CreationDate; source='Msvm_ComputerSystem.ProcessID' }
}
function Emit([object] $Value) { $Value | ConvertTo-Json -Depth 30 -Compress }
function Assert-Artifact([string] $Path, [string] $ExpectedSha, [int64] $ExpectedSize) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail 'artifact source is missing' }
    $item = Assert-NoReparse $Path 'artifact source'
    $sha = Sha $item.FullName
    if ($ExpectedSha -notmatch '^[0-9a-fA-F]{64}$' -or $sha -ne $ExpectedSha.ToLowerInvariant() -or ($ExpectedSize -ge 0 -and [int64]$item.Length -ne $ExpectedSize)) { Fail 'artifact source bytes differ from the planned digest/size' }
    return [ordered]@{ path = $item.FullName; sha256 = $sha; size = [int64]$item.Length }
}
function Invoke-Guest([object] $Child, [string] $GuestScript, [string] $GuestAction, [string] $ExpectedSha, [string] $ExpectedArtifactRole, [string] $ExpectedVersion, [string] $TokenEvidence, [string] $UiSource, [string] $LauncherSource) {
    $session = New-Session $Child
    try {
        $childRunId = [string]$Child.marker.run_id; $childCaseId = [string]$Child.marker.case_id; $childVmId = [guid]$Child.vm.Id
        $guestRoot = "C:\ProgramData\AmneziaLab\runs\$($Child.marker.run_id)\windows-x64\$($Child.marker.case_id)"
        $guestRunner = Join-Path $guestRoot 'release-lab.ps1'
        $guestArtifact = Join-Path $guestRoot 'current.exe'
        $guestReceipt = Join-Path $guestRoot 'receipt.json'
        $guestMarker = Join-Path $guestRoot 'run-marker.txt'
        $guestUi = Join-Path $guestRoot 'hyperv-ui-helper.ps1'
        $capturePaths = New-UiCapturePaths $guestRoot $GuestAction
        $guestEvidence = $capturePaths.evidence
        $guestScreenshot = $capturePaths.screenshot
        $guestLauncher = Join-Path $guestRoot 'hyperv-interactive-launcher.ps1'
        $guestLauncherArgument = if($GuestAction -in @('interactive-start','interactive-collect')){$guestLauncher}else{$null}
        if ([string]::IsNullOrWhiteSpace($GuestScript) -or -not (Test-Path -LiteralPath $GuestScript -PathType Leaf)) { Fail 'guest runner source is missing' }
        Copy-Item -LiteralPath $GuestScript -Destination $guestRunner -ToSession $session -Force
        if (-not [string]::IsNullOrWhiteSpace($UiSource)) { Copy-Item -LiteralPath $UiSource -Destination $guestUi -ToSession $session -Force }
        if (-not [string]::IsNullOrWhiteSpace($LauncherSource)) { Copy-Item -LiteralPath $LauncherSource -Destination $guestLauncher -ToSession $session -Force }
        $remote = Invoke-Command -Session $session -ScriptBlock {
            param($root, $runner, $uiHelper, $uiEvidence, $uiScreenshot, $action, $runId, $caseId, $expectedVersion, $expectedArtifactRole, $baselineVersion, $candidateVersion, $expectedSha, $receipt, $artifact, $marker, $tokenPath, $vmId, $launcher, $launcherHash)
            if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'guest runner is missing' }
            function Invoke-InteractiveUiCapture {
                param([string]$Helper,[string]$Evidence,[string]$Screenshot,[string]$Id,[string]$Case,[string]$Vm)
                $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1)
                if($explorer.Count -ne 1){throw 'interactive UI capture requires one logged-in Explorer session'}
                $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop
                $userId=if([string]::IsNullOrWhiteSpace([string]$owner.Domain)){[string]$owner.User}else{"$($owner.Domain)\$($owner.User)"}
                $taskName="AmneziaLab-UiCapture-$Id-$Case"; if($taskName.Length -gt 200){$taskName=$taskName.Substring(0,200)}
                if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'owned UI capture task already exists'}
                $args="-NoProfile -ExecutionPolicy Bypass -File `"$Helper`" -Action capture -RunId $Id -CaseId $Case -VmId $Vm -OutputPath `"$Evidence`" -ScreenshotPath `"$Screenshot`""
                $taskAction=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $args
                $taskPrincipal=New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
                $taskSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
                try {
                    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings -Description 'Owned release-lab interactive UI evidence capture' -ErrorAction Stop | Out-Null
                    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $deadline=(Get-Date).AddSeconds(30)
                    while((Get-Date)-lt $deadline -and -not(Test-Path -LiteralPath $Evidence -PathType Leaf)){Start-Sleep -Milliseconds 250}
                    if(-not(Test-Path -LiteralPath $Evidence -PathType Leaf)){throw 'interactive UI capture did not publish evidence before deadline'}
                    $text=[IO.File]::ReadAllText($Evidence)
                    if([string]::IsNullOrWhiteSpace($text)){throw 'interactive UI capture evidence is empty'}
                    return $text
                } finally {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                    if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'interactive UI capture task remained after cleanup'}
                }
            }
            if ($action -eq 'interactive-collect') { $tokenPath = $uiEvidence; [void](Invoke-InteractiveUiCapture $uiHelper $uiEvidence $uiScreenshot $runId $caseId $vmId) }
            $runnerArgs=@($action,'windows-x64','-RunId',$runId,'-CaseId',$caseId,'-GuestRoot',$root,'-ExpectedVersion',$expectedVersion,'-ExpectedArtifactRole',$expectedArtifactRole,'-BaselineVersion',$baselineVersion,'-CandidateVersion',$candidateVersion,'-ExpectedSha256',$expectedSha,'-ArtifactPath',$artifact,'-ReceiptPath',$receipt,'-Transport','hyperv-powershell-direct','-GuestMarkerPath',$marker)
            if(-not [string]::IsNullOrWhiteSpace($tokenPath)){ $runnerArgs += @('-TokenEvidencePath',$tokenPath) }
            if(-not [string]::IsNullOrWhiteSpace($launcher)){ $runnerArgs += @('-LauncherPath',$launcher,'-LauncherSha256',$launcherHash) }
            $supervisorPath=Join-Path $root 'runner-supervisor.json'; $stdoutPath=Join-Path $root 'runner.stdout.log'; $stderrPath=Join-Path $root 'runner.stderr.log'
            $nestedArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$runner)+$runnerArgs
            $runnerProcess=Start-Process -FilePath powershell.exe -ArgumentList $nestedArgs -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden
            [void]$runnerProcess.Handle
            $runnerStart=[string]$runnerProcess.StartTime.ToUniversalTime().ToString('o'); $supervisor=[ordered]@{schema=1;run_id=$runId;case_id=$caseId;action=$action;artifact_sha256=$expectedSha;pid=[int]$runnerProcess.Id;start_time=$runnerStart;state='running';started_at=[DateTime]::UtcNow.ToString('o')}; $tmp="$supervisorPath.tmp"; $supervisor|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $supervisorPath -Force
            $runnerExitCode=$null; $runnerDeadline=(Get-Date).AddSeconds(900)
            do {
                Start-Sleep -Seconds 5
                $stillRunning=$null; try{$stillRunning=Get-Process -Id ([int]$runnerProcess.Id) -ErrorAction Stop}catch{$stillRunning=$null}
                if($null -eq $stillRunning){$runnerProcess.Refresh();$rawRunnerExit=$runnerProcess.ExitCode;if($null-eq$rawRunnerExit-or$rawRunnerExit-isnot[int]){throw 'guest runner exit code unavailable or non-integer'};$runnerExitCode=$rawRunnerExit;break}
            } while((Get-Date)-lt $runnerDeadline)
            if($null -ne $stillRunning){$supervisor.state='timeout';$supervisor.completed_at=[DateTime]::UtcNow.ToString('o');$tmp="$supervisorPath.tmp";$supervisor|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $tmp -Encoding UTF8;Move-Item -LiteralPath $tmp -Destination $supervisorPath -Force;throw 'guest runner exceeded bounded 900 second supervision deadline'}
            $supervisor.state=if($runnerExitCode -eq 0){'completed'}else{'failed'};$supervisor.exit_code=$runnerExitCode;$supervisor.completed_at=[DateTime]::UtcNow.ToString('o');$supervisor.receipt_present=[bool](Test-Path -LiteralPath $receipt -PathType Leaf);$tmp="$supervisorPath.tmp";$supervisor|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $tmp -Encoding UTF8;Move-Item -LiteralPath $tmp -Destination $supervisorPath -Force
            if ($runnerExitCode -ne 0) { throw "guest runner exited with ${runnerExitCode}" }
            if ($action -eq 'interactive-start') { [void](Invoke-InteractiveUiCapture $uiHelper $uiEvidence $uiScreenshot $runId $caseId $vmId) }
            $receiptText = [IO.File]::ReadAllText($receipt)
            $markerText = [IO.File]::ReadAllText($marker)
            $guestHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            [ordered]@{ receipt = $receiptText; guest_marker = $markerText; guest_artifact_sha256 = $guestHash; guest_artifact_size = [int64](Get-Item -LiteralPath $artifact).Length; action = $action }
        } -ArgumentList $guestRoot, $guestRunner, $guestUi, $guestEvidence, $guestScreenshot, $GuestAction, $childRunId, $childCaseId, $ExpectedVersion, $ExpectedArtifactRole, $BaselineVersion, $CandidateVersion, $ExpectedSha, $guestReceipt, $guestArtifact, $guestMarker, $TokenEvidence, $childVmId, $guestLauncherArgument, $LauncherSha256
        return [ordered]@{ transport = 'hyperv-powershell-direct'; origin = 'guest'; injected = $false; vm_id = [string]$Child.vm.Id; parent_sha256 = [string]$Child.parent.sha256; readback = $remote }
    } finally { Remove-PSSession $session }
}

function Get-PublisherPrivateKey() {
    $encoded = [string]$env:AMNEZIA_LAB_PUBLISHER_KEY_B64
    if ([string]::IsNullOrWhiteSpace($encoded)) { Fail 'publisher key was not supplied through the runtime-only environment' }
    try { $bytes = [Convert]::FromBase64String($encoded); $value = [Text.Encoding]::UTF8.GetString($bytes) } catch { Fail 'publisher key environment value is not valid base64' }
    $env:AMNEZIA_LAB_PUBLISHER_KEY_B64 = $null
    if ($value -notmatch '-----BEGIN OPENSSH PRIVATE KEY-----' -or $value -notmatch '-----END OPENSSH PRIVATE KEY-----') { Fail 'publisher key is not an OpenSSH private key' }
    return $value
}

function Start-PublisherSeed([object] $Child) {
    if ([string]$Child.vm.State -ne 'Running') { Fail 'publisher profile seed requires a running child VM' }
    if ([string]::IsNullOrWhiteSpace($SeedHelperPath) -or -not (Test-Path -LiteralPath $SeedHelperPath -PathType Leaf)) { Fail 'publisher seed helper is missing' }
    if ($SeedHelperSha256 -notmatch '^[0-9a-fA-F]{64}$' -or (Sha $SeedHelperPath) -ne $SeedHelperSha256.ToLowerInvariant()) { Fail 'publisher seed helper hash differs from the planned helper' }
    if ([string]::IsNullOrWhiteSpace($AttemptNonce) -or $AttemptNonce -notmatch '^[0-9a-f]{48}$' -or [string]::IsNullOrWhiteSpace($SeedHost) -or $SeedHost -notmatch '^[0-9.]+$' -or [string]::IsNullOrWhiteSpace($SeedUser) -or $SeedUser -notmatch '^[A-Za-z0-9._-]{1,32}$' -or $SeedPort -lt 1 -or $SeedPort -gt 65535 -or $SeedFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') { Fail 'publisher seed endpoint or nonce is invalid' }
    $privateKey = Get-PublisherPrivateKey
    $session = New-Session $Child
    try {
        $root = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\publisher"
        $guestExe = Join-Path $root 'publisher_seed.exe'
        $dependencies=Invoke-Command -Session $session -ScriptBlock {
            param($path,$nonce,$id,$case,$vmid)
            $requiredNames=@('Qt6Core.dll','icuuc.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll','msvcp140_codecvt_ids.dll','vcruntime140.dll','vcruntime140_1.dll')
            function Assert-GuestSeedNoReparse([string]$value) {
                $full=[IO.Path]::GetFullPath($value);$cursor=$full
                while(-not[string]::IsNullOrEmpty($cursor)) {
                    if(Test-Path -LiteralPath $cursor) {
                        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
                        if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'guest seed path follows a reparse point'}
                    }
                    $parent=Split-Path -Parent $cursor
                    if($parent-eq$cursor){break};$cursor=$parent
                }
                return $full
            }
            if($id-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'-or$case-ne'publisher-clean'-or$nonce-cnotmatch'^[0-9a-f]{48}$'-or$vmid-notmatch'^[0-9a-fA-F-]{36}$'){throw 'guest seed identity invalid'}
            $caseRoot="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"
            $expected=Join-Path $caseRoot 'publisher'
            if([IO.Path]::GetFullPath($path)-ine[IO.Path]::GetFullPath($expected)){throw 'guest seed destination escaped owned case'}
            [void](Assert-GuestSeedNoReparse $caseRoot)
            $marker=Join-Path $caseRoot 'run-marker.txt';[void](Assert-GuestSeedNoReparse $marker)
            $markerItem=Get-Item -LiteralPath $marker -Force -ErrorAction Stop
            if($markerItem.PSIsContainer-or$markerItem.Length-gt4096){throw 'guest seed marker invalid'}
            $lines=@(Get-Content -LiteralPath $marker -ErrorAction Stop)
            if($lines-notcontains"amnezia-release-lab:${id}:windows-x64"-or$lines-notcontains'backend=hyperv'-or$lines-notcontains"case_id=$case"-or$lines-notcontains"vm_id=$vmid"){throw 'guest seed marker binding differs'}
            [void](Assert-GuestSeedNoReparse $path)
            if(-not(Test-Path -LiteralPath $path -PathType Container)){New-Item -ItemType Directory -Path $path -ErrorAction Stop|Out-Null}
            $noncePath=Join-Path $path 'attempt-nonce.txt';[void](Assert-GuestSeedNoReparse $noncePath)
            if(Test-Path -LiteralPath $noncePath) {
                $nonceItem=Get-Item -LiteralPath $noncePath -Force -ErrorAction Stop
                if($nonceItem.PSIsContainer-or$nonceItem.Length-gt128-or[string](Get-Content -LiteralPath $noncePath -Raw -ErrorAction Stop).Trim()-cne$nonce){throw 'guest seed attempt nonce differs'}
            } else {New-Item -ItemType File -Path $noncePath -Value $nonce -ErrorAction Stop|Out-Null}
            $installedRoot='C:\Program Files\AmneziaVPN';[void](Assert-GuestSeedNoReparse $installedRoot)
            $sources=@()
            foreach($name in $requiredNames) {
                $source=Join-Path $installedRoot $name;[void](Assert-GuestSeedNoReparse $source)
                $item=Get-Item -LiteralPath $source -Force -ErrorAction Stop
                if($item.PSIsContainer-or$item.Length-le0-or$item.Length-gt67108864){throw "guest seed dependency missing/invalid: $name"}
                $sources+=@{name=$name;source=$source;target=(Join-Path $path $name);sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();size=[int64]$item.Length}
            }
            foreach($record in $sources) {
                [void](Assert-GuestSeedNoReparse $record.target)
                if(Test-Path -LiteralPath $record.target) {
                    if((Get-FileHash -LiteralPath $record.target -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$record.sha256){throw 'guest seed dependency destination differs'}
                } else {Copy-Item -LiteralPath $record.source -Destination $record.target -ErrorAction Stop|Out-Null}
                if((Get-FileHash -LiteralPath $record.source -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$record.sha256-or(Get-FileHash -LiteralPath $record.target -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$record.sha256-or(Get-Item -LiteralPath $record.target -ErrorAction Stop).Length-ne$record.size){throw 'guest seed dependency copy readback differs'}
            }
            [ordered]@{run_id=$id;case_id=$case;vm_id=$vmid;attempt_nonce=$nonce;source_root=$installedRoot;seed_root=$path;files=$sources;origin='guest';host_installed_files_read=$false}
        } -ArgumentList $root,$AttemptNonce,$RunId,$CaseId,([string]$Child.vm.Id)
        if($dependencies.run_id-ne$RunId-or$dependencies.case_id-ne$CaseId-or$dependencies.vm_id-ne([string]$Child.vm.Id)-or$dependencies.attempt_nonce-cne$AttemptNonce-or$dependencies.origin-ne'guest'-or$dependencies.host_installed_files_read-ne$false-or@($dependencies.files).Count-ne9){Fail 'guest seed dependencies lack bound readback'}
        Copy-Item -LiteralPath $SeedHelperPath -Destination $guestExe -ToSession $session -Force
        $result = Invoke-Command -Session $session -ScriptBlock {
            param($exe,$work,$hostName,$user,$port,$fingerprint,$key,$id,$case,$vmid,$nonce,$helperSha)
            $caseRoot="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"
            if([IO.Path]::GetFullPath($work)-ine[IO.Path]::GetFullPath((Join-Path $caseRoot 'publisher'))-or[IO.Path]::GetFullPath($exe)-ine[IO.Path]::GetFullPath((Join-Path $work 'publisher_seed.exe'))){throw 'guest seed executable path escaped owned case'}
            $lines=@(Get-Content -LiteralPath (Join-Path $caseRoot 'run-marker.txt') -ErrorAction Stop)
            if($lines-notcontains"amnezia-release-lab:${id}:windows-x64"-or$lines-notcontains'backend=hyperv'-or$lines-notcontains"case_id=$case"-or$lines-notcontains"vm_id=$vmid"){throw 'guest seed launch marker differs'}
            if([string](Get-Content -LiteralPath (Join-Path $work 'attempt-nonce.txt') -Raw -ErrorAction Stop).Trim()-cne$nonce){throw 'guest seed launch nonce differs'}
            if(((Get-Item -LiteralPath $exe -Force -ErrorAction Stop).Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or(Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$helperSha){throw 'guest seed helper bytes/reparse differ'}
            $psi = [Diagnostics.ProcessStartInfo]::new(); $psi.FileName = $exe; $psi.WorkingDirectory = $work; $psi.Arguments = "$hostName $user $port $fingerprint"; $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi; if (-not $process.Start()) { throw 'publisher seed helper did not start' }; $process.StandardInput.Write($key); $process.StandardInput.Close(); if (-not $process.WaitForExit(120000)) { try { $process.Kill() } catch {} ; throw 'publisher seed helper exceeded the bounded timeout' }
            [ordered]@{ exit_code=[int]$process.ExitCode; stdout=$process.StandardOutput.ReadToEnd(); stderr=$process.StandardError.ReadToEnd() }
        } -ArgumentList $guestExe,$root,$SeedHost,$SeedUser,$SeedPort,$SeedFingerprint,$privateKey,$RunId,$CaseId,([string]$Child.vm.Id),$AttemptNonce,$SeedHelperSha256
        if ([int]$result.exit_code -ne 0) { Fail "publisher seed helper exited with $($result.exit_code): $($result.stderr)" }
        return [ordered]@{ action='seed-profile'; passed=$true; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$Child.vm.Id; seed=$result; dependencies=$dependencies }
    } finally { Remove-PSSession $session }
}

function Register-RelayServices([string] $RelayRootPath) {
    $script = Join-Path $PSScriptRoot 'hyperv_socket_relay.ps1'; if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { Fail 'relay registry helper is missing' }
    $args = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$script,'-Action','register','-RelayRoot',$RelayRootPath,'-RunId',$RunId)
    $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Fail "relay registry registration failed with exit $($proc.ExitCode)" }
    try { $json = & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action validate -RelayRoot $RelayRootPath -RunId $RunId | Out-String; return ($json | ConvertFrom-Json) } catch { Fail 'relay registry registration readback was invalid' }
}

function Unregister-RelayServices([string] $RelayRootPath) {
    $script = Join-Path $PSScriptRoot 'hyperv_socket_relay.ps1'
    $args = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$script,'-Action','unregister','-RelayRoot',$RelayRootPath,'-RunId',$RunId)
    $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Fail "relay registry unregistration failed with exit $($proc.ExitCode)" }
    try { $json = & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action validate -RelayRoot $RelayRootPath -RunId $RunId | Out-String; return ($json | ConvertFrom-Json) } catch { Fail 'relay registry unregistration readback was invalid' }
}

function Wait-RelayReceipt([string] $Path) {
    $deadline = (Get-Date).AddSeconds(20); $last = ''
    do { if (Test-Path -LiteralPath $Path -PathType Leaf) { $last = [string](Get-Content -LiteralPath $Path | Select-Object -Last 1); if ($last -eq 'state=running') { return $true } }; Start-Sleep -Milliseconds 250 } while ((Get-Date) -lt $deadline)
    return $false
}

function Stage-OwnedGuestRelayDependencies([object]$Session,[string]$Root,[string]$VmId) {
    $result=Invoke-Command -Session $Session -ScriptBlock {
        param($root,$id,$case,$vm)
        function Assert-RelayDependencyPath([string]$path) {
            $full=[IO.Path]::GetFullPath($path);$cursor=$full
            while($cursor){if(Test-Path -LiteralPath $cursor){$item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'relay dependency traverses reparse point'}};$parent=Split-Path -Parent $cursor;if($parent-eq$cursor){break};$cursor=$parent}
            return $full
        }
        $expected="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case\relay"
        if([IO.Path]::GetFullPath($root)-ine$expected){throw 'relay dependency root differs'}
        [void](Assert-RelayDependencyPath $root)
        $lines=@(Get-Content -LiteralPath (Join-Path (Split-Path -Parent $root) 'run-marker.txt') -ErrorAction Stop)
        if($lines-notcontains"amnezia-release-lab:${id}:windows-x64"-or$lines-notcontains'backend=hyperv'-or$lines-notcontains"case_id=$case"-or$lines-notcontains"vm_id=$vm"){throw 'relay dependency marker differs'}
        [void](New-Item -ItemType Directory -Path $root -Force)
        # The SYSTEM helper loads these DLLs from this directory. Do not inherit
        # writable permissions from ProgramData into its executable search path.
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544')){
            $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop
        $files=@()
        foreach($name in @('MSVCP140.dll','VCRUNTIME140.dll','VCRUNTIME140_1.dll')) {
            $source=Join-Path 'C:\Program Files\AmneziaVPN' $name;$target=Join-Path $root $name
            [void](Assert-RelayDependencyPath $source);[void](Assert-RelayDependencyPath $target)
            $item=Get-Item -LiteralPath $source -Force -ErrorAction Stop
            if($item.PSIsContainer-or$item.Length-le0-or$item.Length-gt16777216){throw 'relay dependency source invalid'}
            $hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();$size=[int64]$item.Length
            if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$hash){throw 'relay dependency destination differs'}}else{Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop|Out-Null}
            [void](Assert-RelayDependencyPath $source);[void](Assert-RelayDependencyPath $target)
            if((Get-Item -LiteralPath $source -ErrorAction Stop).Length-ne$size-or(Get-Item -LiteralPath $target -ErrorAction Stop).Length-ne$size-or(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$hash-or(Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$hash){throw 'relay dependency copy readback differs'}
            $files+=@{name=$name;source=$source;path=$target;sha256=$hash;size=$size}
        }
        [ordered]@{run_id=$id;case_id=$case;vm_id=$vm;origin='guest';source_root='C:\Program Files\AmneziaVPN';root=$root;host_installed_files_read=$false;files=$files}
    } -ArgumentList $Root,$RunId,$CaseId,$VmId
    if($result.run_id-cne$RunId-or$result.case_id-cne$CaseId-or$result.vm_id-cne$VmId-or$result.origin-cne'guest'-or$result.host_installed_files_read-ne$false-or@($result.files).Count-ne3){throw 'relay dependency bound guest readback missing'}
    return $result
}

function Start-Relays([object] $Child) {
    if ([string]$Child.vm.State -ne 'Running') { Fail 'relay startup requires a running child VM' }
    if ($Child.vm.Id.ToString() -ne $Child.marker.vm_id) { Fail 'relay child VM ID differs from the owned marker' }
    if ([string]::IsNullOrWhiteSpace($ChildVmId) -or $ChildVmId -ine [string]$Child.vm.Id -or $AttemptNonce -notmatch '^[0-9a-f]{48}$') { Fail 'relay startup request is not bound to the owned child VM ID/nonce' }
    foreach ($value in @($RelayHelperPath,$RelaySupervisorPath,$RelayGuestTaskPath)) { if ([string]::IsNullOrWhiteSpace($value) -or -not (Test-Path -LiteralPath $value -PathType Leaf)) { Fail 'relay source path is missing' } }
    if ($RelayHelperSha256 -notmatch '^[0-9a-fA-F]{64}$' -or (Sha $RelayHelperPath) -ne $RelayHelperSha256.ToLowerInvariant()) { Fail 'relay helper hash differs from the frozen bytes' }
    $hostRoot = Join-Path (Join-Path 'C:\ProgramData\AmneziaReleaseLab\hyperv\runs' $RunId) 'relay'; New-Item -ItemType Directory -Force -Path $hostRoot | Out-Null
    $registry = Register-RelayServices $hostRoot
    $session = New-Session $Child
    $guestRoot = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay"; $guestRelay = Join-Path $guestRoot 'relay.exe'; $guestSupervisor = Join-Path $guestRoot 'supervisor.exe'; $guestTask = Join-Path $guestRoot 'guest-task.ps1'
    try {
        $dependencies=Stage-OwnedGuestRelayDependencies $session $guestRoot ([string]$Child.vm.Id)
        Copy-Item -LiteralPath $RelayHelperPath -Destination $guestRelay -ToSession $session -Force; Copy-Item -LiteralPath $RelaySupervisorPath -Destination $guestSupervisor -ToSession $session -Force; Copy-Item -LiteralPath $RelayGuestTaskPath -Destination $guestTask -ToSession $session -Force
        $guest = @(); foreach ($channel in @('ssh','http')) {
            $lease = Join-Path $guestRoot "$channel.lease"; $receipt = Join-Path $guestRoot "$channel.receipt"
            $ready=Invoke-Command -Session $session -ScriptBlock {
                param($task,$ch,$id,$case,$vm,$sup,$relay,$leasePath,$receiptPath,$hash)
                $previous=$ErrorActionPreference;$ErrorActionPreference='Continue'
                try{$wire=@(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $task -Action start -RunId $id -CaseId $case -Channel $ch -VmId $vm -SupervisorPath $sup -RelayPath $relay -OwnershipFile $leasePath -ReceiptPath $receiptPath -HelperSha256 $hash 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$previous}
                if($code-ne0){$diagnosticPath=Join-Path (Split-Path -Parent $receiptPath) "startup-$ch.json";$detail='';if(Test-Path -LiteralPath $diagnosticPath -PathType Leaf){$item=Get-Item -LiteralPath $diagnosticPath;if($item.Length-le32768){$detail=[IO.File]::ReadAllText($diagnosticPath)}};throw "guest relay startup exit $code; diagnostic=$detail"}
                $text=($wire|ForEach-Object{[string]$_})-join"`n";$answer=$text|ConvertFrom-Json -ErrorAction Stop
                if($answer-is[array]-or$answer.action-cne'start'-or$answer.run_id-cne$id-or$answer.case_id-cne$case-or$answer.vm_id-cne([guid]$vm).ToString('B')-or$answer.ready-ne$true-or$answer.readiness.ready-ne$true){throw 'guest relay startup proof differs'}
                return $answer
            } -ArgumentList $guestTask,$channel,$RunId,$CaseId,$Child.vm.Id,$guestSupervisor,$guestRelay,$lease,$receipt,$RelayHelperSha256
            if($ready.run_id-cne$RunId-or$ready.case_id-cne$CaseId-or$ready.vm_id-cne$Child.vm.Id.ToString('B')-or$ready.ready-ne$true-or$ready.readiness.channel-cne$channel){Fail 'guest relay readiness missing'}
            $guest+=,$ready
        }
    } finally { Remove-PSSession $session }
    $hostRelays = @(); foreach ($channel in @('ssh','http')) {
        $lease = Join-Path $hostRoot "host-$channel.lease"; $receipt = Join-Path $hostRoot "host-$channel.receipt"; $args = @('--relay-exe',$RelayHelperPath,'--mode','host','--channel',$channel,'--vm-id',$Child.vm.Id.ToString('B'),'--run-id',$RunId,'--case-id',$CaseId,'--ownership-file',$lease,'--receipt-path',$receipt,'--helper-sha256',$RelayHelperSha256,'--ready-timeout-ms','15000')
        $process = Start-Process -FilePath $RelaySupervisorPath -Verb RunAs -ArgumentList $args -WindowStyle Hidden -PassThru
        if (-not (Wait-RelayReceipt $receipt)) { Fail "host $channel relay did not become ready" }
        $hostRelays += [ordered]@{ channel=$channel; pid=[int]$process.Id; lease=$lease; receipt=$receipt; running=(-not $process.HasExited) }
    }
    [ordered]@{ action='relays-start'; passed=$true; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; run_id=$RunId; case_id=$CaseId; vm_id=[string]$Child.vm.Id; registry=$registry; guest=$guest; dependencies=$dependencies; host=$hostRelays; host_network_mutation=$false }
}

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

function Invoke-ElevatedOwnedRelayStop([string]$Channel,[guid]$Vm,[string]$Lease,[string]$Receipt) {
    if($RelayGuestTaskSha256-notmatch'^[a-fA-F0-9]{64}$'-or(Sha $RelayGuestTaskPath)-cne$RelayGuestTaskSha256.ToLowerInvariant()){throw 'elevated relay task source hash differs'}
    # Encode only exact, individually quoted literal values. Elevated code verifies
    # the task bytes again before executing the same strict owned-stop proof.
    $literal={param([string]$Value) "'"+$Value.Replace("'","''")+"'"}
    $task=&$literal $RelayGuestTaskPath;$pin=&$literal $RelayGuestTaskSha256.ToLowerInvariant()
    $command="`$ErrorActionPreference='Stop';if((Get-FileHash -LiteralPath $task -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()-cne$pin){throw 'elevated relay task source hash differs'};& $task -Action stop -Mode host"
    foreach($pair in @(@('RunId',$RunId),@('CaseId',$CaseId),@('Channel',$Channel),@('VmId',$Vm.ToString('B')),@('SupervisorPath',$RelaySupervisorPath),@('RelayPath',$RelayHelperPath),@('OwnershipFile',$Lease),@('ReceiptPath',$Receipt),@('HelperSha256',$RelayHelperSha256),@('SourceSha256',$RelayGuestTaskSha256))){$command+=' -'+$pair[0]+' '+(&$literal ([string]$pair[1]))}
    $command+=';exit $LASTEXITCODE'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $stop=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -WindowStyle Hidden -Wait -PassThru
    if($stop.ExitCode-ne0){throw "elevated owned relay stop failed with exit $($stop.ExitCode)"}
    if(-not(Test-OwnedRelayStopped 'host' $Channel $RunId $CaseId $Vm $RelayHelperSha256 $Lease $Receipt $RelaySupervisorPath $RelayHelperPath)){throw 'elevated relay stop lacks independent stopped and PID absence proof'}
}

function Stop-Relays([object] $Child) {
    $errors = @()
    $hostRoot = Join-Path (Join-Path (Join-Path 'C:\ProgramData\AmneziaReleaseLab\hyperv' 'runs') $RunId) 'relay'
    $guestRoot = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path 'C:\ProgramData\AmneziaLab' 'runs') $RunId) 'windows-x64') $CaseId) 'relay'
    $guestTask = Join-Path $guestRoot 'guest-task.ps1'; $guestStopped = $true; $hostStopped = $true
    if ([string]$Child.vm.State -eq 'Running') { $session = $null; try { $session = New-Session $Child; foreach ($channel in @('ssh','http')) { $lease=Join-Path $guestRoot "$channel.lease"; $receipt=Join-Path $guestRoot "$channel.receipt"; try { $answer=Invoke-Command -Session $session -ScriptBlock { param($task,$ch,$id,$case,$vm,$sup,$relay,$leasePath,$receiptPath,$hash,$taskHash); if (-not (Test-Path -LiteralPath $task -PathType Leaf)) { throw 'guest relay task is missing' }
            $raw=& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $task -Action stop -RunId $id -CaseId $case -Channel $ch -VmId $vm -SupervisorPath $sup -RelayPath $relay -OwnershipFile $leasePath -ReceiptPath $receiptPath -HelperSha256 $hash -SourceSha256 $taskHash
            $nativeExit=$LASTEXITCODE
            if($nativeExit-ne0){throw "guest relay stop task exited with $nativeExit"}
            $wire=([string[]]@($raw))-join"`n"
            if([string]::IsNullOrWhiteSpace($wire)-or[Text.Encoding]::UTF8.GetByteCount($wire)-gt65536-or-not$wire.TrimStart().StartsWith('{')-or-not$wire.TrimEnd().EndsWith('}')){throw 'guest relay stop response is not a bounded JSON object'}
            try{$answer=$wire|ConvertFrom-Json -ErrorAction Stop}catch{throw 'guest relay stop response is malformed JSON'}
            if($null-eq$answer-or$answer-is[Array]-or$answer-isnot[pscustomobject]){throw 'guest relay stop response object is missing'}
            $fields=@($answer.PSObject.Properties.Name)
            foreach($field in @('action','task','run_id','case_id','terminal_state','host_network_mutation')){if($fields-notcontains$field){throw 'guest relay stop response fields are incomplete'}}
            $expectedTask="AmneziaReleaseLab-Relay-${id}-${case}-${ch}"
            if($ch-notin@('ssh','http')-or$answer.action-isnot[string]-or$answer.action-cne'stop'-or$answer.run_id-isnot[string]-or$answer.run_id-cne$id-or$answer.case_id-isnot[string]-or$answer.case_id-cne$case-or$answer.task-isnot[string]-or$answer.task-cne$expectedTask){throw 'guest relay stop response action/run/case/task/channel binding differs'}
            if($answer.terminal_state-isnot[string]-or$answer.terminal_state-cne'state=stopped'-or$answer.host_network_mutation-isnot[bool]-or$answer.host_network_mutation-ne$false){throw 'guest relay stop response lacks safe stopped state'}
            return $answer } -ArgumentList $guestTask,$channel,$RunId,$CaseId,$Child.vm.Id,(Join-Path $guestRoot 'supervisor.exe'),(Join-Path $guestRoot 'relay.exe'),$lease,$receipt,$RelayHelperSha256,$RelayGuestTaskSha256; if ([string]$answer.terminal_state -ne 'state=stopped') { $guestStopped=$false } } catch { $guestStopped=$false; $errors += "guest ${channel}: $($_.Exception.Message)" } } } catch { $guestStopped=$false; $errors += "guest session: $($_.Exception.Message)" } finally { if ($null -ne $session) { Remove-PSSession $session -ErrorAction SilentlyContinue } } }
    foreach ($channel in @('ssh','http')) { $lease=Join-Path $hostRoot "host-$channel.lease"; if (Test-Path -LiteralPath $lease -PathType Leaf) { try { Invoke-ElevatedOwnedRelayStop $channel $Child.vm.Id $lease (Join-Path $hostRoot "host-$channel.receipt") } catch { $hostStopped=$false; $errors += "host ${channel}: $($_.Exception.Message)" } } }
    $registryStopped = $false
    if ($guestStopped -and $hostStopped) {
        try { [void](Unregister-RelayServices $hostRoot); $registryStopped=$true } catch { $errors += "registry: $($_.Exception.Message)" }
    } else {
        $errors += 'relay registry ownership retained because one or more relays did not stop'
    }
    if ($errors.Count -gt 0) { Fail ($errors -join '; ') }
    [ordered]@{ action='relays-stop'; passed=$true; relays_stopped=($guestStopped -and $hostStopped); relay_registry_unregistered=$registryStopped; host_network_mutation=$false; transport='hyperv-powershell-direct'; origin='guest'; injected=$false }
}

if ($Action -eq 'plan') {
    $parent = Get-Parent $ParentRoot
    Emit ([ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; transport = 'hyperv-powershell-direct'; ready = $true; cases = @('thin-clean','thin-upgrade','thin-reinstall','outer-clean','outer-upgrade','outer-reinstall','outer-interactive','publisher-clean'); parent_vm_id = [string]$parent.vm.Id; parent_state = [string]$parent.vm.State; parent_vhdx = $parent.vhdx; parent_sha256 = $parent.sha256; child_root = (Full (Join-Path $RunsRoot 'RUN_ID\windows-x64\cases\CASE_ID')); host_network_mutation = $false; release_passed = $false; product_verified = $false })
    exit 0
}
if ($Action -eq 'create-child') {
    Assert-CaseId $CaseId | Out-Null
    $parent = Get-Parent $ParentRoot; $root = CaseRoot $RunsRoot $RunId $CaseId
    if ((Test-Path -LiteralPath $root -PathType Container) -and (@(Get-ChildItem -LiteralPath $root -Force).Count -gt 0)) { Fail 'child root already exists and is non-empty' }
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'disk'),(Join-Path $root 'vm'),(Join-Path $root 'staging') | Out-Null
    $disk = Join-Path $root 'disk\child.vhdx'; $vmPath = Join-Path $root 'vm'
    $nameBytes=[Text.Encoding]::UTF8.GetBytes("$RunId|$CaseId"); $nameHash=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($nameBytes))).Replace('-','').ToLowerInvariant().Substring(0,12)
    $runSlug=($RunId -replace '[^A-Za-z0-9._-]','_'); if($runSlug.Length -gt 32){$runSlug=$runSlug.Substring(0,32)}
    $name = "AmneziaLab-$runSlug-$CaseId-$nameHash"
    if ($name.Length -gt 80) { $name = $name.Substring(0,80) }
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) { Fail 'child VM name already exists' }
    $vm=$null; $intentPath=Join-Path $root '.creation-intent.json'
    try {
    $intent=[ordered]@{schema=1; backend='hyperv'; profile='windows-x64'; run_id=$RunId; case_id=$CaseId; vm_id=''; vm_name=$name; child_vhdx=$disk; run_root=$root; parent_vhdx=$parent.vhdx; parent_sha256=$parent.sha256; state='creation-intent'; created_at=[DateTime]::UtcNow.ToString('o')}
    Write-JsonNoClobber $intentPath $intent
    New-VHD -Path $disk -ParentPath $parent.vhdx -Differencing -ErrorAction Stop | Out-Null
    $vm = New-VM -Name $name -Generation 2 -MemoryStartupBytes 8GB -VHDPath $disk -Path $vmPath -ErrorAction Stop
    $intent.vm_id=[string]$vm.Id; $intent.state='vm-created'; $intent.updated_at=[DateTime]::UtcNow.ToString('o')
    $intent | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $intentPath -Encoding UTF8
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 8GB -ErrorAction Stop
    Set-VMProcessor -VM $vm -Count 4
    Set-VM -VM $vm -AutomaticCheckpointsEnabled:$false
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
    foreach ($adapter in @(Get-VMNetworkAdapter -VM $vm)) { Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -Confirm:$false }
    foreach ($dvd in @(Get-VMDvdDrive -VM $vm)) { Remove-VMDvdDrive -VMDvdDrive $dvd -Confirm:$false }
    $ownedDiskDrive = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
    if ($ownedDiskDrive.Count -ne 1) { Fail 'new child VM did not expose exactly one owned VHDX' }
    Set-VMFirmware -VM $vm -FirstBootDevice $ownedDiskDrive[0]
    $parentAfter = Get-Parent $ParentRoot
    if ($parentAfter.sha256 -ne $parent.sha256 -or $parentAfter.vhdx -ine $parent.vhdx -or [string]$parentAfter.vm.Id -ne [string]$parent.vm.Id) { Fail 'sealed parent changed during child creation' }
    $marker = [ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; run_id = $RunId; case_id = $CaseId; vm_id = [string]$vm.Id; vm_name = $name; run_root = $root; child_vhdx = $disk; parent_vhdx = $parent.vhdx; parent_sha256 = $parentAfter.sha256; parent_sha256_before = $parent.sha256; parent_sha256_after = $parentAfter.sha256; parent_vm_id = [string]$parentAfter.vm.Id; transport = 'hyperv-powershell-direct'; state = 'created'; created_at = [DateTime]::UtcNow.ToString('o') }
    Write-JsonNoClobber (Join-Path $root '.owned-child.json') $marker
    Remove-Item -LiteralPath $intentPath -Force
    Emit ([ordered]@{ action = 'create-child'; child = $marker; parent_readback = [ordered]@{ before_sha256=$parent.sha256; after_sha256=$parentAfter.sha256; before_vm_id=[string]$parent.vm.Id; after_vm_id=[string]$parentAfter.vm.Id; before_vhdx=$parent.vhdx; after_vhdx=$parentAfter.vhdx }; configuration = (Verify-ChildConfig ([ordered]@{ root=$root; marker=[pscustomobject]$marker; vm=$vm; parent=$parentAfter })) })
    exit 0
    } catch {
        $original=$_.Exception.Message; $cleanup=@()
        if($null -ne $vm){try{Remove-VM -VM $vm -Force -Confirm:$false}catch{$cleanup += "Remove-VM: $($_.Exception.Message)"}}
        if(Test-Path -LiteralPath $disk -PathType Leaf){try{Remove-Item -LiteralPath $disk -Force}catch{$cleanup += "Remove child VHDX: $($_.Exception.Message)"}}
        if(Test-Path -LiteralPath $vmPath -PathType Container){try{Remove-Item -LiteralPath $vmPath -Recurse -Force}catch{$cleanup += "Remove child VM state: $($_.Exception.Message)"}}
        foreach($ownedDir in @((Join-Path $root 'disk'),(Join-Path $root 'staging'))){if(Test-Path -LiteralPath $ownedDir -PathType Container){try{Remove-Item -LiteralPath $ownedDir -Recurse -Force}catch{$cleanup += "Remove child directory: $($_.Exception.Message)"}}}
        if($cleanup.Count -eq 0 -and (Test-Path -LiteralPath $intentPath -PathType Leaf)){try{Remove-Item -LiteralPath $intentPath -Force}catch{$cleanup += "Remove creation intent: $($_.Exception.Message)"}}
        $markerPath = Join-Path $root '.owned-child.json'; if($cleanup.Count -eq 0 -and (Test-Path -LiteralPath $markerPath -PathType Leaf)){try{Remove-Item -LiteralPath $markerPath -Force}catch{$cleanup += "Remove owned child marker: $($_.Exception.Message)"}}
        $remaining=@(); if(Test-Path -LiteralPath $root -PathType Container){$remaining=@(Get-ChildItem -LiteralPath $root -Force | Select-Object -ExpandProperty Name)}
        if($cleanup.Count -gt 0 -or $remaining.Count -gt 0){$details=@($cleanup + @("remaining=$($remaining -join ',')")); Fail "$original; creation cleanup incomplete; preserve owned recovery path ${root}: $($details -join '; ')"}
        if(Test-Path -LiteralPath $root -PathType Container){Remove-Item -LiteralPath $root -Force}
        throw
    }
}
$child = $null
if ($Action -eq 'reset') {
    try { $child = Read-Child $RunsRoot $RunId $ParentRoot $CaseId }
    catch {
        $orphanRoot = CaseRoot $RunsRoot $RunId $CaseId
        $expectedName = Expected-ChildName $RunId $CaseId
        $nameLookupErrors = @()
        # Get-VM -Name rejects some long historical owned names as an invalid
        # parameter before it can return ObjectNotFound.  Enumerate and compare
        # exactly so absence recovery remains read-only and fail-closed.
        $namedVm = @(Get-VM -ErrorAction SilentlyContinue -ErrorVariable nameLookupErrors | Where-Object { $_.Name -ceq $expectedName })
        if (@($nameLookupErrors | Where-Object { [string]$_.FullyQualifiedErrorId -notmatch 'ObjectNotFound' -and [string]$_.Exception.Message -notmatch '(?i)did not find|not found' }).Count -gt 0) { throw $nameLookupErrors[0] }
        if (-not (Test-Path -LiteralPath $orphanRoot -PathType Container) -and $namedVm.Count -eq 0) {
            $orphanParent = Get-Parent $ParentRoot
            $orphanParentAfter = Get-Parent $ParentRoot
            Emit ([ordered]@{ action='reset'; run_id=$RunId; case_id=$CaseId; removed_child=$true; absence_proof=[ordered]@{ case_root_absent=$true; expected_vm_name=$expectedName; expected_vm_absent=$true }; parent_sha256_before=$orphanParent.sha256; parent_sha256_after=$orphanParentAfter.sha256; release_passed=$false }); exit 0
        }
        $intentPath = Join-Path $orphanRoot '.creation-intent.json'
        if ((Test-Path -LiteralPath $intentPath -PathType Leaf) -and -not (Test-Path -LiteralPath (Join-Path $orphanRoot '.owned-child.json') -PathType Leaf)) {
            $intent = Read-Json $intentPath 'creation intent'
            if ($intent.schema -ne 1 -or $intent.backend -ne 'hyperv' -or $intent.profile -ne 'windows-x64' -or [string]$intent.run_id -ne $RunId -or [string]$intent.case_id -ne $CaseId -or [string]$intent.vm_name -ne $expectedName -or [string]$intent.state -notin @('creation-intent','vm-created')) { throw 'creation intent identity mismatch' }
            $intentVmErrors=@(); $intentVm=@()
            if (-not [string]::IsNullOrWhiteSpace([string]$intent.vm_id)) { $intentVm=@(Get-VM -Id ([guid]$intent.vm_id) -ErrorAction SilentlyContinue -ErrorVariable intentVmErrors) }
            if (@($intentVmErrors | Where-Object { [string]$_.FullyQualifiedErrorId -notmatch 'ObjectNotFound' -and [string]$_.Exception.Message -notmatch '(?i)did not find|not found' }).Count -gt 0) { throw $intentVmErrors[0] }
            if ($intentVm.Count -ne 0 -or $namedVm.Count -ne 0) { throw 'creation intent still resolves to a VM; refusing absence cleanup' }
            Assert-NoReparse $orphanRoot 'creation intent root' | Out-Null
            foreach ($entry in @(Get-ChildItem -LiteralPath $orphanRoot -Force)) {
                if ($entry.Name -notin @('.creation-intent.json','disk','vm','staging')) { throw "creation intent root contains unexpected entry: $($entry.Name)" }
                Assert-NoReparse $entry.FullName 'creation intent resource' | Out-Null
            }
            $intentParent = Get-Parent $ParentRoot
            Remove-Item -LiteralPath $orphanRoot -Recurse -Force
            $intentParentAfter = Get-Parent $ParentRoot
            if ($intentParent.sha256 -ne $intentParentAfter.sha256) { throw 'sealed parent changed during creation-intent recovery' }
            Emit ([ordered]@{ action='reset'; run_id=$RunId; case_id=$CaseId; removed_child=$true; absence_proof=[ordered]@{ creation_intent_recovered=$true; expected_vm_name=$expectedName; expected_vm_absent=$true }; parent_sha256_before=$intentParent.sha256; parent_sha256_after=$intentParentAfter.sha256; release_passed=$false }); exit 0
        }
        # A failed create can leave only its owned marker after Hyper-V has
        # already removed the VM/disk. Recover that exact orphan through the
        # normal reset path; never infer ownership from an arbitrary root.
        $orphanMarkerPath = Join-Path $orphanRoot '.owned-child.json'
        if (-not (Test-Path -LiteralPath $orphanMarkerPath -PathType Leaf)) { throw }
        $orphan = Read-Json $orphanMarkerPath 'orphan child marker'
        if ($orphan.schema -ne 1 -or $orphan.backend -ne 'hyperv' -or $orphan.profile -ne 'windows-x64' -or [string]$orphan.run_id -ne $RunId -or [string]$orphan.case_id -ne $CaseId) { throw }
        $orphanVmError=@(); $orphanVm = @(Get-VM -Id ([guid]$orphan.vm_id) -ErrorAction SilentlyContinue -ErrorVariable orphanVmError)
        if(@($orphanVmError | Where-Object { [string]$_.FullyQualifiedErrorId -notmatch 'ObjectNotFound' -and [string]$_.Exception.Message -notmatch '(?i)did not find|not found' }).Count -gt 0){ throw $orphanVmError[0] }
        if ($orphanVm.Count -ne 0) { Fail 'orphan marker still resolves to a VM; refusing recovery deletion' }
        $orphanParent = Get-Parent $ParentRoot
        $orphanEntries = @(Get-ChildItem -LiteralPath $orphanRoot -Force | Select-Object -ExpandProperty Name)
        if (@($orphanEntries | Where-Object { $_ -ne '.owned-child.json' }).Count -ne 0) { Fail 'orphan child root contains resources; refusing recovery deletion' }
        Remove-Item -LiteralPath $orphanMarkerPath -Force
        Remove-Item -LiteralPath $orphanRoot -Force
        $orphanParentAfter = Get-Parent $ParentRoot
        if ($orphanParent.sha256 -ne $orphanParentAfter.sha256) { Fail 'sealed parent changed during orphan recovery reset' }
        Emit ([ordered]@{ action='reset'; run_id=$RunId; case_id=$CaseId; removed_child=$true; orphan_recovered=$true; parent_sha256_before=$orphanParent.sha256; parent_sha256_after=$orphanParentAfter.sha256; release_passed=$false }); exit 0
    }
}
# Definitions only. The tracked Hyper-V adapter must explicitly dispatch this
# fixed action after Read-Child verifies actual VM/disk/parent/NICnone ownership.
function Invoke-OwnedNetstackFixture {
 param($Child,[string]$RunId,[string]$CaseId,[string]$ManifestPath,[string]$ManifestSha256,[string]$ExpectedArtifactSha256)
 if([string]$Child.vm.State-ne 'Running' -or [string]$Child.marker.run_id-cne $RunId -or [string]$Child.marker.case_id-cne $CaseId -or [string]$Child.marker.vm_id-cne [string]$Child.vm.Id){throw 'fixture requires actual owned running child'}
 if((Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()-cne $ManifestSha256){throw 'fixture manifest changed'}
 $manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
 if($manifest.schema-ne 1 -or $manifest.candidate_artifact_sha256-cne $ExpectedArtifactSha256){throw 'fixture candidate binding mismatch'}
 $names=[ordered]@{helper='fixture.exe';observer='product_observer.ps1';profile='profile-template.json';expected_routes='expected-routes.json';routes='routes.json';config='config.json';observer_plan='observer-plan.json';limited_runner='limited_interactive_runner.ps1';limited_controller='limited_interactive_controller.ps1';operator_capture='BoundedOperatorCapture.cs'}
 if(@(Compare-Object @($names.Keys|Sort-Object) @($manifest.files.PSObject.Properties.Name|Sort-Object)).Count-ne 0){throw 'fixture exact file set differs'}
 foreach($key in $names.Keys){$r=$manifest.files.$key;Assert-NoReparse $r.path 'fixture source'|Out-Null;if((Get-Item -LiteralPath $r.path).Length-ne $r.size -or (Get-FileHash -LiteralPath $r.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne $r.sha256){throw 'fixture source bytes changed'}}
 $config=Get-Content -LiteralPath $manifest.files.config.path -Raw|ConvertFrom-Json
 $plan=Get-Content -LiteralPath $manifest.files.observer_plan.path -Raw|ConvertFrom-Json
 $vmid=[string]$Child.vm.Id
 if($config.run_id-cne $RunId -or $config.case_id-cne $CaseId -or $config.vm_id-cne $vmid -or $config.nonce-notmatch '^[0-9a-f]{48}$' -or $config.ttl_seconds-lt 120 -or $config.ttl_seconds-gt 300){throw 'fixture config ownership mismatch'}
 if($plan.run_id-cne $RunId -or $plan.case_id-cne $CaseId -or $plan.vm_id-cne $vmid -or $plan.nonce-cne $config.nonce -or $plan.task_token-notmatch '^[0-9a-f]{48}$' -or $plan.installed_exe_sha256-cne $manifest.installed_exe_sha256){throw 'fixture observer ownership mismatch'}
 $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\netstack-fixture"
 if($config.marker-cne "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\run-marker.txt" -or $config.routes-cne "$guestRoot\routes.json"){throw 'fixture canonical guest paths differ'}
 $session=New-Session $Child
 try {
  Invoke-Command -Session $session -ScriptBlock {
   param($root,$id,$case,$vm)
# This descriptor factory has no filesystem/process/network side effects.
function New-FixtureSecurityDescriptor([string]$UserSid,[ValidateSet('Directory','File','Output')][string]$Kind){
 $directory=$Kind-ne'File'
 $acl=if($directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 $inherit=if($directory){'ContainerInherit,ObjectInherit'}else{'None'}
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',$inherit,'None','Allow')))
 }
 $rights=if($Kind-eq'Output'){'Modify'}else{'ReadAndExecute'}
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($UserSid)),$rights,$inherit,'None','Allow')))
 # Suppress implicit owner WRITE_DAC even if a later high-created telemetry
 # file inherits a labadmin owner SID. Admin/SYSTEM explicit Full remains.
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-3-4')),'ReadPermissions',$inherit,'None','Allow')))
 return $acl
}
function Set-OwnedFixtureAcl([string]$Path,[string]$UserSid,[ValidateSet('Directory','File','Output')][string]$Kind){
 $item=Get-Item -LiteralPath $Path -Force
 if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or($Kind-eq'File')-eq[bool]$item.PSIsContainer){throw 'fixture ACL target type/reparse differs'}
 Set-Acl -LiteralPath $item.FullName -AclObject (New-FixtureSecurityDescriptor $UserSid $Kind)
}
function Assert-FixtureAncestorPaths([string]$Path){
 $cursor=[IO.Path]::GetFullPath($Path)
 while($true){
  $item=Get-Item -LiteralPath $cursor -Force
  if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'fixture ancestor redirected'}
  $parent=[IO.Directory]::GetParent($cursor);if($null-eq$parent){break};$cursor=$parent.FullName
 }
}
function Protect-OwnedFixtureNamespace([string]$Root,[string]$RunId,[string]$CaseId,[string]$VmId,[string]$UserSid){
 $base='C:\ProgramData\AmneziaLab'
 $expected="$base\runs\$RunId\windows-x64\$CaseId\netstack-fixture"
 if([IO.Path]::GetFullPath($Root)-ine$expected-or$RunId-notmatch'^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$'-or$CaseId-notin@('outer-clean','outer-upgrade')-or$VmId-notmatch'^[a-fA-F0-9-]{36}$'){throw 'owned fixture namespace differs'}
 $caseRoot=Split-Path -Parent $expected
 Assert-FixtureAncestorPaths $caseRoot
 $marker=Join-Path $caseRoot 'run-marker.txt';$item=Get-Item -LiteralPath $marker -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'fixture marker redirected'}
 $lines=@(Get-Content -LiteralPath $marker)
 if($lines-notcontains"amnezia-release-lab:${RunId}:windows-x64"-or$lines-notcontains"vm_id=$VmId"-or$lines-notcontains"case_id=$CaseId"){throw 'fixture marker does not authorize ACL scope'}
 # Only the existing required lab namespace components in this proven owned
 # disposable guest. Never mutate ProgramData,drive root or installed app ACLs.
 foreach($directory in @($base,"$base\runs","$base\runs\$RunId","$base\runs\$RunId\windows-x64",$caseRoot)){
  Set-OwnedFixtureAcl $directory $UserSid 'Directory'
 }
 Set-OwnedFixtureAcl $marker $UserSid 'File'
}

   if(Test-Path -LiteralPath $root){throw 'fixture attempt root already exists'}
   $user=Get-LocalUser -Name labadmin;$sid=$user.SID.Value
   Protect-OwnedFixtureNamespace $root $id $case $vm $sid
   [void](New-Item -ItemType Directory -Path $root)
   Set-OwnedFixtureAcl $root $sid 'Directory'
  } -ArgumentList $guestRoot,$RunId,$CaseId,$vmid|Out-Null
  foreach($key in $names.Keys){Copy-Item -LiteralPath $manifest.files.$key.path -Destination (Join-Path $guestRoot $names[$key]) -ToSession $session -ErrorAction Stop}
  $result=Invoke-Command -Session $session -ScriptBlock {
   param($root,$files,$mapping,$id,$case,$vm,$nonce,$token,$installed,$ttl)
# This descriptor factory has no filesystem/process/network side effects.
function New-FixtureSecurityDescriptor([string]$UserSid,[ValidateSet('Directory','File','Output')][string]$Kind){
 $directory=$Kind-ne'File'
 $acl=if($directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 $inherit=if($directory){'ContainerInherit,ObjectInherit'}else{'None'}
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',$inherit,'None','Allow')))
 }
 $rights=if($Kind-eq'Output'){'Modify'}else{'ReadAndExecute'}
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($UserSid)),$rights,$inherit,'None','Allow')))
 # Suppress implicit owner WRITE_DAC even if a later high-created telemetry
 # file inherits a labadmin owner SID. Admin/SYSTEM explicit Full remains.
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-3-4')),'ReadPermissions',$inherit,'None','Allow')))
 return $acl
}
function Set-OwnedFixtureAcl([string]$Path,[string]$UserSid,[ValidateSet('Directory','File','Output')][string]$Kind){
 $item=Get-Item -LiteralPath $Path -Force
 if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or($Kind-eq'File')-eq[bool]$item.PSIsContainer){throw 'fixture ACL target type/reparse differs'}
 Set-Acl -LiteralPath $item.FullName -AclObject (New-FixtureSecurityDescriptor $UserSid $Kind)
}
function Assert-FixtureAncestorPaths([string]$Path){
 $cursor=[IO.Path]::GetFullPath($Path)
 while($true){
  $item=Get-Item -LiteralPath $cursor -Force
  if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'fixture ancestor redirected'}
  $parent=[IO.Directory]::GetParent($cursor);if($null-eq$parent){break};$cursor=$parent.FullName
 }
}
function Protect-OwnedFixtureNamespace([string]$Root,[string]$RunId,[string]$CaseId,[string]$VmId,[string]$UserSid){
 $base='C:\ProgramData\AmneziaLab'
 $expected="$base\runs\$RunId\windows-x64\$CaseId\netstack-fixture"
 if([IO.Path]::GetFullPath($Root)-ine$expected-or$RunId-notmatch'^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$'-or$CaseId-notin@('outer-clean','outer-upgrade')-or$VmId-notmatch'^[a-fA-F0-9-]{36}$'){throw 'owned fixture namespace differs'}
 $caseRoot=Split-Path -Parent $expected
 Assert-FixtureAncestorPaths $caseRoot
 $marker=Join-Path $caseRoot 'run-marker.txt';$item=Get-Item -LiteralPath $marker -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'fixture marker redirected'}
 $lines=@(Get-Content -LiteralPath $marker)
 if($lines-notcontains"amnezia-release-lab:${RunId}:windows-x64"-or$lines-notcontains"vm_id=$VmId"-or$lines-notcontains"case_id=$CaseId"){throw 'fixture marker does not authorize ACL scope'}
 # Only the existing required lab namespace components in this proven owned
 # disposable guest. Never mutate ProgramData,drive root or installed app ACLs.
 foreach($directory in @($base,"$base\runs","$base\runs\$RunId","$base\runs\$RunId\windows-x64",$caseRoot)){
  Set-OwnedFixtureAcl $directory $UserSid 'Directory'
 }
 Set-OwnedFixtureAcl $marker $UserSid 'File'
}

   $sid=(Get-LocalUser -Name labadmin).SID.Value
   foreach($key in $mapping.Keys){$path=Join-Path $root $mapping[$key];$info=Get-Item -LiteralPath $path;if(($info.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0 -or $info.Length-ne $files.$key.size -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne $files.$key.sha256){throw 'fixture stage readback differs'};Set-OwnedFixtureAcl $path $sid 'File'}
   if((Get-FileHash -LiteralPath 'C:\Program Files\AmneziaVPN\AmneziaVPN.exe' -Algorithm SHA256).Hash.ToLowerInvariant()-cne $installed){throw 'installed GUI bytes differ'}
   $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{$_.SessionId-gt 0});if($explorer.Count-ne 1){throw 'exactly one interactive guest session required'}
   $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner;if($owner.User-cne 'labadmin'){throw 'interactive guest account differs'}
   $helper=Start-Process -FilePath (Join-Path $root 'fixture.exe') -ArgumentList @('--config',("`""+(Join-Path $root 'config.json')+"`"")) -PassThru -WindowStyle Hidden
   $readyPath=Join-Path $root 'ready.json';$deadline=[DateTime]::UtcNow.AddSeconds(15)
   while(-not(Test-Path -LiteralPath $readyPath)){if($helper.HasExited -or [DateTime]::UtcNow-gt $deadline){throw 'fixture readiness timeout'};Start-Sleep -Milliseconds 100}
   $ready=Get-Content -LiteralPath $readyPath -Raw|ConvertFrom-Json;$actual=Get-Process -Id $helper.Id -ErrorAction Stop
   $start=($actual.StartTime.ToUniversalTime().Ticks-([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime().Ticks)*100
   if($ready.pid-ne $helper.Id -or $ready.process_start_unix_ns-ne $start -or $ready.exe_sha256-cne $files.helper.sha256 -or $ready.run_id-cne $id -or $ready.case_id-cne $case -or $ready.vm_id-cne $vm -or $ready.nonce-cne $nonce){throw 'fixture PID creation/hash lease differs'}
   $ports=@([int]$ready.source_udp_port,[int]$ready.target_udp_port)
   if($ports[0]-eq $ports[1] -or $ports[0]-lt 1 -or $ports[1]-lt 1){throw 'invalid leased UDP ports'}
   foreach($port in $ports){$listeners=@(Get-NetUDPEndpoint -LocalPort $port);if($listeners.Count-ne 1 -or $listeners[0].LocalAddress-cne '127.0.0.1' -or $listeners[0].OwningProcess-ne $helper.Id){throw 'fixture UDP lease differs'}}
   $taskName="AmneziaLab-RouteFixture-$id-$case";if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'observer task already exists'}
   $observer=Join-Path $root 'product_observer.ps1';$plan=Join-Path $root 'observer-plan.json'
   $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$observer`" -PlanPath `"$plan`""
   $principal=New-ScheduledTaskPrincipal -UserId 'labadmin' -LogonType Interactive -RunLevel Highest
   Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 250))|Out-Null
   Start-ScheduledTask -TaskName $taskName
   # Never infer successful cleanup from the helper's own terminal.json.
   $deadline=[DateTime]::UtcNow.AddSeconds($ttl+20)
   while(-not $helper.HasExited){if([DateTime]::UtcNow-gt $deadline){throw 'fixture helper cleanup timeout; preserve owned guest'};Start-Sleep -Milliseconds 250}
   $task=Get-ScheduledTask -TaskName $taskName;$info=Get-ScheduledTaskInfo -TaskName $taskName
   if($task.State-eq 'Running' -or $info.LastTaskResult-ne 0){throw 'observer failed or still running; preserve guest'}
   if(@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"|Where-Object{$_.CommandLine-like "*$observer*"}).Count-ne 0){throw 'observer process still present'}
   if(@(Get-NetUDPEndpoint|Where-Object{$_.LocalPort-in $ports}).Count-ne 0){throw 'fixture UDP ports remain'}
   if(@(Get-Process -Id $helper.Id -ErrorAction SilentlyContinue).Count-ne 0){throw 'fixture helper PID remains'}
   $terminal=Get-Content -LiteralPath (Join-Path $root 'terminal.json') -Raw|ConvertFrom-Json
   if($terminal.pid-ne $helper.Id -or $terminal.process_start_unix_ns-ne $start -or $terminal.nonce-cne $nonce -or $terminal.run_id-cne $id -or $terminal.vm_id-cne $vm){throw 'terminal attempt binding differs'}
   $observation=Get-Content -LiteralPath (Join-Path $root 'observer.json') -Raw|ConvertFrom-Json
   if($observation.task_token-cne $token -or $observation.nonce-cne $nonce -or $observation.run_id-cne $id -or $observation.case_id-cne $case -or $observation.vm_id-cne $vm -or $observation.capability_observed-ne $true){throw 'observer transcript binding differs'}
   Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
   if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'observer task remains'}
   [ordered]@{ready=$ready;terminal=$terminal;observation=$observation;cleanup=[ordered]@{helper_process_absent=$true;helper_udp_ports_absent=$true;observer_task_removed=$true;observer_process_absent=$true}}
  } -ArgumentList $guestRoot,$manifest.files,$names,$RunId,$CaseId,$vmid,$config.nonce,$plan.task_token,$manifest.installed_exe_sha256,$config.ttl_seconds
  return [ordered]@{action='netstack-fixture';run_id=$RunId;case_id=$CaseId;vm_id=$vmid;nonce=$config.nonce;task_token=$plan.task_token;parent_sha256=$Child.parent.sha256;candidate_artifact_sha256=$ExpectedArtifactSha256;manifest_sha256=$ManifestSha256;transport='hyperv-powershell-direct';origin='guest';injected=$false;production_journal=$false;migration_pass=$false;runtime_pass=$false;observation=$result.observation;lease=$result.ready;terminal=$result.terminal;cleanup=$result.cleanup}
 }finally{if($null-ne $session){Remove-PSSession $session}}
}

if ($null -eq $child) { $child = Read-Child $RunsRoot $RunId $ParentRoot $CaseId }
if ($Action -eq 'netstack-fixture') {
    $fixtureChild = Read-Child $RunsRoot $RunId $ParentRoot $CaseId
    Emit (Invoke-OwnedNetstackFixture $fixtureChild $RunId $CaseId $FixtureManifestPath $FixtureManifestSha256 $ExpectedArtifactSha256); exit 0
}
if ($Action -eq 'seed-profile') {
    Emit (Start-PublisherSeed $child); exit 0
}
if ($Action -eq 'relays-start') {
    Emit (Start-Relays $child); exit 0
}
if ($Action -eq 'relays-stop') {
    Emit (Stop-Relays $child); exit 0
}

function Get-NativeBindingCloseout([object[]]$Records) {
    $failed=0;$errorTypes=@()
    foreach($record in $Records){
        try{[void](Assert-Artifact $record.path $record.sha256 $record.size)}
        catch{$failed++;$type=$_.Exception.GetType().FullName;if($errorTypes-notcontains$type){$errorTypes+=,$type}}
    }
    return [ordered]@{unchanged=($failed-eq0);failed_input_count=$failed;error_types=$errorTypes}
}

function Assert-NativeTestPe([string]$Path,[bool]$Dll) {
    $stream=[IO.File]::OpenRead($Path)
    try {
        $reader=New-Object IO.BinaryReader($stream)
        if($reader.ReadUInt16()-ne0x5a4d){Fail 'native test PE DOS header'};$stream.Position=0x3c;$offset=$reader.ReadUInt32()
        if($offset-lt64-or$offset+24-gt$stream.Length){Fail 'native test PE bounds'};$stream.Position=$offset
        if($reader.ReadUInt32()-ne0x4550-or$reader.ReadUInt16()-ne0x8664){Fail 'native test PE signature/architecture'};$stream.Position=$offset+22;$flags=$reader.ReadUInt16()
        if(($flags-band2)-eq0-or[bool]($flags-band0x2000)-ne$Dll){Fail 'native test PE executable/DLL role differs'}
    } finally { $stream.Dispose() }
}

# Fixed native unit tests are a separate capability, never an installer action.
if ($Action -eq 'native-tests') {
    if ($CaseId -cne 'control' -or [string]$child.vm.State -cne 'Running' -or [string]$child.vm.Id -ine $ChildVmId -or $AttemptNonce -cnotmatch '^[0-9a-f]{48}$') { Fail 'native tests require the exact running owned control child and fresh nonce' }
    foreach($localPath in @($NativeManifestPath,$NativeHelperPath,$NativeCapturePath)){if($localPath-cnotmatch'^[A-Za-z]:[\\/]' -or $localPath-match'(^|[\\/])\.\.([\\/]|$)'){Fail 'native test inputs must be local drive paths'}}
    $manifestRecord = Assert-Artifact $NativeManifestPath $NativeManifestSha256 -1
    $helperRecord = Assert-Artifact $NativeHelperPath $NativeHelperSha256 -1
    $captureRecord = Assert-Artifact $NativeCapturePath $NativeCaptureSha256 -1
    if ($manifestRecord.size -gt 131072 -or $helperRecord.size -gt 65536 -or $captureRecord.size -gt 65536) { Fail 'native test input bounds' }
    if ([IO.Path]::GetFileName($helperRecord.path) -cne 'native_test_guest.ps1' -or [IO.Path]::GetFileName($captureRecord.path) -cne 'BoundedOperatorCapture.cs') { Fail 'native test helper role differs' }
    $manifest = Read-Json $manifestRecord.path 'native test manifest'
    $fields=@('schema','candidate_sha256','candidate_version','compile_source_commit','source_root','review_capsule','files')
    if (@($manifest.PSObject.Properties.Name).Count -ne $fields.Count -or @($fields | Where-Object { $manifest.PSObject.Properties.Name -notcontains $_ }).Count -ne 0 -or $manifest.schema -cne 'amnezia.native-windows-tests.v1') { Fail 'native test manifest shape' }
    $tests=@('operator_command_tests.exe','privileged_ipc_security_tests.exe','selfhosted_update_policy_tests.exe','windows_privileged_pipe_reuse_tests.exe')
    $seen=@{}; $executables=@(); $total=0L; $records=@(); $files=@($manifest.files)
    if ($files.Count -lt 4 -or $files.Count -gt 64) { Fail 'native test closure count' }
    foreach ($file in $files) {
        $name=[string]$file.name
        if (@($file.PSObject.Properties.Name).Count -ne 4 -or @(@('name','source','sha256','size')|Where-Object{$file.PSObject.Properties.Name -notcontains $_}).Count -ne 0 -or $name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$' -or $seen.ContainsKey($name)) { Fail 'native test unsafe/duplicate file' }
        if ($tests -ccontains $name) { $executables+=,$name } elseif (-not $name.EndsWith('.dll',[StringComparison]::Ordinal)) { Fail 'native test executable role is forbidden' }
        if ([IO.Path]::GetFileName([string]$file.source) -cne $name -or [int64]$file.size -le 0 -or [int64]$file.size -gt 134217728) { Fail 'native test source/size differs' }
        if([string]$file.source-cnotmatch'^[A-Za-z]:[\\/]' -or [string]$file.source-match'(^|[\\/])\.\.([\\/]|$)'){Fail 'native test source must be local drive path'}
        $record=Assert-Artifact ([string]$file.source) ([string]$file.sha256) ([int64]$file.size)
        Assert-NativeTestPe $record.path ($name.EndsWith('.dll',[StringComparison]::Ordinal))
        $records+=,$record; $seen[$name]=$true; $total+=$record.size
    }
    if ($executables.Count -ne 4 -or @($tests|Where-Object{$executables -cnotcontains $_}).Count -ne 0 -or $total -gt 536870912) { Fail 'native tests require exact four executable roles' }
    if([string]$manifest.review_capsule.path-cnotmatch'^[A-Za-z]:[\\/]' -or [string]$manifest.source_root-cnotmatch'^[A-Za-z]:[\\/]'){Fail 'native test capsule/source root must be local drive paths'}
    $capsuleRecord=Assert-Artifact ([string]$manifest.review_capsule.path) ([string]$manifest.review_capsule.sha256) ([int64]$manifest.review_capsule.size)
    if($capsuleRecord.size-gt2097152){Fail 'native test review capsule bounds'}
    $capsule=Read-Json $capsuleRecord.path 'native test compile capsule'
    if($manifest.compile_source_commit-cnotmatch'^[0-9a-f]{40}$'-or$capsule.sourceCommit-cne$manifest.compile_source_commit-or$manifest.candidate_sha256-cnotmatch'^[0-9a-f]{64}$'-or$manifest.candidate_version-cnotmatch'^\d+\.\d+\.\d+\.\d+$'){Fail 'native test compile/candidate identity'}
    $bindingRecords=@($manifestRecord,$helperRecord,$captureRecord,$capsuleRecord)
    foreach($entry in @($capsule.runtimeHashes.PSObject.Properties)){if([string]$entry.Name-cnotmatch'^[A-Za-z]:[\\/]'){Fail 'native runtime capsule path must be local'};$bindingRecords+=,(Assert-Artifact ([string]$entry.Name) ([string]$entry.Value) -1)}
    if(@($capsule.runtimeHashes.PSObject.Properties).Count-lt4-or@($capsule.sourceHashes.PSObject.Properties).Count-lt1){Fail 'native test compile capsule is incomplete'}
    $sourceRoot=Full ([string]$manifest.source_root)
    foreach($entry in @($capsule.sourceHashes.PSObject.Properties)){
        $path=Assert-Contained (Join-Path $sourceRoot ([string]$entry.Name)) $sourceRoot 'native test compile source'
        $bindingRecords+=,(Assert-Artifact $path ([string]$entry.Value) -1)
    }
    foreach($record in $records){
        $bound=@($capsule.runtimeHashes.PSObject.Properties|Where-Object{(Full ([string]$_.Name))-ieq$record.path-and[string]$_.Value-ceq$record.sha256})
        if($bound.Count-ne1){Fail 'native test runtime file is outside the reviewed compile capsule'}
    }
    $session=New-Session $child
    $remote=$null;$sessionCleanup=$false;$sessionCleanupFailure=''
    try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\control"
        $nativeInputRoot=Join-Path $guestRoot 'native-tests-input'; $nativeOutputRoot=Join-Path $guestRoot 'native-tests-output'
        Invoke-Command -Session $session -ScriptBlock {
            param($root,$nativeInputRoot,$nativeOutputRoot,$id,$vmid)
            $marker=Join-Path $root 'run-marker.txt';$lines=@([IO.File]::ReadAllLines($marker))
            if($lines-notcontains"amnezia-release-lab:${id}:windows-x64"-or$lines-notcontains'case_id=control'-or$lines-notcontains"vm_id=$vmid"){throw 'native test guest marker differs before staging'}
            $cursor=$root;while($cursor){$item=Get-Item -LiteralPath $cursor -Force;if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'native test staging ancestor redirected'};$parent=Split-Path -Parent $cursor;if($parent-eq$cursor){break};$cursor=$parent}
            if((Test-Path -LiteralPath $nativeInputRoot)-or(Test-Path -LiteralPath $nativeOutputRoot)){throw 'native test fresh guest paths required'}
            New-Item -ItemType Directory -Path $nativeInputRoot,$nativeOutputRoot -ErrorAction Stop|Out-Null
        } -ArgumentList $guestRoot,$nativeInputRoot,$nativeOutputRoot,$RunId,$ChildVmId | Out-Null
        Copy-Item -LiteralPath $manifestRecord.path -Destination (Join-Path $nativeInputRoot 'manifest.json') -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $helperRecord.path -Destination (Join-Path $nativeInputRoot 'native_test_guest.ps1') -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $captureRecord.path -Destination (Join-Path $nativeInputRoot 'BoundedOperatorCapture.cs') -ToSession $session -ErrorAction Stop
        foreach($record in $records){Copy-Item -LiteralPath $record.path -Destination (Join-Path $nativeInputRoot ([IO.Path]::GetFileName($record.path))) -ToSession $session -ErrorAction Stop}
        $remote=Invoke-Command -Session $session -ScriptBlock {
            param($root,$nativeInputRoot,$nativeOutputRoot,$id,$vmid,$nonce,$manifestSha,$helperSha,$captureSha)
            $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{$_.SessionId-gt0})
            if($explorer.Count-ne1){throw 'native tests require one existing interactive Explorer'}
            $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop
            $ownerSid=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwnerSid -ErrorAction Stop
            if([string]$owner.User-cne'labadmin'){throw 'native tests require guest labadmin Explorer'}
            function Set-NativeAcl([string]$Path,[string]$Kind){
                $directory=$Kind-ne'File';$acl=if($directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
                $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
                $inherit=if($directory){'ContainerInherit,ObjectInherit'}else{'None'}
                foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',$inherit,'None','Allow')))}
                $rights=if($Kind-eq'Output'){'Modify'}else{'ReadAndExecute'}
                $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier([string]$ownerSid.Sid)),$rights,$inherit,'None','Allow')))
                $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-3-4')),'ReadPermissions',$inherit,'None','Allow')))
                Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
            }
            $base='C:\ProgramData\AmneziaLab'
            foreach($path in @($base,"$base\runs","$base\runs\$id","$base\runs\$id\windows-x64",$root,$nativeInputRoot)){Set-NativeAcl $path 'Directory'}
            Set-NativeAcl (Join-Path $root 'run-marker.txt') 'File';Set-NativeAcl $nativeOutputRoot 'Output'
            foreach($file in @(Get-ChildItem -LiteralPath $nativeInputRoot -File)){Set-NativeAcl $file.FullName 'File'}
            if((Get-FileHash -LiteralPath (Join-Path $nativeInputRoot 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$manifestSha-or(Get-FileHash -LiteralPath (Join-Path $nativeInputRoot 'native_test_guest.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$helperSha-or(Get-FileHash -LiteralPath (Join-Path $nativeInputRoot 'BoundedOperatorCapture.cs') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$captureSha){throw 'native test helper guest copy differs'}
            $taskName="AmneziaLab-NativeTests-$id";if($taskName.Length-gt200-or(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)){throw 'native test task must be fresh'}
            $helper=Join-Path $nativeInputRoot 'native_test_guest.ps1';$arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$helper`" -RunId $id -VmId $vmid -AttemptNonce $nonce -ManifestSha256 $manifestSha -HelperSha256 $helperSha -CaptureSha256 $captureSha"
            $taskAction=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
            $userId=if([string]::IsNullOrWhiteSpace([string]$owner.Domain)){[string]$owner.User}else{"$($owner.Domain)\$($owner.User)"}
            $principal=New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 120) -MultipleInstances IgnoreNew
            $taskStarted=$false;$taskCompleted=$false;$taskCleanup=$false;$taskExit=$null;$taskFailure=''
            try{
                Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $principal -Settings $settings -Description 'Owned four native release tests; no installer' -ErrorAction Stop|Out-Null
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop;$taskStarted=$true;$deadline=[DateTime]::UtcNow.AddSeconds(115)
                do{$task=Get-ScheduledTask -TaskName $taskName; $info=Get-ScheduledTaskInfo -TaskName $taskName;if($task.State-ne'Running'-and$info.LastRunTime-gt[DateTime]::MinValue-and($info.LastTaskResult-ne267011)){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow-lt$deadline)
                if($task.State-eq'Running'){throw 'native test bounded task did not complete'}
                $taskCompleted=$true;$taskExit=[int64]$info.LastTaskResult
            }catch{$taskFailure=$_.Exception.GetType().FullName+': '+$_.Exception.Message}
            finally{
                $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if($null-eq$task){$taskCleanup=$true}
                elseif($task.State-ne'Running'){
                    try{Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop;$taskCleanup=$null-eq(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)}catch{$taskFailure+='; task cleanup='+$_.Exception.GetType().FullName}
                }
            }
            # Original fixed output bytes are returned even on native failure,
            # missing receipt, startup rejection or a live task timeout. The
            # canonical controller resets the whole owned child only after this
            # private capture has been archived; no task/PID/name broad kill.
            $captures=@();$receiptBytes=[byte[]]@();$total=0L
            foreach($name in @('receipt.json','failure.json')+@('operator_command_tests.exe.capture.json','privileged_ipc_security_tests.exe.capture.json','selfhosted_update_policy_tests.exe.capture.json','windows_privileged_pipe_reuse_tests.exe.capture.json')){
                $path=Join-Path $nativeOutputRoot $name
                if(Test-Path -LiteralPath $path -PathType Leaf){
                    $item=Get-Item -LiteralPath $path -Force
                    if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or$item.Length-gt4194304){throw 'native test output path/bounds differ'}
                    $raw=[IO.File]::ReadAllBytes($path);$total+=$raw.Length;if($total-gt8388608){throw 'native test aggregate capture bound'}
                    $captures+=,[ordered]@{name=$name;size=$raw.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();bytes_b64=[Convert]::ToBase64String($raw)}
                    if($name-ceq'receipt.json'){$receiptBytes=$raw}
                }
            }
            [ordered]@{receipt_bytes_b64=[Convert]::ToBase64String($receiptBytes);captures=$captures;task_exit=$taskExit;task_name=$taskName;task_started=$taskStarted;task_completed=$taskCompleted;task_removed=$taskCleanup;task_failure=$taskFailure}
        } -ArgumentList $guestRoot,$nativeInputRoot,$nativeOutputRoot,$RunId,$ChildVmId,$AttemptNonce,$manifestRecord.sha256,$helperRecord.sha256,$captureRecord.sha256
    } finally { try{Remove-PSSession $session -ErrorAction Stop;$sessionCleanup=$true}catch{$sessionCleanupFailure=$_.Exception.GetType().FullName} }
    $bindingCloseout=Get-NativeBindingCloseout $bindingRecords
    $receipt=$null;$receiptParseFailure='';$raw=[Convert]::FromBase64String([string]$remote.receipt_bytes_b64)
    if($raw.Length-gt0){try{$receipt=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json}catch{$receiptParseFailure=$_.Exception.GetType().FullName}}
    Emit ([ordered]@{action='native-tests';transport='hyperv-powershell-direct';origin='guest';injected=$false;vm_id=[string]$child.vm.Id;parent_sha256=$child.parent.sha256;manifest_sha256=$manifestRecord.sha256;host_bindings_unchanged=$bindingCloseout.unchanged;host_binding_closeout=$bindingCloseout;session_cleanup_confirmed=$sessionCleanup;session_cleanup_failure=$sessionCleanupFailure;receipt_parse_failure=$receiptParseFailure;receipt=$receipt;original=$remote;release_passed=$false});exit 0
}

if ($Action -eq 'publish') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'publisher CLI requires a running child VM' }
    $session = New-Session $child
    try {
        $remote = Invoke-Command -Session $session -ScriptBlock {
            param($id,$case,$nonce)
            $exe='C:\Program Files\AmneziaVPN\AmneziaVPN.exe'; $root="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"; $out=Join-Path $root 'publisher.stdout.log'; $err=Join-Path $root 'publisher.stderr.log'
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'installed AmneziaVPN.exe is missing' }
            if (-not (Test-Path -LiteralPath (Join-Path $root 'publisher\attempt-nonce.txt') -PathType Leaf) -or [string](Get-Content -LiteralPath (Join-Path $root 'publisher\attempt-nonce.txt') -Raw).Trim() -ne $nonce) { throw 'publisher attempt nonce marker is missing or mismatched' }
            Remove-Item -LiteralPath $out,$err -Force -ErrorAction SilentlyContinue
            function New-PublisherCaptureRecord([object]$Capture,[string]$RunId,[string]$CaseId,[string]$AttemptNonce,[string]$StdoutPath,[string]$StderrPath,[string]$CapturePath) {
                if($RunId-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'){throw 'publisher capture run id invalid'}
                if($CaseId-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'){throw 'publisher capture case id invalid'}
                if($AttemptNonce-notmatch'^[0-9a-f]{48}$'){throw 'publisher capture attempt nonce invalid'}
                $sha=[Security.Cryptography.SHA256]::Create()
                try{$nonceHash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($AttemptNonce))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
                $exit=$null; $exitValid=($null-ne$Capture.ExitCode-and$Capture.ExitCode-is[int]); if($exitValid){$exit=$Capture.ExitCode}
                $status=[string]$Capture.Status
                $failure=([string]$Capture.Failure)-replace'[^\x20-\x7E]','?'
                [ordered]@{
                    schema=2
                    run_id=$RunId
                    case_id=$CaseId
                    attempt_nonce_sha256=$nonceHash
                    pid=[int]$Capture.Pid
                    process_start_time=[string]$Capture.StartTime
                    exit_code=$exit
                    capture_status=$status
                    timed_out=[bool]$Capture.TimedOut
                    termination_confirmed=[bool]$Capture.TerminationConfirmed
                    drain_completed=[bool]$Capture.DrainCompleted
                    stdout_bytes=[long]$Capture.StdoutBytes
                    stderr_bytes=[long]$Capture.StderrBytes
                    stdout_truncated=[bool]$Capture.StdoutTruncated
                    stderr_truncated=[bool]$Capture.StderrTruncated
                    stdout_head_b64=[string]$Capture.StdoutHeadB64
                    stdout_tail_b64=[string]$Capture.StdoutTailB64
                    stderr_head_b64=[string]$Capture.StderrHeadB64
                    stderr_tail_b64=[string]$Capture.StderrTailB64
                    stdout_path=[string]$StdoutPath
                    stderr_path=[string]$StderrPath
                    capture_path=[string]$CapturePath
                    capture_error=$failure
                    passed=($status-eq'completed'-and$exitValid-and$exit-eq0-and$Capture.DrainCompleted-eq$true-and$Capture.TerminationConfirmed-eq$true-and-not$Capture.TimedOut-and[string]::IsNullOrWhiteSpace($failure))
                }
            }
            function Invoke-OwnedPublisherProcess([string]$FilePath,[string]$Arguments,[string]$StdoutPath,[string]$StderrPath,[string]$RunId,[string]$CaseId,[string]$AttemptNonce,[int]$TimeoutMilliseconds=900000) {
                if($TimeoutMilliseconds-lt1-or$TimeoutMilliseconds-gt900000){throw 'publisher capture deadline invalid'}
                if($RunId-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'){throw 'publisher capture run id invalid'}
                if($CaseId-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'){throw 'publisher capture case id invalid'}
                if($AttemptNonce-notmatch'^[0-9a-f]{48}$'){throw 'publisher capture attempt nonce invalid'}
                if([string]::IsNullOrWhiteSpace($FilePath)){throw 'publisher capture executable path is empty'}
                if([string]::IsNullOrWhiteSpace($StdoutPath)-or[string]::IsNullOrWhiteSpace($StderrPath)){throw 'publisher capture output paths are empty'}
                if([IO.Path]::GetFullPath($StdoutPath)-ieq[IO.Path]::GetFullPath($StderrPath)){throw 'publisher capture output paths collide'}
                if(-not(Test-Path -LiteralPath (Split-Path -Parent $StdoutPath) -PathType Container)){throw 'publisher capture directory is missing'}
                $capturePath=Join-Path (Split-Path -Parent $StdoutPath) 'publisher.capture.json'
                if(Test-Path -LiteralPath $capturePath){Remove-Item -LiteralPath $capturePath -Force -ErrorAction Stop}
                if(-not('AmneziaPublisherCaptureV2' -as [type])) {
                    Add-Type -TypeDefinition @'
            using System;
            using System.Diagnostics;
            using System.IO;
            using System.Text;
            using System.Threading.Tasks;
            
            public sealed class AmneziaPublisherCaptureV2 {
              // Bounded head+tail window per stream: 131072 bytes total, small enough for
              // the PowerShell Direct/WSMan 500 KB envelope with both streams present.
              public const int HeadLimit = 65536;
              public const int TailLimit = 65536;
              public const int ReadLimit = 8192;
              public const int JoinMilliseconds = 10000;
            
              public sealed class Result {
                public int Pid;
                public string StartTime;
                public int? ExitCode;
                public bool TimedOut;
                public string Status;
                public bool TerminationConfirmed;
                public bool DrainCompleted;
                public long StdoutBytes;
                public long StderrBytes;
                public bool StdoutTruncated;
                public bool StderrTruncated;
                public string StdoutHeadB64;
                public string StdoutTailB64;
                public string StderrHeadB64;
                public string StderrTailB64;
                public string Failure;
              }
            
              sealed class Sink {
                readonly object gate = new object();
                readonly FileStream file;
                readonly byte[] head = new byte[HeadLimit];
                readonly byte[] tail = new byte[TailLimit];
                int headCount;
                int tailCount;
                int tailPosition;
                long count;
                bool closed;
                public string Failure;
            
                public Sink(string path) {
                  file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 65536);
                }
            
                public void Pump(Stream source) {
                  byte[] buffer = new byte[ReadLimit];
                  try {
                    int read;
                    while ((read = source.Read(buffer, 0, buffer.Length)) > 0) {
                      lock (gate) {
                        if (closed) return;
                        file.Write(buffer, 0, read);
                        int headRoom = HeadLimit - headCount;
                        if (headRoom > 0) {
                          int copy = read < headRoom ? read : headRoom;
                          Array.Copy(buffer, 0, head, headCount, copy);
                          headCount += copy;
                        }
                        if (read >= TailLimit) {
                          Array.Copy(buffer, read - TailLimit, tail, 0, TailLimit);
                          tailCount = TailLimit;
                          tailPosition = 0;
                        } else {
                          int first = read < TailLimit - tailPosition ? read : TailLimit - tailPosition;
                          Array.Copy(buffer, 0, tail, tailPosition, first);
                          int rest = read - first;
                          if (rest > 0) Array.Copy(buffer, first, tail, 0, rest);
                          tailPosition = (tailPosition + read) % TailLimit;
                          tailCount = tailCount + read < TailLimit ? tailCount + read : TailLimit;
                        }
                        count += read;
                      }
                    }
                  } catch (Exception error) {
                    if (Failure == null) Failure = error.GetType().Name + ": " + error.Message;
                  }
                }
            
                public void Close() {
                  lock (gate) {
                    if (closed) return;
                    closed = true;
                    try { file.Flush(); } catch { }
                    try { file.Dispose(); } catch { }
                  }
                }
                public long Count { get { lock (gate) { return count; } } }
                public bool Truncated { get { lock (gate) { return count > (long)HeadLimit + (long)TailLimit; } } }
                public byte[] HeadBytes() {
                  lock (gate) {
                    byte[] copy = new byte[headCount];
                    Array.Copy(head, 0, copy, 0, headCount);
                    return copy;
                  }
                }
                public byte[] TailBytes() {
                  lock (gate) {
                    if (count <= (long)HeadLimit) return new byte[0];
                    byte[] copy = new byte[tailCount];
                    if (tailCount == TailLimit) {
                      int first = TailLimit - tailPosition;
                      Array.Copy(tail, tailPosition, copy, 0, first);
                      if (tailPosition > 0) Array.Copy(tail, 0, copy, first, tailPosition);
                    } else {
                      Array.Copy(tail, 0, copy, 0, tailCount);
                    }
                    return copy;
                  }
                }
              }
            
              static string Join(string left, string right) {
                if (left == null || left.Length == 0) return right;
                if (right == null || right.Length == 0) return left;
                return left + "; " + right;
              }
            
              public static Result Run(string path, string args, int timeout, string stdoutPath, string stderrPath) {
                Result result = new Result();
                Sink stdout = null;
                Sink stderr = null;
                Process process = new Process();
                process.StartInfo = new ProcessStartInfo(path, args);
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                bool started = false;
                Task drainOut = null;
                Task drainErr = null;
                try {
                  stdout = new Sink(stdoutPath);
                  stderr = new Sink(stderrPath);
                  if (!process.Start()) throw new InvalidOperationException("publisher process did not start");
                  started = true;
                  // Retaining the real handle keeps StartTime/ExitCode readable for this exact
                  // child.  Start-Process -PassThru with redirection loses it on PowerShell 5.
                  IntPtr retained = process.Handle;
                  if (process.Handle != retained) throw new InvalidOperationException("publisher process handle identity changed");
                  result.Pid = process.Id;
                  try {
                    result.StartTime = process.StartTime.ToUniversalTime().ToString("o");
                  } catch (Exception error) {
                    result.Failure = Join(result.Failure, "start time unavailable: " + error.Message);
                  }
                  drainOut = Task.Run(() => stdout.Pump(process.StandardOutput.BaseStream));
                  drainErr = Task.Run(() => stderr.Pump(process.StandardError.BaseStream));
                  bool exited = process.WaitForExit(timeout);
                  if (!exited) {
                    result.TimedOut = true;
                    try {
                      process.Kill();
                    } catch (Exception error) {
                      result.Failure = Join(result.Failure, "timeout termination failed: " + error.Message);
                    }
                    try {
                      result.TerminationConfirmed = process.WaitForExit(5000);
                    } catch (Exception error) {
                      result.Failure = Join(result.Failure, "timeout termination unproven: " + error.Message);
                    }
                  } else {
                    result.TerminationConfirmed = true;
                  }
                  process.Refresh();
                  try {
                    if (process.HasExited) result.ExitCode = process.ExitCode;
                  } catch (Exception error) {
                    result.Failure = Join(result.Failure, "exit code unavailable: " + error.Message);
                  }
                  if (result.TimedOut) result.Status = result.TerminationConfirmed ? "timeout" : "termination-unconfirmed";
                  else if (result.ExitCode.HasValue) result.Status = "completed";
                  else result.Status = "exit-unavailable";
                  bool drained = false;
                  try {
                    drained = Task.WaitAll(new Task[] { drainOut, drainErr }, JoinMilliseconds);
                  } catch (Exception error) {
                    result.Failure = Join(result.Failure, "output drain failed: " + error.Message);
                  }
                  result.DrainCompleted = drained;
                  if (!drained) result.Failure = Join(result.Failure, "output drain exceeded the bounded deadline");
                } catch (Exception error) {
                  result.Failure = Join(result.Failure, "capture failed: " + error.GetType().Name + ": " + error.Message);
                  if (started) {
                    try { if (!process.HasExited) process.Kill(); } catch { }
                  }
                  if (result.Status == null) result.Status = "capture-failed";
                } finally {
                  if (stdout != null) stdout.Close();
                  if (stderr != null) stderr.Close();
                  result.StdoutBytes = stdout == null ? 0 : stdout.Count;
                  result.StderrBytes = stderr == null ? 0 : stderr.Count;
                  result.StdoutTruncated = stdout != null && stdout.Truncated;
                  result.StderrTruncated = stderr != null && stderr.Truncated;
                  result.StdoutHeadB64 = stdout == null ? "" : Convert.ToBase64String(stdout.HeadBytes());
                  result.StdoutTailB64 = stdout == null ? "" : Convert.ToBase64String(stdout.TailBytes());
                  result.StderrHeadB64 = stderr == null ? "" : Convert.ToBase64String(stderr.HeadBytes());
                  result.StderrTailB64 = stderr == null ? "" : Convert.ToBase64String(stderr.TailBytes());
                  if (stdout != null && stdout.Failure != null) result.Failure = Join(result.Failure, "stdout: " + stdout.Failure);
                  if (stderr != null && stderr.Failure != null) result.Failure = Join(result.Failure, "stderr: " + stderr.Failure);
                  try { process.Dispose(); } catch { }
                }
                return result;
              }
            }
'@ | Out-Null
                }
                $capture=$null;$launchError=$null
                try{$capture=[AmneziaPublisherCaptureV2]::Run($FilePath,$Arguments,$TimeoutMilliseconds,$StdoutPath,$StderrPath)}catch{$launchError=$_.Exception.Message}
                if($null-eq$capture){
                    $stub=[pscustomobject]@{Pid=0;StartTime='';ExitCode=$null;TimedOut=$false;Status='not-started';TerminationConfirmed=$false;DrainCompleted=$false;StdoutBytes=0L;StderrBytes=0L;StdoutTruncated=$false;StderrTruncated=$false;StdoutHeadB64='';StdoutTailB64='';StderrHeadB64='';StderrTailB64='';Failure=[string]$launchError}
                    $record=New-PublisherCaptureRecord $stub $RunId $CaseId $AttemptNonce $StdoutPath $StderrPath $capturePath
                } else {
                    $record=New-PublisherCaptureRecord $capture $RunId $CaseId $AttemptNonce $StdoutPath $StderrPath $capturePath
                }
                $json=$record|ConvertTo-Json -Compress
                [IO.File]::WriteAllText($capturePath,$json,(New-Object Text.UTF8Encoding($false)))
                $readback=[IO.File]::ReadAllText($capturePath,(New-Object Text.UTF8Encoding($false)))
                if($readback-cne$json){throw 'publisher capture record readback differs'}
                return $record
            }
            $capture=Invoke-OwnedPublisherProcess $exe '--publish-bundled-updates-once' $out $err $id $case $nonce 900000
            if($capture.run_id-cne$id-or$capture.case_id-cne$case){throw 'publisher capture binding differs from the requested run/case'}
            [ordered]@{ exit_code=$capture.exit_code; timed_out=$capture.timed_out; capture_status=$capture.capture_status; passed=$capture.passed; capture_path=$capture.capture_path; stdout_path=$out; stderr_path=$err; capture=$capture }



        } -ArgumentList $RunId,$CaseId,$AttemptNonce
        $hostCapture=''
        if($null-ne$remote.capture){
            # Stream bytes are archived privately by the POSIX controller. Keep
            # only an allowlisted status record in the host's case directory.
            $hostMetadata=[ordered]@{}
            foreach($field in @('schema','run_id','case_id','attempt_nonce_sha256','pid','process_start_time','exit_code','capture_status','timed_out','termination_confirmed','drain_completed','stdout_bytes','stderr_bytes','stdout_truncated','stderr_truncated','passed')){$hostMetadata[$field]=$remote.capture.$field}
            $hostCapture=Join-Path $child.root 'publisher.capture.json'
            [IO.File]::WriteAllText($hostCapture,($hostMetadata|ConvertTo-Json -Depth 8 -Compress),(New-Object Text.UTF8Encoding($false)))
        }
        Emit ([ordered]@{ action='publish'; passed=($remote.passed-eq $true); transport='hyperv-powershell-direct'; origin='guest'; injected=$false; run_id=$RunId; case_id=$CaseId; vm_id=[string]$child.vm.Id; host_capture_path=$hostCapture; raw=$remote }); exit 0
    } finally { Remove-PSSession $session }
}
if ($Action -eq 'status') { Emit ([ordered]@{ action='status'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=$child.parent.sha256; release_passed=$false; product_verified=$false }); exit 0 }
if ($Action -eq 'start') {
    Verify-ChildConfig $child | Out-Null
    if ([string]$child.vm.State -ne 'Off') { Fail 'child VM must be Off before start' }
    Start-VM -VM $child.vm | Out-Null
    $running = @(Get-VM -Id ([guid]$child.vm.Id) -ErrorAction Stop)[0]
    if ([string]$running.State -ne 'Running') { Fail 'child VM did not reach Running state' }
    $worker=Get-ChildWorkerIdentity $running; $startMarker=[ordered]@{}; foreach($property in $child.marker.PSObject.Properties){$startMarker[$property.Name]=$property.Value}; $startMarker['state']='running'; $startMarker['process_pid']=$worker.process_pid; $startMarker['process_uuid']=$worker.process_uuid; $startMarker['process_start_time']=$worker.process_start_time; Emit ([ordered]@{ action='start'; child=$startMarker; worker=$worker; configuration=(Verify-ChildConfig $child); parent_sha256=(Get-Parent $ParentRoot).sha256 }); exit 0
}
if ($Action -eq 'stop') {
    if ([string]$child.vm.State -eq 'Running') { Stop-VM -VM $child.vm -TurnOff:$false -Force | Out-Null }
    $deadline=(Get-Date).AddSeconds(90); do { $stopped=@(Get-VM -Id ([guid]$child.vm.Id))[0]; if ([string]$stopped.State -eq 'Off'){break}; Start-Sleep -Seconds 1 } while((Get-Date)-lt $deadline)
    if ([string]$stopped.State -ne 'Off') { Fail 'child VM did not stop within bounded wait' }
    $child.marker.state='stopped'; Emit ([ordered]@{ action='stop'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=(Get-Parent $ParentRoot).sha256 }); exit 0
}
if ($Action -eq 'probe') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for probe' }
    $childVmId = [string]$child.vm.Id
    $session=New-Session $child; try {
        $probe=Invoke-Command -Session $session -ScriptBlock {
            param($runId,$caseId,$vmId)
            $p='C:\ProgramData\AmneziaLab\READY'; if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw 'guest readiness marker missing'}
            $root="C:\ProgramData\AmneziaLab\runs\$runId\windows-x64\$caseId"; $marker=Join-Path $root 'run-marker.txt'; New-Item -ItemType Directory -Force -Path $root | Out-Null
            $expectedMarker = "amnezia-release-lab:${runId}:windows-x64`r`nbackend=hyperv`r`ncase_id=$caseId`r`nvm_id=$vmId`r`n"
            if(Test-Path -LiteralPath $marker -PathType Leaf){ if([IO.File]::ReadAllText($marker) -ne $expectedMarker){throw 'existing guest case marker does not match this run/case/VM'} } else { [IO.File]::WriteAllText($marker,$expectedMarker,(New-Object Text.ASCIIEncoding)) }
            $savedProfileValues=0; $checkedHives=0
            $loadedHives=@([Microsoft.Win32.Registry]::Users.GetSubKeyNames())
            $launchSids=@('S-1-5-18',[string](Get-LocalUser -Name 'labadmin' -ErrorAction Stop).SID.Value)
            foreach($sid in $launchSids){if($loadedHives -notcontains $sid){throw 'guest app launch account hive is not loaded for privacy inspection'}}
            foreach($hiveName in $loadedHives) {
                $key=[Microsoft.Win32.Registry]::Users.OpenSubKey("$hiveName\Software\AmneziaVPN.ORG\AmneziaVPN\Servers")
                $checkedHives++
                if($null -ne $key){try{if(@($key.GetValueNames()) -contains 'serversList'){$savedProfileValues++}}finally{$key.Dispose()}}
            }
            $settingsFiles=0
            foreach($profile in @(Get-CimInstance Win32_UserProfile)) {
                foreach($suffix in @('AppData\Local\AmneziaVPN.ORG','AppData\Roaming\AmneziaVPN.ORG','AppData\Local\AmneziaVPN','AppData\Roaming\AmneziaVPN')) {
                    $dir=Join-Path $profile.LocalPath $suffix
                    if(Test-Path -LiteralPath $dir -PathType Container){$settingsFiles+=@(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction Stop | Where-Object {$_.Extension -in @('.conf','.ini')}).Count}
                }
            }
            if($savedProfileValues -ne 0 -or $settingsFiles -ne 0){throw 'guest saved server profile privacy precondition failed'}
            [ordered]@{ readiness=[IO.File]::ReadAllText($p); guest_marker=[IO.File]::ReadAllText($marker); privacy=[ordered]@{checked_loaded_hives=$checkedHives;checked_launch_accounts=$launchSids.Count;saved_profile_values=$savedProfileValues;settings_files=$settingsFiles;eligible_admin_count=0;endpoint_scope='no saved profiles';passed=$true} }
        } -ArgumentList $RunId,$CaseId,$childVmId
    } finally { Remove-PSSession $session }
    if ($probe.guest_marker -notmatch "(?m)^amnezia-release-lab:$([regex]::Escape($RunId)):windows-x64\s*$" -or $probe.guest_marker -notmatch "(?m)^case_id=$([regex]::Escape($CaseId))\s*$" -or $probe.guest_marker -notmatch "(?m)^vm_id=$([regex]::Escape($childVmId))\s*$") { Fail 'guest case marker readback is not bound to this run/case/VM' }
    $readiness=$probe.readiness
    if ($readiness -notmatch '(?m)^profile=windows-x64\s*$' -or $readiness -notmatch '(?m)^phase=ready\s*$' -or $readiness -notmatch '(?m)^candidate_credentials=absent\s*$') { Fail 'guest readiness marker is invalid' }
    Emit ([ordered]@{ action='probe'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; guest_marker=$probe.guest_marker; readiness_marker=$readiness; privacy=$probe.privacy }); exit 0
}
if ($Action -eq 'precondition') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for precondition' }
    $childVmId = [string]$child.vm.Id
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestMarker=Join-Path $guestRoot 'run-marker.txt'
        $proof=Invoke-Command -Session $session -ScriptBlock {
            param($marker,$id,$case,$vmid)
            if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'guest case marker missing' }
            $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${id}:windows-x64" -or $lines -notcontains "case_id=$case" -or $lines -notcontains "vm_id=$vmid"){throw 'guest case marker binding mismatch'}
            $service=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
            $components=Test-Path -LiteralPath 'C:\Program Files\AmneziaVPN\components.xml' -PathType Leaf
            $installRoot=Test-Path -LiteralPath 'C:\Program Files\AmneziaVPN' -PathType Container
            [ordered]@{ case_id=$case; run_id=$id; vm_id=$vmid; service_present=[bool]($null -ne $service); install_root_present=[bool]$installRoot; components_present=[bool]$components; clean=[bool]($null -eq $service -and -not $installRoot -and -not $components) }
        } -ArgumentList $guestMarker,$RunId,$CaseId,$childVmId
    } finally { Remove-PSSession $session }
    if ($proof.clean -ne $true) { Fail 'clean case precondition found installed product/service/components' }
    Emit ([ordered]@{ action='precondition'; proof=$proof; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256 }); exit 0
}
if ($Action -eq 'prepare-interactive') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for interactive preparation' }
    $credential=Get-CredentialFromStdin; $plain=Get-PlainCredential $credential
    $session=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
    $before=$null; $after=$null; $restartError=$null; $rebootObserved=$false
    $cleanupReadback=$null; $cleanupError=$null; $cleanupAttempted=$false
    $cleanupGuest = {
        param($cleanupCredential,$runId,$caseId)
        $s=$null
        try {
            $s=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $cleanupCredential -ErrorAction Stop
            Invoke-Command -Session $s -ScriptBlock {
                param($id,$case)
                $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -PropertyType String -Value '0' -Force | Out-Null; Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $key -Name DefaultUserName -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $key -Name DefaultDomainName -ErrorAction SilentlyContinue
                $taskName="AmneziaLab-Interactive-$id-$case"; Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                $props=Get-ItemProperty -LiteralPath $key -ErrorAction Stop; $remainingTask=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                [ordered]@{ auto_admin_logon=[string]$props.AutoAdminLogon; default_password_present=($props.PSObject.Properties.Name -contains 'DefaultPassword'); task_present=($null -ne $remainingTask) }
            } -ArgumentList $runId,$caseId
        } finally { if($null -ne $s){Remove-PSSession $s -ErrorAction SilentlyContinue} }
    }
    try {
        $before=Invoke-Command -Session $session -ScriptBlock { $os=Get-CimInstance Win32_OperatingSystem; [ordered]@{ last_boot=[string]$os.LastBootUpTime; explorer_count=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue).Count } }
        Invoke-Command -Session $session -ScriptBlock {
            param($password,$runId,$caseId)
            $marker="C:\ProgramData\AmneziaLab\runs\$runId\windows-x64\$caseId\run-marker.txt"
            if(-not(Test-Path -LiteralPath $marker -PathType Leaf)){throw 'guest case marker missing before autologon preparation'}
            $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${runId}:windows-x64" -or $lines -notcontains "case_id=$caseId"){throw 'guest marker binding mismatch before autologon preparation'}
            $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -PropertyType String -Value '1' -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultUserName -PropertyType String -Value 'labadmin' -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultDomainName -PropertyType String -Value '.' -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultPassword -PropertyType String -Value $password -Force | Out-Null
            Restart-Computer -Force -Confirm:$false
        } -ArgumentList $plain,$RunId,$CaseId | Out-Null
    } catch { $restartError=$_.Exception }
    finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
    $readinessError=$null
    try {
      $deadline=(Get-Date).AddMinutes(5); $after=$null; $reconnected=$null
      do {
        Start-Sleep -Seconds 2
        try {
            $reconnected=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
            $after=Invoke-Command -Session $reconnected -ScriptBlock { $os=Get-CimInstance Win32_OperatingSystem; $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 }); [ordered]@{ last_boot=[string]$os.LastBootUpTime; explorer_count=$explorer.Count; explorer_sessions=@($explorer | ForEach-Object { [int]$_.SessionId }) } }
            Remove-PSSession $reconnected; $reconnected=$null
            if($null -ne $before -and $after.last_boot -ne $before.last_boot -and [int]$after.explorer_count -gt 0){break}
        } catch { if($reconnected){Remove-PSSession $reconnected -ErrorAction SilentlyContinue; $reconnected=$null} }
      } while((Get-Date)-lt $deadline)
      if($null -eq $after -or $null -eq $before -or $after.last_boot -eq $before.last_boot -or [int]$after.explorer_count -lt 1){ $readinessError='guest autologon/session preparation did not prove reboot and Explorer readiness' } else { $rebootObserved=$true }
    } finally {
      $cleanupAttempted=$true
      try { $cleanupReadback=& $cleanupGuest $credential $RunId $CaseId } catch { $cleanupError=$_.Exception }
    }
    if($null -ne $readinessError){ if($null -ne $restartError){ throw $restartError }; Fail $readinessError }
    if($null -ne $cleanupError -or $null -eq $cleanupReadback -or [string]$cleanupReadback.auto_admin_logon -ne '0' -or $cleanupReadback.default_password_present -eq $true -or $cleanupReadback.task_present -eq $true){ if($null -ne $cleanupError){throw $cleanupError}; Fail 'guest interactive cleanup was not fully read back; preserving failed case' }
    Emit ([ordered]@{ action='prepare-interactive'; before=$before; after=$after; cleanup=$cleanupReadback; reboot_observed=$rebootObserved; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_ready=$true }); exit 0
}
if ($Action -eq 'ui-observe') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for UI observation' }
    if ($ExpectedArtifactSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'ui-observe requires the planned artifact SHA-256' }
    $keyboard=Get-MsvmKeyboardMetadata ([string]$child.vm.Id)
    $session=New-Session $child; try { $consent=Get-GuestConsentProof $child $session; $console=Get-OwnedConsentConsole $child $session $consent } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='ui-observe'; consent=$consent; keyboard=$keyboard; console_capture=$console; thumbnail_status='captured_bound_console_root_review_pending'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_verified=$false }); exit 0
}
if ($Action -eq 'ui-confirm') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for UI confirmation' }
    if ($ExpectedArtifactSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'ui-confirm requires the planned artifact SHA-256' }
    $keyboard=Get-MsvmKeyboardMetadata ([string]$child.vm.Id)
    if (-not $keyboard.type_key_supported) { Fail 'Msvm_Keyboard TypeKey metadata is unavailable; refusing to synthesize UAC confirmation' }
    $session=New-Session $child; try { $consent=Get-GuestConsentProof $child $session } finally { Remove-PSSession $session }
    $keyboardInstance=@(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction Stop | Where-Object { [string]$_.SystemName -eq [string]$child.vm.Id })
    if ($keyboardInstance.Count -ne 1) { Fail 'Msvm_Keyboard is not uniquely bound to the owned VM ID' }
    $press=Invoke-CimMethod -InputObject $keyboardInstance[0] -MethodName PressKey -Arguments @{ KeyCode = 0x12 } -ErrorAction Stop
    if([int]$press.ReturnValue -ne 0){Fail "Msvm_Keyboard PressKey Alt failed with return $($press.ReturnValue)"}
    $type=Invoke-CimMethod -InputObject $keyboardInstance[0] -MethodName TypeKey -Arguments @{ KeyCode = 0x59 } -ErrorAction Stop
    if([int]$type.ReturnValue -ne 0){Fail "Msvm_Keyboard TypeKey Y failed with return $($type.ReturnValue)"}
    $release=Invoke-CimMethod -InputObject $keyboardInstance[0] -MethodName ReleaseKey -Arguments @{ KeyCode = 0x12 } -ErrorAction Stop
    if([int]$release.ReturnValue -ne 0){Fail "Msvm_Keyboard ReleaseKey Alt failed with return $($release.ReturnValue)"}
    Emit ([ordered]@{ action='ui-confirm'; consent=$consent; confirmed_at=[DateTime]::UtcNow.ToString('o'); keyboard=$keyboard; keyboard_return=[ordered]@{press_alt=[int]$press.ReturnValue; type_y=[int]$type.ReturnValue; release_alt=[int]$release.ReturnValue}; fixed_key='Alt+Y'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_verified=$false }); exit 0
}
if ($Action -eq 'app-window') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for app-window acceptance' }
    if ([string]::IsNullOrWhiteSpace($UiHelperPath) -or -not (Test-Path -LiteralPath $UiHelperPath -PathType Leaf) -or (Sha $UiHelperPath) -ne $UiHelperSha256.ToLowerInvariant()) { Fail 'app-window requires the planned UI helper hash' }
    if ($ExpectedVersion -notmatch '^[0-9]+(\.[0-9]+){2,3}$') { Fail 'app-window requires expected version' }
    $session=New-Session $child
    try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestHelper=Join-Path $guestRoot 'hyperv-ui-helper.ps1'; $guestEvidence=Join-Path $guestRoot 'app-window-evidence.json'; $guestScreenshot=Join-Path $guestRoot 'app-window.png'
        Copy-Item -LiteralPath $UiHelperPath -Destination $guestHelper -ToSession $session -Force
        $evidenceText=Invoke-Command -Session $session -ScriptBlock {
            param($helper,$evidence,$screenshot,$id,$case,$vmid,$version)
            $marker=Join-Path (Split-Path -Parent $helper) 'run-marker.txt'; $lines=@(Get-Content -LiteralPath $marker)
            if($lines -notcontains "amnezia-release-lab:${id}:windows-x64" -or $lines -notcontains "case_id=$case" -or $lines -notcontains "vm_id=$vmid"){throw 'app-window marker binding mismatch'}
            $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{$_.SessionId-gt0}|Select-Object -First 1);if($explorer.Count-ne1){throw 'app-window requires one Explorer session'}
            $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop;$user=if([string]::IsNullOrWhiteSpace([string]$owner.Domain)){[string]$owner.User}else{"$($owner.Domain)\$($owner.User)"}
            $task="AmneziaLab-AppWindow-$id-$case";if($task.Length-gt200){$task=$task.Substring(0,200)};if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'app-window task already exists'}
            $args="-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Action launch-app -RunId $id -CaseId $case -VmId $vmid -ExpectedVersion $version -OutputPath `"$evidence`" -ScreenshotPath `"$screenshot`""
            $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $args;$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew
            try { Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Description 'Owned release-lab app window acceptance'|Out-Null;Start-ScheduledTask -TaskName $task;$deadline=(Get-Date).AddSeconds(120);while((Get-Date)-lt$deadline-and-not(Test-Path -LiteralPath $evidence -PathType Leaf)){Start-Sleep -Milliseconds 500};if(-not(Test-Path -LiteralPath $evidence -PathType Leaf)){throw 'app-window evidence deadline exceeded'};[IO.File]::ReadAllText($evidence) } finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue;if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'app-window task remained after cleanup'} }
        } -ArgumentList $guestHelper,$guestEvidence,$guestScreenshot,$RunId,$CaseId,([string]$child.vm.Id),$ExpectedVersion
        $evidence=$evidenceText|ConvertFrom-Json;if($evidence.run_id-ne$RunId-or$evidence.case_id-ne$CaseId-or$evidence.vm_id-ne([string]$child.vm.Id)-or$evidence.interactive_token-ne$true-or$evidence.action-ne'launch-app'-or$evidence.app.visible-ne$true-or[int]$evidence.app.pid-le0-or[string]::IsNullOrWhiteSpace([string]$evidence.app.sha256)){Fail 'app-window evidence is incomplete or unbound'}
        $evidenceDir=Join-Path $child.root 'evidence';New-Item -ItemType Directory -Force -Path $evidenceDir|Out-Null;$hostPath=Join-Path $evidenceDir 'app-window.png';Copy-Item -LiteralPath $guestScreenshot -Destination $hostPath -FromSession $session -Force;$item=Assert-NoReparse $hostPath 'exported app screenshot';$sha=Sha $item.FullName;if($sha-ne[string]$evidence.screenshot_sha256-or[int64]$item.Length-le1024){Fail 'exported app-window screenshot differs or is empty'}
    } finally {Remove-PSSession $session}
    Emit ([ordered]@{action='app-window';evidence=$evidence;screenshot=[ordered]@{host_path=$item.FullName;sha256=$sha;size=[int64]$item.Length};transport='hyperv-powershell-direct';origin='guest';injected=$false;vm_id=[string]$child.vm.Id;parent_sha256=$child.parent.sha256});exit 0
}
if ($Action -eq 'export-ui') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for UI export' }
    if ($ExpectedScreenshotSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'export-ui requires the planned screenshot SHA-256' }
    $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"
    $guestPath=[IO.Path]::GetFullPath($ScreenshotGuestPath)
    if ([IO.Path]::GetDirectoryName($guestPath) -ne $guestRoot -or [IO.Path]::GetFileName($guestPath) -notmatch '^ui-screenshot-interactive-collect-[0-9a-f]{32}\.png$') { Fail 'exported screenshot path is not a fresh owned collect capture' }
    $evidenceDir=Join-Path $child.root 'evidence'; New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
    $hostPath=Join-Path $evidenceDir 'ui-screenshot.png'
    $session=New-Session $child
    try { Copy-Item -LiteralPath $guestPath -Destination $hostPath -FromSession $session -Force -ErrorAction Stop } finally { Remove-PSSession $session }
    $item=Assert-NoReparse $hostPath 'exported UI screenshot'; $sha=Sha $item.FullName
    if($sha -ne $ExpectedScreenshotSha256.ToLowerInvariant() -or [int64]$item.Length -le 1024){Fail 'exported UI screenshot bytes differ or are empty'}
    Emit ([ordered]@{action='export-ui';host_path=$item.FullName;sha256=$sha;size=[int64]$item.Length;transport='hyperv-powershell-direct';origin='guest';injected=$false;vm_id=[string]$child.vm.Id;parent_sha256=$child.parent.sha256});exit 0
}
if ($Action -eq 'stage') {
    if ($Stage -notmatch '^(baseline|candidate)-(thin|outer)$') { Fail 'stage is required' }
    $source=Assert-Artifact $ArtifactPath $ArtifactSha256 $ArtifactSize
    $staging=Join-Path $child.root 'staging'; New-Item -ItemType Directory -Force -Path $staging | Out-Null
    $destination=Join-Path $staging "$Stage.exe"
    if (Test-Path -LiteralPath $destination) { if ((Sha $destination) -ne $source.sha256) { Fail 'staging destination exists with different bytes' } } else { Copy-Item -LiteralPath $source.path -Destination $destination; if ((Sha $destination) -ne $source.sha256) { Fail 'staging copy hash differs' } }
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running before guest upload' }
    $childVmId = [string]$child.vm.Id
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestArtifact=Join-Path $guestRoot 'current.exe'; $guestMarker=Join-Path $guestRoot 'run-marker.txt'
        Invoke-Command -Session $session -ScriptBlock { param($r,$m,$id,$case,$vmid); New-Item -ItemType Directory -Force -Path $r | Out-Null; Set-Content -LiteralPath $m -Value @("amnezia-release-lab:${id}:windows-x64","backend=hyperv","case_id=$case","vm_id=$vmid") -Encoding ASCII } -ArgumentList $guestRoot,$guestMarker,$RunId,$CaseId,$childVmId | Out-Null
        Copy-Item -LiteralPath $destination -Destination $guestArtifact -ToSession $session -Force
        $readback=Invoke-Command -Session $session -ScriptBlock { param($p); $i=Get-Item -LiteralPath $p; [ordered]@{ sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant(); size=[int64]$i.Length } } -ArgumentList $guestArtifact
        if ($readback.sha256 -ne $source.sha256 -or [int64]$readback.size -ne [int64]$source.size) { Fail 'guest artifact bytes differ from planned source' }
    } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='stage'; stage=$Stage; source=$source; destination=$destination; guest_artifact=$guestArtifact; guest=$readback; transport='hyperv-powershell-direct'; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; origin='guest'; injected=$false }); exit 0
}
if ($Action -eq 'run') {
    if ([string]::IsNullOrWhiteSpace($GuestAction) -or [string]::IsNullOrWhiteSpace($ExpectedSha256) -or [string]::IsNullOrWhiteSpace($ExpectedVersion)) { Fail 'run requires guest action, expected version and artifact hash' }
    if (-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)) { Fail 'runner source is missing' }
    if ((Sha $RunnerPath) -ne $RunnerSha256.ToLowerInvariant()) { Fail 'runner source hash differs from planned record' }
    $uiSource = $null
    $launcherSource = $null
    if ($GuestAction -in @('interactive-start','interactive-collect')) {
        if ([string]::IsNullOrWhiteSpace($UiHelperPath) -or -not (Test-Path -LiteralPath $UiHelperPath -PathType Leaf) -or (Sha $UiHelperPath) -ne $UiHelperSha256.ToLowerInvariant()) { Fail 'interactive Hyper-V action requires the planned UI helper hash' }
        $uiSource = $UiHelperPath
        if ([string]::IsNullOrWhiteSpace($LauncherPath) -or -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf) -or (Sha $LauncherPath) -ne $LauncherSha256.ToLowerInvariant()) { Fail 'interactive Hyper-V action requires the planned limited launcher hash' }
        $launcherSource = $LauncherPath
    }
    $result=Invoke-Guest $child $RunnerPath $GuestAction $ExpectedSha256 $ExpectedArtifactRole $ExpectedVersion $TokenEvidencePath $uiSource $launcherSource
    try { $receipt = $result.readback.receipt | ConvertFrom-Json } catch { Fail 'guest receipt is not valid JSON' }
    if ($receipt.schema -ne 1 -or [string]$receipt.run_id -ne $RunId -or [string]$receipt.profile -ne 'windows-x64' -or [string]$receipt.transport -ne 'hyperv-powershell-direct' -or [string]$receipt.origin -ne 'guest' -or $receipt.injected -eq $true -or [string]$receipt.artifact_sha256 -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'guest receipt identity or artifact proof is incomplete' }
    $steps = @($receipt.steps)
    if ($steps.Count -eq 0 -or @($steps | Where-Object { $_.passed -ne $true }).Count -ne 0) { Fail 'guest receipt has no fully passed assertions' }
    Emit ([ordered]@{ action='run'; result=$result; release_passed=$false; product_verified=$true; receipt_identity=[ordered]@{ run_id=[string]$receipt.run_id; profile=[string]$receipt.profile; artifact_sha256=[string]$receipt.artifact_sha256; steps=@($steps | ForEach-Object { [string]$_.id }) } }); exit 0
}
if ($Action -eq 'collect') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for collect' }
    if (-not [string]::IsNullOrWhiteSpace($AttemptNonce) -and $AttemptNonce -notmatch '^[0-9a-f]{64}$') { Fail 'collect acquisition challenge must be 256-bit lowercase hex' }
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestReceipt=Join-Path $guestRoot 'receipt.json'; $guestMarker=Join-Path $guestRoot 'run-marker.txt'; $guestArtifact=Join-Path $guestRoot 'current.exe'
        $readback=Invoke-Command -Session $session -ScriptBlock {
            param($receipt,$marker,$artifact,$runId,$caseId,$challenge)
            $receiptPresent=Test-Path -LiteralPath $receipt -PathType Leaf
            $receiptText=''; $markerText=if(Test-Path -LiteralPath $marker -PathType Leaf){[IO.File]::ReadAllText($marker)}else{''}
            $rawReceiptB64=''
            if(-not [string]::IsNullOrWhiteSpace($challenge)) {
                $receiptInfo=Get-Item -LiteralPath $receipt -Force -ErrorAction Stop
                if(($receiptInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $receiptInfo.Length -le 0 -or $receiptInfo.Length -gt 524288){throw 'live acquisition receipt bounds/type'}
                $rawReceipt=[IO.File]::ReadAllBytes($receipt)
                $after=Get-Item -LiteralPath $receipt -Force -ErrorAction Stop
                if($rawReceipt.Length -ne $receiptInfo.Length -or $after.Length -ne $receiptInfo.Length -or $after.LastWriteTimeUtc -ne $receiptInfo.LastWriteTimeUtc){throw 'live acquisition receipt changed'}
                $rawReceiptB64=[Convert]::ToBase64String($rawReceipt)
                $receiptText=([Text.UTF8Encoding]::new($false,$true)).GetString($rawReceipt)
                if($receiptText.Length -gt 0 -and $receiptText[0] -eq [char]0xFEFF){$receiptText=$receiptText.Substring(1)}
            }
            if([string]::IsNullOrWhiteSpace($challenge) -and $receiptPresent){$receiptText=[IO.File]::ReadAllText($receipt)}
            $guestHash=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            $svc=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
            $guestRoot=Split-Path -Parent $receipt; $supervisorPath=Join-Path $guestRoot 'runner-supervisor.json'; $supervisorText=if(Test-Path -LiteralPath $supervisorPath -PathType Leaf){[IO.File]::ReadAllText($supervisorPath)}else{''}; $milestonePath=Join-Path $guestRoot 'runner-milestones.jsonl'; $milestoneText=if(Test-Path -LiteralPath $milestonePath -PathType Leaf){[IO.File]::ReadAllText($milestonePath)}else{''}; $pendingPath=Join-Path $guestRoot 'pending-installer.json'; $pendingText=if(Test-Path -LiteralPath $pendingPath -PathType Leaf){[IO.File]::ReadAllText($pendingPath)}else{''}; $outPath=Join-Path $guestRoot 'runner.stdout.log'; $errPath=Join-Path $guestRoot 'runner.stderr.log'; $nativeOutPath=Join-Path $guestRoot 'installer.stdout.log'; $nativeErrPath=Join-Path $guestRoot 'installer.stderr.log'; $redact={param($v);[regex]::Replace([string]$v,'(?i)(password|token|secret|private[_-]?key|key)\s*[:=]\s*[^,; ]+','$1=<redacted>')}; $outTail=if(Test-Path $outPath){@(Get-Content $outPath -Tail 40|ForEach-Object{&$redact $_})}else{@()}; $errTail=if(Test-Path $errPath){@(Get-Content $errPath -Tail 40|ForEach-Object{&$redact $_})}else{@()}; $nativeOut=if(Test-Path $nativeOutPath){@((Get-Content $nativeOutPath -Tail 300)|ForEach-Object{&$redact $_})}else{@()}; $nativeErr=if(Test-Path $nativeErrPath){@((Get-Content $nativeErrPath -Tail 300)|ForEach-Object{&$redact $_})}else{@()}
            $bootstrapRoot=Join-Path $guestRoot 'ifw-bootstrap-root'; $bootstrapOutPath=Join-Path $guestRoot 'bootstrap.stdout.log'; $bootstrapErrPath=Join-Path $guestRoot 'bootstrap.stderr.log'; $bootstrap=[ordered]@{present=(Test-Path -LiteralPath $bootstrapRoot -PathType Container);items=@(Get-ChildItem -LiteralPath $bootstrapRoot -Force -ErrorAction SilentlyContinue|ForEach-Object{$_.Name});stdout_tail=if(Test-Path $bootstrapOutPath){@(Get-Content $bootstrapOutPath -Tail 300|ForEach-Object{&$redact $_})}else{@()};stderr_tail=if(Test-Path $bootstrapErrPath){@(Get-Content $bootstrapErrPath -Tail 300|ForEach-Object{&$redact $_})}else{@()}}
            $os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; $tz=Get-TimeZone -ErrorAction SilentlyContinue; $events=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1074,6005,6006;StartTime=(Get-Date).AddHours(-2)} -ErrorAction SilentlyContinue|Select-Object -First 20|ForEach-Object{[ordered]@{id=[int]$_.Id;time_utc=$_.TimeCreated.ToUniversalTime().ToString('o');provider=[string]$_.ProviderName}}); $logRoot='C:\Users\labadmin\AppData\Local\AmneziaVPN-InstallerLogs'; $installerLogs=@(Get-ChildItem -LiteralPath $logRoot -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 3|ForEach-Object{[ordered]@{name=$_.Name;size=[int64]$_.Length;last_write_utc=$_.LastWriteTimeUtc.ToString('o');tail=@(Get-Content -LiteralPath $_.FullName -Tail 20 -ErrorAction SilentlyContinue|ForEach-Object{&$redact $_})}})
            [ordered]@{ challenge=$challenge; case_id=$caseId; receipt_bytes_b64=$rawReceiptB64; receipt=$receiptText; receipt_present=[bool]$receiptPresent; guest_marker=$markerText; guest_artifact_sha256=$guestHash; guest_artifact_size=[int64](Get-Item -LiteralPath $artifact).Length; supervisor=$supervisorText; milestones=$milestoneText; pending_installer=$pendingText; stdout_tail=$outTail; stderr_tail=$errTail; native_installer_stdout_tail=$nativeOut; native_installer_stderr_tail=$nativeErr; bootstrap_diagnostic=$bootstrap; installer_logs=$installerLogs; guest_clock=[ordered]@{utc_now=[DateTime]::UtcNow.ToString('o');local_now=[DateTime]::Now.ToString('o');timezone_id=if($tz){[string]$tz.Id}else{''};timezone_display=if($tz){[string]$tz.DisplayName}else{''};last_boot=if($os){[string]$os.LastBootUpTime}else{''}}; system_events=$events; service=if($svc){[ordered]@{state=[string]$svc.State;pid=[int]$svc.ProcessId}}else{$null}; run_id=$runId }
        } -ArgumentList $guestReceipt,$guestMarker,$guestArtifact,$RunId,$CaseId,$AttemptNonce
    } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='collect'; result=[ordered]@{ transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; readback=$readback }; release_passed=$false; product_verified=$false }); exit 0
}
if ($Action -eq 'diagnose-bootstrap-root') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for bootstrap-root diagnostic' }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSha256 -notmatch '^[0-9a-f]{64}$') { Fail 'bootstrap-root diagnostic requires expected candidate hash' }
    $credential=Get-CredentialFromStdin; $session=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
    try {
        $proof=Invoke-Command -Session $session -ScriptBlock {
            param($id,$case,$vmid,$sha)
            $root="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"; $artifact=Join-Path $root 'current.exe'; $marker=Join-Path $root 'run-marker.txt'; $bootstrap=Join-Path $root 'ifw-bootstrap-root'; $stdout=Join-Path $root 'bootstrap.stdout.log'; $stderr=Join-Path $root 'bootstrap.stderr.log'
            if(-not(Test-Path $artifact -PathType Leaf)-or(Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant()-ne$sha){throw 'diagnostic artifact hash mismatch'}
            $markerLines=@(Get-Content -LiteralPath $marker);if($markerLines -notcontains "amnezia-release-lab:${id}:windows-x64" -or $markerLines -notcontains "case_id=$case" -or $markerLines -notcontains "vm_id=$vmid"){throw 'diagnostic guest binding mismatch'}
            if(Test-Path $bootstrap){throw 'diagnostic bootstrap root already exists'};New-Item -ItemType Directory $bootstrap|Out-Null
            $p=Start-Process -FilePath $artifact -ArgumentList @('--verbose','--root',$bootstrap,'--accept-messages','--accept-licenses','--confirm-command','install','AmneziaSelfHostedUpdate=true') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
            [void]$p.Handle
            if(-not$p.WaitForExit(900000)){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue;throw 'diagnostic installer timeout'}
            $p.Refresh();$raw=$p.ExitCode;if($null-eq$raw-or$raw-isnot[int]){throw 'diagnostic exit code unavailable'}
            $components='C:\Program Files\AmneziaVPN\components.xml';$version='';if(Test-Path $components){$m=[regex]::Match([IO.File]::ReadAllText($components),'<Version>\s*([^<]+)');if($m.Success){$version=$m.Groups[1].Value}}
            $svc=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
            [ordered]@{run_id=$id;case_id=$case;vm_id=$vmid;artifact_sha256=$sha;bootstrap_root=$bootstrap;bootstrap_items=@(Get-ChildItem $bootstrap -Force -ErrorAction SilentlyContinue|ForEach-Object{$_.Name});exit_code=[int]$raw;installed_version=$version;service=if($svc){[ordered]@{state=[string]$svc.State;pid=[int]$svc.ProcessId}}else{$null};stdout_tail=@(Get-Content $stdout -Tail 120 -ErrorAction SilentlyContinue);stderr_tail=@(Get-Content $stderr -Tail 120 -ErrorAction SilentlyContinue)}
        } -ArgumentList $RunId,$CaseId,([string]$child.vm.Id),$ExpectedSha256
    } finally {Remove-PSSession $session}
    Emit ([ordered]@{action='diagnose-bootstrap-root';origin='guest';injected=$false;transport='hyperv-powershell-direct';product_verified=$false;release_passed=$false;proof=$proof});exit 0
}
if ($Action -eq 'reset') {
    $before=(Get-Parent $ParentRoot).sha256
    if ([string]$child.vm.State -eq 'Running') { Stop-VM -VM $child.vm -TurnOff:$false -Force | Out-Null }
    $deadline=(Get-Date).AddSeconds(90); do { $vm=@(Get-VM -Id ([guid]$child.vm.Id))[0]; if([string]$vm.State -eq 'Off'){break}; Start-Sleep -Seconds 1 } while((Get-Date)-lt $deadline)
    if ([string]$vm.State -ne 'Off') { Fail 'child VM did not stop during reset' }
    Remove-VM -VM $vm -Force -Confirm:$false
    if (Test-Path -LiteralPath $child.root -PathType Container) { Remove-Item -LiteralPath $child.root -Recurse -Force }
    $after=(Get-Parent $ParentRoot).sha256; if ($before -ne $after) { Fail 'sealed parent VHDX changed during child reset' }
    Emit ([ordered]@{ action='reset'; run_id=$RunId; removed_child=$true; parent_sha256_before=$before; parent_sha256_after=$after; release_passed=$false }); exit 0
}
Fail "unsupported action: $Action"
